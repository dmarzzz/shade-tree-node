//! RLN proof verification and the field arithmetic around it.
//!
//! The snarkjs parsing and the tree conventions are taken from `crates/shadenet-rln`
//! (`src/verify.rs` and `src/tree.rs`), so a proof this module accepts is exactly a proof the
//! reference node accepts. The Poseidon
//! permutation is a fixed-width reimplementation: the reference crate links round constants for
//! every width, which costs a device hundreds of kilobytes of flash it does not have.

use ark_bn254::{Bn254, Fq, Fq12, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::bn::BnConfig;
use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_groth16::Proof;
use num_bigint::BigUint;
use serde_json::Value;
use sha3::{Digest, Keccak256};

use crate::poseidon_t3::{ARK, FULL_ROUNDS, MDS, PARTIAL_ROUNDS};

/// circom-rln tree depth (`RLN(20,16)`).
pub const TREE_DEPTH: usize = 20;

/// The verification key compiled into the node: the PSE RLN ceremony output at
/// `circuits/rln/verification_key.json` in this repository.
pub const BUILTIN_VKEY: &[u8] = include_bytes!("../../../../circuits/rln/verification_key.json");

/// `poseidon2([a, b])` over BN254 with circomlib's parameters.
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::from(0u64), a, b];
    let half = FULL_ROUNDS / 2;
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        for (i, s) in state.iter_mut().enumerate() {
            *s += ARK[round * 3 + i];
        }
        let full = round < half || round >= half + PARTIAL_ROUNDS;
        let boxes = if full { 3 } else { 1 };
        for s in state.iter_mut().take(boxes) {
            let square = s.square();
            *s *= square.square();
        }
        let mut next = [Fr::from(0u64); 3];
        for (row, out) in MDS.iter().zip(next.iter_mut()) {
            *out = row[0] * state[0] + row[1] * state[1] + row[2] * state[2];
        }
        state = next;
    }
    state[0]
}

/// `poseidon1([a])` over BN254 with circomlib's parameters.
pub fn poseidon1(a: Fr) -> Fr {
    use crate::poseidon_t2 as t2;
    let mut state = [Fr::from(0u64), a];
    let half = t2::FULL_ROUNDS / 2;
    for round in 0..t2::FULL_ROUNDS + t2::PARTIAL_ROUNDS {
        for (i, s) in state.iter_mut().enumerate() {
            *s += t2::ARK[round * 2 + i];
        }
        let full = round < half || round >= half + t2::PARTIAL_ROUNDS;
        let boxes = if full { 2 } else { 1 };
        for s in state.iter_mut().take(boxes) {
            let square = s.square();
            *s *= square.square();
        }
        state = [
            t2::MDS[0][0] * state[0] + t2::MDS[0][1] * state[1],
            t2::MDS[1][0] * state[0] + t2::MDS[1][1] * state[1],
        ];
    }
    state[0]
}

/// The membership leaf for an identity secret at a tier:
/// `Poseidon2(Poseidon1(identitySecret), userMessageLimit)`.
pub fn rate_commitment(identity_secret: Fr, limit: u64) -> Fr {
    poseidon2(poseidon1(identity_secret), Fr::from(limit))
}

/// Recover the identity secret from two shares of one proof slot. Each share is a point on
/// the line `y = secret + a1 * x`, so two distinct points give its intercept.
pub fn recover_secret(first: (&str, &str), second: (&str, &str)) -> Result<Fr, String> {
    let (x1, y1) = (parse_fr(first.0)?, parse_fr(first.1)?);
    let (x2, y2) = (parse_fr(second.0)?, parse_fr(second.1)?);
    let dx = (x2 - x1)
        .inverse()
        .ok_or("the two shares have the same x")?;
    let slope = (y2 - y1) * dx;
    Ok(y1 - slope * x1)
}

/// `externalNullifier = poseidon2(epoch, rlnIdentifier)`.
pub fn external_nullifier(epoch: u64, rln_identifier: u64) -> Fr {
    poseidon2(Fr::from(epoch), Fr::from(rln_identifier))
}

/// A field element as its canonical decimal string.
pub fn fr_to_dec(f: &Fr) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_str_radix(10)
}

/// Parse a canonical BN254 scalar from decimal or `0x` hex. Values at or above the modulus are
/// rejected, not reduced, so one element never has two spellings.
pub fn parse_fr(s: &str) -> Result<Fr, String> {
    let s = s.trim();
    let big = match s.strip_prefix("0x") {
        Some(hex) if !hex.is_empty() => BigUint::parse_bytes(hex.as_bytes(), 16),
        Some(_) => None,
        None if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            BigUint::parse_bytes(s.as_bytes(), 10)
        }
        None => None,
    }
    .ok_or_else(|| format!("{:?} is not a decimal or 0x-hex field element", truncate(s)))?;
    let modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    if big >= modulus {
        return Err(format!(
            "{:?} is not below the BN254 scalar field modulus",
            truncate(s)
        ));
    }
    Ok(Fr::from(big))
}

fn truncate(s: &str) -> String {
    s.chars().take(24).collect()
}

/// The Semaphore group hash that seeds the tree's zero value:
/// `keccak256(be32(id)) >> 8`.
fn tree_zero(rln_identifier: u64) -> Fr {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&rln_identifier.to_be_bytes());
    let digest = Keccak256::digest(buf);
    Fr::from(BigUint::from_bytes_be(&digest) >> 8u32)
}

/// Root of the depth-20 Poseidon tree over `leaves` in order, with the group's zero value in
/// every empty position. Works level by level in place, so memory is one copy of the leaves.
pub fn tree_root(rln_identifier: u64, leaves: &[Fr]) -> Fr {
    let mut zero = tree_zero(rln_identifier);
    let mut level: Vec<Fr> = leaves.to_vec();
    for _ in 0..TREE_DEPTH {
        let parents = level.len().div_ceil(2);
        for i in 0..parents {
            let left = level[2 * i];
            let right = level.get(2 * i + 1).copied().unwrap_or(zero);
            level[i] = poseidon2(left, right);
        }
        level.truncate(parents);
        zero = poseidon2(zero, zero);
    }
    level.first().copied().unwrap_or(zero)
}

/// Root for a members list given as decimal (or `0x`) strings.
pub fn members_root(rln_identifier: u64, members: &[String]) -> Result<String, String> {
    let leaves: Vec<Fr> = members
        .iter()
        .map(|m| parse_fr(m))
        .collect::<Result<_, _>>()?;
    Ok(fr_to_dec(&tree_root(rln_identifier, &leaves)))
}

// ---------------------------------------------------------------------------------------------
// Groth16 over snarkjs JSON (parsing from crates/shadenet-rln/src/verify.rs)

/// A parsed snarkjs verification key, plus the one pairing that never changes.
///
/// The reference node keeps the key "prepared": two precomputed G2 line tables, about 34 KB
/// that stay allocated for the life of the process. A device with 190 KB of heap cannot spare
/// that, so the tables are rebuilt during each verification (about 60 ms each on an ESP32)
/// and only `e(alpha, beta)` is kept.
pub struct VerifyingKey {
    alpha_beta: Fq12,
    gamma_neg: G2Affine,
    delta_neg: G2Affine,
    ic: Vec<G1Affine>,
}

impl VerifyingKey {
    /// Parse a snarkjs `verification_key.json`, checking every point is on the curve and in the
    /// prime-order subgroup. Computes one pairing, which needs about 20 KB of stack.
    pub fn parse(json: &Value) -> Result<Self, String> {
        let ic = json["IC"]
            .as_array()
            .ok_or("verification key IC is not an array")?
            .iter()
            .enumerate()
            .map(|(index, value)| g1(value, &format!("verification key IC[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        if ic.is_empty() {
            return Err("verification key IC is empty".into());
        }
        let alpha = g1(&json["vk_alpha_1"], "verification key vk_alpha_1")?;
        let beta = g2(&json["vk_beta_2"], "verification key vk_beta_2")?;
        let gamma = g2(&json["vk_gamma_2"], "verification key vk_gamma_2")?;
        let delta = g2(&json["vk_delta_2"], "verification key vk_delta_2")?;
        Ok(Self {
            alpha_beta: Bn254::pairing(alpha, beta).0,
            gamma_neg: (-gamma.into_group()).into_affine(),
            delta_neg: (-delta.into_group()).into_affine(),
            ic,
        })
    }

    /// The key compiled into the node.
    pub fn builtin() -> Result<Self, String> {
        let json: Value = serde_json::from_slice(BUILTIN_VKEY).map_err(|e| e.to_string())?;
        Self::parse(&json)
    }
}

/// Parse a snarkjs proof object (`pi_a`, `pi_b`, `pi_c` in affine coordinates with the trailing
/// `1` / `["1","0"]` marker), checking every point.
pub fn parse_proof(json: &Value) -> Result<Proof<Bn254>, String> {
    Ok(Proof {
        a: affine_g1(&json["pi_a"], "proof pi_a")?,
        b: affine_g2(&json["pi_b"], "proof pi_b")?,
        c: affine_g1(&json["pi_c"], "proof pi_c")?,
    })
}

/// One pairing input in the Miller loop: the G1 point, the G2 point and its negation, and the
/// running G2 point in homogeneous projective coordinates.
struct MillerPair {
    p: G1Affine,
    q: G2Affine,
    neg_q: G2Affine,
    x: Fq2,
    y: Fq2,
    z: Fq2,
}

impl MillerPair {
    fn new(p: G1Affine, q: G2Affine) -> Self {
        Self {
            p,
            q,
            neg_q: (-q.into_group()).into_affine(),
            x: q.x,
            y: q.y,
            z: Fq2::one(),
        }
    }

    /// Double the running point and fold the tangent line, evaluated at `p`, into `f`.
    fn double(&mut self, two_inv: &Fq, f: &mut Fq12) {
        let mut a = self.x * self.y;
        a.mul_assign_by_fp(two_inv);
        let b = self.y.square();
        let c = self.z.square();
        let e = <ark_bn254::g2::Config as SWCurveConfig>::COEFF_B * (c.double() + c);
        let f3 = e.double() + e;
        let mut g = b + f3;
        g.mul_assign_by_fp(two_inv);
        let h = (self.y + self.z).square() - (b + c);
        let i = e - b;
        let j = self.x.square();
        let e_square = e.square();
        self.x = a * (b - f3);
        self.y = g.square() - (e_square.double() + e_square);
        self.z = b * h;
        self.line(-h, j.double() + j, i, f);
    }

    /// Add `q` to the running point and fold the chord line, evaluated at `p`, into `f`.
    fn add(&mut self, q: &G2Affine, f: &mut Fq12) {
        let theta = self.y - (q.y * self.z);
        let lambda = self.x - (q.x * self.z);
        let c = theta.square();
        let d = lambda.square();
        let e = lambda * d;
        let f2 = self.z * c;
        let g = self.x * d;
        let h = e + f2 - g.double();
        self.x = lambda * h;
        self.y = theta * (g - h) - (e * self.y);
        self.z *= e;
        let j = theta * q.x - (lambda * q.y);
        self.line(lambda, -theta, j, f);
    }

    /// BN254 has a D-type twist: the line's coefficients land in slots 0, 3 and 4 of Fq12.
    fn line(&self, mut c0: Fq2, mut c1: Fq2, c2: Fq2, f: &mut Fq12) {
        c0.mul_assign_by_fp(&self.p.y);
        c1.mul_assign_by_fp(&self.p.x);
        f.mul_by_034(&c0, &c1, &c2);
    }
}

/// `q` multiplied by the field characteristic (the Frobenius endomorphism on the twist).
fn mul_by_char(q: G2Affine) -> G2Affine {
    let mut s = q;
    s.x.frobenius_map_in_place(1);
    s.x *= <ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_X;
    s.y.frobenius_map_in_place(1);
    s.y *= <ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_Y;
    s
}

/// The optimal-ate Miller loop over several pairs at once, computing each line as it is
/// needed.
///
/// arkworks first builds a table of about 90 line coefficients per G2 point (17 KB each, in a
/// vector that grows to 24 KB) and then walks the tables. The arithmetic here is the same,
/// taken from `ark-ec`'s BN model, with the table removed: a device whose largest free heap
/// block is a few tens of kilobytes cannot allocate one.
fn miller_loop(pairs: &mut [MillerPair]) -> Fq12 {
    const ATE: &[i8] = <ark_bn254::Config as BnConfig>::ATE_LOOP_COUNT;
    // The steps below are for a positive curve parameter, which BN254 has.
    const _: () = assert!(!<ark_bn254::Config as BnConfig>::X_IS_NEGATIVE);
    let two_inv = Fq::one().double().inverse().expect("2 is invertible");
    let mut f = Fq12::one();
    for i in (1..ATE.len()).rev() {
        if i != ATE.len() - 1 {
            f.square_in_place();
        }
        for pair in pairs.iter_mut() {
            pair.double(&two_inv, &mut f);
        }
        match ATE[i - 1] {
            1 => {
                for pair in pairs.iter_mut() {
                    let q = pair.q;
                    pair.add(&q, &mut f);
                }
            }
            -1 => {
                for pair in pairs.iter_mut() {
                    let q = pair.neg_q;
                    pair.add(&q, &mut f);
                }
            }
            _ => {}
        }
    }
    for pair in pairs.iter_mut() {
        let q1 = mul_by_char(pair.q);
        pair.add(&q1, &mut f);
    }
    for pair in pairs.iter_mut() {
        let mut q2 = mul_by_char(mul_by_char(pair.q));
        q2.y = -q2.y;
        pair.add(&q2, &mut f);
    }
    f
}

/// The Groth16 check `e(A, B) * e(L, -gamma) * e(C, -delta) == e(alpha, beta)`, where `L` is
/// the public-input combination of the key's `IC` points. `public_inputs` are the circuit's
/// public signals in witness order: `y, root, nullifier, x, externalNullifier`.
pub fn verify(
    key: &VerifyingKey,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool, String> {
    if public_inputs.len() + 1 != key.ic.len() {
        return Err("pairing check failed: wrong number of public inputs".into());
    }
    let mut combination = key.ic[0].into_group();
    for (input, point) in public_inputs.iter().zip(&key.ic[1..]) {
        combination += point.mul_bigint(input.into_bigint());
    }
    let mut pairs: Vec<MillerPair> = [
        (proof.a, proof.b),
        (combination.into_affine(), key.gamma_neg),
        (proof.c, key.delta_neg),
    ]
    .into_iter()
    // A pair with the point at infinity contributes the identity.
    .filter(|(p, q)| !p.is_zero() && !q.is_zero())
    .map(|(p, q)| MillerPair::new(p, q))
    .collect();
    let product = miller_loop(&mut pairs);
    let result = Bn254::final_exponentiation(MillerLoopOutput(product))
        .ok_or("pairing check failed: unexpected identity")?;
    Ok(result.0 == key.alpha_beta)
}

fn dec_to_fq(value: &Value, what: &str) -> Result<Fq, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} is not a decimal string"))?;
    let integer = BigUint::parse_bytes(text.as_bytes(), 10)
        .ok_or_else(|| format!("{what} is not a decimal string"))?;
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    if integer >= modulus {
        return Err(format!("{what} is outside the BN254 base field"));
    }
    Ok(Fq::from(integer))
}

fn g1(value: &Value, what: &str) -> Result<G1Affine, String> {
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| format!("{what} is not a G1 point"))?;
    let point = G1Affine::new_unchecked(
        dec_to_fq(&values[0], &format!("{what}.x"))?,
        dec_to_fq(&values[1], &format!("{what}.y"))?,
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!("{what} is not a G1 point"));
    }
    Ok(point)
}

fn g2(value: &Value, what: &str) -> Result<G2Affine, String> {
    let not_g2 = |what: &str| format!("{what} is not a G2 point");
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| not_g2(what))?;
    let x = values[0]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| not_g2(&format!("{what}.x")))?;
    let y = values[1]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| not_g2(&format!("{what}.y")))?;
    let point = G2Affine::new_unchecked(
        Fq2::new(
            dec_to_fq(&x[0], &format!("{what}.x.c0"))?,
            dec_to_fq(&x[1], &format!("{what}.x.c1"))?,
        ),
        Fq2::new(
            dec_to_fq(&y[0], &format!("{what}.y.c0"))?,
            dec_to_fq(&y[1], &format!("{what}.y.c1"))?,
        ),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(not_g2(what));
    }
    Ok(point)
}

fn affine_g1(value: &Value, what: &str) -> Result<G1Affine, String> {
    if value.get(2).and_then(|z| z.as_str()) != Some("1") {
        return Err(format!("{what} is not an affine point"));
    }
    g1(value, what)
}

fn affine_g2(value: &Value, what: &str) -> Result<G2Affine, String> {
    let z = value.get(2).and_then(|z| z.as_array());
    let affine =
        z.is_some_and(|z| z.len() == 2 && z[0].as_str() == Some("1") && z[1].as_str() == Some("0"));
    if !affine {
        return Err(format!("{what} is not an affine point"));
    }
    g2(value, what)
}

#[cfg(test)]
mod tests {
    use super::*;
    use light_poseidon::{Poseidon, PoseidonHasher};

    #[test]
    fn poseidon2_matches_the_reference() {
        let mut reference = Poseidon::<Fr>::new_circom(2).unwrap();
        for (a, b) in [(0u64, 0u64), (1, 2), (29_929_860, 1), (u64::MAX, 7)] {
            let (a, b) = (Fr::from(a), Fr::from(b));
            assert_eq!(poseidon2(a, b), reference.hash(&[a, b]).unwrap());
        }
        let big = parse_fr(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        assert_eq!(poseidon2(big, big), reference.hash(&[big, big]).unwrap());
    }

    #[test]
    fn table_free_miller_loop_matches_arkworks() {
        use ark_bn254::{G1Projective, G2Projective};
        use ark_ec::PrimeGroup;
        let pairs: Vec<(G1Affine, G2Affine)> = [(3u64, 5u64), (7, 11), (123_456_789, 987_654_321)]
            .into_iter()
            .map(|(a, b)| {
                (
                    (G1Projective::generator() * Fr::from(a)).into_affine(),
                    (G2Projective::generator() * Fr::from(b)).into_affine(),
                )
            })
            .collect();
        let expected =
            Bn254::multi_miller_loop(pairs.iter().map(|(p, _)| *p), pairs.iter().map(|(_, q)| *q));
        let mut ours: Vec<MillerPair> =
            pairs.iter().map(|(p, q)| MillerPair::new(*p, *q)).collect();
        assert_eq!(miller_loop(&mut ours), expected.0);
        // And one pair at a time agrees with the pairing itself.
        let (p, q) = pairs[0];
        let single = miller_loop(&mut [MillerPair::new(p, q)]);
        assert_eq!(
            Bn254::final_exponentiation(MillerLoopOutput(single)).unwrap(),
            Bn254::pairing(p, q)
        );
    }

    #[test]
    fn poseidon1_and_leaf_match_the_reference() {
        let mut reference = Poseidon::<Fr>::new_circom(1).unwrap();
        for a in [0u64, 1, 111, u64::MAX] {
            assert_eq!(
                poseidon1(Fr::from(a)),
                reference.hash(&[Fr::from(a)]).unwrap()
            );
        }
        // The fixture envelope's tree has one leaf: identity secret 111 at tier 8.
        let env: Value =
            serde_json::from_str(include_str!("../../../firmware/fixtures/envelope.json")).unwrap();
        let root = env["proof"]["snarkProof"]["publicSignals"]["root"]
            .as_str()
            .unwrap();
        let leaf = rate_commitment(Fr::from(111u64), 8);
        assert_eq!(fr_to_dec(&tree_root(1, &[leaf])), root);
    }

    #[test]
    fn two_shares_give_the_secret_back() {
        let secret = Fr::from(123_456_789u64);
        let a1 = Fr::from(987u64);
        let share = |x: u64| {
            let x = Fr::from(x);
            (fr_to_dec(&x), fr_to_dec(&(secret + a1 * x)))
        };
        let (p, q) = (share(5), share(77));
        assert_eq!(recover_secret((&p.0, &p.1), (&q.0, &q.1)).unwrap(), secret);
        assert!(recover_secret((&p.0, &p.1), (&p.0, &p.1)).is_err());
    }

    #[test]
    fn the_builtin_key_parses() {
        VerifyingKey::builtin().unwrap();
    }

    #[test]
    fn field_parsing_rejects_non_canonical_values() {
        assert_eq!(fr_to_dec(&parse_fr("0x10").unwrap()), "16");
        assert!(parse_fr(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        )
        .is_err());
        assert!(parse_fr("").is_err());
        assert!(parse_fr("12a").is_err());
    }

    #[test]
    fn empty_and_single_leaf_roots_follow_the_zero_chain() {
        let mut zero = tree_zero(1);
        let leaf = Fr::from(42u64);
        let mut node = leaf;
        for _ in 0..TREE_DEPTH {
            node = poseidon2(node, zero);
            zero = poseidon2(zero, zero);
        }
        assert_eq!(tree_root(1, &[]), zero);
        assert_eq!(tree_root(1, &[leaf]), node);
        assert_ne!(tree_root(1, &[leaf]), tree_root(2, &[leaf]));
    }
}
