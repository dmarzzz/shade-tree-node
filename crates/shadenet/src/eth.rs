//! The small slice of Ethereum the member lifecycle needs: addresses, 256-bit integers, ABI
//! encoding for `uint256`/`address`/`bytes`, keccak, and locally signed EIP-1559 transactions.
//!
//! This replaces the archived `ethers-core`. It reuses `k256` and `sha3`, which the protocol crate
//! already depends on, and is cross-checked byte for byte against `ethers-core` in the CLI's tests.

use std::fmt;
use std::str::FromStr;

use k256::ecdsa::SigningKey;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Keccak-256.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The 4-byte function selector of a signature such as `register(uint256,uint256)`.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// A 20-byte account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub [u8; 20]);

impl FromStr for Address {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, String> {
        let hex_part = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        let mut out = [0u8; 20];
        hex::decode_to_slice(hex_part, &mut out)
            .map_err(|_| format!("not a 20-byte hex address: {value}"))?;
        Ok(Self(out))
    }
}

impl fmt::Display for Address {
    /// EIP-55 checksummed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lower = hex::encode(self.0);
        let hash = keccak256(lower.as_bytes());
        f.write_str("0x")?;
        for (i, c) in lower.chars().enumerate() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if c.is_ascii_alphabetic() && nibble >= 8 {
                write!(f, "{}", c.to_ascii_uppercase())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An unsigned integer below 2^256.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct U256(BigUint);

impl U256 {
    pub fn zero() -> Self {
        Self(BigUint::default())
    }
    pub fn from_u64(value: u64) -> Self {
        Self(BigUint::from(value))
    }
    fn checked(value: BigUint) -> Option<Self> {
        (value.bits() <= 256).then_some(Self(value))
    }
    pub fn from_big_endian(bytes: &[u8]) -> Option<Self> {
        Self::checked(BigUint::from_bytes_be(bytes))
    }
    pub fn from_dec_str(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Self::checked(BigUint::parse_bytes(value.as_bytes(), 10)?)
    }
    /// A JSON-RPC quantity: `0x`-prefixed hex without leading zeros (`0x0` for zero).
    pub fn from_quantity(value: &str) -> Option<Self> {
        let hex_part = value.strip_prefix("0x")?;
        if hex_part.is_empty() || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Self::checked(BigUint::parse_bytes(hex_part.as_bytes(), 16)?)
    }
    pub fn to_quantity(&self) -> String {
        format!("0x{}", self.0.to_str_radix(16))
    }
    pub fn to_big_endian(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }
    /// Minimal big-endian bytes, empty for zero (the RLP integer form).
    fn minimal_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            Vec::new()
        } else {
            self.0.to_bytes_be()
        }
    }
    pub fn is_zero(&self) -> bool {
        self.0.bits() == 0
    }
    pub fn as_u64(&self) -> Option<u64> {
        u64::try_from(&self.0).ok()
    }
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        Self::checked(&self.0 + &other.0)
    }
    pub fn checked_mul(&self, other: &Self) -> Option<Self> {
        Self::checked(&self.0 * &other.0)
    }
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        (self.0 >= other.0).then(|| Self(&self.0 - &other.0))
    }
    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

/// An ABI argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Uint(U256),
    Address(Address),
    Bytes(Vec<u8>),
}

/// ABI-encode arguments (head/tail layout; `bytes` is the only dynamic type).
pub fn encode(tokens: &[Token]) -> Vec<u8> {
    let head_len = 32 * tokens.len();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for token in tokens {
        match token {
            Token::Uint(value) => head.extend_from_slice(&value.to_big_endian()),
            Token::Address(address) => {
                head.extend_from_slice(&[0u8; 12]);
                head.extend_from_slice(&address.0);
            }
            Token::Bytes(bytes) => {
                head.extend_from_slice(&U256::from((head_len + tail.len()) as u64).to_big_endian());
                tail.extend_from_slice(&U256::from(bytes.len() as u64).to_big_endian());
                tail.extend_from_slice(bytes);
                let pad = (32 - bytes.len() % 32) % 32;
                tail.extend(std::iter::repeat_n(0u8, pad));
            }
        }
    }
    head.extend(tail);
    head
}

/// Calldata: selector followed by the encoded arguments.
pub fn calldata(signature: &str, tokens: &[Token]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend(encode(tokens));
    out
}

/// Decode `count` consecutive `uint256` words from return data.
pub fn decode_uints(data: &[u8], count: usize) -> Result<Vec<U256>, String> {
    if data.len() < 32 * count {
        return Err(format!(
            "return data has {} bytes, expected at least {}",
            data.len(),
            32 * count
        ));
    }
    Ok(data
        .chunks(32)
        .take(count)
        .map(|word| U256::from_big_endian(word).unwrap_or_default())
        .collect())
}

// ---------------------------------------------------------------------- RLP

fn rlp_length(prefix_short: u8, prefix_long: u8, len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(prefix_short + len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(prefix_long + (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

fn rlp_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_length(0x80, 0xb7, bytes.len(), out);
        out.extend_from_slice(bytes);
    }
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    let mut out = Vec::with_capacity(body.len() + 9);
    rlp_length(0xc0, 0xf7, body.len(), &mut out);
    out.extend(body);
    out
}

fn item_uint(value: &U256) -> Vec<u8> {
    let mut out = Vec::new();
    rlp_bytes(&value.minimal_bytes(), &mut out);
    out
}

fn item_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rlp_bytes(value, &mut out);
    out
}

// ------------------------------------------------------------ transactions

/// An EIP-1559 contract call with an empty access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas: U256,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

impl Eip1559 {
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            item_uint(&U256::from(self.chain_id)),
            item_uint(&self.nonce),
            item_uint(&self.max_priority_fee_per_gas),
            item_uint(&self.max_fee_per_gas),
            item_uint(&self.gas),
            item_bytes(&self.to.0),
            item_uint(&self.value),
            item_bytes(&self.data),
            rlp_list(&[]),
        ]
    }

    /// The hash that is signed: `keccak256(0x02 || rlp(fields))`.
    pub fn sighash(&self) -> [u8; 32] {
        let mut payload = vec![0x02];
        payload.extend(rlp_list(&self.fields()));
        keccak256(&payload)
    }
}

/// A local secp256k1 key. The scalar is zeroized on drop and never printed.
pub struct Wallet {
    key: SigningKey,
    pub address: Address,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Wallet {
    /// From a 32-byte hex private key. Errors never echo the value.
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        let mut bytes = Zeroizing::new([0u8; 32]);
        if normalized.len() != 64 || hex::decode_to_slice(normalized, bytes.as_mut()).is_err() {
            return Err("funding key is not a 32-byte hex private key (value not shown)".into());
        }
        let key = SigningKey::from_slice(bytes.as_ref()).map_err(|_| {
            "funding key is not a valid secp256k1 private key (value not shown)".to_string()
        })?;
        let point = key.verifying_key().to_sec1_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Ok(Self {
            key,
            address: Address(address),
        })
    }

    /// Sign and serialize: `0x02 || rlp(fields ++ [yParity, r, s])`. Returns the raw bytes.
    pub fn sign(&self, tx: &Eip1559) -> Result<Vec<u8>, String> {
        let (signature, recovery) = self.key.sign_prehash_recoverable(&tx.sighash());
        let bytes = signature.to_bytes();
        let mut fields = tx.fields();
        fields.push(item_uint(&U256::from(u64::from(recovery.is_y_odd()))));
        fields.push(item_uint(
            &U256::from_big_endian(&bytes[..32]).unwrap_or_default(),
        ));
        fields.push(item_uint(
            &U256::from_big_endian(&bytes[32..]).unwrap_or_default(),
        ));
        let mut raw = vec![0x02];
        raw.extend(rlp_list(&fields));
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Anvil's first account: a published test key.
    const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn address_derivation_and_checksum_match_known_values() {
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        assert_eq!(
            wallet.address.to_string(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert!(Wallet::from_hex("0x1234").is_err());
        assert!(!format!("{wallet:?}").contains("ac0974"));
    }

    #[test]
    fn selectors_and_abi_match_solidity() {
        assert_eq!(
            hex::encode(selector("transfer(address,uint256)")),
            "a9059cbb"
        );
        let data = encode(&[Token::Uint(U256::from(1)), Token::Bytes(vec![0xaa; 33])]);
        let words: Vec<String> = data.chunks(32).map(hex::encode).collect();
        assert_eq!(words[0], format!("{:064x}", 1));
        assert_eq!(words[1], format!("{:064x}", 64)); // offset of the bytes tail
        assert_eq!(words[2], format!("{:064x}", 33)); // length
        assert_eq!(words.len(), 5); // 33 bytes pad to two words
    }

    #[test]
    fn integers_are_bounded_and_rlp_is_minimal() {
        assert!(U256::from_dec_str(&"9".repeat(80)).is_none());
        assert_eq!(U256::from_quantity("0x0").unwrap(), U256::zero());
        assert_eq!(U256::from(255).to_quantity(), "0xff");
        assert!(U256::from(1).checked_sub(&U256::from(2)).is_none());
        assert_eq!(item_uint(&U256::zero()), vec![0x80]);
        assert_eq!(item_uint(&U256::from(0x7f)), vec![0x7f]);
        assert_eq!(item_uint(&U256::from(0x80)), vec![0x81, 0x80]);
        let long = vec![0u8; 60];
        assert_eq!(&item_bytes(&long)[..2], &[0xb8, 60]);
    }
}
