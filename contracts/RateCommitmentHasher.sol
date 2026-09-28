// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICommitmentHasher} from "./StakedReputationSet.sol";
import {PoseidonT2} from "./PoseidonT2.sol";
import {PoseidonT3} from "./PoseidonT3.sol";

/// RateCommitmentHasher — the real, demo-grade commitment hasher for the RLN PoC.
///
/// It is a *real* Poseidon implementation, not a stub. `commitmentOf(identitySecret)`
/// returns the RLN **rate commitment** (the Merkle tree leaf), computed over the BN254
/// scalar field exactly as `circom-rln`'s `rln.circom` does it:
///
///     identityCommitment = Poseidon(1)([ identitySecret ])            // t=2 / single-input
///     rateCommitment     = Poseidon(2)([ identityCommitment, K ])     // t=3 / two-input   <-- leaf
///
/// with the per-member message limit `userMessageLimit` — the member's reputation TIER
/// (docs/adr/0006-reputation-tiers.md, T-FEAT-8b). The one-argument `commitmentOf(secret)`
/// is the DEFAULT tier `K = 8` (byte-equivalent to the rln-v3 hasher, which pinned K); the
/// two-argument `commitmentOf(secret, limit)` is the tiered leaf the redeployed
/// `StakedReputationSet.slash(commitment, secret, limit, receiver)` recomputes.
///
/// This is the value stored as the membership leaf in `StakedReputationSet`, so a
/// slash — which reveals the member's `identitySecret` — recomputes exactly this and
/// matches it against the stored leaf. If this formula drifts from the circuit /
/// `rlnjs` side, a genuine over-spender's reconstructed secret would fail to slash the
/// correct leaf (silent BadSecret). See circuits/rln/ARTIFACTS.md for the confirmed
/// leaf formula and Phase-0 gate.
///
/// ============================ COMMITMENT SCHEME (MUST MATCH THE CRYPTO SIDE) ============================
/// rateCommitment = Poseidon(2)([ Poseidon(1)([identitySecret]), 8 ])   over BN254 field
///                  F = 21888242871839275222246405745257275088548364400416034343698204186575808495617
///
/// The canonical JS match (poseidon-lite is already a repo dependency):
///
///     import { poseidon1, poseidon2 } from "poseidon-lite";
///     const rateCommitment = poseidon2([ poseidon1([identitySecret]), 8n ]);  // == commitmentOf(identitySecret)
///
/// (equivalently circomlibjs `poseidon([poseidon([s]), 8n])`). Verified test vectors,
/// JS ==> Solidity (see test/Poseidon.t.sol which asserts these on-chain):
///     commitmentOf(1)         == 19891105629297951594670588741444296361737921464595154400690791765679348608752
///     commitmentOf(2)         ==   829125768753819539800244880652039674283559009741491044486206649483843818383
///     commitmentOf(42)        == 18761753399903396742513213281650676703493682377645661572914919902014839614171
///     commitmentOf(111)       == 11302006078516901731073162965056551612114122314181142374993834332168998510316
///     commitmentOf(123456789) == 21329507788392969599237625293681982274847848071789066949605792135001356234277
/// =======================================================================================================
contract RateCommitmentHasher is ICommitmentHasher {
    /// BN254 scalar field. Inputs are reduced mod F inside the Poseidon libraries, so a
    /// secret >= F still hashes deterministically; keep JS secrets in [0, F) to avoid ambiguity.
    uint256 public constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// DEFAULT per-member message limit (RLN `userMessageLimit`), the second Poseidon(2)
    /// input of the one-argument form. 8 across the circuit defaults, rlnjs, and lib/rln.mjs
    /// K_SLOTS; other tiers pass their limit explicitly.
    uint256 public constant K = 8;

    /// Upper bound on a tier limit: the circuit's LessThan(16) range check is unsound at or
    /// above 2^16 (lib/rln.mjs MAX_LIMIT); a leaf at such a limit must never be admitted.
    uint256 public constant MAX_LIMIT = 65535;

    error BadLimit();

    /// @return rateCommitment = Poseidon(2)([ Poseidon(1)([identitySecret]), K ]).
    function commitmentOf(uint256 identitySecret) external pure override returns (uint256) {
        return _commitmentOf(identitySecret, K);
    }

    /// @return rateCommitment = Poseidon(2)([ Poseidon(1)([identitySecret]), limit ]),
    ///         the tier-`limit` leaf (T-FEAT-8b). Reverts BadLimit outside [1, MAX_LIMIT].
    function commitmentOf(uint256 identitySecret, uint256 limit) external pure override returns (uint256) {
        if (limit == 0 || limit > MAX_LIMIT) revert BadLimit();
        return _commitmentOf(identitySecret, limit);
    }

    /// @return identityCommitment = Poseidon(1)([ identitySecret ]), what a member registers.
    function identityCommitmentOf(uint256 identitySecret) external pure override returns (uint256) {
        return PoseidonT2.hash([identitySecret]);
    }

    /// @return rateCommitment = Poseidon(2)([ identityCommitment, limit ]), the leaf
    ///         `StakedReputationSet.registerIdentity` derives. Reverts BadLimit outside [1, MAX_LIMIT].
    function rateCommitmentOf(uint256 identityCommitment, uint256 limit) external pure override returns (uint256) {
        if (limit == 0 || limit > MAX_LIMIT) revert BadLimit();
        return PoseidonT3.hash([identityCommitment, limit]);
    }

    function _commitmentOf(uint256 identitySecret, uint256 limit) internal pure returns (uint256) {
        uint256 identityCommitment = PoseidonT2.hash([identitySecret]);
        return PoseidonT3.hash([identityCommitment, limit]);
    }
}
