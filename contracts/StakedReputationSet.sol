// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// StakedReputationSet: the on-chain admission gate for the access-gated onion
// egress. See docs/ONCHAIN.md for the full design and the anonymity argument. This
// is a REFERENCE implementation, unaudited, testnet-only. The ZK verifier and the
// commitment hasher are abstracted behind interfaces (below); wiring the real RLN
// artifacts is the remaining work.
//
// Semantics (docs/ONCHAIN.md, requirements R1-R5):
//   register    permissionless: post a fixed BOND for a Semaphore/RLN commitment.
//   initiateExit ZK-authorized: prove knowledge of the secret, start the unbonding
//                clock, leave the admission root. NOT keyed off msg.sender, so the
//                member stays anonymous (R1).
//   withdraw    ZK-authorized: after UNBONDING and if not slashed, pay the bond to a
//                caller-named fresh recipient (R2). Unlinkable fund-in vs fund-out.
//   slash       permissionless: whoever reconstructed the secret from an RLN
//                over-spend (in practice the gateway) claims at most 10% of the bond;
//                the remaining >=90% goes to the fixed burn address (R3).
//
// The bond stays fully slashable for the entire unbonding window, which is what makes
// "spam then instantly unstake" impossible (R4). UNBONDING must be >= F + E + C
// (freshness window + epoch + slash-confirmation margin); the contract enforces a
// caller-supplied lower bound so a misconfiguration cannot open that escape.
//
// The Merkle root itself is maintained off chain: members and their indices live in a
// mapping here and are emitted as events, and the gateway/clients rebuild the tree
// locally and verify their local root against the event log (docs/ROADMAP.md #2). A
// companion on-chain incremental-tree + root accessor can replace that later without
// changing this contract's admission/stake logic.
//
// T-DEV-9: that companion is now here. This contract ALSO maintains the identical RLN
// depth-20 Poseidon(2) incremental Merkle tree on chain, so the current membership root
// lives in a deterministic STORAGE SLOT (`currentRoot`, ROOT_STORAGE_SLOT below) and a
// light client can prove it with `eth_getProof` against a block's stateRoot — no trusted
// RPC event replay required (lib/root-provider.mjs LightClientRootProvider). The on-chain
// tree tracks the SAME zero-in-place removal semantics the off-chain reconstructRoot uses
// (register = insert at the append index; exit/slash-while-active = zero the leaf at its
// original index), so `currentRoot` == the off-chain reconstructRoot root by construction
// (proven in test/StakedReputationSet.t.sol::test_Root_* against the lib/rln-removal-parity
// golden). The gas cost is 20 Poseidon(2) hashes per membership change; see the note by
// `_updateLeaf`.
//
// T-FEAT-8b (reputation tiers on chain, docs/adr/0006-reputation-tiers.md, docs/ONCHAIN.md
// "Tiers on chain"): a tier IS the leaf's private RLN `userMessageLimit`, so the leaf is
// `Poseidon2(Poseidon1(identitySecret), limit)`. This contract now RECORDS the limit a member
// staked at and prices admission per tier: `register(commitment, limit)` requires exactly
// `bondFor(limit)` (a FIXED denomination per tier, so amounts still never fingerprint a member
// within a tier, R1) from an immutable tier table fixed at construction (no owner, no
// governance key — the set stays permissionless and un-upgradeable), and
// `slash(commitment, secret, limit, receiver)` recomputes the leaf at the CLAIMED limit through
// the tiered hasher, so a tier-32 leaf slashes only with limit 32 and burns the tier-32 bond.
// The one-argument `register(commitment)` / three-argument `slash(..)` overloads are the
// DEFAULT_LIMIT (= 8, the pre-tier K) path. Both slash overloads enforce the same burn.
// The exit-auth verifier receives the recorded limit so a real Groth16 exit proof ties the
// revealed identity commitment to the leaf at that member's tier (contracts/WithdrawVerifier.sol).

import {PoseidonT3} from "./PoseidonT3.sol";

/// Verifies a ZK proof that the caller knows the identity secret behind `commitment`.
/// Used to authorize exit and withdrawal without revealing which member (R1/R2).
/// `context` binds the proof to this action (e.g. keccak(action, recipient)) so a
/// withdrawal authorization cannot be replayed for a different recipient.
/// `limit` is the member's recorded tier (RLN userMessageLimit): the leaf is
/// Poseidon2(Poseidon1(secret), limit), so a verifier that ties the proof to the leaf needs it.
interface IWithdrawVerifier {
    function verify(uint256 commitment, uint256 limit, bytes32 context, bytes calldata proof)
        external
        view
        returns (bool);
}

/// Recomputes the RLN rate commitment (the tree leaf) from a revealed secret and a tier
/// limit, so `slash` can check that a reconstructed secret really belongs to the leaf it
/// claims (R3): commitment == Poseidon2(Poseidon1(secret), limit). The one-argument form is
/// the DEFAULT_LIMIT (8) leaf, byte-equivalent to the pre-tier hasher.
interface ICommitmentHasher {
    function commitmentOf(uint256 secret) external view returns (uint256);
    function commitmentOf(uint256 secret, uint256 limit) external view returns (uint256);
}

contract StakedReputationSet {
    // ---- immutable parameters -------------------------------------------------

    uint256 public immutable BOND; // bond of the DEFAULT_LIMIT tier; fixed per tier (R1)
    uint256 public immutable UNBONDING; // exit time-lock in seconds (R4)

    /// The pre-tier per-member message limit (RLN userMessageLimit K = 8): the tier the
    /// one-argument `register`/`slash` overloads use, always admitted, bond == BOND.
    uint256 public constant DEFAULT_LIMIT = 8;
    /// App-level upper bound on a tier limit: the circuit range-checks messageId with
    /// LessThan(16), which is NOT sound for a limit >= 2^16 (lib/rln.mjs MAX_LIMIT).
    uint256 public constant MAX_LIMIT = 65535;

    /// Slash economics v1: floor(bond / 10) is the maximum caller-directed reward.
    /// All remaining wei go to address(0). Even a member slashing itself loses >=90%.
    /// This is an ETH sink transfer, not Ethereum's protocol-level base-fee burn.
    uint256 public constant SLASH_REWARD_DIVISOR = 10;
    address public constant SLASH_BURN_ADDRESS = address(0);

    IWithdrawVerifier public immutable withdrawVerifier;
    ICommitmentHasher public immutable hasher;

    // ---- membership state -----------------------------------------------------

    struct Member {
        uint256 bond; // staked amount (== bondFor(limit) while held); 0 once gone
        uint64 index; // append-only leaf index, for off-chain tree rebuild
        uint64 exitInitiatedAt; // 0 while active; timestamp once exiting
        uint32 limit; // the tier (RLN userMessageLimit) the leaf was staked at
    }

    mapping(uint256 => Member) public members; // commitment => Member   (storage slot 0)
    uint64 public nextIndex; // append-only leaf counter (slot 1)
    uint256 public activeCount; // members currently staked (slot 2)

    // ---- on-chain incremental Merkle tree (T-DEV-9) ---------------------------
    //
    // The RLN admission root, maintained on chain so a light client can state-prove it.
    // MUST mirror the off-chain tree exactly (lib/rln.mjs newGroup / root-provider.mjs
    // reconstructRoot): a depth-20, arity-2 tree hashed with Poseidon(2) over BN254, whose
    // zero value is `keccak256(GROUP_ID) >> 8` (Semaphore v3 group convention) and whose
    // removals are ZERO-IN-PLACE at the leaf's original index.

    uint256 public constant TREE_DEPTH = 20; // circom-rln RLN(20,16); matches lib/rln.mjs TREE_DEPTH
    // Semaphore/RLN group id. MUST equal the JS SHADE_TREE_RLN_IDENTIFIER (default 1) so the
    // zero value — and therefore every root — matches the off-chain tree. If you change
    // one side you MUST change the other (same coordination the tree depth already needs).
    uint256 public constant GROUP_ID = 1;

    /// The current membership Merkle root, kept in a fixed storage slot so it is provable
    /// via `eth_getProof`. Declared FIRST among the tree state so its slot is stable and
    /// known: it is storage slot `ROOT_STORAGE_SLOT`. The empty tree's root is the depth-20
    /// all-zero-leaf root (NOT zero); an empty set is that value, which the off-chain
    /// reconstructRoot represents as `null` — same meaning, different encoding.
    uint256 public currentRoot;

    /// The storage slot `currentRoot` occupies. A light client reads this slot directly
    /// via eth_getProof / eth_getStorageAt. Asserted against `vm.load` in the Foundry test
    /// so a future storage reorder that moves the root fails loudly instead of silently.
    uint256 public constant ROOT_STORAGE_SLOT = 3;

    // Precomputed zero subtree roots: _zeroes[i] is the root of an empty subtree of height
    // i (_zeroes[0] = leaf zero value, _zeroes[i] = Poseidon2(_zeroes[i-1], _zeroes[i-1])).
    // _zeroes[TREE_DEPTH] is the empty-tree root. Filled once in the constructor.
    uint256[TREE_DEPTH + 1] private _zeroes;

    // Sparse node store: _treeNode[level][index] is the materialized node, or unset (0) to
    // mean "the empty subtree value _zeroes[level]". Real leaves/nodes are Poseidon field
    // elements (and the zero LEAF is _zeroes[0], itself nonzero), so 0 unambiguously means
    // "never written" — exactly the length-based default the JS @zk-kit tree uses.
    mapping(uint256 => mapping(uint256 => uint256)) private _treeNode;

    // ---- tier table (T-FEAT-8b) — declared AFTER the tree so currentRoot stays at slot 3 --
    //
    // limit => bond (0 = tier not admitted). Fixed at construction: a small, public table
    // (e.g. 8 => BOND, 32 => 4*BOND) with ONE denomination per tier, so a stake amount
    // reveals the tier (public at registration anyway, as in members.json) but never the
    // member within it (R1). No owner can add/remove tiers or change a bond after deploy.
    mapping(uint256 => uint256) private _bondOf;
    uint256[] private _allowedLimits; // ascending, distinct; always contains DEFAULT_LIMIT

    // ---- events (off-chain tree + gateway root refresh) -----------------------
    //
    // T-FEAT-8b: `MemberRegistered`/`MemberSlashed` carry the tier limit (non-indexed), so an
    // off-chain reader can rebuild the tier table of the set from the log alone. Their
    // topic0 therefore differs from the rln-v3 events; lib/root-provider.mjs accepts both.

    event MemberRegistered(uint256 indexed commitment, uint64 indexed index, uint256 limit);
    event MemberExiting(uint256 indexed commitment, uint64 exitInitiatedAt, uint64 withdrawableAt);
    event MemberWithdrawn(uint256 indexed commitment, address indexed recipient);
    event MemberSlashed(uint256 indexed commitment, address indexed receiver, uint256 limit);
    // Keep MemberSlashed unchanged for existing root-event readers; publish the split separately.
    event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward);

    error BadBond();
    error BadLimit();
    error BadTierTable();
    error UnbondingTooShort();
    error AlreadyMember();
    error NotMember();
    error NotExiting();
    error AlreadyExiting();
    error StillBonded();
    error BadProof();
    error BadSecret();
    error PayoutFailed();

    /// @param bond        the stake denomination of the DEFAULT_LIMIT (8) tier.
    /// @param unbonding   exit time-lock; must be >= minUnbonding.
    /// @param minUnbonding lower bound = F + E + C (see docs/ONCHAIN.md). Passed in so
    ///                     the gateway operator pins it to their own epoch/freshness
    ///                     parameters and the contract refuses an unsafe value.
    /// @param extraLimits additional admitted tiers (RLN userMessageLimit values), each in
    ///                     [1, MAX_LIMIT], distinct, != DEFAULT_LIMIT, in ascending order.
    /// @param extraBonds  the fixed bond of each extra tier (same length, each nonzero).
    ///                     Empty arrays = the pre-tier single-tier set (limit 8 only).
    constructor(
        uint256 bond,
        uint256 unbonding,
        uint256 minUnbonding,
        IWithdrawVerifier _withdrawVerifier,
        ICommitmentHasher _hasher,
        uint256[] memory extraLimits,
        uint256[] memory extraBonds
    ) {
        if (bond == 0) revert BadBond();
        if (unbonding < minUnbonding) revert UnbondingTooShort();
        BOND = bond;
        UNBONDING = unbonding;
        withdrawVerifier = _withdrawVerifier;
        hasher = _hasher;

        // Tier table: globally ascending, including extra limits below DEFAULT_LIMIT. Earlier
        // deployments only used limits above 8; the public low-rate profile adds limit 1 and
        // every consumer is promised an ascending table.
        if (extraLimits.length != extraBonds.length) revert BadTierTable();
        _bondOf[DEFAULT_LIMIT] = bond;
        uint256 prev = 0;
        bool pushedDefault = false;
        for (uint256 i = 0; i < extraLimits.length; i++) {
            uint256 lim = extraLimits[i];
            if (lim == 0 || lim > MAX_LIMIT || lim == DEFAULT_LIMIT) revert BadLimit();
            if (lim <= prev || _bondOf[lim] != 0) revert BadTierTable(); // ascending + distinct
            if (extraBonds[i] == 0) revert BadBond();
            if (!pushedDefault && lim > DEFAULT_LIMIT) {
                _allowedLimits.push(DEFAULT_LIMIT);
                pushedDefault = true;
            }
            _bondOf[lim] = extraBonds[i];
            _allowedLimits.push(lim);
            prev = lim;
        }
        if (!pushedDefault) _allowedLimits.push(DEFAULT_LIMIT);

        // Initialize the incremental tree's zero subtree roots and the empty-tree root.
        // _zeroes[0] = keccak256(GROUP_ID) >> 8 (Semaphore v3 `hash(id)` leaf zero value).
        uint256 zero = uint256(keccak256(abi.encodePacked(GROUP_ID))) >> 8;
        _zeroes[0] = zero;
        for (uint256 i = 1; i <= TREE_DEPTH; i++) {
            zero = PoseidonT3.hash([zero, zero]);
            _zeroes[i] = zero;
        }
        currentRoot = zero; // empty-tree root (depth-20 all-zero-leaf root)
    }

    // ---- incremental Merkle tree internals (T-DEV-9) --------------------------

    /// Set leaf `index` to `value` and recompute the root, walking the depth-20 path and
    /// updating every node on it. Mirrors the zk-kit IncrementalMerkleTree insert/update
    /// exactly: at each level the node's sibling is read from the sparse store (defaulting
    /// to the level's empty-subtree value), the parent is Poseidon2(left, right), and we
    /// ascend. Works for both an append (register) and an in-place overwrite (removal sets
    /// the leaf back to _zeroes[0]). Cost: TREE_DEPTH Poseidon2 hashes per call.
    function _updateLeaf(uint256 index, uint256 value) internal {
        uint256 node = value;
        uint256 idx = index;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            _treeNode[level][idx] = node;
            uint256 left;
            uint256 right;
            if (idx & 1 == 0) {
                left = node;
                right = _nodeAt(level, idx + 1);
            } else {
                left = _nodeAt(level, idx - 1);
                right = node;
            }
            node = PoseidonT3.hash([left, right]);
            idx >>= 1;
        }
        currentRoot = node;
    }

    /// The materialized node at (level, index), or the level's empty-subtree value when the
    /// slot was never written (0 sentinel; see `_treeNode`).
    function _nodeAt(uint256 level, uint256 index) internal view returns (uint256) {
        uint256 v = _treeNode[level][index];
        return v == 0 ? _zeroes[level] : v;
    }

    /// The leaf zero value (_zeroes[0]); exposed for cross-checking against the off-chain
    /// tree's `zeroValue`.
    function treeZeroValue() external view returns (uint256) {
        return _zeroes[0];
    }

    // ---- tier table views (T-FEAT-8b) ------------------------------------------

    /// The bond a member of tier `limit` posts (and gets back / loses); 0 = tier not admitted.
    function bondFor(uint256 limit) public view returns (uint256) {
        return _bondOf[limit];
    }

    /// The admitted tiers, ascending; always starts with DEFAULT_LIMIT.
    function allowedLimits() external view returns (uint256[] memory) {
        return _allowedLimits;
    }

    /// The tier `commitment` was staked at, or 0 if it holds no bond (active or exiting).
    /// The gateway's slash path uses this to name the tier of a reconstructed secret's leaf
    /// (lib/rln.mjs resolveSlashLeaf) before calling `slash(.., limit, ..)`.
    function limitOf(uint256 commitment) external view returns (uint256) {
        Member storage m = members[commitment];
        return m.bond == 0 ? 0 : uint256(m.limit);
    }

    // ---- register (R1) --------------------------------------------------------

    /// Permissionless. Post the tier's bond for a commitment. The commitment's secret is
    /// generated locally by the member and never revealed here, so registering
    /// reveals nothing but a pseudonymous leaf, its tier, and that tier's fixed stake
    /// amount. Fund this from a Layer-0 shielded (e.g. Railgun) fresh address for max
    /// anonymity. `limit` MUST be the userMessageLimit the leaf was derived with, else the
    /// member's proofs open a leaf the contract cannot slash at this tier and its exit
    /// proofs fail; the contract cannot see inside the leaf, so it trusts the declared tier
    /// exactly as far as the bond it prices (docs/ONCHAIN.md "Tiers on chain").
    function register(uint256 commitment, uint256 limit) public payable {
        uint256 bond = _bondOf[limit];
        if (bond == 0) revert BadLimit();
        if (msg.value != bond) revert BadBond();
        if (_exists(commitment)) revert AlreadyMember();

        uint64 index = nextIndex++;
        members[commitment] = Member({bond: bond, index: index, exitInitiatedAt: 0, limit: uint32(limit)});
        activeCount++;
        emit MemberRegistered(commitment, index, limit);
        _updateLeaf(index, commitment); // append the leaf; refresh currentRoot
    }

    /// The pre-tier entry point: register at DEFAULT_LIMIT for exactly BOND.
    function register(uint256 commitment) external payable {
        register(commitment, DEFAULT_LIMIT);
    }

    // ---- exit + withdraw (R2, R4) --------------------------------------------

    /// ZK-authorized. Start the unbonding clock and leave the admission root. The
    /// bond remains slashable for the whole UNBONDING window. Authorized by a proof
    /// of knowledge of the secret, not by msg.sender, so the exiting member stays
    /// anonymous. `context` here is fixed to the exit action.
    function initiateExit(uint256 commitment, bytes calldata proof) external {
        Member storage m = members[commitment];
        if (m.bond == 0) revert NotMember();
        if (m.exitInitiatedAt != 0) revert AlreadyExiting();

        bytes32 context = keccak256(abi.encodePacked("SHADE_TREE_EXIT", commitment));
        if (!withdrawVerifier.verify(commitment, uint256(m.limit), context, proof)) revert BadProof();

        m.exitInitiatedAt = uint64(block.timestamp);
        activeCount--; // no longer in the admission set, though still slashable
        emit MemberExiting(commitment, m.exitInitiatedAt, uint64(block.timestamp + UNBONDING));
        _updateLeaf(m.index, _zeroes[0]); // leave the admission root: zero the leaf in place
    }

    /// ZK-authorized. After UNBONDING elapses and if not slashed, pay BOND to a
    /// caller-named fresh recipient. Binding the recipient into the proof context
    /// stops a captured proof from being redirected. Unlinkable to the register tx
    /// at the address-graph level (only the pseudonymous commitment is common).
    function withdraw(uint256 commitment, address recipient, bytes calldata proof) external {
        Member storage m = members[commitment];
        if (m.bond == 0) revert NotMember();
        if (m.exitInitiatedAt == 0) revert NotExiting();
        if (block.timestamp < uint256(m.exitInitiatedAt) + UNBONDING) revert StillBonded();

        bytes32 context = keccak256(abi.encodePacked("SHADE_TREE_WITHDRAW", commitment, recipient));
        if (!withdrawVerifier.verify(commitment, uint256(m.limit), context, proof)) revert BadProof();

        uint256 amount = m.bond;
        delete members[commitment];
        emit MemberWithdrawn(commitment, recipient);

        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    // ---- slash (R3) -----------------------------------------------------------

    /// Permissionless. The gateway reconstructs a proven over-spender's secret from
    /// L+1 RLN shares (docs/ONCHAIN.md), then calls this. Possession of a valid
    /// (commitment, secret) pair is the authorization. A member also knows its own
    /// secret and can self-slash, but cannot redirect or recover the burned portion.
    /// Works whether the member is active or mid-unbonding, which is what closes the "exit to dodge slash"
    /// escape (R4). Pays floor(bond / 10) to `receiver` and the remainder to the fixed
    /// burn address. The receiver argument controls only the bounty, never the penalty.
    ///
    /// T-FEAT-8b: `limit` is the tier the slasher resolved for the leaf (the gateway's
    /// resolveSlashLeaf, or `limitOf(commitment)`). The leaf is recomputed at THAT limit,
    /// so the (commitment, secret, limit) triple must be consistent — a wrong limit is a
    /// different Poseidon output and reverts BadSecret; and it must equal the recorded tier
    /// (a leaf staked at 32 is, by construction, never Poseidon2(.., 8) of any secret, so this
    /// second check is belt-and-braces: BadLimit names the mismatch precisely).
    function slash(uint256 commitment, uint256 secret, uint256 limit, address receiver) public {
        Member storage m = members[commitment];
        if (m.bond == 0) revert NotMember();
        if (uint256(m.limit) != limit) revert BadLimit();
        if (hasher.commitmentOf(secret, limit) != commitment) revert BadSecret();

        uint256 amount = m.bond;
        uint256 reward = amount / SLASH_REWARD_DIVISOR;
        uint256 burned = amount - reward; // round toward the penalty, including bonds < 10 wei
        bool wasActive = m.exitInitiatedAt == 0;
        uint64 idx = m.index; // capture before delete for the tree update
        delete members[commitment];
        if (wasActive) activeCount--;
        emit MemberSlashed(commitment, receiver, limit);
        emit SlashPayout(commitment, receiver, burned, reward);
        // Zero the leaf ONLY if the member was still in the admission set. A slash of an
        // already-exiting member left the tree at initiateExit; re-zeroing would be a no-op
        // here but is skipped to mirror reconstructRoot (which ignores a removal event for a
        // commitment no longer live), keeping the two roots identical event-for-event.
        if (wasActive) _updateLeaf(idx, _zeroes[0]);

        (bool ok,) = SLASH_BURN_ADDRESS.call{value: burned}("");
        if (!ok) revert PayoutFailed();
        if (reward != 0) {
            (ok,) = receiver.call{value: reward}("");
            if (!ok) revert PayoutFailed(); // rolls back the burn, membership and root together
        }
    }

    /// The pre-tier ABI entry point: slash a DEFAULT_LIMIT leaf with the same mandatory burn.
    function slash(uint256 commitment, uint256 secret, address receiver) external {
        slash(commitment, secret, DEFAULT_LIMIT, receiver);
    }

    // ---- views ---------------------------------------------------------------

    function isActive(uint256 commitment) external view returns (bool) {
        Member storage m = members[commitment];
        return m.bond != 0 && m.exitInitiatedAt == 0;
    }

    function withdrawableAt(uint256 commitment) external view returns (uint256) {
        Member storage m = members[commitment];
        if (m.bond == 0 || m.exitInitiatedAt == 0) return 0;
        return uint256(m.exitInitiatedAt) + UNBONDING;
    }

    function _exists(uint256 commitment) internal view returns (bool) {
        return members[commitment].bond != 0;
    }
}
