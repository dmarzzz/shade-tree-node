// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// PaidAccessSet: the paid-access membership tree for Shade Tree
// (docs/PAYMENTS.md "Layer 1", T-FEAT-7). It is the structural sibling of the live
// StakedReputationSet (contracts/StakedReputationSet.sol, rln-v4-tiers): the SAME on-chain
// depth-20 Poseidon(2) incremental Merkle tree, the SAME leaf (the RLN rate commitment
// Poseidon2(Poseidon1(identitySecret), userMessageLimit), computed by the SAME tiered
// RateCommitmentHasher), the SAME immutable allowed-tier table, the SAME zero-in-place removal
// on slash, and `currentRoot` in the SAME storage slot (ROOT_STORAGE_SLOT = 3), so every
// off-chain reader that already understands the staked set (lib/root-provider.mjs
// NodeRootProvider / LightClientRootProvider, the gateway's tiered slasher, `shade-tree`'s ABI probes:
// DEFAULT_LIMIT / allowedLimits / limitOf) works against this contract unchanged. The gateway
// trusts the UNION of the roots of both sets.
//
// What is different is where the money goes: NOT HERE. NO FUNDS EVER TOUCH THIS CONTRACT.
// Payment is settled OFF this contract, over HTTP 402 rails (x402 / MPP, USDC or another
// stablecoin on the same chain), by a registrar the operator runs; the stablecoin goes straight
// to the operator's address in that settlement. This contract's only job is to be the paid-access
// membership tree the operator INSERTS into after a settlement clears:
//   insert(commitment, limit)        onlyOperator: append the buyer's leaf at an allowed tier,
//                                    emit Inserted. Nothing payable.
//   insertBatch(commitments, limits) onlyOperator: the same for an issuance round in one tx
//                                    (cheaper per leaf, and batching is what grows the anonymity
//                                    set of a round: docs/PAYMENTS.md open item 3).
//   NO exit, NO withdraw:            access is not refundable. The buyer redeems the leaf OFF
//                                    CHAIN, to the gateway, with the ordinary RLN membership
//                                    proof against this contract's root (docs/PAYMENTS.md "The
//                                    redemption is the proof you already verify"); the gateway
//                                    sees a proof, not a buyer.
//   slash(commitment, secret, limit, receiver)
//                                    permissionless, gated by knowledge of the secret exactly
//                                    like StakedReputationSet.slash: the gateway reconstructs an
//                                    over-spender's identitySecret from L+1 RLN shares and zeroes
//                                    the leaf in place (the buyer loses the access they bought).
//                                    THERE IS NOTHING TO BURN: no bond is held here, so `receiver`
//                                    receives nothing — the argument is kept so the call shape is
//                                    identical to the staked set's and one gateway slasher drives
//                                    both sets.
//   setOperator / acceptOperator     two-step operator transfer (the registrar key rotates).
//
// The honest trust statement (docs/PAYMENTS.md "Why off-chain redemption, stated plainly"): the
// operator could take a payment and not insert, or insert and refuse to honor a valid proof.
// That is buyer-seller trust, irreducible for any prepaid service; no third party is added. What
// the contract gives is a PUBLIC, light-client-provable record of exactly which leaves the
// operator admitted (every insert is an event + a root move), and cryptographic UNLINKABILITY of
// payer to user (the redemption is a zk membership proof over this tree). The operator's
// off-chain settlement rail sees the payer; this contract never does.
//
// A buyer's anonymity is bounded by the number of leaves under the root the gateway accepts
// (`leafCount()`), which is why the gateway logs it against a floor (docs/PAYMENTS.md open
// item 3), and by the buyer's OWN choice of funding address on the settlement rail.
//
// REFERENCE implementation, unaudited, testnet-only. The operator can ONLY insert (at the fixed
// tiers) and hand the role over; it cannot add tiers, move or remove a leaf, or pause. No
// upgrade path.

import {PoseidonT3} from "./PoseidonT3.sol";
import {ICommitmentHasher} from "./StakedReputationSet.sol";

contract PaidAccessSet {
    // ---- immutable parameters -------------------------------------------------

    /// The tiered rate-commitment hasher (RateCommitmentHasher, `commitmentOf(secret, limit)`),
    /// used by `slash` to check a revealed secret against the leaf at its recorded tier.
    ICommitmentHasher public immutable hasher;

    /// The default per-member message limit (RLN userMessageLimit K = 8). Always in the tier
    /// table; the tier off-chain tooling assumes when none is named.
    uint256 public constant DEFAULT_LIMIT = 8;
    /// App-level upper bound on a tier limit: the circuit range-checks messageId with
    /// LessThan(16), which is NOT sound for a limit >= 2^16 (lib/rln.mjs MAX_LIMIT).
    uint256 public constant MAX_LIMIT = 65535;

    // ---- leaf state -----------------------------------------------------------
    //
    // Storage layout is deliberately the staked set's: slots 0..2 are the per-leaf record, the
    // append counter and the live counter; slot 3 is `currentRoot` (see below).

    struct Leaf {
        uint64 index; // append-only leaf index (immutable once assigned)
        uint32 limit; // the tier (RLN userMessageLimit) the leaf was inserted at; 0 = not live
    }

    mapping(uint256 => Leaf) public leaves; // commitment => Leaf   (storage slot 0)
    uint64 public nextIndex;                // append-only leaf counter == leafCount() (slot 1)
    uint256 public liveCount;               // leaves currently in the root (slot 2)

    // ---- on-chain incremental Merkle tree (identical to StakedReputationSet, T-DEV-9) ------
    //
    // MUST mirror the off-chain tree exactly (lib/rln.mjs newGroup / root-provider.mjs
    // reconstructRoot): depth 20, arity 2, Poseidon(2) over BN254, zero value
    // `keccak256(GROUP_ID) >> 8`, removals ZERO-IN-PLACE at the leaf's original index. The tree
    // code below is a verbatim copy of StakedReputationSet's `_updateLeaf` / `_nodeAt` (the
    // deployed staked set is immutable, so it is duplicated rather than refactored);
    // test/PaidAccessSet.t.sol drives BOTH contracts through the same leaf sequence and asserts
    // identical roots, and pins the same JS goldens.

    uint256 public constant TREE_DEPTH = 20; // circom-rln RLN(20,16); matches lib/rln.mjs TREE_DEPTH
    uint256 public constant GROUP_ID = 1;    // MUST equal the JS SHADE_TREE_RLN_IDENTIFIER (default 1)

    /// The current membership Merkle root, in a fixed storage slot so a light client can prove
    /// it via `eth_getProof` (lib/root-provider.mjs LightClientRootProvider reads slot 3 of any
    /// set). Declared FIRST among the tree state, AFTER exactly three state slots, so it is
    /// storage slot `ROOT_STORAGE_SLOT` == 3, the same slot as StakedReputationSet.currentRoot.
    /// The empty tree's root is the depth-20 all-zero-leaf root (NOT zero).
    uint256 public currentRoot;

    /// The storage slot `currentRoot` occupies. Asserted with `vm.load(addr, bytes32(3))` in
    /// test/PaidAccessSet.t.sol so a storage reorder fails loudly.
    uint256 public constant ROOT_STORAGE_SLOT = 3;

    uint256[TREE_DEPTH + 1] private _zeroes;                              // empty-subtree roots per level
    mapping(uint256 => mapping(uint256 => uint256)) private _treeNode;    // [level][index] => node (0 = unset)

    // ---- tier table — declared AFTER the tree so currentRoot stays at slot 3 --------------
    //
    // limit => allowed. Fixed at construction, no setter: the operator cannot admit a tier the
    // table does not name, so a leaf's declared budget class is bounded on chain exactly as in
    // the staked set. Pricing lives entirely on the 402 rail (off chain).
    mapping(uint256 => bool) private _allowed;
    uint256[] private _allowedLimits; // ascending, distinct; always contains DEFAULT_LIMIT

    // ---- operator (the registrar key) — declared LAST; two-step transfer -------------------

    /// The one address allowed to insert. Rotated with setOperator + acceptOperator (two-step,
    /// so a fat-fingered address cannot brick issuance: the old operator keeps the role until
    /// the new one proves it holds the key).
    address public operator;
    address public pendingOperator;

    /// Commitments that have been slashed. A slash reveals the identitySecret (revealing it is
    /// what authorises the removal), so the secret is now public and the leaf is spendable-to-zero
    /// by anyone; it must never be admitted again. Declared LAST so `currentRoot` stays at storage
    /// slot 3 (the light-client path).
    mapping(uint256 => bool) public burned;

    // ---- events ---------------------------------------------------------------

    /// A leaf was admitted after an off-chain settlement; `root` is currentRoot AFTER the
    /// insertion, so an off-chain reader can cross-check its reconstruction event by event.
    event Inserted(uint256 indexed commitment, uint256 limit, uint256 index, uint256 root);
    /// A leaf was zeroed in place after a proven over-spend; `root` is currentRoot AFTER.
    event Slashed(uint256 indexed commitment, uint256 limit, uint256 index, uint256 root);
    event OperatorTransferStarted(address indexed from, address indexed to);
    event OperatorTransferred(address indexed from, address indexed to);

    error BadLimit();
    error BadTierTable();
    error BadHasher();
    error BadBatch();
    error AlreadyInserted();
    error NotInserted();
    error BurnedCommitment();
    error BadSecret();
    error NotOperator();
    error NotPendingOperator();

    /// @param _operator  the registrar / insert authority; address(0) => the deployer (msg.sender).
    /// @param _hasher    the TIERED RateCommitmentHasher (`commitmentOf(secret, limit)`).
    /// @param limits     the tiers this set admits (RLN userMessageLimit values): non-empty,
    ///                   ascending, distinct, each in [1, MAX_LIMIT], and containing DEFAULT_LIMIT (8).
    constructor(address _operator, ICommitmentHasher _hasher, uint256[] memory limits) {
        operator = _operator == address(0) ? msg.sender : _operator;
        if (address(_hasher) == address(0)) revert BadHasher();
        hasher = _hasher;

        // Tier table (validated: non-empty, ascending, distinct, in range, has DEFAULT_LIMIT).
        if (limits.length == 0) revert BadTierTable();
        uint256 prev = 0;
        bool hasDefault = false;
        for (uint256 i = 0; i < limits.length; i++) {
            uint256 lim = limits[i];
            if (lim == 0 || lim > MAX_LIMIT) revert BadLimit();
            if (lim <= prev) revert BadTierTable(); // ascending + distinct
            _allowed[lim] = true;
            _allowedLimits.push(lim);
            if (lim == DEFAULT_LIMIT) hasDefault = true;
            prev = lim;
        }
        if (!hasDefault) revert BadTierTable();

        // Initialize the incremental tree's zero subtree roots and the empty-tree root
        // (identical to StakedReputationSet's constructor).
        uint256 zero = uint256(keccak256(abi.encodePacked(GROUP_ID))) >> 8;
        _zeroes[0] = zero;
        for (uint256 i = 1; i <= TREE_DEPTH; i++) {
            zero = PoseidonT3.hash([zero, zero]);
            _zeroes[i] = zero;
        }
        currentRoot = zero; // empty-tree root (depth-20 all-zero-leaf root)
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    // ---- incremental Merkle tree internals (verbatim from StakedReputationSet) ------------

    /// Set leaf `index` to `value` and recompute the root along the depth-20 path (append when
    /// `value` is a fresh leaf, zero-in-place removal when it is _zeroes[0]). TREE_DEPTH
    /// Poseidon2 hashes per call.
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

    function _nodeAt(uint256 level, uint256 index) internal view returns (uint256) {
        uint256 v = _treeNode[level][index];
        return v == 0 ? _zeroes[level] : v;
    }

    /// The leaf zero value (_zeroes[0]); cross-check against the off-chain tree's `zeroValue`.
    function treeZeroValue() external view returns (uint256) {
        return _zeroes[0];
    }

    // ---- views ---------------------------------------------------------------

    /// Whether tier `limit` may be inserted here.
    function isAllowedLimit(uint256 limit) public view returns (bool) {
        return _allowed[limit];
    }

    /// The admitted tiers, ascending; always contains DEFAULT_LIMIT.
    function allowedLimits() external view returns (uint256[] memory) {
        return _allowedLimits;
    }

    /// Total leaves ever appended (== nextIndex): the size of the tree the root commits to and
    /// the anonymity-set figure the gateway logs against its floor. Slashed leaves are zeroed
    /// in place and STILL count here (their index is never reused); `liveCount` is the number
    /// of leaves currently in the root.
    function leafCount() external view returns (uint256) {
        return uint256(nextIndex);
    }

    /// The leaf a buyer with `secret` at tier `limit` is inserted as: the RLN rate commitment
    /// via the tiered hasher (reverts BadLimit there outside [1, MAX_LIMIT]).
    function commitmentOf(uint256 secret, uint256 limit) external view returns (uint256) {
        return hasher.commitmentOf(secret, limit);
    }

    /// The tier `commitment` is live at, or 0 if it was never inserted or has been slashed.
    /// The gateway's slasher uses this to find which set (and which tier) holds a leaf.
    function limitOf(uint256 commitment) external view returns (uint256) {
        return uint256(leaves[commitment].limit);
    }

    // ---- insert (operator, after an off-chain 402 settlement) ---------------------------

    /// onlyOperator. Admit the leaf `commitment` at tier `limit` (must be in the immutable
    /// table: BadLimit). Appends the leaf and refreshes currentRoot; nothing payable, no external
    /// calls. `limit` MUST be the userMessageLimit the buyer derived the leaf with (the contract
    /// cannot see inside the leaf; a mismatch buys nothing: the gateway enforces the leaf's real
    /// budget and the leaf can never be slashed at the wrong tier). A commitment that is
    /// currently live cannot be inserted again (AlreadyInserted): the leaf already buys an
    /// ongoing per-epoch budget. A slashed commitment is BURNED and can NEVER be inserted again
    /// (BurnedCommitment): slashing reveals its identitySecret, so the leaf is spendable-to-zero by
    /// anyone. The vacated slot is never reused.
    function insert(uint256 commitment, uint256 limit) external onlyOperator {
        _insert(commitment, limit);
    }

    /// onlyOperator. `insert` for a whole issuance round in one transaction: all-or-nothing
    /// (any bad tier / live duplicate reverts the batch), one Inserted event per leaf, leaves
    /// appended in array order. Empty or mismatched arrays revert BadBatch.
    function insertBatch(uint256[] calldata commitments, uint256[] calldata limits) external onlyOperator {
        if (commitments.length == 0 || commitments.length != limits.length) revert BadBatch();
        for (uint256 i = 0; i < commitments.length; i++) {
            _insert(commitments[i], limits[i]);
        }
    }

    function _insert(uint256 commitment, uint256 limit) internal {
        if (!_allowed[limit]) revert BadLimit();
        if (burned[commitment]) revert BurnedCommitment(); // slashed => secret public, never re-admit
        if (leaves[commitment].limit != 0) revert AlreadyInserted();

        uint64 index = nextIndex++;
        leaves[commitment] = Leaf({index: index, limit: uint32(limit)});
        liveCount++;
        _updateLeaf(index, commitment); // append the leaf; refresh currentRoot
        emit Inserted(commitment, limit, index, currentRoot);
    }

    // ---- slash ---------------------------------------------------------------

    /// Permissionless, gated by knowledge of the secret (a valid (commitment, secret, limit)
    /// triple only exists after a genuine RLN over-spend, exactly as in the staked set): zero
    /// the leaf in place so the over-spender's proofs stop verifying against the next root, and
    /// BURN the commitment so it can never be re-inserted (the revealed secret is now public).
    /// NO FUNDS ARE BURNED OR PAID: no funds are held here, so `receiver` receives nothing (kept
    /// for call-shape parity with StakedReputationSet.slash so one gateway slasher drives both
    /// sets). Reverts NotInserted (leaf not live), BadLimit (`limit` != the recorded tier),
    /// BadSecret (the secret does not hash to the leaf at that tier), in that order.
    function slash(uint256 commitment, uint256 secret, uint256 limit, address /* receiver */) external {
        Leaf storage l = leaves[commitment];
        if (l.limit == 0) revert NotInserted();
        if (uint256(l.limit) != limit) revert BadLimit();
        if (hasher.commitmentOf(secret, limit) != commitment) revert BadSecret();

        uint64 idx = l.index;
        delete leaves[commitment];
        burned[commitment] = true;
        liveCount--;
        _updateLeaf(idx, _zeroes[0]); // zero the leaf in place; refresh currentRoot
        emit Slashed(commitment, limit, idx, currentRoot);
    }

    // ---- operator transfer (two-step) ---------------------------------------------------

    /// onlyOperator. Nominate `to` as the next operator; nothing changes until `to` accepts.
    /// Passing address(0) cancels a pending nomination.
    function setOperator(address to) external onlyOperator {
        pendingOperator = to;
        emit OperatorTransferStarted(operator, to);
    }

    /// The nominee takes the role. Only the pending operator may call.
    function acceptOperator() external {
        if (msg.sender == address(0) || msg.sender != pendingOperator) revert NotPendingOperator();
        address from = operator;
        operator = msg.sender;
        pendingOperator = address(0);
        emit OperatorTransferred(from, msg.sender);
    }
}
