// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "./Cheats.sol";
import {PaidAccessSet} from "../contracts/PaidAccessSet.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

/// T-FEAT-7 Layer 1: PaidAccessSet (docs/PAYMENTS.md), the operator-inserted paid-access
/// membership tree next to the staked set (payment settles OFF chain over HTTP 402 rails; no
/// funds ever touch this contract). Proven here: only the operator inserts (single + batch, at an
/// allowed tier only), live duplicate reverts + slashed re-insert appends fresh, events carry the
/// post-update root, slash needs the recorded tier + the right secret and moves nothing (the
/// contract holds no ETH, ever, and has no payable surface), two-step operator transfer,
/// ROOT_STORAGE_SLOT == 3 by `vm.load`, and the on-chain root equals the JS `newGroup` goldens
/// AND the live StakedReputationSet's root for the same leaf sequence (the tree code is a
/// verbatim copy; this is the parity proof).
contract PaidAccessSetTest is Cheats {
    PaidAccessSet set;
    RateCommitmentHasher hasher;
    address constant OPERATOR = address(0x0BE7A70B);
    address constant OPERATOR2 = address(0x0BE7A70B2);
    address constant RECEIVER = address(0xCAFE); // ignored by slash (nothing to pay)
    address constant STRANGER = address(0xBAD);

    uint256 constant SECRET_A = 111;
    uint256 constant SECRET_B = 222;
    uint256 constant SECRET_C = 333;
    uint256 constant SECRET_D = 444;

    // JS goldens (poseidon-lite / lib/rln.mjs deriveCommitment + newGroup), see the header of
    // test/StakedReputationSet.tiers.t.sol and:
    //   node -e 'import("./lib/rln.mjs").then(({newGroup,deriveCommitment})=>{ ... })'
    uint256 constant LEAF_A_8 = 11302006078516901731073162965056551612114122314181142374993834332168998510316;
    uint256 constant LEAF_B_32 = 6559234296040236204575836750760151586782987140458381330408475886232473073686;
    uint256 constant LEAF_C_8 = 5527131182811693631850291830791844533392664118062693956923196629560743717040;
    uint256 constant LEAF_D_32 = 4519864742717106018030752500708563870544915948666789533619234033036093092211;
    uint256 constant EMPTY_ROOT = 10354334201938752428558948798274962999644820234654929486063894213598717249307;
    uint256 constant ROOT_A8 = 21843396211530193797470373475386291320603740020342416123298140124981078029340;
    // newGroup([A8, B32, C8, D32]).root, then removeMember(2) (zero-in-place at index 2).
    uint256 constant ROOT_ABCD = 4632055583234330270221474381962843385276685307414569434965167052261759454697;
    uint256 constant ROOT_ABCD_MINUS_2 = 11425392560547100985267542376730718714021252002365897385059367313374831722850;
    uint256 constant TREE_ZERO_VALUE = 312829776796408387545637016147278514583116203736587368460269838669765409292;

    event Inserted(uint256 indexed commitment, uint256 limit, uint256 index, uint256 root);
    event Slashed(uint256 indexed commitment, uint256 limit, uint256 index, uint256 root);
    event OperatorTransferStarted(address indexed from, address indexed to);
    event OperatorTransferred(address indexed from, address indexed to);

    function _table() internal pure returns (uint256[] memory limits) {
        limits = new uint256[](2);
        limits[0] = 8;
        limits[1] = 32;
    }

    function _newSet(uint256[] memory limits) internal returns (PaidAccessSet) {
        return new PaidAccessSet(OPERATOR, ICommitmentHasher(address(hasher)), limits);
    }

    function setUp() public {
        hasher = new RateCommitmentHasher();
        set = _newSet(_table());
        vm.deal(address(this), 100 ether);
        vm.deal(STRANGER, 1 ether);
    }

    function _insert(uint256 leaf, uint256 limit) internal {
        vm.prank(OPERATOR);
        set.insert(leaf, limit);
    }

    // ---- constructor ---------------------------------------------------------------

    function test_Constructor_Views() public view {
        assertEq(set.operator(), OPERATOR);
        assertEq(set.pendingOperator(), address(0));
        assertEq(address(set.hasher()), address(hasher));
        assertEq(set.DEFAULT_LIMIT(), 8);
        assertEq(set.MAX_LIMIT(), 65535);
        assertTrue(set.isAllowedLimit(8) && set.isAllowedLimit(32), "table admits 8 and 32");
        assertFalse(set.isAllowedLimit(16), "unlisted tier not admitted");
        uint256[] memory lim = set.allowedLimits();
        assertEq(lim.length, 2);
        assertEq(lim[0], 8);
        assertEq(lim[1], 32);
        assertEq(set.leafCount(), 0);
        assertEq(set.liveCount(), 0);
        assertEq(set.currentRoot(), EMPTY_ROOT, "fresh set == empty depth-20 root");
        assertEq(set.treeZeroValue(), TREE_ZERO_VALUE);
        assertEq(set.commitmentOf(SECRET_A, 8), LEAF_A_8, "commitmentOf == tiered hasher == JS golden");
        assertEq(set.commitmentOf(SECRET_B, 32), LEAF_B_32);
        assertEq(set.limitOf(LEAF_A_8), 0, "unknown leaf -> 0");
        assertEq(address(set).balance, 0);
    }

    function test_Constructor_ZeroOperatorIsDeployer() public {
        PaidAccessSet s = new PaidAccessSet(address(0), ICommitmentHasher(address(hasher)), _table());
        assertTrue(s.operator() == address(this), "address(0) => msg.sender");
    }

    function test_Constructor_RejectsBadTables() public {
        uint256[] memory l = new uint256[](1);
        l[0] = 8;
        vm.expectRevert(PaidAccessSet.BadHasher.selector);
        new PaidAccessSet(OPERATOR, ICommitmentHasher(address(0)), l);
        vm.expectRevert(PaidAccessSet.BadTierTable.selector);
        _newSet(new uint256[](0));
        l[0] = 32; // missing DEFAULT_LIMIT
        vm.expectRevert(PaidAccessSet.BadTierTable.selector);
        _newSet(l);
        l[0] = 0;
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        _newSet(l);
        l[0] = 65536;
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        _newSet(l);
        uint256[] memory l2 = new uint256[](2);
        l2[0] = 32; l2[1] = 8; // not ascending
        vm.expectRevert(PaidAccessSet.BadTierTable.selector);
        _newSet(l2);
        l2[0] = 8; l2[1] = 8; // duplicate
        vm.expectRevert(PaidAccessSet.BadTierTable.selector);
        _newSet(l2);
        uint256[] memory l3 = new uint256[](3);
        l3[0] = 8; l3[1] = 32; l3[2] = 64;
        PaidAccessSet s = _newSet(l3);
        assertEq(s.allowedLimits().length, 3);
        assertTrue(s.isAllowedLimit(64));
    }

    // ---- insert -------------------------------------------------------------------

    function test_Insert_OnlyOperator() public {
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(LEAF_A_8, 8); // deployer / test contract is not the operator
        vm.prank(STRANGER);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(LEAF_A_8, 8);
        uint256[] memory c = new uint256[](1);
        uint256[] memory l = new uint256[](1);
        c[0] = LEAF_A_8; l[0] = 8;
        vm.prank(STRANGER);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insertBatch(c, l);
        assertEq(set.leafCount(), 0);
        assertEq(set.currentRoot(), EMPTY_ROOT, "rejected inserts leave the root alone");

        vm.prank(OPERATOR);
        vm.expectEmit(true, false, false, true);
        emit Inserted(LEAF_A_8, 8, 0, ROOT_A8);
        set.insert(LEAF_A_8, 8);
        assertEq(set.leafCount(), 1);
        assertEq(set.liveCount(), 1);
        assertEq(set.limitOf(LEAF_A_8), 8);
        (uint64 index, uint32 limit) = set.leaves(LEAF_A_8);
        assertEq(uint256(index), 0);
        assertEq(uint256(limit), 8);
        assertEq(set.currentRoot(), ROOT_A8, "root after one insert == newGroup([A8]).root");
        assertEq(address(set).balance, 0, "no funds, ever");
    }

    function test_Insert_UnlistedTierReverts() public {
        uint256 leaf16 = hasher.commitmentOf(SECRET_A, 16);
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.insert(leaf16, 16);
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.insert(LEAF_A_8, 0);
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.insert(LEAF_A_8, 70_000);
        assertEq(set.leafCount(), 0);
    }

    /// Duplicate policy: a LIVE commitment cannot be inserted twice (the leaf already buys an
    /// ongoing budget), and a SLASHED one is BURNED — it can never be inserted again, because the
    /// slash revealed its identitySecret and the leaf is spendable-to-zero by anyone.
    function test_Insert_DuplicatePolicy() public {
        _insert(LEAF_A_8, 8);
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.AlreadyInserted.selector);
        set.insert(LEAF_A_8, 8);
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.AlreadyInserted.selector);
        set.insert(LEAF_A_8, 32); // even at another tier
        assertEq(set.leafCount(), 1);

        _insert(LEAF_B_32, 32);                     // index 1
        set.slash(LEAF_A_8, SECRET_A, 8, RECEIVER); // zero @0; burns LEAF_A_8
        assertEq(set.limitOf(LEAF_A_8), 0);
        assertTrue(set.burned(LEAF_A_8), "a slashed commitment is burned");
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        set.insert(LEAF_A_8, 8);                    // a slashed leaf can never be re-inserted
        assertEq(set.leafCount(), 2, "no fresh leaf appended for a burned commitment");
        assertEq(set.liveCount(), 1, "only B_32 remains live");
    }

    /// Once a commitment is slashed its identitySecret is public (that reveal is how the leaf
    /// was zeroed), so the leaf is spendable-to-zero by anyone. A slashed commitment is BURNED and
    /// can never be admitted again — via insert or insertBatch, at its old tier or any other.
    function test_SlashedCommitment_CannotBeReinserted() public {
        _insert(LEAF_A_8, 8);                        // index 0
        set.slash(LEAF_A_8, SECRET_A, 8, RECEIVER);  // secret now public
        assertEq(set.limitOf(LEAF_A_8), 0, "slashed leaf is not live");
        assertTrue(set.burned(LEAF_A_8), "slashed commitment is burned");

        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        set.insert(LEAF_A_8, 8);                      // same tier
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        set.insert(LEAF_A_8, 32);                     // and any other tier

        // a batch that contains the burned commitment reverts the whole round (all-or-nothing)
        uint256[] memory c = new uint256[](2);
        uint256[] memory l = new uint256[](2);
        c[0] = LEAF_B_32; l[0] = 32;
        c[1] = LEAF_A_8;  l[1] = 8;
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        set.insertBatch(c, l);

        assertEq(set.leafCount(), 1, "no new leaf appended");
        assertEq(set.liveCount(), 0, "still nothing live");
    }

    function test_InsertBatch_AllOrNothing_EmitsPerLeaf() public {
        uint256[] memory c = new uint256[](4);
        uint256[] memory l = new uint256[](4);
        c[0] = LEAF_A_8;  l[0] = 8;
        c[1] = LEAF_B_32; l[1] = 32;
        c[2] = LEAF_C_8;  l[2] = 8;
        c[3] = LEAF_D_32; l[3] = 32;
        // empty / mismatched
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadBatch.selector);
        set.insertBatch(new uint256[](0), new uint256[](0));
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadBatch.selector);
        set.insertBatch(c, new uint256[](3));
        // one bad tier in the middle reverts the whole batch
        l[2] = 16;
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.insertBatch(c, l);
        assertEq(set.leafCount(), 0, "nothing from a reverted batch lands");
        assertEq(set.currentRoot(), EMPTY_ROOT);
        l[2] = 8;
        // a live duplicate inside the batch reverts it too
        _insert(LEAF_A_8, 8);                         // A8 (a batch leaf) live at index 0
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.AlreadyInserted.selector);
        set.insertBatch(c, l);
        assertEq(set.leafCount(), 1);
        // A slashed leaf is BURNED, so a live batch leaf cannot be "vacated" and re-batched;
        // the good-batch case is proven on a fresh set (indices 0..3) just below.

        // the good batch on a fresh set: four Inserted events, indices 0..3 in array order, and the
        // root equals the JS golden newGroup([A8,B32,C8,D32]).root.
        PaidAccessSet fresh = _newSet(_table());
        vm.prank(OPERATOR);
        vm.expectEmit(true, false, false, true);
        emit Inserted(LEAF_A_8, 8, 0, ROOT_A8);       // first event carries the root after leaf 0
        vm.expectEmit(true, false, false, false);
        emit Inserted(LEAF_B_32, 32, 1, 0);
        vm.expectEmit(true, false, false, false);
        emit Inserted(LEAF_C_8, 8, 2, 0);
        vm.expectEmit(true, false, false, false);
        emit Inserted(LEAF_D_32, 32, 3, 0);
        fresh.insertBatch(c, l);
        assertEq(fresh.leafCount(), 4);
        assertEq(fresh.liveCount(), 4);
        (uint64 iA,) = fresh.leaves(LEAF_A_8);
        (uint64 iD,) = fresh.leaves(LEAF_D_32);
        assertEq(uint256(iA), 0);
        assertEq(uint256(iD), 3);
        assertEq(fresh.currentRoot(), ROOT_ABCD, "batch root == newGroup([A8,B32,C8,D32]).root");
    }

    // ---- slash ---------------------------------------------------------------------

    function test_Slash_RequiresRecordedTierAndSecret_MovesNothing() public {
        _insert(LEAF_B_32, 32);
        vm.expectRevert(PaidAccessSet.NotInserted.selector);
        set.slash(LEAF_A_8, SECRET_A, 8, RECEIVER);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.slash(LEAF_B_32, SECRET_B, 8, RECEIVER);
        vm.expectRevert(PaidAccessSet.BadSecret.selector);
        set.slash(LEAF_B_32, SECRET_A, 32, RECEIVER);
        assertEq(set.limitOf(LEAF_B_32), 32, "failed slashes leave the leaf live");
        uint256 rootBefore = set.currentRoot();

        uint256 recvBefore = RECEIVER.balance;
        uint256 opBefore = OPERATOR.balance;
        vm.expectEmit(true, false, false, true);
        emit Slashed(LEAF_B_32, 32, 0, EMPTY_ROOT); // the only leaf zeroed -> back to the empty root
        set.slash(LEAF_B_32, SECRET_B, 32, RECEIVER);
        assertEq(set.limitOf(LEAF_B_32), 0, "slashed leaf gone");
        assertEq(set.liveCount(), 0);
        assertEq(set.leafCount(), 1, "leafCount counts appended leaves, slashed included");
        assertTrue(set.currentRoot() != rootBefore, "slash moves the root");
        assertEq(set.currentRoot(), EMPTY_ROOT);
        assertEq(RECEIVER.balance, recvBefore, "receiver gets NOTHING (nothing to burn)");
        assertEq(OPERATOR.balance, opBefore);
        assertEq(address(set).balance, 0);
        vm.expectRevert(PaidAccessSet.NotInserted.selector);
        set.slash(LEAF_B_32, SECRET_B, 32, RECEIVER);
    }

    function test_Slash_Permissionless() public {
        _insert(LEAF_A_8, 8);
        vm.prank(STRANGER);
        set.slash(LEAF_A_8, SECRET_A, 8, STRANGER);
        assertEq(set.limitOf(LEAF_A_8), 0);
    }

    // ---- no funds ------------------------------------------------------------------

    /// There is no payable function, no receive and no fallback: ETH cannot enter (a plain
    /// transfer and a value-carrying insert both revert), so the balance is 0 forever.
    function test_NoFunds_EthCannotEnter() public {
        (bool ok,) = address(set).call{value: 1 wei}("");
        assertFalse(ok, "plain transfer rejected (no receive/fallback)");
        vm.prank(OPERATOR);
        vm.deal(OPERATOR, 1 ether);
        (ok,) = address(set).call{value: 1 wei}(abi.encodeWithSignature("insert(uint256,uint256)", LEAF_A_8, 8));
        assertFalse(ok, "value-carrying insert rejected (not payable)");
        assertEq(address(set).balance, 0);
        assertEq(set.leafCount(), 0);
    }

    // ---- operator transfer (two-step) ---------------------------------------------------

    function test_Operator_TwoStepTransfer() public {
        // only the operator nominates
        vm.prank(STRANGER);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.setOperator(STRANGER);
        // nobody can accept without a nomination
        vm.prank(OPERATOR2);
        vm.expectRevert(PaidAccessSet.NotPendingOperator.selector);
        set.acceptOperator();
        // nominate: role unchanged until accepted
        vm.prank(OPERATOR);
        vm.expectEmit(true, true, false, true);
        emit OperatorTransferStarted(OPERATOR, OPERATOR2);
        set.setOperator(OPERATOR2);
        assertEq(set.operator(), OPERATOR);
        assertEq(set.pendingOperator(), OPERATOR2);
        _insert(LEAF_A_8, 8); // old operator still inserts
        vm.prank(OPERATOR2);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(LEAF_B_32, 32); // nominee cannot yet
        // a stranger cannot accept
        vm.prank(STRANGER);
        vm.expectRevert(PaidAccessSet.NotPendingOperator.selector);
        set.acceptOperator();
        // cancel + re-nominate
        vm.prank(OPERATOR);
        set.setOperator(address(0));
        vm.prank(OPERATOR2);
        vm.expectRevert(PaidAccessSet.NotPendingOperator.selector);
        set.acceptOperator();
        vm.prank(OPERATOR);
        set.setOperator(OPERATOR2);
        // accept: role moves, pending cleared
        vm.prank(OPERATOR2);
        vm.expectEmit(true, true, false, true);
        emit OperatorTransferred(OPERATOR, OPERATOR2);
        set.acceptOperator();
        assertEq(set.operator(), OPERATOR2);
        assertEq(set.pendingOperator(), address(0));
        vm.prank(OPERATOR);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(LEAF_B_32, 32); // old operator locked out
        vm.prank(OPERATOR2);
        set.insert(LEAF_B_32, 32);
        assertEq(set.leafCount(), 2);
        // second accept is not replayable
        vm.prank(OPERATOR2);
        vm.expectRevert(PaidAccessSet.NotPendingOperator.selector);
        set.acceptOperator();
    }

    // ---- storage slot + root parity ---------------------------------------------------

    function test_Root_StorageSlot3() public {
        assertEq(set.ROOT_STORAGE_SLOT(), 3);
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), set.currentRoot(), "empty root at slot 3");
        _insert(LEAF_A_8, 8);
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), set.currentRoot(), "slot 3 tracks currentRoot");
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), ROOT_A8);
        // and the operator transfer never disturbs slot 3 (operator lives after the tree)
        vm.prank(OPERATOR);
        set.setOperator(OPERATOR2);
        vm.prank(OPERATOR2);
        set.acceptOperator();
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), ROOT_A8, "slot 3 untouched by operator transfer");
    }

    function test_Root_MatchesJsGoldens() public {
        _insert(LEAF_A_8, 8);    // 0
        _insert(LEAF_B_32, 32);  // 1
        _insert(LEAF_C_8, 8);    // 2
        _insert(LEAF_D_32, 32);  // 3
        assertEq(set.currentRoot(), ROOT_ABCD, "root == newGroup([A8,B32,C8,D32]).root");
        set.slash(LEAF_C_8, SECRET_C, 8, RECEIVER);  // zero @2
        assertEq(set.currentRoot(), ROOT_ABCD_MINUS_2, "root == JS tree with index 2 zeroed in place");
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), ROOT_ABCD_MINUS_2);
    }

    /// The parity proof against the LIVE contract's tree code: drive a StakedReputationSet
    /// (rln-v4 tiers, mock exit verifier) and the PaidAccessSet through the same leaf sequence
    /// (register/insert at the same tiers, slash the same middle leaf) and compare roots after
    /// every step. Because the deployed staked set is immutable, PaidAccessSet duplicates its
    /// `_updateLeaf` / `_nodeAt`; this test is what keeps that duplication honest.
    function test_Root_ParityWithStakedReputationSet() public {
        MockWithdrawVerifier v = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        uint256[] memory xl = new uint256[](1);
        uint256[] memory xb = new uint256[](1);
        xl[0] = 32;
        xb[0] = 4 * 0.001 ether;
        StakedReputationSet staked = new StakedReputationSet(
            0.001 ether, 300, 270, IWithdrawVerifier(address(v)), ICommitmentHasher(address(hasher)), xl, xb
        );
        assertEq(staked.currentRoot(), set.currentRoot(), "empty roots equal");
        assertEq(staked.ROOT_STORAGE_SLOT(), set.ROOT_STORAGE_SLOT());
        assertEq(staked.treeZeroValue(), set.treeZeroValue());

        uint256[4] memory leavesArr = [LEAF_A_8, LEAF_B_32, LEAF_C_8, LEAF_D_32];
        uint256[4] memory lims = [uint256(8), 32, 8, 32];
        for (uint256 i = 0; i < 4; i++) {
            staked.register{value: staked.bondFor(lims[i])}(leavesArr[i], lims[i]);
            _insert(leavesArr[i], lims[i]);
            assertEq(staked.currentRoot(), set.currentRoot(), "roots equal after each append");
        }
        staked.slash(LEAF_B_32, SECRET_B, 32, RECEIVER);
        set.slash(LEAF_B_32, SECRET_B, 32, RECEIVER);
        assertEq(staked.currentRoot(), set.currentRoot(), "roots equal after slash-middle");
        // Re-append a FRESH leaf at index 4 (B32 is now burned in the paid set, so it cannot
        // be re-inserted here); the two trees must still track each other on the new append.
        uint256 leafA32 = hasher.commitmentOf(SECRET_A, 32); // distinct from every leaf so far
        staked.register{value: staked.bondFor(32)}(leafA32, 32);
        _insert(leafA32, 32);
        (, uint64 si,,) = staked.members(leafA32);
        (uint64 pi,) = set.leaves(leafA32);
        assertEq(uint256(si), 4);
        assertEq(uint256(pi), 4);
        assertEq(staked.currentRoot(), set.currentRoot(), "roots equal after re-append");
    }

    receive() external payable {}
}
