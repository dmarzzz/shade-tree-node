// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "./Cheats.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract StakedReputationSetTest is Cheats {
    // Demo params (docs/NEXT-VERSION.md), matching script/Deploy.s.sol.
    uint256 constant BOND = 0.01 ether;
    uint256 constant UNBONDING = 300;
    uint256 constant MIN_UNBONDING = 270;

    StakedReputationSet set;
    RateCommitmentHasher hasher;
    MockWithdrawVerifier verifier;

    // Two demo members. identitySecret in [0, F); the membership leaf is the RLN rate
    // commitment  = Poseidon(2)([ Poseidon(1)([identitySecret]), 8 ]).
    uint256 constant SECRET_A = 111;
    uint256 constant SECRET_B = 222;
    uint256 constant SECRET_C = 333; // third demo member, for the removal-parity test
    // Hardcoded rate commitment for SECRET_A=111, from poseidon-lite:
    //   poseidon2([poseidon1([111n]), 8n]). Pins the leaf a demo member registers.
    uint256 constant COMMIT_A_EXPECTED =
        11302006078516901731073162965056551612114122314181142374993834332168998510316;
    uint256 commitA;
    uint256 commitB;
    uint256 commitC;

    address constant RECIPIENT = address(0xBEEF);
    address constant RECEIVER = address(0xCAFE); // gateway/treasury slash receiver

    function setUp() public {
        hasher = new RateCommitmentHasher();
        verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        set = new StakedReputationSet(
            BOND,
            UNBONDING,
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            new uint256[](0),
            new uint256[](0)
        );
        commitA = hasher.commitmentOf(SECRET_A);
        commitB = hasher.commitmentOf(SECRET_B);
        commitC = hasher.commitmentOf(SECRET_C);
        vm.deal(address(this), 100 ether);
    }

    function _proof(uint256 secret) internal pure returns (bytes memory) {
        return abi.encode(secret);
    }

    // ---- constructor guard ----------------------------------------------------

    function test_Constructor_RejectsUnsafeUnbonding() public {
        vm.expectRevert(StakedReputationSet.UnbondingTooShort.selector);
        new StakedReputationSet(
            BOND,
            MIN_UNBONDING - 1, // below the F+E+C lower bound
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            new uint256[](0),
            new uint256[](0)
        );
    }

    function test_Constructor_RejectsZeroBond() public {
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        new StakedReputationSet(
            0,
            UNBONDING,
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            new uint256[](0),
            new uint256[](0)
        );
    }

    // ---- register (R1) --------------------------------------------------------

    function test_Register_Succeeds() public {
        set.register{value: BOND}(commitA);
        assertTrue(set.isActive(commitA), "A should be active");
        assertEq(set.activeCount(), 1);
        (uint256 bond, uint64 index, uint64 exitAt,) = set.members(commitA);
        assertEq(bond, BOND);
        assertEq(uint256(index), 0);
        assertEq(uint256(exitAt), 0);
        assertEq(address(set).balance, BOND);
    }

    function test_Register_RequiresExactBond() public {
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: BOND - 1}(commitA);

        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: BOND + 1}(commitA);

        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: 0}(commitA);
    }

    function test_Register_RejectsDuplicate() public {
        set.register{value: BOND}(commitA);
        vm.expectRevert(StakedReputationSet.AlreadyMember.selector);
        set.register{value: BOND}(commitA);
    }

    function test_Register_AppendOnlyIndex() public {
        set.register{value: BOND}(commitA);
        set.register{value: BOND}(commitB);
        (, uint64 idxA,,) = set.members(commitA);
        (, uint64 idxB,,) = set.members(commitB);
        assertEq(uint256(idxA), 0);
        assertEq(uint256(idxB), 1);
        assertEq(uint256(set.nextIndex()), 2);
        assertEq(set.activeCount(), 2);
    }

    // ---- initiateExit (R2/R4) -------------------------------------------------

    function test_InitiateExit_RequiresValidProof() public {
        set.register{value: BOND}(commitA);
        // wrong secret => verifier returns false => BadProof
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.initiateExit(commitA, _proof(SECRET_B));
        // malformed proof (not 32 bytes) => verifier returns false => BadProof
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.initiateExit(commitA, abi.encode(SECRET_A, SECRET_A));
    }

    function test_InitiateExit_StartsClockAndLeavesActiveSet() public {
        set.register{value: BOND}(commitA);
        uint256 t = block.timestamp;
        set.initiateExit(commitA, _proof(SECRET_A));

        assertFalse(set.isActive(commitA), "A should leave active set");
        assertEq(set.activeCount(), 0, "activeCount decremented on exit");
        assertEq(set.withdrawableAt(commitA), t + UNBONDING);
        // bond still held (still slashable through unbonding)
        assertEq(address(set).balance, BOND);
    }

    function test_InitiateExit_RejectsUnknownMember() public {
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.initiateExit(commitA, _proof(SECRET_A));
    }

    function test_InitiateExit_RejectsDoubleExit() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));
        vm.expectRevert(StakedReputationSet.AlreadyExiting.selector);
        set.initiateExit(commitA, _proof(SECRET_A));
    }

    // ---- withdraw (R2/R4) -----------------------------------------------------

    function test_Withdraw_BlockedBeforeExit() public {
        set.register{value: BOND}(commitA);
        vm.expectRevert(StakedReputationSet.NotExiting.selector);
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_A));
    }

    function test_Withdraw_BlockedBeforeUnbondingElapses() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));

        // one second short of the unbonding delay
        vm.warp(block.timestamp + UNBONDING - 1);
        vm.expectRevert(StakedReputationSet.StillBonded.selector);
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_A));
    }

    function test_Withdraw_SucceedsAfterUnbondingAndPaysRecipient() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));
        vm.warp(block.timestamp + UNBONDING);

        uint256 before = RECIPIENT.balance;
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_A));

        assertEq(RECIPIENT.balance - before, BOND, "recipient paid the bond");
        assertEq(address(set).balance, 0, "contract emptied");
        (uint256 bond,,,) = set.members(commitA);
        assertEq(bond, 0, "member deleted");
    }

    function test_Withdraw_RequiresValidProofEvenAfterUnbonding() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));
        vm.warp(block.timestamp + UNBONDING);
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_B));
    }

    // ---- slash (R3) -----------------------------------------------------------

    /// The linchpin, end to end: register the hardcoded rate-commitment leaf for a demo
    /// identitySecret, then slash by revealing that identitySecret. Proves the on-chain
    /// leaf (poseidon2([poseidon1([s]),8])) matches the value the crypto side computes,
    /// so a reconstructed secret slashes the right leaf and pays out.
    function test_Slash_RateCommitmentLeaf_RevealedSecret_Pays() public {
        // the leaf a member registers is exactly the poseidon-lite rate commitment
        assertEq(commitA, COMMIT_A_EXPECTED, "commitA must equal the hardcoded rate commitment");
        assertEq(
            hasher.commitmentOf(SECRET_A),
            COMMIT_A_EXPECTED,
            "on-chain commitmentOf(identitySecret) must equal poseidon2([poseidon1([s]),8])"
        );

        set.register{value: BOND}(COMMIT_A_EXPECTED);
        uint256 before = RECEIVER.balance;

        // revealing the identitySecret slashes the leaf
        set.slash(COMMIT_A_EXPECTED, SECRET_A, RECEIVER);
        assertEq(RECEIVER.balance - before, BOND / 10, "revealed identitySecret pays only the bounty");
        (uint256 bond,,,) = set.members(COMMIT_A_EXPECTED);
        assertEq(bond, 0, "slashed leaf deleted");

        // a WRONG secret does not hash to the leaf => BadSecret
        set.register{value: BOND}(commitB);
        vm.expectRevert(StakedReputationSet.BadSecret.selector);
        set.slash(commitB, SECRET_A, RECEIVER);
    }

    function test_Slash_ActiveMember_BurnsPenaltyPaysBounty() public {
        set.register{value: BOND}(commitA);
        uint256 before = RECEIVER.balance;

        set.slash(commitA, SECRET_A, RECEIVER);

        assertEq(RECEIVER.balance - before, BOND / 10, "receiver paid only the bounty");
        (uint256 bond,,,) = set.members(commitA);
        assertEq(bond, 0, "slashed member deleted");
        assertEq(set.activeCount(), 0, "activeCount decremented on slash of active member");
        assertFalse(set.isActive(commitA));
    }

    function test_Slash_RejectsWrongSecret() public {
        set.register{value: BOND}(commitA);
        vm.expectRevert(StakedReputationSet.BadSecret.selector);
        set.slash(commitA, SECRET_B, RECEIVER); // secret doesn't hash to commitA
    }

    function test_Slash_RejectsUnknownMember() public {
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.slash(commitA, SECRET_A, RECEIVER);
    }

    function test_Slash_WorksDuringUnbonding_AndBlocksLaterWithdraw() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));
        assertEq(set.activeCount(), 0);

        // over-spend detected mid-unbonding => slash lands
        uint256 before = RECEIVER.balance;
        set.slash(commitA, SECRET_A, RECEIVER);
        assertEq(RECEIVER.balance - before, BOND / 10, "slash pays only the bounty during unbonding");
        assertEq(set.activeCount(), 0, "already-exiting member not double-decremented");

        // the escape is closed: the later withdraw finds no bond
        vm.warp(block.timestamp + UNBONDING);
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_A));
    }

    // ---- leaf-removal parity (T-DEV-2) ----------------------------------------

    /// The on-chain half of the JS<->contract removal-parity proof
    /// (lib/rln-removal-parity.selftest.mjs). Register 3 members, slash the MIDDLE one, and
    /// assert the contract's leaf indexing is ZERO-IN-PLACE: the slashed member's index is
    /// NOT reused and the survivors keep their ORIGINAL indices (nextIndex is append-only,
    /// never renumbered). That immutable index assignment is exactly what the off-chain
    /// reconstructRoot mirrors: it appends leaves 0,1,2 in register order and vacates leaf 1
    /// on the middle slash, yielding GOLDEN_ROOT in the JS selftest. Because both sides use
    /// the SAME leaves (rate commitments for secrets 111/222/333) at the SAME indices, the
    /// JS root and the contract's membership state agree by construction.
    function test_Slash_Middle_PreservesIndices() public {
        set.register{value: BOND}(commitA); // index 0
        set.register{value: BOND}(commitB); // index 1 (the middle)
        set.register{value: BOND}(commitC); // index 2
        assertEq(uint256(set.nextIndex()), 3, "three appends -> nextIndex 3");
        assertEq(set.activeCount(), 3);

        // slash the MIDDLE member (commitB / index 1)
        set.slash(commitB, SECRET_B, RECEIVER);

        // the middle leaf is deleted...
        (uint256 bondB, , ,) = set.members(commitB);
        assertEq(bondB, 0, "middle member deleted");
        assertFalse(set.isActive(commitB));
        assertEq(set.activeCount(), 2, "one fewer active member");

        // ...but the survivors KEEP their original indices (zero-in-place, no renumber)...
        (uint256 bondA, uint64 idxA, ,) = set.members(commitA);
        (uint256 bondC, uint64 idxC, ,) = set.members(commitC);
        assertEq(bondA, BOND, "survivor A still bonded");
        assertEq(bondC, BOND, "survivor C still bonded");
        assertEq(uint256(idxA), 0, "survivor A keeps index 0");
        assertEq(uint256(idxC), 2, "survivor C keeps index 2 (NOT renumbered to 1)");

        // ...and the vacated index 1 is never reused: the next registration appends at 3.
        assertEq(uint256(set.nextIndex()), 3, "slash does not decrement/reuse nextIndex");
        set.register{value: BOND}(commitB); // re-register the same commitment
        (, uint64 idxBnew, ,) = set.members(commitB);
        assertEq(uint256(idxBnew), 3, "re-registration appends at a FRESH index, not the vacated 1");
    }

    // ---- on-chain incremental root (T-DEV-9) ----------------------------------

    // Golden roots of the RLN depth-20 Poseidon tree, computed by the off-chain reference
    // (lib/rln.mjs newGroup) and pinned here. The whole point of T-DEV-9 is that the
    // ON-CHAIN currentRoot equals what the off-chain reconstructRoot/newGroup produce for
    // the same membership ops, so a light client can prove the root via eth_getProof and
    // compare it to its locally reconstructed root. Recompute with:
    //   node -e 'import("./lib/rln.mjs").then(({newGroup})=>{const g=newGroup();console.log(g.root)})'
    uint256 constant EMPTY_ROOT =
        10354334201938752428558948798274962999644820234654929486063894213598717249307;
    // newGroup() with just commitA (secret 111) inserted at index 0.
    uint256 constant ROOT_A_ONLY =
        21843396211530193797470373475386291320603740020342416123298140124981078029340;
    // register c0@0, c1@1, c2@2 then remove the MIDDLE (index 1) -> zero-in-place. This is
    // the exact GOLDEN_ROOT from lib/rln-removal-parity.selftest.mjs (JS reconstructRoot ==
    // zero-in-place oracle). Both a slash and an initiateExit of the middle must reach it.
    uint256 constant GOLDEN_ROOT_MIDDLE_REMOVED =
        14367190620832145537223890636337926502210861635134078778082353204233456513838;
    // The Semaphore v3 leaf zero value = keccak256(GROUP_ID=1) >> 8.
    uint256 constant TREE_ZERO_VALUE =
        312829776796408387545637016147278514583116203736587368460269838669765409292;

    function test_Root_EmptyTree_IsAllZeroLeafRoot() public view {
        // fresh contract, no members: currentRoot is the depth-20 all-zero-leaf root.
        assertEq(set.currentRoot(), EMPTY_ROOT, "empty on-chain root == newGroup() root");
        assertEq(set.treeZeroValue(), TREE_ZERO_VALUE, "leaf zero value == keccak(GROUP_ID)>>8");
    }

    function test_Root_KnownStorageSlot() public {
        // The light client reads currentRoot at a fixed, known slot via eth_getProof. Pin it
        // so a storage reorder that moves the root fails here instead of silently.
        set.register{value: BOND}(commitA);
        bytes32 atSlot = vm.load(address(set), bytes32(set.ROOT_STORAGE_SLOT()));
        assertEq(uint256(atSlot), set.currentRoot(), "ROOT_STORAGE_SLOT holds currentRoot");
        assertEq(set.ROOT_STORAGE_SLOT(), 3, "root lives at storage slot 3");
    }

    function test_Root_SingleRegister_MatchesOffchain() public {
        set.register{value: BOND}(commitA);
        assertEq(set.currentRoot(), ROOT_A_ONLY, "root after one register == newGroup([c0]) root");
    }

    /// The T-DEV-9 acceptance property: after register-3 / slash-middle, the ON-CHAIN root
    /// equals the off-chain reconstructRoot zero-in-place golden. Proves the on-chain
    /// incremental tree mirrors lib/root-provider.mjs exactly.
    function test_Root_RegisterThreeSlashMiddle_EqualsReconstructRoot() public {
        set.register{value: BOND}(commitA); // index 0
        set.register{value: BOND}(commitB); // index 1 (middle)
        set.register{value: BOND}(commitC); // index 2
        set.slash(commitB, SECRET_B, RECEIVER); // zero leaf 1 in place
        assertEq(
            set.currentRoot(),
            GOLDEN_ROOT_MIDDLE_REMOVED,
            "on-chain root after slash-middle == off-chain reconstructRoot golden"
        );
    }

    /// initiateExit removes from the admission root exactly like a slash (reconstructRoot
    /// treats MemberExiting/MemberSlashed identically): register-3 / exit-middle reaches the
    /// SAME golden root as slash-middle.
    function test_Root_RegisterThreeExitMiddle_EqualsSlashMiddle() public {
        set.register{value: BOND}(commitA);
        set.register{value: BOND}(commitB);
        set.register{value: BOND}(commitC);
        set.initiateExit(commitB, _proof(SECRET_B)); // zero leaf 1 in place
        assertEq(
            set.currentRoot(),
            GOLDEN_ROOT_MIDDLE_REMOVED,
            "exit-middle root == slash-middle root (same zero-in-place removal)"
        );
    }

    /// Withdraw must NOT touch the tree (the leaf was already zeroed at initiateExit), and a
    /// slash of an already-exiting member must not re-zero: both keep the root stable.
    function test_Root_WithdrawAndReExitAreStable() public {
        set.register{value: BOND}(commitA);
        set.register{value: BOND}(commitB);
        set.initiateExit(commitB, _proof(SECRET_B));
        uint256 afterExit = set.currentRoot();

        // slash the already-exiting member: root unchanged (leaf already vacated)
        set.slash(commitB, SECRET_B, RECEIVER);
        assertEq(set.currentRoot(), afterExit, "slash of exiting member does not move the root");

        // register another member then exit+withdraw it; withdraw leaves the root as exit set it
        set.register{value: BOND}(commitC); // index 2
        set.initiateExit(commitC, _proof(SECRET_C));
        uint256 afterExitC = set.currentRoot();
        vm.warp(block.timestamp + UNBONDING);
        set.withdraw(commitC, RECIPIENT, _proof(SECRET_C));
        assertEq(set.currentRoot(), afterExitC, "withdraw does not move the root");
    }

    /// A removed leaf that is re-registered appends at a FRESH index (zero-in-place never
    /// reuses the vacated slot), so the root reflects leaves c0, zero, c2, c1 at indices
    /// 0,1,2,3 -- matching the off-chain reconstructRoot re-registration case.
    function test_Root_ReRegisterAfterSlash_AppendsFreshLeaf() public {
        set.register{value: BOND}(commitA); // 0
        set.register{value: BOND}(commitB); // 1
        set.register{value: BOND}(commitC); // 2
        set.slash(commitB, SECRET_B, RECEIVER); // zero @1
        uint256 rMiddleGone = set.currentRoot();

        set.register{value: BOND}(commitB); // re-append at index 3 (NOT the vacated 1)
        (, uint64 idxNew,,) = set.members(commitB);
        assertEq(uint256(idxNew), 3, "re-register appends at fresh index 3");
        // the root must change (a new live leaf at index 3) and differ from the middle-gone root
        assertTrue(set.currentRoot() != rMiddleGone, "re-register moves the root (fresh leaf)");
    }

    // ---- re-registration ------------------------------------------------------

    function test_ReRegister_AfterWithdraw() public {
        set.register{value: BOND}(commitA);
        set.initiateExit(commitA, _proof(SECRET_A));
        vm.warp(block.timestamp + UNBONDING);
        set.withdraw(commitA, RECIPIENT, _proof(SECRET_A));

        // commitment was deleted, so it can be registered again (new leaf index)
        set.register{value: BOND}(commitA);
        assertTrue(set.isActive(commitA), "re-registered after withdraw");
        (, uint64 idx,,) = set.members(commitA);
        assertEq(uint256(idx), 1, "re-registration gets a fresh append-only index");
    }

    function test_ReRegister_AfterSlash() public {
        set.register{value: BOND}(commitA);
        set.slash(commitA, SECRET_A, RECEIVER);

        set.register{value: BOND}(commitA);
        assertTrue(set.isActive(commitA), "re-registered after slash");
        assertEq(set.activeCount(), 1);
    }

    // allow this test contract to receive ETH if ever named as a recipient
    receive() external payable {}
}
