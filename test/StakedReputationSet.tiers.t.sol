// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "./Cheats.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";
import {WithdrawGroth16Verifier} from "../contracts/WithdrawGroth16Verifier.sol";
import {WithdrawVerifier} from "../contracts/WithdrawVerifier.sol";

/// T-FEAT-8b: reputation tiers ON CHAIN (docs/adr/0006-reputation-tiers.md, docs/ONCHAIN.md
/// "Tiers on chain"). A tier is the leaf's private RLN userMessageLimit; this contract now
/// records it, prices admission per tier, and slashes at the claimed tier.
///
/// What is proven here (the ADR's Foundry ask): a tier-32 leaf slashes ONLY with limit 32
/// and burns the tier-32 bond; a tier-8 leaf only with limit 8; the legacy one-argument
/// paths retain the rln-v3 selectors (limit 8) and enforce the same burn; the tiered hasher matches the JS
/// goldens (lib/tiers.selftest.mjs / rust tree_parity `rate_commitment_tiers_*`); a
/// two-tier tree's on-chain root equals the JS newGroup root; the REAL Groth16 exit proof
/// authorizes the same identity's tier-32 leaf when the set passes 32 (and never at 8).
contract StakedReputationSetTiersTest is Cheats {
    uint256 constant BOND = 0.01 ether; // tier 8
    uint256 constant BOND32 = 4 * BOND; // tier 32 (docs/ONCHAIN.md example table)
    uint256 constant PUBLIC_BOND = 0.1 ether; // tier 1 public Sepolia profile
    uint256 constant UNBONDING = 300;
    uint256 constant MIN_UNBONDING = 270;

    StakedReputationSet set;
    RateCommitmentHasher hasher;
    MockWithdrawVerifier verifier;

    uint256 constant SECRET_A = 111;
    uint256 constant SECRET_B = 222;
    uint256 constant SECRET_C = 333;

    // JS goldens: poseidon2([poseidon1([s]), limit]) (poseidon-lite), see the header.
    uint256 constant LEAF_A_8 = 11302006078516901731073162965056551612114122314181142374993834332168998510316;
    uint256 constant LEAF_A_32 = 15363698809722346745616993869789510363416645981863858152379739283427647190637;
    uint256 constant LEAF_A_64 = 752151844580547856361140321410438225793123938984450609976488660829856464371;
    uint256 constant LEAF_B_32 = 6559234296040236204575836750760151586782987140458381330408475886232473073686;
    uint256 constant LEAF_C_32 = 13578725982537756154216427591212680693581654199467726022384131873183677257483;
    uint256 constant LEAF_1_32 = 21870821934631409796951764463230306021276785678227429566889140684627332455916;
    // newGroup([leafA8, leafB32]).root  and  newGroup([leafA8, leafB32, leafC32]) minus index 1.
    uint256 constant ROOT_A8_B32 = 999545622477661542770851523408301966697872713731637418335043567790453142627;
    uint256 constant ROOT_A8_C32_MIDDLE_REMOVED =
        20065059751002061676348401220246220318416130971542254276689180612584217408439;

    address constant RECIPIENT = address(0xBEEF);
    address constant RECEIVER = address(0xCAFE);

    event MemberRegistered(uint256 indexed commitment, uint64 indexed index, uint256 limit);
    event MemberSlashed(uint256 indexed commitment, address indexed receiver, uint256 limit);

    function _tiers32() internal pure returns (uint256[] memory limits, uint256[] memory bonds) {
        limits = new uint256[](1);
        bonds = new uint256[](1);
        limits[0] = 32;
        bonds[0] = BOND32;
    }

    function _newSet(uint256[] memory limits, uint256[] memory bonds, IWithdrawVerifier v)
        internal
        returns (StakedReputationSet)
    {
        return new StakedReputationSet(
            BOND, UNBONDING, MIN_UNBONDING, v, ICommitmentHasher(address(hasher)), limits, bonds
        );
    }

    function setUp() public {
        hasher = new RateCommitmentHasher();
        verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        (uint256[] memory limits, uint256[] memory bonds) = _tiers32();
        set = _newSet(limits, bonds, IWithdrawVerifier(address(verifier)));
        vm.deal(address(this), 100 ether);
    }

    function _proof(uint256 secret) internal pure returns (bytes memory) {
        return abi.encode(secret);
    }

    // ---- tiered hasher: byte-equivalent at 8, JS goldens at 32/64 -----------------

    function test_Hasher_TwoArgAtDefault_EqualsOneArg() public view {
        assertEq(hasher.commitmentOf(SECRET_A, 8), hasher.commitmentOf(SECRET_A), "limit 8 == legacy K=8 path");
        assertEq(hasher.commitmentOf(SECRET_A, 8), LEAF_A_8);
        assertEq(hasher.K(), 8);
        assertEq(hasher.MAX_LIMIT(), 65535);
    }

    function test_Hasher_MatchesJsTierGoldens() public view {
        assertEq(hasher.commitmentOf(SECRET_A, 32), LEAF_A_32, "poseidon2([poseidon1([111]),32])");
        assertEq(hasher.commitmentOf(SECRET_A, 64), LEAF_A_64, "poseidon2([poseidon1([111]),64])");
        assertEq(hasher.commitmentOf(SECRET_B, 32), LEAF_B_32);
        assertEq(hasher.commitmentOf(1, 32), LEAF_1_32);
        // a different limit is a different leaf (tiers never collide)
        assertTrue(hasher.commitmentOf(SECRET_A, 32) != hasher.commitmentOf(SECRET_A, 8), "tier leaves distinct");
    }

    function test_Hasher_RejectsOutOfRangeLimit() public {
        vm.expectRevert(RateCommitmentHasher.BadLimit.selector);
        hasher.commitmentOf(SECRET_A, 0);
        vm.expectRevert(RateCommitmentHasher.BadLimit.selector);
        hasher.commitmentOf(SECRET_A, 65536); // LessThan(16) unsound at 2^16
        assertTrue(hasher.commitmentOf(SECRET_A, 65535) != 0, "MAX_LIMIT itself is admitted");
    }

    // ---- tier table --------------------------------------------------------------

    function test_TierTable_Views() public view {
        assertEq(set.DEFAULT_LIMIT(), 8);
        assertEq(set.MAX_LIMIT(), 65535);
        assertEq(set.bondFor(8), BOND, "default tier costs BOND");
        assertEq(set.bondFor(32), BOND32);
        assertEq(set.bondFor(16), 0, "unadmitted tier -> 0");
        uint256[] memory lim = set.allowedLimits();
        assertEq(lim.length, 2);
        assertEq(lim[0], 8);
        assertEq(lim[1], 32);
        assertEq(set.limitOf(LEAF_A_8), 0, "no member -> 0");
    }

    function test_TierTable_SingleTierWhenNoExtras() public {
        StakedReputationSet s = _newSet(new uint256[](0), new uint256[](0), IWithdrawVerifier(address(verifier)));
        uint256[] memory lim = s.allowedLimits();
        assertEq(lim.length, 1);
        assertEq(lim[0], 8);
        assertEq(s.bondFor(32), 0);
    }

    function test_TierTable_LimitOnePublicProfile_IsGloballyAscending() public {
        uint256[] memory limits = new uint256[](1);
        uint256[] memory bonds = new uint256[](1);
        limits[0] = 1;
        bonds[0] = PUBLIC_BOND;
        StakedReputationSet s = _newSet(limits, bonds, IWithdrawVerifier(address(verifier)));

        uint256[] memory admitted = s.allowedLimits();
        assertEq(admitted.length, 2);
        assertEq(admitted[0], 1, "the one-tunnel tier sorts before the legacy tier 8");
        assertEq(admitted[1], 8);
        assertEq(s.bondFor(1), PUBLIC_BOND, "0.1 ETH buys the limit-1 tier");

        uint256 leaf = hasher.commitmentOf(SECRET_A, 1);
        s.register{value: PUBLIC_BOND}(leaf, 1);
        assertTrue(s.isActive(leaf));
        assertEq(s.limitOf(leaf), 1);
    }

    function test_Constructor_RejectsBadTierTables() public {
        uint256[] memory one = new uint256[](1);
        uint256[] memory two = new uint256[](2);
        uint256[] memory oneB = new uint256[](1);
        oneB[0] = BOND32;
        // length mismatch
        vm.expectRevert(StakedReputationSet.BadTierTable.selector);
        _newSet(one, two, IWithdrawVerifier(address(verifier)));
        // limit 0
        one[0] = 0;
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        _newSet(one, oneB, IWithdrawVerifier(address(verifier)));
        // limit > MAX_LIMIT
        one[0] = 65536;
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        _newSet(one, oneB, IWithdrawVerifier(address(verifier)));
        // duplicate of the default tier
        one[0] = 8;
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        _newSet(one, oneB, IWithdrawVerifier(address(verifier)));
        // zero bond
        one[0] = 32;
        oneB[0] = 0;
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        _newSet(one, oneB, IWithdrawVerifier(address(verifier)));
        // not ascending / duplicate extra
        uint256[] memory twoB = new uint256[](2);
        twoB[0] = BOND32;
        twoB[1] = BOND32;
        two[0] = 64;
        two[1] = 32;
        vm.expectRevert(StakedReputationSet.BadTierTable.selector);
        _newSet(two, twoB, IWithdrawVerifier(address(verifier)));
        two[0] = 32;
        two[1] = 32;
        vm.expectRevert(StakedReputationSet.BadTierTable.selector);
        _newSet(two, twoB, IWithdrawVerifier(address(verifier)));
        // a valid two-extra table works and is ascending
        two[1] = 64;
        StakedReputationSet s = _newSet(two, twoB, IWithdrawVerifier(address(verifier)));
        assertEq(s.allowedLimits().length, 3);
        assertEq(s.bondFor(64), BOND32);
    }

    // ---- register at a tier ------------------------------------------------------

    function test_Register_Tier32_RequiresTierBond() public {
        uint256 leaf = hasher.commitmentOf(SECRET_B, 32);
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: BOND}(leaf, 32); // the tier-8 bond is not enough
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: BOND32 + 1}(leaf, 32);

        vm.expectEmit(true, true, false, true);
        emit MemberRegistered(leaf, 0, 32);
        set.register{value: BOND32}(leaf, 32);

        (uint256 bond, uint64 index, uint64 exitAt, uint32 limit) = set.members(leaf);
        assertEq(bond, BOND32);
        assertEq(uint256(index), 0);
        assertEq(uint256(exitAt), 0);
        assertEq(uint256(limit), 32);
        assertEq(set.limitOf(leaf), 32);
        assertTrue(set.isActive(leaf));
        assertEq(address(set).balance, BOND32);
    }

    function test_Register_UnadmittedTier_Reverts() public {
        uint256 leaf = hasher.commitmentOf(SECRET_B, 16);
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        set.register{value: BOND}(leaf, 16);
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        set.register{value: BOND}(leaf, 0);
    }

    function test_Register_OneArg_IsDefaultTier() public {
        // legacy entry point == register(c, 8): same bond, same recorded limit, same event.
        vm.expectEmit(true, true, false, true);
        emit MemberRegistered(LEAF_A_8, 0, 8);
        set.register{value: BOND}(LEAF_A_8);
        assertEq(set.limitOf(LEAF_A_8), 8);
        (uint256 bond,,, uint32 limit) = set.members(LEAF_A_8);
        assertEq(bond, BOND);
        assertEq(uint256(limit), 8);
        // the two-arg form at 8 costs exactly BOND too
        set.register{value: BOND}(hasher.commitmentOf(SECRET_B, 8), 8);
        assertEq(set.activeCount(), 2);
    }

    // ---- slash at the claimed tier -----------------------------------------------

    function test_Slash_Tier32_OnlyWithLimit32_BurnsTierBond() public {
        uint256 leaf32 = hasher.commitmentOf(SECRET_B, 32);
        set.register{value: BOND32}(leaf32, 32);

        // wrong tier claimed: BadLimit (recorded 32 != claimed 8)
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        set.slash(leaf32, SECRET_B, 8, RECEIVER);
        // the legacy 3-arg slash IS the limit-8 claim -> same revert
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        set.slash(leaf32, SECRET_B, RECEIVER);
        // the tier-8 leaf of the same secret is simply not a member
        uint256 leaf8 = hasher.commitmentOf(SECRET_B, 8);
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.slash(leaf8, SECRET_B, 8, RECEIVER);
        // right tier, wrong secret: BadSecret
        vm.expectRevert(StakedReputationSet.BadSecret.selector);
        set.slash(leaf32, SECRET_A, 32, RECEIVER);
        // still bonded after every failed attempt
        assertEq(set.limitOf(leaf32), 32);
        assertEq(address(set).balance, BOND32);

        // right tier + right secret: burns 90% of the TIER-32 bond and pays a 10% bounty
        uint256 before = RECEIVER.balance;
        vm.expectEmit(true, true, false, true);
        emit MemberSlashed(leaf32, RECEIVER, 32);
        set.slash(leaf32, SECRET_B, 32, RECEIVER);
        assertEq(RECEIVER.balance - before, BOND32 / 10, "receiver gets only the tier-32 bounty");
        assertEq(address(set).balance, 0);
        assertEq(set.limitOf(leaf32), 0);
        assertFalse(set.isActive(leaf32));
        assertEq(set.activeCount(), 0);
    }

    function test_Slash_Tier8_OnlyWithLimit8() public {
        set.register{value: BOND}(LEAF_A_8, 8);
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        set.slash(LEAF_A_8, SECRET_A, 32, RECEIVER);
        // legacy 3-arg == limit 8: same mandatory burn
        uint256 before = RECEIVER.balance;
        set.slash(LEAF_A_8, SECRET_A, RECEIVER);
        assertEq(RECEIVER.balance - before, BOND / 10);
    }

    function test_Slash_Tier32_WhileExiting_StillBurns() public {
        uint256 leaf32 = hasher.commitmentOf(SECRET_B, 32);
        set.register{value: BOND32}(leaf32, 32);
        set.initiateExit(leaf32, _proof(SECRET_B)); // mock verifier: verify(leaf, 32, ctx, secret)
        assertEq(set.activeCount(), 0);
        set.slash(leaf32, SECRET_B, 32, RECEIVER);
        assertEq(RECEIVER.balance, BOND32 / 10);
        assertEq(address(set).balance, 0);
    }

    // ---- exit / withdraw at a tier pays the tier bond ---------------------------

    function test_ExitWithdraw_Tier32_PaysTierBond() public {
        uint256 leaf32 = hasher.commitmentOf(SECRET_B, 32);
        set.register{value: BOND32}(leaf32, 32);
        set.initiateExit(leaf32, _proof(SECRET_B));
        vm.warp(block.timestamp + UNBONDING);
        set.withdraw(leaf32, RECIPIENT, _proof(SECRET_B));
        assertEq(RECIPIENT.balance, BOND32, "withdraw pays the tier bond");
        assertEq(address(set).balance, 0);
    }

    function test_Exit_MockVerifierUsesRecordedLimit() public {
        // A leaf staked at 32 is authorized by the secret at limit 32 (verify gets m.limit);
        // the same secret's proof against a limit-8 leaf that is not staked is NotMember.
        uint256 leaf32 = hasher.commitmentOf(SECRET_B, 32);
        uint256 leaf8 = hasher.commitmentOf(SECRET_B, 8);
        set.register{value: BOND32}(leaf32, 32);
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.initiateExit(leaf8, _proof(SECRET_B));
        // and a wrong secret fails BadProof at the recorded tier
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.initiateExit(leaf32, _proof(SECRET_A));
        set.initiateExit(leaf32, _proof(SECRET_B));
        assertEq(set.activeCount(), 0);
    }

    // ---- REAL Groth16 exit-auth at a tier ----------------------------------------

    /// The withdraw circuit proves the identity commitment (Poseidon1(secret)); the wrapper
    /// ties it to the leaf at the limit the SET recorded. The committed fixture
    /// (`testdata/withdraw-proof.json` `.tier32.exit`, generated by gen-withdraw-proof.mjs
    /// for SECRET_A's tier-32 leaf's exit context) authorizes that leaf when the set passes
    /// 32; the verifier refuses to tie it to the leaf at 8, and the tier-8 fixture proof
    /// (bound to the tier-8 leaf's context) cannot be replayed against the tier-32 leaf.
    function test_RealVerifier_TiedToRecordedLimit() public {
        WithdrawGroth16Verifier groth16 = new WithdrawGroth16Verifier();
        WithdrawVerifier real = new WithdrawVerifier(groth16);
        (uint256[] memory limits, uint256[] memory bonds) = _tiers32();
        StakedReputationSet s = _newSet(limits, bonds, IWithdrawVerifier(address(real)));

        string memory json = vm.readFile("testdata/withdraw-proof.json");
        bytes memory exitProof32 = vm.parseJsonBytes(json, ".tier32.exit.proof");
        bytes memory exitProof8 = vm.parseJsonBytes(json, ".exit.proof");
        uint256 leaf32 = hasher.commitmentOf(SECRET_A, 32);
        assertEq(leaf32, LEAF_A_32);
        bytes32 ctx = keccak256(abi.encodePacked("SHADE_TREE_EXIT", leaf32));
        // direct verifier checks
        assertTrue(real.verify(leaf32, 32, ctx, exitProof32), "fixture proof authorizes the tier-32 leaf at 32");
        assertFalse(real.verify(leaf32, 8, ctx, exitProof32), "...but not at limit 8 (leaf mismatch)");
        assertFalse(real.verify(LEAF_A_8, 32, ctx, exitProof32), "nor the tier-8 leaf at 32");
        assertFalse(
            real.verify(leaf32, 32, ctx, exitProof8), "the tier-8 exit proof is bound to another leaf's context"
        );
        // through the set: it passes the recorded limit
        s.register{value: BOND32}(leaf32, 32);
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        s.initiateExit(leaf32, exitProof8);
        s.initiateExit(leaf32, exitProof32);
        assertEq(s.activeCount(), 0);
        (uint256 bond,, uint64 exitAt, uint32 limit) = s.members(leaf32);
        assertEq(bond, BOND32);
        assertTrue(exitAt != 0);
        assertEq(uint256(limit), 32);
    }

    // ---- on-chain root == JS root for a mixed-tier tree --------------------------

    function test_Root_MixedTiers_EqualsJsNewGroup() public {
        set.register{value: BOND}(LEAF_A_8, 8); // index 0
        set.register{value: BOND32}(LEAF_B_32, 32); // index 1
        assertEq(set.currentRoot(), ROOT_A8_B32, "root == newGroup([leafA8, leafB32]).root");
        assertEq(uint256(vm.load(address(set), bytes32(set.ROOT_STORAGE_SLOT()))), ROOT_A8_B32, "still slot 3");
        set.register{value: BOND32}(LEAF_C_32, 32); // index 2
        set.slash(LEAF_B_32, SECRET_B, 32, RECEIVER); // zero-in-place @1
        assertEq(set.currentRoot(), ROOT_A8_C32_MIDDLE_REMOVED, "root == JS tree minus index 1");
    }

    // ---- storage layout guard: tier table must not move currentRoot ------------

    function test_Root_StorageSlotUnchangedByTierTable() public view {
        assertEq(set.ROOT_STORAGE_SLOT(), 3);
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), set.currentRoot());
    }
}
