// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "./Cheats.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract RejectSlashReward {
    receive() external payable {
        revert("reject reward");
    }
}

contract ReenterSlashReward {
    StakedReputationSet immutable set;
    uint256 immutable leaf;
    uint256 immutable secret;
    bool public reentryBlocked;

    constructor(StakedReputationSet s, uint256 c, uint256 k) {
        set = s;
        leaf = c;
        secret = k;
    }

    receive() external payable {
        (bool ok, bytes memory reason) =
            address(set).call(abi.encodeWithSignature("slash(uint256,uint256,address)", leaf, secret, address(this)));
        reentryBlocked = !ok && bytes4(reason) == StakedReputationSet.NotMember.selector;
        require(reentryBlocked, "old stake remained slashable during payout");
    }
}

contract StakedReputationSetSlashPenaltyTest is Cheats {
    address constant MEMBER = address(0xA11CE);
    address constant KEEPER = address(0xCAFE);
    uint256 constant SECRET = 111;
    RateCommitmentHasher hasher;
    MockWithdrawVerifier verifier;
    uint256 leaf;

    event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward);

    function setUp() public {
        hasher = new RateCommitmentHasher();
        verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        leaf = hasher.commitmentOf(SECRET);
        vm.deal(address(0), 0);
        vm.deal(KEEPER, 0);
    }

    function _register(uint256 amount) internal returns (StakedReputationSet set) {
        set = new StakedReputationSet(
            amount,
            300,
            270,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            new uint256[](0),
            new uint256[](0)
        );
        vm.deal(MEMBER, amount);
        vm.prank(MEMBER);
        set.register{value: amount}(leaf);
    }

    // Full uint256 bond range; covers active/exiting, both ABIs, and either ordering of
    // competing member/keeper transactions. A self-slasher recovers at most one tenth.
    function testFuzz_SelfSlashAndCompetingClaims(uint256 raw, bool exiting, bool legacy, bool memberFirst) public {
        uint256 amount = raw == 0 ? 1 : raw;
        StakedReputationSet set = _register(amount);
        uint256 registeredRoot = set.currentRoot();
        if (exiting) set.initiateExit(leaf, abi.encode(SECRET));
        uint256 rootBeforeSlash = set.currentRoot();
        address winner = memberFirst ? MEMBER : KEEPER;
        uint256 reward = amount / 10;
        uint256 burned = amount - reward;
        assertEq(set.SLASH_BURN_ADDRESS(), address(0));
        assertEq(set.SLASH_REWARD_DIVISOR(), 10);
        vm.expectEmit(true, true, false, true);
        emit SlashPayout(leaf, winner, burned, reward);
        vm.prank(winner);
        if (legacy) set.slash(leaf, SECRET, winner);
        else set.slash(leaf, SECRET, 8, winner);
        assertEq(winner.balance, reward, "only the bounty is recoverable, even by the offender");
        assertEq(address(0).balance, burned, "mandatory penalty reaches the fixed sink");
        assertTrue(burned > 0 && reward <= amount / 10, "no positive stake can self-refund in full");
        assertEq(address(set).balance, 0, "whole bond accounted for");
        assertEq(set.activeCount(), 0);
        assertEq(set.nextIndex(), 1);
        assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), set.currentRoot(), "root stays in slot 3");
        if (exiting) assertEq(set.currentRoot(), rootBeforeSlash, "exiting leaf is not removed twice");
        else assertTrue(set.currentRoot() != registeredRoot, "active leaf removed");
        (uint256 bond,,,) = set.members(leaf);
        assertEq(bond, 0);
        address loser = memberFirst ? KEEPER : MEMBER;
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        vm.prank(loser);
        set.slash(leaf, SECRET, 8, loser);
        vm.warp(block.timestamp + 300);
        vm.expectRevert(StakedReputationSet.NotMember.selector);
        set.withdraw(leaf, MEMBER, abi.encode(SECRET));
        assertEq(address(0).balance, burned, "competing slash cannot change the first burn");
    }

    function test_TinyBondsBurnCompletelyWithoutCallingZeroRewardReceiver() public {
        RejectSlashReward rejector = new RejectSlashReward();
        for (uint256 amount = 1; amount < 10; amount++) {
            StakedReputationSet set = _register(amount);
            uint256 before = address(0).balance;
            set.slash(leaf, SECRET, address(rejector));
            assertEq(address(0).balance - before, amount);
            assertEq(address(set).balance, 0);
        }
    }

    function test_RejectingRewardRollsBackBurnAndMembershipThenRetrySucceeds() public {
        StakedReputationSet set = _register(101);
        RejectSlashReward rejector = new RejectSlashReward();
        uint256 root = set.currentRoot();
        vm.expectRevert(StakedReputationSet.PayoutFailed.selector);
        set.slash(leaf, SECRET, address(rejector));
        assertEq(address(0).balance, 0, "failed payout also rolls back burn transfer");
        assertEq(address(set).balance, 101);
        assertEq(set.currentRoot(), root);
        assertEq(set.activeCount(), 1);
        assertTrue(set.isActive(leaf));
        set.slash(leaf, SECRET, KEEPER);
        assertEq(address(0).balance, 91, "rounding favors the penalty");
        assertEq(KEEPER.balance, 10);
    }

    function test_RewardCallbackCannotClaimTheSameBondTwice() public {
        StakedReputationSet set = _register(101);
        ReenterSlashReward receiver = new ReenterSlashReward(set, leaf, SECRET);
        set.slash(leaf, SECRET, address(receiver));
        assertTrue(receiver.reentryBlocked());
        assertEq(address(receiver).balance, 10);
        assertEq(address(0).balance, 91);
        assertEq(address(set).balance, 0);
    }

    function test_ZeroRewardDestinationVoluntarilyBurnsTheWholeBond() public {
        StakedReputationSet set = _register(101);
        set.slash(leaf, SECRET, address(0));
        assertEq(address(0).balance, 101);
        assertEq(address(set).balance, 0);
    }
}
