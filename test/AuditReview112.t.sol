// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Regression tests for the internal smart-contract audit (issue #113, PR #112). Each started as a
// local reproduction of a reported vulnerability (where PASS meant the bug was present) and now
// asserts the fix. Findings: 2.1.1 self-slash refund, 2.1.2 non-canonical alias, 2.1.3 zero leaf,
// 2.1.4 wrong-tier registration, 2.2.1 proof replay (re-registration, other deployment), 2.3.3
// burned identity re-entering the paid set at another tier.

import {WithdrawVerifierTest} from "./WithdrawVerifier.t.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {PaidAccessSet} from "../contracts/PaidAccessSet.sol";

contract AuditReview112 is WithdrawVerifierTest {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function fresh() internal returns (StakedReputationSet) {
        uint256[] memory limits = new uint256[](1);
        uint256[] memory bonds = new uint256[](1);
        limits[0] = 32;
        bonds[0] = 4 * BOND;
        return new StakedReputationSet(
            BOND,
            UNBONDING,
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            limits,
            bonds,
            10
        );
    }

    /// 2.1.1: a self-slash returns at most the bounty; the rest burns.
    function test_Audit_SelfSlashNoLongerRefundsBond() public {
        set.registerIdentity{value: BOND}(idcA, 8);
        uint256 before = RECIPIENT.balance;
        set.slash(commitA, SECRET_A, 8, RECIPIENT);
        assertEq(RECIPIENT.balance - before, BOND / 10, "only the bounty comes back");
        assertFalse(set.isActive(commitA));
    }

    /// 2.1.2: the alias idc + P (same value inside the circuit) is rejected, in both sets.
    function test_Audit_NonCanonicalAliasRejected() public {
        vm.expectRevert(StakedReputationSet.BadCommitment.selector);
        set.registerIdentity{value: BOND}(idcA + P, 8);
        uint256[] memory limits = new uint256[](1);
        limits[0] = 8;
        PaidAccessSet paid = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), limits);
        vm.expectRevert(PaidAccessSet.BadCommitment.selector);
        paid.insert(commitA + P, 8);
    }

    /// 2.1.3: the zero leaf (the tree's empty-slot sentinel) can no longer be admitted.
    function test_Audit_ZeroLeafRejected() public {
        vm.expectRevert(StakedReputationSet.BadCommitment.selector);
        set.registerIdentity{value: BOND}(0, 8);
        uint256[] memory limits = new uint256[](1);
        limits[0] = 8;
        PaidAccessSet paid = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), limits);
        vm.expectRevert(PaidAccessSet.BadCommitment.selector);
        paid.insert(0, 8);
    }

    /// 2.1.4: paying the tier-8 bond buys only the tier-8 leaf; the limit-32 leaf stays out, and
    /// the leaf that is admitted is slashable at its tier.
    function test_Audit_WrongTierCannotBuyHighTierLeaf() public {
        StakedReputationSet s = fresh();
        uint256 leaf32 = hasher.commitmentOf(SECRET_A, 32);
        uint256 leaf8 = s.registerIdentity{value: BOND}(idcA, 8);
        assertTrue(leaf8 != leaf32);
        assertFalse(s.isActive(leaf32), "the limit-32 leaf was not admitted at the tier-8 price");
        s.slash(leaf8, SECRET_A, 8, RECIPIENT);
        assertFalse(s.isActive(leaf8), "the admitted leaf is slashable at its own tier");
    }

    /// 2.2.1: proofs from before a withdrawal do not authorize the re-registered stake.
    function test_Audit_ProofsDoNotReplayAfterReregistration() public {
        set.registerIdentity{value: BOND}(idcA, 8);
        set.initiateExit(commitA, exitProof);
        vm.warp(block.timestamp + UNBONDING);
        set.withdraw(commitA, RECIPIENT, withdrawProof);
        set.registerIdentity{value: BOND}(idcA, 8);
        vm.prank(address(0xBAD));
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.initiateExit(commitA, exitProof);
        assertTrue(set.isActive(commitA));
    }

    /// 2.2.1: proofs for one deployment do not authorize another.
    function test_Audit_ProofsDoNotReplayAcrossDeployments() public {
        StakedReputationSet second = fresh();
        set.registerIdentity{value: BOND}(idcA, 8);
        second.registerIdentity{value: BOND}(idcA, 8);
        set.initiateExit(commitA, exitProof);
        vm.prank(address(0xBAD));
        vm.expectRevert(StakedReputationSet.BadProof.selector);
        second.initiateExit(commitA, exitProof);
        assertTrue(second.isActive(commitA));
    }

    /// 2.3.3: a slashed identity is burned at every tier and cannot come back into the paid set.
    function test_Audit_BurnedIdentityCannotReenterAtAnyTier() public {
        uint256[] memory limits = new uint256[](2);
        limits[0] = 8;
        limits[1] = 32;
        PaidAccessSet paid = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), limits);
        paid.insert(commitA, 8);
        paid.slash(commitA, SECRET_A, 8, RECIPIENT);
        uint256 leaf32 = hasher.commitmentOf(SECRET_A, 32);
        assertTrue(paid.burned(commitA) && paid.burned(leaf32), "both tiers of the identity are burned");
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        paid.insert(commitA, 8);
        vm.expectRevert(PaidAccessSet.BurnedCommitment.selector);
        paid.insert(leaf32, 32);
        assertEq(paid.liveCount(), 0);
    }
}
