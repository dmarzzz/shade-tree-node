// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Fuzz tests for StakedReputationSet. Commitments are the real Poseidon rate commitments of
// a fuzzed identity secret (via RateCommitmentHasher), and the MockWithdrawVerifier accepts
// abi.encode(secret) as the demo proof — so we can drive register / exit / withdraw / slash
// over random secrets and timings and assert the state-machine invariants per call.

import {FuzzBase} from "./FuzzHelpers.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract StakedReputationSetFuzzTest is FuzzBase {
    uint256 constant BOND = 0.01 ether;
    uint256 constant UNBONDING = 300;
    uint256 constant MIN_UNBONDING = 270;

    StakedReputationSet set;
    RateCommitmentHasher hasher;
    MockWithdrawVerifier verifier;

    address constant RECIPIENT = address(0xBEEF);
    address constant RECEIVER = address(0xCAFE);

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
        vm.deal(address(this), 1_000 ether);
    }

    function _proof(uint256 secret) internal pure returns (bytes memory) {
        return abi.encode(secret);
    }

    // Keep secrets well inside [1, F) so distinct fuzzed secrets give distinct commitments
    // (the hasher reduces mod F; staying small avoids the aliasing corner).
    function _secret(uint256 raw) internal pure returns (uint256) {
        return _bound(raw, 1, 1e30);
    }

    // ---- register: only the exact BOND is admitted ---------------------------

    function testFuzz_register_exactBondAdmits(uint256 rawSecret) public {
        uint256 secret = _secret(rawSecret);
        uint256 commit = hasher.commitmentOf(secret);

        set.register{value: BOND}(commit);

        assertTrue(set.isActive(commit), "exact bond admits the leaf");
        assertEq(set.activeCount(), 1);
        (uint256 bond, uint64 index, uint64 exitAt,) = set.members(commit);
        assertEq(bond, BOND, "bond recorded");
        assertEq(uint256(index), 0);
        assertEq(uint256(exitAt), 0);
        assertEq(address(set).balance, BOND, "one live bond held");
    }

    function testFuzz_register_wrongBondReverts(uint256 rawSecret, uint96 value) public {
        vmf.assume(value != BOND);
        uint256 commit = hasher.commitmentOf(_secret(rawSecret));

        vm.deal(address(this), value); // fund the exact (wrong) amount so the call can carry it
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        set.register{value: value}(commit);

        assertFalse(set.isActive(commit));
        assertEq(set.activeCount(), 0);
        assertEq(address(set).balance, 0);
    }

    // ---- exit + withdraw honour the unbonding clock for any timing -----------

    function testFuzz_exitWithdraw_timing(uint256 rawSecret, uint256 wait) public {
        uint256 secret = _secret(rawSecret);
        uint256 commit = hasher.commitmentOf(secret);
        wait = _bound(wait, 0, 3 * UNBONDING);

        set.register{value: BOND}(commit);
        set.initiateExit(commit, _proof(secret));

        assertFalse(set.isActive(commit), "exit leaves admission set");
        assertEq(set.activeCount(), 0);
        uint256 unlock = set.withdrawableAt(commit);

        vm.warp(block.timestamp + wait);

        if (block.timestamp < unlock) {
            vm.expectRevert(StakedReputationSet.StillBonded.selector);
            set.withdraw(commit, RECIPIENT, _proof(secret));
            assertEq(address(set).balance, BOND, "bond held while still bonded");
        } else {
            uint256 before = RECIPIENT.balance;
            set.withdraw(commit, RECIPIENT, _proof(secret));
            assertEq(RECIPIENT.balance - before, BOND, "recipient paid after unbonding");
            assertEq(address(set).balance, 0, "contract emptied");
        }
    }

    // ---- withdraw needs the matching secret even after unbonding -------------

    function testFuzz_withdraw_wrongProofReverts(uint256 rawSecret, uint256 rawWrong) public {
        uint256 secret = _secret(rawSecret);
        uint256 commit = hasher.commitmentOf(secret);
        uint256 wrong = _secret(rawWrong);
        vmf.assume(hasher.commitmentOf(wrong) != commit);

        set.register{value: BOND}(commit);
        set.initiateExit(commit, _proof(secret));
        vm.warp(block.timestamp + UNBONDING);

        vm.expectRevert(StakedReputationSet.BadProof.selector);
        set.withdraw(commit, RECIPIENT, _proof(wrong));
        assertEq(address(set).balance, BOND, "bad proof keeps the bond");
    }

    // ---- slash: a revealed matching secret always pays -----------------------

    function testFuzz_slash_revealedSecretPays(uint256 rawSecret, bool exiting) public {
        uint256 secret = _secret(rawSecret);
        uint256 commit = hasher.commitmentOf(secret);

        set.register{value: BOND}(commit);
        if (exiting) set.initiateExit(commit, _proof(secret));

        uint256 before = RECEIVER.balance;
        set.slash(commit, secret, RECEIVER);

        assertEq(RECEIVER.balance - before, BOND / 10, "revealed secret pays only the bounty");
        (uint256 bond,,,) = set.members(commit);
        assertEq(bond, 0, "slashed leaf deleted");
        assertEq(set.activeCount(), 0);
        assertEq(address(set).balance, 0, "no bond left behind");
    }

    function testFuzz_slash_wrongSecretReverts(uint256 rawSecret, uint256 rawWrong) public {
        uint256 secret = _secret(rawSecret);
        uint256 commit = hasher.commitmentOf(secret);
        uint256 wrong = _secret(rawWrong);
        vmf.assume(hasher.commitmentOf(wrong) != commit);

        set.register{value: BOND}(commit);
        vm.expectRevert(StakedReputationSet.BadSecret.selector);
        set.slash(commit, wrong, RECEIVER);

        assertTrue(set.isActive(commit), "wrong secret is a no-op");
        assertEq(address(set).balance, BOND);
    }

    // ---- public tiers (T-FEAT-8b): a fresh 0.1/0.8 ETH set per test -----------

    uint256 constant PUBLIC_BOND = 0.1 ether;
    uint256 constant PUBLIC_DEFAULT_BOND = 0.8 ether;

    function _tieredSet() internal returns (StakedReputationSet t) {
        uint256[] memory l = new uint256[](1);
        uint256[] memory b = new uint256[](1);
        l[0] = 1;
        b[0] = PUBLIC_BOND;
        t = new StakedReputationSet(
            PUBLIC_DEFAULT_BOND,
            UNBONDING,
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            l,
            b
        );
    }

    /// For ANY secret and either admitted tier: only exactly bondFor(limit) admits, the
    /// recorded limit is the one staked, and the leaf is the tiered hasher's output.
    function testFuzz_register_tierBondAdmits(uint256 rawSecret, bool tierOne, uint256 rawWei) public {
        StakedReputationSet t = _tieredSet();
        uint256 secret = _secret(rawSecret);
        uint256 limit = tierOne ? 1 : 8;
        uint256 due = t.bondFor(limit);
        uint256 commit = hasher.commitmentOf(secret, limit);

        uint256 wrongWei = _bound(rawWei, 0, 10 * PUBLIC_DEFAULT_BOND);
        vmf.assume(wrongWei != due);
        vm.expectRevert(StakedReputationSet.BadBond.selector);
        t.register{value: wrongWei}(commit, limit);

        t.register{value: due}(commit, limit);
        assertTrue(t.isActive(commit), "tier bond admits the leaf");
        assertEq(t.limitOf(commit), limit, "recorded limit == staked limit");
        assertEq(address(t).balance, due);
    }

    /// For ANY secret and tier: the slash succeeds ONLY at the recorded limit (any other
    /// admitted-or-not limit reverts and changes nothing) and pays only that tier's bounty.
    function testFuzz_slash_onlyAtRecordedLimit(uint256 rawSecret, bool tierOne, uint256 rawOther, bool exiting)
        public
    {
        StakedReputationSet t = _tieredSet();
        uint256 secret = _secret(rawSecret);
        uint256 limit = tierOne ? 1 : 8;
        uint256 due = t.bondFor(limit);
        uint256 commit = hasher.commitmentOf(secret, limit);
        t.register{value: due}(commit, limit);
        if (exiting) t.initiateExit(commit, _proof(secret));

        uint256 other = _bound(rawOther, 0, 70_000);
        vmf.assume(other != limit);
        vm.expectRevert(StakedReputationSet.BadLimit.selector);
        t.slash(commit, secret, other, RECEIVER);
        assertEq(address(t).balance, due, "wrong-limit slash is a no-op");

        uint256 before = RECEIVER.balance;
        t.slash(commit, secret, limit, RECEIVER);
        assertEq(RECEIVER.balance - before, due / 10, "pays exactly the tier bounty");
        assertEq(address(t).balance, 0);
        assertEq(t.limitOf(commit), 0);
    }

    /// The tiered hasher never collides across tiers for the same secret, and equals the
    /// legacy one-argument hasher at limit 8.
    function testFuzz_hasher_tiersDistinctAndDefaultEqual(uint256 rawSecret, uint256 rawLimit) public view {
        uint256 secret = _secret(rawSecret);
        uint256 limit = _bound(rawLimit, 1, 65535);
        vmf.assume(limit != 8);
        assertEq(hasher.commitmentOf(secret, 8), hasher.commitmentOf(secret), "two-arg at 8 == one-arg");
        assertTrue(hasher.commitmentOf(secret, limit) != hasher.commitmentOf(secret, 8), "tiers never collide");
    }

    receive() external payable {}
}
