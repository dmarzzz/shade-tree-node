// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Fuzz tests for PaidAccessSet (T-FEAT-7 Layer 1). Commitments are the real Poseidon rate
// commitments of a fuzzed identity secret at a fuzzed admitted tier; the REFERENCE tree is a
// StakedReputationSet (the live, immutable rln-v4 tree code) driven through the same
// register/slash sequence, so "root == reference" means "root == what the deployed staked set
// (and therefore lib/root-provider.mjs reconstructRoot) computes for the same leaves".

import {FuzzBase} from "./FuzzHelpers.sol";
import {PaidAccessSet} from "../contracts/PaidAccessSet.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract PaidAccessSetFuzzTest is FuzzBase {
    uint256 constant BOND = 0.001 ether; // reference set only

    PaidAccessSet set;
    StakedReputationSet ref; // reference tree (same leaves, same indices, same removals)
    RateCommitmentHasher hasher;
    address constant SINK = address(0x5151);

    function setUp() public {
        hasher = new RateCommitmentHasher();
        uint256[] memory l = new uint256[](2);
        l[0] = 8; l[1] = 32;
        set = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), l); // this test is the operator
        MockWithdrawVerifier v = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        uint256[] memory xl = new uint256[](1);
        uint256[] memory xb = new uint256[](1);
        xl[0] = 32; xb[0] = 4 * BOND;
        ref = new StakedReputationSet(BOND, 300, 270, IWithdrawVerifier(address(v)), ICommitmentHasher(address(hasher)), xl, xb);
        vm.deal(address(this), 1_000 ether);
    }

    function _secret(uint256 raw) internal pure returns (uint256) {
        return _bound(raw, 1, 1e30);
    }

    /// For ANY secret and either tier: the operator's insert lands with the recorded tier, index
    /// and leafCount, and the root equals the reference tree's; a live leaf cannot be re-inserted.
    function testFuzz_insert_admitsAtTier(uint256 rawSecret, bool tier32) public {
        uint256 secret = _secret(rawSecret);
        uint256 limit = tier32 ? 32 : 8;
        uint256 leaf = hasher.commitmentOf(secret, limit);
        set.insert(leaf, limit);
        ref.register{value: ref.bondFor(limit)}(leaf, limit);
        assertEq(set.limitOf(leaf), limit, "recorded tier == inserted tier");
        assertEq(set.leafCount(), 1);
        assertEq(set.liveCount(), 1);
        assertEq(set.currentRoot(), ref.currentRoot(), "root == reference tree");
        vm.expectRevert(PaidAccessSet.AlreadyInserted.selector);
        set.insert(leaf, limit);
        vm.expectRevert(PaidAccessSet.AlreadyInserted.selector);
        set.insert(leaf, tier32 ? 8 : 32);
        assertEq(address(set).balance, 0);
    }

    /// Any non-operator caller is refused, single and batch.
    function testFuzz_insert_onlyOperator(address caller, uint256 rawSecret) public {
        vmf.assume(caller != address(this));
        uint256 leaf = hasher.commitmentOf(_secret(rawSecret), 8);
        vm.prank(caller);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(leaf, 8);
        uint256[] memory c = new uint256[](1);
        uint256[] memory l = new uint256[](1);
        c[0] = leaf; l[0] = 8;
        vm.prank(caller);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insertBatch(c, l);
        assertEq(set.leafCount(), 0);
    }

    /// An unlisted limit never admits, even from the operator.
    function testFuzz_insert_unlistedLimitReverts(uint256 rawSecret, uint256 rawLimit) public {
        uint256 limit = _bound(rawLimit, 0, 70_000);
        vmf.assume(limit != 8 && limit != 32);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.insert(_secret(rawSecret), limit);
        assertEq(set.leafCount(), 0);
    }

    /// insertBatch of n leaves == n single inserts: same indices, same root as the reference.
    function testFuzz_insertBatch_equalsSingles(uint256 seed, uint8 rawN) public {
        uint256 n = _bound(rawN, 1, 8);
        uint256[] memory c = new uint256[](n);
        uint256[] memory l = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            l[i] = r % 2 == 0 ? 8 : 32;
            c[i] = hasher.commitmentOf(1 + (r >> 8) % 1e30, l[i]);
            // duplicates inside one batch would revert AlreadyInserted; keep them distinct
            for (uint256 j = 0; j < i; j++) vmf.assume(c[j] != c[i]);
            ref.register{value: ref.bondFor(l[i])}(c[i], l[i]);
        }
        set.insertBatch(c, l);
        assertEq(set.leafCount(), n, "leafCount == batch size");
        assertEq(set.liveCount(), n);
        for (uint256 i = 0; i < n; i++) {
            (uint64 idx, uint32 lim) = set.leaves(c[i]);
            assertEq(uint256(idx), i, "array order == index order");
            assertEq(uint256(lim), l[i]);
        }
        assertEq(set.currentRoot(), ref.currentRoot(), "batch root == reference singles root");
    }

    /// slash succeeds ONLY at the recorded tier with the right secret, moves nothing, and the
    /// root after it equals the reference tree's zero-in-place root.
    function testFuzz_slash_onlyAtRecordedTier(uint256 rawSecret, bool tier32, uint256 rawOther, uint256 rawWrong) public {
        uint256 secret = _secret(rawSecret);
        uint256 limit = tier32 ? 32 : 8;
        uint256 leaf = hasher.commitmentOf(secret, limit);
        set.insert(leaf, limit);
        ref.register{value: ref.bondFor(limit)}(leaf, limit);

        uint256 other = _bound(rawOther, 0, 70_000);
        vmf.assume(other != limit);
        vm.expectRevert(PaidAccessSet.BadLimit.selector);
        set.slash(leaf, secret, other, SINK);
        uint256 wrong = _secret(rawWrong);
        vmf.assume(hasher.commitmentOf(wrong, limit) != leaf);
        vm.expectRevert(PaidAccessSet.BadSecret.selector);
        set.slash(leaf, wrong, limit, SINK);
        assertEq(set.limitOf(leaf), limit, "failed slashes are no-ops");

        uint256 sinkBefore = SINK.balance;
        set.slash(leaf, secret, limit, SINK);
        ref.slash(leaf, secret, limit, SINK);
        assertEq(SINK.balance, sinkBefore + ref.bondFor(limit), "(the reference staked set DID pay; the paid set has nothing to pay)");
        assertEq(address(set).balance, 0);
        assertEq(set.limitOf(leaf), 0);
        assertEq(set.liveCount(), 0);
        assertEq(set.leafCount(), 1);
        assertEq(set.currentRoot(), ref.currentRoot(), "root after slash == reference zero-in-place root");
    }

    /// A random insert/slash sequence over a small pool: paid set root == reference root after
    /// every step; leafCount == inserts; slot 3 == currentRoot; balance stays 0.
    function testFuzz_sequence_matchesReference(uint256 seed, uint8 steps) public {
        uint256 n = _bound(steps, 1, 12);
        uint256 inserts;
        for (uint256 s = 0; s < n; s++) {
            uint256 r = uint256(keccak256(abi.encode(seed, s)));
            uint256 secret = 1_000 + (r % 6);
            uint256 limit = (r >> 8) % 2 == 0 ? 8 : 32;
            uint256 leaf = hasher.commitmentOf(secret, limit);
            if (set.burned(leaf)) {
                // slashed => burned in the paid set; do not re-insert in EITHER set so the
                // two trees stay in lockstep (the staked ref set has no burned set of its own).
            } else if (set.limitOf(leaf) == 0) {
                set.insert(leaf, limit);
                ref.register{value: ref.bondFor(limit)}(leaf, limit);
                inserts++;
            } else {
                set.slash(leaf, secret, limit, SINK);
                ref.slash(leaf, secret, limit, SINK);
            }
            assertEq(set.currentRoot(), ref.currentRoot(), "root == reference after every step");
            assertEq(uint256(vm.load(address(set), bytes32(uint256(3)))), set.currentRoot(), "slot 3 == currentRoot");
            assertEq(set.leafCount(), inserts, "leafCount == inserts");
            assertEq(address(set).balance, 0, "no funds ever");
        }
    }

    /// Two-step transfer for any pair of addresses: only the nominee can accept, and afterwards
    /// only the nominee inserts.
    function testFuzz_operator_twoStep(address next, address other) public {
        vmf.assume(next != address(0) && next != address(this) && other != next);
        set.setOperator(next);
        assertEq(set.operator(), address(this));
        vm.prank(other);
        vm.expectRevert(PaidAccessSet.NotPendingOperator.selector);
        set.acceptOperator();
        vm.prank(next);
        set.acceptOperator();
        assertEq(set.operator(), next);
        uint256 leaf = hasher.commitmentOf(7, 8);
        vm.expectRevert(PaidAccessSet.NotOperator.selector);
        set.insert(leaf, 8);
        vm.prank(next);
        set.insert(leaf, 8);
        assertEq(set.leafCount(), 1);
    }

    receive() external payable {}
}
