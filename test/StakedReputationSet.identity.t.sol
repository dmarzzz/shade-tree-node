// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ShadeNet M1 launch-audit fixes (internal audit #113), full uint256 range:
//   2.1.2 / 2.1.3  identity commitments and leaves must be nonzero canonical field elements, in
//                  StakedReputationSet.registerIdentity and PaidAccessSet.insert / insertBatch;
//   2.1.4 / 2.3.2  the set derives the leaf Poseidon2(idc, limit) itself, so the tier a bond pays
//                  for is the tier the leaf's RLN proofs are limited to; the leaf-taking
//                  register(..) selectors are gone.

import {FuzzBase} from "./FuzzHelpers.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {StakedReputationSetHarness} from "./StakedReputationSetHarness.sol";
import {PaidAccessSet} from "../contracts/PaidAccessSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract StakedReputationSetIdentityTest is FuzzBase {
    uint256 constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant BOND1 = 0.1 ether; // tier 1 (public profile shape)
    uint256 constant BOND8 = 0.8 ether; // tier 8

    RateCommitmentHasher hasher;
    MockWithdrawVerifier verifier;
    StakedReputationSet set;
    PaidAccessSet paid;

    function setUp() public {
        hasher = new RateCommitmentHasher();
        verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        uint256[] memory limits = new uint256[](1);
        uint256[] memory bonds = new uint256[](1);
        limits[0] = 1;
        bonds[0] = BOND1;
        set = new StakedReputationSet(
            BOND8, 86_400, 3_720, IWithdrawVerifier(address(verifier)), ICommitmentHasher(address(hasher)), limits, bonds
        );
        uint256[] memory paidLimits = new uint256[](1);
        paidLimits[0] = 8;
        paid = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), paidLimits);
        vm.deal(address(this), 1_000_000 ether);
    }

    // ---- 2.1.4: the tier is proven ------------------------------------------------

    /// For ANY secret and tier: the stored leaf is exactly the circuit's rate commitment at the
    /// staked tier, so the member's RLN proofs are limited to what the bond paid for.
    function testFuzz_leafIsDerivedAtStakedTier(uint256 secret, bool tierOne) public {
        uint256 limit = tierOne ? 1 : 8;
        uint256 idc = hasher.identityCommitmentOf(secret);
        vmf.assume(idc != 0);
        uint256 leaf = set.registerIdentity{value: set.bondFor(limit)}(idc, limit);
        assertEq(leaf, hasher.commitmentOf(secret, limit), "leaf == Poseidon2(Poseidon1(secret), limit)");
        assertEq(set.limitOf(leaf), limit);
        assertTrue(set.isActive(leaf));
    }

    /// The 2.1.4 attack: a member holding a limit-8 leaf cannot get it admitted at the tier-1
    /// price. Paying tier 1 admits only the identity's tier-1 leaf, a different leaf.
    function test_CannotUnderpayForAHighLimitLeaf() public {
        uint256 secret = 111;
        uint256 idc = hasher.identityCommitmentOf(secret);
        uint256 leaf8 = hasher.commitmentOf(secret, 8);
        uint256 leaf1 = set.registerIdentity{value: BOND1}(idc, 1);
        assertTrue(leaf1 != leaf8, "tier-1 bond buys the tier-1 leaf");
        assertFalse(set.isActive(leaf8), "the limit-8 leaf is not admitted");
        assertEq(set.limitOf(leaf1), 1);
    }

    /// The leaf-taking v4 selectors are gone, so a stale client can't bond a leaf nobody opens.
    function test_LeafSelectorsRemoved() public {
        (bool ok,) = address(set).call{value: BOND8}(abi.encodeWithSignature("register(uint256,uint256)", 42, 8));
        assertFalse(ok, "register(uint256,uint256) must not exist");
        (ok,) = address(set).call{value: BOND8}(abi.encodeWithSignature("register(uint256)", 42));
        assertFalse(ok, "register(uint256) must not exist");
        assertEq(address(set).balance, 0);
    }

    // ---- 2.1.2 / 2.1.3: canonical, nonzero commitments -----------------------------

    function test_ZeroIdentityCommitment_Reverts() public {
        vm.expectRevert(StakedReputationSet.BadCommitment.selector);
        set.registerIdentity{value: BOND8}(0, 8);
    }

    /// For ANY idc >= FIELD (the whole non-canonical range): rejected before any state change.
    function testFuzz_NonCanonicalIdentityCommitment_Reverts(uint256 raw, bool tierOne) public {
        uint256 idc = _bound(raw, FIELD, type(uint256).max);
        uint256 limit = tierOne ? 1 : 8;
        uint256 bond = set.bondFor(limit);
        vm.expectRevert(StakedReputationSet.BadCommitment.selector);
        set.registerIdentity{value: bond}(idc, limit);
        assertEq(set.nextIndex(), 0);
        assertEq(address(set).balance, 0);
    }

    /// For ANY canonical nonzero idc: admitted, and the root stays a function of canonical leaves.
    function testFuzz_CanonicalIdentityCommitment_Admits(uint256 raw) public {
        uint256 idc = _bound(raw, 1, FIELD - 1);
        uint256 leaf = set.registerIdentity{value: BOND8}(idc, 8);
        assertTrue(leaf != 0 && leaf < FIELD, "derived leaf is canonical");
        assertEq(leaf, hasher.rateCommitmentOf(idc, 8));
    }

    /// The leaf-level guard also holds (belt-and-braces behind the derivation), full range.
    function testFuzz_LeafGuard_FullRange(uint256 raw) public {
        StakedReputationSetHarness h = new StakedReputationSetHarness(
            BOND8,
            86_400,
            3_720,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            new uint256[](0),
            new uint256[](0)
        );
        if (raw == 0 || raw >= FIELD) {
            vm.expectRevert(StakedReputationSet.BadCommitment.selector);
            h.register{value: BOND8}(raw, 8);
        } else {
            h.register{value: BOND8}(raw, 8);
            assertTrue(h.isActive(raw));
        }
    }

    function test_PaidInsert_ZeroAndFieldRejected() public {
        vm.expectRevert(PaidAccessSet.BadCommitment.selector);
        paid.insert(0, 8);
        vm.expectRevert(PaidAccessSet.BadCommitment.selector);
        paid.insert(FIELD, 8);
        assertEq(paid.leafCount(), 0);
    }

    /// For ANY commitment: the paid set admits exactly the canonical nonzero range, and a
    /// batch containing one bad commitment reverts whole.
    function testFuzz_PaidInsert_FullRange(uint256 raw) public {
        if (raw == 0 || raw >= FIELD) {
            vm.expectRevert(PaidAccessSet.BadCommitment.selector);
            paid.insert(raw, 8);
            uint256[] memory cs = new uint256[](2);
            uint256[] memory ls = new uint256[](2);
            cs[0] = 7;
            cs[1] = raw;
            ls[0] = 8;
            ls[1] = 8;
            vm.expectRevert(PaidAccessSet.BadCommitment.selector);
            paid.insertBatch(cs, ls);
            assertEq(paid.leafCount(), 0);
        } else {
            paid.insert(raw, 8);
            assertEq(paid.limitOf(raw), 8);
        }
    }

    receive() external payable {}
}
