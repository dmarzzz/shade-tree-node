// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Invariant test for PaidAccessSet (T-FEAT-7 Layer 1). A handler drives random insert /
// insertBatch / slash / operator-transfer sequences over a fixed pool of (secret, tier)
// leaves, mirrors every tree operation on a REFERENCE StakedReputationSet (the live rln-v4
// tree code), and tracks ghost counters. After every call Foundry re-checks:
//
//   * contract balance == 0 (no funds ever: nothing payable, no receive/fallback);
//   * leafCount == number of accepted inserts (append-only; slashed leaves still count);
//   * liveCount == inserts − slashes;
//   * currentRoot == the reference tree's root (and == storage slot 3);
//   * only the current operator's inserts land (the handler tries a non-operator each time).
//
// No forge-std: `targetContracts()` / `targetSelectors()` are implemented directly.

import {Cheats} from "./Cheats.sol";
import {FuzzSelector} from "./FuzzHelpers.sol";
import {PaidAccessSet} from "../contracts/PaidAccessSet.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

/// A second operator identity the handler can rotate to and back.
contract OperatorProxy {
    function call(address target, bytes calldata data) external returns (bool ok) {
        (ok,) = target.call(data);
    }
}

contract PaidHandler is Cheats {
    PaidAccessSet public set;
    StakedReputationSet public ref;
    RateCommitmentHasher public hasher;
    OperatorProxy public alt;

    uint256 public constant BOND = 0.001 ether;
    address constant SINK = address(0x5151);
    address constant STRANGER = address(0xBAD);

    uint256[6] public secrets;
    uint256[6] public commits;
    uint256[6] public limits;

    uint256 public ghostInserts;
    uint256 public ghostLive;
    address public ghostOperator;

    constructor() {
        hasher = new RateCommitmentHasher();
        uint256[] memory l = new uint256[](2);
        l[0] = 8; l[1] = 32;
        set = new PaidAccessSet(address(this), ICommitmentHasher(address(hasher)), l); // this handler is the operator
        ghostOperator = address(this);
        alt = new OperatorProxy();
        MockWithdrawVerifier v = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        uint256[] memory xl = new uint256[](1);
        uint256[] memory xb = new uint256[](1);
        xl[0] = 32; xb[0] = 4 * BOND;
        ref = new StakedReputationSet(BOND, 300, 270, IWithdrawVerifier(address(v)), ICommitmentHasher(address(hasher)), xl, xb);
        for (uint256 i = 0; i < 6; i++) {
            secrets[i] = 1_000 + i;
            limits[i] = (i % 2 == 0) ? 8 : 32;
            commits[i] = hasher.commitmentOf(secrets[i], limits[i]);
        }
        vm.deal(address(this), 1_000_000 ether);
    }

    function _pick(uint256 seed) internal view returns (uint256 secret, uint256 commit, uint256 limit) {
        uint256 i = seed % 6;
        return (secrets[i], commits[i], limits[i]);
    }

    // Issue `insert(c, l)` as the CURRENT operator (this handler or the alt proxy).
    function _opInsert(uint256 c, uint256 l) internal {
        if (ghostOperator == address(this)) set.insert(c, l);
        else require(alt.call(address(set), abi.encodeWithSelector(PaidAccessSet.insert.selector, c, l)), "alt insert failed");
    }

    function insert(uint256 seed) external {
        (, uint256 commit, uint256 limit) = _pick(seed);
        if (set.limitOf(commit) != 0 || set.burned(commit)) return; // AlreadyInserted / burned
        // a non-operator must always be refused
        vm.prank(STRANGER);
        (bool ok,) = address(set).call(abi.encodeWithSelector(PaidAccessSet.insert.selector, commit, limit));
        require(!ok, "stranger insert must revert");
        // the OTHER identity (whichever is not the operator now) must be refused too
        if (ghostOperator == address(this)) require(!alt.call(address(set), abi.encodeWithSelector(PaidAccessSet.insert.selector, commit, limit)), "non-operator alt must revert");
        else { (ok,) = address(set).call(abi.encodeWithSelector(PaidAccessSet.insert.selector, commit, limit)); require(!ok, "old operator must revert"); }
        _opInsert(commit, limit);
        ref.register{value: ref.bondFor(limit)}(commit, limit);
        ghostInserts++;
        ghostLive++;
    }

    function insertBatch(uint256 seed) external {
        // batch every currently-absent pool leaf, in pool order
        uint256 n;
        for (uint256 i = 0; i < 6; i++) if (set.limitOf(commits[i]) == 0 && !set.burned(commits[i])) n++;
        if (n == 0) return;
        uint256[] memory c = new uint256[](n);
        uint256[] memory l = new uint256[](n);
        uint256 k;
        for (uint256 i = 0; i < 6; i++) if (set.limitOf(commits[i]) == 0 && !set.burned(commits[i])) { c[k] = commits[i]; l[k] = limits[i]; k++; }
        seed; // order fixed; seed unused
        if (ghostOperator == address(this)) set.insertBatch(c, l);
        else require(alt.call(address(set), abi.encodeWithSelector(PaidAccessSet.insertBatch.selector, c, l)), "alt batch failed");
        for (uint256 i = 0; i < n; i++) ref.register{value: ref.bondFor(l[i])}(c[i], l[i]);
        ghostInserts += n;
        ghostLive += n;
    }

    function slash(uint256 seed) external {
        (uint256 secret, uint256 commit, uint256 limit) = _pick(seed);
        if (set.limitOf(commit) == 0) return;
        uint256 other = limit == 8 ? 32 : 8;
        (bool ok,) = address(set).call(abi.encodeWithSelector(PaidAccessSet.slash.selector, commit, secret, other, SINK));
        require(!ok, "wrong-limit slash must revert");
        set.slash(commit, secret, limit, SINK);
        ref.slash(commit, secret, limit, SINK);
        ghostLive--;
    }

    /// Rotate the operator between this handler and the alt proxy (two-step, both directions).
    function rotateOperator() external {
        if (ghostOperator == address(this)) {
            set.setOperator(address(alt));
            require(alt.call(address(set), abi.encodeWithSelector(PaidAccessSet.acceptOperator.selector)), "alt accept failed");
            ghostOperator = address(alt);
        } else {
            require(alt.call(address(set), abi.encodeWithSelector(PaidAccessSet.setOperator.selector, address(this))), "alt nominate failed");
            set.acceptOperator();
            ghostOperator = address(this);
        }
    }

    receive() external payable {}
}

contract PaidAccessSetInvariantTest is Cheats {
    PaidHandler handler;

    function setUp() public {
        handler = new PaidHandler();
    }

    function targetContracts() public view returns (address[] memory addrs) {
        addrs = new address[](1);
        addrs[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory sel) {
        sel = new FuzzSelector[](1);
        bytes4[] memory s = new bytes4[](4);
        s[0] = PaidHandler.insert.selector;
        s[1] = PaidHandler.insertBatch.selector;
        s[2] = PaidHandler.slash.selector;
        s[3] = PaidHandler.rotateOperator.selector;
        sel[0] = FuzzSelector({addr: address(handler), selectors: s});
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_noFundsEver() public view {
        assertEq(address(handler.set()).balance, 0, "PaidAccessSet must never hold ETH");
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_leafCountEqualsInserts() public view {
        assertEq(handler.set().leafCount(), handler.ghostInserts(), "leafCount != inserts");
        assertEq(handler.set().liveCount(), handler.ghostLive(), "liveCount != inserts - slashes");
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_rootEqualsReference() public view {
        assertEq(handler.set().currentRoot(), handler.ref().currentRoot(), "root != reference StakedReputationSet root");
        assertEq(uint256(vm.load(address(handler.set()), bytes32(uint256(3)))), handler.set().currentRoot(), "slot 3 != currentRoot");
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_operatorIsGhost() public view {
        assertEq(handler.set().operator(), handler.ghostOperator());
        assertTrue(handler.set().pendingOperator() == address(0), "no dangling nomination after a completed rotation");
    }
}
