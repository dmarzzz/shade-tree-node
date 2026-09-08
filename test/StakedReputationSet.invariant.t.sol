// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Invariant test for StakedReputationSet. A handler drives random register / initiateExit /
// withdraw / slash / warp sequences over a fixed pool of (secret, rate-commitment) pairs and
// tracks the expected state in ghost counters. After every call Foundry re-checks:
//
//   * activeCount always equals the number of currently-active members;
//   * the contract's ETH balance always equals the sum of live bonds — no wei created or
//     destroyed across the register/exit/withdraw/slash lifecycle. T-FEAT-8b: the pool mixes
//     public tier-1 (0.1 ether) and tier-8 (0.8 ether) members, so this now also proves per-tier bond
//     accounting (register takes the bond; slash splits it and withdrawal returns it) and that a
//     member's recorded limit is the only limit its slash succeeds at.
//
// No forge-std: `targetContracts()` / `targetSelectors()` are implemented directly.

import {Cheats} from "./Cheats.sol";
import {FuzzSelector} from "./FuzzHelpers.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {RateCommitmentHasher} from "../contracts/RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

contract SetHandler is Cheats {
    StakedReputationSet public set;
    RateCommitmentHasher public hasher;
    MockWithdrawVerifier public verifier;

    uint256 public constant BOND = 0.8 ether; // public profile's default tier-8 bond
    uint256 public constant BOND1 = 0.1 ether;
    uint256 public constant UNBONDING = 300;
    uint256 public constant MIN_UNBONDING = 270;

    address constant SINK = address(0x5151); // EOA payout sink (withdraw recipient + slash receiver)

    // Fixed pool of identity secrets and their pinned rate commitments (the tree leaves).
    // Even indices are tier-1 leaves, odd indices tier-8 leaves (public-stake-v1).
    uint256[6] public secrets;
    uint256[6] public commits;
    uint256[6] public limits;

    uint256 public ghostActive; // active members
    uint256 public ghostLiveWei; // bond wei still held (active or exiting), summed per tier
    uint256 public ghostBurnedWei;
    uint256 public ghostRewardWei;
    uint256 public ghostWithdrawnWei;
    uint256 public initialBurnBalance;
    uint256 public initialSinkBalance;

    constructor() {
        hasher = new RateCommitmentHasher();
        verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        set = new StakedReputationSet(
            BOND,
            UNBONDING,
            MIN_UNBONDING,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            _tierLimits(),
            _tierBonds()
        );
        initialBurnBalance = set.SLASH_BURN_ADDRESS().balance;
        initialSinkBalance = SINK.balance;
        for (uint256 i = 0; i < 6; i++) {
            uint256 secret = 1_000 + i; // distinct, small secrets => distinct leaves
            secrets[i] = secret;
            limits[i] = (i % 2 == 0) ? 1 : 8;
            commits[i] = hasher.commitmentOf(secret, limits[i]);
        }
        vm.deal(address(this), 1_000_000 ether);
    }

    function _tierLimits() internal pure returns (uint256[] memory l) {
        l = new uint256[](1);
        l[0] = 1;
    }

    function _tierBonds() internal pure returns (uint256[] memory b) {
        b = new uint256[](1);
        b[0] = BOND1;
    }

    function _pick(uint256 seed) internal view returns (uint256 secret, uint256 commit, uint256 limit) {
        uint256 i = seed % 6;
        return (secrets[i], commits[i], limits[i]);
    }

    function _proof(uint256 secret) internal pure returns (bytes memory) {
        return abi.encode(secret);
    }

    function register(uint256 seed) external {
        (, uint256 commit, uint256 limit) = _pick(seed);
        (uint256 bond,,,) = set.members(commit);
        if (bond != 0) return; // AlreadyMember

        uint256 due = set.bondFor(limit);
        vm.deal(address(this), due);
        set.register{value: due}(commit, limit);
        ghostActive++;
        ghostLiveWei += due;
    }

    function initiateExit(uint256 seed) external {
        (uint256 secret, uint256 commit,) = _pick(seed);
        (uint256 bond,, uint64 exitAt,) = set.members(commit);
        if (bond == 0 || exitAt != 0) return;

        set.initiateExit(commit, _proof(secret));
        ghostActive--;
    }

    function withdraw(uint256 seed) external {
        (uint256 secret, uint256 commit,) = _pick(seed);
        (uint256 bond,, uint64 exitAt,) = set.members(commit);
        if (bond == 0 || exitAt == 0) return;
        if (block.timestamp < uint256(exitAt) + UNBONDING) return; // StillBonded

        set.withdraw(commit, SINK, _proof(secret));
        ghostLiveWei -= bond;
        ghostWithdrawnWei += bond;
    }

    function slash(uint256 seed) external {
        (uint256 secret, uint256 commit, uint256 limit) = _pick(seed);
        (uint256 bond,, uint64 exitAt,) = set.members(commit);
        if (bond == 0) return;

        // The OTHER tier's claim must always revert (wrong-limit slash) and change nothing.
        uint256 other = limit == 1 ? 8 : 1;
        (bool ok,) = address(set).call(
            abi.encodeWithSignature("slash(uint256,uint256,uint256,address)", commit, secret, other, SINK)
        );
        require(!ok, "wrong-limit slash must revert");

        bool wasActive = exitAt == 0;
        set.slash(commit, secret, limit, SINK);
        if (wasActive) ghostActive--;
        ghostLiveWei -= bond;
        ghostRewardWei += bond / 10;
        ghostBurnedWei += bond - bond / 10;
    }

    function sinkBalance() external view returns (uint256) {
        return SINK.balance;
    }

    function warp(uint256 dt) external {
        dt = dt % (2 * UNBONDING + 1);
        vm.warp(block.timestamp + dt);
    }
}

contract StakedReputationSetInvariantTest is Cheats {
    SetHandler handler;

    function setUp() public {
        handler = new SetHandler();
    }

    function targetContracts() public view returns (address[] memory addrs) {
        addrs = new address[](1);
        addrs[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory sel) {
        sel = new FuzzSelector[](1);
        bytes4[] memory s = new bytes4[](5);
        s[0] = SetHandler.register.selector;
        s[1] = SetHandler.initiateExit.selector;
        s[2] = SetHandler.withdraw.selector;
        s[3] = SetHandler.slash.selector;
        s[4] = SetHandler.warp.selector;
        sel[0] = FuzzSelector({addr: address(handler), selectors: s});
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_activeCountMatchesActiveMembers() public view {
        assertEq(handler.set().activeCount(), handler.ghostActive(), "activeCount != number of active members");
    }

    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 64
    function invariant_ethEqualsSumOfLiveBonds() public view {
        assertEq(address(handler.set()).balance, handler.ghostLiveWei(), "contract ETH != sum of live bonds (per tier)");
        assertEq(
            handler.set().SLASH_BURN_ADDRESS().balance - handler.initialBurnBalance(),
            handler.ghostBurnedWei(),
            "mandatory burn differs from accumulated penalties"
        );
        assertEq(
            handler.sinkBalance() - handler.initialSinkBalance(),
            handler.ghostRewardWei() + handler.ghostWithdrawnWei(),
            "receiver got more than bounties plus honest withdrawals"
        );
    }
}
