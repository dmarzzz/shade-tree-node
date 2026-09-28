// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "../test/Cheats.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";
import {GatewayRegistry} from "../contracts/GatewayRegistry.sol";
import {MockCommitmentHasher} from "../contracts/MockCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../contracts/MockWithdrawVerifier.sol";

/// Deploys the demo stack (hasher + verifier + StakedReputationSet) with the
/// docs/NEXT-VERSION.md demo params, then writes the addresses to
/// contracts/deployed.local.json for the gateway/lib to read.
///
/// Run against a local anvil:
///   anvil                                     # terminal 1
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url http://127.0.0.1:8545 \
///     --broadcast \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
/// (anvil's well-known account #0 — a public test key, never real funds.)
contract Deploy is Cheats {
    // Demo parameters (docs/NEXT-VERSION.md). Env-overridable so a testnet deploy can
    // use a smaller bond than the local-anvil default (testnet ETH is faucet-scarce):
    //   SHADE_TREE_BOND_WEI, SHADE_TREE_UNBONDING, SHADE_TREE_MIN_UNBONDING.
    function run() external {
        uint256 bond = vm.envOr("SHADE_TREE_BOND_WEI", uint256(0.01 ether));
        uint256 unbonding = vm.envOr("SHADE_TREE_UNBONDING", uint256(300));
        uint256 minUnbonding = vm.envOr("SHADE_TREE_MIN_UNBONDING", uint256(270)); // F+E+C lower bound

        vm.startBroadcast();

        MockCommitmentHasher hasher = new MockCommitmentHasher();
        MockWithdrawVerifier verifier = new MockWithdrawVerifier(ICommitmentHasher(address(hasher)));
        // Local demo: the default tier (limit 8, BOND) plus tier 32 at 4*BOND (T-FEAT-8b),
        // so the anvil selftests can stake at both tiers.
        uint256[] memory extraLimits = new uint256[](1);
        uint256[] memory extraBonds = new uint256[](1);
        extraLimits[0] = 32;
        extraBonds[0] = 4 * bond;
        StakedReputationSet set = new StakedReputationSet(
            bond,
            unbonding,
            minUnbonding,
            IWithdrawVerifier(address(verifier)),
            ICommitmentHasher(address(hasher)),
            extraLimits,
            extraBonds,
            10
        );

        // Gateway operator stake (optional at the bootnode; deployed so the on-chain path exists).
        // Same bond/unbonding params; owner (slasher) defaults to the deployer/broadcaster.
        address gwOwner = vm.envOr("SHADE_TREE_GATEWAY_OWNER", address(0));
        GatewayRegistry gwReg = new GatewayRegistry(bond, unbonding, minUnbonding, gwOwner);

        vm.stopBroadcast();

        _writeDeployment(address(set), address(hasher), address(verifier), address(gwReg));
    }

    function _writeDeployment(address set, address hasher, address verifier, address gwReg) internal {
        // rpcUrl defaults to local anvil; override with SHADE_TREE_RPC_URL for a fork/testnet.
        string memory rpcUrl = vm.envOr("SHADE_TREE_RPC_URL", string("http://127.0.0.1:8545"));
        string memory json = string.concat(
            "{\n",
            '  "stakedReputationSet": "', vm.toString(set), '",\n',
            '  "gatewayRegistry": "', vm.toString(gwReg), '",\n',
            '  "hasher": "', vm.toString(hasher), '",\n',
            '  "verifier": "', vm.toString(verifier), '",\n',
            '  "rpcUrl": "', rpcUrl, '"\n',
            "}\n"
        );
        vm.writeFile("contracts/deployed.local.json", json);
    }
}
