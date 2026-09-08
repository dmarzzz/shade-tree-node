// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Cheats} from "../../test/Cheats.sol";
import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../StakedReputationSet.sol";
import {GatewayRegistry} from "../GatewayRegistry.sol";
import {RateCommitmentHasher} from "../RateCommitmentHasher.sol";
import {MockWithdrawVerifier} from "../MockWithdrawVerifier.sol";
import {WithdrawGroth16Verifier} from "../WithdrawGroth16Verifier.sol";
import {WithdrawVerifier} from "../WithdrawVerifier.sol";

/// DeployRegistry — the persistent on-chain deployer for T-DEPLOY-7.
///
/// Deploys `GatewayRegistry` (the gateway-operator stake the bootnode reads for
/// `stake`-mode admission) and, unless disabled, `StakedReputationSet` (the member
/// admission set). Every constructor argument is sourced from an environment variable
/// with a safe default, so the SAME script deploys to a local anvil, Sepolia, or a chosen
/// L2 by changing only `--rpc-url` and the env. It logs each deployed address and records
/// them to a JSON file the gateway/lib read (`contracts/deployed.local.json` by default).
///
/// This differs from `script/Deploy.s.sol` (the local demo-stack deployer) in two ways
/// that matter for a persistent testnet/L2 deployment:
///   1. It takes the ZK verifier + commitment hasher as ADDRESSES from env, so a real
///      pre-deployed RLN/Groth16 verifier can be wired in. It falls back to deploying the
///      in-repo Mock verifier/hasher ONLY when those env vars are unset, and shouts a
///      warning when it does, because the mocks are not zero-knowledge (testnet-only).
///   2. The output path is parameterized (SHADE_TREE_DEPLOY_OUT), so a simulation run can be
///      pointed at a scratch file and never clobber a committed record.
///
/// SCOPE: this file is deploy TOOLING. Broadcasting a real transaction (spending funds on
/// a live chain) is an operator action, gated behind `--broadcast` + a funded key, and is
/// documented in docs/ONCHAIN-DEPLOY.md. Running this script WITHOUT `--broadcast`
/// simulates the whole deploy against Foundry's in-memory EVM and sends nothing.
///
/// Reference implementation, unaudited, testnet-only.
///
/// Environment variables (all optional; defaults in parens):
///   SHADE_TREE_BOND_WEI          fixed stake denomination, wei         (0.01 ether)
///   SHADE_TREE_UNBONDING         exit time-lock, seconds               (300; public profile: 86400)
///   SHADE_TREE_MIN_UNBONDING     F+E+C lower bound the ctor enforces   (270; public profile: 3720)
///   SHADE_TREE_GATEWAY_OWNER     GatewayRegistry slashing/gov address  (0 => deployer)
///   SHADE_TREE_DEPLOY_STAKED     1 = also deploy StakedReputationSet   (1)
///   SHADE_TREE_DEPLOY_REGISTRY   1 = deploy GatewayRegistry; 0 = keep an existing one and only
///                          record SHADE_TREE_GATEWAY_REGISTRY (addr) in the JSON     (1)
///                          (the rln-v4 Sepolia redeploy: the live registry stays as is)
///   SHADE_TREE_WITHDRAW_VERIFIER pre-deployed IWithdrawVerifier addr   (0 => deploy per below)
///   SHADE_TREE_DEPLOY_REAL_VERIFIER 1 = deploy REAL Groth16 verifier   (0 => deploy Mock)
///                          (only when SHADE_TREE_WITHDRAW_VERIFIER unset; testnet-only VK)
///   SHADE_TREE_COMMITMENT_HASHER pre-deployed ICommitmentHasher addr   (0 => deploy RateCommitmentHasher)
///                          (must implement the TIERED commitmentOf(secret, limit); the
///                          rln-v3 hasher 0x08F9a754… pins K=8 and cannot be reused)
///   SHADE_TREE_TIER_LIMITS       extra admitted tiers, comma-separated   ("" => default tier 8 only)
///                          e.g. "32" or "32,64"; ascending, distinct, 1..65535, != 8
///   SHADE_TREE_TIER_BONDS_WEI    bond of each extra tier, comma-separated, same length as
///                          SHADE_TREE_TIER_LIMITS; each nonzero            (required with SHADE_TREE_TIER_LIMITS)
///                          The default tier 8 always costs SHADE_TREE_BOND_WEI.
///   SHADE_TREE_PUBLIC_STAKE_PROFILE 1 = pin the public Sepolia table:
///                          tier 1 => 0.1 ether, tier 8 => 0.8 ether, with the real
///                          Groth16 exit verifier. Every Proxy/node must separately use
///                          SHADE_TREE_EPOCH_SECONDS=60; epoch length is off chain.
///   SHADE_TREE_RPC_URL           endpoint, recorded into the JSON      ("http://127.0.0.1:8545")
///   SHADE_TREE_DEPLOY_OUT        JSON output path                      ("contracts/deployed.local.json")
contract DeployRegistry is Cheats {
    function run()
        external
        returns (
            address gatewayRegistry,
            address stakedReputationSet,
            address withdrawVerifier,
            address commitmentHasher
        )
    {
        // ---- parameters (env-overridable) ------------------------------------
        bool publicStakeProfile = vm.envOr("SHADE_TREE_PUBLIC_STAKE_PROFILE", uint256(0)) != 0;
        uint256 bond = vm.envOr("SHADE_TREE_BOND_WEI", publicStakeProfile ? uint256(0.8 ether) : uint256(0.01 ether));
        uint256 unbonding = vm.envOr("SHADE_TREE_UNBONDING", publicStakeProfile ? uint256(1 days) : uint256(300));
        uint256 minUnbonding = vm.envOr("SHADE_TREE_MIN_UNBONDING", publicStakeProfile ? uint256(3720) : uint256(270)); // root freshness + epoch + slash confirmation
        address gwOwner = vm.envOr("SHADE_TREE_GATEWAY_OWNER", address(0)); // 0 => deployer
        bool deployStaked = vm.envOr("SHADE_TREE_DEPLOY_STAKED", uint256(1)) != 0;
        bool deployRegistry = vm.envOr("SHADE_TREE_DEPLOY_REGISTRY", uint256(1)) != 0;
        if (publicStakeProfile) {
            require(block.chainid == 11155111, "public stake profile is Sepolia-only");
            require(deployStaked, "public stake profile requires SHADE_TREE_DEPLOY_STAKED=1");
            require(!deployRegistry, "public stake profile reuses the live GatewayRegistry");
            require(bond == 0.8 ether, "public stake profile pins tier 8 to 0.8 ether");
            require(unbonding == 1 days, "public stake profile pins unbonding to 24 hours");
            require(minUnbonding == 3720, "public stake profile pins F+E+C minimum to 3720 seconds");
        }

        console.log("== DeployRegistry ==");
        console.log("chainid    ", block.chainid);
        console.log("bond (wei) ", bond);
        console.log("unbonding  ", unbonding);
        console.log("minUnbond  ", minUnbonding);
        if (publicStakeProfile) console.log("profile      public-stake-v1 (tier 1 = 0.1 ether)");

        vm.startBroadcast();

        // ---- GatewayRegistry: the gateway-operator stake ---------------------
        // owner (slasher/governance) defaults to the deployer when 0 (ctor enforces it).
        // SHADE_TREE_DEPLOY_REGISTRY=0 keeps a live registry untouched and just records its address.
        if (deployRegistry) {
            GatewayRegistry gwReg = new GatewayRegistry(bond, unbonding, minUnbonding, gwOwner);
            gatewayRegistry = address(gwReg);
        } else {
            gatewayRegistry = vm.envOr("SHADE_TREE_GATEWAY_REGISTRY", address(0));
            require(gatewayRegistry != address(0), "SHADE_TREE_GATEWAY_REGISTRY required when registry deploy disabled");
            console.log("GatewayRegistry: not deployed (SHADE_TREE_DEPLOY_REGISTRY=0); recording", gatewayRegistry);
        }

        // ---- StakedReputationSet: the member admission set (optional) --------
        if (deployStaked) {
            (stakedReputationSet, withdrawVerifier, commitmentHasher) =
                _deploySet(bond, unbonding, minUnbonding, publicStakeProfile);
        }

        vm.stopBroadcast();

        // ---- log + record ----------------------------------------------------
        console.log("GatewayRegistry     ", gatewayRegistry);
        if (deployStaked) {
            console.log("StakedReputationSet ", stakedReputationSet);
            console.log("withdrawVerifier    ", withdrawVerifier);
            console.log("commitmentHasher    ", commitmentHasher);
        } else {
            console.log("StakedReputationSet   (skipped: SHADE_TREE_DEPLOY_STAKED=0)");
        }

        _writeDeployment(gatewayRegistry, stakedReputationSet, commitmentHasher, withdrawVerifier, publicStakeProfile);
    }

    /// Deploy the member admission set: hasher + exit-auth verifier (pre-deployed addresses
    /// from env, else fresh) + the tiered StakedReputationSet (T-FEAT-8b tier table from
    /// SHADE_TREE_TIER_LIMITS / SHADE_TREE_TIER_BONDS_WEI). Split out of run() to keep the stack shallow.
    function _deploySet(uint256 bond, uint256 unbonding, uint256 minUnbonding, bool publicStakeProfile)
        internal
        returns (address set, address verifierAddr, address hasherAddr)
    {
        verifierAddr = vm.envOr("SHADE_TREE_WITHDRAW_VERIFIER", address(0));
        hasherAddr = vm.envOr("SHADE_TREE_COMMITMENT_HASHER", address(0));
        if (publicStakeProfile) {
            require(verifierAddr == address(0), "public stake profile deploys the pinned in-repo verifier");
            require(hasherAddr == address(0), "public stake profile deploys the pinned in-repo hasher");
        }
        // Opt-in: when no pre-deployed verifier address is given, deploy the REAL Groth16
        // exit-auth verifier (T-DEV-1) instead of the revealed-secret Mock. Default 0 keeps
        // the Mock so the local demo (scripts/demo-e2e.mjs, which authorizes by revealing the
        // secret) still works. The REAL verifier is TESTNET-ONLY until T-HARD-1 (untrusted VK).
        bool realVerifier =
            vm.envOr("SHADE_TREE_DEPLOY_REAL_VERIFIER", publicStakeProfile ? uint256(1) : uint256(0)) != 0;
        if (publicStakeProfile) {
            require(realVerifier, "public stake profile requires SHADE_TREE_DEPLOY_REAL_VERIFIER=1");
        }
        // T-FEAT-8b tier table (extra tiers beyond the default limit 8 => SHADE_TREE_BOND_WEI).
        uint256[] memory extraLimits =
            _parseUintList(vm.envOr("SHADE_TREE_TIER_LIMITS", publicStakeProfile ? string("1") : string("")));
        uint256[] memory extraBonds = _parseUintList(
            vm.envOr("SHADE_TREE_TIER_BONDS_WEI", publicStakeProfile ? string("100000000000000000") : string(""))
        );
        require(
            extraLimits.length == extraBonds.length,
            "SHADE_TREE_TIER_LIMITS / SHADE_TREE_TIER_BONDS_WEI length mismatch"
        );
        if (publicStakeProfile) {
            require(
                extraLimits.length == 1 && extraLimits[0] == 1 && extraBonds[0] == 0.1 ether,
                "public stake profile pins tier 1 to 0.1 ether"
            );
        }
        console.log("tier 8 bond", bond);
        for (uint256 i = 0; i < extraLimits.length; i++) {
            console.log("tier       ", extraLimits[i]);
            console.log("  bond     ", extraBonds[i]);
        }

        // Wire the real ZK verifier + hasher if their addresses were supplied; otherwise deploy
        // the in-repo ones. The hasher is the REAL Poseidon rate-commitment hasher (tiered,
        // T-FEAT-8b); only the exit-auth verifier has a Mock (TESTNET ONLY — not zero-knowledge).
        if (hasherAddr == address(0)) {
            RateCommitmentHasher h = new RateCommitmentHasher();
            hasherAddr = address(h);
            console.log("deployed RateCommitmentHasher (tiered Poseidon rate-commitment hasher)");
        }
        if (verifierAddr == address(0)) {
            if (realVerifier) {
                // REAL Groth16 exit-auth verifier (T-DEV-1). Genuine ZK proof of knowledge
                // of the identity secret; nothing revealed in calldata.
                WithdrawGroth16Verifier groth16 = new WithdrawGroth16Verifier();
                WithdrawVerifier realV = new WithdrawVerifier(groth16);
                verifierAddr = address(realV);
                console.log("deployed WithdrawVerifier (REAL Groth16 exit-auth)");
                console.log("  WARNING: testnet-only VK (untrusted dev setup, T-HARD-1 pending)");
            } else {
                MockWithdrawVerifier mockVerifier = new MockWithdrawVerifier(ICommitmentHasher(hasherAddr));
                verifierAddr = address(mockVerifier);
                console.log("WARNING: deployed MockWithdrawVerifier (testnet-only, secret revealed in calldata)");
            }
        }

        StakedReputationSet s = new StakedReputationSet(
            bond,
            unbonding,
            minUnbonding,
            IWithdrawVerifier(verifierAddr),
            ICommitmentHasher(hasherAddr),
            extraLimits,
            extraBonds
        );
        set = address(s);
        console.log("slash reward divisor", s.SLASH_REWARD_DIVISOR());
        console.log("slash burn address  ", s.SLASH_BURN_ADDRESS());
    }

    /// Parse "a,b,c" (decimal, no spaces) into a uint256[]; "" => empty. Reverts on any
    /// non-digit so a typo in the tier table fails the deploy instead of admitting a bad tier.
    function _parseUintList(string memory csv) internal pure returns (uint256[] memory out) {
        bytes memory b = bytes(csv);
        if (b.length == 0) return out;
        uint256 n = 1;
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ",") n++;
        }
        out = new uint256[](n);
        uint256 k = 0;
        uint256 acc = 0;
        bool any = false;
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ",") {
                require(any, "SHADE_TREE_TIER_*: empty list item");
                out[k++] = acc;
                acc = 0;
                any = false;
            } else {
                require(b[i] >= "0" && b[i] <= "9", "SHADE_TREE_TIER_*: digits only");
                acc = acc * 10 + (uint8(b[i]) - 48);
                any = true;
            }
        }
        require(any, "SHADE_TREE_TIER_*: empty list item");
        out[k] = acc;
    }

    /// Record the addresses to a JSON file the gateway/lib read to find the contracts.
    /// Path is env-overridable (SHADE_TREE_DEPLOY_OUT) so a simulation can target a scratch file
    /// and leave the committed `contracts/deployed.local.json` untouched.
    function _writeDeployment(address gwReg, address set, address hasher, address verifier, bool publicStakeProfile)
        internal
    {
        string memory outPath = vm.envOr("SHADE_TREE_DEPLOY_OUT", string("contracts/deployed.local.json"));
        string memory rpcUrl = vm.envOr("SHADE_TREE_RPC_URL", string("http://127.0.0.1:8545"));
        uint256 bond = vm.envOr("SHADE_TREE_BOND_WEI", publicStakeProfile ? uint256(0.8 ether) : uint256(0.01 ether));
        uint256 unbonding = vm.envOr("SHADE_TREE_UNBONDING", publicStakeProfile ? uint256(1 days) : uint256(300));
        uint256 minUnbonding = vm.envOr("SHADE_TREE_MIN_UNBONDING", publicStakeProfile ? uint256(3720) : uint256(270));

        // stakedReputationSet/hasher/verifier are the zero address when the set is skipped;
        // the gateway/lib only need gatewayRegistry + rpcUrl for stake-mode admission.
        string memory setStr = set != address(0) ? vm.toString(set) : "";
        string memory hasherStr = hasher != address(0) ? vm.toString(hasher) : "";
        string memory verifierStr = verifier != address(0) ? vm.toString(verifier) : "";

        string memory json = string.concat(
            "{\n",
            '  "gatewayRegistry": "',
            vm.toString(gwReg),
            '",\n',
            '  "stakedReputationSet": "',
            setStr,
            '",\n',
            '  "hasher": "',
            hasherStr,
            '",\n',
            '  "verifier": "',
            verifierStr,
            '",\n',
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n"
        );
        json = string.concat(
            json,
            '  "profile": ',
            publicStakeProfile ? '"public-stake-v1"' : "null",
            ",\n",
            '  "defaultBondWei": "',
            vm.toString(bond),
            '",\n',
            '  "unbondingSeconds": ',
            vm.toString(unbonding),
            ",\n",
            '  "minUnbondingSeconds": ',
            vm.toString(minUnbonding),
            ",\n"
        );
        json = string.concat(json, '  "slashPayout": ', _slashPayoutJson(set), ",\n");
        json = string.concat(json, '  "rpcUrl": "', rpcUrl, '"\n', "}\n");
        vm.writeFile(outPath, json);
        console.log("wrote", outPath);
    }

    function _slashPayoutJson(address set) internal view returns (string memory) {
        if (set == address(0)) {
            return "null";
        } else {
            return string.concat(
                '{"policy":"burn-90-reward-10-v1","rewardDivisor":',
                vm.toString(StakedReputationSet(set).SLASH_REWARD_DIVISOR()),
                ',"burnAddress":"',
                vm.toString(StakedReputationSet(set).SLASH_BURN_ADDRESS()),
                '"}'
            );
        }
    }
}

/// Minimal `console.log` shim (staticcalls Foundry's console precompile), so this script
/// prints deployed addresses in `forge script` output without pulling in forge-std — the
/// same "no lib/ submodule" constraint that test/Cheats.sol exists to satisfy.
library console {
    address constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    function _send(bytes memory payload) private view {
        address target = CONSOLE;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            pop(staticcall(gas(), target, add(payload, 0x20), mload(payload), 0x00, 0x00))
        }
    }

    function log(string memory a) internal view {
        _send(abi.encodeWithSignature("log(string)", a));
    }

    function log(string memory a, address b) internal view {
        _send(abi.encodeWithSignature("log(string,address)", a, b));
    }

    function log(string memory a, uint256 b) internal view {
        _send(abi.encodeWithSignature("log(string,uint256)", a, b));
    }

    function log(string memory a, string memory b) internal view {
        _send(abi.encodeWithSignature("log(string,string)", a, b));
    }
}
