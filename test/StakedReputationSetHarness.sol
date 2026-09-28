// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StakedReputationSet, IWithdrawVerifier, ICommitmentHasher} from "../contracts/StakedReputationSet.sol";

/// TEST-ONLY. Exposes the leaf-level admission path (`_admit`) under the pre-M1 `register`
/// names so bookkeeping, tree-parity and cross-contract tests can post raw leaves (fuzzed
/// values, golden vectors). `_admit` applies the same bond, tier and canonical-leaf checks as
/// `registerIdentity`; only the Poseidon2(idc, limit) derivation is skipped. Never deployed:
/// the production set has no way to register a leaf it did not derive.
contract StakedReputationSetHarness is StakedReputationSet {
    constructor(
        uint256 bond,
        uint256 unbonding,
        uint256 minUnbonding,
        IWithdrawVerifier _withdrawVerifier,
        ICommitmentHasher _hasher,
        uint256[] memory extraLimits,
        uint256[] memory extraBonds
    ) StakedReputationSet(bond, unbonding, minUnbonding, _withdrawVerifier, _hasher, extraLimits, extraBonds) {}

    function register(uint256 commitment, uint256 limit) public payable {
        _admit(commitment, limit);
    }

    function register(uint256 commitment) external payable {
        _admit(commitment, DEFAULT_LIMIT);
    }
}
