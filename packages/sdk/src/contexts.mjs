// The action contexts the staking contract binds exit and withdraw proofs to. These must match
// contracts/StakedReputationSet.sol byte for byte (test/wire-freeze.selftest.mjs pins the tags).
// When a fresh deploy changes them (roadmap M1, CHAIN-4), this file is the one JS place to update.

import { solidityPackedKeccak256, getAddress } from "ethers";
import { FIELD } from "../../../lib/identity-core.mjs";

export function exitContext(commitment) {
  return solidityPackedKeccak256(["string", "uint256"], ["SHADE_TREE_EXIT", BigInt(commitment)]);
}

export function withdrawContext(commitment, recipient) {
  return solidityPackedKeccak256(["string", "uint256", "address"], ["SHADE_TREE_WITHDRAW", BigInt(commitment), getAddress(recipient)]);
}

// The withdraw circuit's public `address` input: the context reduced into the field.
export const contextToField = (contextHex) => BigInt(contextHex) % FIELD;
