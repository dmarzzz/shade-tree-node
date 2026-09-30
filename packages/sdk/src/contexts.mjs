// The action contexts the staking contract binds exit and withdraw proofs to. These must match
// contracts/StakedReputationSet.sol byte for byte (test/wire-freeze.selftest.mjs pins the tags).
//
// ShadeNet sets (launch audit 2.2.1) bind the chain, the set address and the member's leaf index:
//   exit     keccak256(abi.encodePacked("SHADENET_EXIT", chainId, set, leaf, index))
//   withdraw keccak256(abi.encodePacked("SHADENET_WITHDRAW", chainId, set, leaf, index, recipient))
// Pass `binding = { chainId, contract, index }` for those. Without a binding these return the v4
// contexts of the retired v4 set, which the bundled record may still name until its replacement.

import { solidityPackedKeccak256, getAddress } from "ethers";
import { FIELD } from "../../node/lib/identity-core.mjs";

export function exitContext(commitment, binding = null) {
  if (!binding) return solidityPackedKeccak256(["string", "uint256"], ["SHADE_TREE_EXIT", BigInt(commitment)]);
  return solidityPackedKeccak256(
    ["string", "uint256", "address", "uint256", "uint256"],
    ["SHADENET_EXIT", BigInt(binding.chainId), getAddress(binding.contract), BigInt(commitment), BigInt(binding.index)],
  );
}

export function withdrawContext(commitment, recipient, binding = null) {
  if (!binding) {
    return solidityPackedKeccak256(["string", "uint256", "address"], ["SHADE_TREE_WITHDRAW", BigInt(commitment), getAddress(recipient)]);
  }
  return solidityPackedKeccak256(
    ["string", "uint256", "address", "uint256", "uint256", "address"],
    ["SHADENET_WITHDRAW", BigInt(binding.chainId), getAddress(binding.contract), BigInt(commitment), BigInt(binding.index), getAddress(recipient)],
  );
}

// The withdraw circuit's public `address` input: the context reduced into the field.
export const contextToField = (contextHex) => BigInt(contextHex) % FIELD;
