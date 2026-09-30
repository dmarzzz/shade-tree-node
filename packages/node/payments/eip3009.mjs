// EIP-3009 `transferWithAuthorization` typed data — the ONE settlement primitive both 402 rails
// (x402 `exact`/eip3009 and MPP `evm`/charge type="authorization") sign and the registrar submits.
//
// The buyer signs an EIP-712 TransferWithAuthorization over the token's domain; the OPERATOR
// submits it (`transferWithAuthorization(from,to,value,validAfter,validBefore,nonce,v,r,s)`) and
// pays the gas, so the buyer's wallet needs the stablecoin and NOTHING else. The token contract
// enforces single use per (from, nonce) — `authorizationState(from, nonce)` — which is the replay
// primitive both protocols lean on (x402 scheme_exact_evm.md §1; MPP draft-evm-charge-00 §"Replay
// Protection").
//
// Pure module: no I/O, no env. ethers is imported for TypedDataEncoder / verifyTypedData /
// Signature only (already a dependency: group/register-onchain.mjs, packages/node/lib/gateway-registry.mjs).
//
// Type string per EIP-3009 (and byte-identical to the one x402-specification-v2.md §6.1.1 lists):
//   TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,
//                             uint256 validBefore,bytes32 nonce)

import { ethers } from "ethers";

export const TRANSFER_WITH_AUTHORIZATION_TYPES = Object.freeze({
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
});

// keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
// == what USDC exposes as TRANSFER_WITH_AUTHORIZATION_TYPEHASH (checked on Sepolia USDC 2026-08-17).
export const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";

// The minimal ABI the registrar and the token probe need.
export const EIP3009_ABI = Object.freeze([
  "function name() view returns (string)",
  "function version() view returns (string)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function DOMAIN_SEPARATOR() view returns (bytes32)",
  "function balanceOf(address) view returns (uint256)",
  "function authorizationState(address authorizer, bytes32 nonce) view returns (bool)",
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)",
]);

// EIP-712 domain of the token: { name, version, chainId, verifyingContract }.
export function tokenDomain({ name, version, chainId, asset }) {
  return { name: String(name), version: String(version), chainId: Number(chainId), verifyingContract: ethers.getAddress(asset) };
}

export const isAddress = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
export const isBytes32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
// A decimal uint256 as a string ("10000"); no sign, no exponent, no leading + / whitespace.
export const isUintString = (v) => typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) < (1n << 256n);
export const sameAddress = (a, b) => isAddress(a) && isAddress(b) && a.toLowerCase() === b.toLowerCase();

// Shape-check an authorization object as it arrives on the wire (all numeric fields are decimal
// STRINGS per both specs). Returns null when well-formed, else a short reason.
export function checkAuthorizationShape(auth) {
  if (!auth || typeof auth !== "object" || Array.isArray(auth)) return "authorization must be an object";
  for (const k of ["from", "to"]) if (!isAddress(auth[k])) return `authorization.${k} must be a 0x address`;
  for (const k of ["value", "validAfter", "validBefore"]) if (!isUintString(auth[k])) return `authorization.${k} must be a decimal uint256 string`;
  if (!isBytes32(auth.nonce)) return "authorization.nonce must be 32 bytes hex";
  return null;
}

// Fresh random 32-byte nonce (x402 exact/eip3009: "a 32-byte random value").
export function randomNonce() {
  return ethers.hexlify(ethers.randomBytes(32));
}

// Sign a TransferWithAuthorization with an ethers Signer that supports signTypedData (Wallet).
export async function signAuthorization(signer, domain, auth) {
  const shapeErr = checkAuthorizationShape(auth);
  if (shapeErr) throw new Error(shapeErr);
  return signer.signTypedData(domain, TRANSFER_WITH_AUTHORIZATION_TYPES, auth);
}

// Recover the signer of an authorization; returns the checksummed address, or null when the
// signature is malformed (never throws — a wire surface).
export function recoverAuthorization(domain, auth, signature) {
  try {
    if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
    return ethers.verifyTypedData(domain, TRANSFER_WITH_AUTHORIZATION_TYPES, auth, signature);
  } catch {
    return null;
  }
}

// EIP-712 digest of an authorization (what the contract recovers against).
export function authorizationDigest(domain, auth) {
  return ethers.TypedDataEncoder.hash(domain, TRANSFER_WITH_AUTHORIZATION_TYPES, auth);
}

// { v, r, s } for the on-chain call.
export function splitSignature(signature) {
  const s = ethers.Signature.from(signature);
  return { v: s.v, r: s.r, s: s.s };
}
