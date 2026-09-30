// Isomorphic identity math: the member identity secret, its RLN leaf, and the identity file.
// No Node imports, so the gateway (via packages/node/lib/rln.mjs), the Node SDK and the browser SDK share it.
//
//   appSecret        a 32-byte seed reduced into the field (what `shade-tree identity` calls the secret)
//   identitySecret   Semaphore-v3 Poseidon2(nullifier, trapdoor), nullifier/trapdoor from SHA-512(appSecret)
//   leaf             RLN rateCommitment = Poseidon2(Poseidon1(identitySecret), limit)
//
// poseidon-lite is imported by subpath so a browser bundle carries only the two widths it uses.

import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// RLN(20, 16): the circuit range-checks messageId against a 16-bit limit.
export const MAX_LIMIT = 65535;

const encoder = new TextEncoder();
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

// A tier limit as a bigint in 1..MAX_LIMIT. Throws on anything else.
export function tierLimit(limit) {
  let n;
  if (typeof limit === "bigint") n = limit;
  else if (typeof limit === "number" && Number.isSafeInteger(limit)) n = BigInt(limit);
  else if (typeof limit === "string" && /^[0-9]+$/.test(limit)) n = BigInt(limit);
  else throw new Error("limit: not an integer");
  if (n < 1n || n > BigInt(MAX_LIMIT)) throw new Error(`limit: out of range 1..${MAX_LIMIT} (got ${n})`);
  return n;
}

// A canonical decimal field element (no leading zeros, < FIELD, nonzero by default).
export function canonicalField(value, label = "value", { nonzero = true } = {}) {
  if (typeof value !== "string" || !DECIMAL_RE.test(value)) {
    throw new Error(`${label} must be a canonical decimal field element.`);
  }
  const parsed = BigInt(value);
  if (parsed >= FIELD || (nonzero && parsed === 0n)) {
    throw new Error(`${label} is outside the supported identity field.`);
  }
  return parsed;
}

export function identityCommitmentOf(identitySecret) {
  return poseidon1([BigInt(identitySecret)]);
}

// The RLN leaf for an identity secret at a tier.
export function rateCommitment(identitySecret, limit) {
  return poseidon2([poseidon1([BigInt(identitySecret)]), tierLimit(limit)]);
}

// The leaf a ShadeNet staking set derives from a public identity commitment at a tier
// (StakedReputationSet.registerIdentity, launch audit 2.1.4).
export function leafFromIdentityCommitment(identityCommitment, limit) {
  return poseidon2([BigInt(identityCommitment), tierLimit(limit)]);
}

// Semaphore-v3 identity secret for an app secret (bigint or decimal string), using WebCrypto
// SHA-512 exactly as `new Identity(appSecret.toString())` does.
export async function identitySecretFromAppSecret(appSecret) {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-512", encoder.encode(BigInt(appSecret).toString())));
  const nullifier = bytesToBigInt(digest.slice(0, 32)) >> 3n;
  const trapdoor = bytesToBigInt(digest.slice(32)) >> 3n;
  digest.fill(0);
  return poseidon2([nullifier, trapdoor]);
}

// { identitySecret, leaf, limit } from a 32-byte random seed. The seed is not retained.
export async function deriveIdentity(seed, limit) {
  if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
    throw new Error("Identity seed must be exactly 32 random bytes.");
  }
  const lim = tierLimit(limit);
  const identitySecret = await identitySecretFromAppSecret(bytesToBigInt(seed) % FIELD);
  return {
    identitySecret: identitySecret.toString(),
    leaf: rateCommitment(identitySecret, lim).toString(),
    limit: Number(lim),
  };
}

// A file without `limit` is a pre-tier file at the original default tier (packages/node/lib/identity-file.mjs
// and the Rust client read a missing `limit` the same way).
export const FILE_DEFAULT_LIMIT = 8;

// Parse and check an identity file. `limits`, when given, is the set of tiers the caller accepts.
export function parseIdentityFile(text, { limits, defaultLimit = FILE_DEFAULT_LIMIT } = {}) {
  let value;
  try {
    value = typeof text === "string" ? JSON.parse(text) : text;
  } catch {
    throw new Error("That is not a valid identity JSON file.");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("The identity file must contain one JSON object.");
  }
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "identitySecret,leaf,limit" && keys !== "identitySecret,leaf") {
    throw new Error("The identity file must contain only identitySecret, leaf, and limit.");
  }
  const limit = tierLimit(value.limit ?? defaultLimit);
  if (limits && ![...limits].map((l) => BigInt(l)).includes(limit)) {
    throw new Error(`This network does not admit tier ${limit}.`);
  }
  const identitySecret = canonicalField(value.identitySecret, "identitySecret");
  const leaf = canonicalField(value.leaf, "leaf");
  if (leaf !== rateCommitment(identitySecret, limit)) {
    throw new Error("The public leaf does not match this identity secret and tier.");
  }
  return { identitySecret: identitySecret.toString(), leaf: leaf.toString(), limit: Number(limit) };
}

// The exact file bytes the Rust client and `shade-tree identity` read: 2-space JSON + newline.
export function serializeIdentity(identity) {
  return `${JSON.stringify({ identitySecret: identity.identitySecret, leaf: identity.leaf, limit: identity.limit }, null, 2)}\n`;
}

export function parseCommitment(text) {
  return canonicalField(String(text ?? "").trim(), "Commitment").toString();
}
