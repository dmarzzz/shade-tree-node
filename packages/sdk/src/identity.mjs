// Member identities: create, import, back up. The math lives in packages/node/lib/identity-core.mjs (shared
// with the gateway); this module adds the network's tier rules and a browser download helper.
// In a browser nothing is persisted: the identity exists in memory until the caller saves the
// file the member downloads.

import {
  deriveIdentity, parseIdentityFile, serializeIdentity, parseCommitment, rateCommitment, identityCommitmentOf,
} from "../../node/lib/identity-core.mjs";
import { resolveNetwork } from "./network.mjs";
import { ShadeNetError } from "./errors.mjs";

export { serializeIdentity, parseCommitment, rateCommitment, identityCommitmentOf };

function limitsOf(network) {
  const net = typeof network === "object" && network?.record ? network : resolveNetwork(network);
  return { net, limits: net.staked?.tiers.map((t) => t.limit) ?? null, defaultLimit: net.staked?.defaultLimit };
}

// A fresh identity from 32 random bytes (WebCrypto in both Node and browsers).
export async function createIdentity({ network = "sepolia", limit } = {}) {
  const { limits, defaultLimit } = limitsOf(network);
  const lim = Number(limit ?? defaultLimit ?? 1);
  if (limits && !limits.includes(lim)) throw new ShadeNetError("InvalidInput", `tier ${lim} is not offered on this network`);
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  try {
    return await deriveIdentity(seed, lim);
  } finally {
    seed.fill(0);
  }
}

// Import and check an identity file (text or parsed object) against the network's tiers.
export function importIdentity(text, { network = "sepolia" } = {}) {
  const { limits } = limitsOf(network);
  try {
    return parseIdentityFile(text, { limits });
  } catch (cause) {
    throw new ShadeNetError("InvalidInput", cause.message, { cause });
  }
}

export const identityFileName = (identity) => `shadenet-identity-${identity.leaf.slice(0, 8)}.json`;

// Browser only: offer the identity file as a download. Returns the file name.
export function downloadIdentity(identity, { document: doc = globalThis.document } = {}) {
  if (!doc?.createElement) throw new ShadeNetError("InvalidInput", "downloadIdentity needs a browser document");
  const blob = new Blob([serializeIdentity(identity)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = doc.createElement("a");
  link.href = url;
  link.download = identityFileName(identity);
  link.click();
  URL.revokeObjectURL(url);
  return link.download;
}
