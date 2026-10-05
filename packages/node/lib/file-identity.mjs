// A member identity as an identity file holds it (#251). The file is the one the Rust
// `shadenet init` writes and `shade-tree identity` exports:
//
//   { "identitySecret": "<dec>", "leaf": "<dec>", "limit": 1 }
//
// It holds the identity secret itself, not the app secret it was derived from, so the JS client
// proves with this value as is: packages/node/lib/rln.mjs identityFor / identitySecretOf accept a
// FileIdentity wherever they accept an app secret. Reading files (and the passphrase-protected
// form) is packages/node/lib/identity-file.mjs.
//
// Kept apart from identity-core.mjs so the browser bundles built from that module do not change.

import { tierLimit, canonicalField, rateCommitment } from "./identity-core.mjs";

// True for the passphrase-protected layout `shadenet init --passphrase` and
// `shadenet identity-lock` write: { version: 2, leaf, limit, encrypted: { ... } }. The leaf and
// the tier are public; the identity secret is sealed.
export function isEncryptedIdentityFile(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) && value.encrypted != null && typeof value.encrypted === "object";
}

// The secret stays in a private field: it is not enumerable, not in JSON.stringify, not in
// util.inspect and not in String().
export class FileIdentity {
  #identitySecret;
  constructor({ identitySecret, leaf, limit }) {
    const lim = tierLimit(limit);
    const secret = canonicalField(String(identitySecret), "identitySecret");
    const commitment = rateCommitment(secret, lim);
    if (leaf != null && canonicalField(String(leaf), "leaf") !== commitment) {
      throw new Error("The public leaf does not match this identity secret and tier.");
    }
    this.#identitySecret = secret;
    this.leaf = commitment.toString();
    this.limit = Number(lim);
    Object.freeze(this);
  }
  // The Semaphore-v3 identity secret (bigint): the RLN circuit's private input.
  get identitySecret() {
    return this.#identitySecret;
  }
  toJSON() {
    return { leaf: this.leaf, limit: this.limit };
  }
  toString() {
    return `[identity ${this.leaf.slice(0, 12)}.. tier ${this.limit}]`;
  }
  // util.inspect, with any options (showHidden, getters), shows the same line.
  [Symbol.for("nodejs.util.inspect.custom")]() {
    return this.toString();
  }
}
