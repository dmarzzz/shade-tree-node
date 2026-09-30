// Node crypto backend for the wire code (packages/node/lib/directory.mjs), selected by the `#crypto` import
// in package.json. The browser build resolves the same import to packages/node/lib/crypto-browser.mjs, so the
// canonical bytes and verification logic exist once and only the primitives differ.
//
// Byte values here are Buffers, so existing Node callers (`.toString("utf8")`, `.equals`) keep
// working unchanged.

import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify, createHash } from "node:crypto";

// Raw 32-byte keys wrapped in the fixed DER prefixes so KeyObjects can be built
// without a keygen round-trip. ed25519 signs/verifies with a null digest.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // + 32B pubkey
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex"); // + 32B seed

export const utf8 = (s) => Buffer.from(s, "utf8");
export const fromHex = (h) => Buffer.from(h, "hex");
export const toHex = (b) => Buffer.from(b).toString("hex");
export const concatBytes = (parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
export const bytesEqual = (a, b) => Buffer.from(a).equals(Buffer.from(b));
export const sha3_256 = (bytes) => createHash("sha3-256").update(bytes).digest();

export function ed25519PublicKey(rawHex) {
  const raw = Buffer.from(rawHex, "hex");
  if (raw.length !== 32) throw new Error("ed25519 pubkey must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

export function ed25519PrivateKey(rawHex) {
  const raw = Buffer.from(rawHex, "hex");
  if (raw.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: "der", type: "pkcs8" });
}

export function ed25519Sign(msgBuf, privHex) {
  return edSign(null, msgBuf, ed25519PrivateKey(privHex)).toString("hex");
}

export function ed25519Verify(msgBuf, sigHex, pubHex) {
  try {
    return edVerify(null, msgBuf, ed25519PublicKey(pubHex), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

export function ed25519PubFromSeed(seedHex) {
  const der = createPublicKey(ed25519PrivateKey(seedHex)).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32)).toString("hex");
}
