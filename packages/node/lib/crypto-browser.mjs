// Browser crypto backend for the wire code (packages/node/lib/directory.mjs), selected by the `#crypto`
// import's "browser" condition. Same exports as packages/node/lib/crypto-node.mjs, backed by @noble (the
// libraries ethers already ships), all synchronous so verifyDirectory keeps one code path.
//
// Verification uses RFC 8032 rules (zip215: false) to match OpenSSL in the Node backend, so a
// signature one side rejects the other side rejects too.

import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 as nobleSha3 } from "@noble/hashes/sha3";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

const encoder = new TextEncoder();
const HEX_RE = /^(?:[0-9a-fA-F]{2})*$/;

export const utf8 = (s) => encoder.encode(s);
export function fromHex(h) {
  if (typeof h !== "string" || !HEX_RE.test(h)) throw new Error("bad hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
export const sha3_256 = (bytes) => nobleSha3(bytes);
export const sha256 = (bytes) => nobleSha256(bytes);

function key32(hex, what) {
  const raw = fromHex(hex);
  if (raw.length !== 32) throw new Error(`ed25519 ${what} must be 32 bytes`);
  return raw;
}

export function ed25519PublicKey() {
  throw new Error("ed25519PublicKey returns a Node KeyObject; use ed25519Verify in the browser");
}
export function ed25519PrivateKey() {
  throw new Error("ed25519PrivateKey returns a Node KeyObject; use ed25519Sign in the browser");
}

export function ed25519Sign(msg, privHex) {
  return toHex(ed25519.sign(msg, key32(privHex, "seed")));
}

export function ed25519Verify(msg, sigHex, pubHex) {
  try {
    return ed25519.verify(fromHex(sigHex), msg, key32(pubHex, "pubkey"), { zip215: false });
  } catch {
    return false;
  }
}

export function ed25519PubFromSeed(seedHex) {
  return toHex(ed25519.getPublicKey(key32(seedHex, "seed")));
}
