// The browser crypto backend (packages/node/lib/crypto-browser.mjs, @noble) must agree byte for
// byte with the Node backend (crypto-node.mjs, OpenSSL) on every primitive the wire code uses:
// sha256, sha3-256 and ed25519 sign/verify in both directions, with RFC 8032 (non-zip215)
// verification on both sides. Pinned digests make a library bump that changes an output fail here
// before it reaches a signed directory (Dependabot #260 @noble/hashes 2, #259 @noble/curves 2).
import assert from "node:assert/strict";
import * as browser from "../packages/node/lib/crypto-browser.mjs";
import * as nodeBackend from "../packages/node/lib/crypto-node.mjs";

let checks = 0;
const check = (cond, msg) => { assert.ok(cond, msg); checks++; };
const hex = (b) => Buffer.from(b).toString("hex");

// Fixed inputs, including the empty string and a 1 KiB block.
const inputs = ["", "abc", "shadenet canopy v4", "x".repeat(1024)].map((s) => new TextEncoder().encode(s));
// Known answers (FIPS 180-4 / FIPS 202) for the first two inputs.
const KNOWN = {
  sha256: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  sha3_256: ["a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"],
};
for (const [name, known] of Object.entries(KNOWN)) {
  inputs.forEach((input, i) => {
    const b = hex(browser[name](input));
    const n = hex(nodeBackend[name](input));
    check(b === n, `${name}: browser and node agree on input ${i}`);
    if (known[i]) check(b === known[i], `${name}: known answer for input ${i}`);
  });
}

// ed25519: a fixed seed, both backends sign the same bytes, each verifies the other's signature,
// and a flipped bit is refused by both.
const seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; // RFC 8032 test 1
const pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const rfcSig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
check(nodeBackend.ed25519PubFromSeed(seed) === pub, "node derives the RFC 8032 public key");
const empty = new Uint8Array(0);
check(browser.ed25519Sign(empty, seed) === rfcSig, "browser signs the RFC 8032 test vector");
check(nodeBackend.ed25519Sign(empty, seed) === rfcSig, "node signs the RFC 8032 test vector");
for (const msg of inputs) {
  const sb = browser.ed25519Sign(msg, seed);
  const sn = nodeBackend.ed25519Sign(msg, seed);
  check(sb === sn, "deterministic ed25519: both backends produce the same signature");
  check(nodeBackend.ed25519Verify(msg, sb, pub), "node verifies the browser's signature");
  check(browser.ed25519Verify(msg, sn, pub), "browser verifies node's signature");
  const bad = (sb.slice(0, 2) === "00" ? "01" : "00") + sb.slice(2);
  check(!browser.ed25519Verify(msg, bad, pub) && !nodeBackend.ed25519Verify(msg, bad, pub), "both refuse a corrupted signature");
}
// A non-canonical S (S + L) is accepted under zip215 but refused under RFC 8032 rules: both refuse.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const sBytes = Buffer.from(rfcSig.slice(64), "hex");
let s = 0n; for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sBytes[i]);
const sPlusL = s + L;
const out = Buffer.alloc(32); let t = sPlusL; for (let i = 0; i < 32; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
if (t === 0n) {
  const malleable = rfcSig.slice(0, 64) + out.toString("hex");
  check(!browser.ed25519Verify(empty, malleable, pub) && !nodeBackend.ed25519Verify(empty, malleable, pub), "both refuse a non-canonical S (RFC 8032, not zip215)");
}
console.log(`PASS: crypto backends agree (${checks} checks)`);
