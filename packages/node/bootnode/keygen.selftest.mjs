// Offline proof of the Tor v3 hidden-service key format. This is the load-bearing crypto
// claim of keygen.mjs: the 32-byte seed we KEEP (to sign announces with node crypto) and the
// EXPANDED key we hand Tor (which Tor publishes) derive the SAME v3 onion. If that binding
// ever slipped, Tor would publish an address we cannot sign for, or we would sign for an
// address Tor never publishes. So we mint an identity, then re-derive every published byte
// independently from the seed and byte-compare it against what generateOnionIdentity wrote.
//
//   node packages/node/bootnode/keygen.selftest.mjs
//
// Exit 0 = the seed and Tor's key agree on the onion, and the on-disk format is exact;
// nonzero = a check failed (prints which).

import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, createPublicKey } from "node:crypto";
import { generateOnionIdentity } from "./keygen.mjs";
import { onionToPubkey, pubkeyToOnion, ed25519PrivateKey } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const TAG_SECRET = "== ed25519v1-secret: type0 ==";
const TAG_PUBLIC = "== ed25519v1-public: type0 ==";

// Independent re-derivation of the raw 32-byte ed25519 public key from the seed, via node
// crypto's standard SPKI export. This must match both the returned pub and Tor's published key.
function rawPubFromSeed(seedHex) {
  const der = createPublicKey(ed25519PrivateKey(seedHex)).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-keygen-"));
  try {
    // --- mint one identity and re-derive everything from its seed --------------
    console.log("keygen v3 format:");
    const id = await generateOnionIdentity(join(work, "hs"), { label: "kg" });

    // 1. shape of the returned identity
    ok(typeof id.onion === "string" && id.onion.endsWith(".onion") && id.onion.length === 62,
      "onion is a 62-char .onion (56 base32 + \".onion\")");
    ok(/^[0-9a-f]{64}$/.test(id.pub), "pub is 64 hex chars (32-byte ed25519 key)");
    ok(/^[0-9a-f]{64}$/.test(id.seed), "seed is 64 hex chars (32-byte seed)");

    // 2. the address encodes exactly this key + a valid checksum (round-trip both ways)
    ok(onionToPubkey(id.onion) === id.pub, "onionToPubkey(onion) === pub (key + checksum decode)");
    ok(pubkeyToOnion(id.pub) === id.onion, "pubkeyToOnion(pub) === onion (re-encodes identically)");

    // 3. the seed independently derives the SAME raw public key the address carries
    const seedBuf = Buffer.from(id.seed, "hex");
    const expectedRawPub = rawPubFromSeed(id.seed);
    ok(expectedRawPub.toString("hex") === id.pub, "seed -> ed25519 pubkey (node crypto) === pub");

    // --- hs_ed25519_public_key: 32-byte tag ++ 32-byte raw pubkey (64 bytes) ----
    console.log("\nhs_ed25519_public_key:");
    const pubFile = await readFile(join(work, "hs", "hs_ed25519_public_key"));
    ok(pubFile.length === 64, "public key file is 64 bytes (32 tag + 32 key)");
    const pubTag = pubFile.subarray(0, 32);
    const pubKeyBytes = pubFile.subarray(32, 64);
    ok(pubTag.subarray(0, TAG_PUBLIC.length).toString("ascii") === TAG_PUBLIC,
      `public tag begins ASCII "${TAG_PUBLIC}"`);
    ok(pubTag.subarray(TAG_PUBLIC.length).every((b) => b === 0), "public tag is NUL-padded to 32 bytes");
    ok(pubKeyBytes.equals(expectedRawPub),
      "published key bytes EQUAL the seed-derived raw pubkey (Buffer compare)");

    // --- hs_ed25519_secret_key: 32-byte tag ++ 64-byte expanded key (96 bytes) ---
    console.log("\nhs_ed25519_secret_key:");
    const secFile = await readFile(join(work, "hs", "hs_ed25519_secret_key"));
    ok(secFile.length === 96, "secret key file is 96 bytes (32 tag + 64 expanded)");
    const secTag = secFile.subarray(0, 32);
    const expanded = secFile.subarray(32, 96);
    ok(secTag.subarray(0, TAG_SECRET.length).toString("ascii") === TAG_SECRET,
      `secret tag begins ASCII "${TAG_SECRET}"`);
    ok(secTag.subarray(TAG_SECRET.length).every((b) => b === 0), "secret tag is NUL-padded to 32 bytes");

    // The expanded key MUST be clamp(SHA512(seed)[:32]) ++ SHA512(seed)[32:].
    const h = createHash("sha512").update(seedBuf).digest();
    const a = Buffer.from(h.subarray(0, 32));
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    const expectedExpanded = Buffer.concat([a, h.subarray(32, 64)]);
    ok(expanded.equals(expectedExpanded),
      "expanded key === clamp(SHA512(seed)[:32]) ++ SHA512(seed)[32:] (Buffer compare)");

    // Clamp bits asserted directly on the file's scalar (defends the exact bit pattern
    // Tor/ed25519 require, independent of how we recomputed the expected buffer above).
    const scalar = expanded.subarray(0, 32);
    ok((scalar[0] & 0b00000111) === 0, "scalar byte 0 low 3 bits cleared (& 248)");
    ok((scalar[31] & 0b10000000) === 0, "scalar byte 31 high bit cleared (& 127)");
    ok((scalar[31] & 0b01000000) !== 0, "scalar byte 31 bit 6 set (| 64)");

    // --- hostname file matches the onion ---------------------------------------
    console.log("\nhostname:");
    const hostname = (await readFile(join(work, "hs", "hostname"), "utf8")).trim();
    ok(hostname === id.onion, "hostname file (trimmed) === onion");

    // --- fresh randomness: two mints must differ -------------------------------
    console.log("\nfreshness:");
    const id2 = await generateOnionIdentity(join(work, "hs2"), { label: "kg2" });
    ok(id2.onion !== id.onion, "two generateOnionIdentity calls produce different onions");
    ok(id2.seed !== id.seed, "two generateOnionIdentity calls produce different seeds");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: keygen selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
