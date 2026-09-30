// Mint a gateway (or bootnode) onion identity that is BOTH:
//   1. a real Tor v3 hidden-service key Tor will publish, and
//   2. a seed node-crypto can sign announces with (packages/node/bootnode/announce.mjs).
//
// This is what lets onion control be proven with the built-in crypto and no new dependency.
// A v3 onion's public key is exactly the standard ed25519 public key of a 32-byte seed:
//     h = SHA-512(seed);  a = clamp(h[:32]);  A = a*B;  onion = base32(A ‖ checksum ‖ 0x03)
// Tor's hs_ed25519_secret_key stores the EXPANDED key (a_clamped ‖ h[32:]) behind a 32-byte
// tag, and derives the SAME A. So we generate the seed, hand Tor the expanded form, and keep
// the seed to sign with — one identity, published by Tor and signable by us.
//
// Usage:
//   node packages/node/bootnode/keygen.mjs <hsDir> [--label name] [--force]
//     writes into <hsDir>:  hs_ed25519_secret_key  hs_ed25519_public_key  hostname
//     writes alongside:     identity.local.json  { onion, pub, seed }   (gitignored; the
//                           announce-signing secret — never ship it)
//     Point Tor's HiddenServiceDir at <hsDir> and it publishes exactly this onion.

import { createHash, randomBytes, createPublicKey } from "node:crypto";
import { access, writeFile, mkdir, chmod } from "node:fs/promises";
import { resolve, join } from "node:path";
import { ed25519PrivateKey, pubkeyToOnion } from "../lib/directory.mjs";

const TAG_SECRET = "== ed25519v1-secret: type0 =="; // 29 bytes, NUL-padded to 32 in the file
const TAG_PUBLIC = "== ed25519v1-public: type0 ==";
const IDENTITY_FILES = ["hs_ed25519_secret_key", "hs_ed25519_public_key", "hostname", "identity.local.json"];

function tag32(s) {
  const b = Buffer.alloc(32);
  Buffer.from(s, "ascii").copy(b);
  return b;
}

// Derive the raw 32-byte ed25519 public key of a seed via node crypto (standard derivation),
// so onion == pubkeyToOnion(pub) matches the address Tor will compute from the expanded key.
function pubFromSeed(seedHex) {
  const pubDer = createPublicKey(ed25519PrivateKey(seedHex)).export({ format: "der", type: "spki" });
  return Buffer.from(pubDer.subarray(pubDer.length - 32));
}

// Tor's expanded secret key: clamp(SHA512(seed)[:32]) ‖ SHA512(seed)[32:].
function expandedSecret(seed) {
  const h = createHash("sha512").update(seed).digest();
  const a = Buffer.from(h.subarray(0, 32));
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  return Buffer.concat([a, h.subarray(32, 64)]);
}

export async function generateOnionIdentity(hsDir, { label = "", force = false } = {}) {
  const dir = resolve(hsDir);
  const existing = [];
  for (const file of IDENTITY_FILES) {
    try { await access(join(dir, file)); existing.push(file); } catch {}
  }
  if (existing.length && !force) {
    throw new Error(
      `refusing to overwrite onion identity in ${dir} (${existing.join(", ")}); ` +
      "reuse it, choose another directory, or pass --force only for an intentional rotation",
    );
  }

  const seed = randomBytes(32);
  const seedHex = seed.toString("hex");
  const pub = pubFromSeed(seedHex);
  const onion = pubkeyToOnion(pub.toString("hex"));

  const secretFile = Buffer.concat([tag32(TAG_SECRET), expandedSecret(seed)]); // 32 + 64
  const publicFile = Buffer.concat([tag32(TAG_PUBLIC), pub]); // 32 + 32

  await mkdir(dir, { recursive: true });
  await chmod(dir, 0o700).catch(() => {}); // Tor refuses a group/other-accessible HS dir
  await writeFile(join(dir, "hs_ed25519_secret_key"), secretFile, { mode: 0o600, flag: force ? "w" : "wx" });
  await writeFile(join(dir, "hs_ed25519_public_key"), publicFile, { mode: 0o600 });
  await writeFile(join(dir, "hostname"), onion + "\n");
  await writeFile(
    join(dir, "identity.local.json"),
    JSON.stringify({ label, onion, pub: pub.toString("hex"), seed: seedHex }, null, 2) + "\n",
    { mode: 0o600 }
  );

  return { onion, pub: pub.toString("hex"), seed: seedHex, dir };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const hsDir = args.find((a) => !a.startsWith("--"));
  const li = args.indexOf("--label");
  const label = li !== -1 ? args[li + 1] : "";
  const force = args.includes("--force");
  if (!hsDir) {
    console.error("usage: node packages/node/bootnode/keygen.mjs <hsDir> [--label name] [--force]");
    process.exit(1);
  }
  try {
    const id = await generateOnionIdentity(hsDir, { label, force });
    console.log(`minted onion identity${label ? ` (${label})` : ""}:`);
    console.log(`  onion:    ${id.onion}`);
    console.log(`  hsDir:    ${id.dir}   (point Tor's HiddenServiceDir here)`);
    console.log(`  secret:   ${join(id.dir, "identity.local.json")}   (announce-signing seed; keep secret)`);
  } catch (error) {
    console.error(`keygen: ${error.message}`);
    process.exit(1);
  }
}
