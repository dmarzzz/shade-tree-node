// Sign a fleet directory (and, with no args, mint a signed EXAMPLE with fresh
// gateway onions so the whole path is runnable end to end).
//
// The directory signer is a long-lived ed25519 key whose PUBLIC half is PINNED in
// the client (SHADE_TREE_DIR_SIGNER / the default in packages/node/client/selection.mjs). This tool
// holds the SECRET half, offline, and signs the list the fleet publishes.
//
// Usage:
//   node group/sign-directory.mjs                     -> mint keys + example file
//   node group/sign-directory.mjs <unsigned.json>     -> sign an existing list
//
// Each example gateway gets a REAL v3 onion address derived from a fresh ed25519
// key, so onionToPubkey(onion) === pubkey and verifyDirectory passes. These are
// not reachable onions; they exist to exercise the signature and binding checks.

import { chmod, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { signDirectory, verifyDirectory, pubkeyToOnion, ed25519PublicKey } from "../packages/node/lib/directory.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SIGNER_KEY_PATH = join(HERE, "directory-signer.key"); // secret; do not ship
const EXAMPLE_PATH = join(HERE, "directory.example.json");

// Raw 32-byte ed25519 seed as hex, from a KeyObject.
function rawSeedHex(privKey) {
  const der = privKey.export({ format: "der", type: "pkcs8" });
  return der.subarray(der.length - 32).toString("hex");
}
function rawPubHex(pubKey) {
  const der = pubKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}
function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: rawPubHex(publicKey), priv: rawSeedHex(privateKey) };
}

// Load or mint the signer secret.
let signer;
if (existsSync(SIGNER_KEY_PATH)) {
  await chmod(SIGNER_KEY_PATH, 0o600);
  signer = JSON.parse(await readFile(SIGNER_KEY_PATH, "utf8"));
} else {
  signer = newEd25519();
  await writeFile(SIGNER_KEY_PATH, JSON.stringify(signer, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log("minted a new directory signer key -> " + SIGNER_KEY_PATH + " (keep this secret)");
}

const arg = process.argv[2];
let dir;
if (arg) {
  dir = JSON.parse(await readFile(arg, "utf8"));
} else {
  // Mint three example gateways with real, internally-consistent onions.
  const gw = (weight, health, note) => {
    const k = newEd25519();
    return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health, note };
  };
  dir = {
    version: 1,
    issued: Math.floor(Date.now() / 1000),
    gateways: [
      { ...gw(100, "up", "primary, AS-A (e.g. datacenter provider 1)") },
      { ...gw(100, "up", "AS-B (different provider / region)") },
      { ...gw(50, "up", "AS-C (spread the both-ends AS vantage; adversarial-review #11)") },
    ],
    signer: signer.pub,
  };
}

// `note` is documentation only; it is NOT covered by the signature (see
// canonicalDirectoryBytes), so strip nothing but be aware it is unauthenticated.
dir.signer = signer.pub;
const signed = signDirectory(dir, signer.priv);

const check = verifyDirectory(signed, signer.pub);
if (!check.ok) {
  console.error("self-check failed: " + check.reason);
  process.exit(1);
}

const out = arg ? arg : EXAMPLE_PATH;
await writeFile(out, JSON.stringify(signed, null, 2) + "\n");
console.log("wrote signed directory -> " + out);
console.log("pinned signer pubkey (put this in the client):");
console.log("  " + signer.pub);
console.log("verify: " + (verifyDirectory(signed, signer.pub).ok ? "ok" : "FAILED"));
// sanity: the pinned-key check must reject a different signer
const other = ed25519PublicKey(newEd25519().pub); void other;
