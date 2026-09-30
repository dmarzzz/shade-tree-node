#!/usr/bin/env node
// scripts/onion-identity.mjs — onion-identity continuity for a rebuilt gateway/bootnode box.
//
// When a box is destroyed and rebuilt, the SAME .onion MUST come back or the signed directory
// (packages/node/lib/directory.mjs) and every client that pinned that onion break. This tool lets an operator:
//
//   1. DERIVE + PRINT the .onion address a Tor v3 secret key resolves to, so they can verify a
//      restored key is the EXPECTED onion BEFORE cutting Tor over to it (a bad key = a new,
//      unannounced onion = a silently broken gateway).
//   2. RESTORE a bare `hs_ed25519_secret_key` into a fresh HiddenServiceDir with the correct file
//      layout + perms — reconstructing `hs_ed25519_public_key` and `hostname` FROM the secret key,
//      so a single backed-up secret (all scripts/backup.mjs stores) is sufficient to rebuild.
//
// It uses ONLY node:crypto + the repo's existing onion encoder (packages/node/lib/directory.mjs#pubkeyToOnion).
//
//   node scripts/onion-identity.mjs derive  <secret_key_file>
//   node scripts/onion-identity.mjs restore <secret_key_file> <hsDir> [--force]
//
// A v3 onion address IS its ed25519 public key: onion = base32(A ‖ checksum ‖ 0x03). Tor's
// hs_ed25519_secret_key stores the EXPANDED key clamp(SHA512(seed)[:32]) ‖ SHA512(seed)[32:]
// behind a 32-byte ASCII tag. SHA512 is one-way, so we cannot recover the seed — but we do not
// need it: the public key A = a·B is fixed by the clamped scalar `a` (the first 32 bytes of the
// expanded key). node:crypto's ed25519 only derives A from a 32-byte SEED, never from a bare
// scalar, so we compute A = a·B directly with a small, self-checked ed25519 base-point multiply
// (BigInt field math below; cross-checked against node:crypto in the selftest). The secret's raw
// bytes are NEVER printed or logged.

import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { resolve, join } from "node:path";
import { pubkeyToOnion } from "../packages/node/lib/directory.mjs";

// Tor HS v3 file constants (must match packages/node/bootnode/keygen.mjs, which mints these files).
const TAG_SECRET = "== ed25519v1-secret: type0 =="; // 29 bytes, NUL-padded to 32 in the file
const TAG_PUBLIC = "== ed25519v1-public: type0 ==";
const TAG_LEN = 32;
const EXPANDED_LEN = 64;                 // clamped scalar (32) ‖ prefix (32)
const SECRET_FILE_LEN = TAG_LEN + EXPANDED_LEN; // 96

function tag32(s) {
  const b = Buffer.alloc(TAG_LEN);
  Buffer.from(s, "ascii").copy(b);
  return b;
}

// --- ed25519 base-point scalar multiplication (pure BigInt; node:crypto-checked) --------------
// Twisted Edwards curve -x^2 + y^2 = 1 + d·x^2·y^2 over F_p, p = 2^255 - 19. We need only A = a·B
// for a fixed scalar and the standard base point, then point compression to 32 bytes. This is the
// one step node:crypto cannot do from a raw scalar; the rest of the onion math is reused from lib.

const P = (1n << 255n) - 19n;
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const By = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

const mod = (x) => ((x % P) + P) % P;
const modInv = (x) => modPow(mod(x), P - 2n); // Fermat inverse (p is prime)

function modPow(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

// Extended homogeneous coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z. Addition formulas for
// a = -1 (Hisil–Wong–Carter–Dawson, RFC 8032 §5.1.4).
function pointAdd(p1, p2) {
  const [X1, Y1, Z1, T1] = p1;
  const [X2, Y2, Z2, T2] = p2;
  const A = mod((Y1 - X1) * (Y2 - X2));
  const B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(T1 * 2n * D * T2);
  const Dd = mod(Z1 * 2n * Z2);
  const E = mod(B - A);
  const F = mod(Dd - C);
  const G = mod(Dd + C);
  const H = mod(B + A);
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

const IDENTITY = [0n, 1n, 1n, 0n]; // neutral element (0, 1)

// Compress an affine-recoverable extended point to Tor/RFC-8032 wire form: 32-byte little-endian
// y with the low bit of x folded into the top bit.
function compress(point) {
  const [X, Y, Z] = point;
  const zInv = modInv(Z);
  const x = mod(X * zInv);
  const y = mod(Y * zInv);
  const out = Buffer.alloc(32);
  let yy = y;
  for (let i = 0; i < 32; i++) { out[i] = Number(yy & 0xffn); yy >>= 8n; }
  out[31] |= Number(x & 1n) << 7; // sign bit
  return out;
}

// A = a·B for a 32-byte little-endian scalar `a` (already clamped). Double-and-add; timing is not
// sensitive here (we derive a PUBLIC key from a key the operator already holds locally).
function scalarMultBase(scalarLE) {
  let scalar = 0n;
  for (let i = 31; i >= 0; i--) scalar = (scalar << 8n) | BigInt(scalarLE[i]);
  let result = IDENTITY;
  let addend = [Bx, By, 1n, mod(Bx * By)];
  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    scalar >>= 1n;
  }
  return compress(result);
}

// --- pure helpers (exported for testing) ------------------------------------------------------

// Parse + validate a Tor hs_ed25519_secret_key buffer, returning the 32-byte clamped scalar.
// Throws on a wrong tag or length rather than silently deriving a bogus onion.
export function scalarFromSecretKeyFile(buf) {
  if (!Buffer.isBuffer(buf)) throw new Error("secret key must be a Buffer");
  if (buf.length !== SECRET_FILE_LEN) {
    throw new Error(`hs_ed25519_secret_key must be ${SECRET_FILE_LEN} bytes (got ${buf.length})`);
  }
  const tag = buf.subarray(0, TAG_LEN);
  if (Buffer.compare(tag, tag32(TAG_SECRET)) !== 0) {
    throw new Error("not a Tor v3 hs_ed25519_secret_key (bad type tag)");
  }
  return Buffer.from(buf.subarray(TAG_LEN, TAG_LEN + 32)); // clamped scalar a
}

// Derive { pub (hex), onion } from a hs_ed25519_secret_key buffer. Reconstructs the public key
// via A = a·B and the onion via the repo's existing v3 encoder — a bare secret is sufficient.
export function identityFromSecretKeyFile(buf) {
  const scalar = scalarFromSecretKeyFile(buf);
  const pub = scalarMultBase(scalar); // 32-byte compressed ed25519 public key
  const pubHex = pub.toString("hex");
  return { pub: pubHex, onion: pubkeyToOnion(pubHex) };
}

// Build the exact bytes Tor expects for hs_ed25519_public_key from a 32-byte pubkey.
export function publicKeyFileBytes(pubHex) {
  const pub = Buffer.from(pubHex, "hex");
  if (pub.length !== 32) throw new Error("pubkey must be 32 bytes");
  return Buffer.concat([tag32(TAG_PUBLIC), pub]); // 32 + 32
}

// --- disk drivers -----------------------------------------------------------------------------

// Read a secret key file from disk and return its derived identity. Never logs the bytes.
export function deriveFromFile(secretKeyFile) {
  const buf = readFileSync(resolve(secretKeyFile));
  return identityFromSecretKeyFile(buf);
}

// Restore an onion identity into a fresh HiddenServiceDir. Writes, with Tor's required layout:
//   hs_ed25519_secret_key  (the input, verbatim)  0600
//   hs_ed25519_public_key  (reconstructed)         0600
//   hostname               (reconstructed onion)   0644
// and the dir itself 0700 (Tor refuses a group/other-accessible HS dir). Refuses to overwrite an
// existing populated HS dir unless force. Returns { onion, pub, dir }.
export function restoreToHsDir(secretKeyFile, hsDir, { force = false } = {}) {
  const secretBuf = readFileSync(resolve(secretKeyFile));
  const { pub, onion } = identityFromSecretKeyFile(secretBuf); // validates before touching disk
  const dir = resolve(hsDir);

  const secretPath = join(dir, "hs_ed25519_secret_key");
  const publicPath = join(dir, "hs_ed25519_public_key");
  const hostnamePath = join(dir, "hostname");
  if (!force) {
    const clash = [secretPath, publicPath, hostnamePath].find((p) => existsSync(p));
    if (clash) throw new Error(`refusing to overwrite existing ${clash} (pass --force to overwrite)`);
  }

  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700); // enforce even if the dir pre-existed with looser perms

  writeFileSync(secretPath, secretBuf, { mode: 0o600 });
  chmodSync(secretPath, 0o600);
  writeFileSync(publicPath, publicKeyFileBytes(pub), { mode: 0o600 });
  chmodSync(publicPath, 0o600);
  writeFileSync(hostnamePath, onion + "\n", { mode: 0o644 });
  chmodSync(hostnamePath, 0o644);

  return { onion, pub, dir };
}

// --- CLI --------------------------------------------------------------------------------------

function usage() {
  console.error(
    "usage:\n" +
    "  node scripts/onion-identity.mjs derive  <secret_key_file>\n" +
    "  node scripts/onion-identity.mjs restore <secret_key_file> <hsDir> [--force]\n" +
    "\nderive  prints the .onion a hs_ed25519_secret_key resolves to (verify BEFORE cutover).\n" +
    "restore rebuilds a HiddenServiceDir (secret 0600, public 0600, hostname 0644, dir 0700).\n" +
    "The secret key's bytes are never printed or logged."
  );
}

function cli(argv) {
  const mode = argv[0];
  const positionals = argv.slice(1).filter((a) => !a.startsWith("--"));
  const force = argv.includes("--force");

  if (mode !== "derive" && mode !== "restore") { usage(); process.exit(1); }

  try {
    if (mode === "derive") {
      const secretKeyFile = positionals[0];
      if (!secretKeyFile) { usage(); process.exit(1); }
      const { onion } = deriveFromFile(secretKeyFile);
      console.log(onion);
    } else {
      const secretKeyFile = positionals[0];
      const hsDir = positionals[1];
      if (!secretKeyFile || !hsDir) { usage(); process.exit(1); }
      const r = restoreToHsDir(secretKeyFile, hsDir, { force });
      console.log(`restored onion identity -> ${r.dir}`);
      console.log(`  onion:  ${r.onion}`);
      console.log("  wrote:  hs_ed25519_secret_key (0600), hs_ed25519_public_key (0600), hostname (0644)");
      console.log("  point Tor's HiddenServiceDir here; verify this onion matches the expected before cutover.");
    }
  } catch (e) {
    console.error(`error: ${e.message}`); // never prints the secret bytes
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  cli(process.argv.slice(2));
}
