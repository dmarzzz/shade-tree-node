#!/usr/bin/env node
// scripts/backup.mjs — encrypted, dependency-free backup/restore of the secret key
// material a Shade Tree operator cannot afford to lose: the onion identity seeds
// (identity.local.json + Tor's hs_ed25519_secret_key) and the bootnode signer key
// (bootnode-signer.key). This replaces the manual `tar | gpg` recipe in docs/OPERATOR.md.
//
// It uses ONLY node:crypto (no gpg, no shelling out), so it runs anywhere node runs.
//
//   node scripts/backup.mjs backup  <srcDir> <outFile>          (env SHADE_TREE_BACKUP_SRC / _OUT)
//   node scripts/backup.mjs restore <inFile> <destDir> [--force] (env SHADE_TREE_BACKUP_IN / _DEST)
//
// The passphrase is REQUIRED via SHADE_TREE_BACKUP_PASSPHRASE (non-interactive, testable). It is the
// operator's responsibility: a lost passphrase means an unrecoverable backup, by design.
//
// Crypto: a per-backup 16-byte scrypt salt derives a 32-byte key (N=2^15, r=8, p=1); the plaintext
// bundle is sealed with AES-256-GCM (12-byte IV, 16-byte auth tag). The plaintext NEVER touches
// disk — it is built in memory and encrypted directly. A wrong passphrase or any tampering fails
// the GCM tag on restore (decipher.final() throws) and writes nothing.

import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import {
  readdirSync, statSync, readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync,
} from "node:fs";
import { resolve, join, relative, dirname, basename, sep } from "node:path";

// The sensitive files we collect, matched by basename anywhere under srcDir.
export const SENSITIVE_NAMES = new Set([
  "identity.local.json",   // onion seed (announce-signing) — losing it loses the onion address
  "hs_ed25519_secret_key", // Tor's expanded HS secret key
  "bootnode-signer.key",   // {pub,priv} that signs the directory clients pin
]);

const ENVELOPE_VERSION = 1;
const KDF = { N: 1 << 15, r: 8, p: 1, keylen: 32 };
// scrypt needs maxmem >= ~128*N*r (32 MiB here) plus overhead; the 32 MiB default is too tight.
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const IV_BYTES = 12;    // GCM's recommended nonce length
const SALT_BYTES = 16;

// --- collection (pure) -------------------------------------------------------

// Walk srcDir and return the sensitive files as { relpath, content:Buffer }. Skips VCS/dep dirs
// and does not follow into symlinked directories. relpath is POSIX-style, relative to srcDir.
export function collectSecrets(srcDir) {
  const root = resolve(srcDir);
  if (!existsSync(root)) throw new Error(`source dir not found: ${root}`);
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === ".git") continue;
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && SENSITIVE_NAMES.has(basename(p))) {
        out.push({ relpath: relative(root, p).split(sep).join("/"), content: readFileSync(p) });
      }
    }
  };
  walk(root);
  return out.sort((a, b) => a.relpath.localeCompare(b.relpath));
}

// --- encrypt / decrypt (pure, no disk) ---------------------------------------

// Seal the collected files into an encrypted envelope object. The plaintext bundle exists only
// as an in-memory Buffer that is fed straight into the cipher — it is never written to disk.
export function encrypt(files, passphrase) {
  if (!passphrase) throw new Error("passphrase required");
  if (!files.length) throw new Error("no sensitive files to back up");
  const bundle = {
    version: ENVELOPE_VERSION,
    created: new Date().toISOString(),
    files: files.map((f) => ({ relpath: f.relpath, base64content: f.content.toString("base64") })),
  };
  const plaintext = Buffer.from(JSON.stringify(bundle), "utf8");

  const salt = randomBytes(SALT_BYTES);
  const key = scryptSync(passphrase, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: SCRYPT_MAXMEM });
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    version: ENVELOPE_VERSION,
    cipher: "aes-256-gcm",
    kdf: "scrypt",
    kdfParams: { N: KDF.N, r: KDF.r, p: KDF.p, keylen: KDF.keylen },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

// Decrypt an envelope back to [{ relpath, content:Buffer }]. Throws loudly on a wrong passphrase
// or any tampering (the GCM auth tag fails inside decipher.final()).
export function decrypt(envelope, passphrase) {
  if (!passphrase) throw new Error("passphrase required");
  if (!envelope || envelope.cipher !== "aes-256-gcm" || envelope.kdf !== "scrypt") {
    throw new Error("not a recognized shade-tree-node backup envelope");
  }
  const kp = envelope.kdfParams || KDF;
  const salt = Buffer.from(envelope.salt, "base64");
  const key = scryptSync(passphrase, salt, kp.keylen, { N: kp.N, r: kp.r, p: kp.p, maxmem: SCRYPT_MAXMEM });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
  let plaintext;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(), // throws if the tag doesn't verify (wrong passphrase / tampering)
    ]);
  } catch {
    throw new Error("decryption failed — wrong passphrase or corrupted/tampered backup");
  }
  const bundle = JSON.parse(plaintext.toString("utf8"));
  return bundle.files.map((f) => ({ relpath: f.relpath, content: Buffer.from(f.base64content, "base64") }));
}

// --- disk drivers ------------------------------------------------------------

// Collect, encrypt, and write the envelope JSON to outFile. Returns { count, relpaths }.
export function runBackup({ srcDir, outFile, passphrase }) {
  const files = collectSecrets(srcDir);
  const envelope = encrypt(files, passphrase); // plaintext lives only in memory here
  mkdirSync(dirname(resolve(outFile)), { recursive: true });
  writeFileSync(resolve(outFile), JSON.stringify(envelope, null, 2) + "\n", { mode: 0o600 });
  return { count: files.length, relpaths: files.map((f) => f.relpath) };
}

// Decrypt inFile and write each file back under destDir with restrictive perms (0700 dirs,
// 0600 secrets). Refuses to overwrite existing files unless force. On a wrong passphrase the
// decrypt throws before any write, so nothing is written. Returns { count, relpaths }.
export function runRestore({ inFile, destDir, passphrase, force = false }) {
  const envelope = JSON.parse(readFileSync(resolve(inFile), "utf8"));
  const files = decrypt(envelope, passphrase); // throws (writes nothing) on wrong passphrase
  const dest = resolve(destDir);

  // Resolve + guard every target BEFORE writing anything (path-traversal + overwrite checks),
  // so a bad entry can't leave a half-written restore.
  const targets = files.map((f) => {
    const abs = resolve(dest, f.relpath);
    if (abs !== dest && !abs.startsWith(dest + sep)) throw new Error(`refusing path outside destDir: ${f.relpath}`);
    return { abs, content: f.content, relpath: f.relpath };
  });
  if (!force) {
    const clash = targets.find((t) => existsSync(t.abs));
    if (clash) throw new Error(`refusing to overwrite existing file: ${clash.relpath} (pass --force to overwrite)`);
  }

  for (const t of targets) {
    mkdirSync(dirname(t.abs), { recursive: true, mode: 0o700 });
    writeFileSync(t.abs, t.content, { mode: 0o600 });
    chmodSync(t.abs, 0o600); // enforce perms even if the file pre-existed under --force
  }
  return { count: targets.length, relpaths: targets.map((t) => t.relpath) };
}

// --- CLI ---------------------------------------------------------------------

function usage() {
  console.error(
    "usage:\n" +
    "  node scripts/backup.mjs backup  <srcDir> <outFile>\n" +
    "  node scripts/backup.mjs restore <inFile> <destDir> [--force]\n" +
    "\nSHADE_TREE_BACKUP_PASSPHRASE must be set (never passed on argv; never logged)."
  );
}

function cli(argv) {
  const mode = argv[0];
  const positionals = argv.slice(1).filter((a) => !a.startsWith("--"));
  const force = argv.includes("--force");
  const passphrase = process.env.SHADE_TREE_BACKUP_PASSPHRASE;

  if (mode !== "backup" && mode !== "restore") { usage(); process.exit(1); }
  if (!passphrase) {
    console.error("error: SHADE_TREE_BACKUP_PASSPHRASE is not set (required, non-interactive).");
    console.error("the passphrase is your responsibility — a lost passphrase = an unrecoverable backup.");
    process.exit(1);
  }

  try {
    if (mode === "backup") {
      const srcDir = positionals[0] || process.env.SHADE_TREE_BACKUP_SRC;
      const outFile = positionals[1] || process.env.SHADE_TREE_BACKUP_OUT;
      if (!srcDir || !outFile) { usage(); process.exit(1); }
      const r = runBackup({ srcDir, outFile, passphrase });
      console.log(`backed up ${r.count} secret file(s) -> ${resolve(outFile)} (encrypted, AES-256-GCM)`);
      for (const rp of r.relpaths) console.log(`  + ${rp}`);
      console.log("keep the passphrase safe: a lost passphrase = an unrecoverable backup.");
    } else {
      const inFile = positionals[0] || process.env.SHADE_TREE_BACKUP_IN;
      const destDir = positionals[1] || process.env.SHADE_TREE_BACKUP_DEST;
      if (!inFile || !destDir) { usage(); process.exit(1); }
      const r = runRestore({ inFile, destDir, passphrase, force });
      console.log(`restored ${r.count} secret file(s) -> ${resolve(destDir)} (0600, dirs 0700)`);
      for (const rp of r.relpaths) console.log(`  + ${rp}`);
    }
  } catch (e) {
    console.error(`error: ${e.message}`); // never prints the passphrase or plaintext
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  cli(process.argv.slice(2));
}
