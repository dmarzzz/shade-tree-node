// identity-file: the ONE place the Rust client's `--identity` file is derived and serialized.
//
// The Rust `shade-tree egress` (crates/shadenet-cli, `--features live`) does not derive an identity from
// the app secret; it takes the two field elements it needs as inputs:
//
//   { "identitySecret": "<dec>",   // Semaphore-v3 identitySecret = Poseidon2(nullifier, trapdoor)
//     "leaf":           "<dec>" }  // RLN rateCommitment = Poseidon2(Poseidon1(identitySecret), K)
//
// Both come from the JS reference (packages/node/lib/rln.mjs): identityFor(secret) is the SAME derivation the
// JS client's proveForSlot uses, and rateCommitmentOf() is the SAME leaf `shade-tree enroll` publishes
// and the on-chain slash names. So a member's Rust and JS clients are the same member, and the
// leaf here is exactly the entry in group/members.json.
//
// Consumers: `shade-tree identity` (group/identity.mjs, the operator/member-facing command) and the
// Rust interop harness (crates/shadenet-rln/interop/egress-derive.mjs). They MUST agree byte-for-byte,
// which is why the serialization lives here too and group/identity.selftest.mjs pins both.
//
// NOTE: the leaf depends on the member's tier limit (T-FEAT-8; default K = SHADE_TREE_SLOTS = 8) exactly
// like every other rateCommitment in the system — derive with the limit the leaf was enrolled with,
// or the leaf will not be in the tree. A NON-default limit is written as a third field,
//   { "identitySecret": ..., "leaf": ..., "limit": 32 }
// which the Rust client reads as its default `--k`. At the default limit the field is OMITTED, so
// every pre-tier identity file is byte-identical (Rust treats a missing `limit` as K_SLOTS).

import { readFileSync, statSync } from "node:fs";
import { scryptSync, createDecipheriv } from "node:crypto";
import { identityFor, identitySecretOf, rateCommitmentOf, K_SLOTS, normLimit } from "./rln.mjs";
import { parseIdentityFile, FILE_DEFAULT_LIMIT } from "./identity-core.mjs";
import { FileIdentity, isEncryptedIdentityFile } from "./file-identity.mjs";

export { FileIdentity, isEncryptedIdentityFile };

// identityFileFor(secret, limit = K_SLOTS) -> { identitySecret, leaf[, limit] } (decimal strings,
// as the Rust side parses; `limit` a Number, present only when != K_SLOTS).
// `secret` is the app secret (0x-hex or decimal; toField() normalizes it) — the SHADE_TREE_SECRET value.
export function identityFileFor(secret, limit = K_SLOTS) {
  if (typeof secret !== "string" || secret.trim() === "") throw new Error("identityFileFor: empty secret");
  const lim = Number(normLimit(limit));
  const identity = identityFor(secret.trim());
  const file = {
    identitySecret: identitySecretOf(identity).toString(),
    leaf: rateCommitmentOf(identity, lim).toString(),
  };
  if (lim !== K_SLOTS) file.limit = lim;
  return file;
}

// The exact on-disk bytes: 2-space JSON + trailing newline (what the harness has always written,
// what the Rust client parses). Key order is fixed by construction above; `limit` last, and only
// when the file carries a non-default tier.
export function serializeIdentityFile(file) {
  const out = { identitySecret: file.identitySecret, leaf: file.leaf };
  if (file.limit != null && Number(file.limit) !== K_SLOTS) out.limit = Number(file.limit);
  return JSON.stringify(out, null, 2) + "\n";
}

// ---- reading an identity file (#251) ------------------------------------------------------------
//
// ONE file for both clients. The JS client reads what the Rust `shadenet init` writes, in both of
// its forms (crates/shadenet/src/identity.rs), and what `shade-tree identity` writes:
//
//   plaintext   { "identitySecret": "<dec>", "leaf": "<dec>", "limit": 1 }      (`limit` may be absent)
//   sealed      { "version": 2, "leaf": "<dec>", "limit": 1,
//                 "encrypted": { "kdf": "scrypt", "logN": 17, "r": 8, "p": 1, "salt": "<hex>",
//                                "cipher": "xchacha20poly1305", "nonce": "<hex>", "ciphertext": "<hex>" } }
//
// The sealed secret is the decimal identitySecret under XChaCha20-Poly1305, keyed by scrypt of the
// passphrase, with the public fields and the KDF parameters bound as associated data. testdata/identity/
// holds one file of each form written by the Rust CLI; group/identity.selftest.mjs and the Rust
// identity tests read the same two files.

const MAX_IDENTITY_FILE = 16 * 1024; // the Rust reader's cap
const MAX_LOG_N = 20; // 1 GiB of scrypt memory; a file asking for more is refused, as in Rust
const SEALED_VERSION = 2;

const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;

// HChaCha20 (draft-irtf-cfrg-xchacha section 2.2): the 32-byte subkey XChaCha20 derives from the key
// and the first 16 nonce bytes. Node has ChaCha20-Poly1305 (12-byte nonce) built in, not XChaCha20.
export function hchacha20(key, nonce16) {
  if (key.length !== 32 || nonce16.length !== 16) throw new Error("hchacha20: need a 32-byte key and a 16-byte nonce");
  const x = new Uint32Array(16);
  x.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) x[4 + i] = key.readUInt32LE(4 * i);
  for (let i = 0; i < 4; i++) x[12 + i] = nonce16.readUInt32LE(4 * i);
  const quarter = (a, b, c, d) => {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
  };
  for (let round = 0; round < 10; round++) {
    quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15);
    quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeUInt32LE(x[i], 4 * i);
    out.writeUInt32LE(x[12 + i], 16 + 4 * i);
  }
  x.fill(0);
  return out;
}

const HEX_RE = /^(?:[0-9a-f]{2})+$/i;
const fromHex = (value) => (typeof value === "string" && HEX_RE.test(value) ? Buffer.from(value, "hex") : null);

// Open the sealed form. Returns the decimal identitySecret; throws without saying which part failed
// beyond "wrong passphrase or altered file", like the Rust reader.
function openSealed(value, passphrase) {
  const sealed = value.encrypted;
  if (value.version !== SEALED_VERSION || sealed.kdf !== "scrypt" || sealed.cipher !== "xchacha20poly1305") {
    throw new Error("the identity file uses an unsupported encryption format");
  }
  const { logN, r, p } = sealed;
  if (![logN, r, p].every(Number.isSafeInteger) || logN < 1 || logN > MAX_LOG_N || r < 1 || r > 32 || p < 1 || p > 16) {
    throw new Error("the identity file asks for unsupported scrypt parameters");
  }
  const salt = fromHex(sealed.salt), nonce = fromHex(sealed.nonce), ciphertext = fromHex(sealed.ciphertext);
  if (!salt || !nonce || !ciphertext || salt.length < 16 || nonce.length !== 24 || ciphertext.length <= 16) {
    throw new Error("the identity file is corrupt");
  }
  if (typeof value.leaf !== "string" || !/^[0-9]+$/.test(value.leaf) || (value.limit != null && !Number.isSafeInteger(value.limit))) {
    throw new Error("the identity file has a malformed leaf or tier");
  }
  // Byte-for-byte the Rust `aad`: the public fields and KDF parameters cannot be changed without
  // the tag failing, so a file edited to a higher tier does not open.
  const aad = Buffer.from(`shadenet-identity-v2\n${value.leaf}\n${value.limit ?? ""}\n${sealed.kdf}\n${logN}\n${r}\n${p}\n${sealed.cipher}`);
  const N = 2 ** logN;
  const key = scryptSync(Buffer.from(String(passphrase), "utf8"), salt, 32, { N, r, p, maxmem: 256 * N * r });
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  key.fill(0);
  try {
    const opener = createDecipheriv("chacha20-poly1305", subkey, Buffer.concat([Buffer.alloc(4), nonce.subarray(16)]), { authTagLength: 16 });
    const body = ciphertext.subarray(0, ciphertext.length - 16);
    opener.setAAD(aad, { plaintextLength: body.length });
    opener.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
    const plain = Buffer.concat([opener.update(body), opener.final()]);
    const secret = plain.toString("utf8");
    plain.fill(0);
    return secret;
  } catch {
    throw new Error("wrong passphrase for the identity file (or the file was altered)");
  } finally {
    subkey.fill(0);
  }
}

// openIdentity(source, { passphrase }) -> FileIdentity. `source` is the file's text, its parsed
// object, or a FileIdentity (returned as is). The leaf is checked against the secret and the tier,
// so a file whose `limit` was edited, or that pairs someone else's leaf with this secret, is refused.
export function openIdentity(source, { passphrase } = {}) {
  if (source instanceof FileIdentity) return source;
  let value = source;
  if (typeof source === "string") {
    try { value = JSON.parse(source); } catch { throw new Error("That is not a valid identity JSON file."); }
  }
  if (!isEncryptedIdentityFile(value)) return new FileIdentity(parseIdentityFile(value));
  if (value.identitySecret != null) throw new Error("the identity file holds both a plaintext and an encrypted secret");
  if (passphrase == null || passphrase === "") {
    throw new Error("the identity file is passphrase-protected; set SHADE_TREE_PASSPHRASE_FILE, or remove the passphrase with `shadenet identity-unlock`");
  }
  return new FileIdentity({ identitySecret: openSealed(value, passphrase), leaf: value.leaf, limit: value.limit ?? FILE_DEFAULT_LIMIT });
}

// readIdentityFile(path, { passphrase }) -> FileIdentity, for `--identity <path>` / SHADE_TREE_IDENTITY.
// Errors name the path and never echo file contents.
export function readIdentityFile(path, { passphrase } = {}) {
  let text;
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_IDENTITY_FILE) throw new Error("not a regular file under 16 KiB");
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(`identity ${path}: ${e.code === "ENOENT" ? "file not found" : e.message}`);
  }
  try {
    return openIdentity(text, { passphrase });
  } catch (e) {
    throw new Error(`identity ${path}: ${e.message}`);
  }
}
