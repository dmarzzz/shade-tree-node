// One identity file for both clients (#251): the JS client reads what the Rust `shadenet init`
// writes, in its plaintext and passphrase-protected forms, and keeps reading the app secret.
//
// testdata/identity/ holds files written by the Rust client (see vectors.json there). The Rust
// test crates/shadenet/src/identity.rs `the_shared_identity_files_load_in_both_forms` reads the
// same files, so the two readers cannot drift apart.
//
//   node packages/node/lib/identity-file.selftest.mjs

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import {
  identityFor, identitySecretOf, rateCommitmentOf, identityCommitmentOf, newGroup, proveForSlot, verifyEnvelope,
  requestSignal, currentEpoch, cleanUp,
} from "./rln.mjs";
import { identityFileFor, serializeIdentityFile, openIdentity, readIdentityFile, hchacha20, FileIdentity, isEncryptedIdentityFile } from "./identity-file.mjs";
import { parseIdentityFile, identityCommitmentOf as commitmentOfSecret } from "./identity-core.mjs";
import { validateConfig } from "./config.mjs";
import { ShadeTreeClient, memberCredential, makeSlotPool, makeLeafSourceLoader } from "../client/shade-tree-client.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const DIR = join(ROOT, "testdata", "identity");
const vectors = JSON.parse(readFileSync(join(DIR, "vectors.json"), "utf8"));
const PLAIN = join(DIR, vectors.plain);
const LOCKED = join(DIR, vectors.locked);
const LOCKED_LOW_COST = join(DIR, vectors.lockedLowCost);
// Sealed by the Rust client after the scrypt 0.11 -> 0.12 bump (Dependabot #266).
const LOCKED_SCRYPT012 = join(DIR, vectors.lockedScrypt012);
const PASSPHRASE = vectors.passphrase;

let passed = 0;
async function test(name, fn) {
  await fn();
  passed += 1;
  console.log(`  ok   ${name}`);
}

const scratch = mkdtempSync(join(tmpdir(), "identity-file-selftest-"));
const offline = { onion: "x", prove: async () => ({}), slotStateDir: join(scratch, "slots") };

try {
  await test("HChaCha20 matches the XChaCha draft's test vector", () => {
    const key = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
    const nonce = Buffer.from("000000090000004a0000000031415927", "hex");
    assert.equal(hchacha20(key, nonce).toString("hex"), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assert.throws(() => hchacha20(key.subarray(1), nonce), /32-byte key/);
  });

  let plain;
  await test("the plaintext file `shadenet init` writes opens, and its leaf is the secret's leaf", () => {
    plain = readIdentityFile(PLAIN);
    assert.ok(plain instanceof FileIdentity);
    assert.equal(plain.leaf, vectors.leaf);
    assert.equal(plain.limit, vectors.limit);
    assert.equal(commitmentOfSecret(plain.identitySecret).toString(), vectors.identityCommitment);
    // The same bytes through the text and object entry points.
    const text = readFileSync(PLAIN, "utf8");
    assert.equal(openIdentity(text).identitySecret, plain.identitySecret);
    assert.equal(openIdentity(JSON.parse(text)).identitySecret, plain.identitySecret);
    assert.equal(openIdentity(plain), plain, "a FileIdentity passes through");
  });

  await test("the passphrase-protected files open with the passphrase to the same identity", () => {
    for (const path of [LOCKED, LOCKED_LOW_COST, LOCKED_SCRYPT012]) {
      const raw = JSON.parse(readFileSync(path, "utf8"));
      assert.ok(isEncryptedIdentityFile(raw));
      assert.equal(raw.identitySecret, undefined, "the sealed form carries no plaintext secret");
      const opened = readIdentityFile(path, { passphrase: PASSPHRASE });
      assert.equal(opened.identitySecret, plain.identitySecret, basename(path));
      assert.equal(opened.leaf, vectors.leaf);
      assert.equal(opened.limit, vectors.limit);
    }
  });

  await test("a wrong passphrase, a missing one and an edited file are refused without echoing the file", () => {
    const text = readFileSync(LOCKED_LOW_COST, "utf8");
    assert.throws(() => readIdentityFile(LOCKED_LOW_COST, { passphrase: "wrong horse" }), /wrong passphrase/);
    assert.throws(() => readIdentityFile(LOCKED_LOW_COST), /passphrase-protected; set SHADE_TREE_PASSPHRASE_FILE/);
    // The public fields are bound: raising the tier in the file breaks the seal.
    const raised = JSON.parse(text);
    raised.limit = 8;
    assert.throws(() => openIdentity(raised, { passphrase: PASSPHRASE }), /wrong passphrase/);
    const greedy = JSON.parse(text);
    greedy.encrypted.logN = 30;
    assert.throws(() => openIdentity(greedy, { passphrase: PASSPHRASE }), /unsupported scrypt/);
    // The shared over-limit vector (logN 20, r 32, p 16: 4 GiB and minutes of scrypt) is refused
    // before any work starts, in both readers.
    const started = Date.now();
    assert.throws(() => readIdentityFile(join(DIR, vectors.overLimit), { passphrase: PASSPHRASE }), /unsupported scrypt/);
    assert.ok(Date.now() - started < 1000, "refused before running scrypt");
    for (const [field, value] of [["logN", 21], ["r", 9], ["p", 5]]) {
      const past = JSON.parse(text);
      past.encrypted[field] = value;
      assert.throws(() => openIdentity(past, { passphrase: PASSPHRASE }), /unsupported scrypt/, `${field} ${value}`);
    }
    // The joint memory bound bites even when logN and r are each within their cap:
    // r 8, logN 21 -> r * 2^logN = 16 * 2^20 > 8 * 2^20.
    const jointOverLimit = JSON.parse(text);
    jointOverLimit.encrypted.r = 8;
    jointOverLimit.encrypted.logN = 21;
    assert.throws(() => openIdentity(jointOverLimit, { passphrase: PASSPHRASE }), /unsupported scrypt/);
    const other = JSON.parse(text);
    other.encrypted.cipher = "aes-256-gcm";
    assert.throws(() => openIdentity(other, { passphrase: PASSPHRASE }), /unsupported encryption/);
    const short = JSON.parse(text);
    short.encrypted.nonce = "00";
    assert.throws(() => openIdentity(short, { passphrase: PASSPHRASE }), /corrupt/);
    const both = { ...JSON.parse(text), identitySecret: "1" };
    assert.throws(() => openIdentity(both, { passphrase: PASSPHRASE }), /both a plaintext and an encrypted secret/);
    // The browser-side parser is unchanged: it reads the plaintext form and refuses the sealed one.
    assert.throws(() => parseIdentityFile(text), /must contain only identitySecret, leaf, and limit/);
    assert.equal(parseIdentityFile(readFileSync(PLAIN, "utf8")).leaf, vectors.leaf);
    // A plaintext file whose leaf belongs to another tier or another secret is refused.
    const mismatched = JSON.parse(readFileSync(PLAIN, "utf8"));
    mismatched.limit = 8;
    assert.throws(() => openIdentity(mismatched), /does not match/);
    assert.throws(() => openIdentity("not json"), /not a valid identity JSON/);
    assert.throws(() => readIdentityFile(join(scratch, "absent.json")), /absent\.json: file not found/);
    for (const attempt of [() => readIdentityFile(LOCKED_LOW_COST, { passphrase: "wrong horse" }), () => openIdentity(mismatched)]) {
      try { attempt(); } catch (e) { assert.ok(!e.message.includes(plain.identitySecret.toString()), "no secret in an error"); }
    }
  });

  await test("a FileIdentity never shows its secret", () => {
    const secret = plain.identitySecret.toString();
    for (const shown of [String(plain), JSON.stringify(plain), inspect(plain, { depth: 5, showHidden: true, getters: true }), `${inspect([plain], { showHidden: true, getters: true })}`, JSON.stringify({ ...plain })]) {
      assert.ok(!shown.includes(secret), shown);
    }
    assert.deepEqual(Object.keys(plain).sort(), ["leaf", "limit"]);
    assert.throws(() => { plain.limit = 8; }, TypeError, "frozen");
  });

  await test("identityFor / identitySecretOf take an identity file wherever they take an app secret", () => {
    assert.equal(identityFor(plain), plain);
    assert.equal(identitySecretOf(identityFor(plain)), plain.identitySecret);
    assert.equal(rateCommitmentOf(identityFor(plain), plain.limit).toString(), vectors.leaf);
    assert.equal(identityCommitmentOf(identityFor(plain)).toString(), vectors.identityCommitment);
  });

  await test("the file `shade-tree identity` writes is the same member as its app secret", () => {
    // JS's own export, default tier (no `limit` key) and a non-default tier.
    const appSecret = "0x" + "5a".repeat(32);
    for (const limit of [8, 32]) {
      const file = openIdentity(serializeIdentityFile(identityFileFor(appSecret, limit)));
      assert.equal(file.limit, limit);
      assert.equal(file.identitySecret, identitySecretOf(identityFor(appSecret)));
      assert.equal(file.leaf, rateCommitmentOf(identityFor(appSecret), limit).toString());
    }
  });

  await test("the client takes the file: tier, slot-state name and leaf lookup come from it", async () => {
    const group = newGroup([BigInt(vectors.leaf)]);
    const client = new ShadeTreeClient({ identityFile: PLAIN, loadGroupFn: async () => ({ group, source: "members.json" }), ...offline });
    assert.equal(client.secret, client.secret instanceof FileIdentity ? client.secret : null);
    assert.equal(client.limit, vectors.limit, "the file's tier, not the default");
    assert.equal(client.pool.K, vectors.limit);
    assert.equal(await client.leafSource(), "invited");
    // The slot cursor is named by the identity commitment Poseidon1(secret), not the leaf (#B),
    // so every leaf of one secret shares one file; still the Rust client's file, shared.
    const reservation = client.pool.nextSlot();
    reservation.release?.();
    assert.ok(readFileSync(join(scratch, "slots", `${vectors.identityCommitment}.json`), "utf8").includes("nextSlot"));
    // The discovery loader finds the leaf of the file in a staked set.
    const loader = makeLeafSourceLoader({
      secret: client.secret, limit: vectors.limit, env: {}, contracts: [{ address: "0xabc", kind: "staked" }],
      loadStatic: async () => ({ group: newGroup([]), count: 0 }), loadContract: async () => ({ group, count: 1 }),
    });
    assert.equal((await loader()).source, "staked(0xabc)");
    // An explicit tier that is not the file's is a different leaf: refused up front.
    assert.throws(() => new ShadeTreeClient({ identityFile: PLAIN, limit: 8, ...offline }), /identity file is tier 1; limit 8/);
    assert.equal(new ShadeTreeClient({ identityFile: PLAIN, limit: 1, ...offline }).limit, 1);
    // The pool alone, as the proxy builds it.
    const pool = makeSlotPool({ secret: plain, K: plain.limit, prove: async () => ({}), loadGroupFn: async () => ({ group }), slotStateDir: join(scratch, "pool") });
    pool.nextSlot().release?.();
    assert.ok(readFileSync(join(scratch, "pool", `${vectors.identityCommitment}.json`), "utf8").includes("nextSlot"));
  });

  await test("the credential comes from an option before the environment, and a sealed file asks for its passphrase", () => {
    const passFile = join(scratch, "passphrase");
    writeFileSync(passFile, `${PASSPHRASE}\n`, { mode: 0o600 });
    assert.equal(memberCredential({ secret: "0x01" }, { SHADE_TREE_IDENTITY: PLAIN }), "0x01");
    assert.equal(memberCredential({ identityFile: PLAIN }, { SHADE_TREE_SECRET: "0x02" }).leaf, vectors.leaf);
    // Two credentials at one level never pick one quietly.
    assert.throws(() => memberCredential({ secret: "0x01", identityFile: PLAIN }, {}), /both given; pass one/);
    assert.throws(() => memberCredential({ secret: "0x01", identity: plain }, {}), /both given; pass one/);
    assert.throws(() => memberCredential({}, { SHADE_TREE_SECRET: "0x02", SHADE_TREE_IDENTITY: PLAIN }), /both set; unset one, or pass --identity or --secret/);
    assert.equal(memberCredential({}, { SHADE_TREE_IDENTITY: PLAIN }).leaf, vectors.leaf);
    assert.equal(memberCredential({ identity: readFileSync(PLAIN, "utf8") }, {}).leaf, vectors.leaf);
    assert.equal(memberCredential({ identity: plain }, {}), plain);
    assert.equal(memberCredential({}, { SHADE_TREE_IDENTITY: LOCKED_LOW_COST, SHADE_TREE_PASSPHRASE_FILE: passFile }).identitySecret, plain.identitySecret);
    assert.equal(memberCredential({}, { SHADE_TREE_IDENTITY: LOCKED_LOW_COST, SHADE_TREE_PASSPHRASE: PASSPHRASE }).identitySecret, plain.identitySecret);
    assert.equal(memberCredential({ identityFile: LOCKED_LOW_COST, passphrase: PASSPHRASE }, {}).identitySecret, plain.identitySecret);
    assert.throws(() => memberCredential({}, { SHADE_TREE_IDENTITY: LOCKED_LOW_COST }), /ShadeTreeClient: identity .*passphrase-protected/);
    assert.throws(() => memberCredential({}, { SHADE_TREE_IDENTITY: LOCKED_LOW_COST, SHADE_TREE_PASSPHRASE: "wrong horse" }), /wrong passphrase/);
    assert.throws(() => memberCredential({}, { SHADE_TREE_IDENTITY: LOCKED_LOW_COST, SHADE_TREE_PASSPHRASE_FILE: join(scratch, "nope") }), /read passphrase file/);
    assert.throws(() => memberCredential({}, { SHADE_TREE_IDENTITY: join(scratch, "absent.json") }), /file not found/);
    assert.throws(() => memberCredential({}, {}), /`secret` \(or SHADE_TREE_SECRET\) is required, or an identity file/);
  });

  await test("the launcher's config check accepts an identity file in place of the secret", () => {
    const onion = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";
    assert.ok(validateConfig("client", { SHADE_TREE_IDENTITY: PLAIN, SHADE_TREE_ONION: onion }).ok);
    assert.ok(validateConfig("client", { SHADE_TREE_SECRET: "0x01", SHADE_TREE_ONION: onion }).ok);
    const missing = validateConfig("client", { SHADE_TREE_ONION: onion });
    assert.equal(missing.ok, false);
    assert.equal(missing.errors[0].var, "SHADE_TREE_SECRET");
    assert.match(missing.errors[0].problem, /^required but not set \(or set SHADE_TREE_IDENTITY/);
    const both = validateConfig("client", { SHADE_TREE_SECRET: "0x01", SHADE_TREE_IDENTITY: PLAIN, SHADE_TREE_ONION: onion });
    assert.equal(both.ok, false);
    assert.equal(both.errors[0].var, "SHADE_TREE_IDENTITY");
    assert.match(both.errors[0].problem, /set together with SHADE_TREE_SECRET/);
    const zero = validateConfig("client", { SHADE_TREE_SECRET: "0x0", SHADE_TREE_ONION: onion });
    assert.equal(zero.errors[0].var, "SHADE_TREE_SECRET", "a malformed secret is still an error");
  });

  await test("`shade-tree proxy --identity <file>` starts the proxy with no SHADE_TREE_SECRET", async () => {
    const cli = join(ROOT, "packages", "node", "bin", "shade-tree.mjs");
    const onion = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";
    const env = { PATH: process.env.PATH, HOME: scratch, SHADE_TREE_BANNER: "never", SHADE_TREE_LOG_FORMAT: "json", SHADE_TREE_SLOT_STATE_DIR: join(scratch, "cli-slots") };
    // A sealed file with no passphrase: one line, exit 1, nothing from the file echoed.
    const sealed = spawnSync(process.execPath, [cli, "proxy", "--identity", LOCKED_LOW_COST, "--onion", onion], { env, encoding: "utf8", timeout: 60_000 });
    const sealedOut = `${sealed.stdout}${sealed.stderr}`;
    assert.equal(sealed.status, 1, sealedOut);
    assert.match(sealedOut, /passphrase-protected; set SHADE_TREE_PASSPHRASE_FILE/);
    assert.ok(!/\n\s+at /.test(sealedOut), "no stack trace");
    const absent = spawnSync(process.execPath, [cli, "proxy", "--identity", join(scratch, "absent.json"), "--onion", onion], { env, encoding: "utf8", timeout: 60_000 });
    assert.equal(absent.status, 1);
    assert.match(`${absent.stdout}${absent.stderr}`, /absent\.json: file not found/);
    // An exported SHADE_TREE_SECRET does not win over an explicit --identity: the flag chooses,
    // so the proxy reaches the sealed file (and asks for its passphrase) instead of proving as
    // the other member.
    const chosen = spawnSync(process.execPath, [cli, "proxy", "--identity", LOCKED_LOW_COST, "--onion", onion], { env: { ...env, SHADE_TREE_SECRET: "0x01" }, encoding: "utf8", timeout: 60_000 });
    assert.equal(chosen.status, 1);
    assert.match(`${chosen.stdout}${chosen.stderr}`, /passphrase-protected; set SHADE_TREE_PASSPHRASE_FILE/);
    // Both exported and no flag choosing: refused up front.
    const ambiguous = spawnSync(process.execPath, [cli, "proxy", "--onion", onion], { env: { ...env, SHADE_TREE_SECRET: "0x01", SHADE_TREE_IDENTITY: PLAIN }, encoding: "utf8", timeout: 60_000 });
    assert.notEqual(ambiguous.status, 0);
    assert.match(`${ambiguous.stdout}${ambiguous.stderr}`, /SHADE_TREE_IDENTITY: set together with SHADE_TREE_SECRET/);
    // Neither credential: the launcher's config check says which two would do.
    const neither = spawnSync(process.execPath, [cli, "proxy", "--onion", onion], { env, encoding: "utf8", timeout: 60_000 });
    assert.notEqual(neither.status, 0);
    assert.match(`${neither.stdout}${neither.stderr}`, /SHADE_TREE_SECRET: required but not set \(or set SHADE_TREE_IDENTITY/);

    // The plaintext file: the proxy comes up. No tunnel is opened (that needs Tor and a node).
    const port = await new Promise((resolve, reject) => {
      const probe = net.createServer().once("error", reject).listen(0, "127.0.0.1", () => {
        const { port: free } = probe.address();
        probe.close(() => resolve(free));
      });
    });
    const child = spawn(process.execPath, [cli, "proxy", "--identity", PLAIN, "--onion", onion, "--shim-port", String(port)], { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`the proxy did not come up: ${out.slice(-600)}`)), 60_000);
        const seen = (chunk) => {
          out += chunk;
          if (/Proxy ready/.test(out)) { clearTimeout(timer); resolve(); }
        };
        child.stdout.on("data", seen);
        child.stderr.on("data", seen);
        child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`the proxy exited ${code}: ${out.slice(-600)}`)); });
      });
    } finally {
      child.removeAllListeners("exit");
      child.kill("SIGTERM");
    }
    assert.ok(!out.includes(plain.identitySecret.toString()), "the identity secret is never logged");
  });

  await test("a proof made from the Rust-written file verifies (real Groth16)", async () => {
    // The Rust-created identity, opened from its sealed file, in a set with two other leaves.
    const member = readIdentityFile(LOCKED, { passphrase: PASSPHRASE });
    const group = newGroup([rateCommitmentOf(identityFor("0x11")), BigInt(member.leaf), rateCommitmentOf(identityFor("0x12"))]);
    const nowMs = Date.now();
    const epoch = currentEpoch(nowMs);
    const proved = await proveForSlot(member, epoch, 0, requestSignal("example.com:443", "n-1"), { group, limit: member.limit });
    const envelope = { v: 4, target: "example.com:443", nonce: "n-1", proof: proved.proof, nullifier: proved.nullifier, externalNullifier: proved.externalNullifier, share: proved.share, artifact: proved.artifact };
    const verdict = await verifyEnvelope(envelope, new Set([group.root.toString()]), nowMs);
    assert.equal(verdict.ok, true, verdict.reason);
    // Tier 1 has one slot: slot 1 is outside it, as for any tier-1 member.
    await assert.rejects(() => proveForSlot(member, epoch, 1, requestSignal("example.com:443", "n-2"), { group, limit: member.limit }), /out of this member's tier/);
  });

  console.log(`\nPASS: ${passed} identity-file checks`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
  cleanUp();
}
process.exit(0);
