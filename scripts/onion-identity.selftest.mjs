// Selftest for the onion-identity continuity tool (scripts/onion-identity.mjs).
//
// It proves the operationally critical property: a bare hs_ed25519_secret_key is sufficient to
// (a) DERIVE the exact .onion Tor will publish, and (b) RESTORE a working HiddenServiceDir with
// the right layout + perms — so a rebuilt box comes back on the SAME onion.
//
//   - mint a real onion identity (reuse packages/node/bootnode/keygen.mjs), so the expected onion is known
//   - derive-from-secret reproduces that onion (our hand-rolled A = a·B == keygen's node:crypto pub)
//   - restore into a FRESH dir writes secret/public/hostname with 0600/0600/0644 + dir 0700
//   - restored hostname == derived onion; restored public/secret bytes are correct
//   - derive-from-restored-secret round-trips to the SAME onion
//   - a corrupt (bad-tag / wrong-length) secret is rejected, not silently mis-derived
//   - restore refuses to overwrite a populated HS dir without --force
//
//   node scripts/onion-identity.selftest.mjs   (exit 0 = all invariants held)

import { mkdtempSync, rmSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "../packages/node/bootnode/keygen.mjs";
import { pubkeyToOnion } from "../packages/node/lib/directory.mjs";
import {
  identityFromSecretKeyFile, scalarFromSecretKeyFile, publicKeyFileBytes,
  deriveFromFile, restoreToHsDir,
} from "./onion-identity.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const perms = (p) => statSync(p).mode & 0o777;

async function main() {
  const work = mkdtempSync(join(tmpdir(), "shade-tree-onion-"));
  try {
    // --- mint a real onion identity: gives us the ground-truth onion + secret key file --------
    console.log("mint (packages/node/bootnode/keygen.mjs):");
    const srcHs = join(work, "src-hs");
    const id = await generateOnionIdentity(srcHs, { label: "selftest" });
    const secretFile = join(srcHs, "hs_ed25519_secret_key");
    ok(existsSync(secretFile), "keygen wrote hs_ed25519_secret_key");
    ok(id.onion.endsWith(".onion") && id.onion.length === 62, "minted a v3 .onion");

    // --- derive: reconstruct the onion FROM THE SECRET KEY ALONE ------------------------------
    console.log("\nderive (secret key -> onion, no seed):");
    const derived = deriveFromFile(secretFile);
    ok(derived.onion === id.onion, "derived onion == the minted onion");
    ok(derived.pub === id.pub, "derived pubkey == the minted pubkey (hand-rolled A=a·B matches node:crypto)");
    ok(pubkeyToOnion(derived.pub) === id.onion, "derived pubkey re-encodes to the same onion");

    // pure-function scalar extraction sanity
    const scalar = scalarFromSecretKeyFile(readFileSync(secretFile));
    ok(scalar.length === 32, "scalarFromSecretKeyFile returns a 32-byte clamped scalar");

    // Multi-key cross-check: the hand-rolled A = a·B scalar multiplication is the security-critical
    // step (a bug in point compression's sign bit could pass one key and fail another), so verify it
    // against node:crypto's INDEPENDENT derivation (keygen uses createPublicKey) over many fresh keys,
    // not just the single mint above. All must reproduce keygen's onion exactly.
    console.log("\ncross-check A=a·B vs node:crypto over 24 fresh keys:");
    let xchk = 0;
    for (let i = 0; i < 24; i++) {
      const hs = join(work, `xchk-${i}`);
      const kid = await generateOnionIdentity(hs, { label: `xchk-${i}` });
      const kd = deriveFromFile(join(hs, "hs_ed25519_secret_key"));
      if (kd.pub === kid.pub && kd.onion === kid.onion) xchk++;
    }
    ok(xchk === 24, `all 24 hand-rolled derivations match node:crypto (got ${xchk}/24)`);

    // --- restore into a FRESH dir: layout + perms ---------------------------------------------
    console.log("\nrestore (secret key -> fresh HiddenServiceDir):");
    const dstHs = join(work, "restored-hs");
    const r = restoreToHsDir(secretFile, dstHs);
    ok(r.onion === id.onion, "restore reports the same onion");

    const rSecret = join(dstHs, "hs_ed25519_secret_key");
    const rPublic = join(dstHs, "hs_ed25519_public_key");
    const rHost = join(dstHs, "hostname");
    ok(existsSync(rSecret) && existsSync(rPublic) && existsSync(rHost), "wrote secret + public + hostname");

    ok(perms(dstHs) === 0o700, `HS dir is 0700 (got 0${perms(dstHs).toString(8)})`);
    ok(perms(rSecret) === 0o600, `hs_ed25519_secret_key is 0600 (got 0${perms(rSecret).toString(8)})`);
    ok(perms(rPublic) === 0o600, `hs_ed25519_public_key is 0600 (got 0${perms(rPublic).toString(8)})`);
    ok(perms(rHost) === 0o644, `hostname is 0644 (got 0${perms(rHost).toString(8)})`);

    ok(readFileSync(rHost, "utf8").trim() === id.onion, "restored hostname == the onion");
    ok(Buffer.compare(readFileSync(rSecret), readFileSync(secretFile)) === 0, "restored secret key is byte-identical to the input");
    ok(Buffer.compare(readFileSync(rPublic), publicKeyFileBytes(id.pub)) === 0, "restored public key matches the reconstructed bytes");
    ok(Buffer.compare(readFileSync(rPublic), readFileSync(join(srcHs, "hs_ed25519_public_key"))) === 0, "restored public key == keygen's public key file");

    // --- derive-from-restored round-trips ------------------------------------------------------
    console.log("\nround-trip (restored secret -> onion):");
    const derived2 = deriveFromFile(rSecret);
    ok(derived2.onion === id.onion, "derive from the RESTORED secret yields the same onion");

    // --- corrupt input is rejected, not silently mis-derived ----------------------------------
    console.log("\nrejection (bad inputs):");
    const badTag = Buffer.concat([Buffer.alloc(32, 0x41), readFileSync(secretFile).subarray(32)]);
    let tagThrew = false;
    try { identityFromSecretKeyFile(badTag); } catch (e) { tagThrew = /type tag/.test(e.message); }
    ok(tagThrew, "a wrong type tag is rejected");
    let lenThrew = false;
    try { identityFromSecretKeyFile(readFileSync(secretFile).subarray(0, 90)); } catch (e) { lenThrew = /96 bytes/.test(e.message); }
    ok(lenThrew, "a wrong-length secret is rejected");

    // --- overwrite guard -----------------------------------------------------------------------
    console.log("\noverwrite guard:");
    let refuseThrew = false;
    try { restoreToHsDir(secretFile, dstHs); } catch (e) { refuseThrew = /overwrite|--force/.test(e.message); }
    ok(refuseThrew, "restore into a populated HS dir refuses without --force");
    const forced = restoreToHsDir(secretFile, dstHs, { force: true });
    ok(forced.onion === id.onion, "restore --force overwrites and yields the same onion");

    // secret bytes must not have been logged by any code path we exercised (spot-check the tool
    // exposes no byte-dumping API): identity result carries only pub hex + onion, never the scalar.
    ok(!("scalar" in derived) && !("secret" in derived), "derive result exposes no secret material");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: onion-identity selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
