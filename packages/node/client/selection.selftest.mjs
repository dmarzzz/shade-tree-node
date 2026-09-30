// Offline proof of the client proxy's per-tunnel gateway selection (packages/node/client/selection.mjs) over the
// STATIC signed-directory source — no Tor, no live bootnode. This is the same verify +
// last-known-good + weighted-selection code the live bootnode path shares; only the fetch
// differs. We mint three real, internally-consistent v3 onions, sign a directory with a fresh
// ed25519 signer, pin that signer, and drive selectCandidates / reportResult.
//
// selection.mjs captures its config from the environment AT IMPORT TIME (SHADE_TREE_DIRECTORY,
// SHADE_TREE_DIR_SIGNER, ...), so the positive case sets the env BEFORE the dynamic import, and the
// negative case (wrong pinned signer) runs in a SEPARATE spawned node process with a different
// env — you cannot re-pin inside a process that has already imported the module.
//
//   node packages/node/client/selection.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { signDirectory, verifyDirectory, pubkeyToOnion } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION_PATH = join(HERE, "selection.mjs");

// Raw 32-byte ed25519 key material as hex (last 32 bytes of the DER encodings), matching how
// packages/node/lib/directory.mjs's ed25519PrivateKey/PublicKey and the sign-directory tool treat keys.
function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    pub: Buffer.from(pub.subarray(pub.length - 32)).toString("hex"),
    priv: Buffer.from(priv.subarray(priv.length - 32)).toString("hex"),
  };
}

// A gateway entry whose pubkey is exactly the key encoded in its own v3 onion, so
// verifyDirectory's onion<->pubkey binding holds.
function mintGateway(weight, health) {
  const k = newEd25519();
  return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-selection-"));
  try {
    // --- mint a signer + a 3-gateway signed directory -------------------------
    const signer = newEd25519();
    const gateways = [mintGateway(100, "up"), mintGateway(100, "up"), mintGateway(100, "up")];
    const dir = { version: 1, issued: Math.floor(Date.now() / 1000), gateways, signer: signer.pub };
    const signed = signDirectory(dir, signer.priv);

    console.log("directory:");
    ok(verifyDirectory(signed, signer.pub).ok, "minted directory verifies against its signer (self-check)");
    ok(verifyDirectory(signed, "00".repeat(32)).ok === false, "minted directory is rejected under a wrong pinned signer");

    const dirFile = join(work, "directory.signed.json");
    await writeFile(dirFile, JSON.stringify(signed, null, 2) + "\n");

    const wantOnions = new Set(gateways.map((g) => g.onion.replace(/\.onion$/, "")));

    // --- import selection.mjs with the env it reads AT IMPORT TIME ------------
    process.env.SHADE_TREE_DIRECTORY = dirFile;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    delete process.env.SHADE_TREE_BOOTNODE_ONION; // force the static-file source, not live discovery
    const sel = await import(pathToFileURL(SELECTION_PATH).href);

    console.log("\ndirectoryEnabled + selectCandidates:");
    ok(sel.directoryEnabled() === true, "directoryEnabled() is true with a directory file + pinned signer");

    const first = await sel.selectCandidates();
    ok(Array.isArray(first) && first.length === 3, "selectCandidates() returns all 3 gateways");
    ok(first.every((c) => c && typeof c.onion === "string"), "each candidate is an object shaped { onion }");
    ok(first.every((c) => wantOnions.has(c.onion)), "every returned candidate onion is one of the minted gateways");
    ok(new Set(first.map((c) => c.onion)).size === 3, "the failover order has no duplicate gateways");

    // Weighted rotation is not deadlocked on one gateway: over many independent selections,
    // every gateway lands in the FIRST (weighted-pick) slot at least once.
    const firsts = new Set();
    for (let i = 0; i < 400; i++) firsts.add((await sel.selectCandidates())[0].onion);
    ok(firsts.size === 3, `every gateway appears first at least once over many selections (${firsts.size}/3)`);

    // --- health degradation must not dead-end --------------------------------
    console.log("\nreportResult (health degradation):");
    const victim = first[0].onion;
    sel.reportResult(victim, { ok: false });
    sel.reportResult(victim, { ok: false }); // 2 fails -> marked "down"
    const afterFail = await sel.selectCandidates();
    ok(afterFail.length === 3, "a gateway marked down is still offered as a last-resort failover (fleet does not shrink to nothing)");
    ok(afterFail.some((c) => c.onion === victim), "the downed gateway is still present in the failover order");
    // and its full set is still every gateway
    ok(new Set(afterFail.map((c) => c.onion)).size === 3, "after degradation the order still covers all 3 with no duplicates");

    // --- negative: a WRONG pinned signer must fail verification --------------
    // Run in a fresh process so the module re-reads env; re-importing in-process would reuse the
    // already-captured (correct) signer.
    console.log("\nwrong pinned signer (separate process):");
    const wrong = newEd25519();
    const script = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
try {
  const c = await sel.selectCandidates();
  console.log("UNEXPECTED-OK:" + c.length);
  process.exit(0);
} catch (e) {
  console.error("verify-fail: " + e.message);
  process.exit(3);
}`;
    let negCode = 0, negOut = "";
    try {
      execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        encoding: "utf8",
        env: { ...process.env, SHADE_TREE_DIRECTORY: dirFile, SHADE_TREE_DIR_SIGNER: wrong.pub, SHADE_TREE_BOOTNODE_ONION: "" },
      });
      negCode = 0; // execFileSync only returns on exit 0
    } catch (e) {
      negCode = e.status ?? 1;
      negOut = (e.stdout || "") + (e.stderr || "");
    }
    ok(negCode !== 0, "selectCandidates() under a wrong pinned signer fails (subprocess exits nonzero)");
    ok(/verify-fail|no verifiable directory|signer-not-pinned|bad-signature/i.test(negOut),
      "the failure is a directory verification failure, not candidates");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: selection selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
