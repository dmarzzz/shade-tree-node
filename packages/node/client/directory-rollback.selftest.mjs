// Selftest for the directory ROLLBACK / stale-replay guard (audit loop-15 F2).
//
// A v3 directory is signed by the bootnode itself, and an ed25519 signature is valid forever.
// A stateless verifyDirectory therefore CANNOT tell a current directory from an old, validly
// signed one — so a hostile or replaying bootnode could serve a stale directory to resurrect a
// gateway that has since been dropped or slashed. The client defends by refusing any FRESH
// directory whose `issued` timestamp moves BACKWARD past the newest it has already accepted.
//
// This drives the real packages/node/client/selection.mjs load path against a file-backed directory (no Tor,
// no chain): write a signed directory, load it, then rewrite the SAME file with an older/newer
// `issued` and force a refresh. Env is set BEFORE importing selection.mjs because its config is
// read at module load.
//
//   node packages/node/client/directory-rollback.selftest.mjs
//
// Exit 0 = the guard holds (forward + equal accepted, backward rejected, fleet retained).

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}

async function main() {
  const { pubkeyToOnion, signDirectory } = await import("../lib/directory.mjs");
  const signer = newKey();

  // A directory with a single gateway whose pubkey is encoded in its own v3 onion, signed by
  // `signer`, declaring the given `issued`.
  function signedDir(issued) {
    const g = newKey();
    const base = {
      version: 1,
      issued,
      gateways: [{ onion: pubkeyToOnion(g.pub), pubkey: g.pub, weight: 100, health: "up" }],
      signer: signer.pub,
    };
    return signDirectory(base, signer.priv);
  }

  const dir = mkdtempSync(join(tmpdir(), "shade-tree-rollback-"));
  const dirPath = join(dir, "directory.json");
  const writeDir = (issued) => { const d = signedDir(issued); writeFileSync(dirPath, JSON.stringify(d) + "\n"); return d; };

  // Config is read at import — set it first. File source (no bootnode), reload on every call, and
  // an isolated health cache so this test never touches the real one.
  process.env.SHADE_TREE_DIRECTORY = dirPath;
  process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
  process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0"; // every selectCandidates() re-reads the file
  process.env.SHADE_TREE_HEALTH_CACHE = join(dir, "health.json");
  delete process.env.SHADE_TREE_BOOTNODE_ONION;
  delete process.env.SHADE_TREE_VERIFY_STAKE;

  writeDir(1000);
  const sel = await import("./selection.mjs");
  sel._resetIssuedFloor();

  console.log("baseline load establishes the issued floor:");
  const first = await sel.selectCandidates();
  ok(first.length === 1, "initial directory (issued 1000) loads one gateway");
  const firstOnion = first[0].onion;

  console.log("\na newer directory (issued 2000) is accepted and replaces the fleet:");
  writeDir(2000);
  const second = await sel.selectCandidates();
  ok(second.length === 1, "forward directory loads");
  ok(second[0].onion !== firstOnion, "fleet advanced to the newer directory's gateway");
  const secondOnion = second[0].onion;

  console.log("\na ROLLBACK directory (issued 1500 < 2000) is rejected; last-good fleet retained:");
  writeDir(1500);
  const third = await sel.selectCandidates();
  ok(third.length === 1, "still serving a fleet (did not go dark)");
  ok(third[0].onion === secondOnion, "rolled-back directory REJECTED — kept the issued-2000 gateway, did not resurrect");

  console.log("\nan even-older rollback (issued 1) is also rejected:");
  writeDir(1);
  const fourth = await sel.selectCandidates();
  ok(fourth[0].onion === secondOnion, "deep rollback rejected, floor held at 2000");

  console.log("\na same-issued refetch (issued 2000) is idempotently accepted (not a rollback):");
  const sameProbe = writeDir(2000);
  const fifth = await sel.selectCandidates();
  ok(fifth.length === 1, "equal-issued directory accepted");
  ok(fifth[0].onion === sameProbe.gateways[0].onion.replace(/\.onion$/, ""), "equal-issued directory swapped in (>= floor, not < floor)");

  console.log("\nforward progress resumes after the attack (issued 3000 accepted):");
  const fwd = writeDir(3000);
  const sixth = await sel.selectCandidates();
  ok(sixth[0].onion === fwd.gateways[0].onion.replace(/\.onion$/, ""), "issued 3000 accepted, floor advances");

  rmSync(dir, { recursive: true, force: true });
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-rollback selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
