// Offline proof of the client's zero-trust operator re-verification (packages/node/client/selection.mjs,
// T-DEV-5) — no Tor, no chain. In stake mode the signed directory carries the bootnode's
// `operator`/`staked` LABEL, but the onion<->operator binding and the live stake are NOT in the
// signed directory: they live in the raw announce and on chain. So a compromised bootnode (or
// directory signer) could paste a `staked:true` label onto a gateway whose operator never
// authorized it, or whose stake has lapsed. With SHADE_TREE_VERIFY_STAKE=1 the client refuses the
// label: for every entry claiming stake it fetches the stored signed announce (GET /gateway/<onion>)
// and independently re-runs the onion-control + operator signatures (announce.mjs verifyAnnounce)
// and the live isStaked() check, dropping any gateway that fails.
//
// We mint real v3 onions + real ethers operator signatures and inject an in-memory announce fetch
// + a mock stake verifier, so the whole re-verification runs with no Tor and no chain. The env
// (SHADE_TREE_DIRECTORY / SHADE_TREE_DIR_SIGNER / SHADE_TREE_VERIFY_STAKE) is set BEFORE the dynamic import, exactly
// as selection.mjs captures its config at import time. The flag-OFF case runs in a SEPARATE
// spawned process (the flag cannot be un-captured in a process that already imported the module).
//
//   node packages/node/client/verify-stake.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { ethers } from "ethers";
import { signDirectory, pubkeyToOnion } from "../lib/directory.mjs";
import { buildAnnounce, operatorAuthMessage } from "../bootnode/announce.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION_PATH = join(HERE, "selection.mjs");

// Raw 32-byte ed25519 key material as hex (last 32 bytes of the DER encodings), matching how
// packages/node/lib/directory.mjs treats keys and how buildAnnounce expects `onionSeedHex`.
function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    pub: Buffer.from(pub.subarray(pub.length - 32)).toString("hex"),
    priv: Buffer.from(priv.subarray(priv.length - 32)).toString("hex"),
  };
}

// A real onion identity: its v3 address is exactly its ed25519 key, and we hold the seed so we
// can sign a live announce with onion control.
function mintOnion() {
  const k = newEd25519();
  return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, seed: k.priv };
}

const strip = (o) => String(o).replace(/\.onion$/, "");

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-verify-stake-"));
  try {
    const signer = newEd25519();

    // --- four gateways -------------------------------------------------------
    //   gValid   : honest staked gateway — valid operator sig, operator IS staked.
    //   gBadSig  : bootnode labels it staked, but the stored announce's operator sig is INVALID
    //              (signed by a stranger, not the claimed operator — the bootnode lied about the pairing).
    //   gLapsed  : valid operator sig, but the operator's stake has LAPSED (isStaked=false).
    //   gPlain   : onion-only entry, no operator label — not claiming stake, nothing to re-verify.
    const gValid = mintOnion();
    const gBadSig = mintOnion();
    const gLapsed = mintOnion();
    const gPlain = mintOnion();

    const wValid = ethers.Wallet.createRandom();
    const wLapsed = ethers.Wallet.createRandom();
    const wStranger = ethers.Wallet.createRandom();

    // Real announces the bootnode would have STORED and serve from GET /gateway/<onion>.
    const validSig = await wValid.signMessage(operatorAuthMessage(gValid.onion, wValid.address));
    const annValid = buildAnnounce({ onion: gValid.onion, weight: 100, onionSeedHex: gValid.seed, operator: wValid.address, operatorSig: validSig });

    // gBadSig: operator field claims wValid... no — claim a fresh operator but sign with a stranger.
    const claimedOp = ethers.Wallet.createRandom().address;
    const strangerSig = await wStranger.signMessage(operatorAuthMessage(gBadSig.onion, claimedOp)); // recovers to wStranger, not claimedOp
    const annBadSig = buildAnnounce({ onion: gBadSig.onion, weight: 100, onionSeedHex: gBadSig.seed, operator: claimedOp, operatorSig: strangerSig });

    const lapsedSig = await wLapsed.signMessage(operatorAuthMessage(gLapsed.onion, wLapsed.address));
    const annLapsed = buildAnnounce({ onion: gLapsed.onion, weight: 100, onionSeedHex: gLapsed.seed, operator: wLapsed.address, operatorSig: lapsedSig });

    // The bootnode's served directory (labels included). gBadSig / gLapsed carry a staked:true LABEL
    // the client must not trust; the announces above tell the real story.
    const gateways = [
      { onion: gValid.onion, pubkey: gValid.pubkey, weight: 100, health: "up", operator: wValid.address.toLowerCase(), staked: true },
      { onion: gBadSig.onion, pubkey: gBadSig.pubkey, weight: 100, health: "up", operator: claimedOp.toLowerCase(), staked: true },
      { onion: gLapsed.onion, pubkey: gLapsed.pubkey, weight: 100, health: "up", operator: wLapsed.address.toLowerCase(), staked: true },
      { onion: gPlain.onion, pubkey: gPlain.pubkey, weight: 100, health: "up" },
    ];
    const signed = signDirectory({ version: 1, issued: Math.floor(Date.now() / 1000), gateways, signer: signer.pub }, signer.priv);
    const dirFile = join(work, "directory.signed.json");
    await writeFile(dirFile, JSON.stringify(signed, null, 2) + "\n");

    // In-memory GET /gateway/<onion>: the stored announce, keyed by normalized onion.
    const store = new Map([
      [strip(gValid.onion), annValid],
      [strip(gBadSig.onion), annBadSig],
      [strip(gLapsed.onion), annLapsed],
      // gPlain has no announce here; it must never be fetched (no operator label => not re-verified).
    ]);
    let fetched = 0;
    const injectedFetch = async (onion) => {
      fetched++;
      const rec = store.get(strip(onion));
      if (!rec) throw new Error("not-found");
      return rec;
    };
    // Mock stake: only wValid is staked right now (wLapsed lapsed; claimedOp never staked).
    const stakedSet = new Set([wValid.address.toLowerCase()]);
    const injectedStake = { isStaked: async (op) => stakedSet.has(String(op).toLowerCase()) };

    // --- import selection.mjs with the env it reads AT IMPORT TIME -----------
    process.env.SHADE_TREE_DIRECTORY = dirFile;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    process.env.SHADE_TREE_VERIFY_STAKE = "1";
    delete process.env.SHADE_TREE_BOOTNODE_ONION; // static-file source, not live discovery
    const sel = await import(pathToFileURL(SELECTION_PATH).href);
    sel.setVerifyDeps({ fetchAnnounce: injectedFetch, stake: injectedStake });

    console.log("flag + wiring:");
    ok(sel.verifyStakeEnabled() === true, "SHADE_TREE_VERIFY_STAKE=1 arms client-side re-verification");
    ok(sel.directoryEnabled() === true, "directory mode is on (file + pinned signer)");

    // --- (a)/(b)/(c): reverifyGateway on each entry, deps injected -----------
    console.log("\nreverifyGateway (per-entry, injected fetch + stake):");
    const rValid = await sel.reverifyGateway(gateways[0]);
    ok(rValid.ok === true, "(a) valid operator sig AND isStaked=true is KEPT");

    const rBadSig = await sel.reverifyGateway(gateways[1]);
    ok(rBadSig.ok === false, "(b) bootnode-labeled-staked but INVALID operator sig is DROPPED");
    ok(rBadSig.reason === "bad-operator-sig", `    ...dropped for the right reason (${rBadSig.reason})`);

    const rLapsed = await sel.reverifyGateway(gateways[2]);
    ok(rLapsed.ok === false, "(c) operator stake LAPSED (isStaked=false) is DROPPED");
    ok(rLapsed.reason === "not-staked", `    ...dropped for the right reason (${rLapsed.reason})`);

    const rPlain = await sel.reverifyGateway(gateways[3]);
    ok(rPlain.ok === true, "onion-only entry (no operator) needs no re-verification (passes through)");

    // A bootnode that returns a valid announce for a DIFFERENT onion must not satisfy re-verify.
    const rMismatch = await sel.reverifyGateway(gateways[0], { fetchAnnounce: async () => annLapsed });
    ok(rMismatch.ok === false && rMismatch.reason === "announce-onion-mismatch", "an announce for a different onion is rejected (onion binding)");

    // --- end-to-end: selectCandidates drops the unverifiable, keeps the rest -
    console.log("\nselectCandidates (flag ON, full filter):");
    const cands = await sel.selectCandidates();
    const got = new Set(cands.map((c) => c.onion));
    ok(got.has(strip(gValid.onion)), "the honest staked gateway is offered");
    ok(got.has(strip(gPlain.onion)), "the onion-only gateway is offered");
    ok(!got.has(strip(gBadSig.onion)), "the invalid-operator-sig gateway is NOT offered");
    ok(!got.has(strip(gLapsed.onion)), "the stake-lapsed gateway is NOT offered");
    ok(got.size === 2, `exactly the two legitimate gateways survive (${got.size}/2)`);
    ok(fetched > 0, "re-verification actually fetched stored announces (did not trust the label)");

    // --- (d): flag OFF -> no re-verification (label trusted, matching today) --
    // Separate process so the module re-reads env with the flag off. It injects a fetch that
    // THROWS if called, so the staked-labeled gateway surviving proves no re-verification ran.
    console.log("\nflag OFF (separate process): label trusted, no re-verification");
    const dirOffFile = join(work, "directory.off.json");
    // A directory whose sole staked-labeled entry WOULD be dropped if re-verified (gLapsed).
    const offSigned = signDirectory(
      { version: 1, issued: Math.floor(Date.now() / 1000), gateways: [gateways[2]], signer: signer.pub },
      signer.priv
    );
    await writeFile(dirOffFile, JSON.stringify(offSigned, null, 2) + "\n");

    const script = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
sel.setVerifyDeps({
  fetchAnnounce: () => { throw new Error("FETCH-CALLED: re-verification ran with the flag OFF"); },
  stake: { isStaked: async () => false },
});
try {
  const cands = await sel.selectCandidates();
  console.log("ONIONS:" + cands.map((c) => c.onion).join(","));
  console.log("ENABLED:" + sel.verifyStakeEnabled());
  process.exit(0);
} catch (e) {
  console.error("ERR:" + e.message);
  process.exit(3);
}`;
    let offCode = 0, offOut = "";
    try {
      offOut = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        encoding: "utf8",
        env: { ...process.env, SHADE_TREE_DIRECTORY: dirOffFile, SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_VERIFY_STAKE: "", SHADE_TREE_BOOTNODE_ONION: "" },
      });
    } catch (e) {
      offCode = e.status ?? 1;
      offOut = (e.stdout || "") + (e.stderr || "");
    }
    ok(offCode === 0, "flag-OFF selectCandidates succeeds without ever fetching an announce");
    ok(/ENABLED:false/.test(offOut), "verifyStakeEnabled() is false in the flag-OFF process");
    ok(new RegExp("ONIONS:.*" + strip(gLapsed.onion)).test(offOut), "(d) the staked-labeled gateway is offered on the label alone (today's behavior)");
    ok(!/FETCH-CALLED/.test(offOut), "no announce fetch happened with the flag off");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: verify-stake selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
