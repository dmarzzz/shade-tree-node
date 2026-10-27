// Self-verifying canopy entries in the Proxy client (WIRE-SPEC 4.5, discovery v1 step 3). Every
// Elder Tree is asked, every entry that carries the node's own announce is checked and rebuilt
// from it, and the verified canopies are unioned with the newest announce winning.
//
//   node packages/node/client/canopy-merge.selftest.mjs

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { pubkeyToOnion, signDirectory } from "../lib/directory.mjs";
import { buildAnnounce } from "../bootnode/announce.mjs";

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else { console.log(`  FAIL ${message}`); failures++; }
};

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION = join(HERE, "selection.mjs");
const ELDERS = ["elder-one", "elder-two"];

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return { pub: pub.subarray(pub.length - 32).toString("hex"), priv: priv.subarray(priv.length - 32).toString("hex") };
}

function node() {
  const key = keypair();
  return { ...key, onion: pubkeyToOnion(key.pub) };
}

// A listed entry carrying the node's announce, the way an Elder serves it.
function listed(n, { ts, region, weight = 100 }) {
  const announce = buildAnnounce({ onion: n.onion, weight, onionSeedHex: n.priv, ts, caps: { ports: [443], region } });
  return { onion: n.onion, pubkey: n.pub, weight, health: "up", caps: announce.caps, capsSig: announce.capsSig, announce };
}

const legacy = (n) => ({ onion: n.onion, pubkey: n.pub, weight: 100, health: "up" });
const canopy = (signer, issued, gateways) => signDirectory({ version: 1, issued, gateways, signer: signer.pub }, signer.priv);
const onions = (candidates) => new Set(candidates.map((c) => `${c.onion}.onion`));

async function loadSelection(tag, work, signers, cache) {
  delete process.env.SHADE_TREE_NETWORK;
  delete process.env.SHADE_TREE_DIRECTORY;
  process.env.SHADE_TREE_DIR_SIGNER = signers;
  process.env.SHADE_TREE_BOOTNODE_ONION = ELDERS[0];
  process.env.SHADE_TREE_BOOTNODE_ONIONS = ELDERS.join(",");
  process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0";
  process.env.SHADE_TREE_DIRECTORY_CACHE = cache || join(work, `${tag}.lkg.json`);
  process.env.SHADE_TREE_HEALTH_CACHE = join(work, `${tag}.health.json`);
  process.env.SHADE_TREE_RECEIPT_SCORING = "0";
  return import(pathToFileURL(SELECTION).href + `?canopy-merge=${tag}-${Date.now()}`);
}

async function rejects(fn) {
  try { await fn(); return false; } catch { return true; }
}

async function main() {
  const work = mkdtempSync(join(tmpdir(), "shade-tree-canopy-merge-"));
  try {
    const a = keypair();
    const b = keypair();
    const pins = `${a.pub},${b.pub}`;
    const now = Math.floor(Date.now() / 1000);
    const [x, y, z, w, v] = [node(), node(), node(), node(), node()];

    console.log("union of every Elder, checked per entry:");
    const tampered = listed(z, { ts: now, region: "eu" });
    tampered.announce = { ...tampered.announce, weight: 999 };
    const canopyA = canopy(a, now, [listed(x, { ts: now - 100, region: "na" }), legacy(y)]);
    const canopyB = canopy(b, now - 10, [listed(x, { ts: now - 10, region: "eu" }), tampered, listed(w, { ts: now - 1000, region: "eu" })]);
    const sel = await loadSelection("union", work, pins);
    const asked = [];
    sel._setCanopyFetch(async (elder) => { asked.push(elder); return elder === ELDERS[0] ? canopyA : canopyB; });
    const all = onions(await sel.selectCandidates());
    ok(asked.join() === ELDERS.join(), "both Elders are asked");
    ok(all.size === 2 && all.has(x.onion) && all.has(y.onion), "the union keeps the node both list and the legacy entry");
    ok(!all.has(z.onion), "an entry whose announce was tampered with is dropped, the rest of its canopy kept");
    ok(!all.has(w.onion), "an entry whose announce expired is dropped");
    const eu = onions(await sel.selectCandidates({ region: "eu" }));
    ok(eu.size === 1 && eu.has(x.onion), "the node listed twice carries its newest announce, from the older canopy");
    ok(await rejects(() => sel.selectCandidates({ region: "na" })), "its older announce is not used");

    console.log("\nrollback floor per Elder:");
    const floors = await loadSelection("floors", work, pins);
    let answers = { [ELDERS[0]]: canopy(a, now, [legacy(y)]), [ELDERS[1]]: canopy(b, now - 50, [legacy(x)]) };
    floors._setCanopyFetch(async (elder) => { const doc = answers[elder]; if (!doc) throw new Error("socks: unreachable"); return doc; });
    ok(onions(await floors.selectCandidates()).size === 2, "both Elders' canopies are used");
    answers = { [ELDERS[1]]: canopy(b, now - 40, [legacy(v)]) };
    const second = onions(await floors.selectCandidates());
    ok(second.size === 1 && second.has(v.onion), "an older-issued Elder is not a rollback while the newer Elder is down");
    answers = { [ELDERS[1]]: canopy(b, now - 45, [legacy(w)]) };
    const third = onions(await floors.selectCandidates());
    ok(!third.has(w.onion) && third.has(v.onion), "the same Elder moving its issued backward is refused");

    console.log("\nlast-known-good cache:");
    const cache = join(work, "cache.lkg.json");
    const writer = await loadSelection("cache-write", work, pins, cache);
    writer._setCanopyFetch(async (elder) => (elder === ELDERS[0] ? canopyA : canopyB));
    await writer.selectCandidates();
    const written = JSON.parse(readFileSync(cache, "utf8"));
    ok(Array.isArray(written.canopies) && written.canopies.length === 2, "the cache holds every Elder's signed canopy");
    writeFileSync(cache, JSON.stringify({ canopies: [canopy(a, now - 5000, [listed(v, { ts: now - 5000, region: "eu" })])] }));
    const reader = await loadSelection("cache-read", work, pins, cache);
    reader._setCanopyFetch(async () => { throw new Error("socks: timeout"); });
    const cached = onions(await reader.selectCandidates());
    ok(cached.size === 1 && cached.has(v.onion), "with every Elder down, cached entries outlive their announces");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: canopy merge selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => { console.error(error); process.exit(1); });
