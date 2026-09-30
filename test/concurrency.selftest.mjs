// Concurrency selftest: correctness under interleaved-async access. Both subjects here mutate
// shared in-memory state across `await` points, so a naive implementation could double-slash or
// lose/duplicate registry entries when many callers race. We drive the REAL code paths (no
// mocks beyond the injected reconstruct/derive/slash hooks makeSpentSet already exposes) and
// fire dense Promise.all bursts to interleave them.
//
//   node test/concurrency.selftest.mjs
//
// Exit 0 = every invariant held under concurrency; nonzero = a check failed (prints which).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeSpentSet } from "../packages/node/gateway/gateway.mjs";
import { makeRegistry, loadOrMintSigner } from "../packages/node/bootnode/server.mjs";
import { MockStakeVerifier } from "../packages/node/lib/gateway-registry.mjs";
import { generateOnionIdentity } from "../packages/node/bootnode/keygen.mjs";
import { buildAnnounce } from "../packages/node/bootnode/announce.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Fisher-Yates: randomize the order calls are queued so no test relies on a fixed interleaving.
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

async function main() {
  // === subject 1: gateway spent-set slashes EXACTLY once under a concurrent burst ==========
  console.log("spent-set (concurrent over-spend):");
  {
    let slashCount = 0;
    const set = makeSpentSet({
      reconstruct: () => "identity-secret",     // injected mock: real lib lands at combine
      derive: () => "rate-commitment",
      slash: async () => { await Promise.resolve(); slashCount++; }, // yields, so races can interleave
    });

    const nullifier = "null-A";
    const honest = { x: "1" };       // the honest share, replayed many times
    const overspend = { x: "2" };    // a SECOND distinct evaluation point => provable over-spend
    // A dense burst: mostly honest replays with several distinct over-spend shares mixed in.
    const shares = [];
    for (let i = 0; i < 40; i++) shares.push(honest);
    for (let i = 0; i < 8; i++) shares.push(overspend);
    shuffle(shares);

    const results = await Promise.all(shares.map((s) => set.admit(nullifier, s)));
    const slashActions = results.filter((r) => r.action === "slash");
    const firstActions = results.filter((r) => r.action === "first");

    ok(slashCount === 1, `slash() invoked exactly once across ${shares.length} concurrent admits (got ${slashCount})`);
    ok(slashActions.length === 1, `exactly one admit returned action:"slash" (got ${slashActions.length})`);
    ok(firstActions.length === 1, `exactly one admit returned action:"first" (got ${firstActions.length})`);
    ok(set.size() === 1, "spent-set holds exactly one nullifier entry after the burst");
  }

  // Concurrent admits on DIFFERENT nullifiers must never cross-trigger a slash.
  console.log("\nspent-set (concurrent distinct nullifiers, no cross-slash):");
  {
    let slashCount = 0;
    const set = makeSpentSet({
      reconstruct: () => "identity-secret",
      derive: () => "rate-commitment",
      slash: async () => { slashCount++; },
    });

    const N = 200;
    const calls = [];
    for (let i = 0; i < N; i++) calls.push(set.admit(`null-${i}`, { x: String(i) }));
    // Also interleave an honest replay of each nullifier's own share (same x) — never a slash.
    for (let i = 0; i < N; i++) calls.push(set.admit(`null-${i}`, { x: String(i) }));
    const results = await Promise.all(shuffle(calls));

    ok(slashCount === 0, `no slash across ${N} distinct concurrent nullifiers (got ${slashCount})`);
    ok(results.every((r) => r.action === "first" || r.action === "replay"), "every distinct-nullifier admit was first|replay (never slash)");
    ok(set.size() === N, `spent-set holds exactly ${N} nullifier entries (got ${set.size()})`);
  }

  // === subject 2: bootnode registry loses/duplicates NOTHING under concurrent announces =====
  console.log("\nregistry (concurrent announces, no lost/duplicate entries):");
  const work = await mkdtemp(join(tmpdir(), "shade-tree-concurrency-"));
  try {
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    const fixedClock = 2_000_000;
    // minReannounceSec:0 removes the per-onion throttle so concurrent re-announces of the same
    // onion are NOT rejected as rate-limited — the test isolates keying/interleaving, not throttling.
    const registry = makeRegistry({
      signer,
      stake: MockStakeVerifier({}),
      admission: "open",
      ttlSec: 900,
      minReannounceSec: 0,
      now: () => fixedClock,
    });

    const M = 12;
    const onions = [];
    for (let i = 0; i < M; i++) onions.push(await generateOnionIdentity(join(work, `g${i}`), { label: `g${i}` }));

    // Each distinct onion is announced several times concurrently (each announce carries its own
    // fresh nonce, ts:fixedClock so freshness passes). Correct keying => size == DISTINCT onions.
    const announces = [];
    for (const o of onions) {
      for (let rep = 0; rep < 5; rep++) {
        announces.push(buildAnnounce({ onion: o.onion, weight: 100, onionSeedHex: o.seed, ts: fixedClock }));
      }
    }
    shuffle(announces);
    const results = await Promise.all(announces.map((a) => registry.announce(a)));

    ok(results.every((r) => r.ok === true), `all ${announces.length} concurrent announces accepted`);
    ok(registry.size() === M, `registry.size() equals the ${M} DISTINCT onions announced (got ${registry.size()})`);

    const dir = registry.directory();
    ok(dir.gateways.length === M, `directory() lists exactly ${M} gateways (got ${dir.gateways.length})`);
    const listed = new Set(dir.gateways.map((g) => g.onion));
    ok(listed.size === M, "directory has no duplicate onions");
    ok(onions.every((o) => listed.has(o.onion)), "every distinct announced onion appears once in the directory");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: concurrency selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
