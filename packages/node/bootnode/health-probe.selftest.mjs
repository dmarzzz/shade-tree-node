// Active bootnode health probing (T-DEV-12): directory() defaults every announced-within-TTL
// gateway to health:"up", so a gateway that announced then silently DIED still shows up:"up" until
// TTL. OPTIONAL active probing lets the bootnode dial each live onion itself and DEMOTE a
// silently-dead one to health:"down" sooner (still listed -- TTL, not the probe, governs removal --
// just deprioritized by the client's pickGateway). This test drives the real makeRegistry with an
// INJECTED probe(onion)->bool + an INJECTED clock (no Tor), announces a couple of real onion
// identities, and asserts:
//   - probing OFF (default, no prober) => every live entry is "up" (today's behavior, unchanged)
//   - a gateway whose probe returns false N times is demoted to health:"down" in directory()
//   - a probe returning true keeps a healthy one up, and RESTORES a demoted one to up (recover)
//   - a probe that THROWS is treated as a fail (fail-closed to down), never crashing the cycle
//   - the per-onion fail-counter state is BOUNDED: swept with the live set when a gateway TTLs out
//
//   node packages/node/bootnode/health-probe.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce } from "./announce.mjs";
import { makeRegistry, makeProber, makeProbeHealth } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";
import { loadOrMintSigner } from "./server.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// health label for a given onion in the CURRENT signed directory (or undefined if not listed).
const healthOf = (registry, onion) => registry.directory().gateways.find((g) => g.onion === onion)?.health;

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-health-probe-"));
  try {
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const signer = await loadOrMintSigner(join(work, "signer.key"));

    // Injected clock (seconds), shared by the registry and the announce timestamps.
    let clock = Math.floor(Date.now() / 1000);
    const ttlSec = 900;

    // Injected probe: a per-onion verdict table the test flips at will. Default reachable (true);
    // set false to simulate a dead onion, or "throw" to simulate a dial that blows up.
    const verdict = new Map(); // onion -> true | false | "throw"
    const probe = async (onion) => {
      const v = verdict.get(onion);
      if (v === "throw") throw new Error("simulated dial failure");
      return v !== false; // default true
    };

    const FAILS = 3; // demote after 3 consecutive failed probes

    // -----------------------------------------------------------------------
    // (1) Probing OFF (default): no prober => every live entry is "up".
    // -----------------------------------------------------------------------
    console.log("probing OFF (default) => all live entries up:");
    const off = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec, minReannounceSec: 0, now: () => clock });
    ok((await off.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }))).ok, "announce g1 accepted (probing-off registry)");
    ok((await off.announce(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }))).ok, "announce g2 accepted (probing-off registry)");
    const offDir = off.directory();
    ok(offDir.gateways.length === 2 && offDir.gateways.every((g) => g.health === "up"), "with no prober, every live gateway is health:up (unchanged behavior)");

    // -----------------------------------------------------------------------
    // Build a probing-ON registry sharing the injected clock + probe.
    // -----------------------------------------------------------------------
    const health = makeProbeHealth({ failThreshold: FAILS, now: () => clock * 1000 });
    let registry; // prober lists onions from the registry we build just below
    const prober = makeProber({ probe, health, listOnions: () => registry.liveOnions() });
    registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec, minReannounceSec: 0, now: () => clock, prober });

    ok((await registry.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }))).ok, "announce g1 accepted (probing-on registry)");
    ok((await registry.announce(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }))).ok, "announce g2 accepted (probing-on registry)");

    // Before any probe, both are up (never probed == no failures).
    console.log("\nbefore probing, both up:");
    ok(healthOf(registry, g1.onion) === "up" && healthOf(registry, g2.onion) === "up", "both gateways start health:up");

    // -----------------------------------------------------------------------
    // (2) g1 fails N probes => demoted to health:"down"; g2 keeps passing => up.
    // -----------------------------------------------------------------------
    console.log("\ng1 fails N probes => down; g2 stays up:");
    verdict.set(g1.onion, false); // g1's onion is now unreachable
    verdict.set(g2.onion, true);
    for (let i = 1; i < FAILS; i++) {
      await prober.runCycle();
      ok(healthOf(registry, g1.onion) === "up", `after ${i} failed probe(s) (< N=${FAILS}) g1 is still up (not demoted early)`);
    }
    await prober.runCycle(); // the Nth failure
    ok(healthOf(registry, g1.onion) === "down", `after N=${FAILS} consecutive failed probes g1 is demoted to health:down`);
    ok(healthOf(registry, g2.onion) === "up", "g2 (still reachable) stays health:up");
    // Demoted != removed: g1 is still LISTED in the directory (TTL governs removal, not the probe).
    ok(registry.directory().gateways.some((g) => g.onion === g1.onion), "demoted g1 is still LISTED in the directory (deprioritized, not removed)");

    // -----------------------------------------------------------------------
    // (3) g1 becomes reachable again => a single successful probe RESTORES up.
    // -----------------------------------------------------------------------
    console.log("\ng1 recovers on a successful probe:");
    verdict.set(g1.onion, true);
    await prober.runCycle();
    ok(healthOf(registry, g1.onion) === "up", "one successful probe restores g1 to health:up (recover on success)");
    ok(health.fails(g1.onion) === 0, "recovery clears g1's fail counter to 0");

    // -----------------------------------------------------------------------
    // (4) A probe that THROWS is a fail (fail-closed to down), not a crash.
    // -----------------------------------------------------------------------
    console.log("\na throwing probe is treated as a fail (fail-closed), never crashes the cycle:");
    verdict.set(g1.onion, "throw");
    verdict.set(g2.onion, true); // g2 keeps passing -- one bad onion must not abort the whole cycle
    for (let i = 0; i < FAILS; i++) await prober.runCycle();
    ok(healthOf(registry, g1.onion) === "down", "N throwing probes demote g1 to down (fail-closed)");
    ok(healthOf(registry, g2.onion) === "up", "g2 still probed + kept up in the same cycle (a throw on g1 didn't abort it)");

    // -----------------------------------------------------------------------
    // (5) Fail-counter state is BOUNDED: swept with the live set on TTL-out.
    // -----------------------------------------------------------------------
    console.log("\nfail-counter state is bounded (swept when a gateway TTLs out):");
    ok(health.size() >= 1, "g1's fail counter is currently resident (it is demoted)");
    // Advance past the TTL and re-announce ONLY g2, so g1 expires on the next sweep.
    clock += ttlSec + 1;
    ok((await registry.announce(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }))).ok, "re-announce g2 (kept live); g1 left to expire");
    registry.sweep(); // evicts g1 AND retains only live onions in the health map
    ok(!registry.liveOnions().includes(g1.onion), "g1 has TTL'd out of the live set");
    ok(health.fails(g1.onion) === 0 && health.size() === 0, "g1's fail counter was swept with it -- probe state never outlives the gateway");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: health-probe selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
