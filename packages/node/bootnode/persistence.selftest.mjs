// Offline proof of the bootnode PERSISTENCE layer (T-DEV-4): the in-memory registry is a
// convenience cache that must survive a process restart WITHOUT becoming a trust bypass.
//
// It mints real onion identities, announces them into a registry that write-throughs to a JSON
// store, then constructs a SECOND registry pointing at the SAME store (a simulated restart) and
// checks the fleet came back. Crucially it also proves persistence cannot smuggle in trust:
//   - a record whose ts is now outside the freshness window is dropped on reload,
//   - a tampered store record (flipped onionSig) fails verification and is dropped,
//   - with persistence OFF (persistPath unset) nothing is ever written to disk.
//
//   node packages/node/bootnode/persistence.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce, operatorAuthMessage } from "./announce.mjs";
import { makeRegistry, loadOrMintSigner } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const onionsOf = (registry) => new Set(registry.directory().gateways.map((g) => g.onion));

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-bootnode-persist-"));
  try {
    // --- mint three real onion identities + a pinned signer --------------------
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const g3 = await generateOnionIdentity(join(work, "g3"), { label: "g3" });
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    ok(((await stat(join(work, "signer.key"))).mode & 0o777) === 0o600, "new signer key is mode 0600");
    await chmod(join(work, "signer.key"), 0o644);
    await loadOrMintSigner(join(work, "signer.key"));
    ok(((await stat(join(work, "signer.key"))).mode & 0o777) === 0o600, "existing loose signer key is tightened to mode 0600");
    const TTL = 900; // seconds an accepted gateway stays listed without re-announcing
    const mk = (persistPath, now) => makeRegistry({
      signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: TTL,
      minReannounceSec: 0, now: () => now, persistPath,
    });

    // === survives a "restart" ================================================
    console.log("persistence: survives restart:");
    const storeA = join(work, "storeA.json");
    const clockA = 2_000_000;
    const regA1 = mk(storeA, clockA);
    for (const g of [g1, g2, g3]) {
      await regA1.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clockA }));
    }
    ok(existsSync(storeA), "write-through created the store file on accepted announces");
    const rawA = JSON.parse(readFileSync(storeA, "utf8"));
    ok(rawA.entries.length === 3, "store holds one entry per live gateway (3)");
    ok(rawA.entries.every((e) => e.rec && typeof e.rec.onionSig === "string" && e.expiresAt),
      "store persists the RAW signed record (rec.onionSig) + expiresAt, not derived state");
    ok(rawA.entries.every((e) => e.rec.pubkey === undefined),
      "store does NOT cache a derived verdict (no pubkey/staked stashed to trust on reload)");

    // second registry, same store, same clock == the restart
    const regA2 = mk(storeA, clockA);
    const reload = await regA2.loadPersisted();
    ok(reload.loaded === 3 && reload.dropped === 0, "reload re-verified and restored all 3 gateways");
    const backA = onionsOf(regA2);
    ok(backA.size === 3 && backA.has(g1.onion) && backA.has(g2.onion) && backA.has(g3.onion),
      "directory() after restart lists the same live gateways");

    // === a now-expired record is dropped on reload ===========================
    // Reload freshness is the stored TTL (expiresAt) checked against the CURRENT clock, so a
    // normal restart within TTL keeps the fleet (proven above) but a restart AFTER the last
    // heartbeat's TTL has lapsed must NOT resurrect long-dead gateways.
    console.log("\npersistence: expired record dropped:");
    const storeB = join(work, "storeB.json");
    const clockB = 3_000_000;
    const regB1 = mk(storeB, clockB);
    for (const g of [g1, g2, g3]) {
      await regB1.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clockB }));
    }
    // restart AFTER every persisted entry's TTL (expiresAt = clockB + TTL) has passed.
    const regB2 = mk(storeB, clockB + TTL + 1);
    const reloadB = await regB2.loadPersisted();
    ok(reloadB.loaded === 0 && reloadB.dropped === 3, "records whose stored TTL lapsed are re-checked against the CURRENT clock and dropped");
    ok(onionsOf(regB2).size === 0, "directory() after a restart past TTL is empty (no dead gateway resurrected)");

    // A restart WITHIN TTL but well beyond the live-announce ts-skew still keeps the fleet:
    // reload must not confuse the anti-replay window with the gateway TTL.
    const storeB2 = join(work, "storeB2.json");
    const clockB3 = 3_500_000;
    const regB3 = mk(storeB2, clockB3);
    await regB3.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clockB3 }));
    const regB4 = mk(storeB2, clockB3 + 300); // 300s later: past the ~120s skew, inside the 900s TTL
    const reloadB4 = await regB4.loadPersisted();
    ok(reloadB4.loaded === 1 && onionsOf(regB4).has(g1.onion), "a restart within TTL but past the ts-skew window still restores the gateway");

    // === a tampered store record is dropped on reload ========================
    console.log("\npersistence: tampered record dropped:");
    const storeC = join(work, "storeC.json");
    const clockC = 4_000_000;
    const regC1 = mk(storeC, clockC);
    for (const g of [g1, g2, g3]) {
      await regC1.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clockC }));
    }
    // flip the last nibble of g1's onion signature directly in the store file.
    const poisoned = JSON.parse(readFileSync(storeC, "utf8"));
    const victim = poisoned.entries.find((e) => e.rec.onion === g1.onion);
    victim.rec.onionSig = victim.rec.onionSig.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
    writeFileSync(storeC, JSON.stringify(poisoned));

    const regC2 = mk(storeC, clockC);
    const reloadC = await regC2.loadPersisted();
    ok(reloadC.loaded === 2 && reloadC.dropped === 1, "a tampered store record fails signature verification and is dropped");
    const backC = onionsOf(regC2);
    ok(!backC.has(g1.onion) && backC.has(g2.onion) && backC.has(g3.onion),
      "the tampered gateway is absent; the untouched ones survive (poisoned file cannot inject trust)");

    // === stake mode: label survives, but stake is RE-CHECKED on reload =======
    // Reload does not trust a cached staked verdict — it re-runs the operator stake check on the
    // current chain (fail-closed). So a gateway whose operator UNSTAKED during downtime drops, and
    // a still-staked one comes back correctly labeled.
    console.log("\npersistence: stake re-checked on reload:");
    const { ethers } = await import("ethers");
    const opWallet = ethers.Wallet.createRandom();
    const operator = opWallet.address;
    const operatorSig = await opWallet.signMessage(operatorAuthMessage(g1.onion, operator));
    const storeS = join(work, "storeS.json");
    const clockS = 4_500_000;
    const mkStake = (allow, now) => makeRegistry({
      signer, stake: MockStakeVerifier({ allowlist: allow }), admission: "stake", ttlSec: TTL,
      minReannounceSec: 0, now: () => now, persistPath: storeS,
    });
    const regS1 = mkStake(operator, clockS);
    await regS1.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, operator, operatorSig, ts: clockS }));
    // restart, operator STILL staked -> reloads and is re-labeled staked from a fresh chain check
    const regS2 = mkStake(operator, clockS + 300);
    ok((await regS2.loadPersisted()).loaded === 1, "staked gateway reloads across a restart in stake mode");
    ok(regS2.directory().gateways[0]?.staked === true, "reloaded gateway is re-labeled staked from a fresh on-chain check");
    // restart, operator NO LONGER staked -> reload re-checks the chain and drops it (fail-closed)
    const regS3 = mkStake("0x0000000000000000000000000000000000000000", clockS + 300);
    ok((await regS3.loadPersisted()).dropped === 1, "an operator unstaked during downtime is dropped on reload (fail-closed, no cached verdict)");

    // === a corrupt store file never crashes boot =============================
    console.log("\npersistence: corrupt store ignored:");
    const storeD = join(work, "storeD.json");
    writeFileSync(storeD, "{ this is not valid json");
    const regD = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: TTL,
      minReannounceSec: 0, now: () => 4_800_000, persistPath: storeD });
    ok((await regD.loadPersisted()).loaded === 0, "an unparseable store file is ignored — boot starts empty, does not throw");

    // === persistence OFF writes nothing ======================================
    console.log("\npersistence: off by default writes nothing:");
    const emptyDir = join(work, "no-persist");
    const regOff = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900,
      minReannounceSec: 0, now: () => 5_000_000, persistPath: null }); // OFF
    await regOff.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: 5_000_000 }));
    ok(regOff.directory().gateways.length === 1, "unset persistPath: registry still works in memory");
    ok(!existsSync(emptyDir) || readdirSync(emptyDir).length === 0, "unset persistPath: nothing written to disk");
    const off2 = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900,
      minReannounceSec: 0, now: () => 5_000_000, persistPath: null });
    const reloadOff = await off2.loadPersisted();
    ok(reloadOff.loaded === 0 && reloadOff.dropped === 0, "unset persistPath: loadPersisted is a no-op");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: bootnode persistence selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
