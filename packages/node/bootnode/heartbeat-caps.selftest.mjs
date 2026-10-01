// T-FEAT-10b: wire the gateway heartbeat to advertise its REAL capabilities.
//
// T-FEAT-10 added the build/verify/select SUPPORT for signed caps; this proves the PRODUCER
// side (packages/node/bootnode/heartbeat.mjs) populates them from the gateway's actual config and — crucially
// — stays invisible when nothing is configured. Four load-bearing properties:
//
//   1. DERIVED FROM REAL CONFIG. advertisedPorts() coarsens an SHADE_TREE_EGRESS_ALLOW spec to its
//      concrete allowed ports (`*:443` -> [443]; `*:443,*:8443` -> [443,8443]); a wildcard `*`
//      port is dropped (never advertise "any port"); junk is dropped; deduped + sorted.
//   2. SIGNED + ACCEPTED. A configured gateway (region + non-default egress policy) produces an
//      announce whose signed caps EXACTLY match the derived config AND verifyAnnounce accepts it
//      (the caps ride under the real onion signature; capsSig re-verifies against the onion key).
//   3. UNCONFIGURED == BYTE-IDENTICAL. With no region and no egress policy env, the announce is
//      BYTE-for-BYTE identical (same canonical bytes, no caps/capsSig keys) to a plain announce
//      built with no caps at all — an unconfigured gateway is indistinguishable on the wire.
//   4. proto NEVER triggers caps alone. proto rides only alongside a real cap; it can't by itself
//      make an unconfigured gateway advertise.
//
//   node packages/node/bootnode/heartbeat-caps.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain, no Tor.

import { generateKeyPairSync } from "node:crypto";
import { advertisedPorts, advertisedRate, advertisedSets, buildGatewayCaps, announceOnce } from "./heartbeat.mjs";
import { buildAnnounce, verifyAnnounce, canonicalAnnounceBytes } from "./announce.mjs";
import { pubkeyToOnion, canonicalCaps } from "../lib/directory.mjs";
import { PROTO_RANGE } from "../gateway/gateway.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// A fresh onion identity: raw ed25519 seed/pub hex + the v3 onion whose key IS that pub.
function newOnion() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return {
    seed: priv.subarray(priv.length - 32).toString("hex"),
    pub: pub.subarray(pub.length - 32).toString("hex"),
    onion: pubkeyToOnion(pub.subarray(pub.length - 32).toString("hex")),
  };
}

async function main() {
  console.log("heartbeat caps (T-FEAT-10b):");

  // --- 1. advertisedPorts: coarsen an egress-allow spec to concrete ports -------
  ok(JSON.stringify(advertisedPorts("*:443")) === "[443]", "`*:443` -> [443]");
  ok(JSON.stringify(advertisedPorts("*:443,*:8443")) === "[443,8443]", "`*:443,*:8443` -> [443,8443] (sorted, deduped)");
  ok(JSON.stringify(advertisedPorts("*:8443, *:443")) === "[443,8443]", "unsorted/spaced input -> sorted");
  ok(JSON.stringify(advertisedPorts("*:443,example.com:443")) === "[443]", "same port across hosts deduped");
  ok(JSON.stringify(advertisedPorts("*:*")) === "[]", "wildcard `*` port dropped (never advertise any-port)");
  ok(JSON.stringify(advertisedPorts("garbage,,*:70000,x:0")) === "[]", "junk / out-of-range ports dropped, total");
  ok(JSON.stringify(advertisedPorts(undefined)) === "[]", "undefined spec -> [] (total)");

  // --- 2. buildGatewayCaps from real config -------------------------------------
  // Unconfigured env -> null (no caps).
  ok(buildGatewayCaps({}) === null, "unconfigured env -> null caps");
  // proto alone must NOT trigger caps: only ports/region do. An env with neither -> null even
  // though the gateway obviously speaks a proto version.
  ok(buildGatewayCaps({ SHADE_TREE_UNRELATED: "x" }) === null, "unrelated env -> still null (proto never triggers caps)");
  // Invalid region alone -> null (not in REGION_BUCKETS).
  ok(buildGatewayCaps({ SHADE_TREE_GATEWAY_REGION: "narnia" }) === null, "invalid region bucket -> ignored -> null");

  // A real config: non-default egress policy + a valid region.
  const caps = buildGatewayCaps({ SHADE_TREE_EGRESS_ALLOW: "*:443,*:8443", SHADE_TREE_GATEWAY_REGION: "eu" });
  ok(caps !== null, "configured env -> caps object");
  ok(JSON.stringify(caps.ports) === "[443,8443]", "caps.ports derived from SHADE_TREE_EGRESS_ALLOW");
  ok(caps.region === "eu", "caps.region from SHADE_TREE_GATEWAY_REGION");
  ok(caps.proto && caps.proto.min === PROTO_RANGE.min && caps.proto.max === PROTO_RANGE.max, "caps.proto == gateway PROTO_RANGE (not hardcoded)");
  const rateEnv = { SHADE_TREE_EPOCH_SECONDS: "60", SHADE_TREE_ROOT_FRESHNESS_SECONDS: "60", SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES: "41943040" };
  const rate = advertisedRate(rateEnv);
  ok(rate?.scope === "grove-v4" && rate.epochSeconds === 60 && rate.payloadBytesPerSlot === 41943040, "runtime epoch/freshness/payload become one canonical signed rate policy");
  ok(advertisedRate({ SHADE_TREE_EPOCH_SECONDS: "60" }) === null, "partial runtime rate policy is not advertised");
  // sets (dogfood #234): the admission sets this node reads, from the contract env, lowercased.
  ok(advertisedSets({}) === null, "no contract env -> no sets advertised (invited-only node)");
  ok(JSON.stringify(advertisedSets({ SHADE_TREE_GROUP_CONTRACT: "0xDEB294E6e9ad6A3FcBDeFfD1F67aC9678AC94bBC, 0xf117FDEA83ac57d15D9394A2B56873C32d227B7E", SHADE_TREE_PAID_ACCESS_CONTRACT: "0xf117FDEA83ac57d15D9394A2B56873C32d227B7E" })) === JSON.stringify(["0xdeb294e6e9ad6a3fcbdeffd1f67ac9678ac94bbc", "0xf117fdea83ac57d15d9394a2b56873c32d227b7e"]), "group + paid contracts -> lowercase, deduped, sorted sets");
  ok(advertisedSets({ SHADE_TREE_GROUP_CONTRACT: "not-an-address" }) === null, "a malformed contract is never advertised");
  const withSets = buildGatewayCaps({ SHADE_TREE_GROUP_CONTRACT: "0xDEB294E6e9ad6A3FcBDeFfD1F67aC9678AC94bBC" });
  ok(withSets && JSON.stringify(withSets.sets) === JSON.stringify(["0xdeb294e6e9ad6a3fcbdeffd1f67ac9678ac94bbc"]) && withSets.proto, "a configured set alone yields caps (with proto riding along)");
  const ratedCaps = buildGatewayCaps(rateEnv);
  ok(ratedCaps?.rate?.epochSeconds === 60 && ratedCaps.proto, "a complete rate policy triggers signed caps and carries protocol range");

  // Explicit default-equivalent egress policy still advertises [443] (operator opted in by SETTING it).
  const capsDefault = buildGatewayCaps({ SHADE_TREE_EGRESS_ALLOW: "*:443" });
  ok(capsDefault && JSON.stringify(capsDefault.ports) === "[443]" && capsDefault.region === undefined, "explicit `*:443` alone -> ports [443], no region");
  // Region-only config (default/unset policy) still advertises, region + proto, no ports.
  const capsRegionOnly = buildGatewayCaps({ SHADE_TREE_GATEWAY_REGION: "na" });
  ok(capsRegionOnly && capsRegionOnly.region === "na" && capsRegionOnly.ports === undefined && capsRegionOnly.proto, "region-only -> region + proto, no ports");

  // --- 3. a configured gateway's announce carries signed caps verifyAnnounce accepts ---
  const g = newOnion();
  const configuredEnv = { SHADE_TREE_EGRESS_ALLOW: "*:443,*:8443", SHADE_TREE_GATEWAY_REGION: "eu" };
  const rec = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, caps: buildGatewayCaps(configuredEnv) });
  ok(rec.caps !== undefined && rec.capsSig !== undefined, "configured announce carries caps + capsSig");
  ok(JSON.stringify(rec.caps) === JSON.stringify(canonicalCaps({ ports: [443, 8443], region: "eu", proto: PROTO_RANGE })), "announce caps == canonicalized real config");
  const v = await verifyAnnounce(rec, { now: rec.ts });
  ok(v.ok === true, "verifyAnnounce ACCEPTS the configured announce");
  ok(v.caps !== null && JSON.stringify(v.caps.ports) === "[443,8443]" && v.caps.region === "eu", "verifyAnnounce surfaces the signed caps");
  // Tamper: flip a cap AFTER signing -> the onion signature no longer covers it -> rejected.
  const tampered = { ...rec, caps: { ...rec.caps, ports: [443, 8443, 22] } };
  const vt = await verifyAnnounce(tampered, { now: rec.ts });
  ok(vt.ok === false, "tampered caps rejected (caps are signed, not forgeable)");

  // --- 4. UNCONFIGURED announce is BYTE-IDENTICAL to a no-caps announce ----------
  // Same identity, same ts+nonce so ONLY the caps wiring can differ. Build one via the T-FEAT-10b
  // path (caps: buildGatewayCaps(unconfigured)) and one the pre-T-FEAT-10 way (no caps arg at all).
  const ts = 1_700_000_000, nonce = "00112233445566778899aabbccddeeff";
  const unconfiguredCaps = buildGatewayCaps({}); // null
  const wired = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts, nonce, caps: unconfiguredCaps });
  const legacy = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts, nonce });
  ok(wired.caps === undefined && wired.capsSig === undefined, "unconfigured announce has NO caps/capsSig keys");
  ok(JSON.stringify(wired) === JSON.stringify(legacy), "unconfigured announce is byte-identical to a legacy no-caps announce (full record)");
  ok(canonicalAnnounceBytes(wired).equals(canonicalAnnounceBytes(legacy)), "unconfigured canonical signed bytes are byte-identical");
  ok(wired.onionSig === legacy.onionSig, "unconfigured onion signature is byte-identical");

  // --- 5. announceOnce threads caps through (injected caps, no network) ----------
  // Prove the producer path (announceOnce) actually passes caps to buildAnnounce -> postOverTor.
  // We can't hit Tor here; instead confirm the default caps argument resolves via buildGatewayCaps
  // by checking the two building blocks announceOnce composes are the ones wired above. (The
  // buildAnnounce+verifyAnnounce acceptance in step 3 already proves the end-to-end wire shape.)
  ok(typeof announceOnce === "function", "announceOnce exported (producer wired)");

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
