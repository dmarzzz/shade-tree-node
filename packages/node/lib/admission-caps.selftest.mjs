// T-FEAT-9 signed caps `admits` + `pay` (fast lane, no Tor, no chain):
//   - canonicalCaps round-trip: admits deduped in ANONYMITY order (invited > staked > paid), pay
//     normalized (protocol order x402,mpp; lowercased onion/asset; numeric-ascending tier keys), both
//     appended AFTER artifacts; absent => byte-identical to the pre-T-FEAT-9 canonical form;
//   - BOUNDS + ADVERSARIAL: oversized / junk admits and pay (100-entry lists, unknown names, a 9-tier
//     price list, half adverts, huge prices, non-canonical keys) canonicalize to ABSENT, never throw;
//   - signatures: signCaps/verifyCapsSig cover admits+pay; widening a policy (grafting `paid`) or a
//     price breaks the onion-bound capsSig; verifyDirectory rejects the tampered entry;
//   - the bootnode: an announce carrying admits+pay is accepted (bounded by canonicalCaps), the
//     registry passes caps + capsSig THROUGH into the signed /directory (verifyDirectory green), and
//     the delta protocol re-ships an entry whose policy changed in place; payAdvertFromEnv honours
//     SHADE_TREE_PAY_PROTOCOLS;
//   - the heartbeat producer: advertisedAdmits (SHADE_TREE_ADMIT / the SHADE_TREE_ROOTS alias / unset), advertisedPay
//     (+ onion when the registrar rides another onion), buildGatewayCaps stays null when unconfigured.
//
//   node packages/node/lib/admission-caps.selftest.mjs

import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalCaps, canonicalAdmits, canonicalPay, hasCaps, canonicalCapsBytes, signCaps, verifyCapsSig, signDirectory, verifyDirectory, pubkeyToOnion, ADMIT_PATHS, PAY_PROTOCOLS, MAX_CAPS_PAY_TIERS } from "./directory.mjs";
import { buildAnnounce, verifyAnnounce } from "../bootnode/announce.mjs";
import { makeRegistry, loadOrMintSigner, payAdvertFromEnv } from "../bootnode/server.mjs";
import { MockStakeVerifier } from "./gateway-registry.mjs";
import { buildGatewayCaps, advertisedAdmits, advertisedPay } from "../bootnode/heartbeat.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const J = (x) => JSON.stringify(x);

function newOnion() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  const pubHex = pub.subarray(pub.length - 32).toString("hex");
  return { seed: priv.subarray(priv.length - 32).toString("hex"), pub: pubHex, onion: pubkeyToOnion(pubHex) };
}

const ASSET = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const PAY = { protocols: ["mpp", "x402"], port: 8878, asset: ASSET, chain: "eip155:11155111", tiers: { "32": "400000", "8": "100000" } };

async function main() {
  console.log("canonicalCaps admits + pay (round-trip, order, additivity):");
  {
    ok(J(ADMIT_PATHS) === '["invited","staked","paid"]' && J(PAY_PROTOCOLS) === '["x402","mpp"]' && MAX_CAPS_PAY_TIERS === 8, "constants: ADMIT_PATHS anonymity order, PAY_PROTOCOLS order, 8 tiers max");
    ok(J(canonicalAdmits(["paid", "Invited", "paid", "staked"])) === '["invited","staked","paid"]', "canonicalAdmits: dedupe + case + anonymity order");
    ok(J(canonicalAdmits(["onchain", "static"])) === "[]" && J(canonicalAdmits("invited")) === "[]" && J(canonicalAdmits(null)) === "[]", "unknown names / non-array -> [] (dropped)");
    const c = canonicalCaps({ ports: [443], region: "eu", proto: { min: 3, max: 3 }, artifacts: ["rln-aaaaaaaaaaaaaaaa"], admits: ["paid", "invited"], pay: PAY });
    ok(Object.keys(c).join() === "ports,region,proto,artifacts,admits,pay", "fixed field order: ports,region,proto,artifacts,admits,pay (admits/pay appended LAST)");
    ok(J(c.admits) === '["invited","paid"]' && J(c.pay) === '{"protocols":["x402","mpp"],"port":8878,"asset":"0x1c7d4b196cb0c7b01d743fbc6116a902379c7238","chain":"eip155:11155111","tiers":{"8":"100000","32":"400000"}}', "pay normalized: protocol order, lowercased asset, tiers by numeric limit; no onion when absent");
    const withOnion = canonicalPay({ ...PAY, onion: newOnion().onion.toUpperCase() });
    ok(withOnion.onion && /^[a-z2-7]{56}\.onion$/.test(withOnion.onion) && Object.keys(withOnion).join() === "protocols,onion,port,asset,chain,tiers", "pay.onion kept (lowercased) between protocols and port");
    ok(canonicalPay({ ...PAY, onion: "not-an-onion" }).onion === undefined, "a malformed pay.onion is dropped (the advert survives: the gateway's own onion applies)");
    ok(canonicalPay({ ...PAY, tiers: { "8": 100000, "32": 400000 } }).tiers["8"] === "100000", "integer prices are accepted and rendered as decimal strings");
    ok(hasCaps({ admits: ["invited"] }) && hasCaps({ pay: PAY }) && !hasCaps({ admits: ["nope"] }) && !hasCaps({ pay: { protocols: ["x402"] } }), "hasCaps: admits alone / pay alone count; junk does not");
    // additivity: without admits/pay the canonical JSON is byte-identical to before
    const legacy = { ports: [80, 443], region: "eu", proto: { min: 3, max: 3 } };
    ok(J(canonicalCaps(legacy)) === J(canonicalCaps({ ...legacy, admits: [], pay: null })) && J(canonicalCaps(legacy)) === '{"ports":[80,443],"region":"eu","proto":{"min":3,"max":3}}', "no/empty admits+pay -> byte-identical legacy canonical form");
    ok(J(canonicalCaps({ admits: ["invited"], pay: PAY, artifacts: [] })) === '{"admits":["invited"],"pay":' + J(canonicalCaps({ pay: PAY }).pay) + "}", "admits/pay stand alone (no ports/region/proto/artifacts needed)");
  }

  console.log("\nbounds + adversarial (TOTAL: dropped, never thrown):");
  {
    const big = Array.from({ length: 100 }, (_, i) => (i % 2 ? "invited" : "paid"));
    ok(J(canonicalCaps({ admits: big }).admits) === '["invited","paid"]', "a 100-entry admits list collapses to the deduped canonical set (bounded by construction: at most 3)");
    ok(canonicalCaps({ admits: Array.from({ length: 1000 }, (_, i) => "x".repeat(i)) }).admits === undefined, "1000 junk names -> no admits");
    ok(canonicalCaps({ admits: [{}, 1, null, "INVITED "] }).admits === undefined, "non-string / padded names dropped");
    const nine = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [String(i + 1), "1"]));
    ok(canonicalCaps({ pay: { ...PAY, tiers: nine } }).pay === undefined, "9 tiers (> MAX_CAPS_PAY_TIERS=8) -> the whole pay advert is dropped");
    const eight = Object.fromEntries(Array.from({ length: 8 }, (_, i) => [String((i + 1) * 4), "1"]));
    ok(Object.keys(canonicalCaps({ pay: { ...PAY, tiers: eight } }).pay.tiers).length === 8, "8 tiers are kept");
    ok(canonicalCaps({ pay: { ...PAY, tiers: {} } }).pay === undefined && canonicalCaps({ pay: { ...PAY, tiers: [] } }).pay === undefined, "no tiers / array tiers -> dropped");
    ok(canonicalCaps({ pay: { ...PAY, tiers: { "08": "1", "0": "1", "70000": "1", "8": "0", "abc": "1", "16": "1".repeat(41) } } }).pay === undefined, "non-canonical keys, 0/70000 limits, 0 / 41-digit prices are all dropped -> nothing left -> no pay");
    ok(canonicalCaps({ pay: { ...PAY, tiers: { "08": "1", "8": "5" } } }).pay.tiers["8"] === "5" && Object.keys(canonicalCaps({ pay: { ...PAY, tiers: { "08": "1", "8": "5" } } }).pay.tiers).length === 1, "a leading-zero key is dropped, the canonical one kept");
    ok(canonicalCaps({ pay: { ...PAY, protocols: ["lightning"] } }).pay === undefined && canonicalCaps({ pay: { ...PAY, protocols: [] } }).pay === undefined && canonicalCaps({ pay: { ...PAY, protocols: "x402" } }).pay === undefined, "unknown / empty / non-array protocols -> no pay");
    ok(canonicalCaps({ pay: { ...PAY, port: 0 } }).pay === undefined && canonicalCaps({ pay: { ...PAY, port: 65536 } }).pay === undefined && canonicalCaps({ pay: { ...PAY, port: "8878" } }).pay === undefined, "port out of range / string -> no pay");
    ok(canonicalCaps({ pay: { ...PAY, asset: "usdc" } }).pay === undefined && canonicalCaps({ pay: { ...PAY, chain: "eip155:" } }).pay === undefined && canonicalCaps({ pay: { ...PAY, chain: "eip155:0" + "9".repeat(20) } }).pay === undefined, "bad asset / chain shapes -> no pay");
    for (const k of ["protocols", "port", "asset", "chain", "tiers"]) { const p = { ...PAY }; delete p[k]; ok(canonicalCaps({ pay: p }).pay === undefined, `a pay advert missing ${k} is dropped WHOLE (never a half advert)`); }
    ok(canonicalCaps({ pay: "x402" }).pay === undefined && canonicalCaps({ pay: [PAY] }).pay === undefined && canonicalCaps({ pay: null }).pay === undefined, "non-object pay -> no pay");
    const huge = { ...PAY, tiers: { "8": "9".repeat(40) } };
    ok(canonicalCaps({ pay: huge }).pay.tiers["8"].length === 40 && canonicalCaps({ pay: { ...PAY, tiers: { "8": "9".repeat(41) } } }).pay === undefined, "a 40-digit price is the ceiling; 41 digits -> dropped");
    // size of the biggest canonical caps stays small
    const maxCaps = canonicalCaps({ ports: Array.from({ length: 65535 }, (_, i) => i + 1), admits: ADMIT_PATHS.slice(), pay: { ...PAY, onion: newOnion().onion, tiers: Object.fromEntries(Array.from({ length: 8 }, (_, i) => [String(65535 - i), "9".repeat(40)])) } });
    ok(J(maxCaps.admits).length + J(maxCaps.pay).length < 800, `the largest possible admits+pay canonical form is < 800 bytes (${J(maxCaps.admits).length + J(maxCaps.pay).length})`);
  }

  console.log("\nsignatures + directory verification:");
  {
    const g = newOnion();
    const caps = { admits: ["invited", "paid"], pay: PAY };
    const sig = signCaps(g.onion, caps, g.seed);
    ok(verifyCapsSig(g.onion, caps, sig), "capsSig over admits+pay verifies");
    ok(verifyCapsSig(g.onion, { admits: ["paid", "invited", "invited"], pay: { ...PAY, protocols: ["x402", "mpp"], tiers: { "8": "100000", "32": "400000" } } }, sig), "…and against any equivalent (non-canonical) spelling of the same caps");
    ok(!verifyCapsSig(g.onion, { ...caps, admits: ["invited", "staked", "paid"] }, sig), "grafting `staked` onto the policy breaks the onion-bound signature (a bootnode cannot widen a policy)");
    ok(!verifyCapsSig(g.onion, { ...caps, admits: ["invited"] }, sig), "narrowing the policy breaks it too");
    ok(!verifyCapsSig(g.onion, { ...caps, pay: { ...PAY, tiers: { "8": "1", "32": "400000" } } }, sig), "changing a price breaks it");
    ok(!verifyCapsSig(g.onion, { ...caps, pay: { ...PAY, protocols: ["x402"] } }, sig), "dropping a rail breaks it");
    ok(canonicalCapsBytes(g.onion, caps).toString("utf8").startsWith("Shade Tree gateway capabilities v1\n{\"onion\":"), "domain-separated, onion-bound bytes");
    // a directory entry carrying admits+pay verifies; a tampered one is rejected
    const signer = newOnion();
    const entry = { onion: g.onion, pubkey: g.pub, weight: 100, health: "up", caps: canonicalCaps(caps), capsSig: sig };
    const dir = signDirectory({ version: 1, issued: 1000, gateways: [entry] }, signer.seed);
    ok(verifyDirectory(dir, signer.pub).ok === true, "verifyDirectory accepts an entry with signed admits+pay");
    const evil = JSON.parse(JSON.stringify(dir)); evil.gateways[0].caps.admits = ["invited", "staked", "paid"];
    const resigned = signDirectory({ version: evil.version, issued: evil.issued, gateways: evil.gateways }, signer.seed);
    ok(verifyDirectory(resigned, signer.pub).reason?.startsWith("bad-caps-sig"), "a directory signer that widens a gateway's admits (and re-signs the directory) is still rejected: bad-caps-sig");
  }

  console.log("\nbootnode: announce accepts + bounds admits/pay; /directory passes them through; delta re-ships a changed policy:");
  const work = await mkdtemp(join(tmpdir(), "shade-tree-admission-caps-"));
  try {
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0 });
    const g1 = newOnion(), g2 = newOnion(), g3 = newOnion();
    const rec1 = buildAnnounce({ onion: g1.onion, onionSeedHex: g1.seed, caps: { admits: ["paid", "invited", "staked"], pay: { ...PAY, onion: g3.onion } } });
    const rec2 = buildAnnounce({ onion: g2.onion, onionSeedHex: g2.seed, caps: { admits: ["invited", "staked"] } });
    const rec3 = buildAnnounce({ onion: g3.onion, onionSeedHex: g3.seed }); // legacy: no caps
    const a1 = await registry.announce(rec1), a2 = await registry.announce(rec2), a3 = await registry.announce(rec3);
    ok(a1.ok && a2.ok && a3.ok, "announces with admits+pay / admits / no caps all accepted");
    const dir = registry.directory();
    const v = verifyDirectory(dir, signer.pub);
    ok(v.ok === true, `signed /directory verifies under the pinned signer (${v.reason || "ok"})`);
    const e1 = dir.gateways.find((g) => g.onion === g1.onion), e2 = dir.gateways.find((g) => g.onion === g2.onion), e3 = dir.gateways.find((g) => g.onion === g3.onion);
    ok(J(e1.caps.admits) === '["invited","staked","paid"]' && e1.caps.pay && e1.caps.pay.onion === g3.onion && J(e1.caps.pay.protocols) === '["x402","mpp"]' && typeof e1.capsSig === "string" && verifyCapsSig(g1.onion, e1.caps, e1.capsSig), "gateway-1 entry carries admits=[invited,staked,paid] + pay (with the registrar onion) + a verifying capsSig -- passed THROUGH, not re-derived");
    ok(J(e2.caps.admits) === '["invited","staked"]' && e2.caps.pay === undefined && verifyCapsSig(g2.onion, e2.caps, e2.capsSig), "gateway-2 entry carries admits=[invited,staked], no pay");
    ok(e3.caps === undefined && e3.capsSig === undefined, "legacy gateway-3 entry has no caps/capsSig keys (byte-identical to before)");
    // adversarial announce: an oversized policy / pay is BOUNDED by canonicalCaps at announce time,
    // and a bootnode-side widening cannot be listed (capsSig would fail).
    const gX = newOnion();
    const recX = buildAnnounce({ onion: gX.onion, onionSeedHex: gX.seed, caps: { admits: Array.from({ length: 500 }, () => "paid"), pay: { ...PAY, tiers: Object.fromEntries(Array.from({ length: 50 }, (_, i) => [String(i + 1), "1"])) } } });
    const vX = await verifyAnnounce(recX);
    ok(vX.ok && J(vX.caps) === '{"admits":["paid"]}', "an announce with a 500-entry admits + a 50-tier pay verifies with admits collapsed to [paid] and the oversized pay DROPPED (bounded)");
    const evilRec = { ...rec2, caps: { admits: ["invited", "staked", "paid"] } };
    const vE = await verifyAnnounce(evilRec);
    ok(vE.ok === false && (vE.reason === "bad-caps-sig" || vE.reason === "bad-onion-sig"), `an announce whose admits were widened in transit is rejected (${vE.reason})`);
    // delta: a policy change IN PLACE (same onion) is re-shipped in `added`
    const { etag: base } = registry.directoryWithEtag();
    const rec2b = buildAnnounce({ onion: g2.onion, onionSeedHex: g2.seed, caps: { admits: ["invited"] } });
    ok((await registry.announce(rec2b)).ok, "gateway-2 re-announces with a NARROWER policy (invited only)");
    const d = registry.delta(base);
    ok(!d.full && d.added.length === 1 && d.added[0].onion === g2.onion && J(d.added[0].caps.admits) === '["invited"]' && d.removed.length === 0, "delta since the previous etag re-ships gateway-2 (changed in place: admits=[invited]) in `added`, nothing removed");
    // payAdvertFromEnv honours SHADE_TREE_PAY_PROTOCOLS
    const envBase = { SHADE_TREE_REGISTRAR_ADVERTISE: "1", SHADE_TREE_PAY_ASSET: ASSET, SHADE_TREE_PAY_PRICES: "8=100000,32=400000" };
    ok(J(payAdvertFromEnv(envBase).protocols) === '["x402","mpp"]' && J(payAdvertFromEnv({ ...envBase, SHADE_TREE_PAY_PROTOCOLS: "mpp" }).protocols) === '["mpp"]' && J(payAdvertFromEnv({ ...envBase, SHADE_TREE_PAY_PROTOCOLS: "MPP, x402" }).protocols) === '["x402","mpp"]', "payAdvertFromEnv: protocols = SHADE_TREE_PAY_PROTOCOLS (default both; canonical order)");
    ok(payAdvertFromEnv({ ...envBase, SHADE_TREE_PAY_PROTOCOLS: "lightning" }) === null, "an unknown rail -> no advert at all (never a half-truth in /health)");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log("\nheartbeat producer (advertisedAdmits / advertisedPay / buildGatewayCaps):");
  {
    ok(advertisedAdmits({}) === null, "SHADE_TREE_ADMIT unset (and no SHADE_TREE_ROOTS) -> not advertised (null)");
    ok(J(advertisedAdmits({ SHADE_TREE_ADMIT: "paid,invited" })) === '["invited","paid"]', "SHADE_TREE_ADMIT -> canonical list");
    ok(J(advertisedAdmits({ SHADE_TREE_ROOTS: "static,onchain", SHADE_TREE_GROUP_CONTRACT: "0xA" })) === '["invited","staked"]' && J(advertisedAdmits({ SHADE_TREE_ROOTS: "static,onchain", SHADE_TREE_GROUP_CONTRACT: "0xA", SHADE_TREE_PAID_ACCESS_CONTRACT: "0xP" })) === '["invited","staked","paid"]', "the deprecated SHADE_TREE_ROOTS alias maps over the contracts THIS env names");
    ok(J(advertisedAdmits({ SHADE_TREE_ADMIT: "invited", SHADE_TREE_ROOTS: "static,onchain", SHADE_TREE_GROUP_CONTRACT: "0xA" })) === '["invited"]', "SHADE_TREE_ADMIT wins over SHADE_TREE_ROOTS");
    let threw = null; try { advertisedAdmits({ SHADE_TREE_ADMIT: "onchain" }); } catch (e) { threw = e.message; }
    ok(/unknown admission path "onchain"/.test(threw || ""), "a malformed SHADE_TREE_ADMIT is a startup error in the heartbeat too (never advertise a guess)");
    const gwOnion = newOnion().onion, bnOnion = newOnion().onion;
    const envPay = { SHADE_TREE_REGISTRAR_ADVERTISE: "1", SHADE_TREE_PAY_ASSET: ASSET, SHADE_TREE_PAY_PRICES: "8=100000,32=400000", SHADE_TREE_PAY_PROTOCOLS: "x402" };
    ok(advertisedPay({}) === null && advertisedPay({ ...envPay, SHADE_TREE_REGISTRAR_ADVERTISE: "0" }) === null, "no SHADE_TREE_REGISTRAR_ADVERTISE -> no pay");
    const p1 = advertisedPay(envPay, { gatewayOnion: gwOnion });
    ok(p1 && J(p1.protocols) === '["x402"]' && p1.port === 8878 && p1.asset === ASSET && p1.chain === "eip155:11155111" && J(p1.tiers) === '{"8":"100000","32":"400000"}' && p1.onion === undefined, "advertisedPay: the /health advert shape; no onion when the registrar rides the gateway's own onion (SHADE_TREE_REGISTRAR_ONION unset)");
    ok(advertisedPay({ ...envPay, SHADE_TREE_REGISTRAR_ONION: gwOnion.toUpperCase() }, { gatewayOnion: gwOnion }).onion === undefined, "SHADE_TREE_REGISTRAR_ONION == the gateway onion -> no onion field");
    ok(advertisedPay({ ...envPay, SHADE_TREE_REGISTRAR_ONION: bnOnion.replace(/\.onion$/, "") }, { gatewayOnion: gwOnion }).onion === bnOnion, "SHADE_TREE_REGISTRAR_ONION = the BOOTNODE onion -> pay.onion names it (with .onion normalized)");
    ok(buildGatewayCaps({}) === null && buildGatewayCaps({ SHADE_TREE_UNRELATED: "1" }) === null, "buildGatewayCaps: unconfigured -> null (byte-identical legacy announce)");
    const c1 = buildGatewayCaps({ SHADE_TREE_ADMIT: "invited,staked,paid", ...envPay, SHADE_TREE_REGISTRAR_ONION: bnOnion }, { gatewayOnion: gwOnion });
    ok(c1 && J(c1.admits) === '["invited","staked","paid"]' && c1.pay && c1.pay.onion === bnOnion && c1.proto && c1.ports === undefined, "SHADE_TREE_ADMIT + advert -> caps { admits, pay, proto } (proto rides along; no ports without an egress policy)");
    const c2 = buildGatewayCaps({ SHADE_TREE_ADMIT: "invited" });
    ok(c2 && J(c2.admits) === '["invited"]' && c2.pay === undefined && c2.proto, "SHADE_TREE_ADMIT=invited alone -> caps { admits:[invited], proto } (an invited-only gateway IS advertised, so --max-anon clients can find it)");
    // the whole thing signs into an announce the bootnode + a directory verifier accept
    const g = newOnion();
    const rec = buildAnnounce({ onion: g.onion, onionSeedHex: g.seed, caps: c1 });
    const v = await verifyAnnounce(rec);
    ok(v.ok && J(v.caps.admits) === '["invited","staked","paid"]' && v.caps.pay.onion === bnOnion && verifyCapsSig(g.onion, rec.caps, rec.capsSig), "the heartbeat's announce carries signed admits+pay that verifyAnnounce + verifyCapsSig accept");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: admission-caps selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.log(`  FAIL (uncaught) ${e && e.stack ? e.stack : e}`); process.exit(1); });
