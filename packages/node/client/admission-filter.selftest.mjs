// T-FEAT-9 client admission-aware selection + `--max-anon` (fast lane: unit, no Tor, no chain):
//   - filterByAdmission (pure): a paid/staked/invited leaf keeps only gateways whose SIGNED
//     caps.admits include it; an entry with NO policy is kept (rollout compat, logged once);
//     maxAnon keeps ONLY admits === [invited] (a policy-less entry cannot prove it -> dropped);
//     inactive => the SAME array reference (byte-identical default path);
//   - selectCandidates(null, adm) over a real signed directory file: filters, carries `admits` on
//     each candidate, and FAILS CLOSED with a precise error naming every gateway's policy when
//     nothing admits the leaf source / nothing is invited-only;
//   - ShadeTreeClient: leafSource() from the discovered source label (members.json -> invited,
//     staked(0x..) -> staked, paid(0x..) -> paid), SHADE_TREE_LEAF_SOURCE / { leafSource } pins it,
//     --max-anon / SHADE_TREE_MAX_ANON refuses a staked/paid leaf BEFORE any dial with the reason, and
//     `{ maxAnon, leafSource: "paid" }` is refused at construction; makeLeafSourceLoader `only`.
//
//   node packages/node/client/admission-filter.selftest.mjs

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { signDirectory, pubkeyToOnion, canonicalCaps, signCaps } from "../lib/directory.mjs";
import { makeSlotPool, makeLeafSourceLoader, ShadeTreeClient } from "./shade-tree-client.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const HERE = dirname(fileURLToPath(import.meta.url));

function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return { pub: Buffer.from(pub.subarray(pub.length - 32)).toString("hex"), priv: Buffer.from(priv.subarray(priv.length - 32)).toString("hex") };
}
// A gateway entry with (optionally) SIGNED admits caps, so verifyDirectory accepts it.
function mintGateway(admits) {
  const k = newEd25519();
  const onion = pubkeyToOnion(k.pub);
  const e = { onion, pubkey: k.pub, weight: 100, health: "up" };
  if (admits) { e.caps = canonicalCaps({ admits }); e.capsSig = signCaps(onion, e.caps, k.priv); }
  return e;
}
const short = (o) => o.replace(/\.onion$/, "");

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-admission-filter-"));
  try {
    // --- a signed 4-gateway directory: invited-only, invited+staked, all three, legacy (no policy) ---
    const signer = newEd25519();
    const gInv = mintGateway(["invited"]), gInvStk = mintGateway(["invited", "staked"]), gAll = mintGateway(["paid", "staked", "invited"]), gLegacy = mintGateway(null);
    const signed = signDirectory({ version: 1, issued: Math.floor(Date.now() / 1000), gateways: [gInv, gInvStk, gAll, gLegacy], signer: signer.pub }, signer.priv);
    const dirFile = join(work, "directory.signed.json");
    await writeFile(dirFile, JSON.stringify(signed, null, 2) + "\n");
    process.env.SHADE_TREE_DIRECTORY = dirFile;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    delete process.env.SHADE_TREE_BOOTNODE_ONION;
    delete process.env.SHADE_TREE_HEALTH_CACHE; process.env.SHADE_TREE_HEALTH_CACHE = "off";
    const sel = await import(pathToFileURL(join(HERE, "selection.mjs")).href);
    const G = signed.gateways;

    console.log("filterByAdmission (pure):");
    {
      const logs = [];
      const log = (m) => logs.push(m);
      ok(sel.filterByAdmission(G, null) === G && sel.filterByAdmission(G, { leafSource: "auto" }) === G && sel.filterByAdmission(G, {}) === G, "inactive (null / auto / {}) -> the SAME array reference (byte-identical default path)");
      ok(!sel.admissionActive(null) && !sel.admissionActive({ leafSource: "auto", maxAnon: false }) && sel.admissionActive({ leafSource: "paid" }) && sel.admissionActive({ maxAnon: true }), "admissionActive: only a real leaf source or maxAnon activates it");
      const paid = sel.filterByAdmission(G, { leafSource: "paid" }, { log });
      ok(paid.length === 2 && paid.includes(gAll) && paid.includes(gLegacy), "paid leaf -> the all-three gateway + the policy-less legacy one (rollout compat); invited-only and invited+staked are OUT");
      ok(logs.length === 1 && /1 gateway\(s\) advertise no admission policy/.test(logs[0]) && /paid leaf/.test(logs[0]), "…and the legacy assumption is logged ONCE with the reason");
      sel.filterByAdmission(G, { leafSource: "paid" }, { log });
      ok(logs.length === 1, "the legacy warning is not repeated");
      const staked = sel.filterByAdmission(G, { leafSource: "staked" }, { log });
      ok(staked.length === 3 && !staked.includes(gInv), "staked leaf -> invited+staked, all-three, legacy (not the invited-only gateway)");
      const inv = sel.filterByAdmission(G, { leafSource: "invited" }, { log });
      ok(inv.length === 4, "invited leaf -> every gateway (all admit invited; legacy assumed)");
      const max = sel.filterByAdmission(G, { leafSource: "invited", maxAnon: true }, { log });
      ok(max.length === 1 && max[0] === gInv, "maxAnon -> ONLY the gateway whose admits is exactly [invited]; a policy-less entry cannot prove invited-only -> excluded");
      ok(sel.filterByAdmission([gInvStk, gAll, gLegacy], { maxAnon: true }, { log }).length === 0, "maxAnon over a fleet with no invited-only gateway -> empty (the caller fails closed)");
      ok(JSON.stringify(sel.admitsOf(gAll)) === '["invited","staked","paid"]' && sel.admitsOf(gLegacy) === null, "admitsOf: canonical list or null");
      const desc = sel.describeFleetAdmits(G);
      ok(desc.includes(`${short(gInv.onion).slice(0, 12)}..=[invited]`) && desc.includes("=(no policy advertised)"), "describeFleetAdmits names each gateway's policy (or its absence)");
    }

    console.log("\nselectCandidates(null, adm) over the signed directory:");
    {
      const all = await sel.selectCandidates();
      ok(all.length === 4 && all.filter((c) => c.admits).length === 3 && all.find((c) => c.onion === short(gAll.onion)).admits.join() === "invited,staked,paid" && !("admits" in all.find((c) => c.onion === short(gLegacy.onion))), "no admission constraint -> all 4; each candidate carries its signed `admits` (absent on the legacy one)");
      const paid = await sel.selectCandidates(null, { leafSource: "paid" });
      ok(paid.length === 2 && paid.every((c) => [short(gAll.onion), short(gLegacy.onion)].includes(c.onion)), "leafSource=paid -> 2 candidates (all-three + legacy)");
      const max = await sel.selectCandidates(null, { leafSource: "invited", maxAnon: true });
      ok(max.length === 1 && max[0].onion === short(gInv.onion) && max[0].admits.join() === "invited", "maxAnon -> exactly the invited-only gateway");
      // fail closed, precisely -- selection.mjs captures its directory at import, so run the
      // refusals in a fresh process over a 2-gateway directory (invited-only + invited,staked).
      const onlyInvStk = signDirectory({ version: 1, issued: Math.floor(Date.now() / 1000) + 1, gateways: [gInv, gInvStk], signer: signer.pub }, signer.priv);
      const dir2 = join(work, "directory2.signed.json");
      await writeFile(dir2, JSON.stringify(onlyInvStk, null, 2) + "\n");
      const script = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(join(HERE, "selection.mjs")).href)});
const out = {};
try { await sel.selectCandidates(null, { leafSource: "paid" }); out.paid = "UNEXPECTED-OK"; } catch (e) { out.paid = e.message; }
try { out.staked = (await sel.selectCandidates(null, { leafSource: "staked" })).map((c) => c.admits ? c.admits.join() : null); } catch (e) { out.staked = e.message; }
process.stdout.write(JSON.stringify(out));
`;
      const { execFileSync } = await import("node:child_process");
      const raw = execFileSync(process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, SHADE_TREE_DIRECTORY: dir2, SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_BOOTNODE_ONION: "", SHADE_TREE_HEALTH_CACHE: "off" }, encoding: "utf8" });
      const out = JSON.parse(raw.trim().split("\n").pop());
      ok(/^no gateway admits a paid leaf \(your leaf source\); fleet: /.test(out.paid) && /=\[invited\]/.test(out.paid) && /=\[invited,staked\]/.test(out.paid) && /docs\/CLIENTS\.md/.test(out.paid), `paid leaf vs an invited/staked-only fleet -> selectCandidates FAILS CLOSED naming every gateway's policy: ${out.paid.slice(0, 100)}...`);
      ok(Array.isArray(out.staked) && out.staked.length === 1 && out.staked[0] === "invited,staked", "staked leaf on the same fleet -> exactly the invited,staked gateway");
      const script2 = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(join(HERE, "selection.mjs")).href)});
try { await sel.selectCandidates(null, { leafSource: "invited", maxAnon: true }); process.stdout.write("UNEXPECTED-OK"); } catch (e) { process.stdout.write(e.message); }
`;
      const onlyStk = signDirectory({ version: 1, issued: Math.floor(Date.now() / 1000) + 2, gateways: [gInvStk, gAll, gLegacy], signer: signer.pub }, signer.priv);
      const dir3 = join(work, "directory3.signed.json");
      await writeFile(dir3, JSON.stringify(onlyStk, null, 2) + "\n");
      const raw2 = execFileSync(process.execPath, ["--input-type=module", "-e", script2], { env: { ...process.env, SHADE_TREE_DIRECTORY: dir3, SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_BOOTNODE_ONION: "", SHADE_TREE_HEALTH_CACHE: "off" }, encoding: "utf8" });
      ok(/^--max-anon: no invited-only gateway in the directory/.test(raw2.trim().split("\n").pop()) && /\(no policy advertised\)/.test(raw2), `--max-anon over a fleet with no invited-only gateway -> FAILS CLOSED with the fleet summary: ${raw2.trim().split("\n").pop().slice(0, 100)}...`);
    }

    console.log("\nShadeTreeClient: leaf source discovery, SHADE_TREE_LEAF_SOURCE, --max-anon refusal:");
    {
      const fake = { group: { indexOf: () => 0 }, root: "1" };
      const mkPool = (source) => makeSlotPool({ secret: "0x1234", K: 8, loadGroupFn: async () => ({ ...fake, source }), epochOf: () => 1n, prove: async () => {} });
      ok(await mkPool("members.json").leafSource() === "invited" && await mkPool("staked(0xA)").leafSource() === "staked" && await mkPool("paid(0xP)").leafSource() === "paid" && await mkPool(undefined).leafSource() === null, "makeSlotPool.leafSource(): members.json->invited, staked(..)->staked, paid(..)->paid, unlabeled->null");
      const clientFor = (source, opts = {}) => new ShadeTreeClient({ secret: "0x1234", loadGroupFn: async () => ({ ...fake, source }), directory: dirFile, dirSigner: signer.pub, ...opts });
      ok(await clientFor("paid(0xP)").leafSource() === "paid" && await clientFor("members.json").leafSource() === "invited" && await clientFor(undefined).leafSource() === "invited", "ShadeTreeClient.leafSource(): discovered source; an unlabeled loader (legacy PoC) counts as invited");
      ok(await clientFor("paid(0xP)", { leafSource: "staked" }).leafSource() === "staked", "{ leafSource } pins the leaf source over discovery");
      const admPaid = await clientFor("paid(0xP)")._admission();
      ok(admPaid.leafSource === "paid" && admPaid.maxAnon === false, "_admission(): { leafSource: paid, maxAnon: false }");
      // max-anon over a paid leaf: refused before any dial, with the reason
      let err = null;
      try { await clientFor("paid(0xP)", { maxAnon: true })._candidates(); } catch (e) { err = e.message; }
      ok(err && /--max-anon: your leaf is in the paid set/.test(err) && /wrong-group-root/.test(err) && /buyer address/.test(err), `max-anon + paid leaf refused before dialing: ${err.slice(0, 90)}...`);
      err = null;
      try { await clientFor("staked(0xA)", { maxAnon: true })._candidates(); } catch (e) { err = e.message; }
      ok(err && /--max-anon: your leaf is in the staked set/.test(err) && /staking wallet/.test(err), "max-anon + staked leaf refused (names the linkability)");
      err = null;
      try { clientFor("paid(0xP)", { maxAnon: true, leafSource: "paid" }); } catch (e) { err = e.message; }
      ok(err && /--max-anon requires an invited/.test(err), "constructing { maxAnon, leafSource: paid } is refused outright");
      // max-anon over an invited leaf: only the invited-only gateway
      const c = clientFor("members.json", { maxAnon: true });
      const cands = await c._candidates();
      ok(cands.length === 1 && cands[0].onion === short(gInv.onion) && cands[0].admits.join() === "invited", "max-anon + invited leaf -> candidates = [the invited-only gateway]");
      // paid leaf without max-anon: the two admitting gateways
      const cp = await clientFor("paid(0xP)")._candidates();
      ok(cp.length === 2 && cp.every((x) => [short(gAll.onion), short(gLegacy.onion)].includes(x.onion)), "paid leaf -> candidates = [all-three, legacy]");
      // env spellings
      process.env.SHADE_TREE_MAX_ANON = "1"; process.env.SHADE_TREE_LEAF_SOURCE = "invited";
      const ce = new ShadeTreeClient({ secret: "0x1234", loadGroupFn: async () => ({ ...fake, source: "paid(0xP)" }), directory: dirFile, dirSigner: signer.pub });
      ok(ce.maxAnon === true && ce.leafSourcePin === "invited" && await ce.leafSource() === "invited", "SHADE_TREE_MAX_ANON=1 + SHADE_TREE_LEAF_SOURCE=invited are read (the pin wins over discovery)");
      process.env.SHADE_TREE_MAX_ANON = "true"; delete process.env.SHADE_TREE_LEAF_SOURCE;
      ok(new ShadeTreeClient({ secret: "0x1234", loadGroupFn: async () => fake, directory: dirFile, dirSigner: signer.pub }).maxAnon === true, "SHADE_TREE_MAX_ANON=true (the bare --max-anon flag) is on");
      delete process.env.SHADE_TREE_MAX_ANON;
      process.env.SHADE_TREE_LEAF_SOURCE = "onchain";
      err = null; try { new ShadeTreeClient({ secret: "0x1234", loadGroupFn: async () => fake }); } catch (e) { err = e.message; }
      ok(/SHADE_TREE_LEAF_SOURCE: expected auto, invited, staked, paid/.test(err || ""), "a bad SHADE_TREE_LEAF_SOURCE is a precise construction error");
      delete process.env.SHADE_TREE_LEAF_SOURCE;
      // a pinned onion: no filtering possible, but max-anon still refuses a paid leaf
      err = null; try { await clientFor("paid(0xP)", { maxAnon: true, onion: short(gAll.onion) })._candidates(); } catch (e) { err = e.message; }
      ok(err && /--max-anon: your leaf is in the paid set/.test(err), "a pinned onion + max-anon + paid leaf is still refused");
      ok((await clientFor("paid(0xP)", { onion: short(gInv.onion) })._candidates())[0].onion === short(gInv.onion), "a pinned onion is honoured as-is without max-anon (a policy mismatch surfaces as the gateway's wrong-group-root)");
    }

    console.log("\nmakeLeafSourceLoader `only` (SHADE_TREE_LEAF_SOURCE pins the set searched):");
    {
      const leafOf = () => 0n; // holds() uses group.indexOf(BigInt(leaf)) !== -1
      const contracts = [{ address: "0xA", kind: "staked" }, { address: "0xP", kind: "paid" }];
      const loadStatic = async () => ({ group: { indexOf: () => -1 }, root: "s", count: 1 });
      const loadContract = async ({ contract }) => ({ group: { indexOf: () => (contract === "0xP" ? 0 : -1) }, root: contract, count: 1 });
      const env = { SHADE_TREE_RPC_URL: "http://127.0.0.1:1" };
      const auto = await makeLeafSourceLoader({ secret: "0x1234", limit: 8, env, contracts, loadStatic, loadContract })();
      ok(auto.source === "paid(0xP)", "auto: found in the paid set after members.json + staked missed");
      const paidOnly = await makeLeafSourceLoader({ secret: "0x1234", limit: 8, env, contracts, loadStatic, loadContract, only: "paid" })();
      ok(paidOnly.source === "paid(0xP)", "only=paid: found (members.json + staked not consulted)");
      let err = null;
      try { await makeLeafSourceLoader({ secret: "0x1234", limit: 8, env, contracts, loadStatic, loadContract, only: "staked" })(); } catch (e) { err = e.message; }
      ok(err && /is in none of: staked\(0xA\) \(1 leaves\)/.test(err) && !/paid\(/.test(err) && /SHADE_TREE_LEAF_SOURCE=staked pins the search/.test(err), `only=staked: not found there -> precise error naming ONLY the staked set: ${err.slice(0, 80)}...`);
      err = null;
      try { await makeLeafSourceLoader({ secret: "0x1234", limit: 8, env, contracts: [contracts[0]], loadStatic, loadContract, only: "paid" })(); } catch (e) { err = e.message; }
      ok(err && /SHADE_TREE_LEAF_SOURCE=paid but no paid set is configured/.test(err), "only=paid with no paid contract configured -> precise error");
      const inv = await makeLeafSourceLoader({ secret: "0x1234", limit: 8, env, contracts, loadStatic: async () => ({ group: { indexOf: () => 0 }, root: "s", count: 1 }), loadContract, only: "invited" })();
      ok(inv.source === "members.json", "only=invited: members.json alone (contracts never read)");
      void leafOf;
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: admission-filter selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.log(`  FAIL (uncaught) ${e && e.stack ? e.stack : e}`); process.exit(1); });
