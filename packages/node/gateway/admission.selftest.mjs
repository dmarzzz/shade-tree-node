// T-FEAT-9 gateway ADMISSION POLICY (fast lane, no chain, no Tor): SHADE_TREE_ADMIT resolution + fail-closed
// misconfig + the deprecated SHADE_TREE_ROOTS alias (warning) + the `admits:` startup line + initRoots
// narrowing (a configured-but-not-admitted contract is never read; its root is NOT trusted, so a
// proof under it is dropped `wrong-group-root` at the cheap-first check) + slasher routing over the
// ADMITTED contracts only. The anvil twin with real proofs is test/paid-access.selftest.mjs (slow lane).
//
//   node packages/node/gateway/admission.selftest.mjs

import { EventEmitter } from "node:events";
import { resolveAdmission, resolveRootSources, describeAdmission, initRoots, makeHandler, makeSpentSet, _getRecentRoots, _setRecentRoots } from "./gateway.mjs";
import { ADMIT_ORDER, parseAdmit, admitsFromRoots, describeAdmits, parsePayProtocols, parseLeafSource, admitPathOfSource, envFlag } from "../lib/admission.mjs";
import { calculateSignalHash, requestSignal, externalNullifierFor, currentEpoch } from "../lib/rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const throws = (fn, re) => { try { fn(); return false; } catch (e) { return re.test(e.message) ? true : (console.log(`       (threw: ${e.message})`), false); } };

const A = { address: "0xA", kind: "staked" }, B = { address: "0xB", kind: "staked" }, P = { address: "0xP", kind: "paid" };
const capture = () => { const w = []; return { w, warn: (m, f) => w.push({ m, f }) }; };

async function main() {
  console.log("packages/node/lib/admission.mjs parsers:");
  {
    ok(JSON.stringify(ADMIT_ORDER) === '["invited","staked","paid"]', "ADMIT_ORDER = invited > staked > paid (the anonymity order, docs/adr/0008)");
    ok(JSON.stringify(parseAdmit(" Paid , invited ,paid ")) === '["invited","paid"]', "parseAdmit: case/space tolerant, deduped, canonical anonymity order");
    ok(throws(() => parseAdmit("invited,onchain"), /unknown admission path "onchain"/), "parseAdmit rejects an unknown name (SHADE_TREE_ROOTS words are not SHADE_TREE_ADMIT words)");
    ok(throws(() => parseAdmit(" , "), /no admission path selected/), "parseAdmit rejects an empty list");
    ok(JSON.stringify(admitsFromRoots("static,onchain", { hasStaked: true, hasPaid: true })) === '["invited","staked","paid"]', "SHADE_TREE_ROOTS alias: static,onchain -> invited+staked+paid");
    ok(JSON.stringify(admitsFromRoots("onchain", { hasStaked: false, hasPaid: true })) === '["paid"]', "SHADE_TREE_ROOTS=onchain with only a paid set -> paid");
    ok(throws(() => admitsFromRoots("onchain", {}), /no contract is configured/), "SHADE_TREE_ROOTS=onchain without a contract still errors (as T-FEAT-7)");
    ok(describeAdmits(["paid", "invited"]) === "admits: invited+paid" && describeAdmits([]) === "admits: (none)", "describeAdmits renders the canonical `admits: invited+paid` line");
    ok(JSON.stringify(parsePayProtocols("")) === '["x402","mpp"]' && JSON.stringify(parsePayProtocols("MPP")) === '["mpp"]' && JSON.stringify(parsePayProtocols("mpp,x402")) === '["x402","mpp"]', "parsePayProtocols: unset = both; subset; canonical order x402,mpp");
    ok(throws(() => parsePayProtocols("x402,lightning"), /unknown payment protocol "lightning"/), "parsePayProtocols rejects an unknown rail");
    ok(parseLeafSource("") === "auto" && parseLeafSource("PAID") === "paid" && throws(() => parseLeafSource("onchain"), /expected auto, invited, staked, paid/), "parseLeafSource: auto default, names, precise error");
    ok(admitPathOfSource("members.json") === "invited" && admitPathOfSource("staked(0xA)") === "staked" && admitPathOfSource("paid(0xP)") === "paid" && admitPathOfSource("x") === null, "admitPathOfSource maps the client's discovered source labels");
    ok(envFlag("1") && envFlag("true") && !envFlag("0") && !envFlag(undefined), "envFlag: 1/true on, 0/unset off");
  }

  console.log("\nresolveAdmission (SHADE_TREE_ADMIT; default invited = max-anon; fail closed):");
  {
    let c = capture();
    let r = resolveAdmission({ admit: "", roots: "", contracts: [], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["invited"]' && r.static && !r.onchain && r.contracts.length === 0 && r.source === "default" && c.w.length === 0, "nothing set, no contract -> invited only, no warning");
    c = capture();
    r = resolveAdmission({ admit: "", roots: "", contracts: [A, P], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["invited"]' && r.static && !r.onchain && r.contracts.length === 0 && !r.explicit, "nothing set, staked+paid CONFIGURED -> STILL invited only (opt-in is explicit; the contracts are not root sources)");
    ok(c.w.length === 1 && /SHADE_TREE_ADMIT is unset: admitting invited ONLY/.test(c.w[0].m) && /set SHADE_TREE_ADMIT=invited,staked,paid/.test(c.w[0].m), "…and WARNs at startup, naming the exact SHADE_TREE_ADMIT that would trust them");
    c = capture();
    r = resolveAdmission({ admit: "invited,paid", roots: "", contracts: [A, P], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["invited","paid"]' && r.static && r.onchain && r.contracts.length === 1 && r.contracts[0].kind === "paid" && r.explicit && r.source === "SHADE_TREE_ADMIT" && c.w.length === 0, "SHADE_TREE_ADMIT=invited,paid -> members.json + the paid set; the STAKED contract is filtered OUT of the root sources");
    r = resolveAdmission({ admit: "staked", roots: "", contracts: [A, B, P], warn: () => {} });
    ok(JSON.stringify(r.admits) === '["staked"]' && !r.static && r.onchain && r.contracts.map((x) => x.address).join() === "0xA,0xB", "SHADE_TREE_ADMIT=staked -> every staked set, no members.json, no paid");
    r = resolveAdmission({ admit: "paid,staked,invited", roots: "", contracts: [A, P], warn: () => {} });
    ok(JSON.stringify(r.admits) === '["invited","staked","paid"]' && r.contracts.length === 2, "SHADE_TREE_ADMIT=paid,staked,invited -> all three (canonical order)");
    // fail closed: a named path with no contract behind it
    ok(throws(() => resolveAdmission({ admit: "invited,staked", roots: "", contracts: [P], warn: () => {} }), /SHADE_TREE_ADMIT names staked but no StakedReputationSet is configured .*refusing to start/), "SHADE_TREE_ADMIT names staked, only a paid set configured -> refuses to start (never a silently smaller set)");
    ok(throws(() => resolveAdmission({ admit: "paid", roots: "", contracts: [A], warn: () => {} }), /SHADE_TREE_ADMIT names paid but no PaidAccessSet is configured/), "SHADE_TREE_ADMIT names paid without SHADE_TREE_PAID_ACCESS_CONTRACT -> refuses to start");
    ok(throws(() => resolveAdmission({ admit: "invited,onchain", roots: "", contracts: [A], warn: () => {} }), /unknown admission path "onchain"/), "SHADE_TREE_ADMIT with an SHADE_TREE_ROOTS word -> precise error");
    // the deprecated alias
    c = capture();
    r = resolveAdmission({ admit: "", roots: "static,onchain", contracts: [A, P], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["invited","staked","paid"]' && r.source === "SHADE_TREE_ROOTS" && r.contracts.length === 2, "SHADE_TREE_ROOTS=static,onchain (deprecated alias) -> invited+staked+paid over the configured contracts");
    ok(c.w.length === 1 && /SHADE_TREE_ROOTS is DEPRECATED/.test(c.w[0].m) && /set SHADE_TREE_ADMIT=invited,staked,paid instead/.test(c.w[0].m), "…with the deprecation warning naming the equivalent SHADE_TREE_ADMIT");
    c = capture();
    r = resolveAdmission({ admit: "", roots: "onchain", contracts: [P], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["paid"]' && !r.static, "SHADE_TREE_ROOTS=onchain with only the paid set -> paid alone (no members.json)");
    c = capture();
    r = resolveAdmission({ admit: "invited", roots: "static,onchain", contracts: [A, P], warn: c.warn });
    ok(JSON.stringify(r.admits) === '["invited"]' && r.source === "SHADE_TREE_ADMIT" && c.w.length === 1 && /SHADE_TREE_ROOTS is ignored because SHADE_TREE_ADMIT is set/.test(c.w[0].m), "both set -> SHADE_TREE_ADMIT wins, SHADE_TREE_ROOTS ignored with a warning");
    ok(throws(() => resolveAdmission({ admit: "", roots: "onchain", contracts: [], warn: () => {} }), /SHADE_TREE_ROOTS names onchain but no contract is configured/), "SHADE_TREE_ROOTS=onchain with no contract -> config error (unchanged)");
    // the back-compat shim
    const rr = resolveRootSources({ spec: "", contracts: [A] });
    ok(rr.static === true && rr.onchain === false && rr.explicit === false, "resolveRootSources('') = the T-FEAT-9 default (invited only), not the T-FEAT-7 union");
    ok(describeAdmission(["invited", "staked", "paid"]) === "admits: invited+staked+paid", "describeAdmission = `admits: invited+staked+paid` (the startup line)");
  }

  console.log("\ninitRoots under a policy: a configured-but-not-admitted contract is never read; its root is untrusted:");
  {
    const staticRoot = "424242", stakedRoot = "777", paidRoot = "888";
    const loadStatic = async () => ({ root: staticRoot, count: 2, leaves: ["1", "2"] });
    const noWatch = () => {};
    const made = [];
    const provider = (addrs) => ({
      contract: addrs[0], addrs,
      currentRoots: async () => ({ roots: addrs.map((a) => (a === "0xP" ? paidRoot : stakedRoot)), observedAtBlock: 5, finalized: true, leafCount: 1 }),
      onChange: () => () => {},
      describe: () => ({ provider: "node", contract: addrs[0] }),
    });
    const makeProvider = (addrs) => { made.push(addrs.slice()); return provider(addrs); };
    // (a) invited only, contracts configured: NO provider is built; only the static root is trusted
    _setRecentRoots([]); made.length = 0;
    let want = resolveAdmission({ admit: "invited", roots: "", contracts: [A, P], warn: () => {} });
    let r = await initRoots({ contracts: want.contracts, want, loadStatic, makeProvider, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(made.length === 0 && _getRecentRoots().size === 1 && _getRecentRoots().has(staticRoot) && r.contracts.length === 0 && JSON.stringify(r.admits) === '["invited"]', "SHADE_TREE_ADMIT=invited -> no chain provider built, recentRoots = {members.json root}, initRoots().contracts = [] (nothing to route slashes to)");
    // (b) invited,paid: only the paid contract is read; the staked root is NOT trusted
    _setRecentRoots([]); made.length = 0;
    want = resolveAdmission({ admit: "invited,paid", roots: "", contracts: [A, P], warn: () => {} });
    r = await initRoots({ contracts: want.contracts, want, loadStatic, makeProvider, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(made.length === 1 && made[0].join() === "0xP" && _getRecentRoots().has(staticRoot) && _getRecentRoots().has(paidRoot) && !_getRecentRoots().has(stakedRoot) && r.contracts.map((c) => c.kind).join() === "paid", "SHADE_TREE_ADMIT=invited,paid -> provider over the PAID set only; staked root absent from recentRoots; contracts = [paid] (slash targets)");
    // (c) the default resolution path (no `want` injected): env-driven, contracts narrowed automatically
    _setRecentRoots([]); made.length = 0;
    const saved = { admit: process.env.SHADE_TREE_ADMIT, roots: process.env.SHADE_TREE_ROOTS };
    process.env.SHADE_TREE_ADMIT = "staked"; delete process.env.SHADE_TREE_ROOTS;
    r = await initRoots({ contracts: [A, B, P], loadStatic, makeProvider, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(made.length === 1 && made[0].join() === "0xA,0xB" && !_getRecentRoots().has(staticRoot) && _getRecentRoots().has(stakedRoot) && r.count === null && JSON.stringify(r.admits) === '["staked"]', "env SHADE_TREE_ADMIT=staked (no want injected) -> initRoots resolves it, narrows to the staked sets, no members.json");
    if (saved.admit === undefined) delete process.env.SHADE_TREE_ADMIT; else process.env.SHADE_TREE_ADMIT = saved.admit;
    if (saved.roots !== undefined) process.env.SHADE_TREE_ROOTS = saved.roots;

    // (d) the CHEAP-FIRST reject: under (a)'s roots a proof rooted in the paid tree is dropped
    //     `wrong-group-root` by the real handler, before any SNARK work (packages/node/lib/rln.mjs verifyEnvelope step 3).
    _setRecentRoots([staticRoot]);
    class FakeSocket extends EventEmitter { constructor() { super(); this.written = []; } setNoDelay() {} write(s) { this.written.push(String(s)); } destroy() { this.emit("close"); } pipe() {} }
    const handler = makeHandler(makeSpentSet({ slash: async () => {} }), {});
    const envelopeUnder = (root) => {
      const target = "example.com:443", nonce = "n-" + root;
      const x = String(calculateSignalHash(requestSignal(target, nonce)));
      const ep = currentEpoch();
      const ps = { x, y: "7", root, nullifier: "5" + root, externalNullifier: externalNullifierFor(ep).toString() };
      return JSON.stringify({ v: 4, target, nonce, proof: { snarkProof: { proof: {}, publicSignals: ps }, epoch: String(ep), rlnIdentifier: "1" }, nullifier: ps.nullifier, externalNullifier: ps.externalNullifier, share: { x, y: "7" } }) + "\n";
    };
    const drive = async (line) => {
      const s = new FakeSocket(); handler(s); s.emit("data", Buffer.from(line));
      for (let i = 0; i < 200 && !s.written.length; i++) await new Promise((r2) => setTimeout(r2, 25)); // the invited-rooted one reaches the SNARK
      return JSON.parse(s.written[0] || "{}");
    };
    const paidAck = await drive(envelopeUnder(paidRoot));
    ok(paidAck.ok === false && paidAck.err === "gate:wrong-group-root", `an invited-only gateway drops a PAID-rooted proof: ${JSON.stringify(paidAck)}`);
    const stakedAck = await drive(envelopeUnder(stakedRoot));
    ok(stakedAck.ok === false && stakedAck.err === "gate:wrong-group-root", `…and a STAKED-rooted proof: ${JSON.stringify(stakedAck)}`);
    ok(Array.isArray(stakedAck.roots) && stakedAck.roots.includes(String(staticRoot)) && !stakedAck.roots.includes(String(stakedRoot)), `a root refusal advertises the roots this node accepts (public on chain) so the client can name the stale side: ${JSON.stringify(stakedAck.roots)}`);
    const staticAck = await drive(envelopeUnder(staticRoot));
    ok(staticAck.ok === false && staticAck.err !== "gate:wrong-group-root", `an INVITED-rooted envelope passes the root check (fails later on its fake proof bytes: ${staticAck.err})`);
    _setRecentRoots([]);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: admission selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.log(`  FAIL (uncaught) ${e && e.stack ? e.stack : e}`); process.exit(1); });
