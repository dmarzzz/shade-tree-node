// T-FEAT-7 gateway unit tests (fast lane, no chain): the root-SOURCE resolution (the deprecated
// SHADE_TREE_ROOTS spelling; SHADE_TREE_ADMIT proper is gateway/admission.selftest.mjs), the ABI-file `roots:` startup line, and the ROUTING slasher
// (makeRoutingSlasher over a fake `ethers` — a reconstructed secret is slashed on the contract
// whose limitOf() holds its leaf; none => the primary gets the default claim). The anvil end-to-end
// twin is test/paid-access.selftest.mjs (slow lane).
//
//   node gateway/root-sources.selftest.mjs

import { resolveRootSources, describeRootSources, makeRoutingSlasher, makeOnchainSlasher, PAID_MIN_LEAVES, initRoots, _getRecentRoots, _setRecentRoots } from "./gateway.mjs";
import { Interface } from "ethers";
import { registry as gatewayMetrics } from "../lib/metrics.mjs";
import { identityFor, identitySecretOf, deriveCommitment, K_SLOTS } from "../lib/rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// A fake `ethers` whose Contract answers the slasher's probes from a per-address table:
//   { tiered: bool, tiers: [..], holds: { commitment: limit }, active: Set } and records slash calls.
function fakeEthers(table, calls) {
  class Contract {
    constructor(address, abi) { this.interface = new Interface(abi); this.address = address; this.t = table[address]; if (!this.t) throw new Error("unknown contract " + address); }
    async DEFAULT_LIMIT() { if (!this.t.tiered) throw new Error("no DEFAULT_LIMIT"); return 8n; }
    async allowedLimits() { return (this.t.tiers || [8]).map(BigInt); }
    async limitOf(c) { return BigInt(this.t.holds?.[String(c)] || 0); }
    async isActive(c) { return !!this.t.active?.has(String(c)); }
    async "slash(uint256,uint256,uint256,address)"(leaf, secret, limit, receiver) { calls.push({ via: this.address, leaf: String(leaf), limit: Number(limit), receiver }); return { hash: "0xtx" + calls.length, wait: async () => ({ blockNumber: 7, logs: this.t.logs || [] }) }; }
    async "slash(uint256,uint256,address)"(leaf, secret, receiver) { calls.push({ via: this.address, leaf: String(leaf), limit: null, receiver }); return { hash: "0xtx" + calls.length, wait: async () => ({ blockNumber: 7, logs: this.t.logs || [] }) }; }
  }
  return { Contract };
}

async function main() {
  console.log("root sources + routing slasher (T-FEAT-7):");
  const A = { address: "0xA", kind: "staked" }, P = { address: "0xP", kind: "paid" };

  // 1. SHADE_TREE_ROOTS resolution
  {
    let r = resolveRootSources({ spec: "", contracts: [], staticExists: true });
    ok(r.static === true && r.onchain === false, "no contract, members.json present -> static only (PoC path)");
    r = resolveRootSources({ spec: "", contracts: [], staticExists: false });
    ok(r.static === true && r.onchain === false, "no contract, no members.json -> still static (loadGroup reports the missing file, as before)");
    // T-FEAT-9 (docs/adr/0008): the default is `invited` (members.json) ALONE even with contracts
    // configured -- a provider opts into staked/paid via SHADE_TREE_ADMIT (gateway/admission.selftest.mjs).
    r = resolveRootSources({ spec: "", contracts: [A], staticExists: true });
    ok(r.static === true && r.onchain === false, "contract + members.json, SHADE_TREE_ROOTS/SHADE_TREE_ADMIT unset -> invited only (T-FEAT-9 max-anon default; opt in with SHADE_TREE_ADMIT)");
    r = resolveRootSources({ spec: "", contracts: [A, P], staticExists: false });
    ok(r.static === true && r.onchain === false, "contracts, no members.json, nothing set -> still invited only (initRoots then fails closed on the missing members.json)");
    r = resolveRootSources({ spec: "onchain", contracts: [A], staticExists: true });
    ok(r.static === false && r.onchain === true && r.explicit, "SHADE_TREE_ROOTS=onchain -> chain alone even with members.json present");
    r = resolveRootSources({ spec: "static", contracts: [A], staticExists: true });
    ok(r.static === true && r.onchain === false, "SHADE_TREE_ROOTS=static -> ignore configured contracts");
    r = resolveRootSources({ spec: " Static , ONCHAIN ", contracts: [A], staticExists: true });
    ok(r.static && r.onchain, "SHADE_TREE_ROOTS=static,onchain (case/space tolerant) -> both");
    let threw = null;
    try { resolveRootSources({ spec: "onchain", contracts: [], staticExists: true }); } catch (e) { threw = e.message; }
    ok(/no contract is configured/.test(threw || ""), "SHADE_TREE_ROOTS=onchain without a contract is a config error");
    threw = null;
    try { resolveRootSources({ spec: "chain", contracts: [A], staticExists: true }); } catch (e) { threw = e.message; }
    ok(/unknown source "chain"/.test(threw || ""), "an unknown source name is rejected");
  }

  // 2. the ABI-file startup line
  {
    ok(describeRootSources({ static: true, contracts: [A, P] }) === "roots: members.json + staked(0xA) + paid(0xP)", "`roots: members.json + staked(0x..) + paid(0x..)`");
    ok(describeRootSources({ static: false, contracts: [P] }) === "roots: paid(0xP)", "paid alone");
    ok(describeRootSources({ static: true, contracts: [] }) === "roots: members.json", "static alone");
    ok(PAID_MIN_LEAVES === 8, "paid floor default K=8 (SHADE_TREE_PAID_MIN_LEAVES)");
  }

  // 3. routing slasher over a fake ethers
  {
    const secret = identitySecretOf(identityFor("0x1234"));
    const leaf8 = deriveCommitment(secret, 8), leaf32 = deriveCommitment(secret, 32);
    const secretB = identitySecretOf(identityFor("0x5678"));
    const leafB8 = deriveCommitment(secretB, 8);
    const secretC = identitySecretOf(identityFor("0x9abc"));
    const calls = [];
    const ethers = fakeEthers({
      "0xV3": { tiered: false, active: new Set([leafB8]) },                    // rln-v3 primary holds B at tier 8
      "0xA": { tiered: true, tiers: [8, 32], holds: {} },                       // staked set holds nobody
      "0xP": { tiered: true, tiers: [8, 32], holds: { [leaf32]: 32 } },         // paid set holds A's tier-32 leaf
    }, calls);
    const wallet = {};
    const route = await makeRoutingSlasher({ ethers, wallet, contracts: [{ address: "0xV3", kind: "primary" }, A, P], receiver: "0xR" });
    ok(route.slashers.length === 3 && route.slashers[0].slash.tiered() === false && route.slashers[2].slash.tiered() === true, "one slasher per contract; v3 vs tiered detected per contract");

    // secret A: unresolved locally (default tier named) -> paid holds leaf32 -> slashed on 0xP at limit 32
    let r = await route(leaf8, secret, { commitment: leaf8, limit: K_SLOTS, resolved: false });
    ok(r.contract === "0xP" && r.limit === 32 && r.commitment === leaf32 && calls.at(-1).via === "0xP" && calls.at(-1).limit === 32, "over-spender held by the PAID set -> slash routed to 0xP at its tier (32), leaf recomputed there");
    // secret B: rln-v3 primary holds it (isActive) -> 3-arg slash on 0xV3
    r = await route(leafB8, secretB, { commitment: leafB8, limit: 8, resolved: false });
    ok(r.contract === "0xV3" && calls.at(-1).via === "0xV3" && calls.at(-1).limit === null, "over-spender held by the rln-v3 primary -> 3-arg slash there");
    // secret C: nobody holds it -> primary gets the default claim (revert on record), nothing elsewhere
    const before = calls.length;
    r = await route(deriveCommitment(secretC, 8), secretC, { commitment: deriveCommitment(secretC, 8), limit: 8, resolved: false });
    ok(r.contract === "0xV3" && calls.length === before + 1 && calls.at(-1).via === "0xV3", "held by nobody -> the default claim goes to the primary only");
    // locally-resolved tier (members.json leaf) still routes by holder, not by the local guess
    r = await route(leaf8, secret, { commitment: leaf8, limit: 8, resolved: true });
    ok(r.contract === "0xP" && r.limit === 32, "a locally-resolved tier does not override the on-chain holder");
    // holds() probe failure on one contract skips it (never blocks the others)
    const bad = fakeEthers({ "0xA": { tiered: true, tiers: [8], holds: {} }, "0xP": { tiered: true, tiers: [8, 32], holds: { [leaf32]: 32 } } }, calls);
    const origLimitOf = bad.Contract.prototype.limitOf;
    bad.Contract.prototype.limitOf = async function (c) { if (this.address === "0xA") throw new Error("rpc down"); return origLimitOf.call(this, c); };
    const route2 = await makeRoutingSlasher({ ethers: bad, wallet, contracts: [A, P], receiver: "0xR" });
    r = await route2(leaf8, secret, { commitment: leaf8, limit: 8, resolved: false });
    ok(r.contract === "0xP", "a contract whose probe throws is skipped; the holder is still found");
    // single-contract slasher: holds() exposed
    const single = await makeOnchainSlasher({ ethers, wallet, address: "0xP", receiver: "0xR" });
    ok((await single.holds(secret)).limit === 32 && (await single.holds(secretC)) === null && single.address === "0xP", "makeOnchainSlasher.holds(secret) names the tier the contract holds (or null)");
  }

  // Slash payout reporting uses only a matching event from the configured contract.
  {
    const secret = identitySecretOf(identityFor("0x1234"));
    const leaf = deriveCommitment(secret, 8);
    const address = "0x00000000000000000000000000000000000000AA";
    const receiver = "0x00000000000000000000000000000000000000BB";
    const iface = new Interface(["event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward)"]);
    const event = (via, commitment, burned, reward) => ({ address: via, ...iface.encodeEventLog(iface.getEvent("SlashPayout"), [commitment, receiver, burned, reward]) });
    const logs = [
      event(receiver, leaf, 999n, 999n), // foreign emitter
      { address, topics: ["0x00"], data: "0x" }, // malformed event
      event(address, BigInt(leaf) + 1n, 888n, 888n), // another leaf
    ];
    const table = { [address]: { tiered: true, tiers: [8], holds: { [leaf]: 8 }, logs } };
    const slash = await makeOnchainSlasher({ ethers: fakeEthers(table, []), wallet: {}, address, receiver });
    let result = await slash(leaf, secret, { resolved: true, commitment: leaf, limit: 8 });
    ok(result.burnedWei === undefined && result.rewardWei === undefined, "unrelated or malformed logs never claim a payout split");
    logs.push(event(address.toLowerCase(), leaf, 91n, 10n));
    result = await slash(leaf, secret, { resolved: true, commitment: leaf, limit: 8 });
    ok(result.burnedWei === "91" && result.rewardWei === "10", "matching mined SlashPayout reports the actual burn and bounty");
  }

  // 5. STARTUP posture of initRoots (fleet crash-loop 2026-08-17: eth_getLogs range cap at boot):
  //    a chain source that cannot be read at startup is FAIL-SOFT when a static root is trusted
  //    (serve members.json, gauge degraded=1, recover on the provider's next successful read) and
  //    FAIL-CLOSED (throws -> exit) when NO root would be trusted at all.
  {
    console.log("\ninitRoots startup posture (fail-soft with a static root / fail-closed without):");
    const staticRoot = "424242";
    const loadStatic = async () => ({ root: staticRoot, count: 2, leaves: ["1", "2"] });
    const noWatch = () => {};
    // a provider that fails N times, then serves roots; onChange delivers a manual `poll()` hook
    const flaky = (failures0, roots) => {
      let left = failures0; let cb = null;
      const p = {
        contract: "0xA",
        currentRoots: async () => { if (left > 0) { left--; throw new Error("eth_getLogs: exceed maximum block range: 50000"); } return { roots, observedAtBlock: 5, finalized: true, leafCount: roots.length }; },
        onChange: (fn) => { cb = fn; return () => {}; },
        describe: () => ({ provider: "node", contract: "0xA" }),
        poll: async () => { if (cb) await cb(); },
      };
      return p;
    };
    const A = { address: "0xA", kind: "staked" };
    const scrape = () => gatewayMetrics.render();

    // fail-soft: static root present, chain down at boot
    _setRecentRoots([]);
    let prov = flaky(1, ["777"]);
    let r = await initRoots({ contracts: [A], want: { static: true, onchain: true }, loadStatic, makeProvider: () => prov, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(r.degraded.join() === "0xa" && _getRecentRoots().has(staticRoot) && _getRecentRoots().size === 1, "chain source down at boot + members.json root -> starts DEGRADED serving the static root only");
    ok(/shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 1/.test(scrape()), "shade_tree_gateway_root_source_degraded{source=\"staked\"} 1");
    await prov.poll(); // the provider's own poll recovers -> refresh merges the chain root
    ok(_getRecentRoots().has("777") && _getRecentRoots().has(staticRoot) && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 0/.test(scrape()), "next successful read -> chain root unioned in, degraded back to 0 (no restart needed)");

    // fail-closed: no static root at all -> throws (main() exits nonzero; systemd restarts = the retry)
    _setRecentRoots([]);
    let threw = null;
    try { await initRoots({ contracts: [A], want: { static: false, onchain: true }, loadStatic, makeProvider: () => flaky(9, ["777"]), watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" }); } catch (e) { threw = e.message; }
    ok(/no admission root available/.test(threw || "") && /exceed maximum block range/.test(threw || ""), "chain source down + NO static root -> refuses to start (fail closed), naming the RPC error");
    // fail-closed too when members.json is wanted but EMPTY (root null): nothing to serve
    threw = null;
    try { await initRoots({ contracts: [A], want: { static: true, onchain: true }, loadStatic: async () => ({ root: null, count: 0, leaves: [] }), makeProvider: () => flaky(9, ["777"]), watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" }); } catch (e) { threw = e.message; }
    ok(/no admission root available/.test(threw || ""), "an EMPTY members.json is not a fallback root -> still fail closed");

    // partial failure inside a composite (one of two chain sources) is degraded, not fatal, and heals
    _setRecentRoots([]);
    const P = { address: "0xP", kind: "paid" };
    const good = { contract: "0xP", currentRoots: async () => ({ roots: ["999"], observedAtBlock: 5, finalized: true, leafCount: 1 }), onChange: () => () => {}, describe: () => ({ provider: "node", contract: "0xP" }) };
    const badChild = flaky(1, ["777"]);
    const { CompositeRootProvider } = await import("../lib/root-provider.mjs");
    const comp = CompositeRootProvider([badChild, good]);
    r = await initRoots({ contracts: [A, P], want: { static: false, onchain: true }, loadStatic, makeProvider: () => comp, watchFile: noWatch, pollIntervalMs: 5, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(r.degraded.join() === "0xa" && _getRecentRoots().has("999") && !_getRecentRoots().has("777"), "one of two chain sources down at boot -> serve the other, that one degraded (composite errors[])");
    for (let i = 0; i < 50 && !_getRecentRoots().has("777"); i++) await new Promise((resolve) => setTimeout(resolve, 2));
    ok(_getRecentRoots().has("777") && _getRecentRoots().has("999") && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 0/.test(scrape()), "it heals on its next successful read");
    r.close();

    // A provider with an established LKG returns that root with stale:true instead of throwing.
    // The gateway must retain the root while making the bounded source gauge reflect the outage,
    // then clear the gauge after the next fresh read.
    let stale = false;
    let stalePoll = null;
    const cached = {
      contract: "0xA",
      currentRoots: async () => ({
        roots: ["1234"],
        observedAtBlock: 8,
        finalized: true,
        leafCount: 1,
        stale,
        ...(stale ? { error: "RPC path sentinel should stay out of metrics" } : {}),
      }),
      onChange: (fn) => { stalePoll = fn; return () => {}; },
      describe: () => ({ provider: "node", contract: "0xA" }),
    };
    _setRecentRoots([]);
    await initRoots({ contracts: [A], want: { static: false, onchain: true }, loadStatic, makeProvider: () => cached, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(_getRecentRoots().has("1234") && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 0/.test(scrape()), "fresh provider read -> cached root trusted, degraded gauge 0");
    stale = true;
    await stalePoll();
    const staleScrape = scrape();
    ok(_getRecentRoots().has("1234") && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 1/.test(staleScrape), "later provider outage -> keep LKG root and set bounded degraded gauge 1");
    ok(!/0xa|sentinel|rpc path/i.test(staleScrape), "degraded metrics expose neither contract addresses nor provider errors");
    stale = false;
    await stalePoll();
    ok(_getRecentRoots().has("1234") && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 0/.test(scrape()), "provider recovery -> keep root and clear degraded gauge");
    _setRecentRoots([]);

    // Once the provider reports that its bounded LKG has expired, the gateway
    // removes every on-chain root immediately. The same root may be restored only
    // by a later successful refresh.
    let expiryPoll = null;
    const expiring = {
      contract: "0xA",
      currentRoots: async () => ({ roots: ["5678"], observedAtBlock: 9, finalized: true, leafCount: 1 }),
      onChange: (fn) => { expiryPoll = fn; return () => {}; },
      describe: () => ({ provider: "node", contract: "0xA" }),
    };
    await initRoots({ contracts: [A], want: { static: false, onchain: true }, loadStatic, makeProvider: () => expiring, watchFile: noWatch, quiet: true, rpcUrl: "http://127.0.0.1:1" });
    ok(_getRecentRoots().has("5678"), "fresh on-chain root is admitted before its freshness window expires");
    await expiryPoll([], new Error("freshness expired"));
    ok(_getRecentRoots().size === 0 && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 1/.test(scrape()), "expired LKG is removed so on-chain admission fails closed");
    await expiryPoll(["5678"], null);
    ok(_getRecentRoots().has("5678") && /shade_tree_gateway_root_source_degraded\{[^}]*source="staked"[^}]*\} 0/.test(scrape()), "fresh read after expiry restores the root and clears degraded state");
    _setRecentRoots([]);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: root-sources selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
