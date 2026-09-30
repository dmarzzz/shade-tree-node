// T-FEAT-7 client leaf discovery (fast lane, no chain): makeLeafSourceLoader finds WHICH set holds
// the member's leaf — members.json first, then each configured contract in order — with injected
// loaders, and names every source tried when none does. Legacy (no contract) behavior is byte-
// compatible: the static group is returned as-is. The anvil twin is test/paid-access.selftest.mjs.
//
//   node packages/node/client/leaf-source.selftest.mjs

import { makeLeafSourceLoader, makeSlotPool } from "./shade-tree-client.mjs";
import { identityFor, rateCommitmentOf, newGroup } from "../lib/rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const groupOf = (leaves) => { const g = newGroup(leaves.map(BigInt)); return { group: g, root: g.root.toString(), count: leaves.length, leaves: leaves.map(String) }; };

async function main() {
  console.log("client leaf-source discovery (T-FEAT-7):");
  const s = "0x1111", a = "0x2222", p = "0x3333", x = "0x4444";
  const leaf = (secret, limit) => rateCommitmentOf(identityFor(secret), limit).toString();
  const staticG = groupOf([leaf(s, 8), leaf("0x9", 8)]);
  const stakedG = groupOf([leaf(a, 8)]);
  const paidG = groupOf([leaf(p, 32)]);
  const contracts = [{ address: "0xA", kind: "staked" }, { address: "0xP", kind: "paid" }];
  const calls = [];
  const loadStatic = async () => { calls.push("static"); return staticG; };
  const loadContract = async ({ contract, rpcUrl, blockTag }) => { calls.push(contract + "@" + rpcUrl + (blockTag ? `#${blockTag}` : "")); if (contract === "0xA") return { ...stakedG, contract }; if (contract === "0xP") return { ...paidG, contract }; throw new Error("boom"); };
  const mk = (secret, limit) => makeLeafSourceLoader({ secret, limit, contracts, rpcUrl: "http://rpc", loadStatic, loadContract });

  let r = await mk(s, 8)();
  ok(r.source === "members.json" && r.root === staticG.root && calls.join() === "static", "static member: found in members.json, no chain read");
  calls.length = 0;
  r = await mk(a, 8)();
  ok(r.source === "staked(0xA)" && r.root === stakedG.root && calls.join() === "static,0xA@http://rpc", "staked member: members.json miss, then the staked set (order preserved)");
  calls.length = 0;
  r = await mk(p, 32)();
  ok(r.source === "paid(0xP)" && r.root === paidG.root && calls.join() === "static,0xA@http://rpc,0xP@http://rpc", "paid member: found in the paid set last");
  calls.length = 0;
  r = await makeLeafSourceLoader({ secret: a, limit: 8, env: { SHADE_TREE_STAKE_PROFILE: "public-stake-v1" }, contracts, rpcUrl: "http://rpc", loadStatic, loadContract, only: "staked" })();
  ok(r.source === "staked(0xA)" && calls.join() === "0xA@http://rpc#finalized", "public-stake-v1 leaf discovery pins the same finalized snapshot as its gateways");
  let err = null;
  try { await mk(p, 8)(); } catch (e) { err = e.message; }
  ok(/in none of: members\.json \(2 leaves\), staked\(0xA\) \(1 leaves\), paid\(0xP\) \(1 leaves\)/.test(err || "") && /must equal the tier/.test(err), "wrong --limit (paid at 32, asked 8) -> precise error naming every source + the tier hint");
  err = null;
  try { await mk(x, 8)(); } catch (e) { err = e.message; }
  ok(/is in none of/.test(err || "") && /docs\/PAYMENTS\.md/.test(err) && /register-member/.test(err), "unknown member -> error points at paid access / staking / members.json");
  // an unreadable source is reported, not fatal, and the search continues
  const flaky = makeLeafSourceLoader({ secret: p, limit: 32, contracts: [{ address: "0xZ", kind: "staked" }, ...contracts], rpcUrl: "http://rpc", loadStatic: async () => { throw new Error("ENOENT members.json"); }, loadContract });
  r = await flaky();
  ok(r.source === "paid(0xP)", "unreadable members.json + a throwing contract are skipped; the holder is still found");
  err = null;
  try { await makeLeafSourceLoader({ secret: x, limit: 8, contracts: [{ address: "0xZ", kind: "staked" }], loadStatic: async () => { throw new Error("ENOENT members.json"); }, loadContract })(); } catch (e) { err = e.message; }
  ok(/members\.json \(unreadable: ENOENT members\.json\), staked\(0xZ\) \(unreadable: boom\)/.test(err || ""), "…and the error names why each source was unusable");

  // legacy: no contract configured -> the static group, verbatim, even for a non-member / odd secret
  const legacy = makeLeafSourceLoader({ secret: "test-secret", limit: 8, contracts: [], loadStatic: async () => ({ group: null, root: "ROOT", count: 1 }), loadContract });
  r = await legacy();
  ok(r.root === "ROOT" && r.group === null && r.source === "members.json", "no contract configured -> the static loader's result as-is (pre-T-FEAT-7 behavior; fakes/tests keep working)");
  err = null;
  try { await makeLeafSourceLoader({ secret: x, limit: 8, contracts: [], loadStatic: async () => { throw new Error("ENOENT"); }, loadContract })(); } catch (e) { err = e.message; }
  ok(err === "ENOENT", "no contract configured + missing members.json -> that read error, unchanged");

  // plugs into makeSlotPool
  const pool = makeSlotPool({ secret: p, K: 32, loadGroupFn: mk(p, 32), epochOf: () => 1n, prove: async () => {} });
  const g = await pool.ensureGroup();
  ok(g && g.indexOf(BigInt(leaf(p, 32))) === 0, "makeSlotPool.ensureGroup() resolves through the discovered source");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: leaf-source selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
