// Selftest for packages/node/lib/gateway-registry.mjs — the StakeVerifier the bootnode uses to decide
// which gateways an admission=stake policy admits. Covers both providers with no chain:
// the mock (open + allowlist) and the on-chain eth_call encode/decode against a stubbed fetch.
//
//   node packages/node/lib/gateway-registry.selftest.mjs

import pkg from "js-sha3";
const { keccak256 } = pkg;
import { MockStakeVerifier, OnchainStakeVerifier, makeStakeVerifier } from "./gateway-registry.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";

async function main() {
  console.log("MockStakeVerifier:");
  {
    const open = MockStakeVerifier({});
    ok(open.mode === "mock:open", "no allowlist => open mode");
    ok((await open.isStaked(A)) === true && (await open.isStaked(B)) === true, "open mode: everyone counts as staked");

    const allow = MockStakeVerifier({ allowlist: `${A}, ${B.toUpperCase()}` });
    ok(allow.mode.startsWith("mock:allowlist"), "allowlist mode reported");
    ok((await allow.isStaked(A)) === true, "allowlisted address is staked");
    ok((await allow.isStaked(B.toLowerCase())) === true, "allowlist is case-insensitive");
    ok((await allow.isStaked("0x3333333333333333333333333333333333333333")) === false, "non-listed address is not staked");
  }

  console.log("\nmakeStakeVerifier factory resolution:");
  {
    const saved = { reg: process.env.SHADE_TREE_GATEWAY_REGISTRY, mode: process.env.SHADE_TREE_STAKE_MODE };
    delete process.env.SHADE_TREE_GATEWAY_REGISTRY; delete process.env.SHADE_TREE_STAKE_MODE;
    ok(makeStakeVerifier().mode.startsWith("mock"), "no registry => mock by default");
    ok(makeStakeVerifier("mock").mode.startsWith("mock"), "explicit mock honored");
    process.env.SHADE_TREE_GATEWAY_REGISTRY = "0x000000000000000000000000000000000000dEaD";
    ok(makeStakeVerifier().mode === "onchain", "registry set => onchain by default");
    let threw = false; try { makeStakeVerifier("bogus"); } catch { threw = true; }
    ok(threw, "unknown mode rejected");
    // restore
    if (saved.reg) process.env.SHADE_TREE_GATEWAY_REGISTRY = saved.reg; else delete process.env.SHADE_TREE_GATEWAY_REGISTRY;
    if (saved.mode) process.env.SHADE_TREE_STAKE_MODE = saved.mode; else delete process.env.SHADE_TREE_STAKE_MODE;
  }

  console.log("\nOnchainStakeVerifier eth_call encode/decode (stubbed fetch):");
  {
    const realFetch = globalThis.fetch;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    const selector = "0x" + keccak256("isStaked(address)").slice(0, 8);
    let lastCall = null, calls = 0;
    // stub: capture the eth_call, return true for A (nonzero word), false otherwise.
    globalThis.fetch = async (url, opts) => {
      calls++;
      const body = JSON.parse(opts.body);
      lastCall = { url, method: body.method, params: body.params };
      // decide by the address embedded in the calldata (last 40 hex of the 32-byte arg)
      const addr = body.params[0].data.toLowerCase().slice(-40);
      const isA = addr === A.slice(2).toLowerCase();
      return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: isA ? "0x" + "0".repeat(63) + "1" : "0x" + "0".repeat(64) }) };
    };
    try {
      const v = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 10_000 });
      ok(v.mode === "onchain", "onchain mode");
      const rA = await v.isStaked(A);
      ok(rA === true, "staked address decodes to true (nonzero return word)");
      ok(lastCall.method === "eth_call" && lastCall.params[0].to.toLowerCase() === CONTRACT.toLowerCase(), "calls eth_call on the registry address");
      ok(lastCall.params[0].data.startsWith(selector), "calldata carries the isStaked(address) selector");
      ok(lastCall.params[0].data.length === 2 + 8 + 64, "calldata = 0x + 4-byte selector + 32-byte address arg");
      ok((await v.isStaked(B)) === false, "unstaked address decodes to false (zero return word)");

      // caching: a repeat within cacheMs must not hit the RPC again
      const before = calls; await v.isStaked(A);
      ok(calls === before, "result is cached within cacheMs (no duplicate RPC)");

      // bad address input rejected before any RPC
      let threw = false; try { await v.isStaked("not-an-address"); } catch { threw = true; }
      ok(threw, "malformed address is rejected");
    } finally { globalThis.fetch = realFetch; }
  }

  console.log("\nOnchainStakeVerifier fail-closed on bad RPC responses:");
  {
    const realFetch = globalThis.fetch;
    try {
      // 1. an RPC-level error must THROW, so a caller in requireStake mode rejects (never admits).
      globalThis.fetch = async () => ({ json: async () => ({ jsonrpc: "2.0", id: 1, error: { message: "node down" } }) });
      const v1 = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: "0xabcabcabcabcabcabcabcabcabcabcabcabcabca", cacheMs: 0 });
      let threw = false; try { await v1.isStaked("0x1111111111111111111111111111111111111111"); } catch { threw = true; }
      ok(threw, "an RPC error throws (caller fails closed), never silently returns staked");

      // 2. an empty "0x" (no return data, e.g. wrong address / not a contract) decodes to false.
      globalThis.fetch = async () => ({ json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x" }) });
      const v2 = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: "0xabcabcabcabcabcabcabcabcabcabcabcabcabca", cacheMs: 0 });
      ok((await v2.isStaked("0x1111111111111111111111111111111111111111")) === false, "empty 0x return decodes to not-staked (fail-closed)");
    } finally { globalThis.fetch = realFetch; }
  }

  console.log("\nError messages are asserted verbatim (blanking the throw strings must be caught):");
  {
    // (1a) missing GatewayRegistry address: assert the message names the env var, not just that it throws.
    let msg = "";
    try { OnchainStakeVerifier({ contract: "" }); } catch (e) { msg = e.message; }
    ok(/SHADE_TREE_GATEWAY_REGISTRY/.test(msg), "missing contract throws a message naming SHADE_TREE_GATEWAY_REGISTRY");

    // (1b) unknown stake mode: assert the message names the env var, echoes the bad value, and lists the valid set.
    let msg2 = "";
    try { makeStakeVerifier("bogus"); } catch (e) { msg2 = e.message; }
    ok(/unknown SHADE_TREE_STAKE_MODE/.test(msg2), "unknown mode throws a message naming SHADE_TREE_STAKE_MODE");
    ok(/bogus/.test(msg2) && /onchain\|mock/.test(msg2), "unknown-mode message echoes the bad value and the expected onchain|mock set");
  }

  console.log("\nMockStakeVerifier allowlist filter(Boolean) drops empty entries:");
  {
    // (4) trailing comma => a blank entry; filter(Boolean) must drop it so the set size (and mode) is 1, not 2.
    const allow = MockStakeVerifier({ allowlist: `${A},` });
    ok(allow.mode === "mock:allowlist(1)", "trailing-comma allowlist => size 1, blank entry dropped (kills .filter(Boolean) removal)");
    ok((await allow.isStaked(A)) === true, "the real address is still staked");
    ok((await allow.isStaked("")) === false, "empty-string operator is NOT staked (the blank entry never entered the set)");

    const allow2 = MockStakeVerifier({ allowlist: `${A},,${B}` });
    ok(allow2.mode === "mock:allowlist(2)", "double-comma allowlist => size 2, blank middle entry dropped");
  }

  console.log("\nOnchainStakeVerifier cache-expiry boundary + case-folded cache key (injected clock):");
  {
    const realFetch = globalThis.fetch;
    const realNow = Date.now;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    let calls = 0;
    globalThis.fetch = async (_url, opts) => {
      calls++;
      const body = JSON.parse(opts.body);
      return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x" + "0".repeat(63) + "1" }) };
    };
    try {
      // (2) expiry edge: reused strictly UNDER cacheMs, refetched AT cacheMs. Pins `<` vs `<=`.
      let clock = 100000;
      Date.now = () => clock;
      const v = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 1000 });
      const addr = "0x1111111111111111111111111111111111111111";

      calls = 0;
      await v.isStaked(addr);                 // populate cache at t=100000
      ok(calls === 1, "first read hits the RPC once (cache populated)");

      clock = 100000 + 999;                   // now - at = 999 < 1000 => cached
      await v.isStaked(addr);
      ok(calls === 1, "999ms later (just under cacheMs): served from cache, no new RPC");

      clock = 100000 + 1000;                  // now - at = 1000, NOT < 1000 => must refetch
      await v.isStaked(addr);
      ok(calls === 2, "exactly at cacheMs (1000ms): cache expired, RPC refetched (kills `<` -> `<=`)");

      // (3) case-folded cache key: 0xAbC... and 0xabc... are one operator => one cache entry.
      const mixed = "0xABCdef" + "0".repeat(33) + "1"; // 0x + 40 hex, mixed case
      calls = 0;
      clock = 200000;
      await v.isStaked(mixed);                // 0xABCdef...1
      ok(calls === 1, "first mixed-case read hits the RPC");
      await v.isStaked(mixed.toLowerCase());  // same address, all lower
      ok(calls === 1, "differently-cased SAME address hits the SAME cache entry (kills cache-key .toLowerCase() drop)");
    } finally { globalThis.fetch = realFetch; Date.now = realNow; }
  }

  console.log("\nOnchainStakeVerifier return-shape guards (non-string return + odd zero-padding):");
  {
    const realFetch = globalThis.fetch;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    const addr = "0x1111111111111111111111111111111111111111";
    const stubResult = (result) => async (_url, opts) => {
      const body = JSON.parse(opts.body);
      return { json: async () => ({ jsonrpc: "2.0", id: body.id, result }) };
    };
    try {
      // (5a) non-string return (misbehaving RPC hands back null / a number): the `typeof ret === "string"`
      // guard must short-circuit to not-staked and NEVER throw (a dropped guard would `null.replace(...)` throw).
      globalThis.fetch = stubResult(null);
      const vNull = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      let threw = false, res;
      try { res = await vNull.isStaked(addr); } catch { threw = true; }
      ok(threw === false && res === false, "null return => not-staked and does NOT throw (typeof guard holds)");

      globalThis.fetch = stubResult(1);
      const vNum = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      let threw2 = false, res2;
      try { res2 = await vNum.isStaked(addr); } catch { threw2 = true; }
      ok(threw2 === false && res2 === false, "numeric return => not-staked and does NOT throw (typeof guard holds)");

      // (5b) odd zero-padding: high nibble set, all-zero tail. The /^0x0*/ anchor strips only the prefix zeros.
      globalThis.fetch = stubResult("0xa" + "0".repeat(63));
      const vHi = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      ok((await vHi.isStaked(addr)) === true, "leading-nonzero odd padding (0xa000...) decodes to staked");

      // single low nonzero nibble after a full run of leading zeros still decodes true.
      globalThis.fetch = stubResult("0x" + "0".repeat(63) + "3");
      const vLo = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      ok((await vLo.isStaked(addr)) === true, "single low nonzero nibble after full zero padding decodes to staked");

      // a genuinely all-zero return remains not-staked (anchors the false side of the parse).
      globalThis.fetch = stubResult("0x" + "0".repeat(64));
      const vZero = OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      ok((await vZero.isStaked(addr)) === false, "fully zero-padded return decodes to not-staked");
    } finally { globalThis.fetch = realFetch; }
  }

  // blockTag() reorg-safety branch. SHADE_TREE_CONFIRMATIONS is captured at module-eval time
  // (a top-level const), so we re-import the module under a cache-busting specifier per env
  // value. The stake read must target head-N (an OLDER, confirmed block) so a reorg can't
  // flash a fake stake at the tip; with confirmations unset it must stay byte-identical to
  // today and read at "latest".
  console.log("\nOnchainStakeVerifier reads stake at a confirmed depth (head-N) when SHADE_TREE_CONFIRMATIONS>0:");
  {
    const realFetch = globalThis.fetch;
    const savedConf = process.env.SHADE_TREE_CONFIRMATIONS;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    const addr = "0x1111111111111111111111111111111111111111";
    try {
      process.env.SHADE_TREE_CONFIRMATIONS = "6";
      const mod = await import("./gateway-registry.mjs?conf=6");

      const HEAD_HEX = "0x1000"; // 4096
      let blockCalls = 0, callTag = null;
      globalThis.fetch = async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.method === "eth_getBlockByNumber") {
          blockCalls++;
          // the tip is fetched at "latest", then we step back N confirmations from it.
          ok(body.params[0] === "latest", "head is fetched via eth_getBlockByNumber('latest', false)");
          return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: { number: HEAD_HEX } }) };
        }
        callTag = body.params[1]; // eth_call block tag
        return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x" + "0".repeat(63) + "1" }) };
      };

      const v = mod.OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      const res = await v.isStaked(addr);
      ok(res === true, "stake still decodes on the head-N branch (eth_call bool preserved)");
      ok(blockCalls === 1, "confirmations>0 => fetches the head before reading stake");
      // 4096 - 6 = 4090 = 0xffa
      ok(callTag === "0xffa", `stake is read at head-N (0x1000 - 6 = 0xffa), got ${callTag}`);
      ok(callTag !== "latest", "confirmations>0 does NOT read at 'latest' (reorg-safety branch active)");
    } finally {
      globalThis.fetch = realFetch;
      if (savedConf === undefined) delete process.env.SHADE_TREE_CONFIRMATIONS; else process.env.SHADE_TREE_CONFIRMATIONS = savedConf;
    }
  }

  console.log("\nOnchainStakeVerifier reads at 'latest' when SHADE_TREE_CONFIRMATIONS unset/0 (byte-identical to today):");
  {
    const realFetch = globalThis.fetch;
    const savedConf = process.env.SHADE_TREE_CONFIRMATIONS;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    const addr = "0x1111111111111111111111111111111111111111";
    try {
      delete process.env.SHADE_TREE_CONFIRMATIONS;
      const mod = await import("./gateway-registry.mjs?conf=unset");
      let blockCalls = 0, callTag = null;
      globalThis.fetch = async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.method === "eth_getBlockByNumber") {
          blockCalls++;
          return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: { number: "0x1000" } }) };
        }
        callTag = body.params[1];
        return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x" + "0".repeat(63) + "1" }) };
      };
      const v = mod.OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      await v.isStaked(addr);
      ok(callTag === "latest", "confirmations unset => stake read at 'latest'");
      ok(blockCalls === 0, "confirmations unset => no head lookup (head-N branch skipped entirely)");
    } finally {
      globalThis.fetch = realFetch;
      if (savedConf === undefined) delete process.env.SHADE_TREE_CONFIRMATIONS; else process.env.SHADE_TREE_CONFIRMATIONS = savedConf;
    }
  }

  console.log("\nOnchainStakeVerifier head-N boundary + hex encoding (depth deeper than head clamps to 0x0):");
  {
    const realFetch = globalThis.fetch;
    const savedConf = process.env.SHADE_TREE_CONFIRMATIONS;
    const CONTRACT = "0xabcabcabcabcabcabcabcabcabcabcabcabcabca";
    const addr = "0x1111111111111111111111111111111111111111";
    try {
      // depth 100 vs a head of 5 => head-N is negative => Math.max(0, ...) clamps to block 0.
      process.env.SHADE_TREE_CONFIRMATIONS = "100";
      const mod = await import("./gateway-registry.mjs?conf=100");
      let callTag = null;
      const headHex = { v: "0x5" };
      globalThis.fetch = async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.method === "eth_getBlockByNumber") {
          return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: { number: headHex.v } }) };
        }
        callTag = body.params[1];
        return { json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x" + "0".repeat(63) + "1" }) };
      };
      const vClamp = mod.OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      await vClamp.isStaked(addr);
      ok(callTag === "0x0", `depth deeper than head clamps to block 0 ('0x0'), got ${callTag}`);

      // hex format: head 0xff (255) - 100 = 155 = 0x9b — compact, lowercase, 0x-prefixed (no leading zeros).
      headHex.v = "0xff";
      const vFmt = mod.OnchainStakeVerifier({ rpcUrl: "http://stub", contract: CONTRACT, cacheMs: 0 });
      await vFmt.isStaked(addr);
      ok(callTag === "0x9b", `head-N is encoded as compact 0x-hex (0xff - 100 = 0x9b), got ${callTag}`);
    } finally {
      globalThis.fetch = realFetch;
      if (savedConf === undefined) delete process.env.SHADE_TREE_CONFIRMATIONS; else process.env.SHADE_TREE_CONFIRMATIONS = savedConf;
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: gateway-registry selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
