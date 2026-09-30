// T-DEV-9b: the Helios stateRoot anchor (packages/node/lib/helios-root.mjs) wired into LightClientRootProvider
// (packages/node/lib/root-provider.mjs). Two in-process HTTP JSON-RPC fakes stand in for the LOCAL Helios
// verifying RPC and the ordinary upstream RPC, and the provider is driven end to end against
// REAL single-entry account/storage tries (the same construction as root-provider-light.selftest).
//
// Asserted:
//   1. hook honoured: with SHADE_TREE_HELIOS_RPC_URL (heliosRpcUrl) the provider anchors the EIP-1186
//      proof to Helios' finalized stateRoot, surfaces the golden root, reports stateRootVerified,
//      and describe() names the source "helios (sync-committee verified)"; without it describe()
//      says the stateRoot is RPC-trusted (unchanged default path).
//   2. chainId: Helios on a different chain than the RPC (or than SHADE_TREE_HELIOS_CHAIN_ID) -> the
//      provider REJECTS at first use with "chainId mismatch"; a matching explicit chain id passes.
//   3. unreachable Helios / non-JSON / JSON-RPC error / null block / malformed header -> REJECT
//      with a reason that names helios (never a silent fallback to the RPC header).
//   4. THE ATTACK: the RPC lies about the block's stateRoot -> rejected with the precise
//      "stateRoot mismatch ... RPC ... claims X but the anchor ... attests Y" reason, both when the
//      RPC's proof is stale-honest and when the RPC serves a fully self-consistent fake world.
//   5. tag mapping: "finalized" -> Helios asked "finalized"; a numeric tag -> hex; "latest" passes
//      through; Helios' out-of-sync error / null propagate as rejections.
//   6. Helios-lies (simulated): if the ANCHOR attests a fake world that the RPC serves
//      consistently, the provider accepts it -- by construction; the anchor's trust is the sync
//      committee (docs/LIGHT-CLIENT.md). Recorded here so the boundary is explicit, not implied.
//   7. SHADE_TREE_HELIOS_RPC_URL with SHADE_TREE_ROOT_PROVIDER=node is a refused misconfig (fail closed).
//
//   node packages/node/lib/helios-root.selftest.mjs

import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { keccak256, encodeRlp, getBytes } from "ethers";
import { LightClientRootProvider } from "./root-provider.mjs";
import { makeHeliosTrustedStateRoot } from "./helios-root.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
async function rejects(fn, re, msg) {
  try { await fn(); ok(false, `${msg} (expected rejection)`); }
  catch (e) { ok(re.test(e.message), `${msg}${re.test(e.message) ? "" : ` -- got: ${e.message}`}`); }
}

// ---- trie builders (single-entry secure tries; identical to root-provider-light.selftest) ---
const nibbles = (hex) => [...getBytes(hex)].flatMap((b) => [b >> 4, b & 0x0f]);
function hpEncode(nibs, isLeaf) {
  const flag = isLeaf ? 2 : 0;
  const odd = nibs.length % 2 === 1;
  const bytes = [];
  if (odd) bytes.push(((flag | 1) << 4) | nibs[0]); else bytes.push(flag << 4);
  for (let i = odd ? 1 : 0; i < nibs.length; i += 2) bytes.push((nibs[i] << 4) | nibs[i + 1]);
  return "0x" + bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}
function minimalHex(v) {
  if (v === 0n) return "0x";
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return "0x" + h;
}
function singleEntryTrie(rawKeyHex, valueFieldHex) {
  const leaf = encodeRlp([hpEncode(nibbles(keccak256(rawKeyHex)), true), valueFieldHex]);
  return { root: keccak256(leaf), proof: [leaf] };
}
const CONTRACT = "0xdae242ae3ecd18e5f74d5e96332fcd4682eb20fc";
const SLOT_HEX = "0x" + (3).toString(16).padStart(64, "0");
const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const GOLDEN_ROOT = 14367190620832145537223890636337926502210861635134078778082353204233456513838n;
// A "world": the state a chain (honest or fake) commits to for slot 3 = rootValue.
function world(rootValue) {
  const storage = singleEntryTrie(SLOT_HEX, encodeRlp(minimalHex(rootValue)));
  const account = singleEntryTrie(CONTRACT, encodeRlp(["0x", "0x", storage.root, EMPTY_CODE_HASH]));
  return {
    stateRoot: account.root,
    proof: { accountProof: account.proof, storageHash: storage.root, storageProof: [{ key: SLOT_HEX, value: minimalHex(rootValue), proof: storage.proof }] },
  };
}

// ---- in-process JSON-RPC fakes ------------------------------------------------------------
// handler(method, params, seen) -> result | { __error: msg } | { __raw: string }
async function fakeRpc(handler) {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      let j;
      try { j = JSON.parse(body); } catch { res.writeHead(400).end("bad"); return; }
      seen.push({ method: j.method, params: j.params });
      const r = handler(j.method, j.params, seen);
      res.setHeader("content-type", "application/json");
      if (r && r.__raw !== undefined) { res.end(r.__raw); return; }
      if (r && r.__error) { res.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, error: { code: 1, message: r.__error } })); return; }
      res.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, result: r === undefined ? null : r }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, seen, close: () => new Promise((r) => srv.close(r)) };
}
const SEPOLIA = "0xaa36a7";
const N = 0xafa12b; // block number both sides talk about
const hexN = "0x" + N.toString(16);
// A well-behaved Helios: chain SEPOLIA, finalized/latest/hexN -> header of `w`.
const heliosFor = (w, { chainId = SEPOLIA, header = null } = {}) => (m, p) => {
  if (m === "eth_chainId") return chainId;
  if (m === "eth_getBlockByNumber") {
    const tag = p[0];
    if (tag === "finalized" || tag === "latest" || tag === hexN) return header || { number: hexN, hash: "0x" + "ab".repeat(32), stateRoot: w.stateRoot };
    return null;
  }
  return { __error: `method ${m} not supported by fake helios` };
};
// A well-behaved upstream RPC serving world `w` (header + proof), optionally lying.
const rpcFor = (w, { headerStateRoot = null, proofWorld = null, chainId = SEPOLIA } = {}) => (m, p) => {
  if (m === "eth_chainId") return chainId;
  if (m === "eth_getBlockByNumber") return { number: hexN, stateRoot: headerStateRoot || w.stateRoot };
  if (m === "eth_getProof") return (proofWorld || w).proof;
  return null;
};

async function main() {
  const honest = world(GOLDEN_ROOT);
  const fake = world(GOLDEN_ROOT + 7n); // an attacker's tree (their own commitments)

  // ---- 1. hook honoured ------------------------------------------------------------------
  console.log("1. hook honoured (Helios anchor):");
  {
    const helios = await fakeRpc(heliosFor(honest));
    const rpc = await fakeRpc(rpcFor(honest));
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, heliosRpcUrl: helios.url });
    const d = p.describe();
    ok(d.stateRootSource === "helios (sync-committee verified)" && d.stateRootVerified === true, `describe(): stateRootSource = ${d.stateRootSource}`);
    const res = await p.currentRoots();
    ok(res.roots.length === 1 && res.roots[0] === GOLDEN_ROOT.toString(), "provider surfaces the golden on-chain root anchored to Helios' stateRoot");
    ok(res.stateRootVerified === true && res.verified === true && res.observedAtBlock === N && res.finalized === true, "result: verified, stateRootVerified, block + finalized from the anchor");
    ok(helios.seen.some((s) => s.method === "eth_chainId") && helios.seen.some((s) => s.method === "eth_getBlockByNumber" && s.params[0] === "finalized"), "Helios asked eth_chainId (startup) then eth_getBlockByNumber('finalized')");
    ok(!helios.seen.some((s) => s.method === "eth_getProof"), "the proof itself is fetched from the RPC, not Helios (Helios is only the header anchor)");
    ok(rpc.seen.some((s) => s.method === "eth_getBlockByNumber" && s.params[0] === hexN) && rpc.seen.some((s) => s.method === "eth_getProof" && s.params[2] === hexN), "RPC cross-checked at the anchored block NUMBER and proof pinned to it");
    // second call: the chainId check is memoised (one startup check, not per read)
    const before = helios.seen.filter((s) => s.method === "eth_chainId").length;
    await p.currentRoots();
    ok(helios.seen.filter((s) => s.method === "eth_chainId").length === before, "chainId check runs once (memoised), not on every read");
    // default path unchanged: no helios -> RPC-trusted, and describe() says so loudly
    const p0 = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, heliosRpcUrl: "" });
    const d0 = p0.describe();
    ok(/TRUSTED/.test(d0.stateRootSource) && d0.stateRootVerified === false, `no SHADE_TREE_HELIOS_RPC_URL: describe() = "${d0.stateRootSource}"`);
    const r0 = await p0.currentRoots();
    ok(r0.roots[0] === GOLDEN_ROOT.toString() && r0.stateRootVerified === false, "default path still returns the root, flagged stateRootVerified:false");
    await helios.close(); await rpc.close();
  }

  // ---- 2. chainId ------------------------------------------------------------------------
  console.log("2. chainId fail-closed:");
  {
    const helios = await fakeRpc(heliosFor(honest, { chainId: "0x1" })); // mainnet helios by mistake
    const rpc = await fakeRpc(rpcFor(honest));
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, heliosRpcUrl: helios.url });
    await rejects(() => p.currentRoots(), /helios chainId mismatch: .*reports 1 but the configured chain is 11155111/, "Helios on chain 1 vs RPC on 11155111 -> rejected with both ids named");
    ok(!rpc.seen.some((s) => s.method === "eth_getProof"), "no proof was even requested after the chain check failed");
    // explicit expected chain (SHADE_TREE_HELIOS_CHAIN_ID) wins over the RPC's answer
    const h2 = makeHeliosTrustedStateRoot({ rpcUrl: helios.url, chainId: 1, upstreamRpcUrl: rpc.url });
    const got = await h2("finalized");
    ok(got.stateRoot === honest.stateRoot && got.number === N, "explicit chainId=1 matching the sidecar passes (RPC's chain not consulted)");
    const h3 = makeHeliosTrustedStateRoot({ rpcUrl: helios.url, chainId: "0xaa36a7", upstreamRpcUrl: rpc.url });
    await rejects(() => h3("finalized"), /chainId mismatch: .*reports 1 but the configured chain is 11155111 \(from SHADE_TREE_HELIOS_CHAIN_ID\)/, "explicit chainId 0xaa36a7 vs sidecar on 1 -> rejected, source named");
    // upstream RPC unreachable while deriving the expected chain -> rejected (never assume)
    const h4 = makeHeliosTrustedStateRoot({ rpcUrl: helios.url, upstreamRpcUrl: "http://127.0.0.1:1" });
    await rejects(() => h4("finalized"), /rpc unreachable/, "expected chain unknown (RPC down) -> rejected, not assumed");
    // a failed check is retried on the next call (sidecar booting late), not cached as failure
    let up = false;
    const flappy = await fakeRpc((m, p2) => (up ? heliosFor(honest)(m, p2) : { __error: "not ready" }));
    const h5 = makeHeliosTrustedStateRoot({ rpcUrl: flappy.url, chainId: SEPOLIA });
    await rejects(() => h5("finalized"), /helios eth_chainId error: not ready/, "sidecar not ready -> rejected");
    up = true;
    ok((await h5("finalized")).stateRoot === honest.stateRoot, "next call retries the startup check and succeeds once the sidecar is up");
    await helios.close(); await rpc.close(); await flappy.close();
  }

  // ---- 3. unreachable / malformed ---------------------------------------------------------
  console.log("3. unreachable / malformed Helios:");
  {
    const rpc = await fakeRpc(rpcFor(honest));
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, heliosRpcUrl: "http://127.0.0.1:1" });
    await rejects(() => p.currentRoots(), /helios unreachable at http:\/\/127\.0\.0\.1:1/, "Helios unreachable -> provider rejects (no fallback to the RPC header)");
    ok(!rpc.seen.some((s) => s.method === "eth_getProof"), "no proof requested when the anchor is down");
    const raw = await fakeRpc(() => ({ __raw: "<html>nope</html>" }));
    await rejects(() => makeHeliosTrustedStateRoot({ rpcUrl: raw.url, chainId: SEPOLIA })("finalized"), /returned non-JSON/, "non-JSON reply -> rejected");
    const nul = await fakeRpc((m) => (m === "eth_chainId" ? SEPOLIA : null));
    await rejects(() => makeHeliosTrustedStateRoot({ rpcUrl: nul.url, chainId: SEPOLIA })("finalized"), /helios has no verified block for tag finalized/, "null block -> rejected");
    const bad = await fakeRpc(heliosFor(honest, { header: { number: hexN, stateRoot: "0x1234" } }));
    await rejects(() => makeHeliosTrustedStateRoot({ rpcUrl: bad.url, chainId: SEPOLIA })("finalized"), /missing\/malformed stateRoot/, "malformed stateRoot -> rejected");
    const nonum = await fakeRpc(heliosFor(honest, { header: { stateRoot: honest.stateRoot } }));
    await rejects(() => makeHeliosTrustedStateRoot({ rpcUrl: nonum.url, chainId: SEPOLIA })("finalized"), /missing number/, "header without number -> rejected");
    for (const u of ["", "not a url", "ftp://x"]) {
      let threw = false; try { makeHeliosTrustedStateRoot({ rpcUrl: u, chainId: SEPOLIA }); } catch { threw = true; }
      ok(threw, `bad SHADE_TREE_HELIOS_RPC_URL ${JSON.stringify(u)} rejected at construction`);
    }
    await rpc.close(); await raw.close(); await nul.close(); await bad.close(); await nonum.close();
  }

  // ---- 4. THE ATTACK: RPC lies about the stateRoot --------------------------------------
  console.log("4. RPC lies about the stateRoot (the lever the anchor closes):");
  {
    const helios = await fakeRpc(heliosFor(honest));
    // (a) RPC header claims the fake stateRoot, proof still the honest one
    const rpcA = await fakeRpc(rpcFor(honest, { headerStateRoot: fake.stateRoot }));
    const pA = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpcA.url, heliosRpcUrl: helios.url });
    await rejects(() => pA.currentRoots(), new RegExp(`stateRoot mismatch at block ${N}: RPC \\(.*\\) claims ${fake.stateRoot} but the anchor \\(helios \\(sync-committee verified\\)\\) attests ${honest.stateRoot}`), "RPC header lies -> rejected with the precise mismatch reason (both roots named)");
    ok(!rpcA.seen.some((s) => s.method === "eth_getProof"), "rejected BEFORE fetching a proof (header cross-check first)");
    // (b) RPC serves a fully self-consistent FAKE world (fake header + a proof valid for it)
    const rpcB = await fakeRpc(rpcFor(fake));
    const pB = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpcB.url, heliosRpcUrl: helios.url });
    await rejects(() => pB.currentRoots(), /stateRoot mismatch/, "self-consistent fake world (attacker's tree) -> rejected: its header != the sync-committee-attested one");
    // (c) sanity: WITHOUT the anchor that same fake world is ACCEPTED (this is the T-DEV-9 gap)
    const pC = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpcB.url, heliosRpcUrl: "" });
    const rC = await pC.currentRoots();
    ok(rC.roots[0] === (GOLDEN_ROOT + 7n).toString() && rC.stateRootVerified === false, "control: without SHADE_TREE_HELIOS_RPC_URL the fake world IS accepted (RPC-trusted stateRoot) -- the gap this task closes");
    // (d) RPC honest header, but the proof is for a different world (tampered proof) -> the MPT
    //     verifier still catches it against the anchored root
    const rpcD = await fakeRpc(rpcFor(honest, { proofWorld: fake }));
    const pD = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpcD.url, heliosRpcUrl: helios.url });
    await rejects(() => pD.currentRoots(), /mpt: proof node missing|storageHash mismatch|proven slot value/, "honest header + proof for another world -> proof rejected against the anchored stateRoot");
    // (e) RPC has no such block -> rejected, named
    const rpcE = await fakeRpc((m) => (m === "eth_chainId" ? SEPOLIA : null));
    const pE = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpcE.url, heliosRpcUrl: helios.url });
    await rejects(() => pE.currentRoots(), new RegExp(`RPC has no block ${hexN} that the anchor`), "RPC withholds the block -> rejected (unavailability, named)");
    await helios.close(); await rpcA.close(); await rpcB.close(); await rpcD.close(); await rpcE.close();
  }

  // ---- 5. tag mapping --------------------------------------------------------------------
  console.log("5. block tag mapping:");
  {
    const helios = await fakeRpc((m, p) => {
      if (m === "eth_chainId") return SEPOLIA;
      if (m === "eth_getBlockByNumber") {
        if (p[0] === "latest") return { __error: "out of sync: 296 seconds behind" }; // verbatim Helios 0.11.1 behaviour
        if (p[0] === "finalized" || p[0] === hexN) return { number: hexN, stateRoot: honest.stateRoot, hash: "0x" + "cd".repeat(32) };
        if (p[0] === "0xaf0000") return { __error: "block 11468800 is outside EIP-2935 ring buffer range" };
        return null;
      }
      return null;
    });
    const h = makeHeliosTrustedStateRoot({ rpcUrl: helios.url, chainId: SEPOLIA });
    const f = await h("finalized");
    ok(f.number === N && f.stateRoot === honest.stateRoot && f.hash === "0x" + "cd".repeat(32), "'finalized' -> Helios finalized header {stateRoot, number, hash}");
    ok((await h(N)).number === N && helios.seen.at(-1).params[0] === hexN, "numeric tag -> asked as 0x-hex; header returned");
    ok((await h(hexN)).number === N && helios.seen.at(-1).params[0] === hexN && helios.seen.at(-1).params[1] === false, "hex tag passes through; full-tx flag is false");
    await rejects(() => h("latest"), /helios eth_getBlockByNumber error: out of sync/, "'latest' while Helios is out of sync -> its error propagates (fail closed)");
    await rejects(() => h("0xaf0000"), /outside EIP-2935 ring buffer/, "old block outside Helios' window -> rejected (use SHADE_TREE_CONFIRMATIONS=0 / finalized)");
    await rejects(() => h("pending"), /unsupported block tag pending/, "unknown tag rejected before any call");
    const g = await h("finalized"); ok(g.stateRoot === honest.stateRoot, "default tag = finalized");
    await helios.close();
  }

  // ---- 6. Helios lies (simulated): the anchor IS the trust root -------------------------
  console.log("6. anchor lies (simulated; documents the trust boundary):");
  {
    const heliosLiar = await fakeRpc(heliosFor(fake));   // "sync committee" attested the fake world
    const rpc = await fakeRpc(rpcFor(fake));             // and the RPC serves it consistently
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, heliosRpcUrl: heliosLiar.url });
    const r = await p.currentRoots();
    ok(r.roots[0] === (GOLDEN_ROOT + 7n).toString() && r.stateRootVerified === true, "a stateRoot the ANCHOR attests is accepted: the anchor's trust is the sync committee (2/3-honest) + WS checkpoint, by design (docs/LIGHT-CLIENT.md)");
    await heliosLiar.close(); await rpc.close();
  }

  // ---- 7. misconfig guard: helios + node provider ---------------------------------------
  console.log("7. SHADE_TREE_HELIOS_RPC_URL with SHADE_TREE_ROOT_PROVIDER=node:");
  {
    const r = spawnSync(process.execPath, ["-e", "import('./packages/node/lib/root-provider.mjs').then(m=>{try{m.makeRootProvider('node');console.log('NO-THROW')}catch(e){console.log('THREW:'+e.message)}})"], {
      cwd: new URL("../../..", import.meta.url).pathname,
      env: { ...process.env, SHADE_TREE_HELIOS_RPC_URL: "http://127.0.0.1:8545", SHADE_TREE_ROOT_PROVIDER: "node", SHADE_TREE_GROUP_CONTRACT: CONTRACT },
      encoding: "utf8",
    });
    ok(/THREW:SHADE_TREE_HELIOS_RPC_URL is set but SHADE_TREE_ROOT_PROVIDER=node/.test(r.stdout), `node provider + helios env refused (${r.stdout.trim().slice(0, 80)})`);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: helios-root selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
