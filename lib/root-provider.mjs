// RootProvider: the pluggable source of the on-chain reputation-set Merkle root(s).
//
// The gateway does not care HOW it learned the root, only which roots it will accept
// proofs against right now. So the source sits behind one interface and is chosen at
// config time (SHADE_TREE_ROOT_PROVIDER=node|light). See docs/ONCHAIN.md, "Reading the root".
//
//   currentRoots() -> { roots: string[], observedAtBlock: number, finalized: boolean }
//        roots = the current root plus every root still inside the freshness window F.
//   onChange(cb)   -> unsubscribe        (optional; refresh promptly on membership change)
//
// Two providers, interchangeable:
//   - NodeRootProvider  : trusted local node. The solo-staker path: someone running this
//                         next to their validator already has a trusted node, so this is
//                         optimal for them, not a compromise. Point SHADE_TREE_RPC_URL at it.
//                         Implemented here in EVENT-RECONSTRUCTION mode: eth_getLogs the
//                         contract's Member* events and rebuild the LeanIMT locally
//                         (StakedReputationSet keeps the tree off chain; contracts/README).
//   - LightClientRootProvider : proves the root's on-chain storage slot with eth_getProof
//                         (EIP-1186 MPT) against a block stateRoot. The stateRoot is RPC-
//                         trusted by default; set SHADE_TREE_HELIOS_RPC_URL (a local Helios
//                         verifying RPC, lib/helios-root.mjs) to anchor it to the beacon
//                         sync committee instead -- then no RPC trust remains (T-DEV-9b).
//
// Zero extra runtime deps: JSON-RPC over global fetch (Node 18+) + the Semaphore Group
// (already a dependency) for the LeanIMT. Event topic0 hashes are precomputed + hardcoded
// below (keccak256 of the event signature) so this file needs no keccak dep at runtime.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
// Build the tree with the RLN v3 depth-20 Poseidon tree (newGroup), NOT the app's
// top-level Semaphore v4 LeanIMT — only the former matches the circom-rln circuit root.
// The indexed event value (topics[1]) is now the rateCommitment leaf.
import { newGroup } from "./rln.mjs";
import { makeHeliosTrustedStateRoot } from "./helios-root.mjs";
import { parseFromBlocks, deployBlockForContract } from "./network-record.mjs";
import { jsonRpcCall, rpcOrigin } from "./rpc-safety.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

// Env knobs are read at CALL time (not import time) so a process that imports this module early
// (the client library does, T-FEAT-7) and sets SHADE_TREE_* later still gets the intended values.
const CONFIRMATIONS = () => Number(process.env.SHADE_TREE_CONFIRMATIONS || 0); // 0 = use finalized
const RPC_URL = () => process.env.SHADE_TREE_RPC_URL || "http://127.0.0.1:8545";
// The public profile is time-bounded, not count-bounded: every root this provider actually
// observes remains usable for F seconds. A legacy operator may still impose an explicit cap,
// but doing so weakens that guarantee under unusually rapid root churn.
const FRESHNESS_ROOTS = () => process.env.SHADE_TREE_FRESHNESS_ROOTS
  ? Number(process.env.SHADE_TREE_FRESHNESS_ROOTS)
  : Number.POSITIVE_INFINITY;
// A count-only root ring is unsafe for bonded membership: if nobody mutates the set after an
// exit, the exited member's old root would otherwise remain usable forever. Retire superseded
// roots, and last-known-good RPC snapshots, after this wall-clock bound even when the chain is
// quiet. The public profile pins this to one 60-second epoch.
const ROOT_FRESHNESS_SECONDS = () => Number(
  process.env.SHADE_TREE_ROOT_FRESHNESS_SECONDS ||
  process.env.SHADE_TREE_EPOCH_SECONDS ||
  120,
);
const HELIOS_RPC_URL = () => process.env.SHADE_TREE_HELIOS_RPC_URL || ""; // T-DEV-9b: local Helios anchor (light provider only)
// eth_getLogs paging (docs/OPERATOR.md "public RPC log-range caps"): blocks per call, halved on a
// range/size error down to the floor. 10k is under every public cap we know of (table below).
const LOGS_CHUNK = () => Math.max(1, Math.floor(Number(process.env.SHADE_TREE_LOGS_CHUNK) || 10_000));
const LOGS_CHUNK_FLOOR = 8;

// ---- eth_getLogs start block ------------------------------------------------
//
// fromBlockFor(contract) -> 0x-hex start block for `contract`'s event scan, first match wins:
//   1. SHADE_TREE_FROM_BLOCKS=<addr>=<block>,...   per-contract (each set scanned from its own deploy block)
//   2. SHADE_TREE_FROM_BLOCK=<block>               one start block for every contract
//   3. the contract's deploy block from a committed network record (network/<SHADE_TREE_NETWORK>/
//      contracts.json, else any record naming the address — lib/network-record.mjs
//      deployBlockForContract; SHADE_TREE_NETWORK's applyNetworkEnv also fills 1+2 from the record)
//   4. 0x0 (anvil / an unknown contract; chunked scanning below keeps even this correct, only slow)
// Explicit env always wins over the record. Exported for the selftest + `shade-tree leaves`.
export function fromBlockFor(contract, env = process.env) {
  const map = parseFromBlocks(env.SHADE_TREE_FROM_BLOCKS);
  const per = contract ? map.get(String(contract).toLowerCase()) : undefined;
  if (per !== undefined) return "0x" + per.toString(16);
  if (env.SHADE_TREE_FROM_BLOCK) return env.SHADE_TREE_FROM_BLOCK;
  const rec = contract ? deployBlockForContract(contract, { env }) : null;
  if (rec != null) return "0x" + rec.toString(16);
  return "0x0";
}

// parseContractList("0xA, 0xB,0xA") -> ["0xA", "0xB"]: the comma-separated address list form
// of SHADE_TREE_GROUP_CONTRACT (T-FEAT-7: several sets trusted at once). Trimmed, empties dropped,
// de-duplicated case-insensitively (first spelling wins). A single value is a one-element list.
export function parseContractList(spec) {
  const out = [];
  const seen = new Set();
  for (const part of String(spec == null ? "" : spec).split(",")) {
    const a = part.trim();
    if (!a) continue;
    const k = a.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(a);
  }
  return out;
}

// The configured contract SOURCES, in trust order: every SHADE_TREE_GROUP_CONTRACT entry (kind
// "staked"), then SHADE_TREE_PAID_ACCESS_CONTRACT (kind "paid"; sugar that appends a PaidAccessSet —
// docs/PAYMENTS.md). Each -> { address, kind }. A paid address that also appears in the group
// list keeps its first (staked) position but is tagged "paid" so the startup log names it right.
export function configuredContracts(env = process.env) {
  const out = parseContractList(env.SHADE_TREE_GROUP_CONTRACT).map((address) => ({ address, kind: "staked" }));
  const paid = parseContractList(env.SHADE_TREE_PAID_ACCESS_CONTRACT);
  for (const address of paid) {
    const dup = out.find((c) => c.address.toLowerCase() === address.toLowerCase());
    if (dup) dup.kind = "paid";
    else out.push({ address, kind: "paid" });
  }
  return out;
}

// Contract address: contracts/deployed.local.json (written by the deploy) wins, else env.
// With a LIST in SHADE_TREE_GROUP_CONTRACT the FIRST entry is this (single) provider's contract; the
// composite provider (makeRootProvider) is what fans out over the whole list.
function resolveContract(explicit) {
  if (explicit) return explicit;
  if (process.env.SHADE_TREE_GROUP_CONTRACT) return parseContractList(process.env.SHADE_TREE_GROUP_CONTRACT)[0] || "";
  try {
    const raw = JSON.parse(
      readFileSync(join(HERE, "..", "contracts", "deployed.local.json"), "utf8")
    );
    // be liberal in what we accept from Track 1's deploy JSON
    return (
      raw.stakedReputationSet ||
      raw.StakedReputationSet ||
      raw.address ||
      raw.group ||
      (raw.contracts && (raw.contracts.StakedReputationSet || raw.contracts.stakedReputationSet)) ||
      ""
    );
  } catch {
    return "";
  }
}

// ---- Member* event topic0 (keccak256 of the signature) ----------------------
// Precomputed; recompute with: node -e "import('ethers').then(({id})=>console.log(id('MemberRegistered(uint256,uint64,uint256)')))"
// Two generations of the set emit two shapes of register/slash event: rln-v3 (no limit) and
// rln-v4 (T-FEAT-8b: a trailing non-indexed `limit`). Both carry the rateCommitment as
// topics[1], so reconstruction is identical; we accept either topic0 so ONE provider reads
// either deployment (the fleet's rln-v3 slasher and the rln-v4 tiered set coexist).
const TOPIC = {
  registered: "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d", // MemberRegistered(uint256,uint64)          rln-v3
  registeredV4: "0x509c8735bf3647b16c92625a43b5459d0b51845aa0f3ec846f9d24594e7b824b", // MemberRegistered(uint256,uint64,uint256)  rln-v4
  exiting: "0x971e754215411b0ec07054d759063d876d53872b7d4b37294744e5a776604f37", // MemberExiting(uint256,uint64,uint64)
  withdrawn: "0x8f2d81dd61a3f7ff90ea7265e45192f03f643615dd2458e287d84aaac222ffe9", // MemberWithdrawn(uint256,address)
  slashed: "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450", // MemberSlashed(uint256,address)            rln-v3
  slashedV4: "0x0a39eb0fcb6a37e10a529e106ae887cbd1721626fa57900170ed0c2437af3797", // MemberSlashed(uint256,address,uint256)    rln-v4
  // PaidAccessSet (T-FEAT-7, docs/PAYMENTS.md, ADR 0007): the same tree, fed by operator inserts
  // after an off-chain (HTTP 402) payment. Its events carry the rateCommitment as topics[1] too, so
  // ONE reconstruction serves staked and paid sets alike. Both spellings of the append event are
  // accepted (`Inserted` = the insert-only contract; `Deposit` = the earlier payable draft), each
  // (commitment indexed, limit, index, root); the removal event is `Slashed` with the same fields.
  inserted: "0x829b3fd9a2105b78eea5138f4d692eb507be107a9b265a9456ea94fb2db9f992", // Inserted(uint256,uint256,uint256,uint256)  paid: append (operator insert)
  deposit: "0x9b776d199f09c774f5b205c9bc2ac6f40d508c347aaea919867eeaf06ebef0e9", // Deposit(uint256,uint256,uint256,uint256)   paid: append
  paidSlashed: "0xac0c8be2061774c705c517af2a774ab5cb33a2d7fe7054dd4a2728433026029c", // Slashed(uint256,uint256,uint256,uint256)   paid: zero in place
};
const ALL_TOPICS = [TOPIC.registered, TOPIC.registeredV4, TOPIC.exiting, TOPIC.withdrawn, TOPIC.slashed, TOPIC.slashedV4, TOPIC.inserted, TOPIC.deposit, TOPIC.paidSlashed];
const REGISTERED_TOPICS = new Set([TOPIC.registered, TOPIC.registeredV4, TOPIC.inserted, TOPIC.deposit]);
const REMOVED_TOPICS = new Set([TOPIC.exiting, TOPIC.withdrawn, TOPIC.slashed, TOPIC.slashedV4, TOPIC.paidSlashed]);

// ---- minimal JSON-RPC -------------------------------------------------------

let rpcId = 0;
function rpcOriginForError(value) {
  return rpcOrigin(value);
}

async function rpc(method, params, url = RPC_URL()) {
  return jsonRpcCall(url, method, params, { id: ++rpcId });
}

async function blockNumber(tag = "latest", url = RPC_URL()) {
  const b = await rpc("eth_getBlockByNumber", [tag, false], url);
  return b ? Number(BigInt(b.number)) : null;
}

async function confirmedBlockTag(rpcUrl = RPC_URL()) {
  const confirmations = CONFIRMATIONS();
  if (confirmations <= 0) return "finalized";
  const head = await blockNumber("latest", rpcUrl);
  if (head == null) return "latest";
  return "0x" + BigInt(Math.max(0, head - confirmations)).toString(16);
}

// ---- shared last-known-good cache ------------------------------------------

function withCache(fetchFresh, { maxStaleMs = ROOT_FRESHNESS_SECONDS() * 1000, now = Date.now } = {}) {
  let lkg = null; // { snapshot: { roots, observedAtBlock, finalized }, fetchedAt }
  return async function currentRoots() {
    try {
      const fresh = await fetchFresh();
      if (fresh) lkg = { snapshot: fresh, fetchedAt: now() };
      return fresh;
    } catch (e) {
      if (lkg && now() - lkg.fetchedAt <= maxStaleMs) {
        // A cached snapshot may contain roots retired almost F ago. Re-serving the whole array
        // for another F-long RPC outage would extend those roots to nearly 2F. Conservatively
        // bridge the outage with only the snapshot's current root; superseded proofs may retry
        // another gateway, while no retired membership root outlives the signed freshness bound.
        const roots = Array.isArray(lkg.snapshot.roots) ? lkg.snapshot.roots.slice(0, 1) : [];
        return { ...lkg.snapshot, roots, stale: true, error: e.message };
      }
      throw e;
    }
  };
}

// Keep the current root plus recently superseded roots. Unlike the original count-only ring,
// expiry is driven by time and therefore progresses even when no later membership event occurs.
// `maxRoots` is a legacy operator safety cap. The default is unbounded inside the finite
// wall-clock window so a burst of observed root changes cannot evict a still-fresh proof.
function makeFreshRootRing({
  maxRoots = FRESHNESS_ROOTS(),
  freshnessMs = ROOT_FRESHNESS_SECONDS() * 1000,
  now = Date.now,
} = {}) {
  let initialized = false;
  let current = null;
  let retired = []; // newest first: { root, retiredAt }

  return function pushRoot(root) {
    const at = now();
    const next = root == null || root === "" ? null : String(root);
    if (!initialized) {
      initialized = true;
      current = next;
    } else if (next !== current) {
      if (current != null) retired.unshift({ root: current, retiredAt: at });
      current = next;
    }

    retired = retired.filter((entry) => at - entry.retiredAt <= freshnessMs);
    const roots = current == null ? [] : [current];
    for (const entry of retired) {
      if (Number.isFinite(maxRoots) && roots.length >= maxRoots) break;
      if (!roots.includes(entry.root)) roots.push(entry.root);
    }
    return roots;
  };
}

// ---- NodeRootProvider (trusted local node, event reconstruction) ------------

export function NodeRootProvider({
  rpcUrl = RPC_URL(),
  contract,
  freshnessRoots = FRESHNESS_ROOTS(),
  freshnessMs = ROOT_FRESHNESS_SECONDS() * 1000,
  now = Date.now,
} = {}) {
  const addr = resolveContract(contract);
  if (!addr) throw new Error("NodeRootProvider needs a contract (deployed.local.json or SHADE_TREE_GROUP_CONTRACT)");

  // A time-bounded ring of every root this provider observes, so a proof built against a
  // just-superseded root still verifies for the full freshness window F.
  const newRootRing = () => makeFreshRootRing({ maxRoots: freshnessRoots, freshnessMs, now });
  let pushRoot = newRootRing();

  // Incremental scan state (finalized reads only): the logs already replayed up to `scannedTo`.
  // Finalized blocks do not reorg, so the next refresh only fetches (scannedTo, newHead] and
  // appends -- one small call per poll instead of re-paging the whole history from the deploy
  // block every 12 s against a public RPC. Any error or a head that moved BACKWARDS (RPC behind /
  // switched) drops the cache and the next refresh rescans from the start block. head-N reads
  // (SHADE_TREE_CONFIRMATIONS>0) always rescan (a reorg deeper than N would otherwise stick).
  let scanned = null; // { to: number, logs: [] }
  let lastSuccessfulAt = null;

  const currentRoots = withCache(async () => {
    const refreshStartedAt = now();
    const tag = await confirmedBlockTag(rpcUrl);
    const blk = await rpc("eth_getBlockByNumber", [tag, false], rpcUrl);
    const observedAtBlock = blk ? Number(BigInt(blk.number)) : null;
    const toBlock = blk ? blk.number : tag;

    // eth_getLogs the Member*/Deposit/Slashed events up to the confirmation-depth block (chunked
    // + paged, fetchMemberLogs; the start block is this contract's own, fromBlockFor).
    let logs;
    const incremental = tag === "finalized" && observedAtBlock != null && scanned && observedAtBlock >= scanned.to;
    const previousLogCount = incremental ? scanned.logs.length : Number.POSITIVE_INFINITY;
    try {
      if (incremental) {
        const fresh = observedAtBlock > scanned.to ? await fetchMemberLogs({ contract: addr, rpcUrl, fromBlock: hexBlock(scanned.to + 1), toBlock }) : [];
        logs = scanned.logs.concat(fresh);
      } else {
        logs = await fetchMemberLogs({ contract: addr, rpcUrl, fromBlock: fromBlockFor(addr), toBlock });
      }
    } catch (e) {
      scanned = null;
      throw e;
    }
    scanned = tag === "finalized" && observedAtBlock != null ? { to: observedAtBlock, logs } : null;

    const { root, active, transitions } = reconstructGroup(logs, { trackFrom: previousLogCount });
    // Never timestamp historical transitions as if they happened at recovery time. After the
    // previous observation has aged past F, or an incremental finalized scan was invalidated and
    // required a full replay, we cannot safely infer when the replayed transitions happened from
    // logs alone. Reset the ring and publish only the current finalized root. This prevents a
    // day-long RPC outage from briefly reviving roots whose members have already withdrawn.
    const staleObservationGap = lastSuccessfulAt != null && refreshStartedAt - lastSuccessfulAt > freshnessMs;
    const finalizedScanWasInvalidated = lastSuccessfulAt != null && tag === "finalized" && observedAtBlock != null && !incremental;
    const resetToCurrent = staleObservationGap || finalizedScanWasInvalidated;
    if (resetToCurrent) pushRoot = newRootRing();
    let roots = null;
    // A finalized head can advance across several membership mutations between polls.
    // Retain every intermediate root from that immutable fresh suffix; otherwise a client
    // that read finalized state A while this gateway moved directly to B would be rejected
    // even though A is still inside the advertised freshness window.
    if (!resetToCurrent) for (const transition of transitions) roots = pushRoot(transition);
    if (roots == null) roots = pushRoot(root);
    lastSuccessfulAt = now();
    return { roots, observedAtBlock, finalized: tag === "finalized", leafCount: active };
  }, { maxStaleMs: freshnessMs, now });

  const describe = () => ({ provider: "node", stateRootSource: "trusted node (RPC trusted by design; solo-staker path)", stateRootVerified: false, contract: addr });
  return { currentRoots, onChange: pollOnChange(currentRoots), describe, contract: addr };
}

// ---- eth_getLogs paging (public RPC range caps) --------------------------------
//
// Public / hosted RPCs cap one eth_getLogs call by block RANGE and/or RESULT SIZE, and say so in
// the error message (there is no standard code). What we have seen or read, verbatim, so the
// matcher below can be checked against them:
//   publicnode      "eth_getLogs: exceed maximum block range: 50000"        (LIVE, fleet crash-loop
//                    2026-08-17, docs/history/GO-LIVE-LOG-2026-08-17.md; Sepolia, cap 50k blocks)
//   Alchemy         "Log response size exceeded. You can make eth_getLogs requests with up to a 2K
//                    block range and no limit on the response size, or you can request any block
//                    range with a cap of 10K logs in the response." (docs.alchemy.com eth_getLogs)
//   Infura          "query returned more than 10000 results. Try with this block range [0x.., 0x..]"
//                    (code -32005 "limit exceeded"; docs.infura.io eth_getLogs)
//   QuickNode       "eth_getLogs and eth_newFilter are limited to a 10,000 blocks range" (-32614)
//   Ankr / BSC etc  "block range is too wide" / "block range too large" / "exceed maximum block range"
//   Erigon / geth   "query exceeds max results 10000" / "query timeout exceeded"
//   Nodereal        "the response size should not greater than ..." / Chainstack "Block range limit exceeded"
// Any of these -> the caller HALVES the chunk and retries; anything else is a real error.
export const LOG_RANGE_ERROR_PATTERNS = [
  /block range/i,                                  // "exceed maximum block range", "10,000 blocks range", "block range too large/wide"
  /exceed(?:s|ed)? max(?:imum)?/i,                 // "exceed maximum block range", "query exceeds max results"
  /range (?:is )?too (?:large|wide|big)/i,
  /(?:more than|over) [\d,]+ (?:results|logs)/i,   // Infura
  /response size (?:exceeded|should not|too large|limit)/i, // Alchemy, Nodereal
  /too many (?:results|logs|blocks)/i,
  /query timeout/i,                                // geth: a too-wide scan timing out server side
  /limited to a? ?[\d,]+ (?:blocks? )?range/i,     // QuickNode
  /limit exceeded/i,                               // Infura -32005 (also covers a burst limit: a retry is harmless)
];
export function isLogRangeError(e) {
  const m = String((e && e.message) || e || "");
  return LOG_RANGE_ERROR_PATTERNS.some((re) => re.test(m));
}

// Block-number helpers: a 0x-hex / decimal string, number or bigint -> Number; a tag
// ("latest"/"finalized"/"earliest"/"safe"/"pending") -> null.
function asBlockNumber(v) {
  if (v == null) return null;
  if (typeof v === "number") return Number.isFinite(v) ? Math.floor(v) : null;
  if (typeof v === "bigint") return Number(v);
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s) || /^\d+$/.test(s)) return Number(BigInt(s));
  if (s === "earliest") return 0;
  return null;
}
const hexBlock = (n) => "0x" + BigInt(n).toString(16);

// fetchLogsChunked({ rpcUrl, filter, from, to, chunk, floor, onChunk }) -> logs[] in block order:
// eth_getLogs over [from, to] in windows of `chunk` blocks; on a range/size error the window is
// halved (down to `floor`) and the SAME window retried; the pieces are concatenated in order.
// `filter` = the eth_getLogs object minus fromBlock/toBlock. Exported via _internals for tests.
async function fetchLogsChunked({ rpcUrl, filter, from, to, chunk = LOGS_CHUNK(), floor = LOGS_CHUNK_FLOOR, onChunk = null }) {
  const out = [];
  let size = Math.max(1, chunk);
  let cursor = from;
  while (cursor <= to) {
    const end = Math.min(to, cursor + size - 1);
    try {
      const part = await rpc("eth_getLogs", [{ ...filter, fromBlock: hexBlock(cursor), toBlock: hexBlock(end) }], rpcUrl);
      if (onChunk) onChunk({ from: cursor, to: end, count: (part || []).length, size });
      for (const l of part || []) out.push(l);
      cursor = end + 1;
    } catch (e) {
      if (!isLogRangeError(e) || size <= floor) throw e;
      size = Math.max(floor, Math.floor(size / 2));
    }
  }
  return out;
}

// eth_getLogs of every membership event this module understands (both StakedReputationSet
// generations + PaidAccessSet), for `contract`, in [fromBlock, toBlock] — PAGED (T-FEAT-7 fleet
// follow-up): `toBlock` is resolved to a NUMBER once (so every page sees the same head; "latest"
// is not re-read per page), the range is split into SHADE_TREE_LOGS_CHUNK-block windows and a window the
// RPC refuses as too wide/large is halved and retried (isLogRangeError). A range that fits one
// window is a single call, byte-identical to the pre-paging behaviour (anvil, a fresh set). A
// single call that fails with a range error is retried paged as well. Exported for the client's
// leaf discovery (loadGroupFromContract) and the `shade-tree leaves` exporter.
export async function fetchMemberLogs({ contract, rpcUrl = RPC_URL(), fromBlock, toBlock = "latest", chunk = LOGS_CHUNK(), onChunk = null } = {}) {
  if (!contract) throw new Error("fetchMemberLogs needs a contract address");
  if (fromBlock == null) fromBlock = fromBlockFor(contract);
  const filter = { address: contract, topics: [ALL_TOPICS] };
  const from = asBlockNumber(fromBlock) ?? 0;
  let to = asBlockNumber(toBlock);
  if (to == null) {
    // Resolve the tag once. An RPC that cannot (a stub without blocks) leaves us with the plain
    // single call below, exactly as before.
    try { to = await blockNumber(toBlock, rpcUrl); } catch { to = null; }
  }
  if (to == null || to - from + 1 <= chunk) {
    try {
      const single = await rpc("eth_getLogs", [{ ...filter, fromBlock: hexBlock(from), toBlock: to == null ? toBlock : hexBlock(to) }], rpcUrl);
      if (onChunk) onChunk({ from, to, count: (single || []).length, size: to == null ? null : to - from + 1 });
      return single;
    } catch (e) {
      if (to == null || !isLogRangeError(e) || chunk <= LOGS_CHUNK_FLOOR) throw e;
      // Even the small window was refused: page it with a halved window (the loop keeps halving).
      return fetchLogsChunked({ rpcUrl, filter, from, to, chunk: Math.max(LOGS_CHUNK_FLOOR, Math.floor(chunk / 2)), onChunk });
    }
  }
  return fetchLogsChunked({ rpcUrl, filter, from, to, chunk, onChunk });
}

// loadGroupFromContract({ contract, rpcUrl, blockTag }) -> { group, root, count, leaves, contract }:
// the CLIENT-side twin of NodeRootProvider — rebuild the whole tree (not just the root) from the
// event log so a member can generate a Merkle proof for its leaf under a staked or paid set.
// `leaves` = the LIVE leaves (decimal strings; zeroed slots excluded), `group.members` = the
// ordered leaf array including in-place zeros. Same shape as lib/rln.mjs loadGroup, so it plugs
// straight into makeSlotPool's loadGroupFn. `fromBlock` defaults to the contract's own start
// block (fromBlockFor: SHADE_TREE_FROM_BLOCKS / SHADE_TREE_FROM_BLOCK / the network record's deploy block).
export async function loadGroupFromContract({ contract, rpcUrl = RPC_URL(), fromBlock, blockTag = "latest" } = {}) {
  const logs = await fetchMemberLogs({ contract, rpcUrl, fromBlock, toBlock: blockTag });
  const { group, liveIndex, root, active } = reconstructGroup(logs);
  return { group, root, count: active, leaves: Array.from(liveIndex.keys()), contract };
}

// Rebuild the admission tree from ordered Member* logs and compute the depth-20 RLN root
// by REPLAYING the contract's own state transitions in block/logIndex order. Client and
// gateway both run this and must agree with each other AND with the leaf indices the
// contract assigns, so their roots agree by construction (the PoC keeps the tree off
// chain; contracts/README).
//
// REMOVAL SEMANTICS — zero-in-place (T-DEV-2). The contract (StakedReputationSet.sol)
// assigns every member an IMMUTABLE append-only leaf `index` at register (`nextIndex++`,
// never decremented, never reused) and a slash/exit/withdraw DELETES that member while
// leaving every other member's index untouched (see test_ReRegister_AfterSlash: a
// re-registered commitment gets a FRESH index, the old slot stays vacated). That is the
// standard Semaphore/RLN convention: a removed leaf is set to the tree's zero value AT ITS
// ORIGINAL INDEX, survivors keep their indices and Merkle paths, the root is recomputed
// over the zeroed leaf. So we mirror the contract exactly:
//   register  -> addMember (appends at the next index == the contract's nextIndex)
//   remove    -> removeMember(originalIndex) (Semaphore Group.delete: zero-in-place)
// The earlier implementation rebuilt a FRESH tree of the survivors, renumbering their
// indices — that produced a DIFFERENT root after any removal (and silently dropped a
// legitimately re-registered member), diverging from the contract. Fixed here.
export function reconstructRoot(logs) {
  return reconstructGroup(logs).root;
}

// reconstructGroup(logs, { trackFrom }) -> { group, liveIndex, active, root, transitions }:
// the replayed tree itself (root = null when no member is live), its live commitment ->
// leaf-index map, the live count, and each root produced by an applied mutation at or after
// the ordered-log index `trackFrom`. The gateway uses transitions only for the immutable
// finalized suffix it learned since its previous poll; an initial history scan never admits
// historical intermediate roots.
export function reconstructGroup(logs, { trackFrom = Number.POSITIVE_INFINITY } = {}) {
  const ordered = [...logs].sort(
    (a, b) =>
      Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) ||
      Number(BigInt(a.logIndex) - BigInt(b.logIndex))
  );
  const g = newGroup();                 // empty depth-20 RLN tree
  const liveIndex = new Map();          // commitment(string) -> its current live leaf index
  let active = 0;                       // members currently in the admission set
  const transitions = [];
  for (let position = 0; position < ordered.length; position++) {
    const log = ordered[position];
    const topic0 = (log.topics[0] || "").toLowerCase();
    const commitment = BigInt(log.topics[1]).toString(); // indexed commitment = topics[1]
    let changed = false;
    if (REGISTERED_TOPICS.has(topic0)) {
      // A register APPENDS a fresh leaf at the next free index — exactly the contract's
      // monotonic nextIndex. `g.members.length` is that append index. The guard is purely
      // defensive: the contract reverts a second active registration of the same
      // commitment (AlreadyMember), so a duplicate register log can only be a reorg echo.
      if (liveIndex.has(commitment)) continue;
      liveIndex.set(commitment, g.members.length);
      g.addMember(BigInt(commitment));
      active++;
      changed = true;
    } else if (REMOVED_TOPICS.has(topic0)) {
      const idx = liveIndex.get(commitment);
      if (idx === undefined) continue;  // not currently live -> nothing to vacate
      g.removeMember(idx);              // ZERO-IN-PLACE at the original index (indices preserved)
      liveIndex.delete(commitment);
      active--;
      changed = true;
    }
    if (changed && position >= trackFrom) transitions.push(active === 0 ? null : g.root.toString());
  }
  // COORDINATION: the on-chain StakedReputationSet / PaidAccessSet MUST maintain the identical
  // circom-rln depth-20 Poseidon tree of rateCommitments for these roots to match proof roots,
  // and MUST emit the rateCommitment as the indexed topic[1]. Removed leaves are zeroed in
  // place (above), matching the contract's immutable indices. An empty admission set has no
  // root (root null; the gateway then accepts nothing from this source).
  return { group: g, liveIndex, active, root: active === 0 ? null : g.root.toString(), transitions };
}

// ---- Merkle-Patricia storage-proof verification (T-DEV-9) -------------------
//
// A self-contained EIP-1186 proof verifier: no new dependency — keccak256 + RLP come from
// `ethers`, already a direct dep. Given a trusted state root, it cryptographically proves
// the value at a contract storage slot: verify the ACCOUNT proof against the state root to
// extract the account's storageHash, then verify the STORAGE proof against that storageHash
// to extract the slot value. A tampered value or a tampered/missing proof node fails (the
// node's keccak no longer matches the hash its parent commits to), so this defeats a lying
// RPC — as far as the state root we anchor to (see the trust note on LightClientRootProvider).

// keccak256 of a 0x-hex byte string -> 0x-hex (32 bytes). Imported lazily so the node path
// (NodeRootProvider) never loads ethers.
async function ethersMod() {
  return import("ethers");
}

// nibble array of a 0x-hex byte string (each byte -> hi, lo).
function toNibbles(bytes) {
  const out = [];
  for (const b of bytes) { out.push(b >> 4, b & 0x0f); }
  return out;
}

// Decode a hex-prefix (compact) encoded path -> { path: nibbles[], leaf: bool }.
function decodeCompactPath(getBytes, hex) {
  const bytes = getBytes(hex);
  if (bytes.length === 0) return { path: [], leaf: false };
  const flag = bytes[0] >> 4;
  const leaf = (flag & 2) !== 0;
  const odd = (flag & 1) !== 0;
  const nibs = [];
  if (odd) nibs.push(bytes[0] & 0x0f);
  for (let i = 1; i < bytes.length; i++) { nibs.push(bytes[i] >> 4, bytes[i] & 0x0f); }
  return { path: nibs, leaf };
}

// Walk an MPT proof for `keyBytesHex` (the RAW key; it is keccak-hashed here to the secure
// trie key) from `rootHex`. Returns the terminal value FIELD (0x-hex, RLP-encoded) if the
// key is present, null if the proof proves ABSENCE, and THROWS if the proof is invalid,
// incomplete, or tampered. `nodesHex` is the ordered eth_getProof node list (root..leaf).
async function verifyMptProof(rootHex, keyBytesHex, nodesHex) {
  const { keccak256, decodeRlp, getBytes } = await ethersMod();
  // Index every supplied node by its keccak so ordering/embedding is irrelevant and a
  // missing/altered node is detected as an absent hash.
  const byHash = new Map();
  for (const n of nodesHex) byHash.set(keccak256(n).toLowerCase(), decodeRlp(n));

  const key = toNibbles(getBytes(keccak256(keyBytesHex)));
  let expected = rootHex.toLowerCase();
  let i = 0;
  // Bounded by key length + slack; a correct proof terminates well within this.
  for (let step = 0; step < key.length + 4; step++) {
    let node;
    if (typeof expected === "string") {
      if (expected === "0x" || expected === "0x0") return null; // empty child -> absent
      node = byHash.get(expected);
      if (node === undefined) throw new Error("mpt: proof node missing for referenced hash");
    } else {
      node = expected; // embedded (<32B) node, used inline
    }
    if (Array.isArray(node) && node.length === 17) {
      if (i === key.length) return node[16]; // value at a branch
      expected = node[key[i]];
      i += 1;
      if (typeof expected === "string" && (expected === "0x" || expected === "0x0")) return null;
    } else if (Array.isArray(node) && node.length === 2) {
      const { path, leaf } = decodeCompactPath(getBytes, node[0]);
      for (let j = 0; j < path.length; j++) {
        if (key[i + j] !== path[j]) return null; // diverges from key -> absent
      }
      i += path.length;
      if (leaf) return i === key.length ? node[1] : null;
      expected = node[1]; // extension -> descend
    } else {
      throw new Error("mpt: malformed node");
    }
  }
  throw new Error("mpt: proof did not terminate");
}

// ---- LightClientRootProvider (Helios-style, run-many path) -------------------
//
// TRUST MODEL (read before relying on this):
//   VERIFIED cryptographically here: given a state root, the returned membership root is
//     the exact value at the contract's ROOT storage slot — proven with the account +
//     storage Merkle-Patricia proofs from eth_getProof. The RPC cannot substitute a false
//     root without breaking a keccak commitment, so this removes trust in the RPC's honesty
//     about the slot's contents (the gap the node/event-reconstruction path leaves open).
//   THE STATE ROOT we anchor the proof to -- two modes, chosen by SHADE_TREE_HELIOS_RPC_URL:
//     * unset (default): TRUSTED. It comes from the RPC's eth_getBlockByNumber at a confirmed
//       depth (finalized / head-N) and is NOT verified. `describe().stateRootSource` says so and
//       the gateway logs it at startup. A lying RPC can then forge a root by pairing a fake
//       header with a proof consistent with that fake header (docs/THREAT-MODEL.md).
//     * set (T-DEV-9b): VERIFIED. The header comes from a LOCAL Helios verifying RPC
//       (`lib/helios-root.mjs`, `makeHeliosTrustedStateRoot`), i.e. it chains to a beacon
//       sync-committee-signed execution payload. The RPC's own header for that block number is
//       then only CROSS-CHECKED: if its stateRoot differs from Helios' the provider REJECTS with
//       a precise reason (that is exactly the lying-RPC attack). Residual trust = the sync
//       committee + Helios' weak-subjectivity checkpoint (docs/LIGHT-CLIENT.md).
//     The `trustedStateRoot(blockTag) -> { stateRoot, number }` option is the same seam for
//     tests or another anchor; the env var just installs the Helios implementation of it.
//   FALLBACK: SHADE_TREE_LIGHT_MODE=storageat skips the proof and reads eth_getStorageAt at the
//     confirmed block. That TRUSTS the RPC for the value (no cryptographic check) and exists
//     only for RPCs without eth_getProof; it is clearly the weaker mode.
//
// Either way the returned root can be compared by a client to its own reconstructRoot: a
// match means the on-chain committed root and the locally-rebuilt tree agree.
export function LightClientRootProvider({
  contract,
  rpcUrl = RPC_URL(),
  slot = 3, // StakedReputationSet.ROOT_STORAGE_SLOT (currentRoot); see the contract
  mode = process.env.SHADE_TREE_LIGHT_MODE || "proof",
  trustedStateRoot = null, // optional: (blockTag) -> { stateRoot, number } from a verified header
  heliosRpcUrl = HELIOS_RPC_URL(), // SHADE_TREE_HELIOS_RPC_URL: installs the Helios trustedStateRoot
  freshnessMs = ROOT_FRESHNESS_SECONDS() * 1000,
  now = Date.now,
} = {}) {
  const addr = resolveContract(contract);
  if (!addr) throw new Error("LightClientRootProvider needs a contract address");
  if (!trustedStateRoot && heliosRpcUrl) {
    trustedStateRoot = makeHeliosTrustedStateRoot({ rpcUrl: heliosRpcUrl, upstreamRpcUrl: rpcUrl });
  }
  // What the startup log says about the anchor (gateway/gateway.mjs prints describe()).
  const stateRootSource = trustedStateRoot
    ? (trustedStateRoot.source || "injected trustedStateRoot hook")
    : "rpc header (TRUSTED, not verified; set SHADE_TREE_HELIOS_RPC_URL to anchor to the sync committee)";

  const slotHex = "0x" + BigInt(slot).toString(16).padStart(64, "0");
  const newRootRing = () => makeFreshRootRing({ freshnessMs, now });
  let pushRoot = newRootRing();
  let lastSuccessfulAt = null;

  // Normalize a 0x-hex slot value to the decimal root string the gateway/client compare on.
  // The empty tree's on-chain root is the depth-20 all-zero-leaf root (a nonzero field
  // element), which the off-chain reconstructRoot represents as null — same "no members"
  // meaning; a caller treats that sentinel as an empty set.
  function toRoot(valueHex) {
    if (valueHex == null) return null;
    const v = BigInt(valueHex);
    return v === 0n ? null : v.toString();
  }

  const currentRoots = withCache(async () => {
    const refreshStartedAt = now();
    // Resolve the confirmed block + its (trusted) state root.
    const tag = await confirmedBlockTag(rpcUrl);
    let stateRoot;
    let observedAtBlock;
    let blockTagForProof;
    if (trustedStateRoot) {
      const h = await trustedStateRoot(tag);
      if (!h || typeof h.stateRoot !== "string") throw new Error("LightClientRootProvider: trustedStateRoot returned no stateRoot");
      stateRoot = h.stateRoot;
      observedAtBlock = h.number != null ? Number(BigInt(h.number)) : null;
      blockTagForProof = h.number != null ? "0x" + BigInt(h.number).toString(16) : tag;
      // Cross-check the RPC's header for the SAME block. The proof below is anchored to the
      // verified stateRoot regardless, so a lying RPC could not pass anyway -- but naming the
      // attack beats a generic "proof node missing", and a divergent header is exactly what an
      // RPC that fabricates state looks like. Fail closed with the precise reason.
      const rpcBlk = await rpc("eth_getBlockByNumber", [blockTagForProof, false], rpcUrl);
      if (!rpcBlk) {
        throw new Error(`LightClientRootProvider: RPC has no block ${blockTagForProof} that the anchor (${stateRootSource}) attests`);
      }
      if (typeof rpcBlk.stateRoot !== "string" || rpcBlk.stateRoot.toLowerCase() !== stateRoot.toLowerCase()) {
        throw new Error(
          `LightClientRootProvider: stateRoot mismatch at block ${observedAtBlock}: RPC (${rpcOriginForError(rpcUrl)}) claims ${rpcBlk.stateRoot} but the anchor (${stateRootSource}) attests ${stateRoot} -- RPC is lying about the header or serving another chain; refusing its proofs`,
        );
      }
    } else {
      const blk = await rpc("eth_getBlockByNumber", [tag, false], rpcUrl);
      if (!blk) throw new Error("LightClientRootProvider: no block at " + tag);
      stateRoot = blk.stateRoot;
      observedAtBlock = Number(BigInt(blk.number));
      blockTagForProof = blk.number; // pin the proof to the exact block we read the root of
    }

    let root;
    if (mode === "storageat") {
      // Weaker fallback: trust the RPC for the value (no proof). Documented above.
      const valueHex = await rpc("eth_getStorageAt", [addr, slotHex, blockTagForProof], rpcUrl);
      root = toRoot(valueHex);
    } else {
      // Proof path: eth_getProof, then verify account + storage proofs against stateRoot.
      const proof = await rpc("eth_getProof", [addr, [slotHex], blockTagForProof], rpcUrl);
      if (!proof || !proof.accountProof || !proof.storageProof || !proof.storageProof[0]) {
        throw new Error("LightClientRootProvider: eth_getProof returned no proof");
      }
      const { decodeRlp } = await ethersMod();

      // 1. Account proof -> the account leaf [nonce, balance, storageHash, codeHash].
      const accountField = await verifyMptProof(stateRoot, addr, proof.accountProof);
      if (accountField == null) throw new Error("LightClientRootProvider: account absent in state proof");
      const account = decodeRlp(accountField);
      if (!Array.isArray(account) || account.length !== 4) {
        throw new Error("LightClientRootProvider: malformed account node");
      }
      const storageHash = account[2].toLowerCase();
      // Cross-check against the RPC-reported storageHash (defense in depth; the proof is
      // authoritative, but a mismatch flags a broken/lying RPC early).
      if (proof.storageHash && proof.storageHash.toLowerCase() !== storageHash) {
        throw new Error("LightClientRootProvider: storageHash mismatch vs proof");
      }

      // 2. Storage proof -> the slot value, proven against the account's storageHash.
      const sp = proof.storageProof[0];
      const valueField = await verifyMptProof(storageHash, slotHex, sp.proof);
      const proven = valueField == null ? 0n : BigInt(decodeRlp(valueField));
      // The RPC's claimed value must equal what the proof proves.
      if (sp.value != null && BigInt(sp.value) !== proven) {
        throw new Error("LightClientRootProvider: proven slot value != reported value");
      }
      root = proven === 0n ? null : proven.toString();
    }

    // As with the event-reconstruction provider, a root first observed after F elapsed cannot
    // safely make the previously observed root fresh again. Reset before recording recovery.
    if (lastSuccessfulAt != null && refreshStartedAt - lastSuccessfulAt > freshnessMs) pushRoot = newRootRing();
    const roots = pushRoot(root);
    lastSuccessfulAt = now();
    return {
      roots,
      observedAtBlock,
      finalized: tag === "finalized",
      verified: mode !== "storageat",
      stateRootVerified: !!trustedStateRoot,
    };
  }, { maxStaleMs: freshnessMs, now });

  const describe = () => ({ provider: "light", mode, stateRootSource, stateRootVerified: !!trustedStateRoot, contract: addr });
  return { currentRoots, onChange: pollOnChange(currentRoots), describe, contract: addr };
}

// Exported for the T-DEV-9 selftest (unit-test the MPT verifier against hand-built proofs)
// and the T-FEAT-8b selftest (both event generations reconstruct identically).
export const _internals = { verifyMptProof, decodeCompactPath, toNibbles, TOPIC, fetchLogsChunked, asBlockNumber, LOGS_CHUNK_FLOOR, pollOnChange, pollSnapshotKey, makeFreshRootRing, withCache };

// ---- change notification (poll; upgrade to log subscription later) ----------

function pollSnapshotKey(snapshot) {
  return JSON.stringify({
    roots: (snapshot?.roots || []).map(String),
    perSource: (snapshot?.perSource || []).map((source) => ({
      contract: String(source?.contract || "").toLowerCase(),
      roots: (source?.roots || []).map(String),
      stale: !!source?.stale,
      error: !!source?.error,
    })),
    errors: (snapshot?.errors || [])
      .map((entry) => String(entry?.contract || "").toLowerCase())
      .sort(),
  });
}

function pollOnChange(currentRoots) {
  return function onChange(cb, intervalMs = 12000) {
    let last = null;
    let failed = false;
    let stopped = false;
    let timer = null;
    const schedule = () => {
      if (stopped) return;
      timer = setTimeout(run, intervalMs);
      timer.unref?.();
    };
    const run = async () => {
      let snapshot;
      try {
        snapshot = await currentRoots();
      } catch (error) {
        // An expired last-known-good window is an admission event, not merely a
        // telemetry failure. Notify the consumer once so it can remove the
        // untrustworthy roots, then force the first successful read to emit even
        // when the recovered root bytes equal the pre-outage snapshot.
        last = null;
        if (!failed) {
          failed = true;
          try { await cb([], error); } catch { /* consumer failure must not stop polling */ }
        }
        schedule();
        return;
      }
      try {
        failed = false;
        const next = pollSnapshotKey(snapshot);
        if (next !== last) {
          last = next;
          await cb(snapshot.roots || [], null);
        }
      } catch { /* consumer failure must not stop polling */ }
      finally { schedule(); }
    };
    schedule();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  };
}

// ---- factory ----------------------------------------------------------------

// One provider (node|light) for ONE contract.
function makeSingleProvider(mode, contract) {
  if (mode === "light") return LightClientRootProvider(contract ? { contract } : {});
  if (mode === "node") {
    // Fail closed on a misconfig that would otherwise look verified: the Helios anchor is a
    // light-provider concept (the node provider trusts its RPC by design; to get light-client
    // security there, point SHADE_TREE_RPC_URL itself at Helios -- docs/LIGHT-CLIENT.md option A).
    if (HELIOS_RPC_URL()) throw new Error("SHADE_TREE_HELIOS_RPC_URL is set but SHADE_TREE_ROOT_PROVIDER=node; the Helios stateRoot anchor needs SHADE_TREE_ROOT_PROVIDER=light (or point SHADE_TREE_RPC_URL at Helios instead)");
    return NodeRootProvider(contract ? { contract } : {});
  }
  throw new Error(`unknown SHADE_TREE_ROOT_PROVIDER: ${mode} (expected node|light)`);
}

// ---- CompositeRootProvider (T-FEAT-7: several sets trusted at once) --------------
//
// The UNION of the roots of several providers, one per contract (a staked set, a paid set, a
// superseded set still inside its window...). currentRoots() = the de-duplicated union of every
// child's roots (order preserved: child order, then each child's freshness ring); a child that
// throws is dropped from THIS refresh (logged via `errors[]`) rather than blanking the whole
// union — the same last-known-good posture withCache gives each child. If EVERY child throws
// the composite throws (nothing to trust). onChange polls the composite once (one serial refresh,
// rather than one timer per child); describe() lists the children.
// `perSource` carries each child's result so the gateway can log/gauge roots per source.
export function CompositeRootProvider(children) {
  if (!Array.isArray(children) || children.length === 0) throw new Error("CompositeRootProvider needs at least one child provider");
  async function currentRoots() {
    const roots = [];
    const seen = new Set();
    const perSource = [];
    const errors = [];
    let observedAtBlock = null;
    let finalized = true;
    for (const child of children) {
      try {
        const r = await child.currentRoots();
        perSource.push({
          contract: child.contract || child.describe?.().contract || null,
          roots: (r.roots || []).slice(),
          leafCount: r.leafCount ?? null,
          stale: !!r.stale,
          ...(r.error ? { error: r.error } : {}),
        });
        for (const root of r.roots || []) { const k = String(root); if (!seen.has(k)) { seen.add(k); roots.push(k); } }
        if (r.observedAtBlock != null) observedAtBlock = observedAtBlock == null ? r.observedAtBlock : Math.min(observedAtBlock, r.observedAtBlock);
        if (r.finalized === false) finalized = false;
      } catch (e) {
        const contract = child.contract || child.describe?.().contract || null;
        errors.push({ contract, error: e.message });
        perSource.push({ contract, roots: [], leafCount: null, error: e.message });
      }
    }
    if (errors.length === children.length) throw new Error("all root providers failed: " + errors.map((e) => `${e.contract}: ${e.error}`).join("; "));
    return { roots, observedAtBlock, finalized, perSource, errors };
  }
  function onChange(cb, intervalMs) {
    return pollOnChange(currentRoots)(cb, intervalMs);
  }
  const describe = () => ({ provider: "composite", children: children.map((c) => (c.describe ? c.describe() : { contract: c.contract })) });
  return { currentRoots, onChange, describe, children };
}

// makeRootProvider(mode, { contracts }) — the gateway's factory. `contracts` (default: every
// configured contract, configuredContracts()) is the address list to trust; ONE address returns
// the plain node|light provider (byte-equivalent to the pre-T-FEAT-7 single-contract path), more
// than one returns their CompositeRootProvider union. No contract at all: the single provider's
// own resolution (contracts/deployed.local.json) applies, as before.
export function makeRootProvider(mode = process.env.SHADE_TREE_ROOT_PROVIDER || "node", { contracts } = {}) {
  const list = contracts || configuredContracts().map((c) => c.address);
  if (list.length <= 1) return makeSingleProvider(mode, list[0]);
  return CompositeRootProvider(list.map((c) => makeSingleProvider(mode, c)));
}
