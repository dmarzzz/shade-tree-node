// StakeVerifier: the pluggable source of "is this gateway operator staked right now?"
//
// The bootnode (admission = stake) and any zero-trust client ask one question about an
// operator address: does GatewayRegistry.isStaked(operator) hold at the confirmation depth
// we trust? So the source sits behind one interface and is chosen at config time, exactly
// like the membership RootProvider (packages/node/lib/root-provider.mjs):
//
//   isStaked(operatorAddr) -> Promise<boolean>
//
// Two providers, interchangeable:
//   - OnchainStakeVerifier : eth_call GatewayRegistry.isStaked(address) over JSON-RPC. Reads
//                            at `finalized` (or head - SHADE_TREE_CONFIRMATIONS). Trusts the RPC the
//                            same way the rest of the node path does; run your own for the
//                            solo-staker path. Short TTL cache so a heartbeat storm is cheap.
//   - MockStakeVerifier    : chainless dev. SHADE_TREE_STAKE_ALLOWLIST=addr,addr (staked set), or
//                            with no allowlist, everyone is "staked" (open dev). Lets the whole
//                            announce/discovery loop run and be tested with no chain at all.
//
// Zero new runtime deps: JSON-RPC over global fetch + keccak256 from js-sha3 (already a dep)
// to build the 4-byte selector. Mirrors root-provider.mjs so the two read paths stay uniform.

import pkg from "js-sha3";
import { networkDefault } from "./network-record.mjs";
import { jsonRpcCall } from "./rpc-safety.mjs";
const { keccak256 } = pkg;

// Registry address + RPC: explicit env wins; else the SHADE_TREE_NETWORK record (network/<name>/
// contracts.json `contracts.gatewayRegistry` / `rpcUrl`, packages/node/lib/network-record.mjs); else dev defaults.
// networkDefault() never throws (null when SHADE_TREE_NETWORK is unset or the slot is null = undeployed).
const registryAddress = () => process.env.SHADE_TREE_GATEWAY_REGISTRY || networkDefault("SHADE_TREE_GATEWAY_REGISTRY");
const RPC_URL = process.env.SHADE_TREE_RPC_URL || networkDefault("SHADE_TREE_RPC_URL") || "http://127.0.0.1:8545";
// Stake is an admission/liveness read, not a slash trigger, so it defaults to `latest`
// (dev chains like anvil don't advance `finalized` promptly). Set SHADE_TREE_CONFIRMATIONS>0
// to read at head-N for reorg safety on a public chain.
const CONFIRMATIONS = Number(process.env.SHADE_TREE_CONFIRMATIONS || 0); // 0 => latest
const CACHE_MS = Number(process.env.SHADE_TREE_STAKE_CACHE_MS || 15000);

// selector = first 4 bytes of keccak256("isStaked(address)")
const IS_STAKED_SELECTOR = "0x" + keccak256("isStaked(address)").slice(0, 8);

let rpcId = 0;
async function rpc(method, params, url) {
  return jsonRpcCall(url, method, params, { id: ++rpcId });
}

function encodeAddress(addr) {
  const a = String(addr).toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error(`bad address: ${addr}`);
  return "0".repeat(24) + a; // left-pad to 32 bytes
}

async function blockTag(url) {
  if (CONFIRMATIONS <= 0) return "latest";
  const b = await rpc("eth_getBlockByNumber", ["latest", false], url);
  const head = b ? Number(BigInt(b.number)) : 0;
  return "0x" + BigInt(Math.max(0, head - CONFIRMATIONS)).toString(16);
}

export function OnchainStakeVerifier({ rpcUrl = RPC_URL, contract = registryAddress(), cacheMs = CACHE_MS } = {}) {
  if (!contract) throw new Error("OnchainStakeVerifier needs SHADE_TREE_GATEWAY_REGISTRY (GatewayRegistry address; or SHADE_TREE_NETWORK with contracts.gatewayRegistry deployed)");
  const cache = new Map(); // operator -> { value, at }

  async function isStaked(operator) {
    const key = String(operator).toLowerCase();
    const hit = cache.get(key);
    const now = Date.now();
    if (hit && now - hit.at < cacheMs) return hit.value;
    const tag = await blockTag(rpcUrl);
    const data = IS_STAKED_SELECTOR + encodeAddress(operator);
    const ret = await rpc("eth_call", [{ to: contract, data }, tag], rpcUrl);
    // bool is the last byte of the 32-byte word; anything nonzero is true.
    const value = typeof ret === "string" && /[1-9a-f]/i.test(ret.replace(/^0x0*/, ""));
    cache.set(key, { value, at: now });
    return value;
  }
  return { isStaked, mode: "onchain" };
}

export function MockStakeVerifier({ allowlist = process.env.SHADE_TREE_STAKE_ALLOWLIST } = {}) {
  const set = allowlist
    ? new Set(String(allowlist).split(",").map((s) => s.trim().toLowerCase()).filter(Boolean))
    : null;
  async function isStaked(operator) {
    if (!set) return true; // no allowlist => open dev: everyone counts as staked
    return set.has(String(operator).toLowerCase());
  }
  return { isStaked, mode: set ? `mock:allowlist(${set.size})` : "mock:open" };
}

// Factory. Default: on-chain when a registry address is configured, else mock (dev).
export function makeStakeVerifier(mode = process.env.SHADE_TREE_STAKE_MODE) {
  const resolved = mode || (registryAddress() ? "onchain" : "mock");
  if (resolved === "onchain") return OnchainStakeVerifier();
  if (resolved === "mock") return MockStakeVerifier();
  throw new Error(`unknown SHADE_TREE_STAKE_MODE: ${resolved} (expected onchain|mock)`);
}
