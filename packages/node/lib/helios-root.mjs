// Helios trust anchor for LightClientRootProvider (T-DEV-9b, docs/LIGHT-CLIENT.md option A).
//
// LightClientRootProvider (packages/node/lib/root-provider.mjs) proves the contract's `currentRoot` storage
// slot against a block's `stateRoot` with EIP-1186 Merkle-Patricia proofs. That closes every
// trust gap EXCEPT the stateRoot itself, which by default is read from the RPC's block header
// and trusted. This module supplies the missing anchor: a `trustedStateRoot(blockTag)` hook
// that reads the header from a LOCAL Helios verifying JSON-RPC (a16z/helios, run as a sidecar
// -- packages/node/bootnode/deploy/bootstrap.sh SHADE_TREE_HELIOS=1), whose `eth_getBlockByNumber` only returns
// headers that chain to a beacon-chain sync-committee-verified execution payload.
//
// Trust, stated plainly: with this hook wired the RPC (`SHADE_TREE_RPC_URL`) is a dumb data pipe.
// It can withhold (unavailability) but it cannot forge the root: the account+storage proof must
// hash up to a stateRoot that Helios attests, and Helios attests only what the sync committee
// signed. The residual trust is the sync committee (2/3-honest, ~512 validators / ~27h) plus the
// weak-subjectivity checkpoint Helios booted from -- see docs/LIGHT-CLIENT.md. Helios itself is a
// LOCAL process on loopback: if the loopback socket is hijacked the anchor is gone, which is why
// the sidecar binds 127.0.0.1 and the unit is sandboxed like the other shade-tree units.
//
// Fail-closed contract (every branch throws with a precise reason; nothing degrades silently):
//   * Helios unreachable / non-JSON / JSON-RPC error         -> throw (no anchor, no roots)
//   * Helios eth_chainId != expected chain                    -> throw at first use (misconfig
//                                                                or a wrong sidecar), never later
//   * Helios has no block for the tag (null / out of window)  -> throw
//   * header without a 32-byte stateRoot / number             -> throw
// The chain check runs once, on the first call ("startup" from the provider's point of view:
// packages/node/gateway/gateway.mjs awaits the first currentRoots() before serving), and is retried on the
// next call if it failed, so a sidecar that is still booting delays start rather than poisoning
// it. Expected chain: `chainId` option, else SHADE_TREE_HELIOS_CHAIN_ID, else the upstream RPC's own
// eth_chainId (both endpoints must agree on the chain; either unreachable -> throw).
//
// Tag mapping (what LightClientRootProvider passes in -> what Helios is asked):
//   "finalized" -> eth_getBlockByNumber("finalized")   the recommended setting (SHADE_TREE_CONFIRMATIONS=0)
//   "latest"    -> eth_getBlockByNumber("latest")      Helios refuses this while it is out of sync
//                                                       (error passes through -> fail closed)
//   0x<hex>     -> eth_getBlockByNumber("0x<hex>")     Helios serves only recent verified blocks
//                                                       (its EIP-2935 window); older -> error/null -> throw
// Zero new dependencies: JSON-RPC over global fetch (Node 18+), like root-provider.mjs.

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

// Minimal JSON-RPC POST with a bounded timeout. Every failure is rethrown with the endpoint and
// method named so an operator can tell "Helios is down" from "the RPC is down" from the log line.
async function rpcCall(url, method, params, { timeoutMs = 10_000, label = "helios" } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ctrl.signal,
    });
  } catch (e) {
    throw new Error(`${label} unreachable at ${url} (${method}): ${e.message}`);
  } finally {
    clearTimeout(t);
  }
  let json;
  try { json = await res.json(); } catch { throw new Error(`${label} at ${url} returned non-JSON to ${method} (HTTP ${res.status})`); }
  if (json && json.error) throw new Error(`${label} ${method} error: ${json.error.message || JSON.stringify(json.error)}`);
  return json ? json.result : undefined;
}

function parseChainId(hexOrNum, label) {
  if (hexOrNum == null) throw new Error(`${label} eth_chainId returned nothing`);
  let n;
  try { n = BigInt(hexOrNum); } catch { throw new Error(`${label} eth_chainId returned an unparseable value: ${String(hexOrNum)}`); }
  if (n <= 0n) throw new Error(`${label} eth_chainId returned a non-positive chain id`);
  return n;
}

// Build the hook. Options:
//   rpcUrl          Helios local JSON-RPC (SHADE_TREE_HELIOS_RPC_URL), e.g. http://127.0.0.1:8545
//   chainId         expected chain (number|bigint|hex string); default SHADE_TREE_HELIOS_CHAIN_ID
//   upstreamRpcUrl  the ordinary RPC (SHADE_TREE_RPC_URL): used to derive the expected chain when
//                   `chainId` is not given (both must agree)
//   timeoutMs       per-call timeout (default 10s)
// Returns trustedStateRoot(blockTag) -> { stateRoot, number, hash } and exposes
// `.checkChain()` (the memoised startup check) and `.rpcUrl` for logging.
export function makeHeliosTrustedStateRoot({
  rpcUrl = process.env.SHADE_TREE_HELIOS_RPC_URL,
  chainId = process.env.SHADE_TREE_HELIOS_CHAIN_ID,
  upstreamRpcUrl = process.env.SHADE_TREE_RPC_URL || "http://127.0.0.1:8545",
  timeoutMs = 10_000,
} = {}) {
  if (!rpcUrl) throw new Error("makeHeliosTrustedStateRoot needs rpcUrl (SHADE_TREE_HELIOS_RPC_URL)");
  let u;
  try { u = new URL(rpcUrl); } catch { throw new Error(`SHADE_TREE_HELIOS_RPC_URL is not a URL: ${rpcUrl}`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`SHADE_TREE_HELIOS_RPC_URL must be http(s): ${rpcUrl}`);
  const expectedGiven = chainId != null && chainId !== "" ? parseChainId(chainId, "configured SHADE_TREE_HELIOS_CHAIN_ID") : null;

  // Memoised startup check; a rejected attempt is dropped so the next call retries.
  let chainCheck = null;
  async function checkChain() {
    if (!chainCheck) {
      chainCheck = (async () => {
        const heliosId = parseChainId(await rpcCall(rpcUrl, "eth_chainId", [], { timeoutMs, label: "helios" }), "helios");
        let expected = expectedGiven;
        let source = "SHADE_TREE_HELIOS_CHAIN_ID";
        if (expected == null) {
          expected = parseChainId(await rpcCall(upstreamRpcUrl, "eth_chainId", [], { timeoutMs, label: "rpc" }), "rpc");
          source = `SHADE_TREE_RPC_URL (${upstreamRpcUrl})`;
        }
        if (heliosId !== expected) {
          throw new Error(
            `helios chainId mismatch: helios at ${rpcUrl} reports ${heliosId} but the configured chain is ${expected} (from ${source}); refusing to anchor`,
          );
        }
        return { chainId: heliosId };
      })().catch((e) => { chainCheck = null; throw e; });
    }
    return chainCheck;
  }

  async function trustedStateRoot(blockTag = "finalized") {
    await checkChain();
    let tag = blockTag;
    if (typeof tag === "number" || typeof tag === "bigint") tag = "0x" + BigInt(tag).toString(16);
    if (typeof tag !== "string" || !(tag === "finalized" || tag === "latest" || tag === "safe" || /^0x[0-9a-fA-F]+$/.test(tag))) {
      throw new Error(`helios: unsupported block tag ${String(blockTag)} (expected finalized|latest|safe|0x<hex>)`);
    }
    const blk = await rpcCall(rpcUrl, "eth_getBlockByNumber", [tag, false], { timeoutMs, label: "helios" });
    if (!blk) throw new Error(`helios has no verified block for tag ${tag} (null; outside its verified window or not yet synced)`);
    if (typeof blk.stateRoot !== "string" || !HEX32.test(blk.stateRoot)) throw new Error(`helios block ${tag}: missing/malformed stateRoot`);
    if (blk.number == null) throw new Error(`helios block ${tag}: missing number`);
    let number;
    try { number = Number(BigInt(blk.number)); } catch { throw new Error(`helios block ${tag}: malformed number ${String(blk.number)}`); }
    return { stateRoot: blk.stateRoot.toLowerCase(), number, hash: typeof blk.hash === "string" ? blk.hash.toLowerCase() : null };
  }

  trustedStateRoot.checkChain = checkChain;
  trustedStateRoot.rpcUrl = rpcUrl;
  trustedStateRoot.source = "helios (sync-committee verified)";
  return trustedStateRoot;
}
