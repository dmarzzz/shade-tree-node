// GET /api/v1/data/stake/sepolia/head: aggregate, identity-free staking state for the Get access
// page (the page's CSP allows only same-origin fetches). It takes no parameters, so it can never
// see a visitor's commitment; per-member status stays in the visitor's own wallet.
import profile from "./_stake-profile.mjs";

export const STAKE_HEAD_SCHEMA = "shadenet-stake-head-v1";
const SELECTORS = Object.freeze({
  nextIndex: "0xfc7e9c6f",
  activeCount: "0x4331ed1f",
  bondFor: "0xe0b91f92",
});
const SUCCESS_HEADERS = {
  "Cache-Control": "public, max-age=30",
  "Content-Type": "application/json; charset=utf-8",
  "Vercel-CDN-Cache-Control": "public, max-age=60, stale-while-revalidate=600",
  "X-Content-Type-Options": "nosniff",
};
const FAILURE_HEADERS = { "Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8", "Retry-After": "60", "X-Content-Type-Options": "nosniff" };
const REQUEST_ERROR_HEADERS = { "Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff" };

const word = (value) => BigInt(value).toString(16).padStart(64, "0");

export function makeRpc(fetchImpl = globalThis.fetch, url = profile.rpcUrl, timeoutMs = 4_000) {
  let id = 0;
  return async (method, params) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`rpc-http-${response.status}`);
      const body = await response.json();
      if (body.error || body.result === undefined || body.result === null) throw new Error("rpc-error");
      return body.result;
    } finally {
      clearTimeout(timer);
    }
  };
}

function uint(hex) {
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(hex)) throw new Error("rpc-shape");
  return BigInt(hex);
}

export async function readStakeHead(rpc, now = new Date()) {
  const call = (data, tag) => rpc("eth_call", [{ to: profile.contract, data }, tag]);
  const finalized = await rpc("eth_getBlockByNumber", ["finalized", false]).catch(() => null);
  const [head, nextIndex, activeCount, ...bonds] = await Promise.all([
    rpc("eth_blockNumber", []),
    call(SELECTORS.nextIndex, "finalized"),
    call(SELECTORS.activeCount, "finalized"),
    ...profile.tiers.map((tier) => call(`${SELECTORS.bondFor}${word(tier.limit)}`, "latest")),
  ]);
  return {
    schema: STAKE_HEAD_SCHEMA,
    network: profile.network,
    chainId: profile.chainId,
    contract: profile.contract,
    observedAt: now.toISOString(),
    headBlock: Number(uint(head)),
    finalizedBlock: finalized && typeof finalized === "object" ? Number(uint(finalized.number)) : null,
    nextIndex: Number(uint(nextIndex)),
    activeCount: Number(uint(activeCount)),
    tiers: profile.tiers.map((tier, i) => ({
      limit: tier.limit,
      bondWei: tier.bondWei,
      onChainBondWei: uint(bonds[i]).toString(),
    })),
  };
}

export async function GET(request, { rpc = makeRpc() } = {}) {
  if (request?.url && new URL(request.url).search) return new Response('{"error":"unsupported_query"}\n', { status: 400, headers: REQUEST_ERROR_HEADERS });
  try {
    const head = await readStakeHead(rpc);
    return new Response(`${JSON.stringify(head)}\n`, { status: 200, headers: { ...SUCCESS_HEADERS, "X-ShadeNet-Schema": STAKE_HEAD_SCHEMA } });
  } catch (error) {
    console.error(JSON.stringify({ event: "stake_head_unavailable", reason: String(error?.message || "internal").slice(0, 40) }));
    return new Response('{"error":"stake_head_unavailable"}\n', { status: 503, headers: FAILURE_HEADERS });
  }
}
