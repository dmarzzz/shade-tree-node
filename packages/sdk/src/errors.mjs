// One error type with the same codes as the Rust SDK (ADR-0010), so docs and agents describe one API.
//
//   NotAdmitted       the leaf is in none of the admission sets the node honours
//   NotFinalized      the leaf is registered but its root is not final yet
//   BudgetExhausted   every slot of this epoch is spent; `retryAfterMs` says when the next epoch opens
//   PortNotAllowed    the target port is not one the canopy egresses to
//   NoEligibleNode    no node in the canopy fits this request (admission, artifacts, protocol, port)
//   NodeRefused       a node answered and refused the proof
//   Transport         Tor, SOCKS, TLS or the local proxy failed
//   Canopy            the directory is missing, stale or fails verification
//   Rpc               the chain RPC failed or disagreed
//   Wallet            the browser wallet refused, is missing, or is on the wrong chain (JS only)
//   InvalidInput      a caller-supplied value is malformed (JS only)

export const ERROR_CODES = Object.freeze([
  "NotAdmitted", "NotFinalized", "BudgetExhausted", "PortNotAllowed", "NoEligibleNode",
  "NodeRefused", "Transport", "Canopy", "Rpc", "Wallet", "InvalidInput",
]);

export class ShadeNetError extends Error {
  constructor(code, message, { cause, retryAfterMs, ...details } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    if (!ERROR_CODES.includes(code)) throw new TypeError(`unknown ShadeNet error code: ${code}`);
    this.name = "ShadeNetError";
    this.code = code;
    if (retryAfterMs !== undefined) this.retryAfterMs = retryAfterMs;
    Object.assign(this, details);
  }
}

export const isShadeNetError = (e, code) => e instanceof ShadeNetError && (code === undefined || e.code === code);

// Map an error from the JS client (packages/node/client/shade-tree-client.mjs) or the wire code onto a code.
// The original error stays on `cause`.
export function toShadeNetError(error) {
  if (error instanceof ShadeNetError) return error;
  const message = String(error?.message ?? error);
  const code = error?.code;
  const wrap = (c, extra = {}) => new ShadeNetError(c, message, { cause: error, ...extra });
  if (code === "SHADE_TREE_EPOCH_BUDGET_EXHAUSTED") {
    return wrap("BudgetExhausted", { retryAfterMs: error.retryAfterMs ?? null, resetAt: error.resetAt ?? null });
  }
  if (/is in none of|not in group|leaf is in the .* set|--max-anon/i.test(message)) return wrap("NotAdmitted");
  if (/not finali[sz]ed|finality/i.test(message)) return wrap("NotFinalized");
  if (/https:\/\/ only|port .*not allowed|egresses :443/i.test(message)) return wrap("PortNotAllowed");
  if (/no gateway|no eligible|negotiation failed|no-mutual-artifact/i.test(message)) return wrap("NoEligibleNode");
  if (/gate refused|refused:|rejected the proof/i.test(message)) return wrap("NodeRefused");
  if (/directory|canopy|signer-not-pinned|bad-signature/i.test(message)) return wrap("Canopy");
  if (/rpc|eth_|could not detect network|missing revert data/i.test(message)) return wrap("Rpc");
  if (error?.name === "ShadeTreeGatewayAckError" || error?.name === "ShadeTreeFetchError") return wrap("Transport");
  if (/socks|tor|ECONNREFUSED|ETIMEDOUT|ECONNRESET|socket|tls/i.test(message)) return wrap("Transport");
  return wrap("Transport");
}
