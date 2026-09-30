// packages/node/lib/admission.mjs — T-FEAT-9: per-gateway ADMISSION POLICY names (docs/adr/0008).
//
// A gateway PROVIDER chooses which membership roots it honours (`SHADE_TREE_ADMIT`) and, if it sells
// access, which payment rails (`SHADE_TREE_PAY_PROTOCOLS`). These are the pure, dependency-free
// parsers shared by the gateway (packages/node/gateway/gateway.mjs resolveAdmission — which ALSO checks the
// named contracts are configured and fails closed), the heartbeat (advertises the policy as
// signed caps), the bootnode (/health `pay` advert), the registrar (which rails to serve) and
// the client (which gateways admit ITS leaf; `--max-anon`).
//
// The ADMISSION PATHS, in ANONYMITY ORDER (most anonymous first) — this order is the canonical
// order everywhere (startup line, signed caps, error messages):
//   invited  the static members.json — no on-chain footprint at all
//   staked   a StakedReputationSet — the staking wallet <-> commitment is linkable on chain
//   paid     the PaidAccessSet — the buyer address -> operator transfer + tier bucket are public
//            (x402 and MPP are equal on this axis)
// The DEFAULT is `invited` — the maximum-anonymity mode — even when the network record supplies
// contract addresses; a provider opts into staked/paid explicitly.
//
// `SHADE_TREE_ROOTS` (T-FEAT-7: static,onchain) stays as a DEPRECATED alias: static -> invited,
// onchain -> staked+paid (whichever contracts are configured); the gateway warns at startup.

export const ADMIT_ORDER = Object.freeze(["invited", "staked", "paid"]);
export const ADMIT_SET = new Set(ADMIT_ORDER);
export const DEFAULT_ADMIT = Object.freeze(["invited"]);
export const PAY_PROTOCOL_ORDER = Object.freeze(["x402", "mpp"]);
export const PAY_PROTOCOL_SET = new Set(PAY_PROTOCOL_ORDER);

// The root-source kind (packages/node/lib/root-provider.mjs configuredContracts: "staked" | "paid") and the
// client's discovered leaf-source label ("members.json" | "staked(0x..)" | "paid(0x..)") -> the
// admission path name. Returns null for an unknown label (never throws).
export function admitPathOfSource(label) {
  const s = String(label ?? "");
  if (s === "members.json" || s === "static" || s === "invited") return "invited";
  if (s === "staked" || s.startsWith("staked(")) return "staked";
  if (s === "paid" || s.startsWith("paid(")) return "paid";
  return null;
}

// Parse an `SHADE_TREE_ADMIT` spec ("invited,paid", case/space tolerant) into the canonical
// anonymity-ordered, deduped list. Throws a precise error on an unknown name or an empty list.
// (Whether the named paths have a contract behind them is the GATEWAY's check, resolveAdmission.)
export function parseAdmit(spec, { name = "SHADE_TREE_ADMIT" } = {}) {
  const raw = String(spec ?? "").trim();
  const parts = raw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  for (const p of parts) if (!ADMIT_SET.has(p)) throw new Error(`${name}: unknown admission path "${p.slice(0, 16)}" (expected a comma list drawn from: ${ADMIT_ORDER.join(", ")})`);
  if (!parts.length) throw new Error(`${name}: no admission path selected (expected a comma list drawn from: ${ADMIT_ORDER.join(", ")})`);
  return ADMIT_ORDER.filter((p) => parts.includes(p));
}

// The deprecated `SHADE_TREE_ROOTS` alias -> admission paths. `hasStaked` / `hasPaid` say which
// contract kinds are configured, so `onchain` maps to exactly the on-chain sets that exist.
// Throws (as T-FEAT-7 did) on an unknown source, an empty list, or `onchain` with no contract.
export function admitsFromRoots(spec, { hasStaked = false, hasPaid = false } = {}) {
  const raw = String(spec ?? "").trim();
  const parts = raw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  for (const p of parts) if (p !== "static" && p !== "onchain") throw new Error(`SHADE_TREE_ROOTS: unknown source "${p.slice(0, 16)}" (expected static,onchain; SHADE_TREE_ROOTS is deprecated -- use SHADE_TREE_ADMIT=invited,staked,paid)`);
  const st = parts.includes("static"), on = parts.includes("onchain");
  if (!st && !on) throw new Error("SHADE_TREE_ROOTS: no source selected (SHADE_TREE_ROOTS is deprecated -- use SHADE_TREE_ADMIT=invited,staked,paid)");
  if (on && !hasStaked && !hasPaid) throw new Error("SHADE_TREE_ROOTS names onchain but no contract is configured (set SHADE_TREE_GROUP_CONTRACT and/or SHADE_TREE_PAID_ACCESS_CONTRACT); SHADE_TREE_ROOTS is deprecated -- use SHADE_TREE_ADMIT");
  const out = [];
  if (st) out.push("invited");
  if (on && hasStaked) out.push("staked");
  if (on && hasPaid) out.push("paid");
  return out;
}

// The startup / status line: `admits: invited+staked+paid`.
export function describeAdmits(admits) {
  const list = ADMIT_ORDER.filter((p) => (admits || []).includes(p));
  return "admits: " + (list.join("+") || "(none)");
}

// Parse `SHADE_TREE_PAY_PROTOCOLS` ("x402,mpp"; any non-empty subset; unset/empty = both) into the
// canonical ordered list. Throws on an unknown rail.
export function parsePayProtocols(spec, { name = "SHADE_TREE_PAY_PROTOCOLS" } = {}) {
  const raw = String(spec ?? "").trim();
  if (!raw) return [...PAY_PROTOCOL_ORDER];
  const parts = raw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  for (const p of parts) if (!PAY_PROTOCOL_SET.has(p)) throw new Error(`${name}: unknown payment protocol "${p.slice(0, 16)}" (expected a comma list drawn from: ${PAY_PROTOCOL_ORDER.join(", ")})`);
  if (!parts.length) throw new Error(`${name}: no payment protocol selected (expected a comma list drawn from: ${PAY_PROTOCOL_ORDER.join(", ")})`);
  return PAY_PROTOCOL_ORDER.filter((p) => parts.includes(p));
}

// The client's leaf-source pin: `SHADE_TREE_LEAF_SOURCE=auto|invited|staked|paid` (default auto).
export function parseLeafSource(spec, { name = "SHADE_TREE_LEAF_SOURCE" } = {}) {
  const raw = String(spec ?? "").trim().toLowerCase();
  if (!raw || raw === "auto") return "auto";
  if (ADMIT_SET.has(raw)) return raw;
  throw new Error(`${name}: expected auto, ${ADMIT_ORDER.join(", ")} (got "${raw.slice(0, 16)}")`);
}

// Boolean env/flag: `1`, `true`, `yes`, `on` => true (SHADE_TREE_MAX_ANON; `--max-anon` maps to "true").
export function envFlag(v) {
  const s = String(v ?? "").trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}
