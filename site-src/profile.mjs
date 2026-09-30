// The Get access page's only source of numbers and addresses: the bundled network record.
// Every price, tier, rate and address on /stake/ comes from here, so a redeploy (new contract,
// new economics) is a rebuild, not a copy edit. esbuild inlines the JSON at bundle time.
import deployment from "./record.mjs";
export { SITE_NETWORK, CLIENT_RELEASE } from "./record.mjs";

const staked = deployment.admission?.roots?.staked;
if (!staked) throw new Error("deployment.json has no staked admission root; the Get access page needs one.");

const WEI_PER_ETH = 10n ** 18n;
const MIB = 1024 * 1024;

export const NETWORK = deployment.network;
// The raw record, for the SDK (same source of truth).
export const NETWORK_RECORD = deployment;
export const CHAIN_ID = BigInt(staked.chainId);
export const CONTRACT = staked.contract;
export const RPC_URL = staked.rpcUrl;
export const DEPLOY_BLOCK = staked.deployBlock;
export const DEFAULT_LIMIT = BigInt(staked.defaultLimit);
export const UNBONDING_SECONDS = staked.unbondingSeconds;
export const EXPLORER_URL = CHAIN_ID === 11155111n ? "https://sepolia.etherscan.io" : null;
// What `register` takes: the tier-bound leaf today, or the bare identity commitment once the
// contract derives the leaf itself (audit 2.1.4, Option A). Absent means the current leaf ABI.
export const REGISTER_INPUT = staked.registerInput === "identityCommitment" ? "identityCommitment" : "leaf";
// Slash split, when the record states it: 1/divisor goes to the reporter, the rest is burned.
export const SLASH_REWARD_DIVISOR = staked.slashRewardDivisor ? BigInt(staked.slashRewardDivisor) : null;

export const TIERS = Object.freeze(staked.tiers.map((tier) => Object.freeze({
  limit: BigInt(tier.limit),
  bondWei: BigInt(tier.bondWei),
})));

export const RATE = Object.freeze({
  epochSeconds: deployment.ratePolicy.epochSeconds,
  payloadBytesPerSlot: deployment.ratePolicy.payloadBytesPerSlot,
  payloadMiB: deployment.ratePolicy.payloadBytesPerSlot / MIB,
});

// H2's switch (ADR 0011): with session tickets on, one slot opens a session at one node instead of
// one tunnel. The book's shape is the research-v1 class in docs/design/SESSION-TICKETS.md, not a
// record value, so it lives here as a constant next to the switch that turns it on.
export const SESSION_TICKETS = deployment.sessionTickets === true || staked.sessionTickets === true;
export const SESSION_CLASS = Object.freeze({ tickets: 6, lifetimeSeconds: 90 });

export const SECURITY = Object.freeze({
  proofArtifacts: deployment.security?.proofArtifacts || "unknown",
  status: deployment.status,
});

export function tierFor(limit) {
  const wanted = BigInt(limit);
  return TIERS.find((tier) => tier.limit === wanted) || null;
}

// Wei -> "0.1" / "0.8" / "1.25": exact decimal, no float rounding, trailing zeros trimmed.
export function formatEth(wei) {
  const value = BigInt(wei);
  const whole = value / WEI_PER_ETH;
  const fraction = (value % WEI_PER_ETH).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

export function formatDuration(seconds) {
  if (seconds % 86400 === 0) return seconds === 86400 ? "24 hours" : `${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? "1 hour" : `${seconds / 3600} hours`;
  if (seconds % 60 === 0) return seconds === 60 ? "1 minute" : `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

export function shortAddress(address) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export const CHAIN_NAME = CHAIN_ID === 11155111n ? "Sepolia" : `chain ${CHAIN_ID}`;
