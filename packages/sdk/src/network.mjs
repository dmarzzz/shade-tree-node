// Network records. Every contract address, tier, bond and signer the SDK uses comes from a
// deployment record (network/<name>/deployment.json), never from constants in code, so a new
// deploy or new economics only changes the record.

import sepolia from "../../../network/sepolia/deployment.json" with { type: "json" };
import { ShadeNetError } from "./errors.mjs";

const BUNDLED = Object.freeze({ sepolia });

export const CHAIN_NAMES = Object.freeze({ 1: "Ethereum", 11155111: "Sepolia" });

export function bundledNetworks() {
  return Object.keys(BUNDLED);
}

// The staked admission profile of a record, normalized: bigint wei, number limits.
function stakedProfile(record) {
  const staked = record?.admission?.roots?.staked;
  if (!staked) return null;
  return Object.freeze({
    profile: staked.profile,
    chainId: Number(staked.chainId),
    contract: staked.contract,
    rpcUrl: staked.rpcUrl,
    deployBlock: staked.deployBlock ?? null,
    withdrawVerifier: staked.withdrawVerifier ?? null,
    defaultLimit: Number(staked.defaultLimit),
    tiers: Object.freeze((staked.tiers || []).map((t) => Object.freeze({ limit: Number(t.limit), bondWei: BigInt(t.bondWei) }))),
    unbondingSeconds: Number(staked.unbondingSeconds),
    // "identityCommitment": a ShadeNet set (registerIdentity, bound proof contexts). Absent: the v4 set.
    registerInput: staked.registerInput === "identityCommitment" ? "identityCommitment" : "leaf",
  });
}

// resolveNetwork("sepolia") or resolveNetwork(recordObject) -> a frozen view the rest of the SDK reads.
export function resolveNetwork(nameOrRecord = "sepolia") {
  const record = typeof nameOrRecord === "string" ? BUNDLED[nameOrRecord] : nameOrRecord;
  if (!record || typeof record !== "object") {
    throw new ShadeNetError("InvalidInput", `unknown network ${String(nameOrRecord)}; bundled: ${bundledNetworks().join(", ")}`);
  }
  return Object.freeze({
    name: record.network,
    status: record.status,
    record,
    protocol: record.protocol,
    ratePolicy: record.ratePolicy,
    elder: record.elder ? Object.freeze({ onion: record.elder.onion, canopySigner: record.elder.canopySigner }) : null,
    staked: stakedProfile(record),
    trust: record.security?.proofArtifacts ?? null,
  });
}

export function tierFor(network, limit) {
  const tier = network.staked?.tiers.find((t) => t.limit === Number(limit));
  if (!tier) throw new ShadeNetError("InvalidInput", `tier ${limit} is not offered on ${network.name}`);
  return tier;
}
