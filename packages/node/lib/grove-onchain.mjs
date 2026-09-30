// Target-independent collection and privacy projection for the Grove v2 onchain ledger.
//
// This module deliberately does not contain a production address or RPC URL. A collector must
// receive a current `status: "live"` v4 record, verify every admitted runtime code hash at one
// delayed finalized block, and obtain the same block/counters from every approved RPC. The only
// checked-in Sepolia record is retired, so it is rejected before any RPC call is made.

import {
  Interface,
  getAddress,
  isAddress,
  keccak256,
  verifyMessage,
} from "ethers";

export const GROVE_ONCHAIN_DEFINITION = "finalized-v4-onchain-activity";
export const GROVE_ONCHAIN_MINIMUM_COHORT = 5;
export const GROVE_ONCHAIN_DELAY_HOURS = 6;
export const GROVE_ONCHAIN_MAX_COUNT = 100_000_000;
export const GROVE_SETTLEMENT_SCHEMA = "shade-tree-registrar-settlements-v1";

const U64_MAX = (1n << 64n) - 1n;
const FIELD_MAX = (1n << 256n) - 1n;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const ISO_DELAY_MS = GROVE_ONCHAIN_DELAY_HOURS * 60 * 60_000;
const SET_ABI = new Interface([
  "function activeCount() view returns (uint256)",
  "function liveCount() view returns (uint256)",
]);
const TOKEN_ABI = new Interface([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
]);
const PAID_ABI = new Interface([
  "event Inserted(uint256 indexed commitment,uint256 limit,uint256 index,uint256 root)",
]);

export class GroveOnchainError extends Error {
  constructor(code) {
    super(code);
    this.name = "GroveOnchainError";
    this.code = code;
  }
}

function fail(code) { throw new GroveOnchainError(code); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function exactKeys(value, keys) {
  return object(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}
function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= GROVE_ONCHAIN_MAX_COUNT;
}
function canonicalIso(value) {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
function decimalU64(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return null;
  try { const parsed = BigInt(value); return parsed <= U64_MAX ? parsed : null; } catch { return null; }
}
function decimalUint256(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value)) return null;
  try { const parsed = BigInt(value); return parsed <= FIELD_MAX ? parsed : null; } catch { return null; }
}
function normalizedAddress(value) {
  try { return isAddress(value) ? getAddress(value) : null; } catch { return null; }
}
function lowerHash(value) { return typeof value === "string" && HASH.test(value) ? value.toLowerCase() : null; }

function validRole(role) {
  return exactKeys(role, ["address", "deployBlock", "runtimeCodeHash"])
    && normalizedAddress(role.address) !== null
    && Number.isSafeInteger(role.deployBlock) && role.deployBlock >= 0
    && lowerHash(role.runtimeCodeHash) !== null;
}

// The activity block is an additive record contract. Other deployment keys may exist around it,
// but these fields are mandatory before the observer is allowed to touch a chain.
export function validateLiveOnchainTarget(record, { expectedNetwork = "sepolia", expectedChainId = 11155111 } = {}) {
  if (!object(record)) fail("target-missing");
  if (record.status === "retired") fail("target-retired");
  if (record.status !== "live") fail("target-not-live");
  if (record.network !== expectedNetwork) fail("target-network");
  if (!Number.isSafeInteger(record.chainId) || record.chainId <= 0 || record.chainId !== expectedChainId) fail("target-chain-id");
  if (record.protocolVersion !== 4) fail("target-protocol-version");
  const finality = record.finality;
  if (!exactKeys(finality, ["confirmations", "approvedRpcUrls"]) || !Number.isSafeInteger(finality.confirmations)
    || finality.confirmations < 1 || !Array.isArray(finality.approvedRpcUrls)
    || finality.approvedRpcUrls.length < 1 || finality.approvedRpcUrls.some((url) => {
      try { return new URL(url).protocol !== "https:"; } catch { return true; }
    })) fail("target-finality");
  const activity = record.activity;
  if (!exactKeys(activity, ["contracts", "payment", "migration"])) fail("target-activity");
  if (!exactKeys(activity.contracts, ["stakedReputationSet", "paidAccessSet"])
    || !validRole(activity.contracts.stakedReputationSet)
    || !validRole(activity.contracts.paidAccessSet)) fail("target-contracts");
  const migration = activity.migration;
  if (!exactKeys(migration, ["startsAtBlock", "retiresBeforeBlock"])
    || !Number.isSafeInteger(migration.startsAtBlock) || migration.startsAtBlock < 0
    || !(migration.retiresBeforeBlock === null
      || (Number.isSafeInteger(migration.retiresBeforeBlock) && migration.retiresBeforeBlock > migration.startsAtBlock))) {
    fail("target-migration");
  }
  const payment = activity.payment;
  if (!exactKeys(payment, ["attributionRule", "asset", "payee", "registrarKeyId", "registrarPublicKey"])
    || payment.attributionRule !== "signed-registrar-chain-verified-v1"
    || !exactKeys(payment.asset, ["address", "decimals", "symbol"])
    || normalizedAddress(payment.asset.address) === null
    || !Number.isInteger(payment.asset.decimals) || payment.asset.decimals < 0 || payment.asset.decimals > 255
    || typeof payment.asset.symbol !== "string" || !/^[A-Za-z0-9._-]{1,16}$/.test(payment.asset.symbol)
    || normalizedAddress(payment.payee) === null
    || typeof payment.registrarKeyId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(payment.registrarKeyId)
    || typeof payment.registrarPublicKey !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(payment.registrarPublicKey)) {
    fail("target-payment");
  }
  return record;
}

function validSettlementFact(value) {
  return exactKeys(value, ["asset", "atomicValue", "commitment", "insertTx", "payee", "rail", "settlementTx"])
    && normalizedAddress(value.asset) !== null && decimalUint256(value.atomicValue) !== null
    && decimalUint256(value.atomicValue) > 0n && decimalUint256(value.commitment) !== null
    && lowerHash(value.settlementTx) !== null && lowerHash(value.insertTx) !== null
    && normalizedAddress(value.payee) !== null && ["x402", "mpp"].includes(value.rail);
}

export function settlementSigningPayload(aggregate) {
  return {
    schema: aggregate.schema,
    chainId: aggregate.chainId,
    generatedAt: aggregate.generatedAt,
    registrarKeyId: aggregate.registrarKeyId,
    settlements: aggregate.settlements.map((fact) => ({
      asset: fact.asset,
      atomicValue: fact.atomicValue,
      commitment: fact.commitment,
      insertTx: fact.insertTx,
      payee: fact.payee,
      rail: fact.rail,
      settlementTx: fact.settlementTx,
    })),
  };
}

export function validateRegistrarAggregate(aggregate, target) {
  const payment = target.activity.payment;
  if (!exactKeys(aggregate, ["schema", "chainId", "generatedAt", "registrarKeyId", "settlements", "attestation"])
    || aggregate.schema !== GROVE_SETTLEMENT_SCHEMA || aggregate.chainId !== target.chainId
    || !canonicalIso(aggregate.generatedAt) || aggregate.registrarKeyId !== payment.registrarKeyId
    || !Array.isArray(aggregate.settlements) || aggregate.settlements.length > 100_000
    || !aggregate.settlements.every(validSettlementFact)
    || !exactKeys(aggregate.attestation, ["algorithm", "keyId", "signature"])
    || aggregate.attestation.algorithm !== "EIP-191" || aggregate.attestation.keyId !== payment.registrarKeyId
    || typeof aggregate.attestation.signature !== "string") fail("registrar-schema");
  let recovered;
  try { recovered = verifyMessage(JSON.stringify(settlementSigningPayload(aggregate)), aggregate.attestation.signature); }
  catch { fail("registrar-signature"); }
  if (recovered.toLowerCase() !== payment.registrarPublicKey.toLowerCase()) fail("registrar-signature");
  return aggregate;
}

function eventKey(event, chainId) {
  if (!Number.isInteger(event.logIndex) || event.logIndex < 0 || !lowerHash(event.transactionHash)
    || !normalizedAddress(event.address)) fail("event-identity");
  return `${chainId}:${event.address.toLowerCase()}:${event.transactionHash.toLowerCase()}:${event.logIndex}`;
}

// Pure event reducer used for counter cross-checks and persisted index replay. Commitments stay
// in this private state only; public projection below never copies them.
export function reduceActivityEvents(events, { chainId, previous = null } = {}) {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) fail("event-chain");
  const state = previous ? structuredClone(previous) : {
    seen: {}, staked: {}, paid: {}, stakedSlashes: 0, paidSlashes: 0,
  };
  for (const event of events) {
    if (event.removed === true) fail("event-removed");
    const key = eventKey(event, chainId);
    if (state.seen[key]) continue;
    const commitment = decimalUint256(event.commitment);
    if (commitment === null) fail("event-commitment");
    const member = commitment.toString();
    switch (event.kind) {
      case "staked-registered":
        state.staked[member] = "active";
        break;
      case "staked-exiting":
        if (state.staked[member] === "active") state.staked[member] = "exiting";
        break;
      case "staked-withdrawn":
        if (state.staked[member] === "exiting") state.staked[member] = "withdrawn";
        break;
      case "staked-slashed":
        state.staked[member] = "slashed";
        state.stakedSlashes += 1;
        break;
      case "paid-inserted":
        state.paid[member] = "live";
        break;
      case "paid-slashed":
        state.paid[member] = "slashed";
        state.paidSlashes += 1;
        break;
      default:
        fail("event-kind");
    }
    if (!safeCount(state.stakedSlashes) || !safeCount(state.paidSlashes)) fail("event-count");
    state.seen[key] = true;
  }
  return state;
}

export function activityCounts(state) {
  return {
    activeStakedCommitments: Object.values(state.staked).filter((status) => status === "active").length,
    activePaidCommitments: Object.values(state.paid).filter((status) => status === "live").length,
    stakedSlashes: state.stakedSlashes,
    paidSlashes: state.paidSlashes,
  };
}

export function applyIndexedBlocks(previous, blocks, { chainId } = {}) {
  let state = previous ? structuredClone(previous) : { blocks: [], activity: null };
  const incoming = [...blocks].sort((a, b) => a.number - b.number);
  for (const block of incoming) {
    if (!Number.isSafeInteger(block.number) || block.number < 0 || !lowerHash(block.hash)
      || (block.number > 0 && !lowerHash(block.parentHash)) || !Array.isArray(block.events)) fail("block-shape");
    const existingIndex = state.blocks.findIndex((known) => known.number === block.number);
    if (existingIndex !== -1 && state.blocks[existingIndex].hash.toLowerCase() !== block.hash.toLowerCase()) {
      state.blocks = state.blocks.slice(0, existingIndex);
      state.activity = null;
      for (const known of state.blocks) {
        state.activity = reduceActivityEvents(known.events, { chainId, previous: state.activity });
      }
    }
    const parent = state.blocks.at(-1);
    if (parent && block.number === parent.number + 1 && block.parentHash.toLowerCase() !== parent.hash.toLowerCase()) fail("block-parent");
    if (!state.blocks.some((known) => known.number === block.number)) {
      state.activity = reduceActivityEvents(block.events, { chainId, previous: state.activity });
      state.blocks.push({ number: block.number, hash: block.hash, parentHash: block.parentHash, events: block.events });
    }
  }
  return state;
}

async function agreed(rpcs, operation, code) {
  let values;
  try { values = await Promise.all(rpcs.map(operation)); } catch { fail(code); }
  if (values.length === 0) fail(code);
  const canonical = JSON.stringify(values[0]);
  if (values.some((value) => JSON.stringify(value) !== canonical)) fail("rpc-disagreement");
  return values[0];
}

async function verifyCode(rpcs, role, blockNumber) {
  const code = await agreed(rpcs, (rpc) => rpc.getCode(role.address, blockNumber), "rpc-code");
  if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code) || code === "0x") fail("runtime-code-missing");
  if (keccak256(code).toLowerCase() !== role.runtimeCodeHash.toLowerCase()) fail("runtime-code-mismatch");
}

async function readCounter(rpcs, role, method, blockNumber) {
  const data = SET_ABI.encodeFunctionData(method);
  const result = await agreed(rpcs, (rpc) => rpc.call({ to: role.address, data }, blockNumber), "rpc-counter");
  try {
    const value = SET_ABI.decodeFunctionResult(method, result)[0];
    const count = Number(value);
    if (!safeCount(count)) fail("counter-range");
    return count;
  } catch (error) {
    if (error instanceof GroveOnchainError) throw error;
    fail("counter-decode");
  }
}

async function verifySettlementFact(fact, target, rpcs, finalizedBlock) {
  const payment = target.activity.payment;
  if (fact.asset.toLowerCase() !== payment.asset.address.toLowerCase()
    || fact.payee.toLowerCase() !== payment.payee.toLowerCase()) fail("settlement-target");
  const [tx, settlementReceipt, insertReceipt] = await Promise.all([
    agreed(rpcs, (rpc) => rpc.getTransaction(fact.settlementTx), "rpc-settlement-transaction"),
    agreed(rpcs, (rpc) => rpc.getTransactionReceipt(fact.settlementTx), "rpc-settlement-receipt"),
    agreed(rpcs, (rpc) => rpc.getTransactionReceipt(fact.insertTx), "rpc-insert-receipt"),
  ]);
  if (!tx || !settlementReceipt || !insertReceipt || settlementReceipt.status !== 1 || insertReceipt.status !== 1
    || settlementReceipt.blockNumber > finalizedBlock || insertReceipt.blockNumber > finalizedBlock
    || tx.to?.toLowerCase() !== payment.asset.address.toLowerCase()) fail("settlement-not-finalized");
  let decoded;
  try { decoded = TOKEN_ABI.parseTransaction({ data: tx.data, value: tx.value || 0 }); } catch { fail("settlement-calldata"); }
  if (!decoded || decoded.name !== "transferWithAuthorization"
    || decoded.args.to.toLowerCase() !== payment.payee.toLowerCase()
    || decoded.args.value.toString() !== fact.atomicValue) fail("settlement-calldata");
  let inserted = false;
  for (const log of insertReceipt.logs || []) {
    if (log.address?.toLowerCase() !== target.activity.contracts.paidAccessSet.address.toLowerCase()) continue;
    try {
      const parsed = PAID_ABI.parseLog(log);
      if (parsed?.name === "Inserted" && parsed.args.commitment.toString() === fact.commitment) inserted = true;
    } catch { /* another event */ }
  }
  if (!inserted) fail("settlement-insert-missing");
  return BigInt(fact.atomicValue);
}

// RPC adapter contract: getChainId(), getDelayedFinalizedBlock({before, confirmations}),
// getCode(address, block), call(tx, block), getTransaction(hash), getTransactionReceipt(hash).
// Every method is queried against every approved RPC and must agree exactly.
export async function collectOnchainActivity({
  target,
  rpcs,
  events,
  registrarAggregate = null,
  now = new Date(),
} = {}) {
  validateLiveOnchainTarget(target);
  if (!Array.isArray(rpcs) || rpcs.length !== target.finality.approvedRpcUrls.length || rpcs.length < 1) fail("rpc-set");
  const chainId = await agreed(rpcs, (rpc) => rpc.getChainId(), "rpc-chain-id");
  if (chainId !== target.chainId) fail("rpc-wrong-chain");
  const cutoff = new Date(new Date(now).getTime() - ISO_DELAY_MS).toISOString();
  const block = await agreed(
    rpcs,
    (rpc) => rpc.getDelayedFinalizedBlock({ before: cutoff, confirmations: target.finality.confirmations }),
    "rpc-finality",
  );
  if (!object(block) || !Number.isSafeInteger(block.number) || !lowerHash(block.hash)
    || !canonicalIso(block.time) || Date.parse(block.time) > Date.parse(cutoff)) fail("finalized-block");
  if (block.number < target.activity.migration.startsAtBlock
    || (target.activity.migration.retiresBeforeBlock !== null && block.number >= target.activity.migration.retiresBeforeBlock)) {
    fail("finalized-block-boundary");
  }
  const { stakedReputationSet: stakedRole, paidAccessSet: paidRole } = target.activity.contracts;
  if (block.number < stakedRole.deployBlock || block.number < paidRole.deployBlock) fail("finalized-block-before-deploy");
  await verifyCode(rpcs, stakedRole, block.number);
  await verifyCode(rpcs, paidRole, block.number);
  const [activeStakedCommitments, activePaidCommitments] = await Promise.all([
    readCounter(rpcs, stakedRole, "activeCount", block.number),
    readCounter(rpcs, paidRole, "liveCount", block.number),
  ]);
  const state = reduceActivityEvents(events || [], { chainId });
  const replayed = activityCounts(state);
  if (replayed.activeStakedCommitments !== activeStakedCommitments
    || replayed.activePaidCommitments !== activePaidCommitments) fail("counter-event-disagreement");

  let settlements = null;
  if (registrarAggregate !== null) {
    validateRegistrarAggregate(registrarAggregate, target);
    let atomicValue = 0n;
    const dedupe = new Set();
    let completedAccesses = 0;
    for (const fact of registrarAggregate.settlements) {
      const key = `${fact.settlementTx.toLowerCase()}:${fact.insertTx.toLowerCase()}`;
      if (dedupe.has(key)) continue;
      dedupe.add(key);
      atomicValue += await verifySettlementFact(fact, target, rpcs, block.number);
      completedAccesses += 1;
    }
    settlements = { completedAccesses, atomicValue: atomicValue.toString() };
  }
  return {
    generatedAt: new Date(now).toISOString(),
    source: {
      chainId,
      finalizedBlock: String(block.number),
      finalizedBlockHash: block.hash.toLowerCase(),
      finalizedBlockTime: block.time,
      finalityConfirmations: target.finality.confirmations,
    },
    membership: { activeStakedCommitments, activePaidCommitments },
    settlements,
    enforcement: { stakedSlashes: replayed.stakedSlashes, paidSlashes: replayed.paidSlashes },
    asset: {
      chainId,
      address: getAddress(target.activity.payment.asset.address),
      decimals: target.activity.payment.asset.decimals,
      symbol: target.activity.payment.asset.symbol,
    },
  };
}

function publicCount(count, key, minimumCohort) {
  return count >= minimumCohort
    ? { status: "available", [key]: count }
    : { status: "suppressed", suppressionReason: "minimum-cohort" };
}

export function buildPublicOnchainActivity(observation, {
  minimumCohort = GROVE_ONCHAIN_MINIMUM_COHORT,
  delayHours = GROVE_ONCHAIN_DELAY_HOURS,
} = {}) {
  if (!Number.isInteger(minimumCohort) || minimumCohort < 5 || !Number.isInteger(delayHours) || delayHours < 6) {
    fail("privacy-policy");
  }
  const settlement = observation.settlements === null
    ? { status: "unavailable", unavailableReason: "attribution-unavailable" }
    : observation.settlements.completedAccesses < minimumCohort
      ? { status: "suppressed", suppressionReason: "minimum-cohort" }
      : {
          status: "available",
          completedAccesses: observation.settlements.completedAccesses,
          atomicValue: observation.settlements.atomicValue,
          asset: { ...observation.asset },
        };
  return {
    definition: GROVE_ONCHAIN_DEFINITION,
    generatedAt: observation.generatedAt,
    delayHours,
    minimumCohort,
    source: { ...observation.source },
    membership: {
      definition: "active-commitments-at-finalized-block",
      duplicatePolicy: "separate-contract-classes-no-cross-set-dedup",
      staked: publicCount(observation.membership.activeStakedCommitments, "activeCommitments", minimumCohort),
      paid: publicCount(observation.membership.activePaidCommitments, "activeCommitments", minimumCohort),
    },
    settlements: {
      definition: "finalized-settlement-linked-to-finalized-insert",
      attributionRule: "signed-registrar-chain-verified-v1",
      ...settlement,
    },
    enforcement: {
      definition: "finalized-contract-slash-events",
      staked: publicCount(observation.enforcement.stakedSlashes, "finalizedSlashes", minimumCohort),
      paid: publicCount(observation.enforcement.paidSlashes, "finalizedSlashes", minimumCohort),
    },
  };
}

function validPublicMetric(value, key, minimumCohort) {
  if (value?.status === "available") {
    return exactKeys(value, ["status", key]) && safeCount(value[key]) && value[key] >= minimumCohort;
  }
  return exactKeys(value, ["status", "suppressionReason"])
    && value.status === "suppressed" && value.suppressionReason === "minimum-cohort";
}

export function validPublicOnchainActivity(value, { observedAt = null } = {}) {
  const generated = Date.parse(value?.generatedAt);
  const blockTime = Date.parse(value?.source?.finalizedBlockTime);
  const observed = observedAt === null ? generated : Date.parse(observedAt);
  if (!exactKeys(value, ["definition", "generatedAt", "delayHours", "minimumCohort", "source", "membership", "settlements", "enforcement"])
    || value.definition !== GROVE_ONCHAIN_DEFINITION || !canonicalIso(value.generatedAt)
    || !Number.isFinite(generated) || !Number.isFinite(observed) || generated > observed + 5 * 60_000
    || generated < observed - 60 * 60_000 || !Number.isInteger(value.delayHours) || value.delayHours < 6
    || !Number.isInteger(value.minimumCohort) || value.minimumCohort < 5
    || !exactKeys(value.source, ["chainId", "finalizedBlock", "finalizedBlockHash", "finalizedBlockTime", "finalityConfirmations"])
    || value.source.chainId !== 11155111
    || decimalU64(value.source.finalizedBlock) === null || !lowerHash(value.source.finalizedBlockHash)
    || !canonicalIso(value.source.finalizedBlockTime) || !Number.isFinite(blockTime)
    || blockTime > generated - value.delayHours * 60 * 60_000
    || !Number.isInteger(value.source.finalityConfirmations) || value.source.finalityConfirmations < 1
    || !exactKeys(value.membership, ["definition", "duplicatePolicy", "staked", "paid"])
    || value.membership.definition !== "active-commitments-at-finalized-block"
    || value.membership.duplicatePolicy !== "separate-contract-classes-no-cross-set-dedup"
    || !validPublicMetric(value.membership.staked, "activeCommitments", value.minimumCohort)
    || !validPublicMetric(value.membership.paid, "activeCommitments", value.minimumCohort)
    || !exactKeys(value.enforcement, ["definition", "staked", "paid"])
    || value.enforcement.definition !== "finalized-contract-slash-events"
    || !validPublicMetric(value.enforcement.staked, "finalizedSlashes", value.minimumCohort)
    || !validPublicMetric(value.enforcement.paid, "finalizedSlashes", value.minimumCohort)) return false;
  const settlements = value.settlements;
  if (!object(settlements) || settlements.definition !== "finalized-settlement-linked-to-finalized-insert"
    || settlements.attributionRule !== "signed-registrar-chain-verified-v1") return false;
  if (settlements.status === "unavailable") {
    return exactKeys(settlements, ["definition", "attributionRule", "status", "unavailableReason"])
      && settlements.unavailableReason === "attribution-unavailable";
  }
  if (settlements.status === "suppressed") {
    return exactKeys(settlements, ["definition", "attributionRule", "status", "suppressionReason"])
      && settlements.suppressionReason === "minimum-cohort";
  }
  return settlements.status === "available"
    && exactKeys(settlements, ["definition", "attributionRule", "status", "completedAccesses", "atomicValue", "asset"])
    && safeCount(settlements.completedAccesses) && settlements.completedAccesses >= value.minimumCohort
    && decimalUint256(settlements.atomicValue) > 0n
    && exactKeys(settlements.asset, ["chainId", "address", "decimals", "symbol"])
    && settlements.asset.chainId === value.source.chainId && normalizedAddress(settlements.asset.address) !== null
    && Number.isInteger(settlements.asset.decimals) && settlements.asset.decimals >= 0 && settlements.asset.decimals <= 255
    && typeof settlements.asset.symbol === "string" && /^[A-Za-z0-9._-]{1,16}$/.test(settlements.asset.symbol);
}

export function onchainSigningPayload(value) {
  return {
    definition: value.definition,
    generatedAt: value.generatedAt,
    delayHours: value.delayHours,
    minimumCohort: value.minimumCohort,
    source: { ...value.source },
    membership: {
      definition: value.membership.definition,
      duplicatePolicy: value.membership.duplicatePolicy,
      staked: { ...value.membership.staked },
      paid: { ...value.membership.paid },
    },
    settlements: {
      definition: value.settlements.definition,
      attributionRule: value.settlements.attributionRule,
      status: value.settlements.status,
      ...(value.settlements.status === "available" ? {
        completedAccesses: value.settlements.completedAccesses,
        atomicValue: value.settlements.atomicValue,
        asset: { ...value.settlements.asset },
      } : value.settlements.status === "suppressed"
        ? { suppressionReason: value.settlements.suppressionReason }
        : { unavailableReason: value.settlements.unavailableReason }),
    },
    enforcement: {
      definition: value.enforcement.definition,
      staked: { ...value.enforcement.staked },
      paid: { ...value.enforcement.paid },
    },
  };
}
