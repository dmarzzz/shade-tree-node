// Network records: the committed per-deployment truth under network/<name>/ (T-DEPLOY-5, GAP-2 +
// GAP-10 in docs/GO-LIVE.md), and the ONE place that turns them into SHADE_TREE_* defaults.
//
//   network/<name>/deployment.json  current protocol deployment, including the v4 Elder trust pair
//   network/<name>/contracts.json   deployed contract addresses (+ tx / block per contract)
//   network/<name>/bootnode.json    legacy discovery inputs: bootnode onion, pinned signer,
//                                   admission mode, static-directory fallback
//
// Two jobs, both pure over the parsed JSON (the file I/O is a thin sync wrapper at the bottom):
//
//   1. validate*Record(obj)  — shape checks so a hand-edited or half-written record fails LOUDLY
//                              at load, not as an opaque crash later. Same posture as
//                              lib/config.mjs (which validates the env these records feed).
//   2. networkEnvDefaults()  — SHADE_TREE_NETWORK=<name> resolves the records into the env vars the
//                              client / bootnode / heartbeat / register-gateway / uptime probe
//                              already read. applyNetworkEnv() copies them into an env object
//                              WITHOUT overwriting anything already set: an explicit env var (or
//                              `shade-tree --flag`) always beats the file. The record is a default, never
//                              an override, so an operator can pin a different bootnode or signer
//                              for testing without editing a committed file.
//
// "Not yet deployed" is REPRESENTED, not omitted: a contract slot (e.g. `contracts.gatewayRegistry`)
// or a discovery input (`bootnode.onion`) that is not live yet is `null`. Loaders treat null and a
// missing key identically (both mean "no default"), so a record can be committed with the schema
// slot in place BEFORE the broadcast happens (GO-LIVE row 3.2 / 7.1), and `scripts/record-deploy.mjs`
// fills it in one command afterwards. `status: "pending"` on bootnode.json says the same at the
// file level and is what a `live` record must NOT be.
//
// Privacy: records carry onions, pubkeys and contract addresses — the public discovery handles —
// and never IPs, keys, or operator identities beyond an EOA address. validate* rejects a record
// that smuggles an IP into a discovery field.

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { isOnion, isEd25519PubHex, isEthAddress, isUrl } from "./config.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const NETWORK_ROOT = join(HERE, "..", "network");
export const DEFAULT_CLIENT_NETWORK = "sepolia";

// A network name is a plain directory label (`sepolia`, `anvil-local`, `mainnet`): no path
// separators, no dots, so SHADE_TREE_NETWORK can never escape network/.
export function isNetworkName(v) {
  return typeof v === "string" && /^[a-z0-9][a-z0-9-]{0,63}$/.test(v);
}

// A 32-byte tx hash, 0x-prefixed.
export function isTxHash(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v.trim());
}

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const looksLikeIp = (v) => typeof v === "string" && (IPV4.test(v) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(v.trim()));

// Contract slots a record may carry. Any slot may be null (= that contract not deployed on that network
// yet); `stakedReputationSet` is what every live record has so far. `paidAccessSet` is the
// T-FEAT-7 fixed-denomination deposit/sweep set (docs/PAYMENTS.md) that sits next to the staked
// set — its root is UNIONED with the staked set's by the gateway. Unknown extra slots are
// allowed (a future contract just adds a key) but must still be address|null.
export const KNOWN_CONTRACTS = ["stakedReputationSet", "hasher", "withdrawVerifier", "gatewayRegistry", "paidAccessSet"];
export const PAY_PROTOCOLS = ["x402", "mpp"];
export const CONTRACTS_STATUS = ["live", "pending", "retired"];
export const BOOTNODE_STATUS = ["live", "pending", "retired"];
export const ADMISSION_MODES = ["open", "stake"];

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const addrOrNull = (v) => v === null || isEthAddress(v);
// Block numbers are JSON numbers (not strings), so `deployBlock: "123"` is a schema error.
const isBlock = (v) => Number.isInteger(v) && v >= 0;
const isPosInt = (v) => Number.isInteger(v) && v > 0;
const isWeiString = (v) => typeof v === "string" && /^[1-9][0-9]*$/.test(v);

function validateRatePolicy(rate, bad, { required = false } = {}) {
  if (rate == null) {
    if (required) bad("ratePolicy", "is required when staked admission is live");
    return;
  }
  if (!isPlainObject(rate)) { bad("ratePolicy", "must be an object or null"); return; }
  if (rate.scope !== "grove-v4") bad("ratePolicy.scope", "must be grove-v4");
  if (rate.window !== "fixed") bad("ratePolicy.window", "must be fixed");
  if (!isPosInt(rate.epochSeconds)) bad("ratePolicy.epochSeconds", "must be a positive integer");
  if (rate.previousEpochsAccepted !== 1) bad("ratePolicy.previousEpochsAccepted", "must be 1 for protocol v4");
  if (!isPosInt(rate.rootFreshnessSeconds)) bad("ratePolicy.rootFreshnessSeconds", "must be a positive integer");
  if (!Number.isSafeInteger(rate.payloadBytesPerSlot) || rate.payloadBytesPerSlot <= 0) bad("ratePolicy.payloadBytesPerSlot", "must be a positive safe integer");
  if (!isPosInt(rate.slashConfirmationSeconds)) bad("ratePolicy.slashConfirmationSeconds", "must be a positive integer");
}

function validateStakedRoot(root, bad, rate) {
  if (!isPlainObject(root) || !isEthAddress(root.contract)) return;
  if (root.chainId !== undefined && !isPosInt(root.chainId)) bad("admission.roots.staked.chainId", "must be a positive integer");
  if (root.deployTx !== undefined && !isTxHash(root.deployTx)) bad("admission.roots.staked.deployTx", "must be a transaction hash");
  for (const field of ["hasher", "withdrawVerifier"]) {
    if (root[field] !== undefined && !isEthAddress(root[field])) bad(`admission.roots.staked.${field}`, "must be a contract address");
  }
  for (const field of ["defaultLimit", "unbondingSeconds", "minUnbondingSeconds"]) {
    if (root[field] !== undefined && !isPosInt(root[field])) bad(`admission.roots.staked.${field}`, "must be a positive integer");
  }
  if (root.tiers !== undefined) {
    if (!Array.isArray(root.tiers) || root.tiers.length === 0) bad("admission.roots.staked.tiers", "must be a non-empty array");
    else {
      let prior = 0;
      for (let i = 0; i < root.tiers.length; i++) {
        const tier = root.tiers[i];
        if (!isPlainObject(tier) || !isPosInt(tier.limit) || tier.limit > 65535 || !isWeiString(tier.bondWei)) bad(`admission.roots.staked.tiers[${i}]`, "must be { limit: 1..65535, bondWei: positive decimal string }");
        else if (tier.limit <= prior) bad("admission.roots.staked.tiers", "must be strictly ascending by limit");
        else prior = tier.limit;
      }
    }
  }
  if (root.slashRewardDivisor !== undefined && !(isPosInt(root.slashRewardDivisor) && root.slashRewardDivisor >= 2 && root.slashRewardDivisor <= 1000)) {
    bad("admission.roots.staked.slashRewardDivisor", "must be an integer in 2..1000 (the contract's bound)");
  }
  if (root.profile === "public-stake-v1") {
    // Economics (tier bonds, unbonding, slash split) come from network/<net>/economics.json and
    // are read back from the chain at deploy; the record pins their shape, not their values.
    const limits = Array.isArray(root.tiers) ? root.tiers.map((tier) => tier?.limit) : [];
    if (root.chainId !== 11155111) bad("admission.roots.staked.chainId", "public-stake-v1 is Sepolia-only (11155111)");
    if (!isTxHash(root.deployTx)) bad("admission.roots.staked.deployTx", "public-stake-v1 requires its deploy transaction");
    if (!isEthAddress(root.hasher)) bad("admission.roots.staked.hasher", "public-stake-v1 requires the deployed hasher");
    if (!isEthAddress(root.withdrawVerifier)) bad("admission.roots.staked.withdrawVerifier", "public-stake-v1 requires the real exit verifier");
    if (!limits.includes(root.defaultLimit)) bad("admission.roots.staked.defaultLimit", "public-stake-v1 needs a default tier that the set admits");
    if (!limits.includes(8)) bad("admission.roots.staked.tiers", "public-stake-v1 sets always admit tier 8 (the contract's DEFAULT_LIMIT)");
    if (rate?.crossGateway !== "best-effort-fleet-tally") bad("ratePolicy.crossGateway", "public-stake-v1 requires best-effort fleet tallying");
    if (rate?.epochSeconds !== 60 || rate?.rootFreshnessSeconds !== 60 || rate?.payloadBytesPerSlot !== 41_943_040 || rate?.slashConfirmationSeconds !== 3_600) {
      bad("ratePolicy", "public-stake-v1 pins 60-second epochs/freshness, 40 MiB per slot, and a 3600-second slash allowance");
    }
    const derivedMin = rate && isPosInt(rate.rootFreshnessSeconds) && isPosInt(rate.epochSeconds) && isPosInt(rate.slashConfirmationSeconds)
      ? rate.rootFreshnessSeconds + rate.epochSeconds + rate.slashConfirmationSeconds
      : null;
    if (derivedMin !== 3_720 || root.minUnbondingSeconds !== 3_720 || root.unbondingSeconds < 3_720) bad("admission.roots.staked.minUnbondingSeconds", "public-stake-v1 pins root freshness + epoch + slash confirmation to 3720 seconds and requires it to fit inside unbonding");
  }
}

// ---- contracts.json ----------------------------------------------------------------------
// {
//   network, chainId, status, release?, deployer?, rpcUrl?, params?,
//   contracts:    { <name>: 0xaddr | null, ... },   // null = slot exists, not deployed
//   deployTxs?:   { <name>: 0xtxhash | null, ... },
//   deployBlock?: N,                                 // block of the ORIGINAL deploy batch
//   deployBlocks?:{ <name>: N, ... },                // per-contract, for later additions
//   payAsset?:    { address, name?, symbol?, version?, decimals?, kind?, deployTx?, deployBlock?, note? } | null,
//                                                    // T-FEAT-7: the EIP-3009 stablecoin the 402
//                                                    // registrar settles in (-> SHADE_TREE_PAY_ASSET)
//   registrar?:   { port, protocols: ["x402","mpp"], prices?, note? } | null,
//                                                    // T-FEAT-7: where/what the fleet sells
//                                                    // (on the bootnode onion; -> SHADE_TREE_REGISTRAR_PORT)
//   ...free-form documentation keys (circuit, note, liveIntegration) are ignored here
// }
export function validateContractsRecord(rec) {
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  if (!isPlainObject(rec)) return { ok: false, errors: [{ field: "$", problem: "record must be a JSON object" }] };

  if (!isNetworkName(rec.network)) bad("network", "must be a network name (lowercase [a-z0-9-])");
  if (!Number.isInteger(rec.chainId) || rec.chainId < 1) bad("chainId", "must be a positive integer chain id");
  if (rec.status !== undefined && !CONTRACTS_STATUS.includes(rec.status)) bad("status", `must be one of: ${CONTRACTS_STATUS.join(", ")}`);
  if (rec.deployer !== undefined && rec.deployer !== null && !isEthAddress(rec.deployer)) bad("deployer", "must be a 0x address or null");
  if (rec.rpcUrl !== undefined && rec.rpcUrl !== null && !isUrl(rec.rpcUrl)) bad("rpcUrl", "must be an http(s)/ws(s) URL or null");

  if (!isPlainObject(rec.contracts)) bad("contracts", "must be an object of { name: 0xaddr | null }");
  else {
    for (const [name, v] of Object.entries(rec.contracts)) {
      if (!addrOrNull(v)) bad(`contracts.${name}`, "must be a 0x-prefixed 20-byte address, or null (= not deployed)");
    }
  }
  if (rec.deployTxs !== undefined) {
    if (!isPlainObject(rec.deployTxs)) bad("deployTxs", "must be an object of { name: 0xtxhash | null }");
    else for (const [name, v] of Object.entries(rec.deployTxs)) {
      if (!(v === null || isTxHash(v))) bad(`deployTxs.${name}`, "must be a 0x-prefixed 32-byte tx hash, or null");
      // A tx recorded for a slot that is null/missing is contradictory.
      if (v && rec.contracts && !isEthAddress(rec.contracts[name])) bad(`deployTxs.${name}`, `has a tx hash but contracts.${name} is not an address`);
    }
  }
  if (rec.deployBlock !== undefined && rec.deployBlock !== null && !isBlock(rec.deployBlock)) bad("deployBlock", "must be a non-negative integer");
  // T-FEAT-7 payments (both optional; null = not deployed / not sold on this network).
  if (rec.payAsset !== undefined && rec.payAsset !== null) {
    const pa = rec.payAsset;
    if (!isPlainObject(pa)) bad("payAsset", "must be { address, ... } or null");
    else {
      if (!isEthAddress(pa.address)) bad("payAsset.address", "must be a 0x-prefixed 20-byte token address");
      if (pa.decimals !== undefined && !(Number.isInteger(pa.decimals) && pa.decimals >= 0 && pa.decimals <= 255)) bad("payAsset.decimals", "must be an integer 0..255");
      if (pa.deployTx !== undefined && pa.deployTx !== null && !isTxHash(pa.deployTx)) bad("payAsset.deployTx", "must be a 0x-prefixed 32-byte tx hash, or null");
      if (pa.deployBlock !== undefined && pa.deployBlock !== null && !isBlock(pa.deployBlock)) bad("payAsset.deployBlock", "must be a non-negative integer");
      for (const k of ["name", "symbol", "version", "kind", "note"]) if (pa[k] !== undefined && typeof pa[k] !== "string") bad(`payAsset.${k}`, "must be a string");
    }
  }
  if (rec.registrar !== undefined && rec.registrar !== null) {
    const rg = rec.registrar;
    if (!isPlainObject(rg)) bad("registrar", "must be { port, protocols } or null");
    else {
      if (!(Number.isInteger(rg.port) && rg.port >= 1 && rg.port <= 65535)) bad("registrar.port", "must be a TCP port (integer 1..65535)");
      if (!(Array.isArray(rg.protocols) && rg.protocols.length > 0 && rg.protocols.every((x) => PAY_PROTOCOLS.includes(x)))) bad("registrar.protocols", `must be a non-empty array of: ${PAY_PROTOCOLS.join(", ")}`);
      if (rg.prices !== undefined && rg.prices !== null && !(isPlainObject(rg.prices) && Object.entries(rg.prices).every(([l, v]) => /^[1-9][0-9]{0,4}$/.test(l) && typeof v === "string" && /^[1-9][0-9]*$/.test(v)))) bad("registrar.prices", "must be { \"<limit>\": \"<atomic amount>\" }");
      if (rg.note !== undefined && typeof rg.note !== "string") bad("registrar.note", "must be a string");
      if (typeof rg.note === "string" && looksLikeIp(rg.note)) bad("registrar.note", "must not contain an IP address");
    }
  }
  if (rec.deployBlocks !== undefined) {
    if (!isPlainObject(rec.deployBlocks)) bad("deployBlocks", "must be an object of { name: blockNumber }");
    else for (const [name, v] of Object.entries(rec.deployBlocks)) {
      if (!(v === null || isBlock(v))) bad(`deployBlocks.${name}`, "must be a non-negative integer, or null");
      if (v !== null && rec.contracts && !isEthAddress(rec.contracts[name])) bad(`deployBlocks.${name}`, `has a block but contracts.${name} is not an address`);
    }
  }
  return { ok: errors.length === 0, errors };
}

// The address of one contract slot, or null when the slot is missing / null.
export function contractAddress(rec, name) {
  const v = rec && rec.contracts ? rec.contracts[name] : undefined;
  return isEthAddress(v) ? v : null;
}

// The deploy block of one contract slot: `deployBlocks.<name>` when present, else the record's
// `deployBlock` (the ORIGINAL deploy batch — a slot added later without its own entry then gets
// the batch block, which is EARLIER than its real birth: a safe start, just more blocks to scan).
// null when unknown. Used to start `eth_getLogs` scans at the contract's birth instead of block 0
// (lib/root-provider.mjs; public RPCs cap the range per call, so "from 0" is thousands of calls).
export function contractDeployBlock(rec, name) {
  if (!rec || !contractAddress(rec, name)) return null;
  const per = rec.deployBlocks && rec.deployBlocks[name];
  if (isBlock(per)) return per;
  return isBlock(rec.deployBlock) ? rec.deployBlock : null;
}

// Every deployed contract in the record (live slots + superseded generations) -> its deploy
// block: { <address lowercased>: block }. Superseded generations (`superseded.<release>`) carry
// their own `contracts` + `deployBlock` and are included so a gateway still reading an older set
// (docs/ONCHAIN.md "superseded") gets a sane start block too. Addresses without a known block are
// omitted (a caller falls back to 0).
export function contractDeployBlocks(rec) {
  const out = {};
  if (!rec || !isPlainObject(rec.contracts)) return out;
  for (const name of Object.keys(rec.contracts)) {
    const addr = contractAddress(rec, name);
    const blk = contractDeployBlock(rec, name);
    if (addr && blk != null) out[addr.toLowerCase()] = blk;
  }
  if (isPlainObject(rec.superseded)) {
    for (const gen of Object.values(rec.superseded)) {
      if (!isPlainObject(gen) || !isPlainObject(gen.contracts)) continue;
      for (const [name, addr] of Object.entries(gen.contracts)) {
        if (!isEthAddress(addr)) continue;
        const per = gen.deployBlocks && gen.deployBlocks[name];
        const blk = isBlock(per) ? per : (isBlock(gen.deployBlock) ? gen.deployBlock : null);
        if (blk != null && out[addr.toLowerCase()] === undefined) out[addr.toLowerCase()] = blk;
      }
    }
  }
  return out;
}

// Serialize / parse the per-contract start-block map SHADE_TREE_FROM_BLOCKS: `<addr>=<block>,...`
// (block decimal or 0x-hex; addresses compared case-insensitively). Malformed entries THROW
// (a typo'd start block silently scanning from 0 is exactly the failure this exists to prevent).
export function formatFromBlocks(map) {
  return Object.entries(map).map(([a, b]) => `${a}=${b}`).join(",");
}
export function parseFromBlocks(spec) {
  const out = new Map();
  for (const part of String(spec == null ? "" : spec).split(",")) {
    const s = part.trim();
    if (!s) continue;
    const eq = s.indexOf("=");
    const addr = eq < 0 ? "" : s.slice(0, eq).trim();
    const blk = eq < 0 ? "" : s.slice(eq + 1).trim();
    if (!isEthAddress(addr) || !/^(0x[0-9a-fA-F]+|\d+)$/.test(blk)) throw new Error(`SHADE_TREE_FROM_BLOCKS: bad entry "${s.slice(0, 64)}" (expected <0xaddress>=<block>, comma-separated)`);
    out.set(addr.toLowerCase(), Number(BigInt(blk)));
  }
  return out;
}

// ---- bootnode.json -----------------------------------------------------------------------
// {
//   network, status: live|pending|retired,
//   onion:      <bootnode v3 .onion> | null,       // SHADE_TREE_BOOTNODE_ONION
//   signer:     <64-hex ed25519> | [<hex>, ...] | null, // SHADE_TREE_DIR_SIGNER (array = rotation
//                                                       // overlap allowlist, joined with ",")
//   admission:  open|stake,                         // what the bootnode enforces
//   staticDirectory?: { path: "directory.json", signer: <hex> | [<hex>] } | null,
//                                                   // cold-path fallback: SHADE_TREE_DIRECTORY +
//                                                   // its own pinned signer
//   deployedRef?, updated?, note?                   // documentation
// }
// `live` REQUIRES onion + signer (a live record without discovery inputs is a lie); `pending`
// tolerates nulls. Nothing here may look like an IP.
function signerListOk(v) {
  if (isEd25519PubHex(v)) return true;
  return Array.isArray(v) && v.length > 0 && v.every(isEd25519PubHex);
}
function signerToEnv(v) {
  return Array.isArray(v) ? v.map((s) => s.trim()).join(",") : v.trim();
}

export function validateBootnodeRecord(rec) {
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  if (!isPlainObject(rec)) return { ok: false, errors: [{ field: "$", problem: "record must be a JSON object" }] };

  if (!isNetworkName(rec.network)) bad("network", "must be a network name (lowercase [a-z0-9-])");
  if (!BOOTNODE_STATUS.includes(rec.status)) bad("status", `must be one of: ${BOOTNODE_STATUS.join(", ")}`);
  if (!(rec.onion === null || isOnion(rec.onion))) bad("onion", looksLikeIp(rec.onion) ? "must be a v3 .onion, never an IP" : "must be a valid v3 .onion, or null (= not deployed)");
  if (!(rec.signer === null || signerListOk(rec.signer))) bad("signer", "must be a 64-hex ed25519 pubkey (no 0x), a non-empty array of them, or null");
  if (!ADMISSION_MODES.includes(rec.admission)) bad("admission", `must be one of: ${ADMISSION_MODES.join(", ")}`);
  if (rec.gatewayRegistry !== undefined && !addrOrNull(rec.gatewayRegistry)) bad("gatewayRegistry", "must be a 0x address or null (canonical home is contracts.json)");
  if (rec.staticDirectory !== undefined && rec.staticDirectory !== null) {
    const sd = rec.staticDirectory;
    if (!isPlainObject(sd)) bad("staticDirectory", "must be { path, signer } or null");
    else {
      if (typeof sd.path !== "string" || !sd.path || sd.path.includes("..") || isAbsolute(sd.path)) bad("staticDirectory.path", "must be a relative path inside network/<name>/ (no .., not absolute)");
      if (!signerListOk(sd.signer)) bad("staticDirectory.signer", "must be a 64-hex ed25519 pubkey or a non-empty array of them");
    }
  }
  if (rec.status === "live") {
    if (!isOnion(rec.onion)) bad("onion", "required (non-null) when status is live");
    if (!signerListOk(rec.signer)) bad("signer", "required (non-null) when status is live");
  }
  for (const k of ["note", "deployedRef", "updated"]) {
    if (rec[k] !== undefined && rec[k] !== null && typeof rec[k] !== "string") bad(k, "must be a string");
    if (typeof rec[k] === "string" && looksLikeIp(rec[k])) bad(k, "must not contain an IP address");
  }
  return { ok: errors.length === 0, errors };
}

// ---- deployment.json ---------------------------------------------------------------------
// The v4 deployment record is the current source of truth. The full deployment preflight lives in
// deploy/v4/preflight.mjs; this focused validator owns only the fields safe client discovery needs.
// A live record must describe a protocol-v4 Elder and its pinned Canopy signer as one atomic pair.
export function validateDeploymentRecord(rec) {
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  if (!isPlainObject(rec)) return { ok: false, errors: [{ field: "$", problem: "record must be a JSON object" }] };

  if (rec.schemaVersion !== 1) bad("schemaVersion", "must be 1");
  if (!isNetworkName(rec.network)) bad("network", "must be a network name (lowercase [a-z0-9-])");
  if (!BOOTNODE_STATUS.includes(rec.status)) bad("status", `must be one of: ${BOOTNODE_STATUS.join(", ")}`);
  if (!isPlainObject(rec.protocol)) bad("protocol", "must be { min, max }");
  else {
    if (!Number.isInteger(rec.protocol.min) || rec.protocol.min < 1) bad("protocol.min", "must be a positive integer");
    if (!Number.isInteger(rec.protocol.max) || rec.protocol.max < rec.protocol.min) bad("protocol.max", "must be an integer >= protocol.min");
  }
  if (!isPlainObject(rec.elder)) bad("elder", "must be an object");
  else {
    if (!(rec.elder.onion === null || isOnion(rec.elder.onion))) bad("elder.onion", looksLikeIp(rec.elder.onion) ? "must be a v3 .onion, never an IP" : "must be a valid v3 .onion, or null");
    if (!(rec.elder.canopySigner === null || signerListOk(rec.elder.canopySigner))) bad("elder.canopySigner", "must be a 64-hex ed25519 public key, a non-empty array of them, or null");
    if (rec.elder.admission !== undefined && !ADMISSION_MODES.includes(rec.elder.admission)) bad("elder.admission", `must be one of: ${ADMISSION_MODES.join(", ")}`);
    if (rec.elder.gatewayRegistry !== undefined && !addrOrNull(rec.elder.gatewayRegistry)) bad("elder.gatewayRegistry", "must be a 0x address or null");
  }
  const hasStaked = Array.isArray(rec.admission?.paths) && rec.admission.paths.includes("staked");
  validateRatePolicy(rec.ratePolicy, bad, { required: rec.status === "live" && hasStaked });
  if (rec.admission?.defaultPath !== undefined) {
    if (!Array.isArray(rec.admission?.paths) || !rec.admission.paths.includes(rec.admission.defaultPath)) bad("admission.defaultPath", "must name one of admission.paths");
  }
  if (rec.admission?.roots?.staked) {
    validateStakedRoot(rec.admission.roots.staked, bad, rec.ratePolicy);
    if (rec.admission.roots.staked.profile === "public-stake-v1" && rec.admission.defaultPath !== "staked") {
      bad("admission.defaultPath", "public-stake-v1 must be the default admission path");
    }
    if (rec.admission.roots.staked.profile === "public-stake-v1" && !isPosInt(rec.admission.roots.staked.deployBlock)) {
      bad("admission.roots.staked.deployBlock", "public-stake-v1 requires a positive deployment block");
    }
  }
  if (rec.status === "live") {
    if (!isPlainObject(rec.protocol) || rec.protocol.min > 4 || rec.protocol.max < 4) bad("protocol", "a live client default must support protocol v4");
    if (!isPlainObject(rec.elder) || !isOnion(rec.elder.onion)) bad("elder.onion", "required when status is live");
    if (!isPlainObject(rec.elder) || !signerListOk(rec.elder.canopySigner)) bad("elder.canopySigner", "required when status is live");
  }
  return { ok: errors.length === 0, errors };
}

// ---- loading -----------------------------------------------------------------------------
export function networkDir(name, root = NETWORK_ROOT) {
  if (!isNetworkName(name)) throw new Error(`SHADE_TREE_NETWORK: bad network name "${name}" (expected [a-z0-9-])`);
  return join(root, name);
}

function readJsonIfExists(path) {
  if (!existsSync(path)) return null;
  const raw = readFileSync(path, "utf8");
  try { return JSON.parse(raw); } catch (e) { throw new Error(`${path}: invalid JSON (${e.message})`); }
}

function throwIfInvalid(path, res) {
  if (res.ok) return;
  const lines = res.errors.map((e) => `  ${e.field}: ${e.problem}`).join("\n");
  throw new Error(`${path}: invalid record\n${lines}`);
}

// { name, dir, deployment: rec|null, contracts: rec|null, bootnode: rec|null }. A missing file is null (no defaults
// from it); a present-but-invalid file THROWS (never silently ignore a broken record).
export function loadNetworkRecords(name, { root = NETWORK_ROOT } = {}) {
  const dir = networkDir(name, root);
  if (!existsSync(dir)) throw new Error(`SHADE_TREE_NETWORK=${name}: no such network record directory ${dir}`);
  const deploymentPath = join(dir, "deployment.json");
  const contractsPath = join(dir, "contracts.json");
  const bootnodePath = join(dir, "bootnode.json");
  const deployment = readJsonIfExists(deploymentPath);
  if (deployment) throwIfInvalid(deploymentPath, validateDeploymentRecord(deployment));
  const contracts = readJsonIfExists(contractsPath);
  if (contracts) throwIfInvalid(contractsPath, validateContractsRecord(contracts));
  const bootnode = readJsonIfExists(bootnodePath);
  if (bootnode) throwIfInvalid(bootnodePath, validateBootnodeRecord(bootnode));
  return { name, dir, deployment, contracts, bootnode };
}

// Pure: records -> { SHADE_TREE_*: value } defaults. Only keys with a resolvable value appear.
//   deployment.json -> SHADE_TREE_BOOTNODE_ONION, SHADE_TREE_DIR_SIGNER, SHADE_TREE_BOOTNODE_ADMISSION
//                      from a live protocol-v4 Elder (takes precedence over legacy bootnode.json)
//   bootnode.json  -> the same fields for legacy records, plus static-directory fallback
//                     (fallback when the bootnode is not live: SHADE_TREE_DIRECTORY + SHADE_TREE_DIR_SIGNER
//                      from staticDirectory, so a pending fleet still has a cold path)
//   contracts.json -> SHADE_TREE_GATEWAY_REGISTRY, SHADE_TREE_GROUP_CONTRACT (= stakedReputationSet), SHADE_TREE_RPC_URL,
//                     SHADE_TREE_PAID_ACCESS_CONTRACT (= paidAccessSet), SHADE_TREE_PAY_ASSET (= payAsset.address),
//                     SHADE_TREE_REGISTRAR_PORT (= registrar.port)     [T-FEAT-7]
export function envDefaultsFromRecords({ dir, deployment, contracts, bootnode }) {
  const out = {};
  if (deployment?.status === "live" && deployment.protocol?.min <= 4 && deployment.protocol?.max >= 4) {
    out.SHADE_TREE_BOOTNODE_ONION = deployment.elder.onion.trim();
    out.SHADE_TREE_DIR_SIGNER = signerToEnv(deployment.elder.canopySigner);
    if (deployment.elder.admission) out.SHADE_TREE_BOOTNODE_ADMISSION = deployment.elder.admission;
    if (deployment.elder.gatewayRegistry) out.SHADE_TREE_GATEWAY_REGISTRY = deployment.elder.gatewayRegistry;
    const rate = deployment.ratePolicy;
    if (rate) {
      out.SHADE_TREE_EPOCH_SECONDS = String(rate.epochSeconds);
      out.SHADE_TREE_ROOT_FRESHNESS_SECONDS = String(rate.rootFreshnessSeconds);
      out.SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES = String(rate.payloadBytesPerSlot);
    }
    const staked = deployment.admission?.roots?.staked;
    if (staked && isEthAddress(staked.contract)) {
      out.SHADE_TREE_GROUP_CONTRACT = staked.contract;
      if (isUrl(staked.rpcUrl)) out.SHADE_TREE_RPC_URL = staked.rpcUrl;
      if (isPosInt(staked.chainId)) out.SHADE_TREE_CHAIN_ID = String(staked.chainId);
      if (staked.profile === "public-stake-v1") out.SHADE_TREE_STAKE_PROFILE = staked.profile;
      if (isBlock(staked.deployBlock)) {
        out.SHADE_TREE_FROM_BLOCK = "0x" + staked.deployBlock.toString(16);
        out.SHADE_TREE_FROM_BLOCKS = formatFromBlocks({ [staked.contract]: staked.deployBlock });
      }
      if (Array.isArray(staked.tiers)) out.SHADE_TREE_TIERS = staked.tiers.map((tier) => tier.limit).join(",");
      if (deployment.admission?.defaultPath === "staked") {
        out.SHADE_TREE_LEAF_SOURCE = "staked";
        if (isPosInt(staked.defaultLimit)) out.SHADE_TREE_LIMIT = String(staked.defaultLimit);
      }
    }
  }
  if (bootnode && !out.SHADE_TREE_BOOTNODE_ONION) {
    const liveish = bootnode.status !== "retired";
    if (liveish && isOnion(bootnode.onion)) out.SHADE_TREE_BOOTNODE_ONION = bootnode.onion.trim();
    if (liveish && signerListOk(bootnode.signer)) out.SHADE_TREE_DIR_SIGNER = signerToEnv(bootnode.signer);
    if (liveish && bootnode.admission) out.SHADE_TREE_BOOTNODE_ADMISSION = bootnode.admission;
    // Cold path: no live bootnode onion -> point the client at the committed static directory,
    // pinned to THAT directory's signer. (If a bootnode is live it wins in client/selection.mjs
    // anyway, so we only wire the static path when there is no onion.)
    if (liveish && !out.SHADE_TREE_BOOTNODE_ONION && bootnode.staticDirectory && bootnode.staticDirectory.path) {
      const p = resolve(dir, bootnode.staticDirectory.path);
      if (existsSync(p)) {
        out.SHADE_TREE_DIRECTORY = p;
        if (!out.SHADE_TREE_DIR_SIGNER && signerListOk(bootnode.staticDirectory.signer)) out.SHADE_TREE_DIR_SIGNER = signerToEnv(bootnode.staticDirectory.signer);
      }
    }
  }
  // A retired contract record remains valuable provenance (addresses, receipts, deploy blocks),
  // but it must never silently configure current software. Operators can still pin one of its
  // addresses explicitly for historical inspection; SHADE_TREE_NETWORK only supplies active or
  // pending-generation defaults.
  if (contracts && contracts.status !== "retired") {
    const reg = contractAddress(contracts, "gatewayRegistry");
    if (reg) out.SHADE_TREE_GATEWAY_REGISTRY = reg;
    const set = contractAddress(contracts, "stakedReputationSet");
    if (set) out.SHADE_TREE_GROUP_CONTRACT = set;
    const paid = contractAddress(contracts, "paidAccessSet");
    if (paid) out.SHADE_TREE_PAID_ACCESS_CONTRACT = paid;
    if (isUrl(contracts.rpcUrl)) out.SHADE_TREE_RPC_URL = contracts.rpcUrl;
    if (contracts.payAsset && isEthAddress(contracts.payAsset.address)) out.SHADE_TREE_PAY_ASSET = contracts.payAsset.address;
    if (contracts.registrar && Number.isInteger(contracts.registrar.port)) out.SHADE_TREE_REGISTRAR_PORT = String(contracts.registrar.port);
    // eth_getLogs start blocks (lib/root-provider.mjs): the MIN deploy block of the contracts this
    // record configures (SHADE_TREE_FROM_BLOCK) plus the exact per-contract map (SHADE_TREE_FROM_BLOCKS), so
    // each set is scanned from its own birth block. Only the slots resolved above count.
    const fromBlocks = {};
    for (const name of ["stakedReputationSet", "paidAccessSet", "gatewayRegistry"]) {
      const addr = contractAddress(contracts, name);
      const blk = contractDeployBlock(contracts, name);
      if (addr && blk != null) fromBlocks[addr] = blk;
    }
    const blocks = Object.values(fromBlocks);
    if (blocks.length) {
      out.SHADE_TREE_FROM_BLOCK = "0x" + Math.min(...blocks).toString(16);
      out.SHADE_TREE_FROM_BLOCKS = formatFromBlocks(fromBlocks);
    }
  }
  return out;
}

export function networkEnvDefaults(name, opts = {}) {
  const { allowRetired = false, ...loadOpts } = opts;
  const records = loadNetworkRecords(name, loadOpts);
  const present = [records.deployment, records.contracts, records.bootnode].filter(Boolean);
  if (!allowRetired && present.length > 0 && present.every((record) => record.status === "retired")) {
    throw new Error(`SHADE_TREE_NETWORK=${name}: retired deployment record; select a current v4 network, or unset SHADE_TREE_NETWORK and configure explicit endpoints`);
  }
  return envDefaultsFromRecords(records);
}

// Client-only convenience: explicit discovery always wins; an explicit group contract without an
// explicit network is a custom deployment and must not inherit the bundled Grove's Sepolia chain,
// staking profile, RPC, or scan start. An explicit SHADE_TREE_NETWORK selects that record;
// otherwise use the bundled current v4 research Grove. Keeping this separate from applyNetworkEnv
// means nodes/Elders never silently inherit a public client endpoint.
export function applyClientNetworkEnv(env = process.env, { root, defaultNetwork = DEFAULT_CLIENT_NETWORK } = {}) {
  const set = (key) => env[key] !== undefined && env[key] !== null && String(env[key]).trim() !== "";
  if (set("SHADE_TREE_ONION") || set("SHADE_TREE_BOOTNODE_ONION") || set("SHADE_TREE_DIRECTORY")) return [];
  if (set("SHADE_TREE_NETWORK")) return applyNetworkEnv(env, { ...(root ? { root } : {}) });
  if (set("SHADE_TREE_GROUP_CONTRACT")) return [];
  return applyNetworkEnv(env, { name: defaultNetwork, ...(root ? { root } : {}) });
}

// Copy the network defaults into `env` for every key NOT already set (empty string counts as
// unset). Returns the list of keys it filled. No-op (returns []) when SHADE_TREE_NETWORK is unset.
// Throws on a bad/invalid record — the caller decides whether that is fatal (shade-tree: yes).
export function applyNetworkEnv(env = process.env, { name = env.SHADE_TREE_NETWORK, root, allowRetired = false } = {}) {
  if (!name) return [];
  const defaults = networkEnvDefaults(name, { ...(root ? { root } : {}), allowRetired });
  const applied = [];
  const unset = (k) => env[k] === undefined || env[k] === null || String(env[k]).trim() === "";
  // SHADE_TREE_FROM_BLOCK / SHADE_TREE_FROM_BLOCKS are ONE setting with two spellings: an operator who pins
  // either explicitly has decided where scans start, so neither is filled from the record then
  // (otherwise a derived per-contract map would silently out-rank an explicit SHADE_TREE_FROM_BLOCK).
  const fromPinned = !unset("SHADE_TREE_FROM_BLOCK") || !unset("SHADE_TREE_FROM_BLOCKS");
  for (const [k, v] of Object.entries(defaults)) {
    if (fromPinned && (k === "SHADE_TREE_FROM_BLOCK" || k === "SHADE_TREE_FROM_BLOCKS")) continue;
    if (unset(k)) { env[k] = v; applied.push(k); }
  }
  return applied;
}

// deployBlockForContract(address, { name, env, root }) -> block number | null. Best-effort, never
// throws: the deploy block of `address` from network/<name>/contracts.json (name = SHADE_TREE_NETWORK by
// default), else from ANY committed network record that lists the address (a fleet unit that pins
// SHADE_TREE_GROUP_CONTRACT / SHADE_TREE_PAID_ACCESS_CONTRACT explicitly, without SHADE_TREE_NETWORK, still gets a
// sane start block — tonight's crash-loop, docs/GO-LIVE-LOG-2026-08-17.md). Addresses are unique
// enough across our records for the scan to be safe; a record that fails validation is skipped.
export function deployBlockForContract(address, { name, env = process.env, root = NETWORK_ROOT } = {}) {
  if (!isEthAddress(address)) return null;
  const key = address.toLowerCase();
  const names = [];
  const preferred = name || (env && env.SHADE_TREE_NETWORK);
  if (preferred && isNetworkName(preferred)) names.push(preferred);
  try {
    if (existsSync(root)) for (const d of readdirSync(root, { withFileTypes: true })) if (d.isDirectory() && isNetworkName(d.name) && !names.includes(d.name)) names.push(d.name);
  } catch { /* unreadable network/ -> no default */ }
  for (const n of names) {
    try {
      const rec = readJsonIfExists(join(networkDir(n, root), "contracts.json"));
      if (!rec || !validateContractsRecord(rec).ok) continue;
      const blk = contractDeployBlocks(rec)[key];
      if (blk != null) return blk;
    } catch { /* skip a broken record */ }
  }
  return null;
}

// Best-effort variant for library defaults (lib/gateway-registry.mjs, group/register-gateway.mjs):
// the value of ONE default from SHADE_TREE_NETWORK, or null if unset / unresolvable. Never throws, so a
// missing/invalid record cannot break a code path that only wanted a default.
export function networkDefault(key, env = process.env) {
  try {
    if (!env.SHADE_TREE_NETWORK) return null;
    return networkEnvDefaults(env.SHADE_TREE_NETWORK)[key] ?? null;
  } catch {
    return null;
  }
}
