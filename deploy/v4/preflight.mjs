#!/usr/bin/env node
// Fail-closed validation for the public, secret-free Protocol v4 deployment record.
// This runs on the controller before Ansible is allowed to touch a target. It deliberately
// validates only public deployment identity: onions, signer pins, roots, artifact hashes,
// protocol range, and immutable source commits. Secret/operator checks remain in the role.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { AbiCoder, Interface } from "ethers";
import { isOnion, isEd25519PubHex, isEthAddress } from "../../packages/node/lib/config.mjs";
import { isNetworkName } from "../../packages/node/lib/network-record.mjs";
import { jsonRpcCall } from "../../packages/node/lib/rpc-safety.mjs";
import { artifactIdOf, isArtifactId } from "../../packages/node/lib/zk-artifacts.mjs";

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const SHA256_RE = /^[0-9a-f]{64}$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const SERVICE_NAMES = ["elder", "node", "heartbeat"];
const ADMISSION_PATHS = ["invited", "staked", "paid"];
const TX_RE = /^0x[0-9a-fA-F]{64}$/;
const isPosInt = (value) => Number.isInteger(value) && value > 0;
const PUBLIC_STAKE_BYTECODE_MANIFEST = "deploy/v4/public-stake-v1-bytecode.json";

function validateRatePolicy(rate, bad, { required }) {
  if (rate == null) {
    if (required) bad("ratePolicy", "is required for live staked admission");
    return;
  }
  if (!isObject(rate)) { bad("ratePolicy", "must be an object or null"); return; }
  if (rate.scope !== "grove-v4") bad("ratePolicy.scope", "must be grove-v4");
  if (rate.window !== "fixed") bad("ratePolicy.window", "must be fixed");
  if (!isPosInt(rate.epochSeconds)) bad("ratePolicy.epochSeconds", "must be a positive integer");
  if (rate.previousEpochsAccepted !== 1) bad("ratePolicy.previousEpochsAccepted", "must be 1 for v4");
  if (!isPosInt(rate.rootFreshnessSeconds)) bad("ratePolicy.rootFreshnessSeconds", "must be a positive integer");
  if (!Number.isSafeInteger(rate.payloadBytesPerSlot) || rate.payloadBytesPerSlot <= 0) bad("ratePolicy.payloadBytesPerSlot", "must be a positive safe integer");
  if (!isPosInt(rate.slashConfirmationSeconds)) bad("ratePolicy.slashConfirmationSeconds", "must be a positive integer");
}

function validateStakedProfile(root, rate, bad) {
  if (!isObject(root) || root.profile !== "public-stake-v1") return;
  // Economics come from network/<net>/economics.json and are read back from the chain at deploy
  // (scripts/deploy-contracts.mjs); here the record's shape is checked, not its prices.
  const limits = Array.isArray(root.tiers) ? root.tiers.map((tier) => tier?.limit) : [];
  const tiersOk = limits.length > 0 && limits.includes(8)
    && root.tiers.every((tier, i) => Number.isInteger(tier?.limit) && tier.limit >= 1 && tier.limit <= 65535
      && /^[1-9][0-9]*$/.test(tier.bondWei || "") && (i === 0 || tier.limit > root.tiers[i - 1].limit));
  if (root.chainId !== 11155111) bad("admission.roots.staked.chainId", "public-stake-v1 is Sepolia-only");
  if (!TX_RE.test(root.deployTx || "")) bad("admission.roots.staked.deployTx", "must pin the deployment transaction");
  if (!isEthAddress(root.hasher)) bad("admission.roots.staked.hasher", "must pin the deployed hasher");
  if (!isEthAddress(root.withdrawVerifier)) bad("admission.roots.staked.withdrawVerifier", "must pin the real exit verifier");
  if (!limits.includes(root.defaultLimit)) bad("admission.roots.staked.defaultLimit", "must be one of the admitted tiers");
  if (!tiersOk) bad("admission.roots.staked.tiers", "must be ascending { limit, bondWei } entries that include tier 8");
  if (root.slashRewardDivisor !== undefined && !(Number.isInteger(root.slashRewardDivisor) && root.slashRewardDivisor >= 2 && root.slashRewardDivisor <= 1000)) {
    bad("admission.roots.staked.slashRewardDivisor", "must be an integer in 2..1000");
  }
  if (rate?.crossGateway !== "best-effort-fleet-tally") bad("ratePolicy.crossGateway", "public-stake-v1 requires best-effort fleet tallying");
  const derived = isPosInt(rate?.rootFreshnessSeconds) && isPosInt(rate?.epochSeconds) && isPosInt(rate?.slashConfirmationSeconds)
    ? rate.rootFreshnessSeconds + rate.epochSeconds + rate.slashConfirmationSeconds
    : null;
  if (derived !== 3_720 || root.minUnbondingSeconds !== 3_720 || root.unbondingSeconds < 3_720) bad("admission.roots.staked.minUnbondingSeconds", "public-stake-v1 pins root freshness + epoch + slash confirmation to 3720 seconds and requires it to fit inside unbonding");
  if (rate?.epochSeconds !== 60 || rate?.rootFreshnessSeconds !== 60 || rate?.payloadBytesPerSlot !== 41_943_040 || rate?.slashConfirmationSeconds !== 3_600) bad("ratePolicy", "public-stake-v1 pins 60-second epochs/freshness, 40 MiB per slot, and a 3600-second slash allowance");
}

function safeRelativePath(value) {
  if (typeof value !== "string" || !value || isAbsolute(value) || value.includes("\\")) return false;
  const parts = value.split("/");
  return parts.every((part) => part && part !== "." && part !== "..");
}

function safeRepository(value) {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.hash;
  } catch {
    return false;
  }
}

export function validateDeploymentRecord(record, { requireLive = true, repoRoot = null, requireStakeProfile = null } = {}) {
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  if (!isObject(record)) return { ok: false, errors: [{ field: "$", problem: "record must be a JSON object" }] };

  if (record.schemaVersion !== 1 && record.schemaVersion !== 2) bad("schemaVersion", "must be 1 or 2");
  if (record.schemaVersion === 2) {
    if (!Array.isArray(record.elders) || record.elders.length === 0) bad("elders", "must be a non-empty array in schemaVersion 2");
    else record.elders.forEach((elder, i) => {
      if (!isObject(elder) || !isOnion(elder.onion)) bad(`elders[${i}].onion`, "must be a v3 .onion");
      if (!isObject(elder) || !isEd25519PubHex(elder.canopySigner)) bad(`elders[${i}].canopySigner`, "must be a 64-hex Ed25519 public key");
    });
    if (Array.isArray(record.elders) && isObject(record.elder) && record.elders[0]?.onion !== record.elder.onion) bad("elder", "must equal elders[0]");
  }
  if (!isNetworkName(record.network)) bad("network", "must be a lowercase network name");
  if (!["pending", "live"].includes(record.status)) bad("status", "must be pending or live");
  if (requireLive && record.status !== "live") bad("status", "must be live before any target is changed");
  if (requireStakeProfile && record?.admission?.roots?.staked?.profile !== requireStakeProfile) {
    bad("admission.roots.staked.profile", `this rollout requires ${requireStakeProfile}`);
  }

  if (!isObject(record.protocol)) bad("protocol", "must be { min, max }");
  else {
    const { min, max } = record.protocol;
    if (!Number.isInteger(min) || !Number.isInteger(max) || min !== 4 || max < min || max > 255) {
      bad("protocol", "must be an integer v4 range with min=4 and 4 <= max <= 255");
    }
  }

  const hasStaked = Array.isArray(record.admission?.paths) && record.admission.paths.includes("staked");
  validateRatePolicy(record.ratePolicy, bad, { required: requireLive && hasStaked });

  if (!isObject(record.elder)) bad("elder", "must be an object");
  else {
    if (record.elder.onion !== null && !isOnion(record.elder.onion)) bad("elder.onion", "must be a v3 .onion or null while pending");
    if (record.elder.canopySigner !== null && !isEd25519PubHex(record.elder.canopySigner)) bad("elder.canopySigner", "must be a 64-hex Ed25519 public key or null while pending");
    if (!["open", "stake"].includes(record.elder.admission)) bad("elder.admission", "must be open or stake");
    if (record.elder.gatewayRegistry !== null && !isEthAddress(record.elder.gatewayRegistry)) bad("elder.gatewayRegistry", "must be a contract address or null");
    if (requireLive && !isOnion(record.elder.onion)) bad("elder.onion", "is required for a live record");
    if (requireLive && !isEd25519PubHex(record.elder.canopySigner)) bad("elder.canopySigner", "is required for a live record");
    if (record.elder.admission === "stake" && !isEthAddress(record.elder.gatewayRegistry)) bad("elder.gatewayRegistry", "is required when Elder admission is stake");
  }

  if (!isObject(record.security)) bad("security", "must record proof-artifact trust, rollout scope, and decision reference");
  else {
    const trust = record.security.proofArtifacts;
    const scope = record.security.scope;
    if (trust !== null && !["trusted-ceremony", "untrusted-testnet"].includes(trust)) bad("security.proofArtifacts", "must be trusted-ceremony, untrusted-testnet, or null while pending");
    if (scope !== null && !["production", "disposable-research"].includes(scope)) bad("security.scope", "must be production, disposable-research, or null while pending");
    if (record.security.decisionRef !== null && (typeof record.security.decisionRef !== "string" || !record.security.decisionRef.trim())) bad("security.decisionRef", "must be a non-empty string or null while pending");
    if (requireLive && !trust) bad("security.proofArtifacts", "is required for a live record");
    if (requireLive && !scope) bad("security.scope", "is required for a live record");
    if (requireLive && !(typeof record.security.decisionRef === "string" && record.security.decisionRef.trim())) bad("security.decisionRef", "is required for a live record");
    if (trust === "untrusted-testnet" && scope !== "disposable-research") bad("security", "untrusted proof artifacts are allowed only in a disposable-research fleet");
    if (scope === "production" && trust !== "trusted-ceremony") bad("security", "production requires trusted-ceremony proof artifacts");
  }

  const servicePins = [];
  if (!isObject(record.services)) bad("services", "must pin elder, node, and heartbeat");
  else for (const name of SERVICE_NAMES) {
    const service = record.services[name];
    if (!isObject(service)) { bad(`services.${name}`, "must be { repository, commit }"); continue; }
    if (service.repository !== null && !safeRepository(service.repository)) bad(`services.${name}.repository`, "must be a credential-free https URL or null while pending");
    if (service.commit !== null && !(typeof service.commit === "string" && COMMIT_RE.test(service.commit))) bad(`services.${name}.commit`, "must be a full lowercase 40-hex commit or null while pending");
    if (requireLive && !safeRepository(service.repository)) bad(`services.${name}.repository`, "is required for a live record");
    if (requireLive && !(typeof service.commit === "string" && COMMIT_RE.test(service.commit))) bad(`services.${name}.commit`, "is required for a live record");
    if (service.repository && service.commit) servicePins.push(`${service.repository}\n${service.commit}`);
  }
  if (servicePins.length > 1 && new Set(servicePins).size !== 1) {
    bad("services", "elder, node, and heartbeat must share one repository and commit in the current single-checkout deployer");
  }

  if (!isObject(record.admission)) bad("admission", "must be an object");
  else {
    const paths = record.admission.paths;
    if (!Array.isArray(paths) || paths.length === 0 || paths.some((p) => !ADMISSION_PATHS.includes(p)) || new Set(paths).size !== paths.length) {
      bad("admission.paths", "must be a non-empty unique subset of invited, staked, paid");
    } else {
      const canonical = ADMISSION_PATHS.filter((p) => paths.includes(p));
      if (paths.join(",") !== canonical.join(",")) bad("admission.paths", "must use canonical order: invited, staked, paid");
    }
    if (!record.admission.paths?.includes(record.admission.defaultPath)) bad("admission.defaultPath", "must name one of admission.paths");
    if (!isObject(record.admission.roots)) bad("admission.roots", "must name invited, staked, and paid roots");
    else {
      const roots = record.admission.roots;
      if (roots.invited !== null) {
        if (!isObject(roots.invited) || !(typeof roots.invited.membersSha256 === "string" && SHA256_RE.test(roots.invited.membersSha256))) bad("admission.roots.invited.membersSha256", "must be a lowercase sha256 or null while pending");
      }
      for (const path of ["staked", "paid"]) if (roots[path] !== null) {
        if (!isObject(roots[path]) || !isEthAddress(roots[path].contract)) bad(`admission.roots.${path}.contract`, "must be a contract address or null");
        if (roots[path].rpcUrl !== undefined && !safeRepository(roots[path].rpcUrl)) bad(`admission.roots.${path}.rpcUrl`, "must be a credential-free HTTPS URL when present");
        // ADR 0012: the failover list; rpcUrl stays its first entry for readers that know one endpoint.
        if (roots[path].rpcUrls !== undefined) {
          const list = roots[path].rpcUrls;
          if (!Array.isArray(list) || list.length === 0 || list.length > 5 || !list.every(safeRepository)) bad(`admission.roots.${path}.rpcUrls`, "must be 1..5 credential-free HTTPS URLs when present");
          else if (new Set(list).size !== list.length) bad(`admission.roots.${path}.rpcUrls`, "must not list an endpoint twice");
          else if (roots[path].rpcUrl !== undefined && roots[path].rpcUrl !== list[0]) bad(`admission.roots.${path}.rpcUrl`, "must equal rpcUrls[0] (the primary endpoint)");
        }
        if (roots[path].deployBlock !== undefined && (!Number.isInteger(roots[path].deployBlock) || roots[path].deployBlock < 0)) bad(`admission.roots.${path}.deployBlock`, "must be a non-negative integer when present");
      }
      if (Array.isArray(paths)) for (const path of paths) {
        const root = roots[path];
        if (requireLive && root === null) bad(`admission.roots.${path}`, `is required because ${path} is admitted`);
      }
      validateStakedProfile(roots.staked, record.ratePolicy, bad);
      if (roots.staked?.profile === "public-stake-v1" && record.admission.defaultPath !== "staked") {
        bad("admission.defaultPath", "public-stake-v1 must be the default admission path");
      }
      if (roots.staked?.profile === "public-stake-v1" && !isPosInt(roots.staked.deployBlock)) {
        bad("admission.roots.staked.deployBlock", "public-stake-v1 requires a positive deployment block");
      }
    }
    const onchain = Array.isArray(paths) && paths.some((p) => p === "staked" || p === "paid");
    const auth = record.admission.operatorAuthorization;
    if (auth !== null && (!isObject(auth) || auth.approved !== true || typeof auth.decisionRef !== "string" || !auth.decisionRef.trim())) {
      bad("admission.operatorAuthorization", "must be { approved: true, decisionRef } or null");
    }
    if (onchain && (!isObject(auth) || auth.approved !== true || typeof auth.decisionRef !== "string" || !auth.decisionRef.trim())) {
      bad("admission.operatorAuthorization", "is required before staked or paid admission can deploy");
    }
  }

  if (!isObject(record.artifacts)) bad("artifacts", "must be { accepted, legacy }");
  else {
    const accepted = record.artifacts.accepted;
    if (!Array.isArray(accepted)) bad("artifacts.accepted", "must be an array");
    else {
      if (requireLive && accepted.length === 0) bad("artifacts.accepted", "must contain at least one accepted RLN verification key");
      if (accepted.length > 4) bad("artifacts.accepted", "must contain at most four rollout keys");
      const ids = new Set();
      for (let i = 0; i < accepted.length; i++) {
        const artifact = accepted[i];
        const base = `artifacts.accepted[${i}]`;
        if (!isObject(artifact)) { bad(base, "must be { id, verificationKeyPath, sha256 }"); continue; }
        if (!isArtifactId(artifact.id) || !artifact.id.startsWith("rln-")) bad(`${base}.id`, "must be a bounded rln artifact id");
        else if (ids.has(artifact.id)) bad(`${base}.id`, "must be unique");
        else ids.add(artifact.id);
        if (!safeRelativePath(artifact.verificationKeyPath)) bad(`${base}.verificationKeyPath`, "must be a relative path without . or .. segments");
        if (!(typeof artifact.sha256 === "string" && SHA256_RE.test(artifact.sha256))) bad(`${base}.sha256`, "must be a lowercase sha256");
        if (repoRoot && safeRelativePath(artifact.verificationKeyPath)) {
          const root = resolve(repoRoot);
          const path = resolve(root, artifact.verificationKeyPath);
          if (path !== root && !path.startsWith(root + sep)) bad(`${base}.verificationKeyPath`, "escapes the repository root");
          else if (!existsSync(path)) bad(`${base}.verificationKeyPath`, `not found under repository root: ${artifact.verificationKeyPath}`);
          else {
            const bytes = readFileSync(path);
            const digest = createHash("sha256").update(bytes).digest("hex");
            if (artifact.sha256 !== digest) bad(`${base}.sha256`, `does not match ${artifact.verificationKeyPath}`);
            const derived = artifactIdOf("rln", bytes);
            if (artifact.id !== derived) bad(`${base}.id`, `does not match verification-key content id ${derived}`);
          }
        }
      }
      if (record.artifacts.legacy !== null && !isArtifactId(record.artifacts.legacy)) bad("artifacts.legacy", "must be a bounded artifact id or null");
    }
    if (requireLive && !repoRoot) bad("artifacts", "live preflight requires --repo-root so hashes and content-derived ids are verified");
    if (repoRoot && record.security?.proofArtifacts === "trusted-ceremony") {
      const lockPath = resolve(repoRoot, "testdata/zk-artifacts.lock.json");
      let lock = null;
      try { lock = JSON.parse(readFileSync(lockPath, "utf8")); } catch { /* diagnosed below */ }
      if (lock?.trust !== "TRUSTED-CEREMONY" || lock?.ceremony?.status !== "complete") {
        bad("security.proofArtifacts", "claims trusted-ceremony but the pinned artifact lock does not record a completed trusted ceremony");
      }
    }
  }

  for (const field of ["created", "note"]) {
    if (record[field] !== undefined && record[field] !== null && typeof record[field] !== "string") bad(field, "must be a string or null");
  }
  return { ok: errors.length === 0, errors };
}

export function loadDeploymentRecord(path) {
  let record;
  try { record = JSON.parse(readFileSync(path, "utf8")); }
  catch (error) { throw new Error(`${path}: invalid JSON (${error.message})`); }
  return record;
}

// Verify that the public pins describe bytes which actually exist at the immutable commit, not
// merely whatever happens to be in the controller's working tree today.
export function validatePinnedCheckout(record, { repoRoot }) {
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  if (!repoRoot || !isObject(record?.services?.node) || !COMMIT_RE.test(record.services.node.commit || "")) return { ok: false, errors: [{ field: "services.node.commit", problem: "cannot verify an absent immutable commit" }] };
  const root = resolve(repoRoot);
  const commit = record.services.node.commit;
  const git = (...args) => spawnSync("git", ["-C", root, ...args], { encoding: null });
  const commitCheck = git("cat-file", "-e", `${commit}^{commit}`);
  if (commitCheck.status !== 0) return { ok: false, errors: [{ field: "services.node.commit", problem: "is not a commit available in the controller checkout" }] };

  for (const path of ["packages/node/bootnode/server.mjs", "packages/node/gateway/gateway.mjs", "packages/node/bootnode/heartbeat.mjs", "packages/node/bootnode/deploy/bootstrap.sh"]) {
    if (git("cat-file", "-e", `${commit}:${path}`).status !== 0) bad("services", `pinned commit does not contain ${path}`);
  }
  if (record?.admission?.roots?.staked?.profile === "public-stake-v1" && git("cat-file", "-e", `${commit}:${PUBLIC_STAKE_BYTECODE_MANIFEST}`).status !== 0) {
    bad("services.node.commit", `pinned commit does not contain ${PUBLIC_STAKE_BYTECODE_MANIFEST}`);
  }
  if (record.security?.proofArtifacts === "trusted-ceremony") {
    const lockBytes = git("show", `${commit}:testdata/zk-artifacts.lock.json`);
    let lock = null;
    try { if (lockBytes.status === 0) lock = JSON.parse(lockBytes.stdout.toString("utf8")); } catch { /* diagnosed below */ }
    if (lock?.trust !== "TRUSTED-CEREMONY" || lock?.ceremony?.status !== "complete") {
      bad("security.proofArtifacts", "is not backed by a completed trusted ceremony in the pinned commit's artifact lock");
    }
  }
  for (let i = 0; i < (record.artifacts?.accepted || []).length; i++) {
    const artifact = record.artifacts.accepted[i];
    if (!safeRelativePath(artifact?.verificationKeyPath)) continue;
    const shown = git("show", `${commit}:${artifact.verificationKeyPath}`);
    const base = `artifacts.accepted[${i}]`;
    if (shown.status !== 0) { bad(`${base}.verificationKeyPath`, "is absent from the pinned service commit"); continue; }
    const digest = createHash("sha256").update(shown.stdout).digest("hex");
    if (artifact.sha256 !== digest) bad(`${base}.sha256`, "does not match the verification key at the pinned service commit");
    const derived = artifactIdOf("rln", shown.stdout);
    if (artifact.id !== derived) bad(`${base}.id`, `does not match pinned verification-key content id ${derived}`);
  }
  return { ok: errors.length === 0, errors };
}

function loadPinnedPublicBytecodeManifest(record, repoRoot) {
  if (!repoRoot) throw new Error("public-stake-v1 bytecode verification requires --repo-root");
  const commit = record?.services?.node?.commit;
  if (!COMMIT_RE.test(commit || "")) throw new Error("public-stake-v1 bytecode verification requires an immutable service commit");
  const shown = spawnSync("git", ["-C", resolve(repoRoot), "show", `${commit}:${PUBLIC_STAKE_BYTECODE_MANIFEST}`], { encoding: "utf8" });
  if (shown.status !== 0) throw new Error(`pinned service commit does not contain ${PUBLIC_STAKE_BYTECODE_MANIFEST}`);
  try { return JSON.parse(shown.stdout); }
  catch (error) { throw new Error(`pinned ${PUBLIC_STAKE_BYTECODE_MANIFEST} is invalid JSON (${error.message})`); }
}

function normalizedRuntime(code, spec) {
  const raw = String(code || "").replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(raw) || raw.length % 2 !== 0) throw new Error("has no deployed bytecode");
  if (!isObject(spec) || !Number.isSafeInteger(spec.runtimeBytes) || spec.runtimeBytes <= 0 || !SHA256_RE.test(spec.normalizedSha256 || "") || !Array.isArray(spec.zeroRanges)) {
    throw new Error("has an invalid pinned bytecode specification");
  }
  if (raw.length / 2 !== spec.runtimeBytes) throw new Error(`runtime length ${raw.length / 2} does not match pinned ${spec.runtimeBytes}`);
  let normalized = raw;
  for (const range of spec.zeroRanges) {
    if (!isObject(range) || !Number.isSafeInteger(range.start) || range.start < 0 || !Number.isSafeInteger(range.length) || range.length <= 0 || range.start + range.length > spec.runtimeBytes) {
      throw new Error("has an invalid pinned normalization range");
    }
    normalized = normalized.slice(0, range.start * 2) + "0".repeat(range.length * 2) + normalized.slice((range.start + range.length) * 2);
  }
  const digest = createHash("sha256").update(Buffer.from(normalized, "hex")).digest("hex");
  if (digest !== spec.normalizedSha256) throw new Error(`runtime bytecode digest ${digest} does not match pinned ${spec.normalizedSha256}`);
  return raw;
}

function linkedAddress(runtime, ranges, name) {
  if (!Array.isArray(ranges) || ranges.length === 0) throw new Error(`has no pinned ${name} link references`);
  const values = ranges.map((range) => {
    if (!isObject(range) || range.length !== 20 || !Number.isSafeInteger(range.start) || range.start < 0 || (range.start + range.length) * 2 > runtime.length) {
      throw new Error(`has an invalid pinned ${name} link reference`);
    }
    return "0x" + runtime.slice(range.start * 2, (range.start + range.length) * 2);
  });
  if (!values.every((value) => value.toLowerCase() === values[0].toLowerCase()) || !isEthAddress(values[0]) || /^0x0{40}$/i.test(values[0])) {
    throw new Error(`does not consistently link a deployed ${name} library`);
  }
  return values[0];
}

export async function validatePublicStakeOnchain(record, { rpcCall = jsonRpcCall, rpcUrl = null, repoRoot = null, bytecodeManifest = null } = {}) {
  const root = record?.admission?.roots?.staked;
  if (root?.profile !== "public-stake-v1") return { ok: true, errors: [] };
  const errors = [];
  const bad = (field, problem) => errors.push({ field, problem });
  const call = (method, params) => rpcCall(rpcUrl || root.rpcUrl, method, params);
  try {
    const manifest = bytecodeManifest || loadPinnedPublicBytecodeManifest(record, repoRoot);
    if (manifest?.schemaVersion !== 1 || manifest?.profile !== "public-stake-v1" || !isObject(manifest.contracts) || !isObject(manifest.libraries)) {
      throw new Error("pinned public-stake-v1 bytecode manifest has the wrong schema or profile");
    }
    if (Object.keys(manifest.contracts).sort().join(",") !== "groth16,hasher,staking,withdrawVerifier" || Object.keys(manifest.libraries).sort().join(",") !== "PoseidonT2,PoseidonT3") {
      throw new Error("pinned public-stake-v1 bytecode manifest must cover the exact contract and linked-library graph");
    }
    const chainId = BigInt(await call("eth_chainId", []));
    if (chainId !== 11_155_111n) bad("onchain.chainId", `RPC reports ${chainId}, expected Sepolia 11155111`);

    // A public RPC pool can answer a historical receipt with null from a pruned backend (seen
    // on the M7 fleet roll, 2026-09-30, 13 000 blocks after the deploy); a second call lands on
    // another backend. Only a receipt that stays missing is a finding.
    let receipt = null;
    for (let attempt = 0; attempt < 4 && !receipt; attempt++) {
      receipt = await call("eth_getTransactionReceipt", [root.deployTx]);
    }
    if (!receipt) bad("onchain.deployTx", "deployment receipt is missing");
    else {
      if (BigInt(receipt.status ?? 0) !== 1n) bad("onchain.deployTx", "deployment transaction did not succeed");
      if (BigInt(receipt.blockNumber ?? 0) !== BigInt(root.deployBlock)) bad("onchain.deployBlock", "receipt block does not match the record");
      if (String(receipt.contractAddress || "").toLowerCase() !== root.contract.toLowerCase()) bad("onchain.contract", "receipt contractAddress does not match the record");
    }

    const runtimeByRole = {};
    const roleAddresses = { staking: root.contract, hasher: root.hasher, withdrawVerifier: root.withdrawVerifier };
    for (const [role, address] of Object.entries(roleAddresses)) {
      try {
        const code = await call("eth_getCode", [address, "latest"]);
        runtimeByRole[role] = normalizedRuntime(code, manifest.contracts[role]);
      } catch (error) { bad(`onchain.bytecode.${role}`, error.message); }
    }
    const linkedLibraries = {};
    for (const [role, runtime] of Object.entries(runtimeByRole)) {
      for (const [name, ranges] of Object.entries(manifest.contracts[role]?.links || {})) {
        try {
          const address = linkedAddress(runtime, ranges, name);
          if (linkedLibraries[name] && linkedLibraries[name].toLowerCase() !== address.toLowerCase()) throw new Error(`links ${name} at ${address}, inconsistent with ${linkedLibraries[name]}`);
          linkedLibraries[name] = address;
        } catch (error) { bad(`onchain.bytecode.${role}.${name}`, error.message); }
      }
    }

    // Every expected value comes from the record (which scripts/deploy-contracts.mjs wrote from
    // network/<net>/economics.json); the chain must match it exactly.
    const tiers = Array.isArray(root.tiers) ? root.tiers : [];
    const tier8 = tiers.find((tier) => tier.limit === 8);
    const extra = tiers.filter((tier) => tier.limit !== 8);
    const divisor = BigInt(root.slashRewardDivisor ?? 10);
    const tx = await call("eth_getTransactionByHash", [root.deployTx]);
    const constructorArgs = AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "address", "address", "uint256[]", "uint256[]", "uint256"],
      [
        BigInt(tier8?.bondWei ?? 0), BigInt(root.unbondingSeconds), BigInt(root.minUnbondingSeconds),
        root.withdrawVerifier, root.hasher,
        extra.map((tier) => BigInt(tier.limit)), extra.map((tier) => BigInt(tier.bondWei)), divisor,
      ],
    ).slice(2).toLowerCase();
    const input = String(tx?.input || tx?.data || "").toLowerCase();
    if (!tx || tx.to != null || !input.endsWith(constructorArgs)) {
      bad("onchain.deployTx", "contract-creation input does not pin the public-stake-v1 constructor parameters");
    }

    const iface = new Interface([
      "function BOND() view returns (uint256)",
      "function UNBONDING() view returns (uint256)",
      "function bondFor(uint256) view returns (uint256)",
      "function allowedLimits() view returns (uint256[])",
      "function SLASH_REWARD_DIVISOR() view returns (uint256)",
      "function hasher() view returns (address)",
      "function withdrawVerifier() view returns (address)",
      "function groth16() view returns (address)",
    ]);
    const view = async (name, args = []) => {
      const result = await call("eth_call", [{ to: root.contract, data: iface.encodeFunctionData(name, args) }, "latest"]);
      return iface.decodeFunctionResult(name, result);
    };
    if ((await view("BOND"))[0] !== BigInt(tier8?.bondWei ?? -1)) bad("onchain.BOND", "must equal the recorded tier-8 bond");
    for (const tier of tiers) {
      if ((await view("bondFor", [tier.limit]))[0] !== BigInt(tier.bondWei)) bad(`onchain.bondFor(${tier.limit})`, `must equal the recorded ${tier.bondWei} wei`);
    }
    const limits = Array.from((await view("allowedLimits"))[0], Number);
    if (limits.join(",") !== tiers.map((tier) => tier.limit).join(",")) bad("onchain.allowedLimits", "must equal the recorded tier limits");
    if ((await view("UNBONDING"))[0] !== BigInt(root.unbondingSeconds)) bad("onchain.UNBONDING", "must equal the recorded unbonding");
    if ((await view("SLASH_REWARD_DIVISOR"))[0] !== divisor) bad("onchain.SLASH_REWARD_DIVISOR", "must equal the recorded slash split");
    if (String((await view("hasher"))[0]).toLowerCase() !== root.hasher.toLowerCase()) bad("onchain.hasher", "does not match the record");
    if (String((await view("withdrawVerifier"))[0]).toLowerCase() !== root.withdrawVerifier.toLowerCase()) bad("onchain.withdrawVerifier", "does not match the record");
    const wrapperCall = async (name) => {
      const result = await call("eth_call", [{ to: root.withdrawVerifier, data: iface.encodeFunctionData(name) }, "latest"]);
      return iface.decodeFunctionResult(name, result);
    };
    const groth16 = String((await wrapperCall("groth16"))[0]);
    if (!isEthAddress(groth16)) bad("onchain.withdrawVerifier.groth16", "wrapper does not point to a valid Groth16 verifier address");
    else {
      try { normalizedRuntime(await call("eth_getCode", [groth16, "latest"]), manifest.contracts.groth16); }
      catch (error) { bad("onchain.bytecode.groth16", error.message); }
    }
    for (const [name, spec] of Object.entries(manifest.libraries)) {
      const address = linkedLibraries[name];
      if (!address) { bad(`onchain.bytecode.${name}`, "pinned library is not linked by the deployed contract graph"); continue; }
      try { normalizedRuntime(await call("eth_getCode", [address, "latest"]), spec); }
      catch (error) { bad(`onchain.bytecode.${name}`, error.message); }
    }
  } catch (error) {
    bad("onchain.rpc", error.message);
  }
  return { ok: errors.length === 0, errors };
}

function parseArgs(argv) {
  const flags = { requireLive: true, repoRoot: null, requireStakeProfile: null, rpcUrl: null, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--record") flags.record = argv[++i];
    else if (arg.startsWith("--record=")) flags.record = arg.slice(9);
    else if (arg === "--repo-root") flags.repoRoot = argv[++i];
    else if (arg.startsWith("--repo-root=")) flags.repoRoot = arg.slice(12);
    else if (arg === "--require-stake-profile") flags.requireStakeProfile = argv[++i];
    else if (arg.startsWith("--require-stake-profile=")) flags.requireStakeProfile = arg.slice(24);
    else if (arg === "--rpc-url") flags.rpcUrl = argv[++i];
    else if (arg.startsWith("--rpc-url=")) flags.rpcUrl = arg.slice(10);
    else if (arg === "--allow-pending") flags.requireLive = false;
    else if (arg === "--quiet") flags.quiet = true;
    else if (arg === "--help") flags.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return flags;
}

async function main() {
  try {
    const flags = parseArgs(process.argv.slice(2));
    if (flags.help) {
      console.log("usage: node deploy/v4/preflight.mjs --record <deployment.json> --repo-root <checkout> [--require-stake-profile public-stake-v1] [--rpc-url <runtime-rpc>[,<fallback>...]] [--allow-pending] [--quiet]");
      return;
    }
    if (!flags.record) throw new Error("--record <deployment.json> is required");
    const record = loadDeploymentRecord(flags.record);
    const shape = validateDeploymentRecord(record, flags);
    const pin = shape.ok && flags.requireLive ? validatePinnedCheckout(record, flags) : { ok: true, errors: [] };
    // The runtime RPC may be a failover list (SHADE_TREE_RPC_URL takes up to five, comma-separated):
    // every endpoint the nodes can fall back to must pass the same on-chain checks.
    // Without --rpc-url, every endpoint of the record's own failover list is checked (ADR 0012).
    const recordRpcs = record.admission?.roots?.staked?.rpcUrls;
    const rpcUrls = flags.rpcUrl ? flags.rpcUrl.split(",").map((url) => url.trim()).filter(Boolean) : (Array.isArray(recordRpcs) && recordRpcs.length ? recordRpcs : [null]);
    if (rpcUrls.length > 5) throw new Error("--rpc-url takes at most five comma-separated endpoints");
    const chain = { ok: true, errors: [] };
    if (shape.ok && pin.ok && flags.requireLive) {
      for (const rpcUrl of rpcUrls) {
        const one = await validatePublicStakeOnchain(record, { repoRoot: flags.repoRoot, rpcUrl });
        chain.ok &&= one.ok;
        const via = rpcUrls.length > 1 ? ` (via ${new URL(rpcUrl).host})` : "";
        chain.errors.push(...one.errors.map((e) => ({ ...e, problem: `${e.problem}${via}` })));
      }
    }
    const result = { ok: shape.ok && pin.ok && chain.ok, errors: [...shape.errors, ...pin.errors, ...chain.errors] };
    if (!result.ok) {
      const lines = result.errors.map((e) => `  ${e.field}: ${e.problem}`).join("\n");
      throw new Error(`${flags.record}: deployment preflight failed\n${lines}`);
    }
    if (!flags.quiet) console.log(`${flags.record}: ${flags.requireLive ? "deployable v4 record" : "valid v4 record"}`);
  } catch (error) {
    console.error(`v4-preflight: ${error.message}`);
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
