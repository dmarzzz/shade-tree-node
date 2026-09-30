// Config validation — fail-fast on a malformed SHADE_TREE_* environment before a component boots.
//
// Every knob in this system is an `SHADE_TREE_*` env var (see docs/CONFIG.md). A missing required
// var, or a value in the wrong shape (a truncated onion, a non-hex signer, an out-of-range
// port), otherwise surfaces LATER as an opaque crash deep inside Tor/RPC/crypto. This module
// is the single place that says, up front and per role, exactly which var is wrong and why.
//
// It is PURE: no process.exit, no I/O, no network, no chain. It only reads the env object it
// is handed (defaulting to process.env) and returns a plain result. That keeps it trivially
// testable (packages/node/lib/config.selftest.mjs drives it with hand-built envs) and safe to import anywhere.
//
// NOT WIRED YET (by design): a follow-up task calls `validateConfig(role)` at the top of each
// entrypoint (packages/node/bootnode/server.mjs, packages/node/gateway/gateway.mjs, packages/node/client/shim.mjs, group/enroll.mjs) and,
// on `ok:false`, prints the errors and exits non-zero. This file deliberately does NOT touch
// those entrypoints — it lands on disjoint files so it can ship independently. The `main()`-side
// exit/print policy lives there; the truth about what is valid lives here.
//
// The rules are grounded in what the code ACTUALLY reads (grep of process.env.SHADE_TREE_*, plus the
// resolution logic in gateway-registry / root-provider / selection / shade-tree-client). Where a var
// has a default in code it is treated as OPTIONAL (validated only if present), never required —
// requiring a var the code happily runs without would be inventing a constraint. Genuine
// conditionals (onchain stake needs a registry; directory discovery needs a pinned signer) are
// encoded as such and called out in the header of each role block below.

import { onionToPubkey } from "./directory.mjs";

// BN254 (alt_bn128) scalar field prime — the field the RLN secret / Poseidon operate in.
// Inlined (not imported from packages/node/lib/rln.mjs) so this validator stays dependency-light and pure:
// importing rln.mjs would drag in Poseidon/circuit machinery for a single constant.
export const FIELD_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---- field validators --------------------------------------------------------
// Each is TOTAL: any input (undefined, number, object, hostile string) yields a boolean,
// never a throw. They validate SHAPE only; liveness/on-chain truth is checked elsewhere.

// A v3 .onion: 56 base32 chars (+optional `.onion`) whose embedded ed25519 key + checksum
// decode. Reuse onionToPubkey so "valid onion" means exactly what the fleet code means by it.
export function isOnion(v) {
  if (typeof v !== "string") return false;
  try {
    onionToPubkey(v.trim());
    return true;
  } catch {
    return false;
  }
}

// A raw ed25519 public key: exactly 64 hex chars, NO 0x prefix (that is how SHADE_TREE_DIR_SIGNER is
// stored and how normalizePinnedSigners in directory.mjs consumes it; a 0x-prefixed value would
// silently fail signature verification, so reject it here).
export function isEd25519PubHex(v) {
  return typeof v === "string" && /^[0-9a-fA-F]{64}$/.test(v.trim());
}

// A 32-byte private key (SHADE_TREE_SLASH_KEY / SHADE_TREE_REGISTER_KEY / SHADE_TREE_GW_OPERATOR_KEY): 64 hex,
// 0x optional (ethers.Wallet accepts either).
export function isPrivHex(v) {
  return typeof v === "string" && /^(0x)?[0-9a-fA-F]{64}$/.test(v.trim());
}

// A 20-byte Ethereum address, 0x-prefixed. Case-insensitive (does not enforce EIP-55 checksum,
// matching how the code passes addresses straight into eth_call).
export function isEthAddress(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v.trim());
}

// A comma-separated list of addresses (SHADE_TREE_GROUP_CONTRACT since T-FEAT-7: several sets trusted
// at once). Every entry must be an address; a single address is a one-element list; empty
// entries ("0xA,,0xB") are rejected so a typo never silently drops a set.
export function isEthAddressList(v) {
  if (typeof v !== "string") return false;
  const parts = v.split(",").map((x) => x.trim());
  return parts.length > 0 && parts.every(isEthAddress);
}

// SHADE_TREE_ROOTS: comma list drawn from {static, onchain} (gateway root sources, T-FEAT-7).
export function isRootSourceList(v) {
  if (typeof v !== "string") return false;
  const parts = v.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => p === "static" || p === "onchain");
}

// SHADE_TREE_ADMIT: comma list drawn from {invited, staked, paid} (gateway admission policy, T-FEAT-9).
export function isAdmitList(v) {
  if (typeof v !== "string") return false;
  const parts = v.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => p === "invited" || p === "staked" || p === "paid");
}
// SHADE_TREE_PAY_PROTOCOLS: comma list drawn from {x402, mpp} (registrar rails, T-FEAT-9).
export function isPayProtocolList(v) {
  if (typeof v !== "string") return false;
  const parts = v.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => p === "x402" || p === "mpp");
}
// SHADE_TREE_LEAF_SOURCE: auto | invited | staked | paid (client leaf-source pin, T-FEAT-9).
export function isLeafSource(v) {
  return typeof v === "string" && ["auto", "invited", "staked", "paid"].includes(v.trim().toLowerCase());
}
// A boolean flag: 0/1/true/false/yes/no/on/off (SHADE_TREE_MAX_ANON).
export function isBoolFlag(v) {
  return typeof v === "string" && ["0", "1", "true", "false", "yes", "no", "on", "off"].includes(v.trim().toLowerCase());
}

// TCP port: integer 1..65535.
export function isPort(v) {
  const s = String(v).trim();
  if (!/^\d+$/.test(s)) return false;
  const n = Number(s);
  return n >= 1 && n <= 65535;
}

// A listen port that may be 0 = "off/disabled" (e.g. SHADE_TREE_METRICS_PORT): integer 0..65535.
export function isPortOrOff(v) {
  const s = String(v).trim();
  if (!/^\d+$/.test(s)) return false;
  const n = Number(s);
  return n >= 0 && n <= 65535;
}

// An http(s)/ws(s) URL (SHADE_TREE_RPC_URL). Uses the URL parser, then pins the protocol so a bare
// host or a file: path is rejected.
export function isUrl(v) {
  if (typeof v !== "string") return false;
  let u;
  try {
    u = new URL(v.trim());
  } catch {
    return false;
  }
  return ["http:", "https:", "ws:", "wss:"].includes(u.protocol);
}

// SHADE_TREE_RPC_URL: one URL, or up to five comma-separated for RPC failover (OPS-8, tried in
// order by packages/node/lib/rpc-safety.mjs). Every entry must pass isUrl.
export function isRpcUrls(v) {
  if (typeof v !== "string") return false;
  const parts = v.split(",").map((p) => p.trim());
  return parts.length >= 1 && parts.length <= 5 && parts.every((p) => p !== "" && isUrl(p));
}

// A field-element secret (SHADE_TREE_SECRET): parseable as a bigint (0x-hex OR decimal), strictly
// positive, and NON-zero in the field. A zero (or a multiple of FIELD_MOD) is the identity /
// a degenerate secret and must be rejected.
export function isField(v) {
  if (v == null) return false;
  const s = String(v).trim();
  if (s === "") return false;
  let n;
  try {
    n = BigInt(s); // handles "0x..." and plain decimal; throws on anything else
  } catch {
    return false;
  }
  if (n <= 0n) return false;
  return ((n % FIELD_MOD) + FIELD_MOD) % FIELD_MOD !== 0n;
}

// A strictly-positive integer (counts/intervals/bonds).
export function isPosInt(v) {
  const s = String(v).trim();
  return /^\d+$/.test(s) && Number(s) >= 1;
}

// A non-negative integer (e.g. SHADE_TREE_CONFIRMATIONS, where 0 = "latest").
export function isNonNegInt(v) {
  return /^\d+$/.test(String(v).trim());
}

// Membership in a fixed set (enum vars). Returns a validator so it composes with the field table.
export function isEnum(v, allowed) {
  return allowed.includes(String(v));
}
function enumOf(...allowed) {
  return (v) => isEnum(v, allowed);
}

// ---- presence + check helpers ------------------------------------------------

function present(env, name) {
  const v = env[name];
  return v !== undefined && v !== null && String(v).length > 0;
}

function checkRequired(env, name, validator, problem, errors) {
  if (!present(env, name)) {
    errors.push({ var: name, problem: "required but not set" });
    return;
  }
  if (!validator(env[name])) errors.push({ var: name, problem });
}

function checkOptional(env, name, validator, problem, errors) {
  if (present(env, name) && !validator(env[name])) errors.push({ var: name, problem });
}

function checkMetricsPortCollision(env, errors, serviceVar, serviceDefault, serviceLabel) {
  const metrics = present(env, "SHADE_TREE_METRICS_PORT") ? env.SHADE_TREE_METRICS_PORT : "0";
  const service = present(env, serviceVar) ? env[serviceVar] : String(serviceDefault);
  if (isPortOrOff(metrics) && isPort(service) && Number(metrics) > 0 && Number(metrics) === Number(service)) {
    errors.push({
      var: "SHADE_TREE_METRICS_PORT",
      problem: `must not reuse the ${serviceLabel} port (${service})`,
    });
  }
}

// ---- role field specifications ----------------------------------------------
// Field = [ VAR_NAME, validator, problem-message ]. `required` fails when absent OR malformed;
// `optional` fails only when PRESENT and malformed. Cross-field conditionals (which cannot be a
// flat list) are the per-role `conditional(env, errors)` callbacks below.

const P_ONION = "must be a 56-char v3 .onion address (checksum-valid)";
const P_ED = "must be a raw 64-hex-char ed25519 public key (no 0x prefix)";
const P_PRIV = "must be a 32-byte hex private key (64 hex chars, 0x optional)";
const P_ADDR = "must be a 0x-prefixed 20-byte Ethereum address";
const P_ADDRLIST = "must be a 0x-prefixed 20-byte Ethereum address, or a comma-separated list of them";
const P_ROOTS = "must be a comma-separated list drawn from: static, onchain (DEPRECATED alias of SHADE_TREE_ADMIT)";
const P_ADMIT = "must be a comma-separated list drawn from: invited, staked, paid";
const P_PAYPROTO = "must be a comma-separated list drawn from: x402, mpp";
const P_LEAFSRC = "must be one of: auto, invited, staked, paid";
const P_BOOL = "must be a boolean flag: 0/1/true/false/yes/no/on/off";
const P_PORT = "must be an integer TCP port in 1..65535";
const P_PORT0 = "must be an integer port in 0..65535 (0 = disabled)";
const P_URL = "must be an http(s)/ws(s) URL";
const P_FIELD = "must be a positive field-element secret (0x-hex or decimal, non-zero mod field)";
const P_POSINT = "must be a positive integer";
const P_NONNEG = "must be a non-negative integer";
const P_ADMISSION = "must be one of: open, stake";
const P_STAKEMODE = "must be one of: onchain, mock";
const P_ROOTPROV = "must be one of: node, light";
const P_LOGLEVEL = "must be one of: debug, info, warn, error, off";
const P_LOGFORMAT = "must be one of: auto, pretty, text, json";
const P_BANNER = "must be one of: auto, always, never, on, off, true, false, 1, 0";

const OPERATOR_FIELDS = [
  ["SHADE_TREE_LOG_LEVEL", enumOf("debug", "info", "warn", "error", "off"), P_LOGLEVEL],
  ["SHADE_TREE_LOG_FORMAT", enumOf("auto", "pretty", "text", "json"), P_LOGFORMAT],
  ["SHADE_TREE_BANNER", enumOf("auto", "always", "never", "on", "off", "true", "false", "1", "0"), P_BANNER],
  ["SHADE_TREE_METRICS_PORT", isPortOrOff, P_PORT0],
];

export const ROLE_SPECS = {
  // BOOTNODE — packages/node/bootnode/server.mjs (discovery service) + packages/node/lib/gateway-registry.mjs stake source.
  // Nothing is unconditionally required: every var has a default in code. The one real
  // conditional: an ONCHAIN stake verifier (SHADE_TREE_STAKE_MODE=onchain, or implied by a registry
  // being set) THROWS without SHADE_TREE_GATEWAY_REGISTRY, so that pairing is enforced below.
  bootnode: {
    required: [],
    optional: [
      ...OPERATOR_FIELDS,
      ["SHADE_TREE_BOOTNODE_PORT", isPort, P_PORT],
      ["SHADE_TREE_BOOTNODE_ADMISSION", enumOf("open", "stake"), P_ADMISSION],
      ["SHADE_TREE_BOOTNODE_TTL", isPosInt, P_POSINT],
      ["SHADE_TREE_BOOTNODE_HEARTBEAT", isPosInt, P_POSINT],
      ["SHADE_TREE_BOOTNODE_MAX_ENTRIES", isPosInt, P_POSINT],
      ["SHADE_TREE_BOOTNODE_MIN_REANNOUNCE", isPosInt, P_POSINT],
      ["SHADE_TREE_STAKE_MODE", enumOf("onchain", "mock"), P_STAKEMODE],
      ["SHADE_TREE_GATEWAY_REGISTRY", isEthAddress, P_ADDR],
      ["SHADE_TREE_STAKE_CACHE_MS", isPosInt, P_POSINT],
      ["SHADE_TREE_CONFIRMATIONS", isNonNegInt, P_NONNEG],
      ["SHADE_TREE_RPC_URL", isRpcUrls, P_URL],
    ],
    conditional(env, errors) {
      checkMetricsPortCollision(env, errors, "SHADE_TREE_BOOTNODE_PORT", 8877, "Elder Tree backend");
      // Effective stake mode: explicit SHADE_TREE_STAKE_MODE, else onchain iff a registry is set
      // (makeStakeVerifier), else mock. Onchain REQUIRES the registry address.
      const mode = present(env, "SHADE_TREE_STAKE_MODE")
        ? String(env.SHADE_TREE_STAKE_MODE)
        : present(env, "SHADE_TREE_GATEWAY_REGISTRY")
          ? "onchain"
          : "mock";
      if (mode === "onchain" && !present(env, "SHADE_TREE_GATEWAY_REGISTRY")) {
        errors.push({
          var: "SHADE_TREE_GATEWAY_REGISTRY",
          problem: "required when stake mode is onchain (SHADE_TREE_STAKE_MODE=onchain)",
        });
      }
    },
  },

  // GATEWAY — packages/node/gateway/gateway.mjs (egress proxy) + root-provider + slasher. Also fully
  // defaulted: with NO env at all it runs chainless (members.json root, dry-run slashing,
  // mock stake). So there are no required vars; everything present is shape-checked. Setting
  // SHADE_TREE_GROUP_CONTRACT switches the root source on-chain, but SHADE_TREE_RPC_URL has a localhost
  // default, so no hard pairing is forced here.
  gateway: {
    required: [],
    optional: [
      ...OPERATOR_FIELDS,
      ["SHADE_TREE_GATEWAY_PORT", isPort, P_PORT],
      ["SHADE_TREE_GROUP_CONTRACT", isEthAddressList, P_ADDRLIST],
      ["SHADE_TREE_PAID_ACCESS_CONTRACT", isEthAddress, P_ADDR], // T-FEAT-7: PaidAccessSet root source (appends)
      ["SHADE_TREE_ADMIT", isAdmitList, P_ADMIT],                // T-FEAT-9: invited[,staked][,paid] (default invited = max-anon)
      ["SHADE_TREE_ROOTS", isRootSourceList, P_ROOTS],           // T-FEAT-7 spelling, deprecated alias (static->invited, onchain->staked+paid)
      ["SHADE_TREE_PAY_PROTOCOLS", isPayProtocolList, P_PAYPROTO], // T-FEAT-9: registrar / advert rails (heartbeat shares the gateway role)
      ["SHADE_TREE_PAID_MIN_LEAVES", isPosInt, P_POSINT],        // T-FEAT-7: paid anonymity-set floor (warn only)
      ["SHADE_TREE_ROOT_PROVIDER", enumOf("node", "light"), P_ROOTPROV],
      ["SHADE_TREE_SLASH_KEY", isPrivHex, P_PRIV],
      ["SHADE_TREE_SLASH_CONTRACT", isEthAddress, P_ADDR],
      ["SHADE_TREE_SLASH_RECEIVER", isEthAddress, P_ADDR],
      ["SHADE_TREE_RPC_URL", isRpcUrls, P_URL],
      ["SHADE_TREE_HELIOS_RPC_URL", isUrl, P_URL],   // T-DEV-9b: local Helios anchor for the light provider
      ["SHADE_TREE_HELIOS_CHAIN_ID", isPosInt, P_POSINT],
      ["SHADE_TREE_HEARTBEAT_METRICS_PORT", isPortOrOff, P_PORT0],
      ["SHADE_TREE_CONFIRMATIONS", isNonNegInt, P_NONNEG],
      ["SHADE_TREE_FRESHNESS_ROOTS", isPosInt, P_POSINT],
      ["SHADE_TREE_ROOT_FRESHNESS_SECONDS", isPosInt, P_POSINT],
      ["SHADE_TREE_EPOCH_SECONDS", isPosInt, P_POSINT],
      ["SHADE_TREE_SLOTS", isPosInt, P_POSINT],
      ["SHADE_TREE_RLN_IDENTIFIER", isPosInt, P_POSINT],
    ],
    conditional(env, errors) {
      checkMetricsPortCollision(env, errors, "SHADE_TREE_GATEWAY_PORT", 8443, "node backend");
    },
  },

  // CLIENT — packages/node/client/shade-tree-client.mjs + packages/node/client/selection.mjs. SHADE_TREE_SECRET is the ONE hard
  // requirement (shade-tree-client throws without it). Discovery is a three-way choice, enforced by
  // the conditional below:
  //   (a) pin       : SHADE_TREE_ONION
  //   (b) static    : SHADE_TREE_DIRECTORY      + SHADE_TREE_DIR_SIGNER
  //   (c) live       : SHADE_TREE_BOOTNODE_ONION + SHADE_TREE_DIR_SIGNER
  // selection.directoryEnabled() = (bootnode || directory) && dir-signer. The routed client and
  // SDK install the bundled current-v4 Elder+signer pair when no source is explicit; any explicit
  // directory/bootnode source WITHOUT its own signer is still a misconfig, not a silent TOFU path.
  client: {
    required: [["SHADE_TREE_SECRET", isField, P_FIELD]],
    optional: [
      ...OPERATOR_FIELDS,
      ["SHADE_TREE_ONION", isOnion, P_ONION],
      ["SHADE_TREE_BOOTNODE_ONION", isOnion, P_ONION],
      ["SHADE_TREE_DIR_SIGNER", isEd25519PubHex, P_ED],
      ["SHADE_TREE_SHIM_PORT", isPort, P_PORT],
      ["SHADE_TREE_TOR_PORT", isPort, P_PORT],
      // T-FEAT-7 leaf discovery: which sets to look for this member's leaf in (after members.json).
      ["SHADE_TREE_GROUP_CONTRACT", isEthAddressList, P_ADDRLIST],
      ["SHADE_TREE_PAID_ACCESS_CONTRACT", isEthAddress, P_ADDR],
      ["SHADE_TREE_RPC_URL", isRpcUrls, P_URL],
      ["SHADE_TREE_STAKE_PROFILE", enumOf("public-stake-v1"), "must be public-stake-v1"],
      ["SHADE_TREE_LEAF_SOURCE", isLeafSource, P_LEAFSRC],   // T-FEAT-9: pin the set to prove from
      ["SHADE_TREE_MAX_ANON", isBoolFlag, P_BOOL],           // T-FEAT-9: invited-only gateways
      ["SHADE_TREE_DIRECTORY_REFRESH_MS", isPosInt, P_POSINT],
      ["SHADE_TREE_ROTATION_SPREAD", isBoolFlag, P_BOOL],
      ["SHADE_TREE_ROOT_FRESHNESS_SECONDS", isPosInt, P_POSINT],
      ["SHADE_TREE_EPOCH_SECONDS", isPosInt, P_POSINT],
      ["SHADE_TREE_SLOTS", isPosInt, P_POSINT],
      ["SHADE_TREE_RLN_IDENTIFIER", isPosInt, P_POSINT],
      // SHADE_TREE_DIRECTORY is a filesystem path (no shape to check); presence is handled in the
      // conditional. SHADE_TREE_DIRECTORY_CACHE likewise.
    ],
    conditional(env, errors) {
      checkMetricsPortCollision(env, errors, "SHADE_TREE_SHIM_PORT", 8888, "Proxy backend");
      const hasPin = present(env, "SHADE_TREE_ONION");
      const hasDir = present(env, "SHADE_TREE_DIRECTORY");
      const hasBoot = present(env, "SHADE_TREE_BOOTNODE_ONION");
      const hasSigner = present(env, "SHADE_TREE_DIR_SIGNER");

      if (!hasPin && !hasDir && !hasBoot) {
        errors.push({
          var: "SHADE_TREE_ONION",
          problem:
            "no gateway discovery configured: set SHADE_TREE_ONION, or SHADE_TREE_DIRECTORY+SHADE_TREE_DIR_SIGNER, or SHADE_TREE_BOOTNODE_ONION+SHADE_TREE_DIR_SIGNER",
        });
        return;
      }
      // A directory/bootnode source is only enabled with a pinned signer.
      if ((hasDir || hasBoot) && !hasSigner && !hasPin) {
        errors.push({
          var: "SHADE_TREE_DIR_SIGNER",
          problem:
            "required for explicit directory/bootnode discovery (SHADE_TREE_DIRECTORY / SHADE_TREE_BOOTNODE_ONION set without it disables discovery)",
        });
      }
    },
  },

  // MEMBER-ENROLL — group/enroll.mjs generates a member identity locally and reads NO SHADE_TREE_*
  // vars at all (the secret is minted, only the commitment leaves the machine). The on-chain
  // registration half (group/register-onchain.mjs, `shade-tree register-member`) reads the vars below,
  // all OPTIONAL: each falls back to contracts/deployed.local.json or an anvil dev default. So
  // there is nothing this role strictly requires; present values are just shape-checked.
  "member-enroll": {
    required: [],
    optional: [
      ["SHADE_TREE_GROUP_CONTRACT", isEthAddressList, P_ADDRLIST],
      ["SHADE_TREE_PAID_ACCESS_CONTRACT", isEthAddress, P_ADDR], // T-FEAT-7 (`shade-tree leaves` default)
      ["SHADE_TREE_RPC_URL", isRpcUrls, P_URL],
      ["SHADE_TREE_STAKE_PROFILE", enumOf("public-stake-v1"), "must be public-stake-v1"],
      ["SHADE_TREE_CHAIN_ID", isPosInt, P_POSINT],
      ["SHADE_TREE_REGISTER_KEY", isPrivHex, P_PRIV],
      ["SHADE_TREE_BOND", isPosInt, P_POSINT],
    ],
    conditional() {},
  },
};

export const ROLES = Object.keys(ROLE_SPECS);

// ---- the checker -------------------------------------------------------------

// validateConfig(role, env=process.env) -> { ok, errors: [{ var, problem }] }
// PURE: reads only `env`. Unknown role is itself a (single) error, so a typo'd role never
// silently passes. Order of errors: required (in spec order), then optional, then conditionals.
export function validateConfig(role, env = process.env) {
  const spec = ROLE_SPECS[role];
  if (!spec) {
    return { ok: false, errors: [{ var: "role", problem: `unknown role: ${role} (expected one of: ${ROLES.join(", ")})` }] };
  }
  const errors = [];
  for (const [name, validator, problem] of spec.required) checkRequired(env, name, validator, problem, errors);
  for (const [name, validator, problem] of spec.optional) checkOptional(env, name, validator, problem, errors);
  spec.conditional(env, errors);
  return { ok: errors.length === 0, errors };
}

// Convenience: a one-line human summary of a result (for the future entrypoint wiring to print).
export function formatErrors(result) {
  if (result.ok) return "config ok";
  return result.errors.map((e) => `  - ${e.var}: ${e.problem}`).join("\n");
}
