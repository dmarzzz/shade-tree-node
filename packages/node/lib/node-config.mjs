// Operator front door: the ten knobs of `shadenet-node`, resolved from env (SHADENET_*) or a
// `node.toml` in the state directory, and turned into the SHADE_TREE_* environment the gateway
// and heartbeat already read. Everything else a node needs comes from the deployment record
// (Elders, signers, contract, RPC list, tiers, epoch, payload cap, accepted proof artifacts,
// session-ticket switch), through the same envDefaultsFromRecords() that SHADE_TREE_NETWORK uses.
//
// PURE: no process.exit, no network, no spawning. File reads happen only in loadNodeConfig()
// (node.toml, members file existence) and are easy to stub. The supervisor in
// packages/node/bin/shadenet-node.mjs owns Tor, the children and the signals.
//
// Precedence (highest first): SHADE_TREE_* set explicitly by the operator (the advanced layer,
// never overwritten) > SHADENET_* env > node.toml > the record > built-in defaults.

import { readFileSync, existsSync, statSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { envDefaultsFromRecords, validateDeploymentRecord, rpcUrlsOf, eldersOf } from "./network-record.mjs";
import { isEthAddress, isPrivHex } from "./config.mjs";
import { REGION_BUCKETS } from "./directory.mjs";

export const DEFAULT_STATE_DIR = process.platform === "linux" && existsSync("/state") ? "/state" : "./shadenet-node";
export const GATEWAY_PORT = 8443;
export const TOR_SOCKS_PORT = 9050;
export const FLEET_TALLY_PORT = 8444;

// The knobs. `env` is the SHADENET_* name; `toml` the node.toml key; `advanced` the SHADE_TREE_*
// variable(s) it ultimately sets (documented in CONFIG.md as the advanced layer).
export const KNOBS = [
  { key: "record", env: "SHADENET_RECORD", toml: "record", what: "deployment record: https URL or file path (required)" },
  { key: "state", env: "SHADENET_STATE", toml: "state", what: "state directory: onion identity, Tor state, spent set, logs", default: DEFAULT_STATE_DIR },
  { key: "admit", env: "SHADENET_ADMIT", toml: "admit", what: "who this node admits: staked | invited,staked | staked,paid (ADR 0008)", default: "staked", advanced: "SHADE_TREE_ADMIT" },
  { key: "sets", env: "SHADENET_SETS", toml: "sets", what: "extra staked sets to admit besides the record's: 0xcontract@deployBlock, comma-separated (one node, several canopies)", default: "", advanced: "SHADE_TREE_GROUP_CONTRACT, SHADE_TREE_FROM_BLOCKS" },
  { key: "members_file", env: "SHADENET_MEMBERS_FILE", toml: "members_file", what: "operator-owned members.json for the invited path", advanced: "SHADE_TREE_MEMBERS_FILE" },
  { key: "allow", env: "SHADENET_ALLOW", toml: "allow", what: "egress allow list, host:port patterns", default: "*:443", advanced: "SHADE_TREE_EGRESS_ALLOW" },
  { key: "deny", env: "SHADENET_DENY", toml: "deny", what: "egress deny list; deny wins", default: "", advanced: "SHADE_TREE_EGRESS_DENY" },
  { key: "weight", env: "SHADENET_WEIGHT", toml: "weight", what: "selection weight 1..1000 (lower = less traffic lands here)", default: 100, advanced: "SHADE_TREE_GW_WEIGHT" },
  { key: "region", env: "SHADENET_REGION", toml: "region", what: "coarse region bucket advertised: na sa eu af as oc aq unknown", default: "", advanced: "SHADE_TREE_GATEWAY_REGION" },
  { key: "metrics", env: "SHADENET_METRICS", toml: "metrics", what: "Prometheus port on loopback, or off", default: 9101, advanced: "SHADE_TREE_METRICS_PORT" },
  { key: "log", env: "SHADENET_LOG", toml: "log", what: "log format json | pretty | text, with an optional :level", default: "json:info", advanced: "SHADE_TREE_LOG_FORMAT, SHADE_TREE_LOG_LEVEL" },
  { key: "operator_key_file", env: "SHADENET_OPERATOR_KEY_FILE", toml: "operator_key_file", what: "file holding the staked operator key (stake-admission canopies)", advanced: "SHADE_TREE_GW_OPERATOR_KEY" },
  { key: "operator", env: "SHADENET_OPERATOR", toml: "operator", what: "operator address, with operator_sig instead of a key on the box", advanced: "SHADE_TREE_GW_OPERATOR" },
  { key: "operator_sig", env: "SHADENET_OPERATOR_SIG", toml: "operator_sig", what: "operator signature over operatorAuthMessage(onion, operator)", advanced: "SHADE_TREE_GW_OPERATOR_SIG" },
  { key: "pow", env: "SHADENET_POW", toml: "pow", what: "onion proof-of-work defense (needs a Tor built with the pow module)", default: false },
];

// ---- node.toml -------------------------------------------------------------------------
// A deliberately small TOML subset: `key = value` lines, optional `[node]` table, `#` comments,
// strings in double quotes, integers, true/false, and `["a", "b"]` string arrays. Anything else
// is an error with the line number, so a typo never silently becomes a default.
export function parseNodeToml(text) {
  const out = {};
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    if (/^\[[A-Za-z0-9_.-]+\]$/.test(line)) {
      if (line !== "[node]") throw new Error(`node.toml line ${i + 1}: only the [node] table is understood`);
      continue;
    }
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(line);
    if (!m) throw new Error(`node.toml line ${i + 1}: expected key = value`);
    const [, key, rhs] = m;
    let value;
    if (/^"([^"\\]|\\.)*"$/.test(rhs)) value = JSON.parse(rhs);
    else if (/^-?\d+$/.test(rhs)) value = Number(rhs);
    else if (rhs === "true" || rhs === "false") value = rhs === "true";
    else if (/^\[.*\]$/.test(rhs)) {
      try { value = JSON.parse(rhs); } catch { throw new Error(`node.toml line ${i + 1}: arrays hold double-quoted strings only`); }
      if (!value.every((v) => typeof v === "string")) throw new Error(`node.toml line ${i + 1}: arrays hold double-quoted strings only`);
      value = value.join(",");
    } else throw new Error(`node.toml line ${i + 1}: value must be a "string", integer, true/false or ["array"]`);
    out[key] = value;
  }
  return out;
}

// ---- knob resolution --------------------------------------------------------------------
// Returns { knobs, sources, errors }. `sources[key]` says where each value came from so `check`
// can print it. Errors are collected, not thrown, so the operator sees all of them at once.
export function resolveKnobs({ env = process.env, toml = {} } = {}) {
  const knobs = {}; const sources = {}; const errors = [];
  for (const k of KNOBS) {
    const fromEnv = env[k.env];
    if (fromEnv !== undefined && String(fromEnv).trim() !== "") { knobs[k.key] = String(fromEnv).trim(); sources[k.key] = `env ${k.env}`; }
    else if (toml[k.toml] !== undefined) { knobs[k.key] = toml[k.toml]; sources[k.key] = `node.toml ${k.toml}`; }
    else if (k.default !== undefined) { knobs[k.key] = k.default; sources[k.key] = "default"; }
  }
  if (!knobs.record) errors.push("record: set SHADENET_RECORD (the deployment record URL or path); nothing else is required");
  else if (!/^https:\/\//.test(knobs.record) && !/^(\/|\.|~)/.test(knobs.record)) errors.push(`record: must be an https:// URL or a file path (got ${knobs.record})`);
  const admit = String(knobs.admit).split(",").map((s) => s.trim()).filter(Boolean);
  if (!admit.length || !admit.every((a) => ["invited", "staked", "paid"].includes(a))) errors.push(`admit: must be a comma list of invited, staked, paid (got ${knobs.admit})`);
  if (admit.includes("invited") && !knobs.members_file) errors.push("admit: the invited path needs members_file (your own members.json)");
  if (knobs.members_file && !isAbsolute(String(knobs.members_file))) errors.push(`members_file: must be an absolute path (got ${knobs.members_file})`);
  for (const entry of parseSets(knobs.sets).errors) errors.push(`sets: ${entry}`);
  const weight = Number(knobs.weight);
  if (!Number.isInteger(weight) || weight < 1 || weight > 1000) errors.push(`weight: integer 1..1000 (got ${knobs.weight})`);
  if (knobs.region && !REGION_BUCKETS.has(String(knobs.region))) errors.push(`region: one of ${[...REGION_BUCKETS].join(" ")} (got ${knobs.region})`);
  const metrics = String(knobs.metrics);
  if (!(metrics === "off" || metrics === "0" || (/^\d+$/.test(metrics) && Number(metrics) >= 1 && Number(metrics) <= 65535))) errors.push(`metrics: a port 1..65535 or off (got ${knobs.metrics})`);
  const [fmt, lvl = "info"] = String(knobs.log).split(":");
  if (!["json", "pretty", "text"].includes(fmt)) errors.push(`log: json | pretty | text, optionally :debug|info|warn|error (got ${knobs.log})`);
  if (!["debug", "info", "warn", "error"].includes(lvl)) errors.push(`log: level must be debug, info, warn or error (got ${lvl})`);
  if (knobs.operator && !isEthAddress(String(knobs.operator))) errors.push("operator: not a 0x-prefixed 20-byte address");
  if (knobs.operator_sig && !/^0x[0-9a-fA-F]{130}$/.test(String(knobs.operator_sig).trim())) errors.push("operator_sig: not a 65-byte 0x-hex signature");
  if ((knobs.operator && !knobs.operator_sig) || (!knobs.operator && knobs.operator_sig)) errors.push("operator and operator_sig go together (or use operator_key_file)");
  if (knobs.operator_key_file && !isAbsolute(String(knobs.operator_key_file))) errors.push("operator_key_file: must be an absolute path");
  knobs.pow = knobs.pow === true || /^(1|true|yes|on)$/i.test(String(knobs.pow));
  return { knobs, sources, errors };
}

// `sets`: "0xContract@block,0xOther@block". The deploy block is required: an eth_getLogs scan
// from 0 against a public RPC is exactly the empty-page failure the rehearsal hit.
export function parseSets(spec) {
  const out = []; const errors = [];
  for (const raw of String(spec || "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^(0x[0-9a-fA-F]{40})(?:@(\d+))?$/.exec(raw);
    if (!m) { errors.push(`${raw}: expected 0x<contract>@<deployBlock>`); continue; }
    if (!m[2]) { errors.push(`${raw}: add @<deployBlock> (the block the set was deployed at; it is in that canopy's record)`); continue; }
    if (out.some((e) => e.contract.toLowerCase() === m[1].toLowerCase())) { errors.push(`${raw}: listed twice`); continue; }
    out.push({ contract: m[1], deployBlock: Number(m[2]) });
  }
  return { sets: out, errors };
}

// Read node.toml from the state dir (if any) and resolve. Throws only on an unreadable toml.
export function loadNodeConfig({ env = process.env, stateDir } = {}) {
  const state = stateDir || (env.SHADENET_STATE && String(env.SHADENET_STATE).trim()) || DEFAULT_STATE_DIR;
  const tomlPath = join(state, "node.toml");
  const toml = existsSync(tomlPath) ? parseNodeToml(readFileSync(tomlPath, "utf8")) : {};
  const res = resolveKnobs({ env, toml });
  res.knobs.state = resolve(String(res.knobs.state || state));
  res.tomlPath = existsSync(tomlPath) ? tomlPath : null;
  return res;
}

// ---- the record -------------------------------------------------------------------------
// { ok, record, errors } for a parsed record a node may join. Status live or staging, protocol
// range covering v4, at least one Elder, a staked root with a contract and an RPC.
export function checkJoinableRecord(record) {
  const errors = [];
  const v = validateDeploymentRecord(record);
  if (!v.ok) for (const e of v.errors) errors.push(`${e.field}: ${e.problem}`);
  if (!["live", "staging"].includes(record?.status)) errors.push(`status: ${record?.status}; only live or staging records can be joined`);
  if (!(record?.protocol?.min <= 4 && record?.protocol?.max >= 4)) errors.push("protocol: this node speaks v4; the record does not include it");
  if (!eldersOf(record).length) errors.push("elders: the record names no Elder Tree to announce to");
  const staked = record?.admission?.roots?.staked;
  if (!staked?.contract) errors.push("admission.roots.staked.contract: missing; a joinable record names the staked set");
  if (!rpcUrlsOf(staked || {}).length) errors.push("admission.roots.staked.rpcUrl(s): missing");
  return { ok: errors.length === 0, errors };
}

// ---- derived environment ---------------------------------------------------------------
// knobs + record -> the SHADE_TREE_* env for the gateway and the heartbeat. `explicit` is the
// operator's own SHADE_TREE_* (advanced layer) and always wins. Secrets are NOT read here: the
// operator key file is turned into SHADE_TREE_GW_OPERATOR_KEY by the supervisor at spawn time.
export function deriveNodeEnv({ knobs, record, explicit = {}, hsDir, torPort = TOR_SOCKS_PORT, gatewayPort = GATEWAY_PORT }) {
  const fromRecord = envDefaultsFromRecords({ dir: "", deployment: { ...record, status: "live" }, contracts: null, bootnode: null });
  // Client-only defaults the gateway must not inherit.
  delete fromRecord.SHADE_TREE_LEAF_SOURCE; delete fromRecord.SHADE_TREE_LIMIT;
  const arts = (record.artifacts?.accepted || []).map((a) => `${a.id}=${a.verificationKeyPath}`);
  const [fmt, lvl = "info"] = String(knobs.log).split(":");
  const metricsOff = String(knobs.metrics) === "off" || String(knobs.metrics) === "0";
  const out = {
    ...fromRecord,
    SHADE_TREE_REF: record.services?.node?.commit || "",
    SHADE_TREE_ADMIT: String(knobs.admit),
    SHADE_TREE_EGRESS_ALLOW: String(knobs.allow),
    SHADE_TREE_GW_WEIGHT: String(knobs.weight),
    SHADE_TREE_LOG_FORMAT: fmt,
    SHADE_TREE_LOG_LEVEL: lvl,
    SHADE_TREE_BANNER: "never",
    SHADE_TREE_METRICS_PORT: metricsOff ? "0" : String(knobs.metrics),
    SHADE_TREE_HEARTBEAT_METRICS_PORT: metricsOff ? "0" : String(Number(knobs.metrics) + 2),
    SHADE_TREE_GATEWAY_PORT: String(gatewayPort),
    SHADE_TREE_TOR_HOST: "127.0.0.1",
    SHADE_TREE_TOR_PORT: String(torPort),
    SHADE_TREE_GW_IDENTITY: join(hsDir, "identity.local.json"),
    SHADE_TREE_SPENT_STATE_FILE: join(knobs.state, "spent-set.local.json"),
    SHADE_TREE_RELAY_TELEMETRY_STATE: join(knobs.state, "relay-telemetry.local.json"),
    SHADE_TREE_RELAY_REPORT_STATE: join(knobs.state, "relay-report.local.json"),
  };
  if (arts.length) out.SHADE_TREE_ZK_ARTIFACTS = arts.join(",");
  // Extra sets: the record's set stays first; every set carries its own scan start.
  const extra = parseSets(knobs.sets).sets.filter((e) => e.contract.toLowerCase() !== String(fromRecord.SHADE_TREE_GROUP_CONTRACT || "").toLowerCase());
  if (extra.length && fromRecord.SHADE_TREE_GROUP_CONTRACT) {
    const recordBlock = record.admission.roots.staked.deployBlock;
    const all = [{ contract: fromRecord.SHADE_TREE_GROUP_CONTRACT, deployBlock: recordBlock }, ...extra];
    out.SHADE_TREE_GROUP_CONTRACT = all.map((e) => e.contract).join(",");
    out.SHADE_TREE_FROM_BLOCKS = all.map((e) => `${e.contract}=${e.deployBlock}`).join(",");
    out.SHADE_TREE_FROM_BLOCK = "0x" + Math.min(...all.map((e) => e.deployBlock)).toString(16);
  }
  if (String(knobs.deny || "")) out.SHADE_TREE_EGRESS_DENY = String(knobs.deny);
  if (knobs.region) out.SHADE_TREE_GATEWAY_REGION = String(knobs.region);
  if (knobs.members_file) out.SHADE_TREE_MEMBERS_FILE = String(knobs.members_file);
  if (knobs.operator && knobs.operator_sig) { out.SHADE_TREE_GW_OPERATOR = String(knobs.operator); out.SHADE_TREE_GW_OPERATOR_SIG = String(knobs.operator_sig).trim(); }
  for (const [k, v] of Object.entries(explicit)) if (k.startsWith("SHADE_TREE_") && v !== undefined && String(v).trim() !== "") out[k] = String(v);
  return out;
}

// The operator key file: one line, 64 hex (0x optional). Returned trimmed; never logged.
export function readOperatorKeyFile(path) {
  const st = statSync(path);
  if (st.mode & 0o077) throw new Error(`${path}: must be readable by the owner only (chmod 600)`);
  const key = readFileSync(path, "utf8").trim();
  if (!isPrivHex(key)) throw new Error(`${path}: not a 32-byte hex private key (64 hex, 0x optional)`);
  return key;
}

// ---- torrc ----------------------------------------------------------------------------
// torLevel: "notice" (default) or "info" (SHADENET_TOR_LOG=info) for the file log at <state>/tor.log,
// kept so an operator can read Tor's own account of descriptor uploads and circuit failures.
export function renderTorrc({ stateDir, hsDir, gatewayPort = GATEWAY_PORT, socksPort = TOR_SOCKS_PORT, pow = false, maxStreams = 512, fleetTallyPort = null, torLevel = "notice" }) {
  const level = torLevel === "info" ? "info" : "notice";
  const lines = [
    "# shadenet-node: written at every start; edit node.toml or SHADENET_*, not this file.",
    `DataDirectory ${join(stateDir, "tor")}`,
    `SocksPort 127.0.0.1:${socksPort}`,
    "ClientOnly 0",
    "Log notice stdout",
    `Log ${level} file ${join(stateDir, "tor.log")}`,
    "AvoidDiskWrites 1",
    `HiddenServiceDir ${hsDir}`,
    `HiddenServicePort 80 127.0.0.1:${gatewayPort}`,
  ];
  if (fleetTallyPort) lines.push(`HiddenServicePort ${fleetTallyPort} 127.0.0.1:${fleetTallyPort}`);
  lines.push(`HiddenServicePoWDefensesEnabled ${pow ? 1 : 0}`, `HiddenServiceMaxStreams ${maxStreams}`, "HiddenServiceMaxStreamsCloseCircuit 1");
  return lines.join("\n") + "\n";
}

// Redact for printing: keys and signatures show their first six characters only.
export function redactEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) out[k] = /(_KEY|_SIG|_TOKEN|_SECRET)$/.test(k) && v ? `${String(v).slice(0, 6)}…` : v;
  return out;
}
