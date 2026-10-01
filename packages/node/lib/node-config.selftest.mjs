// Selftest for the operator front door's pure half: node.toml parsing, knob resolution and its
// error list, the joinable-record gate, the derived SHADE_TREE_* env and the torrc.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseNodeToml, resolveKnobs, checkJoinableRecord, deriveNodeEnv, renderTorrc, redactEnv, parseSets, KNOBS } from "./node-config.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "../../..");
const staging = JSON.parse(readFileSync(join(ROOT, "network/sepolia-staging/deployment.json"), "utf8"));
const production = JSON.parse(readFileSync(join(ROOT, "network/sepolia/deployment.json"), "utf8"));

// node.toml: the small subset, with line-numbered errors.
assert.deepEqual(parseNodeToml(`# comment\n[node]\nrecord = "https://x/y.json"\nweight = 40\npow = false\nallow = ["*:443", "api.example.com:8443"]\n`),
  { record: "https://x/y.json", weight: 40, pow: false, allow: "*:443,api.example.com:8443" });
assert.throws(() => parseNodeToml("[tor]\nx = 1"), /only the \[node\] table/);
assert.throws(() => parseNodeToml("weight = 10 apples"), /line 1/);
assert.throws(() => parseNodeToml("allow = [1, 2]"), /double-quoted strings/);

// Knobs: env beats toml beats default; every error is collected, not thrown.
{
  const { knobs, sources, errors } = resolveKnobs({ env: { SHADENET_RECORD: "https://r/x.json", SHADENET_WEIGHT: "250" }, toml: { weight: 5, region: "eu" } });
  assert.equal(errors.length, 0, errors.join("; "));
  assert.equal(knobs.weight, "250"); assert.equal(sources.weight, "env SHADENET_WEIGHT");
  assert.equal(knobs.region, "eu"); assert.equal(sources.region, "node.toml region");
  assert.equal(knobs.admit, "staked"); assert.equal(sources.admit, "default");
  assert.equal(knobs.pow, false);
}
{
  const { errors } = resolveKnobs({ env: { SHADENET_ADMIT: "invited", SHADENET_WEIGHT: "0", SHADENET_REGION: "mars", SHADENET_METRICS: "70000", SHADENET_LOG: "xml", SHADENET_OPERATOR: "0x12" } });
  const text = errors.join("\n");
  for (const needle of ["record:", "invited path needs members_file", "weight:", "region:", "metrics:", "log:", "operator:", "operator and operator_sig go together"]) assert.match(text, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}
assert.equal(resolveKnobs({ env: { SHADENET_RECORD: "ftp://x" } }).errors.some((e) => /https:\/\/ URL or a file path/.test(e)), true);
assert.equal(KNOBS.length, 15, "the knob list is the documented surface; update CONFIG.md when it changes");

// The record gate: both committed records are joinable; a retired or pre-v4 one is not.
assert.deepEqual(checkJoinableRecord(staging), { ok: true, errors: [] });
assert.deepEqual(checkJoinableRecord(production), { ok: true, errors: [] });
assert.match(checkJoinableRecord({ ...production, status: "retired" }).errors.join(), /only live or staging/);
assert.match(checkJoinableRecord({ ...production, protocol: { min: 5, max: 5 } }).errors.join(), /speaks v4/);

// Derived env: record-driven values, every Elder, the RPC failover list, knobs mapped, secrets absent,
// an explicit SHADE_TREE_* (advanced layer) wins, client-only defaults dropped.
{
  const { knobs } = resolveKnobs({ env: { SHADENET_RECORD: "https://r/x.json", SHADENET_DENY: "*.internal:443", SHADENET_REGION: "eu", SHADENET_LOG: "pretty:debug", SHADENET_METRICS: "off", SHADENET_OPERATOR: "0x16c9F91c38669850f192fbfBbd22DE7946b30b63", SHADENET_OPERATOR_SIG: "0x" + "ab".repeat(65) } });
  knobs.state = "/state";
  const env = deriveNodeEnv({ knobs, record: production, explicit: { SHADE_TREE_GW_WEIGHT: "7", HOME: "/x" }, hsDir: "/state/hs-gateway" });
  assert.equal(env.SHADE_TREE_GROUP_CONTRACT, production.admission.roots.staked.contract);
  assert.equal(env.SHADE_TREE_BOOTNODE_ONIONS.split(",").length, production.elders.length);
  assert.equal(env.SHADE_TREE_RPC_URL, production.admission.roots.staked.rpcUrls.join(","));
  assert.equal(env.SHADE_TREE_ZK_ARTIFACTS, production.artifacts.accepted.map((a) => `${a.id}=${a.verificationKeyPath}`).join(","));
  assert.equal(env.SHADE_TREE_SESSION_TICKETS, production.sessionTickets === true ? "1" : undefined);
  assert.equal(env.SHADE_TREE_REF, production.services.node.commit);
  assert.equal(env.SHADE_TREE_EGRESS_DENY, "*.internal:443");
  assert.equal(env.SHADE_TREE_GATEWAY_REGION, "eu");
  assert.equal(env.SHADE_TREE_LOG_FORMAT, "pretty"); assert.equal(env.SHADE_TREE_LOG_LEVEL, "debug");
  assert.equal(env.SHADE_TREE_METRICS_PORT, "0"); assert.equal(env.SHADE_TREE_HEARTBEAT_METRICS_PORT, "0");
  assert.equal(env.SHADE_TREE_GW_WEIGHT, "7", "an explicit SHADE_TREE_* wins over the knob");
  assert.equal(env.HOME, undefined, "only SHADE_TREE_* passes through from the explicit layer");
  assert.equal(env.SHADE_TREE_GW_OPERATOR, "0x16c9F91c38669850f192fbfBbd22DE7946b30b63");
  assert.equal(env.SHADE_TREE_GW_OPERATOR_KEY, undefined, "the key file is never read by the pure layer");
  assert.equal(env.SHADE_TREE_LEAF_SOURCE, undefined); assert.equal(env.SHADE_TREE_LIMIT, undefined);
  assert.equal(env.SHADE_TREE_GW_IDENTITY, "/state/hs-gateway/identity.local.json");
  assert.equal(env.SHADE_TREE_SPENT_STATE_FILE, "/state/spent-set.local.json");
  assert.equal(redactEnv(env).SHADE_TREE_GW_OPERATOR_SIG, "0xabab…");
}

// sets: extra staked sets ride along with the record's, each with its own scan start.
{
  assert.deepEqual(parseSets("0xf117FDEA83ac57d15D9394A2B56873C32d227B7E@11803707"), { sets: [{ contract: "0xf117FDEA83ac57d15D9394A2B56873C32d227B7E", deployBlock: 11803707 }], errors: [] });
  assert.match(parseSets("0xf117FDEA83ac57d15D9394A2B56873C32d227B7E").errors.join(), /add @<deployBlock>/);
  assert.match(parseSets("nope").errors.join(), /expected 0x<contract>@<deployBlock>/);
  assert.match(resolveKnobs({ env: { SHADENET_RECORD: "https://r/x.json", SHADENET_SETS: "0x12" } }).errors.join(), /^sets:/m);
  const { knobs } = resolveKnobs({ env: { SHADENET_RECORD: "https://r/x.json", SHADENET_SETS: `${staging.admission.roots.staked.contract}@${staging.admission.roots.staked.deployBlock}` } });
  knobs.state = "/state";
  const env = deriveNodeEnv({ knobs, record: production, hsDir: "/state/hs-gateway" });
  const prod = production.admission.roots.staked;
  assert.equal(env.SHADE_TREE_GROUP_CONTRACT, `${prod.contract},${staging.admission.roots.staked.contract}`, "the record's set stays first");
  assert.equal(env.SHADE_TREE_FROM_BLOCKS, `${prod.contract}=${prod.deployBlock},${staging.admission.roots.staked.contract}=${staging.admission.roots.staked.deployBlock}`);
  assert.equal(env.SHADE_TREE_FROM_BLOCK, "0x" + Math.min(prod.deployBlock, staging.admission.roots.staked.deployBlock).toString(16));
  const same = deriveNodeEnv({ knobs: { ...knobs, sets: `${prod.contract}@${prod.deployBlock}` }, record: production, hsDir: "/state/hs-gateway" });
  assert.equal(same.SHADE_TREE_GROUP_CONTRACT, prod.contract, "listing the record's own set changes nothing");
}

// torrc: one onion service on the node port, PoW only when asked, Tor state under the state dir.
{
  const t = renderTorrc({ stateDir: "/state", hsDir: "/state/hs-gateway", pow: false });
  assert.match(t, /^DataDirectory \/state\/tor$/m);
  assert.match(t, /^SocksPort 127\.0\.0\.1:9050$/m);
  assert.match(t, /^HiddenServiceDir \/state\/hs-gateway$/m);
  assert.match(t, /^HiddenServicePort 80 127\.0\.0\.1:8443$/m);
  assert.match(t, /^HiddenServicePoWDefensesEnabled 0$/m);
  assert.match(renderTorrc({ stateDir: "/s", hsDir: "/s/h", pow: true }), /PoWDefensesEnabled 1/);
  assert.doesNotMatch(t, /0\.0\.0\.0/, "nothing listens off loopback");
}

console.log("PASS: shadenet-node config (node.toml, knobs, record gate, derived env, torrc)");
