// Offline proof of what bootnode/deploy/bootstrap.sh RENDERS, without root, apt, tor, or systemd.
// bootstrap.sh has a render mode (SHADE_TREE_RENDER_ONLY=<dir> / --render <dir>) that runs the SAME
// torrc + unit renderers the live path uses and writes them under <dir>/etc/... with fixed
// placeholder onions, so the output is deterministic and can be byte-compared.
//
// What is asserted:
//   1. DEFAULT (no tunables) is frozen against bootnode/deploy/golden/default/** — any drift in
//      the torrc include or the three units is a deliberate, reviewed change (regenerate with
//      SHADE_TREE_UPDATE_GOLDEN=1 node bootnode/deploy/bootstrap.selftest.mjs and commit the diff).
//   2. SHADE_TREE_ENABLE_POW=1 / =0 (GAP-3): valid torrc in both states; the PoW line is a PER-SERVICE
//      option and must sit inside each HiddenServiceDir block right after its HiddenServicePort;
//      nothing else changes; a garbage value is rejected before anything would be installed.
//   3. SHADE_TREE_BOOTNODE_ONION=<onion> (GAP-6, gateway-only): NO shade-tree-bootnode unit, NO bootnode HS
//      block, the heartbeat announces to the REMOTE onion (with/without .onion suffix accepted),
//      the gateway unit is byte-identical to the default one, a malformed onion is rejected.
//   3b. SHADE_TREE_ELDER_ONLY=1: ONLY the Elder hidden service + unit are rendered; no gateway
//      identity, gateway unit, or heartbeat exists, and incompatible gateway tunables fail closed.
//   4. SHADE_TREE_GATEWAY_REGION passthrough into the heartbeat unit; invalid bucket rejected.
//   5. Nothing outside <dir> is touched (the render dir is the only side effect).
//   6. SHADE_TREE_HELIOS=1 (T-DEV-9b, opt-in): a 4th unit shade-tree-helios.service (hardened, loopback-only,
//      endpoints via env not argv, W^X on) and the gateway unit ordered after it carrying
//      SHADE_TREE_ROOT_PROVIDER=light + SHADE_TREE_HELIOS_RPC_URL + SHADE_TREE_RPC_URL + SHADE_TREE_GROUP_CONTRACT; the
//      other files byte-identical to the default; missing/invalid companions rejected up front;
//      SHADE_TREE_HELIOS=0 == default (golden unchanged, i.e. the sidecar is opt-in).
//
//   7. SHADE_TREE_REGISTRAR=1 (T-FEAT-7, opt-in): a shade-tree-registrar.service (hardened, loopback, operator
//      key NOT rendered), an EXTRA HiddenServicePort inside the bootnode HS block (same onion), the
//      bootnode unit advertising the offer (SHADE_TREE_REGISTRAR_ADVERTISE=1 + SHADE_TREE_PAY_*), everything
//      else byte-identical; companions validated up front; incompatible with gateway-only mode;
//      SHADE_TREE_REGISTRAR=0 == default (golden unchanged).
//   8. SHADE_TREE_FROM_BLOCK / SHADE_TREE_FROM_BLOCKS (eth_getLogs start blocks, fleet crash-loop 2026-08-17):
//      passed verbatim into the gateway unit when set, validated up front, everything else
//      byte-identical; unset == default (golden unchanged).
//   9. SHADE_TREE_ADMIT (T-FEAT-9, docs/adr/0008): DEFAULT `invited` (the golden gateway + heartbeat units
//      carry Environment=SHADE_TREE_ADMIT=invited -- regenerated for this); staked/paid opt-in renders the
//      contracts + RPC into the gateway unit and is fail-closed on a missing companion; canonical
//      order; SHADE_TREE_PAY_PROTOCOLS subset normalized into registrar + both adverts; SHADE_TREE_REGISTRAR=1
//      requires `paid` admitted; a GATEWAY-ONLY box may run the registrar on the GATEWAY onion.
//  10. SHADE_TREE_ZK_ARTIFACTS: an explicit accepted vkey set is rendered into the gateway and
//      heartbeat (so verification and signed capability advertisement agree); the optional legacy
//      id is gateway-only; malformed ids/paths and a legacy id without a set fail closed.
//  11. SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES: the 40 MiB protocol default is pinned in the gateway
//      unit; a bounded non-negative override is passed verbatim and malformed values fail closed.
//
//   node bootnode/deploy/bootstrap.selftest.mjs
//
// Exit 0 = every check passed; nonzero = a check failed (prints which). Needs bash on PATH.

import { spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile, readdir, mkdir, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "bootstrap.sh");
const GOLDEN = join(HERE, "golden", "default");

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";

// Run bootstrap.sh in render mode with a MINIMAL env (only PATH + HOME + our tunables), so
// nothing from the developer's shell (e.g. a stray SHADE_TREE_ENABLE_POW) leaks into the render.
function render(work, name, env = {}, args = []) {
  const out = join(work, name);
  const r = spawnSync("bash", [SCRIPT, ...args], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME ?? "/", SHADE_TREE_RENDER_ONLY: args.length ? "" : out, ...env },
    encoding: "utf8",
  });
  return { out, status: r.status, stdout: r.stdout, stderr: r.stderr };
}

async function listFiles(root) {
  const acc = [];
  async function walk(d) {
    for (const e of await readdir(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p); else acc.push(relative(root, p));
    }
  }
  await walk(root);
  return acc.sort();
}

async function readAll(root) {
  const files = await listFiles(root);
  const m = new Map();
  for (const f of files) m.set(f, await readFile(join(root, f), "utf8"));
  return m;
}

// Parse a torrc include into HS blocks: [{dir, lines:[...]}]. Lines before the first
// HiddenServiceDir (comments) are dropped. Comments inside blocks are dropped too.
function hsBlocks(torrc) {
  const blocks = [];
  for (const raw of torrc.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("HiddenServiceDir ")) blocks.push({ dir: line.slice("HiddenServiceDir ".length), lines: [] });
    else if (blocks.length) blocks[blocks.length - 1].lines.push(line);
    else throw new Error(`torrc option before any HiddenServiceDir: ${line}`);
  }
  return blocks;
}

function unitEnv(unit, key) {
  const m = unit.match(new RegExp(`^Environment=${key}=(.*)$`, "m"));
  return m ? m[1] : null;
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-bootstrap-render-"));
  try {
    console.log("client handoff template:");
    const bootstrapSource = await readFile(SCRIPT, "utf8");
    const deployReadme = await readFile(join(HERE, "README.md"), "utf8");
    ok(!/shade-tree client\b/.test(bootstrapSource) && !/--secret\s+<member-hex>/.test(bootstrapSource), "bootstrap never emits the legacy client or argv-secret form");
    ok(/read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(bootstrapSource) && /shade-tree proxy/.test(bootstrapSource), "bootstrap handoff loads the bearer secret through a hidden read before starting the Proxy");
    ok(/SHADE_TREE_MEMBERS_FILE=\/path\/from-operator\/members\.json/.test(bootstrapSource) && /--limit "\\\$SHADE_TREE_LIMIT"/.test(bootstrapSource), "bootstrap handoff requires the invited member file and explicit operator tier");
    ok((bootstrapSource.match(/\$\(print_client_setup "\$BN_ONION" "\$SIGNER"\)/g) || []).length === 2, "full-Grove and gateway-only summaries share the safe handoff template");
    ok(/MEMBERS_DEST="\/etc\/shade-tree\/members\.json"/.test(bootstrapSource) && /install -o root -g "\$RUN_USER" -m 0640 "\$MEMBERS_SOURCE" "\$MEMBERS_DEST"/.test(bootstrapSource), "live bootstrap installs the invited admission root as root-owned and node-readable");
    ok(!/chown "\$RUN_USER:\$RUN_USER" "\$MEMBERS_DEST"/.test(bootstrapSource) && /ProtectSystem=strict/.test(bootstrapSource) && /ReadWritePaths=\$\{SHADE_TREE_DIR\}\/deploy-state/.test(bootstrapSource), "the node cannot make its trusted member set service-writable through the systemd sandbox");
    ok(/else\s+# An omitted peer list is the off switch[\s\S]*?rm -f "\$FLEET_TALLY_ENV_FILE"\s+fi/.test(bootstrapSource), "disabling the optional fleet tally removes its stale bearer-token file");
    ok(/^systemctl restart \$UNITS$/m.test(bootstrapSource) && /^  systemctl restart shade-tree-heartbeat$/m.test(bootstrapSource), "an idempotent re-run restarts every rendered unit (Elder, gateway, heartbeat) so new configuration takes effect");
    ok(/mktemp \/etc\/shade-tree\/\.fleet-tally\.env\.XXXXXX/.test(bootstrapSource) && /mv -f "\$FLEET_TALLY_ENV_TMP" "\$FLEET_TALLY_ENV_FILE"/.test(bootstrapSource), "fleet tally token rotation replaces the root-only environment file atomically");
    ok(/safe `shade-tree proxy` template/.test(deployReadme) && /exact\s+enrolled tier/.test(deployReadme) && !/shade-tree client/.test(deployReadme), "deploy README promises a template and names the operator values it cannot invent");

    // ---------------------------------------------------------------- 1. default == golden
    console.log("default render (golden):");
    const def = render(work, "default");
    ok(def.status === 0, `render exits 0 (${(def.stdout || "").trim()})`);
    const got = await readAll(def.out);
    ok(
      [...got.keys()].join(",") === "etc/systemd/system/shade-tree-bootnode.service,etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/tor/torrc.d-shade-tree",
      `emits exactly torrc + 3 units (${[...got.keys()].join(", ")})`,
    );
    if (process.env.SHADE_TREE_UPDATE_GOLDEN === "1") {
      await rm(GOLDEN, { recursive: true, force: true });
      for (const [f, body] of got) { await mkdir(dirname(join(GOLDEN, f)), { recursive: true }); await writeFile(join(GOLDEN, f), body); }
      console.log(`  (golden regenerated at ${GOLDEN})`);
    }
    const want = await readAll(GOLDEN);
    ok(want.size === got.size, `golden has the same file set (${want.size} files)`);
    for (const [f, body] of want) ok(got.get(f) === body, `byte-identical to golden: ${f}`);
    // Sanity on the golden itself (so a bad regeneration cannot freeze a broken render).
    const torrc = got.get("etc/tor/torrc.d-shade-tree");
    const blocks = hsBlocks(torrc);
    ok(blocks.length === 2 && blocks[0].dir === "/var/lib/tor/shade-tree-bootnode" && blocks[1].dir === "/var/lib/tor/shade-tree-gateway", "default torrc: bootnode + gateway HS blocks, in that order");
    for (const b of blocks) {
      ok(b.lines[0]?.startsWith("HiddenServicePort 80 127.0.0.1:") && b.lines[1] === "HiddenServicePoWDefensesEnabled 0" && b.lines.length === 2,
        `${b.dir}: HiddenServicePort then HiddenServicePoWDefensesEnabled 0 (PoW default OFF), nothing else`);
    }
    ok(blocks[0].lines[0].endsWith(":8877") && blocks[1].lines[0].endsWith(":8443"), "default ports 8877 (bootnode) / 8443 (gateway)");
    const hbDef = got.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(unitEnv(hbDef, "SHADE_TREE_BOOTNODE_ONION")?.endsWith(".onion") && /^After=shade-tree-bootnode\.service tor\.service$/m.test(hbDef), "default heartbeat -> LOCAL bootnode, ordered after shade-tree-bootnode.service");
    ok(unitEnv(hbDef, "SHADE_TREE_GATEWAY_REGION") === null, "default heartbeat advertises no region");
    const elderDef = got.get("etc/systemd/system/shade-tree-bootnode.service");
    const nodeDef = got.get("etc/systemd/system/shade-tree-gateway.service");
    ok(unitEnv(nodeDef, "SHADE_TREE_GATEWAY_PORT") === "8443", "gateway unit and Tor backend share the default node port");
    ok(unitEnv(nodeDef, "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES") === "41943040", "default gateway unit explicitly pins the 40 MiB protocol parameter");
    ok(unitEnv(nodeDef, "SHADE_TREE_EPOCH_SECONDS") === "120" && unitEnv(hbDef, "SHADE_TREE_EPOCH_SECONDS") === "120", "gateway and heartbeat share the fixed epoch");
    ok(unitEnv(nodeDef, "SHADE_TREE_TIERS") === "8" && unitEnv(hbDef, "SHADE_TREE_TIERS") === "8", "gateway and heartbeat share the admitted tier table");
    ok(unitEnv(nodeDef, "SHADE_TREE_ROOT_FRESHNESS_SECONDS") === "120", "gateway pins a wall-clock root freshness bound");
    const publicRate = render(work, "public-rate", { SHADE_TREE_EPOCH_SECONDS: "60", SHADE_TREE_TIERS: "1,8", SHADE_TREE_ROOT_FRESHNESS_SECONDS: "60" });
    const publicRateGateway = await readFile(join(publicRate.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    const publicRateHeartbeat = await readFile(join(publicRate.out, "etc/systemd/system/shade-tree-heartbeat.service"), "utf8");
    ok(publicRate.status === 0 && [publicRateGateway, publicRateHeartbeat].every((unit) => unitEnv(unit, "SHADE_TREE_EPOCH_SECONDS") === "60" && unitEnv(unit, "SHADE_TREE_TIERS") === "1,8"), "public 60-second tier-1 policy is rendered identically into enforcement and advertisement");
    const payloadOverride = render(work, "payload-override", { SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES: "1048576" });
    const payloadOverrideGateway = await readFile(join(payloadOverride.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    ok(payloadOverride.status === 0 && unitEnv(payloadOverrideGateway, "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES") === "1048576", "payload ceiling override is rendered verbatim");
    for (const [value, re] of [
      ["-1", /SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES must be an integer/],
      ["40MiB", /SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES must be an integer/],
      ["9007199254740992", /SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES must be an integer/],
    ]) {
      const bad = render(work, "payload-bad", { SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES: value });
      ok(bad.status !== 0 && re.test(bad.stderr), `bad payload ceiling rejected up front: ${JSON.stringify(value)}`);
    }
    for (const [key, value] of [["SHADE_TREE_EPOCH_SECONDS", "0"], ["SHADE_TREE_ROOT_FRESHNESS_SECONDS", "nope"], ["SHADE_TREE_TIERS", "1,,8"]]) {
      const bad = render(work, `rate-bad-${key}`, { [key]: value });
      ok(bad.status !== 0 && bad.stderr.includes(key), `bad public rate parameter rejected up front: ${key}=${value}`);
    }
    ok(unitEnv(elderDef, "SHADE_TREE_METRICS_PORT") === "9100" && unitEnv(nodeDef, "SHADE_TREE_METRICS_PORT") === "9101" && unitEnv(hbDef, "SHADE_TREE_HEARTBEAT_METRICS_PORT") === "9103", "default operator metrics use distinct loopback ports for Elder, Node, and heartbeat");
    ok([elderDef, nodeDef, hbDef].every((u) => unitEnv(u, "SHADE_TREE_LOG_LEVEL") === "info" && unitEnv(u, "SHADE_TREE_LOG_FORMAT") === "json" && unitEnv(u, "SHADE_TREE_BANNER") === "never"), "systemd defaults to structured info logs without terminal art");
    for (const f of got.keys()) if (f.endsWith(".service")) {
      const u = got.get(f);
      ok(/^NoNewPrivileges=true$/m.test(u) && /^ProtectSystem=strict$/m.test(u) && /^CapabilityBoundingSet=$/m.test(u) && /^SystemCallFilter=@system-service$/m.test(u), `${f}: sandbox lines present (T-DEPLOY-4)`);
    }

    // ---------------------------------------------------------------- 2. PoW toggle
    console.log("SHADE_TREE_ENABLE_POW (GAP-3):");
    const powOn = render(work, "pow-on", { SHADE_TREE_ENABLE_POW: "1" });
    ok(powOn.status === 0, "SHADE_TREE_ENABLE_POW=1 renders");
    const onT = await readFile(join(powOn.out, "etc/tor/torrc.d-shade-tree"), "utf8");
    const onBlocks = hsBlocks(onT);
    ok(onBlocks.length === 2 && onBlocks.every((b) => b.lines[0].startsWith("HiddenServicePort ") && b.lines[1] === "HiddenServicePoWDefensesEnabled 1" && b.lines.length === 2),
      "pow=1: each HS block = HiddenServicePort then HiddenServicePoWDefensesEnabled 1 (per-service option placement)");
    const strip = (s) => s.split("\n").filter((l) => !l.startsWith("#") && !l.startsWith("HiddenServicePoWDefensesEnabled")).join("\n");
    ok(strip(onT) === strip(torrc), "pow=1 vs default: only the PoW lines (and the comment) differ");
    const onUnits = await readAll(powOn.out);
    for (const f of got.keys()) if (f.endsWith(".service")) ok(onUnits.get(f) === got.get(f), `pow=1 leaves ${f} byte-identical`);
    for (const alias of ["true", "yes", "on"]) {
      const r = render(work, `pow-${alias}`, { SHADE_TREE_ENABLE_POW: alias });
      ok(r.status === 0 && (await readFile(join(r.out, "etc/tor/torrc.d-shade-tree"), "utf8")) === onT, `SHADE_TREE_ENABLE_POW=${alias} == 1`);
    }
    const powOff = render(work, "pow-off", { SHADE_TREE_ENABLE_POW: "0" });
    ok(powOff.status === 0 && (await readFile(join(powOff.out, "etc/tor/torrc.d-shade-tree"), "utf8")) === torrc, "SHADE_TREE_ENABLE_POW=0 == default (explicit off is the default)");
    for (const alias of ["false", "no", "off"]) {
      const r = render(work, `pow-${alias}`, { SHADE_TREE_ENABLE_POW: alias });
      ok(r.status === 0 && (await readFile(join(r.out, "etc/tor/torrc.d-shade-tree"), "utf8")) === torrc, `SHADE_TREE_ENABLE_POW=${alias} == 0`);
    }
    const powBad = render(work, "pow-bad", { SHADE_TREE_ENABLE_POW: "maybe" });
    ok(powBad.status !== 0 && /SHADE_TREE_ENABLE_POW must be 1 or 0/.test(powBad.stderr), "SHADE_TREE_ENABLE_POW=maybe is rejected up front");
    ok(!(await stat(powBad.out).catch(() => null)), "rejected render writes nothing");

    // ---------------------------------------------------------------- 3. gateway-only mode
    console.log("SHADE_TREE_BOOTNODE_ONION gateway-only (GAP-6):");
    const gw = render(work, "gw-only", { SHADE_TREE_BOOTNODE_ONION: `${ONION}.onion` });
    ok(gw.status === 0 && /gateway-only/.test(gw.stdout), `gateway-only renders (${(gw.stdout || "").trim()})`);
    const gwFiles = await readAll(gw.out);
    ok([...gwFiles.keys()].join(",") === "etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/tor/torrc.d-shade-tree",
      `emits torrc + gateway + heartbeat ONLY (${[...gwFiles.keys()].join(", ")})`);
    const gwBlocks = hsBlocks(gwFiles.get("etc/tor/torrc.d-shade-tree"));
    ok(gwBlocks.length === 1 && gwBlocks[0].dir === "/var/lib/tor/shade-tree-gateway", "torrc: gateway HS block only (no bootnode HS)");
    ok(!/shade-tree-bootnode/.test(gwFiles.get("etc/tor/torrc.d-shade-tree").split("\n").filter((l) => !l.startsWith("#")).join("\n")), "torrc: no bootnode dir anywhere");
    ok(gwBlocks[0].lines[0] === "HiddenServicePort 80 127.0.0.1:8443" && gwBlocks[0].lines[1] === "HiddenServicePoWDefensesEnabled 0", "gateway block: port then PoW (default off)");
    ok(gwFiles.get("etc/systemd/system/shade-tree-gateway.service") === got.get("etc/systemd/system/shade-tree-gateway.service"), "gateway unit byte-identical to the default one");
    const hb = gwFiles.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(unitEnv(hb, "SHADE_TREE_BOOTNODE_ONION") === `${ONION}.onion`, "heartbeat announces to the REMOTE bootnode onion");
    ok(!/shade-tree-bootnode\.service/.test(hb) && /^After=network-online\.target tor\.service$/m.test(hb), "heartbeat no longer ordered after a (non-existent) local shade-tree-bootnode unit");
    ok(unitEnv(hb, "SHADE_TREE_GW_IDENTITY") === unitEnv(hbDef, "SHADE_TREE_GW_IDENTITY") && unitEnv(hb, "SHADE_TREE_TOR_PORT") === "9050", "heartbeat identity/Tor SOCKS unchanged");
    const stripUnit = (u) => u.split("\n").filter((l) => !/^(Description=|After=|Wants=|Environment=SHADE_TREE_BOOTNODE_ONION=)/.test(l)).join("\n");
    ok(stripUnit(hb) === stripUnit(hbDef), "heartbeat unit otherwise identical to the default (sandbox, exec, restart)");
    const gwBare = render(work, "gw-only-bare", { SHADE_TREE_BOOTNODE_ONION: ONION });
    ok(gwBare.status === 0 && unitEnv(await readFile(join(gwBare.out, "etc/systemd/system/shade-tree-heartbeat.service"), "utf8"), "SHADE_TREE_BOOTNODE_ONION") === `${ONION}.onion`, "bare 56-char onion (no suffix) is normalised to <onion>.onion");
    for (const bad of ["not-an-onion", `${ONION.slice(0, 55)}.onion`, `${ONION}1.onion`, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX.onion", `${ONION}.onion;rm -rf /`]) {
      const r = render(work, "gw-bad", { SHADE_TREE_BOOTNODE_ONION: bad });
      ok(r.status !== 0 && /SHADE_TREE_BOOTNODE_ONION must be a v3 onion/.test(r.stderr), `malformed bootnode onion rejected: ${JSON.stringify(bad)}`);
    }
    // PoW toggle composes with gateway-only.
    const gwPow = render(work, "gw-only-pow", { SHADE_TREE_BOOTNODE_ONION: ONION, SHADE_TREE_ENABLE_POW: "1" });
    const gwPowBlocks = hsBlocks(await readFile(join(gwPow.out, "etc/tor/torrc.d-shade-tree"), "utf8"));
    ok(gwPow.status === 0 && gwPowBlocks.length === 1 && gwPowBlocks[0].lines[1] === "HiddenServicePoWDefensesEnabled 1", "gateway-only + SHADE_TREE_ENABLE_POW=1: single block, PoW on");
    // OPS-11: SHADENET_NETWORK fills a joining node from the deployment record; explicit env wins.
    const recordPath = join(HERE, "..", "..", "network", "sepolia", "deployment.json");
    const record = JSON.parse(await readFile(recordPath, "utf8"));
    const pre = render(work, "preset", { SHADENET_NETWORK: "sepolia", SHADENET_NETWORK_RECORD: recordPath });
    ok(pre.status === 0 && /gateway-only/.test(pre.stdout), `SHADENET_NETWORK=sepolia renders a gateway-only join (${(pre.stdout || pre.stderr || "").trim()})`);
    const preGw = await readFile(join(pre.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    const preHb = await readFile(join(pre.out, "etc/systemd/system/shade-tree-heartbeat.service"), "utf8");
    const st = record.admission.roots.staked;
    ok(unitEnv(preGw, "SHADE_TREE_GROUP_CONTRACT") === st.contract && unitEnv(preGw, "SHADE_TREE_FROM_BLOCK") === String(st.deployBlock), "preset: staked contract + deploy block from the record");
    ok(unitEnv(preGw, "SHADE_TREE_EPOCH_SECONDS") === String(record.ratePolicy.epochSeconds) && unitEnv(preGw, "SHADE_TREE_TIERS") === st.tiers.map((t) => t.limit).join(","), "preset: epoch + tiers from the record");
    ok(unitEnv(preGw, "SHADE_TREE_ADMIT") === "staked", "preset: a joiner without a members file admits staked only");
    ok(unitEnv(preHb, "SHADE_TREE_BOOTNODE_ONION") === record.elder.onion, "preset: heartbeat announces to the record's Elder");
    const preOverride = render(work, "preset-override", { SHADENET_NETWORK: "sepolia", SHADENET_NETWORK_RECORD: recordPath, SHADE_TREE_EPOCH_SECONDS: "120", SHADE_TREE_ROOT_FRESHNESS_SECONDS: "120" });
    ok(unitEnv(await readFile(join(preOverride.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8"), "SHADE_TREE_EPOCH_SECONDS") === "120", "preset: explicit env wins over the record");
    const retired = join(tmpdir(), `shade-retired-${process.pid}.json`);
    await writeFile(retired, JSON.stringify({ ...record, status: "retired" }));
    const preRetired = render(work, "preset-retired", { SHADENET_NETWORK: "sepolia", SHADENET_NETWORK_RECORD: retired });
    await rm(retired, { force: true });
    ok(preRetired.status !== 0 && /not joinable/.test(preRetired.stderr), "preset: a retired record is refused");
    ok(render(work, "preset-bad", { SHADENET_NETWORK: "../x" }).status !== 0, "preset: a bad network name is refused");
    ok(/^ImportCredential=SHADE_TREE_\*$/m.test(preGw) && !/KEY=/.test(preGw), "units import SHADE_TREE_* credentials and hold no key material");
    // OPS-9: a joining Elder federates with the record's Elder and checks stake on chain.
    const preElder = render(work, "preset-elder", { SHADE_TREE_ELDER_ONLY: "1", SHADENET_NETWORK: "sepolia", SHADENET_NETWORK_RECORD: recordPath });
    const preElderUnit = await readFile(join(preElder.out, "etc/systemd/system/shade-tree-bootnode.service"), "utf8");
    ok(preElder.status === 0 && unitEnv(preElderUnit, "SHADE_TREE_BOOTNODE_PEERS") === record.elder.onion && unitEnv(preElderUnit, "SHADE_TREE_STAKE_MODE") === "onchain"
      && unitEnv(preElderUnit, "SHADE_TREE_GATEWAY_REGISTRY") === record.elder.gatewayRegistry && unitEnv(preElderUnit, "SHADE_TREE_TOR_PORT") === "9050", "preset + ELDER_ONLY: federated stake-admission Elder");
    ok(render(work, "peers-bad", { SHADE_TREE_BOOTNODE_PEERS: "nope.onion" }).status !== 0, "malformed federation peer rejected");
    // --render <dir> CLI form == env form.
    const cli = render(work, "cli", { SHADE_TREE_BOOTNODE_ONION: ONION }, ["--render", join(work, "cli")]);
    ok(cli.status === 0 && (await readAll(join(work, "cli"))).get("etc/systemd/system/shade-tree-heartbeat.service") === hb, "`--render <dir>` == SHADE_TREE_RENDER_ONLY=<dir>");

    // ---------------------------------------------------------------- 3b. dedicated Elder mode
    console.log("SHADE_TREE_ELDER_ONLY dedicated control plane:");
    const elderOnly = render(work, "elder-only", { SHADE_TREE_ELDER_ONLY: "1" });
    ok(elderOnly.status === 0 && /elder-only/.test(elderOnly.stdout), `Elder-only renders (${(elderOnly.stdout || "").trim()})`);
    const elderFiles = await readAll(elderOnly.out);
    ok([...elderFiles.keys()].join(",") === "etc/systemd/system/shade-tree-bootnode.service,etc/tor/torrc.d-shade-tree",
      `emits torrc + Elder unit ONLY (${[...elderFiles.keys()].join(", ")})`);
    const elderBlocks = hsBlocks(elderFiles.get("etc/tor/torrc.d-shade-tree"));
    ok(elderBlocks.length === 1 && elderBlocks[0].dir === "/var/lib/tor/shade-tree-bootnode", "Elder-only torrc contains exactly the Elder hidden service");
    ok(elderBlocks[0].lines[0] === "HiddenServicePort 80 127.0.0.1:8877" && elderBlocks[0].lines[1] === "HiddenServicePoWDefensesEnabled 0", "Elder-only backend remains loopback-only with PoW off by default");
    ok(elderFiles.get("etc/systemd/system/shade-tree-bootnode.service") === elderDef, "Elder-only unit is byte-identical to the default Elder unit");
    for (const alias of ["true", "yes", "on"]) {
      const r = render(work, `elder-only-${alias}`, { SHADE_TREE_ELDER_ONLY: alias });
      ok(r.status === 0 && (await readAll(r.out)).size === 2, `SHADE_TREE_ELDER_ONLY=${alias} == 1`);
    }
    for (const [name, env, message] of [
      ["elder-remote", { SHADE_TREE_ELDER_ONLY: "1", SHADE_TREE_BOOTNODE_ONION: ONION }, /mutually exclusive/],
      ["elder-region", { SHADE_TREE_ELDER_ONLY: "1", SHADE_TREE_GATEWAY_REGION: "na" }, /not valid in Elder-only mode/],
      ["elder-helios", { SHADE_TREE_ELDER_ONLY: "1", SHADE_TREE_HELIOS: "1" }, /requires a gateway/],
    ]) {
      const r = render(work, name, env);
      ok(r.status !== 0 && message.test(r.stderr), `${name} is rejected before rendering`);
    }
    const elderBad = render(work, "elder-bad", { SHADE_TREE_ELDER_ONLY: "maybe" });
    ok(elderBad.status !== 0 && /SHADE_TREE_ELDER_ONLY must be 1 or 0/.test(elderBad.stderr), "invalid Elder-only toggle is rejected");

    // ---------------------------------------------------------------- 4. region passthrough
    console.log("SHADE_TREE_GATEWAY_REGION passthrough:");
    const reg = render(work, "region", { SHADE_TREE_GATEWAY_REGION: "eu" });
    ok(reg.status === 0 && unitEnv(await readFile(join(reg.out, "etc/systemd/system/shade-tree-heartbeat.service"), "utf8"), "SHADE_TREE_GATEWAY_REGION") === "eu", "SHADE_TREE_GATEWAY_REGION=eu lands in the heartbeat unit");
    const regT = await readAll(reg.out);
    ok(regT.get("etc/tor/torrc.d-shade-tree") === torrc && regT.get("etc/systemd/system/shade-tree-bootnode.service") === got.get("etc/systemd/system/shade-tree-bootnode.service"), "region does not touch torrc / bootnode unit");
    const regBad = render(work, "region-bad", { SHADE_TREE_GATEWAY_REGION: "mars" });
    ok(regBad.status !== 0 && /SHADE_TREE_GATEWAY_REGION must be one of/.test(regBad.stderr), "invalid region bucket rejected");

    // ---------------------------------------------------------------- 6. helios sidecar (opt-in)
    console.log("SHADE_TREE_HELIOS sidecar (T-DEV-9b):");
    // T-FEAT-9: the helios sidecar anchors the STAKED (on-chain) root, so it requires an admission
    // policy that admits staked leaves; SHADE_TREE_ADMIT=invited,staked here (default `invited` alone is rejected below).
    const HEL = { SHADE_TREE_HELIOS: "1", SHADE_TREE_HELIOS_CONSENSUS_RPC: "https://beacon.example/", SHADE_TREE_RPC_URL: "https://rpc.example/v1/KEY", SHADE_TREE_GROUP_CONTRACT: "0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC", SHADE_TREE_ADMIT: "invited,staked" };
    const hel = render(work, "helios", HEL);
    ok(hel.status === 0 && /helios=1/.test(hel.stdout), `SHADE_TREE_HELIOS=1 renders (${(hel.stdout || "").trim()})`);
    const helFiles = await readAll(hel.out);
    ok([...helFiles.keys()].join(",") === "etc/systemd/system/shade-tree-bootnode.service,etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/systemd/system/shade-tree-helios.service,etc/tor/torrc.d-shade-tree",
      `emits torrc + 3 units + shade-tree-helios.service (${[...helFiles.keys()].join(", ")})`);
    const hu = helFiles.get("etc/systemd/system/shade-tree-helios.service");
    ok(/^ExecStart=\/usr\/local\/bin\/helios ethereum --network sepolia --rpc-bind-ip 127\.0\.0\.1 --rpc-port 8546 --data-dir \/opt\/shade-tree\/deploy-state\/helios --load-external-fallback$/m.test(hu), "helios ExecStart: sepolia, loopback bind, port 8546, data-dir under deploy-state, external checkpoint fallback (no SHADE_TREE_HELIOS_CHECKPOINT)");
    ok(unitEnv(hu, "EXECUTION_RPC") === HEL.SHADE_TREE_RPC_URL && unitEnv(hu, "CONSENSUS_RPC") === HEL.SHADE_TREE_HELIOS_CONSENSUS_RPC, "helios endpoints passed via EXECUTION_RPC / CONSENSUS_RPC env (not argv)");
    ok(!/ExecStart=.*(rpc\.example|beacon\.example)/.test(hu), "no endpoint URL on the helios command line (API keys stay out of `ps`)");
    ok(/^User=shade-tree$/m.test(hu) && /^MemoryDenyWriteExecute=true$/m.test(hu) && /^NoNewPrivileges=true$/m.test(hu) && /^ProtectSystem=strict$/m.test(hu) && /^CapabilityBoundingSet=$/m.test(hu) && /^SystemCallFilter=@system-service$/m.test(hu) && /^Restart=always$/m.test(hu), "helios unit: sandbox lines + W^X (Rust binary) + Restart=always");
    ok(unitEnv(hu, "CHECKPOINT") === null, "no CHECKPOINT env when SHADE_TREE_HELIOS_CHECKPOINT unset");
    const gwH = helFiles.get("etc/systemd/system/shade-tree-gateway.service");
    ok(/^After=network-online\.target tor\.service shade-tree-helios\.service$/m.test(gwH) && /^Wants=network-online\.target shade-tree-helios\.service$/m.test(gwH), "gateway unit ordered after + wants shade-tree-helios.service");
    ok(unitEnv(gwH, "SHADE_TREE_ROOT_PROVIDER") === "light" && unitEnv(gwH, "SHADE_TREE_HELIOS_RPC_URL") === "http://127.0.0.1:8546" && unitEnv(gwH, "SHADE_TREE_RPC_URL") === HEL.SHADE_TREE_RPC_URL && unitEnv(gwH, "SHADE_TREE_GROUP_CONTRACT") === HEL.SHADE_TREE_GROUP_CONTRACT, "gateway unit: SHADE_TREE_ROOT_PROVIDER=light + SHADE_TREE_HELIOS_RPC_URL + SHADE_TREE_RPC_URL + SHADE_TREE_GROUP_CONTRACT");
    const stripGw = (u) => u.split("\n").filter((l) => !/^(After=|Wants=|Environment=SHADE_TREE_(GROUP_CONTRACT|RPC_URL|ROOT_PROVIDER|HELIOS_RPC_URL)=)/.test(l)).join("\n").replace("Environment=SHADE_TREE_ADMIT=invited,staked", "Environment=SHADE_TREE_ADMIT=invited");
    ok(stripGw(gwH) === stripGw(got.get("etc/systemd/system/shade-tree-gateway.service")), "gateway unit otherwise identical to the default (sandbox, exec, restart)");
    for (const f of ["etc/tor/torrc.d-shade-tree", "etc/systemd/system/shade-tree-bootnode.service"]) ok(helFiles.get(f) === got.get(f), `helios=1 leaves ${f} byte-identical`);
    ok(helFiles.get("etc/systemd/system/shade-tree-heartbeat.service").replace("Environment=SHADE_TREE_ADMIT=invited,staked", "Environment=SHADE_TREE_ADMIT=invited") === got.get("etc/systemd/system/shade-tree-heartbeat.service"), "helios=1 leaves the heartbeat unit byte-identical apart from advertising SHADE_TREE_ADMIT=invited,staked");
    // companions + checkpoint + port + network
    const helCp = render(work, "helios-cp", { ...HEL, SHADE_TREE_HELIOS_CHECKPOINT: "0x" + "ab".repeat(32), SHADE_TREE_HELIOS_PORT: "9545", SHADE_TREE_HELIOS_NETWORK: "mainnet" });
    const huCp = await readFile(join(helCp.out, "etc/systemd/system/shade-tree-helios.service"), "utf8");
    ok(helCp.status === 0 && unitEnv(huCp, "CHECKPOINT") === "0x" + "ab".repeat(32) && /--network mainnet --rpc-bind-ip 127\.0\.0\.1 --rpc-port 9545 /.test(huCp) && !/--load-external-fallback/.test(huCp), "pinned checkpoint -> CHECKPOINT env, no external fallback; port + network passthrough");
    ok(unitEnv(await readFile(join(helCp.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8"), "SHADE_TREE_HELIOS_RPC_URL") === "http://127.0.0.1:9545", "gateway SHADE_TREE_HELIOS_RPC_URL follows SHADE_TREE_HELIOS_PORT");
    // guards
    const bad = [
      [{ ...HEL, SHADE_TREE_HELIOS_CONSENSUS_RPC: "" }, /needs SHADE_TREE_HELIOS_CONSENSUS_RPC/],
      [{ ...HEL, SHADE_TREE_HELIOS_CONSENSUS_RPC: "beacon.example" }, /needs SHADE_TREE_HELIOS_CONSENSUS_RPC/],
      [{ ...HEL, SHADE_TREE_RPC_URL: "" }, /needs SHADE_TREE_RPC_URL/],
      [{ ...HEL, SHADE_TREE_RPC_URL: "https://x/;rm -rf /" }, /needs SHADE_TREE_RPC_URL/],
      [{ ...HEL, SHADE_TREE_GROUP_CONTRACT: "" }, /needs SHADE_TREE_GROUP_CONTRACT/],
      [{ ...HEL, SHADE_TREE_GROUP_CONTRACT: "0x1234" }, /needs SHADE_TREE_GROUP_CONTRACT/],
      [{ ...HEL, SHADE_TREE_ADMIT: "invited" }, /SHADE_TREE_HELIOS=1 anchors the ON-CHAIN \(staked\) admission root, but SHADE_TREE_ADMIT=invited/],
      [{ ...HEL, SHADE_TREE_HELIOS_NETWORK: "goerli" }, /SHADE_TREE_HELIOS_NETWORK must be/],
      [{ ...HEL, SHADE_TREE_HELIOS_PORT: "80" }, /SHADE_TREE_HELIOS_PORT must be/],
      [{ ...HEL, SHADE_TREE_HELIOS_PORT: "abc" }, /SHADE_TREE_HELIOS_PORT must be/],
      [{ ...HEL, SHADE_TREE_HELIOS_CHECKPOINT: "0x1234" }, /SHADE_TREE_HELIOS_CHECKPOINT must be/],
      [{ ...HEL, SHADE_TREE_HELIOS_VERSION: "latest" }, /SHADE_TREE_HELIOS_VERSION must look like/],
      [{ ...HEL, SHADE_TREE_HELIOS_SHA256: "nothex" }, /SHADE_TREE_HELIOS_SHA256 must be/],
      [{ SHADE_TREE_HELIOS: "maybe" }, /SHADE_TREE_HELIOS must be 1 or 0/],
    ];
    for (const [env, re] of bad) {
      const r = render(work, "helios-bad", env);
      ok(r.status !== 0 && re.test(r.stderr), `rejected up front: ${JSON.stringify(Object.fromEntries(Object.entries(env).filter(([k, v]) => HEL[k] !== v)))}`);
    }
    for (const off of ["0", "false", "off"]) {
      const r = render(work, `helios-${off}`, { SHADE_TREE_HELIOS: off });
      const files = await readAll(r.out);
      ok(r.status === 0 && files.size === got.size && [...got].every(([f, b]) => files.get(f) === b), `SHADE_TREE_HELIOS=${off} == default (opt-in; golden untouched)`);
    }
    // composes with gateway-only
    const helGw = render(work, "helios-gw-only", { ...HEL, SHADE_TREE_BOOTNODE_ONION: ONION });
    const helGwFiles = await readAll(helGw.out);
    ok(helGw.status === 0 && [...helGwFiles.keys()].join(",") === "etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/systemd/system/shade-tree-helios.service,etc/tor/torrc.d-shade-tree" && helGwFiles.get("etc/systemd/system/shade-tree-helios.service") === hu, "gateway-only + helios: gateway + heartbeat + helios units, helios unit identical");

    // ---------------------------------------------------------------- 7. 402 registrar (opt-in)
    console.log("SHADE_TREE_REGISTRAR (T-FEAT-7):");
    // T-FEAT-9: a gateway must ADMIT what it sells, so SHADE_TREE_REGISTRAR=1 requires `paid` in SHADE_TREE_ADMIT
    // (the default `invited` alone is rejected below); the gateway unit then carries the paid set + RPC.
    const REG = { SHADE_TREE_REGISTRAR: "1", SHADE_TREE_PAID_ACCESS_CONTRACT: "0x1111111111111111111111111111111111111111", SHADE_TREE_PAY_ASSET: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", SHADE_TREE_PAY_PRICES: "8=100000,32=400000", SHADE_TREE_RPC_URL: "https://rpc.example/v1/KEY", SHADE_TREE_ADMIT: "invited,paid" };
    const reg1 = render(work, "registrar", REG);
    ok(reg1.status === 0 && /registrar=1/.test(reg1.stdout), `SHADE_TREE_REGISTRAR=1 renders (${(reg1.stdout || "").trim()})`);
    const regFiles = await readAll(reg1.out);
    ok([...regFiles.keys()].join(",") === "etc/systemd/system/shade-tree-bootnode.service,etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/systemd/system/shade-tree-registrar.service,etc/tor/torrc.d-shade-tree",
      `emits torrc + 3 units + shade-tree-registrar.service (${[...regFiles.keys()].join(", ")})`);
    const rgT = hsBlocks(regFiles.get("etc/tor/torrc.d-shade-tree"));
    ok(rgT.length === 2 && rgT[0].dir === "/var/lib/tor/shade-tree-bootnode" && rgT[0].lines.join("|") === "HiddenServicePort 80 127.0.0.1:8877|HiddenServicePort 8878 127.0.0.1:8878|HiddenServicePoWDefensesEnabled 0", "bootnode HS block: port 80 + EXTRA port 8878 -> 127.0.0.1:8878, then the PoW line (registrar rides the bootnode onion)");
    ok(rgT[1].lines.join("|") === "HiddenServicePort 80 127.0.0.1:8443|HiddenServicePoWDefensesEnabled 0", "gateway HS block unchanged");
    const ru = regFiles.get("etc/systemd/system/shade-tree-registrar.service");
    ok(/^ExecStart=\/usr\/bin\/node \/opt\/shade-tree\/payments\/registrar\.mjs$/m.test(ru) && unitEnv(ru, "SHADE_TREE_REGISTRAR_PORT") === "8878" && unitEnv(ru, "SHADE_TREE_PAID_ACCESS_CONTRACT") === REG.SHADE_TREE_PAID_ACCESS_CONTRACT && unitEnv(ru, "SHADE_TREE_PAY_ASSET") === REG.SHADE_TREE_PAY_ASSET && unitEnv(ru, "SHADE_TREE_PAY_PRICES") === REG.SHADE_TREE_PAY_PRICES && unitEnv(ru, "SHADE_TREE_RPC_URL") === REG.SHADE_TREE_RPC_URL && unitEnv(ru, "SHADE_TREE_REGISTRAR_STORE") === "/opt/shade-tree/deploy-state/registrar-state.json" && unitEnv(ru, "SHADE_TREE_REGISTRAR_ONION")?.endsWith(".onion"), "registrar unit: ExecStart payments/registrar.mjs + port/contract/asset/prices/rpc/store/onion env");
    ok(unitEnv(ru, "SHADE_TREE_REGISTRAR_KEY") === null && !/SHADE_TREE_REGISTRAR_KEY/.test(ru) && unitEnv(ru, "SHADE_TREE_PAY_TO") === null, "operator key NOT rendered (drop-in only); no SHADE_TREE_PAY_TO unless given");
    ok(unitEnv(ru, "SHADE_TREE_METRICS_PORT") === "9102" && unitEnv(ru, "SHADE_TREE_LOG_FORMAT") === "json" && unitEnv(ru, "SHADE_TREE_BANNER") === "never", "registrar operator metrics and structured logging use isolated defaults");
    ok(/^User=shade-tree$/m.test(ru) && /^NoNewPrivileges=true$/m.test(ru) && /^ProtectSystem=strict$/m.test(ru) && /^CapabilityBoundingSet=$/m.test(ru) && /^SystemCallFilter=@system-service$/m.test(ru) && /^Restart=always$/m.test(ru) && !/MemoryDenyWriteExecute/.test(ru), "registrar unit: same sandbox as the other Node units (no W^X: V8 JIT)");
    const bnR = regFiles.get("etc/systemd/system/shade-tree-bootnode.service");
    ok(unitEnv(bnR, "SHADE_TREE_REGISTRAR_ADVERTISE") === "1" && unitEnv(bnR, "SHADE_TREE_REGISTRAR_PORT") === "8878" && unitEnv(bnR, "SHADE_TREE_PAY_ASSET") === REG.SHADE_TREE_PAY_ASSET && unitEnv(bnR, "SHADE_TREE_PAY_PRICES") === REG.SHADE_TREE_PAY_PRICES && unitEnv(bnR, "SHADE_TREE_PAY_CHAIN_ID") === "11155111", "bootnode unit advertises the offer (SHADE_TREE_REGISTRAR_ADVERTISE=1 + port/asset/prices/chain)");
    ok(unitEnv(bnR, "SHADE_TREE_PAY_PROTOCOLS") === "x402,mpp" && unitEnv(ru, "SHADE_TREE_PAY_PROTOCOLS") === "x402,mpp", "default rails x402,mpp rendered into the bootnode advert + the registrar unit (SHADE_TREE_PAY_PROTOCOLS, T-FEAT-9)");
    const stripBn = (u) => u.split("\n").filter((l) => !/^Environment=SHADE_TREE_(REGISTRAR_ADVERTISE|REGISTRAR_PORT|PAY_ASSET|PAY_PRICES|PAY_CHAIN_ID|PAY_PROTOCOLS)=/.test(l)).join("\n");
    ok(stripBn(bnR) === got.get("etc/systemd/system/shade-tree-bootnode.service"), "bootnode unit otherwise byte-identical to the default");
    // T-FEAT-9: the gateway unit admits invited,paid (+ the paid set + RPC it needs); the heartbeat
    // advertises the SAME policy + the offer as signed caps (SHADE_TREE_REGISTRAR_ADVERTISE + SHADE_TREE_PAY_* + onion).
    const gwR = regFiles.get("etc/systemd/system/shade-tree-gateway.service"), hbR = regFiles.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(unitEnv(gwR, "SHADE_TREE_ADMIT") === "invited,paid" && unitEnv(gwR, "SHADE_TREE_PAID_ACCESS_CONTRACT") === REG.SHADE_TREE_PAID_ACCESS_CONTRACT && unitEnv(gwR, "SHADE_TREE_RPC_URL") === REG.SHADE_TREE_RPC_URL && unitEnv(gwR, "SHADE_TREE_GROUP_CONTRACT") === null, "gateway unit: SHADE_TREE_ADMIT=invited,paid + SHADE_TREE_PAID_ACCESS_CONTRACT + SHADE_TREE_RPC_URL (no staked contract)");
    ok(unitEnv(hbR, "SHADE_TREE_ADMIT") === "invited,paid" && unitEnv(hbR, "SHADE_TREE_REGISTRAR_ADVERTISE") === "1" && unitEnv(hbR, "SHADE_TREE_REGISTRAR_ONION") === unitEnv(ru, "SHADE_TREE_REGISTRAR_ONION") && unitEnv(hbR, "SHADE_TREE_PAY_ASSET") === REG.SHADE_TREE_PAY_ASSET && unitEnv(hbR, "SHADE_TREE_PAY_PRICES") === REG.SHADE_TREE_PAY_PRICES && unitEnv(hbR, "SHADE_TREE_PAY_PROTOCOLS") === "x402,mpp" && unitEnv(hbR, "SHADE_TREE_PAY_CHAIN_ID") === "11155111" && unitEnv(hbR, "SHADE_TREE_REGISTRAR_PORT") === "8878", "heartbeat unit: same SHADE_TREE_ADMIT + the pay advert env (advertised as signed caps.pay; registrar onion = the bootnode's)");
    const stripAdm = (u) => u.split("\n").filter((l) => !/^Environment=SHADE_TREE_(PAID_ACCESS_CONTRACT|RPC_URL|REGISTRAR_ADVERTISE|REGISTRAR_PORT|REGISTRAR_ONION|PAY_ASSET|PAY_PRICES|PAY_CHAIN_ID|PAY_PROTOCOLS)=/.test(l)).join("\n").replace("Environment=SHADE_TREE_ADMIT=invited,paid", "Environment=SHADE_TREE_ADMIT=invited");
    for (const f of ["etc/systemd/system/shade-tree-gateway.service", "etc/systemd/system/shade-tree-heartbeat.service"]) ok(stripAdm(regFiles.get(f)) === got.get(f), `registrar=1 leaves ${f} otherwise byte-identical`);
    const regPT = render(work, "registrar-payto", { ...REG, SHADE_TREE_PAY_TO: "0x2222222222222222222222222222222222222222", SHADE_TREE_REGISTRAR_PORT: "9878", SHADE_TREE_PAY_CHAIN_ID: "1" });
    const ruPT = await readFile(join(regPT.out, "etc/systemd/system/shade-tree-registrar.service"), "utf8");
    ok(regPT.status === 0 && unitEnv(ruPT, "SHADE_TREE_PAY_TO") === "0x2222222222222222222222222222222222222222" && unitEnv(ruPT, "SHADE_TREE_REGISTRAR_PORT") === "9878" && hsBlocks(await readFile(join(regPT.out, "etc/tor/torrc.d-shade-tree"), "utf8"))[0].lines[1] === "HiddenServicePort 9878 127.0.0.1:9878" && unitEnv(await readFile(join(regPT.out, "etc/systemd/system/shade-tree-bootnode.service"), "utf8"), "SHADE_TREE_PAY_CHAIN_ID") === "1", "SHADE_TREE_PAY_TO / SHADE_TREE_REGISTRAR_PORT / SHADE_TREE_PAY_CHAIN_ID passthrough (unit + torrc + advert)");
    const rgBad = [
      [{ ...REG, SHADE_TREE_PAID_ACCESS_CONTRACT: "" }, /needs SHADE_TREE_PAID_ACCESS_CONTRACT/],
      [{ ...REG, SHADE_TREE_PAY_ASSET: "usdc" }, /needs SHADE_TREE_PAY_ASSET/],
      [{ ...REG, SHADE_TREE_PAY_PRICES: "8=free" }, /needs SHADE_TREE_PAY_PRICES/],
      [{ ...REG, SHADE_TREE_PAY_PRICES: "" }, /needs SHADE_TREE_PAY_PRICES/],
      [{ ...REG, SHADE_TREE_RPC_URL: "" }, /needs SHADE_TREE_RPC_URL/],
      [{ ...REG, SHADE_TREE_PAY_TO: "0x12" }, /SHADE_TREE_PAY_TO must be/],
      [{ ...REG, SHADE_TREE_REGISTRAR_PORT: "80" }, /SHADE_TREE_REGISTRAR_PORT must be/],
      [{ ...REG, SHADE_TREE_PAY_CHAIN_ID: "sepolia" }, /SHADE_TREE_PAY_CHAIN_ID must be/],
      [{ ...REG, SHADE_TREE_ADMIT: "invited" }, /SHADE_TREE_REGISTRAR=1 sells paid leaves but SHADE_TREE_ADMIT=invited does not admit them/],
      [{ ...REG, SHADE_TREE_PAY_PROTOCOLS: "lightning" }, /SHADE_TREE_PAY_PROTOCOLS must be/],
      [{ ...REG, SHADE_TREE_PAY_PROTOCOLS: "x402,,mpp" }, /SHADE_TREE_PAY_PROTOCOLS must be/],
      [{ SHADE_TREE_REGISTRAR: "maybe" }, /SHADE_TREE_REGISTRAR must be 1 or 0/],
    ];
    for (const [env, re] of rgBad) {
      const r = render(work, "registrar-bad", env);
      ok(r.status !== 0 && re.test(r.stderr), `rejected up front: ${JSON.stringify(Object.fromEntries(Object.entries(env).filter(([k, v]) => REG[k] !== v)))}`);
    }
    for (const off of ["0", "false", "off"]) {
      const r = render(work, `registrar-${off}`, { SHADE_TREE_REGISTRAR: off });
      const files = await readAll(r.out);
      ok(r.status === 0 && files.size === got.size && [...got].every(([f, b]) => files.get(f) === b), `SHADE_TREE_REGISTRAR=${off} == default (opt-in; golden untouched)`);
    }
    const regHel = render(work, "registrar-helios", { ...REG, ...HEL, SHADE_TREE_ADMIT: "invited,staked,paid" });
    ok(regHel.status === 0 && (await readAll(regHel.out)).size === 6, "composes with SHADE_TREE_HELIOS=1 (6 files; SHADE_TREE_ADMIT=invited,staked,paid admits both what helios anchors and what the registrar sells)");
    const regHelNoPaid = render(work, "registrar-helios-nopaid", { ...REG, ...HEL });
    ok(regHelNoPaid.status !== 0 && /SHADE_TREE_REGISTRAR=1 sells paid leaves but SHADE_TREE_ADMIT=invited,staked does not admit them/.test(regHelNoPaid.stderr), "…and SHADE_TREE_HELIOS=1's invited,staked WITHOUT paid is refused when the registrar sells");

    // ---------------------------------------------------------------- 8. from-block passthrough
    console.log("SHADE_TREE_FROM_BLOCK / SHADE_TREE_FROM_BLOCKS (eth_getLogs start blocks):");
    const FB = { SHADE_TREE_FROM_BLOCK: "0xafa5ad", SHADE_TREE_FROM_BLOCKS: "0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25=11510541,0x4e8C2Bf5d3c5454A04837401095fce2646484111=0xafa6b9" };
    const fb = render(work, "fromblock", FB);
    ok(fb.status === 0, "renders with both set");
    const fbFiles = await readAll(fb.out);
    const gwFb = fbFiles.get("etc/systemd/system/shade-tree-gateway.service");
    ok(unitEnv(gwFb, "SHADE_TREE_FROM_BLOCK") === FB.SHADE_TREE_FROM_BLOCK && unitEnv(gwFb, "SHADE_TREE_FROM_BLOCKS") === FB.SHADE_TREE_FROM_BLOCKS, "gateway unit carries SHADE_TREE_FROM_BLOCK + SHADE_TREE_FROM_BLOCKS verbatim");
    const stripFb = (u) => u.split("\n").filter((l) => !/^Environment=SHADE_TREE_FROM_BLOCKS?=/.test(l)).join("\n");
    ok(stripFb(gwFb) === got.get("etc/systemd/system/shade-tree-gateway.service"), "gateway unit otherwise byte-identical to the default");
    for (const f of ["etc/tor/torrc.d-shade-tree", "etc/systemd/system/shade-tree-bootnode.service", "etc/systemd/system/shade-tree-heartbeat.service"]) ok(fbFiles.get(f) === got.get(f), `from-block leaves ${f} byte-identical`);
    const fbOne = render(work, "fromblock-one", { SHADE_TREE_FROM_BLOCK: "11510541" });
    const gwOne = await readFile(join(fbOne.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    ok(fbOne.status === 0 && unitEnv(gwOne, "SHADE_TREE_FROM_BLOCK") === "11510541" && unitEnv(gwOne, "SHADE_TREE_FROM_BLOCKS") === null, "decimal SHADE_TREE_FROM_BLOCK alone -> one line, no SHADE_TREE_FROM_BLOCKS");
    const fbHel = render(work, "fromblock-helios", { ...HEL, SHADE_TREE_FROM_BLOCK: "0xafa5ad" });
    const gwHelFb = await readFile(join(fbHel.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    ok(fbHel.status === 0 && unitEnv(gwHelFb, "SHADE_TREE_FROM_BLOCK") === "0xafa5ad" && unitEnv(gwHelFb, "SHADE_TREE_ROOT_PROVIDER") === "light", "composes with SHADE_TREE_HELIOS=1 (light provider + start block)");
    for (const [env, re] of [
      [{ SHADE_TREE_FROM_BLOCK: "latest" }, /SHADE_TREE_FROM_BLOCK must be a block number/],
      [{ SHADE_TREE_FROM_BLOCK: "0x" }, /SHADE_TREE_FROM_BLOCK must be a block number/],
      [{ SHADE_TREE_FROM_BLOCK: "12; rm -rf /" }, /SHADE_TREE_FROM_BLOCK must be a block number/],
      [{ SHADE_TREE_FROM_BLOCKS: "0x1234=5" }, /SHADE_TREE_FROM_BLOCKS must be/],
      [{ SHADE_TREE_FROM_BLOCKS: "0x" + "ab".repeat(20) + "=" }, /SHADE_TREE_FROM_BLOCKS must be/],
      [{ SHADE_TREE_FROM_BLOCKS: "0x" + "ab".repeat(20) + "=5,junk" }, /SHADE_TREE_FROM_BLOCKS must be/],
      [{ SHADE_TREE_FROM_BLOCKS: "0x" + "ab".repeat(20) + "=5 " }, /SHADE_TREE_FROM_BLOCKS must be/],
    ]) {
      const r = render(work, "fromblock-bad", env);
      ok(r.status !== 0 && re.test(r.stderr), `rejected up front: ${JSON.stringify(env)}`);
    }
    for (const env of [{ SHADE_TREE_FROM_BLOCK: "" }, { SHADE_TREE_FROM_BLOCKS: "" }]) {
      const r = render(work, "fromblock-unset", env);
      const files = await readAll(r.out);
      ok(r.status === 0 && files.size === got.size && [...got].every(([f, b]) => files.get(f) === b), `${Object.keys(env)[0]} empty == default (golden untouched)`);
    }

    // ---------------------------------------------------------------- 9. admission policy + rails (T-FEAT-9)
    console.log("SHADE_TREE_ADMIT / SHADE_TREE_PAY_PROTOCOLS / registrar on a gateway-only box (T-FEAT-9):");
    // default = invited: both units carry Environment=SHADE_TREE_ADMIT=invited (this IS the golden now)
    ok(unitEnv(got.get("etc/systemd/system/shade-tree-gateway.service"), "SHADE_TREE_ADMIT") === "invited" && unitEnv(got.get("etc/systemd/system/shade-tree-heartbeat.service"), "SHADE_TREE_ADMIT") === "invited", "default render: gateway + heartbeat units carry SHADE_TREE_ADMIT=invited (max-anon default; golden regenerated for T-FEAT-9)");
    ok(!/SHADE_TREE_(GROUP_CONTRACT|PAID_ACCESS_CONTRACT|RPC_URL)=/.test(got.get("etc/systemd/system/shade-tree-gateway.service")), "default gateway unit carries no contract / RPC (invited needs none)");
    for (const spelling of ["invited", "INVITED", " invited ", ""]) {
      const r = render(work, "admit-inv", { SHADE_TREE_ADMIT: spelling });
      const files = await readAll(r.out);
      ok(r.status === 0 && files.size === got.size && [...got].every(([f, b]) => files.get(f) === b), `SHADE_TREE_ADMIT=${JSON.stringify(spelling)} == default (case/space tolerant; empty = the default)`);
    }
    const STK = { SHADE_TREE_ADMIT: "paid,staked,invited", SHADE_TREE_GROUP_CONTRACT: "0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC", SHADE_TREE_PAID_ACCESS_CONTRACT: "0x1111111111111111111111111111111111111111", SHADE_TREE_RPC_URL: "https://rpc.example/v1/KEY" };
    const stk = render(work, "admit-all", STK);
    const stkFiles = await readAll(stk.out);
    const gwS = stkFiles.get("etc/systemd/system/shade-tree-gateway.service"), hbS = stkFiles.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(stk.status === 0 && /admit=invited,staked,paid/.test(stk.stdout) && unitEnv(gwS, "SHADE_TREE_ADMIT") === "invited,staked,paid" && unitEnv(hbS, "SHADE_TREE_ADMIT") === "invited,staked,paid", "SHADE_TREE_ADMIT=paid,staked,invited -> normalized to the canonical anonymity order invited,staked,paid in both units");
    ok(unitEnv(gwS, "SHADE_TREE_GROUP_CONTRACT") === STK.SHADE_TREE_GROUP_CONTRACT && unitEnv(gwS, "SHADE_TREE_PAID_ACCESS_CONTRACT") === STK.SHADE_TREE_PAID_ACCESS_CONTRACT && unitEnv(gwS, "SHADE_TREE_RPC_URL") === STK.SHADE_TREE_RPC_URL && unitEnv(gwS, "SHADE_TREE_ROOT_PROVIDER") === null, "gateway unit carries the staked + paid contracts + RPC (node provider; helios off)");
    ok(!/SHADE_TREE_(GROUP_CONTRACT|PAID_ACCESS_CONTRACT|RPC_URL)=/.test(hbS), "heartbeat unit carries the policy only (no contracts)");
    const stripAll = (u) => u.split("\n").filter((l) => !/^Environment=SHADE_TREE_(GROUP_CONTRACT|PAID_ACCESS_CONTRACT|RPC_URL)=/.test(l)).join("\n").replace("Environment=SHADE_TREE_ADMIT=invited,staked,paid", "Environment=SHADE_TREE_ADMIT=invited");
    ok(stripAll(gwS) === got.get("etc/systemd/system/shade-tree-gateway.service") && stripAll(hbS) === got.get("etc/systemd/system/shade-tree-heartbeat.service"), "…otherwise byte-identical to the default units");
    ok(stkFiles.get("etc/tor/torrc.d-shade-tree") === torrc && stkFiles.get("etc/systemd/system/shade-tree-bootnode.service") === got.get("etc/systemd/system/shade-tree-bootnode.service"), "policy does not touch torrc / bootnode unit");
    const stkOnly = render(work, "admit-staked", { SHADE_TREE_ADMIT: "staked", SHADE_TREE_GROUP_CONTRACT: STK.SHADE_TREE_GROUP_CONTRACT, SHADE_TREE_RPC_URL: STK.SHADE_TREE_RPC_URL });
    const gwSO = await readFile(join(stkOnly.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    ok(stkOnly.status === 0 && unitEnv(gwSO, "SHADE_TREE_ADMIT") === "staked" && unitEnv(gwSO, "SHADE_TREE_GROUP_CONTRACT") === STK.SHADE_TREE_GROUP_CONTRACT && unitEnv(gwSO, "SHADE_TREE_PAID_ACCESS_CONTRACT") === null, "SHADE_TREE_ADMIT=staked alone: staked contract only, no members.json needed, no paid");
    for (const [env, re] of [
      [{ SHADE_TREE_ADMIT: "onchain" }, /SHADE_TREE_ADMIT must be a comma list drawn from invited, staked, paid/],
      [{ SHADE_TREE_ADMIT: "static,onchain" }, /SHADE_TREE_ADMIT must be/],
      [{ SHADE_TREE_ADMIT: "invited,,paid" }, /SHADE_TREE_ADMIT must be/],
      [{ SHADE_TREE_ADMIT: "invited,staked" }, /SHADE_TREE_ADMIT names staked: needs SHADE_TREE_GROUP_CONTRACT/],
      [{ SHADE_TREE_ADMIT: "invited,staked", SHADE_TREE_GROUP_CONTRACT: "0x12" }, /SHADE_TREE_ADMIT names staked: needs SHADE_TREE_GROUP_CONTRACT/],
      [{ SHADE_TREE_ADMIT: "invited,paid" }, /SHADE_TREE_ADMIT names paid: needs SHADE_TREE_PAID_ACCESS_CONTRACT/],
      [{ SHADE_TREE_ADMIT: "invited,staked", SHADE_TREE_GROUP_CONTRACT: STK.SHADE_TREE_GROUP_CONTRACT }, /SHADE_TREE_ADMIT names invited,staked: needs SHADE_TREE_RPC_URL/],
      [{ SHADE_TREE_ADMIT: "paid", SHADE_TREE_PAID_ACCESS_CONTRACT: STK.SHADE_TREE_PAID_ACCESS_CONTRACT, SHADE_TREE_RPC_URL: "ftp://x" }, /needs SHADE_TREE_RPC_URL/],
    ]) {
      const r = render(work, "admit-bad", env);
      ok(r.status !== 0 && re.test(r.stderr), `rejected up front (fail closed): ${JSON.stringify(env)}`);
    }
    // rails subset -> registrar unit + bootnode advert + heartbeat advert all carry it, normalized
    const mppOnly = render(work, "pay-mpp", { ...REG, SHADE_TREE_PAY_PROTOCOLS: "MPP" });
    const mppFiles = await readAll(mppOnly.out);
    ok(mppOnly.status === 0 && /pay=mpp/.test(mppOnly.stdout) && ["shade-tree-registrar", "shade-tree-bootnode", "shade-tree-heartbeat"].every((u) => unitEnv(mppFiles.get(`etc/systemd/system/${u}.service`), "SHADE_TREE_PAY_PROTOCOLS") === "mpp"), "SHADE_TREE_PAY_PROTOCOLS=MPP -> `mpp` in the registrar unit, the bootnode advert and the heartbeat advert");
    const both = render(work, "pay-both", { ...REG, SHADE_TREE_PAY_PROTOCOLS: "mpp,x402" });
    ok(both.status === 0 && unitEnv(await readFile(join(both.out, "etc/systemd/system/shade-tree-registrar.service"), "utf8"), "SHADE_TREE_PAY_PROTOCOLS") === "x402,mpp", "SHADE_TREE_PAY_PROTOCOLS=mpp,x402 -> canonical order x402,mpp");
    // registrar on a GATEWAY-ONLY box: rides the gateway onion; heartbeat advertises it; no bootnode unit
    const gwReg = render(work, "registrar-gw-only", { ...REG, SHADE_TREE_BOOTNODE_ONION: ONION });
    const gwRegFiles = await readAll(gwReg.out);
    ok(gwReg.status === 0 && [...gwRegFiles.keys()].join(",") === "etc/systemd/system/shade-tree-gateway.service,etc/systemd/system/shade-tree-heartbeat.service,etc/systemd/system/shade-tree-registrar.service,etc/tor/torrc.d-shade-tree", `gateway-only + registrar renders gateway + heartbeat + registrar units, no bootnode (${[...gwRegFiles.keys()].join(", ")})`);
    const gwRegT = hsBlocks(gwRegFiles.get("etc/tor/torrc.d-shade-tree"));
    ok(gwRegT.length === 1 && gwRegT[0].dir === "/var/lib/tor/shade-tree-gateway" && gwRegT[0].lines.join("|") === "HiddenServicePort 80 127.0.0.1:8443|HiddenServicePort 8878 127.0.0.1:8878|HiddenServicePoWDefensesEnabled 0", "torrc: ONE HS block (gateway) with port 80 + EXTRA port 8878 (the registrar rides the GATEWAY onion), then the PoW line");
    const ruG = gwRegFiles.get("etc/systemd/system/shade-tree-registrar.service"), hbG = gwRegFiles.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(unitEnv(ruG, "SHADE_TREE_REGISTRAR_ONION") === "gatewayplaceholderplaceholderplaceholderplaceholderplace.onion" && unitEnv(hbG, "SHADE_TREE_REGISTRAR_ONION") === "gatewayplaceholderplaceholderplaceholderplaceholderplace.onion" && unitEnv(hbG, "SHADE_TREE_REGISTRAR_ADVERTISE") === "1" && unitEnv(hbG, "SHADE_TREE_BOOTNODE_ONION") === ONION + ".onion", "registrar + heartbeat name the GATEWAY onion as the registrar onion; heartbeat still announces to the remote bootnode");
    ok(unitEnv(gwRegFiles.get("etc/systemd/system/shade-tree-gateway.service"), "SHADE_TREE_ADMIT") === "invited,paid", "gateway-only gateway unit admits invited,paid");

    console.log("explicit ZK artifact set:");
    const artifactId = "rln-0b25f824a04da3a8";
    const artifactPath = "circuits/rln/verification_key.json";
    const artifactSpec = `${artifactId}=${artifactPath}`;
    const artifacts = render(work, "zk-artifacts", {
      SHADE_TREE_ZK_ARTIFACTS: artifactSpec,
      SHADE_TREE_ZK_ARTIFACT_LEGACY: artifactId,
    });
    const artifactFiles = await readAll(artifacts.out);
    const artifactGateway = artifactFiles.get("etc/systemd/system/shade-tree-gateway.service");
    const artifactHeartbeat = artifactFiles.get("etc/systemd/system/shade-tree-heartbeat.service");
    ok(artifacts.status === 0 && unitEnv(artifactGateway, "SHADE_TREE_ZK_ARTIFACTS") === artifactSpec && unitEnv(artifactHeartbeat, "SHADE_TREE_ZK_ARTIFACTS") === artifactSpec,
      "gateway verifies and heartbeat advertises the same explicit artifact set");
    ok(unitEnv(artifactGateway, "SHADE_TREE_ZK_ARTIFACT_LEGACY") === artifactId && unitEnv(artifactHeartbeat, "SHADE_TREE_ZK_ARTIFACT_LEGACY") === null,
      "legacy envelope mapping is verifier-only and is not leaked into heartbeat configuration");
    const stripArtifacts = (u) => u.split("\n").filter((l) => !/^Environment=SHADE_TREE_ZK_ARTIFACT/.test(l)).join("\n");
    ok(stripArtifacts(artifactGateway) === got.get("etc/systemd/system/shade-tree-gateway.service") && stripArtifacts(artifactHeartbeat) === got.get("etc/systemd/system/shade-tree-heartbeat.service"),
      "explicit artifact configuration otherwise leaves the default units byte-identical");
    for (const [name, env, re] of [
      ["bad-id", { SHADE_TREE_ZK_ARTIFACTS: "RLN-BAD=circuits/rln/verification_key.json" }, /SHADE_TREE_ZK_ARTIFACTS must be/],
      ["missing-path", { SHADE_TREE_ZK_ARTIFACTS: `${artifactId}=` }, /SHADE_TREE_ZK_ARTIFACTS must be/],
      ["unit-injection", { SHADE_TREE_ZK_ARTIFACTS: `${artifactSpec}\nEnvironment=BAD=1` }, /SHADE_TREE_ZK_ARTIFACTS must be/],
      ["path-traversal", { SHADE_TREE_ZK_ARTIFACTS: `${artifactId}=circuits/../secret.json` }, /paths must not contain/],
      ["legacy-without-set", { SHADE_TREE_ZK_ARTIFACT_LEGACY: artifactId }, /requires an explicit/],
      ["bad-legacy", { SHADE_TREE_ZK_ARTIFACTS: artifactSpec, SHADE_TREE_ZK_ARTIFACT_LEGACY: "BAD ID" }, /bounded lowercase artifact id/],
    ]) {
      const rejected = render(work, `zk-artifacts-${name}`, env);
      ok(rejected.status !== 0 && re.test(rejected.stderr), `explicit artifacts reject ${name}`);
    }

    console.log("fleet tally onion route:");
    const tallyToken = "t".repeat(32);
    const tallyPeer = `${ONION}.onion:8879`;
    const tally = render(work, "fleet-tally", { SHADE_TREE_FLEET_TALLY_PEERS: tallyPeer, SHADE_TREE_FLEET_TALLY_TOKEN: tallyToken });
    const tallyFiles = await readAll(tally.out);
    const tallyBlocks = hsBlocks(tallyFiles.get("etc/tor/torrc.d-shade-tree"));
    const tallyUnit = tallyFiles.get("etc/systemd/system/shade-tree-gateway.service");
    ok(tally.status === 0 && tallyBlocks[1].lines.join("|") === "HiddenServicePort 80 127.0.0.1:8443|HiddenServicePort 8879 127.0.0.1:8879|HiddenServicePoWDefensesEnabled 0", "gateway onion maps distinct virtual port 8879 to the HTTP tally listener");
    ok(unitEnv(tallyUnit, "SHADE_TREE_FLEET_TALLY_PEERS") === tallyPeer && unitEnv(tallyUnit, "SHADE_TREE_FLEET_TALLY_LISTEN") === "127.0.0.1:8879" && unitEnv(tallyUnit, "SHADE_TREE_TOR_PORT") === "9050", "gateway unit sends tally pushes through the local Tor SOCKS port and listens on the mapped backend");
    ok(/^EnvironmentFile=-\/etc\/shade-tree\/fleet-tally\.env$/m.test(tallyUnit) && ![...tallyFiles.values()].some((body) => body.includes(tallyToken)), "rendered artifacts reference a protected token file and never contain the tally token");
    for (const [name, env, re] of [
      ["missing-token", { SHADE_TREE_FLEET_TALLY_PEERS: tallyPeer }, /needs SHADE_TREE_FLEET_TALLY_TOKEN/],
      ["bad-peer", { SHADE_TREE_FLEET_TALLY_PEERS: "example.com:8879", SHADE_TREE_FLEET_TALLY_TOKEN: tallyToken }, /tally peers must be/],
      ["port-collision", { SHADE_TREE_FLEET_TALLY_PEERS: tallyPeer, SHADE_TREE_FLEET_TALLY_TOKEN: tallyToken, SHADE_TREE_FLEET_TALLY_PORT: "9101" }, /active local service ports must be distinct/],
    ]) {
      const rejected = render(work, `fleet-tally-${name}`, env);
      ok(rejected.status !== 0 && re.test(rejected.stderr), `fleet tally rejects ${name}`);
    }

    // ---------------------------------------------------------------- 5. other guards
    console.log("guards:");
    const noMembers = spawnSync("bash", [SCRIPT], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME ?? "/" },
      encoding: "utf8",
    });
    ok(noMembers.status !== 0 && /pass SHADE_TREE_MEMBERS_FILE=\/absolute\/path/.test(noMembers.stderr), "live invited bootstrap refuses the repository demo member set before requiring root or installing anything");
    const operatorMembers = join(def.out, "etc", "operator-members.json");
    await writeFile(operatorMembers, '{"version":2,"members":["1"]}\n');
    const explicitMembers = spawnSync("bash", [SCRIPT], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME ?? "/", SHADE_TREE_MEMBERS_FILE: operatorMembers },
      encoding: "utf8",
    });
    ok(explicitMembers.status !== 0 && /run as root or with sudo/.test(explicitMembers.stderr + explicitMembers.stdout), "an explicit readable operator member set passes the live preflight and reaches the root boundary");
    const membersInjection = render(work, "members-path-bad", { SHADE_TREE_MEMBERS_FILE: "/tmp/members.json\nEnvironment=BAD=1" });
    ok(membersInjection.status !== 0 && /unsupported path characters/.test(membersInjection.stderr), "members path cannot inject a systemd Environment line");
    const membersRendered = render(work, "members-canonical", { SHADE_TREE_MEMBERS_FILE: operatorMembers });
    const membersUnit = await readFile(join(membersRendered.out, "etc/systemd/system/shade-tree-gateway.service"), "utf8");
    ok(membersRendered.status === 0 && unitEnv(membersUnit, "SHADE_TREE_MEMBERS_FILE") === "/etc/shade-tree/members.json", "render review keeps the trusted member set outside service-writable deploy state");
    const adm = render(work, "adm-bad", { SHADE_TREE_ADMISSION: "vip" });
    ok(adm.status !== 0 && /SHADE_TREE_ADMISSION must be open or stake/.test(adm.stderr), "SHADE_TREE_ADMISSION=vip rejected");
    const admStake = render(work, "adm-stake", { SHADE_TREE_ADMISSION: "stake" });
    ok(admStake.status === 0 && unitEnv(await readFile(join(admStake.out, "etc/systemd/system/shade-tree-bootnode.service"), "utf8"), "SHADE_TREE_BOOTNODE_ADMISSION") === "stake", "SHADE_TREE_ADMISSION=stake lands in the bootnode unit");
    const metricsLow = render(work, "metrics-low", { SHADE_TREE_ELDER_METRICS_PORT: "80" });
    ok(metricsLow.status !== 0 && /operator metrics ports must be in 1024\.\.65535/.test(metricsLow.stderr), "privileged or malformed operator metrics ports are rejected");
    const metricsCollision = render(work, "metrics-collision", { SHADE_TREE_ELDER_METRICS_PORT: "9101" });
    ok(metricsCollision.status !== 0 && /operator metrics ports must be distinct/.test(metricsCollision.stderr), "operator metrics port collisions are rejected before install");
    const badBackend = render(work, "backend-port-bad", { SHADE_TREE_GATEWAY_PORT: "abc" });
    ok(badBackend.status !== 0 && /bootnode and gateway ports must be in 1024\.\.65535/.test(badBackend.stderr), "malformed gateway backend ports are rejected before install");
    const sameBackends = render(work, "backend-port-collision", { SHADE_TREE_GATEWAY_PORT: "8877" });
    ok(sameBackends.status !== 0 && /active local service ports must be distinct/.test(sameBackends.stderr), "bootnode and gateway cannot share a local backend port");
    for (const [name, env] of [
      ["elder-metrics-vs-bootnode", { SHADE_TREE_ELDER_METRICS_PORT: "8877" }],
      ["elder-metrics-vs-gateway", { SHADE_TREE_ELDER_METRICS_PORT: "8443" }],
      ["node-metrics-vs-gateway", { SHADE_TREE_NODE_METRICS_PORT: "8443" }],
      ["heartbeat-metrics-vs-tor", { SHADE_TREE_HEARTBEAT_METRICS_PORT: "9050" }],
      ["registrar-metrics-vs-backend", { ...REG, SHADE_TREE_REGISTRAR_METRICS_PORT: "8878" }],
      ["node-metrics-vs-helios", { ...HEL, SHADE_TREE_NODE_METRICS_PORT: "8546" }],
    ]) {
      const collision = render(work, name, env);
      ok(collision.status !== 0 && /active local service ports must be distinct/.test(collision.stderr), `${name} collision is rejected before install`);
    }
    const customGatewayPort = render(work, "gateway-port-custom", { SHADE_TREE_GATEWAY_PORT: "9443" });
    const customGatewayFiles = await readAll(customGatewayPort.out);
    const customGatewayBlocks = hsBlocks(customGatewayFiles.get("etc/tor/torrc.d-shade-tree"));
    ok(customGatewayPort.status === 0 && customGatewayBlocks[1].lines[0] === "HiddenServicePort 80 127.0.0.1:9443" && unitEnv(customGatewayFiles.get("etc/systemd/system/shade-tree-gateway.service"), "SHADE_TREE_GATEWAY_PORT") === "9443", "custom gateway port stays in sync across Tor and the node process");
    const logBad = render(work, "log-bad", { SHADE_TREE_LOG_LEVEL: "verbose" });
    ok(logBad.status !== 0 && /SHADE_TREE_LOG_LEVEL must be/.test(logBad.stderr), "unknown logging levels are rejected before install");
    const only = await listFiles(work);
    ok(only.every((f) => f.startsWith("etc/") || /^[^/]+\/etc\//.test(f)), "render mode writes only under <dir>/etc/ (no stray files)");
    ok(!/apt-get|systemctl|useradd/.test(def.stdout + def.stderr + gw.stdout + gw.stderr), "render mode never mentions apt/systemctl/useradd (nothing executed on the host)");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(failures ? `\nbootstrap render selftest: ${failures} FAILED` : "\nbootstrap render selftest: all checks passed");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
