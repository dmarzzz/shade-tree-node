// Selftest for the external uptime prober (scripts/uptime-probe.mjs).
//
// Spins a MOCK bootnode (local http server) serving a real signDirectory()-signed /directory and
// a /health, points the prober at it via SHADE_TREE_BOOTNODE_URL (dev mode, no Tor), and drives it as a
// SUBPROCESS so we can assert the actual process EXIT CODES a monitor consumes:
//   healthy         -> exit 0, ok:true, signerOk:true, directoryFresh:true, correct fleetSize
//   wrong signer    -> unhealthy, signerOk:false, nonzero exit
//   stale directory -> unhealthy even with a valid signer
//   unreachable     -> unhealthy, bootnodeReachable:false, nonzero exit
//   --format nagios -> "OK: ..." exit 0 healthy / "CRITICAL: ..." exit 2 unhealthy
//
//   node scripts/uptime-probe.selftest.mjs   (exit 0 = all invariants held)

import { spawn, execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  canonicalCaps,
  canonicalPreV4CapsBytes,
  ed25519Sign,
  signDirectory,
  pubkeyToOnion,
} from "../packages/node/lib/directory.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROBE = join(HERE, "uptime-probe.mjs");

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// --- ed25519 raw-key helpers (same extraction the bootnode signer uses) --------
const rawPubHex = (k) => { const der = k.export({ format: "der", type: "spki" }); return der.subarray(der.length - 32).toString("hex"); };
const rawSeedHex = (k) => { const der = k.export({ format: "der", type: "pkcs8" }); return der.subarray(der.length - 32).toString("hex"); };
function mintEd() { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); return { pub: rawPubHex(publicKey), priv: rawSeedHex(privateKey) }; }

// Build a real signed directory: each gateway's pubkey is the ed25519 key encoded in its own v3
// .onion (pubkeyToOnion), so verifyDirectory's onion<->pubkey binding check passes.
function makeSignedDir(signer, n, issued = Math.floor(Date.now() / 1000)) {
  const gateways = [];
  for (let i = 0; i < n; i++) {
    const gw = mintEd();
    gateways.push({ onion: pubkeyToOnion(gw.pub), pubkey: gw.pub, weight: 100, health: "up" });
  }
  return signDirectory({ version: 1, issued, gateways, signer: signer.pub }, signer.priv);
}

// The deployed Sepolia research fleet predates the Shade Tree v4 domain reset. This fixture
// proves the observer can authenticate those old capability signatures only when its explicit
// compatibility switch is set; ordinary verification stays v4-only.
function makePreV4CapsDir(signer, issued = Math.floor(Date.now() / 1000)) {
  const gw = mintEd();
  const onion = pubkeyToOnion(gw.pub);
  const caps = canonicalCaps({ ports: [443], proto: { min: 3, max: 3 } });
  const capsSig = ed25519Sign(canonicalPreV4CapsBytes(onion, caps), gw.priv);
  return signDirectory({
    version: 1,
    issued,
    gateways: [{ onion, pubkey: gw.pub, weight: 100, health: "up", caps, capsSig }],
    signer: signer.pub,
  }, signer.priv);
}

// The mock bootnode MUST run in its own process: the tests drive the prober with execFileSync
// (synchronous), which blocks this process's event loop -- an in-process http server could not
// answer the subprocess while we're blocked, so the child would just time out. A separate process
// keeps serving. It serves fixed /health + /directory strings passed via env, prints its port.
function startMockBootnode(dirJson, healthJson) {
  const code = `
    const http = require('http');
    const s = http.createServer((req, res) => {
      const send = (b) => { res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(b) }); res.end(b); };
      if (req.url === '/health') return send(process.env.MOCK_HEALTH);
      if (req.url === '/directory') return send(process.env.MOCK_DIR);
      res.writeHead(404); res.end();
    });
    s.listen(0, '127.0.0.1', () => process.stdout.write('PORT ' + s.address().port + '\\n'));
  `;
  const child = spawn(process.execPath, ["--input-type=commonjs", "-e", code], {
    env: { ...process.env, MOCK_DIR: dirJson, MOCK_HEALTH: healthJson },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const port = new Promise((resolve, reject) => {
    let buf = "";
    child.stdout.on("data", (d) => { buf += d; const m = buf.match(/PORT (\d+)/); if (m) resolve(Number(m[1])); });
    child.on("exit", (c) => reject(new Error("mock bootnode exited early, code " + c)));
    setTimeout(() => reject(new Error("mock bootnode did not start in time")), 5000);
  });
  return { child, port };
}

// Run the prober as a subprocess with a curated env (parent SHADE_TREE_* stripped) and capture exit code.
function runProbe(overrides, args = []) {
  const env = { ...process.env };
  delete env.SHADE_TREE_BOOTNODE_ONION; delete env.SHADE_TREE_BOOTNODE_URL; delete env.SHADE_TREE_DIR_SIGNER; delete env.SHADE_TREE_NETWORK;
  delete env.SHADE_TREE_DIR_MAX_AGE_SEC; delete env.SHADE_TREE_DIR_FUTURE_SEC;
  delete env.SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS;
  Object.assign(env, overrides);
  try {
    const stdout = execFileSync(process.execPath, [PROBE, ...args], { env, encoding: "utf8" });
    return { status: 0, stdout };
  } catch (e) {
    return { status: e.status ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

async function main() {
  const signer = mintEd();
  const FLEET = 3;
  const dir = makeSignedDir(signer, FLEET);

  // --- mock bootnode (separate process): /health + /directory --------------
  const { child, port: portP } = startMockBootnode(
    JSON.stringify(dir),
    JSON.stringify({ ok: true, count: FLEET, admission: "open", signer: signer.pub })
  );
  const base = `http://127.0.0.1:${await portP}`;
  const staleDir = makeSignedDir(signer, FLEET, Math.floor(Date.now() / 1000) - 3600);
  const { child: staleChild, port: stalePortP } = startMockBootnode(
    JSON.stringify(staleDir),
    JSON.stringify({ ok: true, count: FLEET, admission: "open", signer: signer.pub })
  );
  const staleBase = `http://127.0.0.1:${await stalePortP}`;
  const preV4Dir = makePreV4CapsDir(signer);
  const preV4Prefix = preV4Dir.gateways[0].onion.slice(0, 12);
  const { child: preV4Child, port: preV4PortP } = startMockBootnode(
    JSON.stringify(preV4Dir),
    JSON.stringify({ ok: true, count: 1, admission: "stake", signer: signer.pub })
  );
  const preV4Base = `http://127.0.0.1:${await preV4PortP}`;
  // A port nothing listens on -> connection refused (fast, no hang).
  const deadBase = "http://127.0.0.1:1";

  try {
    // 1. HEALTHY -----------------------------------------------------------
    console.log("healthy:");
    const h = runProbe({ SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: signer.pub });
    ok(h.status === 0, "healthy -> exit 0");
    let hj = {};
    try { hj = JSON.parse(h.stdout.trim()); } catch {}
    ok(hj.ok === true, "healthy -> ok:true");
    ok(hj.bootnodeReachable === true, "healthy -> bootnodeReachable:true");
    ok(hj.signerOk === true, "healthy -> signerOk:true");
    ok(hj.directoryFresh === true, "healthy -> directoryFresh:true");
    ok(hj.fleetSize === FLEET, `healthy -> fleetSize:${FLEET} (count, not identities)`);
    ok(!/\.onion/.test(h.stdout), "output prints no onion address (count only)");

    // 2. WRONG PINNED SIGNER ----------------------------------------------
    console.log("\nwrong pinned signer:");
    const other = mintEd();
    const w = runProbe({ SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: other.pub });
    ok(w.status !== 0, "wrong signer -> nonzero exit");
    let wj = {};
    try { wj = JSON.parse(w.stdout.trim()); } catch {}
    ok(wj.ok === false, "wrong signer -> ok:false");
    ok(wj.bootnodeReachable === true, "wrong signer -> still reachable (signature is what fails)");
    ok(wj.signerOk === false, "wrong signer -> signerOk:false");

    // Rotation pin: a comma-separated list (what network-record.mjs sets for a two-signer record).
    const l = runProbe({ SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: `${other.pub}, ${signer.pub}` });
    const lj = JSON.parse(l.stdout.trim().split("\n").pop());
    ok(l.status === 0 && lj.ok === true && lj.signerOk === true, "comma-separated signer list -> healthy when one pin matches");

    // 3. STALE, VALIDLY SIGNED DIRECTORY -----------------------------------
    console.log("\nstale signed directory:");
    const s = runProbe({ SHADE_TREE_BOOTNODE_URL: staleBase, SHADE_TREE_DIR_SIGNER: signer.pub });
    let sj = {};
    try { sj = JSON.parse(s.stdout.trim()); } catch {}
    ok(s.status !== 0 && sj.ok === false, "stale signed directory -> unhealthy");
    ok(sj.signerOk === true, "stale signed directory -> signature still valid");
    ok(sj.directoryFresh === false && sj.fleetSize === 0, "stale signed directory -> rejected before counting");

    // 4. UNREACHABLE BOOTNODE ---------------------------------------------
    console.log("\nunreachable bootnode:");
    const u = runProbe({ SHADE_TREE_BOOTNODE_URL: deadBase, SHADE_TREE_DIR_SIGNER: signer.pub });
    ok(u.status !== 0, "unreachable -> nonzero exit");
    let uj = {};
    try { uj = JSON.parse(u.stdout.trim()); } catch {}
    ok(uj.ok === false, "unreachable -> ok:false");
    ok(uj.bootnodeReachable === false, "unreachable -> bootnodeReachable:false");

    // 5. NAGIOS FORMAT -----------------------------------------------------
    console.log("\nnagios format:");
    const nOk = runProbe({ SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: signer.pub }, ["--format", "nagios"]);
    ok(nOk.status === 0, "nagios healthy -> exit 0");
    ok(/^OK:/.test(nOk.stdout.trim()), "nagios healthy -> 'OK: ...' line");
    ok(!nOk.stdout.includes(`fleet=${FLEET}`) && !/\b\d+\b/.test(nOk.stdout), "hosted Nagios line omits the fleet count");

    const nBad = runProbe({ SHADE_TREE_BOOTNODE_URL: deadBase, SHADE_TREE_DIR_SIGNER: signer.pub }, ["--format", "nagios"]);
    ok(nBad.status === 2, "nagios unhealthy -> exit 2 (CRITICAL)");
    ok(/^CRITICAL:/.test(nBad.stdout.trim()), "nagios unhealthy -> 'CRITICAL: ...' line");
    ok(!/\.onion/.test(nBad.stdout), "nagios line leaks no onion address");

    // 6. EXPLICIT PRE-v4 OBSERVATION COMPATIBILITY ------------------------
    console.log("\npre-v4 observation compatibility:");
    const oldOff = runProbe({ SHADE_TREE_BOOTNODE_URL: preV4Base, SHADE_TREE_DIR_SIGNER: signer.pub });
    let oldOffJson = {};
    try { oldOffJson = JSON.parse(oldOff.stdout.trim()); } catch {}
    ok(oldOff.status !== 0 && oldOffJson.signerOk === false, "pre-v4 caps fail closed by default");
    ok(!oldOff.stdout.includes(preV4Prefix), "JSON verification reason omits the gateway prefix");

    const oldOn = runProbe({
      SHADE_TREE_BOOTNODE_URL: preV4Base,
      SHADE_TREE_DIR_SIGNER: signer.pub,
      SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS: "1",
    });
    let oldOnJson = {};
    try { oldOnJson = JSON.parse(oldOn.stdout.trim()); } catch {}
    ok(oldOn.status === 0 && oldOnJson.ok === true && oldOnJson.fleetSize === 1, "explicit observer switch authenticates and counts the pre-v4 fixture");

    const oldNagios = runProbe({ SHADE_TREE_BOOTNODE_URL: preV4Base, SHADE_TREE_DIR_SIGNER: signer.pub }, ["--format", "nagios"]);
    ok(oldNagios.status === 2 && oldNagios.stdout.trim() === "CRITICAL: directory verification failed", "hosted failure is fixed and identifier-free");
    ok(!oldNagios.stdout.includes(preV4Prefix), "Nagios verification failure omits the gateway prefix");

    // 7. SHADE_TREE_NETWORK RECORD (packages/node/lib/network-record.mjs) ------------------------
    // Explicit env wins over the record (the mock URL + signer still drive the probe); a record
    // that resolves NO bootnode (network/sepolia/bootnode.json is pending, or an unknown network)
    // is a misconfig -> unhealthy, never a throw / hang.
    console.log("\nSHADE_TREE_NETWORK record:");
    const nEnv = runProbe({ SHADE_TREE_NETWORK: "sepolia", SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: signer.pub });
    ok(nEnv.status === 0, "SHADE_TREE_NETWORK + explicit URL/signer -> explicit env wins, healthy");
    // A closed Tor port keeps this hermetic: with a reachable Tor the live record would verify.
    const nOnly = runProbe({ SHADE_TREE_NETWORK: "sepolia", SHADE_TREE_TOR_PORT: "1" });
    let nj = {};
    try { nj = JSON.parse(nOnly.stdout.trim()); } catch {}
    ok(nOnly.status !== 0 && nj.ok === false, "SHADE_TREE_NETWORK alone (no live bootnode in the record, or a live one unreachable here) -> unhealthy, not a crash");
    const nBadNet = runProbe({ SHADE_TREE_NETWORK: "no-such-network-zzz" });
    let bj = {};
    try { bj = JSON.parse(nBadNet.stdout.trim()); } catch {}
    ok(nBadNet.status === 1 && bj.ok === false && /^misconfig:/.test(bj.reason || ""), "unknown SHADE_TREE_NETWORK -> misconfig reason, exit 1");

    // 8. OPS-7: probe-side Tor down is UNKNOWN, never CRITICAL; the Elder commit is checked
    // against the record pin and reported without counting as downtime.
    console.log("\nprobe-side failures and pin check (OPS-7):");
    const unk = runProbe({ SHADE_TREE_BOOTNODE_ONION: pubkeyToOnion(mintEd().pub), SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_TOR_PORT: "1" });
    let unkJson = {};
    try { unkJson = JSON.parse(unk.stdout.trim()); } catch {}
    ok(unk.status === 3 && unkJson.status === "unknown" && unkJson.reason === "probe:local-tor-unavailable", "local Tor down -> UNKNOWN, exit 3");
    const unkN = runProbe({ SHADE_TREE_BOOTNODE_ONION: pubkeyToOnion(mintEd().pub), SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_TOR_PORT: "1" }, ["--format", "nagios"]);
    ok(unkN.status === 3 && unkN.stdout.startsWith("UNKNOWN:"), "nagios UNKNOWN line, exit 3");
    const { recordElderCommit, promLines } = await import("./uptime-probe.mjs");
    const prom = promLines({ ok: true, bootnodeReachable: true, directoryFresh: true, fleetSize: 3, ts: 1, pinMatch: false });
    ok(/^shade_tree_probe_ok 1$/m.test(prom) && /^shade_tree_probe_pin_match 0$/m.test(prom) && /^shade_tree_probe_fleet_size 3$/m.test(prom), "textfile metrics render");
    ok(!/onion|signer/i.test(prom.replace(/# HELP.*$/gm, "")), "textfile metrics carry no identities");
    const promPath = join(tmpdir(), `probe-${process.pid}.prom`);
    runProbe({ SHADE_TREE_BOOTNODE_URL: base, SHADE_TREE_DIR_SIGNER: signer.pub }, ["--prom-file", promPath]);
    let written = "";
    try { written = readFileSync(promPath, "utf8"); rmSync(promPath); } catch {}
    ok(/^shade_tree_probe_ok 1$/m.test(written), "--prom-file writes the textfile after a healthy run");
    const pin = recordElderCommit("sepolia");
    ok(/^[0-9a-f]{40}$/.test(pin || ""), "sepolia record pin resolves");
    ok(recordElderCommit("../etc") === null && recordElderCommit("no-such-network-zzz") === null, "bad or unknown network -> no pin");
    for (const [commit, want] of [[pin, true], ["f".repeat(40), false]]) {
      const { child: pc, port: pp } = startMockBootnode(JSON.stringify(dir), JSON.stringify({ ok: true, count: FLEET, admission: "open", signer: signer.pub, commit }));
      try {
        const pbase = `http://127.0.0.1:${await pp}`;
        const r = runProbe({ SHADE_TREE_NETWORK: "sepolia", SHADE_TREE_BOOTNODE_URL: pbase, SHADE_TREE_DIR_SIGNER: signer.pub });
        let rj = {};
        try { rj = JSON.parse(r.stdout.trim()); } catch {}
        ok(r.status === 0 && rj.ok === true && rj.pinMatch === want, `Elder commit ${want ? "matches" : "differs from"} the record pin -> pinMatch ${want}, still healthy`);
        if (!want) {
          const n = runProbe({ SHADE_TREE_NETWORK: "sepolia", SHADE_TREE_BOOTNODE_URL: pbase, SHADE_TREE_DIR_SIGNER: signer.pub }, ["--format", "nagios"]);
          ok(n.status === 0 && /differs from the record pin/.test(n.stdout), "nagios reports pin drift as OK with a note");
        }
      } finally {
        pc.kill();
      }
    }
  } finally {
    child.kill();
    staleChild.kill();
    preV4Child.kill();
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: uptime-probe selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
