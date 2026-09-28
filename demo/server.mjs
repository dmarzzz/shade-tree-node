// Tiny demo backend for the Shade Tree.
//
// Serves demo/index.html and two endpoints:
//   GET /api/status  -> the demo member's address + live on-chain staked status + tor state
//   GET /api/run     -> SSE stream of the REAL flow (prove -> Tor -> gateway -> egress),
//                       ending with the gateway egress IP vs. your own IP.
//
// The proving + Tor routing are real (ShadeTreeClient); only staking is assumed done. Config via
// env, with local fallbacks:
//   SHADE_TREE_SECRET            member secret (default keys.local.json[SHADE_TREE_DEMO_INDEX|0])
//   SHADE_TREE_DEMO_WALLET       address to show as the funder (optional, display only)
//   SHADE_TREE_DIRECTORY         signed directory json (default network/sepolia/directory.json)
//   SHADE_TREE_DIR_SIGNER        directory signer (required for fleet mode)
//   SHADE_TREE_TOR_PORT          client Tor SOCKS (default 9260)
//   SHADE_TREE_DEMO_PORT         http port (default 8790)
//
// Run:  node demo/server.mjs   (start scripts/start-tor-client.sh first, or let this spawn it)

import http from "node:http";
import net from "node:net";
import https from "node:https";
import { spawn } from "node:child_process";
import { readFile, readFileSync as rfs } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { SocksClient } from "socks";
import { ShadeTreeClient } from "../client/shade-tree-client.mjs";
import { deriveCommitment, identitySecretOf, identityFor, currentEpoch, K_SLOTS, EPOCH_SECONDS } from "../lib/rln.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PORT = Number(process.env.SHADE_TREE_DEMO_PORT || 8790);
const TOR_PORT = Number(process.env.SHADE_TREE_TOR_PORT || 9260);
const TARGET = "https://api.ipify.org";

// ---- config: member + directory ---------------------------------------------
const idx = Number(process.env.SHADE_TREE_DEMO_INDEX || 0);
const secret = process.env.SHADE_TREE_SECRET || JSON.parse(rfs(join(ROOT, "keys.local.json"), "utf8"))[idx].secret;
const wallet = process.env.SHADE_TREE_DEMO_WALLET || null;
const dep = JSON.parse(rfs(join(ROOT, "contracts", "deployed.local.json"), "utf8"));
const dirPath = process.env.SHADE_TREE_DIRECTORY || join(ROOT, "network", "sepolia", "directory.json");
const dirSigner = process.env.SHADE_TREE_DIR_SIGNER || JSON.parse(rfs(dirPath, "utf8")).signer;
const directory = JSON.parse(rfs(dirPath, "utf8"));

const leaf = deriveCommitment(identitySecretOf(identityFor(secret)));

// Parse gateway metadata from the signed directory notes
// ("gateway-2 / egress-02").
const gateways = (directory.gateways || []).map((g) => {
  const parts = (g.note || "").split("/").map((s) => s.trim());
  const ip = ((g.note || "").match(/\d+\.\d+\.\d+\.\d+/) || [])[0] || null;
  return { onion: g.onion, onionShort: g.onion.replace(/\.onion$/, ""), name: parts[1] || g.onion.slice(0, 12), ip };
});
const onionNote = (onion) => (directory.gateways || []).find((x) => x.onion.startsWith(onion))?.note || onion;
const gwByOnion = (onion) => gateways.find((g) => g.onionShort === String(onion).replace(/\.onion$/, ""));

let deployer = null;
try { deployer = JSON.parse(rfs(join(ROOT, "network", "sepolia", "contracts.json"), "utf8")).deployer; } catch {}

// live reachability of each gateway onion (background probe loop below)
const health = new Map(); // onion -> { up, latencyMs, at }
// The candidate pool is the currently-reachable gateways (fall back to all if the probe
// hasn't found any yet). Returns { pool, chosen } so the UI's "random of N" is truthful.
function chooseGateway() {
  const up = gateways.filter((g) => health.get(g.onion)?.up);
  const pool = up.length ? up : gateways;
  return { pool, chosen: pool[Math.floor(Math.random() * pool.length)] };
}

const client = new ShadeTreeClient({ secret, directory: dirPath, dirSigner, torPort: TOR_PORT });

// Static cryptographic facts, attached to the prove:done event for the UI's crypto panel.
const CRYPTO = {
  system: "Groth16", curve: "BN254 (alt_bn128)", hash: "Poseidon",
  circuit: "circom-rln · RLN(20,16)", treeDepth: 20, msgLimit: K_SLOTS,
  ceremony: "circom-rln v1.0.0 · local testnet setup (unaudited)",
  leaf: leaf.toString(),                                   // the member's rateCommitment (Merkle leaf)
  leafFormula: `Poseidon(Poseidon(idSecret), ${K_SLOTS})`,
  contract: dep.stakedReputationSet,
};

// DEMO SAFETY: the member has K_SLOTS nullifiers per epoch. Sending a (K+1)-th request in
// one epoch reuses a slot with a fresh signal — which is exactly the over-spend the gateway
// SLASHES on. So budget requests to K per epoch (and surface it as the live rate limit).
// Start "capped" for the boot epoch so the first real request only fires in a FRESH epoch
// with a clean slot space at the gateway. This makes restarts safe: a restarted server can
// never reuse a slot it already sent this epoch (its pool cursor reset to 0) and get the
// member slashed. Costs up to one epoch of "resets in Ns" at startup (overlaps Tor warmup).
let epUsed = { epoch: currentEpoch(), count: K_SLOTS };
function budget() {
  const ep = currentEpoch();
  if (ep !== epUsed.epoch) epUsed = { epoch: ep, count: 0 };
  const resetIn = EPOCH_SECONDS - (Math.floor(Date.now() / 1000) % EPOCH_SECONDS);
  return { remaining: Math.max(0, K_SLOTS - epUsed.count), perEpoch: K_SLOTS, resetIn };
}

// ---- on-chain status --------------------------------------------------------
const provider = new ethers.JsonRpcProvider(dep.rpcUrl);
const contract = new ethers.Contract(
  dep.stakedReputationSet,
  ["function members(uint256) view returns (uint256 bond,uint64 index,uint64 exitInitiatedAt)", "function BOND() view returns (uint256)"],
  provider
);
async function chainStatus() {
  const [m, BOND] = await Promise.all([contract.members(leaf), contract.BOND()]);
  return {
    staked: m.bond > 0n && m.exitInitiatedAt === 0n,
    bondEth: ethers.formatEther(m.bond),
    denomEth: ethers.formatEther(BOND),
    contract: dep.stakedReputationSet,
    network: "sepolia",
    leaf: leaf.toString(),
  };
}

// ---- your real IP (direct, for contrast) ------------------------------------
let realIp = null;
function fetchRealIp() {
  return new Promise((resolve) => {
    https.get(TARGET, (res) => { let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve(b.trim())); }).on("error", () => resolve(null));
  });
}

// ---- tor + per-gateway health (background probe loop) -----------------------
let torReady = false;
function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => { s.destroy(); resolve(true); });
    s.on("error", () => resolve(false));
    s.setTimeout(1500, () => { s.destroy(); resolve(false); });
  });
}
async function probeGw(g) {
  const t0 = Date.now();
  try {
    const { socket } = await SocksClient.createConnection({
      proxy: { host: "127.0.0.1", port: TOR_PORT, type: 5 },
      command: "connect", destination: { host: g.onion, port: 80 }, timeout: 20000,
    });
    socket.destroy(); return { up: true, latencyMs: Date.now() - t0 };
  } catch { return { up: false, latencyMs: null }; }
}
async function healthLoop() {
  if (!(await portOpen(TOR_PORT))) {
    console.log("client tor not on " + TOR_PORT + " — spawning scripts/start-tor-client.sh");
    spawn("bash", [join(ROOT, "scripts", "start-tor-client.sh")], { cwd: ROOT, stdio: "ignore", detached: true }).unref();
  }
  for (;;) {
    let anyUp = false;
    for (const g of gateways) {
      const r = await probeGw(g);
      health.set(g.onion, { ...r, at: Date.now() });
      if (r.up) anyUp = true;
    }
    // latch torReady on first reachability (onion connectivity is stable once established;
    // don't flip the button back on a transient miss).
    if (anyUp && !torReady) { torReady = true; console.log("tor ready (onions reachable)"); }
    await new Promise((r) => setTimeout(r, torReady ? 30000 : 6000));
  }
}

// ---- http -------------------------------------------------------------------
function sse(res, obj) { res.write(`data: ${JSON.stringify(obj)}\n\n`); }

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/" || u.pathname === "/index.html") {
    readFile(join(HERE, "index.html"), (e, buf) => {
      if (e) { res.writeHead(500); return res.end("no index.html"); }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(buf);
    });
    return;
  }
  if (u.pathname === "/api/status") {
    try {
      const cs = await chainStatus();
      if (!realIp) realIp = await fetchRealIp(); // cache; lets the UI show "your IP" pre-run
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...cs, wallet, torReady, target: TARGET, yourIp: realIp, ...budget() }));
    } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); }
    return;
  }
  if (u.pathname === "/api/network") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      network: "sepolia",
      contract: dep.stakedReputationSet,
      staker: wallet,
      deployer,
      epochSeconds: EPOCH_SECONDS,
      torReady,
      gateways: gateways.map((g) => { const h = health.get(g.onion) || {}; return { name: g.name, ip: g.ip, onion: g.onionShort, up: !!h.up, latencyMs: h.latencyMs ?? null }; }),
    }));
    return;
  }
  if (u.pathname === "/api/run") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    const t0 = Date.now();
    const b = budget();
    if (b.remaining <= 0) {
      sse(res, { phase: "error", error: `rate cap reached — all ${b.perEpoch} slots used this epoch, resets in ${b.resetIn}s` });
      res.end();
      return;
    }
    epUsed.count++; // reserve a slot up-front (conservative: a failed run still can't reuse)
    const marks = {};
    try {
      if (!realIp) realIp = await fetchRealIp();
      sse(res, { phase: "begin", yourIp: realIp });

      // pick a gateway at random from the reachable set, and SHOW the choice + the pool
      sse(res, { phase: "select", status: "start" });
      const { pool, chosen } = chooseGateway();
      sse(res, { phase: "select", status: "done", chosen: { name: chosen.name, ip: chosen.ip, onion: chosen.onionShort }, pool: pool.map((g) => g.name) });

      const result = await client.fetch(TARGET, {
        onion: chosen.onionShort,
        onEvent: (e) => {
          marks[e.phase + ":" + e.status] = Date.now();
          const ev = { ...e, onionNote: e.onion ? onionNote(e.onion) : undefined };
          if (e.phase === "prove" && e.status === "done") ev.crypto = CRYPTO;
          sse(res, ev);
        },
      });

      // the response has travelled back through the gateway + Tor to us
      sse(res, { phase: "return", status: "done", bytes: result.body.length });

      const seg = (a, z) => (marks[a] != null && marks[z] != null ? marks[z] - marks[a] : null);
      sse(res, {
        phase: "result",
        egressIp: result.body.trim(),
        httpStatus: result.status,
        gateway: result.gateway ? { onion: result.gateway.onion, name: gwByOnion(result.gateway.onion)?.name, slot: result.gateway.slot, nullifier: result.gateway.nullifier } : null,
        yourIp: realIp,
        latencyMs: Date.now() - t0,
        timings: {
          prove: seg("prove:start", "prove:done"),
          dial: seg("dial:start", "dial:done"),
          gate: seg("gate:start", "gate:done"),
          roundtrip: seg("egress:start", "egress:done"),
        },
      });
    } catch (e) {
      sse(res, { phase: "error", error: String(e.message || e) });
    }
    res.end();
    return;
  }
  res.writeHead(404); res.end("not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Shade Tree demo: http://127.0.0.1:${PORT}  (member leaf ${leaf.toString().slice(0, 14)}.., contract ${dep.stakedReputationSet})`);
  console.log(`target ${TARGET} via ${directory.gateways?.length || 0}-gateway fleet over Tor ${TOR_PORT}`);
});
healthLoop();
