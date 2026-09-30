// A tiny, read-only fleet status page.
//
// It reads a bootnode's /health + /directory, VERIFIES the directory signature against a
// pinned signer, and serves a privacy-preserving summary: fleet size, per-gateway health,
// and a signature-verified indicator. It never exposes an operator identity or a full onion
// address -- a status board is a public surface, and the fleet's whole point is that onions
// are not enumerable. So every gateway is reduced to a TRUNCATED onion (first 16 chars) plus
// weight/health, and operator identity collapses to a single staked:true/false badge. The
// address is dropped before it ever leaves this process.
//
// It is a CACHE VIEWER, not a trust root: the signature check is the real bootnode signature
// path (packages/node/lib/directory.mjs verifyDirectory), so a lying bootnode shows up here as signerOk=false
// rather than as a forged fleet.
//
// Config (all SHADE_TREE_*):
//   SHADE_TREE_BOOTNODE_ONION   the bootnode's v3 onion; reached over Tor (packages/node/bootnode/fetch.mjs)
//   SHADE_TREE_BOOTNODE_URL     OR a plain http base URL (e.g. http://127.0.0.1:8877) for local/dev
//   SHADE_TREE_DIR_SIGNER       the pinned directory-signer pubkey (hex) the bootnode prints on boot
//   SHADE_TREE_STATUS_PORT      loopback port for this status page          (default 8090)
//   SHADE_TREE_TOR_PORT         local Tor SOCKS port for the onion path     (default 9250)
//   SHADE_TREE_TOR_HOST         local Tor SOCKS host                        (default 127.0.0.1)
//
// It binds LOOPBACK by default and has no auth: everything it serves is already-public,
// privacy-scrubbed data, and loopback keeps it off the network until an operator chooses to
// front it. Run: node web/status-server.mjs

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyDirectory } from "../packages/node/lib/directory.mjs";
import { fetchOverTor } from "../packages/node/bootnode/fetch.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PAGE = readFileSync(join(HERE, "status.html"), "utf8");

// How many leading chars of an onion we ever reveal. Enough to eyeball-distinguish two
// gateways in the table, far short of the 56 chars that would make the fleet enumerable.
const ONION_PREFIX = 16;

// Bounded in-memory trend buffer. A status page is a point-in-time snapshot; this ring lets an
// operator see the shape of the last window (fleet growing/shrinking, a bootnode flapping) with
// no persistence and no growth beyond the cap. 120 samples ~= 30 min at the page's 15s poll.
// Samples are COUNTS + BOOLEANS only -- never a gateway, onion, or operator -- so the history
// endpoint stays exactly as privacy-scrubbed as /api/status.
const HISTORY_CAP = 120;

// A trivial fixed-size ring: push appends, and we trim from the front once we exceed the cap, so
// memory is bounded by `cap` samples regardless of uptime.
function makeHistoryRing(cap = HISTORY_CAP) {
  const buf = [];
  return {
    cap,
    // Reduce a full status to the privacy-safe trend sample: timestamp + two booleans + a count.
    push(status) {
      buf.push({
        ts: status.lastFetch,
        bootnodeReachable: status.bootnodeReachable === true,
        signerOk: status.signerOk === true,
        fleetSize: Number(status.fleetSize) || 0,
      });
      if (buf.length > cap) buf.splice(0, buf.length - cap);
    },
    samples() { return buf.slice(); },
    // A compact summary for embedding in /api/status without shipping the whole ring twice.
    summary() {
      const first = buf[0];
      const last = buf[buf.length - 1];
      return {
        count: buf.length,
        cap,
        oldest: first ? first.ts : null,
        newest: last ? last.ts : null,
        reachableCount: buf.reduce((n, s) => n + (s.bootnodeReachable ? 1 : 0), 0),
      };
    },
  };
}

export function configFromEnv(env = process.env) {
  return {
    bootnodeUrl: env.SHADE_TREE_BOOTNODE_URL || null,
    bootnodeOnion: env.SHADE_TREE_BOOTNODE_ONION || null,
    dirSigner: env.SHADE_TREE_DIR_SIGNER || null,
    torHost: env.SHADE_TREE_TOR_HOST || "127.0.0.1",
    torPort: Number(env.SHADE_TREE_TOR_PORT || 9250),
    port: Number(env.SHADE_TREE_STATUS_PORT || 8090),
  };
}

// Fetch one JSON endpoint from the bootnode, over plain http (dev) or over Tor (onion).
async function fetchBootnode(cfg, path) {
  if (cfg.bootnodeUrl) {
    return await fetchPlainHttp(cfg.bootnodeUrl.replace(/\/$/, "") + path);
  }
  if (cfg.bootnodeOnion) {
    return await fetchOverTor(cfg.bootnodeOnion, path, { torHost: cfg.torHost, torPort: cfg.torPort });
  }
  throw new Error("no bootnode configured (set SHADE_TREE_BOOTNODE_URL or SHADE_TREE_BOOTNODE_ONION)");
}

// Minimal plain-http GET + JSON parse, bounded read (mirrors fetch.mjs's cap). Dev/local only.
function fetchPlainHttp(url, { maxBytes = 2 * 1024 * 1024, timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers: { Accept: "application/json" } }, (res) => {
      let buf = "";
      res.on("data", (c) => {
        buf += c;
        if (buf.length > maxBytes) { req.destroy(); reject(new Error(`response exceeded ${maxBytes} bytes`)); }
      });
      res.on("end", () => {
        if (res.statusCode !== 200) return reject(new Error(`bootnode HTTP ${res.statusCode}: ${buf.slice(0, 200)}`));
        try { resolve(JSON.parse(buf)); } catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("timeout")); });
  });
}

// Reduce a signed directory to the privacy-scrubbed public view. This is the ONLY place a
// gateway's fields cross into the response, so the truncation/omission happens here, once.
export function scrubGateways(dir) {
  return (dir.gateways || []).map((g) => {
    const view = {
      onionShort: String(g.onion || "").slice(0, ONION_PREFIX),
      weight: Number(g.weight) || 0,
      health: g.health || "unknown",
    };
    // An entry MAY carry operator/staked labels; surface only whether it is staked, never the
    // operator address. Entries with no operator field simply have no staked badge.
    if (Object.prototype.hasOwnProperty.call(g, "operator")) view.staked = g.staked === true;
    return view;
  });
}

// Build the full status object the API returns. Never throws: an unreachable or lying bootnode
// degrades to bootnodeReachable:false / signerOk:false with an empty fleet, so the page stays up.
export async function buildStatus(cfg) {
  const out = {
    bootnodeReachable: false,
    fleetSize: 0,
    gateways: [],
    signerOk: false,
    admission: null,
    signerPinned: cfg.dirSigner || null,
    lastFetch: new Date().toISOString(),
    error: null,
  };
  let health, dir;
  try {
    [health, dir] = await Promise.all([
      fetchBootnode(cfg, "/health"),
      fetchBootnode(cfg, "/directory"),
    ]);
    out.bootnodeReachable = true;
  } catch (e) {
    out.error = e.message;
    return out;
  }
  out.admission = health?.admission ?? null;
  // Verify the directory signature against the PINNED signer. Without a pinned signer we cannot
  // claim the fleet is authentic, so signerOk stays false.
  if (cfg.dirSigner) {
    const v = verifyDirectory(dir, cfg.dirSigner);
    out.signerOk = v.ok === true;
    if (!v.ok) out.error = "directory verify: " + v.reason;
  } else {
    out.error = "no SHADE_TREE_DIR_SIGNER pinned; signature not verified";
  }
  out.gateways = scrubGateways(dir);
  out.fleetSize = out.gateways.length;
  return out;
}

export function makeStatusServer(cfg, { historyCap = HISTORY_CAP } = {}) {
  // Per-server ring: history lives only as long as the process, and each server instance keeps its
  // own trend (so tests are isolated and a restart simply starts a fresh window).
  const history = makeHistoryRing(historyCap);
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://status");
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        return res.end(PAGE);
      }
      if (req.method === "GET" && url.pathname === "/api/status") {
        const status = await buildStatus(cfg);
        // The page only computes status on request, so we append one trend sample per /api/status
        // hit -- the auto-refresh poll fills the ring naturally, no background timer needed.
        history.push(status);
        status.history = history.summary();
        const body = JSON.stringify(status);
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        return res.end(body);
      }
      if (req.method === "GET" && url.pathname === "/api/history") {
        // Read-only trend buffer: counts + booleans only, same privacy posture as /api/status.
        const samples = history.samples();
        const body = JSON.stringify({ cap: history.cap, count: samples.length, samples });
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        return res.end(body);
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, err: "no-route" }));
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, err: "status-error:" + e.message }));
    }
  });
}

async function main() {
  const cfg = configFromEnv();
  if (!cfg.bootnodeUrl && !cfg.bootnodeOnion) {
    console.error("set SHADE_TREE_BOOTNODE_URL (dev) or SHADE_TREE_BOOTNODE_ONION (Tor). See web/README.md");
    process.exit(1);
  }
  if (!cfg.dirSigner) console.warn("warning: SHADE_TREE_DIR_SIGNER unset -- signature will not be verified (signerOk=false)");
  const server = makeStatusServer(cfg);
  server.listen(cfg.port, "127.0.0.1", () => {
    const target = cfg.bootnodeUrl || cfg.bootnodeOnion;
    console.log(`status page up on http://127.0.0.1:${cfg.port}  (bootnode=${target})`);
    console.log(`  GET /            the HTML status page`);
    console.log(`  GET /api/status  the JSON summary`);
    console.log(`  GET /api/history the bounded in-memory trend buffer (last ${HISTORY_CAP} samples)`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
