// The Shade Tree client proxy: a local HTTP CONNECT proxy that adds a reputation proof and routes to
// a gateway onion over Tor. It is a thin front-end over client/shade-tree-client.mjs — proving,
// slot/gateway rotation, deterministic retry, Tor dialing, and tunneling all live in
// ShadeTreeClient. Run the proxy when you want unmodified tools to use the Grove:
//
//   HTTPS_PROXY=http://127.0.0.1:8888 curl https://example.com
//   curl -x http://127.0.0.1:8888 https://api.ipify.org
//
// Application code may also use ShadeTreeClient directly, but CONNECT is the stable integration
// surface for agents and existing HTTP clients.
//
// Two anti-correlation rotations run together (docs/NEXT-VERSION.md B), inside ShadeTreeClient:
// a different gateway onion per CONNECT tunnel and a different per-tunnel slot nullifier. The
// deterministic-retry invariant (same signal reused across failover) also lives there.

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ShadeTreeClient, makeSlotPool, buildEnvelope } from "./shade-tree-client.mjs";
import { createLogger } from "../lib/log.mjs";
import { makeRegistry, installRuntimeMetrics, listenMetrics, safeMetricsPort } from "../lib/metrics.mjs";
import { printOperatorBanner } from "../lib/operator-ui.mjs";

// Re-exported for the selftest + any caller that historically imported them from the shim.
export { makeSlotPool, buildEnvelope };

const LISTEN_PORT = Number(process.env.SHADE_TREE_SHIM_PORT || 8888);
const HERE = dirname(fileURLToPath(import.meta.url));
const log = createLogger("proxy");
const metrics = makeRegistry();

function makeProxyMetrics(reg) {
  return {
    tunnels: reg.counter("shade_tree_proxy_tunnels_total", "Local Proxy CONNECT tunnels by result=opened|failed and bounded reason."),
    active: reg.gauge("shade_tree_proxy_active_tunnels", "Open local Proxy tunnels."),
    connect: reg.histogram("shade_tree_proxy_connect_seconds", "End-to-end Proxy tunnel setup latency in seconds."),
    prove: reg.histogram("shade_tree_proxy_proof_seconds", "Local proof construction latency in seconds."),
    dial: reg.histogram("shade_tree_proxy_tor_dial_seconds", "Tor-to-node dial latency in seconds."),
    failovers: reg.counter("shade_tree_proxy_failovers_total", "Node dial failures that caused local failover."),
    canopy: reg.counter("shade_tree_proxy_canopy_refresh_total", "Live Canopy refresh events by result=query|verified|cache|error."),
    candidates: reg.gauge("shade_tree_proxy_candidates", "Candidates in the last verified local selection."),
  };
}

export function proxyFailureLabel(error) {
  if (error?.code === "SHADE_TREE_LOCAL_CLIENT_CLOSED") return "client-closed";
  if (error?.code === "SHADE_TREE_EPOCH_BUDGET_EXHAUSTED") return "epoch-budget";
  if (/^SHADE_TREE_SLOT_STATE_/.test(String(error?.code || ""))) return "slot-state";
  if (/^SHADE_TREE_GATEWAY_(?:ACK|WRITE)_/.test(String(error?.code || ""))) return "node-ack-failed";
  const value = String(error?.message || error || "internal").toLowerCase();
  if (value.includes("gate refused")) return "gate-refused";
  if (value.includes("version")) return "version-mismatch";
  if (value.includes("artifact")) return "artifact-mismatch";
  if (value.includes("directory") || value.includes("canopy")) return "canopy-unavailable";
  if (value.includes("proof") || value.includes("not in group")) return "proof-failed";
  if (value.includes("no gateway") || value.includes("no node")) return "no-node";
  if (value.includes("socks") || value.includes("tor") || value.includes("connect")) return "tor-dial-failed";
  return "internal";
}

function observeClientEvents(M, logger, now) {
  let proofStarted = 0;
  return (event) => {
    if (!event || typeof event !== "object") return;
    if (event.phase === "canopy" && ["query", "verified", "cache", "error"].includes(event.status)) {
      M.canopy.inc({ result: event.status });
      if (["verified", "cache"].includes(event.status) && Number.isFinite(Number(event.count))) M.candidates.set(Number(event.count));
    }
    if (event.phase === "select" && event.status === "done") {
      M.candidates.set(Array.isArray(event.candidates) ? event.candidates.length : 0);
      logger.debug("node selection ready", { candidates: Array.isArray(event.candidates) ? event.candidates.length : 0, leafSource: event.leafSource || "unknown", maxAnon: Boolean(event.maxAnon) });
    }
    if (event.phase === "prove" && event.status === "start") proofStarted = now();
    if (event.phase === "prove" && ["done", "error"].includes(event.status) && proofStarted) {
      M.prove.observe((now() - proofStarted) / 1000);
      proofStarted = 0;
    }
    if (event.phase === "dial" && event.status === "done" && Number.isFinite(Number(event.latencyMs))) {
      M.dial.observe(Number(event.latencyMs) / 1000);
    }
    if (event.phase === "dial" && event.status === "failover") M.failovers.inc();
  };
}

// The transport boundary is injectable so lifecycle races can be exercised without a Tor dial.
// Production passes the real ShadeTreeClient and process-local operator instrumentation.
export function makeProxyServer(client, { reg = metrics, logger = log, now = () => performance.now() } = {}) {
  const M = makeProxyMetrics(reg);
  let activeTunnels = 0;
  M.active.setCollect(() => activeTunnels);
  const server = http.createServer();

  // Plain HTTP has no end-to-end TLS and is deliberately unsupported. `shade-tree run` sets
  // HTTP_PROXY to this listener as well as HTTPS_PROXY so accidental plaintext requests fail here
  // instead of silently taking a direct route.
  server.on("request", (_req, res) => {
    res.writeHead(403, { "content-type": "text/plain; charset=utf-8", connection: "close" });
    res.end("Shade Tree accepts HTTPS CONNECT tunnels only.\n");
  });

  server.on("connect", async (req, clientSocket, head) => {
    const target = req.url; // "host:port"
    const started = now();
    let counted = false;
    let localClosed = clientSocket.destroyed || clientSocket.readableEnded;
    const markLocalClosed = () => {
      localClosed = true;
      if (counted) { counted = false; activeTunnels = Math.max(0, activeTunnels - 1); }
    };
    clientSocket.once("end", markLocalClosed);
    clientSocket.once("close", markLocalClosed);
    logger.debug("tunnel requested");
    try {
      // ShadeTreeClient.connect builds one proof, picks a gateway (rotation + failover), dials it
      // over Tor, sends the envelope, checks the ack, and returns a raw tunnel to the target.
      // TLS stays end-to-end client<->target.
      const tunnel = await client.connect(target, {
        // T-FEAT-9: record only the leaf-source class and candidate count. Node identities stay
        // out of the operator log even though the local selection event contains them.
        onEvent: observeClientEvents(M, logger, now),
      });

      if (localClosed || clientSocket.destroyed || clientSocket.readableEnded) {
        tunnel.destroy();
        const error = new Error("local client closed before the tunnel was ready");
        error.code = "SHADE_TREE_LOCAL_CLIENT_CLOSED";
        throw error;
      }
      M.connect.observe((now() - started) / 1000);
      M.tunnels.inc({ result: "opened", reason: "none" });
      activeTunnels += 1;
      counted = true;
      clientSocket.write("HTTP/1.1 200 Connection established\r\n\r\n");
      if (head && head.length) tunnel.write(head);
      clientSocket.pipe(tunnel);
      tunnel.pipe(clientSocket);
      clientSocket.on("error", () => tunnel.destroy());
      tunnel.on("error", () => clientSocket.destroy());
      logger.debug("tunnel opened");
    } catch (e) {
      const msg = String(e.message || e);
      const reason = proxyFailureLabel(e);
      M.connect.observe((now() - started) / 1000);
      M.tunnels.inc({ result: "failed", reason });
      try { clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n${msg}\n`); } catch {}
      clientSocket.destroy();
      // Surface a bounded stage label at the default log level. The raw error can carry
      // a destination, onion, or provider response and must stay out of operator logs.
      if (reason === "client-closed") logger.debug("tunnel canceled", { reason });
      else logger.warn("tunnel failed", { reason });
    }
  });

  return server;
}

async function startClientProxy() {
  if (!process.env.SHADE_TREE_SECRET) {
    log.error("set SHADE_TREE_SECRET (from `shade-tree enroll`) before starting the Proxy");
    process.exit(1);
  }

  const pkg = JSON.parse(await readFile(join(HERE, "..", "package.json"), "utf8"));
  installRuntimeMetrics(metrics, { role: "proxy", version: pkg.version });

  // One client (one slot pool) for the whole proxy; it reads the SHADE_TREE_* client environment
  // (SHADE_TREE_SECRET, SHADE_TREE_ONION | SHADE_TREE_DIRECTORY+SHADE_TREE_DIR_SIGNER, SHADE_TREE_TOR_HOST/PORT).
  const client = new ShadeTreeClient();
  const server = makeProxyServer(client);

  const metricsPort = safeMetricsPort(process.env.SHADE_TREE_METRICS_PORT, [["Proxy backend", LISTEN_PORT]]);
  let metricsServer = null;
  if (metricsPort > 0) {
    metricsServer = listenMetrics({ port: metricsPort, reg: metrics, host: "127.0.0.1", ready: () => server.listening });
    await new Promise((resolve, reject) => {
      metricsServer.once("listening", resolve);
      metricsServer.once("error", reject);
    });
    log.info("operator metrics ready", { event: "metrics.ready", listen: `127.0.0.1:${metricsPort}` });
  }

  server.on("error", (error) => {
    log.error(error.code === "EADDRINUSE"
      ? `port ${LISTEN_PORT} is already in use; stop the other Proxy or set SHADE_TREE_SHIM_PORT`
      : "Proxy listener failed", { event: "service.failed", code: error.code || "UNKNOWN" });
    process.exit(1);
  });
  server.listen(LISTEN_PORT, "127.0.0.1", () => {
    const mode = client.onion ? "pinned node" : "Canopy rotation";
    printOperatorBanner({ role: "proxy", rows: [
      ["listen", `127.0.0.1:${LISTEN_PORT}`],
      ["route", `Tor ${client.torHost}:${client.torPort}`],
      ["mode", mode],
      ["metrics", metricsPort > 0 ? `127.0.0.1:${metricsPort}` : "off"],
      ["logs", `${process.env.SHADE_TREE_LOG_LEVEL || "info"} / ${process.env.SHADE_TREE_LOG_FORMAT || "auto"}`],
    ] });
    log.info("Proxy ready", { event: "service.ready", listen: `127.0.0.1:${LISTEN_PORT}`, mode, maxAnon: client.maxAnon, metricsPort });
    log.debug("Proxy usage", { example: `curl -x http://127.0.0.1:${LISTEN_PORT} https://example.com` });
  });
}

// Only stand up the server when run directly; importing pulls the re-exported helpers.
if (import.meta.url === `file://${process.argv[1]}`) {
  startClientProxy().catch((error) => { log.error("Proxy failed", { event: "service.failed", err: error }); process.exit(1); });
}
