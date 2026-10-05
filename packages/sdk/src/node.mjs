// Node entry (`@shadenet/sdk/node`): everything in the isomorphic entry plus egress.
//
// Two ways out, both typed with ShadeNetError codes:
//   - through a local `shadenet` proxy (the Rust daemon; recommended): proxyConnect / proxyFetch
//   - in process over a Tor SOCKS port with the JS client: createClient(...).connect / .fetch

import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { ShadeTreeClient } from "../../node/client/shade-tree-client.mjs";
import { ShadeNetError, ERROR_CODES, toShadeNetError } from "./errors.mjs";
import { DEFAULT_DAEMON } from "./status.mjs";
import { setDefaultArtifacts } from "./exit-proof.mjs";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

export * from "./index.mjs";
// Identity files from disk, including the passphrase-protected form `shadenet init --passphrase`
// writes (the isomorphic importIdentity reads the plaintext form only). Both return an identity
// createClient({ identity }) takes.
export { openIdentity, readIdentityFile } from "../../node/lib/identity-file.mjs";

// In Node, exit and withdraw proofs default to the committed withdraw circuit: circuits/ sits at
// the repo root in a checkout (src/ is three levels down) and at the package root when published
// (dist/ is one level down).
const circuitsDir = ["../circuits/rln/", "../../../circuits/rln/"]
  .map((rel) => fileURLToPath(new URL(rel, import.meta.url)))
  .find((dir) => existsSync(`${dir}withdraw.wasm`));
if (circuitsDir) setDefaultArtifacts({ wasm: `${circuitsDir}withdraw.wasm`, zkey: `${circuitsDir}withdraw_final.zkey` });

// Proxy refusals, as the Rust proxy reports them (roadmap M3 AGENT-1): an HTTP status plus an
// optional `X-ShadeNet-Error` header naming the code. The status alone is the fallback.
const STATUS_CODES = { 403: "NotAdmitted", 429: "BudgetExhausted", 502: "NodeRefused", 503: "NoEligibleNode" };

function proxyRefusal(res, target) {
  const named = res.headers["x-shadenet-error"];
  const code = ERROR_CODES.includes(named) ? named : STATUS_CODES[res.statusCode] ?? "Transport";
  const retryAfter = Number(res.headers["retry-after"]);
  return new ShadeNetError(code, `proxy refused CONNECT ${target}: HTTP ${res.statusCode}${named ? ` (${named})` : ""}`, {
    status: res.statusCode,
    retryAfterMs: Number.isFinite(retryAfter) ? retryAfter * 1000 : undefined,
  });
}

function splitTarget(target) {
  const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(String(target));
  if (!m) throw new ShadeNetError("InvalidInput", `target must be host:port, got ${target}`);
  return { host: m[1], port: Number(m[2]) };
}

// Open a raw tunnel to host:port through the local proxy. Resolves to a connected net.Socket.
export function proxyConnect(target, { proxy = DEFAULT_DAEMON, token, timeoutMs = 120_000 } = {}) {
  const { host, port } = splitTarget(target);
  const p = new URL(proxy);
  const headers = { host: `${host}:${port}` };
  if (token) headers["proxy-authorization"] = `Bearer ${token}`;
  return new Promise((resolve, reject) => {
    const req = http.request({ host: p.hostname, port: Number(p.port || 80), method: "CONNECT", path: `${host}:${port}`, headers, timeout: timeoutMs });
    req.once("connect", (res, socket, head) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        reject(proxyRefusal(res, `${host}:${port}`));
        return;
      }
      if (head?.length) socket.unshift(head);
      resolve(socket);
    });
    req.once("timeout", () => req.destroy(new Error(`proxy CONNECT timed out after ${timeoutMs} ms`)));
    req.once("error", (cause) => reject(new ShadeNetError("Transport", `could not reach the shadenet proxy at ${proxy}: ${cause.message}`, { cause })));
    req.end();
  });
}

// HTTPS GET/POST through the local proxy. Resolves { status, headers, body: Buffer }.
export async function proxyFetch(url, { proxy = DEFAULT_DAEMON, token, method = "GET", headers = {}, body, maxBodyBytes = 8 * 1024 * 1024, timeoutMs = 120_000 } = {}) {
  const u = new URL(url);
  if (u.protocol !== "https:") throw new ShadeNetError("PortNotAllowed", "shadenet egresses HTTPS only");
  const port = Number(u.port || 443);
  const raw = await proxyConnect(`${u.hostname}:${port}`, { proxy, token, timeoutMs });
  const socket = tls.connect({ socket: raw, servername: u.hostname });
  return new Promise((resolve, reject) => {
    const req = https.request({ method, host: u.hostname, port, path: `${u.pathname}${u.search}`, headers, createConnection: () => socket, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > maxBodyBytes) res.destroy(new Error(`response over ${maxBodyBytes} bytes`));
        else chunks.push(c);
      });
      res.once("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.once("error", (cause) => reject(new ShadeNetError("Transport", cause.message, { cause })));
    });
    req.once("timeout", () => req.destroy(new Error(`request timed out after ${timeoutMs} ms`)));
    req.once("error", (cause) => reject(cause instanceof ShadeNetError ? cause : new ShadeNetError("Transport", cause.message, { cause })));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

// In-process client over a Tor SOCKS port (the JS client). Options are ShadeTreeClient's:
// { secret | identity | identityFile, limit, network, torHost, torPort, leafSource, ... }; an
// identity file is the one `shadenet init` writes. Errors come back as ShadeNetError.
export function createClient(options = {}) {
  let inner;
  try {
    inner = new ShadeTreeClient(options);
  } catch (e) {
    throw toShadeNetError(e);
  }
  const guard = async (fn) => {
    try {
      return await fn();
    } catch (e) {
      throw toShadeNetError(e);
    }
  };
  return {
    inner,
    connect: (target, opts) => guard(() => inner.connect(target, opts)),
    fetch: (url, opts) => guard(() => inner.fetch(url, opts)),
    leafSource: () => guard(() => inner.leafSource()),
  };
}
