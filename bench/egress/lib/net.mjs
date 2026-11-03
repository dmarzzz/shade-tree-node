// Tunnel and fetch helpers for the egress benchmark: open a TCP stream to host:port through an
// exit (direct, HTTP CONNECT, SOCKS5), time each phase, and run one HTTP(S) GET over it.
//
// The `node` client and dial.mjs both use this, so "the time to open a tunnel through the
// member Proxy" means the same thing in both. The ShadeNet member Proxy does its work (pick a
// node, prove a slot, build the onion circuit) between our CONNECT and its "200", so
// `tTunnelMs` is exactly the dial cost an agent pays, before any TLS.
//
// Every byte read here comes from a remote party (the proxy, the site), so reads are bounded:
// a CONNECT response head is capped, a body is capped, redirects are capped, and every phase
// has a timeout. A hostile peer gets an error result, never a hang or a throw.

import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import zlib from "node:zlib";
import { SocksClient } from "socks";

export const MAX_CONNECT_HEAD = 16 * 1024;
export const MAX_BODY = 12 * 1024 * 1024;
export const MAX_REDIRECTS = 5;

const now = () => Number(process.hrtime.bigint()) / 1e6;

function hp(host, port) { return `${host.includes(":") ? `[${host}]` : host}:${port}`; }

// -> Promise<{ socket, tTcpMs, tTunnelMs, connectCode }>; rejects with Error{code} on failure.
//    code: timeout | connect-refused-<status> | bad-proxy-reply | proxy-closed | socks-<reason> | E*
export function openTunnel(exit, host, port, { timeoutMs = 45_000 } = {}) {
  const t0 = now();
  const type = exit ? exit.type : "direct";
  if (type === "socks5") {
    return SocksClient.createConnection({
      proxy: { host: exit.host, port: exit.port, type: 5 },
      command: "connect",
      destination: { host, port },
      timeout: timeoutMs,
    }).then(({ socket }) => {
      const t = now() - t0;
      return { socket, tTcpMs: null, tTunnelMs: t, connectCode: null };
    }, (e) => { throw tag(new Error(String(e.message || e).slice(0, 160)), "socks-" + socksReason(e)); });
  }
  return new Promise((resolve, reject) => {
    const target = type === "http" ? { host: exit.host, port: exit.port } : { host, port };
    const sock = net.createConnection(target);
    let tTcp = null;
    let settled = false;
    const fail = (code, msg) => { if (settled) return; settled = true; sock.destroy(); reject(tag(new Error(msg || code), code)); };
    const timer = setTimeout(() => fail("timeout", "tunnel timeout"), timeoutMs);
    // Before "connect" an error is about reaching the proxy itself, not the site: name it so a
    // report row says "the member Proxy was down", not a bare ECONNREFUSED.
    sock.once("error", (e) => { clearTimeout(timer); fail((type === "http" && tTcp === null ? "proxy-" : "") + (e.code || "error"), e.message); });
    sock.once("connect", () => {
      tTcp = now() - t0;
      if (type !== "http") {
        clearTimeout(timer); settled = true; sock.removeAllListeners("error");
        resolve({ socket: sock, tTcpMs: tTcp, tTunnelMs: tTcp, connectCode: null });
        return;
      }
      sock.write(`CONNECT ${hp(host, port)} HTTP/1.1\r\nHost: ${hp(host, port)}\r\n\r\n`);
      let head = Buffer.alloc(0);
      const onData = (d) => {
        head = Buffer.concat([head, d]);
        const end = head.indexOf("\r\n\r\n");
        if (end === -1) {
          if (head.length > MAX_CONNECT_HEAD) { clearTimeout(timer); fail("bad-proxy-reply", "CONNECT reply head too large"); }
          return;
        }
        sock.off("data", onData);
        sock.off("close", onClose);
        clearTimeout(timer);
        const m = /^HTTP\/1\.[01] (\d{3})/.exec(head.subarray(0, end).toString("latin1"));
        if (!m) return fail("bad-proxy-reply", "CONNECT reply is not HTTP");
        const code = Number(m[1]);
        if (code !== 200) return fail(`connect-refused-${code}`, `proxy answered ${code}`);
        // Bytes after the head belong to the tunnel; a CONNECT-only proxy should send none
        // before the client speaks TLS, but put any back so the stream stays intact.
        const extra = head.subarray(end + 4);
        if (extra.length) sock.unshift(extra);
        settled = true;
        sock.removeAllListeners("error");
        resolve({ socket: sock, tTcpMs: tTcp, tTunnelMs: now() - t0, connectCode: code });
      };
      const onClose = () => { clearTimeout(timer); fail("proxy-closed", "proxy closed before CONNECT reply"); };
      sock.on("data", onData);
      sock.once("close", onClose);
    });
  });
}

function socksReason(e) {
  const m = String(e && e.message || "").toLowerCase();
  if (m.includes("timeout") || m.includes("timed out")) return "timeout";
  if (m.includes("refused")) return "refused";
  if (m.includes("host unreachable")) return "host-unreachable";
  return "error";
}
function tag(e, code) { e.code = code; return e; }

// TLS on top of an open tunnel. -> Promise<{ tls, tTlsMs }>
export function startTls(socket, servername, { timeoutMs = 45_000, rejectUnauthorized = true, ca } = {}) {
  const t0 = now();
  return new Promise((resolve, reject) => {
    const s = tls.connect({ socket, servername: net.isIP(servername) ? undefined : servername, rejectUnauthorized, ca, ALPNProtocols: ["http/1.1"] });
    const timer = setTimeout(() => { s.destroy(); reject(tag(new Error("tls timeout"), "timeout")); }, timeoutMs);
    s.once("secureConnect", () => { clearTimeout(timer); resolve({ tls: s, tTlsMs: now() - t0 }); });
    s.once("error", (e) => { clearTimeout(timer); reject(tag(e, e.code || "tls-error")); });
  });
}

function decode(buf, enc) {
  const e = String(enc || "").toLowerCase().trim();
  try {
    if (e === "gzip" || e === "x-gzip") return zlib.gunzipSync(buf, { maxOutputLength: MAX_BODY });
    if (e === "br") return zlib.brotliDecompressSync(buf, { maxOutputLength: MAX_BODY });
    if (e === "deflate") return zlib.inflateSync(buf, { maxOutputLength: MAX_BODY });
  } catch { return null; }
  return buf;
}

// One GET over an exit, following up to MAX_REDIRECTS redirects (each hop is a new tunnel,
// as a browser would open). Never throws.
// -> { code, headers, body, finalUrl, t (s), transport, connectCode, tunnels }
export async function fetchVia(exit, url, { headers = {}, timeoutMs = 45_000, ca, maxBytes = MAX_BODY } = {}) {
  const t0 = now();
  let current = url;
  let tunnels = 0;
  let connectCode = null;
  const deadline = t0 + timeoutMs;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let u;
    try { u = new URL(current); } catch { return res(null, {}, "", current, "error:bad-redirect"); }
    if (u.protocol !== "http:" && u.protocol !== "https:") return res(null, {}, "", current, "error:bad-scheme");
    const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
    const left = () => Math.max(1, deadline - now());
    let r;
    try {
      const tun = await openTunnel(exit, u.hostname.replace(/^\[|\]$/g, ""), port, { timeoutMs: left() });
      tunnels++;
      connectCode = tun.connectCode ?? connectCode;
      let stream = tun.socket;
      if (u.protocol === "https:") stream = (await startTls(stream, u.hostname, { timeoutMs: left(), ca })).tls;
      r = await requestOver(stream, u, headers, left(), maxBytes);
    } catch (e) {
      return res(null, {}, "", current, e.code === "timeout" ? "timeout" : `error:${e.code || "error"}`);
    }
    if (r.code >= 300 && r.code < 400 && r.headers.location && hop < MAX_REDIRECTS) {
      try { current = new URL(r.headers.location, u).href; } catch { return res(r.code, r.headers, "", current, "error:bad-redirect"); }
      continue;
    }
    const body = decode(r.body, r.headers["content-encoding"]);
    if (body === null) return res(r.code, r.headers, "", current, "error:bad-encoding");
    return res(r.code, r.headers, body.toString("utf8"), current, null, r.truncated);
  }
  return res(null, {}, "", current, "error:too-many-redirects");

  function res(code, hdrs, body, finalUrl, transport, truncated = false) {
    return { code, headers: hdrs, body, finalUrl, t: (now() - t0) / 1000, transport, connectCode, tunnels, truncated };
  }
}

function requestOver(stream, u, headers, timeoutMs, maxBytes) {
  return new Promise((resolve, reject) => {
    // Plain http over the stream: TLS (if any) is already done by startTls, so https.request
    // would wrap a second TLS layer (and ignore our pinned CA).
    const req = http.request({
      method: "GET",
      host: u.hostname,
      port: u.port || undefined,
      path: u.pathname + u.search,
      headers: { host: u.host, connection: "close", "accept-encoding": "gzip, deflate, br", ...headers },
      // No `agent` key on purpose: with agent:false Node builds a fresh Agent that ignores
      // createConnection and dials the target directly, silently bypassing the exit.
      createConnection: () => stream,
    }, (resp) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      resp.on("data", (d) => {
        if (truncated) return;
        size += d.length;
        if (size > maxBytes) { truncated = true; resp.destroy(); finish(); return; }
        chunks.push(d);
      });
      resp.on("end", finish);
      resp.on("error", (e) => { if (!truncated) { clearTimeout(timer); reject(tag(e, e.code || "read-error")); } });
      let done = false;
      function finish() {
        if (done) return; done = true;
        clearTimeout(timer);
        const h = {};
        for (const [k, v] of Object.entries(resp.headers)) h[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
        resolve({ code: resp.statusCode, headers: h, body: Buffer.concat(chunks), truncated });
      }
    });
    const timer = setTimeout(() => { req.destroy(tag(new Error("timeout"), "timeout")); }, timeoutMs);
    req.on("error", (e) => { clearTimeout(timer); reject(tag(e, e.code || "request-error")); });
    req.end();
  });
}
