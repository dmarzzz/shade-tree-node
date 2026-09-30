// Buyer-side HTTP: reach the registrar either through the local Tor SOCKS (an onion:port, the
// production path — the registrar never learns the buyer's IP) or a plain URL (tests, a local
// registrar). Unlike packages/node/bootnode/fetch.mjs this returns status + headers + body for ANY status,
// because 402 is the happy path here and the protocol lives in the headers
// (PAYMENT-REQUIRED / WWW-Authenticate / PAYMENT-RESPONSE / Payment-Receipt).
//
// request({ onion, port, url, method, path, headers, body, torHost, torPort, timeoutMs, attempts })
//   -> { status, headers: { lower-name: string | string[] }, body: string, json: object|null }
// Repeated header lines (several WWW-Authenticate challenges) are returned as an array.

import { SocksClient } from "socks";

const MAX_RESP = 256 * 1024;

export async function request({ onion = null, port = 8878, url = null, method = "GET", path = "/", headers = {}, body = null,
    torHost = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1", torPort = Number(process.env.SHADE_TREE_TOR_PORT || 9250),
    timeoutMs = 30000, attempts = 3 } = {}) {
  if (url) return viaFetch(url.replace(/\/$/, "") + path, method, headers, body, timeoutMs);
  if (!onion) throw new Error("request: onion or url required");
  const host = String(onion).replace(/\.onion$/, "") + ".onion";
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try { return await onceOverTor(host, port, method, path, headers, body, { torHost, torPort, timeoutMs }); }
    catch (e) { lastErr = e; await new Promise((r) => setTimeout(r, Math.min(1500 * (i + 1), 5000))); }
  }
  throw new Error(`registrar ${method} ${path} failed after ${attempts} attempts: ${lastErr?.message || lastErr}`);
}

async function viaFetch(fullUrl, method, headers, body, timeoutMs) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const payload = body == null ? undefined : (Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body), "utf8"));
    const res = await fetch(fullUrl, { method, headers: { ...(payload ? { "content-type": "application/json" } : {}), ...headers }, body: payload, signal: ac.signal });
    const hdrs = {};
    // Node's fetch joins repeated headers with ", "; www-authenticate is exposed via getSetCookie-
    // like semantics only for set-cookie, so re-split Payment challenges on the scheme boundary.
    for (const [k, v] of res.headers) hdrs[k.toLowerCase()] = v;
    if (typeof hdrs["www-authenticate"] === "string") hdrs["www-authenticate"] = splitChallenges(hdrs["www-authenticate"]);
    const text = await res.text();
    return { status: res.status, headers: hdrs, body: text, json: safeJson(text) };
  } finally { clearTimeout(t); }
}

// A joined "Payment id=..., realm=..., Payment id=..." string -> ["Payment id=..., realm=...", ...].
export function splitChallenges(s) {
  const parts = String(s).split(/(?:^|,\s*)(?=Payment\s+id=)/).map((p) => p.trim()).filter(Boolean);
  return parts.length ? parts : [String(s)];
}

function onceOverTor(host, port, method, path, headers, body, { torHost, torPort, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let socket;
    const payload = body == null ? null : (Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body), "utf8"));
    const timer = setTimeout(() => { try { socket?.destroy(); } catch {} reject(new Error("timeout")); }, timeoutMs);
    SocksClient.createConnection({ proxy: { host: torHost, port: torPort, type: 5 }, command: "connect", destination: { host, port } })
      .then(({ socket: s }) => {
        socket = s;
        let buf = Buffer.alloc(0);
        s.on("data", (c) => {
          buf = Buffer.concat([buf, c]);
          if (buf.length > MAX_RESP) { clearTimeout(timer); try { s.destroy(); } catch {} reject(new Error(`response exceeded ${MAX_RESP} bytes`)); }
        });
        s.on("end", () => { clearTimeout(timer); try { resolve(parseHttp(buf)); } catch (e) { reject(e); } });
        s.on("error", (e) => { clearTimeout(timer); reject(e); });
        let req = `${method} ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: close\r\nAccept: application/json\r\n`;
        for (const [k, v] of Object.entries(headers)) req += `${k}: ${v}\r\n`;
        if (payload) req += `Content-Type: application/json\r\nContent-Length: ${payload.length}\r\n`;
        req += "\r\n";
        s.write(req);
        if (payload) s.write(payload);
      })
      .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

// Minimal HTTP/1.1 response parse (Content-Length bodies, Connection: close). Repeated headers
// -> array; single -> string.
export function parseHttp(buf) {
  const sep = buf.indexOf("\r\n\r\n");
  if (sep === -1) throw new Error("no HTTP header terminator");
  const lines = buf.subarray(0, sep).toString("utf8").split("\r\n");
  const status = Number(lines[0].split(" ")[1]);
  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i === -1) continue;
    const k = line.slice(0, i).trim().toLowerCase(); const v = line.slice(i + 1).trim();
    if (headers[k] === undefined) headers[k] = v;
    else headers[k] = Array.isArray(headers[k]) ? [...headers[k], v] : [headers[k], v];
  }
  const body = buf.subarray(sep + 4).toString("utf8");
  return { status, headers, body, json: safeJson(body) };
}
const safeJson = (t) => { try { return JSON.parse(t); } catch { return null; } };
