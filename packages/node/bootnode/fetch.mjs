// Client side of discovery: fetch the live directory from the bootnode onion over Tor.
//
// The bootnode is itself a v3 onion service, so the client reaches it the same way it reaches
// a gateway — a SOCKS dial through the local Tor daemon, no exit node, the bootnode never
// learns the client IP. Inside the tunnel it speaks plain HTTP/1.1 (the onion layer already
// provides the encryption and authentication). The returned JSON is then handed to
// packages/node/lib/directory.mjs verifyDirectory(), so a lying or MITM'd bootnode cannot forge an entry.
//
// Onion services cold-start slowly right after publication (descriptor propagation), so the
// dial retries a few times, exactly like packages/node/client/shade-tree-client.mjs.

import { SocksClient } from "socks";

export async function fetchOverTor(onion, path, opts = {}) {
  return requestOverTor(onion, { method: "GET", path, ...opts });
}

// POST a JSON body to the bootnode onion over Tor (used by the gateway heartbeat).
export async function postOverTor(onion, path, body, opts = {}) {
  return requestOverTor(onion, { method: "POST", path, body, ...opts });
}

// The client's ingress from the bootnode is only SEMI-trusted: a lying or MITM'd bootnode
// cannot forge a verified entry, but it CAN try to exhaust the long-running client/heartbeat by
// streaming an unbounded body. Cap the response so a hostile bootnode gets a bounded read, not an
// OOM. A signed directory is tiny (~a few hundred bytes/entry); 2 MB is generous headroom.
const MAX_RESP = Number(process.env.SHADE_TREE_BOOTNODE_MAX_RESP || 2 * 1024 * 1024);

export async function requestOverTor(onion, { method = "GET", path = "/", body = null, torHost = "127.0.0.1", torPort = 9250, destinationPort = 80, timeoutMs = 20000, attempts = 4, maxBytes = MAX_RESP, authorization = null, socksClient = SocksClient } = {}) {
  const host = onion.replace(/\.onion$/, "") + ".onion";
  if (!Number.isSafeInteger(Number(destinationPort)) || Number(destinationPort) < 1 || Number(destinationPort) > 65535) {
    throw new Error("invalid onion destination port");
  }
  destinationPort = Number(destinationPort);
  if (authorization != null && (typeof authorization !== "string" || !/^[\x20-\x7e]{1,512}$/.test(authorization))) {
    throw new Error("invalid authorization header");
  }
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await once(host, method, path, body, { torHost, torPort, destinationPort, timeoutMs, maxBytes, authorization, socksClient });
    } catch (e) {
      // The bootnode answered and said no (4xx other than 408/429): asking again in a second
      // gets the same answer. Hand the refusal back as is, status and reply attached.
      if (isRefusal(e)) throw e;
      lastErr = e;
      await sleep(Math.min(1000 * (i + 1), 4000)); // back off through onion cold-start
    }
  }
  throw new Error(`bootnode ${method} failed after ${attempts} attempts: ${lastErr?.message || lastErr}`);
}

function once(host, method, path, body, { torHost, torPort, destinationPort, timeoutMs, maxBytes = MAX_RESP, authorization = null, socksClient }) {
  return new Promise((resolve, reject) => {
    let socket;
    const payload = body == null ? null : Buffer.from(JSON.stringify(body), "utf8");
    const timer = setTimeout(() => { try { socket?.destroy(); } catch {} reject(new Error("timeout")); }, timeoutMs);
    socksClient.createConnection({
      proxy: { host: torHost, port: torPort, type: 5 },
      command: "connect",
      destination: { host, port: destinationPort },
      // The socks library gives up after 30 s by default, which fired before timeoutMs (the
      // probe's documented 60 s) and cut a cold onion dial short.
      timeout: timeoutMs,
    })
      .then(({ socket: s }) => {
        socket = s;
        let buf = Buffer.alloc(0);
        s.on("data", (c) => {
          buf = Buffer.concat([buf, c]);
          if (buf.length > maxBytes) { clearTimeout(timer); try { s.destroy(); } catch {} reject(new Error(`bootnode response exceeded ${maxBytes} bytes`)); }
        });
        s.on("end", () => { clearTimeout(timer); try { resolve(parseHttp(buf)); } catch (e) { reject(e); } });
        s.on("error", (e) => { clearTimeout(timer); reject(e); });
        const authority = destinationPort === 80 ? host : `${host}:${destinationPort}`;
        let req = `${method} ${path} HTTP/1.1\r\nHost: ${authority}\r\nConnection: close\r\nAccept: application/json\r\n`;
        if (payload) req += `Content-Type: application/json\r\nContent-Length: ${payload.length}\r\n`;
        if (authorization) req += `Authorization: ${authorization}\r\n`;
        req += "\r\n";
        s.write(req);
        if (payload) s.write(payload);
      })
      .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

// Minimal HTTP/1.1 response parse. The bootnode always sends a Content-Length body (never
// chunked), and we close the connection per request, so header/body split is enough.
export function parseHttp(buf) {
  const sep = buf.indexOf("\r\n\r\n");
  if (sep === -1) throw new Error("no HTTP header terminator");
  const head = buf.subarray(0, sep).toString("utf8");
  const status = Number(head.split("\r\n")[0].split(" ")[1]);
  const body = buf.subarray(sep + 4).toString("utf8");
  if (status !== 200) {
    const err = new Error(`bootnode HTTP ${status}: ${body.slice(0, 200)}`);
    err.status = status;
    try { err.reply = JSON.parse(body); } catch { err.reply = null; }
    throw err;
  }
  return JSON.parse(body);
}

// A refusal is an answer, not a transport failure: the bootnode spoke HTTP and declined with a
// 4xx. 408 and 429 ask the caller to come back, so they stay retryable.
export function isRefusal(e) {
  const s = Number(e?.status);
  return s >= 400 && s < 500 && s !== 408 && s !== 429;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
