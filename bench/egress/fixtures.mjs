// Loopback fixtures for the egress benchmark selftests. Nothing here reaches the network:
// every server binds 127.0.0.1 on an ephemeral port and the proxies only dial 127.0.0.1.
//
//   startOrigin()        HTTP origin that serves canned pages modelled on real walls
//   startConnectProxy()  HTTP CONNECT proxy (the shape of the ShadeNet member Proxy)
//   startSocks5()        minimal SOCKS5 (no auth, CONNECT only), the shape of Tor's SocksPort
//   startHostile(mode)   a "proxy" that misbehaves in one specific way
//   startTorControl()    a fake Tor control port
//   startTlsOrigin()     HTTPS origin with a throwaway self-signed cert minted by openssl at
//                        test time (returns null when openssl is missing; callers skip)

import http from "node:http";
import https from "node:https";
import net from "node:net";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));

// Each page is a tiny caricature of what the real wall serves, enough for the classifier's
// rules. They are written from the November 2026 captures, not copied from any site.
export const PAGES = {
  "/ok": { code: 200, headers: { server: "fixture" }, body: '<html><head><title>Fixture Home</title></head><body><div id="fixture-ok">real page</div>' + "x".repeat(2000) + "</body></html>" },
  "/cf-challenge": { code: 403, headers: { server: "cloudflare", "cf-ray": "0-FIX", "cf-mitigated": "challenge" }, body: "<html><head><title>Just a moment...</title></head><body>cf-chl-opt</body></html>" },
  "/rate": { code: 429, headers: { "retry-after": "60" }, body: "<html><title>Too Many Requests</title></html>" },
  "/deny": { code: 403, headers: {}, body: "<html><head><title>Access Denied</title></head><body>no</body></html>" },
  "/datadome": { code: 403, headers: { "x-datadome": "protected", server: "fixture" }, body: '<html><script src="https://geo.captcha-delivery.com/captcha/"></script></html>' },
  "/amazon-stub": { code: 200, headers: {}, body: '<html><head><title>Amazon.com</title></head><body><div id="nav-logo"></div>Click the button below to continue shopping</body></html>' },
  "/cf-202": { code: 202, headers: { "x-amz-cf-id": "fix", server: "CloudFront" }, body: "" },
  "/empty": { code: 200, headers: {}, body: "<html></html>" },
  "/nomarker": { code: 200, headers: {}, body: "<html><title>Something else</title>" + "y".repeat(1000) + "</html>" },
  "/boom": { code: 503, headers: {}, body: "upstream down" },
  "/api": { code: 401, headers: { "content-type": "application/json" }, body: '{"error":{"code":"invalid_api_key"}}' },
  "/ip": { code: 200, headers: { "content-type": "application/json" }, body: '{"ip":"203.0.113.7","org":"AS64500 Example Net","country":"ZZ"}' },
};

export async function startOrigin() {
  const hits = new Map();
  const srv = http.createServer((req, res) => {
    const path = req.url.split("?")[0];
    hits.set(path, (hits.get(path) || 0) + 1);
    if (path === "/redirect") { res.writeHead(302, { location: "/ok" }); return res.end(); }
    if (path === "/loop") { res.writeHead(302, { location: "/loop" }); return res.end(); }
    if (path === "/badloc") { res.writeHead(302, { location: "http://[::1" }); return res.end(); }
    if (path === "/slow") { setTimeout(() => { try { res.end("late"); } catch { /* closed */ } }, 30_000).unref(); return; }
    if (path === "/gzip") {
      const body = zlib.gzipSync(Buffer.from(PAGES["/ok"].body));
      res.writeHead(200, { "content-encoding": "gzip", "content-length": body.length });
      return res.end(body);
    }
    if (path === "/badgzip") { res.writeHead(200, { "content-encoding": "gzip" }); return res.end("not gzip at all"); }
    if (path === "/big") {
      res.writeHead(200, { "content-type": "text/html" });
      const chunk = Buffer.alloc(1 << 16, 97);
      let sent = 0;
      const pump = () => { while (sent < 20 * (1 << 20)) { sent += chunk.length; if (!res.write(chunk)) return res.once("drain", pump); } res.end(); };
      res.on("error", () => {});
      return pump();
    }
    if (path === "/ua") { res.writeHead(200, { "content-type": "text/plain" }); return res.end(`<title>ua</title>ua=${req.headers["user-agent"] || ""}`); }
    const p = PAGES[path];
    if (!p) { res.writeHead(404); return res.end("nope"); }
    res.writeHead(p.code, p.headers);
    res.end(p.body);
  });
  const port = await listen(srv);
  return { port, url: (p) => `http://127.0.0.1:${port}${p}`, hits, close: () => closeAll(srv) };
}

function closeAll(srv) {
  return new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); });
}

// Only loopback targets: a test bug can never turn the fixture into an open proxy.
// ONLY_VIA_EXIT is a name that does not resolve anywhere (.invalid, RFC 6761) except inside
// these fixture proxies, which map it to 127.0.0.1. A request for it can only succeed if it
// really went through the exit, so a client that silently dials direct fails the test.
export const ONLY_VIA_EXIT = "via-exit.invalid";
function loopbackTarget(host) { return host === "127.0.0.1" || host === "localhost" || host === ONLY_VIA_EXIT; }

export async function startConnectProxy({ delayMs = 0 } = {}) {
  const log = [];
  const socks = new Set();
  const srv = net.createServer((c) => {
    socks.add(c);
    c.on("close", () => socks.delete(c));
    c.on("error", () => {});
    let head = "";
    const onData = (d) => {
      head += d.toString("latin1");
      const end = head.indexOf("\r\n\r\n");
      if (end === -1) return;
      c.off("data", onData);
      const m = /^CONNECT ([^\s:]+):(\d+) HTTP\/1\.[01]/.exec(head);
      if (!m || !loopbackTarget(m[1])) { c.end("HTTP/1.1 403 Forbidden\r\n\r\n"); log.push({ refused: true }); return; }
      log.push({ host: m[1], port: Number(m[2]) });
      setTimeout(() => {
        const up = net.createConnection({ host: "127.0.0.1", port: Number(m[2]) }, () => {
          c.write("HTTP/1.1 200 Connection established\r\n\r\n");
          const rest = head.slice(end + 4);
          if (rest) up.write(Buffer.from(rest, "latin1"));
          c.pipe(up); up.pipe(c);
        });
        up.on("error", () => { try { c.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch { /* gone */ } });
        socks.add(up); up.on("close", () => socks.delete(up));
      }, delayMs);
    };
    c.on("data", onData);
  });
  const port = await listen(srv);
  return { port, log, close: () => { for (const s of socks) s.destroy(); return new Promise((r) => srv.close(() => r())); } };
}

export async function startSocks5() {
  const log = [];
  const socks = new Set();
  const srv = net.createServer((c) => {
    socks.add(c); c.on("close", () => socks.delete(c)); c.on("error", () => {});
    let buf = Buffer.alloc(0);
    let stage = 0;
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        if (buf[0] !== 5) return c.destroy();
        buf = buf.subarray(2 + buf[1]);
        c.write(Buffer.from([5, 0]));
        stage = 1;
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        const atyp = buf[3];
        let host; let off;
        if (atyp === 1) { if (buf.length < 10) return; host = [...buf.subarray(4, 8)].join("."); off = 8; }
        else if (atyp === 3) { const n = buf[4]; if (buf.length < 5 + n + 2) return; host = buf.subarray(5, 5 + n).toString(); off = 5 + n; }
        else return c.destroy();
        const port = buf.readUInt16BE(off);
        const rest = buf.subarray(off + 2);
        c.off("data", onData);
        log.push({ host, port });
        if (!loopbackTarget(host)) { c.end(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        const up = net.createConnection({ host: "127.0.0.1", port }, () => {
          c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          if (rest.length) up.write(rest);
          c.pipe(up); up.pipe(c);
        });
        socks.add(up); up.on("close", () => socks.delete(up));
        up.on("error", () => c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])));
      }
    };
    c.on("data", onData);
  });
  const port = await listen(srv);
  return { port, log, close: () => { for (const s of socks) s.destroy(); return new Promise((r) => srv.close(() => r())); } };
}

// mode: "garbage" (non-HTTP reply) | "huge" (endless head) | "close" (hang up) | "407" | "silent"
export async function startHostile(mode) {
  const socks = new Set();
  const srv = net.createServer((c) => {
    socks.add(c); c.on("close", () => socks.delete(c)); c.on("error", () => {});
    c.once("data", () => {
      if (mode === "garbage") c.end("SSH-2.0-OpenSSH_9.6\r\n\r\n");
      else if (mode === "huge") { const junk = "X-Junk: " + "a".repeat(1000) + "\r\n"; c.write("HTTP/1.1 200 OK\r\n"); for (let i = 0; i < 40; i++) c.write(junk); }
      else if (mode === "close") c.destroy();
      else if (mode === "407") c.end("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
      // silent: never answer
    });
  });
  const port = await listen(srv);
  return { port, close: () => { for (const s of socks) s.destroy(); return new Promise((r) => srv.close(() => r())); } };
}

// reply: "ok" (250 x2) | "bad-auth" (515) | "silent"
export async function startTorControl(reply = "ok") {
  const got = [];
  const srv = net.createServer((c) => {
    c.on("error", () => {});
    c.on("data", (d) => {
      got.push(d.toString());
      if (reply === "ok") c.write("250 OK\r\n250 OK\r\n250 closing connection\r\n");
      else if (reply === "bad-auth") c.end("515 Authentication failed\r\n");
      else if (reply === "flood") c.write("650 " + "z".repeat(5000) + "\r\n");
    });
  });
  const port = await listen(srv);
  return { port, got, close: () => new Promise((r) => { srv.close(() => r()); }) };
}

export async function startTlsOrigin() {
  let dir;
  try {
    dir = mkdtempSync(join(tmpdir(), "egress-tls-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
  } catch {
    if (dir) rmSync(dir, { recursive: true, force: true });
    return null;
  }
  const key = readFileSync(join(dir, "k.pem"));
  const cert = readFileSync(join(dir, "c.pem"));
  rmSync(dir, { recursive: true, force: true });
  const srv = https.createServer({ key, cert }, (req, res) => {
    const p = PAGES[req.url.split("?")[0]] || PAGES["/ok"];
    res.writeHead(p.code, p.headers); res.end(p.body);
  });
  const port = await listen(srv);
  return { port, ca: cert, url: (p) => `https://localhost:${port}${p}`, close: () => closeAll(srv) };
}
