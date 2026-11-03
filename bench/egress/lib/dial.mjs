// Cold vs warm dial timing through an exit.
//
// cold = the first tunnel after the exit has been idle (the caller controls how long);
// warm = the next N tunnels right after it. Each probe opens a tunnel to the target, does TLS,
// sends one GET and reads the reply, timing each phase. The default target is a tiny "what is
// my IP" endpoint, so the number is the dial and not the page, and the body (the exit IP) shows
// whether the warm dials reused the cold dial's exit.
//
// Why this matters for ShadeNet: the member Proxy picks a node, proves an RLN slot and builds
// an onion circuit between our CONNECT and its 200. The first dial after idle pays for circuit
// build and descriptor fetch; an agent tool with a 30 s timeout loses that request if it is
// slow. The November 2026 run measured cold 5.9 to 30.1 s (median 13.7 s, n=5) and warm 0.9
// to 3.2 s (n=19) through the member Proxy.

import { openTunnel, startTls } from "./net.mjs";
import { isIP } from "node:net";
import http from "node:http";

export const MAX_PROBE_BODY = 4096;

const now = () => Number(process.hrtime.bigint()) / 1e6;
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);

// One probe. Never throws. -> {phase, tTunnelMs, tTlsMs, tTotalMs, code, connectCode, body, error}
export async function probe(exit, url, { phase = "warm", timeoutMs = 150_000, ca } = {}) {
  const t0 = now();
  const out = { type: "dial", phase, tTunnelMs: null, tTlsMs: null, tTotalMs: null, code: null, connectCode: null, body: null, error: null };
  let u;
  try { u = new URL(url); } catch { out.error = "bad-url"; return out; }
  if (!["http:", "https:"].includes(u.protocol)) { out.error = "bad-scheme"; return out; }
  const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
  try {
    const tun = await openTunnel(exit, u.hostname.replace(/^\[|\]$/g, ""), port, { timeoutMs });
    out.tTunnelMs = r1(tun.tTunnelMs);
    out.connectCode = tun.connectCode;
    let stream = tun.socket;
    if (u.protocol === "https:") {
      const t = await startTls(stream, u.hostname, { timeoutMs: Math.max(1, timeoutMs - (now() - t0)), ca });
      out.tTlsMs = r1(t.tTlsMs);
      stream = t.tls;
    }
    const r = await new Promise((resolve, reject) => {
      const req = http.request({ host: u.hostname, port, path: u.pathname + u.search, method: "GET",
        headers: { host: u.host, connection: "close", "user-agent": "curl/8", accept: "*/*" },
        createConnection: () => stream }, (resp) => {
        let body = "";
        resp.setEncoding("latin1");
        resp.on("data", (d) => { if (body.length + d.length > MAX_PROBE_BODY) { req.destroy(Object.assign(new Error("body-limit"), { code: "body-limit" })); return; } body += d; });
        resp.on("end", () => resolve({ code: resp.statusCode, body }));
        resp.on("error", reject);
      });
      const timer = setTimeout(() => req.destroy(Object.assign(new Error("timeout"), { code: "timeout" })), Math.max(1, timeoutMs - (now() - t0)));
      req.on("error", (e) => { clearTimeout(timer); reject(e); });
      req.on("close", () => clearTimeout(timer));
      req.end();
    });
    out.code = r.code;
    let ip = r.body.trim();
    try { ip = JSON.parse(ip).ip; } catch { /* plain IP endpoint */ }
    if (r.code < 200 || r.code >= 300) out.error = `http-${r.code}`;
    else if (typeof ip !== "string" || !isIP(ip)) out.error = "invalid-exit-ip";
    else out.body = ip;
  } catch (e) {
    out.error = String(e.code || "error").slice(0, 60);
  }
  out.tTotalMs = r1(now() - t0);
  return out;
}

// One cold probe followed by `warm` warm probes, `gapMs` apart. -> rows
export async function coldWarm(exit, url, { warm = 4, gapMs = 2000, timeoutMs, ca, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const rows = [await probe(exit, url, { phase: "cold", timeoutMs, ca })];
  for (let i = 0; i < warm; i++) {
    await sleep(gapMs);
    rows.push(await probe(exit, url, { phase: "warm", timeoutMs, ca }));
  }
  return rows;
}
