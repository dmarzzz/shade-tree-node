// Exit specs for the egress benchmark: where a cell's traffic leaves for the clearnet.
//
//   direct                 this machine's own address
//   http://HOST:PORT       any HTTP CONNECT proxy. The ShadeNet member Proxy is one of these
//                          (default http://127.0.0.1:8888, CONNECT only, 443 only).
//   socks5://HOST:PORT     any SOCKS5 proxy with remote DNS (socks5h semantics), e.g. Tor 9050
//
// Every client in lib/clients.mjs takes the same parsed exit, so a cell's exit is the only thing
// that differs between columns. Credentials in the spec are refused: the spec lands in the
// result rows and the reproducibility stamp, and a benchmark file must never carry a secret.

import net from "node:net";
import { isLoopbackHost } from "./sites.mjs";

export const EXIT_KINDS = Object.freeze(["datacenter", "tor", "shadenet", "residential", "mobile", "other"]);

export function parseExit(spec) {
  const s = String(spec ?? "").trim();
  if (s === "direct" || s === "") return { ok: true, exit: { type: "direct", host: null, port: null } };
  let u;
  try { u = new URL(s); } catch { return { ok: false, error: `bad exit "${s.slice(0, 80)}": use direct, http://host:port or socks5://host:port` }; }
  if (u.username || u.password) return { ok: false, error: "exit spec must not carry credentials" };
  const type = u.protocol === "http:" ? "http" : (u.protocol === "socks5:" || u.protocol === "socks5h:") ? "socks5" : null;
  if (!type) return { ok: false, error: `unsupported exit scheme "${u.protocol}"` };
  if ((u.pathname && u.pathname !== "/") || u.search || u.hash) return { ok: false, error: "exit spec is scheme://host:port only" };
  const port = Number(u.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: "exit spec needs an explicit port" };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (!host) return { ok: false, error: "exit spec needs a host" };
  return { ok: true, exit: { type, host, port } };
}

// The form written into result rows. A loopback proxy is printed as is (it says nothing about
// the operator); any other proxy host is reduced to its scheme so a published report does not
// name the operator's machines.
export function describeExit(exit) {
  if (!exit || exit.type === "direct") return "direct";
  if (isLoopbackHost(exit.host)) return `${exit.type}://${exit.host.includes(":") ? `[${exit.host}]` : exit.host}:${exit.port}`;
  return `${exit.type}://<redacted>`;
}

export function curlArgs(exit) {
  if (!exit || exit.type === "direct") return ["--proxy", ""];
  const hp = `${exit.host.includes(":") ? `[${exit.host}]` : exit.host}:${exit.port}`;
  if (exit.type === "socks5") return ["--noproxy", "", "--socks5-hostname", hp];
  return ["--noproxy", "", "--proxytunnel", "-x", `http://${hp}`];
}

export function chromiumProxy(exit) {
  if (!exit || exit.type === "direct") return undefined;
  const hp = `${exit.host.includes(":") ? `[${exit.host}]` : exit.host}:${exit.port}`;
  return { server: `${exit.type}://${hp}` };
}

// Ask Tor for a fresh circuit (and so, usually, a fresh exit IP) before the next site.
// Cookie/password auth is not supported on purpose: point --tor-control at a control port that
// accepts the null auth of a throwaway benchmark Tor, never at a long-lived Tor with secrets.
// Tor rate-limits NEWNYM to one per 10 s, so the caller waits `settleMs` after a 250.
export function parseHostPort(spec) {
  const m = /^\[?([^\]\s]+?)\]?:(\d{1,5})$/.exec(String(spec || "").trim());
  if (!m) return null;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { host: m[1], port } : null;
}

export function newnym(control, { timeoutMs = 10_000, settleMs = 11_000, sleep = defaultSleep } = {}) {
  const hp = parseHostPort(control);
  if (!hp) return Promise.resolve({ ok: false, reason: "bad-control-spec" });
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    // `r` null = success path: close the socket but resolve only after Tor's settle window.
    const finish = (r) => { if (done) return; done = true; sock.destroy(); if (r) resolve(r); };
    const sock = net.createConnection({ host: hp.host, port: hp.port });
    sock.setTimeout(timeoutMs, () => finish({ ok: false, reason: "timeout" }));
    sock.on("error", (e) => finish({ ok: false, reason: e.code || "error" }));
    sock.on("connect", () => sock.write('AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n'));
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      if (buf.length > 4096) return finish({ ok: false, reason: "oversized-reply" });
      const lines = buf.split("\r\n").filter(Boolean);
      // Expect "250 OK" for AUTHENTICATE and for SIGNAL. Anything else (515 bad auth) fails.
      if (lines.some((l) => /^[45]\d\d/.test(l))) return finish({ ok: false, reason: lines.find((l) => /^[45]/.test(l)).slice(0, 60) });
      if (lines.filter((l) => l.startsWith("250")).length >= 2) {
        if (done) return;
        finish(null);
        Promise.resolve(sleep(settleMs)).then(() => resolve({ ok: true }));
      }
    });
    sock.on("close", () => finish({ ok: false, reason: "closed" }));
  });
}

function defaultSleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
