// Clients for the egress benchmark. A client is "the software that makes the request", and it
// matters as much as the exit: sites score the TLS and HTTP fingerprint and whether JavaScript
// runs, not only the IP. The November 2026 run found headed Chromium beat curl on every exit and
// default headless was the worst client on every exit (bench/egress/README.md).
//
//   curl      the system curl, spawned. What a shell agent sends. Kept as the real binary
//             because its TLS fingerprint is the thing being measured.
//   node      Node's https over the same exit (lib/net.mjs). What an agent written in Node sends.
//   headless  Playwright Chromium, default headless (HeadlessChrome UA), default context.
//             What most agent stacks ship.
//   headed    Playwright Chromium with a window (use xvfb-run on a display-less Linux box),
//             1920x1080, en-US, AutomationControlled off. The closest to a person's browser.
//
// Each client returns the same shape, which lib/classify.mjs consumes:
//   { code, headers, body, title, finalUrl, t, transport, connectCode, failedRequests }
// and never throws: a client that cannot run returns transport "error:client-unavailable".

import { isLoopbackHost } from "./sites.mjs";
import { classify } from "./classify.mjs";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { curlArgs, chromiumProxy } from "./exits.mjs";
import { fetchVia } from "./net.mjs";

export const CLIENTS = Object.freeze(["curl", "node", "headless", "headed"]);

// A stock desktop Chrome UA for curl/node (what agents that fake a browser send), or an honest
// one that names the benchmark so a site operator can identify and block it (--ua polite).
export const UA_CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
export const UA_POLITE = "shadenet-egress-bench/1 (+https://github.com/dmarzzz/shade-tree-node/tree/main/bench/egress)";
export function userAgent(mode) { return mode === "polite" ? UA_POLITE : UA_CHROME; }

const ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const ACCEPT_LANGUAGE = "en-US,en;q=0.9";

export const PROFILE_US = Object.freeze({ locale: "en-US", timezoneId: "America/New_York", acceptLanguage: ACCEPT_LANGUAGE });

function fail(url, transport, t = 0) {
  return { code: null, headers: {}, body: "", title: "", finalUrl: url, t, transport, connectCode: null, failedRequests: null };
}

// Parse curl's -D header dump: keep only the LAST response's headers (after redirects and the
// proxy's "HTTP/1.1 200 Connection established" block).
export function parseCurlHeaders(text) {
  const blocks = String(text || "").replace(/\r\n/g, "\n").trim().split(/\n\n+/).filter((b) => /^HTTP\//.test(b));
  const out = {};
  const last = blocks[blocks.length - 1];
  if (!last) return out;
  for (const line of last.split("\n").slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return out;
}

// curl exit codes that mean "the tunnel or the network failed", named for the report.
const CURL_RC = { 5: "proxy-resolve", 6: "resolve", 7: "connect", 35: "tls", 52: "empty-reply", 56: "recv", 97: "proxy-handshake" };

export function runCurl(exit, site, { timeoutS = 45, ua = UA_CHROME, curlBin = "curl", extraArgs = [], localOnly = false, signal } = {}) {
  return (async () => {
    if (signal?.aborted) return fail(site.url, "error:cancelled");
    const t0 = Date.now();
    let dir;
    try { dir = await mkdtemp(join(tmpdir(), "egress-curl-")); } catch { return fail(site.url, "error:tmpdir"); }
    const hf = join(dir, "h");
    const args = ["-q", "--max-filesize", "12582912", "-s", "-L", "--max-redirs", "5", "--compressed", "-m", String(timeoutS), "-A", ua,
      "-H", `Accept: ${ACCEPT}`, "-H", `Accept-Language: ${ACCEPT_LANGUAGE}`,
      "-D", hf, "-o", "-", "-w", "%{stderr}%{json}", ...curlArgs(exit), ...extraArgs, ...(localOnly ? ["--max-redirs", "0"] : []), site.url];
    const chunks = [];
    let bytes = 0;
    let limited = false;
    const r = await new Promise((resolve) => {
      let out = "";
      let child;
      try { child = spawn(curlBin, args, { stdio: ["ignore", "pipe", "pipe"] }); } catch { resolve({ rc: -1, out: "" }); return; }
      const abort = () => child.kill("SIGKILL");
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      child.once("close", () => signal?.removeEventListener("abort", abort));
      const killer = setTimeout(() => child.kill("SIGKILL"), Math.max(1, timeoutS * 1000 - (Date.now() - t0)));
      child.stderr.on("data", (d) => { if (out.length < 65536) out += d; });
      child.stdout.on("data", d => {
        bytes += d.length;
        if (bytes > 12 * 1024 * 1024) { limited = true; child.kill("SIGKILL"); return; }
        chunks.push(d);
      });
      child.on("error", () => { clearTimeout(killer); resolve({ rc: -1, out: "" }); });
      child.on("close", (rc) => { clearTimeout(killer); resolve({ rc, out }); });
    });
    const t = (Date.now() - t0) / 1000;
    let w = {};
    try { w = JSON.parse(r.out); } catch { /* curl too old for %{json}, or killed */ }
    const hdr = await readFile(hf, "latin1").catch(() => "");
    const body = limited ? "" : Buffer.concat(chunks).toString("utf8");
    await rm(dir, { recursive: true, force: true });
    let transport = null;
    if (limited || r.rc === 63) transport = "error:body-limit";
    else if (signal?.aborted) transport = "error:cancelled";
    else if (r.rc === -1) transport = "error:client-unavailable";
    else if (r.rc === 28 || r.rc === null) transport = "timeout";
    // rc 7 with a proxy configured and no CONNECT reply means curl never reached the proxy.
    else if (r.rc === 7 && exit && exit.type !== "direct" && !w.http_connect) transport = "error:curl-proxy-connect";
    else if (r.rc !== 0) transport = `error:curl-${CURL_RC[r.rc] || "rc" + r.rc}${w.http_connect ? `-connect${w.http_connect}` : ""}`;
    const code = Number.isInteger(w.http_code) && w.http_code > 0 ? w.http_code : null;
    return { code, headers: parseCurlHeaders(hdr), body, title: "", finalUrl: w.url_effective || site.url, t,
      transport, connectCode: w.http_connect || null, failedRequests: null };
  })();
}

export async function runNode(exit, site, { timeoutS = 45, ua = UA_CHROME, ca, localOnly = false, signal } = {}) {
  const r = await fetchVia(exit, site.url, {
    headers: { "user-agent": ua, accept: ACCEPT, "accept-language": ACCEPT_LANGUAGE },
    timeoutMs: timeoutS * 1000, ca, localOnly, signal,
  });
  return { code: r.code, headers: r.headers, body: r.body, title: "", finalUrl: r.finalUrl, t: r.t,
    transport: r.transport, connectCode: r.connectCode, failedRequests: null };
}

// Lazily import playwright so curl/node-only runs (and CI) never need a browser installed.
export async function loadChromium() {
  try {
    const m = await import("@playwright/test");
    return m.chromium || null;
  } catch { return null; }
}

// Owns the browser processes for one run: one browser per mode, one fresh context per cell.
export class Browsers {
  constructor({ exit, modes, profile = PROFILE_US, chromium = null, navTimeoutMs = 45_000, settleMs = 6_000, ignoreHTTPSErrors = false }) {
    this.exit = exit; this.modes = modes; this.profile = profile; this.chromium = chromium;
    this.navTimeoutMs = navTimeoutMs; this.settleMs = settleMs; this.ignoreHTTPSErrors = ignoreHTTPSErrors;
    this.browsers = new Map(); this.unavailable = new Map();
  }

  async start() {
    this.started = true;
    return this;
  }

  async startMode(requestedMode, signal) {
    const chromium = this.chromium || (await loadChromium());
    if (signal?.aborted) return this;
    for (const mode of this.modes.filter(mode => mode === requestedMode)) {
      if (!chromium) { this.unavailable.set(mode, "playwright-missing"); continue; }
      if (mode === "headed" && process.platform === "linux" && !process.env.DISPLAY) {
        // Refuse rather than fall back to headless: a silently-headless "headed" column would
        // report the worst client's numbers under the best client's name.
        this.unavailable.set(mode, "no-display (run under xvfb-run)");
        continue;
      }
      const args = ["--disable-dev-shm-usage"];
      if (!this.exit || this.exit.type === "direct") args.push("--no-proxy-server");
      // Chromium bypasses any proxy for loopback by default. Route loopback through the exit
      // too, so the selftest's loopback fixtures exercise the same path a real site takes.
      if (this.exit && this.exit.type !== "direct") args.push("--proxy-bypass-list=<-loopback>");
      if (mode === "headed") args.push("--disable-blink-features=AutomationControlled");
      try {
        const browser = await chromium.launch({ headless: mode !== "headed", timeout: this.navTimeoutMs, args, proxy: chromiumProxy(this.exit) });
        if (signal?.aborted) { await browser.close().catch(() => {}); return this; }
        this.browsers.set(mode, browser);
      } catch (e) {
        this.unavailable.set(mode, "launch-failed: " + String(e.message || e).split("\n")[0].slice(0, 120));
      }
    }
    return this;
  }

  contextOptions(mode) {
    const base = { ignoreHTTPSErrors: this.ignoreHTTPSErrors, serviceWorkers: "block" };
    if (mode === "headless") return base; // the default an agent stack ships with
    const p = this.profile;
    return { ...base, viewport: { width: 1920, height: 1080 }, locale: p.locale, timezoneId: p.timezoneId,
      extraHTTPHeaders: { "Accept-Language": p.acceptLanguage }, colorScheme: "light" };
  }

  async run(mode, site, options = {}) {
    const controller = new AbortController();
    let timer;
    let abort;
    const started = Date.now();
    try {
      const stopped = new Promise(resolve => {
        abort = () => {
          controller.abort("cancelled");
          resolve(fail(site.url, "error:cancelled"));
        };
        options.signal?.addEventListener("abort", abort, { once: true });
        if (options.signal?.aborted) abort();
        timer = setTimeout(() => {
          controller.abort("timeout");
          resolve(fail(site.url, "timeout"));
        }, this.navTimeoutMs);
      });
      const result = await Promise.race([
        stopped,
        this.runCell(mode, site, { ...options, signal: controller.signal }),
      ]);
      return { ...result, t: (Date.now() - started) / 1000, browserVersion: this.browsers.get(mode)?.version?.() || null };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }

  async runCell(mode, site, { screenshot = null, localOnly = false, signal } = {}) {
    if (!this.browsers.has(mode) && this.started && !signal?.aborted) await this.startMode(mode, signal);
    if (signal?.aborted) return fail(site.url, signal.reason === "timeout" ? "timeout" : "error:cancelled");
    const b = this.browsers.get(mode);
    if (!b) return fail(site.url, `error:client-unavailable:${this.unavailable.get(mode) || "not-started"}`);
    const t0 = Date.now();
    let ctx;
    if (signal?.aborted) return fail(site.url, "error:cancelled");
    let expired = false;
    const abort = () => { expired = true; clearTimeout(timer); if (ctx) void ctx.close().catch(() => {}); };
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => { expired = true; if (ctx) void ctx.close().catch(() => {}); }, this.navTimeoutMs);
    try {
      ctx = await b.newContext(this.contextOptions(mode));
      if (expired) throw new Error("timeout");
      if (localOnly) await ctx.route("**/*", route => {
        const u = new URL(route.request().url());
        return isLoopbackHost(u.hostname) ? route.continue() : route.abort();
      });
      const page = await ctx.newPage();
      const cdp = await ctx.newCDPSession(page);
      await cdp.send("Network.enable");
      let received = 0;
      let limited = false;
      cdp.on("Network.dataReceived", event => {
        received += event.dataLength;
        if (received > 12 * 1024 * 1024) { limited = true; void ctx.close().catch(() => {}); }
      });
      let lastNav = null;
      let failed = 0;
      page.on("response", (r) => { try { if (r.request().isNavigationRequest() && r.frame() === page.mainFrame()) lastNav = r; } catch { /* detached */ } });
      page.on("requestfailed", () => { failed++; });
      let code = null; let headers = {}; let body = ""; let title = ""; let transport = null;
      try {
        const resp = await page.goto(site.url, { waitUntil: "domcontentloaded", timeout: this.navTimeoutMs });
        await page.waitForTimeout(this.settleMs);
        const r = lastNav || resp;
        if (r) { code = r.status(); try { headers = await r.allHeaders(); } catch { headers = r.headers(); } }
        body = await page.content().catch(() => "");
        if (Buffer.byteLength(body) > 12 * 1024 * 1024) { body = ""; transport = "error:body-limit"; }
        title = await page.title().catch(() => "");
      } catch (e) {
        const msg = String(e && e.message || e).split("\n")[0];
        transport = signal?.aborted ? (signal.reason === "timeout" ? "timeout" : "error:cancelled") : limited ? "error:body-limit" : expired || /timeout/i.test(msg) ? "timeout" : "error:" + msg.slice(0, 160);
      }
      let shot = null;
      if (screenshot && classify({ site, code, headers, body, title, transport }).outcome !== "ok") { try { await page.screenshot({ path: screenshot }); shot = screenshot; } catch { /* page gone */ } }
      return { code, headers, body, title, finalUrl: page.url(), t: (Date.now() - t0) / 1000, transport,
        connectCode: null, failedRequests: failed, screenshot: shot };
    } catch (e) {
      return fail(site.url, signal?.aborted ? (signal.reason === "timeout" ? "timeout" : "error:cancelled") : expired ? "timeout" : "error:" + String(e && e.message || e).split("\n")[0].slice(0, 160), (Date.now() - t0) / 1000);
    } finally {
      signal?.removeEventListener("abort", abort);
      clearTimeout(timer);
      if (ctx) await ctx.close().catch(() => {});
    }
  }

  async close() {
    for (const b of this.browsers.values()) await b.close().catch(() => {});
    this.browsers.clear();
  }
}
