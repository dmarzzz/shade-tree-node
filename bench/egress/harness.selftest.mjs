// End-to-end selftest for the egress benchmark harness, against loopback fixtures only.
//
//   node bench/egress/harness.selftest.mjs
//
// Covers: every client through every exit type (direct, HTTP CONNECT, SOCKS5) against canned
// wall pages, the JSONL rows that come out, the tunnel code against hostile proxies (garbage,
// endless head, hang-up, 407, silence), body/redirect caps, Tor NEWNYM, cold/warm dial timing,
// and the CLI's refusal to touch real sites without --real or under CI.
//
// No network: every server binds 127.0.0.1, and the fixture proxies refuse any non-loopback
// target. Browser cases run when Playwright's Chromium is installed and are reported as
// skipped (not passed) otherwise; CI's node job installs no browsers.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";

// The fixtures live in THIS process, so a CLI under test must be spawned asynchronously:
// spawnSync would block the event loop that serves the fixtures and every cell would time out.
function spawnAsync(cmd, args, { env, timeout = 60_000 } = {}) {
  return new Promise((resolve) => {
    const c = spawn(cmd, args, { env: env || process.env });
    let stdout = ""; let stderr = "";
    c.stdout.on("data", (d) => { stdout += d; });
    c.stderr.on("data", (d) => { stderr += d; });
    const k = setTimeout(() => c.kill("SIGKILL"), timeout);
    c.on("close", (status) => { clearTimeout(k); resolve({ status, stdout, stderr }); });
  });
}
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startOrigin, startConnectProxy, startSocks5, startHostile, startTorControl, startTlsOrigin, ONLY_VIA_EXIT } from "./fixtures.mjs";
import { parseExit } from "./lib/exits.mjs";
import { newnym } from "./lib/exits.mjs";
import { openTunnel, fetchVia, startTls, MAX_REDIRECTS } from "./lib/net.mjs";
import { runCurl, runNode, Browsers, parseCurlHeaders, loadChromium, userAgent, UA_POLITE } from "./lib/clients.mjs";
import { runMatrix } from "./lib/runner.mjs";
import { probe, coldWarm } from "./lib/dial.mjs";
import { exitLookup } from "./lib/meta.mjs";
import { parseJsonl, buildReport } from "./lib/report.mjs";
import { classify } from "./lib/classify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let n = 0;
const skipped = [];
const t = async (name, fn) => { await fn(); n++; console.log(`  ok   ${name}`); };
const skip = (name, why) => { skipped.push(name); console.log(`  skip ${name} (${why})`); };
const noSleep = () => Promise.resolve();

const origin = await startOrigin();
const proxy = await startConnectProxy();
const socks = await startSocks5();
const EXITS = {
  direct: parseExit("direct").exit,
  http: parseExit(`http://127.0.0.1:${proxy.port}`).exit,
  socks5: parseExit(`socks5://127.0.0.1:${socks.port}`).exit,
};
const site = (path, okMarker = 'id="fixture-ok"', extra = {}) => ({ tier: "web", site: path.replace(/\W/g, "") || "root", wall: "fixture", url: origin.url(path), okMarker, ...extra });
const haveCurl = spawnSync("curl", ["--version"]).status === 0;

// Expected label for each canned page, the same for every exit and client.
const EXPECT = {
  "/ok": "ok", "/cf-challenge": "blocked-challenge", "/rate": "blocked-429", "/deny": "blocked-403",
  "/datadome": "captcha", "/cf-202": "blocked-challenge", "/empty": "unverified", "/nomarker": "unverified", "/boom": "error",
  "/redirect": "ok", "/gzip": "ok",
};

try {
  for (const [ename, exit] of Object.entries(EXITS)) {
    await t(`node client via ${ename}: every canned wall gets its label`, async () => {
      for (const [path, want] of Object.entries(EXPECT)) {
        const s = site(path);
        const r = await runNode(exit, s, { timeoutS: 10 });
        const got = classify({ site: s, ...r }).outcome;
        assert.equal(got, want, `${ename} ${path}: ${got} (${r.code} ${r.transport})`);
      }
    });
    if (haveCurl) {
      await t(`curl client via ${ename}: every canned wall gets its label`, async () => {
        for (const [path, want] of Object.entries(EXPECT)) {
          const s = site(path);
          const r = await runCurl(exit, s, { timeoutS: 10 });
          assert.equal(classify({ site: s, ...r }).outcome, want, `${ename} ${path}: ${r.code} ${r.transport}`);
        }
      });
    } else skip(`curl client via ${ename}`, "curl not installed");
  }
  assert.ok(proxy.log.length > 0 && proxy.log.every((l) => l.host === "127.0.0.1"), "the CONNECT proxy saw only loopback targets");

  // The traffic really goes through the exit: this host name resolves only inside the fixture
  // proxies, so a client that opened the tunnel but then dialed direct would fail here. (An
  // earlier draft of lib/net.mjs did exactly that: http.request with agent:false ignores
  // createConnection, and every "via proxy" cell above still passed.)
  await t("node and curl traffic really traverses the HTTP and SOCKS5 exits", async () => {
    for (const ename of ["http", "socks5"]) {
      const s = { ...site("/ok"), url: `http://${ONLY_VIA_EXIT}:${origin.port}/ok` };
      const r = await runNode(EXITS[ename], s, { timeoutS: 10 });
      assert.equal(classify({ site: s, ...r }).outcome, "ok", `node via ${ename}: ${r.code} ${r.transport}`);
      if (haveCurl) {
        const c = await runCurl(EXITS[ename], s, { timeoutS: 10 });
        assert.equal(classify({ site: s, ...c }).outcome, "ok", `curl via ${ename}: ${c.code} ${c.transport}`);
      }
    }
    const direct = await runNode(EXITS.direct, { ...site("/ok"), url: `http://${ONLY_VIA_EXIT}:${origin.port}/ok` }, { timeoutS: 10 });
    assert.match(direct.transport, /^error:/, "the name must not resolve without the exit");
  });
  assert.ok(socks.log.length > 0, "the SOCKS5 server was used");

  await t("api tier: unauthenticated 401 with the API error counts as reachable", async () => {
    const s = { tier: "api", site: "api", wall: "fixture", url: origin.url("/api"), okMarker: "invalid_api_key" };
    assert.equal(classify({ site: s, ...(await runNode(EXITS.http, s)) }).outcome, "ok");
  });

  await t("node client: polite UA is sent when asked", async () => {
    const r = await runNode(EXITS.direct, site("/ua"), { ua: userAgent("polite") });
    assert.ok(r.body.includes(UA_POLITE));
    assert.notEqual(userAgent("chrome"), UA_POLITE);
  });

  await t("fetchVia: redirect loop, bad Location, bad gzip and oversized bodies fail cleanly", async () => {
    const loop = await fetchVia(EXITS.direct, origin.url("/loop"), { timeoutMs: 10_000 });
    assert.equal(loop.code, 302, "after MAX_REDIRECTS the last 3xx is returned as is");
    assert.equal(loop.tunnels, MAX_REDIRECTS + 1);
    assert.equal((await fetchVia(EXITS.direct, origin.url("/badloc"))).transport, "error:bad-redirect");
    assert.equal((await fetchVia(EXITS.direct, origin.url("/badgzip"))).transport, "error:bad-encoding");
    const big = await fetchVia(EXITS.direct, origin.url("/big"), { maxBytes: 1 << 20 });
    assert.equal(big.truncated, true);
    assert.ok(big.body.length <= 1 << 20);
    assert.equal((await fetchVia(EXITS.direct, "not a url")).transport, "error:bad-redirect");
    assert.equal((await fetchVia(EXITS.direct, "ftp://127.0.0.1/")).transport, "error:bad-scheme");
    const slow = await fetchVia(EXITS.direct, origin.url("/slow"), { timeoutMs: 300 });
    assert.equal(slow.transport, "timeout");
  });

  await t("openTunnel fails closed on every hostile proxy reply, within its timeout", async () => {
    const cases = { garbage: /bad-proxy-reply/, huge: /bad-proxy-reply/, close: /proxy-closed|ECONNRESET/, 407: /connect-refused-407/, silent: /timeout/ };
    for (const [mode, re] of Object.entries(cases)) {
      const h = await startHostile(mode);
      const t0 = Date.now();
      await assert.rejects(openTunnel({ type: "http", host: "127.0.0.1", port: h.port }, "127.0.0.1", 80, { timeoutMs: 500 }), (e) => re.test(e.code), mode);
      assert.ok(Date.now() - t0 < 3000, `${mode} took ${Date.now() - t0}ms`);
      // and the node client turns it into an error row, never a throw
      const r = await runNode({ type: "http", host: "127.0.0.1", port: h.port }, site("/ok"), { timeoutS: 0.5 });
      assert.ok(["error", "timeout"].includes(classify({ site: site("/ok"), ...r }).outcome), mode);
      await h.close();
    }
    // refused by the proxy: a CONNECT to a non-loopback target is a 403 from the fixture
    await assert.rejects(openTunnel(EXITS.http, "192.0.2.1", 443, { timeoutMs: 2000 }), (e) => e.code === "connect-refused-403");
    // nothing listening
    await assert.rejects(openTunnel({ type: "http", host: "127.0.0.1", port: 1 }, "127.0.0.1", 80, { timeoutMs: 2000 }), (e) => e.code === "proxy-ECONNREFUSED");
    await assert.rejects(openTunnel(EXITS.direct, "127.0.0.1", 1, { timeoutMs: 2000 }), (e) => e.code === "ECONNREFUSED", "direct refusals are the site's, not a proxy's");
    await assert.rejects(openTunnel({ type: "socks5", host: "127.0.0.1", port: 1 }, "127.0.0.1", 80, { timeoutMs: 2000 }), (e) => /^socks-/.test(e.code));
    // SOCKS refusal (fixture refuses non-loopback)
    await assert.rejects(openTunnel(EXITS.socks5, "192.0.2.1", 80, { timeoutMs: 2000 }), (e) => /^socks-/.test(e.code));
  });

  if (haveCurl) {
    await t("curl client: proxy failures and timeouts map to error/timeout rows", async () => {
      const h = await startHostile("407");
      const r = await runCurl({ type: "http", host: "127.0.0.1", port: h.port }, site("/ok"), { timeoutS: 5 });
      assert.equal(classify({ site: site("/ok"), ...r }).outcome, "error");
      assert.match(r.transport, /^error:curl-/);
      await h.close();
      const slow = await runCurl(EXITS.direct, site("/slow"), { timeoutS: 1 });
      assert.equal(slow.transport, "timeout");
      const down = await runCurl({ type: "http", host: "127.0.0.1", port: 1 }, site("/ok"), { timeoutS: 5 });
      assert.equal(down.transport, "error:curl-proxy-connect");
      const missing = await runCurl(EXITS.direct, site("/ok"), { curlBin: "/nonexistent/curl" });
      assert.equal(missing.transport, "error:client-unavailable");
    });
  }

  await t("parseCurlHeaders keeps only the final response's headers", () => {
    const dump = "HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /x\r\nServer: a\r\n\r\nHTTP/2 200\r\nServer: B\r\nX-Thing: 1: 2\r\n\r\n";
    assert.deepEqual(parseCurlHeaders(dump), { server: "B", "x-thing": "1: 2" });
    assert.deepEqual(parseCurlHeaders(""), {});
    assert.deepEqual(parseCurlHeaders("garbage\n\nmore"), {});
  });

  const tlsOrigin = await startTlsOrigin();
  if (tlsOrigin) {
    await t("https through the CONNECT proxy and SOCKS5, with a pinned throwaway CA; a wrong CA fails", async () => {
      for (const exit of [EXITS.http, EXITS.socks5, EXITS.direct]) {
        const r = await fetchVia(exit, tlsOrigin.url("/ok"), { ca: tlsOrigin.ca });
        assert.equal(r.code, 200, `${exit.type} ${r.transport}`);
      }
      const bad = await fetchVia(EXITS.http, tlsOrigin.url("/ok"));
      assert.match(bad.transport, /^error:/);
      const tun = await openTunnel(EXITS.direct, "127.0.0.1", tlsOrigin.port);
      const s = await startTls(tun.socket, "127.0.0.1", { rejectUnauthorized: false });
      assert.ok(s.tTlsMs >= 0);
      s.tls.destroy();
    });
    await t("dial probe: cold then warm through the CONNECT proxy, phases timed", async () => {
      const rows = await coldWarm(EXITS.http, tlsOrigin.url("/ip"), { warm: 2, gapMs: 0, ca: tlsOrigin.ca, sleep: noSleep });
      assert.deepEqual(rows.map((r) => r.phase), ["cold", "warm", "warm"]);
      for (const r of rows) {
        assert.equal(r.error, null, r.error);
        assert.equal(r.code, 200);
        assert.equal(r.connectCode, 200);
        assert.ok(r.tTunnelMs >= 0 && r.tTlsMs >= 0 && r.tTotalMs >= r.tTunnelMs);
      }
    });
    await t("exitLookup reads ip/org/country through the exit", async () => {
      const x = await exitLookup(EXITS.socks5, { url: tlsOrigin.url("/ip"), ca: tlsOrigin.ca });
      assert.deepEqual(x, { ip: "203.0.113.7", org: "AS64500 Example Net", country: "ZZ" });
      const bad = await exitLookup(EXITS.direct, { url: origin.url("/boom") });
      assert.equal(bad.error, "http-503");
    });
  } else {
    skip("https / dial / exitLookup over TLS", "openssl not installed");
  }

  await t("dial probe: errors are rows, not throws", async () => {
    const d = await probe(EXITS.direct, "nope");
    assert.equal(d.error, "bad-url");
    const h = await startHostile("silent");
    const s = await probe({ type: "http", host: "127.0.0.1", port: h.port }, origin.url("/ip"), { timeoutMs: 300 });
    assert.equal(s.error, "timeout");
    await h.close();
    const plain = await probe(EXITS.socks5, origin.url("/ip"), { phase: "cold" });
    assert.equal(plain.code, 200);
    // the body is reduced to IP characters (it is the exit IP) and capped
    assert.match(plain.body, /^[0-9a-fA-F.:]+$/);
  });

  await t("tor NEWNYM: success waits for the settle window, failures carry a reason", async () => {
    const ok = await startTorControl("ok");
    let slept = null;
    assert.deepEqual(await newnym(`127.0.0.1:${ok.port}`, { sleep: (ms) => { slept = ms; } }), { ok: true });
    assert.equal(slept, 11_000);
    assert.match(ok.got.join(""), /AUTHENTICATE ""\r\nSIGNAL NEWNYM/);
    await ok.close();
    const bad = await startTorControl("bad-auth");
    assert.match((await newnym(`127.0.0.1:${bad.port}`, { sleep: noSleep })).reason, /^515/);
    await bad.close();
    const flood = await startTorControl("flood");
    assert.equal((await newnym(`127.0.0.1:${flood.port}`, { sleep: noSleep })).reason, "oversized-reply");
    await flood.close();
    const silent = await startTorControl("silent");
    assert.equal((await newnym(`127.0.0.1:${silent.port}`, { timeoutMs: 200, sleep: noSleep })).reason, "timeout");
    await silent.close();
    assert.equal((await newnym("nonsense")).reason, "bad-control-spec");
    assert.equal((await newnym("127.0.0.1:1", { sleep: noSleep })).ok, false);
  });

  await t("runMatrix: n passes x sites x clients rows, shuffled, rotated, paced, NEWNYM per site", async () => {
    const rows = [];
    const sleeps = [];
    const tor = await startTorControl("ok");
    let tags = 0;
    const sites = [site("/ok"), site("/cf-challenge"), site("/rate")];
    const counts = await runMatrix({ exit: EXITS.socks5, label: "fixture", kind: "other", clients: haveCurl ? ["curl", "node"] : ["node"],
      sites, passes: 2, gapS: 3, passGapS: 9, seed: 1, runId: "r1", write: (r) => rows.push(r), sleep: (ms) => { sleeps.push(ms); },
      torControl: `127.0.0.1:${tor.port}`, exitTag: () => ({ exit_ip: `x${++tags}` }), timeoutS: 10, now: () => "T" });
    await tor.close();
    const per = haveCurl ? 2 : 1;
    assert.equal(rows.length, 2 * 3 * per);
    assert.equal(tags, 6, "exit re-tagged once per site per pass");
    assert.equal(counts.ok, 2 * per);
    assert.equal(counts["blocked-challenge"], 2 * per);
    assert.equal(counts["blocked-429"], 2 * per);
    for (const r of rows) {
      assert.equal(r.outcome, EXPECT["/" + r.site.replace("cfchallenge", "cf-challenge")]);
      assert.equal(r.exit, "fixture");
      assert.equal(r.wall, "fixture");
      assert.equal(r.ts, "T");
    }
    // cell gaps are >= gapS and < gapS + 2; the pass gap is there once
    const cellGaps = sleeps.filter((s) => s !== 9000 && s !== 11000);
    assert.ok(cellGaps.length === rows.length && cellGaps.every((s) => s >= 3000 && s < 5000), JSON.stringify(cellGaps));
    assert.equal(sleeps.filter((s) => s === 9000).length, 1);
    assert.equal(sleeps.filter((s) => s === 11000).length, 6, "one NEWNYM settle per site per pass");
    if (haveCurl) {
      // client order rotates per site: both clients go first at least once
      const firsts = new Set();
      for (let i = 0; i < rows.length; i += 2) firsts.add(rows[i].client);
      assert.equal(firsts.size, 2);
    }
    // the rows render
    const md = buildReport(parseJsonl(rows.map((r) => JSON.stringify(r)).join("\n")));
    assert.match(md, /\| fixture \|/);
  });

  // ---- browsers ----
  const chromium = await loadChromium();
  let canLaunch = false;
  if (chromium) { try { const b = await chromium.launch(); await b.close(); canLaunch = true; } catch { canLaunch = false; } }
  if (canLaunch) {
    // Browser via the HTTP exit is not in this loop on purpose: for an http:// URL Chromium
    // sends a forward-proxy GET, not CONNECT, and the member Proxy (like this fixture) is
    // CONNECT-only. Real sites are https, where Chromium uses CONNECT; SOCKS5 covers the
    // "browser through an exit" path here.
    await t("headless browser direct and via SOCKS5: walls get their labels, a fresh context per cell", async () => {
      for (const exit of [EXITS.direct, EXITS.socks5]) {
        const b = await new Browsers({ exit, modes: ["headless"], settleMs: 50, navTimeoutMs: 10_000 }).start();
        try {
          for (const path of ["/ok", "/cf-challenge", "/rate", "/redirect", "via-exit"]) {
            if (path === "via-exit" && exit.type === "direct") continue;
            const s = path === "via-exit" ? { ...site("/ok"), url: `http://${ONLY_VIA_EXIT}:${origin.port}/ok` } : site(path);
            const r = await b.run("headless", s);
            assert.equal(classify({ site: s, ...r }).outcome, EXPECT[path] || "ok", `${exit.type} ${path} ${r.code} ${r.transport}`);
            assert.equal(typeof r.failedRequests, "number");
          }
          const shotDir = mkdtempSync(join(tmpdir(), "egress-shot-"));
          const r = await b.run("headless", site("/deny"), { screenshot: join(shotDir, "s.png") });
          assert.ok(existsSync(r.screenshot));
          const okShot = join(shotDir, "ok.png");
          const okResult = await b.run("headless", site("/ok"), { screenshot: okShot });
          assert.equal(okResult.screenshot, null);
          assert.equal(existsSync(okShot), false);
          rmSync(shotDir, { recursive: true, force: true });
          const slow = await new Browsers({ exit, modes: ["headless"], settleMs: 0, navTimeoutMs: 300 }).start();
          assert.equal((await slow.run("headless", site("/slow"))).transport, "timeout");
          await slow.close();
        } finally { await b.close(); }
      }
    });
    if (tlsOrigin) await t("browser HTTPS via CONNECT and SOCKS, including headed with DISPLAY", async () => {
      const modes = process.env.DISPLAY ? ["headless", "headed"] : ["headless"];
      for (const exit of [EXITS.http, EXITS.socks5]) {
        const b = await new Browsers({ exit, modes, settleMs: 0, navTimeoutMs: 10_000, ignoreHTTPSErrors: true }).start();
        try {
          for (const mode of modes) {
            const target = { ...site("/ok"), url: tlsOrigin.url("/ok") };
            const result = await b.run(mode, target);
            assert.equal(classify({ site: target, ...result }).outcome, "ok", `${exit.type} ${mode} ${result.transport}`);
          }
        } finally { await b.close(); }
      }
    });
    await t("headed refuses to run without a display instead of silently going headless", async () => {
      const saved = process.env.DISPLAY;
      delete process.env.DISPLAY;
      const b = await new Browsers({ exit: EXITS.direct, modes: ["headed"] }).start();
      const r = await b.run("headed", site("/ok"));
      if (process.platform === "linux") assert.match(r.transport, /client-unavailable:no-display/);
      await b.close();
      if (saved !== undefined) process.env.DISPLAY = saved;
    });
  } else {
    skip("browser clients", chromium ? "chromium not installed (npx playwright install chromium)" : "@playwright/test not installed");
    await t("browser clients report client-unavailable when Chromium cannot launch", async () => {
      const b = await new Browsers({ exit: EXITS.direct, modes: ["headless"] }).start();
      const r = await b.run("headless", site("/ok"));
      assert.match(r.transport, /^error:client-unavailable/);
      assert.equal(classify({ site: site("/ok"), ...r }).outcome, "error");
      await b.close();
    });
  }
  await t("a browser client that was never started reports client-unavailable", async () => {
    const fake = { launch: async () => { throw new Error("nope\nstack"); } };
    const b = await new Browsers({ exit: EXITS.direct, modes: ["headless"], chromium: fake }).start();
    assert.match((await b.run("headless", site("/ok"))).transport, /client-unavailable:launch-failed/);
    assert.match(b.unavailable.get("headless"), /^launch-failed: nope$/);
    assert.match((await b.run("headed", site("/ok"))).transport, /client-unavailable:not-started/);
    await b.close();
  });

  // ---- CLI ----
  await t("run.mjs CLI: loopback run writes a meta row then cells; report.mjs renders it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "egress-cli-"));
    try {
      const sites = join(dir, "sites.txt");
      writeFileSync(sites, `web ok fixture ${origin.url("/ok")} id="fixture-ok"\nweb chl fixture ${origin.url("/cf-challenge")} never\n`);
      const out = join(dir, "out.jsonl");
      const r = await spawnAsync(process.execPath, [join(HERE, "run.mjs"), "--label", "cli", "--kind", "other", "--exit", `http://127.0.0.1:${proxy.port}`,
        "--clients", "node", "--sites", sites, "--passes", "1", "--gap", "0", "--no-exit-lookup", "--out", out]);
      assert.equal(r.status, 0, r.stderr + r.stdout);
      const p = parseJsonl(readFileSync(out, "utf8"));
      assert.equal(p.metas.length, 1);
      assert.equal(p.metas[0].exitSpec, `http://127.0.0.1:${proxy.port}`);
      assert.equal(p.metas[0].sites.count, 2);
      assert.deepEqual(p.rows.map((x) => x.outcome).sort(), ["blocked-challenge", "ok"]);
      const rep = spawnSync(process.execPath, [join(HERE, "report.mjs"), out], { encoding: "utf8" });
      assert.equal(rep.status, 0, rep.stderr);
      assert.match(rep.stdout, /## Provenance/);
      const dial = join(dir, "dial.jsonl");
      const d = await spawnAsync(process.execPath, [join(HERE, "dial.mjs"), "--label", "cli", "--exit", `socks5://127.0.0.1:${socks.port}`, "--target", origin.url("/ip"),
        "--warm", "1", "--gap", "0", "--out", dial]);
      assert.equal(d.status, 0, d.stderr);
      const drows = readFileSync(dial, "utf8").trim().split("\n").map((l) => JSON.parse(l));
      assert.deepEqual(drows.map((x) => x.phase), ["cold", "warm"]);
      assert.ok(drows.every((x) => !("body" in x) && /^[0-9a-f]{8}$/.test(x.exitHash)), "dial rows carry an exit hash, never the exit IP");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  await t("run.mjs CLI refuses real sites without --real, under CI, and on bad input", async () => {
    const run = (args, env = {}) => spawnSync(process.execPath, [join(HERE, "run.mjs"), ...args], { encoding: "utf8", env: { ...process.env, CI: "", ...env }, timeout: 30_000 });
    const base = ["--label", "x", "--kind", "other", "--out", join(tmpdir(), "never-written.jsonl"), "--clients", "node"];
    const noReal = run(base);
    assert.equal(noReal.status, 2);
    assert.match(noReal.stderr, /--real/);
    const ci = run([...base, "--real"], { CI: "true" });
    assert.equal(ci.status, 2);
    assert.match(ci.stderr, /CI/);
    assert.match(run([...base, "--real", "--gap", "1"]).stderr, /--gap must be >= 2/);
    assert.match(run(["--kind", "other", "--out", "x"]).stderr, /--label/);
    assert.match(run(["--label", "x", "--kind", "nope", "--out", "x"]).stderr, /--kind/);
    assert.match(run([...base, "--exit", "http://u:p@127.0.0.1:1"]).stderr, /credentials/);
    assert.match(run([...base, "--only", "no-such-site"]).stderr, /unknown site/);
    assert.match(run([...base, "--passes", "0"]).stderr, /--passes/);
    assert.match(run([...base, "--ua", "evil"]).stderr, /--ua/);
    assert.match(run([...base, "--bogus"]).stderr, /Unknown option|unknown/i);
    assert.equal(run(["--help"]).status, 0);
    assert.equal(existsSync(join(tmpdir(), "never-written.jsonl")), false, "a refused run writes nothing");
    const dialReal = spawnSync(process.execPath, [join(HERE, "dial.mjs"), "--label", "x", "--out", join(tmpdir(), "nw.jsonl")], { encoding: "utf8", env: { ...process.env, CI: "" } });
    assert.match(dialReal.stderr, /--real/);
    const dialCi = spawnSync(process.execPath, [join(HERE, "dial.mjs"), "--label", "x", "--real", "--out", join(tmpdir(), "nw.jsonl")], { encoding: "utf8", env: { ...process.env, CI: "1" } });
    assert.match(dialCi.stderr, /CI/);
  });

} finally {
  await origin.close(); await proxy.close(); await socks.close();
}

console.log(`PASS harness (${n} cases${skipped.length ? `, ${skipped.length} skipped: ${skipped.join("; ")}` : ""})`);
process.exit(0);
