// Selftest for the egress benchmark's operator-input parsers and the report generator:
// bench/egress/lib/{sites,exits,report,meta}.mjs and the shipped sites.txt.
//
//   node bench/egress/parse.selftest.mjs
//
// The sites file and exit spec decide what gets measured and what lands in a published file,
// so they fail closed: a malformed line is an error with a line number, never a silently
// dropped site; an exit spec with credentials is refused; a non-loopback proxy host is
// redacted in rows. The report must never print an exit IP unless asked.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSites, selectSites, isLoopbackHost, allLoopback, TIERS } from "./lib/sites.mjs";
import { parseExit, describeExit, curlArgs, chromiumProxy, parseHostPort } from "./lib/exits.mjs";
import { parseJsonl, fmtCell, quantile, buildReport } from "./lib/report.mjs";
import { parseIpInfo, buildMeta, hostClass, sha256File, gitInfo, curlVersion, HARNESS_VERSION } from "./lib/meta.mjs";
import { rng, shuffle, rotate, checkPlan, buildRow, MIN_REAL_GAP_S } from "./lib/runner.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ok   ${name}`); };

// ---- sites -------------------------------------------------------------------------------

t("the shipped sites.txt parses, has unique names, and every marker compiles", () => {
  const r = parseSites(readFileSync(join(HERE, "sites.txt"), "utf8"));
  assert.ok(r.ok, r.errors.join("; "));
  assert.ok(r.sites.length >= 20);
  for (const s of r.sites) {
    assert.ok(TIERS.includes(s.tier));
    assert.ok(s.okMarker, `${s.site} has no ok-marker, every shipped site needs one`);
    new RegExp(s.okMarker, "i");
  }
  assert.equal(new Set(r.sites.map((s) => s.site)).size, r.sites.length);
  assert.equal(r.sites.find((s) => s.site === "amazon").minBytes, 10000);
  assert.equal(r.sites.find((s) => s.site === "reddit").minBytes, 60000);
  assert.equal(allLoopback(r.sites), false);
});

t("a good line with and without min= and marker", () => {
  const r = parseSites("# c\n\nweb a none https://a.example/ min=50 <title>a b\nsearch b own http://b.example/x?q=1\n");
  assert.ok(r.ok);
  assert.deepEqual(r.sites.map((s) => [s.site, s.minBytes, s.okMarker]), [["a", 50, "<title>a b"], ["b", null, ""]]);
});

t("every malformed line is reported with its line number and nothing is returned", () => {
  const bad = [
    ["web a none", /expected/],
    ["blog a none https://a.example/", /unknown tier/],
    ["web A! none https://a.example/", /bad name/],
    ["web a WALL https://a.example/", /bad wall/],
    ["web a none not-a-url", /bad url/],
    ["web a none ftp://a.example/", /http\(s\)/],
    ["web a none file:///etc/passwd", /http\(s\)/],
    ["web a none https://u:p@a.example/", /credentials/],
    ["web a none https://a.example/ (unclosed", /not a valid regex/],
    ["web a none https://a.example/ (a+)+$", /nested quantifier/],
    ["web a none https://a.example/ (.*)*", /nested quantifier/],
    ["web a none https://a.example/ " + "x".repeat(301), /longer than/],
  ];
  for (const [line, re] of bad) {
    const r = parseSites(`# header\n${line}\n`);
    assert.equal(r.ok, false, line);
    assert.equal(r.sites.length, 0);
    assert.match(r.errors[0], /^line 2: /);
    assert.match(r.errors[0], re, line);
  }
  const dup = parseSites("web a none https://a.example/\nweb a none https://b.example/\n");
  assert.match(dup.errors[0], /line 2: duplicate/);
  assert.deepEqual(parseSites("# only comments\n").errors, ["no sites"]);
  assert.equal(parseSites(null).ok, false);
});

t("--only keeps file order and rejects unknown names", () => {
  const { sites } = parseSites("web a none https://a.example/\nweb b none https://b.example/\nweb c none https://c.example/\n");
  assert.deepEqual(selectSites(sites, "c,a").sites.map((s) => s.site), ["a", "c"]);
  assert.equal(selectSites(sites, "").sites.length, 3);
  const r = selectSites(sites, "a,zz");
  assert.equal(r.ok, false);
  assert.match(r.error, /zz/);
});

t("loopback detection is exact (a lookalike host is not loopback)", () => {
  for (const h of ["127.0.0.1", "127.1.2.3", "localhost", "LOCALHOST", "::1", "[::1]"]) assert.ok(isLoopbackHost(h), h);
  for (const h of ["127.0.0.1.example.com", "localhost.example", "10.0.0.1", "0.0.0.0", "", null, "::ffff:8.8.8.8"]) assert.equal(isLoopbackHost(h), false, String(h));
  assert.equal(allLoopback([{ url: "not a url" }]), false);
});

// ---- exits -------------------------------------------------------------------------------

t("exit specs parse to direct, http and socks5", () => {
  assert.deepEqual(parseExit("direct").exit, { type: "direct", host: null, port: null });
  assert.deepEqual(parseExit("").exit.type, "direct");
  assert.deepEqual(parseExit("http://127.0.0.1:8888").exit, { type: "http", host: "127.0.0.1", port: 8888 });
  assert.deepEqual(parseExit("socks5://127.0.0.1:9050").exit, { type: "socks5", host: "127.0.0.1", port: 9050 });
  assert.deepEqual(parseExit("socks5h://[::1]:9050").exit, { type: "socks5", host: "::1", port: 9050 });
});

t("bad exit specs fail closed with a reason", () => {
  for (const [s, re] of [["https://p.example:443", /unsupported/], ["http://u:pw@127.0.0.1:1", /credentials/], ["http://127.0.0.1", /port/],
    ["http://127.0.0.1:1/path", /host:port only/], ["socks4://127.0.0.1:1", /unsupported/], ["127.0.0.1:8888", /unsupported|bad exit/], ["::::", /bad exit/]]) {
    const r = parseExit(s);
    assert.equal(r.ok, false, s);
    assert.match(r.error, re, s);
  }
});

t("describeExit never names a non-loopback proxy host", () => {
  assert.equal(describeExit(parseExit("http://127.0.0.1:8888").exit), "http://127.0.0.1:8888");
  assert.equal(describeExit(parseExit("socks5://[::1]:9050").exit), "socks5://[::1]:9050");
  assert.equal(describeExit(parseExit("http://198.51.100.4:3128").exit), "http://<redacted>");
  assert.equal(describeExit(parseExit("socks5://tor.internal:9050").exit), "socks5://<redacted>");
  assert.equal(describeExit(null), "direct");
});

t("curl and chromium proxy args match the exit", () => {
  assert.deepEqual(curlArgs(parseExit("direct").exit), []);
  assert.deepEqual(curlArgs(parseExit("socks5://127.0.0.1:9050").exit), ["--socks5-hostname", "127.0.0.1:9050"]);
  assert.deepEqual(curlArgs(parseExit("http://[::1]:8888").exit), ["--proxytunnel", "-x", "http://[::1]:8888"]);
  assert.equal(chromiumProxy(parseExit("direct").exit), undefined);
  assert.deepEqual(chromiumProxy(parseExit("http://127.0.0.1:8888").exit), { server: "http://127.0.0.1:8888" });
  assert.deepEqual(chromiumProxy(parseExit("socks5://[::1]:9050").exit), { server: "socks5://[::1]:9050" });
});

t("tor control host:port parsing", () => {
  assert.deepEqual(parseHostPort("127.0.0.1:9051"), { host: "127.0.0.1", port: 9051 });
  assert.deepEqual(parseHostPort("[::1]:9051"), { host: "::1", port: 9051 });
  for (const s of ["", "127.0.0.1", "h:0", "h:70000", "h: 1", null]) assert.equal(parseHostPort(s), null, String(s));
});

// ---- runner plan + helpers ---------------------------------------------------------------

t("seeded shuffle is reproducible, a permutation, and seed-dependent", () => {
  const xs = Array.from({ length: 20 }, (_, i) => i);
  const a = shuffle(xs, rng(7)); const b = shuffle(xs, rng(7)); const c = shuffle(xs, rng(8));
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.deepEqual([...a].sort((p, q) => p - q), xs);
  assert.deepEqual(xs, Array.from({ length: 20 }, (_, i) => i), "shuffle must not mutate its input");
  const r = rng(0)();
  assert.ok(r >= 0 && r < 1);
});

t("rotate gives every client a turn at the front", () => {
  assert.deepEqual(rotate(["a", "b", "c"], 1), ["b", "c", "a"]);
  assert.deepEqual(rotate(["a", "b", "c"], 4), ["b", "c", "a"]);
  assert.deepEqual(rotate(["a", "b", "c"], -1), ["c", "a", "b"]);
  assert.deepEqual(rotate([], 3), []);
});

t("checkPlan: CI never touches real sites; real runs are opt-in and paced", () => {
  const local = [{ url: "http://127.0.0.1:1/x" }];
  const real = [{ url: "https://www.example.com/" }];
  assert.ok(checkPlan({ sites: local, clients: ["curl"], gapS: 0, real: false, ci: "true" }).ok);
  assert.match(checkPlan({ sites: real, clients: ["curl"], gapS: 5, real: true, ci: "true" }).error, /CI/);
  assert.match(checkPlan({ sites: real, clients: ["curl"], gapS: 5, real: false, ci: "" }).error, /--real/);
  assert.match(checkPlan({ sites: real, clients: ["curl"], gapS: MIN_REAL_GAP_S - 0.5, real: true, ci: "" }).error, /--gap/);
  assert.ok(checkPlan({ sites: real, clients: ["curl", "headed"], gapS: MIN_REAL_GAP_S, real: true, ci: "" }).ok);
  assert.match(checkPlan({ sites: [], clients: ["curl"], gapS: 5, real: true, ci: "" }).error, /no sites/);
  assert.match(checkPlan({ sites: local, clients: ["wget"], gapS: 5, real: true, ci: "" }).error, /wget/);
  assert.match(checkPlan({ sites: local, clients: [], gapS: 5, real: true, ci: "" }).error, /client/);
  // mixed list: one real site among loopback ones is still real
  assert.match(checkPlan({ sites: [...local, ...real], clients: ["curl"], gapS: 5, real: false, ci: "" }).error, /--real/);
});

t("buildRow keeps only the evidence headers and bounds every string", () => {
  const row = buildRow({ ts: "T", runId: "r", label: "L", kind: "other", exitTag: {}, client: "curl", pass: 1,
    site: { tier: "web", site: "a", wall: "none", url: "u" }, ua: "UA",
    res: { code: 200, headers: { Server: "s".repeat(500), "Set-Cookie": "secret=1", "CF-Mitigated": "challenge" }, body: "<title>" + "t".repeat(300), finalUrl: "f".repeat(500), t: 1.23456, transport: null },
    outcome: "ok", marker: "m" });
  assert.equal(row.hdr.server.length, 80);
  assert.equal(row.hdr["cf-mitigated"], "challenge");
  assert.equal("set-cookie" in row.hdr, false, "cookies must never be written to a result file");
  assert.equal(row.title.length, 120);
  assert.equal(row.final_url.length, 200);
  assert.equal(row.t, 1.23);
  assert.equal(row.err, null);
  assert.equal(row.ua, "UA");
  const b = buildRow({ ts: "T", runId: "r", label: "L", kind: "other", exitTag: {}, client: "headed", pass: 1, site: { tier: "web", site: "a", wall: "none", url: "u" },
    res: { code: null, headers: null, body: null, transport: "error:" + "e".repeat(400) }, outcome: "error", marker: null, ua: "UA" });
  assert.equal(b.err.length, 160);
  assert.equal(b.ua, "browser-default");
  assert.equal(b.bytes, 0);
});

// ---- report ------------------------------------------------------------------------------

const row = (exit, client, site, outcome, extra = {}) => ({ exit, client, site, outcome, tier: "web", wall: "w-" + site, pass: 1, code: 200, t: 1, ts: "2026-11-03T00:00:00Z", ...extra });

t("parseJsonl separates meta, dial and cell rows and counts malformed lines", () => {
  const text = [JSON.stringify({ type: "meta", run: "r" }), JSON.stringify(row("a", "curl", "s", "ok")), "", "not json", "[1]", "null",
    JSON.stringify({ exit: "a", client: "curl", site: "s", outcome: "made-up" }), JSON.stringify({ type: "dial", exit: "a", phase: "cold" })].join("\n");
  const p = parseJsonl(text);
  assert.equal(p.metas.length, 1);
  assert.equal(p.rows.length, 1);
  assert.equal(p.dials.length, 1);
  assert.equal(p.bad, 4);
  assert.deepEqual(parseJsonl(undefined), { rows: [], dials: [], metas: [], bad: 0 });
});

t("fmtCell prints ok/n with the non-ok labels by count", () => {
  assert.equal(fmtCell([]), ".");
  assert.equal(fmtCell(["ok", "ok", "ok"]), "3/3");
  assert.equal(fmtCell(["ok", "blocked-challenge", "blocked-challenge"]), "1/3 chl:2");
  assert.equal(fmtCell(["captcha", "error", "error", "blocked-429"]), "0/4 err:2,429,cap");
  assert.equal(fmtCell(["weird"]), "0/1 weird");
  assert.equal(fmtCell(["blocked-403", "blocked-403"]), "0/2 403:2", "a count must not glue onto a numeric label");
});

t("quantile is nearest-rank and ignores non-numbers", () => {
  assert.equal(quantile([], 0.5), null);
  assert.equal(quantile([3, 1, 2], 0.5), 2);
  assert.equal(quantile([1, 2, 3, 4], 0.9), 4);
  assert.equal(quantile([NaN, 5, "x"], 0.5), 5);
});

t("buildReport: summary, per-wall, per-site and timing tables in the requested order", () => {
  const rows = [row("dc", "curl", "a", "ok"), row("dc", "curl", "a", "captcha", { pass: 2 }), row("tor", "curl", "a", "blocked-403"),
    row("dc", "headed", "b", "ok", { t: 4 }), row("tor", "headed", "b", "ok", { t: 8 }), row("tor", "headed", "z", "ok", { tier: "api", t: 8 })];
  const md = buildReport({ rows }, { exitOrder: ["tor", "dc"], clientOrder: ["headed", "curl"], title: "T | x" });
  assert.match(md, /^# T \\\| x/);
  assert.match(md, /\| client \| tor \| dc \|/);
  assert.match(md, /\| curl \| 0\/1 \(0%\) \| 1\/2 \(50%\) \|/);
  assert.match(md, /\| w-a \| curl \| 0\/1 403 \| 1\/2 cap \|/);
  assert.doesNotMatch(md, /\| w-a \| headed \|/, "a wall x client pair with no cells is not printed");
  assert.ok(md.indexOf("client = headed") < md.indexOf("client = curl"));
  // api tier rows sort after web rows
  const perSite = md.slice(md.indexOf("client = headed"));
  assert.ok(perSite.indexOf("| web | b |") < perSite.indexOf("| api | z |"));
  assert.match(md, /2 pass\(es\)/);
  assert.match(md, /\| headed \| 8\.0 \/ 8\.0 \| 4\.0 \/ 4\.0 \|/);
});

t("buildReport hides exit IPs unless asked, and renders dials", () => {
  const metas = [{ type: "meta", run: "r1", exit: "dc", exitKind: "datacenter", exitSpec: "direct", exitInfo: { ip: "203.0.113.9", org: "AS64500 Example", country: "ZZ" },
    clients: ["curl"], passes: 1, startedAt: "S", git: { commit: "0123456789abcdef", dirty: true }, versions: { node: "v24", curl: "curl 8" }, host: { cpus: 2, cpu: "cpu", os: "linux" } }];
  const dials = [{ type: "dial", exit: "sn", phase: "cold", tTunnelMs: 13700, tTotalMs: 14000 }, { type: "dial", exit: "sn", phase: "warm", tTunnelMs: 1400, tTotalMs: 1700 },
    { type: "dial", exit: "sn", phase: "warm", error: "timeout" }];
  const hidden = buildReport({ rows: [row("dc", "curl", "a", "ok")], metas, dials });
  assert.doesNotMatch(hidden, /203\.0\.113\.9/);
  assert.match(hidden, /AS64500 Example, ZZ/);
  assert.match(hidden, /0123456789ab\+dirty/);
  assert.match(hidden, /\| sn \| cold \| 1 \| 0 \| 13\.7 \|/);
  assert.match(hidden, /\| sn \| warm \| 2 \| 1 \| 1\.4 \|/);
  assert.match(buildReport({ rows: [], metas }, { showIps: true }), /203\.0\.113\.9/);
  assert.match(buildReport({ rows: [], metas: [{ type: "meta" }] }), /exit not looked up/);
  assert.match(buildReport(), /^# Egress benchmark report/);
});

// ---- meta --------------------------------------------------------------------------------

t("parseIpInfo is bounded and tolerant", () => {
  assert.deepEqual(parseIpInfo('{"ip":"203.0.113.1","org":"AS1 X","country":"ZZ"}'), { ip: "203.0.113.1", org: "AS1 X", country: "ZZ" });
  assert.deepEqual(parseIpInfo("nope"), { ip: null, org: null, country: null });
  assert.deepEqual(parseIpInfo("null"), { ip: null, org: null, country: null });
  assert.deepEqual(parseIpInfo('{"ip":7,"org":["x"]}'), { ip: null, org: null, country: null });
  assert.equal(parseIpInfo(JSON.stringify({ org: "o".repeat(500) })).org.length, 120);
});

t("buildMeta stamps versions, git, host and a redacted exit spec", () => {
  const m = buildMeta({ runId: "r", label: "L", kind: "other", exit: parseExit("http://198.51.100.1:3128").exit, clients: ["curl"], passes: 1,
    sitesPath: join(HERE, "sites.txt"), siteCount: 3, args: [], root: join(HERE, "../.."), startedAt: "S" });
  assert.equal(m.type, "meta");
  assert.equal(m.harnessVersion, HARNESS_VERSION);
  assert.equal(m.exitSpec, "http://<redacted>");
  assert.match(m.sites.sha256, /^[0-9a-f]{64}$/);
  assert.equal(m.versions.node, process.version);
  assert.ok(m.host.cpus >= 1);
  assert.equal(typeof hostClass().os, "string");
  assert.equal(sha256File("/nonexistent/x"), null);
  assert.equal(gitInfo("/nonexistent/dir").commit, null);
  assert.equal(curlVersion("/nonexistent/curl"), null);
  const noSites = buildMeta({ runId: "r", label: "L", kind: "other", exit: null, clients: [], passes: 1, sitesPath: null, siteCount: 0, args: [], root: null, startedAt: "S" });
  assert.equal(noSites.sites.sha256, null);
  assert.equal(noSites.git, null);
});

console.log(`PASS parse (${n} cases)`);
