// The benchmark loop: one exit x clients x sites x passes -> JSONL rows. CLI-free so the
// selftest can drive it against loopback servers; bench/egress/run.mjs is the thin CLI.
//
// Method rules (each one is about not measuring our own behavior instead of the site's):
//   - No retries. A block is the measurement; retrying until ok would report the retry policy.
//   - Fresh browser context per cell, so one cell's cookies or solved challenge never carry
//     into the next.
//   - Site order is shuffled per pass (seeded, so a run is reproducible) and the client order
//     rotates per site, so no site always comes first after a quiet period and no client always
//     gets the first request from a fresh IP (the first request is scored more leniently by
//     some vendors; PerimeterX on zillow did exactly that in the November 2026 run).
//   - Pacing: a minimum gap plus jitter between cells. For non-loopback targets the gap cannot
//     go below MIN_REAL_GAP_S. A ShadeNet member Proxy also has its own per-epoch slot budget
//     (direct-proof/session-init spends slots; session redemptions differ), and a browser loading one page opens many CONNECTs, so a
//     too-small gap shows up as `epoch-budget` refusals: our own budget, not the site.

import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { classify, titleOf, vendorOf, lowerHeaders } from "./classify.mjs";
import { runCurl, runNode, Browsers, userAgent, CLIENTS } from "./clients.mjs";
import { allLoopback } from "./sites.mjs";
import { newnym } from "./exits.mjs";

export const MIN_REAL_GAP_S = 2;
const KEEP_HEADERS = ["server", "cf-mitigated", "x-amzn-waf-action", "x-datadome", "x-px-blocked", "x-cache", "content-type"];

// Small seeded PRNG (mulberry32) so the shuffle is reproducible from --seed.
export function rng(seed) {
  let a = (Number(seed) >>> 0) || 1;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export function shuffle(xs, rand) {
  const a = [...xs];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
export function rotate(xs, k) {
  if (!xs.length) return [];
  const n = ((k % xs.length) + xs.length) % xs.length;
  return [...xs.slice(n), ...xs.slice(0, n)];
}

// Validate the parts of a run plan that protect real sites. -> {ok, error?}
export function checkPlan({ sites, clients, gapS, real, ci = process.env.CI }) {
  if (!Array.isArray(sites) || !sites.length) return { ok: false, error: "no sites" };
  const bad = (clients || []).filter((c) => !CLIENTS.includes(c));
  if (!clients || !clients.length || bad.length) return { ok: false, error: `unknown client(s): ${bad.join(",") || "(none given)"}` };
  const local = allLoopback(sites);
  // CI must never touch a real site, whatever flags a workflow passes.
  if (ci && !local) return { ok: false, error: "refusing to run against non-loopback sites under CI" };
  // A real run is opt-in, so a fat-fingered invocation cannot spray the site list.
  if (!local && !real) return { ok: false, error: "sites are not loopback: pass --real to run a real measurement (read bench/egress/README.md first)" };
  if (!local && !(gapS >= MIN_REAL_GAP_S)) return { ok: false, error: `--gap must be >= ${MIN_REAL_GAP_S}s for real sites` };
  return { ok: true };
}

function artifactUrl(value) {
  try {
    const u = new URL(value);
    u.username = ""; u.password = ""; u.search = ""; u.hash = "";
    return u.href;
  } catch { return String(value || ""); }
}

export function buildRow({ ts, runId, label, kind, exitTag, client, pass, site, res, outcome, marker, ua }) {
  const body = res.body || "";
  const hl = lowerHeaders(res.headers);
  const keep = {};
  for (const k of KEEP_HEADERS) if (k in hl) keep[k] = String(hl[k]).slice(0, 80);
  return {
    ts, run: runId, exit: label, exit_kind: kind, ...exitTag, client, pass,
    tier: site.tier, site: site.site, wall: site.wall, url: artifactUrl(site.url), url_sha256: createHash("sha256").update(site.url || "").digest("hex"),
    browser_version: res.browserVersion || null,
    code: res.code ?? null, connect_code: res.connectCode ?? null, t: Math.round((res.t || 0) * 100) / 100,
    outcome, marker, title: (res.title || titleOf(body)).slice(0, 120), vendor: vendorOf(hl, body),
    final_url: artifactUrl(res.finalUrl).slice(0, 200), bytes: body.length, failed_reqs: res.failedRequests ?? null,
    err: res.transport && res.transport !== "timeout" ? String(res.transport).slice(0, 160) : null,
    hdr: keep, ua: client === "curl" || client === "node" ? ua : "browser-default", shot: res.screenshot || null,
  };
}

// opts: {exit, label, kind, clients, sites, passes, gapS, passGapS, seed, uaMode, torControl,
//        timeoutS, shotsDir, runId, write(row), log(line), sleep(ms), chromium, ca, ignoreHTTPSErrors, settleMs}
export async function runMatrix(opts) {
  const { exit, label, kind, clients, sites, passes = 3, gapS = 4, passGapS = 60, seed = 7, uaMode = "chrome",
    torControl = null, timeoutS = 45, shotsDir = null, runId, write, log = () => {}, sleep = (ms) => delay(ms, undefined, { signal: opts.signal }).catch(e => { if (e.name !== "AbortError") throw e; }),
    chromium = null, ca, ignoreHTTPSErrors = false, settleMs = 6000, now = () => new Date().toISOString(), exitTag = () => ({}) } = opts;
  const ua = userAgent(uaMode);
  const rand = rng(seed);
  const modes = clients.filter((c) => c === "headless" || c === "headed");
  const browsers = modes.length
    ? await new Browsers({ exit, modes, chromium, navTimeoutMs: timeoutS * 1000, settleMs, ignoreHTTPSErrors }).start()
    : null;
  const counts = {};
  try {
    for (let pass = 1; pass <= passes; pass++) {
      const order = shuffle(sites, rand);
      for (let i = 0; i < order.length; i++) {
        const site = order[i];
        if (torControl) {
          const r = await newnym(torControl, { sleep });
          if (!r.ok) log(`newnym failed: ${r.reason}`);
        }
        const tag = await exitTag();
        for (const client of rotate(clients, i + pass)) {
          if (opts.signal?.aborted) return counts;
          let res;
          const shot = shotsDir && (client === "headless" || client === "headed")
            ? `${shotsDir}/${label}-${client}-${site.site}-p${pass}.png` : null;
          if (client === "curl") res = await runCurl(exit, site, { timeoutS, ua, localOnly: opts.localOnly, signal: opts.signal });
          else if (client === "node") res = await runNode(exit, site, { timeoutS, ua, ca, localOnly: opts.localOnly, signal: opts.signal });
          else res = await browsers.run(client, site, { screenshot: shot, localOnly: opts.localOnly, signal: opts.signal });
          const { outcome, marker } = classify({ site, code: res.code, headers: res.headers, body: res.body, title: res.title, finalUrl: res.finalUrl, transport: res.transport });
          const row = buildRow({ ts: now(), runId, label, kind, exitTag: tag, client, pass, site, res, outcome, marker, ua });
          await write(row);
          counts[outcome] = (counts[outcome] || 0) + 1;
          log(`[${label} p${pass}] ${site.site.padEnd(12)} ${client.padEnd(8)} ${String(res.code ?? "-").padEnd(4)} ${outcome.padEnd(17)} ${marker || ""} ${(res.t || 0).toFixed(1)}s`);
          if (!opts.signal?.aborted) await sleep((gapS + rand() * 2) * 1000);
        }
      }
      if (pass < passes) await sleep(passGapS * 1000);
    }
  } finally {
    if (browsers) await browsers.close();
  }
  return counts;
}
