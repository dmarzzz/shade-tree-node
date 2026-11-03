// Aggregate egress benchmark JSONL into markdown tables. Pure: rows in, string out.
//
// Cell format: `ok/n` plus the non-ok labels by count, e.g. `1/3 chl:2` (the colon keeps
// "403 twice" from reading as "4032"). n is the number of rows
// for that (exit, client, site); it is printed so a reader never mistakes 1/1 for 3/3.
//
// The report deliberately has no single "percent blocked per exit" headline. The November 2026
// run showed exit type wins on some sites and loses on others (Tor reached reddit and amazon
// where every datacenter IP failed, and failed nike and indeed where datacenter passed), so a
// per-exit average hides the result. The summary is there, but the per-wall and per-site tables
// come right after it.

import { ABBR, OUTCOMES } from "./classify.mjs";

const TIER_ORDER = { search: 0, web: 1, api: 2 };

// Parse JSONL text; skip blank lines; collect (not throw on) malformed lines.
export function parseJsonl(text) {
  const rows = [];
  const metas = [];
  let bad = 0;
  for (const line of String(text || "").split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    let r;
    try { r = JSON.parse(s); } catch { bad++; continue; }
    if (!r || typeof r !== "object" || Array.isArray(r)) { bad++; continue; }
    if (r.type === "meta") { metas.push(r); continue; }
    if (r.type === "dial") { rows.push(r); continue; }
    if (typeof r.exit !== "string" || typeof r.client !== "string" || typeof r.site !== "string" || !OUTCOMES.includes(r.outcome)) { bad++; continue; }
    rows.push(r);
  }
  return { rows: rows.filter((r) => r.type !== "dial"), dials: rows.filter((r) => r.type === "dial"), metas, bad };
}

export function fmtCell(outs) {
  if (!outs || !outs.length) return ".";
  const ok = outs.filter((o) => o === "ok").length;
  const rest = new Map();
  for (const o of outs) if (o !== "ok") rest.set(o, (rest.get(o) || 0) + 1);
  const tail = [...rest.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, v]) => (ABBR[k] || k) + (v > 1 ? `:${v}` : "")).join(",");
  return `${ok}/${outs.length}` + (tail ? " " + tail : "");
}

export function quantile(xs, q) {
  const a = xs.filter((x) => Number.isFinite(x)).sort((p, r) => p - r);
  if (!a.length) return null;
  return a[Math.min(a.length - 1, Math.max(0, Math.ceil(q * a.length) - 1))];
}

const r1 = (x) => (x == null ? "-" : (Math.round(x * 10) / 10).toFixed(1));
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");

function uniq(xs) { return [...new Set(xs)]; }

export function buildReport({ rows = [], dials = [], metas = [] } = {}, { showIps = false, exitOrder = null, clientOrder = null, title = "Egress benchmark report" } = {}) {
  const out = [];
  const p = (s = "") => out.push(s);
  const exits = exitOrder ? exitOrder.filter((e) => rows.some((r) => r.exit === e)) : uniq(rows.map((r) => r.exit));
  const clients = clientOrder ? clientOrder.filter((c) => rows.some((r) => r.client === c)) : uniq(rows.map((r) => r.client));
  const siteKeys = uniq(rows.map((r) => `${r.tier}\u0000${r.site}`)).map((k) => { const [tier, site] = k.split("\u0000"); return { tier, site }; })
    .sort((a, b) => (TIER_ORDER[a.tier] ?? 9) - (TIER_ORDER[b.tier] ?? 9) || a.site.localeCompare(b.site));
  const wallOf = new Map(rows.map((r) => [r.site, r.wall || ""]));
  const cell = new Map();
  for (const r of rows) {
    const k = `${r.exit}\u0000${r.client}\u0000${r.site}`;
    if (!cell.has(k)) cell.set(k, []);
    cell.get(k).push(r.outcome);
  }
  const get = (e, c, s) => cell.get(`${e}\u0000${c}\u0000${s}`) || [];

  p(`# ${esc(title)}`);
  p();
  const passes = uniq(rows.map((r) => r.pass)).length;
  const ts = rows.map((r) => r.ts).filter(Boolean).sort();
  p(`${rows.length} cells: ${exits.length} exit(s) x ${clients.length} client(s) x ${siteKeys.length} site(s), ${passes} pass(es)` +
    (ts.length ? `, ${ts[0]} to ${ts[ts.length - 1]}` : "") + ".");
  p("Cells are ok/n. chl = blocked-challenge, cap = captcha, 403 = blocked-403, 429 = blocked-429, to = timeout, err = error, unv = unverified; ':2' is a count.");
  p();

  if (rows.length) {
    p("## Summary: share of cells ok");
    p();
    p(`| client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|${exits.map(() => "---|").join("")}`);
    for (const c of clients) {
      const vals = exits.map((e) => {
        const outs = rows.filter((r) => r.exit === e && r.client === c).map((r) => r.outcome);
        if (!outs.length) return ".";
        const ok = outs.filter((o) => o === "ok").length;
        return `${ok}/${outs.length} (${Math.floor((100 * ok) / outs.length)}%)`;
      });
      p(`| ${esc(c)} | ${vals.join(" | ")} |`);
    }
    p();

    const walls = uniq(siteKeys.map((s) => wallOf.get(s.site))).sort();
    p("## By wall (anti-bot vendor in front of the site)");
    p();
    p(`| wall | client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|---|${exits.map(() => "---|").join("")}`);
    for (const w of walls) {
      for (const c of clients) {
        const vals = exits.map((e) => fmtCell(rows.filter((r) => r.exit === e && r.client === c && (r.wall || "") === w).map((r) => r.outcome)));
        if (vals.every((v) => v === ".")) continue;
        p(`| ${esc(w || "-")} | ${esc(c)} | ${vals.join(" | ")} |`);
      }
    }
    p();

    for (const c of clients) {
      p(`## Per site, client = ${esc(c)}`);
      p();
      p(`| tier | site | wall | ${exits.map(esc).join(" | ")} |`);
      p(`|---|---|---|${exits.map(() => "---|").join("")}`);
      for (const s of siteKeys) p(`| ${esc(s.tier)} | ${esc(s.site)} | ${esc(wallOf.get(s.site) || "-")} | ${exits.map((e) => fmtCell(get(e, c, s.site))).join(" | ")} |`);
      p();
    }

    p("## Page time, seconds (p50 / p90, all cells that returned a status)");
    p();
    p(`| client | ${exits.map(esc).join(" | ")} |`);
    p(`|---|${exits.map(() => "---|").join("")}`);
    for (const c of clients) {
      const vals = exits.map((e) => {
        const ts2 = rows.filter((r) => r.exit === e && r.client === c && r.code != null).map((r) => Number(r.t));
        return ts2.length ? `${r1(quantile(ts2, 0.5))} / ${r1(quantile(ts2, 0.9))}` : ".";
      });
      p(`| ${esc(c)} | ${vals.join(" | ")} |`);
    }
    p();
  }

  if (dials.length) {
    p("## Dial time through the exit, seconds (tunnel open = CONNECT 200 or SOCKS ready, then TLS)");
    p();
    p("| exit | phase | n | failed | tunnel p50 | tunnel max | total p50 | total max |");
    p("|---|---|---|---|---|---|---|---|");
    const keys = uniq(dials.map((d) => `${d.exit}\u0000${d.phase}`));
    for (const k of keys) {
      const [e, ph] = k.split("\u0000");
      const ds = dials.filter((d) => d.exit === e && d.phase === ph);
      const good = ds.filter((d) => !d.error);
      const tun = good.map((d) => d.tTunnelMs / 1000);
      const tot = good.map((d) => d.tTotalMs / 1000);
      p(`| ${esc(e)} | ${esc(ph)} | ${ds.length} | ${ds.length - good.length} | ${r1(quantile(tun, 0.5))} | ${r1(quantile(tun, 1))} | ${r1(quantile(tot, 0.5))} | ${r1(quantile(tot, 1))} |`);
    }
    p();
  }

  if (metas.length) {
    p("## Provenance");
    p();
    for (const m of metas) {
      const x = m.exitInfo || {};
      const where = [x.org, x.country].filter(Boolean).join(", ") || "exit not looked up";
      const ip = showIps && x.ip ? ` ${x.ip}` : "";
      const git = m.git && m.git.commit ? `${String(m.git.commit).slice(0, 12)}${m.git.dirty ? "+dirty" : ""}` : "unknown";
      const v = m.versions || {};
      p(`- \`${esc(m.run)}\`: exit \`${esc(m.exit)}\` (${esc(m.exitKind)}, ${esc(m.exitSpec)}): ${esc(where)}${esc(ip)}. ` +
        `clients ${esc((m.clients || []).join(","))}, passes ${esc(m.passes)}, started ${esc(m.startedAt)}. ` +
        `harness ${esc(git)}, node ${esc(v.node)}, chromium ${esc(v.chromium || "-")}, ${esc(v.curl || "curl ?")}. ` +
        `host ${esc(m.host && m.host.cpus)} x ${esc(m.host && m.host.cpu)}, ${esc(m.host && m.host.os)}.`);
    }
    p();
  }
  return out.join("\n");
}
