// Sites-file parser for the egress benchmark.
//
// One site per line, whitespace separated, `#` starts a comment line:
//
//   tier  name  wall  url  [min=<bytes>]  [ok-marker regex, rest of line, case-insensitive]
//
//   tier    search | web | api (api: an unauthenticated 401/403 with the marker counts as ok)
//   name    [a-z0-9_-], unique; the report row key
//   wall    the anti-bot vendor or policy in front of the site, as documented by whoever added
//           it (cloudflare, akamai, datadome, perimeterx, aws-waf, own, none, ...). The report
//           groups by it, because the vendor is the real axis (docs/exit-blocking-benchmark.md).
//   url     http(s) only
//   min=N   optional size guard: a 2xx that matched the marker but is under N bytes is an
//           interstitial wearing the site's title, not the page (see lib/classify.mjs)
//   marker  positive evidence the real page rendered. Without one a 2xx is `unverified`.
//
// The file is operator input, but it is still parsed strictly: a typo that silently drops a
// site or a marker that never matches would quietly change the measurement. Every malformed
// line is reported with its line number and nothing is returned.

export const TIERS = Object.freeze(["search", "web", "api"]);
const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;
const WALL_RE = /^[a-z0-9][a-z0-9+._-]{0,39}$/;
// A marker is a regex the harness runs on up to 8 MB of page. Cap its length and refuse the
// nested-quantifier shapes that backtrack catastrophically, e.g. (a+)+ or (.*)*.
const MAX_MARKER = 300;
const NESTED_QUANT = /\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)[+*{]/;

export function parseSites(text) {
  const sites = [];
  const errors = [];
  const seen = new Set();
  if (typeof text !== "string") return { ok: false, errors: ["sites file is not text"], sites: [] };
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, idx) => {
    const n = idx + 1;
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const m = /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/.exec(line);
    if (!m) { errors.push(`line ${n}: expected "tier name wall url [min=N] [marker]"`); return; }
    const [, tier, name, wall, url] = m;
    let rest = (m[5] || "").trim();
    let minBytes = null;
    const g = /^min=(\d{1,9})(?:\s+|$)/.exec(rest);
    if (g) { minBytes = Number(g[1]); rest = rest.slice(g[0].length).trim(); }
    if (!TIERS.includes(tier)) { errors.push(`line ${n}: unknown tier "${tier}"`); return; }
    if (!NAME_RE.test(name)) { errors.push(`line ${n}: bad name "${name}"`); return; }
    if (seen.has(name)) { errors.push(`line ${n}: duplicate name "${name}"`); return; }
    if (!WALL_RE.test(wall)) { errors.push(`line ${n}: bad wall label "${wall}"`); return; }
    let u;
    try { u = new URL(url); } catch { errors.push(`line ${n}: bad url`); return; }
    if (u.protocol !== "https:" && u.protocol !== "http:") { errors.push(`line ${n}: url must be http(s)`); return; }
    if (u.username || u.password) { errors.push(`line ${n}: url must not carry credentials`); return; }
    if (rest.length > MAX_MARKER) { errors.push(`line ${n}: marker longer than ${MAX_MARKER} chars`); return; }
    if (rest && NESTED_QUANT.test(rest)) { errors.push(`line ${n}: marker has a nested quantifier (catastrophic backtracking)`); return; }
    if (rest) {
      try { new RegExp(rest, "i"); } catch { errors.push(`line ${n}: marker is not a valid regex`); return; }
    }
    seen.add(name);
    sites.push({ tier, site: name, wall, url: u.href, okMarker: rest, minBytes, line: n });
  });
  if (!errors.length && !sites.length) errors.push("no sites");
  return errors.length ? { ok: false, errors, sites: [] } : { ok: true, errors: [], sites };
}

// Keep only the named sites (comma list), in file order. Unknown names are an error, so a
// typo in --only does not quietly run zero sites.
export function selectSites(sites, only) {
  if (!only) return { ok: true, sites };
  const want = String(only).split(",").map((s) => s.trim()).filter(Boolean);
  const names = new Set(sites.map((s) => s.site));
  const unknown = want.filter((w) => !names.has(w));
  if (unknown.length) return { ok: false, error: `unknown site(s): ${unknown.join(", ")}`, sites: [] };
  const keep = new Set(want);
  return { ok: true, sites: sites.filter((s) => keep.has(s.site)) };
}

// True when every URL points at this machine. Used by the CI guard in run.mjs.
export function isLoopbackHost(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}
export function allLoopback(sites) {
  return sites.every((s) => { try { return isLoopbackHost(new URL(s.url).hostname); } catch { return false; } });
}
