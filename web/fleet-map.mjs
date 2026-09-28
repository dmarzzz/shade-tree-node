// A privacy-preserving fleet "map": a static, self-contained HTML view of the fleet's
// geographic / network DIVERSITY -- how many independent vantage points the rotation spreads
// across -- WITHOUT deanonymizing or locating any single gateway.
//
// THREAT MODEL FIRST. The signed directory (lib/directory.mjs) is { onion, pubkey, weight,
// health } and DELIBERATELY carries no geo/IP data: a v3 onion service has no clearnet IP by
// design, and the fleet is non-enumerable on purpose. So there is NOTHING here to geolocate and
// we never try. onion -> country is both impossible (no IP) and against the point (it would
// deanonymize an operator). This map is driven ONLY by OPTIONAL, operator-SELF-DECLARED, COARSE
// labels a gateway may voluntarily advertise:
//
//     { onion, pubkey, weight, health, region?: "eu-west", asn?: "AS13335" }
//
// `region` / `asn` are free coarse strings (a broad region slug, an AS group) -- never a lat/long,
// never a city, never a precise address. A gateway that declares nothing simply lands in the
// "undeclared" aggregate. For the demo, web/fleet-map.sample.json is a static example dataset.
//
// PRIVACY (the whole reason this file is careful):
//   - AGGREGATE ONLY. The output is per-bucket COUNTS (+ summed weight). No onion, no pubkey, no
//     operator, no per-gateway row ever crosses into the page. There is no pin, no coordinate.
//   - SMALL-BUCKET FOLD (k-anonymity). A bucket whose count is < k is never shown under its own
//     label; it is merged into an UNNAMED "other" bucket. This is what stops the map from saying
//     "the only gateway in region X is ...": if a region has just one gateway, its NAME never
//     appears, so the map cannot single out that operator. Default k = 2 (a named bucket always
//     stands for >= 2 gateways). The "other" bucket is intentionally unnamed, so the folded
//     remainder is attributable to no specific region/ASN.
//
// It is a GENERATOR, mirroring web/status-server.mjs's shape (pure exported builders + a thin CLI)
// but producing a fully self-contained HTML file (inline CSS + inline SVG, no CDN, no map tiles,
// no fonts, no fetch) that renders from file:// with no network.
//
//   node web/fleet-map.mjs                          # sample dataset -> ./fleet-map.html
//   node web/fleet-map.mjs path/to/directory.json   # a directory JSON -> ./fleet-map.html
//   node web/fleet-map.mjs directory.json out.html   # explicit output path
//   SHADE_TREE_FLEET_MAP_K=3 node web/fleet-map.mjs        # stronger fold threshold
//
// Exported for tests: coarseLabel, bucketBy, bucketFleet, renderFleetMapHTML.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

// Minimum count for a bucket to appear under its own name. Below this it folds into the unnamed
// "other" bucket, so a named region/ASN always stands for at least k gateways and can never
// single out one operator. k = 2 is the floor (a name never means "exactly one"); raise it for a
// larger anonymity set.
export const DEFAULT_K = 2;

// The label a gateway lands in when it self-declares nothing. Not identifying -- it is itself an
// aggregate ("some gateways carry no label") and, like every label, still folds if it is too thin.
const UNDECLARED = "undeclared";

// The sink for folded small buckets. Deliberately UNNAMED: it stands for a remainder that is
// attributable to no specific region/ASN, so a lone gateway's region is never revealed.
const OTHER = "other";

// Normalize a self-declared label to a coarse, safe token. We intentionally KEEP it coarse: we do
// not parse or enrich it (no city, no geo lookup) -- whatever coarse string the operator chose,
// lowercased and length-capped, is all that ever appears. Empty / missing -> UNDECLARED.
export function coarseLabel(raw) {
  if (raw === null || raw === undefined) return UNDECLARED;
  const s = String(raw).trim().toLowerCase();
  if (!s) return UNDECLARED;
  // Reduce to a plain slug (a-z0-9._-) and cap the length. This is a markup-safety + length guard,
  // NOT a precision filter: declaring a COARSE label is the operator's responsibility. The real
  // privacy guarantees are aggregate-only output + the small-bucket fold below, which mean a
  // lone/over-precise label never gets its own named bar regardless.
  const safe = s.replace(/[^a-z0-9._-]+/g, "-").slice(0, 24).replace(/^-+|-+$/g, "");
  return safe || UNDECLARED;
}

// Bucket gateways by one self-declared field ("region" | "asn"), then FOLD every bucket whose
// count is < k into a single unnamed "other" bucket. Returns:
//   { field, k, total, shown: [{label,count,weight}...], folded: {count,weight,mergedLabels} }
// Invariant: no entry in `shown` has count < k, and `folded` (if present) carries no label list.
export function bucketBy(gateways, field, k = DEFAULT_K) {
  const counts = new Map(); // label -> { count, weight }
  for (const g of gateways || []) {
    const label = coarseLabel(g && g[field]);
    const cur = counts.get(label) || { count: 0, weight: 0 };
    cur.count += 1;
    cur.weight += Number(g && g.weight) || 0;
    counts.set(label, cur);
  }

  const shown = [];
  const folded = { count: 0, weight: 0, mergedLabels: 0 };
  for (const [label, { count, weight }] of counts) {
    if (count < k) {
      // Too thin to name: fold into the unnamed remainder. The LABEL is dropped here and never
      // reaches the page -- this is the line that prevents singling out a lone operator.
      folded.count += count;
      folded.weight += weight;
      folded.mergedLabels += 1;
    } else {
      shown.push({ label, count, weight });
    }
  }

  // Largest bucket first; stable by label for ties so the render is deterministic.
  shown.sort((a, b) => b.count - a.count || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  const out = { field, k, total: (gateways || []).length, shown };
  if (folded.count > 0) out.folded = folded;
  return out;
}

// Reduce a (signed or plain) directory to the aggregate diversity view: region + ASN buckets, both
// folded at k. This is the ONLY place gateway fields are read, and only `weight` + the coarse
// self-declared labels are ever touched -- onion / pubkey / operator are never referenced.
export function bucketFleet(dir, { k = DEFAULT_K, now = new Date() } = {}) {
  const gateways = (dir && dir.gateways) || [];
  const declaredRegion = gateways.filter((g) => coarseLabel(g && g.region) !== UNDECLARED).length;
  const declaredAsn = gateways.filter((g) => coarseLabel(g && g.asn) !== UNDECLARED).length;
  return {
    total: gateways.length,
    k,
    generatedAt: (now instanceof Date ? now : new Date(now)).toISOString(),
    declared: { region: declaredRegion, asn: declaredAsn },
    regions: bucketBy(gateways, "region", k),
    asns: bucketBy(gateways, "asn", k),
  };
}

// --- rendering ----------------------------------------------------------------------------------

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// A simple diversity metric: 1 - (largest bucket share). 0 = everything in one bucket (no
// diversity); approaches 1 as the fleet spreads evenly across many vantage points. Computed over
// SHOWN + folded buckets so a concentrated fleet reads as concentrated.
function spreadIndex(bucket) {
  const parts = bucket.shown.map((b) => b.count).concat(bucket.folded ? [bucket.folded.count] : []);
  const total = parts.reduce((n, c) => n + c, 0);
  if (total <= 0) return 0;
  const largest = Math.max(0, ...parts);
  return 1 - largest / total;
}

// Render one section (regions or ASNs) as an inline-SVG horizontal bar chart. Aggregate counts
// only -- one bar per shown bucket, plus one unnamed "other" bar for the folded remainder.
function renderBars(bucket, title, subtitle) {
  const rows = bucket.shown.map((b) => ({ label: b.label, count: b.count, weight: b.weight, folded: false }));
  if (bucket.folded) {
    rows.push({ label: OTHER, count: bucket.folded.count, weight: bucket.folded.weight, folded: true, merged: bucket.folded.mergedLabels });
  }

  const maxCount = Math.max(1, ...rows.map((r) => r.count));
  const ROW_H = 30, BAR_H = 18, LABEL_W = 128, PAD_R = 56, W = 560;
  const barMax = W - LABEL_W - PAD_R;
  const H = Math.max(ROW_H, rows.length * ROW_H);

  const svgRows = rows.map((r, i) => {
    const y = i * ROW_H + (ROW_H - BAR_H) / 2;
    const w = Math.max(2, (r.count / maxCount) * barMax);
    const cls = r.folded ? "bar folded" : "bar";
    const labelTitle = r.folded
      ? `other (${r.merged} coarse label${r.merged === 1 ? "" : "s"} folded, each < k=${bucket.k})`
      : esc(r.label);
    return (
      `<g transform="translate(0 ${y})">` +
      `<text class="blabel" x="${LABEL_W - 10}" y="${BAR_H / 2}" dominant-baseline="middle" text-anchor="end">${esc(r.label)}</text>` +
      `<rect class="btrack" x="${LABEL_W}" y="0" width="${barMax}" height="${BAR_H}" rx="4" />` +
      `<rect class="${cls}" x="${LABEL_W}" y="0" width="${w.toFixed(1)}" height="${BAR_H}" rx="4"><title>${labelTitle}: ${r.count}</title></rect>` +
      `<text class="bcount" x="${LABEL_W + barMax + 10}" y="${BAR_H / 2}" dominant-baseline="middle">${r.count}</text>` +
      `</g>`
    );
  }).join("");

  const spread = Math.round(spreadIndex(bucket) * 100);
  const namedShown = bucket.shown.length;
  return (
    `<section class="panel">` +
    `<div class="phead"><h2>${esc(title)}</h2><span class="pmeta">${namedShown} named &middot; spread ${spread}%</span></div>` +
    `<p class="psub">${esc(subtitle)}</p>` +
    `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)} distribution" preserveAspectRatio="xMinYMin meet">${svgRows}</svg>` +
    `</section>`
  );
}

// Build the full self-contained HTML page. No external URLs of any kind: inline CSS + inline SVG,
// no <script>, no <img>, no <link>, no fonts. Renders from file:// offline.
export function renderFleetMapHTML(dir, { k = DEFAULT_K, now = new Date(), title = "ShadeNet Canopy Map" } = {}) {
  const agg = bucketFleet(dir, { k, now });
  const regionSection = renderBars(
    agg.regions,
    "Regions",
    "Self-declared coarse region labels, aggregated. A region is named only when ≥ k gateways carry it.",
  );
  const asnSection = renderBars(
    agg.asns,
    "Networks (ASN)",
    "Self-declared coarse AS-group labels, aggregated. An AS group is named only when ≥ k gateways carry it.",
  );

  const cards = [
    { label: "Gateways", value: String(agg.total) },
    { label: "Regions named", value: String(agg.regions.shown.filter((b) => b.label !== UNDECLARED).length) },
    { label: "Networks named", value: String(agg.asns.shown.filter((b) => b.label !== UNDECLARED).length) },
    { label: "Fold threshold", value: "k = " + agg.k },
  ].map((c) => `<div class="card"><div class="clabel">${esc(c.label)}</div><div class="cvalue">${esc(c.value)}</div></div>`).join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" />
<title>${esc(title)}</title>
<style>
  :root {
    --bg: #0c0e12; --panel: #14181f; --panel-2: #1a1f28; --line: #262d38;
    --fg: #e6ebf2; --muted: #8a93a3; --accent: #7dd3fc; --accent-2: #a78bfa; --folded: #3a4453;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 32px 20px 64px; }
  .wrap { max-width: 880px; margin: 0 auto; }
  header { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  h1 { font-size: 18px; margin: 0; letter-spacing: 0.04em; font-weight: 600; }
  .sub { color: var(--muted); font-size: 12px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
  .card .clabel { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
  .card .cvalue { font-size: 22px; margin-top: 6px; font-weight: 600; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; margin: 14px 0; }
  .phead { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  .phead h2 { font-size: 13px; margin: 0; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; color: var(--fg); }
  .pmeta { color: var(--muted); font-size: 11px; }
  .psub { color: var(--muted); font-size: 11px; margin: 6px 0 12px; line-height: 1.6; }
  .chart { display: block; width: 100%; height: auto; }
  .chart .blabel { fill: var(--accent); font-size: 12px; }
  .chart .bcount { fill: var(--fg); font-size: 12px; font-weight: 600; }
  .chart .btrack { fill: var(--panel-2); }
  .chart .bar { fill: var(--accent); }
  .chart .bar.folded { fill: var(--folded); }
  .note { background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px;
    color: var(--muted); font-size: 12px; line-height: 1.7; margin: 14px 0; }
  .note strong { color: var(--fg); }
  code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; color: var(--accent); }
  footer { margin-top: 22px; color: var(--muted); font-size: 11px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>SHADE TREE &middot; FLEET MAP</h1>
    <div class="sub">generated ${esc(agg.generatedAt)}</div>
  </header>

  <div class="note">
    <strong>This is a diversity view, not a location map.</strong> Onion services have no clearnet IP
    by design, so a gateway <strong>cannot</strong> be geolocated and this page never tries. Every
    bar below comes only from <strong>optional, operator-self-declared, coarse</strong>
    <code>region</code> / <code>asn</code> labels (or the bundled sample dataset). Output is
    <strong>aggregate counts only</strong> &mdash; no onion, no operator, no coordinate, no per-gateway pin.
  </div>

  <div class="cards">${cards}</div>

  ${regionSection}
  ${asnSection}

  <div class="note">
    <strong>Privacy: small-bucket fold (k = ${esc(String(agg.k))}).</strong> A region or network is shown under
    its own name only when at least <strong>k</strong> gateways declare it. Anything thinner is merged
    into an unnamed <code>other</code> bar, so the map can never reveal that "the only gateway in
    region X is &hellip;". The <code>other</code> bar is intentionally nameless: its remainder is
    attributable to no specific region or network.
  </div>

  <footer>
    <span>self-contained &middot; no network &middot; renders from file://</span>
    <span>aggregate-only &middot; k-anonymized</span>
  </footer>
</div>
</body>
</html>
`;
}

// --- CLI ----------------------------------------------------------------------------------------

function loadDir(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function main() {
  const k = Math.max(2, Number(process.env.SHADE_TREE_FLEET_MAP_K) || DEFAULT_K);
  const inPath = process.argv[2] ? resolve(process.argv[2]) : join(HERE, "fleet-map.sample.json");
  const outPath = process.argv[3] ? resolve(process.argv[3]) : resolve(process.cwd(), "fleet-map.html");
  let dir;
  try {
    dir = loadDir(inPath);
  } catch (e) {
    console.error(`could not read directory JSON at ${inPath}: ${e.message}`);
    console.error("pass a signed/plain directory JSON, or omit the arg to use web/fleet-map.sample.json");
    process.exit(1);
  }
  const html = renderFleetMapHTML(dir, { k });
  writeFileSync(outPath, html);
  const agg = bucketFleet(dir, { k });
  console.log(`fleet map written to ${outPath}`);
  console.log(`  ${agg.total} gateways, k=${k}`);
  console.log(`  regions: ${agg.regions.shown.map((b) => `${b.label}(${b.count})`).join(" ") || "(none named)"}` +
    (agg.regions.folded ? ` +other(${agg.regions.folded.count})` : ""));
  console.log(`  asns:    ${agg.asns.shown.map((b) => `${b.label}(${b.count})`).join(" ") || "(none named)"}` +
    (agg.asns.folded ? ` +other(${agg.asns.folded.count})` : ""));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
