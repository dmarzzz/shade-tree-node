// Outcome classifier for one egress benchmark cell: (exit, client, site) -> one label.
//
// The point of the benchmark is to tell a real page apart from every way a site can refuse an
// automated client, and to keep the refusals apart from each other: a 429 is rate limiting (a
// property of the request volume), a challenge or CAPTCHA is reputation or fingerprint scoring
// (a property of the IP and the client), a 403 is a flat deny. Folding them together hides the
// thing the egress design is about (docs/exit-blocking-benchmark.md).
//
// Labels, exactly one per cell:
//   ok                 2xx (or 401/403 for the api tier) AND the site's positive marker matched
//   blocked-429        HTTP 429 or a rate-limit page ("unusual traffic", "too many requests")
//   blocked-challenge  a JS / managed interstitial the client may pass by running code
//   captcha            an interactive human test
//   blocked-403        403/451 or a deny page with no challenge offered
//   timeout            transport timeout
//   error              transport or proxy error, no status, or 5xx
//   unverified         a status with neither a positive nor a block marker (needs a human look)
//
// Why a POSITIVE marker is required for ok: a 200 is not a page. Several walls answer 200 with
// an interstitial (Cloudflare "Just a moment", the Amazon "continue shopping" stub, Reddit's
// JS proof-of-work page). Without a marker those count as ok and the benchmark overstates reach.
// Why the marker WINS over block markers on a 2xx: real pages embed captcha widgets and
// mention "captcha" in text (the October medium false positive), so a page that proves it
// rendered is ok even when a block regex also matches.
//
// Pure: no I/O. Every input may be hostile (it is whatever a remote server sent), so the
// function never throws and does bounded work: block regexes run on a capped prefix, and the
// positive marker (supplied by the operator's sites file, not the server) runs on the full body
// because headed search result pages are 0.07 to 1.8 MB and the results container sits past
// the first 400 KB.

export const OUTCOMES = Object.freeze([
  "ok", "blocked-429", "blocked-challenge", "captcha", "blocked-403", "timeout", "error", "unverified",
]);

// Short forms for report cells (same as the November 2026 results tables).
export const ABBR = Object.freeze({
  ok: "ok", "blocked-challenge": "chl", captcha: "cap", "blocked-403": "403", "blocked-429": "429",
  timeout: "to", error: "err", unverified: "unv",
});

// Block markers are matched on at most this many characters of the lowercased body. Every
// interstitial we have seen is under 100 KB; the cap bounds regex work on a hostile 50 MB body.
export const BLOCK_SCAN_CHARS = 400_000;
// The positive marker scan is capped too, far above any real page, for the same reason.
export const MARKER_SCAN_CHARS = 8_000_000;

// [name, regex]. Order inside a table is the order of evidence; the first hit names the marker.
export const CAPTCHA = Object.freeze([
  ["recaptcha", /class="g-recaptcha|google\.com\/recaptcha|\/sorry\/index/],
  ["hcaptcha", /class="h-captcha|hcaptcha\.com\/1\/api/],
  ["perimeterx", /px-captcha|press (?:&amp;|&) hold|access to this page has been denied/],
  ["datadome", /captcha-delivery\.com/],
  ["ddg-ducks", /bots use duckduckgo too|select all squares containing a duck/],
  ["yandex-smartcaptcha", /are you not a robot|smart-captcha|showcaptcha/],
  ["title-captcha", /<title>\s*captcha/],
  ["robot-check", /are you a robot|suspect you.re a robot|verify you are human by completing/],
]);
export const CHALLENGE = Object.freeze([
  ["cf-just-a-moment", /<title>just a moment/],
  ["cf-chl", /cf-chl-|\/cdn-cgi\/challenge-platform\/h\/[gb]\/orchestrate/],
  ["cf-turnstile-interstitial", /verifying you are human|checking your browser|checking if the site connection is secure/],
  ["security-check-title", /<title>security check/],
  ["google-enablejs", /\/httpservice\/retry\/enablejs/],
  ["enable-js-cookies", /enable javascript and cookies to continue|please enable js and disable any ad blocker/],
  ["pow-challenge", /"challenge":\{"issuedat"|"rules":\{"algorithm"/],
  ["akamai-sec-cpt", /sec-if-cpt|_sec\/cp_challenge|behavioral-content/],
  ["amazon-continue-shopping", /click the button below to continue shopping/],
  ["reddit-js-pow", /nameditem\("solution"\)/],
  ["aws-waf-js", /awswafcookiedomainlist|token\.awswaf\.com/],
]);
export const DENY = Object.freeze([
  ["access-denied-title", /<title>access denied/],
  ["cf-you-have-been-blocked", /you have been blocked/],
  ["reddit-network-security", /blocked by network security/],
  ["forbidden-title", /<title>(?:403 )?forbidden/],
]);
export const RATE_LIMIT = Object.freeze([
  ["unusual-traffic", /unusual traffic from your computer/],
  ["too-many-requests", /too many requests/],
]);

// Size guards: a 2xx that matched the positive marker but is far too small to be the real page.
// Each was found by hand in the November 2026 run and checked against a screenshot:
//   amazon: a ~3.5 KB "Click the button below to continue shopping" page titled "Amazon.com"
//           (the real homepage is > 500 KB), so "<title>amazon" alone is not proof.
//   reddit: an ~8.4 KB page titled "Reddit" that runs a JS proof-of-work and auto-submits
//           (the real homepage is ~1.1 MB). curl cannot run it, so it is a challenge.
// Keyed by the site's `guard` field in the sites file: `min=<bytes>`.
export function sizeGuardFails(site, bytes) {
  const min = Number(site && site.minBytes);
  return Number.isFinite(min) && min > 0 && bytes < min;
}

function str(v) {
  if (typeof v === "string") return v;
  if (v == null || typeof v === "object" || typeof v === "function") return "";
  try { return String(v); } catch { return ""; }
}

// Lowercased header map from a plain object, a Map, a Headers instance, or garbage.
export function lowerHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  let entries = [];
  try {
    entries = typeof h.entries === "function" && !(h.constructor === Object) ? [...h.entries()] : Object.entries(h);
  } catch { return out; }
  for (const [k, v] of entries) {
    if (typeof k !== "string") continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.map(str).join(", ") : str(v);
  }
  return out;
}

function firstHit(table, hay) {
  for (const [name, re] of table) if (re.test(hay)) return name;
  return null;
}

// Best-effort anti-bot vendor from response headers (and two body tells). Evidence only, it
// never changes the label: a Cloudflare header on an ok page is normal.
export function vendorOf(headers, body = "") {
  const h = lowerHeaders(headers);
  const b = str(body).slice(0, BLOCK_SCAN_CHARS).toLowerCase();
  const server = (h.server || "").toLowerCase();
  const keys = Object.keys(h);
  const v = [];
  if ("cf-ray" in h || server.includes("cloudflare") || "cf-mitigated" in h) v.push("cloudflare");
  if (server.includes("akamai") || keys.some((k) => k.startsWith("akamai")) || "x-akamai-transformed" in h) v.push("akamai");
  if (keys.some((k) => k.startsWith("x-datadome")) || server.includes("datadome") || b.includes("captcha-delivery")) v.push("datadome");
  if (keys.some((k) => k.startsWith("x-px")) || b.includes("px-captcha") || b.includes("perimeterx")) v.push("perimeterx");
  if ("x-amz-cf-id" in h || server === "cloudfront") v.push("cloudfront");
  if ("x-amzn-waf-action" in h) v.push("aws-waf");
  if (server.includes("snooserv")) v.push("reddit");
  if ((h["x-served-by"] || "").includes("cache-")) v.push("fastly");
  return v;
}

export function titleOf(body) {
  const m = /<title[^>]*>([^<]{0,200})/i.exec(str(body).slice(0, BLOCK_SCAN_CHARS));
  return m ? m[1].replace(/\s+/g, " ").trim().slice(0, 120) : "";
}

// Compile a sites-file marker. Returns null for an absent or invalid one (the sites parser
// rejects invalid markers up front; this is the belt to that brace).
export function compileMarker(src) {
  if (src instanceof RegExp) return src;
  if (typeof src !== "string" || !src) return null;
  try { return new RegExp(src, "i"); } catch { return null; }
}

// classify({site, code, headers, body, title, finalUrl, transport}) -> {outcome, marker}
//   site:      {tier, okMarker (string|RegExp), minBytes?}
//   code:      HTTP status of the main document, or null
//   transport: null on a completed response, "timeout", or an error string
export function classify(input) {
  const { site: rawSite, code: rawCode = null, headers = {}, body: rawBody = "", title: rawTitle = "",
    finalUrl = "", transport = null } = input && typeof input === "object" ? input : {};
  const site = rawSite && typeof rawSite === "object" ? rawSite : {};
  if (transport === "timeout") return { outcome: "timeout", marker: null };
  if (transport) return { outcome: "error", marker: str(transport).slice(0, 160) };

  const code = Number.isInteger(rawCode) ? rawCode : (/^\d{3}$/.test(str(rawCode)) ? Number(rawCode) : null);
  const body = str(rawBody);
  const title = str(rawTitle) || titleOf(body);
  const h = lowerHeaders(headers);
  const low = body.slice(0, BLOCK_SCAN_CHARS).toLowerCase();
  const hay = `${low} ${str(finalUrl).slice(0, 2000).toLowerCase()} <title>${title.toLowerCase()}`;
  const is2xx = code !== null && code >= 200 && code < 300;
  const ok = compileMarker(site.okMarker);
  const markerHit = () => ok !== null && ok.test(`${body.slice(0, MARKER_SCAN_CHARS)} <title>${title}`);

  // api tier: an unauthenticated 401/403 with the API's own JSON error proves the path works.
  if (site.tier === "api" && (code === 401 || code === 403) && ok && ok.test(low)) {
    return { outcome: "ok", marker: `api-${code}` };
  }
  if (is2xx && markerHit()) {
    if (sizeGuardFails(site, body.length)) return { outcome: "blocked-challenge", marker: `small-page-${body.length}b` };
    return { outcome: "ok", marker: "ok-marker" };
  }
  if (code === 429) return { outcome: "blocked-429", marker: "http-429" };
  const rl = firstHit(RATE_LIMIT, low);
  if (rl) return { outcome: "blocked-429", marker: rl };

  if ((h["cf-mitigated"] || "").toLowerCase().includes("challenge")) return { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" };
  const waf = (h["x-amzn-waf-action"] || "").toLowerCase();
  if (waf === "captcha") return { outcome: "captcha", marker: "hdr-aws-waf-captcha" };
  if (waf === "challenge") return { outcome: "blocked-challenge", marker: "hdr-aws-waf-challenge" };
  // CloudFront answers a bot-scored client with an empty 202 (AWS WAF silent challenge).
  if (code === 202 && body.length < 5000 && ("x-amz-cf-id" in h || (h.server || "").toLowerCase() === "cloudfront")) {
    return { outcome: "blocked-challenge", marker: "cloudfront-202-stub" };
  }

  const cap = firstHit(CAPTCHA, hay);
  if (cap) return { outcome: "captcha", marker: cap };
  const chl = firstHit(CHALLENGE, hay);
  if (chl) return { outcome: "blocked-challenge", marker: chl };
  if (h["x-px-blocked"]) return { outcome: "captcha", marker: "hdr-x-px-blocked" };
  if (code === 403 || code === 451) return { outcome: "blocked-403", marker: `http-${code}` };
  const deny = firstHit(DENY, hay);
  if (deny) return { outcome: "blocked-403", marker: deny };

  if (code === null) return { outcome: "error", marker: "no-status" };
  if (code >= 500 && code < 600) return { outcome: "error", marker: `http-${code}` };
  if (is2xx && body.length < 200) return { outcome: "unverified", marker: `empty-${code}` };
  return { outcome: "unverified", marker: `http-${code}-no-marker` };
}
