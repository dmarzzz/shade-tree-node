// Selftest for the egress benchmark classifier (bench/egress/lib/classify.mjs).
//
//   node bench/egress/classify.selftest.mjs
//
// The classifier reads untrusted bytes (whatever a site or proxy sent), and its label IS the
// measurement, so a wrong label is a wrong result. The cases below are the real failure modes
// found by hand in the November 2026 run (each one once produced a wrong label), plus hostile
// input. Each assertion fails on a specific defect: a flipped precedence, a lost size guard, a
// marker scan window that is too short, a regex that throws, a header lookup that is case
// sensitive.

import assert from "node:assert/strict";
import { classify, vendorOf, titleOf, lowerHeaders, compileMarker, sizeGuardFails, OUTCOMES, ABBR, BLOCK_SCAN_CHARS } from "./lib/classify.mjs";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log(`  ok   ${name}`); };
const web = (okMarker, extra = {}) => ({ tier: "web", okMarker, ...extra });
const c = (o) => classify(o);

t("every outcome has an abbreviation and OUTCOMES is closed", () => {
  for (const o of OUTCOMES) assert.ok(ABBR[o], o);
  assert.equal(Object.keys(ABBR).length, OUTCOMES.length);
});

t("plain ok needs a positive marker", () => {
  assert.deepEqual(c({ site: web("id=\"main\""), code: 200, body: '<div id="main">' }), { outcome: "ok", marker: "ok-marker" });
  assert.equal(c({ site: web(""), code: 200, body: "<html>" + "a".repeat(500) }).outcome, "unverified");
  assert.equal(c({ site: web("id=\"main\""), code: 200, body: "<html>" + "a".repeat(500) }).marker, "http-200-no-marker");
});

t("marker matches the title even when the body does not carry it", () => {
  assert.equal(c({ site: web("<title>hacker news"), code: 200, body: "x".repeat(300), title: "Hacker News" }).outcome, "ok");
});

t("a captcha widget inside a real page is ok when the marker matched (medium false positive)", () => {
  const body = '<title>Medium</title><div class="g-recaptcha"></div> human stories ' + "z".repeat(1000);
  assert.equal(c({ site: web("human stories"), code: 200, body }).outcome, "ok");
  // and without the marker the same widget is a captcha, so the precedence really matters
  assert.equal(c({ site: web("never-there"), code: 200, body }).outcome, "captcha");
});

t("marker past the 400 KB block-scan window still counts (headed SERP pages are up to 1.8 MB)", () => {
  const body = "<title>weather today - Search</title>" + "q".repeat(BLOCK_SCAN_CHARS + 50_000) + '<ol id="b_results">';
  assert.equal(c({ site: web('id="b_results"'), code: 200, body }).outcome, "ok");
});

t("block markers past the scan window are ignored (bounded work on hostile bodies)", () => {
  const body = "<title>x</title>" + "q".repeat(BLOCK_SCAN_CHARS + 10) + "<title>just a moment";
  assert.equal(c({ site: web("never"), code: 200, body }).outcome, "unverified");
});

t("size guard: amazon interstitial wearing the real title is a challenge, the real page is ok", () => {
  const site = web('id="nav-logo', { minBytes: 10000 });
  const stub = '<title>Amazon.com</title><div id="nav-logo"></div>Click the button below to continue shopping';
  assert.equal(c({ site, code: 200, body: stub }).outcome, "blocked-challenge");
  assert.match(c({ site, code: 200, body: stub }).marker, /^small-page-/);
  assert.equal(c({ site, code: 200, body: stub + "w".repeat(10000) }).outcome, "ok");
  // boundary: exactly minBytes is not "under"
  const exact = '<div id="nav-logo">'.padEnd(10000, "w");
  assert.equal(exact.length, 10000);
  assert.equal(c({ site, code: 200, body: exact }).outcome, "ok");
  assert.equal(c({ site, code: 200, body: exact.slice(0, 9999) }).outcome, "blocked-challenge");
});

t("size guard ignores junk minBytes", () => {
  for (const v of [null, undefined, "abc", -5, 0, NaN]) assert.equal(sizeGuardFails({ minBytes: v }, 1), false, String(v));
  assert.equal(sizeGuardFails(null, 1), false);
});

t("reddit JS proof-of-work page is a challenge even with a 200", () => {
  const body = '<title>Reddit</title><script>document.forms.namedItem("solution")</script>';
  assert.deepEqual(c({ site: web("heart of the internet", { minBytes: 60000 }), code: 200, body }), { outcome: "blocked-challenge", marker: "reddit-js-pow" });
});

t("CloudFront 202 empty stub is a challenge; a 202 with a big body is not", () => {
  assert.equal(c({ site: web("x"), code: 202, headers: { Server: "CloudFront" }, body: "" }).outcome, "blocked-challenge");
  assert.equal(c({ site: web("x"), code: 202, headers: { "X-Amz-Cf-Id": "a" }, body: "" }).marker, "cloudfront-202-stub");
  assert.notEqual(c({ site: web("x"), code: 202, headers: { server: "cloudfront" }, body: "b".repeat(6000) }).marker, "cloudfront-202-stub");
});

t("429 beats every reputation marker (rate limit is kept apart)", () => {
  assert.equal(c({ site: web("x"), code: 429, body: "<title>just a moment" }).outcome, "blocked-429");
  assert.equal(c({ site: web("x"), code: 200, body: "Our systems have detected unusual traffic from your computer network" }).outcome, "blocked-429");
});

t("header signals are case-insensitive and typed correctly", () => {
  assert.deepEqual(c({ site: web("x"), code: 403, headers: { "CF-Mitigated": "challenge" } }), { outcome: "blocked-challenge", marker: "hdr-cf-mitigated" });
  assert.equal(c({ site: web("x"), code: 405, headers: { "X-Amzn-Waf-Action": "CAPTCHA" } }).outcome, "captcha");
  assert.equal(c({ site: web("x"), code: 202, headers: { "x-amzn-waf-action": "challenge" } }).outcome, "blocked-challenge");
  assert.equal(c({ site: web("x"), code: 200, headers: { "x-px-blocked": "1" }, body: "z".repeat(300) }).outcome, "captcha");
  assert.equal(c({ site: web("x"), code: 200, headers: new Map([["CF-MITIGATED", "challenge"]]) }).outcome, "blocked-challenge");
});

t("captcha vendors are told apart from challenges and denies", () => {
  const cases = [
    ['<script src="https://geo.captcha-delivery.com/c.js">', "captcha", "datadome"],
    ["Press &amp; Hold to confirm you are a human", "captcha", "perimeterx"],
    ["<title>Captcha</title>", "captcha", "title-captcha"],
    ["Bots use DuckDuckGo too. Select all squares containing a duck", "captcha", "ddg-ducks"],
    ["<title>Just a moment...</title>", "blocked-challenge", "cf-just-a-moment"],
    ["/httpservice/retry/enablejs?sei=", "blocked-challenge", "google-enablejs"],
    ["<title>Access Denied</title>", "blocked-403", "access-denied-title"],
    ["Sorry, you have been blocked", "blocked-403", "cf-you-have-been-blocked"],
    ["You've been blocked by network security.", "blocked-403", "reddit-network-security"],
  ];
  for (const [body, outcome, marker] of cases) assert.deepEqual(c({ site: web("never"), code: 200, body }), { outcome, marker }, body);
});

t("captcha precedence over challenge, challenge over plain 403", () => {
  assert.equal(c({ site: web("never"), code: 403, body: '<title>just a moment</title><div class="h-captcha">' }).outcome, "captcha");
  assert.equal(c({ site: web("never"), code: 403, body: "<title>just a moment</title>" }).outcome, "blocked-challenge");
  assert.deepEqual(c({ site: web("never"), code: 403, body: "nope" }), { outcome: "blocked-403", marker: "http-403" });
  assert.deepEqual(c({ site: web("never"), code: 451, body: "" }), { outcome: "blocked-403", marker: "http-451" });
});

t("a final URL on Google's /sorry/ page is a captcha even when the body is empty", () => {
  assert.equal(c({ site: web("never"), code: 200, body: "", finalUrl: "https://www.google.com/sorry/index?continue=x" }).outcome, "captcha");
});

t("api tier: unauthenticated 401/403 with the API error is ok; a 403 HTML deny is not", () => {
  const api = { tier: "api", okMarker: "invalid_api_key|\"error\"" };
  assert.deepEqual(c({ site: api, code: 401, body: '{"error":{"code":"invalid_api_key"}}' }), { outcome: "ok", marker: "api-401" });
  assert.equal(c({ site: api, code: 403, body: "<title>Access Denied</title>" }).outcome, "blocked-403");
  // the api exception does not leak into the web tier
  assert.equal(c({ site: { tier: "web", okMarker: "\"error\"" }, code: 401, body: '{"error":1}' }).outcome, "unverified");
});

t("transport outcomes: timeout and error never look at the body", () => {
  assert.deepEqual(c({ site: web("x"), code: 200, body: "x", transport: "timeout" }), { outcome: "timeout", marker: null });
  assert.equal(c({ site: web("x"), transport: "error:curl-connect" }).outcome, "error");
  assert.equal(c({ site: web("x"), transport: "e".repeat(1000) }).marker.length, 160);
});

t("5xx is error, no status is error, tiny 2xx is unverified", () => {
  assert.deepEqual(c({ site: web("x"), code: 503, body: "down" }), { outcome: "error", marker: "http-503" });
  assert.deepEqual(c({ site: web("x"), code: null }), { outcome: "error", marker: "no-status" });
  assert.deepEqual(c({ site: web("x"), code: 200, body: "<html></html>" }), { outcome: "unverified", marker: "empty-200" });
  assert.deepEqual(c({ site: web("x"), code: 302, body: "" }), { outcome: "unverified", marker: "http-302-no-marker" });
});

t("string status codes are accepted, junk ones are not", () => {
  assert.equal(c({ site: web("yes"), code: "200", body: "yes" }).outcome, "ok");
  assert.equal(c({ site: web("yes"), code: "2OO", body: "yes" }).outcome, "error");
  assert.equal(c({ site: web("yes"), code: 200.5, body: "yes" }).outcome, "error");
});

t("hostile and garbage input never throws", () => {
  const weird = [undefined, null, 42, "str", [], { site: null }, { site: { okMarker: "(" }, code: 200, body: "(" },
    { site: { okMarker: 5 }, code: 200, body: {} }, { headers: "nope", body: Symbol.iterator.toString() },
    { headers: { toString: null, a: [1, 2] }, code: 200, body: { toString() { throw new Error("x"); } } },
    { site: web("x"), code: 200, body: "\u0000".repeat(1000), title: { length: 9 } }];
  for (const w of weird) {
    const r = classify(w);
    assert.ok(OUTCOMES.includes(r.outcome), JSON.stringify(r));
  }
});

t("a 2 MB body classifies in bounded time", () => {
  const body = ("<div class=\"g-rec" + "a".repeat(100)).repeat(20000);
  const t0 = Date.now();
  classify({ site: web("never-matches"), code: 200, body });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0}ms`);
});

t("an invalid marker regex is treated as no marker, not a crash", () => {
  assert.equal(compileMarker("(unclosed"), null);
  assert.equal(compileMarker(""), null);
  assert.equal(compileMarker(7), null);
  const re = /x/;
  assert.equal(compileMarker(re), re);
  assert.equal(c({ site: web("(unclosed"), code: 200, body: "(unclosed" + "a".repeat(300) }).outcome, "unverified");
});

t("vendorOf names the vendor from headers and two body tells", () => {
  assert.deepEqual(vendorOf({ "CF-RAY": "1" }), ["cloudflare"]);
  assert.deepEqual(vendorOf({ server: "AkamaiGHost" }), ["akamai"]);
  assert.deepEqual(vendorOf({ "x-akamai-transformed": "9" }), ["akamai"]);
  assert.deepEqual(vendorOf({}, "geo.captcha-delivery.com"), ["datadome"]);
  assert.deepEqual(vendorOf({ "x-px-foo": "1" }), ["perimeterx"]);
  assert.deepEqual(vendorOf({ server: "CloudFront", "x-amzn-waf-action": "challenge" }), ["cloudfront", "aws-waf"]);
  assert.deepEqual(vendorOf({ server: "snooserv" }), ["reddit"]);
  assert.deepEqual(vendorOf({ "x-served-by": "cache-fra1" }), ["fastly"]);
  assert.deepEqual(vendorOf(null, null), []);
});

t("titleOf and lowerHeaders are bounded and tolerant", () => {
  assert.equal(titleOf("<title>  A \n B </title>"), "A B");
  assert.equal(titleOf("<TITLE lang=en>" + "t".repeat(500)).length, 120);
  assert.equal(titleOf(null), "");
  assert.deepEqual(lowerHeaders({ A: "1", B: ["x", "y"] }), { a: "1", b: "x, y" });
  assert.deepEqual(lowerHeaders("x"), {});
  const bad = { get entries() { throw new Error("no"); } };
  Object.setPrototypeOf(bad, { constructor: Map });
  assert.deepEqual(lowerHeaders(bad), {});
});

console.log(`PASS classify (${n} cases)`);
