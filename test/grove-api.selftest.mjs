import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { GET } from "../docs/post/api/grove.mjs";
import {
  GROVE_MAX_BYTES,
  GROVE_NETWORK,
  GROVE_SNAPSHOT_URL,
  validGroveSnapshot,
  verifyGroveSnapshot,
} from "../docs/post/api/_grove-contract.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const snapshot = JSON.parse(await readFile(join(ROOT, "docs/post/grove/network.fallback.json"), "utf8"));
const dataApiSpec = await readFile(join(ROOT, "specs/data-api.md"), "utf8");
const dataApiOpenApi = await readFile(join(ROOT, "specs/data-api.openapi.yaml"), "utf8");
const originalFetch = globalThis.fetch;
const originalError = console.error;
const checks = [];

function check(name, condition) {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`  ok   ${name}`);
}

function upstream(body, { status = 200, contentType = "text/plain; charset=utf-8" } = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": contentType },
  });
}

async function requestWith(fetchImpl, request) {
  globalThis.fetch = fetchImpl;
  return GET(request);
}

try {
  check("reference snapshot passes API schema validation", validGroveSnapshot(snapshot));
  check("reference snapshot passes API attestation verification", verifyGroveSnapshot(snapshot));
  check("versioned API contract is bound to Sepolia", GROVE_NETWORK === "sepolia" && !validGroveSnapshot({ ...snapshot, network: "mainnet" }));
  check("network label cannot pass through regular-expression coercion", !validGroveSnapshot({ ...snapshot, network: null }));
  check("numeric timestamps cannot pass through Date.parse coercion", !validGroveSnapshot({
    ...snapshot,
    observedAt: 0,
    history: snapshot.history.map((sample, index) => index === snapshot.history.length - 1 ? { ...sample, at: 0 } : sample),
  }));
  check("non-canonical timestamps are rejected", !validGroveSnapshot({
    ...snapshot,
    observedAt: snapshot.observedAt.replace(".000Z", "Z"),
    history: snapshot.history.map((sample, index) => index === snapshot.history.length - 1
      ? { ...sample, at: sample.at.replace(".000Z", "Z") }
      : sample),
  }));

  let upstreamCall = null;
  const success = await requestWith(async (url, options) => {
    upstreamCall = { url, options };
    return upstream(snapshot);
  });
  const upstreamUrl = new URL(upstreamCall.url);
  const fixedSource = new URL(GROVE_SNAPSHOT_URL);
  check("API requests only the fixed signed-snapshot source", upstreamUrl.href === fixedSource.href);
  check("API fetch is bounded by a signal and refuses redirects", upstreamCall.options.signal instanceof AbortSignal && upstreamCall.options.redirect === "error");
  check("API revalidates the generated branch before applying its own cache", upstreamCall.options.cache === "no-store" && upstreamCall.options.headers["Cache-Control"] === "no-cache");
  check("API requests GitHub's raw representation with a pinned API version", upstreamCall.options.headers.Accept === "application/vnd.github.raw+json" && upstreamCall.options.headers["X-GitHub-Api-Version"] === "2022-11-28");
  check("API returns a successful JSON response", success.status === 200 && success.headers.get("content-type") === "application/json; charset=utf-8");
  const successBody = await success.text();
  check("API returns the signed envelope unchanged", successBody === `${JSON.stringify(snapshot)}\n`);
  check("API gives browsers a short cache", success.headers.get("cache-control") === "public, max-age=60");
  check("API gives Vercel a five-minute stale-while-revalidate cache", success.headers.get("vercel-cdn-cache-control") === "public, max-age=300, stale-while-revalidate=3600");
  const expectedEtag = `"${createHash("sha256").update(successBody).digest("base64url")}"`;
  check("API identifies its signed schema and hashes the exact response bytes", success.headers.get("x-shade-tree-schema") === snapshot.schema && success.headers.get("etag") === expectedEtag);
  check("public contract permits Vercel's weak transfer validator", /Vercel can expose the weak `W\/` form/.test(dataApiSpec) && /pattern: '\^\(\?:W\/\)\?/.test(dataApiOpenApi));
  check("API does not opt into cross-origin browser reads", success.headers.get("access-control-allow-origin") === null);

  const reorderedSnapshot = Object.fromEntries(Object.entries(snapshot).reverse());
  const reordered = await requestWith(async () => upstream(reorderedSnapshot));
  const reorderedBody = await reordered.text();
  check("byte-distinct valid envelopes receive distinct strong validators", reorderedBody !== successBody && reordered.headers.get("etag") !== expectedEtag);

  const conditional = await requestWith(
    async () => upstream(snapshot),
    new Request("https://shadenet.xyz/api/v1/data/grove/sepolia/head", {
      headers: { "If-None-Match": success.headers.get("etag") },
    }),
  );
  check("API honors a matching snapshot validator", conditional.status === 304 && await conditional.text() === "");

  const weakListConditional = await requestWith(
    async () => upstream(snapshot),
    new Request("https://shadenet.xyz/api/v1/data/grove/sepolia/head", {
      headers: { "If-None-Match": `"unrelated", W/${expectedEtag}` },
    }),
  );
  check("API weakly matches validators in an If-None-Match list", weakListConditional.status === 304);

  const wildcardConditional = await requestWith(
    async () => upstream(snapshot),
    new Request("https://shadenet.xyz/api/v1/data/grove/sepolia/head", {
      headers: { "If-None-Match": "*" },
    }),
  );
  check("API honors the If-None-Match wildcard", wildcardConditional.status === 304);

  let queryReachedUpstream = false;
  const unsupportedQuery = await requestWith(
    async () => {
      queryReachedUpstream = true;
      return upstream(snapshot);
    },
    new Request("https://shadenet.xyz/api/v1/data/grove/sepolia/head?cache-bust=1"),
  );
  check("API rejects unsupported query parameters before reaching upstream", unsupportedQuery.status === 400 && !queryReachedUpstream);
  check("unsupported query responses are generic and not cached", unsupportedQuery.headers.get("cache-control") === "no-store" && await unsupportedQuery.text() === '{"error":"unsupported_query"}\n');

  console.error = () => {};
  for (const [name, body, options] of [
    ["bad signature", { ...snapshot, attestation: { ...snapshot.attestation, signature: `B${snapshot.attestation.signature.slice(1)}` } }],
    ["extra field", { ...snapshot, directory: { gateways: [] } }],
    ["wrong content type", JSON.stringify(snapshot), { contentType: "text/html" }],
    ["oversized response", "x".repeat(GROVE_MAX_BYTES + 1)],
  ]) {
    const response = await requestWith(async () => upstream(body, options));
    check(`${name} fails closed with 503`, response.status === 503);
    check(`${name} failure is not cached`, response.headers.get("cache-control") === "no-store");
    check(`${name} does not reflect upstream details`, await response.text() === '{"error":"network_snapshot_unavailable"}\n');
  }

  const upstreamFailure = await requestWith(async () => upstream("unavailable", { status: 502 }));
  check("upstream HTTP failure returns 503", upstreamFailure.status === 503);
  check("upstream HTTP failure suggests a bounded retry", upstreamFailure.headers.get("retry-after") === "60");
} finally {
  globalThis.fetch = originalFetch;
  console.error = originalError;
}

console.log(`PASS: Grove API selftest (${checks.length} checks)`);
