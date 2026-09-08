import assert from "node:assert/strict";

const origin = new URL(process.env.SITE_BASE_URL || "https://shade-tree-node.vercel.app/");
const attempts = Number(process.env.SITE_SMOKE_ATTEMPTS || 6);
const retryDelay = Number(process.env.SITE_SMOKE_RETRY_MS || 2500);

function endpoint(path) {
  return new URL(path.replace(/^\//, ""), origin).href;
}

async function pause(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function fetchWithRetry(path) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(endpoint(path), {
        headers: { "User-Agent": "shade-tree-site-smoke/1.0" },
        redirect: "follow",
        signal: AbortSignal.timeout(15_000),
      });
      if (response.status < 500 || attempt === attempts) return response;
      lastError = new Error(`${path} returned ${response.status}`);
    } catch (error) {
      lastError = error;
      if (attempt === attempts) throw error;
    }
    await pause(retryDelay);
  }
  throw lastError;
}

async function checkPage(path, marker) {
  const response = await fetchWithRetry(path);
  const html = await response.text();
  assert.equal(response.status, 200, `${path} should return 200`);
  assert.match(html, marker, `${path} should contain its page marker`);
  console.log(`  ok   ${path}`);
  return { response, html };
}

console.log(`Smoke testing ${origin.origin}`);

const home = await checkPage("/", /id="home-title"/);
await checkPage("/research/", /id="references"/);
await checkPage("/grove/", /id="grove-main"/);
await checkPage("/agent/", /<main\b/);
await checkPage("/operator/", /<main\b/);
await checkPage("/stake/", /data-member-steps/);

assert.match(home.html, /class="nav-lab"/, "the Lab route should remain explicitly hidden");
assert.doesNotMatch(home.html, /The best shade asks for proof, not a name\.<\/p>/, "removed footer copy must stay removed");

for (const asset of ["/site.css", "/site.js", "/grove.js", "/stake/stake.css", "/stake/stake.js", "/fig/shade-tree-readme.svg"]) {
  const response = await fetchWithRetry(asset);
  assert.equal(response.status, 200, `${asset} should return 200`);
  console.log(`  ok   ${asset}`);
}

for (const [path, schema] of [
  ["/api/v1/data/grove/sepolia/head", "shade-tree-public-grove-v1"],
  ["/api/v2/data/grove/sepolia/head", "shade-tree-public-grove-v2"],
]) {
  const response = await fetchWithRetry(path);
  const body = await response.json();
  if (response.status === 503 && path.includes("/v2/")) {
    assert.equal(body.error, "network_snapshot_unavailable", `${path} should fail closed when its upstream snapshot is unavailable`);
    assert.equal(response.headers.get("cache-control"), "no-store", `${path} unavailability must not be cached`);
    assert.match(response.headers.get("retry-after") || "", /^\d+$/, `${path} should tell clients when to retry`);
    console.log(`  ok   ${path} (documented upstream-unavailable state)`);
  } else {
    assert.equal(response.status, 200, `${path} should return 200`);
    assert.equal(body.schema, schema, `${path} should return ${schema}`);
    console.log(`  ok   ${path}`);
  }
}

const missing = await fetchWithRetry("/__shade_tree_missing_page__");
const missingHtml = await missing.text();
assert.equal(missing.status, 404, "unknown routes should return 404");
assert.match(missingHtml, /Trail not found|leaves the grove/i, "the branded 404 should be served");
console.log("  ok   branded 404");

if (origin.protocol === "https:") {
  const csp = home.response.headers.get("content-security-policy") || "";
  assert.match(csp, /default-src 'none'/, "production pages should keep the restrictive CSP");
  assert.equal(home.response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(home.response.headers.get("referrer-policy"), "no-referrer");
  console.log("  ok   production security headers");
}

console.log("PASS: production site smoke test");
