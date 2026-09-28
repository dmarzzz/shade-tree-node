import assert from "node:assert/strict";
import { once } from "node:events";
import { createEventSanitizer, createLabRunner, extractAnswer, labClientOptions } from "./runner.mjs";

let checks = 0;
function ok(condition, message) {
  assert.ok(condition, message);
  checks += 1;
  console.log(`  ok   ${message}`);
}

const sanitizer = createEventSanitizer();
const safe = sanitizer({
  phase: "prove", status: "done", slot: 2, epoch: "123", nullifier: "4", rlnIdentifier: "5", artifact: "rln-test",
  pub: { y: "1", root: "2", nullifier: "3", x: "4", externalNullifier: "5" },
  pi: { a: ["1", "2", "1"], b: [["3", "4"], ["5", "6"], ["1", "0"]], c: ["7", "8", "1"] },
});
ok(safe?.pub.root === "2" && safe?.pi.b[1][1] === "6", "real public signals and Groth16 points survive sanitization");
const node = sanitizer({ phase: "dial", status: "done", onion: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion", latencyMs: 42.4 });
ok(node.node === "node-1" && !JSON.stringify(node).includes("onion"), "node identities leave the runner only as ephemeral aliases");
ok(sanitizer({ phase: "unknown", status: "done", secret: "nope" }) === null, "unknown client events fail closed");
ok(extractAnswer("<main><h1>Example Domain</h1></main>") === "Example Domain", "the fixed response is reduced to its simple answer");
ok(
  labClientOptions({ SHADE_TREE_SECRET: "secret", SHADE_TREE_LIMIT: "8", SHADE_TREE_SLOT_STATE_DIR: "/durable/rln" }).slotStateDir === "/durable/rln",
  "the production client receives its durable RLN slot-state directory",
);
const mixedAdmission = labClientOptions({
  SHADE_TREE_SECRET: "secret",
  SHADE_TREE_LIMIT: "32",
  SHADE_TREE_LEAF_SOURCE: "invited",
  SHADE_TREE_MAX_ANON: "0",
});
ok(
  mixedAdmission.leafSource === "invited" && mixedAdmission.maxAnon === false,
  "the Lab can use an invited leaf through an explicitly authorized mixed-admission gateway",
);
ok(
  labClientOptions({ SHADE_TREE_SECRET: "secret" }).maxAnon === true,
  "the Lab preserves invited-only max-anon as its default",
);

let release;
const held = new Promise((resolve) => { release = resolve; });
let seenUrl;
const token = "t".repeat(64);
const server = createLabRunner({
  token,
  cooldownMs: 0,
  clientFactory: () => ({
    async fetch(url, opts) {
      seenUrl = url;
      opts.onEvent({ phase: "canopy", status: "verified", count: 3, issued: 10 });
      opts.onEvent({ phase: "select", status: "done", leafSource: "invited", candidates: [{ onion: "a".repeat(56) }] });
      opts.onEvent({ phase: "prove", status: "done", slot: 0, epoch: "10", nullifier: "3", rlnIdentifier: "4", artifact: "rln-test", pub: { y: "1", root: "2", nullifier: "3", x: "4", externalNullifier: "5" }, pi: { a: ["1", "2", "1"], b: [["3", "4"], ["5", "6"], ["1", "0"]], c: ["7", "8", "1"] } });
      await held;
      opts.onEvent({ phase: "egress", status: "done", httpStatus: 200, target: "example.com" });
      return { status: 200, body: "<h1>Example Domain</h1>" };
    },
  }),
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const base = `http://127.0.0.1:${server.address().port}`;

try {
  const health = await fetch(`${base}/health`);
  ok(health.ok && (await health.json()).target === "example.com", "health exposes no secret configuration");
  const denied = await fetch(`${base}/v1/run`, { method: "POST", body: "{}" });
  ok(denied.status === 401, "the run endpoint requires its server-side bearer token");
  const firstPromise = fetch(`${base}/v1/run`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "{}" });
  await new Promise((resolve) => setTimeout(resolve, 20));
  const busy = await fetch(`${base}/v1/run`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "{}" });
  ok(busy.status === 429, "only one proof-bearing run may be in flight");
  release();
  const first = await firstPromise;
  const stream = await first.text();
  ok(first.ok && /event: done/.test(stream) && /Example Domain/.test(stream), "a successful request streams trace events and a bounded result");
  ok(seenUrl === "https://example.com/", "callers cannot choose an arbitrary destination");
  ok(!/aaaaaa/.test(stream), "the streamed trace contains no raw onion identity");
} finally {
  server.close();
  await once(server, "close");
}

// The production factory is the SDK client; its ShadeNet codes reach the page as UPPER_SNAKE.
{
  const { ShadeNetError } = await import("@shadenet/sdk");
  const failing = createLabRunner({
    token,
    cooldownMs: 0,
    clientFactory: () => ({ async fetch() { throw new ShadeNetError("BudgetExhausted", "spent", { retryAfterMs: 5 }); } }),
  });
  failing.listen(0, "127.0.0.1");
  await once(failing, "listening");
  try {
    const res = await fetch(`http://127.0.0.1:${failing.address().port}/v1/run`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: "{}" });
    ok(/"code":"BUDGET_EXHAUSTED"/.test(await res.text()), "SDK error codes stream as UPPER_SNAKE public codes");
  } finally {
    failing.close();
    await once(failing, "close");
  }
}

console.log(`\n${checks} lab runner checks passed`);
