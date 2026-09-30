// Self-test for the configurable egress target policy (T-DEV-10).
//
// Drives makeEgressPolicy() directly (pure, no gateway process, no sockets) and proves:
//   - default (no env) allows host:443 and denies :80/:22/other ports  (today's rule)
//   - the default policy is BYTE-EQUIVALENT to the old `port === 443` rule across a table
//   - `*.example.com:8443` permits sub.example.com:8443 but NOT the bare apex nor evil.com
//   - a deny pattern overrides an allow (deny wins, evaluated first)
//   - `*` host / `*` port wildcards behave, and the 1..65535 range still holds
//   - malformed patterns are dropped safely (never widen or break the policy)
//
// Run:  node packages/node/gateway/egress-policy.selftest.mjs
//
// gateway.mjs imports cleanly standalone (no signal handlers, no port bound at import),
// so this pulls makeEgressPolicy straight out with no lib mocks.

import assert from "node:assert/strict";
import {
  isPublicEgressAddress,
  MAX_EGRESS_ADDRESSES,
  makeEgressPolicy,
  privateTargetsAllowed,
  resolveEgressTarget,
} from "./gateway.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
function test(name, fn) { try { fn(); ok(name); } catch (e) { bad(name, e); } }
async function testAsync(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// The old, hardcoded rule this policy must preserve by default (verbatim from the
// pre-T-DEV-10 validTarget): a target is valid iff its port is exactly 443.
const oldRule = (host, port) => Number.isInteger(port) && port >= 1 && port <= 65535 && port === 443;

console.log("egress policy — default (no env):");

test("default allows any host on :443", () => {
  const p = makeEgressPolicy({}); // unset env => allow `*:443`, deny ""
  assert.equal(p("example.com", 443), true);
  assert.equal(p("sub.example.com", 443), true);
  assert.equal(p("anything.at.all", 443), true);
});

test("default denies :80, :22, and other non-443 ports", () => {
  const p = makeEgressPolicy({});
  assert.equal(p("example.com", 80), false);
  assert.equal(p("example.com", 22), false);
  assert.equal(p("example.com", 8443), false);
  assert.equal(p("example.com", 442), false);
});

test("default is BYTE-EQUIVALENT to the old :443-only rule across a target table", () => {
  const p = makeEgressPolicy({});
  const hosts = ["example.com", "sub.example.com", "a.b.c.example.com", "evil.com", "localhost", "1.2.3.4"];
  const ports = [1, 22, 79, 80, 81, 442, 443, 444, 8080, 8443, 65535];
  for (const h of hosts) {
    for (const port of ports) {
      assert.equal(p(h, port), oldRule(h, port), `mismatch at ${h}:${port}`);
    }
  }
});

console.log("egress policy — subdomain wildcard `*.example.com:8443`:");

test("`*.` matches subdomains but NOT the bare apex, and not other hosts", () => {
  const p = makeEgressPolicy({ allow: "*.example.com:8443" });
  assert.equal(p("sub.example.com", 8443), true, "subdomain allowed");
  assert.equal(p("a.b.example.com", 8443), true, "nested subdomain allowed");
  assert.equal(p("example.com", 8443), false, "bare apex NOT matched by *.");
  assert.equal(p("evil.com", 8443), false, "unrelated host denied");
  assert.equal(p("notexample.com", 8443), false, "suffix must be dot-bounded");
});

test("subdomain wildcard is still port-exact", () => {
  const p = makeEgressPolicy({ allow: "*.example.com:8443" });
  assert.equal(p("sub.example.com", 8443), true);
  assert.equal(p("sub.example.com", 443), false, "wrong port denied");
  assert.equal(p("sub.example.com", 8444), false);
});

console.log("egress policy — deny overrides allow (deny wins):");

test("a deny pattern overrides a matching allow", () => {
  const p = makeEgressPolicy({ allow: "*.example.com:8443", deny: "bad.example.com:8443" });
  assert.equal(p("good.example.com", 8443), true, "non-denied subdomain still allowed");
  assert.equal(p("bad.example.com", 8443), false, "denied subdomain refused despite allow");
});

test("a broad deny beats a broad allow", () => {
  const p = makeEgressPolicy({ allow: "*:443", deny: "*:443" });
  assert.equal(p("example.com", 443), false, "deny *:443 wins over allow *:443");
});

test("deny by host-any on a specific port", () => {
  const p = makeEgressPolicy({ allow: "*.corp.net:*", deny: "*:22" });
  assert.equal(p("host.corp.net", 8443), true);
  assert.equal(p("host.corp.net", 22), false, "ssh denied even though host+port* allowed");
});

console.log("egress policy — wildcards, ranges, multiple patterns:");

test("`*` host and `*` port wildcards", () => {
  const anyPort = makeEgressPolicy({ allow: "example.com:*" });
  assert.equal(anyPort("example.com", 1), true);
  assert.equal(anyPort("example.com", 65535), true);
  assert.equal(anyPort("other.com", 443), false, "host still exact");

  const anyHost = makeEgressPolicy({ allow: "*:8080" });
  assert.equal(anyHost("whatever.com", 8080), true);
  assert.equal(anyHost("whatever.com", 8081), false);
});

test("port range 1..65535 enforced regardless of pattern", () => {
  const p = makeEgressPolicy({ allow: "*:*" });
  assert.equal(p("example.com", 0), false, "port 0 rejected");
  assert.equal(p("example.com", 65536), false, "port > 65535 rejected");
  assert.equal(p("example.com", -1), false);
  assert.equal(p("example.com", 65535), true);
  assert.equal(p("example.com", 1), true);
});

test("multiple comma-separated allow patterns union", () => {
  const p = makeEgressPolicy({ allow: "*:443, *.example.com:8443" });
  assert.equal(p("anyone.com", 443), true);
  assert.equal(p("sub.example.com", 8443), true);
  assert.equal(p("sub.example.com", 443), true, "matched by the *:443 clause");
  assert.equal(p("example.com", 8443), false, "apex not matched by *.example.com");
  assert.equal(p("other.com", 8443), false);
});

console.log("egress policy — malformed handled safely:");

test("malformed allow patterns are dropped, valid ones survive", () => {
  const p = makeEgressPolicy({ allow: "garbage, :443, host:, host:notaport, *:443, host:99999" });
  assert.equal(p("example.com", 443), true, "the one valid `*:443` pattern still works");
  assert.equal(p("example.com", 80), false);
});

test("all-malformed allow => default-DENY everything", () => {
  const p = makeEgressPolicy({ allow: "garbage,:80,host:" });
  assert.equal(p("example.com", 443), false, "no valid allow => nothing passes");
  assert.equal(p("example.com", 80), false);
});

test("empty/whitespace inputs are safe", () => {
  const empty = makeEgressPolicy({ allow: "", deny: "" });
  assert.equal(empty("example.com", 443), false, "empty allow => deny-all");
  const spaces = makeEgressPolicy({ allow: "  ,  ,  " });
  assert.equal(spaces("example.com", 443), false);
});

test("bad host/port arguments never throw and return false", () => {
  const p = makeEgressPolicy({ allow: "*:*" });
  assert.equal(p(null, 443), false);
  assert.equal(p("", 443), false);
  assert.equal(p("example.com", "notaport"), false, "non-numeric port rejected");
  assert.equal(p("example.com", NaN), false);
  assert.equal(p("example.com", 44.3), false, "non-integer port rejected");
});

console.log("\negress policy — host canonicalization (trailing-dot bypass, audit loop-13):");

test("a trailing-dot FQDN cannot evade a host-specific deny", () => {
  // `sub.evil.com.` resolves to the SAME server as `sub.evil.com`, so appending a dot must NOT
  // slip past a `*.evil.com` deny (the HIGH finding). With a broad :443 allow, the deny must win.
  const p = makeEgressPolicy({ allow: "*:443", deny: "*.evil.com:*" });
  assert.equal(p("sub.evil.com", 443), false, "plain host denied");
  assert.equal(p("sub.evil.com.", 443), false, "trailing-dot host STILL denied (no bypass)");
  assert.equal(p("a.b.evil.com.", 443), false, "deeper dotted subdomain still denied");
});

test("trailing dot on an exact deny is still denied; exact allow still permits the dotted form", () => {
  const d = makeEgressPolicy({ allow: "*:443", deny: "bad.example.com:443" });
  assert.equal(d("bad.example.com", 443), false);
  assert.equal(d("bad.example.com.", 443), false, "dotted exact-deny host still denied");
  const a = makeEgressPolicy({ allow: "only.example.com:443" });
  assert.equal(a("only.example.com", 443), true);
  assert.equal(a("only.example.com.", 443), true, "dotted host of an exact allow is still permitted (no false deny)");
});

test("invalid empty-label hosts are dropped (default-deny)", () => {
  const p = makeEgressPolicy({ allow: "*:443" });
  assert.equal(p(".evil.com", 443), false, "leading-dot host dropped");
  assert.equal(p("sub..evil.com", 443), false, "double-dot host dropped");
  assert.equal(p(".", 443), false, "lone dot dropped");
});

console.log("\negress policy — public-address boundary and DNS pinning:");

test("public IPv4 and IPv6 addresses pass", () => {
  assert.equal(isPublicEgressAddress("1.1.1.1"), true);
  assert.equal(isPublicEgressAddress("8.8.8.8"), true);
  assert.equal(isPublicEgressAddress("2606:4700:4700::1111"), true);
  assert.equal(isPublicEgressAddress("2001:4860:4860::8888"), true);
});

test("loopback, private, link-local, shared, documentation, and multicast addresses fail", () => {
  for (const address of [
    "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
    "172.16.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.168.1.1",
    "192.175.48.1", "198.18.0.1", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1",
    "64:ff9b::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1",
    "fc00::1", "fe80::1", "ff02::1",
  ]) assert.equal(isPublicEgressAddress(address), false, address);
});

await testAsync("a literal private target fails closed by default", async () => {
  assert.deepEqual(
    await resolveEgressTarget({ ok: true, host: "169.254.169.254", port: 443 }),
    { ok: false, reason: "bad-target-address" },
  );
});

await testAsync("DNS answers are checked as a set and the chosen public address is pinned", async () => {
  const lookup = async (host, options) => {
    assert.equal(host, "example.com");
    assert.deepEqual(options, { all: true, verbatim: true });
    return [{ address: "93.184.216.34", family: 4 }, { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }];
  };
  const result = await resolveEgressTarget({ ok: true, host: "example.com", port: 443 }, { lookup });
  assert.deepEqual(result, {
    ok: true,
    host: "example.com",
    port: 443,
    address: "93.184.216.34",
    family: 4,
    addresses: [
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
    ],
  });
});

await testAsync("one private answer makes a mixed DNS response fail closed", async () => {
  const lookup = async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "127.0.0.1", family: 4 },
  ];
  assert.deepEqual(
    await resolveEgressTarget({ ok: true, host: "example.com", port: 443 }, { lookup }),
    { ok: false, reason: "bad-target-address" },
  );
});

await testAsync("the pinned dial set is capped only after every DNS answer passes the public-address check", async () => {
  const publicAnswers = Array.from({ length: MAX_EGRESS_ADDRESSES + 4 }, (_, i) => ({
    address: `8.8.4.${i + 1}`,
    family: 4,
  }));
  const bounded = await resolveEgressTarget(
    { ok: true, host: "many.example", port: 443 },
    { lookup: async () => publicAnswers },
  );
  assert.equal(bounded.ok, true);
  assert.equal(bounded.addresses.length, MAX_EGRESS_ADDRESSES, "one proof can dial at most the hard-capped answer count");
  assert.deepEqual(bounded.addresses, publicAnswers.slice(0, MAX_EGRESS_ADDRESSES));

  const poisonedAfterCap = [...publicAnswers, { address: "127.0.0.1", family: 4 }];
  assert.deepEqual(
    await resolveEgressTarget(
      { ok: true, host: "poisoned.example", port: 443 },
      { lookup: async () => poisonedAfterCap },
    ),
    { ok: false, reason: "bad-target-address" },
    "a private answer beyond the dial cap still rejects the whole hostname",
  );
});

await testAsync("DNS errors and empty answers fail closed without exposing resolver details", async () => {
  const throws = async () => { throw new Error("resolver detail"); };
  assert.deepEqual(await resolveEgressTarget({ ok: true, host: "missing.example", port: 443 }, { lookup: throws }), { ok: false, reason: "bad-target-dns" });
  assert.deepEqual(await resolveEgressTarget({ ok: true, host: "empty.example", port: 443 }, { lookup: async () => [] }), { ok: false, reason: "bad-target-dns" });
});

await testAsync("a stalled resolver is bounded", async () => {
  const never = () => new Promise(() => {});
  const started = Date.now();
  assert.deepEqual(
    await resolveEgressTarget({ ok: true, host: "stalled.example", port: 443 }, { lookup: never, timeoutMs: 5 }),
    { ok: false, reason: "bad-target-dns" },
  );
  assert.ok(Date.now() - started < 500, "resolver timeout returned promptly");
});

await testAsync("private destinations require the explicit local-development opt-in", async () => {
  const result = await resolveEgressTarget(
    { ok: true, host: "localhost", port: 443 },
    { lookup: async () => [{ address: "127.0.0.1", family: 4 }], allowPrivateTargets: true },
  );
  assert.equal(result.address, "127.0.0.1");
  assert.equal(privateTargetsAllowed({ SHADE_TREE_ALLOW_PRIVATE_TARGETS: "1" }), true);
  assert.equal(privateTargetsAllowed({ SHADE_TREE_ALLOW_PRIVATE_TARGETS: "true" }), false);
  assert.equal(privateTargetsAllowed({}), false);
});

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
