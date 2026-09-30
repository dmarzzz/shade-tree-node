// Offline proof of per-tunnel SOCKS circuit isolation (T-FEAT-17) — no Tor, no network.
//
// Tor with `IsolateSOCKSAuth` (packages/node/bootnode/deploy/torrc.hardened, T-HARD-7) forks a SEPARATE
// circuit per distinct SOCKS username/password. The client used to send NO auth, so tunnels
// through one SocksPort could share a circuit — undoing the per-tunnel rotation's
// unlinkability. ShadeTreeClient now gives each TUNNEL a unique SOCKS credential derived from its
// nonce, so each tunnel rides its own circuit. This test drives that logic directly:
//
//   - socksAuthForTunnel(nonce): DIFFERENT tunnels (nonces) => DIFFERENT, well-formed creds.
//   - deterministic-retry choice: the SAME nonce => the SAME cred (a retry / failover of one
//     logical tunnel reuses the SAME circuit identity — the documented decision).
//   - no seed => a fresh random cred per call.
//   - _dial forwards the per-tunnel cred into the SOCKS proxy config (distinct tunnels pass
//     distinct auth; the same tunnel reuses one cred across attempts + gateway failover), and
//     legacy null-auth omits the credentials entirely.
//
//   node packages/node/client/socks-isolation.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import assert from "node:assert/strict";
import { socksAuthForTunnel, ShadeTreeClient } from "./shade-tree-client.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + ((e && e.message) || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

const HEX32 = /^[0-9a-f]{32}$/;

// A fake `socks` lib: records every createConnection() proxy config, returns a dummy socket.
function fakeSocks() {
  const calls = [];
  return {
    calls,
    createConnection: async ({ proxy, destination }) => {
      calls.push({ proxy: { ...proxy }, destination });
      return { socket: { setNoDelay() {} } };
    },
  };
}

console.log("socksAuthForTunnel (pure):");

await test("distinct tunnels (nonces) => distinct userId AND password", () => {
  const a = socksAuthForTunnel("nonce-A");
  const b = socksAuthForTunnel("nonce-B");
  assert.notEqual(a.userId, b.userId, "distinct userId across tunnels");
  assert.notEqual(a.password, b.password, "distinct password across tunnels");
});

await test("credentials are well-formed opaque tags (32 hex chars, uid !== pwd)", () => {
  const a = socksAuthForTunnel("nonce-A");
  assert.ok(HEX32.test(a.userId), "userId is 32 hex chars");
  assert.ok(HEX32.test(a.password), "password is 32 hex chars");
  assert.notEqual(a.userId, a.password, "userId and password differ within one credential");
});

await test("deterministic retry: SAME nonce => SAME credential (same circuit identity)", () => {
  const a1 = socksAuthForTunnel("nonce-A");
  const a2 = socksAuthForTunnel("nonce-A");
  assert.deepEqual(a1, a2, "a retry / failover of one tunnel reuses the same SOCKS credential");
});

await test("no seed => a fresh random credential per call", () => {
  const a = socksAuthForTunnel();
  const b = socksAuthForTunnel();
  assert.ok(HEX32.test(a.userId) && HEX32.test(a.password), "random creds are well-formed");
  assert.notEqual(a.userId, b.userId, "unseeded calls yield distinct userId");
  assert.notEqual(a.password, b.password, "unseeded calls yield distinct password");
});

console.log("_dial (injected fake SocksClient):");

await test("distinct tunnels pass distinct SOCKS auth into the proxy config", async () => {
  const fake = fakeSocks();
  const client = new ShadeTreeClient({ secret: "test-secret", onion: "gatewayonion", socksClient: fake });
  await client._dial("gatewayonion", 1, socksAuthForTunnel("req-1"));
  await client._dial("gatewayonion", 1, socksAuthForTunnel("req-2"));
  assert.equal(fake.calls.length, 2);
  const [p1, p2] = fake.calls.map((c) => c.proxy);
  assert.ok(HEX32.test(p1.userId) && HEX32.test(p1.password), "auth threaded into proxy.userId/password");
  assert.notEqual(p1.userId, p2.userId, "distinct tunnels => distinct proxy.userId");
  assert.notEqual(p1.password, p2.password, "distinct tunnels => distinct proxy.password");
});

await test("same tunnel reuses ONE credential across attempts + gateway failover", async () => {
  const fake = fakeSocks();
  const client = new ShadeTreeClient({ secret: "test-secret", onion: "gatewayonion", socksClient: fake });
  const auth = socksAuthForTunnel("one-logical-tunnel");
  // three dials standing in for cold-start retries + a failover to another gateway onion
  await client._dial("onionA", 1, auth);
  await client._dial("onionA", 1, auth);
  await client._dial("onionB", 1, auth);
  const uids = fake.calls.map((c) => c.proxy.userId);
  const pwds = fake.calls.map((c) => c.proxy.password);
  assert.ok(uids.every((u) => u === auth.userId), "same tunnel keeps one userId across all dials");
  assert.ok(pwds.every((p) => p === auth.password), "same tunnel keeps one password across all dials");
});

await test("legacy null auth: no userId/password on the proxy (harmless no-auth dial)", async () => {
  const fake = fakeSocks();
  const client = new ShadeTreeClient({ secret: "test-secret", onion: "gatewayonion", socksClient: fake });
  await client._dial("gatewayonion", 1, null);
  const p = fake.calls[0].proxy;
  assert.ok(!("userId" in p), "no userId when isolation auth is null");
  assert.ok(!("password" in p), "no password when isolation auth is null");
  assert.equal(p.type, 5, "still a SOCKS5 proxy config");
});

await test("socksIsolation:false disables auth derivation (toggle off)", async () => {
  const off = new ShadeTreeClient({ secret: "test-secret", onion: "g", socksClient: fakeSocks(), socksIsolation: false });
  assert.equal(off.socksIsolation, false, "toggle honored");
  const on = new ShadeTreeClient({ secret: "test-secret", onion: "g", socksClient: fakeSocks() });
  assert.equal(on.socksIsolation, true, "default-ON");
});

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
