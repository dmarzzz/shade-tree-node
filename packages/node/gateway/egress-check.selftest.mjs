// Self-test for the gateway egress self-check + heartbeat announce-gating (T-FEAT-16).
//
// The problem: a gateway whose clearnet egress is broken (bad routing, firewall, dead
// upstream) still announces to the bootnode and then DROPs every member routed to it. The
// fix: the heartbeat probes egress before each announce and SKIPs announcing when it is DOWN,
// so a broken gateway ages out of the bootnode /directory via TTL and a healthy one keeps
// announcing. This proves both halves against INJECTED fakes — NO real network:
//
//   checkEgress (packages/node/gateway/gateway.mjs), with an injected connector:
//     - connector connects        => { healthy: true }
//     - connector errors          => { healthy: false } (never throws)
//     - connector hangs           => { healthy: false, reason: "timeout" } (short timeout)
//     - connector throws sync      => { healthy: false } (never throws)
//     - it is METADATA-ONLY: the probe never writes a byte to the socket
//
//   announceIfHealthy (packages/node/bootnode/heartbeat.mjs), with a fake checkEgress + fake announce:
//     - egress DOWN  => announce SKIPPED
//     - egress UP    => announce PROCEEDS
//     - SHADE_TREE_EGRESS_CHECK=0 => always announce (egress never even probed)
//
// Run:  node packages/node/gateway/egress-check.selftest.mjs
//
// gateway.mjs and heartbeat.mjs both import cleanly standalone (no port bound, no signal
// handlers, no heartbeat loop at import), so this pulls the functions straight out, no mocks.

import assert from "node:assert/strict";
import { checkEgress } from "./gateway.mjs";
import { announceIfHealthy, egressCheckEnabled } from "../bootnode/heartbeat.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// ---- fake connectors (net.connect(port, host, onConnect) -> socket-like) ----
// Each returns a minimal socket exposing .on(event, cb) and .destroy(); none touches a real
// network. A `writes` array records any bytes the probe tries to send (there must be none).

function connectorOk(writes) {
  return (port, host, onConnect) => {
    const sock = {
      on() { return sock; },
      write(chunk) { writes.push(chunk); return true; }, // must never be called by the probe
      destroy() {},
    };
    queueMicrotask(() => onConnect && onConnect()); // async "connected"
    return sock;
  };
}

function connectorErr(code = "ECONNREFUSED") {
  return () => {
    const handlers = {};
    const sock = {
      on(ev, cb) { handlers[ev] = cb; return sock; },
      write() { return true; },
      destroy() {},
    };
    queueMicrotask(() => handlers.error && handlers.error(Object.assign(new Error("refused"), { code })));
    return sock;
  };
}

function connectorHang() {
  // Never connects, never errors — forces the timeout path.
  return () => ({ on() { return this; }, write() { return true; }, destroy() {} });
}

function connectorThrows() {
  return () => { throw new Error("socket create failed"); };
}

// ---- checkEgress -------------------------------------------------------------

console.log("checkEgress — injected connector:");

await test("healthy when the connector connects", async () => {
  const writes = [];
  const r = await checkEgress({ target: "1.1.1.1:443", connect: connectorOk(writes) });
  assert.equal(r.healthy, true);
  assert.equal(r.target, "1.1.1.1:443");
  assert.equal(r.reason, "connected");
});

await test("METADATA-ONLY: a healthy probe writes NO bytes to the socket", async () => {
  const writes = [];
  await checkEgress({ target: "check-host:443", connect: connectorOk(writes) });
  assert.equal(writes.length, 0, "the probe must never send data — connect + close only");
});

await test("unhealthy on connect error, and never throws", async () => {
  const r = await checkEgress({ target: "1.1.1.1:443", connect: connectorErr("ECONNREFUSED") });
  assert.equal(r.healthy, false);
  assert.ok(String(r.reason).includes("ECONNREFUSED"), "reason carries the connect error code");
});

await test("unhealthy on timeout (connector hangs), short timeout so no real wait", async () => {
  const r = await checkEgress({ target: "1.1.1.1:443", connect: connectorHang(), timeoutMs: 5 });
  assert.equal(r.healthy, false);
  assert.equal(r.reason, "timeout");
});

await test("unhealthy (not a throw) when the connector throws synchronously", async () => {
  const r = await checkEgress({ target: "1.1.1.1:443", connect: connectorThrows() });
  assert.equal(r.healthy, false);
  assert.ok(String(r.reason).startsWith("connect-threw"));
});

await test("parses host:port from the target (default port 443 when absent)", async () => {
  const r = await checkEgress({ target: "example.net", connect: connectorOk([]) });
  assert.equal(r.target, "example.net:443");
});

// ---- announceIfHealthy (heartbeat gating) -----------------------------------

console.log("announceIfHealthy — egress-gated announce:");

const upEgress = async () => ({ healthy: true, target: "1.1.1.1:443", reason: "connected" });
const downEgress = async () => ({ healthy: false, target: "1.1.1.1:443", reason: "connect-error:ECONNREFUSED" });

await test("egress UP => announce PROCEEDS", async () => {
  let announced = 0;
  const r = await announceIfHealthy({
    enabled: true,
    egress: upEgress,
    announce: async () => { announced++; return { ok: true, ttl: 900 }; },
  });
  assert.equal(announced, 1, "announce ran exactly once");
  assert.equal(r.ok, true);
  assert.ok(!r.skipped);
});

await test("egress DOWN => announce SKIPPED", async () => {
  let announced = 0;
  const r = await announceIfHealthy({
    enabled: true,
    egress: downEgress,
    announce: async () => { announced++; return { ok: true }; },
  });
  assert.equal(announced, 0, "a broken gateway must NOT announce");
  assert.equal(r.skipped, true);
  assert.equal(r.egress.healthy, false);
});

await test("SHADE_TREE_EGRESS_CHECK=0 (disabled) => always announce, egress never probed", async () => {
  let announced = 0, probed = 0;
  const r = await announceIfHealthy({
    enabled: false, // simulates SHADE_TREE_EGRESS_CHECK=0
    egress: async () => { probed++; return { healthy: false }; },
    announce: async () => { announced++; return { ok: true, ttl: 900 }; },
  });
  assert.equal(announced, 1, "off-switch announces unconditionally (current behavior)");
  assert.equal(probed, 0, "disabled check must not even probe egress");
  assert.equal(r.ok, true);
});

await test("recovery: DOWN skips, then UP announces (announcing resumes, no state to reset)", async () => {
  let announced = 0;
  const announce = async () => { announced++; return { ok: true, ttl: 900 }; };
  const r1 = await announceIfHealthy({ enabled: true, egress: downEgress, announce });
  assert.equal(r1.skipped, true);
  assert.equal(announced, 0);
  const r2 = await announceIfHealthy({ enabled: true, egress: upEgress, announce });
  assert.equal(r2.ok, true);
  assert.equal(announced, 1, "once egress recovers the next beat announces again");
});

// ---- egressCheckEnabled: the off-switch reads SHADE_TREE_EGRESS_CHECK --------------

console.log("egressCheckEnabled — off-switch semantics:");

await test("default (unset) => ON; =0 => OFF; =1 => ON", async () => {
  const saved = process.env.SHADE_TREE_EGRESS_CHECK;
  try {
    delete process.env.SHADE_TREE_EGRESS_CHECK;
    assert.equal(egressCheckEnabled(), true, "unset defaults to ON");
    process.env.SHADE_TREE_EGRESS_CHECK = "0";
    assert.equal(egressCheckEnabled(), false, "=0 disables");
    process.env.SHADE_TREE_EGRESS_CHECK = "1";
    assert.equal(egressCheckEnabled(), true, "=1 enables");
  } finally {
    if (saved === undefined) delete process.env.SHADE_TREE_EGRESS_CHECK;
    else process.env.SHADE_TREE_EGRESS_CHECK = saved;
  }
});

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
