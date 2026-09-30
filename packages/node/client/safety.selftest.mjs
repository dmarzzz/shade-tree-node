// Client-side safety regressions: local RLN budget exhaustion and end-to-end node failover.
// No Tor, network, or Groth16 work. Fake SOCKS sockets drive the real ShadeTreeClient.connect path.

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { identityFor, rateCommitmentOf } from "../lib/rln.mjs";
import {
  ShadeTreeClient,
  ShadeTreeEpochBudgetError,
  buildEnvelope,
  makeSlotPool,
  retryableGatewayRefusal,
} from "./shade-tree-client.mjs";
import { proxyFailureLabel } from "./shim.mjs";

let failures = 0;
const slotWork = mkdtempSync(join(tmpdir(), "shade-tree-safety-slots-"));
let slotFileId = 0;
const slotStatePath = () => join(slotWork, `slots-${slotFileId++}.json`);
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

const fakeGroup = async () => ({ group: {}, source: "members.json" });
const fakeProve = async (_secret, epoch, slot, signal, opts = {}) => ({
  proof: {
    epoch: String(epoch),
    rlnIdentifier: "1",
    snarkProof: {
      publicSignals: { y: "1", root: "2", nullifier: `null-${epoch}-${slot}`, x: signal, externalNullifier: `ext-${epoch}` },
      proof: { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] },
    },
  },
  nullifier: `null-${epoch}-${slot}`,
  externalNullifier: `ext-${epoch}`,
  share: { x: signal, y: "1" },
  artifact: opts.artifact,
});

class FakeSocket extends EventEmitter {
  constructor(mode, writes) {
    super();
    this.mode = mode;
    this.writes = writes;
    this.destroyed = false;
    this.destroyCalls = 0;
  }
  setNoDelay() {}
  write(data, callback) {
    this.writes.push(String(data));
    const done = typeof callback === "function" ? callback : () => {};
    queueMicrotask(() => {
      if (this.mode === "write-error") { done(new Error("simulated write failure")); return; }
      done();
      if (this.mode === "oversize") this.emit("data", Buffer.from("x".repeat(33) + "\n"));
      else if (this.mode === "end") this.emit("end");
      else if (this.mode === "close") this.emit("close");
      else if (this.mode === "timeout") { /* bounded reader must finish this attempt */ }
      else if (this.mode === "malformed") this.emit("data", Buffer.from('{"ok":"yes"}\n'));
      else if (this.mode === "transient") this.emit("data", Buffer.from('{"ok":false,"err":"upstream:ETIMEDOUT"}\n'));
      else if (this.mode === "terminal") this.emit("data", Buffer.from('{"ok":false,"err":"gate:invalid-proof"}\n'));
      else if (this.mode === "version-mismatch") this.emit("data", Buffer.from('{"ok":false,"err":"unsupported-version:4","proto":{"min":5,"max":5}}\n'));
      else if (this.mode === "artifact-mismatch") this.emit("data", Buffer.from('{"ok":false,"err":"gate:artifact-unknown:test-artifact","artifacts":["other-artifact"]}\n'));
      else if (this.mode === "success-with-rest") {
        this.emit("data", Buffer.concat([Buffer.from('{"ok":true}\n'), Buffer.alloc(256, 0x61)]));
      } else this.emit("data", Buffer.from('{"ok":true}\n'));
    });
    return true;
  }
  end(callback) { callback?.(); }
  destroy() {
    this.destroyCalls += 1;
    if (this.destroyed) return this;
    this.destroyed = true;
    queueMicrotask(() => this.emit("close"));
    return this;
  }
}

function clientHarness(modes, { ackTimeoutMs = 15, ackMaxBytes = 32 } = {}) {
  const writes = [];
  const sockets = [];
  const reports = [];
  const events = [];
  const calls = [];
  const candidates = modes.map((_, index) => ({ onion: `node-${index}`, artifacts: ["test-artifact"] }));
  const fakeSocks = {
    async createConnection({ destination }) {
      const onion = destination.host.replace(/\.onion$/, "");
      const index = candidates.findIndex((candidate) => candidate.onion === onion);
      calls.push(onion);
      if (modes[index] === "dial-error") throw new Error("SOCKS dial failed");
      const socket = new FakeSocket(modes[index], writes);
      sockets[index] = socket;
      return { socket };
    },
  };
  const client = new ShadeTreeClient({
    secret: "test-secret",
    // This harness makes two independent tunnels to test learned per-onion capabilities.
    // Keep that fixture explicit now that the bundled live public profile correctly defaults to 1.
    limit: 2,
    socksClient: fakeSocks,
    socksIsolation: false,
    dialAttempts: 1,
    gatewayAckTimeoutMs: ackTimeoutMs,
    gatewayAckMaxBytes: ackMaxBytes,
    artifacts: ["test-artifact"],
    gatewayArtifacts: ["test-artifact"],
    loadGroupFn: fakeGroup,
    prove: fakeProve,
    slotStatePath: slotStatePath(),
  });
  client._candidates = async () => candidates;
  client._sel = async () => ({ reportResult: (onion, result) => reports.push({ onion, ...result }) });
  return { client, writes, sockets, reports, events, calls, connect: () => client.connect("example.com:443", { onEvent: (event) => events.push(event) }) };
}

console.log("local epoch budget:");

await test("default state is namespaced by the public member leaf and stores no bearer secret", () => {
  const secret = "0x01";
  const pool = makeSlotPool({
    secret, K: 2, epochOf: () => 9n, loadGroupFn: fakeGroup, prove: fakeProve,
    slotStateDir: join(slotWork, "default-state"),
  });
  const publicLeaf = rateCommitmentOf(identityFor(secret), 2).toString();
  assert.equal(basename(pool.statePath()), `${publicLeaf}.json`);
  assert.equal(pool.nextSlot().slot, 0);
  const raw = readFileSync(pool.statePath(), "utf8");
  assert.equal(raw.includes(secret), false);
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["epoch", "nextSlot", "version"]);
});

await test("the K+1 request throws typed reset metadata instead of reusing slot zero", () => {
  let epoch = 10n;
  const pool = makeSlotPool({
    secret: "s", K: 2, epochOf: () => epoch, epochSeconds: 60, now: () => 605_000,
    loadGroupFn: fakeGroup, prove: fakeProve, slotStatePath: slotStatePath(),
  });
  assert.deepEqual([pool.nextSlot().slot, pool.nextSlot().slot], [0, 1]);
  assert.throws(
    () => pool.nextSlot(),
    (error) => {
      assert.ok(error instanceof ShadeTreeEpochBudgetError);
      assert.equal(error.code, "SHADE_TREE_EPOCH_BUDGET_EXHAUSTED");
      assert.deepEqual(
        { epoch: error.epoch, limit: error.limit, used: error.used, remaining: error.remaining },
        { epoch: "10", limit: 2, used: 2, remaining: 0 },
      );
      assert.equal(error.resetAtMs, 660_000);
      assert.equal(error.retryAfterMs, 55_000);
      assert.equal(error.resetAt, "1970-01-01T00:11:00.000Z");
      assert.equal(proxyFailureLabel(error), "epoch-budget", "the local Proxy records a bounded exhaustion reason");
      return true;
    },
  );
  assert.deepEqual(pool.state(), { epoch: 10n, cursor: 2, remaining: 0, source: null }, "failure does not advance or wrap the cursor");
  epoch = 11n;
  assert.equal(pool.nextSlot().slot, 0, "the next real epoch resets the budget");
});

await test("slash tests can opt into slot reuse only through the explicit unsafe test seam", () => {
  const pool = makeSlotPool({
    secret: "s", K: 2, epochOf: () => 10n, loadGroupFn: fakeGroup, prove: fakeProve,
    unsafeAllowSlotReuseForTests: true,
  });
  assert.deepEqual([pool.nextSlot().slot, pool.nextSlot().slot, pool.nextSlot().slot], [0, 1, 0]);
});

await test("local envelope failures durably burn reservations so a restart cannot reuse them", async () => {
  const failProve = async () => { throw new Error("local prover failed"); };
  const state = slotStatePath();
  const pool = makeSlotPool({
    secret: "s", K: 2, epochOf: () => 10n, loadGroupFn: fakeGroup, prove: failProve, slotStatePath: state,
  });
  await assert.rejects(() => buildEnvelope({ secret: "s", target: "example.com:443", pool, prove: failProve }), /local prover failed/);
  assert.deepEqual(pool.state(), { epoch: 10n, cursor: 1, remaining: 1, source: "members.json" });
  const restarted = makeSlotPool({ secret: "s", K: 2, epochOf: () => 10n, loadGroupFn: fakeGroup, prove: fakeProve, slotStatePath: state });
  const built = await buildEnvelope({ secret: "s", target: "example.com:443", pool: restarted, prove: fakeProve });
  assert.equal(built.slot, 1, "restart advances past the slot allocated before the local failure");
  assert.throws(() => restarted.nextSlot(), ShadeTreeEpochBudgetError);
});

await test("concurrent reservations stay distinct and a failed proof cannot release one for reuse", async () => {
  const pending = [];
  const deferredProve = (...args) => new Promise((resolve, reject) => pending.push({ args, slot: args[2], resolve, reject }));
  const pool = makeSlotPool({
    secret: "s", K: 2, epochOf: () => 10n, loadGroupFn: fakeGroup, prove: fakeProve, slotStatePath: slotStatePath(),
  });
  const first = buildEnvelope({ secret: "s", target: "a.example:443", pool, prove: deferredProve })
    .then((value) => ({ value }), (error) => ({ error }));
  const second = buildEnvelope({ secret: "s", target: "b.example:443", pool, prove: deferredProve })
    .then((value) => ({ value }), (error) => ({ error }));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(pending.map(({ slot }) => slot), [0, 1], "concurrent builds reserve distinct slots");
  await assert.rejects(
    () => buildEnvelope({ secret: "s", target: "blocked.example:443", pool, prove: deferredProve }),
    ShadeTreeEpochBudgetError,
  );

  pending[0].reject(new Error("first local proof failed"));
  assert.match((await first).error.message, /first local proof failed/);
  await assert.rejects(
    () => buildEnvelope({ secret: "s", target: "c.example:443", pool, prove: deferredProve }),
    ShadeTreeEpochBudgetError,
    "the failed slot remains burned",
  );

  pending[1].resolve(await fakeProve(...pending[1].args));
  assert.equal((await second).value.slot, 1);
  assert.deepEqual(pool.state(), { epoch: 10n, cursor: 2, remaining: 0, source: "members.json" });
});

console.log("\nacknowledged failover:");

await test("dial, write, cap, EOF, close, timeout, and malformed-ack failures all fail over with one identical envelope", async () => {
  const h = clientHarness([
    "dial-error", "write-error", "oversize", "end", "close", "timeout", "malformed", "success-with-rest",
  ]);
  const started = Date.now();
  const tunnel = await h.connect();
  assert.ok(Date.now() - started < 1000, "the silent node was bounded by the ack timeout");
  assert.equal(h.calls.length, 8, "every failed stage advanced to the next candidate");
  assert.equal(h.writes.length, 7, "the SOCKS failure happened before a write; every connected node got one frame");
  assert.ok(h.writes.every((wire) => wire === h.writes[0]), "failover reused the byte-identical envelope");
  for (let index = 1; index <= 6; index++) {
    assert.equal(h.sockets[index].destroyed, true, `failed socket ${index} was destroyed`);
    assert.ok(h.sockets[index].destroyCalls >= 1, `failed socket ${index} had an explicit destroy path`);
  }
  assert.deepEqual(h.reports.map(({ onion, ok }) => ({ onion, ok })), [
    { onion: "node-0", ok: false },
    { onion: "node-1", ok: false },
    { onion: "node-2", ok: false },
    { onion: "node-3", ok: false },
    { onion: "node-4", ok: false },
    { onion: "node-5", ok: false },
    { onion: "node-6", ok: false },
    { onion: "node-7", ok: true },
  ], "health is positive only after ok:true; every failed attempt is negative");
  assert.equal(tunnel.shadeTree.onion, "node-7");
  assert.equal(tunnel.readableLength, 256, "bytes after the ack newline are tunnel data, not part of the ack cap");
  const ackMetricError = new Error("unbounded peer detail must not become a metric label");
  ackMetricError.code = "SHADE_TREE_GATEWAY_ACK_TIMEOUT";
  assert.equal(proxyFailureLabel(ackMetricError), "node-ack-failed");
  tunnel.destroy();
});

await test("a node-local transient refusal fails over, but a proof refusal is terminal and does not poison health", async () => {
  assert.equal(retryableGatewayRefusal({ err: "upstream:ETIMEDOUT" }), true);
  assert.equal(retryableGatewayRefusal({ err: "gate:invalid-proof" }), false);

  const transient = clientHarness(["transient", "success"], { ackMaxBytes: 128 });
  const tunnel = await transient.connect();
  assert.deepEqual(transient.reports.map(({ onion, ok }) => ({ onion, ok })), [
    { onion: "node-0", ok: false }, { onion: "node-1", ok: true },
  ]);
  assert.equal(transient.writes[0], transient.writes[1], "transient refusal retries the identical envelope");
  tunnel.destroy();

  const terminal = clientHarness(["terminal", "success"], { ackMaxBytes: 128 });
  let terminalError = null;
  try { await terminal.connect(); } catch (error) { terminalError = error; }
  assert.match(String(terminalError?.message || ""), /gate refused: gate:invalid-proof/, `calls=${terminal.calls.join(",")} events=${JSON.stringify(terminal.events)}`);
  assert.deepEqual(terminal.calls, ["node-0"], "terminal client/proof refusal does not sweep the fleet");
  assert.deepEqual(terminal.reports, [], "a client/proof refusal is not node-health evidence");
  assert.equal(terminal.sockets[0].destroyed, true);
});

await test("protocol and artifact rejects are onion-local and fail over with one envelope", async () => {
  const h = clientHarness(["version-mismatch", "artifact-mismatch", "success"], { ackMaxBytes: 256 });
  const first = await h.connect();
  assert.deepEqual(h.calls, ["node-0", "node-1", "node-2"]);
  assert.equal(h.writes.length, 3);
  assert.ok(h.writes.every((wire) => wire === h.writes[0]), "both capability failovers reused the byte-identical envelope");
  assert.deepEqual(h.reports.map(({ onion, ok }) => ({ onion, ok })), [
    { onion: "node-2", ok: true },
  ], "capability mismatch is not node-health evidence");
  assert.equal(h.client.gatewayRange, null, "one directory candidate did not become a global protocol cap");
  assert.deepEqual(h.client.gatewayArtifacts, ["test-artifact"], "one directory candidate did not replace the global artifact default");
  first.destroy();

  const callMark = h.calls.length;
  const reportMark = h.reports.length;
  const second = await h.connect();
  assert.deepEqual(h.calls.slice(callMark), ["node-2"], "future calls skip only the two onions learned incompatible");
  assert.deepEqual(h.reports.slice(reportMark).map(({ onion, ok }) => ({ onion, ok })), [
    { onion: "node-2", ok: true },
  ]);
  second.destroy();
});

rmSync(slotWork, { recursive: true, force: true });
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
