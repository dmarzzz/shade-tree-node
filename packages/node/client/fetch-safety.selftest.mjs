// ShadeTreeClient.fetch safety boundaries. No Tor, TLS, gateway, or proof work.

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import {
  DEFAULT_FETCH_MAX_BODY_BYTES,
  DEFAULT_FETCH_TIMEOUT_MS,
  ShadeTreeClient,
  ShadeTreeFetchError,
} from "./shade-tree-client.mjs";

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

class Destroyable extends EventEmitter {
  constructor() {
    super();
    this.destroyed = false;
    this.destroyCalls = 0;
  }
  destroy() {
    this.destroyed = true;
    this.destroyCalls += 1;
    return this;
  }
}

class FakeRequest extends Destroyable {
  constructor(start) {
    super();
    this.start = start;
    this.writes = [];
    this.ended = false;
  }
  write(body) { this.writes.push(body); }
  end() {
    this.ended = true;
    this.start?.();
  }
}

function harness({ response, chunks = [], timeoutMs = 1000, maxBodyBytes = 1024, connect } = {}) {
  const tunnel = new Destroyable();
  tunnel.shadeTree = { onion: "node-0", slot: 3 };
  const calls = [];
  let request;
  const client = Object.create(ShadeTreeClient.prototype);
  client.fetchTimeoutMs = timeoutMs;
  client.fetchMaxBodyBytes = maxBodyBytes;
  client.connect = connect || (async () => tunnel);
  client._httpsRequest = (options, onResponse) => {
    calls.push(options);
    request = new FakeRequest(() => {
      if (!response) return;
      queueMicrotask(() => {
        onResponse(response);
        for (const chunk of chunks) response.emit("data", chunk);
        response.emit("end");
      });
    });
    return request;
  };
  return { client, tunnel, calls, request: () => request };
}

console.log("fetch safety:");

await test("finite defaults are exported", () => {
  assert.equal(DEFAULT_FETCH_TIMEOUT_MS, 120_000);
  assert.equal(DEFAULT_FETCH_MAX_BODY_BYTES, 8 * 1024 * 1024);
});

await test("invalid and timer-overflowing fetch bounds fall back safely", () => {
  const client = new ShadeTreeClient({
    secret: "11".repeat(32),
    fetchTimeoutMs: 2_147_483_648,
    fetchMaxBodyBytes: 0,
  });
  assert.equal(client.fetchTimeoutMs, DEFAULT_FETCH_TIMEOUT_MS);
  assert.equal(client.fetchMaxBodyBytes, DEFAULT_FETCH_MAX_BODY_BYTES);
});

await test("a bounded response preserves the public result shape", async () => {
  const response = new Destroyable();
  response.statusCode = 201;
  response.headers = { "content-type": "text/plain" };
  const h = harness({ response, chunks: [Buffer.from("shade"), " tree"] });
  const result = await h.client.fetch("https://example.com/path?q=grove", {
    method: "POST", headers: { "x-test": "1" }, body: "seed",
  });
  assert.deepEqual(result, {
    status: 201,
    headers: { "content-type": "text/plain" },
    body: "shade tree",
    gateway: { onion: "node-0", slot: 3 },
  });
  assert.equal(h.calls[0].path, "/path?q=grove");
  assert.equal(h.request().writes[0], "seed");
  assert.equal(h.tunnel.destroyed, false, "a successful response is not force-destroyed");
});

await test("an oversized response rejects with byte metadata and destroys every owned layer", async () => {
  const response = new Destroyable();
  response.statusCode = 200;
  response.headers = {};
  const events = [];
  const h = harness({ response, chunks: [Buffer.from("1234"), Buffer.from("56789")], maxBodyBytes: 100 });
  await assert.rejects(
    () => h.client.fetch("https://example.com/stream", { maxBodyBytes: 8, onEvent: (event) => events.push(event) }),
    (error) => {
      assert.ok(error instanceof ShadeTreeFetchError);
      assert.equal(error.code, "SHADE_TREE_FETCH_BODY_TOO_LARGE");
      assert.equal(error.maxBodyBytes, 8);
      assert.equal(error.receivedBytes, 9);
      assert.equal(error.retryable, false);
      assert.match(error.message, /per-call \{ maxBodyBytes \}/);
      return true;
    },
  );
  assert.equal(response.destroyed, true);
  assert.equal(h.request().destroyed, true);
  assert.equal(h.tunnel.destroyed, true);
  assert.deepEqual(events.at(-1), {
    phase: "egress", status: "error",
    error: "ShadeTreeClient.fetch response exceeded 8 bytes; raise { fetchMaxBodyBytes } or per-call { maxBodyBytes } only for a trusted destination",
    code: "SHADE_TREE_FETCH_BODY_TOO_LARGE",
  });
});

await test("the operation deadline covers a stalled connect and closes a late tunnel", async () => {
  let releaseConnect;
  const lateTunnel = new Destroyable();
  const connect = () => new Promise((resolve) => { releaseConnect = () => resolve(lateTunnel); });
  const h = harness({ timeoutMs: 1000, connect });
  const started = Date.now();
  await assert.rejects(
    () => h.client.fetch("https://example.com/stall", { timeoutMs: 15 }),
    (error) => {
      assert.ok(error instanceof ShadeTreeFetchError);
      assert.equal(error.code, "SHADE_TREE_FETCH_TIMEOUT");
      assert.equal(error.timeoutMs, 15);
      assert.equal(error.retryable, true);
      assert.match(error.message, /per-call \{ timeoutMs \}/);
      return true;
    },
  );
  assert.ok(Date.now() - started < 500, "the public operation did not wait for connect");
  assert.equal(h.calls.length, 0, "no HTTPS request starts after the deadline");
  releaseConnect();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lateTunnel.destroyed, true, "a tunnel acquired after timeout is immediately closed");
});

await test("a stalled response destroys the request and tunnel at the same total deadline", async () => {
  const response = new Destroyable();
  response.statusCode = 200;
  response.headers = {};
  const h = harness({ response, chunks: [], timeoutMs: 1000 });
  // Keep the response open: override the seam's scripted completion.
  h.client._httpsRequest = (_options, onResponse) => {
    const req = new FakeRequest(() => queueMicrotask(() => onResponse(response)));
    Object.defineProperty(h, "stalledRequest", { value: req });
    return req;
  };
  await assert.rejects(
    () => h.client.fetch("https://example.com/stall", { timeoutMs: 15 }),
    (error) => error.code === "SHADE_TREE_FETCH_TIMEOUT",
  );
  assert.equal(response.destroyed, true);
  assert.equal(h.stalledRequest.destroyed, true);
  assert.equal(h.tunnel.destroyed, true);
});

await test("request transport errors stay typed and tear down the tunnel", async () => {
  const h = harness();
  h.client._httpsRequest = () => {
    const req = new FakeRequest(() => queueMicrotask(() => req.emit("error", new Error("TLS failed"))));
    Object.defineProperty(h, "failedRequest", { value: req });
    return req;
  };
  await assert.rejects(
    () => h.client.fetch("https://example.com/fail"),
    (error) => {
      assert.ok(error instanceof ShadeTreeFetchError);
      assert.equal(error.code, "SHADE_TREE_FETCH_TRANSPORT");
      assert.equal(error.retryable, true);
      assert.equal(error.cause.message, "TLS failed");
      return true;
    },
  );
  assert.equal(h.failedRequest.destroyed, true);
  assert.equal(h.tunnel.destroyed, true);
});

console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
