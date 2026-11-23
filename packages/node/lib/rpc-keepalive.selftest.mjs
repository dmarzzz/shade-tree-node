// Keep-alive for JSON-RPC fetches (rpc-safety.mjs rpcDispatcher). Everything runs against
// loopback fake JSON-RPC servers; no network, no chain.
//
//   node packages/node/lib/rpc-keepalive.selftest.mjs
//
// The main case replays the root provider's poll shape: 3 sequential calls per poll, polls 12 s
// apart (the gateway's root poll interval), 3 polls. undici's diagnostics channels
// (`undici:client:connected`, `undici:client:sendHeaders`) show which socket each request used.
// The first call of polls 2 and 3 must reuse a socket from an earlier poll with the RPC dispatcher,
// and must open a new one in the control (dispatcher: null, the global dispatcher with its 4 s idle
// close). Total connection counts are not asserted: on loopback a call that follows another within
// a millisecond can open a second socket before the first is returned to the pool, on either arm.
// This case waits about 24 s of real time on purpose: undici's idle timers cannot be faked.

import assert from "node:assert/strict";
import dc from "node:diagnostics_channel";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_RPC_KEEPALIVE_MS,
  MAX_RPC_KEEPALIVE_MS,
  jsonRpcCall,
  rpcDispatcher,
  rpcKeepAliveMs,
} from "./rpc-safety.mjs";

const GLOBAL_DISPATCHER = Symbol.for("undici.globalDispatcher.1");
const POLL_GAP_MS = 12_000;

// ---- fake JSON-RPC server ---------------------------------------------------
// Answers every call with `result` (default "0x1"). `hold()` makes the NEXT request wait until the returned
// release function is called. The server never drops an idle socket unless a test says so, and it
// sends no `Keep-Alive: timeout=` hint (keepAliveTimeout 0), so the client's own idle timeout decides,
// as with the RPC providers we measured.
async function fakeRpc({ result = "0x1" } = {}) {
  const holds = [];
  let requests = 0;
  let tunnels = 0;
  const tunnelSockets = new Set();
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      requests++;
      const { id } = JSON.parse(body);
      const answer = () => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
      };
      const hold = holds.shift();
      if (hold) { hold.arrived(); hold.wait.then(answer); } else answer();
    });
  });
  // As an HTTP proxy: a CONNECT tunnel to `localhost:<port>` (only used by the env-proxy case).
  server.on("connect", (req, socket, head) => {
    tunnels++;
    const port = Number(String(req.url).split(":").pop());
    const upstream = net.connect({ host: "localhost", port }, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    for (const s of [socket, upstream]) { tunnelSockets.add(s); s.on("error", () => {}); s.on("close", () => tunnelSockets.delete(s)); }
    socket.on("close", () => upstream.destroy());
    upstream.on("close", () => socket.destroy());
  });
  server.keepAliveTimeout = 0;
  await new Promise((resolve) => server.listen(0, "localhost", resolve));
  const port = server.address().port;
  return {
    port,
    url: `http://localhost:${port}/`,
    get requests() { return requests; },
    get tunnels() { return tunnels; },
    // Returns { arrived: Promise (request reached the server), release() }.
    hold() {
      let release;
      let arrivedResolve;
      const arrived = new Promise((r) => { arrivedResolve = r; });
      const wait = new Promise((r) => { release = r; });
      holds.push({ wait, arrived: arrivedResolve });
      return { arrived, release };
    },
    closeIdle() { server.closeIdleConnections(); },
    close() {
      for (const s of tunnelSockets) s.destroy();
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

// New TCP connections opened by undici, by server port.
const connects = new Map();
dc.subscribe("undici:client:connected", ({ socket }) => {
  const port = socket?.remotePort;
  connects.set(port, (connects.get(port) ?? 0) + 1);
});
const connectsTo = (srv) => connects.get(srv.port) ?? 0;
// Every socket that has carried a request, and the socket of the latest request, by server port.
const usedSockets = new Map();
const lastSocket = new Map();
dc.subscribe("undici:client:sendHeaders", ({ socket }) => {
  const port = socket?.remotePort;
  if (!usedSockets.has(port)) usedSockets.set(port, new Set());
  usedSockets.get(port).add(socket);
  lastSocket.set(port, socket);
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const withEnv = async (value, fn) => {
  const before = process.env.SHADE_TREE_RPC_KEEPALIVE_MS;
  if (value === undefined) delete process.env.SHADE_TREE_RPC_KEEPALIVE_MS;
  else process.env.SHADE_TREE_RPC_KEEPALIVE_MS = value;
  try { return await fn(); } finally {
    if (before === undefined) delete process.env.SHADE_TREE_RPC_KEEPALIVE_MS;
    else process.env.SHADE_TREE_RPC_KEEPALIVE_MS = before;
  }
};
// Swap Node's global fetch dispatcher for the duration of fn, then put the real one back.
async function withGlobalDispatcher(replacement, fn) {
  void globalThis.Response;
  const real = globalThis[GLOBAL_DISPATCHER];
  globalThis[GLOBAL_DISPATCHER] = replacement;
  try { return await fn(real); } finally { globalThis[GLOBAL_DISPATCHER] = real; }
}
// A dispatcher that is not a plain Agent (stands in for a proxy agent) and forwards to `inner`.
class ForwardingDispatcher {
  constructor(inner) { this.inner = inner; this.dispatched = 0; }
  dispatch(opts, handler) { this.dispatched++; return this.inner.dispatch(opts, handler); }
}

const cases = [];
const test = (name, fn) => cases.push({ name, fn });

// ---- parse surface: SHADE_TREE_RPC_KEEPALIVE_MS ------------------------------
test("env: default, valid values, off, cap, and garbage fall back to the default", () => {
  assert.equal(DEFAULT_RPC_KEEPALIVE_MS, 30_000);
  assert.ok(DEFAULT_RPC_KEEPALIVE_MS > POLL_GAP_MS, "default must outlast the 12 s root poll");
  const cases = [
    [undefined, 30_000], ["", 30_000], ["20000", 20_000], ["0", 0], [" 25000 ", 25_000],
    [String(MAX_RPC_KEEPALIVE_MS), MAX_RPC_KEEPALIVE_MS], ["9999999999", MAX_RPC_KEEPALIVE_MS],
    ["-1", 30_000], ["abc", 30_000], ["1e4", 30_000], ["0x10", 30_000], ["12.5", 30_000],
    ["Infinity", 30_000], ["NaN", 30_000], ["30000ms", 30_000], ["99999999999", 30_000],
    ["\u0661\u0662", 30_000], ["+5", 30_000], [" ", 30_000],
    ["\t20000\n", 20_000], ["0000020000", 20_000], ["00000020000", 30_000],
  ];
  for (const [raw, want] of cases) {
    const env = raw === undefined ? {} : { SHADE_TREE_RPC_KEEPALIVE_MS: raw };
    assert.equal(rpcKeepAliveMs(env), want, `SHADE_TREE_RPC_KEEPALIVE_MS=${JSON.stringify(raw)}`);
  }
});

// ---- dispatcher selection and cache ------------------------------------------
test("dispatcher: one per keep-alive value, null when off, rebuilt when the value changes", () => {
  const a = rpcDispatcher({ env: {} });
  assert.ok(a && typeof a.dispatch === "function", "a dispatcher by default");
  assert.equal(a.constructor, globalThis[GLOBAL_DISPATCHER].constructor, "same class as Node's fetch dispatcher");
  assert.notEqual(a, globalThis[GLOBAL_DISPATCHER], "never the global dispatcher itself");
  assert.equal(rpcDispatcher({ env: {} }), a, "cached");
  assert.equal(rpcDispatcher({ env: { SHADE_TREE_RPC_KEEPALIVE_MS: "0" } }), null, "0 turns it off");
  const b = rpcDispatcher({ env: { SHADE_TREE_RPC_KEEPALIVE_MS: "20000" } });
  assert.ok(b && b !== a, "a changed value builds a new dispatcher");
  assert.equal(rpcDispatcher({ env: { SHADE_TREE_RPC_KEEPALIVE_MS: "20000" } }), b);
  assert.equal(rpcDispatcher({ env: { SHADE_TREE_RPC_KEEPALIVE_MS: "garbage" } }) === b, false, "garbage means the default, not the last value");
});

test("dispatcher: a proxy (non-Agent) global dispatcher is never bypassed", async () => {
  const srv = await fakeRpc();
  try {
    await withGlobalDispatcher(null, async (real) => {
      const proxy = new ForwardingDispatcher(real);
      globalThis[GLOBAL_DISPATCHER] = proxy;
      assert.equal(rpcDispatcher({ env: {} }), null, "no RPC dispatcher over a proxy");
      assert.equal(await jsonRpcCall(srv.url, "eth_chainId", [], { timeoutMs: 5000, retries: 0 }), "0x1");
      assert.equal(proxy.dispatched, 1, "the RPC request went through the installed global dispatcher");
    });
  } finally { await srv.close(); }
});

// An operator-configured plain Agent (same class as Node's default) must never be replaced. The
// connect function sends every connection to the `routed` fixture, whatever origin was asked for;
// the `direct` fixture is the origin the URL names and must see no request at all.
test("dispatcher: an operator-configured plain Agent (connect function) is never bypassed, on the wire", async () => {
  const direct = await fakeRpc({ result: "direct" });
  const routed = await fakeRpc({ result: "routed" });
  try {
    await withGlobalDispatcher(null, async (real) => {
      const Agent = real.constructor;
      let connectorCalls = 0;
      const configured = new Agent({
        connect(_opts, callback) {
          connectorCalls++;
          const socket = net.connect({ host: "localhost", port: routed.port });
          socket.once("connect", () => callback(null, socket));
          socket.once("error", (e) => callback(e, null));
        },
      });
      globalThis[GLOBAL_DISPATCHER] = configured;
      try {
        assert.equal(configured.constructor.name, "Agent", "the same class name as Node's default");
        assert.equal(rpcDispatcher({ env: {} }), null, "no RPC dispatcher over a configured Agent");
        assert.equal(await jsonRpcCall(direct.url, "eth_chainId", [], { timeoutMs: 5000, retries: 0 }), "routed");
        assert.equal(await jsonRpcCall(direct.url, "eth_chainId", [], { timeoutMs: 5000, retries: 0, dispatcher: null }), "routed");
        assert.equal(direct.requests, 0, "the direct origin received no bypass request");
        assert.equal(routed.requests, 2);
        assert.ok(connectorCalls >= 1, "the operator's connect function was used");
      } finally { await configured.destroy(); }
    });
  } finally { await direct.close(); await routed.close(); }
});

test("dispatcher: any other configured, composed, subclassed or patched Agent is left alone", async () => {
  await withGlobalDispatcher(null, async (real) => {
    const Agent = real.constructor;
    const plain = new Agent();
    const patched = new Agent();
    patched.dispatch = (opts, handler) => Agent.prototype.dispatch.call(patched, opts, handler);
    const variants = {
      "connect options (TLS)": new Agent({ connect: { rejectUnauthorized: false } }),
      "connect timeout": new Agent({ connect: { timeout: 1234 } }),
      "custom factory": new Agent({ factory: (origin, opts) => new Agent(opts) }),
      "connection limit": new Agent({ connections: 1 }),
      "max origins": new Agent({ maxOrigins: 5 }),
      "own keep-alive": new Agent({ keepAliveTimeout: 1000 }),
      "composed interceptor": plain.compose((dispatch) => dispatch),
      "subclass": new (class extends Agent {})(),
      "instance dispatch override": patched,
    };
    try {
      for (const [label, dispatcher] of Object.entries(variants)) {
        globalThis[GLOBAL_DISPATCHER] = dispatcher;
        assert.equal(rpcDispatcher({ env: {} }), null, label);
      }
      globalThis[GLOBAL_DISPATCHER] = plain;
      assert.ok(rpcDispatcher({ env: {} }), "an unconfigured `new Agent()` gets the RPC dispatcher");
      globalThis[GLOBAL_DISPATCHER] = { dispatch() {} };
      assert.equal(rpcDispatcher({ env: {} }), null, "a plain object");
      // A dispatcher class without undici's Agent slots (a proxy agent, for one) is never constructed.
      let built = 0;
      class OtherDispatcher { constructor() { built++; } dispatch() { return false; } }
      globalThis[GLOBAL_DISPATCHER] = new OtherDispatcher();
      assert.equal(rpcDispatcher({ env: {} }), null, "another dispatcher class");
      assert.equal(built, 1, "rpcDispatcher did not construct another instance of a non-Agent class");
    } finally {
      for (const d of [plain, ...Object.values(variants)]) await d.destroy().catch(() => {});
    }
  });
});

// The actual EnvHttpProxyAgent Node installs for NODE_USE_ENV_PROXY=1, in a child process (it is
// installed at startup). The RPC request must go through the proxy: one CONNECT tunnel, and the
// origin answers through it.
test("dispatcher: NODE_USE_ENV_PROXY=1 (EnvHttpProxyAgent) keeps RPC on the proxy", async () => {
  const origin = await fakeRpc({ result: "origin" });
  const proxy = await fakeRpc({ result: "proxy-itself" });
  try {
    const proxyUrl = `http://localhost:${proxy.port}`;
    const env = { ...process.env, NODE_USE_ENV_PROXY: "1", NO_PROXY: "", no_proxy: "" };
    for (const name of ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]) env[name] = proxyUrl;
    const out = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--env-proxy-child", origin.url], { env, stdio: ["ignore", "pipe", "inherit"] });
      let text = "";
      child.stdout.on("data", (c) => { text += c; });
      const timer = setTimeout(() => { child.kill(); reject(new Error("env-proxy child still alive after 10 s")); }, 10_000);
      child.on("exit", (c) => { clearTimeout(timer); resolve({ c, text }); });
    });
    assert.equal(out.c, 0, out.text);
    const seen = JSON.parse(out.text.trim().split("\n").pop());
    assert.deepEqual(seen, { cls: "EnvHttpProxyAgent", dedicated: false, result: "origin" });
    assert.equal(proxy.tunnels, 1, "the RPC request went through one CONNECT tunnel");
    assert.equal(origin.requests, 1);
  } finally { await origin.close(); await proxy.close(); }
});

test("jsonRpcCall: an injected fetchImpl gets no dispatcher unless one is passed", async () => {
  const seen = [];
  const fetchImpl = async (_url, init) => {
    seen.push("dispatcher" in init);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x2" }), { status: 200 });
  };
  assert.equal(await jsonRpcCall("http://rpc.invalid/", "eth_chainId", [], { fetchImpl, retries: 0 }), "0x2");
  const marker = { dispatch() { throw new Error("unused"); } };
  assert.equal(await jsonRpcCall("http://rpc.invalid/", "eth_chainId", [], { fetchImpl, retries: 0, dispatcher: marker }), "0x2");
  assert.deepEqual(seen, [false, true]);
});

// ---- interleaving: a request in flight across a dispatcher change ------------
// The LAST request on the old dispatcher is held at the server while the dispatcher changes, then
// released. It must complete on its own socket. Success = the env value changed and a new
// dispatcher was built. Failed reload = the global dispatcher became something the RPC dispatcher
// cannot be built from (rpcDispatcher returns null) and the next call took the global path.
test("interleaving: held request survives a rebuild (success) and a fallback to the global (failed reload)", async () => {
  const srv = await fakeRpc();
  try {
    await withEnv("21000", async () => {
      const first = rpcDispatcher();
      const h = srv.hold();
      const held = jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 });
      held.catch(() => {}); // an early rejection is reported by the `await held` below, not as a crash
      await h.arrived;
      process.env.SHADE_TREE_RPC_KEEPALIVE_MS = "22000";
      const second = rpcDispatcher();
      assert.ok(second && second !== first, "rebuilt");
      assert.equal(await jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 }), "0x1", "new call on the new dispatcher");
      h.release();
      assert.equal(await held, "0x1", "held call on the superseded dispatcher completed (success reload)");
    });
    await withEnv("23000", async () => {
      const before = rpcDispatcher();
      const h = srv.hold();
      const held = jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 });
      held.catch(() => {});
      await h.arrived;
      await withGlobalDispatcher(null, async (real) => {
        globalThis[GLOBAL_DISPATCHER] = new ForwardingDispatcher(real);
        assert.equal(rpcDispatcher(), null, "reload failed: no RPC dispatcher");
        assert.equal(await jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 }), "0x1", "new call on the global path");
        h.release();
        assert.equal(await held, "0x1", "held call completed (failed reload)");
      });
      assert.equal(rpcDispatcher(), before, "the cached dispatcher is reused once the global is an Agent again");
    });
    // Failed reload, second kind: the global becomes an operator-configured Agent of the SAME class,
    // so the cached keep-alive Agent still matches by class but must not be used.
    await withEnv("26000", async () => {
      const before = rpcDispatcher();
      assert.ok(before);
      const h = srv.hold();
      const held = jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 });
      held.catch(() => {});
      await h.arrived;
      await withGlobalDispatcher(null, async (real) => {
        const configured = new real.constructor({ connect: { timeout: 4321 } });
        globalThis[GLOBAL_DISPATCHER] = configured;
        try {
          assert.equal(rpcDispatcher(), null, "reload failed: the cached Agent is not used over a configured one");
          h.release();
          assert.equal(await held, "0x1", "held call on the cached Agent completed (configured global)");
        } finally { await configured.destroy(); }
      });
      assert.equal(rpcDispatcher(), before, "cached dispatcher back once the default global is restored");
    });
  } finally { await srv.close(); }
});

// A call picks its dispatcher synchronously, but fetch hands the request to it later. A rebuild in
// that gap must not close the dispatcher the call already chose.
test("interleaving: rebuild between choosing a dispatcher and dispatching does not fail the call", async () => {
  const srv = await fakeRpc();
  try {
    await withEnv("24000", async () => {
      rpcDispatcher();
      const pending = jsonRpcCall(srv.url, "eth_call", [], { timeoutMs: 10_000, retries: 0 });
      process.env.SHADE_TREE_RPC_KEEPALIVE_MS = "25000";
      rpcDispatcher();
      assert.equal(await pending, "0x1");
    });
  } finally { await srv.close(); }
});

// ---- idle close by the server ------------------------------------------------
test("server closes the idle keep-alive socket: the next call reconnects and succeeds", async () => {
  const srv = await fakeRpc();
  try {
    assert.equal(await jsonRpcCall(srv.url, "eth_chainId", [], { timeoutMs: 5000, retries: 0 }), "0x1");
    assert.equal(connectsTo(srv), 1);
    srv.closeIdle();
    await sleep(200); // let the FIN reach the client
    assert.equal(await jsonRpcCall(srv.url, "eth_chainId", [], { timeoutMs: 5000, retries: 0 }), "0x1");
    assert.equal(connectsTo(srv), 2, "a new connection, not a failed write on the closed one");
    assert.equal(srv.requests, 2);
  } finally { await srv.close(); }
});

// ---- process exit ------------------------------------------------------------
test("an idle keep-alive socket does not hold a short-lived process open", async () => {
  const srv = await fakeRpc();
  try {
    const t0 = Date.now();
    const code = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--child", srv.url], { stdio: ["ignore", "pipe", "inherit"] });
      let out = "";
      child.stdout.on("data", (c) => { out += c; });
      const timer = setTimeout(() => { child.kill(); reject(new Error("child still alive after 10 s")); }, 10_000);
      child.on("exit", (c) => { clearTimeout(timer); resolve({ c, out }); });
    });
    assert.equal(code.c, 0);
    assert.match(code.out, /child-ok 0x1/);
    assert.ok(Date.now() - t0 < 10_000);
  } finally { await srv.close(); }
});

// ---- the poll shape ----------------------------------------------------------
test("poll shape: 3 polls x 3 calls, 12 s apart: polls 2-3 reuse a socket with the RPC dispatcher, reconnect without", async () => {
  const ka = await fakeRpc();
  const control = await fakeRpc();
  try {
    // reused[arm] = for polls 2 and 3, did the poll's first call go out on a socket that an
    // earlier poll had used.
    const reused = { rpc: [], control: [] };
    await withEnv(undefined, async () => {
      for (let poll = 0; poll < 3; poll++) {
        if (poll > 0) await sleep(POLL_GAP_MS);
        const before = {
          rpc: new Set(usedSockets.get(ka.port) ?? []),
          control: new Set(usedSockets.get(control.port) ?? []),
        };
        for (const [i, method] of ["eth_getBlockByNumber", "eth_call", "eth_call"].entries()) {
          // The two arms run one after the other, so neither request shares a loop turn with the other.
          assert.equal(await jsonRpcCall(ka.url, method, [], { timeoutMs: 5000, retries: 0 }), "0x1");
          if (i === 0 && poll > 0) reused.rpc.push(before.rpc.has(lastSocket.get(ka.port)));
          assert.equal(await jsonRpcCall(control.url, method, [], { timeoutMs: 5000, retries: 0, dispatcher: null }), "0x1");
          if (i === 0 && poll > 0) reused.control.push(before.control.has(lastSocket.get(control.port)));
        }
      }
    });
    assert.equal(ka.requests, 9);
    assert.equal(control.requests, 9);
    const seen = `first call of polls 2-3 reused an earlier socket: ${JSON.stringify(reused)}; connections [rpc, control]: [${connectsTo(ka)}, ${connectsTo(control)}]`;
    assert.deepEqual(reused.control, [false, false], `control: the global dispatcher reconnects at every poll (4 s idle close); ${seen}`);
    assert.deepEqual(reused.rpc, [true, true], `RPC dispatcher: polls 2 and 3 reuse the connection; ${seen}`);
    assert.ok(connectsTo(control) >= 3, seen);
  } finally { await ka.close(); await control.close(); }
});

if (process.argv[2] === "--env-proxy-child") {
  const result = await jsonRpcCall(process.argv[3], "eth_chainId", [], { timeoutMs: 5000, retries: 0 });
  console.log(JSON.stringify({ cls: globalThis[GLOBAL_DISPATCHER].constructor.name, dedicated: rpcDispatcher() !== null, result }));
} else if (process.argv[2] === "--child") {
  const result = await jsonRpcCall(process.argv[3], "eth_chainId", [], { timeoutMs: 5000, retries: 0 });
  console.log(`child-ok ${result}`);
} else {
  let failed = 0;
  for (const { name, fn } of cases) {
    try {
      await fn();
      console.log(`  PASS  ${name}`);
    } catch (error) {
      failed++;
      console.log(`  FAIL  ${name} :: ${error?.message || error}`);
    }
  }
  if (failed) {
    console.log(`FAIL: ${failed}/${cases.length} RPC keep-alive cases failed`);
    process.exit(1);
  }
  console.log(`PASS: RPC keep-alive (${cases.length} cases): env parse, dispatcher cache, proxy / configured Agent / env proxy not bypassed, in-flight rebuild, server idle close, process exit, 12 s poll reuse`);
}
