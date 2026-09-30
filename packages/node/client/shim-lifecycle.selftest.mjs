// Regression coverage for a local CONNECT client disappearing while the Proxy is still dialing.

import assert from "node:assert/strict";
import net from "node:net";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import { makeRegistry } from "../lib/metrics.mjs";
import { makeProxyServer } from "./shim.mjs";

async function within(promise, label, ms = 2000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), ms); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function onceAny(emitter, events) {
  return new Promise((resolve) => {
    const listeners = new Map(events.map((event) => [event, () => {
      for (const [name, listener] of listeners) emitter.removeListener(name, listener);
      resolve(event);
    }]));
    for (const [event, listener] of listeners) emitter.once(event, listener);
  });
}

async function main() {
  const reg = makeRegistry();
  const tunnel = new PassThrough();
  let resolveDial;
  let markDialStarted;
  const dialStarted = new Promise((resolve) => { markDialStarted = resolve; });
  const delayedDial = new Promise((resolve) => { resolveDial = resolve; });
  const client = {
    async connect(target, options) {
      assert.equal(target, "agent.example:443");
      assert.equal(typeof options?.onEvent, "function");
      markDialStarted();
      return delayedDial;
    },
  };
  const logger = { debug() {} };
  let clock = 100;
  const server = makeProxyServer(client, { reg, logger, now: () => ++clock });
  let localSocket = null;
  let proxySocket = null;

  server.on("connection", (socket) => {
    proxySocket = socket;
    socket.on("error", () => {});
  });

  try {
    server.listen(0, "127.0.0.1");
    await within(once(server, "listening"), "Proxy listener");
    const address = server.address();
    assert.equal(typeof address, "object");

    localSocket = net.createConnection({ host: "127.0.0.1", port: address.port });
    localSocket.on("error", () => {});
    await within(once(localSocket, "connect"), "local client connection");
    localSocket.write("CONNECT agent.example:443 HTTP/1.1\r\nHost: agent.example:443\r\n\r\n");
    await within(dialStarted, "delayed Shade Tree dial");
    assert.ok(proxySocket, "the Proxy accepted the local socket");

    const proxyGone = onceAny(proxySocket, ["end", "close"]);
    const proxyClosed = once(proxySocket, "close");
    localSocket.destroy();
    await within(proxyGone, "Proxy-side local socket shutdown");

    const tunnelClosed = once(tunnel, "close");
    resolveDial(tunnel);
    await within(tunnelClosed, "late tunnel destruction");
    await within(proxyClosed, "Proxy-side socket destruction");

    assert.equal(tunnel.destroyed, true, "a tunnel returned after local close is destroyed");
    const exposition = reg.render();
    assert.match(exposition, /^shade_tree_proxy_active_tunnels 0$/m, "no active tunnel remains");
    assert.doesNotMatch(exposition, /^shade_tree_proxy_tunnels_total\{[^\n]*result="opened"/m, "the race never records an opened tunnel");
    assert.match(
      exposition,
      /^shade_tree_proxy_tunnels_total\{reason="client-closed",result="failed"\} 1$/m,
      "the race records one bounded client-closed failure",
    );
    assert.match(exposition, /^shade_tree_proxy_connect_seconds_count 1$/m, "the failed setup is included in latency accounting");
    assert.doesNotMatch(exposition, /agent\.example|:443/, "metrics contain no destination detail");
  } finally {
    resolveDial(tunnel);
    localSocket?.destroy();
    proxySocket?.destroy();
    if (!tunnel.destroyed) tunnel.destroy();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }

  console.log("PASS: Proxy delayed-connect local-close lifecycle");
}

main().catch((error) => { console.error(error); process.exit(1); });
