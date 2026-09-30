// A failed CONNECT must be diagnosable at the default log level without logging its target.
import assert from "node:assert/strict";
import net from "node:net";
import { once } from "node:events";
import { makeProxyServer } from "./shim.mjs";
import { makeRegistry } from "../lib/metrics.mjs";

const previousLevel = process.env.SHADE_TREE_LOG_LEVEL;
const previousFormat = process.env.SHADE_TREE_LOG_FORMAT;
const previousWarn = console.warn;
const logs = [];
process.env.SHADE_TREE_LOG_LEVEL = "info";
process.env.SHADE_TREE_LOG_FORMAT = "json";
console.warn = (line) => logs.push(JSON.parse(line));

try {
  for (const [message, reason] of [
    ["canopy fetch failed at private-node.onion", "canopy-unavailable"],
    ["proof failed for private-member-value", "proof-failed"],
    ["SOCKS connect to private-node.onion refused", "tor-dial-failed"],
    ["unclassified private-member-value", "internal"],
  ]) {
    const server = makeProxyServer({ connect: async () => { throw new Error(message); } }, { reg: makeRegistry() });
    let socket;
    let timer;
    try {
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      socket = net.connect(server.address().port, "127.0.0.1");
      timer = setTimeout(() => socket.destroy(new Error("CONNECT response timed out")), 5000);
      const chunks = [];
      socket.on("data", (chunk) => chunks.push(chunk));
      await once(socket, "connect");
      const closed = once(socket, "close");
      socket.write("CONNECT private-target.example:443 HTTP/1.1\r\nHost: private-target.example:443\r\n\r\n");
      await closed;
      assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1\.1 502/);
      const record = logs.at(-1);
      assert.equal(record.level, "warn");
      assert.equal(record.msg, "tunnel failed");
      assert.equal(record.reason, reason);
      assert.doesNotMatch(JSON.stringify(record), /private-|\.onion|:443/);
    } finally {
      clearTimeout(timer);
      socket?.destroy();
      if (server.listening) await new Promise((resolve) => server.close(resolve));
    }
  }
  assert.equal(logs.length, 4, "one warning per failed CONNECT");
} finally {
  console.warn = previousWarn;
  if (previousLevel === undefined) delete process.env.SHADE_TREE_LOG_LEVEL;
  else process.env.SHADE_TREE_LOG_LEVEL = previousLevel;
  if (previousFormat === undefined) delete process.env.SHADE_TREE_LOG_FORMAT;
  else process.env.SHADE_TREE_LOG_FORMAT = previousFormat;
}
console.log("PASS: failed CONNECT logs a bounded reason at the default level");
