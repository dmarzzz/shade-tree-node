import assert from "node:assert/strict";
import net from "node:net";

process.env.SHADE_TREE_EGRESS_ALLOW = "*:*";
process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1";
const { makeConnLimiter, makeEgressPolicy, makeHandler } = await import("./gateway.mjs");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, message) {
  for (let tries = 0; tries < 200; tries += 1) { if (predicate()) return; await sleep(5); }
  throw new Error(`timed out waiting for ${message}`);
}
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const close = (server) => new Promise((resolve) => server.close(resolve));

const echo = net.createServer((socket) => socket.on("data", (data) => socket.write(data)));
await listen(echo);
const counted = { agent: 0, destination: 0 };
const relayCounter = {
  addAgentToDestination(chunk) { counted.agent += chunk.length; },
  addDestinationToAgent(chunk) { counted.destination += chunk.length; },
};
const spent = { admit: async () => ({ ok: true }), commit() {} };
const handler = makeHandler(spent, {
  verify: async (env) => ({ ok: true, nullifier: env.nullifier, externalNullifier: "1", share: env.share }),
  targetPolicy: makeEgressPolicy({ allow: "*:*" }),
  lookup: async () => [{ address: "127.0.0.1", family: 4 }],
  envelopeTimeoutMs: 2000,
  idleTimeoutMs: 0,
  limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  relayCounter,
});
const gateway = net.createServer(handler);
await listen(gateway);

const client = net.connect(gateway.address().port, "127.0.0.1");
client.on("error", () => {});
let received = Buffer.alloc(0);
client.on("data", (chunk) => { received = Buffer.concat([received, chunk]); });
await new Promise((resolve) => client.once("connect", resolve));
const early = Buffer.from("early-payload");
const later = Buffer.from("later-payload");
const envelope = Buffer.from(JSON.stringify({
  v: 4,
  target: `127.0.0.1:${echo.address().port}`,
  nullifier: "telemetry-test",
  nonce: "n",
  share: { x: "1", y: "2" },
}) + "\n");
client.write(Buffer.concat([envelope, early]));
await until(() => received.includes(Buffer.from("{\"ok\":true}\n")), "success acknowledgement");
client.write(later);
await until(() => counted.destination === early.length + later.length, "both echoed payloads");

assert.equal(counted.agent, early.length + later.length, "agent payload counted once, including proof-read remainder");
assert.equal(counted.destination, early.length + later.length, "destination payload counted once");
assert.equal(counted.agent < envelope.length, true, "proof envelope is not counted as payload");

client.destroy();
await close(gateway);
await close(echo);
console.log("PASS: established tunnel counts both payload directions exactly once");
