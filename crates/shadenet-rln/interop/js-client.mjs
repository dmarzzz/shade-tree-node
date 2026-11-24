// ADR 0014 conformance harness driver: the JavaScript reference client
// (packages/node/client/shade-tree-client.mjs) minting a real RLN proof and opening a tunnel
// through a running Rust node on a plain loopback socket. Every "onion dial" the client makes
// goes to 127.0.0.1:<gateway port> through a SOCKS stand-in, so this leg needs no Tor and the
// envelope, ack and relay bytes are the real ones. The payload must come back echoed by the
// sink the node connects to, which proves the accept and the post-ack relay.
//
//   env SHADE_TREE_SECRET        member app secret (its leaf is in SHADE_TREE_MEMBERS_FILE)
//       SHADE_TREE_MEMBERS_FILE  the member set the node admits
//   argv[2]  gateway port on 127.0.0.1
//   argv[3]  target "host:port" (the local sink the node egresses to)
//   argv[4]  payload to send; the sink answers "shade-tree-payload-ok:<payload>"
import net from "node:net";
import { ShadeTreeClient } from "../../../packages/node/client/shade-tree-client.mjs";
import { cleanUp } from "../../../packages/node/lib/rln.mjs";

const [gwPort, target, payload] = process.argv.slice(2);
const secret = process.env.SHADE_TREE_SECRET;
if (!gwPort || !target || !payload || !secret) {
  console.error("usage: SHADE_TREE_SECRET=... node js-client.mjs <gateway-port> <host:port> <payload>");
  process.exit(2);
}

// the client dials the node's onion through SOCKS; here every dial is the loopback node
const plainTcp = {
  createConnection: async () => {
    const socket = net.connect(Number(gwPort), "127.0.0.1");
    await new Promise((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
    return { socket };
  },
};

function emit(e) {
  const parts = [`[js-client] ${e.phase}/${e.status}`];
  if (e.slot != null) parts.push(`slot=${e.slot}`);
  if (e.error) parts.push(`error=${e.error}`);
  console.error(parts.join(" "));
}

async function main() {
  const client = new ShadeTreeClient({ secret, onion: "a".repeat(56), socksClient: plainTcp, dialAttempts: 1 });
  const tunnel = await client.connect(target, { onEvent: emit });
  const got = [];
  const reply = new Promise((resolve, reject) => {
    tunnel.on("data", (d) => got.push(d));
    tunnel.on("end", () => resolve(Buffer.concat(got).toString("utf8")));
    tunnel.on("error", reject);
    setTimeout(() => reject(new Error("no echo within 15 s")), 15_000).unref();
  });
  tunnel.write(payload);
  const echoed = await reply;
  const expected = `shade-tree-payload-ok:${payload}`;
  if (echoed !== expected) throw new Error(`relayed payload mismatch: got ${JSON.stringify(echoed)}, expected ${JSON.stringify(expected)}`);
  console.log(JSON.stringify({ accept: true, target, slot: tunnel.shadeTree?.slot ?? null, echoed }));
}

main()
  .then(() => { cleanUp(); process.exit(0); })
  .catch((e) => {
    console.error("[js-client] egress FAILED:", e && e.message);
    console.log(JSON.stringify({ accept: false, target, error: (e && e.message) || String(e) }));
    cleanUp();
    process.exit(1);
  });
