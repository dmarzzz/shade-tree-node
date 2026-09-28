// T-RUST-2d de-risk (layer 2): the MINIMAL socket contract the real gateway is built on.
//
// A tiny TCP server that reads ONE newline-terminated envelope exactly as
// gateway/gateway.mjs readEnvelope does (first 0x0a, JSON.parse), runs the REAL
// lib/rln.mjs verifyEnvelope against the group root computed from a member set, replies
// `JSON.stringify(ack) + "\n"` exactly as the gateway's reply() does, then exits. This
// isolates the WIRE FRAMING + verifyEnvelope ACCEPT from the gateway's target-policy +
// upstream-proxy path, so a framing/binding bug is caught here before the full harness.
//
// Usage: node verify-socket.mjs <port> <members-file>
import net from "node:net";
import { readFileSync } from "node:fs";
import { verifyEnvelope, newGroup, cleanUp } from "../../../lib/semaphore.mjs";

const port = Number(process.argv[2]);
const membersFile = process.argv[3];
if (!port || !membersFile) {
  console.error("usage: node verify-socket.mjs <port> <members-file>");
  process.exit(2);
}

const raw = JSON.parse(readFileSync(membersFile, "utf8"));
const group = newGroup((raw.members || []).map((m) => BigInt(m)));
const recentRoots = new Set([String(group.root)]);
console.error("[verify-socket] group root =", String(group.root));

const server = net.createServer((socket) => {
  socket.setNoDelay(true);
  let buf = Buffer.alloc(0);
  socket.on("data", async (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const nl = buf.indexOf(0x0a);
    if (nl === -1) return;
    const line = buf.subarray(0, nl).toString("utf8");
    let env;
    try {
      env = JSON.parse(line);
    } catch (e) {
      socket.write(JSON.stringify({ ok: false, err: "bad-envelope:" + e.message }) + "\n");
      done(false, "bad-envelope");
      return;
    }
    const v = await verifyEnvelope(env, recentRoots);
    socket.write(JSON.stringify(v.ok ? { ok: true } : { ok: false, err: "gate:" + v.reason }) + "\n");
    done(v.ok, v.ok ? "ACCEPTED" : v.reason);
  });
});

function done(ok, reason) {
  console.log(ok ? `PASS: verifyEnvelope ACCEPTED (${reason})` : `FAIL: verifyEnvelope rejected: ${reason}`);
  try { server.close(); } catch {}
  cleanUp();
  setTimeout(() => process.exit(ok ? 0 : 1), 50);
}

server.listen(port, "127.0.0.1", () => console.error(`[verify-socket] listening on 127.0.0.1:${port}`));
