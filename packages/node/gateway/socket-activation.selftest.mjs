// systemd socket activation for the gateway (zero-downtime restarts).
//   1. inheritedListener(): only when LISTEN_FDS >= 1 AND LISTEN_PID is this process; never a
//      parent's fd (a stray env from a wrapper must not make us steal a socket).
//   2. The handover itself, with real processes: this process binds the socket (systemd's role),
//      hands the fd to a CHILD as fd 3 (LISTEN_FDS=1, LISTEN_PID=child), closes its own copy, and
//      a client connects BEFORE the child starts accepting. The child adopts the fd via
//      listen({ fd: 3 }) and serves that queued connection and later ones. That is the property
//      the .socket unit relies on: Tor's connects during a restart queue instead of being refused.
import assert from "node:assert/strict";
import net from "node:net";
import { spawn } from "node:child_process";
import { inheritedListener } from "./gateway.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n += 1; console.log(`  ok   ${m}`); };

// 1. decision
ok(inheritedListener({}, 42) === null, "no LISTEN_FDS -> bind normally");
ok(inheritedListener({ LISTEN_FDS: "1", LISTEN_PID: "41" }, 42) === null, "LISTEN_PID of another process -> bind normally (never steal)");
ok(inheritedListener({ LISTEN_FDS: "0", LISTEN_PID: "42" }, 42) === null, "LISTEN_FDS=0 -> bind normally");
ok(inheritedListener({ LISTEN_FDS: "x", LISTEN_PID: "42" }, 42) === null, "garbage LISTEN_FDS -> bind normally");
assert.deepEqual(inheritedListener({ LISTEN_FDS: "1", LISTEN_PID: "42" }, 42), { fd: 3 }); n += 1;
console.log("  ok   LISTEN_FDS=1 addressed to us -> serve fd 3 (SD_LISTEN_FDS_START)");

// 2. handover across processes
const holder = net.createServer();
await new Promise((r) => holder.listen(0, "127.0.0.1", r));
const { port } = holder.address();
const fd = holder._handle.fd;
ok(Number.isInteger(fd) && fd > 2, "the bound socket has a kernel fd to hand over");

// The child waits for "go" on stdin before listening, so the early connection is queued in the
// kernel backlog with NOBODY accepting (the parent has closed its copy by then).
const childSource = `
  import net from "node:net";
  const fds = Number(process.env.LISTEN_FDS), pid = Number(process.env.LISTEN_PID);
  if (fds !== 1 || pid !== process.pid) { console.error("child: not addressed"); process.exit(3); }
  let served = 0;
  process.stdin.once("data", () => {
    const s = net.createServer((sock) => { served += 1; sock.end("adopted " + served + "\\n"); });
    s.listen({ fd: 3 }, () => console.log("listening " + s.address().port));
  });
`;
// systemd sets LISTEN_PID to the service's main pid; a shell wrapper does the same with $$ + exec.
const child2 = spawn("/bin/sh", ["-c", `LISTEN_PID=$$ exec "${process.execPath}" --input-type=module -e "$0"`, childSource], {
  stdio: ["pipe", "pipe", "inherit", fd],
  env: { ...process.env, LISTEN_FDS: "1" },
});
let childOut = "";
child2.stdout.on("data", (d) => { childOut += d; });
// Parent lets go of its copy; the kernel socket survives through the child's dup.
holder.close();
await new Promise((r) => setTimeout(r, 100));
const early = net.connect({ port, host: "127.0.0.1" });
await new Promise((r, j) => { early.once("connect", r); early.once("error", j); });
ok(true, "a client connects while NO process is accepting (queued in the backlog)");
let earlyData = "";
early.on("data", (d) => { earlyData += d; });
const earlyDone = new Promise((r) => early.once("end", r));
child2.stdin.write("go\n");
await new Promise((r) => { const t = setInterval(() => { if (/listening/.test(childOut)) { clearInterval(t); r(); } }, 20); });
ok(new RegExp(`listening ${port}`).test(childOut), "the child adopted fd 3 and reports the same port (no bind of its own)");
await earlyDone;
ok(earlyData === "adopted 1\n", "the connection queued before the child listened is served by the child");
const late = net.connect({ port, host: "127.0.0.1" });
const lateData = await new Promise((r) => { let b = ""; late.on("data", (d) => { b += d; }); late.on("end", () => r(b)); });
ok(lateData === "adopted 2\n", "later connections keep working through the adopted socket");
child2.kill();
await new Promise((r) => child2.once("exit", r));
console.log(`PASS: socket activation (${n} checks)`);
