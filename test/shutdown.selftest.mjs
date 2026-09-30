// Unit self-test for graceful shutdown / connection draining (T-DEV-8).
//
// Drives the exported makeGracefulShutdown() from BOTH packages/node/gateway/gateway.mjs and
// packages/node/bootnode/server.mjs with a fake server + fake sockets + an injected clock and an
// injected onExit (instead of real process.exit). No real process signals, no real
// timers, no real net listener — pure control-flow proof.
//
// Invariants:
//   (a) no open sockets            => close() called, exits 0 immediately (no timer left armed)
//   (b) socket finishes < timeout  => stays open until it finishes, then exits 0 cleanly,
//                                      and the in-flight socket is NEVER force-destroyed
//   (c) socket never finishes      => force-destroys the straggler + exits after timeoutMs
//   (d) merely IMPORTING the modules installs no signal handlers (only main() does)
//
//   node test/shutdown.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { makeGracefulShutdown as gatewayShutdown } from "../packages/node/gateway/gateway.mjs";
import { makeGracefulShutdown as bootnodeShutdown } from "../packages/node/bootnode/server.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// A hand-driven clock: setTimer/clearTimer capture pending timers; advance() fires them.
function makeClock() {
  let seq = 1;
  const timers = new Map();
  return {
    setTimer(fn, ms) { const id = seq++; timers.set(id, { fn, ms }); return { id, unref() {} }; },
    clearTimer(t) { if (t) timers.delete(t.id); },
    advance() { for (const [id, { fn }] of [...timers]) { timers.delete(id); fn(); } },
    pending() { return timers.size; },
  };
}

// A fake server mirroring net/http server.close semantics: close(cb) fires cb once every
// open connection has ended. If nothing is open it fires synchronously (immediate drain);
// otherwise drainOne() releases sockets and fires cb when the last one goes.
function makeFakeServer(openSockets) {
  const s = { closeCalls: 0, _cb: null };
  s.close = (cb) => {
    s.closeCalls++;
    if (openSockets.size === 0) cb();
    else s._cb = cb;
  };
  s.drainOne = (sock) => {
    openSockets.delete(sock);
    if (openSockets.size === 0 && s._cb) { const cb = s._cb; s._cb = null; cb(); }
  };
  return s;
}

const makeSocket = () => ({ destroyed: false, destroy() { this.destroyed = true; } });

// Run the three scenarios against a given makeGracefulShutdown implementation.
function runScenarios(name, makeGracefulShutdown) {
  console.log(`\n${name}:`);

  // (a) no open sockets -> immediate clean exit after close().
  {
    const clock = makeClock();
    const openSockets = new Set();
    const server = makeFakeServer(openSockets);
    let exited;
    const shutdown = makeGracefulShutdown(server, {
      openSockets, timeoutMs: 1000, onExit: (c) => { exited = c; }, log: () => {},
      setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    });
    shutdown("SIGTERM");
    ok(server.closeCalls === 1, "(a) server.close() called exactly once");
    ok(exited === 0, "(a) exits 0 immediately with no open sockets");
    ok(clock.pending() === 0, "(a) grace timer cleared on clean drain (nothing left armed)");
  }

  // (b) socket finishes before the timeout -> clean exit, socket never destroyed.
  {
    const clock = makeClock();
    const openSockets = new Set();
    const sock = makeSocket();
    openSockets.add(sock);
    const server = makeFakeServer(openSockets);
    let exited;
    const shutdown = makeGracefulShutdown(server, {
      openSockets, timeoutMs: 1000, onExit: (c) => { exited = c; }, log: () => {},
      setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    });
    shutdown("SIGINT");
    ok(server.closeCalls === 1, "(b) server.close() called (stops new conns)");
    ok(exited === undefined, "(b) does NOT exit while a tunnel is in-flight");
    ok(clock.pending() === 1, "(b) grace timer armed while draining");
    server.drainOne(sock); // the in-flight work finishes before the timeout
    ok(exited === 0, "(b) exits 0 once the in-flight socket finishes");
    ok(sock.destroyed === false, "(b) in-flight socket allowed to finish, never force-destroyed");
    ok(clock.pending() === 0, "(b) grace timer cleared after clean drain");
  }

  // (c) socket never finishes -> force-destroy + forced (nonzero) exit at timeoutMs.
  {
    const clock = makeClock();
    const openSockets = new Set();
    const sock = makeSocket();
    openSockets.add(sock);
    const server = makeFakeServer(openSockets);
    let exited;
    const shutdown = makeGracefulShutdown(server, {
      openSockets, timeoutMs: 5000, onExit: (c) => { exited = c; }, log: () => {},
      setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    });
    shutdown();
    ok(server.closeCalls === 1, "(c) server.close() called");
    ok(exited === undefined, "(c) no exit before the timeout while the socket hangs");
    ok(sock.destroyed === false, "(c) hung socket left alone before the grace window");
    clock.advance(); // grace window elapses
    ok(exited === 1, "(c) forces exit (nonzero) after timeoutMs");
    ok(sock.destroyed === true, "(c) hung socket is force-destroyed on timeout");

    // A second signal mid-drain is idempotent (does not re-arm / double-exit).
    let reexited = false;
    const clock2 = makeClock();
    const server2 = makeFakeServer(new Set());
    const sd2 = makeGracefulShutdown(server2, {
      openSockets: new Set(), timeoutMs: 1000, onExit: () => { reexited = reexited === false ? 1 : 2; },
      log: () => {}, setTimer: clock2.setTimer, clearTimer: clock2.clearTimer,
    });
    sd2("SIGTERM");
    sd2("SIGTERM");
    ok(server2.closeCalls === 1 && reexited === 1, "(idempotent) a second signal during drain is ignored");
  }
}

runScenarios("gateway makeGracefulShutdown", gatewayShutdown);
runScenarios("bootnode makeGracefulShutdown", bootnodeShutdown);

// Gateway shutdown also stops its background runtime resources at the beginning of a drain.
console.log("\ngateway runtime cleanup:");
{
  const clock = makeClock();
  const openSockets = new Set();
  const events = [];
  const server = makeFakeServer(openSockets);
  const close = server.close;
  server.close = (cb) => { events.push("server"); close(cb); };
  const shutdown = gatewayShutdown(server, {
    openSockets,
    timeoutMs: 1000,
    onExit: () => events.push("exit"),
    onStart: () => events.push("runtime"),
    log: () => {},
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
  });
  shutdown("SIGTERM");
  shutdown("SIGTERM");
  ok(events.join(",") === "runtime,server,exit", "runtime resources close once, before the listener and process exit");
}

// (d) importing the modules must NOT have installed signal handlers (only main() does).
console.log("\nimport is side-effect-free (no signal handlers on import):");
ok(process.listenerCount("SIGTERM") === 0, "(d) no SIGTERM listener installed by import");
ok(process.listenerCount("SIGINT") === 0, "(d) no SIGINT listener installed by import");

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: shutdown selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
