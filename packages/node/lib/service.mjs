// What a long-running JavaScript service still needs now that the node and the Elder are Rust
// binaries (ADR 0014, ADR 0015): a token bucket for its endpoints and a graceful shutdown.
// Both came out of the JavaScript Elder unchanged; the registrar is the one caller left.

// Refill uses the injected `now()` (seconds) so tests are deterministic; fractional tokens
// accumulate, so a sub-1/s rate still refills correctly. rate=0 && burst=0 disables (opt-out).
export function makeAnnounceBucket({ rate, burst, now = () => Math.floor(Date.now() / 1000) }) {
  let tokens = burst;
  let last = now();
  const disabled = !(rate > 0) && !(burst > 0);
  const refill = () => {
    const t = now();
    if (t > last) { tokens = Math.min(burst, tokens + (t - last) * rate); last = t; }
    return tokens;
  };
  return {
    rate, burst, disabled,
    take() {
      if (disabled) return true;
      if (refill() < 1) return false;
      tokens -= 1;
      return true;
    },
    tokens: refill,
    // Seconds until one token is available (for Retry-After); >= 1.
    retryAfterSec: () => (rate > 0 ? Math.max(1, Math.ceil((1 - tokens) / rate)) : 1),
  };
}

// Graceful shutdown: on the first signal stop accepting, let in-flight requests finish, then
// exit 0; a straggler past the grace window is force-closed and we exit nonzero.
//
// Injectable (server, timer, onExit) so the selftest drives it with a fake server +
// fake sockets + fake clock and no real process signals.
export function makeGracefulShutdown(server, {
  openSockets = new Set(),
  timeoutMs = 10000,
  onExit = (code) => process.exit(code),
  log = console.log,
  label = "service",
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let started = false; // idempotent: a second signal during drain is ignored
  return function shutdown(signal) {
    if (started) return;
    started = true;
    log(`${label}: draining (${signal || "shutdown"}); ${openSockets.size} in-flight, no new connections, ${timeoutMs}ms grace`);
    let timer = null;
    const finish = (code) => { if (timer) clearTimer(timer); onExit(code); };
    // Arm the grace window FIRST so an immediate (synchronous) clean drain can clear it.
    timer = setTimer(() => {
      log(`${label}: drain timeout (${timeoutMs}ms) with ${openSockets.size} still open; forcing exit`);
      for (const s of openSockets) { try { s.destroy(); } catch {} }
      finish(1);
    }, timeoutMs);
    timer.unref?.();
    server.close(() => { log(`${label}: drained cleanly, exiting`); finish(0); });
    return timer;
  };
}
