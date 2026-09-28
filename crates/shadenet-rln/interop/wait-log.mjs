// Readiness helper for the T-RUST-2d harness that does NOT touch the server socket.
// Polls a log file (server stdout/stderr) until <pattern> appears, on its OWN setInterval
// (no shell `sleep`). Unlike a TCP connect-probe, this never opens a half-request that a
// raw-TCP server (the gateway reads a full newline-terminated envelope) would choke on.
// Exits 0 when the line appears, 1 on timeout.
//
// Usage: node wait-log.mjs <logfile> <pattern> [timeoutMs]
import { readFileSync } from "node:fs";

const file = process.argv[2];
const pattern = process.argv[3];
const timeoutMs = Number(process.argv[4] || 20000);
const deadline = Date.now() + timeoutMs;

const timer = setInterval(() => {
  let hit = false;
  try {
    hit = readFileSync(file, "utf8").includes(pattern);
  } catch {
    /* file not created yet */
  }
  if (hit) {
    clearInterval(timer);
    process.exit(0);
  }
  if (Date.now() >= deadline) {
    clearInterval(timer);
    console.error(`wait-log: "${pattern}" not seen in ${file} after ${timeoutMs}ms`);
    process.exit(1);
  }
}, 100);
