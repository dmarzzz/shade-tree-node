#!/usr/bin/env node
// Cold vs warm dial timing through an exit -> JSONL (type "dial"). See lib/dial.mjs.
//
//   node bench/egress/dial.mjs --real --label shadenet --exit http://127.0.0.1:8888 --out runs/dial.jsonl
//   node bench/egress/dial.mjs --real --label shadenet --exit http://127.0.0.1:8888 --idle 600 --series 3 --out runs/dial.jsonl
//
// --idle S waits S seconds before each cold dial. The harness cannot know whether something
// else used the exit meanwhile (another agent on the same member Proxy makes the next dial
// warm), so note in the report what else shared the exit.

import { parseArgs } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parseExit, describeExit } from "./lib/exits.mjs";
import { isLoopbackHost } from "./lib/sites.mjs";
import { coldWarm } from "./lib/dial.mjs";

const { values: a } = parseArgs({ options: {
  label: { type: "string" }, exit: { type: "string", default: "direct" }, out: { type: "string" },
  target: { type: "string", default: "https://api.ipify.org/" }, warm: { type: "string", default: "4" },
  gap: { type: "string", default: "2" }, idle: { type: "string", default: "0" }, series: { type: "string", default: "1" },
  timeout: { type: "string", default: "150" }, real: { type: "boolean", default: false }, "show-ips": { type: "boolean", default: false },
} });
const die = (m) => { console.error(m); process.exit(2); };
if (!a.label || !/^[A-Za-z0-9._-]{1,40}$/.test(a.label)) die("--label is required");
if (!a.out) die("--out is required");
const ex = parseExit(a.exit);
if (!ex.ok) die(ex.error);
let target;
try { target = new URL(a.target); } catch { die("bad --target"); }
const local = isLoopbackHost(target.hostname);
if (!local && process.env.CI) die("refusing a non-loopback target under CI");
if (!local && !a.real) die("target is not loopback: pass --real");
const n = (k, lo, hi) => { const v = Number(a[k]); if (!Number.isFinite(v) || v < lo || v > hi) die(`--${k} out of range`); return v; };
const warm = n("warm", 0, 50); const gapMs = n("gap", local ? 0 : 1, 600) * 1000; const idle = n("idle", 0, 86400);
const series = n("series", 1, 100); const timeoutMs = n("timeout", 1, 600) * 1000;

await mkdir(dirname(resolve(a.out)), { recursive: true });
// Per-run random salt: equal hashes within one run mean "same exit", but an unsalted hash of
// an IPv4 address could be reversed by hashing all 2^32 of them.
const SALT = randomBytes(16);
for (let i = 1; i <= series; i++) {
  if (idle) await new Promise((r) => setTimeout(r, idle * 1000));
  const rows = await coldWarm(ex.exit, target.href, { warm, gapMs, timeoutMs });
  for (const r of rows) {
    const row = { ...r, ts: new Date().toISOString(), exit: a.label, exitSpec: describeExit(ex.exit), target: target.host, sample: i, idleS: idle };
    // The probe body is the exit IP. Keep it only when asked, so a dial file can be shared; a
    // salted short hash still shows whether the warm dials reused the cold dial's exit.
    row.exitHash = row.body ? createHash("sha256").update(SALT).update(row.body).digest("hex").slice(0, 8) : null;
    if (!a["show-ips"]) delete row.body;
    await appendFile(a.out, JSON.stringify(row) + "\n");
    console.log(`[${a.label} #${i}] ${r.phase} tunnel=${r.tTunnelMs}ms tls=${r.tTlsMs}ms total=${r.tTotalMs}ms code=${r.code} ${r.error || ""}`);
  }
}
