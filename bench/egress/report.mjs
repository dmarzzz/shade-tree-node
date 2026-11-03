#!/usr/bin/env node
// Turn one or more egress benchmark JSONL files (from run.mjs and dial.mjs) into markdown.
//
//   node bench/egress/report.mjs runs/*.jsonl > REPORT.md
//   node bench/egress/report.mjs --exits dc-fsn,tor,shadenet --clients curl,headed runs/*.jsonl
//   node bench/egress/report.mjs --show-ips runs/*.jsonl      (operator view; do not publish)

import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import { parseJsonl, buildReport } from "./lib/report.mjs";

const { values: a, positionals: files } = parseArgs({ allowPositionals: true, options: {
  exits: { type: "string" }, clients: { type: "string" }, title: { type: "string", default: "Egress benchmark report" },
  "show-ips": { type: "boolean", default: false },
} });
if (!files.length) { console.error("usage: node bench/egress/report.mjs [--exits a,b] [--clients a,b] [--title T] [--show-ips] FILE.jsonl..."); process.exit(2); }

const all = { rows: [], dials: [], metas: [] };
let bad = 0;
for (const f of files) {
  const p = parseJsonl(await readFile(f, "utf8"));
  all.rows.push(...p.rows); all.dials.push(...p.dials); all.metas.push(...p.metas); bad += p.bad;
}
if (bad) console.error(`skipped ${bad} malformed line(s)`);
const list = (s) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : null);
process.stdout.write(buildReport(all, { showIps: a["show-ips"], exitOrder: list(a.exits), clientOrder: list(a.clients), title: a.title }) + "\n");
