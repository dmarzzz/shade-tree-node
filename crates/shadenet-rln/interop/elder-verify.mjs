// The JavaScript reference checks against a running Elder: the signed canopy directory, the
// incident feed and the relay aggregate verify with the same functions the JavaScript clients,
// the uptime probe and the grove snapshot use, and the directory lists every onion named.
// Fetches go either straight to a loopback port or through a SOCKS shim as a client would.
//
// Usage: node elder-verify.mjs <elder-port> <signer-hex> [--via-socks <port> <onion>] [--expect <onion>...]
import { verifyDirectory } from "../../../packages/node/lib/directory.mjs";
import { verifyIncidents } from "../../../packages/node/lib/incidents.mjs";
import { verifyRelayAggregate } from "../../../packages/node/lib/relay-telemetry.mjs";
import { fetchOverTor } from "../../../packages/node/bootnode/fetch.mjs";

const args = process.argv.slice(2);
const port = Number(args.shift());
const signer = args.shift();
let socks = null;
const expected = [];
while (args.length) {
  const flag = args.shift();
  if (flag === "--via-socks") socks = { torPort: Number(args.shift()), onion: args.shift() };
  else if (flag === "--expect") expected.push(args.shift());
}

async function get(path) {
  if (socks) return fetchOverTor(socks.onion, path, { torHost: "127.0.0.1", torPort: socks.torPort, attempts: 1 });
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  if (res.status !== 200) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const dir = await get("/directory");
const v = verifyDirectory(dir, signer);
ok(v.ok, `the canopy directory verifies under the pinned signer${socks ? " (fetched through SOCKS like a client)" : ""}: ${v.reason || "ok"}`);
const onions = new Set((dir.gateways || []).map((g) => g.onion));
for (const onion of expected) ok(onions.has(onion), `the directory lists ${onion.slice(0, 12)}..`);
for (const g of dir.gateways || []) ok(g.announce && g.announce.onion === g.onion, `the entry for ${g.onion.slice(0, 12)}.. carries its announce`);

const incidents = await get("/incidents");
const vi = verifyIncidents(incidents, signer);
ok(vi.ok, `the incident feed verifies under the pinned signer: ${vi.reason || "ok"}`);

const aggregate = await get("/telemetry/aggregate");
ok(verifyRelayAggregate(aggregate, signer), "the relay aggregate verifies under the pinned signer");
ok(aggregate.windows?.sixHour?.status === "suppressed", "a cohort under five reporters is suppressed");

console.log(failures ? `FAIL: ${failures} check(s)` : "PASS: elder-verify");
process.exit(failures ? 1 : 0);
