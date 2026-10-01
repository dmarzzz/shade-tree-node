// Incident feed (GET /incidents + POST /incidents/alertmanager): the signed document, its
// canonical bytes (shared with crates/shadenet/src/incidents.rs), the Alertmanager mapping, the
// file round trip, and the server routes (webhook token, disabled-by-default).
//
//   node packages/node/bootnode/incidents.selftest.mjs
//   node packages/node/bootnode/incidents.selftest.mjs --vector   # print the Rust test vector

import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import {
  INCIDENTS_DOMAIN, canonicalIncidentsBytes, signIncidents, verifyIncidents,
  applyAlertmanagerPayload, pruneIncidents, makeIncidents, normalizeIncident,
} from "./incidents.mjs";
import { ed25519PubFromSeed } from "../lib/directory.mjs";
import { makeRegistry, makeServer, loadOrMintSigner } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Fixed seed so the vector below is reproducible; the Rust unit test pins the same bytes.
const SEED = "0000000000000000000000000000000000000000000000000000000000000001";
const SAMPLE = {
  issued: 1759300000,
  incidents: [{
    id: "BootnodeDown:shade-elder-v4-02", component: "elder", instance: "shade-elder-v4-02",
    severity: "critical", summary: "Bootnode \"shade-elder-v4-02\" is down", since: 1759299000, until: null,
  }],
};

if (process.argv.includes("--vector")) {
  const doc = signIncidents(SAMPLE, SEED);
  console.log(JSON.stringify({ signer: doc.signer, signature: doc.signature, bytes: canonicalIncidentsBytes(SAMPLE).toString("utf8") }, null, 2));
  process.exit(0);
}

async function main() {
  console.log("canonical bytes + signature:");
  const bytes = canonicalIncidentsBytes(SAMPLE).toString("utf8");
  ok(bytes.startsWith(INCIDENTS_DOMAIN), "domain separator leads the signed bytes");
  ok(bytes === INCIDENTS_DOMAIN + '{"version":1,"issued":1759300000,"incidents":[{"id":"BootnodeDown:shade-elder-v4-02","component":"elder","instance":"shade-elder-v4-02","severity":"critical","summary":"Bootnode \\"shade-elder-v4-02\\" is down","since":1759299000,"until":null}]}', "canonical JSON has fixed key order (matches the Rust vector)");
  const signed = signIncidents(SAMPLE, SEED);
  ok(signed.signer === ed25519PubFromSeed(SEED), "signer is the seed's public key");
  ok(verifyIncidents(signed, signed.signer).ok, "a signed feed verifies under its pinned signer");
  ok(verifyIncidents(signed, "ab".repeat(32)).reason === "signer-not-pinned", "another pinned signer is refused");
  ok(verifyIncidents({ ...signed, incidents: [{ ...signed.incidents[0], summary: "tampered" }] }, signed.signer).reason === "bad-signature", "a tampered incident fails the signature");
  ok(verifyIncidents({ ...signed, signature: undefined }, signed.signer).reason === "unsigned", "an unsigned feed is refused");

  console.log("normalization:");
  ok(normalizeIncident({ id: "x" }) === null, "an incident without `since` is dropped");
  const n = normalizeIncident({ id: "x", since: "2026-09-30T22:11:20Z", component: "weird", severity: "loud" });
  ok(n.since === Math.floor(Date.parse("2026-09-30T22:11:20Z") / 1000) && n.component === "other" && n.severity === "warning" && n.instance === "canopy" && n.summary === "x", "ISO since parses; unknown component/severity fall to other/warning; instance and summary default");

  console.log("Alertmanager mapping:");
  const T = (iso) => Math.floor(Date.parse(iso) / 1000);
  const now = T("2026-10-01T06:55:00Z");
  const firing = {
    version: "4", status: "firing",
    alerts: [
      { status: "firing", labels: { alertname: "BootnodeDown", instance: "shade-elder-v4-02", job: "shade-tree-bootnode", severity: "critical" },
        annotations: { summary: "Bootnode shade-elder-v4-02 is down / unscrapable" }, startsAt: "2026-10-01T06:50:00Z", endsAt: "0001-01-01T00:00:00Z" },
      { status: "firing", labels: { alertname: "GatewayRootDegraded", instance: "node-06", job: "shade-tree-gateway" }, annotations: {}, startsAt: "2026-10-01T06:52:00Z" },
    ],
  };
  const a = applyAlertmanagerPayload([], firing, now);
  ok(a.firing === 2 && a.incidents.length === 2, "two firing alerts become two open incidents");
  const elder = a.incidents.find((i) => i.id === "BootnodeDown:shade-elder-v4-02");
  ok(elder && elder.component === "elder" && elder.severity === "critical" && elder.until === null && elder.since === T("2026-10-01T06:50:00Z"), `job -> component, severity kept, startsAt parsed: ${JSON.stringify(elder)}`);
  const node = a.incidents.find((i) => i.id === "GatewayRootDegraded:node-06");
  ok(node && node.component === "node" && node.severity === "warning" && node.summary === "GatewayRootDegraded", "a gateway job maps to node; missing severity/summary default");
  const resolved = { alerts: [{ status: "resolved", labels: { alertname: "BootnodeDown", instance: "shade-elder-v4-02", job: "shade-tree-bootnode" }, startsAt: "2026-10-01T06:50:00Z", endsAt: "2026-10-01T07:12:00Z" }] };
  const b = applyAlertmanagerPayload(a.incidents, resolved, T("2026-10-01T07:12:30Z"));
  const closed = b.incidents.find((i) => i.id === "BootnodeDown:shade-elder-v4-02");
  ok(b.resolved === 1 && closed.until === T("2026-10-01T07:12:00Z") && closed.since === T("2026-10-01T06:50:00Z"), "a resolved alert keeps the incident with `until` = endsAt");
  ok(pruneIncidents(b.incidents, T("2026-10-01T07:12:00Z") + 3601).length === 1, "a resolved incident is pruned an hour after `until`");
  ok(pruneIncidents(b.incidents, T("2026-10-01T07:12:00Z") + 10).length === 2, "…but stays listed inside the grace period");
  const many = { alerts: Array.from({ length: 100 }, (_, i) => ({ status: "firing", labels: { alertname: "A", instance: `h${i}` }, startsAt: "2026-10-01T06:50:00Z" })) };
  ok(pruneIncidents(applyAlertmanagerPayload([], many, now).incidents, now).length === 64, "the list is bounded to 64");

  console.log("file round trip + server routes:");
  const work = await mkdtemp(join(tmpdir(), "shade-tree-incidents-"));
  try {
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    const path = join(work, "incidents.json");
    let clock = now;
    const incidents = makeIncidents({ path, signer, now: () => clock });
    ok(incidents.feed().incidents.length === 0 && verifyIncidents(incidents.feed(), signer.pub).ok, "an absent file serves an empty, signed feed");
    await writeFile(path, JSON.stringify({ incidents: [{ id: "ByHand:node-05", component: "node", instance: "node-05", severity: "info", summary: "planned restart", since: now - 60 }] }));
    ok(incidents.feed().incidents[0]?.id === "ByHand:node-05", "a hand-written file is served as-is");
    const r = incidents.applyAlertmanager(firing);
    ok(r.firing === 2 && r.open === 3, "the webhook merges with the hand-written entry");
    const onDisk = JSON.parse(await readFile(path, "utf8"));
    ok(onDisk.incidents.length === 3, "the merged list is persisted");
    await writeFile(path, "{not json");
    ok(incidents.feed().incidents.length === 0, "an unreadable file serves an empty feed (never throws)");

    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, now: () => clock });
    const base = await new Promise((resolve) => {
      const server = makeServer(registry, { signerPub: signer.pub, incidents, incidentsToken: "s3cret" });
      server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
    });
    const get = (p, opts = {}) => new Promise((resolve, reject) => {
      const req = http.request(base.url + p, { method: opts.method || "GET", headers: opts.headers || {} }, (res) => {
        let body = ""; res.on("data", (c) => (body += c)); res.on("end", () => resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null, headers: res.headers }));
      });
      req.on("error", reject);
      if (opts.body) req.write(JSON.stringify(opts.body));
      req.end();
    });
    await writeFile(path, JSON.stringify({ incidents: [] }));
    const feed = await get("/incidents");
    ok(feed.status === 200 && verifyIncidents(feed.body, signer.pub).ok && feed.headers["x-shade-tree-view"] === "canopy", "GET /incidents serves a signed feed with the canopy headers");
    ok((await get("/incidents/alertmanager", { method: "POST", body: firing })).status === 401, "the webhook refuses a missing token");
    ok((await get("/incidents/alertmanager", { method: "POST", body: firing, headers: { authorization: "Bearer wrong" } })).status === 401, "…and a wrong one");
    const posted = await get("/incidents/alertmanager", { method: "POST", body: firing, headers: { authorization: "Bearer s3cret" } });
    ok(posted.status === 200 && posted.body.firing === 2, "a bearer-authenticated webhook is applied");
    const after = await get("/incidents");
    ok(after.body.incidents.length === 2 && verifyIncidents(after.body, signer.pub).ok, "the feed now lists the firing alerts, still signed");
    base.server.close();

    const off = await new Promise((resolve) => {
      const server = makeServer(registry, { signerPub: signer.pub, incidents });
      server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
    });
    const r404 = await new Promise((resolve) => {
      const req = http.request(off.url + "/incidents/alertmanager", { method: "POST", headers: { authorization: "Bearer s3cret" } }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
      req.end("{}");
    });
    ok(r404 === 404, "without a token the webhook route is off (404), the feed still serves");
    off.server.close();
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  if (failures) { console.log(`FAIL: ${failures} check(s)`); process.exit(1); }
  console.log("PASS: incident feed");
}

main().catch((e) => { console.error(e); process.exit(1); });
