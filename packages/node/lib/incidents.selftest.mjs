// Incident feed, client side (lib/incidents.mjs): the signed document and its canonical bytes
// (shared with crates/shadenet/src/incidents.rs and the Rust Elder that serves the feed).
//
//   node packages/node/lib/incidents.selftest.mjs
//   node packages/node/lib/incidents.selftest.mjs --vector   # print the Rust test vector

import { INCIDENTS_DOMAIN, canonicalIncidentsBytes, signIncidents, verifyIncidents } from "./incidents.mjs";
import { ed25519PubFromSeed } from "./directory.mjs";

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
ok(verifyIncidents({ ...signed, version: 2 }, signed.signer).reason === "bad-version", "another document version is refused");
ok(verifyIncidents({ ...signed, incidents: Array.from({ length: 65 }, () => signed.incidents[0]) }, signed.signer).reason === "bad-incidents", "a feed over the size bound is refused before any crypto");

if (failures) { console.log(`FAIL: ${failures} incident feed check(s)`); process.exit(1); }
console.log("PASS: incident feed");
