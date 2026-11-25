// The canopy incident feed, client side: the Elder Tree (crates/shadenet-elder) serves a small
// SIGNED list of operator-declared incidents at GET /incidents so a client can tell its agent the
// real cause ("node-06 restarting since 22:11Z") instead of a bare transport timeout.
//
// The document is signed by the Elder's canopy signer (the key clients already pin for the
// directory) over INCIDENTS_DOMAIN + JSON.stringify({version, issued, incidents}) with fixed key
// order. crates/shadenet/src/incidents.rs builds byte-identical input; the selftest prints the
// vector both sides check.

import { ed25519Sign, ed25519Verify, ed25519PubFromSeed } from "./directory.mjs";

export const INCIDENTS_DOMAIN = "Shade Tree incidents v1\n";
export const MAX_INCIDENTS = 64;

export function canonicalIncidentsBytes({ issued, incidents }) {
  const payload = {
    version: 1,
    issued,
    incidents: (incidents || []).map((i) => ({
      id: i.id, component: i.component, instance: i.instance, severity: i.severity,
      summary: i.summary, since: i.since, until: i.until == null ? null : i.until,
    })),
  };
  return Buffer.from(INCIDENTS_DOMAIN + JSON.stringify(payload), "utf8");
}

export function signIncidents({ issued, incidents }, signerPrivHex) {
  const signature = ed25519Sign(canonicalIncidentsBytes({ issued, incidents }), signerPrivHex);
  return { version: 1, issued, incidents, signer: ed25519PubFromSeed(signerPrivHex), signature };
}

export function verifyIncidents(doc, pinnedSigner) {
  if (!doc || typeof doc !== "object" || doc.version !== 1) return { ok: false, reason: "bad-version" };
  if (!Array.isArray(doc.incidents) || doc.incidents.length > MAX_INCIDENTS) return { ok: false, reason: "bad-incidents" };
  if (typeof doc.signature !== "string" || typeof doc.signer !== "string") return { ok: false, reason: "unsigned" };
  if (pinnedSigner && doc.signer.toLowerCase() !== String(pinnedSigner).toLowerCase()) return { ok: false, reason: "signer-not-pinned" };
  const ok = ed25519Verify(canonicalIncidentsBytes(doc), doc.signature, doc.signer);
  return ok ? { ok: true } : { ok: false, reason: "bad-signature" };
}
