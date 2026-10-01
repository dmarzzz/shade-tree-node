// Canopy incident feed (ergonomics, 2026-10-01): the Elder Tree serves a small SIGNED list of
// operator-declared incidents at GET /incidents so a client can tell its agent the real cause
// ("node-06 restarting since 22:11Z") instead of a bare transport timeout.
//
// Sources, in order of how operators actually use them:
//   - Alertmanager: POST /incidents/alertmanager with `Authorization: Bearer <token>` and the
//     standard webhook payload. Firing alerts are upserted, resolved ones get `until`.
//   - by hand: edit the incidents file (`{ "incidents": [ ... ] }`); the Elder re-reads it on
//     every fetch, so a change is live at once.
//
// The document is signed by the Elder's canopy signer (the key clients already pin for the
// directory) over INCIDENTS_DOMAIN + JSON.stringify({version, issued, incidents}) with fixed key
// order. crates/shadenet/src/incidents.rs builds byte-identical input; the selftest prints the
// vector both sides check.
//
//   SHADE_TREE_BOOTNODE_INCIDENTS_FILE   where the list lives (default bootnode/incidents.local.json)
//   SHADE_TREE_BOOTNODE_INCIDENTS_TOKEN  bearer token for the Alertmanager webhook (unset = webhook off)

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { ed25519Sign, ed25519Verify, ed25519PubFromSeed } from "../lib/directory.mjs";

export const INCIDENTS_DOMAIN = "Shade Tree incidents v1\n";
export const MAX_INCIDENTS = 64;
const MAX_FIELD = 256;
const COMPONENTS = new Set(["elder", "node", "heartbeat", "rpc", "canopy", "other"]);
const SEVERITIES = new Set(["critical", "warning", "info"]);
// A resolved incident stays listed this long after `until`, so a client that fetches a minute
// later still learns why its last request failed.
const RESOLVED_GRACE_SEC = 60 * 60;

function clip(value, fallback = "") {
  const s = typeof value === "string" ? value : fallback;
  return s.length > MAX_FIELD ? s.slice(0, MAX_FIELD) : s;
}

function unix(value, fallback) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.floor(value);
  if (typeof value === "string") {
    const ms = Date.parse(value);
    if (Number.isFinite(ms) && ms > 0) return Math.floor(ms / 1000);
  }
  return fallback;
}

// Normalize one incident into the exact field set the signature covers; null when unusable.
export function normalizeIncident(raw) {
  if (!raw || typeof raw !== "object") return null;
  const id = clip(raw.id);
  if (!id) return null;
  const component = COMPONENTS.has(raw.component) ? raw.component : "other";
  const severity = SEVERITIES.has(raw.severity) ? raw.severity : "warning";
  const since = unix(raw.since, null);
  if (since == null) return null;
  const until = raw.until == null ? null : unix(raw.until, null);
  return {
    id,
    component,
    instance: clip(raw.instance, "") || "canopy",
    severity,
    summary: clip(raw.summary, "") || id,
    since,
    until,
  };
}

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

// Map one Alertmanager webhook payload (https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
// onto incidents. Pure: returns the merged list.
export function applyAlertmanagerPayload(existing, payload, now) {
  const byId = new Map((existing || []).map((i) => [i.id, i]));
  let firing = 0;
  let resolved = 0;
  for (const alert of Array.isArray(payload?.alerts) ? payload.alerts : []) {
    const labels = alert.labels || {};
    const name = clip(labels.alertname, "") || "alert";
    const instance = clip(labels.instance || labels.host || labels.job, "") || "canopy";
    const id = `${name}:${instance}`;
    const component = COMPONENTS.has(labels.component) ? labels.component
      : /bootnode|elder/i.test(labels.job || "") ? "elder"
        : /gateway|node/i.test(labels.job || "") ? "node"
          : /heartbeat/i.test(labels.job || "") ? "heartbeat" : "other";
    const severity = SEVERITIES.has(labels.severity) ? labels.severity : "warning";
    const summary = clip(alert.annotations?.summary, "") || name;
    const since = unix(alert.startsAt, now);
    if (alert.status === "resolved") {
      const prev = byId.get(id);
      const until = unix(alert.endsAt, now) || now;
      byId.set(id, normalizeIncident({ ...(prev || { id, component, instance, severity, summary, since }), until }));
      resolved++;
    } else {
      byId.set(id, normalizeIncident({ id, component, instance, severity, summary, since, until: null }));
      firing++;
    }
  }
  const merged = [...byId.values()].filter(Boolean);
  return { incidents: merged, firing, resolved };
}

// Drop resolved incidents past their grace period and bound the list (newest first by `since`).
export function pruneIncidents(incidents, now) {
  return (incidents || [])
    .map(normalizeIncident)
    .filter((i) => i && (i.until == null || i.until + RESOLVED_GRACE_SEC > now))
    .sort((a, b) => b.since - a.since)
    .slice(0, MAX_INCIDENTS);
}

export function makeIncidents({ path, signer, now = () => Math.floor(Date.now() / 1000), log = null } = {}) {
  if (!path) throw new Error("makeIncidents needs a path");
  if (!signer?.priv) throw new Error("makeIncidents needs the Elder signer");

  function load() {
    if (!existsSync(path)) return [];
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8"));
      const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.incidents) ? parsed.incidents : [];
      return pruneIncidents(list, now());
    } catch (error) {
      log?.warn?.("incidents file unreadable; serving an empty feed", { path, err: error.message });
      return [];
    }
  }

  function save(incidents) {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ incidents }, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, path);
  }

  return {
    path,
    load,
    // The signed document for GET /incidents, built from the file on every call (operators edit
    // it by hand; a change is live at once).
    feed() {
      const incidents = load();
      return signIncidents({ issued: now(), incidents }, signer.priv);
    },
    // POST /incidents/alertmanager body -> file. Returns counts for the response.
    applyAlertmanager(payload) {
      const current = load();
      const { incidents, firing, resolved } = applyAlertmanagerPayload(current, payload, now());
      save(pruneIncidents(incidents, now()));
      return { firing, resolved, open: incidents.filter((i) => i.until == null).length };
    },
  };
}
