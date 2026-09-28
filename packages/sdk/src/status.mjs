// Status from a local `shadenet` daemon (the Rust proxy). A browser cannot open Tor circuits, so
// it asks the daemon on loopback: GET http://127.0.0.1:8118/_shadenet/status.
//
// Expected body (the Rust SDK's `status()`, roadmap M3 AGENT-2):
//   { admitted: bool, finalized: bool, tier: number, slotsLeft: number, slotsPerEpoch: number,
//     epochResetsAt: ISO string, canopy: { nodes: number, issued: ISO string }, network: string }
// Fields the daemon omits come back as null, so an older daemon still yields a partial status.

import { ShadeNetError } from "./errors.mjs";

export const DEFAULT_DAEMON = "http://127.0.0.1:8118";
export const STATUS_PATH = "/_shadenet/status";

const FIELDS = ["admitted", "finalized", "tier", "slotsLeft", "slotsPerEpoch", "epochResetsAt", "canopy", "network"];

export function normalizeStatus(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ShadeNetError("Transport", "the daemon returned a status that is not a JSON object");
  }
  return Object.fromEntries(FIELDS.map((f) => [f, body[f] ?? null]));
}

export async function daemonStatus({ daemon = DEFAULT_DAEMON, fetchImpl = globalThis.fetch, timeoutMs = 3_000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(new URL(STATUS_PATH, daemon), { signal: controller.signal, headers: { accept: "application/json" } });
  } catch (cause) {
    throw new ShadeNetError("Transport", `no shadenet daemon answered at ${daemon}; start it with \`shade-tree proxy\``, { cause });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new ShadeNetError("Transport", `daemon status returned HTTP ${res.status}`, { status: res.status });
  return normalizeStatus(await res.json());
}
