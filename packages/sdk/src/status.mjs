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

// `token` is the proxy token (`~/.config/shadenet/proxy-token`); the daemon answers 407 without it.
// The timeout covers a cold call: when its canopy is due the daemon refreshes it first (~5 s over Tor).
export async function daemonStatus({ daemon = DEFAULT_DAEMON, token, fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    const headers = { accept: "application/json" };
    if (token) headers.authorization = `Bearer ${token}`;
    res = await fetchImpl(new URL(STATUS_PATH, daemon), { signal: controller.signal, headers });
  } catch (cause) {
    throw new ShadeNetError("Transport", `no shadenet daemon answered at ${daemon}; start it with \`shadenet proxy\``, { cause });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new ShadeNetError("Transport", `daemon status returned HTTP ${res.status}`, { status: res.status });
  return normalizeStatus(await res.json());
}
