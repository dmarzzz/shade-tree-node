// Canopy verification: the signed directory of Shade Tree nodes, checked with the same code the
// gateway and the JS client use (lib/directory.mjs), in Node or a browser.

import { verifyDirectory, onionToPubkey, canonicalCaps } from "../../../lib/directory.mjs";
import { resolveNetwork } from "./network.mjs";
import { ShadeNetError } from "./errors.mjs";

// Verify a canopy directory against the network's pinned signer (or explicit `signers`).
// Returns { nodes, signer, issued } or throws ShadeNetError("Canopy").
export function verifyCanopy(directory, { network = "sepolia", signers, maxAgeSeconds, nowMs = Date.now() } = {}) {
  const net = typeof network === "object" && network?.record ? network : resolveNetwork(network);
  const pinned = signers ?? (net.elder?.canopySigner ? [net.elder.canopySigner] : []);
  if (!pinned.length) throw new ShadeNetError("Canopy", `no canopy signer is pinned for ${net.name}`);
  const result = verifyDirectory(directory, pinned);
  if (!result.ok) throw new ShadeNetError("Canopy", `canopy failed verification: ${result.reason}`, { reason: result.reason });
  if (maxAgeSeconds != null) {
    const issuedMs = Date.parse(directory.issued);
    if (!Number.isFinite(issuedMs) || nowMs - issuedMs > maxAgeSeconds * 1000) {
      throw new ShadeNetError("Canopy", `canopy is older than ${maxAgeSeconds}s (issued ${directory.issued})`);
    }
  }
  return {
    signer: result.signer ?? result.signers,
    issued: directory.issued,
    nodes: (directory.gateways || []).map((g) => ({
      onion: g.onion,
      pubkey: onionToPubkey(g.onion),
      weight: g.weight,
      health: g.health,
      caps: canonicalCaps(g.caps),
    })),
  };
}
