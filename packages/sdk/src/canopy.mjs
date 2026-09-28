// Canopy verification: the signed directory of Shade Tree nodes, checked with the same code the
// gateway and the JS client use (lib/directory.mjs), in Node or a browser.

import { verifyDirectory, onionToPubkey, canonicalCaps } from "../../../lib/directory.mjs";
import { resolveNetwork } from "./network.mjs";
import { ShadeNetError } from "./errors.mjs";

const asList = (signer) => (Array.isArray(signer) ? signer : [signer]);

// Verify a canopy directory. With explicit `signers` it must verify against them; otherwise it must
// verify against the pinned signer of one of the network's Elder Trees (each Elder signs its own
// directory). Returns { nodes, signer, issued, elder } or throws ShadeNetError("Canopy").
export function verifyCanopy(directory, { network = "sepolia", signers, elder, maxAgeSeconds, nowMs = Date.now() } = {}) {
  const net = typeof network === "object" && network?.record ? network : resolveNetwork(network);
  const candidates = signers
    ? [{ onion: null, canopySigner: signers }]
    : (elder ? net.elders.filter((e) => e.onion === elder) : net.elders);
  if (!candidates.length) throw new ShadeNetError("Canopy", `no canopy signer is pinned for ${net.name}${elder ? ` Elder ${elder}` : ""}`);
  let result = null;
  let verifiedBy = null;
  for (const candidate of candidates) {
    result = verifyDirectory(directory, asList(candidate.canopySigner));
    if (result.ok) { verifiedBy = candidate.onion; break; }
  }
  if (!result.ok) throw new ShadeNetError("Canopy", `canopy failed verification: ${result.reason}`, { reason: result.reason });
  if (maxAgeSeconds != null) {
    const issuedMs = Date.parse(directory.issued);
    if (!Number.isFinite(issuedMs) || nowMs - issuedMs > maxAgeSeconds * 1000) {
      throw new ShadeNetError("Canopy", `canopy is older than ${maxAgeSeconds}s (issued ${directory.issued})`);
    }
  }
  return {
    signer: result.signer ?? result.signers,
    elder: verifiedBy,
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

// Union of verified canopies (the output of verifyCanopy for each Elder): every node once; when
// two canopies list the same node, the entry from the more recently issued one wins.
export function mergeCanopies(views) {
  const sorted = [...views].sort((a, b) => Number(b.issued) - Number(a.issued));
  const seen = new Set();
  const nodes = [];
  for (const view of sorted) {
    for (const node of view.nodes) {
      if (!seen.has(node.onion)) { seen.add(node.onion); nodes.push(node); }
    }
  }
  return { issued: sorted[0]?.issued ?? null, elders: sorted.map((v) => v.elder).filter(Boolean), nodes };
}
