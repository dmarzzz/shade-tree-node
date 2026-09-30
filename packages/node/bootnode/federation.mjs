// Bootnode federation / gossip (T-FEAT-1): make discovery survive one bootnode going dark.
//
// A bootnode PEERS with a configured set of OTHER bootnode onions and periodically PULLS their
// directories over Tor, re-VERIFIES every gossiped gateway through the SAME real announce path
// (onion control + operator/stake, on THIS bootnode's own chain view), and MERGES the verified
// entries into its own registry. This is "cache, not trust root" applied to gossip: a gossiped
// entry is admitted ONLY if it self-verifies exactly like a direct announce.
//
//   THE PEER'S DIRECTORY SIGNATURE IS NEVER TRUSTED AS AUTHORITY OVER THE ENTRIES.
//
// The peer's signed /directory is used only as a HINT LIST of onion strings to probe. Its
// pubkey/weight/health/operator/staked labels and its signer signature carry no admission weight.
// For each listed onion we pull the peer's stored, verbatim signed announce (GET /gateway/<onion>,
// the exact bytes a zero-trust client fetches) and hand THAT to registry.admitGossip(), which runs
// the real verifyAnnounce (v3 .onion == its ed25519 key, so a swapped/grafted onion fails; a
// tampered field breaks the onion signature; an unstaked operator is rejected on chain). So a
// forged/tampered/unstaked gossiped gateway is rejected exactly as a direct announce would be.
//
// WHY /directory + per-gateway /gateway/<onion>, not /directory alone:
//   /directory carries only { onion, pubkey, weight, health } (+ operator/staked labels) -- it does
//   NOT carry the announce's onionSig / ts / nonce / operatorSig, so it is NOT independently
//   re-verifiable per entry (verifyDirectory only proves the PEER signer signed that shape, which we
//   refuse to trust). The per-gateway announce IS the self-authenticating unit, and the bootnode
//   already serves it at GET /gateway/<onion> (added for exactly this zero-trust re-verification), so
//   federation needs NO new endpoint or new linkability/DoS surface -- it only CONSUMES peers.
//
// Loop / bounding / fail-soft:
//   - admitGossip sets each entry's expiry from the origin announce's OWN ts (+ttl), never refreshed
//     by gossip, so an entry cannot be kept alive forever by re-gossiping a fixed rec, and gossip
//     never re-propagates a TTL. Re-pulling the same rec is idempotent (dedup by expiry).
//   - maxPullPerPeer caps how many gateways we fetch from any one peer, so a hostile peer advertising
//     a giant directory cannot make us do unbounded per-gateway fetches; the registry maxEntries cap
//     still bounds what is actually admitted.
//   - a peer that is down (fetch throws) is skipped; one failing gateway fetch doesn't abort the peer;
//     one failing peer doesn't abort the cycle. Discovery is strictly additive and fail-soft.

import { fetchOverTor } from "./fetch.mjs";

// Normalize a peer entry to a bare "<addr>.onion": strip an accidental scheme/path, lowercase,
// ensure the .onion suffix. A malformed entry still normalizes to something that simply fails the
// fetch (and is skipped fail-soft), so this never needs to be a strict validator.
export function normOnion(s) {
  if (typeof s !== "string") return "";
  const t = s.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
  if (!t) return "";
  return t.endsWith(".onion") ? t : t + ".onion";
}

// Parse SHADE_TREE_BOOTNODE_PEERS: a comma-list of peer bootnode onions. Empty/unset => [] (off, so the
// bootnode is byte-for-byte today's standalone one). Blanks are dropped, entries deduped, and our
// OWN onion (opts.self) filtered out so a bootnode never gossips from itself.
export function parsePeers(raw, { self = null } = {}) {
  if (!raw) return [];
  const selfNorm = self ? normOnion(self) : null;
  const seen = new Set();
  const out = [];
  for (const part of String(raw).split(",")) {
    const n = normOnion(part);
    if (!n) continue;
    if (selfNorm && n === selfNorm) continue;
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

// Build the federation pull loop over `registry`. Fetchers are injected (default: real Tor) so the
// selftest drives pullAll()/pullPeer() with crafted responses and no Tor/chain. Nothing dials until
// start() is called AND peers is non-empty; the timer self-unrefs, so it never keeps the process up.
export function makeFederation({
  registry,
  peers = [],
  // Tor SOCKS for the default fetchers. Before OPS-9 these ignored SHADE_TREE_TOR_HOST/PORT and
  // always dialed 127.0.0.1:9250, so an Elder on a box whose tor listens elsewhere never merged.
  tor = { torHost: process.env.SHADE_TREE_TOR_HOST || "127.0.0.1", torPort: Number(process.env.SHADE_TREE_TOR_PORT || 9250) },
  // async (peerOnion) => the peer's /directory object (untrusted hint list)
  fetchDir = (peer) => fetchOverTor(peer, "/directory", tor),
  // async (peerOnion, onion) => the peer's stored signed announce rec for that gateway
  fetchGateway = (peer, onion) => fetchOverTor(peer, "/gateway/" + encodeURIComponent(onion), tor),
  intervalMs = Number(process.env.SHADE_TREE_BOOTNODE_FED_INTERVAL || 60) * 1000,
  // Bound per-peer gateway fetches. Default to the registry's own cap (can't hold more anyway).
  maxPullPerPeer = Number(process.env.SHADE_TREE_BOOTNODE_FED_MAX_PULL || (registry.maxEntries?.() ?? 10000)),
  log = console,
  setTimer = setInterval,
  clearTimer = clearInterval,
} = {}) {
  let timer = null;

  // Pull + merge one peer. Fail-soft at every level. Returns per-peer stats.
  async function pullPeer(peer) {
    const stats = { peer, listed: 0, merged: 0, skipped: 0, rejected: 0, errors: 0 };
    let dir;
    try {
      dir = await fetchDir(peer);
    } catch (e) {
      // A down / unreachable peer is skipped, never fatal to the cycle.
      stats.errors++;
      stats.error = e?.message || String(e);
      return stats;
    }
    // Enumerate onion STRINGS only -- the peer's labels + signature are not trusted.
    const gateways = Array.isArray(dir?.gateways) ? dir.gateways : [];
    const onions = [];
    for (const g of gateways) {
      const o = typeof g?.onion === "string" ? g.onion : null;
      if (o) onions.push(o);
      if (onions.length >= maxPullPerPeer) break; // bound a hostile over-large directory
    }
    stats.listed = onions.length;
    for (const onion of onions) {
      let rec;
      try {
        rec = await fetchGateway(peer, onion);
      } catch {
        // One gateway fetch failing (404 / truncated / down) doesn't abort the peer.
        stats.errors++;
        continue;
      }
      let r;
      try {
        r = await registry.admitGossip(rec);
      } catch {
        stats.rejected++;
        continue;
      }
      if (r.merged) stats.merged++;
      else if (r.ok) stats.skipped++; // fresh-existing (dedup) -- already held at >= this freshness
      else stats.rejected++; // forged / tampered / unstaked / stale / full -> NOT admitted
    }
    return stats;
  }

  // One full pass over every peer (sequential; peer sets are small). Aggregates stats.
  async function pullAll() {
    const results = [];
    for (const peer of peers) results.push(await pullPeer(peer));
    const agg = results.reduce(
      (a, s) => ({ merged: a.merged + s.merged, skipped: a.skipped + s.skipped, rejected: a.rejected + s.rejected, errors: a.errors + s.errors }),
      { merged: 0, skipped: 0, rejected: 0, errors: 0 },
    );
    if (agg.merged || agg.rejected) {
      try { log.info?.("federation pull", { ...agg, peers: peers.length }); } catch { /* logging is best-effort */ }
    }
    // A peer that cannot be reached at all is worth a warning: silence here hid a wrong Tor port.
    for (const r of results) {
      if (r.errors && !r.listed) {
        try { log.warn?.("federation peer unreachable", { error: String(r.error || "").replace(/[a-z2-7]{56}\.onion/g, "<onion>").slice(0, 200) }); } catch { /* best-effort */ }
      }
    }
    return { results, ...agg };
  }

  return {
    peers,
    intervalMs,
    maxPullPerPeer,
    pullPeer,
    pullAll,
    // Start the periodic pull. No-op if already started or if there are no peers, so the default
    // (no SHADE_TREE_BOOTNODE_PEERS) never dials anything. Kicks one convergence pull immediately
    // (non-blocking), then every intervalMs. The timer self-unrefs.
    start() {
      if (timer || peers.length === 0) return timer;
      Promise.resolve().then(() => pullAll()).catch(() => {}); // initial convergence, fire-and-forget
      timer = setTimer(() => { pullAll().catch(() => {}); }, intervalMs);
      timer.unref?.();
      return timer;
    },
    stop() { if (timer) { clearTimer(timer); timer = null; } },
  };
}
