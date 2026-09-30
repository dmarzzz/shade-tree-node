// Signed egress success receipts (T-FEAT-13).
//
// After a gateway SUCCESSFULLY opens an upstream tunnel, it returns a small receipt signed by
// its onion-control key that attests, in effect: "I (this onion) opened a tunnel at
// epoch E." A client holding the gateway's directory pubkey can VERIFY it and accumulate
// it as evidence of gateway liveness/quality (feeds quality-aware rotation, T-FEAT-4).
//
// PRIVACY IS THE WHOLE POINT. The receipt is a per-GATEWAY liveness attestation, NOT a
// per-TUNNEL non-repudiation proof, precisely so it can carry ZERO tunnel-linkable data:
//
//   field    what it is                        why it is safe (reveals nothing about member/target)
//   -----    ----------------------------      ----------------------------------------------------
//   v        receipt schema version (int)      a constant; version tag only.
//   onion    the GATEWAY's own .onion addr     the gateway's PUBLIC identity (already in the signed
//                                              directory). It IS the ed25519 pubkey (onionToPubkey),
//                                              so the receipt is self-authenticating. Says nothing
//                                              about WHO connected or WHERE they egressed.
//   epoch    COARSE epoch bucket (dec string)  the same low-resolution time bucket the RLN rate cap
//                                              already uses (EPOCH_SECONDS, default 120s). Every
//                                              tunnel in a bucket shares one value, so it does not
//                                              pin a tunnel in time. We DELIBERATELY use the coarse
//                                              epoch instead of a fine `ts` or a counter: a
//                                              wall-clock timestamp or monotonic counter would be a
//                                              distinguishing per-tunnel tag (a covert linkability /
//                                              logging channel), which a coarse bucket is not.
//   ok       literal boolean true              a constant success flag. Carries no tunnel data.
//   sig      ed25519 sig by the onion key      over canonicalReceiptBytes below.
//
// What is DELIBERATELY ABSENT (and must stay absent): member identity/commitment, the
// nullifier (or any prefix of it), the RLN share, the target host/port, the tunnel nonce,
// a fine timestamp, or a per-tunnel counter. Any of those would tie a receipt to a
// specific member or a specific tunnel and hand a colluding party a correlation handle.
// (This is a deliberate, stronger-privacy divergence from the loose `{nullifier-prefix,
// ts, ok}` sketch in the backlog note — see docs/RECEIPTS.md for the rationale.)
//
// Consequence, stated honestly: because two receipts from the same gateway in the same
// epoch are byte-identical, a receipt proves gateway LIVENESS/QUALITY over an epoch, not
// that YOUR specific tunnel opened. That per-tunnel binding is exactly the linkability
// channel we refuse to add. An honest gateway only emits a receipt on the egress-success
// path, so "drops-every-tunnel" produces none; a byte-identical epoch receipt cannot be
// used to prove a specific tunnel without reintroducing the forbidden per-tunnel field.
//
// DOMAIN SEPARATION. The onion key ALSO signs announces (packages/node/bootnode/announce.mjs). To make a
// receipt signature impossible to confuse with an announce (or directory) signature under
// that same key, the signed bytes are prefixed with a fixed, receipt-only domain string.
// A receipt signature therefore never validates as an announce, and vice versa.

import { onionToPubkey, ed25519Sign, ed25519Verify } from "./directory.mjs";

export const RECEIPT_VERSION = 1;

// A receipt-only domain tag prepended to the signed bytes. This is what stops cross-protocol
// signature confusion between a receipt and an announce/directory signature by the same onion
// key (both are bare versioned JSON without this prefix).
export const RECEIPT_DOMAIN = "Shade Tree egress success receipt v1\n";

// The bytes the ONION key signs: the domain tag || a fixed-field-order JSON payload, so the
// signature is independent of JSON whitespace or key ordering (same style as
// canonicalAnnounceBytes / canonicalDirectoryBytes). `epoch` is normalized to a decimal
// string so a BigInt epoch and its string form sign identically.
export function canonicalReceiptBytes({ v, onion, epoch, ok }) {
  const payload = { v, onion, epoch: String(epoch), ok: ok === true };
  return Buffer.concat([
    Buffer.from(RECEIPT_DOMAIN, "utf8"),
    Buffer.from(JSON.stringify(payload), "utf8"),
  ]);
}

// Build a signed success receipt. `onionSeedHex` is the 32-byte ed25519 seed behind the
// gateway's .onion (tor/hs/identity.local.json, same key that signs the announce). `epoch`
// is the coarse current epoch (BigInt|number|string); it is stored as a decimal string.
export function buildReceipt({ onion, epoch, onionSeedHex, ok = true }) {
  const rec = { v: RECEIPT_VERSION, onion, epoch: String(epoch), ok: ok === true };
  rec.sig = ed25519Sign(canonicalReceiptBytes(rec), onionSeedHex);
  return rec;
}

// Verify a receipt. Returns { ok, reason } and, on success, { onion, pubkey, epoch }.
// The pubkey is recovered from the receipt's OWN .onion address (self-authenticating, like
// the directory), so anyone holding the gateway's directory entry can verify it offline.
//
//   onion     : optional. If given, the receipt's onion MUST equal it — bind the receipt to
//               the specific gateway the client dialed (reject a receipt for another onion).
//   epoch     : optional current epoch (BigInt|number|string). If given, the receipt's epoch
//               must be within `epochSkew` of it, so a stale receipt is not counted as fresh
//               liveness evidence. Omit to skip the freshness check (verify signature only).
//   epochSkew : max |epoch - rec.epoch| accepted (default 1: this or the adjacent bucket).
export function verifyReceipt(rec, { onion = null, epoch = null, epochSkew = 1 } = {}) {
  if (!rec || typeof rec !== "object") return { ok: false, reason: "no-receipt" };
  if (rec.v !== RECEIPT_VERSION) return { ok: false, reason: `bad-version:${rec.v}` };
  if (rec.ok !== true) return { ok: false, reason: "not-success" };
  if (typeof rec.onion !== "string") return { ok: false, reason: "no-onion" };

  const stripOnion = (o) => String(o).replace(/\.onion$/, "").toLowerCase();
  if (onion && stripOnion(rec.onion) !== stripOnion(onion)) {
    return { ok: false, reason: "onion-mismatch" };
  }

  // Recover the ed25519 key from the (checksummed) v3 address; a malformed onion fails here.
  let pubkey;
  try {
    pubkey = onionToPubkey(rec.onion);
  } catch (e) {
    return { ok: false, reason: `bad-onion:${e.message}` };
  }

  // epoch must be a canonical non-negative decimal string (so String(BigInt) round-trips and
  // no float / hex / leading-zero ambiguity can slip into the signed bytes).
  if (typeof rec.epoch !== "string" || !/^(0|[1-9][0-9]*)$/.test(rec.epoch)) {
    return { ok: false, reason: "bad-epoch" };
  }
  if (epoch != null) {
    let recEp, curEp;
    try {
      recEp = BigInt(rec.epoch);
      curEp = BigInt(String(epoch));
    } catch {
      return { ok: false, reason: "bad-epoch" };
    }
    const diff = recEp > curEp ? recEp - curEp : curEp - recEp;
    if (diff > BigInt(epochSkew)) return { ok: false, reason: `stale-epoch:${rec.epoch}` };
  }

  // The signature must verify under the key the onion address commits to.
  const bytes = canonicalReceiptBytes({ v: rec.v, onion: rec.onion, epoch: rec.epoch, ok: rec.ok });
  if (!rec.sig || !ed25519Verify(bytes, rec.sig, pubkey)) {
    return { ok: false, reason: "bad-sig" };
  }
  return { ok: true, onion: rec.onion, pubkey, epoch: rec.epoch };
}
