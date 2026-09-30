// The announce protocol: how a gateway tells the bootnode "I am live at this onion",
// and how the bootnode and clients verify that claim. This module is SHARED — the
// gateway builds an announce with buildAnnounce(); the bootnode and any zero-trust
// client verify one with verifyAnnounce(). No new dependency for the hard guarantee
// (onion control is node-crypto ed25519); ethers is used lazily only for the optional
// operator-stake signature.
//
// Two independent proofs ride in one announce:
//
//   1. ONION CONTROL (always required, cryptographic, client-verifiable). The announce
//      is ed25519-signed by the onion's OWN identity key. A v3 .onion address IS that
//      key (packages/node/lib/directory.mjs onionToPubkey), so nobody can announce an onion they do
//      not hold the key for. This is the guarantee the whole directory rests on and it
//      never trusts the bootnode. The signature covers a fresh {ts, nonce} so a captured
//      announce cannot be replayed past a short window.
//
//   2. OPERATOR STAKE (optional, `admission=stake`). A DURABLE authorization signed once
//      by the operator's Ethereum key binding operator<->onion:
//         operatorSig = personal_sign("Shade Tree gateway operator authorization\n
//                                      onion=<onion>\noperator=<operator>")
//      The bootnode/clients recover the signer, confirm it equals `operator`, and check
//      GatewayRegistry.isStaked(operator) on chain (packages/node/lib/gateway-registry.mjs). The
//      operator signs ONCE (a long-lived credential the gateway reuses every heartbeat);
//      only the cheap onion signature is refreshed per announce. Revocation is simply
//      unstaking — isStaked flips to false and the entry drops on the next refresh.
//
// The onion is NEVER on chain. Only the operator ADDRESS stakes (contracts/GatewayRegistry.sol),
// and the onion<->operator link lives only here, in the signed announce the bootnode serves.
// So the fleet is not enumerable on chain and one stake can rotate across many onions.

import { randomBytes } from "node:crypto";
import { onionToPubkey, ed25519Sign, verifyOnionControl, canonicalCaps, hasCaps, signCaps, verifyCapsSig } from "../lib/directory.mjs";

export const ANNOUNCE_VERSION = 1;
export const DEFAULT_ANNOUNCE_SKEW = 120; // seconds a {ts} may lead/lag the verifier's clock

// The bytes the ONION key signs: fixed field order, independent of JSON whitespace.
// T-FEAT-10: capabilities are an OPTIONAL signed field. They are included ONLY when present
// (canonicalCaps + hasCaps), APPENDED after {v,onion,weight,ts,nonce}, so an announce WITHOUT
// caps serializes byte-IDENTICALLY to before — the golden canonicalAnnounceBytes vector is
// unchanged. When present, caps are covered by the main onion signature (bound to ts/nonce),
// so they cannot be forged or altered without the onion key.
export function canonicalAnnounceBytes({ v, onion, weight, ts, nonce, caps }) {
  const payload = { v, onion, weight, ts, nonce };
  if (hasCaps(caps)) payload.caps = canonicalCaps(caps);
  return Buffer.from(JSON.stringify(payload), "utf8");
}

// The human-readable message the OPERATOR key signs (personal_sign). Durable: no ts, so
// one signature authorizes this onion for as long as the operator stays staked.
export function operatorAuthMessage(onion, operator) {
  return `Shade Tree gateway operator authorization\nonion=${onion}\noperator=${String(operator).toLowerCase()}`;
}

// Build a signed announce. `onionSeedHex` is the 32-byte ed25519 seed behind the onion
// (packages/node/bootnode/keygen.mjs writes it). `operator`/`operatorSig` are optional (stake mode).
export function buildAnnounce({ onion, weight = 100, onionSeedHex, operator = null, operatorSig = null, ts, nonce, caps = null }) {
  const rec = {
    v: ANNOUNCE_VERSION,
    onion,
    weight,
    ts: ts ?? Math.floor(Date.now() / 1000),
    nonce: nonce ?? cryptoNonce(),
  };
  // T-FEAT-10: attach normalized capabilities + a standalone durable capsSig BEFORE signing,
  // so the main onionSig covers the caps (canonicalAnnounceBytes includes them when present)
  // and the capsSig can be copied onto the directory entry for zero-trust re-verification.
  // Omitted entirely when caps are absent/empty -> byte-identical to a legacy announce.
  if (hasCaps(caps)) {
    rec.caps = canonicalCaps(caps);
    rec.capsSig = signCaps(onion, rec.caps, onionSeedHex);
  }
  rec.onionSig = ed25519Sign(canonicalAnnounceBytes(rec), onionSeedHex);
  if (operator && operatorSig) {
    rec.operator = String(operator).toLowerCase();
    rec.operatorSig = operatorSig;
  }
  return rec;
}

function cryptoNonce() {
  // 16 random bytes hex; unique enough for replay defense across the announce window.
  return randomBytes(16).toString("hex");
}

// Verify one announce. Returns { ok, reason, onion, pubkey, operator, staked }.
//   now         : verifier clock (seconds); injectable for tests.
//   skew        : max |ts - now| accepted.
//   isStaked    : async (operatorAddr) => bool. If provided AND requireStake, the operator
//                 signature + live stake are enforced. If omitted, stake is not checked
//                 (operator/staked are still reported when a valid operatorSig is present).
//   requireStake: reject an announce with no live, authorized stake (admission = "stake").
//   seenNonce   : optional Set-like { has, add } for replay defense across a window.
export async function verifyAnnounce(rec, { now = Math.floor(Date.now() / 1000), skew = DEFAULT_ANNOUNCE_SKEW, isStaked = null, requireStake = false, seenNonce = null } = {}) {
  if (!rec || typeof rec !== "object") return { ok: false, reason: "no-announce" };
  if (rec.v !== ANNOUNCE_VERSION) return { ok: false, reason: `bad-version:${rec.v}` };
  if (typeof rec.onion !== "string") return { ok: false, reason: "no-onion" };

  // onion must be a well-formed v3 address whose key we can recover.
  let pubkey;
  try {
    pubkey = onionToPubkey(rec.onion);
  } catch (e) {
    return { ok: false, reason: `bad-onion:${e.message}` };
  }

  // freshness: reject a stale or future-dated announce (replay window).
  if (typeof rec.ts !== "number" || Math.abs(now - rec.ts) > skew) {
    return { ok: false, reason: `stale-ts:${rec.ts}` };
  }
  if (seenNonce) {
    const key = `${rec.onion}:${rec.nonce}`;
    if (seenNonce.has(key)) return { ok: false, reason: "replayed-nonce" };
  }

  // proof 1: onion control (cryptographic, never trusts the bootnode).
  if (!rec.onionSig || !verifyOnionControl(rec.onion, canonicalAnnounceBytes(rec), rec.onionSig)) {
    return { ok: false, reason: "bad-onion-sig" };
  }

  // T-FEAT-10: carry capabilities through, verified. If caps are present they are already
  // covered by the onionSig above (they are in canonicalAnnounceBytes), so getting here proves
  // authenticity; we normalize to the canonical signed view so any unsigned junk key a hostile
  // relay appended is dropped (ignored safely, never fatal). A standalone capsSig, when present,
  // must ALSO verify against the onion key (it is what a directory entry re-checks). Malformed
  // caps normalize to empty -> reported as null (no caps), never an exception.
  let caps = null;
  if (rec.caps !== undefined && rec.caps !== null) {
    if (rec.capsSig !== undefined && !verifyCapsSig(rec.onion, rec.caps, rec.capsSig)) {
      return { ok: false, reason: "bad-caps-sig" };
    }
    const c = canonicalCaps(rec.caps);
    caps = hasCaps(c) ? c : null;
  }

  // proof 2: operator stake (optional unless requireStake).
  let operator = null, staked = false;
  if (rec.operator && rec.operatorSig) {
    const okAuth = await verifyOperatorSig(rec.onion, rec.operator, rec.operatorSig);
    if (!okAuth) return { ok: false, reason: "bad-operator-sig" };
    operator = String(rec.operator).toLowerCase();
    if (isStaked) {
      try {
        staked = await isStaked(operator);
      } catch (e) {
        // A chain read failure must not silently pass an unstaked gateway in stake mode.
        if (requireStake) return { ok: false, reason: `stake-check-failed:${e.message}` };
      }
    }
  }
  if (requireStake && !staked) return { ok: false, reason: "not-staked" };

  if (seenNonce) seenNonce.add(`${rec.onion}:${rec.nonce}`);
  return { ok: true, onion: rec.onion, pubkey, operator, staked, caps };
}

// Recover the operator address from a personal_sign over operatorAuthMessage and confirm
// it equals the claimed operator. ethers is imported lazily so the onion-only path (and
// the offline selftest) never require it.
export async function verifyOperatorSig(onion, operator, operatorSig) {
  let ethers;
  try {
    ({ ethers } = await import("ethers"));
  } catch {
    // Without ethers we cannot verify an ECDSA sig; treat as unverifiable => not authorized.
    return false;
  }
  try {
    const recovered = ethers.verifyMessage(operatorAuthMessage(onion, operator), operatorSig);
    return recovered.toLowerCase() === String(operator).toLowerCase();
  } catch {
    return false;
  }
}
