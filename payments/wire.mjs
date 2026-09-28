// The two HTTP-402 wire formats the registrar speaks and `shade-tree-node pay` consumes, implemented directly
// from the primary specs (fetched 2026-08-17; no SDK — see docs/PAYMENTS.md "Why no x402 SDK"):
//
//   x402 v2 (coinbase/x402 specs/x402-specification-v2.md + specs/transports-v2/http.md +
//            specs/schemes/exact/scheme_exact_evm.md):
//     402 + `PAYMENT-REQUIRED: base64(JSON PaymentRequired)`  { x402Version:2, resource, accepts[] }
//     req  `PAYMENT-SIGNATURE: base64(JSON PaymentPayload)`  { x402Version:2, accepted, payload:{signature, authorization} }
//     resp `PAYMENT-RESPONSE:  base64(JSON SettlementResponse)` { success, transaction, network, payer[, errorReason] }
//     scheme "exact", network CAIP-2 "eip155:<chainId>", assetTransferMethod eip3009 (EIP-3009
//     TransferWithAuthorization typed data, domain {name,version} advertised in `extra`).
//     (x402 v1 used X-PAYMENT / X-PAYMENT-RESPONSE and x402Version:1; NOT served here — v2 only.)
//
//   MPP (Machine Payments Protocol, tempoxyz/mpp-specs: core draft-httpauth-payment-00, intent
//        draft-payment-intent-charge-00, method draft-evm-charge-00):
//     402 + `WWW-Authenticate: Payment id=".." realm=".." method="evm" intent="charge"
//            request="<b64url JCS JSON>" expires="<RFC3339>" opaque="<b64url JCS JSON>" [digest=".."]`
//     req  `Authorization: Payment <base64url-nopad JSON { challenge, payload, source? }>`
//          payload type="authorization" (EIP-3009; nonce == keccak256(abi.encodePacked(id, realm)))
//     resp `Payment-Receipt: <base64url-nopad JSON { status:"success", method:"evm", challengeId,
//            reference:<txhash>, timestamp, chainId }>`, errors = 402 + fresh challenge + RFC 9457 body.
//     Challenge `id` = base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|digest|opaque))
//     exactly as the core draft's "Recommended: HMAC-SHA256 Binding" (7 fixed slots).
//
// Pure functions over strings/objects: no I/O, no env, no chain. Everything a hostile client can
// send passes through a parse* function here that returns { ok:false, reason } instead of throwing.

import { createHmac, createHash, randomBytes } from "node:crypto";
import { ethers } from "ethers";
import { checkAuthorizationShape, isUintString, sameAddress } from "./eip3009.mjs";

// ---- encoding helpers ---------------------------------------------------------
export const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
export const b64url = (s) => Buffer.from(s, "utf8").toString("base64url"); // node: unpadded
export function b64decode(s, { url = false, max = 16 * 1024 } = {}) {
  if (typeof s !== "string" || s.length === 0 || s.length > max) return null;
  if (url ? !/^[A-Za-z0-9_-]+$/.test(s) : !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try { return Buffer.from(s, url ? "base64url" : "base64").toString("utf8"); } catch { return null; }
}
export function jsonParseSafe(s) {
  try { const v = JSON.parse(s); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
}
// JSON Canonicalization Scheme (RFC 8785) for the value shapes MPP requests carry: objects with
// sorted keys, arrays in order, strings, integers, booleans, null. (No floats are ever emitted here.)
export function jcs(v) {
  if (v === null || typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isFinite(v) || !Number.isInteger(v)) throw new Error("jcs: only integers"); return String(v); }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  throw new Error("jcs: unsupported type " + typeof v);
}
export const caip2 = (chainId) => `eip155:${Number(chainId)}`;
export function chainIdOfCaip2(network) {
  const m = typeof network === "string" ? /^eip155:([1-9][0-9]{0,15})$/.exec(network) : null;
  return m ? Number(m[1]) : null;
}
export const rfc3339 = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
// RFC 9530 Content-Digest for a request body: sha-256=:<base64>:
export const contentDigest = (bodyBytes) => `sha-256=:${createHash("sha256").update(bodyBytes).digest("base64")}:`;

// ---- offer: the operator's price list, one shape both rails are rendered from ---------------
// { chainId, asset, assetName, assetVersion, decimals, payTo, tiers: {"8":"100000",...},
//   maxTimeoutSeconds, realm, resourceUrl, description }
export function parsePrices(spec) {
  // "8=100000,32=400000" -> { "8": "100000", "32": "400000" } (limits 1..65535, prices uint strings > 0)
  const out = {};
  for (const part of String(spec || "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^([1-9][0-9]{0,4})=([1-9][0-9]*)$/.exec(part);
    if (!m || Number(m[1]) > 65535) throw new Error(`SHADE_TREE_PAY_PRICES: bad entry "${part}" (want <limit>=<atomic-amount>, e.g. 8=100000)`);
    if (out[m[1]]) throw new Error(`SHADE_TREE_PAY_PRICES: duplicate tier ${m[1]}`);
    out[m[1]] = m[2];
  }
  if (!Object.keys(out).length) throw new Error("SHADE_TREE_PAY_PRICES: empty (e.g. 8=100000,32=400000)");
  return out;
}
export function tierForAmount(offer, amount) {
  for (const [limit, price] of Object.entries(offer.tiers)) if (price === amount) return Number(limit);
  return null;
}
export const priceOf = (offer, limit) => offer.tiers[String(Number(limit))] || null;
export const tierList = (offer) => Object.keys(offer.tiers).map(Number).sort((a, b) => a - b);

// ---- x402 v2 -------------------------------------------------------------------
export function x402Requirements(offer, limit) {
  return {
    scheme: "exact",
    network: caip2(offer.chainId),
    amount: priceOf(offer, limit),
    asset: offer.asset,
    payTo: offer.payTo,
    maxTimeoutSeconds: offer.maxTimeoutSeconds,
    extra: { name: offer.assetName, version: offer.assetVersion, assetTransferMethod: "eip3009", limit: Number(limit) },
  };
}
// The PaymentRequired object (header value = base64 of its JSON). limits = the tiers to offer.
export function x402PaymentRequired(offer, limits, { error = null } = {}) {
  const pr = {
    x402Version: 2,
    ...(error ? { error } : {}),
    resource: { url: offer.resourceUrl, description: offer.description, mimeType: "application/json" },
    accepts: limits.map((l) => x402Requirements(offer, l)),
  };
  return pr;
}
export const encodeX402Header = (obj) => b64(JSON.stringify(obj));
export const decodeX402Header = (h) => { const s = b64decode(h); return s == null ? null : jsonParseSafe(s); };

// Client side: build the PaymentPayload for the requirements entry it picked.
export function x402PaymentPayload(paymentRequired, accepted, authorization, signature) {
  return { x402Version: 2, resource: paymentRequired.resource, accepted, payload: { signature, authorization } };
}
// Server side: parse + shape-check a PAYMENT-SIGNATURE header against the offer. Returns
// { ok, reason, limit, accepted, authorization, signature } — signature/chain checks are the caller's.
export function parseX402Payment(header, offer) {
  const bad = (reason) => ({ ok: false, reason });
  const p = decodeX402Header(header);
  if (!p) return bad("invalid_payment_payload");
  if (p.x402Version !== 2) return bad("invalid_x402_version");
  const a = p.accepted;
  if (!a || typeof a !== "object") return bad("invalid_payment_requirements");
  if (a.scheme !== "exact") return bad("invalid_scheme");
  if (chainIdOfCaip2(a.network) !== Number(offer.chainId)) return bad("invalid_network");
  if (!sameAddress(a.asset, offer.asset)) return bad("invalid_exact_evm_payload_asset");
  if (!sameAddress(a.payTo, offer.payTo)) return bad("invalid_exact_evm_payload_recipient_mismatch");
  if (!isUintString(a.amount)) return bad("invalid_payment_requirements");
  const limit = tierForAmount(offer, a.amount);
  if (limit == null) return bad("invalid_exact_evm_payload_authorization_value_mismatch");
  const pl = p.payload;
  if (!pl || typeof pl !== "object") return bad("invalid_payment_payload");
  const shapeErr = checkAuthorizationShape(pl.authorization);
  if (shapeErr) return bad("invalid_exact_evm_payload_authorization");
  if (typeof pl.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(pl.signature)) return bad("invalid_exact_evm_payload_signature");
  const auth = pl.authorization;
  if (!sameAddress(auth.to, offer.payTo)) return bad("invalid_exact_evm_payload_recipient_mismatch");
  if (auth.value !== a.amount) return bad("invalid_exact_evm_payload_authorization_value_mismatch");
  return { ok: true, limit, accepted: a, authorization: auth, signature: pl.signature, resource: p.resource };
}
export function x402Settlement({ success, transaction = "", network, payer, errorReason }) {
  return { success, ...(errorReason ? { errorReason } : {}), transaction, network, ...(payer ? { payer } : {}) };
}

// ---- MPP -----------------------------------------------------------------------
export const MPP_METHOD = "evm";
export const MPP_INTENT = "charge";
export const PERMIT2_CANONICAL = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
export const MPP_PROBLEM_BASE = "https://paymentauth.org/problems/";

// The `request` object for one tier (draft-evm-charge-00 §"Request Schema" + charge intent).
export function mppRequest(offer, limit) {
  return {
    amount: priceOf(offer, limit),
    currency: offer.asset,
    recipient: offer.payTo,
    description: `${offer.description} (tier ${Number(limit)})`,
    externalId: `limit=${Number(limit)}`,
    methodDetails: {
      chainId: Number(offer.chainId),
      permit2Address: PERMIT2_CANONICAL, // REQUIRED by the method table; we accept "authorization" only
      credentialTypes: ["authorization"],
      decimals: Number(offer.decimals),
      // EXTENSION (not in draft-evm-charge-00): the token's EIP-712 domain, which type=authorization
      // signers need and the method has no field for. Also echoed in the 402 body's `pay` block.
      eip712Domain: { name: offer.assetName, version: offer.assetVersion },
    },
  };
}
// The seven-slot HMAC binding from the core draft (positional; absent optionals are "").
export function mppChallengeId(secret, { realm, method, intent, request, expires = "", digest = "", opaque = "" }) {
  const input = [realm, method, intent, request, expires || "", digest || "", opaque || ""].join("|");
  return createHmac("sha256", secret).update(input, "utf8").digest("base64url");
}
// nonce = keccak256(abi.encodePacked(challenge.id, challenge.realm)) — both are strings, so
// encodePacked is their UTF-8 bytes concatenated (draft-evm-charge-00 §"Authorization Payload").
export function mppNonce(id, realm) {
  return ethers.keccak256(ethers.concat([ethers.toUtf8Bytes(String(id)), ethers.toUtf8Bytes(String(realm))]));
}
// Build one challenge for a tier. `digest` binds a request body (POST /pay) when the challenge
// answers a bodied request; `nowMs` injectable for tests. Returns { params, header } where params
// is the parsed form (what verify recomputes over) and header the WWW-Authenticate value.
export function mppChallenge(offer, limit, secret, { digest = "", nowMs = Date.now() } = {}) {
  const request = b64url(jcs(mppRequest(offer, limit)));
  const expires = rfc3339(nowMs + offer.maxTimeoutSeconds * 1000);
  // opaque: flat string map, echoed back; the random nonce keeps every issued challenge unique
  // (so two quotes in the same second bind to different EIP-3009 nonces).
  const opaque = b64url(jcs({ limit: String(Number(limit)), nonce: randomBytes(12).toString("hex") }));
  const params = { realm: offer.realm, method: MPP_METHOD, intent: MPP_INTENT, request, expires, opaque, ...(digest ? { digest } : {}) };
  const id = mppChallengeId(secret, params);
  const full = { id, ...params, description: `${offer.description} (tier ${Number(limit)})` };
  return { params: full, header: formatWwwAuthenticate(full) };
}
// auth-param serialization: token BWS "=" BWS quoted-string. Every value is quoted (RFC 9110
// permits quoting tokens); quote and backslash are escaped.
export function formatWwwAuthenticate(params) {
  const order = ["id", "realm", "method", "intent", "request", "expires", "digest", "opaque", "description"];
  const q = (v) => `"${String(v).replace(/[\\"]/g, (c) => "\\" + c)}"`;
  return "Payment " + order.filter((k) => params[k] !== undefined && params[k] !== "").map((k) => `${k}=${q(params[k])}`).join(", ");
}
// Parse ONE `WWW-Authenticate` header value into [{ scheme, params }] (a header MAY carry several
// comma-separated challenges; RFC 9110 §11.6.1). Only `Payment` challenges are returned. Tolerant
// of quoted-string escapes and bare tokens; never throws.
export function parseWwwAuthenticate(value) {
  const out = [];
  if (typeof value !== "string" || value.length > 64 * 1024) return out;
  let i = 0; const s = value; const n = s.length;
  const ws = () => { while (i < n && /[ \t]/.test(s[i])) i++; };
  const token = () => { const st = i; while (i < n && /[!#$%&'*+\-.^_`|~0-9A-Za-z]/.test(s[i])) i++; return s.slice(st, i); };
  let cur = null;
  while (i < n) {
    ws();
    if (s[i] === ",") { i++; continue; }
    const t = token();
    if (!t) { i++; continue; } // skip junk
    ws();
    if (s[i] === "=") {
      // auth-param inside the current challenge
      i++; ws();
      let v;
      if (s[i] === '"') {
        i++; v = "";
        while (i < n && s[i] !== '"') { if (s[i] === "\\" && i + 1 < n) { v += s[i + 1]; i += 2; } else v += s[i++]; }
        i++; // closing quote
      } else v = token();
      if (cur) cur.params[t.toLowerCase()] = v;
      continue;
    }
    // a new scheme
    cur = { scheme: t, params: {} };
    if (t.toLowerCase() === "payment") out.push(cur); else cur = { scheme: t, params: {} }; // non-Payment: parse-and-drop
  }
  return out;
}
// Client side: the credential the buyer sends.
export function mppCredential(challengeParams, payload, { source = null } = {}) {
  const echo = {};
  for (const k of ["id", "realm", "method", "intent", "request", "description", "opaque", "digest", "expires"]) if (challengeParams[k] !== undefined) echo[k] = challengeParams[k];
  const cred = { challenge: echo, payload, ...(source ? { source } : {}) };
  return b64url(JSON.stringify(cred));
}
// Server side: parse + verify a credential against the HMAC secret / offer / (optional) body digest.
// Returns { ok, reason(problem code), detail, limit, challenge, authorization, signature } —
// the EIP-3009 signature/chain checks are the caller's (same helpers as x402).
export function parseMppCredential(authorizationHeader, secret, offer, { bodyDigest = null, nowMs = Date.now() } = {}) {
  const bad = (reason, detail) => ({ ok: false, reason, detail });
  if (typeof authorizationHeader !== "string") return bad("malformed-credential", "missing Authorization");
  const m = /^Payment[ \t]+([A-Za-z0-9_-]+)$/.exec(authorizationHeader.trim());
  if (!m) return bad("malformed-credential", "Authorization must be `Payment <base64url>`");
  const json = b64decode(m[1], { url: true });
  const cred = json == null ? null : jsonParseSafe(json);
  if (!cred) return bad("malformed-credential", "credential is not base64url JSON");
  const ch = cred.challenge;
  if (!ch || typeof ch !== "object") return bad("malformed-credential", "credential.challenge missing");
  for (const k of ["id", "realm", "method", "intent", "request"]) if (typeof ch[k] !== "string" || !ch[k]) return bad("malformed-credential", `challenge.${k} missing`);
  if (ch.method !== MPP_METHOD || ch.intent !== MPP_INTENT) return bad("method-unsupported", `only ${MPP_METHOD}/${MPP_INTENT}`);
  if (ch.realm !== offer.realm) return bad("invalid-challenge", "realm mismatch");
  // Recompute the binding over the echoed params: any tampering (amount, recipient, expiry, digest…)
  // changes the HMAC and the id no longer matches.
  const want = mppChallengeId(secret, { realm: ch.realm, method: ch.method, intent: ch.intent, request: ch.request, expires: ch.expires || "", digest: ch.digest || "", opaque: ch.opaque || "" });
  if (want !== ch.id) return bad("invalid-challenge", "challenge id does not verify");
  if (!ch.expires || !Number.isFinite(Date.parse(ch.expires))) return bad("invalid-challenge", "expires missing");
  if (Date.parse(ch.expires) <= nowMs) return bad("payment-expired", "challenge expired");
  if (ch.digest) {
    if (!bodyDigest || ch.digest !== bodyDigest) return bad("invalid-challenge", "request body digest does not match the challenge");
  }
  const reqJson = b64decode(ch.request, { url: true });
  const req = reqJson == null ? null : jsonParseSafe(reqJson);
  if (!req) return bad("invalid-challenge", "request is not base64url JSON");
  // The request was ours (HMAC verified) — still cross-check it against the CURRENT offer, so a
  // price change or a payTo rotation retires outstanding challenges.
  const limit = tierForAmount(offer, req.amount);
  if (limit == null || !sameAddress(req.currency, offer.asset) || !sameAddress(req.recipient, offer.payTo)) return bad("invalid-challenge", "challenge no longer matches the current offer");
  const pl = cred.payload;
  if (!pl || typeof pl !== "object") return bad("malformed-credential", "payload missing");
  if (pl.type !== "authorization") return bad("verification-failed", `unsupported payload type ${JSON.stringify(pl.type)} (this registrar accepts type=authorization only)`);
  const auth = { from: pl.from, to: pl.to, value: pl.value, validAfter: pl.validAfter, validBefore: pl.validBefore, nonce: pl.nonce };
  const shapeErr = checkAuthorizationShape(auth);
  if (shapeErr) return bad("malformed-credential", shapeErr);
  if (typeof pl.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(pl.signature)) return bad("malformed-credential", "signature must be 65 bytes hex");
  if (!sameAddress(auth.to, req.recipient)) return bad("verification-failed", "to != challenge recipient");
  if (auth.value !== req.amount) return bad("verification-failed", "value != challenge amount");
  if (auth.nonce.toLowerCase() !== mppNonce(ch.id, ch.realm)) return bad("verification-failed", "nonce != keccak256(id ‖ realm)");
  return { ok: true, limit, challenge: ch, request: req, authorization: auth, signature: pl.signature, source: typeof cred.source === "string" ? cred.source : null };
}
export function mppReceipt({ challengeId, txHash, chainId, nowMs = Date.now() }) {
  const r = { status: "success", method: MPP_METHOD, challengeId, reference: txHash, timestamp: rfc3339(nowMs), chainId: Number(chainId) };
  return { receipt: r, header: b64url(JSON.stringify(r)) };
}
export const decodeMppReceipt = (h) => { const s = b64decode(h, { url: true }); return s == null ? null : jsonParseSafe(s); };
export function mppProblem(code, detail, status = 402) {
  const titles = { "payment-required": "Payment Required", "payment-insufficient": "Payment Insufficient", "payment-expired": "Payment Expired", "verification-failed": "Verification Failed", "method-unsupported": "Method Unsupported", "malformed-credential": "Malformed Credential", "invalid-challenge": "Invalid Challenge" };
  return { type: MPP_PROBLEM_BASE + code, title: titles[code] || code, status, detail };
}
