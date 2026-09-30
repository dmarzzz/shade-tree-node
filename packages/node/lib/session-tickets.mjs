// Session tickets (session-v1, docs/design/SESSION-TICKETS.md, ADR 0011): the pure ticket-book
// cryptography shared by the node, the JS client and @shadenet/sdk, and reproduced byte for byte by
// `shadenet_proto::session` in Rust (testdata/vectors.json `sessionTickets`).
//
// One RLN proof, whose signal commits to ONE node, ONE policy class, a session nonce and the digest
// of a client-generated ticket book, buys a bounded book of single-use tickets at that node. Each
// ticket then opens one destination tunnel with a cheap envelope (no proof) inside the proof's
// epoch payload budget. Nothing here does I/O; the strings hashed below are frozen wire strings
// (test/wire-freeze.selftest.mjs) — a rename that touches them breaks proofs.
//
// Byte values are Uint8Array/Buffer (the `#crypto` shim decides), hex is lowercase.

import { utf8, sha256, toHex, fromHex, concatBytes } from "#crypto";

export const SESSION_VERSION = 1;
export const SESSION_SIGNAL_PREFIX = "shade-tree:session:v1\n";
export const TICKET_DOMAIN = "Shade Tree session ticket v1\n";
export const TICKET_BOOK_DOMAIN = "Shade Tree session ticket book v1\n";
export const TICKET_SPEND_DOMAIN = "Shade Tree session ticket spend v1\n";

// The class ids a node may advertise and a client may request. The values are operator-enforced
// and echoed after initialization; a client fails closed when the echo differs from this table.
export const SESSION_CLASSES = Object.freeze({
  "research-v1": Object.freeze({
    tickets: 6,
    maxPayloadBytes: 41_943_040,
    lifetimeMs: 90_000,
    idleTimeoutMs: 15_000,
    maxConcurrentStreams: 4,
    maxPendingConnects: 4,
    agentToDestinationBytesPerSecond: 64 * 1024,
    agentToDestinationBurstBytes: 128 * 1024,
    destinationToAgentBytesPerSecond: 512 * 1024,
    destinationToAgentBurstBytes: 1024 * 1024,
  }),
});
export const MAX_SESSION_CLASSES = 8;
export const MAX_TICKETS = 64;
export const TICKET_SECRET_BYTES = 32;

export const CLASS_ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const HEX32_RE = /^[0-9a-f]{32}$/;
const ONION_RE = /^[a-z2-7]{56}\.onion$/;
const B64URL_RE = /^[A-Za-z0-9_-]{43}$/;

export const isClassId = (s) => typeof s === "string" && CLASS_ID_RE.test(s);
export const isHex64 = (s) => typeof s === "string" && HEX64_RE.test(s);
export const isNonce32 = (s) => typeof s === "string" && HEX32_RE.test(s);
export const isSessionOnion = (s) => typeof s === "string" && ONION_RE.test(s);

function u16be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new Error("session-tickets: index out of u16 range");
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function bytes32(value, what) {
  const b = typeof value === "string" ? fromHex(value) : value;
  if (!b || b.length !== 32) throw new Error(`session-tickets: ${what} must be 32 bytes`);
  return b;
}

// ticketCommitment_i = SHA256("Shade Tree session ticket v1\n" || u16be(i) || secret_i)
export function ticketCommitment(index, secret) {
  return toHex(sha256(concatBytes([utf8(TICKET_DOMAIN), u16be(index), bytes32(secret, "ticket secret")])));
}

// ticketBookDigest = SHA256("Shade Tree session ticket book v1\n" || u16be(N) || c_0 || ... || c_(N-1))
// Each commitment contributes its raw 32 bytes, never its hex text.
export function ticketBookDigest(commitments) {
  if (!Array.isArray(commitments) || commitments.length === 0 || commitments.length > MAX_TICKETS) {
    throw new Error("session-tickets: a ticket book holds 1..64 commitments");
  }
  const parts = [utf8(TICKET_BOOK_DOMAIN), u16be(commitments.length)];
  for (const c of commitments) {
    if (!isHex64(c)) throw new Error("session-tickets: commitments are 64 lowercase hex characters");
    parts.push(fromHex(c));
  }
  return toHex(sha256(concatBytes(parts)));
}

// spendDigest = SHA256("Shade Tree session ticket spend v1\n" || bookDigest || u16be(i)
//                      || u16be(len(target)) || target || requestNonce)
// Node-local and ephemeral: it only tells an exact retry apart from a reuse for another target.
export function spendDigest({ ticketBookDigest: digest, index, target, requestNonce }) {
  if (!isHex64(digest)) throw new Error("session-tickets: ticketBookDigest must be 64 hex characters");
  if (!isNonce32(requestNonce)) throw new Error("session-tickets: requestNonce must be 32 hex characters");
  const t = utf8(String(target));
  if (t.length === 0 || t.length > 256) throw new Error("session-tickets: target must be 1..256 bytes");
  return toHex(sha256(concatBytes([utf8(TICKET_SPEND_DOMAIN), fromHex(digest), u16be(index), u16be(t.length), t, fromHex(requestNonce)])));
}

// The RLN signal of a session initialization. Every field has a strict grammar so the newline
// framing stays injective: onion (56 base32 + .onion), class id, 32-hex nonce, 64-hex digest.
export function sessionSignal({ gateway, classId, nonce, ticketBookDigest: digest }) {
  const onion = normalizeOnion(gateway);
  if (!isSessionOnion(onion)) throw new Error("session-tickets: gateway must be a v3 .onion");
  if (!isClassId(classId)) throw new Error("session-tickets: class id grammar is ^[a-z0-9][a-z0-9-]{0,31}$");
  if (!isNonce32(nonce)) throw new Error("session-tickets: session nonce must be 32 hex characters");
  if (!isHex64(digest)) throw new Error("session-tickets: ticketBookDigest must be 64 hex characters");
  return `${SESSION_SIGNAL_PREFIX}${onion}\n${classId}\n${nonce}\n${digest}`;
}

export function normalizeOnion(onion) {
  const s = String(onion ?? "").trim().toLowerCase();
  return s.endsWith(".onion") ? s : `${s}.onion`;
}

// A whole client-side ticket book from caller-supplied randomness (the caller draws `secrets`
// from its CSPRNG; the vectors pass fixed ones). Secrets stay raw bytes; only commitments leave.
export function buildTicketBook(secrets) {
  if (!Array.isArray(secrets) || secrets.length === 0) throw new Error("session-tickets: secrets required");
  const bytes = secrets.map((s, i) => bytes32(s, `secret[${i}]`));
  const commitments = bytes.map((s, i) => ticketCommitment(i, s));
  const seen = new Set(commitments);
  if (seen.size !== commitments.length) throw new Error("session-tickets: duplicate ticket secret");
  return { secrets: bytes, commitments, ticketBookDigest: ticketBookDigest(commitments) };
}

// --- base64url (unpadded) for the ticket secret on the wire -------------------------------
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
export function base64urlEncode(bytes) {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}
// Decodes exactly one 32-byte secret (43 unpadded chars, canonical trailing bits) or returns null.
export function decodeTicketSecret(s) {
  if (typeof s !== "string" || !B64URL_RE.test(s)) return null;
  const out = new Uint8Array(32);
  let acc = 0, bits = 0, o = 0;
  for (const ch of s) {
    acc = (acc << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // 43 chars = 258 bits: the last 2 bits must be zero for a canonical encoding.
  if (o !== 32 || (acc & ((1 << bits) - 1)) !== 0) return null;
  return out;
}

// --- envelope shapes ----------------------------------------------------------------------
// The session-initialization fields ride inside a v4 envelope in place of `target`/`nonce`:
//   { v: 4, session: { v, class, gateway, nonce, ticketCommitments, ticketBookDigest }, artifact, proof, ... }
// A ticket spend is a v4 envelope with no proof:
//   { v: 4, ticket: { v, book, i, t, n }, target }
export function sessionInitFields({ classId, gateway, nonce, commitments, ticketBookDigest: digest }) {
  return { v: SESSION_VERSION, class: classId, gateway: normalizeOnion(gateway), nonce, ticketCommitments: [...commitments], ticketBookDigest: digest };
}

export function ticketFields({ ticketBookDigest: digest, index, secret, requestNonce }) {
  return { v: SESSION_VERSION, book: digest, i: index, t: base64urlEncode(bytes32(secret, "ticket secret")), n: requestNonce };
}

// TOTAL validators: return { ok, reason } with bounded reasons (never peer bytes).
export function validateSessionInit(session, { classes = SESSION_CLASSES } = {}) {
  if (!session || typeof session !== "object" || Array.isArray(session)) return { ok: false, reason: "session-malformed" };
  if (session.v !== SESSION_VERSION) return { ok: false, reason: "session-version" };
  if (!isClassId(session.class)) return { ok: false, reason: "session-class" };
  const policy = classes[session.class];
  if (!policy) return { ok: false, reason: "session-class" };
  if (!isSessionOnion(session.gateway)) return { ok: false, reason: "session-gateway" };
  if (!isNonce32(session.nonce)) return { ok: false, reason: "session-nonce" };
  const list = session.ticketCommitments;
  if (!Array.isArray(list) || list.length !== policy.tickets) return { ok: false, reason: "session-ticket-count" };
  if (!list.every(isHex64) || new Set(list).size !== list.length) return { ok: false, reason: "session-commitment" };
  if (!isHex64(session.ticketBookDigest) || ticketBookDigest(list) !== session.ticketBookDigest) return { ok: false, reason: "session-digest" };
  return { ok: true, policy, classId: session.class };
}

export function validateTicket(ticket) {
  if (!ticket || typeof ticket !== "object" || Array.isArray(ticket)) return { ok: false, reason: "ticket-malformed" };
  if (ticket.v !== SESSION_VERSION) return { ok: false, reason: "ticket-version" };
  if (!isHex64(ticket.book)) return { ok: false, reason: "ticket-book" };
  if (!Number.isInteger(ticket.i) || ticket.i < 0 || ticket.i >= MAX_TICKETS) return { ok: false, reason: "ticket-index" };
  const secret = decodeTicketSecret(ticket.t);
  if (!secret) return { ok: false, reason: "ticket-secret" };
  if (!isNonce32(ticket.n)) return { ok: false, reason: "ticket-nonce" };
  return { ok: true, book: ticket.book, index: ticket.i, secret, requestNonce: ticket.n };
}

// The policy echo a node returns; a client compares it field by field with its own table.
export function policyEcho(classId, policy = SESSION_CLASSES[classId]) {
  return {
    class: classId,
    tickets: policy.tickets,
    maxPayloadBytes: policy.maxPayloadBytes,
    lifetimeMs: policy.lifetimeMs,
    idleTimeoutMs: policy.idleTimeoutMs,
    maxConcurrentStreams: policy.maxConcurrentStreams,
  };
}

export function policyMatches(echo, classId, classes = SESSION_CLASSES) {
  const mine = classes[classId];
  if (!mine || !echo || typeof echo !== "object") return false;
  const expected = policyEcho(classId, mine);
  return Object.keys(expected).every((k) => echo[k] === expected[k]);
}
