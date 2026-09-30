// Session-ticket books on the node (session-v1, ADR 0011, docs/design/SESSION-TICKETS.md §13-17).
//
// A book is created by one verified session-initialization proof and lives for the class's hard
// lifetime. Every child tunnel spends one ticket; the transitions UNUSED -> RESERVED -> SPENT (and
// RESERVED -> UNUSED only on a definite pre-connect failure) happen SYNCHRONOUSLY, before any DNS or
// TCP work, which is the JavaScript atomicity boundary: two simultaneous spends of one ticket can
// never both reach an upstream connect. All streams of a book share its concurrency, pending-connect,
// lifetime and idle limits and two directional token buckets; the byte ceiling is the proof's
// existing per-slot payload budget (gateway.mjs makePayloadBudget), so a session can never relay
// more than the one RLN slot it was bought with.
//
// Ticket, target, session, nullifier and spend identifiers are never log or metric labels; the
// bounded reasons below are the only strings that leave this module.

import { SESSION_CLASSES, spendDigest as computeSpendDigest, ticketCommitment } from "../lib/session-tickets.mjs";
import { bytesEqual, fromHex } from "#crypto";

export const SESSION_REASONS = Object.freeze([
  "session-unsupported", "session-malformed", "session-version", "session-class", "session-gateway", "session-nonce",
  "session-ticket-count", "session-commitment", "session-digest", "session-wrong-gateway", "session-conflict",
  "session-capacity", "session-unknown", "session-expired", "session-idle", "session-streams", "session-pending",
  "ticket-malformed", "ticket-version", "ticket-book", "ticket-index", "ticket-secret", "ticket-nonce",
  "ticket-mismatch", "ticket-spent", "ticket-conflict", "ticket-inflight",
]);

// A shared token bucket per direction per session: `take(n)` returns the delay in ms before `n`
// bytes may pass. Opening six streams therefore never multiplies the advertised rate.
export function makeTokenBucket({ bytesPerSecond, burstBytes, now = () => Date.now() }) {
  let tokens = burstBytes;
  let at = now();
  return {
    take(n) {
      const t = now();
      tokens = Math.min(burstBytes, tokens + ((t - at) * bytesPerSecond) / 1000);
      at = t;
      tokens -= n;
      if (tokens >= 0) return 0;
      return Math.ceil((-tokens * 1000) / bytesPerSecond);
    },
  };
}

export function makeSessionBooks({
  classes = SESSION_CLASSES,
  maxSessions = 256,
  now = () => Date.now(),
  setTimer = (fn, ms) => { const t = setTimeout(fn, ms); t.unref?.(); return t; },
  clearTimer = clearTimeout,
} = {}) {
  const books = new Map();      // ticketBookDigest -> book
  const byNullifier = new Map(); // "epoch\0nullifier" -> ticketBookDigest (one book per proof slot)
  const slotKey = (nullifier, epoch) => `${String(epoch)}\0${String(nullifier)}`;

  function close(book, reason) {
    if (book.closed) return;
    book.closed = true;
    book.closeReason = reason;
    clearTimer(book.lifetimeTimer);
    clearTimer(book.idleTimer);
    books.delete(book.digest);
    if (byNullifier.get(book.slot) === book.digest) byNullifier.delete(book.slot);
    for (const socket of book.sockets) { try { socket.destroy(); } catch { /* already gone */ } }
    book.sockets.clear();
    book.onClose?.(reason);
  }

  function armIdle(book) {
    clearTimer(book.idleTimer);
    book.idleTimer = setTimer(() => {
      const idleFor = now() - book.lastPayloadAt;
      if (idleFor >= book.policy.idleTimeoutMs) close(book, "session-idle");
      else armIdle(book);
    }, Math.max(1, book.policy.idleTimeoutMs - (now() - book.lastPayloadAt)));
  }

  // Open a book for a verified initialization. An exact replay of a live book (same digest for
  // the same proof slot) is idempotent; a different digest for the same slot is a conflict (the
  // spent set has already seen the second share and taken its own action).
  function open({ digest, commitments, classId, policy = classes[classId], nullifier, epoch, onClose = null }) {
    if (!policy) return { ok: false, reason: "session-class" };
    const slot = slotKey(nullifier, epoch);
    const existing = byNullifier.get(slot);
    if (existing !== undefined) {
      if (existing === digest && books.has(digest)) return { ok: true, book: books.get(digest), replay: true };
      return { ok: false, reason: "session-conflict" };
    }
    if (books.has(digest)) return { ok: false, reason: "session-conflict" };
    if (books.size >= maxSessions) return { ok: false, reason: "session-capacity" };
    const t = now();
    const book = {
      digest, classId, policy, nullifier: String(nullifier), epoch: String(epoch), slot,
      commitments: commitments.map((c) => fromHex(c)),
      tickets: commitments.map(() => ({ state: "unused", spendDigest: null, streamId: null })),
      createdAt: t, expiresAt: t + policy.lifetimeMs, lastPayloadAt: t,
      openStreams: 0, pendingConnects: 0, sockets: new Set(), closed: false, closeReason: null, onClose,
      up: makeTokenBucket({ bytesPerSecond: policy.agentToDestinationBytesPerSecond, burstBytes: policy.agentToDestinationBurstBytes, now }),
      down: makeTokenBucket({ bytesPerSecond: policy.destinationToAgentBytesPerSecond, burstBytes: policy.destinationToAgentBurstBytes, now }),
      lifetimeTimer: null, idleTimer: null,
    };
    book.lifetimeTimer = setTimer(() => close(book, "session-expired"), policy.lifetimeMs);
    armIdle(book);
    books.set(digest, book);
    byNullifier.set(slot, digest);
    return { ok: true, book, replay: false };
  }

  // SYNCHRONOUS: verify the ticket against its commitment and move it UNUSED -> RESERVED, taking
  // one stream and one pending-connect slot. Nothing here awaits.
  function reserve({ digest, index, secret, target, requestNonce, streamId }) {
    const book = books.get(digest);
    if (!book || book.closed) return { ok: false, reason: "session-unknown" };
    if (now() >= book.expiresAt) { close(book, "session-expired"); return { ok: false, reason: "session-expired" }; }
    if (index >= book.tickets.length) return { ok: false, reason: "ticket-index" };
    const expected = book.commitments[index];
    if (!bytesEqual(fromHex(ticketCommitment(index, secret)), expected)) return { ok: false, reason: "ticket-mismatch" };
    const sd = computeSpendDigest({ ticketBookDigest: digest, index, target, requestNonce });
    const ticket = book.tickets[index];
    if (ticket.state === "spent") return { ok: false, reason: "ticket-spent" };
    if (ticket.state === "reserved") {
      return { ok: false, reason: ticket.spendDigest === sd ? "ticket-inflight" : "ticket-conflict" };
    }
    if (book.openStreams >= book.policy.maxConcurrentStreams) return { ok: false, reason: "session-streams" };
    if (book.pendingConnects >= book.policy.maxPendingConnects) return { ok: false, reason: "session-pending" };
    ticket.state = "reserved";
    ticket.spendDigest = sd;
    ticket.streamId = streamId;
    book.openStreams += 1;
    book.pendingConnects += 1;
    return { ok: true, book, ticket };
  }

  // A definite pre-connect failure: the reservation returns to UNUSED for an exact retry. Only
  // the stream that holds the reservation may release it.
  function release(book, ticket, streamId) {
    if (ticket.state !== "reserved" || ticket.streamId !== streamId) return false;
    ticket.state = "unused";
    ticket.spendDigest = null;
    ticket.streamId = null;
    book.pendingConnects = Math.max(0, book.pendingConnects - 1);
    book.openStreams = Math.max(0, book.openStreams - 1);
    return true;
  }

  // The commit point: inside the successful upstream connect, before the success ack.
  function spend(book, ticket, streamId, socket) {
    if (ticket.state !== "reserved" || ticket.streamId !== streamId) return false;
    ticket.state = "spent";
    book.pendingConnects = Math.max(0, book.pendingConnects - 1);
    if (socket) book.sockets.add(socket);
    return true;
  }

  // Any end of a stream after reservation: releases the stream slot (and a still-pending
  // connect whose outcome is ambiguous stays SPENT — it is burned rather than refunded).
  function streamClosed(book, ticket, streamId, socket) {
    if (socket) book.sockets.delete(socket);
    if (ticket.state === "reserved" && ticket.streamId === streamId) {
      ticket.state = "spent";
      book.pendingConnects = Math.max(0, book.pendingConnects - 1);
    }
    if (ticket.streamId === streamId) {
      ticket.streamId = null;
      book.openStreams = Math.max(0, book.openStreams - 1);
    }
  }

  // Payload forwarded in either direction resets the session idle clock (control traffic and
  // ticket attempts do not).
  function touch(book) { book.lastPayloadAt = now(); }

  function get(digest) { const b = books.get(digest); return b && !b.closed ? b : null; }

  function closeAll(reason = "shutdown") { for (const book of [...books.values()]) close(book, reason); }

  return { open, reserve, release, spend, streamClosed, touch, get, close, closeAll, size: () => books.size };
}
