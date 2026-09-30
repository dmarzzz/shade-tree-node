// Session tickets (ADR 0011): the shared ticket-book crypto against testdata/vectors.json
// `sessionTickets` (the same values shadenet_proto::session reproduces), the validators' bounded
// reasons, the base64url secret encoding and the onion-signed `session` capability.
//
//   node lib/session-tickets.selftest.mjs

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as st from "./session-tickets.mjs";
import { canonicalCaps, canonicalCapsBytes, verifyCapsSig, hasCaps, canonicalSession } from "./directory.mjs";
import { calculateSignalHash } from "./rln.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const V = JSON.parse(readFileSync(join(ROOT, "testdata", "vectors.json"), "utf8")).sessionTickets;
let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.stack || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }
const hex = (b) => Buffer.from(b).toString("hex");

console.log("session tickets (ADR 0011):");

await test("domains and the signal prefix are the frozen wire strings", () => {
  assert.equal(st.SESSION_SIGNAL_PREFIX, V.signalPrefix);
  assert.equal(st.TICKET_DOMAIN, V.ticketDomain);
  assert.equal(st.TICKET_BOOK_DOMAIN, V.ticketBookDomain);
  assert.equal(st.TICKET_SPEND_DOMAIN, V.ticketSpendDomain);
});

const book = st.buildTicketBook(V.secretsHex);
await test("ticket commitments and the book digest match the vector", () => {
  assert.deepEqual(book.commitments, V.commitments);
  assert.equal(book.ticketBookDigest, V.ticketBookDigest);
  assert.equal(st.ticketCommitment(2, V.secretsHex[2]), V.commitments[2]);
  assert.equal(st.ticketBookDigest(V.commitments), V.ticketBookDigest);
});

await test("the session signal and its hash (the circuit's public x) match the vector", () => {
  const signal = st.sessionSignal({ gateway: V.onion, classId: V.classId, nonce: V.sessionNonce, ticketBookDigest: V.ticketBookDigest });
  assert.equal(signal, V.signal);
  assert.equal(String(calculateSignalHash(signal)), V.signalHashDecimal);
  // The onion may be given without its suffix; the signal always carries it.
  assert.equal(st.sessionSignal({ gateway: V.onion.replace(/\.onion$/, ""), classId: V.classId, nonce: V.sessionNonce, ticketBookDigest: V.ticketBookDigest }), V.signal);
});

await test("the spend digest and the wire ticket match the vector; the secret round-trips base64url", () => {
  const { index, target, requestNonce, spendDigest, ticket } = V.spend;
  assert.equal(st.spendDigest({ ticketBookDigest: V.ticketBookDigest, index, target, requestNonce }), spendDigest);
  assert.deepEqual(st.ticketFields({ ticketBookDigest: V.ticketBookDigest, index, secret: book.secrets[index], requestNonce }), ticket);
  assert.equal(hex(st.decodeTicketSecret(ticket.t)), V.secretsHex[index]);
  assert.equal(ticket.t.length, 43);
  // Non-canonical trailing bits, padding, wrong length and wrong alphabet are all rejected.
  assert.equal(st.decodeTicketSecret(ticket.t.slice(0, 42) + "B"), null);
  assert.equal(st.decodeTicketSecret(ticket.t + "="), null);
  assert.equal(st.decodeTicketSecret(ticket.t.slice(1)), null);
  assert.equal(st.decodeTicketSecret(ticket.t.replace(/./, "+")), null);
});

await test("the research-v1 policy echo matches the vector and the class table", () => {
  assert.deepEqual(st.policyEcho("research-v1"), V.policy);
  assert.equal(st.SESSION_CLASSES["research-v1"].tickets, V.secretsHex.length);
  assert.equal(st.policyMatches(V.policy, "research-v1"), true);
  assert.equal(st.policyMatches({ ...V.policy, tickets: 7 }, "research-v1"), false);
  assert.equal(st.policyMatches(V.policy, "bulk-v9"), false);
});

await test("validateSessionInit accepts the vector book and names every malformed field with a bounded reason", () => {
  const good = st.sessionInitFields({ classId: V.classId, gateway: V.onion, nonce: V.sessionNonce, commitments: V.commitments, ticketBookDigest: V.ticketBookDigest });
  assert.equal(st.validateSessionInit(good).ok, true);
  const cases = [
    [null, "session-malformed"], [[], "session-malformed"], [{ ...good, v: 2 }, "session-version"],
    [{ ...good, class: "Bulk" }, "session-class"], [{ ...good, class: "bulk-v9" }, "session-class"],
    [{ ...good, gateway: "example.com" }, "session-gateway"], [{ ...good, nonce: "abc" }, "session-nonce"],
    [{ ...good, ticketCommitments: good.ticketCommitments.slice(1) }, "session-ticket-count"],
    [{ ...good, ticketCommitments: [good.ticketCommitments[0], ...good.ticketCommitments.slice(2), good.ticketCommitments[0]] }, "session-commitment"],
    [{ ...good, ticketCommitments: ["Z".repeat(64), ...good.ticketCommitments.slice(1)] }, "session-commitment"],
    [{ ...good, ticketBookDigest: "0".repeat(64) }, "session-digest"],
  ];
  for (const [input, reason] of cases) assert.equal(st.validateSessionInit(input).reason, reason, JSON.stringify(input)?.slice(0, 60));
});

await test("validateTicket accepts the vector ticket and rejects each malformed field", () => {
  const t = V.spend.ticket;
  const r = st.validateTicket(t);
  assert.equal(r.ok, true);
  assert.equal(r.index, 2);
  assert.equal(hex(r.secret), V.secretsHex[2]);
  const cases = [
    ["x", "ticket-malformed"], [{ ...t, v: 0 }, "ticket-version"], [{ ...t, book: "zz" }, "ticket-book"],
    [{ ...t, i: -1 }, "ticket-index"], [{ ...t, i: 64 }, "ticket-index"], [{ ...t, i: "2" }, "ticket-index"],
    [{ ...t, t: "nope" }, "ticket-secret"], [{ ...t, n: "short" }, "ticket-nonce"],
  ];
  for (const [input, reason] of cases) assert.equal(st.validateTicket(input).reason, reason);
});

await test("signal and spend-digest builders refuse fields that could break the newline framing or the length prefix", () => {
  assert.throws(() => st.sessionSignal({ gateway: V.onion, classId: "a\nb", nonce: V.sessionNonce, ticketBookDigest: V.ticketBookDigest }));
  assert.throws(() => st.sessionSignal({ gateway: V.onion, classId: V.classId, nonce: V.sessionNonce.toUpperCase(), ticketBookDigest: V.ticketBookDigest }));
  assert.throws(() => st.spendDigest({ ticketBookDigest: V.ticketBookDigest, index: 0, target: "x".repeat(257), requestNonce: V.spend.requestNonce }));
  assert.throws(() => st.spendDigest({ ticketBookDigest: V.ticketBookDigest, index: 0, target: "", requestNonce: V.spend.requestNonce }));
  assert.throws(() => st.ticketBookDigest([]));
  // The index is part of the commitment, so one secret at two indices is two distinct tickets.
  assert.notEqual(st.ticketCommitment(0, V.secretsHex[0]), st.ticketCommitment(1, V.secretsHex[0]));
});

await test("the onion-signed `session` capability canonicalizes after `rate`, matches the vector and cannot be widened by a signer without the onion key", () => {
  const { caps, canonicalCapsBytesHex, capsSig } = V.capsWithSession;
  assert.equal(hex(canonicalCapsBytes(V.onion, caps)), canonicalCapsBytesHex);
  assert.equal(verifyCapsSig(V.onion, caps, capsSig), true);
  assert.equal(verifyCapsSig(V.onion, { ...caps, session: { version: 1, classes: ["research-v1", "bulk-v1"] } }, capsSig), false);
  assert.equal(verifyCapsSig(V.onion, { admits: caps.admits, rate: caps.rate }, capsSig), false);
  assert.deepEqual(canonicalCaps({ session: { version: 1, classes: ["zeta", "alpha", "zeta", "Bad", 7] } }).session, { version: 1, classes: ["alpha", "zeta"] });
  for (const junk of [null, 1, [], { version: 0, classes: ["research-v1"] }, { version: 1, classes: [] }, { version: 1, classes: ["Bad"] }, { version: 1, classes: Array.from({ length: 9 }, (_, i) => `c${i}`) }]) {
    assert.equal(canonicalSession(junk), null, JSON.stringify(junk));
  }
  assert.equal(hasCaps({ session: { version: 0, classes: ["research-v1"] } }), false);
  assert.equal(hasCaps({ session: { version: 1, classes: ["research-v1"] } }), true);
  // Absent session: the pre-existing caps bytes are unchanged.
  assert.equal(hex(canonicalCapsBytes(V.onion, { admits: caps.admits, rate: caps.rate })), hex(canonicalCapsBytes(V.onion, { admits: caps.admits, rate: caps.rate, session: null })));
});

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: session-tickets selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
