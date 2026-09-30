// Session tickets (ADR 0011): the ticket-book crypto and validators, shared with the node and the
// JS client (../../node/lib/session-tickets.mjs) and reproduced by the Rust SDK. Browser-safe.
export {
  SESSION_VERSION, SESSION_SIGNAL_PREFIX, SESSION_CLASSES,
  buildTicketBook, ticketCommitment, ticketBookDigest, spendDigest, sessionSignal,
  sessionInitFields, ticketFields, validateSessionInit, validateTicket, policyEcho, policyMatches,
  base64urlEncode, decodeTicketSecret, normalizeOnion,
} from "../../node/lib/session-tickets.mjs";
