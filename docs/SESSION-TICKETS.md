# Multiplexed request tickets over a gateway session

**Status: detailed design; not implemented.**

**Roadmap track:** gateway-bound session tickets, before transferable zkAPI credits.

**Last updated:** 2026-09-01.

This page scopes a concrete way to exchange one anonymous RLN admission proof for a
short-lived book of single-use request tickets, then spend those tickets over one
persistent Tor connection to a Shade Tree node. It turns the provisional multi-target
capability in [ADR 0009](adr/0009-epoch-bandwidth-envelope.md) into an implementable
transport design.

The design deliberately does **not** claim that a Shade Tree node can count arbitrary
HTTP requests inside destination TLS. It cannot. The enforceable unit is one logical
HTTP/2 `CONNECT` stream created between the local Proxy and a node. The bytes carried by
that stream remain an opaque end-to-end TLS tunnel between the agent and the destination.

The short version is:

```text
one Tor connection to one node
        |
        | HTTP/2 session initialization
        | + one target-independent RLN proof
        | + commitments to N random tickets
        v
short-lived, gateway-bound ticket book
        |
        +-- ticket 0 --> CONNECT stream --> search.example:443
        +-- ticket 1 --> CONNECT stream --> result-a.example:443
        +-- ticket 2 --> CONNECT stream --> result-b.example:443
        `-- ...
```

The initial implementation is a fixed-cost specialization of the ideas in
“ZK API Usage Credits: LLMs and Beyond.” It has no variable-cost refund, no
homomorphic balance, no per-request chain transaction, and no fleet-wide transferable
credit. Those are separate follow-on designs described near the end of this page.

---

## 1. Decision at a glance

Build an opt-in `session-v1` transport alongside Protocol v4 with these properties:

1. A client selects and connects to one session-capable node before producing a proof.
2. A dedicated onion-service port speaks HTTP/2 with prior knowledge; Protocol v4 on
   its existing port remains byte-for-byte unchanged.
3. The first HTTP/2 exchange initializes a session with one existing RLN proof.
4. The proof signal commits to the selected node, a fixed policy class, a session nonce,
   and a digest of client-generated ticket commitments.
5. A successful initialization grants a small fixed ticket book for that HTTP/2
   connection, initially the `research-v1` class proposed below.
6. Each HTTP/2 `CONNECT` stream spends one random ticket preimage before the node opens
   an upstream TCP socket.
7. The node atomically moves the ticket from `unused` to `reserved` before any async
   DNS or TCP work and to `spent` immediately after upstream TCP establishment.
8. All open streams share a combined byte ceiling, lifetime, concurrency ceiling, and
   directional token-bucket shapers.
9. The node never parses destination TLS and never claims that one ticket equals one
   inner HTTP/1.1 request or HTTP/2 stream.
10. The whole session is intentionally linkable to the serving node. The RLN proof
    still hides the member leaf and payment identity; it does not make streams sharing
    one transport connection unlinkable from each other.

This design needs no new ZK circuit and no smart-contract change for the first
prototype. It changes the proof's application signal and transport framing, not the
membership statement proved by the current RLN circuit.

---

## 2. Why this exists

### 2.1 Protocol v4 has the wrong cost unit for a research session

Protocol v4 performs one proof-gated onion dial for one target-bound TCP tunnel. Once
the node acknowledges that envelope, it directly pipes bytes in both directions. That
is a good generic CONNECT proxy boundary, but it creates three product problems:

- one search-and-fetch job usually touches several origins;
- every origin currently consumes a fresh RLN slot and usually a fresh onion stream;
- one admitted tunnel can carry an unbounded number of encrypted HTTP requests unless
  byte, time, and rate limits are added.

ADR 0009 estimates a text-oriented research job at 4 MiB and proposes a 10x safety
factor: 40 MiB of combined application payload, at most six targets, and a 90-second
lifetime. Protocol v4 cannot aggregate that envelope across targets because each proof
is bound to exactly one `host:port`.

### 2.2 A connection-local ticket book supplies the missing aggregation object

A session gives the node one local object against which it can atomically account:

- how many logical target tunnels were attempted;
- which tickets are unused, reserved, or spent;
- how many aggregate bytes crossed all child streams;
- how many streams are concurrently active;
- whether the session's hard deadline has elapsed.

The object is ephemeral and node-local. It does not need a central seer because its
tickets are not valid at another node. That is the main simplification relative to
transferable anonymous credits.

### 2.3 “Actual ticket” has a precise meaning here

A session ticket is a 32-byte random bearer secret generated by the client. The node
sees only its commitment at session initialization. Spending reveals the secret once.
The node verifies the commitment and changes ticket state atomically before doing
expensive or externally visible work.

On one authenticated connection, a plain sequence counter could enforce the same
quota. We use committed random tickets anyway because they:

- make parallel reservation semantics explicit;
- give retries a stable idempotency key that is not the HTTP/2 stream number;
- prevent the node from fabricating an unused client ticket preimage;
- prepare the wire model for narrowly scoped resumption later;
- make “one authorization object per scarce action” concrete and testable.

They do **not** make child streams unlinkable while those streams share one connection.

---

## 3. Semantic boundary: what a ticket pays for

### 3.1 Enforceable unit

One ticket authorizes the node to attempt one logical outbound TCP connection for one
HTTP/2 CONNECT stream under the session's shared resource limits.

The ticket is consumed when the upstream TCP connection is established, whether or not:

- the destination later completes TLS;
- the destination returns an HTTP response;
- the client cancels immediately after the `2xx` acknowledgement;
- the stream later times out or is reset;
- the destination returns an application error.

This boundary is objective. The node can prove to itself that its `connect()` callback
ran, and it begins incurring egress and socket costs at that point. Application success
is not objectively visible without terminating destination TLS.

### 3.2 What it does not count

A ticket does not necessarily equal:

- one HTTP/1.1 request;
- one HTTP/2 request at the destination;
- one browser navigation;
- one redirect chain;
- one LLM prompt;
- one unit of downstream API billing.

An honest `ShadeTreeClient.fetch()` adapter can close its CONNECT stream after exactly
one fetch lifecycle and thereby make one SDK call consume one ticket. The generic
loopback CONNECT Proxy cannot enforce that an arbitrary application sends only one
inner request. HTTP keep-alive and HTTP/2 multiplexing are encrypted and invisible to
the node.

### 3.3 True downstream API-request tickets

If the desired unit really is one LLM call, RPC method invocation, image generation,
or other API operation, the destination API must verify the ticket at the application
layer after terminating its own TLS. The credential can ride end to end through Shade
Tree in an `Authorization`, x402, MPP, or future zkAPI field. Shade Tree then supplies
network privacy but does not act as the usage-credit verifier.

That API-origin mode and this gateway-session mode can coexist, but they solve different
accounting problems and must not share misleading names in user-facing policy.

---

## 4. Goals

The first implementation should provide:

- **One expensive proof per bounded session.** Child ticket checks use only bounded
  parsing, hashes, map operations, and existing target-policy checks.
- **Several targets over one onion connection.** A search origin and fetched result
  origins can share one Tor rendezvous and one session envelope.
- **Parallel child streams.** Independent requests do not head-of-line block at the
  application layer, subject to HTTP/2 connection-level flow control.
- **End-to-end destination TLS.** A node continues to see target, timing, lifetime, and
  byte counts, never plaintext HTTP content.
- **Exact node-local single use.** Two simultaneous spends of one ticket at one node
  cannot both establish upstream sockets.
- **Bounded resource exposure.** Tickets, bytes, rate, lifetime, pending DNS operations,
  active streams, headers, and initialization bodies all have explicit limits.
- **Compatibility.** Existing Protocol v4 clients and nodes continue to interoperate on
  the current service port.
- **Cross-language parity.** JavaScript remains the reference behavior and Rust consumes
  the same canonical vectors and failure cases.
- **Truthful privacy labels.** Session-level linkability is visible in documentation,
  APIs, and progress events rather than hidden behind “anonymous ticket” language.

---

## 5. Non-goals for `session-v1`

The following are explicitly out of scope:

- transferable tickets that work at any node in the canopy;
- unlinkability between child streams sharing one session;
- a permanent monetary balance that decreases across epochs;
- variable request pricing or server-computed refunds;
- homomorphic refund accumulation;
- server policy slashing based on plaintext request content;
- ticket resale prevention;
- fair exchange proving that the node delivered a useful application response;
- session recovery after node process restart;
- UDP, QUIC, CONNECT-UDP, or MASQUE;
- destination ports other than those allowed by the node's existing egress policy;
- replacing x402 or MPP for downstream API payment;
- calling the current asynchronous fleet tally an atomic distributed spent set.

---

## 6. Why HTTP/2 CONNECT is the outer transport

HTTP/2 already defines exactly the transport primitive needed here: one connection can
carry many independently flow-controlled streams, and a standard CONNECT request turns
one stream into a tunnel to a `host:port`. After a successful response, DATA frames are
the tunneled TCP bytes.

That is preferable to a new Shade Tree binary multiplexer because HTTP/2 supplies:

- stream identifiers and lifecycle states;
- connection and stream flow control;
- cancellation through `RST_STREAM`;
- bounded concurrent-stream negotiation;
- mature parsers in Node.js and Rust;
- standard CONNECT semantics and error status handling;
- a clean mapping from each local HTTP/1.1 CONNECT socket to one outer HTTP/2 stream.

This design uses ordinary HTTP/2 CONNECT as specified by RFC 9113, not Extended CONNECT
from RFC 8441. No `:protocol` pseudo-header is required.

### 6.1 Dedicated service port

The safest rollout is a separate onion virtual port, provisionally:

```text
gateway.onion:80  -> 127.0.0.1:8443  Protocol v4 raw envelope + one tunnel
gateway.onion:81  -> 127.0.0.1:8444  session-v1 HTTP/2 prior knowledge
```

The exact public and loopback ports remain operator-configurable. The important rule is
that the protocols are not sniffed or opportunistically reinterpreted on one socket.
A malformed HTTP/2 preface cannot fall through to the v4 JSON parser, and a malformed v4
envelope cannot reach the HTTP/2 stack.

Because the client learns session support from an onion-signed capability, HTTP/2 prior
knowledge is safe: there is no unauthenticated cleartext upgrade dance and no ALPN
ambiguity. The Tor onion connection already authenticates the onion service and encrypts
the network path. The HTTP/2 hop is plaintext only after Tor terminates on the node's
loopback interface, which is already inside the operator trust boundary.

### 6.2 Outer and inner HTTP/2 are unrelated

The outer HTTP/2 connection runs from Proxy to Shade Tree node and multiplexes CONNECT
tunnels. A destination TLS connection carried inside one CONNECT stream may itself
negotiate HTTP/2 with the destination. The node sees only encrypted inner bytes and does
not confuse, merge, or account inner streams individually.

---

## 7. Roles and state

### 7.1 Client / Proxy

The client owns:

- membership secret and Merkle witness;
- crash-safe RLN slot allocation;
- selected node and onion-isolated Tor dial;
- random ticket secrets and their commitments;
- session nonce and request nonces;
- the mapping from local CONNECT sockets or SDK fetches to outer HTTP/2 streams;
- remaining local ticket inventory;
- retry decisions.

### 7.2 Node

The node owns, for the lifetime of one accepted HTTP/2 connection:

- accepted proof result and authoritative RLN nullifier;
- ticket-book digest and fixed commitment array;
- one state entry per ticket;
- session policy and counters;
- active child stream and upstream socket handles;
- a hard session deadline;
- shared byte and token-bucket state.

The node does not persist ticket secrets, target history, or session state after the
connection closes in the MVP.

### 7.3 Destination

The destination sees:

- the node's clearnet egress IP;
- its own application/TLS interaction;
- whichever account, cookies, API key, payment credential, or fingerprint the agent
  sends end to end.

It does not receive the Shade Tree RLN proof, ticket, ticket-book digest, or member leaf.

### 7.4 Elder Tree / canopy directory

The discovery layer carries only a coarse, onion-signed declaration that a node supports
`session-v1`, the service port, and a small allowlisted set of policy-class identifiers.
It does not carry live session counts, ticket-book identifiers, request targets, or
per-client negotiated policy.

---

## 8. Initial policy class

Start with exactly one class so policy selection does not become a fingerprinting
surface before representative measurements exist.

### `research-v1`

| Parameter | Initial value | Meaning |
|---|---:|---|
| tickets | `6` | At most six upstream TCP establishments |
| combined payload | `41,943,040` bytes | Agent-to-destination plus destination-to-agent payload |
| hard lifetime | `90` seconds | Absolute from successful session initialization |
| idle timeout | `15` seconds | No payload in either direction across the whole session |
| concurrent streams | `4` | Streams connecting or established at once |
| pending connects | `4` | DNS/TCP work in flight at once |
| agent -> destination rate | `64 KiB/s` | Shared token bucket, `128 KiB` burst |
| destination -> agent rate | `512 KiB/s` | Shared token bucket, `1 MiB` burst |
| destination ports | existing node policy | `443` under the default deployment |
| proof slots consumed | `1` | One current RLN message slot per initialized session |

The 40 MiB limit and direction-specific rates come from ADR 0009. The ticket count is
the proposed search origin plus five result origins. Four-way concurrency keeps the
first implementation useful without allowing all six targets to hold DNS lookups and
sockets simultaneously.

### 8.1 Policy is operator-enforced, not client-requested

The client requests only the literal class identifier `research-v1`. It does not send
arbitrary `maxBytes`, `tickets`, or `expiresIn` values. The node resolves the identifier
through its local immutable table and returns the effective values in the initialization
response.

Unknown classes fail closed. A future policy-table change that alters security-relevant
values must use a new class identifier rather than silently changing `research-v1`.

### 8.2 Relationship to RLN tiers

One RLN slot buys one session, regardless of whether that member's private leaf limit is
1, 8, or 32. A higher tier can initialize more sessions per epoch because it owns more
private RLN slots. Each initialized session receives the same `research-v1` ticket book.

Therefore the maximum entitlement is multiplicative:

```text
member maximum per epoch
  = private RLN slots
  x sessions successfully initialized per slot
  x six child tickets per session
```

The protocol must state this honestly. If the desired policy is one aggregate 40 MiB
envelope per member per epoch rather than per RLN slot, `session-v1` cannot enforce it
without introducing a stable epoch/member handle or another private aggregation proof.

---

## 9. Ticket cryptography and canonical encoding

The ticket layer is intentionally conventional. It does not need Poseidon or a SNARK
because only the book digest is carried inside the already-proved RLN signal.

### 9.1 Algorithms

- Randomness: operating-system CSPRNG.
- Hash: SHA-256.
- Ticket secret: exactly 32 bytes.
- Ticket index: unsigned 16-bit integer, network byte order.
- Wire encoding for ticket secret: unpadded base64url.
- Wire encoding for commitments and digests: 64 lowercase hexadecimal characters.
- String encoding inside domain-separated hashes: UTF-8.

The initial class has only six tickets, but the 16-bit index makes the format reusable
without permitting an unbounded implementation. Each policy class still sets a much
smaller hard maximum.

### 9.2 Ticket commitment

For ticket index `i` and random 32-byte secret `s_i`:

```text
ticketCommitment_i = SHA256(
    UTF8("Shade Tree session ticket v1\n")
    || UINT16_BE(i)
    || s_i
)
```

Including the index prevents a commitment from being moved to another slot in a
malformed or reordered book.

### 9.3 Ticket-book digest

For ordered commitments `c_0 ... c_(N-1)`:

```text
ticketBookDigest = SHA256(
    UTF8("Shade Tree session ticket book v1\n")
    || UINT16_BE(N)
    || c_0
    || ...
    || c_(N-1)
)
```

Each `c_i` contributes its raw 32 hash bytes, not its hexadecimal text. The count is
fixed by the policy class and must match the number of commitments in the initialization
body.

A Merkle tree is unnecessary for six to a few dozen tickets because the node already
stores connection-local state and the whole commitment list is small. A later
transferable or very large ticket book may replace the flat digest with a Merkle root,
but that is a new protocol version, not an implicit encoding change.

### 9.4 Session nonce

The client generates 16 random bytes and encodes them as 32 lowercase hexadecimal
characters. The nonce is not a bearer secret. It gives exact retries a stable value and
ensures two otherwise identical session initializations produce different proof signals.

### 9.5 Request nonce and spend digest

Each logical child request receives a separate 16-byte random request nonce. On the
first attempt to reserve ticket `i` for target `target`, the node computes:

```text
spendDigest = SHA256(
    UTF8("Shade Tree session ticket spend v1\n")
    || ticketBookDigest
    || UINT16_BE(i)
    || UINT16_BE(byteLength(UTF8(target)))
    || UTF8(target)
    || requestNonce
)
```

`ticketBookDigest` and `requestNonce` contribute raw bytes. `target` must pass the same
length and delimiter safety checks as the v4 target before hashing.

The spend digest is node-local and ephemeral. It is not emitted in receipts, metrics,
directory records, or logs. It exists only to distinguish an exact retry from an attempt
to reuse one ticket for another target.

---

## 10. RLN session proof

### 10.1 Reused statement

The existing circuit continues to prove:

- membership of a rate-commitment leaf under an accepted root;
- private `messageId < userMessageLimit`;
- the epoch-scoped external nullifier;
- correct RLN share and internal nullifier construction;
- evaluation at the public signal hash `x`.

No circuit input or public-signal shape changes. Only the application message hashed
into `x` changes.

### 10.2 Session signal

The exact signal string is:

```text
shade-tree:session:v1\n<gateway-onion>\n<class-id>\n<session-nonce>\n<ticket-book-digest>
```

For example:

```text
shade-tree:session:v1
abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion
research-v1
86fe22b71e0d1c681e679150f8f103aa
4e7f...64-lowercase-hex-characters...
```

Every field has a strict grammar:

- `gateway-onion`: one checksummed 56-character Tor v3 name plus `.onion`, lowercase;
- `class-id`: an allowlisted ASCII token matching `^[a-z0-9][a-z0-9-]{0,31}$`;
- `session-nonce`: exactly 32 lowercase hexadecimal characters;
- `ticket-book-digest`: exactly 64 lowercase hexadecimal characters.

No field may contain CR or LF. The client and node build the same string and apply the
existing RLN signal hash function.

### 10.3 Why the selected gateway is bound

Binding the onion makes the entire book valid at exactly one node. Consequently:

- a captured session initialization cannot be redeemed at another node;
- no fleet-wide atomic spent set is needed for child tickets;
- two nodes cannot concurrently honor copies of the same book;
- the current asynchronous fleet tally is not placed in a role it cannot safely fill.

The cost is loss of post-proof failover. The client must select and successfully complete
the HTTP/2/Tor dial before allocating the RLN slot and building the proof. If that node
fails after proof generation, the slot may be burned. It must not reuse the same proof at
another onion because the signal would be wrong.

### 10.4 Root and admission policy

The session proof is checked against the same explicitly admitted root union as v4:

- invited local set;
- `StakedReputationSet` roots when `staked` is admitted;
- `PaidAccessSet` roots when `paid` is admitted.

The proof root remains public to the node, so the node may learn which root or admission
source accepted the session. Ticketing does not improve that existing leakage.

### 10.5 Spent RLN slot

The session initializer passes through the existing node spent-set before the node sends
a success response. A conflicting RLN share under the same nullifier follows the current
reconstruction/slashing path. An exact replay is eligible only for the narrowly defined
recovery behavior in section 15; it must never create an independent second ticket book.

---

## 11. Discovery capability

Add one optional, onion-signed capability object:

```json
{
  "session": {
    "version": 1,
    "port": 81,
    "classes": ["research-v1"]
  }
}
```

Canonicalization requirements:

- unknown `session` keys are discarded;
- `version` is an integer in the supported range;
- `port` is an integer from 1 through 65535;
- `classes` is non-empty, deduplicated, sorted, grammar-checked, and count-bounded;
- the entire object is included in the existing onion-key `capsSig` bytes;
- JavaScript and Rust produce byte-identical canonical capability bytes;
- a directory signer cannot add or modify session support without the onion key.

The capability intentionally advertises class identifiers rather than per-node arbitrary
numeric quotas. The class name is the stable contract. Effective values are echoed by
the node after initialization so the client can fail closed if they differ from its
compiled understanding of that class.

Clients requiring session transport filter to entries with a valid signed session
capability. Legacy entries remain valid candidates for Protocol v4 but are not silently
treated as session capable.

---

## 12. HTTP/2 initialization exchange

### 12.1 Connection establishment

1. Client chooses a compatible directory entry.
2. Client creates a per-session Tor circuit-isolation credential.
3. Client dials the advertised session port through Tor.
4. Client starts HTTP/2 with prior knowledge.
5. Client waits for bounded peer settings and confirms the connection permits no more
   than the locally configured stream ceiling.
6. Only now does the client durably allocate an RLN slot, generate tickets, and build the
   session proof.

Dial-before-proof avoids spending a slot on an unreachable onion. Proof generation still
happens before the node authenticates the connection; a node that accepts TCP and then
stalls can consume client time, so the entire initialization has one absolute deadline.

### 12.2 Request

The client sends:

```text
:method: POST
:scheme: http
:authority: <gateway-onion>:<session-port>
:path: /shade-tree/session/v1
content-type: application/shade-tree-session+json
content-length: <bounded>
```

Body:

```jsonc
{
  "v": 1,
  "class": "research-v1",
  "gateway": "<56-char>.onion",
  "nonce": "<32 lowercase hex>",
  "ticketCommitments": [
    "<64 lowercase hex>",
    "<64 lowercase hex>",
    "<64 lowercase hex>",
    "<64 lowercase hex>",
    "<64 lowercase hex>",
    "<64 lowercase hex>"
  ],
  "ticketBookDigest": "<64 lowercase hex>",
  "artifact": "rln-<verification-key hash prefix>",
  "proof": { "snarkProof": {}, "epoch": "...", "rlnIdentifier": "1" },
  "nullifier": "...",
  "externalNullifier": "...",
  "share": { "x": "...", "y": "..." }
}
```

As in v4, duplicate `nullifier`, `externalNullifier`, and `share` fields are transport
conveniences only. The node acts on values recovered from verified public signals.

The initialization body inherits the v4 64 KiB maximum and one absolute read deadline.
JSON nesting, key count, string sizes, ticket count, proof shape, and numeric grammar are
bounded before Groth16 verification.

### 12.3 Cheap-first verification order

The node performs:

1. HTTP/2 method, path, content type, and body-length checks.
2. JSON parse and exact top-level type checks.
3. session version check.
4. selected gateway equality against the node's own onion.
5. allowlisted policy-class lookup.
6. ticket count equals policy count.
7. every commitment has exact lowercase-hex grammar and is unique.
8. recompute and compare the ticket-book digest in constant-time style.
9. external nullifier freshness.
10. proof public `x` equals the hash of the exact session signal.
11. proof root is in the explicitly admitted recent-root set.
12. proof artifact is accepted.
13. Groth16 verification.
14. existing RLN spent-set admission and conflict handling.
15. acquire session-level connection and proof-nullifier limits.

No DNS lookup or upstream connection occurs during initialization.

### 12.4 Success response

```text
:status: 201
content-type: application/shade-tree-session+json
cache-control: no-store
```

```json
{
  "v": 1,
  "ok": true,
  "ticketBookDigest": "<64 lowercase hex>",
  "policy": {
    "class": "research-v1",
    "tickets": 6,
    "maxPayloadBytes": 41943040,
    "lifetimeMs": 90000,
    "idleTimeoutMs": 15000,
    "maxConcurrentStreams": 4
  }
}
```

The response contains no member identifier, leaf, payer, target, fine timestamp, or
server-generated per-session identifier. The HTTP/2 connection itself is the session
handle. The client verifies every returned policy value against its understanding of the
class and closes on disagreement.

### 12.5 Failure response

Initialization failures return a bounded status and machine-readable coarse error:

```json
{ "v": 1, "ok": false, "error": "invalid-proof" }
```

Suggested mapping:

| Status | Error family | Examples |
|---:|---|---|
| `400` | malformed | bad JSON, wrong count, bad commitment grammar |
| `404` | unsupported path | unknown session endpoint |
| `409` | replay/conflict | conflicting or already-consumed RLN initialization |
| `413` | too large | headers or body exceed bound |
| `429` | capacity | connection/proof/session limiter exhausted |
| `503` | unavailable | root source or verifier temporarily unavailable |

Proof failures should preserve the current bounded public taxonomy rather than echoing
peer-controlled values or verifier exception messages.

---

## 13. Spending a ticket with CONNECT

### 13.1 Request headers

After successful initialization, a child tunnel begins with ordinary HTTP/2 CONNECT:

```text
:method: CONNECT
:authority: example.com:443
authorization: ShadeTreeTicket v=1,i=0,t=<unpadded-base64url-secret>,n=<32-hex-request-nonce>
```

Per RFC 9113 CONNECT semantics, `:scheme` and `:path` are omitted. No Extended CONNECT
`:protocol` value is used.

The `authorization` value is sensitive bearer material and must:

- be marked never-index in HPACK by both JavaScript and Rust clients;
- never be logged, included in exceptions, reflected in responses, or exported as a
  metric label;
- have a small exact maximum length;
- be decoded into a fixed 32-byte buffer or rejected;
- be zeroed or released promptly where the language/runtime permits;
- be compared through its SHA-256 commitment rather than by string identity.

The node rejects CONNECT before initialization on that HTTP/2 connection.

### 13.2 Verification and reservation

For ticket `i`:

1. Parse `i`, secret, and request nonce with no coercive numeric conversion.
2. Require `0 <= i < policy.tickets`.
3. Recompute `ticketCommitment_i` and compare with the stored commitment.
4. Parse and policy-check `:authority` without DNS.
5. Compute `spendDigest`.
6. Synchronously inspect and update ticket state before the first `await`:
   - `unused` -> `reserved(spendDigest, streamId)`;
   - same reservation -> exact in-flight duplicate, reject without another upstream;
   - different reservation -> `ticket-conflict`, reject;
   - `spent` -> `ticket-spent`, reject.
7. Acquire shared pending-connect and concurrent-stream capacity.
8. Perform bounded DNS resolution and public-address validation.
9. Attempt the validated upstream addresses under one absolute connect deadline.

The synchronous state transition is the JavaScript atomicity boundary. Rust performs
the same transition while holding the session-state mutex, then releases the lock before
DNS or I/O.

### 13.3 Commit point

The ticket becomes `spent` immediately inside the successful upstream TCP connect path,
before the node sends `:status 200` and before it forwards any client DATA.

This ordering ensures that:

- two concurrent streams cannot both receive service;
- loss of the success response cannot make a real upstream establishment free;
- the node never sends application bytes for an uncommitted ticket;
- client cancellation immediately after `200` still consumes the objectively incurred
  connection action.

### 13.4 Successful tunnel

The node sends:

```text
:status: 200
```

Subsequent DATA frames on that HTTP/2 stream are relayed to and from the upstream TCP
socket. The node applies shared and per-stream backpressure. End of stream half-closes
the matching TCP direction when safe; reset destroys the upstream socket.

### 13.5 Pre-connect failure

If all validated upstream candidates fail before any TCP establishment, the node:

- releases pending-connect and stream capacity;
- changes `reserved` back to `unused` only if the reservation still belongs to this
  stream and spend digest;
- returns a bounded non-2xx status and coarse reason;
- allows the same ticket, target, and request nonce to be tried again on a new stream.

A different target or request nonce is not considered the same retry. After an
unambiguous pre-connect release it may reserve the now-unused ticket as a new spend, but
clients should retain the original logical request nonce until they abandon that request.

### 13.6 Failure after connect

Any failure after the upstream connect callback leaves the ticket `spent`. This includes
TLS failure, destination close, idle timeout, quota exhaustion, client reset, and node
relay error.

---

## 14. State machines

### 14.1 Session state

```text
NEW
  | valid initialization + RLN admission
  v
ADMITTED
  | hard limit, idle timeout, GOAWAY, protocol error, or peer close
  v
DRAINING
  | all child streams closed or drain deadline reached
  v
CLOSED
```

Rules:

- `NEW` accepts only one initialization request plus bounded HTTP/2 control traffic.
- initialization racing on two streams is a connection protocol error; at most one can
  enter proof verification.
- `ADMITTED` accepts CONNECT streams and rejects a second initializer.
- `DRAINING` refuses new CONNECT streams but permits already-established streams only
  until the smaller of their deadline and the drain deadline.
- `CLOSED` retains no session or target state.

### 14.2 Ticket state

```text
UNUSED
  | atomic reserve(spendDigest, streamId)
  v
RESERVED
  | upstream established             | definite pre-connect failure
  v                                  v
SPENT                              UNUSED
```

There is no transition from `SPENT` back to `UNUSED`.

If a stream disappears while DNS/TCP work is pending, the node cancels that work where
possible. It may release the ticket only if it can establish that no upstream socket
connected. An ambiguous connect outcome burns the ticket rather than risking duplicate
service.

### 14.3 Stream state

```text
HEADERS
  -> AUTHORIZED
  -> RESOLVING
  -> CONNECTING
  -> ESTABLISHED
  -> HALF_CLOSED / CLOSED
```

Every transition is monotonic. Cleanup functions must be idempotent because HTTP/2
reset, TCP error, timeout, session close, and process shutdown can race.

---

## 15. Initialization replay and limited recovery

The MVP should not promise general session resumption, but it must define what happens
when the initialization response is lost.

### 15.1 Same live HTTP/2 connection

A second initialization request is rejected. The client already has a definitive stream
result or the HTTP/2 connection is no longer trustworthy.

### 15.2 New connection to the same node

The conservative MVP behavior is:

- the original RLN slot remains consumed;
- unused child tickets are lost when the connection closes;
- an exact initialization replay on a new connection is rejected as already spent;
- the client may create a new session only with another RLN slot.

This is simple and fail-closed but can be harsh under unstable Tor circuits.

### 15.3 Follow-on: exact book recovery

A later additive recovery mode may retain a short-lived node-local record keyed by
`(authoritative RLN nullifier, ticketBookDigest)` for at most the policy lifetime. An
exact replay of the same verified initialization could reattach the same book state to a
new HTTP/2 connection after forcibly draining the old one.

Before shipping recovery, specify and test:

- proof that both initializations are byte-equivalent in all semantic fields;
- prevention of two simultaneously attached connections;
- ticket-state preservation across the handoff;
- how a capture of the initialization envelope interacts with bearer ticket secrecy;
- bounded memory under repeated reconnect attempts;
- whether process restart deliberately loses recovery state.

Do not add a reusable server-generated session cookie as a shortcut. It would become a
stable tracking and bearer handle without improving the underlying authorization model.

---

## 16. Byte accounting, shaping, and deadlines

### 16.1 Counted bytes

Count only opaque application payload forwarded after a child upstream connection is
established:

```text
combinedPayload
  = bytes forwarded agent -> destination
  + bytes forwarded destination -> agent
```

Do not count:

- HTTP/2 frame headers;
- session initialization JSON;
- ticket headers;
- Tor cells or TCP/IP overhead;
- DNS packets;
- node success/error response headers.

This matches the payload measure already described by ADR 0009 and keeps implementation
parity between raw v4 stream accounting and session streams.

### 16.2 Exact hard ceiling

Before forwarding a payload chunk of length `L`, atomically reserve at most the remaining
session allowance. If only `R < L` bytes remain, forward exactly `R`, mark the session
quota exhausted, stop all child streams, and send GOAWAY/reset as appropriate.

Do not forward the whole final chunk and accept a high-water-mark overshoot. The maximum
must be a real maximum independent of runtime chunk size.

### 16.3 Directional shaping

Maintain one token bucket per direction for the whole session, not one bucket per child
stream. Otherwise opening six streams multiplies the advertised rate by six.

Delayed writes must propagate backpressure to the matching HTTP/2 or TCP reader. The
implementation may queue at most one bounded chunk per active direction/stream and must
not accumulate a session-sized buffer in user space.

### 16.4 Hard lifetime

The absolute session deadline begins when the node commits initialization and returns
`201`. Activity never extends it. At expiry the node:

1. sends GOAWAY refusing new streams;
2. resets pending DNS/TCP streams;
3. grants established streams only a small fixed drain interval;
4. destroys remaining upstream sockets;
5. releases the HTTP/2 connection and all session state.

### 16.5 Idle timeout

The session idle clock resets only when application payload is successfully forwarded in
either direction. HTTP/2 PING, SETTINGS, WINDOW_UPDATE, ticket attempts, and other control
frames do not keep a session alive indefinitely.

---

## 17. Resource and abuse controls

The session endpoint creates new parser and multiplexing surfaces. It needs at least:

- global accepted TCP connection cap before reading the HTTP/2 preface;
- maximum HTTP/2 sessions in `NEW`, verifying, admitted, and draining states;
- initialization header and body size limits;
- initialization absolute deadline;
- at most one proof verification job per connection;
- process-wide bounded proof-verification concurrency;
- HTTP/2 maximum concurrent streams no greater than the policy limit plus one control
  stream allowance;
- maximum header-list size and field count;
- disabled server push;
- bounded HPACK dynamic table size;
- rate limit on malformed initialization attempts;
- maximum pending DNS and TCP connects per session and globally;
- existing target lexical policy before proof-costly or DNS work where possible;
- existing public-address revalidation after DNS;
- connection and stream flow-control windows chosen to bound memory;
- absolute connect, session, idle, and drain deadlines;
- idempotent cleanup under GOAWAY, reset, socket error, and shutdown;
- no exception path that leaves an HTTP/2 stream hanging without a response or reset.

Unknown pseudo-headers, forbidden connection-specific headers, duplicate authorization
headers, malformed base64url, duplicate commitments, and out-of-range ticket indices fail
closed.

---

## 18. Privacy analysis

### 18.1 Properties retained

- Tor hides the client source IP from the node application under the existing Tor threat
  model.
- The RLN proof hides which accepted membership leaf initialized the session.
- A paid leaf still separates the payer observed by the 402 registrar from the member
  secret used in the proof.
- The destination sees the node egress IP rather than the client IP.
- Destination TLS remains end to end and the node sees no plaintext HTTP headers, URL
  paths, prompts, responses, cookies, or API keys.

### 18.2 New linkability accepted by design

The serving node can link every child stream on one HTTP/2 connection. It learns the
ordered set of:

- target `host:port` values;
- stream start and stop times;
- upstream success/failure outcomes;
- direction-specific byte counts;
- concurrent-request shape;
- which request attempts share one policy envelope.

The ticket-book digest is also a unique session-local handle. It must never leave the
node's connection-local state or client progress data except where required for protocol
debugging under an explicit unsafe development flag.

### 18.3 What tickets do not fix

- application cookies and accounts can link the user at destinations;
- writing style, prompts, and fetched content can be identifying;
- a node and destination can correlate timing;
- a global passive observer remains out of scope to the same degree as current Tor;
- unique policy classes or rare ticket counts can fingerprint sessions;
- a small accepted Merkle root is a small anonymity set;
- payment timing and first use can correlate outside the proof system;
- all streams sharing one node necessarily share that node's public egress identity.

### 18.4 Logging rule

Normal logs may include only bounded coarse reasons and aggregate counts. They must not
include:

- ticket secret or commitment;
- ticket-book or spend digest;
- authoritative RLN nullifier or share;
- target;
- HTTP/2 stream ID associated with target or ticket;
- session nonce;
- proof bytes;
- per-session fine timestamps or byte totals.

Operators already possess live connection metadata in memory. The design must not turn
that unavoidable observation into a durable browsing-history dataset.

---

## 19. Security properties and adversaries

### 19.1 Malicious client

A client may attempt to:

- submit more commitments than the class allows;
- reuse a secret at several indices;
- spend one ticket concurrently;
- alter a target while a spend is pending;
- send DATA before CONNECT succeeds;
- create many idle streams;
- exploit HPACK/header bombs;
- hold DNS or TCP connects open;
- multiply byte rates across streams;
- keep the session alive with control traffic;
- race reset against upstream connect;
- replay initialization across nodes.

The fixed class, unique commitment rule, synchronous reservation, connection-local shared
limits, absolute deadlines, gateway-bound proof signal, and bounded HTTP/2 settings address
these cases.

### 19.2 Malicious node

A node can always:

- refuse a valid initialization or ticket;
- mark tickets spent without providing service;
- connect to a different destination than requested;
- delay, truncate, reorder, or inspect traffic metadata;
- misreport effective policy in its response;
- log everything it observes;
- correlate all streams in the session.

The client detects a policy mismatch and TLS detects destination impersonation when the
application validates certificates correctly. No protocol can force a prepaid network
operator to provide useful service. Ticket commitments prevent the node from knowing
unused preimages in advance, but do not prevent denial or false local accounting.

### 19.3 Malicious destination

The destination can fingerprint the inner TLS/application client, correlate accounts,
stall responses, return large bodies, or induce redirects. Shared time/byte limits bound
the node cost. Redirect handling remains a client decision and a new origin consumes a
new ticket.

### 19.4 Malicious Elder Tree or directory signer

The existing directory trust model applies. Session capabilities are onion-key signed,
so a directory signer that lacks the onion key cannot add session support to an existing
entry. A compromised directory signer can still add a wholly attacker-controlled onion
with internally valid capabilities, omit honest nodes, or concentrate selection.

### 19.5 Cross-node replay adversary

Child tickets are not accepted outside the HTTP/2 connection whose gateway-bound RLN
proof committed their book. Therefore cross-node child-ticket replay is invalid by
construction. The initial RLN slot still follows the current fleet evidence/slashing
model, but no child action relies on asynchronous fleet tally propagation for local
single use.

---

## 20. Client behavior

### 20.1 Session pool

The reusable client owns at most a small configured number of session objects. Each is
keyed by the selected onion and policy class. A session is eligible when:

- its HTTP/2 connection is healthy;
- initialization succeeded;
- at least one local ticket remains;
- its hard deadline has sufficient headroom for a new request;
- its concurrent-stream count is below policy;
- its locally observed byte budget is not exhausted.

The node remains authoritative. Local counters are scheduling hints that avoid doomed
requests, not security checks.

### 20.2 Loopback Proxy mapping

Each incoming local HTTP/1.1 CONNECT request maps to one outer HTTP/2 CONNECT stream:

```text
application TCP socket
    -> local Proxy CONNECT host:443
    -> allocate one ticket from session
    -> outer HTTP/2 CONNECT stream
    -> node upstream TCP socket
    -> destination TLS
```

The local Proxy sends `HTTP/1.1 200 Connection established` only after the outer stream
receives `:status 200`. Bytes received early from the local application remain bounded
and are forwarded exactly once after success, mirroring the current v4 behavior.

### 20.3 SDK fetch mapping

`ShadeTreeClient.fetch()` may use one session ticket for one fetch lifecycle. It should:

- open a dedicated outer CONNECT stream;
- create a new inner TLS connection for that stream;
- perform one request;
- enforce its existing total deadline and body cap;
- close the stream after the response body completes;
- expose coarse ticket/session progress without secrets or stable handles.

It should not silently pool the inner destination TLS socket for another fetch because
that would make the documented “one SDK fetch consumes one ticket” behavior false.

### 20.4 Selection and rotation

A session pins several requests to one node and one Tor connection, weakening current
per-tunnel gateway and SOCKS circuit rotation. This is an explicit privacy/performance
tradeoff, not an implementation detail.

Recommended selection behavior:

- rotate/select at session granularity;
- keep sessions short and policy-bounded;
- never move a session identifier or book across nodes;
- optionally hold independent sessions at several nodes only when the member has enough
  RLN slots and the application accepts the extra linkability sets;
- fall back to v4 per-tunnel rotation when maximum unlinkability is preferred over
  amortized setup and multi-target accounting.

Expose the choice as a client policy such as:

```text
transportPrivacy = per-tunnel | bounded-session
```

Do not make bounded-session the silent default until measurements and user-facing privacy
language are complete.

---

## 21. Node implementation structure

Keep the v4 handler small and unchanged. Add separate modules rather than growing one
1,500-line gateway file further:

```text
lib/session-ticket.mjs
  ticketCommitment()
  ticketBookDigest()
  sessionSignal()
  spendDigest()
  parseTicketCredential()
  canonical validation helpers

gateway/session-policy.mjs
  immutable policy classes
  configuration validation

gateway/session-state.mjs
  session and ticket state machines
  synchronous reserve/commit/release
  byte/rate/lifetime accounting

gateway/session-server.mjs
  HTTP/2 server
  initialization handler
  CONNECT handler
  upstream lifecycle and shutdown

client/session.mjs
  ticket generation
  HTTP/2 connection and initialization
  child stream adapter
  local scheduling counters

client/session-pool.mjs
  gateway selection at session granularity
  lifecycle, draining, fallback
```

Rust mirrors the pure ticket functions in `shadenet-proto`, puts HTTP/2 transport and
pooling in `shadenet-egress`, and keeps CLI policy in `shade-tree-client`.

Use shared JSON/conformance vectors for:

- ticket commitments;
- book digests;
- session signals and RLN public `x`;
- spend digests;
- capability canonical bytes and signatures;
- valid and invalid ticket credentials;
- policy tables.

---

## 22. Metrics and observability

Suggested aggregate metrics:

```text
shade_tree_session_initializations_total{result,reason}
shade_tree_session_active
shade_tree_session_connects_total{result,reason}
shade_tree_session_streams_active
shade_tree_session_ticket_checks_total{result,reason}
shade_tree_session_payload_bytes_total{direction}
shade_tree_session_payload_per_session_bytes_bucket
shade_tree_session_lifetime_seconds_bucket
shade_tree_session_verify_seconds_bucket
shade_tree_session_upstream_connect_seconds_bucket
shade_tree_session_closes_total{reason}
```

All labels come from fixed allowlists. Never label by onion, target, member, root,
nullifier, session, stream, ticket, class if there is only one class, or peer-supplied
error text.

The payload-per-session histogram is useful for recalibrating the 4 MiB workload estimate
without retaining per-session records. Histogram buckets and retention policy must still
be reviewed for low-volume uniqueness.

Client progress events may say:

```jsonc
{ "phase": "session", "status": "initializing", "class": "research-v1" }
{ "phase": "session", "status": "ready", "tickets": 6 }
{ "phase": "ticket", "status": "reserved", "remaining": 5 }
{ "phase": "ticket", "status": "spent", "remaining": 5 }
```

They must not include book digests, ticket values, nullifiers, proof points, or targets in
normal mode.

---

## 23. Error taxonomy

Keep public reasons coarse and bounded. Suggested initializer reasons:

```text
bad-session-request
unsupported-session-version
unsupported-session-class
gateway-mismatch
bad-ticket-book
duplicate-ticket-commitment
session-init-timeout
session-init-too-large
stale-external-nullifier
wrong-group-root
unsupported-artifact
invalid-proof
rln-replay
rln-conflict
too-many-sessions
internal-error
```

Suggested CONNECT reasons:

```text
session-not-initialized
session-draining
session-expired
bad-target
bad-ticket
ticket-conflict
ticket-in-use
ticket-spent
too-many-streams
too-many-pending-connects
dns-failed
dns-timeout
blocked-address
upstream-failed
upstream-timeout
payload-limit
idle-timeout
```

Internally useful details such as DNS error codes remain mapped into these fixed labels.
Peer-controlled header values never appear in normal log messages.

---

## 24. Adversarial acceptance matrix

The feature is not complete without all of these tests.

### 24.1 Ticket construction

- JS and Rust derive identical commitment, book, signal, and spend digests.
- Changing index, ticket secret, order, count, class, gateway, or nonce changes the
  expected digest.
- malformed encodings are rejected without throwing across the process boundary.
- duplicate ticket commitments are rejected.
- ticket generation uses the operating-system CSPRNG and never falls back to time/PID.

### 24.2 Initialization

- non-member, wrong root, stale epoch, bad artifact, and invalid proof never admit a
  session.
- a proof over another gateway onion is rejected.
- a proof over another class or book is rejected by public `x` binding.
- oversized headers/body, slow body, deep JSON, and many keys stay within memory and
  deadline limits.
- two initialization streams cannot start two proof verifications.
- closing the HTTP/2 connection during proof verification leaves no admitted state.
- an accepted initialization consumes exactly one RLN slot.
- a conflicting share follows the existing reconstruct/slash behavior exactly once.

### 24.3 Ticket reservation

- six distinct tickets can each establish one upstream under the initial class.
- a seventh ticket or out-of-range index is rejected.
- wrong preimage is rejected before DNS.
- simultaneous duplicate spends result in at most one DNS operation and exactly one
  upstream establishment.
- changing target or request nonce while a ticket is reserved produces conflict.
- definite pre-connect failure releases only the owning reservation.
- ambiguous or post-connect failure leaves the ticket spent.
- loss of the `200` response after upstream establishment does not refund the ticket.

### 24.4 Multiplexing and flow control

- two or more CONNECT streams carry independent TLS byte sequences concurrently.
- reset of one stream destroys only its upstream socket.
- connection GOAWAY drains or resets children under the defined deadline.
- a stalled stream cannot accumulate unbounded buffers or block cleanup of another.
- HTTP/2 control traffic cannot reset the application idle timer.
- per-stream windows cannot multiply the shared directional rate.
- server push is disabled.
- forbidden HTTP/2 headers and malformed pseudo-header combinations are rejected.

### 24.5 Quotas

- combined count includes both payload directions.
- the final forwarded byte lands exactly on the configured hard ceiling; no chunk-sized
  overshoot occurs.
- all streams stop when the shared byte budget is exhausted.
- hard lifetime is not extended by payload or control traffic.
- concurrent active and pending-connect ceilings are enforced independently.
- byte/rate counters are released exactly once on every close race.

### 24.6 Compatibility

- a v4 client and v4 node path remain byte-for-byte unchanged with session support off.
- a session-capable client ignores nodes without a valid signed session capability.
- a legacy client ignores the additive session capability.
- capability canonical bytes and signatures match in JS and Rust.
- a mixed fleet can serve v4 and session clients during rollout.
- disabling the session listener removes the advertised capability.

### 24.7 Privacy

- node never receives plaintext inner HTTP headers in an integration test.
- target and ticket values do not appear in normal logs or metrics.
- session receipts/progress objects contain no ticket, nullifier, target, or fine timestamp.
- one session is explicitly classified as linkable at the node in docs and API policy.
- v4 `per-tunnel` mode remains available for clients preferring rotation.

### 24.8 Real Tor integration

- one Arti/Tor bootstrap creates one session to a real onion service.
- at least two concurrent outer CONNECT streams reach two controlled TLS destinations.
- both destinations observe the node egress IP, not the client IP.
- only one RLN proof verification is recorded for the session.
- ticket and byte counts agree between client progress and aggregate node metrics.
- killing one destination does not tear down the other stream.

---

## 25. Implementation backlog

These are intended to become independently reviewable engineering tickets.

### ST-SESSION-0 — protocol and threat-model lock

**Scope**

- accept this page or an ADR derived from it;
- freeze the metering unit, commit point, retry semantics, policy values, and privacy
  language;
- decide the session service-port defaults;
- add the feature to the protocol acceptance matrix.

**Acceptance**

- reviewers can answer exactly when a ticket is charged;
- the page never claims to count encrypted inner HTTP requests;
- session linkability and loss of per-tunnel rotation are explicit;
- unresolved choices are listed rather than silently delegated to code.

**Estimate:** 1-2 engineer-days.

### ST-SESSION-1 — pure ticket-book library and vectors

**Scope**

- implement ticket commitment, book digest, spend digest, parsing, and fixed policy table;
- generate language-neutral vectors;
- port pure functions to Rust.

**Acceptance**

- JS and Rust pass identical valid/tampered vectors;
- all parsers are total on arbitrary input;
- fuzz/property tests cover lengths, indices, duplicates, and encoding variants.

**Estimate:** 2-3 engineer-days.

### ST-SESSION-2 — session signal and RLN verification

**Scope**

- add domain-separated `sessionSignal()` construction;
- build the current RLN proof over that signal;
- verify public `x`, root, artifact, epoch, and share using existing primitives;
- bind the selected checksummed onion.

**Acceptance**

- no circuit or artifact change;
- current v4 signal vectors remain unchanged;
- any mutation of gateway/class/nonce/book fails before admission;
- conflicting share behavior matches v4.

**Estimate:** 2-3 engineer-days.

### ST-SESSION-3 — HTTP/2 initialization server

**Scope**

- add a dedicated loopback HTTP/2 listener;
- implement bounded initialization parsing and cheap-first checks;
- create/close connection-local session state;
- integrate graceful shutdown and global limiters.

**Acceptance**

- one valid proof admits one session and no upstream socket;
- malformed and adversarial initialization tests cannot hang or crash the process;
- all state is released on connection close and shutdown;
- feature remains off by default.

**Estimate:** 4-6 engineer-days.

### ST-SESSION-4 — CONNECT ticket reservation and relay

**Scope**

- parse never-indexed ticket credentials;
- implement ticket state machine and target-bound spend digest;
- reuse egress policy, DNS safety, upstream address iteration, and deadlines;
- bridge HTTP/2 DATA to upstream TCP with idempotent cleanup.

**Acceptance**

- concurrent duplicate ticket test creates at most one upstream socket;
- definite pre-connect failure and post-connect failure follow documented semantics;
- stream reset affects only the corresponding upstream;
- destination TLS remains opaque.

**Estimate:** 5-7 engineer-days.

### ST-SESSION-5 — shared quotas and shaping

**Scope**

- implement exact combined byte ceiling;
- add shared directional token buckets with bounded backpressure;
- enforce lifetime, idle, active-stream, and pending-connect limits;
- add aggregate metrics.

**Acceptance**

- no limit multiplies with stream count;
- hard byte ceiling has no chunk overshoot;
- control frames cannot extend idle lifetime;
- metrics contain no request/session identifiers.

**Estimate:** 3-5 engineer-days.

### ST-SESSION-6 — JavaScript session client

**Scope**

- dial before proof, generate ticket book, initialize HTTP/2;
- expose a raw child-stream API;
- schedule tickets and track local policy state;
- map coarse events and typed failures.

**Acceptance**

- two concurrent child streams work over one injected transport;
- secrets are marked never-index and never surfaced;
- client closes on policy mismatch;
- exhausted/expired sessions are never selected locally.

**Estimate:** 4-6 engineer-days.

### ST-SESSION-7 — loopback Proxy and SDK integration

**Scope**

- map local HTTP/1.1 CONNECT sockets to outer streams;
- use one stream per `ShadeTreeClient.fetch()` call;
- add explicit `per-tunnel` versus `bounded-session` policy;
- preserve v4 fallback without silent privacy downgrade.

**Acceptance**

- existing proxy tests remain green in per-tunnel mode;
- session mode reuses one onion connection for several local CONNECT requests;
- early local bytes are bounded and forwarded once;
- fallback behavior is explicit and observable.

**Estimate:** 4-6 engineer-days.

### ST-SESSION-8 — signed capability and rollout controls

**Scope**

- add canonical `caps.session` in JS and Rust;
- advertise only when the listener is configured and healthy;
- filter selection by version/class;
- add operator configuration, health checks, and documentation.

**Acceptance**

- bootnode cannot forge session support for an existing onion;
- legacy canonical vectors remain byte-identical when the field is absent;
- disabling listener and restarting removes the advertisement;
- mixed fleet selection is deterministic and fail-closed.

**Estimate:** 2-3 engineer-days.

### ST-SESSION-9 — Rust transport parity

**Scope**

- add HTTP/2 client support to `shadenet-egress`;
- implement session lifecycle, ticket allocation, and child stream adapter;
- integrate the Rust loopback Proxy and `run` path;
- consume shared vectors and acceptance fixtures.

**Acceptance**

- Rust client interoperates with JS node and vice versa where applicable;
- one Arti bootstrap/session carries concurrent child streams;
- crash-safe RLN allocation remains before proof and never rewinds;
- Rust cancellation/backpressure semantics match the reference tests.

**Estimate:** 6-9 engineer-days.

### ST-SESSION-10 — adversarial and real-Tor gate

**Scope**

- implement the complete matrix in section 24;
- add load, soak, malformed-frame, and shutdown-race tests;
- run a controlled real-Tor multi-target demonstration;
- record proof, ticket-check, and end-to-end latency.

**Acceptance**

- simultaneous duplicate ticket cannot obtain duplicate service;
- bounded memory under worst allowed concurrency;
- no target/ticket leakage in logs and metrics corpus;
- v4 release gates remain green;
- measured benefit justifies the extra session complexity.

**Estimate:** 5-8 engineer-days.

### Expected effort

- HTTP/2-over-Tor spike with fake admission: 3-5 days.
- JavaScript vertical slice through two controlled destinations: 3-4 engineer-weeks.
- Hardened JavaScript research-preview implementation: 4-6 engineer-weeks.
- Full JavaScript/Rust parity and real-Tor acceptance gate: approximately 6-8 weeks for
  one engineer, or less elapsed time with carefully partitioned parallel work.

These are planning estimates, not commitments. HTTP/2 cancellation/backpressure and
cross-language interoperability are the largest uncertainty, not ticket hashing.

---

## 26. Rollout plan

### Stage 0 — transport spike

- create an isolated experimental HTTP/2 listener;
- establish two CONNECT streams over one Tor/onion connection;
- use fake tickets and fake proof verification;
- prove backpressure, reset isolation, and clean shutdown.

**Exit:** two controlled TLS destinations work concurrently without custom framing.

### Stage 1 — cryptographic ticket prototype

- implement ticket book and session signal;
- verify one real RLN proof at initialization;
- enforce single-use ticket reservation locally;
- keep byte shaping disabled but hard-limit payload and lifetime.

**Exit:** duplicate-ticket race creates exactly one upstream connection.

### Stage 2 — JavaScript end-to-end mode

- integrate `ShadeTreeClient` and loopback Proxy;
- add full quotas, metrics, policy, and capability advertisement;
- preserve explicit v4 fallback;
- run deterministic adversarial suite.

**Exit:** several local CONNECT requests use one bounded session under all declared
limits, and Protocol v4 is unchanged.

### Stage 3 — Rust parity

- port client/session transport and shared vectors;
- run JS node <-> Rust client interop;
- add real-Arti lifecycle and cancellation tests.

**Exit:** the distributable client has the same safety and privacy policy as the JS
reference.

### Stage 4 — disposable live experiment

- enable on one invited-only test node under a new onion service port;
- advertise one fixed class;
- compare proof amortization, Tor latency, completion rate, bytes, and memory against v4;
- keep session mode opt-in and collect only aggregate metrics.

**Exit:** measured performance benefit, no unexplained quota divergence, and no privacy
or reliability regression large enough to outweigh session reuse.

### Stage 5 — broader policy decision

Only after the experiment decide whether to:

- retain session mode as an opt-in research-workload profile;
- make it available to staked/paid admission;
- add short-lived exact recovery;
- add another fixed policy class;
- pursue blind transferable tickets;
- pursue a real zkAPI credit adapter at API origins.

---

## 27. Relationship to zkAPI usage credits

The motivating zkAPI proposal has a user fund a deposit, select a ticket index `i`, prove
that maximum cumulative spend is covered by deposit plus authenticated refunds, and use
an RLN nullifier to make index reuse detectable or slashable. Its variable-cost version
updates a rerandomized, server-signed homomorphic refund total after service.

This session design adopts only the parts that fit Shade Tree's current transport:

| zkAPI concept | `session-v1` analogue |
|---|---|
| deposited/authorized user | member under invited, staked, or paid RLN root |
| expensive anonymous authorization | one RLN session proof |
| ticket index | fixed index in client ticket book |
| request nullifier | random ticket preimage commitment + node-local spent state |
| maximum request cost | fixed `research-v1` transport envelope |
| server execution | one upstream TCP establishment and bounded relay |
| spent-ticket database | connection-local ticket state array |
| refund | none |
| cumulative private balance | none |
| online seer | unnecessary because tickets are gateway/connection bound |

Calling this a complete zkAPI implementation would be false. It is a fixed-class,
connection-local transport specialization that lets us validate ticket lifecycle and
amortized authorization before designing money-like anonymous credits.

### 27.1 Why fixed classes come first

Fixed classes avoid:

- trusting a node to report an unknowable “actual” encrypted HTTP cost;
- ever-growing signed refund histories;
- rerandomizable signature/commitment machinery;
- balance-update serialization across parallel requests;
- a new circuit and trusted setup;
- disputes over partial service and refund amount;
- per-request pricing fingerprints.

The cost is overprovisioning: an unused ticket or byte allowance is not refunded. For a
short research session that is a reasonable first engineering trade.

---

## 28. Follow-on A: unlinkable blind bearer tickets

If tickets should be issued once and redeemed across fresh connections without the
issuer linking issuance to redemption, use a reviewed blind-token protocol rather than
extending the session book ad hoc.

Privacy Pass provides a useful architecture:

1. client proves eligibility to an issuer/attester;
2. issuer blindly issues fixed-class tokens;
3. client later redeems one token at an origin;
4. origin checks token validity and an atomic spent-token set.

For Shade Tree, an RLN proof could authorize one fixed-size blind issuance batch. A
publicly verifiable token could be checked by several nodes, but those nodes would still
need an atomic shared spent service before providing egress. A privately verifiable
token centralizes verification at its issuer.

Blind cryptography alone does not defeat timing and connection correlation. Issuance and
redemption should be separated in time and/or connection, ticket counts and classes
should be common, and issuer keys/challenges must not be client-specific.

This follow-on should be a separate protocol page because its fault model is materially
different from gateway-bound sessions.

---

## 29. Follow-on B: finite prepaid credit rather than subscription access

The current `PaidAccessSet` inserts a membership leaf whose private RLN limit refreshes
each epoch for as long as the leaf remains live. It is subscription-like access, not a
permanent balance of `N` consumable credits.

A finite fixed-price credit design needs decisions about:

- whether a top-up creates a fresh secret/leaf or updates a hidden balance;
- stable credit series or expiry rounds;
- root changes without resetting already-spent ticket indices;
- permanent versus round-bounded spent-nullifier retention;
- withdrawal and unused-credit refund;
- settlement proofs for the provider;
- atomicity across several redeeming nodes;
- replay after reorg or root rollback;
- how top-up amount/denomination affects anonymity sets.

One possible prototype is a fixed issuance cohort: one equal-denomination purchase adds
a fresh rate commitment with a lifetime/round message limit, and every spend uses a
non-time-resetting external nullifier scoped to that cohort. This might reuse much of the
current RLN circuit, but it cannot reuse current gateway epoch-freshness logic unchanged
and it needs bounded cohort expiry to avoid an ever-growing spent database.

Do not mutate `PaidAccessSet` semantics implicitly. Use a distinct contract/root source
and an explicit privacy label if finite credits are pursued.

---

## 30. Follow-on C: variable-cost refund credits

The full zkAPI-style variable-cost design is a separate research program. Before code,
it needs a standalone cryptographic specification covering:

- deposit and policy stake semantics;
- exact circuit statement for `D`, index, maximum cost, refund total, and membership;
- signature scheme verified inside the circuit;
- commitment rerandomization and unlinkability;
- parallel in-flight requests against one stale refund state;
- server under-refund and dispute behavior;
- client rollback/fork of refund state;
- lost response recovery;
- slashing and withdrawal races;
- proof size, generation latency, verification cost, and artifact ceremony;
- settlement batching and provider accounting;
- traffic-analysis leakage from cost, token count, timing, and response size.

It should start with a simulator and mock signed state, then a benchmark circuit, and only
then a contract or real-value integration.

---

## 31. Follow-on D: API-origin adapter

For a downstream API that wants to sell actual request units:

1. API returns a 402/PrivateToken/MPP-style challenge inside destination TLS.
2. `ShadeTreeClient` selects an anonymous-credit payment adapter.
3. Client obtains or selects a compatible ticket/proof.
4. Client retries the API request with that credential inside TLS.
5. API atomically marks the nullifier/token spent before executing the operation.
6. API returns its payment/usage receipt end to end.

The Shade Tree node remains a raw encrypted transport. It sees neither the challenge nor
the credential. This is the only truthful way to claim one ticket per actual API request
without giving the node plaintext application access.

An x402 custom scheme or MPP method can carry the credit proof so APIs do not need a new
unrelated HTTP negotiation universe.

---

## 32. Rejected alternatives

### One ticket per encrypted inner HTTP request at the node

Rejected because the node cannot identify inner request boundaries without terminating
TLS. HTTP/2 multiplexing makes byte-pattern heuristics especially unsound. Client-declared
markers could meter honest SDK behavior but could not enforce malicious-client request
count.

### Terminate destination TLS at the node

Rejected because it exposes plaintext requests, responses, cookies, prompts, and payment
credentials to the node and changes Shade Tree from a network-privacy layer into a trusted
application proxy.

### A custom binary multiplexing protocol

Rejected for the first implementation because HTTP/2 already provides concurrent
CONNECT streams, flow control, cancellation, mature parsers, and client libraries. A
custom format would recreate the riskiest parts of HTTP/2 without its interoperability
and testing history.

### Put a full RLN proof on every child stream

Possible, and closer to the original zkAPI request flow, but it fails the main
amortization goal. It preserves independent RLN nullifiers yet every child stream on one
connection is still linkable through transport metadata. Keep Protocol v4 for per-tunnel
proofs and rotation instead.

### Server-signed sequential session counter

A connection-local counter is cheaper than committed random tickets but gives no stable
client-owned retry object and prepares poorly for recovery. Signature verification on
every action is also unnecessary when all state is local to the issuer/verifier.

### Transferable ticket book in the MVP

Rejected because it immediately requires an atomic canopy-wide reservation service. The
current asynchronous tally can reduce accidental replay but cannot guarantee that two
nodes do not provide service concurrently.

### Quietly reinterpret current RLN tiers

Rejected because current limits count per-epoch proof slots. Multiplying each slot into
six child actions is a policy change that must be named, advertised, and deployed under
an explicit session class.

### Allow arbitrary client-requested quotas

Rejected because unique combinations fingerprint sessions and complicate operator cost
bounds. Begin with one fixed class and version new policy choices explicitly.

---

## 33. Open decisions before implementation

These do not block storing the roadmap design, but ST-SESSION-0 must close them:

1. Is six tickets the right first class, or should the spike use two and production use
   six?
2. Is the provisional public onion session port `81`, or should operators advertise a
   different default?
3. Does a definite DNS `NXDOMAIN` refund an unused ticket, or count as an attempted
   scarce action? This page currently refunds all definite pre-connect failures.
4. Should the byte limit terminate the whole session immediately or send GOAWAY and let
   only the stream that reached the boundary close cleanly? This page currently stops all
   streams because the budget is shared and exhausted.
5. What bounded drain interval follows the 90-second hard deadline?
6. Is inner TLS connection reuse ever allowed for the SDK, or must one fetch always own
   one child stream and one inner TLS connection? This page currently requires the latter.
7. Is short-lived exact book recovery necessary for the first live experiment?
8. Which HTTP/2 libraries and versions give both Node and Rust reliable sensitive-header,
   cancellation, and backpressure controls?
9. Should session mode be offered to all admitted roots initially, or invited-only during
   measurement?
10. Does one tier-1 RLN slot intentionally grant six child target tunnels, and are public
    bond/payment prices still defensible under that multiplier?

---

## 34. Ship/no-ship gates

Do not enable session tickets on a public profile until:

- ST-SESSION-0 through ST-SESSION-10 are complete or explicitly waived with rationale;
- the trusted-setup status is no weaker than the profile being advertised;
- exact duplicate-ticket races pass under load;
- aggregate byte and rate limits are proven not to multiply across streams;
- memory remains bounded under maximum sessions, streams, headers, and stalled peers;
- JavaScript and Rust conformance vectors match;
- real-Tor interop demonstrates more than one target over one onion connection;
- logging/metrics privacy review finds no ticket, target, or nullifier retention;
- operator documentation covers port, limits, health, shutdown, rollback, and disabling;
- client UI/docs state that session requests are linkable to the serving node;
- a measured latency or throughput improvement justifies the larger attack surface;
- Protocol v4 remains available as the simpler, per-tunnel-rotation mode.

---

## 35. References

- [Shade Tree Protocol](../specs/protocol.md) — current v4 one-proof/one-CONNECT-tunnel
  semantics.
- [ADR 0009](adr/0009-epoch-bandwidth-envelope.md) — provisional six-target, 40 MiB,
  90-second research-session envelope.
- [Payments](PAYMENTS.md) — shipped paid membership and the rule that hot-path checks
  should remain cheap.
- [Roadmap zkAPI track](ROADMAP.md#7-zkapi--anonymous-api-usage-credits--research-track)
  — anonymous-credit and distributed-seer research context.
- [ZK API Usage Credits: LLMs and Beyond](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104)
  — deposit, ticket index, RLN double-spend accountability, and refund-ticket proposal.
- [ZK API Usage Credits v2](https://hackmd.io/3da7PaYmTqmNTTwqxVidRg) — rerandomized,
  server-signed homomorphic refund state.
- [RFC 9113, HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html#name-the-connect-method)
  — one CONNECT tunnel per HTTP/2 stream and multiplexed stream semantics.
- [RFC 9576, Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html)
  — issuance/redemption roles and unlinkability requirements for future blind tickets.
- [RFC 9577, PrivateToken HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
  — application-layer token challenge and redemption.
- [RFC 9578, Privacy Pass Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
  — privately and publicly verifiable blind issuance variants.
