# Roadmap: from the first Shade Tree prototype to a network

**Status: active design, updated 2026-09-01.** The original roadmap was written
against the first Semaphore PoC. Several of its headline items have since moved into
the implementation: members self-generate identities, the client/gateway use a real
RLN Groth16 circuit, an on-chain staked reputation set exists, and the client has a
fleet-aware library with per-tunnel gateway rotation. The remaining work is no
longer “make the PoC less toy.” It is to turn the construction into a coherent
network with explicit security properties, discovery, fleet-wide accountability,
egress-reputation management, and payment interoperability.

The protocol abstraction we should optimize for is broader than Tor:

> **anonymous access to a reputation-constrained shared resource.**

Tor onion egress is the first resource. The same gate could later protect API
capacity, search, model inference, datasets, or other scarce capabilities. Keeping
that abstraction explicit prevents the roadmap from accidentally baking properties
of one egress implementation into the protocol definition.

For detailed component designs, see [FLEET.md](FLEET.md), [ONCHAIN.md](ONCHAIN.md),
[PAYMENTS.md](PAYMENTS.md), [SESSION-TICKETS.md](design/SESSION-TICKETS.md),
[LIGHT-CLIENT.md](LIGHT-CLIENT.md), and [adversarial-review.md](history/adversarial-review.md).

The original milestone design notes (1–5: unlinkable rate limiting, on-chain set, fleet,
bootnode, productionization) live in [ROADMAP-v1.md](history/ROADMAP-v1.md); the checkable shipping
backlog with acceptance criteria is [SHIP-PLAN.md](history/SHIP-PLAN.md).

## Implementation status against this roadmap (2026-08-14)

What `feat/bootnode-and-productionize` (PR #5, merged to `main` 2026-08-16) already delivers,
mapped onto the sections below, so the roadmap reads as *remaining* work rather than restating what exists:

| Section | Built | Where |
|---|---|---|
| 2.1 fleet-wide RLN evidence exchange | **partial** — shared spent-nullifier tally across gateways (only `(nullifier, epoch)` on the wire, fail-open) catches a replay to a second gateway; cross-fleet *share* exchange and reconstruction is not wired | `packages/node/gateway/fleet-tally.mjs`, `docs/FLEET.md` |
| 2.4 client leak resistance | **partial** — per-tunnel Tor circuit isolation, endpoint hardening (bounded reads, strict parsers, adversarial tests on every wire surface) | `client/`, `test/adversarial.selftest.mjs`, `test/protocol-adversarial.selftest.mjs` |
| 3.1 discover onions, not egress IPs | **built** — the onion is never on chain; `GatewayRegistry` stakes an operator address only | `contracts/GatewayRegistry.sol`, ADR 0002 |
| 3.2 boot node = liveness layer, not trust root | **built** — announces carry onion-control (ed25519) + optional operator-stake signature; clients re-verify; bootnode can omit but not inject | `bootnode/`, ADR 0003, `docs/BOOTNODE.md` |
| 3.2 gateway record | **built (subset)** — signed `{ports, region, proto}` capability advertisement; clients select by capability and fail closed. `payment` and `sequence` fields not yet in the record | `packages/node/lib/directory.mjs`, `packages/node/bootnode/announce.mjs` |
| 3.3 / 3.4 join + client bootstrap | **built** — `shade-tree register-gateway` / `heartbeat`; client queries bootnode over Tor, verifies, caches last-known-good, rotates with failover | `packages/node/bin/shade-tree.mjs`, `docs/QUICKSTART.md` |
| 3.5 bootstrap v0 (one onion) | **built** | `packages/node/bootnode/server.mjs` |
| 3.5 bootstrap v1 (mirrors) | **built** — bootnode federation with gossip; every gossiped gateway re-verified through the full announce path; M-of-N threshold-signed directory removes the single signer | `packages/node/bootnode/federation.mjs`, `packages/node/lib/directory.mjs` (threshold) |
| 3.5 bootstrap v2 (on-chain registry + mirrors) | **built (registry)** — `GatewayRegistry` live on Sepolia; client can rebuild the *member* root from chain via EIP-1186 light-client proof; rebuilding the *gateway* set purely from chain is not yet a client path | `contracts/GatewayRegistry.sol`, `docs/LIGHT-CLIENT.md` |
| 3.5 bootstrap v3 (DHT) | not planned | — |
| 4–8 payments / x402 / MPP / zkAPI | **partial + design** — paid-access 402 issuance is built; downstream payment adapters and zkAPI credits remain design-only | `docs/PAYMENTS.md`, sections below |
| 7.5 gateway-bound session tickets | **detailed design** — one RLN proof authorizes a fixed book of cheap single-use CONNECT-stream tickets over one bounded HTTP/2/Tor session; no implementation yet | `docs/design/SESSION-TICKETS.md` |
| Distributable client | **built for v0.4.0** — the checksummed Rust `-live` binary creates identities, wraps one agent process, serves a loopback CONNECT Proxy over embedded Arti, and exposes the reusable §2.6 client; npm remains an operator/contributor dependency, not an agent dependency | `rust/`, `docs/CLIENTS.md` |

Not built and human-gated: the production trusted-setup ceremony and the first live
deployment (see SHIP-PLAN T-HARD-1 / T-DEPLOY-*).

---

## 0. Current baseline

The roadmap starts from the code that exists now, not from the June PoC.

| Capability | Current state |
|---|---|
| Anonymous ingress | Tor v3 onion-service rendezvous; gateway does not receive client IP |
| Membership | member self-generates secret; only the rate commitment leaves the client |
| Anonymous rate accountability | real RLN Groth16 proof, private message slot, per-epoch external nullifier |
| Over-spend consequence | two distinct shares under one nullifier reconstruct the identity secret and can slash the rate-commitment leaf |
| Request binding | RLN signal binds the proof to `(target, requestNonce)`; deterministic retry reuses the same signal |
| Admission | local set fallback plus `StakedReputationSet` / on-chain registration path |
| Fleet client | `ShadeTreeClient`, signed directory support, weighted per-tunnel gateway selection and failover |
| Transport | TCP `CONNECT :443`; TLS remains end-to-end between client and destination |
| Payments | separate design exists in [PAYMENTS.md](PAYMENTS.md), but payment is not part of the live request path |

Documentation reconciliation is itself a P0 item: a security property is not useful if the
code and the stated threat model describe different protocols. **Status (2026-08-17,
SHIP-PLAN T-DOC-8): done for the operator-facing set** — `OPERATOR.md`, `INCIDENT.md`,
`TOR-HARDENING.md`, `DEPLOYMENT.md`, `network/sepolia/README.md`, the bootstrap URLs and
the member-facing `JOIN.md` were reconciled against the code (superseded contract address,
bootnode persistence, replay defense, backup tooling, signer rotation, IP/onion hygiene).
Docs that describe the pre-RLN single-gateway PoC (`docs/JOIN.md`, `docs/history/STATUS.md`,
`docs/history/REPORT.md`, `docs/history/DEPLOY.md`, `docs/history/DEPLOYMENT.md`) are kept as history and now say
so at the top and point at the current path. `docs/THREAT-MODEL.md` and `docs/AUDIT.md`
are the current statements of the trust model; the design docs (`ONCHAIN.md`,
`LIGHT-CLIENT.md`, `FLEET.md`, `PAYMENTS.md`) carry a status line saying what of them is
built.

---

## 1. Define the protocol properties before adding more machinery

The PoC proves that the pieces can work. The next version needs properties stated in
a way that can be evaluated independently of a particular implementation. Each new
feature below should say which property it improves and which property it might
weaken.

### 1.1 Eligibility soundness

A party that is not in the currently accepted reputation set must not be able to
cause a clearnet egress. This is the basic gate property. Invalid proofs, stale roots,
wrong epochs, and malformed requests must fail before `net.connect`.

**Why it matters.** A single bypass turns the clean IP into an open proxy and destroys
its reputation. This is therefore both a cryptographic property and an economic
property.

### 1.2 Member anonymity

A valid gateway should learn that **some eligible member** made the request, but not
which member. The operator must not know member secrets and should see only proof
public signals, the target metadata needed to route, and traffic timing/volume.

**Why it matters.** “The gateway does not see the client IP” is weaker than anonymity.
If enrollment, payment, or repeated protocol identifiers name the member anyway, Tor
has not bought the property we actually want.

### 1.3 Request unlinkability

Two honest requests by the same member should not expose a stable identifier that lets
one gateway, or colluding gateways, join them into a profile. The current RLN private
message slots give distinct honest-use nullifiers; the property needs to remain true
when we add fleet coordination and payments.

**Why it matters.** Gateway rotation is only meaningful if the logs of multiple
gateways cannot simply be joined on a common pseudonym.

### 1.4 Global rate accountability

A member gets one network-wide budget, not one independent budget per gateway. Honest
use remains unlinkable; an actual over-spend must become detectable even when the two
conflicting shares land at different gateways.

**Why it matters.** Local RLN share collection is sufficient for one gateway but is
not sufficient for a rotating fleet. Without fleet-wide evidence exchange, rotation
becomes an easy way to evade slashing.

### 1.5 Admission integrity / the unblockability boundary

The cryptography proves membership; it does not manufacture reputation. The admission
policy has to make it expensive or difficult for the parties who want to abuse or
blocklist the egress fleet to acquire unlimited memberships.

**Why it matters.** An admitted adversary can send traffic to a server it controls,
observe the source egress IP, and learn that gateway's clean IP. If every adversary can
join cheaply, the network eventually recreates a public Tor exit list. Admission is
therefore not just the Sybil boundary; it is the **unblockability boundary**.

### 1.6 Gateway authenticity and discovery integrity

A client must be able to discover gateways without trusting the discovery server to
invent or substitute them. Discovery may affect availability and ordering, but it
should not become a new authority that can forge gateway identity.

### 1.7 Egress non-enumerability, as a best-effort property

The system should avoid publishing a complete mapping from gateway identity to clean
clearnet IP and should limit how much of the fleet one admitted adversary can cheaply
enumerate.

This is not absolute cryptographic secrecy: a member that is allowed to use a gateway
can always request a server it controls and observe the source IP. The goal is to
avoid making enumeration free and global, and to limit the blast radius of one
compromised membership.

### 1.8 Payment-to-use unlinkability

If a member pays, the payment identity must not silently become the request identity.
We should distinguish:

- **network anonymity:** destination does not see the member's IP;
- **membership anonymity:** gateway does not learn which member;
- **payer anonymity / payer-use unlinkability:** destination and gateway cannot link a
  request to the wallet/account that funded it.

x402 or MPP can preserve the first property while losing the third. Payment support
must state which mode it provides.

### 1.9 Content confidentiality

The gateway should remain a raw tunnel and must not terminate destination TLS merely
to add payments or policy. It necessarily sees destination `host:port`, timing, and
volume; it should not gain plaintext request/response content.

### 1.10 Censorship and availability robustness

A gateway can always refuse service and a discovery node can always omit records. The
system should make these failures detectable and route around them, not pretend they
can be cryptographically eliminated.

### 1.11 Credential lifecycle and transferability

An RLN secret is still a bearer credential. A member can share it; the parties then
share one budget and one slashing risk, but the protocol does not prevent sharing.
Revocation, exit, key loss, rotation, and optional anti-sharing economics need to be
specified as lifecycle properties rather than left as operator procedures.

### 1.12 Explicit non-goals

The system does **not** by itself hide an application identity if a user logs into a
site, defeat a global passive traffic-correlation adversary, or stop an admitted
member from learning the source IP of a gateway it is allowed to use. Those are
separate problems. The roadmap should improve them where practical without claiming a
stronger anonymity model than Tor provides.

---

## 2. Close the fleet-level gaps the PoC does not solve

### 2.1 Fleet-wide RLN evidence exchange — P0

**Problem.** Today a gateway slashes when *it* sees two distinct public `x` values for
the same RLN nullifier. With gateway rotation, an over-spender can send one conflicting
share to gateway A and the other to gateway B. Each gateway sees a valid first share;
neither reconstructs the secret.

**Design.** Gateways exchange only cryptographically self-verifying abuse evidence,
not normal browsing metadata. A candidate evidence record should contain the RLN proof
(or enough proof material to independently verify it), root, external nullifier,
nullifier, `x`, `y`, protocol version, expiry, and a gateway signature. It should **not**
contain the target hostname. Any peer can verify that the share came from a valid proof
before admitting it to the short-lived evidence set.

- First valid share for a nullifier: cache it until the relevant epoch expires.
- Same `x` again: idempotent retry; ignore it.
- Second valid, distinct `x`: reconstruct the identity secret, derive the commitment,
  and submit the slash.
- Invalid/unverifiable evidence: discard before it can poison the collector.

The first transport can be a small replicated evidence service reachable over onion.
Later it can be gossiped among gateways or folded into the bootstrap network. The
important invariant is that **honest requests never need a global join key**; only reuse
of the same nullifier creates a cross-gateway record.

**Why this is better than a global request counter.** RLN already gives exactly `K`
private message IDs. We do not need to send every honest request to a central counter.
We only need conflicting shares for the *same* nullifier to meet. That keeps normal
traffic unlinkable while making cross-gateway over-spend slashable.

**Acceptance test.** Generate two valid proofs that reuse one private slot with two
different request signals, send them to two different gateways, and show that neither
gateway alone can slash but the evidence layer reconstructs and slashes exactly once.

### 2.2 Preserve the reputation of the scarce resource — P0/P1

**Problem.** ZK membership prevents outsiders from using the IP, but a valid member can
still dirty it within budget. The clean IP is only as good as the worst authorized
traffic that reaches it.

**Work.** Add controls that operate on metadata the gateway already has rather than
breaking TLS:

- per-destination connection and concurrency budgets in addition to the global RLN
  budget;
- byte/time ceilings so one allowed request cannot become an unbounded tunnel;
- separate egress pools for new/unproven members versus high-standing members;
- multi-provider / multi-ASN / multi-region fleet diversity so one provider or range is
  not the whole reputation surface;
- canary probes and external block/reputation checks for gateway IP health;
- quarantine/retire tooling for an IP whose reputation is deteriorating;
- gateway capacity and reputation weights in client selection;
- operator-visible aggregate abuse metrics that do not require storing member request
  histories.

**Why it matters.** This is the operational half of the protocol. Strong ZK around a
single abused IP produces a beautifully authenticated blocklisted proxy.

### 2.3 Limit fleet enumeration by admitted adversaries — P1 research

**Problem.** A member that can use every gateway can enumerate every egress IP by
requesting a server it controls through each gateway.

**Direction.** Do not make every membership valid at every gateway forever. Explore
member-to-gateway assignment where each member can prove, in zero knowledge, that it is
eligible for a rotating subset of the fleet without revealing which member it is.
A simpler intermediate version can use multiple admission groups / gateway shards; a
later version can derive an epoch-specific assignment from the member secret and
`gatewayId` inside the circuit.

**Property.** Compromising one membership should reveal only its assigned slice of the
fleet, while honest clients still get enough gateways for failover and geographic
choice.

### 2.4 Client leak resistance and protocol surface — P1

The shim only protects traffic that actually uses it. Production clients need a
fail-closed mode and a test suite for bypasses: DNS, IPv6, direct sockets, redirects,
proxy environment differences, and applications that silently ignore proxy settings.

The current egress is TCP `:443` only. Keep that as the safe default. If QUIC/UDP is
ever added, treat it as a separate protocol extension with the same gate semantics;
do not silently fall back to direct UDP from the client.

### 2.5 Reduce operator trust without overstating what is possible — research

A gateway still sees destination metadata and can selectively censor. It can also lie
about what it logs. Possible hardening includes reproducible gateway builds, signed
software/version receipts, transparency around gateway policy, and optionally an
attested execution environment for a no-log / constrained-egress implementation.

A TEE would reduce operator discretion but would add hardware/vendor trust and should
be an optional stronger deployment mode, not a prerequisite for the base network.

### 2.6 Reusable in-process Rust client — P2

**Implementation status (v0.4.0).** The reusable core now lives in the
non-crates.io `shadenet-egress` workspace crate. Its async public surface is
`Client`, `ConnectRequest`, `ProofRequest`, `SlotPolicy`, `Connected`, and
`Gateway`. The CLI remains the policy/configuration shell: it verifies signed
directories, applies capability/admission filters, negotiates artifacts, and
passes the ordered candidates and proof inputs into the crate.

Completed architecture:

- [x] One Proxy-lifetime multi-thread Tokio runtime and one `Arc<Client>` serve
  all CONNECT workers. The client stores one successfully bootstrapped base
  `Arc<TorClient>` in a Tokio `OnceCell`; each logical tunnel gets an
  `isolated_client` view reused only across that tunnel's candidate failover.
- [x] `BlockingProver` admits Groth16 jobs through a bounded semaphore and runs
  them with `spawn_blocking`, outside the async network executor. Proxy admission
  has the same bounded worker count and queue, returning 503 before slot
  allocation when full.
- [x] The public `connect` API accepts no raw message slot. Production callers
  use `SlotPolicy::CrashSafe`, which durably allocates inside the crate before
  proof construction; the explicit unsafe variant is limited to slashing tests.
- [x] `shade-tree proxy` and one-shot `shade-tree egress` consume the same client
  for slot allocation, proving, failover, Arti transport, gateway acknowledgement,
  and the accepted bidirectional stream.
- [x] The loopback Proxy requires an unpredictable URL-safe token of at least 32
  characters, and `run` authenticates its preflight before it puts Basic
  credentials only in the child-scoped proxy URLs. Gateway acknowledgements and
  bootnode HTTP I/O have bounded deadlines.
- [x] FFI remains out of scope. Non-Rust agents use the loopback CONNECT Proxy;
  Rust callers can use a Git/path dependency because the crate is not published
  on crates.io.

Acceptance evidence is intentionally split rather than overstated:

- [x] `two_tunnels_share_one_injected_bootstrap` opens two tunnels through one
  client and observes one injected transport bootstrap; a separate bounded-prover
  test proves the concurrency ceiling.
- [x] `restart_never_rewinds_a_consumed_slot` covers crash/restart persistence.
- [x] The always-green Proxy interop sends two real Rust proofs through one
  long-lived Proxy and has both accepted by the JavaScript gateway over its
  deterministic plain-TCP transport.
- [x] The gated Hermes harness opens two CONNECT tunnels through Rust `run` and
  one long-lived embedded-Arti Proxy, requires two gateway acceptances, and
  asserts the Proxy reports exactly one successful Arti bootstrap.
- [x] Release-commit gate closed 2026-09-01: the real-Hermes/Arti harness passed
  locally with the post-release relay-close/harness fixes, and the pre-fix v0.4.0
  commit `db074e4` independently passed remotely in
  [GitHub Actions run 33576017408](https://github.com/dmarzzz/shade-tree-node/actions/runs/33576017408).
  T-RUST-5 is complete, without changing the unaudited, untrusted-testnet status
  or the separate production trusted-setup gate.

---

## 3. Gateway bootstrap / discovery service

The existing signed directory is the right **record format** but not yet a network
bootstrap mechanism. Add boot nodes whose job is to help a fresh client find current
gateway records.

### 3.1 Important correction: discover gateway endpoints, not public egress IPs

A gateway is reached through its `.onion`; the client does not need its clearnet egress
IP to route. Therefore a public bootstrap response should contain the **onion endpoint
and authenticated gateway metadata**, not the clean IP.

Publishing `{ onion -> egress IP }` would hand blocklisters the list that membership is
supposed to protect. If there is ever a use case that genuinely needs the exact egress
IP before use, make that a separately authenticated/member-gated feature and document
that it weakens non-enumerability. The normal client should learn an egress IP only as a
consequence of using the gateway, if it needs to learn it at all.

### 3.2 Boot node is a liveness layer and discovery trust boundary

A boot node can return, omit, reorder, or cache gateway records. The pinned directory
signer controls which records a client sees. Gateway-signed records should narrow that
trust by proving onion control and, once available, an on-chain `GatewayRegistry`
stake or registration. The current compact directory does not include the full signed
announcement, so signer compromise remains a selection risk.

A gateway record can look roughly like:

```json
{
  "protocol": "shade-tree/1",
  "onion": "...onion",
  "gatewayKey": "...",
  "sequence": 42,
  "expires": 1780000000,
  "region": "us-east",
  "capabilities": ["rln-v3", "connect-443"],
  "payment": ["none", "x402-v2", "mpp-charge"],
  "weight": 100,
  "stakeRef": "eip155:.../0x...",
  "signature": "..."
}
```

The public record deliberately omits `egressIp`. Fast-changing observed health should
be returned as boot-node observation metadata, separate from the gateway-signed record,
so a gateway is not signing the monitor's opinion of its own uptime.

### 3.3 Gateway join flow

1. Gateway creates / loads its onion identity.
2. Gateway constructs a signed, expiring service record.
3. Optional but preferred: gateway registers its identity + metadata hash + stake in a
   dedicated `GatewayRegistry` contract. Do not overload the member reputation set;
   gateways and members are different actors with different slash conditions.
4. Gateway submits the record to any boot node, or boot nodes learn it from registry
   events and fetch the signed metadata.
5. Boot nodes probe the onion for liveness and publish their observation separately.

Stake is primarily a Sybil cost at first. Only add slashing conditions when the
misbehavior is objectively provable; “the destination timed out” is not enough evidence
to slash a gateway.

### 3.4 Client bootstrap flow

1. Ship the client with several seed boot-node onion addresses and/or an on-chain
   registry address.
2. Query multiple seeds over Tor in parallel.
3. Union the returned records.
4. Verify record signature, onion-key binding, expiry, protocol version, and optional
   registry inclusion/stake locally.
5. Merge health observations as advisory data; never let one boot node redefine gateway
   identity.
6. Cache the last-known-good set.
7. Feed verified candidates into the existing weighted selection/failover code.

If step 4 is implemented for every candidate, a dead boot service should degrade to cached
gateways and a malicious mirror should be limited to censoring its own answer. The current
compact directory does not carry each record signature and therefore still trusts the pinned
directory signer as described in section 3.2.

### 3.5 Deployment stages

**Bootstrap v0 — centralized service, self-authenticating records.** One small onion
service serves the signed records. This removes GitHub-commit discovery while keeping
the existing pinned/signed semantics.

**Bootstrap v1 — multiple mirrors.** Run several independent boot nodes; client queries
2–3 and unions verified records. Because records self-authenticate, mirrors can be
permissionless caches.

**Bootstrap v2 — on-chain gateway registry + mirrors.** Chain is the canonical membership
of the gateway set; boot nodes become low-latency indexes and health observers. A client
can recover from a fully malicious boot layer by rebuilding the registered gateway set
from chain, analogous to the member root provider.

**Bootstrap v3 — optional gossip/DHT.** Only pursue this if fleet size makes seed mirrors
a real bottleneck. A DHT adds eclipse/Sybil complexity; it is not automatically more
decentralized than several self-verifying mirrors.

### 3.6 Relationship to API discovery

Do not conflate gateway discovery with paid-API discovery. x402 and MPP both have service
metadata/discovery mechanisms. Those tell an agent **what API exists and how it wants to
be paid**. Shade Tree boot nodes tell the client **which anonymous egress gateways exist**.
The client can consume both, but they are different trust domains.

---

## 4. Payments: separate the two problems first

There are two payment questions and they should not be mixed:

1. **Pay for Shade Tree itself.** How does a member buy/stake/renew access without making its
   later requests linkable to the payer? The strongest current design is still
   [PAYMENTS.md](PAYMENTS.md): anonymous on-chain deposit / commitment plus off-chain ZK
   redemption, with no required facilitator.
2. **Use Shade Tree to access a paid downstream API.** How does an anonymous client satisfy an
   x402, MPP, or future zkAPI payment challenge while preserving the desired privacy
   properties?

x402 and MPP are valuable interoperability targets, but neither should silently replace
the native privacy-preserving access-funding design. Depending on the chosen payment
method they may introduce a facilitator, payment processor, wallet identifier, or
persistent merchant session. Those can be acceptable modes; they just need explicit
privacy labels.

The general payment API should therefore expose a policy such as:

- `direct`: member pays the destination itself;
- `delegated`: gateway/payment agent pays the destination on the member's behalf;
- `anonymous-credit`: member spends an unlinkable prepaid credit (future zkAPI-like
  mode).

---

## 5. x402 interoperability

x402 V2 is an HTTP `402 Payment Required` payment standard with pluggable payment
schemes, facilitators, discovery, and current schemes including exact, usage-bounded
(`upto`), and batch-settlement patterns. Treat x402 as a protocol adapter, not as the
identity model of Shade Tree.

### 5.1 x402-A: transport compatibility — P1, very small

First prove that an ordinary x402 buyer can use the existing local Shade Tree proxy unchanged:
TLS and the HTTP 402/payment headers remain end-to-end between client and API; Shade Tree is
only the transport. Add an interoperability test and example before adding custom code.

**Privacy.** This hides the client's network IP from the API, but the API still sees
whatever wallet/payment identifier x402 exposes. It is **network-private, not
payer-anonymous**.

### 5.2 x402-B: native `ShadeTreeClient` buyer adapter — P1

Add an x402-aware request loop to the library for agents that use `ShadeTreeClient.fetch`
directly rather than a generic HTTP proxy:

1. make request through Shade Tree;
2. receive the destination's 402 challenge end-to-end;
3. invoke the configured x402 payment method;
4. retry through Shade Tree with the payment credential;
5. return the x402 receipt alongside the Shade Tree gateway receipt.

Start with `exact`; add `upto` / batch settlement only when there is a real workload that
needs them.

### 5.3 x402-C: delegated payer / privacy adapter — P2

This is the interesting mode. Do **not** terminate destination TLS at the gateway.
Instead:

1. client receives the destination's x402 challenge over its end-to-end TLS connection;
2. client sends the challenge over a separate authenticated onion control request to its
   selected Shade Tree gateway/payment service;
3. the gateway pays/signs with a gateway-owned x402 wallet and returns the payment
   credential to the client;
4. client retries the destination request end-to-end using that credential;
5. member is charged separately through its Shade Tree anonymous balance/credit mechanism.

The destination can now link the payment to the **gateway**, which is already the public
egress identity, rather than to the hidden member. This turns Shade Tree into a privacy adapter
for machine payments without giving the gateway plaintext API content.

**Open issue.** Pricing and fraud risk move to the gateway: it must not spend a $10
payment for a member whose anonymous balance covers $0.10. The authorization from member
to gateway therefore has to bind `maxAmount`, destination/challenge hash, expiry, and
idempotency before the gateway signs or settles anything.

### 5.4 x402 seller mode for Shade Tree access — optional

Shade Tree itself could respond with x402 to sell access. That is useful for adoption, but a
plain x402 purchase can reveal a payer wallet to the Shade Tree operator. If seller mode is
added, label it a convenience/privacy-weaker mode unless issuance is blinded or the
payment buys an anonymously redeemable commitment as in `PAYMENTS.md`.

Do not call direct x402 membership purchase “anonymous payment” merely because the later
network request uses Tor.

Official reference: <https://docs.x402.org/introduction>.

---

## 6. MPP interoperability

MPP (Machine Payments Protocol) is an HTTP machine-payment protocol co-authored by
Tempo and Stripe. Its current model supports one-shot `charge`, high-frequency
usage-based `session`, subscriptions, multiple payment methods, and discovery metadata;
its TypeScript stack also supports compatible x402 exact flows.

### 6.1 MPP-A: direct charge compatibility — P1

As with x402, first make the simple path work through the Shade Tree transport. A client gets
an MPP 402 Challenge, signs an authorization Credential, and receives a Receipt. This
should remain end-to-end through the tunnel.

**Privacy.** The destination sees the MPP payment identity/credential semantics. Shade Tree
hides the client IP but does not magically make that payment unlinkable.

### 6.2 MPP-B: native client adapter — P1/P2

Expose MPP from `ShadeTreeClient` so an agent can select `charge` as a payment method without
running a separate proxy stack. Reuse one internal `PaymentAdapter` interface for both
MPP and x402 so we do not fork the request lifecycle.

MPP already supports x402 exact through the `mppx` SDK, so an implementation should
investigate whether `mppx` can be the compatibility layer while Shade Tree remains the custom
transport.

### 6.3 MPP-C: gateway-owned sessions — P2

MPP `session` is attractive for LLM tokens, streamed bytes, and other high-frequency
usage because the client authorizes a funded session once and then incrementally raises
the cumulative authorization off the hot on-chain path.

A member-owned session, however, is intentionally persistent state with a merchant and
can become a stable payment pseudonym. For the strongest Shade Tree privacy mode, make the
**gateway/payment service own the MPP session** to the API while anonymous members debit
against the gateway internally. The destination sees one or more gateway payment
sessions, not a member session.

This pairs naturally with per-tunnel gateway selection only if session routing is
explicit: either pin paid traffic to a gateway for the lifetime of that gateway-owned
session, or let several gateways maintain independent provider sessions and select among
them. Do not accidentally move a member-specific session identifier across gateways.

### 6.4 MPP seller mode for Shade Tree access — optional

MPP can also sell the egress service itself via charge/session/subscription. As with
x402 seller mode, this is an interoperability/convenience path and must not overwrite
the stronger payer-use unlinkability goal in `PAYMENTS.md`.

Official references: <https://mpp.dev/> and the MPP session/discovery specifications.

---

## 7. zkAPI / anonymous API usage credits — research track

**Status: theoretical. There is no implementation to integrate today.** Treat zkAPI
as a protocol research project that can later become a payment method for Shade Tree, x402,
or MPP rather than pretending an SDK exists.

The intended primitive is an **anonymous prepaid API credit**:

1. user funds or acquires a credit commitment;
2. per tunnel, the client proves in zero knowledge that it owns a valid credit and
   presents a request-specific nullifier;
3. the service verifies the proof and checks that nullifier against a spent set before
   serving;
4. the payment/funding event is unlinkable to the eventual API use;
5. repeated/double use is rejected and, where RLN-style construction is used, can be
   made punishable.

This is closely aligned with Shade Tree because both systems are already asking the same
question: **how do I authorize a scarce action without naming the authorized actor?**

### 7.1 The central design fork: online check vs channel

**Online spent-nullifier check (“the seer”).** The server checks a live spent set before
serving. This preserves a large shared anonymity set and gives pre-service double-spend
prevention without pinning the user to a persistent payment channel.

The cost is an online coordination point. A single seer can censor, fail, or become a
metadata aggregation point even if it cannot identify the payer.

**Payment/channel approach.** A channel or session makes repeated payments cheap and can
avoid a global online spent set, but the payer establishes persistent state with a
specific counterparty/funding output. That is excellent for throughput and worse for
the strong payer-use unlinkability target.

This is why MPP sessions and zkAPI are complementary rather than substitutes: MPP
sessions optimize repeated bilateral payment; zkAPI is trying to preserve anonymous
fungible usage across a larger set.

### 7.2 “Distribute the seer”

The research direction is to replace one online spent-set authority with a committee or
replicated service:

- nullifier state replicated across independent operators;
- threshold/quorum response before a spend is accepted, or a BFT/consensus layer with a
  clearly specified finality window;
- clients/gateways query over anonymity-preserving transport;
- committee sees only the minimum proof/nullifier material, not payer identity or API
  plaintext;
- equivocation / stale-state behavior is detectable;
- service remains available under some subset of failed/censoring seers.

The hard question is not “can we put a database behind a SNARK?” It is whether the
online check can prevent double service **before** the API response while keeping
latency, metadata leakage, and operator trust low enough to beat a channel for the use
case.

### 7.3 zkAPI research deliverables

Before implementation, write a standalone spec with:

1. actors: payer, credit issuer/funding contract, API, seer/committee, optional gateway;
2. exact properties: funding-to-use unlinkability, double-spend safety, liveness,
   censorship resistance, request unlinkability, and settlement correctness;
3. credit commitment and nullifier construction;
4. what state the online checker stores and for how long;
5. race semantics for two simultaneous spends;
6. refund/expiry/denomination behavior;
7. committee fault model and latency budget;
8. proof/circuit choice and benchmark target;
9. a simulator/mock-credit prototype before real value is involved.

Only after those exist should we build a real circuit or contract.

### 7.4 Make zkAPI an adapter, not another HTTP universe

The best end state may be to expose zkAPI credits through existing machine-payment
standards:

- **x402:** a custom V2 payment scheme/extension whose payment payload is a zkAPI proof +
  nullifier and whose verifier is the spent-set/committee;
- **MPP:** a custom payment method (initially `charge`-like) whose Credential carries the
  zkAPI proof and whose Receipt names the accepted credit spend.

That would let APIs keep one 402 negotiation surface while choosing among transparent
stablecoin/card payments, bilateral sessions, or anonymous ZK credits.

### 7.5 Gateway-bound session ticket books — scoped/P1-P2

There is a smaller, buildable ticket mechanism between today's one-proof-per-tunnel v4
transport and a future transferable zkAPI credit. A client can exchange one existing RLN
proof for a fixed, short-lived book of random single-use tickets at one selected gateway,
then spend one ticket for each logical HTTP/2 CONNECT stream over the same Tor connection.

The complete design is [SESSION-TICKETS.md](design/SESSION-TICKETS.md). Its first policy class
implements the provisional research envelope from ADR 0009: at most six target streams,
40 MiB combined payload, a 90-second hard lifetime, bounded concurrency, and shared
directional shaping. The proof binds the gateway onion, class, session nonce, and ticket-book
digest; the gateway atomically reserves and commits each ticket before providing service.

This is deliberately **not** called one ticket per HTTP request. Destination TLS remains
end to end, so the gateway can enforce only one ticket per outer CONNECT stream. An honest
`ShadeTreeClient.fetch()` can map one fetch to one stream, while a true LLM/RPC/API request
credit must be verified by that API inside TLS. All child streams in one session are linkable
to the serving gateway, and gateway-bound books avoid a distributed seer only because they
cannot move across the fleet.

The scoped implementation backlog is ST-SESSION-0 through ST-SESSION-10. The first version
reuses the current RLN circuit, accepted roots, target policy, and paid/staked admission;
it adds a separate HTTP/2 onion-service port and does not change Protocol v4 or any contract.

---

## 8. One payment adapter layer inside Shade Tree

Do not implement x402, MPP, and zkAPI as three unrelated branches in the networking
code. Add a small internal interface that separates payment negotiation from transport.
Conceptually:

```text
PaymentAdapter
  canHandle(challenge) -> bool
  authorize(challenge, policy) -> credential
  describePrivacyMode() -> direct | delegated | anonymous-credit
  consumeReceipt(response) -> receipt
```

`ShadeTreeClient` owns transport and gateway selection; payment adapters own payment
negotiation. The gateway directory/bootstrap record may advertise supported delegated
payment modes, but payment support must not be confused with gateway authenticity.

This also gives agents an explicit policy knob: “prefer anonymous-credit; otherwise use
delegated MPP; never expose my wallet directly,” rather than making privacy an accidental
consequence of whichever SDK handled the 402 first.

---

## 9. Suggested sequencing

### Phase A — make the protocol truthful and fleet-safe (P0)

- reconcile README / STATUS / ROADMAP / adversarial review with the current RLN v3 code;
- publish the protocol-property definitions above;
- build cross-gateway RLN evidence exchange and the two-gateway over-spend test;
- add egress connection/byte/destination budgets and IP health/quarantine tooling;
- make credential lifecycle and revocation procedures explicit.

**Exit condition:** rotating gateways cannot be used to evade the network budget, and
the documented guarantees match the implementation.

### Phase B — bootstrap the gateway network (P0/P1)

- boot-node v0 onion service serving self-authenticating gateway records;
- multi-seed client fetch/verify/union/cache;
- separate observed health from signed identity metadata;
- design/deploy `GatewayRegistry` if the staked gateway set is ready;
- do **not** publish clean egress IPs in the public bootstrap record;
- begin gateway-sharding / anti-enumeration research.

**Exit condition:** a fresh client can discover and authenticate the live fleet without a
GitHub directory update, and compromise of one boot node cannot insert a fake gateway.

### Phase C — payment interoperability (P1/P2)

- x402 transport test, then `ShadeTreeClient` x402 exact adapter;
- MPP direct `charge` test and adapter;
- unified `PaymentAdapter` interface and privacy-mode policy;
- prototype delegated-payer control flow while preserving end-to-end destination TLS;
- evaluate gateway-owned MPP sessions for high-frequency paid APIs;
- keep native Shade Tree access funding in `PAYMENTS.md` as the strongest payer-use-unlinkable
  mode.

**Exit condition:** an agent can reach paid x402/MPP APIs through Shade Tree with an explicit,
tested choice between direct payment identity and gateway-delegated payment identity.

### Phase D — gateway-bound session tickets (P1/P2)

- lock the session-ticket protocol, fixed policy class, privacy label, and commit point;
- prove ordinary HTTP/2 CONNECT multiplexing over one Tor/onion connection;
- implement ticket-book commitments and the gateway-bound RLN session signal;
- build the JavaScript node/client vertical slice with exact duplicate-spend prevention;
- enforce shared byte, time, rate, pending-connect, and concurrent-stream limits;
- advertise the separate session endpoint with onion-signed capabilities;
- add Rust parity only after the JavaScript transport and adversarial semantics stabilize;
- keep Protocol v4 as the explicit per-tunnel privacy/fallback mode.

**Exit condition:** several target tunnels share one bounded onion session after one RLN
proof; every upstream establishment consumes exactly one ticket; simultaneous duplicate
spends cannot both receive service; TLS stays end to end; and session-level linkability is
explicitly surfaced.

### Phase E — zkAPI research and prototype (research/P2+)

- standalone zkAPI spec;
- formalize online-seer vs channel tradeoff;
- design distributed-seer fault model;
- mock-credit prototype with simultaneous-spend tests;
- benchmark proof + online check latency;
- only then build an x402 scheme and/or MPP payment-method adapter.

**Exit condition:** zkAPI has a threat model, a reproducible prototype, and a measured
reason to exist relative to MPP sessions and ordinary x402 payments.

### Phase F — harder privacy / decentralization (later)

- member-specific gateway subsets to limit fleet enumeration;
- multiple independent bootstrap mirrors / optional gossip;
- gateway staking and only objectively provable slash conditions;
- optional attested gateway profile;
- traffic-analysis mitigations where they have measurable benefit;
- broader transport support only when it can fail closed.

---

## 10. Roadmap acceptance matrix

A feature is not “done” because its happy-path demo works. The milestone tests should
include at least:

| Property | Required test |
|---|---|
| Eligibility soundness | non-member / wrong-root / stale / malformed proof never creates upstream socket |
| Member anonymity | operator enrollment path never receives the member secret |
| Request unlinkability | honest requests across slots/gateways expose no stable member identifier |
| Global rate accountability | conflicting slot use split across two gateways reconstructs + slashes once |
| Bootstrap integrity | pinned directory signer is a documented selection trust boundary; signed node data remains independently checkable when present |
| Bootstrap availability | all boot nodes down -> cached last-known-good fleet still works |
| Egress non-enumerability | public bootstrap output contains no clearnet egress IP mapping |
| Payment privacy labeling | direct x402/MPP mode explicitly exposes payer identity semantics; delegated mode does not expose member wallet to destination |
| TLS confidentiality | payment support does not require gateway TLS termination |
| Session-ticket single use | two simultaneous spends of one connection-local ticket create at most one upstream socket; post-connect failure never refunds it |
| Session-ticket truthfulness | one ticket is documented and tested as one outer CONNECT stream, not an invisible inner HTTP request; all streams share the advertised byte/rate/lifetime envelope |
| Rust client lifecycle | two CONNECT tunnels share one bootstrapped base Arti client but use separate circuit-isolation views; crash/restart never rewinds the RLN slot cursor; the CLI Proxy and crate pass the same gateway acceptance vectors |
| zkAPI safety | simultaneous duplicate credit spend cannot both receive service under the declared fault model |

The standard for the next version should be: every architectural claim maps to one of
these properties, and every property has an adversarial test or an explicitly stated
assumption.
