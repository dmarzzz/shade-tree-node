# Adversarial design review

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

What is the worst each party can do? This walks every actor in the system, states
what it is trusted for, the worst it can achieve, what it provably cannot, and the
remediation. It is written against the PoC as it stands (`gateway/gateway.mjs`,
`client/shim.mjs`, `lib/semaphore.mjs`, `group/enroll.mjs`), not an idealized
version.

The one-line summary: the cryptography does what it claims against an **outsider**,
but the PoC's enrollment hands the operator every member's secret, so anonymity
against the **operator** is currently not real. That is finding 1, and it is the
one to fix first.

## Trust map

| Party | Trusted for | Not trusted for |
|---|---|---|
| Member (holds a set secret) | nothing | staying in budget, honest targets |
| Outsider (no valid proof) | nothing | anything |
| Gateway operator | availability, honest egress | confidentiality of metadata, anonymity |
| Enroller / set admin | the entire sybil boundary | restraint |
| Network / global observer | nothing | (Tor's standard limits apply) |
| Destination site (passive) | nothing | n/a |
| Destination that can obtain membership | nothing | enumerating + blocklisting the egress fleet |

---

## 1. Enroller + gateway operator (the same person, in the PoC): CRITICAL

**Worst case: full deanonymization of every request.**

`group/enroll.mjs` generates each member's secret with `randomBytes(32)` and prints
it. So whoever runs enrollment holds **every member's secret**. The Semaphore
nullifier is `H(scope, secret)`, and the gateway logs the nullifier on every
request (`PASS ... null=...`). With the secrets in hand, the operator recomputes
`H(scope, secret_M)` for each known member `M` and the public `scope`, and matches
it against the logged nullifiers. That maps **every request to the exact membership
that made it**.

In the PoC the enroller and the gateway operator are the same machine, so this is
not even a collusion assumption. The README's "client is anonymous to the gateway"
and "no identity anywhere" guarantees hold against a *third party*, not against the
operator who enrolled the members.

**What it cannot do:** read traffic content (TLS is end to end), or learn the
client's IP (rendezvous). So the leak is "which member, and what destination," not
"what they sent."

**Remediation (do this first).** Self-enrollment. The member generates its own
`Identity` locally and submits only the `commitment`. The secret never leaves the
member. The operator then knows commitments only, and `commitment = Poseidon(secret)`
is one-way, so it cannot derive any nullifier and the deanonymization closes
completely. This is a small change to `enroll.mjs` (accept a commitment instead of
minting one) and pairs naturally with the on-chain set in the README's future
upgrades, where members `addMember(commitment)` themselves.

## 2. Member (holds a valid secret): HIGH

**Worst case: vandalize the shared clean IP, within budget.**

A member can point the `:443` egress at any host and use it to scrape, spam, or
attack a third party. The whole value of the system is one clean egress IP, and any
authorized member can dirty it, up to `RATE_LIMIT` (30) redemptions per epoch. With
`N` members the aggregate is `N * 30` requests/hour against arbitrary targets, all
attributed to the gateway's IP. Nothing cryptographic bounds the *content* of that
traffic, only its rate.

Secondary: a member can hand its secret to other people. Because they then share one
nullifier, they also share one budget, so this does not amplify the rate, but it
does silently widen the membership beyond the admission policy.

**What it cannot do:** exceed its budget (per-nullifier dedup in `spend()`), forge
membership (zk soundness), or impersonate another member (needs that member's
secret).

**Remediation.** Smaller per-member budgets; destination allow/deny lists in
`validTarget`; per-destination budgets; and an eviction path (remove a leaf, or in a
staked set, slash) so abuse has a cost. The clean IP is only as clean as the worst
in-budget member, so admission and eviction are load-bearing.

## 3. Enroller as sybil source: HIGH (acknowledged)

**Worst case: mint unlimited memberships.** Whoever controls the leaf-adding
ceremony can add sybils and multiply the aggregate budget without bound. This is the
trust root; the proof gates on membership, it does not create reputation. The
on-chain upgrade moves this to whatever guards `addMember` (stake, token, DAO, World
ID), it does not remove it. Stated plainly in the README's honest limits; restated
here because it is an adversary, not a footnote.

## 4. Outsider (no valid proof): MEDIUM

**Worst case: CPU/connection DoS on the rendezvous.** An outsider who knows the
`.onion` cannot egress (the gate drops `no-proof` / `invalid-proof` /
`wrong-group-root`, verified by `scripts/probe.mjs`). But it can open circuits and
send well-formed-but-invalid proofs, each costing a full `verifyProof` (~30 ms of
CPU, measured). There is no client IP to rate-limit, because Tor. At volume this is
a CPU-exhaustion DoS on availability.

**What it cannot do:** egress, forge membership, deanonymize members, or read
traffic.

**Remediation.** The onion-service proof-of-work defense is the outer gate, now
wired opportunistically (`scripts/build-tor-pow.sh` + auto-enable in
`scripts/start-tor.sh`). Cheap defense-in-depth: reorder `checkProof` so the
cheap public checks (`scope` in range, `merkleTreeRoot` equals the trusted root)
run *before* the expensive SNARK `verifyProof`. That rejects lazy floods for free.
A determined attacker can still copy the real root and current scope into the
envelope and force the verify, so PoW remains the real answer; the reorder just
raises the floor.

## 5. Gateway operator as metadata/censorship point: MEDIUM (inherent)

Setting aside finding 1 (assume secrets are self-generated), the gateway still sees,
per tunnel: the per-epoch nullifier, the destination `host:port`, and timing and
volume. With that it can:

- **Profile a pseudonym.** Within an epoch every request from a member shares one
  nullifier (the PoC's known within-epoch linkability), so the gateway builds a
  per-epoch behavioral profile: which sites, when, how much. Future upgrade 1
  removes the within-epoch link; it does not remove the next point.
- **Re-link across epochs by behavior.** Nullifiers rotate each epoch, but a member
  who hits the same niche destinations at the same times every epoch is
  fingerprintable. Rotating nullifiers do not defeat traffic-pattern correlation.
- **Censor.** Selectively drop destinations or specific nullifiers.

**What it cannot do:** read TLS content (end to end), MITM a cert-validating client
(the shim only tunnels TCP; real TLS terminates at the client and the target), or
reach plaintext (egress is `:443` only).

**Remediation.** This is the residual the project is honest about. The correct
comparison is the residential proxy, which sees all of the above *plus* a billing
identity; this design strips the identity. Shrinking the metadata further (cover
traffic, per-tunnel destinations batched, multiple gateways) is its own project.

## 6. Network / global passive observer: inherent Tor limit

**Worst case: end-to-end traffic confirmation.** The egress hop (gateway to
destination) is deliberately *not* over Tor, so it is observable in the clear,
including the destination SNI/host. An adversary watching both the client's Tor
entry and the gateway's uplink can correlate timing and volume to confirm that a
client is using the gateway and what it fetched. This is standard Tor
confirmation-attack territory and out of Tor's threat model, but worth naming
because the clean-IP design intentionally exposes the egress side.

## 7. Destination site: LOW

Sees the gateway IP and the request. Can block or rate-limit the gateway, and learns
no member identity unless the application layer leaks it (logins, cookies), which is
user opsec, the same as any proxy. Colluding with the gateway gets it the metadata
graph of finding 5, still no identity (given finding 1 is fixed).

## 8. Proof replay / binding: LOW

The proof rides inside the Tor-encrypted tunnel to a single verifier, so an
eavesdropper cannot lift it. It is not bound to the request, though: `MESSAGE` is a
constant. A malicious gateway that also fronts a second egress could replay a
member's proof there. Minor under the single-gateway model; bind `MESSAGE` to the
target host to close it.

## 9. Client host / shim: LOW

The shim tunnels TCP and never sees plaintext (TLS is end to end), so a compromised
shim is a network position, not a content reader. It does hold `SHADE_TREE_SECRET`, so a
compromised client host is membership theft, the standard key-at-rest concern. Keep
the secret out of shell history and process listings.

## 10. Destination that can obtain membership: HIGH

**Worst case: enumerate and blocklist the entire egress fleet, collapsing the
unblockability the whole design exists for.**

Finding 7 is the *passive* destination: it sees the gateway's egress IP (the source
of the clearnet leg) and nothing else. That is benign — the gateway IP is published
by design. The dangerous variant is a destination that can also become a **member**.
A member can egress to a URL the destination controls and read the source IP, which
deterministically maps `onion hash -> egress IP` and tags that IP as an Shade Tree gateway.
In a multi-gateway fleet (see `docs/ROADMAP.md` §3), the adversary repeats this and
harvests *every* gateway's IP, then blocklists the set. This is exactly how Tor exits
are enumerated and killed (route through to a server you control, read the exit IP),
and it works against any open egress.

The reason it belongs as its own finding: the membership gate is usually described as
*rate limiting*, but it is **also the only thing keeping the egress IPs out of an
adversary's enumeration reach.** Tor exits die because Tor membership is open to
everyone, including the parties who want to block it. Shade Tree's sole moat is that the
adversary cannot join. If admission is open or cheap, the reputation gate collapses to
Tor's situation and the clean IPs are enumerable and blockable by lunch. So admission
is not just the sybil/rate boundary (findings 2, 3); it is the **unblockability
boundary**, and the set must specifically *exclude the parties who would blocklist
you*. A set that admits your adversary can be enumerated by your adversary, and no
amount of correct cryptography fixes that.

**What it cannot do:** learn any client/member IP (still behind Tor; the destination
is on the far side of the gateway). And without a valid proof it cannot even *trigger*
an egress — the gateway drops on `checkProof` failure before any `net.connect`, so
hash-without-membership yields no egress connection to observe. The membership proof
is precisely what gates the ability to cause the IP-revealing egress.

**Remediation.** Admission an adversary cannot cheaply pass (stake / invite / accrued
standing / proof-of-personhood). Partition which gateways a member can learn/use so a
single compromised member enumerates only its slice, not the fleet; treat the gateway
directory as members-only (§3). Rotating gateway IPs raises the cost of a stale
blocklist. None of these are cryptographic; this finding is a reminder that the
crypto's guarantees are bounded by who you let in.

## 11. Tor-layer & network adversaries: relay positions, correlation, self-deanon

Findings 1–10 are application/operator layer. This section is the network layer — Tor
relay positions and AS-level observers — grounded in the deanonymization literature
(guard discovery: Biryukov–Pustogarov–Weinmann 2013; the vanguards technical docs;
the 2014 RELAY_EARLY advisory; flow correlation: DeepCorr 2018 and the DeepCoFFEA
line; AS-level routing attacks: RAPTOR). Figures from very recent (2025–2026)
correlation papers are reported as direction-of-travel, not load-bearing.

### Single relay position — what it sees, what it can do

| Position | Client IP | Gateway IP | Onion addr | Deanon alone? |
|---|---|---|---|---|
| Client's entry guard | **yes** | no | no | no — needs the other end |
| Gateway's entry guard | no | **yes** | no | no — needs the other end |
| Middle (either side) | no | no | no | no |
| Rendezvous point | no | no | no | no |
| Introduction point | no | no | the addr it fronts | no |
| HSDir (v3) | no | no | **no** (blinded) | no |

Corrections to common belief, both load-bearing here:
- **The rendezvous point sees neither IP.** It sees the *middle* relay on each side
  and that the two circuits are paired (same cookie), and relays cells it cannot read
  — two hops short of either machine. The literature sweep flagged this as a "gap,"
  but it follows directly from the v3 circuit structure.
- **A v3 HSDir does not learn the `.onion` address.** Descriptors are stored under a
  *blinded* key and encrypted to the address, so an HSDir cannot derive or enumerate
  onion addresses. That was a v2 weakness (HSDir snooping / "honey onions"); v3 closed
  it. An HSDir learns only a blinded index and fetch timing/popularity.
- **The only IP-knowers are the two guards, each only on its own side.** The client's
  guard sees the client IP but does not know it is onion traffic; the gateway's guard
  sees the gateway IP (already public here). Neither links IP↔onion alone.

### The combinations that actually break you

| Adversary owns | Attack | Result |
|---|---|---|
| Client guard **+** gateway uplink/egress | end-to-end flow correlation | links client IP ↔ egress activity |
| Client guard **+** an RP/intro near the gateway | traffic confirmation | same, via an in-network foothold |
| Middle adjacent to the gateway's guard, repeated | guard discovery (Biryukov et al.) | finds the gateway's guard → then watch/coerce it |
| One AS/IXP on both side-paths | RAPTOR / asymmetric-routing | both-ends correlation **without running relays** |

**Why "both ends" is the whole game.** DeepCorr (2018) reported ~80–95% TPR at
10⁻³–10⁻⁴ FPR; the DeepCoFFEA line cut FPR further via metric learning + amplification;
recent work *reports* deep correlators near >99% TPR at ~10⁻⁵ FPR and robustness to
partial/noisy observation. Treat the newest numbers as trend, not fact, but the
direction is unambiguous: **an adversary who sees both ends wins, and no deployed Tor
defense (WTF-PAD, DeTorrent padding, Conflux splitting) closes the gap.** Tor never
promised to beat the both-ends adversary; this only sharpens how cheap that win is.

**AS-level is the realistic both-ends adversary, and it is worse for us.** A few large
ASes (Hurricane, Level3, **Hetzner** and hosting providers generally) sit on a majority
of guard/exit path probability; for some paths one AS sees both ends >20% of the time.
Two system-specific consequences: (1) the gateway lives in a **datacenter AS**
(DigitalOcean) — exactly the centralized vantage these studies flag — so the
gateway-side leg is disproportionately observable; (2) a datacenter egress IP is itself
a weak fingerprint, since destinations increasingly distrust hosting ranges, which
erodes the "clean IP" premise independent of any deanonymization. RELAY_EARLY (2014)
does not apply to v3 in its original form.

### The dominant real-world risk: client-side self-deanonymization

The literature is blunt that **most real deanonymizations are operational, not protocol
breaks.** This system inherits every one of them, because the shim is *only* a TCP
CONNECT proxy with none of Tor Browser's hardening:

- **DNS.** On the `curl -x … https://…` path the client sends `CONNECT host:443` and
  the *gateway* resolves the name, so there is no local DNS leak. But any app that
  resolves locally (a browser with proxy-side DNS off, a tool that pre-resolves) leaks
  *which sites* to the local network, bypassing the tunnel. Proxy-side DNS is mandatory
  and the shim does not enforce it.
- **WebRTC / fingerprint.** A browser pointed at the shim can leak the real IP via
  WebRTC ICE candidates and is linkable across sessions by canvas/WebGL/TLS (JA3/JA4)
  fingerprint regardless of IP. The shim supplies none of these defenses.
- **Accounts & cookies.** Logging in or carrying cookies ties activity to an identity
  in one request and defeats the whole stack. User opsec, same as any proxy.
- **Behavioral / timing linkability.** Hitting the same niche destinations on the same
  schedule re-links sessions even as the per-epoch nullifier rotates — and the constant
  within-epoch nullifier **amplifies** it: one successful correlation or fingerprint
  match attributes the member's *entire epoch*, not one stream (finding 5).

**Posture.** For machine-to-machine egress (the real use case) the CONNECT path avoids
DNS/WebRTC leaks and the residual is metadata + correlation. For anything
browser-driven this is **not** a Tor Browser substitute and must not be presented as
one. Net: strong on IP-reputation, only as strong as Tor on metadata, and **weaker than
Tor against a both-ends adversary, because the nullifier turns one hit into a day.**

---

## Priority order

1. **Self-enrollment (finding 1).** Until the operator stops holding member secrets,
   anonymity against the operator is not real. Highest priority, smallest change.
2. **Budget + eviction + destination policy (finding 2).** The clean IP is only as
   clean as the worst in-budget member.
3. **PoW + cheap-check reorder (finding 4).** Availability under flood. PoW is wired;
   the reorder is a few lines in `checkProof`.
4. **Unlinkable nullifiers (finding 5, partial).** Future upgrade 1 removes the
   within-epoch link; behavioral correlation remains.
5. **Client-leak hardening + honest positioning (finding 11).** Document and, where
   possible, enforce proxy-side DNS; warn that browser use leaks via WebRTC/fingerprint;
   never present this as a Tor Browser replacement. Cheap, and it closes the
   deanonymization vectors that actually bite in practice.
6. **AS / datacenter exposure (finding 11).** The single datacenter egress is the
   weakest both-ends vantage and a fingerprintable IP range. A future fleet
   (`docs/ROADMAP.md` §3) should spread gateways across diverse ASes, not just add IPs
   in one provider.
