# Shade Tree: build, deployment, and validation

**Status: historical report of the June 2026 single-gateway PoC (live and verified at
the time, both ends).** The current system (RLN per-tunnel proofs, on-chain stake,
bootnode fleet) is described in `README.md` and `docs/ROADMAP.md`. A clean-IP egress, reachable only
through Tor, that forwards to the clearnet for clients who prove in zero knowledge
that they belong to a curated set, and drops everyone else before a byte leaves.

This report is the record of what was built, what was deployed, and what we tested.
For the moving picture see [`walkthrough.html`](walkthrough.html); for the raw
experiment view see [`../experiments/dashboard.html`](../../experiments/dashboard.html).

## The problem

Tor exit IPs are a public, auto-blockable list with permanently bad reputation, so
honest Tor users get locked out of large parts of the web. The usual escape is a
residential proxy, which is an anonymity anti-pattern: you swap IP-reputation
evasion for a fully trusted third party who links every request to your billing
identity. The constraint underneath both is that an open clean-IP egress becomes a
blocklisted IP within hours, because spammers find it. Clean IPs stay clean only
because they are gated and scarce.

We gate the egress with a proof instead of an identity. The zero-knowledge
membership proof is what lets a clean-IP egress stay clean without ever learning
who its users are. It swaps per-IP reputation for per-member reputation that is
anonymous and portable.

## What we built

| Component | Role |
|---|---|
| `lib/semaphore.mjs` | Semaphore v4 group membership + epoch-scoped nullifiers (RLN-style anonymous rate limiting) |
| `gateway/gateway.mjs` | Onion-side egress proxy: verify the proof, match the trusted root, check the epoch, enforce the per-nullifier budget, tunnel `:443` only, drop on any failure |
| `client/shim.mjs` | Local CONNECT proxy: mint a proof, dial the onion over Tor, tunnel |
| `group/enroll.mjs`, `group/seed-demo-members.mjs` | Add members to the set (the trust boundary); mint a labeled demo set |
| split-role scripts | `run-gateway.sh` (server), `run-client.sh` (laptop), `join.sh` (friend), `verify.sh` / `gateway-status.sh` (receipts) |

The gate rides on top of Tor as a thin application-layer protocol. Tor cannot carry
the proof natively (cells are opaque, the exit speaks no application semantics), but
onion services make "use Tor as my destination" literally true: there is no exit
node, and the gateway never learns the client IP.

## What we deployed

- A DigitalOcean droplet (Ubuntu 24.04, NYC, 2 vCPU / 2 GB), hardened to inbound
  SSH only. The gateway needs no inbound port because the hidden service is
  outbound-only.
- Tor installed from the official Tor Project apt repo, so `tor --list-modules`
  reports `pow: yes`. The onion proof-of-work DoS defense is enabled in the torrc.
- The gateway and its tor run as two durable `systemd` services (`shade-tree-tor`,
  `shade-tree-gateway`), enabled, so they survive disconnect and reboot and restart on
  failure. The gateway binds `127.0.0.1:8443`; Tor maps the onion `:80` to it.
- The reputation set (`group/members.json`, public commitments only) was shipped to
  the box. Member secrets never left the laptops. The gateway holds no secret.

## Verification

**End to end, both ends agree.** A request from a laptop, dialing the onion through
a separate Tor instance, egressed from the droplet's clean IP and returned a 200
from Google. The gateway logged the matching `PASS` at the same epoch and nullifier.
The path crosses six real Tor relays (a 3-hop client half and a 3-hop service half
that splice at a shared rendezvous relay), with no exit node anywhere.

**The client IP is never delivered to the gateway.** This was checked on the box,
not assumed:

- the gateway binds `127.0.0.1` only, no public listener,
- every connection it accepts comes from the box's own tor over loopback, so the
  source address it sees is always `127.0.0.1`,
- the laptop's real public IP appears zero times in `gateway.log` and zero times in
  the tor journal,
- the envelope carries `{ v, target, proof }` and no IP; the nullifier is one-way.

The destination sees the droplet's IP, never the client's. The only parties that
see a client IP are its own ISP and Tor guard, exactly as in any Tor usage, and the
gateway is not among them.

## Experiments

Four hypotheses, run as real requests against the live gateway. All confirmed. The
gateway's own log corroborated the client view to the request: **16 PASS, 32 DROP,
7 distinct members**, all in one epoch.

| | Hypothesis | Method | Result |
|---|---|---|---|
| H1 | Distinct members egress independently | 5 members each send a proof | 5/5 admitted, **5 distinct nullifiers** |
| H2 | Only a valid proof in our set gets in | no-proof, garbage, forged-group, non-member | all dropped: `no-proof`, `invalid-proof`, `wrong-group-root`, and the non-member cannot even build a proof |
| H3 | A member cannot exceed its budget | budget lowered to 4, one member sends 8 | 4 admitted, then **4 rate-limited**, exactly at the cap |
| H4 | Spam cannot ban you or leak egress | 25 junk envelopes concurrent, then a real member | 25/25 rejected, **0 leaked**, real member admitted immediately after |

Drops broke down as 26 invalid-proof, 4 rate-limited, 1 wrong-group-root, 1
no-proof. The forged-group case is the real attack (a perfectly valid Semaphore
proof, against a set the attacker invented) and the trusted-root check defeats it.

## What holds, and what does not

Proven:

- Membership is necessary and sufficient to egress. The root check rejects invented
  sets.
- The per-nullifier budget throttles a member without learning the member.
- There is nothing to IP-ban: the gateway never sees a client IP, so the only lever
  against a member is its per-epoch budget, which touches only that one nullifier.
- Junk is cheap to reject: a failed proof costs a verify, never an egress.

Honest limits (see [`adversarial-review.md`](adversarial-review.md) for the
per-party worst case):

- **Enrollment is the trust root, and the PoC enroll tool hands the operator each
  member's secret.** Anonymity against the operator is not real until members
  self-generate their own identities. This is the first thing to fix.
- **Within-epoch linkability.** The nullifier scope is the public epoch, so a
  member's requests within the window share one nullifier. This is a limitation of
  the construction, not an inherent cost; the fix (hide and range-prove the scope)
  is scoped in the README's Future upgrades.
- **Replay within an epoch is allowed by design.** The cached proof is re-sent each
  request; it only ever travels inside the Tor tunnel.
- **Single clean IP at high volume still looks botlike.** Scaling is a
  fleet-of-clean-IPs question, out of scope for the PoC.
- **DoS scope.** Our flood test was functional (25 concurrent), not a saturation
  attack. The outer wall against real volume is Tor's onion proof-of-work defense,
  which raises the client's cost to reach the rendezvous before the zk gate runs.
- **Correlation.** A global adversary watching both uplinks can correlate timing.
  That is the standard Tor threat model, not a gateway leak.

## Reproduce

Server (the egress box): `bash scripts/run-gateway.sh` prints the onion. Full
procedure, invariants, and a verification matrix are in [`DEPLOY.md`](DEPLOY.md).

Laptop: `export SHADE_TREE_ONION=<onion>` then `bash scripts/run-client.sh` and
`bash scripts/verify.sh`. To hand the egress to a friend, give them their own key
and [`JOIN.md`](../JOIN.md); they run `bash scripts/join.sh <onion> <secret>`.

## Bottom line

The mechanism works as designed and is running live. A clean-IP egress now serves a
curated, anonymous membership over Tor, gates every request on a zero-knowledge
proof, rate-limits members without identifying them, and never learns who its users
are. The honest gap is enrollment: until members generate their own secrets, the
operator is trusted. That is the next build, not a question about whether the gate
itself holds. It does.
