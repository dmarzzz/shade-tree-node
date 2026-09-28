# SLOs and error budget

Service level objectives for the fleet: a set of Shade Tree gateways plus a
discovery bootnode. This is milestone T-MON-5 in [SHIP-PLAN.md](history/SHIP-PLAN.md).

**Status: proposals, not commitments.** This is a reference implementation. The targets below are
starting points chosen to be honest and defensible, not numbers anyone has yet held over 30 days of
real traffic. They become measurable only once T-MON-2 (Prometheus metrics) and T-MON-3
(dashboards + alerts) land, and they should be recalibrated against the first month of real data.
Every target flagged **[NEEDS DATA]** is a guess until a production baseline exists.

The one rule that overrides every number here: **anonymity and membership-soundness are never traded
for an availability SLO.** They are correctness properties, not availability dials. If the only way to
hit a target is to weaken the gate, admit an unverified gateway, or narrow the anonymity set, you miss
the target. See the closing section.

## 0. What the research preview commits to (OPS-14)

The ShadeNet research preview on Sepolia runs on a **best-effort** basis. The only published
targets are these, measured over 30 days:

| Target | Measured by |
|---|---|
| The Elder answers over Tor with a fresh, signer-verified canopy 95% of probe runs | The hosted uptime probe (dispatched every 15 minutes) and the Lab-runner probe (every 5 minutes); runs where the probe's own Tor failed are UNKNOWN and excluded |
| At least 2 nodes are listed in the signed canopy 95% of probe runs | The same probes (`fleetSize`) |
| A paging alert is acknowledged within 24 hours | The canopy monitor's Matrix alert log |

Everything in sections 1 to 3 below is the longer-term model; its targets stay proposals until
there is real member traffic to calibrate them. Contact and escalation are in
[INCIDENT.md](INCIDENT.md#0-on-call-contact-and-escalation). The live surfaces are the canopy page
(`/canopy`, built from the signed public snapshot) and the Data API head
(`/api/v2/data/grove/sepolia/head`).

---

## 1. The SLIs that matter

An SLI is a ratio of good events to valid events, or a latency distribution. Each maps to metrics
T-MON-2 is adding. Metric names below are conceptual; use the actual names once T-MON-2 defines them.

| SLI | Definition (good / valid) | Source signal (maps to T-MON-2 metric) |
|---|---|---|
| **Egress success rate** | A valid member's request completes end to end (PASS + tunnel opened + bytes flow) / all requests from valid members | gateway PASS counter vs (PASS + non-gate DROP + upstream/tunnel errors); excludes gate DROPs, which are correct rejections |
| **Fleet availability** | Fraction of time >=1 healthy gateway is discoverable and dialable | directory-size gauge + external onion `/health`/dial probes (T-MON-4) |
| **Bootnode availability** | `GET /directory` responds AND the body verifies against the pinned signer | external onion probe of `/directory` + `/health`, plus a client-side `verifyDirectory` check (T-MON-4) |
| **Gate correctness** | No false DROP of a valid member (a member who should pass is not rejected). Measured **indirectly**: the false-DROP rate is inferred from the DROP-reason mix, not observed directly (the gateway cannot know a prover was honest). | drop counter broken out by reason (`root-not-recent`, `bad-target`, `rate-slashed`, `over-spend-slashed`, epoch-window); a spike in `root-not-recent` across many nullifiers is the false-DROP signal |
| **Proof-verify latency** | Server-side time to run `verifyEnvelope` (cheap-first checks + Groth16 verify) | verify-latency histogram |
| **Discovery freshness** | Time from a gateway going down to it dropping out of `/directory` | derived: bounded by TTL; measured as (now - last successful heartbeat) at drop time |

Two ratios that look like SLIs but are **correctness counters, not availability SLIs**: `slash` events
(a correct response to a member over-spend, not a failure) and announce accept/reject counts (a
rejected forged announce is the system working). They belong on the dashboard; they are not error
budget.

---

## 2. Proposed SLO targets

Each target names its measurement window. Windows are 30 days rolling unless noted, because that is
the shortest span over which a 99%-class target has enough events to mean anything.

### 2.1 Egress success rate: 99% over 30 days **[NEEDS DATA]**

A valid member's request completes end to end 99% of the time. "Valid member" excludes gate DROPs:
a member proving against a stale root or requesting a non-`:443` target is a *correct* rejection and
does not count against this SLI (that failure is the member's or a config mismatch, tracked separately
under gate correctness). What counts against it: the member had a good proof and a good target and
still did not get bytes, because no gateway was dialable, the chosen gateway dropped the tunnel, or
the upstream connect failed.

Why 99% and not higher: the request path crosses two Tor circuits (client->gateway rendezvous, and
the load test in [STATUS.md](history/STATUS.md) showed Tor circuit variance dominates the tail). Client-side
failover already routes around a single bad gateway (`reportHealth` marks a gateway `down` after 2
failures, `selectionOrder` tries the rest of the fleet), so most single-gateway failures are absorbed
and never reach the member as a failed request. 99% leaves headroom for Tor-level flakiness the
operator does not control. **[NEEDS DATA]**: no end-to-end success baseline for real member traffic
exists yet; the 1000-request load test is a proxy, not a 30-day member cohort.

### 2.2 Bootnode availability: 99.5% over 30 days **[NEEDS DATA]**

`/directory` responds and the body verifies against the pinned signer, 99.5% of the time, measured by
an external tor-capable prober (T-MON-4). 99.5% (about 3.6h/month of allowed downtime) rather than a
higher tier because: (a) a single bootnode today is one process on one box behind one onion
descriptor, and descriptor propagation alone can cost ~30s after a restart (OPERATOR.md); (b) clients
tolerate bootnode downtime by design, falling back to the last-known-good cached directory
([INCIDENT.md](INCIDENT.md) #1), so bootnode unavailability rarely becomes member-visible. The path to
a stricter target is redundant bootnodes (each its own onion + signer), not a heroic single instance.

Both halves of the SLI are required: a `/directory` that returns 200 but fails signature verification
is **not** available. A served-but-unverifiable directory is a security event (INCIDENT.md #2), not an
uptime success.

### 2.3 Fleet has >=2 healthy gateways: 99% of the time **[NEEDS DATA]**

At least two gateways are healthy and discoverable in `/directory` 99% of the time, sampled by the
prober. Two, not one, because the whole failover story (per-tunnel rotation, dial-timeout failover,
`down`-marking) needs somewhere to fail over *to*; a one-gateway fleet has no anonymity spread
(target metadata is 1/1, not 1/N) and no route-around. This is the SLI that most directly protects
egress success and anonymity at once. **[NEEDS DATA]**: depends entirely on how many gateways are
actually deployed; on today's small reference fleet this is aspirational and cannot be met with one
box.

### 2.4 Proof-verify latency: p95 < 50 ms, p99 < 100 ms (server-side) over 7 days

The gateway-side `verifyEnvelope` time. Grounded in the real numbers: a cached RLN proof verifies in
~10 to 32 ms, ~27 to 31 verifies/sec/core on the 2 vCPU reference box
([PAYMENTS.md](PAYMENTS.md), [ROADMAP.md](ROADMAP.md), adversarial-review.md). p95 < 50 ms leaves room
for GC and scheduling jitter above the ~30 ms typical; p99 < 100 ms bounds the tail. 7-day window
because latency regressions show up fast and a shorter window catches them sooner.

This is explicitly **server-side verify CPU only**, not end-to-end request latency. End-to-end latency
is dominated by Tor circuit build and RTT (hundreds of ms to seconds, highly variable per the STATUS.md
load test), which the operator does not control. Putting Tor RTT inside an SLO would make the SLO a
measure of the Tor network's health, not this system's. End-to-end latency is a dashboard line and a
capacity signal, not an SLO. If verify latency creeps toward the per-core throughput ceiling
(~30 verifies/sec/core), that is the signal to add cores or gateways before it becomes an egress-success
problem.

### 2.5 Discovery freshness: a down gateway leaves `/directory` within TTL + one sweep

A gateway that stops heartbeating drops out of the served directory within `SHADE_TREE_BOOTNODE_TTL`
(default 900s) of its last accepted announce, plus at most one sweep interval (`min(ttl,60)`s, so ~60s;
and `directory()` sweeps on every request anyway). So worst case ~960s, typically < 900s. This is a
*bound*, not a percentile: it is set by the TTL knob, so the "target" is really "pick the TTL that
matches how fast you need dead gateways to disappear." Shorter TTL = fresher directory but more
heartbeat load and less restart tolerance; 900s is the shipped default. Clients further protect
themselves below this bound by marking a non-responsive gateway `down` after 2 failed dials, so a dead
gateway stops being *selected* long before it ages out of the directory.

---

## 3. Error budget

The error budget is the allowed failure, `1 - SLO`, over the window. It is a quantity you spend, not a
line you must never cross.

| SLO | Budget over 30d |
|---|---|
| Egress success 99% | 1% of valid-member requests may fail |
| Bootnode availability 99.5% | ~3.6 hours of unavailability |
| Fleet >=2 healthy 99% | ~7.2 hours with <2 healthy gateways |
| Verify latency p95 < 50 ms (7d) | 5% of verifies may exceed 50 ms |

**Computing it:** budget_remaining = allowed_bad_events - actual_bad_events over the rolling window.
Example: egress success at 100k valid-member requests/30d gives a budget of 1000 failed requests; if
620 have failed 18 days in, 380 remain for the next 12 days. **Burn rate** is bad-events per unit time
against that budget: a burn rate that would exhaust the remaining budget before the window closes is
the alert condition (T-MON-3 owns the exact multi-window burn-rate alerts).

**What the operator does when a budget is burning** (tie-ins to [INCIDENT.md](INCIDENT.md)):

- **Egress-success budget burning + `root-not-recent` DROP spike** -> not an availability outage, a gate
  correctness/config problem. Follow INCIDENT.md #6 (mass-DROP spike): align `SHADE_TREE_EPOCH_SECONDS`,
  `SHADE_TREE_SLOTS`, `SHADE_TREE_RLN_IDENTIFIER`, and the root source across client and gateway; widen
  `SHADE_TREE_FRESHNESS_ROOTS` if a membership change out-ran the window. **Do not slash** (these are
  rejections, not over-spends).
- **Egress-success budget burning + dial/upstream failures, not gate DROPs** -> a capacity or
  gateway-health problem. **Add gateways** (section 2.3 exists for exactly this headroom) and/or pull
  the misbehaving gateway (INCIDENT.md #3: stop its heartbeat and let the TTL drop it, or cut stake in
  stake mode).
- **Bootnode-availability budget burning** -> INCIDENT.md #1. Members are cushioned by the LKG cache, so
  this is usually not member-visible; restore or restart the bootnode, and stand up a redundant bootnode
  so the next burn does not depend on one box. If `/directory` verifies-false rather than time-out,
  escalate to INCIDENT.md #2 (signer compromise), which is a security event, not budget spend.
- **Fleet-availability budget burning (<2 healthy)** -> add or restore gateways before egress-success
  starts burning; these two budgets are coupled.
- **Verify-latency budget burning** -> add cores or gateways before the throughput ceiling turns into a
  correctness-preserving backpressure that fails requests. Never respond by skipping or weakening any
  `verifyEnvelope` check to buy latency.

**Throttling new members** is a legitimate lever when egress-success budget is burning *because the
fleet is saturated* (verify throughput or gateway capacity is the bottleneck): slowing admission caps
load while you add gateways. It is the wrong lever when the burn is a config/root mismatch (throttling
admits fewer members but every current member still DROPs). Diagnose the DROP-reason mix first.

---

## 4. What is explicitly NOT an SLO here

- **Individual gateway uptime.** The fleet routes around a dead gateway (client failover +
  `down`-marking + per-tunnel rotation). A single gateway can be down for hours with zero egress-success
  budget spent, as long as the *fleet* SLI (>=2 healthy) holds. Chasing per-gateway uptime would optimize
  the wrong thing and could even push against rotating/retiring gateways, which is a normal operation
  (OPERATOR.md #6).
- **Anonymity, unlinkability, membership soundness.** These are **correctness properties, not
  availability SLIs.** "The gateway sees 127.0.0.1", "target metadata spreads to ~1/N across
  non-colluding gateways", "a valid RLN proof against a recent root is required", "a swapped onion fails
  the client's own key re-derivation" are true or violated, never "99.9% true." A violation is a security
  incident (INCIDENT.md #2, #3, #4), not a budget line. You cannot buy back an anonymity violation with
  uptime.
- **End-to-end (Tor-inclusive) request latency.** Dominated by the Tor network, outside the operator's
  control (section 2.4). A dashboard signal and capacity input, not an SLO.
- **Slash correctness / over-spend handling.** A slash is the rate limit working (INCIDENT.md #7), not a
  failure. Slash counts are monitored, never budgeted as errors.
- **Bootnode discovery trust.** The pinned signer controls the candidate list and can omit, reorder,
  or add entries if compromised. Availability is an SLI (section 2.2). Signer compromise is a
  security incident, not an availability-budget event.
- **On-chain / RPC availability.** Handled by fail-closed and last-known-good behavior
  (INCIDENT.md #5), not an egress SLO. A chain outage shrinks the fleet safely toward what was already
  admitted; it does not fail existing members' egress.

---

## 5. When these become real, and the hard line

These SLOs are **inert until the telemetry lands**:

- **T-MON-2 (Prometheus metrics)** supplies every source signal in section 1: pass/drop/slash counters,
  the verify-latency histogram, announce accept/reject counters, and the directory-size gauge. Until
  then the SLIs cannot be computed. Use T-MON-2's actual metric names when wiring these up; the names in
  this doc are conceptual.
- **T-MON-3 (dashboards + alerts)** turns the budgets in section 3 into multi-window burn-rate alerts and
  owns the exact alert thresholds.
- **T-MON-4 (external uptime checks)** is the source for the availability SLIs (2.2, 2.3): a tor-capable
  prober hitting onion `/health` and `/directory` from outside the box, which is the only way to measure
  availability as a member experiences it.

Recalibrate every **[NEEDS DATA]** target against the first 30 days of real metrics. The targets in
section 2 are defensible defaults, not measured commitments.

**The hard line, restated because it is the one that must never bend:** no availability SLO here
justifies weakening the gate, admitting an unverified gateway, serving an unverifiable directory,
narrowing the anonymity set, or skipping a `verifyEnvelope` check. When a target and a
correctness/anonymity property conflict, the property wins and the target is missed. An SLO is a
promise about availability; it is never a license to trade away the properties this system exists to
provide.
