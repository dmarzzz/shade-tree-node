# Response timing, shaped tunnels and cover traffic

- **Status:** analysis, decision pending; ADR after staging measurements. Nothing here is shipped.
- **Last updated:** 2026-10-23.
- **Tracking:** roadmap [#369](https://github.com/dmarzzz/shade-tree-node/issues/369) (M0 records
  the threat, M2 builds shaped return timing and cover); related
  [#379](https://github.com/dmarzzz/shade-tree-node/issues/379) (session-book expiry cuts long
  responses at 90 s) and [#380](https://github.com/dmarzzz/shade-tree-node/issues/380) (every
  tunnel gets its own Tor isolation group, so tickets of one book never share a circuit).
- **Companion docs:** [`THREAT-MODEL.md`](../THREAT-MODEL.md) §4.3, §5;
  [`FLEET.md`](../FLEET.md#a-rogue-gateway-is-a-free-both-ends-vantage);
  [ADR 0009](../adr/0009-epoch-bandwidth-envelope.md), [ADR 0011](../adr/0011-session-tickets.md),
  [ADR 0013](../adr/0013-the-proxy-is-a-scheduler.md).

This page does four things. It states the response-timing attack in ShadeNet's own terms and says
who can run it today. It works out what a round-based anonymous broadcast network would and would
not buy on top of Tor, and lands on the mechanism that fits this protocol: constant-rate shaped
tunnels, which only the node can provide on the return path, and which the client can check. It
designs cover on the same mechanism, with real traffic riding inside the standing cover and useful
bytes as filler. It then costs each step in both rate and monthly volume. Nothing here is out of
scope; the things not fixed are listed as not fixed, with what would fix them.

The attack is not new to this project. A [public writeup](https://x.com/VitalikButerin/status/2111046730959433793)
of an anonymizing setup in front of a paid LLM API (zkAPI credentials, Tor, a per-conversation
circuit, cover traffic; code on the
[`feat/client-concession-local` branch of zkapi](https://github.com/vbuterin/zkapi/tree/feat/client-concession-local))
names it as the weak point of Tor-based cover: a provider that colludes with the user's guard and
manipulates its own response timing. ShadeNet sits in exactly that position for agents, including
agents run inside sandboxes such as [monkeybox](https://github.com/vbuterin/monkeybox), so it has to
say what it does about it.

---

## 1. The attack, in ShadeNet's terms

The traffic path today ([`specs/protocol.md`](../../specs/protocol.md) "Two planes"):

```
agent ──► Proxy ──► guard ─► middle ─► rendezvous ─► node's 3 hops ──► Shade Tree node ──► destination
          (local)   Tor, client side              Tor, node side        (.onion, exit)      (clearnet, TLS e2e)
```

Everything between the Proxy and the node is Tor cells. The node is an endpoint of the tunnel, not
a relay: it sees TLS record sizes and timing in the clear and forwards them as they arrive. The only
shaping today is the per-session token bucket (`packages/node/gateway/session.mjs:makeTokenBucket`,
512 KiB/s down with a 1 MiB burst). That bucket is a rate cap, and a destination's timing passes
through it unchanged whenever the destination sends below the cap, which is nearly always. The
destination sees the node's IP.

The destination controls when its response bytes leave. If it delays them in a pattern (a
watermark: gaps of chosen lengths, a burst schedule, an interval-centroid shift), the pattern
survives Tor, because Tor adds jitter but preserves order and rough timing, and it arrives at the
client's guard as a pattern of cells on one circuit. A party that sees both the destination's send
times and the guard's receive times links `client IP ↔ this tunnel ↔ this destination`. The client
cannot do anything about it: it is not the sender.

Who can be that party:

| attacker pair | what each side sees | what today's protocol does about it |
|---|---|---|
| **destination + client's guard** (or the client's ISP, or an AS on the uplink) | destination: the response it watermarks, the node IP, the account or cookie the agent used; guard: client IP, the cell timing | nothing. The node forwards faithfully, so an honest node does not help. Per-tunnel nullifiers bound one hit to one request. |
| **node + client's guard** | node: destination, nullifier, TLS record sizes and timing in both directions, and it can inject delay itself; guard: as above | `FLEET.md` already records this as the worst case. Rotation gives any one node ~1/N of a member's tunnels; per-tunnel nullifiers bound the blast radius. |
| **destination + observer at the node's egress** (A4) | both ends of the clearnet leg | no client identity on that leg; harmless alone, dangerous combined with the guard. |

Four properties of agent traffic make this worse than the browser case:

1. **The loop is serial and half of it is lit.** An agent fetches, thinks, fetches. The "think"
   step is usually a model-API call that `shadenet run` deliberately keeps off ShadeNet (ADR 0013,
   the default bypass list). So the destination does not even need the guard: delay the response,
   and the agent's next model call, visible to its ISP and to the model provider, is delayed by the
   same amount. The watermark is read off a different flow. This page calls it the *lit loop*.
2. **Response sizes are a watermark too.** A destination can vary how many bytes it sends. Over Tor
   that becomes cell counts, which the guard also sees.
3. **Token streams leak by their timing.** A streamed LLM completion sends roughly one token per
   event; [Whisper Leak](https://arxiv.org/abs/2511.03675) classifies prompt topic from event sizes
   and timing alone at often above 98% AUPRC across 28 models. One framed token event (about 323
   bytes after SSE, HTTP/2 and TLS framing, estimated from the OpenAI chunk schema) fits in one Tor
   relay cell, so Tor cell timing reproduces token timing for the guard, and the node additionally
   sees record sizes ([token-length side channel](https://arxiv.org/abs/2403.09751)).
4. **Agents make long, regular sessions.** Watermarks need hundreds to thousands of packets
   ([RAINBOW](https://people.cs.umass.edu/~amir/papers/NDSS09.pdf),
   [interval-centroid](https://www.freehaven.net/anonbib/cache/Wang-SP2007.pdf),
   [FINN](https://people.cs.umass.edu/~amir/papers/ACSAC21-FINN.pdf)); an agent session supplies
   them. Far-end marks are shown to survive Tor congestion control on the live network
   ([DUSTER](https://www.usenix.org/conference/raid2019/presentation/iacovazzi),
   [INFLOW](https://cris.iucc.ac.il/en/publications/inflow-inverse-network-flow-watermarking-for-detecting-hidden-ser/)).

The threat model lists "timing and traffic metadata" as a separate correlation channel (§4.3) and
puts the global passive adversary out of scope (§5). The pair above is not a global adversary. It is
one website and one guard, and for an agent that talks to a model API, it is one website alone.
This page treats it as in scope and not fixed.

## 2. What rounds buy on top of Tor, and what they do not

A round-based anonymous broadcast network closes the channel by construction: every participant
receives the same round output at the same time, so a server's delay changes content, never timing,
and the receiver's flow carries no per-user signal. The cost is the broadcast, which multiplies both
the bytes on the wire and the round-trip time over a three-hop Tor path. That is the wrong trade
for an agent fetching pages today, and this protocol deliberately has no multi-hop or broadcast
layer of its own (ROADMAP §3, THREAT-MODEL §5). It stays the direction for the strongest property
(#369, later milestones).

Take the two halves of the round fix apart:

- **Rounds alone** (the node releases destination bytes only at round boundaries) shrink the
  channel from fine timing to "which round", roughly `log2(rounds in a tunnel)` bits per tunnel.
  They do not remove it. A destination that delays across a boundary still moves a cell.
- **Constant rate** (the node sends the same number of cells every interval whether or not the
  destination has answered) is the part that removes the channel on the Tor leg. The guard sees a
  stream whose timing is fixed by the node's clock, not by the destination. Response size becomes
  how long the content portion lasts inside the stream, invisible unless the stream ends when the
  content does.

**Why constant rate and not light padding.** Modern learned correlators win against cheap padding.
[DeepCoFFEA](https://www-users.cs.umn.edu/~hopper/deepcoffea.pdf) (IEEE S&P 2022) keeps 90% and
84% TPR at FPR 1e-3 against [WTF-PAD](https://arxiv.org/abs/1512.00524) (27.5% bandwidth overhead)
and [FRONT](https://www.usenix.org/conference/usenixsecurity20/presentation/gong) (33%), using 25 to
35 s of traffic; [ESPRESSO](https://github.com/notem/ESPRESSO-Flow-Correlation) reports over 90% TPR
at FPR 1e-6; [RECTor](https://arxiv.org/abs/2512.00436) works on partial observations. Only
constant-rate regularization ([BuFLO, Tamaraw](https://www.cs.uwaterloo.ca/~iang/pubs/webfingerprint-ccs14.pdf),
[CS-BuFLO](https://www.freehaven.net/anonbib/cache/wpes14-csbuflo.pdf), constant traffic in
mixnets) holds up, and Tamaraw's bounds are proofs, not measurements. ShadeNet's adversary is an
*active* destination, which is stronger than any passive correlator, so "light padding" is not an
option worth building.

So the mechanism that fits ShadeNet is a **shaped tunnel**: a fixed cell size and a fixed cell rate
in both directions for a fixed lifetime, with padding cells filling idle time. Rounds fall out of it
(one cell interval is one round). Broadcast is not needed because the guard never sees content,
only timing, and the timing is now the node's.

Why this is the node's job and not the client's: the client already controls upstream timing and
can pace itself. Downstream, the first party on the return path that is not the destination is the
node. Nobody else can set the rate. A Tor exit cannot add a framing layer to a TLS stream it does
not terminate, while a Shade Tree node already speaks a framed protocol with the client (the v4
envelope, the `{"ok":true}` ack, session tickets). Mixnets learned the same rule:
[a study of website fingerprinting on Nym](https://www.petsymposium.org/popets/2026/popets-2026-0055.pdf)
found its return path did not apply the cover rate by default, and [Loopix](https://arxiv.org/abs/1703.00536)
providers answer each pull with a constant number of messages. The party that answers has to shape
the answer.

### The property worth having: the client can check it

A shaped tunnel is a commitment the receiver can verify. The client knows the ideal schedule (cell
*i* should arrive near `t0 + i/r`) and measures the deviation. Under a constant-rate commitment, a
deviation above Tor's own queueing noise is a fault, whether the destination caused it (an honest
node absorbed it wrongly) or the node injected it (a rogue node). The client can mark that node down
and route around it, per tunnel, with no coordination. Most padding schemes are promises the user
cannot audit; this one is checkable. It does not make a rogue node harmless (§7): a node that injects
2 to 10 ms delays (RAINBOW or FINN scale) sits inside Tor jitter and is not detectable per tunnel.
Evidence accumulated across many tunnels at one node improves the odds roughly with the square root
of the number of tunnels. The detection floor is a number to measure (§6), not "below jitter".

## 3. Shaped tunnels: the design

Everything below is additive and off unless both sides agree, in the same way session tickets are
(ADR 0011). A plain v4 tunnel stays byte for byte what it is.

### 3.1 Cell: 498 bytes, one Tor relay cell

A Tor RELAY_DATA cell carries at most 498 bytes of stream data (a 509-byte body minus an 11-byte
relay header, [tor-spec "Relay cells"](https://tpo.pages.torproject.net/core/torspec/tor-spec/relay-cells.html)).
A 512-byte ShadeNet cell would spill into a second relay cell and cost two 514-byte wire cells. One
ShadeNet cell is exactly one relay cell:

```
cell (498 bytes)
  type(1) ‖ stream(2) ‖ len(2) ‖ payload(493)
  type: 0 data | 1 pad | 2 fill | 3 end | 4 open | 5 credit | 6 reset
```

`open` carries a ticket and target for a sub-stream inside a pipe (§4), `credit` is in-band flow
control, `reset` ends a sub-stream. Every cell is the same size and leaves on the same tick. The cell
size goes in the capability, so a later relay-cell format can change it without a protocol bump.

### 3.2 Classes, fixed at open

Rates are in cells per second; wire figures use 514-byte Tor cells.

| class | down cells/s | up cells/s | down payload | down on the wire | for |
|---|---|---|---|---|---|
| `low` | 32 | 8 | 16 KB/s | 16 KB/s | RPC, `canopy` filler, keep-alive |
| `infer` | 128 | 32 | 63 KB/s | 66 KB/s | SSE completions, small API calls |
| `page` | 512 | 128 | 252 KB/s | 263 KB/s | page fetches, search |

- **`infer` at 128 cells/s** covers a one-token-per-event stream up to 128 tokens/s with no added
  delay. A 1,000-token answer is about 323 KB, about 5 s of pipe time, while the model itself takes
  longer at typical frontier speeds. Very fast hosted models become pipe-bound; that is acceptable
  for a paranoid profile.
- **`page` at 512 cells/s** puts ADR 0009's 600 KiB per-document estimate at about 2.4 s minimum,
  and sits above Tamaraw's inbound rate, so its bound holds with margin.
- **4:1 down:up.** Tamaraw found an out:in cell rate near 1:3.3 efficient for web traffic, and the
  session books already cap upstream at 64 KiB/s against 512 KiB/s downstream
  (`packages/node/lib/session-tickets.mjs`).
- **Three classes, ratio 4.** Every free parameter is a fingerprint: three classes are a crowd,
  arbitrary values are a name.
- **The rate is fixed when the tunnel opens and never changes inside it.** A tunnel that idles at a
  low rate and speeds up when data arrives shows its start time as the rate change. An agent that
  needs `page` speed inside an `infer` pipe either waits or opens a second pipe of class `page` at
  session start.

A node that offers shaping advertises it in its onion-signed capabilities, next to `session`:

```jsonc
"shape": {
  "version": 1,
  "cell": 498,
  "classes": ["low", "infer", "page"],
  "filler": ["random", "canopy"],   // see §4.3
  "machines": null                  // reserved for serialized Maybenot machines (§3.6)
}
```

### 3.3 Lifetimes double; a stream is never cut

A shaped tunnel's lifetime starts at 30 s and doubles while a stream is still running: 30, 60, 120,
240, 480, 960 s. That is six buckets, at most 2.6 bits per tunnel and at most 2x the needed time,
the trade [CS-BuFLO](https://www.freehaven.net/anonbib/cache/wpes14-csbuflo.pdf) makes when it pads
a stream to the next power of two. A long SSE completion is never cut; it moves into the next
bucket. If it finished early, the tunnel idles at full rate until its bucket ends, sending `end`
cells: that is the cost of hiding the response size. A stream longer than 960 s continues on a
fresh tunnel opened before the old one closes. This also settles the session-book side of
[#379](https://github.com/dmarzzz/shade-tree-node/issues/379): a lifetime boundary must never
destroy an open stream.

### 3.4 Open

A shaped tunnel is opened by the existing admission path, so it costs one proof slot or one session
ticket and goes through the same admission checks (`specs/protocol.md` "Admission checks"). The
envelope gains one field:

```jsonc
{ "v": 4, "target": "example.com:443", "nonce": "…", "proof": {…}, "shape": { "v": 1, "class": "infer" } }
```

For a session-ticket spend the same `shape` object rides next to `ticket`. The node echoes the
accepted parameters in the ack; the client fails closed if they differ, as it does for a session
policy today.

### 3.5 Node pacer

- `payloadTransform` in `packages/node/gateway/gateway.mjs` already holds a per-direction `shaper`
  for session books, a token bucket that delays a chunk when the bucket is empty. Shaping turns that
  bucket into a timer-driven pacer. Node.js timers are millisecond-grained and jitter under load, so
  the pacer ticks every 10 ms and emits `floor(accumulated)` cells per tick (1 to 2 cells at
  128/s). The 10 ms tick is the same at every node, sits below Tor jitter, and is part of the class
  spec.
- Each tick takes data cells first, then `fill` from a subscribed feed, then `pad`. The destination
  socket only fills a bounded buffer. The send loop never waits on it.
- **The node never back-propagates a destination stall onto the Tor leg.** If the destination
  stops reading and the node stops reading its Tor socket in turn, the client's stream stalls on
  Tor flow control, and that stall is a watermark. INFLOW and DUSTER both work through this
  channel. So the node reads its Tor-side socket at line rate, always. Upstream bytes for a stalled
  destination go into a bounded per-stream buffer; when it fills, the node stops granting `credit`
  to that sub-stream, and past a deadline it sends `reset`. A destination stall never becomes a
  missing Tor SENDME, and the upstream schedule is the same whether or not the destination reads.
- Data bytes keep counting against the ADR 0009 payload budget. `pad`, `fill` and `end` go to a
  separate `coverBytes` counter, so the public relay figure stays an honest payload number
  (`docs/RELAY-TELEMETRY.md`).

### 3.6 Client framer, auditor, and Maybenot

- In the Rust client (`crates/shadenet/src/transport.rs`, `proxy.rs`), a framer sits between the
  tunnel stream and the splice: an upstream pacer on the same tick rules, a downstream cell parser,
  and the auditor. The JS SDK gets the same framer in `packages/node/client/`, kept honest by shared
  vectors (ADR 0010).
- **Auditor.** With `e_i = arrival_i − (t0 + i/r)`: a gap test (any inter-cell gap above the honest
  p99.99 for that class and node, calibrated from the first 30 s and the node's warm-up history in
  `client.rs:warm_nodes`), a count test (cells per 1 s window inside the honest band; catches rate
  modulation such as [DSSS marking](https://dblp.org/search?q=DSSS-based+flow+marking+technique+for+invisible+traceback)),
  and CUSUM on `e_i` (catches slow interval-centroid shifts). A firing test marks the node down and
  its tunnels are not reused.
- **[Maybenot](https://github.com/maybenot-io/maybenot)** (Rust, MIT or Apache-2.0, a simulator and
  an FFI crate; the framework behind [Mullvad's DAITA](https://mullvad.net/blog/daita-version-2-now-available-on-all-platforms);
  [paper](https://arxiv.org/abs/2304.09510)) fits the client: its machines are probabilistic state
  machines with padding and blocking actions, and the integrator supplies the clock. A constant-rate
  machine (bypassable blocking plus padding at a fixed rate) is small, and the crate gives the
  project a standard machine format, a simulator, and a path to cheaper classes later without new
  framer code. Its padding limits are turned off for constant-rate classes, since an idle pipe is
  close to 100% padding.
- On the node there is no Node.js binding, so v1 implements the constant-rate pacer directly (a
  timer and a queue). `maybenot-ffi` through N-API, or a small Rust shaper process between
  `gateway.mjs` and tor, can come when the menu grows past constant rate. Any non-constant class is
  gated on measured overhead: [Maybenot's implementation study](https://arxiv.org/abs/2310.10789)
  measured RegulaTor at about 2x and Surakav at over 12x their simulated bandwidth.
- Arti's experimental `circ-padding` feature (built on `maybenot`) pads between the client and a
  relay hop. It does not reach the node, so it cannot shape the return path; it is a later option
  for hop-level cover on the client side of the rendezvous, not a replacement.

## 4. Cover: real traffic rides inside a standing pipe

A shaped tunnel hides what happens inside it. It does not hide that it exists. A guard that sees a
client open a shaped tunnel at 09:14 and another at 09:41 still learns when the agent works, and
start times are the most informative events on a circuit.

### 4.1 A pipe is a session book with a constant-rate body

The design that hides start times is a **shaped pipe**: a standing shaped tunnel to one node,
opened when an agent session starts and renewed on a fixed clock, with real requests multiplexed
inside it as in-band sub-streams (`open` cells), each spent with a session ticket from the pipe's
book. The node can already link the tickets of one book (ADR 0011), so multiplexing inside a pipe
gives the node nothing new.

Opening real tunnels *next to* cover tunnels at the cover nodes does not work. Today every tunnel
gets its own isolated Arti client (`crates/shadenet/src/transport.rs`, `Dialer::isolated`;
[#380](https://github.com/dmarzzz/shade-tree-node/issues/380)), so a new tunnel is a new rendezvous
circuit and the guard watches it being built. Cover beside it would hide nothing about when the real
request started. Real traffic has to share the pipe's existing circuit.

A pipe renews every 600 s on a clock seeded at session start and independent of traffic. The
replacement circuit is built before the old one closes (make before break), so there is no gap.
A pipe leaks only when the session starts and stops: for an agent sandbox, when the sandbox runs,
not when it fetches.

A cover pipe with nothing inside it targets the pseudo-target `shadenet:cover`, handled before the
allow policy: the node opens no destination socket and runs the stream from its own pacer. It is
spent with a ticket, so it is gated by the same proof as a real tunnel and cannot be used by a
non-member to drain a node.

### 4.2 Constant, not Poisson; session-scoped first

- On one circuit with no mixing, Poisson gaps add nothing over constant gaps; both are independent
  of the data, which is all that matters for the guard. Poisson's value in Loopix and Nym comes from
  mixing at the hops, which ShadeNet does not have. Constant gaps can also be audited (§2); with
  Poisson gaps a rogue node's injected delays hide in the natural variance. The Nym study found its
  Poisson cover did little for website fingerprinting, while a constant-traffic variant brought F1
  to 0.06.
- Pipes are **session-scoped by default** (`k = 1` per class in use), opened with the agent
  session. That hides what watermarks need, the timing of each request, at a fraction of the cost
  of always-on cover. Always-on cover additionally hides when the agent works; it is a later
  default, after the crowd at each node exists to make it worth the volume (§5).
- Concentrating a member on a few nodes is a change of posture and it should be named. Today a
  member rotates every tunnel across the fleet so any one node sees ~1/N of its traffic (FLEET.md).
  A pipe concentrates a session on one node. That is the trade Tor made with entry guards: meet a
  rogue party rarely with larger exposure, rather than often with small exposure. With per-tunnel
  nullifiers, what a rogue pipe node learns is traffic metadata, never a cryptographic link to the
  leaf. The pipe's node is re-picked daily from the healthy set, and a `--rotate` flag restores
  per-tunnel rotation without cover for members who prefer the old trade.

What cover buys depends on the crowd at the node. The observer at the node's clearnet egress (A4)
sees a destination connection open at time `t`. If one client has a pipe to that node at `t`, that
is the client. If forty do, it is one of forty. Cover makes every client at the node look identical;
it does not make the node's crowd bigger. The crowd is the canopy's job.

### 4.3 Useful bytes as filler

Padding is pure cost. Filler is cover the client wanted anyway, pushed down the pipe instead of
fetched as a separate, identifiable flow. The node advertises feeds and the client subscribes at
open:

| feed | what the node sends | who has it | why it is good filler |
|---|---|---|---|
| `canopy` | the signed directory, member-set leaves, Elder telemetry aggregate, record updates | every node (it reads them anyway) | the client fetches these every five minutes today as their own flows; inside the pipe they vanish |
| `eth-headers` | Sepolia or mainnet headers and the receipts a light client wants | operators who run an Ethereum node | an agent's chain reads are a lit layer today; the light client ([`LIGHT-CLIENT.md`](../LIGHT-CLIENT.md)) and `leaves.rs` consume exactly this |
| `random` | nothing useful | everyone | the fallback |

Rules for a feed, so that filler does not become a channel:

- A feed is chosen at open and pushed at whatever rate is left after data. The client never requests
  pieces of it mid-pipe; interactive filler would have its own timing.
- A feed is public data, identical for every subscriber. The node learns that a client wants
  headers, which is a weak fingerprint; it must not learn more. No per-client feeds.
- Filler never displaces data: `data` cells take priority at every tick, so a pipe with a feed
  delivers the TLS stream exactly as fast as one without.

## 5. Costs: rate and monthly volume

The only constraint is performance: nothing added may slow a tunnel unless the trade is worth it.
Rate alone hides the bill, so every row gives volume next to rate.

| mechanism | who pays | rate | volume | how |
|---|---|---|---|---|
| shaped tunnel, data phase | the agent: a response of `S` bytes takes at least `S / rate` | `page`: 600 KiB in ≥ 2.4 s; `infer`: 1,000 tokens in ≈ 5 s | n/a | ADR 0009 estimate; §3.2 |
| shaped tunnel, idle phase | node uplink, six Tor relays | the class rate until the lifetime bucket ends | `infer` at 30 s: about 2 MB | arithmetic |
| `infer` pipe, 8-hour agent day | node uplink, client line, Tor relays | 66 KB/s down, 16 KB/s up | about 1.9 GB down, 0.5 GB up per day | 28,800 s |
| always-on cover, one 64 KiB/s pipe | the same, continuously | 64 KiB/s each way | **about 5.3 GiB a day, about 160 GiB a month, each way, per client** | 64 KiB × 86,400 × 30 |
| home node, 20 Mbit/s upload | the operator's residential upload | holds about 38 `infer` pipes or 9 `page` pipes at line rate | 38 always-on clients would push about **6 TiB a month** upstream, far past what most residential plans allow | 2.5 MB/s ÷ 66 or 263 KB/s; 38 × 160 GiB |
| Tor relays | relays the project does not run | every pipe byte crosses six relays (three each side of the rendezvous) | six times the pipe volume, network-wide | onion-service path |
| local round delivery | the agent | ≤ 250 ms per response | none | §6 |
| audit | the client's CPU | one timestamp per cell | none | §3.6 |

Two readings. First, a home node's limit is volume before it is rate: "38 clients per 20 Mbit/s" is
true only for session-scoped pipes, and an operator's monthly cap, not their line speed, bounds
always-on cover. Session-scoped cover on one pipe for an 8-hour agent day costs about a sixth
of always-on cover to two nodes, which is why it comes first. Second, constant-rate cover lands mostly on Tor relays that did not
sign up to carry it. A shaded network with constant-rate cover wants its own middle capacity or its
own overlay eventually; that is the direction, not the preview.

## 6. The agent's lit loop and token timing

Shaping the Tor leg does nothing for the lit loop (§1, item 1): the agent's next model call leaves
outside ShadeNet and carries the destination's delay with it.

- **Round delivery in the Proxy is a speed bump, not a fix.** The Proxy hands each completed
  response to the agent on a coarse 250 ms tick. For a destination that encodes in delays of 100 ms
  to 2 s, each response then carries at most `log2(8)` ≈ **3 bits** instead of a fine-grained value.
  A 32-bit identifier then needs at least 11 error-free responses; an agent session makes dozens.
  Round delivery slows a patient destination down and does not stop it. It costs at most 250 ms per
  response, on the local loop only, and is worth turning on in a paranoid profile.
- **What closes the lit loop** is the model call riding inside an `infer` pipe. Then the guard sees a
  constant stream, and the destination's delay changes nothing anyone outside the pipe can measure.
  The shade check should name the coupling when a user's network row is dark and their inference row
  is not.
- **Token-stream timing.** Inside an `infer` pipe the guard sees a constant stream, so Whisper
  Leak-style classification from the client's uplink drops to chance (a pass bar below). The node
  still terminates the framed leg but not TLS: it sees the record sizes and timing of the provider's
  stream, the full Whisper Leak and token-length view. Shaping cannot hide this from the node. The
  partial answers are rotation (one node sees one slice of a member), keeping the provider's own
  stream padding on (OpenAI's [streaming obfuscation](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events)
  defaults to on; [Cloudflare](https://blog.cloudflare.com/ai-side-channel-attack-mitigated) pads
  too), and, for the full property, a round-based transport or a local model.

## 7. What would count as evidence

The bar "no pattern above Tor's own jitter" cannot be tested as written. The M2 exit criteria in
#369 are detector pass bars on staging, with a control that has to fail:

| # | bar |
|---|---|
| P0 | **Control.** Unshaped tunnels carrying a 100 ms to 2 s gap mark and an interval-centroid mark (500 ms intervals, 350 ms shifts) are detected at ≥ 95% TPR at 1% FPR from a capture on the client's uplink. Otherwise the harness is broken. |
| P1 | Shaped tunnels: for the best of the gap, interval-centroid, 5 to 20 ms non-blind and response-size marks, detection AUC ≤ 0.55 (95% CI upper bound) and TPR ≤ 2% at 1% FPR, over ≥ 1,000 marked and 1,000 unmarked tunnels. |
| P2 | Requests inside a pipe: a learned correlator (ESPRESSO and its DeepCoFFEA reimplementation, retrained on staging) reaches ≤ 1% TPR at FPR 1e-3, reported next to the unshaped baseline. |
| P3 | `infer` pipe: a Whisper Leak style topic classifier on the client's uplink scores within 0.05 AUPRC of chance. |
| P4 | Auditor: flags ≥ 99% of node-injected gaps of 50 ms or more and of interval-centroid shifts, zero false flags over 24 hours of normal traffic; the smallest magnitude it catches is published. |
| P5 | Performance: the rate table per class, measured; an SSE completion longer than 960 s finishes without a cut. |
| P6 | Lit loop: bits per response with round delivery on and off, published in `THREAT-MODEL.md`. A reported number, no bar. |

The datasets are the [exit-blocking harness](../exit-blocking-benchmark.md)'s 1,812 web requests,
the [DeepCoFFEA public dataset](https://github.com/traffic-analysis/deepcoffea) for pretraining, a
prompt set for the topic classifier, and 24 hours of normal staging traffic. Scale runs can use a
private network in [Shadow](https://shadow.github.io/).

## 8. What this does not fix, and what would

In scope, not fixed by anything above:

- **A node and a guard that collude and are patient.** Shaping limits a rogue node to signals below
  Tor jitter per tunnel; across many tunnels of one member those add up. Per-tunnel nullifiers mean
  a hit names one request, not a member. What would fix it: the member never meeting the same rogue
  node often, which is rotation, which cover trades away; hence daily re-pick and `--rotate`. No
  setting fixes both.
- **What the node sees of TLS.** Record sizes and timing of every response, including token
  streams. Fixed only by a round-based transport or by not sending the bytes (a local model).
- **A small crowd at the node.** Cover makes clients identical, not numerous. The egress observer
  plus the guard still wins against a node with one client. What would fix it: trees and members.
- **The agent's lit loop, when the model call stays outside.** Round delivery narrows it to about 3
  bits per response; the model call inside an `infer` pipe closes it.
- **Session start and stop.** Session-scoped pipes still show when an agent session runs.
  Always-on cover hides it at the volume in §5.
- **The destination's content.** A page can make an agent do something visible (follow a link,
  retry). That is the application layer and no transport fixes it; the shade check should keep
  saying so.
- **Tor relay load.** Constant-rate streams are a cost to relays the project does not run. Fixed by
  running middle capacity of its own, which is a later network, not a flag.

## 9. Recommendation, in order

Each step is useful on its own:

1. **Write it down (M0, docs only).** The active-destination watermark, the lit loop, response size
   and token timing go into `THREAT-MODEL.md` §5 as in scope and not fixed, pointing here. Done with
   this page.
2. **Fix the two plumbing issues the design leans on.** Session-book expiry must not cut open
   streams (#379), and tickets of one book must be able to share a circuit (#380); a pipe is both.
3. **Shaped tunnels behind a capability.** The node pacer, the framer and auditor in the Rust client,
   `shape` in the signed caps, three classes, default off. Measure the P0 to P5 bars on staging
   before any default is discussed.
4. **Local round delivery in the Proxy.** Small, no wire change, labelled as a speed bump.
5. **Session-scoped pipes on the same framer,** with `canopy` as the first feed because every node
   already has it and every client already fetches it.
6. **`eth-headers` as a feed** from operators' own Ethereum nodes, after the crowd exists to serve.

An ADR follows step 3's measurements, not before: the decision in it that is not reversible by a
flag is the posture change in §4.2, and that deserves numbers from staging and a crowd that exists.

## References

- In this repository: `specs/protocol.md` ("Two planes", "Tunnel flow", "Admission checks",
  "Session tickets"); [`FLEET.md`](../FLEET.md#a-rogue-gateway-is-a-free-both-ends-vantage);
  [`THREAT-MODEL.md`](../THREAT-MODEL.md) §4.3, §5; ADRs [0009](../adr/0009-epoch-bandwidth-envelope.md),
  [0011](../adr/0011-session-tickets.md), [0013](../adr/0013-the-proxy-is-a-scheduler.md);
  `packages/node/gateway/gateway.mjs:payloadTransform`, `packages/node/gateway/session.mjs:makeTokenBucket`,
  `packages/node/lib/session-tickets.mjs`; `crates/shadenet/src/transport.rs` (`Dialer::isolated`),
  `crates/shadenet/src/client.rs` (`spawn_warmer`, `warm_nodes`, `spawn_preopener`);
  [`RELAY-TELEMETRY.md`](../RELAY-TELEMETRY.md); [`LIGHT-CLIENT.md`](../LIGHT-CLIENT.md).
- Watermarks and correlation: [interval-centroid, IEEE S&P 2007](https://www.freehaven.net/anonbib/cache/Wang-SP2007.pdf);
  [RAINBOW, NDSS 2009](https://people.cs.umass.edu/~amir/papers/NDSS09.pdf);
  [SWIRL, NDSS 2011](https://www.ndss-symposium.org/wp-content/uploads/2017/09/houm.pdf);
  [FINN, ACSAC 2021](https://people.cs.umass.edu/~amir/papers/ACSAC21-FINN.pdf);
  [DUSTER, RAID 2019](https://www.usenix.org/conference/raid2019/presentation/iacovazzi);
  [INFLOW, INFOCOM 2018](https://cris.iucc.ac.il/en/publications/inflow-inverse-network-flow-watermarking-for-detecting-hidden-ser/);
  [DeepCorr, CCS 2018](https://arxiv.org/abs/1808.07285);
  [DeepCoFFEA, IEEE S&P 2022](https://www-users.cs.umn.edu/~hopper/deepcoffea.pdf);
  [ESPRESSO](https://github.com/notem/ESPRESSO-Flow-Correlation); [RECTor](https://arxiv.org/abs/2512.00436).
- LLM streams: [Whisper Leak](https://arxiv.org/abs/2511.03675);
  [What Was Your Prompt?, USENIX Security 2024](https://arxiv.org/abs/2403.09751);
  [Remote Timing Attacks on Efficient Language Model Inference](https://arxiv.org/abs/2410.17175).
- Defenses: [Tor padding spec](https://spec.torproject.org/padding-spec/circuit-level-padding.html);
  [Tamaraw, CCS 2014](https://www.cs.uwaterloo.ca/~iang/pubs/webfingerprint-ccs14.pdf);
  [CS-BuFLO, WPES 2014](https://www.freehaven.net/anonbib/cache/wpes14-csbuflo.pdf);
  [WTF-PAD](https://arxiv.org/abs/1512.00524); [FRONT](https://www.usenix.org/conference/usenixsecurity20/presentation/gong);
  [Maybenot](https://github.com/maybenot-io/maybenot) and its [implementation study](https://arxiv.org/abs/2310.10789);
  [Loopix](https://arxiv.org/abs/1703.00536); [website fingerprinting on Nym, PoPETs 2026](https://www.petsymposium.org/popets/2026/popets-2026-0055.pdf).
