# Deploying the split: droplet gateway + laptop client

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

> **PoC-era guide** (single pinned gateway, `scripts/run-*.sh`, `members.json`). The
> current one-command bring-up is `bootnode/deploy/bootstrap.sh` — see
> [`OPERATOR.md`](../OPERATOR.md) and [`QUICKSTART.md`](../QUICKSTART.md).

The PoC runs all three pieces (Tor, gateway, shim) on one machine via
`scripts/run-all.sh`. A real deployment splits them across the trust boundary:

```
  DROPLET  (clean-IP egress box)            LAPTOP  (the client)
  ─────────────────────────────            ─────────────────────
  Tor  → publishes gateway.onion            Tor  → SOCKS only (no onion)
  gateway.mjs  (binds 127.0.0.1:8443)       shim.mjs  (binds 127.0.0.1:8888)
  trusts root of group/members.json         holds SHADE_TREE_SECRET (never leaves)
       ▲                                          │
       └──────── Tor rendezvous (6 hops) ◀────────┘
       │
       ▼
  clean egress → the internet   ← returns the DROPLET's IP if it worked
```

No application code differs between the two roles. The split is config:
`scripts/run-gateway.sh` on the droplet, `scripts/run-client.sh` on the laptop.

## Invariants (break one and every request silently drops)

1. **`group/members.json` must be byte-identical on both machines.** The gateway
   computes its trusted Merkle root from its copy; the client rebuilds the same
   tree from its copy to generate the proof. One differing byte means different
   roots and the gateway drops every proof as `wrong-group-root`. The file is
   public (only commitments), so copy it freely.
2. **`SHADE_TREE_SECRET` lives only on the laptop.** The droplet never needs a secret;
   `run-gateway.sh` does not read one. Putting a secret on the egress box buys
   nothing and widens the blast radius.
3. **Both clocks on NTP.** The epoch is `floor(now / EPOCH_SECONDS)`, default a
   day (86400s) so a whole demo session sits in one epoch and nobody hits a
   boundary mid-stream. The gateway accepts the current epoch and one behind
   (`now` or `now-1`), so a lagging client is fine, but a client whose clock is
   *ahead* of the gateway proves for a future epoch and is dropped as
   `stale-epoch`. NTP on both removes the asymmetry. `EPOCH_SECONDS` lives in
   shared code (`lib/semaphore.mjs`), so it already matches everywhere; only
   override `SHADE_TREE_EPOCH_SECONDS` if you set it identically on both sides.
4. **The gateway binds loopback and egresses :443 only.** It is reachable solely
   through the onion, never the droplet's public IP. Keep it that way (firewall
   below); it is the whole point that no exit node and no public listener sits in
   the path.

## One-time: author the reputation set

Enrollment is the trust boundary (see `group/enroll.mjs`). For the PoC it is a
local command; in production a leaf is added only after whatever admission
ceremony you choose (stake, invite, proof-of-personhood).

```bash
node group/enroll.mjs alice        # prints a secret value for the member's hidden prompt
# repeat per member; each appends a commitment to group/members.json
```

`members.json` is the artifact you ship to the droplet. Each member keeps their
own `SHADE_TREE_SECRET` on their own laptop.

## Droplet (gateway role)

Ubuntu droplet, Tor + Node 20+:

```bash
# Prefer the official Tor Project repo: its packages are built with the GPL
# module, so `tor --list-modules` reports `pow: yes` and start-tor.sh turns on
# the rendezvous DoS defense automatically. Ubuntu's universe `tor` may not.
#   https://support.torproject.org/apt/  (add deb.torproject.org, then:)
sudo apt-get update && sudo apt-get install -y tor
tor --list-modules | grep pow        # want: pow: yes
# install Node 20+ (nodesource or nvm)

git clone <this-repo> && cd shade-tree-node
npm install
# put the authored group/members.json in place (scp it up; it is public)

bash scripts/run-gateway.sh          # prints the gateway .onion to hand to clients
bash scripts/gateway-status.sh       # live receipt: PASS/DROP counts, members, egress IP
```

Lock it down:

```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw enable
# no inbound rule for the gateway: it is loopback-only, reached via the onion.
# outbound :443 is all the gateway uses.
```

Operational notes:
- **The onion address is stable across restarts** because the key persists in
  `tor/hs/` (gitignored). To keep the same address across droplet rebuilds, back
  up `tor/hs/` and restore it. To rotate the address, delete it.
- **PoW DoS defense** is opportunistic: stock Tor lacks the module, so the outer
  rendezvous-flood gate is off unless you build a PoW-capable Tor
  (`scripts/build-tor-pow.sh`) and point `SHADE_TREE_TOR_BIN` at it. Optional; the zk
  proof is the inner gate regardless.

## Laptop (client role)

Hold the same `group/members.json` and your own secret:

```bash
export SHADE_TREE_ONION=<addr-from-the-droplet>.onion
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT   # exact enrolled tier
bash scripts/run-client.sh           # starts a client-only Tor (9260) + the shim
bash scripts/verify.sh               # receipt: your IP vs the egress IP, RTT, google 200
```

To reuse an existing Tor instead of the bundled client Tor (system tor 9050, Tor
Browser 9150), set `SHADE_TREE_TOR_PORT` before running and `run-client.sh` skips
starting its own.

## Handing it to friends

Give a friend three things: this repo (with `group/members.json` already in it),
the gateway's `.onion`, and their own `SHADE_TREE_SECRET` block from `demo-keys.local.md`.
They run one command:

```bash
npm install
bash scripts/join.sh <gateway-onion> <their-secret>
```

`join.sh` starts their client Tor + shim and prints the verification receipt. If
it ends in `PASS` (or `TUNNEL WORKS`), they just reached Google from the droplet's
clean IP, having proven set membership in zero knowledge and revealing nothing
about who they are. Each friend gets their own key, so each has an independent
per-epoch rate budget and an unlinkable nullifier.

## Verification matrix

Run these against the live droplet. `api.ipify.org` echoes the source IP.

| # | Test | Command / action | Expected |
|---|------|------------------|----------|
| 1 | Positive path | `curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json` | Returns the **droplet's** IP, not the laptop's, not a Tor exit. Gateway logs `PASS`. |
| 2 | Non-member | run the shim with a secret never enrolled | Client cannot build a proof (`leaf at index -1`); nothing egresses. |
| 3 | Wrong set | give the client a `members.json` the gateway does not trust | Gateway logs `DROP wrong-group-root`; curl gets a failed CONNECT. |
| 4 | Rate limit | exceed `SHADE_TREE_RATE_LIMIT` (default 30) per epoch | Over-budget requests log `DROP rate-limited`; refusal reaches curl. |
| 5 | IP privacy | `grep <your-public-ip> gateway.log` on the droplet | No match. Rendezvous never reveals the client IP to the gateway. |

## Pre-flight: simulate the split on one machine

Before paying for a droplet you can exercise the exact two-Tor topology locally.
This runs a gateway Tor (9250) and an independent client Tor (9260); traffic
still crosses the real Tor rendezvous between them.

```bash
bash scripts/run-gateway.sh                       # note the printed onion
export SHADE_TREE_ONION=<that-onion>
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET   # paste the enrolled member value
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT     # exact enrolled tier
bash scripts/run-client.sh
curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json
```

The returned IP is your own machine here (the gateway egresses locally); on the
droplet it becomes the droplet's IP. Everything else — proof, rendezvous, gate,
rate limit — behaves identically.

## Teardown

```bash
bash scripts/stop.sh                               # stops shim, gateway, gateway Tor
pkill -f "tor -f ./tor/torrc.client"               # stops the client Tor
```
