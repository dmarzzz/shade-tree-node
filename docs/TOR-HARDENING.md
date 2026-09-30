# Tor hardening (gateway + bootnode onion services)

Operator guide for hardening the Tor layer under the shade-tree fleet. This is the
**network layer**; the reputation zk-gate is the application layer and is
unchanged by anything here. Tor DoS/deanon defenses are the cheap outer gates,
the zk proof is the expensive inner gate.

Scope: the droplet runs two v3 onion services (bootnode + gateway) via the
`/etc/tor/torrc.d-shade-tree` include that `packages/node/bootnode/deploy/bootstrap.sh` writes
(two `HiddenServiceDir` blocks, each with `HiddenServicePoWDefensesEnabled
<SHADE_TREE_ENABLE_POW>` — `0` by default, `1` when you opt in; gateway-only boxes get
one block).
Clients run a SOCKS-only tor (see `tor/torrc.client`).

A ready-to-copy config fragment lives at
[`packages/node/bootnode/deploy/torrc.hardened`](../packages/node/bootnode/deploy/torrc.hardened). It is a
REFERENCE and is deliberately not wired into `bootstrap.sh`. Apply pieces by
hand after reading the tradeoffs below.

> Version note. Several options below are recent (PoW defense landed in tor
> 0.4.8). Confirm exact names/units with `man tor` on the box before relying on
> them; where a name is version-sensitive it is flagged inline. Do not paste an
> option tor does not recognize -- stock tor hard-fails config validation and
> refuses to start.

---

## 1. Onion-service PoW DoS defense

The PoW defense makes an attacker burn client-side compute to get a rendezvous
slot, so flooding the introduction/rendezvous path (before any zk work) costs
the attacker, not just the service. Under load tor raises the required effort
and serves clients in priority order by the effort they proved.

- `HiddenServicePoWDefensesEnabled 1` -- written per service by `bootstrap.sh`
  when `SHADE_TREE_ENABLE_POW=1` (default `0`, i.e. `HiddenServicePoWDefensesEnabled 0`).
  Requires a **pow-capable tor build on BOTH ends**: the official Tor Project
  apt package (what `bootstrap.sh` installs) ships the `pow` module; the
  Homebrew bottle does NOT (the PoW code is GPL, the bottle is BSD-only), and a
  `pow: no` client could not reach a PoW-enabled onion at all
  (`docs/history/DEPLOYMENT.md` "PoW capability mismatch") — which is why the deploy
  default is off, the repo's `tor/torrc` leaves it off, and the local demo enables
  it only when the running tor has the module. Check with `tor --version` /
  `tor --list-modules` (look for `pow: yes`).
- `HiddenServicePoWQueueRate` [verify name/units per version] -- steady-state
  rate (requests/sec) at which the service dequeues rendezvous requests from the
  PoW-priority queue. It is the drain rate of the effort-sorted queue.
- `HiddenServicePoWQueueBurst` [verify] -- how far above the steady rate a short
  burst may spike before being shaped.

**When to raise them.** The defaults are tuned for a typical service. Raise
`QueueRate` (and `Burst` alongside it) when you are under real load and have CPU
headroom and you observe legitimate clients being shed with the defense on:
a higher drain rate serves more real rendezvous per second at more CPU cost.
Do not raise them pre-emptively -- a queue that drains too fast under attack
just admits more of the flood. Leave the effort auto-tuning to tor; you are
tuning the queue geometry, not the difficulty.

---

## 2. Vanguards / guard-discovery defense

A long-lived onion service builds many circuits over its lifetime. An adversary
running middle relays can, over time, use guard-discovery attacks to learn the
service's entry guards and then attack or watch them (Biryukov-Pustogarov-
Weinmann 2013; see `docs/history/adversarial-review.md` section 11). Vanguards pin extra
layers of semi-persistent guards so the set of relays adjacent to the service
does not churn freely, raising the cost of that discovery.

- **vanguards-lite** is built into modern tor and on by default for onion
  services. No torrc option to enable; you already have the baseline.
- **vanguards** (the full add-on) is a separate external Python tool
  (`github.com/mikeperry-tor/vanguards`) that drives tor over the control port.
  It adds a second guard layer, rotation-time randomization, and bandwidth-based
  attack detection beyond what lite does.

**Recommendation.** The shade-tree onions are persistent, long-lived, and worth
attacking (they front the whole fleet), so a persistent deploy should run the
full vanguards add-on against tor's control port, not just rely on lite. It is
an external tool, out of scope for `bootstrap.sh`; install and supervise it
separately (its own systemd unit), pointed at tor's `ControlPort` with cookie
auth. Vanguards-lite is the acceptable minimum if you cannot run the add-on.

---

## 3. Client-auth for a PRIVATE fleet (optional, off by design)

Tor v3 onion services can require the CLIENT to present an x25519 key before the
service will even build a rendezvous. This is a Tor-layer allowlist that sits
UNDER the app-layer zk gate: an unauthorized client cannot reach the HTTP
service at all, so it never gets to attempt (or flood) the reputation proof.

Mechanism (v3, current tor):

- **Server side:** drop `<name>.auth` files into an `authorized_clients/`
  subdirectory of each `HiddenServiceDir` (e.g.
  `/var/lib/tor/shade-tree-gateway/authorized_clients/`), each holding a line like
  `descriptor:x25519:<base32-pubkey>`. Restart tor.
- **Client side:** `ClientOnionAuthDir <dir>` pointing at a directory of
  `<onion>.auth_private` files holding the matching private keys.

> Flag: the old torrc line `HiddenServiceAuthorizeClient` is the **v2**
> mechanism and does not apply to v3 onion services. Do not use it. v3 client
> auth is the `authorized_clients/` directory described above. Verify the file
> formats with `man tor` for your version.

**Tradeoff, and why shade-tree leaves it off.** Client-auth is a static, linkable
keypair allowlist: every authorized client is a fixed public key you provision
and manage out of band, and the set is not reputation-derived. That is exactly
right for a small **private fleet** with a fixed operator roster, and wrong for
the open, access-gated model this project exists to demonstrate -- where
membership is a zk proof, not an entry on a keylist. The whole point of shade-tree is
app-layer gating; client-auth is an optional defense-in-depth tier for private
deployments, mutually exclusive in spirit with permissionless
`--admission open`. Enable it only if your deployment is closed-membership.

---

## 4. Process / OS hardening

- **Run tor as its own user.** The official apt package runs tor as
  `debian-tor` under its packaged systemd unit; keep it that way. Do not run tor
  as root or fold it into the `shade-tree` service user. `bootstrap.sh` already
  chowns the HS dirs to `debian-tor:debian-tor` because tor owns them.
- **DataDirectory / HS dir perms.** Tor enforces `0700` (owner-only) on its
  `DataDirectory` and on each `HiddenServiceDir`, and refuses to start if they
  are looser -- this is why `bootstrap.sh` installs the copied HS key files
  `0600` owned by `debian-tor`. Do not relax these. If some other local process
  genuinely needs to read the dir, `DataDirectoryGroupReadable 1` (verify) opens
  it to `0750` for the group only; avoid it unless required.
- **Keep the HS secret key off-box.** The onion identity IS the ed25519 secret
  in `hs_ed25519_secret_key`. Anyone with that file can impersonate the onion.
  Take an encrypted, off-box backup and store it outside the droplet:
  `shade-tree backup <deploy-state-dir> <out.shade-tree-backup>` / `shade-tree restore` (T-FEAT-15,
  `docs/BACKUP.md`; passphrase only via `SHADE_TREE_BACKUP_PASSPHRASE`), and verify a
  restored key before cutover with `scripts/onion-identity.mjs`
  (`docs/ONION-IDENTITY.md`). Never commit or log the secret key.
- **`Sandbox 1`.** Tor's own seccomp2 syscall filter around the tor process,
  strong defense in depth. CAVEATS: Linux-only (x86_64 and a few arches), and
  once enabled tor cannot live-reload a config change that needs a new syscall
  or a new file path -- some changes require a full `systemctl restart tor`
  rather than a reload. Test a restart cycle before trusting it, and confirm it
  does not conflict with any other option you set.

---

## 5. Rate / circuit isolation (client-side tor)

shade-tree rotates gateways and slots per tunnel at the app layer. The client tor
should back that with circuit isolation so distinct requests do not silently
share one path.

- **SocksPort isolation flags.** On the client `SocksPort` line:
  - `IsolateDestAddr` -- separate circuit per distinct destination `.onion`.
  - `IsolateDestPort` -- separate circuit per distinct destination port.
  - `IsolateSOCKSAuth` -- separate circuit per distinct SOCKS username/password.
    The client can pass a per-tunnel tag as the SOCKS auth to force a fresh
    circuit on demand, which pairs directly with per-tunnel rotation.

  Example (compare `tor/torrc.client`):
  `SocksPort 9260 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth`

- **`MaxCircuitDirtiness`** (seconds, default 600) -- how long a circuit keeps
  accepting NEW streams before tor rotates to a fresh one. The isolation flags
  already fork circuits per destination, so lowering this mainly adds
  time-based rotation WITHIN a single destination, at the cost of more circuit
  builds and more load on guards. Leave at the default unless you specifically
  want faster same-destination rotation; do not set it so low that build churn
  itself becomes a fingerprint.

---

## Quick apply

1. Read [`packages/node/bootnode/deploy/torrc.hardened`](../packages/node/bootnode/deploy/torrc.hardened).
2. Server: append the `[S]` / `[S-POW]` lines you want to
   `/etc/tor/torrc.d-shade-tree`, then `systemctl restart tor`. Confirm the PoW module
   is present first (`tor --list-modules`).
3. Client: apply the `[C]` isolation flags to the client `SocksPort`.
4. Persistent deploy: install the external vanguards add-on against tor's
   control port (section 2).
5. Verify every option with `man tor` on the box before restart -- an unknown
   option makes tor refuse to start.
