# Deploy bootstrap, tested in a container (T-TEST-8)

`bootstrap.sh` used to be a hand-run-once script: you rented a droplet, ran it,
eyeballed the output. This makes it a **repeatable test**. The exact same install
path a fresh Ubuntu 24.04 droplet takes is exercised on every relevant PR.

- **Runner:** [`e2e-container.sh`](e2e-container.sh) — run it locally.
- **CI:** [`.github/workflows/bootstrap-e2e.yml`](../../../../.github/workflows/bootstrap-e2e.yml)
  — the authoritative execution path; it just calls the runner.

## Run it locally

```bash
bash packages/node/bootnode/deploy/e2e-container.sh
```

Needs Docker and a kernel that can run systemd in a privileged container (GitHub
Actions `ubuntu-latest`, or Docker Desktop / colima on macOS). It clones **your
current checkout** into the container from a read-only bind mount (not GitHub), so
you test the branch in front of you. `E2E_KEEP=1` leaves the container up for
`docker exec` poking; `SHADE_TREE_REF=<ref>` overrides the ref that gets cloned.

## Why systemd-in-a-container (and not `docker run ubuntu:24.04 bash bootstrap.sh`)

`bootstrap.sh` is systemd-native: it writes three `.service` units plus a Tor
`torrc.d` include and drives them with `systemctl enable --now` / `restart` /
`daemon-reload`. A plain `docker run` has **no init** — PID 1 is your command, not
systemd — so every `systemctl` call fails and the script (which runs `set -euo
pipefail`) aborts. Two ways out:

1. **Adapt the check** — skip systemd, launch `node packages/node/bootnode/server.mjs` etc. by
   hand, assert they bind. This is easy but it would test *a paraphrase* of
   `bootstrap.sh`, not `bootstrap.sh` itself: the units, the sandbox directives, the
   Tor include, the enable/restart ordering — none of it would be exercised.
2. **Give the container a real init** — boot `ubuntu:24.04` as a `--privileged`
   container with `/lib/systemd/systemd` as PID 1 (host cgroup namespace + a
   writable `/sys/fs/cgroup`), then run `bootstrap.sh` unmodified via `docker exec`.

We chose **(2)**: `bootstrap.sh` is the artifact under test, so it runs verbatim,
including the systemd units and the Tor hidden-service setup. The container installs
`systemd systemd-sysv`, execs systemd, we wait for `systemctl is-system-running`,
then hand off to `bootstrap.sh`.

## What the job asserts

After `bootstrap.sh` returns, inside the container:

1. `systemctl is-active` for **tor**, **shade-tree-bootnode**, **shade-tree-gateway** — the units
   the script installed all came up under real systemd (sandbox directives and all).
2. Both onion **hostname files** exist and end in `.onion`
   (`/var/lib/tor/shade-tree-bootnode/hostname`, `/var/lib/tor/shade-tree-gateway/hostname`) —
   Tor accepted the minted hidden-service keys and published the services.
3. The bootnode answers **`GET /health` on `127.0.0.1:8877`** — the Node service is
   actually serving, not merely "active".
4. The gateway is **accepting TCP on `127.0.0.1:8443`** (it is a raw TCP proxy, not
   HTTP, so this is a connect check, not a request).
5. **Best-effort:** dial the bootnode onion over Tor SOCKS
   (`curl --socks5-hostname 127.0.0.1:9050 http://<onion>/health`). Reported, **not**
   required to pass — see coverage note.

## Honest coverage — what is and isn't exercised

**Exercised for real:** package install (Node, Tor from the Tor Project repo), the
service user, cloning + `npm install`, onion **key minting** (`keygen.mjs`), the
`torrc.d-shade-tree` hidden-service config, all three **systemd units under real systemd**
with their full sandbox (`ProtectSystem=strict`, `SystemCallFilter`, empty
`CapabilityBoundingSet`, …), Tor **writing the hostname files** for both services,
and the bootnode + gateway **actually binding and serving on loopback**.

**Not fully exercised (deliberately best-effort):**

- **Onion reachable over the live Tor network.** Publishing a v3 descriptor and
  building a circuit to it needs outbound Tor access and ~30–90 s of propagation —
  flaky and slow in CI. The over-Tor `/health` dial is attempted and reported but the
  job does **not** fail on it. Loopback `/health` + the written hostname files already
  prove the service published locally; the over-Tor hop is Tor's job, not
  `bootstrap.sh`'s.
- **PoW defenses (`HiddenServicePoWDefensesEnabled`).** Off by default (`SHADE_TREE_ENABLE_POW=0`,
  see `bootstrap.sh`); `SHADE_TREE_ENABLE_POW=1` is passed through by the runner but never
  driven under attack here. Both renderings are asserted offline by
  `packages/node/bootnode/deploy/bootstrap.selftest.mjs`.
- **Gateway-only mode (`E2E_MODE=gateway-only`, a CI matrix entry).** Hands `bootstrap.sh`
  a well-formed but unreachable `SHADE_TREE_BOOTNODE_ONION` and asserts: tor + `shade-tree-gateway`
  active, **no** `shade-tree-bootnode` unit / bootnode HS dir / bootnode identity, exactly one
  `HiddenServiceDir` in the torrc include, and the heartbeat unit pointing at the remote
  onion. The heartbeat's actual announce to a *real* remote bootnode is not exercised
  (there is none in the container) — that is the same over-Tor caveat as above, and the
  announce path itself is covered by the bootnode/heartbeat selftests.
- **`shade-tree-heartbeat`** is installed by `bootstrap.sh` but intentionally **not**
  asserted active: it dials the bootnode *over the onion via Tor*, so until a
  descriptor propagates it restart-loops — the same best-effort caveat as above.
- **Container ≠ droplet.** systemd runs `--privileged` (seccomp off), so the seccomp
  side of `SystemCallFilter` is not enforced exactly as on a locked-down droplet; and
  `--cgroupns=host` is a container concession. The unit *definitions* and startup are
  tested; a hostile-syscall test is out of scope here.

Bottom line: this proves `bootstrap.sh` **brings the fleet up** end-to-end from a
clean Ubuntu image. It does not prove the onions are reachable from the public Tor
network (that hop is reported, not gated).
