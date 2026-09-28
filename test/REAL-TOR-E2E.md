# T-TEST-1 — real-Tor client→gateway egress e2e

A real-Tor END-TO-END test of the member egress path: bring up a fleet with a REAL published
v3 `.onion` gateway, run the JS **reference client** through it — mint a real per-request RLN
membership proof, dial the gateway onion over Tor, and the gateway ACCEPTS and proxies the
CONNECT to a local sink. Three independent facts are asserted for a genuine accept:

1. the client got an `ok` ack (an ACCEPT, not a gate refusal),
2. the gateway logged `egress target=<sink> …`,
3. the sink actually received the tunneled TCP connection.

Nothing under `client/`, `gateway/`, or `lib/` is modified — these are thin drivers over the
shipped code.

## Pieces

| File | Role |
|------|------|
| `test/real-tor-e2e-client.mjs` | Thin driver: instantiates `ShadeTreeClient` exactly as a real caller would (`{ secret, onion, torPort }`), `connect()`s to the sink target, prints the accept outcome as JSON. Adds no protocol logic. |
| `test/real-tor-e2e.sh` | **Local** harness (gated `SHADE_TREE_TOR_E2E=1`). Publishes the gateway's HS via system `tor` + a SOCKS port, points `group/members.json` at a derived single member (backup+restore), runs the client egress over Tor, asserts the accept. SIGPIPE-robust cleanup — leaves zero tor/gateway/sink processes. |
| `test/real-tor-e2e-container.sh` | **CI/authoritative** runner. Boots the systemd-container fleet via `bootnode/deploy/bootstrap.sh` (real onions), points the gateway root at a derived member + restarts it, then runs the same client egress over the container's Tor SOCKS against the published gateway onion. |
| `.github/workflows/real-tor-e2e.yml` | CI job wrapping the container runner. |

The single-member derivation reuses `crates/shadenet-rln/interop/egress-derive.mjs`; the log-readiness
polling reuses `interop/wait-log.mjs`. The gateway's default `*:443` egress policy is satisfied by
using a `:443` sink in CI (no unit edit); the local harness uses a `127.0.0.1:9443` sink with
`SHADE_TREE_EGRESS_ALLOW` set for it.

## Running

Local (needs system `tor`; `SHADE_TREE_TOR_BIN` overrides the path):

    SHADE_TREE_TOR_E2E=1 bash test/real-tor-e2e.sh

Container (needs docker + a kernel that runs systemd privileged — GitHub Actions ubuntu-latest,
Docker Desktop / colima):

    bash test/real-tor-e2e-container.sh

Neither is part of `node scripts/test-all.mjs` (it auto-discovers `*.selftest.mjs` only) or
`cargo test`.

## Gating — why a propagation timeout is a soft pass

v3 HS descriptor propagation over the live Tor network (local tor uploads to the HSDirs → the
client's tor fetches the descriptor) is slow (~30–90s) and flaky. Both runners therefore RETRY
the whole client run a few times and treat "no accept, onions did publish" as a **soft/neutral**
outcome (exit 0), exactly as `bootnode/deploy/e2e-container.sh` treats its best-effort over-Tor
dial. What is NOT soft:

- a client that reports ACCEPT **without** the corroborating gateway+sink evidence → HARD failure
  (a real inconsistency), and
- in CI, any hard error from the fleet bootstrap itself.

This job is additive — it does **not** gate the existing `ci.yml` suites.

## Verified vs. gated (honest coverage)

- **CI (authoritative):** `real-tor-e2e.yml` runs the accept against the real fleet on
  ubuntu-latest, where descriptor propagation normally completes. This is the execution path that
  observes the over-Tor ACCEPT, mirroring T-TEST-8's container-is-authoritative posture.
- **Locally observed here:** the full client→proof→gateway ACCEPT→sink **wire path** was exercised
  against the real gateway (real RLN proof minted, gateway accepted, sink received the connection).
  The **Tor transport** itself was not confirmed on the dev box because the local Tor daemon did
  not finish bootstrapping (loading microdescriptors stalled) within the window — the harness
  soft-skipped, as designed. The cleanup was verified to leave zero leftover processes, including a
  piped/SIGPIPE run.
