# Aggregate relay-byte telemetry

Relay telemetry is optional and private by default. It measures **application payload bytes
relayed**, not host-interface traffic. Each byte is counted once when read from either side of an
established tunnel:

- `agentToDestinationBytes`
- `destinationToAgentBytes`

The proof envelope, success acknowledgement, Tor cells, TCP/IP/TLS overhead, failed connection
attempts, active probes, and retransmissions below the socket layer are excluded. Never derive the
metric by adding OS ingress and egress: that observes the same relayed payload twice.

## Node reporting

Set `SHADE_TREE_RELAY_TELEMETRY=1` in both the gateway and heartbeat services. They share:

- `SHADE_TREE_RELAY_TELEMETRY_STATE` (default `tor/hs/relay-telemetry.local.json`), written by the
  gateway with mode `0600`;
- `SHADE_TREE_RELAY_REPORT_STATE` (default `tor/hs/relay-report.local.json`), written by the
  heartbeat only after an Elder accepts a report.

The gateway state carries a fresh random `bootId`, start/update times, and decimal unsigned-64-bit
directional counters. The heartbeat sends a separate onion-key-signed
`shade-tree-relay-report-v1` to `POST /telemetry/relay` only after its `/announce` was accepted.
Telemetry is never added to `/announce`, capabilities, `/directory`, logs, or public Prometheus.
Reports contain no destination, port, member, nullifier, flow, payment, error, or tunnel field.

The Elder binds the report to a currently announced onion identity and rejects malformed
signatures, stale/future/overlapping intervals, replayed or non-monotonic sequences, unexplained
resets, counter rollback/wraparound, intervals over 24 hours, and deltas above the conservative
combined 16-Gibit/s ceiling. Raw contributions live only in the Elder process and expire after 36
hours. A private 0600 replay checkpoint (`SHADE_TREE_RELAY_ELDER_STATE`, default
`bootnode/relay-telemetry-state.local.json`) retains only each node's last sequence, boot ID,
counters, and interval end. That rejects a captured report after an Elder restart without restoring
raw contributions; old aggregate input becomes unavailable rather than reconstructed or reported as
zero.

## Publication

`GET /telemetry/aggregate` returns an Elder-signed `shade-tree-relay-aggregate-v1`. It contains only
fixed 6-hour and 24-hour windows ending on an hour boundary at least six hours in the past. Positive
totals are rounded upward to fixed 1-GiB buckets. Each window publishes `roundedBytes` only when at
least five reporting node identities contributed; this is not proof of five independent operators.

Below five reporters the window is `suppressed` with `minimum-cohort`. Missing, stale, or zero-input
windows are `suppressed` with `unavailable`. Suppressed windows omit `roundedBytes` completely—zero
is never a placeholder for unavailable data. No API exposes the Elder's raw node map.

The Tor-capable canopy collector verifies the Elder aggregate against the same pinned signer as the
directory, strips its transport signature and signer, and places the allowlisted aggregate under the
single top-level `relay` field in `shade-tree-public-grove-v2`. The dedicated canopy publication
signature covers the whole v2 object. V1 remains unchanged.

The same-origin endpoint is `GET /api/v2/data/grove/sepolia/head`; its exact OpenAPI document is
served at `/api/v2/openapi.json`. The function validates exact keys, a fresh `observedAt`, a relay
aggregate generated within the last hour, the publication signature, cohort/window/rounding
relationships, and a 64-KiB response cap. Failures are
non-cacheable `503` responses. The browser repeats exact-key and Ed25519 verification. The canopy UI
adds `Payload relayed, 24h` only for a verified, non-suppressed 24-hour value; it renders no empty,
sample, demo, or zero placeholder.
