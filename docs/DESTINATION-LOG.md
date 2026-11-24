# Relay destination logging (local opt-in)

Off by default. `SHADE_TREE_DESTINATION_LOG=1` enables an independent local JSONL sink; no destination fields enter the ordinary logger, Prometheus, relay telemetry, alerts, or fleet tally. No network transport is added. Both v4 and session-ticket tunnels use the shared `establishTunnel` instrumentation.

## Provisioning (not performed by this patch)

Pre-create a dedicated directory owned by the gateway service uid with **0700** permissions, under a trusted parent not writable by other users. Set `SHADE_TREE_DESTINATION_LOG_DIR` to its absolute path. Startup fails if enabled without a suitable directory. Files must be regular, singly linked, service-owned **0600** files; symlinks are refused. Use one gateway process per directory; the size cap is not a cross-process coordination mechanism. Exclude this directory from log shippers, backups, sync and shared mounts. Do not point it at the general log directory.

No deployment, service configuration, or external host changes are included.

## Record contract

One `destination.tunnel.closed` record is queued when an **established** tunnel's local client socket closes. Rejected targets and failed connects create no record. The closed allowlist is:

- `host`: admitted `tgt.host` (not a URL).
- `ip`: numeric address of the **successful actual pinned candidate**, not the first DNS answer.
- `port`: admitted destination port.
- `openedAt`: UTC ISO timestamp at TCP establishment.
- `durationMs`: monotonic elapsed time until local close, rounded to milliseconds.
- `agentToDestinationBytes`, `destinationToAgentBytes`: byte lengths at existing budget-admission callbacks, including proof-read remainder exactly once; excludes proof envelope and success acknowledgement. These count admitted relay bytes, **not proof of delivery** to the remote application.
- `closeReason`: existing `idle-timeout`, `payload-limit`, or `upstream-error` when available; otherwise `peer-close`. The latter is deliberately generic and does not claim to distinguish FIN, reset, client shutdown, session teardown or operator shutdown.

No client identifiers, nullifiers, ticket/session IDs, proof fields, payloads, URLs, TLS parsing/certificates/SNI, or error text are recorded. There are no new per-chunk payload inspections: only existing `chunk.length` accounting is reused.

## Bounds and limitations

| Variable | Default | Meaning |
|---|---|---|
| `SHADE_TREE_DESTINATION_LOG` | off | Only `1` enables the sink. |
| `SHADE_TREE_DESTINATION_LOG_DIR` | unset | Required absolute path to a dedicated private directory. |
| `SHADE_TREE_DESTINATION_LOG_RETENTION` | `7d` | Positive integer followed by `m`, `h`, or `d`, for example `30m`, `6h`, or `7d`. Literal `forever` disables age expiry only. |
| `SHADE_TREE_DESTINATION_LOG_MAX_BYTES` | `50331648` (48 MiB) | Positive integer global cap in logical JSONL bytes, across all log segments. Cannot be disabled, including in `forever` mode. |

Invalid enabled configuration fails startup without echoing the supplied value. Disabled configuration does no destination-log filesystem work and ignores the other destination-log settings. No dependency, cron job, deployment change, or additional interval is needed.

Files are minute buckets named `destination-<UTC epoch minute>-<sequence>.jsonl`, rotated at **8 MiB each**. Size enforcement evicts the oldest bucket/sequence first, **before** appending, including during `forever` retention. A busy minute rotates instead of permanently dropping all later records. An individual record larger than the global or segment cap is dropped. Startup rescans sizes and enforces any reduced cap. The cap measures logical file contents, not filesystem allocation, directory entries or unrelated files; use a dedicated directory with no other writers. Unrelated filenames are neither deleted nor counted.

Age retention is rolling from **tunnel close/queue time**, not `openedAt`. A bucket expires when its end is at least the configured age in the past, so no record is removed early for age. There is **up to one minute of bucket rounding**, followed by up to **one existing gateway sweep period (`EPOCH_SECONDS` seconds)** before removal under healthy I/O, an unsaturated queue and a running event loop. For example, `30m` means 30 minutes plus up to one minute of rounding plus up to one epoch sweep, not an exact 30-minute deletion deadline. Large epoch settings also increase pruning lag. Size pressure can always delete records sooner.

Pruning runs at startup and asynchronously from the gateway's existing `sweepTimer`, even with no new tunnels. The nominal lag above also includes async queue and filesystem latency; it is not a wall-clock upper bound under arbitrary load. There is **no per-request age-prune or additional timer**. Maintenance is serialized with appends and overlapping sweep calls coalesce. At most **256 operations** are pending; a saturated queue drops records/maintenance attempts and retries maintenance on a later shared sweep. I/O failures or event-loop stalls can extend the lag; this is not a hard deletion SLA. One metadata-free warning reports degradation per process lifetime, without destination or client data. All runtime sink failures are isolated from relay cleanup.

**When the process is stopped, files remain until the next startup or independent operator cleanup.** No offline cleanup is installed by this feature. Pruning is unlinking, not secure erasure; snapshots/backups must be excluded separately.

This is best-effort destination logging, not a billing/forensic ledger. Open/long-lived tunnels have no record until close. Crashes, forced exits and shutdown before queue drainage can lose the tail. No per-tunnel persistent identity is created. Normal relay policy, acknowledgement, stream transforms and cleanup remain unchanged.

## Local validation

`node packages/node/gateway/destination-log.selftest.mjs` exercises the real shared handler and loopback echo relay, with injected admission verification and a controlled first-candidate refusal. It checks byte-identical acknowledgement/payload, early/remainder and later bytes, chosen IP fallback, exact schema/exclusion, disabled and failed-dial silence, idle/payload-limit reasons, sink-failure isolation and permissions. A pre-opened synthetic ticket book also exercises the real session-ticket spend path and verifies the same schema and exact relay counters; no session or ticket metadata reaches the file.

`node packages/node/gateway/destination-log-retention.selftest.mjs` uses a controlled clock and private disposable directories to check the default and minute/hour/day retention boundaries, idle sweeps, coalescing, `forever`, global oldest-first eviction, same-minute segment rotation, restart recovery, invalid settings, bounded queue, oversize drops, symlink/hardlink refusal and runtime I/O failure isolation.

Run all gateway selftests for regressions. This is not a real Groth16/Tor/deployed-host test.
