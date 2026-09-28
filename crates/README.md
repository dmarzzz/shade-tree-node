# ShadeNet for Rust

The Rust workspace holds the `shadenet` SDK, the `shadenet` command-line
binary built on it, and the trust-critical protocol code behind both.

> Research preview. The bundled RLN artifacts are suitable for testing, not a
> production trusted setup. See [`../circuits/rln/ARTIFACTS.md`](../circuits/rln/ARTIFACTS.md).

The protocol spec, [`../docs/WIRE-SPEC.md`](../docs/WIRE-SPEC.md) and the golden
vectors in [`../testdata/vectors.json`](../testdata/vectors.json) are the
reference. The Rust SDK and the JavaScript SDK both test against them
([ADR 0010](../docs/adr/0010-two-sdks-one-spec.md)).

## Workspace

```text
crates/
├── shadenet/         THE RUST SDK: Client, config, status, connect, fetch, the local proxy
├── shadenet-cli/     the `shadenet` binary (also installed as `shade-tree` for one minor release)
├── shadenet-proto/   canonical bytes, signatures, selection, receipts (no I/O)
└── shadenet-rln/     RLN proving, verification, and artifact bindings
```

`shadenet-proto` owns every deterministic security decision and has no I/O or
JSON serializer dependency. The SDK parses untrusted input into local structures
and hands them to it. The CLI is a thin clap shell over the SDK.

## The SDK

```rust
use std::sync::Arc;

let config = shadenet::Config::builder()
    .identity_file("identity.json")      // from `shadenet init`
    .build()?;                           // bundled Sepolia network by default
let client = Arc::new(shadenet::Client::new(config)?);
client.spawn_canopy_refresh();           // keep the signed canopy fresh in the background

let status = client.status().await;      // admitted? finalized? tunnels left? resets when?
let page = client.fetch(shadenet::FetchRequest::get("https://example.com/")).await?;
let tunnel = client.connect("example.com:443").await?;   // raw stream; speak TLS over it

// The same proxy the CLI runs:
let proxy = shadenet::ProxyConfig::new("127.0.0.1:8118", token);
let listener = shadenet::proxy::bind(&proxy).await?;
shadenet::proxy::serve(client, listener, proxy).await?;
```

One `Client` serves many tunnels. It keeps the verified canopy in memory (with a
last-known-good copy on disk and a rollback floor), reuses the member set for 30
seconds instead of replaying chain logs per tunnel, remembers node health, and
shares one embedded Arti bootstrap and one bounded prover across tunnels.

Every failure is a typed `shadenet::Error` with a stable code, exit code and
HTTP status:

| Code | HTTP | Exit | Meaning |
|---|---|---|---|
| `not_admitted` | 403 | 2 | The leaf is not in the admission set |
| `not_finalized` | 403 | 2 | Registered, but the block is not final yet |
| `port_not_allowed` | 403 | 2 | No node egresses to this port (nodes serve 443) |
| `budget_exhausted` | 429 | 4 | This epoch's tunnels are used up; `Retry-After` says when it resets |
| `no_eligible_node` | 503 | 2 | No node fits the admission, rate or capability policy |
| `canopy` | 503 | 2 | The signed canopy is unavailable and no last-known-good copy exists |
| `rpc` | 503 | 2 | Member discovery over JSON-RPC failed |
| `transport` | 503 | 3 | Every candidate failed at the Tor or TCP level |
| `node_refused` | 502 | 1 | A node answered and refused |
| `config`, `artifact`, `slot_state`, `prove`, `internal` | 500 | 2–3 | Local problems; nothing was sent |

Without the default `live` feature the crate is the deterministic half only:
network profiles, canopy verification and caching, selection filters and the
health cache. The fast default CLI build links it that way.

The crate is not on crates.io yet (`publish = false`): its embedded circuit
artifacts and network record are read from the repository at build time. Use a
Git or path dependency.

## Build and test

```sh
cargo build --release -p shadenet-cli                   # deterministic commands only
cargo build --release -p shadenet-cli --features live   # the full client
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
bash shadenet-rln/interop/proxy-concurrency-run.sh      # 8 tunnels at once through the real JS node
```

The binaries are `target/release/shadenet` and `target/release/shade-tree`.
Release binaries and checksums are attached to tagged GitHub releases; see
[`INSTALL.md`](INSTALL.md).

## Commands

```text
shadenet init                  # identity, proxy token, config file; then what is left to do
shadenet status [--json]       # admission, budget, canopy; --wait polls until ready
shadenet doctor [--json]       # every local problem at once
shadenet proxy                 # the local HTTP CONNECT proxy for agents and SearXNG
shadenet run -- <agent>        # run a command through that proxy
shadenet mcp                   # MCP tools shadenet_fetch, shadenet_status, shadenet_search
shadenet fetch <https-url>     # one request through ShadeNet
shadenet register-member …     # stake a leaf on chain
shadenet member-status …       # read bond and exit state
shadenet exit-member …         # local ZK exit authorization
shadenet withdraw-member …     # private refund to a recipient
shadenet egress …              # one tunnel, for scripts and debugging
shadenet enroll | identity | proxy-token | leaves
shadenet verify-directory | fetch-directory | select | verify-receipt
```

`shadenet <command> --help` documents each one. Global flags: `--network
<name|deployment.json>` selects a network record (so a staging canopy needs no
new binary), `--config`, `--log-level`, `--log-format json`.

Configuration is read in this order: flags, then `SHADENET_*` environment
variables, then `~/.config/shadenet/config.toml`, then the network record.
`SHADE_TREE_*` names still work for one minor release; setting both names of one
variable to different values is an error. `shadenet run` removes every
variable under either prefix from the child's environment.

## Safety notes

- RLN slot state lives in `…/shade-tree/rln-slots/<leaf>.json`, shared with the
  JavaScript client. The directory keeps that name through the rename: a fresh
  directory mid-epoch would reuse a nullifier and get the member slashed.
- The slot file is written and fsynced before a proof is built, so a crash burns
  a slot rather than reusing one. A lock left by a dead process is recovered.
- The proxy binds loopback only unless `--allow-non-loopback` is given, and it
  always requires the token.
- `--plain-tcp` (no Tor) exists only in debug builds, for test harnesses.
- Identity secrets are never accepted on the command line and are zeroized in
  memory after use.

## Protocol changes

ShadeNet speaks protocol v4. Signed, hashed and proved strings keep their
"Shade Tree" spelling until a versioned v5; `test/wire-freeze.selftest.mjs`
pins them. See [`../docs/MIGRATING-TO-SHADE-TREE.md`](../docs/MIGRATING-TO-SHADE-TREE.md)
for the v3 to v4 boundary.
