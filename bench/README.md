# Benchmarks

Reproducible measurements of what ShadeNet costs and what it reaches. Each benchmark is a
small Node CLI with a selftest, writes raw results with the provenance needed to reproduce
them, and has a report step that turns raw results into a markdown table.

| Benchmark | Measures | Network |
|---|---|---|
| [`egress/`](egress/README.md) | Which sites an exit type (direct, any HTTP CONNECT proxy incl. the member Proxy, SOCKS5 incl. Tor) lets each client (curl, Node, headless and headed Chromium) reach, how each site refuses, page time, and cold vs warm dial time | real sites, manual runs only |
| [`rln/`](#rln-proof-and-verify-timing) | RLN v4 proof generation (`proveForSlot`) and verification (`verifyEnvelope`) time, cold and warm, JS path | none |

`experiments/` holds historical measurements of older protocol versions and is not
maintained; new benchmarks go here.

## Rules every benchmark follows

- **CI never touches a real site.** Selftests use loopback servers only (`egress/fixtures.mjs`).
  The egress CLIs refuse non-loopback targets unless `--real` is passed, and refuse them under
  `CI` even with `--real`. Real runs are manual.
- **Provenance in the raw file.** The first row of every run says what produced it: harness
  commit and dirty flag, Node, Playwright, Chromium and curl versions, host CPU and OS, the sites
  file hash, the exit's ASN and country, and the exact arguments.
- **No secrets, no operator addresses in committed files.** Result rows never store cookies. A
  non-loopback proxy host is written as `scheme://<redacted>`. Reports hide exit IPs unless
  `--show-ips` is given; dial rows store a short hash of the exit IP, not the IP. Name exits by
  label, ASN and country in anything you publish.
- **Honest scope.** A report states n, the time window, and what was not measured.

## Adding a benchmark

A directory under `bench/` with a CLI, a `*.selftest.mjs` (picked up by `npm test`
automatically), and a section in this README: what it measures, what it does not, how to run
it. Use what is already in `package.json`; a new dependency needs a note on why.

## RLN proof and verify timing

`bench/rln/prove-verify.mjs` builds an in-memory RLN group of ephemeral members (as
`test/timing.selftest.mjs` does), then times `proveForSlot` and `verifyEnvelope`. The first
call of each is reported as cold (artifact load and snarkjs worker start, paid once per
process); the rest are warm. Every envelope it times must verify, or the run fails.

```bash
node bench/rln/prove-verify.mjs --label laptop --prove 20 --verify 200 --out bench/rln/runs/laptop.json
node bench/rln/prove-verify.mjs --markdown bench/rln/runs/*.json
```

The output stamps the commit, the circuit artifact id, K, the CPU and the exact command.

This is one piece of [#63](https://github.com/dmarzzz/shade-tree-node/issues/63): the JS
proof and verify rows. Still open there: the Rust prover (`crates/shadenet-rln`), paired
direct-Tor vs ShadeNet request latency to one target, gateway saturation under a controlled
ramp, and the published table. Crypto timing is not throughput and not Tor latency.
