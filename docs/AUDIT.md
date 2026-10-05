# Audit guide

This is a reference implementation, unaudited. This page is the entry point for reviewing it
end to end: how to run everything, what the trust boundaries are, what is guaranteed vs trusted
vs out of scope, and what to read in what order.

## Run everything

```bash
npm install
npm test                 # every *selftest.mjs (auto-discovered) + `forge test`
npm run test:node        # node selftests only (no foundry toolchain needed)
npm run test:contracts   # forge test only
node scripts/doctor.mjs  # environment sanity (node, tor, deps, keys)
```

`scripts/test-all.mjs` discovers every selftest, so a new `*selftest.mjs` is included with no
wiring. It exits nonzero and names the failing suite if anything breaks.

## Test inventory

| Suite | Covers |
|---|---|
| `packages/node/lib/directory.selftest.mjs` | The trust-critical module. ed25519 sign/verify, the v3 onion↔key binding, canonical signing, every `verifyDirectory` rejection (wrong signer, unsigned, tampered field, **grafted onion**, mismatched declared signer), live onion-control proofs, last-known-good fallback, weighted selection + health. |
| `packages/node/bootnode/selftest.mjs` | The discovery loop end to end over real HTTP. Honest announce accepted; **forged onion sig, wrong key, stale ts, replayed nonce, unstaked operator, stolen operator sig all rejected**; served directory verifies against the pinned signer; TTL expiry; zero-trust re-verification. |
| `packages/node/bootnode/keygen.selftest.mjs` | Tor v3 key-format correctness: the seed we keep and the key Tor publishes derive the same onion. Asserts the expanded secret key equals `clamp(SHA512(seed)[:32]) ‖ SHA512(seed)[32:]` and the public file equals the seed's ed25519 pubkey. |
| `packages/node/bootnode/fetch.selftest.mjs` | The HTTP response parser (`parseHttp`): well-formed 200, non-200 throws, missing terminator throws, unicode/large bodies. |
| `packages/node/lib/gateway-registry.selftest.mjs` | The stake verifier: mock (open + allowlist), factory resolution, and the on-chain `eth_call` encode/decode (selector, address padding, bool decode, caching) against a stubbed fetch. |
| `packages/node/lib/rln.selftest.mjs` | RLN prove/verify, the spent-set: first share egresses, identical replay deduped (no slash), second distinct signal reconstructs + slashes exactly once, independent per-nullifier counters. |
| `packages/node/gateway/shim.selftest.mjs` | The gateway spent-set control flow and the client envelope (v4 bundle, share bound to `requestSignal(target,nonce)`, per-tunnel nonce). |
| `packages/node/bin/shade-tree.selftest.mjs` | The CLI: help/version/unknown-command/doctor, flag→env mapping, positional + passthrough flags. |
| `packages/node/client/selection.selftest.mjs` | Directory-source selection: verify + rotate + last-known-good, and rejection under a wrong pinned signer. |
| `test/*.t.sol` (Foundry) | `StakedReputationSet` (register/exit/withdraw/slash, unbonding, ZK-auth), `GatewayRegistry` (stake/exit/withdraw/governed slash/ownership), Poseidon JS↔Solidity parity. |

## Trust model, by component

**What is cryptographically guaranteed (never trusts an intermediary):**

- *Client anonymity to the gateway.* Onion rendezvous, no exit node. The gateway sees
  `127.0.0.1` for every request.
- *Membership.* A valid RLN Groth16 proof against an admission root inside the freshness window.
  Forged sets fail the root check; bad proofs fail verification.
- *Per-tunnel unlinkability + rate limiting.* Each request carries a fresh nullifier; an
  over-spend reconstructs the secret (Shamir) and slashes. No shared per-epoch key to correlate.
- *Onion control.* A directory/announce entry's `.onion` **is** its ed25519 key; the key is
  re-derived from the address, so a grafted or swapped onion is rejected by the client's own check.

**What is trusted, and how far:**

- *The bootnode and pinned directory signer* form a discovery trust boundary. A compromised signer
  can omit, reorder, or add an internally consistent entry, including a malicious onion it controls.
  Onion/key binding prevents redirection of an existing onion to another key. Signed capabilities
  remain verifiable when present. `GET /gateway/<onion>` exposes the raw announcement, and optional
  stake re-verification narrows risk for entries that claim stake.
- *The pinned directory signer* (`SHADE_TREE_DIR_SIGNER`) is distributed out of band. There is
  intentionally no default. The pin prevents trust-on-first-use, but its holder still controls
  the candidate list.
- *The RPC endpoint* for on-chain reads is trusted like any node read; run your own for the
  solo-staker path. Stake reads default to `latest`; set `SHADE_TREE_CONFIRMATIONS` for reorg safety.
- *The admission ceremony* (whatever adds a leaf) is the sybil-resistance root. The proof gates
  membership; it does not create reputation.
- *The gateway operator* sees a member's `host:port` targets (metadata only, never plaintext) for
  the requests routed to it. Per-tunnel rotation across N non-colluding gateways spreads this to
  ~1/N; RLN's fresh nullifiers stop even colluding gateways from rejoining a member's requests.

**Governed, not permissionless (by design):**

- `GatewayRegistry.slash` is owner-gated. A member over-spend is a cryptographic proof, so
  `StakedReputationSet.slash` is permissionless; gateway misbehavior is a subjective judgment, so
  its slash is governance. Swapping `owner` for a DAO or a fraud-proof verifier is a drop-in change.

## Known unaudited surfaces (review these hardest)

- **ZK artifacts** in `circuits/rln/` are the output of PSE's 2023 RLN trusted setup ceremony,
  adopted and re-verified by this project, not run by it (`circuits/rln/ARTIFACTS.md`). Sound if
  at least one contributor to each was honest; not for real funds or sensitive traffic
  (see the [research preview statement](../SECURITY.md#status)).
- **The onion↔operator binding** in a stake-mode announce is verified by the bootnode at announce
  time; clients re-verify onion control cryptographically and can re-check the operator's live
  stake, but rely on the bootnode's signature for the operator↔onion *pairing* unless they fetch
  `GET /gateway/<onion>` and re-verify the operator signature themselves.
- **Replay within the Tor tunnel.** The gateway dedups by nullifier and slots; a proof only ever
  travels inside the onion-encrypted tunnel to a single verifier. The message is not bound to the
  target beyond the request signal.
- **The deploy bootstrap** (`packages/node/bootnode/deploy/bootstrap.sh`) runs as root on a fresh box. It is
  exercised end to end in CI inside a systemd container (`.github/workflows/bootstrap-e2e.yml`,
  `packages/node/bootnode/deploy/e2e-container.sh`, T-TEST-8), which proves it brings the fleet up, not that
  every root-level side effect is safe; read it before running it.
- **Docker image build** is unverified in CI here (no daemon on the authoring machine); the compose
  schema validates.

## Suggested review order

1. `docs/BOOTNODE.md` + `docs/ONCHAIN.md` for the model, then this page.
2. `packages/node/lib/directory.mjs` (the trust core) with `packages/node/lib/directory.selftest.mjs` beside it.
3. `packages/node/bootnode/announce.mjs` + `packages/node/bootnode/server.mjs` + `packages/node/bootnode/selftest.mjs` (the discovery loop).
4. `contracts/StakedReputationSet.sol` + `contracts/GatewayRegistry.sol` + their `test/*.t.sol`.
5. `packages/node/lib/rln.mjs` + `packages/node/gateway/gateway.mjs` (the spent-set / slash path) + `packages/node/lib/rln.selftest.mjs`.
6. `packages/node/client/shade-tree-client.mjs` + `packages/node/client/selection.mjs` (proof-per-tunnel, rotation, failover).
