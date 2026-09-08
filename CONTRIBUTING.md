# Contributing

A research-preview reference implementation of Shade Tree. The bundled v4 Sepolia
profile is a disposable test network; the older `network/sepolia/contracts.json`
record is retired pre-v4 history. The code is unaudited (see [`SECURITY.md`](SECURITY.md)).
Contributions are welcome; this page is how to run the tests and the house rules a change must hold to.

## Run the tests

```bash
npm ci
npm run test:fast        # quick iteration; slow proof/onchain suites + Foundry skipped
npm test                 # every *selftest.mjs (auto-discovered) + `forge test`
npm run test:node        # node selftests only, no foundry toolchain
npm run test:contracts   # forge test only
node scripts/doctor.mjs  # environment sanity (node, tor, deps, keys)
```

`scripts/test-all.mjs` is the audit entrypoint. It recursively discovers every
file ending in `selftest.mjs`, runs each, then runs the Foundry contract suite,
and exits nonzero naming the failing suite. There is no test manifest to edit:
drop a `*selftest.mjs` anywhere in the tree and the runner picks it up (it skips
`node_modules`, `out`, `.git`, and `cache`). If `forge` is not installed the
contract suite is skipped, not failed; run `npm run test:node` to skip it
deliberately.

## Definitions of done

Every change is expected to meet these before it lands (from
`docs/SHIP-PLAN.md`):

- **Every new module ships a `*selftest.mjs`.** No module without one.
- **Every wire or parse surface gets an adversarial test.** Anything that takes
  untrusted bytes (a signature check, a parser, a state machine) needs negative
  cases that *fail on a real defect*: garbage in returns `ok:false` and never
  throws or hangs, a tampered field is rejected, a flipped comparison would be
  caught. Positive-path-only does not count.
- **Every contract change gets a Foundry test** in `test/*.t.sol`.
- **No secret is ever committed or logged.** Not a member identity secret, a
  seed, or an onion secret key. `test/log-hygiene.selftest.mjs` scans for this;
  keep it passing.
- **Docs are updated in the same change**, never deferred to a "docs later"
  task. If you touch a wire format, update `docs/WIRE-SPEC.md`; if you touch a
  command or flag, update `docs/CLI.md` / `docs/CONFIG.md`.
- **No new dependency without a note on why.** Prefer the standard library and
  what is already in `package.json`.
- **Honest scope.** If a task is only partly done, split it and mark what
  remains rather than implying it is complete.

## Trust-model invariants

These are load-bearing. A change must not break them; if a change appears to
need to, that is a design discussion, not a quiet edit. All are grounded in
[`docs/AUDIT.md`](docs/AUDIT.md).

- **The onion is never on chain.** On-chain state carries stake and membership,
  never a node's `.onion`. Discovery is off-chain, through the Elder Tree.
- **The Elder Tree is a cache; its pinned Canopy signer is an authority.** The
  Proxy re-derives each onion's ed25519 key and verifies onion-signed
  capabilities when present. The signer can still omit, reorder, or add an
  internally consistent entry. Live stake rechecking is opt-in. Do not expand
  that authority or describe discovery as trustless.
- **Fail closed on missing or hostile input.** A missing signer, an absent
  nonce, a malformed field, an unreachable RPC: reject with a precise reason and
  a nonzero exit, never fall through to an open or trusting default.
- **Cheap checks before expensive verify.** Do the cheap rejections (format,
  freshness, throttle, size cap) before an ed25519 verify or a Groth16 verify, so
  hostile input cannot force expensive work. Keep new code on this ordering.
- **The `2b <- check4` authority invariant** in `verifyEnvelope`
  (`lib/rln.mjs` / `gateway/gateway.mjs`). Target binding recomputes
  `calculateSignalHash(requestSignal(target, nonce))` and binds it to the
  proof's committed `x`; the field-safety check (`signalFieldSafe`, rejecting a
  delimiter or over-long nonce) must run *before* hashing so `(target, nonce) ->
  signal` stays injective independent of the gateway's later `validTarget`
  filter. Do not reorder these or let a swapped target/nonce reach egress.

## Code style

- **Match the surrounding code.** ESM `.mjs`, the existing import and error
  conventions, the existing naming. Read the neighbours before adding a file.
- **Comment the WHY, thoroughly.** The existing code explains *why* a check
  exists and what attack it closes, not just what the line does. Keep that up;
  a security check with no rationale is hard to review and easy to delete.
- **No em dashes** in prose or comments (repo convention). Use a comma, a
  colon, or a full stop.
- **No marketing.** Terse and accurate. Say what a thing does and what it does
  not.

## Roadmap and gates

The shipping backlog and priorities live in
[`docs/SHIP-PLAN.md`](docs/SHIP-PLAN.md); the protocol-design milestones are in
`docs/ROADMAP.md`. The 2026-08-17 go-live log records the retired pre-v4
research deployment; `network/sepolia/deployment.json` records the current disposable
v4 research profile. Keep wire
formats and signed capabilities versioned (`docs/VERSIONING.md`), keep
the golden vectors and Rust conformance suite green, and read
`docs/OPERATOR.md` before touching service code.

Some actions are never taken autonomously and must be flagged for a human:
rotating or replacing production onion or operator keys, spending real funds,
running a trusted-setup ceremony, deploying a breaking change to a live gateway
serving members, or merging to `main` without CI green.
