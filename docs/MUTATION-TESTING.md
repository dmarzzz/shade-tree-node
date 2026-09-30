# Mutation testing (T-TEST-10)

Line/branch coverage tells you a line *ran* during a test. It does not tell you the
test would have *failed* if that line were wrong. Mutation testing closes that gap: it
injects small bugs ("mutants") into the source — flip a `<` to `<=`, replace a string
with `""`, force an `if` to `true` — then reruns the tests. A mutant that makes a test
fail is **killed** (good: the suite catches that regression). A mutant that leaves every
test green **survived** (a blind spot: a real bug shaped like that would ship silently).

The **mutation score** is `killed / (killed + survived)`. Higher is better; it is a
direct measure of how well the tests would catch regressions, not just how much code
they touch.

We use [Stryker](https://stryker-mutator.io/) with its built-in **`command`** test
runner (this repo uses hand-rolled `*.selftest.mjs` scripts, not jest/mocha, so there is
no framework plugin to load). Config: [`stryker.config.json`](../stryker.config.json).

## Scope — and why

Mutation testing is expensive: every mutant reruns the whole test command. So we scope
it tightly to the **fast, security-critical, pure modules** whose fast selftests fully
cover them. The `mutate` glob in the config is:

| Mutated file | Why it is high-value | Covering fast selftest(s) |
| --- | --- | --- |
| `packages/node/lib/gateway-registry.mjs` | Stake gate — decides which gateways an `admission=stake` policy admits (mock + on-chain `eth_call` encode/decode). | `packages/node/lib/gateway-registry.selftest.mjs` |
| `packages/node/gateway/gateway.mjs` | Egress guard — `makeEgressPolicy` + `validTarget` (allow/deny host:port matching) and `makeSpentSet` (proof replay defense). | `packages/node/gateway/egress-policy.selftest.mjs`, `packages/node/gateway/replay-cache.selftest.mjs` |
| `packages/node/lib/directory.mjs` | Signed gateway directory — verification, onion→pubkey derivation. | `packages/node/lib/directory.selftest.mjs`, `packages/node/lib/directory-rotation.selftest.mjs` |
| `packages/node/bootnode/announce.mjs` | Announce record build/verify — canonical bytes, operator sig, staleness/replay checks. | `packages/node/bootnode/selftest.mjs` (exercises `buildAnnounce`/`verifyAnnounce` via `makeServer`) |

**Deliberately excluded:** `packages/node/lib/rln.mjs` (and the `rln`, `rln-slash`, `timing` suites).
Mutating RLN forces the slow real-Groth16 proof suites, which would make a run take
hours. Those keep their own `*.selftest.mjs` real-proof coverage; they are just not
mutation-tested here. If you add RLN to the scope, expect a very long run and raise the
`timeoutMS`.

Because the `command` runner cannot map an individual mutant to individual tests
(`coverageAnalysis: "off"`), **every mutant reruns the full covering-selftest chain**
defined in `commandRunner.command`. That chain is only the fast selftests above (~2s),
never the slow proof suites.

## How to run

Full scoped run (all four files — this is the periodic quality check, slow):

```
npm run mutation:test
```

Quick smoke run on a single small file (proves the config works in ~2 min):

```
npx stryker run --mutate packages/node/lib/gateway-registry.mjs
```

Reports:

- Console: a `clear-text` summary table (mutation score per file) plus a `progress` bar.
- HTML: `reports/mutation/index.html` — click any file to see each surviving mutant with
  its exact source diff. (Generated output; not committed.)

## Reading the score

```
File                  |  % score | # killed | # survived | # errors |
 gateway-registry.mjs |    66.07 |       74 |         38 |        0 |
```

- **`# errors` must be 0.** A nonzero count means the test *command* failed to run (a
  broken sandbox, a bad path), not that a mutant was caught — fix the harness first, the
  score is meaningless until then.
- **killed** = a test failed on the injected bug. Good.
- **survived** = no test noticed. Each survivor is a candidate test gap.

Config thresholds (`stryker.config.json`): `high: 85`, `low: 65`, `break: null`. `break`
is intentionally `null` — **this job never fails a build.** It is a diagnostic surfaced
to humans, not a CI gate.

## NOT in default CI

This is a **periodic** check (run it before a release, or when touching one of the scoped
security modules), not part of `npm test` / the coverage gate. It is far too slow for
per-push CI: the single-file smoke run above already takes ~2 minutes; the full scoped
run is minutes-to-tens-of-minutes depending on the machine. Run it deliberately and read
the survivors.

## Known survivors (test-gap follow-ups)

A smoke run on `packages/node/lib/gateway-registry.mjs` scored **66.07%** (74 killed / 38 survived, 0
errors). The survivors cluster in the **on-chain `OnchainStakeVerifier`** path, which the
selftest exercises against a stubbed `fetch` but does not assert exhaustively. Examples
worth a follow-up test (do NOT change source to satisfy the mutant — add the assertion):

- **Error-message text is not asserted.** Mutants that blank the `throw new Error("…")`
  strings ("OnchainStakeVerifier needs SHADE_TREE_GATEWAY_REGISTRY…", the `unknown
  SHADE_TREE_STAKE_MODE` message) survive. Follow-up: assert the thrown message, or at least
  that a throw occurs on missing `contract` / bad mode.
- **Cache boundary `now - hit.at < cacheMs`** — the `<` vs `<=` mutant survives; no test
  pins the exact expiry edge. Follow-up: a test that a cached value is reused just under
  `cacheMs` and refetched just over it.
- **`.toLowerCase()` on the operator cache key** — flipping to `.toUpperCase()` survives;
  no test mixes operator-address casing against the cache.
- **Allowlist `.filter(Boolean)`** — dropping it survives; no test feeds a trailing-comma
  / empty-entry allowlist string.
- **`typeof ret === "string"` guard and the `/^0x0*/` anchor** in the return-value parse
  survive; no test feeds a non-string / oddly-padded `eth_call` return.

These are follow-up **tests**, not source changes: the source is correct; the suite just
does not yet prove it. Re-run and update this list as the scope grows to the other three
files.
