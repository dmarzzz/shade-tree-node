# PSE RLN ceremony: verification run of 2026-09-30

Status: **verified from public inputs on an independently built toolchain; adopted** (this PR).
Companion to [PSE-ADOPTION.md](PSE-ADOPTION.md) (the decision and the interop evidence) and to the
`ceremony` block of [`testdata/zk-artifacts.lock.json`](../../testdata/zk-artifacts.lock.json)
(every pin). Machine-readable transcript: [`pse-transcript.json`](pse-transcript.json).

## What was verified, and how

Everything below was reproduced on 2026-09-30 on a machine that had none of it before: circom
v2.1.5 built from the iden3 source, `circom-rln` cloned at `17f0fed`, snarkjs 0.7.5 from the
ceremony kit's lockfile, and every ceremony file fetched from PSE's public bucket and Firestore.

| # | Check | rln-20 | rln-withdraw |
|---|---|---|---|
| 1 | PSE's initial and final zkeys match the hashes pinned in `pse-check.mjs` | pass | pass |
| 2 | Initial zkey blake2b-512 matches PSE's Firestore `initialZkeyBlake2bHash` | pass | pass |
| 3 | Final zkey blake2b-512 matches Firestore's `final` contribution record | pass | pass |
| 4 | PSE's published R1CS and WASM are byte-identical to a local circom 2.1.5 `--O2` build of `17f0fed` | pass (2,737,828 B / 2,399,653 B) | pass (97,188 B / 1,627,935 B) |
| 5 | Their blake2b-512 match Firestore's `r1csBlake2bHash` / `wasmBlake2bHash` | pass | pass |
| 6 | Hermez `powersOfTau28_hez_final_13.ptau` sha256 and blake2b-512 match the pins and Firestore's `potBlake2bHash` | pass | pass (PSE used the power-8 prefix; identical key material) |
| 7 | Every key section (1–9) of PSE's initial zkey is byte-identical to `snarkjs zkey new` from the rebuilt R1CS and the ptau | pass | pass |
| 8 | `snarkjs zkey verifyFromInit` accepts the whole chain from the initial zkey to the final zkey | 60 contributions + beacon | 62 contributions + beacon |
| 9 | Every contribution in Firestore is `valid: true`, and the contributor set matches the zkey headers | 60 records, 60 distinct participants | 62 records, 62 distinct participants |
| 10 | Beacon: the chain's generator equals sha256 of the beacon value PSE published | `003089a0…0203` = sha256(`0xa894a3f9…bb9d`), 2^10 iterations | same value, same generator |
| 11 | Verification keys exported from the final zkeys parse equal to PSE's published `*_vkey.json` | pass | pass |
| 12 | A witness from the rebuilt WASM proves under the final zkey and verifies under its key | via the repo's JS + Rust interop (below) | pass |

Repo-side, with the swapped artifacts in place: `node scripts/zk-artifacts-lock.mjs --check`,
`test/zk-artifacts.selftest.mjs`, `forge test` (169 tests, the withdraw fixture regenerated under
the new key and verified on-chain by `WithdrawVerifier`), the bytecode manifest, and
`cargo test -p shadenet-rln --all-features` (embedded artifacts self-check against the lock) all pass.

## The ceremony, as recorded

- **Coordinator:** Privacy & Scaling Explorations (EF). p0tion ceremony `B7HZ7yW6waAWGKLr7GiA`,
  prefix `rln-trusted-setup-ceremony`, state `FINALIZED`; open 2023-07-31 to 2023-09-03,
  finalized 2023-09-04. Page: <https://ceremony.pse.dev/projects/RLN%20Trusted%20Setup%20Ceremony>.
- **Source:** `Rate-Limiting-Nullifier/circom-rln` at `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d`,
  compiled with circom 2.1.5 (`127414e9`) at `--O2`. `RLN(20,16)` = 5,820 constraints;
  `Withdraw` = 214.
- **Phase 1:** Hermez `powersOfTau28_hez_final_13.ptau`, sha256
  `95751b5207f20aa822f01109902315c01c15250303feacea2b8aa7dc9fdfeefd`.
- **Contributors** (GitHub login and id, as the zkey headers name them; the same 60 people
  contributed to `rln-20` and 62 to `rln-withdraw`): see `ceremony.contributors` in the lock and
  `pse-transcript.json`. The coordinator account `mpc-dev-121107909` closed both chains with the
  beacon.
- **Beacon:** value `0xa894a3f9b7ae52bcf5802b944aa60d46f72cfa1c5ad5ee601085c7c6ca08bb9d`,
  generator `sha256(value)` = `003089a09896828eafa9def4c833db71a1a4e5e884229f80312623a03cda0203`,
  2^10 iterations (snarkjs `zkey beacon`).
- **Files:** `rln-20_final.zkey` sha256 `ae30d3d4b29d9dab8c65ff181644a3eb57c2c0fa9f687ea3baf8c7f711d7946a`;
  `rln-withdraw_final.zkey` sha256 `c8c778bc0123b43071ae2d218d88f343d7be05d6b1a843c695289c6c3d7cf8e5`.

## Archive (two mirrors)

Bundle `shadenet-ceremony-pse-rln-2026-09-30.tar.gz`, sha256 `47d623f62428ab9efdce3e1c8ba9be8666254fb6f032568acbe62c87fe7e4ba7`: PSE's published zkeys, R1CS,
WASM, vkeys and verifier contracts; the ptau; Firestore snapshots (ceremony, circuits, both
contribution collections, participants); both `verifyFromInit` transcripts; the `pse-check` log;
the rebuilt R1CS; `SHA256SUMS`.

1. GitHub release <https://github.com/dmarzzz/shade-tree-node/releases/tag/ceremony-pse-rln-2026-09-30>
   (tarball, `SHA256SUMS`, the four zkeys, both vkeys and `pse-transcript.json` as assets).
2. Cloudflare R2, bucket `flightdeck-private`, prefix `shadenet/ceremony/pse-rln-2026-09-30/`
   (private; served through the Flight Deck hub's presigned links).

Upstream stays at `rln-trusted-setup-ceremony-pse-p0tion-production` (S3 eu-central-1, public GET).

## What this does and does not establish

The toxic waste of both proving keys is gone **if at least one of the contributors to each chain
was honest** and the Hermez phase-1 and snarkjs assumptions hold. The chains verify; the
published beacon closes them; the inputs are the source we build. This does not audit the
circuits, the contracts or this software, and it is not a statement by anyone outside this
project. The runbook's H3 step 2, a signed statement from an independent verifier outside the
core team who re-runs `scripts/ceremony/pse-check.mjs`, is still open; link it in the lock's
`ceremony.independentVerifierStatement` when it exists.

## Re-run it

```sh
npm ci --prefix scripts/ceremony --ignore-scripts
git clone https://github.com/iden3/circom && (cd circom && git checkout v2.1.5 && cargo build --release)
git clone https://github.com/Rate-Limiting-Nullifier/circom-rln && (cd circom-rln && git checkout 17f0fed && npm ci --omit=dev --ignore-scripts)
node scripts/ceremony/pse-check.mjs --work /tmp/pse --circom circom/target/release/circom --circom-rln circom-rln
```

Then relate the beacon yourself: `printf '%s' 0xa894a3f9b7ae52bcf5802b944aa60d46f72cfa1c5ad5ee601085c7c6ca08bb9d | shasum -a 256`
must print the generator the transcript shows.
