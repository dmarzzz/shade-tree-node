# Trusted-setup ceremony runbook (T-HARD-1)

Operator runbook for producing PRODUCTION Groth16 artifacts for this repo's two circuits and
pinning them into every consumer. This is the human half of ship-plan **T-HARD-1**; the
autonomous half (hash lock + CI check) is already wired and described in §7.

**Status: no ceremony has been run.** Everything under `circuits/rln/` is circom-rln's DEV
phase-2 (two hard-coded contributions + a fixed beacon, `circuits/rln/ARTIFACTS.md` "Trust /
honesty note"). `testdata/zk-artifacts.lock.json` declares this as `provenance:
"dev-testnet-untrusted"`, `trust: "UNTRUSTED-TESTNET"`. Anyone holding that toxic waste can
forge membership proofs (free egress under any root) and exit-auth proofs (drain any member's
bond). Do not run real funds or real anonymity on these artifacts.

Nothing in this document runs by itself. Every command is for a human on a machine they control.

---

## 0. Inventory — what exists, who loads it

### Circuits (upstream, unchanged; we do NOT author circuits)

| Circuit | Source | `main` | Public signals | Constraints |
| --- | --- | --- | --- | --- |
| `rln` | `Rate-Limiting-Nullifier/circom-rln` tag `v1.0.0`, commit `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d`, `circuits/rln.circom` | `RLN(20, 16)` (DEPTH=20, LIMIT_BIT_SIZE=16) | 5: `[y, root, nullifier, x, externalNullifier]` | 12,390 (12,413 wires) — needs ptau ≥ 2^14 |
| `withdraw` | same checkout, `circuits/withdraw.circom` | `Withdraw` | 2: `[identityCommitment, address]` | not recorded in-repo; run `snarkjs r1cs info` (fits 2^14, zkey is 188 KB) |

Toolchain the current artifacts were built with (`circuits/rln/ARTIFACTS.md`): circom `2.2.2`
(iden3/circom tag `v2.2.2`, built from source), snarkjs `0.7.x`, circomlib `2.x`. The repo's
`node_modules/snarkjs` is `0.7.5` (`npx snarkjs`). Neither `circom` nor `snarkjs` is on PATH
by default on the dev box.

### Artifacts and consumers (all pinned in `testdata/zk-artifacts.lock.json`)

| Artifact | Setup-dependent? | Loaded by |
| --- | --- | --- |
| `circuits/rln/rln.wasm` | no (compiler output) | `lib/rln.mjs` `proveForSlot` (client + shim); Rust `include_bytes!` in `rust/shade-tree-rln/src/prover.rs` (live binary); `rust/shade-tree-rln/src/main.rs` probe |
| `circuits/rln/rln_final.zkey` | **yes** | `lib/rln.mjs` `proveForSlot`; Rust `include_bytes!` (live binary) |
| `circuits/rln/verification_key.json` | **yes** | `lib/rln.mjs` `verifyEnvelope` (gateway; the built-in entry of the `SHADE_TREE_ZK_ARTIFACTS` accepted set, id `rln-<sha256[0:16]>`); Rust in-process self-check + startup lock check; `rust/shade-tree-rln/interop/verify-envelope.mjs` |
| `circuits/rln/Verifier.sol` | **yes** | provenance copy of the snarkjs export; `contracts/RlnGroth16Verifier.sol` is this file + a `///` header (NOT deployed, membership is verified off-chain) |
| `circuits/rln/withdraw.wasm` | no | `testdata/gen-withdraw-proof.mjs`; (client-side exit-auth proving: **not wired**, no CLI command yet) |
| `circuits/rln/withdraw_final.zkey` | **yes** | `testdata/gen-withdraw-proof.mjs` |
| `circuits/rln/withdraw_verification_key.json` | **yes** | `testdata/gen-withdraw-proof.mjs` |
| `contracts/WithdrawGroth16Verifier.sol` | **yes** | wrapped by `contracts/WithdrawVerifier.sol`, deployed as `StakedReputationSet.withdrawVerifier` (**immutable**, `contracts/StakedReputationSet.sol:66`); `contracts/script/DeployRegistry.s.sol` (`SHADE_TREE_DEPLOY_REAL_VERIFIER=1`); `test/WithdrawVerifier.t.sol` |
| `testdata/withdraw-proof.json` | **yes** (bound to the withdraw VK) | `test/WithdrawVerifier.t.sol`, `test/StakedReputationSet*.t.sol` |

The `.wasm` files are compiler output and independent of the setup: recompiling the same
commit with the same circom SHOULD reproduce them byte-for-byte (see §2.4). Everything else
changes on a new ceremony and must move as a set per circuit.

Not in the repo, needed for the ceremony: the `.r1cs` files (`snarkjs zkey verify` needs
them) and the phase-1 `.ptau` (~300 MB). Both are reproducible; §2 pins their hashes.

Currently deployed on Sepolia against these untrusted artifacts (`network/sepolia/contracts.json`,
release `rln-v4-tiers`, 2026-08-17): `withdrawVerifier 0x522409038aA03FFF998d33C60A37486975695351`
(the REAL Groth16 `WithdrawVerifier` over `WithdrawGroth16Verifier 0x6B26a9B6…507E`, VK = this
untrusted dev phase-2), `stakedReputationSet 0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`.
(rln-v3, superseded: `withdrawVerifier 0x5A6FD01d…dbDB2` (mock), `stakedReputationSet
0xdAE242AE…20FC`.) Testnet only; superseded by §6.

---

## 1. Roles, decisions to make before day 0

| Role | Count | Duty |
| --- | --- | --- |
| Coordinator | 1 | builds `*_0000.zkey`, relays zkeys between contributors, verifies each contribution, applies the beacon, publishes the transcript, opens the pinning PR |
| Contributors | N ≥ 3 (recommend 5–10, at least one outside the core team) | one `snarkjs zkey contribute` each, on their own machine, then destroy entropy and publish an attestation |
| Independent verifier | ≥ 1, not the coordinator | reruns §4.1 from the published transcript before the pinning PR merges |

Decide and write down (goes into the transcript, §5):

- `CEREMONY_ID` — e.g. `shade-tree-rln-2026-09` (used as the beacon name and lock `ceremony.id`).
- Contributor list and order; a private channel for zkey hand-off (any transport — the
  protocol tolerates a malicious relay because every hop is verifiable, §4.1).
- **Beacon source, fixed in advance:** the hash of a future public randomness value neither
  the coordinator nor contributors control — e.g. Ethereum mainnet block hash at a block number
  announced ≥ 24 h ahead, or a drand round. Record source + index before contributions start.
- Whether to run the two circuits in one round (each contributor contributes to both zkeys
  back-to-back — recommended, one attestation covers both) or as two rounds.

---

## 2. Phase 1 — Powers of Tau (reuse, do not run)

Do NOT run a phase-1 ceremony. Reuse the Hermez / Perpetual-Powers-of-Tau BN254 file that the
current artifacts were already built with. `2^14 = 16,384 ≥ 12,390` constraints, the smallest
standard hermez file that fits `RLN(20,16)`.

```sh
mkdir -p ceremony/ptau && cd ceremony/ptau
curl -fLO https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau
shasum -a 256 powersOfTau28_hez_final_14.ptau
# MUST print 489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d
#   (pinned in testdata/zk-artifacts.lock.json -> ptau.sha256 and circuits/rln/ARTIFACTS.md)
npx snarkjs powersoftau verify powersOfTau28_hez_final_14.ptau
```

`powersoftau verify` must end in `Powers of Tau Ok!` and prints the file's blake2b contribution
hash; the coordinator records that hash in the transcript and compares it against the hash table
in the snarkjs README (iden3/snarkjs, "7. Prepare phase 2" table, row `14`). If either check
fails, stop — do not proceed with a mismatched ptau.

Rationale for reuse: the hermez ceremony had >50 independent contributors; the phase-1 toxic
waste is destroyed if any one of them was honest. A bespoke phase 1 would have fewer
contributors than that, so it is strictly weaker.

### 2.1 Compile the circuits (coordinator, deterministic)

```sh
# circom 2.2.2 from source (matches ARTIFACTS.md); do not use a newer major/minor without re-checking
git clone https://github.com/iden3/circom && cd circom && git checkout v2.2.2 && cargo build --release && cd ..
export PATH="$PWD/circom/target/release:$PATH"; circom --version   # circom compiler 2.2.2

git clone https://github.com/Rate-Limiting-Nullifier/circom-rln && cd circom-rln
git checkout 17f0fed7d8d19e8b127fd0b3e5295a4831193a0d && npm ci      # circomlib comes from its lockfile
mkdir -p ../build/rln ../build/withdraw
circom circuits/rln.circom      --r1cs --wasm --sym -l node_modules -o ../build/rln
circom circuits/withdraw.circom --r1cs --wasm --sym -l node_modules -o ../build/withdraw
cd ..
npx snarkjs r1cs info build/rln/rln.r1cs            # expect 12390 constraints, 5 public
npx snarkjs r1cs info build/withdraw/withdraw.r1cs  # record the constraint count
shasum -a 256 build/rln/rln.r1cs build/rln/rln_js/rln.wasm build/withdraw/withdraw.r1cs build/withdraw/withdraw_js/withdraw.wasm
```

Record all four hashes in the transcript. Cross-check the two `.wasm` hashes against the lock
(`d06035…ab0` for `rln.wasm`, `d0b642…2bb` for `withdraw.wasm`). If they match, the compile is
reproduced and the repo's `.wasm` files stay as they are. If they differ, stop and find out why
(different circom/circomlib build) BEFORE any contribution — contributors sign off on the
`.r1cs` they were given, so the `.r1cs` hash is the thing that must be published and stable.

### 2.2 Phase-2 initial zkey (coordinator)

```sh
mkdir -p ceremony/rln ceremony/withdraw
npx snarkjs groth16 setup build/rln/rln.r1cs           ceremony/ptau/powersOfTau28_hez_final_14.ptau ceremony/rln/rln_0000.zkey
npx snarkjs groth16 setup build/withdraw/withdraw.r1cs ceremony/ptau/powersOfTau28_hez_final_14.ptau ceremony/withdraw/withdraw_0000.zkey
shasum -a 256 ceremony/rln/rln_0000.zkey ceremony/withdraw/withdraw_0000.zkey   # -> transcript
```

Publish `rln.r1cs`, `withdraw.r1cs`, both `_0000.zkey` files and their sha256 to a
world-readable location BEFORE the first contribution (so contributors can verify they start
from the genuine setup, §3 step 1).

---

## 3. Phase 2 — multi-party contribution protocol

Each contributor `i = 1..N` runs the following on a machine they control (ideally freshly
installed / air-gapped for the entropy step; a laptop is acceptable). Contribution `i` consumes
`*_{i-1}.zkey` and produces `*_{i}.zkey`.

```sh
# 1. fetch inputs from the coordinator (any channel) and VERIFY the chain so far — this proves the
#    coordinator did not hand you a zkey with a hidden trapdoor for a different circuit.
shasum -a 256 rln.r1cs withdraw.r1cs                                       # == published hashes
npx snarkjs powersoftau verify powersOfTau28_hez_final_14.ptau            # (or trust the sha256 in §2)
npx snarkjs zkey verify rln.r1cs      powersOfTau28_hez_final_14.ptau rln_$((i-1)).zkey
npx snarkjs zkey verify withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_$((i-1)).zkey
#    both must print "ZKey Ok!" and list contributions 1..i-1 with hashes equal to the
#    attestations already published by contributors 1..i-1.

# 2. contribute. OMIT -e so snarkjs prompts for entropy; type a long random string (dice, keyboard
#    mashing, a hardware RNG dump pasted in). Never reuse it, never write it down.
npx snarkjs zkey contribute rln_$((i-1)).zkey      rln_$i.zkey      --name="<contributor i, CEREMONY_ID>" -v
npx snarkjs zkey contribute withdraw_$((i-1)).zkey withdraw_$i.zkey --name="<contributor i, CEREMONY_ID>" -v
#    each command prints "Contribution Hash:" — a 64-byte hex block. Copy both.

# 3. attest (this is what everyone else verifies against later)
shasum -a 256 rln_$i.zkey withdraw_$i.zkey > contribution-$i.txt
#    append: contributor name, date, machine description, the two Contribution Hash blocks,
#    and one sentence "entropy destroyed". Sign it (GPG / ssh-keygen -Y sign / an on-chain
#    signed message — any key the contributor is publicly known by). Publish it (their own
#    site / gist / repo / tweet) AND send it to the coordinator.

# 4. hand rln_$i.zkey + withdraw_$i.zkey back to the coordinator, then wipe the machine's
#    shell history / temp files.
```

Coordinator, on receipt of contribution `i`, before forwarding to `i+1`:

```sh
shasum -a 256 rln_$i.zkey withdraw_$i.zkey             # == contributor i's attestation
npx snarkjs zkey verify rln.r1cs      ceremony/ptau/powersOfTau28_hez_final_14.ptau rln_$i.zkey
npx snarkjs zkey verify withdraw.r1cs ceremony/ptau/powersOfTau28_hez_final_14.ptau withdraw_$i.zkey
#   both "ZKey Ok!"; the i-th listed contribution hash == the Contribution Hash in the attestation
```

A contribution that fails `zkey verify` or does not match its attestation is dropped (go back
to `i-1`), and the incident is written into the transcript. Contributions are strictly serial.

Optional alternative for contributors who want the bellman/kobi challenge-response flow (no
snarkjs on the contributor box): `snarkjs zkey export bellman`, `snarkjs zkey bellman
contribute`, `snarkjs zkey import bellman` — same verification rules apply.

### 3.1 Beacon + finalize (coordinator, after contribution N)

```sh
BEACON=<hex of the pre-announced public randomness, e.g. the mainnet block hash, 0x stripped>
npx snarkjs zkey beacon rln_$N.zkey      rln_final.zkey      $BEACON 10 -n="Final Beacon $CEREMONY_ID"
npx snarkjs zkey beacon withdraw_$N.zkey withdraw_final.zkey $BEACON 10 -n="Final Beacon $CEREMONY_ID"

npx snarkjs zkey verify rln.r1cs      ceremony/ptau/powersOfTau28_hez_final_14.ptau rln_final.zkey
npx snarkjs zkey verify withdraw.r1cs ceremony/ptau/powersOfTau28_hez_final_14.ptau withdraw_final.zkey

npx snarkjs zkey export verificationkey  rln_final.zkey      verification_key.json
npx snarkjs zkey export verificationkey  withdraw_final.zkey withdraw_verification_key.json
npx snarkjs zkey export solidityverifier rln_final.zkey      Verifier.sol
npx snarkjs zkey export solidityverifier withdraw_final.zkey WithdrawVerifier.sol
shasum -a 256 rln_final.zkey withdraw_final.zkey verification_key.json withdraw_verification_key.json Verifier.sol WithdrawVerifier.sol
```

The beacon step is what makes the final zkey uniformly random even if every contributor colluded
on their entropy; it is NOT a substitute for honest contributors (the trapdoor is destroyed iff
at least one contributor's entropy was honest and discarded).

---

## 4. Publish the transcript

Publish, world-readable and immutable (a git tag in this repo under `ceremony/<CEREMONY_ID>/`
plus a mirror — IPFS or a release asset):

1. `TRANSCRIPT.md`: `CEREMONY_ID`, dates, coordinator, ordered contributor list, beacon source
   + index + value, ptau sha256 + blake2b, `rln.r1cs`/`withdraw.r1cs` sha256, wasm sha256,
   `_0000.zkey` sha256, every `contribution-i.txt` verbatim + its signature, final zkey/vkey/
   verifier sha256, and the full stdout of the final `zkey verify` runs.
2. Every intermediate `*_i.zkey` (or at minimum their sha256 — publishing the files lets anyone
   recompute the chain; the rln chain is ~5.5 MB per step, withdraw ~190 KB).
3. Contributor attestation files + signatures.
4. The `.r1cs` files (**not wired:** the repo does not commit `.r1cs`; the transcript is where
   they live).

### 4.1 Independent verification (anyone, before merge)

```sh
# with the transcript's r1cs + ptau + final zkey:
shasum -a 256 powersOfTau28_hez_final_14.ptau rln.r1cs withdraw.r1cs rln_final.zkey withdraw_final.zkey   # == transcript
npx snarkjs zkey verify rln.r1cs      powersOfTau28_hez_final_14.ptau rln_final.zkey
npx snarkjs zkey verify withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_final.zkey
# the printed contribution list must equal (in order) the attested Contribution Hashes 1..N
# followed by the beacon; the beacon hash must be recomputable from the announced randomness.
npx snarkjs zkey export verificationkey rln_final.zkey /tmp/vk.json && diff /tmp/vk.json verification_key.json
```

An independent verifier signs a one-line statement "verified `<CEREMONY_ID>` transcript, final
zkey sha256 …" and it is added to the transcript.

---

## 5. Pin into the repo (one PR, one commit for the artifact swap)

Every step below is on a branch; CI (`.github/workflows/ci.yml` → `npm test` →
`test/zk-artifacts.selftest.mjs`) must go green.

```sh
# 5.0 keep the OUTGOING rln vkey for the dual-VK rollout window (§6): gateways in the window
#     verify old-client proofs under it. Its artifact id is the current lock's
#     circuits.rln.artifactId (`rln-<sha256(vkey)[0:16]>`, e.g. rln-0b25f824a04da3a8 today).
OLD_ID=$(node -e 'console.log(require("./testdata/zk-artifacts.lock.json").circuits.rln.artifactId)')
mkdir -p circuits/rln/previous/$OLD_ID
cp circuits/rln/verification_key.json circuits/rln/previous/$OLD_ID/verification_key.json
#     (only the vkey — the old proving key must NOT stay in the tree; clients that still hold it
#      are the un-upgraded ones the window exists for)

# 5.1 copy the set (wasm only if §2.1 produced a different hash — otherwise leave as is)
cp ceremony/rln/rln_final.zkey                circuits/rln/rln_final.zkey
cp ceremony/rln/verification_key.json         circuits/rln/verification_key.json
cp ceremony/rln/Verifier.sol                  circuits/rln/Verifier.sol
cp ceremony/withdraw/withdraw_final.zkey      circuits/rln/withdraw_final.zkey
cp ceremony/withdraw/withdraw_verification_key.json circuits/rln/withdraw_verification_key.json

# 5.2 Solidity verifiers — regenerate from the exports, keep the repo's header comments:
#   contracts/RlnGroth16Verifier.sol  = circuits/rln/Verifier.sol + the existing 8-line `///` header
#                                       (the selftest asserts equality modulo `///` lines)
#   contracts/WithdrawGroth16Verifier.sol = ceremony WithdrawVerifier.sol with the contract renamed
#                                       `Groth16Verifier` -> `WithdrawGroth16Verifier` + existing header
#   contracts/WithdrawVerifier.sol (the wrapper) is unchanged.
forge build && forge test --match-contract WithdrawVerifier    # will FAIL until 5.3 regenerates the fixture

# 5.3 regenerate the exit-auth fixture against the new withdraw zkey/vk
node testdata/gen-withdraw-proof.mjs                       # rewrites testdata/withdraw-proof.json
forge test

# 5.4 prove the JS + Rust paths still round-trip on the new set
node circuits/rln/smoke.mjs                                # GATE PASSED
node lib/rln.selftest.mjs
node test/rln-slash.property.selftest.mjs
( cd rust && cargo test -p shade-tree-rln && bash shade-tree-rln/interop/run.sh )   # Rust prover vs JS verifier

# 5.5 update the docs table + the lock (provenance flips to "ceremony")
#   circuits/rln/ARTIFACTS.md: replace the sha256 table + toolchain rows + the "Trust / honesty
#   note" with a pointer to the transcript. The selftest asserts the ARTIFACTS.md table == lock.
node scripts/zk-artifacts-lock.mjs --provenance=ceremony
#   The regenerated lock now carries the NEW circuits.rln.artifactId (= the new vkey's sha256
#   prefix) and records the outgoing id as circuits.rln.previousArtifactId (T-HARD-8): that is
#   the DEFAULT legacy id a gateway maps field-less (un-upgraded-client) envelopes to, so after
#   the window closes those clients get a precise `artifact-retired:<old>` with zero env.
#   Note the two ids for §6:  NEW=$(node -e 'console.log(require("./testdata/zk-artifacts.lock.json").circuits.rln.artifactId)')
#   then hand-edit testdata/zk-artifacts.lock.json -> "ceremony": { "id", "date", "coordinator",
#   "contributors": [...], "transcriptSha256": [one per contributor, = sha256 of contribution-i.txt],
#   "finalContributionHash": "<beacon contribution hash from zkey verify>", "beacon": "<hex>",
#   "beaconSource": "...", "ptauBlake2b": "...", "r1csSha256": { "rln": "...", "withdraw": "..." },
#   "publishedAt": "<url/tag>" }
#   and flip EXPECTED_PROVENANCE in test/zk-artifacts.selftest.mjs from PROVENANCE_DEV to "ceremony".
node test/zk-artifacts.selftest.mjs
npm test

# 5.6 sweep the "testnet-only / untrusted" notices (grep and update each):
grep -rln "T-HARD-1\|untrusted\|TESTNET-ONLY\|testnet-only" --exclude-dir=node_modules --exclude-dir=out --exclude-dir=rust/target . \
  | grep -v "docs/CEREMONY.md"
#   at least: SECURITY.md, README.md, docs/AUDIT.md, docs/THREAT-MODEL.md, docs/CONTRACTS-AUDIT.md,
#   contracts/WithdrawVerifier.sol header, contracts/script/DeployRegistry.s.sol comments,
#   rust/INSTALL.md, rust/shade-tree-rln/README.md, rust/shade-tree-rln/src/prover.rs comment,
#   .github/workflows/release.yml header, testdata/gen-withdraw-proof.mjs, network/sepolia/contracts.json.
#   circuits/rln/ARTIFACTS.md also lists the artifact ids (T-HARD-8): update `rln-…` / `withdraw-…`
#   there to the new lock's circuits.<c>.artifactId (the selftest checks the hash table, the ids
#   are the hash prefixes, so a stale id is obvious).
```

### 5.7 Rust binary — embedded artifacts

`rust/shade-tree-rln/src/prover.rs` `mod embedded` `include_bytes!`s exactly
`circuits/rln/{rln.wasm, rln_final.zkey, verification_key.json}` (paths anchored at
`CARGO_MANIFEST_DIR/../../`), behind the `embedded-artifacts` feature that `shade-tree-client`'s
`live` feature enables (`rust/shade-tree-client/Cargo.toml`). There is no `build.rs` and no copy of the
files under `rust/` — the binary embeds the SAME files the lock hashes, so no separate hash is
needed and the selftest checks those three include paths textually without a cargo build. The
`live` release binaries (`.github/workflows/release.yml`, `cargo build --release -p shade-tree-client
--features live`) therefore pick up the new artifacts on the next tag with no Rust change.

Wired (T-HARD-8): the `live` binary ALSO embeds `testdata/zk-artifacts.lock.json`
(`rust/shade-tree-rln/src/artifacts.rs`, `include_str!`) and at `shade-tree egress` startup recomputes the
sha256 + size of its embedded wasm/zkey/vkey against that lock and derives the set's artifact id
(`rln-<sha256(vkey)[0:16]>` == `circuits.rln.artifactId`); any drift is a hard, named error
(`egress: REFUSING to prove — embedded RLN artifacts do NOT match …`). Rust tests:
`cargo test -p shade-tree-rln` (lock check over the tree) and `cargo test -p shade-tree-rln --features
embedded-artifacts` (over the actually-embedded bytes). `release.yml` runs
`test/zk-artifacts.selftest.mjs` in a `lock-check` job that BOTH build jobs depend on, so a tag
cannot package a binary whose artifacts drift from the lock. Still: tag only a commit that CI has
gone green on. Each release asset ships with a `.sha256`; the transcript should list the release
tag + asset hashes that first embed the ceremony output.

---

## 6. Rollout / rollback — the dual-VK window (T-HARD-8)

The proving key (client) and the verification key (gateway) must come from the same zkey.
Since T-HARD-8 the wire carries WHICH set a proof was made with, and a gateway can hold
several vkeys at once, so the swap is a **window**, not a flag day (`docs/VERSIONING.md`
"Artifact-version negotiation", `lib/zk-artifacts.mjs`):

- **Artifact id** = `rln-<sha256(verification_key.json)[0:16]>` — the vkey's hash prefix in the
  lock (`circuits.rln.artifactId`). Content-derived on every side (gateway from the files it
  loads, JS client from its prover set, Rust client from its embedded bytes at startup), so
  nobody can mislabel a key: a wrong `<id>=<path>` refuses to start.
- **Gateway** `SHADE_TREE_ZK_ARTIFACTS=<id>=<vkey path>[,<id>=<vkey path>]` = the accepted set
  `{id → vkey}`; the envelope's `artifact` field selects the vkey; absent field ⇒
  `SHADE_TREE_ZK_ARTIFACT_LEGACY` (default: the lock's `previousArtifactId`, else the built-in id).
  Accepted ids are advertised as SIGNED caps (`caps.artifacts`) by the heartbeat.
- **Client** sends the newest of its sets the gateway advertises (else its newest); a mismatch is
  a precise reject carrying the accepted list, never a bare `invalid-proof`.

Let `OLD` = the outgoing id (today `rln-0b25f824a04da3a8`, kept under
`circuits/rln/previous/$OLD/verification_key.json` by §5.0) and `NEW` = the ceremony id (the
regenerated lock's `circuits.rln.artifactId`). Both are printed by
`node -e 'const l=require("./testdata/zk-artifacts.lock.json").circuits.rln;console.log(l.artifactId,l.previousArtifactId)'`.

```sh
# 1. GATEWAYS FIRST — open the window. Ship the §5 commit (new built-in set) with BOTH vkeys accepted
#    and the legacy (field-less) envelope mapped to OLD:
Environment=SHADE_TREE_ZK_ARTIFACTS=$NEW=circuits/rln/verification_key.json,$OLD=circuits/rln/previous/$OLD/verification_key.json
Environment=SHADE_TREE_ZK_ARTIFACT_LEGACY=$OLD          # (== the lock's previousArtifactId; explicit is clearer)
#    gateway log at start:  zk artifacts accepted=[NEW,OLD] legacy=OLD legacyStatus=accepted (window open)
#    heartbeat log:         capabilities advertised (signed): {"proto":{...},"artifacts":["…","…"]}
#    Old clients (no field, old zkey) verify under OLD; upgraded clients send artifact=NEW and verify
#    under NEW. Verified with real proofs from two sets in test/zk-artifact-window.selftest.mjs.

# 2. CLIENTS NEXT. Ship the same commit to clients (JS: the built-in prover set is now NEW; Rust: tag a
#    release so release.yml builds `live` binaries embedding NEW — the binary self-checks the bytes
#    against the embedded lock and stamps artifact=NEW). A client that meets a gateway still on OLD-only
#    (its ad lists only OLD) fails closed BEFORE proving: `artifact negotiation failed:
#    no-mutual-artifact:client=NEW,gateway=OLD` — i.e. do step 1 on every gateway before step 2. A JS
#    client that must talk to both fleets during the transition can hold both sets:
#    SHADE_TREE_ZK_PROVER_ARTIFACTS=$NEW=circuits/rln,$OLD=/path/to/old-set-dir  (newest first).

# 3. CLOSE the window — drop OLD from the accepted set, keep it named as legacy:
Environment=SHADE_TREE_ZK_ARTIFACTS=$NEW=circuits/rln/verification_key.json
Environment=SHADE_TREE_ZK_ARTIFACT_LEGACY=$OLD          # (or unset: the lock's previousArtifactId is OLD)
#    gateway log:  … legacy=OLD legacyStatus=RETIRED
#    Any remaining old client is now rejected `gate:artifact-retired:<OLD>` with `artifacts:[NEW]` in the
#    reply (metrics: reason="artifact-retired") — precise and observable, never mis-verified. Once no
#    such drops appear, `rm -r circuits/rln/previous/$OLD` in a follow-up commit.

# 0. (unset — today's behavior) a gateway with NEITHER var accepts only its built-in set under its own
#    id and advertises no artifact caps; byte-equivalent to the single-VK gateway.
```

Rollback: revert the artifact-swap commit (§5 is one commit for exactly this reason); a gateway
in the window keeps serving OLD-set clients throughout, and a rolled-back gateway (built-in =
OLD again) that still has `SHADE_TREE_ZK_ARTIFACTS` naming NEW keeps accepting NEW too. The lock
selftest goes red on any partial revert (mixed sets), which is intended. Adversarial cases the
window does not open (proven in the selftests): a proof made with one set CLAIMING the other id
is `invalid-proof` (verified under the claimed key); an id the gateway holds no key for is
`artifact-unknown:<id>` before any SNARK; stripping the field downgrades to the legacy id and is
judged under that key.

On-chain: `StakedReputationSet.withdrawVerifier` is `immutable`, so the ceremony's
`WithdrawGroth16Verifier` requires a NEW `StakedReputationSet` deployment
(`contracts/script/DeployRegistry.s.sol` with `SHADE_TREE_DEPLOY_REAL_VERIFIER=1`, or pre-deploy the
verifier and pass `SHADE_TREE_WITHDRAW_VERIFIER=<addr>`), and members re-enroll — the same
fresh-deploy path `docs/RLN-MIGRATION.md` "Decisions" §5 already chose. Membership leaves are
unchanged (`rateCommitment = Poseidon(2)([Poseidon(1)([secret]), 8])`, the circuit did not
change), so identities carry over. Do the ceremony BEFORE the first production deploy so no
funds ever sit behind the untrusted verifier; the Sepolia contracts in
`network/sepolia/contracts.json` stay testnet.

---

## 7. Hash lock + CI (already wired — the autonomous half)

- `testdata/zk-artifacts.lock.json` — sha256, byte size, role, circuit, `provenance` for the
  10 artifacts in §0, plus the ptau hash and a `ceremony` block (`status: "not-run"` today).
- `scripts/zk-artifacts-lock.mjs` — `node scripts/zk-artifacts-lock.mjs` rewrites the lock from
  disk (keeps each entry's existing provenance; new entries default to `dev-testnet-untrusted`);
  `--provenance=ceremony` declares all entries as ceremony output; `--check` verifies only.
- `test/zk-artifacts.selftest.mjs` — auto-discovered by `scripts/test-all.mjs` (every
  `*.selftest.mjs`), so `npm test` and therefore `.github/workflows/ci.yml` recompute every hash
  on every push/PR. Fails on: any sha256/size drift, a `circuits/rln/*.{wasm,zkey,sol}` /
  `verification_key.json` or `contracts/*Groth16Verifier.sol` with no lock entry, an unknown
  provenance value, provenance ≠ `EXPECTED_PROVENANCE`, Solidity VK constants ≠ the JSON vkeys,
  `contracts/RlnGroth16Verifier.sol` ≠ `circuits/rln/Verifier.sol` (mod `///`), Rust
  `include_bytes!` paths not pointing at the locked files, `circuits/rln/ARTIFACTS.md` hash
  table ≠ lock.
- (T-HARD-8) the lock also carries `circuits.<c>.artifactId` (= the vkey hash prefix; the checker
  rejects a hand-edited one) and `circuits.rln.previousArtifactId` (auto-recorded when a
  regeneration sees the rln vkey change — the default legacy id for the rollout window, §6). The
  Rust `live` binary embeds the lock and self-checks against it (`rust/shade-tree-rln/src/artifacts.rs`);
  `release.yml` runs the selftest before either build job.
- After a ceremony: §5.5 regenerates the lock with `--provenance=ceremony`, the operator fills
  the `ceremony` block by hand, flips `EXPECTED_PROVENANCE`, and the selftest then also requires
  ≥ 2 contributors, one transcript hash per contributor, a final contribution hash and a beacon
  in the lock. `trust` becomes `"CEREMONY"` (the script derives it; the checker rejects
  `CEREMONY` while any entry is still `dev-testnet-untrusted`).

The lock records provenance as a DECLARATION. Nothing here can prove a ceremony happened;
the transcript + independent verification (§4) is the evidence, the lock is the pin.

---

## 8. Human checklist

Nothing below may be done by an agent.

- [ ] Choose `CEREMONY_ID`, contributors (≥ 3, ≥ 1 external), coordinator, independent verifier.
- [ ] Announce the beacon source + index ≥ 24 h before the first contribution.
- [ ] Coordinator: build circom v2.2.2, compile circom-rln `17f0fed`; confirm 12,390 constraints
      and that both `.wasm` hashes match the lock; publish `.r1cs` + `_0000.zkey` hashes.
- [ ] Verify the ptau: sha256 `489be9e5…895d` and `powersoftau verify` → `Powers of Tau Ok!`.
- [ ] Each contributor: `zkey verify` the incoming chain, contribute with interactive entropy,
      publish + sign `contribution-i.txt`, destroy entropy, wipe temp files.
- [ ] Coordinator: `zkey verify` after every contribution; drop and log any failure.
- [ ] Apply the beacon; `zkey verify` both finals; export vkeys + Solidity verifiers.
- [ ] Publish the transcript (§4); obtain ≥ 1 independent verification statement.
- [ ] Pin (§5): keep the outgoing rln vkey under `circuits/rln/previous/<OLD id>/`, copy the set,
      regenerate both Solidity verifiers with headers, regenerate
      `testdata/withdraw-proof.json`, update `circuits/rln/ARTIFACTS.md`, run
      `node scripts/zk-artifacts-lock.mjs --provenance=ceremony`, fill the `ceremony` block, flip
      `EXPECTED_PROVENANCE`, sweep the "untrusted" notices, `npm test` green, `cargo test -p shade-tree-rln`
      + `rust/shade-tree-rln/interop/run.sh` green.
- [ ] Merge; tag a release so `release.yml` builds `live` binaries embedding the new set; add the
      tag + asset `.sha256`s to the transcript.
- [ ] Rollout (§6): open the dual-VK window on every gateway (`SHADE_TREE_ZK_ARTIFACTS=$NEW=…,$OLD=…`
      + `SHADE_TREE_ZK_ARTIFACT_LEGACY=$OLD`), then ship clients / tag the Rust release, then close it
      (`SHADE_TREE_ZK_ARTIFACTS=$NEW=…`) once `artifact-retired` drops are gone.
- [ ] Fresh production `StakedReputationSet` deployment with the ceremony
      `WithdrawGroth16Verifier`; record it in `network/<chain>/contracts.json`.
- [ ] Update `SECURITY.md` / `docs/AUDIT.md` / `docs/THREAT-MODEL.md` residual-risk lists and
      close T-HARD-1 in `docs/SHIP-PLAN.md`.
