# Community trusted setup: research preview

This runbook prepares a community phase-2 ceremony for Shade Tree's existing
Groth16 **RLN and withdraw circuits**. It does not change proving systems or
payment semantics. A successful ceremony would give these circuit artifacts a
public, independently checkable contribution history. **It would not make Shade
Tree production grade, audited, or suitable for real funds or sensitive anonymity.**

**Status: preparation only. No community ceremony has run, no artifacts have been
rotated, and no deployment is authorized by this runbook.** The checked-in
`circuits/rln/` keys remain development artifacts. Their provenance lock remains
`dev-testnet-untrusted`, `UNTRUSTED-TESTNET`, and `ceremony.status: "not-run"`.
The existing development contribution process is not evidence of an honest
secret contribution. See [ARTIFACTS.md](../circuits/rln/ARTIFACTS.md) and
[the lock](../testdata/zk-artifacts.lock.json).

Use these companion documents:

- [Build and independently reproduce the inputs](ceremony/BUILD.md).
- [Participant quickstart and contribution statement](ceremony/PARTICIPANT.md).
- [Event worksheet, announcement copy, and livestream run-of-show](ceremony/EVENT.md).

## 0. What is being prepared

| Circuit | Pinned source | Relation | Public signals |
| --- | --- | --- | --- |
| `rln` | `Rate-Limiting-Nullifier/circom-rln`, commit `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d` | `RLN(20,16)`, 12,390 constraints | `[y, root, nullifier, x, externalNullifier]` |
| `withdraw` | Same source commit | Existing `Withdraw` relation, 416 constraints | `[identityCommitment, address]` |

The compiler baseline is Circom 2.2.2. The build instructions pin the actual
compiler, dependencies, source, R1CS, and WASM outputs. A compiler version string
alone is not a reproducible-build attestation. An independent builder should
reproduce and compare both circuits before anyone contributes.

The phase-1 input is the existing BN254
`powersOfTau28_hez_final_14.ptau`, SHA-256:

```text
489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d
```

Verify the fetched file against this pin and run the Powers of Tau verification
described in [BUILD.md](ceremony/BUILD.md). Compare its published upstream
transcript identity independently; a download and checksum obtained only from
the same coordinator are not an independent check.

This event starts **fresh circuit-specific phase 2** from the pinned R1CS files
and verified phase-1 input. It does not add contributions to the checked-in
development final zkeys. Reusing phase 1 retains that ceremony's trust assumption:
the new event does not repair a compromised phase-1 setup.

## 1. Event agreement before contributions

Complete [EVENT.md](ceremony/EVENT.md), then publish and freeze its finalized
version, the input manifest, plan, and tooling commit before contributions begin.
The date, roster, publication endpoints, and future beacon round are intentionally
pending. Do not announce placeholders as confirmed details.

| Role | Responsibility |
| --- | --- |
| Coordinator | Freeze public inputs; sequence paired contributions; verify every handoff; maintain the public transcript |
| Contributors | Independently check inputs; contribute to both circuits on their own machines; publish paired receipts |
| Independent verifier | Reproduce inputs, check every accepted contribution, reproduce finalization/exports, and publish a separate statement |
| Stream host / moderator | Explain the research scope; show public verification; record interruptions without exposing private contribution work |

The default event requires at least **three friends on independently controlled
machines**, preferably including someone outside the core team. The roster is
not itself a security proof. For each circuit, phase-2 secrecy depends on at
least one accepted contributor supplying secret, unpredictable randomness that
is not subsequently recovered, together with the protocol, implementation, and
phase-1 assumptions.

Each participant contributes to **both** circuit chains as one handoff. The
`state.json` contribution entries are the public paired receipts: each records
the predecessor state hash, both output hashes, and contribution metadata. The
unchanging `manifest.json` identifies the ceremony inputs and plan. Authenticate
the hash of the complete `state.json`, not an extracted or reformatted entry.
A receipt does not prove a real-world identity,
the absence of malware, or secure erasure. Authenticate its hash through a
separately controlled channel, or sign the exact receipt with a key whose identity
has already been checked outside the artifact transfer channel.

## 2. Prepare and freeze the public inputs

Use isolated directories outside the repository for inputs, ceremony bundles,
and final exports. The tooling stages outputs; it must not overwrite live
`circuits/rln/` files, deployed verifiers, release assets, or the provenance lock.
Keep rehearsals in separate directories with a separate ceremony ID and the
explicit rehearsal mode. Rehearsal results remain labeled as rehearsals and never
count toward the announced research-preview event.

Follow [BUILD.md](ceremony/BUILD.md) to produce both R1CS files, both witness
calculators, and the pinned phase-1 file. Record source/dependency pins, compiler
identity, versions, hashes, circuit parameters, constraint counts, and public-signal
order. An unexplained hash mismatch is a stop condition, not permission to update
the expected hash.

The coordinator prepares a fresh initial pair and verifies it. Publish its
manifest and state hashes before the first contribution. Participants obtain the
expected manifest hash and **current predecessor state hash** independently of
the bundle delivery. Verification establishes consistency with pinned inputs;
source review and independent reproduction establish that the inputs describe
the intended circuits.

Use Node.js 22 or newer. Install isolated tooling dependencies from the reviewed
checkout; participants do not need the full application's dependencies:

```sh
npm ci --prefix scripts/ceremony --ignore-scripts
```

Copy [plan.example.json](../scripts/ceremony/plan.example.json) outside the
repository and fill in its ID, UTC deadline, future quicknet round, and minimum
contributor count. Its placeholders deliberately fail validation. The optional
time helper finds a round for the desired beacon time; choose a time at least
60 minutes after the contribution deadline:

```sh
node scripts/ceremony/cli.mjs beacon-round --time "REPLACE_WITH_BEACON_TIME_ISO_UTC"
```

The following paths and hashes are placeholders. Replace them before running.
The build-input JSON comes from [BUILD.md](ceremony/BUILD.md); the output
directory must not already exist, but its parent directory must exist. Use a
location outside the checkout or under `out/ceremony/`.

```sh
node scripts/ceremony/cli.mjs prepare \
  --inputs "/absolute/path/to/build-inputs.json" \
  --plan "/absolute/path/to/plan.json" \
  --out "/absolute/path/to/ceremony/00-prepared"

node scripts/ceremony/cli.mjs verify \
  --bundle "/absolute/path/to/ceremony/00-prepared" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_INITIAL_STATE_SHA256" \
  --phase1
```

Each mutation prints the actual manifest and state SHA-256 values. Publish them
through the agreed authenticated channels. Every `verify`, `contribute`, `close`,
and `finalize` requires **both** expected hashes. The expected state changes at
each accepted mutation; do not accidentally keep using the initial state hash.

The self-contained bundle includes:

```text
manifest.json
state.json                         # Includes ordered paired receipts
inputs/rln.r1cs
inputs/rln.wasm
inputs/withdraw.r1cs
inputs/withdraw.wasm
inputs/powersOfTau28_hez_final_14.ptau
keys/0000/rln.zkey                 # Fresh phase-2 initial pair
keys/0000/withdraw.zkey
keys/0001/...                      # First accepted contributor; later indices follow
```

`prepare` always cryptographically verifies phase 1. Other verification checks
the exact pinned ptau hash; add `verify --phase1` to repeat its cryptographic
transcript verification independently.

Bundles have an exact file inventory. Keep extra logs, signatures, statements,
and saved beacon responses **beside** the bundle in the public archive rather
than adding files inside a bundle that will be handed to the next participant.

### Optional local rehearsal

After building inputs, this opt-in harness exercises the real circuits through
fresh setup, three local paired contributions, closure, beacon finalization, and
verification. It also checks rejected tampering and invalid handoffs. Run it
privately in a new directory outside the repository:

```sh
node scripts/ceremony/rehearse.mjs \
  --inputs "/absolute/path/to/build-inputs.json" \
  --out "/absolute/path/to/new-rehearsal"
```

The harness uses an explicitly historical beacon and permanently labels results
`REHEARSAL-DO-NOT-USE`. Its three local aliases are **not three independent
contributors** and do not count toward a live event. It writes public test logs
and `rehearsal-report.json`, or a failure report; these are tooling evidence, not
a community transcript. Timings are measured by each run rather than promised
here. No runtime artifact or provenance lock is activated.

## 3. Serial paired contributions

The [participant guide](ceremony/PARTICIPANT.md) is the operational quickstart.
Each participant verifies the incoming pair, contributes fresh randomness to
both circuits, verifies the output, and publishes the public receipt. The
coordinator verifies again before acceptance and forwarding. Preserve every
accepted intermediate pair; never overwrite the incoming files.

The helper generates cryptographic randomness privately in memory and passes it
directly to the proving library. **There is no entropy to type, paste, show, or
send to the coordinator.** Do not add an entropy flag, environment variable,
shell pipeline, seed file, debugger, or heap dump. The public contribution hash
is safe to publish; the secret randomness used to produce it is not.

Contributors run outside the livestream. The host can show public input hashes,
receipts, contribution hashes, and verification results. Do not screen-share a
participant's desktop, private terminal, clipboard, crash reporter, or process
inspection session. If secret material is exposed or a machine is suspected
compromised, record the incident without republishing the secret and do not count
that contribution as an honest-secret contribution.

If either circuit fails or a receipt/hash differs, the whole handoff is
unaccepted. Pause, retain public evidence, and return to the last accepted pair.
Do not advance only one circuit. A retry uses a new output directory, attempt
identity, and randomness; failed attempts remain separate from the accepted
sequence. If the frozen input identity or plan must change, abort and restart
under a new ceremony ID.

JavaScript and WebAssembly provide no verifiable secure-erasure guarantee.
Process exit, overwriting an application buffer, or deleting shell history cannot
prove copies are absent from memory, swap, crash dumps, VM snapshots, backups,
or a compromised device. Avoid these capture mechanisms and terminate the
contribution process after use, but make only an honest best-effort handling
statement. Do not require a false claim that erasure was proved.

## 4. Freeze the cutoff, apply the beacon, and verify

The helper uses **drand quicknet** with a fixed network identity and BLS signature
verification. The public plan fixes a future round at least **60 minutes after**
the contribution deadline. The helper's pinned source and finalized event
agreement specify the network identity, exact byte-selection rule, and iteration
exponent. Record an availability deadline and the independent observer's method
for checking the round/signature.

The pinned quicknet chain hash is
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.
The helper verifies its signed response, then derives each circuit's snarkjs
beacon seed as SHA-256 of these UTF-8 strings joined with single NUL bytes:
`shade-tree-phase2-v1`, ceremony manifest SHA-256, closed state SHA-256, circuit
name (`rln` or `withdraw`), and the response's lowercase hexadecimal `randomness`.
The iteration exponent is `10` (2^10 hash iterations). Thus both circuits use the
same fixed public round and policy, with different domain-bound derived seeds.
The exact implementation is [protocol.mjs](../scripts/ceremony/protocol.mjs).

Close the accepted chain **before the contribution deadline**, then immediately
publish the closed state hash and its accepted final pair before the future round
is available. A timestamp in a local JSON file is not independent evidence of
when this happened; retain the public announcement and independent witnesses.
After close, no additional contribution is accepted into that chain.

After the final accepted contributor, authenticate its current state hash and
close into a new directory. `close` enforces the plan's minimum contributor
count and deadline:

```sh
node scripts/ceremony/cli.mjs close \
  --bundle "/absolute/path/to/ceremony/last-accepted" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_LAST_ACCEPTED_STATE_SHA256" \
  --out "/absolute/path/to/ceremony/closed"
```

Publish the **new closed state hash** immediately. Once the fixed round is
available, finalize from that exact closed state:

```sh
node scripts/ceremony/cli.mjs finalize \
  --bundle "/absolute/path/to/ceremony/closed" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_PUBLISHED_CLOSED_STATE_SHA256" \
  --out "/absolute/path/to/ceremony/finalized"

node scripts/ceremony/cli.mjs verify \
  --bundle "/absolute/path/to/ceremony/finalized" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_FINALIZED_STATE_SHA256" \
  --phase1
```

Finalization fetches the pinned quicknet round. An independent replay can use
`--beacon "/absolute/path/to/saved-round.json"` with the saved public response;
both paths verify its BLS signature against the pinned network key. No private
beacon secret or arbitrary replacement value is accepted. Preserve the response
in the public transcript.

If the cutoff is missed, the round becomes known before the chain is publicly
closed, the source/signature cannot be validated, or the announced availability
deadline passes, abort or reschedule with a newly announced future round. Never
choose among already-known values, reroll, or silently substitute another round.

The beacon value is public and can appear on stream. Anyone can reproduce the
deterministic beacon transform from the frozen last pair. A public beacon is
**not secret entropy** and does not replace the honest-contributor or phase-1
assumptions. See the
[snarkjs beacon implementation](https://github.com/iden3/snarkjs/blob/v0.7.5/src/zkey_beacon.js).

Finalization produces staged zkeys, verification keys, and Solidity exports for
both circuits, with the verifier exports in `exports/`. The independent verifier
must:

1. Authenticate the frozen agreement, plan, manifest, and closed state separately
   from the bundle transport.
2. Reproduce the source build and verify the phase-1 file.
3. Verify every accepted intermediate zkey against its R1CS and ptau, including
   ordered contribution history, paired receipts, and exact predecessor chain.
4. Check the signed quicknet round against the precommitted plan and public
   cutoff evidence; reproduce its application to both chains.
5. Verify both final zkeys, independently re-export both verification keys and
   Solidity verifiers, and compare exact output hashes.
6. Publish a statement naming the manifests, final pair, source/tooling pins,
   checks performed, and exceptions. A green summary alone is insufficient.

Archive the complete public transcript: frozen agreement and amendments, plan,
build manifest, R1CS/WASM, initial pair, **every accepted intermediate zkey for
both circuits**, every version of `state.json` (including initial, closed, and
finalized states), attestations/signatures, verification logs, public
incident records, cutoff evidence, signed beacon evidence, final pair, and
exports. Include the pinned ptau or a durable independently verifiable mirror.
Hashes alone are not a substitute for intermediate files. Publish a hash index
to the announced primary archive and independent mirror, preserving old versions.
Never include private randomness or memory captures.

Publication and the real ceremony are future event actions. Preparing this
runbook or running a rehearsal does not publish or execute them.

### Optional staged application smoke checks

The compatibility harness can test a finalized rehearsal or research-preview
bundle using public application fixtures. It needs the root application's
dependencies in addition to the isolated ceremony dependencies. Its output must
be a new separate directory, outside the immutable bundle:

```sh
npm ci --ignore-scripts
node scripts/ceremony/smoke.mjs \
  --bundle "/absolute/path/to/finalized-bundle" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_FINALIZED_STATE_SHA256" \
  --out "/absolute/path/to/new-smoke-results"
```

It checks RLN proofs at limits 8 and 32, rejection of wrong epochs/messages,
withdraw action-context binding, and rejection of the new proofs by the current
development verification keys. It writes `smoke-report.json` and a staged
`withdraw-proof.json` for later contract testing. The public fixture witnesses
are unrelated to private ceremony randomness. These checks do not execute
Solidity, validate a network rollout, or authorize replacing repository fixtures.

## 5. Future artifact integration — a separate reviewed change

Ceremony completion and artifact adoption are different milestones. A later
review must select the verified final transcript and move each circuit's keys,
exports, fixtures, and provenance together. Do not copy staged output into the
application during the livestream.

| Consumer | Future integration inventory |
| --- | --- |
| JavaScript proving / gateway verification | RLN WASM, zkey, JSON verification key; `lib/rln.mjs` and accepted-key configuration |
| Rust client releases | Embedded RLN WASM, zkey, JSON verification key, and lock; rebuild actual `live` binaries |
| RLN Solidity provenance copy | `circuits/rln/Verifier.sol` and `contracts/RlnGroth16Verifier.sol`; membership remains verified off-chain |
| Withdraw proving / fixtures | Withdraw WASM, zkey, JSON verification key; regenerate `testdata/withdraw-proof.json` |
| Withdraw contracts | `contracts/WithdrawGroth16Verifier.sol`, its `WithdrawVerifier.sol` wrapper, and registry deployment/migration plan |
| Provenance / releases | `circuits/rln/ARTIFACTS.md`, lock, transcript references, test expectations, release hashes, operator docs |

WASM is compiler output, not phase-2 output. Reuse it only after independently
reproduced bytes match; investigate any difference before claiming an unchanged
circuit. New verification keys produce new content-derived artifact IDs.

The later integration review must run artifact-lock checks, RLN proof/slashing
tests, withdraw contract tests, and JavaScript/Rust interoperability against the
selected artifacts. Tests establish tested behavior; they do not audit the
ceremony or application. Do not remove research, testnet, or unaudited notices
merely because artifact provenance changes.

## 6. Future rollout and retirement

RLN proving and verification keys must come from the same final zkey. Existing
[artifact negotiation](PROTOCOL-VERSIONING.md) names a set by
`rln-<sha256(verification_key.json)[0:16]>` and lets gateways accept multiple
keys through `SHADE_TREE_ZK_ARTIFACTS`. The legacy mapping is
`SHADE_TREE_ZK_ARTIFACT_LEGACY`; Rust clients embed their artifacts and lock.
See [lib/zk-artifacts.mjs](../lib/zk-artifacts.mjs).

**Accepting the old development verification key preserves its forgery risk.**
A dual-key transition is a compatibility option, not a secure boundary. A later
rollout must explicitly decide whether any overlap is acceptable and when it
ends. Claims about retiring the development setup apply only after every
accepting gateway rejects that key. Deleting a local old proving key cannot
revoke copies elsewhere. A rollback that re-enables the old key also re-enables
its risk. Keep legacy rejections observable and communicate required client
versions.

`StakedReputationSet.withdrawVerifier` is **immutable**. Exporting a new withdraw
verifier or changing the repository cannot replace an existing registry's
verifier. Adoption requires a separately reviewed new registry/verifier
deployment and migration/re-enrollment plan accounting for bonds, exits, roots,
and old contracts. A ceremony does not upgrade or protect an existing registry
using old keys. No deployment is part of this preparation. See
[the contract](../contracts/StakedReputationSet.sol) and
[migration discussion](history/RLN-MIGRATION.md).

## 7. Provenance lock and evidence

The [artifact selftest](../test/zk-artifacts.selftest.mjs) checks hashes, sizes,
verifier consistency, and consumers. The
[lock generator](../scripts/zk-artifacts-lock.mjs) records provenance declarations.
Neither proves participant independence or secret handling.

Keep the current lock and test expectations unchanged until an actual ceremony
has completed and a separate artifact-adoption change is reviewed. A future
`ceremony` declaration must name the real paired transcript and independent
verification evidence. If the existing schema cannot represent both chains and
both final contribution hashes faithfully, revise the schema and checks during
adoption; do not squeeze two histories into one ambiguous scalar. A label such
as `CEREMONY` describes provenance, not production readiness.

## 8. Event completion checklist

- [ ] Agreement, plan, date, roster, input/source/tooling pins, and future quicknet
      round are complete, independently checked, and published before use.
- [ ] Independent input reproduction agrees for both circuits.
- [ ] At least three independently controlled contributor machines participate;
      each accepted participant contributes to both chains.
- [ ] Every paired receipt is independently authenticated; intermediate files,
      ordered histories, and predecessor checks verify.
- [ ] Incident records explain failures/aborts without exposing secrets.
- [ ] The chain closes before the deadline; its closed state hash is published
      before the fixed future round.
- [ ] Both final zkeys and independently regenerated exports verify.
- [ ] Full public transcripts/intermediate files are archived and mirrored.
- [ ] Independent statements identify exactly what was checked.
- [ ] The event closes as a **research preview**, without an artifact swap,
      deployment, production-safety claim, or old-key acceptance by default.

For underlying semantics, consult the pinned
[snarkjs guide](https://github.com/iden3/snarkjs/blob/v0.7.5/README.md) and
[contribution implementation](https://github.com/iden3/snarkjs/blob/v0.7.5/src/zkey_contribute.js).
Use the event's pinned helper rather than copying generic entropy examples into
a streamed shell.
