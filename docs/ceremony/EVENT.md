# ShadeNet community ceremony event worksheet

> **Fallback only; not run.** PSE's finalized RLN setup was adopted for both circuits on
> 2026-09-30 (`PSE-ADOPTION.md`, `PSE-VERIFICATION.md`), so no ShadeNet community event took
> place. This worksheet is kept ready in case the owner prefers a ShadeNet-specific setup or a
> later circuit change needs one. The fields an agent can fill without people are filled; roster,
> date and channels stay **PENDING** for the owner.

**Draft event plan — details below are pending.** This document schedules no
event, sends no invitations, publishes no artifacts, and starts no ceremony.
Complete and publish an immutable event agreement before using it. Keep the
[runbook](../CEREMONY.md), [build guide](BUILD.md), and
[participant quickstart](PARTICIPANT.md) with the agreement.

## Event fields to complete

| Field | Value |
| --- | --- |
| Public ceremony ID | `shadenet-rln-2026` (proposed) |
| Livestream date, start, timezone, expected end | **PENDING** |
| Independent-verification follow-up time | **PENDING** |
| Stream URL / recording archive | **PENDING** |
| Coordinator / public contact | **PENDING** |
| Host / moderator | **PENDING** |
| At least three contributors: ordered public labels, distinct machines, consent | **PENDING** |
| Independent input builder | **PENDING** |
| Independent final verifier | **PENDING** |
| Frozen tooling commit / dependency-install instructions | `86aff71b4dfd` (main at the circuit freeze); `npm ci --prefix scripts/ceremony --ignore-scripts`; Rust 1.98.0 per `BUILD.md` |
| Frozen build-input manifest URL / full SHA-256 | URL **PENDING**; a local rebuild on 2026-09-28 produced `build-inputs.json` with SHA-256 `a1a6caf8e0c968cd3733c5561be51410df95503a714361083ae9ee648656b739` (both R1CS/WASM and the ptau matched every pin) |
| Published plan URL / full SHA-256 | **PENDING** |
| Initial bundle URL / full ceremony-manifest and state hashes | **PENDING** |
| Independent hash-authentication channel | **PENDING** |
| Public handoff transport / upload instructions | **PENDING** |
| Primary immutable public transcript archive | **PENDING** |
| Independent transcript/file mirror / archive host | **PENDING** |
| Incident and cancellation announcement channel | **PENDING** |
| Contribution deadline in UTC | **PENDING** |
| Method for publishing the closed state before the future round | **PENDING** |
| Beacon network | drand quicknet, identity pinned by the reviewed helper |
| Future quicknet round | **PENDING**, at least 60 minutes after contribution deadline |
| Expected beacon time / availability deadline | **PENDING** |
| Observer's independent quicknet signature/round verification | **PENDING** |
| Beacon byte selection / encoding | SHA-256 of NUL-separated domain, manifest hash, closed-state hash, circuit name, and verified quicknet randomness; exact rule in `protocol.mjs` |
| Beacon iteration exponent | `10` (2^10 hash iterations) |
| Failure rule | Abort/reschedule with a newly announced future round; never choose an already-known replacement value |
| Artifact adoption / deployment | Separate later decision; **none during this event** |

The machine-readable plan fixes the ceremony ID, mode, deadline, round, and
minimum contributor count. The human agreement adds identities, publication
channels, chronology evidence, and failure handling that software cannot prove.
The pinned quicknet chain hash is
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`;
the reviewed helper pins its public key and BLS scheme as well.
Do not use the placeholder example as a real plan. The intended mode is
`research-preview`; rehearsal mode remains permanently labeled and is never an
alternative route to a completed real event.

## Announcement draft

Replace brackets and verify the completed agreement before posting. This is
prepared copy; no announcement has been sent.

> We're preparing a public trusted-setup ceremony for Shade Tree's existing RLN
> and withdraw Groth16 circuits on [DATE, TIME, TIMEZONE]. Community contributors
> will add private randomness on their own machines, and we'll livestream the
> public handoffs and verification. The complete public transcript, intermediate
> files, and verification instructions will be available at [ARCHIVE].
>
> This is a research preview. A successful ceremony improves the provenance of
> these specific proving artifacts; it does not make Shade Tree audited or
> production grade. We will not deploy contracts or rotate running services
> during the event.
>
> Participant instructions: [PARTICIPANT_GUIDE]. Frozen inputs, contribution
> cutoff, and the precommitted future quicknet round: [EVENT_AGREEMENT].
> Watch or verify independently: [STREAM / VERIFICATION_GUIDE].

## Preparation before event day

1. Choose at least three friends contributing on independently controlled
   machines, preferably including someone outside the core team, and an
   independent verifier. Obtain consent for public labels and optional
   appearances; legal identities are not required. Confirm a separate receipt
   authentication channel.
2. Freeze source, toolchain, build manifest, and intended relations. An
   independent builder reproduces both R1CS and WASM outputs. Resolve differences
   before contributions, then publish the agreement, plan, and initial bundle.
3. Rehearse with separate identities/directories and explicit rehearsal mode.
   Rehearsal receipts/randomness never enter the real event. Measure timings on
   actual contributor machines; do not promise duration from one laptop's result.
4. Test full paired downloads/uploads. Each accepted step needs both circuits,
   not only a screenshot or receipt. Check archive space and retention for every
   intermediate pair and verification log.
5. Publish the fixed future quicknet round and contribution deadline with time
   for review. The round must be at least 60 minutes after the deadline, leaving
   enough event time for serial contributions and public closure. Keep an abort
   margin instead of extending the deadline after seeing randomness.
6. Prepare a host view containing public files/results only. Contributors work
   privately. Disable desktop notifications and prepare a holding slide. Do not
   capture process memory, entropy, or private terminals for educational footage.

## Livestream run-of-show

Times are suggested segments, not a confirmed schedule. Contribution slot lengths
come from the rehearsal; all acceptance must fit before the deadline.

| Segment | Host action | Public evidence / exit condition |
| --- | --- | --- |
| Opening, about 5 minutes | Explain RLN/withdraw, phase 1 versus phase 2, and research scope | Read ceremony ID; display frozen agreement/manifest hashes |
| Input review, about 10 minutes | Independent builder explains source reproduction and ptau checks | Both circuit hashes, build manifest, and initial pair agree |
| Contribution slots, serial | Introduce public label; keep private work off stream; show the resulting public handoff | Both circuits verify; receipt/state hash independently authenticated |
| Per-slot acceptance | Coordinator announces accepted sequence and paired hashes | Publish/mirror the complete pair, receipt, and public verification log |
| Close before deadline | Close the chain and publish its closed state hash | Independently witnessed public hash predates the fixed future round |
| Beacon wait / intermission | Show precommitted round and failure rule | No additional contributions; wait for signed quicknet round |
| Finalization | Observer checks beacon evidence; coordinator applies fixed rule | Staged final pair verifies; exact beacon parameters recorded |
| Independent replay | Verifier repeats finalization and re-exports keys/verifiers | Hashes agree, or status stays pending/unverified |
| Close | Share archives, unresolved issues, independent-verification status | Research preview; no installation, deployment, or release tag |

### Opening script

> Today we're adding community contributions to fresh phase-2 setups for Shade
> Tree's existing RLN and withdraw circuits. Secret randomness stays on each
> contributor's machine. What you will see is public: input identity, receipts,
> file hashes, and verification results.
>
> A valid transcript lets anyone check the mathematical contribution chain. It
> cannot prove a machine was uncompromised or that all secret copies were erased.
> The reused phase-1 assumption remains. This is a research preview; we're not
> claiming production safety or deploying these artifacts during the stream.

### Per-contributor checklist

- Confirm the participant independently authenticated the current paired input
  and uses the frozen helper. Never ask them to show a seed or type random words
  for the camera.
- Keep the contribution process off stream. Use an explanation or holding slide
  without pressuring the participant to hurry.
- Show only public receipts/hashes after completion. Obtain the participant's
  independent receipt publication/attestation.
- Verify both circuits, predecessor identity, and ordered histories before
  acceptance. Record the accepted sequence in the public transcript.
- Mirror the full output pair and preserve its predecessor before the next slot.

### Cutoff script

> The contribution chain is closed. The closed state is [FULL_STATE_HASH], with
> manifest [FULL_MANIFEST_HASH], published at [PUBLIC_RECORD]. We will use exactly
> the future quicknet round and byte rule announced in [AGREEMENT]. If that rule
> cannot be followed, we'll stop and announce a new event; we will not select
> another already-known randomness value.

The host can display the public beacon value. It is not a contributor's secret
and does not replace an honest contribution. An observer independently verifies
the pinned quicknet identity, round, signature, and rule, rather than merely
reading back the coordinator's copied value.

## Interruptions and aborts

| Situation | Required response |
| --- | --- |
| Hash, predecessor, circuit, or receipt mismatch | Pause; preserve public evidence; reject the whole paired handoff; diagnose from the last accepted pair |
| One circuit fails | Keep the attempt unaccepted; retry as a new paired attempt with fresh randomness |
| Participant disconnects | Pause or skip under the announced timeout/roster policy; never invent a contribution or use rehearsal output |
| Secret exposure / suspected compromise | Avoid rebroadcasting it; log the incident; do not count it as an honest-secret contribution |
| Input/toolchain/plan needs changing | Abort the agreement; rebuild/review under a new ceremony ID |
| Deadline missed / round known before public closure | Abort/reschedule before finalization; archive the prior event as aborted |
| Beacon unavailable or invalid by deadline | Abort/reschedule with a new future round; no favorable replacement selection |
| Independent verification disagrees | Publish discrepancy; leave status unverified; no installation, deployment, or completion claim |
| Stream fails | Preserve public cryptographic files; pause acceptance until the agreed public announcement channel is available |

A technical failure is a legitimate outcome. Use precise status labels:
**prepared**, **contributing**, **closed and published**, **finalization pending**,
**independently verified**, or **aborted**. A successful process exit is not
independent verification. Local timestamps do not prove public precommitment or
cutoff chronology.

## Public transcript and closing copy

Archive frozen inputs, plan, both initial zkeys, every accepted intermediate
pair, paired receipts/attestations, verification logs, public cutoff evidence,
beacon precommitment and signed response, final zkeys/exports, independent replay
statements, and incident records. Preserve the phase-1 reference/mirror. Publish
a full hash index and keep primary and independent archives available. A stream
recording supplements these files; it does not replace them.

Use only closing copy matching the evidence:

> The paired ceremony outputs and public history are archived at [ARCHIVE] and
> [MIRROR]. Independent verification is [COMPLETE WITH STATEMENT LINKS / STILL
> PENDING / BLOCKED BY DESCRIBED DISCREPANCY]. These are research-preview
> artifacts. Adoption into clients, gateways, or new contracts requires a separate
> review; no running deployment changed during this event.

The follow-up inventory is in [CEREMONY.md](../CEREMONY.md), sections 5–7.
An existing registry's withdraw verifier is immutable, and a gateway accepting
development verification keys still accepts their setup risk. Completion must
not be presented as silently resolving either issue.
