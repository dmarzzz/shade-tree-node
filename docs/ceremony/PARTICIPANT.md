# Participate in the Shade Tree research ceremony

You will contribute fresh randomness to **two existing Groth16 circuits**, RLN
and withdraw. The helper runs on your own machine and creates a public output
bundle and receipt. The coordinator never needs your secret randomness.

**This is preparation for a community research preview. No event date or roster
is confirmed here, and no ceremony has run.** Even a successful ceremony would
not certify Shade Tree's payment, contract, or anonymity security. Read the
[runbook](../CEREMONY.md) and finalized [event agreement](EVENT.md) before
participating.

## Before your slot

1. Obtain the agreed tooling commit and installation instructions from the event
   agreement. Review the helper or ask an independent technical reviewer to do
   so. Use pinned dependencies; do not run a replacement command sent in chat.
2. Use a machine you control with enough disk for complete incoming/outgoing
   bundles. Stop screen sharing; avoid process recorders, debuggers, heap dumps,
   or VM snapshots while contributing. Rehearse separately beforehand; rehearsal
   work never counts toward the actual event.
3. Download the public inputs and **currently accepted** incoming pair. An old
   successful bundle can still be the wrong predecessor.
4. Obtain the frozen manifest hash and current predecessor state hash through a
   separately controlled channel. Compare a prior contributor's signed receipt
   using a previously authenticated key, or contact them through a known separate
   account. A checksum file beside a download is not independent authentication.
5. Check ceremony ID, input identity, circuit/source parameters, and predecessor
   against the event record. Use exact published bytes; do not reformat a JSON
   receipt before hashing or signing it.

The [build guide](BUILD.md) explains independent source reproduction. The helper
establishes consistency with the manifest; it cannot decide whether the
coordinator chose the intended circuit or who owns a signing key.

## Quickstart

Use Node.js 22 or newer. From the reviewed checkout, install isolated helper
dependencies; full application dependencies are not required for contribution:

```sh
npm ci --prefix scripts/ceremony --ignore-scripts
```

Replace the quoted path/hash placeholders with the event's actual values.
`manifest.json` stays fixed; `state.json` changes after each handoff and contains
the ordered paired receipts. Obtain both expected hashes independently of the
incoming download. The new output directory must not exist, its parent must
already exist, and it must be outside the checkout or under `out/ceremony/`.

```sh
node scripts/ceremony/cli.mjs verify \
  --bundle "/absolute/path/to/incoming-bundle" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_PREDECESSOR_STATE_SHA256" \
  --phase1

node scripts/ceremony/cli.mjs contribute \
  --bundle "/absolute/path/to/incoming-bundle" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_PREDECESSOR_STATE_SHA256" \
  --name "YOUR-PUBLIC-ALIAS" \
  --out "/absolute/path/to/my-new-output-bundle"
```

The contribution prints the actual manifest and **new output state** hashes.
Use that new state hash for the outgoing check:

```sh
node scripts/ceremony/cli.mjs verify \
  --bundle "/absolute/path/to/my-new-output-bundle" \
  --expect-manifest "FULL_PUBLISHED_MANIFEST_SHA256" \
  --expect-state "FULL_NEW_OUTPUT_STATE_SHA256"
```

You can also inspect exact public file hashes directly:

```sh
shasum -a 256 "/absolute/path/to/my-new-output-bundle/manifest.json" \
  "/absolute/path/to/my-new-output-bundle/state.json"
```

The paired receipt is the new entry in `state.json`'s `contributions` array; its
predecessor state hash and both circuit output hashes must match your handoff.
Publish/authenticate the hash of the **whole original `state.json` file**, not a
reformatted or extracted receipt. Send the full bundle, including public inputs
and intermediate zkeys, to the next verifier/coordinator.

The verifier rejects unexpected files inside a bundle. Store your extra
statement, signature, and captured public logs beside the bundle, not inside it.

Your name is a **public label**. Use the agreed ASCII name or pseudonym, at most
48 characters. Never put a secret, control character, or private contact detail
in it. Output directories must be new and separate from incoming files and the
repository's live artifact directory.

The helper verifies the incoming pair, generates fresh cryptographic randomness
privately in memory for each circuit, contributes to both, verifies the output,
and writes a paired public receipt. There is no entropy prompt or seed to save.
If anything asks you to paste randomness into a command, file, environment
variable, form, or chat, stop and check the agreed tooling. Do not replace the
helper with `snarkjs ... -e` examples.

After success, verify the outgoing bundle, keep its public receipt, and transfer
the complete public output pair using the event's announced transport. Publish
its receipt/state hash through your separately authenticated channel. Wait for
the coordinator's public acceptance of **both** circuits before considering the
slot complete. Retain public output files until both archives contain them.

If one circuit fails, the pair is unaccepted. Do not send one successful half as
a completed contribution, edit the receipt, or overwrite incoming files. Record
the public error and contact the coordinator. Retry from the last accepted pair
with a new attempt/output directory and fresh randomness.

## What is public, and what stays private

| Safe to publish | Do not create, share, or livestream |
| --- | --- |
| Sources, build manifest, R1CS, WASM, ptau | Private randomness or derived secret contribution state |
| Incoming/outgoing zkeys and their hashes | Seed files, entropy pasted in a shell, clipboard captures |
| Contribution hashes and paired receipts | Heap/core dumps, debugger state, contribution-process memory |
| Verification logs and an honest statement | A recording of your private contribution environment |

The `.zkey` is public proving material, not your private entropy. Intermediate
zkeys allow independent reconstruction of the accepted history. Publishing them
does not prove a participant kept a secret; that remains an assumption about at
least one participant per circuit, in addition to phase 1 and protocol/software
assumptions.

The helper avoids deliberately placing secrets in argv, environment variables,
logs, or files. It does **not** prove secure erasure. JavaScript strings, library
internals, swap, crash reports, snapshots, or a compromised machine may retain
copies. Close the contribution process after completion and use your device's
normal secure-handling practices. Deleting shell history or saying a laptop was
wiped is not cryptographic evidence. Never claim a guarantee you cannot establish.

If secret material is exposed, tell the coordinator without repeating or
publishing it. Log the incident and do not count that contribution as the
required honest-secret contribution.

## Public contribution statement template

Fill this in only after successful acceptance. Sign the exact public receipt or
publish its full hash through your authenticated channel. This statement does
not replace the machine-readable receipt or either output file.

```text
Shade Tree research ceremony: <CEREMONY_ID>
Participant / public pseudonym: <LABEL>
Accepted contribution / attempt: <SEQUENCE_OR_ATTEMPT>
Tooling commit: <FULL_COMMIT>
Frozen ceremony manifest SHA-256: <FULL_HASH>
Incoming state SHA-256: <FULL_HASH>
Outgoing state.json SHA-256 (contains paired receipt): <FULL_HASH>
Public output and receipt location: <URL>
Verification result for RLN: <RESULT_AND_LOG_REFERENCE>
Verification result for withdraw: <RESULT_AND_LOG_REFERENCE>

I ran the published helper on a machine I control and verified the incoming and
outgoing paired artifacts against the identified inputs. I did not knowingly
record or disclose private contribution randomness. The contribution process
has exited. This is a best-effort statement; I cannot prove no copies remain in
memory, swap, snapshots, or other systems.

Exceptions or incidents: <NONE_KNOWN_OR_ACCURATE_DESCRIPTION_WITHOUT_SECRETS>
Statement date/time and timezone: <TIME>
Authenticated signing key / publication identity: <PUBLIC_REFERENCE>
```

## After the event

Check that the final transcript includes your receipt and both zkeys in order.
Compare finalization against the quicknet round and cutoff published before
contributions began. Anyone can independently verify public results using the
[runbook](../CEREMONY.md#4-freeze-the-cutoff-apply-the-beacon-and-verify).
Report missing or changed artifacts through the announced channel. A stream
recording alone is not a verifiable transcript.
