# Envelope and artifact versioning

Shade Tree negotiates two independent versions:

1. the **envelope version**, which defines the client-to-node wire shape; and
2. the **artifact id**, which identifies the proving and verification key set.

Changing one does not require changing the other.

## Envelope v4

The JavaScript client and node each declare one inclusive range:

| Side | Source of truth | Current range |
| --- | --- | --- |
| Client | `CLIENT_PROTO_MIN`, `CLIENT_PROTO_MAX` in `client/shade-tree-client.mjs` | `4..4` |
| Node | `PROTO_MIN`, `PROTO_MAX` in `gateway/gateway.mjs` | `4..4` |

Signed node capabilities advertise `caps.proto = {min,max}`. The client selects the
highest overlapping version before it proves or dials. With no advertisement it tries
its own maximum; a rejection includes the node's range.

There is no v3 compatibility mode. A frame with no `v` is classified as legacy v3 and
then rejected against the v4-only range. A numeric version outside the range returns
`unsupported-version:<v>`; a non-integer returns `bad-version:<repr>`. Both failures are
checked before any other envelope field is interpreted.

The v4 proof signal is domain-separated as:

```text
shade-tree:v4\n<target>\n<nonce>
```

Accepting a version never bypasses the independent target, nonce, root, artifact, or
Groth16 checks.

## Adding an envelope version

To add v5 without a flag day:

1. Add and test a v5 parser on the node, then raise `PROTO_MAX` to `5`.
2. Advertise the new node range in signed capabilities.
3. Add v5 emission on the client, then raise `CLIENT_PROTO_MAX` to `5`.
4. Keep both minimums at `4` until the fleet and supported clients have migrated.
5. Raise each minimum only after its old parser/emitter is deliberately removed.

Every selected version must have a round-trip conformance case. Unknown values remain
fail-closed.

## Artifact ids

An artifact id is content-derived:

```text
<circuit>-<first 16 hex characters of sha256(verification_key.json bytes)>
```

The envelope's optional `artifact` field names the key used to create the proof. The
node resolves that id before Groth16 verification. A known retired id returns
`artifact-retired:<id>`; an unknown id returns `artifact-unknown:<id>`; a malformed id
returns `bad-artifact:<repr>`.

Operators configure accepted verification keys with `SHADE_TREE_ZK_ARTIFACTS`. Clients
configure ordered prover sets with `SHADE_TREE_ZK_PROVER_ARTIFACTS`. Signed capabilities
advertise the accepted ids, and the client selects the newest mutual id.

## Rotating artifacts

Use a dual-key window:

1. Nodes accept the new and old verification keys and advertise both ids.
2. Clients ship the new prover first and retain the old prover second.
3. Observe that active clients select the new id.
4. Remove the old verifier from nodes.
5. Remove the old prover from clients.

The envelope can stay v4 throughout because the wire shape has not changed. The complete
trusted-setup and rollback procedure is in [`CEREMONY.md`](CEREMONY.md).

## Conformance

Golden values live in [`../testdata/vectors.json`](../testdata/vectors.json). Run:

```bash
node gateway/version-negotiation.selftest.mjs
node lib/zk-artifacts.selftest.mjs
(cd rust && cargo test --workspace --all-features)
```
