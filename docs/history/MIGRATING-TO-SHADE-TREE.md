# Migrating to Shade Tree v4

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

Shade Tree v4 is a clean protocol and naming boundary. It intentionally does
not accept the earlier wire format or configuration names.

## Name map

| Earlier surface | Shade Tree v4 |
| --- | --- |
| repository/package | `shade-tree-node` |
| CLI and Rust binary | `shade-tree` |
| JavaScript class | `ShadeTreeClient` |
| stream metadata | `.shadeTree` |
| environment prefix | `SHADE_TREE_*` |
| metric prefix | `shade_tree_*` |
| install directory/user | `/opt/shade-tree`, `shade-tree` |

There are no aliases for the old CLI, JavaScript class, environment prefix,
service names, or install paths. Update automation and secrets before rolling
out the new units.

## Protocol reset

- The only accepted envelope version is `4`.
- Missing versions are classified as legacy v3 and rejected.
- The request signal is `shade-tree:v4`.
- Capability, operator authorization, receipt, exit, and withdrawal domains
  use new Shade Tree contexts.
- Deterministic member subkeys now use `shade-tree-subkey:v1`; the same master,
  context, and index therefore derive a different secret and membership leaf.
- Old request proofs cannot be relabeled as v4 because the signal hash is a
  public input to the proof.
- Old capability, operator, and receipt signatures must be regenerated.

The RLN circuit artifacts, artifact identifiers, membership commitments, and
Tor onion identities did not change solely because of the rename. Existing
ordinary membership leaves remain valid, but anyone who enrolled a leaf made
by the old subkey derivation must keep its old derived secret or enroll the new
Shade Tree-derived leaf; changing the prefix does not migrate it.

## Contracts and network records

Deployed contracts retain the domain constants compiled into their bytecode.
Existing exit and withdrawal deployments therefore cannot enforce the new
Shade Tree contexts. Deploy fresh contracts for those paths; state does not
migrate automatically.

The records under `network/sepolia/` document the earlier research deployment.
Treat them as migration evidence, not as confirmation that a v4 fleet is live.
A v4 operator rollout must:

1. deploy contracts that contain the new exit and withdrawal contexts;
2. update node configuration to the new addresses and `SHADE_TREE_*` names;
3. restart the v4 gateway and bootnode services;
4. regenerate operator authorization, capability, and receipt signatures;
5. republish a signed directory and distribute its pinned signer;
6. verify an end-to-end v4 tunnel before retiring the old fleet.

Base directory and announcement bytes that carry no renamed capability or
domain fields remain structurally compatible, but a mixed fleet is not. Keep
the old and new configurations separate during rollout. In particular,
capability-free directory entries now inherit a v4 default. A still-valid
signature on a capless Sepolia directory does not prove its running nodes were
upgraded: a v4 client fails closed against a v3 node, and a v4 node rejects an
old client. Publish the directory, node, and client cutover as one boundary.

## Client rollout

Start the local proxy, then scope proxy variables to one child:

```sh
shade-tree client
shade-tree run -- your-agent
```

The wrapper replaces ambient proxy bypass configuration with a loopback-safe
list plus explicit additions. Review [`CLI.md`](../CLI.md) before using it around
software with custom proxy behavior.
