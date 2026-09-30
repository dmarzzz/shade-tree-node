# Protocol v4 deployment preflight and Ansible role

This directory implements the target-independent parts of deployment-plan gates 5–7. It does
not contain an inventory, provider address, onion, key, contract, or deployment claim. It has
not provisioned or changed a provider.

The layer reuses [`packages/node/bootnode/deploy/bootstrap.sh`](../../packages/node/bootnode/deploy/bootstrap.sh) for the
Tor configuration and hardened systemd units, then adds the things a live v4 rollout must not
infer: a reviewed network record, immutable source pins, firewall policy, restored identity
continuity, admission authorization, and postflight checks.

## 1. Create the public v4 record

Copy [`deployment.example.json`](deployment.example.json) to
`network/<network>/deployment.json`. The example is intentionally `pending` and null-filled; it
cannot deploy.

Populate only operator-verified public values:

- `protocol`: the accepted v4 envelope range (`min` must be 4).
- `security`: the proof-artifact trust decision, rollout scope, and its review reference. The
  current `UNTRUSTED-TESTNET` lock can describe only a `disposable-research` fleet; a production
  record is rejected until the lock records `TRUSTED-CEREMONY` with a completed ceremony.
- `services`: credential-free HTTPS repository and a full 40-hex commit for Elder, node, and
  heartbeat. The current deployer packages all three from one checkout, so all pins must match.
- `elder`: the restored Elder onion, pinned Canopy signer, and operator-admission policy.
- `admission.paths` and `admission.roots`: default to invited-only. The invited root records the
  exact operator member file's SHA-256; staked/paid roots record contract addresses.
- `artifacts.accepted`: each content-derived RLN artifact id, repo-relative verification-key
  path, and full SHA-256. The preflight recomputes both the hash and id from the file bytes.
- `operatorAuthorization`: a non-secret approval reference is mandatory when staked or paid is
  selected.

Review an incomplete record without making it deployable:

```bash
node deploy/v4/preflight.mjs \
  --record network/<network>/deployment.json \
  --repo-root . \
  --allow-pending
```

The deploy form omits `--allow-pending`. It requires `status: "live"`, every pin/root, a valid
Elder identity, at least one byte-verified artifact, and no floating ref. For
`public-stake-v1` it verifies Sepolia chain ID, deployment receipt/block, constructor parameters,
tier bonds, allowed limits, unbonding, and the normalized runtime bytecode of the set, hasher,
withdrawal wrapper, Groth16 verifier, and linked Poseidon libraries. The operator role repeats
this full check through its exact runtime RPC before any target is changed:

```bash
node deploy/v4/preflight.mjs \
  --record network/<network>/deployment.json \
  --repo-root . \
  --require-stake-profile public-stake-v1 \
  --rpc-url "$SHADE_TREE_RPC_URL"
```

## 2. Prepare secret inputs outside Git

Restore each host's identity backup into a controller directory. A `node` target requires complete
`gateway-hs/` material; an `elder` target requires `bootnode-hs/` and `bootnode-signer.key`;
the backward-compatible `elder-and-node` mode requires both. Before any remote mutation it derives the onions from the Tor secret keys
and compares the Elder onion and Canopy signer to the public record.

Keep the operator member file, slashing key, gateway-operator key, and credentialed RPC URL in
Ansible Vault or an equivalent secret store. Never put them in the public record, inventory,
command line, or repository. Secret-bearing role tasks use `no_log`.

On-chain admission is deliberately harder to enable than invited-only:

- `shade_tree_operator_authorized=true` is required;
- the selected contract roots must be present in the live record;
- `shade_tree_rpc_url` and a 32-byte `shade_tree_slash_key` are required;
- a stake-gated Elder additionally requires its `gatewayRegistry` and
  `shade_tree_gateway_operator_key`.

Missing input stops the play before packages, checkout, firewall, or services change.

## 3. Use a private inventory

Copy [`ansible/inventory.example.yml`](ansible/inventory.example.yml) outside the repository and
replace its placeholders. Set host variables there or in encrypted vars:

```yaml
shade_tree_deployment_record: /absolute/controller/path/network/research-v4/deployment.json
shade_tree_target_mode: elder # or node; elder-and-node remains available for a colocated test host
shade_tree_admin_cidr: 198.51.100.24/32
shade_tree_identity_source: /absolute/controller/path/restored-host-identity
shade_tree_members_file: /absolute/controller/path/operator-members.json
```

The documentation CIDR above is illustrative, not a default. Use the operator's exact real CIDR.

Then run from this repository:

```bash
ANSIBLE_CONFIG=deploy/v4/ansible/ansible.cfg \
  ansible-playbook \
  -i /absolute/private/inventory.yml \
  deploy/v4/ansible/playbook.yml
```

## What the role enforces

- Ubuntu 24.04+, a credential-free repository, and the exact reviewed commit.
- Restored onion/signer continuity; no automatic replacement identities.
- Tor onion mappings and hardened Elder/node/heartbeat units from the shared bootstrap.
- Explicit accepted ZK artifacts in both node verification and signed heartbeat capabilities.
- Invited-only by default; contract/RPC/key/operator checks before any on-chain path.
- JSON service logs, no banner, distinct loopback metrics, and no public Elder/node/metrics
  listener.
- UFW default-deny inbound with exactly one reviewed admin-CIDR SSH allow rule. Unexpected
  inbound allow rules abort the play for an operator decision.
- A non-secret reconciliation fingerprint. The marker is written only after source, services,
  environment, listener, and identity postflight checks pass, so an unchanged second run is a
  no-op. Set `shade_tree_force_reconcile=true` for a deliberate repair run.

## Remaining external blockers

The code cannot safely choose a provider account, owner, region, host size, admin CIDR, SSH key,
rollback target, real onion identities, Canopy signer, trusted proof artifacts, contracts, RPC,
or operator keys. The trusted-setup decision and actual live v4 record therefore remain rollout
gates. Do not copy values from the retired Sepolia fleet merely to satisfy the preflight.
