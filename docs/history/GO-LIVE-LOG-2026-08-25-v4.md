# Protocol v4 research Grove go-live — 2026-08-25

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

## Scope and security boundary

- One dedicated Elder Tree and three dedicated Shade Tree nodes on DigitalOcean.
- Ubuntu 24.04, Basic 1-vCPU/2-GiB droplets, spread across New York, San Francisco,
  and Amsterdam. Backups are off and provider monitoring is on.
- Estimated steady-state compute cost: **$48/month** before tax and incidental
  bandwidth; no load balancer, volume, managed database, or reserved IP.
- Sepolia, invited-only admission, Protocol 4 envelopes, and the explicitly
  untrusted `rln-0b25f824a04da3a8` testnet artifact. This is disposable research
  infrastructure, not production.
- Public deployment record: [`network/sepolia/deployment.json`](../../network/sepolia/deployment.json).
  Service pin: `4b141797cd4d4fd961190c0f9774f6f181e81181`.
- The provider addresses, SSH inventory, identity backups, member secret, and
  OpenTofu state are not committed to this repository.

## Deployment evidence

- The v4 preflight recomputed the proof-artifact hash and accepted the live
  deployment record.
- Ansible reconciled all four hosts with zero failures. A second pass reported
  `changed=0` for the Elder and every node.
- Only the Elder service is enabled on the Elder host. Only gateway and heartbeat
  services are enabled on node hosts.
- Every application and metrics listener is loopback-only. Host UFW and the
  DigitalOcean firewall admit SSH only from the reviewed operator `/32`.
- Deployed and Tor-active onion identities were derived independently and matched
  the controller backups. The Elder onion and signer also match the public record.
- The live Elder `/health` reported three entries. Its signed `/directory` contained
  three fresh, `health: up`, Protocol 4 announcements with the accepted artifact
  and the intended NA/NA/EU region buckets.
- The signer-pinned uptime probe passed over Tor with
  `bootnodeReachable=true`, `signerOk=true`, `directoryFresh=true`, and
  `fleetSize=3`.
- Invited RLN proofs established real HTTPS CONNECT tunnels through all three
  node onions; the observed egress addresses matched the three provider hosts.

## Grove Data API

The repository observer variables now point at this v4 Elder and signer, with
pre-v4 capability compatibility disabled. GitHub Actions run
[`32908979132`](https://github.com/dmarzzz/shade-tree-node/actions/runs/32908979132)
passed its Tor probe and minimal publisher job, replacing the parentless
`network-state` head with signed v1 and v2 aggregate snapshots. Default-branch
run [`32910049456`](https://github.com/dmarzzz/shade-tree-node/actions/runs/32910049456)
then passed the same probe and publisher path with the repository's ongoing
scheduled-workflow source.

The production Vercel endpoint returned `200`, schema
`shade-tree-public-grove-v2`, a fresh signed observation, and
`nodes.announced=3`:

```text
https://shade-tree-node.vercel.app/api/v2/data/grove/sepolia/head
```

The Grove page is live at `https://shade-tree-node.vercel.app/grove/`. It uses
only the signed aggregate count and bounded history; it receives no onion, IP,
location, identity, traffic-path, or stable-position data. Relay-byte windows
remain suppressed because this fleet has fewer than the required five-reporting-
node cohort and relay telemetry is not configured.

## Operations and teardown

- The hosted Tor probe runs every 15 minutes and publishes nothing on a failed
  observation; the API continues serving the last valid signed head and the UI
  labels it stale.
- Reconciliation is the v4 Ansible playbook documented in
  [`deploy/v4/README.md`](../../deploy/v4/README.md).
- Provider lifecycle and the ignored local state live in the isolated
  `agent-devops/tofu/environments/shade-tree-v4` environment. Run an OpenTofu
  plan there before either changing or destroying this fleet; do not target the
  older shared fleet environment.
- Before teardown, repoint or clear the four `SHADE_TREE_*` Actions variables so
  scheduled probes stop targeting a removed Elder. Preserve the encrypted SSH
  keys and private identity backup if onion continuity may be needed later.
