# Docs index

The documentation and canonical specifications, one line each, grouped by what you are trying
to do: use ShadeNet, run a node, look something up, check its security, read the design, or
dig into history. The [README](../README.md) is the short front door;
[`OVERVIEW.md`](OVERVIEW.md) is the long one.

ShadeNet was formerly called Shade Tree Grove. Current docs say ShadeNet for the protocol and
product, Shade Tree node for one gateway, and canopy for a group of nodes with the signed
directory that lists them. Historical logs, ADRs and the changelog keep the old names.
A browsable HTML build of all of this: `node docs-site/build.mjs` ([`docs-site/`](../docs-site/README.md)).

> **Network status:** a research preview on Sepolia. [`network/sepolia/deployment.json`](../network/sepolia/deployment.json)
> records the live v4 research canopy. It admits invited members and anyone who stakes Sepolia
> testnet ETH, and its proof keys come from an adopted, re-verified RLN trusted setup. Invited
> credentials remain private; the staking profile is public. See the [research preview
> statement](../SECURITY.md#status).

## Use

| Doc | What it is |
|-----|------------|
| [`AGENT.md`](AGENT.md) | Install the live binary, get admitted, and launch one agent through the local Proxy |
| [`QUICKSTART.md`](QUICKSTART.md) | Connect with operator-supplied v4 pins, run the local loop, or start your own droplet |
| [`JOIN.md`](JOIN.md) | The member page: get a leaf, connect to an operator's canopy or a local one, what is public per path |
| [`PUBLIC-STAKING.md`](PUBLIC-STAKING.md) | The public Sepolia staking profile: bond, entitlement per epoch, exit and withdraw |
| [`ADAPTERS.md`](ADAPTERS.md) | Routing tools and agents (curl, SearXNG, browsers, LLM agents) through the local Proxy |
| [`CLIENTS.md`](CLIENTS.md) | Client modes: the local Proxy vs the library; leaf source and admission filtering |
| [`../packages/sdk/README.md`](../packages/sdk/README.md) | `@shadenet/sdk`, the JavaScript SDK for browsers and Node |
| [`SDK.md`](SDK.md) | The older in-repo `ShadeTreeClient` surface |
| [`../crates/INSTALL.md`](../crates/INSTALL.md) | Rust binaries, checksums, attestations, source builds |

## Launch

| Doc | What it is |
|-----|------------|
| [`LAUNCH-RUNBOOK.md`](LAUNCH-RUNBOOK.md) | The owner's gates in order: set the economics (H2), adopt the trusted setup (H3), deploy and launch (M8), each rehearsable on staging |

## Run

| Doc | What it is |
|-----|------------|
| [`OPERATOR.md`](OPERATOR.md) | Shade Tree node and Elder Tree runbook: deploy, day-2 health, keys, slash response, retirement |
| [`../packages/node/bootnode/deploy/README.md`](../packages/node/bootnode/deploy/README.md) | The one-command bootstrap and every tunable it accepts |
| [`DEPLOYMENT-PLAN.md`](DEPLOYMENT-PLAN.md) | The v4 topology, rollout gates, safe order, and health checks |
| [`BOOTNODE.md`](BOOTNODE.md) | Elder Tree discovery: announce, signed canopy directory, per-node capabilities, trust boundary |
| [`FLEET.md`](FLEET.md) | Per-tunnel node selection, weights, failover, canopy-wide budget |
| [`INCIDENT.md`](INCIDENT.md) | Incident playbook |
| [`SLO.md`](SLO.md) | Service-level objectives and error budget |
| [`BACKUP.md`](BACKUP.md) | Encrypted key backup and restore |
| [`KEY-ROTATIONS.md`](KEY-ROTATIONS.md) | Public record of key rotations (addresses only) |
| [`ONION-IDENTITY.md`](ONION-IDENTITY.md) | Bring a node or Elder Tree back on the same `.onion` |
| [`TOR-HARDENING.md`](TOR-HARDENING.md) | Hardening the Tor layer under a node or Elder Tree |
| [`LIGHT-CLIENT.md`](LIGHT-CLIENT.md) | Light-client root reads and the Helios sync-committee anchor |
| [`RELAY-TELEMETRY.md`](RELAY-TELEMETRY.md) | Optional aggregate relay-byte telemetry and its privacy floor |
| [`ONCHAIN-DEPLOY.md`](ONCHAIN-DEPLOY.md) | Deploying the contracts and recording the deployment |
| [`RELEASING.md`](RELEASING.md) | How a release is rehearsed, built and published |
| [`../monitoring/README.md`](../monitoring/README.md) | Grafana dashboard and Prometheus alert rules |
| [`../docker/README.md`](../docker/README.md) | Single image and the local compose canopy |
| [`../network/README.md`](../network/README.md), [`../network/sepolia/`](../network/sepolia/README.md) | Deployment-record schema, the current research record, historical pre-v4 artifacts |

## Reference

| Doc | What it is |
|-----|------------|
| [`../specs/protocol.md`](../specs/protocol.md) | The canonical protocol specification |
| [`WIRE-SPEC.md`](WIRE-SPEC.md) | Wire formats, byte encodings, and the Elder Tree HTTP API |
| [`../specs/data-api.md`](../specs/data-api.md) | The public canopy Data API: aggregate counts, privacy, history, caching |
| [`GROVE-ONCHAIN-ACTIVITY.md`](GROVE-ONCHAIN-ACTIVITY.md) | The optional finalized on-chain activity section of the Data API |
| [`CLI.md`](CLI.md) | Every command with its module and an example |
| [`CONFIG.md`](CONFIG.md) | Every `SHADE_TREE_*` variable, its default, who reads it, its flag |
| [`VERSIONING.md`](VERSIONING.md) | The v4 boundary, legacy rejection, artifact rotation, coordinated rollout |
| [`RECEIPTS.md`](RECEIPTS.md) | Signed egress success receipts |
| [`ONCHAIN.md`](ONCHAIN.md) | Staked reputation set, gateway registry, root provider |
| [`ECONOMICS.md`](ECONOMICS.md) | The bond, the slot and what it buys, and what misuse costs |
| [`../contracts/README.md`](../contracts/README.md) | The contract map |
| [`PAYMENTS.md`](PAYMENTS.md) | The HTTP 402 rails (x402 v2, MPP, EIP-3009) and their leak ledger |
| [`ERRORS.md`](ERRORS.md) | The stable error codes across the SDK, CLI, proxy and MCP, with cause and fix |
| [`PROTOCOL.md`](PROTOCOL.md), [`PROTOCOL-API.md`](PROTOCOL-API.md), [`PROTOCOL-VERSIONING.md`](PROTOCOL-VERSIONING.md), [`PUBLIC-GROVE.md`](PUBLIC-GROVE.md) | Redirect pages kept so old links resolve |

## Security

| Doc | What it is |
|-----|------------|
| [`../SECURITY.md`](../SECURITY.md) | Security policy and private reporting |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Assets, adversaries, trust per party, every property and where it is enforced, residual risks |
| [`AUDIT.md`](AUDIT.md) | Trust boundaries, test inventory, suggested review order |
| [`CONTRACTS-AUDIT.md`](CONTRACTS-AUDIT.md) | Contract invariants and the Foundry evidence |
| [`CEREMONY.md`](CEREMONY.md) | The trusted-setup ceremony runbook and kit ([`ceremony/`](ceremony/EVENT.md)) |
| [`MUTATION-TESTING.md`](MUTATION-TESTING.md) | Mutation-testing setup and surviving mutants |

## Design

| Doc | What it is |
|-----|------------|
| [`OVERVIEW.md`](OVERVIEW.md) | How a request flows, the anonymity ledger per admission path, what is not done |
| [`adr/`](adr/README.md) | Decision records 0001 to 0013: context, decision, consequences, rejected alternatives |
| [`design/SESSION-TICKETS.md`](design/SESSION-TICKETS.md) | Session tickets: one proof buys a bounded research session (implemented behind the `sessionTickets` switch; on in the live record) |
| [`exit-blocking-benchmark.md`](exit-blocking-benchmark.md) | The motivating measurement: 51 Tor exits against web and search destinations |
| [`ROADMAP.md`](ROADMAP.md) | The forward roadmap |

## History

Kept as written. They describe earlier versions and must not be executed as current runbooks.

| Doc | What it is |
|-----|------------|
| [`history/SHIP-PLAN.md`](history/SHIP-PLAN.md) | The implementation ledger through v0.6 |
| [`history/ROADMAP-v1.md`](history/ROADMAP-v1.md), [`history/NEXT-VERSION.md`](history/NEXT-VERSION.md), [`history/RLN-MIGRATION.md`](history/RLN-MIGRATION.md) | Earlier designs; what they specified is built |
| [`history/GO-LIVE.md`](history/GO-LIVE.md), [`history/GO-LIVE-LOG-2026-08-17.md`](history/GO-LIVE-LOG-2026-08-17.md), [`history/GO-LIVE-LOG-2026-08-25-v4.md`](history/GO-LIVE-LOG-2026-08-25-v4.md) | The August go-live runbook and logs |
| [`STAGING-REHEARSAL.md`](STAGING-REHEARSAL.md), [`LAUNCH-REPORT.md`](LAUNCH-REPORT.md), [`DOGFOOD-2026-10-01.md`](DOGFOOD-2026-10-01.md) | The ShadeNet launch rehearsal, the launch report, and the 2026-10-01 dogfood pass |
| [`history/REPORT.md`](history/REPORT.md), [`history/STATUS.md`](history/STATUS.md), [`history/DEPLOY.md`](history/DEPLOY.md), [`history/DEPLOYMENT.md`](history/DEPLOYMENT.md), [`history/walkthrough.html`](history/walkthrough.html) | The June 2026 PoC report, status and deploy guide, the July fleet record, the request walkthrough |
| [`history/MIGRATING-TO-SHADE-TREE.md`](history/MIGRATING-TO-SHADE-TREE.md) | The v3 to v4 (RGOE to Shade Tree) name map |
| [`history/adversarial-review.md`](history/adversarial-review.md) | Per-party worst case against the PoC; superseded by the threat model |
| [`history/residential-proxies.md`](history/residential-proxies.md), [`history/residential-proxy-providers.md`](history/residential-proxy-providers.md) | June 2026 survey of residential proxies |
| [`post/`](post/) | The published site source: landing page, canopy page, research note, figures |
