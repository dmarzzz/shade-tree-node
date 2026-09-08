# Docs index

The documentation and canonical specifications, one line each, grouped by what
you are trying to do. The [README](../README.md) is the short front door;
[`OVERVIEW.md`](OVERVIEW.md) is the long one.
A browsable HTML build of all of this: `node docs-site/build.mjs` ([`docs-site/`](../docs-site/README.md)).

> **Network status:** the current implementation speaks envelope v4 only. The legacy Sepolia
> contracts, bootnode record, and signed directories remain incompatible pre-v4 history and are
> not client presets. A separate [`network/sepolia/deployment.json`](../network/sepolia/deployment.json)
> records the live disposable v4 research Grove observed by the public aggregate map. It is
> admits invited and explicitly self-staked Sepolia testnet members and uses untrusted testnet
> artifacts. Invited credentials remain private; the staking profile is public and explicit.

## Start here

| Doc | What it is |
|-----|------------|
| [`OVERVIEW.md`](OVERVIEW.md) | How a request flows, the anonymity ledger per admission path, what is not done and why it matters, the exit-blocking numbers, the repo layout |
| [`QUICKSTART.md`](QUICKSTART.md) | Connect with operator-supplied v4 pins, run the local loop, or start your own droplet |
| [`JOIN.md`](JOIN.md) | The member page: get a leaf, connect to a v4 operator or local fleet, what is public per path |
| [`CLI.md`](CLI.md) | Every `shade-tree` command with its module and an example |
| [`CONFIG.md`](CONFIG.md) | Every `SHADE_TREE_*` variable, its default, who reads it, its `--flag` |
| [`STATUS.md`](STATUS.md) | Historical: the June 2026 single-gateway PoC status (the README warning and Boundaries are current) |

## Use it (clients, SDK, agents)

| Doc | What it is |
|-----|------------|
| [`AGENT.md`](AGENT.md) | Install the agent CLI, add a current access profile, launch one process through Shade Tree, or use the SDK |
| [`CLIENTS.md`](CLIENTS.md) | Client modes: the local proxy (shim) vs the library, and a planned no-tooling path; leaf source and admission filtering |
| [`SDK.md`](SDK.md) | The `ShadeTreeClient` SDK surface (`package.json` exports) |
| [`ADAPTERS.md`](ADAPTERS.md) | Routing tools and agents (curl, SearXNG, browsers, LLM agents) through the local proxy |
| [`RECEIPTS.md`](RECEIPTS.md) | Signed egress success receipts: proof a gateway actually served traffic, with no linkability channel |
| [`VERSIONING.md`](VERSIONING.md) | The explicit v4 boundary, legacy-v3 rejection, artifact rotation, and coordinated fleet rollout |
| [`../rust/INSTALL.md`](../rust/INSTALL.md) | The static Rust client: platform binaries, checksums, one-shot `egress`, and the embedded-Arti CONNECT Proxy |

## Run it (gateway, bootnode, fleet)

| Doc | What it is |
|-----|------------|
| [`DEPLOYMENT-PLAN.md`](DEPLOYMENT-PLAN.md) | Current v4 topology, Elder Tree and node rollout gates, safe order, and health checks |
| [`OPERATOR.md`](OPERATOR.md) | Shade Tree node and Elder Tree runbook, including current deployment blocks, day-2 health, keys, slash response, and retirement |
| [`../bootnode/deploy/README.md`](../bootnode/deploy/README.md) | The one-command droplet bootstrap and every tunable it accepts |
| [`BOOTNODE.md`](BOOTNODE.md) | Elder Tree discovery: announce, signed Canopy, per-node signed capabilities, and the trust boundary |
| [`data-api.md`](../specs/data-api.md) | The canonical public Grove Data API: verified aggregate counts, publisher/observer surfaces, privacy, bounded history, caching, and evolution |
| [`FLEET.md`](FLEET.md) | Per-tunnel gateway selection, weights, failover, fleet budget |
| [`INCIDENT.md`](INCIDENT.md) | Incident playbook |
| [`SLO.md`](SLO.md) | Service-level objectives and error budget (proposals, recalibrated on live data) |
| [`BACKUP.md`](BACKUP.md) | Encrypted key backup and restore |
| [`ONION-IDENTITY.md`](ONION-IDENTITY.md) | Onion continuity: bring a gateway or bootnode back on the same `.onion` (verify before cutover, restore) |
| [`TOR-HARDENING.md`](TOR-HARDENING.md) | Hardening the Tor layer under a gateway or bootnode |
| [`LIGHT-CLIENT.md`](LIGHT-CLIENT.md) | Light-client root reads and the Helios sync-committee anchor (`SHADE_TREE_HELIOS=1`), with live receipts |
| [`../monitoring/README.md`](../monitoring/README.md) | Grafana dashboard + Prometheus alert rules on the real metric names |
| [`../docker/README.md`](../docker/README.md) | Single image and the local compose fleet |
| [`DEPLOYMENT-PLAN.md`](DEPLOYMENT-PLAN.md), [`GO-LIVE-LOG-2026-08-25-v4.md`](GO-LIVE-LOG-2026-08-25-v4.md) | The current v4 rollout boundary and the disposable research Grove deployment record |
| [`../network/README.md`](../network/README.md), [`../network/sepolia/`](../network/sepolia/README.md) | Deployment-record schema, the current v4 research record (`deployment.json`), and historical pre-v4 Sepolia artifacts |

## Design and security

| Doc | What it is |
|-----|------------|
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Assets, adversaries, trust assumptions per party, every property and where it is enforced, residual risks (section 5), audit checklist |
| [`AUDIT.md`](AUDIT.md) | Trust boundaries, test inventory, suggested review order |
| [`CONTRACTS-AUDIT.md`](CONTRACTS-AUDIT.md) | Contract invariants and the Foundry evidence |
| [`adversarial-review.md`](adversarial-review.md) | Per-party worst case |
| [`CEREMONY.md`](CEREMONY.md) | The trusted-setup runbook (not run; [issue #6](https://github.com/dmarzzz/shade-tree-node/issues/6)) |
| [`protocol.md`](../specs/protocol.md) | The canonical anonymous-paid-access protocol specification |
| [`WIRE-SPEC.md`](WIRE-SPEC.md) | Wire formats and the bootnode HTTP API |
| [`MUTATION-TESTING.md`](MUTATION-TESTING.md) | Mutation-testing setup and surviving mutants |
| [`adr/`](adr/README.md) | Decision records: context, decision, consequences, rejected alternatives |
| [`adr/0001`](adr/0001-client-language.md) | JS stays the reference implementation; the Rust client is the distributable, kept honest by conformance vectors |
| [`adr/0002`](adr/0002-onion-never-on-chain.md) | The onion address is never on chain; stake is keyed by operator address |
| [`adr/0003`](adr/0003-bootnode-is-a-cache-not-a-trust-root.md) | The bootnode is a cache and a discovery trust boundary |
| [`adr/0004`](adr/0004-rln-over-slot-scheme.md) | Real RLN over the public-slot scheme |
| [`adr/0005`](adr/0005-governed-gateway-slash.md) | Member slashing permissionless, gateway slashing governed |
| [`adr/0006`](adr/0006-reputation-tiers.md) | Reputation tiers are per-leaf `userMessageLimit`s in one tree |
| [`adr/0007`](adr/0007-paid-access.md) | Paid access is an operator-inserted leaf in a second on-chain tree, redeemed with the same proof |
| [`adr/0008`](adr/0008-per-gateway-admission-and-payment-choice.md) | Each provider chooses what it admits and sells; the default is maximum anonymity |
| [`../SECURITY.md`](../SECURITY.md), [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Security policy and how to report; tests and house rules |

## On chain

| Doc | What it is |
|-----|------------|
| [`ONCHAIN.md`](ONCHAIN.md) | Staked reputation set, gateway registry, root provider: the design |
| [`ONCHAIN-DEPLOY.md`](ONCHAIN-DEPLOY.md) | Deploying the contracts and recording the deployment |
| [`../contracts/README.md`](../contracts/README.md) | The contract map (`StakedReputationSet`, `PaidAccessSet`, `GatewayRegistry`, verifiers) |

## Payments

| Doc | What it is |
|-----|------------|
| [`PAYMENTS.md`](PAYMENTS.md) | The HTTP 402 rails as shipped (x402 v2, MPP, EIP-3009), the leak ledger, the design of record |
| [`adr/0007`](adr/0007-paid-access.md), [`adr/0008`](adr/0008-per-gateway-admission-and-payment-choice.md) | Paid access is an operator-inserted leaf; each provider chooses what it admits and sells |

## Background and history

| Doc | What it is |
|-----|------------|
| [`exit-blocking-benchmark.md`](exit-blocking-benchmark.md) | The benchmark: 51 exits, web and search destinations, block rates and reasons |
| [`residential-proxies.md`](residential-proxies.md), [`residential-proxy-providers.md`](residential-proxy-providers.md) | What residential proxies do to your privacy; a provider taxonomy |
| [`post/`](post/) | The published landing page ([`index.html`](post/index.html)), [live Grove](post/grove/index.html), full [research note](post/research/index.html), figures, plus [`JOIN.md`](post/JOIN.md) and [`RUN-A-GATEWAY.md`](post/RUN-A-GATEWAY.md) |
| [`SHIP-PLAN.md`](SHIP-PLAN.md), [`ROADMAP.md`](ROADMAP.md) | The shipping backlog and release gates; the forward roadmap |
| [`ROADMAP-v1.md`](ROADMAP-v1.md), [`NEXT-VERSION.md`](NEXT-VERSION.md), [`RLN-MIGRATION.md`](RLN-MIGRATION.md) | Historical designs (milestones 1 to 5, next-version spec, RLN migration); what they specified is built |
| [`REPORT.md`](REPORT.md), [`DEPLOY.md`](DEPLOY.md), [`DEPLOYMENT.md`](DEPLOYMENT.md), [`walkthrough.html`](walkthrough.html) | Historical: the June 2026 PoC report and deploy guide, the July fleet deployment record, the request walkthrough |
