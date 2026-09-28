# GO-LIVE runbook: T-DEPLOY-1 + T-DEPLOY-2

> **Historical pre-v4 runbook.** This checklist records the August 2026 research deployment
> and must not be executed against the current envelope-v4 code. Its Sepolia records are
> retired; use `QUICKSTART.md`, `OPERATOR.md`, and explicit v4 operator values for new work.

The single ordered checklist for the first live deployment. It composes the existing docs; it
does not replace them. Every command below exists in this repo (`bin/shade-tree.mjs`,
`bootnode/deploy/*`, `scripts/*`) or in the cited doc. Where the repo lacks something the
runbook needs, the line is marked `GAP:` and repeated in the "Gaps found" section at the end.

**Targets (from `docs/SHIP-PLAN.md` section 3):**

- **T-DEPLOY-1** — bootnode + one gateway on a **fresh** droplet, gateway announced, laptop
  client egresses through the fleet. Accept: `curl -x` through the client returns the
  gateway's IP; `GET /directory` lists the gateway. The existing live gateway fleet is **not**
  touched.
- **T-DEPLOY-2** — at least two gateways on different providers/regions/ASNs. Accept:
  `/directory` shows >= 2, the client rotates across them.

**Machines:** `laptop` (operator workstation with this repo + an enrolled `SHADE_TREE_SECRET`),
`droplet-1` (fresh box: bootnode + gateway-1), `droplet-2` (fresh box, different provider/ASN:
gateway-2), `chain` (Sepolia, via `SHADE_TREE_RPC_URL`).

**Markers:** `[HUMAN]` = a human decision, not something an agent runs unattended.
`[FUNDS]` = spends real (testnet) funds or requires a funded key. `[RECEIPT]` = what to
capture as evidence that the step is done.

**Placeholders used throughout:** `<D1_IP>` `<D2_IP>` (droplet public IPs, SSH only),
`<BN_ONION>` (bootnode onion), `<SIGNER>` (bootnode pinned signer pubkey, hex),
`<GW1_ONION>` `<GW2_ONION>` (gateway onions), `<GW_REGISTRY>` (`GatewayRegistry` address).
Never substitute the address/onion of the existing fleet for any of these.

---

## Phase 0 — Preconditions (laptop; nothing is deployed in this phase)

| # | Check | Command (laptop) | Receipt / gate | Rollback |
|---|---|---|---|---|
| 0.1 | Gates 1+2 green | `npm test` and `npm run test:contracts` on this branch (`feat/bootnode-and-productionize`) | Both exit 0. SHIP-PLAN section "Sequencing and release gates" says T-DEPLOY-* is BLOCKED until Gate 1 + Gate 2 are green; SHIP-PLAN loop-23 records Gate 2 code path closed. | n/a |
| 0.2 | Ceremony status `[HUMAN]` | Read `docs/CEREMONY.md` (T-HARD-1; being authored separately) | Decide: (a) go live with the **testnet-only, untrusted** RLN artifacts pinned in `circuits/rln/ARTIFACTS.md` and label the fleet testnet, or (b) wait for the ceremony. Record the decision + date at the top of the go-live log. The `-live` Rust binary embeds these artifacts (`.github/workflows/release.yml` header). | n/a |
| 0.3 | Artifact hashes | `shasum -a 256 circuits/rln/rln.wasm circuits/rln/rln_final.zkey circuits/rln/verification_key.json` vs the table in `circuits/rln/ARTIFACTS.md` | All three match. | n/a |
| 0.4 | Existing fleet inventory (read-only) | Read `network/sepolia/README.md`, `network/sepolia/directory.json`, `docs/DEPLOYMENT.md`; in `~/agent-devops`: `FLEET.md`, `ansible/inventory/group_vars/egress.yml`, `tofu/environments/dev/generated/fleet-ledger.md` | Write down the names of the boxes you must NOT touch (agent-devops `egress` group: `egress-01`, `egress-02`, `shade-tree-03`; firewall class `anon_egress`). No host literally named `anon-egress` exists in either repo — see GAP-1. | n/a |
| 0.5 | Sepolia contract addresses | `cat network/sepolia/contracts.json` | `stakedReputationSet = 0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC` (rln-v3, block 11279842), `hasher = 0x08F9a754…`, `withdrawVerifier = 0x5A6FD01d…`, `rpcUrl = https://ethereum-sepolia-rpc.publicnode.com`. **There is no `gatewayRegistry` entry** — `GatewayRegistry` is not yet deployed on Sepolia (see Phase 3 / GAP-2). Note that `network/sepolia/README.md` still lists the superseded `0x35719A47…98EC` (see Contradictions). | n/a |
| 0.6 | Deployer / operator keys `[HUMAN]` `[FUNDS]` | `cast wallet list` (Foundry) — expect `shade-tree-deployer` (per `docs/ONCHAIN-DEPLOY.md` section 3); `cast balance <deployer> --rpc-url https://ethereum-sepolia-rpc.publicnode.com` | Deployer `0x3261DaF3672Dc8E6063b6960C161Fdc8a6Fc2ff7` (per `network/sepolia/contracts.json`) has > 0.05 Sepolia ETH if Phase 3 is in scope. Operator EOA for `register-gateway` funded with >= `SHADE_TREE_BOND_WEI` + gas. Keys are never pasted inline; keystore or env only. | n/a |
| 0.7 | Member secret | `test -f demo-keys.local.md` (gitignored, laptop only) or `shade-tree enroll --commitment-only` | You hold an `SHADE_TREE_SECRET` whose rateCommitment leaf is in the committed `group/members.json` (`{"version":2,"members":[...]}`). A **new** enrollment via `shade-tree enroll` appends to the local `group/members.json`; that change must reach droplets (commit + `rolling-update.sh`) or every proof drops `wrong-group-root`. Prefer an existing enrolled secret for go-live. | n/a |
| 0.8 | Laptop Tor | `tor --version; tor --list-modules` | Note `pow: yes|no`. Homebrew tor reports `pow: no`. `docs/DEPLOYMENT.md` ("PoW capability mismatch") records that such a client **could not** reach a PoW-enabled onion, while `bootnode/deploy/bootstrap.sh` writes `HiddenServicePoWDefensesEnabled 1` for both onions. See Phase 4.0 for the mitigation and Contradictions. | n/a |
| 0.9 | Rust client `[HUMAN]` | Either download a Release asset per `crates/INSTALL.md` (needs a `v*` tag pushed → `.github/workflows/release.yml`), or `cargo build --release -p shadenet-cli --features live` | `./target/release/shade-tree --version` prints. Decide whether to cut a release tag now (a tag push is a human git action, not part of this runbook). | n/a |
| 0.10 | Provider accounts `[HUMAN]` `[FUNDS]` | DO: `export TF_VAR_do_token=...` (droplet-1). Second provider account (droplet-2) chosen and funded. | Two providers with **different ASNs**. Verify after creation with `curl -s https://ipinfo.io/<IP>/org`. DO is AS14061; pick a non-DO second provider (e.g. Hetzner AS24940, Vultr AS20473, OVH AS16276 — verify at creation). | n/a |
| 0.11 | Bootstrap ref pinned `[HUMAN]` | Decide the git ref droplets clone: `feat/bootnode-and-productionize` (bootstrap default) or a tag/sha. | Record it; pass as `SHADE_TREE_REF` / `git_ref`. `docs/post/RUN-A-GATEWAY.md:28` points at `main` — do not use that URL for this branch's bootstrap (see Contradictions). | n/a |
| 0.12 | Go/no-go `[HUMAN]` | — | Someone with authority writes "GO <date>" in the go-live log with the Phase 0.2 decision attached. | — |

---

## Phase 1 — Bootnode (droplet-1)

Bootstrap brings up **bootnode + gateway-1 + heartbeat** on the same box in one shot
(`bootnode/deploy/bootstrap.sh`), so Phases 1 and 2 are one provisioning action followed by
two separate verifications.

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 1.1 | Create droplet-1 (IaC) `[FUNDS]` | laptop | `cd bootnode/deploy/terraform && cp terraform.tfvars.example terraform.tfvars` (set `ssh_public_key`, `droplet_name="shade-tree-bn1"`, `region`, `git_ref=<0.11>`, `ssh_allowed_cidrs=["<your-ip>/32"]`) then `export TF_VAR_do_token=...; tofu init && tofu plan && tofu apply` | `tofu output ipv4_address` → `<D1_IP>`. Firewall = SSH-in only, all-out (`main.tf`). **This is the repo's own module, a fresh state dir; it does not touch `~/agent-devops` state** (never run a blanket `tofu apply` in `~/agent-devops/tofu/environments/dev` — `docs/DEPLOYMENT.md` "SAFETY: targeted applies only"). | `tofu destroy` in `bootnode/deploy/terraform` (destroys only this module's droplet/key/firewall). |
| 1.2 | Watch first-boot bootstrap | laptop | `ssh root@<D1_IP> 'tail -f /var/log/shade-tree-bootstrap.log'` (`tofu output provisioning_log_command`) | Final banner prints `bootnode onion`, `bootnode signer`, `gateway onion`, `admission open`. Record `<BN_ONION>`, `<SIGNER>`, `<GW1_ONION>` in the go-live log (these are the NEW fleet's; safe to publish). | If bootstrap failed mid-way: `ssh root@<D1_IP> 'sudo bash /opt/shade-tree/bootnode/deploy/bootstrap.sh'` (idempotent, reuses keys/units). |
| 1.3 | Units + tor | droplet-1 | `systemctl status tor shade-tree-bootnode shade-tree-gateway shade-tree-heartbeat`; `tor --list-modules \| grep pow`; `systemd-analyze security shade-tree-bootnode` | All 4 active; `pow: yes`; exposure ~2.x (`bootnode/deploy/README.md` "Systemd hardening"). | `journalctl -u shade-tree-bootnode -n 100`; fix env in `/etc/systemd/system/shade-tree-*.service`, `systemctl daemon-reload && systemctl restart <unit>`. |
| 1.4 | Bootnode health, loopback | droplet-1 | `curl -s http://127.0.0.1:8877/health` | JSON with liveness, gateway count, `admission: open`. | as 1.3 |
| 1.5 | Bootnode health, over Tor | droplet-1 | wait ~30–120 s for descriptor upload, then `BN=$(cat /opt/shade-tree/deploy-state/bootnode-hs/hostname); curl --socks5-hostname 127.0.0.1:9050 http://$BN/health` | 200 + same JSON. | Descriptor cold-start is expected (`docs/DEPLOYMENT.md` item 3); retry for up to ~5 min before treating as failure. |
| 1.6 | Signer pinned | droplet-1 | `node -e "console.log(JSON.parse(require('fs').readFileSync('/opt/shade-tree/deploy-state/bootnode-signer.key')).pub)"` | Equals `<SIGNER>` from 1.2. `SHADE_TREE_BOOTNODE_SIGNER_KEY` + `SHADE_TREE_BOOTNODE_STORE` are set on the unit by bootstrap (persistence across restart is on). | Never regenerate the signer after clients pin it (`docs/INCIDENT.md` #2). |
| 1.7 | Firewall sanity | laptop | `nc -zv <D1_IP> 8877; nc -zv <D1_IP> 8443` | Both refused/timeout. Only 22 open. | Fix `ssh_allowed_cidrs`/firewall in tofu; `tofu apply`. |

---

## Phase 2 — Gateway-1 (droplet-1, same box)

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 2.1 | Node up | droplet-1 | `journalctl -u shade-tree-gateway -n 50 -o cat` | JSON records include `"msg":"gateway up on 127.0.0.1:8443","event":"service.ready"`, `"msg":"egress policy ready"`, and `"msg":"root source: members.json (PoC fallback)"`. The `members` field equals `jq '.members\|length' group/members.json` on the laptop at the same ref. | `systemctl restart shade-tree-gateway`. |
| 2.2 | Heartbeat announcing | droplet-1 | `journalctl -u shade-tree-heartbeat -n 20 -o cat` | A JSON record has `"msg":"heartbeat accepted","staked":false,"ttlSec":900`; readiness reports `"first":"accepted"`. | `systemctl restart shade-tree-heartbeat`; check `SHADE_TREE_BOOTNODE_ONION`, `SHADE_TREE_GW_IDENTITY`, and `SHADE_TREE_TOR_PORT=9050` in the unit. |
| 2.3 | Directory lists gateway-1 `[RECEIPT T-DEPLOY-1 half]` | droplet-1 | `curl -s --socks5-hostname 127.0.0.1:9050 http://<BN_ONION>/directory` | `gateways[]` contains `{onion:"<GW1_ONION>", weight:100, ...}`; save the JSON body as `golive/directory-1gw.json` (laptop copy). | If empty: TTL is 900 s / heartbeat 300 s; wait one interval; check 2.2. |
| 2.4 | (Optional) region cap | droplet-1 | Add `Environment=SHADE_TREE_GATEWAY_REGION=na` (or `eu`, per box) to `/etc/systemd/system/shade-tree-heartbeat.service`; `systemctl daemon-reload && systemctl restart shade-tree-heartbeat` | The next verified `/directory` entry has `caps.region` set to the chosen continent bucket (`docs/OPERATOR.md` section 7). | Remove the line, reload, restart. |
| 2.5 | Verify node metrics | droplet-1 | `curl --fail 127.0.0.1:9101/readyz && curl --fail 127.0.0.1:9101/metrics \| head` | Readiness is `ok`; `shade_tree_gateway_*` and runtime metrics are present on loopback (`monitoring/README.md`). Bootstrap already configures this listener. | Restart `shade-tree-gateway` if readiness is not `ok`. |
| 2.6 | Egress IP of gateway-1 (for Phase 4 comparison) | droplet-1 | `curl -s https://api.ipify.org` | Equals `<D1_IP>`. | — |

---

## Phase 3 — On-chain registration / stake (chain) `[HUMAN]` `[FUNDS]` — optional for T-DEPLOY-1 acceptance

T-DEPLOY-1/2 acceptance is met with `--admission open` (bootstrap default). Do Phase 3 only if
the go/no-go (0.12) includes "staked admission". It follows `docs/ONCHAIN-DEPLOY.md` exactly.

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 3.1 | Dry run (no funds) | laptop | `SHADE_TREE_DEPLOY_OUT=cache/deployed.sim.json forge script contracts/script/DeployRegistry.s.sol:DeployRegistry` then again with real env (`SHADE_TREE_RPC_URL`, `SHADE_TREE_BOND_WEI=1000000000000000`, `SHADE_TREE_UNBONDING=300 SHADE_TREE_MIN_UNBONDING=270`, `SHADE_TREE_GATEWAY_OWNER`, `SHADE_TREE_DEPLOY_STAKED=0`) still without `--broadcast` | `== Logs ==` shows chainid 11155111, bond/unbonding, no unintended `WARNING: deployed Mock…` (`SHADE_TREE_DEPLOY_STAKED=0` deploys `GatewayRegistry` only, since `StakedReputationSet` already exists at 0xdAE242…). | n/a |
| 3.2 | Broadcast `GatewayRegistry` `[FUNDS]` | laptop→chain | `forge script contracts/script/DeployRegistry.s.sol:DeployRegistry --rpc-url "$SHADE_TREE_RPC_URL" --account shade-tree-deployer --broadcast` (with the 3.1 env, `SHADE_TREE_DEPLOY_OUT` unset) | `contracts/deployed.local.json` gains `gatewayRegistry`; `broadcast/DeployRegistry.s.sol/11155111/run-latest.json`; `cast call <GW_REGISTRY> "BOND()(uint256)" --rpc-url $SHADE_TREE_RPC_URL` = 1000000000000000. Record `<GW_REGISTRY>` in the go-live log **and** add it to `network/sepolia/contracts.json` (GAP-2: schema has no `gatewayRegistry` key yet; add one). | Contracts are immutable; a bad deploy is abandoned and re-deployed. Do not wire a bad address into units. |
| 3.3 | Verify source (optional) | laptop | `forge verify-contract <GW_REGISTRY> contracts/GatewayRegistry.sol:GatewayRegistry --chain sepolia --etherscan-api-key <key> --constructor-args $(cast abi-encode "c(uint256,uint256,uint256,address)" "$SHADE_TREE_BOND_WEI" "$SHADE_TREE_UNBONDING" "$SHADE_TREE_MIN_UNBONDING" "$SHADE_TREE_GATEWAY_OWNER")` | Etherscan shows verified. | — |
| 3.4 | Stake operator `[FUNDS]` | laptop→chain | `read -s SHADE_TREE_REGISTER_KEY; SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree register-gateway --gateway-registry <GW_REGISTRY> --rpc-url "$SHADE_TREE_RPC_URL"; unset SHADE_TREE_REGISTER_KEY` | Prints tx; `cast call <GW_REGISTRY> "isStaked(address)(bool)" <operator> --rpc-url $SHADE_TREE_RPC_URL` = true. Idempotent (`group/register-gateway.mjs:51`). | Exit path is manual `cast send … "initiateExit()"` then `withdraw(address)` after `UNBONDING` (`docs/OPERATOR.md` section 6). |
| 3.5 | Switch bootnode to stake admission | droplet-1 | In `/etc/systemd/system/shade-tree-bootnode.service` set `Environment=SHADE_TREE_BOOTNODE_ADMISSION=stake`, add `Environment=SHADE_TREE_STAKE_MODE=onchain`, `Environment=SHADE_TREE_GATEWAY_REGISTRY=<GW_REGISTRY>`, `Environment=SHADE_TREE_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com` (optionally `SHADE_TREE_CONFIRMATIONS=6`); `systemctl daemon-reload && systemctl restart shade-tree-bootnode` | `/health` shows `admission: stake`. Bootnode reloads its store and re-verifies entries (`docs/BOOTNODE.md` "Surviving a restart"). | Set `SHADE_TREE_BOOTNODE_ADMISSION=open`, remove the three vars, reload, restart. |
| 3.6 | Heartbeat signs operator auth | droplet-1 | Put `SHADE_TREE_GW_OPERATOR_KEY=<operator-key>` in a root-readable mode-0600 environment file referenced by `shade-tree-heartbeat.service` (or use `SHADE_TREE_GW_OPERATOR` + precomputed `SHADE_TREE_GW_OPERATOR_SIG` to keep the key off-box); `systemctl daemon-reload && systemctl restart shade-tree-heartbeat` | The `heartbeat accepted` JSON record has `"staked":true`; the `/directory` entry shows staked. | Remove var, restart; bootnode back to `open` (3.5 rollback). |
| 3.7 | (Optional) gateway slashing on-chain | droplet-1 | Put `SHADE_TREE_SLASH_CONTRACT=0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC`, `SHADE_TREE_RPC_URL`, and `SHADE_TREE_SLASH_KEY=<hot-key>` in the gateway's root-readable mode-0600 environment file | Gateway startup no longer logs `slash: DRY-RUN`. This is the config the existing fleet already runs (`~/agent-devops/ansible/inventory/group_vars/egress.yml`). Do NOT reuse the existing fleet's slash key on the new box unless the human decides so. | Remove vars, restart (returns to dry-run). |

---

## Phase 4 — First laptop client egress (JS and Rust) `[RECEIPT T-DEPLOY-1]`

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 4.0 | PoW compatibility check | laptop | If Phase 0.8 said `pow: no`, first try 4.2 anyway. If the dial fails `HostUnreachable`/timeout while 1.5 passes on-box, on droplet-1 set `HiddenServicePoWDefensesEnabled 0` for both blocks in `/etc/tor/torrc.d-shade-tree`, `systemctl reload tor` (onions unchanged; keys persist). | Documented decision in the go-live log. GAP-3: bootstrap.sh has no `SHADE_TREE_ENABLE_POW` toggle; the agent-devops role defaults `shade_tree_enable_pow: false` for exactly this reason. | Re-enable, `systemctl reload tor`. |
| 4.1 | Laptop Tor | laptop | `bash scripts/start-tor-client.sh` (SOCKS 9260, `tor/torrc.client`) or use system tor and `export SHADE_TREE_TOR_PORT=9050` | `curl --socks5-hostname 127.0.0.1:9260 http://<BN_ONION>/health` returns the same JSON as 1.5. | `pkill -f torrc.client`. |
| 4.2 | JS client (fleet mode via bootnode) | laptop | `read -s SHADE_TREE_SECRET; read -r SHADE_TREE_LIMIT; SHADE_TREE_SECRET="$SHADE_TREE_SECRET" shade-tree proxy --limit "$SHADE_TREE_LIMIT" --bootnode <BN_ONION> --dir-signer <SIGNER> --tor-port 9260; unset SHADE_TREE_SECRET SHADE_TREE_LIMIT` (`npm link` once, or `node bin/shade-tree.mjs proxy …`) | Log shows directory fetched + verified against `<SIGNER>`, `source: fresh`, Proxy on `127.0.0.1:8888`. `SHADE_TREE_DIR_SIGNER` **must** be set in fleet mode. | Ctrl-C. |
| 4.3 | **T-DEPLOY-1 acceptance A** | laptop | `curl -sx http://127.0.0.1:8888 "https://api.ipify.org?format=json"` | Returns `{"ip":"<D1_IP>"}` — the gateway's IP, not the laptop's, not a Tor exit. On droplet-1 `journalctl -u shade-tree-gateway` shows a `PASS egress->api.ipify.org:443 …` line. Save both to `golive/accept-1a.txt`. | See `docs/INCIDENT.md` #6 (mass-DROP): `root-not-recent`/`wrong-group-root` = members.json/epoch/slots mismatch — confirm `SHADE_TREE_EPOCH_SECONDS=120`, `SHADE_TREE_SLOTS=8`, `SHADE_TREE_RLN_IDENTIFIER=1` on both sides and identical `group/members.json`. |
| 4.4 | **T-DEPLOY-1 acceptance B** | laptop | `curl -s --socks5-hostname 127.0.0.1:9260 http://<BN_ONION>/directory \| jq '.gateways[].onion'` and `shade-tree verify-directory <saved.json> --signer <SIGNER>` (Rust default binary) | Lists `<GW1_ONION>`; verify prints ok. Save to `golive/accept-1b.json`. | — |
| 4.5 | Privacy check | droplet-1 | `journalctl -u shade-tree-gateway --no-pager \| grep -c "<laptop-public-ip>"` | `0`. | If non-zero: STOP, treat as incident; the rendezvous path is not being used. |
| 4.6 | Rust client — derive inputs | laptop | `mkdir -p golive/rust && shade-tree identity --limit "$SHADE_TREE_LIMIT" --out golive/rust/identity.json` | Writes `golive/rust/identity.json` (`{identitySecret, leaf, limit?}`) mode 0600 using the exact enrolled tier. Use the operator's full `group/members.json`; `identity.json` is secret material, so keep it in gitignored/local space and delete it after. | Delete `golive/rust/identity.json`. |
| 4.7 | Rust client — live egress over embedded Tor | laptop | `./target/release/shade-tree egress --bootnode-onion <BN_ONION> --signer <SIGNER> --identity golive/rust/identity.json --members group/members.json --target api.ipify.org:443 --slot-cursor golive/rust/slot.cursor` (needs the `--features live` build) | Reports gateway ACCEPT; droplet-1 logs a second `PASS egress->api.ipify.org:443`. Save output as `golive/accept-1c.txt`. This step deliberately tests the one-shot `egress` command; the same live binary also ships the loopback HTTP CONNECT `proxy` documented in `crates/INSTALL.md`. | Retry with `--directory <saved-directory.json> --signer <SIGNER>` (file transport) to separate discovery from dial problems. |
| 4.8 | Negative check | laptop | Run 4.2 with a secret from `shade-tree enroll --commitment-only` that was never added to `members.json` | Client cannot build a proof / gateway DROPs; nothing egresses (verification matrix row 2, `docs/DEPLOY.md`). | — |
| 4.9 | Uptime probe (external view) | laptop | `SHADE_TREE_BOOTNODE_ONION=<BN_ONION> SHADE_TREE_DIR_SIGNER=<SIGNER> SHADE_TREE_TOR_PORT=9260 node scripts/uptime-probe.mjs; echo $?` | Exit 0, `signerOk` (`monitoring/UPTIME.md`). | — |

---

## Phase 5 — Gateway-2, different provider / region / ASN (droplet-2) `[RECEIPT T-DEPLOY-2]`

The repo's tofu module is DigitalOcean-only (`bootnode/deploy/terraform/main.tf`); for a
non-DO provider create the box by hand/that provider's tooling and run `bootstrap.sh` directly
(it is provider-agnostic; needs fresh Ubuntu 24.04, root, outbound internet). GAP-5.

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 5.1 | Create droplet-2 `[HUMAN]` `[FUNDS]` | laptop | Provider console/CLI: Ubuntu 24.04, 1 vCPU/1 GB is enough, SSH key only, firewall inbound 22 only, different region than droplet-1. | `<D2_IP>`; `curl -s https://ipinfo.io/<D2_IP>/org` shows a **different AS** than `curl -s https://ipinfo.io/<D1_IP>/org`. Save both to `golive/asn.txt`. | Destroy the box at the provider. |
| 5.2 | Bootstrap (gateway role) | droplet-2 | `ssh root@<D2_IP>`; `curl -fsSL https://raw.githubusercontent.com/dmarzzz/shade-tree-node/<REF>/bootnode/deploy/bootstrap.sh \| sudo SHADE_TREE_REF=<REF> bash` | Banner prints a local bootnode onion (unused below), signer, and `<GW2_ONION>`. Record `<GW2_ONION>`. | Re-run (idempotent). |
| 5.3 | Point heartbeat at Elder Tree 1 | droplet-2 | Bootstrap the box with `SHADE_TREE_BOOTNODE_ONION=<BN_ONION>` and the pinned `SHADE_TREE_BOOTNODE_SIGNER=<SIGNER>` as shown in `docs/OPERATOR.md` section 2; optionally set `SHADE_TREE_GATEWAY_REGION=<eu\|na>`. | `journalctl -u shade-tree-heartbeat -o cat` includes `"msg":"heartbeat accepted"`; no local Elder Tree unit is installed. | Re-run bootstrap with the intended Elder Tree values. |
| 5.4 | Local bootnode on droplet-2 `[HUMAN]` | droplet-2 | Either (a) `systemctl disable --now shade-tree-bootnode` (single-bootnode fleet), or (b) keep it and federate: on **both** boxes add `Environment=SHADE_TREE_BOOTNODE_PEERS=<other-bootnode-onion>` + `Environment=SHADE_TREE_BOOTNODE_ONION=<own-bootnode-onion>` to `shade-tree-bootnode.service`, reload, restart (`docs/BOOTNODE.md` "Federation"). | (a) unit inactive; (b) both `/directory` converge on the same 2 gateways within `SHADE_TREE_BOOTNODE_FED_INTERVAL` (60 s). Prefer (a) for the first go-live; (b) is the SLO 2.2 path to redundancy. | (a) `systemctl enable --now shade-tree-bootnode`; (b) remove the two vars. |
| 5.5 | Metrics on node 2 | droplet-2 | Run the two checks from 2.5 against `127.0.0.1:9101`. | `/readyz` is `ok`; `/metrics` is available only on loopback. | Restart `shade-tree-gateway`. |
| 5.6 | If Phase 3 was done: stake/authorize node 2 `[FUNDS]` | laptop to chain / droplet-2 | Either reuse the same operator (one stake backs many onions; see `docs/BOOTNODE.md` "The onion is never on chain"): add `SHADE_TREE_GW_OPERATOR_KEY` (or `SHADE_TREE_GW_OPERATOR` plus `SHADE_TREE_GW_OPERATOR_SIG`) to droplet-2's heartbeat unit; or stake a second operator via 3.4. | The `heartbeat accepted` JSON record has `"staked":true`. | Remove the variable; the entry expires from a stake-admission Elder Tree. |
| 5.7 | **T-DEPLOY-2 acceptance A** | laptop | `curl -s --socks5-hostname 127.0.0.1:9260 http://<BN_ONION>/directory \| jq '.gateways \| length'` | `2` (`<GW1_ONION>` and `<GW2_ONION>`). Save as `golive/directory-2gw.json`. `FleetTooSmall` (`monitoring/alerts.yml`) clears. | — |
| 5.8 | **T-DEPLOY-2 acceptance B (rotation)** | laptop | With the 4.2 client running (smooth weighted round-robin is the default, `docs/CONFIG.md` T-FEAT-4): `for i in $(seq 1 8); do curl -sx http://127.0.0.1:8888 https://api.ipify.org; echo; done \| sort \| uniq -c` | Both `<D1_IP>` and `<D2_IP>` appear (for equal weights, 4/4). Save as `golive/accept-2b.txt`. Note: 8 requests = one epoch's `SHADE_TREE_SLOTS=8` budget; wait 120 s before more. | If only one IP, inspect `shade_tree_gateway_tunnels_total` and temporarily enable `debug` logs; check whether the Proxy health cache marked node 2 down after dial failures. |
| 5.9 | Rust rotation | laptop | Run 4.7 four times with the same `--slot-cursor` and `--health-cache golive/rust/health.json` | Accepts land on both gateways (see each box's gateway journal). | — |
| 5.10 | Both-ends AS spread receipt | laptop | `golive/asn.txt` + `golive/accept-2b.txt` | Two ASNs, two egress IPs, one client. This is the T-DEPLOY-2 accept. | — |

---

## Phase 6 — Monitoring, SLO baseline, backup of onion identities

| # | Step | Machine | Command | Receipt | Rollback |
|---|---|---|---|---|---|
| 6.1 | Scrape via SSH tunnels | laptop (or a monitoring host) | `ssh -N -L 19100:127.0.0.1:9100 root@<D1_IP> & ssh -N -L 19101:127.0.0.1:9101 root@<D1_IP> & ssh -N -L 19102:127.0.0.1:9101 root@<D2_IP> &`; use the Prometheus jobs in `monitoring/README.md`; load `monitoring/alerts.yml`; run `promtool check rules monitoring/alerts.yml`. | `up{job="shade-tree-bootnode"}==1`, `up{job="shade-tree-gateway"}==1` for both nodes, and `shade_tree_bootnode_live_gateways == 2`. The Elder Tree protocol port `8877` is never scraped. | Kill the tunnels; nothing on the droplets changes. |
| 6.2 | Dashboard | monitoring host | Import `monitoring/grafana-dashboard.json` (`monitoring/README.md` "Import the dashboard"). | Fleet-size, pass/drop, verify p95 panels populated. | — |
| 6.3 | External uptime probe on a schedule `[HUMAN]` | any tor-capable runner | cron/hosted: `SHADE_TREE_BOOTNODE_ONION=<BN_ONION> SHADE_TREE_DIR_SIGNER=<SIGNER> node scripts/uptime-probe.mjs` every 5 min (`monitoring/UPTIME.md`) | Exit codes logged. This is the SLI source for SLO 2.2/2.3. GAP-8: no scheduler config ships; the runner is the operator's. | Remove the cron. |
| 6.4 | SLO baseline snapshot | laptop | Record at go-live+1h and +24h: `shade_tree_gateway_tunnels_total` by `result/reason`, `histogram_quantile(0.95, rate(shade_tree_gateway_verify_seconds_bucket[5m]))`, `shade_tree_bootnode_live_gateways`, uptime-probe success ratio | Write to `golive/slo-baseline-<date>.md`. `docs/SLO.md` targets are `[NEEDS DATA]`; this is the first data point for the 30-day recalibration (`docs/SLO.md` section 5, `monitoring/README.md` "Calibration note"). | n/a |
| 6.5 | Status page (optional) | laptop | `web/status-server.mjs` (T-WEB-1) pointed at `<BN_ONION>` + `<SIGNER>` | Fleet size 2, onions truncated to 16 chars. | — |
| 6.6 | **Backup onion identities + signer** | droplet-1 and droplet-2 | `export SHADE_TREE_BACKUP_PASSPHRASE='<long unique>'; sudo -E -u shade-tree node /opt/shade-tree/bin/shade-tree.mjs backup /opt/shade-tree/deploy-state /opt/shade-tree/deploy-state/shade-tree-keys-$(hostname)-$(date +%F).shade-tree-backup` then `scp` the `.shade-tree-backup` off-box; delete the on-box copy | One `.shade-tree-backup` per box, stored encrypted-at-rest off-box; passphrase in the password manager, **separately** (`docs/BACKUP.md`). Covers `identity.local.json`, `hs_ed25519_secret_key` (bootnode-hs + gateway-hs), `bootnode-signer.key`. Operator EOA key is NOT included (wallet backup). | — |
| 6.7 | Prove restore | laptop | `SHADE_TREE_BACKUP_PASSPHRASE=… shade-tree restore <file>.shade-tree-backup /tmp-scratch/restore-test && node scripts/onion-identity.mjs derive /tmp-scratch/restore-test/gateway-hs/hs_ed25519_secret_key` | Prints exactly `<GW1_ONION>` (resp. `<GW2_ONION>`); repeat for `bootnode-hs` → `<BN_ONION>` (`docs/ONION-IDENTITY.md` "verify-before-cutover"). Then `rm -rf` the scratch dir. | — |
| 6.8 | Systemd security check | both droplets | `systemd-analyze security shade-tree-gateway shade-tree-heartbeat shade-tree-bootnode` | Each ~2.x. | — |
| 6.9 | (Recommended) vanguards add-on `[HUMAN]` | both droplets | Per `docs/TOR-HARDENING.md` section 2 — external tool, own unit, tor `ControlPort` + cookie auth | Running. GAP-9: not scripted anywhere in this repo. | Stop the unit. |

---

## Phase 7 — Announce to members / rotate docs `[HUMAN]`

| # | Step | Machine | Command / action | Receipt | Rollback |
|---|---|---|---|---|---|
| 7.1 | Publish the fleet record | laptop (git) | Add a committed record of the NEW fleet's discovery inputs: `<BN_ONION>`, `<SIGNER>`, admission mode, `<GW_REGISTRY>` if any, ref deployed. Suggested home: `network/sepolia/README.md` "Bootnode" section + a `network/sepolia/bootnode.json {onion, signer, admission}` next to `contracts.json`/`directory.json` (`network/README.md` says `network/<name>/` is the canonical per-deployment record). GAP-10: no schema/file for a bootnode record exists yet. Also add `gatewayRegistry` to `contracts.json` if Phase 3 ran. Commit + push is a human git action. | PR merged. Never include the existing fleet's or laptop's IPs in the new record; onions of the NEW fleet are fine (they are the discovery handle). | Revert the commit. |
| 7.2 | Static fallback directory (cold path) | laptop | `shade-tree sign-directory <unsigned-list.json>` listing `<GW1_ONION>`,`<GW2_ONION>` with a **separate** static signer, or export the bootnode's signed `/directory` body as `network/sepolia/directory.bootnode.json` | Members can set `SHADE_TREE_DIRECTORY` + `SHADE_TREE_DIR_SIGNER` if the bootnode is dark (`docs/INCIDENT.md` #1 containment). | — |
| 7.3 | Member instructions | laptop | Update the member-facing docs to use a hidden `SHADE_TREE_SECRET` read followed by `shade-tree proxy --limit <exact-tier> --bootnode <BN_ONION> --dir-signer <SIGNER>` (JS), and the Rust `-live` `egress --bootnode-onion <BN_ONION> --signer <SIGNER> …`. Files: `docs/JOIN.md`, `docs/post/JOIN.md`, `docs/QUICKSTART.md` "Path A", `docs/post/RUN-A-GATEWAY.md`. | Docs name the new bootnode + signer only and never put a bearer secret in argv. | — |
| 7.4 | Release tag (optional) `[HUMAN]` | laptop | `git tag v<version> && git push origin v<version>` → `.github/workflows/release.yml` publishes `shade-tree-<version>-<target>` and `-live` assets | Release page has the assets + `.sha256`. Note the release header: artifacts are testnet-only until T-HARD-1. | Delete the tag/release. |
| 7.5 | Announce `[HUMAN]` | — | Message to members: bootnode onion + signer, the two client commands, "testnet-only artifacts" caveat (per 0.2), rate budget (`SHADE_TREE_SLOTS=8` per 120 s epoch), incident contact. Do not include droplet IPs; do not mention the existing fleet's onions/IPs. | Sent. | — |
| 7.6 | Backlog | laptop | Mark T-DEPLOY-1 / T-DEPLOY-2 done in `docs/SHIP-PLAN.md` with the receipt file names (owned by another agent — hand them this list). | — | — |

---

## Do-not list

1. **Never print, commit, or announce the droplet IP or onion of the existing live gateways** (agent-devops `egress` group / `anon_egress` class: `egress-01`, `egress-02`, `shade-tree-03`, and the older PoC gateway). This runbook deliberately contains none of them. Note: `network/sepolia/README.md`, `network/sepolia/directory.json` (`note` fields), `docs/DEPLOYMENT.md` "Live Tor round-trip", `docs/JOIN.md:26,34`, `scripts/run-client.sh:23-25`, `scripts/join.sh:28` already carry them — flagged under Contradictions for their owners; do not add more.
2. **Do not touch the existing gateways.** No `task provision`, no `tofu apply`, no ssh, no unit edits on `egress-01`/`egress-02`/`shade-tree-03`; do not re-sign or re-commit `network/sepolia/directory.json`'s gateway list; do not reuse their slash key/signer on the new boxes without an explicit human decision. Their `deploy/onchain-staked-fleet` branch + static signed directory stay live and independent.
3. **Do not run a blanket `tofu apply` in `~/agent-devops/tofu/environments/dev`** (`docs/DEPLOYMENT.md` "SAFETY: targeted applies only"). Use the repo's own `bootnode/deploy/terraform` for droplet-1.
4. **Do not paste private keys on a command line** (`docs/ONCHAIN-DEPLOY.md` section 3): keystore (`--account shade-tree-deployer`) or env only; `SHADE_TREE_BACKUP_PASSPHRASE` env only.
5. **Do not open 8877 / 8443 / 9101 to clearnet** — SSH-in only; metrics via SSH tunnel (`monitoring/README.md`).
6. **Do not regenerate the bootnode signer or the onion keys** after clients pin them (`docs/INCIDENT.md` #2, #4). Restores go through `docs/ONION-IDENTITY.md` verify-before-cutover.
7. **Do not clear an alert by weakening the gate** (`docs/SLO.md` section 5).
8. **Do not use `--broadcast` or spend funds unattended**; Phase 3 and every `[FUNDS]` row is a human action.
9. **Do not restart both gateways at once** once members are on the fleet (`bootnode/deploy/ROLLING-UPDATE.md`).

---

## Gaps found

- **GAP-1** — **CLOSED 2026-08-17**: droplet-1 = the idle June PoC box `anon-egress` (DO NYC1, bootnode + gateway-1); droplet-2 = agent-devops `shade-tree-gw-04` (DO SFO3, gateway-only). Both LIVE, stake admission on (`docs/GO-LIVE-LOG-2026-08-17.md`). No host named `anon-egress` exists in this repo or `~/agent-devops` (only the `anon_egress` firewall/role class covering `egress-01`, `egress-02`, `shade-tree-03`, plus an older PoC gateway referenced by IP in `docs/JOIN.md`/`scripts/run-client.sh`). SHIP-PLAN T-DEPLOY-1 should name the box(es) explicitly.
- **GAP-2** — **DONE 2026-08-17.** `GatewayRegistry` live on Sepolia `0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868` (block 11509783), recorded in `network/sepolia/contracts.json:contracts.gatewayRegistry` via `scripts/record-deploy.mjs:recordDeploy` (receipt `network/sepolia/gateway-registry-broadcast.json`). Was: `GatewayRegistry` is not deployed on Sepolia: `network/sepolia/contracts.json` has no `gatewayRegistry` key and `contracts/deployed.local.json` has none either. Phase 3 requires a live broadcast (`docs/ONCHAIN-DEPLOY.md` section 5) and a schema addition to `contracts.json`.
- **GAP-3** — **DONE 2026-08-17** (PR #8): `bootnode/deploy/bootstrap.sh:render_torrc` honours `SHADE_TREE_ENABLE_POW` (default `0`; per-HS line after each `HiddenServicePort`); Phase 4.0 is now `SHADE_TREE_ENABLE_POW=1` at bootstrap or a re-run. Was: `bootnode/deploy/bootstrap.sh` hard-codes `HiddenServicePoWDefensesEnabled 1` with no `SHADE_TREE_ENABLE_POW` tunable, while `docs/DEPLOYMENT.md` records that a Homebrew (`pow: no`) client tor could not connect to a PoW-enabled onion and the agent-devops role defaults `shade_tree_enable_pow: false`. Phase 4.0 is a manual torrc edit.
- **GAP-4** — **DONE 2026-08-17** (PR #9): `shade-tree identity [--limit <exact-tier>] [--out <p>]` (`bin/shade-tree.mjs:COMMANDS.identity` → `group/identity.mjs`, derivation `lib/identity-file.mjs`); Phase 4.6 = `shade-tree identity --limit "$SHADE_TREE_LIMIT" --out golive/rust/identity.json`. Was: No first-class command exports the Rust `--identity` file (`{identitySecret, leaf}`); only the harness helper `crates/shadenet-rln/interop/egress-derive.mjs` does, and it also writes a single-leaf `members.json` that must be ignored.
- **GAP-5** — (partially addressed 2026-08-17 — droplet-2 provisioned + bootstrapped via agent-devops tofu/ansible in another region; a second PROVIDER/ASN is still open: droplet-2 is provisioned via `~/agent-devops` OpenTofu as a plain box + `bootstrap.sh` gateway-only mode; still no second-provider IaC in this repo.) `bootnode/deploy/terraform` is DigitalOcean-only; the second-provider box in Phase 5 has no IaC in this repo (bootstrap.sh by hand). The `~/agent-devops` `shade_tree_gateway` role (T-DEPLOY-3) is the **legacy gateway-only** role (dedicated tor on 9250, HS dir `/var/lib/tor-shade-tree/hs`, default `shade_tree_git_ref: main`, no bootnode/heartbeat units), so it does not produce the bootnode-era topology this runbook needs.
- **GAP-6** — **DONE 2026-08-17** (PR #8): `SHADE_TREE_BOOTNODE_ONION=<onion>` = gateway-only mode (`bootstrap.sh:render_heartbeat_unit` / `WITH_BOOTNODE`; only tor + gateway + heartbeat, heartbeat announces to the remote bootnode; `SHADE_TREE_GATEWAY_REGION` passthrough; e2e matrix entry `gateway-only`). Phase 5.2–5.3 collapse to one command. Was: `bootstrap.sh` has no gateway-only mode / no `SHADE_TREE_BOOTNODE_ONION` input; every box gets its own bootnode and heartbeat points at it. Joining a remote bootnode is a manual unit edit (Phase 5.3–5.4).
- **GAP-7** — No Prometheus/Grafana host is provisioned by anything in the repo; scraping is via SSH tunnels per `monitoring/README.md`.
- **GAP-8** — **DONE 2026-08-17** (PR #11): `monitoring/uptime/shade-tree-uptime-probe.{service,timer}` (5 min), `monitoring/uptime/crontab.example`, `.github/workflows/uptime-probe.yml` (*/15, no-ops until repo vars are set); `monitoring/UPTIME.md` "Scheduling it". Was: `scripts/uptime-probe.mjs` has no shipped scheduler/cron/hosted-runner config.
- **GAP-9** — vanguards add-on (recommended in `docs/TOR-HARDENING.md` section 2) is not scripted.
- **GAP-10** — **DONE 2026-08-17** (PR #11): `network/sepolia/bootnode.json` (schema in `network/README.md`, validator `lib/network-record.mjs:validateBootnodeRecord`, consumed via `SHADE_TREE_NETWORK=<name>` / `applyNetworkEnv`; env still overrides). Filled with the live fleet by the go-live PR. Was: `network/<name>/` has no bootnode record file/schema (`onion`, `signer`, `admission`); the canonical per-network record (`network/README.md`) only covers contracts + static directory.
- **GAP-11** — **DONE** (loop-34/35): `docs/CEREMONY.md` exists; issue #6 explains why the ceremony is needed. Was: `docs/CEREMONY.md` did not exist at authoring time (being written by another agent); Phase 0.2 links to it by name.
- **GAP-12** — **DONE 2026-08-17** (PR #9): `shade-tree exit-gateway` / `shade-tree withdraw-gateway [--recipient]` / `shade-tree gateway-status` (`group/exit-gateway.mjs`, `--dry-run` prints calldata + eth_call, never broadcasts). Was: No `shade-tree` wrapper for gateway exit/withdraw (manual `cast`, `docs/OPERATOR.md` section 6) — the rollback for Phase 3.4.

## Contradictions in existing docs (for their owners; not fixed here)

> **Status 2026-08-17:** all bullets below were resolved by PR #10 (T-DOC-8), PR #9 (CLI.md) and PR #8 (PoW default now `0` on both sides; bootstrap ref → `main`). Kept for the audit trail.

- `network/sepolia/README.md:10-15` lists `StakedReputationSet 0x35719A47…98EC` (block 11274471) as live, but `network/sepolia/contracts.json` (`release: rln-v3`, block 11279842) says `0xdAE242AE…20FC` **supersedes** it; `docs/DEPLOYMENT.md:125` also cites the old address; `~/agent-devops/ansible/inventory/group_vars/egress.yml` uses the new one.
- `docs/DEPLOYMENT.md` "PoW capability mismatch" (client with `pow: no` cannot connect; fleet default `shade_tree_enable_pow: false`) vs `bootnode/deploy/bootstrap.sh` (`HiddenServicePoWDefensesEnabled 1`, unconditional) and `bootnode/deploy/README.md` "PoW … available and enabled".
- `docs/INCIDENT.md:40` and `:307-308` say bootnode persistence across restart is "not yet built (T-DEV-4)", but `docs/BOOTNODE.md` "Surviving a restart", `docs/CONFIG.md` (`SHADE_TREE_BOOTNODE_STORE`) and `bootstrap.sh` (sets `SHADE_TREE_BOOTNODE_STORE`) ship it. Same file `:104`, `:286`, `:309-310` says no cross-gateway replay defense (T-FEAT-12) while `docs/OPERATOR.md` section 5 documents T-FEAT-12 + T-FEAT-20.
- `docs/OPERATOR.md:185` "Backup — Manual for now (no backup tooling is shipped)" and `docs/TOR-HARDENING.md:128-131` ("manual `tar | gpg` … tracked as T-FEAT-15") vs `docs/BACKUP.md` (`shade-tree backup`/`shade-tree restore` shipped, listed in `bin/shade-tree.mjs`).
- `docs/CLI.md` command table omits `join`, `backup`, `restore`, which `bin/shade-tree.mjs` `COMMANDS` defines.
- `docs/post/RUN-A-GATEWAY.md:28` fetches `bootstrap.sh` from the `main` ref; `docs/OPERATOR.md`, `docs/QUICKSTART.md`, `bootnode/deploy/README.md`, and `bootstrap.sh` itself pin `feat/bootnode-and-productionize`.
- `docs/DEPLOYMENT.md` "Verification" (`SHADE_TREE_DIRECTORY` static-file client, `SHADE_TREE_TOR_PORT=9260`) vs `docs/QUICKSTART.md` (bootnode discovery, `--dir-signer`); both valid, but the member docs (`docs/JOIN.md`, `scripts/join.sh`) still describe the single-onion PoC path with a hard-coded gateway.
- `docs/DEPLOYMENT.md` topology says "Membership gating uses `members.json`" and the on-chain set is only economic; `docs/CONFIG.md` profile (b) and `docs/OPERATOR.md` describe `SHADE_TREE_GROUP_CONTRACT` on-chain root mode as available. Not contradictory in code (both modes exist), but the runbook keeps the bootstrap default (`members.json`) and says so.
- Public-IP / onion hygiene: `docs/JOIN.md:26,34`, `scripts/run-client.sh:23-25`, `scripts/join.sh:28`, `docs/DEPLOYMENT.md` "Live Tor round-trip" table, `network/sepolia/README.md` fleet table and `network/sepolia/directory.json` `note` fields all print existing-gateway IPs and/or onions, contrary to do-not item 1.
