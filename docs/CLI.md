# shade-tree-node CLI

`shade-tree-node <command> [--flags] [args]`

One entrypoint for running Shade Tree nodes and the Elder Tree (`packages/node/bin/shade-tree.mjs`). Install it as `shade-tree-node` with `npm link` (uses the `bin` field in `package.json`), or run it directly with `node packages/node/bin/shade-tree.mjs <command>`.

`shade-tree` (without `-node`) is the Rust binary agents run; see [the Rust install guide](../crates/INSTALL.md). The two are separate commands so both can sit on one PATH. Commands the Rust binary also has (`run`, `proxy`, `enroll`, `identity`, `register-member`, `leaves`) are shown below with the Rust name. For JavaScript programs, use [`@shadenet/sdk`](../packages/sdk/README.md).

The public roles are short: a `proxy` runs beside an agent, a `node` provides egress, and the `elder` command runs the Elder Tree that signs the canopy directory. The older `client`, `gateway`, and `bootnode` commands remain exact aliases. `shim` also remains an alias for `proxy`.

For module-backed commands, every mapped `--flag` is a thin alias: it sets the matching `SHADE_TREE_*` environment variable, then runs the underlying module as a child with that environment. So flags and env vars are one-to-one and interchangeable, and a flag simply overrides whatever the environment already had. Mapped flags are accepted on any module command (setting env is harmless where unused). A flag the router does not know is passed through verbatim to the child module (e.g. `keygen --label`). `run` has its own deliberately narrow parser, documented below. `--help` / `-h` on any command prints its one-line help; `shade-tree help` lists all commands; `shade-tree version` prints the package version.

See `docs/CONFIG.md` for the full env-var reference and defaults.

## Run one process through Shade Tree

After `shade-tree proxy` has started the local proxy, `run` scopes standard proxy variables to
one child process:

```bash
shade-tree run -- hermes
shade-tree run -- curl https://api.ipify.org
shade-tree run --proxy http://127.0.0.1:8888 -- command arg
```

The command performs an initial TCP preflight before spawning the child and fails closed when it cannot connect.
It sets `HTTP_PROXY`, `HTTPS_PROXY`, and `WSS_PROXY` in upper- and lowercase, removes inherited
`ALL_PROXY`, and replaces ambient `NO_PROXY` with
`127.0.0.1,localhost,::1,host.docker.internal` plus values supplied through `--no-proxy` or
`SHADE_TREE_NO_PROXY`. A wildcard bypass is rejected. The wrapper does not continuously enforce
proxy use after the child starts. The current shell is unchanged. `run` accepts
only `--proxy`, `--no-proxy`, and `--check-timeout-ms` before the required `--`; everything after
that separator is the child command and its arguments. Software that ignores standard proxy
environment variables must be configured explicitly for the local HTTP CONNECT proxy.

## Commands

Examples that send a transaction assume the key was first loaded with a hidden prompt, for
example `read -s SHADE_TREE_REGISTER_KEY`. The one-shot
`SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree …` form keeps its value out of
argv and shell history; clear the shell variable with `unset SHADE_TREE_REGISTER_KEY` afterward.

| Command | Script | What it does | Example |
|---|---|---|---|
| `run` | built into the CLI | Run one proxy-aware child with process-scoped Shade Tree routing. Refuses to spawn if the local proxy is unavailable. | `shade-tree run -- hermes` |
| `join` | `group/join.mjs` | Guided front door. `shade-tree-node join [member] [label]` self-enrolls a member (secret on stderr, commitment + next commands on stdout); `shade-tree-node join node [hsDir]` mints an onion identity and prints the operator's next commands. `gateway` remains an input alias. Composes `enroll` / `keygen`; never reimplements crypto. | `shade-tree-node join` / `shade-tree-node join node tor/hs` |
| `keygen` | `packages/node/bootnode/keygen.mjs` | Mint an onion identity: a Tor v3 hidden-service key plus the announce-signing seed. Writes `hs_ed25519_secret_key`, `hs_ed25519_public_key`, `hostname`, and `identity.local.json` into `<hsDir>`. Refuses to overwrite any identity file; `--force` is only for intentional rotation. | `shade-tree-node keygen tor/hs --label node-1` |
| `elder` | `packages/node/bootnode/server.mjs` | Run the Elder Tree as an onion service. It verifies node announcements and serves the signed canopy directory. Long-running. | `shade-tree-node elder --port 8877 --admission stake --gateway-registry 0xReg --rpc-url https://rpc.example` |
| `bootnode` | `packages/node/bootnode/server.mjs` | Legacy alias for `elder`. | `shade-tree-node bootnode --port 8877` |
| `heartbeat` | `packages/node/bootnode/heartbeat.mjs` | Keep this node announced to the Elder. Long-running. For a staked Elder, load `SHADE_TREE_GW_OPERATOR_KEY` through a hidden prompt or use a precomputed operator address/signature pair. | `shade-tree-node heartbeat --bootnode <onion> --identity tor/hs-gateway/identity.local.json` |
| `enroll` | `group/enroll.mjs` | Generate a member identity locally and print its secret + commitment (the secret never leaves the machine). | `shade-tree enroll alice --commitment-only` |
| `identity` | `group/identity.mjs` | Export the **Rust client's `--identity` file** `{identitySecret, leaf}` from your member secret (same derivation as the JS client, `packages/node/lib/identity-file.mjs` → `packages/node/lib/rln.mjs`; `leaf` is your `members.json` entry). Secret from `--secret-file` > `SHADE_TREE_SECRET` (`--secret`) > `./.secret`. Stdout = the JSON only; `--out <path>` writes it mode 0600 instead. The public leaf is echoed on stderr, never the secret. Derive with the exact member `SHADE_TREE_LIMIT`; a non-default tier produces a different leaf. | `shade-tree identity --secret-file ./.secret --limit 32 --out identity.json` |
| `register-member` | `group/register-onchain.mjs` | Stake a self-enrolled member commitment into `StakedReputationSet` (posts the tier's bond). `--limit N` (or `SHADE_TREE_LIMIT`) is the reputation tier the leaf was enrolled at (`enroll --limit N`); default 8. The rln-v4 set records it and charges `bondFor(N)`; an rln-v3 set admits only 8. A non-loopback RPC requires `SHADE_TREE_REGISTER_KEY`. | `SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree register-member 0xCOMMITMENT --limit 32 --rpc-url https://rpc.example --group-contract 0xSet` |
| `pay` | `group/pay.mjs` | **Buy a membership leaf over HTTP 402** (T-FEAT-7): fetch the operator's quote from the registrar on the bootnode onion (`:8878`, over Tor), sign an EIP-3009 `TransferWithAuthorization` for the stablecoin with the **buyer** wallet (holds the coin, needs **no gas token**; the operator submits and pays gas), POST it, and print `settleTx` / `insertTx` / `leafIndex` / `root` once the operator has inserted your commitment into `PaidAccessSet`. `--protocol x402` (default) or `mpp`; `--limit 8\|32` (tier; default 8); registrar via the v4 operator's `--bootnode <onion>` (+ `--registrar-port`, default 8878) or `--registrar-url http://…` (no Tor); buyer key `--key-file <path>` / `--account <keystore.json>` (`SHADE_TREE_PAY_PASSPHRASE`) / `SHADE_TREE_PAY_KEY`; commitment `--commitment <dec>` or derived from your member secret like `identity` (`--secret-file` / `SHADE_TREE_SECRET` / `./.secret`) at `--limit`. `--dry-run` prints the challenge + the exact authorization it would sign and signs nothing; `--json` for machine output. Prints the Layer-0 advice (the transfer is public: pay from a fresh address). The checked-in Sepolia registrar is pre-v4 history, not a current payment endpoint. | `shade-tree-node pay --bootnode <v4-bootnode.onion> --limit 8 --protocol mpp --key-file buyer.key --secret-file ./.secret` |
| `leaves` | `group/leaves.mjs` | Export an ON-CHAIN set's ordered leaves as a `members.json` document (`{ version: 2, members: [leaf, …] }`, slashed/exited slots written as the tree ZERO so the root matches). This is the bridge for the **Rust client**, whose `shade-tree egress --members <f>` reads only that file (T-FEAT-7). Rebuilds the tree from the contract's event log exactly as the gateway does (`packages/node/lib/root-provider.mjs`). Contract: `--contract` > `SHADE_TREE_PAID_ACCESS_CONTRACT` > first `SHADE_TREE_GROUP_CONTRACT`. Stdout = the JSON only; `--out <path>` writes it instead. Nothing secret involved. | `shade-tree leaves --contract 0xPaid --rpc-url https://rpc.example --out members.json` |
| `register-gateway` | `group/register-gateway.mjs` | Stake a gateway operator bond into `GatewayRegistry` (binds to the operator address). A non-loopback RPC requires `SHADE_TREE_REGISTER_KEY`. | `SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree register-gateway --gateway-registry 0xReg --rpc-url https://rpc.example` |
| `exit-gateway` | `group/exit-gateway.mjs exit` | Operator-side exit half of `GatewayRegistry` (rollback of `register-gateway`): call `initiateExit()`, leave the active set, start the `UNBONDING` clock, and stay slashable until it elapses. Reads state first and refuses what would revert (`NotStaked`, second call = no-op). `--dry-run` prints target + calldata + an `eth_call` simulation and never broadcasts. Signer: `--key-file` / `--account` (Foundry keystore, `SHADE_TREE_KEYSTORE_PASSWORD`) / `--keystore` / `SHADE_TREE_REGISTER_KEY`; never on argv. | `shade-tree-node exit-gateway --gateway-registry 0xReg --rpc-url https://rpc.example --account shade-tree-operator --dry-run` |
| `withdraw-gateway` | `group/exit-gateway.mjs withdraw` | After `UNBONDING`, call `withdraw(recipient)` to reclaim the bond (`--recipient`, default the operator address). Refuses `NotStaked` / `NotExiting` / `StillBonded` (prints the withdrawable time). Same `--dry-run` and signer options as `exit-gateway`. | `shade-tree-node withdraw-gateway --recipient 0xCold --gateway-registry 0xReg --rpc-url https://rpc.example --account shade-tree-operator` |
| `gateway-status` | `group/exit-gateway.mjs status` | Read-only: an operator's stake state (`staked (active)` / `exiting` / `not staked`), `BOND`, `UNBONDING`, `withdrawableAt` and chain time. Needs no key: `--operator 0x…`. | `shade-tree-node gateway-status --operator 0xOp --gateway-registry 0xReg --rpc-url https://rpc.example` |
| `sign-directory` | `group/sign-directory.mjs` | Sign a static fleet directory for offline discovery; with no args mints example keys + file. | `shade-tree-node sign-directory unsigned.json` |
| `node` | `packages/node/gateway/gateway.mjs` | Run an access-gated egress node (Tor onion, `:443` metadata-only tunnel). Long-running. `--admit invited[,staked][,paid]` selects accepted membership paths. The default is `invited`. | `shade-tree-node node --admit invited,staked,paid --group-contract 0xSet --paid-access-contract 0xPaid --rpc-url https://rpc.example` |
| `gateway` | `packages/node/gateway/gateway.mjs` | Legacy alias for `node`. | `shade-tree-node gateway --admit invited` |
| `proxy` | `packages/node/client/shim.mjs` | Run the local HTTP-CONNECT proxy. Long-running. It finds the set holding your leaf, creates proofs, and selects nodes whose signed policy admits that leaf source. Load the bearer secret through `SHADE_TREE_SECRET`, not argv. | `shade-tree proxy --bootnode <v4-elder.onion> --dir-signer <v4-signer-hex>` |
| `client` | `packages/node/client/shim.mjs` | Legacy alias for `proxy`. | `shade-tree-node client --onion <onion>` |
| `shim` | `packages/node/client/shim.mjs` | Legacy alias for `proxy`. | `shade-tree-node shim --onion <onion>` |
| `doctor` | `scripts/doctor.mjs` | Check the local setup (node, tor, keys, deps). | `shade-tree-node doctor` |
| `record-deploy` | `scripts/record-deploy.mjs` | Record a broadcast contract deploy (address + tx + block) into `network/<name>/contracts.json` from Foundry's `run-latest.json` or explicit flags; never touches a chain. | `shade-tree-node record-deploy --network <current-v4-network> --from-broadcast broadcast/DeployRegistry.s.sol/<chain-id>/run-latest.json` |
| `backup` | `scripts/backup.mjs backup` | Encrypt and back up secret key material (onion seeds + signer key) from a directory into one file. Passphrase only via `SHADE_TREE_BACKUP_PASSPHRASE` (never argv). See `docs/BACKUP.md`. | `SHADE_TREE_BACKUP_PASSPHRASE=… shade-tree-node backup deploy-state keys.shade-tree-backup` |
| `restore` | `scripts/backup.mjs restore` | Restore an encrypted key backup into a directory (`--force` to overwrite). Passphrase via `SHADE_TREE_BACKUP_PASSPHRASE`. | `SHADE_TREE_BACKUP_PASSPHRASE=… shade-tree-node restore keys.shade-tree-backup deploy-state --force` |

`keygen` takes a positional `<hsDir>` plus `--label` and an intentional-rotation `--force`; `join` takes an optional role (`member` | `node`, with `gateway` as an alias) and a label / `<hsDir>`; `register-member` takes a positional `<commitment>` (`--limit` is env-mapped to `SHADE_TREE_LIMIT`, which it reads); `sign-directory` takes an optional positional unsigned-list path; `backup` / `restore` take `<src> <dest>` positionals. All other positionals are forwarded to the child module.

Module-parsed flags (passed through, not env-mapped): `identity --out --secret-file`; `leaves --contract --out --from-block`; `exit-gateway` / `withdraw-gateway` / `gateway-status` `--dry-run --recipient --key-file --account --keystore` (`--operator`, `--rpc-url`, `--gateway-registry`, `--register-key` are env-mapped as usual); `restore --force`; `keygen --label --force`; `join node --force`; `enroll --commitment-only`. `--limit` is env-mapped to `SHADE_TREE_LIMIT`; `enroll`, `join`, `identity`, `register-member`, `pay`, and the Proxy all read it.

## Flags

A mapped `--flag` sets exactly one `SHADE_TREE_*` env var (from `FLAG_ENV` in `packages/node/bin/shade-tree.mjs`). Mapped flags override the environment; command-specific flags are passed through to the child module.
`--secret` remains a compatibility flag but exposes the bearer value in process
arguments. Prefer a hidden shell read into `SHADE_TREE_SECRET` as shown in the
[agent guide](AGENT.md).

| Flag | Env var | Group |
|---|---|---|
| `--network` | `SHADE_TREE_NETWORK` | global (fills unset vars from `network/<name>/`; see `docs/CONFIG.md`) |
| `--rpc-url` | `SHADE_TREE_RPC_URL` | global |
| `--tor-host` | `SHADE_TREE_TOR_HOST` | global |
| `--tor-port` | `SHADE_TREE_TOR_PORT` | global |
| `--epoch-seconds` | `SHADE_TREE_EPOCH_SECONDS` | global |
| `--log-level` | `SHADE_TREE_LOG_LEVEL` | operator output (`debug\|info\|warn\|error\|off`) |
| `--log-format` | `SHADE_TREE_LOG_FORMAT` | operator output (`auto\|pretty\|text\|json`) |
| `--metrics-port` | `SHADE_TREE_METRICS_PORT` | local metrics for a long-running role; heartbeat remaps this to its dedicated variable |
| `--heartbeat-metrics-port` | `SHADE_TREE_HEARTBEAT_METRICS_PORT` | local heartbeat metrics |
| `--port` | `SHADE_TREE_BOOTNODE_PORT` | bootnode |
| `--gateway-port` | `SHADE_TREE_GATEWAY_PORT` | node backend mapped by Tor |
| `--admission` | `SHADE_TREE_BOOTNODE_ADMISSION` | bootnode |
| `--ttl` | `SHADE_TREE_BOOTNODE_TTL` | bootnode |
| `--signer-key` | `SHADE_TREE_BOOTNODE_SIGNER_KEY` | bootnode |
| `--stake-mode` | `SHADE_TREE_STAKE_MODE` | bootnode |
| `--gateway-registry` | `SHADE_TREE_GATEWAY_REGISTRY` | bootnode |
| `--stake-allowlist` | `SHADE_TREE_STAKE_ALLOWLIST` | bootnode |
| `--group-contract` | `SHADE_TREE_GROUP_CONTRACT` | gateway (comma list allowed, T-FEAT-7) / client leaf discovery |
| `--paid-access-contract` | `SHADE_TREE_PAID_ACCESS_CONTRACT` | gateway / client / `leaves` (T-FEAT-7) |
| `--admit` | `SHADE_TREE_ADMIT` | gateway (`invited[,staked][,paid]`; default `invited` = max-anon; T-FEAT-9) |
| `--roots` | `SHADE_TREE_ROOTS` | gateway (`static,onchain`; T-FEAT-7 spelling, DEPRECATED alias of `--admit`) |
| `--pay-protocols` | `SHADE_TREE_PAY_PROTOCOLS` | registrar / bootnode advert (`x402,mpp` subset; T-FEAT-9) |
| `--leaf-source` | `SHADE_TREE_LEAF_SOURCE` | client (`auto\|invited\|staked\|paid`; T-FEAT-9) |
| `--max-anon` | `SHADE_TREE_MAX_ANON` | client (bare flag ⇒ `true`: invited-only gateways; T-FEAT-9) |
| `--limit` | `SHADE_TREE_LIMIT` | enroll / join / Proxy / identity / register-member / pay (the member's exact tier) |
| `--root-provider` | `SHADE_TREE_ROOT_PROVIDER` | gateway |
| `--slash-key` | `SHADE_TREE_SLASH_KEY` | gateway |
| `--slash-contract` | `SHADE_TREE_SLASH_CONTRACT` | gateway |
| `--secret` | `SHADE_TREE_SECRET` | Proxy / identity / pay (compatibility only; prefer a hidden read or secret file) |
| `--onion` | `SHADE_TREE_ONION` | client |
| `--bootnode` | `SHADE_TREE_BOOTNODE_ONION` | Proxy / heartbeat / pay |
| `--directory` | `SHADE_TREE_DIRECTORY` | client |
| `--dir-signer` | `SHADE_TREE_DIR_SIGNER` | client |
| `--shim-port` | `SHADE_TREE_SHIM_PORT` | client |
| `--identity` | `SHADE_TREE_GW_IDENTITY` | heartbeat |
| `--weight` | `SHADE_TREE_GW_WEIGHT` | gateway announce / heartbeat |
| `--interval` | `SHADE_TREE_BOOTNODE_HEARTBEAT` | gateway announce / heartbeat |
| `--operator-key` | `SHADE_TREE_GW_OPERATOR_KEY` | gateway announce / heartbeat |
| `--operator` | `SHADE_TREE_GW_OPERATOR` | heartbeat / gateway status and exit tools |
| `--operator-sig` | `SHADE_TREE_GW_OPERATOR_SIG` | gateway announce / heartbeat |
| `--register-key` | `SHADE_TREE_REGISTER_KEY` | member/gateway registration and gateway exit tools; avoid argv |
| `--bond` | `SHADE_TREE_BOND` | member/gateway registration |

Operator shortcuts are handled before command dispatch: `--quiet` sets the log
level to `warn` unless `--log-level` is explicit, `--banner` sets
`SHADE_TREE_BANNER=always`, and `--no-banner` sets it to `never`. A banner is
never mixed into JSON logs. `auto` output uses pretty logs and one ASCII tree on
an interactive TTY, then JSON with no tree in systemd, CI, pipes, and files.

Some env vars have no mapped module flag and must be set directly: `SHADE_TREE_SLASH_RECEIVER`, `SHADE_TREE_MEMBERS_FILE`, `SHADE_TREE_PAID_MIN_LEAVES`, `SHADE_TREE_CONFIRMATIONS`, `SHADE_TREE_STAKE_CACHE_MS`, `SHADE_TREE_FRESHNESS_ROOTS`, `SHADE_TREE_FROM_BLOCK`, `SHADE_TREE_FROM_BLOCKS`, `SHADE_TREE_LOGS_CHUNK`, `SHADE_TREE_DIRECTORY_CACHE`, `SHADE_TREE_DIRECTORY_REFRESH_MS`, `SHADE_TREE_SOCKS_ISOLATION`, `SHADE_TREE_PAY_HTTP_TIMEOUT_MS`, `SHADE_TREE_SLOTS`, and `SHADE_TREE_RLN_IDENTIFIER`. `shade-tree run` also reads `SHADE_TREE_PROXY_URL`, `SHADE_TREE_NO_PROXY`, and `SHADE_TREE_PROXY_CHECK_TIMEOUT_MS`; its equivalent flags are handled by the runner's narrow parser. See `docs/CONFIG.md`.
