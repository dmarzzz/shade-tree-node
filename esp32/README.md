# A Shade Tree node on an ESP32

A second implementation of the Shade Tree node that runs on an ESP32: a proof-gated Tor
egress node on a $5 microcontroller with 4 MB of flash and no external RAM.

The reference node ([`crates/shadenet-node`](../crates/shadenet-node)) is a Rust binary built
on tokio that launches the C Tor daemon as a child process. Neither exists on
a microcontroller, so this project replaces both: `microtor` is a minimal Tor client and v3
onion-service host written for a 200 KB heap, and `shadenode` is the node logic on top of it.
The wire protocol is unchanged. An unmodified ShadeNet client cannot tell the difference.

## What has been shown to work

Measured on 2026-11-27 on an ESP32-D0WD-V3 rev 3.1 (2 cores, 240 MHz, 4 MB flash, no PSRAM)
over home Wi-Fi, against the live Tor network and Sepolia, with the unmodified released
client (`shadenet` 0.7.5, embedded Arti):

| | |
|---|---|
| HTTPS fetch through the board, invited member, one proof per tunnel | HTTP 200 |
| HTTPS fetch through the board, **staked** member proving against the live on-chain set, **session tickets** | book opened, ticket accepted, HTTP 200 |
| Listed in the public canopy | both Sepolia Elders answered `staked=true`; the signed directory carries the board's entry; the client verifies that directory |
| Double-spend of one proof slot | refused `over-spend-slashed`; the board recovered the secret, signed and sent the slash; confirmed on Sepolia (`0xcc3ee338…da55f4`) |
| RLN Groth16 proof check on the board (parse + pairing) | 1.1 s |
| Boot to published onion service | 83 to 156 s |
| Tor consensus verified on the board | 9 of 9 directory-authority signatures, 9,600 relays |
| 1 MB download through the board | about 60 KB/s |
| Free heap while serving / lowest seen | about 100 KB / 10 to 22 KB |
| Firmware image | 1.87 MB, 71 % of the 2.5 MB app partition |

The same crates run on a desktop (`crates/host`), where the onion service was also reached by a
stock C Tor client.

## Layout

```
crates/microtor    Tor client + v3 onion-service host and client, no async runtime, no C
crates/shadenode   the Shade Tree node: envelope checks, RLN verifier, sessions, spent set,
                   egress, heartbeat, chain roots, slashing, canary
crates/host        the same stack as a desktop process (development and interop tests)
firmware/          ESP-IDF std firmware: Wi-Fi, NVS keys and settings, flash scratch, console
tools/             generator for the directory-authority table
```

`firmware/README.md` covers the toolchain, build and flash commands and the on-device
benchmarks of the verifier.

## How it fits in 200 KB

- **One TLS link, one thread, no runtime.** All circuits ride one link to a guard. Tasks are
  plain futures polled in a loop; there are no wakers, timers or I/O driver.
- **Streaming directory parsing.** The 2.7 MB consensus is inflated and parsed a line at a
  time. Only about thirty relays are kept in RAM.
- **Flash as scratch space.** Finding the onion service's directories needs the ed25519
  identity of every HSDir (about 5,100). Their consensus entries go to a raw flash partition
  during the first pass and are read back in batches for the second.
- **A table-free pairing.** arkworks precomputes about 50 KB of line tables per verification
  key and 24 KB per proof. `shadenode::rln` computes each line as the Miller loop needs it
  (same arithmetic, checked against arkworks in the tests), so a verification allocates
  almost nothing.
- **Fixed-width Poseidon.** The reference crate links constants for every width; this links
  two.
- **Heavy jobs take turns.** A directory refresh, a descriptor build or fetch, an HTTPS
  request and a proof check never overlap.

## Run it on a desktop

```sh
cd esp32
cargo build -p shadenode-host
# a private node for an invited member set
target/debug/shadenode-host --state ./state --members members.json --epoch-seconds 120
# a node for the public Sepolia staking set
target/debug/shadenode-host --state ./state --epoch-seconds 60 \
    --contract 0x789967F0bDD7f3a96fb60F6D315e93F103b5680b \
    --rpc https://ethereum-sepolia-rpc.publicnode.com
```

It prints the onion address, then `ready: <onion>` once the descriptor is published. With the
`shadenet` client:

```sh
shadenet enroll --limit 8 --out identity.json --members members.json
shadenet fetch --onion <onion>:80 --identity identity.json --members members.json https://example.com/
```

`--epoch-seconds 120` matches what the client assumes when it is given `--members` and a
pinned node; the public network uses 60. A node refuses proofs for the epoch it booted in
(see below), so the first request can need a minute's patience.

## Run it on the board

```sh
cd esp32/firmware
. <path>/export-esp.sh                 # from `espup install`
cargo build --release
tools/flash.sh release
uv run --with pyserial tools/provision.py --set epoch=60 \
    --set contract=0x789967f0bdd7f3a96fb60f6d315e93f103b5680b \
    --set rpc=https://ethereum-sepolia-rpc.publicnode.com      # then prompts for Wi-Fi
```

The board prints `NODE onion=...` at boot and `NODE state=published` when clients can reach
it, then a `STATUS` line every 30 s. Settings live in NVS and are changed from the serial
console (`set <key> <value>`, `get`, `unset`), followed by `reboot`:

| Key | Meaning |
|---|---|
| `epoch` | RLN epoch length in seconds (60 on the public network) |
| `members`, `roots` | invited leaves (comma list); extra accepted roots |
| `contract`, `rpc` | staking contract and JSON-RPC endpoints: admit the on-chain set |
| `slash_key` | hex key that signs slashes and receives the reward (absent: dry run) |
| `elders`, `operator`, `operator_sig`, `weight`, `region` | announce to these Elder onions as this bonded operator |
| `allow`, `deny`, `bandwidth`, `conns` | egress policy, bytes per second, tunnels at once |
| `sessions`, `receipts`, `canary` | `off`/`on` switches (sessions default on, the others off) |

`drain on` / `drain off` asks clients to prefer other nodes without a reboot.

To be listed, the operator address needs the 0.001 ETH bond in the gateway registry
(`register()`), and `operator_sig` is its EIP-191 signature over
`Shade Tree gateway operator authorization\nonion=<onion>\noperator=<address>`.

## What matches the reference node

Checked byte for byte against the golden vectors ([`testdata/vectors.json`](../testdata/vectors.json)): onion
addresses, canonical announce and capability bytes (including the rate, session, sets and
draining fields) and their ed25519 signatures, the request and session signal hashes, ticket
commitments, book and spend digests, the session policy echo, receipts, and artifact ids.
Checked against a real proof made by the `shadenet-rln` prover: the verification order and every
refusal string of the envelope gate. Checked against the chain: the tree code reproduces the
staking contract's live root from its event log.

Implemented:

- the v4 envelope and reply lines, the version gate, target grammar and allow/deny policy,
  the public-address filter with every blocked range;
- invited member sets (root computed on the device) and the on-chain staked set;
- session tickets (`research-v1`, `research-v2`): books, the ticket state machine, per-book
  shaping, lifetimes and idle timeouts;
- the spent set with the 5 s exact-retry rule, over-spend detection and slashing on chain;
- the per-slot 40 MiB byte budget, per-nullifier and total tunnel caps, a global bandwidth
  cap;
- the Elder heartbeat with signed capabilities and operator authorization, the drain flag,
  and the reputation canary;
- signed liveness receipts.

## Where it still differs

- **On-chain roots are read, not replayed or proven.** The node reads the contract's
  `currentRoot` slot at the `finalized` tag every 30 s and keeps a superseded root for one
  freshness window. That is the reference node's `storageat` light mode: it trusts the RPC
  endpoint (over authenticated TLS). The default reference mode replays the event log and
  so also accepts every intermediate root between two polls; the `eth_getProof` mode
  verifies the read against the state root. Neither is implemented.
- **No spent-set file.** The reference node persists the spent set across restarts. This
  one refuses proofs for the epoch it booted in instead, which closes the same replay
  window without wearing flash; it means no tunnels for up to one epoch after a reboot.
- **Settings instead of the deployment record.** The reference front door downloads
  `deployment.json` and derives its settings; here they are set key by key.
- **Optional reference subsystems that are off by default and absent here:** the
  paid admission set and its 402 registrar, the fleet-wide nullifier tally, relay telemetry,
  the Prometheus endpoint (the `STATUS` line stands in), alert webhooks, the deny-list file
  and Tor's onion-service proof-of-work defence.
- **Relay TLS certificates are not checked.** Every hop is authenticated by the ntor handshake
  against a key from the signed consensus. The exception is the first directory fetch, which
  uses an unauthenticated one-hop circuit and only carries documents that are then verified.
- **Simplified path selection.** Middle hops and introduction points come from a
  bandwidth-weighted sample of 24 relays; there are no vanguards, family checks or guard
  rotation. That is weaker service-side anonymity than C Tor, on a node whose address every
  destination sees anyway.
- **Smaller limits on the device**: 4 tunnels, 4 ticket books, 8 KiB envelopes (64 KiB in
  the reference node), 256 remembered nullifiers. A full spent set refuses new proofs (`busy`) instead
  of forgetting old ones.
- **Proofs wait during a directory refresh.** About once an hour the consensus download holds
  the heavy-job slot for roughly a minute; a proof that arrives then is checked afterwards,
  which can exceed the client's 15 s acknowledgement timeout and send it to another node.

## Known weak spots

- **Memory is the tight resource.** Free heap has been seen as low as 10 KB (during a slash)
  and 22 KB (during boot). An allocation failure restarts the node, which costs a few
  minutes of reachability. Four busy tunnels at once have not been tried.
- **No long soak.** The longest continuous run so far is minutes, not days; the hourly
  consensus refresh while serving has not been observed on the board.
- **The canary's drain transition** is unit-tested; a real challenge has not been seen.
- **`research-v1` books idle out after 15 s**, and Tor sometimes takes longer than that to
  carry the first ticket; the client then proves again. That is the protocol's timing, but a
  slow node feels it more.

Research preview, like the network it talks to: unaudited, Sepolia testnet, not for real
funds or sensitive traffic. A listed node carries strangers' HTTPS connections out of its own
internet connection, and that connection's address is what destinations see; read
[`docs/HOME-NODE.md`](../docs/HOME-NODE.md) first.

## Licence

MIT, like the rest of the repository. The Miller loop in `shadenode::rln` follows `ark-ec`'s
BN model (MIT/Apache-2.0).
