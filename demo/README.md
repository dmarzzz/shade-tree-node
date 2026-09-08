# Demo

A tiny one-card demo of an anonymous request through the live fleet. It shows a staked
member's address + live on-chain staked status, then runs the **real** flow (RLN proof →
Tor → gateway → egress) with the steps animating, and reveals the gateway egress IP vs.
your own IP.

Staking is assumed done (the demo just uses an already-staked member). Everything else is
real: real Groth16 proof, real Tor transport, real fleet gateway, real Sepolia read.

## Run

This is an operator-provisioned presentation harness, not the fresh-clone quickstart.
`keys.local.json` is a private, untracked file supplied locally by the operator; alternatively,
provide the already-enrolled member secret through `SHADE_TREE_SECRET`. The harness also
requires `contracts/deployed.local.json` and a matching signed directory. Its bundled
Sepolia directory is historical pre-v4 material and must not be used as a current profile.
For a fresh checkout, use [QUICKSTART.md](../docs/QUICKSTART.md) instead.

```bash
# needs a local keys.local.json (the demo member) + the signed directory in the repo
SHADE_TREE_DEMO_WALLET=0x2ec9838Ea920Dc33D2771F4d29CBF6e7784929F9 \
SHADE_TREE_TOR_PORT=9260 \
npm run demo
# open the printed http://127.0.0.1:<port>
```

The server manages client Tor itself (spawns `scripts/start-tor-client.sh` if needed).
Env (all optional, sane local defaults):

| var | default |
|---|---|
| `SHADE_TREE_SECRET` | `keys.local.json[SHADE_TREE_DEMO_INDEX \|\| 0]` |
| `SHADE_TREE_DEMO_WALLET` | none (falls back to showing the membership commitment) |
| `SHADE_TREE_DIRECTORY` / `SHADE_TREE_DIR_SIGNER` | `network/sepolia/directory.json` + its signer |
| `SHADE_TREE_TOR_PORT` | `9260` |
| `SHADE_TREE_DEMO_PORT` | `8790` |

## Two things worth knowing before you demo

- **Warm-up:** a freshly started client Tor needs ~1–2 min before onions connect reliably;
  the button stays disabled (`establishing Tor circuit…`) until it's ready.
- **Epoch alignment / rate cap:** the member has 8 slots per 120s epoch (shown as 8 pips).
  The server starts "capped" and serves from the next clean epoch (`rate cap · resets in
  Ns`), and enforces ≤8 requests/epoch — this is deliberate: reusing a slot is exactly the
  over-spend the gateway slashes on, so the cap keeps the demo member safe *and* shows the
  rate limiter live. Start it a couple minutes before you present.
