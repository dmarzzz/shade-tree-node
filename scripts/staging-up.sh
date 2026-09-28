#!/usr/bin/env bash
# One command for the Sepolia staging contracts: deploy from network/sepolia-staging/economics.json,
# read back and source-verify, then start the staking smoke with real proofs. The smoke stops after
# the exit; rerun with --resume once the 24 h unbonding has passed to finish the withdraw.
#
#   scripts/staging-up.sh              deploy + verify + smoke (rehearse first: --fork)
#   scripts/staging-up.sh --fork       the same on an anvil fork of Sepolia; writes nothing
#   scripts/staging-up.sh --resume     finish the smoke's withdraw after unbonding
#
# Needs SOPS_AGE_KEY_FILE (agent-devops keys.txt) and, for Etherscan, ETHERSCAN_API_KEY. The deployer
# key is decrypted into this process's environment only and funds the smoke's placeholder bonds.
set -euo pipefail
cd "$(dirname "$0")/.."
SOPS_FILE="${SHADENET_DEPLOYER_SOPS:-$HOME/agent-devops/secrets/shadenet/deployer.sops.yml}"
RPC="${SHADE_TREE_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"

if [ "${1:-}" = "--fork" ]; then
  exec node scripts/deploy-contracts.mjs --network sepolia-staging --fork --rpc-url "$RPC"
fi

SHADE_TREE_DEPLOYER_KEY="0x$(sops -d --extract '["vault_shadenet_deployer_key"]' "$SOPS_FILE")"
export SHADE_TREE_DEPLOYER_KEY SHADE_TREE_SMOKE_KEY="$SHADE_TREE_DEPLOYER_KEY"

if [ "${1:-}" = "--resume" ]; then
  SET="$(node -e 'console.log(require("./network/sepolia-staging/deployment.json").admission.roots.staked.contract)')"
  exec node scripts/smoke-staking.mjs --rpc-url "$RPC" --contract "$SET" --resume
fi

node scripts/deploy-contracts.mjs --network sepolia-staging --broadcast --verify --rpc-url "$RPC"
SET="$(node -e 'console.log(require("./network/sepolia-staging/deployment.json").admission.roots.staked.contract)')"
node scripts/smoke-staking.mjs --rpc-url "$RPC" --contract "$SET"
