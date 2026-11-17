# the node a harness or dev script starts (adr 0014): SHADE_TREE_GATEWAY_CMD names a
# shadenet-node binary, or any command that reads the same SHADE_TREE_* variables; unset, the
# rust node is built from this checkout. source this file, then:
#   GATEWAY_CMD="$(shadenet_node_cmd "$REPO")"
shadenet_node_cmd() {
  if [ -n "${SHADE_TREE_GATEWAY_CMD:-}" ]; then
    printf '%s\n' "$SHADE_TREE_GATEWAY_CMD"
    return 0
  fi
  cargo build --locked -p shadenet-node --manifest-path "$1/Cargo.toml" >&2 || return 1
  printf '%s\n' "$1/target/debug/shadenet-node"
}
