# Shade Tree — one image for every role.
#
# The image ships the whole repo behind the unified `shade-tree` CLI, so a single
# build serves bootnode / gateway / client / keygen / doctor etc. purely by the
# subcommand you pass at `docker run`. That keeps the fleet homogeneous: same
# artifact everywhere, role chosen at runtime.

FROM node:24-bookworm-slim

WORKDIR /app

# Install deps in their own layer so editing source doesn't bust the npm cache.
# We copy only the manifests first; the lockfile makes `npm ci` reproducible.
# --omit=dev drops the toolchain (foundry/test-only deps) the runtime never uses.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source. .dockerignore keeps node_modules, tor state, keys, out/, etc. out
# so the layer stays small and no local secrets leak into the image.
COPY . .

# A writable spot for state that the code mints at runtime — chiefly the
# bootnode's ed25519 signer key (server.mjs writes SHADE_TREE_BOOTNODE_SIGNER_KEY if
# it's missing). The repo's default path lives under /app which is root-owned
# and thus unwritable to the non-root user; point SHADE_TREE_* at /data instead.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

# Never run the fleet as root. node:*-slim ships an unprivileged `node` (uid 1000).
USER node

# `shade-tree <command> [--flags]` — e.g. `docker run IMG bootnode --port 8877`.
# CMD makes a bare `docker run IMG` print the command list.
ENTRYPOINT ["node", "/app/packages/node/bin/shade-tree.mjs"]
CMD ["help"]
