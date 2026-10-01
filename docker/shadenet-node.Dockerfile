# ShadeNet node image: Tor + the JS node + its heartbeat, run from a deployment record alone.
#
#   docker run -d --name shadenet-node --restart unless-stopped \
#     -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
#     -v shadenet-node:/state ghcr.io/dmarzzz/shadenet-node:<version>
#
# No inbound ports: the node is an onion service. /state keeps the onion identity (the node's
# name), Tor state and the spent set across restarts; back it up with `shadenet-node backup`.
# Built by release.yml from the tagged checkout; nothing is compiled here.

FROM node:24-bookworm-slim

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="shadenet-node" \
      org.opencontainers.image.description="ShadeNet Shade Tree node: proof-gated Tor egress for agents (research preview)" \
      org.opencontainers.image.source="https://github.com/dmarzzz/shade-tree-node" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

# Stock Debian tor (no pow module: SHADENET_POW stays off), curl for `docker exec` health peeks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/tor/torrc

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY . .

# One unprivileged user runs tor and the node; /state is the only writable place.
RUN mkdir -p /state && chown node:node /state /app
ENV SHADENET_STATE=/state \
    SHADE_TREE_BUILD_COMMIT=${COMMIT} \
    NODE_ENV=production
VOLUME ["/state"]
USER node

HEALTHCHECK --interval=60s --timeout=10s --start-period=240s --retries=3 \
  CMD ["node", "/app/packages/node/bin/shadenet-node.mjs", "status", "--quiet"]

ENTRYPOINT ["node", "/app/packages/node/bin/shadenet-node.mjs"]
CMD ["run"]
