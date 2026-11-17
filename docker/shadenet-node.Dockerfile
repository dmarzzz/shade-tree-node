# ShadeNet node image: Tor + the Rust `shadenet-node` binary (ADR 0014), run from a deployment
# record alone. One process serves tunnels, announces to every Elder Tree and exposes metrics.
#
#   docker run -d --name shadenet-node --restart unless-stopped \
#     -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
#     -v shadenet-node:/state ghcr.io/dmarzzz/shadenet-node:<version>
#
# No inbound ports: the node is an onion service. /state keeps the onion identity (the node's
# name), Tor state, the spent set and status.json across restarts.
#
# The binary is compiled on the build platform and cross-compiled to the target architecture
# with cargo-zigbuild (a static musl binary), so a multi-arch build never compiles Rust under
# QEMU; only the small runtime stage (Debian + Tor) runs under emulation.

FROM --platform=$BUILDPLATFORM rust:1.98-bookworm AS build

ARG TARGETARCH
ARG COMMIT=unknown

# cargo-zigbuild from PyPI bundles zig, the cross linker for the musl targets.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir cargo-zigbuild==0.20.1

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY circuits/rln/verification_key.json ./circuits/rln/verification_key.json
COPY testdata/zk-artifacts.lock.json testdata/vectors.json ./testdata/
COPY network ./network
COPY group/members.json ./group/members.json

# the musl target of the image's architecture; the commit stamps `shadenet-node --version`
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$target" \
    && SHADENET_BUILD_COMMIT="$COMMIT" cargo zigbuild --release --locked -p shadenet-node --target "$target" \
    && install -m 0755 "target/$target/release/shadenet-node" /shadenet-node

FROM debian:bookworm-slim

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="shadenet-node" \
      org.opencontainers.image.description="ShadeNet Shade Tree node: proof-gated Tor egress for agents (research preview)" \
      org.opencontainers.image.source="https://github.com/dmarzzz/shade-tree-node" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

# Stock Debian tor (0.4.9 ships the pow module, so SHADENET_POW=1 works), curl for `docker exec` health peeks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/tor/torrc \
    && useradd --system --uid 1000 --create-home --shell /usr/sbin/nologin shadenet \
    && mkdir -p /state && chown shadenet:shadenet /state

COPY --from=build /shadenet-node /usr/local/bin/shadenet-node

ENV SHADENET_STATE=/state \
    SHADENET_BUILD_COMMIT=${COMMIT}
VOLUME ["/state"]
USER shadenet

HEALTHCHECK --interval=60s --timeout=10s --start-period=240s --retries=3 \
  CMD ["shadenet-node", "status", "--quiet"]

ENTRYPOINT ["shadenet-node"]
CMD ["run"]
