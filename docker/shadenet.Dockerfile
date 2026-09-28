# ShadeNet client image: the static `shadenet` live binary (embedded Tor + RLN prover).
#
# Built by release.yml from the already-verified, attested musl `-live` release binaries;
# nothing is compiled here. The build context holds them as image/<arch>/shadenet, so a
# multi-arch build needs no emulation. Published as ghcr.io/dmarzzz/shadenet:<version>.
#
#   docker run --rm ghcr.io/dmarzzz/shadenet:<version> --help
#
# The proxy binds loopback. Share its network namespace with the agent container
# (compose `network_mode: service:shadenet`) rather than publishing a port.

# distroless static, nonroot (uid 65532); includes CA roots for chain RPC over HTTPS.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="shadenet" \
      org.opencontainers.image.description="ShadeNet proof-gated Tor egress client (research preview)" \
      org.opencontainers.image.source="https://github.com/dmarzzz/shade-tree-node" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=0755 image/${TARGETARCH}/shadenet /usr/local/bin/shadenet

# Arti state and cache, and the member identity, live under HOME; mount a volume to keep
# them across restarts.
ENV HOME=/home/nonroot
VOLUME ["/home/nonroot"]
USER nonroot

ENTRYPOINT ["/usr/local/bin/shadenet"]
CMD ["--help"]
