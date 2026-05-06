# Minimal runtime image for paraloom-node.
#
# The CI release pipeline (.github/workflows/release.yml) builds the
# Linux amd64 binary natively on ubuntu-latest, then this Dockerfile
# embeds that *exact same* binary into the image. Two consequences
# matter:
#
#   1. The bytes inside the image are byte-for-byte identical to the
#      `paraloom-node-linux-amd64` artifact attached to the GitHub
#      Release. An operator who verifies the binary's SHA-256 against
#      `SHA256SUMS` is verifying the same code the container runs.
#
#   2. Image build is fast (~30s) because we don't rebuild from
#      source — the heavy lifting (~5–15 min for the Solana SDK +
#      RocksDB + arkworks dep tree) happens once in the Build job.
#
# Build context expectation: the workflow downloads the
# `paraloom-node-linux-amd64` artifact into ./paraloom-node-linux-amd64/
# before invoking docker/build-push-action.

FROM debian:bookworm-slim AS runtime

# Runtime-only system packages: TLS roots, libgcc and libstdc++ for
# the dynamically-linked C++ symbols rocksdb pulls in. Slim image
# (~80 MiB after layer dedup) without dragging in build toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        libgcc-s1 \
 && rm -rf /var/lib/apt/lists/*

# Non-root operating user. Validators write to /var/lib/paraloom (a
# bind-mounted host volume in production); the container should not
# need root for any normal operation.
RUN useradd --system --create-home --uid 1000 paraloom \
 && mkdir -p /var/lib/paraloom \
 && chown -R paraloom:paraloom /var/lib/paraloom

# The release workflow downloads the artifact into a directory of
# the same name; copy from there. If you run `docker build` locally
# you'll need to stage the binary at the same path.
COPY paraloom-node-linux-amd64/paraloom-node-linux-amd64 /usr/local/bin/paraloom-node
RUN chmod +x /usr/local/bin/paraloom-node

USER paraloom
WORKDIR /var/lib/paraloom

# Default ports (override at runtime as needed):
#   8080 — operational HTTP (/health, /ready, /metrics — see #67)
#   9000 — libp2p (TCP + QUIC share the port)
EXPOSE 8080 9000

ENTRYPOINT ["/usr/local/bin/paraloom-node"]
