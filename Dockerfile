# syntax=docker/dockerfile:1
#
# Base images are pinned by digest; see "Updating the pinned versions" in
# the README. The same image runs `lore proxy`, the built-in agents' egress
# proxy, in the compose stack.

FROM rust:1.100-trixie@sha256:e84068000361bf3d4a5ba2b7647f62893528b1eb9f847d7a23b493f5ce8ea254 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/lore /lore

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data lore \
    && mkdir /data && chown lore:lore /data
COPY --from=build /lore /usr/local/bin/lore
USER lore
ENV LORE_DATA_DIR=/data \
    LORE_BIND=0.0.0.0:8080 \
    LORE_TRUST_PROXY=on
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["lore", "healthcheck"]
ENTRYPOINT ["lore"]
