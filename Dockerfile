# syntax=docker/dockerfile:1

FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/lore /lore

FROM debian:trixie-slim
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
