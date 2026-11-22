# syntax=docker/dockerfile:1

FROM rust:1.99-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock Toasty.toml ./
COPY src ./src
COPY views ./views
COPY toasty ./toasty

ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=guard-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo build --locked --release --bin run \
    && install -D target/release/run /out/guard

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 guard \
    && useradd --uid 10001 --gid guard --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin guard \
    && install -d -o guard -g guard /data

COPY --from=build /out/guard /usr/local/bin/guard

ENV DATABASE_URL=sqlite:///data/guard.sqlite3 \
    LISTEN_ADDR=0.0.0.0:4444 \
    FORWARDAUTH_LISTEN_ADDR=0.0.0.0:4445

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 4444 4445
ENTRYPOINT ["/usr/local/bin/guard"]
