# syntax=docker/dockerfile:1

FROM rust:1.99-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Keep dependencies in an ordinary image layer so the GHA exporter retains
# both Cargo's registry and compiled artifacts between fresh runners.
RUN mkdir -p src/bin \
    && touch src/lib.rs \
    && printf 'fn main() {}\n' > src/bin/run.rs \
    && printf 'fn main() {}\n' > src/bin/cli.rs \
    && cargo build --locked --release --bin run \
    && cargo clean --release --package guard

COPY Toasty.toml ./
COPY src ./src
COPY views ./views
COPY toasty ./toasty

RUN cargo build --locked --release --bin run \
    && install -D target/release/run /out/guard \
    && install -d -m 0750 /out/data

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

COPY --from=build /out/guard /usr/local/bin/guard
COPY --from=build --chown=10001:10001 /out/data /data

ENV DATABASE_URL=sqlite:///data/guard.sqlite3 \
    LISTEN_ADDR=0.0.0.0:4444 \
    FORWARDAUTH_LISTEN_ADDR=0.0.0.0:4445

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 4444 4445
ENTRYPOINT ["/usr/local/bin/guard"]
