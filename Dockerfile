# syntax=docker/dockerfile:1.6

FROM rustlang/rust:nightly-bullseye AS builder

WORKDIR /app

# Компилятора схем в образе нет намеренно: protobuf собирается protox'ом,
# то есть самим cargo. Всё, что нужно сборке, приезжает с зависимостями.

# Pre-cache dependencies.
COPY Cargo.toml Cargo.lock build.rs ./
COPY schemas ./schemas
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo fetch

# Build the real binary.
COPY . ./
RUN cargo build --release


FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 10001 -r -m -d /srv/trust-message trust

WORKDIR /srv/trust-message
RUN mkdir -p data \
    && chown trust:trust data

COPY --from=builder /app/target/release/trust_message_tcp /usr/local/bin/trust_message_tcp

USER trust

EXPOSE 5000 9000

ENV RUST_LOG=info

CMD ["trust_message_tcp"]
