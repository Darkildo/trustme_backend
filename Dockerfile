# syntax=docker/dockerfile:1.6

# Тот же тулчейн и та же дистрибуция, что у сборки прода
# (deploy/builder.Dockerfile): образ собирается тем компилятором, которым
# собран выкаченный бинарь, а не плавающим nightly. Версия меняется вместе
# с builder.Dockerfile и тегом BUILDER_IMAGE в build-message-runtime.sh.
FROM rust:1.97-slim-bookworm AS builder

# build-essential/cmake/perl нужны не Rust'у, а aws-lc-sys — C-бэкенду
# rustls, который собирается из исходников. В slim-образе их нет.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Компилятора схем в образе нет намеренно: protobuf собирается protox'ом,
# то есть самим cargo. Всё, что нужно сборке, приезжает с зависимостями.

# Pre-cache dependencies.
COPY Cargo.toml Cargo.lock build.rs ./
COPY schemas ./schemas
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo fetch --locked

# Build the real binary.
COPY . ./
RUN cargo build --release --locked


# Рантайм на той же дистрибуции, что и сборка (bookworm): бинарь
# слинкован с glibc сборочного образа и на более старой не запустится.
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
