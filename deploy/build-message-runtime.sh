#!/usr/bin/env bash
set -euo pipefail

# Компиляция ноды на сервере.
#
# Сборка идёт в официальном rust-образе той же дистрибуции, что и рантайм
# (bookworm), поэтому glibc бинаря совпадает с glibc рантайма.
#
# Тулчейн пинится тегом образа: RUST_IMAGE меняется осознанно, а не
# уезжает вместе с latest.
#
# build-essential/cmake/perl нужны не Rust'у, а aws-lc-sys — C-бэкенду
# rustls, который собирается из исходников.

BUILDER_IMAGE=${BUILDER_IMAGE:-trust-message-builder:1.97-bookworm}
SRC_DIR=${SRC_DIR:-/root/trust/Trust_me_deploy/tcp_message_server}
CARGO_CACHE=${CARGO_CACHE:-/root/.cargo-deploy}

# Сборочный образ строится один раз. Пересобрать принудительно —
# REBUILD_BUILDER=1 (нужно при смене версии тулчейна в builder.Dockerfile).
if [ "${REBUILD_BUILDER:-0}" = "1" ] || ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
  echo "building $BUILDER_IMAGE (это разово)"
  docker build -f "$SRC_DIR/deploy/builder.Dockerfile" -t "$BUILDER_IMAGE" "$SRC_DIR/deploy"
fi

docker run --rm \
  --user 0:0 \
  -v "$SRC_DIR:/work" \
  -v "$CARGO_CACHE:/cargo-home" \
  -e CARGO_HOME=/cargo-home \
  -w /work \
  "$BUILDER_IMAGE" \
  sh -euc '
    # Не login-шелл: `sh -lc` перечитывает /etc/profile и затирает PATH из
    # образа, после чего cargo не находится.
    export PATH="/usr/local/cargo/bin:$PATH"
    cargo build --release --locked
    install -m 0755 target/release/trust_message_tcp deploy/message-runtime/trust_message_tcp
  '
