#!/bin/sh
# Установка ноды TrustMe одной командой (docs/tmnode.md).
#
#   curl -fsSL https://raw.githubusercontent.com/Darkildo/trustme_backend/stable/deploy/install.sh \
#     | sudo sh -s -- install --public-host 203.0.113.10 --with-turn
#
# или, по команде из админки:
#
#   … | sudo sh -s -- enroll --url https://admin.example.org --token tme_…
#
# Что делает: ставит Docker (apt), если его нет; скачивает tmnode нужной
# версии из GitHub Releases и сверяет SHA-256; запускает tmnode с
# переданными аргументами. Версию можно закрепить: TMNODE_VERSION=v0.6.0.
set -eu

REPO="Darkildo/trustme_backend"
VERSION="${TMNODE_VERSION:-latest}"
BIN="/usr/local/bin/tmnode"

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(id -u)" = "0" ] || fail "нужен root: запустите через sudo"
[ "$#" -gt 0 ] || fail "передайте команду tmnode: install … или enroll …"

case "$(uname -m)" in
    x86_64 | amd64) ARCH="x86_64" ;;
    aarch64 | arm64) ARCH="aarch64" ;;
    *) fail "архитектура $(uname -m) не поддерживается" ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 \
        || fail "Docker не найден, а apt-get нет: поставьте Docker сами и повторите"
    echo "Ставлю Docker (docker.io)…"
    DEBIAN_FRONTEND=noninteractive apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io curl ca-certificates
    systemctl enable --now docker
fi

if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Скачиваю tmnode ($VERSION, $ARCH)…"
curl -fsSL -o "$TMP/tmnode-$ARCH-linux" "$BASE/tmnode-$ARCH-linux"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$TMP" && grep " tmnode-$ARCH-linux\$" SHA256SUMS | sha256sum -c -) \
    || fail "контрольная сумма tmnode не сошлась"
install -m 0755 "$TMP/tmnode-$ARCH-linux" "$BIN"

exec "$BIN" "$@"
