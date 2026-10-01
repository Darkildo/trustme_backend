#!/usr/bin/env bash
set -euo pipefail

# Восстановление ноды из архива backup-node.sh.
#
# Использование:
#   bash restore-node.sh /root/trust/backups/node-20260825-120000.tgz
#   DRY_RUN=1 bash restore-node.sh <архив>   # только проверить содержимое
#
# Скрипт не останавливает стек сам и отказывается работать при запущенной
# ноде: восстановление поверх живой базы порвало бы sled.

ARCHIVE=${1:?usage: restore-node.sh <archive.tgz>}
DEPLOY_DIR=${DEPLOY_DIR:-/root/trust/Trust_me_deploy}
DRY_RUN=${DRY_RUN:-0}

[ -f "$ARCHIVE" ] || { echo "no such archive: $ARCHIVE" >&2; exit 1; }

# Список пишется во временный файл, а не в `tar | head`: под pipefail
# закрытый head'ом пайп даёт tar'у SIGPIPE, и `set -e` обрывает скрипт.
listing=$(mktemp)
trap 'rm -f "$listing"' EXIT
tar tzf "$ARCHIVE" > "$listing"

echo "== содержимое архива ($(wc -l < "$listing") записей) =="
head -20 "$listing"
echo "..."

# Ключ ноды — единственное, потеря чего необратима: клиенты запиннуты на
# него, и новый ключ отрезает всех разом. Его наличие в архиве проверяется
# до того, как что-либо трогать.
if ! grep -qx '\.env' "$listing"; then
  echo "FATAL: в архиве нет .env — значит нет NODE_IDENTITY_KEY" >&2
  exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "dry-run: архив читается, .env на месте"
  exit 0
fi

running=$(docker ps --format '{{.Names}}' | grep -c '^message-service$' || true)
if [ "$running" != "0" ]; then
  echo "FATAL: message-service запущен. Остановите стек: docker compose down" >&2
  exit 1
fi

ts=$(date -u +%Y%m%d-%H%M%S)
if [ -d "$DEPLOY_DIR/data" ]; then
  mv "$DEPLOY_DIR/data" "$DEPLOY_DIR/data.before-restore-$ts"
  echo "прежние данные отодвинуты в data.before-restore-$ts"
fi

tar xzf "$ARCHIVE" -C "$DEPLOY_DIR" data .env
tar xzf "$ARCHIVE" -C /root/trust secrets

echo "restore ok. Поднимите стек и сверьте node_key в логе с тем, что раздан клиентам."
