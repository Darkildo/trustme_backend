#!/usr/bin/env bash
set -euo pipefail

# Восстановление ноды из архива backup-node.sh.
#
# Использование:
#   bash restore-node.sh /root/trust/backups/node-20260825-120000.tgz
#   DRY_RUN=1 bash restore-node.sh <архив>   # только проверить содержимое
#
# DEPLOY_DIR и SECRETS_DIR — те же переменные и с теми же умолчаниями, что
# у backup-node.sh: секреты возвращаются туда, откуда их брал бэкап.
#
# Скрипт не останавливает стек сам и отказывается работать при запущенной
# ноде: восстановление поверх живой базы порвало бы sled.

ARCHIVE=${1:?usage: restore-node.sh <archive.tgz>}
DEPLOY_DIR=${DEPLOY_DIR:-/root/trust/Trust_me_deploy}
SECRETS_DIR=${SECRETS_DIR:-/root/trust/secrets}
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

# Каталог секретов лежит в архиве под тем именем, которое было у
# SECRETS_DIR при бэкапе. Он находится по содержимому, а не по имени:
# переименованный каталог не должен молча остаться невосстановленным.
secrets_member=$(cut -d/ -f1 "$listing" | sort -u | grep -vx -e data -e '\.env' || true)
if [ -z "$secrets_member" ] || [ "$(printf '%s\n' "$secrets_member" | wc -l)" != "1" ]; then
  echo "FATAL: в архиве не найден однозначный каталог секретов (кандидаты: ${secrets_member:-нет})" >&2
  exit 1
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "dry-run: архив читается, .env на месте, секреты — $secrets_member/ -> $SECRETS_DIR"
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

# Текущий .env может быть новее архивного: в нём бывают значения, которых
# в бэкапе ещё не было (webhook алертов, идентификаторы push). Перезапись
# без копии делала бы восстановление необратимым. `cp -p` сохраняет режим:
# в копии тот же NODE_IDENTITY_KEY, и закрыта она должна быть так же.
if [ -f "$DEPLOY_DIR/.env" ]; then
  cp -p "$DEPLOY_DIR/.env" "$DEPLOY_DIR/.env.before-restore-$ts"
  echo "прежний .env сохранён как .env.before-restore-$ts"
fi

tar xzf "$ARCHIVE" -C "$DEPLOY_DIR" data .env
mkdir -p "$SECRETS_DIR"
tar xzf "$ARCHIVE" -C "$SECRETS_DIR" --strip-components=1 "$secrets_member"
echo "секреты восстановлены в $SECRETS_DIR"

echo "restore ok. Поднимите стек и сверьте node_key в логе с тем, что раздан клиентам."
