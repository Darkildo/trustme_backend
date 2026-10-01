#!/usr/bin/env bash
set -euo pipefail

# Deploy script: builds and ships trust_message_tcp to the remote server.
#
# Auth-сервис в тракте сообщений не участвует (identity доказывает статик
# Noise-сессии) и на хосте выключен профилем `legacy-auth`; нода собирается
# в официальном rust-образе, nats — на debian-slim. Образ auth-сервиса по
# умолчанию не пересобирается; --rebuild-auth нужен, только если сервис
# поднимают профилем.
#
# Usage:
#   SSH_HOST=user@host bash deploy/run-deploy.sh                 # только нода
#   SSH_HOST=user@host bash deploy/run-deploy.sh --rebuild-auth  # плюс auth-образ
#                                                                # из соседнего репозитория
#
# SSH_HOST is required. Other env overrides: SSH_PORT, DEPLOY_DIR,
# MESSAGE_REPO_LOCAL, AUTH_REPO_LOCAL; AUTH_IMAGE is required with
# --rebuild-auth. SKIP_AUTH_REBUILD=0 works instead of the CLI flag.

SSH_HOST=${SSH_HOST:-}
SSH_PORT=${SSH_PORT:-22}
DEPLOY_DIR=${DEPLOY_DIR:-/root/trust/Trust_me_deploy}
AUTH_IMAGE=${AUTH_IMAGE:-}
SKIP_AUTH_REBUILD=${SKIP_AUTH_REBUILD:-1}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild-auth) SKIP_AUTH_REBUILD=0; shift ;;
    --skip-auth-rebuild) SKIP_AUTH_REBUILD=1; shift ;;  # оставлен для совместимости вызовов
    -h|--help) sed -n '4,19p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$SSH_HOST" ]]; then
  echo "SSH_HOST is not set: export SSH_HOST=user@host (deploy target)" >&2
  exit 2
fi
if [[ "$SKIP_AUTH_REBUILD" -eq 0 && -z "$AUTH_IMAGE" ]]; then
  echo "AUTH_IMAGE is not set: --rebuild-auth needs the image tag to build" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MESSAGE_REPO_LOCAL=${MESSAGE_REPO_LOCAL:-"$(cd "$SCRIPT_DIR/.." && pwd)"}
AUTH_REPO_LOCAL=${AUTH_REPO_LOCAL:-"$(cd "$MESSAGE_REPO_LOCAL/.." && pwd)/trust_tcp_auth"}

# Pipe the command string into remote bash via stdin. Avoids issues when the
# remote login shell is not bash (e.g. fish).
ssh_run() { ssh -p "$SSH_PORT" "$SSH_HOST" /bin/bash -s <<<"$1"; }
log()     { printf '\n[deploy] %s\n' "$*"; }

log "Source roots:"
log "  message: $MESSAGE_REPO_LOCAL"
log "  auth:    $AUTH_REPO_LOCAL"
log "Target: $SSH_HOST:$DEPLOY_DIR"

[ -f "$MESSAGE_REPO_LOCAL/Cargo.toml" ]                            || { echo "Missing message Cargo.toml at $MESSAGE_REPO_LOCAL" >&2; exit 1; }
[ -f "$MESSAGE_REPO_LOCAL/deploy/message-runtime/Dockerfile" ]      || { echo "Missing deploy/message-runtime/Dockerfile in message repo" >&2; exit 1; }
[ -f "$MESSAGE_REPO_LOCAL/deploy/build-message-runtime.sh" ]        || { echo "Missing deploy/build-message-runtime.sh in message repo" >&2; exit 1; }

if [[ "$SKIP_AUTH_REBUILD" -eq 0 ]]; then
  [ -f "$AUTH_REPO_LOCAL/Cargo.toml" ] || { echo "Missing auth Cargo.toml at $AUTH_REPO_LOCAL (drop --rebuild-auth to reuse the existing image)" >&2; exit 1; }
  [ -f "$AUTH_REPO_LOCAL/Dockerfile" ] || { echo "Missing Dockerfile in auth repo at $AUTH_REPO_LOCAL (drop --rebuild-auth to reuse the existing image)" >&2; exit 1; }
fi

log "1/6 Syncing message source -> $DEPLOY_DIR/tcp_message_server"
rsync -av --delete \
  --exclude='.git/' \
  --exclude='target/' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='secret/' \
  --exclude='deploy/message-runtime/trust_message_tcp' \
  -e "ssh -p $SSH_PORT" \
  "$MESSAGE_REPO_LOCAL/" "$SSH_HOST:$DEPLOY_DIR/tcp_message_server/"

if [[ "$SKIP_AUTH_REBUILD" -eq 1 ]]; then
  log "2/6 Skipping auth source sync (auth-сервис выключен на хосте)"
  log "3/6 Skipping auth image rebuild (сборка ноды от него не зависит)"
else
  log "2/6 Syncing auth source -> /root/trust/auth_src"
  ssh_run "mkdir -p /root/trust/auth_src"
  rsync -av --delete \
    --exclude='.git/' \
    --exclude='target/' \
    --exclude='.env' \
    --exclude='.env.*' \
    -e "ssh -p $SSH_PORT" \
    "$AUTH_REPO_LOCAL/" "$SSH_HOST:/root/trust/auth_src/"

  log "3/6 Building auth image: $AUTH_IMAGE"
  ssh_run "cd /root/trust/auth_src && docker build -t '$AUTH_IMAGE' ."
fi

log "4/6 Compiling message-runtime binary on server"
ssh_run "bash '$DEPLOY_DIR/tcp_message_server/deploy/build-message-runtime.sh'"

log "4.5/6 Installing monitoring config and the backup schedule"
# Конфиг мониторинга версионируется в репозитории и раскладывается отсюда.
ssh_run "mkdir -p '$DEPLOY_DIR/monitoring'"
rsync -av -e "ssh -p $SSH_PORT" \
  "$MESSAGE_REPO_LOCAL/deploy/monitoring/" "$SSH_HOST:$DEPLOY_DIR/monitoring/"
rsync -av -e "ssh -p $SSH_PORT" \
  "$MESSAGE_REPO_LOCAL/deploy/prometheus-alerts.yml" "$SSH_HOST:$DEPLOY_DIR/monitoring/"

# Канал доставки алертов. Пусто — приёмник остаётся пустым, и алерты видны
# только в UI. Это состояние объявляется вслух, а не прячется в конфиге.
ssh_run "$(cat <<'REMOTE'
set -euo pipefail
cd /root/trust/Trust_me_deploy
url=$(grep -E '^ALERT_WEBHOOK_URL=' .env 2>/dev/null | cut -d= -f2- || true)
if [ -n "${url:-}" ]; then
  python3 - "$url" <<'PY'
import sys, pathlib
url = sys.argv[1]
path = pathlib.Path("monitoring/alertmanager.yml")
text = path.read_text()
block = f"    webhook_configs:\n      - url: {url}\n        send_resolved: true\n"
marker = "    # __WEBHOOK_BLOCK__"
lines = [l for l in text.splitlines(True) if not l.strip().startswith("# __WEBHOOK_BLOCK__")]
text = "".join(lines)
text = text.replace("  - name: channel\n", "  - name: channel\n" + block, 1)
path.write_text(text)
PY
  echo "alert channel configured"
else
  echo "WARNING: ALERT_WEBHOOK_URL не задан в .env — алерты будут вычисляться, но никого не разбудят"
fi
REMOTE
)"

# Бэкап по расписанию на этом развёртывании не ставится: раздел делят
# данные ноды, слои docker и посторонние сервисы, и ротация архивов
# занимала больше места, чем поток JetStream. `backup-node.sh` и
# `restore-node.sh` рассчитаны на развёртывания, где состояние sled
# (push-токены, реестр очередей, недоставленное) стоит дороже места.
# Строка бэкапа в cron здесь вычищается, чтобы её не оставил прежний деплой.
ssh_run "$(cat <<REMOTE
set -euo pipefail
# Слои docker и кэш сборки растут незаметно. `image prune` трогает только
# dangling-образы, `builder prune` держит кэш в разумных рамках — оба
# безопасны для запущенных контейнеров.
prune_line='41 4 * * 0 docker image prune -f && docker builder prune -f --keep-storage 2GB'
(
  crontab -l 2>/dev/null | grep -v -e trust-backup-node -e 'docker image prune' || true
  echo "\$prune_line"
) | crontab -
echo "cron installed:"; crontab -l | grep -e 'docker image prune'
REMOTE
)"

# Файлы разложены — но Prometheus и Alertmanager читают конфигурацию
# только при старте или по SIGHUP. `compose up -d` их не пересоздаёт, если
# изменился лишь bind-mount, поэтому без перезагрузки деплой правил молча
# не делал бы ничего: на диске новое, в памяти старое.
ssh_run "docker kill -s HUP prometheus 2>/dev/null && echo 'prometheus reloaded' || echo 'prometheus not running yet (первый запуск)'"
ssh_run "docker kill -s HUP alertmanager 2>/dev/null && echo 'alertmanager reloaded' || echo 'alertmanager not running yet (первый запуск)'"

log "5/6 Building local images and restarting stack"
# The repo ships a JetStream-flavoured override under tcp_message_server/deploy/.
# `docker compose` only auto-loads `docker-compose.override.yml` from the project
# root, so promote the JetStream variant into place here. This keeps the repo as
# the single source of truth for compose config (no manual drift between local
# and prod-only copies).
ssh_run "cp '$DEPLOY_DIR/tcp_message_server/deploy/docker-compose.override.jetstream.yml' '$DEPLOY_DIR/docker-compose.override.yml'"
ssh_run "cd '$DEPLOY_DIR' && docker compose build && docker compose up -d"

log "6/6 Verifying"
ssh_run "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'"
# Правило, которого Prometheus не загрузил, — это текст на диске. Проверяем
# не «есть ли хоть какие-то правила» (они были и до этого), а совпадает ли
# их число с тем, что лежит в репозитории: расхождение означает, что
# перезагрузка не сработала и в памяти осталась прежняя конфигурация.
expected_rules=$(grep -c '^      - alert:' "$MESSAGE_REPO_LOCAL/deploy/prometheus-alerts.yml")
ssh_run "$(cat <<REMOTE
sleep 5
loaded=\$(docker exec prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules 2>/dev/null \
  | grep -o '"type":"alerting"' | wc -l)
if [ "\$loaded" = "$expected_rules" ]; then
  echo "alert rules loaded: \$loaded (совпадает с репозиторием)"
else
  echo "WARNING: загружено \$loaded правил, в репозитории $expected_rules — перезагрузка не сработала" >&2
fi
REMOTE
)"
ssh_run "for c in nats message-service; do echo; echo === \$c ===; docker logs --tail 40 \$c 2>&1 | sed 's/^/  /'; done"

log "DONE"
