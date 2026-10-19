# Протокол агента tmnode и админки, версия 1

Агент `tmnode` связывает хост ноды с админкой
([trustme_admin](https://github.com/Darkildo/trustme_admin)).

**Направление.** Агент всегда звонит сам — исходящими HTTPS-запросами.
На сервере ноды ради управления не открывается ни одного входящего порта.

**Типы.** Описаны в `tmnode/src/protocol.rs`. Админка берёт их из этого
же крейта, поэтому стороны не расходятся.

Все пути начинаются с `/api/v1/agent`; тела запросов и ответов — JSON.

## Подключение: `POST /enroll`

В панели администратор заводит ноду и получает одноразовый токен
подключения `tme_…` (живёт 24 часа). На чистом сервере он запускает:

```bash
curl -fsSL https://raw.githubusercontent.com/Darkildo/trustme_backend/stable/deploy/install.sh \
  | sudo sh -s -- enroll --url https://admin.example.org --token tme_…
```

`install.sh`:
1. ставит Docker, если его нет;
2. скачивает `tmnode` из GitHub Releases и сверяет SHA-256;
3. запускает `tmnode enroll`.

Запрос:

```json
{ "token": "tme_…", "hostname": "srv-1", "arch": "x86_64", "tmnode_version": "0.2.0" }
```

Ответ:

```json
{
  "agent_id": "…",
  "agent_token": "tma_…",
  "node_id": "…",
  "node_name": "Офис",
  "install": {
    "image": "ghcr.io/darkildo/trustme_backend:v0.6.0",
    "public_host": "203.0.113.10",
    "port": 18081,
    "backend": "sled",
    "coturn": {
      "image": "coturn/coturn:4.6.3",
      "realm": "node.example.org",
      "secret": "…",
      "port": 3478,
      "relay_min_port": 49160,
      "relay_max_port": 49200
    }
  },
  "runtime": { "version": "…", "content": "<runtime.toml>" }
}
```

Токен подключения одноразовый: повтор получает `401`.

Что делает `tmnode enroll`:

1. Сохраняет `agent_token` в `/etc/tmnode/agent.toml` (права 0600).
2. Ставит ноду по `install` (см. ниже) и кладёт `runtime` в каталог её
   данных.
3. Пишет `/etc/tmnode/node.toml` с `management.mode = "managed"` и
   `node.id`.
4. Включает службу `tmnode-agent`.

## Установка

`tmnode install` (без админки) и `tmnode enroll` ставят одно и то же.
Используется только `docker`, без compose.

| Что | Как |
|---|---|
| Сеть | `trustme` |
| Нода | контейнер `message-service`, порт `port:port`, данные в `/var/lib/trustme/node` (владелец — пользователь ноды, uid 10001) |
| JetStream | при `backend = "jetstream"` — контейнер `trustme-nats` |
| coturn | контейнер `trustme-coturn` в сети хоста: диапазон relay-портов через проброс медленный |

**Конфиг coturn** — `/etc/tmnode/coturn/turnserver.conf`.
- Права 0400, владелец — пользователь coturn. Секрет лежит в файле, а не
  в командной строке: её видят `ps` и `docker inspect`.
- Учётки — по общему секрету (`use-auth-secret`), тому же, что в секции
  `[ice]` `runtime.toml` ноды (server-contract.md §6.12).
- Ретрансляция во внутренние сети запрещена (`denied-peer-ip`): иначе
  TURN стал бы входом в сеть сервера.

**Живая нода не затирается.** Если контейнер `message-service` уже есть,
установка останавливается.

## Heartbeat: `POST /heartbeat`

Заголовок `Authorization: Bearer tma_…`. Служба `tmnode-agent` шлёт
heartbeat раз в `interval_secs`. Пределы, которые агент принимает, — от
5 до 3600 секунд.

Запрос:

```json
{
  "tmnode_version": "0.2.0",
  "node_key": "005bdc6b…",
  "report": { "format": "tmnode.report/1" },
  "runtime_status": { "result": "applied", "version": "…", "pending_restart": [] }
}
```

| Поле | Откуда |
|---|---|
| `report` | отчёт `tmnode doctor` (docs/tmnode.md) |
| `runtime_status` | содержимое `runtime.status.json` ноды (docs/runtime-config.md) |

Ответ:

```json
{ "interval_secs": 30, "runtime": { "version": "…", "content": "<runtime.toml>" } }
```

**Желаемые настройки.** Если версия `runtime` отличается от той, что
лежит на диске, агент записывает файл:
- атомарно, с правами 0600, владелец — пользователь ноды;
- нода подхватывает его сама, без перезапуска;
- до записи файл разбирается: документ, который не разбирается, или
  версия в нём не совпадает с объявленной — на диск не попадает.

**Ошибки** агент пишет в журнал службы и повторяет с растущей паузой:
10, 20, 40… секунд, не дольше пяти минут.

## Пути

По умолчанию `tmnode` работает в стандартных каталогах:

| Что | Путь | Переменная окружения |
|---|---|---|
| настройки | `/etc/tmnode` | `TMNODE_ETC_DIR` |
| данные ноды | `/var/lib/trustme/node` | `TMNODE_DATA_DIR` |
| юнит агента | `/etc/systemd/system/tmnode-agent.service` | `TMNODE_UNIT_PATH` |

Переопределять их нужно, если нода работает не в Docker — например,
рядом с бинарём, запущенным тем же пользователем.

Владельца файлов (пользователь ноды, пользователь coturn) `tmnode`
меняет, только когда запущен от root. Без root файлы остаются за
текущим пользователем.

## Безопасность

- Адрес админки — только `https://`; `http://` допустим лишь для
  localhost.
- Токен агента хранится только в `/etc/tmnode/agent.toml` (0600) и не
  выводится ни в лог, ни в отладочный вывод. Админка хранит только его
  хэш.
- Агент не принимает от админки команд, кроме желаемого `runtime.toml`.
  Остальное — обновления и перезапуски — придёт отдельными версиями
  протокола, с явным разрешением в `node.toml`.
