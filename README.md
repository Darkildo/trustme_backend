# trust_message_tcp

Нода (сервер) мессенджера с end-to-end шифрованием. Принимает клиентов по
TCP, аутентифицирует их Noise-хендшейком (`Noise_IK_25519_ChaChaPoly_BLAKE2s`
для клиента с пином ключа ноды, `Noise_XX_25519_ChaChaPoly_BLAKE2s` для
первого контакта), маршрутизирует непрозрачные E2E-конверты между
пользователями и их устройствами, хранит недоставленное (локально в `sled`
или в NATS JetStream) и будит офлайн-устройства push-уведомлениями (FCM,
APNs VoIP, либо внешний push-шлюз). Протокол внутри шифрованного канала —
protobuf.

## Модель безопасности

Что обеспечивает нода. Канал клиент ↔ нода — Noise поверх TCP; TLS не
используется. Identity клиента — его Ed25519-ключ (`user_id`): нода
конвертирует заявленный в хендшейке ключ в X25519 и сверяет с
аутентифицированным Noise-статиком, поэтому выдать себя за другого
пользователя без его секрета нельзя; паролей и токенов в протоколе нет.
Нода аутентифицируется своим X25519-статиком: в IK клиент обязан знать его
заранее (пин, раздаётся вне полосы); в XX клиент получает ключ в ходе
хендшейка и решает, доверять ли ему (TOFU). Магия, версия протокола и
выбранный паттерн входят в Noise prologue, поэтому подмена версии или
переключение клиента с пином на XX ломает хендшейк. Снапшот конфигурации
ноды подписан Ed25519-ключом, из которого выводится её статик; подпись
доменно разделена и имеет срок действия. Тело сообщения нода не
расшифровывает и не разбирает; push-уведомления не содержат тела.
Квоты, rate-limit'ы и лимиты входа ограничивают расход ресурсов ноды
(best-effort; счётчики rate-limit живут в памяти и сбрасываются
рестартом).

Чего нода не обеспечивает. E2E-шифрование тела выполняют клиенты; эта
криптография вне репозитория. Нода видит метаданные: `user_id` и `deviceId`
отправителя и получателя, размеры, время, приоритет и признак звонка, IP
клиентов. Провайдер push видит push-токен и время пробуждений; в FCM-wake
и в запросе к push-шлюзу едут также `user_id` получателя и `deviceId`,
VoIP-пуш APNs их не содержит. Хранилище на диске не шифруется (конверты
лежат как пришли: E2E-шифротекст плюс метаданные в открытом виде), секрет
ноды — hex-файл с правами `0600`. TOFU
не защищает от активного MITM в момент первого контакта
(`NOISE_ALLOW_TOFU=false` отключает этот путь). Payload первого сообщения
IK (identity клиента, `deviceId`) зашифрован на статик ноды без forward
secrecy, и это сообщение может быть переиграно; трафик после хендшейка
forward secrecy имеет. Нода может задерживать или не отдавать сообщения.
Подробности — разделы 5 и 12 [server-contract.md](server-contract.md).

## Спецификация протокола

- [server-contract.md](server-contract.md) — контракт ноды на проводе:
  хендшейк, кадрирование, словарь кадров, семантика отправки и доставки,
  push, лимиты, ограничения.
- [docs/protocol-schema.md](docs/protocol-schema.md) — правила эволюции
  схемы, версионирование.
- [docs/push-gateway.md](docs/push-gateway.md) — контракт ноды с внешним
  push-шлюзом.
- Схемы protobuf — единственный источник правды для кода:
  - [`schemas/trustmessage/wire/v1/wire.proto`](schemas/trustmessage/wire/v1/wire.proto) — клиент ↔ нода;
  - [`schemas/trustmessage/broker/v1/broker.proto`](schemas/trustmessage/broker/v1/broker.proto) — конверт в JetStream (внутренний);
  - [`schemas/trustmessage/push/v1/push.proto`](schemas/trustmessage/push/v1/push.proto) — нода → push-шлюз (gRPC).

Эталонная клиентская проверка подписанного конфига —
`net::framing::verify_signed_server_config`; эталонный инициатор
хендшейка — `NoiseFramed::connect` / `connect_unpinned` в
`src/net/noise.rs`.

## Сборка и тесты

Требования: Rust toolchain с поддержкой edition 2024. `protoc` не нужен:
схемы компилирует `protox` в `build.rs`.

```bash
cargo build --release
cargo test --all-targets
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

Тесты брокерного тракта (`tests/jetstream_delivery.rs`) требуют NATS с
JetStream и помечены `#[ignore]`, поэтому `cargo test` без флагов их не
запускает:

```bash
nats-server -js -sd /tmp/nats-test &
TRUST_MESSAGE_TEST_NATS_URL=nats://127.0.0.1:4222 \
TRUST_MESSAGE_TEST_NATS_BIN=nats-server \
  cargo test --test jetstream_delivery -- --ignored --test-threads=1
```

- `TRUST_MESSAGE_TEST_NATS_URL` — адрес брокера, по умолчанию
  `nats://127.0.0.1:4222`.
- `TRUST_MESSAGE_TEST_NATS_BIN` — путь к бинарю `nats-server`; нужен тесту,
  который сам поднимает и останавливает брокер (без переменной этот тест
  падает). CI использует релиз nats-server v2.12.6.
- `--test-threads=1` обязателен: все тесты используют один поток JetStream
  (два потока не могут делить subject).

Проверка схем (нужен [`buf`](https://buf.build)):

```bash
cd schemas && buf lint
cd schemas && buf breaking --against '../.git#branch=master,subdir=schemas'
```

Фаззинг разборщиков недоверенных байт (нужны nightly и `cargo-fuzz`):

```bash
cargo +nightly fuzz run frame_decode           # разбор Frame
cargo +nightly fuzz run chunk_framing          # сборка логических кадров из Noise-чанков
cargo +nightly fuzz run client_hello           # payload хендшейка (до проверки identity)
cargo +nightly fuzz run signed_server_config   # проверка подписанного конфига
```

Покрытие изменённых строк (гейт CI, порог 70%):

```bash
cargo llvm-cov --all-targets --json --output-path coverage.json \
  -- --include-ignored --test-threads=1
python3 scripts/coverage-gate.py coverage.json origin/master --min 70
```

CI (`.github/workflows/`): fmt, clippy, тесты, брокерные тесты под живым
NATS, `buf lint`/`buf breaking`, покрытие диффа, минутный фаззинг каждого
таргета; ночной фаззинг — `nightly-fuzz.yml`.

## Структура репозитория

| Путь | Содержимое |
|---|---|
| `src/main.rs` | Загрузка конфигурации, ключа ноды, хранилища; запуск listener'а |
| `src/config.rs` | Конфигурация из `.env` и переменных окружения |
| `src/net/noise.rs` | Noise-хендшейк (IK/XX), ключ ноды, кадрирование поверх Noise |
| `src/net/framing.rs` | Кодирование кадров, подписанный `ServerConfig` и его проверка |
| `src/net/conn.rs` | Жизненный цикл сессии, маршрутизация, отказы |
| `src/net/listener.rs` | Accept-цикл, допуск на хендшейк |
| `src/net/rate_limit.rs` | Rate-limit отправки, лимит Ping, лимит одновременных хендшейков |
| `src/delivery/` | Бэкенды доставки: прямой (sled) и JetStream |
| `src/state/` | Хранилище sled: офлайн-очереди, push-токены, состояние планировщика пушей, реестр очередей, реестр сессий |
| `src/push/` | Планировщик пушей, транспорты FCM HTTP v1, APNs VoIP, gRPC-клиент push-шлюза |
| `src/domain/` | Доменные типы: приоритет, причины отказа, wake-подсказка |
| `src/observability.rs` | Логи и Prometheus-метрики |
| `schemas/` | protobuf-схемы (buf-модуль) |
| `build.rs` | Генерация Rust-кода из схем (`protox` + `prost-build` + `tonic-prost-build`) |
| `tests/` | Интеграционные тесты через настоящий Noise-канал на loopback |
| `fuzz/` | Таргеты `cargo-fuzz`, словарь и сиды |
| `examples/` | `e2e_smoke` (сценарии против живой ноды), `load_gen` (нагрузка), административные утилиты push |
| `deploy/` | Образы, compose-override для JetStream, правила алертов, мониторинг, скрипты бэкапа и восстановления |
| `docs/` | Эксплуатационная документация (см. ниже) |

## Запуск

```bash
cargo run --release -- --port 5000
```

При первом старте нода генерирует ключ в `STORAGE_PATH/node_identity_key`
и печатает в лог `node_key=<hex>` — X25519-статик, который нужен клиентам
для IK.

Docker:

```bash
docker build -t trust_message_tcp:local .
docker run --rm \
  -p 5000:5000 -p 127.0.0.1:9000:9000 \
  -e BIND_PORT=5000 -e METRICS_ENABLED=true \
  -v "$(pwd)/data:/srv/trust-message/data" \
  trust_message_tcp:local
```

[compose.yaml](compose.yaml) поднимает ноду вместе с NATS JetStream.

## Конфигурация

Источники: файл `.env` в рабочем каталоге (INI-формат) и переменные
окружения; переменные окружения имеют приоритет. Обязательных параметров
нет. Шаблон — [.env.example](.env.example). CLI: `--addr`/`--bind-addr <host:port>`, `--host <host>`,
`--port <port>` (также в форме `--port=5000`) перекрывают адрес бинда.
Уровень логов — `RUST_LOG` (по умолчанию `info,sled::config=off`).

Сеть, ключ, протокол:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `BIND_ADDR` | — | `host:port`; приоритетнее `BIND_HOST`/`BIND_PORT` |
| `BIND_HOST` | `0.0.0.0` | |
| `BIND_PORT` | `443` | |
| `STORAGE_PATH` | `data` | Каталог sled и файла ключа ноды |
| `NODE_IDENTITY_KEY` | — | Секрет ноды: Ed25519 seed, 64 hex-символа. Перекрывает файл `STORAGE_PATH/node_identity_key`. См. [docs/runbook-node-key.md](docs/runbook-node-key.md) |
| `NOISE_HANDSHAKE_TIMEOUT_MS` | `10000` | Потолок времени на хендшейк; `0` запрещён |
| `NOISE_ALLOW_TOFU` | `true` | Принимать ли XX (первый контакт). `false` — только клиенты с пином |
| `MAX_FRAME_LEN` | `8388608` | Максимальный логический кадр, байт |
| `SERVER_CONFIG_TTL_SECONDS` | `86400` | Срок жизни подписанного снапшота; `0` запрещён |
| `ADVERTISED_ADDRESS` | — | `host:port` в подписанном снапшоте; пусто — нода адрес не объявляет |
| `QUEUE_ADDRESSING_ENABLED` | `false` | Адресация депозита по `queueId` |
| `METRICS_ENABLED` | `false` | Включается автоматически, если задан `METRICS_ADDR` |
| `METRICS_ADDR` | `0.0.0.0:9000` | Адрес Prometheus-экспортера |

Хранение и доставка:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `OFFLINE_MESSAGES_RETENTION` | `30d` | Срок хранения офлайн-очередей (`inbox`, `device_inbox`) |
| `DELETED_MESSAGES_RETENTION` | `30d` | Срок хранения архива `meta` |
| `DELIVERY_BACKEND` | `sled` | `sled` — прямой бэкенд; `jetstream` — доставка через NATS JetStream с `DeliveryAck` |
| `NATS_URL` | `nats://nats:4222` | |
| `NATS_STREAM_NAME` | `messages` | |
| `NATS_ACK_WAIT_SECS` | `30` | Через сколько неподтверждённый конверт передоставляется |
| `NATS_STREAM_MAX_AGE_DAYS` | `14` | Максимальный возраст записи в потоке |
| `NATS_STREAM_MAX_BYTES` | `367001600` (350 MiB) | Объём потока; при переполнении вытесняются старые записи (`discard: old`) |
| `NATS_CONSUMER_INACTIVE_THRESHOLD_DAYS` | `30` | Удаление неактивных durable-consumer'ов; обязан быть больше `NATS_STREAM_MAX_AGE_DAYS` |
| `NATS_PUBLISH_TIMEOUT_MS` | `2000` | Ожидание подтверждения публикации |

Значения retention: число дней (`30`, `30d`), `disabled` (синонимы `off`,
`none`, `false`, `infinite`) — записи не удаляются по сроку, `instant`
(`immediate`, `0`) — офлайн-сообщения не сохраняются.

Лимиты (`0` — без ограничения):

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `TTL_MIN_SECONDS` | `86400` | Пол ненулевого `ClientSend.ttlSeconds`; ниже — `INVALID_TTL`. `0` отключает проверку |
| `QUOTA_MAX_MESSAGES_PER_QUEUE` | `10000` | Записей в одной офлайн-очереди (account и device считаются раздельно) |
| `QUOTA_MAX_BYTES_PER_QUEUE` | `67108864` (64 MiB) | Байт в одной офлайн-очереди |
| `QUOTA_MAX_MESSAGES_SENDER_PAIR` | `2000` | Записей одного отправителя в очереди получателя |
| `RATE_LIMIT_SEND_MSGS_PER_SEC` | `100` | `ClientSend` в секунду на пользователя (фиксированное окно) |
| `RATE_LIMIT_SEND_BYTES_PER_DAY` | `268435456` (256 MiB) | Байт отправки на пользователя за UTC-сутки |
| `LIMIT_MAX_SESSIONS_PER_USER` | `64` | Одновременных сессий пользователя; сверх — `AuthError 401` |
| `LIMIT_PING_PER_SEC` | `50` | `Ping` в секунду на соединение; сверх — `Pong` не отправляется |
| `LIMIT_HANDSHAKE_INFLIGHT` | `256` | Одновременных хендшейков на ноду |
| `LIMIT_HANDSHAKE_INFLIGHT_PER_IP` | `32` | Одновременных хендшейков с одного IP; за общим NAT поднимать |
| `MAX_QUEUES_PER_USER` | `1024` | Mailbox-очередей на пользователя |

Квоты очередей применяются только на прямом бэкенде; брокерный ограничен
лимитами потока JetStream.

Push:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `PUSH_ENABLED` | `false` | Без него используется mock-транспорт |
| `PUSH_GATEWAY_URL` | — | Режим шлюза: кредов FCM/APNs на ноде быть не должно. См. [docs/push-gateway.md](docs/push-gateway.md) |
| `PUSH_GATEWAY_TIMEOUT_MS` | `10000` | |
| `FCM_PROJECT_ID`, `FCM_SERVICE_ACCOUNT_PATH` | — | Обязательны при `PUSH_ENABLED=true` без шлюза |
| `PUSH_HTTP_TIMEOUT_MS` | `10000` | Таймаут запроса к FCM/APNs |
| `PUSH_MIN_GAP_{HIGH,MEDIUM,LOW,NONE}_MS` | `0` / `10000` / `60000` / `120000` | Минимальный интервал между пушами одному устройству по максимальному приоритету накопленного |
| `PUSH_BURST_{HIGH,MEDIUM,LOW,NONE}` | `1` / `3` / `8` / `15` | Сколько накопленных сообщений будят досрочно |
| `PUSH_WAKE_ON_UNSPECIFIED` | `true` | `false` — сообщения без приоритета не будят по времени, только по burst или вместе с приоритетным |
| `PUSH_SUPPRESS_INITIAL_MS`, `PUSH_SUPPRESS_MAX_MS` | `30000`, `3600000` | Экспоненциальный backoff после ошибок провайдера |
| `PUSH_CHANNEL_CAPACITY` | `8192` | Очередь триггеров планировщика; при переполнении триггер отбрасывается |
| `APNS_ENABLED` | `false` | VoIP-пуши входящих звонков на iOS |
| `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID` | — | Обязательны при `APNS_ENABLED=true` |
| `APNS_ENVIRONMENT` | `production` | `production` или `sandbox` |
| `PUSH_RING_COOLDOWN_MS` | `3000` | Подавление повторного VoIP-ring того же устройства |

## Хранилище

Деревья sled под `STORAGE_PATH`: `inbox` и `device_inbox` (офлайн-очереди
account- и device-scope), `queue_stats` (счётчики квот, пересчитываются при
старте), `meta` (архив удалённых из очереди), `system`, `device_push_tokens`,
`push_state` (состояние троттлинга пушей), `queues` и `queue_owner`
(mailbox-очереди). Раз в сутки фоновая задача удаляет записи с истёкшим
retention или `ttlSeconds`; просроченное также отбрасывается лениво при
чтении очереди.

## Эксплуатация

- [docs/deployment.md](docs/deployment.md) — развёртывание, решения до
  запуска, бэкапы, обновление.
- [docs/runbook-node-key.md](docs/runbook-node-key.md) — ключ ноды: бэкап,
  ротация, сигналы потери.
- [docs/runbook-metrics.md](docs/runbook-metrics.md) — метрики и алерты.
- [docs/runbook-failure-modes.md](docs/runbook-failure-modes.md) —
  поведение при отказе брокера, диска, часов, при рестарте и за NAT.
