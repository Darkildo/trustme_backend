# Архитектура ноды

Карта того, как устроена нода и как через неё проходят соединение,
сообщение и пробуждение устройства. Документ обзорный: нормативное
поведение на проводе описано в [server-contract.md](../server-contract.md),
формат — в схемах [`schemas/`](../schemas/). Расхождение между этим
документом и контрактом — ошибка этого документа.

Схемы нарисованы на [Mermaid](https://mermaid.js.org/), GitHub рисует их
прямо в просмотре файла.

---

## 1. Система целиком

```mermaid
flowchart TB
    op(["Оператор ноды"])
    subgraph clients["Клиенты: iOS, Android"]
        A["Устройство A"]
        B["Устройство B"]
    end
    subgraph host["Хост ноды"]
        N["Нода<br/>trust_message_tcp"]
        S[("sled на диске")]
        J[("NATS JetStream<br/>опционально")]
        P["Prometheus"]
    end
    subgraph wake["Пробуждение офлайн-устройств"]
        GW["Push-шлюз<br/>опционально,<br/>вне репозитория"]
        FCM["FCM HTTP v1"]
        APNS["APNs VoIP"]
    end

    op -. "ключ ноды вне полосы:<br/>конфиг приложения, QR" .-> clients
    clients <-->|"Noise IK/XX поверх TCP,<br/>protobuf-кадры"| N
    N --- S
    N <-->|"конверты, ack"| J
    P -->|"scrape /metrics"| N
    N -->|"wake и ring:<br/>напрямую или через шлюз"| wake
    GW --> FCM
    GW --> APNS
```

- Клиенты говорят с нодой по TCP. Канал шифрует Noise, TLS не
  используется. Identity клиента — его Ed25519-ключ, паролей и токенов в
  протоколе нет.
- Ключ ноды клиент получает до первого подключения, от оператора
  (паттерн IK), либо узнаёт в ходе хендшейка и решает, доверять ли ему
  (XX, TOFU).
- Недоставленное лежит в `sled` (бэкенд по умолчанию) или в потоке NATS
  JetStream (`DELIVERY_BACKEND=jetstream`).
- Push работает в одном из двух режимов: локальные креды FCM и APNs на
  ноде либо внешний push-шлюз, у которого креды владельца приложения.
  Смешивать режимы нельзя — это ошибка старта. Подробности —
  [push-gateway.md](push-gateway.md).

## 2. Компоненты ноды

```mermaid
flowchart LR
    tcp(["TCP"]) --> L["net/listener.rs<br/>accept, лимиты входа"]
    L --> NZ["net/noise.rs<br/>net/device_cert.rs<br/>хендшейк IK/XX,<br/>сертификат устройства"]
    NZ --> C["net/conn.rs<br/>net/framing.rs<br/>net/rate_limit.rs<br/>сессия, кадры, лимиты"]
    C <--> R["state/registry.rs<br/>реестр сессий"]
    C --> D["delivery/<br/>sled или JetStream"]
    D --> R
    D --> Q[("state/storage.rs<br/>state/queues.rs<br/>очереди в sled")]
    D <--> NATS[("NATS JetStream")]
    C --> SCH["push/mod.rs<br/>PushScheduler"]
    D --> SCH
    SCH --- PT[("state/push_tokens.rs<br/>state/push_state.rs<br/>токены и окна пушей")]
    SCH --> TR["push/fcm.rs<br/>push/apns.rs<br/>push/gateway.rs"]
    TR --> EXT(["FCM, APNs<br/>или push-шлюз"])
```

- Пути на схеме — относительно `src/`.
- Каждое соединение обслуживает отдельная задача tokio. Она проводит
  хендшейк и дальше читает и пишет шифрованный кадровый поток.
- **Реестр сессий** — общая карта `пользователь → список сессий`. В
  записи — `deviceId` сессии и канал на запись в её сокет, до 1024
  кадров. Отправка ищет в реестре цели и кладёт кадр в их каналы.
- **DeliveryBackend** выбирается конфигурацией. Прямой бэкенд
  доставляет в живые сессии сам и складывает недоставленное в `sled`.
  Брокерный публикует всё в JetStream, а выдают конверты пулы доставки.
- **PushScheduler** — отдельная задача с ограниченной очередью триггеров:
  путь доставки на пушах не блокируется.
- Остальные модули (`config.rs`, `observability.rs`, `src/domain/`) —
  в таблице [структуры репозитория](../README.md#структура-репозитория).

## 3. Соединение: от TCP до сессии

```mermaid
stateDiagram-v2
    direction LR
    state "Принято" as Accepted
    state "Хендшейк" as Handshake
    state "Ждёт подтверждения" as Unconfirmed
    state "Сессия" as Session
    state "Закрыто" as Closed

    [*] --> Accepted: accept
    Accepted --> Closed: потолок соединений
    Accepted --> Closed: лимит хендшейков
    Accepted --> Handshake: допуск
    Handshake --> Closed: отказ хендшейка
    Handshake --> Closed: AuthError 401
    Handshake --> Unconfirmed: AuthOk
    Unconfirmed --> Closed: таймаут подтверждения
    Unconfirmed --> Session: первый кадр клиента
    Session --> Closed: разрыв или AuthError 503
    Closed --> [*]
```

- **Принято.** Соединение сверх `LIMIT_MAX_CONNECTIONS` закрывается сразу
  после `accept`. Дальше нужен допуск на хендшейк: не больше
  `LIMIT_HANDSHAKE_INFLIGHT` одновременно на ноду и
  `LIMIT_HANDSHAKE_INFLIGHT_PER_IP` с одного адреса.
- **Хендшейк.** Отказ — разрыв TCP без диагностики: не та магия или
  версия, неизвестный паттерн, XX при `NOISE_ALLOW_TOFU=false`, чужой
  статик ноды, `identityKey` не совпал со статиком, ключ малого порядка,
  таймаут. Лимит сессий пользователя проверяется до `AuthOk`: вместо него
  приходит `AuthError 401`.
- **Ждёт подтверждения.** После `AuthOk` нода ничего не доставляет и не
  считает соединение онлайн-устройством. Сессию открывает первый кадр
  клиента, обычно `Ping`: прислать расшифровываемый кадр может только
  владелец эфемерного ключа хендшейка. Так переигранный msg1 IK не
  получает ни сессии, ни сообщений. Без кадра соединение закрывается
  через `SESSION_CONFIRM_TIMEOUT_SECS`.
- **Сессия.** Сессия попадает в реестр, после чего дренируется
  офлайн-очередь (прямой бэкенд) или поднимаются пулы доставки
  (JetStream). Закрывается разрывом, `AuthError 503` (доставка недоступна),
  истечением сертификата устройства или, на прямом бэкенде, когда сессия
  не успевает читать.

## 4. Хендшейк

```mermaid
sequenceDiagram
    participant C as Клиент
    participant N as Нода

    C->>N: TCP connect
    alt IK: клиент знает ключ ноды
        C->>N: "TMN1", protoVersion, pattern = 1
        C->>N: msg1: e, es, s, ss + NoiseClientHello
        Note right of N: identityKey → X25519<br/>должен совпасть со статиком клиента
        N->>C: msg2: e, ee, se
    else XX: первый контакт, TOFU
        C->>N: "TMN1", protoVersion, pattern = 2
        C->>N: msg1: e
        N->>C: msg2: e, ee, s, es
        Note left of C: клиент решает, доверять ли<br/>ключу ноды, до раскрытия identity
        C->>N: msg3: s, se + NoiseClientHello
    end
    Note over C,N: дальше весь поток зашифрован
    N->>C: AuthOk: userId, serverTime
    C->>N: Ping — подтверждение сессии
    Note right of N: регистрация в реестре,<br/>дренаж или пулы доставки
    N-->>C: недоставленные IncomingMessage
    N->>C: Pong
```

- Магия `TMN1`, версия протокола и байт паттерна идут открытым текстом, но
  входят в prologue Noise. Подмена любого из них разводит transcript'ы
  сторон, и хендшейк не сходится. Так закрыты downgrade версии и
  переключение клиента с пином на TOFU-путь.
- `NoiseClientHello` несёт `identityKey`, `deviceId` и, при делегированном
  входе, сертификат устройства. Нода конвертирует `identityKey` в X25519 и
  сверяет с аутентифицированным статиком. При входе по сертификату статик
  сверяется с `deviceCert.transportKey`.
- Payload msg1 в IK зашифрован на статик ноды без её эфемерала и потому
  не имеет forward secrecy. Транспортная фаза forward secrecy имеет.
- Ключ ноды — один Ed25519-seed. Из него выводятся X25519-статик для
  Noise и ключ подписи `SignedServerConfig` и запросов к push-шлюзу, так что
  пиннить клиенту нужно одну величину. Обращение с ключом —
  [runbook-node-key.md](runbook-node-key.md).

## 5. Доставка сообщения

Обе ветки начинаются одинаково. Нода принимает `ClientSend` и
проверяет его в фиксированном порядке:
1. разрешение `queueId`, если включена адресация по очередям;
2. пол `ttlSeconds`;
3. rate-limit отправителя.

Получатель — `recipientId` или владелец очереди. Account-scope сообщение
(без `recipientDeviceId`) уходит во все сессии пользователя, device-scope —
только сессиям этого устройства. Дальше ветки расходятся.

### 5.1. Прямой бэкенд (`sled`)

```mermaid
sequenceDiagram
    participant A as Отправитель
    participant N as Нода
    participant Q as Офлайн-очередь sled
    participant P as PushScheduler
    participant B as Получатель

    A->>N: ClientSend
    N->>N: queueId, ttlSeconds, rate-limit
    alt у получателя есть живые сессии
        N-)B: IncomingMessage через буфер сессии
        N->>A: SendAck: ok = true
    else ни одна сессия не приняла кадр
        N->>Q: запись в очередь с проверкой квот
        N->>A: SendAck: ok = false, queued = true
        N-)P: триггер для офлайн-устройств
        P-)B: wake через FCM или шлюз
        B->>N: подключение, AuthOk, Ping
        Q->>N: дренаж: account-очередь, затем device-очередь
        N->>B: IncomingMessage с messageId записи
        Note over N,Q: запись удаляется после записи в сокет,<br/>DeliveryAck не нужен
    end
```

- Онлайн-доставка не ждёт чужой сокет: кадр кладётся в канал сессии без
  ожидания. Сессия с переполненным каналом выписывается из реестра и
  закрывается, а сообщение, не принятое ни одной сессией, уходит в
  очередь.
- Квоты очереди (`QUOTA_*`) действуют только на этом офлайн-пути. Упёршаяся
  квота даёт `SendAck` с `FULL`.
- `SendAck.ok` здесь значит «доставлено в живую сессию», а
  `ok = false, queued = true` — «принято в очередь».

### 5.2. Брокерный бэкенд (JetStream)

```mermaid
sequenceDiagram
    participant A as Отправитель
    participant N as Нода
    participant J as JetStream
    participant P as PushScheduler
    participant B as Получатель

    A->>N: ClientSend
    N->>N: queueId, ttlSeconds, rate-limit
    N->>J: publish в ящик получателя
    alt поток принял конверт
        J-->>N: подтверждение публикации
        N->>A: SendAck: ok = true, queued = true, queueId = messageId
        N-)P: триггер для устройств без живой сессии
    else ящик или поток заполнен
        N->>A: SendAck: ok = false, reason = FULL
    end
    Note over N,J: пул доставки scope, пока у scope есть сессии
    J->>N: конверт из durable-consumer
    N->>B: IncomingMessage с messageId
    B->>N: DeliveryAck
    N->>J: ack и удаление конверта из потока
    Note over J,B: без DeliveryAck за NATS_ACK_WAIT_SECS<br/>конверт передоставляется
```

Ящики и пулы доставки:

```mermaid
flowchart LR
    PUB(["publish"]) --> STREAM[("Поток messages<br/>discard: new")]
    STREAM --> SA["msg.user.{id}<br/>ящик аккаунта"]
    STREAM --> SD["msg.user.{id}.device.{n}<br/>ящик устройства"]
    SA --> CA["consumer user_{id}"] --> PA["пул account-scope"] --> SESS["все сессии пользователя"]
    SD --> CD["consumer user_{id}_device_{n}"] --> PDV["пул device-scope"] --> SESSD["сессии устройства n"]
```

- У каждого ящика свой durable pull-consumer. Пул доставки поднимается
  при подтверждении первой сессии scope и завершается, когда scope уходит
  в офлайн. Неподтверждённые конверты завершившегося пула сразу
  возвращаются потоку.
- Пул ждёт место в канале сессии и сессии не выписывает.
- `DeliveryAck` снимает конверт, только если его прислал получатель этого
  scope. Account-scope конверт закрывается первым подтверждением от любой
  сессии пользователя.
- Поток работает по политике `discard: new`. Заполненный ящик
  (`NATS_MAX_MSGS_PER_SUBJECT`) или поток (`NATS_STREAM_MAX_BYTES`)
  отвечает новому конверту `FULL`, уже принятые не вытесняются. Лимиты
  считают только недоставленное.
- Модель — at-least-once. Дубликаты штатны, клиент дедуплицирует по
  `messageId` и по своему идентификатору внутри шифротекста
  ([server-contract.md](../server-contract.md) §6).
- Пуш порождают публикация и первая выдача обычного конверта пулом, если
  устройство успело уйти в офлайн. Передоставка не будит, звонковый
  конверт будит только публикация.

## 6. Пробуждение устройств

```mermaid
flowchart TD
    T["Триггер для офлайн-устройства:<br/>получатель, устройство, приоритет, wakeHint"] --> CALL{"Звонок и есть<br/>voip-слот?"}
    CALL -->|"да"| CD{"Ring этому устройству<br/>был недавно?"}
    CD -->|"да"| SKIP["Повторный ring подавлен"]
    CD -->|"нет"| RING["APNs VoIP ring<br/>или Ring через шлюз"]
    RING -->|"ошибка или мёртвый токен"| TOK
    CALL -->|"нет"| TOK{"Есть alert-токен?"}
    TOK -->|"нет"| NOTOK["Будить нечем,<br/>триггер отброшен"]
    TOK -->|"да"| ST["Окно устройства:<br/>сколько накоплено, макс. приоритет"]
    ST --> DEC{"Прошёл мин. интервал<br/>или набрался порог?"}
    DEC -->|"нет"| WAIT["Ждать таймера<br/>или новых сообщений"]
    DEC -->|"да"| WAKE["FCM wake без содержимого<br/>или Wake через шлюз"]
    WAKE --> OUT{"Ответ провайдера"}
    OUT -->|"успех"| OK["Окно закрыто"]
    OUT -->|"токен мёртв"| DEL["Слот токена удалён"]
    OUT -->|"временная ошибка"| BO["Экспоненциальный backoff"]
```

- Пуш получают только устройства без живой подтверждённой сессии. Сессия
  без `deviceId` ни с каким токеном не сопоставляется и пушей не
  подавляет.
- Триггеры идут через ограниченную очередь (`PUSH_CHANNEL_CAPACITY`): путь
  доставки на ней не ждёт, а при переполнении триггер отбрасывается и
  учитывается в метриках.
- Пороги выбираются по максимальному приоритету накопленного:
  `PUSH_MIN_GAP_*_MS` — минимальный интервал между пушами,
  `PUSH_BURST_*` — сколько сообщений будят досрочно. Состояние окна лежит
  в `sled` и переживает рестарт.
- Звонок (`wakeHint = INCOMING_CALL`) идёт мимо коалесинга. Если ring
  невозможен, звонок уезжает обычным wake с маркером
  `wake_hint = "call"`: только так о звонке узнаёт Android.
- Триггеры одного устройства обрабатываются строго по очереди, разных —
  параллельно. К провайдеру одновременно идёт не больше
  `PUSH_SEND_CONCURRENCY` обращений, это касается и wake, и ring.
- Payload пуша не содержит тела сообщения. Состав полей —
  [server-contract.md](../server-contract.md) §8.

## 7. Развёртывание

Прод-стек из [deploy/docker-compose.override.jetstream.yml](../deploy/docker-compose.override.jetstream.yml):

```mermaid
flowchart LR
    NET(["Интернет"]) -->|"BIND_PORT: Noise"| M
    subgraph host["Хост: docker compose"]
        M["message<br/>нода"]
        NA[("nats<br/>JetStream, том nats-data")]
        DATA[("data/<br/>sled и ключ ноды")]
        SEC[/"секреты push<br/>только чтение"/]
        PR["prometheus"]
        NE["node-exporter"]
        AM["alertmanager"]
    end
    M -->|"nats:4222"| NA
    M --- DATA
    SEC --> M
    PR -->|"/metrics"| M
    PR --> NE
    PR --> AM
    AM -->|"ALERT_WEBHOOK_URL"| HOOK(["канал алертов"])
    M -->|"HTTPS"| PUSHP(["FCM, APNs"])
```

- Наружу открыт только порт протокола. Метрики, мониторинг NATS и
  Alertmanager слушают внутреннюю сеть или `127.0.0.1`: у экспортера метрик
  нет аутентификации.
- TLS-терминатор перед нодой ставить нельзя: он сломает Noise-хендшейк.
- Ключ ноды приходит из `NODE_IDENTITY_KEY` в `.env` рядом с compose.
  Без него деплой падает намеренно, а не генерирует новый ключ.
- Сборка, выкладка, бэкапы и откат — [deployment.md](deployment.md).

## 8. Кто что видит

Тело сообщения шифруется дважды: E2E-шифрованием клиентов и Noise-каналом
каждого клиента до ноды. Нода снимает только второй слой.

```mermaid
flowchart LR
    A["Клиент A"] -->|"Noise-канал A ↔ нода"| N["Нода"]
    N -->|"Noise-канал нода ↔ B"| B["Клиент B"]
    A -. "E2E-шифротекст тела:<br/>нода его не расшифровывает" .-> B
```

| Сторона | Видит | Не видит |
|---|---|---|
| Наблюдатель в сети | IP, размеры и тайминги Noise-сообщений | Адресатов, `deviceId`, кадры, тела |
| Нода и NATS | Отправителя и получателя (`user_id`, `deviceId`), размеры, время, приоритет, признак звонка, IP клиентов; всё это хранится в открытом виде | Тело: это E2E-шифротекст |
| FCM, APNs | Push-токен, время пробуждений; в FCM wake — `user_id` и `deviceId` получателя | Тело, отправителя |
| Push-шлюз | Push-токен, время пробуждений, ключ ноды; в `Wake` — `user_id`, `deviceId`, число и приоритет накопленного | Тело, отправителя, размер сообщения |

Подробно о модели угроз и ограничениях —
[README](../README.md#модель-безопасности) и
[server-contract.md](../server-contract.md) §12.
