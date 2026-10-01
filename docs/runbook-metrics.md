# Runbook: метрики

Что смотреть, чтобы понять состояние ноды, и какие алерты завести.
Экспортер включается `METRICS_ENABLED=true` (или просто `METRICS_ADDR`);
эндпоинт — Prometheus-текст на `METRICS_ADDR`.

Все имена начинаются с `trust_message_tcp_`; ниже префикс опущен.

---

Готовый файл правил — [`deploy/prometheus-alerts.yml`](../deploy/prometheus-alerts.yml)
(подключается через `rule_files`, см. `deploy/monitoring/prometheus.yml`).
Ниже — главное из него и почему.

**Длительности экспортируются как summary с готовыми квантилями, а не как
histogram с бакетами.** Выражения через `histogram_quantile()` и `*_bucket`
вернут пустой результат — обращаться надо к метке `quantile`.

## Четыре сигнала, с которых начинать

Если заводить только четыре алерта, то эти:

```promql
# 1. Нода потеряла свой ключ — клиенты отрезаны, графики при этом зелёные
node_key_source{source="generated"} == 1

# 2. Нода перестала пускать клиентов
rate(noise_handshake_total{result="rejected"}[5m]) > <порог>

# 3. Хранилище отвечает ошибками (диск, права, повреждение)
rate(storage_operation_total{result="error"}[5m]) > 0

# 4. Нода упёрлась во вход: либо её заливают, либо потолок занижен
rate(handshake_admission_rejected_total[5m]) > 0
```

Первый — про доступность сервиса целиком и не виден ни в чём другом:
нода с новым ключом работает идеально и не обслуживает никого.

## Вход: соединения и хендшейки

| Метрика | Метки | О чём |
|---|---|---|
| `listener_accept_total` | `result` = `ok` / `error` | Исход `accept` слушателя |
| `connection_limit_rejected_total` | — | Соединение закрыто сразу после `accept`, до хендшейка: занят весь потолок `LIMIT_MAX_CONNECTIONS` |
| `handshake_admission_rejected_total` | `reason` = `global` / `per_ip` | Отказ во входе **до** крипты |
| `noise_handshake_total` | `result`, `pattern` | Исход хендшейка |
| `noise_handshake_seconds` | `result`, `pattern` | Его длительность |
| `connections_opened_total` / `connections_closed_total` / `connections_active` | — | Жизненный цикл соединений |
| `connection_auth_total` | `result` = `ok` / `unconfirmed` / `limit` / `unavailable` | Сессия подтверждена первым кадром клиента; не подтверждена и закрыта; отбита лимитом сессий; закрыта `AuthError 503` |
| `connection_lifetime_seconds` | — | Сколько живут сессии |
| `connection_reset_by_peer_total` | — | Клиент оборвал соединение |

Значения `result` у хендшейка — стабильный контракт, на них строятся
алерты:

| `result` | Что значит | Тревожно? |
|---|---|---|
| `ok` | Сессия установлена | — |
| `timeout` | Клиент открыл сокет и замолчал | Фоновый шум; всплеск — сканеры |
| `bad_magic` | В порт стучится не наш протокол | Само по себе не авария |
| `unsupported_version` | Клиент говорит на другой версии | Остатки старых клиентов в поле |
| `identity_mismatch` | Заявленный `identityKey` не совпал со статиком | Сломанный или враждебный клиент |
| `tofu_disabled` | Клиент пришёл по XX, а нода его не принимает | Ожидаемо при `NOISE_ALLOW_TOFU=false` |
| `unknown_pattern` | Байт паттерна не 1 и не 2 | Мусор или чужой протокол |
| `rejected` | Всё остальное: чаще всего чужой пин, также невалидный сертификат устройства, обрыв посреди хендшейка | Всплеск = клиенты не знают ключа |

Отказ во входе по лимиту одновременных хендшейков сюда не попадает — он
считается в `handshake_admission_rejected_total`. Ключ малого порядка
(identity клиента, ключи сертификата устройства) даёт `rejected`.

**`connection_auth_total{result}`.** `ok` считает только сессии,
подтверждённые первым кадром клиента после `AuthOk`; соединение без
такого кадра закрывается через `SESSION_CONFIRM_TIMEOUT_SECS` и даёт
`unconfirmed` (в логе — info
`session not confirmed by the client; closing` с `reason` = `timeout` /
`closed` / `unreadable`). Устойчивая доля `unconfirmed` означает клиентов,
которые после `AuthOk` молчат, — их надо обновить; всплеск при ровном
`ok` похож на повторы записанных хендшейков. `limit` бывает и после
`AuthOk`: лимит сессий перепроверяется при подтверждении.

**`connection_limit_rejected_total`** ненулевой — нода упёрлась в потолок
открытых соединений: её заливают соединениями, либо потолок занижен под
реальную нагрузку. Соседние сигналы — `connections_active` у потолка и
`listener_accept_total{result="error"}`: рост последнего с warn
`accept failed; pausing before retry` в логе означает, что раньше потолка
кончились дескрипторы (EMFILE), см.
[runbook-failure-modes.md](runbook-failure-modes.md).

`pattern` = `ik` / `xx` / `unknown`. **Доля `xx` — это доля подключений,
доверие в которых не проверено пином.** На зрелом развёртывании её рост
означает, что клиенты теряют пин.

Все неуспешные хендшейки сейчас помечаются `pattern="unknown"`, в том числе
те, где байт паттерна уже был прочитан; разбивка по паттерну доступна
только для `result="ok"`.

## Маршрутизация сообщений

| Метрика | Метки | О чём |
|---|---|---|
| `frames_received_total` | — | Кадры от клиентов |
| `frame_decode_errors_total` | — | Кадр не разобрался; соединение закрывается |
| `message_route_total` | `route` | Куда ушёл конверт |
| `message_accepted_total` | — | Принято к доставке |
| `message_pushed_online_total` | — | Отдано в живую сессию |
| `reject_total` | `reason` | Отказ приёма |

Значения `route`: `online`, `online_device`, `offline_queue`,
`offline_queue_device`, `offline_replay`, `offline_replay_device`,
`offline_drop_policy`, `offline_drop_device_policy`,
`jetstream_publish`, `jetstream_publish_device`, `server_push`.

`reject_total{reason}` — отказы с точки зрения ноды:

| `reason` | Видно клиенту как | Комментарий |
|---|---|---|
| `full` | `SendAck` c `FULL` | Прямой бэкенд — квота очереди получателя. Брокерный — заполнен ящик получателя (`NATS_MAX_MSGS_PER_SUBJECT`) или весь поток (`NATS_STREAM_MAX_BYTES`); в логе warn `recipient queue in the broker is full; answering the sender with FULL` |
| `rate_limited` | `SendAck` c `RATE_LIMITED` | Лимит msg/s или байт/сутки |
| `too_large` | `SendAck` c `TOO_LARGE` | Тело длиннее `MAX_FRAME_LEN − 128` байт. Постоянный рост — клиент режет медиа на куски крупнее потолка ноды |
| `invalid_ttl` | `SendAck` c `INVALID_TTL` | ttl ниже пола ноды |
| `no_permit` | `SendAck` c `NO_PERMIT` | Депозит в неизвестную или отозванную очередь (только при `QUEUE_ADDRESSING_ENABLED=true`) |
| `forbidden` | `SendAck` c `FORBIDDEN` | Сессия по сертификату устройства без права отправки |
| `internal` | `SendAck` c `INTERNAL` | Ошибка хранилища или брокера. **Ненулевое значение — всегда авария**, смотреть `storage_operation_total{result="error"}`, `broker_publish_timeout_total` и логи |
| `unspecified` / `expired` | одноимённые | Зарезервированы, сейчас не выдаются |
| `retention_policy` | `SendAck` c `UNSPECIFIED` | Дроп по политике `immediate` |
| `session_limit` | `AuthError 401` | Лимит сессий на пользователя |
| `delivery_unavailable` | `AuthError 503` | Пул доставки JetStream не поднялся при открытии сессии |
| `storage_unavailable` | `AuthError 503` | Офлайн-очередь не читается при открытии сессии |

`retention_policy` клиент видит как родовой отказ, и отличить его от
других родовых отказов может только оператор. Так же клиенту неразличимы
`delivery_unavailable` и `storage_unavailable`: оба приходят как
`AuthError 503`. Закрытие живой сессии из-за умершего пула доставки
считается не здесь, а в `pump_session_closed_total`.

**`full` на брокерном бэкенде** бывает двух видов, и в логе они
различаются текстом ошибки рядом с warn: `maximum messages per subject
exceeded` — заполнен один ящик, отказ получают только отправители этому
получателю; `maximum bytes exceeded` — заполнен поток целиком, и `FULL`
получают все. Второе — авария: смотреть заполнение потока
(`nats stream info messages`) и `NATS_STREAM_MAX_BYTES`. Принятые конверты
при этом не теряются; поток разгружается подтверждениями клиентов и по
`NATS_STREAM_MAX_AGE_DAYS`.

## Хранилище

| Метрика | Метки | О чём |
|---|---|---|
| `storage_operation_total` | `op`, `result` = `ok` / `error` | Операции sled |
| `storage_operation_seconds` | `op` | Их длительность (summary) |

Значения `op`: `enqueue_inbox`, `enqueue_device_inbox`, `drain_inbox`,
`drain_device_inbox`, `remove_inbox`, `remove_device_inbox`,
`get_queue_depth`, `queue_quota_fast_path`, `scan_queue_quota`,
`queue_usage`, `count_from_sender`, `rebuild_queue_stats`,
`cleanup_expired_messages`, `cleanup_expired_meta`.

**Проверка квот на горячем пути офлайн-депозита даёт одну из двух меток:**

- `queue_quota_fast_path` — ответ дан по счётчикам, очередь не читалась.
  Нормальное состояние: единицы микросекунд независимо от глубины.
- `scan_queue_quota` — счётчик достиг потолка, и понадобился настоящий
  проход по очереди (счётчик считает и протухшие записи, поэтому у границы
  он не является доказательством). Длительность растёт с глубиной.

Устойчивая доля `scan_queue_quota` означает, что чьи-то очереди стоят у
потолка квоты. Само по себе не авария, но приём для этих получателей
заметно медленнее — стоит посмотреть, кому и почему не доставляют.

`rebuild_queue_stats` — один раз при старте: счётчики не восстанавливаются
с диска, а пересчитываются. Его длительность пропорциональна общему числу
хранимых сообщений и добавляется ко времени запуска ноды.

## Брокер (JetStream)

| Метрика | Метки | О чём |
|---|---|---|
| `message_broker_acked_total` | — | Подтверждённые доставки (по `DeliveryAck` клиента) |
| `message_redelivered_total` | — | Передоставки после ack-таймаута |
| `broker_decode_error_total` | `scope` | Конверт снят с потока: разобрать нельзя |
| `oversized_envelope_total` | `path` | Конверт снят, не доставлен: его кадр длиннее `MAX_FRAME_LEN`. `path`: `broker` — с потока, `offline_replay` — из офлайн-очереди прямого бэкенда, `session` — отброшен в канале сессии |
| `jetstream_no_targets_total` | `scope` | Конверт пришёл, а получателя уже нет онлайн |
| `jetstream_pump_failed_total` | `scope` | Пул доставки упал |
| `jetstream_pump_revived_total` | `scope` | Пул доставки поднят заново |
| `pump_session_closed_total` | `scope` | Сессия закрыта из-за упавшего пула — клиент об аварии узнал |
| `inflight_released_total` | `scope` | Неподтверждённый конверт возвращён потоку сразу, не по `ack_wait` |
| `broker_publish_timeout_total` | — | Публикация не уложилась в `NATS_PUBLISH_TIMEOUT_MS` |

Ненулевой `broker_decode_error_total` означает, что в поток пишет кто-то
ещё или что схема конверта разъехалась между узлами.

Ненулевой `oversized_envelope_total` — это потерянные сообщения: конверт
удалён, получатель его не увидит. Свежие конверты сюда не попадают — тело
сверх потолка нода отклоняет отправителю (`reject_total{reason="too_large"}`).
Причины: `MAX_FRAME_LEN` снизили при непустом хранилище; конверт принят
нодой версии 0.2.1 или раньше; в поток пишет кто-то в обход ноды. В логе —
error `envelope does not fit max_frame_len; terminating it` с отправителем,
получателем и размером. `path="session"` штатно не срабатывает вовсе.

Рост `message_redelivered_total` без роста `message_broker_acked_total` —
клиенты получают конверты, но не подтверждают их. Неподтверждённые
конверты занимают место в лимитах ящика и потока: подтверждённый конверт
нода удаляет из потока, неподтверждённый лежит до `max_age`. Передоставка
пушей не порождает.

`inflight_released_total` — не авария: конверт, который некому
подтвердить, возвращается в поток при завершении пула и выдаётся снова.
Метрика показывает, сколько передоставок случилось быстро вместо
ожидания `ack_wait`.

`pump_session_closed_total` идёт следом за `jetstream_pump_failed_total`:
упавший пул закрывает сессии, которые обслуживал, и они переподключаются.
Разрыв между этими счётчиками означает, что известить сессию не удалось —
её канал был переполнен, и клиент остался в неведении.

## Очереди

Метрики появляются только на ноде с поднятым `QUEUE_ADDRESSING_ENABLED`;
со снятым флагом обе линии плоские, и это нормальное состояние.

| Метрика | О чём |
|---|---|
| `queue_addressed_send_total` | Депозитов, доставленных по `queueId`, а не по `recipientId` |
| `queue_addressed_reject_total` | Депозитов в неизвестную или отозванную очередь |

Считаются отдельно от `message_route_total`: тот отвечает на вопрос «куда
ушёл конверт», а эти — «чем его адресовали». По росту первой метрики видно,
сколько клиентов уже перешло на очереди.

**Устойчиво ненулевой `queue_addressed_reject_total` чаще всего означает
рассинхронизацию**: клиенты держат `queue_id`, которых у ноды нет. Либо
получатель отозвал очередь и не передал новый адрес, либо реестр ноды
разъехался с клиентским состоянием (восстановление из бэкапа старше
последних аллокаций). Первое лечится на клиенте, второе — сверкой через
`ListQueues`. Всплеск сразу после включения флага ожидаем: часть клиентов
шлёт `queueId`, заведённый на другой ноде или до восстановления этой.

## Push

Профиль пробуждения задаётся `PUSH_MIN_GAP_*_MS`, `PUSH_BURST_*` и
`PUSH_WAKE_ON_UNSPECIFIED`. При `PUSH_WAKE_ON_UNSPECIFIED=false` сообщения
без приоритета не будят по времени — они копятся в окне и уезжают вместе с
первым приоритетным либо по порогу `PUSH_BURST_NONE`. Расхождение между
числом недоставленных сообщений и `push_sent_total` для такого профиля —
норма.

| Метрика | Метки | О чём |
|---|---|---|
| `push_sent_total` | `priority`, `result` | Исход отправки пуша |
| `push_dropped_total` | `reason` | Триггер отброшен |
| `push_coalesced_total` | `priority` | Схлопнут окном коалесинга — ждёт **известного** момента |
| `push_deferred_total` | `priority` | Отложен **без таймера** — ждёт соседа или burst |
| `push_pending_recipients` | — | Сколько пар (пользователь, устройство) прямо сейчас ждут пуша |
| `push_latency_seconds` | — | Задержка транспорта |
| `push_token_removed_total` | `reason` = `invalid_token` / `voip_invalid_token` | Слот снят: провайдер или шлюз ответили «токен мёртв» |

`push_dropped_total{reason="channel_full"}` — очередь планировщика
переполнена: путь доставки не блокируется на пушах, и лишний триггер
отбрасывается. Устойчивый рост означает, что транспорт не справляется.
Другие значения `reason`:

| `reason` | Что значит |
|---|---|
| `no_token` | У устройства нет alert-токена — будить нечем, состояние под пару не заводится. Фоновый уровень нормален: сообщения устройствам без пушей |
| `recipient_backlog` | У одного устройства накопилось больше 64 необработанных триггеров, пока его предыдущая отправка висит. Рост — провайдер отвечает медленно |
| `channel_closed`, `welcome_channel_full`, `welcome_channel_closed` | Планировщик остановлен или переполнен канал welcome-пушей |

`push_sent_total{result}`: `ok`, `invalid_token`, `backoff`,
`transient_error`; у ring'ов — ещё `cooldown` (подавлен окном
`PUSH_RING_COOLDOWN_MS`). `result="no_token"` — токен исчез, пока копилось
окно коалесинга: отправка отменена, состояние пары забыто. Одновременно к
провайдеру идёт не больше `PUSH_SEND_CONCURRENCY` запросов.

**`push_deferred_total` и `push_coalesced_total`.** Оба означают «пуш
сейчас не ушёл», но ждут разного. Схлопнутый коалесингом уйдёт в известный
момент — таймер уже стоит. Отложенный ждёт приоритетного соседа в том же
окне либо порога burst: интервал для его приоритета не истекает. При
`PUSH_WAKE_ON_UNSPECIFIED=false` весь поток без приоритета идёт во второй
счётчик, и растущий `push_deferred_total{priority="none"}` при плоском
`push_sent_total` — штатное поведение.

**`push_pending_recipients` — текущая глубина**: сколько пар
(пользователь, устройство) прямо сейчас ждут пуша. Ровная линия —
равновесие: накопление гасится отправками и подключениями. Монотонный рост
означает, что порог `PUSH_BURST_NONE` для реального профиля недостижим и
переписка доезжает только при следующем подключении клиента. При старте
значение восстанавливается из сохранённого состояния планировщика;
обвал до нуля без соответствующих отправок означает потерю этого
состояния.

## Keepalive и ключ

| Метрика | О чём |
|---|---|
| `ping_total` / `pong_total` | Keepalive |
| `ping_dropped_total` | Ping сверх лимита; `Pong` не отправлен, соединение живо |
| `node_key_source` | `source` = `configured` / `file` / `generated` |
| `node_key_permissions_ok` | 0 = файл ключа читаем не только владельцем |
| `process_start_total`, `build_info{version}` | Рестарты и версия |

## Дашборд: минимальный набор панелей

1. **Доступность входа** — `rate(noise_handshake_total[5m])` по `result`,
   стопкой. Всё, что не `ok`, — это клиенты, которые не подключились.
2. **Пропускная способность** — `rate(message_route_total[5m])` по `route`.
   Соотношение `online` к `offline_queue` показывает, сколько получателей
   офлайн.
3. **Отказы** — `rate(reject_total[5m])` по `reason`. Ноль — норма; любая
   ненулевая линия должна быть объяснима.
4. **Хранилище** — p99 `storage_operation_seconds` по `op` и
   `rate(storage_operation_total{result="error"}[5m])`.
5. **Ключ и версия** — `node_key_source`, `node_key_permissions_ok`,
   `build_info`. Три числа, которые обязаны быть скучными.
