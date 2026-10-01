use std::net::SocketAddr;
use std::time::{Duration, Instant};

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::MetricsConfig;

/// Уровень по умолчанию — `info`, а модуль `sled::config` выключен целиком.
///
/// Причина конкретная: при каждом старте под cgroup-лимитом sled пишет
/// «cache capacity is limited to the cgroup memory limit» на уровне ERROR.
/// Это не ошибка, а сообщение о корректно прочитанном лимите, но любой
/// подсчёт ошибок в логах из-за него начинается с единицы, и «ERROR при
/// старте» перестаёт быть сигналом.
///
/// Именно `off`, а не `warn`: уровни фильтруются «этот и выше», поэтому
/// `warn` пропускает ERROR и ничего не меняет. Модуль отвечает за разбор
/// конфигурации sled и в нормальной работе больше ничего не пишет, так что
/// глушится именно он, а не уровень. `RUST_LOG` перекрывает директиву
/// целиком.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sled::config=off"));
    if let Err(err) = tracing_subscriber::fmt().with_env_filter(filter).try_init() {
        eprintln!("logging init skipped: {err}");
    }
}

pub fn init_metrics(cfg: &MetricsConfig) {
    if !cfg.enabled {
        info!("metrics exporter disabled");
        return;
    }

    let addr = match cfg.addr.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(err) => {
            warn!(
                metrics_addr = %cfg.addr,
                error = %err,
                "metrics exporter disabled due to invalid METRICS_ADDR"
            );
            return;
        }
    };

    match PrometheusBuilder::new().with_http_listener(addr).install() {
        Ok(()) => {
            info!(metrics_addr = %cfg.addr, "metrics exporter enabled");
            gauge!(
                "trust_message_tcp_build_info",
                "version" => env!("CARGO_PKG_VERSION")
            )
            .set(1.0);
            counter!("trust_message_tcp_process_start_total").increment(1);
        }
        Err(err) => {
            warn!(
                metrics_addr = %cfg.addr,
                error = %err,
                "metrics exporter failed to start; continuing without metrics"
            );
        }
    }
}

pub struct ConnectionMetricsGuard {
    started_at: Instant,
}

impl ConnectionMetricsGuard {
    pub fn open() -> Self {
        counter!("trust_message_tcp_connections_opened_total").increment(1);
        gauge!("trust_message_tcp_connections_active").increment(1.0);
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Drop for ConnectionMetricsGuard {
    fn drop(&mut self) {
        gauge!("trust_message_tcp_connections_active").decrement(1.0);
        counter!("trust_message_tcp_connections_closed_total").increment(1);
        histogram!("trust_message_tcp_connection_lifetime_seconds")
            .record(self.started_at.elapsed().as_secs_f64());
    }
}

/// Исход Noise-хендшейка — первого барьера ноды, поэтому он считается
/// отдельно от `connection_auth`. `result` — `ok` либо класс отказа из
/// `classify_handshake_error` (`timeout`, `bad_magic`, `identity_mismatch`,
/// `tofu_disabled`, …, `rejected`).
///
/// `pattern` — `ik` / `xx` / `unknown`: доля `xx` — это доля подключений,
/// доверие в которых установлено на первом контакте, а не проверено пином,
/// и следить за ней стоит отдельно. У отказов паттерн всегда `unknown`: в
/// ошибку хендшейка он не передаётся.
pub fn observe_handshake(result: &'static str, pattern: &'static str, elapsed: Duration) {
    counter!(
        "trust_message_tcp_noise_handshake_total",
        "result" => result,
        "pattern" => pattern
    )
    .increment(1);
    histogram!(
        "trust_message_tcp_noise_handshake_seconds",
        "result" => result,
        "pattern" => pattern
    )
    .record(elapsed.as_secs_f64());
}

pub fn observe_listener_accept_ok() {
    counter!("trust_message_tcp_listener_accept_total", "result" => "ok").increment(1);
}

pub fn observe_listener_accept_error() {
    counter!("trust_message_tcp_listener_accept_total", "result" => "error").increment(1);
}

pub fn observe_connection_auth(result: &'static str) {
    counter!(
        "trust_message_tcp_connection_auth_total",
        "result" => result
    )
    .increment(1);
}

pub fn observe_frame_received() {
    counter!("trust_message_tcp_frames_received_total").increment(1);
}

pub fn observe_frame_decode_error() {
    counter!("trust_message_tcp_frame_decode_errors_total").increment(1);
}

pub fn observe_message_route(route: &'static str) {
    counter!(
        "trust_message_tcp_message_route_total",
        "route" => route
    )
    .increment(1);
}

pub fn observe_message_accepted() {
    counter!("trust_message_tcp_message_accepted_total").increment(1);
}

pub fn observe_message_pushed_online() {
    counter!("trust_message_tcp_message_pushed_online_total").increment(1);
}

pub fn observe_message_broker_acked() {
    counter!("trust_message_tcp_message_broker_acked_total").increment(1);
}

pub fn observe_message_redelivered() {
    counter!("trust_message_tcp_message_redelivered_total").increment(1);
}

pub fn observe_jetstream_no_targets(scope: &'static str) {
    counter!(
        "trust_message_tcp_jetstream_no_targets_total",
        "scope" => scope
    )
    .increment(1);
}

/// Пул доставки завершился ошибкой — чаще всего потому, что недоступен
/// брокер. Сессии этой области видимости после этого закрываются
/// (`pump_session_closed_total`), но причину показывает только этот
/// счётчик.
pub fn observe_jetstream_pump_failed(scope: &'static str) {
    counter!(
        "trust_message_tcp_jetstream_pump_failed_total",
        "scope" => scope
    )
    .increment(1);
}

pub fn observe_jetstream_pump_revived(scope: &'static str) {
    counter!(
        "trust_message_tcp_jetstream_pump_revived_total",
        "scope" => scope
    )
    .increment(1);
}

/// Конверт в брокере, который нода не может разобрать. Ненулевое значение
/// означает, что в поток пишет кто-то ещё или что схема конверта
/// разъехалась между узлами. Такой конверт снимается с потока навсегда:
/// оставить его неподтверждённым значит получить вечную переотдачу одного
/// и того же сообщения.
pub fn observe_broker_decode_error(scope: &'static str) {
    counter!(
        "trust_message_tcp_broker_decode_error_total",
        "scope" => scope
    )
    .increment(1);
}

/// Неподтверждённый конверт возвращён потоку при завершении пула, не
/// дожидаясь `ack_wait`. Это не потеря и не ошибка: конверт выдадут
/// снова — метрика показывает, сколько передоставок случилось быстро
/// вместо того, чтобы ждать таймаут подтверждения.
pub fn observe_inflight_released(scope: &'static str) {
    counter!(
        "trust_message_tcp_inflight_released_total",
        "scope" => scope
    )
    .increment(1);
}

/// Сессия закрыта потому, что умер обслуживавший её пул доставки.
/// Пара к `jetstream_pump_failed_total`: показывает, скольким клиентам
/// авария стала видна вместо того, чтобы остаться тихой.
pub fn observe_pump_session_closed(scope: &'static str) {
    counter!(
        "trust_message_tcp_pump_session_closed_total",
        "scope" => scope
    )
    .increment(1);
}

/// Публикация в брокер не уложилась в `NATS_PUBLISH_TIMEOUT_MS`.
/// Отправитель получает отказ (`SendAck.reason = INTERNAL`), а не ждёт:
/// ненулевое значение здесь означает, что брокер жив не настолько,
/// насколько считает клиент NATS.
pub fn observe_broker_publish_timeout() {
    counter!("trust_message_tcp_broker_publish_timeout_total").increment(1);
}

pub fn observe_connection_reset_by_peer() {
    counter!("trust_message_tcp_connection_reset_by_peer_total").increment(1);
}

pub fn observe_ping() {
    counter!("trust_message_tcp_ping_total").increment(1);
}

pub fn observe_pong() {
    counter!("trust_message_tcp_pong_total").increment(1);
}

/// Отказ во входе на хендшейк. `reason` — global / per_ip. Ненулевая
/// величина здесь означает, что нода упёрлась в потолок входа: либо её
/// заливают, либо потолок занижен.
pub fn observe_handshake_admission_rejected(reason: &'static str) {
    counter!(
        "trust_message_tcp_handshake_admission_rejected_total",
        "reason" => reason
    )
    .increment(1);
}

/// Соединение закрыто сразу после `accept`, до хендшейка: занят весь
/// потолок открытых соединений (`LIMIT_MAX_CONNECTIONS`). Ненулевая
/// величина означает, что нода упёрлась в потолок: либо её заливают
/// соединениями, либо потолок занижен для реальной нагрузки.
pub fn observe_connection_limit_rejected() {
    counter!("trust_message_tcp_connection_limit_rejected_total").increment(1);
}

/// Источник ключа ноды на этом старте. `source="generated"` на живой
/// ноде — авария: прежний ключ потерян, клиенты отрезаны. Это gauge, а не
/// счётчик: величина описывает текущий запуск.
pub fn observe_node_key(source: &'static str) {
    gauge!("trust_message_tcp_node_key_source", "source" => source).set(1.0);
}

/// Права файла ключа: 1 — только владелец, 0 — доступен шире. Ключ,
/// который может прочитать кто-то ещё, позволяет выдавать себя за ноду.
pub fn observe_node_key_permissions(owner_only: bool) {
    gauge!("trust_message_tcp_node_key_permissions_ok").set(if owner_only { 1.0 } else { 0.0 });
}

pub fn observe_ping_dropped() {
    counter!("trust_message_tcp_ping_dropped_total").increment(1);
}

/// Отказ отправки с уточнением причины (`SendAck.reason`); основной сигнал
/// для настройки квот и rate-limit'ов.
pub fn observe_reject(reason: &'static str) {
    counter!("trust_message_tcp_reject_total", "reason" => reason).increment(1);
}

pub fn observe_storage_operation(op: &'static str, result: &'static str, elapsed: Duration) {
    counter!(
        "trust_message_tcp_storage_operation_total",
        "op" => op,
        "result" => result
    )
    .increment(1);
    histogram!("trust_message_tcp_storage_operation_seconds", "op" => op)
        .record(elapsed.as_secs_f64());
}

/// Депозит, доставленный по `queueId`, а не по `recipientId`. Отдельный
/// счётчик, а не метка у `message_route_total`: во время выкатки нужно
/// видеть, сколько клиентов уже перешло на очереди, и это вопрос про
/// адресацию, а не про маршрут доставки.
pub fn observe_queue_addressed_send() {
    counter!("trust_message_tcp_queue_addressed_send_total").increment(1);
}

/// Депозит в неизвестную или отозванную очередь. Устойчиво ненулевое
/// значение во время выкатки означает, что клиенты держат `queue_id`,
/// которых у ноды нет, — то есть их состояние разъехалось с её реестром.
pub fn observe_queue_addressed_reject() {
    counter!("trust_message_tcp_queue_addressed_reject_total").increment(1);
}

pub fn observe_push_sent(priority: &'static str, result: &'static str) {
    counter!(
        "trust_message_tcp_push_sent_total",
        "priority" => priority,
        "result" => result
    )
    .increment(1);
}

pub fn observe_push_coalesced(priority: &'static str) {
    counter!(
        "trust_message_tcp_push_coalesced_total",
        "priority" => priority
    )
    .increment(1);
}

/// Сообщение, которое планировщик отложил **без таймера**: интервал для его
/// приоритета не истекает никогда (`PUSH_WAKE_ON_UNSPECIFIED = false`), и
/// пуш за него уйдёт только вместе с приоритетным соседом либо по порогу
/// burst. Считается отдельно от `push_coalesced_total`: там сообщение ждёт
/// известного момента, здесь — неизвестного.
pub fn observe_push_deferred(priority: &'static str) {
    counter!(
        "trust_message_tcp_push_deferred_total",
        "priority" => priority
    )
    .increment(1);
}

/// Абсолютная установка глубины: сколько пар `(пользователь, устройство)`
/// держат ненулевой счётчик накопленного. Вызывается один раз при гидрации
/// из персистентности — дальше глубина двигается дельтами.
pub fn set_push_pending_recipients(value: usize) {
    gauge!("trust_message_tcp_push_pending_recipients").set(value as f64);
}

/// Пара `(пользователь, устройство)` перешла из «накопленного нет» в
/// «накопленное есть» (`now_pending = true`) или обратно. Глубина отвечает на
/// вопрос «сколько людей сейчас ждут пуша», на который счётчики потока не
/// отвечают.
pub fn observe_push_pending_transition(now_pending: bool) {
    if now_pending {
        gauge!("trust_message_tcp_push_pending_recipients").increment(1.0);
    } else {
        gauge!("trust_message_tcp_push_pending_recipients").decrement(1.0);
    }
}

pub fn observe_push_dropped(reason: &'static str) {
    counter!(
        "trust_message_tcp_push_dropped_total",
        "reason" => reason
    )
    .increment(1);
}

pub fn observe_push_token_removed(reason: &'static str) {
    counter!(
        "trust_message_tcp_push_token_removed_total",
        "reason" => reason
    )
    .increment(1);
}

pub fn observe_push_latency(elapsed: Duration) {
    histogram!("trust_message_tcp_push_latency_seconds").record(elapsed.as_secs_f64());
}
