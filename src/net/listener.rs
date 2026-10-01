use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, LimitsConfig};
use crate::delivery::DeliveryBackend;
use crate::net::conn::handle_conn;
use crate::net::noise::{HandshakePolicy, NodeIdentity};
use crate::net::rate_limit::{HandshakeAdmission, SessionLimits};
use crate::observability;
use crate::push::PushScheduler;
use crate::state::{push_tokens::PushTokenStore, registry::ConnRegistry, storage::Storage};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Первая пауза после ошибки `accept`, не связанной с конкретным
/// соединением.
const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(100);
/// Потолок паузы: при затяжной нехватке дескрипторов цикл просыпается раз в
/// секунду — и сразу замечает, что они освободились.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
pub async fn accept_loop(
    listener: TcpListener,
    registry: ConnRegistry,
    storage: Storage,
    delivery_backend: DeliveryBackend,
    push_tokens: PushTokenStore,
    push_scheduler: PushScheduler,
    node: Arc<NodeIdentity>,
    cfg: Config,
) {
    let server_config = cfg.server_config_snapshot();
    let handshake_policy = HandshakePolicy {
        timeout: cfg.handshake_timeout,
        max_frame_len: cfg.max_frame_len,
        allow_tofu: cfg.noise_allow_tofu,
        device_cert_max_ttl_secs: cfg.device_cert_max_ttl.as_secs(),
    };
    // Один на процесс: rate-limiter отправки считает бюджет пользователя, а
    // не соединения — на сессию его дробить нельзя.
    let limits = Arc::new(SessionLimits::new(cfg.limits));
    // Вход на хендшейк считается до крипты: респондер платит DH за любого,
    // кто открыл сокет, поэтому ограничение живёт здесь, а не внутри
    // `handle_conn`.
    let admission = Arc::new(HandshakeAdmission::new(
        cfg.limits.handshake_max_inflight,
        cfg.limits.handshake_max_inflight_per_ip,
    ));
    // Потолок открытых соединений. Лимит хендшейков ограничивает только
    // вход, а сессий на пользователя — только одного пользователя; без
    // общего потолка число задач и буферов растёт, пока не кончится память
    // или дескрипторы. Разрешение держится всё время жизни соединения.
    // Потолка на IP у установленных сессий нет намеренно: за
    // carrier-grade NAT с одного адреса приходят сотни честных устройств.
    let connections = Arc::new(Semaphore::new(if cfg.limits.max_connections == 0 {
        Semaphore::MAX_PERMITS
    } else {
        cfg.limits.max_connections
    }));
    let keepalive = tcp_keepalive_params(&cfg.limits);
    let mut backoff = AcceptBackoff::new(ACCEPT_BACKOFF_INITIAL, ACCEPT_BACKOFF_MAX);

    info!(
        addr = %cfg.bind_addr,
        node_key = %node.public_hex(),
        allow_tofu = cfg.noise_allow_tofu,
        max_connections = cfg.limits.max_connections,
        max_sessions_per_user = cfg.limits.max_sessions_per_user,
        send_msgs_per_sec = cfg.limits.send_msgs_per_sec,
        ping_per_sec = cfg.limits.ping_per_sec,
        tcp_keepalive_secs = cfg.limits.tcp_keepalive_secs,
        "accept loop started"
    );

    loop {
        let (stream, addr) = accept_with_backoff(|| listener.accept(), &mut backoff).await;
        observability::observe_listener_accept_ok();

        let connection_permit = match connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                observability::observe_connection_limit_rejected();
                debug!(peer = %addr, "connection limit reached; closing connection");
                // Закрытие до хендшейка: ожидание места — та же нагрузка,
                // от которой потолок защищает.
                continue;
            }
        };

        let admission_guard = match admission.try_admit(addr.ip()) {
            Ok(guard) => guard,
            Err(reason) => {
                observability::observe_handshake_admission_rejected(reason.as_metric_label());
                debug!(
                    peer = %addr,
                    reason = reason.as_metric_label(),
                    "handshake admission refused; closing connection"
                );
                // Соединение закрывается вместе с `stream`: очередь на
                // вход — та же нагрузка, от которой мы защищаемся.
                continue;
            }
        };
        configure_accepted_socket(&stream, keepalive.as_ref());

        let registry = registry.clone();
        let storage = storage.clone();
        let delivery_backend = delivery_backend.clone();
        let push_tokens = push_tokens.clone();
        let push_scheduler = push_scheduler.clone();
        let server_config = server_config.clone();
        let limits = limits.clone();
        let node = node.clone();
        // Адрес клиента — метаданные: в info-логе построчно по каждому
        // соединению ему не место.
        debug!(peer = %addr, "incoming tcp connection accepted");
        tokio::spawn(async move {
            // Место под потолком освобождается вместе с задачей — после
            // хендшейка, сессии или любой их ошибки.
            let _connection_permit = connection_permit;
            if let Err(e) = handle_conn(
                stream,
                registry,
                storage,
                delivery_backend,
                push_tokens,
                push_scheduler,
                node,
                handshake_policy,
                server_config,
                limits,
                admission_guard,
            )
            .await
            {
                error!(peer = %addr, error = ?e, "connection handler terminated with error");
            }
            debug!(peer = %addr, "connection handler finished");
        });
    }
}

/// Параметры TCP keepalive из конфигурации; `None` — keepalive выключен
/// (`TCP_KEEPALIVE_SECS=0`).
fn tcp_keepalive_params(limits: &LimitsConfig) -> Option<TcpKeepalive> {
    if limits.tcp_keepalive_secs == 0 {
        return None;
    }
    let params = TcpKeepalive::new().with_time(Duration::from_secs(limits.tcp_keepalive_secs));
    // Интервал и число проб задаются не везде; там, где нельзя, действуют
    // системные значения, а время простоя — всё равно наше.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "windows",
    ))]
    let params = params
        .with_interval(Duration::from_secs(limits.tcp_keepalive_interval_secs))
        .with_retries(limits.tcp_keepalive_retries);
    Some(params)
}

/// Опции принятого сокета. Ошибка любой из них не повод рвать соединение:
/// сессия работает и без них, только хуже.
fn configure_accepted_socket(stream: &TcpStream, keepalive: Option<&TcpKeepalive>) {
    // Кадры протокола маленькие (ack — десяток байт), и Nagle придерживает
    // их до подтверждения предыдущего сегмента; в паре с delayed-ACK
    // получателя это добавляет ~40 мс к каждому ответу.
    if let Err(err) = stream.set_nodelay(true) {
        warn!(error = %err, "failed to disable nagle on accepted socket");
    }
    // Без keepalive полуоткрытое соединение (клиент сменил сеть, не послав
    // FIN) живёт, пока нода в него не пишет: держит место в лимите сессий
    // пользователя и его статус «в сети».
    if let Some(params) = keepalive
        && let Err(err) = SockRef::from(stream).set_tcp_keepalive(params)
    {
        warn!(error = %err, "failed to enable tcp keepalive on accepted socket");
    }
}

/// Экспоненциальная пауза между неудачными `accept`.
///
/// Нехватка дескрипторов или памяти ядра (EMFILE, ENFILE, ENOBUFS) не
/// проходит от повтора: без паузы цикл крутится вхолостую, занимая ядро
/// CPU и заливая лог той же ошибкой. Пауза удваивается до потолка и
/// сбрасывается первым успешным `accept`.
struct AcceptBackoff {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl AcceptBackoff {
    fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            next: initial,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        delay
    }

    fn reset(&mut self) {
        self.next = self.initial;
    }
}

/// Ошибка `accept`, относящаяся к одному входящему соединению: клиент
/// сбросил его, не дождавшись приёма. Она забирает это соединение из
/// очереди и не повторяется сама по себе, поэтому паузы не требует.
fn is_per_connection_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// Принять следующее соединение, переживая ошибки `accept`. Не
/// возвращается, пока соединение не принято: ошибка слушающего сокета не
/// повод останавливать ноду, а повод подождать.
async fn accept_with_backoff<T, F, Fut>(mut accept: F, backoff: &mut AcceptBackoff) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(accepted) => {
                backoff.reset();
                return accepted;
            }
            Err(err) if is_per_connection_error(&err) => {
                observability::observe_listener_accept_error();
                debug!(error = %err, "accept failed for a single connection");
            }
            Err(err) => {
                observability::observe_listener_accept_error();
                let delay = backoff.next_delay();
                warn!(
                    error = %err,
                    retry_in_ms = delay.as_millis() as u64,
                    "accept failed; pausing before retry"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptBackoff, accept_with_backoff, configure_accepted_socket, tcp_keepalive_params,
    };
    use crate::config::LimitsConfig;
    use socket2::SockRef;
    use std::io;
    use std::time::{Duration, Instant};
    use tokio::net::{TcpListener, TcpStream};

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn backoff_doubles_to_the_ceiling_and_resets() {
        let mut backoff = AcceptBackoff::new(ms(100), ms(1_000));
        let delays: Vec<_> = (0..6).map(|_| backoff.next_delay()).collect();
        assert_eq!(
            delays,
            vec![ms(100), ms(200), ms(400), ms(800), ms(1_000), ms(1_000)]
        );

        backoff.reset();
        assert_eq!(backoff.next_delay(), ms(100));
    }

    /// Ошибка ресурса не крутит цикл вхолостую: между попытками — пауза,
    /// растущая от попытки к попытке.
    #[tokio::test]
    async fn resource_errors_pause_between_retries() {
        let mut backoff = AcceptBackoff::new(ms(20), ms(40));
        let mut calls = 0u32;
        let started = Instant::now();

        let accepted = accept_with_backoff(
            || {
                calls += 1;
                let attempt = calls;
                async move {
                    if attempt <= 3 {
                        Err(io::Error::other("too many open files"))
                    } else {
                        Ok(attempt)
                    }
                }
            },
            &mut backoff,
        )
        .await;

        assert_eq!(accepted, 4);
        // 20 + 40 + 40: три паузы, вторая и третья упёрлись в потолок.
        assert!(
            started.elapsed() >= ms(100),
            "retries were not paused: {:?}",
            started.elapsed()
        );
        // Успех сбросил паузу к начальной.
        assert_eq!(backoff.next_delay(), ms(20));
    }

    /// Сброс одного соединения клиентом не тормозит приём остальных и не
    /// раскручивает паузу.
    #[tokio::test]
    async fn per_connection_errors_do_not_pause() {
        let mut backoff = AcceptBackoff::new(ms(1_000), ms(1_000));
        let mut calls = 0u32;
        let started = Instant::now();

        let accepted = accept_with_backoff(
            || {
                calls += 1;
                let attempt = calls;
                async move {
                    if attempt <= 50 {
                        Err(io::Error::from(io::ErrorKind::ConnectionAborted))
                    } else {
                        Ok(attempt)
                    }
                }
            },
            &mut backoff,
        )
        .await;

        assert_eq!(accepted, 51);
        assert!(started.elapsed() < ms(500), "{:?}", started.elapsed());
    }

    async fn accepted_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    /// Принятый сокет выходит из настройки с keepalive из конфигурации и
    /// без Nagle.
    #[tokio::test]
    async fn accepted_socket_gets_keepalive_and_nodelay() {
        let limits = LimitsConfig {
            tcp_keepalive_secs: 77,
            tcp_keepalive_interval_secs: 11,
            tcp_keepalive_retries: 3,
            ..LimitsConfig::default()
        };
        let params = tcp_keepalive_params(&limits).expect("keepalive is enabled");
        let (server, _client) = accepted_pair().await;

        configure_accepted_socket(&server, Some(&params));

        let socket = SockRef::from(&server);
        assert!(socket.keepalive().unwrap());
        assert!(server.nodelay().unwrap());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                socket.tcp_keepalive_time().unwrap(),
                Duration::from_secs(77)
            );
            assert_eq!(
                socket.tcp_keepalive_interval().unwrap(),
                Duration::from_secs(11)
            );
            assert_eq!(socket.tcp_keepalive_retries().unwrap(), 3);
        }
    }

    /// `TCP_KEEPALIVE_SECS=0` выключает keepalive: сокет остаётся с
    /// системным значением по умолчанию — без проб.
    #[tokio::test]
    async fn zero_keepalive_time_leaves_keepalive_off() {
        let limits = LimitsConfig {
            tcp_keepalive_secs: 0,
            ..LimitsConfig::default()
        };
        assert!(tcp_keepalive_params(&limits).is_none());

        let (server, _client) = accepted_pair().await;
        configure_accepted_socket(&server, None);
        assert!(!SockRef::from(&server).keepalive().unwrap());
        assert!(server.nodelay().unwrap());
    }
}
