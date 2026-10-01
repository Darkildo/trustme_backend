use std::sync::Arc;

use crate::config::Config;
use crate::delivery::DeliveryBackend;
use crate::net::conn::handle_conn;
use crate::net::noise::{HandshakePolicy, NodeIdentity};
use crate::net::rate_limit::{HandshakeAdmission, SessionLimits};
use crate::observability;
use crate::push::PushScheduler;
use crate::state::{push_tokens::PushTokenStore, registry::ConnRegistry, storage::Storage};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

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

    info!(
        addr = %cfg.bind_addr,
        node_key = %node.public_hex(),
        allow_tofu = cfg.noise_allow_tofu,
        max_sessions_per_user = cfg.limits.max_sessions_per_user,
        send_msgs_per_sec = cfg.limits.send_msgs_per_sec,
        ping_per_sec = cfg.limits.ping_per_sec,
        "accept loop started"
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                observability::observe_listener_accept_ok();
                // Кадры протокола маленькие (ack — десяток байт), и Nagle
                // придерживает их до подтверждения предыдущего сегмента; в
                // паре с delayed-ACK получателя это добавляет ~40 мс к
                // каждому ответу.
                if let Err(err) = stream.set_nodelay(true) {
                    warn!(peer = %addr, error = %err, "failed to disable nagle on accepted socket");
                }
                let admission_guard = match admission.try_admit(addr.ip()) {
                    Ok(guard) => guard,
                    Err(reason) => {
                        observability::observe_handshake_admission_rejected(
                            reason.as_metric_label(),
                        );
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
                let registry = registry.clone();
                let storage = storage.clone();
                let delivery_backend = delivery_backend.clone();
                let push_tokens = push_tokens.clone();
                let push_scheduler = push_scheduler.clone();
                let server_config = server_config.clone();
                let limits = limits.clone();
                let node = node.clone();
                info!(peer = %addr, "incoming tcp connection accepted");
                tokio::spawn(async move {
                    debug!(peer = %addr, "starting connection handshake");
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
            Err(e) => {
                observability::observe_listener_accept_error();
                warn!("accept error: {e:?}");
            }
        }
    }
}
