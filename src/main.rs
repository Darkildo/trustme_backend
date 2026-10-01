use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use trust_message_tcp::delivery::DeliveryBackend;
use trust_message_tcp::net::listener::accept_loop;
use trust_message_tcp::net::noise::NodeIdentity;
use trust_message_tcp::push::{
    ApnsEnvironment, ApnsVoipClient, FcmHttpV1Client, MockTransport, PushGatewayClient,
    PushScheduler, PushStatePersistence,
};
use trust_message_tcp::state::{
    push_tokens::PushTokenStore, registry::ConnRegistry, storage::Storage,
};
use trust_message_tcp::{config, observability};
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    observability::init_logging();

    let mut cfg = config::load()?;
    apply_cli_overrides(&mut cfg).context("failed to apply command-line overrides")?;
    observability::init_metrics(&cfg.metrics);

    // Identity ноды — один Ed25519-ключ: из него выводится X25519-статик
    // для Noise IK, им же подписываются снапшот конфигурации и запросы к
    // push-шлюзу. Ключ живёт рядом с хранилищем (или приходит из
    // NODE_IDENTITY_KEY), а его публичная часть печатается при старте:
    // клиент обязан знать статик заранее, чтобы начать IK-хендшейк.
    let node = Arc::new(NodeIdentity::load_or_generate(
        &cfg.storage_path,
        cfg.node_identity_key.as_deref(),
    )?);
    info!(
        node_key = %node.public_hex(),
        node_identity_key = %node.identity_public_hex(),
        "node key ready"
    );

    let storage = Storage::open(
        &cfg.storage_path,
        cfg.deleted_messages_retention,
        cfg.offline_messages_retention,
    )?;
    storage.start_periodic_cleanup(Duration::from_secs_f64(3600.0 * 24.0));
    let push_tokens: PushTokenStore = storage.push_token_store()?;
    // Persist push throttling state so a restart does not flood every recipient
    // with a fresh push burst.
    let push_state_store: Arc<dyn PushStatePersistence> = Arc::new(storage.push_state_store()?);
    let push_scheduler =
        build_push_scheduler(&cfg, &node, push_tokens.clone(), push_state_store.clone())?;

    let delivery_backend = DeliveryBackend::from_config(
        &cfg,
        storage.clone(),
        push_tokens.clone(),
        push_scheduler.clone(),
    )
    .await?;
    let registry = ConnRegistry::default();

    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    info!("listening on {}", cfg.bind_addr);

    // Штатная остановка. Процесс с PID 1 в контейнере без обработчика
    // SIGTERM сигнал игнорирует, и docker добивает его SIGKILL'ом через
    // десять секунд. Обработчик даёт сбросить sled на диск и выйти сразу.
    //
    // Установленные соединения при этом не дренируются: сессии и
    // планировщик пушей работают до выхода из `main` и отменяются вместе с
    // рантаймом. Останавливается только приём новых.
    let storage_for_shutdown = storage.clone();
    let server = tokio::spawn(accept_loop(
        listener,
        registry,
        storage,
        delivery_backend,
        push_tokens,
        push_scheduler,
        node,
        cfg,
    ));

    let outcome = run_until_shutdown(server, shutdown_signal()).await;
    if let Err(err) = &outcome {
        error!(error = %err, "accept loop failed; shutting down");
    }

    // Хранилище сбрасывается и при аварии цикла: принятое до неё не должно
    // теряться из-за того, что умер приём.
    match storage_for_shutdown.flush() {
        Ok(bytes) => info!(bytes, "storage flushed on shutdown"),
        Err(err) => warn!(error = %err, "storage flush on shutdown failed"),
    }

    outcome
}

/// Работает, пока не придёт сигнал остановки, следя за accept-циклом.
///
/// Цикл бесконечен, поэтому его завершение — авария (паника или отмена), а
/// не штатный выход: результат — ошибка, и процесс выходит с ненулевым
/// кодом, который видят рестарт-политика и мониторинг.
///
/// По сигналу задача цикла отменяется, и её завершение дожидается: вместе
/// с ней закрывается слушающий сокет, так что к сбросу хранилища новых
/// сессий уже не появляется.
async fn run_until_shutdown(
    mut server: JoinHandle<()>,
    shutdown: impl Future<Output = &'static str>,
) -> Result<()> {
    tokio::select! {
        joined = &mut server => Err(match joined {
            Ok(()) => anyhow!("accept loop exited unexpectedly"),
            Err(err) if err.is_panic() => anyhow!("accept loop panicked: {err}"),
            Err(err) => anyhow!("accept loop was cancelled: {err}"),
        }),
        signal = shutdown => {
            info!(signal, "shutting down; no longer accepting connections");
            server.abort();
            // Отмена вступает в силу на ближайшей точке ожидания цикла;
            // результат — заведомо `cancelled`, интересен только сам факт.
            let _ = server.await;
            Ok(())
        }
    }
}

/// Ждёт SIGTERM (docker stop, systemd) или SIGINT (Ctrl-C) и возвращает
/// имя пришедшего — оно попадает в лог, потому что «нода остановилась»
/// и «ноду остановили» разбираются по-разному.
///
/// Не удалась подписка на один сигнал — ждём другой. Вечное ожидание на
/// месте неудавшейся подписки лишило бы ноду и второго способа остановки.
async fn shutdown_signal() -> &'static str {
    let interrupt = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            // Ошибка подписки — не сигнал: принять её за Ctrl-C значило бы
            // остановить ноду сразу после старта.
            warn!(error = %err, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let term = match signal(SignalKind::terminate()) {
            Ok(mut stream) => Some(async move {
                stream.recv().await;
            }),
            Err(err) => {
                warn!(error = %err, "cannot listen for SIGTERM; only SIGINT stops the node");
                None
            }
        };
        first_signal(term, interrupt).await
    }
    #[cfg(not(unix))]
    {
        first_signal(None::<std::future::Pending<()>>, interrupt).await
    }
}

/// Первый из пришедших сигналов. `term = None` — SIGTERM недоступен, и
/// остановить ноду может только SIGINT.
async fn first_signal(
    term: Option<impl Future<Output = ()>>,
    interrupt: impl Future<Output = ()>,
) -> &'static str {
    match term {
        Some(term) => tokio::select! {
            _ = term => "SIGTERM",
            _ = interrupt => "SIGINT",
        },
        None => {
            interrupt.await;
            "SIGINT"
        }
    }
}

/// Собирает планировщик пушей под один из трёх режимов, выбранный
/// конфигурацией:
///
/// - **Шлюз** (`PUSH_GATEWAY_URL`): кредов на ноде нет, и wake, и voip-ring
///   уезжают одним gRPC-клиентом. Соединение ленивое — недоступный шлюз не
///   мешает ноде подняться: пуши best-effort, доставка сообщений от них не
///   зависит.
/// - **Локальные креды**: FCM плюс опциональный APNs voip. Без APNs звонковые
///   конверты будят iOS обычным FCM-wake.
/// - **Выключено** (`PUSH_ENABLED=false`): планировщик стартует с
///   mock-транспортом, но `on_undelivered` и `send_welcome` отбрасывают
///   триггеры сразу — mock лишь сохраняет остальному конвейеру единый тип.
fn build_push_scheduler(
    cfg: &config::Config,
    node: &Arc<NodeIdentity>,
    push_tokens: PushTokenStore,
    push_state_store: Arc<dyn PushStatePersistence>,
) -> Result<PushScheduler> {
    let tokens = Arc::new(push_tokens);

    if !cfg.push.enabled {
        info!("push scheduler running with mock transport (PUSH_ENABLED=false)");
        return Ok(PushScheduler::start(
            cfg.push.clone(),
            Arc::new(MockTransport::always_ok()),
            tokens,
            push_state_store,
        ));
    }

    if let Some(gateway_url) = cfg.push.gateway_url.as_deref() {
        let gateway = Arc::new(
            PushGatewayClient::new(gateway_url, cfg.push.gateway_timeout, node.clone())
                .context("failed to initialise push gateway client")?,
        );
        info!(
            gateway = %gateway_url,
            node_key = %node.identity_public_hex(),
            "push gateway transport initialised"
        );
        return Ok(PushScheduler::start_with_voip(
            cfg.push.clone(),
            gateway.clone(),
            tokens,
            push_state_store,
            Some(gateway),
        ));
    }

    let transport = Arc::new(
        FcmHttpV1Client::new(
            cfg.push.fcm_project_id.clone(),
            &cfg.push.fcm_service_account_path,
            cfg.push.http_timeout,
        )
        .context("failed to initialise FCM HTTP v1 transport")?,
    );
    info!(
        project = %cfg.push.fcm_project_id,
        "FCM push transport initialised"
    );

    let voip = match cfg.push.apns.as_ref() {
        Some(apns) => {
            let environment =
                ApnsEnvironment::parse(&apns.environment).context("invalid APNS_ENVIRONMENT")?;
            let client = ApnsVoipClient::new(
                &apns.key_path,
                apns.key_id.clone(),
                apns.team_id.clone(),
                &apns.bundle_id,
                environment,
                cfg.push.http_timeout,
            )
            .context("failed to initialise APNs voip transport")?;
            info!(
                bundle = %apns.bundle_id,
                environment = %apns.environment,
                "APNs voip ring transport initialised"
            );
            Some(Arc::new(client))
        }
        None => None,
    };

    Ok(PushScheduler::start_with_voip(
        cfg.push.clone(),
        transport,
        tokens,
        push_state_store,
        voip,
    ))
}

fn apply_cli_overrides(cfg: &mut config::Config) -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut override_addr: Option<String> = None;
    let mut override_host: Option<String> = None;
    let mut override_port: Option<u16> = None;

    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--host=") {
            override_host = Some(value.to_string());
            continue;
        }

        if let Some(value) = arg.strip_prefix("--port=") {
            let port = value
                .parse::<u16>()
                .map_err(|err| anyhow!("--port must be a valid u16: {err}"))?;
            override_port = Some(port);
            continue;
        }

        if let Some(value) = arg
            .strip_prefix("--addr=")
            .or_else(|| arg.strip_prefix("--bind-addr="))
        {
            override_addr = Some(value.to_string());
            continue;
        }

        match arg.as_str() {
            "--host" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("expected value after --host"))?;
                override_host = Some(value);
            }
            "--port" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("expected value after --port"))?;
                let port = value
                    .parse::<u16>()
                    .map_err(|err| anyhow!("--port must be a valid u16: {err}"))?;
                override_port = Some(port);
            }
            "--addr" | "--bind-addr" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("expected value after --addr"))?;
                override_addr = Some(value);
            }
            _ => {}
        }
    }

    if let Some(addr) = override_addr {
        let trimmed = addr.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("--addr requires a non-empty value"));
        }
        cfg.bind_addr = trimmed.to_string();
        return Ok(());
    }

    if override_host.is_none() && override_port.is_none() {
        return Ok(());
    }

    let (current_host, current_port) = split_bind_addr(&cfg.bind_addr)?;

    let host = override_host
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(anyhow!("--host requires a non-empty value"))
            } else {
                Ok(trimmed.to_string())
            }
        })
        .transpose()?
        .unwrap_or(current_host);

    let port = override_port.unwrap_or(current_port);
    if port == 0 {
        return Err(anyhow!("--port must be greater than 0"));
    }

    cfg.bind_addr = format!("{host}:{port}");

    Ok(())
}

fn split_bind_addr(addr: &str) -> Result<(String, u16)> {
    if let Some((host, port_raw)) = addr.rsplit_once(':') {
        let port = port_raw
            .parse::<u16>()
            .map_err(|err| anyhow!("bind address `{addr}` has invalid port: {err}"))?;
        return Ok((host.to_string(), port));
    }

    Err(anyhow!(
        "bind address `{addr}` is missing a port; provide `host:port`"
    ))
}

#[cfg(test)]
mod tests {
    use super::{first_signal, run_until_shutdown};
    use std::future::{pending, ready};
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    const GUARD: Duration = Duration::from_secs(5);

    /// Паника accept-цикла — ошибка процесса, а не штатный выход с кодом 0.
    #[tokio::test]
    async fn accept_loop_panic_is_an_error() {
        let server = tokio::spawn(async { panic!("accept loop blew up") });
        let err = timeout(GUARD, run_until_shutdown(server, pending()))
            .await
            .expect("must not wait for a signal once the loop is gone")
            .expect_err("a panicked accept loop must fail the process");
        assert!(err.to_string().contains("panicked"), "unexpected: {err}");
    }

    /// Цикл, вернувшийся сам, — тоже авария: штатно он не завершается.
    #[tokio::test]
    async fn accept_loop_returning_is_an_error() {
        let server = tokio::spawn(async {});
        let err = timeout(GUARD, run_until_shutdown(server, pending()))
            .await
            .expect("must not wait for a signal once the loop is gone")
            .expect_err("an exited accept loop must fail the process");
        assert!(err.to_string().contains("exited"), "unexpected: {err}");
    }

    /// По сигналу приём прекращается до возврата: к сбросу хранилища
    /// слушающий сокет уже закрыт, и новое подключение получает отказ.
    #[tokio::test]
    async fn signal_closes_the_listener_before_returning() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        timeout(GUARD, run_until_shutdown(server, ready("SIGTERM")))
            .await
            .unwrap()
            .expect("a signal is a clean shutdown");

        assert!(
            TcpStream::connect(addr).await.is_err(),
            "listener must be closed once shutdown returns"
        );
    }

    /// Без подписки на SIGTERM нода всё ещё останавливается по SIGINT, а
    /// не ждёт вечно.
    #[tokio::test]
    async fn sigint_works_without_sigterm() {
        let signal = timeout(
            GUARD,
            first_signal(None::<std::future::Pending<()>>, ready(())),
        )
        .await
        .expect("SIGINT must stop the node when SIGTERM is unavailable");
        assert_eq!(signal, "SIGINT");
    }

    #[tokio::test]
    async fn first_signal_names_the_one_that_arrived() {
        assert_eq!(first_signal(Some(ready(())), pending()).await, "SIGTERM");
        assert_eq!(first_signal(Some(pending()), ready(())).await, "SIGINT");
    }
}
