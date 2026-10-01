use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::TcpListener;
use tracing::{info, warn};
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
    // Соединения при этом не дренируются: accept-цикл, сессии и планировщик
    // пушей продолжают работать до выхода из `main` и отменяются вместе с
    // рантаймом.
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

    tokio::select! {
        _ = server => {
            info!("accept loop exited on its own");
        }
        signal = shutdown_signal() => {
            info!(signal, "shutting down");
        }
    }

    match storage_for_shutdown.flush() {
        Ok(bytes) => info!(bytes, "storage flushed on shutdown"),
        Err(err) => warn!(error = %err, "storage flush on shutdown failed"),
    }

    Ok(())
}

/// Ждёт SIGTERM (docker stop, systemd) или SIGINT (Ctrl-C) и возвращает
/// имя пришедшего — оно попадает в лог, потому что «нода остановилась»
/// и «ноду остановили» разбираются по-разному.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(err) => {
                warn!(error = %err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = tokio::signal::ctrl_c() => "SIGINT",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
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
