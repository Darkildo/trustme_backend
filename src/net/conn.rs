use anyhow::{Result, bail};
use bytes::BytesMut;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::error::TrySendError;
use tokio::{net::TcpStream, select, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::config::ServerConfigSnapshot;
use crate::delivery::DeliveryBackend;
use crate::delivery::sled_ack::{Offer, SledSession, WriteDecision};
use crate::domain::priority::MessagePriority;
use crate::domain::push::PushPlatform;
use crate::domain::reject::SendRejectReason;
use crate::domain::wake::WakeHint;
use crate::net::framing::{
    PROTO_VERSION, QueueListing, as_fixed_32, decode_device_id, decode_frame, encode_auth_error,
    encode_auth_ok, encode_incoming, encode_pong, encode_push_token_ack, encode_queue_ack,
    encode_queue_list, encode_send_ack, encode_signed_server_config, max_send_body_len,
};
use crate::net::noise::{HandshakePolicy, NodeIdentity, NoiseFramed};
use crate::net::rate_limit::{AdmissionGuard, PingGate, SessionLimits, unix_now_secs};
use crate::observability::{self, ConnectionMetricsGuard};
use crate::push::PushScheduler;
use crate::state::cert_revocations::{self, CertRevocationStore, RevocationError};
use crate::state::queues::{AllocateParams, QueueError, derive_queue_id, queue_fingerprint};
use crate::state::{
    push_tokens::{PushTokenStore, RegisterOutcome},
    registry::{ConnRegistry, DeviceId, OutboundFrame, SessionRevocation, UserId},
    storage::{EnqueueResult, InboxScope, QueueQuotaCeilings, Storage},
};
use crate::wire::QueueRejectReason as WireQueueRejectReason;
use crate::wire::frame;

/// Сколько записей очереди сессия дочитывает за один заход цикла. Между
/// порциями цикл успевает прочитать кадры клиента — подтверждения в том
/// числе, — а не пишет весь бэклог одним куском.
const PULL_BATCH: usize = 64;

struct RegistryCleanup {
    registry: ConnRegistry,
    delivery_backend: DeliveryBackend,
    user_id: [u8; 32],
    connection_id: u64,
}

impl Drop for RegistryCleanup {
    fn drop(&mut self) {
        self.registry.remove(&self.user_id, self.connection_id);
        self.delivery_backend.on_disconnect(self.connection_id);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_conn(
    stream: TcpStream,
    registry: ConnRegistry,
    storage: Storage,
    delivery_backend: DeliveryBackend,
    push_tokens: PushTokenStore,
    push_scheduler: PushScheduler,
    node: Arc<NodeIdentity>,
    handshake_policy: HandshakePolicy,
    server_config: ServerConfigSnapshot,
    limits: Arc<SessionLimits>,
    admission_guard: AdmissionGuard,
) -> Result<()> {
    let _connection_metrics = ConnectionMetricsGuard::open();

    // Реестр очередей открывается здесь, а не приезжает параметром: sled-tree
    // после первого открытия — это клон Arc.
    let queues = storage.queue_store()?;
    let cert_revocations = storage.cert_revocation_store()?;
    let device_cert_max_ttl_secs = server_config.device_cert_max_ttl.as_secs();
    let max_queues = limits.cfg.max_queues_per_user;
    let queue_addressing = server_config.supports_queue_addressing;

    // Сессия начинается с Noise-хендшейка; после него identity клиента
    // доказана статиком соединения. Pre-auth plaintext-фазы нет.
    let handshake_started = std::time::Instant::now();
    // Адрес снимается до хендшейка: `accept` забирает сокет, а отказ
    // логируется здесь же.
    let peer = stream.peer_addr().ok();
    let (mut framed, identity) = match NoiseFramed::accept(stream, &node, handshake_policy).await {
        Ok(established) => {
            observability::observe_handshake(
                "ok",
                established.1.pattern.as_metric_label(),
                handshake_started.elapsed(),
            );
            established
        }
        Err(err) => {
            let class = classify_handshake_error(&err.to_string());
            observability::observe_handshake(
                class,
                // Паттерн неизвестен: отказ мог случиться до его чтения.
                "unknown",
                handshake_started.elapsed(),
            );
            // Отказ до сессии — не сбой ноды, а чужой трафик на порту. Он
            // посчитан метрикой и залогирован здесь, поэтому наверх уходит
            // `Ok`: `error!` листенера остаётся за сбоями установленной
            // сессии. `bad_magic` (сканеры портов, чужие протоколы) не
            // стоит и warn'а.
            let peer = peer.map(tracing::field::display);
            if class == "bad_magic" {
                debug!(peer, error = %err, "noise handshake refused: not a noise peer");
            } else {
                warn!(peer, error = %err, "noise handshake failed; closing connection");
            }
            return Ok(());
        }
    };

    let user_id = identity.user_id;
    let device_id = identity.device_id;
    let protocol_version = identity.protocol_version;
    let scope = identity.scope;
    let cert_not_after = identity.cert_not_after;
    let cert_not_before = identity.cert_not_before;

    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        protocol_version,
        pattern = identity.pattern.as_metric_label(),
        delegated = scope.is_delegated(),
        "noise session established"
    );

    // Лимит одновременных сессий на ключ. Проверяется до AuthOk; отказ
    // приходит по уже установленному каналу.
    refuse_over_session_limit(&mut framed, &registry, &limits, &user_id).await?;

    // Отзыв сертификата (§6.10 контракта): хендшейк состояния не читает,
    // поэтому проверка здесь, до `AuthOk`. Сессии ключом аккаунта не
    // читают ничего.
    match is_cert_revoked(&cert_revocations, &user_id, device_id, cert_not_before) {
        Ok(false) => {}
        Ok(true) => {
            return refuse_revoked_cert(&mut framed, &user_id, device_id, "handshake").await;
        }
        Err(err) => return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await,
    }

    let ok_bytes = encode_auth_ok(user_id)?;
    framed.send_frame(&ok_bytes).await?;
    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        protocol_version,
        "sent auth ok to client"
    );

    // Сессия начинается с первого кадра клиента, а не с хендшейка. msg1 IK
    // можно записать и переиграть: нода ответит на повтор msg2 и `AuthOk`,
    // но транспортные ключи зависят от свежего эфемерала ноды, и прислать
    // расшифровываемый кадр может только владелец эфемерного ключа клиента.
    // До этого кадра соединение не регистрируется, не поднимает доставку,
    // не трогает офлайн-очередь и ничего не получает.
    //
    // Место на входе держится до подтверждения: неподтверждённое соединение
    // ещё не учтено лимитом сессий, и без входа повторы не ограничивало бы
    // ничто.
    let confirm_timeout = Duration::from_secs(limits.cfg.session_confirm_timeout_secs);
    let Some(confirming_frame) =
        await_session_confirmation(&mut framed, &user_id, device_id, confirm_timeout).await?
    else {
        return Ok(());
    };
    drop(admission_guard);

    if cert_not_after.is_some_and(|not_after| unix_now_secs() >= not_after) {
        info!(
            user = %hex::encode(user_id),
            ?device_id,
            "device certificate expired; closing delegated session"
        );
        return Ok(());
    }

    // Пока клиент подтверждал сессию, лимит могли выбрать другие его
    // сессии. Проверка и регистрация не атомарны, так что гонка двух
    // подтверждений через порог остаётся — лимит best-effort, см.
    // `ConnRegistry::session_count`.
    refuse_over_session_limit(&mut framed, &registry, &limits, &user_id).await?;

    // Отправитель канала живёт только в реестре. Выписка из реестра —
    // например, за то, что сессия не успевает читать, — закрывает канал, и
    // сессия, отдав уже принятое, завершается, а не остаётся живой, но
    // недостижимой для новых сообщений.
    let (tx_to_client, mut rx_to_client) = mpsc::channel::<OutboundFrame>(1024);
    let registration = registry.insert_session(user_id, device_id, cert_not_before, tx_to_client);
    let _registry_cleanup = RegistryCleanup {
        registry: registry.clone(),
        delivery_backend: delivery_backend.clone(),
        user_id,
        connection_id: registration.connection_id,
    };
    let revocation = registration.revocation.clone();

    // Отзыв мог прийти между `AuthOk` и подтверждением. Проверка стоит
    // после регистрации, а `RevokeDeviceCerts` пишет отзыв до обхода
    // реестра: либо обход застанет эту сессию, либо эта проверка — отзыв.
    // Доставка, реплей и пуши к этому моменту ещё не тронуты.
    match is_cert_revoked(&cert_revocations, &user_id, device_id, cert_not_before) {
        Ok(false) if !revocation.is_revoked() => {}
        Ok(_) => {
            return close_revoked_session(
                &mut framed,
                &user_id,
                device_id,
                &mut rx_to_client,
                "confirm",
            )
            .await;
        }
        Err(err) => return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await,
    }
    observability::observe_connection_auth("ok");
    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        connection_id = registration.connection_id,
        protocol_version,
        "registered client in connection registry"
    );

    let mut messages_sent = 0u64;
    let mut messages_queued = 0u64;
    let mut frames_received = 0u64;
    let mut messages_delivered_online = 0u64;
    let mut messages_delivered_offline = 0u64;
    let mut messages_failed = 0u64;
    let mut messages_rejected = 0u64;
    // Пер-соединение окно Ping: флудер перестаёт получать pong, честный
    // keepalive-клиент проверки не замечает.
    let mut ping_gate = PingGate::new(limits.cfg.ping_per_sec);
    // То же окно для управляющих кадров очередей: каждый — транзакция или
    // скан хранилища.
    let mut control_gate = PingGate::new(limits.cfg.control_per_sec);

    if delivery_backend.is_jetstream() {
        // Always invoke; start_scope_pump dedupes via `pumps` map and revives
        // finished handles. This survives flaps where a stale session is still
        // in the registry (so `is_first_for_user` would be false) but the pump
        // for that user has already exited.
        let pumps_started = async {
            delivery_backend
                .start_user_pump(user_id, registry.clone())
                .await?;
            if let Some(current_device_id) = device_id {
                delivery_backend
                    .start_device_pump(user_id, current_device_id, registry.clone())
                    .await?;
            }
            anyhow::Ok(())
        }
        .await;
        // Пул доставки не поднимается, когда недоступен брокер. Молча
        // оборвать сессию — оставить клиента гадать, что не так с его
        // ключом; держать её живой — хуже: входящих не будет, а выглядеть
        // она будет подключённой. Поэтому отказ явный, и клиент уходит на
        // повтор с backoff.
        if let Err(err) = pumps_started {
            observability::observe_reject("delivery_unavailable");
            observability::observe_connection_auth("unavailable");
            error!(
                user = %hex::encode(user_id),
                ?device_id,
                error = %err,
                "delivery backend unavailable; refusing the session"
            );
            let err_frame = encode_auth_error(503, "delivery backend unavailable");
            send_final_frame(&mut framed, &err_frame).await?;
            bail!("delivery backend unavailable");
        }
    }

    // Прямой бэкенд с хранением: окно подтверждений этой сессии. Объявлено
    // после `_registry_cleanup` и потому уничтожается раньше: уходя, сессия
    // учитывает неподтверждённое и будит другие сессии получателя, пока
    // сама ещё в реестре и в их число не попадает.
    //
    // Реплея на входе как отдельного шага нет: окно помечает очереди к
    // чтению с начала, и цикл сессии дочитывает их порциями по мере места в
    // окне, перемежая с подтверждениями клиента. Каждая сессия получателя
    // читает свои очереди сама, а не только первая: запись остаётся в
    // очереди до подтверждения, и вторая сессия аккаунта получает
    // неподтверждённое первой так же, как получила бы его онлайн.
    let mut sled = match delivery_backend.sled_ack_config() {
        Some(ack_cfg) if server_config.supports_offline_messages() => Some(SledSession::new(
            storage.clone(),
            ack_cfg,
            user_id,
            device_id,
            registry.clone(),
            registration.connection_id,
        )),
        _ => None,
    };
    let resync = registration.resync.clone();

    // Первая порция очередей уходит до первого ответа клиенту, как уходил
    // реплей: до того как цикл возьмётся за подтверждающий кадр, клиент
    // получает накопленное — столько, сколько помещается в окно. Хранилище,
    // не ответившее здесь, — отказ на входе (503), как и прежде.
    if let Some(session) = sled.as_mut() {
        let mut counters = BacklogCounters {
            delivered: &mut messages_delivered_offline,
            failed: &mut messages_failed,
        };
        while session.wants_pull() {
            match deliver_backlog(
                &mut framed,
                &storage,
                session,
                &user_id,
                device_id,
                &revocation,
                cert_not_after,
                &mut counters,
            )
            .await
            {
                Ok(BacklogOutcome::Delivered) => {}
                Ok(BacklogOutcome::Revoked) => {
                    return close_revoked_session(
                        &mut framed,
                        &user_id,
                        device_id,
                        &mut rx_to_client,
                        "live",
                    )
                    .await;
                }
                Ok(BacklogOutcome::Expired) => return Ok(()),
                Err(DeliverError::Io(err)) => return Err(err.into()),
                Err(DeliverError::Storage(err)) => {
                    return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await;
                }
            }
        }
    }

    // Срок сертификата закрывает и молчащую сессию: проверка на входящем
    // кадре одна не сработала бы, пока клиент ничего не шлёт.
    let cert_expiry = async move {
        match cert_not_after {
            Some(not_after) => tokio::time::sleep_until(instant_at_unix_secs(not_after)).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(cert_expiry);
    let mut confirming_frame = Some(confirming_frame);

    'session: loop {
        let pull_ready = sled.as_ref().is_some_and(SledSession::wants_pull);
        let ack_deadline = sled.as_mut().and_then(SledSession::next_deadline);
        select! {
          () = revocation.revoked() => {
              return close_revoked_session(
                  &mut framed,
                  &user_id,
                  device_id,
                  &mut rx_to_client,
                  "live",
              )
              .await;
          }

          maybe_in = next_client_frame(&mut framed, &mut confirming_frame) => {
              let maybe_in = match maybe_in {
                  Ok(value) => value,
                  Err(err) => {
                      if is_connection_reset(&err) {
                          observability::observe_connection_reset_by_peer();
                      }
                      return Err(err.into());
                  }
              };
              let bytes = match maybe_in {
                  Some(bytes) => bytes,
                  None => break,
              };
              // Отозванная сессия больше ничего не делает от имени
              // устройства, даже если сигнал ещё не выбран `select!`.
              if revocation.is_revoked() {
                  return close_revoked_session(
                      &mut framed,
                      &user_id,
                      device_id,
                      &mut rx_to_client,
                      "live",
                  )
                  .await;
              }
              debug!(user = %hex::encode(user_id), size = bytes.len(), "received frame from client");
              frames_received += 1;
              observability::observe_frame_received();

              let incoming_frame = match decode_frame(bytes.as_ref()) {
                  Ok(frame) => frame,
                  Err(err) => {
                      observability::observe_frame_decode_error();
                      warn!(user = %hex::encode(user_id), size = bytes.len(), error = %err, "failed to decode frame");
                      return Err(err);
                  }
              };

              enum ClientFrame {
                  Send {
                      /// `None` — поле пустое. Осмысленно только вместе с
                      /// разрешимым `queueId`: в целевой модели отправитель
                      /// личности получателя не знает. Непустое поле
                      /// неверной длины должно быть ошибкой кадра.
                      recipient: Option<[u8; 32]>,
                      recipient_device_id: Option<DeviceId>,
                      body: Vec<u8>,
                      priority: Option<MessagePriority>,
                      wake_hint: Option<WakeHint>,
                      /// Node-header конверта v3: mailbox-очередь получателя.
                      /// Определяет получателя, только если включена
                      /// адресация по очередям; иначе игнорируется.
                      queue_id: Option<[u8; 32]>,
                      /// Node-header конверта v3: время жизни в очереди,
                      /// 0 = не указан.
                      ttl_seconds: u64,
                  },
                  DeliveryAck {
                      message_id: u64,
                  },
                  GetServerConfig,
                  Ping,
                  RegisterPushToken {
                      token: String,
                      /// Сырое wire-значение: незнакомая платформа — не
                      /// повод рвать сессию, клиент получит отказ в ack.
                      platform: i32,
                  },
                  UnregisterPushToken,
                  AllocateQueue {
                      /// Сырые поля: негодные значения — не повод рвать
                      /// сессию, клиент получит `INVALID` в ack.
                      tag: Vec<u8>,
                      expires_at: u64,
                      revoked: bool,
                  },
                  RevokeQueue {
                      /// Сырые байты: неверная длина — не повод рвать
                      /// сессию, клиент получит `NOT_FOUND` в ack.
                      queue_id: Vec<u8>,
                  },
                  ListQueues,
                  SetQueueOnly {
                      enabled: bool,
                  },
                  SetAccountRecord {
                      record: Vec<u8>,
                      expected_version: u64,
                  },
                  RevokeDeviceCerts {
                      /// Сырое wire-значение: вне u16 — `INVALID` в ack, а
                      /// не разрыв сессии.
                      device_id: u32,
                      issued_before: u64,
                      all: bool,
                  },
                  Ignore,
              }

              let parsed = match incoming_frame.payload {
                  Some(frame::Payload::ClientSend(cmd)) => {
                      let recipient = if cmd.recipient_id.is_empty() {
                          None
                      } else {
                          Some(as_fixed_32(&cmd.recipient_id)?)
                      };
                      let recipient_device_id = decode_device_id(cmd.recipient_device_id)?;
                      // Незнакомое wire-значение (клиент новее сервера) — не
                      // ошибка кадра: приоритет читается как «не указан»,
                      // wake-подсказка — как «обычное сообщение».
                      let priority = MessagePriority::from_wire(cmd.priority);
                      let wake_hint = WakeHint::from_wire(cmd.wake_hint);
                      // Node-header v3: аддитивные поля, клиенты без них
                      // присылают нули. queueId неверной длины не рвёт кадр
                      // и трактуется как отсутствие.
                      let queue_id = decode_queue_id(&cmd.queue_id);
                      ClientFrame::Send {
                          recipient,
                          recipient_device_id,
                          body: cmd.body,
                          priority,
                          wake_hint,
                          queue_id,
                          ttl_seconds: cmd.ttl_seconds,
                      }
                  }
                  Some(frame::Payload::DeliveryAck(ack)) => ClientFrame::DeliveryAck {
                      message_id: ack.message_id,
                  },
                  Some(frame::Payload::GetServerConfig(_)) => ClientFrame::GetServerConfig,
                  Some(frame::Payload::Ping(_)) => ClientFrame::Ping,
                  Some(frame::Payload::RegisterPushToken(req)) => ClientFrame::RegisterPushToken {
                      token: req.token,
                      platform: req.platform,
                  },
                  Some(frame::Payload::UnregisterPushToken(_)) => ClientFrame::UnregisterPushToken,
                  Some(frame::Payload::AllocateQueue(cmd)) => ClientFrame::AllocateQueue {
                      tag: cmd.tag,
                      expires_at: cmd.expires_at,
                      revoked: cmd.revoked,
                  },
                  Some(frame::Payload::RevokeQueue(cmd)) => ClientFrame::RevokeQueue {
                      queue_id: cmd.queue_id,
                  },
                  Some(frame::Payload::ListQueues(_)) => ClientFrame::ListQueues,
                  Some(frame::Payload::SetQueueOnly(cmd)) => ClientFrame::SetQueueOnly {
                      enabled: cmd.enabled,
                  },
                  Some(frame::Payload::SetAccountRecord(cmd)) => ClientFrame::SetAccountRecord {
                      record: cmd.record,
                      expected_version: cmd.expected_version,
                  },
                  Some(frame::Payload::RevokeDeviceCerts(cmd)) => ClientFrame::RevokeDeviceCerts {
                      device_id: cmd.device_id,
                      issued_before: cmd.issued_before,
                      all: cmd.all,
                  },
                  _ => ClientFrame::Ignore,
              };

              // Сессия не должна пережить сертификат, которым открыта:
              // отзыва у сертификатов нет, и срок — единственный предел
              // украденному. Проверяется на каждом входящем кадре.
              if cert_not_after.is_some_and(|not_after| unix_now_secs() >= not_after) {
                  info!(
                      user = %hex::encode(user_id),
                      ?device_id,
                      "device certificate expired; closing delegated session"
                  );
                  break;
              }

              // Права делегированной сессии. Отказ едет ack'ом того же вида,
              // что и у самой операции: клиент ждёт ответа на кадр, и
              // молчание выглядело бы зависшей нодой.
              let forbidden = match &parsed {
                  ClientFrame::Send { .. } if !scope.can_send() => {
                      observability::observe_reject(SendRejectReason::Forbidden.as_metric_label());
                      Some(encode_send_ack(false, false, 0, SendRejectReason::Forbidden))
                  }
                  ClientFrame::RegisterPushToken { .. } | ClientFrame::UnregisterPushToken
                      if !scope.can_manage_push_tokens() =>
                  {
                      Some(encode_push_token_ack(
                          false,
                          "device certificate does not permit push token changes",
                      ))
                  }
                  ClientFrame::AllocateQueue { .. }
                  | ClientFrame::RevokeQueue { .. }
                  | ClientFrame::ListQueues
                  | ClientFrame::SetQueueOnly { .. }
                  | ClientFrame::SetAccountRecord { .. }
                      if !scope.can_manage_queues() =>
                  {
                      Some(encode_queue_ack(false, None, WireQueueRejectReason::Forbidden))
                  }
                  // Не бит, а вид сессии: отзывать сертификаты вправе только
                  // ключ аккаунта. Иначе украденный сертификат с битом
                  // QUEUES отзывал бы сертификаты других устройств владельца.
                  ClientFrame::RevokeDeviceCerts { .. } if scope.is_delegated() => {
                      Some(encode_queue_ack(false, None, WireQueueRejectReason::Forbidden))
                  }
                  _ => None,
              };
              if let Some(ack) = forbidden {
                  warn!(
                      user = %hex::encode(user_id),
                      ?device_id,
                      "delegated session attempted an operation outside its scope"
                  );
                  framed.send_frame(&ack).await?;
                  continue;
              }

              let is_control = matches!(
                  parsed,
                  ClientFrame::AllocateQueue { .. }
                      | ClientFrame::RevokeQueue { .. }
                      | ClientFrame::ListQueues
                      | ClientFrame::SetQueueOnly { .. }
                      | ClientFrame::SetAccountRecord { .. }
                      | ClientFrame::RevokeDeviceCerts { .. }
              );
              if is_control && !control_gate.allow(unix_now_secs()) {
                  observability::observe_control_rate_limited();
                  debug!(
                      user = %hex::encode(user_id),
                      ?device_id,
                      limit = limits.cfg.control_per_sec,
                      "control frame rate limit exceeded"
                  );
                  framed
                      .send_frame(&encode_queue_ack(false, None, WireQueueRejectReason::RateLimited))
                      .await?;
                  continue;
              }

              match parsed {
                  ClientFrame::Send {
                      recipient,
                      recipient_device_id,
                      body,
                      priority,
                      wake_hint,
                      queue_id,
                      ttl_seconds,
                  } => {
                      // Адресация по очередям. Флаг снят — `queueId`
                      // принимается и игнорируется; поднят — очередь
                      // определяет получателя.
                      //
                      // Когда очередь разрешилась, `recipientId` из кадра
                      // не используется вовсе, даже если указывает на
                      // кого-то другого: в целевой модели отправитель
                      // личности получателя не знает. Назвать чужую
                      // очередь можно, только зная её идентификатор, а
                      // знание идентификатора и есть право в неё писать.
                      //
                      // `recipientDeviceId` при этом сохраняется и сужает
                      // доставку до этого устройства владельца очереди —
                      // ровно как рядом с `recipientId` (§6.8 контракта).
                      // Прав это не расширяет: знание очереди и так даёт
                      // право писать её владельцу, а одно устройство —
                      // подмножество аккаунта. Дальше по коду разницы
                      // между адресацией по очереди и по `recipientId` нет:
                      // и прямой бэкенд, и брокер, и пуши получают уже
                      // разрешённую пару «получатель, устройство».
                      let mut resolved = recipient;
                      // Определён ли получатель очередью. `false` — по
                      // `recipientId`: очереди в кадре нет либо нода её
                      // проигнорировала (адресация по очередям снята).
                      let mut addressed_by_queue = false;
                      if let Some(id) = queue_id {
                          if !queue_addressing {
                              debug!(
                                  sender = %hex::encode(user_id),
                                  queue = %queue_fingerprint(&id),
                                  ttl_seconds,
                                  "clientSend carries v3 node-header; queueId ignored"
                              );
                          } else {
                              match queues.owner_of(&id, unix_now_secs()) {
                                  Ok(Some(owner)) => {
                                      resolved = Some(owner);
                                      addressed_by_queue = true;
                                      observability::observe_queue_addressed_send();
                                  }
                                  Ok(None) => {
                                      // Неизвестная, отозванная или истёкшая
                                      // очередь. Разница между ними клиенту
                                      // не сообщается: ответ не должен
                                      // подтверждать существование чужого
                                      // адреса (как и у RevokeQueue).
                                      warn!(
                                          sender = %hex::encode(user_id),
                                          queue = %queue_fingerprint(&id),
                                          "clientSend addressed to an unknown queue"
                                      );
                                      observability::observe_queue_addressed_reject();
                                      reject_send(&mut framed, SendRejectReason::NoPermit).await?;
                                      messages_rejected += 1;
                                      continue;
                                  }
                                  Err(err) => {
                                      warn!(
                                          sender = %hex::encode(user_id),
                                          queue = %queue_fingerprint(&id),
                                          error = %err,
                                          "failed to resolve the queue owner"
                                      );
                                      reject_send(&mut framed, SendRejectReason::Internal).await?;
                                      messages_rejected += 1;
                                      continue;
                                  }
                              }
                          }
                      }
                      // Получатель не определён (пустой `recipientId` и нет
                      // разрешённой очереди) — ошибка кадра: такое присылает
                      // только сломанный клиент.
                      let Some(recipient) = resolved else {
                          bail!("clientSend carries neither a routable queueId nor a recipientId");
                      };

                      // Режим «только по очередям» получателя (§6.9
                      // контракта): кадр, адресованный по `recipientId`,
                      // отвергается так же, как депозит в отозванную
                      // очередь, — иначе отзыв очереди не блокировал бы
                      // контакт, знающий `user_id`. Свои устройства пишут
                      // себе свободно. Со снятой адресацией по очередям
                      // флаг не действует: аккаунт был бы недостижим вовсе.
                      //
                      // Проверка стоит до лимитов (бюджет rate-limit отказ
                      // не расходует) и до развилки бэкендов: в брокер и
                      // офлайн-очередь отвергнутое не попадает, пушей нет.
                      if queue_addressing && !addressed_by_queue && recipient != user_id {
                          match queues.is_queue_only(&recipient) {
                              Ok(false) => {}
                              Ok(true) => {
                                  debug!(
                                      sender = %hex::encode(user_id),
                                      recipient = %hex::encode(recipient),
                                      "clientSend by recipientId refused: recipient accepts queue-addressed deposits only"
                                  );
                                  observability::observe_queue_only_reject();
                                  reject_send(&mut framed, SendRejectReason::NoPermit).await?;
                                  messages_rejected += 1;
                                  continue;
                              }
                              Err(err) => {
                                  warn!(
                                      sender = %hex::encode(user_id),
                                      error = %err,
                                      "failed to read the recipient's queue-only flag"
                                  );
                                  reject_send(&mut framed, SendRejectReason::Internal).await?;
                                  messages_rejected += 1;
                                  continue;
                              }
                          }
                      }

                      debug!(
                          sender = %hex::encode(user_id),
                          ?device_id,
                          recipient = %hex::encode(recipient),
                          ?recipient_device_id,
                          size = body.len(),
                          ?priority,
                          backend = if delivery_backend.is_jetstream() { "jetstream" } else { "sled" },
                          "message send initiated by user"
                      );

                      // Лимиты проверяются до публикации и постановки в
                      // очередь: отказ не должен ни попасть в брокер, ни
                      // будить пушем.
                      if let Some(reason) = precheck_send(
                          &limits,
                          &user_id,
                          body.len(),
                          ttl_seconds,
                          unix_now_secs(),
                          max_send_body_len(framed.max_frame_len()),
                      ) {
                          warn!(
                              sender = %hex::encode(user_id),
                              recipient = %hex::encode(recipient),
                              ?recipient_device_id,
                              size = body.len(),
                              ttl_seconds,
                              reason = reason.as_metric_label(),
                              "clientSend rejected by node limits"
                          );
                          reject_send(&mut framed, reason).await?;
                          messages_rejected += 1;
                          continue;
                      }

                      if delivery_backend.is_jetstream() {
                          // Отказ ноды — это отказ отправки, а не конец
                          // сессии: получатель на том же соединении
                          // продолжает принимать входящие, и рвать их
                          // из-за чужой неудачной публикации незачем.
                          let published = async {
                              let message_id = storage.generate_id()?;
                              delivery_backend
                                  .publish(
                                      message_id,
                                      user_id,
                                      device_id,
                                      recipient,
                                      recipient_device_id,
                                      &body,
                                      priority,
                                      wake_hint,
                                      ttl_seconds,
                                  )
                                  .await?;
                              anyhow::Ok(message_id)
                          }
                          .await;
                          let message_id = match published {
                              Ok(id) => id,
                              Err(err) => {
                                  // Переполненный ящик или поток — штатный
                                  // отказ новому конверту (FULL), уже лежащие
                                  // не тронуты; всё прочее — авария ноды.
                                  let reason = err
                                      .downcast_ref::<crate::delivery::PublishError>()
                                      .map_or(
                                          SendRejectReason::Internal,
                                          crate::delivery::PublishError::reject_reason,
                                      );
                                  if reason == SendRejectReason::Full {
                                      warn!(
                                          sender = %hex::encode(user_id),
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          size = body.len(),
                                          error = %err,
                                          "recipient queue in the broker is full; answering the sender with FULL"
                                      );
                                  } else {
                                      error!(
                                          sender = %hex::encode(user_id),
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          size = body.len(),
                                          error = %err,
                                          "publish to broker failed; answering the sender with a reject"
                                      );
                                  }
                                  reject_send(&mut framed, reason).await?;
                                  messages_rejected += 1;
                                  continue;
                              }
                          };
                          let ack =
                              encode_send_ack(true, true, message_id, SendRejectReason::Unspecified);
                          framed.send_frame(&ack).await?;
                          messages_queued += 1;
                          observability::observe_message_route(match recipient_device_id {
                              Some(_) => "jetstream_publish_device",
                              None => "jetstream_publish",
                          });
                          debug!(
                              sender = %hex::encode(user_id),
                              recipient = %hex::encode(recipient),
                              ?recipient_device_id,
                              message_id,
                              size = body.len(),
                              "message successfully accepted by JetStream"
                          );

                          // Wake-push trigger for the JetStream backend. The
                          // delivery pump (the only other caller of the push
                          // scheduler) runs only while the recipient is
                          // connected, so a fully-offline recipient is woken
                          // here, at publish time, skipping any device that
                          // currently holds a live session.
                          let online_device_ids: Vec<DeviceId> = registry
                              .route_targets(&recipient, recipient_device_id)
                              .iter()
                              .filter_map(|target| target.device_id)
                              .collect();
                          trigger_offline_pushes(
                              &push_tokens,
                              &push_scheduler,
                              recipient,
                              recipient_device_id,
                              priority,
                              wake_hint,
                              &online_device_ids,
                          );
                      } else {
                          // Прямой бэкенд с хранением пишет конверт в
                          // очередь получателя всегда, а не только когда тот
                          // офлайн: запись снимает `DeliveryAck` клиента, и
                          // онлайн-сессии уходит лишь уведомление с её
                          // `message_id` (см. `delivery::sled_ack`). Без
                          // хранения (`OFFLINE_MESSAGES_RETENTION=instant`)
                          // доставка только онлайн, `message_id = 0`, как до
                          // подтверждений.
                          let durable = server_config.supports_offline_messages();
                          let route_targets = registry.route_targets(&recipient, recipient_device_id);

                          // Квоты очереди прямого бэкенда. С хранением они
                          // меряют неподтверждённое и действуют и для живого
                          // получателя: иначе не подтверждающая сессия копила
                          // бы записи без предела. Брокерный путь ограничен
                          // лимитами самого потока JetStream и сюда не
                          // заходит.
                          let mut depth_before = None;
                          if durable || route_targets.is_empty() {
                              let quota = match queue_quota_reason(
                                  &storage,
                                  &limits,
                                  &recipient,
                                  recipient_device_id,
                                  &user_id,
                              ) {
                                  Ok(quota) => quota,
                                  Err(err) => {
                                      error!(
                                          sender = %hex::encode(user_id),
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          error = %err,
                                          "queue quota scan failed; answering the sender with a reject"
                                      );
                                      reject_send(&mut framed, SendRejectReason::Internal).await?;
                                      messages_rejected += 1;
                                      continue;
                                  }
                              };
                              if let Some(reason) = quota.reason {
                                  warn!(
                                      sender = %hex::encode(user_id),
                                      recipient = %hex::encode(recipient),
                                      ?recipient_device_id,
                                      size = body.len(),
                                      reason = reason.as_metric_label(),
                                      "enqueue rejected by queue quota"
                                  );
                                  reject_send(&mut framed, reason).await?;
                                  messages_rejected += 1;
                                  continue;
                              }
                              depth_before = quota.depth_before;
                          }

                          let enqueue_result = if durable {
                              let enqueued = match recipient_device_id {
                                  Some(target_device_id) => storage.enqueue_device_inbox(
                                      &recipient,
                                      target_device_id,
                                      &user_id,
                                      device_id,
                                      &body,
                                      priority,
                                      ttl_seconds,
                                  ),
                                  None => storage.enqueue_inbox(
                                      &recipient,
                                      &user_id,
                                      device_id,
                                      &body,
                                      priority,
                                      ttl_seconds,
                                  ),
                              };
                              match enqueued {
                                  Ok(result) => result,
                                  Err(err) => {
                                      // Диск кончился или БД повреждена.
                                      // Сессия при этом остаётся живой:
                                      // принимать входящие она может и с
                                      // полным диском.
                                      error!(
                                          sender = %hex::encode(user_id),
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          size = body.len(),
                                          error = %err,
                                          "enqueue failed; answering the sender with a reject"
                                      );
                                      reject_send(&mut framed, SendRejectReason::Internal).await?;
                                      messages_rejected += 1;
                                      continue;
                                  }
                              }
                          } else {
                              // Retention `instant`: хранить нельзя, а
                              // офлайн-получателю — некуда.
                              EnqueueResult { id: 0, stored: false }
                          };
                          let message_id = enqueue_result.stored.then_some(enqueue_result.id);
                          let incoming = encode_incoming(
                              user_id,
                              device_id,
                              message_id.unwrap_or(0),
                              &body,
                              priority,
                          );
                          let mut delivered_count = 0usize;

                          // Канал получателя не ждём: отправитель не должен
                          // висеть на чужом медленном сокете. Переполненный
                          // канал значит, что сессия не успевает писать в
                          // сокет, — она выписывается из реестра (и этим
                          // закрывается, см. регистрацию). Записи в очереди
                          // это не касается: её дочитает следующая сессия.
                          for target in route_targets {
                              let outgoing = OutboundFrame {
                                  bytes: incoming.clone(),
                                  message_id,
                                  close_after_send: false,
                                  sender_user_id: Some(user_id),
                                  sender_device_id: device_id,
                                  target_device_id: recipient_device_id,
                              };
                              match target.tx.try_send(outgoing) {
                                  Ok(()) => {
                                      delivered_count += 1;
                                  }
                                  Err(TrySendError::Full(_)) => {
                                      registry.remove(&recipient, target.id);
                                      warn!(
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          lagging_connection_id = target.id,
                                          ?target.device_id,
                                          "recipient session is not keeping up; evicted from the registry"
                                      );
                                  }
                                  Err(TrySendError::Closed(_)) => {
                                      registry.remove(&recipient, target.id);
                                      warn!(
                                          sender = %hex::encode(user_id),
                                          recipient = %hex::encode(recipient),
                                          ?recipient_device_id,
                                          stale_connection_id = target.id,
                                          ?target.device_id,
                                          "peer delivery failed; removed stale registry entry"
                                      );
                                  }
                              }
                          }

                          if delivered_count > 0 {
                              let ack = encode_send_ack(
                                  true,
                                  false,
                                  message_id.unwrap_or(0),
                                  SendRejectReason::Unspecified,
                              );
                              framed.send_frame(&ack).await?;
                              messages_delivered_online += delivered_count as u64;
                              observability::observe_message_route(match recipient_device_id {
                                  Some(_) => "online_device",
                                  None => "online",
                              });
                              debug!(
                                  sender = %hex::encode(user_id),
                                  recipient = %hex::encode(recipient),
                                  ?recipient_device_id,
                                  ?message_id,
                                  delivered_count,
                                  size = body.len(),
                                  delivery_method = "online",
                                  "message handed to online recipient sessions"
                              );
                          } else {
                              if enqueue_result.stored {
                                  // Сюда доходит, только когда ни одна сессия
                                  // получателя уведомления не приняла, — будить
                                  // некого исключать.
                                  trigger_offline_pushes(
                                      &push_tokens,
                                      &push_scheduler,
                                      recipient,
                                      recipient_device_id,
                                      priority,
                                      wake_hint,
                                      &[],
                                  );
                              }
                              handle_offline_enqueue_result(
                                  &mut framed,
                                  &user_id,
                                  &recipient,
                                  recipient_device_id,
                                  body.len(),
                                  enqueue_result,
                                  depth_before,
                                  &mut messages_queued,
                              ).await?;
                          }
                      }
                  }
                  ClientFrame::DeliveryAck { message_id } => {
                      let acked = match sled.as_mut() {
                          Some(session) => match session.ack(message_id) {
                              Ok(acked) => acked,
                              Err(err) => {
                                  return close_on_storage_failure(&mut framed, user_id, device_id, &err)
                                      .await;
                              }
                          },
                          None => {
                              delivery_backend
                                  .ack_delivery(user_id, device_id, message_id)
                                  .await?
                          }
                      };
                      if acked {
                          debug!(
                              user = %hex::encode(user_id),
                              ?device_id,
                              message_id,
                              "delivery acknowledged by client"
                          );
                      } else {
                          debug!(
                              user = %hex::encode(user_id),
                              ?device_id,
                              message_id,
                              "ignoring unmatched delivery ack"
                          );
                      }
                  }
                  ClientFrame::Ping => {
                      observability::observe_ping();
                      if !ping_gate.allow(unix_now_secs()) {
                          observability::observe_ping_dropped();
                          debug!(
                              user = %hex::encode(user_id),
                              limit = limits.cfg.ping_per_sec,
                              "ping rate limit exceeded; pong suppressed"
                          );
                          continue;
                      }
                      debug!(user = %hex::encode(user_id), "ping received; sending pong");
                      let pong = encode_pong();
                      framed.send_frame(&pong).await?;
                      observability::observe_pong();
                  }
                  ClientFrame::GetServerConfig => {
                      let response =
                          encode_signed_server_config(&server_config, &node, unix_now_secs());
                      framed.send_frame(&response).await?;
                      debug!(user = %hex::encode(user_id), "sent server config to authenticated client");
                  }
                  ClientFrame::RegisterPushToken { token, platform } => {
                      // Платформа обязательна: по ней выбирается слот токена (FCM или VoIP).
                      // Незаполненное поле или значение из будущей схемы —
                      // отказ в ack, а не молчаливый выбор Android.
                      let platform = PushPlatform::from_wire(platform)
                          .inspect_err(|err| {
                              warn!(
                                  user = %hex::encode(user_id),
                                  ?device_id,
                                  error = %err,
                                  "push token registration carries an unknown platform"
                              );
                          })
                          .ok();
                      let ack = match (device_id, platform) {
                          (None, _) => encode_push_token_ack(
                              false,
                              "device_id is required to register a push token",
                          ),
                          (_, None) => encode_push_token_ack(false, "unknown push platform"),
                          (Some(current_device_id), Some(platform)) => register_push_token(
                              &push_tokens,
                              &push_scheduler,
                              limits.cfg.max_push_devices_per_user,
                              &user_id,
                              current_device_id,
                              platform,
                              &token,
                          ),
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::UnregisterPushToken => {
                      let ack = match device_id {
                          None => encode_push_token_ack(
                              false,
                              "device_id is required to unregister a push token",
                          ),
                          Some(current_device_id) => {
                              // Логаут/disable снимает оба слота устройства
                              // (alert + voip) — иначе после логаута телефон
                              // продолжит звонить на мёртвую сессию.
                              match push_tokens.remove_all(&user_id, current_device_id) {
                                  Ok(removed) => {
                                      debug!(
                                          user = %hex::encode(user_id),
                                          device_id = current_device_id,
                                          removed,
                                          "push token unregistered"
                                      );
                                      encode_push_token_ack(true, "")
                                  }
                                  Err(err) => {
                                      warn!(
                                          user = %hex::encode(user_id),
                                          device_id = current_device_id,
                                          error = %err,
                                          "push token unregister failed"
                                      );
                                      encode_push_token_ack(false, "internal error")
                                  }
                              }
                          }
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::AllocateQueue {
                      tag,
                      expires_at,
                      revoked,
                  } => {
                      let now = unix_now_secs();
                      let ack = match AllocateParams::parse(&tag, expires_at, revoked, now) {
                          Err(err) => queue_reject(err),
                          Ok(params) => {
                              // С тегом id считает нода, и в нём владелец:
                              // чужой id тегом не назвать. Без тега — 32
                              // байта из CSPRNG: не перебрать, а знание id
                              // и есть право писать в очередь.
                              let queue_id = match params.tag {
                                  Some(tag) => Ok(derive_queue_id(&user_id, &tag)),
                                  None => {
                                      let mut random = [0u8; 32];
                                      getrandom::fill(&mut random).map(|()| random)
                                  }
                              };
                              match queue_id {
                                  Err(err) => {
                                      warn!(
                                          user = %hex::encode(user_id),
                                          error = %err,
                                          "failed to read random bytes for a queue id"
                                      );
                                      encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                                  }
                                  Ok(queue_id) => {
                                      match queues.allocate(&user_id, queue_id, params, now, max_queues) {
                                          Ok(Ok(record)) => {
                                              debug!(
                                                  user = %hex::encode(user_id),
                                                  queue = %queue_fingerprint(&record.queue_id),
                                                  derived = params.tag.is_some(),
                                                  tombstone = record.is_tombstone(),
                                                  expires_at = record.expires_at_secs,
                                                  "queue allocated"
                                              );
                                              encode_queue_ack(
                                                  true,
                                                  Some(record.queue_id),
                                                  WireQueueRejectReason::Unspecified,
                                              )
                                          }
                                          Ok(Err(err)) => queue_reject(err),
                                          Err(err) => {
                                              warn!(
                                                  user = %hex::encode(user_id),
                                                  error = %err,
                                                  "queue allocation failed"
                                              );
                                              encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                                          }
                                      }
                                  }
                              }
                          }
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::RevokeQueue { queue_id } => {
                      // Неверная длина и чужая очередь дают один и тот же
                      // ответ, что и несуществующая: иначе отзыв становится
                      // оракулом «такая очередь есть, но не твоя», а это
                      // подсказка для перебора права на запись.
                      let ack = match decode_queue_id(&queue_id) {
                          None => encode_queue_ack(false, None, WireQueueRejectReason::NotFound),
                          Some(queue_id) => match queues.revoke(&user_id, &queue_id, unix_now_secs()) {
                              Ok(Ok(())) => {
                                  debug!(
                                      user = %hex::encode(user_id),
                                      queue = %queue_fingerprint(&queue_id),
                                      "queue revoked"
                                  );
                                  encode_queue_ack(true, None, WireQueueRejectReason::Unspecified)
                              }
                              Ok(Err(err)) => queue_reject(err),
                              Err(err) => {
                                  warn!(
                                      user = %hex::encode(user_id),
                                      error = %err,
                                      "queue revocation failed"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                              }
                          },
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::ListQueues => {
                      let now = unix_now_secs();
                      let listed = queues.list(&user_id, now).and_then(|records| {
                          let queue_only = queues.is_queue_only(&user_id)?;
                          let account_record = queues.account_record(&user_id)?;
                          let revocations =
                              cert_revocations.list(&user_id, now, device_cert_max_ttl_secs)?;
                          Ok((records, queue_only, account_record, revocations))
                      });
                      let response = match listed {
                          Ok((records, queue_only, account_record, revocations)) => {
                              let list = encode_queue_list(&QueueListing {
                                  records: &records,
                                  queue_only,
                                  account_record: account_record.as_ref(),
                                  revocations: &revocations,
                              });
                              // Список с надгробиями растёт до ~0,4 МБ (1024
                              // живых и 8192 надгробия). Если оператор опустил
                              // MAX_FRAME_LEN ниже, кадр не записать — отказ
                              // вместо разрыва сессии, который клиент принял
                              // бы за сбой сети и повторял бы по кругу.
                              if list.len() > framed.max_frame_len() {
                                  error!(
                                      user = %hex::encode(user_id),
                                      records = records.len(),
                                      size = list.len(),
                                      max_frame_len = framed.max_frame_len(),
                                      "queue list does not fit max_frame_len; answering with a reject"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                              } else {
                                  list
                              }
                          }
                          Err(err) => {
                              warn!(
                                  user = %hex::encode(user_id),
                                  error = %err,
                                  "queue listing failed"
                              );
                              // Список — единственная операция без ack'а
                              // своего вида, поэтому отказ едет как QueueAck:
                              // клиент обязан различать их по типу кадра, а
                              // не по факту ответа.
                              encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                          }
                      };
                      framed.send_frame(&response).await?;
                  }
                  ClientFrame::SetQueueOnly { enabled } => {
                      // Со снятой адресацией по очередям режим не действовал
                      // бы, а клиент считал бы себя защищённым. Честнее
                      // отказать и не трогать флаг.
                      let ack = if !server_config.supports_queue_only() {
                          encode_queue_ack(false, None, WireQueueRejectReason::Unsupported)
                      } else {
                          match queues.set_queue_only(&user_id, enabled, unix_now_secs()) {
                              Ok(()) => {
                                  debug!(
                                      user = %hex::encode(user_id),
                                      ?device_id,
                                      enabled,
                                      "queue-only mode changed"
                                  );
                                  encode_queue_ack(true, None, WireQueueRejectReason::Unspecified)
                              }
                              Err(err) => {
                                  warn!(
                                      user = %hex::encode(user_id),
                                      error = %err,
                                      "failed to change the queue-only mode"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                              }
                          }
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::SetAccountRecord {
                      record,
                      expected_version,
                  } => {
                      // Содержимое записи не логируется: ноде оно
                      // непрозрачно, и лишняя копия шифротекста в логах
                      // никому не нужна.
                      let ack = match queues.set_account_record(&user_id, &record, expected_version) {
                          Ok(Ok(version)) => {
                              debug!(
                                  user = %hex::encode(user_id),
                                  ?device_id,
                                  version,
                                  size = record.len(),
                                  "account record replaced"
                              );
                              encode_queue_ack(true, None, WireQueueRejectReason::Unspecified)
                          }
                          Ok(Err(err)) => {
                              debug!(
                                  user = %hex::encode(user_id),
                                  ?device_id,
                                  expected_version,
                                  size = record.len(),
                                  reason = ?err,
                                  "account record replacement refused"
                              );
                              queue_reject(err)
                          }
                          Err(err) => {
                              warn!(
                                  user = %hex::encode(user_id),
                                  error = %err,
                                  "failed to write the account record"
                              );
                              encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                          }
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::RevokeDeviceCerts {
                      device_id: revoked_device,
                      issued_before,
                      all,
                  } => {
                      let now = unix_now_secs();
                      let ack = match cert_revocations::validate(
                          revoked_device,
                          issued_before,
                          all,
                          now,
                          device_cert_max_ttl_secs,
                      ) {
                          Err(_) => encode_queue_ack(false, None, WireQueueRejectReason::Invalid),
                          Ok(revocation_request) => match cert_revocations.revoke(
                              &user_id,
                              revocation_request,
                              now,
                              device_cert_max_ttl_secs,
                          ) {
                              Ok(Ok(())) => {
                                  // Отзыв уже записан: сессия, которая
                                  // зарегистрируется после обхода, увидит его
                                  // своей проверкой.
                                  let closed = registry.revoke_delegated(
                                      &user_id,
                                      revocation_request.device_id,
                                      revocation_request.issued_before,
                                  );
                                  // Пуш-токены устройства тоже уходят: будить
                                  // украденный телефон незачем, а токен в
                                  // руках вора — канал наблюдения за
                                  // активностью аккаунта.
                                  let tokens_removed = push_tokens
                                      .remove_all(&user_id, revocation_request.device_id)
                                      .unwrap_or_else(|err| {
                                          warn!(
                                              user = %hex::encode(user_id),
                                              revoked_device_id = revocation_request.device_id,
                                              error = %err,
                                              "failed to remove push tokens of a revoked device"
                                          );
                                          false
                                      });
                                  info!(
                                      user = %hex::encode(user_id),
                                      revoked_device_id = revocation_request.device_id,
                                      closed_sessions = closed,
                                      tokens_removed,
                                      "device certificates revoked"
                                  );
                                  encode_queue_ack(true, None, WireQueueRejectReason::Unspecified)
                              }
                              Ok(Err(RevocationError::Limit)) => {
                                  warn!(
                                      user = %hex::encode(user_id),
                                      revoked_device_id = revocation_request.device_id,
                                      "device certificate revocation refused: limit reached"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Limit)
                              }
                              Ok(Err(RevocationError::Invalid)) => {
                                  encode_queue_ack(false, None, WireQueueRejectReason::Invalid)
                              }
                              Err(err) => {
                                  warn!(
                                      user = %hex::encode(user_id),
                                      error = %err,
                                      "failed to store a device certificate revocation"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                              }
                          },
                      };
                      framed.send_frame(&ack).await?;
                  }
                  ClientFrame::Ignore => {
                      debug!(user = %hex::encode(user_id), "ignoring unsupported frame");
                  }
              }
          }

          outgoing = rx_to_client.recv() => {
              // Отправитель канала есть только у реестра, поэтому `None` —
              // это выписка сессии из реестра: новых сообщений в неё не
              // будет, а всё принятое в канал уже отдано. Разрыв заставит
              // клиента переподключиться и забрать остальное из офлайн-очереди.
              let Some(outgoing) = outgoing else {
                  // Отзыв тоже выписывает сессию из реестра, и закрытый
                  // канал может прийти раньше сигнала отзыва: клиент должен
                  // узнать о 403, а не о разрыве.
                  if revocation.is_revoked() {
                      return close_revoked_session(
                          &mut framed,
                          &user_id,
                          device_id,
                          &mut rx_to_client,
                          "live",
                      )
                      .await;
                  }
                  warn!(
                      user = %hex::encode(user_id),
                      ?device_id,
                      connection_id = registration.connection_id,
                      "closing session: it was evicted from the connection registry"
                  );
                  break;
              };
              // Ни одного кадра отозванной сессии: всё, что ещё лежит в её
              // канале, ей не отдаётся (записи прямого бэкенда остаются в
              // очередях, брокерный вернёт неподтверждённое в поток при
              // отключении).
              if revocation.is_revoked() {
                  return close_revoked_session(
                      &mut framed,
                      &user_id,
                      device_id,
                      &mut rx_to_client,
                      "live",
                  )
                  .await;
              }
              let size = outgoing.bytes.len();
              let sender_hex = outgoing.sender_user_id.map(hex::encode);
              debug!(
                  recipient = %hex::encode(user_id),
                  recipient_device_id = ?device_id,
                  sender = ?sender_hex,
                  sender_device_id = ?outgoing.sender_device_id,
                  message_id = ?outgoing.message_id,
                  size,
                  "forwarding envelope to recipient TCP socket"
              );
              // Страховка: кадр длиннее потолка `send_frame` отвергает
              // ошибкой, и раньше она закрывала сессию получателя — один
              // негабаритный конверт рвал её при каждой доставке. Штатно
              // такой кадр сюда не доходит: тело ограничено на входе, а
              // пул доставки снимает негабаритный конверт с потока сам.
              if size > framed.max_frame_len() {
                  observability::observe_oversized_envelope("session");
                  error!(
                      recipient = %hex::encode(user_id),
                      recipient_device_id = ?device_id,
                      sender = ?sender_hex,
                      message_id = ?outgoing.message_id,
                      size,
                      max_frame_len = framed.max_frame_len(),
                      "outbound frame exceeds max_frame_len; dropped, session kept"
                  );
                  continue;
              }
              // Уведомление прямого бэкенда: запись уже лежит в очереди
              // получателя, и решает окно подтверждений — отдать сейчас,
              // пропустить (уже отдана или снята) или отложить до места в
              // окне. Брокерные конверты и кадры без `message_id` идут как
              // есть.
              let written = match (sled.as_mut(), outgoing.message_id) {
                  (Some(session), Some(message_id)) => {
                      let scope = outgoing
                          .target_device_id
                          .map_or(InboxScope::Account, InboxScope::Device);
                      if session.offer(scope, message_id) != Offer::Accept {
                          continue;
                      }
                      match deliver_stored(&mut framed, session, scope, message_id, &outgoing.bytes)
                          .await
                      {
                          Ok(true) => Ok(()),
                          Ok(false) => continue,
                          Err(DeliverError::Io(err)) => Err(err),
                          Err(DeliverError::Storage(err)) => {
                              return close_on_storage_failure(&mut framed, user_id, device_id, &err)
                                  .await;
                          }
                      }
                  }
                  _ => framed.send_frame(&outgoing.bytes).await,
              };
              if let Err(err) = written {
                  if is_connection_reset(&err) {
                      observability::observe_connection_reset_by_peer();
                  }
                  // Запись прямого бэкенда остаётся в очереди и дойдёт
                  // следующей сессией; брокерный конверт вернёт поток.
                  warn!(
                      recipient = %hex::encode(user_id),
                      recipient_device_id = ?device_id,
                      sender = ?sender_hex,
                      message_id = ?outgoing.message_id,
                      size,
                      error = %err,
                      "TCP write to recipient failed; the envelope stays undelivered on this connection"
                  );
                  return Err(err.into());
              }
              messages_sent += 1;
              observability::observe_message_route("server_push");
              debug!(
                  recipient = %hex::encode(user_id),
                  recipient_device_id = ?device_id,
                  sender = ?sender_hex,
                  message_id = ?outgoing.message_id,
                  size,
                  "envelope written to recipient TCP socket"
              );

              // Кадр-извещение о том, что сессия больше не обслуживается
              // (умер пул доставки). Он уже записан; дальше держать
              // соединение нельзя — именно ради разрыва он и посылался.
              if outgoing.close_after_send {
                  warn!(
                      user = %hex::encode(user_id),
                      ?device_id,
                      connection_id = registration.connection_id,
                      "closing session: delivery for it is no longer running"
                  );
                  break;
              }
          }

          () = wait_until(ack_deadline), if ack_deadline.is_some() => {
              if let Some(session) = sled.as_mut()
                  && let Err(err) = session.expire(tokio::time::Instant::now())
              {
                  return close_on_storage_failure(&mut framed, user_id, device_id, &err).await;
              }
          }

          () = resync.notified(), if sled.is_some() => {
              if let Some(session) = sled.as_mut() {
                  session.resync();
              }
          }

          () = std::future::ready(()), if pull_ready => {
              let Some(session) = sled.as_mut() else { continue };
              let mut counters = BacklogCounters {
                  delivered: &mut messages_delivered_offline,
                  failed: &mut messages_failed,
              };
              match deliver_backlog(
                  &mut framed,
                  &storage,
                  session,
                  &user_id,
                  device_id,
                  &revocation,
                  cert_not_after,
                  &mut counters,
              )
              .await
              {
                  Ok(BacklogOutcome::Delivered) => {}
                  Ok(BacklogOutcome::Revoked) => {
                      return close_revoked_session(
                          &mut framed,
                          &user_id,
                          device_id,
                          &mut rx_to_client,
                          "live",
                      )
                      .await;
                  }
                  Ok(BacklogOutcome::Expired) => break 'session,
                  Err(DeliverError::Io(err)) => return Err(err.into()),
                  Err(DeliverError::Storage(err)) => {
                      return close_on_storage_failure(&mut framed, user_id, device_id, &err).await;
                  }
              }
          }

          () = &mut cert_expiry => {
              info!(
                  user = %hex::encode(user_id),
                  ?device_id,
                  "device certificate expired; closing delegated session"
              );
              break;
          }
        }
    }

    info!(
        user = %hex::encode(user_id),
        ?device_id,
        connection_id = registration.connection_id,
        protocol_version = protocol_version.min(PROTO_VERSION),
        messages_sent,
        messages_queued,
        frames_received,
        messages_delivered_online,
        messages_delivered_offline,
        messages_failed,
        messages_rejected,
        "client disconnected - session summary"
    );
    Ok(())
}

/// Fire push notifications for any of the recipient's devices that did **not**
/// receive the message through a live TCP session.
///
/// Behaviour parallels `JetStreamBackend::trigger_push_for_offline`:
/// device-scope triggers for the one device; account-scope fans out to every
/// device we know a push token for. `online_devices` holds the `device_id`s
/// that currently have a live session — they are skipped so we never push to a
/// device that is already receiving the message over TCP.
///
/// Callers:
/// * Sled backend — only after a message was actually persisted
///   (`EnqueueResult::stored == true`) and `route_targets` was empty, so it
///   passes an empty `online_devices` slice.
/// * JetStream backend — at publish time, passing the device_ids that
///   currently hold a live session.
fn trigger_offline_pushes(
    push_tokens: &PushTokenStore,
    push_scheduler: &PushScheduler,
    recipient: [u8; 32],
    recipient_device_id: Option<DeviceId>,
    priority: Option<MessagePriority>,
    wake_hint: Option<WakeHint>,
    online_devices: &[DeviceId],
) {
    match recipient_device_id {
        Some(device) => {
            if !online_devices.contains(&device) {
                push_scheduler.on_undelivered(recipient, device, priority, wake_hint);
            }
        }
        None => match push_tokens.list_user(&recipient) {
            Ok(devices) => {
                for stored in devices {
                    if !online_devices.contains(&stored.device_id) {
                        push_scheduler.on_undelivered(
                            recipient,
                            stored.device_id,
                            priority,
                            wake_hint,
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    recipient = %hex::encode(recipient),
                    error = %err,
                    "failed to list push tokens for offline enqueue fan-out"
                );
            }
        },
    }
}

/// Дешёвая валидация депозита до публикации. `Some(reason)` — кадр
/// принимать нельзя, клиенту уходит `SendAck { ok: false, reason }`.
///
/// Порядок проверок значим: детерминированная валидация размера и ttl идёт
/// перед rate-limit'ом, иначе поток заведомо невалидных кадров выжигал бы
/// секундный и суточный бюджет пользователя (успешный `check_at` списывает
/// бюджет, отказ — нет).
///
/// `max_body_len` — потолок тела (`framing::max_send_body_len`). Кадр
/// `ClientSend` уже уложился в `max_frame_len`, иначе он не был бы
/// прочитан; но получателю тело уходит в `IncomingMessage`, у которого
/// служебных полей больше. Тело, не оставляющее под них места, нельзя
/// доставить вовсе, поэтому его нельзя и принимать.
///
/// `ttl_seconds == 0` — «не указан» (клиенты без node-header v3): действует
/// только глобальная retention-политика ноды, пол не применяется.
fn precheck_send(
    limits: &SessionLimits,
    user_id: &UserId,
    body_len: usize,
    ttl_seconds: u64,
    now_secs: u64,
    max_body_len: usize,
) -> Option<SendRejectReason> {
    if body_len > max_body_len {
        return Some(SendRejectReason::TooLarge);
    }

    if limits.cfg.ttl_min_seconds > 0 && ttl_seconds > 0 && ttl_seconds < limits.cfg.ttl_min_seconds
    {
        return Some(SendRejectReason::InvalidTtl);
    }

    if !limits.send.check_at(user_id, body_len, now_secs) {
        return Some(SendRejectReason::RateLimited);
    }

    None
}

/// Квоты офлайн-очереди прямого бэкенда: общий потолок очереди (записей и
/// байт) плюс под-квота одного отправителя на пару sender→recipient. Каждый
/// лимит `0` = не ограничен; если выключены все три, скан не выполняется.
///
/// Проверка идёт до вставки, поэтому очередь может превысить лимит ровно на
/// одно сообщение при гонке двух отправителей — как и лимит сессий, это
/// best-effort защита ресурса, а не бухгалтерия.
fn queue_quota_reason(
    storage: &Storage,
    limits: &SessionLimits,
    recipient: &UserId,
    recipient_device_id: Option<DeviceId>,
    sender: &UserId,
) -> Result<QuotaVerdict> {
    let cfg = &limits.cfg;
    let ceilings = QueueQuotaCeilings {
        messages: cfg.max_messages_per_queue as u64,
        bytes: cfg.max_bytes_per_queue,
        from_sender: cfg.max_messages_sender_pair as u64,
    };

    if ceilings.messages == 0 && ceilings.bytes == 0 && ceilings.from_sender == 0 {
        return Ok(QuotaVerdict {
            reason: None,
            depth_before: None,
        });
    }

    let scan = storage.scan_queue_quota(recipient, recipient_device_id, sender, ceilings)?;
    let reason = if (ceilings.messages > 0 && scan.messages >= ceilings.messages)
        || (ceilings.bytes > 0 && scan.bytes >= ceilings.bytes)
        || (ceilings.from_sender > 0 && scan.from_sender >= ceilings.from_sender)
    {
        Some(SendRejectReason::Full)
    } else {
        None
    };

    Ok(QuotaVerdict {
        reason,
        // Глубину знает уже сделанный скан; отдельный подсчёт ради строчки
        // лога стоил бы ещё одного полного прохода по очереди.
        depth_before: (!scan.truncated).then_some(scan.messages),
    })
}

/// Ответ квоты плюс глубина очереди, посчитанная попутно.
struct QuotaVerdict {
    reason: Option<SendRejectReason>,
    /// `None`, если скан не выполнялся или остановился досрочно — тогда
    /// число было бы нижней границей и вводило бы в заблуждение.
    depth_before: Option<u64>,
}

/// Регистрация push-токена устройства сессии; возвращает готовый
/// `PushTokenAck`.
///
/// Приветственный пуш — один на всё время жизни аккаунта: его выдаёт
/// [`PushTokenStore::claim_welcome`], а не переход «токенов не было → есть»,
/// иначе цикл Register/Unregister будил бы приветствием на каждом круге.
/// Отметку получает и аккаунт, у которого токены уже были до появления
/// отметок, — но без приветствия: своё он уже получил. Регистрация
/// VoIP-токена (второго токена iOS-устройства) приветствия не трогает: оно
/// уходит только по alert-каналу.
fn register_push_token(
    push_tokens: &PushTokenStore,
    push_scheduler: &PushScheduler,
    max_devices: usize,
    user_id: &UserId,
    device_id: DeviceId,
    platform: PushPlatform,
    token: &str,
) -> Vec<u8> {
    // Снимок до записи. Не прочитался — приветствие пропускается: лишнее
    // хуже пропущенного.
    let had_tokens = if platform == PushPlatform::IosVoip {
        None
    } else {
        match push_tokens.has_any_for_user(user_id) {
            Ok(has_any) => Some(has_any),
            Err(err) => {
                warn!(
                    user = %hex::encode(user_id),
                    error = %err,
                    "could not check prior push tokens; skipping welcome push"
                );
                None
            }
        }
    };

    match push_tokens.register(user_id, device_id, platform, token, max_devices) {
        Ok(RegisterOutcome::Stored) => {
            debug!(
                user = %hex::encode(user_id),
                device_id,
                ?platform,
                "push token registered"
            );
            if let Some(had_tokens) = had_tokens {
                match push_tokens.claim_welcome(user_id) {
                    Ok(true) if !had_tokens => {
                        debug!(
                            user = %hex::encode(user_id),
                            device_id,
                            "first push token of the account; firing welcome push"
                        );
                        push_scheduler.send_welcome(*user_id, device_id);
                    }
                    Ok(_) => {}
                    Err(err) => warn!(
                        user = %hex::encode(user_id),
                        error = %err,
                        "could not claim the welcome push; skipping it"
                    ),
                }
            }
            encode_push_token_ack(true, "")
        }
        Ok(RegisterOutcome::InvalidToken) => encode_push_token_ack(false, "invalid token"),
        Ok(RegisterOutcome::DeviceLimit) => {
            warn!(
                user = %hex::encode(user_id),
                device_id,
                limit = max_devices,
                "push token registration rejected: device limit reached"
            );
            encode_push_token_ack(false, "push device limit reached")
        }
        Err(err) => {
            warn!(
                user = %hex::encode(user_id),
                device_id,
                error = %err,
                "push token registration failed"
            );
            encode_push_token_ack(false, "internal error")
        }
    }
}

/// Лимит одновременных сессий на ключ: исчерпан — клиенту уходит
/// `AuthError(401)`, и соединение закрывается ошибкой.
///
/// Проверяется дважды: до `AuthOk` (основной случай — отказ вместо него) и
/// перед регистрацией подтверждённой сессии. Во втором случае 401 приходит
/// уже после `AuthOk`: пока клиент подтверждал сессию, лимит выбрали другие
/// его сессии.
async fn refuse_over_session_limit(
    framed: &mut NoiseFramed<TcpStream>,
    registry: &ConnRegistry,
    limits: &SessionLimits,
    user_id: &UserId,
) -> Result<()> {
    let limit = limits.cfg.max_sessions_per_user;
    if limit == 0 || registry.session_count(user_id) < limit {
        return Ok(());
    }
    observability::observe_reject("session_limit");
    observability::observe_connection_auth("limit");
    let err_frame = encode_auth_error(401, "session limit exceeded");
    send_final_frame(framed, &err_frame).await?;
    warn!(
        user = %hex::encode(user_id),
        limit,
        "connection rejected: session limit exceeded"
    );
    bail!("session limit exceeded")
}

/// Дождаться кадра, которым клиент подтверждает сессию. `Some` — кадр
/// расшифрован и разобран; обработать его ещё предстоит, первым в цикле
/// сессии. `None` — подтверждения не будет (таймаут, разрыв, кадр не
/// расшифровался): соединение закрывается, не оставив следа ни в реестре,
/// ни в очередях.
///
/// Неподтверждённая сессия — отказ, а не сбой ноды (именно так кончается
/// повтор записанного msg1), поэтому наверх уходит `Ok`, как и при отказе
/// на хендшейке.
async fn await_session_confirmation(
    framed: &mut NoiseFramed<TcpStream>,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    within: Duration,
) -> Result<Option<BytesMut>> {
    let (reason, error) = match tokio::time::timeout(within, framed.next_frame()).await {
        Ok(Ok(Some(bytes))) => {
            // Кадр расшифровался — ключи сессии у клиента есть. Неразбираемый
            // кадр — уже не повтор, а сломанный клиент, и с ним поступаем
            // так же, как цикл сессии.
            if let Err(err) = decode_frame(bytes.as_ref()) {
                observability::observe_frame_decode_error();
                warn!(
                    user = %hex::encode(user_id),
                    size = bytes.len(),
                    error = %err,
                    "failed to decode frame"
                );
                return Err(err);
            }
            return Ok(Some(bytes));
        }
        Ok(Ok(None)) => ("closed", None),
        Ok(Err(err)) => {
            if is_connection_reset(&err) {
                observability::observe_connection_reset_by_peer();
            }
            ("unreadable", Some(err))
        }
        Err(_) => ("timeout", None),
    };
    observability::observe_connection_auth("unconfirmed");
    let error = error.as_ref().map(tracing::field::display);
    info!(
        user = %hex::encode(user_id),
        ?device_id,
        reason,
        error,
        "session not confirmed by the client; closing"
    );
    Ok(None)
}

/// Следующий кадр клиента. Подтвердивший сессию кадр прочитан ещё до
/// регистрации и отдаётся первым, дальше — чтение из канала.
///
/// Cancel-safe, как и `NoiseFramed::next_frame`: отложенный кадр забирается
/// только при первом опросе, который сразу же и завершается.
async fn next_client_frame(
    framed: &mut NoiseFramed<TcpStream>,
    confirming_frame: &mut Option<BytesMut>,
) -> std::io::Result<Option<BytesMut>> {
    match confirming_frame.take() {
        Some(frame) => Ok(Some(frame)),
        None => framed.next_frame().await,
    }
}

/// Момент `unix_secs` на монотонных часах рантайма. Прошедший момент —
/// «сейчас»; недостижимо далёкий ограничивается сверху, чтобы не
/// переполнить `Instant`.
fn instant_at_unix_secs(unix_secs: u64) -> tokio::time::Instant {
    const FAR: Duration = Duration::from_secs(100 * 365 * 24 * 3600);
    let remaining = match UNIX_EPOCH.checked_add(Duration::from_secs(unix_secs)) {
        Some(at) => at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO),
        None => FAR,
    };
    tokio::time::Instant::now() + remaining.min(FAR)
}

/// Хранилище не отвечает на входе сессии — прочитать офлайн-очередь нечем.
///
/// Просто оборвать соединение нельзя: разрыв неотличим от сетевого сбоя, и
/// клиент переподключится немедленно — в ту же неработающую ноду, и так по
/// кругу. Явный `AuthError(503)` говорит ему, что дело не в сети, и
/// переводит на backoff; код тот же, что при недоступной доставке.
///
/// Цикл сессии при этом не запускается: пропустить реплей и работать
/// дальше значило бы молча не отдать уже принятые сообщения.
async fn refuse_storage_unavailable(
    framed: &mut NoiseFramed<TcpStream>,
    user_id: UserId,
    device_id: Option<DeviceId>,
    err: &anyhow::Error,
) -> Result<()> {
    observability::observe_reject("storage_unavailable");
    observability::observe_connection_auth("unavailable");
    error!(
        user = %hex::encode(user_id),
        ?device_id,
        error = %err,
        "storage unavailable; refusing the session"
    );
    let err_frame = encode_auth_error(503, "storage unavailable");
    send_final_frame(framed, &err_frame).await?;
    bail!("storage unavailable")
}

/// Отозван ли сертификат делегированной сессии: есть отзыв устройства с
/// `issued_before` позже `not_before` сертификата. Сессия ключом аккаунта
/// (`cert_not_before = None`) хранилище не читает.
fn is_cert_revoked(
    revocations: &CertRevocationStore,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    cert_not_before: Option<u64>,
) -> Result<bool> {
    let (Some(not_before), Some(device_id)) = (cert_not_before, device_id) else {
        return Ok(false);
    };
    Ok(revocations
        .revoked_since(user_id, device_id)?
        .is_some_and(|issued_before| not_before < issued_before))
}

/// Сертификат сессии отозван: `AuthError(403)` и закрытие. Код говорит
/// клиенту, что повтор с этим сертификатом бессмыслен, — в отличие от
/// разрыва, после которого он переподключался бы по кругу.
async fn refuse_revoked_cert(
    framed: &mut NoiseFramed<TcpStream>,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    stage: &'static str,
) -> Result<()> {
    observability::observe_device_cert_revoked_reject(stage);
    if stage != "live" {
        observability::observe_connection_auth("revoked");
    }
    info!(
        user = %hex::encode(user_id),
        ?device_id,
        stage,
        "device certificate revoked; closing delegated session"
    );
    let err_frame = encode_auth_error(403, "device certificate revoked");
    send_final_frame(framed, &err_frame).await
}

/// Сколько ждать записи последнего кадра перед закрытием (`AuthError`).
/// Клиент, переставший читать, не должен держать задачу сессии: кадр-отказ
/// — вежливость, а не условие закрытия.
const FINAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Записать последний кадр сессии с таймаутом; не успели — закрываемся
/// без него.
async fn send_final_frame(framed: &mut NoiseFramed<TcpStream>, bytes: &[u8]) -> Result<()> {
    match tokio::time::timeout(FINAL_FRAME_TIMEOUT, framed.send_frame(bytes)).await {
        Ok(written) => Ok(written?),
        Err(_) => {
            debug!("final frame was not written in time; closing without it");
            Ok(())
        }
    }
}

/// Закрыть сессию, чей сертификат отозван, ответом `AuthError(403)`.
///
/// Канал закрывается первым: конверт, который параллельный отправитель
/// успел направить в эту сессию, получает отказ записи и уходит
/// офлайн-путём у самого отправителя. Лежащее в канале просто
/// отбрасывается: на прямом бэкенде с хранением это уведомления о записях,
/// которые остаются в очередях до `DeliveryAck`, брокерные конверты вернутся
/// в поток при отключении, а без хранения (`immediate`) вернуть конверт
/// некуда.
async fn close_revoked_session(
    framed: &mut NoiseFramed<TcpStream>,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    rx_to_client: &mut mpsc::Receiver<OutboundFrame>,
    stage: &'static str,
) -> Result<()> {
    rx_to_client.close();
    while rx_to_client.try_recv().is_ok() {}
    refuse_revoked_cert(framed, user_id, device_id, stage).await
}

/// Отправить отказ и учесть его в `reject_total{reason=...}`. Отказ всегда
/// `ok = false, queued = false, queueId = 0` — сообщение не принято нигде.
async fn reject_send(framed: &mut NoiseFramed<TcpStream>, reason: SendRejectReason) -> Result<()> {
    observability::observe_reject(reason.as_metric_label());
    let ack = encode_send_ack(false, false, 0, reason);
    framed.send_frame(&ack).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_offline_enqueue_result(
    framed: &mut NoiseFramed<TcpStream>,
    sender_user_id: &[u8; 32],
    recipient: &[u8; 32],
    recipient_device_id: Option<DeviceId>,
    body_len: usize,
    enqueue_result: EnqueueResult,
    depth_before: Option<u64>,
    messages_queued: &mut u64,
) -> Result<()> {
    if enqueue_result.stored {
        *messages_queued += 1;
        observability::observe_message_route(match recipient_device_id {
            Some(_) => "offline_queue_device",
            None => "offline_queue",
        });
        let queue_depth = depth_before.map(|depth| depth + 1);
        let ack = encode_send_ack(
            false,
            true,
            enqueue_result.id,
            SendRejectReason::Unspecified,
        );
        framed.send_frame(&ack).await?;
        debug!(
            sender = %hex::encode(sender_user_id),
            recipient = %hex::encode(recipient),
            ?recipient_device_id,
            queue_id = enqueue_result.id,
            ?queue_depth,
            size = body_len,
            delivery_method = "offline_queue",
            "message successfully queued for recipient"
        );
    } else {
        observability::observe_message_route(match recipient_device_id {
            Some(_) => "offline_drop_device_policy",
            None => "offline_drop_policy",
        });
        // Дроп по retention-политике ноды — не квота и не rate-limit, поэтому
        // на проводе это родовой отказ (`unspecified`); в метрике причина
        // остаётся различимой.
        observability::observe_reject("retention_policy");
        let ack = encode_send_ack(false, false, 0, SendRejectReason::Unspecified);
        framed.send_frame(&ack).await?;
        warn!(
            sender = %hex::encode(sender_user_id),
            recipient = %hex::encode(recipient),
            ?recipient_device_id,
            size = body_len,
            delivery_method = "dropped_by_storage_policy",
            "message was not queued because offline retention policy is immediate"
        );
    }

    Ok(())
}

/// Почему не удалось отдать запись очереди.
enum DeliverError {
    /// Запись в сокет: сессия кончилась, запись осталась в очереди.
    Io(std::io::Error),
    /// Хранилище не ответило.
    Storage(anyhow::Error),
}

/// Отдать запись очереди прямого бэкенда через окно подтверждений.
/// `Ok(true)` — кадр записан в сокет; `Ok(false)` — записи уже нет
/// (подтверждена другой сессией, истекла), писать нечего.
async fn deliver_stored(
    framed: &mut NoiseFramed<TcpStream>,
    session: &mut SledSession,
    scope: InboxScope,
    message_id: u64,
    frame: &[u8],
) -> std::result::Result<bool, DeliverError> {
    let (last, redelivery) = match session
        .prepare(scope, message_id)
        .map_err(DeliverError::Storage)?
    {
        WriteDecision::Skip => return Ok(false),
        WriteDecision::Deliver { last, redelivery } => (last, redelivery),
    };
    framed.send_frame(frame).await.map_err(DeliverError::Io)?;
    // Повторная выдача никого не будит: пушей на этом пути нет вовсе,
    // разбудила уже приёмка конверта.
    if redelivery {
        observability::observe_message_redelivered();
    }
    session
        .written(scope, message_id, last)
        .map_err(DeliverError::Storage)?;
    Ok(true)
}

/// Счётчики сводки сессии, которые трогает дочитывание очередей.
struct BacklogCounters<'a> {
    delivered: &'a mut u64,
    failed: &'a mut u64,
}

/// Чем кончилась порция дочитывания.
enum BacklogOutcome {
    Delivered,
    /// Сертификат отозван — сессию закрывает `AuthError(403)`.
    Revoked,
    /// Сертификат истёк — сессия закрывается.
    Expired,
}

/// Дочитать порцию очередей сессии (не больше [`PULL_BATCH`] и места в
/// окне) и отдать её клиенту.
#[allow(clippy::too_many_arguments)]
async fn deliver_backlog(
    framed: &mut NoiseFramed<TcpStream>,
    storage: &Storage,
    session: &mut SledSession,
    user_id: &UserId,
    device_id: Option<DeviceId>,
    revocation: &SessionRevocation,
    cert_not_after: Option<u64>,
    counters: &mut BacklogCounters<'_>,
) -> std::result::Result<BacklogOutcome, DeliverError> {
    let batch = session.pull(PULL_BATCH).map_err(DeliverError::Storage)?;
    for (scope, message) in batch {
        // Перед каждой записью: отозванной или истёкшей сессии не уходит
        // ничего, остаток остаётся в очереди.
        if revocation.is_revoked() {
            return Ok(BacklogOutcome::Revoked);
        }
        if cert_not_after.is_some_and(|not_after| unix_now_secs() >= not_after) {
            info!(
                user = %hex::encode(user_id),
                ?device_id,
                "device certificate expired during offline delivery; closing delegated session"
            );
            return Ok(BacklogOutcome::Expired);
        }
        let frame = encode_incoming(
            message.sender_id,
            message.sender_device_id,
            message.id,
            &message.body,
            message.priority,
        );

        // Запись, которую нельзя доставить ни в одной сессии: кадр длиннее
        // потолка. Оставить её — значит пробовать заново при каждом
        // подключении и держать под неё квоту очереди до конца хранения.
        // Свежие записи такими не бывают (тело ограничено на входе); эта
        // принята раньше либо потолок кадра с тех пор снизили.
        if frame.len() > framed.max_frame_len() {
            observability::observe_oversized_envelope("offline_replay");
            *counters.failed += 1;
            error!(
                user = %hex::encode(user_id),
                sender = %hex::encode(message.sender_id),
                message_id = message.id,
                size = message.body.len(),
                max_frame_len = framed.max_frame_len(),
                "offline message does not fit max_frame_len; removing it from the queue"
            );
            if let Err(err) = storage.remove_inbox_record(user_id, scope, message.id) {
                warn!(
                    user = %hex::encode(user_id),
                    message_id = message.id,
                    error = %err,
                    "failed to remove an undeliverable offline message"
                );
            }
            continue;
        }

        match deliver_stored(framed, session, scope, message.id, &frame).await {
            Ok(true) => {
                *counters.delivered += 1;
                observability::observe_message_route(match scope {
                    InboxScope::Account => "offline_replay",
                    InboxScope::Device(_) => "offline_replay_device",
                });
                debug!(
                    user = %hex::encode(user_id),
                    sender = %hex::encode(message.sender_id),
                    message_id = message.id,
                    ?message.sender_device_id,
                    size = message.body.len(),
                    "delivered a queued message; awaiting DeliveryAck"
                );
            }
            Ok(false) => {}
            Err(DeliverError::Io(err)) => {
                if is_connection_reset(&err) {
                    observability::observe_connection_reset_by_peer();
                }
                warn!(
                    user = %hex::encode(user_id),
                    sender = %hex::encode(message.sender_id),
                    message_id = message.id,
                    error = %err,
                    "connection lost while delivering a queued message; it stays in the queue"
                );
                return Err(DeliverError::Io(err));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(BacklogOutcome::Delivered)
}

/// Хранилище перестало отвечать посреди сессии: отдавать и подтверждать
/// записи очередей нечем. `AuthError(503)` переводит клиента на backoff, как
/// и отказ на входе (см. [`refuse_storage_unavailable`]).
async fn close_on_storage_failure(
    framed: &mut NoiseFramed<TcpStream>,
    user_id: UserId,
    device_id: Option<DeviceId>,
    err: &anyhow::Error,
) -> Result<()> {
    observability::observe_reject("storage_unavailable");
    error!(
        user = %hex::encode(user_id),
        ?device_id,
        error = %format!("{err:#}"),
        "storage failed during the session; closing it"
    );
    send_final_frame(framed, &encode_auth_error(503, "storage unavailable")).await?;
    bail!("storage unavailable")
}

/// Дождаться срока; `None` — никогда.
async fn wait_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Отказ операции над очередью — `QueueAck` с причиной на проводе.
fn queue_reject(err: QueueError) -> Vec<u8> {
    let reason = match err {
        QueueError::Limit => WireQueueRejectReason::Limit,
        QueueError::NotFound => WireQueueRejectReason::NotFound,
        QueueError::Invalid => WireQueueRejectReason::Invalid,
        QueueError::Revoked => WireQueueRejectReason::Revoked,
        QueueError::Conflict => WireQueueRejectReason::Conflict,
    };
    encode_queue_ack(false, None, reason)
}

/// Node-header конверта v3: `queueId` из clientSend. `None` — для пустого
/// поля и для значения неверной длины: такой кадр не рвётся, а адресуется по
/// `recipientId`.
fn decode_queue_id(raw: &[u8]) -> Option<[u8; 32]> {
    match raw.len() {
        0 => None,
        32 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(raw);
            Some(id)
        }
        len => {
            debug!(len, "clientSend.queueId has unexpected length; ignoring");
            None
        }
    }
}

/// Метка исхода хендшейка для метрики. Значения стабильны — на них
/// строятся алерты «нода перестала пускать клиентов».
fn classify_handshake_error(message: &str) -> &'static str {
    if message.contains("timed out") {
        "timeout"
    } else if message.contains("magic") {
        "bad_magic"
    } else if message.contains("unsupported protocol version") {
        "unsupported_version"
    } else if message.contains("tofu handshake is disabled") {
        "tofu_disabled"
    } else if message.contains("unknown noise pattern") {
        "unknown_pattern"
    } else if message.contains("identity key does not match") {
        "identity_mismatch"
    } else {
        "rejected"
    }
}

fn is_connection_reset(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LimitsConfig, PushConfig, RetentionPolicy};
    use crate::push::{MockTransport, NoopStatePersistence, PushScheduler};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn fast_cfg() -> PushConfig {
        PushConfig {
            enabled: true,
            gateway_url: None,
            gateway_timeout: Duration::from_secs(10),
            fcm_project_id: String::new(),
            fcm_service_account_path: String::new(),
            http_timeout: Duration::from_secs(5),
            // High priority sends immediately (gap 0 / burst 1), so these tests
            // don't depend on the 120s none-priority coalescing window.
            min_gap_high: Duration::from_secs(0),
            min_gap_medium: Duration::from_millis(0),
            min_gap_low: Duration::from_secs(60),
            min_gap_none: Duration::from_secs(120),
            wake_on_unspecified: true,
            burst_high: 1,
            burst_medium: 3,
            burst_low: 8,
            burst_none: 15,
            suppress_initial: Duration::from_secs(1),
            suppress_max: Duration::from_secs(8),
            channel_capacity: 64,
            send_concurrency: crate::push::DEFAULT_SEND_CONCURRENCY,
            apns: None,
            ring_cooldown: Duration::from_secs(3),
        }
    }

    fn token_store_with(user: &[u8; 32], devices: &[(DeviceId, &str)]) -> Arc<PushTokenStore> {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let store = PushTokenStore::open(&db).unwrap();
        for (device, token) in devices {
            store
                .add(user, *device, PushPlatform::AndroidFcm, token)
                .unwrap();
        }
        Arc::new(store)
    }

    async fn collect_sent(transport: &MockTransport, want: usize) -> Vec<crate::push::PushPayload> {
        for _ in 0..100 {
            if transport.sent_payloads().len() >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        transport.sent_payloads()
    }

    /// An account-scope message fans the push out to every registered device
    /// that is not currently online, and skips the device that holds a live
    /// session.
    #[tokio::test]
    async fn account_scope_push_skips_online_device_and_wakes_offline() {
        let user = [9u8; 32];
        let tokens = token_store_with(&user, &[(10, "tok-online"), (20, "tok-offline")]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );

        // Device 10 is online; device 20 is offline. Account-scope (None).
        trigger_offline_pushes(
            &tokens,
            &scheduler,
            user,
            None,
            Some(MessagePriority::High),
            None,
            &[10],
        );

        let sent = collect_sent(&transport, 1).await;
        assert_eq!(sent.len(), 1, "only the offline device should be woken");
        assert_eq!(sent[0].device_id, 20);
        assert_eq!(sent[0].token, "tok-offline");
    }

    /// When nothing of the account is online, every registered device is woken.
    #[tokio::test]
    async fn account_scope_push_wakes_all_when_none_online() {
        let user = [8u8; 32];
        let tokens = token_store_with(&user, &[(10, "tok-a"), (20, "tok-b")]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );

        trigger_offline_pushes(
            &tokens,
            &scheduler,
            user,
            None,
            Some(MessagePriority::High),
            None,
            &[],
        );

        let sent = collect_sent(&transport, 2).await;
        let mut devices: Vec<DeviceId> = sent.iter().map(|p| p.device_id).collect();
        devices.sort_unstable();
        assert_eq!(devices, vec![10, 20]);
    }

    /// A device-scope message to an online device fires no push.
    #[tokio::test]
    async fn device_scope_push_suppressed_when_target_online() {
        let user = [7u8; 32];
        let tokens = token_store_with(&user, &[(5, "tok-5")]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );

        trigger_offline_pushes(
            &tokens,
            &scheduler,
            user,
            Some(5),
            Some(MessagePriority::High),
            None,
            &[5],
        );

        // Give the worker a chance to (not) send.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            transport.sent_payloads().is_empty(),
            "online target device must not be pushed"
        );
    }

    #[test]
    fn queue_id_decode_accepts_only_32_bytes() {
        assert_eq!(decode_queue_id(&[]), None);
        let mut id = [0u8; 32];
        id[..].copy_from_slice(&[9u8; 32]);
        assert_eq!(decode_queue_id(&[9u8; 32]), Some(id));
        assert_eq!(decode_queue_id(&[9u8; 31]), None);
        assert_eq!(decode_queue_id(&[9u8; 33]), None);
    }

    /// Node-header v3 аддитивен: кадр legacy-клиента без новых полей
    /// декодируется с queueId-по-умолчанию (пусто) и ttl = 0; кадр нового
    /// клиента читается целиком.
    #[test]
    fn client_send_v3_node_header_fields_are_additive() {
        let legacy = encode_client_send_frame(None, 0);
        let (legacy_queue, legacy_ttl) = parse_client_send_header(&legacy).unwrap();
        assert_eq!(legacy_queue, None);
        assert_eq!(legacy_ttl, 0);

        let v3 = encode_client_send_frame(Some([7u8; 32]), 3600);
        let (queue, ttl) = parse_client_send_header(&v3).unwrap();
        assert_eq!(queue, Some([7u8; 32]));
        assert_eq!(ttl, 3600);
    }

    fn encode_client_send_frame(queue_id: Option<[u8; 32]>, ttl_seconds: u64) -> Vec<u8> {
        use prost::Message;

        crate::wire::Frame {
            proto_version: PROTO_VERSION as u32,
            payload: Some(frame::Payload::ClientSend(crate::wire::ClientSend {
                recipient_id: vec![1u8; 32],
                body: b"payload".to_vec(),
                ttl_seconds,
                queue_id: queue_id.map(|id| id.to_vec()).unwrap_or_default(),
                ..crate::wire::ClientSend::default()
            })),
        }
        .encode_to_vec()
    }

    fn parse_client_send_header(bytes: &[u8]) -> anyhow::Result<(Option<[u8; 32]>, u64)> {
        let decoded = crate::net::framing::decode_frame(bytes)?;
        match decoded.payload {
            Some(frame::Payload::ClientSend(cmd)) => {
                Ok((decode_queue_id(&cmd.queue_id), cmd.ttl_seconds))
            }
            _ => anyhow::bail!("expected clientSend frame"),
        }
    }

    // ---- лимиты и квоты ----

    fn limits_with(cfg: LimitsConfig) -> SessionLimits {
        SessionLimits::new(cfg)
    }

    fn open_temp_storage(label: &str) -> (Storage, String) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("trust_message_tcp_conn_{label}_{nanos}"));
        let path = path.to_string_lossy().into_owned();
        let storage = Storage::open(
            &path,
            RetentionPolicy::KeepFor(Duration::from_secs(3600)),
            RetentionPolicy::KeepFor(Duration::from_secs(3600)),
        )
        .unwrap();
        (storage, path)
    }

    /// Тело сверх потолка отклоняется как `TooLarge`, на самом потолке
    /// проходит. Отказ не списывает бюджет отправителя: следующая посылка
    /// в том же окне проходит при лимите в одно сообщение в секунду.
    #[test]
    fn precheck_send_rejects_a_body_over_the_ceiling() {
        let limits = limits_with(LimitsConfig {
            send_msgs_per_sec: 1,
            send_bytes_per_day: 0,
            ..LimitsConfig::default()
        });
        let user = [3u8; 32];

        assert_eq!(
            precheck_send(&limits, &user, 101, 0, 1_000, 100),
            Some(SendRejectReason::TooLarge)
        );
        assert_eq!(precheck_send(&limits, &user, 100, 0, 1_000, 100), None);
    }

    /// ttl ниже пола ноды отвергается, ttl == 0 (legacy-клиент без
    /// node-header v3) проходит, ttl на самом полу проходит.
    #[test]
    fn precheck_send_enforces_ttl_floor() {
        let limits = limits_with(LimitsConfig {
            ttl_min_seconds: 86_400,
            send_msgs_per_sec: 0,
            send_bytes_per_day: 0,
            ..LimitsConfig::default()
        });
        let user = [1u8; 32];

        assert_eq!(
            precheck_send(&limits, &user, 10, 3_600, 1_000, usize::MAX),
            Some(SendRejectReason::InvalidTtl)
        );
        assert_eq!(
            precheck_send(&limits, &user, 10, 0, 1_000, usize::MAX),
            None
        );
        assert_eq!(
            precheck_send(&limits, &user, 10, 86_400, 1_000, usize::MAX),
            None
        );
        assert_eq!(
            precheck_send(&limits, &user, 10, 172_800, 1_000, usize::MAX),
            None
        );
    }

    /// Пол ttl == 0 отключает проверку целиком.
    #[test]
    fn precheck_send_ttl_floor_disabled_by_zero() {
        let limits = limits_with(LimitsConfig {
            ttl_min_seconds: 0,
            send_msgs_per_sec: 0,
            send_bytes_per_day: 0,
            ..LimitsConfig::default()
        });
        assert_eq!(
            precheck_send(&limits, &[2u8; 32], 10, 1, 1_000, usize::MAX),
            None
        );
    }

    #[test]
    fn precheck_send_enforces_rate_limit() {
        let limits = limits_with(LimitsConfig {
            ttl_min_seconds: 0,
            send_msgs_per_sec: 2,
            send_bytes_per_day: 0,
            ..LimitsConfig::default()
        });
        let user = [3u8; 32];

        assert_eq!(precheck_send(&limits, &user, 10, 0, 500, usize::MAX), None);
        assert_eq!(precheck_send(&limits, &user, 10, 0, 500, usize::MAX), None);
        assert_eq!(
            precheck_send(&limits, &user, 10, 0, 500, usize::MAX),
            Some(SendRejectReason::RateLimited)
        );
        // Новое секундное окно — бюджет снова есть.
        assert_eq!(precheck_send(&limits, &user, 10, 0, 501, usize::MAX), None);
    }

    /// Порядок проверок: невалидный ttl не должен списывать rate-бюджет,
    /// иначе поток заведомо битых кадров глушил бы честные отправки.
    #[test]
    fn precheck_send_invalid_ttl_does_not_consume_rate_budget() {
        let limits = limits_with(LimitsConfig {
            ttl_min_seconds: 86_400,
            send_msgs_per_sec: 1,
            send_bytes_per_day: 0,
            ..LimitsConfig::default()
        });
        let user = [4u8; 32];

        for _ in 0..5 {
            assert_eq!(
                precheck_send(&limits, &user, 10, 60, 700, usize::MAX),
                Some(SendRejectReason::InvalidTtl)
            );
        }
        // Единственный слот секунды всё ещё свободен.
        assert_eq!(precheck_send(&limits, &user, 10, 0, 700, usize::MAX), None);
    }

    #[test]
    fn queue_quota_rejects_when_message_count_reached() {
        let (storage, path) = open_temp_storage("quota_count");
        let recipient = [5u8; 32];
        let sender = [6u8; 32];
        let limits = limits_with(LimitsConfig {
            max_messages_per_queue: 2,
            max_bytes_per_queue: 0,
            max_messages_sender_pair: 0,
            ..LimitsConfig::default()
        });

        for _ in 0..2 {
            storage
                .enqueue_inbox(&recipient, &sender, None, b"x", None, 0)
                .unwrap();
        }

        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &sender)
                .unwrap()
                .reason,
            Some(SendRejectReason::Full)
        );
        // Очередь другого получателя не затронута.
        assert_eq!(
            queue_quota_reason(&storage, &limits, &[7u8; 32], None, &sender)
                .unwrap()
                .reason,
            None
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn queue_quota_rejects_when_byte_budget_reached() {
        let (storage, path) = open_temp_storage("quota_bytes");
        let recipient = [8u8; 32];
        let sender = [9u8; 32];
        let limits = limits_with(LimitsConfig {
            max_messages_per_queue: 0,
            max_bytes_per_queue: 16,
            max_messages_sender_pair: 0,
            ..LimitsConfig::default()
        });

        // Одна запись уже больше 16 байт (только заголовок — 52 байта).
        storage
            .enqueue_inbox(&recipient, &sender, None, b"payload", None, 0)
            .unwrap();

        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &sender)
                .unwrap()
                .reason,
            Some(SendRejectReason::Full)
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Под-квота sender→recipient: один болтливый отправитель не должен
    /// занимать всю очередь получателя.
    #[test]
    fn queue_quota_rejects_single_sender_pair_only() {
        let (storage, path) = open_temp_storage("quota_pair");
        let recipient = [10u8; 32];
        let loud = [11u8; 32];
        let quiet = [12u8; 32];
        let limits = limits_with(LimitsConfig {
            max_messages_per_queue: 0,
            max_bytes_per_queue: 0,
            max_messages_sender_pair: 2,
            ..LimitsConfig::default()
        });

        for _ in 0..2 {
            storage
                .enqueue_inbox(&recipient, &loud, None, b"spam", None, 0)
                .unwrap();
        }

        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &loud)
                .unwrap()
                .reason,
            Some(SendRejectReason::Full)
        );
        // Другой отправитель в ту же очередь всё ещё проходит.
        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &quiet)
                .unwrap()
                .reason,
            None
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Device-scope очередь считается отдельно от account-scope.
    #[test]
    fn queue_quota_scopes_account_and_device_separately() {
        let (storage, path) = open_temp_storage("quota_scope");
        let recipient = [13u8; 32];
        let sender = [14u8; 32];
        let limits = limits_with(LimitsConfig {
            max_messages_per_queue: 1,
            max_bytes_per_queue: 0,
            max_messages_sender_pair: 0,
            ..LimitsConfig::default()
        });

        storage
            .enqueue_inbox(&recipient, &sender, None, b"account", None, 0)
            .unwrap();

        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &sender)
                .unwrap()
                .reason,
            Some(SendRejectReason::Full)
        );
        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, Some(7), &sender)
                .unwrap()
                .reason,
            None
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Все лимиты нулевые — квоты выключены, сканы не выполняются.
    #[test]
    fn queue_quota_disabled_when_all_limits_zero() {
        let (storage, path) = open_temp_storage("quota_off");
        let recipient = [15u8; 32];
        let sender = [16u8; 32];
        let limits = limits_with(LimitsConfig {
            max_messages_per_queue: 0,
            max_bytes_per_queue: 0,
            max_messages_sender_pair: 0,
            ..LimitsConfig::default()
        });

        for _ in 0..50 {
            storage
                .enqueue_inbox(&recipient, &sender, None, b"x", None, 0)
                .unwrap();
        }

        assert_eq!(
            queue_quota_reason(&storage, &limits, &recipient, None, &sender)
                .unwrap()
                .reason,
            None
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&path);
    }

    // ---- регистрация push-токенов ----

    fn welcome_count(transport: &MockTransport) -> usize {
        transport
            .sent_payloads()
            .iter()
            .filter(|payload| payload.kind == crate::push::PushKind::Welcome)
            .count()
    }

    fn ack_of(bytes: &[u8]) -> crate::wire::PushTokenAck {
        match decode_frame(bytes).unwrap().payload {
            Some(frame::Payload::PushTokenAck(ack)) => ack,
            other => panic!("expected PushTokenAck, got {other:?}"),
        }
    }

    /// Welcome — один на аккаунт: Register → Unregister → Register второго
    /// не даёт, как и регистрация с другого устройства.
    #[tokio::test]
    async fn welcome_push_is_sent_once_per_account() {
        let user = [21u8; 32];
        let tokens = token_store_with(&user, &[]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );
        let register = |device: DeviceId, platform: PushPlatform, token: &str| {
            ack_of(&register_push_token(
                &tokens, &scheduler, 32, &user, device, platform, token,
            ))
        };

        assert!(register(1, PushPlatform::AndroidFcm, "tok-1").ok);
        // Токен разрешается в момент отправки: снимать его до неё нельзя,
        // иначе первое приветствие потерялось бы и тест ничего не доказал.
        collect_sent(&transport, 1).await;
        assert_eq!(welcome_count(&transport), 1);

        tokens.remove_all(&user, 1).unwrap();
        assert!(!tokens.has_any_for_user(&user).unwrap());
        assert!(register(1, PushPlatform::AndroidFcm, "tok-1b").ok);
        tokens.remove_all(&user, 1).unwrap();
        assert!(register(2, PushPlatform::IosFcm, "tok-2").ok);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(welcome_count(&transport), 1, "welcome must not repeat");
    }

    /// Аккаунт, у которого токены были до появления отметок, приветствия
    /// не получает — ни сразу, ни после круга Unregister/Register.
    #[tokio::test]
    async fn account_with_prior_tokens_is_marked_without_welcome() {
        let user = [22u8; 32];
        let tokens = token_store_with(&user, &[(1, "legacy")]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );

        let ack = register_push_token(
            &tokens,
            &scheduler,
            32,
            &user,
            1,
            PushPlatform::AndroidFcm,
            "refreshed",
        );
        assert!(ack_of(&ack).ok);
        tokens.remove_all(&user, 1).unwrap();
        let ack = register_push_token(
            &tokens,
            &scheduler,
            32,
            &user,
            1,
            PushPlatform::AndroidFcm,
            "again",
        );
        assert!(ack_of(&ack).ok);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(welcome_count(&transport), 0);
    }

    /// VoIP-регистрация приветствия не трогает: ни не шлёт его, ни не
    /// расходует отметку.
    #[tokio::test]
    async fn voip_registration_does_not_consume_the_welcome() {
        let user = [23u8; 32];
        let tokens = token_store_with(&user, &[]);
        let transport = Arc::new(MockTransport::always_ok());
        let scheduler = PushScheduler::start(
            fast_cfg(),
            transport.clone(),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );

        let ack = register_push_token(
            &tokens,
            &scheduler,
            32,
            &user,
            1,
            PushPlatform::IosVoip,
            "0a1b2c3d",
        );
        assert!(ack_of(&ack).ok);
        tokens.remove_all(&user, 1).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(welcome_count(&transport), 0);

        assert!(tokens.claim_welcome(&[24u8; 32]).unwrap());
        assert!(
            tokens.claim_welcome(&user).unwrap(),
            "voip registration must not have claimed the welcome"
        );
    }

    #[tokio::test]
    async fn push_registration_acks_device_limit_and_bad_voip_token() {
        let user = [25u8; 32];
        let tokens = token_store_with(&user, &[]);
        let scheduler = PushScheduler::start(
            fast_cfg(),
            Arc::new(MockTransport::always_ok()),
            tokens.clone(),
            Arc::new(NoopStatePersistence),
        );
        let register = |device: DeviceId, platform: PushPlatform, token: &str| {
            ack_of(&register_push_token(
                &tokens, &scheduler, 2, &user, device, platform, token,
            ))
        };

        assert!(register(1, PushPlatform::AndroidFcm, "a").ok);
        assert!(register(2, PushPlatform::AndroidFcm, "b").ok);
        let refused = register(3, PushPlatform::AndroidFcm, "c");
        assert!(!refused.ok);
        assert_eq!(refused.message, "push device limit reached");
        assert!(register(2, PushPlatform::AndroidFcm, "b2").ok);

        let bad = register(1, PushPlatform::IosVoip, "../evil");
        assert!(!bad.ok);
        assert_eq!(bad.message, "invalid token");
        assert!(tokens.get_voip(&user, 1).unwrap().is_none());
    }

    #[test]
    fn instant_at_unix_secs_tracks_the_wall_clock() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let base = tokio::time::Instant::now();

        let past = instant_at_unix_secs(now.saturating_sub(10));
        assert!(past <= tokio::time::Instant::now());

        let soon = instant_at_unix_secs(now + 5);
        let ahead = soon.saturating_duration_since(base);
        assert!(
            ahead > Duration::from_secs(3) && ahead <= Duration::from_secs(5),
            "{ahead:?}"
        );

        // Далёкое и непредставимое будущее не паникует.
        let far = instant_at_unix_secs(u64::MAX);
        assert!(far.saturating_duration_since(base) > Duration::from_secs(365 * 24 * 3600));
    }
}
