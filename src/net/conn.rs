use anyhow::{Result, bail};
use std::sync::Arc;
use tokio::{net::TcpStream, select, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::config::ServerConfigSnapshot;
use crate::delivery::DeliveryBackend;
use crate::domain::priority::MessagePriority;
use crate::domain::push::PushPlatform;
use crate::domain::reject::SendRejectReason;
use crate::domain::wake::WakeHint;
use crate::net::framing::{
    PROTO_VERSION, as_fixed_32, decode_device_id, decode_frame, encode_auth_error, encode_auth_ok,
    encode_incoming, encode_pong, encode_push_token_ack, encode_queue_ack, encode_queue_list,
    encode_send_ack, encode_signed_server_config,
};
use crate::net::noise::{HandshakePolicy, NodeIdentity, NoiseFramed};
use crate::net::rate_limit::{AdmissionGuard, PingGate, SessionLimits, unix_now_secs};
use crate::observability::{self, ConnectionMetricsGuard};
use crate::push::PushScheduler;
use crate::state::queues::QueueError;
use crate::state::{
    push_tokens::PushTokenStore,
    registry::{ConnRegistry, DeviceId, OutboundFrame, UserId},
    storage::{EnqueueResult, QueueQuotaCeilings, Storage, StoredMessage},
};
use crate::wire::QueueRejectReason as WireQueueRejectReason;
use crate::wire::frame;

const OFFLINE_REPLAY_LIMIT: usize = 10_000;

enum ReplayScope {
    Account,
    Device(DeviceId),
}

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
    let max_queues = limits.cfg.max_queues_per_user;
    let queue_addressing = server_config.supports_queue_addressing;

    // Сессия начинается с Noise-хендшейка; после него identity клиента
    // доказана статиком соединения. Pre-auth plaintext-фазы нет.
    let handshake_started = std::time::Instant::now();
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
            observability::observe_handshake(
                classify_handshake_error(&err.to_string()),
                // Паттерн неизвестен: отказ мог случиться до его чтения.
                "unknown",
                handshake_started.elapsed(),
            );
            warn!(error = %err, "noise handshake failed; closing connection");
            return Err(err);
        }
    };

    // Хендшейк позади — место на входе освобождается немедленно, дальше
    // сессия учитывается лимитом сессий на пользователя.
    drop(admission_guard);

    let user_id = identity.user_id;
    let device_id = identity.device_id;
    let protocol_version = identity.protocol_version;

    observability::observe_connection_auth("ok");
    info!(
        user = %hex::encode(user_id),
        ?device_id,
        protocol_version,
        pattern = identity.pattern.as_metric_label(),
        "noise session established"
    );

    // Лимит одновременных сессий на ключ. Проверяется до AuthOk и
    // регистрации; отказ приходит по уже установленному каналу. Гонка двух
    // параллельных подключений через порог допустима — лимит best-effort,
    // см. `ConnRegistry::session_count`.
    if limits.cfg.max_sessions_per_user > 0
        && registry.session_count(&user_id) >= limits.cfg.max_sessions_per_user
    {
        observability::observe_reject("session_limit");
        observability::observe_connection_auth("limit");
        let err_frame = encode_auth_error(401, "session limit exceeded");
        framed.send_frame(&err_frame).await?;
        warn!(
            user = %hex::encode(user_id),
            limit = limits.cfg.max_sessions_per_user,
            "connection rejected: session limit exceeded"
        );
        bail!("session limit exceeded");
    }

    let ok_bytes = encode_auth_ok(user_id)?;
    framed.send_frame(&ok_bytes).await?;
    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        protocol_version,
        "sent auth ok to client"
    );

    let (tx_to_client, mut rx_to_client) = mpsc::channel::<OutboundFrame>(1024);
    let registration = registry.insert(user_id, device_id, tx_to_client.clone());
    let _registry_cleanup = RegistryCleanup {
        registry: registry.clone(),
        delivery_backend: delivery_backend.clone(),
        user_id,
        connection_id: registration.connection_id,
    };
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
            framed.send_frame(&err_frame).await?;
            bail!("delivery backend unavailable");
        }
    } else {
        if registration.is_first_for_user {
            let inbox_messages = match storage.drain_inbox(&user_id, OFFLINE_REPLAY_LIMIT) {
                Ok(messages) => messages,
                Err(err) => {
                    return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await;
                }
            };
            if !inbox_messages.is_empty() {
                info!(
                    user = %hex::encode(user_id),
                    ?device_id,
                    count = inbox_messages.len(),
                    "starting account-level offline message replay"
                );
            }
            replay_messages(
                &mut framed,
                &storage,
                &user_id,
                ReplayScope::Account,
                inbox_messages,
                &mut messages_delivered_offline,
                &mut messages_failed,
            )
            .await?;
        }

        if let Some(current_device_id) = device_id
            && registration.is_first_for_device
        {
            let inbox_messages =
                match storage.drain_device_inbox(&user_id, current_device_id, OFFLINE_REPLAY_LIMIT)
                {
                    Ok(messages) => messages,
                    Err(err) => {
                        return refuse_storage_unavailable(&mut framed, user_id, device_id, &err)
                            .await;
                    }
                };
            if !inbox_messages.is_empty() {
                info!(
                    user = %hex::encode(user_id),
                    device_id = current_device_id,
                    count = inbox_messages.len(),
                    "starting device-level offline message replay"
                );
            }
            replay_messages(
                &mut framed,
                &storage,
                &user_id,
                ReplayScope::Device(current_device_id),
                inbox_messages,
                &mut messages_delivered_offline,
                &mut messages_failed,
            )
            .await?;
        }
    }

    loop {
        select! {
          maybe_in = framed.next_frame() => {
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
                  AllocateQueue,
                  RevokeQueue {
                      /// Сырые байты: неверная длина — не повод рвать
                      /// сессию, клиент получит `NOT_FOUND` в ack.
                      queue_id: Vec<u8>,
                  },
                  ListQueues,
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
                  Some(frame::Payload::AllocateQueue(_)) => ClientFrame::AllocateQueue,
                  Some(frame::Payload::RevokeQueue(cmd)) => ClientFrame::RevokeQueue {
                      queue_id: cmd.queue_id,
                  },
                  Some(frame::Payload::ListQueues(_)) => ClientFrame::ListQueues,
                  _ => ClientFrame::Ignore,
              };

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
                      let mut resolved = recipient;
                      let mut recipient_device_id = recipient_device_id;
                      if let Some(id) = queue_id {
                          if !queue_addressing {
                              debug!(
                                  sender = %hex::encode(user_id),
                                  queue_id = %hex::encode(id),
                                  ttl_seconds,
                                  "clientSend carries v3 node-header; queueId ignored"
                              );
                          } else {
                              match queues.owner_of(&id) {
                                  Ok(Some(owner)) => {
                                      // Очередь принадлежит аккаунту, а не
                                      // устройству, поэтому
                                      // `recipientDeviceId` сбрасывается.
                                      resolved = Some(owner);
                                      recipient_device_id = None;
                                      observability::observe_queue_addressed_send();
                                  }
                                  Ok(None) => {
                                      // Неизвестная или отозванная очередь.
                                      // Разница между ними клиенту не
                                      // сообщается: ответ не должен
                                      // подтверждать существование чужого
                                      // адреса (как и у RevokeQueue).
                                      warn!(
                                          sender = %hex::encode(user_id),
                                          queue_id = %hex::encode(id),
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
                                          queue_id = %hex::encode(id),
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

                      info!(
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
                                  error!(
                                      sender = %hex::encode(user_id),
                                      recipient = %hex::encode(recipient),
                                      ?recipient_device_id,
                                      size = body.len(),
                                      error = %err,
                                      "publish to broker failed; answering the sender with a reject"
                                  );
                                  reject_send(&mut framed, SendRejectReason::Internal).await?;
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
                          info!(
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
                          let incoming =
                              encode_incoming(user_id, device_id, 0, &body, priority);
                          let route_targets = registry.route_targets(&recipient, recipient_device_id);
                          let mut delivered_count = 0usize;

                          for target in route_targets {
                              match target.tx.send(OutboundFrame {
                                  bytes: incoming.clone(),
                                  message_id: None,
                                  close_after_send: false,
                                  sender_user_id: Some(user_id),
                                  sender_device_id: device_id,
                              }).await {
                                  Ok(()) => {
                                      delivered_count += 1;
                                  }
                                  Err(_) => {
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
                              let ack =
                                  encode_send_ack(true, false, 0, SendRejectReason::Unspecified);
                              framed.send_frame(&ack).await?;
                              messages_delivered_online += delivered_count as u64;
                              observability::observe_message_route(match recipient_device_id {
                                  Some(_) => "online_device",
                                  None => "online",
                              });
                              info!(
                                  sender = %hex::encode(user_id),
                                  recipient = %hex::encode(recipient),
                                  ?recipient_device_id,
                                  delivered_count,
                                  size = body.len(),
                                  delivery_method = "online",
                                  "message successfully delivered to online recipient"
                              );
                          } else {
                              // Квоты очереди прямого бэкенда. Брокерный
                              // путь ограничен лимитами самого потока
                              // JetStream и сюда не заходит.
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
                                      "offline enqueue rejected by queue quota"
                                  );
                                  reject_send(&mut framed, reason).await?;
                                  messages_rejected += 1;
                                  continue;
                              }

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
                              let enqueue_result = match enqueued {
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
                                          "offline enqueue failed; answering the sender with a reject"
                                      );
                                      reject_send(&mut framed, SendRejectReason::Internal).await?;
                                      messages_rejected += 1;
                                      continue;
                                  }
                              };
                              if enqueue_result.stored {
                                  // Sled backend reaches this branch only when
                                  // route_targets was empty, so nothing of this
                                  // user is online — pass an empty online slice.
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
                                  quota.depth_before,
                                  &mut messages_queued,
                              ).await?;
                          }
                      }
                  }
                  ClientFrame::DeliveryAck { message_id } => {
                      let acked = delivery_backend
                          .ack_delivery(user_id, device_id, message_id)
                          .await?;
                      if acked {
                          info!(
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
                          (Some(current_device_id), Some(platform)) => {
                              // Snapshot whether this user had any prior push
                              // token row, *before* we insert: the transition
                              // empty → non-empty gates the welcome push. On
                              // read error assume "had some" so no welcome is
                              // sent. A VoIP registration (the second token of
                              // an iOS device) never triggers a welcome: the
                              // welcome is sent over the alert channel only.
                              let was_first_registration = platform
                                  != PushPlatform::IosVoip
                                  && match push_tokens.has_any_for_user(&user_id) {
                                      Ok(has_any) => !has_any,
                                      Err(err) => {
                                          warn!(
                                              user = %hex::encode(user_id),
                                              error = %err,
                                              "could not check prior push tokens; skipping welcome push"
                                          );
                                          false
                                      }
                                  };

                              match push_tokens.add(
                                  &user_id,
                                  current_device_id,
                                  platform,
                                  &token,
                              ) {
                                  Ok(true) => {
                                      info!(
                                          user = %hex::encode(user_id),
                                          device_id = current_device_id,
                                          ?platform,
                                          "push token registered"
                                      );
                                      if was_first_registration {
                                          info!(
                                              user = %hex::encode(user_id),
                                              device_id = current_device_id,
                                              "first push token for user; firing welcome push"
                                          );
                                          push_scheduler
                                              .send_welcome(user_id, current_device_id);
                                      }
                                      encode_push_token_ack(true, "")
                                  }
                                  Ok(false) => encode_push_token_ack(false, "invalid token"),
                                  Err(err) => {
                                      warn!(
                                          user = %hex::encode(user_id),
                                          device_id = current_device_id,
                                          error = %err,
                                          "push token registration failed"
                                      );
                                      encode_push_token_ack(false, "internal error")
                                  }
                              }
                          }
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
                                      info!(
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
                  ClientFrame::AllocateQueue => {
                      // Идентификатор выдаёт нода: уникальность в её
                      // пространстве имён гарантирует только она. 32 байта
                      // из CSPRNG не перебрать, а знание идентификатора и
                      // есть право писать в очередь.
                      let mut queue_id = [0u8; 32];
                      let ack = if let Err(err) = getrandom::fill(&mut queue_id) {
                          warn!(
                              user = %hex::encode(user_id),
                              error = %err,
                              "failed to read random bytes for a queue id"
                          );
                          encode_queue_ack(false, None, WireQueueRejectReason::Internal)
                      } else {
                          match queues.allocate(&user_id, queue_id, unix_now_secs(), max_queues) {
                              Ok(Ok(record)) => {
                                  info!(
                                      user = %hex::encode(user_id),
                                      queue_id = %hex::encode(record.queue_id),
                                      "queue allocated"
                                  );
                                  encode_queue_ack(
                                      true,
                                      Some(record.queue_id),
                                      WireQueueRejectReason::Unspecified,
                                  )
                              }
                              Ok(Err(QueueError::Limit)) => {
                                  encode_queue_ack(false, None, WireQueueRejectReason::Limit)
                              }
                              Ok(Err(QueueError::NotFound)) => {
                                  encode_queue_ack(false, None, WireQueueRejectReason::NotFound)
                              }
                              Err(err) => {
                                  warn!(
                                      user = %hex::encode(user_id),
                                      error = %err,
                                      "queue allocation failed"
                                  );
                                  encode_queue_ack(false, None, WireQueueRejectReason::Internal)
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
                          Some(queue_id) => match queues.revoke(&user_id, &queue_id) {
                              Ok(Ok(())) => {
                                  info!(
                                      user = %hex::encode(user_id),
                                      queue_id = %hex::encode(queue_id),
                                      "queue revoked"
                                  );
                                  encode_queue_ack(true, None, WireQueueRejectReason::Unspecified)
                              }
                              Ok(Err(QueueError::Limit)) => {
                                  encode_queue_ack(false, None, WireQueueRejectReason::Limit)
                              }
                              Ok(Err(QueueError::NotFound)) => {
                                  encode_queue_ack(false, None, WireQueueRejectReason::NotFound)
                              }
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
                      let response = match queues.list(&user_id) {
                          Ok(records) => encode_queue_list(&records),
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
                  ClientFrame::Ignore => {
                      debug!(user = %hex::encode(user_id), "ignoring unsupported frame");
                  }
              }
          }

          Some(outgoing) = rx_to_client.recv() => {
              let size = outgoing.bytes.len();
              let sender_hex = outgoing.sender_user_id.map(hex::encode);
              info!(
                  recipient = %hex::encode(user_id),
                  recipient_device_id = ?device_id,
                  sender = ?sender_hex,
                  sender_device_id = ?outgoing.sender_device_id,
                  message_id = ?outgoing.message_id,
                  size,
                  "forwarding envelope to recipient TCP socket"
              );
              if let Err(err) = framed.send_frame(&outgoing.bytes).await {
                  if is_connection_reset(&err) {
                      observability::observe_connection_reset_by_peer();
                  }
                  warn!(
                      recipient = %hex::encode(user_id),
                      recipient_device_id = ?device_id,
                      sender = ?sender_hex,
                      message_id = ?outgoing.message_id,
                      size,
                      error = %err,
                      "TCP write to recipient failed; envelope lost on this connection"
                  );
                  return Err(err.into());
              }
              messages_sent += 1;
              observability::observe_message_route("server_push");
              info!(
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
/// Порядок проверок значим: детерминированная валидация ttl идёт перед
/// rate-limit'ом, иначе поток заведомо невалидных кадров выжигал бы
/// секундный и суточный бюджет пользователя (успешный `check_at` списывает
/// бюджет, отказ — нет).
///
/// `ttl_seconds == 0` — «не указан» (клиенты без node-header v3): действует
/// только глобальная retention-политика ноды, пол не применяется.
fn precheck_send(
    limits: &SessionLimits,
    user_id: &UserId,
    body_len: usize,
    ttl_seconds: u64,
    now_secs: u64,
) -> Option<SendRejectReason> {
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
    framed.send_frame(&err_frame).await?;
    bail!("storage unavailable")
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
        info!(
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

async fn replay_messages(
    framed: &mut NoiseFramed<TcpStream>,
    storage: &Storage,
    user_id: &[u8; 32],
    scope: ReplayScope,
    messages: Vec<StoredMessage>,
    messages_delivered_offline: &mut u64,
    messages_failed: &mut u64,
) -> Result<()> {
    for message in messages {
        let frame = encode_incoming(
            message.sender_id,
            message.sender_device_id,
            message.id,
            &message.body,
            message.priority,
        );

        match framed.send_frame(&frame).await {
            Ok(_) => {
                let remove_result = match scope {
                    ReplayScope::Account => storage.remove_inbox(user_id, message.id),
                    ReplayScope::Device(device_id) => {
                        storage.remove_device_inbox(user_id, device_id, message.id)
                    }
                };
                if let Err(err) = remove_result {
                    warn!(
                        user = %hex::encode(user_id),
                        sender = %hex::encode(message.sender_id),
                        message_id = message.id,
                        error = %err,
                        operation = "offline_message_remove",
                        "failed to remove offline message from storage after replay"
                    );
                }

                *messages_delivered_offline += 1;
                observability::observe_message_route(match scope {
                    ReplayScope::Account => "offline_replay",
                    ReplayScope::Device(_) => "offline_replay_device",
                });
                info!(
                    user = %hex::encode(user_id),
                    sender = %hex::encode(message.sender_id),
                    message_id = message.id,
                    ?message.sender_device_id,
                    size = message.body.len(),
                    "successfully delivered offline message during replay"
                );
            }
            Err(err) => {
                if is_connection_reset(&err) {
                    observability::observe_connection_reset_by_peer();
                }

                let is_connection_error = matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                );

                if is_connection_error {
                    warn!(
                        user = %hex::encode(user_id),
                        sender = %hex::encode(message.sender_id),
                        message_id = message.id,
                        ?message.sender_device_id,
                        size = message.body.len(),
                        error = %err,
                        operation = "offline_message_send",
                        error_type = "connection_lost",
                        "connection lost while sending offline message - aborting replay"
                    );
                    break;
                }

                *messages_failed += 1;
                warn!(
                    user = %hex::encode(user_id),
                    sender = %hex::encode(message.sender_id),
                    message_id = message.id,
                    ?message.sender_device_id,
                    size = message.body.len(),
                    error = %err,
                    operation = "offline_message_send",
                    error_type = "send_failure",
                    "failed to send offline message to client - continuing with next message"
                );
            }
        }
    }

    Ok(())
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
            precheck_send(&limits, &user, 10, 3_600, 1_000),
            Some(SendRejectReason::InvalidTtl)
        );
        assert_eq!(precheck_send(&limits, &user, 10, 0, 1_000), None);
        assert_eq!(precheck_send(&limits, &user, 10, 86_400, 1_000), None);
        assert_eq!(precheck_send(&limits, &user, 10, 172_800, 1_000), None);
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
        assert_eq!(precheck_send(&limits, &[2u8; 32], 10, 1, 1_000), None);
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

        assert_eq!(precheck_send(&limits, &user, 10, 0, 500), None);
        assert_eq!(precheck_send(&limits, &user, 10, 0, 500), None);
        assert_eq!(
            precheck_send(&limits, &user, 10, 0, 500),
            Some(SendRejectReason::RateLimited)
        );
        // Новое секундное окно — бюджет снова есть.
        assert_eq!(precheck_send(&limits, &user, 10, 0, 501), None);
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
                precheck_send(&limits, &user, 10, 60, 700),
                Some(SendRejectReason::InvalidTtl)
            );
        }
        // Единственный слот секунды всё ещё свободен.
        assert_eq!(precheck_send(&limits, &user, 10, 0, 700), None);
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
}
