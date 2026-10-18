//! Сессия роли `BLOB` и кадры хранилища файлов (server-contract.md §6.11).
//!
//! Байты файлов ходят только по сессии роли `BLOB`: ОС делит канал между
//! двумя TCP-соединениями, и сообщение не ждёт в одном канале за
//! мегабайтными кадрами. Поэтому сессия сообщений кадры хранилища не
//! принимает (`UNSUPPORTED`) — кроме `BlobStat`: он мал, а поднимать сессию
//! передачи ради проверки наличия незачем.
//!
//! Сессия `BLOB` для доставки не регистрируется: входящих не получает,
//! очередь не читает, «в сети» для пушей не делает и `ClientSend` не
//! принимает. В реестре она видна только потолку
//! `MAX_BLOB_SESSIONS_PER_USER` и отзыву сертификатов.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::net::TcpStream;
use tokio::select;
use tracing::{debug, info, warn};

use crate::blob::{BlobReject, BlobStore};
use crate::config::ServerConfigSnapshot;
use crate::domain::reject::SendRejectReason;
use crate::net::conn::{
    await_session_confirmation, instant_at_unix_secs, is_cert_revoked, is_connection_reset,
    next_client_frame, refuse_revoked_cert, refuse_storage_unavailable, send_final_frame,
};
use crate::net::device_cert::SessionScope;
use crate::net::framing::{
    decode_frame, encode_auth_error, encode_auth_ok, encode_blob_ack, encode_pong,
    encode_push_token_ack, encode_queue_ack, encode_send_ack, encode_signed_server_config,
};
use crate::net::noise::{NodeIdentity, NoiseFramed, NoiseSessionIdentity, SessionRole};
use crate::net::rate_limit::{AdmissionGuard, PingGate, SessionLimits, unix_now_secs};
use crate::observability;
use crate::state::cert_revocations::CertRevocationStore;
use crate::state::registry::{ConnRegistry, DeviceId, UserId};
use crate::wire::{self, QueueRejectReason, frame};

/// Что нужно кадрам хранилища в сессии любой роли.
pub(crate) struct BlobContext {
    /// `None` — хранилище выключено оператором.
    pub store: Option<BlobStore>,
    pub limits: Arc<SessionLimits>,
    /// Данных в одном куске при потолке кадра этой ноды.
    pub chunk_max: usize,
    /// `MAX_BLOB_SESSIONS_PER_USER`.
    pub max_sessions_per_user: usize,
}

/// Кто прислал кадр хранилища.
pub(crate) struct BlobPeer {
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub scope: SessionScope,
    /// Соединение: им помечается, чей дескриптор загрузки открыт.
    pub connection_id: u64,
}

/// Кадр клиента для хранилища файлов.
pub(crate) fn is_blob_request(payload: &frame::Payload) -> bool {
    matches!(
        payload,
        frame::Payload::BlobUploadInit(_)
            | frame::Payload::BlobUploadChunk(_)
            | frame::Payload::BlobUploadCommit(_)
            | frame::Payload::BlobUploadStatus(_)
            | frame::Payload::BlobGet(_)
            | frame::Payload::BlobRelease(_)
            | frame::Payload::BlobDelete(_)
            | frame::Payload::BlobExtend(_)
            | frame::Payload::BlobStat(_)
    )
}

/// Обработать кадр хранилища. Отказ — `BlobAck` с причиной, сессия живёт;
/// `Err` — только сбой записи в сокет.
pub(crate) async fn handle_blob_frame(
    framed: &mut NoiseFramed<TcpStream>,
    ctx: &BlobContext,
    peer: &BlobPeer,
    role: SessionRole,
    payload: frame::Payload,
) -> Result<()> {
    let op = op_label(&payload);
    let allowed_here = role == SessionRole::Blob || matches!(payload, frame::Payload::BlobStat(_));
    if ctx.store.is_none() || !allowed_here {
        observability::observe_blob_op(op, BlobReject::Unsupported.as_metric_label());
        debug!(
            user = %hex::encode(peer.user_id),
            op,
            role = role.as_metric_label(),
            "blob frame refused: storage disabled or wrong session role"
        );
        framed
            .send_frame(&reject_frame(&payload, BlobReject::Unsupported))
            .await?;
        return Ok(());
    }
    debug!(
        user = %hex::encode(peer.user_id),
        device_id = ?peer.device_id,
        connection_id = peer.connection_id,
        delegated = peer.scope.is_delegated(),
        chunk_max = ctx.chunk_max,
        op,
        "blob operation is not implemented yet"
    );
    observability::observe_blob_op(op, BlobReject::Unsupported.as_metric_label());
    framed
        .send_frame(&reject_frame(&payload, BlobReject::Unsupported))
        .await?;
    Ok(())
}

/// Метка операции для `blob_ops_total`.
fn op_label(payload: &frame::Payload) -> &'static str {
    match payload {
        frame::Payload::BlobUploadInit(_) => "init",
        frame::Payload::BlobUploadChunk(_) => "chunk",
        frame::Payload::BlobUploadCommit(_) => "commit",
        frame::Payload::BlobUploadStatus(_) => "status",
        frame::Payload::BlobGet(_) => "get",
        frame::Payload::BlobRelease(_) => "release",
        frame::Payload::BlobDelete(_) => "delete",
        frame::Payload::BlobExtend(_) => "extend",
        frame::Payload::BlobStat(_) => "stat",
        _ => "other",
    }
}

/// `BlobAck` с отказом на кадр: `request_id` из кадра, у куска — его
/// `blob_id` (своего `request_id` у куска нет).
pub(crate) fn reject_frame(payload: &frame::Payload, reason: BlobReject) -> Vec<u8> {
    let (request_id, blob_id) = match payload {
        frame::Payload::BlobUploadInit(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobUploadChunk(cmd) => (0, cmd.blob_id.clone()),
        frame::Payload::BlobUploadCommit(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobUploadStatus(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobGet(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobRelease(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobDelete(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobExtend(cmd) => (cmd.request_id, Vec::new()),
        frame::Payload::BlobStat(cmd) => (cmd.request_id, Vec::new()),
        _ => (0, Vec::new()),
    };
    // В ответ уходит только корректный по длине id: эхо мусора клиенту
    // ничего не даёт.
    let blob_id = if blob_id.len() == 32 {
        blob_id
    } else {
        Vec::new()
    };
    encode_blob_ack(wire::BlobAck {
        request_id,
        ok: false,
        reason: reason.to_wire(),
        blob_id,
        committed_offset: 0,
        expires_at: 0,
    })
}

/// Снять сессию `BLOB` с учёта и отпустить её дескрипторы загрузок.
struct BlobSessionCleanup {
    registry: ConnRegistry,
    store: Option<BlobStore>,
    user_id: UserId,
    connection_id: u64,
}

impl Drop for BlobSessionCleanup {
    fn drop(&mut self) {
        self.registry
            .remove_blob_session(&self.user_id, self.connection_id);
        if let Some(store) = &self.store {
            store.detach_connection(self.connection_id);
        }
    }
}

/// Обслужить сессию роли `BLOB` после хендшейка.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    mut framed: NoiseFramed<TcpStream>,
    identity: NoiseSessionIdentity,
    registry: ConnRegistry,
    cert_revocations: CertRevocationStore,
    ctx: BlobContext,
    server_config: ServerConfigSnapshot,
    node: Arc<NodeIdentity>,
    confirm_timeout: Duration,
    admission_guard: AdmissionGuard,
) -> Result<()> {
    let user_id = identity.user_id;
    let device_id = identity.device_id;
    let cert_not_before = identity.cert_not_before;
    let cert_not_after = identity.cert_not_after;

    refuse_over_blob_limit(&mut framed, &registry, &ctx, &user_id).await?;
    match is_cert_revoked(&cert_revocations, &user_id, device_id, cert_not_before) {
        Ok(false) => {}
        Ok(true) => {
            return refuse_revoked_cert(&mut framed, &user_id, device_id, "handshake").await;
        }
        Err(err) => return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await,
    }
    framed.send_frame(&encode_auth_ok(user_id)?).await?;

    let Some(confirming_frame) =
        await_session_confirmation(&mut framed, &user_id, device_id, confirm_timeout).await?
    else {
        return Ok(());
    };
    drop(admission_guard);
    if cert_not_after.is_some_and(|not_after| unix_now_secs() >= not_after) {
        return Ok(());
    }
    refuse_over_blob_limit(&mut framed, &registry, &ctx, &user_id).await?;

    let registration = registry.insert_blob_session(user_id, device_id, cert_not_before);
    let _cleanup = BlobSessionCleanup {
        registry: registry.clone(),
        store: ctx.store.clone(),
        user_id,
        connection_id: registration.connection_id,
    };
    let revocation = registration.revocation.clone();
    // Отзыв мог прийти между `AuthOk` и регистрацией (см. `handle_conn`).
    match is_cert_revoked(&cert_revocations, &user_id, device_id, cert_not_before) {
        Ok(false) if !revocation.is_revoked() => {}
        Ok(_) => return refuse_revoked_cert(&mut framed, &user_id, device_id, "confirm").await,
        Err(err) => return refuse_storage_unavailable(&mut framed, user_id, device_id, &err).await,
    }
    observability::observe_connection_auth("ok");
    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        connection_id = registration.connection_id,
        "blob session registered"
    );

    let peer = BlobPeer {
        user_id,
        device_id,
        scope: identity.scope,
        connection_id: registration.connection_id,
    };
    let mut ping_gate = PingGate::new(ctx.limits.cfg.ping_per_sec);
    let mut pending = Some(confirming_frame);
    let mut frames_received = 0u64;
    let cert_expiry = async move {
        match cert_not_after {
            Some(not_after) => tokio::time::sleep_until(instant_at_unix_secs(not_after)).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(cert_expiry);

    loop {
        let bytes = select! {
            () = revocation.revoked() => {
                return refuse_revoked_cert(&mut framed, &user_id, device_id, "live").await;
            }
            () = &mut cert_expiry => {
                info!(
                    user = %hex::encode(user_id),
                    ?device_id,
                    "device certificate expired; closing delegated blob session"
                );
                break;
            }
            read = next_client_frame(&mut framed, &mut pending) => match read {
                Ok(Some(bytes)) => bytes,
                Ok(None) => break,
                Err(err) => {
                    if is_connection_reset(&err) {
                        observability::observe_connection_reset_by_peer();
                    }
                    return Err(err.into());
                }
            },
        };
        if revocation.is_revoked() {
            return refuse_revoked_cert(&mut framed, &user_id, device_id, "live").await;
        }
        frames_received += 1;
        observability::observe_frame_received();
        let frame = match decode_frame(bytes.as_ref()) {
            Ok(frame) => frame,
            Err(err) => {
                observability::observe_frame_decode_error();
                warn!(
                    user = %hex::encode(user_id),
                    size = bytes.len(),
                    error = %err,
                    "failed to decode frame"
                );
                return Err(err);
            }
        };
        if cert_not_after.is_some_and(|not_after| unix_now_secs() >= not_after) {
            break;
        }
        let Some(payload) = frame.payload else {
            continue;
        };
        match payload {
            frame::Payload::Ping(_) => {
                observability::observe_ping();
                if ping_gate.allow(unix_now_secs()) {
                    framed.send_frame(&encode_pong()).await?;
                    observability::observe_pong();
                } else {
                    observability::observe_ping_dropped();
                }
            }
            frame::Payload::GetServerConfig(_) => {
                let response = encode_signed_server_config(&server_config, &node, unix_now_secs());
                framed.send_frame(&response).await?;
            }
            // Сессия передачи сообщений не отправляет: отказ, а не разрыв.
            frame::Payload::ClientSend(_) => {
                observability::observe_reject(SendRejectReason::Forbidden.as_metric_label());
                framed
                    .send_frame(&encode_send_ack(
                        false,
                        false,
                        0,
                        SendRejectReason::Forbidden,
                    ))
                    .await?;
            }
            frame::Payload::RegisterPushToken(_) | frame::Payload::UnregisterPushToken(_) => {
                framed
                    .send_frame(&encode_push_token_ack(
                        false,
                        "push tokens are managed in a messages session",
                    ))
                    .await?;
            }
            frame::Payload::AllocateQueue(_)
            | frame::Payload::RevokeQueue(_)
            | frame::Payload::ListQueues(_)
            | frame::Payload::SetQueueOnly(_)
            | frame::Payload::SetAccountRecord(_)
            | frame::Payload::RevokeDeviceCerts(_) => {
                framed
                    .send_frame(&encode_queue_ack(
                        false,
                        None,
                        QueueRejectReason::Unsupported,
                    ))
                    .await?;
            }
            payload if is_blob_request(&payload) => {
                handle_blob_frame(&mut framed, &ctx, &peer, SessionRole::Blob, payload).await?;
            }
            // DeliveryAck и прочее: подтверждать в этой сессии нечего.
            _ => {}
        }
    }

    debug!(
        user = %hex::encode(user_id),
        ?device_id,
        connection_id = registration.connection_id,
        frames_received,
        "blob session closed"
    );
    Ok(())
}

/// Потолок сессий `BLOB` на пользователя — свой, не
/// `max_sessions_per_user`: передача файлов не должна отнимать места у
/// сессий сообщений.
async fn refuse_over_blob_limit(
    framed: &mut NoiseFramed<TcpStream>,
    registry: &ConnRegistry,
    ctx: &BlobContext,
    user_id: &UserId,
) -> Result<()> {
    let limit = ctx.max_sessions_per_user;
    if limit == 0 || registry.blob_session_count(user_id) < limit {
        return Ok(());
    }
    observability::observe_reject("blob_session_limit");
    observability::observe_connection_auth("limit");
    send_final_frame(
        framed,
        &encode_auth_error(401, "blob session limit exceeded"),
    )
    .await?;
    warn!(
        user = %hex::encode(user_id),
        limit,
        "blob session rejected: session limit exceeded"
    );
    bail!("blob session limit exceeded")
}
