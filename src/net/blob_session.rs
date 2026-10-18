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
use zeroize::{Zeroize, Zeroizing};

use crate::blob::record::Releaser;
use crate::blob::{
    BlobId, BlobReject, BlobStore, ChunkOk, ChunkReject, InitRequest, MAX_STAT_ITEMS, StatQuery,
    StatState, blob_fingerprint, blob_id_of, fixed_32,
};
use crate::config::ServerConfigSnapshot;
use crate::domain::reject::SendRejectReason;
use crate::net::conn::{
    await_session_confirmation, instant_at_unix_secs, is_cert_revoked, is_connection_reset,
    next_client_frame, refuse_revoked_cert, refuse_storage_unavailable, send_final_frame,
};
use crate::net::device_cert::SessionScope;
use crate::net::framing::{
    decode_frame, encode_auth_error, encode_auth_ok, encode_blob_ack, encode_blob_data,
    encode_blob_stat_result, encode_pong, encode_push_token_ack, encode_queue_ack, encode_send_ack,
    encode_signed_server_config,
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
    let echo = Echo::of(&payload);
    let allowed_here = role == SessionRole::Blob || matches!(payload, frame::Payload::BlobStat(_));
    let store = match &ctx.store {
        Some(store) if allowed_here => store,
        _ => {
            debug!(
                user = %hex::encode(peer.user_id),
                op,
                role = role.as_metric_label(),
                "blob frame refused: storage disabled or wrong session role"
            );
            return refuse(framed, op, &echo, BlobReject::Unsupported).await;
        }
    };
    // Кусок загрузки rate-limit'ом не считается: его ограничивает суточный
    // объём, а куски одного файла идут сотнями подряд.
    let limiter = match &payload {
        frame::Payload::BlobUploadChunk(_) => None,
        frame::Payload::BlobStat(_) => Some(&ctx.limits.blob_stat),
        _ => Some(&ctx.limits.blob_ops),
    };
    if limiter.is_some_and(|limiter| !limiter.check(&peer.user_id, 0)) {
        return refuse(framed, op, &echo, BlobReject::RateLimited).await;
    }
    // Загрузка и управление — действия отправителя: делегированной
    // сессии нужно право SEND. Скачать, отпустить и проверить может любая.
    let writes = matches!(
        payload,
        frame::Payload::BlobUploadInit(_)
            | frame::Payload::BlobUploadChunk(_)
            | frame::Payload::BlobUploadCommit(_)
            | frame::Payload::BlobUploadStatus(_)
            | frame::Payload::BlobDelete(_)
            | frame::Payload::BlobExtend(_)
    );
    if writes && !peer.scope.can_send() {
        return refuse(framed, op, &echo, BlobReject::Forbidden).await;
    }

    let now = unix_now_secs();
    let outcome = match payload {
        frame::Payload::BlobGet(cmd) => {
            return stream_get(framed, store, ctx, peer, cmd, now).await;
        }
        other => operate(store, ctx, peer, other, now).await,
    };
    let reply = match outcome {
        Ok(reply) => reply,
        Err(err) => {
            warn!(
                user = %hex::encode(peer.user_id),
                op,
                error = %err,
                "blob operation failed"
            );
            Reply::reject(&echo, BlobReject::Internal)
        }
    };
    observability::observe_blob_op(op, reply.label);
    if let Some(frame) = reply.frame {
        framed.send_frame(&frame).await?;
    }
    Ok(())
}

/// Ответ на кадр хранилища и его исход для метрики.
struct Reply {
    frame: Option<Vec<u8>>,
    label: &'static str,
}

impl Reply {
    fn ok(ack: wire::BlobAck) -> Self {
        Self {
            frame: Some(encode_blob_ack(wire::BlobAck { ok: true, ..ack })),
            label: "ok",
        }
    }

    fn reject(echo: &Echo, reason: BlobReject) -> Self {
        Self {
            frame: Some(echo.reject(reason)),
            label: reason.as_metric_label(),
        }
    }

    fn silent() -> Self {
        Self {
            frame: None,
            label: "ok",
        }
    }
}

/// Операции, отвечающие одним кадром.
async fn operate(
    store: &BlobStore,
    ctx: &BlobContext,
    peer: &BlobPeer,
    payload: frame::Payload,
    now: u64,
) -> Result<Reply> {
    let echo = Echo::of(&payload);
    let invalid = || Ok(Reply::reject(&echo, BlobReject::Invalid));
    match payload {
        frame::Payload::BlobUploadInit(cmd) => {
            let queue_id = match cmd.queue_id.len() {
                0 => None,
                _ => match fixed_32(&cmd.queue_id) {
                    Some(queue_id) => Some(queue_id),
                    None => return invalid(),
                },
            };
            let (Some(sha256), Some(blob_id), Some(delete_token_hash)) = (
                fixed_32(&cmd.sha256),
                fixed_32(&cmd.blob_id),
                fixed_32(&cmd.delete_token_hash),
            ) else {
                return invalid();
            };
            let request = InitRequest {
                queue_id,
                size: cmd.size,
                sha256,
                ttl_secs: cmd.ttl_seconds,
                max_releases: cmd.max_releases,
                blob_id,
                delete_token_hash,
            };
            Ok(match store.init(&peer.user_id, &request, now)? {
                Ok(init) => {
                    debug!(
                        user = %hex::encode(peer.user_id),
                        blob = %blob_fingerprint(&blob_id),
                        size = request.size,
                        scope = if queue_id.is_some() { "recipient" } else { "own" },
                        "blob upload started"
                    );
                    Reply::ok(wire::BlobAck {
                        request_id: cmd.request_id,
                        blob_id: blob_id.to_vec(),
                        expires_at: init.expires_at,
                        ..wire::BlobAck::default()
                    })
                }
                Err(reason) => Reply::reject(&echo, reason),
            })
        }
        frame::Payload::BlobUploadChunk(cmd) => {
            let Some(blob_id) = fixed_32(&cmd.blob_id) else {
                return invalid();
            };
            let chunk_ack = |reason: BlobReject, committed_offset| Reply {
                frame: Some(encode_blob_ack(wire::BlobAck {
                    blob_id: blob_id.to_vec(),
                    reason: reason.to_wire(),
                    committed_offset,
                    ..wire::BlobAck::default()
                })),
                label: reason.as_metric_label(),
            };
            if cmd.data.len() > ctx.chunk_max {
                // Кусок длиннее объявленного — ошибка клиента; с какого
                // смещения продолжать, скажет сброшенное на диск.
                let committed = store
                    .status(&peer.user_id, &blob_id, now)?
                    .map_or(0, |status| status.committed_offset);
                return Ok(chunk_ack(BlobReject::Invalid, committed));
            }
            let written = store
                .write_chunk(
                    peer.connection_id,
                    &peer.user_id,
                    &blob_id,
                    cmd.offset,
                    &cmd.data,
                    now,
                )
                .await?;
            Ok(match written {
                Ok(ChunkOk { synced: None }) => Reply::silent(),
                Ok(ChunkOk {
                    synced: Some(synced),
                }) => Reply::ok(wire::BlobAck {
                    blob_id: blob_id.to_vec(),
                    committed_offset: synced,
                    ..wire::BlobAck::default()
                }),
                Err(ChunkReject {
                    reason,
                    expected_offset,
                }) => chunk_ack(reason, expected_offset),
            })
        }
        frame::Payload::BlobUploadCommit(cmd) => {
            let Some(blob_id) = fixed_32(&cmd.blob_id) else {
                return invalid();
            };
            Ok(match store.commit(&peer.user_id, &blob_id, now).await? {
                Ok(expires_at) => {
                    debug!(
                        user = %hex::encode(peer.user_id),
                        blob = %blob_fingerprint(&blob_id),
                        expires_at,
                        "blob committed"
                    );
                    Reply::ok(wire::BlobAck {
                        request_id: cmd.request_id,
                        blob_id: blob_id.to_vec(),
                        expires_at,
                        ..wire::BlobAck::default()
                    })
                }
                Err(reason) => Reply::reject(&echo, reason),
            })
        }
        frame::Payload::BlobUploadStatus(cmd) => {
            let Some(blob_id) = fixed_32(&cmd.blob_id) else {
                return invalid();
            };
            Ok(match store.status(&peer.user_id, &blob_id, now)? {
                Ok(status) => Reply::ok(wire::BlobAck {
                    request_id: cmd.request_id,
                    blob_id: blob_id.to_vec(),
                    committed_offset: status.committed_offset,
                    expires_at: status.expires_at,
                    ..wire::BlobAck::default()
                }),
                Err(reason) => Reply::reject(&echo, reason),
            })
        }
        frame::Payload::BlobRelease(mut cmd) => {
            let Some(blob_id) = id_from_secret(&mut cmd.blob_secret) else {
                return invalid();
            };
            let releaser = Releaser {
                user: peer.user_id,
                device: peer.device_id,
            };
            Ok(match store.release(&blob_id, releaser, now).await? {
                Ok(()) => Reply::ok(wire::BlobAck {
                    request_id: cmd.request_id,
                    ..wire::BlobAck::default()
                }),
                Err(reason) => Reply::reject(&echo, reason),
            })
        }
        frame::Payload::BlobDelete(mut cmd) => {
            let token = take_secret(&mut cmd.delete_token);
            let (Some(blob_id), Some(token)) = (fixed_32(&cmd.blob_id), token) else {
                return invalid();
            };
            Ok(match store.delete(&blob_id, &token, now).await? {
                Ok(()) => {
                    debug!(
                        user = %hex::encode(peer.user_id),
                        blob = %blob_fingerprint(&blob_id),
                        "blob deleted by the uploader"
                    );
                    Reply::ok(wire::BlobAck {
                        request_id: cmd.request_id,
                        blob_id: blob_id.to_vec(),
                        ..wire::BlobAck::default()
                    })
                }
                Err(reason) => Reply::reject(&echo, reason),
            })
        }
        frame::Payload::BlobExtend(mut cmd) => {
            let token = take_secret(&mut cmd.delete_token);
            let (Some(blob_id), Some(token)) = (fixed_32(&cmd.blob_id), token) else {
                return invalid();
            };
            Ok(
                match store.extend(&blob_id, &token, cmd.ttl_seconds, now).await? {
                    Ok(expires_at) => Reply::ok(wire::BlobAck {
                        request_id: cmd.request_id,
                        blob_id: blob_id.to_vec(),
                        expires_at,
                        ..wire::BlobAck::default()
                    }),
                    Err(reason) => Reply::reject(&echo, reason),
                },
            )
        }
        frame::Payload::BlobStat(mut cmd) => {
            if cmd.items.len() > MAX_STAT_ITEMS {
                return invalid();
            }
            let mut queries = Vec::with_capacity(cmd.items.len());
            for item in &mut cmd.items {
                match stat_query(item) {
                    Some(query) => queries.push(query),
                    None => return invalid(),
                }
            }
            let entries = store
                .stat(&queries, now)?
                .into_iter()
                .map(|entry| wire::BlobStatEntry {
                    state: stat_state(entry.state) as i32,
                    expires_at: entry.expires_at,
                    releases_done: entry.releases.map_or(0, |(done, _)| done),
                    max_releases: entry.releases.map_or(0, |(_, max)| max),
                })
                .collect();
            Ok(Reply {
                frame: Some(encode_blob_stat_result(wire::BlobStatResult {
                    request_id: cmd.request_id,
                    entries,
                })),
                label: "ok",
            })
        }
        _ => Ok(Reply::silent()),
    }
}

/// Ответ на `BlobGet`: поток `BlobData`, а при отказе — `BlobAck` с
/// причиной, в том числе посреди потока, если блоб стёрли.
async fn stream_get(
    framed: &mut NoiseFramed<TcpStream>,
    store: &BlobStore,
    ctx: &BlobContext,
    peer: &BlobPeer,
    mut cmd: wire::BlobGet,
    now: u64,
) -> Result<()> {
    let echo = Echo {
        request_id: cmd.request_id,
        blob_id: Vec::new(),
    };
    let Some(blob_id) = id_from_secret(&mut cmd.blob_secret) else {
        return refuse(framed, "get", &echo, BlobReject::Invalid).await;
    };
    let mut reader = match store
        .open_reader(&blob_id, cmd.offset, cmd.length, ctx.chunk_max, now)
        .await
    {
        Ok(Ok(reader)) => reader,
        Ok(Err(reason)) => return refuse(framed, "get", &echo, reason).await,
        Err(err) => {
            warn!(
                user = %hex::encode(peer.user_id),
                blob = %blob_fingerprint(&blob_id),
                error = %err,
                "blob read failed"
            );
            return refuse(framed, "get", &echo, BlobReject::Internal).await;
        }
    };
    loop {
        let chunk = match reader.next_chunk().await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(reason)) => return refuse(framed, "get", &echo, reason).await,
            Err(err) => {
                warn!(
                    user = %hex::encode(peer.user_id),
                    blob = %blob_fingerprint(&blob_id),
                    error = %err,
                    "blob read failed"
                );
                return refuse(framed, "get", &echo, BlobReject::Internal).await;
            }
        };
        // Кусок прочитан до того, как блоб стёрли, но отправляется после:
        // ворота уже закрыты — вместо него причина.
        if let Some(reason) = reader.interrupted() {
            return refuse(framed, "get", &echo, reason).await;
        }
        let eof = chunk.eof;
        framed
            .send_frame(&encode_blob_data(
                cmd.request_id,
                chunk.offset,
                chunk.data,
                eof,
            ))
            .await?;
        if eof {
            break;
        }
    }
    observability::observe_blob_op("get", "ok");
    Ok(())
}

async fn refuse(
    framed: &mut NoiseFramed<TcpStream>,
    op: &'static str,
    echo: &Echo,
    reason: BlobReject,
) -> Result<()> {
    observability::observe_blob_op(op, reason.as_metric_label());
    framed.send_frame(&echo.reject(reason)).await?;
    Ok(())
}

/// Секрет клиента (32 байта) в затираемую копию; поле кадра затирается
/// сразу. `None` — длина не та.
fn take_secret(raw: &mut Vec<u8>) -> Option<Zeroizing<[u8; 32]>> {
    let secret = fixed_32(raw).map(Zeroizing::new);
    raw.zeroize();
    secret
}

/// `blob_id` по секрету читателя; сам секрет нигде не остаётся.
fn id_from_secret(raw: &mut Vec<u8>) -> Option<BlobId> {
    take_secret(raw).map(|secret| blob_id_of(&secret))
}

/// Запись `BlobStat`: ровно одно из — секрет читателя или id с токеном.
fn stat_query(item: &mut wire::BlobStatQuery) -> Option<StatQuery> {
    let by_secret = !item.blob_secret.is_empty();
    let by_token = !item.blob_id.is_empty() || !item.delete_token.is_empty();
    match (by_secret, by_token) {
        (true, false) => id_from_secret(&mut item.blob_secret).map(StatQuery::Reader),
        (false, true) => {
            let token = take_secret(&mut item.delete_token)?;
            Some(StatQuery::Manager {
                id: fixed_32(&item.blob_id)?,
                token,
            })
        }
        _ => {
            item.blob_secret.zeroize();
            item.delete_token.zeroize();
            None
        }
    }
}

fn stat_state(state: StatState) -> wire::BlobState {
    match state {
        StatState::Ready => wire::BlobState::Ready,
        StatState::Uploading => wire::BlobState::Uploading,
        StatState::Expired => wire::BlobState::Expired,
        StatState::Deleted => wire::BlobState::Deleted,
        StatState::NotFound => wire::BlobState::NotFound,
        StatState::Forbidden => wire::BlobState::Forbidden,
    }
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

/// Что вернуть в отказе: `request_id` кадра, у куска — его `blob_id`
/// (своего `request_id` у куска нет).
struct Echo {
    request_id: u64,
    blob_id: Vec<u8>,
}

impl Echo {
    fn of(payload: &frame::Payload) -> Self {
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
        Self {
            request_id,
            blob_id,
        }
    }

    fn reject(&self, reason: BlobReject) -> Vec<u8> {
        encode_blob_ack(wire::BlobAck {
            request_id: self.request_id,
            ok: false,
            reason: reason.to_wire(),
            blob_id: self.blob_id.clone(),
            committed_offset: 0,
            expires_at: 0,
        })
    }
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
