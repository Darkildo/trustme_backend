//! Хранилище файлов по проводу (server-contract.md §6.11): загрузка,
//! докачка, скачивание, релизы, удаление, проверка наличия, права и
//! лимиты.

mod common;

use std::time::Duration;

use anyhow::{Result, bail};
use common::{
    Conn, FRAME_MAX, NodeOptions, ServerHandle, connect_as, connect_blob, connect_delegated_blob,
    decode, device_key, expect_auth_ok, issue_device_cert, next_frame, random_identity,
    spawn_node_with, spawn_server, unix_now_secs, user_id_of,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::net::TcpSocket;
use trust_message_tcp::config::LimitsConfig;
use trust_message_tcp::net::noise::{NoiseFramed, SessionRole};
use trust_message_tcp::wire::{self, BlobRejectReason, BlobState, Frame, frame};

/// Кусок тестовой ноды (`common::test_blob_config`).
const CHUNK: usize = 64 * 1024;
const WINDOW: usize = 256 * 1024;
const TOKEN: [u8; 32] = [0x77; 32];

fn wrap(payload: frame::Payload) -> Vec<u8> {
    Frame {
        proto_version: common::PROTO_VERSION,
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn sha(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
        .collect()
}

fn random_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    secret
}

async fn messages(server: &ServerHandle, identity: &SigningKey, device: u16) -> Result<Conn> {
    let mut conn = connect_as(server, identity, Some(device), FRAME_MAX).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn blob(server: &ServerHandle, identity: &SigningKey, device: u16) -> Result<Conn> {
    let mut conn = connect_blob(server, identity, Some(device)).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

async fn allocate_queue(conn: &mut Conn) -> Result<Vec<u8>> {
    conn.send_frame(&wrap(frame::Payload::AllocateQueue(
        wire::AllocateQueue::default(),
    )))
    .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::QueueAck(ack) if ack.ok => Ok(ack.queue_id),
        other => bail!("expected a successful QueueAck, got {other:?}"),
    }
}

async fn expect_ack(conn: &mut Conn) -> Result<wire::BlobAck> {
    match decode(&next_frame(conn).await?)? {
        frame::Payload::BlobAck(ack) => Ok(ack),
        other => bail!("expected BlobAck, got {other:?}"),
    }
}

fn reason(ack: &wire::BlobAck) -> BlobRejectReason {
    BlobRejectReason::try_from(ack.reason).unwrap_or(BlobRejectReason::Unspecified)
}

/// Загружаемый файл: секрет у клиентов, нода видит только его хэш.
struct Upload {
    secret: [u8; 32],
    data: Vec<u8>,
    queue_id: Vec<u8>,
    ttl_seconds: u64,
    max_releases: u32,
}

impl Upload {
    fn new(data: Vec<u8>, queue_id: Vec<u8>) -> Self {
        Self {
            secret: random_secret(),
            data,
            queue_id,
            ttl_seconds: 0,
            max_releases: 0,
        }
    }

    fn blob_id(&self) -> Vec<u8> {
        sha(&self.secret)
    }

    fn init(&self, request_id: u64) -> Vec<u8> {
        wrap(frame::Payload::BlobUploadInit(wire::BlobUploadInit {
            queue_id: self.queue_id.clone(),
            size: self.data.len() as u64,
            sha256: sha(&self.data),
            ttl_seconds: self.ttl_seconds,
            max_releases: self.max_releases,
            blob_id: self.blob_id(),
            delete_token_hash: sha(&TOKEN),
            request_id,
        }))
    }

    fn chunk(&self, offset: usize, len: usize) -> Vec<u8> {
        let end = (offset + len).min(self.data.len());
        wrap(frame::Payload::BlobUploadChunk(wire::BlobUploadChunk {
            blob_id: self.blob_id(),
            offset: offset as u64,
            data: self.data[offset..end].to_vec(),
        }))
    }

    fn commit(&self, request_id: u64) -> Vec<u8> {
        wrap(frame::Payload::BlobUploadCommit(wire::BlobUploadCommit {
            blob_id: self.blob_id(),
            request_id,
        }))
    }

    fn status(&self, request_id: u64) -> Vec<u8> {
        wrap(frame::Payload::BlobUploadStatus(wire::BlobUploadStatus {
            blob_id: self.blob_id(),
            request_id,
        }))
    }

    fn get(&self, offset: u64, length: u64, request_id: u64) -> Vec<u8> {
        get_frame(&self.secret, offset, length, request_id)
    }

    fn release(&self, request_id: u64) -> Vec<u8> {
        wrap(frame::Payload::BlobRelease(wire::BlobRelease {
            blob_secret: self.secret.to_vec(),
            request_id,
        }))
    }

    fn delete(&self, token: [u8; 32], request_id: u64) -> Vec<u8> {
        wrap(frame::Payload::BlobDelete(wire::BlobDelete {
            blob_id: self.blob_id(),
            delete_token: token.to_vec(),
            request_id,
        }))
    }
}

fn get_frame(secret: &[u8; 32], offset: u64, length: u64, request_id: u64) -> Vec<u8> {
    wrap(frame::Payload::BlobGet(wire::BlobGet {
        blob_secret: secret.to_vec(),
        offset,
        length,
        request_id,
    }))
}

/// Отправить куски `[from, to)` подряд, не читая ответов.
async fn send_chunks(conn: &mut Conn, upload: &Upload, from: usize, to: usize) -> Result<()> {
    let mut offset = from;
    while offset < to {
        let len = CHUNK.min(to - offset);
        conn.send_frame(&upload.chunk(offset, len)).await?;
        offset += len;
    }
    Ok(())
}

/// Дочитать подтверждения прогресса до `want` включительно.
async fn await_progress(conn: &mut Conn, upload: &Upload, want: u64) -> Result<()> {
    loop {
        let ack = expect_ack(conn).await?;
        assert!(ack.ok, "chunk rejected: {:?}", reason(&ack));
        assert_eq!(ack.blob_id, upload.blob_id());
        assert_eq!(ack.request_id, 0);
        if ack.committed_offset == want {
            return Ok(());
        }
        assert!(ack.committed_offset < want);
    }
}

/// Полный цикл загрузки; возвращает срок из `Commit`.
async fn upload(conn: &mut Conn, upload: &Upload) -> Result<u64> {
    conn.send_frame(&upload.init(1)).await?;
    let ack = expect_ack(conn).await?;
    assert!(ack.ok, "init rejected: {:?}", reason(&ack));
    assert_eq!((ack.request_id, ack.committed_offset), (1, 0));
    assert_eq!(ack.blob_id, upload.blob_id());
    send_chunks(conn, upload, 0, upload.data.len()).await?;
    await_progress(conn, upload, upload.data.len() as u64).await?;
    conn.send_frame(&upload.commit(2)).await?;
    let ack = expect_ack(conn).await?;
    assert!(ack.ok, "commit rejected: {:?}", reason(&ack));
    assert_eq!(ack.request_id, 2);
    Ok(ack.expires_at)
}

/// Ответ на один `BlobGet`: данные и, если поток оборвался, отказ.
async fn get(
    conn: &mut Conn,
    frame: &[u8],
    request_id: u64,
) -> Result<(Vec<u8>, Option<wire::BlobAck>)> {
    conn.send_frame(frame).await?;
    read_get(conn, request_id).await
}

async fn read_get(conn: &mut Conn, request_id: u64) -> Result<(Vec<u8>, Option<wire::BlobAck>)> {
    let mut data = Vec::new();
    loop {
        match decode(&next_frame(conn).await?)? {
            frame::Payload::BlobData(chunk) => {
                assert_eq!(chunk.request_id, request_id);
                assert!(chunk.data.len() <= CHUNK);
                data.extend_from_slice(&chunk.data);
                if chunk.eof {
                    return Ok((data, None));
                }
            }
            frame::Payload::BlobAck(ack) => {
                assert_eq!(ack.request_id, request_id);
                assert!(!ack.ok);
                return Ok((data, Some(ack)));
            }
            other => bail!("expected BlobData or BlobAck, got {other:?}"),
        }
    }
}

async fn download_all(conn: &mut Conn, upload: &Upload) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut request_id = 100;
    while data.len() < upload.data.len() {
        request_id += 1;
        let (part, refused) = get(
            conn,
            &upload.get(data.len() as u64, 0, request_id),
            request_id,
        )
        .await?;
        assert!(refused.is_none(), "get refused: {refused:?}");
        assert!(part.len() <= WINDOW);
        data.extend_from_slice(&part);
    }
    Ok(data)
}

fn stat_item_reader(secret: &[u8; 32]) -> wire::BlobStatQuery {
    wire::BlobStatQuery {
        blob_secret: secret.to_vec(),
        ..wire::BlobStatQuery::default()
    }
}

async fn stat(
    conn: &mut Conn,
    items: Vec<wire::BlobStatQuery>,
    request_id: u64,
) -> Result<std::result::Result<wire::BlobStatResult, wire::BlobAck>> {
    conn.send_frame(&wrap(frame::Payload::BlobStat(wire::BlobStat {
        items,
        request_id,
    })))
    .await?;
    match decode(&next_frame(conn).await?)? {
        frame::Payload::BlobStatResult(result) => {
            assert_eq!(result.request_id, request_id);
            Ok(Ok(result))
        }
        frame::Payload::BlobAck(ack) => Ok(Err(ack)),
        other => bail!("expected BlobStatResult, got {other:?}"),
    }
}

/// Личный файл: отправитель кладёт его в ящик получателя по очереди,
/// получатель скачивает целиком и диапазонами, проверяет и отпускает.
#[tokio::test]
async fn personal_file_roundtrip() -> Result<()> {
    let server = spawn_server("blob_roundtrip", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let mut alice_messages = messages(&server, &alice, 1).await?;
    let queue_id = allocate_queue(&mut alice_messages).await?;

    let mut bob_blob = blob(&server, &bob, 1).await?;
    let mut file = Upload::new(payload(600 * 1024 + 123, 1), queue_id);
    file.max_releases = 1;
    file.ttl_seconds = 999_999_999;
    let now = unix_now_secs();
    let expires_at = upload(&mut bob_blob, &file).await?;
    // Срок зажат потолком ноды (30 суток) и считается от `Commit`.
    assert!((now + 30 * 86_400..=now + 30 * 86_400 + 5).contains(&expires_at));

    let mut alice_blob = blob(&server, &alice, 1).await?;
    // Целиком — окнами по 256 КиБ.
    assert_eq!(download_all(&mut alice_blob, &file).await?, file.data);
    // Диапазон.
    let (part, refused) = get(&mut alice_blob, &file.get(1_000, 5_000, 7), 7).await?;
    assert!(refused.is_none());
    assert_eq!(part, file.data[1_000..6_000]);
    // За пределами — INVALID; неверный секрет неотличим от отсутствия.
    let (_, refused) = get(&mut alice_blob, &file.get(file.data.len() as u64, 0, 8), 8).await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::Invalid);
    let (_, refused) = get(&mut alice_blob, &get_frame(&random_secret(), 0, 0, 9), 9).await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::NotFound);
    let (_, refused) = get(
        &mut alice_blob,
        &wrap(frame::Payload::BlobGet(wire::BlobGet {
            blob_secret: vec![1u8; 31],
            request_id: 10,
            ..wire::BlobGet::default()
        })),
        10,
    )
    .await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::Invalid);

    // Проверка наличия — из сессии сообщений.
    let result = stat(
        &mut alice_messages,
        vec![stat_item_reader(&file.secret)],
        11,
    )
    .await?
    .unwrap();
    assert_eq!(result.entries[0].state, BlobState::Ready as i32);
    assert_eq!(result.entries[0].expires_at, expires_at);

    // Релиз единственным читателем стирает блоб; повтор — NOT_FOUND.
    alice_blob.send_frame(&file.release(12)).await?;
    let ack = expect_ack(&mut alice_blob).await?;
    assert!(ack.ok && ack.request_id == 12);
    let (_, refused) = get(&mut alice_blob, &file.get(0, 0, 13), 13).await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::NotFound);
    Ok(())
}

/// Обрыв посреди загрузки: новое соединение узнаёт сброшенное смещение
/// (`Status`) и продолжает с него; кусок не с того смещения — INVALID с
/// ожидаемым смещением.
#[tokio::test]
async fn upload_resumes_after_a_disconnect() -> Result<()> {
    let server = spawn_server("blob_resume", LimitsConfig::default()).await?;
    let bob = random_identity();
    let file = Upload::new(payload(400 * 1024, 2), Vec::new());
    {
        let mut conn = blob(&server, &bob, 1).await?;
        conn.send_frame(&file.init(1)).await?;
        assert!(expect_ack(&mut conn).await?.ok);
        // Три куска: сброс на диск — на 128 КиБ, третий остаётся в памяти.
        send_chunks(&mut conn, &file, 0, 3 * CHUNK).await?;
        await_progress(&mut conn, &file, 2 * CHUNK as u64).await?;
    }

    let mut conn = blob(&server, &bob, 1).await?;
    let mut status = expect_status(&mut conn, &file, 5).await?;
    for _ in 0..50 {
        if status.committed_offset == 2 * CHUNK as u64 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        status = expect_status(&mut conn, &file, 5).await?;
    }
    assert_eq!(status.committed_offset, 2 * CHUNK as u64);
    assert!(status.expires_at > unix_now_secs());

    // Продолжать с несброшенного нельзя.
    conn.send_frame(&file.chunk(3 * CHUNK, CHUNK)).await?;
    let ack = expect_ack(&mut conn).await?;
    assert_eq!(reason(&ack), BlobRejectReason::Invalid);
    assert_eq!(ack.committed_offset, 2 * CHUNK as u64);
    assert_eq!(ack.blob_id, file.blob_id());
    // Кусок длиннее объявленного — тоже INVALID со смещением.
    conn.send_frame(&wrap(frame::Payload::BlobUploadChunk(
        wire::BlobUploadChunk {
            blob_id: file.blob_id(),
            offset: 2 * CHUNK as u64,
            data: vec![0u8; CHUNK + 1],
        },
    )))
    .await?;
    let ack = expect_ack(&mut conn).await?;
    assert_eq!(reason(&ack), BlobRejectReason::Invalid);
    assert_eq!(ack.committed_offset, 2 * CHUNK as u64);

    send_chunks(&mut conn, &file, 2 * CHUNK, file.data.len()).await?;
    await_progress(&mut conn, &file, file.data.len() as u64).await?;
    conn.send_frame(&file.commit(6)).await?;
    assert!(expect_ack(&mut conn).await?.ok);
    assert_eq!(download_all(&mut conn, &file).await?, file.data);

    // `Status` готового — полный размер.
    let status = expect_status(&mut conn, &file, 7).await?;
    assert_eq!(status.committed_offset, file.data.len() as u64);
    Ok(())
}

async fn expect_status(conn: &mut Conn, file: &Upload, request_id: u64) -> Result<wire::BlobAck> {
    conn.send_frame(&file.status(request_id)).await?;
    let ack = expect_ack(conn).await?;
    assert!(ack.ok, "status rejected: {:?}", reason(&ack));
    assert_eq!(ack.request_id, request_id);
    Ok(ack)
}

/// Права: живая очередь получателя, загрузку дописывает только
/// загрузивший, занятый id — CONFLICT, управление — только по токену,
/// делегированной сессии без SEND загружать нельзя, а скачивать можно.
#[tokio::test]
async fn rights_follow_queues_uploaders_and_tokens() -> Result<()> {
    let server = spawn_server("blob_rights", LimitsConfig::default()).await?;
    let alice = random_identity();
    let bob = random_identity();
    let mallory = random_identity();
    let mut alice_messages = messages(&server, &alice, 1).await?;
    let queue_id = allocate_queue(&mut alice_messages).await?;
    let revoked_queue = allocate_queue(&mut alice_messages).await?;
    alice_messages
        .send_frame(&wrap(frame::Payload::RevokeQueue(wire::RevokeQueue {
            queue_id: revoked_queue.clone(),
        })))
        .await?;
    match decode(&next_frame(&mut alice_messages).await?)? {
        frame::Payload::QueueAck(ack) => assert!(ack.ok),
        other => bail!("expected QueueAck, got {other:?}"),
    }

    let mut bob_blob = blob(&server, &bob, 1).await?;
    for queue in [revoked_queue, vec![5u8; 32]] {
        let file = Upload::new(payload(10, 3), queue);
        bob_blob.send_frame(&file.init(1)).await?;
        assert_eq!(
            reason(&expect_ack(&mut bob_blob).await?),
            BlobRejectReason::Forbidden
        );
    }
    let file = Upload::new(payload(100 * 1024, 4), queue_id.clone());
    let wrong_length = Upload::new(payload(10, 3), vec![1u8; 31]);
    bob_blob.send_frame(&wrong_length.init(1)).await?;
    assert_eq!(
        reason(&expect_ack(&mut bob_blob).await?),
        BlobRejectReason::Invalid
    );
    bob_blob.send_frame(&file.init(1)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);

    // Чужой не дописывает и не занимает тот же id.
    let mut mallory_blob = blob(&server, &mallory, 1).await?;
    mallory_blob.send_frame(&file.chunk(0, CHUNK)).await?;
    assert_eq!(
        reason(&expect_ack(&mut mallory_blob).await?),
        BlobRejectReason::Forbidden
    );
    mallory_blob.send_frame(&file.init(1)).await?;
    assert_eq!(
        reason(&expect_ack(&mut mallory_blob).await?),
        BlobRejectReason::Conflict
    );
    mallory_blob.send_frame(&file.delete([0u8; 32], 2)).await?;
    assert_eq!(
        reason(&expect_ack(&mut mallory_blob).await?),
        BlobRejectReason::Forbidden
    );
    // Скачать до коммита — NOT_READY.
    let (_, refused) = get(&mut mallory_blob, &file.get(0, 0, 3), 3).await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::NotReady);

    // Делегированная сессия без SEND: загружать нельзя, скачивать — можно.
    send_chunks(&mut bob_blob, &file, 0, file.data.len()).await?;
    await_progress(&mut bob_blob, &file, file.data.len() as u64).await?;
    bob_blob.send_frame(&file.commit(4)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    let now = unix_now_secs();
    let key = device_key();
    let cert = issue_device_cert(&alice, 9, &key.public, 0, now - 60, now + 86_400);
    let mut alice_background =
        connect_delegated_blob(&server, &user_id_of(&alice), &key, 9, cert).await?;
    expect_auth_ok(
        &next_frame(&mut alice_background).await?,
        &user_id_of(&alice),
    )?;
    let own = Upload::new(payload(10, 5), Vec::new());
    alice_background.send_frame(&own.init(5)).await?;
    let ack = expect_ack(&mut alice_background).await?;
    assert_eq!(
        (reason(&ack), ack.request_id),
        (BlobRejectReason::Forbidden, 5)
    );
    assert_eq!(download_all(&mut alice_background, &file).await?, file.data);
    alice_background.send_frame(&file.release(6)).await?;
    assert!(expect_ack(&mut alice_background).await?.ok);
    Ok(())
}

/// Сессия с маленьким приёмным буфером: нода упирается в сокет посреди
/// ответа на `BlobGet`, и удаление застаёт скачивание в процессе.
async fn slow_blob_session(server: &ServerHandle, identity: &SigningKey) -> Result<Conn> {
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(8 * 1024)?;
    let stream = socket.connect(server.addr).await?;
    let inner = NoiseFramed::connect_with_role(
        stream,
        &server.node_public,
        identity,
        Some(2),
        SessionRole::Blob,
        common::HANDSHAKE_TIMEOUT,
        FRAME_MAX,
    )
    .await?;
    let mut conn = common::confirm(inner).await?;
    expect_auth_ok(&next_frame(&mut conn).await?, &user_id_of(identity))?;
    Ok(conn)
}

/// Удаление загрузившим посреди чужого скачивания: поток обрывается
/// `BlobAck` DELETED, хвост не досылается; дальше всё — DELETED.
#[tokio::test]
async fn delete_interrupts_a_download_in_another_session() -> Result<()> {
    const SIZE: usize = 12 * 1024 * 1024;
    let (server, _internals) = spawn_node_with(
        "blob_delete_download",
        LimitsConfig::default(),
        NodeOptions {
            blob_config: Some(Box::new(|blobs| {
                blobs.get_window = 16 * 1024 * 1024;
                blobs.sync_every = 4 * 1024 * 1024;
            })),
            ..NodeOptions::default()
        },
    )
    .await?;
    let alice = random_identity();
    let bob = random_identity();
    let mut bob_blob = blob(&server, &bob, 1).await?;
    let file = Upload::new(payload(SIZE, 6), Vec::new());
    upload(&mut bob_blob, &file).await?;

    let mut alice_blob = slow_blob_session(&server, &alice).await?;
    alice_blob.send_frame(&file.get(0, 0, 21)).await?;
    match decode(&next_frame(&mut alice_blob).await?)? {
        frame::Payload::BlobData(chunk) => assert_eq!((chunk.offset, chunk.eof), (0, false)),
        other => bail!("expected BlobData, got {other:?}"),
    }
    // Нода дописывает в сокет, пока не упрётся в буферы.
    tokio::time::sleep(Duration::from_millis(300)).await;

    bob_blob.send_frame(&file.delete(TOKEN, 22)).await?;
    let ack = expect_ack(&mut bob_blob).await?;
    assert!(ack.ok && ack.request_id == 22);

    let (received, refused) = read_get(&mut alice_blob, 21).await?;
    let refused = refused.expect("download must end with DELETED");
    assert_eq!(reason(&refused), BlobRejectReason::Deleted);
    assert!(
        received.len() + CHUNK < SIZE,
        "хвост не досылается: получено {} из {SIZE}",
        received.len() + CHUNK
    );
    // После отказа данных этого ответа больше нет: следующий кадр — Pong.
    alice_blob
        .send_frame(&wrap(frame::Payload::Ping(wire::Ping {})))
        .await?;
    match decode(&next_frame(&mut alice_blob).await?)? {
        frame::Payload::Pong(_) => {}
        other => bail!("expected Pong after the interrupted download, got {other:?}"),
    }

    // Всё дальше — DELETED, повтор удаления — ok, чужой токен — FORBIDDEN.
    let (_, refused) = get(&mut alice_blob, &file.get(0, 0, 23), 23).await?;
    assert_eq!(reason(&refused.unwrap()), BlobRejectReason::Deleted);
    alice_blob.send_frame(&file.release(24)).await?;
    assert_eq!(
        reason(&expect_ack(&mut alice_blob).await?),
        BlobRejectReason::Deleted
    );
    bob_blob.send_frame(&file.delete(TOKEN, 25)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    bob_blob.send_frame(&file.delete([1u8; 32], 26)).await?;
    assert_eq!(
        reason(&expect_ack(&mut bob_blob).await?),
        BlobRejectReason::Forbidden
    );
    bob_blob
        .send_frame(&wrap(frame::Payload::BlobExtend(wire::BlobExtend {
            blob_id: file.blob_id(),
            delete_token: TOKEN.to_vec(),
            ttl_seconds: 60,
            request_id: 27,
        })))
        .await?;
    assert_eq!(
        reason(&expect_ack(&mut bob_blob).await?),
        BlobRejectReason::Deleted
    );
    bob_blob.send_frame(&file.status(28)).await?;
    assert_eq!(
        reason(&expect_ack(&mut bob_blob).await?),
        BlobRejectReason::Deleted
    );
    Ok(())
}

/// `BlobStat`: все состояния в одной пачке и в её порядке, число релизов —
/// только по токену, больше 64 записей или негодная запись — INVALID,
/// ничего не меняет.
#[tokio::test]
async fn stat_reports_states_in_order() -> Result<()> {
    let server = spawn_server("blob_stat", LimitsConfig::default()).await?;
    let bob = random_identity();
    let mut bob_blob = blob(&server, &bob, 1).await?;

    let mut ready = Upload::new(payload(1_000, 7), Vec::new());
    ready.max_releases = 2;
    upload(&mut bob_blob, &ready).await?;
    bob_blob.send_frame(&ready.release(3)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    let uploading = Upload::new(payload(1_000, 8), Vec::new());
    bob_blob.send_frame(&uploading.init(4)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    let deleted = Upload::new(payload(1_000, 9), Vec::new());
    upload(&mut bob_blob, &deleted).await?;
    bob_blob.send_frame(&deleted.delete(TOKEN, 5)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);

    let manager = |file: &Upload, token: [u8; 32]| wire::BlobStatQuery {
        blob_secret: Vec::new(),
        blob_id: file.blob_id(),
        delete_token: token.to_vec(),
    };
    let items = vec![
        stat_item_reader(&ready.secret),
        stat_item_reader(&uploading.secret),
        stat_item_reader(&deleted.secret),
        stat_item_reader(&random_secret()),
        manager(&ready, [0u8; 32]),
        manager(&ready, TOKEN),
    ];
    let result = stat(&mut bob_blob, items.clone(), 6).await?.unwrap();
    let states: Vec<i32> = result.entries.iter().map(|entry| entry.state).collect();
    assert_eq!(
        states,
        [
            BlobState::Ready as i32,
            BlobState::Uploading as i32,
            BlobState::Deleted as i32,
            BlobState::NotFound as i32,
            BlobState::Forbidden as i32,
            BlobState::Ready as i32,
        ]
    );
    assert_eq!(
        (
            result.entries[0].releases_done,
            result.entries[0].max_releases
        ),
        (0, 0)
    );
    assert_eq!(
        (
            result.entries[5].releases_done,
            result.entries[5].max_releases
        ),
        (1, 2)
    );
    // Ничего не меняет: повтор даёт то же самое.
    assert_eq!(
        stat(&mut bob_blob, items, 7).await?.unwrap().entries,
        result.entries
    );

    let too_many = vec![stat_item_reader(&ready.secret); 65];
    let ack = stat(&mut bob_blob, too_many, 8).await?.unwrap_err();
    assert_eq!(
        (reason(&ack), ack.request_id),
        (BlobRejectReason::Invalid, 8)
    );
    let both = wire::BlobStatQuery {
        blob_secret: ready.secret.to_vec(),
        blob_id: ready.blob_id(),
        delete_token: TOKEN.to_vec(),
    };
    let ack = stat(&mut bob_blob, vec![both], 9).await?.unwrap_err();
    assert_eq!(reason(&ack), BlobRejectReason::Invalid);
    let empty = wire::BlobStatQuery::default();
    let ack = stat(&mut bob_blob, vec![empty], 10).await?.unwrap_err();
    assert_eq!(reason(&ack), BlobRejectReason::Invalid);
    Ok(())
}

/// Rate-limit'ы хранилища — свои, на пользователя, отдельно для `BlobStat`.
#[tokio::test]
async fn storage_operations_are_rate_limited() -> Result<()> {
    let (server, _internals) = spawn_node_with(
        "blob_rate",
        LimitsConfig::default(),
        NodeOptions {
            blob_config: Some(Box::new(|blobs| {
                blobs.ops_per_sec = 2;
                blobs.stat_per_sec = 2;
            })),
            ..NodeOptions::default()
        },
    )
    .await?;
    let bob = random_identity();
    let mut bob_blob = blob(&server, &bob, 1).await?;
    let file = Upload::new(payload(10, 1), Vec::new());
    let mut limited = 0;
    for request_id in 0..5 {
        bob_blob.send_frame(&file.status(request_id)).await?;
        let ack = expect_ack(&mut bob_blob).await?;
        if reason(&ack) == BlobRejectReason::RateLimited {
            limited += 1;
        } else {
            assert_eq!(reason(&ack), BlobRejectReason::NotFound);
        }
    }
    assert!(limited >= 1, "пять операций в секунду при потолке 2");

    // Свой бюджет у `BlobStat`, в том числе в сессии сообщений.
    let mut bob_messages = messages(&server, &bob, 2).await?;
    let mut limited = 0;
    for request_id in 0..5 {
        if stat(&mut bob_messages, Vec::new(), request_id)
            .await?
            .is_err()
        {
            limited += 1;
        }
    }
    assert!(limited >= 1, "пять проверок в секунду при потолке 2");
    Ok(())
}

/// Квота ящика получателя считается по объявленному размеру.
#[tokio::test]
async fn mailbox_quota_is_reserved_at_init() -> Result<()> {
    let (server, _internals) = spawn_node_with(
        "blob_quota",
        LimitsConfig::default(),
        NodeOptions {
            blob_config: Some(Box::new(|blobs| blobs.quota_per_owner = 100 * 1024)),
            ..NodeOptions::default()
        },
    )
    .await?;
    let alice = random_identity();
    let bob = random_identity();
    let mut alice_messages = messages(&server, &alice, 1).await?;
    let queue_id = allocate_queue(&mut alice_messages).await?;
    let mut bob_blob = blob(&server, &bob, 1).await?;
    let first = Upload::new(payload(80 * 1024, 1), queue_id.clone());
    bob_blob.send_frame(&first.init(1)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    let second = Upload::new(payload(40 * 1024, 2), queue_id);
    bob_blob.send_frame(&second.init(2)).await?;
    assert_eq!(
        reason(&expect_ack(&mut bob_blob).await?),
        BlobRejectReason::Quota
    );
    // Удаление освобождает квоту.
    bob_blob.send_frame(&first.delete(TOKEN, 3)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    bob_blob.send_frame(&second.init(4)).await?;
    assert!(expect_ack(&mut bob_blob).await?.ok);
    Ok(())
}
