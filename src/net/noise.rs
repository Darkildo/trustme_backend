//! Noise-транспорт ноды: Noise_IK (и Noise_XX для первого контакта) поверх
//! TCP.
//!
//! # Аутентификация клиента
//!
//! Identity клиента доказывается самим транспортом: статический ключ Noise
//! **и есть** `user_id`. Внешнего issuer'а токенов нет — в
//! permissionless-сети он был бы единой точкой доверия и отказа.
//!
//! # Ключевой материал
//!
//! `user_id` остаётся 32-байтовым Ed25519 public key (на нём держится вся
//! адресация: ключи sled, реестр сессий, subject'ы JetStream, push-токены).
//! Noise работает на X25519, поэтому статик выводится birational-отображением
//! Ed25519 → Montgomery — та же операция, что `crypto_sign_ed25519_pk_to_
//! curve25519` в libsodium. Клиент кладёт свой Ed25519 pk в payload
//! хендшейка, нода сверяет его конверсию с аутентифицированным
//! `remote_static`: подменить чужой `user_id` нельзя, не владея его секретом.
//!
//! # Формат на проводе
//!
//! ```text
//! MAGIC(4) || protoVersion(u16 LE) || pattern(u8) || [u16 LE len || noise message]...
//! ```
//!
//! Магию нельзя принять за правдоподобный length-prefix (её little-endian
//! прочтение много больше любого `MAX_FRAME_LEN`), поэтому peer с
//! length-prefixed кадрированием без Noise отвергается по первым байтам, без
//! эвристик. `protoVersion` и `pattern` идут открытым текстом, но входят в
//! **prologue** хендшейка: MITM, подменивший любой из них, получает
//! расхождение transcript'а, и хендшейк не сходится — это и есть
//! anti-downgrade.
//!
//! Noise-сообщение ограничено 65535 байтами, а логический кадр протокола —
//! `max_frame_len` (по умолчанию 8 MiB), поэтому поверх шифрованного потока
//! живёт собственное кадрирование: `u32 LE` длина логического кадра, затем
//! его байты, нарезанные на чанки по `NOISE_MAX_PAYLOAD_LEN`.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, info, warn};

use crate::net::device_cert::{self, SessionScope};
use crate::net::framing::PROTO_VERSION;
use crate::net::rate_limit::unix_now_secs;
use crate::observability;
use crate::state::registry::{DeviceId, UserId};
use crate::wire::NoiseClientHello;

/// Магия в начале соединения; входит в prologue хендшейка. В little-endian
/// это 0x314E4D54 ≈ 827 MB — заведомо больше любого `MAX_FRAME_LEN`, поэтому
/// её нельзя спутать с length-prefix кадра, а нода без Noise такой «кадр»
/// отвергает.
pub const NOISE_MAGIC: [u8; 4] = *b"TMN1";

/// Паттерн для клиента, который уже знает статик ноды.
pub const NOISE_PARAMS_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Паттерн для первого контакта: клиент узнаёт статик ноды в ходе
/// хендшейка и решает, доверять ли ему (TOFU).
pub const NOISE_PARAMS_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Какой паттерн Noise использует соединение.
///
/// Байт паттерна едет открытым текстом, но входит в **prologue**
/// хендшейка — поэтому MITM не может подменить IK на XX и заставить
/// клиента с пином принять чужой ключ: у сторон разойдутся transcript'ы, и
/// хендшейк не сойдётся.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoisePattern {
    /// Клиент знает статик ноды заранее. Нода не раскрывает свой ключ тому,
    /// кто его и так не знает.
    Ik,
    /// Первый контакт: клиент узнаёт статик ноды в msg2 и решает, доверять
    /// ли ему, до того как раскроет собственную identity в msg3.
    Xx,
}

impl NoisePattern {
    fn from_wire(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Ik),
            2 => Ok(Self::Xx),
            other => bail!("unknown noise pattern {other}"),
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            Self::Ik => 1,
            Self::Xx => 2,
        }
    }

    fn params(self) -> &'static str {
        match self {
            Self::Ik => NOISE_PARAMS_IK,
            Self::Xx => NOISE_PARAMS_XX,
        }
    }

    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Ik => "ik",
            Self::Xx => "xx",
        }
    }
}

/// Условия, на которых нода принимает хендшейк.
#[derive(Clone, Copy, Debug)]
pub struct HandshakePolicy {
    /// Потолок времени на весь хендшейк.
    pub timeout: Duration,
    /// Потолок логического кадра установленной сессии.
    pub max_frame_len: usize,
    /// Принимать ли XX — путь первого контакта. Выключение оставляет только
    /// клиентов с пином: активный MITM на первом контакте перестаёт быть
    /// возможен ценой того, что новый клиент не может подключиться, не
    /// получив ключ вне полосы.
    pub allow_tofu: bool,
    /// Потолок срока жизни сертификата устройства в секундах. Ноль —
    /// делегированный вход выключен, хендшейк с сертификатом отвергается.
    pub device_cert_max_ttl_secs: u64,
}

/// Потолок одного Noise-сообщения, зафиксированный спецификацией.
const NOISE_MAX_MESSAGE_LEN: usize = 65535;
/// Длина AEAD-тега ChaChaPoly.
const NOISE_TAG_LEN: usize = 16;
/// Сколько открытого текста влезает в одно Noise-сообщение.
const NOISE_MAX_PAYLOAD_LEN: usize = NOISE_MAX_MESSAGE_LEN - NOISE_TAG_LEN;
/// Заголовок логического кадра внутри шифрованного потока (u32 LE длина).
const LOGICAL_HEADER_LEN: usize = 4;
/// Имя файла с identity-ключом ноды внутри каталога хранилища.
const NODE_KEY_FILE: &str = "node_identity_key";

/// Человекочитаемый отпечаток статика ноды.
///
/// Сравнивать нужно строку целиком: отпечаток — это сам ключ, а не его
/// хеш, поэтому совпадение начала ничего не доказывает. Группировка
/// существует ради глаз, разделители при сравнении игнорируются.
pub fn fingerprint(node_static: &[u8; 32]) -> String {
    hex::encode_upper(node_static)
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Домен подписи снапшота конфигурации. Префикс отделяет эти подписи от
/// любых других, которые ключ ноды когда-либо сделает: без него подпись,
/// снятая в одном контексте, могла бы быть предъявлена в другом.
pub const SERVER_CONFIG_SIGNING_DOMAIN: &[u8] = b"trustmessage/server-config/v1";

/// Домен подписи запросов к внешнему push-шлюзу. Отделён от
/// конфигурационного: подпись запроса к шлюзу не должна предъявляться как
/// подпись конфигурации, и наоборот.
pub const PUSH_GATEWAY_SIGNING_DOMAIN: &[u8] = b"trustmessage/push-gateway/v1";

/// Умеет ли нода заявленную клиентом версию протокола.
///
/// Версия определяет кодек кадров: приняв соединение с чужой версией, нода
/// получила бы успешный хендшейк и мусор в кадрах вместо внятного отказа.
/// Поддерживается ровно одна версия.
fn supports_proto_version(version: u16) -> bool {
    version == PROTO_VERSION
}

/// Откуда взялся ключ ноды на этом старте. Различать источники важно
/// эксплуатационно: `Generated` на живой ноде означает, что прежний ключ
/// потерян вместе с томом, и все клиенты отрезаны до перепиннинга.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKeySource {
    /// Пин из `NODE_IDENTITY_KEY`.
    Configured,
    /// Прочитан из `storage_path/node_identity_key`.
    File,
    /// Сгенерирован на этом старте (файла не было).
    Generated,
}

impl NodeKeySource {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::File => "file",
            Self::Generated => "generated",
        }
    }
}

/// Ключ ноды. Хранится один секрет — **Ed25519 seed**, из которого
/// выводится всё остальное:
///
/// * X25519-статик для Noise — birational-отображением, ровно тем же,
///   каким клиент выводит свой статик из `user_id`;
/// * Ed25519-подписи (снапшот конфигурации, запросы к push-шлюзу) — напрямую.
///
/// Один ключ вместо двух: клиент, пиннящий X25519-статик, получает
/// проверяемую связь «подписал тот, с кем я говорю» — конверсия
/// identity-ключа обязана дать пин. С отдельным подписывающим ключом
/// пиннить пришлось бы два ключа.
///
/// Публичная часть X25519 — то, что клиент обязан знать заранее, чтобы
/// вообще начать IK-хендшейк: pre-auth plaintext-канала для bootstrap'а
/// нет, ключ раздаётся оператором вне полосы (конфиг приложения, QR,
/// ручной пин).
#[derive(Clone)]
pub struct NodeIdentity {
    signing: SigningKey,
    identity_public: [u8; 32],
    secret: [u8; 32],
    public: [u8; 32],
    source: NodeKeySource,
}

impl NodeIdentity {
    /// Загрузить ключ из `storage_path/node_identity_key`, а при
    /// отсутствии — сгенерировать и записать (0600). `configured`
    /// перекрывает файл: это путь для операторов, которые держат ключ в
    /// секрет-менеджере и хотят пин, переживающий пересоздание тома.
    pub fn load_or_generate(storage_path: &str, configured: Option<&str>) -> Result<Self> {
        if let Some(raw) = configured {
            let seed = parse_hex_secret(raw).context("NODE_IDENTITY_KEY is not valid hex")?;
            let identity = Self::from_seed(seed, NodeKeySource::Configured);
            observability::observe_node_key(identity.source.as_metric_label());
            info!(
                node_key = %identity.public_hex(),
                node_identity_key = %identity.identity_public_hex(),
                "node key pinned from NODE_IDENTITY_KEY"
            );
            return Ok(identity);
        }

        let path = node_key_path(storage_path);
        if path.exists() {
            warn_on_loose_permissions(&path);
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read node key at {}", path.display()))?;
            let seed = parse_hex_secret(raw.trim())
                .with_context(|| format!("node key at {} is malformed", path.display()))?;
            let identity = Self::from_seed(seed, NodeKeySource::File);
            observability::observe_node_key(identity.source.as_metric_label());
            return Ok(identity);
        }

        let seed = random_seed()?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create node key directory {}", parent.display())
            })?;
        }
        std::fs::write(&path, hex::encode(seed))
            .with_context(|| format!("failed to persist node key at {}", path.display()))?;
        restrict_permissions(&path)?;

        let identity = Self::from_seed(seed, NodeKeySource::Generated);
        observability::observe_node_key(identity.source.as_metric_label());
        // WARN, а не INFO: на первом старте это норма, но на живой ноде —
        // авария: прежний ключ потерян вместе с томом, и каждый клиент
        // отрезан до перепиннинга.
        warn!(
            path = %path.display(),
            node_key = %identity.public_hex(),
            node_identity_key = %identity.identity_public_hex(),
            "generated a NEW node key; clients pinned to the previous key \
             can no longer connect — expected only on a fresh node"
        );
        Ok(identity)
    }

    /// Собрать identity из Ed25519 seed. X25519-статик выводится тем же
    /// birational-отображением, которым нода проверяет статик клиента, —
    /// поэтому связь между подписывающим ключом и пином клиента
    /// арифметическая, а не «мы обещаем, что это один и тот же оператор».
    pub fn from_seed(seed: [u8; 32], source: NodeKeySource) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let identity_public = signing.verifying_key().to_bytes();
        let secret = signing.to_scalar_bytes();
        let public = signing.verifying_key().to_montgomery().to_bytes();
        Self {
            signing,
            identity_public,
            secret,
            public,
            source,
        }
    }

    /// Ed25519 public key — им проверяется подпись снапшота конфигурации.
    pub fn identity_public(&self) -> [u8; 32] {
        self.identity_public
    }

    pub fn identity_public_hex(&self) -> String {
        hex::encode(self.identity_public)
    }

    /// Подписать снапшот конфигурации. Домен подписи прибивается здесь, а
    /// не у вызывающего: ключ ноды не должен уметь подписать что-то, что
    /// потом предъявят как конфиг.
    pub fn sign_server_config(&self, config_bytes: &[u8]) -> [u8; 64] {
        let mut message =
            Vec::with_capacity(SERVER_CONFIG_SIGNING_DOMAIN.len() + config_bytes.len());
        message.extend_from_slice(SERVER_CONFIG_SIGNING_DOMAIN);
        message.extend_from_slice(config_bytes);
        self.signing.sign(&message).to_bytes()
    }

    /// Подписать запрос к push-шлюзу. Домен, как и у конфигурации,
    /// прибивается здесь: наружу `SigningKey` не выдаётся, поэтому вызывающий
    /// физически не может подписать этим ключом произвольные байты.
    ///
    /// Что доказывает эта подпись — см. `schemas/trustmessage/push/v1`:
    /// не право будить устройство (его даёт знание токена), а лишь
    /// самосогласованность запроса и стабильный ключ для rate-limit'а.
    pub fn sign_push_gateway(&self, payload: &[u8]) -> [u8; 64] {
        let mut message = Vec::with_capacity(PUSH_GATEWAY_SIGNING_DOMAIN.len() + payload.len());
        message.extend_from_slice(PUSH_GATEWAY_SIGNING_DOMAIN);
        message.extend_from_slice(payload);
        self.signing.sign(&message).to_bytes()
    }

    /// Откуда ключ взялся на этом старте — для логов и метрики.
    pub fn source(&self) -> NodeKeySource {
        self.source
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// Что нода узнала о клиенте из хендшейка. `user_id` уже сверен с
/// аутентифицированным статиком — это не заявка, а доказанная identity.
#[derive(Clone, Copy, Debug)]
pub struct NoiseSessionIdentity {
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub protocol_version: u16,
    /// Каким паттерном пришёл клиент. Различие видно в логах и метриках:
    /// доля XX — это доля подключений, доверие в которых установлено на
    /// первом контакте, а не проверено пином.
    pub pattern: NoisePattern,
    /// Права сессии. `FULL` — вход ключом аккаунта; иначе — биты
    /// сертификата устройства.
    pub scope: SessionScope,
    /// Когда истекает сертификат, которым открыта сессия (unix-секунды).
    /// Сессия не должна пережить своё основание: отзыва у сертификатов
    /// нет, и срок — единственное, что ограничивает украденный.
    pub cert_not_after: Option<u64>,
}

/// Кадровый транспорт поверх установленной Noise-сессии: «прочитать кадр /
/// отправить кадр». Внутри — шифрование и сборка логических кадров из
/// Noise-сообщений (до 64 KiB каждое).
pub struct NoiseFramed<S> {
    inner: Framed<S, LengthDelimitedCodec>,
    transport: TransportState,
    /// Расшифрованный, но ещё не разобранный на кадры поток.
    assembler: FrameAssembler,
    /// Буфер под одно расшифрованное/зашифрованное Noise-сообщение.
    scratch: Vec<u8>,
}

/// Сборка логических кадров из расшифрованного потока.
///
/// Живёт отдельным типом, потому что это единственный самописный парсер в
/// транспорте — всё остальное делают snow и `LengthDelimitedCodec`. В
/// отрыве от крипты его можно гонять фаззером (`fuzz/fuzz_targets/
/// chunk_framing.rs`) и тестами, не поднимая сессию.
///
/// Инвариант: сколько бы мусора ни прислал пир, буфер ограничен одним
/// кадром (плюс одно Noise-сообщение) — заявленная длина больше
/// `max_frame_len` отвергается до накопления байт.
pub struct FrameAssembler {
    pending: BytesMut,
    max_frame_len: usize,
}

impl FrameAssembler {
    pub fn new(max_frame_len: usize) -> Self {
        Self {
            pending: BytesMut::new(),
            max_frame_len,
        }
    }

    /// Добавить расшифрованный чанк в поток.
    pub fn push(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
    }

    /// Сколько байт сейчас накоплено и ещё не отдано кадром.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Потолок логического кадра этой сессии.
    pub fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }

    /// Отдать следующий полный кадр, если он уже собрался.
    ///
    /// `Ok(None)` — данных пока мало; `Err` — заявленная длина больше
    /// потолка, и это конец соединения: договориться о меньшем размере
    /// внутри установленной сессии нечем.
    pub fn take_frame(&mut self) -> io::Result<Option<BytesMut>> {
        if self.pending.len() < LOGICAL_HEADER_LEN {
            return Ok(None);
        }

        let mut header = [0u8; LOGICAL_HEADER_LEN];
        header.copy_from_slice(&self.pending[..LOGICAL_HEADER_LEN]);
        let frame_len = u32::from_le_bytes(header) as usize;
        if frame_len > self.max_frame_len {
            return Err(io::Error::other(format!(
                "incoming frame of {frame_len} bytes exceeds max_frame_len {}",
                self.max_frame_len
            )));
        }

        if self.pending.len() < LOGICAL_HEADER_LEN + frame_len {
            return Ok(None);
        }

        let _ = self.pending.split_to(LOGICAL_HEADER_LEN);
        Ok(Some(self.pending.split_to(frame_len)))
    }
}

impl<S> NoiseFramed<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Серверная сторона: прочитать пролог, отработать IK или XX и вернуть
    /// готовый транспорт вместе с доказанной identity клиента.
    ///
    /// Весь хендшейк укладывается в `handshake_timeout`: без него повисшее
    /// на первом байте соединение держало бы слот бесплатно.
    pub async fn accept(
        mut stream: S,
        node: &NodeIdentity,
        policy: HandshakePolicy,
    ) -> Result<(Self, NoiseSessionIdentity)> {
        timeout(
            policy.timeout,
            Self::accept_inner(&mut stream, node, policy),
        )
        .await
        .map_err(|_| anyhow::anyhow!("noise handshake timed out"))?
        .map(|(transport, identity)| {
            (
                Self {
                    inner: framed_codec(stream),
                    transport,
                    assembler: FrameAssembler::new(policy.max_frame_len),
                    scratch: vec![0u8; NOISE_MAX_MESSAGE_LEN],
                },
                identity,
            )
        })
    }

    async fn accept_inner(
        stream: &mut S,
        node: &NodeIdentity,
        policy: HandshakePolicy,
    ) -> Result<(TransportState, NoiseSessionIdentity)> {
        let mut magic = [0u8; 4];
        stream
            .read_exact(&mut magic)
            .await
            .context("failed to read noise magic")?;
        if magic != NOISE_MAGIC {
            bail!("unexpected transport magic {magic:?}: this node speaks noise only");
        }

        let mut version_bytes = [0u8; 2];
        stream
            .read_exact(&mut version_bytes)
            .await
            .context("failed to read client protocol version")?;
        let protocol_version = u16::from_le_bytes(version_bytes);

        // Отказ по версии — до крипты: хендшейк стоит нескольких
        // DH-операций, и платить их за соединение, кадры которого мы всё
        // равно не прочитаем, незачем.
        if !supports_proto_version(protocol_version) {
            bail!(
                "unsupported protocol version {protocol_version}; this node speaks {PROTO_VERSION}"
            );
        }

        let mut pattern_byte = [0u8; 1];
        stream
            .read_exact(&mut pattern_byte)
            .await
            .context("failed to read noise pattern")?;
        let pattern = NoisePattern::from_wire(pattern_byte[0])?;

        if matches!(pattern, NoisePattern::Xx) && !policy.allow_tofu {
            bail!("tofu handshake is disabled on this node");
        }

        // protoVersion и паттерн в prologue: подмена любого из них на
        // проводе ломает transcript, и хендшейк не сходится. Для паттерна
        // это важнее, чем для версии: без такой привязки MITM переключал бы
        // клиента с пином на TOFU-путь, где чужой ключ принимается.
        let prologue = build_prologue(protocol_version, pattern);
        let mut handshake = Builder::new(pattern.params().parse()?)
            .prologue(&prologue)
            .map_err(|err| anyhow::anyhow!("failed to set noise prologue: {err}"))?
            .local_private_key(node.secret())
            .map_err(|err| anyhow::anyhow!("failed to load node static key: {err}"))?
            .build_responder()
            .map_err(|err| anyhow::anyhow!("failed to build noise responder: {err}"))?;

        let mut payload = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut response = vec![0u8; NOISE_MAX_MESSAGE_LEN];

        // IK: клиент представляется в первом же сообщении. XX: первое
        // сообщение — только эфемерал, статик клиента приезжает третьим,
        // после того как он увидел статик ноды и решил ему доверять.
        let hello = match pattern {
            NoisePattern::Ik => {
                let message = read_handshake_message(stream).await?;
                let payload_len = handshake
                    .read_message(&message, &mut payload)
                    .map_err(|err| anyhow::anyhow!("noise handshake message 1 rejected: {err}"))?;
                let hello = decode_client_hello(&payload[..payload_len])?;

                let response_len = handshake.write_message(&[], &mut response).map_err(|err| {
                    anyhow::anyhow!("failed to build noise handshake response: {err}")
                })?;
                write_handshake_message(stream, &response[..response_len]).await?;
                hello
            }
            NoisePattern::Xx => {
                let message = read_handshake_message(stream).await?;
                handshake
                    .read_message(&message, &mut payload)
                    .map_err(|err| anyhow::anyhow!("noise handshake message 1 rejected: {err}"))?;

                let response_len = handshake.write_message(&[], &mut response).map_err(|err| {
                    anyhow::anyhow!("failed to build noise handshake response: {err}")
                })?;
                write_handshake_message(stream, &response[..response_len]).await?;

                let message = read_handshake_message(stream).await?;
                let payload_len = handshake
                    .read_message(&message, &mut payload)
                    .map_err(|err| anyhow::anyhow!("noise handshake message 3 rejected: {err}"))?;
                decode_client_hello(&payload[..payload_len])?
            }
        };

        let identity = verify_client_identity(
            &handshake,
            hello,
            protocol_version,
            pattern,
            unix_now_secs(),
            policy.device_cert_max_ttl_secs,
        )?;
        let transport = handshake
            .into_transport_mode()
            .map_err(|err| anyhow::anyhow!("noise handshake did not complete: {err}"))?;

        debug!(
            user = %hex::encode(identity.user_id),
            device_id = ?identity.device_id,
            protocol_version,
            pattern = pattern.as_metric_label(),
            delegated = identity.scope.is_delegated(),
            "noise handshake completed"
        );

        Ok((transport, identity))
    }

    /// Клиентская сторона (IK, ключ аккаунта). Эталонный инициатор для
    /// тестов и `examples/`.
    pub async fn connect(
        mut stream: S,
        node_public: &[u8; 32],
        identity: &SigningKey,
        device_id: Option<DeviceId>,
        handshake_timeout: Duration,
        max_frame_len: usize,
    ) -> Result<Self> {
        let transport = timeout(
            handshake_timeout,
            Self::connect_inner(&mut stream, node_public, identity, device_id),
        )
        .await
        .map_err(|_| anyhow::anyhow!("noise handshake timed out"))??;

        Ok(Self {
            inner: framed_codec(stream),
            transport,
            assembler: FrameAssembler::new(max_frame_len),
            scratch: vec![0u8; NOISE_MAX_MESSAGE_LEN],
        })
    }

    /// Делегированный вход: статик — ключ устройства, право говорить от
    /// имени `identity_key` доказывает сертификат. Секрет ключа аккаунта
    /// здесь не нужен.
    ///
    /// Инициатор использует только IK: сертификат выписывается устройству,
    /// которое ноду уже знает, а первый контакт (XX) — дело
    /// разблокированного клиента. Респондер сертификат в XX не запрещает.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_delegated(
        mut stream: S,
        node_public: &[u8; 32],
        device_static_secret: &[u8; 32],
        identity_key: &[u8; 32],
        device_id: DeviceId,
        device_cert: crate::wire::DeviceCertificate,
        handshake_timeout: Duration,
        max_frame_len: usize,
    ) -> Result<Self> {
        let transport = timeout(
            handshake_timeout,
            Self::connect_ik(
                &mut stream,
                node_public,
                device_static_secret,
                identity_key,
                Some(device_id),
                Some(device_cert),
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("noise handshake timed out"))??;

        Ok(Self {
            inner: framed_codec(stream),
            transport,
            assembler: FrameAssembler::new(max_frame_len),
            scratch: vec![0u8; NOISE_MAX_MESSAGE_LEN],
        })
    }

    /// Первый контакт с незнакомой нодой (TOFU).
    ///
    /// Ключ ноды приезжает в ходе хендшейка, и решение доверять ему
    /// принимает `accept_key`, а не эта функция: узнать ключ и принять его —
    /// разные решения.
    ///
    /// Колбэк вызывается после msg2 и до msg3. В XX клиент раскрывает свой
    /// статик именно в msg3, поэтому при отказе сторона, которой не
    /// доверяют, не получает и identity клиента.
    ///
    /// Возвращает статик ноды — его и нужно запинить, чтобы следующие
    /// подключения шли по IK.
    pub async fn connect_unpinned(
        mut stream: S,
        identity: &SigningKey,
        device_id: Option<DeviceId>,
        handshake_timeout: Duration,
        max_frame_len: usize,
        accept_key: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<(Self, [u8; 32])> {
        let (transport, node_public) = timeout(
            handshake_timeout,
            Self::connect_tofu_inner(&mut stream, identity, device_id, accept_key),
        )
        .await
        .map_err(|_| anyhow::anyhow!("noise handshake timed out"))??;

        Ok((
            Self {
                inner: framed_codec(stream),
                transport,
                assembler: FrameAssembler::new(max_frame_len),
                scratch: vec![0u8; NOISE_MAX_MESSAGE_LEN],
            },
            node_public,
        ))
    }

    async fn connect_inner(
        stream: &mut S,
        node_public: &[u8; 32],
        identity: &SigningKey,
        device_id: Option<DeviceId>,
    ) -> Result<TransportState> {
        Self::connect_ik(
            stream,
            node_public,
            &identity.to_scalar_bytes(),
            &identity.verifying_key().to_bytes(),
            device_id,
            None,
        )
        .await
    }

    /// IK-хендшейк с явным статиком: либо выведенным из ключа аккаунта
    /// (`device_cert = None`), либо ключом устройства с сертификатом.
    async fn connect_ik(
        stream: &mut S,
        node_public: &[u8; 32],
        static_secret: &[u8; 32],
        identity_key: &[u8; 32],
        device_id: Option<DeviceId>,
        device_cert: Option<crate::wire::DeviceCertificate>,
    ) -> Result<TransportState> {
        write_client_prologue(stream, NoisePattern::Ik).await?;

        let prologue = build_prologue(PROTO_VERSION, NoisePattern::Ik);
        let mut handshake = Builder::new(NOISE_PARAMS_IK.parse()?)
            .prologue(&prologue)
            .map_err(|err| anyhow::anyhow!("failed to set noise prologue: {err}"))?
            .local_private_key(static_secret)
            .map_err(|err| anyhow::anyhow!("failed to load client static key: {err}"))?
            .remote_public_key(node_public)
            .map_err(|err| anyhow::anyhow!("failed to load node public key: {err}"))?
            .build_initiator()
            .map_err(|err| anyhow::anyhow!("failed to build noise initiator: {err}"))?;

        let hello = encode_client_hello(identity_key, device_id, device_cert)?;
        let mut message = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = handshake
            .write_message(&hello, &mut message)
            .map_err(|err| anyhow::anyhow!("failed to build noise handshake message 1: {err}"))?;
        write_handshake_message(stream, &message[..len]).await?;

        let response = read_handshake_message(stream).await?;
        let mut payload = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        handshake
            .read_message(&response, &mut payload)
            .map_err(|err| anyhow::anyhow!("noise handshake response rejected: {err}"))?;

        handshake
            .into_transport_mode()
            .map_err(|err| anyhow::anyhow!("noise handshake did not complete: {err}"))
    }

    async fn connect_tofu_inner(
        stream: &mut S,
        identity: &SigningKey,
        device_id: Option<DeviceId>,
        accept_key: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<(TransportState, [u8; 32])> {
        write_client_prologue(stream, NoisePattern::Xx).await?;

        let prologue = build_prologue(PROTO_VERSION, NoisePattern::Xx);
        let mut handshake = Builder::new(NOISE_PARAMS_XX.parse()?)
            .prologue(&prologue)
            .map_err(|err| anyhow::anyhow!("failed to set noise prologue: {err}"))?
            .local_private_key(&identity.to_scalar_bytes())
            .map_err(|err| anyhow::anyhow!("failed to load client static key: {err}"))?
            .build_initiator()
            .map_err(|err| anyhow::anyhow!("failed to build noise initiator: {err}"))?;

        let mut message = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let mut payload = vec![0u8; NOISE_MAX_MESSAGE_LEN];

        let len = handshake
            .write_message(&[], &mut message)
            .map_err(|err| anyhow::anyhow!("failed to build noise handshake message 1: {err}"))?;
        write_handshake_message(stream, &message[..len]).await?;

        let response = read_handshake_message(stream).await?;
        handshake
            .read_message(&response, &mut payload)
            .map_err(|err| anyhow::anyhow!("noise handshake response rejected: {err}"))?;

        let node_public = handshake
            .get_remote_static()
            .ok_or_else(|| anyhow::anyhow!("noise handshake produced no node static key"))?;
        let node_public = to_fixed_32(node_public, "node static key")?;

        // Точка решения. Дальше клиент раскроет свой статик, поэтому отказ
        // здесь оставляет собеседника без identity клиента.
        if !accept_key(&node_public) {
            bail!("node key {} was not accepted", fingerprint(&node_public));
        }

        let hello = encode_client_hello(&identity.verifying_key().to_bytes(), device_id, None)?;
        let len = handshake
            .write_message(&hello, &mut message)
            .map_err(|err| anyhow::anyhow!("failed to build noise handshake message 3: {err}"))?;
        write_handshake_message(stream, &message[..len]).await?;

        let transport = handshake
            .into_transport_mode()
            .map_err(|err| anyhow::anyhow!("noise handshake did not complete: {err}"))?;
        Ok((transport, node_public))
    }

    /// Прочитать следующий логический кадр.
    ///
    /// Cancel-safe: единственная точка ожидания — чтение очередного
    /// Noise-сообщения из `Framed` (сам по себе cancel-safe), а расшифровка
    /// и накопление происходят синхронно и оседают в `self`. Это условие
    /// обязательное: метод вызывается из ветки `select!`.
    pub async fn next_frame(&mut self) -> io::Result<Option<BytesMut>> {
        loop {
            if let Some(frame) = self.assembler.take_frame()? {
                return Ok(Some(frame));
            }

            let Some(message) = self.inner.next().await.transpose()? else {
                return Ok(None);
            };

            let len = self
                .transport
                .read_message(&message, &mut self.scratch)
                .map_err(|err| io::Error::other(format!("noise decrypt failed: {err}")))?;
            self.assembler.push(&self.scratch[..len]);
        }
    }

    /// Отправить логический кадр: длина + тело, нарезанные на Noise-чанки.
    ///
    /// Отмена посередине рвёт кадр, поэтому вызывать метод можно только из
    /// тела ветки `select!`, а не как саму ветку.
    pub async fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > self.assembler.max_frame_len() {
            return Err(io::Error::other(format!(
                "outgoing frame of {} bytes exceeds max_frame_len {}",
                payload.len(),
                self.assembler.max_frame_len()
            )));
        }

        let mut header = [0u8; LOGICAL_HEADER_LEN];
        header.copy_from_slice(&(payload.len() as u32).to_le_bytes());

        // Заголовок и тело — один непрерывный поток: чанк может нести хвост
        // заголовка и начало тела.
        let mut chunk = Vec::with_capacity(NOISE_MAX_PAYLOAD_LEN);
        let mut source = header.iter().chain(payload.iter()).copied();
        loop {
            chunk.clear();
            chunk.extend(source.by_ref().take(NOISE_MAX_PAYLOAD_LEN));
            if chunk.is_empty() {
                return Ok(());
            }

            let len = self
                .transport
                .write_message(&chunk, &mut self.scratch)
                .map_err(|err| io::Error::other(format!("noise encrypt failed: {err}")))?;
            self.inner
                .send(Bytes::copy_from_slice(&self.scratch[..len]))
                .await?;
        }
    }
}

/// Кодек Noise-сообщений: префикс длины u16 LE; потолок сообщения — 65535
/// байт, как требует спецификация Noise.
fn framed_codec<S>(stream: S) -> Framed<S, LengthDelimitedCodec>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let codec = LengthDelimitedCodec::builder()
        .little_endian()
        .length_field_length(2)
        .max_frame_length(NOISE_MAX_MESSAGE_LEN)
        .new_codec();
    Framed::new(stream, codec)
}

fn build_prologue(protocol_version: u16, pattern: NoisePattern) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(NOISE_MAGIC.len() + 3);
    prologue.extend_from_slice(&NOISE_MAGIC);
    prologue.extend_from_slice(&protocol_version.to_le_bytes());
    prologue.push(pattern.to_wire());
    prologue
}

/// Пролог клиента: магия, версия, паттерн. Все три входят в prologue
/// хендшейка, поэтому правка любого байта на проводе разводит transcript'ы.
async fn write_client_prologue<S>(stream: &mut S, pattern: NoisePattern) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&NOISE_MAGIC)
        .await
        .context("failed to write noise magic")?;
    stream
        .write_all(&PROTO_VERSION.to_le_bytes())
        .await
        .context("failed to write protocol version")?;
    stream
        .write_all(&[pattern.to_wire()])
        .await
        .context("failed to write noise pattern")?;
    Ok(())
}

async fn read_handshake_message<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 2];
    stream
        .read_exact(&mut len_bytes)
        .await
        .context("failed to read noise message length")?;
    let len = u16::from_le_bytes(len_bytes) as usize;
    let mut message = vec![0u8; len];
    stream
        .read_exact(&mut message)
        .await
        .context("failed to read noise message body")?;
    Ok(message)
}

async fn write_handshake_message<S>(stream: &mut S, message: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(message.len()).context("noise message longer than 65535 bytes")?;
    stream
        .write_all(&len.to_le_bytes())
        .await
        .context("failed to write noise message length")?;
    stream
        .write_all(message)
        .await
        .context("failed to write noise message body")?;
    stream
        .flush()
        .await
        .context("failed to flush noise message")?;
    Ok(())
}

/// Сверить заявленный Ed25519 `user_id` с аутентифицированным статиком.
///
/// Именно здесь identity перестаёт быть заявкой: `remote_static` доказан
/// DH-операцией хендшейка, а конверсия Ed25519 → Montgomery детерминирована,
/// поэтому подставить чужой `user_id` можно только владея его секретом.
///
/// Делегированный вход меняет одно звено цепочки: статик сверяется с ключом
/// из сертификата, а связь сертификата с `user_id` доказывает подпись
/// аккаунта. Пути не комбинируются: если сертификат есть, он проверяется
/// целиком, и отката к прямой сверке при неудаче нет — иначе это был бы
/// оракул.
fn verify_client_identity(
    handshake: &HandshakeState,
    hello: ClientHello,
    protocol_version: u16,
    pattern: NoisePattern,
    now_secs: u64,
    device_cert_max_ttl_secs: u64,
) -> Result<NoiseSessionIdentity> {
    let remote_static = handshake
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("noise handshake produced no remote static key"))?;
    let remote_static = to_fixed_32(remote_static, "remote static key")?;

    let (scope, cert_not_after) = match &hello.device_cert {
        None => {
            let verifying = VerifyingKey::from_bytes(&hello.identity_key)
                .context("client identity key is not a valid ed25519 public key")?;
            let derived = verifying.to_montgomery().to_bytes();
            if derived != remote_static {
                bail!("client identity key does not match the authenticated noise static key");
            }
            (SessionScope::FULL, None)
        }
        Some(cert) => {
            let verified = device_cert::verify(
                &hello.identity_key,
                hello.device_id,
                cert,
                now_secs,
                device_cert_max_ttl_secs,
            )?;
            if verified.transport_key != remote_static {
                bail!("device certificate does not match the authenticated noise static key");
            }
            (verified.scope, Some(verified.not_after))
        }
    };

    Ok(NoiseSessionIdentity {
        user_id: hello.identity_key,
        device_id: hello.device_id,
        protocol_version,
        pattern,
        scope,
        cert_not_after,
    })
}

/// Разобранный payload хендшейка с identity клиента (msg1 в IK, msg3 в XX).
/// Публичен ради фаззера: это второй (после сборки кадров) самописный разбор
/// недоверенных байт в транспорте.
#[derive(Clone, Debug)]
pub struct ClientHello {
    pub identity_key: [u8; 32],
    pub device_id: Option<DeviceId>,
    /// Сертификат устройства как приехал: длины полей и подпись проверяет
    /// `device_cert::verify`, а не разбор.
    pub device_cert: Option<crate::wire::DeviceCertificate>,
}

fn encode_client_hello(
    identity_key: &[u8; 32],
    device_id: Option<DeviceId>,
    device_cert: Option<crate::wire::DeviceCertificate>,
) -> Result<Vec<u8>> {
    Ok(NoiseClientHello {
        identity_key: identity_key.to_vec(),
        device_id: crate::net::framing::encode_device_id(device_id),
        device_cert,
    }
    .encode_to_vec())
}

pub fn decode_client_hello(bytes: &[u8]) -> Result<ClientHello> {
    let hello = NoiseClientHello::decode(bytes).context("failed to decode noise client hello")?;
    let identity_key = to_fixed_32(&hello.identity_key, "client identity key")?;
    let device_id = crate::net::framing::decode_device_id(hello.device_id)?;
    Ok(ClientHello {
        identity_key,
        device_id,
        device_cert: hello.device_cert,
    })
}

fn parse_hex_secret(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).context("expected 64 hex characters")?;
    to_fixed_32(&bytes, "node static key")
}

fn to_fixed_32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        bail!("{what} must contain 32 bytes (got {})", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// 32 байта из системного CSPRNG под Ed25519 seed.
fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("failed to read random bytes for the node key")?;
    Ok(seed)
}

fn node_key_path(storage_path: &str) -> PathBuf {
    Path::new(storage_path).join(NODE_KEY_FILE)
}

/// Ключ, доступный не только владельцу, — это утечка identity ноды: кто
/// его прочитал, тот может выдавать себя за неё. Не падаем (нода в
/// контейнере может лежать на томе с чужой umask), но говорим громко.
#[cfg(unix)]
fn warn_on_loose_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        observability::observe_node_key_permissions(false);
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:o}"),
            "node static key is readable beyond its owner; fix with chmod 600"
        );
    } else {
        observability::observe_node_key_permissions(true);
    }
}

#[cfg(not(unix))]
fn warn_on_loose_permissions(_path: &Path) {}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const TEST_FRAME_MAX: usize = 8 * 1024 * 1024;

    fn client_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node() -> NodeIdentity {
        NodeIdentity::from_seed([7u8; 32], NodeKeySource::Configured)
    }

    fn test_policy() -> HandshakePolicy {
        HandshakePolicy {
            timeout: TEST_TIMEOUT,
            max_frame_len: TEST_FRAME_MAX,
            allow_tofu: true,
            device_cert_max_ttl_secs: 30 * 24 * 3600,
        }
    }

    /// Инвариант, на котором держится вся схема identity: X25519-статик,
    /// выведенный клиентом из секрета Ed25519, совпадает с конверсией его
    /// публичного Ed25519 — иначе нода не смогла бы сверить `user_id`.
    #[test]
    fn ed25519_and_x25519_derivations_agree() {
        for seed in [1u8, 42, 200] {
            let signing = client_key(seed);
            let from_secret =
                curve25519_dalek::MontgomeryPoint::mul_base_clamped(signing.to_scalar_bytes())
                    .to_bytes();
            let from_public = signing.verifying_key().to_montgomery().to_bytes();
            assert_eq!(from_secret, from_public);
        }
    }

    /// Первый контакт: клиент не знает ключа ноды, узнаёт его в ходе
    /// хендшейка и получает рабочую сессию.
    #[tokio::test]
    async fn tofu_handshake_learns_the_node_key() {
        let node = node();
        let expected = node.public();
        let client = client_key(31);

        let (server_stream, client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        let (_conn, learned) = NoiseFramed::connect_unpinned(
            client_stream,
            &client,
            Some(4),
            TEST_TIMEOUT,
            TEST_FRAME_MAX,
            |_key| true,
        )
        .await
        .unwrap();

        let (_server_conn, identity) = server.await.unwrap().unwrap();
        assert_eq!(learned, expected, "клиент обязан узнать статик ноды");
        assert_eq!(identity.user_id, client.verifying_key().to_bytes());
        assert_eq!(identity.device_id, Some(4));
        assert_eq!(identity.pattern, NoisePattern::Xx);
    }

    /// Отказ доверять ключу происходит до того, как клиент раскрыл свою
    /// identity: в XX статик клиента едет третьим сообщением, поэтому
    /// сторона, которой не доверяют, не узнаёт, кто с ней говорил.
    #[tokio::test]
    async fn tofu_rejection_leaves_the_client_anonymous() {
        let node = node();
        let client = client_key(32);

        let (server_stream, client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        let err = NoiseFramed::connect_unpinned(
            client_stream,
            &client,
            None,
            TEST_TIMEOUT,
            TEST_FRAME_MAX,
            |_key| false,
        )
        .await
        .map(|_| ())
        .unwrap_err()
        .to_string();
        assert!(err.contains("was not accepted"), "unexpected error: {err}");

        // Нода не дождалась msg3 и осталась без identity клиента.
        let server_result = server.await.unwrap();
        assert!(
            server_result.map(|_| ()).is_err(),
            "нода не должна получить сессию, если клиент отказался доверять её ключу"
        );
    }

    /// Нода, которой TOFU выключен, не отвечает на XX вовсе — остаются
    /// только клиенты с пином.
    #[tokio::test]
    async fn tofu_is_refused_when_disabled() {
        let node = node();
        let client = client_key(33);

        let (server_stream, client_stream) = loopback().await;
        let server = tokio::spawn(async move {
            NoiseFramed::accept(
                server_stream,
                &node,
                HandshakePolicy {
                    allow_tofu: false,
                    device_cert_max_ttl_secs: 30 * 24 * 3600,
                    ..test_policy()
                },
            )
            .await
        });

        let _ = NoiseFramed::connect_unpinned(
            client_stream,
            &client,
            None,
            Duration::from_millis(200),
            TEST_FRAME_MAX,
            |_key| true,
        )
        .await;

        let err = server.await.unwrap().map(|_| ()).unwrap_err().to_string();
        assert!(
            err.contains("tofu handshake is disabled"),
            "unexpected error: {err}"
        );
    }

    /// Паттерн входит в prologue, поэтому подмена байта на проводе не
    /// переключает клиента с пином на TOFU-путь: transcript'ы расходятся, и
    /// хендшейк не сходится. Без этой привязки MITM выбирал бы за клиента
    /// режим, в котором принимается чужой ключ.
    #[tokio::test]
    async fn pattern_downgrade_breaks_the_handshake() {
        let node = node();
        let node_public = node.public();
        let client = client_key(34);

        let (server_stream, mut client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        // На проводе — XX (его и увидит нода), а клиент играет IK: ровно то,
        // что делает MITM, правя байт паттерна на лету.
        client_stream.write_all(&NOISE_MAGIC).await.unwrap();
        client_stream
            .write_all(&PROTO_VERSION.to_le_bytes())
            .await
            .unwrap();
        client_stream
            .write_all(&[NoisePattern::Xx.to_wire()])
            .await
            .unwrap();

        let mut handshake = Builder::new(NOISE_PARAMS_IK.parse().unwrap())
            .prologue(&build_prologue(PROTO_VERSION, NoisePattern::Ik))
            .unwrap()
            .local_private_key(&client.to_scalar_bytes())
            .unwrap()
            .remote_public_key(&node_public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let hello = encode_client_hello(&client.verifying_key().to_bytes(), None, None).unwrap();
        let mut message = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = handshake.write_message(&hello, &mut message).unwrap();
        write_handshake_message(&mut client_stream, &message[..len])
            .await
            .unwrap();

        let result = server.await.unwrap();
        assert!(
            result.map(|_| ()).is_err(),
            "подмена паттерна обязана ломать хендшейк"
        );
    }

    /// Отпечаток — это сам ключ, а не его хеш: сравнение начала строки
    /// ничего не доказывает, поэтому в нём обязаны быть все байты.
    #[test]
    fn fingerprint_carries_the_whole_key() {
        let key = [0xABu8; 32];
        let printed = fingerprint(&key);

        assert_eq!(printed.replace('-', "").len(), 64);
        assert_eq!(printed.replace('-', ""), hex::encode_upper(key));
        assert_ne!(printed, fingerprint(&[0xACu8; 32]));

        // Группировка существует ради глаз и не должна ломать сравнение
        // без разделителей.
        assert!(printed.starts_with("ABAB-"));
    }

    /// Магия не должна читаться как правдоподобный length-prefix, иначе
    /// length-prefixed кадр можно было бы спутать с началом
    /// Noise-соединения.
    #[test]
    fn magic_is_not_a_plausible_length_prefix() {
        let as_length = u32::from_le_bytes(NOISE_MAGIC) as usize;
        assert!(as_length > 64 * 1024 * 1024);
    }

    async fn loopback() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (server, connect.await.unwrap())
    }

    #[tokio::test]
    async fn handshake_establishes_identity_and_moves_frames() {
        let node = node();
        let client = client_key(3);
        let expected_user = client.verifying_key().to_bytes();
        let node_public = node.public();

        let (server_stream, client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        let mut client_conn = NoiseFramed::connect(
            client_stream,
            &node_public,
            &client,
            Some(9),
            TEST_TIMEOUT,
            TEST_FRAME_MAX,
        )
        .await
        .unwrap();

        let (mut server_conn, identity) = server.await.unwrap().unwrap();
        assert_eq!(identity.user_id, expected_user);
        assert_eq!(identity.device_id, Some(9));
        assert_eq!(identity.protocol_version, PROTO_VERSION);

        client_conn.send_frame(b"hello node").await.unwrap();
        let received = server_conn.next_frame().await.unwrap().unwrap();
        assert_eq!(received.as_ref(), b"hello node");

        server_conn.send_frame(b"hello client").await.unwrap();
        let echoed = client_conn.next_frame().await.unwrap().unwrap();
        assert_eq!(echoed.as_ref(), b"hello client");
    }

    /// Кадр крупнее одного Noise-сообщения обязан пережить нарезку и
    /// сборку: логическое кадрирование живёт поверх 64 KiB-чанков.
    #[tokio::test]
    async fn frames_larger_than_one_noise_message_roundtrip() {
        let node = node();
        let client = client_key(4);
        let node_public = node.public();

        let (server_stream, client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );
        let mut client_conn = NoiseFramed::connect(
            client_stream,
            &node_public,
            &client,
            None,
            TEST_TIMEOUT,
            TEST_FRAME_MAX,
        )
        .await
        .unwrap();
        let (mut server_conn, _) = server.await.unwrap().unwrap();

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        client_conn.send_frame(&payload).await.unwrap();
        let received = server_conn.next_frame().await.unwrap().unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received.as_ref(), payload.as_slice());
    }

    /// IK с неверным статиком ноды не сходится: сессию не получает ни нода,
    /// ни клиент.
    #[tokio::test]
    async fn handshake_fails_for_wrong_node_key() {
        let node = node();
        let client = client_key(5);
        let wrong_public = NodeIdentity::from_seed([9u8; 32], NodeKeySource::Configured).public();

        let (server_stream, client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        let client_result = NoiseFramed::connect(
            client_stream,
            &wrong_public,
            &client,
            None,
            TEST_TIMEOUT,
            TEST_FRAME_MAX,
        )
        .await;

        assert!(
            server.await.unwrap().is_err(),
            "node must reject the handshake"
        );
        assert!(
            client_result.is_err(),
            "client must not reach transport mode"
        );
    }

    /// Соединение, начатое не с магии (например, plaintext-клиент с
    /// length-prefix кадрированием), отвергается сразу, без эвристик.
    #[tokio::test]
    async fn non_noise_prologue_is_rejected() {
        let node = node();
        let (server_stream, mut client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        // Первые байты length-prefixed кадрирования — little-endian длина кадра.
        client_stream.write_all(&64u32.to_le_bytes()).await.unwrap();
        client_stream.write_all(&[0u8; 64]).await.unwrap();

        let err = server.await.unwrap().map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("magic"), "unexpected error: {err}");
    }

    /// Хендшейк не должен держать слот бесконечно: клиент, открывший TCP и
    /// замолчавший, отваливается по таймауту.
    #[tokio::test]
    async fn handshake_times_out_on_silent_client() {
        let node = node();
        let (server_stream, _client_stream) = loopback().await;

        let result = NoiseFramed::accept(
            server_stream,
            &node,
            HandshakePolicy {
                timeout: Duration::from_millis(50),
                ..test_policy()
            },
        )
        .await;

        let err = result.map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("timed out"), "unexpected error: {err}");
    }

    /// Версия определяет кодек кадров, поэтому неподдерживаемая отвергается
    /// до крипты: успешный хендшейк с чужой версией дал бы установленную
    /// сессию, в которой ни одна сторона не понимает кадры другой.
    #[tokio::test]
    async fn unsupported_proto_version_is_rejected_before_crypto() {
        let node = node();
        let (server_stream, mut client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        client_stream.write_all(&NOISE_MAGIC).await.unwrap();
        // Версия, которую нода не поддерживает.
        client_stream.write_all(&2u16.to_le_bytes()).await.unwrap();

        let err = server.await.unwrap().map(|_| ()).unwrap_err().to_string();
        assert!(
            err.contains("unsupported protocol version 2"),
            "unexpected error: {err}"
        );
    }

    /// Anti-downgrade: `protoVersion` едет открытым текстом, но входит в
    /// prologue. Сторона, у которой в prologue не то, что она написала на
    /// провод, — это и есть MITM, правящий байты версии на лету: transcript'ы
    /// расходятся, и хендшейк не сходится.
    #[tokio::test]
    async fn tampered_proto_version_breaks_the_handshake() {
        let node = node();
        let client = client_key(6);
        let node_public = node.public();

        let (server_stream, mut client_stream) = loopback().await;
        let server =
            tokio::spawn(
                async move { NoiseFramed::accept(server_stream, &node, test_policy()).await },
            );

        // На проводе — версия, которую нода поддерживает (её она и
        // прочитает), а в собственный prologue инициатор кладёт другую:
        // ровно то, что видит нода, когда версию правят на лету.
        client_stream.write_all(&NOISE_MAGIC).await.unwrap();
        client_stream
            .write_all(&PROTO_VERSION.to_le_bytes())
            .await
            .unwrap();
        client_stream
            .write_all(&[NoisePattern::Ik.to_wire()])
            .await
            .unwrap();

        let mut handshake = Builder::new(NOISE_PARAMS_IK.parse().unwrap())
            .prologue(&build_prologue(PROTO_VERSION + 1, NoisePattern::Ik))
            .unwrap()
            .local_private_key(&client.to_scalar_bytes())
            .unwrap()
            .remote_public_key(&node_public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let hello = encode_client_hello(&client.verifying_key().to_bytes(), None, None).unwrap();
        let mut message = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = handshake.write_message(&hello, &mut message).unwrap();
        write_handshake_message(&mut client_stream, &message[..len])
            .await
            .unwrap();

        let err = server.await.unwrap().map(|_| ()).unwrap_err().to_string();
        assert!(
            err.contains("message 1 rejected"),
            "downgrade must break the handshake, got: {err}"
        );
    }

    /// Replay: подслушанный трафик не воспроизводится. Нода отвечает на
    /// переигранный msg1 (в IK responder не может отличить его в одиночку),
    /// но её эфемерал каждый раз новый, поэтому транспортные ключи той
    /// сессии не совпадают с записанными — первый же переигранный кадр
    /// данных отвергается.
    ///
    /// Ресурсная сторона реплея (бесполезная сессия занимает слот)
    /// ограничена лимитом одновременных сессий на пользователя.
    #[tokio::test]
    async fn replayed_handshake_cannot_replay_data() {
        let node = node();
        let client = client_key(7);
        let node_public = node.public();

        // 1. Честная сессия: записываем и msg1, и кадр данных.
        let (server_stream, mut client_stream) = loopback().await;
        let honest_node = node.clone();
        let server = tokio::spawn(async move {
            NoiseFramed::accept(server_stream, &honest_node, test_policy()).await
        });

        client_stream.write_all(&NOISE_MAGIC).await.unwrap();
        client_stream
            .write_all(&PROTO_VERSION.to_le_bytes())
            .await
            .unwrap();
        client_stream
            .write_all(&[NoisePattern::Ik.to_wire()])
            .await
            .unwrap();
        let mut handshake = Builder::new(NOISE_PARAMS_IK.parse().unwrap())
            .prologue(&build_prologue(PROTO_VERSION, NoisePattern::Ik))
            .unwrap()
            .local_private_key(&client.to_scalar_bytes())
            .unwrap()
            .remote_public_key(&node_public)
            .unwrap()
            .build_initiator()
            .unwrap();
        let hello = encode_client_hello(&client.verifying_key().to_bytes(), None, None).unwrap();
        let mut buffer = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        let len = handshake.write_message(&hello, &mut buffer).unwrap();
        let recorded_msg1 = buffer[..len].to_vec();
        write_handshake_message(&mut client_stream, &recorded_msg1)
            .await
            .unwrap();

        let response = read_handshake_message(&mut client_stream).await.unwrap();
        let mut scratch = vec![0u8; NOISE_MAX_MESSAGE_LEN];
        handshake.read_message(&response, &mut scratch).unwrap();
        let mut client_transport = handshake.into_transport_mode().unwrap();
        let (_server_conn, _identity) = server.await.unwrap().unwrap();

        // Кадр данных честной сессии, как его увидел бы наблюдатель.
        let mut payload = Vec::new();
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(b"ping");
        let len = client_transport
            .write_message(&payload, &mut scratch)
            .unwrap();
        let recorded_data = scratch[..len].to_vec();

        // 2. Реплей на свежее соединение: те же байты хендшейка и данных.
        let (replay_server_stream, mut attacker_stream) = loopback().await;
        let replay_node = node.clone();
        let replay_server = tokio::spawn(async move {
            let (mut conn, _) =
                NoiseFramed::accept(replay_server_stream, &replay_node, test_policy()).await?;
            // Единственный интересный вопрос: примет ли нода переигранные
            // данные.
            conn.next_frame().await.map_err(anyhow::Error::from)
        });

        attacker_stream.write_all(&NOISE_MAGIC).await.unwrap();
        attacker_stream
            .write_all(&PROTO_VERSION.to_le_bytes())
            .await
            .unwrap();
        attacker_stream
            .write_all(&[NoisePattern::Ik.to_wire()])
            .await
            .unwrap();
        write_handshake_message(&mut attacker_stream, &recorded_msg1)
            .await
            .unwrap();
        let _replayed_response = read_handshake_message(&mut attacker_stream).await.unwrap();
        write_handshake_message(&mut attacker_stream, &recorded_data)
            .await
            .unwrap();

        let err = replay_server
            .await
            .unwrap()
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("decrypt"),
            "replayed data must not decrypt, got: {err}"
        );
    }

    /// Источник ключа — наблюдаемая величина: пин, файл и «сгенерирован»
    /// должны различаться, потому что третий случай на живой ноде авария.
    #[test]
    fn node_key_source_is_reported() {
        let dir = std::env::temp_dir().join(format!(
            "trust_message_tcp_nodekey_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.to_string_lossy().into_owned();

        // Файла нет — ключ рождается здесь.
        let generated = NodeIdentity::load_or_generate(&path, None).unwrap();
        assert_eq!(generated.source(), NodeKeySource::Generated);

        // Второй старт на том же томе обязан взять тот же ключ: иначе
        // рестарт отрезал бы всех клиентов.
        let reloaded = NodeIdentity::load_or_generate(&path, None).unwrap();
        assert_eq!(reloaded.source(), NodeKeySource::File);
        assert_eq!(reloaded.public(), generated.public());

        // Пин перекрывает файл.
        let pinned = NodeIdentity::load_or_generate(&path, Some(&hex::encode([3u8; 32]))).unwrap();
        assert_eq!(pinned.source(), NodeKeySource::Configured);
        assert_ne!(pinned.public(), generated.public());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Сгенерированный ключ ложится на диск с правами 0600: файл, который
    /// может прочитать кто-то ещё, позволяет выдавать себя за ноду.
    #[cfg(unix)]
    #[test]
    fn generated_node_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "trust_message_tcp_nodekey_perm_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.to_string_lossy().into_owned();
        let _identity = NodeIdentity::load_or_generate(&path, None).unwrap();

        let mode = std::fs::metadata(dir.join("node_identity_key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "node key must not be readable by others");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Битый файл — это отказ старта, а не тихая генерация нового ключа:
    /// молчаливая подмена отрезала бы всех клиентов без единого сигнала.
    #[test]
    fn malformed_node_key_file_fails_startup() {
        let dir = std::env::temp_dir().join(format!(
            "trust_message_tcp_nodekey_bad_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("node_identity_key"), "not-a-key").unwrap();

        let result = NodeIdentity::load_or_generate(&dir.to_string_lossy(), None);
        assert!(
            result.map(|_| ()).is_err(),
            "malformed key must not be ignored"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Подпись снапшота проверяется тем же ключом, что виден клиенту, и
    /// домен подписи прибит к содержимому: та же строка без домена не
    /// проверяется.
    #[test]
    fn server_config_signature_is_domain_separated() {
        use ed25519_dalek::{Signature, Verifier};

        let node = NodeIdentity::from_seed([21u8; 32], NodeKeySource::Configured);
        let payload = b"snapshot-bytes";
        let signature = Signature::from_bytes(&node.sign_server_config(payload));
        let verifying = VerifyingKey::from_bytes(&node.identity_public()).unwrap();

        let mut domained = SERVER_CONFIG_SIGNING_DOMAIN.to_vec();
        domained.extend_from_slice(payload);
        assert!(verifying.verify(&domained, &signature).is_ok());
        assert!(
            verifying.verify(payload, &signature).is_err(),
            "подпись без домена не должна проверяться — иначе её можно предъявить в другом контексте"
        );
    }
}
