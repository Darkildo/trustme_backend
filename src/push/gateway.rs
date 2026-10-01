//! Клиент внешнего push-шлюза (gRPC).
//!
//! Альтернатива локальным кредам: вместо service-account FCM и .p8-ключа
//! APNs на диске ноды в конфиге указывается адрес шлюза, а креды остаются у
//! владельца приложения. Это единственный способ дать пуши сторонней ноде —
//! вендорские ключи ей выдать нельзя, а без них её резиденты перестают
//! просыпаться.
//!
//! Схема и модель доверия — `schemas/trustmessage/push/v1/push.proto`.
//! Коротко: подпись node-ключом не является capability на пробуждение
//! (реестра нод у шлюза нет), она даёт лишь самосогласованность запроса и
//! стабильный ключ для rate-limit'а. Реальная capability — знание
//! push-токена.
//!
//! Ответы шлюза маппятся в тот же `SendOutcome`, что и у прямых
//! транспортов: иначе в режиме шлюза мёртвые токены не вычищались бы, а
//! перегрузка провайдера не замедляла бы ретраи.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use prost::Message as _;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tracing::{debug, warn};

use crate::domain::priority::MessagePriority;
use crate::net::noise::NodeIdentity;
use crate::proto::trustmessage::push::v1 as pb;
use crate::proto::trustmessage::push::v1::push_gateway_service_client::PushGatewayServiceClient;
use crate::push::transport::{
    BackoffReason, PushKind, PushPayload, PushTransport, RingPayload, SendOutcome,
    VoipRingTransport,
};

/// Ring протухает быстро — то же окно, что и у прямого APNs-транспорта.
/// Держать дольше вредно: phantom-ring на давно отменённый звонок.
const RING_EXPIRATION_SECS: u32 = 30;

/// Nonce для окна анти-реплея на шлюзе. 16 байт: коллизия в пределах
/// короткого окна невозможна практически, а длиннее незачем.
const NONCE_LEN: usize = 16;

/// gRPC-клиент push-шлюза. Реализует оба транспорта — и обычное
/// пробуждение, и voip-ring, — потому что шлюз владеет и FCM-, и
/// APNs-кредами: разделять их между нодой и шлюзом означало бы держать
/// половину секретов на ноде, то есть не решить исходную задачу.
#[derive(Clone)]
pub struct PushGatewayClient {
    client: PushGatewayServiceClient<Channel>,
    /// Ключ ноды целиком, а не `SigningKey`: домен подписи прибит внутри
    /// `NodeIdentity`, и вынести секрет наружу означало бы дать этому модулю
    /// возможность подписать им что угодно.
    node: Arc<NodeIdentity>,
    node_key: Vec<u8>,
}

impl PushGatewayClient {
    /// Собирает клиента. Соединение здесь не устанавливается: `connect_lazy`
    /// откладывает его до первого запроса. Вызывать всё же нужно внутри
    /// tokio-рантайма — hyper регистрирует таймеры сразу.
    ///
    /// Пуши — best-effort, а недоступный на момент старта шлюз не повод не
    /// поднимать ноду: доставка сообщений от него не зависит. Eager-connect
    /// превратил бы чужую аварию в отказ собственного сервиса.
    pub fn new(url: &str, request_timeout: Duration, node: Arc<NodeIdentity>) -> Result<Self> {
        let node_key = node.identity_public().to_vec();
        let endpoint = gateway_endpoint(parse_gateway_url(url)?, request_timeout)?;

        Ok(Self {
            client: PushGatewayServiceClient::new(endpoint.connect_lazy()),
            node,
            node_key,
        })
    }

    /// Подписывает сериализованный конверт. Подписываются именно те байты,
    /// что уедут на провод: повторная сериализация могла бы дать другие
    /// байты при том же смысле — порядок полей в protobuf не канонизирован.
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.node.sign_push_gateway(payload).to_vec()
    }
}

/// Разбирает адрес шлюза (`PUSH_GATEWAY_URL`) и проверяет схему.
///
/// `https` — всегда. `http` — только для loopback (127.0.0.0/8, `::1`,
/// `localhost`): открытым текстом по сети уезжали бы push-токены устройств,
/// то есть capability на их пробуждение, а подменённый ответ
/// `INVALID_TOKEN` заставлял бы ноду стирать токены своих резидентов.
/// Loopback оставлен для шлюза-соседа на той же машине и для тестов.
pub fn parse_gateway_url(url: &str) -> Result<Uri> {
    let uri: Uri = url
        .parse()
        .with_context(|| format!("PUSH_GATEWAY_URL is not a valid url: {url}"))?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("PUSH_GATEWAY_URL has no host: {url}"))?;

    match uri.scheme_str() {
        Some("https") => Ok(uri),
        Some("http") if is_loopback_host(host) => Ok(uri),
        Some("http") => bail!(
            "PUSH_GATEWAY_URL must use https: plaintext http is allowed only for a loopback \
             gateway (127.0.0.0/8, ::1, localhost), got {url}"
        ),
        _ => bail!("PUSH_GATEWAY_URL must be an https:// url, got {url}"),
    }
}

/// `localhost` или loopback-адрес. Имена вроде `*.localhost` не
/// принимаются: куда они резолвятся, решает чужой резолвер.
fn is_loopback_host(host: &str) -> bool {
    // `Uri::host` отдаёт IPv6 в квадратных скобках.
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Endpoint шлюза с TLS для `https`.
///
/// TLS включается явно: `Endpoint::from`/`from_shared` сами его не
/// включают даже для `https` (это делает только скрытый `Endpoint::new`),
/// и без этого клиент говорил бы с `:443` открытым h2c — то есть не
/// работал бы вовсе.
fn gateway_endpoint(uri: Uri, request_timeout: Duration) -> Result<Endpoint> {
    let tls = uri.scheme_str() == Some("https");
    let endpoint = Endpoint::from(uri)
        .timeout(request_timeout)
        .connect_timeout(request_timeout);
    if !tls {
        return Ok(endpoint);
    }
    endpoint
        .tls_config(ClientTlsConfig::new().with_enabled_roots())
        .context(
            "failed to configure TLS for the push gateway (are system CA certificates installed?)",
        )
}

/// Маппинг статуса шлюза в решение планировщика.
///
/// `Unspecified` — родовой отказ, и он обязан быть безопасным: сюда же
/// попадает незнакомое значение от более свежего шлюза. Трактуется как
/// транзиентная ошибка (повторить, токен не трогать), потому что цена
/// ошибки несимметрична: лишний ретрай стоит одного запроса, а ошибочная
/// эвикция токена — молчания устройства до следующей регистрации.
fn outcome_of(status: pb::DeliveryStatus) -> SendOutcome {
    match status {
        pb::DeliveryStatus::Ok => SendOutcome::Ok,
        pb::DeliveryStatus::InvalidToken => SendOutcome::InvalidToken,
        pb::DeliveryStatus::Quota => SendOutcome::backoff(BackoffReason::Quota),
        pb::DeliveryStatus::ProviderError => SendOutcome::backoff(BackoffReason::ServerError),
        pb::DeliveryStatus::Unavailable => SendOutcome::backoff(BackoffReason::Unavailable),
        pb::DeliveryStatus::Unspecified => SendOutcome::TransientError,
    }
}

fn priority_of(p: Option<MessagePriority>) -> pb::MessagePriority {
    match p {
        Some(MessagePriority::High) => pb::MessagePriority::High,
        Some(MessagePriority::Medium) => pb::MessagePriority::Medium,
        Some(MessagePriority::Low) => pb::MessagePriority::Low,
        None => pb::MessagePriority::Unspecified,
    }
}

fn kind_of(kind: PushKind) -> pb::WakeKind {
    match kind {
        PushKind::Wake => pb::WakeKind::Wake,
        PushKind::Welcome => pb::WakeKind::Welcome,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn nonce() -> Vec<u8> {
    let mut buf = vec![0u8; NONCE_LEN];
    // Провал RNG здесь не повод ронять пуш: шлюз отвергнет повтор по
    // нулевому nonce, и это худший случай — не отправленный пуш, а не
    // подделанный.
    if getrandom::fill(&mut buf).is_err() {
        warn!("failed to read random bytes for the push gateway nonce");
    }
    buf
}

impl PushTransport for PushGatewayClient {
    async fn send(&self, payload: PushPayload) -> SendOutcome {
        // `payload.wake_hint` тут теряется: в `push.proto` соответствующего
        // поля нет, а схема — контракт с внешним шлюзом и односторонне не
        // меняется. Следствие: нода за шлюзом будит Android под звонок
        // обычным wake'ом, и клиент покажет баннер вместо ринга. iOS с
        // voip-слотом не затронут — там звонок уходит методом `Ring`.
        let wake = pb::Wake {
            token: payload.token,
            kind: kind_of(payload.kind) as i32,
            pending: payload.pending,
            max_priority: priority_of(payload.max_priority) as i32,
            server_ts_secs: payload.server_ts_secs,
            recipient_user: payload.user_id.to_vec(),
            recipient_device: u32::from(payload.device_id),
            issued_at_secs: now_secs(),
            nonce: nonce(),
        };

        let body = wake.encode_to_vec();
        let request = pb::WakeRequest {
            signature: self.sign(&body),
            node_key: self.node_key.clone(),
            wake: body,
        };

        match self.client.clone().wake(request).await {
            Ok(response) => {
                let response = response.into_inner();
                let status = pb::DeliveryStatus::try_from(response.status)
                    .unwrap_or(pb::DeliveryStatus::Unspecified);
                if status != pb::DeliveryStatus::Ok {
                    debug!(?status, detail = %response.detail, "push gateway rejected wake");
                }
                outcome_of(status)
            }
            Err(status) => {
                // Транспортный сбой (шлюз лежит, таймаут, TLS). Токен ни при
                // чём — эвиктить его нельзя даже при `NOT_FOUND`: это ответ
                // про метод gRPC, а не про регистрацию устройства.
                warn!(code = ?status.code(), error = %status.message(), "push gateway wake failed");
                SendOutcome::TransientError
            }
        }
    }
}

impl VoipRingTransport for PushGatewayClient {
    fn send_ring(&self, payload: RingPayload) -> impl Future<Output = SendOutcome> + Send {
        let client = self.clone();
        async move {
            let ring = pb::Ring {
                token: payload.token,
                server_ts_secs: payload.server_ts_secs,
                expiration_secs: RING_EXPIRATION_SECS,
                issued_at_secs: now_secs(),
                nonce: nonce(),
            };

            let body = ring.encode_to_vec();
            let request = pb::RingRequest {
                signature: client.sign(&body),
                node_key: client.node_key.clone(),
                ring: body,
            };

            match client.client.clone().ring(request).await {
                Ok(response) => {
                    let response = response.into_inner();
                    let status = pb::DeliveryStatus::try_from(response.status)
                        .unwrap_or(pb::DeliveryStatus::Unspecified);
                    if status != pb::DeliveryStatus::Ok {
                        debug!(?status, detail = %response.detail, "push gateway rejected ring");
                    }
                    outcome_of(status)
                }
                Err(status) => {
                    warn!(code = ?status.code(), error = %status.message(), "push gateway ring failed");
                    SendOutcome::TransientError
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::noise::NodeKeySource;

    fn client() -> PushGatewayClient {
        PushGatewayClient::new(
            "http://127.0.0.1:1",
            Duration::from_secs(1),
            Arc::new(NodeIdentity::from_seed(
                [7u8; 32],
                NodeKeySource::Configured,
            )),
        )
        .expect("client")
    }

    #[test]
    fn every_gateway_status_maps_to_a_scheduler_decision() {
        assert_eq!(outcome_of(pb::DeliveryStatus::Ok), SendOutcome::Ok);
        assert_eq!(
            outcome_of(pb::DeliveryStatus::InvalidToken),
            SendOutcome::InvalidToken
        );
        assert_eq!(
            outcome_of(pb::DeliveryStatus::Quota),
            SendOutcome::backoff(BackoffReason::Quota)
        );
        assert_eq!(
            outcome_of(pb::DeliveryStatus::ProviderError),
            SendOutcome::backoff(BackoffReason::ServerError)
        );
        assert_eq!(
            outcome_of(pb::DeliveryStatus::Unavailable),
            SendOutcome::backoff(BackoffReason::Unavailable)
        );
    }

    #[test]
    fn unknown_status_never_evicts_a_token() {
        // Незнакомое значение от более свежего шлюза декодируется в
        // `Unspecified`. Оно обязано вести к повтору, а не к эвикции:
        // ошибочно снятый токен молчит до следующей регистрации клиента.
        let decoded = pb::DeliveryStatus::try_from(9999).unwrap_or(pb::DeliveryStatus::Unspecified);
        assert_eq!(decoded, pb::DeliveryStatus::Unspecified);
        assert_eq!(outcome_of(decoded), SendOutcome::TransientError);
    }

    // `connect_lazy` регистрирует таймеры hyper'а, поэтому конструктор
    // требует запущенного рантайма даже без единого запроса.
    #[tokio::test]
    async fn signature_covers_the_domain_and_the_exact_bytes() {
        use crate::net::noise::PUSH_GATEWAY_SIGNING_DOMAIN;
        use ed25519_dalek::{Verifier, VerifyingKey};

        let client = client();
        let body = b"payload bytes".to_vec();
        let signature = client.sign(&body);

        let mut expected = PUSH_GATEWAY_SIGNING_DOMAIN.to_vec();
        expected.extend_from_slice(&body);

        let key = VerifyingKey::from_bytes(&client.node_key.clone().try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        assert!(key.verify(&expected, &sig).is_ok());
        // Без домена та же подпись не проверяется — иначе подпись
        // push-запроса можно было бы предъявить как подпись чего-то ещё.
        assert!(key.verify(&body, &sig).is_err());
    }

    #[test]
    fn nonces_do_not_repeat() {
        assert_ne!(nonce(), nonce());
        assert_eq!(nonce().len(), NONCE_LEN);
    }

    fn wake_payload() -> PushPayload {
        PushPayload {
            user_id: [1u8; 32],
            device_id: 3,
            token: "t".into(),
            pending: 2,
            max_priority: Some(MessagePriority::High),
            server_ts_secs: 100,
            kind: PushKind::Wake,
            wake_hint: None,
        }
    }

    #[tokio::test]
    async fn a_dead_gateway_is_transient_and_never_evicts() {
        // Порт 1 закрыт: connect_lazy откладывает соединение, поэтому
        // конструктор проходит, а провал случается на запросе.
        let client = client();
        let outcome = client.send(wake_payload()).await;
        assert_eq!(outcome, SendOutcome::TransientError);
    }

    #[test]
    fn https_gateway_url_is_accepted_anywhere() {
        for url in [
            "https://push.example.org",
            "https://push.example.org:8443/",
            "https://203.0.113.7:443",
        ] {
            assert!(parse_gateway_url(url).is_ok(), "{url}");
        }
    }

    /// Открытый текст допустим только до соседнего процесса на той же
    /// машине: по сети он отдал бы push-токены, то есть capability на
    /// пробуждение устройств, любому на пути.
    #[test]
    fn plaintext_gateway_url_is_accepted_only_for_loopback() {
        for url in [
            "http://127.0.0.1:50051",
            "http://127.10.20.30:50051",
            "http://[::1]:50051",
            "http://localhost:50051",
            "http://LOCALHOST",
        ] {
            assert!(parse_gateway_url(url).is_ok(), "{url}");
        }

        for url in [
            "http://push.example.org",
            "http://10.0.0.5:50051",
            "http://[::ffff:127.0.0.1]:50051",
            "http://push.localhost",
        ] {
            let err = parse_gateway_url(url).unwrap_err().to_string();
            assert!(err.contains("must use https"), "{url}: {err}");
            assert!(err.contains("loopback"), "{url}: {err}");
        }
    }

    #[test]
    fn gateway_url_without_a_usable_scheme_is_rejected() {
        for url in [
            "push.example.org:443",
            "ftp://push.example.org",
            "unix:///run/push.sock",
            "not a url",
        ] {
            assert!(parse_gateway_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn constructor_refuses_a_plaintext_remote_gateway() {
        // Без рантайма: проверка схемы срабатывает раньше `connect_lazy`.
        let err = PushGatewayClient::new(
            "http://push.example.org",
            Duration::from_secs(1),
            Arc::new(NodeIdentity::from_seed(
                [7u8; 32],
                NodeKeySource::Configured,
            )),
        )
        .err()
        .expect("plaintext remote gateway must be refused");
        assert!(err.to_string().contains("must use https"), "{err}");
    }

    /// Первые байты, которые клиент шлёт шлюзу по указанной схеме.
    async fn first_bytes_on_the_wire(scheme: &str) -> [u8; 3] {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = PushGatewayClient::new(
            &format!("{scheme}://127.0.0.1:{port}"),
            Duration::from_secs(2),
            Arc::new(NodeIdentity::from_seed(
                [7u8; 32],
                NodeKeySource::Configured,
            )),
        )
        .expect("client");
        let request = tokio::spawn(async move { client.send(wake_payload()).await });

        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("client must connect")
            .unwrap();
        let mut head = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut head))
            .await
            .expect("client must speak first")
            .unwrap();
        drop(socket);

        assert_eq!(request.await.unwrap(), SendOutcome::TransientError);
        head
    }

    /// `https` обязан означать TLS. `Endpoint::from_shared` сам его не
    /// включает, и клиент слал `:443` открытый h2c — шлюз по https не
    /// работал вовсе.
    #[tokio::test]
    async fn https_gateway_speaks_tls() {
        let head = first_bytes_on_the_wire("https").await;
        // TLS record: handshake (0x16), версия 3.x.
        assert_eq!(head[0], 0x16, "expected a TLS ClientHello, got {head:?}");
        assert_eq!(head[1], 0x03);
    }

    #[tokio::test]
    async fn loopback_http_gateway_speaks_plaintext_h2() {
        let head = first_bytes_on_the_wire("http").await;
        // Префейс HTTP/2: `PRI * HTTP/2.0`.
        assert_eq!(&head, b"PRI");
    }
}
