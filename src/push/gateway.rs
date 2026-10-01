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
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use prost::Message as _;
use tonic::transport::{Channel, Endpoint};
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

        let endpoint = Endpoint::from_shared(url.to_owned())
            .with_context(|| format!("invalid push gateway url: {url}"))?
            .timeout(request_timeout)
            .connect_timeout(request_timeout);

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
        pb::DeliveryStatus::Quota => SendOutcome::Backoff(BackoffReason::Quota),
        pb::DeliveryStatus::ProviderError => SendOutcome::Backoff(BackoffReason::ServerError),
        pb::DeliveryStatus::Unavailable => SendOutcome::Backoff(BackoffReason::Unavailable),
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
            SendOutcome::Backoff(BackoffReason::Quota)
        );
        assert_eq!(
            outcome_of(pb::DeliveryStatus::ProviderError),
            SendOutcome::Backoff(BackoffReason::ServerError)
        );
        assert_eq!(
            outcome_of(pb::DeliveryStatus::Unavailable),
            SendOutcome::Backoff(BackoffReason::Unavailable)
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

    #[tokio::test]
    async fn a_dead_gateway_is_transient_and_never_evicts() {
        // Порт 1 закрыт: connect_lazy откладывает соединение, поэтому
        // конструктор проходит, а провал случается на запросе.
        let client = client();
        let outcome = client
            .send(PushPayload {
                user_id: [1u8; 32],
                device_id: 3,
                token: "t".into(),
                pending: 2,
                max_priority: Some(MessagePriority::High),
                server_ts_secs: 100,
                kind: PushKind::Wake,
                wake_hint: None,
            })
            .await;
        assert_eq!(outcome, SendOutcome::TransientError);
    }
}
