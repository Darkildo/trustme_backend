//! Временные учётки ICE-серверов для звонков (server-contract.md §6.12).
//!
//! TURN-учётка — по схеме coturn REST (`use-auth-secret`):
//! `username = <expires_at>:<псевдоним>`,
//! `credential = base64(HMAC-SHA1(secret, username))`. Нода и coturn
//! делят только общий секрет, а не список пользователей: coturn сам
//! проверяет подпись и срок в имени.
//!
//! Псевдоним — первые 8 байт SHA-256 от `user_id` с доменом: постоянен для
//! пользователя (оператор TURN видит, что сессии одного человека), но не
//! раскрывает его ключ и не сопоставляется с другими нодами.

use std::sync::{Arc, RwLock};

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::config::IceConfig;
use crate::wire::{self, IceRejectReason};

const PSEUDONYM_DOMAIN: &[u8] = b"trustmessage/ice-user/v1\0";

/// Текущий список ICE-серверов, заменяемый на лету (`runtime.toml`).
#[derive(Clone, Default)]
pub struct SharedIce(Arc<RwLock<Arc<IceConfig>>>);

impl SharedIce {
    pub fn new(cfg: IceConfig) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(cfg))))
    }

    pub fn current(&self) -> Arc<IceConfig> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn replace(&self, cfg: IceConfig) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(cfg);
    }
}

/// Псевдоним пользователя в имени учётки TURN.
pub fn pseudonym(user_id: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PSEUDONYM_DOMAIN);
    hasher.update(user_id);
    hex::encode(&hasher.finalize()[..8])
}

/// Пароль coturn REST для имени `username`.
pub fn turn_credential(secret: &str, username: &str) -> String {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(username.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Ответ на `GetIceServers` для `user_id` в момент `now`.
pub fn issue(cfg: &IceConfig, user_id: &[u8; 32], now: u64) -> wire::IceServers {
    if cfg.servers.is_empty() {
        return reject(IceRejectReason::NotConfigured);
    }
    let expires_at = now.saturating_add(cfg.credential_ttl_secs);
    let username = format!("{expires_at}:{}", pseudonym(user_id));
    let servers = cfg
        .servers
        .iter()
        .map(|server| match &server.secret {
            Some(secret) => wire::IceServer {
                urls: server.urls.clone(),
                username: username.clone(),
                credential: turn_credential(secret, &username),
            },
            None => wire::IceServer {
                urls: server.urls.clone(),
                ..wire::IceServer::default()
            },
        })
        .collect();
    wire::IceServers {
        servers,
        expires_at,
        reason: IceRejectReason::Unspecified as i32,
    }
}

pub fn reject(reason: IceRejectReason) -> wire::IceServers {
    wire::IceServers {
        servers: Vec::new(),
        expires_at: 0,
        reason: reason as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IceServerConfig;

    fn config() -> IceConfig {
        IceConfig {
            servers: vec![
                IceServerConfig {
                    urls: vec!["stun:stun.example.org:3478".into()],
                    secret: None,
                },
                IceServerConfig {
                    urls: vec![
                        "turn:turn.example.org:3478?transport=udp".into(),
                        "turns:turn.example.org:5349".into(),
                    ],
                    secret: Some("north-wind-shared-secret".into()),
                },
            ],
            credential_ttl_secs: 7200,
        }
    }

    #[test]
    fn credential_matches_the_coturn_rest_scheme() {
        // Эталон посчитан независимо:
        // python3 -c "import hmac,hashlib,base64;print(base64.b64encode(hmac.new(b'north-wind-shared-secret',b'1700007200:0123456789abcdef',hashlib.sha1).digest()).decode())"
        assert_eq!(
            turn_credential("north-wind-shared-secret", "1700007200:0123456789abcdef"),
            "8aIjY/mZgy6YCrW3QtqRAOm5G5Y="
        );
    }

    #[test]
    fn issued_servers_carry_expiry_pseudonym_and_signature() {
        let user = [7u8; 32];
        let reply = issue(&config(), &user, 1_700_000_000);
        assert_eq!(reply.reason, IceRejectReason::Unspecified as i32);
        assert_eq!(reply.expires_at, 1_700_007_200);
        assert_eq!(reply.servers.len(), 2);

        let stun = &reply.servers[0];
        assert!(stun.username.is_empty() && stun.credential.is_empty());

        let turn = &reply.servers[1];
        assert_eq!(turn.urls.len(), 2);
        assert_eq!(turn.username, format!("1700007200:{}", pseudonym(&user)));
        assert_eq!(
            turn.credential,
            turn_credential("north-wind-shared-secret", &turn.username)
        );
        // Ключ пользователя в учётку не попадает.
        assert!(!turn.username.contains(&hex::encode(user)));
        assert_eq!(pseudonym(&user).len(), 16);
        assert_ne!(pseudonym(&user), pseudonym(&[8u8; 32]));
    }

    #[test]
    fn empty_config_is_not_configured() {
        let reply = issue(&IceConfig::default(), &[1u8; 32], 5);
        assert_eq!(reply.reason, IceRejectReason::NotConfigured as i32);
        assert!(reply.servers.is_empty());
        assert_eq!(reject(IceRejectReason::RateLimited).reason, 2);
    }

    #[test]
    fn shared_config_swaps() {
        let shared = SharedIce::new(IceConfig::default());
        assert!(shared.current().servers.is_empty());
        shared.replace(config());
        assert_eq!(shared.current().servers.len(), 2);
    }
}
