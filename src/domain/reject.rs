use crate::wire::SendRejectReason as WireSendRejectReason;

/// Причина отказа отправки, уточняющая `ok = false` в `SendAck`.
///
/// Контракт совместимости (server-contract.md §6): `Unspecified` —
/// zero-значение proto3 и потому неотличимо от «поле не заполнено»; пара
/// `ok = false, reason = Unspecified` читается как родовой отказ — так же,
/// как у серверов, не знающих этого поля. Клиенты не должны завязывать
/// логику на reason, кроме диагностики и ретраев.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendRejectReason {
    /// Родовой отказ / поле не заполнено.
    Unspecified,
    /// Очередь получателя переполнена квотой.
    Full,
    /// Нет права писать в адресат: `queueId` неизвестен или отозван.
    NoPermit,
    /// ttl уже истёк к моменту приёма. Зарезервировано: нода эту причину
    /// сейчас не выдаёт.
    Expired,
    /// Превышен rate-limit msg/s или байт/сутки.
    RateLimited,
    /// ttl ниже пола ноды.
    InvalidTtl,
    /// Ноде плохо: диск, брокер, внутренняя ошибка.
    Internal,
    /// Сессия открыта сертификатом устройства без права на отправку.
    Forbidden,
}

impl SendRejectReason {
    pub fn to_wire(self) -> i32 {
        let wire = match self {
            Self::Unspecified => WireSendRejectReason::Unspecified,
            Self::Full => WireSendRejectReason::Full,
            Self::NoPermit => WireSendRejectReason::NoPermit,
            Self::Expired => WireSendRejectReason::Expired,
            Self::RateLimited => WireSendRejectReason::RateLimited,
            Self::InvalidTtl => WireSendRejectReason::InvalidTtl,
            Self::Internal => WireSendRejectReason::Internal,
            Self::Forbidden => WireSendRejectReason::Forbidden,
        };
        wire as i32
    }

    /// Незнакомое wire-значение от более свежего сервера трактуется как
    /// родовой отказ — форвард-совместимость в обе стороны.
    pub fn from_wire(value: i32) -> Self {
        match WireSendRejectReason::try_from(value) {
            Ok(WireSendRejectReason::Full) => Self::Full,
            Ok(WireSendRejectReason::NoPermit) => Self::NoPermit,
            Ok(WireSendRejectReason::Expired) => Self::Expired,
            Ok(WireSendRejectReason::RateLimited) => Self::RateLimited,
            Ok(WireSendRejectReason::InvalidTtl) => Self::InvalidTtl,
            Ok(WireSendRejectReason::Internal) => Self::Internal,
            Ok(WireSendRejectReason::Forbidden) => Self::Forbidden,
            Ok(WireSendRejectReason::Unspecified) | Err(_) => Self::Unspecified,
        }
    }

    /// Стабильная метка для Prometheus (`reject_total{reason=...}`).
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Full => "full",
            Self::NoPermit => "no_permit",
            Self::Expired => "expired",
            Self::RateLimited => "rate_limited",
            Self::InvalidTtl => "invalid_ttl",
            Self::Internal => "internal",
            Self::Forbidden => "forbidden",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SendRejectReason;
    use crate::wire::SendRejectReason as WireSendRejectReason;

    #[test]
    fn wire_roundtrip_covers_all_variants() {
        for domain in [
            SendRejectReason::Unspecified,
            SendRejectReason::Full,
            SendRejectReason::NoPermit,
            SendRejectReason::Expired,
            SendRejectReason::RateLimited,
            SendRejectReason::InvalidTtl,
            SendRejectReason::Internal,
            SendRejectReason::Forbidden,
        ] {
            assert_eq!(SendRejectReason::from_wire(domain.to_wire()), domain);
        }
    }

    /// Метки уходят в `reject_total{reason=...}`: менять их — ломать
    /// существующие дашборды и алерты, поэтому набор зафиксирован тестом.
    #[test]
    fn metric_labels_are_stable() {
        assert_eq!(
            SendRejectReason::Unspecified.as_metric_label(),
            "unspecified"
        );
        assert_eq!(SendRejectReason::Full.as_metric_label(), "full");
        assert_eq!(SendRejectReason::NoPermit.as_metric_label(), "no_permit");
        assert_eq!(SendRejectReason::Expired.as_metric_label(), "expired");
        assert_eq!(
            SendRejectReason::RateLimited.as_metric_label(),
            "rate_limited"
        );
        assert_eq!(
            SendRejectReason::InvalidTtl.as_metric_label(),
            "invalid_ttl"
        );
        assert_eq!(SendRejectReason::Internal.as_metric_label(), "internal");
        assert_eq!(SendRejectReason::Forbidden.as_metric_label(), "forbidden");
    }

    #[test]
    fn unspecified_is_zero_value() {
        // zero-значение proto3 неотличимо от отсутствия поля.
        assert_eq!(WireSendRejectReason::Unspecified as i32, 0);
        assert_eq!(SendRejectReason::Unspecified.to_wire(), 0);
    }

    /// Причина из будущей версии схемы читается как родовой отказ:
    /// клиент видит `ok = false` и не залипает на незнакомом значении.
    #[test]
    fn unknown_wire_value_reads_as_unspecified() {
        assert_eq!(
            SendRejectReason::from_wire(4242),
            SendRejectReason::Unspecified
        );
    }
}
