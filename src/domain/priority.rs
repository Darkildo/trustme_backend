use anyhow::{Result, bail};

use crate::wire::MessagePriority as WirePriority;

/// Доменный приоритет сообщения. Отсутствие выражается через
/// `Option<MessagePriority>`: на проводе это `UNSPECIFIED` (нулевое значение
/// enum'а), в хранилище — байт 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessagePriority {
    Low,
    Medium,
    High,
}

impl MessagePriority {
    /// Отсутствие приоритета — нулевое значение enum'а на проводе, а не
    /// отдельная обёртка: proto3 не отличает zero от незаполненного поля,
    /// и `UNSPECIFIED` для нас и есть «не указан».
    pub fn to_wire(this: Option<Self>) -> i32 {
        let wire = match this {
            None => WirePriority::Unspecified,
            Some(Self::Low) => WirePriority::Low,
            Some(Self::Medium) => WirePriority::Medium,
            Some(Self::High) => WirePriority::High,
        };
        wire as i32
    }

    /// Незнакомое значение от более свежего клиента — не ошибка кадра:
    /// конверт обрабатывается как «приоритет не указан».
    pub fn from_wire(value: i32) -> Option<Self> {
        match WirePriority::try_from(value) {
            Ok(WirePriority::Low) => Some(Self::Low),
            Ok(WirePriority::Medium) => Some(Self::Medium),
            Ok(WirePriority::High) => Some(Self::High),
            Ok(WirePriority::Unspecified) | Err(_) => None,
        }
    }

    pub fn as_storage_byte(this: Option<Self>) -> u8 {
        match this {
            None => 0,
            Some(Self::Low) => 1,
            Some(Self::Medium) => 2,
            Some(Self::High) => 3,
        }
    }

    pub fn from_storage_byte(byte: u8) -> Result<Option<Self>> {
        match byte {
            0 => Ok(None),
            1 => Ok(Some(Self::Low)),
            2 => Ok(Some(Self::Medium)),
            3 => Ok(Some(Self::High)),
            other => bail!("unknown stored message priority byte: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessagePriority;
    use crate::wire::MessagePriority as WirePriority;

    #[test]
    fn storage_byte_roundtrip_covers_all_variants() {
        for variant in [
            None,
            Some(MessagePriority::Low),
            Some(MessagePriority::Medium),
            Some(MessagePriority::High),
        ] {
            let byte = MessagePriority::as_storage_byte(variant);
            assert_eq!(MessagePriority::from_storage_byte(byte).unwrap(), variant);
        }
    }

    #[test]
    fn unknown_storage_byte_is_rejected() {
        assert!(MessagePriority::from_storage_byte(99).is_err());
    }

    #[test]
    fn wire_roundtrip_covers_all_variants() {
        for variant in [
            None,
            Some(MessagePriority::Low),
            Some(MessagePriority::Medium),
            Some(MessagePriority::High),
        ] {
            assert_eq!(
                MessagePriority::from_wire(MessagePriority::to_wire(variant)),
                variant
            );
        }
    }

    /// Байт хранилища и номер на проводе совпадают намеренно: одна таблица
    /// значений вместо двух, которые пришлось бы держать синхронными.
    #[test]
    fn wire_numbers_match_storage_bytes() {
        for variant in [
            None,
            Some(MessagePriority::Low),
            Some(MessagePriority::Medium),
            Some(MessagePriority::High),
        ] {
            assert_eq!(
                MessagePriority::to_wire(variant),
                i32::from(MessagePriority::as_storage_byte(variant))
            );
        }
    }

    /// Приоритет из будущей версии схемы обрабатывается как «не указан», а
    /// не роняет кадр.
    #[test]
    fn unknown_wire_value_reads_as_unset() {
        assert_eq!(MessagePriority::from_wire(99), None);
        assert_eq!(
            MessagePriority::from_wire(WirePriority::Unspecified as i32),
            None
        );
    }
}
