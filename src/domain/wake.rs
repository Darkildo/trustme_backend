use crate::wire::WakeHint as WireWakeHint;

/// Wake-семантика конверта. `Option<WakeHint>` — `None` = обычное сообщение
/// (wire-значение `UNSPECIFIED`, его же шлют клиенты, не знающие подсказок).
/// `IncomingCall` клиент-отправитель ставит только на WebRTC OFFER; проверить
/// это нода не может — тело зашифровано. Значение означает «получателя нужно
/// разбудить как на входящий звонок»: iOS-устройству с зарегистрированным
/// PushKit-токеном сервер шлёт voip-пуш мимо коалесинга, остальные
/// устройства идут обычным FCM-wake путём с маркером звонка.
///
/// Не персистится в inbox: push-триггер срабатывает в момент приёма/publish'а
/// конверта, а офлайн-replay протухшего OFFER'а звонить не должен.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeHint {
    IncomingCall,
}

impl WakeHint {
    pub fn to_wire(this: Option<Self>) -> i32 {
        let wire = match this {
            None => WireWakeHint::Unspecified,
            Some(Self::IncomingCall) => WireWakeHint::IncomingCall,
        };
        wire as i32
    }

    /// Незнакомая подсказка от более свежего клиента — «обычное
    /// сообщение»: разбудить получателя звонком по значению, смысла
    /// которого нода не знает, хуже, чем не разбудить.
    pub fn from_wire(value: i32) -> Option<Self> {
        match WireWakeHint::try_from(value) {
            Ok(WireWakeHint::IncomingCall) => Some(Self::IncomingCall),
            Ok(WireWakeHint::Unspecified) | Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WakeHint;
    use crate::wire::WakeHint as WireWakeHint;

    #[test]
    fn wire_roundtrip_covers_all_variants() {
        for (domain, wire) in [
            (None, WireWakeHint::Unspecified),
            (Some(WakeHint::IncomingCall), WireWakeHint::IncomingCall),
        ] {
            assert_eq!(WakeHint::to_wire(domain), wire as i32);
            assert_eq!(WakeHint::from_wire(wire as i32), domain);
        }
    }

    #[test]
    fn unknown_wire_value_reads_as_plain_message() {
        assert_eq!(WakeHint::from_wire(31), None);
    }
}
