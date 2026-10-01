use anyhow::{Result, bail};

use crate::wire::PushPlatform as WirePushPlatform;

/// Platform of the client device that registered a push token.
///
/// `AndroidFcm` and `IosFcm` share the device's alert slot and get the same
/// FCM envelope: it carries both the `android` block and the `apns` headers
/// that FCM forwards to APNs. `IosVoip` is a separate PushKit VoIP token of an
/// iOS device (not equal to its FCM token); it lives in its own slot of
/// `PushTokenStore` and is delivered via APNs (`apns-push-type: voip`)
/// directly or through the push gateway, bypassing FCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushPlatform {
    AndroidFcm,
    IosFcm,
    IosVoip,
}

impl PushPlatform {
    pub fn to_wire(self) -> i32 {
        let wire = match self {
            Self::AndroidFcm => WirePushPlatform::AndroidFcm,
            Self::IosFcm => WirePushPlatform::IosFcm,
            Self::IosVoip => WirePushPlatform::IosVoip,
        };
        wire as i32
    }

    /// В отличие от приоритета, платформа обязательна: по ней выбирается
    /// слот токена (alert или voip). Незаполненное или незнакомое значение —
    /// отказ регистрации, а не молчаливый выбор Android.
    pub fn from_wire(value: i32) -> Result<Self> {
        match WirePushPlatform::try_from(value) {
            Ok(WirePushPlatform::AndroidFcm) => Ok(Self::AndroidFcm),
            Ok(WirePushPlatform::IosFcm) => Ok(Self::IosFcm),
            Ok(WirePushPlatform::IosVoip) => Ok(Self::IosVoip),
            Ok(WirePushPlatform::Unspecified) | Err(_) => {
                bail!("unknown push platform: {value}")
            }
        }
    }

    pub fn as_storage_byte(self) -> u8 {
        match self {
            Self::AndroidFcm => 1,
            Self::IosFcm => 2,
            Self::IosVoip => 3,
        }
    }

    pub fn from_storage_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::AndroidFcm),
            2 => Ok(Self::IosFcm),
            3 => Ok(Self::IosVoip),
            other => bail!("unknown push platform byte: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PushPlatform;
    use crate::wire::PushPlatform as WirePushPlatform;

    #[test]
    fn storage_byte_roundtrip_covers_all_variants() {
        for variant in [
            PushPlatform::AndroidFcm,
            PushPlatform::IosFcm,
            PushPlatform::IosVoip,
        ] {
            let byte = variant.as_storage_byte();
            assert_eq!(PushPlatform::from_storage_byte(byte).unwrap(), variant);
        }
    }

    #[test]
    fn wire_roundtrip_covers_all_variants() {
        for (wire, expected) in [
            (WirePushPlatform::AndroidFcm, PushPlatform::AndroidFcm),
            (WirePushPlatform::IosFcm, PushPlatform::IosFcm),
            (WirePushPlatform::IosVoip, PushPlatform::IosVoip),
        ] {
            assert_eq!(PushPlatform::from_wire(wire as i32).unwrap(), expected);
            assert_eq!(expected.to_wire(), wire as i32);
        }
    }

    /// Платформа обязательна: незаполненное поле и значение из будущей
    /// схемы одинаково отвергаются, а не превращаются в Android.
    #[test]
    fn unset_and_unknown_platforms_are_rejected() {
        assert!(PushPlatform::from_wire(WirePushPlatform::Unspecified as i32).is_err());
        assert!(PushPlatform::from_wire(77).is_err());
    }
}
