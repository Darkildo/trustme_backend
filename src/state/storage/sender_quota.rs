//! SEC-43: a sender's budget is shared by account and every device inbox.
use super::*;

/// 33-byte namespace, distinct from account (32) and device (34) keys.
pub(super) fn aggregate_prefix(key: &[u8]) -> Result<Vec<u8>> {
    let recipient = key.get(..USER_PREFIX_LEN).context("invalid inbox prefix")?;
    let mut prefix = Vec::with_capacity(USER_PREFIX_LEN + 1);
    prefix.push(0xff);
    prefix.extend_from_slice(recipient);
    Ok(prefix)
}

impl Storage {
    /// Count the sender across every scope of this recipient. Stored counters
    /// include expired records, so below-ceiling is a safe fast path; at the
    /// ceiling scan real records and release expired ones before rejecting.
    pub fn scan_sender_pair_quota(
        &self,
        recipient: &[u8; 32],
        sender: &[u8; 32],
        ceiling: u64,
    ) -> Result<u64> {
        if ceiling == 0 {
            return Ok(0);
        }
        let mut key = aggregate_prefix(recipient)?;
        key.extend_from_slice(sender);
        let stored = self
            .queue_stats
            .get(key)?
            .map(|value| {
                value
                    .get(..8)
                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                    .map(u64::from_be_bytes)
                    .context("invalid aggregate sender counter")
            })
            .transpose()?
            .unwrap_or(0);
        if stored < ceiling {
            return Ok(stored);
        }
        let now = unix_timestamp_secs()?;
        let mut count = 0u64;
        for (tree, prefix_len) in [
            (&self.inbox, USER_PREFIX_LEN),
            (&self.device_inbox, DEVICE_PREFIX_LEN),
        ] {
            let mut expired = Vec::new();
            for entry in tree.scan_prefix(recipient) {
                let (key, value) = entry?;
                let decoded = decode_message_value(&value)?;
                if self
                    .offline_messages_retention
                    .expires(decoded.created_at_secs, now)
                    || ttl_expired(decoded.ttl_seconds, decoded.created_at_secs, now)
                {
                    expired.push(key);
                    continue;
                }
                if decoded.sender_id == *sender {
                    count = count.saturating_add(1);
                }
                if count >= ceiling {
                    break;
                }
            }
            for key in expired {
                self.remove_and_note(tree, &key, prefix_len)?;
            }
            if count >= ceiling {
                break;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (String, Storage) {
        let path = std::env::temp_dir()
            .join(format!(
                "trust_sender_quota_{}_{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .to_string_lossy()
            .into_owned();
        let keep = RetentionPolicy::KeepFor(std::time::Duration::from_secs(30 * 86400));
        let storage = Storage::open(&path, keep, keep).unwrap();
        (path, storage)
    }

    #[test]
    fn aggregate_quota_survives_restart_and_ack_releases_all_scopes() {
        let (path, storage) = open();
        let recipient = [1; 32];
        let sender = [2; 32];
        let account = storage
            .enqueue_inbox(&recipient, &sender, None, b"account", None, 0)
            .unwrap();
        let device = storage
            .enqueue_device_inbox(&recipient, 7, &sender, None, b"phone", None, 0)
            .unwrap();
        storage
            .enqueue_device_inbox(&recipient, 65535, &sender, None, b"tablet", None, 0)
            .unwrap();
        storage
            .enqueue_inbox(&recipient, &[3; 32], None, b"other sender", None, 0)
            .unwrap();
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &sender, 10)
                .unwrap(),
            3
        );
        drop(storage);
        let keep = RetentionPolicy::KeepFor(std::time::Duration::from_secs(30 * 86400));
        let storage = Storage::open(&path, keep, keep).unwrap();
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &sender, 3)
                .unwrap(),
            3
        );
        storage.remove_inbox(&recipient, account.id).unwrap();
        storage
            .remove_device_inbox(&recipient, 7, device.id)
            .unwrap();
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &sender, 10)
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &[3; 32], 10)
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .scan_sender_pair_quota(&[9; 32], &sender, 10)
                .unwrap(),
            0
        );
        drop(storage);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn expired_device_records_release_the_shared_sender_budget() {
        let (path, storage) = open();
        let recipient = [1; 32];
        let sender = [2; 32];
        let now = unix_timestamp_secs().unwrap();
        let stale = encode_message_value(now - 7200, &sender, None, None, 3600, b"expired");
        for device in [7, 65535] {
            storage
                .device_inbox
                .insert(build_device_key(&recipient, device, 1), stale.clone())
                .unwrap();
            storage
                .note_stored(
                    &build_device_prefix(&recipient, device),
                    stale.len(),
                    Some(&sender),
                )
                .unwrap();
        }
        storage
            .enqueue_inbox(&recipient, &sender, None, b"fresh", None, 0)
            .unwrap();
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &sender, 3)
                .unwrap(),
            1
        );
        assert!(storage.device_inbox.is_empty());
        assert_eq!(
            storage
                .scan_sender_pair_quota(&recipient, &sender, 10)
                .unwrap(),
            1
        );
        drop(storage);
        std::fs::remove_dir_all(path).unwrap();
    }
}
