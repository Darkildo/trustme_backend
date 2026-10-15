//! Queue provenance is a side tree keyed by the exact inbox key. Message
//! insertion/removal and this metadata share a sled transaction; old v5
//! message bodies remain unchanged and old records read as unknown/None.
use super::*;

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_inbox(
        &self,
        recipient: &[u8; 32],
        sender: &[u8; 32],
        sender_device: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        ttl: u64,
    ) -> Result<EnqueueResult> {
        self.enqueue_inbox_with_queue(recipient, sender, sender_device, body, priority, ttl, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_device_inbox(
        &self,
        recipient: &[u8; 32],
        device: DeviceId,
        sender: &[u8; 32],
        sender_device: Option<DeviceId>,
        body: &[u8],
        priority: Option<MessagePriority>,
        ttl: u64,
    ) -> Result<EnqueueResult> {
        self.enqueue_device_inbox_with_queue(
            recipient,
            device,
            sender,
            sender_device,
            body,
            priority,
            ttl,
            None,
        )
    }

    pub(super) fn queue_id_for(&self, key: &[u8]) -> Result<Option<[u8; 32]>> {
        self.message_queues
            .get(key)?
            .map(|value| {
                <[u8; 32]>::try_from(value.as_ref())
                    .map_err(|_| anyhow::anyhow!("invalid stored queue provenance"))
            })
            .transpose()
    }

    pub(super) fn prune_provenance_orphans(&self) -> Result<()> {
        for entry in self.message_queues.iter() {
            let (key, _) = entry?;
            let exists = match key.len() {
                40 => self.inbox.contains_key(&key)?,
                42 => self.device_inbox.contains_key(&key)?,
                _ => false,
            };
            if !exists {
                self.message_queues.remove(&key)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RetentionPolicy;
    use std::time::Duration;

    #[test]
    fn provenance_survives_reopen_and_ack_removes_metadata() {
        let path = std::env::temp_dir().join(format!(
            "trust_provenance_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let open = || {
            Storage::open(
                path.to_str().unwrap(),
                RetentionPolicy::KeepFor(Duration::from_secs(3600)),
                RetentionPolicy::Disabled,
            )
            .unwrap()
        };
        let recipient = [1; 32];
        let sender = [2; 32];
        let queue = [3; 32];
        let (account_id, device_id);
        {
            let storage = open();
            account_id = storage
                .enqueue_inbox_with_queue(
                    &recipient,
                    &sender,
                    None,
                    b"account",
                    None,
                    0,
                    Some(queue),
                )
                .unwrap()
                .id;
            device_id = storage
                .enqueue_device_inbox_with_queue(
                    &recipient,
                    7,
                    &sender,
                    None,
                    b"device",
                    None,
                    0,
                    Some(queue),
                )
                .unwrap()
                .id;
            storage
                .enqueue_inbox(&recipient, &sender, None, b"legacy", None, 0)
                .unwrap();
            storage.message_queues.insert(b"orphan", &queue).unwrap();
            storage.db.flush().unwrap();
        }
        {
            let storage = open();
            assert_eq!(
                storage.message_queues.len(),
                2,
                "startup removes orphan metadata"
            );
            for _ in 0..2 {
                let scan = storage
                    .scan_inbox(&recipient, InboxScope::Account, 0, 10, |_| false)
                    .unwrap();
                assert_eq!(scan.messages.len(), 2);
                assert_eq!(scan.messages[0].queue_id, Some(queue));
                assert_eq!(
                    scan.messages[1].queue_id, None,
                    "legacy addressing stays unknown"
                );
            }
            assert_eq!(
                storage
                    .scan_inbox(&recipient, InboxScope::Device(7), 0, 10, |_| false)
                    .unwrap()
                    .messages[0]
                    .queue_id,
                Some(queue)
            );
            assert_eq!(
                storage.ack_inbox(&recipient, None, device_id).unwrap(),
                None
            );
            assert_eq!(
                storage.message_queues.len(),
                2,
                "wrong scope cannot erase metadata"
            );
            storage.ack_inbox(&recipient, None, account_id).unwrap();
            storage.ack_inbox(&recipient, Some(7), device_id).unwrap();
            assert!(storage.message_queues.is_empty());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
