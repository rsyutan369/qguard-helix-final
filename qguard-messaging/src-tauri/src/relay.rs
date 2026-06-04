use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayTarget {
    pub user_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayQueueItem {
    pub envelope_id: String,
    pub recipient: RelayTarget,
    pub encrypted_payload: String,
}

pub const SUPABASE_REALTIME_CHANNELS: &[&str] = &[
    "messaging_message_envelopes",
    "messaging_delivery_receipts",
    "messaging_security_events",
    "messaging_vault_files",
];
