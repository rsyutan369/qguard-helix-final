use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceTrustState {
    ThisDevice,
    Trusted,
    PendingQrApproval,
    Revoked,
    Suspicious,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: String,
    pub user_id: String,
    pub label: String,
    pub fingerprint: String,
    pub trust_state: DeviceTrustState,
    pub pqc_status: String,
    pub last_seen_at: DateTime<Utc>,
}

impl TrustedDevice {
    pub fn new_this_device(
        user_id: String,
        device_id: String,
        label: String,
        fingerprint: String,
    ) -> Self {
        Self {
            device_id,
            user_id,
            label,
            fingerprint,
            trust_state: DeviceTrustState::ThisDevice,
            pqc_status: "Hybrid active: X25519 + ML-KEM-768".to_string(),
            last_seen_at: Utc::now(),
        }
    }
}
