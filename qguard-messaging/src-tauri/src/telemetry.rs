use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub stage: String,
    pub detail: String,
    pub progress: u8,
    pub created_at: DateTime<Utc>,
}

impl TelemetryEvent {
    pub fn new(stage: impl Into<String>, detail: impl Into<String>, progress: u8) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            stage: stage.into(),
            detail: detail.into(),
            progress,
            created_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuantumSecurityReport {
    pub hybrid_session_status: String,
    pub pqc_algorithm: String,
    pub forward_secrecy: String,
    pub hndl_protection: String,
    pub quantum_safe_score: u8,
    pub key_rotation_history: Vec<String>,
    pub warnings: Vec<String>,
}

impl Default for QuantumSecurityReport {
    fn default() -> Self {
        Self {
            hybrid_session_status: "Hybrid Active".to_string(),
            pqc_algorithm: "ML-KEM-768 + ML-DSA-65".to_string(),
            forward_secrecy: "Per-message ratchet keys active".to_string(),
            hndl_protection: "Enabled".to_string(),
            quantum_safe_score: 98,
            key_rotation_history: vec![
                "Identity generated".to_string(),
                "Signed prekey prepared".to_string(),
                "One-time prekey batch available".to_string(),
            ],
            warnings: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub e2ee_status: String,
    pub pqc_status: String,
    pub active_sessions: u32,
    pub vault_storage: String,
    pub device_count: u32,
    pub quantum_safe_score: u8,
    pub hndl_status: String,
}
