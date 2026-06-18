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
    /// Zero-evidence baseline. This is intentionally NOT a "healthy" posture:
    /// a real report must be derived from runtime evidence (loaded identity,
    /// prekeys, active ratchet sessions, device trust state, and the verified
    /// audit chain). Returning fabricated scores or status here would put
    /// untraceable metrics into exported security reports.
    fn default() -> Self {
        Self {
            hybrid_session_status: "No Active Session".to_string(),
            pqc_algorithm: "No active device keys".to_string(),
            forward_secrecy: "Awaiting prekey material".to_string(),
            hndl_protection: "Not Ready".to_string(),
            quantum_safe_score: 0,
            key_rotation_history: Vec::new(),
            warnings: vec![
                "Quantum posture has not been evaluated from runtime evidence".to_string(),
            ],
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
