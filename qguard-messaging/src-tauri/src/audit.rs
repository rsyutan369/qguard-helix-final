use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::kdf::sha3_hex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: String,
    pub severity: AuditSeverity,
    pub description: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct AuditChain {
    events: Vec<AuditEvent>,
}

impl AuditChain {
    pub fn append(
        &mut self,
        event_type: impl Into<String>,
        severity: AuditSeverity,
        description: impl Into<String>,
    ) -> AuditEvent {
        let previous_hash = self
            .events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        let created_at = Utc::now();
        let id = Uuid::new_v4().to_string();
        let event_type = event_type.into();
        let description = description.into();
        let material = format!(
            "{id}|{event_type}|{description}|{previous_hash}|{}",
            created_at.to_rfc3339()
        );
        let event_hash = sha3_hex(material.as_bytes());
        let event = AuditEvent {
            id,
            event_type,
            severity,
            description,
            previous_hash,
            event_hash,
            created_at,
        };
        self.events.push(event.clone());
        event
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        self.events.iter().rev().take(limit).cloned().collect()
    }

    pub fn verify(&self) -> bool {
        let mut previous = "genesis".to_string();
        for event in &self.events {
            if event.previous_hash != previous {
                return false;
            }
            previous = event.event_hash.clone();
        }
        true
    }
}
