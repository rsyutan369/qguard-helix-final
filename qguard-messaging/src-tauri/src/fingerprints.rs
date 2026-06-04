use serde::{Deserialize, Serialize};

use crate::crypto::kdf::sha3_hex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafetyNumber {
    pub display: String,
    pub qr_payload: String,
}

pub fn conversation_safety_number(
    local_fingerprint: &str,
    remote_fingerprint: &str,
) -> SafetyNumber {
    let mut parts = [
        local_fingerprint.to_string(),
        remote_fingerprint.to_string(),
    ];
    parts.sort();
    let digest = sha3_hex(parts.join(":").as_bytes());
    let display = digest
        .as_bytes()
        .chunks(5)
        .take(12)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .unwrap_or_default()
                .to_uppercase()
        })
        .collect::<Vec<_>>()
        .join(" ");
    SafetyNumber {
        qr_payload: format!("qguard-verify:v1:{digest}"),
        display,
    }
}
