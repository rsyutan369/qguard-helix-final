use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::kdf::derive_32;
use crate::error::{QGuardError, Result};

const MAX_SKIPPED_KEYS: usize = 128;

fn sending_chain_info() -> Vec<u8> {
    let mut info = crate::security::obf::ratchet_chain();
    info.extend_from_slice(b":send");
    info
}

fn receiving_chain_info() -> Vec<u8> {
    let mut info = crate::security::obf::ratchet_chain();
    info.extend_from_slice(b":recv");
    info
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageKey {
    pub counter: u64,
    pub key: [u8; 32],
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetSession {
    pub session_id: String,
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
    pub send_counter: u64,
    pub receive_counter: u64,
    pub skipped_message_keys: HashMap<u64, [u8; 32]>,
    #[serde(skip)]
    pub seen_message_ids: HashSet<String>,
}

impl Drop for RatchetSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        self.skipped_message_keys
            .values_mut()
            .for_each(|key| key.zeroize());
    }
}

impl RatchetSession {
    pub fn new(session_id: impl Into<String>, shared_secret: [u8; 32]) -> Result<Self> {
        Ok(Self {
            session_id: session_id.into(),
            root_key: derive_32(&shared_secret, &crate::security::obf::ratchet_root_key())?,
            // The two chains MUST derive from different info strings. They used
            // to share one, which made them byte-identical: the key protecting
            // counter N outbound was the same key that would open counter N
            // inbound. Nothing exploited it -- every session here is seeded from
            // a fresh per-message encapsulation and the AAD binds sender and
            // recipient device ids, so a reflected message fails anyway -- but a
            // primitive that hands out the same key in both directions is one
            // stateful-session refactor away from being a real reflection bug.
            //
            // Not a wire change: the live protocol re-derives both chains in
            // `rotate_root` (which already separated them) and the receive path
            // explicitly re-points `receiving_chain_key` at the sending chain
            // for its single-message sessions. Nothing on the wire reads these
            // initial values.
            sending_chain_key: derive_32(&shared_secret, &sending_chain_info())?,
            receiving_chain_key: derive_32(&shared_secret, &receiving_chain_info())?,
            send_counter: 0,
            receive_counter: 0,
            skipped_message_keys: HashMap::new(),
            seen_message_ids: HashSet::new(),
        })
    }

    pub fn next_send_key(&mut self) -> Result<MessageKey> {
        let counter = self.send_counter;
        let key = derive_32(&self.sending_chain_key, format!("msg:{counter}").as_bytes())?;
        self.sending_chain_key = derive_32(&self.sending_chain_key, b"advance")?;
        self.send_counter += 1;
        Ok(MessageKey { counter, key })
    }

    pub fn receive_key(&mut self, message_id: &str, counter: u64) -> Result<MessageKey> {
        if !self.seen_message_ids.insert(message_id.to_string()) {
            return Err(QGuardError::Replay(format!(
                "message {message_id} already processed"
            )));
        }

        if let Some(key) = self.skipped_message_keys.remove(&counter) {
            return Ok(MessageKey { counter, key });
        }

        while self.receive_counter < counter {
            if self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS {
                return Err(QGuardError::Replay(
                    "skipped key cache limit reached".to_string(),
                ));
            }
            let skipped = derive_32(
                &self.receiving_chain_key,
                format!("msg:{}", self.receive_counter).as_bytes(),
            )?;
            self.skipped_message_keys
                .insert(self.receive_counter, skipped);
            self.receiving_chain_key = derive_32(&self.receiving_chain_key, b"advance")?;
            self.receive_counter += 1;
        }

        let key = derive_32(
            &self.receiving_chain_key,
            format!("msg:{counter}").as_bytes(),
        )?;
        self.receiving_chain_key = derive_32(&self.receiving_chain_key, b"advance")?;
        self.receive_counter = counter + 1;
        Ok(MessageKey { counter, key })
    }

    pub fn rotate_root(&mut self, entropy: &[u8]) -> Result<()> {
        let mut material = Vec::with_capacity(self.root_key.len() + entropy.len());
        material.extend_from_slice(&self.root_key);
        material.extend_from_slice(entropy);
        self.root_key = derive_32(&material, &crate::security::obf::ratchet_root_rotation())?;
        self.sending_chain_key = derive_32(&self.root_key, b"rotated-send")?;
        self.receiving_chain_key = derive_32(&self.root_key, b"rotated-receive")?;
        material.zeroize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_chains_never_start_from_the_same_key() {
        let s = RatchetSession::new("a", [3u8; 32]).unwrap();
        assert_ne!(
            s.sending_chain_key, s.receiving_chain_key,
            "a chain shared between directions hands out the same key twice"
        );
        // rotate_root, which the live protocol always applies, must keep them apart.
        let mut rotated = RatchetSession::new("a", [3u8; 32]).unwrap();
        rotated.rotate_root(b"dh output").unwrap();
        assert_ne!(rotated.sending_chain_key, rotated.receiving_chain_key);
    }

    #[test]
    fn rotates_keys_and_rejects_replay() {
        let shared = [7u8; 32];
        let mut s = RatchetSession::new("a", shared).unwrap();
        let first = s.receive_key("msg-1", 0).unwrap();
        assert_eq!(first.counter, 0);
        assert!(s.receive_key("msg-1", 0).is_err());
        let old_root = s.root_key;
        s.rotate_root(b"new dh output").unwrap();
        assert_ne!(old_root, s.root_key);
    }
}
