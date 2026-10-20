//! Test-only: a complete device — its own `AppState`, data directory, signed-in
//! user, identity and prekeys — so tests can run two of them against each other
//! through the real command code.

use std::path::PathBuf;

use crate::commands::calls::CallPeerIdentity;
use crate::commands::messaging::{RecipientIdentityBundle, RecipientKeyBundle, RecipientPrekeyBundle};
use crate::identity::LocalIdentity;
use crate::state::{AppState, AuthSession};

pub struct TestDevice {
    pub state: AppState,
    pub user: String,
    pub dir: PathBuf,
    pub device_id: String,
}

impl TestDevice {
    /// A fresh device for a fresh user, with the ratchet setting given.
    pub fn new(ratchet: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("qguard-device-test-{}", uuid::Uuid::new_v4()));
        let user = format!("test-user-{}", uuid::Uuid::new_v4());
        let device = Self::open(dir, user);
        device.state.set_ratchet_enabled(ratchet).expect("ratchet setting");
        device
    }

    /// An app start over an existing data directory.
    pub fn open(dir: PathBuf, user: String) -> Self {
        let state = AppState::new(dir.clone()).expect("state");
        state
            .set_auth_session(AuthSession {
                user_id: user.clone(),
                email: format!("{user}@example.test"),
                tier: "pro".to_string(),
                access_token: "test".to_string(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            })
            .expect("auth");
        let device_id = state.ensure_identity(&user, "Desktop").expect("identity").device_id;
        Self { state, user, dir, device_id }
    }

    /// Quit and relaunch the app over the same data.
    pub fn restart(self) -> Self {
        self.state.flush_loaded_message_keys();
        let dir = self.dir.clone();
        let user = self.user.clone();
        std::mem::forget(self); // keep the directory and keychain entry for the new instance
        Self::open(dir, user)
    }

    /// This device's directory row, as a peer would fetch it.
    pub fn identity_row(&self) -> RecipientIdentityBundle {
        let bundle = self.state.ensure_identity(&self.user, "Desktop").expect("identity");
        RecipientIdentityBundle {
            user_id: bundle.user_id,
            device_id: bundle.device_id,
            x25519_identity_public: bundle.x25519_identity_public,
            mlkem_identity_public: bundle.mlkem_identity_public,
            ed25519_identity_public: bundle.ed25519_identity_public,
            mldsa_identity_public: bundle.mldsa_identity_public,
            identity_signature: bundle.signature,
            suite: Some(bundle.suite),
        }
    }

    /// The full bundle a sender seals to.
    pub fn key_bundle(&self) -> RecipientKeyBundle {
        let signed = self.state.signed_prekey.lock().unwrap().as_ref().expect("signed prekey").public.clone();
        RecipientKeyBundle {
            identity: self.identity_row(),
            signed_prekey: RecipientPrekeyBundle {
                prekey_id: signed.prekey_id,
                x25519_public: signed.x25519_public,
                mlkem_public: signed.mlkem_public,
                signature: signed.signature,
            },
            one_time_prekey: None,
        }
    }

    /// This device as the call and verification commands take it.
    pub fn call_peer(&self) -> CallPeerIdentity {
        let row = self.identity_row();
        CallPeerIdentity {
            user_id: row.user_id,
            device_id: row.device_id,
            x25519_identity_public: row.x25519_identity_public,
            mlkem_identity_public: row.mlkem_identity_public,
            ed25519_identity_public: row.ed25519_identity_public,
            mldsa_identity_public: row.mldsa_identity_public,
            identity_signature: row.identity_signature,
        }
    }
}

impl Drop for TestDevice {
    fn drop(&mut self) {
        let _ = crate::security::keystore::delete_secret(&AppState::safe_user_key(&self.user), &self.dir);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Any identity — e.g. an impostor's — as the call commands take it.
pub fn call_peer_of(identity: &LocalIdentity) -> CallPeerIdentity {
    let bundle = identity.public_bundle().expect("bundle");
    CallPeerIdentity {
        user_id: bundle.user_id,
        device_id: bundle.device_id,
        x25519_identity_public: bundle.x25519_identity_public,
        mlkem_identity_public: bundle.mlkem_identity_public,
        ed25519_identity_public: bundle.ed25519_identity_public,
        mldsa_identity_public: bundle.mldsa_identity_public,
        identity_signature: bundle.signature,
    }
}
