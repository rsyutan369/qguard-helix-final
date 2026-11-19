//! Profile pictures shared with trusted devices.
//!
//! Each device keeps a small thumbnail of its own account picture (made by the
//! app from the signed-in profile) and a cache of the pictures its trusted
//! peers sent. Pictures travel only on the persistent channel (`channel.rs`),
//! which is an authenticated hybrid post-quantum session with a peer both
//! users paired: a picture is therefore stored under the fingerprint that
//! authenticated the session, never under a name the peer chose.
//!
//! The channel exchanges a SHA3-256 digest first; the picture itself moves
//! only when the receiver does not hold that digest yet, so a reconnect costs
//! one small frame. The receiver re-hashes the bytes before storing them, and
//! accepts only small JPEG, PNG or WebP images. Images are never decoded in
//! the native core; the web view renders them from a data URL.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::provider,
    error::{QGuardError, Result},
    state::AppState,
};

use super::{lan::fingerprint_valid, profile::TrustBook};

pub(super) const DOC: &str = "offline-avatars";
const AAD: &[u8] = b"QGuard-Offline-Avatars-v1";
/// Upper bound for one picture. The app sends a ~192 px JPEG of a few KiB;
/// the bound keeps a Bluetooth channel from stalling behind a large frame.
pub(super) const MAX_BYTES: usize = 48 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Avatar {
    /// Lowercase hex SHA3-256 of the image bytes.
    pub digest: String,
    pub mime: String,
    /// Base64 image bytes.
    pub image: String,
    pub updated_at: i64,
}

impl Avatar {
    pub fn data_url(&self) -> String {
        format!("data:{};base64,{}", self.mime, self.image)
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct AvatarBook {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<Avatar>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peers: BTreeMap<String, Avatar>,
}

impl AvatarBook {
    pub fn load(state: &AppState, owner: &str) -> Result<Self> {
        let Some(bytes) = state.load_user_secret_doc(owner, DOC, AAD, DOC)? else {
            return Ok(Self::default());
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| QGuardError::Storage("offline profile pictures are unreadable".into()))
    }

    /// Save, keeping only pictures of devices that are still trusted.
    pub fn save(&mut self, state: &AppState, owner: &str, book: &TrustBook) -> Result<()> {
        self.peers.retain(|fingerprint, _| book.peers.contains_key(fingerprint));
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| {
            QGuardError::Storage("offline profile pictures could not be encoded".into())
        })?);
        state.save_user_secret_doc(owner, DOC, AAD, &bytes, DOC)
    }

    pub fn local_digest(&self) -> Option<String> {
        self.local.as_ref().map(|avatar| avatar.digest.clone())
    }

    /// The cached picture of a trusted peer.
    pub fn peer<'a>(&'a self, book: &TrustBook, fingerprint: &str) -> Option<&'a Avatar> {
        book.peers
            .contains_key(fingerprint)
            .then(|| self.peers.get(fingerprint))
            .flatten()
    }
}

/// The image type, from its signature. Anything else is refused.
pub(super) fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        Some("image/png")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(provider::sha3_256(bytes))
}

pub(super) fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn invalid() -> QGuardError {
    QGuardError::InvalidInput("The profile picture must be a JPEG, PNG or WebP image under 48 KiB.".into())
}

/// Validate image bytes and build the stored record.
pub(super) fn from_bytes(bytes: &[u8]) -> Result<Avatar> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let mime = image_mime(bytes).ok_or_else(invalid)?;
    Ok(Avatar {
        digest: digest(bytes),
        mime: mime.into(),
        image: STANDARD.encode(bytes),
        updated_at: Utc::now().timestamp(),
    })
}

/// A picture received from a peer: it must hash to the digest it claims.
pub(super) fn received(claimed: &str, image: &str) -> Result<Avatar> {
    if !valid_digest(claimed) || image.len() > MAX_BYTES.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(STANDARD.decode(image).map_err(|_| invalid())?);
    let avatar = from_bytes(&bytes)?;
    if avatar.digest != claimed {
        return Err(QGuardError::Trust("The profile picture does not match its digest.".into()));
    }
    Ok(avatar)
}

/// Remove a peer's picture (the device was removed or blocked).
pub(super) fn forget(state: &AppState, owner: &str, fingerprint: &str) -> Result<()> {
    if !fingerprint_valid(fingerprint) {
        return Ok(());
    }
    let mut avatars = AvatarBook::load(state, owner)?;
    if avatars.peers.remove(fingerprint).is_some() {
        let book = TrustBook::load(state, owner)?;
        avatars.save(state, owner, &book)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F', 0, 1, 0xff, 0xd9];

    #[test]
    fn accepts_small_signed_images_and_refuses_everything_else() {
        let avatar = from_bytes(JPEG).unwrap();
        assert_eq!(avatar.mime, "image/jpeg");
        assert!(valid_digest(&avatar.digest));
        assert!(avatar.data_url().starts_with("data:image/jpeg;base64,"));
        let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0];
        assert_eq!(image_mime(&png), Some("image/png"));
        assert_eq!(image_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert!(from_bytes(b"<svg onload=alert(1)>").is_err());
        assert!(from_bytes(b"GIF89a").is_err());
        assert!(from_bytes(&[]).is_err());
        let mut large = JPEG.to_vec();
        large.resize(MAX_BYTES + 1, 0);
        assert!(from_bytes(&large).is_err());
    }

    #[test]
    fn a_received_picture_must_hash_to_the_digest_it_claims() {
        let avatar = from_bytes(JPEG).unwrap();
        assert_eq!(received(&avatar.digest, &avatar.image).unwrap().digest, avatar.digest);
        let other = "0".repeat(64);
        assert!(matches!(received(&other, &avatar.image), Err(QGuardError::Trust(_))));
        assert!(received("ABC", &avatar.image).is_err());
        assert!(received(&avatar.digest, "not base64!").is_err());
    }
}
