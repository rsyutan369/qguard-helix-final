//! Local trust is scoped to the active Qguard account and kept in its protected
//! storage. Discovery hints never authorize a peer.

use std::{collections::BTreeMap, net::SocketAddrV4};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    error::{QGuardError, Result},
    state::AppState,
};

use super::{
    lan::{fingerprint_valid, lan_address},
    session,
};

pub(super) const TRUST_DOC: &str = "offline-peer-trust";
const TRUST_AAD: &[u8] = b"QGuard-Offline-Peer-Trust-v1";
pub(super) const XFER_KEY_DOC: &str = "offline-xfer-key";
const XFER_KEY_AAD: &[u8] = b"QGuard-Offline-Xfer-Storage-Key-v1";
const MAX_TRUSTED: usize = 128;
const MAX_BLOCKED: usize = 128;
pub(super) const MAX_DEVICE_LABEL_BYTES: usize = 100;
pub(super) const PEER_PLATFORMS: [&str; 4] = ["android", "windows", "macos", "linux"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum PeerCapability {
    Mesh,
    Xfer,
}

impl PeerCapability {
    fn name(self) -> &'static str {
        match self {
            Self::Mesh => "Mesh messaging",
            Self::Xfer => "XFER file transfer",
        }
    }
}

/// Self-described device metadata. Treat it as a hint in discovery and as a
/// statement by the peer only when received on the authenticated session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerMetadata {
    pub label: String,
    pub platform: String,
    pub capabilities: Vec<PeerCapability>,
}

impl PeerMetadata {
    pub fn local(state: &AppState, owner: &str, fingerprint: &str) -> Self {
        let platform = std::env::consts::OS;
        let platform_label = crate::identity::platform_device_label();
        let label = state
            .load_applock(owner)
            .ok()
            .flatten()
            .map(|lock| lock.device.device_name.trim().to_owned())
            .filter(|label| valid_device_label(label))
            .or_else(|| {
                let identity = state.identity.lock().ok()?;
                let identity = identity
                    .as_ref()
                    .filter(|identity| identity.user_id == owner)?;
                let label = identity.device_label.trim();
                (valid_device_label(label)
                    && label != platform_label
                    && !crate::identity::is_legacy_hardcoded_label(label))
                .then(|| label.to_owned())
            })
            .unwrap_or_else(|| format!("{platform_label} {}", fingerprint.get(..8).unwrap_or("")));
        Self {
            label,
            platform: platform.into(),
            capabilities: vec![PeerCapability::Mesh, PeerCapability::Xfer],
        }
    }

    pub fn validate(&self) -> Result<()> {
        let distinct_capabilities = match self.capabilities.as_slice() {
            [_] => true,
            [first, second] => first != second,
            _ => false,
        };
        if !valid_device_label(&self.label)
            || !PEER_PLATFORMS.contains(&self.platform.as_str())
            || !distinct_capabilities
        {
            return Err(QGuardError::InvalidInput(
                "The peer device information is invalid.".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn valid_device_label(label: &str) -> bool {
    !label.is_empty()
        && label == label.trim()
        && label.len() <= MAX_DEVICE_LABEL_BYTES
        && !label.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

/// The user name a paired device sent after both users confirmed the code.
/// It is presentation data on an authenticated session, never an identifier.
pub(super) fn valid_owner_name(name: &str) -> bool {
    valid_device_label(name)
}

/// Normalize a profile display name for the local pairing statement.
pub(super) fn owner_name(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    let mut end = value.len().min(MAX_DEVICE_LABEL_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let value = value[..end].trim_end();
    valid_owner_name(value).then(|| value.to_owned())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PairedIdentity {
    pub public_key: String,
    pub platform: String,
    /// Capabilities both users approved. Older records stored the advertised
    /// set, which was always both capabilities.
    pub capabilities: Vec<PeerCapability>,
    pub paired_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TrustedPeer {
    pub label: String,
    pub address: Option<SocketAddrV4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<PairedIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The peer's Mesh relay public key, received on an authenticated
    /// session. It lets this device seal messages for the peer end to end
    /// when they can only travel through other devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_key: Option<super::relay::RelayPublic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct BlockedPeer {
    pub previous: Option<TrustedPeer>,
    pub blocked_at: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct TrustBook {
    pub peers: BTreeMap<String, TrustedPeer>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blocked: BTreeMap<String, BlockedPeer>,
    #[serde(default)]
    pub auto_start: bool,
    /// This account's display name, shared with a device only after both
    /// users confirm a pairing code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_owner: Option<String>,
    /// Keep Mesh running while Qguard is locked or in the background
    /// (Android: a visible foreground service). Off until the user turns it on.
    #[serde(default)]
    pub background: bool,
    /// Carry sealed Mesh envelopes for trusted devices (multi-hop relay).
    /// Relays only ever hold ciphertext addressed by an opaque tag.
    #[serde(default = "relay_default")]
    pub relay: bool,
    /// Show this account's picture to nearby Qguard devices before pairing.
    /// Off unless the user turns it on: the picture is then readable by any
    /// nearby Qguard device that asks.
    #[serde(default)]
    pub share_picture_nearby: bool,
}

fn relay_default() -> bool {
    true
}

impl Default for TrustBook {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
            blocked: BTreeMap::new(),
            auto_start: false,
            local_owner: None,
            background: false,
            relay: true,
            share_picture_nearby: false,
        }
    }
}

impl TrustBook {
    pub fn load(state: &AppState, owner: &str) -> Result<Self> {
        let Some(bytes) = state.load_user_secret_doc(owner, TRUST_DOC, TRUST_AAD, TRUST_DOC)?
        else {
            return Ok(Self::default());
        };
        let mut book: Self = serde_json::from_slice(&bytes)
            .map_err(|_| QGuardError::Storage("offline trust records are unreadable".into()))?;
        book.peers
            .retain(|fingerprint, _| !book.blocked.contains_key(fingerprint));
        Ok(book)
    }

    pub fn save(&self, state: &AppState, owner: &str) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| {
            QGuardError::Storage("offline trust records could not be encoded".into())
        })?);
        state.save_user_secret_doc(owner, TRUST_DOC, TRUST_AAD, &bytes, TRUST_DOC)
    }

    pub fn can_pair(&self, fingerprint: &str) -> Result<()> {
        check_fingerprint(fingerprint)?;
        if self.is_blocked(fingerprint) {
            return Err(QGuardError::Trust("This device is blocked.".into()));
        }
        if self.peers.len() >= MAX_TRUSTED && !self.peers.contains_key(fingerprint) {
            return Err(QGuardError::InvalidInput(
                "The trusted device list is full.".into(),
            ));
        }
        Ok(())
    }

    /// Called after the shared pairing protocol validates both confirmations.
    /// `granted` is the capability set both users approved for this pairing.
    /// A later pairing of the same identity can add a capability, never swap
    /// the identity key behind an existing trust record.
    pub fn trust_paired(
        &mut self,
        fingerprint: &str,
        metadata: PeerMetadata,
        identity_public: &[u8],
        address: Option<SocketAddrV4>,
        granted: &[PeerCapability],
        owner: Option<String>,
    ) -> Result<()> {
        self.can_pair(fingerprint)?;
        metadata.validate()?;
        let mut distinct = granted.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        if granted.is_empty()
            || distinct.len() != granted.len()
            || granted
                .iter()
                .any(|capability| !metadata.capabilities.contains(capability))
            || owner.as_deref().is_some_and(|name| !valid_owner_name(name))
        {
            return Err(QGuardError::Trust(
                "The approved pairing capabilities are invalid.".into(),
            ));
        }
        if identity_public.len() != session::ID_BYTES
            || session::fingerprint(identity_public) != fingerprint
        {
            return Err(QGuardError::Trust(
                "The verified device identity does not match its fingerprint.".into(),
            ));
        }
        let previous = self.peers.get(fingerprint);
        let public_key = STANDARD.encode(identity_public);
        if previous
            .and_then(|record| record.paired.as_ref())
            .is_some_and(|identity| identity.public_key != public_key)
        {
            return Err(QGuardError::Trust(
                "The verified identity key does not match the saved device.".into(),
            ));
        }
        let now = Utc::now().timestamp();
        let previous_identity = previous.and_then(|record| record.paired.as_ref());
        let paired_at = previous_identity
            .map(|identity| identity.paired_at)
            .unwrap_or(now);
        let mut capabilities = previous_identity
            .map(|identity| identity.capabilities.clone())
            .unwrap_or_default();
        capabilities.extend_from_slice(&distinct);
        capabilities.sort_unstable();
        capabilities.dedup();
        let owner = owner.or_else(|| previous.and_then(|record| record.owner.clone()));
        let address = address
            .and_then(|value| lan_address(value.into()))
            .or_else(|| previous.and_then(|record| record.address));
        // A re-pairing keeps the relay key: the identity is unchanged.
        let relay_key = previous.and_then(|record| record.relay_key.clone());
        self.peers.insert(
            fingerprint.to_owned(),
            TrustedPeer {
                label: metadata.label,
                address,
                paired: Some(PairedIdentity {
                    public_key,
                    platform: metadata.platform,
                    capabilities,
                    paired_at,
                }),
                last_connected_at: Some(now),
                owner,
                relay_key,
            },
        );
        Ok(())
    }

    /// Mutual pairings authorize only the capabilities both users approved.
    /// Fingerprints pinned before scoped pairing keep their original access.
    pub fn allows(&self, fingerprint: &str, capability: PeerCapability) -> bool {
        !self.is_blocked(fingerprint)
            && self.peers.get(fingerprint).is_some_and(|peer| {
                peer.paired
                    .as_ref()
                    .is_none_or(|identity| identity.capabilities.contains(&capability))
            })
    }

    pub fn require(&self, fingerprint: &str, capability: PeerCapability) -> Result<()> {
        if self.allows(fingerprint, capability) {
            return Ok(());
        }
        if self.is_blocked(fingerprint) || !self.peers.contains_key(fingerprint) {
            return Err(QGuardError::Trust(
                "This device fingerprint is outside the trusted device list.".into(),
            ));
        }
        Err(QGuardError::Trust(format!(
            "This device is not paired for {}. Pair it again and allow {} on both devices.",
            capability.name(),
            capability.name(),
        )))
    }

    pub fn record_connection(&mut self, fingerprint: &str) -> Result<bool> {
        let record = self.peers.get_mut(fingerprint).ok_or_else(|| {
            QGuardError::Trust("This device fingerprint is outside the trusted device list.".into())
        })?;
        let now = Utc::now().timestamp();
        if record.last_connected_at.is_some_and(|last| last >= now) {
            return Ok(false);
        }
        record.last_connected_at = Some(now);
        Ok(true)
    }

    pub fn is_blocked(&self, fingerprint: &str) -> bool {
        self.blocked.contains_key(fingerprint)
    }

    pub fn block(&mut self, fingerprint: &str) -> Result<bool> {
        check_fingerprint(fingerprint)?;
        if self.is_blocked(fingerprint) {
            return Ok(false);
        }
        if self.blocked.len() >= MAX_BLOCKED {
            return Err(QGuardError::InvalidInput(
                "The blocked device list is full. Unblock a device before adding another.".into(),
            ));
        }
        self.blocked.insert(
            fingerprint.into(),
            BlockedPeer {
                previous: self.peers.remove(fingerprint),
                blocked_at: Utc::now().timestamp(),
            },
        );
        Ok(true)
    }

    pub fn unblock(&mut self, fingerprint: &str) -> Result<bool> {
        check_fingerprint(fingerprint)?;
        Ok(self.blocked.remove(fingerprint).is_some())
    }

    pub fn revoke(&mut self, fingerprint: &str) -> Result<bool> {
        check_fingerprint(fingerprint)?;
        Ok(self.peers.remove(fingerprint).is_some())
    }
}

fn check_fingerprint(fingerprint: &str) -> Result<()> {
    if !fingerprint_valid(fingerprint) {
        return Err(QGuardError::InvalidInput(
            "Invalid device fingerprint.".into(),
        ));
    }
    Ok(())
}

pub(super) fn local_owner(state: &AppState) -> Result<String> {
    network_owner(state, false)
}

/// The account a running network may keep serving. With `background`, an
/// Android network the user unlocked keeps serving that same account after
/// Qguard locks (the user turned background Mesh on). The UI and every
/// command that starts new work still need `local_owner`, i.e. an unlock.
pub(super) fn network_owner(state: &AppState, background: bool) -> Result<String> {
    let owner = state.offline_principal.owner(state)?;
    #[cfg(target_os = "android")]
    {
        let same_account = state.load_applock_user_pointer().as_deref() == Some(owner.as_str());
        if !same_account || !(background || state.is_applock_unlocked()) {
            return Err(QGuardError::Trust(
                "Unlock Qguard on this device to use local networking.".into(),
            ));
        }
    }
    #[cfg(not(target_os = "android"))]
    let _ = background;
    Ok(owner)
}

/// Whether the user is in front of an unlocked Qguard. Desktop has no app lock.
pub(super) fn unlocked_in_front(state: &AppState) -> bool {
    #[cfg(target_os = "android")]
    return state.is_applock_unlocked();
    #[cfg(not(target_os = "android"))]
    {
        let _ = state;
        true
    }
}

pub(super) fn xfer_key(state: &AppState, owner: &str) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(bytes) =
        state.load_user_secret_doc(owner, XFER_KEY_DOC, XFER_KEY_AAD, XFER_KEY_DOC)?
    {
        let key = bytes.as_slice().try_into().map_err(|_| {
            QGuardError::Storage("The offline transfer storage key is unreadable.".into())
        })?;
        return Ok(Zeroizing::new(key));
    }
    let key = Zeroizing::new(crate::crypto::provider::random_array());
    state.save_user_secret_doc(
        owner,
        XFER_KEY_DOC,
        XFER_KEY_AAD,
        key.as_ref(),
        XFER_KEY_DOC,
    )?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::provider::{self, MlDsa};

    fn metadata() -> PeerMetadata {
        PeerMetadata {
            label: "A nearby test device".into(),
            platform: "android".into(),
            capabilities: vec![PeerCapability::Mesh, PeerCapability::Xfer],
        }
    }

    fn identity() -> (String, Vec<u8>) {
        let (_, ed_public) = provider::ed25519_generate().unwrap();
        let (pq_public, _) = provider::mldsa_generate(MlDsa::Ml65).unwrap();
        let public = [ed_public.as_slice(), pq_public.as_slice()].concat();
        (session::fingerprint(&public), public)
    }

    const BOTH: [PeerCapability; 2] = [PeerCapability::Mesh, PeerCapability::Xfer];

    fn trust(book: &mut TrustBook, fingerprint: &str, public: &[u8]) -> Result<()> {
        book.trust_paired(fingerprint, metadata(), public, None, &BOTH, None)
    }

    #[test]
    fn pairing_grants_only_the_approved_capabilities_and_can_add_one_later() {
        let mut book = TrustBook::default();
        let (fingerprint, public) = identity();
        for invalid in [
            &[][..],
            &[PeerCapability::Mesh, PeerCapability::Mesh][..],
        ] {
            assert!(book
                .trust_paired(&fingerprint, metadata(), &public, None, invalid, None)
                .is_err());
        }
        let mesh_only = PeerMetadata {
            capabilities: vec![PeerCapability::Mesh],
            ..metadata()
        };
        assert!(book
            .trust_paired(&fingerprint, mesh_only, &public, None, &[PeerCapability::Xfer], None)
            .is_err());
        assert!(book.peers.is_empty());

        book.trust_paired(
            &fingerprint,
            metadata(),
            &public,
            None,
            &[PeerCapability::Mesh],
            Some("Ruel".into()),
        )
        .unwrap();
        assert!(book.allows(&fingerprint, PeerCapability::Mesh));
        assert!(!book.allows(&fingerprint, PeerCapability::Xfer));
        assert!(book.require(&fingerprint, PeerCapability::Xfer).is_err());
        assert_eq!(book.peers[&fingerprint].owner.as_deref(), Some("Ruel"));

        // A second approved pairing adds XFER and keeps the earlier owner name.
        book.trust_paired(&fingerprint, metadata(), &public, None, &[PeerCapability::Xfer], None)
            .unwrap();
        assert!(book.allows(&fingerprint, PeerCapability::Mesh));
        assert!(book.allows(&fingerprint, PeerCapability::Xfer));
        assert_eq!(book.peers[&fingerprint].owner.as_deref(), Some("Ruel"));
        assert!(book
            .trust_paired(
                &fingerprint,
                metadata(),
                &public,
                None,
                &[PeerCapability::Mesh],
                Some("Bad\u{202e}name".into()),
            )
            .is_err());

        book.block(&fingerprint).unwrap();
        assert!(!book.allows(&fingerprint, PeerCapability::Mesh));
        assert!(!book.allows(&"b".repeat(64), PeerCapability::Mesh));
    }

    #[test]
    fn legacy_pins_keep_their_access_and_owner_names_are_normalized() {
        let fingerprint = "a".repeat(64);
        let json = serde_json::json!({
            "peers": { (&fingerprint): {"label": "Old laptop", "address": null} }
        });
        let book: TrustBook = serde_json::from_value(json).unwrap();
        assert!(book.allows(&fingerprint, PeerCapability::Mesh));
        assert!(book.allows(&fingerprint, PeerCapability::Xfer));
        assert_eq!(owner_name(Some("  Ruel Syutan  ")).as_deref(), Some("Ruel Syutan"));
        assert_eq!(owner_name(Some("   ")), None);
        assert_eq!(owner_name(Some("Bad\u{202e}name")), None);
        assert_eq!(owner_name(None), None);
        let long = "\u{00e9}".repeat(80);
        let trimmed = owner_name(Some(&long)).unwrap();
        assert!(trimmed.len() <= MAX_DEVICE_LABEL_BYTES && long.starts_with(&trimmed));
    }

    #[test]
    fn old_pins_preserve_trust_without_inventing_pairing_metadata() {
        let fingerprint = "a".repeat(64);
        let json = serde_json::json!({
            "peers": { (&fingerprint): {"label": "Old laptop", "address": "192.168.1.20:41000"} },
            "auto_start": true
        });
        let book: TrustBook = serde_json::from_value(json).unwrap();
        let peer = &book.peers[&fingerprint];
        assert_eq!(peer.label, "Old laptop");
        assert_eq!(peer.address.unwrap().port(), 41000);
        assert!(peer.paired.is_none());
        assert!(peer.last_connected_at.is_none());
        assert!(book.blocked.is_empty());
        assert!(book.auto_start);
    }

    #[test]
    fn authenticated_metadata_and_identity_are_validated_before_saving_trust() {
        let mut book = TrustBook::default();
        let (fingerprint, public) = identity();
        let (_, other_public) = identity();
        assert!(trust(&mut book, &fingerprint, &other_public).is_err());
        for invalid in [
            PeerMetadata {
                label: "Example\u{202e}device".into(),
                ..metadata()
            },
            PeerMetadata {
                platform: "invalid".into(),
                ..metadata()
            },
            PeerMetadata {
                capabilities: vec![PeerCapability::Xfer; 2],
                ..metadata()
            },
        ] {
            let granted = &invalid.capabilities[..1];
            assert!(book
                .trust_paired(&fingerprint, invalid.clone(), &public, None, granted, None)
                .is_err());
        }
        assert!(book.peers.is_empty());

        let public_route = "198.51.100.25:41000".parse().unwrap();
        book.trust_paired(&fingerprint, metadata(), &public, Some(public_route), &BOTH, None)
            .unwrap();
        assert!(book.peers[&fingerprint].address.is_none());
        let paired = book
            .peers
            .get_mut(&fingerprint)
            .unwrap()
            .paired
            .as_mut()
            .unwrap();
        paired.paired_at = 123;
        trust(&mut book, &fingerprint, &public).unwrap();
        assert_eq!(
            book.peers[&fingerprint].paired.as_ref().unwrap().paired_at,
            123
        );
    }

    #[test]
    fn block_and_revoke_require_fresh_pairing_to_restore_authorization() {
        let mut book = TrustBook::default();
        let (fingerprint, public) = identity();
        trust(&mut book, &fingerprint, &public).unwrap();
        assert!(book.block(&fingerprint).unwrap());
        assert!(!book.block(&fingerprint).unwrap());
        assert!(book.is_blocked(&fingerprint));
        assert!(book.blocked[&fingerprint].previous.is_some());
        assert!(!book.peers.contains_key(&fingerprint));
        assert!(trust(&mut book, &fingerprint, &public).is_err());
        assert!(book.unblock(&fingerprint).unwrap());
        assert!(!book.unblock(&fingerprint).unwrap());
        assert!(book.record_connection(&fingerprint).is_err());
        trust(&mut book, &fingerprint, &public).unwrap();
        book.peers.get_mut(&fingerprint).unwrap().last_connected_at = Some(1);
        assert!(book.record_connection(&fingerprint).unwrap());
        assert!(book.peers[&fingerprint].last_connected_at.unwrap() > 1);
        assert!(book.revoke(&fingerprint).unwrap());
        assert!(!book.revoke(&fingerprint).unwrap());
        assert!(book.record_connection(&fingerprint).is_err());
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn protected_registry_survives_restart_and_stays_account_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let owner = uuid::Uuid::new_v4().to_string();
        let other = uuid::Uuid::new_v4().to_string();
        let (fingerprint, public) = identity();
        let (blocked, blocked_key) = identity();
        let state = AppState::new(dir.path().to_owned()).unwrap();
        let mut book = TrustBook::default();
        book.local_owner = Some("Local owner".into());
        book.trust_paired(
            &fingerprint,
            metadata(),
            &public,
            None,
            &BOTH,
            Some("Remote owner".into()),
        )
        .unwrap();
        trust(&mut book, &blocked, &blocked_key).unwrap();
        book.block(&blocked).unwrap();
        book.save(&state, &owner).unwrap();
        drop(state);

        let state = AppState::new(dir.path().to_owned()).unwrap();
        let loaded = TrustBook::load(&state, &owner);
        let isolated = TrustBook::load(&state, &other);
        crate::security::keystore::delete_secret(&AppState::safe_user_key(&owner), dir.path())
            .unwrap();

        let loaded = loaded.unwrap();
        let peer = &loaded.peers[&fingerprint];
        let paired = peer.paired.as_ref().unwrap();
        assert_eq!(STANDARD.decode(&paired.public_key).unwrap(), public);
        assert_eq!(paired.capabilities, metadata().capabilities);
        assert_eq!(peer.owner.as_deref(), Some("Remote owner"));
        assert_eq!(loaded.local_owner.as_deref(), Some("Local owner"));
        assert!(peer.last_connected_at.is_some());
        assert!(loaded.is_blocked(&blocked));
        assert!(!loaded.peers.contains_key(&blocked));
        let isolated = isolated.unwrap();
        assert!(isolated.peers.is_empty() && isolated.blocked.is_empty());
    }
}
