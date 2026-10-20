//! Device pins: this device's own record of which devices belong to whom.
//!
//! WHY THIS EXISTS
//! ---------------------------------------------------------------------------
//! The relay is the device directory. To send to someone, the app asks the
//! relay for their devices and seals a copy of the message to each one; to
//! check a signature, it asks the relay for the sender device's identity keys.
//! Every one of those rows is checked for self-consistency (its dual signature
//! binds its keys together) — and that is all. A row the relay invents is
//! perfectly self-consistent.
//!
//! So whoever controls the relay could add a device to any account, and from
//! then on:
//!   * every new message to that person was also sealed to the added device;
//!   * history was RE-SEALED to it automatically (trusted-device sync fills in
//!     any listed device that lacks a copy);
//!   * messages signed by it were displayed as verified messages from that
//!     person.
//! Nothing on screen changed. The directory was believed on every use.
//!
//! WHAT THE PINS DO
//! ---------------------------------------------------------------------------
//! The first time a person's devices are seen, they are recorded here (trust on
//! first use). After that, a device that is not in the record is NEW: nothing
//! is sealed to it and nothing from it is shown as verified until the user
//! approves it on this device. A device id that reappears with DIFFERENT
//! identity keys is never accepted — a legitimate re-key always registers a new
//! device id.
//!
//! What this does not do: it cannot tell whether the devices present at first
//! use were genuine (compare safety numbers for that), and it protects against
//! a dishonest directory, not against someone with access to this device's
//! storage.
//!
//! The record is encrypted at rest under the device storage key, like the rest
//! of the key material.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::kdf::sha3_hex;
use crate::error::{QGuardError, Result};

/// How a device stands against the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStanding {
    /// Recorded, with the same identity keys.
    Pinned,
    /// Not in the record of a person whose devices have been seen before.
    New,
    /// Recorded under this device id with different identity keys.
    KeyChanged,
}

/// How a pin came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinSource {
    /// Present the first time this person's devices were seen.
    FirstUse,
    /// Approved by the user on this device.
    Approved,
    /// This device itself.
    ThisDevice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePin {
    /// SHA3-256 over all four identity public keys (see [`identity_digest`]).
    pub digest: String,
    pub pinned_at: i64,
    pub source: PinSource,
    /// The user compared this device's safety number with its owner and said
    /// it matched — in THIS app, on THIS device. Never set from anything the
    /// relay says. Bound to `digest`: it means nothing for other keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<UserVerification>,
    /// Call-pairing halves exchanged with this device (see
    /// `commands::contact_verification`). Secrets: encrypted at rest with the
    /// rest of the record, never logged, never sent anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<Pairing>,
}

/// How the user verified a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Safety numbers compared (read aloud, or over another trusted channel).
    SafetyNumber,
    /// The QR code was scanned in person.
    QrCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserVerification {
    pub at: i64,
    pub method: VerificationMethod,
}

/// One device's half of a call-pairing secret: the hybrid shared secret of an
/// offer one side sealed to the other's verified identity keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingHalf {
    /// The offer's id; replays are judged by it and by `created_at`.
    pub offer_id: String,
    pub created_at: i64,
    pub secret: [u8; 32],
}

impl Drop for PairingHalf {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

impl std::fmt::Debug for PairingHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingHalf")
            .field("offer_id", &self.offer_id)
            .field("created_at", &self.created_at)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pairing {
    /// The half this device sealed to the other one.
    #[serde(default)]
    pub sent: Option<PairingHalf>,
    /// The half the other device sealed to this one.
    #[serde(default)]
    pub received: Option<PairingHalf>,
}

/// What can be said about a device's verification, without any secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VerificationView {
    pub verified: Option<UserVerification>,
    pub sent: bool,
    pub received: bool,
}

impl VerificationView {
    /// A call phrase can be shown: verified here, and both halves held.
    pub fn paired(&self) -> bool {
        self.verified.is_some() && self.sent && self.received
    }
}

/// What became of a received pairing half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfReceived {
    Stored,
    /// This exact offer was already stored (a repeat delivery).
    AlreadyHeld,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct UserPins {
    /// When this person's devices were first recorded.
    first_seen_at: i64,
    devices: HashMap<String, DevicePin>,
}

#[derive(Serialize, Deserialize)]
struct PinFile {
    version: u8,
    users: HashMap<String, UserPins>,
}

/// One device's identity, reduced to what a pin compares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinSubject {
    pub user_id: String,
    pub device_id: String,
    pub digest: String,
}

/// A digest of a device's four identity public keys.
///
/// All four, length-prefixed: the signing keys are what authenticate the
/// device, and the KEM keys are what messages are sealed to — changing either
/// pair is a different device as far as a pin is concerned.
pub fn identity_digest(
    ed25519_public: &[u8],
    mldsa_public: &[u8],
    x25519_public: &[u8],
    mlkem_public: &[u8],
) -> String {
    let mut material = Vec::with_capacity(
        ed25519_public.len() + mldsa_public.len() + x25519_public.len() + mlkem_public.len() + 40,
    );
    material.extend_from_slice(b"QGuard-Device-Pin-v1");
    for part in [ed25519_public, mldsa_public, x25519_public, mlkem_public] {
        material.extend_from_slice(&(part.len() as u32).to_be_bytes());
        material.extend_from_slice(part);
    }
    sha3_hex(&material)
}

pub struct DevicePinBook {
    owner: Option<String>,
    /// False when a stored record exists but could not be opened. Such a book
    /// answers nothing and is never written: treating it as empty would
    /// silently re-record whatever the directory lists right now as trusted.
    available: bool,
    retry_after: i64,
    users: HashMap<String, UserPins>,
    dirty: bool,
}

impl Default for DevicePinBook {
    fn default() -> Self {
        Self {
            owner: None,
            available: false,
            retry_after: 0,
            users: HashMap::new(),
            dirty: false,
        }
    }
}

impl DevicePinBook {
    pub fn empty(owner: &str) -> Self {
        Self {
            owner: Some(owner.to_string()),
            available: true,
            ..Self::default()
        }
    }

    pub fn unavailable(owner: &str, retry_after: i64) -> Self {
        Self {
            owner: Some(owner.to_string()),
            available: false,
            retry_after,
            ..Self::default()
        }
    }

    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn should_retry_load(&self, now: i64) -> bool {
        !self.available && now >= self.retry_after
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    /// Whether this person's devices have been recorded before.
    pub fn knows_user(&self, user_id: &str) -> bool {
        self.available && self.users.contains_key(user_id)
    }

    pub fn pin(&self, user_id: &str, device_id: &str) -> Option<&DevicePin> {
        if !self.available {
            return None;
        }
        self.users.get(user_id)?.devices.get(device_id)
    }

    /// How `subject` stands. `None` means there is nothing to judge it against:
    /// the book is unavailable, or this person has never been recorded.
    pub fn standing(&self, subject: &PinSubject) -> Option<DeviceStanding> {
        if !self.available {
            return None;
        }
        let user = self.users.get(&subject.user_id)?;
        Some(match user.devices.get(&subject.device_id) {
            Some(pin) if pin.digest == subject.digest => DeviceStanding::Pinned,
            Some(_) => DeviceStanding::KeyChanged,
            None => DeviceStanding::New,
        })
    }

    /// Record this device itself. Always allowed: it is the one device whose
    /// keys did not come from the directory.
    pub fn pin_this_device(&mut self, subject: &PinSubject, now: i64) {
        if !self.available {
            return;
        }
        let user = self.users.entry(subject.user_id.clone()).or_insert_with(|| UserPins {
            first_seen_at: now,
            devices: HashMap::new(),
        });
        let current = user.devices.get(&subject.device_id);
        if current.is_some_and(|pin| pin.digest == subject.digest && pin.source == PinSource::ThisDevice) {
            return;
        }
        user.devices.insert(
            subject.device_id.clone(),
            DevicePin {
                digest: subject.digest.clone(),
                pinned_at: now,
                source: PinSource::ThisDevice,
                verified: None,
                pairing: None,
            },
        );
        self.dirty = true;
    }

    /// Judge a set of devices, recording the ones that establish first use.
    ///
    /// `subjects` should be EVERY device currently listed for the people in it:
    /// for a person never seen before, all of their listed devices become the
    /// first-use record, so a partial list would make the rest look new later.
    /// For a person already recorded, nothing is added — new devices are
    /// reported as [`DeviceStanding::New`] and stay that way until approved.
    pub fn assess(&mut self, subjects: &[PinSubject], now: i64) -> Vec<Option<DeviceStanding>> {
        if !self.available {
            return vec![None; subjects.len()];
        }
        let first_use: Vec<String> = subjects
            .iter()
            .map(|subject| subject.user_id.clone())
            .filter(|user_id| !self.users.contains_key(user_id))
            .collect();
        for subject in subjects {
            if !first_use.contains(&subject.user_id) {
                continue;
            }
            let user = self.users.entry(subject.user_id.clone()).or_insert_with(|| UserPins {
                first_seen_at: now,
                devices: HashMap::new(),
            });
            // Two listed rows with one device id and different keys: the first
            // is recorded, and the second then reads as a key change below.
            user.devices.entry(subject.device_id.clone()).or_insert_with(|| DevicePin {
                digest: subject.digest.clone(),
                pinned_at: now,
                source: PinSource::FirstUse,
                verified: None,
                pairing: None,
            });
            self.dirty = true;
        }
        let standings: Vec<Option<DeviceStanding>> = subjects.iter().map(|subject| self.standing(subject)).collect();
        // A device presenting different keys is not the device the user
        // verified: the verification and any call pairing go now, so neither
        // can be carried over to whoever holds the new keys.
        for (subject, standing) in subjects.iter().zip(&standings) {
            if *standing == Some(DeviceStanding::KeyChanged) {
                self.clear_verification_for(&subject.user_id, &subject.device_id);
            }
        }
        standings
    }

    fn clear_verification_for(&mut self, user_id: &str, device_id: &str) -> bool {
        let Some(pin) = self.users.get_mut(user_id).and_then(|user| user.devices.get_mut(device_id)) else {
            return false;
        };
        if pin.verified.is_none() && pin.pairing.is_none() {
            return false;
        }
        pin.verified = None;
        pin.pairing = None;
        self.dirty = true;
        true
    }

    /// The pin for `subject` if, and only if, its keys are the recorded ones.
    fn pinned_mut(&mut self, subject: &PinSubject) -> Result<&mut DevicePin> {
        if !self.available {
            return Err(QGuardError::Storage(
                "the device record on this device could not be opened right now".to_string(),
            ));
        }
        match self.standing(subject) {
            Some(DeviceStanding::Pinned) => {}
            Some(DeviceStanding::KeyChanged) => {
                return Err(QGuardError::Trust(format!(
                    "device {} is presenting different identity keys than the ones recorded for it",
                    subject.device_id
                )))
            }
            Some(DeviceStanding::New) | None => {
                return Err(QGuardError::Trust(format!(
                    "device {} is not one this device has recorded or approved",
                    subject.device_id
                )))
            }
        }
        self.users
            .get_mut(&subject.user_id)
            .and_then(|user| user.devices.get_mut(&subject.device_id))
            .ok_or_else(|| QGuardError::NotFound("device pin".to_string()))
    }

    /// What is known about the user's verification of `subject`. `None` when
    /// its keys are not the recorded ones (or nothing is recorded).
    pub fn verification(&self, subject: &PinSubject) -> Option<VerificationView> {
        if self.standing(subject) != Some(DeviceStanding::Pinned) {
            return None;
        }
        let pin = self.pin(&subject.user_id, &subject.device_id)?;
        Some(Self::view_of(pin))
    }

    /// The same, by ids alone — for a call, whose setup has already checked
    /// the keys against this record. A pairing secret only exists for the keys
    /// it was made with, so this can never vouch for anyone else.
    pub fn verification_by_id(&self, user_id: &str, device_id: &str) -> Option<VerificationView> {
        self.pin(user_id, device_id).map(Self::view_of)
    }

    fn view_of(pin: &DevicePin) -> VerificationView {
        let pairing = pin.pairing.as_ref();
        VerificationView {
            verified: pin.verified,
            sent: pairing.is_some_and(|pairing| pairing.sent.is_some()),
            received: pairing.is_some_and(|pairing| pairing.received.is_some()),
        }
    }

    /// Record that the user verified `subject` here. Only a device whose keys
    /// are the recorded ones can be verified.
    pub fn mark_verified(&mut self, subject: &PinSubject, method: VerificationMethod, now: i64) -> Result<()> {
        let pin = self.pinned_mut(subject)?;
        pin.verified = Some(UserVerification { at: now, method });
        self.dirty = true;
        Ok(())
    }

    /// Withdraw the user's verification. The pairing goes with it: it is
    /// re-made after the device is verified again.
    pub fn clear_verification(&mut self, subject: &PinSubject) -> bool {
        if self.standing(subject) != Some(DeviceStanding::Pinned) {
            return false;
        }
        self.clear_verification_for(&subject.user_id, &subject.device_id)
    }

    /// Store this device's half, just sealed to `subject`. Requires the user's
    /// verification: nothing is paired with a device the user has not checked.
    pub fn record_sent_half(&mut self, subject: &PinSubject, half: PairingHalf) -> Result<()> {
        let pin = self.pinned_mut(subject)?;
        if pin.verified.is_none() {
            return Err(QGuardError::Trust(format!(
                "device {} has not been verified on this device, so no call pairing is made with it",
                subject.device_id
            )));
        }
        pin.pairing.get_or_insert_with(Pairing::default).sent = Some(half);
        self.dirty = true;
        Ok(())
    }

    /// Store the half `subject` sealed to this device. Accepted from a device
    /// whose keys are the recorded ones even before the user verifies it — it
    /// is USED only once they do. An older or same-time offer under another id
    /// is a replay and is refused.
    pub fn record_received_half(&mut self, subject: &PinSubject, half: PairingHalf) -> Result<HalfReceived> {
        let pin = self.pinned_mut(subject)?;
        let pairing = pin.pairing.get_or_insert_with(Pairing::default);
        if let Some(existing) = pairing.received.as_ref() {
            if existing.offer_id == half.offer_id {
                return Ok(HalfReceived::AlreadyHeld);
            }
            if half.created_at <= existing.created_at {
                return Err(QGuardError::Replay(
                    "this call-pairing offer is older than the one already held; refusing it".to_string(),
                ));
            }
        }
        pairing.received = Some(half);
        self.dirty = true;
        Ok(HalfReceived::Stored)
    }

    /// Both halves, when the user has verified the device. By ids, for the
    /// reason given on [`Self::verification_by_id`].
    pub fn pairing_halves(&self, user_id: &str, device_id: &str) -> Option<(PairingHalf, PairingHalf)> {
        let pin = self.pin(user_id, device_id)?;
        pin.verified?;
        let pairing = pin.pairing.as_ref()?;
        Some((pairing.sent.clone()?, pairing.received.clone()?))
    }

    /// Record a device the user has approved. Only a NEW device can be
    /// approved; a key change cannot be approved away.
    pub fn approve(&mut self, subject: &PinSubject, now: i64) -> Result<()> {
        if !self.available {
            return Err(QGuardError::Storage(
                "the device record on this device could not be opened, so nothing can be approved right now"
                    .to_string(),
            ));
        }
        match self.standing(subject) {
            Some(DeviceStanding::Pinned) => Ok(()),
            Some(DeviceStanding::KeyChanged) => Err(QGuardError::Trust(format!(
                "device {} is presenting different identity keys than the ones recorded for it; it cannot be approved",
                subject.device_id
            ))),
            Some(DeviceStanding::New) | None => {
                let user = self.users.entry(subject.user_id.clone()).or_insert_with(|| UserPins {
                    first_seen_at: now,
                    devices: HashMap::new(),
                });
                user.devices.insert(
                    subject.device_id.clone(),
                    DevicePin {
                        digest: subject.digest.clone(),
                        pinned_at: now,
                        source: PinSource::Approved,
                        verified: None,
                        pairing: None,
                    },
                );
                self.dirty = true;
                Ok(())
            }
        }
    }

    /// Drop a device from the record (it was revoked or removed). If it shows
    /// up again it is NEW, not silently trusted.
    pub fn forget_device(&mut self, user_id: &str, device_id: &str) -> bool {
        if !self.available {
            return false;
        }
        let removed = self
            .users
            .get_mut(user_id)
            .is_some_and(|user| user.devices.remove(device_id).is_some());
        if removed {
            self.dirty = true;
        }
        removed
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&PinFile {
            version: 1,
            users: self.users.clone(),
        })
        .map_err(|e| QGuardError::Storage(format!("encode device record: {e}")))
    }

    pub fn decode(owner: &str, bytes: &[u8]) -> Result<Self> {
        let file: PinFile = serde_json::from_slice(bytes)
            .map_err(|e| QGuardError::Storage(format!("decode device record: {e}")))?;
        if file.version != 1 {
            return Err(QGuardError::Storage(format!(
                "unsupported device record version {}",
                file.version
            )));
        }
        Ok(Self {
            owner: Some(owner.to_string()),
            available: true,
            retry_after: 0,
            users: file.users,
            dirty: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn subject(user: &str, device: &str, keys: &str) -> PinSubject {
        PinSubject {
            user_id: user.to_string(),
            device_id: device.to_string(),
            digest: identity_digest(keys.as_bytes(), b"mldsa", b"x25519", b"mlkem"),
        }
    }

    #[test]
    fn first_use_records_every_listed_device_and_reports_them_pinned() {
        let mut book = DevicePinBook::empty("me");
        let listed = [subject("ana", "phone", "k1"), subject("ana", "laptop", "k2")];
        assert_eq!(
            book.assess(&listed, NOW),
            vec![Some(DeviceStanding::Pinned), Some(DeviceStanding::Pinned)]
        );
        assert!(book.is_dirty());
        assert_eq!(book.pin("ana", "phone").unwrap().source, PinSource::FirstUse);
        assert!(book.knows_user("ana"));
    }

    #[test]
    fn a_device_added_later_is_new_until_approved() {
        let mut book = DevicePinBook::empty("me");
        book.assess(&[subject("ana", "phone", "k1")], NOW);

        // The directory now lists a second device for the same person.
        let added = subject("ana", "tablet", "k9");
        let standings = book.assess(&[subject("ana", "phone", "k1"), added.clone()], NOW + 60);
        assert_eq!(standings, vec![Some(DeviceStanding::Pinned), Some(DeviceStanding::New)]);
        // Assessing again does not quietly accept it.
        assert_eq!(book.assess(&[added.clone()], NOW + 120), vec![Some(DeviceStanding::New)]);
        assert!(book.pin("ana", "tablet").is_none());

        book.approve(&added, NOW + 180).unwrap();
        assert_eq!(book.standing(&added), Some(DeviceStanding::Pinned));
        assert_eq!(book.pin("ana", "tablet").unwrap().source, PinSource::Approved);
    }

    #[test]
    fn the_same_device_id_with_different_keys_is_never_accepted() {
        let mut book = DevicePinBook::empty("me");
        book.assess(&[subject("ana", "phone", "k1")], NOW);

        let swapped = subject("ana", "phone", "attacker-keys");
        assert_eq!(book.assess(&[swapped.clone()], NOW + 60), vec![Some(DeviceStanding::KeyChanged)]);
        let error = book.approve(&swapped, NOW + 120).unwrap_err();
        assert!(matches!(error, QGuardError::Trust(_)), "{error}");
        // The original keys still stand.
        assert_eq!(book.standing(&subject("ana", "phone", "k1")), Some(DeviceStanding::Pinned));
    }

    #[test]
    fn people_are_recorded_independently() {
        let mut book = DevicePinBook::empty("me");
        book.assess(&[subject("ana", "phone", "k1")], NOW);
        // Ben is seen for the first time later: his devices are first use,
        // while Ana's new device in the same batch is still new.
        let standings = book.assess(
            &[subject("ben", "phone", "b1"), subject("ana", "tablet", "k9")],
            NOW + 60,
        );
        assert_eq!(standings, vec![Some(DeviceStanding::Pinned), Some(DeviceStanding::New)]);
        // The same device id under another person is unrelated.
        assert_eq!(book.standing(&subject("ben", "tablet", "k9")), Some(DeviceStanding::New));
    }

    #[test]
    fn duplicate_rows_for_one_device_id_cannot_both_be_first_use() {
        let mut book = DevicePinBook::empty("me");
        let standings = book.assess(
            &[subject("ana", "phone", "k1"), subject("ana", "phone", "other")],
            NOW,
        );
        assert_eq!(standings, vec![Some(DeviceStanding::Pinned), Some(DeviceStanding::KeyChanged)]);
    }

    #[test]
    fn nobody_is_judged_before_they_have_been_seen() {
        let book = DevicePinBook::empty("me");
        assert_eq!(book.standing(&subject("ana", "phone", "k1")), None);
        assert!(!book.knows_user("ana"));
    }

    #[test]
    fn this_device_is_always_pinned_and_does_not_make_the_rest_first_use() {
        let mut book = DevicePinBook::empty("me");
        let this = subject("me", "this-device", "mine");
        book.pin_this_device(&this, NOW);
        assert_eq!(book.standing(&this), Some(DeviceStanding::Pinned));
        assert_eq!(book.pin("me", "this-device").unwrap().source, PinSource::ThisDevice);

        // Another device on my own account is NOT covered by first use: my own
        // account already has a record (this device), so it needs approval.
        let other = subject("me", "other-device", "theirs");
        assert_eq!(book.assess(&[this.clone(), other.clone()], NOW + 60), vec![
            Some(DeviceStanding::Pinned),
            Some(DeviceStanding::New),
        ]);

        // Recording this device again changes nothing.
        book.mark_saved();
        book.pin_this_device(&this, NOW + 120);
        assert!(!book.is_dirty());
    }

    #[test]
    fn a_forgotten_device_comes_back_as_new() {
        let mut book = DevicePinBook::empty("me");
        let phone = subject("ana", "phone", "k1");
        book.assess(&[phone.clone(), subject("ana", "laptop", "k2")], NOW);
        assert!(book.forget_device("ana", "phone"));
        assert!(!book.forget_device("ana", "phone"));
        assert_eq!(book.standing(&phone), Some(DeviceStanding::New));
    }

    #[test]
    fn an_unavailable_book_answers_nothing_and_records_nothing() {
        let mut book = DevicePinBook::unavailable("me", NOW + 60);
        let phone = subject("ana", "phone", "k1");
        assert_eq!(book.assess(&[phone.clone()], NOW), vec![None]);
        assert_eq!(book.standing(&phone), None);
        assert!(book.approve(&phone, NOW).is_err());
        book.pin_this_device(&phone, NOW);
        assert!(!book.is_dirty());
        assert!(!book.knows_user("ana"));
        assert!(!book.should_retry_load(NOW));
        assert!(book.should_retry_load(NOW + 60));
    }

    #[test]
    fn the_record_survives_a_round_trip() {
        let mut book = DevicePinBook::empty("me");
        let phone = subject("ana", "phone", "k1");
        let tablet = subject("ana", "tablet", "k9");
        book.assess(&[phone.clone()], NOW);
        book.approve(&tablet, NOW + 60).unwrap();

        let restored = DevicePinBook::decode("me", &book.encode().unwrap()).unwrap();
        assert!(restored.is_available());
        assert!(!restored.is_dirty());
        assert_eq!(restored.owner(), Some("me"));
        assert_eq!(restored.standing(&phone), Some(DeviceStanding::Pinned));
        assert_eq!(restored.standing(&tablet), Some(DeviceStanding::Pinned));
        assert_eq!(restored.standing(&subject("ana", "tablet", "other")), Some(DeviceStanding::KeyChanged));
        assert_eq!(restored.pin("ana", "tablet"), book.pin("ana", "tablet"));

        assert!(DevicePinBook::decode("me", b"not json").is_err());
        assert!(DevicePinBook::decode("me", br#"{"version":9,"users":{}}"#).is_err());
    }

    fn half(id: &str, at: i64, byte: u8) -> PairingHalf {
        PairingHalf { offer_id: id.to_string(), created_at: at, secret: [byte; 32] }
    }

    #[test]
    fn verification_is_only_for_recorded_keys_and_goes_when_they_change() {
        let mut book = DevicePinBook::empty("me");
        let phone = subject("ana", "phone", "k1");
        book.assess(&[phone.clone()], NOW);
        assert_eq!(book.verification(&phone).unwrap().verified, None);

        book.mark_verified(&phone, VerificationMethod::SafetyNumber, NOW + 10).unwrap();
        assert_eq!(book.verification(&phone).unwrap().verified.unwrap().at, NOW + 10);
        book.record_sent_half(&phone, half("o1", NOW + 11, 1)).unwrap();
        book.record_received_half(&phone, half("o2", NOW + 12, 2)).unwrap();
        assert!(book.verification(&phone).unwrap().paired());
        assert!(book.pairing_halves("ana", "phone").is_some());

        // Negative controls: other keys under the same id, a new device, nobody.
        let swapped = subject("ana", "phone", "attacker");
        assert!(book.verification(&swapped).is_none());
        assert!(book.mark_verified(&swapped, VerificationMethod::QrCode, NOW).is_err());
        assert!(book.mark_verified(&subject("ana", "tablet", "k9"), VerificationMethod::QrCode, NOW).is_err());
        assert!(book.mark_verified(&subject("zed", "phone", "z"), VerificationMethod::QrCode, NOW).is_err());

        // The directory presents other keys for the phone: verification and
        // pairing are destroyed, even though the old keys could come back.
        assert_eq!(book.assess(&[swapped], NOW + 20), vec![Some(DeviceStanding::KeyChanged)]);
        let view = book.verification(&phone).unwrap();
        assert_eq!(view.verified, None);
        assert!(!view.sent && !view.received);
        assert!(book.pairing_halves("ana", "phone").is_none());
    }

    #[test]
    fn pairing_needs_the_users_verification_and_refuses_replays() {
        let mut book = DevicePinBook::empty("me");
        let phone = subject("ana", "phone", "k1");
        book.assess(&[phone.clone()], NOW);
        // Not verified: our half is refused, theirs is held but not usable.
        assert!(book.record_sent_half(&phone, half("o1", NOW, 1)).is_err());
        assert_eq!(book.record_received_half(&phone, half("t1", NOW + 5, 2)).unwrap(), HalfReceived::Stored);
        assert!(book.pairing_halves("ana", "phone").is_none());
        assert!(!book.verification(&phone).unwrap().paired());

        // The same offer again is harmless; an older or equal-time one is a replay.
        assert_eq!(book.record_received_half(&phone, half("t1", NOW + 5, 2)).unwrap(), HalfReceived::AlreadyHeld);
        assert!(matches!(book.record_received_half(&phone, half("t0", NOW + 4, 9)), Err(QGuardError::Replay(_))));
        assert!(matches!(book.record_received_half(&phone, half("t9", NOW + 5, 9)), Err(QGuardError::Replay(_))));
        // A newer one replaces it.
        assert_eq!(book.record_received_half(&phone, half("t2", NOW + 6, 3)).unwrap(), HalfReceived::Stored);

        book.mark_verified(&phone, VerificationMethod::QrCode, NOW + 7).unwrap();
        book.record_sent_half(&phone, half("o1", NOW + 8, 1)).unwrap();
        let (sent, received) = book.pairing_halves("ana", "phone").unwrap();
        assert_eq!((sent.secret[0], received.secret[0]), (1, 3));

        // Withdrawing the verification removes the pairing too.
        assert!(book.clear_verification(&phone));
        assert!(book.pairing_halves("ana", "phone").is_none());
        // And from an unrecorded device nothing is stored at all.
        assert!(book.record_received_half(&subject("ana", "tablet", "k9"), half("x", NOW, 1)).is_err());
    }

    #[test]
    fn verification_survives_the_round_trip_and_revocation_removes_it() {
        let mut book = DevicePinBook::empty("me");
        let phone = subject("ana", "phone", "k1");
        book.assess(&[phone.clone()], NOW);
        book.mark_verified(&phone, VerificationMethod::SafetyNumber, NOW).unwrap();
        book.record_sent_half(&phone, half("o1", NOW, 1)).unwrap();
        book.record_received_half(&phone, half("t1", NOW, 2)).unwrap();
        let restored = DevicePinBook::decode("me", &book.encode().unwrap()).unwrap();
        assert!(restored.verification(&phone).unwrap().paired());
        // Debug output never carries a secret.
        assert!(!format!("{:?}", restored.pin("ana", "phone")).contains("[1, 1"));

        assert!(book.forget_device("ana", "phone"));
        assert!(book.verification_by_id("ana", "phone").is_none());
        // Pins written before verification existed still decode.
        let old = br#"{"version":1,"users":{"ana":{"first_seen_at":1,"devices":{"phone":{"digest":"d","pinned_at":1,"source":"first_use"}}}}}"#;
        let old = DevicePinBook::decode("me", old).unwrap();
        assert_eq!(old.verification_by_id("ana", "phone").unwrap().verified, None);
    }

    #[test]
    fn the_digest_covers_every_key_and_cannot_be_reshuffled() {
        let base = identity_digest(b"ed", b"mldsa", b"x", b"mlkem");
        assert_ne!(base, identity_digest(b"ed2", b"mldsa", b"x", b"mlkem"));
        assert_ne!(base, identity_digest(b"ed", b"mldsa2", b"x", b"mlkem"));
        assert_ne!(base, identity_digest(b"ed", b"mldsa", b"x2", b"mlkem"));
        assert_ne!(base, identity_digest(b"ed", b"mldsa", b"x", b"mlkem2"));
        // Moving a byte across a field boundary must change the digest.
        assert_ne!(
            identity_digest(b"ab", b"c", b"x", b"mlkem"),
            identity_digest(b"a", b"bc", b"x", b"mlkem"),
        );
        assert_eq!(base, identity_digest(b"ed", b"mldsa", b"x", b"mlkem"));
    }
}
