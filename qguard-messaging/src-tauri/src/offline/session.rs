//! Pinned, mutually authenticated local sessions. The fixed version/suite and
//! both ephemeral shares are included in both signatures and the key schedule.
//! This protocol uses the QHCE provider and needs independent review before release.

use std::time::Duration;

use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::TcpStream,
    sync::watch,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::{
    crypto::provider::{self, MlDsa},
    error::{QGuardError, Result},
    state::AppState,
};

pub(super) const DOC: &str = "offline-identity";
const IDENTITY_AAD: &[u8] = b"QGuard-Offline-Identity-Seal-v1";
const WIRE: &[u8] = b"QGLN\x01\x01"; // protocol version 1, suite 1
const HELLO: u8 = 1;
const REPLY: u8 = 2;
const FINISH: u8 = 3;
const PAIRING_HELLO: u8 = 4;
const HEADER: usize = WIRE.len() + 1;
const PQ_SIGNATURE: MlDsa = MlDsa::Ml65;
pub(super) const ID_BYTES: usize = 32 + PQ_SIGNATURE.public_key_bytes();
const SIGNATURE_BYTES: usize = 64 + PQ_SIGNATURE.signature_bytes();
const ID_RECORD_BYTES: usize = ID_BYTES + PQ_SIGNATURE.secret_key_bytes();
const EPHEMERAL_OFFSET: usize = HEADER + ID_BYTES + 32;
const SHARE_OFFSET: usize = EPHEMERAL_OFFSET + 32;
const HELLO_BYTES: usize = SHARE_OFFSET + provider::MLKEM768_PUBLIC_KEY_BYTES;
const REPLY_BODY_BYTES: usize = SHARE_OFFSET + provider::MLKEM768_CIPHERTEXT_BYTES;
const REPLY_BYTES: usize = REPLY_BODY_BYTES + SIGNATURE_BYTES;
const FINISH_BYTES: usize = HEADER + SIGNATURE_BYTES;
const MAX_PAYLOAD: usize = super::xfer::CHUNK_SIZE as usize + 1;
const PAIRING_MAX_PAYLOAD: usize = 2048;
const FRAME_HEAD: usize = 8 + provider::AES_GCM_NONCE_BYTES;
const FRAME_OVERHEAD: usize = FRAME_HEAD + provider::AES_GCM_TAG_BYTES;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const BLE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);

/// Description of the only authenticated LAN suite accepted by WIRE v1.
/// The digest covers file integrity independently of session authentication.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransferSuite {
    pub mode: &'static str,
    pub key_establishment: &'static str,
    pub signatures: &'static str,
    pub encryption: &'static str,
    pub integrity: &'static str,
}

pub(super) const TRANSFER_SUITE_V1: TransferSuite = TransferSuite {
    mode: "Hybrid",
    key_establishment: "ML-KEM-768 + X25519",
    signatures: "ML-DSA-65 + Ed25519",
    encryption: "AES-256-GCM",
    integrity: "SHA3-256",
};

const TIMEOUT_MESSAGE: &str = "The local peer did not respond before the connection deadline.";
const HANDSHAKE_MESSAGE: &str = "Local session version, suite, or key confirmation failed.";

pub(super) fn is_timeout(error: &QGuardError) -> bool {
    matches!(error, QGuardError::Storage(message) if message == TIMEOUT_MESSAGE)
}

pub(super) fn is_handshake_failure(error: &QGuardError) -> bool {
    matches!(error, QGuardError::Crypto(_))
        || matches!(error, QGuardError::Trust(message) if message == HANDSHAKE_MESSAGE)
}

trait SessionStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SessionStream for T {}
type Stream = Box<dyn SessionStream>;

#[derive(Clone, Copy)]
struct Limits {
    max_payload: usize,
    io_timeout: Duration,
    bluetooth: bool,
}

const LAN_LIMITS: Limits = Limits {
    max_payload: MAX_PAYLOAD,
    io_timeout: IO_TIMEOUT,
    bluetooth: false,
};
const BLE_LIMITS: Limits = Limits {
    // A 4 KiB message can expand sixfold when JSON escapes control bytes.
    max_payload: 32 * 1024,
    io_timeout: Duration::from_secs(90),
    bluetooth: true,
};

pub(super) struct Identity {
    ed_secret: Zeroizing<[u8; 32]>,
    pq_secret: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    fingerprint: String,
}

impl Identity {
    pub fn load(state: &AppState, owner: &str) -> Result<Self> {
        provider::require_offline_suite()?;
        if let Some(bytes) = state.load_user_secret_doc(owner, DOC, IDENTITY_AAD, DOC)? {
            if bytes.len() != ID_RECORD_BYTES {
                return Err(QGuardError::Storage(
                    "The local device identity is unreadable.".into(),
                ));
            }
            let seed = Zeroizing::new(array32(&bytes[..32])?);
            let ed_public = provider::ed25519_public(&seed)?;
            return Ok(Self::from_parts(
                seed,
                ed_public,
                &bytes[32..ID_BYTES],
                &bytes[ID_BYTES..],
            ));
        }
        let identity = Self::generate()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(ID_RECORD_BYTES));
        bytes.extend_from_slice(identity.ed_secret.as_ref());
        bytes.extend_from_slice(&identity.public[32..]);
        bytes.extend_from_slice(&identity.pq_secret);
        state.save_user_secret_doc(owner, DOC, IDENTITY_AAD, &bytes, DOC)?;
        Ok(identity)
    }

    pub(super) fn generate() -> Result<Self> {
        let (ed_secret, ed_public) = provider::ed25519_generate()?;
        let (pq_public, pq_secret) = provider::mldsa_generate(PQ_SIGNATURE)?;
        Ok(Self::from_parts(
            ed_secret, ed_public, &pq_public, &pq_secret,
        ))
    }

    fn from_parts(
        ed_secret: Zeroizing<[u8; 32]>,
        ed_public: [u8; 32],
        pq_public: &[u8],
        pq_secret: &[u8],
    ) -> Self {
        let mut public = Vec::with_capacity(ID_BYTES);
        public.extend_from_slice(&ed_public);
        public.extend_from_slice(pq_public);
        let fingerprint = fingerprint(&public);
        Self {
            ed_secret,
            pq_secret: Zeroizing::new(pq_secret.to_vec()),
            public,
            fingerprint,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[cfg(test)]
    pub(super) fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Hybrid Ed25519 + ML-DSA-65 signature over a domain-separated digest
    /// (multi-hop Mesh envelopes; see offline::relay).
    pub(super) fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let mut signature = Vec::with_capacity(SIGNATURE_BYTES);
        self.sign(digest, &mut signature)?;
        Ok(signature)
    }

    fn sign(&self, transcript: &[u8; 32], output: &mut Vec<u8>) -> Result<()> {
        output.extend_from_slice(&provider::ed25519_sign(&self.ed_secret, transcript)?);
        output.extend_from_slice(&provider::mldsa_sign(
            PQ_SIGNATURE,
            &self.pq_secret,
            transcript,
        )?);
        Ok(())
    }
}

pub(super) fn fingerprint(public: &[u8]) -> String {
    hex::encode(hash(b"QGuard-Offline-Identity-Fingerprint-v1", &[public]))
}

/// Verify a [`Identity::sign_digest`] signature against a pinned identity key.
/// Both component signatures must verify.
pub(super) fn verify_digest(public: &[u8], digest: &[u8; 32], signature: &[u8]) -> Result<()> {
    if public.len() != ID_BYTES || signature.len() != SIGNATURE_BYTES {
        return Err(QGuardError::Crypto("Invalid hybrid signature.".into()));
    }
    verify(public, digest, signature)
}

/// Length-prefixed, domain-separated SHA3-256 (the session's transcript hash).
pub(super) fn domain_hash(label: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    hash(label, fields)
}

fn verify(public: &[u8], transcript: &[u8; 32], signature: &[u8]) -> Result<()> {
    provider::ed25519_verify(&public[..32], transcript, &signature[..64])?;
    provider::mldsa_verify(PQ_SIGNATURE, &public[32..], transcript, &signature[64..])
}

fn hash(label: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut digest = provider::Sha3_256Hasher::new();
    digest.update(label);
    for field in fields {
        digest.update(&(field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.finalize()
}

fn record(kind: u8) -> Vec<u8> {
    let mut bytes = WIRE.to_vec();
    bytes.push(kind);
    bytes
}

fn is_record(bytes: &[u8], kind: u8) -> bool {
    bytes.starts_with(WIRE) && bytes.get(WIRE.len()) == Some(&kind)
}

fn opening(kind: u8, identity: &Identity, ephemeral: &[u8; 32], kem: &[u8]) -> Vec<u8> {
    let mut bytes = record(kind);
    bytes.extend_from_slice(&identity.public);
    bytes.extend_from_slice(&provider::random_array::<32>());
    bytes.extend_from_slice(ephemeral);
    bytes.extend_from_slice(kem);
    bytes
}

pub(super) struct Session {
    stream: Stream,
    local_fingerprint: String,
    peer: String,
    peer_public: Vec<u8>,
    pairing: bool,
    authorization: Option<watch::Receiver<bool>>,
    id: [u8; 32],
    sending: Zeroizing<[u8; 32]>,
    receiving: Zeroizing<[u8; 32]>,
    sent: u64,
    received: u64,
    failed: bool,
    limits: Limits,
}

impl Session {
    pub fn local_fingerprint(&self) -> &str {
        &self.local_fingerprint
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn peer_public(&self) -> &[u8] {
        &self.peer_public
    }

    pub fn pairing(&self) -> bool {
        self.pairing
    }

    pub fn binding(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn authorize(&mut self, authorization: watch::Receiver<bool>) {
        self.authorization = Some(authorization);
    }

    pub fn bluetooth(&self) -> bool {
        self.limits.bluetooth
    }

    pub async fn connect(stream: TcpStream, identity: &Identity, expected: &str) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            HANDSHAKE_TIMEOUT,
            Self::client_handshake(Box::new(stream), identity, expected, LAN_LIMITS, false),
        )
        .await
        .map_err(|_| timed_out())?
    }

    pub async fn connect_ble(
        stream: DuplexStream,
        identity: &Identity,
        expected: &str,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            BLE_HANDSHAKE_TIMEOUT,
            Self::client_handshake(Box::new(stream), identity, expected, BLE_LIMITS, false),
        )
        .await
        .map_err(|_| timed_out())?
    }

    pub async fn connect_pairing(
        stream: TcpStream,
        identity: &Identity,
        expected: &str,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            HANDSHAKE_TIMEOUT,
            Self::client_handshake(Box::new(stream), identity, expected, LAN_LIMITS, true),
        )
        .await
        .map_err(|_| timed_out())?
    }

    pub async fn connect_pairing_ble(
        stream: DuplexStream,
        identity: &Identity,
        expected: &str,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            BLE_HANDSHAKE_TIMEOUT,
            Self::client_handshake(Box::new(stream), identity, expected, BLE_LIMITS, true),
        )
        .await
        .map_err(|_| timed_out())?
    }

    async fn client_handshake(
        mut stream: Stream,
        identity: &Identity,
        expected: &str,
        limits: Limits,
        pairing: bool,
    ) -> Result<Self> {
        let (dh_secret, dh_public) = provider::x25519_generate()?;
        let (kem_public, kem_secret) = provider::mlkem768_generate()?;
        // The signed Hello record separates pairing from pinned application sessions.
        let hello_kind = if pairing { PAIRING_HELLO } else { HELLO };
        let hello = opening(hello_kind, identity, &dh_public, &kem_public);
        stream.write_all(&hello).await.map_err(io_error)?;
        let mut reply = [0; REPLY_BYTES];
        stream.read_exact(&mut reply).await.map_err(io_error)?;
        if !is_record(&reply, REPLY) {
            return Err(handshake_error());
        }
        let peer_public = &reply[HEADER..HEADER + ID_BYTES];
        let peer = fingerprint(peer_public);
        if peer != expected || peer == identity.fingerprint() {
            // Fingerprints are public. Naming both tells a stale discovery
            // entry (the device shows this one as its own) from a damaged link.
            return Err(QGuardError::Trust(format!(
                "The peer identity does not match the selected fingerprint (selected {}, the device presented {}). Refresh discovery and try again.",
                expected.get(..8).unwrap_or(expected),
                peer.get(..8).unwrap_or(&peer),
            )));
        }
        let body = &reply[..REPLY_BODY_BYTES];
        let challenge = hash(b"QGuard-Offline-Responder-Signature-v1", &[&hello, body]);
        verify(peer_public, &challenge, &reply[REPLY_BODY_BYTES..])?;
        let challenge = hash(b"QGuard-Offline-Initiator-Signature-v1", &[&hello, &reply]);
        let mut finish = record(FINISH);
        identity.sign(&challenge, &mut finish)?;
        let session_id = hash(b"QGuard-Offline-Session-v1", &[&hello, &reply, &finish]);
        let dh = provider::x25519_shared(
            &dh_secret,
            &array32(&reply[EPHEMERAL_OFFSET..SHARE_OFFSET])?,
        )?;
        let kem =
            provider::mlkem768_decapsulate(&kem_secret, &reply[SHARE_OFFSET..REPLY_BODY_BYTES])?;
        let (client_key, server_key) = keys(&session_id, &dh, &kem)?;
        stream.write_all(&finish).await.map_err(io_error)?;
        let mut session = Self::new(
            stream,
            identity,
            peer,
            peer_public.to_vec(),
            session_id,
            client_key,
            server_key,
            limits,
            pairing,
        );
        session
            .send(&hash(
                b"QGuard-Offline-Initiator-Key-Confirmation-v1",
                &[&session_id],
            ))
            .await?;
        let proof = session.recv().await?;
        if !provider::constant_time_eq(
            &proof,
            &hash(
                b"QGuard-Offline-Responder-Key-Confirmation-v1",
                &[&session_id],
            ),
        ) {
            return Err(handshake_error());
        }
        Ok(session)
    }

    #[cfg(test)]
    pub async fn accept(
        stream: TcpStream,
        identity: &Identity,
        trusted: impl Fn(&str) -> bool,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            HANDSHAKE_TIMEOUT,
            Self::server_handshake(Box::new(stream), identity, trusted, |_| false, LAN_LIMITS),
        )
        .await
        .map_err(|_| timed_out())?
    }

    #[cfg(test)]
    pub async fn accept_ble(
        stream: DuplexStream,
        identity: &Identity,
        trusted: impl Fn(&str) -> bool,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            BLE_HANDSHAKE_TIMEOUT,
            Self::server_handshake(Box::new(stream), identity, trusted, |_| false, BLE_LIMITS),
        )
        .await
        .map_err(|_| timed_out())?
    }

    pub async fn accept_mixed(
        stream: TcpStream,
        identity: &Identity,
        trusted: impl Fn(&str) -> bool,
        pairing_allowed: impl Fn(&str) -> bool,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            HANDSHAKE_TIMEOUT,
            Self::server_handshake(
                Box::new(stream),
                identity,
                trusted,
                pairing_allowed,
                LAN_LIMITS,
            ),
        )
        .await
        .map_err(|_| timed_out())?
    }

    pub async fn accept_mixed_ble(
        stream: DuplexStream,
        identity: &Identity,
        trusted: impl Fn(&str) -> bool,
        pairing_allowed: impl Fn(&str) -> bool,
    ) -> Result<Self> {
        provider::require_offline_suite()?;
        timeout(
            BLE_HANDSHAKE_TIMEOUT,
            Self::server_handshake(
                Box::new(stream),
                identity,
                trusted,
                pairing_allowed,
                BLE_LIMITS,
            ),
        )
        .await
        .map_err(|_| timed_out())?
    }

    async fn server_handshake(
        mut stream: Stream,
        identity: &Identity,
        trusted: impl Fn(&str) -> bool,
        pairing_allowed: impl Fn(&str) -> bool,
        limits: Limits,
    ) -> Result<Self> {
        let mut hello = [0; HELLO_BYTES];
        stream.read_exact(&mut hello).await.map_err(io_error)?;
        let pairing = is_record(&hello, PAIRING_HELLO);
        if !pairing && !is_record(&hello, HELLO) {
            return Err(handshake_error());
        }
        let peer_public = &hello[HEADER..HEADER + ID_BYTES];
        let peer = fingerprint(peer_public);
        let allowed = |peer: &str| {
            if pairing {
                pairing_allowed(peer)
            } else {
                trusted(peer)
            }
        };
        if peer == identity.fingerprint() || !allowed(&peer) {
            return Err(QGuardError::Trust(
                "The initiating device has not been pinned.".into(),
            ));
        }
        let (dh_secret, dh_public) = provider::x25519_generate()?;
        let dh = provider::x25519_shared(
            &dh_secret,
            &array32(&hello[EPHEMERAL_OFFSET..SHARE_OFFSET])?,
        )?;
        if !dh.was_contributory() {
            return Err(handshake_error());
        }
        let (ciphertext, kem) = provider::mlkem768_encapsulate(&hello[SHARE_OFFSET..])?;
        let mut reply = opening(REPLY, identity, &dh_public, &ciphertext);
        let challenge = hash(b"QGuard-Offline-Responder-Signature-v1", &[&hello, &reply]);
        identity.sign(&challenge, &mut reply)?;
        stream.write_all(&reply).await.map_err(io_error)?;
        let mut finish = [0; FINISH_BYTES];
        stream.read_exact(&mut finish).await.map_err(io_error)?;
        if !is_record(&finish, FINISH) {
            return Err(handshake_error());
        }
        let challenge = hash(b"QGuard-Offline-Initiator-Signature-v1", &[&hello, &reply]);
        verify(peer_public, &challenge, &finish[HEADER..])?;
        let session_id = hash(b"QGuard-Offline-Session-v1", &[&hello, &reply, &finish]);
        let (client_key, server_key) = keys(&session_id, &dh, &kem)?;
        let mut session = Self::new(
            stream,
            identity,
            peer,
            peer_public.to_vec(),
            session_id,
            server_key,
            client_key,
            limits,
            pairing,
        );
        let proof = session.recv().await?;
        if !allowed(session.peer())
            || !provider::constant_time_eq(
                &proof,
                &hash(
                    b"QGuard-Offline-Initiator-Key-Confirmation-v1",
                    &[&session_id],
                ),
            )
        {
            return Err(handshake_error());
        }
        session
            .send(&hash(
                b"QGuard-Offline-Responder-Key-Confirmation-v1",
                &[&session_id],
            ))
            .await?;
        Ok(session)
    }

    fn new(
        stream: Stream,
        identity: &Identity,
        peer: String,
        peer_public: Vec<u8>,
        id: [u8; 32],
        sending: Zeroizing<[u8; 32]>,
        receiving: Zeroizing<[u8; 32]>,
        mut limits: Limits,
        pairing: bool,
    ) -> Self {
        if pairing {
            limits.max_payload = PAIRING_MAX_PAYLOAD;
        }
        Self {
            stream,
            local_fingerprint: identity.fingerprint().into(),
            peer,
            peer_public,
            pairing,
            authorization: None,
            id,
            sending,
            receiving,
            sent: 0,
            received: 0,
            failed: false,
            limits,
        }
    }

    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        if let Some(mut authorization) = self.authorization.clone() {
            tokio::select! {
                biased;
                _ = authorization.wait_for(|revoked| *revoked) => Err(session_revoked()),
                result = self.send_frame(plaintext) => result,
            }
        } else {
            self.send_frame(plaintext).await
        }
    }

    async fn send_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        provider::require_offline_suite()?;
        if self.failed || plaintext.is_empty() || plaintext.len() > self.limits.max_payload {
            return Err(frame_error());
        }
        self.failed = true;
        let sequence = self.sent.to_be_bytes();
        let (key, aad) = frame_key(&self.sending, &self.id, sequence)?;
        let sealed = provider::aes256gcm_seal(&key, &aad, plaintext)?;
        let length = (sealed.ciphertext.len() + FRAME_OVERHEAD) as u32;
        timeout(self.limits.io_timeout, async {
            self.stream.write_all(&length.to_be_bytes()).await?;
            self.stream.write_all(&sequence).await?;
            self.stream.write_all(&sealed.nonce).await?;
            self.stream.write_all(&sealed.ciphertext).await?;
            self.stream.write_all(&sealed.tag).await
        })
        .await
        .map_err(|_| timed_out())?
        .map_err(io_error)?;
        self.sent = self.sent.checked_add(1).ok_or_else(frame_error)?;
        self.failed = false;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        if let Some(mut authorization) = self.authorization.clone() {
            tokio::select! {
                biased;
                _ = authorization.wait_for(|revoked| *revoked) => Err(session_revoked()),
                result = self.recv_frame() => result,
            }
        } else {
            self.recv_frame().await
        }
    }

    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        provider::require_offline_suite()?;
        if self.failed {
            return Err(frame_error());
        }
        self.failed = true;
        let expected = self.received.to_be_bytes();
        let mut header = [0; FRAME_HEAD];
        let body = timeout(self.limits.io_timeout, async {
            let length = self.stream.read_u32().await.map_err(io_error)? as usize;
            if !(FRAME_OVERHEAD + 1..=self.limits.max_payload + FRAME_OVERHEAD).contains(&length) {
                return Err(frame_error());
            }
            self.stream
                .read_exact(&mut header)
                .await
                .map_err(io_error)?;
            if header[..8] != expected {
                return Err(QGuardError::Replay(
                    "Unexpected local session frame sequence.".into(),
                ));
            }
            let mut body = vec![0; length - FRAME_HEAD];
            self.stream.read_exact(&mut body).await.map_err(io_error)?;
            Ok(body)
        })
        .await
        .map_err(|_| timed_out())??;
        let split = body.len() - provider::AES_GCM_TAG_BYTES;
        let (key, aad) = frame_key(&self.receiving, &self.id, expected)?;
        let result =
            provider::aes256gcm_open(&key, &header[8..], &aad, &body[..split], &body[split..])?;
        self.received = self.received.checked_add(1).ok_or_else(frame_error)?;
        self.failed = false;
        Ok(result)
    }
}

/// The receiving half of a long-lived session. See [`Session::split`].
pub(super) struct SessionReader {
    stream: tokio::io::ReadHalf<Stream>,
    id: [u8; 32],
    receiving: Zeroizing<[u8; 32]>,
    received: u64,
    failed: bool,
    limits: Limits,
}

/// The sending half of a long-lived session. See [`Session::split`].
pub(super) struct SessionWriter {
    stream: tokio::io::WriteHalf<Stream>,
    id: [u8; 32],
    sending: Zeroizing<[u8; 32]>,
    sent: u64,
    failed: bool,
    limits: Limits,
}

impl Session {
    /// Turn an authenticated session into independent halves, so a persistent
    /// channel can wait for the peer's next frame while it sends its own. The
    /// keys, sequence counters and frame format are unchanged: each direction
    /// already has its own key and its own strictly ordered sequence.
    /// Signals when this peer's authorization is withdrawn (revoked, blocked
    /// or disconnected by the user). The halves do not carry it.
    pub fn authorization(&self) -> Option<watch::Receiver<bool>> {
        self.authorization.clone()
    }

    pub fn split(self) -> (SessionReader, SessionWriter) {
        let (read, write) = tokio::io::split(self.stream);
        (
            SessionReader {
                stream: read,
                id: self.id,
                receiving: self.receiving,
                received: self.received,
                failed: self.failed,
                limits: self.limits,
            },
            SessionWriter {
                stream: write,
                id: self.id,
                sending: self.sending,
                sent: self.sent,
                failed: self.failed,
                limits: self.limits,
            },
        )
    }
}

impl SessionReader {
    /// The next frame. `idle` bounds how long the link may stay silent before
    /// a frame starts (the channel's heartbeat keeps a healthy link inside
    /// it); once a frame has started, the session's own I/O deadline applies.
    /// Any error ends this half for good.
    pub async fn recv(&mut self, idle: Duration) -> Result<Vec<u8>> {
        provider::require_offline_suite()?;
        if self.failed {
            return Err(frame_error());
        }
        self.failed = true;
        let expected = self.received.to_be_bytes();
        let length = timeout(idle, self.stream.read_u32())
            .await
            .map_err(|_| timed_out())?
            .map_err(io_error)? as usize;
        if !(FRAME_OVERHEAD + 1..=self.limits.max_payload + FRAME_OVERHEAD).contains(&length) {
            return Err(frame_error());
        }
        let mut header = [0; FRAME_HEAD];
        let body = timeout(self.limits.io_timeout, async {
            self.stream
                .read_exact(&mut header)
                .await
                .map_err(io_error)?;
            if header[..8] != expected {
                return Err(QGuardError::Replay(
                    "Unexpected local session frame sequence.".into(),
                ));
            }
            let mut body = vec![0; length - FRAME_HEAD];
            self.stream.read_exact(&mut body).await.map_err(io_error)?;
            Ok(body)
        })
        .await
        .map_err(|_| timed_out())??;
        let split = body.len() - provider::AES_GCM_TAG_BYTES;
        let (key, aad) = frame_key(&self.receiving, &self.id, expected)?;
        let result =
            provider::aes256gcm_open(&key, &header[8..], &aad, &body[..split], &body[split..])?;
        self.received = self.received.checked_add(1).ok_or_else(frame_error)?;
        self.failed = false;
        Ok(result)
    }
}

impl SessionWriter {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        provider::require_offline_suite()?;
        if self.failed || plaintext.is_empty() || plaintext.len() > self.limits.max_payload {
            return Err(frame_error());
        }
        self.failed = true;
        let sequence = self.sent.to_be_bytes();
        let (key, aad) = frame_key(&self.sending, &self.id, sequence)?;
        let sealed = provider::aes256gcm_seal(&key, &aad, plaintext)?;
        let length = (sealed.ciphertext.len() + FRAME_OVERHEAD) as u32;
        timeout(self.limits.io_timeout, async {
            self.stream.write_all(&length.to_be_bytes()).await?;
            self.stream.write_all(&sequence).await?;
            self.stream.write_all(&sealed.nonce).await?;
            self.stream.write_all(&sealed.ciphertext).await?;
            self.stream.write_all(&sealed.tag).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| timed_out())?
        .map_err(io_error)?;
        self.sent = self.sent.checked_add(1).ok_or_else(frame_error)?;
        self.failed = false;
        Ok(())
    }
}

type Secret = Zeroizing<[u8; 32]>;

fn keys(id: &[u8; 32], dh: &provider::X25519Shared, kem: &Secret) -> Result<(Secret, Secret)> {
    if !dh.was_contributory() {
        return Err(handshake_error());
    }
    // Fixed-width KEM || ECDHE order follows the X25519MLKEM768 group. The
    // extraction salt binds the signed transcript, including both shares and
    // the encapsulation ciphertext, to the two direction-specific keys.
    let mut secrets = Zeroizing::new([0; 64]);
    secrets[..32].copy_from_slice(kem.as_ref());
    secrets[32..].copy_from_slice(dh.as_bytes());
    let mut client = Zeroizing::new([0; 32]);
    let mut server = Zeroizing::new([0; 32]);
    provider::hkdf_sha3_256(
        Some(id),
        secrets.as_ref(),
        b"QGuard-Offline-Client-to-Server-v1",
        client.as_mut(),
    )?;
    provider::hkdf_sha3_256(
        Some(id),
        secrets.as_ref(),
        b"QGuard-Offline-Server-to-Client-v1",
        server.as_mut(),
    )?;
    Ok((client, server))
}

fn frame_key(base: &Secret, session: &[u8; 32], sequence: [u8; 8]) -> Result<(Secret, [u8; 32])> {
    let aad = hash(b"QGuard-Offline-Frame-v1", &[session, &sequence]);
    let mut key = Zeroizing::new([0; 32]);
    provider::hkdf_sha3_256(
        Some(&aad),
        base.as_ref(),
        b"QGuard-Offline-Frame-Key-v1",
        key.as_mut(),
    )?;
    Ok((key, aad))
}

fn array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| handshake_error())
}

fn session_revoked() -> QGuardError {
    QGuardError::Trust("This local session is no longer authorized.".into())
}

fn handshake_error() -> QGuardError {
    QGuardError::Trust(HANDSHAKE_MESSAGE.into())
}

fn frame_error() -> QGuardError {
    QGuardError::InvalidInput("Invalid local session frame.".into())
}

fn timed_out() -> QGuardError {
    QGuardError::Storage(TIMEOUT_MESSAGE.into())
}

fn io_error(_: std::io::Error) -> QGuardError {
    QGuardError::Storage("The local peer connection closed or could not carry the frame.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn split_halves_carry_many_frames_both_ways_at_once_in_order_over_bluetooth_packets() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (client, server) = super::super::smart::test_ble_pair();
        let (client, server) = tokio::join!(
            Session::connect_ble(client, &alice, bob.fingerprint()),
            Session::accept_ble(server, &bob, |peer| peer == alice.fingerprint()),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.binding(), server.binding(), "both devices derive one session id");
        let (mut client_reader, mut client_writer) = client.split();
        let (mut server_reader, mut server_writer) = server.split();
        const FRAMES: usize = 25;
        let idle = Duration::from_secs(20);
        // Both devices send at the same time on one persistent session.
        let to_server = tokio::spawn(async move {
            for index in 0..FRAMES {
                client_writer.send(format!("from the client {index}").as_bytes()).await.unwrap();
            }
            client_writer
        });
        let to_client = tokio::spawn(async move {
            for index in 0..FRAMES {
                server_writer.send(format!("from the server {index}").as_bytes()).await.unwrap();
            }
            server_writer
        });
        let at_server = tokio::spawn(async move {
            for index in 0..FRAMES {
                assert_eq!(server_reader.recv(idle).await.unwrap(), format!("from the client {index}").as_bytes());
            }
            server_reader
        });
        for index in 0..FRAMES {
            assert_eq!(client_reader.recv(idle).await.unwrap(), format!("from the server {index}").as_bytes());
        }
        let mut client_writer = to_server.await.unwrap();
        let _server_writer = to_client.await.unwrap();
        let mut server_reader = at_server.await.unwrap();
        // An oversized frame is refused locally and the half stays usable.
        assert!(client_writer.send(&vec![0; BLE_LIMITS.max_payload + 1]).await.is_err());
        client_writer.send(b"still open").await.unwrap();
        assert_eq!(server_reader.recv(idle).await.unwrap(), b"still open");
        // A silent link is reported, and the half is then finished for good.
        assert!(is_timeout(&client_reader.recv(Duration::from_millis(150)).await.unwrap_err()));
        assert!(client_reader.recv(idle).await.is_err());
    }

    #[tokio::test]
    async fn ble_packets_carry_a_pinned_qhce_session_and_enforce_small_message_limits() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (client, server) = super::super::smart::test_ble_pair();
        let (client, server) = tokio::join!(
            Session::connect_ble(client, &alice, bob.fingerprint()),
            Session::accept_ble(server, &bob, |peer| peer == alice.fingerprint()),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert!(client.bluetooth() && server.bluetooth());
        let body = b"Bluetooth-only authenticated message";
        client.send(body).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), body);
        server.send(b"acknowledged").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"acknowledged");
        assert!(client
            .send(&vec![0; BLE_LIMITS.max_payload + 1])
            .await
            .is_err());
        // An oversized local request is rejected without consuming the stream.
        client.send(b"still usable").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"still usable");
    }

    #[tokio::test]
    async fn pinned_sessions_exchange_records_and_reject_a_repeated_sequence() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(
            async {
                Session::connect(
                    TcpStream::connect(address).await.unwrap(),
                    &alice,
                    bob.fingerprint(),
                )
                .await
            },
            async {
                Session::accept(listener.accept().await.unwrap().0, &bob, |peer| {
                    peer == alice.fingerprint()
                })
                .await
            },
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        client.send(b"offline request").await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"offline request");
        server.send(b"offline receipt").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"offline receipt");
        // Inject only the old header so the receiver must reject it before the body.
        client
            .stream
            .write_u32((FRAME_OVERHEAD + 1) as u32)
            .await
            .unwrap();
        let mut replay = [0; FRAME_HEAD];
        replay[..8].copy_from_slice(&1u64.to_be_bytes());
        client.stream.write_all(&replay).await.unwrap();
        assert!(matches!(server.recv().await, Err(QGuardError::Replay(_))));
    }

    #[tokio::test]
    async fn an_unpinned_responder_cannot_establish_a_session() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let wrong = "ab".repeat(32);
        let (client, server) = tokio::join!(
            async {
                Session::connect(TcpStream::connect(address).await.unwrap(), &alice, &wrong).await
            },
            async {
                Session::accept(listener.accept().await.unwrap().0, &bob, |peer| {
                    peer == alice.fingerprint()
                })
                .await
            },
        );
        assert!(matches!(client, Err(QGuardError::Trust(_))));
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn revocation_interrupts_waiting_frames_and_rejects_future_writes() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (client, server) = tokio::io::duplex(32 * 1024);
        let (client, server) = tokio::join!(
            Session::connect_ble(client, &alice, bob.fingerprint()),
            Session::accept_ble(server, &bob, |peer| peer == alice.fingerprint()),
        );
        let (mut client, _server) = (client.unwrap(), server.unwrap());
        let (revoke, authorization) = watch::channel(false);
        client.authorize(authorization);
        let (result, ()) = tokio::join!(client.recv(), async {
            tokio::task::yield_now().await;
            revoke.send(true).unwrap();
        });
        assert!(matches!(result, Err(QGuardError::Trust(_))));
        assert!(matches!(
            client.send(b"revoked").await,
            Err(QGuardError::Trust(_))
        ));
    }

    #[tokio::test]
    async fn suite_downgrade_and_noncanonical_kem_key_are_rejected() {
        assert!(
            provider::mlkem768_encapsulate(&vec![255; provider::MLKEM768_PUBLIC_KEY_BYTES])
                .is_err()
        );
        let bob = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_, server) = tokio::join!(
            async {
                let mut stream = TcpStream::connect(address).await.unwrap();
                let mut hello = [0; HELLO_BYTES];
                hello[..WIRE.len()].copy_from_slice(WIRE);
                hello[WIRE.len() - 1] = 0;
                hello[WIRE.len()] = HELLO;
                stream.write_all(&hello).await.unwrap();
            },
            async { Session::accept(listener.accept().await.unwrap().0, &bob, |_| true).await },
        );
        assert!(matches!(server, Err(QGuardError::Trust(_))));
    }

    /// Forward one direction of a stream, record every byte, and optionally
    /// flip one bit at an absolute stream offset.
    async fn relay(
        mut from: impl AsyncRead + Unpin,
        mut to: impl AsyncWrite + Unpin,
        log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        flip_at: Option<usize>,
    ) {
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = match from.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            {
                let mut log = log.lock().unwrap();
                let start = log.len();
                if let Some(at) = flip_at.filter(|at| (start..start + read).contains(at)) {
                    buffer[at - start] ^= 0x01;
                }
                log.extend_from_slice(&buffer[..read]);
            }
            if to.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
        let _ = to.shutdown().await;
    }

    type WireLog = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

    /// A LAN-limits session pair whose traffic passes through a recording relay.
    async fn observed_pair(
        alice: &Identity,
        bob: &Identity,
        flip_upstream_at: Option<usize>,
    ) -> (Session, Session, WireLog, WireLog, [tokio::task::JoinHandle<()>; 2]) {
        let (client_end, proxy_client) = tokio::io::duplex(8 * 1024 * 1024);
        let (proxy_server, server_end) = tokio::io::duplex(8 * 1024 * 1024);
        let upstream = WireLog::default();
        let downstream = WireLog::default();
        let (client_read, client_write) = tokio::io::split(proxy_client);
        let (server_read, server_write) = tokio::io::split(proxy_server);
        let relays = [
            tokio::spawn(relay(client_read, server_write, upstream.clone(), flip_upstream_at)),
            tokio::spawn(relay(server_read, client_write, downstream.clone(), None)),
        ];
        let (client, server) = tokio::join!(
            Session::client_handshake(Box::new(client_end), alice, bob.fingerprint(), LAN_LIMITS, false),
            Session::server_handshake(
                Box::new(server_end),
                bob,
                |peer| peer == alice.fingerprint(),
                |_| false,
                LAN_LIMITS,
            ),
        );
        (client.unwrap(), server.unwrap(), upstream, downstream, relays)
    }

    #[tokio::test]
    async fn transfer_payload_on_the_wire_is_hybrid_keyed_aes_256_gcm_ciphertext() {
        // The suite shown in the XFER dashboard is the one this wire version uses.
        assert_eq!(WIRE, b"QGLN\x01\x01");
        assert_eq!(TRANSFER_SUITE_V1.key_establishment, "ML-KEM-768 + X25519");
        assert_eq!(TRANSFER_SUITE_V1.signatures, "ML-DSA-65 + Ed25519");
        assert_eq!(TRANSFER_SUITE_V1.encryption, "AES-256-GCM");
        assert_eq!(TRANSFER_SUITE_V1.integrity, "SHA3-256");
        // FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65 object sizes.
        assert_eq!(provider::MLKEM768_PUBLIC_KEY_BYTES, 1184);
        assert_eq!(provider::MLKEM768_CIPHERTEXT_BYTES, 1088);
        assert_eq!(PQ_SIGNATURE.public_key_bytes(), 1952);
        assert_eq!(PQ_SIGNATURE.signature_bytes(), 3309);
        assert_eq!(provider::AES_GCM_NONCE_BYTES, 12);
        assert_eq!(provider::AES_GCM_TAG_BYTES, 16);

        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut client, mut server, upstream, downstream, relays) =
            observed_pair(&alice, &bob, None).await;
        assert_eq!(client.binding(), server.binding());

        // One full XFER chunk frame: the chunk type byte and 4 MiB of payload.
        let marker = b"QGUARD-XFER-PLAINTEXT-MARKER";
        let mut chunk = vec![1u8];
        chunk.extend((0..super::super::xfer::CHUNK_SIZE as usize).map(|index| marker[index % marker.len()]));
        client.send(&chunk).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), chunk);
        drop((client, server));
        for relay in relays {
            relay.await.unwrap();
        }

        let sent = upstream.lock().unwrap().clone();
        let replied = downstream.lock().unwrap().clone();
        // Hello: version and suite header, Ed25519 + ML-DSA-65 identity,
        // random, X25519 share and ML-KEM-768 encapsulation key.
        assert!(is_record(&sent, HELLO));
        assert_eq!(HELLO_BYTES, HEADER + 32 + 1952 + 32 + 32 + 1184);
        // Reply: the responder's identity, random, X25519 share, ML-KEM-768
        // ciphertext, then Ed25519 + ML-DSA-65 signatures over the transcript.
        assert!(is_record(&replied, REPLY));
        assert_eq!(REPLY_BYTES, HEADER + 32 + 1952 + 32 + 32 + 1088 + 64 + 3309);
        assert!(is_record(&sent[HELLO_BYTES..], FINISH));

        // After Hello, Finish and the key-confirmation frame comes the chunk.
        // Its length covers the sequence number, a 96-bit nonce, ciphertext
        // of exactly the plaintext length and the 128-bit GCM tag.
        let confirmation = 4 + FRAME_OVERHEAD + 32;
        let offset = HELLO_BYTES + FINISH_BYTES + confirmation;
        let length = u32::from_be_bytes(sent[offset..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(length, chunk.len() + FRAME_OVERHEAD);
        assert_eq!(sent.len(), offset + 4 + length);
        assert_eq!(&sent[offset + 4..offset + 12], &1u64.to_be_bytes());
        // No plaintext fragment of the file crosses the wire.
        assert!(!sent.windows(marker.len()).any(|window| window == marker));
        assert!(!replied.windows(marker.len()).any(|window| window == marker));
    }

    #[tokio::test]
    async fn a_single_flipped_ciphertext_bit_fails_gcm_authentication() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        // Flip a bit inside the ciphertext of the first frame after key confirmation.
        let target = HELLO_BYTES + FINISH_BYTES + (4 + FRAME_OVERHEAD + 32) + 4 + FRAME_HEAD + 5;
        let (mut client, mut server, _, _, _relays) =
            observed_pair(&alice, &bob, Some(target)).await;
        client.send(b"authenticated transfer control").await.unwrap();
        assert!(server.recv().await.is_err());
        // The receiver refuses every later frame on the failed session.
        client.send(b"retry on the same session").await.unwrap();
        assert!(server.recv().await.is_err());
    }
}
