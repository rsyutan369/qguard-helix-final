//! QGuard offline protocol v1. The session layer authenticates each frame.
//! Control frames are typed JSON. Chunk frames are raw bytes, requested and
//! processed one at a time to bound memory independently of file size.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{QGuardError, Result};

use super::{
    mesh,
    relay::{Envelope, RelayPublic},
    session::Session,
    xfer::{Manifest, MissingFile, TransferAction},
};

const CONTROL_LIMIT: usize = 1024 * 1024;
const CONTROL: u8 = 0;
const CHUNK: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Control {
    Message(mesh::Delivery),
    Receipt(mesh::Receipt),
    Offer(Manifest),
    RequestSend {
        id: Uuid,
    },
    Checking {
        id: Uuid,
    },
    AwaitingConsent,
    Declined,
    Missing(Vec<MissingFile>),
    RequestChunk {
        file: u32,
        chunk: u32,
    },
    ChunkAck {
        file: u32,
        chunk: u32,
    },
    Complete {
        id: Uuid,
    },
    IntegrityFailed {
        id: Uuid,
    },
    TransferState {
        id: Uuid,
        revision: u64,
        action: TransferAction,
    },
    TransferStateAck {
        id: Uuid,
        revision: u64,
        completed: bool,
    },
    Cancel {
        id: Uuid,
    },
    Reject {
        id: Uuid,
    },
    Cancelled,
    /// Multi-hop Mesh: hand sealed envelopes to a trusted device.
    Relay {
        key: RelayPublic,
        envelopes: Vec<Envelope>,
    },
    RelayAck {
        key: RelayPublic,
        accepted: Vec<Uuid>,
        envelopes: Vec<Envelope>,
    },
    RelayDone {
        accepted: Vec<Uuid>,
    },
    /// Ask to keep this authenticated session open as the persistent channel
    /// to this peer (see `channel.rs`). An older build does not know the
    /// frame and closes; the caller then delivers one message per session.
    Channel {
        version: u8,
    },
    ChannelReady {
        version: u8,
    },
    /// Channel heartbeat. `id` is echoed back to measure the round trip.
    Ping {
        id: u64,
    },
    Pong {
        id: u64,
    },
    /// Channel only: "I have queued file-transfer work for you". The peer runs
    /// its transfer schedulers now instead of at its next discovery beacon.
    Nudge,
    /// Channel version 2: this device's current profile for its trusted peer.
    /// `owner` is the display name already shared at pairing (sent again so
    /// a rename reaches the peer); `avatar` is the SHA3-256 digest of the
    /// profile picture, or none when the user has no picture.
    Profile {
        owner: Option<String>,
        avatar: Option<String>,
    },
    /// Channel version 2: send the picture with this digest.
    AvatarRequest {
        digest: String,
    },
    /// Channel version 2: a profile picture (base64), checked by the receiver
    /// against `digest` before it is stored for the authenticated peer.
    Avatar {
        digest: String,
        image: String,
    },
    /// Channel version 3: a file offer sent over the channel because no local
    /// network reaches the receiver. The receiver stores it for consent exactly
    /// as an offer received on a transfer session, and answers `OfferState`.
    ChannelOffer(Manifest),
    /// Channel version 3: the receiver's answer to a `ChannelOffer`.
    OfferState {
        id: Uuid,
        state: super::link::OfferState,
    },
    /// Channel version 3 (see `link.rs`): please host a Wi-Fi link.
    LinkRequest,
    /// Channel version 3: the host's temporary network and its addresses.
    LinkOffer {
        ssid: String,
        password: String,
        security: Option<String>,
        addresses: Vec<std::net::SocketAddrV4>,
    },
    /// Channel version 3: the joiner reached the host over the link.
    LinkJoined,
    /// Channel version 3: the link could not be set up.
    LinkFailed {
        reason: String,
    },
    /// Channel version 3: the link is closed.
    LinkClose,
}

/// Encode a control frame for a split session half.
pub(super) fn encode(control: &Control) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(vec![CONTROL]);
    serde_json::to_writer(&mut *bytes, control).map_err(|_| protocol_error())?;
    if bytes.len() > CONTROL_LIMIT {
        return Err(protocol_error());
    }
    Ok(bytes)
}

/// Decode a control frame received on a split session half.
pub(super) fn decode(bytes: &[u8]) -> Result<Control> {
    if bytes.len() > CONTROL_LIMIT || bytes.first() != Some(&CONTROL) {
        return Err(protocol_error());
    }
    serde_json::from_slice(&bytes[1..]).map_err(|_| protocol_error())
}

pub(super) async fn send(session: &mut Session, control: &Control) -> Result<()> {
    let mut bytes = zeroize::Zeroizing::new(vec![CONTROL]);
    serde_json::to_writer(&mut *bytes, control).map_err(|_| protocol_error())?;
    if bytes.len() > CONTROL_LIMIT {
        return Err(protocol_error());
    }
    session.send(&bytes).await
}

pub(super) async fn recv(session: &mut Session) -> Result<Control> {
    let bytes = zeroize::Zeroizing::new(session.recv().await?);
    if bytes.len() > CONTROL_LIMIT || bytes.first() != Some(&CONTROL) {
        return Err(protocol_error());
    }
    serde_json::from_slice(&bytes[1..]).map_err(|_| protocol_error())
}

pub(super) async fn send_chunk(session: &mut Session, chunk: &[u8]) -> Result<()> {
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(chunk.len() + 1));
    bytes.push(CHUNK);
    bytes.extend_from_slice(chunk);
    session.send(&bytes).await
}

pub(super) async fn recv_chunk(session: &mut Session) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let bytes = zeroize::Zeroizing::new(session.recv().await?);
    if bytes.first() != Some(&CHUNK) {
        return Err(protocol_error());
    }
    Ok(bytes)
}

pub(super) fn protocol_error() -> QGuardError {
    QGuardError::InvalidInput("The peer sent an invalid offline protocol frame.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::{
        session::Identity,
        xfer::{Status, Store, Upload},
    };
    use crate::test_support::TestDevice;
    use std::fs;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn transfer_state_frames_round_trip_revision_and_completion() {
        let id = Uuid::new_v4();
        for action in [
            TransferAction::Pause,
            TransferAction::Resume,
            TransferAction::Stop,
            TransferAction::Cancel,
        ] {
            let frame = Control::TransferState {
                id,
                revision: 42,
                action,
            };
            let decoded = serde_json::from_slice(&serde_json::to_vec(&frame).unwrap()).unwrap();
            assert!(
                matches!(decoded, Control::TransferState { id: received, revision: 42, action: received_action } if received == id && received_action == action)
            );
        }
        let ack = Control::TransferStateAck {
            id,
            revision: 42,
            completed: true,
        };
        let decoded = serde_json::from_slice(&serde_json::to_vec(&ack).unwrap()).unwrap();
        assert!(
            matches!(decoded, Control::TransferStateAck { id: received, revision: 42, completed: true } if received == id)
        );
    }

    #[tokio::test]
    async fn encrypted_control_acknowledges_durable_holds_and_verified_completion() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        let sender = Identity::load(&alice.state, &alice.user).unwrap();
        let receiver = Identity::load(&bob.state, &bob.user).unwrap();
        let source = alice.dir.join("authenticated-control.txt");
        let payload = b"verified control fixture";
        fs::write(&source, payload).unwrap();
        let upload = Upload::prepare(
            sender.fingerprint().into(),
            receiver.fingerprint().into(),
            vec![source.canonicalize().unwrap()],
        )
        .unwrap();
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let sender_store = Store::open(alice.dir.join("control-store"), [4; 32]).unwrap();
        let receiver_store = Store::open(bob.dir.join("control-store"), [6; 32]).unwrap();
        sender_store.register_upload(&upload).unwrap();
        receiver_store
            .offer(manifest, sender.fingerprint(), receiver.fingerprint())
            .unwrap();
        receiver_store.accept(id).unwrap();

        // Exercise the authenticated frame codec over an in-memory stream so
        // this regression can run where loopback listeners are unavailable.
        let (a, b) = tokio::io::duplex(32 * 1024);
        let (client, server) = tokio::join!(
            Session::connect_ble(a, &sender, receiver.fingerprint()),
            Session::accept_ble(b, &receiver, |peer| peer == sender.fingerprint()),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        tokio::join!(
            async {
                for action in [
                    TransferAction::Pause,
                    TransferAction::Stop,
                    TransferAction::Resume,
                    TransferAction::Cancel,
                ] {
                    let record = match action {
                        TransferAction::Pause => sender_store.pause(id),
                        TransferAction::Stop => sender_store.stop(id),
                        TransferAction::Resume => sender_store.resume(id),
                        TransferAction::Cancel => sender_store.cancel(id),
                    }
                    .unwrap();
                    let intent = record.pending_control.unwrap();
                    send(
                        &mut client,
                        &Control::TransferState {
                            id,
                            revision: intent.revision,
                            action,
                        },
                    )
                    .await
                    .unwrap();
                    let Control::TransferStateAck {
                        id: received,
                        revision,
                        completed,
                    } = recv(&mut client).await.unwrap()
                    else {
                        panic!("expected a transfer state acknowledgment");
                    };
                    assert_eq!((received, revision), (id, intent.revision));
                    assert_eq!(completed, action == TransferAction::Cancel);
                    if completed {
                        assert_eq!(
                            sender_store.mark_verified(id).unwrap().status,
                            Status::Verified
                        );
                    } else {
                        assert!(sender_store
                            .ack_control(id, revision)
                            .unwrap()
                            .pending_control
                            .is_none());
                    }
                }
            },
            async {
                for status in [
                    Status::Paused,
                    Status::Stopped,
                    Status::Ready,
                    Status::Verified,
                ] {
                    let Control::TransferState {
                        id: received,
                        revision,
                        action,
                    } = recv(&mut server).await.unwrap()
                    else {
                        panic!("expected a transfer state update");
                    };
                    assert_eq!(received, id);
                    assert_eq!(
                        receiver_store.get(id).unwrap().manifest.sender,
                        server.peer()
                    );
                    let updated = receiver_store
                        .apply_remote_control(id, revision, action)
                        .unwrap();
                    assert_eq!(updated.status, status);
                    send(
                        &mut server,
                        &Control::TransferStateAck {
                            id,
                            revision,
                            completed: status == Status::Verified,
                        },
                    )
                    .await
                    .unwrap();
                    if status == Status::Ready {
                        receiver_store.put(id, 0, 0, payload).unwrap();
                        receiver_store.verify(id).unwrap();
                    }
                }
            },
        );
        assert_eq!(sender_store.get(id).unwrap().status, Status::Verified);
        assert_eq!(receiver_store.get(id).unwrap().status, Status::Verified);
    }

    #[tokio::test]
    async fn authenticated_loopback_delivers_a_durable_mesh_receipt_and_verified_file() {
        let alice = TestDevice::new(false);
        let bob = TestDevice::new(false);
        let sender = Identity::load(&alice.state, &alice.user).unwrap();
        let receiver = Identity::load(&bob.state, &bob.user).unwrap();
        let recipient = receiver.fingerprint().to_owned();
        mesh::queue(
            &alice.state,
            &alice.user,
            sender.fingerprint(),
            vec![recipient.clone()],
            "field report".into(),
            None,
            false,
            3600,
        )
        .unwrap();
        let (_, delivery) =
            mesh::pending_for_peers(&alice.state, &alice.user, vec![recipient.clone()])
                .unwrap()
                .pop()
                .unwrap();

        let source = alice.dir.join("field-report.txt");
        fs::write(&source, b"verified file payload").unwrap();
        let upload = Upload::prepare(
            sender.fingerprint().into(),
            recipient,
            vec![source.canonicalize().unwrap()],
        )
        .unwrap();
        let manifest = upload.manifest().clone();
        let id = manifest.id;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let ((), ()) = tokio::join!(
            async {
                let stream = TcpStream::connect(address).await.unwrap();
                let mut session = Session::connect(stream, &sender, receiver.fingerprint())
                    .await
                    .unwrap();
                send(&mut session, &Control::Message(delivery))
                    .await
                    .unwrap();
                let Control::Receipt(receipt) = recv(&mut session).await.unwrap() else {
                    panic!("expected receipt")
                };
                mesh::acknowledge(&alice.state, &alice.user, receiver.fingerprint(), receipt)
                    .unwrap();
                send(&mut session, &Control::Offer(manifest)).await.unwrap();
                assert!(matches!(
                    recv(&mut session).await.unwrap(),
                    Control::RequestChunk { file: 0, chunk: 0 }
                ));
                send_chunk(&mut session, &upload.read_chunk(0, 0).unwrap())
                    .await
                    .unwrap();
                assert!(
                    matches!(recv(&mut session).await.unwrap(), Control::Complete { id: complete } if complete == id)
                );
            },
            async {
                let stream = listener.accept().await.unwrap().0;
                let mut session =
                    Session::accept(stream, &receiver, |peer| peer == sender.fingerprint())
                        .await
                        .unwrap();
                let Control::Message(delivery) = recv(&mut session).await.unwrap() else {
                    panic!("expected delivery")
                };
                let (receipt, new) = mesh::receive(
                    &bob.state,
                    &bob.user,
                    receiver.fingerprint(),
                    session.peer(),
                    delivery,
                )
                .unwrap();
                assert!(new.is_some(), "a first delivery is new");
                send(&mut session, &Control::Receipt(receipt))
                    .await
                    .unwrap();
                let Control::Offer(manifest) = recv(&mut session).await.unwrap() else {
                    panic!("expected offer")
                };
                let store = Store::open(bob.dir.join("xfer-test"), [7; 32]).unwrap();
                let record = store
                    .offer(manifest, session.peer(), receiver.fingerprint())
                    .unwrap();
                assert!(store.put(id, 0, 0, b"unauthorized").is_err());
                assert_eq!(record.completed_bytes, 0);
                store.accept(id).unwrap();
                send(&mut session, &Control::RequestChunk { file: 0, chunk: 0 })
                    .await
                    .unwrap();
                let chunk = recv_chunk(&mut session).await.unwrap();
                store.put(id, 0, 0, &chunk[1..]).unwrap();
                assert_eq!(store.verify(id).unwrap().verified_files, 1);
                send(&mut session, &Control::Complete { id }).await.unwrap();
            },
        );
        assert_eq!(mesh::pending_count(&alice.state, &alice.user).unwrap(), 0);
    }
}
