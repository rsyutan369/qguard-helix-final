mod alerts;
mod avatar;
mod channel;
mod diag;
mod background;
pub(crate) mod commands;
pub(crate) mod enrollment;
mod lan;
mod link;
mod mesh;
mod network;
mod pairing;
pub(crate) mod principal;
mod profile;
mod relay;
mod relay_net;
mod session;
mod smart;
mod transfer;
mod wire;
mod xfer;
pub(crate) mod xfer_open;

/// Account-scoped offline records sealed under the device storage key.
pub(crate) fn sealed_documents() -> [&'static str; 8] {
    [avatar::DOC, session::DOC, profile::TRUST_DOC, profile::XFER_KEY_DOC, mesh::DOC, enrollment::DOC, relay::DOC, relay::KEY_DOC]
}
