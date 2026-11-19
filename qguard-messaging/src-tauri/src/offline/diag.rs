//! Connection diagnostics: a bounded, in-memory log of what the transport and
//! session layers actually did (dial, handshake, channel open and close,
//! message sent / acknowledged / received, heartbeat, transfer steps).
//!
//! Every entry is recorded at the point where the event happens. Nothing is
//! derived, estimated or replayed for the view. Entries carry a millisecond
//! timestamp, a per-process event id, the first 16 hex digits of the session
//! binding (the same value on both devices for one session) and the first 8
//! of the peer fingerprint, so two devices' logs can be lined up. They never
//! carry message text, file names, keys or full fingerprints, and they are
//! not written to disk.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use serde::Serialize;
use tauri::{AppHandle, Manager};

use super::network::Runtime;

const MAX_EVENTS: usize = 400;
const MAX_DETAIL: usize = 200;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkEvent {
    id: u64,
    at_ms: i64,
    kind: &'static str,
    /// First 8 hex digits of the peer's device fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    /// First 16 hex digits of the authenticated session binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Default)]
pub(crate) struct Events {
    next: AtomicU64,
    log: Mutex<VecDeque<LinkEvent>>,
}

/// What an event is about. Every field is optional.
#[derive(Default, Clone, Copy)]
pub(super) struct Subject<'a> {
    pub peer: Option<&'a str>,
    pub session: Option<&'a str>,
    pub transport: Option<&'static str>,
}

impl<'a> Subject<'a> {
    pub fn peer(peer: &'a str) -> Self {
        Self { peer: Some(peer), ..Self::default() }
    }

    pub fn link(peer: &'a str, session: &'a str, bluetooth: bool) -> Self {
        Self { peer: Some(peer), session: Some(session), transport: Some(transport(bluetooth)) }
    }
}

pub(super) fn transport(bluetooth: bool) -> &'static str {
    if bluetooth {
        "bluetooth"
    } else {
        "lan"
    }
}

/// The session id shown in diagnostics and in the peer list.
pub(super) fn session_id(binding: &[u8; 32]) -> String {
    hex::encode(&binding[..8])
}

impl Events {
    fn push(&self, kind: &'static str, subject: Subject<'_>, detail: Option<String>) {
        let event = LinkEvent {
            id: self.next.fetch_add(1, Ordering::Relaxed) + 1,
            at_ms: chrono::Utc::now().timestamp_millis(),
            kind,
            peer: subject.peer.map(|peer| peer.chars().take(8).collect()),
            session: subject.session.map(str::to_owned),
            transport: subject.transport,
            detail: detail.map(|text| text.chars().filter(|c| !c.is_control()).take(MAX_DETAIL).collect()),
        };
        if let Ok(mut log) = self.log.lock() {
            if log.len() >= MAX_EVENTS {
                log.pop_front();
            }
            log.push_back(event);
        }
    }

    /// Newest last.
    pub(super) fn list(&self) -> Vec<LinkEvent> {
        self.log.lock().map(|log| log.iter().cloned().collect()).unwrap_or_default()
    }

    pub(super) fn clear(&self) {
        if let Ok(mut log) = self.log.lock() {
            log.clear();
        }
    }
}

pub(super) fn record(app: &AppHandle, kind: &'static str, subject: Subject<'_>) {
    app.state::<Runtime>().events.push(kind, subject, None);
}

pub(super) fn record_detail(app: &AppHandle, kind: &'static str, subject: Subject<'_>, detail: impl Into<String>) {
    app.state::<Runtime>().events.push(kind, subject, Some(detail.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_is_bounded_ordered_and_carries_only_prefixes() {
        let events = Events::default();
        let fingerprint = "ab".repeat(32);
        for index in 0..(MAX_EVENTS + 25) {
            events.push(
                "message_sent",
                Subject { peer: Some(&fingerprint), session: Some("0011223344556677"), transport: Some("bluetooth") },
                Some(format!("n={index}\u{7}")),
            );
        }
        let list = events.list();
        assert_eq!(list.len(), MAX_EVENTS);
        assert!(list.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert_eq!(list.last().unwrap().id, (MAX_EVENTS + 25) as u64);
        assert_eq!(list[0].peer.as_deref(), Some("abababab"));
        assert!(!list[0].detail.as_deref().unwrap().contains('\u{7}'));
        events.clear();
        assert!(events.list().is_empty());
    }
}
