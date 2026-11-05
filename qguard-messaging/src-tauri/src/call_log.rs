//! Call history: recent, missed and declined calls, kept ONLY on this device.
//!
//! Nothing here touches the relay. The call engine already learns everything a
//! history entry holds (who, when, how it ended, how its key was agreed); this
//! module just keeps it, sealed with AES-256-GCM under the account's device
//! storage key (the same key that seals the workspace locks), in one file per
//! account (`AppState::{load,save}_call_log`).
//!
//! The rules the frontend cannot bend:
//! * every field is validated and normalised here — ids must be UUIDs, the
//!   enumerations closed, text bounded, times ordered;
//! * the talk time is computed here from the answered/ended times, never taken
//!   from the caller of the command;
//! * a missed call starts unseen (it drives the missed-call badge); every other
//!   outcome is recorded as seen;
//! * the list is newest first, one entry per call id, capped at
//!   [`MAX_RECORDS`] (the oldest drop off).

use serde::{Deserialize, Serialize};

use crate::error::{QGuardError, Result};

/// The most entries kept per account.
pub const MAX_RECORDS: usize = 1000;
const MAX_NAME_CHARS: usize = 120;
const MAX_FAILURE_CHARS: usize = 240;
const MAX_PEERS: usize = 8;
/// No single call is recorded as longer than this.
const MAX_CALL_MS: i64 = 48 * 60 * 60 * 1000;
/// 2020-01-01 UTC, in ms: anything earlier is a clock or encoding error.
const EARLIEST_MS: i64 = 1_577_836_800_000;

pub const DIRECTIONS: [&str; 2] = ["outgoing", "incoming"];
pub const MEDIA: [&str; 2] = ["voice", "video"];
/// How a call ended, from this device's point of view.
pub const OUTCOMES: [&str; 7] = ["completed", "missed", "declined", "no_answer", "busy", "cancelled", "failed"];

/// One call, as stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRecord {
    /// The call id the engine used (a UUID).
    pub id: String,
    pub direction: String,
    pub media: String,
    pub group: bool,
    /// The other people on the call (user ids).
    pub peer_user_ids: Vec<String>,
    /// The name shown for them when the call happened.
    pub peer_name: String,
    pub conversation_id: Option<String>,
    pub outcome: String,
    /// Unix milliseconds.
    pub started_at: i64,
    pub answered_at: Option<i64>,
    pub ended_at: i64,
    /// Seconds between answer and end; 0 for a call that never connected.
    pub duration_secs: u64,
    /// Why a call failed, in the engine's words.
    pub failure: Option<String>,
    /// How the media key was agreed, as the core reported once media connected
    /// (absent when the call never connected).
    pub forward_secret: Option<bool>,
    pub peer_verified: Option<bool>,
    /// Whether the user has looked at it (only ever false for a missed call).
    #[serde(default = "default_true")]
    pub seen: bool,
}

fn default_true() -> bool {
    true
}

/// What the frontend submits. Duration and `seen` are not accepted: both are
/// derived here.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRecordInput {
    pub id: String,
    pub direction: String,
    pub media: String,
    #[serde(default)]
    pub group: bool,
    pub peer_user_ids: Vec<String>,
    pub peer_name: String,
    pub conversation_id: Option<String>,
    pub outcome: String,
    pub started_at: i64,
    pub answered_at: Option<i64>,
    pub ended_at: i64,
    pub failure: Option<String>,
    pub forward_secret: Option<bool>,
    pub peer_verified: Option<bool>,
}

fn invalid(message: impl Into<String>) -> QGuardError {
    QGuardError::InvalidInput(message.into())
}

fn checked_uuid(value: &str, what: &str) -> Result<String> {
    uuid::Uuid::parse_str(value.trim())
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| invalid(format!("{what} is not a valid id")))
}

fn one_of(value: &str, allowed: &[&str], what: &str) -> Result<String> {
    allowed
        .iter()
        .find(|candidate| **candidate == value)
        .map(|candidate| candidate.to_string())
        .ok_or_else(|| invalid(format!("unknown {what}")))
}

/// Trim, drop control characters, and cut to `max` characters.
fn clean_text(value: &str, max: usize) -> String {
    value.trim().chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

/// Validate and normalise a submitted record.
pub fn validate(input: CallRecordInput) -> Result<CallRecord> {
    let id = checked_uuid(&input.id, "call")?;
    let direction = one_of(&input.direction, &DIRECTIONS, "call direction")?;
    let media = one_of(&input.media, &MEDIA, "call type")?;
    let outcome = one_of(&input.outcome, &OUTCOMES, "call outcome")?;
    if input.peer_user_ids.is_empty() || input.peer_user_ids.len() > MAX_PEERS {
        return Err(invalid("a call needs between 1 and 8 other people"));
    }
    let mut peer_user_ids = Vec::with_capacity(input.peer_user_ids.len());
    for peer in &input.peer_user_ids {
        let peer = checked_uuid(peer, "person")?;
        if !peer_user_ids.contains(&peer) {
            peer_user_ids.push(peer);
        }
    }
    let conversation_id = match input.conversation_id.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => Some(checked_uuid(value, "conversation")?),
        _ => None,
    };
    if input.started_at < EARLIEST_MS {
        return Err(invalid("call start time is out of range"));
    }
    if input.ended_at < input.started_at || input.ended_at - input.started_at > MAX_CALL_MS {
        return Err(invalid("call end time is out of range"));
    }
    let answered_at = match input.answered_at {
        Some(at) if at < input.started_at || at > input.ended_at => return Err(invalid("call answer time is out of range")),
        other => other,
    };
    // Only a completed call was answered, and a completed call always was.
    let answered_at = if outcome == "completed" { answered_at.or(Some(input.started_at)) } else { None };
    let duration_secs = answered_at.map_or(0, |at| ((input.ended_at - at) / 1000) as u64);
    let peer_name = match clean_text(&input.peer_name, MAX_NAME_CHARS) {
        name if name.is_empty() => "Secure contact".to_string(),
        name => name,
    };
    let failure = input
        .failure
        .as_deref()
        .map(|text| clean_text(text, MAX_FAILURE_CHARS))
        .filter(|text| !text.is_empty() && outcome == "failed");
    // Key-agreement facts only exist for a call whose media connected.
    let (forward_secret, peer_verified) =
        if answered_at.is_some() { (input.forward_secret, input.peer_verified) } else { (None, None) };
    Ok(CallRecord {
        id,
        direction,
        media,
        group: input.group,
        peer_user_ids,
        peer_name,
        conversation_id,
        seen: outcome != "missed",
        outcome,
        started_at: input.started_at,
        answered_at,
        ended_at: input.ended_at,
        duration_secs,
        failure,
        forward_secret,
        peer_verified,
    })
}

/// Put `record` into `list`: replaces an entry with the same id (keeping it
/// seen if it already was), newest first, capped.
pub fn upsert(mut list: Vec<CallRecord>, mut record: CallRecord) -> Vec<CallRecord> {
    if let Some(existing) = list.iter().find(|entry| entry.id == record.id) {
        record.seen = record.seen || existing.seen;
    }
    list.retain(|entry| entry.id != record.id);
    list.push(record);
    sort_newest_first(&mut list);
    list.truncate(MAX_RECORDS);
    list
}

pub fn sort_newest_first(list: &mut [CallRecord]) {
    list.sort_by(|a, b| b.started_at.cmp(&a.started_at).then_with(|| a.id.cmp(&b.id)));
}

/// Remove the entries with these ids; returns how many went.
pub fn remove(list: &mut Vec<CallRecord>, ids: &[String]) -> usize {
    let before = list.len();
    list.retain(|entry| !ids.contains(&entry.id));
    before - list.len()
}

/// Mark every missed call seen; returns how many changed.
pub fn mark_seen(list: &mut [CallRecord]) -> usize {
    let mut changed = 0;
    for entry in list.iter_mut().filter(|entry| !entry.seen) {
        entry.seen = true;
        changed += 1;
    }
    changed
}

pub fn unseen_missed(list: &[CallRecord]) -> usize {
    list.iter().filter(|entry| entry.outcome == "missed" && !entry.seen).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "11111111-2222-4333-8444-555555555555";
    const CONVO: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const T0: i64 = 1_790_000_000_000;

    fn input(id: u8, outcome: &str) -> CallRecordInput {
        CallRecordInput {
            id: format!("00000000-0000-4000-8000-0000000000{id:02x}"),
            direction: "incoming".to_string(),
            media: "voice".to_string(),
            group: false,
            peer_user_ids: vec![PEER.to_string()],
            peer_name: "  Alice\u{0007} ".to_string(),
            conversation_id: Some(CONVO.to_string()),
            outcome: outcome.to_string(),
            started_at: T0 + i64::from(id) * 1000,
            answered_at: Some(T0 + i64::from(id) * 1000 + 5_000),
            ended_at: T0 + i64::from(id) * 1000 + 65_000,
            failure: Some("ICE failed".to_string()),
            forward_secret: Some(true),
            peer_verified: Some(false),
        }
    }

    #[test]
    fn a_completed_call_gets_its_talk_time_from_its_own_timestamps() {
        let record = validate(input(1, "completed")).unwrap();
        assert_eq!(record.duration_secs, 60);
        assert_eq!(record.peer_name, "Alice", "trimmed, control characters dropped");
        assert_eq!((record.forward_secret, record.peer_verified), (Some(true), Some(false)));
        assert!(record.failure.is_none(), "only a failed call keeps a failure reason");
        assert!(record.seen);
    }

    #[test]
    fn a_call_that_never_connected_has_no_answer_time_duration_or_key_facts() {
        for outcome in ["missed", "declined", "no_answer", "busy", "cancelled"] {
            let record = validate(input(2, outcome)).unwrap();
            assert_eq!((record.answered_at, record.duration_secs), (None, 0), "{outcome}");
            assert_eq!((record.forward_secret, record.peer_verified), (None, None), "{outcome}");
        }
        assert!(!validate(input(2, "missed")).unwrap().seen, "a missed call starts unseen");
        assert_eq!(validate(input(2, "failed")).unwrap().failure.as_deref(), Some("ICE failed"));
    }

    #[test]
    fn bad_input_is_refused() {
        let mut bad = input(3, "completed");
        bad.id = "not-a-uuid".to_string();
        assert!(validate(bad).is_err());
        for (field, value) in [("direction", "sideways"), ("media", "fax"), ("outcome", "great")] {
            let mut bad = input(3, "completed");
            match field {
                "direction" => bad.direction = value.to_string(),
                "media" => bad.media = value.to_string(),
                _ => bad.outcome = value.to_string(),
            }
            assert!(validate(bad).is_err(), "{field}");
        }
        let mut bad = input(3, "completed");
        bad.ended_at = bad.started_at - 1;
        assert!(validate(bad).is_err());
        let mut bad = input(3, "completed");
        bad.answered_at = Some(bad.ended_at + 1);
        assert!(validate(bad).is_err());
        let mut bad = input(3, "completed");
        bad.peer_user_ids = vec![];
        assert!(validate(bad).is_err());
        let mut bad = input(3, "completed");
        bad.started_at = 1_000;
        bad.answered_at = None;
        bad.ended_at = 2_000;
        assert!(validate(bad).is_err());
        let mut long = input(3, "completed");
        long.peer_name = "x".repeat(500);
        assert_eq!(validate(long).unwrap().peer_name.chars().count(), MAX_NAME_CHARS);
    }

    #[test]
    fn upsert_keeps_one_entry_per_call_newest_first_and_capped() {
        let mut list = Vec::new();
        for id in 1..=5u8 {
            list = upsert(list, validate(input(id, "completed")).unwrap());
        }
        assert_eq!(list.iter().map(|r| r.started_at).collect::<Vec<_>>(), (1..=5).rev().map(|id| T0 + id * 1000).collect::<Vec<_>>());
        // The same call recorded again replaces, never duplicates.
        list = upsert(list, validate(input(3, "completed")).unwrap());
        assert_eq!(list.len(), 5);

        let mut many = Vec::new();
        for n in 0..(MAX_RECORDS + 20) {
            let mut record = validate(input(1, "completed")).unwrap();
            record.id = uuid::Uuid::new_v4().to_string();
            record.started_at = T0 + n as i64;
            many = upsert(many, record);
        }
        assert_eq!(many.len(), MAX_RECORDS);
        assert_eq!(many.last().unwrap().started_at, T0 + 20, "the oldest dropped off");
    }

    #[test]
    fn missed_calls_count_until_seen_and_a_rerecord_never_unsees_them() {
        let mut list = upsert(Vec::new(), validate(input(1, "missed")).unwrap());
        list = upsert(list, validate(input(2, "missed")).unwrap());
        list = upsert(list, validate(input(3, "completed")).unwrap());
        assert_eq!(unseen_missed(&list), 2);
        assert_eq!(mark_seen(&mut list), 2);
        assert_eq!(unseen_missed(&list), 0);
        list = upsert(list, validate(input(1, "missed")).unwrap());
        assert_eq!(unseen_missed(&list), 0, "already seen stays seen");
        let ids = vec![list[0].id.clone()];
        assert_eq!(remove(&mut list, &ids), 1);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn records_written_before_the_seen_flag_read_as_seen() {
        let record = validate(input(1, "completed")).unwrap();
        let mut json = serde_json::to_value(&record).unwrap();
        json.as_object_mut().unwrap().remove("seen");
        let back: CallRecord = serde_json::from_value(json).unwrap();
        assert!(back.seen);
    }
}
