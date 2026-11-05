import { describe, expect, it } from "vitest";
import {
  callStats,
  classifyCallOutcome,
  describeCall,
  directConversationWith,
  filterCalls,
  formatCallDuration,
  formatTalkTime,
  groupCallsByDay,
  type CallRecord,
} from "@/lib/call-history";
import { advanceCallTrack, advanceGroupTrack, type CallTrack, type GroupTrack } from "@/lib/call-history-recorder";
import { callReducer, INITIAL_CALL_STATE, type CallState } from "@/lib/call-state";
import { callMediaOf } from "@/lib/call-types";

const PEER = "11111111-2222-4333-8444-555555555555";
const CONVO = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

describe("classifyCallOutcome", () => {
  const base = { connected: false, accepted: false, endReason: null, error: null } as const;
  it("names every way a callee's call ends", () => {
    expect(classifyCallOutcome({ ...base, role: "callee", connected: true, endReason: "connection-lost" })).toBe("completed");
    expect(classifyCallOutcome({ ...base, role: "callee", endReason: "local-reject" })).toBe("declined");
    expect(classifyCallOutcome({ ...base, role: "callee", endReason: "remote-hangup" })).toBe("missed");
    expect(classifyCallOutcome({ ...base, role: "callee", error: "No answer." })).toBe("missed");
    expect(classifyCallOutcome({ ...base, role: "callee", accepted: true, error: "Accept failed" })).toBe("failed");
  });
  it("names every way a caller's call ends", () => {
    expect(classifyCallOutcome({ ...base, role: "caller", endReason: "remote-declined" })).toBe("declined");
    expect(classifyCallOutcome({ ...base, role: "caller", endReason: "remote-busy" })).toBe("busy");
    expect(classifyCallOutcome({ ...base, role: "caller", endReason: "local-hangup" })).toBe("cancelled");
    expect(classifyCallOutcome({ ...base, role: "caller", endReason: "remote-hangup" })).toBe("no_answer");
    expect(classifyCallOutcome({ ...base, role: "caller", error: "No answer." })).toBe("no_answer");
    expect(classifyCallOutcome({ ...base, role: "caller", error: "Could not reach a relay" })).toBe("failed");
    expect(classifyCallOutcome({ ...base, role: "caller", endReason: "connection-lost" })).toBe("failed");
  });
});

/** Drive the reducer and the tracker together, as CallProvider does. */
function run(actions: Array<Parameters<typeof callReducer>[1]>, start = 1_790_000_000_000, step = 10_000) {
  let state: CallState = INITIAL_CALL_STATE;
  let track: CallTrack | null = null;
  const records = [];
  let now = start;
  for (const action of actions) {
    state = callReducer(state, action);
    const out = advanceCallTrack(track, state, now, "Alice");
    track = out.track;
    if (out.record) records.push(out.record);
    now += step;
  }
  return records;
}

describe("advanceCallTrack", () => {
  it("records a completed outgoing voice call once, with when it was answered and how it was keyed", () => {
    const records = run([
      { type: "start-outgoing", callId: "c1", peerUserId: PEER, peerDeviceId: "d", media: "voice", conversationId: CONVO },
      { type: "remote-answered" },
      { type: "media-connected", safetyNumber: "1", forwardSecret: true, peerVerified: true },
      { type: "ended", reason: "local-hangup" },
      { type: "ended", reason: "remote-hangup" },
    ]);
    expect(records).toHaveLength(1);
    const [record] = records;
    expect(record).toMatchObject({
      id: "c1", direction: "outgoing", media: "voice", outcome: "completed", conversationId: CONVO,
      peerUserIds: [PEER], forwardSecret: true, peerVerified: true, failure: null,
    });
    expect(record.answeredAt! - record.startedAt).toBe(20_000);
    expect(record.endedAt - record.answeredAt!).toBe(10_000);
  });

  it("records an unanswered incoming call as missed and a rejected one as declined", () => {
    const missed = run([
      { type: "incoming", callId: "c2", peerUserId: PEER, peerDeviceId: "d", media: "video" },
      { type: "failed", error: "No answer." },
    ]);
    expect(missed[0]).toMatchObject({ direction: "incoming", outcome: "missed", answeredAt: null, failure: null });
    const declined = run([
      { type: "incoming", callId: "c3", peerUserId: PEER, peerDeviceId: "d" },
      { type: "ended", reason: "local-reject" },
    ]);
    expect(declined[0].outcome).toBe("declined");
  });

  it("keeps the failure reason only for a failed call", () => {
    const failed = run([
      { type: "start-outgoing", callId: "c4", peerUserId: PEER, peerDeviceId: "d" },
      { type: "remote-answered" },
      { type: "failed", error: "No relay between your networks" },
    ]);
    expect(failed[0]).toMatchObject({ outcome: "failed", failure: "No relay between your networks", media: "video" });
  });

  it("ignores a call it never saw live", () => {
    const state = { ...INITIAL_CALL_STATE, phase: "ended" as const, callId: "c5", role: "caller" as const, peerUserId: PEER };
    expect(advanceCallTrack(null, state, 1, "x")).toEqual({ track: null, record: null });
  });
});

describe("advanceGroupTrack", () => {
  const me = "99999999-2222-4333-8444-555555555555";
  const other = "88888888-2222-4333-8444-555555555555";
  const invite = { id: "77777777-2222-4333-8444-555555555555", conversationId: CONVO, inviterUserId: other, members: [other, me, PEER] };
  const names = { [other]: "Bob", [PEER]: "Alice" };

  it("records an incoming group call nobody joined as missed, naming the others", () => {
    let track: GroupTrack | null = null;
    ({ track } = advanceGroupTrack(track, { invite, connected: false }, { userId: me, now: 1_000, declined: false, names }));
    const { records } = advanceGroupTrack(track, { invite: null, connected: false }, { userId: me, now: 9_000, declined: false, names });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ group: true, direction: "incoming", outcome: "missed", peerName: "Bob, Alice", peerUserIds: [other, PEER] });
  });

  it("records a joined group call as completed from the moment a link connected", () => {
    let track: GroupTrack | null = null;
    ({ track } = advanceGroupTrack(track, { invite, connected: false }, { userId: me, now: 1_000, declined: false, names }));
    ({ track } = advanceGroupTrack(track, { invite, connected: true }, { userId: me, now: 4_000, declined: false, names }));
    const { records } = advanceGroupTrack(track, { invite: null, connected: false }, { userId: me, now: 64_000, declined: false, names });
    expect(records[0]).toMatchObject({ outcome: "completed", answeredAt: 4_000, endedAt: 64_000 });
  });
});

function record(partial: Partial<CallRecord>): CallRecord {
  return {
    id: crypto.randomUUID(), direction: "incoming", media: "voice", group: false, peerUserIds: [PEER], peerName: "Alice",
    conversationId: CONVO, outcome: "completed", startedAt: Date.now(), answeredAt: Date.now(), endedAt: Date.now(),
    durationSecs: 60, failure: null, forwardSecret: true, peerVerified: false, seen: true, ...partial,
  };
}

describe("presentation helpers", () => {
  it("formats durations and talk time", () => {
    expect(formatCallDuration(0)).toBe("0:00");
    expect(formatCallDuration(42)).toBe("0:42");
    expect(formatCallDuration(725)).toBe("12:05");
    expect(formatCallDuration(3729)).toBe("1:02:09");
    expect(formatTalkTime(59)).toBe("0m");
    expect(formatTalkTime(11_520)).toBe("3h 12m");
  });

  it("describes a call in words", () => {
    expect(describeCall({ direction: "incoming", media: "voice", group: false, outcome: "completed" })).toBe("Incoming voice call");
    expect(describeCall({ direction: "incoming", media: "video", group: false, outcome: "missed" })).toBe("Missed video call");
    expect(describeCall({ direction: "outgoing", media: "video", group: true, outcome: "no_answer" })).toBe("Outgoing group video call");
  });

  it("groups by day and filters by kind and name", () => {
    const now = new Date(2026, 10, 4, 15, 0).getTime();
    const today = record({ startedAt: new Date(2026, 10, 4, 9, 0).getTime(), peerName: "Alice" });
    const today2 = record({ startedAt: new Date(2026, 10, 4, 8, 0).getTime(), outcome: "missed", media: "video", peerName: "Bob" });
    const yesterday = record({ startedAt: new Date(2026, 10, 3, 20, 0).getTime(), direction: "outgoing" });
    const groups = groupCallsByDay([today, today2, yesterday], now);
    expect(groups.map((g) => [g.label, g.records.length])).toEqual([["Today", 2], ["Yesterday", 1]]);
    const all = [today, today2, yesterday];
    expect(filterCalls(all, "missed", "")).toEqual([today2]);
    expect(filterCalls(all, "outgoing", "")).toEqual([yesterday]);
    expect(filterCalls(all, "video", "")).toEqual([today2]);
    expect(filterCalls(all, "all", "bo")).toEqual([today2]);
  });

  it("computes the 7-day figures from the records alone", () => {
    const now = new Date(2026, 10, 4, 15, 0).getTime();
    const recent = [
      record({ startedAt: now - 1_000, durationSecs: 120, forwardSecret: true, peerVerified: true }),
      record({ startedAt: now - 2_000, durationSecs: 60, forwardSecret: false }),
      record({ startedAt: now - 3_000, outcome: "missed", durationSecs: 0, seen: false }),
    ];
    const old = record({ startedAt: now - 30 * 86_400_000, outcome: "missed", seen: false });
    expect(callStats([...recent, old], 7, now)).toEqual({
      total: 3, missed: 1, unseenMissed: 2, talkSecs: 180, connected: 2, forwardSecret: 1, peerVerified: 1,
    });
  });

  it("finds the direct conversation with a person", () => {
    const conversations = [
      { id: "g", conversation_type: "group", member_user_ids: [PEER, "x"], deleted_at: null },
      { id: "d", conversation_type: "direct", member_user_ids: ["me", PEER], deleted_at: null },
    ];
    expect(directConversationWith(conversations, PEER)?.id).toBe("d");
    expect(directConversationWith(conversations, "nobody")).toBeNull();
  });
});

describe("voice call wire flag", () => {
  it("reads voice only when the payload says so", () => {
    expect(callMediaOf({ media: "voice" })).toBe("voice");
    expect(callMediaOf({})).toBe("video");
    expect(callMediaOf({ media: "audio" })).toBe("video");
    expect(callMediaOf(null)).toBe("video");
  });

  it("carries the media kind and conversation through the reducer", () => {
    const s = callReducer(INITIAL_CALL_STATE, { type: "incoming", callId: "c", peerUserId: PEER, peerDeviceId: "d", media: "voice", conversationId: CONVO });
    expect([s.media, s.conversationId]).toEqual(["voice", CONVO]);
    const ended = callReducer(callReducer(s, { type: "ended", reason: "local-reject" }), { type: "ended", reason: "remote-hangup" });
    expect(ended.endReason).toBe("local-reject");
  });
});
