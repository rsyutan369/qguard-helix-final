import { describe, expect, it } from "vitest";
import {
  countUnreadGroups,
  effectiveOriginalSender,
  unreadMessageGroupId,
  type UnreadEnvelope,
  type UnreadReadState,
} from "@/lib/chat-unread";

const ME = "user-me";
const PEER = "user-peer";
const NOW = new Date("2026-07-18T12:00:00.000Z").getTime();

function envelope(overrides: Partial<UnreadEnvelope> = {}): UnreadEnvelope {
  return {
    id: "env-1",
    client_message_id: "cmid-1",
    recipient_user_id: ME,
    sender_user_id: PEER,
    original_sender_user_id: PEER,
    sync_original_sender_user_id: null,
    deleted_at: null,
    expires_at: null,
    lifecycle: {},
    ...overrides,
  };
}

const noState = () => undefined;
const readState = (): UnreadReadState => ({ first_read_at: "2026-07-18T11:00:00.000Z", hidden_at: null });
const hiddenState = (): UnreadReadState => ({ first_read_at: null, hidden_at: "2026-07-18T11:00:00.000Z" });

describe("effectiveOriginalSender", () => {
  it("uses the sync-preserved original sender over the rewrapper column", () => {
    // A peer rewrapped MY message for my other device: the column says PEER,
    // but the sealed-sender sync metadata preserves ME as the true author.
    const rewrappedOwn = envelope({ sender_user_id: PEER, original_sender_user_id: null, sync_original_sender_user_id: ME });
    expect(effectiveOriginalSender(rewrappedOwn)).toBe(ME);
  });

  it("falls back to the original-envelope field, then the column", () => {
    expect(effectiveOriginalSender(envelope({ original_sender_user_id: PEER, sync_original_sender_user_id: null }))).toBe(PEER);
    expect(effectiveOriginalSender(envelope({ original_sender_user_id: null, sync_original_sender_user_id: null }))).toBe(PEER);
    expect(effectiveOriginalSender(envelope({ original_sender_user_id: "  ", sync_original_sender_user_id: "" }))).toBe(PEER);
  });
});

describe("countUnreadGroups", () => {
  it("counts a fresh peer message with no read state", () => {
    const unread = countUnreadGroups([envelope()], ME, noState, NOW);
    expect([...unread]).toEqual(["cmid-1"]);
  });

  it("does not count a peer message that has been read or hidden", () => {
    expect(countUnreadGroups([envelope()], ME, readState, NOW).size).toBe(0);
    expect(countUnreadGroups([envelope()], ME, hiddenState, NOW).size).toBe(0);
  });

  it("REGRESSION: never counts a user's own message rewrapped by a peer for another device", () => {
    // syncMissingDeviceEnvelopes writes recipient=ME, sender_user_id=PEER (the
    // rewrapper), sync_original_sender_user_id=ME. With the raw column this was
    // counted as unread and could never clear (own messages are never read).
    const rewrappedOwn = envelope({
      recipient_user_id: ME,
      sender_user_id: PEER,
      original_sender_user_id: null,
      sync_original_sender_user_id: ME,
    });
    expect(countUnreadGroups([rewrappedOwn], ME, noState, NOW).size).toBe(0);
  });

  it("does not count the user's own local-archive copy", () => {
    const ownArchive = envelope({ recipient_user_id: ME, sender_user_id: ME, original_sender_user_id: ME });
    expect(countUnreadGroups([ownArchive], ME, noState, NOW).size).toBe(0);
  });

  it("STILL counts a peer message that MY device rewrapped for my other device", () => {
    // The inverse: I rewrapped a PEER's message; the column says ME but the
    // sync metadata preserves PEER as the author, so it stays unread.
    const rewrappedPeer = envelope({
      recipient_user_id: ME,
      sender_user_id: ME,
      original_sender_user_id: null,
      sync_original_sender_user_id: PEER,
    });
    expect([...countUnreadGroups([rewrappedPeer], ME, noState, NOW)]).toEqual(["cmid-1"]);
  });

  it("collapses device-copies of one message into a single unread group", () => {
    const copyA = envelope({ id: "env-a", client_message_id: "cmid-9", recipient_user_id: ME });
    const copyB = envelope({ id: "env-b", client_message_id: "cmid-9", recipient_user_id: ME });
    expect(countUnreadGroups([copyA, copyB], ME, noState, NOW).size).toBe(1);
  });

  it("ignores messages not addressed to me", () => {
    expect(countUnreadGroups([envelope({ recipient_user_id: PEER })], ME, noState, NOW).size).toBe(0);
  });

  it("ignores deleted, control, and expired envelopes", () => {
    expect(countUnreadGroups([envelope({ deleted_at: "2026-07-18T10:00:00.000Z" })], ME, noState, NOW).size).toBe(0);
    expect(countUnreadGroups([envelope({ lifecycle: { control_type: "reaction" } })], ME, noState, NOW).size).toBe(0);
    expect(countUnreadGroups([envelope({ expires_at: "2026-07-18T11:00:00.000Z" })], ME, noState, NOW).size).toBe(0);
  });

  it("still counts a disappearing message whose expiry is in the future", () => {
    expect(countUnreadGroups([envelope({ expires_at: "2026-07-18T13:00:00.000Z" })], ME, noState, NOW).size).toBe(1);
  });

  it("falls back to the envelope id when there is no client_message_id", () => {
    const legacy = envelope({ client_message_id: null, id: "raw-env-id" });
    expect(unreadMessageGroupId(legacy)).toBe("raw-env-id");
    expect([...countUnreadGroups([legacy], ME, noState, NOW)]).toEqual(["raw-env-id"]);
  });
});
