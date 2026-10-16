import { describe, expect, it } from "vitest";
import { bytesToBytea } from "@/lib/encoding";
import {
  attributedSenderUserId,
  checkEnvelopeRow,
  describeRejectedEnvelopes,
  screenEnvelopeRows,
} from "@/lib/envelope-integrity";

const ME = "user-me";
const PEER = "user-peer";
const THIRD = "user-third";
const CONVERSATION = "conv-1";

/** Exactly the layout written by `message_crypto::message_aad` in Rust. */
function aad(fields: { messageId: string; conversationId?: string; sender?: string; recipient?: string }): string {
  const text = [
    "QGM1",
    fields.messageId,
    fields.conversationId ?? CONVERSATION,
    fields.sender ?? PEER,
    fields.recipient ?? ME,
    "device-a",
    "device-b",
    "0",
  ].join("|");
  return bytesToBytea(Array.from(new TextEncoder().encode(text)));
}

function row(id: string, overrides: Partial<{
  conversation_id: string;
  recipient_user_id: string;
  sender_user_id: string;
  aad: unknown;
  sealed_sender_envelope: unknown;
}> = {}) {
  return {
    id,
    conversation_id: CONVERSATION,
    recipient_user_id: ME,
    sender_user_id: PEER,
    aad: aad({ messageId: id }),
    sealed_sender_envelope: {},
    ...overrides,
  };
}

describe("checkEnvelopeRow", () => {
  it("accepts a row that sits where its envelope was signed to be", () => {
    const verdict = checkEnvelopeRow(row("m1"));
    expect(verdict.ok).toBe(true);
    expect(verdict.signed?.message_id).toBe("m1");
  });

  it("refuses a genuine envelope copied into a new row", () => {
    // The replay: every signed byte is authentic, only the row id is new.
    const verdict = checkEnvelopeRow(row("m1-copy", { aad: aad({ messageId: "m1" }) }));
    expect(verdict).toMatchObject({ ok: false, reason: "replayed_copy" });
  });

  it("refuses a genuine envelope moved into another conversation", () => {
    const verdict = checkEnvelopeRow(row("m1", { conversation_id: "conv-2" }));
    expect(verdict).toMatchObject({ ok: false, reason: "moved_between_conversations" });
  });

  it("refuses an envelope whose row names a different recipient than was signed", () => {
    const verdict = checkEnvelopeRow(row("m1", { recipient_user_id: THIRD }));
    expect(verdict).toMatchObject({ ok: false, reason: "recipient_mismatch" });
  });

  it("passes an unparseable AAD through without calling it verified", () => {
    // Nothing to compare here; the Rust core decides whether it opens.
    expect(checkEnvelopeRow(row("m1", { aad: null }))).toEqual({ ok: true, signed: null });
    expect(checkEnvelopeRow(row("m1", { aad: bytesToBytea([1, 2, 3]) }))).toEqual({ ok: true, signed: null });
  });
});

describe("screenEnvelopeRows", () => {
  it("keeps genuine rows, drops copies, and never lets one row id through twice", () => {
    const genuine = row("m1");
    const replay = row("m1-again", { aad: aad({ messageId: "m1" }) });
    const second = row("m2");
    const duplicate = row("m2");
    const legacy = row("m3", { aad: null });

    const result = screenEnvelopeRows([genuine, replay, second, duplicate, legacy]);

    expect(result.accepted.map((item) => item.id)).toEqual(["m1", "m2", "m3"]);
    expect(result.rejected.map((item) => [item.row.id, item.reason])).toEqual([
      ["m1-again", "replayed_copy"],
      ["m2", "duplicate_row"],
    ]);
    // Position-verified means compared against a signature, which the legacy
    // row was not.
    expect([...result.positionVerified].sort()).toEqual(["m1", "m2"]);
  });

  it("refuses a replay even when the original is not in the page", () => {
    // The original may have been deleted; a copy of it is still not a message.
    const result = screenEnvelopeRows([row("resurrected", { aad: aad({ messageId: "deleted-original" }) })]);
    expect(result.accepted).toHaveLength(0);
    expect(result.rejected).toHaveLength(1);
  });

  it("handles an empty page", () => {
    const result = screenEnvelopeRows([]);
    expect(result.accepted).toEqual([]);
    expect(result.rejected).toEqual([]);
    expect(result.positionVerified.size).toBe(0);
  });
});

describe("attributedSenderUserId", () => {
  it("names the signed sender on someone else's envelope", () => {
    expect(attributedSenderUserId(row("m1"), ME)).toBe(PEER);
  });

  it("ignores an unsigned author note on an envelope this account did not sign", () => {
    // The misattribution: a peer's genuine message carrying a note that names
    // a third person. The note is not signed by anyone.
    const forged = row("m1", { sealed_sender_envelope: { original_sender_user_id: THIRD, sync_original_sender_user_id: THIRD } });
    expect(attributedSenderUserId(forged, ME)).toBe(PEER);
  });

  it("ignores the unsigned sender column too", () => {
    const forged = row("m1", { sender_user_id: THIRD });
    expect(attributedSenderUserId(forged, ME)).toBe(PEER);
  });

  it("believes the author note on an envelope this account's own device re-sealed", () => {
    // Trusted-device sync: signed by me, carrying the peer's message.
    const synced = row("m1", {
      sender_user_id: ME,
      aad: aad({ messageId: "m1", sender: ME }),
      sealed_sender_envelope: { sync_original_sender_user_id: PEER },
    });
    expect(attributedSenderUserId(synced, ME)).toBe(PEER);
  });

  it("names this account on its own messages", () => {
    const mine = row("m1", {
      sender_user_id: ME,
      recipient_user_id: PEER,
      aad: aad({ messageId: "m1", sender: ME, recipient: PEER }),
      sealed_sender_envelope: { original_sender_user_id: ME },
    });
    expect(attributedSenderUserId(mine, ME)).toBe(ME);
    expect(attributedSenderUserId({ ...mine, sealed_sender_envelope: {} }, ME)).toBe(ME);
  });

  it("falls back to the row's own fields when there is no signed identity to read", () => {
    expect(attributedSenderUserId(row("m1", { aad: null }), ME)).toBe(PEER);
    expect(attributedSenderUserId(row("m1", { aad: null, sealed_sender_envelope: { original_sender_user_id: THIRD } }), ME)).toBe(THIRD);
  });
});

describe("describeRejectedEnvelopes", () => {
  it("says nothing when nothing was refused", () => {
    expect(describeRejectedEnvelopes(0)).toBeNull();
    expect(describeRejectedEnvelopes(-1)).toBeNull();
  });

  it("counts what was refused", () => {
    expect(describeRejectedEnvelopes(1)).toContain("1 message copy was ignored");
    expect(describeRejectedEnvelopes(3)).toContain("3 message copies were ignored");
  });
});
