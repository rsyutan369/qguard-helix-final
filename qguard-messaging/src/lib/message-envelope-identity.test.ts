import { describe, expect, it } from "vitest";
import { parseMessageAad } from "@/lib/message-envelope-identity";
import { bytesToBytea } from "@/lib/encoding";

/** Exactly the layout written by `message_crypto::message_aad` in Rust. */
function aad(fields: {
  messageId: string;
  conversationId: string;
  senderUserId: string;
  recipientUserId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  counter: number;
}): number[] {
  const text = [
    "QGM1",
    fields.messageId,
    fields.conversationId,
    fields.senderUserId,
    fields.recipientUserId,
    fields.senderDeviceId,
    fields.recipientDeviceId,
    String(fields.counter),
  ].join("|");
  return Array.from(new TextEncoder().encode(text));
}

// The real shape from the reported account: the Android device that both sent
// the message and had its row retired later.
const REAL = {
  messageId: "c038a008-9f30-49a9-8396-c6152a3630d9",
  conversationId: "6687b4b1-4632-45ae-baa5-dc4832638ebd",
  senderUserId: "6e20f30c-9917-45db-9903-7e2c84d05aa4",
  recipientUserId: "f3d07da9-30d6-4a00-b392-3ca73bf38b5f",
  senderDeviceId: "533b05f2-451f-413e-8ea2-2a4910be7fc4",
  recipientDeviceId: "a01dfbba-05c2-4714-8996-af3974e4b585",
  counter: 0,
};

describe("parseMessageAad", () => {
  it("recovers the device ids that the FK nulled out of the row", () => {
    // The reported bug: retiring a device set sender_device_id to NULL on every
    // message it had already sent, so the rebuilt signable carried "" where the
    // sender had signed a device id. The AAD still holds the signed value.
    const parsed = parseMessageAad(aad(REAL));
    expect(parsed?.sender_device_id).toBe(REAL.senderDeviceId);
    expect(parsed?.recipient_device_id).toBe(REAL.recipientDeviceId);
    expect(parsed?.message_id).toBe(REAL.messageId);
    expect(parsed?.counter).toBe(0);
  });

  it("accepts the bytea hex form Postgres returns", () => {
    const parsed = parseMessageAad(bytesToBytea(aad(REAL)));
    expect(parsed?.sender_user_id).toBe(REAL.senderUserId);
    expect(parsed?.recipient_user_id).toBe(REAL.recipientUserId);
  });

  it("reads a non-zero ratchet counter", () => {
    expect(parseMessageAad(aad({ ...REAL, counter: 41 }))?.counter).toBe(41);
  });

  it("returns null rather than a shifted identity when a field is missing", () => {
    // A short read must not slide every field one position left; that would
    // yield a confidently wrong sender rather than an honest fallback.
    const short = Array.from(new TextEncoder().encode("QGM1|a|b|c|d|e|f"));
    expect(parseMessageAad(short)).toBeNull();
  });

  it("rejects a foreign or unversioned prefix", () => {
    const wrong = Array.from(new TextEncoder().encode("QGM2|a|b|c|d|e|f|0"));
    expect(parseMessageAad(wrong)).toBeNull();
    const none = Array.from(new TextEncoder().encode("a|b|c|d|e|f|g|0"));
    expect(parseMessageAad(none)).toBeNull();
  });

  it("reads a ratchet envelope's QGM2 AAD (same fields plus the header digest)", () => {
    const digest = "ab".repeat(32);
    const text = ["QGM2", REAL.messageId, REAL.conversationId, REAL.senderUserId, REAL.recipientUserId,
      REAL.senderDeviceId, REAL.recipientDeviceId, "7", digest].join("|");
    const parsed = parseMessageAad(Array.from(new TextEncoder().encode(text)));
    expect(parsed?.message_id).toBe(REAL.messageId);
    expect(parsed?.recipient_device_id).toBe(REAL.recipientDeviceId);
    expect(parsed?.counter).toBe(7);
  });

  it("rejects a QGM2 AAD whose header digest is not a SHA3-256 hex digest", () => {
    const base = ["QGM2", "m", "c", "su", "ru", "sd", "rd", "0"];
    for (const digest of ["", "zz".repeat(32), "ab".repeat(31), "AB".repeat(32)]) {
      expect(parseMessageAad(Array.from(new TextEncoder().encode([...base, digest].join("|"))))).toBeNull();
    }
    // A QGM1 tag with a ninth field is not a v1 AAD either.
    expect(parseMessageAad(Array.from(new TextEncoder().encode(["QGM1", ...base.slice(1), "ab".repeat(32)].join("|"))))).toBeNull();
  });

  it("rejects a non-numeric counter", () => {
    const bad = Array.from(new TextEncoder().encode(`QGM1|a|b|c|d|e|f|nope`));
    expect(parseMessageAad(bad)).toBeNull();
  });

  it("returns null for an absent or unreadable aad", () => {
    expect(parseMessageAad(null)).toBeNull();
    expect(parseMessageAad([])).toBeNull();
    expect(parseMessageAad("")).toBeNull();
    // Invalid UTF-8 must not throw.
    expect(parseMessageAad([0xff, 0xfe, 0xfd])).toBeNull();
  });
});
