import { describe, expect, it } from "vitest";
import { deriveReadState, type ExistingReadState, type ReadStateMessage } from "@/lib/chat-read-state";

const ME = "user-me";
const PEER = "user-peer";
const READ_AT = "2026-07-16T12:00:00.000Z";

function peerText(overrides: Partial<ReadStateMessage> = {}): ReadStateMessage {
  return {
    senderUserId: PEER,
    viewOnce: false,
    hasAttachment: false,
    status: "decrypted",
    authenticated: true,
    threatScore: 0,
    ...overrides,
  };
}

describe("deriveReadState", () => {
  it("marks a freshly rendered peer message as a NEW read", () => {
    const decision = deriveReadState(peerText(), undefined, ME, READ_AT);
    expect(decision.nextReadAt).toBe(READ_AT);
    expect(decision.newRead).toBe(true);
    expect(decision.changed).toBe(true);
  });

  it("never marks my own message as read (and it is not a new read)", () => {
    const decision = deriveReadState(peerText({ senderUserId: ME }), undefined, ME, READ_AT);
    expect(decision.nextReadAt).toBeNull();
    expect(decision.newRead).toBe(false);
  });

  it("does not re-fire a read once first_read_at is already recorded", () => {
    const existing: ExistingReadState = {
      firstReadAt: "2026-07-16T11:00:00.000Z",
      verificationState: "valid",
      threatScore: 0,
    };
    const decision = deriveReadState(peerText(), existing, ME, READ_AT);
    // The original timestamp is preserved (not bumped), and this is NOT a new
    // read — so it must not trigger another unread-badge refresh.
    expect(decision.nextReadAt).toBe("2026-07-16T11:00:00.000Z");
    expect(decision.newRead).toBe(false);
    expect(decision.changed).toBe(false);
  });

  it("marks an undecryptable failed/sealed peer stub as read so it can't hold the badge hostage", () => {
    const failedStub = peerText({ status: "failed", authenticated: false });
    const decision = deriveReadState(failedStub, undefined, ME, READ_AT);
    expect(decision.newRead).toBe(true);
    expect(decision.nextReadAt).toBe(READ_AT);
    // A stub keeps a neutral "pending" verdict rather than being branded tampered.
    expect(decision.nextVerification).toBe("pending");
  });

  it("does NOT auto-read an unopened view-once attachment (first_read_at is its burn trigger)", () => {
    const viewOnceAttachment = peerText({ viewOnce: true, hasAttachment: true });
    const decision = deriveReadState(viewOnceAttachment, undefined, ME, READ_AT);
    expect(decision.nextReadAt).toBeNull();
    expect(decision.newRead).toBe(false);
  });

  it("auto-reads a view-once TEXT message (only view-once attachments defer)", () => {
    const viewOnceText = peerText({ viewOnce: true, hasAttachment: false });
    const decision = deriveReadState(viewOnceText, undefined, ME, READ_AT);
    expect(decision.newRead).toBe(true);
  });

  it("writes a verification/threat change without treating it as a new read", () => {
    const existing: ExistingReadState = {
      firstReadAt: "2026-07-16T11:00:00.000Z",
      verificationState: "pending",
      threatScore: 0,
    };
    // Already read, but the decrypted verdict is now known -> changed, not newRead.
    const decision = deriveReadState(peerText({ authenticated: true }), existing, ME, READ_AT);
    expect(decision.changed).toBe(true);
    expect(decision.newRead).toBe(false);
    expect(decision.nextVerification).toBe("valid");
  });

  it("does not brand an unanchored sender as tampered", () => {
    // `authenticated: false` now means "the sender's device identity could not
    // be checked", not "the ciphertext failed". A message that decrypted and
    // whose signature verified must never be persisted as tampered — that is an
    // accusation of forgery, and it would be recorded permanently against a
    // message that is simply missing a proof it can still acquire later.
    const decision = deriveReadState(peerText({ authenticated: false }), undefined, ME, READ_AT);
    expect(decision.nextVerification).toBe("pending");
    expect(decision.newRead).toBe(true);
  });

  it("only a real integrity failure is left un-upgraded from pending", () => {
    // A stub that never decrypted keeps whatever verdict it already had.
    const decision = deriveReadState(
      peerText({ authenticated: false, status: "failed" }),
      { firstReadAt: null, verificationState: "tampered", threatScore: 0 },
      ME,
      READ_AT,
    );
    expect(decision.nextVerification).toBe("tampered");
  });
});
