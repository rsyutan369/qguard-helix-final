import { describe, expect, it } from "vitest";
import { describeIncomingAssurance, describePairing, type ContactAssurance } from "@/lib/contact-verification";
import { peerIdentityOfDevice } from "@/lib/call-targets";

const assurance = (overrides: Partial<ContactAssurance> = {}): ContactAssurance => ({
  recorded: true,
  verifiedAt: null,
  pairing: "none",
  ...overrides,
});

describe("incoming-call assurance (design §3.4)", () => {
  it("says nothing when the core has not answered", () => {
    expect(describeIncomingAssurance(null, "Ana")).toBeNull();
  });

  it("a device never recorded for the caller is a danger and needs a second tap", () => {
    const notice = describeIncomingAssurance(assurance({ recorded: false }), "Ana");
    expect(notice?.tone).toBe("danger");
    expect(notice?.confirmToAnswer).toBe(true);
    expect(notice?.text).toContain("not approved for Ana");
  });

  it("a recorded but unverified device warns about cloned voices, without extra friction", () => {
    const notice = describeIncomingAssurance(assurance(), "Ana");
    expect(notice?.tone).toBe("warn");
    expect(notice?.confirmToAnswer).toBe(false);
    expect(notice?.text).toContain("cloned voice");
  });

  it("a verified device is reassuring, and mentions the phrase only when one exists", () => {
    const paired = describeIncomingAssurance(assurance({ verifiedAt: 1_790_000_000, pairing: "paired" }), "Ana");
    expect(paired?.tone).toBe("ok");
    expect(paired?.text).toContain("ask for their phrase");
    const unpaired = describeIncomingAssurance(assurance({ verifiedAt: 1_790_000_000, pairing: "waiting_for_them" }), "Ana");
    expect(unpaired?.tone).toBe("ok");
    expect(unpaired?.text).not.toContain("phrase");
  });

  it("a pairing alone never makes a device read as verified (negative control)", () => {
    const notice = describeIncomingAssurance(assurance({ verifiedAt: null, pairing: "needs_your_verification" }), "Ana");
    expect(notice?.tone).toBe("warn");
  });
});

describe("pairing wording", () => {
  it("names every state plainly", () => {
    expect(describePairing("paired", "Ana")).toContain("four-word phrase");
    expect(describePairing("waiting_for_them", "Ana")).toContain("Waiting for Ana");
    expect(describePairing("needs_your_verification", "Ana")).toContain("Ana has verified you");
    expect(describePairing("none", "Ana")).toBe("Not paired yet.");
  });
});

describe("peerIdentityOfDevice", () => {
  const device = {
    user_id: "u1",
    device_id: "d1",
    x25519_identity_public: [1],
    mlkem_identity_public: [2],
    ed25519_identity_public: [3],
    mldsa_identity_public: [4],
    identity_signature: { ed25519: [5], ml_dsa_65: [6] },
  };

  it("maps a directory row to the identity the core takes", () => {
    expect(peerIdentityOfDevice(device)).toEqual({
      user_id: "u1",
      device_id: "d1",
      x25519_identity_public: [1],
      mlkem_identity_public: [2],
      ed25519_identity_public: [3],
      mldsa_identity_public: [4],
      identity_signature: { ed25519: [5], ml_dsa_65: [6] },
    });
  });

  it("refuses a row without a verifiable identity", () => {
    expect(peerIdentityOfDevice({ ...device, identity_signature: null })).toBeNull();
    expect(peerIdentityOfDevice({ ...device, mlkem_identity_public: [] })).toBeNull();
  });
});
