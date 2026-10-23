import { describe, expect, it } from "vitest";
import {
  accountAuditIdentifier,
  accountIdentifierLabel,
  accountProofKind,
  displayableEmail,
  isPlaceholderEmail,
  parseAuthSettings,
} from "@/lib/account-identity";

const emailUser = { email: "ana@example.com", phone: "", app_metadata: { provider: "email" } };
const phoneUser = { email: undefined, phone: "639171234567", app_metadata: { provider: "phone" } };
// Registered by phone, later added an email: still no password.
const phoneUserWithEmail = { email: "ana@example.com", phone: "639171234567", app_metadata: { provider: "phone" } };

describe("placeholder addresses", () => {
  it("are recognised and never displayed", () => {
    expect(isPlaceholderEmail("0b6c1c8e-4f41-4a0f-8a4c-7f6f7a1e2d33@qguard.local")).toBe(true);
    expect(displayableEmail("0b6c1c8e-4f41-4a0f-8a4c-7f6f7a1e2d33@QGUARD.LOCAL")).toBeNull();
    expect(displayableEmail(" ana@example.com ")).toBe("ana@example.com");
    expect(displayableEmail(null)).toBeNull();
  });
});

describe("accountProofKind", () => {
  it("asks email accounts for their password", () => {
    expect(accountProofKind(emailUser)).toBe("password");
  });

  it("asks phone accounts for an SMS code, even after they add an email", () => {
    expect(accountProofKind(phoneUser)).toBe("sms");
    expect(accountProofKind(phoneUserWithEmail)).toBe("sms");
  });

  it("falls back to SMS for an account with only a phone whatever its provider label", () => {
    expect(accountProofKind({ email: undefined, phone: "15551234567", app_metadata: {} })).toBe("sms");
  });
});

describe("identifiers", () => {
  it("label phone accounts with a masked number, never the full one", () => {
    expect(accountIdentifierLabel(phoneUser)).toBe("+63 ••• ••• 4567");
    expect(accountIdentifierLabel(emailUser)).toBe("ana@example.com");
  });

  it("key audit hashes on E.164 for phones and lower-cased email otherwise", () => {
    expect(accountAuditIdentifier(phoneUser)).toBe("+639171234567");
    expect(accountAuditIdentifier({ ...emailUser, email: "Ana@Example.com" })).toBe("ana@example.com");
  });
});

describe("parseAuthSettings", () => {
  it("reads whether phone sign-in is enabled on the project", () => {
    expect(parseAuthSettings({ external: { email: true, phone: false } })).toEqual({ email: true, phone: false });
    expect(parseAuthSettings({ external: { email: true, phone: true } })).toEqual({ email: true, phone: true });
  });

  it("assumes no phone sign-in when the answer is unreadable", () => {
    expect(parseAuthSettings(null)).toEqual({ email: true, phone: false });
  });
});
