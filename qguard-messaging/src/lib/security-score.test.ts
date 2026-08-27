import { describe, expect, it } from "vitest";
import { buildSecurityPosture } from "@/lib/security-score";
import type { SecurityEvent, SecurityHardeningCheck, TrustedDevice } from "@/lib/types";

const KEY32 = Array.from({ length: 32 }, (_, i) => i);
const KEY = [1, 2, 3];

/** The suite every healthy device publishes. */
const SUITE = {
  classical_kex: "X25519",
  pq_kem: "ML-KEM-1024",
  kdf: "HKDF-SHA3-256",
  symmetric: "AES-256-GCM",
  classical_signature: "Ed25519",
  pq_signature: "ML-DSA-65",
};

function liveDevice(overrides: Partial<TrustedDevice> = {}): TrustedDevice {
  return {
    device_id: "d1",
    user_id: "me",
    label: "Android Device",
    fingerprint: "fp-d1",
    trust_state: "ThisDevice",
    pqc_status: "X25519 + ML-KEM-1024",
    suite: SUITE,
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    revoked_at: null,
    approved_by_device_id: null,
    x25519_identity_public: KEY32,
    mlkem_identity_public: KEY,
    ed25519_identity_public: KEY32,
    mldsa_identity_public: KEY,
    identity_signature: { ed25519: KEY, ml_dsa_65: KEY },
    signed_prekey: {
      prekey_id: "pk-d1",
      x25519_public: KEY32,
      mlkem_public: KEY,
      signature: { ed25519: KEY, ml_dsa_65: KEY },
      fingerprint: "pkfp-d1",
    },
    ...overrides,
  } as TrustedDevice;
}

function check(id: string, active = true): SecurityHardeningCheck {
  return {
    id,
    label: id,
    status: active ? "active" : "warning",
    active,
    detail: active ? "ok" : "unavailable",
  };
}

/**
 * The eight checks that describe the RUNNING cryptography — the set the live
 * posture score is measured over once the release-only build gates are removed.
 */
const LIVE_CHECK_IDS = [
  "anti_debugger_protection",
  "anti_tampering_detection",
  "runtime_integrity_hash_checks",
  "secure_memory_zeroize",
  "tamper_evident_audit_chain",
  "post_quantum_protection",
  "rate_limiting",
  "web_asset_integrity",
];

function hardening(failing: string[] = []) {
  return {
    checks: [
      ...LIVE_CHECK_IDS.map((id) => check(id, !failing.includes(id))),
      // Release-only build gates: excluded from live posture by design.
      check("binary_integrity_verification", false),
      check("signed_build_verification", false),
      check("control_flow_flattening", false),
    ],
  } as never;
}

function event(type: string, severity: SecurityEvent["severity"], daysAgo = 0): SecurityEvent {
  return {
    id: `${type}-${daysAgo}-${Math.random()}`,
    event_type: type,
    severity,
    event_hash: "h",
    previous_hash: null,
    created_at: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function posture(opts: { events?: SecurityEvent[]; failingChecks?: string[] } = {}) {
  return buildSecurityPosture({
    profile: { id: "me" } as never,
    devices: [liveDevice()],
    conversations: [],
    vaultFiles: [],
    keyInventory: {
      available_one_time_prekeys: 24,
      active_signed_prekeys: 1,
      algorithms: [],
    } as never,
    telemetry: [],
    securityEvents: opts.events ?? [],
    hardening: hardening(opts.failingChecks),
    vaultStorageLabel: "Local",
  });
}

describe("buildSecurityPosture", () => {
  it("scores a fully healthy account at 100", () => {
    expect(posture().snapshot.quantum_safe_score).toBe(100);
  });

  it("does not punish the account for retiring its own dormant devices", () => {
    // The reported bug, reproduced from the real account: one healthy device,
    // 24 one-time keys, every live check active — but 68% on screen. Eight
    // `device_delete_requested` rows (the user doing exactly the device-hygiene
    // task the dashboard asks for) hit the -20 event-penalty cap and also cost
    // the 3-point clean-events bonus.
    const cleanup = Array.from({ length: 8 }, () => event("device_delete_requested", "warning"));
    const result = posture({ events: cleanup });

    expect(result.snapshot.quantum_safe_score).toBe(100);
    expect(result.report.warnings).toHaveLength(0);
  });

  it("does not punish the account for revoking a device", () => {
    const revocations = Array.from({ length: 5 }, () => event("device_revoked", "warning"));
    expect(posture({ events: revocations }).snapshot.quantum_safe_score).toBe(100);
  });

  it("still penalises genuine security warnings", () => {
    // Failed logins are evidence about the account's safety, not housekeeping.
    const attempts = Array.from({ length: 3 }, () => event("login_failed", "warning"));
    const result = posture({ events: attempts });

    // 3 x 4 penalty, plus the 3-point clean-events bonus withheld.
    expect(result.snapshot.quantum_safe_score).toBe(85);
    expect(result.report.warnings).toContain("Security warning: login_failed");
  });

  it("still penalises an unverified safety number", () => {
    // Severity carries this one: the same event type is `info` when the safety
    // number verified, so the classifier must not key on type alone.
    const result = posture({ events: [event("safety_number_generated", "warning")] });
    expect(result.snapshot.quantum_safe_score).toBe(93);
  });

  it("lets posture recover once warnings age out of the window", () => {
    // A failed login three months ago is history, not current posture. Without
    // a window a single typo'd password caps the score forever.
    const old = Array.from({ length: 5 }, () => event("login_failed", "warning", 90));
    expect(posture({ events: old }).snapshot.quantum_safe_score).toBe(100);
  });

  it("reports the real cost of a runtime measurement that genuinely failed", () => {
    // The Android release build could not hash its own image, failing two of the
    // eight live checks. That is worth 9 points -- and nothing else.
    const result = posture({
      failingChecks: ["anti_tampering_detection", "runtime_integrity_hash_checks"],
    });
    expect(result.snapshot.quantum_safe_score).toBe(91);
    expect(result.report.warnings).toHaveLength(2);
  });
});
