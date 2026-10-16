import { describe, expect, it } from "vitest";
import { buildCryptoPosture, scoreVerdict } from "@/lib/mobile-posture";
import { ONE_TIME_PREKEY_MIN } from "@/lib/security-score";
import type { DashboardData, SecurityHardeningCheck, TrustedDevice } from "@/lib/types";

const KEY = [1, 2, 3];

/** A device carrying complete, current key material. */
function liveDevice(id: string, overrides: Partial<TrustedDevice> = {}): TrustedDevice {
  return {
    device_id: id,
    user_id: "me",
    label: "Android Device",
    fingerprint: `fp-${id}`,
    trust_state: "Trusted",
    pqc_status: "Hybrid",
    suite: {},
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    revoked_at: null,
    approved_by_device_id: null,
    x25519_identity_public: KEY,
    mlkem_identity_public: KEY,
    ed25519_identity_public: KEY,
    mldsa_identity_public: KEY,
    identity_signature: { ed25519: KEY, ml_dsa_65: KEY },
    signed_prekey: {
      prekey_id: `pk-${id}`,
      x25519_public: KEY,
      mlkem_public: KEY,
      signature: { ed25519: KEY, ml_dsa_65: KEY },
      fingerprint: `pkfp-${id}`,
    },
    ...overrides,
  } as TrustedDevice;
}

/**
 * The row a reinstall leaves behind: the identity keys are still published, but
 * the keyring that could sign a prekey is gone, so it can never take part again.
 */
function strandedDevice(id: string): TrustedDevice {
  return liveDevice(id, { signed_prekey: null, trust_state: "Trusted" });
}

function check(id: string, status: SecurityHardeningCheck["status"]): SecurityHardeningCheck {
  return { id, label: id, status, active: status === "active", detail: "" };
}

function dashboard(devices: TrustedDevice[], opts: {
  oneTimeKeys?: number;
  checks?: SecurityHardeningCheck[];
  /** What the core reported about prekey rotation; omit for "could not measure". */
  rotationHealthy?: boolean;
} = {}): DashboardData {
  return {
    profile: { id: "me" },
    devices,
    keyInventory: {
      available_one_time_prekeys: opts.oneTimeKeys ?? ONE_TIME_PREKEY_MIN,
      active_signed_prekeys: devices.filter((d) => d.signed_prekey).length,
      algorithms: [],
    },
    hardening: { checks: opts.checks ?? [check("post_quantum_protection", "active")] },
    report: opts.rotationHealthy === undefined ? {} : { forward_secrecy_healthy: opts.rotationHealthy },
  } as unknown as DashboardData;
}

describe("buildCryptoPosture", () => {
  it("does not let identities stranded by a reinstall deflate the live layers", () => {
    // The reported bug, reproduced from real account shape: 2 live devices and
    // 3 rows left over from reinstalls read as "2 of 4 layers fully active"
    // beside a 100% headline.
    const posture = buildCryptoPosture(dashboard([
      liveDevice("phone"),
      liveDevice("desktop"),
      strandedDevice("old-1"),
      strandedDevice("old-2"),
      strandedDevice("old-3"),
    ]));
    const byId = Object.fromEntries(posture.layers.map((l) => [l.id, l]));
    expect(byId.identity.value).toBe(1);
    expect(byId.handshake.value).toBe(1);
    expect(byId.identity.detail).toBe("2/2 dual-signed");
    expect(posture.enrolledDevices).toBe(2);
  });

  it("reports the stranded rows rather than hiding them", () => {
    // They must not vanish: the user needs the count and an action, they just
    // do not belong inside the handshake measurement.
    const posture = buildCryptoPosture(dashboard([liveDevice("phone"), strandedDevice("old-1")]));
    expect(posture.dormantIdentities).toBe(1);
  });

  it("still fails the identity layer when a LIVE device is not dual-signed", () => {
    // The narrowing must not become a way to pass: an enrolled device missing
    // its PQC identity signature is a real gap and has to stay visible.
    const posture = buildCryptoPosture(dashboard([
      liveDevice("phone"),
      liveDevice("half", { identity_signature: null }),
    ]));
    const identity = posture.layers.find((l) => l.id === "identity")!;
    expect(identity.value).toBe(0.5);
    expect(identity.tone).toBe("warn");
  });

  it("reports an account with no enrolled device as unprotected, not perfect", () => {
    // 0/0 must never round up to 1.
    const posture = buildCryptoPosture(dashboard([strandedDevice("old-1")]));
    const byId = Object.fromEntries(posture.layers.map((l) => [l.id, l]));
    expect(byId.identity.value).toBe(0);
    expect(byId.identity.tone).toBe("alert");
    expect(byId.identity.detail).toBe("No device enrolled");
    expect(posture.enrolledDevices).toBe(0);
  });

  it("measures the session layer by prekey rotation, not by the one-time key pool", () => {
    // The layer's claim is forward secrecy. The one-time prekey pool is not
    // used by the send path, so a full pool proved nothing about it — and an
    // empty one disproved nothing.
    const session = (data: DashboardData) => buildCryptoPosture(data).layers.find((l) => l.id === "session")!;

    const rotating = session(dashboard([liveDevice("phone")], { rotationHealthy: true, oneTimeKeys: 0 }));
    expect(rotating.value).toBe(1);
    expect(rotating.detail).toBe("Prekey rotating daily");

    // Rotation stalled: a full one-time pool must not paper over it.
    const stalled = session(dashboard([liveDevice("phone")], { rotationHealthy: false, oneTimeKeys: ONE_TIME_PREKEY_MIN }));
    expect(stalled.value).toBe(0.5);
    expect(stalled.detail).toBe("Prekey rotation not confirmed");

    // Rotation could not be measured at all: not assumed healthy.
    const unmeasured = session(dashboard([liveDevice("phone")]));
    expect(unmeasured.value).toBe(0.5);

    // No signed prekey published: nothing to rotate, whatever a report says.
    const none = session(dashboard([strandedDevice("old-1")], { rotationHealthy: true }));
    expect(none.value).toBe(0);
    expect(none.detail).toBe("No signed prekey published");
  });

  it("excludes build-provenance gates from the runtime layer", () => {
    // Release metadata (code signing, obfuscation, control-flow flattening) is
    // evidence about how the binary was produced. It is not a statement about
    // whether the running cryptography works, and counting it here reported an
    // unmeasurable build gate as a cryptographic failure.
    const posture = buildCryptoPosture(dashboard([liveDevice("phone")], {
      checks: [
        check("post_quantum_protection", "active"),
        check("secure_memory_zeroize", "active"),
        check("signed_build_verification", "warning"),
        check("code_obfuscation", "warning"),
        check("control_flow_flattening", "warning"),
        check("string_encryption", "warning"),
        check("binary_integrity_verification", "warning"),
      ],
    }));
    const runtime = posture.layers.find((l) => l.id === "runtime")!;
    expect(runtime.value).toBe(1);
    expect(runtime.detail).toBe("2/2 checks active");
  });

  it("still fails the runtime layer on a real runtime control", () => {
    const posture = buildCryptoPosture(dashboard([liveDevice("phone")], {
      checks: [
        check("post_quantum_protection", "active"),
        check("anti_debugger_protection", "failed"),
      ],
    }));
    const runtime = posture.layers.find((l) => l.id === "runtime")!;
    expect(runtime.value).toBe(0.5);
  });

  it("reports an unmeasured runtime as unmeasured, never as a failure", () => {
    const posture = buildCryptoPosture(dashboard([liveDevice("phone")], { checks: [] }));
    const runtime = posture.layers.find((l) => l.id === "runtime")!;
    expect(runtime.detail).toBe("Not measured");
    expect(runtime.tone).toBe("mute");
  });
});

describe("scoreVerdict", () => {
  const layer = (value: number) => ({ id: "x", ordinal: 1, label: "x", caption: "", value, detail: "", tone: "ok" as const });

  it("never claims 'fully protected' over a measurably incomplete layer", () => {
    // The shipped contradiction: a 100 score printed "100% · Fully protected"
    // directly above "2 of 4 cryptographic layers fully active".
    expect(scoreVerdict(100, [layer(1), layer(1), layer(0.4), layer(0.75)]).label).toBe("Review coverage");
    expect(scoreVerdict(95, [layer(1), layer(0.5)]).label).toBe("Review coverage");
  });

  it("claims full protection only when the score AND every layer agree", () => {
    expect(scoreVerdict(100, [layer(1), layer(1), layer(1), layer(1)]).label).toBe("Fully protected");
    expect(scoreVerdict(94, [layer(1), layer(1)]).label).toBe("Protected");
  });

  it("keeps a low score's verdict even when every layer is ready", () => {
    // Layer coverage must not be able to talk a bad score up.
    expect(scoreVerdict(50, [layer(1), layer(1)]).label).toBe("Action needed");
    expect(scoreVerdict(75, [layer(1), layer(1)]).label).toBe("Review warnings");
  });
});
