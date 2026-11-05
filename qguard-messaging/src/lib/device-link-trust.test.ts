import { beforeEach, describe, expect, it, vi } from "vitest";

const pins = vi.hoisted(() => ({ assessDevicePins: vi.fn(), approveDevicePins: vi.fn() }));
const tauri = vi.hoisted(() => ({ safeInvoke: vi.fn(), isTauriRuntime: () => true, isAndroidRuntime: () => false }));
vi.mock("@/lib/device-pins", () => pins);
vi.mock("@/lib/tauri", () => tauri);
vi.mock("@/lib/account-key", () => ({ securityEventDetails: async () => ({ redacted: true }) }));
vi.mock("@/lib/supabase", () => ({ supabaseUrl: "https://project.supabase.co", supabaseAnonKey: "anon" }));

import { computeLinkProof, generateBindingSecret } from "@/lib/device-link";
import { trustLinkedDevice } from "@/lib/device-link-trust";

const USER = "0b6c1c8e-4f41-4a0f-8a4c-7f6f7a1e2d33";
const LINK = "6f9b7f5e-2a1c-4b1e-9a7d-0c2b9b7c3d11";
const NEW_DEVICE = "f1d2c3b4-a596-4877-8899-aabbccddeeff";
const CORE_FINGERPRINT = "QG-CORE-COMPUTED";

function deviceRow(id: string, extra: Record<string, unknown> = {}) {
  return {
    id, user_id: USER, device_label: "Windows Desktop", trust_state: "this_device", revoked_at: null,
    x25519_identity_public: "\\x01", mlkem_identity_public: "\\x02", ed25519_identity_public: "\\x03", mldsa_identity_public: "\\x04",
    identity_signature: { ed25519: [1], ml_dsa_65: [2] }, ...extra,
  };
}

function fakeClient(rows: unknown[]) {
  const updates: unknown[] = [];
  const inserts: unknown[] = [];
  const client = {
    from: (table: string) => ({
      select: () => ({ eq: async () => ({ data: table === "messaging_devices" ? rows : [], error: null }) }),
      update: (patch: unknown) => {
        updates.push(patch);
        const chain = { eq: () => chain, neq: async () => ({ error: null }) };
        return chain;
      },
      insert: async (row: unknown) => {
        inserts.push(row);
        return { error: null };
      },
    }),
  };
  return { client: client as never, updates, inserts };
}

const secret = generateBindingSecret();
const proofFor = (fingerprint: string, deviceId = NEW_DEVICE) =>
  computeLinkProof({ bindingSecret: secret, linkId: LINK, userId: USER, deviceId, fingerprint });

beforeEach(() => {
  pins.assessDevicePins.mockReset();
  pins.approveDevicePins.mockReset().mockResolvedValue({ available: true, verdicts: [] });
  tauri.safeInvoke.mockReset().mockResolvedValue(null);
});

const verdict = (standing: string, fingerprint = CORE_FINGERPRINT) => ({
  available: true,
  verdicts: [{ userId: USER, deviceId: NEW_DEVICE, standing, fingerprint, pinnedAt: null, source: null }],
});

describe("trustLinkedDevice", () => {
  it("trusts and pins the device when the proof matches the fingerprint the core computed", async () => {
    pins.assessDevicePins.mockResolvedValue(verdict("new"));
    const { client, updates, inserts } = fakeClient([deviceRow("approver"), deviceRow(NEW_DEVICE)]);
    const outcome = await trustLinkedDevice({ client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT), approverDeviceId: "approver" });
    expect(outcome).toEqual({ trusted: true, label: "Windows Desktop" });
    expect(pins.assessDevicePins.mock.calls[0][0]).toHaveLength(2); // the whole account, not only the new device
    expect(pins.approveDevicePins).toHaveBeenCalledTimes(1);
    expect(updates[0]).toMatchObject({ trust_state: "trusted", approved_by_device_id: "approver" });
    expect(inserts[0]).toMatchObject({ event_type: "device_linked", device_id: NEW_DEVICE });
  });

  it("refuses when the proof was made for a different fingerprint than the keys in the directory", async () => {
    // The relay row could claim any fingerprint; the core's own computation decides.
    pins.assessDevicePins.mockResolvedValue(verdict("new", "QG-SWAPPED-KEYS"));
    const { client, updates } = fakeClient([deviceRow(NEW_DEVICE, { fingerprint: CORE_FINGERPRINT })]);
    const outcome = await trustLinkedDevice({ client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT), approverDeviceId: null });
    expect(outcome.trusted).toBe(false);
    expect(pins.approveDevicePins).not.toHaveBeenCalled();
    expect(updates).toHaveLength(0);
  });

  it("refuses a proof made for another device id", async () => {
    pins.assessDevicePins.mockResolvedValue(verdict("new"));
    const { client } = fakeClient([deviceRow(NEW_DEVICE)]);
    const outcome = await trustLinkedDevice({ client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT, "00000000-0000-4000-8000-000000000000"), approverDeviceId: null });
    expect(outcome.trusted).toBe(false);
  });

  it.each(["key_changed", "invalid_identity", "unknown"])("never trusts a device whose pin standing is %s", async (standing) => {
    pins.assessDevicePins.mockResolvedValue(verdict(standing));
    const { client } = fakeClient([deviceRow(NEW_DEVICE)]);
    const outcome = await trustLinkedDevice({ client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT), approverDeviceId: null });
    expect(outcome.trusted).toBe(false);
    expect(pins.approveDevicePins).not.toHaveBeenCalled();
  });

  it("refuses when the core is unavailable or the device is not on the account", async () => {
    pins.assessDevicePins.mockResolvedValue(null);
    const { client } = fakeClient([deviceRow(NEW_DEVICE)]);
    expect((await trustLinkedDevice({ client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT), approverDeviceId: null })).trusted).toBe(false);
    const empty = fakeClient([]);
    expect((await trustLinkedDevice({ client: empty.client, userId: USER, linkId: LINK, bindingSecret: secret, linkedDeviceId: NEW_DEVICE, linkProof: await proofFor(CORE_FINGERPRINT), approverDeviceId: null })).trusted).toBe(false);
  });
});
