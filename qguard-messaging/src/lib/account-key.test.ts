import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
let tauri = true;
vi.mock("@/lib/tauri", () => ({
  isTauriRuntime: () => tauri,
  safeInvoke: (command: string, args?: unknown) => invoke(command, args),
}));

import {
  BARE_DETAILS,
  devicesNeedingWrap,
  isSealedEnvelope,
  openSecurityEventDetails,
  openTelemetryDetails,
  openValues,
  rotationDue,
  sealJson,
  securityEventDetails,
  shouldBootstrap,
  telemetryPlaceholder,
  type WrapRowLike,
} from "@/lib/account-key";

const sealedField = { v: 1, e: 1, n: "bm9uY2U=", c: "Y2lwaGVy" };

beforeEach(() => {
  invoke.mockReset();
  tauri = true;
});

describe("isSealedEnvelope", () => {
  it("accepts only the sealed shape", () => {
    expect(isSealedEnvelope({ sealed: sealedField })).toBe(true);
    expect(isSealedEnvelope({ redacted: true })).toBe(false);
    expect(isSealedEnvelope({ sealed: { v: 1 } })).toBe(false);
    expect(isSealedEnvelope(null)).toBe(false);
    expect(isSealedEnvelope("sealed")).toBe(false);
  });
});

describe("shouldBootstrap", () => {
  it("makes the first key on a lone device", () => {
    expect(shouldBootstrap({ selfId: "b", trustedIds: ["b"], anyWrapRows: false })).toBe(true);
  });
  it("elects only the lowest id when several devices have no key", () => {
    expect(shouldBootstrap({ selfId: "a", trustedIds: ["a", "b", "c"], anyWrapRows: false })).toBe(true);
    expect(shouldBootstrap({ selfId: "b", trustedIds: ["a", "b", "c"], anyWrapRows: false })).toBe(false);
    expect(shouldBootstrap({ selfId: "c", trustedIds: ["a", "b", "c"], anyWrapRows: false })).toBe(false);
  });
  it("never makes a second key once any wrap exists (a key is already in circulation)", () => {
    expect(shouldBootstrap({ selfId: "a", trustedIds: ["a", "b"], anyWrapRows: true })).toBe(false);
  });
});

describe("devicesNeedingWrap", () => {
  const row = (to: string, epoch: number): WrapRowLike => ({ from_device_id: "a", to_device_id: to, epoch, accepted_at: null });
  it("lists trusted devices without a wrap at the current epoch, never itself", () => {
    expect(devicesNeedingWrap({ selfId: "a", trustedIds: ["a", "b", "c"], rows: [row("b", 1)], currentEpoch: 1 })).toEqual(["c"]);
  });
  it("wants a new wrap for everyone after a rotation, even those wrapped at the old epoch", () => {
    expect(devicesNeedingWrap({ selfId: "a", trustedIds: ["a", "b", "c"], rows: [row("b", 1), row("c", 1)], currentEpoch: 2 })).toEqual(["b", "c"]);
  });
  it("does not offer a revoked device (it is not in the trusted list)", () => {
    expect(devicesNeedingWrap({ selfId: "a", trustedIds: ["a", "b"], rows: [], currentEpoch: 1 })).toEqual(["b"]);
  });
});

describe("rotationDue", () => {
  const accepted = (from: string, to: string, epoch = 1): WrapRowLike => ({ from_device_id: from, to_device_id: to, epoch, accepted_at: "2026-10-21T00:00:00Z" });
  it("is not due while every device that holds the current key is still trusted", () => {
    expect(rotationDue({ selfId: "a", trustedIds: ["a", "b"], revokedIds: [], rows: [accepted("a", "b")], currentEpoch: 1 })).toBe(false);
  });
  it("is due when a device that was given the current key has been revoked — on one device only", () => {
    const rows = [accepted("a", "b"), accepted("a", "c")];
    const args = { trustedIds: ["a", "b"], revokedIds: ["c"], rows, currentEpoch: 1 };
    expect(rotationDue({ selfId: "a", ...args })).toBe(true);
    expect(rotationDue({ selfId: "b", ...args })).toBe(false); // the lowest-id holder rotates, not both
  });
  it("is not due again once the new epoch exists (the revoked device's row is for the old epoch)", () => {
    expect(rotationDue({ selfId: "a", trustedIds: ["a", "b"], revokedIds: ["c"], rows: [accepted("a", "c", 1)], currentEpoch: 2 })).toBe(false);
  });
});

describe("sealing", () => {
  it("writes a bare marker — never the metadata — when the key is not ready", async () => {
    invoke.mockRejectedValueOnce(new Error("not found: ACCOUNT_KEY_UNAVAILABLE: this device has no account key yet"));
    const details = await securityEventDetails("hash-1", { device_id: "d1", fingerprint: "abc" });
    expect(details).toEqual({ ...BARE_DETAILS });
    expect(JSON.stringify(details)).not.toContain("abc");
  });

  it("writes only the sealed envelope when it can seal", async () => {
    invoke.mockResolvedValueOnce(sealedField);
    const details = await securityEventDetails("hash-1", { device_id: "d1" });
    expect(details).toEqual({ sealed: sealedField });
    expect(invoke).toHaveBeenCalledWith("account_field_seal", { purpose: "security_event", context: "hash-1", plaintext: JSON.stringify({ device_id: "d1" }) });
  });

  it("does not try outside the app", async () => {
    tauri = false;
    expect(await sealJson("telemetry", "t1", { a: 1 })).toBeNull();
    expect(invoke).not.toHaveBeenCalled();
  });
});

describe("openValues", () => {
  it("passes legacy plaintext rows through without calling the core", async () => {
    const out = await openValues("security_event", [{ context: "h1", value: { redacted: true, user_id: "u" } }]);
    expect(out).toEqual([{ value: { redacted: true, user_id: "u" }, state: "plain" }]);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("opens sealed rows, keeps order, and reports the ones this device cannot open as unavailable", async () => {
    invoke.mockResolvedValueOnce([JSON.stringify({ k: 1 }), null, JSON.stringify({ k: 3 })]);
    const out = await openValues("security_event", [
      { context: "a", value: { sealed: sealedField } },
      { context: "b", value: { sealed: sealedField } },
      { context: "c", value: { sealed: sealedField } },
      { context: "d", value: { redacted: true } },
    ]);
    expect(out.map((entry) => entry.state)).toEqual(["opened", "unavailable", "opened", "plain"]);
    expect(out[0].value).toEqual({ k: 1 });
    expect(out[1].value).toBeNull();
    const call = invoke.mock.calls[0][1] as { items: Array<{ context: string }> };
    expect(call.items.map((item) => item.context)).toEqual(["a", "b", "c"]);
  });

  it("treats a failing core as unavailable, not as an error", async () => {
    invoke.mockRejectedValueOnce(new Error("boom"));
    const out = await openValues("telemetry", [{ context: "x", value: { sealed: sealedField } }]);
    expect(out).toEqual([{ value: null, state: "unavailable" }]);
  });
});

describe("row helpers", () => {
  it("marks a security event whose details cannot be opened instead of showing sealed bytes", async () => {
    invoke.mockResolvedValueOnce([null]);
    const [row] = await openSecurityEventDetails([{ event_hash: "h", encrypted_details: { sealed: sealedField } }]);
    expect(row.encrypted_details).toEqual({ redacted: true, unavailable: true });
  });

  it("restores the real telemetry detail once opened and keeps the placeholder otherwise", async () => {
    invoke.mockResolvedValueOnce([JSON.stringify({ detail: "Historical envelopes rewrapped", metadata: { synced_devices: 2 } })]);
    const [sealed, legacy] = await openTelemetryDetails([
      { id: "t1", stage: "device_sync_completed", detail: telemetryPlaceholder("device_sync_completed"), redacted_metadata: { sealed: sealedField } },
      { id: "t2", stage: "x", detail: "plain old detail", redacted_metadata: { module: "m" } },
    ]);
    expect(sealed.detail).toBe("Historical envelopes rewrapped");
    expect(sealed.redacted_metadata).toEqual({ synced_devices: 2 });
    expect(legacy.detail).toBe("plain old detail");
  });

  it("the placeholder carries no more than the stage name", () => {
    expect(telemetryPlaceholder("device_sync_completed")).toBe("device sync completed");
  });
});
