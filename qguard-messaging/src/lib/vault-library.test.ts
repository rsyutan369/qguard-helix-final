import { beforeEach, describe, expect, it, vi } from "vitest";

const core = vi.hoisted(() => ({
  calls: [] as Array<[string, Record<string, unknown> | undefined]>,
  status: { hasRing: false, epoch: null as number | null, revision: 0, publishNeeded: false, recoveryEnvelopeNeeded: false, recoveryReady: true, tombstones: 0, lastMergeAt: null, deviceId: "dev-a" },
}));

const db = vi.hoisted(() => ({
  devices: [] as Array<Record<string, unknown>>,
  wraps: [] as Array<Record<string, unknown>>,
  recovery: null as null | { epoch: number; envelope: unknown },
  libraryState: null as null | { revision: number },
  upserts: [] as Array<Record<string, unknown>>,
  setRecoveryError: null as string | null,
  setRecoveryCalls: 0,
}));

vi.mock("@/lib/tauri", () => ({
  isTauriRuntime: () => true,
  safeInvoke: vi.fn(async (command: string, args?: Record<string, unknown>) => {
    core.calls.push([command, args]);
    switch (command) {
      case "vault_library_status":
        return { ...core.status };
      case "vault_library_create":
        core.status = { ...core.status, hasRing: true, epoch: 1, recoveryEnvelopeNeeded: true };
        return { ...core.status };
      case "vault_library_accept_recovery":
      case "vault_library_accept_wrap":
        core.status = { ...core.status, hasRing: true, epoch: 1, recoveryEnvelopeNeeded: false };
        return { ...core.status };
      case "vault_library_recovery_envelope":
        return { v: 1, epoch: core.status.epoch ?? 1, sealed: {} };
      case "vault_library_mark_recovery_stored":
        core.status = { ...core.status, recoveryEnvelopeNeeded: false };
        return undefined;
      case "vault_library_make_wrap":
        return { epoch: core.status.epoch ?? 1, to: (args?.target as { device_id: string }).device_id };
      case "vault_library_rotate":
        core.status = { ...core.status, epoch: (core.status.epoch ?? 1) + 1, recoveryEnvelopeNeeded: true };
        return { ...core.status };
      default:
        return undefined;
    }
  }),
}));

// Identity rows become peers only when complete; the tests use a stand-in.
vi.mock("@/lib/call-peer-identity", () => ({
  callPeerIdentityFromRow: (row: Record<string, unknown>) => ({ user_id: String(row.user_id), device_id: String(row.id) }),
}));

function query(table: string) {
  const rows = () =>
    table === "messaging_devices" ? db.devices : table === "qv_library_key_wraps" ? db.wraps : [];
  const result = { data: rows(), error: null };
  const builder = {
    select: () => builder,
    eq: () => builder,
    update: () => ({ eq: async () => ({ error: null }) }),
    upsert: async (row: Record<string, unknown>) => {
      db.upserts.push(row);
      return { error: null };
    },
    maybeSingle: async () => ({
      data: table === "qv_library_recovery" ? db.recovery : table === "qv_library_state" ? db.libraryState : null,
      error: null,
    }),
    then: (resolve: (value: typeof result) => unknown) => Promise.resolve(result).then(resolve),
  };
  return builder;
}

const client = {
  from: (table: string) => query(table),
  rpc: async (name: string) => {
    if (name === "qv_library_set_recovery") {
      db.setRecoveryCalls += 1;
      if (db.setRecoveryError) {
        // Someone else claimed the library first.
        db.recovery = { epoch: 1, envelope: { winner: true } };
        return { data: null, error: { message: db.setRecoveryError } };
      }
      return { data: { epoch: 1 }, error: null };
    }
    return { data: null, error: null };
  },
};

import { syncLibraryKey } from "./vault-library";

const device = (id: string, trust: string, revoked = false) => ({ id, user_id: "u", device_label: id, trust_state: trust, revoked_at: revoked ? "2026-11-01" : null });

beforeEach(() => {
  core.calls = [];
  core.status = { hasRing: false, epoch: null, revision: 0, publishNeeded: false, recoveryEnvelopeNeeded: false, recoveryReady: true, tombstones: 0, lastMergeAt: null, deviceId: "dev-a" };
  db.devices = [device("dev-a", "this_device")];
  db.wraps = [];
  db.recovery = null;
  db.libraryState = null;
  db.upserts = [];
  db.setRecoveryError = null;
  db.setRecoveryCalls = 0;
});

const commands = () => core.calls.map(([c]) => c);

describe("library key sync", () => {
  it("the first device starts the library and stores the recovery copy", async () => {
    const result = await syncLibraryKey(client as never, "u");
    expect(commands()).toEqual(expect.arrayContaining(["vault_library_create", "vault_library_recovery_envelope", "vault_library_mark_recovery_stored"]));
    expect(result.status.hasRing).toBe(true);
    expect(result.waitingForAccess).toBe(false);
  });

  it("a device that loses the race to start the library adopts the winner", async () => {
    db.setRecoveryError = "QV_RECOVERY_EXISTS";
    await syncLibraryKey(client as never, "u");
    const adopted = core.calls.find(([c]) => c === "vault_library_accept_recovery");
    expect(adopted?.[1]).toMatchObject({ envelope: { winner: true }, recoveryKey: null });
  });

  it("joins an existing library through the recovery copy instead of starting a second one", async () => {
    db.recovery = { epoch: 1, envelope: { stored: true } };
    await syncLibraryKey(client as never, "u");
    expect(commands()).not.toContain("vault_library_create");
    expect(core.calls.find(([c]) => c === "vault_library_accept_recovery")?.[1]).toMatchObject({ envelope: { stored: true } });
  });

  it("without a recovery key or a wrap it waits for another device", async () => {
    core.status.recoveryReady = false;
    db.libraryState = { revision: 4 };
    const result = await syncLibraryKey(client as never, "u");
    expect(result.waitingForAccess).toBe(true);
    expect(commands()).not.toContain("vault_library_create");
  });

  it("hands the key only to approved, unrevoked devices that lack it", async () => {
    core.status = { ...core.status, hasRing: true, epoch: 1 };
    db.recovery = { epoch: 1, envelope: {} };
    db.devices = [device("dev-a", "this_device"), device("dev-b", "trusted"), device("dev-c", "pending"), device("dev-d", "trusted", true)];
    await syncLibraryKey(client as never, "u");
    const targets = db.upserts.map((row) => row.to_device_id);
    expect(targets).toEqual(["dev-b"]);
  });

  it("rotates when a device that was handed the current key is removed", async () => {
    core.status = { ...core.status, hasRing: true, epoch: 1 };
    db.recovery = { epoch: 1, envelope: {} };
    db.devices = [device("dev-a", "this_device"), device("dev-b", "revoked", true)];
    db.wraps = [{ id: "w1", from_device_id: "dev-a", to_device_id: "dev-b", epoch: 1, accepted_at: "2026-11-01", wrap: {} }];
    const result = await syncLibraryKey(client as never, "u");
    expect(commands()).toContain("vault_library_rotate");
    expect(result.status.epoch).toBe(2);
    // The new epoch goes to the recovery copy, never to the removed device.
    expect(db.setRecoveryCalls).toBe(1);
    expect(db.upserts.map((row) => row.to_device_id)).not.toContain("dev-b");
  });
});
