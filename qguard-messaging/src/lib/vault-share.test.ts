import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  rpcs: [] as Array<[string, Record<string, unknown>]>,
  sealed: [] as Array<Record<string, unknown>>,
  stored: [] as Array<Record<string, unknown>>,
  devices: [] as Array<Record<string, unknown>>,
  envelopes: 1,
  uploads: [] as Array<[string, string]>,
  released: [] as Array<[string, string]>,
  shares: [] as Array<Record<string, unknown>>,
  recipients: [] as Array<Record<string, unknown>>,
}));

vi.mock("@/lib/tauri", () => ({
  safeInvoke: vi.fn(async (command: string, args?: Record<string, unknown>) => {
    if (command === "vault_share_seal") {
      const request = args?.request as { recipients: Array<{ user_id: string; device_id: string }> };
      state.sealed.push(request as never);
      const envelopes = request.recipients.slice(0, state.envelopes).map((r) => ({ recipientUserId: r.user_id, recipientDeviceId: r.device_id, senderDeviceId: "me-1" }));
      return { envelopes, skipped: [] };
    }
    return undefined;
  }),
}));

vi.mock("@/lib/call-peer-identity", () => ({
  callPeerIdentityFromRow: (row: Record<string, unknown>) => ({ user_id: String(row.user_id), device_id: String(row.id) }),
  fetchCallPeerIdentity: async () => null,
}));

vi.mock("@/lib/vault-cloud", () => ({
  CloudError: class CloudError extends Error {
    constructor(public code: string, message: string) {
      super(message);
    }
  },
  describeCloudError: (error: unknown) => String((error as { message?: string })?.message ?? error),
  downloadObject: async () => "download-1",
  uploadShareCopy: vi.fn(async (userId: string, entryId: string, onProgress?: (done: number, total: number) => void) => {
    state.uploads.push([userId, entryId]);
    onProgress?.(50, 100);
    return "copy-1";
  }),
  vaultCloudCore: {
    releaseShareCopy: vi.fn(async (entryId: string, objectId: string) => {
      state.released.push([entryId, objectId]);
      return true;
    }),
  },
}));

vi.mock("@/lib/supabase", () => {
  const client = {
    rpc: async (name: string, args: Record<string, unknown>) => {
      state.rpcs.push([name, args]);
      if (name === "qv_share_create") return { data: { share_id: "share-1", recipients: args.p_recipients }, error: null };
      return { data: true, error: null };
    },
    from: (table: string) => {
      let id = "";
      const rows = () => (table === "qv_shares" ? state.shares : table === "qv_share_recipients" ? state.recipients : table === "messaging_devices" ? state.devices : []);
      const builder = {
        select: () => builder,
        eq: (column: string, value: string) => {
          if (column === "id") id = value;
          return builder;
        },
        is: () => builder,
        in: () => builder,
        maybeSingle: async () => ({ data: { id, container_sha3: "c".repeat(64), status: "committed" }, error: null }),
        upsert: async (upserted: Array<Record<string, unknown>>) => {
          state.stored.push(...upserted);
          return { error: null };
        },
        // Awaiting the builder runs the query.
        then: (resolve: (value: { data: unknown[]; error: null }) => unknown) => resolve({ data: rows(), error: null }),
      };
      return builder;
    },
  };
  return { requireSupabase: () => client };
});

import { createShare, describeShareError, liveSharedObjectIds, releaseUnusedShareCopies } from "./vault-share";
import type { StoreEntry } from "./vault-store";

const entry = (cloudObjectId: string | null, extra: Partial<StoreEntry> = {}) =>
  ({ id: "file-1", kind: "file", name: "Report.pdf", cloudObjectId, ...extra }) as unknown as StoreEntry;
const bob = { userId: "bob", displayName: "Bob", username: "bob" };
const hoursAgo = (hours: number) => new Date(Date.now() - hours * 3600_000).toISOString();

beforeEach(() => {
  state.rpcs = [];
  state.sealed = [];
  state.stored = [];
  state.devices = [
    { id: "bob-phone", user_id: "bob", revoked_at: null, trust_state: "this_device" },
    { id: "bob-old", user_id: "bob", revoked_at: "2026-10-01", trust_state: "revoked" },
  ];
  state.envelopes = 1;
  state.uploads = [];
  state.released = [];
  state.shares = [];
  state.recipients = [];
});

describe("sharing", () => {
  it("shares a file that is not backed up by uploading only its own encrypted copy first", async () => {
    const progress: Array<[number, number]> = [];
    const result = await createShare("user-1", entry(null), [bob], "view", null, (done, total) => progress.push([done, total]));
    expect(state.uploads).toEqual([["user-1", "file-1"]]);
    expect(progress).toEqual([[50, 100]]);
    expect(state.rpcs[0][0]).toBe("qv_share_create");
    expect(state.rpcs[0][1]).toMatchObject({ p_object_id: "copy-1" });
    expect(state.released).toEqual([]);
    expect(result).toMatchObject({ people: 1, devices: 1 });
  });

  it("uses the existing copy of a backed-up file without uploading anything", async () => {
    await createShare("user-1", entry("obj-1"), [bob], "view", null);
    expect(state.uploads).toEqual([]);
    expect(state.rpcs[0][1]).toMatchObject({ p_object_id: "obj-1" });
  });

  it("refuses an empty recipient list before uploading anything", async () => {
    await expect(createShare("user-1", entry(null), [], "view", null)).rejects.toThrow(/at least one person/);
    expect(state.uploads).toEqual([]);
    expect(state.rpcs).toEqual([]);
  });

  it("seals to each live device of each recipient and stores one envelope per device", async () => {
    const result = await createShare("user-1", entry("obj-1"), [bob], "download", new Date(Date.now() + 3600_000));
    expect(state.rpcs[0][0]).toBe("qv_share_create");
    expect(state.rpcs[0][1]).toMatchObject({ p_object_id: "obj-1", p_recipients: ["bob"], p_permission: "download" });
    // The revoked device is never sealed to.
    const request = state.sealed[0] as { recipients: Array<{ device_id: string }>; containerSha3: string };
    expect(request.recipients.map((r) => r.device_id)).toEqual(["bob-phone"]);
    expect(request.containerSha3).toBe("c".repeat(64));
    expect(state.stored).toHaveLength(1);
    expect(state.stored[0]).toMatchObject({ share_id: "share-1", recipient_device_id: "bob-phone", sender_device_id: "me-1" });
    expect(result).toMatchObject({ people: 1, devices: 1 });
  });

  it("withdraws a share that reached no device at all, and takes back a copy made for it", async () => {
    state.envelopes = 0;
    await expect(createShare("user-1", entry(null), [bob], "view", null)).rejects.toThrow(/no device|None of these people/i);
    expect(state.rpcs.map(([name]) => name)).toEqual(["qv_share_create", "qv_share_revoke"]);
    expect(state.released).toEqual([["file-1", "copy-1"]]);
  });

  it("never takes back a backup copy when a share fails", async () => {
    state.envelopes = 0;
    await expect(createShare("user-1", entry("obj-1"), [bob], "view", null)).rejects.toThrow();
    expect(state.released).toEqual([]);
  });

  it("explains server refusals in plain words", () => {
    expect(describeShareError(new Error("QV_NO_CLOUD_ENTITLEMENT"))).toMatch(/plan does not include/);
    expect(describeShareError(new Error("trust error: VAULT_SHARE_EXPIRED: this share has expired"))).toMatch(/expired/);
  });
});

describe("copies made for sharing", () => {
  const copies = [
    entry("copy-declined", { id: "a", cloudSharedOnly: true, cloudBackedUpAt: hoursAgo(24) }),
    entry("copy-live", { id: "b", cloudSharedOnly: true, cloudBackedUpAt: hoursAgo(24) }),
    entry("copy-expired", { id: "c", cloudSharedOnly: true, cloudBackedUpAt: hoursAgo(24) }),
    entry("copy-revoked", { id: "d", cloudSharedOnly: true, cloudBackedUpAt: hoursAgo(24) }),
    // Uploaded a minute ago: its share may still be being created.
    entry("copy-fresh", { id: "e", cloudSharedOnly: true, cloudBackedUpAt: hoursAgo(1 / 60) }),
    // A backup, not a shared copy: never released, shared or not.
    entry("backup", { id: "f", cloudSharedOnly: false, cloudBackedUpAt: hoursAgo(24) }),
  ];

  beforeEach(() => {
    // The query filters revoked shares out, so "copy-revoked" has none here.
    state.shares = [
      { id: "s-declined", object_id: "copy-declined", expires_at: null },
      { id: "s-live", object_id: "copy-live", expires_at: null },
      { id: "s-expired", object_id: "copy-expired", expires_at: hoursAgo(1) },
    ];
    // Recipients still reachable (pending or accepted); everyone declined s-declined.
    state.recipients = [{ share_id: "s-live" }, { share_id: "s-expired" }];
  });

  it("knows which copies a live share still uses", async () => {
    expect([...(await liveSharedObjectIds("user-1"))]).toEqual(["copy-live"]);
  });

  it("takes back only shared copies no live share uses, never a backup or a fresh copy", async () => {
    const released = await releaseUnusedShareCopies("user-1", copies);
    expect(released).toBe(3);
    expect(state.released.map(([, objectId]) => objectId).sort()).toEqual(["copy-declined", "copy-expired", "copy-revoked"]);
  });

  it("does not decide from a list the server cut short", async () => {
    state.shares = Array.from({ length: 1000 }, (_, i) => ({ id: `s${i}`, object_id: `o${i}`, expires_at: null }));
    await expect(releaseUnusedShareCopies("user-1", copies)).rejects.toThrow(/could not all be checked/);
    expect(state.released).toEqual([]);
  });

  it("does nothing at all when there is no shared copy", async () => {
    expect(await releaseUnusedShareCopies("user-1", [copies[5]])).toBe(0);
    expect(state.released).toEqual([]);
  });
});
