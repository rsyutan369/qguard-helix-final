import { beforeEach, describe, expect, it, vi } from "vitest";

// ---- fakes for the three layers vault-cloud talks to ----------------------

const core = vi.hoisted(() => ({
  calls: [] as Array<[string, Record<string, unknown> | undefined]>,
  plan: { enabled: true, uploads: [] as Array<{ entryId: string; name: string; storedBytes: number }>, deletes: [] as string[], indexNeeded: false },
  afterPlan: null as null | { enabled: boolean; uploads: never[]; deletes: string[]; indexNeeded: boolean },
}));

const server = vi.hoisted(() => ({
  rpcs: [] as Array<[string, Record<string, unknown>]>,
  uploads: [] as string[],
  removed: [] as string[],
  stored: new Map<string, string[]>(), // prefix -> part names
  beginError: null as string | null,
  finishDelete: true,
}));

// The library layer (vault-library.ts) as the engine sees it.
const lib = vi.hoisted(() => ({
  hasRing: false,
  revision: 0,
  publishNeeded: false,
  serverRevision: 0,
  publishConflicts: 0,
  /** Another device publishes just before our next publish attempt. */
  raceOnce: false,
}));

vi.mock("@/lib/vault-library", () => ({
  syncLibraryKey: vi.fn(async () => ({
    status: { hasRing: lib.hasRing },
    devices: [],
    waitingForAccess: !lib.hasRing,
  })),
  libraryCore: {
    status: vi.fn(async () => ({
      hasRing: lib.hasRing,
      epoch: lib.hasRing ? 1 : null,
      revision: lib.revision,
      publishNeeded: lib.publishNeeded,
      deviceId: "device-1",
    })),
  },
  fetchLibraryState: vi.fn(async () =>
    lib.serverRevision > 0 ? { revision: lib.serverRevision, object_id: `lib-${lib.serverRevision}`, epoch: 1 } : null,
  ),
  isRevisionConflict: (error: unknown) => String((error as { message?: string })?.message ?? error).includes("QV_REVISION_CONFLICT"),
}));

vi.mock("@/lib/tauri", () => ({
  safeInvoke: vi.fn(async (command: string, args?: Record<string, unknown>) => {
    core.calls.push([command, args]);
    if (command === "vault_cloud_complete_delete") {
      core.plan.deletes = core.plan.deletes.filter((id) => id !== args?.objectId);
      if (core.afterPlan) core.afterPlan.deletes = core.afterPlan.deletes.filter((id) => id !== args?.objectId);
    }
    if (command === "vault_library_merge") {
      lib.revision = Number(args?.revision);
      return { added: 1, updated: 0, removed: [], repaired: 0 };
    }
    if (command === "vault_library_prepare_publish") {
      return { uploadId: "up-library", kind: "library_index", entryId: null, containerBytes: 100, partSize: 8388608, partSha3: ["f".repeat(64)], containerSha3: "9".repeat(64), deviceId: "device-1" };
    }
    if (command === "vault_library_published") {
      lib.revision = Number(args?.revision);
      lib.publishNeeded = false;
      return undefined;
    }
    if (command === "vault_cloud_download_begin") return "download-1";
    if (command === "vault_cloud_plan") {
      const planned = core.afterPlan && core.calls.filter(([c]) => c === "vault_cloud_plan").length > 1 ? core.afterPlan : core.plan;
      return planned;
    }
    if (command === "vault_cloud_prepare_file") {
      return {
        uploadId: `up-${String(args?.entryId)}`,
        kind: "file",
        entryId: args?.entryId,
        containerBytes: 8388608 + 10,
        partSize: 8388608,
        partSha3: ["a".repeat(64), "b".repeat(64)],
        containerSha3: "c".repeat(64),
        deviceId: "device-1",
      };
    }
    if (command === "vault_cloud_prepare_index") {
      return { uploadId: "up-index", kind: "recovery_index", entryId: null, containerBytes: 100, partSize: 8388608, partSha3: ["d".repeat(64)], containerSha3: "e".repeat(64), deviceId: "device-1" };
    }
    return undefined;
  }),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async (command: string) => {
    core.calls.push([command, undefined]);
    return new ArrayBuffer(4);
  }),
}));

vi.mock("@/lib/supabase", () => {
  const client = {
    rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
      server.rpcs.push([name, args]);
      if (name === "qv_begin_upload") {
        if (server.beginError) return { data: null, error: { message: server.beginError } };
        return { data: { id: `obj-${String(args.p_entry_id ?? "index")}`, status: "uploading" }, error: null };
      }
      if (name === "qv_commit_upload") return { data: { id: args.p_object_id, status: "committed" }, error: null };
      if (name === "qv_begin_delete") return { data: { id: args.p_object_id, status: "deleting" }, error: null };
      if (name === "qv_finish_delete") return { data: server.finishDelete, error: null };
      if (name === "qv_publish_library") {
        if (lib.raceOnce) {
          lib.raceOnce = false;
          lib.serverRevision += 1;
        }
        if (Number(args.p_expected_revision) !== lib.serverRevision) {
          lib.publishConflicts += 1;
          return { data: null, error: { message: "QV_REVISION_CONFLICT" } };
        }
        const previous = lib.serverRevision > 0 ? `lib-${lib.serverRevision}` : null;
        lib.serverRevision += 1;
        return { data: { revision: lib.serverRevision, previous_object_id: previous }, error: null };
      }
      return { data: null, error: null };
    }),
    storage: {
      from: () => ({
        list: async (prefix: string) => ({ data: (server.stored.get(prefix) ?? []).map((name) => ({ name })), error: null }),
        upload: async (path: string) => {
          server.uploads.push(path);
          return { error: null };
        },
        remove: async (paths: string[]) => {
          server.removed.push(...paths);
          for (const key of server.stored.keys()) server.stored.set(key, []);
          return { error: null };
        },
        download: async () => ({ data: new Blob([new Uint8Array([1, 2, 3])]), error: null }),
      }),
    },
    // A fluent query builder: every filter returns the builder; maybeSingle
    // answers an object row by the id it was filtered on.
    from: () => {
      let id = "";
      const builder = {
        select: () => builder,
        eq: (column: string, value: string) => {
          if (column === "id") id = value;
          return builder;
        },
        neq: async () => ({ data: [] }),
        in: () => builder,
        maybeSingle: async () => ({
          data: { id, owner_user_id: "user-1", kind: "library_index", container_bytes: 3, part_count: 1, part_sha3: ["0".repeat(64)], container_sha3: "0".repeat(64), status: "committed" },
          error: null,
        }),
      };
      return builder;
    },
    auth: { getSession: async () => ({ data: { session: { user: { id: "user-1" } } } }) },
  };
  return { requireSupabase: () => client };
});

import { CloudError, describeCloudError, runCloudSync } from "./vault-cloud";

beforeEach(() => {
  core.calls = [];
  core.plan = { enabled: true, uploads: [], deletes: [], indexNeeded: false };
  core.afterPlan = null;
  server.rpcs = [];
  server.uploads = [];
  server.removed = [];
  server.stored = new Map();
  server.beginError = null;
  server.finishDelete = true;
  lib.hasRing = false;
  lib.revision = 0;
  lib.publishNeeded = false;
  lib.serverRevision = 0;
  lib.publishConflicts = 0;
  lib.raceOnce = false;
});

describe("library sync (phase 3)", () => {
  it("merges what another device published before publishing its own changes", async () => {
    Object.assign(lib, { hasRing: true, revision: 2, serverRevision: 3, publishNeeded: true });
    const report = await runCloudSync("user-1");
    const order = core.calls.map(([c]) => c).filter((c) => c === "vault_library_merge" || c === "vault_library_published");
    expect(order).toEqual(["vault_library_merge", "vault_library_published"]);
    expect(core.calls.find(([c]) => c === "vault_library_merge")?.[1]).toMatchObject({ revision: 3 });
    expect(core.calls.find(([c]) => c === "vault_library_published")?.[1]).toMatchObject({ revision: 4, previousObjectId: "lib-3" });
    expect(report.libraryPublished).toBe(true);
    expect(report.merged?.added).toBe(1);
  });

  it("never overwrites a revision it has not merged: a lost race merges and retries", async () => {
    Object.assign(lib, { hasRing: true, revision: 1, serverRevision: 1, publishNeeded: true, raceOnce: true });
    await runCloudSync("user-1");
    expect(lib.publishConflicts).toBe(1);
    // The refused upload is discarded and its object removed from the cloud.
    expect(core.calls.map(([c]) => c)).toContain("vault_cloud_discard_upload");
    expect(server.rpcs.some(([name, args]) => name === "qv_begin_delete" && args.p_object_id === "obj-index")).toBe(true);
    // Then the other device's revision is merged, and ours goes on top of it.
    expect(core.calls.find(([c]) => c === "vault_library_merge")?.[1]).toMatchObject({ revision: 2 });
    expect(core.calls.find(([c]) => c === "vault_library_published")?.[1]).toMatchObject({ revision: 3 });
  });

  it("a device without the library key waits instead of publishing", async () => {
    Object.assign(lib, { hasRing: false, publishNeeded: false });
    const report = await runCloudSync("user-1");
    expect(report.waitingForAccess).toBe(true);
    expect(server.rpcs.map(([name]) => name)).not.toContain("qv_publish_library");
    expect(core.calls.map(([c]) => c)).not.toContain("vault_library_prepare_publish");
  });
});

describe("cloud sync engine", () => {
  it("reserves, uploads every part to the reservation's path, commits, then records it in the core", async () => {
    core.plan.uploads = [{ entryId: "e1", name: "a.jpg", storedBytes: 8388618 }];
    const report = await runCloudSync("user-1");
    expect(report).toMatchObject({ uploaded: 1, stoppedBy: null });
    expect(server.rpcs.map(([name]) => name)).toEqual(["qv_begin_upload", "qv_commit_upload"]);
    expect(server.rpcs[0][1]).toMatchObject({ p_kind: "file", p_entry_id: "e1", p_container_bytes: 8388618 });
    expect(server.uploads).toEqual(["user-1/obj-e1/00000", "user-1/obj-e1/00001"]);
    expect(core.calls.map(([c]) => c)).toContain("vault_cloud_complete_upload");
    expect(core.calls.find(([c]) => c === "vault_cloud_complete_upload")?.[1]).toEqual({ uploadId: "up-e1", objectId: "obj-e1" });
    // The run is recorded as clean.
    expect(core.calls.find(([c]) => c === "vault_cloud_record_sync")?.[1]).toEqual({ error: null });
  });

  it("resumes an interrupted upload without re-sending parts already stored", async () => {
    core.plan.uploads = [{ entryId: "e2", name: "big.mov", storedBytes: 8388618 }];
    server.stored.set("user-1/obj-e2", ["00000"]);
    await runCloudSync("user-1");
    expect(server.uploads).toEqual(["user-1/obj-e2/00001"]);
    expect(core.calls.filter(([c]) => c === "vault_cloud_read_part")).toHaveLength(1);
  });

  it("stops at the quota without failing the run, discards the prepared upload and reports why", async () => {
    core.plan.uploads = [
      { entryId: "e3", name: "one", storedBytes: 10 },
      { entryId: "e4", name: "two", storedBytes: 10 },
    ];
    server.beginError = "QV_QUOTA_EXCEEDED";
    const report = await runCloudSync("user-1");
    expect(report.uploaded).toBe(0);
    expect(report.stoppedBy).toMatch(/limit reached/);
    // Only the first file was attempted; the second was not reserved.
    expect(server.rpcs.filter(([name]) => name === "qv_begin_upload")).toHaveLength(1);
    expect(core.calls.map(([c]) => c)).toContain("vault_cloud_discard_upload");
    expect(server.uploads).toEqual([]);
    expect(core.calls.find(([c]) => c === "vault_cloud_record_sync")?.[1]).toEqual({ error: report.stoppedBy });
  });

  it("deletes queued objects: begin, remove parts, finish, then tells the core", async () => {
    core.plan.deletes = ["old-1"];
    server.stored.set("user-1/old-1", ["00000", "00001"]);
    const report = await runCloudSync("user-1");
    expect(report.deleted).toBe(1);
    expect(server.removed).toEqual(["user-1/old-1/00000", "user-1/old-1/00001"]);
    expect(server.rpcs.map(([name]) => name)).toEqual(["qv_begin_delete", "qv_finish_delete"]);
    expect(core.calls.find(([c]) => c === "vault_cloud_complete_delete")?.[1]).toEqual({ objectId: "old-1" });
  });

  it("uploads the index after the files and removes the copy it replaced in the same run", async () => {
    core.plan.indexNeeded = true;
    core.afterPlan = { enabled: true, uploads: [], deletes: ["old-index"], indexNeeded: false };
    const report = await runCloudSync("user-1");
    expect(report.indexUploaded).toBe(true);
    expect(server.rpcs[0][1]).toMatchObject({ p_kind: "recovery_index", p_entry_id: null });
    expect(core.calls.find(([c]) => c === "vault_cloud_complete_delete")?.[1]).toEqual({ objectId: "old-index" });
  });

  it("is single-flight", async () => {
    core.plan.uploads = [{ entryId: "e5", name: "x", storedBytes: 10 }];
    const [first, second] = [runCloudSync("user-1"), runCloudSync("user-1")];
    expect(first).toBe(second);
    await first;
    expect(server.rpcs.filter(([name]) => name === "qv_begin_upload")).toHaveLength(1);
  });

  it("explains database and network failures in plain words", () => {
    expect(describeCloudError(new Error("QV_NO_CLOUD_ENTITLEMENT"))).toMatch(/does not include cloud backup/);
    expect(describeCloudError({ message: "TypeError: Failed to fetch" })).toMatch(/No connection/);
    expect(describeCloudError("trust error: This recovery key does not open this backup.")).toMatch(/does not open this backup/);
    expect(new CloudError("X", "y").code).toBe("X");
  });
});
