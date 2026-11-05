import { describe, expect, test } from "vitest";
import { buildShareNotices } from "@/lib/vault-share";
import { dashboardHub, hubCardLabel } from "@/lib/dashboard-hub";

const NOW = Date.parse("2026-11-05T12:00:00Z");
const names = new Map([["owner-a", "Tesla"], ["owner-b", "@zach"]]);

describe("incoming share notices", () => {
  test("only pending, live, unexpired shares — newest first", () => {
    const notices = buildShareNotices(
      [
        { share_id: "s-old", status: "pending", created_at: "2026-11-05T09:00:00Z" },
        { share_id: "s-new", status: "pending", created_at: "2026-11-05T11:30:00Z" },
        { share_id: "s-accepted", status: "accepted", created_at: "2026-11-05T11:00:00Z" },
        { share_id: "s-declined", status: "declined", created_at: "2026-11-05T11:00:00Z" },
        { share_id: "s-expired", status: "pending", created_at: "2026-11-04T11:00:00Z" },
        { share_id: "s-revoked", status: "pending", created_at: "2026-11-05T10:00:00Z" },
        // RLS hides a share the recipient can no longer see: no share row at all.
        { share_id: "s-hidden", status: "pending", created_at: "2026-11-05T10:30:00Z" },
      ],
      [
        { id: "s-old", owner_user_id: "owner-a", expires_at: null },
        { id: "s-new", owner_user_id: "owner-b", expires_at: "2026-11-06T00:00:00Z" },
        { id: "s-accepted", owner_user_id: "owner-a", expires_at: null },
        { id: "s-declined", owner_user_id: "owner-a", expires_at: null },
        { id: "s-expired", owner_user_id: "owner-a", expires_at: "2026-11-05T11:59:59Z" },
        { id: "s-revoked", owner_user_id: "owner-a", expires_at: null, revoked_at: "2026-11-05T10:05:00Z" },
      ],
      names,
      NOW,
    );
    expect(notices.map((notice) => notice.shareId)).toEqual(["s-new", "s-old"]);
    expect(notices[0]).toEqual({
      shareId: "s-new",
      ownerUserId: "owner-b",
      ownerName: "@zach",
      sharedAt: "2026-11-05T11:30:00Z",
      expiresAt: "2026-11-06T00:00:00Z",
    });
  });

  test("a notice never carries the file name (it is sealed in the device envelope)", () => {
    const [notice] = buildShareNotices(
      [{ share_id: "s", status: "pending", created_at: "2026-11-05T11:00:00Z" }],
      [{ id: "s", owner_user_id: "unknown-owner", expires_at: null }],
      new Map(),
      NOW,
    );
    expect(Object.keys(notice).sort()).toEqual(["expiresAt", "ownerName", "ownerUserId", "shareId", "sharedAt"]);
    expect(notice.ownerName).toBe("A QGuard user");
  });
});

describe("dashboard Quantum Vault card", () => {
  test("shows waiting shared files as its badge and caption", () => {
    const vault = dashboardHub(0, 0, 2).find((entry) => entry.route === "vault")!;
    expect(vault.badge).toBe(2);
    expect(vault.caption).toBe("2 shared files waiting");
    expect(hubCardLabel(vault)).toContain("2 shared files waiting.");
  });

  test("unchanged when nothing is waiting", () => {
    const vault = dashboardHub(0, 0).find((entry) => entry.route === "vault")!;
    expect(vault.badge).toBe(0);
    expect(vault.caption).toBe("Your private storage");
  });
});
