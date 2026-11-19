import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/tauri", () => ({ safeInvoke: vi.fn(), isAndroidRuntime: () => false, isTauriRuntime: () => true }));

import { meshPendingLabel } from "./offline";

describe("meshPendingLabel", () => {
  it("says a message was relayed only once a sealed copy reached a relay", () => {
    expect(meshPendingLabel({})).toBe("Queued for delivery");
    expect(meshPendingLabel({ relayedTo: [] })).toBe("Queued for delivery");
    expect(meshPendingLabel({ relayedTo: ["ab".repeat(32)] })).toBe("Relayed, awaiting delivery");
  });
});
