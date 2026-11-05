import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DashboardData } from "@/lib/types";
import { dashboardHub, hubCardLabel, unreadMessageCount } from "@/lib/dashboard-hub";

const layout = vi.hoisted(() => ({ mobile: false }));
vi.mock("@/lib/use-mobile", () => ({ useIsMobile: () => layout.mobile }));
vi.mock("@/lib/admin", () => ({ useIsAdmin: () => false }));
vi.mock("@/components/UserAvatar", () => ({ UserAvatar: () => null }));

import DashboardPage from "@/pages/DashboardPage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function conversation(id: string, unread: number, hidden = false) {
  return { id, conversation_type: "direct", member_user_ids: ["me", "peer"], unread_count: unread, hidden_at: hidden ? "2026-11-01T00:00:00Z" : null, deleted_at: null, archived_at: null, updated_at: "2026-11-05T00:00:00Z", title: id };
}

function data(): DashboardData {
  return {
    profile: { id: "me", display_name: "Ana" },
    snapshot: { quantum_safe_score: 92, e2ee_status: "Active", pqc_status: "Hybrid", vault_storage: "0 B" },
    devices: [],
    conversations: [conversation("c1", 2), conversation("c2", 1), conversation("c3", 5, true)],
    modules: [],
    report: { pqc_algorithm: "ML-KEM-1024 + X25519", forward_secrecy: "healthy", forward_secrecy_healthy: true, warnings: [] },
    keyInventory: { available_one_time_prekeys: 0, active_signed_prekeys: 0, algorithms: [] },
    telemetry: [],
    securityEvents: [],
    vaultFiles: [],
    vaultStore: { objects: 0 },
    hardening: { checks: [] },
  } as unknown as DashboardData;
}

const liveStatus = { state: "live", lastEventAt: null } as never;

async function render(onOpenArea: (area: string) => void, onNavigate: (page: string) => void = vi.fn()) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(createElement(DashboardPage, { data: data(), liveEvents: [], liveStatus, onNavigate, onOpenArea, missedCalls: 3 }));
  });
  return { container, root };
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("dashboard protected-area cards", () => {
  it("count unread messages the way the Chats badge does (hidden conversations excluded)", () => {
    expect(unreadMessageCount(data().conversations)).toBe(3);
    const calls = dashboardHub(3, 4).find((entry) => entry.route === "calls")!;
    expect(calls.caption).toBe("4 missed · voice & video");
    expect(hubCardLabel(calls)).toBe("Calls: 4 missed · voice & video. 4 missed. Protected by your Secure Chat lock.");
    expect(dashboardHub(0, 0).find((entry) => entry.route === "calls")!.caption).toBe("Voice & video");
  });

  for (const mobile of [false, true]) {
    it(`${mobile ? "Android/phone" : "desktop"} shows Secure Chat, Calls, Quantum Vault and Contacts, and each opens through the lock-first path`, async () => {
      layout.mobile = mobile;
      const onOpenArea = vi.fn();
      const onNavigate = vi.fn();
      const { container, root } = await render(onOpenArea, onNavigate);
      const cards = [...container.querySelectorAll<HTMLButtonElement>("button[aria-label*='Protected by your']")];
      expect(cards.map((card) => card.getAttribute("aria-label"))).toEqual(dashboardHub(3, 3).map(hubCardLabel));
      const callsCard = cards[1];
      expect(callsCard.textContent).toContain("Calls");
      expect(callsCard.textContent).toContain("3 missed · voice & video");
      for (const card of cards) await act(async () => card.click());
      expect(onOpenArea.mock.calls.map(([area]) => area)).toEqual(["chat", "calls", "vault", "contacts"]);
      expect(onNavigate).not.toHaveBeenCalled();
      await act(async () => root.unmount());
    });
  }
});
