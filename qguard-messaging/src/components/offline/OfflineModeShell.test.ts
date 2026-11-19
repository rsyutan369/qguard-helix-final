import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OfflineModeShell, isOfflineRoute } from "./OfflineModeShell";
import type { OfflineSessionInfo } from "@/lib/auth-context";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const session: OfflineSessionInfo = {
  userId: "user-1",
  email: "person@example.test",
  offlineUntil: Date.UTC(2026, 11, 9) / 1000,
  entitlement: null,
};

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

function render(overrides: Partial<Parameters<typeof OfflineModeShell>[0]> = {}) {
  const props = {
    session,
    android: false,
    entitled: true,
    page: "mesh" as const,
    title: "Qguard Mesh",
    theme: "light" as const,
    onToggleTheme: vi.fn(),
    onNavigate: vi.fn(),
    onReconnect: vi.fn(async () => false),
    onSignInOnline: vi.fn(async () => undefined),
    onSignOut: vi.fn(async () => undefined),
    children: createElement("p", { id: "workspace" }, "Discovery radar"),
    ...overrides,
  };
  act(() => root.render(createElement(OfflineModeShell, props)));
  return props;
}

function button(label: string): HTMLButtonElement {
  const found = [...host.querySelectorAll("button")].find((item) => item.textContent?.includes(label) || item.getAttribute("aria-label") === label);
  if (!found) throw new Error(`No button ${label}`);
  return found as HTMLButtonElement;
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
});

describe("OfflineModeShell", () => {
  it("offers only the offline workspaces", () => {
    const props = render();
    const tabs = [...host.querySelectorAll("nav[aria-label='Offline workspaces'] button")].map((item) => item.textContent?.trim());
    expect(tabs).toEqual(["Mesh", "XFER", "History", "Settings"]);
    expect(host.querySelector("[aria-current='page']")?.textContent).toContain("Mesh");
    act(() => button("XFER").click());
    expect(props.onNavigate).toHaveBeenCalledWith("xfer");
    expect(host.textContent).toContain("Discovery radar");
    expect(host.textContent).toContain("ML-KEM-768 + X25519");
    expect(host.textContent).not.toMatch(/Secure Chat\b.*(open|unlock)/i);
  });

  it("names the account and when offline access lapses", () => {
    render();
    expect(host.textContent).toContain("person@example.test");
    expect(host.textContent).toContain(new Date(session.offlineUntil * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }));
  });

  it("desktop leaves offline mode to sign in online", async () => {
    const props = render();
    await act(async () => button("Sign in online").click());
    expect(props.onSignInOnline).toHaveBeenCalledTimes(1);
    expect(props.onReconnect).not.toHaveBeenCalled();
  });

  it("Android reconnects in place and says when it is still offline", async () => {
    const props = render({ android: true });
    await act(async () => button("Reconnect now").click());
    expect(props.onReconnect).toHaveBeenCalledTimes(1);
    expect(props.onSignInOnline).not.toHaveBeenCalled();
    expect(host.textContent).toContain("Still offline");
  });

  it("does not open the workspace without a plan confirmed online", () => {
    render({ entitled: false });
    expect(host.textContent).not.toContain("Discovery radar");
    expect(host.textContent).toContain("Your plan couldn't be confirmed offline");
  });

  it("asks before signing out of the device", async () => {
    const props = render();
    act(() => button("Sign out").click());
    expect(props.onSignOut).not.toHaveBeenCalled();
    await act(async () => button("Sign out of this device").click());
    expect(props.onSignOut).toHaveBeenCalledTimes(1);
  });

  it("recognises the offline routes", () => {
    expect(isOfflineRoute("mesh")).toBe(true);
    expect(isOfflineRoute("offline-settings")).toBe(true);
    expect(isOfflineRoute("chat")).toBe(false);
    expect(isOfflineRoute("vault")).toBe(false);
  });
});
