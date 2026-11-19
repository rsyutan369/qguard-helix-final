import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceKeyRecoveryScreen } from "./DeviceKeyRecoveryScreen";
import { RESET_DEVICE_IDENTITY_CONFIRMATION, type DeviceKeyRecovery } from "@/lib/auth-context";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const recovery: DeviceKeyRecovery = {
  account: "person@example.test",
  detail: "DEVICE_KEYS_UNREADABLE: storage error",
  error: null,
  busy: false,
};
let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
const onRetry = vi.fn(async () => true);
const onReset = vi.fn(async () => true);
const onSignOut = vi.fn(async () => undefined);

function button(label: string) {
  return Array.from(host.querySelectorAll("button")).find((candidate) => candidate.textContent?.trim().includes(label));
}

async function render(state: DeviceKeyRecovery = recovery) {
  await act(async () => root.render(createElement(DeviceKeyRecoveryScreen, { recovery: state, onRetry, onReset, onSignOut })));
}

async function type(value: string) {
  const input = host.querySelector<HTMLInputElement>("input")!;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

beforeEach(() => {
  onRetry.mockClear();
  onReset.mockClear();
  onSignOut.mockClear();
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

describe("Device key recovery at sign-in", () => {
  it("explains the fault and never resets without the exact typed confirmation", async () => {
    await render();
    expect(host.textContent).toContain("This device's keys can't be opened");
    expect(host.textContent).toContain(recovery.account);
    expect(host.textContent).not.toContain(recovery.detail);
    const reset = button("Reset this device and continue")!;
    expect(reset.disabled).toBe(true);
    await type("reset this device identity");
    expect(reset.disabled).toBe(true);
    await type(RESET_DEVICE_IDENTITY_CONFIRMATION);
    expect(reset.disabled).toBe(false);
    await act(async () => reset.click());
    expect(onReset).toHaveBeenCalledWith(RESET_DEVICE_IDENTITY_CONFIRMATION);
  });

  it("offers retry and sign-out, shows details on request and disables actions while busy", async () => {
    await render();
    await act(async () => button("Try again")!.click());
    expect(onRetry).toHaveBeenCalledOnce();
    await act(async () => button("Show technical details")!.click());
    expect(host.textContent).toContain(recovery.detail);
    await act(async () => button("Sign out")!.click());
    expect(onSignOut).toHaveBeenCalledOnce();

    await render({ ...recovery, busy: true, error: "This device's keys still could not be opened." });
    expect(host.querySelector('[role="alert"]')?.textContent).toContain("still could not be opened");
    expect(button("Try again")?.disabled).toBe(true);
    expect(button("Sign out")?.disabled).toBe(true);
  });
});
