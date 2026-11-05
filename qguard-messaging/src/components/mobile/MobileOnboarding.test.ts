import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import MobileOnboarding, { isMobileOnboardingPending } from "./MobileOnboarding";

const DONE_KEY = "qguard_mobile_onboarding_done";
let container: HTMLDivElement;
let root: Root;
const done = vi.fn();

async function mountTour() {
  await act(async () => root.render(createElement(MobileOnboarding, { onDone: done })));
}
async function showSlides() {
  await mountTour();
  await act(async () => { vi.advanceTimersByTime(3000); });
}
async function click(selector: string) {
  const button = container.querySelector<HTMLButtonElement>(selector);
  expect(button).not.toBeNull();
  await act(async () => button!.click());
}

beforeEach(() => {
  vi.useFakeTimers();
  done.mockClear();
  const stored = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => { stored.set(key, value); },
    removeItem: (key: string) => { stored.delete(key); },
  });
  localStorage.removeItem(DONE_KEY);
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  localStorage.removeItem(DONE_KEY);
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Android first-run onboarding", () => {
  it("keeps the existing device completion flag and shows the splash for three seconds", async () => {
    expect(isMobileOnboardingPending()).toBe(true);
    await mountTour();
    expect(container.querySelector(".onb-splash")).not.toBeNull();
    await act(async () => { vi.advanceTimersByTime(2999); });
    expect(container.querySelector(".onb-splash")).not.toBeNull();
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(container.querySelectorAll(".onb-page")).toHaveLength(4);
    expect(container.querySelector(".is-active")?.getAttribute("aria-label")).toContain("Talk.");
    expect(done).not.toHaveBeenCalled();
    expect(localStorage.getItem(DONE_KEY)).toBeNull();
  });
  it("Skip persists completion and hands off to the existing entry flow", async () => {
    await showSlides();
    await click(".onb-skip");
    expect(done).toHaveBeenCalledOnce();
    expect(localStorage.getItem(DONE_KEY)).toBe("1");
    expect(isMobileOnboardingPending()).toBe(false);
  });
  it("visits all four pages without finishing until Get Started is pressed", async () => {
    await showSlides();
    for (const id of ["vault", "calls", "devices"]) {
      await click(".onb-next");
      expect(container.querySelector(".is-active")?.id).toBe(`onb-page-${id}`);
      expect(done).not.toHaveBeenCalled();
      expect(localStorage.getItem(DONE_KEY)).toBeNull();
    }
    expect(container.querySelectorAll('[aria-hidden="false"]')).toHaveLength(1);
    expect(container.querySelectorAll("article[inert]")).toHaveLength(3);
    await click(".onb-start");
    expect(done).toHaveBeenCalledOnce();
    expect(localStorage.getItem(DONE_KEY)).toBe("1");
  });
  it("supports previous and direct page navigation without completing", async () => {
    await showSlides();
    await click('.onb-dot[aria-controls="onb-page-devices"]');
    await click(".onb-back");
    expect(container.querySelector(".is-active")?.id).toBe("onb-page-calls");
    await click('.onb-dot[aria-controls="onb-page-messaging"]');
    expect(container.querySelector(".onb-back")).toBeNull();
    expect(done).not.toHaveBeenCalled();
  });
  it("still hands off if device persistence is unavailable", async () => {
    await showSlides();
    vi.spyOn(localStorage, "setItem").mockImplementation(() => { throw new Error("Unavailable"); });
    await click(".onb-skip");
    expect(done).toHaveBeenCalledOnce();
  });
  it("cancels the splash timer when unmounted", async () => {
    await mountTour();
    expect(vi.getTimerCount()).toBe(1);
    await act(async () => root.render(null));
    expect(vi.getTimerCount()).toBe(0);
  });
});
