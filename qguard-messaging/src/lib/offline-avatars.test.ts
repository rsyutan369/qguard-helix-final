import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const bridge = vi.hoisted(() => ({ safeInvoke: vi.fn() }));
vi.mock("@/lib/tauri", () => ({ safeInvoke: bridge.safeInvoke }));

import { avatarThumbnail, useOfflineAvatarSync } from "./offline-avatars";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

function Sync(props: Parameters<typeof useOfflineAvatarSync>[0]) {
  useOfflineAvatarSync(props);
  return null;
}

beforeEach(() => {
  bridge.safeInvoke.mockReset().mockResolvedValue(null);
  host = document.createElement("div");
  root = createRoot(host);
});

afterEach(async () => {
  await act(async () => root.unmount());
});

describe("offline profile picture sync", () => {
  it("leaves the stored picture alone while the profile is unknown or offline", async () => {
    await act(async () => root.render(createElement(Sync, { accountId: "account", enabled: true, avatarUrl: undefined })));
    await act(async () => root.render(createElement(Sync, { accountId: "account", enabled: false, avatarUrl: null })));
    expect(bridge.safeInvoke).not.toHaveBeenCalled();
  });

  it("reads the picture through an image element, never fetch (the app CSP refuses blob: connections)", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("refused by connect-src"));
    const drawn: unknown[] = [];
    class FakeImage {
      naturalWidth = 400;
      naturalHeight = 300;
      decoding = "";
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) { queueMicrotask(() => this.onload?.()); }
    }
    vi.stubGlobal("Image", FakeImage);
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
      fillRect: () => undefined, drawImage: (...args: unknown[]) => drawn.push(args), fillStyle: "", imageSmoothingQuality: "low",
    } as unknown as CanvasRenderingContext2D);
    const toDataURL = vi.spyOn(HTMLCanvasElement.prototype, "toDataURL").mockReturnValue("data:image/jpeg;base64,/9j/4AAQ");
    try {
      expect(await avatarThumbnail("blob:app/profile-picture")).toBe("/9j/4AAQ");
      expect(fetchSpy).not.toHaveBeenCalled();
      // Centre crop of a 400 x 300 picture into 192 x 192.
      expect(drawn[0]).toEqual([expect.any(FakeImage), 50, 0, 300, 300, 0, 0, 192, 192]);
    } finally {
      fetchSpy.mockRestore();
      getContext.mockRestore();
      toDataURL.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it("clears the shared picture when the profile has none", async () => {
    await act(async () => root.render(createElement(Sync, { accountId: "account", enabled: true, avatarUrl: null })));
    expect(bridge.safeInvoke).toHaveBeenCalledWith("offline_set_avatar", { image: null, expectedAccount: "account" });
  });
});
