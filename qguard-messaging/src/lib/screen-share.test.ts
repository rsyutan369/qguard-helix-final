import { describe, expect, it } from "vitest";
import { SCREEN_SHARE_CONSTRAINTS, screenShareSupported } from "./screen-share";

describe("screen share", () => {
  it("is offered only where the WebView can capture a screen", () => {
    expect(screenShareSupported(undefined)).toBe(false);
    // Android WebView: mediaDevices without getDisplayMedia.
    expect(screenShareSupported({ mediaDevices: { getUserMedia: () => undefined } } as unknown as Navigator)).toBe(false);
    expect(screenShareSupported({} as Navigator)).toBe(false);
    expect(screenShareSupported({ mediaDevices: { getDisplayMedia: () => undefined } } as unknown as Navigator)).toBe(true);
  });

  it("captures video only — system audio is never shared implicitly", () => {
    expect(SCREEN_SHARE_CONSTRAINTS.audio).toBe(false);
    expect(SCREEN_SHARE_CONSTRAINTS.video).toBeTruthy();
  });
});
