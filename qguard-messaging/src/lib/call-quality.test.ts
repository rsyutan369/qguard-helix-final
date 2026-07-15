import { describe, expect, it } from "vitest";
import { mediaConstraints, qualityTier } from "./call-quality";

describe("call quality tiers", () => {
  it("meets the production media spec: auto ≥ 720p@30, hd = 1080p@30", () => {
    const auto = qualityTier("auto");
    expect(auto.height).toBeGreaterThanOrEqual(720);
    expect(auto.frameRate).toBe(30);
    // 720p30 VP8 needs ≥ ~2 Mbps to stay sharp; the ceiling must allow it.
    expect(auto.maxBitrate).toBeGreaterThanOrEqual(2_000_000);

    const hd = qualityTier("hd");
    expect(hd.width).toBe(1920);
    expect(hd.height).toBe(1080);
    expect(hd.frameRate).toBe(30);
    expect(hd.maxBitrate).toBeGreaterThanOrEqual(4_000_000);
  });

  it("keeps the low tier small for constrained networks", () => {
    const low = qualityTier("low");
    expect(low.height).toBeLessThanOrEqual(240);
    expect(low.maxBitrate).toBeLessThanOrEqual(300_000);
  });

  it("raises the Opus audio target above the 32kbps default on auto/hd", () => {
    expect(qualityTier("auto").audioMaxBitrate).toBeGreaterThanOrEqual(64_000);
    expect(qualityTier("hd").audioMaxBitrate).toBeGreaterThanOrEqual(64_000);
    expect(qualityTier("low").audioMaxBitrate).toBeLessThanOrEqual(32_000);
  });

  it("constrains capture with ideal/max (never exact) and enables the audio DSP", () => {
    const constraints = mediaConstraints("auto");
    const video = constraints.video as MediaTrackConstraints;
    expect(video.width).toEqual({ ideal: 1280, max: 1280 });
    expect(video.height).toEqual({ ideal: 720, max: 720 });
    expect(video.frameRate).toEqual({ ideal: 30, max: 30 });
    expect(constraints.audio).toEqual({
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    });
  });
});
