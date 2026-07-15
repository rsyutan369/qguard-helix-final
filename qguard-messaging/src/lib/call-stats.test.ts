import { describe, expect, it } from "vitest";
import { summarizeCallStats, type PreviousCounters } from "./call-stats";

// Synthetic getStats() entries mirroring Chromium's report shape.
function chromiumReport(overrides?: { relay?: boolean }) {
  return [
    { id: "T1", type: "transport", selectedCandidatePairId: "CP1" },
    {
      id: "CP1", type: "candidate-pair", state: "succeeded", nominated: true,
      localCandidateId: "LC1", remoteCandidateId: "RC1",
      currentRoundTripTime: 0.004, availableOutgoingBitrate: 2_400_000,
    },
    { id: "LC1", type: "local-candidate", candidateType: overrides?.relay ? "relay" : "host" },
    { id: "RC1", type: "remote-candidate", candidateType: "prflx" },
    { id: "CODEC1", type: "codec", mimeType: "video/VP8" },
    {
      id: "OUTV", type: "outbound-rtp", kind: "video", codecId: "CODEC1",
      frameWidth: 1280, frameHeight: 720, framesPerSecond: 30,
      qualityLimitationReason: "none", bytesSent: 2_000_000,
    },
    {
      id: "INV", type: "inbound-rtp", kind: "video",
      frameWidth: 640, frameHeight: 480, framesPerSecond: 24,
      packetsLost: 3, jitter: 0.012, framesDropped: 1, bytesReceived: 1_000_000,
    },
    { id: "INA", type: "inbound-rtp", kind: "audio", jitter: 0.005, packetsLost: 1 },
    { id: "OUTA", type: "outbound-rtp", kind: "audio", bytesSent: 100_000 },
  ];
}

describe("summarizeCallStats", () => {
  it("extracts route, codec, resolutions, rtt and limitation from a chromium-shaped report", () => {
    const { sample, counters } = summarizeCallStats(chromiumReport(), 2000, null);
    expect(sample.route).toBe("direct");
    expect(sample.localCandidateType).toBe("host");
    expect(sample.remoteCandidateType).toBe("prflx");
    expect(sample.rttMs).toBe(4);
    expect(sample.availableOutgoingBitrate).toBe(2_400_000);
    expect(sample.videoCodec).toBe("video/VP8");
    expect(sample.outWidth).toBe(1280);
    expect(sample.outHeight).toBe(720);
    expect(sample.outFps).toBe(30);
    expect(sample.qualityLimitationReason).toBe("none");
    expect(sample.inWidth).toBe(640);
    expect(sample.inPacketsLost).toBe(3);
    expect(sample.inJitterMs).toBe(12);
    expect(sample.audioInJitterMs).toBe(5);
    expect(sample.audioInPacketsLost).toBe(1);
    // First sample has no previous counters → bitrates unknown, counters recorded.
    expect(sample.outBitrate).toBeNull();
    expect(counters.videoOutBytes).toBe(2_000_000);
    expect(counters.videoInBytes).toBe(1_000_000);
    expect(counters.audioOutBytes).toBe(100_000);
  });

  it("computes live bitrates from byte deltas between samples", () => {
    const prev: PreviousCounters = { atMs: 0, videoOutBytes: 1_500_000, videoInBytes: 750_000, audioOutBytes: 84_000 };
    const { sample } = summarizeCallStats(chromiumReport(), 2000, prev);
    // (2,000,000 - 1,500,000) bytes over 2s = 2,000,000 bps
    expect(sample.outBitrate).toBe(2_000_000);
    expect(sample.inBitrate).toBe(1_000_000);
    expect(sample.audioOutBitrate).toBe(64_000);
  });

  it("flags a TURN relay route when either selected candidate is a relay", () => {
    const { sample } = summarizeCallStats(chromiumReport({ relay: true }), 2000, null);
    expect(sample.route).toBe("relay");
  });

  it("survives an empty or teardown-shaped report", () => {
    const { sample } = summarizeCallStats([], 2000, null);
    expect(sample.route).toBeNull();
    expect(sample.outWidth).toBeNull();
    expect(sample.rttMs).toBeNull();
  });

  it("falls back to the nominated succeeded pair when transport stats are absent", () => {
    const entries = chromiumReport().filter((entry) => entry.type !== "transport");
    const { sample } = summarizeCallStats(entries, 2000, null);
    expect(sample.route).toBe("direct");
    expect(sample.rttMs).toBe(4);
  });
});
