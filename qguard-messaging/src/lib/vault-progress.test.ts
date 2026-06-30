import { describe, expect, it } from "vitest";
import { formatThroughput, formatEta, phaseLabel, opLabel, overallPercent, type VaultProgress } from "./vault-progress";

function ev(partial: Partial<VaultProgress>): VaultProgress {
  return {
    op: "encrypt", phase: "init", message: "", processedBytes: 0, totalBytes: 0,
    chunkIndex: 0, totalChunks: 0, level: "info", ...partial,
  };
}

describe("vault-progress helpers", () => {
  it("formats throughput from real bytes and elapsed time", () => {
    expect(formatThroughput(41 * 1024 * 1024, 1000)).toBe("41 MB/s");
    expect(formatThroughput(0, 0)).toBe("— MB/s");
  });

  it("estimates ETA from real progress", () => {
    // 50 MB done of 100 MB in 1s => ~1s remaining
    expect(formatEta(50 * 1024 * 1024, 100 * 1024 * 1024, 1000)).toBe("ETA 1s");
    expect(formatEta(0, 0, 0)).toBe("ETA —");
  });

  it("maps phases and ops to human labels", () => {
    expect(phaseLabel("vmk_wrap")).toMatch(/ML-KEM-1024/);
    expect(opLabel("encrypt")).toBe("Encrypting");
    expect(opLabel("rewrap")).toBe("Re-protecting");
  });

  it("computes a stage-weighted percent that climbs across real phases", () => {
    // The encrypt phases must produce a strictly increasing percentage so the
    // bar visibly advances even for a single-chunk (small) file.
    const order = ["init", "fek", "vmk_wrap", "sign", "header"];
    const pcts = order.map((phase) => overallPercent(ev({ phase })));
    for (let i = 1; i < pcts.length; i += 1) {
      expect(pcts[i]).toBeGreaterThan(pcts[i - 1]);
    }
    // The chunk stage fills proportionally to real processed bytes.
    const half = overallPercent(ev({ phase: "chunk", processedBytes: 50, totalBytes: 100 }));
    const full = overallPercent(ev({ phase: "chunk", processedBytes: 100, totalBytes: 100 }));
    expect(full).toBeGreaterThan(half);
    expect(half).toBeGreaterThan(pcts[pcts.length - 1]);
    // Done is always exactly 100.
    expect(overallPercent(ev({ phase: "done" }))).toBe(100);
  });
});
