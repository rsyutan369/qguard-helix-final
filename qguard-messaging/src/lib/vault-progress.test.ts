import { describe, expect, it } from "vitest";
import { formatThroughput, formatEta, phaseLabel, opLabel } from "./vault-progress";

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
});
