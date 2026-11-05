import { describe, expect, it } from "vitest";
import { dotAt } from "./PatternPad";

// A 280 px pad: 70 px cells, dot centers at 35, 105, 175, 245.

describe("pattern pad hit test", () => {
  it("finds the dot under a touch near its center", () => {
    expect(dotAt(35, 35, 280)).toBe(0);
    expect(dotAt(245, 35, 280)).toBe(3);
    expect(dotAt(35, 245, 280)).toBe(12);
    expect(dotAt(180, 100, 280)).toBe(6); // a few pixels off center still counts
  });

  it("ignores the gaps between dots and anything off the pad", () => {
    expect(dotAt(70, 70, 280)).toBeNull(); // the corner between four dots
    expect(dotAt(35, 70, 280)).toBeNull(); // between two rows
    expect(dotAt(-5, 35, 280)).toBeNull();
    expect(dotAt(35, 290, 280)).toBeNull();
  });
});
