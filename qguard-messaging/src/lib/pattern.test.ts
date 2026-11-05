import { describe, expect, it } from "vitest";
import { dotsBetween, encodePattern, extendPattern, isValidPattern, patternStrength } from "./pattern";

// The same cases as src-tauri/src/vault/pattern.rs: the pad must never send a
// pattern the core refuses, nor accept one the core would read differently.

const draw = (...dots: number[]) => dots.reduce<number[]>((pattern, dot) => extendPattern(pattern, dot), []);

describe("unlock patterns", () => {
  it("finds the dots a stroke passes over", () => {
    expect(dotsBetween(0, 2)).toEqual([1]);
    expect(dotsBetween(0, 15)).toEqual([5, 10]);
    expect(dotsBetween(3, 12)).toEqual([6, 9]);
    expect(dotsBetween(0, 6)).toEqual([]); // a knight's move passes no dot
    expect(dotsBetween(4, 4)).toEqual([]);
  });

  it("picks up a dot it passes over, as the pad does", () => {
    expect(draw(0, 2)).toEqual([0, 1, 2]);
    expect(draw(0, 15)).toEqual([0, 5, 10, 15]);
    // Already connected: passing over it again adds nothing.
    expect(draw(1, 0, 2)).toEqual([1, 0, 2]);
    // The same dot twice is ignored.
    expect(draw(0, 1, 1, 0)).toEqual([0, 1]);
  });

  it("accepts exactly what the core accepts", () => {
    expect(isValidPattern([0, 1, 2, 3, 7, 11])).toBe(true);
    expect(isValidPattern([5, 10, 0, 15, 14, 13])).toBe(true);
    expect(isValidPattern([0, 1, 2, 3, 7])).toBe(false); // five dots
    expect(isValidPattern([0, 2, 3, 7, 11, 15])).toBe(false); // jumped over 1
    expect(isValidPattern([0, 1, 2, 3, 7, 3])).toBe(false); // repeated
    expect(isValidPattern([0, 1, 2, 3, 7, 16])).toBe(false); // off the grid
    // Anything the pad draws, the core takes.
    expect(isValidPattern(draw(0, 15, 12, 3, 9, 6))).toBe(true);
  });

  it("encodes to the canonical text and grades length", () => {
    expect(encodePattern([0, 1, 2, 3, 7, 11])).toBe("4x4:0-1-2-3-7-11");
    expect(patternStrength([0, 1, 2])).toBe("too-short");
    expect(patternStrength([0, 1, 2, 3, 7, 11])).toBe("fair");
    expect(patternStrength([0, 1, 2, 3, 7, 11, 15, 14])).toBe("strong");
  });
});
