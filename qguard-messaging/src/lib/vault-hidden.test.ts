import { describe, expect, it } from "vitest";
import { fillWords, PHRASE_WORDS, pickCheckPositions, splitPhrase } from "./vault-hidden";

const PHRASE = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const empty = () => Array.from({ length: PHRASE_WORDS }, () => "");

describe("splitPhrase", () => {
  it("accepts spaces, new lines, commas and list numbers", () => {
    expect(splitPhrase(PHRASE)).toHaveLength(12);
    expect(splitPhrase("1. Legal\n2) WINNER, 3. thank;  4 year")).toEqual(["legal", "winner", "thank", "year"]);
    expect(splitPhrase("   ")).toEqual([]);
  });
});

describe("fillWords", () => {
  it("a whole phrase pasted into the first box fills all twelve", () => {
    expect(fillWords(empty(), 0, PHRASE).join(" ")).toBe(PHRASE);
  });

  it("a paste part way fills from that box and stops at the last", () => {
    const filled = fillWords(empty(), 10, "alpha beta gamma delta");
    expect(filled.slice(10)).toEqual(["alpha", "beta"]);
    expect(filled.slice(0, 10).every((word) => word === "")).toBe(true);
  });

  it("typing one word changes only its box, lowercased and without spaces", () => {
    const start = fillWords(empty(), 0, PHRASE);
    const next = fillWords(start, 3, " YEAR ");
    expect(next[3]).toBe("year");
    expect(next.filter((word, i) => word !== start[i])).toEqual([]);
    expect(fillWords(start, 3, "")[3]).toBe("");
  });

  it("a space typed inside a box carries the next word into the next box", () => {
    const next = fillWords(empty(), 3, "year wa");
    expect(next.slice(3, 5)).toEqual(["year", "wa"]);
  });
});

describe("pickCheckPositions", () => {
  it("picks three distinct ascending positions inside the phrase", () => {
    for (let run = 0; run < 200; run += 1) {
      const positions = pickCheckPositions();
      expect(positions).toHaveLength(3);
      expect(new Set(positions).size).toBe(3);
      expect([...positions].sort((a, b) => a - b)).toEqual(positions);
      expect(positions.every((p) => p >= 0 && p < PHRASE_WORDS)).toBe(true);
    }
  });

  it("is driven by the random source", () => {
    expect(pickCheckPositions(3, () => 0)).toEqual([1, 2, 3]);
    expect(pickCheckPositions(PHRASE_WORDS, () => 0.5)).toEqual(Array.from({ length: PHRASE_WORDS }, (_, i) => i));
  });
});
