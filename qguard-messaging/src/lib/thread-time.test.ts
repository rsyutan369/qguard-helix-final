import { describe, expect, it } from "vitest";
import { formatThreadTime } from "@/lib/thread-time";

// Local-time constructors so the buckets do not depend on the test machine's zone.
const now = new Date(2026, 9, 20, 15, 30);

describe("formatThreadTime", () => {
  it("shows the clock time for today", () => {
    const label = formatThreadTime(new Date(2026, 9, 20, 9, 5).toISOString(), now);
    expect(label).toBe(new Date(2026, 9, 20, 9, 5).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }));
  });

  it("says Yesterday for the previous calendar day, even late at night", () => {
    expect(formatThreadTime(new Date(2026, 9, 19, 23, 59).toISOString(), now)).toBe("Yesterday");
    expect(formatThreadTime(new Date(2026, 9, 19, 0, 1).toISOString(), now)).toBe("Yesterday");
  });

  it("shows the weekday within the last week, then the date", () => {
    const fourDaysAgo = new Date(2026, 9, 16, 12, 0);
    expect(formatThreadTime(fourDaysAgo.toISOString(), now)).toBe(fourDaysAgo.toLocaleDateString(undefined, { weekday: "short" }));
    const lastMonth = new Date(2026, 8, 3, 12, 0);
    expect(formatThreadTime(lastMonth.toISOString(), now)).toBe(lastMonth.toLocaleDateString(undefined, { month: "short", day: "numeric" }));
  });

  it("adds the year only for another year", () => {
    const lastYear = new Date(2025, 11, 31, 12, 0);
    expect(formatThreadTime(lastYear.toISOString(), now)).toContain("2025");
  });

  it("never invents a time", () => {
    expect(formatThreadTime(null, now)).toBe("");
    expect(formatThreadTime("", now)).toBe("");
    expect(formatThreadTime("not a date", now)).toBe("");
  });
});
