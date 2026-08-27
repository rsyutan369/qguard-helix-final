import { describe, expect, it } from "vitest";
import { connectDeadlineMs } from "@/lib/call-deadline";

const STALL = 20_000;
const NOW = 1_000_000;

describe("connectDeadlineMs", () => {
  it("does not arm anything while the call is still ringing", () => {
    // ceiling 0 == not in the connect phase; the ring's own wall clock owns the
    // timer and progress events must not extend it.
    expect(connectDeadlineMs(NOW, 0, STALL)).toBeNull();
  });

  it("arms a full stall window while there is plenty of ceiling left", () => {
    expect(connectDeadlineMs(NOW, NOW + 90_000, STALL)).toBe(STALL);
  });

  it("keeps a slow-but-advancing connection alive past the old fixed give-up", () => {
    // The regression this exists for: at 44s into a call the old clock was about
    // to fire, while the peer was still emitting candidates. Progress at that
    // point must buy more time, not none.
    const ceiling = NOW + 46_000; // 44s into a 90s ceiling
    expect(connectDeadlineMs(NOW, ceiling, STALL)).toBe(STALL);
  });

  it("never arms past the ceiling", () => {
    expect(connectDeadlineMs(NOW, NOW + 5_000, STALL)).toBe(5_000);
  });

  it("stops re-arming once the ceiling has passed, so the backstop can fire", () => {
    // Returning a fresh timeout here would let a call that trickles candidates
    // forever keep resetting its own deadline and never end.
    expect(connectDeadlineMs(NOW, NOW, STALL)).toBeNull();
    expect(connectDeadlineMs(NOW, NOW - 1, STALL)).toBeNull();
  });
});
