import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CALL_STAGES,
  HISTORY_STAGES,
  completeTimeline,
  createTimeline,
  describeTimeline,
  formatTimeline,
  markTimeline,
  onTimeline,
  publishTimeline,
  recentTimelines,
  resetTimelines,
  stageAtMs,
  stageDeltaMs,
} from "./perf-timeline";

beforeEach(() => {
  resetTimelines();
  vi.restoreAllMocks();
});

describe("timeline marks", () => {
  it("records stages as offsets from the start, not wall clock", () => {
    const timeline = createTimeline("history", "conversation-1", 1_000);
    markTimeline(timeline, HISTORY_STAGES.loadStart, 1_000);
    markTimeline(timeline, HISTORY_STAGES.fetchComplete, 1_260);
    markTimeline(timeline, HISTORY_STAGES.rendered, 1_842);

    expect(stageAtMs(timeline, HISTORY_STAGES.loadStart)).toBe(0);
    expect(stageAtMs(timeline, HISTORY_STAGES.fetchComplete)).toBe(260);
    expect(stageDeltaMs(timeline, HISTORY_STAGES.fetchComplete, HISTORY_STAGES.rendered)).toBe(582);
  });

  it("keeps the FIRST time a stage was reached", () => {
    // A stage reachable from two paths (cache hit, then a backend decrypt) must
    // report when the pipeline first got there — a later write would make a slow
    // load look fast.
    const timeline = createTimeline("history", "conversation-1", 0);
    markTimeline(timeline, HISTORY_STAGES.decryptComplete, 120);
    markTimeline(timeline, HISTORY_STAGES.decryptComplete, 900);
    expect(stageAtMs(timeline, HISTORY_STAGES.decryptComplete)).toBe(120);
  });

  it("never reports a negative offset when the clock is handed back a stale now", () => {
    const timeline = createTimeline("call", "call-1", 5_000);
    markTimeline(timeline, CALL_STAGES.initiated, 4_900);
    expect(stageAtMs(timeline, CALL_STAGES.initiated)).toBe(0);
  });

  it("returns null for a stage the pipeline never reached", () => {
    const timeline = createTimeline("call", "call-1", 0);
    markTimeline(timeline, CALL_STAGES.initiated, 0);
    expect(stageAtMs(timeline, CALL_STAGES.mediaConnected)).toBeNull();
    expect(stageDeltaMs(timeline, CALL_STAGES.initiated, CALL_STAGES.mediaConnected)).toBeNull();
  });

  it("ignores marks that arrive after completion", () => {
    const timeline = createTimeline("history", "conversation-1", 0);
    completeTimeline(timeline, "timeout", 10_000);
    markTimeline(timeline, HISTORY_STAGES.rendered, 11_000);
    expect(stageAtMs(timeline, HISTORY_STAGES.rendered)).toBeNull();
  });
});

describe("completion", () => {
  it("keeps the first outcome so a late success cannot mask a timeout", () => {
    const timeline = createTimeline("history", "conversation-1", 0);
    completeTimeline(timeline, "timeout", 10_000);
    completeTimeline(timeline, "ok", 12_000);
    expect(timeline.outcome).toBe("timeout");
    expect(timeline.totalMs).toBe(10_000);
  });
});

describe("formatting", () => {
  it("puts the stage offsets and context on one grep-able line", () => {
    const timeline = createTimeline("history", "66f6662a-aaaa-bbbb-cccc-dddddddddddd", 0);
    markTimeline(timeline, HISTORY_STAGES.loadStart, 0);
    markTimeline(timeline, HISTORY_STAGES.rendered, 842);
    describeTimeline(timeline, { rows: 207, cache: true });
    completeTimeline(timeline, "ok", 842);

    const line = formatTimeline(timeline);
    expect(line).toContain("[perf] history 66f6662a");
    expect(line).toContain("ok total=842ms");
    expect(line).toContain("history_rendered=842");
    expect(line).toContain("rows=207");
    expect(line).toContain("cache=true");
  });
});

describe("publishing", () => {
  it("retains and announces completed timelines", () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const seen: string[] = [];
    const stop = onTimeline((timeline) => seen.push(timeline.id));

    const timeline = createTimeline("history", "conversation-1", 0);
    publishTimeline(completeTimeline(timeline, "ok", 100));

    expect(seen).toEqual(["conversation-1"]);
    expect(recentTimelines("history")).toHaveLength(1);
    expect(recentTimelines("call")).toHaveLength(0);
    stop();
  });

  it("refuses to publish an OPEN timeline", () => {
    // Publishing an unfinished pipeline would log it as though it had finished.
    const timeline = createTimeline("call", "call-1", 0);
    publishTimeline(timeline);
    expect(recentTimelines()).toHaveLength(0);
  });

  it("warns on a failed pipeline and stays quiet on a healthy one", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);

    publishTimeline(completeTimeline(createTimeline("history", "slow", 0), "timeout", 10_000));
    publishTimeline(completeTimeline(createTimeline("history", "fast", 0), "ok", 200));

    expect(warn).toHaveBeenCalledTimes(1);
    expect(debug).toHaveBeenCalledTimes(1);
  });

  it("does not let a throwing listener break the pipeline being observed", () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const stop = onTimeline(() => {
      throw new Error("observer exploded");
    });
    expect(() => publishTimeline(completeTimeline(createTimeline("call", "call-1", 0), "ok", 10)))
      .not.toThrow();
    stop();
  });

  it("bounds retention so a long session cannot grow without limit", () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    for (let index = 0; index < 60; index += 1) {
      publishTimeline(completeTimeline(createTimeline("history", `conversation-${index}`, 0), "ok", 1));
    }
    const kept = recentTimelines();
    expect(kept).toHaveLength(40);
    // The newest are the ones worth keeping.
    expect(kept[kept.length - 1].id).toBe("conversation-59");
  });
});

describe("stage vocabulary", () => {
  it("uses exactly the stage names the production targets are written against", () => {
    expect(Object.values(HISTORY_STAGES)).toContain("history_load_start");
    expect(Object.values(HISTORY_STAGES)).toContain("decrypt_start");
    expect(Object.values(HISTORY_STAGES)).toContain("decrypt_complete");
    expect(Object.values(HISTORY_STAGES)).toContain("history_rendered");
    expect(Object.values(CALL_STAGES)).toEqual([
      "call_initiated",
      "signaling_started",
      "ICE_started",
      "ICE_connected",
      "media_connected",
      "call_established",
    ]);
  });
});
