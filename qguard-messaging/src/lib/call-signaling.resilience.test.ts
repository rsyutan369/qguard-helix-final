import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

// A minimal Supabase double: one realtime channel we can push inserts into, and
// a `messaging_call_signals` table the catch-up reader can poll.
interface FakeRow {
  id: string;
  call_id: string;
  conversation_id: string;
  from_user_id: string;
  from_device_id: string;
  to_user_id: string;
  to_device_id: string;
  signal_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

const rows: FakeRow[] = [];
let insertHandler: ((payload: { new: FakeRow }) => void) | null = null;
let subscribeCallback: ((status: string) => void) | null = null;
let selectCalls = 0;

const channelStub = {
  on(_event: string, _filter: unknown, handler: (payload: { new: FakeRow }) => void) {
    insertHandler = handler;
    return channelStub;
  },
  subscribe(cb?: (status: string) => void) {
    subscribeCallback = cb ?? null;
    return channelStub;
  },
};

function tableQuery() {
  const query = {
    select() { selectCalls += 1; return query; },
    eq() { return query; },
    gte(_column: string, value: string) { query._since = value; return query; },
    order() { return query; },
    limit() {
      const since = query._since ?? "";
      const data = rows.filter((row) => row.created_at >= since);
      return Promise.resolve({ data, error: null });
    },
    _since: "" as string,
  };
  return query;
}

vi.mock("@/lib/supabase", () => ({
  supabase: {
    channel: () => channelStub,
    removeChannel: () => Promise.resolve("ok"),
    from: () => tableQuery(),
  },
}));

const { subscribeCallSignals } = await import("@/lib/call-signaling");

function makeRow(overrides: Partial<FakeRow> = {}): FakeRow {
  return {
    id: overrides.id ?? crypto.randomUUID(),
    call_id: overrides.call_id ?? "call-1",
    conversation_id: "conv-1",
    from_user_id: "peer-user",
    from_device_id: "peer-device",
    to_user_id: "me",
    to_device_id: "my-device",
    signal_type: overrides.signal_type ?? "ring",
    payload: {},
    created_at: overrides.created_at ?? new Date().toISOString(),
    ...overrides,
  };
}

describe("subscribeCallSignals", () => {
  beforeEach(() => {
    rows.length = 0;
    insertHandler = null;
    subscribeCallback = null;
    selectCalls = 0;
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("delivers a realtime insert addressed to this device", async () => {
    const seen: string[] = [];
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: (r) => seen.push(r.signal_type) });
    subscribeCallback?.("SUBSCRIBED");
    insertHandler?.({ new: makeRow({ signal_type: "offer" }) });
    expect(seen).toEqual(["offer"]);
    channel.close();
  });

  test("ignores a signal addressed to another device of the same user", async () => {
    const seen: string[] = [];
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: (r) => seen.push(r.id) });
    subscribeCallback?.("SUBSCRIBED");
    insertHandler?.({ new: makeRow({ to_device_id: "some-other-device" }) });
    expect(seen).toEqual([]);
    channel.close();
  });

  /**
   * The regression this whole layer exists for: Android suspends the WebView's
   * WebSocket in the background, so the ring INSERT never arrives over realtime
   * and `postgres_changes` has no replay. The catch-up reader must find it.
   */
  test("catch-up polling delivers a signal the realtime channel never saw", async () => {
    const seen: string[] = [];
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: (r) => seen.push(r.signal_type) });
    // Socket is down — no SUBSCRIBED, and the insert handler is never invoked.
    subscribeCallback?.("CHANNEL_ERROR");
    rows.push(makeRow({ signal_type: "ring" }));

    await vi.advanceTimersByTimeAsync(2_500);

    expect(seen).toEqual(["ring"]);
    channel.close();
  });

  test("a row delivered by BOTH realtime and polling fires onSignal once", async () => {
    const seen: string[] = [];
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: (r) => seen.push(r.id) });
    subscribeCallback?.("SUBSCRIBED");
    const row = makeRow({ signal_type: "offer" });
    rows.push(row);
    insertHandler?.({ new: row });

    await vi.advanceTimersByTimeAsync(15_000);

    expect(seen).toEqual([row.id]);
    channel.close();
  });

  test("boost() polls far more aggressively than the idle safety net", async () => {
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: () => undefined });
    subscribeCallback?.("SUBSCRIBED");
    await vi.advanceTimersByTimeAsync(0);
    const idleBaseline = selectCalls;

    // Idle with a healthy channel: at most one more read in 3s.
    await vi.advanceTimersByTimeAsync(3_000);
    const idleReads = selectCalls - idleBaseline;

    channel.boost();
    const boostBaseline = selectCalls;
    await vi.advanceTimersByTimeAsync(3_000);
    const boostReads = selectCalls - boostBaseline;

    expect(boostReads).toBeGreaterThan(idleReads);
    channel.close();
  });

  test("close() stops all further polling", async () => {
    const channel = subscribeCallSignals({ userId: "me", deviceId: "my-device", onSignal: () => undefined });
    subscribeCallback?.("CHANNEL_ERROR");
    await vi.advanceTimersByTimeAsync(2_000);
    channel.close();
    const afterClose = selectCalls;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(selectCalls).toBe(afterClose);
  });
});
