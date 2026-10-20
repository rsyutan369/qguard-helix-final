import { describe, expect, it, vi } from "vitest";
import { flushOutbox, isNetworkFailure, type OutboxItem } from "./outbox";
import { mergeRowsById, rowsForDevice } from "./nearby";

vi.mock("@/lib/tauri", () => ({ safeInvoke: vi.fn() }));

const NOW = Date.parse("2026-10-20T12:00:00Z");
const item = (id: string, queuedAt: number, rows: Array<Record<string, unknown>> = [{ id: `${id}-row`, expires_at: null }]): OutboxItem => ({
  id, conversationId: "c1", queuedAt, rows,
});

function store(items: OutboxItem[]) {
  const current = [...items];
  return {
    list: async () => [...current],
    remove: async (id: string) => { current.splice(current.findIndex((entry) => entry.id === id), 1); },
    current,
  };
}

describe("isNetworkFailure", () => {
  it("keeps messages only when the relay never answered", () => {
    expect(isNetworkFailure(new TypeError("Failed to fetch"))).toBe(true);
    expect(isNetworkFailure({ message: "TypeError: Failed to fetch", code: "" })).toBe(true);
    expect(isNetworkFailure({ name: "AbortError", message: "aborted" })).toBe(true);
    expect(isNetworkFailure({ message: "request timed out" })).toBe(true);
  });

  it("NEG treats every database answer as final", () => {
    expect(isNetworkFailure({ message: "new row violates row-level security policy", code: "42501" })).toBe(false);
    expect(isNetworkFailure({ message: "Failed to fetch", code: "23505" })).toBe(false);
    expect(isNetworkFailure(null)).toBe(false);
    expect(isNetworkFailure({ message: "Recipient device is missing signed PQC prekeys" })).toBe(false);
  });
});

describe("flushOutbox", () => {
  it("uploads oldest first and empties the outbox", async () => {
    const outbox = store([item("b", 2), item("a", 1)]);
    const order: string[] = [];
    const result = await flushOutbox({ ...outbox, now: NOW, insert: async (rows) => { order.push(String(rows[0].id)); return { error: null }; } });
    expect(order).toEqual(["a-row", "b-row"]);
    expect(result).toEqual({ sent: 2, dropped: [], remaining: 0, blocked: false });
    expect(outbox.current).toEqual([]);
  });

  it("stops at the first network failure and keeps the rest", async () => {
    const outbox = store([item("a", 1), item("b", 2)]);
    const result = await flushOutbox({ ...outbox, now: NOW, insert: async () => ({ error: new TypeError("Failed to fetch") }) });
    expect(result).toMatchObject({ sent: 0, remaining: 2, blocked: true });
    expect(outbox.current.map((entry) => entry.id)).toEqual(["a", "b"]);
  });

  it("never delivers a disappearing message late", async () => {
    const outbox = store([item("gone", 1, [{ id: "r", expires_at: "2026-10-20T11:00:00Z" }])]);
    const insert = vi.fn(async () => ({ error: null }));
    const result = await flushOutbox({ ...outbox, now: NOW, insert });
    expect(insert).not.toHaveBeenCalled();
    expect(result.dropped).toEqual([{ id: "gone", reason: "expired while waiting" }]);
  });

  it("counts an already-uploaded copy as sent, and reports refusals", async () => {
    const outbox = store([item("dup", 1), item("refused", 2)]);
    let call = 0;
    const result = await flushOutbox({
      ...outbox, now: NOW,
      insert: async () => (call++ === 0 ? { error: { code: "23505", message: "duplicate key" } } : { error: { code: "42501", message: "not a member" } }),
    });
    expect(result.sent).toBe(1);
    expect(result.dropped).toEqual([{ id: "refused", reason: "not a member" }]);
    expect(outbox.current).toEqual([]);
  });
});

describe("nearby rows", () => {
  it("keeps only rows sealed to this device", () => {
    const rows = [{ id: "1", recipient_device_id: "mine" }, { id: "2", recipient_device_id: "theirs" }];
    expect(rowsForDevice(rows, "mine")).toEqual([{ id: "1", recipient_device_id: "mine" }]);
    expect(rowsForDevice(rows, null)).toEqual([]);
  });

  it("prefers the relay's copy of an envelope", () => {
    expect(mergeRowsById([{ id: "a", from: "relay" }], [{ id: "a", from: "nearby" }, { id: "b", from: "nearby" }]))
      .toEqual([{ id: "a", from: "relay" }, { id: "b", from: "nearby" }]);
  });
});
