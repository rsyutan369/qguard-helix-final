import { test, expect } from "vitest";
import { parseCallSignal } from "@/lib/call-signaling";

test("parses a valid signal row", () => {
  const row = parseCallSignal({
    id: "1", call_id: "c1", conversation_id: "cv1",
    from_user_id: "u1", from_device_id: "d1", to_user_id: "u2", to_device_id: "d2",
    signal_type: "offer", payload: { sdp: "x" }, created_at: "2026-06-20T00:00:00Z",
  });
  expect(row?.signal_type).toBe("offer");
  expect(row?.payload.sdp).toBe("x");
});

test("rejects an unknown signal_type", () => {
  expect(parseCallSignal({ signal_type: "nope" })).toBeNull();
});