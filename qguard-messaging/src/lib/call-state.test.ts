import { test, expect } from "vitest";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";

test("caller flow: start -> answered -> connected -> ended", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "start-outgoing", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
  expect(s.phase).toBe("calling");
  expect(s.role).toBe("caller");
  s = callReducer(s, { type: "remote-answered" });
  expect(s.phase).toBe("connecting");
  s = callReducer(s, { type: "media-connected", safetyNumber: "1234-5678-9012-3456-7890" });
  expect(s.phase).toBe("connected");
  expect(s.safetyNumber).toBe("1234-5678-9012-3456-7890");
  s = callReducer(s, { type: "ended" });
  expect(s.phase).toBe("ended");
});

test("incoming ring -> reject -> ended", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "incoming", callId: "c2", peerUserId: "u1", peerDeviceId: "d1" });
  expect(s.phase).toBe("ringing");
  expect(s.role).toBe("callee");
  s = callReducer(s, { type: "ended" });
  expect(s.phase).toBe("ended");
});

test("a second incoming while busy is ignored", () => {
  let s = callReducer(INITIAL_CALL_STATE, { type: "start-outgoing", callId: "c1", peerUserId: "u2", peerDeviceId: "d2" });
  const before = s;
  s = callReducer(s, { type: "incoming", callId: "c3", peerUserId: "u9", peerDeviceId: "d9" });
  expect(s).toBe(before); // unchanged - caller already in a call
});