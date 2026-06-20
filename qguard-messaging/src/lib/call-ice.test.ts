import { test, expect, vi, afterEach } from "vitest";
import { buildRtcConfiguration } from "@/lib/call-ice";

afterEach(() => { vi.unstubAllEnvs(); });

test("defaults to public STUN, no TURN", () => {
  const cfg = buildRtcConfiguration();
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("turn:"))).toBe(false);
});

test("includes TURN when configured", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  vi.stubEnv("VITE_TURN_USERNAME", "u");
  vi.stubEnv("VITE_TURN_CREDENTIAL", "p");
  const cfg = buildRtcConfiguration();
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("turn:"));
  expect(turn).toBeTruthy();
  expect(turn?.username).toBe("u");
});