import { test, expect, vi, afterEach } from "vitest";
import { buildRtcConfiguration, parseRelayRow } from "@/lib/call-ice";

afterEach(() => { vi.unstubAllEnvs(); });

test("defaults to public STUN plus the Open Relay TURN fallback", () => {
  const cfg = buildRtcConfiguration();
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("turn:"));
  expect(turn).toBeTruthy();
  expect(turn?.username).toBe("openrelayproject");
});

test("env TURN overrides the fallback relay", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  vi.stubEnv("VITE_TURN_USERNAME", "u");
  vi.stubEnv("VITE_TURN_CREDENTIAL", "p");
  const cfg = buildRtcConfiguration();
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("turn:"));
  expect(turn?.username).toBe("u");
  expect(String(turn?.urls)).toContain("turn.example.com");
});

test("operator relay config wins over env and fallback", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  const relay = parseRelayRow({
    stun_urls: ["stun:stun.qguard.dev:3478"],
    turn_urls: ["turn:relay.qguard.dev:3478", "turns:relay.qguard.dev:5349"],
    turn_username: "qguard",
    turn_credential: "secret",
  });
  const cfg = buildRtcConfiguration(relay);
  expect(String(cfg.iceServers?.[0]?.urls)).toContain("stun.qguard.dev");
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("relay.qguard.dev"));
  expect(turn?.username).toBe("qguard");
});

test("parseRelayRow rejects rows without valid TURN urls or bad schemes", () => {
  expect(parseRelayRow(null)).toBeNull();
  expect(parseRelayRow({ turn_urls: [] })).toBeNull();
  expect(parseRelayRow({ turn_urls: ["https://not-a-relay.example"] })).toBeNull();
  const relay = parseRelayRow({ turn_urls: ["turn:ok.example:3478", "javascript:alert(1)"] });
  expect(relay?.turnUrls).toEqual(["turn:ok.example:3478"]);
});
