import { test, expect, vi, afterEach } from "vitest";
import { buildRtcConfiguration, describeCallConnectFailure, hasConfiguredRelay, parseRelayRow } from "@/lib/call-ice";

afterEach(() => { vi.unstubAllEnvs(); });

test("defaults to public STUN with NO relay when an operator has not configured one", () => {
  // The old default shipped a public TURN (openrelay.metered.ca). Real Chromium
  // ICE showed it returns `TURN allocate error` and, worse, that an
  // unallocatable TURN entry stops gathering from ever completing — which
  // delayed even same-LAN candidates past the caller's give-up. A relay is now
  // only ever included when someone actually configured one.
  const cfg = buildRtcConfiguration();
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("turn:"))).toBe(false);
});

test("pre-gathers a candidate pool so candidates are ready before negotiation", () => {
  expect(buildRtcConfiguration().iceCandidatePoolSize).toBe(1);
});

test("env TURN is used when no operator relay row exists", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  vi.stubEnv("VITE_TURN_USERNAME", "u");
  vi.stubEnv("VITE_TURN_CREDENTIAL", "p");
  const cfg = buildRtcConfiguration(null, true);
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("turn:"));
  expect(turn?.username).toBe("u");
  expect(String(turn?.urls)).toContain("turn.example.com");
});

test("operator relay config wins over env", () => {
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  const relay = parseRelayRow({
    stun_urls: ["stun:stun.qguard.dev:3478"],
    turn_urls: ["turn:relay.qguard.dev:3478", "turns:relay.qguard.dev:5349"],
    turn_username: "qguard",
    turn_credential: "secret",
  });
  const cfg = buildRtcConfiguration(relay, true);
  expect(String(cfg.iceServers?.[0]?.urls)).toContain("stun.qguard.dev");
  const turn = cfg.iceServers?.find((s) => String(s.urls).includes("relay.qguard.dev"));
  expect(turn?.username).toBe("qguard");
});

test("a relay's STUN urls are used even while the relay itself is withheld", () => {
  // Dropping an unproven TURN entry must not also drop the operator's STUN
  // servers — those are what produce the srflx candidates a direct connection
  // needs, and they are not implicated in the relay's failure.
  const relay = parseRelayRow({
    stun_urls: ["stun:stun.qguard.dev:3478"],
    turn_urls: ["turn:unproven.qguard.dev:3478"],
  });
  const cfg = buildRtcConfiguration(relay, null);
  expect(String(cfg.iceServers?.[0]?.urls)).toContain("stun.qguard.dev");
  expect(cfg.iceServers?.some((s) => String(s.urls).includes("unproven.qguard.dev"))).toBe(false);
});

test("a relay proven unable to allocate is dropped, but STUN is kept", () => {
  const relay = parseRelayRow({ turn_urls: ["turn:dead.example:3478"], turn_username: "u", turn_credential: "p" });
  const healthy = buildRtcConfiguration(relay, true);
  expect(healthy.iceServers?.some((s) => String(s.urls).includes("dead.example"))).toBe(true);
  const dead = buildRtcConfiguration(relay, false);
  expect(dead.iceServers?.some((s) => String(s.urls).includes("dead.example"))).toBe(false);
  expect(dead.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
});

test("a live call withholds a relay that has not been PROVEN to allocate", () => {
  // Deliberately the opposite of the rule that stood here before ("unknown
  // health still tries the relay"). That rule cost every call, not just
  // cross-network ones: a dead TURN entry stops ICE gathering from ever
  // completing, which is measurably worse than having no relay at all. The
  // relay returns the moment the probe proves it — including on this call's own
  // ICE restart — so withholding it costs reachability for seconds, where
  // admitting a dead one costs calling entirely.
  const relay = parseRelayRow({ turn_urls: ["turn:unknown.example:3478"] });
  const unproven = buildRtcConfiguration(relay, null, "proven-only");
  expect(unproven.iceServers?.some((s) => String(s.urls).includes("unknown.example"))).toBe(false);
  expect(unproven.iceServers?.some((s) => String(s.urls).includes("stun:"))).toBe(true);
});

test("proven-only is the DEFAULT admission, so a careless caller cannot admit a dead relay", () => {
  const relay = parseRelayRow({ turn_urls: ["turn:unknown.example:3478"] });
  expect(buildRtcConfiguration(relay).iceServers?.some((s) => String(s.urls).includes("unknown.example")))
    .toBe(false);
});

test("the health probe is the one caller that may use an unproven relay", () => {
  // Otherwise the probe could never measure anything: under proven-only a
  // never-tested relay would be stripped out of its own test, and a relay that
  // recovered could never be found healthy again.
  const relay = parseRelayRow({ turn_urls: ["turn:unknown.example:3478"] });
  expect(buildRtcConfiguration(relay, null, "probe").iceServers
    ?.some((s) => String(s.urls).includes("unknown.example"))).toBe(true);
  // This is why `probeRelayHealth` forces health back to `null` for its own
  // build: a verdict of `false` is still honoured under probe admission, so a
  // probe that passed its previous verdict through would strip the relay out of
  // the very test meant to re-measure it.
  expect(buildRtcConfiguration(relay, false, "probe").iceServers
    ?.some((s) => String(s.urls).includes("unknown.example"))).toBe(false);
});

test("hasConfiguredRelay reports whether cross-network calls are even possible", () => {
  expect(hasConfiguredRelay(null)).toBe(false);
  expect(hasConfiguredRelay(parseRelayRow({ turn_urls: ["turn:relay.example:3478"] }))).toBe(true);
  vi.stubEnv("VITE_TURN_URL", "turn:turn.example.com:3478");
  expect(hasConfiguredRelay(null)).toBe(true);
});

test("parseRelayRow rejects rows without valid TURN urls or bad schemes", () => {
  expect(parseRelayRow(null)).toBeNull();
  expect(parseRelayRow({ turn_urls: [] })).toBeNull();
  expect(parseRelayRow({ turn_urls: ["https://not-a-relay.example"] })).toBeNull();
  const relay = parseRelayRow({ turn_urls: ["turn:ok.example:3478", "javascript:alert(1)"] });
  expect(relay?.turnUrls).toEqual(["turn:ok.example:3478"]);
});

test("a connect failure names the actual blocker instead of saying 'timed out'", () => {
  expect(describeCallConnectFailure({ status: "not-configured", checkedAt: 0 }))
    .toContain("No TURN relay is configured");
  expect(describeCallConnectFailure({ status: "unreachable", checkedAt: 0, detail: "401 Unauthorized" }))
    .toContain("401 Unauthorized");
  // A healthy relay means the relay is not the story — do not blame it.
  const healthy = describeCallConnectFailure({ status: "healthy", checkedAt: 0, relayCandidates: 2 });
  expect(healthy).not.toContain("relay");
  expect(describeCallConnectFailure(null)).not.toContain("relay");
});
