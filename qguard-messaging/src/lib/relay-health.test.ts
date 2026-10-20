import { describe, expect, it } from "vitest";
import { classifyRelayHealth, nextRecheckMs, probeRelay } from "./relay-health";

const RELAY = "https://abcd.supabase.co";

describe("classifyRelayHealth", () => {
  it("is quiet while the relay answers, even with a request-level 4xx", () => {
    expect(classifyRelayHealth({ online: true, relay: { kind: "ok" }, control: "unavailable" }).state).toBe("ok");
    expect(classifyRelayHealth({ online: true, relay: { kind: "http_error", status: 401 }, control: "unavailable" }).state).toBe("ok");
  });

  it("says offline when the OS says so", () => {
    expect(classifyRelayHealth({ online: false, relay: { kind: "unreachable" }, control: "unreachable" }).state).toBe("offline");
  });

  it("blames the service, not the network, for a 5xx", () => {
    const health = classifyRelayHealth({ online: true, relay: { kind: "http_error", status: 503 }, control: "unavailable" });
    expect(health.state).toBe("relay_failing");
    expect(health.detail).toContain("503");
  });

  it("separates a down or blocked relay from no internet using the control host", () => {
    expect(classifyRelayHealth({ online: true, relay: { kind: "unreachable" }, control: "reachable" }).state)
      .toBe("relay_unreachable_internet_ok");
    expect(classifyRelayHealth({ online: true, relay: { kind: "unreachable" }, control: "unreachable" }).state)
      .toBe("relay_unreachable_no_internet");
  });

  it("admits it cannot tell where there is no control host (Android)", () => {
    const health = classifyRelayHealth({ online: true, relay: { kind: "unreachable" }, control: "unavailable" });
    expect(health.state).toBe("relay_unreachable_unknown");
    expect(health.detail).toMatch(/can't tell/);
  });
});

describe("probeRelay", () => {
  it("asks the relay's own health endpoint with the public key and no credentials", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fake = (async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    expect(await probeRelay(`${RELAY}/rest/v1`, "anon-key", fake)).toEqual({ kind: "ok" });
    expect(calls[0].url).toBe(`${RELAY}/auth/v1/health`);
    expect(calls[0].init?.credentials).toBe("omit");
    expect((calls[0].init?.headers as Record<string, string>).apikey).toBe("anon-key");
  });

  it("reports HTTP errors and network failures distinctly", async () => {
    const status503 = (async () => new Response("", { status: 503 })) as unknown as typeof fetch;
    const throws = (async () => { throw new TypeError("Failed to fetch"); }) as unknown as typeof fetch;
    expect(await probeRelay(RELAY, "k", status503)).toEqual({ kind: "http_error", status: 503 });
    expect(await probeRelay(RELAY, "k", throws)).toEqual({ kind: "unreachable" });
  });

  it("times out instead of hanging", async () => {
    const hangs = ((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    })) as unknown as typeof fetch;
    expect(await probeRelay(RELAY, "k", hangs, 20)).toEqual({ kind: "unreachable" });
  });

  it("never probes a missing, placeholder or plain-http relay", async () => {
    const never = (async () => { throw new Error("must not be called"); }) as unknown as typeof fetch;
    expect(await probeRelay("", "k", never)).toEqual({ kind: "not_configured" });
    expect(await probeRelay("https://qguard-messaging-placeholder.supabase.co", "k", never)).toEqual({ kind: "not_configured" });
    expect(await probeRelay("http://abcd.supabase.co", "k", never)).toEqual({ kind: "not_configured" });
  });
});

describe("nextRecheckMs", () => {
  it("backs off to once a minute", () => {
    expect([1, 2, 3, 4, 5, 9].map(nextRecheckMs)).toEqual([5_000, 10_000, 20_000, 40_000, 60_000, 60_000]);
  });
});
