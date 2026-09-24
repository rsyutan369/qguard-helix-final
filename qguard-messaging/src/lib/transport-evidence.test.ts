import { describe, expect, it } from "vitest";
import {
  classifyKeyAgreement,
  measureTransport,
  mergeTransportEvidence,
  parseEdgeTrace,
  transportPolicyCheck,
  type TransportMeasurement,
} from "@/lib/transport-evidence";
import type { SecurityHardeningCheck, SecurityHardeningStatus, TlsPolicy } from "@/lib/types";

const HOST = "project.supabase.co";

/** Verbatim shape of the edge's `/cdn-cgi/trace` body (values changed). */
const HYBRID_TRACE = [
  "fl=998f39",
  `h=${HOST}`,
  "ip=203.0.113.7",
  "ts=1789971768.000",
  "visit_scheme=https",
  "uag=Mozilla/5.0",
  "colo=SIN",
  "http=http/2",
  "loc=PH",
  "tls=TLSv1.3",
  "sni=plaintext",
  "warp=off",
  "kex=X25519MLKEM768",
  "",
].join("\n");

const CLASSICAL_TRACE = HYBRID_TRACE.replace("kex=X25519MLKEM768", "kex=X25519");

const ANDROID_POLICY: TlsPolicy = {
  mode: "strict",
  minimum_version: "TLS 1.3",
  post_quantum_key_agreement: true,
  enforced_by_app: false,
  detail: "The platform WebView owns the TLS stack on this OS; the app cannot pin a minimum version.",
};

const WINDOWS_STRICT: TlsPolicy = { ...ANDROID_POLICY, enforced_by_app: true, detail: "Strict" };
const WINDOWS_COMPAT: TlsPolicy = { ...WINDOWS_STRICT, mode: "compat", minimum_version: "TLS 1.2", detail: "Compat" };

function measured(overrides: Partial<TransportMeasurement> = {}): TransportMeasurement {
  return {
    host: HOST,
    tls: "TLSv1.3",
    kex: "X25519MLKEM768",
    http: "http/2",
    keyAgreement: "hybrid-pq",
    measuredAt: "2026-09-21T06:00:00.000Z",
    ...overrides,
  };
}

describe("parseEdgeTrace", () => {
  it("reads only the negotiated transport parameters", () => {
    const parsed = parseEdgeTrace(HYBRID_TRACE, HOST, "2026-09-21T06:00:00.000Z");
    expect(parsed).toEqual(measured());
    // The trace also echoes the caller's public IP and location. They are not
    // transport evidence and must never be retained.
    expect(JSON.stringify(parsed)).not.toContain("203.0.113.7");
    expect(JSON.stringify(parsed)).not.toContain("PH");
  });

  it("returns null for anything that is not a trace", () => {
    expect(parseEdgeTrace("<!doctype html><html></html>", HOST)).toBeNull();
    expect(parseEdgeTrace("tls=TLSv1.3\n", HOST)).toBeNull();
    expect(parseEdgeTrace("", HOST)).toBeNull();
  });
});

describe("classifyKeyAgreement", () => {
  it("separates ML-KEM hybrid, pure ML-KEM, pre-standard Kyber and classical groups", () => {
    expect(classifyKeyAgreement("X25519MLKEM768")).toBe("hybrid-pq");
    expect(classifyKeyAgreement("SecP256r1MLKEM768")).toBe("hybrid-pq");
    expect(classifyKeyAgreement("MLKEM1024")).toBe("pq");
    // The Kyber draft predates FIPS 203. It is post-quantum in intent but it
    // is not ML-KEM, and must never be reported as the approved standard.
    expect(classifyKeyAgreement("X25519Kyber768Draft00")).toBe("pre-standard-pq");
    expect(classifyKeyAgreement("X25519")).toBe("classical");
    expect(classifyKeyAgreement("P-256")).toBe("classical");
    expect(classifyKeyAgreement("")).toBe("classical");
  });
});

describe("transportPolicyCheck", () => {
  it("passes on Android when the live connection is measured as TLS 1.3 + hybrid PQ", () => {
    const check = transportPolicyCheck(ANDROID_POLICY, measured());
    expect(check.status).toBe("active");
    expect(check.active).toBe(true);
    expect(check.detail).toContain("X25519MLKEM768");
    expect(check.detail).toContain("TLS 1.3");
    // It must say HOW it knows, and must not claim a pin it does not have.
    expect(check.detail.toLowerCase()).toContain("verified");
    expect(check.detail.toLowerCase()).not.toContain("pinned by the app");
  });

  it("fails on Android when the live connection uses classical key agreement", () => {
    const check = transportPolicyCheck(ANDROID_POLICY, measured({ kex: "X25519", keyAgreement: "classical" }));
    expect(check.status).toBe("warning");
    expect(check.active).toBe(false);
    expect(check.detail).toContain("X25519");
    expect(check.detail).toContain("Android System WebView");
  });

  it("does not pass the pre-standard Kyber draft as the approved ML-KEM hybrid", () => {
    const check = transportPolicyCheck(
      ANDROID_POLICY,
      measured({ kex: "X25519Kyber768Draft00", keyAgreement: "pre-standard-pq" }),
    );
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("X25519Kyber768Draft00");
    expect(check.detail).toContain("FIPS 203");
    expect(check.detail).toContain("Android System WebView");
    expect(check.detail).not.toMatch(/\(hybrid post-quantum key agreement\)/);
  });

  it("names the WebView2 runtime when Windows negotiates the Kyber draft", () => {
    const check = transportPolicyCheck(
      WINDOWS_STRICT,
      measured({ kex: "X25519Kyber768Draft00", keyAgreement: "pre-standard-pq" }),
    );
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("WebView2");
  });

  it("fails on Android when the connection is below TLS 1.3, whatever the group", () => {
    const check = transportPolicyCheck(ANDROID_POLICY, measured({ tls: "TLSv1.2" }));
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("TLS 1.2");
  });

  it("stays a warning on Android when nothing could be measured", () => {
    const check = transportPolicyCheck(ANDROID_POLICY, null);
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("owns the TLS stack");
    expect(check.detail.toLowerCase()).toContain("could not be measured");
  });

  it("keeps the configured Windows policy active when the measurement is unavailable", () => {
    const check = transportPolicyCheck(WINDOWS_STRICT, null);
    expect(check.status).toBe("active");
  });

  it("fails on Windows when the WebView2 runtime ignored the post-quantum request", () => {
    const check = transportPolicyCheck(WINDOWS_STRICT, measured({ kex: "X25519", keyAgreement: "classical" }));
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("WebView2");
  });

  it("passes on Windows with the pin AND the measurement, and says both", () => {
    const check = transportPolicyCheck(WINDOWS_STRICT, measured());
    expect(check.status).toBe("active");
    expect(check.detail.toLowerCase()).toContain("enforced");
    expect(check.detail).toContain("X25519MLKEM768");
  });

  it("keeps compat mode a visible downgrade even when this connection happened to be PQ", () => {
    const check = transportPolicyCheck(WINDOWS_COMPAT, measured());
    expect(check.status).toBe("warning");
    expect(check.detail).toContain("TLS 1.2");
  });
});

describe("measureTransport", () => {
  const okFetch = (body: string, status = 200) => async () => new Response(body, { status });

  it("returns the parsed measurement for the backend host", async () => {
    const result = await measureTransport(`https://${HOST}`, okFetch(HYBRID_TRACE) as typeof fetch);
    expect(result?.kex).toBe("X25519MLKEM768");
    expect(result?.host).toBe(HOST);
  });

  it("reports classical groups exactly as negotiated", async () => {
    const result = await measureTransport(`https://${HOST}/`, okFetch(CLASSICAL_TRACE) as typeof fetch);
    expect(result?.keyAgreement).toBe("classical");
  });

  it("returns null instead of guessing when the probe fails", async () => {
    const failing = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;
    expect(await measureTransport(`https://${HOST}`, failing)).toBeNull();
    expect(await measureTransport(`https://${HOST}`, okFetch("nope", 404) as typeof fetch)).toBeNull();
    expect(await measureTransport("", okFetch(HYBRID_TRACE) as typeof fetch)).toBeNull();
    expect(await measureTransport("not a url", okFetch(HYBRID_TRACE) as typeof fetch)).toBeNull();
  });
});

describe("mergeTransportEvidence", () => {
  const baseCheck = (id: string, active = true): SecurityHardeningCheck => ({
    id,
    label: id,
    status: active ? "active" : "warning",
    active,
    detail: id,
  });

  it("replaces the transport check in place and never duplicates it", () => {
    const hardening = {
      checks: [baseCheck("secure_memory_zeroize"), baseCheck("tls_transport_policy", false), baseCheck("rate_limiting")],
      tls_policy: ANDROID_POLICY,
    } as SecurityHardeningStatus;

    const merged = mergeTransportEvidence(hardening, measured());
    expect(merged.checks.map((check) => check.id)).toEqual(["secure_memory_zeroize", "tls_transport_policy", "rate_limiting"]);
    expect(merged.checks[1].status).toBe("active");
    expect(merged.checks[1].label).toBe("Transport Policy (TLS 1.3 + hybrid PQ)");
    // The input is not mutated: the cached Rust status stays the raw report.
    expect(hardening.checks[1].status).toBe("warning");
  });

  it("leaves a status with no transport check untouched", () => {
    const hardening = { checks: [baseCheck("secure_memory_zeroize")], tls_policy: ANDROID_POLICY } as SecurityHardeningStatus;
    expect(mergeTransportEvidence(hardening, measured()).checks).toHaveLength(1);
  });
});
