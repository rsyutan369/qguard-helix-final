import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/supabase", () => ({ supabaseUrl: "https://project.supabase.co", supabaseAnonKey: "anon-key" }));

import {
  buildLinkPayload,
  claimLink,
  computeLinkProof,
  DeviceLinkError,
  deviceLinkOrigin,
  finishPendingLinkCompletion,
  generateBindingSecret,
  hasPendingLinkCompletion,
  normalizeLinkCode,
  parseLinkPayload,
  rememberLinkCompletion,
  thisDevicePlatform,
  verifyLinkProof,
} from "@/lib/device-link";

const LINK_ID = "6f9b7f5e-2a1c-4b1e-9a7d-0c2b9b7c3d11";
const USER_ID = "0b6c1c8e-4f41-4a0f-8a4c-7f6f7a1e2d33";
const DEVICE_ID = "f1d2c3b4-a596-4877-8899-aabbccddeeff";

describe("link payload", () => {
  it("round-trips a scanned payload with its binding secret", () => {
    const secret = generateBindingSecret();
    expect(parseLinkPayload(buildLinkPayload("AB12-CD34-EF56", secret))).toEqual({ code: "AB12-CD34-EF56", bindingSecret: secret });
  });

  it("accepts a hand-typed code but carries no binding secret, so the device is not auto-trusted", () => {
    expect(parseLinkPayload("ab12 cd34 ef56")).toEqual({ code: "AB12-CD34-EF56", bindingSecret: null });
  });

  it("drops a malformed binding secret rather than trusting on it", () => {
    expect(parseLinkPayload("qguard-link:v2:AB12-CD34-EF56#tooshort")).toEqual({ code: "AB12-CD34-EF56", bindingSecret: null });
  });

  it("rejects anything that is not a link code", () => {
    expect(parseLinkPayload("https://evil.example/login")).toBeNull();
    expect(parseLinkPayload("qguard-device-link:v1:token:label:fp")).toBeNull();
    expect(parseLinkPayload("qguard-link:v2:NOPE#x")).toBeNull();
  });

  it("forgives Crockford look-alikes exactly like the server", () => {
    expect(normalizeLinkCode("oooo-iiii-llll")).toBe("0000-1111-1111");
    expect(normalizeLinkCode("ABCD-EFGH-JKMU")).toBeNull();
  });

  it("generates 256-bit base64url secrets", () => {
    const secret = generateBindingSecret();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateBindingSecret()).not.toBe(secret);
  });
});

describe("binding proof", () => {
  const base = { bindingSecret: generateBindingSecret(), linkId: LINK_ID, userId: USER_ID, deviceId: DEVICE_ID, fingerprint: "QG-ABCD-1234-EF56" };

  it("verifies the proof the new device computes", async () => {
    expect(await verifyLinkProof(base, await computeLinkProof(base))).toBe(true);
  });

  it("fails for a different device, fingerprint, account, link or secret", async () => {
    const proof = await computeLinkProof(base);
    expect(await verifyLinkProof({ ...base, deviceId: "00000000-0000-4000-8000-000000000000" }, proof)).toBe(false);
    expect(await verifyLinkProof({ ...base, fingerprint: "QG-OTHER" }, proof)).toBe(false);
    expect(await verifyLinkProof({ ...base, userId: "11111111-1111-4111-8111-111111111111" }, proof)).toBe(false);
    expect(await verifyLinkProof({ ...base, linkId: "22222222-2222-4222-8222-222222222222" }, proof)).toBe(false);
    expect(await verifyLinkProof({ ...base, bindingSecret: generateBindingSecret() }, proof)).toBe(false);
  });

  it("refuses missing or malformed proofs", async () => {
    expect(await verifyLinkProof(base, null)).toBe(false);
    expect(await verifyLinkProof(base, "zz")).toBe(false);
  });
});

describe("pending completion", () => {
  afterEach(() => {
    rememberLinkCompletion(null);
    vi.restoreAllMocks();
  });

  it("is a no-op without a pending link", async () => {
    expect(hasPendingLinkCompletion()).toBe(false);
    expect(await finishPendingLinkCompletion(USER_ID, "token", async () => ({ device_id: DEVICE_ID, fingerprint: "fp" }))).toBe("none");
  });

  it("posts the device id with a proof the approver can verify, exactly once", async () => {
    const bindingSecret = generateBindingSecret();
    rememberLinkCompletion({ linkId: LINK_ID, claimSecret: "c".repeat(43), bindingSecret });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ linkId: LINK_ID, linkedDeviceId: DEVICE_ID }), { status: 200 }));

    const outcome = await finishPendingLinkCompletion(USER_ID, "access-token", async () => ({ device_id: DEVICE_ID, fingerprint: "QG-FP" }));
    expect(outcome).toBe("completed");
    expect(hasPendingLinkCompletion()).toBe(false);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/functions\/v1\/device-link\/complete$/);
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer access-token");
    const body = JSON.parse(String(init.body));
    expect(body.deviceId).toBe(DEVICE_ID);
    expect(await verifyLinkProof({ bindingSecret, linkId: LINK_ID, userId: USER_ID, deviceId: DEVICE_ID, fingerprint: "QG-FP" }, body.proof)).toBe(true);

    expect(await finishPendingLinkCompletion(USER_ID, "access-token", async () => ({ device_id: DEVICE_ID, fingerprint: "QG-FP" }))).toBe("none");
  });

  it("reports failure when the device never registered", async () => {
    rememberLinkCompletion({ linkId: LINK_ID, claimSecret: "c".repeat(43), bindingSecret: generateBindingSecret() });
    expect(await finishPendingLinkCompletion(USER_ID, "t", async () => null)).toBe("failed");
  });
});

describe("service calls", () => {
  afterEach(() => vi.restoreAllMocks());

  it("targets the device-link function on the build's Supabase project", () => {
    expect(deviceLinkOrigin("https://abc.supabase.co/")).toBe("https://abc.supabase.co/functions/v1/device-link");
    expect(deviceLinkOrigin("")).toBe("");
  });

  it("surfaces the server's error code and message", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: { code: "LINK_NOT_FOUND", message: "No link request matches this code." } }), { status: 404 }));
    await expect(claimLink(LINK_ID, "s".repeat(43))).rejects.toMatchObject({ code: "LINK_NOT_FOUND", status: 404 });
  });

  it("explains an undeployed function instead of a bare 404", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("not found", { status: 404 }));
    const error = await claimLink(LINK_ID, "s".repeat(43)).catch((cause) => cause);
    expect(error).toBeInstanceOf(DeviceLinkError);
    expect(error.code).toBe("NOT_DEPLOYED");
  });

  it("reports a network failure as one", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));
    await expect(claimLink(LINK_ID, "s".repeat(43))).rejects.toMatchObject({ code: "NETWORK" });
  });
});

describe("thisDevicePlatform", () => {
  it("classifies common user agents", () => {
    expect(thisDevicePlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
    expect(thisDevicePlatform("Mozilla/5.0 (Linux; Android 15; Pixel 9)")).toBe("android");
    expect(thisDevicePlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")).toBe("macos");
  });
});
