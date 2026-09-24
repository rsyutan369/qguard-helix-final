import { describe, expect, it } from "vitest";
import { billingApiOrigin, BillingRequestError, billingSupportsPlayVerification, postBilling } from "@/lib/billing-api";

const SUPABASE = "https://project.supabase.co";

describe("billingApiOrigin", () => {
  it("defaults to the billing Edge Function on the build's own Supabase project", () => {
    expect(billingApiOrigin({ VITE_SUPABASE_URL: `${SUPABASE}/` })).toBe(`${SUPABASE}/functions/v1/billing`);
  });

  it("never falls back to a hard-coded third-party domain", () => {
    // The old default was https://api.qguard.dev, which does not resolve.
    expect(billingApiOrigin({})).toBe("");
  });

  it("honours an explicit override for a self-hosted API", () => {
    expect(billingApiOrigin({ VITE_BILLING_API_ORIGIN: "https://api.example.test/", VITE_SUPABASE_URL: SUPABASE })).toBe(
      "https://api.example.test",
    );
  });
});

describe("postBilling", () => {
  const origin = `${SUPABASE}/functions/v1/billing`;

  it("returns the data payload and sends the session as a Bearer token", async () => {
    let seen: { url: string; auth: string | null } | null = null;
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seen = { url, auth: new Headers(init.headers).get("Authorization") };
      return new Response(JSON.stringify({ data: { approvalUrl: "https://www.paypal.com/x" } }), { status: 200 });
    }) as unknown as typeof fetch;

    const data = await postBilling("/api/v1/paypal/subscribe", "token-1", { plan: "Pro" }, { origin, fetchImpl });
    expect(data).toEqual({ approvalUrl: "https://www.paypal.com/x" });
    expect(seen).toEqual({ url: `${origin}/api/v1/paypal/subscribe`, auth: "Bearer token-1" });
  });

  it("turns a network failure into a message that names the unreachable host", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    const failure = postBilling("/api/v1/paypal/subscribe", "t", {}, { origin, fetchImpl });
    await expect(failure).rejects.toBeInstanceOf(BillingRequestError);
    await expect(failure).rejects.toThrow("Can't reach the QGuard billing service (project.supabase.co)");
    await expect(failure).rejects.not.toThrow("Failed to fetch");
  });

  it("surfaces the service's own error message", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ error: { code: "PAYPAL_NOT_CONFIGURED", message: "PayPal is not configured on the billing service" } }), {
        status: 503,
      })) as unknown as typeof fetch;
    await expect(postBilling("/x", "t", {}, { origin, fetchImpl })).rejects.toMatchObject({
      message: "PayPal is not configured on the billing service",
      status: 503,
      code: "PAYPAL_NOT_CONFIGURED",
    });
  });

  it("still explains a non-JSON error response", async () => {
    const fetchImpl = (async () => new Response("<html>bad gateway</html>", { status: 502 })) as unknown as typeof fetch;
    await expect(postBilling("/x", "t", {}, { origin, fetchImpl })).rejects.toThrow("HTTP 502");
  });

  it("refuses to run without an origin instead of fetching a relative URL", async () => {
    await expect(postBilling("/x", "t", {}, { origin: "" })).rejects.toThrow("not configured");
  });
});

describe("billingSupportsPlayVerification", () => {
  const origin = `${SUPABASE}/functions/v1/billing`;
  const health = (data: unknown, status = 200) =>
    (async () => new Response(JSON.stringify({ data }), { status })) as unknown as typeof fetch;

  it("is true only when the service explicitly advertises it", async () => {
    expect(await billingSupportsPlayVerification({ origin, fetchImpl: health({ configured: true, playVerification: true }) })).toBe(true);
  });

  it("treats a missing flag, an error or an unreachable service as 'use PayPal'", async () => {
    // The deployed service's health has no playVerification field today.
    expect(await billingSupportsPlayVerification({ origin, fetchImpl: health({ configured: true }) })).toBe(false);
    expect(await billingSupportsPlayVerification({ origin, fetchImpl: health({ playVerification: "yes" }) })).toBe(false);
    expect(await billingSupportsPlayVerification({ origin, fetchImpl: health({ playVerification: true }, 503) })).toBe(false);
    const offline = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    expect(await billingSupportsPlayVerification({ origin, fetchImpl: offline })).toBe(false);
    expect(await billingSupportsPlayVerification({ origin: "" })).toBe(false);
  });
});
