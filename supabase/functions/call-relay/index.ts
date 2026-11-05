/**
 * QGuard call relay — Supabase Edge Function (`/functions/v1/call-relay`).
 *
 * Hands a signed-in caller SHORT-LIVED TURN credentials minted by Cloudflare,
 * so calls can cross networks (a phone on mobile data reaching a desktop behind
 * a home router) without a permanent relay password stored in a table that
 * every signed-in user can read.
 *
 * Routes:
 *   GET  /health   { configured } — booleans only, no auth
 *   POST /         a fresh relay for the caller (auth)
 *
 * The response has the same shape as a `messaging_call_relay` row plus
 * `expires_at`, so the app parses both the same way (src/lib/call-ice.ts) and
 * falls back to that row when this function is not configured.
 *
 * Media stays end-to-end encrypted: a relay only forwards AES-256-GCM
 * ciphertext and never holds call keys.
 *
 * Deployed with verify_jwt = false (like device-link): /health carries no JWT,
 * and the relay route verifies the caller's access token itself.
 *
 * Secrets: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (runtime);
 *          CLOUDFLARE_TURN_KEY_ID, CLOUDFLARE_TURN_KEY_API_TOKEN (Cloudflare
 *          dashboard → Realtime → TURN Server → create key).
 */
import { createClient } from "jsr:@supabase/supabase-js@2";
import { bearerToken, cloudflareCredentialsUrl, CREDENTIAL_TTL_SECONDS, parseCloudflareIceServers } from "./logic.ts";

const env = (key: string) => Deno.env.get(key);

// Bearer-token API with no cookies: a wildcard origin grants a foreign page nothing.
const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Max-Age": "600",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function cloudflareConfigured(): boolean {
  return Boolean(env("CLOUDFLARE_TURN_KEY_ID") && env("CLOUDFLARE_TURN_KEY_API_TOKEN"));
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  const path = new URL(req.url).pathname.replace(/^.*\/call-relay/, "") || "/";

  if (req.method === "GET" && path === "/health") {
    return json(200, { configured: cloudflareConfigured() });
  }
  if (req.method !== "POST" || path !== "/") return json(404, { code: "NOT_FOUND", message: "Unknown route" });

  // Identity from the verified access token only.
  const url = env("SUPABASE_URL");
  const serviceKey = env("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return json(503, { code: "SERVICE_UNAVAILABLE", message: "Call relay is not configured" });
  const token = bearerToken(req.headers.get("Authorization"));
  if (!token) return json(401, { code: "UNAUTHORIZED", message: "Sign in to place calls" });
  const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: userData, error: userError } = await db.auth.getUser(token);
  if (userError || !userData?.user) return json(401, { code: "UNAUTHORIZED", message: "Your session has expired — sign in again" });

  if (!cloudflareConfigured()) {
    // The app treats this as "no minted relay" and falls back to the relay row.
    return json(503, { code: "NOT_CONFIGURED", message: "No Cloudflare TURN key is configured for this project" });
  }

  let response: Response;
  try {
    response = await fetch(cloudflareCredentialsUrl(env("CLOUDFLARE_TURN_KEY_ID")!), {
      method: "POST",
      headers: { Authorization: `Bearer ${env("CLOUDFLARE_TURN_KEY_API_TOKEN")}`, "Content-Type": "application/json" },
      body: JSON.stringify({ ttl: CREDENTIAL_TTL_SECONDS }),
      signal: AbortSignal.timeout(8_000),
    });
  } catch (error) {
    console.error("call-relay: Cloudflare request failed", error instanceof Error ? error.message : String(error));
    return json(502, { code: "RELAY_PROVIDER_UNREACHABLE", message: "The TURN provider did not answer" });
  }
  if (!response.ok) {
    // Status only: the body may echo request details, never log credentials.
    console.error("call-relay: Cloudflare refused", response.status);
    return json(502, { code: "RELAY_PROVIDER_ERROR", message: `The TURN provider refused the request (${response.status})` });
  }

  const relay = parseCloudflareIceServers(await response.json().catch(() => null), new Date());
  if (!relay) return json(502, { code: "RELAY_PROVIDER_ERROR", message: "The TURN provider returned no usable relay" });
  return json(200, relay);
});
