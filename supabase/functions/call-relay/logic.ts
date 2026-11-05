/**
 * Pure logic for the `call-relay` Edge Function: no Deno or network APIs here,
 * so the messaging app's Vitest suite can test it directly.
 */

/** Cloudflare TURN endpoint that mints short-lived ICE server credentials. */
export function cloudflareCredentialsUrl(keyId: string): string {
  return `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`;
}

/**
 * Credential lifetime requested from Cloudflare. A call keeps refreshing its
 * TURN allocation with the credential it started with, so this must outlast the
 * longest call; the app re-mints well before expiry (see call-ice.ts).
 */
export const CREDENTIAL_TTL_SECONDS = 24 * 60 * 60;

/** The relay as the app reads it — the same shape as a `messaging_call_relay` row. */
export interface MintedRelay {
  stun_urls: string[];
  turn_urls: string[];
  turn_username: string;
  turn_credential: string;
  /** ISO time after which the credential no longer authenticates. */
  expires_at: string;
  provider: "cloudflare";
}

/**
 * Browsers refuse port 53, and Cloudflare advertises :53 variants for native
 * clients; leaving them in only adds ICE attempts that can never succeed.
 */
function usableUrl(url: string): boolean {
  return /^(stun|turn|turns):/.test(url) && !/:53(\?|$)/.test(url);
}

function urlsOf(server: Record<string, unknown>): string[] {
  const raw = server.urls;
  const list = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  return list.map(String).filter(usableUrl);
}

/**
 * Turn Cloudflare's response into the relay shape, or null when it carries no
 * usable TURN server. Accepts both response shapes Cloudflare has used:
 * `iceServers` as an array of servers (generate-ice-servers) or as a single
 * server object (the older `credentials/generate`).
 */
export function parseCloudflareIceServers(body: unknown, now: Date, ttlSeconds = CREDENTIAL_TTL_SECONDS): MintedRelay | null {
  if (!body || typeof body !== "object") return null;
  const raw = (body as Record<string, unknown>).iceServers;
  const servers = (Array.isArray(raw) ? raw : raw && typeof raw === "object" ? [raw] : []).filter(
    (server): server is Record<string, unknown> => Boolean(server) && typeof server === "object",
  );

  const stun: string[] = [];
  const turn: string[] = [];
  let username = "";
  let credential = "";
  for (const server of servers) {
    for (const url of urlsOf(server)) {
      if (url.startsWith("stun:")) stun.push(url);
      else {
        turn.push(url);
        if (!username && typeof server.username === "string") username = server.username;
        if (!credential && typeof server.credential === "string") credential = server.credential;
      }
    }
  }
  if (turn.length === 0 || !username || !credential) return null;
  return {
    stun_urls: stun,
    turn_urls: turn,
    turn_username: username,
    turn_credential: credential,
    expires_at: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
    provider: "cloudflare",
  };
}

/** `Authorization: Bearer <token>` → token, else null. */
export function bearerToken(header: string | null): string | null {
  const match = header?.match(/^Bearer\s+(\S+)$/i);
  return match ? match[1] : null;
}
