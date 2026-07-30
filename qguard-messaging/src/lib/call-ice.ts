import { supabase } from "@/lib/supabase";

// ICE resolution for quantum-encrypted calls.
//
// STUN alone only connects peers on cooperative NATs; calls across strict
// corporate firewalls, some mobile carriers, and many cross-country paths need
// a TURN relay. TURN servers are resolved in three tiers so operators can run
// their own relay WITHOUT shipping a new installer:
//   1. `messaging_call_relay` row in Supabase (rotatable server-side, cached);
//   2. build-time env override (VITE_TURN_URL / _USERNAME / _CREDENTIAL);
//   3. the free public Open Relay (openrelay.metered.ca) so cross-NAT calls
//      work out of the box. Media stays end-to-end encrypted regardless of
//      which relay forwards the packets — a relay only sees ciphertext.

const DEFAULT_STUN = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

// Open Relay Project (metered.ca) — free public TURN, publicly documented
// credentials. Fine as a fallback; production operators should configure
// their own relay via the messaging_call_relay table.
const FALLBACK_TURN: RTCIceServer = {
  urls: [
    "turn:openrelay.metered.ca:80",
    "turn:openrelay.metered.ca:443",
    "turns:openrelay.metered.ca:443?transport=tcp",
  ],
  username: "openrelayproject",
  credential: "openrelayproject",
};

export interface RelayConfig {
  stunUrls: string[];
  turnUrls: string[];
  turnUsername: string;
  turnCredential: string;
}

/** Pure assembly of an RTCConfiguration from resolved servers (unit-tested). */
export function buildRtcConfiguration(relay?: RelayConfig | null): RTCConfiguration {
  const iceServers: RTCIceServer[] = [{ urls: relay?.stunUrls?.length ? relay.stunUrls : DEFAULT_STUN }];

  const envTurnUrl = import.meta.env.VITE_TURN_URL as string | undefined;
  if (relay?.turnUrls?.length) {
    iceServers.push({ urls: relay.turnUrls, username: relay.turnUsername, credential: relay.turnCredential });
  } else if (envTurnUrl) {
    iceServers.push({
      urls: envTurnUrl,
      username: (import.meta.env.VITE_TURN_USERNAME as string | undefined) ?? "",
      credential: (import.meta.env.VITE_TURN_CREDENTIAL as string | undefined) ?? "",
    });
  } else {
    iceServers.push(FALLBACK_TURN);
  }

  return { iceServers, iceTransportPolicy: "all", bundlePolicy: "max-bundle" };
}

let cachedRelay: { value: RelayConfig | null; fetchedAt: number } | null = null;
const RELAY_CACHE_MS = 5 * 60_000;

/** Parse a messaging_call_relay row; null when unusable. Exported for tests. */
export function parseRelayRow(row: unknown): RelayConfig | null {
  if (!row || typeof row !== "object") return null;
  const r = row as Record<string, unknown>;
  const toUrls = (value: unknown): string[] =>
    Array.isArray(value) ? value.map(String).filter((url) => /^(stun|turn|turns):/.test(url)) : [];
  const turnUrls = toUrls(r.turn_urls);
  if (turnUrls.length === 0) return null;
  return {
    stunUrls: toUrls(r.stun_urls),
    turnUrls,
    turnUsername: String(r.turn_username ?? ""),
    turnCredential: String(r.turn_credential ?? ""),
  };
}

/**
 * Resolve the live RTC configuration before dialing/answering. Best-effort and
 * fast: a short timeout + 5-minute cache; any failure falls back to the env /
 * Open Relay tiers so a missing table or offline config can never block a call.
 */
export async function resolveRtcConfiguration(): Promise<RTCConfiguration> {
  const now = Date.now();
  if (cachedRelay && now - cachedRelay.fetchedAt < RELAY_CACHE_MS) {
    return buildRtcConfiguration(cachedRelay.value);
  }
  let relay: RelayConfig | null = null;
  try {
    const fetchRow = supabase.from("messaging_call_relay").select("stun_urls,turn_urls,turn_username,turn_credential").eq("id", 1).maybeSingle();
    const timeout = new Promise<never>((_, reject) => window.setTimeout(() => reject(new Error("relay config timeout")), 2_500));
    const { data } = await Promise.race([fetchRow, timeout]);
    relay = parseRelayRow(data);
  } catch {
    relay = null;
  }
  cachedRelay = { value: relay, fetchedAt: now };
  return buildRtcConfiguration(relay);
}

/**
 * Warm the relay cache outside any call. On a cold cache `resolveRtcConfiguration`
 * costs a Supabase round trip (up to its 2.5s timeout) — on a phone that is dead
 * time between "Accept" and the first media packet. Called on mount and when the
 * app resumes so the cache is already fresh when a call actually starts.
 */
export function prewarmRtcConfiguration(): void {
  void resolveRtcConfiguration().catch(() => undefined);
}
