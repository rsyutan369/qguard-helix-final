/**
 * Relay outage / block detection (roadmap 9.2).
 *
 * Everything this app sends goes through one relay (Supabase). When it cannot
 * be reached, the user needs to know which of three very different things is
 * happening, from evidence rather than a guess:
 *
 *   - this device is offline (the OS says so);
 *   - the relay answered but is failing (HTTP 5xx: an outage on our side);
 *   - the relay did not answer at all. If the update server — the one other
 *     host this app already contacts — DID answer, the internet works and the
 *     relay is down or blocked on this network. Where there is no second host
 *     to ask (Android: no updater), the banner says it cannot tell.
 *
 * No new host is ever contacted for this: the relay probe uses the relay's own
 * auth health endpoint, and the control is the existing signed-update check.
 */

export type RelayProbe =
  | { kind: "ok" }
  | { kind: "http_error"; status: number }
  | { kind: "unreachable" }
  | { kind: "not_configured" };

/** The independent control host: reachable, not reachable, or no such host here. */
export type ControlProbe = "reachable" | "unreachable" | "unavailable";

export type RelayHealthState =
  | "ok"
  | "offline"
  | "relay_failing"
  | "relay_unreachable_internet_ok"
  | "relay_unreachable_no_internet"
  | "relay_unreachable_unknown"
  | "not_configured";

export interface RelayHealth {
  state: RelayHealthState;
  title: string;
  detail: string;
}

export function classifyRelayHealth(input: { online: boolean; relay: RelayProbe; control: ControlProbe }): RelayHealth {
  const { online, relay, control } = input;
  if (relay.kind === "not_configured") {
    return { state: "not_configured", title: "No relay configured", detail: "This build has no relay address, so nothing can be sent or received." };
  }
  if (relay.kind === "ok" || (relay.kind === "http_error" && relay.status < 500)) {
    // A 4xx is still the relay answering; the request-level error is handled where it happens.
    return { state: "ok", title: "Connected", detail: "The relay is reachable." };
  }
  if (!online) {
    return {
      state: "offline",
      title: "You're offline",
      detail: "This device has no network connection. Messages won't send or arrive until it reconnects.",
    };
  }
  if (relay.kind === "http_error") {
    return {
      state: "relay_failing",
      title: "The relay is having problems",
      detail: `It answered with an error (HTTP ${relay.status}), so this is on the service's side, not your connection. Messages may fail until it recovers; your keys and history on this device are unaffected.`,
    };
  }
  if (control === "reachable") {
    return {
      state: "relay_unreachable_internet_ok",
      title: "Can't reach the relay",
      detail: "Your internet connection works (the update server answered), but the relay doesn't. It may be down, or blocked on this network (a workplace or national firewall). Messages won't send until it's reachable; try another network or a VPN.",
    };
  }
  if (control === "unreachable") {
    return {
      state: "relay_unreachable_no_internet",
      title: "No internet connection",
      detail: "Neither the relay nor the update server answered, so this network has no working internet access (or a sign-in page is in the way). Messages won't send until it does.",
    };
  }
  return {
    state: "relay_unreachable_unknown",
    title: "Can't reach the relay",
    detail: "Either this network has no internet access, or the relay is down or blocked here; this device can't tell which. Messages won't send until it's reachable.",
  };
}

/** Rechecks while unhealthy: 5 s, 10 s, 20 s, 40 s, then every 60 s. */
export function nextRecheckMs(consecutiveFailures: number): number {
  return Math.min(60_000, 5_000 * 2 ** Math.max(0, Math.min(4, consecutiveFailures - 1)));
}

const PROBE_TIMEOUT_MS = 8_000;

/** GET the relay's auth health endpoint (public anon key, no user token). */
export async function probeRelay(
  relayUrl: string,
  anonKey: string,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<RelayProbe> {
  let origin: string;
  try {
    const url = new URL(relayUrl);
    if (url.protocol !== "https:" || url.hostname.includes("placeholder")) return { kind: "not_configured" };
    origin = url.origin;
  } catch {
    return { kind: "not_configured" };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`${origin}/auth/v1/health`, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      headers: anonKey ? { apikey: anonKey } : undefined,
      signal: controller.signal,
    });
    return response.ok ? { kind: "ok" } : { kind: "http_error", status: response.status };
  } catch {
    return { kind: "unreachable" };
  } finally {
    clearTimeout(timer);
  }
}

/** Event other parts of the app dispatch when the relay just failed them. */
export const RELAY_TROUBLE_EVENT = "qguard:relay-trouble";

export function reportRelayTrouble(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(RELAY_TROUBLE_EVENT));
}
