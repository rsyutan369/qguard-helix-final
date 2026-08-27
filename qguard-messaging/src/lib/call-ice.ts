import { supabase } from "@/lib/supabase";

// ICE resolution for quantum-encrypted calls.
//
// STUN alone only connects peers on cooperative NATs; calls across strict
// corporate firewalls, mobile carriers behind CGNAT, and many cross-country
// paths need a TURN relay. TURN servers are resolved in two tiers so operators
// can rotate a relay WITHOUT shipping a new installer:
//   1. `messaging_call_relay` row in Supabase (rotatable server-side, cached);
//   2. build-time env override (VITE_TURN_URL / _USERNAME / _CREDENTIAL).
// Media stays end-to-end encrypted regardless of which relay forwards the
// packets -- a relay only ever sees AES-256-GCM ciphertext.
//
// THERE IS DELIBERATELY NO PUBLIC FALLBACK RELAY.
// Shipping one (`openrelay.metered.ca`) was actively harmful, and measurably so:
// real Chromium ICE against it returns `TURN allocate error` (code 400) and
// produces zero `typ relay` candidates -- no call in this deployment's signal
// history ever gathered one. Worse, an unreachable TURN entry stops ICE
// gathering from EVER completing: Chromium retries the dead allocation for the
// full gathering timeout, which delayed even same-LAN host candidates by ~28s
// and pushed calls past the caller's give-up. Measured on this machine:
//   STUN only ................ gathering complete in 605 ms
//   STUN + openrelay TURN .... gathering never completes, 0 relay candidates
// So a relay is used only when an operator configured one, and a configured
// relay that provably cannot allocate is dropped rather than left to stall
// every call (see `probeRelayHealth`).

const DEFAULT_STUN = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

export interface RelayConfig {
  stunUrls: string[];
  turnUrls: string[];
  turnUsername: string;
  turnCredential: string;
}

/**
 * Pure assembly of an RTCConfiguration from resolved servers (unit-tested).
 *
 * `relayUsable === false` means a relay was configured but PROVED unable to
 * allocate (see `probeRelayHealth`). It is then left out entirely: a dead TURN
 * entry contributes no relay candidate and stops gathering from completing, so
 * carrying it can only make every call slower. Unknown health still tries it —
 * a relay is never dropped on suspicion, only on evidence.
 */
export function buildRtcConfiguration(
  relay?: RelayConfig | null,
  relayUsable: boolean | null = null,
): RTCConfiguration {
  const iceServers: RTCIceServer[] = [{ urls: relay?.stunUrls?.length ? relay.stunUrls : DEFAULT_STUN }];

  const envTurnUrl = import.meta.env.VITE_TURN_URL as string | undefined;
  if (relayUsable !== false) {
    if (relay?.turnUrls?.length) {
      iceServers.push({ urls: relay.turnUrls, username: relay.turnUsername, credential: relay.turnCredential });
    } else if (envTurnUrl) {
      iceServers.push({
        urls: envTurnUrl,
        username: (import.meta.env.VITE_TURN_USERNAME as string | undefined) ?? "",
        credential: (import.meta.env.VITE_TURN_CREDENTIAL as string | undefined) ?? "",
      });
    }
  }

  return {
    iceServers,
    iceTransportPolicy: "all",
    bundlePolicy: "max-bundle",
    // Pre-gather one candidate set as soon as the peer connection exists, so
    // host/srflx candidates are already in hand when the offer or answer is
    // created instead of being gathered on the call's critical path.
    iceCandidatePoolSize: 1,
  };
}

/** True when a TURN relay is configured at all (operator row or build env). */
export function hasConfiguredRelay(relay?: RelayConfig | null): boolean {
  return Boolean(relay?.turnUrls?.length || (import.meta.env.VITE_TURN_URL as string | undefined));
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

// ---------------------------------------------------------------------------
// Relay health
// ---------------------------------------------------------------------------

export type RelayHealth =
  /**
   * No TURN relay is configured. Calls still work on the same network and
   * across cooperative NATs, but a phone on mobile data will not reach a
   * desktop behind a home router.
   */
  | { status: "not-configured"; checkedAt: number }
  /** A relay is configured and produced a `typ relay` candidate. */
  | { status: "healthy"; checkedAt: number; relayCandidates: number }
  /** A relay is configured but could not allocate. It is excluded from calls. */
  | { status: "unreachable"; checkedAt: number; detail: string };

const RELAY_PROBE_TIMEOUT_MS = 5_000;
const RELAY_HEALTH_TTL_MS = 10 * 60_000;

let relayHealth: RelayHealth | null = null;
let relayProbeInFlight: Promise<RelayHealth> | null = null;

/** Last known relay health, without triggering a probe. */
export function lastRelayHealth(): RelayHealth | null {
  return relayHealth;
}

/**
 * Ask the browser's own ICE agent whether the configured relay can actually
 * allocate, by gathering with `iceTransportPolicy: "relay"` — under that policy
 * the only candidate that can appear IS a relay candidate, so the answer is a
 * direct observation rather than an inference.
 *
 * Runs off the call path (prewarm, resume) and is cached, because a dead relay
 * is precisely what must not be discovered in the middle of a call.
 */
export async function probeRelayHealth(force = false): Promise<RelayHealth> {
  if (!force && relayHealth && Date.now() - relayHealth.checkedAt < RELAY_HEALTH_TTL_MS) return relayHealth;
  if (relayProbeInFlight) return relayProbeInFlight;

  relayProbeInFlight = (async (): Promise<RelayHealth> => {
    const relay = await resolveRelayConfig();
    if (!hasConfiguredRelay(relay) || typeof RTCPeerConnection === "undefined") {
      return { status: "not-configured", checkedAt: Date.now() };
    }
    // Build with health forced back to "unknown": a previously failed probe
    // would otherwise produce a config with the relay already stripped out, and
    // the relay could never be found working again.
    const config = buildRtcConfiguration(relay, null);
    const pc = new RTCPeerConnection({ ...config, iceTransportPolicy: "relay" });
    let relayCandidates = 0;
    let lastError = "";
    try {
      const settled = new Promise<void>((resolve) => {
        const done = window.setTimeout(resolve, RELAY_PROBE_TIMEOUT_MS);
        pc.onicecandidate = (event) => {
          if (!event.candidate) { window.clearTimeout(done); resolve(); return; }
          if (/ typ relay/.test(event.candidate.candidate)) {
            relayCandidates += 1;
            window.clearTimeout(done);
            resolve();
          }
        };
        pc.onicecandidateerror = (event) => {
          const e = event as RTCPeerConnectionIceErrorEvent;
          if (e.errorCode) lastError = [e.url, e.errorCode, e.errorText].filter(Boolean).join(" ");
        };
      });
      pc.createDataChannel("relay-probe");
      await pc.setLocalDescription(await pc.createOffer());
      await settled;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    } finally {
      pc.close();
    }
    return relayCandidates > 0
      ? { status: "healthy", checkedAt: Date.now(), relayCandidates }
      : { status: "unreachable", checkedAt: Date.now(), detail: lastError || "no relay candidate was gathered" };
  })();

  try {
    relayHealth = await relayProbeInFlight;
    return relayHealth;
  } finally {
    relayProbeInFlight = null;
  }
}

/**
 * Turn a failed connect into something the user (and their admin) can act on.
 *
 * "Call timed out" is true and useless. The single most common cause in this
 * deployment is that the two peers are on different networks and there is no
 * working TURN relay to bridge them — a condition the client already knows
 * about from its relay probe, so it should say so instead of making someone
 * guess.
 */
export function describeCallConnectFailure(health: RelayHealth | null): string {
  if (health?.status === "not-configured") {
    return "Could not establish the encrypted media path. No TURN relay is configured for this "
      + "workspace, so calls only connect between devices on the same network. An administrator "
      + "can add a relay in the call relay settings to enable calls across different networks.";
  }
  if (health?.status === "unreachable") {
    return `Could not establish the encrypted media path. The configured TURN relay is not `
      + `responding (${health.detail}), so calls cannot cross between networks until it is fixed.`;
  }
  return "Could not establish the encrypted media path before the call timed out.";
}

/** Fetch + cache the operator relay row. Never throws. */
async function resolveRelayConfig(): Promise<RelayConfig | null> {
  const now = Date.now();
  if (cachedRelay && now - cachedRelay.fetchedAt < RELAY_CACHE_MS) return cachedRelay.value;
  let relay: RelayConfig | null = null;
  try {
    const fetchRow = supabase
      .from("messaging_call_relay")
      .select("stun_urls,turn_urls,turn_username,turn_credential")
      .eq("id", 1)
      .maybeSingle();
    const timeout = new Promise<never>((_, reject) =>
      window.setTimeout(() => reject(new Error("relay config timeout")), 2_500));
    const { data } = await Promise.race([fetchRow, timeout]);
    relay = parseRelayRow(data);
  } catch {
    relay = null;
  }
  cachedRelay = { value: relay, fetchedAt: now };
  return relay;
}

/**
 * Resolve the live RTC configuration before dialing/answering. Best-effort and
 * fast: a short timeout + 5-minute cache, and any failure degrades to public
 * STUN so a missing table or an offline config can never block a call.
 *
 * A relay whose last probe proved it cannot allocate is left out — see
 * `buildRtcConfiguration`.
 */
export async function resolveRtcConfiguration(): Promise<RTCConfiguration> {
  const relay = await resolveRelayConfig();
  const usable = relayHealth?.status === "unreachable" ? false : null;
  return buildRtcConfiguration(relay, usable);
}

/**
 * Warm the relay cache and its health verdict outside any call. On a cold cache
 * `resolveRtcConfiguration` costs a Supabase round trip (up to its 2.5s
 * timeout) — on a phone that is dead time between "Accept" and the first media
 * packet. Called on mount and when the app resumes so both are already fresh
 * when a call actually starts.
 */
export function prewarmRtcConfiguration(): void {
  void resolveRtcConfiguration().catch(() => undefined);
  void probeRelayHealth().catch(() => undefined);
}
