import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { supabase } from "@/lib/supabase";

export type LiveConnectionState = "connecting" | "live" | "fallback" | "error";

export interface QGuardLiveEvent {
  id: string;
  at: string;
  table: string;
  event: string;
  detail: string;
  raw: string;
}

export interface QGuardLiveStatus {
  state: LiveConnectionState;
  detail: string;
  lastEventAt: string | null;
  retryCount: number;
}

/**
 * User-facing presentation of a live event.
 *
 * The raw event carries backend-only fields (table names, DB operation,
 * SSE payload). Those must never reach the customer UI — {@link describeLiveEvent}
 * and {@link liveStatusLabel} translate them into plain, professional language.
 */
export interface LiveEventView {
  title: string;
  meta: string;
}

// Maps an internal table name to a plain-language activity label. Anything not
// listed falls back to a generic, non-technical phrase so we never leak a raw
// table name into the UI.
const LIVE_EVENT_LABELS: Record<string, string> = {
  messaging_user_modules: "Workspace preferences updated",
  profiles: "Profile updated",
  messaging_devices: "Trusted device updated",
  messaging_device_verification_payloads: "Device verification updated",
  messaging_device_link_requests: "Device pairing request updated",
  messaging_contacts: "Contacts updated",
  messaging_conversation_members: "Conversation membership updated",
  messaging_conversation_user_states: "Conversation updated",
  messaging_signed_prekeys: "Encryption keys refreshed",
  messaging_one_time_prekeys: "Encryption keys refreshed",
  messaging_message_envelopes: "Secure message activity",
  messaging_message_user_states: "Message status updated",
  messaging_security_events: "Security check completed",
  messaging_crypto_telemetry: "Encryption activity recorded",
  messaging_org_members: "Organization membership updated",
  messaging_account_recovery: "Account recovery key updated",
  qguard_profile_audit_events: "Account activity recorded",
};

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "Just now";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 45) return "Just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

/** Translate a raw live event into safe, customer-friendly copy. */
export function describeLiveEvent(event: QGuardLiveEvent): LiveEventView {
  let title = LIVE_EVENT_LABELS[event.table] ?? "Workspace activity";
  if (event.table === "messaging_devices" && event.event === "DELETE") {
    title = "Trusted device removed";
  } else if (event.table === "messaging_message_envelopes" && event.event === "INSERT") {
    title = "New secure message received";
  }
  return { title, meta: relativeTime(event.at) };
}

/** Plain-language connection status, free of backend/transport terminology. */
export function liveStatusLabel(state: LiveConnectionState): string {
  switch (state) {
    case "live":
      return "Connected — activity updates in real time";
    case "connecting":
      return "Connecting to live updates…";
    case "fallback":
      return "Reconnecting — refreshing periodically";
    default:
      return "Live updates are temporarily unavailable";
  }
}

interface LiveTableSpec {
  table: string;
  filter: string;
}

const fallbackPollMs = 30_000;
// Floor between full dashboard refreshes. A refresh is ~17 Supabase queries
// (devices, 500 envelopes, prekeys, telemetry, …) and re-renders the whole app.
// Sending one message writes several rows — envelopes per recipient device, read
// states, two crypto-telemetry records — and each of those echoes back as a live
// event. Without a floor those echoes chained refreshes back-to-back every
// ~450ms, which on a phone is what made typing, history and message delivery all
// feel stalled. Coalescing to one refresh per window keeps the data fresh
// without the app spending its time re-fetching itself.
const minRefreshGapMs = 2_500;

function serializeSse(event: Omit<QGuardLiveEvent, "raw">): string {
  return `event: qguard-live\nid: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`;
}

function payloadDetail(table: string, eventType: string, payload: Record<string, unknown>): string {
  if (table === "messaging_devices" && eventType === "DELETE") {
    return `device_deleted: ${String(payload.device_label ?? payload.fingerprint ?? payload.id ?? "trusted device")}`;
  }
  if (table === "messaging_device_link_requests") {
    return `device_link_${String(payload.status ?? eventType).toLowerCase()}: ${String(payload.requested_device_label ?? payload.requested_fingerprint ?? payload.id ?? "pairing request")}`;
  }
  if (table === "messaging_device_verification_payloads") {
    return `verification_payload_${eventType.toLowerCase()}: ${String(payload.fingerprint ?? payload.device_id ?? "trusted device")}`;
  }
  const candidate = payload.display_name_hint
    ?? payload.current_operation
    ?? payload.event_type
    ?? payload.stage
    ?? payload.status
    ?? payload.id
    ?? "state changed";
  return `${table} ${eventType.toLowerCase()}: ${String(candidate)}`;
}

function tableSpecs(userId: string): LiveTableSpec[] {
  return [
    { table: "messaging_user_modules", filter: `user_id=eq.${userId}` },
    { table: "profiles", filter: `id=eq.${userId}` },
    { table: "messaging_devices", filter: `user_id=eq.${userId}` },
    { table: "messaging_device_verification_payloads", filter: `user_id=eq.${userId}` },
    { table: "messaging_device_link_requests", filter: `user_id=eq.${userId}` },
    { table: "messaging_contacts", filter: `owner_user_id=eq.${userId}` },
    { table: "messaging_conversation_members", filter: `user_id=eq.${userId}` },
    { table: "messaging_conversation_user_states", filter: `user_id=eq.${userId}` },
    { table: "messaging_signed_prekeys", filter: `user_id=eq.${userId}` },
    { table: "messaging_one_time_prekeys", filter: `user_id=eq.${userId}` },
    { table: "messaging_message_envelopes", filter: `recipient_user_id=eq.${userId}` },
    { table: "messaging_message_envelopes", filter: `sender_user_id=eq.${userId}` },
    { table: "messaging_message_user_states", filter: `user_id=eq.${userId}` },
    { table: "messaging_security_events", filter: `user_id=eq.${userId}` },
    { table: "messaging_crypto_telemetry", filter: `user_id=eq.${userId}` },
    { table: "messaging_org_members", filter: `user_id=eq.${userId}` },
    { table: "messaging_account_recovery", filter: `user_id=eq.${userId}` },
    { table: "qguard_profile_audit_events", filter: `user_id=eq.${userId}` },
  ];
}

export function useQGuardLiveSse(userId: string | null, onRefresh: () => Promise<void> | void) {
  const [events, setEvents] = useState<QGuardLiveEvent[]>([]);
  const [status, setStatus] = useState<QGuardLiveStatus>({
    state: userId ? "connecting" : "fallback",
    detail: userId ? "Opening live data stream" : "Waiting for authenticated user",
    lastEventAt: null,
    retryCount: 0,
  });
  const refreshRef = useRef(onRefresh);
  const retryRef = useRef(0);
  const retryTimerRef = useRef<number | null>(null);
  const refreshTimerRef = useRef<number | null>(null);
  const lastRefreshAtRef = useRef(0);

  useEffect(() => {
    refreshRef.current = onRefresh;
  }, [onRefresh]);

  const emit = useCallback((table: string, eventType: string, payload: Record<string, unknown>) => {
    const eventWithoutRaw = {
      id: crypto.randomUUID(),
      at: new Date().toISOString(),
      table,
      event: eventType,
      detail: payloadDetail(table, eventType, payload),
    };
    const event: QGuardLiveEvent = {
      ...eventWithoutRaw,
      raw: serializeSse(eventWithoutRaw),
    };
    setEvents((current) => [event, ...current].slice(0, 80));
    setStatus((current) => ({
      ...current,
      state: "live",
      detail: event.detail,
      lastEventAt: event.at,
    }));
  }, []);

  useEffect(() => {
    if (!userId) return undefined;
    let active = true;
    let channel = supabase.channel(`qguard-sse-live-${userId}-${crypto.randomUUID()}`);

    const clearRetry = () => {
      if (retryTimerRef.current) {
        window.clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    };

    const clearScheduledRefresh = () => {
      if (refreshTimerRef.current) {
        window.clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };

    const scheduleRefresh = (delayMs = 450) => {
      if (!active || refreshTimerRef.current) return;
      const sinceLast = Date.now() - lastRefreshAtRef.current;
      const wait = Math.max(delayMs, minRefreshGapMs - sinceLast);
      refreshTimerRef.current = window.setTimeout(() => {
        refreshTimerRef.current = null;
        lastRefreshAtRef.current = Date.now();
        void refreshRef.current();
      }, Math.max(0, wait));
    };

    const scheduleRetry = () => {
      if (!active || retryTimerRef.current) return;
      retryRef.current += 1;
      const waitMs = Math.min(20_000, 1_000 * 2 ** Math.min(5, retryRef.current));
      setStatus({
        state: "fallback",
        detail: `Realtime reconnect scheduled in ${Math.round(waitMs / 1000)}s`,
        lastEventAt: null,
        retryCount: retryRef.current,
      });
      retryTimerRef.current = window.setTimeout(() => {
        retryTimerRef.current = null;
        scheduleRefresh(0);
      }, waitMs);
    };

    tableSpecs(userId).forEach((spec) => {
      channel = channel.on(
        "postgres_changes",
        { event: "*", schema: "public", table: spec.table, filter: spec.filter },
        (payload) => {
          if (!active) return;
          retryRef.current = 0;
          clearRetry();
          emit(spec.table, payload.eventType, (payload.new ?? payload.old ?? {}) as Record<string, unknown>);
          scheduleRefresh();
        },
      );
    });

    setStatus((current) => ({
      ...current,
      state: "connecting",
      detail: "Opening SSE-compatible live stream",
      retryCount: retryRef.current,
    }));

    channel.subscribe((subscriptionStatus) => {
      if (!active) return;
      if (subscriptionStatus === "SUBSCRIBED") {
        retryRef.current = 0;
        clearRetry();
        setStatus((current) => ({
          ...current,
          state: "live",
          detail: "Live backend stream connected",
          retryCount: 0,
        }));
      }
      if (subscriptionStatus === "CHANNEL_ERROR" || subscriptionStatus === "TIMED_OUT") {
        scheduleRetry();
      }
      if (subscriptionStatus === "CLOSED") {
        setStatus((current) => ({
          ...current,
          state: "fallback",
          detail: "Realtime channel closed; fallback polling is active",
        }));
      }
    });

    const poll = window.setInterval(() => {
      scheduleRefresh(0);
    }, fallbackPollMs);

    return () => {
      active = false;
      clearRetry();
      clearScheduledRefresh();
      window.clearInterval(poll);
      supabase.removeChannel(channel);
    };
  }, [emit, userId]);

  return useMemo(() => ({ events, status }), [events, status]);
}
