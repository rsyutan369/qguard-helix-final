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

interface LiveTableSpec {
  table: string;
  filter: string;
}

const fallbackPollMs = 30_000;

function serializeSse(event: Omit<QGuardLiveEvent, "raw">): string {
  return `event: qguard-live\nid: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`;
}

function payloadDetail(table: string, eventType: string, payload: Record<string, unknown>): string {
  if (table === "messaging_vault_files" && eventType === "DELETE") {
    return `file_deleted: ${String(payload.display_name_hint ?? payload.storage_path ?? payload.id ?? "vault object")}`;
  }
  if (table === "messaging_devices" && eventType === "DELETE") {
    return `device_deleted: ${String(payload.device_label ?? payload.fingerprint ?? payload.id ?? "trusted device")}`;
  }
  if (table === "messaging_device_link_requests") {
    return `device_link_${String(payload.status ?? eventType).toLowerCase()}: ${String(payload.requested_device_label ?? payload.requested_fingerprint ?? payload.id ?? "pairing request")}`;
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
    { table: "messaging_device_link_requests", filter: `user_id=eq.${userId}` },
    { table: "messaging_contacts", filter: `owner_user_id=eq.${userId}` },
    { table: "messaging_conversation_members", filter: `user_id=eq.${userId}` },
    { table: "messaging_conversation_user_states", filter: `user_id=eq.${userId}` },
    { table: "messaging_signed_prekeys", filter: `user_id=eq.${userId}` },
    { table: "messaging_one_time_prekeys", filter: `user_id=eq.${userId}` },
    { table: "messaging_message_envelopes", filter: `recipient_user_id=eq.${userId}` },
    { table: "messaging_message_envelopes", filter: `sender_user_id=eq.${userId}` },
    { table: "messaging_vault_files", filter: `owner_user_id=eq.${userId}` },
    { table: "qguard_vault_operations", filter: `user_id=eq.${userId}` },
    { table: "messaging_security_events", filter: `user_id=eq.${userId}` },
    { table: "messaging_crypto_telemetry", filter: `user_id=eq.${userId}` },
    { table: "messaging_org_members", filter: `user_id=eq.${userId}` },
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
        refreshRef.current();
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
          refreshRef.current();
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
      refreshRef.current();
    }, fallbackPollMs);

    return () => {
      active = false;
      clearRetry();
      window.clearInterval(poll);
      supabase.removeChannel(channel);
    };
  }, [emit, userId]);

  return useMemo(() => ({ events, status }), [events, status]);
}
