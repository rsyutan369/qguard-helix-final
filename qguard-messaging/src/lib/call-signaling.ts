import { supabase } from "@/lib/supabase";
import type { CallSignalRow, CallSignalType } from "@/lib/call-types";

const TYPES: CallSignalType[] = ["ring", "offer", "answer", "ice", "accept", "reject", "hangup", "busy"];

const SIGNAL_COLUMNS =
  "id,call_id,conversation_id,from_user_id,from_device_id,to_user_id,to_device_id,signal_type,payload,created_at";

// Poll cadences for the catch-up reader that backs the realtime channel.
//   - BOOST: a call is being set up or is live; every second counts.
//   - DEGRADED: the realtime channel is not joined (mobile suspend, network
//     switch, Supabase hiccup) — polling is the ONLY delivery path right now.
//   - IDLE: channel looks healthy; a slow safety net for the window where a
//     socket has died but the client has not noticed yet (heartbeats are 30s).
const BOOST_POLL_MS = 900;
const DEGRADED_POLL_MS = 2_000;
// IDLE splits on whether the app is actually in front of the user. A ring that
// waits on a 12s idle tick is a ring the caller has already half given up on,
// so a visible app polls fast enough that the phone lights up in ~3s even with
// realtime completely down. A hidden app cannot ring anyone anyway (the modal
// is not on screen and mobile suspends the WebView), so it backs right off and
// leans on the resume refresh instead — this is the battery/latency trade, and
// it is decided by visibility rather than by a fixed number.
const IDLE_VISIBLE_POLL_MS = 3_500;
const IDLE_HIDDEN_POLL_MS = 15_000;
const DEFAULT_BOOST_MS = 60_000;
// First poll cursor: how far back to look before any DB timestamp is known.
// Kept just under the caller's own 45s give-up so catching up after a short
// suspend still finds a live ring, without resurrecting a dead call.
const BOOTSTRAP_LOOKBACK_MS = 30_000;
const SEEN_LIMIT = 400;

export function parseCallSignal(raw: unknown): CallSignalRow | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (!TYPES.includes(r.signal_type as CallSignalType)) return null;
  return {
    id: String(r.id ?? ""),
    call_id: String(r.call_id ?? ""),
    conversation_id: String(r.conversation_id ?? ""),
    from_user_id: String(r.from_user_id ?? ""),
    from_device_id: String(r.from_device_id ?? ""),
    to_user_id: String(r.to_user_id ?? ""),
    to_device_id: String(r.to_device_id ?? ""),
    signal_type: r.signal_type as CallSignalType,
    payload: (r.payload as Record<string, unknown>) ?? {},
    created_at: String(r.created_at ?? new Date().toISOString()),
  };
}

export type CallSignalInput = Omit<CallSignalRow, "id" | "created_at">;

export async function sendCallSignal(input: CallSignalInput): Promise<void> {
  const { error } = await supabase.from("messaging_call_signals").insert(input);
  if (error) throw new Error(error.message);
}

/** Write several signals in ONE round trip (ring fan-out, multi-device cancel). */
export async function sendCallSignals(inputs: CallSignalInput[]): Promise<void> {
  if (inputs.length === 0) return;
  const { error } = await supabase.from("messaging_call_signals").insert(inputs);
  if (error) throw new Error(error.message);
}

export interface CallSignalChannel {
  /**
   * Enter fast catch-up polling for `ms` — call this the moment a call starts
   * or an incoming ring is seen, so `answer`/`ice` are never gated on the
   * realtime socket being healthy.
   */
  boost: (ms?: number) => void;
  /** Force an immediate catch-up read (app resumed, network came back). */
  refresh: () => void;
  close: () => void;
}

/**
 * Deliver `messaging_call_signals` rows addressed to this device.
 *
 * Realtime `postgres_changes` is the fast path, but it is NOT a reliable one on
 * mobile: Android suspends the WebView's WebSocket when the app is backgrounded
 * or the screen turns off, and a Wi-Fi/cellular switch drops it silently. There
 * is no replay — every signal inserted while the socket is down is lost forever,
 * which is exactly how a call "takes too long to reach the other device" and
 * then times out. So the channel is paired with a catch-up reader that polls the
 * same rows from a moving `created_at` cursor, resubscribes when the app resumes
 * or the network returns, and de-duplicates by row id so both paths can deliver
 * the same signal harmlessly.
 */
export function subscribeCallSignals(opts: {
  userId: string;
  deviceId: string;
  onSignal: (row: CallSignalRow) => void;
}): CallSignalChannel {
  const { userId, deviceId, onSignal } = opts;

  let closed = false;
  let channel: ReturnType<typeof supabase.channel> | null = null;
  let channelJoined = false;
  let pollTimer: number | undefined;
  let pollInFlight = false;
  let boostUntil = 0;
  let resubscribeAt = 0;
  let resubscribeAttempts = 0;
  // Cursor into the signal stream, in DB time. Seeded from real row timestamps
  // so a skewed device clock cannot make us skip signals.
  let cursor: string | null = null;
  const seen = new Set<string>();
  const seenOrder: string[] = [];

  const remember = (id: string): boolean => {
    if (!id) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    seenOrder.push(id);
    if (seenOrder.length > SEEN_LIMIT) {
      const evicted = seenOrder.shift();
      if (evicted) seen.delete(evicted);
    }
    return true;
  };

  // NOTE: delivery must never advance `cursor`. The realtime channel can hand us
  // a row from T+10 while a row from T+5 was lost in a socket gap; moving the
  // poll cursor to T+10 would make that missing row unreachable forever. Only
  // `runPoll` — which reads a contiguous range — advances it.
  const deliver = (row: CallSignalRow | null) => {
    if (closed || !row) return;
    // Signals are device-addressed; a row for another one of this user's
    // devices must never drive this device's call state.
    if (row.to_device_id && row.to_device_id !== deviceId) return;
    if (!remember(row.id)) return;
    onSignal(row);
  };

  const appVisible = (): boolean =>
    typeof document === "undefined" || document.visibilityState !== "hidden";

  const pollIntervalMs = (): number => {
    if (Date.now() < boostUntil) return BOOST_POLL_MS;
    if (!channelJoined) return DEGRADED_POLL_MS;
    return appVisible() ? IDLE_VISIBLE_POLL_MS : IDLE_HIDDEN_POLL_MS;
  };

  const runPoll = async (): Promise<void> => {
    if (closed || pollInFlight) return;
    pollInFlight = true;
    try {
      let query = supabase
        .from("messaging_call_signals")
        .select(SIGNAL_COLUMNS)
        .eq("to_user_id", userId);
      // `gte` (not `gt`) plus id de-duplication: rows written in the same
      // transaction can share a timestamp, and skipping them would drop the
      // offer that follows a ring.
      query = cursor
        ? query.gte("created_at", cursor)
        : query.gte("created_at", new Date(Date.now() - BOOTSTRAP_LOOKBACK_MS).toISOString());
      const { data, error } = await query.order("created_at", { ascending: true }).limit(60);
      if (error || closed) return;
      const rows = (data ?? []) as Array<Record<string, unknown>>;
      let newest = cursor;
      for (const raw of rows) {
        const row = parseCallSignal(raw);
        deliver(row);
        // Advance past EVERY row read, including ones addressed to another of
        // this user's devices — otherwise the query window never moves forward
        // on a multi-device account.
        if (row?.created_at && (!newest || row.created_at > newest)) newest = row.created_at;
      }
      // A full page means there may be more; leave the cursor so the next tick
      // continues from here rather than skipping the tail.
      cursor = newest;
    } catch {
      // Offline / transient failure: the next tick retries. Never throw into
      // the timer chain — that would stop catch-up delivery entirely.
    } finally {
      pollInFlight = false;
    }
  };

  const schedule = (delayMs?: number) => {
    if (closed) return;
    if (pollTimer !== undefined) window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(tick, delayMs ?? pollIntervalMs());
  };

  const tick = () => {
    if (closed) return;
    void runPoll().finally(() => {
      if (!channelJoined && Date.now() >= resubscribeAt) openChannel();
      schedule();
    });
  };

  function openChannel() {
    if (closed) return;
    if (channel) {
      const previous = channel;
      channel = null;
      void supabase.removeChannel(previous);
    }
    channelJoined = false;
    // A fresh channel name per attempt: re-subscribing a channel object that
    // the server already considers closed silently never rejoins.
    const next = supabase
      .channel(`qguard-call-signals-${userId}-${deviceId}-${crypto.randomUUID()}`)
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "messaging_call_signals",
          filter: `to_user_id=eq.${userId}`,
        },
        (payload) => deliver(parseCallSignal(payload.new)),
      );
    channel = next;
    next.subscribe((status) => {
      if (closed || channel !== next) return;
      if (status === "SUBSCRIBED") {
        channelJoined = true;
        resubscribeAttempts = 0;
        // Close the gap between the last poll and the join.
        void runPoll();
        schedule();
        return;
      }
      if (status === "CHANNEL_ERROR" || status === "TIMED_OUT" || status === "CLOSED") {
        channelJoined = false;
        resubscribeAttempts += 1;
        resubscribeAt = Date.now() + Math.min(15_000, 1_000 * 2 ** Math.min(4, resubscribeAttempts));
        // Polling is now the delivery path — tighten it immediately.
        schedule(0);
      }
    });
  }

  const refresh = () => {
    if (closed) return;
    if (!channelJoined) {
      resubscribeAt = 0;
      openChannel();
    }
    schedule(0);
  };

  const onVisibility = () => {
    if (document.visibilityState === "visible") refresh();
  };

  openChannel();
  schedule(0);

  if (typeof document !== "undefined") document.addEventListener("visibilitychange", onVisibility);
  if (typeof window !== "undefined") {
    window.addEventListener("online", refresh);
    window.addEventListener("focus", refresh);
  }

  return {
    boost: (ms = DEFAULT_BOOST_MS) => {
      boostUntil = Math.max(boostUntil, Date.now() + ms);
      schedule(0);
    },
    refresh,
    close: () => {
      closed = true;
      if (pollTimer !== undefined) window.clearTimeout(pollTimer);
      pollTimer = undefined;
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisibility);
      if (typeof window !== "undefined") {
        window.removeEventListener("online", refresh);
        window.removeEventListener("focus", refresh);
      }
      if (channel) {
        const previous = channel;
        channel = null;
        void supabase.removeChannel(previous);
      }
    },
  };
}
