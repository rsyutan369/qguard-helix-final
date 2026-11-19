import { useEffect, useRef } from "react";
import { NEARBY_ROWS_EVENT, nearbyStatus } from "@/lib/nearby";
import { OUTBOX_FLUSHED_EVENT, OUTBOX_QUEUED_EVENT, flushOutbox, listOutbox, removeFromOutbox } from "@/lib/outbox";
import { RELAY_RECOVERED_EVENT, reportRelayTrouble } from "@/lib/relay-health";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

const FLUSH_EVERY_MS = 20_000;
const NEARBY_POLL_MS = 3_000;

/**
 * Background delivery for messages sealed while the relay was unreachable
 * (roadmap 9.1): uploads the outbox when the relay answers again, and — on
 * Android with nearby delivery on — offers the waiting rows to phones in range
 * and passes on rows they hand over. Renders nothing.
 */
export function OutboxCourier({ onQueueCount }: { onQueueCount?: (count: number) => void }) {
  const flushingRef = useRef(false);
  const offeredRef = useRef(new Set<string>());

  useEffect(() => {
    if (!isTauriRuntime()) return undefined;
    let cancelled = false;
    let queueVersion = 0;
    let flushAgain = false;

    const flush = async () => {
      if (flushingRef.current) return;
      flushingRef.current = true;
      const observedVersion = queueVersion;
      try {
        const result = await flushOutbox({
          list: listOutbox,
          remove: removeFromOutbox,
          insert: async (rows) => {
            const { error } = await supabase.from("messaging_message_envelopes").insert(rows);
            return { error };
          },
        });
        if (cancelled) return;
        if (observedVersion === queueVersion) onQueueCount?.(result.remaining);
        if (result.blocked) {
          reportRelayTrouble();
          await offerNearby();
        }
        if (result.sent > 0 || result.dropped.length > 0) {
          window.dispatchEvent(new CustomEvent(OUTBOX_FLUSHED_EVENT, { detail: result }));
          if (result.remaining === 0) {
            offeredRef.current.clear();
            void safeInvoke("nearby_clear_outgoing").catch(() => undefined);
          }
        }
      } catch {
        // Nothing queued, or the core is not ready yet; the next tick retries.
      } finally {
        flushingRef.current = false;
        if (!cancelled && flushAgain) {
          flushAgain = false;
          void flush();
        }
      }
    };

    const offerNearby = async () => {
      const status = await nearbyStatus();
      if (!status.running) return;
      for (const item of await listOutbox()) {
        for (const row of item.rows) {
          const id = String(row.id ?? "");
          if (!id || offeredRef.current.has(id)) continue;
          try {
            await safeInvoke("nearby_send", { row });
            offeredRef.current.add(id);
          } catch {
            // Too large for one nearby payload, or the radio stopped: the relay still delivers it later.
          }
        }
      }
    };

    const pollNearby = async () => {
      const status = await nearbyStatus();
      if (!status.running) return;
      const rows = await safeInvoke<Array<Record<string, unknown>>>("nearby_take_received", undefined, []);
      if (rows.length > 0 && !cancelled) window.dispatchEvent(new CustomEvent(NEARBY_ROWS_EVENT, { detail: rows }));
    };

    void flush();
    const flushTimer = window.setInterval(() => { void flush(); }, FLUSH_EVERY_MS);
    const nearbyTimer = window.setInterval(() => { void pollNearby(); }, NEARBY_POLL_MS);
    const onQueued = (event: Event) => {
      queueVersion += 1;
      const count = (event as CustomEvent<number>).detail;
      if (Number.isSafeInteger(count) && count >= 0) onQueueCount?.(count);
      void offerNearby();
    };
    const onOnline = () => { void flush(); };
    const onRelayRecovered = () => {
      if (flushingRef.current) flushAgain = true;
      else void flush();
    };
    window.addEventListener(OUTBOX_QUEUED_EVENT, onQueued);
    window.addEventListener("online", onOnline);
    window.addEventListener(RELAY_RECOVERED_EVENT, onRelayRecovered);
    return () => {
      cancelled = true;
      window.clearInterval(flushTimer);
      window.clearInterval(nearbyTimer);
      window.removeEventListener(OUTBOX_QUEUED_EVENT, onQueued);
      window.removeEventListener("online", onOnline);
      window.removeEventListener(RELAY_RECOVERED_EVENT, onRelayRecovered);
    };
  }, [onQueueCount]);

  return null;
}
