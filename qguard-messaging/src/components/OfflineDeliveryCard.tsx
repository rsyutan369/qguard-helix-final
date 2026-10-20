import { useCallback, useEffect, useState } from "react";
import { Bluetooth, Inbox, Loader2 } from "lucide-react";
import { nearbyStatus, type NearbyStatus } from "@/lib/nearby";
import { OUTBOX_FLUSHED_EVENT, OUTBOX_QUEUED_EVENT, listOutbox } from "@/lib/outbox";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

/**
 * Settings → Offline delivery (roadmap 9.1): messages waiting for the relay,
 * and (Android) nearby delivery through Google Play services.
 */
export function OfflineDeliveryCard() {
  const [waiting, setWaiting] = useState<number | null>(null);
  const [status, setStatus] = useState<NearbyStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setWaiting((await listOutbox()).length);
    setStatus(await nearbyStatus());
  }, []);

  useEffect(() => {
    if (!isTauriRuntime()) return undefined;
    void refresh();
    const onChange = () => { void refresh(); };
    window.addEventListener(OUTBOX_QUEUED_EVENT, onChange);
    window.addEventListener(OUTBOX_FLUSHED_EVENT, onChange);
    const timer = window.setInterval(onChange, 5_000);
    return () => {
      window.removeEventListener(OUTBOX_QUEUED_EVENT, onChange);
      window.removeEventListener(OUTBOX_FLUSHED_EVENT, onChange);
      window.clearInterval(timer);
    };
  }, [refresh]);

  const toggleNearby = async () => {
    if (!status) return;
    setBusy(true);
    setNote(null);
    try {
      if (status.running) {
        setStatus(await safeInvoke<NearbyStatus>("nearby_stop"));
      } else if (!status.permissionsGranted) {
        await safeInvoke("nearby_request_permissions");
        setNote("Allow \"Nearby devices\" (and location on Android 12 and older), then turn it on again.");
      } else {
        setStatus(await safeInvoke<NearbyStatus>("nearby_start"));
      }
    } catch (error) {
      setNote(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  if (!isTauriRuntime()) return null;

  return (
    <section className="shell-card p-5">
      <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><Inbox size={18} /> Offline delivery</div>
      <div className="mt-3 space-y-4 text-sm text-ink-600">
        <div>
          <div className="font-semibold text-ink-900">Waiting to send</div>
          <p className="mt-0.5 text-xs">
            {waiting === null
              ? "Checking…"
              : waiting === 0
                ? "Nothing waiting. Messages written while the relay is unreachable are kept here, encrypted, and sent when it answers again."
                : `${waiting} message${waiting === 1 ? "" : "s"} sealed and waiting for the relay. They send automatically; disappearing messages that expire meanwhile are never sent.`}
          </p>
        </div>
        {status?.supported && (
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 font-semibold text-ink-900"><Bluetooth size={15} /> Nearby delivery</div>
              <p className="mt-0.5 text-xs leading-relaxed">
                While the relay is unreachable, hand waiting messages to QGuard phones in Bluetooth/Wi-Fi range, and receive theirs. Messages
                stay end-to-end encrypted; nearby phones see only that something was sent, never what or exactly to whom. Uses Google Play
                services; off by default.
                {status.running ? ` On — ${status.peers} phone${status.peers === 1 ? "" : "s"} connected.` : ""}
                {!status.available ? " Google Play services is not available on this phone." : ""}
              </p>
              {note && <p className="mt-1 text-xs font-semibold text-amber-700">{note}</p>}
            </div>
            <button
              type="button"
              disabled={busy || !status.available}
              onClick={() => void toggleNearby()}
              className="flex items-center gap-1.5 rounded-md border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60"
            >
              {busy && <Loader2 size={12} className="animate-spin" />}
              {status.running ? "Turn off" : status.permissionsGranted ? "Turn on" : "Allow nearby access"}
            </button>
          </div>
        )}
      </div>
    </section>
  );
}
