import { useCallback, useEffect, useRef, useState } from "react";
import { OfflinePairingDialog } from "@/components/offline/OfflinePairingDialog";
import { offlineError, useOfflineFeed, type OfflineMode, type OfflinePairing, type OfflinePairingDecision } from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";

const terminal = new Set<OfflinePairing["status"]>(["trusted", "rejected", "cancelled", "failed", "expired"]);

export function OfflinePairingHost({ accountId, onOpen }: {
  accountId: string;
  onOpen: (mode: OfflineMode, peer: string, intent?: "send" | "receive") => void;
}) {
  const read = useCallback(() => safeInvoke<OfflinePairing[]>("offline_pairing_snapshot", { expectedAccount: accountId }), [accountId]);
  const { value, refresh } = useOfflineFeed(read, 5_000);
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const [currentId, setCurrentId] = useState<string>();
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [failure, setFailure] = useState<{ id: string; message: string }>();
  const available = value?.filter(({ id }) => !dismissed.has(id)) ?? [];
  const selected = available.find(({ id }) => id === currentId);
  const incoming = available.find(({ direction, status }) => direction === "incoming" && status === "awaitingApproval");
  const keepSelected = selected && !terminal.has(selected.status) && (selected.direction === "incoming" || selected.status === "verifying"
    || selected.status === "awaitingConfirmation" || selected.status === "establishing");
  const current = (keepSelected ? selected : incoming ?? selected)
    ?? available.find(({ status }) => !terminal.has(status)) ?? available[0] ?? null;
  const visibleId = current?.id;

  useEffect(() => {
    if (visibleId) setCurrentId(visibleId);
  }, [visibleId]);

  function dismiss(id: string) {
    setDismissed((previous) => new Set(previous).add(id));
  }

  async function run(id: string, action: () => Promise<unknown>) {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setFailure(undefined);
    try {
      await action();
    } catch (error) {
      setFailure({ id, message: offlineError(error) });
    } finally {
      refresh();
      busyRef.current = false;
      setBusy(false);
    }
  }

  function decide(id: string, decision: OfflinePairingDecision) {
    void run(id, () => safeInvoke("offline_pairing_decide", { id, decision, expectedAccount: accountId }));
  }

  function retry(pairing: OfflinePairing) {
    const mode = pairing.requested[0];
    if (!mode) return;
    void run(pairing.id, async () => {
      const id = await safeInvoke<string>("offline_pairing_start", {
        peer: pairing.peer, mode, both: pairing.requested.length > 1, expectedAccount: accountId,
      });
      dismiss(pairing.id);
      setCurrentId(id);
    });
  }

  return <OfflinePairingDialog pairing={current} busy={busy} error={failure?.id === current?.id ? failure?.message : undefined}
    onDecide={decide} onDismiss={dismiss} onRetry={retry} onOpen={(mode, peer, intent) => {
      if (current?.status !== "trusted" || current.peer !== peer || !current.requested.includes(mode)) return;
      dismiss(current.id);
      if (intent) onOpen(mode, peer, intent);
      else onOpen(mode, peer);
    }} />;
}
