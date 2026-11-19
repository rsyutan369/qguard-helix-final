import { useCallback, useEffect, useRef, useState } from "react";
import { useOfflineFeed, type TransferStatus } from "@/lib/offline";
import { safeInvoke } from "@/lib/tauri";

interface TransferSignal {
  id: string;
  direction: "incoming" | "outgoing";
  status: TransferStatus;
  createdAt: number;
  startedAtMs?: number | null;
  completedAtMs?: number | null;
}

type NoticeStatus = "awaitingConsent" | "active" | "verified";
export type TransferNotice = TransferSignal & { status: NoticeStatus };

interface Monitor {
  accountId: string;
  since: number;
  historicalReceipts: Set<string> | null;
  seenActive: Set<string>;
  dismissed: Set<string>;
}

const noticePriority: Record<NoticeStatus, number> = { verified: 0, awaitingConsent: 1, active: 2 };

function signalTime(transfer: TransferSignal) {
  return transfer.completedAtMs ?? transfer.startedAtMs ?? transfer.createdAt * 1_000;
}

function noticeKey(transfer: Pick<TransferSignal, "id" | "status">) {
  return `${transfer.id}:${transfer.status}`;
}

function isNotice(transfer: TransferSignal): transfer is TransferNotice {
  return transfer.status === "active" || transfer.status === "verified"
    || (transfer.status === "awaitingConsent" && transfer.direction === "incoming");
}

/**
 * Treat events as invalidations only. Navigation and notices come from the
 * account-checked native snapshot, with one outstanding read and a polling
 * fallback supplied by useOfflineFeed.
 */
export function useOfflineTransferMonitor({ accountId, enabled, focusedId, onOpen }: {
  accountId: string | undefined;
  enabled: boolean;
  focusedId: string | null;
  onOpen: (id: string) => void;
}) {
  const scopedAccount = enabled ? accountId : undefined;
  const read = useCallback(
    () => safeInvoke<TransferSignal[]>("offline_xfer_monitor", { expectedAccount: scopedAccount }),
    [scopedAccount],
  );
  const { value } = useOfflineFeed(read, 15_000, Boolean(scopedAccount));
  const monitor = useRef<Monitor | null>(null);
  const [display, setDisplay] = useState<{ accountId: string; items: TransferNotice[] } | null>(null);
  const [dismissed, setDismissed] = useState<{ accountId: string; keys: ReadonlySet<string> } | null>(null);

  useEffect(() => {
    if (!accountId) {
      monitor.current = null;
      setDisplay(null);
      setDismissed(null);
      return;
    }
    if (monitor.current?.accountId !== accountId) {
      monitor.current = { accountId, since: Date.now(), historicalReceipts: null, seenActive: new Set(), dismissed: new Set() };
      setDismissed(null);
    }
    if (!enabled || !value) return;

    const state = monitor.current;
    if (!state.historicalReceipts) {
      // A fast transfer can finish before the first read. Only a timestamp
      // from this observation window distinguishes it from an old receipt.
      state.historicalReceipts = new Set(value
        .filter(({ status, completedAtMs }) => status === "verified" && (completedAtMs ?? 0) < state.since)
        .map(({ id }) => id));
    }
    if (focusedId) {
      state.seenActive.add(focusedId);
      state.dismissed.add(noticeKey({ id: focusedId, status: "active" }));
      state.dismissed.add(noticeKey({ id: focusedId, status: "awaitingConsent" }));
    }

    const active = value.filter(({ status }) => status === "active")
      .sort((a, b) => signalTime(b) - signalTime(a) || a.id.localeCompare(b.id));
    const instantReceipts = value.filter(({ id, status, startedAtMs }) => status === "verified"
      && startedAtMs != null && startedAtMs >= state.since && !state.seenActive.has(id))
      .sort((a, b) => signalTime(b) - signalTime(a) || a.id.localeCompare(b.id));
    const next = !focusedId ? active.find(({ id }) => !state.seenActive.has(id)) ?? instantReceipts[0] : undefined;
    for (const { id } of [...active, ...instantReceipts]) state.seenActive.add(id);
    if (next?.status === "active") state.dismissed.add(noticeKey(next));

    const items = value.filter(isNotice)
      .filter((entry) => !state.dismissed.has(noticeKey(entry))
        && (entry.status !== "verified" || !state.historicalReceipts?.has(entry.id)))
      .sort((a, b) => noticePriority[a.status] - noticePriority[b.status]
        || signalTime(b) - signalTime(a) || a.id.localeCompare(b.id));
    setDisplay((previous) => {
      if (previous?.accountId === accountId && previous.items.length === items.length
        && previous.items.every((entry, index) => noticeKey(entry) === noticeKey(items[index]))) {
        return previous;
      }
      return { accountId, items };
    });
    if (next) onOpen(next.id);
  }, [accountId, enabled, focusedId, onOpen, value]);

  const dismiss = useCallback((notice: TransferNotice) => {
    const state = monitor.current;
    if (!state || state.accountId !== accountId || !enabled) return;
    state.dismissed.add(noticeKey(notice));
    setDismissed({ accountId, keys: new Set(state.dismissed) });
  }, [accountId, enabled]);

  const open = useCallback((notice: TransferNotice) => {
    if (!enabled || !value?.some(({ id, status }) => id === notice.id && status === notice.status)) return;
    dismiss(notice);
    onOpen(notice.id);
  }, [dismiss, enabled, onOpen, value]);

  const notices = enabled && value && display && display.accountId === accountId
    ? display.items.filter((entry) => (entry.id !== focusedId || entry.status === "verified")
      && !(dismissed?.accountId === accountId && dismissed?.keys.has(noticeKey(entry))))
    : [];
  return { notices, dismiss, open };
}
