import { CheckCircle2, FileLock, Loader2, X, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { PendingShareNotice } from "@/lib/vault-share";
import { describeShareError } from "@/lib/vault-share";

function readDismissed(key: string): Set<string> {
  try {
    const value = JSON.parse(window.localStorage.getItem(key) ?? "[]");
    return new Set(Array.isArray(value) ? value.map(String) : []);
  } catch {
    return new Set();
  }
}

function sentAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/**
 * App-wide notice: "<person> sent you an encrypted file", with Accept, Decline
 * and View. Shown on every page except Quantum Vault itself (which has its own
 * banner and badge). Closing it hides those files' notice on this device; the
 * badges stay until each file is answered.
 *
 * It never shows the file's name: that is sealed in this device's envelope and
 * the notice can appear while the vault is locked. Accepting or declining is a
 * server-side answer and needs no vault key; opening the file does, and happens
 * in Quantum Vault → Shared.
 */
export default function IncomingShareNotice({
  userId,
  pending,
  onRespond,
  onView,
}: {
  userId: string;
  pending: PendingShareNotice[];
  onRespond: (shareId: string, accept: boolean) => Promise<void>;
  onView: () => void;
}) {
  const dismissedKey = `qguard.vault.share-notice.dismissed:${userId}`;
  const [dismissed, setDismissed] = useState<Set<string>>(() => readDismissed(dismissedKey));
  const [busy, setBusy] = useState<"accept" | "decline" | null>(null);
  const [confirmDecline, setConfirmDecline] = useState(false);
  const [result, setResult] = useState<{ tone: "success" | "error" | "info"; text: string } | null>(null);

  useEffect(() => {
    try {
      // Only answered-or-shown ids are kept; prune ones no longer pending.
      const live = new Set(pending.map((notice) => notice.shareId));
      window.localStorage.setItem(dismissedKey, JSON.stringify([...dismissed].filter((id) => live.has(id)).slice(-200)));
    } catch {
      // A view preference only.
    }
  }, [dismissed, dismissedKey, pending]);

  const visible = useMemo(() => pending.filter((notice) => !dismissed.has(notice.shareId)), [pending, dismissed]);
  const current = visible[0] ?? null;

  // A result message stays a few seconds, then the notice moves on.
  useEffect(() => {
    if (!result) return undefined;
    const timer = window.setTimeout(() => setResult(null), result.tone === "error" ? 9_000 : 6_000);
    return () => window.clearTimeout(timer);
  }, [result]);

  useEffect(() => setConfirmDecline(false), [current?.shareId]);

  if (!current && !result) return null;

  const answer = async (accept: boolean) => {
    if (!current) return;
    setBusy(accept ? "accept" : "decline");
    try {
      await onRespond(current.shareId, accept);
      setResult(
        accept
          ? { tone: "success", text: `Accepted. Open it in Quantum Vault → Shared, where it is decrypted on this device.` }
          : { tone: "info", text: `Declined. ${current.ownerName} can see that you declined, and the file's keys for your devices were deleted.` },
      );
    } catch (error) {
      setResult({ tone: "error", text: describeShareError(error) });
    } finally {
      setBusy(null);
      setConfirmDecline(false);
    }
  };

  const others = Math.max(0, visible.length - 1);

  return (
    // Positioned by NotificationStack, together with the new-message alerts.
    <div role="status" aria-live="polite">
      <div className="shell-card p-4 shadow-soft">
        {result ? (
          <div className="flex items-start gap-3">
            {result.tone === "error" ? (
              <XCircle className="mt-0.5 shrink-0 text-rose-500" size={18} />
            ) : (
              <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={18} />
            )}
            <p className="min-w-0 flex-1 text-sm text-ink-800">{result.text}</p>
            {result.tone === "success" && (
              <button type="button" onClick={() => { setResult(null); onView(); }} className="shrink-0 text-xs font-bold text-cyan-600 hover:underline">
                Open
              </button>
            )}
            <button type="button" onClick={() => setResult(null)} className="shrink-0 text-ink-500" aria-label="Close">
              <X size={15} />
            </button>
          </div>
        ) : current ? (
          <>
            <div className="flex items-start gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-violet-600 text-white shadow-tight">
                <FileLock size={19} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-bold text-ink-950">
                  <span className="break-words">{current.ownerName}</span> sent you an encrypted file
                </p>
                <p className="mt-0.5 text-xs text-ink-500">
                  {sentAgo(current.sharedAt)} · sealed to your devices with ML-KEM-1024
                  {current.expiresAt ? ` · available until ${new Date(current.expiresAt).toLocaleDateString(undefined, { dateStyle: "medium" })}` : ""}
                </p>
                {others > 0 && (
                  <p className="mt-1 text-xs font-semibold text-cyan-600">
                    +{others} more file{others === 1 ? "" : "s"} waiting
                  </p>
                )}
              </div>
              <button
                type="button"
                onClick={() => setDismissed((set) => new Set([...set, ...visible.map((notice) => notice.shareId)]))}
                className="shrink-0 text-ink-500"
                aria-label="Hide this notice (the files stay in Quantum Vault → Shared)"
                title="Hide (the files stay in Quantum Vault → Shared)"
              >
                <X size={15} />
              </button>
            </div>

            {confirmDecline ? (
              <div className="mt-3 rounded-lg border border-line bg-canvas p-2.5">
                <p className="text-xs text-ink-700">Decline this file? Its keys for your devices are deleted, so it cannot be opened later unless {current.ownerName} shares it again.</p>
                <div className="mt-2 flex justify-end gap-2">
                  <button type="button" onClick={() => setConfirmDecline(false)} className="rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink-800">
                    Keep it
                  </button>
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void answer(false)}
                    className="flex items-center gap-1 rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-50"
                  >
                    {busy === "decline" ? <Loader2 className="animate-spin" size={13} /> : <XCircle size={13} />} Decline
                  </button>
                </div>
              </div>
            ) : (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => void answer(true)}
                  className="flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-50"
                >
                  {busy === "accept" ? <Loader2 className="animate-spin" size={13} /> : <CheckCircle2 size={13} />} Accept
                </button>
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => setConfirmDecline(true)}
                  className="flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink-800 disabled:opacity-50"
                >
                  <XCircle size={13} /> Decline
                </button>
                <button type="button" onClick={onView} className="ml-auto text-xs font-bold text-cyan-600 hover:underline">
                  View in Quantum Vault
                </button>
              </div>
            )}
          </>
        ) : null}
      </div>
    </div>
  );
}
