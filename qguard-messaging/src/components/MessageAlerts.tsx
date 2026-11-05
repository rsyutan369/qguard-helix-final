import { BellOff, MessageSquareLock, X } from "lucide-react";
import type { MessageAlert } from "@/lib/use-message-alerts";

/**
 * "New encrypted message" alerts. Never the message text (it is only ever
 * decrypted inside Secure Chat), and not even the chat's name while Secure
 * Chat is locked — who you talk to is protected by that lock too.
 */
export default function MessageAlerts({
  alerts,
  revealNames,
  onOpen,
  onMute,
  onDismiss,
}: {
  alerts: MessageAlert[];
  revealNames: boolean;
  onOpen: (alert: MessageAlert) => void;
  onMute: (alert: MessageAlert) => void;
  onDismiss: (conversationId: string) => void;
}) {
  return (
    <>
      {alerts.map((alert) => (
        <div key={alert.conversationId} role="status" aria-live="polite" className="shell-card qg-slide p-3 shadow-soft">
          <div className="flex items-start gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-violet-600 text-white">
              <MessageSquareLock size={17} />
            </span>
            <button type="button" onClick={() => onOpen(alert)} className="min-w-0 flex-1 text-left">
              <span className="block truncate text-sm font-bold text-ink-950">
                {revealNames ? alert.title : alert.isGroup ? "New encrypted group message" : "New encrypted message"}
              </span>
              <span className="block text-xs text-ink-500">
                {alert.count === 1 ? "1 new message" : `${alert.count} new messages`}
                {revealNames ? "" : " · unlock Secure Chat to read"}
              </span>
            </button>
            <button type="button" onClick={() => onDismiss(alert.conversationId)} className="shrink-0 text-ink-500" aria-label="Dismiss">
              <X size={15} />
            </button>
          </div>
          <div className="mt-2 flex items-center justify-end gap-2">
            {revealNames && (
              <button type="button" onClick={() => onMute(alert)} className="flex items-center gap-1 rounded-lg border border-line px-2.5 py-1 text-xs font-semibold text-ink-700">
                <BellOff size={12} /> Mute 8 h
              </button>
            )}
            <button type="button" onClick={() => onOpen(alert)} className="rounded-lg bg-violet-600 px-3 py-1 text-xs font-bold text-white">
              Open
            </button>
          </div>
        </div>
      ))}
    </>
  );
}
