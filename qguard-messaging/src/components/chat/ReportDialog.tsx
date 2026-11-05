import { Flag, Loader2 } from "lucide-react";
import { useState } from "react";
import ChatDialog from "@/components/chat/ChatDialog";
import { describeReportError, REPORT_REASONS, submitReport, type ReportReason } from "@/lib/chat-reports";

/**
 * Report a person (and their conversation) or a group. Optionally blocks the
 * person in the same step. The report goes to the QGuard operators; message
 * content is end-to-end encrypted and is never part of it.
 */
export default function ReportDialog({
  targetName,
  reportedUserId,
  conversationId,
  canBlock,
  onBlock,
  onClose,
  onDone,
}: {
  targetName: string;
  reportedUserId: string | null;
  conversationId: string | null;
  /** Offer "Also block" (a person who is a contact and not blocked yet). */
  canBlock: boolean;
  onBlock: () => Promise<void>;
  onClose: () => void;
  onDone: (text: string) => void;
}) {
  const [reason, setReason] = useState<ReportReason | null>(null);
  const [details, setDetails] = useState("");
  const [alsoBlock, setAlsoBlock] = useState(canBlock);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!reason) return;
    setBusy(true);
    setError(null);
    try {
      await submitReport({ reportedUserId, conversationId, reason, details, alsoBlocked: canBlock && alsoBlock });
      if (canBlock && alsoBlock) await onBlock();
      onDone(
        canBlock && alsoBlock
          ? `Report sent and ${targetName} is blocked. Thank you for helping keep QGuard safe.`
          : `Report sent. Thank you for helping keep QGuard safe.`,
      );
      onClose();
    } catch (err) {
      setError(describeReportError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <ChatDialog
      title={`Report ${targetName}`}
      subtitle="Your report goes to the QGuard team. They are not told who reported them."
      icon={<Flag size={18} />}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800">
            Cancel
          </button>
          <button
            type="button"
            disabled={!reason || busy || (reason === "other" && !details.trim())}
            onClick={() => void submit()}
            className="flex items-center gap-2 rounded-lg bg-rose-600 px-4 py-2 text-sm font-bold text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy && <Loader2 className="animate-spin" size={15} />} Send report
          </button>
        </>
      }
    >
      <fieldset>
        <legend className="text-sm font-semibold text-ink-900">What is wrong?</legend>
        <div className="mt-2 space-y-1.5">
          {REPORT_REASONS.map((option) => (
            <label
              key={option.id}
              className={`flex cursor-pointer items-start gap-3 rounded-lg border p-2.5 ${reason === option.id ? "border-rose-300 bg-rose-50" : "border-line hover:bg-canvas"}`}
            >
              <input type="radio" name="report-reason" checked={reason === option.id} onChange={() => setReason(option.id)} className="mt-1 accent-rose-600" />
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-ink-900">{option.label}</span>
                <span className="block text-xs text-ink-500">{option.detail}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <label className="mt-4 block text-sm font-semibold text-ink-900">
        Details {reason === "other" ? "" : <span className="font-normal text-ink-500">(optional)</span>}
        <textarea
          value={details}
          onChange={(event) => setDetails(event.target.value.slice(0, 1000))}
          rows={3}
          placeholder="What happened? Do not paste passwords or codes."
          className="mt-1 w-full resize-none rounded-lg border border-line bg-white px-3 py-2 text-sm font-normal text-ink-950 outline-none focus:border-violet-300"
        />
        <span className="block text-right text-[11px] font-normal text-ink-400">{details.length}/1000</span>
      </label>

      {canBlock && (
        <label className="mt-2 flex items-start gap-2 text-sm text-ink-800">
          <input type="checkbox" checked={alsoBlock} onChange={(event) => setAlsoBlock(event.target.checked)} className="mt-0.5 accent-rose-600" />
          <span>
            Also block {targetName}
            <span className="block text-xs text-ink-500">Their messages and calls stop reaching you. They are not told.</span>
          </span>
        </label>
      )}

      <p className="mt-4 rounded-lg bg-canvas p-2.5 text-xs text-ink-600">
        Messages are end-to-end encrypted, so the report contains only who you are reporting, the conversation, the reason and what you write above — never your messages.
      </p>
      {error && <p className="mt-3 text-sm text-rose-600">{error}</p>}
    </ChatDialog>
  );
}
