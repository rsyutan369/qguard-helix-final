import { LockKeyhole, MessageSquareText, Siren, X } from "lucide-react";
import { MESH_SUITE, type MeshNotice as MeshNoticeData } from "@/lib/offline";

/** A new offline Mesh message, shown on every screen as soon as it arrives. */
export function MeshNotice({ notice, more, onOpen, onReply, onDismiss }: {
  notice: MeshNoticeData;
  more: number;
  onOpen: () => void;
  onReply: () => void;
  onDismiss: () => void;
}) {
  const sender = notice.senderName || `Device ${notice.sender.slice(0, 8)}`;
  const Icon = notice.emergency ? Siren : MessageSquareText;
  return (
    <div className={`shell-card p-3 shadow-soft ${notice.emergency ? "ring-2 ring-rose-500" : ""}`} data-mesh-notice>
      <div className="flex items-start gap-3">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-white ${notice.emergency ? "bg-rose-700" : "bg-cyan-700"}`}>
          <Icon size={19} aria-hidden />
        </span>
        <div className="min-w-0 flex-1" role="status" aria-live="polite">
          <p className="text-sm font-bold text-ink-950">{notice.emergency ? "Emergency Mesh message" : "New Mesh message"}</p>
          <p className="mt-0.5 break-words text-xs font-semibold text-ink-800">{sender}{notice.group ? ` · ${notice.group}` : ""}</p>
          <p className="mt-1 line-clamp-3 whitespace-pre-wrap break-words text-sm text-ink-950">{notice.preview}</p>
          <p className="mt-1.5 flex items-center gap-1 text-[11px] font-semibold text-emerald-700">
            <LockKeyhole size={12} aria-hidden /> {MESH_SUITE.keyEstablishment} · {MESH_SUITE.encryption}
          </p>
          {more > 0 && <p className="mt-1 text-xs text-ink-600">{more} more unread Mesh {more === 1 ? "message" : "messages"}</p>}
        </div>
        <button type="button" onClick={onDismiss} aria-label="Mark Mesh message as read"
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-ink-600 hover:bg-canvas focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">
          <X size={17} aria-hidden />
        </button>
      </div>
      <div className="mt-2 flex justify-end gap-2">
        <button type="button" onClick={onOpen} className="min-h-11 rounded-xl border border-line px-4 text-xs font-bold text-ink-800 hover:bg-canvas focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">Open</button>
        <button type="button" onClick={onReply} className="min-h-11 rounded-xl bg-violet-700 px-4 text-xs font-bold text-white hover:bg-violet-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-500">Reply</button>
      </div>
    </div>
  );
}
