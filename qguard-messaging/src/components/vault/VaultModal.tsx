import { X } from "lucide-react";
import type { ReactNode } from "react";

/** A centred dialog with a title bar and a scrolling body, for vault flows. */
export function VaultModal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={title}>
      <div className="flex max-h-[92vh] w-full max-w-md flex-col overflow-hidden rounded-xl border border-line bg-white shadow-soft">
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h3 className="truncate text-sm font-bold text-ink-950">{title}</h3>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-ink-500 hover:bg-canvas" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}
