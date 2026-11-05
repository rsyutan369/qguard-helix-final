import { X } from "lucide-react";
import { useEffect, type ReactNode } from "react";

/**
 * The modal used by Report, Share contact and Notifications & Sounds. A
 * centered card on desktop, a sheet from the bottom on a phone. Escape and the
 * backdrop close it.
 */
export default function ChatDialog({
  title,
  subtitle,
  icon,
  onClose,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[70] flex items-end justify-center bg-ink-950/40 backdrop-blur-sm sm:items-start sm:p-4 sm:pt-[10vh]" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="flex max-h-[88vh] w-full flex-col overflow-hidden rounded-t-2xl border border-line bg-white shadow-soft sm:max-w-md sm:rounded-xl"
        style={{ paddingBottom: "env(safe-area-inset-bottom, 0px)" }}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start gap-3 border-b border-line p-4">
          {icon && <span className="mt-0.5 shrink-0 text-violet-600">{icon}</span>}
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-base font-bold text-ink-950">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-ink-500">{subtitle}</p>}
          </div>
          <button type="button" onClick={onClose} className="icon-button shrink-0" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
        {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-line p-3">{footer}</div>}
      </div>
    </div>
  );
}
