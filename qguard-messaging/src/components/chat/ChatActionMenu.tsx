import { MoreVertical } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

/**
 * One action in a chat's or contact's menu. The same list feeds the desktop
 * dropdown (below) and the phone's bottom sheet, so both offer the same things.
 */
export interface ChatActionItem {
  id: string;
  label: string;
  detail?: string;
  icon: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}

/** Desktop "⋮" button with a dropdown of actions. */
export default function ChatActionMenu({ items, label = "More options", align = "right" }: { items: ChatActionItem[]; label?: string; align?: "left" | "right" }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("pointerdown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("pointerdown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (items.length === 0) return null;
  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        title={label}
        className={`icon-button ${open ? "border-violet-300 text-violet-700" : ""}`}
      >
        <MoreVertical size={16} />
      </button>
      {open && (
        <div
          role="menu"
          className={`absolute top-full z-40 mt-1 w-72 overflow-hidden rounded-xl border border-line bg-white py-1 shadow-soft ${align === "right" ? "right-0" : "left-0"}`}
        >
          {items.map((item) => (
            <button
              key={item.id}
              type="button"
              role="menuitem"
              disabled={item.disabled}
              onClick={() => {
                setOpen(false);
                item.onSelect();
              }}
              className={`flex w-full items-start gap-3 px-3 py-2 text-left transition hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50 ${item.danger ? "text-rose-600" : "text-ink-800"}`}
            >
              <span className="mt-0.5 shrink-0">{item.icon}</span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold">{item.label}</span>
                {item.detail && <span className={`block text-[11px] ${item.danger ? "text-rose-500/80" : "text-ink-500"}`}>{item.detail}</span>}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
