import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronDown, HelpCircle, Shield, ShieldCheck } from "lucide-react";
import { pqStatusHasWarnings, type PqStatus } from "@/lib/pq-status";

/**
 * The conversation header's protection badge and its explainer.
 *
 * Renders only what `derivePqStatus` concluded from this conversation's
 * evidence. Colour is never the only signal: every state has its own icon and
 * words. A level that is good overall but carries a warning line (a device
 * waiting for approval, say) keeps its level and shows how many notes it has,
 * so the chip never reads as cleaner than the explainer behind it.
 */
export function PqStatusBadge({ status }: { status: PqStatus }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // Horizontal shift that keeps the explainer inside the viewport. On a phone
  // the chip sits well right of the screen edge (back button, avatar), and an
  // explainer anchored at the chip would run off the right side.
  const [shift, setShift] = useState(0);
  const panelId = useId();
  const warnings = status.lines.filter((line) => !line.ok).length;

  useLayoutEffect(() => {
    if (!open) { setShift(0); return; }
    const root = rootRef.current;
    const panel = panelRef.current;
    if (!root || !panel) return;
    const gutter = 16;
    const anchor = root.getBoundingClientRect().left;
    const width = panel.getBoundingClientRect().width;
    const overflowRight = anchor + width - (window.innerWidth - gutter);
    // Shift left by any overflow, but never past the left gutter.
    setShift(overflowRight > 0 ? -Math.min(overflowRight, Math.max(0, anchor - gutter)) : 0);
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const tone = status.level === "attention"
    ? "text-amber-700"
    : status.level === "unknown"
      ? "text-ink-600"
      : "text-emerald-600";
  const Icon = status.level === "attention"
    ? AlertTriangle
    : status.level === "unknown"
      ? HelpCircle
      : status.level === "protected-pinned" ? ShieldCheck : Shield;

  return (
    <div ref={rootRef} className="relative mt-1">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        title={status.headline}
        className={`flex max-w-full items-center gap-1.5 text-xs font-semibold ${tone} hover:underline`}
      >
        <Icon size={14} className="shrink-0" aria-hidden />
        <span className="truncate">{status.label}</span>
        {pqStatusHasWarnings(status) && status.level !== "attention" && (
          <span className="shrink-0 rounded-full bg-amber-50 px-1.5 text-[11px] font-bold text-amber-700">
            {warnings} {warnings === 1 ? "note" : "notes"}
          </span>
        )}
        <ChevronDown size={12} className={`shrink-0 transition-transform ${open ? "rotate-180" : ""}`} aria-hidden />
      </button>
      {open && (
        <div
          ref={panelRef}
          id={panelId}
          role="region"
          aria-label="Conversation protection"
          style={{ left: shift }}
          className="absolute top-full z-30 mt-2 w-[min(26rem,calc(100vw-2rem))] rounded-lg border border-line bg-white p-4 text-sm text-ink-700 shadow-tight"
        >
          <div className="font-bold text-ink-950">{status.headline}</div>
          {status.lines.length > 0 && (
            <ul className="mt-3 space-y-2">
              {status.lines.map((line, index) => (
                <li key={index} className="flex items-start gap-2 leading-5">
                  {line.ok
                    ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-emerald-600" aria-label="OK" />
                    : <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-600" aria-label="Note" />}
                  <span>{line.text}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 border-t border-line pt-3 text-xs leading-5 text-ink-500">
            &quot;Quantum-safe&quot; here means each message is locked with two keys at once: a classical one (X25519) and a
            post-quantum one (ML-KEM-1024, NIST FIPS 203) that a future quantum computer is not known to break. Both would
            have to be broken to read it. Worked out from this conversation&apos;s own devices and messages, as of the
            latest one.
          </p>
        </div>
      )}
    </div>
  );
}
