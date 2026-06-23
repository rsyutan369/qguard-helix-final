import { ArrowLeft, ArrowRight, X } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { TourAccent, TourStep } from "@/lib/onboarding";

interface SpotlightCardProps {
  step: TourStep;
  index: number;
  total: number;
  isFirst: boolean;
  isLast: boolean;
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
}

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

const CARD_WIDTH = 344;
const GAP = 16;
const MARGIN = 16;
const SPOTLIGHT_PADDING = 8;

const ACCENT: Record<TourAccent, { tile: string; bar: string; ring: string; dot: string }> = {
  violet: {
    tile: "border-violet-100 bg-violet-50 text-violet-600",
    bar: "bg-violet-500",
    ring: "rgba(124, 58, 237, 0.55)",
    dot: "bg-violet-500",
  },
  cyan: {
    tile: "border-cyan-100 bg-cyan-50 text-cyan-600",
    bar: "bg-cyan-500",
    ring: "rgba(6, 182, 212, 0.55)",
    dot: "bg-cyan-500",
  },
  emerald: {
    tile: "border-emerald-100 bg-emerald-50 text-emerald-600",
    bar: "bg-emerald-500",
    ring: "rgba(16, 185, 129, 0.55)",
    dot: "bg-emerald-500",
  },
  amber: {
    tile: "border-amber-100 bg-amber-50 text-amber-600",
    bar: "bg-amber-500",
    ring: "rgba(245, 158, 11, 0.6)",
    dot: "bg-amber-500",
  },
};

function measureAnchor(anchor: string): Rect | null {
  if (typeof document === "undefined") return null;
  const element = document.querySelector<HTMLElement>(`[data-tour="${anchor}"]`);
  if (!element) return null;
  const rect = element.getBoundingClientRect();
  if (rect.width === 0 && rect.height === 0) return null;
  return { top: rect.top, left: rect.left, width: rect.width, height: rect.height };
}

/**
 * Spotlights a real UI element by `data-tour` id and floats a coachmark card
 * beside it. Re-measures on resize/scroll and across a few animation frames so
 * the highlight settles even while the underlying page lazy-loads.
 */
export default function SpotlightCard({
  step,
  index,
  total,
  isFirst,
  isLast,
  onBack,
  onNext,
  onSkip,
}: SpotlightCardProps) {
  const [rect, setRect] = useState<Rect | null>(() => measureAnchor(step.anchor));
  const [cardHeight, setCardHeight] = useState(0);
  const cardRef = useRef<HTMLDivElement | null>(null);
  const accent = ACCENT[step.accent];

  const remeasure = useCallback(() => {
    setRect(measureAnchor(step.anchor));
  }, [step.anchor]);

  // Settle the measurement across a few frames after the step changes, then
  // keep it in sync with viewport changes.
  useLayoutEffect(() => {
    let frame = 0;
    let attempts = 0;
    const tick = () => {
      remeasure();
      attempts += 1;
      if (attempts < 8) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    window.addEventListener("resize", remeasure);
    window.addEventListener("scroll", remeasure, true);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", remeasure);
      window.removeEventListener("scroll", remeasure, true);
    };
  }, [remeasure]);

  useLayoutEffect(() => {
    if (cardRef.current) setCardHeight(cardRef.current.offsetHeight);
  }, [step.id, rect]);

  const viewportWidth = typeof window === "undefined" ? 1280 : window.innerWidth;
  const viewportHeight = typeof window === "undefined" ? 800 : window.innerHeight;

  // Decide where the card sits relative to the highlighted element.
  let cardStyle: { top: number; left: number };
  const placeRight = rect ? rect.left < viewportWidth / 2 : false;
  if (!rect) {
    cardStyle = {
      top: Math.max(MARGIN, viewportHeight / 2 - cardHeight / 2),
      left: Math.max(MARGIN, viewportWidth / 2 - CARD_WIDTH / 2),
    };
  } else if (placeRight) {
    const top = rect.top + rect.height / 2 - cardHeight / 2;
    cardStyle = {
      top: Math.min(Math.max(top, MARGIN), Math.max(MARGIN, viewportHeight - cardHeight - MARGIN)),
      left: Math.min(rect.left + rect.width + GAP, viewportWidth - CARD_WIDTH - MARGIN),
    };
  } else {
    const left = rect.left + rect.width - CARD_WIDTH;
    cardStyle = {
      top: Math.min(rect.top + rect.height + GAP, Math.max(MARGIN, viewportHeight - cardHeight - MARGIN)),
      left: Math.min(Math.max(left, MARGIN), viewportWidth - CARD_WIDTH - MARGIN),
    };
  }

  const progress = Math.round(((index + 1) / total) * 100);
  const Icon = step.icon;

  return (
    <div className="fixed inset-0 z-[200]" role="dialog" aria-modal="true" aria-label={step.title}>
      {/* Transparent click-catcher: blocks app interaction while touring.
          The dimming itself comes from the spotlight's box-shadow below, so this
          layer stays clear to keep the highlighted element fully lit. */}
      <div className="tour-fade absolute inset-0" onClick={onSkip} />

      {rect && (
        <div
          aria-hidden
          className="tour-spotlight pointer-events-none absolute"
          style={{
            top: rect.top - SPOTLIGHT_PADDING,
            left: rect.left - SPOTLIGHT_PADDING,
            width: rect.width + SPOTLIGHT_PADDING * 2,
            height: rect.height + SPOTLIGHT_PADDING * 2,
            borderRadius: 12,
            boxShadow: `0 0 0 9999px rgba(15, 23, 42, 0.58), 0 0 0 2px ${accent.ring}`,
          }}
        />
      )}

      <div
        ref={cardRef}
        className="tour-card shell-card absolute w-[344px] p-5 shadow-soft"
        style={cardStyle}
        onClick={(event) => event.stopPropagation()}
      >
        <button
          type="button"
          onClick={onSkip}
          aria-label="Close tour"
          className="focus-ring absolute right-3 top-3 flex h-7 w-7 items-center justify-center rounded-lg text-ink-400 transition hover:bg-canvas hover:text-ink-700"
        >
          <X size={15} />
        </button>

        <div className="flex items-start gap-3">
          <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border ${accent.tile}`}>
            <Icon size={20} />
          </div>
          <div className="min-w-0 pr-5">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-400">{step.eyebrow}</div>
            <h2 className="mt-0.5 text-[15px] font-bold leading-snug text-ink-950">{step.title}</h2>
          </div>
        </div>

        <p className="mt-3 text-[13px] leading-relaxed text-ink-600">{step.body}</p>

        <div className="mt-4">
          <div className="flex items-center justify-between text-[11px] font-semibold text-ink-400">
            <span>
              Step {index + 1} of {total}
            </span>
            <span>{progress}%</span>
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-canvas">
            <div
              className={`h-full rounded-full ${accent.bar} transition-all duration-300`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <button
            type="button"
            onClick={onSkip}
            className="focus-ring rounded-lg px-2 py-1.5 text-[12px] font-semibold text-ink-400 transition hover:text-ink-700"
          >
            Skip tour
          </button>
          <div className="flex items-center gap-2">
            {!isFirst && (
              <button
                type="button"
                onClick={onBack}
                className="focus-ring inline-flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-2 text-[12px] font-semibold text-ink-700 transition hover:border-cyan-200 hover:text-ink-950"
              >
                <ArrowLeft size={14} />
                Back
              </button>
            )}
            <button
              type="button"
              onClick={onNext}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-3.5 py-2 text-[12px] font-bold text-white transition hover:bg-violet-500"
            >
              {isLast ? "Finish" : "Next"}
              {!isLast && <ArrowRight size={14} />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
