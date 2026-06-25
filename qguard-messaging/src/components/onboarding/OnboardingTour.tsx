import { ArrowRight, CheckCircle2, Circle, RotateCcw, ShieldCheck, Sparkles, Timer } from "lucide-react";
import { useEffect, type ReactElement } from "react";
import { createPortal } from "react-dom";
import SpotlightCard from "@/components/onboarding/SpotlightCard";
import {
  TOUR_ESTIMATED_TIME,
  type ChecklistItem,
  type OnboardingController,
  type TourStep,
} from "@/lib/onboarding";
import type { Page } from "@/lib/types";

interface OnboardingTourProps {
  controller: OnboardingController;
  steps: TourStep[];
  checklist: ChecklistItem[];
  userName?: string | null;
  onNavigate: (page: Page) => void;
}

function firstName(name?: string | null): string {
  const clean = (name ?? "").trim();
  if (!clean) return "there";
  return clean.split(/\s+/)[0];
}

export default function OnboardingTour({ controller, steps, checklist, userName, onNavigate }: OnboardingTourProps) {
  const { phase, stepIndex } = controller;
  const activeStep = steps[stepIndex];

  // Drive the app to the page each touring step describes so the user sees the
  // real screen behind the spotlight.
  useEffect(() => {
    if (phase !== "touring" || !activeStep?.page) return;
    onNavigate(activeStep.page);
  }, [phase, activeStep?.page, onNavigate]);

  if (phase === "hidden" || typeof document === "undefined") return null;

  let content: ReactElement | null = null;

  if (phase === "welcome") {
    content = (
      <div className="fixed inset-0 z-[200] flex items-center justify-center p-6">
        <div className="tour-scrim absolute inset-0" />
        <div className="tour-card shell-card relative w-[440px] max-w-full overflow-hidden p-0 shadow-soft">
          <div className="profile-hero flex items-center gap-3 px-6 py-5">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-violet-100 bg-white/80 text-violet-600">
              <ShieldCheck size={24} />
            </div>
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-violet-600">QGuard Messaging</div>
              <div className="text-lg font-bold text-ink-950">Welcome, {firstName(userName)}</div>
            </div>
          </div>

          <div className="px-6 pb-6 pt-5">
            <p className="text-sm leading-relaxed text-ink-600">
              Your secure, quantum-safe workspace is ready. Take a short guided tour to see how messaging,
              encryption, device trust, and recovery fit together — so your data stays protected from day one.
            </p>

            <div className="mt-4 flex items-center gap-2">
              <span className="status-pill bg-cyan-50 text-cyan-700">
                <Timer size={13} />
                {TOUR_ESTIMATED_TIME} walkthrough
              </span>
              <span className="status-pill bg-violet-50 text-violet-600">
                <Sparkles size={13} />
                {steps.length} quick stops
              </span>
            </div>

            <div className="mt-6 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={controller.skip}
                className="focus-ring rounded-lg px-3 py-2 text-sm font-semibold text-ink-500 transition hover:text-ink-800"
              >
                Skip for now
              </button>
              <button
                type="button"
                onClick={controller.start}
                className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white transition hover:bg-violet-500"
              >
                Start tour
                <ArrowRight size={16} />
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  } else if (phase === "complete") {
    const doneCount = checklist.filter((item) => item.done).length;
    content = (
      <div className="fixed inset-0 z-[200] flex items-center justify-center p-6">
        <div className="tour-scrim absolute inset-0" />
        <div className="tour-card shell-card relative w-[460px] max-w-full p-6 shadow-soft">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-emerald-100 bg-emerald-50 text-emerald-600">
              <CheckCircle2 size={24} />
            </div>
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-emerald-600">Tour complete</div>
              <h2 className="text-lg font-bold text-ink-950">You're ready to go</h2>
            </div>
          </div>

          <p className="mt-3 text-sm leading-relaxed text-ink-600">
            Here's your security readiness checklist. Finish any remaining steps whenever you're ready —
            each links straight to the right place.
          </p>

          <div className="mt-4 flex items-center justify-between text-[11px] font-semibold text-ink-400">
            <span>Readiness</span>
            <span>
              {doneCount} of {checklist.length} complete
            </span>
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-canvas">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${checklist.length ? Math.round((doneCount / checklist.length) * 100) : 0}%` }}
            />
          </div>

          <ul className="mt-4 grid gap-1.5">
            {checklist.map((item) => (
              <li
                key={item.id}
                className="flex items-center gap-3 rounded-lg border border-line bg-ink-50 px-3 py-2.5"
              >
                {item.done ? (
                  <CheckCircle2 size={18} className="shrink-0 text-emerald-500" />
                ) : (
                  <Circle size={18} className="shrink-0 text-ink-400" />
                )}
                <div className="min-w-0 flex-1">
                  <div className={`text-[13px] font-semibold ${item.done ? "text-ink-950" : "text-ink-700"}`}>
                    {item.label}
                  </div>
                  {!item.done && <div className="text-[11px] text-ink-400">{item.hint}</div>}
                </div>
                {!item.done && (
                  <button
                    type="button"
                    onClick={() => {
                      onNavigate(item.page);
                      controller.complete();
                    }}
                    className="focus-ring shrink-0 rounded-lg border border-line bg-white px-2.5 py-1.5 text-[11px] font-semibold text-ink-700 transition hover:border-cyan-200 hover:text-ink-950"
                  >
                    Set up
                  </button>
                )}
              </li>
            ))}
          </ul>

          <div className="mt-6 flex items-center justify-between">
            <button
              type="button"
              onClick={controller.replay}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg px-2 py-2 text-[12px] font-semibold text-ink-500 transition hover:text-ink-800"
            >
              <RotateCcw size={14} />
              Replay tour
            </button>
            <button
              type="button"
              onClick={() => {
                onNavigate("dashboard");
                controller.complete();
              }}
              className="focus-ring inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white transition hover:bg-violet-500"
            >
              Go to Dashboard
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      </div>
    );
  } else if (phase === "touring" && activeStep) {
    content = (
      <SpotlightCard
        key={activeStep.id}
        step={activeStep}
        index={stepIndex}
        total={steps.length}
        isFirst={stepIndex === 0}
        isLast={stepIndex === steps.length - 1}
        onBack={controller.back}
        onNext={controller.next}
        onSkip={controller.skip}
      />
    );
  }

  if (!content) return null;
  return createPortal(content, document.body);
}
