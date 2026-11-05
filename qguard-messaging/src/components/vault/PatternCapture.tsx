import { EyeOff, Loader2 } from "lucide-react";
import { useState } from "react";
import { PATTERN_MIN_DOTS, encodePattern, isValidPattern, patternStrength } from "@/lib/pattern";
import { PatternPad, type PatternPadState } from "./PatternPad";

// Drawing a pattern: once to unlock, twice to set one. Hands the canonical
// text to `onSubmit` and keeps nothing; the pattern is checked in the core.

const HIDE_TRAIL_KEY = "qguard.pattern.hideTrail";

function readHideTrail(): boolean {
  try {
    return window.localStorage.getItem(HIDE_TRAIL_KEY) === "1";
  } catch {
    return false;
  }
}

function describe(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "message" in error) return String((error as { message: unknown }).message);
  return "Something went wrong.";
}

export function PatternCapture({
  mode,
  onSubmit,
  disabled = false,
  submitLabel,
}: {
  mode: "unlock" | "set";
  /** Rejects with the reason to show (wrong pattern, lockout…). */
  onSubmit: (pattern: string) => Promise<unknown>;
  disabled?: boolean;
  /** What happens once a new pattern is confirmed ("Saving…" is shown meanwhile). */
  submitLabel?: string;
}) {
  const [first, setFirst] = useState<number[] | null>(null);
  const [padState, setPadState] = useState<PatternPadState>("idle");
  const [message, setMessage] = useState<{ tone: "hint" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [hideTrail, setHideTrail] = useState(readHideTrail);

  const flash = (state: PatternPadState) => {
    setPadState(state);
    window.setTimeout(() => setPadState("idle"), state === "error" ? 900 : 600);
  };

  const submit = async (dots: number[]) => {
    setBusy(true);
    try {
      await onSubmit(encodePattern(dots));
      flash("success");
      setMessage(null);
    } catch (error) {
      flash("error");
      setMessage({ tone: "error", text: describe(error) });
    } finally {
      setBusy(false);
      setFirst(null);
    }
  };

  const drawn = (dots: number[]) => {
    if (busy || disabled) return;
    if (!isValidPattern(dots)) {
      flash("error");
      setMessage({ tone: "error", text: `Connect at least ${PATTERN_MIN_DOTS} dots.` });
      return;
    }
    if (mode === "unlock") {
      void submit(dots);
      return;
    }
    if (!first) {
      setFirst(dots);
      flash("success");
      setMessage({
        tone: "hint",
        text: `${patternStrength(dots) === "strong" ? "Strong pattern." : "OK — 8 or more dots is stronger."} Draw it again to confirm.`,
      });
      return;
    }
    if (first.join("-") !== dots.join("-")) {
      setFirst(null);
      flash("error");
      setMessage({ tone: "error", text: "The two patterns didn't match. Start again." });
      return;
    }
    void submit(dots);
  };

  const prompt =
    mode === "unlock"
      ? "Draw your pattern"
      : first
        ? "Draw the same pattern again"
        : `Draw a new pattern — at least ${PATTERN_MIN_DOTS} dots on the 4 × 4 grid`;

  return (
    <div className="space-y-3">
      <p className="text-center text-sm font-semibold text-ink-800">{prompt}</p>
      <PatternPad onComplete={drawn} disabled={disabled || busy} state={padState} hideTrail={hideTrail} />
      <div className="min-h-[1.25rem] text-center text-xs font-semibold" aria-live="polite">
        {busy ? (
          <span className="inline-flex items-center gap-1.5 text-ink-600">
            <Loader2 className="animate-spin" size={13} /> {mode === "unlock" ? "Checking…" : submitLabel ?? "Saving…"}
          </span>
        ) : message ? (
          <span className={message.tone === "error" ? "text-rose-600" : "text-ink-600"}>{message.text}</span>
        ) : null}
      </div>
      <label className="flex items-center justify-center gap-2 text-[11px] font-semibold text-ink-500">
        <input
          type="checkbox"
          checked={hideTrail}
          onChange={(event) => {
            const next = event.currentTarget.checked;
            setHideTrail(next);
            try {
              window.localStorage.setItem(HIDE_TRAIL_KEY, next ? "1" : "0");
            } catch {
              // A display preference only.
            }
          }}
          className="h-3.5 w-3.5 accent-cyan-600"
        />
        <EyeOff size={12} /> Hide the pattern while drawing
      </label>
    </div>
  );
}
