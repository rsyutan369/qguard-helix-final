import { useCallback, useEffect, useMemo, useState } from "react";
import { Delete, LockKeyhole, ShieldAlert } from "lucide-react";

type Mode = "setup" | "unlock";

interface AppLockScreenProps {
  mode: Mode;
  email?: string | null;
  digits?: number; // unlock: known digit count
  attemptsRemaining?: number;
  lockoutUntil?: string | null;
  rootWarning?: boolean;
  onSubmit: (pin: string, digits: number) => Promise<void>; // throws on failure
  onUsePassword?: () => void; // full email/password auth escape hatch
  busy?: boolean;
  busyLabel?: string; // shown while `busy`, e.g. restoring the session after a correct PIN
}

function useLockoutCountdown(lockoutUntil?: string | null): number {
  const [remaining, setRemaining] = useState(0);
  useEffect(() => {
    if (!lockoutUntil) { setRemaining(0); return; }
    const tick = () => {
      const secs = Math.ceil((new Date(lockoutUntil).getTime() - Date.now()) / 1000);
      setRemaining(secs > 0 ? secs : 0);
    };
    tick();
    const id = window.setInterval(tick, 500);
    return () => window.clearInterval(id);
  }, [lockoutUntil]);
  return remaining;
}

export function AppLockScreen(props: AppLockScreenProps) {
  const { mode, attemptsRemaining, lockoutUntil, rootWarning, onSubmit, onUsePassword, busy, busyLabel } = props;
  const [chosenDigits, setChosenDigits] = useState<number>(props.digits ?? 6);
  const [stage, setStage] = useState<"choose" | "enter" | "confirm">(mode === "setup" ? "choose" : "enter");
  const [entry, setEntry] = useState("");
  const [firstPin, setFirstPin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const digits = mode === "unlock" ? (props.digits ?? 6) : chosenDigits;
  const lockoutRemaining = useLockoutCountdown(lockoutUntil);
  const disabled = Boolean(busy) || submitting || lockoutRemaining > 0;

  const triggerShake = useCallback(() => {
    setShake(true);
    window.setTimeout(() => setShake(false), 500);
  }, []);

  const commit = useCallback(
    async (pin: string) => {
      if (mode === "setup") {
        if (stage === "enter") {
          setFirstPin(pin);
          setEntry("");
          setStage("confirm");
          return;
        }
        // confirm
        if (pin !== firstPin) {
          setError("PINs did not match. Start again.");
          setEntry("");
          setFirstPin("");
          setStage("enter");
          triggerShake();
          return;
        }
      }
      setSubmitting(true);
      setError(null);
      try {
        await onSubmit(pin, digits);
        setEntry("");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Incorrect PIN.");
        setEntry("");
        if (mode === "setup") { setFirstPin(""); setStage("enter"); }
        triggerShake();
      } finally {
        setSubmitting(false);
      }
    },
    [mode, stage, firstPin, digits, onSubmit, triggerShake],
  );

  const press = useCallback(
    (n: string) => {
      if (disabled) return;
      setError(null);
      setEntry((prev) => (prev.length >= digits ? prev : prev + n));
    },
    [disabled, digits],
  );

  // Auto-submit once the entry reaches the target length. Kept out of the
  // setEntry updater above — updaters must be pure, and under
  // React.StrictMode (main.tsx double-invokes updaters in dev) a side effect
  // there would schedule commit() twice, burning two attempts for one PIN.
  // `disabled` matters after a correct PIN: the screen can stay mounted (busy)
  // while the session restores, and `commit` changes identity on every parent
  // render — without the guard the same full entry would be re-submitted.
  useEffect(() => {
    if (entry.length !== digits || disabled) return;
    const id = window.setTimeout(() => void commit(entry), 80);
    return () => window.clearTimeout(id);
  }, [entry, digits, commit, disabled]);

  const back = useCallback(() => {
    if (disabled) return;
    setEntry((p) => p.slice(0, -1));
  }, [disabled]);

  const heading = useMemo(() => {
    if (mode === "unlock") return "Enter your PIN";
    if (stage === "choose") return "Create your app PIN";
    if (stage === "confirm") return "Confirm your PIN";
    return `Enter a ${digits}-digit PIN`;
  }, [mode, stage, digits]);

  const subheading = useMemo(() => {
    if (mode === "unlock") return "Unlock QGuard Messaging";
    if (stage === "choose") return "You'll use this PIN to unlock the app on this device.";
    return "";
  }, [mode, stage]);

  return (
    <div className="qg-stage relative flex min-h-[100dvh] w-screen flex-col items-center justify-center overflow-hidden px-6 py-10">
      {/* Ambient light */}
      <div className="pointer-events-none absolute inset-0 -z-10 overflow-hidden" aria-hidden>
        <span
          className="qg-orb"
          style={{
            width: 320, height: 320, top: -130, left: -100,
            background: "radial-gradient(circle, var(--qg-flux), transparent 68%)", opacity: 0.3,
          }}
        />
        <span
          className="qg-orb"
          style={{
            width: 300, height: 300, bottom: -130, right: -90,
            background: "radial-gradient(circle, var(--qg-helix), transparent 68%)", opacity: 0.28,
            animationDelay: "-7s",
          }}
        />
      </div>

      <div className="flex w-full max-w-[21rem] flex-col items-center gap-7">
        <div className="qg-rise text-center" style={{ ["--qg-i" as string]: 0 }}>
          <span
            className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-[20px]"
            style={{
              background: "var(--qg-panel)",
              border: "1px solid var(--qg-hairline)",
              color: "var(--qg-helix)",
              boxShadow: "var(--qg-glow)",
            }}
          >
            <LockKeyhole size={26} strokeWidth={1.7} />
          </span>
          <h1 className="qg-display text-[21px] leading-tight">{heading}</h1>
          {subheading && (
            <p className="mt-1.5 text-[13px] leading-snug" style={{ color: "var(--qg-text-2)" }}>{subheading}</p>
          )}
          {mode === "unlock" && props.email && (
            <p className="qg-mono mt-1.5 truncate text-[11px]" style={{ color: "var(--qg-text-3)" }}>{props.email}</p>
          )}
        </div>

        {rootWarning && (
          <div
            className="qg-rise flex w-full items-start gap-2 rounded-2xl p-3 text-[11.5px] leading-snug"
            style={{
              ["--qg-i" as string]: 1,
              background: "var(--qg-warn-wash)",
              border: "1px solid var(--qg-hairline)",
              color: "var(--qg-warn)",
            }}
          >
            <ShieldAlert size={14} className="mt-px shrink-0" />
            <span>This device appears rooted. Your session stays encrypted, but rooted devices carry more risk.</span>
          </div>
        )}

        {mode === "setup" && stage === "choose" ? (
          <div className="qg-rise flex w-full flex-col gap-2.5" style={{ ["--qg-i" as string]: 2 }}>
            <button
              onClick={() => { setChosenDigits(6); setStage("enter"); }}
              className="qg-card qg-card-press qg-focusable flex items-center justify-between px-4 py-4 text-left"
            >
              <span>
                <span className="qg-display block text-[14px]">6-digit PIN</span>
                <span className="mt-0.5 block text-[11.5px]" style={{ color: "var(--qg-text-3)" }}>
                  A million combinations. Required for new PINs.
                </span>
              </span>
              <span className="qg-pill qg-tone-info">Continue</span>
            </button>
          </div>
        ) : (
          <>
            <div className={`flex items-center justify-center gap-3.5 ${shake ? "animate-[shake_0.5s]" : ""}`}>
              {Array.from({ length: digits }).map((_, i) => {
                const filled = i < entry.length;
                return (
                  <span
                    key={i}
                    className="rounded-full transition-all duration-200"
                    style={{
                      height: filled ? 13 : 11,
                      width: filled ? 13 : 11,
                      background: filled
                        ? "linear-gradient(140deg, var(--qg-flux), var(--qg-helix))"
                        : "transparent",
                      border: filled ? "none" : "1.5px solid var(--qg-hairline-strong)",
                      boxShadow: filled ? "var(--qg-glow)" : "none",
                    }}
                  />
                );
              })}
            </div>

            <div className="flex min-h-[18px] flex-col items-center gap-1">
              {error && (
                <p className="text-center text-[12.5px] font-semibold" style={{ color: "var(--qg-alert)" }}>{error}</p>
              )}
              {busy && busyLabel && !error && (
                <p role="status" className="qg-mono text-center text-[11.5px]" style={{ color: "var(--qg-text-2)" }}>
                  {busyLabel}
                </p>
              )}
              {lockoutRemaining > 0 && (
                <p className="text-center text-[12.5px] font-semibold" style={{ color: "var(--qg-warn)" }}>
                  Too many attempts. Try again in {lockoutRemaining}s.
                </p>
              )}
              {mode === "unlock" && typeof attemptsRemaining === "number" && attemptsRemaining < 5 && lockoutRemaining === 0 && (
                <p className="qg-mono text-center text-[11px]" style={{ color: "var(--qg-text-3)" }}>
                  {attemptsRemaining} attempt{attemptsRemaining === 1 ? "" : "s"} remaining
                </p>
              )}
            </div>

            <div className="grid w-full grid-cols-3 gap-3.5">
              {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((n) => (
                <button
                  key={n}
                  disabled={disabled}
                  onClick={() => press(n)}
                  className="qg-focusable qg-num mx-auto flex h-[68px] w-[68px] items-center justify-center rounded-full text-[24px] transition-transform duration-150 active:scale-90 disabled:opacity-35"
                  style={{
                    background: "var(--qg-panel)",
                    border: "1px solid var(--qg-hairline)",
                    color: "var(--qg-text)",
                    boxShadow: "var(--qg-shadow)",
                  }}
                >
                  {n}
                </button>
              ))}
              <span />
              <button
                disabled={disabled}
                onClick={() => press("0")}
                className="qg-focusable qg-num mx-auto flex h-[68px] w-[68px] items-center justify-center rounded-full text-[24px] transition-transform duration-150 active:scale-90 disabled:opacity-35"
                style={{
                  background: "var(--qg-panel)",
                  border: "1px solid var(--qg-hairline)",
                  color: "var(--qg-text)",
                  boxShadow: "var(--qg-shadow)",
                }}
              >
                0
              </button>
              <button
                disabled={disabled || entry.length === 0}
                onClick={back}
                aria-label="Delete last digit"
                className="qg-focusable mx-auto flex h-[68px] w-[68px] items-center justify-center rounded-full transition-transform duration-150 active:scale-90 disabled:opacity-25"
                style={{ color: "var(--qg-text-3)" }}
              >
                <Delete size={22} />
              </button>
            </div>
          </>
        )}

        {mode === "unlock" && onUsePassword && !busy && (
          <button
            onClick={onUsePassword}
            className="qg-focusable text-[13px] font-semibold"
            style={{ color: "var(--qg-helix)" }}
          >
            Sign in with password instead
          </button>
        )}
      </div>
    </div>
  );
}

export default AppLockScreen;
