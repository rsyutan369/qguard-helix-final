import { useCallback, useEffect, useMemo, useState } from "react";

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
  const { mode, email, attemptsRemaining, lockoutUntil, rootWarning, onSubmit, onUsePassword, busy } = props;
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
  useEffect(() => {
    if (entry.length !== digits) return;
    const id = window.setTimeout(() => void commit(entry), 80);
    return () => window.clearTimeout(id);
  }, [entry, digits, commit]);

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
    if (mode === "unlock") return email ? `Unlock QGuard Messaging — ${email}` : "Unlock QGuard Messaging";
    if (stage === "choose") return "You'll use this PIN to unlock the app on this device.";
    return "";
  }, [mode, stage, email]);

  return (
    <div className="flex min-h-screen w-screen flex-col items-center justify-center bg-canvas px-6 py-10">
      <div className="flex w-full max-w-sm flex-col items-center gap-8">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/20 to-cyan-500/5 text-2xl">🔐</div>
          <h1 className="text-xl font-bold text-ink-950">{heading}</h1>
          {subheading && <p className="mt-1 text-sm text-ink-600">{subheading}</p>}
        </div>

        {rootWarning && (
          <div className="w-full rounded-lg border border-amber-300/40 bg-amber-50/60 px-3 py-2 text-center text-xs font-medium text-amber-700">
            This device appears rooted. Your session remains encrypted, but rooted devices are higher risk.
          </div>
        )}

        {mode === "setup" && stage === "choose" ? (
          <div className="flex w-full flex-col gap-3">
            <button onClick={() => { setChosenDigits(4); setStage("enter"); }} className="rounded-xl border border-line bg-white px-4 py-4 text-center text-sm font-semibold text-ink-950 hover:border-cyan-400">
              4-digit PIN
            </button>
            <button onClick={() => { setChosenDigits(6); setStage("enter"); }} className="rounded-xl border border-line bg-white px-4 py-4 text-center text-sm font-semibold text-ink-950 hover:border-cyan-400">
              6-digit PIN <span className="text-ink-500">(recommended)</span>
            </button>
          </div>
        ) : (
          <>
            <div className={`flex items-center justify-center gap-3 ${shake ? "animate-[shake_0.5s]" : ""}`}>
              {Array.from({ length: digits }).map((_, i) => (
                <span key={i} className={`h-4 w-4 rounded-full border transition-colors ${i < entry.length ? "border-cyan-500 bg-cyan-500" : "border-line bg-transparent"}`} />
              ))}
            </div>

            {error && <p className="text-center text-sm font-medium text-rose-500">{error}</p>}
            {lockoutRemaining > 0 && <p className="text-center text-sm font-medium text-amber-600">Too many attempts. Try again in {lockoutRemaining}s.</p>}
            {mode === "unlock" && typeof attemptsRemaining === "number" && attemptsRemaining < 5 && lockoutRemaining === 0 && (
              <p className="text-center text-xs text-ink-500">{attemptsRemaining} attempt(s) remaining</p>
            )}

            <div className="grid grid-cols-3 gap-4">
              {["1","2","3","4","5","6","7","8","9"].map((n) => (
                <button key={n} disabled={disabled} onClick={() => press(n)} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-line bg-white text-2xl font-medium text-ink-950 transition active:scale-95 disabled:opacity-40">
                  {n}
                </button>
              ))}
              <span />
              <button disabled={disabled} onClick={() => press("0")} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-line bg-white text-2xl font-medium text-ink-950 transition active:scale-95 disabled:opacity-40">0</button>
              <button disabled={disabled || entry.length === 0} onClick={back} className="mx-auto flex h-16 w-16 items-center justify-center rounded-full text-xl text-ink-500 transition active:scale-95 disabled:opacity-30">⌫</button>
            </div>

            {/* Biometric slot (fast-follow) — disabled placeholder */}
            <button disabled className="text-xs text-ink-500 opacity-40">Unlock with biometrics (coming soon)</button>
          </>
        )}

        {mode === "unlock" && onUsePassword && (
          <button onClick={onUsePassword} className="text-sm font-medium text-cyan-600 hover:underline">
            Sign in with password instead
          </button>
        )}
      </div>
    </div>
  );
}

export default AppLockScreen;
