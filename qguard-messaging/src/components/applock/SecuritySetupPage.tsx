import { CheckCircle2, Circle, Fingerprint, Grid3x3, Loader2, ScanFace, ShieldCheck, Spline } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { AppLockScreen } from "@/components/applock/AppLockScreen";
import { PatternCapture } from "@/components/vault/PatternCapture";
import type { AppLockMethod, BiometricStatus } from "@/lib/use-app-lock";

/**
 * Security Setup — shown on a new installation, a new device, or after signing
 * in again with the account password. The user picks how this device unlocks:
 *
 *   * a PIN or a drawn pattern (one is required — it is the key that wraps the
 *     stored session, and the fallback whenever a biometric cannot be used);
 *   * optionally fingerprint and/or face, as an extra, faster way in.
 *
 * Biometrics are Android's STRONG class only (BiometricPrompt + a Keystore key
 * that a successful prompt releases), so the options say plainly when this
 * phone cannot offer one. Android decides which enrolled strong biometric its
 * prompt uses; fingerprint and face both turn on that same biometric unlock.
 */

type Step = "choose" | "secret" | "biometric";

function availabilityNote(kind: "fingerprint" | "face", status: BiometricStatus | null): string | null {
  if (!status) return "Checking this phone…";
  const sensors = status.modalities ?? [];
  if (status.availability === "unsupported") return "Available on the Android app";
  if (!sensors.includes(kind)) return kind === "fingerprint" ? "No fingerprint sensor on this phone" : "No face recognition on this phone";
  if (status.availability === "none_enrolled") return kind === "fingerprint" ? "Add a fingerprint in Android Settings first" : "Set up face unlock in Android Settings first";
  if (status.availability !== "available") return "Not available right now";
  return null;
}

function Option({
  icon,
  label,
  detail,
  selected,
  disabled,
  kind,
  onToggle,
}: {
  icon: ReactNode;
  label: string;
  detail?: string | null;
  selected: boolean;
  disabled?: boolean;
  kind: "radio" | "check";
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      role={kind === "radio" ? "radio" : "checkbox"}
      aria-checked={selected}
      disabled={disabled}
      onClick={onToggle}
      className="qg-card qg-card-press qg-focusable flex w-full items-center gap-3.5 px-4 py-3.5 text-left disabled:opacity-55"
      style={selected ? { outline: "2px solid var(--qg-helix)", outlineOffset: "-1px", background: "var(--qg-helix-wash)" } : undefined}
    >
      <span className="flex h-9 w-9 shrink-0 items-center justify-center" style={{ color: "var(--qg-helix)" }}>
        {icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="qg-display block text-[14.5px]">{label}</span>
        {detail && (
          <span className="mt-0.5 block text-[11.5px] leading-snug" style={{ color: "var(--qg-text-3)" }}>
            {detail}
          </span>
        )}
      </span>
      {selected ? (
        <CheckCircle2 size={21} className="shrink-0" style={{ color: "var(--qg-helix)" }} />
      ) : (
        <Circle size={21} className="shrink-0" style={{ color: "var(--qg-hairline-strong)" }} />
      )}
    </button>
  );
}

export default function SecuritySetupPage({
  email,
  reconfirm = false,
  onStart,
  onSetup,
  biometricStatus,
  onEnableBiometric,
  onDone,
}: {
  email: string | null;
  /** After signing in again with the password: re-securing an existing lock. */
  reconfirm?: boolean;
  /** Called once when the page opens, so the app keeps it on screen until onDone. */
  onStart: () => void;
  /** Seal the stored session under the chosen PIN or pattern. Throws to show an error. */
  onSetup: (method: AppLockMethod, secret: string) => Promise<void>;
  biometricStatus: () => Promise<BiometricStatus>;
  onEnableBiometric: () => Promise<BiometricStatus>;
  onDone: () => void;
}) {
  const [step, setStep] = useState<Step>("choose");
  const [method, setMethod] = useState<AppLockMethod>("pin");
  const [fingerprint, setFingerprint] = useState(false);
  const [face, setFace] = useState(false);
  const [bio, setBio] = useState<BiometricStatus | null>(null);
  const [bioBusy, setBioBusy] = useState(false);
  const [bioError, setBioError] = useState<string | null>(null);

  useEffect(() => {
    onStart();
    void biometricStatus()
      .then(setBio)
      .catch(() => setBio({ availability: "unavailable", enabled: false, modalities: [] }));
    // Once, when the page opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fingerprintNote = availabilityNote("fingerprint", bio);
  const faceNote = availabilityNote("face", bio);
  const wantsBiometric = fingerprint || face;

  const turnOnBiometric = async () => {
    setBioBusy(true);
    setBioError(null);
    try {
      const next = await onEnableBiometric();
      if (!next.enabled) throw new Error("Biometric unlock did not turn on.");
      onDone();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setBioError(/cancel/i.test(message) ? "Cancelled. Try again, or skip and turn it on later in Settings." : message);
    } finally {
      setBioBusy(false);
    }
  };

  // Offer the biometric prompt once, right after the PIN or pattern is saved.
  useEffect(() => {
    if (step === "biometric") void turnOnBiometric();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const afterSecret = () => {
    if (wantsBiometric && bio?.availability === "available") setStep("biometric");
    else onDone();
  };

  if (step === "secret" && method === "pin") {
    return (
      <AppLockScreen
        mode="setup"
        skipChoose
        email={email}
        onBack={() => setStep("choose")}
        onSubmit={async (pin) => {
          await onSetup("pin", pin);
          afterSecret();
        }}
      />
    );
  }

  const biometricWord = fingerprint && face ? "fingerprint or face" : face ? "face" : "fingerprint";

  return (
    <div className="qg-stage relative flex min-h-[100dvh] w-screen flex-col items-center overflow-y-auto px-5 pb-8 pt-[calc(env(safe-area-inset-top,0px)+40px)]">
      <div className="pointer-events-none absolute inset-0 -z-10 overflow-hidden" aria-hidden>
        <span className="qg-orb" style={{ width: 320, height: 320, top: -130, left: -100, background: "radial-gradient(circle, var(--qg-flux), transparent 68%)", opacity: 0.3 }} />
        <span className="qg-orb" style={{ width: 300, height: 300, bottom: -130, right: -90, background: "radial-gradient(circle, var(--qg-helix), transparent 68%)", opacity: 0.28, animationDelay: "-7s" }} />
      </div>

      <div className="flex w-full max-w-[22rem] flex-1 flex-col">
        <div className="text-center">
          <img src="/brand/qguard-messaging-badge.webp" alt="QGuard Messaging" className="mx-auto h-16 w-16 object-contain" />
          <h1 className="qg-display mt-4 text-[24px] leading-tight">
            {step === "choose" ? "Set Up Security" : step === "secret" ? "Draw your pattern" : "Add biometric unlock"}
          </h1>
          <p className="mx-auto mt-1.5 max-w-[19rem] text-[13.5px] leading-snug" style={{ color: "var(--qg-text-2)" }}>
            {step === "choose"
              ? reconfirm
                ? "Choose how this device unlocks QGuard Messaging again."
                : "Choose a screen lock method for this device."
              : step === "secret"
                ? "Connect at least 6 dots, then draw it again to confirm."
                : `Confirm with your ${biometricWord} to finish.`}
          </p>
          {email && step === "choose" && (
            <p className="qg-mono mt-1 truncate text-[11px]" style={{ color: "var(--qg-text-3)" }}>{email}</p>
          )}
        </div>

        {step === "choose" && (
          <>
            <div className="mt-7 flex flex-col gap-2.5" role="radiogroup" aria-label="Screen lock">
              <Option
                kind="radio"
                icon={<Grid3x3 size={24} />}
                label="PIN Code"
                detail="6 digits"
                selected={method === "pin"}
                onToggle={() => setMethod("pin")}
              />
              <Option
                kind="radio"
                icon={<Spline size={24} />}
                label="Draw Pattern"
                detail="Connect at least 6 of 16 dots"
                selected={method === "pattern"}
                onToggle={() => setMethod("pattern")}
              />
            </div>

            <p className="qg-eyebrow mt-5 px-1">Additional security</p>
            <div className="mt-2 flex flex-col gap-2.5">
              <Option
                kind="check"
                icon={<Fingerprint size={24} />}
                label="Biometric (Fingerprint)"
                detail={fingerprintNote ?? "Unlock with your fingerprint"}
                selected={fingerprint}
                disabled={Boolean(fingerprintNote)}
                onToggle={() => setFingerprint((value) => !value)}
              />
              <Option
                kind="check"
                icon={<ScanFace size={24} />}
                label="Biometric (Face ID)"
                detail={faceNote ?? "Unlock with face recognition"}
                selected={face}
                disabled={Boolean(faceNote)}
                onToggle={() => setFace((value) => !value)}
              />
            </div>
            <p className="mt-3 px-1 text-[11.5px] leading-snug" style={{ color: "var(--qg-text-3)" }}>
              {wantsBiometric
                ? `Your ${method === "pin" ? "PIN" : "pattern"} stays as the backup for when your ${biometricWord} can't be read. Android uses whichever strong biometric you have set up.`
                : "You can add fingerprint or face unlock now or later in Settings."}
            </p>

            <div className="mt-auto pt-6">
              <button
                type="button"
                onClick={() => setStep("secret")}
                className="qg-focusable flex h-12 w-full items-center justify-center rounded-2xl text-[15px] font-bold text-white"
                style={{ background: "linear-gradient(120deg, var(--qg-flux), var(--qg-helix))", boxShadow: "var(--qg-glow)" }}
              >
                Continue
              </button>
              <p className="mt-3 flex items-center justify-center gap-1.5 text-[11px]" style={{ color: "var(--qg-text-3)" }}>
                <ShieldCheck size={13} /> Stays on this device. Your PIN or pattern never leaves it.
              </p>
            </div>
          </>
        )}

        {step === "secret" && method === "pattern" && (
          <div className="mt-6">
            <PatternCapture
              mode="set"
              submitLabel="Saving your pattern…"
              onSubmit={async (pattern) => {
                await onSetup("pattern", pattern);
                afterSecret();
              }}
            />
            <button type="button" onClick={() => setStep("choose")} className="mt-4 w-full text-center text-[13px] font-semibold" style={{ color: "var(--qg-helix)" }}>
              Back to choices
            </button>
          </div>
        )}

        {step === "biometric" && (
          <div className="mt-8 flex flex-col items-center gap-4 text-center">
            <span className="flex h-20 w-20 items-center justify-center rounded-full" style={{ background: "var(--qg-helix-wash)", color: "var(--qg-helix)" }}>
              {face && !fingerprint ? <ScanFace size={40} /> : <Fingerprint size={40} />}
            </span>
            {bioBusy && (
              <p className="flex items-center gap-2 text-[13px]" style={{ color: "var(--qg-text-2)" }}>
                <Loader2 size={15} className="animate-spin" /> Waiting for Android…
              </p>
            )}
            {bioError && <p className="text-[13px] font-semibold" style={{ color: "var(--qg-alert)" }}>{bioError}</p>}
            <div className="mt-2 flex w-full flex-col gap-2">
              <button
                type="button"
                disabled={bioBusy}
                onClick={() => void turnOnBiometric()}
                className="qg-focusable flex h-12 w-full items-center justify-center rounded-2xl text-[15px] font-bold text-white disabled:opacity-60"
                style={{ background: "linear-gradient(120deg, var(--qg-flux), var(--qg-helix))" }}
              >
                Turn on {biometricWord} unlock
              </button>
              <button type="button" disabled={bioBusy} onClick={onDone} className="h-11 w-full text-[13.5px] font-semibold disabled:opacity-60" style={{ color: "var(--qg-helix)" }}>
                Skip for now
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
