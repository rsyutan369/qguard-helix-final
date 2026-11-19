import { useId, useState, type FormEvent } from "react";
import { KeyRound, LogOut, RotateCcw, ShieldAlert, TriangleAlert } from "lucide-react";
import { RESET_DEVICE_IDENTITY_CONFIRMATION, type DeviceKeyRecovery } from "@/lib/auth-context";

interface DeviceKeyRecoveryScreenProps {
  recovery: DeviceKeyRecovery;
  onRetry: () => Promise<boolean>;
  onReset: (confirmation: string) => Promise<boolean>;
  onSignOut: () => Promise<void>;
}

const button = "focus-ring inline-flex min-h-12 items-center justify-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-semibold text-ink-800 transition-colors hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-50";

/**
 * Sign-in succeeded, but this device's stored keys cannot be opened because
 * the OS secure store no longer has the key that unlocks them. Nothing is
 * replaced automatically: re-keying would permanently destroy this device's
 * readable history, so the user chooses to retry, reset deliberately, or leave.
 */
export function DeviceKeyRecoveryScreen({ recovery, onRetry, onReset, onSignOut }: DeviceKeyRecoveryScreenProps) {
  const [confirmation, setConfirmation] = useState("");
  const [showDetail, setShowDetail] = useState(false);
  const titleId = useId();
  const inputId = useId();
  const confirmed = confirmation.trim() === RESET_DEVICE_IDENTITY_CONFIRMATION;

  function reset(event: FormEvent) {
    event.preventDefault();
    if (confirmed && !recovery.busy) void onReset(confirmation.trim());
  }

  return <main className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
    <section aria-labelledby={titleId} className="shell-card w-full max-w-xl space-y-5 p-6 sm:p-8">
      <header className="flex items-start gap-3">
        <span className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-amber-700"><ShieldAlert size={24} aria-hidden /></span>
        <div className="min-w-0">
          <h1 id={titleId} className="text-xl font-bold text-ink-950">This device's keys can't be opened</h1>
          <p className="mt-1 break-words text-sm text-ink-600">Signed in as {recovery.account}</p>
        </div>
      </header>

      <div className="space-y-2 text-sm leading-relaxed text-ink-700">
        <p>Your account signed in, but the key that unlocks this device's stored message keys is no longer in this computer's secure credential store. The encrypted files are still here. Qguard did not replace them.</p>
        <p>This can happen after a Windows profile or Credential Manager reset, a restore from backup, or security software that removed saved credentials. Your other devices are not affected.</p>
      </div>

      {recovery.error && <p role="alert" className="flex gap-2 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">
        <TriangleAlert size={18} className="mt-0.5 shrink-0" aria-hidden /> <span className="min-w-0 break-words">{recovery.error}</span>
      </p>}

      <div className="space-y-2 rounded-lg border border-line p-4">
        <h2 className="text-sm font-bold text-ink-950">If the key can come back</h2>
        <p className="text-sm text-ink-600">Restore the credential store, or sign in to Windows with the account that set this app up, then try again.</p>
        <button type="button" className={button} disabled={recovery.busy} onClick={() => void onRetry()}>
          <RotateCcw size={16} aria-hidden /> Try again
        </button>
      </div>

      <form className="space-y-3 rounded-lg border border-rose-200 p-4" onSubmit={reset}>
        <h2 className="flex items-center gap-2 text-sm font-bold text-ink-950"><KeyRound size={16} aria-hidden /> If the key is lost: reset this device</h2>
        <ul className="list-disc space-y-1 pl-5 text-sm text-ink-700">
          <li>This computer gets a new device identity and can send and receive new messages.</li>
          <li>Messages sealed to the old keys stay unreadable on this computer. Read them on your other devices.</li>
          <li>Secure Chat and Quantum Vault locks must be set up again here. For the vault, use your recovery key or start a fresh vault.</li>
          <li>Nearby devices must be paired again for Mesh and XFER.</li>
        </ul>
        <label htmlFor={inputId} className="block text-sm font-semibold text-ink-800">
          Type <code className="rounded bg-canvas px-1.5 py-0.5 font-mono text-xs">{RESET_DEVICE_IDENTITY_CONFIRMATION}</code> to confirm
        </label>
        <input id={inputId} className="focus-ring min-h-12 w-full rounded-lg border border-line bg-white px-3 py-2 font-mono text-sm text-ink-950"
          value={confirmation} autoComplete="off" spellCheck={false} disabled={recovery.busy}
          onChange={(event) => setConfirmation(event.target.value)} />
        <button type="submit" disabled={!confirmed || recovery.busy}
          className="focus-ring inline-flex min-h-12 items-center justify-center gap-2 rounded-lg bg-rose-700 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-rose-800 disabled:cursor-not-allowed disabled:opacity-50">
          {recovery.busy ? "Working…" : "Reset this device and continue"}
        </button>
      </form>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <button type="button" className={button} disabled={recovery.busy} onClick={() => void onSignOut()}>
          <LogOut size={16} aria-hidden /> Sign out
        </button>
        <button type="button" className="focus-ring text-sm font-semibold text-ink-600 underline-offset-2 hover:underline" aria-expanded={showDetail}
          onClick={() => setShowDetail((open) => !open)}>
          {showDetail ? "Hide technical details" : "Show technical details"}
        </button>
      </div>
      {showDetail && <p className="break-words rounded-lg bg-canvas p-3 font-mono text-xs text-ink-700">{recovery.detail}</p>}
      <p role="status" className="sr-only">{recovery.busy ? "Working" : ""}</p>
    </section>
  </main>;
}
