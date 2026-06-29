import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  KeyRound,
  Loader2,
  Lock,
  MessageSquareLock,
  ShieldCheck,
  UnlockKeyhole,
} from "lucide-react";
import type { ScopeStatus, UnlockMethod, WorkspaceScope } from "@/lib/use-workspace-lock";

function describeError(error: unknown): string {
  if (!error) return "Something went wrong.";
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (typeof error === "object") {
    const record = error as Record<string, unknown>;
    const message = record.message ?? record.error;
    if (typeof message === "string") return message;
    try {
      return JSON.stringify(record);
    } catch {
      return "Unexpected error.";
    }
  }
  return String(error);
}

const COPY: Record<WorkspaceScope, { title: string; locked: string; blurb: string; cta: string; Icon: typeof Lock }> = {
  chat: {
    title: "Secure Chat",
    locked: "Secure Chat Locked",
    blurb: "This workspace contains end-to-end encrypted conversations and protected files. Authenticate to continue.",
    cta: "Unlock Chat",
    Icon: MessageSquareLock,
  },
  vault: {
    title: "Quantum Vault",
    locked: "Quantum Vault Locked",
    blurb: "This workspace contains locally encrypted files and quantum-safe recovery material. Authenticate to continue.",
    cta: "Unlock Vault",
    Icon: Lock,
  },
};

export function WorkspaceLockGate(props: {
  scope: WorkspaceScope;
  status: ScopeStatus;
  recoveryEnabled?: boolean;
  inactivityMinutes: number;
  onUnlock: (method: UnlockMethod, secret: string) => Promise<unknown>;
  onSetup: (method: UnlockMethod, secret: string) => Promise<unknown>;
  onCancel: () => void;
}) {
  const { scope, status } = props;
  const copy = COPY[scope];
  const setupMode = !status.configured;

  const initialMethod: UnlockMethod = status.hasPassword || setupMode ? "password" : "pin";
  const [method, setMethod] = useState<UnlockMethod>(initialMethod);
  const [secret, setSecret] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  // Tick once a second so the lockout countdown stays live.
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const lockoutRemaining = useMemo(() => {
    if (!status.lockoutUntil) return 0;
    return Math.max(0, Math.ceil((new Date(status.lockoutUntil).getTime() - now) / 1000));
  }, [status.lockoutUntil, now]);

  const lockedOut = status.lockdown || lockoutRemaining > 0;

  const availableMethods: UnlockMethod[] = setupMode
    ? ["password", "pin"]
    : ([status.hasPassword ? "password" : null, status.hasPin ? "pin" : null].filter(Boolean) as UnlockMethod[]);

  const minOk =
    method === "password" ? secret.length >= 12 : /^\d{6,12}$/.test(secret);
  const confirmOk = !setupMode || secret === confirm;
  const canSubmit = !busy && !lockedOut && secret.length > 0 && minOk && confirmOk;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      if (setupMode) await props.onSetup(method, secret);
      else await props.onUnlock(method, secret);
      setSecret("");
      setConfirm("");
    } catch (err) {
      setError(describeError(err));
      setSecret("");
    } finally {
      setBusy(false);
    }
  }

  const chips =
    scope === "vault"
      ? [
          { label: status.unlocked ? "Unlocked" : "Locked", tone: status.unlocked ? "ok" : "muted" },
          { label: props.recoveryEnabled ? "Recovery Protected" : "Recovery not set", tone: props.recoveryEnabled ? "ok" : "warn" },
          { label: "ML-KEM-1024 Protected", tone: "ok" },
          { label: "AES-256-GCM Active", tone: "ok" },
          { label: props.inactivityMinutes > 0 ? "Auto-Lock Enabled" : "Auto-Lock Off", tone: props.inactivityMinutes > 0 ? "ok" : "warn" },
        ]
      : [
          { label: status.unlocked ? "Unlocked" : "Locked", tone: status.unlocked ? "ok" : "muted" },
          { label: "End-to-end Encrypted", tone: "ok" },
          { label: props.inactivityMinutes > 0 ? "Auto-Lock Enabled" : "Auto-Lock Off", tone: props.inactivityMinutes > 0 ? "ok" : "warn" },
        ];

  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-md rounded-xl border border-line bg-white p-6 shadow-soft">
        <div className="flex items-center gap-3">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-white shadow-tight">
            <copy.Icon size={22} />
          </span>
          <div className="min-w-0">
            <h2 className="text-lg font-bold text-ink-950">{setupMode ? `Protect ${copy.title}` : copy.locked}</h2>
            <p className="mt-0.5 text-sm text-ink-600">
              {setupMode
                ? `Create a workspace ${method === "pin" ? "PIN" : "password"} to gate ${copy.title}. It is separate from your account and your other workspaces.`
                : copy.blurb}
            </p>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {chips.map((chip) => (
            <span
              key={chip.label}
              className={`status-pill ${
                chip.tone === "ok"
                  ? "bg-emerald-50 text-emerald-600"
                  : chip.tone === "warn"
                    ? "bg-amber-50 text-amber-700"
                    : "bg-ink-50 text-ink-600"
              }`}
            >
              {chip.tone === "ok" ? <ShieldCheck size={12} /> : <Lock size={12} />} {chip.label}
            </span>
          ))}
        </div>

        {status.lockdown ? (
          <div className="mt-5 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm font-semibold text-rose-700">
            <div className="flex items-center gap-2"><AlertTriangle size={16} /> Workspace locked down</div>
            <p className="mt-2 text-xs font-medium text-rose-600">
              Too many failed attempts. Sign out and sign back in to your account to reset access.
            </p>
          </div>
        ) : (
          <>
            {availableMethods.length > 1 && (
              <div className="mt-5 grid grid-cols-2 gap-1 rounded-lg border border-line bg-canvas p-1" role="radiogroup" aria-label="Unlock method">
                {availableMethods.map((option) => (
                  <button
                    key={option}
                    type="button"
                    role="radio"
                    aria-checked={method === option}
                    onClick={() => { setMethod(option); setSecret(""); setConfirm(""); setError(null); }}
                    className={`rounded-md px-3 py-1.5 text-sm font-bold transition ${method === option ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-white/70"}`}
                  >
                    {option === "password" ? "Password" : "PIN"}
                  </button>
                ))}
              </div>
            )}

            <div className="mt-4">
              <input
                type="password"
                inputMode={method === "pin" ? "numeric" : "text"}
                autoFocus
                value={secret}
                onChange={(event) => setSecret(event.currentTarget.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void submit(); }}
                placeholder={method === "pin" ? "Enter your PIN (6–12 digits)" : `Enter your ${copy.title} password`}
                disabled={lockedOut}
                className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300 disabled:opacity-60"
              />
              {setupMode && (
                <input
                  type="password"
                  inputMode={method === "pin" ? "numeric" : "text"}
                  value={confirm}
                  onChange={(event) => setConfirm(event.currentTarget.value)}
                  onKeyDown={(event) => { if (event.key === "Enter") void submit(); }}
                  placeholder={`Confirm ${method === "pin" ? "PIN" : "password"}`}
                  className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300"
                />
              )}
              {setupMode && !minOk && secret.length > 0 && (
                <div className="mt-1.5 text-[11px] font-semibold text-amber-600">
                  {method === "pin" ? "PIN must be 6–12 digits." : "Password must be at least 12 characters."}
                </div>
              )}
              {setupMode && !confirmOk && confirm.length > 0 && (
                <div className="mt-1.5 text-[11px] font-semibold text-amber-600">The two entries don’t match.</div>
              )}
            </div>

            {setupMode && scope === "vault" && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-[11px] font-semibold text-amber-800">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                This {method === "pin" ? "PIN" : "password"} decrypts your Vault Master Key. If you forget it, the only way back in is your recovery key — QGuard cannot reset it.
              </div>
            )}

            {error && (
              <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600">{error}</div>
            )}
            {lockoutRemaining > 0 && (
              <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-700">
                Too many attempts. Try again in {lockoutRemaining}s.
              </div>
            )}

            <div className="mt-5 flex gap-2">
              <button
                type="button"
                onClick={() => void submit()}
                disabled={!canSubmit}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? <Loader2 className="animate-spin" size={16} /> : setupMode ? <KeyRound size={16} /> : <UnlockKeyhole size={16} />}
                {setupMode ? `Set ${method === "pin" ? "PIN" : "password"}` : copy.cta}
              </button>
              <button
                type="button"
                onClick={props.onCancel}
                className="rounded-lg border border-line bg-white px-4 py-2.5 text-sm font-bold text-ink-700 hover:bg-canvas"
              >
                Cancel
              </button>
            </div>
          </>
        )}

        {status.lockdown && (
          <button
            type="button"
            onClick={props.onCancel}
            className="mt-4 w-full rounded-lg border border-line bg-white px-4 py-2.5 text-sm font-bold text-ink-700 hover:bg-canvas"
          >
            Back to dashboard
          </button>
        )}
      </div>
    </div>
  );
}
