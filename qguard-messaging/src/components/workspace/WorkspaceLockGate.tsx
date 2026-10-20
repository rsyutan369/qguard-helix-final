import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  LifeBuoy,
  Loader2,
  Lock,
  MessageSquareLock,
  ShieldAlert,
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
  // Recovery: reset the chat lock after account re-auth (lossless), or reset the
  // vault lock via the recovery key or an account-password "start fresh".
  onRecoverChat?: (accountPassword: string) => Promise<unknown>;
  onRecoverVaultWithKey?: (recoveryKey: string, method: UnlockMethod, secret: string) => Promise<unknown>;
  onRecoverVaultWithAccount?: (accountPassword: string, method: UnlockMethod, secret: string) => Promise<unknown>;
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
  const [view, setView] = useState<"unlock" | "recover">("unlock");
  const [now, setNow] = useState(() => Date.now());

  const recoverySupported =
    scope === "chat" ? Boolean(props.onRecoverChat) : Boolean(props.onRecoverVaultWithKey || props.onRecoverVaultWithAccount);
  // A lock record that no longer opens cannot be unlocked, only replaced
  // through the re-authenticated reset, so that is the only screen offered.
  const unreadable = Boolean(status.unreadable);

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

  // Green ("ok") is reserved for something this screen actually knows to be
  // true right now: the lock state, whether recovery is set, whether auto-lock
  // is on. The algorithm pills say how the workspace is BUILT — they are
  // neutral, because a lock screen has measured nothing about them and a green
  // tick would read as a live check that passed.
  const chips =
    scope === "vault"
      ? [
          { label: status.unlocked ? "Unlocked" : "Locked", tone: status.unlocked ? "ok" : "muted" },
          { label: props.recoveryEnabled ? "Recovery Protected" : "Recovery not set", tone: props.recoveryEnabled ? "ok" : "warn" },
          { label: "ML-KEM-1024 key wrapping", tone: "muted" },
          { label: "AES-256-GCM", tone: "muted" },
          { label: props.inactivityMinutes > 0 ? "Auto-Lock Enabled" : "Auto-Lock Off", tone: props.inactivityMinutes > 0 ? "ok" : "warn" },
        ]
      : [
          { label: status.unlocked ? "Unlocked" : "Locked", tone: status.unlocked ? "ok" : "muted" },
          { label: "End-to-end encrypted", tone: "muted" },
          { label: props.inactivityMinutes > 0 ? "Auto-Lock Enabled" : "Auto-Lock Off", tone: props.inactivityMinutes > 0 ? "ok" : "warn" },
        ];

  // Recovery view — placed AFTER every hook above so switching views never
  // changes the hook count (an early return before the hooks violates the
  // Rules of Hooks and blanks the whole app).
  if ((view === "recover" || unreadable) && recoverySupported) {
    return (
      <WorkspaceRecoveryPanel
        scope={scope}
        recoveryEnabled={props.recoveryEnabled}
        unreadable={unreadable}
        onBack={unreadable ? props.onCancel : () => setView("unlock")}
        onRecoverChat={props.onRecoverChat}
        onRecoverVaultWithKey={props.onRecoverVaultWithKey}
        onRecoverVaultWithAccount={props.onRecoverVaultWithAccount}
      />
    );
  }

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
              Too many failed attempts. Sign out and sign back in to your account to reset access
              {recoverySupported ? ", or recover access below." : "."}
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
                <span>
                  This {method === "pin" ? "PIN" : "password"} decrypts your Vault Master Key. If you forget it, the only way back in is your recovery key — QGuard cannot reset it.
                  {method === "pin" && " A PIN is short: someone holding a copy of this device's data could try every combination offline, so choose a password if the files need to withstand that."}
                </span>
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

        {!setupMode && recoverySupported && (
          <button
            type="button"
            onClick={() => setView("recover")}
            className="mt-4 flex w-full items-center justify-center gap-1.5 text-xs font-bold text-cyan-700 hover:text-cyan-800 hover:underline"
          >
            <LifeBuoy size={13} />
            Forgot your {status.hasPin && !status.hasPassword ? "PIN" : "PIN or password"}?
          </button>
        )}
      </div>
    </div>
  );
}

// New-secret validity for the recovery flows (mirrors the unlock policy).
function newSecretValid(method: UnlockMethod, secret: string): boolean {
  return method === "password" ? secret.length >= 12 : /^\d{6,12}$/.test(secret);
}

function MethodToggle({ method, onChange }: { method: UnlockMethod; onChange: (m: UnlockMethod) => void }) {
  return (
    <div className="grid grid-cols-2 gap-1 rounded-lg border border-line bg-canvas p-1" role="radiogroup" aria-label="New unlock method">
      {(["password", "pin"] as UnlockMethod[]).map((option) => (
        <button
          key={option}
          type="button"
          role="radio"
          aria-checked={method === option}
          onClick={() => onChange(option)}
          className={`rounded-md px-3 py-1.5 text-sm font-bold transition ${method === option ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-white/70"}`}
        >
          {option === "password" ? "Password" : "PIN"}
        </button>
      ))}
    </div>
  );
}

/**
 * "Forgot PIN/password" recovery. Chat is a lossless reset gated by account
 * re-auth (the lock is a verifier only). Vault offers the recovery key (verified
 * against its stored verifier) or an account-password "start fresh" that installs
 * a new Vault Master Key — with a clear, honest warning that files encrypted under
 * the old key are only recoverable with the recovery key.
 */
function WorkspaceRecoveryPanel(props: {
  scope: WorkspaceScope;
  recoveryEnabled?: boolean;
  /** The saved lock no longer opens on this device (see ScopeStatus.unreadable). */
  unreadable?: boolean;
  onBack: () => void;
  onRecoverChat?: (accountPassword: string) => Promise<unknown>;
  onRecoverVaultWithKey?: (recoveryKey: string, method: UnlockMethod, secret: string) => Promise<unknown>;
  onRecoverVaultWithAccount?: (accountPassword: string, method: UnlockMethod, secret: string) => Promise<unknown>;
}) {
  const isChat = props.scope === "chat";
  const [vaultTab, setVaultTab] = useState<"key" | "account">(props.recoveryEnabled === false ? "account" : "key");
  const [accountPassword, setAccountPassword] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [method, setMethod] = useState<UnlockMethod>("pin");
  const [secret, setSecret] = useState("");
  const [confirm, setConfirm] = useState("");
  const [typedReset, setTypedReset] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const secretOk = newSecretValid(method, secret);
  const confirmOk = secret === confirm;

  async function run(action: () => Promise<unknown>, successMessage?: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      if (successMessage) setDone(successMessage);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="w-full max-w-md rounded-xl border border-line bg-white p-6 text-center shadow-soft">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-50 text-emerald-600">
            <CheckCircle2 size={24} />
          </span>
          <h2 className="mt-3 text-lg font-bold text-ink-950">Access recovered</h2>
          <p className="mt-1 text-sm text-ink-600">{done}</p>
          <button
            type="button"
            onClick={props.onBack}
            className="mt-5 w-full rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-cyan-700"
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  const backLink = (
    <button type="button" onClick={props.onBack} className="flex items-center gap-1 text-xs font-bold text-ink-500 hover:text-ink-700">
      <ArrowLeft size={13} /> {props.unreadable ? "Back to dashboard" : "Back to unlock"}
    </button>
  );

  const newSecretFields = (
    <div className="mt-3 space-y-2">
      <MethodToggle method={method} onChange={(m) => { setMethod(m); setSecret(""); setConfirm(""); }} />
      <input
        type="password"
        inputMode={method === "pin" ? "numeric" : "text"}
        value={secret}
        onChange={(e) => setSecret(e.currentTarget.value)}
        placeholder={method === "pin" ? "New PIN (6–12 digits)" : "New password (min 12 chars)"}
        className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300"
      />
      <input
        type="password"
        inputMode={method === "pin" ? "numeric" : "text"}
        value={confirm}
        onChange={(e) => setConfirm(e.currentTarget.value)}
        placeholder={`Confirm ${method === "pin" ? "PIN" : "password"}`}
        className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300"
      />
      {secret.length > 0 && !secretOk && (
        <div className="text-[11px] font-semibold text-amber-600">
          {method === "pin" ? "PIN must be 6–12 digits." : "Password must be at least 12 characters."}
        </div>
      )}
      {confirm.length > 0 && !confirmOk && <div className="text-[11px] font-semibold text-amber-600">The two entries don’t match.</div>}
    </div>
  );

  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-md rounded-xl border border-line bg-white p-6 shadow-soft">
        <div className="flex items-center gap-3">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-white shadow-tight">
            <LifeBuoy size={22} />
          </span>
          <div className="min-w-0">
            <h2 className="text-lg font-bold text-ink-950">{props.unreadable ? `Set up ${COPY[props.scope].title} again` : `Recover ${COPY[props.scope].title}`}</h2>
            <p className="mt-0.5 text-sm text-ink-600">
              {isChat ? "Reset your workspace lock without losing any messages." : "Regain access when you've forgotten your vault PIN or password."}
            </p>
          </div>
        </div>

        {props.unreadable && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-[11px] font-semibold text-amber-800">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>
              {isChat
                ? "This device's storage key was replaced when its keys were reset, so the Secure Chat lock saved before can no longer be opened. Confirm your account password to set a new one."
                : "This device's storage key was replaced when its keys were reset, so the vault lock saved before — and the vault key it protected — can no longer be opened here. Use your recovery key, or start a fresh vault."}
            </span>
          </div>
        )}

        {isChat ? (
          <div className="mt-5">
            <div className="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-[11px] font-semibold text-emerald-800">
              <ShieldCheck size={14} className="mt-0.5 shrink-0" />
              Your messages are encrypted with your device keys, not this PIN — resetting the lock keeps every conversation intact.
            </div>
            <label className="mt-4 block text-xs font-bold text-ink-700">Confirm your account password</label>
            <input
              type="password"
              value={accountPassword}
              onChange={(e) => setAccountPassword(e.currentTarget.value)}
              placeholder="Your QGuard account password"
              className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300"
            />
            {error && <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600">{error}</div>}
            <button
              type="button"
              disabled={busy || accountPassword.length === 0}
              onClick={() => void run(() => props.onRecoverChat!(accountPassword), "Your Secure Chat lock was reset. Set a new PIN or password to continue.")}
              className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />}
              Verify &amp; reset lock
            </button>
          </div>
        ) : (
          <div className="mt-5">
            <div className="grid grid-cols-2 gap-1 rounded-lg border border-line bg-canvas p-1">
              <button
                type="button"
                onClick={() => { setVaultTab("key"); setError(null); }}
                className={`rounded-md px-3 py-1.5 text-xs font-bold transition ${vaultTab === "key" ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-white/70"}`}
              >
                I have my recovery key
              </button>
              <button
                type="button"
                onClick={() => { setVaultTab("account"); setError(null); }}
                className={`rounded-md px-3 py-1.5 text-xs font-bold transition ${vaultTab === "account" ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-white/70"}`}
              >
                I lost my recovery key
              </button>
            </div>

            {vaultTab === "key" ? (
              <div className="mt-4">
                <div className="flex items-start gap-2 rounded-lg border border-cyan-200 bg-cyan-50 p-3 text-[11px] font-semibold text-cyan-800">
                  <ShieldCheck size={14} className="mt-0.5 shrink-0" />
                  Enter your recovery key to set a new vault lock. Files encrypted before the reset stay protected by your recovery key — open them from the Vault's Recovery tools after unlocking.
                </div>
                <label className="mt-3 block text-xs font-bold text-ink-700">Recovery key</label>
                <textarea
                  value={recoveryKey}
                  onChange={(e) => setRecoveryKey(e.currentTarget.value)}
                  rows={2}
                  placeholder="XXXX-XXXX-XXXX-…"
                  className="mt-1.5 w-full resize-none rounded-lg border border-line bg-canvas px-3 py-2.5 font-mono text-sm outline-none focus:border-cyan-300"
                />
                {newSecretFields}
                {error && <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600">{error}</div>}
                <button
                  type="button"
                  disabled={busy || recoveryKey.trim().length < 8 || !secretOk || !confirmOk}
                  onClick={() => void run(() => props.onRecoverVaultWithKey!(recoveryKey.trim(), method, secret), "Your recovery key was accepted and a new vault lock is set.")}
                  className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {busy ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />}
                  Recover &amp; set new lock
                </button>
              </div>
            ) : (
              <div className="mt-4">
                <div className="flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 p-3 text-[11px] font-semibold text-rose-700">
                  <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                  Without your PIN or recovery key, files already encrypted in this vault cannot be recovered — their keys were sealed by the forgotten secret. This creates a new, empty vault. Existing <span className="font-mono">.qvault</span> files remain on disk and stay locked unless you find your recovery key.
                </div>
                <label className="mt-3 block text-xs font-bold text-ink-700">Confirm your account password</label>
                <input
                  type="password"
                  value={accountPassword}
                  onChange={(e) => setAccountPassword(e.currentTarget.value)}
                  placeholder="Your QGuard account password"
                  className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-cyan-300"
                />
                {newSecretFields}
                <label className="mt-3 block text-xs font-bold text-ink-700">Type <span className="font-mono text-rose-600">RESET</span> to confirm</label>
                <input
                  value={typedReset}
                  onChange={(e) => setTypedReset(e.currentTarget.value)}
                  placeholder="RESET"
                  className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-rose-300"
                />
                {error && <div className="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-600">{error}</div>}
                <button
                  type="button"
                  disabled={busy || accountPassword.length === 0 || !secretOk || !confirmOk || typedReset.trim().toUpperCase() !== "RESET"}
                  onClick={() => void run(() => props.onRecoverVaultWithAccount!(accountPassword, method, secret), "A new, empty vault was created with your new lock.")}
                  className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-rose-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-rose-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {busy ? <Loader2 className="animate-spin" size={16} /> : <ShieldAlert size={16} />}
                  Reset vault (start fresh)
                </button>
              </div>
            )}
          </div>
        )}

        <div className="mt-5">{backLink}</div>
      </div>
    </div>
  );
}
