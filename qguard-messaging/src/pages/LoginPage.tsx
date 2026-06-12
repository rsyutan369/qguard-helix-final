import { FormEvent, useState } from "react";
import { KeyRound, LockKeyhole, RefreshCcw, ShieldCheck } from "lucide-react";

interface LoginPageProps {
  loading: boolean;
  error: string | null;
  notice: string | null;
  pendingMfa: { email: string; factorName: string } | null;
  onSignIn: (email: string, password: string) => Promise<boolean>;
  onVerifyMfa: (code: string) => Promise<boolean>;
  onCancelMfa: () => Promise<void>;
  onSignUp: (email: string, password: string, name: string) => Promise<boolean>;
  onResendVerification: (email: string) => Promise<boolean>;
  onClearError: () => void;
}

function toVisibleError(message: string | null): string | null {
  if (!message) return null;

  if (/secure sign in timed out|supabase request timed out|auth service/i.test(message)) {
    return "Supabase Auth is not responding. Your Supabase project may be resource constrained; please wait for the project to recover or upgrade/optimize it, then try again.";
  }

  if (message.includes("QGUARD_SUPABASE_CONFIG_REQUIRED")) {
    return "Registration is not connected to a Supabase project. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in the workspace .env or .env.example, then restart QGuard Messaging.";
  }

  const internalTerms = ["supabase", "vite_", "environment", "jwt", "token", "auth_sync_session", "auth session", "configured"];
  if (internalTerms.some((term) => message.toLowerCase().includes(term))) {
    return "We could not complete sign in right now. Please try again later.";
  }

  if (message.toLowerCase().includes("invalid login credentials")) {
    return "Email or password is incorrect.";
  }

  return message;
}

export default function LoginPage({ loading, error, notice, pendingMfa, onSignIn, onVerifyMfa, onCancelMfa, onSignUp, onResendVerification, onClearError }: LoginPageProps) {
  const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [email, setEmail] = useState("");
  const [lastVerificationEmail, setLastVerificationEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const visibleError = toVisibleError(error);
  const verificationEmail = email.trim() || lastVerificationEmail;

  async function submit(event: FormEvent) {
    event.preventDefault();
    onClearError();
    if (pendingMfa) {
      await onVerifyMfa(mfaCode);
      return;
    }
    const normalizedEmail = email.trim();
    if (mode === "sign-in") {
      await onSignIn(normalizedEmail, password);
    } else {
      const registered = await onSignUp(normalizedEmail, password, name.trim());
      if (registered) {
        setLastVerificationEmail(normalizedEmail);
        setEmail(normalizedEmail);
        setName("");
        setPassword("");
        setMode("sign-in");
      }
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-6">
      <section className="shell-card grid w-full max-w-4xl grid-cols-[1fr_380px] overflow-hidden">
        <div className="bg-violet-600 p-8 text-white">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-white/15">
            <ShieldCheck size={26} />
          </div>
          <h1 className="mt-8 text-3xl font-bold tracking-tight">QGuard Messaging</h1>
          <p className="mt-3 max-w-sm text-sm leading-6 text-violet-100">
            Quantum-ready secure messaging for encrypted chat, trusted devices, file vaults, voice notes, and safety verification.
          </p>
          <div className="mt-8 grid gap-3 text-sm text-violet-50">
            <div className="flex items-center gap-2"><LockKeyhole size={16} /> End-to-end encrypted conversations</div>
            <div className="flex items-center gap-2"><KeyRound size={16} /> Hybrid classical and post-quantum protection</div>
            <div className="flex items-center gap-2"><RefreshCcw size={16} /> Forward secrecy with continuous key rotation</div>
            <div className="flex items-center gap-2"><ShieldCheck size={16} /> Device trust, safety numbers, and vault security</div>
          </div>
        </div>

        <form onSubmit={submit} className="bg-white p-7">
          <h2 className="text-xl font-bold text-ink-950">{pendingMfa ? "Verify MFA" : mode === "sign-in" ? "Sign in" : "Create account"}</h2>
          <p className="mt-1 text-sm text-ink-600">
            {pendingMfa ? pendingMfa.factorName : mode === "sign-in" ? "Use your QGuard account to continue." : "Create your QGuard Messaging account."}
          </p>

          {visibleError && (
            <div className="mt-4 rounded-lg border border-rose-100 bg-rose-50 p-3 text-sm font-semibold text-rose-600">
              {visibleError}
            </div>
          )}

          {notice && (
            <div className="mt-4 rounded-lg border border-emerald-100 bg-emerald-50 p-3 text-sm font-semibold text-emerald-600">
              {notice}
            </div>
          )}

          {pendingMfa ? (
            <label className="mt-5 block text-sm font-semibold text-ink-700">
              Authenticator code
              <input
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 text-center font-mono text-lg tracking-[0.35em] outline-none focus:border-violet-300"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
              />
            </label>
          ) : mode === "sign-up" && (
            <label className="mt-5 block text-sm font-semibold text-ink-700">
              Full name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-violet-300"
                autoComplete="name"
                required
              />
            </label>
          )}

          {!pendingMfa && <label className="mt-5 block text-sm font-semibold text-ink-700">
            Email
            <input
              type="email"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                if (event.target.value.trim()) setLastVerificationEmail(event.target.value.trim());
              }}
              className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-violet-300"
              autoComplete="email"
              required
            />
          </label>}

          {!pendingMfa && <label className="mt-4 block text-sm font-semibold text-ink-700">
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-2 w-full rounded-lg border border-line bg-canvas px-3 py-2 outline-none focus:border-violet-300"
              autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
              minLength={8}
              required
            />
          </label>}

          <button
            type="submit"
            disabled={loading}
            className="mt-6 w-full rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Validating..." : pendingMfa ? "Verify and continue" : mode === "sign-in" ? "Sign in securely" : "Register securely"}
          </button>

          {pendingMfa ? (
            <button
              type="button"
              onClick={onCancelMfa}
              className="mt-4 w-full text-sm font-semibold text-ink-600"
            >
              Cancel sign in
            </button>
          ) : <button
            type="button"
            onClick={() => {
              onClearError();
              setMode((current) => current === "sign-in" ? "sign-up" : "sign-in");
            }}
            className="mt-4 w-full text-sm font-semibold text-violet-600"
          >
            {mode === "sign-in" ? "Need an account? Register" : "Already registered? Sign in"}
          </button>}

          {!pendingMfa && mode === "sign-in" && (
            <button
              type="button"
              disabled={loading || !verificationEmail}
              onClick={() => onResendVerification(verificationEmail)}
              className="mt-3 w-full text-sm font-semibold text-violet-600 hover:text-violet-700 disabled:cursor-not-allowed disabled:text-ink-500 disabled:opacity-50"
            >
              Resend verification email
            </button>
          )}
        </form>
      </section>
    </div>
  );
}
