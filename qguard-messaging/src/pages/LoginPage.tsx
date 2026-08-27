import { FormEvent, useState } from "react";
import { Atom, FileLock2, Fingerprint, LockKeyhole, RefreshCcw, ShieldCheck } from "lucide-react";

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
  onResetPassword: (email: string) => Promise<boolean>;
  onClearError: () => void;
}

function toVisibleError(message: string | null): string | null {
  if (!message) return null;

  // The provider's shared mail service is rate-limited; surface a calm, branded
  // message instead of the raw "email rate limit exceeded" string.
  if (/email rate limit|rate limit exceeded|over_email_send_rate_limit|too many emails/i.test(message)) {
    return "We've sent too many emails in a short window. Please wait a few minutes, then try again.";
  }

  if (/secure sign in timed out|supabase request timed out|auth service/i.test(message)) {
    return "Supabase Auth is not responding. Your Supabase project may be resource constrained; please wait for the project to recover or upgrade/optimize it, then try again.";
  }

  if (message.includes("QGUARD_SUPABASE_CONFIG_REQUIRED")) {
    return "Registration is not connected to a Supabase project. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in the workspace .env or .env.example, then restart Qguard Helix.";
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

// The brand mark sits inside a soft radial glow with a slow-rotating neon ring
// that echoes the swirling light in the QGuard logo — the one signature moment
// of the screen. Motion is disabled under prefers-reduced-motion (see styles).
function LogoMark({ size }: { size: number }) {
  return (
    <div className="qg-halo" style={{ width: size, height: size }}>
      <span className="qg-halo-glow" aria-hidden />
      <span className="qg-halo-ring" aria-hidden />
      <img src="/Android_Logo.jpg" alt="QGuard Helix" className="qg-halo-img" />
    </div>
  );
}

const inputClass =
  "mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-3 text-[15px] text-white placeholder-white/25 outline-none transition focus:border-violet-400/70 focus:bg-white/[0.06] focus:ring-2 focus:ring-violet-500/25";
const labelClass = "block text-[13px] font-semibold text-white/70";

export default function LoginPage({ loading, error, notice, pendingMfa, onSignIn, onVerifyMfa, onCancelMfa, onSignUp, onResendVerification, onResetPassword, onClearError }: LoginPageProps) {
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

  const heading = pendingMfa ? "Verify identity" : mode === "sign-in" ? "Welcome back" : "Create account";
  const subheading = pendingMfa
    ? pendingMfa.factorName
    : mode === "sign-in"
      ? "Sign in to your quantum-safe workspace."
      : "Set up your quantum-safe messaging & vault.";

  return (
    <div className="qg-login mobile-safe-top mobile-safe-bottom relative flex min-h-[100dvh] items-center justify-center overflow-hidden px-4 py-8 md:px-6">
      {/* Ambient neon atmosphere — the logo's palette, blurred into the dark. */}
      <div className="pointer-events-none absolute inset-0 -z-10" aria-hidden>
        <div className="qg-orb qg-orb-violet" />
        <div className="qg-orb qg-orb-blue" />
        <div className="qg-grid" />
      </div>

      <section className="relative w-full max-w-[440px] md:max-w-4xl">
        <div className="qg-shell grid grid-cols-1 overflow-hidden rounded-[26px] md:grid-cols-[1.05fr_400px]">
          {/* Brand hero — desktop only; phones get the compact header in the form. */}
          <aside className="relative hidden flex-col justify-between overflow-hidden p-9 md:flex">
            <div className="qg-hero-veil pointer-events-none absolute inset-0" aria-hidden />
            <div className="relative">
              <LogoMark size={92} />
              <div className="mt-8 text-[11px] font-semibold uppercase tracking-[0.34em] text-violet-300/80">
                Post-quantum secure collaboration
              </div>
              <h1 className="mt-3 text-[34px] font-bold leading-[1.05] tracking-tight text-white">
                QGuard Helix
                <span className="mt-1 block bg-gradient-to-r from-violet-300 to-sky-300 bg-clip-text text-transparent">
                  Messaging &amp; Vault
                </span>
              </h1>
              <p className="mt-4 max-w-sm text-[14px] leading-6 text-white/55">
                Encrypted messaging, calls, and a zero-knowledge file vault —
                engineered to stay private against tomorrow&apos;s quantum threats.
              </p>

              <div className="mt-8 grid gap-3.5 text-[13.5px] text-white/70">
                <div className="flex items-start gap-3"><LockKeyhole size={16} className="mt-0.5 shrink-0 text-violet-300" /> End-to-end encrypted chat, calls &amp; file vault</div>
                <div className="flex items-start gap-3"><Atom size={16} className="mt-0.5 shrink-0 text-sky-300" /> Hybrid key exchange · X25519 + ML-KEM-1024 (FIPS 203)</div>
                <div className="flex items-start gap-3"><Fingerprint size={16} className="mt-0.5 shrink-0 text-violet-300" /> Dual-signature device identity · Ed25519 + ML-DSA (FIPS 204)</div>
                <div className="flex items-start gap-3"><RefreshCcw size={16} className="mt-0.5 shrink-0 text-sky-300" /> Forward secrecy with continuous signed-prekey rotation</div>
                <div className="flex items-start gap-3"><FileLock2 size={16} className="mt-0.5 shrink-0 text-violet-300" /> Zero-knowledge vault · AES-256-GCM key wrapping</div>
                <div className="flex items-start gap-3"><ShieldCheck size={16} className="mt-0.5 shrink-0 text-sky-300" /> Device trust, safety-number verification &amp; audit</div>
              </div>
            </div>

            <div className="relative mt-9 flex flex-wrap gap-2">
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] font-semibold text-white/60">Harvest-now, decrypt-later resistant</span>
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] font-semibold text-white/60">NIST FIPS 203 &amp; 204</span>
            </div>
          </aside>

          {/* Auth panel */}
          <form onSubmit={submit} className="qg-form relative p-7 sm:p-8">
            {/* Compact brand — phones only. */}
            <div className="mb-7 flex flex-col items-center text-center md:hidden">
              <LogoMark size={84} />
              <div className="mt-4 text-[19px] font-bold tracking-wide text-white">QGuard Helix</div>
              {/* Sized to hold the icon and the full line together at 412px:
                  at 11px/0.18em the row overflowed and broke, which left the
                  shield stranded on a line of its own. */}
              <div className="mt-1.5 flex items-center justify-center gap-1.5 text-center text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-300/90">
                <ShieldCheck size={12} className="shrink-0" />
                <span>Quantum-safe · End-to-end encrypted</span>
              </div>
            </div>

            <h2 className="text-[22px] font-bold tracking-tight text-white">{heading}</h2>
            <p className="mt-1.5 text-[13.5px] text-white/50">{subheading}</p>

            {visibleError && (
              <div className="mt-5 rounded-xl border border-rose-400/25 bg-rose-500/10 p-3 text-[13px] font-semibold text-rose-200">
                {visibleError}
              </div>
            )}

            {notice && (
              <div className="mt-5 rounded-xl border border-emerald-400/25 bg-emerald-500/10 p-3 text-[13px] font-semibold text-emerald-200">
                {notice}
              </div>
            )}

            {pendingMfa ? (
              <label className="mt-6 block">
                <span className={labelClass}>Authenticator code</span>
                <input
                  value={mfaCode}
                  onChange={(event) => setMfaCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  className={`${inputClass} text-center font-mono text-lg tracking-[0.4em]`}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
              </label>
            ) : mode === "sign-up" && (
              <label className="mt-6 block">
                <span className={labelClass}>Full name</span>
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  className={inputClass}
                  autoComplete="name"
                  required
                />
              </label>
            )}

            {!pendingMfa && (
              <label className="mt-5 block">
                <span className={labelClass}>Email</span>
                <input
                  type="email"
                  value={email}
                  onChange={(event) => {
                    setEmail(event.target.value);
                    if (event.target.value.trim()) setLastVerificationEmail(event.target.value.trim());
                  }}
                  className={inputClass}
                  autoComplete="email"
                  required
                />
              </label>
            )}

            {!pendingMfa && (
              <div className="mt-4">
                <div className="flex items-center justify-between gap-2">
                  <label htmlFor="qg-login-password" className={labelClass}>Password</label>
                  {mode === "sign-in" && (
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => {
                        onClearError();
                        void onResetPassword(verificationEmail);
                      }}
                      className="text-[12.5px] font-semibold text-violet-300 transition hover:text-violet-200 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <input
                  id="qg-login-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className={inputClass}
                  autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
                  minLength={8}
                  required
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="qg-cta mt-7 flex w-full items-center justify-center gap-2 rounded-xl px-4 py-3.5 text-[14px] font-bold text-white transition disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Validating…" : pendingMfa ? "Verify and continue" : mode === "sign-in" ? "Sign in securely" : "Create account"}
            </button>

            {pendingMfa ? (
              <button
                type="button"
                onClick={onCancelMfa}
                className="mt-4 w-full text-[13px] font-semibold text-white/50 transition hover:text-white/80"
              >
                Cancel sign in
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  onClearError();
                  setMode((current) => (current === "sign-in" ? "sign-up" : "sign-in"));
                }}
                className="mt-4 w-full text-[13px] font-semibold text-violet-300 transition hover:text-violet-200"
              >
                {mode === "sign-in" ? "Need an account? Register" : "Already registered? Sign in"}
              </button>
            )}

            {!pendingMfa && mode === "sign-in" && (
              <button
                type="button"
                disabled={loading || !verificationEmail}
                onClick={() => onResendVerification(verificationEmail)}
                className="mt-2.5 w-full text-[13px] font-semibold text-white/45 transition hover:text-white/70 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Resend verification email
              </button>
            )}

            {/* Trust row — phones only; the desktop hero carries the badges. */}
            <div className="mt-7 flex flex-wrap justify-center gap-2 md:hidden">
              {["ML-KEM-1024", "Zero-knowledge vault", "FIPS 203/204"].map((chip) => (
                <span key={chip} className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[10.5px] font-semibold text-white/55">
                  {chip}
                </span>
              ))}
            </div>
          </form>
        </div>
      </section>

      <style>{`
        .qg-login {
          background:
            radial-gradient(1200px 700px at 15% -10%, #1a1140 0%, transparent 55%),
            radial-gradient(1000px 700px at 110% 120%, #10203f 0%, transparent 50%),
            #070512;
        }
        .qg-grid {
          position: absolute; inset: 0;
          background-image:
            linear-gradient(rgba(139,92,246,0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,92,246,0.05) 1px, transparent 1px);
          background-size: 44px 44px;
          -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 0%, transparent 80%);
          mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 0%, transparent 80%);
        }
        .qg-orb { position: absolute; border-radius: 9999px; filter: blur(90px); opacity: 0.5; }
        .qg-orb-violet { width: 460px; height: 460px; left: -120px; top: -140px; background: radial-gradient(circle, rgba(124,58,237,0.85), transparent 70%); }
        .qg-orb-blue   { width: 480px; height: 480px; right: -160px; bottom: -180px; background: radial-gradient(circle, rgba(56,120,255,0.7), transparent 70%); }

        .qg-shell {
          border: 1px solid rgba(139,92,246,0.18);
          background: linear-gradient(180deg, rgba(23,18,48,0.72), rgba(12,9,28,0.82));
          box-shadow: 0 40px 120px -40px rgba(88,42,214,0.55), inset 0 1px 0 rgba(255,255,255,0.05);
          -webkit-backdrop-filter: blur(22px);
          backdrop-filter: blur(22px);
        }
        .qg-hero-veil {
          background:
            radial-gradient(600px 380px at 20% 0%, rgba(124,58,237,0.28), transparent 60%),
            radial-gradient(500px 400px at 90% 100%, rgba(56,120,255,0.20), transparent 60%);
        }
        .qg-form { border-left: 1px solid rgba(255,255,255,0.06); }
        @media (max-width: 767px) { .qg-form { border-left: none; } }

        .qg-cta {
          background: linear-gradient(100deg, #7c3aed 0%, #6366f1 50%, #3b82f6 100%);
          box-shadow: 0 14px 34px -10px rgba(124,58,237,0.75), inset 0 1px 0 rgba(255,255,255,0.25);
        }
        .qg-cta:hover:not(:disabled) {
          box-shadow: 0 18px 44px -10px rgba(124,58,237,0.9), inset 0 1px 0 rgba(255,255,255,0.3);
          filter: brightness(1.06);
        }
        .qg-cta:active:not(:disabled) { transform: translateY(1px); }

        .qg-halo { position: relative; display: grid; place-items: center; }
        .qg-halo-img {
          position: relative; z-index: 2; width: 78%; height: 78%; object-fit: contain;
          border-radius: 22%;
          box-shadow: 0 8px 30px -6px rgba(76,124,255,0.5);
        }
        .qg-halo-glow {
          position: absolute; inset: -14%; z-index: 0; border-radius: 9999px;
          background: radial-gradient(circle, rgba(139,92,246,0.6), rgba(79,124,255,0.28) 45%, transparent 70%);
          filter: blur(12px);
          animation: qg-pulse 6s ease-in-out infinite;
        }
        .qg-halo-ring {
          position: absolute; inset: -5%; z-index: 1; border-radius: 9999px;
          background: conic-gradient(from 0deg, transparent 0deg, rgba(139,92,246,0.95) 70deg, rgba(56,189,248,0.9) 150deg, transparent 230deg);
          -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
          mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
          animation: qg-spin 14s linear infinite;
        }
        @keyframes qg-spin { to { transform: rotate(360deg); } }
        @keyframes qg-pulse { 0%,100% { opacity: 0.6; transform: scale(0.97); } 50% { opacity: 1; transform: scale(1.05); } }
        @media (prefers-reduced-motion: reduce) {
          .qg-halo-ring, .qg-halo-glow { animation: none; }
        }
      `}</style>
    </div>
  );
}
