import React, { useLayoutEffect, useRef, useState } from "react";
import "../auth.css";
import { AlertTriangle, ArrowLeft, ArrowRight, Cpu, KeyRound, Lock, Mail, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { useAuth } from "@/contexts/auth-context";
import { useTheme } from "@/contexts/theme-context";
import ThemeToggle from "@/components/theme/ThemeToggle";
import { CyberBackground } from "@/components/CyberBackground";
import { supabase } from "@/lib/supabase";
import {
  RESET_PASSWORD_PATH,
  clearPasswordRecovery,
  isPasswordRecoveryPending,
  passwordRecoveryLinkError,
} from "@/lib/password-recovery";

const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;

/**
 * Password recovery, both halves:
 *  - no recovery session  -> request a reset link by email;
 *  - opened from a recovery link (Forgot password, or an administrator's
 *    reset from the Owner Admin Users console) -> set a new password, then
 *    every session is signed out so the old credentials are dead everywhere.
 */
export default function ResetPasswordPage() {
  const { session, loading } = useAuth();
  const { mode, theme, setMode } = useTheme();
  const isLightTheme = theme === "light";
  const restoreModeRef = useRef(mode);
  const [recovery] = useState(() => isPasswordRecoveryPending());
  const [linkError] = useState(() => passwordRecoveryLinkError());
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<"requested" | "updated" | null>(null);

  useLayoutEffect(() => {
    setMode("light");
    return () => setMode(restoreModeRef.current);
  }, [setMode]);

  const view: "set" | "verifying" | "expired" | "request" = recovery
    ? session ? "set" : loading ? "verifying" : "expired"
    : "request";

  const requestLink = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const { error: requestError } = await supabase.auth.resetPasswordForEmail(email.trim(), {
      redirectTo: `${window.location.origin}${RESET_PASSWORD_PATH}`,
    });
    setBusy(false);
    if (requestError) {
      setError(/rate limit/i.test(requestError.message)
        ? "Too many reset emails were requested recently. Please wait a few minutes and try again."
        : requestError.message);
      return;
    }
    // Same answer whether or not the account exists (no account enumeration).
    setDone("requested");
  };

  const setNewPassword = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      setError(`Use ${PASSWORD_MIN}–${PASSWORD_MAX} characters.`);
      return;
    }
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    const { error: updateError } = await supabase.auth.updateUser({ password });
    if (updateError) {
      setBusy(false);
      setError(updateError.message);
      return;
    }
    clearPasswordRecovery();
    // End every session (including this recovery one) so the old password's
    // sessions die too; the user signs in with the new password.
    await supabase.auth.signOut({ scope: "global" }).catch(() => undefined);
    setBusy(false);
    setDone("updated");
  };

  return (
    <div className={`qguard-home qc-page qc-page-gold ${isLightTheme ? "qguard-home--light qc-page-home-light" : ""}`}>
      <CyberBackground variant={isLightTheme ? "light" : "dark"} />
      <div className="qc-hex-grid" />
      <div className="qc-radial-glow" />

      <header className="qc-auth-nav qc-in-1">
        <Link to="/" className="qc-auth-brand">
          <img src="/NEW_LOGO.png" alt="Qguard Helix logo" className="qc-auth-logo-video" />
          <span className="qc-auth-brand-copy">
            <span className="qc-auth-brand-title">Qguard Helix</span>
            <span className="qc-auth-brand-subtitle">Quantum Defense</span>
          </span>
        </Link>
        <div className="qc-auth-nav-actions">
          <ThemeToggle compact showSystem={false} />
          <Link to="/login" className="qc-auth-nav-link">
            <ArrowLeft size={15} />
            Sign in
          </Link>
        </div>
      </header>

      <main className="qc-login-shell">
        <section className="qc-login-hero qc-in-2" aria-labelledby="reset-title">
          <div className="qc-login-kicker">
            <span className="qc-status-dot" />
            Credential Recovery
          </div>
          <h1 id="reset-title" className="qc-auth-title">
            Reset <span>Password</span>
          </h1>
          <p className="qc-auth-lede">
            Recovery links are single-use and short-lived. After you set a new password, every session on every device is signed out.
          </p>
        </section>

        <section className="qc-login-panel" aria-label="Password reset">
          <div className="qc-card qc-in-3">
            <div className="qc-logo-wrap">
              <div className="qc-logo-icon">
                <KeyRound size={20} />
              </div>
              <span className="qc-logo-text">QGUARD</span>
            </div>

            {error && (
              <div className="qc-alert qc-alert-error" role="alert">
                <AlertTriangle size={14} className="text-[var(--qg-red)] shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {done === "updated" ? (
              <>
                <h2 className="qc-heading">Password updated</h2>
                <div className="qc-alert qc-alert-success">
                  <ShieldCheck size={14} className="text-[var(--qg-green)] shrink-0" />
                  <span>Your new password is set and all previous sessions were signed out.</span>
                </div>
                <Link to="/login" className="qc-btn qc-btn-cyan">Sign in <ArrowRight size={15} /></Link>
              </>
            ) : done === "requested" ? (
              <>
                <h2 className="qc-heading">Check your email</h2>
                <div className="qc-alert qc-alert-success">
                  <Mail size={14} className="text-[var(--qg-green)] shrink-0" />
                  <span>If an account exists for {email.trim()}, a reset link is on its way. It expires shortly and works once.</span>
                </div>
                <Link to="/login" className="qc-btn qc-btn-ghost">Back to sign in</Link>
              </>
            ) : view === "verifying" ? (
              <>
                <h2 className="qc-heading">Verifying link…</h2>
                <p className="qc-subtitle"><Cpu size={14} className="mr-2 inline animate-spin" />Validating your recovery link.</p>
              </>
            ) : view === "set" ? (
              <>
                <h2 className="qc-heading">Choose a new password</h2>
                <p className="qc-subtitle">For {session?.user?.email}. {PASSWORD_MIN}–{PASSWORD_MAX} characters.</p>
                <form onSubmit={setNewPassword} className="qc-form">
                  <div>
                    <label className="qc-field-label" htmlFor="reset-new">New password</label>
                    <div className="qc-field-wrap">
                      <Lock size={14} className="qc-field-icon" />
                      <input id="reset-new" type="password" autoComplete="new-password" required minLength={PASSWORD_MIN} maxLength={PASSWORD_MAX} value={password} onChange={(e) => setPassword(e.target.value)} className="qc-input" />
                    </div>
                  </div>
                  <div>
                    <label className="qc-field-label" htmlFor="reset-confirm">Confirm password</label>
                    <div className="qc-field-wrap">
                      <Lock size={14} className="qc-field-icon" />
                      <input id="reset-confirm" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} className="qc-input" />
                    </div>
                  </div>
                  <button type="submit" disabled={busy} className="qc-btn qc-btn-cyan qc-btn-shimmer">
                    {busy ? <Cpu size={16} className="animate-spin" /> : <>Update password <ArrowRight size={15} /></>}
                  </button>
                </form>
              </>
            ) : (
              <>
                <h2 className="qc-heading">{view === "expired" || linkError ? "Link expired" : "Forgot password"}</h2>
                <p className="qc-subtitle">
                  {view === "expired" || linkError
                    ? `${linkError || "This reset link is invalid, expired or already used."} Request a new one below.`
                    : "Enter your account email and we will send you a single-use reset link."}
                </p>
                <form onSubmit={requestLink} className="qc-form">
                  <div>
                    <label className="qc-field-label" htmlFor="reset-email">Email address</label>
                    <div className="qc-field-wrap">
                      <Mail size={14} className="qc-field-icon" />
                      <input id="reset-email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Enter your email" className="qc-input" />
                    </div>
                  </div>
                  <button type="submit" disabled={busy} className="qc-btn qc-btn-cyan qc-btn-shimmer">
                    {busy ? <Cpu size={16} className="animate-spin" /> : <>Send reset link <ArrowRight size={15} /></>}
                  </button>
                  <p className="qc-card-footer">
                    Remembered it? <Link to="/login" className="qc-card-link">Sign in</Link>
                  </p>
                </form>
              </>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
