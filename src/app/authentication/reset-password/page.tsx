import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Check, Loader2, Lock, Mail, MailCheck, ShieldCheck, X } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { ButtonDot } from "@/pages/landing-chars";
import { supabase } from "@/lib/supabase";
import {
  RESET_PASSWORD_PATH,
  clearPasswordRecovery,
  isPasswordRecoveryPending,
  passwordRecoveryLinkError,
} from "@/lib/password-recovery";
import { AuthAlert, AuthCard, AuthField, AuthShell } from "../AuthShell";

const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;

/**
 * Password recovery, both halves:
 *  - no recovery session  -> request a reset link by email ("Forgot password");
 *  - opened from a recovery link (Forgot password, or an administrator's
 *    reset from the Owner Admin Users console) -> set a new password, then
 *    every session is signed out so the old credentials are dead everywhere.
 */
export default function ResetPasswordPage() {
  const { session, loading } = useAuth();
  const [recovery] = useState(() => isPasswordRecoveryPending());
  const [linkError] = useState(() => passwordRecoveryLinkError());
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<"requested" | "updated" | null>(null);

  const view: "set" | "verifying" | "expired" | "request" = recovery
    ? session ? "set" : loading ? "verifying" : "expired"
    : "request";

  const lengthOk = password.length >= PASSWORD_MIN && password.length <= PASSWORD_MAX;
  const matchState = confirm.length === 0 ? "idle" : confirm === password ? "match" : "mismatch";

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
    if (!lengthOk) {
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

  const submitLabel = (idle: string, working: string) =>
    busy ? (
      <>
        <Loader2 className="lp-auth__spin" aria-hidden="true" />
        {working}
      </>
    ) : (
      <>
        {idle}
        <ButtonDot />
      </>
    );

  let card: React.ReactNode;

  if (done === "updated") {
    card = (
      <AuthCard kicker="Password updated" heading="You're all set" sub="Sign in again with your new password.">
        <div className="lp-auth__sent">
          <span className="lp-auth__sent-icon" aria-hidden="true">
            <ShieldCheck />
          </span>
          <AuthAlert tone="success">Your new password is set and every previous session was signed out.</AuthAlert>
        </div>
        <Link to="/login" viewTransition className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot">
          Continue to sign in
          <ButtonDot />
        </Link>
      </AuthCard>
    );
  } else if (done === "requested") {
    card = (
      <AuthCard kicker="Link requested" heading="Check your inbox" sub="The link expires shortly and works once.">
        <div className="lp-auth__sent">
          <span className="lp-auth__sent-icon" aria-hidden="true">
            <MailCheck />
          </span>
          <AuthAlert tone="success">
            If an account exists for <strong>{email.trim()}</strong>, a reset link is on its way.
          </AuthAlert>
        </div>
        <Link to="/login" viewTransition className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot">
          Back to sign in
          <ButtonDot />
        </Link>
        <p className="lp-auth__card-foot">
          Wrong address?{" "}
          <button type="button" className="lp-link lp-auth__text-btn" onClick={() => setDone(null)}>
            Use a different email
          </button>
        </p>
      </AuthCard>
    );
  } else if (view === "verifying") {
    card = (
      <AuthCard kicker="Recovery link" heading="Verifying link…" sub="Validating your single-use recovery link.">
        <p className="lp-auth__card-sub" role="status">
          <Loader2 className="lp-auth__spin" aria-hidden="true" /> This only takes a moment.
        </p>
      </AuthCard>
    );
  } else if (view === "set") {
    card = (
      <AuthCard
        kicker="Set new password"
        heading="Choose a new password"
        sub={`For ${session?.user?.email ?? "your account"}. ${PASSWORD_MIN}–${PASSWORD_MAX} characters.`}
      >
        {error && <AuthAlert tone="error">{error}</AuthAlert>}
        <form onSubmit={setNewPassword} className="lp-auth__form" aria-busy={busy}>
          <AuthField
            id="reset-new"
            label="New password"
            icon={Lock}
            revealable
            required
            minLength={PASSWORD_MIN}
            maxLength={PASSWORD_MAX}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={`At least ${PASSWORD_MIN} characters`}
            hint={
              password.length > 0 ? (
                <p className={`lp-auth__match lp-auth__match--${lengthOk ? "match" : "mismatch"}`} aria-live="polite">
                  {lengthOk ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
                  {lengthOk ? "Length looks good" : `Use ${PASSWORD_MIN}–${PASSWORD_MAX} characters`}
                </p>
              ) : null
            }
          />
          <AuthField
            id="reset-confirm"
            label="Confirm password"
            icon={Lock}
            revealable
            required
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Re-enter your new password"
            aria-invalid={matchState === "mismatch"}
            hint={
              matchState !== "idle" ? (
                <p className={`lp-auth__match lp-auth__match--${matchState}`} aria-live="polite">
                  {matchState === "match" ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
                  {matchState === "match" ? "Passwords match" : "Passwords don't match yet"}
                </p>
              ) : null
            }
          />
          <button type="submit" disabled={busy} className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot lp-auth__submit">
            {submitLabel("Update password", "Updating password…")}
          </button>
        </form>
      </AuthCard>
    );
  } else {
    const expired = view === "expired" || Boolean(linkError);
    const reason = (linkError || "This reset link is invalid, expired or already used.").trim().replace(/([^.!?])$/, "$1.");
    card = (
      <AuthCard
        kicker={expired ? "Link expired" : "Forgot password"}
        heading={expired ? "Request a new link" : "Reset your password"}
        sub={
          expired
            ? `${reason} Request a new one below.`
            : "Enter your account email and we'll send you a single-use reset link."
        }
      >
        {error && <AuthAlert tone="error">{error}</AuthAlert>}
        <form onSubmit={requestLink} className="lp-auth__form" aria-busy={busy}>
          <AuthField
            id="reset-email"
            label="Work email"
            icon={Mail}
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
          />
          <button type="submit" disabled={busy} className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot lp-auth__submit">
            {submitLabel("Send reset link", "Sending link…")}
          </button>
        </form>
        <p className="lp-auth__card-foot">
          Remembered it?{" "}
          <Link to="/login" viewTransition className="lp-link">
            Sign in
          </Link>
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthShell mode="reset" nextQuery="">
      {card}
    </AuthShell>
  );
}
