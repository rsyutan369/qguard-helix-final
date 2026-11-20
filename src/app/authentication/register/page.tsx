"use client";

import React, { useMemo, useState } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { Check, Loader2, Lock, Mail, MailCheck, X } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { PUBLIC_SCAN_PATH, safeAuthDestination } from "@/lib/public-scan-auth";
import { ButtonDot } from "@/pages/landing-chars";
import { AuthAlert, AuthCard, AuthDivider, AuthField, AuthShell, GoogleButton } from "../AuthShell";

const MIN_LENGTH = 6;
const STRENGTH_LABELS = ["Too short", "Weak", "Fair", "Good", "Strong"] as const;

/** 0–4, from what was actually typed: length plus character variety. */
function passwordStrength(value: string) {
  if (value.length < MIN_LENGTH) return 0;
  let score = 1;
  if (value.length >= 10) score += 1;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
  if (classes >= 2) score += 1;
  if (classes >= 3 && value.length >= 12) score += 1;
  return Math.min(4, score);
}

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const { session, signUp, signInWithGoogle } = useAuth();
  const [searchParams] = useSearchParams();
  const next = safeAuthDestination(searchParams.get("next")) ??
    (import.meta.env.VITE_SITE_EDITION === 'public' ? PUBLIC_SCAN_PATH : null);
  const forPublicScan = next === PUBLIC_SCAN_PATH;
  const nextQuery = next ? `?next=${encodeURIComponent(next)}` : "";

  const strength = useMemo(() => passwordStrength(password), [password]);
  const matchState = confirmPassword.length === 0 ? "idle" : confirmPassword === password ? "match" : "mismatch";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    if (password.length < MIN_LENGTH) {
      setIsLoading(false);
      setError(`Your password must be at least ${MIN_LENGTH} characters.`);
      return;
    }
    if (password !== confirmPassword) {
      setIsLoading(false);
      setError("The two passwords don't match.");
      return;
    }

    try {
      const { error } = await signUp(email, password, forPublicScan);
      if (error) {
        setIsLoading(false);
        let msg = error.message || "Registration failed. Please try again.";
        if (msg.includes("already registered")) msg = "An account with this email already exists. Try signing in instead.";
        setError(msg);
        return;
      }
      setIsLoading(false);
      setSentTo(email);
    } catch (err: any) {
      setIsLoading(false);
      setError(err.message || "Something went wrong. Please try again.");
    }
  };

  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const { error } = await signInWithGoogle(forPublicScan);
      if (error) {
        setIsLoading(false);
        setError("Google sign-up failed: " + error.message);
        return;
      }
      setIsLoading(false);
    } catch (err: any) {
      setIsLoading(false);
      setError("Google sign-up failed: " + err.message);
    }
  };

  if (forPublicScan && session) return <Navigate to={PUBLIC_SCAN_PATH} replace />;

  if (sentTo) {
    return (
      <AuthShell mode="register" nextQuery={nextQuery}>
        <AuthCard kicker="Account created" heading="Check your inbox" sub="One last step before you can sign in.">
          <div className="lp-auth__sent">
            <span className="lp-auth__sent-icon" aria-hidden="true">
              <MailCheck />
            </span>
            <AuthAlert tone="success">
              We sent a verification link to <strong>{sentTo}</strong>. Open it to activate your account, then sign in.
            </AuthAlert>
          </div>
          <Link to={`/login${nextQuery}`} viewTransition className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot">
            Continue to sign in
            <ButtonDot />
          </Link>
          <p className="lp-auth__card-foot">
            Wrong address?{" "}
            <button type="button" className="lp-link lp-auth__text-btn" onClick={() => setSentTo(null)}>
              Use a different email
            </button>
          </p>
        </AuthCard>
      </AuthShell>
    );
  }

  return (
    <AuthShell mode="register" nextQuery={nextQuery}>
      <AuthCard kicker="Create account" heading="Set up your access" sub="It takes a minute. We'll verify your email before your first sign-in.">
        {error && <AuthAlert tone="error">{error}</AuthAlert>}

        <form onSubmit={handleSubmit} className="lp-auth__form" aria-busy={isLoading}>
          <AuthField
            id="register-email"
            label="Work email"
            icon={Mail}
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
          />

          <AuthField
            id="register-password"
            label="Password"
            icon={Lock}
            revealable
            required
            minLength={MIN_LENGTH}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={`At least ${MIN_LENGTH} characters`}
            aria-describedby="register-strength"
            hint={
              <div
                id="register-strength"
                className="lp-auth__strength"
                data-level={password.length === 0 ? "none" : strength}
                aria-live="polite"
              >
                <div className="lp-auth__strength-bars" aria-hidden="true">
                  {[1, 2, 3, 4].map((step) => (
                    <i key={step} data-on={strength >= step ? "" : undefined} />
                  ))}
                </div>
                <span>{password.length === 0 ? "Use 10+ characters with a mix of letters, numbers and symbols." : STRENGTH_LABELS[strength]}</span>
              </div>
            }
          />

          <AuthField
            id="register-confirm"
            label="Confirm password"
            icon={Lock}
            revealable
            required
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter your password"
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

          <button type="submit" disabled={isLoading} className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot lp-auth__submit">
            {isLoading ? (
              <>
                <Loader2 className="lp-auth__spin" aria-hidden="true" />
                Creating account…
              </>
            ) : (
              <>
                Create account
                <ButtonDot />
              </>
            )}
          </button>

          <AuthDivider />

          <GoogleButton label="Sign up with Google" disabled={isLoading} onClick={handleGoogleSignIn} />
        </form>

        <p className="lp-auth__card-foot">
          Already have an account?{" "}
          <Link to={`/login${nextQuery}`} viewTransition className="lp-link">
            Sign in
          </Link>
        </p>
      </AuthCard>
    </AuthShell>
  );
}
