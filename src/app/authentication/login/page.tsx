"use client";

import React, { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Lock, Mail } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { PUBLIC_SCAN_PATH, safeAuthDestination } from "@/lib/public-scan-auth";
import { ButtonDot } from "@/pages/landing-chars";
import { AuthAlert, AuthCard, AuthDivider, AuthField, AuthShell, GoogleButton } from "../AuthShell";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const nextParam = searchParams.get("next");
  const safeNext = safeAuthDestination(nextParam) ?? (import.meta.env.VITE_SITE_EDITION === 'public' ? PUBLIC_SCAN_PATH : "/dashboard");
  const nextQuery = safeNext !== "/dashboard" ? `?next=${encodeURIComponent(safeNext)}` : "";
  const { signIn, signInWithGoogle } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const { error } = await signIn(email, password);
      if (error) {
        setIsLoading(false);
        let msg = error.message || "Sign-in failed. Please try again.";
        if (msg.includes("Invalid login")) msg = "That email and password don't match an account.";
        else if (msg.includes("Email not confirmed")) msg = "Please verify your email first. Check your inbox for the confirmation link.";
        setError(msg);
        return;
      }
      setIsLoading(false);
      // If no explicit next survived (e.g. lost across email verification) but a
      // checkout intent was stashed, resume it.
      let target = safeNext;
      if (safeNext === "/dashboard") {
        try {
          if (localStorage.getItem("qguard.pendingCheckout")) target = "/checkout";
        } catch {
          // ignore
        }
      }
      navigate(target);
    } catch (err: any) {
      setIsLoading(false);
      setError(err.message || "Something went wrong. Please try again.");
    }
  };

  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const { error } = await signInWithGoogle(safeNext === PUBLIC_SCAN_PATH);
      if (error) {
        setIsLoading(false);
        setError("Google sign-in failed: " + error.message);
        return;
      }
      setIsLoading(false);
    } catch (err: any) {
      setIsLoading(false);
      setError("Google sign-in failed: " + err.message);
    }
  };

  return (
    <AuthShell mode="login" nextQuery={nextQuery}>
      <AuthCard kicker="Sign in" heading="Access your workspace" sub="Use your work email, or continue with Google.">
        {error && <AuthAlert tone="error">{error}</AuthAlert>}

        <form onSubmit={handleSubmit} className="lp-auth__form" aria-busy={isLoading}>
          <AuthField
            id="login-email"
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
            id="login-password"
            label="Password"
            icon={Lock}
            revealable
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            aside={
              <Link to="/reset-password" className="lp-auth__inline-link">
                Forgot password?
              </Link>
            }
          />

          <button type="submit" disabled={isLoading} className="lp-btn lp-btn--primary lp-btn--block lp-btn--dot lp-auth__submit">
            {isLoading ? (
              <>
                <Loader2 className="lp-auth__spin" aria-hidden="true" />
                Signing in…
              </>
            ) : (
              <>
                Sign in
                <ButtonDot />
              </>
            )}
          </button>

          <AuthDivider />

          <GoogleButton label="Continue with Google" disabled={isLoading} onClick={handleGoogleSignIn} />
        </form>

        <p className="lp-auth__card-foot">
          New to Qguard Helix?{" "}
          <Link to={`/register${nextQuery}`} viewTransition className="lp-link">
            Create an account
          </Link>
        </p>
      </AuthCard>
    </AuthShell>
  );
}
