import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { requireSupabase, supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

interface AuthContextValue {
  user: User | null;
  session: Session | null;
  pendingMfa: PendingMfaChallenge | null;
  loading: boolean;
  error: string | null;
  notice: string | null;
  signIn: (email: string, password: string) => Promise<boolean>;
  verifyMfaSignIn: (code: string) => Promise<boolean>;
  cancelMfaSignIn: () => Promise<void>;
  signUp: (email: string, password: string, name: string) => Promise<boolean>;
  resendVerification: (email: string) => Promise<boolean>;
  signOut: () => Promise<void>;
  clearError: () => void;
}

interface PendingMfaChallenge {
  factorId: string;
  challengeId: string;
  email: string;
  factorName: string;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const missingProviderAuth: AuthContextValue = {
  user: null,
  session: null,
  pendingMfa: null,
  loading: false,
  error: "Please refresh the app to restore your secure session.",
  notice: null,
  signIn: async () => false,
  verifyMfaSignIn: async () => false,
  cancelMfaSignIn: async () => undefined,
  signUp: async () => false,
  resendVerification: async () => false,
  signOut: async () => undefined,
  clearError: () => undefined,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [pendingMfa, setPendingMfa] = useState<PendingMfaChallenge | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const syncBackend = useCallback(async (activeSession: Session) => {
    if (!isTauriRuntime()) return;
    const activeUser = activeSession.user;
    await safeInvoke("auth_sync_session", {
      userId: activeUser.id,
      email: activeUser.email ?? "",
      tier: String(activeUser.app_metadata?.tier ?? activeUser.user_metadata?.tier ?? "user"),
      accessToken: activeSession.access_token,
      expiresAt: activeSession.expires_at ?? 0,
    });
  }, []);

  const hashEmail = useCallback(async (email: string) => {
    const data = new TextEncoder().encode(email.trim().toLowerCase());
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }, []);

  const auditAuthEvent = useCallback(async (
    eventType: string,
    severity: "info" | "warning" | "critical",
    email: string,
    metadata: Record<string, string | number | boolean | null> = {},
    userId?: string | null,
  ) => {
    try {
      await supabase.rpc("log_qguard_profile_security_event", {
        p_event_type: eventType,
        p_severity: severity,
        p_metadata: metadata,
        p_email_hash: await hashEmail(email),
        p_user_id: userId ?? null,
      });
    } catch {
      // Audit failures must not expose auth internals or block auth flow.
    }
  }, [hashEmail]);

  const checkAuthRateLimit = useCallback(async (action: string, email: string) => {
    try {
      const { data, error: limitError } = await supabase.rpc("check_qguard_profile_rate_limit", {
        p_action: action,
        p_email_hash: await hashEmail(email),
        p_limit: 8,
        p_window_seconds: 300,
      });
      if (limitError) return true;
      return Boolean(data);
    } catch {
      return true;
    }
  }, [hashEmail]);

  const requireMfaIfNeeded = useCallback(async (activeSession: Session): Promise<boolean> => {
    const { data: assurance, error: assuranceError } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (assuranceError || assurance?.nextLevel !== "aal2" || assurance.currentLevel === "aal2") {
      setPendingMfa(null);
      return true;
    }

    const { data: factors, error: factorsError } = await supabase.auth.mfa.listFactors();
    if (factorsError) throw factorsError;
    const factor = factors.totp[0];
    if (!factor) return true;

    const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId: factor.id });
    if (challengeError) throw challengeError;

    setUser(null);
    setSession(null);
    setPendingMfa({
      factorId: factor.id,
      challengeId: challenge.id,
      email: activeSession.user.email ?? "",
      factorName: factor.friendly_name ?? "Authenticator app",
    });
    await auditAuthEvent("login_mfa_challenge", "info", activeSession.user.email ?? "", { factor_type: "totp" }, activeSession.user.id);
    return false;
  }, [auditAuthEvent]);

  const completeAuthenticatedSession = useCallback(async (activeSession: Session): Promise<boolean> => {
    const mfaSatisfied = await requireMfaIfNeeded(activeSession);
    if (!mfaSatisfied) return false;
    await syncBackend(activeSession);
    setUser(activeSession.user);
    setSession(activeSession);
    setPendingMfa(null);
    return true;
  }, [requireMfaIfNeeded, syncBackend]);

  const validateSession = useCallback(async () => {
    setLoading(true);
    const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
    if (sessionError || !sessionData.session) {
      setUser(null);
      setSession(null);
      setLoading(false);
      return;
    }

    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData.user) {
      await supabase.auth.signOut({ scope: "local" });
      setUser(null);
      setSession(null);
      setError("Your session could not be validated. Please sign in again.");
      setLoading(false);
      return;
    }

    try {
      const completed = await completeAuthenticatedSession(sessionData.session);
      if (!completed) {
        setLoading(false);
        return;
      }
    } catch (err) {
      setUser(null);
      setSession(null);
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
      return;
    }
    setLoading(false);
  }, [completeAuthenticatedSession]);

  useEffect(() => {
    validateSession();

    const client = supabase;
    const { data } = client.auth.onAuthStateChange((_event, nextSession) => {
      if (!nextSession) {
        setSession(null);
        setUser(null);
        setLoading(false);
        return;
      }

      setLoading(true);
      completeAuthenticatedSession(nextSession)
        .then((completed) => {
          if (!completed) return;
          setSession(nextSession);
          setUser(nextSession.user);
        })
        .catch(async (err) => {
          setSession(null);
          setUser(null);
          setError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => {
          setLoading(false);
        });
    });

    return () => data.subscription.unsubscribe();
  }, [completeAuthenticatedSession, validateSession]);

  const signIn = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const client = requireSupabase();
      const allowed = await checkAuthRateLimit("login_password", email);
      if (!allowed) {
        setError("Too many sign-in attempts. Please wait a few minutes and try again.");
        await auditAuthEvent("login_rate_limited", "warning", email);
        return false;
      }
      const { data, error: signInError } = await client.auth.signInWithPassword({ email, password });
      if (signInError || !data.session) {
        throw signInError ?? new Error("Sign in failed.");
      }
      const completed = await completeAuthenticatedSession(data.session);
      if (!completed) return false;
      await auditAuthEvent("login_success", "info", email, {}, data.session.user.id);
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await auditAuthEvent("login_failed", "warning", email);
      if (message.toLowerCase().includes("email not confirmed")) {
        await requireSupabase().auth.resend({ type: "signup", email }).catch(() => undefined);
        setError("Please verify your email before signing in. We sent a new verification link if the address is registered.");
      } else {
        setError(message);
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, checkAuthRateLimit, completeAuthenticatedSession]);

  const verifyMfaSignIn = useCallback(async (code: string) => {
    if (!pendingMfa) {
      setError("No MFA challenge is active.");
      return false;
    }
    setLoading(true);
    setError(null);
    try {
      const allowed = await checkAuthRateLimit("login_mfa", pendingMfa.email);
      if (!allowed) {
        setError("Too many MFA attempts. Please wait a few minutes and try again.");
        await auditAuthEvent("login_mfa_rate_limited", "warning", pendingMfa.email);
        return false;
      }
      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId: pendingMfa.factorId,
        challengeId: pendingMfa.challengeId,
        code: code.trim(),
      });
      if (verifyError) throw verifyError;
      const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
      if (sessionError || !sessionData.session) throw sessionError ?? new Error("MFA session could not be restored.");
      await syncBackend(sessionData.session);
      setUser(sessionData.session.user);
      setSession(sessionData.session);
      setPendingMfa(null);
      await auditAuthEvent("login_mfa_verified", "info", pendingMfa.email, {}, sessionData.session.user.id);
      return true;
    } catch (err) {
      await auditAuthEvent("login_mfa_failed", "warning", pendingMfa.email);
      setError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, checkAuthRateLimit, pendingMfa, syncBackend]);

  const cancelMfaSignIn = useCallback(async () => {
    await supabase.auth.signOut({ scope: "local" });
    setPendingMfa(null);
    setSession(null);
    setUser(null);
  }, []);

  const signUp = useCallback(async (email: string, password: string, name: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const client = requireSupabase();
      const { data, error: signUpError } = await client.auth.signUp({
        email,
        password,
        options: { data: { full_name: name } },
      });
      if (signUpError) throw signUpError;
      if (data.session) {
        await completeAuthenticatedSession(data.session);
        return true;
      }
      setNotice("Account created. Please check your email to finish verification, then sign in.");
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setLoading(false);
    }
  }, [completeAuthenticatedSession]);

  const resendVerification = useCallback(async (email: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      if (!email.trim()) throw new Error("Enter your email address first.");
      const client = requireSupabase();
      const { error: resendError } = await client.auth.resend({ type: "signup", email: email.trim() });
      if (resendError) throw resendError;
      setNotice("Verification email sent. Please check your inbox and spam folder.");
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    await safeInvoke("auth_logout", {}, false);
    setUser(null);
    setSession(null);
    setPendingMfa(null);
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    session,
    pendingMfa,
    loading,
    error,
    notice,
    signIn,
    verifyMfaSignIn,
    cancelMfaSignIn,
    signUp,
    resendVerification,
    signOut,
    clearError: () => {
      setError(null);
      setNotice(null);
    },
  }), [cancelMfaSignIn, error, loading, notice, pendingMfa, resendVerification, session, signIn, signOut, signUp, user, verifyMfaSignIn]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  return context ?? missingProviderAuth;
}
