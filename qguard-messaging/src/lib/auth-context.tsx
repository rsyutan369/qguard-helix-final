import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { clearChatPlaintextCaches } from "@/lib/chat-plaintext-cache";
import { getSupabaseConfigError, isSupabaseConfigured, requireSupabase, supabase, supabaseAuthTarget } from "@/lib/supabase";
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

const authRequestTimeoutMs = 20_000;
const signInRequestTimeoutMs = 35_000;
const auditRequestTimeoutMs = 3_000;
const desktopSessionSyncTimeoutMs = 8_000;

async function withTimeout<T>(task: PromiseLike<T>, timeoutMs: number, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`${label} timed out. Please try again.`)), timeoutMs);
  });
  try {
    return await Promise.race([task, timeout]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

// A "Failed to fetch" / timeout means the request never reached the auth server
// (e.g. a free-tier project that is still waking up). These are safe to retry —
// unlike an "Invalid login credentials" response, which is returned as data and
// never thrown, so it is never retried here.
function isTransientAuthError(error: unknown): boolean {
  const message = (error instanceof Error ? error.message : String(error ?? "")).toLowerCase();
  return /failed to fetch|networkerror|network error|load failed|timed out|timeout|connection|fetch failed|err_/i.test(message);
}

async function retryOnTransient<T>(task: () => Promise<T>, attempts = 3, delayMs = 600): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await task();
    } catch (error) {
      lastError = error;
      if (!isTransientAuthError(error) || attempt === attempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs * (attempt + 1)));
    }
  }
  throw lastError;
}

const AUTH_UNREACHABLE_MESSAGE = "Couldn't reach the secure sign-in service. Check your connection and try again in a moment.";

function getEmailRedirectTo(): string | undefined {
  if (typeof window === "undefined") return undefined;
  const origin = window.location.origin;
  if (!/^https?:\/\//i.test(origin)) return undefined;
  return origin;
}

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
  const activeSessionTokenRef = useRef<string | null>(null);

  // freshLogin distinguishes an interactive sign-in (password + optional MFA)
  // from a background token refresh / session restore. Only a fresh login
  // clears workspace brute-force lockdowns and re-locks the protected
  // workspaces backend-side — a refresh must never do either.
  const syncBackend = useCallback(async (activeSession: Session, freshLogin = false) => {
    if (!isTauriRuntime()) return;
    const activeUser = activeSession.user;
    await withTimeout(safeInvoke("auth_sync_session", {
      userId: activeUser.id,
      email: activeUser.email ?? "",
      tier: String(activeUser.app_metadata?.tier ?? activeUser.user_metadata?.tier ?? "user"),
      accessToken: activeSession.access_token,
      expiresAt: activeSession.expires_at ?? 0,
      freshLogin,
    }), desktopSessionSyncTimeoutMs, "Desktop session sync");
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
      await withTimeout(supabase.rpc("log_qguard_profile_security_event", {
        p_event_type: eventType,
        p_severity: severity,
        p_metadata: metadata,
        p_email_hash: await hashEmail(email),
        p_user_id: userId ?? null,
      }), auditRequestTimeoutMs, "Auth audit");
    } catch {
      // Audit failures must not expose auth internals or block auth flow.
    }
  }, [hashEmail]);

  const checkAuthRateLimit = useCallback(async (action: string, email: string) => {
    try {
      const { data, error: limitError } = await withTimeout(supabase.rpc("check_qguard_profile_rate_limit", {
        p_action: action,
        p_email_hash: await hashEmail(email),
        p_limit: 8,
        p_window_seconds: 300,
      }), authRequestTimeoutMs, "Auth rate limit check");
      if (limitError) return true;
      return Boolean(data);
    } catch {
      return true;
    }
  }, [hashEmail]);

  const requireMfaIfNeeded = useCallback(async (activeSession: Session): Promise<boolean> => {
    const { data: assurance, error: assuranceError } = await withTimeout(
      supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
      authRequestTimeoutMs,
      "MFA assurance check",
    );
    if (assuranceError || assurance?.nextLevel !== "aal2" || assurance.currentLevel === "aal2") {
      setPendingMfa(null);
      return true;
    }

    const { data: factors, error: factorsError } = await withTimeout(
      supabase.auth.mfa.listFactors(),
      authRequestTimeoutMs,
      "MFA factor check",
    );
    if (factorsError) throw factorsError;
    const factor = factors.totp[0];
    if (!factor) return true;

    const { data: challenge, error: challengeError } = await withTimeout(
      supabase.auth.mfa.challenge({ factorId: factor.id }),
      authRequestTimeoutMs,
      "MFA challenge",
    );
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

  const completeAuthenticatedSession = useCallback(async (activeSession: Session, freshLogin = false): Promise<boolean> => {
    const mfaSatisfied = await requireMfaIfNeeded(activeSession);
    if (!mfaSatisfied) return false;
    await syncBackend(activeSession, freshLogin);
    activeSessionTokenRef.current = activeSession.access_token;
    setUser(activeSession.user);
    setSession(activeSession);
    setPendingMfa(null);
    return true;
  }, [requireMfaIfNeeded, syncBackend]);

  const validateSession = useCallback(async () => {
    setLoading(true);
    if (!isSupabaseConfigured) {
      activeSessionTokenRef.current = null;
      setUser(null);
      setSession(null);
      setError(getSupabaseConfigError()?.message ?? "QGuard Messaging Supabase is not configured.");
      setLoading(false);
      return;
    }

    try {
      const { data: sessionData, error: sessionError } = await withTimeout(
        supabase.auth.getSession(),
        authRequestTimeoutMs,
        "Session restore",
      );
      if (sessionError || !sessionData.session) {
        activeSessionTokenRef.current = null;
        setUser(null);
        setSession(null);
        setLoading(false);
        return;
      }

      const { data: userData, error: userError } = await withTimeout(
        supabase.auth.getUser(),
        authRequestTimeoutMs,
        "Session validation",
      );
      if (userError || !userData.user) {
        await supabase.auth.signOut({ scope: "local" });
        activeSessionTokenRef.current = null;
        setUser(null);
        setSession(null);
        setError("Your session could not be validated. Please sign in again.");
        setLoading(false);
        return;
      }

      const completed = await completeAuthenticatedSession(sessionData.session);
      if (!completed) {
        setLoading(false);
        return;
      }
    } catch (err) {
      activeSessionTokenRef.current = null;
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
        activeSessionTokenRef.current = null;
        setSession(null);
        setUser(null);
        setLoading(false);
        return;
      }

      if (nextSession.access_token === activeSessionTokenRef.current) {
        setSession(nextSession);
        setUser(nextSession.user);
        setLoading(false);
        return;
      }

      setLoading(true);
      const processSession = () => {
        completeAuthenticatedSession(nextSession)
          .catch((err) => {
            activeSessionTokenRef.current = null;
            setSession(null);
            setUser(null);
            setError(err instanceof Error ? err.message : String(err));
          })
          .finally(() => {
            setLoading(false);
          });
      };
      setTimeout(processSession, 0);
    });

    return () => data.subscription.unsubscribe();
  }, [completeAuthenticatedSession, validateSession]);

  const signIn = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    const cleanEmail = email.trim().toLowerCase();
    try {
      const client = requireSupabase();
      const allowed = await checkAuthRateLimit("login_password", cleanEmail);
      if (!allowed) {
        setError("Too many sign-in attempts. Please wait a few minutes and try again.");
        await auditAuthEvent("login_rate_limited", "warning", cleanEmail);
        return false;
      }
      const { data, error: signInError } = await withTimeout(
        retryOnTransient(() => Promise.resolve(client.auth.signInWithPassword({ email: cleanEmail, password }))),
        signInRequestTimeoutMs,
        "Secure sign in",
      );
      if (signInError || !data.session) {
        throw signInError ?? new Error("Sign in failed.");
      }
      const completed = await completeAuthenticatedSession(data.session, true);
      if (!completed) return false;
      void auditAuthEvent("login_success", "info", cleanEmail, {}, data.session.user.id);
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await auditAuthEvent("login_failed", "warning", cleanEmail);
      if (isTransientAuthError(err)) {
        setError(AUTH_UNREACHABLE_MESSAGE);
      } else if (message.toLowerCase().includes("email not confirmed")) {
        const redirectTo = getEmailRedirectTo();
        await requireSupabase().auth.resend({
          type: "signup",
          email: cleanEmail,
          options: redirectTo ? { emailRedirectTo: redirectTo } : undefined,
        }).catch(() => undefined);
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
      const { error: verifyError } = await withTimeout(supabase.auth.mfa.verify({
        factorId: pendingMfa.factorId,
        challengeId: pendingMfa.challengeId,
        code: code.trim(),
      }), authRequestTimeoutMs, "MFA verification");
      if (verifyError) throw verifyError;
      const { data: sessionData, error: sessionError } = await withTimeout(
        supabase.auth.getSession(),
        authRequestTimeoutMs,
        "MFA session restore",
      );
      if (sessionError || !sessionData.session) throw sessionError ?? new Error("MFA session could not be restored.");
      activeSessionTokenRef.current = sessionData.session.access_token;
      await syncBackend(sessionData.session, true);
      setUser(sessionData.session.user);
      setSession(sessionData.session);
      setPendingMfa(null);
      void auditAuthEvent("login_mfa_verified", "info", pendingMfa.email, {}, sessionData.session.user.id);
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
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = name.trim();
    try {
      if (!cleanEmail) throw new Error("Enter your email address first.");
      const client = requireSupabase();
      const redirectTo = getEmailRedirectTo();
      const { data, error: signUpError } = await withTimeout(
        client.auth.signUp({
          email: cleanEmail,
          password,
          options: {
            data: { full_name: cleanName },
            emailRedirectTo: redirectTo,
          },
        }),
        signInRequestTimeoutMs,
        "Secure registration",
      );
      if (signUpError) throw signUpError;
      if (data.user && Array.isArray(data.user.identities) && data.user.identities.length === 0) {
        setNotice(`Supabase says this email is already registered in the ${supabaseAuthTarget}. No new Auth user was created. Use sign in or resend the verification email for this same project.`);
        return true;
      }
      if (data.session) {
        await completeAuthenticatedSession(data.session);
        return true;
      }
      setNotice(`Account request sent to the ${supabaseAuthTarget}. If email verification is enabled, check your inbox and spam folder, then sign in.`);
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
    const cleanEmail = email.trim().toLowerCase();
    try {
      if (!cleanEmail) throw new Error("Enter your email address first.");
      const client = requireSupabase();
      const redirectTo = getEmailRedirectTo();
      const { error: resendError } = await client.auth.resend({
        type: "signup",
        email: cleanEmail,
        options: redirectTo ? { emailRedirectTo: redirectTo } : undefined,
      });
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
    const userId = user?.id;
    clearChatPlaintextCaches();
    await supabase.auth.signOut();
    await safeInvoke("auth_logout", userId ? { userId } : {}, false);
    activeSessionTokenRef.current = null;
    setUser(null);
    setSession(null);
    setPendingMfa(null);
  }, [user?.id]);

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
