import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { coreSha3Hex } from "@/lib/core-crypto";
import type { Session, User } from "@supabase/supabase-js";
import { accountAuditIdentifier, accountIdentifierLabel } from "@/lib/account-identity";
import { clearChatPlaintextCaches } from "@/lib/chat-plaintext-cache";
import type { LinkCredential } from "@/lib/device-link";
import { maskPhone } from "@/lib/phone-number";
import { getSupabaseConfigError, isSupabaseConfigured, requireSupabase, supabase } from "@/lib/supabase";
import { isAndroidRuntime, isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { StoredSession } from "@/lib/use-app-lock";

interface AuthContextValue {
  user: User | null;
  session: Session | null;
  pendingMfa: PendingMfaChallenge | null;
  pendingPhone: PendingPhoneChallenge | null;
  loading: boolean;
  error: string | null;
  notice: string | null;
  signIn: (email: string, password: string) => Promise<boolean>;
  verifyMfaSignIn: (code: string) => Promise<boolean>;
  cancelMfaSignIn: () => Promise<void>;
  signUp: (email: string, password: string, name: string) => Promise<boolean>;
  requestPhoneCode: (phone: string, mode: PhoneAuthMode, name?: string) => Promise<boolean>;
  verifyPhoneCode: (code: string) => Promise<boolean>;
  cancelPhoneSignIn: () => void;
  signInWithLinkCredential: (credential: LinkCredential) => Promise<boolean>;
  resendVerification: (email: string) => Promise<boolean>;
  resetPassword: (email: string) => Promise<boolean>;
  signOut: () => Promise<void>;
  clearError: () => void;
  currentStoredSession: () => StoredSession | null;
}

interface PendingMfaChallenge {
  factorId: string;
  challengeId: string;
  /** The identifier the account signs in with (email, or E.164 for phones). */
  email: string;
  factorName: string;
}

export type PhoneAuthMode = "sign-in" | "sign-up";

export interface PendingPhoneChallenge {
  /** E.164; held only in memory while the code is outstanding. */
  phone: string;
  masked: string;
  mode: PhoneAuthMode;
  sentAt: number;
}

/** Seconds before another SMS may be requested (GoTrue's default OTP interval). */
export const PHONE_RESEND_SECONDS = 60;

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

// Projects a live Supabase session into the compact shape the Android app-lock
// vault persists (Task 6/7). Missing tokens mean the session cannot be
// restored later, so callers must treat a null return as "nothing to store".
function toStoredSession(session: Session | null): StoredSession | null {
  if (!session?.access_token || !session.refresh_token) return null;
  return {
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
    expiresAt: session.expires_at ?? 0,
    userId: session.user.id,
    email: accountIdentifierLabel(session.user),
  };
}

const missingProviderAuth: AuthContextValue = {
  user: null,
  session: null,
  pendingMfa: null,
  pendingPhone: null,
  loading: false,
  error: "Please refresh the app to restore your secure session.",
  notice: null,
  signIn: async () => false,
  verifyMfaSignIn: async () => false,
  cancelMfaSignIn: async () => undefined,
  signUp: async () => false,
  requestPhoneCode: async () => false,
  verifyPhoneCode: async () => false,
  cancelPhoneSignIn: () => undefined,
  signInWithLinkCredential: async () => false,
  resendVerification: async () => false,
  resetPassword: async () => false,
  signOut: async () => undefined,
  clearError: () => undefined,
  currentStoredSession: () => null,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [pendingMfa, setPendingMfa] = useState<PendingMfaChallenge | null>(null);
  const [pendingPhone, setPendingPhone] = useState<PendingPhoneChallenge | null>(null);
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

  const hashEmail = useCallback((email: string) => coreSha3Hex(email.trim().toLowerCase()), []);

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
      email: accountAuditIdentifier(activeSession.user),
      factorName: factor.friendly_name ?? "Authenticator app",
    });
    await auditAuthEvent("login_mfa_challenge", "info", accountAuditIdentifier(activeSession.user), { factor_type: "totp" }, activeSession.user.id);
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
        if (isAndroidRuntime()) {
          const stored = toStoredSession(nextSession);
          if (stored) void safeInvoke("applock_update_session", { session: stored }, null).catch(() => undefined);
        }
        setLoading(false);
        return;
      }

      setLoading(true);
      const processSession = () => {
        completeAuthenticatedSession(nextSession)
          .then((completed) => {
            if (completed && isAndroidRuntime()) {
              const stored = toStoredSession(nextSession);
              if (stored) void safeInvoke("applock_update_session", { session: stored }, null).catch(() => undefined);
            }
          })
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
        setNotice("This email is already registered with QGuard Helix. Please sign in instead, or resend the verification email if you haven't confirmed your account yet.");
        return true;
      }
      if (data.session) {
        await completeAuthenticatedSession(data.session);
        return true;
      }
      setNotice("Account request sent to QGuard Helix. Check your inbox and spam folder to verify your account, then sign in.");
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setLoading(false);
    }
  }, [completeAuthenticatedSession]);

  // Mobile-number accounts: SMS one-time codes, no password (Signal/Telegram
  // model). "sign-up" may create the account; "sign-in" never does, so a typo
  // in a returning user's number cannot silently open a second, empty account.
  const requestPhoneCode = useCallback(async (phone: string, mode: PhoneAuthMode, name?: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const client = requireSupabase();
      const allowed = await checkAuthRateLimit("login_sms", phone);
      if (!allowed) {
        setError("Too many code requests. Please wait a few minutes and try again.");
        await auditAuthEvent("login_sms_rate_limited", "warning", phone);
        return false;
      }
      const cleanName = name?.trim();
      const { error: otpError } = await withTimeout(
        retryOnTransient(() => Promise.resolve(client.auth.signInWithOtp({
          phone,
          options: {
            shouldCreateUser: mode === "sign-up",
            channel: "sms",
            ...(mode === "sign-up" && cleanName ? { data: { full_name: cleanName } } : {}),
          },
        }))),
        signInRequestTimeoutMs,
        "Secure sign in",
      );
      if (otpError) throw otpError;
      const masked = maskPhone(phone);
      setPendingPhone({ phone, masked, mode, sentAt: Date.now() });
      setNotice(`We texted a 6-digit code to ${masked}.`);
      void auditAuthEvent("login_sms_requested", "info", phone, { mode });
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await auditAuthEvent("login_sms_request_failed", "warning", phone, { mode });
      if (isTransientAuthError(err)) {
        setError(AUTH_UNREACHABLE_MESSAGE);
      } else if (/signups? not allowed|user not found|otp_disabled/i.test(message)) {
        setError("We couldn't find an account for that number. Choose \"Create account\" to register it.");
      } else if (/phone.*(provider|disabled|not enabled)|unsupported phone provider|sms.*(provider|disabled)/i.test(message)) {
        setError("Sign-in by mobile number isn't enabled on this server yet. Use your email address for now.");
      } else if (/only request this after|rate limit|too many/i.test(message)) {
        setError("A code was sent very recently. Please wait a minute before requesting another.");
      } else if (/invalid.*phone|phone.*invalid/i.test(message)) {
        setError("That mobile number isn't valid. Check the country and number, then try again.");
      } else {
        setError(message);
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, checkAuthRateLimit]);

  const verifyPhoneCode = useCallback(async (code: string) => {
    if (!pendingPhone) {
      setError("Request a code first.");
      return false;
    }
    setLoading(true);
    setError(null);
    setNotice(null);
    const { phone, mode } = pendingPhone;
    try {
      const allowed = await checkAuthRateLimit("login_sms_verify", phone);
      if (!allowed) {
        setError("Too many attempts. Please wait a few minutes and try again.");
        await auditAuthEvent("login_sms_verify_rate_limited", "warning", phone);
        return false;
      }
      const { data, error: verifyError } = await withTimeout(
        requireSupabase().auth.verifyOtp({ phone, token: code.replace(/\D/g, ""), type: "sms" }),
        signInRequestTimeoutMs,
        "Secure sign in",
      );
      if (verifyError || !data.session) throw verifyError ?? new Error("Sign in failed.");
      setPendingPhone(null);
      const completed = await completeAuthenticatedSession(data.session, true);
      void auditAuthEvent(mode === "sign-up" ? "signup_sms_verified" : "login_success", "info", phone, { method: "sms" }, data.session.user.id);
      return completed;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await auditAuthEvent("login_sms_verify_failed", "warning", phone);
      if (isTransientAuthError(err)) {
        setError(AUTH_UNREACHABLE_MESSAGE);
      } else if (/expired|invalid|token/i.test(message)) {
        setError("That code is incorrect or has expired. Check the SMS or request a new code.");
      } else {
        setError(message);
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, checkAuthRateLimit, completeAuthenticatedSession, pendingPhone]);

  const cancelPhoneSignIn = useCallback(() => {
    setPendingPhone(null);
    setError(null);
    setNotice(null);
  }, []);

  // A QR-linked device redeems the one-time credential the device-link service
  // minted for it. The result is an ordinary, independent session; MFA, if the
  // account has it, is still required here (the credential is only aal1).
  const signInWithLinkCredential = useCallback(async (credential: LinkCredential) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const client = requireSupabase();
      const { data, error: verifyError } = await withTimeout(
        credential.method === "email_token"
          ? client.auth.verifyOtp({ token_hash: credential.tokenHash, type: "magiclink" })
          : client.auth.verifyOtp({ phone: credential.phone, token: credential.code, type: "sms" }),
        signInRequestTimeoutMs,
        "Linked device sign in",
      );
      if (verifyError || !data.session) throw verifyError ?? new Error("The link could not be redeemed.");
      const completed = await completeAuthenticatedSession(data.session, true);
      void auditAuthEvent("login_device_linked", "info", accountAuditIdentifier(data.session.user), { method: credential.method }, data.session.user.id);
      return completed;
    } catch (err) {
      setError(isTransientAuthError(err) ? AUTH_UNREACHABLE_MESSAGE : "This device couldn't be signed in from the link. Show a new QR code and try again.");
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, completeAuthenticatedSession]);

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

  // Password reset uses Supabase's recovery email flow. We intentionally do NOT
  // pass a redirectTo: the app's own origin (tauri://localhost / tauri.localhost)
  // cannot host the recovery page, so Supabase falls back to the project's
  // configured Site URL, which owns the "set a new password" landing page.
  // The confirmation notice is deliberately enumeration-safe — it never reveals
  // whether the address is registered.
  const resetPassword = useCallback(async (email: string) => {
    setLoading(true);
    setError(null);
    setNotice(null);
    const cleanEmail = email.trim().toLowerCase();
    try {
      if (!cleanEmail) throw new Error("Enter your email address first.");
      const client = requireSupabase();
      const allowed = await checkAuthRateLimit("password_reset", cleanEmail);
      if (!allowed) {
        setError("Too many password reset requests. Please wait a few minutes and try again.");
        await auditAuthEvent("password_reset_rate_limited", "warning", cleanEmail);
        return false;
      }
      const { error: resetError } = await withTimeout(
        retryOnTransient(() => Promise.resolve(client.auth.resetPasswordForEmail(cleanEmail))),
        signInRequestTimeoutMs,
        "Password reset request",
      );
      if (resetError) throw resetError;
      await auditAuthEvent("password_reset_requested", "info", cleanEmail);
      setNotice("If that email is registered, a password reset link is on its way. Check your inbox and spam folder, then follow the link to set a new password.");
      return true;
    } catch (err) {
      await auditAuthEvent("password_reset_failed", "warning", cleanEmail);
      if (isTransientAuthError(err)) {
        setError(AUTH_UNREACHABLE_MESSAGE);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
      return false;
    } finally {
      setLoading(false);
    }
  }, [auditAuthEvent, checkAuthRateLimit]);

  const signOut = useCallback(async () => {
    const userId = user?.id;
    clearChatPlaintextCaches();
    await supabase.auth.signOut();
    await safeInvoke("auth_logout", userId ? { userId } : {}, false);
    if (isAndroidRuntime()) {
      await safeInvoke("applock_wipe", userId ? { userId } : {}, null).catch(() => undefined);
    }
    activeSessionTokenRef.current = null;
    setUser(null);
    setSession(null);
    setPendingMfa(null);
    setPendingPhone(null);
  }, [user?.id]);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    session,
    pendingMfa,
    pendingPhone,
    loading,
    error,
    notice,
    signIn,
    verifyMfaSignIn,
    cancelMfaSignIn,
    signUp,
    requestPhoneCode,
    verifyPhoneCode,
    cancelPhoneSignIn,
    signInWithLinkCredential,
    resendVerification,
    resetPassword,
    signOut,
    clearError: () => {
      setError(null);
      setNotice(null);
    },
    currentStoredSession: () => toStoredSession(session),
  }), [cancelMfaSignIn, cancelPhoneSignIn, error, loading, notice, pendingMfa, pendingPhone, requestPhoneCode, resendVerification, resetPassword, session, signIn, signInWithLinkCredential, signOut, signUp, user, verifyMfaSignIn, verifyPhoneCode]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  return context ?? missingProviderAuth;
}
