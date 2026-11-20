import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import {
  canUseFallbackSupabase,
  getSupabaseClient,
  switchToFallbackSupabase,
  beginGoogleOAuth,
  finishGoogleOAuth,
} from '../lib/supabase';
import type { User, Session } from '@supabase/supabase-js';
import { SIGNUP_CONFIRMATION_URL } from '../lib/signup-confirmation';
import { GOOGLE_CALLBACK_PATH } from '../lib/oauth-callback';
import { PUBLIC_SCAN_CONFIRMATION_PATH, PUBLIC_SCAN_OAUTH_KEY } from '../lib/public-scan-auth';

const AUTH_TIMEOUT_MS = 12000;

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: Error | null }>;
  signUp: (email: string, password: string, forPublicScan?: boolean) => Promise<{ error: Error | null }>;
  signInWithGoogle: (forPublicScan?: boolean) => Promise<{ error: Error | null }>;
  completeGoogleSignIn: (code: string) => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function toAuthError(error: unknown, fallbackMessage: string): Error {
  return error instanceof Error ? error : new Error(fallbackMessage);
}

/**
 * Is this the same signed-in session, in every way the application cares about?
 *
 * supabase-js re-emits `onAuthStateChange` whenever the tab becomes visible
 * again — it re-reads storage and revalidates the token on `visibilitychange` —
 * and it hands back a NEWLY CONSTRUCTED session object even when nothing about
 * the session changed. Feeding that object straight into `setSession` /
 * `setUser` gave every consumer of `useAuth()` a new `user` identity on every
 * alt-tab, which is what made `useSubscription` re-run, flip itself back to
 * `loading`, and make `DashboardLayout` swap `<Outlet/>` for its loading shell —
 * unmounting the whole page the user was looking at, mid-scan.
 *
 * Comparing by value keeps the identity stable across those no-op events while
 * still propagating a real sign-in, sign-out or token rotation.
 */
function isSameSession(a: Session | null, b: Session | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    a.access_token === b.access_token &&
    a.refresh_token === b.refresh_token &&
    a.expires_at === b.expires_at &&
    a.user?.id === b.user?.id
  );
}

function isSameUser(a: User | null, b: User | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    a.id === b.id &&
    a.email === b.email &&
    a.updated_at === b.updated_at &&
    a.role === b.role
  );
}

async function withAuthTimeout<T>(operation: Promise<T>, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<T>((_resolve, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${label} timed out. Check Supabase connectivity and credentials.`));
    }, AUTH_TIMEOUT_MS);
  });

  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    let unsubscribe: (() => void) | null = null;

    const attachAuthClient = async () => {
      let client = getSupabaseClient();
      let session: Session | null = null;
      let error: Error | null = null;

      try {
        const result = await withAuthTimeout(client.auth.getSession(), 'Supabase session check');
        session = result.data.session;
        error = result.error;
      } catch (err) {
        error = toAuthError(err, 'Supabase session check failed.');
      }

      if ((error || !session) && canUseFallbackSupabase() && window.location.pathname !== GOOGLE_CALLBACK_PATH) {
        const fallbackClient = switchToFallbackSupabase();
        if (fallbackClient) {
          client = fallbackClient;
          try {
            const fallbackSession = await withAuthTimeout(client.auth.getSession(), 'Fallback Supabase session check');
            session = fallbackSession.data.session;
          } catch {
            session = null;
          }
        }
      }

      if (!mounted) return;
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);

      const { data: { subscription } } = client.auth.onAuthStateChange((_event, nextSession) => {
        // Value-compared, not assigned blind — see `isSameSession`. A tab
        // regaining focus must not re-identify the user to the whole tree.
        const nextUser = nextSession?.user ?? null;
        setSession((current) => (isSameSession(current, nextSession) ? current : nextSession));
        setUser((current) => (isSameUser(current, nextUser) ? current : nextUser));
        setLoading(false);
      });
      unsubscribe = () => subscription.unsubscribe();
    };

    void attachAuthClient();

    return () => {
      mounted = false;
      unsubscribe?.();
    };
  }, []);

  const signIn = async (email: string, password: string) => {
    let client = getSupabaseClient();
    let { data, error } = await withAuthTimeout(
      client.auth.signInWithPassword({ email, password }),
      'Supabase sign-in',
    ).catch((err) => ({
      data: { user: null, session: null },
      error: toAuthError(err, 'Supabase sign-in failed.'),
    }));

    if (error && canUseFallbackSupabase()) {
      const fallbackClient = switchToFallbackSupabase();
      if (fallbackClient) {
        client = fallbackClient;
        const fallbackResult = await withAuthTimeout(
          client.auth.signInWithPassword({ email, password }),
          'Fallback Supabase sign-in',
        ).catch((err) => ({
          data: { user: null, session: null },
          error: toAuthError(err, 'Fallback Supabase sign-in failed.'),
        }));
        data = fallbackResult.data;
        error = fallbackResult.error;
      }
    }

    if (!error) {
      setSession(data.session);
      setUser(data.user ?? data.session?.user ?? null);
    }
    return { error };
  };

  const signUp = async (email: string, password: string, forPublicScan = false) => {
    // Register through the platform API first: client-side auth.signUp sends a
    // confirmation email via Supabase's built-in mailer (~2/hour quota), so a
    // few registrations produce 429 "email rate limit exceeded" for everyone.
    // The server creates the account with the service role — no email, no
    // mailer quota — and we establish the session with a normal password
    // sign-in. Deployments without the API (static hosting) fall through to
    // the original client-side flow below.
    if (!forPublicScan) {
      try {
        const response = await fetch('/api/v1/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        if (response.status === 201) {
          return await signIn(email, password);
        }
        if ([400, 403, 409, 429].includes(response.status)) {
          const payload = await response.json().catch(() => null);
          return { error: new Error(payload?.error?.message || 'Registration failed. Please review your details and try again.') };
        }
        // An unavailable endpoint falls through to Supabase confirmation.
      } catch {
        // Continue with confirmation when the API is unreachable.
      }
    }

    const emailRedirectTo = forPublicScan
      ? new URL(PUBLIC_SCAN_CONFIRMATION_PATH, window.location.origin).href
      : SIGNUP_CONFIRMATION_URL;
    const credentials = { email, password, options: { emailRedirectTo } };
    let client = getSupabaseClient();
    let { data, error } = await withAuthTimeout(
      client.auth.signUp(credentials),
      'Supabase registration',
    ).catch((err) => ({
      data: { user: null, session: null },
      error: toAuthError(err, 'Supabase registration failed.'),
    }));

    if (error && canUseFallbackSupabase()) {
      const fallbackClient = switchToFallbackSupabase();
      if (fallbackClient) {
        client = fallbackClient;
        const fallbackResult = await withAuthTimeout(
          client.auth.signUp(credentials),
          'Fallback Supabase registration',
        ).catch((err) => ({
          data: { user: null, session: null },
          error: toAuthError(err, 'Fallback Supabase registration failed.'),
        }));
        data = fallbackResult.data;
        error = fallbackResult.error;
      }
    }

    if (!error) {
      setSession(data.session);
      setUser(data.user ?? data.session?.user ?? null);
    }
    if (error && /rate limit/i.test(error.message)) {
      // Supabase built-in mailer quota (~2 emails/hour) — translate the raw
      // 429 into something a person can act on.
      return { error: new Error('The email service has reached its hourly limit. Please try again in about an hour.') };
    }
    return { error };
  };

  const signInWithGoogle = async (forPublicScan = false) => {
    if (forPublicScan) sessionStorage.setItem(PUBLIC_SCAN_OAUTH_KEY, '1');
    else sessionStorage.removeItem(PUBLIC_SCAN_OAUTH_KEY);
    const redirectTo = new URL(GOOGLE_CALLBACK_PATH, window.location.origin).href;
    let result = await withAuthTimeout(
      beginGoogleOAuth(redirectTo),
      'Supabase OAuth sign-in',
    ).catch((err) => ({
      data: { provider: null, url: null },
      error: toAuthError(err, 'Supabase OAuth sign-in failed.'),
    }));
    if (result.error && canUseFallbackSupabase()) {
      const fallbackClient = switchToFallbackSupabase();
      if (fallbackClient) {
        result = await withAuthTimeout(
          beginGoogleOAuth(redirectTo),
          'Fallback Supabase OAuth sign-in',
        ).catch((err) => ({
          data: { provider: null, url: null },
          error: toAuthError(err, 'Fallback Supabase OAuth sign-in failed.'),
        }));
      }
    }
    if (!result.error && result.data.url) window.location.assign(result.data.url);
    return { error: result.error };
  };

  const completeGoogleSignIn = async (code: string) => {
    try {
      const { data, error } = await withAuthTimeout(finishGoogleOAuth(code), 'Google sign-in');
      if (!error) {
        setSession(data.session);
        setUser(data.user);
      }
      return { error };
    } catch {
      return { error: new Error('Google sign-in could not be completed. Start again from the sign-in page in this browser tab.') };
    }
  };

  const signOut = async () => {
    await getSupabaseClient().auth.signOut();
    setSession(null);
    setUser(null);
  };

  /* Memoized so a re-render of the provider that changed nothing does not hand
     every consumer a new context object. Combined with the value-comparison in
     `onAuthStateChange`, an alt-tab now produces no state change at all. */
  const value = useMemo(
    () => ({ user, session, loading, signIn, signUp, signInWithGoogle, completeGoogleSignIn, signOut }),
    // The auth actions are stable in behaviour and recreated each render only
    // because they are plain closures; identity churn on them is what the
    // consumers must not see.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [user, session, loading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
