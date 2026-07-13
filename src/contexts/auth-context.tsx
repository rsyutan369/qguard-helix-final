import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  canUseFallbackSupabase,
  getSupabaseClient,
  switchToFallbackSupabase,
} from '../lib/supabase';
import type { User, Session } from '@supabase/supabase-js';

const AUTH_TIMEOUT_MS = 12000;

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: Error | null }>;
  signUp: (email: string, password: string) => Promise<{ error: Error | null }>;
  signInWithGoogle: () => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function toAuthError(error: unknown, fallbackMessage: string): Error {
  return error instanceof Error ? error : new Error(fallbackMessage);
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

      if ((error || !session) && canUseFallbackSupabase()) {
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
        setSession(nextSession);
        setUser(nextSession?.user ?? null);
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

  const signUp = async (email: string, password: string) => {
    // Register through the platform API first: client-side auth.signUp sends a
    // confirmation email via Supabase's built-in mailer (~2/hour quota), so a
    // few registrations produce 429 "email rate limit exceeded" for everyone.
    // The server creates the account with the service role — no email, no
    // mailer quota — and we establish the session with a normal password
    // sign-in. Deployments without the API (static hosting) fall through to
    // the original client-side flow below.
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
      // 404/503/5xx → endpoint unavailable or confirmation required on this
      // deployment; use the standard Supabase signup flow (real confirmation
      // email) instead.
    } catch {
      // API unreachable — fall through to the client-side flow.
    }

    let client = getSupabaseClient();
    let { data, error } = await withAuthTimeout(
      client.auth.signUp({ email, password }),
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
          client.auth.signUp({ email, password }),
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

  const signInWithGoogle = async () => {
    const redirectTo = `${window.location.origin}/dashboard`;
    let client = getSupabaseClient();
    let { error } = await withAuthTimeout(
      client.auth.signInWithOAuth({
        provider: 'google',
        options: { redirectTo },
      }),
      'Supabase OAuth sign-in',
    ).catch((err) => ({
      data: { provider: null, url: null },
      error: toAuthError(err, 'Supabase OAuth sign-in failed.'),
    }));
    if (error && canUseFallbackSupabase()) {
      const fallbackClient = switchToFallbackSupabase();
      if (fallbackClient) {
        client = fallbackClient;
        const fallbackResult = await withAuthTimeout(
          client.auth.signInWithOAuth({
            provider: 'google',
            options: { redirectTo },
          }),
          'Fallback Supabase OAuth sign-in',
        ).catch((err) => ({
          data: { provider: null, url: null },
          error: toAuthError(err, 'Fallback Supabase OAuth sign-in failed.'),
        }));
        error = fallbackResult.error;
      }
    }
    return { error };
  };

  const signOut = async () => {
    await getSupabaseClient().auth.signOut();
    setSession(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, session, loading, signIn, signUp, signInWithGoogle, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
