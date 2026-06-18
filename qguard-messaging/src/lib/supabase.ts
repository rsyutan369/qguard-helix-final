import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export const supabaseUrl = (import.meta.env.VITE_SUPABASE_URL as string | undefined)
  || (import.meta.env.NEXT_PUBLIC_SUPABASE_URL as string | undefined)
  || "";
export const supabaseAnonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined)
  || (import.meta.env.NEXT_PUBLIC_SUPABASE_ANON_KEY as string | undefined)
  || "";

const baseSupabaseAuthStorageKey = "qguard-messaging-auth";
const supabaseRequestTimeoutMs = 30_000;
const placeholderSupabaseUrl = "https://qguard-messaging-placeholder.supabase.co";
const placeholderSupabaseAnonKey = "missing-supabase-anon-key";

function getWindowSessionId(): string {
  if (typeof window === "undefined") return "server";
  const key = `${baseSupabaseAuthStorageKey}:window-id`;
  const existing = window.sessionStorage.getItem(key);
  if (existing) return existing;
  const next = crypto.randomUUID();
  window.sessionStorage.setItem(key, next);
  return next;
}

export const SUPABASE_AUTH_STORAGE_KEY = `${baseSupabaseAuthStorageKey}:${getWindowSessionId()}`;

function getProjectRef(url: string): string | null {
  try {
    const hostname = new URL(url).hostname;
    const [projectRef, ...rest] = hostname.split(".");
    return rest.join(".") === "supabase.co" ? projectRef : null;
  } catch {
    return null;
  }
}

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);
export const supabaseProjectRef = getProjectRef(supabaseUrl);
export const supabaseAuthTarget = supabaseProjectRef ? `project ${supabaseProjectRef}` : "Supabase project";

export function getSupabaseConfigError(): Error | null {
  if (isSupabaseConfigured) return null;
  return new Error(
    "QGUARD_SUPABASE_CONFIG_REQUIRED: Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in qguard-messaging/.env.local, then restart QGuard Messaging.",
  );
}

async function timeoutFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const parentSignal = init?.signal;
  const timeoutId = setTimeout(() => controller.abort(), supabaseRequestTimeoutMs);
  const abortFromParent = () => controller.abort();
  if (parentSignal) {
    if (parentSignal.aborted) controller.abort();
    parentSignal.addEventListener("abort", abortFromParent, { once: true });
  }

  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("Supabase request timed out. The project Auth service may be overloaded or unavailable.");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
    parentSignal?.removeEventListener("abort", abortFromParent);
  }
}

const sharedSupabaseOptions = {
  global: {
    fetch: timeoutFetch,
  },
};

export const supabase: SupabaseClient = createClient(
  isSupabaseConfigured ? supabaseUrl : placeholderSupabaseUrl,
  isSupabaseConfigured ? supabaseAnonKey : placeholderSupabaseAnonKey,
  {
    ...sharedSupabaseOptions,
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      storage: typeof window !== "undefined" ? window.sessionStorage : undefined,
      storageKey: SUPABASE_AUTH_STORAGE_KEY,
    },
  },
);

export function requireSupabase(): SupabaseClient {
  const configError = getSupabaseConfigError();
  if (configError) throw configError;
  return supabase;
}

export function createEphemeralSupabaseClient(): SupabaseClient {
  const configError = getSupabaseConfigError();
  if (configError) throw configError;
  return createClient(supabaseUrl, supabaseAnonKey, {
    ...sharedSupabaseOptions,
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}
