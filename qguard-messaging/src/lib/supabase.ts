import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export const supabaseUrl = (import.meta.env.VITE_SUPABASE_URL as string | undefined)
  || (import.meta.env.NEXT_PUBLIC_SUPABASE_URL as string | undefined)
  || "";
export const supabaseAnonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined)
  || (import.meta.env.NEXT_PUBLIC_SUPABASE_ANON_KEY as string | undefined)
  || "";

export const SUPABASE_AUTH_STORAGE_KEY = "qguard-messaging-auth";

export const supabase: SupabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: false,
    storageKey: SUPABASE_AUTH_STORAGE_KEY,
  },
});

export function requireSupabase(): SupabaseClient {
  return supabase;
}

export function createEphemeralSupabaseClient(): SupabaseClient {
  return createClient(supabaseUrl, supabaseAnonKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}
