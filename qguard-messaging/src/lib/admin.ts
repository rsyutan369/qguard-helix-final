import { useEffect, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { useAuth } from "@/lib/auth-context";
import { supabase } from "@/lib/supabase";

/**
 * Who may see backend/telemetry/hardening internals (roadmap 10.3).
 *
 * Roles are granted server-side in `messaging_app_roles` (migration 041) —
 * service role only; a user can read just their own row. This gates DISPLAY:
 * every internal panel shows the caller's own RLS-scoped data, so nothing
 * privileged depends on it. Normal users see their own security posture, not
 * backend plumbing.
 */
export type AppRole = "operator";

export function parseAppRole(value: unknown): AppRole | null {
  return value === "operator" ? "operator" : null;
}

/** The signed-in user's role, or null (none, or a database without migration 041). */
export async function fetchAppRole(userId: string, client: Pick<SupabaseClient, "from"> = supabase): Promise<AppRole | null> {
  try {
    const { data, error } = await client.from("messaging_app_roles").select("role").eq("user_id", userId).maybeSingle();
    if (error || !data) return null;
    return parseAppRole((data as { role?: unknown }).role);
  } catch {
    return null;
  }
}

// One lookup per user per app session; roles change rarely and only server-side.
const roleCache = new Map<string, Promise<AppRole | null>>();

/** Operator check for the currently authenticated user. False until known. */
export function useIsAdmin(): boolean {
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const [role, setRole] = useState<{ userId: string; role: AppRole | null } | null>(null);

  useEffect(() => {
    if (!userId) return undefined;
    let cancelled = false;
    let pending = roleCache.get(userId);
    if (!pending) {
      pending = fetchAppRole(userId);
      roleCache.set(userId, pending);
    }
    void pending.then((next) => { if (!cancelled) setRole({ userId, role: next }); });
    return () => { cancelled = true; };
  }, [userId]);

  return Boolean(userId && role?.userId === userId && role.role === "operator");
}
