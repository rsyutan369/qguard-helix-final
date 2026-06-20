import { useAuth } from "@/lib/auth-context";

/**
 * The single administrator allowed to see backend/telemetry/hardening internals.
 * Normal users only see their own security posture, not backend plumbing.
 */
export const ADMIN_EMAIL = "zachmatthew369@gmail.com";

export function isAdminEmail(email: string | null | undefined): boolean {
  return (email ?? "").trim().toLowerCase() === ADMIN_EMAIL;
}

/** Admin check for the currently authenticated user. */
export function useIsAdmin(): boolean {
  const { user } = useAuth();
  return isAdminEmail(user?.email);
}