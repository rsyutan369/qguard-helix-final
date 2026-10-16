// Cold-launch PIN unlock: phases between "PIN accepted" and "app shell ready".
//
// On Android the Supabase session lives only in the PIN-wrapped app-lock vault
// (sessionStorage does not survive the process). A correct PIN restores it in
// stages: `applock_unlock` (flips `locked` false at once) -> `setSession` ->
// the auth context's async onAuthStateChange processing -> `auth.user`. The
// PIN gate used to key off `locked` alone, so it dropped at the first stage and
// the email/password LoginPage flashed until `auth.user` arrived. The gate now
// also stays up while this phase is not "idle".
//
//   "restoring": unlock / setSession / revocation check in flight
//   "applied":   session handed to Supabase; waiting for the auth context

export type PinRestorePhase = "idle" | "restoring" | "applied";

/**
 * Next phase given the auth context. The gate is released once the restored
 * session has landed (`signedIn`), or once its processing finished WITHOUT one
 * (MFA/validation failure) so the LoginPage can show the real error instead of
 * a stuck, disabled keypad. "restoring" is only left by the unlock flow itself.
 */
export function settlePinRestore(
  phase: PinRestorePhase,
  auth: { signedIn: boolean; loading: boolean },
): PinRestorePhase {
  if (phase === "idle") return phase;
  if (auth.signedIn) return "idle";
  if (phase === "applied" && !auth.loading) return "idle";
  return phase;
}
