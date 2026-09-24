// Password-recovery redirect handling.
//
// A recovery link (sent by "Forgot password", or by the Owner Admin Users
// console) lands on `…/reset-password#access_token=…&type=recovery`. supabase-js
// consumes that hash asynchronously and strips it, and emits PASSWORD_RECOVERY
// only to listeners that already exist — the AuthProvider subscribes later.
// So the fact "this session came from a recovery link" is captured here,
// synchronously, before the client can erase it. If Supabase Auth fell back to
// the Site URL (redirect not allow-listed), the path is rewritten to
// /reset-password with the hash intact so the right page renders.

const FLAG_KEY = 'qg-password-recovery'
/** A recovery session is only offered for this long after the link was opened. */
const RECOVERY_WINDOW_MS = 60 * 60_000

export const RESET_PASSWORD_PATH = '/reset-password'

function hashParams(): URLSearchParams {
  return new URLSearchParams(window.location.hash.replace(/^#/, ''))
}

export function capturePasswordRecoveryRedirect() {
  if (typeof window === 'undefined') return
  const params = hashParams()
  if (params.get('type') !== 'recovery') return
  try {
    window.sessionStorage.setItem(FLAG_KEY, String(Date.now()))
  } catch {
    // Storage unavailable (private mode): the page falls back to the hash check.
  }
  if (window.location.pathname !== RESET_PASSWORD_PATH && window.location.pathname !== `/authentication${RESET_PASSWORD_PATH}`) {
    window.history.replaceState(window.history.state, '', `${RESET_PASSWORD_PATH}${window.location.search}${window.location.hash}`)
  }
}

export function isPasswordRecoveryPending(): boolean {
  if (typeof window === 'undefined') return false
  if (hashParams().get('type') === 'recovery') return true
  try {
    const at = Number(window.sessionStorage.getItem(FLAG_KEY))
    return Number.isFinite(at) && at > 0 && Date.now() - at < RECOVERY_WINDOW_MS
  } catch {
    return false
  }
}

/** Supabase Auth reports an invalid/expired link through the hash. */
export function passwordRecoveryLinkError(): string | null {
  if (typeof window === 'undefined') return null
  const params = hashParams()
  const description = params.get('error_description')
  if (!params.get('error') && !description) return null
  return (description || 'This password reset link is invalid or has expired.').replace(/\+/g, ' ')
}

export function clearPasswordRecovery() {
  try {
    window.sessionStorage.removeItem(FLAG_KEY)
  } catch {
    // nothing to clear
  }
}
