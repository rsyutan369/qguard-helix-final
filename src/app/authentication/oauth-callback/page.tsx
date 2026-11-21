import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/auth-context'
import { clearAuthReturnUrl } from '@/lib/oauth-callback'
import { PUBLIC_SCAN_LOGIN, PUBLIC_SCAN_OAUTH_KEY, PUBLIC_SCAN_PATH } from '@/lib/public-scan-auth'
import { AuthAlert, AuthCard, AuthShell } from '../AuthShell'

export default function OAuthCallbackPage() {
  const [callback] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    return {
      code: params.get('code'),
      denied: params.has('error'),
      forPublicScan: import.meta.env.VITE_SITE_EDITION === 'public' || sessionStorage.getItem(PUBLIC_SCAN_OAUTH_KEY) === '1',
    }
  })
  const [error, setError] = useState<string | null>(null)
  const { completeGoogleSignIn } = useAuth()
  const navigate = useNavigate()
  const pending = useRef<Promise<{ error: Error | null }> | null>(null)

  useEffect(() => {
    clearAuthReturnUrl()
    sessionStorage.removeItem(PUBLIC_SCAN_OAUTH_KEY)
    if (callback.denied || !callback.code) {
      setError('Google sign-in was cancelled or this link has expired. Start again from the sign-in page.')
      return
    }
    // React StrictMode replays effects. Exchange this single-use code once.
    pending.current ??= completeGoogleSignIn(callback.code)
    let mounted = true
    void pending.current.then((result) => {
      if (!mounted) return
      if (result.error) {
        setError('Google sign-in could not be completed. Start again from the sign-in page in this browser tab.')
        return
      }
      let destination = callback.forPublicScan ? PUBLIC_SCAN_PATH : '/dashboard'
      try {
        if (!callback.forPublicScan && localStorage.getItem('qguard.pendingCheckout')) destination = '/checkout'
      } catch {
        // The dashboard remains available without browser storage.
      }
      navigate(destination, { replace: true })
    })
    return () => { mounted = false }
  }, [callback, completeGoogleSignIn, navigate])

  return (
    <AuthShell mode="login" nextQuery="">
      <AuthCard
        kicker="Google sign-in"
        heading={error ? 'Sign-in could not finish' : 'Completing sign-in'}
        sub={error ? 'Return to sign-in to try again.' : 'Connecting your Google account to Qguard Helix.'}
      >
        {error ? (
          <>
            <AuthAlert tone="error">{error}</AuthAlert>
            <Link to={callback.forPublicScan ? PUBLIC_SCAN_LOGIN : '/login'} className="lp-btn lp-btn--primary lp-btn--block">Return to sign-in</Link>
          </>
        ) : <p role="status" aria-live="polite">Completing sign-in…</p>}
      </AuthCard>
    </AuthShell>
  )
}
