import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { readSignupConfirmation, SIGNUP_CONFIRMATION_PATH } from '@/lib/signup-confirmation';
import { confirmSignupEmail } from '@/lib/supabase';
import { AuthAlert, AuthCard, AuthShell } from '../AuthShell';

export default function ConfirmEmailPage() {
  const [confirmation, setConfirmation] = useState(() => readSignupConfirmation(window.location.hash));
  const [state, setState] = useState<'idle' | 'verifying' | 'verified' | 'error'>('idle');
  const inFlight = useRef(false);

  useEffect(() => {
    // Supabase's legacy redirect can contain session tokens for the default
    // template. Let the main auth client handle that fragment.
    if (new URLSearchParams(window.location.hash.slice(1)).has('token_hash')) {
      window.history.replaceState(window.history.state, '', SIGNUP_CONFIRMATION_PATH);
    }
  }, []);

  async function verify() {
    if (!confirmation || inFlight.current) return;
    inFlight.current = true;
    setState('verifying');
    const verified = await confirmSignupEmail(confirmation.tokenHash, confirmation.source).catch(() => false);
    setConfirmation(null);
    setState(verified ? 'verified' : 'error');
  }

  const canVerify = confirmation !== null;

  return (
    <AuthShell mode="register" nextQuery="">
      <AuthCard
        kicker="Account verification"
        heading={state === 'verified' ? 'Email confirmed' : 'Confirm your email'}
        sub={state === 'verified'
          ? 'Your email address is verified. You can now sign in.'
          : canVerify
            ? 'Confirm your email address to finish creating your Qguard Helix account.'
            : 'Open the verification link from your inbox. If you already confirmed your email, you can sign in.'}
      >
        {state === 'error' && (
          <AuthAlert tone="error">This link could not be verified. It may have expired or been used. Start again from registration to request a fresh email.</AuthAlert>
        )}
        {canVerify ? (
          <button
            type="button"
            className="lp-btn lp-btn--primary lp-btn--block"
            disabled={state === 'verifying'}
            onClick={verify}
          >
            {state === 'verifying' ? 'Confirming…' : 'Confirm email'}
          </button>
        ) : (
          <Link to={state === 'error' ? '/register' : '/login'} className="lp-btn lp-btn--primary lp-btn--block">
            {state === 'error' ? 'Go to registration' : 'Sign in'}
          </Link>
        )}
        <p className="lp-auth__card-foot"><Link to="/" className="lp-link">Qguard Helix homepage</Link></p>
      </AuthCard>
    </AuthShell>
  );
}
