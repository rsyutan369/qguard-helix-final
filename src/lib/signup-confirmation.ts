import { SITE } from './site-identity';

export const SIGNUP_CONFIRMATION_PATH = '/auth/confirm';
export const SIGNUP_CONFIRMATION_URL = new URL(SIGNUP_CONFIRMATION_PATH, SITE.origin).href;

export function readSignupConfirmation(hash: string) {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const tokenHash = params.get('token_hash');
  const source = params.get('source') ?? 'primary';
  if (!tokenHash || !/^[A-Za-z0-9_-]{20,256}$/.test(tokenHash)) return null;
  if (source !== 'primary' && source !== 'fallback') return null;
  return { tokenHash, source } as const;
}
