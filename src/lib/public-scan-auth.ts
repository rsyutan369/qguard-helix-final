export const PUBLIC_SCAN_PATH = '/public-scan'
export const PUBLIC_SCAN_LOGIN = '/login?next=%2Fpublic-scan'
export const PUBLIC_SCAN_REGISTER = '/register?next=%2Fpublic-scan'
export const PUBLIC_SCAN_CONFIRMATION_PATH = '/auth/confirm/public-scan'
export const PUBLIC_SCAN_DRAFT_KEY = 'qguard.publicScanDraft'
export const PUBLIC_SCAN_OAUTH_KEY = 'qguard.publicScanOAuth'

export function safeAuthDestination(value: string | null): string | null {
  if (!value?.startsWith('/') || value.startsWith('//') || /[\\\x00-\x1f\x7f]/u.test(value)) return null
  return value
}
