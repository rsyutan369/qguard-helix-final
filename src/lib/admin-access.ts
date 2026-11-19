export const ADMIN_OWNER_EMAIL = 'zachmatthew369@gmail.com'

export function normalizeEmail(email?: string | null): string {
  return String(email || '').trim().toLowerCase()
}

export function isOwnerEmail(email?: string | null): boolean {
  return normalizeEmail(email) === ADMIN_OWNER_EMAIL
}
