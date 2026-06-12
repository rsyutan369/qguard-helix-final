export const ADMIN_OWNER_EMAIL = 'zachmatthew369@gmail.com'

const ADMIN_ROLES = new Set(['owner', 'super_admin', 'superadmin', 'platform_admin'])

export function normalizeEmail(email?: string | null): string {
  return String(email || '').trim().toLowerCase()
}

export function isOwnerEmail(email?: string | null): boolean {
  return normalizeEmail(email) === ADMIN_OWNER_EMAIL
}

export function hasAdminRole(role?: unknown): boolean {
  return ADMIN_ROLES.has(String(role || '').trim().toLowerCase())
}

export function readMetadataRole(metadata?: unknown): string {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return ''
  const record = metadata as Record<string, unknown>
  return String(record.platformRole || record.platform_role || record.role || '')
}

export function canUseAdminDashboard(identity: {
  email?: string | null
  role?: unknown
  app_metadata?: unknown
  user_metadata?: unknown
}): boolean {
  if (isOwnerEmail(identity.email)) return true
  return hasAdminRole(identity.role) ||
    hasAdminRole(readMetadataRole(identity.app_metadata)) ||
    hasAdminRole(readMetadataRole(identity.user_metadata))
}
