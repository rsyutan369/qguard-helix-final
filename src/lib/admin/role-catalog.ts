// Owner Admin > Roles — the ONE role-catalogue model.
//
// Roles are access labels on profiles.role. What a role actually changes on the
// platform today is the Sophia copilot capability set (api-server/copilot
// normalizeRole + ROLE_CAPABILITIES); per-request API authorization is by plan
// tier and the owner account. So each role reports its REAL effect, and the
// stored permission patterns are shown as what they are — descriptive — with
// their true count (the old "256 / 128 / 96 permissions" were invented numbers).
//
// Assignment counts come from the Users directory, so Roles and Users can never
// disagree about who holds which role.

import { lower, modelVersion, paginate, text, type IntegrityCheck } from './model-utils'

export interface RoleRow {
  id: string
  role_key: string | null
  name: string | null
  description: string | null
  role_type: string | null
  status: string | null
  tenant_id: string | null
  permission_scope: string | null
  permissions: string[] | null
  metadata: Record<string, unknown> | null
  created_at: string | null
  updated_at: string | null
}

export interface RoleDefinition {
  role_key: string
  name: string
  description: string
  role_type: 'system'
  permission_scope: string
  permissions: string[]
}

export interface RoleHolder {
  id: string
  email: string
  name: string
  role: string
  isOwner: boolean
}

export interface SophiaEffect {
  role: string
  label: string
  capabilities: { read: boolean; operate: boolean; audit: boolean; executive: boolean }
}

export type RoleType = 'builtin' | 'system' | 'custom' | 'discovered'
export type RoleStatus = 'active' | 'inactive' | 'archived'

export interface CatalogRole {
  /** admin_roles.id — null for built-in / definition-only roles. */
  id: string | null
  key: string
  name: string
  description: string
  type: RoleType
  status: RoleStatus
  /** Cannot be edited or deleted from the console. */
  protected: boolean
  /** Cannot be given to a user (owner / super admin). */
  reserved: boolean
  assignable: boolean
  tenantId: string | null
  tenantName: string | null
  scope: string
  permissions: string[]
  permissionSummary: string
  holders: number
  holderSample: Array<{ id: string; email: string; name: string }>
  sophia: SophiaEffect
  createdAt: string | null
  updatedAt: string | null
}

export interface RoleCatalogStats {
  total: number
  byType: Record<RoleType, number>
  byStatus: Record<RoleStatus, number>
  inUse: number
  unassignedCustom: number
  inactiveButAssigned: number
  usersCovered: number
  totalUsers: number
}

export interface RoleCatalog {
  roles: CatalogRole[]
  stats: RoleCatalogStats
  integrity: IntegrityCheck[]
  version: string
  generatedAt: string
}

export const ROLE_STATUSES: RoleStatus[] = ['active', 'inactive', 'archived']
export const RESERVED_ROLE_KEYS = new Set(['owner', 'super_admin', 'superadmin', 'platform_admin', 'ceo'])
const PERMISSION_PATTERN = /^[a-z*][a-z0-9_*]*(\.[a-z0-9_*]+)*$/

export function normalizeRoleKey(value: unknown): string {
  return lower(value).replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
}

export function roleTitle(key: string): string {
  return key.split('_').filter(Boolean).map((part) => part[0].toUpperCase() + part.slice(1)).join(' ')
}

/** Validate + normalise a permission-pattern list (e.g. `security.read`, `audit.*`). */
export function normalizePermissions(value: unknown): { permissions: string[]; invalid: string[] } {
  const raw = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[\s,]+/) : []
  const permissions: string[] = []
  const invalid: string[] = []
  for (const item of raw) {
    const permission = lower(item)
    if (!permission) continue
    if (!PERMISSION_PATTERN.test(permission) || permission.length > 64) invalid.push(String(item))
    else if (!permissions.includes(permission)) permissions.push(permission)
  }
  return { permissions: permissions.slice(0, 50), invalid }
}

function permissionSummary(permissions: string[]): string {
  if (permissions.includes('*')) return 'All permissions (*)'
  if (!permissions.length) return 'No permission patterns'
  return `${permissions.length} permission pattern${permissions.length === 1 ? '' : 's'}`
}

function roleStatus(value: unknown): RoleStatus {
  const status = lower(value)
  return status === 'inactive' || status === 'archived' ? status : 'active'
}

export function buildRoleCatalog(input: {
  rows: RoleRow[]
  definitions: RoleDefinition[]
  holders: RoleHolder[]
  tenants: Array<{ id: string; name: string | null }>
  sophiaFor: (roleKey: string, isOwner: boolean) => SophiaEffect
  now?: number
}): RoleCatalog {
  const now = input.now ?? Date.now()
  const tenantNames = new Map(input.tenants.map((tenant) => [tenant.id, text(tenant.name) || null]))
  const holdersByRole = new Map<string, RoleHolder[]>()
  for (const holder of input.holders) {
    const list = holdersByRole.get(holder.role) || []
    list.push(holder)
    holdersByRole.set(holder.role, list)
  }

  const byKey = new Map<string, CatalogRole>()
  const make = (partial: Omit<CatalogRole, 'holders' | 'holderSample' | 'sophia' | 'assignable' | 'permissionSummary'>): CatalogRole => {
    const holders = holdersByRole.get(partial.key) || []
    return {
      ...partial,
      permissionSummary: permissionSummary(partial.permissions),
      holders: holders.length,
      holderSample: holders.slice(0, 5).map((holder) => ({ id: holder.id, email: holder.email, name: holder.name })),
      sophia: input.sophiaFor(partial.key, partial.key === 'owner'),
      assignable: partial.status === 'active' && !partial.reserved,
    }
  }

  // Built-in roles every account resolves to without a catalogue row.
  byKey.set('owner', make({
    id: null, key: 'owner', name: 'Owner', description: 'The platform owner account. Full access by design; granted by the owner e-mail, never assignable.',
    type: 'builtin', status: 'active', protected: true, reserved: true, tenantId: null, tenantName: null, scope: 'All', permissions: ['*'], createdAt: null, updatedAt: null,
  }))
  byKey.set('user', make({
    id: null, key: 'user', name: 'User', description: 'Default role of every account without an explicit role: module access follows the account’s plan; Sophia is read-only (Security Analyst).',
    type: 'builtin', status: 'active', protected: true, reserved: false, tenantId: null, tenantName: null, scope: 'Plan-based', permissions: [], createdAt: null, updatedAt: null,
  }))

  const definitionKeys = new Set(input.definitions.map((definition) => definition.role_key))
  for (const definition of input.definitions) {
    byKey.set(definition.role_key, make({
      id: null, key: definition.role_key, name: definition.name, description: definition.description, type: 'system', status: 'active',
      protected: true, reserved: RESERVED_ROLE_KEYS.has(definition.role_key), tenantId: null, tenantName: null,
      scope: definition.permission_scope, permissions: definition.permissions, createdAt: null, updatedAt: null,
    }))
  }

  for (const row of input.rows) {
    const key = normalizeRoleKey(row.role_key || row.name)
    if (!key || key === 'owner' || key === 'user') continue
    const isSystem = definitionKeys.has(key) || lower(row.role_type) === 'system'
    const definition = input.definitions.find((candidate) => candidate.role_key === key)
    const permissions = Array.isArray(row.permissions) && row.permissions.length ? row.permissions.map((item) => lower(item)).filter(Boolean) : definition?.permissions || []
    const tenantId = text(row.tenant_id) || null
    byKey.set(key, make({
      id: row.id,
      key,
      name: text(row.name) || definition?.name || roleTitle(key),
      description: text(row.description) || definition?.description || '',
      type: isSystem ? 'system' : 'custom',
      status: roleStatus(row.status),
      protected: isSystem || Boolean(row.metadata && (row.metadata as Record<string, unknown>).protected === true),
      reserved: RESERVED_ROLE_KEYS.has(key),
      tenantId,
      tenantName: tenantId ? tenantNames.get(tenantId) || null : null,
      scope: text(row.permission_scope) || definition?.permission_scope || (permissions.includes('*') ? 'All' : 'Custom'),
      permissions,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }))
  }

  // A role held by users but absent from the catalogue is drift, not a role.
  for (const key of holdersByRole.keys()) {
    if (byKey.has(key)) continue
    byKey.set(key, make({
      id: null, key, name: roleTitle(key), description: 'Held by users but missing from the role catalogue.',
      type: 'discovered', status: 'active', protected: false, reserved: RESERVED_ROLE_KEYS.has(key), tenantId: null, tenantName: null,
      scope: 'Unknown', permissions: [], createdAt: null, updatedAt: null,
    }))
  }

  const typeOrder: Record<RoleType, number> = { builtin: 0, system: 1, custom: 2, discovered: 3 }
  const roles = Array.from(byKey.values()).sort((a, b) => typeOrder[a.type] - typeOrder[b.type] || a.name.localeCompare(b.name))
  const count = (predicate: (role: CatalogRole) => boolean) => roles.reduce((sum, role) => sum + (predicate(role) ? 1 : 0), 0)
  const usersCovered = roles.reduce((sum, role) => sum + role.holders, 0)
  const stats: RoleCatalogStats = {
    total: roles.length,
    byType: { builtin: count((r) => r.type === 'builtin'), system: count((r) => r.type === 'system'), custom: count((r) => r.type === 'custom'), discovered: count((r) => r.type === 'discovered') },
    byStatus: { active: count((r) => r.status === 'active'), inactive: count((r) => r.status === 'inactive'), archived: count((r) => r.status === 'archived') },
    inUse: count((r) => r.holders > 0),
    unassignedCustom: count((r) => r.type === 'custom' && r.holders === 0),
    inactiveButAssigned: count((r) => r.status !== 'active' && r.holders > 0),
    usersCovered,
    totalUsers: input.holders.length,
  }
  const integrity: IntegrityCheck[] = [
    { id: 'holders-sum', label: 'Every user holds exactly one role', ok: usersCovered === input.holders.length, detail: `${usersCovered} role assignments for ${input.holders.length} users` },
    { id: 'no-discovered', label: 'Every held role is in the catalogue', ok: stats.byType.discovered === 0, detail: stats.byType.discovered ? `${stats.byType.discovered} role(s) held by users but missing from the catalogue` : 'All held roles are catalogued' },
    { id: 'no-inactive-assigned', label: 'No inactive or archived role is still assigned', ok: stats.inactiveButAssigned === 0, detail: stats.inactiveButAssigned ? `${stats.inactiveButAssigned} inactive/archived role(s) still assigned` : 'None' },
  ]
  const model = { roles, stats, integrity }
  return { ...model, version: modelVersion(model), generatedAt: new Date(now).toISOString() }
}

export interface RoleQuery {
  search?: string
  type?: string
  status?: string
  tenant?: string
  usage?: string
  page?: number
  limit?: number
}

export function queryRoleCatalog(catalog: RoleCatalog, query: RoleQuery) {
  const search = lower(query.search)
  const filtered = catalog.roles.filter((role) => {
    if (search && !`${role.name} ${role.key} ${role.description} ${role.permissions.join(' ')}`.toLowerCase().includes(search)) return false
    if (query.type && query.type !== 'all' && role.type !== query.type) return false
    if (query.status && query.status !== 'all' && role.status !== query.status) return false
    if (query.tenant && query.tenant !== 'all' && (query.tenant === 'platform' ? Boolean(role.tenantId) : role.tenantId !== query.tenant)) return false
    if (query.usage === 'in_use' && role.holders === 0) return false
    if (query.usage === 'unassigned' && role.holders > 0) return false
    return true
  })
  return paginate(filtered, query.page, query.limit)
}
