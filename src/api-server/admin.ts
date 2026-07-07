import { Router, Request, Response, NextFunction } from 'express'
import type { User } from '@supabase/supabase-js'
import { getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'

type AdminRequest = Request & {
  adminUser?: User
  adminToken?: string
  adminDb?: any
}

type SafeContext = {
  unavailable: Set<string>
}

const router = Router()
const DEFAULT_LIMIT = 25
const MAX_LIMIT = 100

function readQueryToken(req: Request): string | null {
  const queryToken = req.query.token
  return typeof queryToken === 'string' && queryToken ? queryToken : null
}

function readClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim()
  const realIp = req.headers['x-real-ip']
  if (typeof realIp === 'string' && realIp.trim()) return realIp.trim()
  return req.ip || req.socket.remoteAddress || 'unknown'
}

function recordOf(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function numberValue(value: unknown, fallback = 0): number {
  const num = Number(value)
  return Number.isFinite(num) ? num : fallback
}

function booleanValue(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') return ['true', '1', 'yes', 'enabled'].includes(value.toLowerCase())
  return fallback
}

function percent(value: number, total: number): number {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return 0
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)))
}

function parsePagination(req: Request) {
  const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1)
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(String(req.query.limit || DEFAULT_LIMIT), 10) || DEFAULT_LIMIT))
  const from = (page - 1) * limit
  const to = from + limit - 1
  return { page, limit, from, to }
}

function cleanSearch(value: unknown): string {
  return String(value || '').replace(/[,%]/g, ' ').replace(/\s+/g, ' ').trim()
}

function jsonError(res: Response, status: number, code: string, message: string) {
  res.status(status).json({ error: { code, message } })
}

async function safeRows(ctx: SafeContext, client: any, table: string, build: (query: any) => any) {
  try {
    const query = build(client.from(table))
    const { data, error } = await query
    if (error) {
      ctx.unavailable.add(table)
      return []
    }
    return data || []
  } catch {
    ctx.unavailable.add(table)
    return []
  }
}

async function optionalRows(client: any, table: string, build: (query: any) => any) {
  try {
    const query = build(client.from(table))
    const { data, error } = await query
    if (error) return []
    return data || []
  } catch {
    return []
  }
}

async function safeCount(ctx: SafeContext, client: any, table: string, build?: (query: any) => any) {
  try {
    let query = client.from(table).select('id', { count: 'exact', head: true })
    if (build) query = build(query)
    const { count, error } = await query
    if (error) {
      ctx.unavailable.add(table)
      return 0
    }
    return count || 0
  } catch {
    ctx.unavailable.add(table)
    return 0
  }
}

async function safeMaybeSingle(ctx: SafeContext, client: any, table: string, build: (query: any) => any) {
  try {
    const { data, error } = await build(client.from(table)).maybeSingle()
    if (error) {
      ctx.unavailable.add(table)
      return null
    }
    return data || null
  } catch {
    ctx.unavailable.add(table)
    return null
  }
}

async function safeInsert(ctx: SafeContext, client: any, table: string, payload: Record<string, unknown>) {
  try {
    const { error } = await client.from(table).insert(payload)
    if (error) ctx.unavailable.add(table)
  } catch {
    ctx.unavailable.add(table)
  }
}

function assertNoSupabaseError(result: any, fallback: string) {
  if (result?.error) throw new Error(result.error.message || fallback)
}

function prettifyAdminAction(action: unknown): string {
  const normalized = textValue(action, 'admin.event')
    .replace(/^admin\./, '')
    .replace(/[._-]+/g, ' ')
    .trim()
  return normalized
    ? normalized.replace(/\b\w/g, (letter) => letter.toUpperCase())
    : 'Admin Event'
}

function activitySeverity(action: unknown, details: Record<string, unknown> = {}): string {
  const normalized = `${textValue(action, '')} ${textValue(details.status, '')} ${textValue(details.result, '')}`.toLowerCase()
  if (/failed|error|delete|disabled|suspend/.test(normalized)) return 'warning'
  if (/restore|approve|active|completed|success/.test(normalized)) return 'info'
  return 'info'
}

function adminAuditTarget(row: any, details: Record<string, unknown>): string {
  const targetName = textValue(details.targetName || details.name || details.full_name, '')
  const targetEmail = textValue(details.targetEmail || details.email, '')
  const targetId = textValue(details.targetUserId || row.entity_id || details.entityId, '')
  const entityType = textValue(row.entity_type || details.targetType, 'platform')
  if (targetName && targetEmail) return `${targetName} (${targetEmail})`
  return targetEmail || targetName || targetId || prettifyAdminAction(entityType)
}

function normalizeAdminAuditActivity(row: any) {
  const details = recordOf(row.details)
  const action = textValue(row.action, 'admin.event')
  const targetType = textValue(row.entity_type || details.targetType, 'platform')
  const targetId = textValue(row.entity_id || details.targetUserId || details.entityId, '')
  const target = adminAuditTarget(row, details)
  const actorEmail = textValue(row.actor_email || details.actorEmail, '')
  const result = textValue(details.status || details.result, 'completed')

  return {
    id: textValue(row.id, `${action}-${row.created_at || targetId || 'admin-audit'}`),
    source: 'admin_audit',
    severity: activitySeverity(action, details),
    title: prettifyAdminAction(action),
    detail: `${actorEmail || 'Administrator'} performed ${prettifyAdminAction(action).toLowerCase()} on ${target}`,
    created_at: row.created_at,
    actorEmail,
    actorId: row.actor_user_id || null,
    administrator: actorEmail || 'Administrator',
    action,
    targetType,
    targetId,
    target,
    result,
    ipAddress: row.ip_address || null,
    row,
  }
}

function normalizeGenericActivity(row: any, source: string, defaults: { title?: string; detail?: string; severity?: string; createdAt?: string } = {}) {
  const details = recordOf(row.details || row.metadata)
  const action = textValue(row.action || row.event_type || row.status || defaults.title, 'activity')
  const actorEmail = textValue(details.actorEmail || row.actor_email || row.user_email || row.email || row.user_id, '')
  const targetType = textValue(row.entity_type || row.resource_type || details.targetType || source, source)
  const targetId = textValue(row.entity_id || row.resource_id || details.targetUserId || row.user_id || row.id, '')
  const target = textValue(details.targetEmail || details.targetName || row.resource_name || row.name || row.plan || targetId, targetType)

  return {
    id: textValue(row.id, `${source}-${defaults.createdAt || row.created_at || row.updated_at || targetId || action}`),
    source,
    severity: textValue(row.severity || defaults.severity, 'info'),
    title: textValue(defaults.title, prettifyAdminAction(action)),
    detail: textValue(defaults.detail, row.message || row.description || row.entity_type || row.status || target),
    created_at: defaults.createdAt || row.created_at || row.updated_at,
    actorEmail,
    actorId: row.actor_user_id || row.user_id || null,
    administrator: actorEmail || (source === 'audit_logs' ? 'Administrator' : 'System'),
    action,
    targetType,
    targetId,
    target,
    result: textValue(details.status || details.result || row.status, 'recorded'),
    ipAddress: row.ip_address || null,
    row,
  }
}

async function recordAdminAudit(req: AdminRequest, action: string, entityType: string, entityId?: string | null, details: Record<string, unknown> = {}) {
  const db = req.adminDb
  const actor = req.adminUser
  if (!db || !actor) return

  const payload = {
    actor_user_id: actor.id,
    actor_email: actor.email || null,
    action,
    entity_type: entityType,
    entity_id: entityId || null,
    ip_address: readClientIp(req),
    user_agent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
    details,
    created_at: new Date().toISOString(),
  }

  try {
    await db.from('admin_audit_events').insert(payload)
  } catch {
    // Admin audit should never make the primary operation fail.
  }

  try {
    await db.from('audit_logs').insert({
      user_id: actor.id,
      action,
      entity_type: entityType,
      entity_id: entityId || null,
      details: { ...details, adminAudit: true, actorEmail: actor.email || null },
      created_at: payload.created_at,
    })
  } catch {
    // Older schemas may not have the general audit sink.
  }
}

async function requireOwner(req: AdminRequest, res: Response, next: NextFunction) {
  const token = getToken(req) || readQueryToken(req)
  if (!token) {
    jsonError(res, 401, 'UNAUTHORIZED', 'Owner session token required')
    return
  }

  const user = await getServerUser(token)
  if (!user) {
    jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired owner session')
    return
  }

  if (!isOwnerEmail(user.email)) {
    await tryForbiddenAudit(user, req)
    jsonError(res, 403, 'FORBIDDEN', 'This dashboard is restricted to the QGuardHelix owner')
    return
  }

  const db = getServiceClient()
  if (!db) {
    jsonError(res, 503, 'CONFIG_ERROR', 'Supabase service role is not configured')
    return
  }

  req.adminUser = user
  req.adminToken = token
  req.adminDb = db
  next()
}

async function tryForbiddenAudit(user: User, req: Request) {
  const db = getServiceClient()
  if (!db) return
  try {
    await db.from('admin_audit_events').insert({
      actor_user_id: user.id,
      actor_email: user.email || null,
      action: 'admin.access_denied',
      entity_type: 'admin_dashboard',
      entity_id: null,
      ip_address: readClientIp(req),
      user_agent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
      details: { path: req.originalUrl },
    })
  } catch {
    // Best effort security trace.
  }
}

function profileMetadata(profile: any) {
  return recordOf(profile?.metadata)
}

function userStatus(profile: any) {
  const metadata = profileMetadata(profile)
  return textValue(profile?.account_status || profile?.status || metadata.accountStatus || metadata.account_status, 'active')
}

function tenantIdFor(profile: any) {
  const metadata = profileMetadata(profile)
  return textValue(profile?.tenant_id || metadata.tenantId || metadata.tenant_id, '')
}

function tierFor(profile: any) {
  const metadata = profileMetadata(profile)
  return textValue(profile?.tier || metadata.subscriptionTier || metadata.subscription_tier, 'starter')
}

function mfaRequiredFor(profile: any) {
  const metadata = profileMetadata(profile)
  return booleanValue(profile?.mfa_required ?? metadata.mfaRequired ?? metadata.mfa_required, false)
}

function groupByDay(rows: any[], dateFields: string[], days = 7) {
  const now = new Date()
  const buckets = Array.from({ length: days }, (_unused, index) => {
    const date = new Date(now)
    date.setDate(now.getDate() - (days - index - 1))
    const key = date.toISOString().slice(0, 10)
    return { key, label: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), count: 0 }
  })
  const indexByKey = new Map(buckets.map((bucket, index) => [bucket.key, index]))

  for (const row of rows) {
    const value = dateFields.map((field) => row?.[field]).find(Boolean)
    if (!value) continue
    const key = new Date(value).toISOString().slice(0, 10)
    const index = indexByKey.get(key)
    if (typeof index === 'number') buckets[index].count += 1
  }

  return buckets.map(({ label, count }) => ({ label, count }))
}

function countBy(rows: any[], field: string, fallback = 'unknown') {
  const counts = new Map<string, number>()
  for (const row of rows) {
    const key = textValue(row?.[field], fallback)
    counts.set(key, (counts.get(key) || 0) + 1)
  }
  return Array.from(counts.entries()).map(([label, count]) => ({ label, count }))
}

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

const SYSTEM_ROLE_DEFINITIONS = [
  {
    role_key: 'super_admin',
    name: 'Super Admin',
    description: 'Full access to all platform features, settings, and administrative functions.',
    role_type: 'system',
    status: 'active',
    permission_scope: 'All',
    permission_count: 256,
    permissions: ['*'],
    metadata: { icon: 'crown', protected: true, aliases: ['owner', 'ceo', 'admin', 'super_admin'] },
  },
  {
    role_key: 'security_admin',
    name: 'Security Admin',
    description: 'Manage security configurations, policies, threat response, and audit logs.',
    role_type: 'system',
    status: 'active',
    permission_scope: 'Security',
    permission_count: 128,
    permissions: ['security.*', 'audit.*', 'policies.*'],
    metadata: { icon: 'shield', protected: true, aliases: ['security_admin', 'secadmin'] },
  },
  {
    role_key: 'tenant_admin',
    name: 'Tenant Admin',
    description: 'Manage tenant settings, users, roles, and subscriptions.',
    role_type: 'system',
    status: 'active',
    permission_scope: 'Tenant',
    permission_count: 96,
    permissions: ['tenant.*', 'users.manage', 'subscriptions.manage'],
    metadata: { icon: 'tenant', protected: true, aliases: ['tenant_admin', 'tenantadmin'] },
  },
]

function normalizeRoleKey(value: unknown, fallback = 'user') {
  const cleaned = textValue(value, fallback)
    .toLowerCase()
    .replace(/&/g, 'and')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return cleaned || fallback
}

function titleFromRoleKey(roleKey: string) {
  return roleKey
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function roleAliases(role: any) {
  const metadata = recordOf(role?.metadata)
  const aliases = Array.isArray(metadata.aliases) ? metadata.aliases : []
  return new Set([role?.role_key, role?.name, ...aliases].map((value) => normalizeRoleKey(value, '')).filter(Boolean))
}

function userCountForRole(profiles: any[], role: any) {
  const aliases = roleAliases(role)
  return profiles.filter((profile) => aliases.has(normalizeRoleKey(profile?.role || profileMetadata(profile).role, 'user'))).length
}

function rolePermissions(role: any) {
  return Array.isArray(role?.permissions) ? role.permissions.filter(Boolean) : []
}

function serializeRole(role: any, profiles: any[], tenants: Map<string, any>) {
  const metadata = recordOf(role?.metadata)
  const roleKey = normalizeRoleKey(role?.role_key || role?.name, 'custom_role')
  const permissions = rolePermissions(role)
  const permissionCount = numberValue(role?.permission_count, permissions.length)
  const tenantId = textValue(role?.tenant_id, '')
  const users = userCountForRole(profiles, { ...role, role_key: roleKey })

  return {
    id: role?.id || `system-${roleKey}`,
    roleKey,
    name: textValue(role?.name, titleFromRoleKey(roleKey)),
    description: textValue(role?.description, 'Platform access role'),
    type: textValue(role?.role_type, 'custom'),
    status: textValue(role?.status, 'active'),
    tenantId: tenantId || null,
    tenantName: tenantId ? tenants.get(tenantId)?.name || null : null,
    users,
    permissionScope: textValue(role?.permission_scope, permissions.includes('*') ? 'All' : 'Custom'),
    permissionCount,
    permissions,
    protected: booleanValue(metadata.protected, textValue(role?.role_type, 'custom') === 'system'),
    icon: textValue(metadata.icon, ''),
    createdAt: role?.created_at || null,
    updatedAt: role?.updated_at || null,
    metadata,
  }
}

function buildRoleCatalog(roleRows: any[], profiles: any[], tenantRows: any[]) {
  const tenants = new Map<string, any>(tenantRows.map((tenant) => [String(tenant.id), tenant]))
  const byKey = new Map<string, any>()

  for (const role of SYSTEM_ROLE_DEFINITIONS) byKey.set(role.role_key, role)
  for (const row of roleRows) {
    const roleKey = normalizeRoleKey(row?.role_key || row?.name, '')
    if (!roleKey) continue
    const existing = byKey.get(roleKey)
    byKey.set(roleKey, existing ? { ...existing, ...row, metadata: { ...recordOf(existing.metadata), ...recordOf(row.metadata) } } : row)
  }

  for (const profile of profiles) {
    const roleKey = normalizeRoleKey(profile?.role || profileMetadata(profile).role, '')
    if (!roleKey || byKey.has(roleKey)) continue
    byKey.set(roleKey, {
      role_key: roleKey,
      name: titleFromRoleKey(roleKey),
      description: 'Role discovered from active user profiles.',
      role_type: 'custom',
      status: 'active',
      permission_scope: 'Custom',
      permission_count: 0,
      permissions: [],
      metadata: { discovered: true },
      created_at: profile.created_at || null,
      updated_at: profile.updated_at || null,
    })
  }

  return Array.from(byKey.values()).map((role) => serializeRole(role, profiles, tenants))
}

function filterRoles(roles: any[], query: Request['query']) {
  const search = cleanSearch(query.search)
  const tenantId = textValue(query.tenantId, '')
  const type = textValue(query.type, '')
  const status = textValue(query.status, '')

  return roles.filter((role) => {
    const searchable = `${role.name} ${role.description} ${role.roleKey} ${role.permissionScope}`.toLowerCase()
    if (search && !searchable.includes(search.toLowerCase())) return false
    if (tenantId && tenantId !== 'all') {
      if (tenantId === 'platform' && role.tenantId) return false
      if (tenantId !== 'platform' && role.tenantId !== tenantId) return false
    }
    if (type && type !== 'all' && role.type !== type) return false
    if (status && status !== 'all' && role.status !== status) return false
    return true
  })
}

function roleStats(roles: any[]) {
  const totalRoles = roles.length
  const customRoles = roles.filter((role) => role.type === 'custom').length
  const systemRoles = roles.filter((role) => role.type === 'system').length
  const rolesInUse = roles.filter((role) => role.users > 0).length
  const orphanedRoles = roles.filter((role) => role.users === 0).length

  return {
    totalRoles,
    customRoles,
    systemRoles,
    rolesInUse,
    orphanedRoles,
    customRolesPercent: percent(customRoles, totalRoles),
    systemRolesPercent: percent(systemRoles, totalRoles),
    rolesInUsePercent: percent(rolesInUse, totalRoles),
    roleGrowthPercent: 0,
  }
}

function roleIsProtected(role: any) {
  const roleKey = normalizeRoleKey(role?.role_key || role?.name, '')
  const metadata = recordOf(role?.metadata)
  return textValue(role?.role_type, 'custom') === 'system'
    || booleanValue(metadata.protected, false)
    || SYSTEM_ROLE_DEFINITIONS.some((definition) => definition.role_key === roleKey)
}

function roleAuditDetails(role: any, details: Record<string, unknown> = {}) {
  const permissions = rolePermissions(role)
  return {
    targetType: 'role',
    targetName: textValue(role?.name, titleFromRoleKey(normalizeRoleKey(role?.role_key || role?.name, 'role'))),
    roleKey: normalizeRoleKey(role?.role_key || role?.name, 'role'),
    roleType: textValue(role?.role_type, 'custom'),
    tenantId: textValue(role?.tenant_id, '') || null,
    permissionScope: textValue(role?.permission_scope, permissions.includes('*') ? 'All' : 'Custom'),
    permissionCount: numberValue(role?.permission_count, permissions.length),
    previousStatus: textValue(role?.status, 'active'),
    protected: roleIsProtected(role),
    ...details,
  }
}

function tenantMetadata(tenant: any) {
  return recordOf(tenant?.metadata)
}

function domainForTenant(tenant: any) {
  const metadata = tenantMetadata(tenant)
  const slug = textValue(tenant?.slug, 'tenant')
  return textValue(tenant?.domain || metadata.domain || metadata.primaryDomain || metadata.primary_domain, `${slug}.qguard.app`)
}

function regionForTenant(tenant: any) {
  const metadata = tenantMetadata(tenant)
  return textValue(tenant?.region || metadata.region || metadata.regionCode || metadata.region_code, 'us-east-1')
}

function regionLabel(region: string) {
  if (/ap-southeast-2/i.test(region)) return 'Australia'
  if (/ap-southeast-1/i.test(region)) return 'Singapore'
  if (/eu-west/i.test(region)) return 'United Kingdom'
  if (/ca-central/i.test(region)) return 'Canada'
  if (/us-west|us-east|us-central/i.test(region)) return 'United States'
  return region.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function maxTimestamp(values: Array<unknown>) {
  const times = values
    .map((value) => typeof value === 'string' ? new Date(value).getTime() : 0)
    .filter((value) => Number.isFinite(value) && value > 0)
  return times.length ? new Date(Math.max(...times)).toISOString() : null
}

async function enrichTenant(ctx: SafeContext, db: any, tenant: any) {
  const tenantId = String(tenant.id)
  const metadata = tenantMetadata(tenant)
  const [profileRows, memberRows, subscriptions, scans, securityEvents, ownerProfile] = await Promise.all([
    safeRows(ctx, db, 'profiles', (q) => q.select('id,email,name,full_name,account_status,updated_at,last_sign_in_at').eq('tenant_id', tenantId).limit(1000)),
    safeRows(ctx, db, 'organization_members', (q) => q.select('*').eq('organization_id', tenantId).limit(1000)),
    safeRows(ctx, db, 'billing_subscriptions', (q) => q.select('*').eq('tenant_id', tenantId).order('updated_at', { ascending: false }).limit(100)),
    safeRows(ctx, db, 'pqc_scan_sessions', (q) => q.select('id,status,created_at,updated_at').eq('tenant_id', tenantId).order('updated_at', { ascending: false }).limit(20)),
    safeRows(ctx, db, 'security_events', (q) => q.select('id,severity,event_type,created_at,updated_at').eq('tenant_id', tenantId).order('created_at', { ascending: false }).limit(50)),
    tenant.owner_user_id ? safeMaybeSingle(ctx, db, 'profiles', (q) => q.select('id,email,name,full_name').eq('id', tenant.owner_user_id)) : Promise.resolve(null),
  ])
  const userIds = Array.from(new Set(profileRows.map((row: any) => String(row.id)).filter(Boolean)))
  const [devices, sessions] = userIds.length
    ? await Promise.all([
      safeRows(ctx, db, 'user_devices', (q) => q.select('id,user_id,revoked_at,last_seen_at,updated_at').in('user_id', userIds).limit(2000)),
      safeRows(ctx, db, 'user_sessions', (q) => q.select('id,user_id,revoked_at,last_seen_at,updated_at').in('user_id', userIds).order('last_seen_at', { ascending: false }).limit(2000)),
    ])
    : [[], []]
  const activeUsers = profileRows.filter((row: any) => userStatus(row) === 'active').length || memberRows.filter((row: any) => row.status === 'active').length
  const totalUsers = profileRows.length || memberRows.length
  const activeSubscriptions = subscriptions.filter((row: any) => ['active', 'trialing', 'approved'].includes(String(row.status || '').toLowerCase()))
  const trialSubscriptions = subscriptions.filter((row: any) => String(row.status || '').toLowerCase() === 'trialing')
  const newestSubscription = subscriptions[0] || null
  const expiresAt = newestSubscription?.current_period_end || newestSubscription?.expires_at || newestSubscription?.trial_ends_at || metadata.renewsAt || metadata.renews_at || null
  const region = regionForTenant(tenant)
  const lastActivityAt = maxTimestamp([
    tenant.updated_at,
    ...profileRows.map((row: any) => row.updated_at || row.last_sign_in_at),
    ...sessions.map((row: any) => row.last_seen_at || row.updated_at),
    ...devices.map((row: any) => row.last_seen_at || row.updated_at),
    ...securityEvents.map((row: any) => row.created_at || row.updated_at),
    ...scans.map((row: any) => row.updated_at || row.created_at),
  ])

  return {
    ...tenant,
    domain: domainForTenant(tenant),
    region,
    regionLabel: regionLabel(region),
    totalUsers,
    activeUsers,
    members: totalUsers,
    activeMembers: activeUsers,
    activeSubscriptions: activeSubscriptions.length,
    trialSubscriptions: trialSubscriptions.length,
    subscriptions: subscriptions.length,
    devices: devices.filter((row: any) => !row.revoked_at).length,
    activeDevices: devices.filter((row: any) => !row.revoked_at).length,
    sessions: sessions.filter((row: any) => !row.revoked_at).length,
    scans: scans.length,
    securityEvents: securityEvents.length,
    renewalDate: expiresAt,
    createdBy: ownerProfile?.full_name || ownerProfile?.name || ownerProfile?.email || metadata.createdBy || metadata.created_by || 'System',
    lastActivityAt,
    metadata,
  }
}

function billingMetadata(row: any) {
  return recordOf(row?.metadata)
}

function billingCycleFor(subscription: any) {
  const metadata = billingMetadata(subscription)
  return textValue(subscription?.billing_cycle || subscription?.plan_interval || metadata.billingCycle || metadata.billing_cycle, 'monthly').toLowerCase()
}

function billingRenewalDate(subscription: any) {
  const metadata = billingMetadata(subscription)
  return subscription?.renewal_date
    || subscription?.current_period_end
    || subscription?.expires_at
    || subscription?.trial_ends_at
    || subscription?.trial_expires_at
    || metadata.renewalDate
    || metadata.renewal_date
    || null
}

function planAmountCents(plan: string, cycle: string) {
  const normalizedPlan = plan.toLowerCase()
  const normalizedCycle = cycle.toLowerCase()
  const annual = normalizedCycle.includes('annual') || normalizedCycle.includes('year')
  // Pricing mirrors billing.ts PLAN_CATALOG and the landing pricing page.
  if (normalizedPlan.includes('elite')) return annual ? 180000 : 19900
  if (normalizedPlan.includes('pro')) return annual ? 24000 : 3000
  if (normalizedPlan.includes('basic')) return annual ? 6000 : 800
  if (normalizedPlan.includes('starter')) return annual ? 3600 : 300
  return 0
}

function invoiceTotalCents(invoice: any) {
  return Math.max(0, numberValue(
    invoice?.amount_paid_cents
    ?? invoice?.total_cents
    ?? invoice?.amount_due_cents
    ?? invoice?.amount_paid
    ?? invoice?.total
    ?? invoice?.amount_due
    ?? invoice?.amount
    ?? billingMetadata(invoice).amountCents
    ?? billingMetadata(invoice).amount_cents,
    0,
  ))
}

function invoiceDueCents(invoice: any) {
  const paid = numberValue(invoice?.amount_paid_cents ?? invoice?.amount_paid, 0)
  const due = numberValue(invoice?.amount_due_cents ?? invoice?.amount_due, NaN)
  if (Number.isFinite(due)) return Math.max(0, due)
  return Math.max(0, invoiceTotalCents(invoice) - paid)
}

function subscriptionAmountCents(subscription: any, invoices: any[]) {
  const metadata = billingMetadata(subscription)
  const direct = numberValue(
    subscription?.amount_cents
    ?? subscription?.amount
    ?? subscription?.price_cents
    ?? metadata.amountCents
    ?? metadata.amount_cents
    ?? metadata.priceCents
    ?? metadata.price_cents,
    NaN,
  )
  if (Number.isFinite(direct) && direct > 0) return direct
  const latestInvoiceAmount = invoiceTotalCents(invoices[0])
  if (latestInvoiceAmount > 0) return latestInvoiceAmount
  return planAmountCents(textValue(subscription?.plan, 'starter'), billingCycleFor(subscription))
}

function monthlyRecurringCents(amountCents: number, cycle: string) {
  const normalized = cycle.toLowerCase()
  return normalized.includes('annual') || normalized.includes('year') ? Math.round(amountCents / 12) : amountCents
}

function billingCurrency(subscription: any, invoices: any[]) {
  const metadata = billingMetadata(subscription)
  return textValue(subscription?.currency || metadata.currency || invoices[0]?.currency, 'USD').toUpperCase()
}

function daysUntil(value?: string | null) {
  if (!value) return null
  const diff = new Date(value).getTime() - Date.now()
  return Math.ceil(diff / (24 * 60 * 60_000))
}

function latestRowsByKey(rows: any[], key: string) {
  const map = new Map<string, any[]>()
  for (const row of rows) {
    const id = textValue(row?.[key], '')
    if (!id) continue
    const list = map.get(id) || []
    list.push(row)
    map.set(id, list)
  }
  return map
}

function creditCents(row: any) {
  const metadata = billingMetadata(row)
  return Math.max(0, numberValue(row?.credit_cents ?? row?.credits_cents ?? metadata.creditCents ?? metadata.credit_cents ?? metadata.creditsCents ?? metadata.credits_cents, 0))
}

function billingStatusIsActive(status: string) {
  return ['active', 'approved', 'trialing', 'trial'].includes(status.toLowerCase())
}

function billingEntitlementTier(plan: unknown, status: unknown) {
  const normalizedStatus = textValue(status, '').toLowerCase()
  if (['canceled', 'cancelled', 'inactive', 'deleted'].includes(normalizedStatus)) return 'free'
  return textValue(plan, 'free').toLowerCase()
}

function subscriptionTargetName(subscription: any, profile?: any, tenant?: any) {
  return textValue(
    tenant?.name
    || profile?.full_name
    || profile?.name
    || profile?.email
    || subscription?.tenant_id
    || subscription?.user_id
    || subscription?.id,
    'Billing subscription',
  )
}

function subscriptionAuditDetails(subscription: any, profile: any = null, tenant: any = null, details: Record<string, unknown> = {}) {
  const metadata = billingMetadata(subscription)
  const plan = textValue(subscription?.plan, 'free')
  const cycle = billingCycleFor(subscription)
  return {
    targetType: 'subscription',
    targetName: subscriptionTargetName(subscription, profile, tenant),
    targetUserId: subscription?.user_id || null,
    targetEmail: profile?.email || null,
    tenantId: subscription?.tenant_id || profile?.tenant_id || null,
    tenantName: tenant?.name || null,
    plan,
    billingCycle: cycle,
    amountCents: subscriptionAmountCents(subscription, []),
    currency: textValue(subscription?.currency || metadata.currency, 'USD').toUpperCase(),
    previousStatus: textValue(subscription?.status, 'inactive'),
    previousPlan: plan,
    previousRenewalDate: billingRenewalDate(subscription),
    ...details,
  }
}

async function loadSubscriptionContext(db: any, subscription: any) {
  const profile = subscription?.user_id
    ? await db.from('profiles').select('id,email,name,full_name,tier,tenant_id').eq('id', subscription.user_id).maybeSingle()
    : { data: null, error: null }
  assertNoSupabaseError(profile, 'Failed to load subscription user profile')

  const tenantId = textValue(subscription?.tenant_id || profile.data?.tenant_id, '')
  const tenant = tenantId
    ? await db.from('organizations').select('id,name,slug,plan,status').eq('id', tenantId).maybeSingle()
    : { data: null, error: null }
  assertNoSupabaseError(tenant, 'Failed to load subscription tenant')

  return { profile: profile.data || null, tenant: tenant.data || null }
}

async function syncBillingEntitlements(db: any, subscription: any, plan: unknown, status: unknown) {
  const tier = billingEntitlementTier(plan, status)
  if (subscription?.user_id) {
    const profileUpdate = await db
      .from('profiles')
      .update({ tier, updated_at: new Date().toISOString() })
      .eq('id', subscription.user_id)
      .select('id,tier')
      .maybeSingle()
    assertNoSupabaseError(profileUpdate, 'Failed to sync user billing tier')
    if (!profileUpdate.data) throw new Error('Failed to sync user billing tier: profile not found')
  }

  const tenantId = textValue(subscription?.tenant_id, '')
  if (tenantId) {
    const tenantUpdate = await db
      .from('organizations')
      .update({ plan: tier, updated_at: new Date().toISOString() })
      .eq('id', tenantId)
      .select('id,plan')
      .maybeSingle()
    assertNoSupabaseError(tenantUpdate, 'Failed to sync tenant billing plan')
    if (!tenantUpdate.data) throw new Error('Failed to sync tenant billing plan: tenant not found')
  }
}

function serializeAdminSubscription(subscription: any, maps: {
  profiles: Map<string, any>
  tenants: Map<string, any>
  invoicesByUser: Map<string, any[]>
  invoicesByTenant: Map<string, any[]>
  methodsByUser: Map<string, any[]>
  usersByTenant: Map<string, any[]>
  devicesByTenant: Map<string, any[]>
}) {
  const profile = subscription?.user_id ? maps.profiles.get(subscription.user_id) : null
  const tenantId = textValue(subscription?.tenant_id || profile?.tenant_id, '')
  const tenant = tenantId ? maps.tenants.get(tenantId) : null
  const invoices = [
    ...(subscription?.user_id ? maps.invoicesByUser.get(subscription.user_id) || [] : []),
    ...(tenantId ? maps.invoicesByTenant.get(tenantId) || [] : []),
  ].filter((invoice, index, arr) => arr.findIndex((row) => row.id === invoice.id) === index)
  const paymentMethods = subscription?.user_id ? maps.methodsByUser.get(subscription.user_id) || [] : []
  const cycle = billingCycleFor(subscription)
  const amountCents = subscriptionAmountCents(subscription, invoices)
  const renewalDate = billingRenewalDate(subscription)
  const region = regionForTenant(tenant || {})
  const users = tenantId ? maps.usersByTenant.get(tenantId) || [] : profile ? [profile] : []
  const devices = tenantId ? maps.devicesByTenant.get(tenantId) || [] : []
  const latestInvoice = invoices[0] || null

  return {
    ...subscription,
    plan: textValue(subscription?.plan || tenant?.plan || profile?.tier, 'starter').toLowerCase(),
    status: textValue(subscription?.status, 'inactive'),
    billing_cycle: cycle,
    plan_interval: subscription?.plan_interval || cycle,
    renewalDate,
    amountCents,
    mrrCents: monthlyRecurringCents(amountCents, cycle),
    currency: billingCurrency(subscription, invoices),
    daysUntilRenewal: daysUntil(renewalDate),
    tenant: tenant ? {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      domain: domainForTenant(tenant),
      region,
      regionLabel: regionLabel(region),
    } : null,
    profile: profile ? {
      id: profile.id,
      email: profile.email,
      name: profile.name,
      full_name: profile.full_name,
      tier: profile.tier,
    } : null,
    totalUsers: users.length || numberValue(subscription?.seats, 1),
    totalDevices: devices.filter((device: any) => !device.revoked_at).length,
    invoices: invoices.slice(0, 5),
    latestInvoiceStatus: latestInvoice?.status || null,
    paymentMethods: paymentMethods.slice(0, 2),
    domain: tenant ? domainForTenant(tenant) : null,
    region,
    regionLabel: regionLabel(region),
  }
}

function filterAdminSubscriptions(subscriptions: any[], query: Record<string, unknown>) {
  const search = cleanSearch(query.search)
  const status = textValue(query.status, '')
  const plan = textValue(query.plan, '')
  const region = textValue(query.region, '')

  return subscriptions.filter((subscription) => {
    const searchable = [
      subscription.id,
      subscription.user_id,
      subscription.profile?.email,
      subscription.profile?.name,
      subscription.profile?.full_name,
      subscription.tenant?.name,
      subscription.tenant?.domain,
      subscription.tenant?.slug,
      subscription.plan,
      subscription.status,
    ].filter(Boolean).join(' ').toLowerCase()
    if (search && !searchable.includes(search.toLowerCase())) return false
    if (status && status !== 'all' && String(subscription.status).toLowerCase() !== status.toLowerCase()) return false
    if (plan && plan !== 'all' && String(subscription.plan).toLowerCase() !== plan.toLowerCase()) return false
    if (region && region !== 'all' && String(subscription.region).toLowerCase() !== region.toLowerCase()) return false
    return true
  })
}

async function buildAdminSubscriptionsPayload(db: any, query: Record<string, unknown> = {}, page = 1, limit = DEFAULT_LIMIT) {
  const ctx: SafeContext = { unavailable: new Set() }
  const now = new Date()
  const ytdStart = new Date(Date.UTC(now.getUTCFullYear(), 0, 1)).toISOString()
  const previousWindowStart = new Date(Date.now() - 60 * 24 * 60 * 60_000).toISOString()
  const currentWindowStart = new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString()

  const [subscriptionRows, profiles, tenants, invoices, paymentMethods, devices] = await Promise.all([
    safeRows(ctx, db, 'billing_subscriptions', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'profiles', (q) => q.select('id,email,name,full_name,tier,tenant_id,updated_at,created_at').order('updated_at', { ascending: false }).limit(5000)),
    safeRows(ctx, db, 'organizations', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'billing_invoices', (q) => q.select('*').order('created_at', { ascending: false }).limit(5000)),
    safeRows(ctx, db, 'billing_payment_methods', (q) => q.select('*').is('removed_at', null).order('is_default', { ascending: false }).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'user_devices', (q) => q.select('id,user_id,tenant_id,revoked_at,updated_at,last_seen_at').order('updated_at', { ascending: false }).limit(10000)),
  ])

  const profileMap = new Map<string, any>(profiles.map((profile: any) => [profile.id, profile] as [string, any]))
  const tenantMap = new Map<string, any>(tenants.map((tenant: any) => [tenant.id, tenant] as [string, any]))
  const usersByTenant = latestRowsByKey(profiles, 'tenant_id')
  const devicesByTenant = latestRowsByKey(devices, 'tenant_id')
  const invoicesByUser = latestRowsByKey(invoices, 'user_id')
  const invoicesByTenant = latestRowsByKey(invoices, 'tenant_id')
  const methodsByUser = latestRowsByKey(paymentMethods, 'user_id')

  const allSubscriptions = subscriptionRows.map((subscription: any) => serializeAdminSubscription(subscription, {
    profiles: profileMap,
    tenants: tenantMap,
    invoicesByUser,
    invoicesByTenant,
    methodsByUser,
    usersByTenant,
    devicesByTenant,
  }))

  const filtered = filterAdminSubscriptions(allSubscriptions, query)
  filtered.sort((a, b) => String(b.updated_at || b.created_at || '').localeCompare(String(a.updated_at || a.created_at || '')))

  const activeSubscriptions = allSubscriptions.filter((subscription) => billingStatusIsActive(subscription.status))
  const pastDueSubscriptions = allSubscriptions.filter((subscription) => String(subscription.status).toLowerCase() === 'past_due')
  const ytdInvoices = invoices.filter((invoice: any) => String(invoice.created_at || '') >= ytdStart)
  const currentInvoices = invoices.filter((invoice: any) => String(invoice.created_at || '') >= currentWindowStart)
  const previousInvoices = invoices.filter((invoice: any) => String(invoice.created_at || '') >= previousWindowStart && String(invoice.created_at || '') < currentWindowStart)
  const currentPaid = currentInvoices.reduce((sum: number, invoice: any) => sum + invoiceTotalCents(invoice), 0)
  const previousPaid = previousInvoices.reduce((sum: number, invoice: any) => sum + invoiceTotalCents(invoice), 0)
  const futureRenewals = activeSubscriptions
    .filter((subscription) => subscription.renewalDate && new Date(subscription.renewalDate).getTime() >= Date.now())
    .sort((a, b) => new Date(a.renewalDate).getTime() - new Date(b.renewalDate).getTime())
  const pastDueAmountCents = pastDueSubscriptions.reduce((sum, subscription) => {
    const invoiceDue = subscription.invoices.reduce((invoiceSum: number, invoice: any) => invoiceSum + invoiceDueCents(invoice), 0)
    return sum + (invoiceDue > 0 ? invoiceDue : subscription.amountCents)
  }, 0)

  const from = (page - 1) * limit
  const to = from + limit
  const totalMrrCents = activeSubscriptions.reduce((sum, subscription) => sum + numberValue(subscription.mrrCents, 0), 0)

  return {
    subscriptions: filtered.slice(from, to),
    stats: {
      totalMrrCents,
      totalTenants: tenants.length || new Set(allSubscriptions.map((subscription) => subscription.tenant_id).filter(Boolean)).size,
      activeSubscriptions: activeSubscriptions.length,
      pastDue: pastDueSubscriptions.length,
      pastDueAmountCents,
      nextBillingDate: futureRenewals[0]?.renewalDate || null,
      nextBillingDays: futureRenewals[0]?.daysUntilRenewal ?? null,
      mrrGrowthPercent: previousPaid > 0 ? Math.round(((currentPaid - previousPaid) / previousPaid) * 100) : 0,
    },
    summary: {
      currentBalanceCents: invoices
        .filter((invoice: any) => !['paid', 'succeeded', 'refunded'].includes(String(invoice.status || '').toLowerCase()))
        .reduce((sum: number, invoice: any) => sum + invoiceDueCents(invoice), 0),
      pastDueCents: pastDueAmountCents,
      creditsCents: [...invoices, ...subscriptionRows].reduce((sum: number, row: any) => sum + creditCents(row), 0),
      totalBilledYtdCents: ytdInvoices.reduce((sum: number, invoice: any) => sum + invoiceTotalCents(invoice), 0),
      totalPaidYtdCents: ytdInvoices
        .filter((invoice: any) => ['paid', 'succeeded'].includes(String(invoice.status || '').toLowerCase()))
        .reduce((sum: number, invoice: any) => sum + invoiceTotalCents(invoice), 0),
    },
    upcomingInvoices: futureRenewals.slice(0, 4).map((subscription) => ({
      id: subscription.id,
      tenantName: subscription.tenant?.name || subscription.profile?.email || subscription.user_id,
      dueDate: subscription.renewalDate,
      amountCents: subscription.amountCents,
      currency: subscription.currency,
    })),
    paymentMethods: paymentMethods.slice(0, 4).map((method: any) => ({
      id: method.id,
      userId: method.user_id,
      brand: method.brand || 'Card',
      last4: method.last4 || '',
      expMonth: method.exp_month || null,
      expYear: method.exp_year || null,
      isDefault: Boolean(method.is_default),
      updatedAt: method.updated_at || null,
    })),
    pagination: { page, limit, total: filtered.length, totalPages: Math.ceil(filtered.length / limit) },
    unavailableTables: Array.from(ctx.unavailable).sort(),
    generatedAt: new Date().toISOString(),
  }
}

function eventTimestamp(row: any) {
  return textValue(row?.created_at || row?.updated_at || row?.last_seen_at || row?.timestamp, '')
}

function eventSeverity(row: any) {
  const raw = textValue(row?.severity || row?.threat_level || row?.risk_level || row?.priority || row?.status, 'info').toLowerCase()
  if (/critical|severe/.test(raw)) return 'critical'
  if (/high|blocked|failed|locked/.test(raw)) return 'high'
  if (/medium|warning|warn|review/.test(raw)) return 'medium'
  if (/low|healthy|resolved|success|info/.test(raw)) return raw.includes('low') ? 'low' : 'info'
  return 'info'
}

function eventText(row: any) {
  return [
    row?.event_type,
    row?.action,
    row?.title,
    row?.message,
    row?.description,
    row?.resource_name,
    row?.finding_type,
    row?.algorithm,
    row?.source,
  ].filter(Boolean).join(' ')
}

function eventTitle(row: any) {
  return textValue(row?.title || row?.event_type || row?.action || row?.finding_type || row?.resource_name, 'Security event')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function threatBucket(row: any) {
  const text = eventText(row).toLowerCase()
  if (/brute|failed|login|auth|credential|password/.test(text)) return { title: 'Brute Force Login Attempts', detail: 'SSH, RDP, VPN' }
  if (/privilege|role|admin|escalat|permission|policy/.test(text)) return { title: 'Suspicious Privilege Escalation', detail: 'IAM, Role manipulation' }
  if (/ip|geo|network|connection|region|malicious/.test(text)) return { title: 'Malicious IP Connections', detail: 'Multiple regions' }
  if (/exfil|download|export|transfer|leak|data/.test(text)) return { title: 'Unusual Data Exfiltration', detail: 'Large outbound transfers' }
  if (/crypto|algorithm|rsa|tls|certificate|pqc|deprecated|weak|vulnerab/.test(text)) return { title: 'Vulnerable Crypto Usage', detail: 'Weak or deprecated algorithms' }
  return { title: eventTitle(row), detail: textValue(row?.resource_type || row?.source || row?.entity_type, 'Live telemetry') }
}

function buildThreatActivity(events: any[]) {
  const now = Date.now()
  const windowMs = 24 * 60 * 60_000
  const bucketMs = 4 * 60 * 60_000
  const buckets = Array.from({ length: 7 }, (_unused, index) => {
    const start = now - windowMs + index * bucketMs
    const date = new Date(start)
    return {
      start,
      end: start + bucketMs,
      label: `${String(date.getHours()).padStart(2, '0')}:00`,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
  })

  for (const event of events) {
    const timestamp = eventTimestamp(event)
    const time = timestamp ? new Date(timestamp).getTime() : 0
    if (!time || time < now - windowMs) continue
    const index = Math.max(0, Math.min(buckets.length - 1, Math.floor((time - (now - windowMs)) / bucketMs)))
    const severity = eventSeverity(event) as 'critical' | 'high' | 'medium' | 'low' | 'info'
    buckets[index][severity] += 1
  }

  return buckets.map(({ label, critical, high, medium, low, info }) => ({ label, critical, high, medium, low, info }))
}

function roleKeyForProfile(profile: any) {
  return normalizeRoleKey(profile?.role || profileMetadata(profile).role || profile?.app_metadata?.role, 'user')
}

function isAdminRole(roleKey: string) {
  return /owner|admin|security|tenant|system|auditor|compliance|ceo/.test(roleKey)
}

async function buildAdminSecurityPayload(db: any) {
  const ctx: SafeContext = { unavailable: new Set() }
  const since24h = new Date(Date.now() - 24 * 60 * 60_000).toISOString()
  const previous24h = new Date(Date.now() - 48 * 60 * 60_000).toISOString()

  const [
    securityEvents,
    userSecurityEvents,
    sessions,
    devices,
    policies,
    evidence,
    profiles,
    vulnerabilities,
    scanResults,
    scanSessions,
    migrationJobs,
    collectors,
    integrations,
    sensors,
    vaultFiles,
    adminAudit,
  ] = await Promise.all([
    safeRows(ctx, db, 'security_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'user_security_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'user_sessions', (q) => q.select('*').order('last_seen_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'user_devices', (q) => q.select('*').order('last_seen_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'admin_governance_policies', (q) => q.select('*').order('updated_at', { ascending: false }).limit(300)),
    safeRows(ctx, db, 'admin_compliance_evidence', (q) => q.select('*').order('created_at', { ascending: false }).limit(300)),
    safeRows(ctx, db, 'profiles', (q) => q.select('*').order('updated_at', { ascending: false }).limit(5000)),
    safeRows(ctx, db, 'vulnerabilities', (q) => q.select('*').order('updated_at', { ascending: false }).limit(3000)),
    safeRows(ctx, db, 'pqc_scan_results', (q) => q.select('*').order('created_at', { ascending: false }).limit(3000)),
    safeRows(ctx, db, 'pqc_scan_sessions', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'migration_jobs', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    optionalRows(db, 'collector_agents', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    optionalRows(db, 'service_integrations', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    optionalRows(db, 'sensor_nodes', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'vault_files', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'admin_audit_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(500)),
  ])

  const allSecurityEvents = [...securityEvents, ...userSecurityEvents]
  const recentEvents = allSecurityEvents.filter((row) => eventTimestamp(row) >= since24h)
  const previousEvents = allSecurityEvents.filter((row) => eventTimestamp(row) >= previous24h && eventTimestamp(row) < since24h)
  const openVulnerabilities = vulnerabilities.filter((row: any) => !/resolved|closed|fixed|accepted/i.test(String(row.status || 'open')))
  const criticalVulnerabilities = [...openVulnerabilities, ...scanResults].filter((row: any) => ['critical', 'high'].includes(eventSeverity(row)))
  const highThreats = recentEvents.filter((row) => eventSeverity(row) === 'high' || eventSeverity(row) === 'critical').length
  const mediumThreats = recentEvents.filter((row) => eventSeverity(row) === 'medium').length
  const lowThreats = recentEvents.filter((row) => eventSeverity(row) === 'low').length
  const activeThreats = highThreats + mediumThreats + lowThreats
  const activeSessions = sessions.filter((row: any) => !row.revoked_at && (!row.last_seen_at || row.last_seen_at >= since24h))
  const trustedDevices = devices.filter((row: any) => (row.trusted || row.trust_status === 'trusted') && !row.revoked_at)
  const mfaEnabledUsers = profiles.filter((profile: any) => mfaRequiredFor(profile)).length
  const mfaCoverage = percent(mfaEnabledUsers, Math.max(1, profiles.length))
  const adminProfiles = profiles.filter((profile: any) => isAdminRole(roleKeyForProfile(profile)))
  const activeAdmins = adminProfiles.filter((profile: any) => userStatus(profile) === 'active')
  const lockedAdmins = adminProfiles.filter((profile: any) => /lock|disabled|suspended/i.test(userStatus(profile)))
  const pendingAdmins = adminProfiles.filter((profile: any) => /pending|invited|review/i.test(userStatus(profile)))
  const inactiveAdmins = adminProfiles.filter((profile: any) => /inactive/i.test(userStatus(profile)))
  const failedLogins = allSecurityEvents.filter((row: any) => /failed|denied|lock|suspicious/i.test(eventText(row)))
  const suspiciousEvents = failedLogins.filter((row: any) => /suspicious|impossible|unknown|privilege|escalat/i.test(eventText(row)))
  const compliancePassed = [...evidence, ...policies].filter((row: any) => /pass|complete|compliant|approved|enabled/i.test(String(row.status || row.enforcement_level || ''))).length
  const complianceTotal = Math.max(1, evidence.length + policies.length)
  const complianceScore = percent(compliancePassed, complianceTotal)
  const scanSuccess = percent(scanSessions.filter((row: any) => /complete|success|passed/i.test(String(row.status || ''))).length, Math.max(1, scanSessions.length))
  const migrationHealth = percent(migrationJobs.filter((row: any) => !/failed|blocked|error/i.test(String(row.status || ''))).length, Math.max(1, migrationJobs.length))
  const securityScore = clamp(100 - (highThreats * 2) - mediumThreats - (criticalVulnerabilities.length * 2) - Math.floor(failedLogins.length / 5) + Math.round(mfaCoverage / 10))

  const threatMap = new Map<string, { title: string; detail: string; severity: string; count: number }>()
  for (const row of [...recentEvents, ...openVulnerabilities, ...scanResults.slice(0, 500)]) {
    const bucket = threatBucket(row)
    const current = threatMap.get(bucket.title)
    const severity = eventSeverity(row)
    const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<string, number>
    threatMap.set(bucket.title, {
      title: bucket.title,
      detail: bucket.detail,
      severity: current && rank[current.severity] > rank[severity] ? current.severity : severity,
      count: (current?.count || 0) + 1,
    })
  }

  const roleCounts = new Map<string, number>()
  for (const profile of adminProfiles) {
    const roleKey = roleKeyForProfile(profile)
    const label = titleFromRoleKey(roleKey)
    roleCounts.set(label, (roleCounts.get(label) || 0) + 1)
  }

  const recentAdminActivities = adminAudit.slice(0, 5).map((row: any) => ({
    id: row.id || `${row.action}-${row.created_at}`,
    title: eventTitle(row),
    detail: row.actor_email || row.entity_type || 'Admin action',
    tag: /mfa/i.test(row.action) ? 'MFA' : /role/i.test(row.action) ? 'Role Change' : /password|login/i.test(row.action) ? 'Security' : 'New Device',
    ip: row.ip_address || 'unknown',
    createdAt: row.created_at || null,
    severity: 'info',
  }))

  return {
    securityEvents,
    userSecurityEvents,
    sessions,
    devices,
    policies,
    evidence,
    metrics: {
      failedLogins: failedLogins.length,
      suspiciousEvents: suspiciousEvents.length,
      activeSessions: activeSessions.length,
      trustedDevices: trustedDevices.length,
      mfaPolicies: policies.filter((row: any) => /mfa|2fa/i.test(`${row.policy_key || ''} ${row.name || ''}`)).length,
      securityScore,
      activeThreats,
      highThreats,
      mediumThreats,
      lowThreats,
      criticalVulnerabilities: criticalVulnerabilities.length,
      users: profiles.length,
      usersDelta: Math.max(0, profiles.filter((profile: any) => String(profile.created_at || '') >= since24h).length),
      adminAccounts: adminProfiles.length,
      mfaCoverage,
      mfaDelta: 0,
      previousThreats: previousEvents.length,
    },
    posture: [
      { label: 'Identify', score: clamp(80 + Math.round(mfaCoverage / 5) - highThreats) },
      { label: 'Protect', score: clamp(75 + Math.round(mfaCoverage / 4) - mediumThreats) },
      { label: 'Detect', score: clamp(70 + Math.round(scanSuccess / 4) - lowThreats) },
      { label: 'Respond', score: clamp(70 + Math.round(migrationHealth / 5) - highThreats) },
      { label: 'Recover', score: clamp(75 + Math.round(complianceScore / 5) - criticalVulnerabilities.length) },
    ],
    threatActivity: buildThreatActivity(allSecurityEvents),
    topThreats: Array.from(threatMap.values()).sort((a, b) => b.count - a.count).slice(0, 5),
    adminOverview: Array.from(roleCounts.entries()).map(([role, count]) => ({ role, count })),
    adminAccessStatus: [
      { status: 'Active', count: activeAdmins.length },
      { status: 'Inactive', count: inactiveAdmins.length },
      { status: 'Locked', count: lockedAdmins.length },
      { status: 'Pending', count: pendingAdmins.length },
    ],
    recentAdminActivities,
    criticalAlerts: recentEvents
      .filter((row) => ['critical', 'high'].includes(eventSeverity(row)))
      .slice(0, 4)
      .map((row) => ({
        id: row.id || `${eventTitle(row)}-${eventTimestamp(row)}`,
        title: eventTitle(row),
        detail: textValue(row.message || row.resource_name || row.email || row.user_email, 'Security signal detected'),
        createdAt: eventTimestamp(row) || null,
        severity: eventSeverity(row),
      })),
    complianceStatus: [
      { label: 'ISO 27001', status: complianceScore >= 80 ? 'Compliant' : 'Review', score: complianceScore },
      { label: 'SOC 2 Type II', status: policies.length > 0 ? 'Compliant' : 'Review', score: clamp(complianceScore - 1) },
      { label: 'PCI DSS v4.0', status: mfaCoverage >= 80 ? 'Compliant' : 'Review', score: clamp(mfaCoverage - 2) },
    ],
    systemHealth: {
      dataCollectors: { healthy: collectors.filter((row: any) => /active|connected|healthy|online|running/i.test(String(row.status || ''))).length, total: collectors.length },
      integrations: { healthy: integrations.filter((row: any) => /active|connected|healthy|ok|synced/i.test(String(row.status || ''))).length, total: integrations.length },
      sensors: { healthy: sensors.filter((row: any) => /active|connected|healthy|online|running/i.test(String(row.status || ''))).length, total: sensors.length || devices.length },
      storage: { usedGb: Math.round(vaultFiles.reduce((sum: number, row: any) => sum + numberValue(row.size_bytes || row.file_size || row.size, 0), 0) / (1024 ** 3) * 10) / 10, totalGb: 5 },
    },
    unavailableTables: Array.from(ctx.unavailable).sort(),
    generatedAt: new Date().toISOString(),
  }
}

async function buildAdminRolesPayload(db: any, query: Record<string, unknown> = {}, page = 1, limit = DEFAULT_LIMIT) {
  const ctx: SafeContext = { unavailable: new Set() }
  const [roleRows, profiles, tenants] = await Promise.all([
    safeRows(ctx, db, 'admin_roles', (q) => q.select('*').order('updated_at', { ascending: false }).limit(500)),
    safeRows(ctx, db, 'profiles', (q) => q.select('*').order('updated_at', { ascending: false }).limit(5000)),
    safeRows(ctx, db, 'organizations', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
  ])
  const allRoles = buildRoleCatalog(roleRows, profiles, tenants)
  const filtered = filterRoles(allRoles, query as Request['query'])
  const sort = textValue(query.sort, 'name')
  const order = textValue(query.order, 'asc')

  filtered.sort((a, b) => {
    const direction = order === 'desc' ? -1 : 1
    if (sort === 'users') return (a.users - b.users) * direction
    if (sort === 'permissions') return (a.permissionCount - b.permissionCount) * direction
    if (sort === 'status') return String(a.status).localeCompare(String(b.status)) * direction
    if (sort === 'type') return String(a.type).localeCompare(String(b.type)) * direction
    return String(a.name).localeCompare(String(b.name)) * direction
  })

  const from = (page - 1) * limit
  const to = from + limit
  return {
    roles: filtered.slice(from, to),
    stats: roleStats(allRoles),
    pagination: { page, limit, total: filtered.length, totalPages: Math.ceil(filtered.length / limit) },
    unavailableTables: Array.from(ctx.unavailable).sort(),
    generatedAt: new Date().toISOString(),
  }
}

async function enrichUser(ctx: SafeContext, db: any, profile: any) {
  const metadata = profileMetadata(profile)
  const userId = String(profile.id)
  const tenantId = tenantIdFor(profile)
  const activeSince = Date.now() - 15 * 60_000

  const [authResult, subscription, tenant, memberships, sessions, loginHistory, devices] = await Promise.all([
    db.auth.admin.getUserById(userId).catch(() => ({ data: { user: null } })),
    safeMaybeSingle(ctx, db, 'billing_subscriptions', (q) => q.select('*').eq('user_id', userId)),
    tenantId ? safeMaybeSingle(ctx, db, 'organizations', (q) => q.select('*').eq('id', tenantId)) : Promise.resolve(null),
    safeRows(ctx, db, 'organization_members', (q) => q.select('*').eq('user_id', userId).order('updated_at', { ascending: false }).limit(5)),
    safeRows(ctx, db, 'user_sessions', (q) => q.select('*').eq('user_id', userId).order('last_seen_at', { ascending: false }).limit(50)),
    safeRows(ctx, db, 'user_security_events', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(5)),
    safeRows(ctx, db, 'user_devices', (q) => q.select('*').eq('user_id', userId).order('last_seen_at', { ascending: false }).limit(50)),
  ])

  const authUser = authResult?.data?.user || null
  const activeSessions = sessions.filter((row: any) => {
    const seenAt = row?.last_seen_at ? new Date(row.last_seen_at).getTime() : 0
    return !row?.revoked_at && seenAt >= activeSince
  }).length
  const idleSessions = sessions.filter((row: any) => {
    const seenAt = row?.last_seen_at ? new Date(row.last_seen_at).getTime() : 0
    return !row?.revoked_at && seenAt < activeSince
  }).length
  const activeDevices = devices.filter((row: any) => !row?.revoked_at)
  const trustedDevices = activeDevices.filter((row: any) => booleanValue(row?.trusted, false)).length
  const latestSession = sessions[0] || null
  const membership = tenantId
    ? memberships.find((row: any) => String(row.organization_id || '') === tenantId) || memberships[0] || null
    : memberships[0] || null

  return {
    id: userId,
    email: profile.email || authUser?.email || '',
    name: profile.full_name || profile.name || authUser?.user_metadata?.full_name || authUser?.user_metadata?.name || '',
    role: profile.role || metadata.role || authUser?.app_metadata?.role || 'user',
    status: userStatus(profile),
    tier: tierFor(profile),
    tenantId: tenantId || null,
    tenantName: tenant?.name || metadata.tenantName || metadata.tenant_name || null,
    tenantSlug: tenant?.slug || metadata.tenantSlug || metadata.tenant_slug || null,
    tenantRole: membership?.role || metadata.tenantRole || metadata.tenant_role || null,
    tenantStatus: tenant?.status || membership?.status || null,
    mfaRequired: mfaRequiredFor(profile),
    subscriptionStatus: subscription?.status || 'none',
    subscriptionPlan: subscription?.plan || tierFor(profile),
    subscriptionInterval: subscription?.billing_cycle || subscription?.plan_interval || 'monthly',
    subscriptionExpiresAt: subscription?.current_period_end || subscription?.expires_at || null,
    qScore: numberValue(profile.q_score, 0),
    maxKeysPerDay: numberValue(profile.max_keys_per_day, 0),
    maxVaultStorage: numberValue(profile.max_vault_storage, 0),
    activeSessions,
    idleSessions,
    deviceCount: activeDevices.length,
    trustedDevices,
    lastSeenAt: latestSession?.last_seen_at || authUser?.last_sign_in_at || null,
    lastIpAddress: latestSession?.ip_address || devices[0]?.ip_address || null,
    lastSignInAt: authUser?.last_sign_in_at || latestSession?.last_seen_at || null,
    emailConfirmedAt: authUser?.email_confirmed_at || null,
    authProvider: authUser?.app_metadata?.provider || 'email',
    createdAt: profile.created_at || authUser?.created_at || null,
    updatedAt: profile.updated_at || null,
    loginHistory,
    devices,
    metadata,
  }
}

async function buildAdminStats(db: any) {
  const ctx: SafeContext = { unavailable: new Set() }
  const since15Min = new Date(Date.now() - 15 * 60_000).toISOString()
  const since24h = new Date(Date.now() - 24 * 60 * 60_000).toISOString()
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString()

  const [
    totalUsers,
    profileRows,
    tenantRows,
    activeSessions,
    subscriptions,
    invoices,
    scanSessions,
    securityEvents,
    migrationJobs,
    vulnerabilities,
    complianceEvidence,
    auditRows,
    usageRows,
  ] = await Promise.all([
    safeCount(ctx, db, 'profiles'),
    safeRows(ctx, db, 'profiles', (q) => q.select('*').order('created_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'organizations', (q) => q.select('*').order('updated_at', { ascending: false }).limit(500)),
    safeCount(ctx, db, 'user_sessions', (q) => q.is('revoked_at', null).gte('last_seen_at', since15Min)),
    safeRows(ctx, db, 'billing_subscriptions', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'billing_invoices', (q) => q.select('*').gte('created_at', since7d).order('created_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'pqc_scan_sessions', (q) => q.select('*').order('created_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'security_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'migration_jobs', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'vulnerabilities', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'compliance_evidence', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'admin_audit_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(100)),
    safeRows(ctx, db, 'billing_usage_events', (q) => q.select('*').gte('created_at', since7d).order('created_at', { ascending: false }).limit(3000)),
  ])

  const activeSubscriptions = subscriptions.filter((row: any) => ['active', 'trialing', 'approved'].includes(String(row.status || '').toLowerCase()))
  const expiredPlans = subscriptions.filter((row: any) => {
    const expiresAt = row.current_period_end || row.expires_at || row.trial_ends_at
    return expiresAt && new Date(expiresAt).getTime() < Date.now()
  })
  const paidInvoices = invoices.filter((row: any) => ['paid', 'succeeded'].includes(String(row.status || '').toLowerCase()))
  const revenue = paidInvoices.reduce((sum: number, row: any) => sum + numberValue(row.amount_paid ?? row.total ?? row.amount_due ?? row.amount, 0), 0)
  const completedJobs = migrationJobs.filter((row: any) => ['completed', 'done', 'success'].includes(String(row.status || '').toLowerCase()))
  const runningJobs = migrationJobs.filter((row: any) => ['running', 'in_progress', 'pending', 'queued'].includes(String(row.status || '').toLowerCase()))
  const scansInProgress = scanSessions.filter((row: any) => ['running', 'scanning', 'in_progress', 'queued'].includes(String(row.status || '').toLowerCase())).length
  const completedScans = scanSessions.filter((row: any) => ['completed', 'done', 'success'].includes(String(row.status || '').toLowerCase()))
  const criticalAlerts = securityEvents.filter((row: any) => ['critical', 'high'].includes(String(row.severity || '').toLowerCase())).length
  const failedLogins = securityEvents.filter((row: any) => /failed|denied|suspicious/i.test(`${row.event_type || ''} ${row.message || ''}`)).length
  const averageProfileScore = profileRows.length
    ? Math.round(profileRows.reduce((sum: number, row: any) => sum + numberValue(row.q_score, 0), 0) / profileRows.length)
    : 0
  const migrationProgress = percent(completedJobs.length, Math.max(1, migrationJobs.length))
  const compliancePassed = complianceEvidence.filter((row: any) => ['passed', 'complete', 'compliant', 'approved'].includes(String(row.status || '').toLowerCase())).length
  const activeUserRows = profileRows.filter((row: any) => userStatus(row) === 'active')
  const adminUsers = profileRows.filter((row: any) => /admin|owner|ceo|super/i.test(String(row.role || '')))
  const mfaEnabledUsers = profileRows.filter((row: any) => mfaRequiredFor(row))
  const unassignedUsers = profileRows.filter((row: any) => !tenantIdFor(row))
  const now = Date.now()
  const currentMonthUsers = profileRows.filter((row: any) => row.created_at && new Date(row.created_at).getTime() >= now - 30 * 24 * 60 * 60_000).length
  const previousMonthUsers = profileRows.filter((row: any) => {
    if (!row.created_at) return false
    const created = new Date(row.created_at).getTime()
    return created >= now - 60 * 24 * 60 * 60_000 && created < now - 30 * 24 * 60 * 60_000
  }).length

  return {
    timestamp: new Date().toISOString(),
    kpis: {
      totalUsers,
      activeUsers: activeUserRows.length,
      administratorUsers: adminUsers.length,
      mfaEnabledUsers: mfaEnabledUsers.length,
      unassignedUsers: unassignedUsers.length,
      userGrowthPercent: previousMonthUsers > 0 ? Math.round(((currentMonthUsers - previousMonthUsers) / previousMonthUsers) * 100) : currentMonthUsers > 0 ? 100 : 0,
      activeTenants: tenantRows.filter((row: any) => userStatus(row) !== 'disabled').length,
      totalTenants: tenantRows.length,
      activeSubscriptions: activeSubscriptions.length,
      subscriptionRevenue: revenue,
      expiredPlans: expiredPlans.length,
      activeSessions,
      pqcReadinessScore: averageProfileScore,
      migrationProgress,
      scansInProgress,
      completedScans: completedScans.length,
      criticalAlerts,
      failedLogins,
      complianceScore: percent(compliancePassed, Math.max(1, complianceEvidence.length)),
      usageEvents: usageRows.length,
    },
    summaries: {
      subscriptionStatus: countBy(subscriptions, 'status', 'none'),
      tenantStatus: countBy(tenantRows, 'status', 'active'),
      vulnerabilitySeverity: countBy(vulnerabilities, 'severity', 'unknown'),
      securitySeverity: countBy(securityEvents, 'severity', 'info'),
      scanStatus: countBy(scanSessions, 'status', 'unknown'),
      migrationStatus: countBy(migrationJobs, 'status', 'unknown'),
      complianceStatus: countBy(complianceEvidence, 'status', 'unknown'),
    },
    charts: {
      userGrowth: groupByDay(profileRows, ['created_at'], 7),
      tenantActivity: groupByDay([...auditRows, ...securityEvents], ['created_at'], 7),
      vulnerabilityTrend: groupByDay(vulnerabilities, ['updated_at', 'created_at'], 7),
      scanTrend: groupByDay(scanSessions, ['created_at'], 7),
      subscriptionChanges: groupByDay(subscriptions, ['updated_at', 'created_at'], 7),
    },
    recent: {
      users: profileRows.slice(0, 8),
      securityEvents: securityEvents.slice(0, 8),
      auditEvents: auditRows.slice(0, 8),
      migrationJobs: migrationJobs.slice(0, 8),
      subscriptions: subscriptions.slice(0, 8),
    },
    realtime: {
      source: 'supabase',
      unavailableTables: Array.from(ctx.unavailable).sort(),
      generatedAt: new Date().toISOString(),
      window: { since24h, since7d },
    },
  }
}

router.use(requireOwner)

router.get('/me', async (req: AdminRequest, res) => {
  const ctx: SafeContext = { unavailable: new Set() }
  const profile = await safeMaybeSingle(ctx, req.adminDb, 'profiles', (q) => q.select('*').eq('id', req.adminUser!.id))
  await recordAdminAudit(req, 'admin.me.viewed', 'admin_dashboard')
  res.json({
    data: {
      user: {
        id: req.adminUser!.id,
        email: req.adminUser!.email,
        role: profile?.role || 'owner',
      },
      permissions: ['users.manage', 'tenants.manage', 'subscriptions.manage', 'security.manage', 'governance.manage', 'telemetry.read'],
      unavailableTables: Array.from(ctx.unavailable).sort(),
    },
  })
})

router.get('/stats', async (req: AdminRequest, res) => {
  const data = await buildAdminStats(req.adminDb)
  res.json({ data })
})

router.get('/roles', async (req: AdminRequest, res) => {
  const { page, limit } = parsePagination(req)
  try {
    const data = await buildAdminRolesPayload(req.adminDb, req.query as Record<string, unknown>, page, limit)
    res.json({ data })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_ROLES_QUERY_FAILED', error instanceof Error ? error.message : 'Failed to load roles')
  }
})

router.post('/roles', async (req: AdminRequest, res) => {
  const body = req.body || {}
  const name = textValue(body.name, '')
  const roleKey = normalizeRoleKey(body.roleKey || name, '')
  if (!name || !roleKey) {
    jsonError(res, 400, 'VALIDATION_ERROR', 'Role name is required')
    return
  }
  if (SYSTEM_ROLE_DEFINITIONS.some((definition) => definition.role_key === roleKey)) {
    jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'System role keys cannot be replaced from the dashboard')
    return
  }

  const permissions = Array.isArray(body.permissions) ? body.permissions.map((item: unknown) => String(item)).filter(Boolean) : []
  const payload = {
    role_key: roleKey,
    name,
    description: textValue(body.description, 'Custom access role'),
    role_type: 'custom',
    status: textValue(body.status, 'active'),
    tenant_id: textValue(body.tenantId, '') || null,
    permission_scope: textValue(body.permissionScope, permissions.length ? 'Custom' : 'Read Only'),
    permission_count: numberValue(body.permissionCount, permissions.length),
    permissions,
    metadata: recordOf(body.metadata),
    created_by: req.adminUser!.id,
    updated_by: req.adminUser!.id,
    updated_at: new Date().toISOString(),
  }

  try {
    const existingRole = await req.adminDb.from('admin_roles').select('*').eq('role_key', roleKey).maybeSingle()
    assertNoSupabaseError(existingRole, 'Failed to check existing role')
    if (existingRole.data && roleIsProtected(existingRole.data)) {
      jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'Protected roles cannot be replaced from the dashboard')
      return
    }

    const { data, error } = await req.adminDb.from('admin_roles').upsert(payload, { onConflict: 'role_key' }).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.role.saved', 'role', data?.id || roleKey, roleAuditDetails(data || payload, {
      result: 'completed',
      operation: existingRole.data ? 'updated_existing_role' : 'created_role',
      changedFields: Object.keys(payload),
    }))
    res.status(201).json({ data: { role: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_ROLE_SAVE_FAILED', error instanceof Error ? error.message : 'Failed to save role')
  }
})

router.patch('/roles/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  if (id.startsWith('system-')) {
    jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'System roles cannot be modified from the dashboard')
    return
  }

  const body = req.body || {}
  const allowed: Record<string, unknown> = { updated_by: req.adminUser!.id, updated_at: new Date().toISOString() }
  for (const [apiKey, dbKey] of Object.entries({
    name: 'name',
    description: 'description',
    status: 'status',
    tenantId: 'tenant_id',
    permissionScope: 'permission_scope',
    permissionCount: 'permission_count',
    permissions: 'permissions',
    metadata: 'metadata',
  })) {
    if (Object.prototype.hasOwnProperty.call(body, apiKey)) allowed[dbKey] = body[apiKey]
  }

  try {
    const existingRole = await req.adminDb.from('admin_roles').select('*').eq('id', id).maybeSingle()
    assertNoSupabaseError(existingRole, 'Failed to load role')
    if (!existingRole.data) {
      jsonError(res, 404, 'ROLE_NOT_FOUND', 'Role not found')
      return
    }
    if (roleIsProtected(existingRole.data)) {
      jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'Protected roles cannot be modified from the dashboard')
      return
    }

    const { data, error } = await req.adminDb.from('admin_roles').update(allowed).eq('id', id).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.role.updated', 'role', id, roleAuditDetails(existingRole.data, {
      result: 'completed',
      nextStatus: data?.status || existingRole.data.status || null,
      changedFields: Object.keys(allowed).filter((key) => !['updated_by', 'updated_at'].includes(key)),
      changes: allowed,
    }))
    res.json({ data: { role: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_ROLE_UPDATE_FAILED', error instanceof Error ? error.message : 'Failed to update role')
  }
})

router.post('/roles/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, '').toLowerCase()
  if (id.startsWith('system-')) {
    jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'System roles cannot be changed from the dashboard')
    return
  }

  try {
    const existingRole = await req.adminDb.from('admin_roles').select('*').eq('id', id).maybeSingle()
    assertNoSupabaseError(existingRole, 'Failed to load role')
    if (!existingRole.data) {
      jsonError(res, 404, 'ROLE_NOT_FOUND', 'Role not found')
      return
    }
    if (roleIsProtected(existingRole.data)) {
      jsonError(res, 400, 'SYSTEM_ROLE_PROTECTED', 'Protected roles cannot be changed from the dashboard')
      return
    }

    if (action === 'delete') {
      const profiles = await req.adminDb.from('profiles').select('id,email,role,metadata').limit(5000)
      assertNoSupabaseError(profiles, 'Failed to check role assignments')
      const assignedUsers = userCountForRole(profiles.data || [], existingRole.data)
      if (assignedUsers > 0) {
        await recordAdminAudit(req, 'admin.role.delete.blocked', 'role', id, roleAuditDetails(existingRole.data, {
          result: 'blocked',
          reason: 'role_in_use',
          assignedUsers,
        }))
        jsonError(res, 409, 'ROLE_IN_USE', `Role cannot be deleted while assigned to ${assignedUsers} user${assignedUsers === 1 ? '' : 's'}`)
        return
      }

      const deleteResult = await req.adminDb.from('admin_roles').delete().eq('id', id).select('id').single()
      assertNoSupabaseError(deleteResult, 'Failed to delete role')
      await recordAdminAudit(req, 'admin.role.deleted', 'role', id, roleAuditDetails(existingRole.data, {
        result: 'completed',
        deleted: true,
      }))
      res.json({ data: { deleted: true } })
      return
    }

    const nextStatus = action === 'activate'
      ? 'active'
      : action === 'deactivate'
        ? 'inactive'
        : action === 'archive'
          ? 'archived'
          : ''
    if (!nextStatus) {
      jsonError(res, 400, 'UNKNOWN_ROLE_ACTION', 'Unknown role action')
      return
    }

    const { data, error } = await req.adminDb.from('admin_roles').update({
      status: nextStatus,
      updated_by: req.adminUser!.id,
      updated_at: new Date().toISOString(),
    }).eq('id', id).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, `admin.role.${action}`, 'role', id, roleAuditDetails(existingRole.data, {
      result: 'completed',
      nextStatus,
      changedFields: ['status'],
    }))
    res.json({ data: { role: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_ROLE_ACTION_FAILED', error instanceof Error ? error.message : 'Failed to update role')
  }
})

router.get('/users', async (req: AdminRequest, res) => {
  const ctx: SafeContext = { unavailable: new Set() }
  const { page, limit, from, to } = parsePagination(req)
  const search = cleanSearch(req.query.search)
  const tier = textValue(req.query.tier, '')
  const role = textValue(req.query.role, '')
  const tenantId = textValue(req.query.tenantId, '')
  const status = textValue(req.query.status, '')
  const sort = ['created_at', 'updated_at', 'email', 'name', 'tier', 'q_score'].includes(String(req.query.sort || ''))
    ? String(req.query.sort)
    : 'created_at'
  const ascending = req.query.order === 'asc'

  try {
    let query = req.adminDb.from('profiles').select('*', { count: 'exact' })
    if (search) query = query.or(`email.ilike.%${search}%,name.ilike.%${search}%,full_name.ilike.%${search}%`)
    if (tier && tier !== 'all') query = query.eq('tier', tier)
    if (role && role !== 'all') query = query.eq('role', role)
    if (tenantId && tenantId !== 'all') query = tenantId === 'unassigned' ? query.is('tenant_id', null) : query.eq('tenant_id', tenantId)
    if (status && status !== 'all') query = query.eq('account_status', status)
    const { data, count, error } = await query.order(sort, { ascending }).range(from, to)
    if (error) throw error
    const users = await Promise.all((data || []).map((profile: any) => enrichUser(ctx, req.adminDb, profile)))
    res.json({ data: { users, pagination: { page, limit, total: count || 0, totalPages: Math.ceil((count || 0) / limit) }, unavailableTables: Array.from(ctx.unavailable).sort() } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_USERS_QUERY_FAILED', error instanceof Error ? error.message : 'Failed to load users')
  }
})

router.post('/users', async (req: AdminRequest, res) => {
  const { email, password, name, role, tier, tenantId, mfaRequired } = req.body || {}
  if (!email || !password) {
    jsonError(res, 400, 'VALIDATION_ERROR', 'Email and password are required')
    return
  }

  try {
    const { data, error } = await req.adminDb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: name || '', mfa_required: Boolean(mfaRequired) },
      app_metadata: { role: role || 'user', tenant_id: tenantId || null },
    })
    if (error) throw error
    const userId = data.user?.id
    if (userId) {
      await req.adminDb.from('profiles').upsert({
        id: userId,
        email,
        name: name || null,
        full_name: name || null,
        role: role || 'user',
        tier: tier || 'free',
        tenant_id: tenantId || null,
        mfa_required: Boolean(mfaRequired),
        account_status: 'active',
        updated_at: new Date().toISOString(),
      })
      if (tenantId) {
        await req.adminDb.from('organization_members').upsert({
          organization_id: tenantId,
          user_id: userId,
          role: role || 'member',
          status: 'active',
          updated_at: new Date().toISOString(),
        }, { onConflict: 'organization_id,user_id' })
      }
      await recordAdminAudit(req, 'admin.user.created', 'user', userId, { email, role, tier, tenantId })
    }
    res.status(201).json({ data: { user: data.user } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_USER_CREATE_FAILED', error instanceof Error ? error.message : 'Failed to create user')
  }
})

router.get('/users/:id', async (req: AdminRequest, res) => {
  const ctx: SafeContext = { unavailable: new Set() }
  const profile = await safeMaybeSingle(ctx, req.adminDb, 'profiles', (q) => q.select('*').eq('id', req.params.id))
  if (!profile) {
    jsonError(res, 404, 'USER_NOT_FOUND', 'User profile not found')
    return
  }
  const user = await enrichUser(ctx, req.adminDb, profile)
  const [sessions, devices, auditLogs, securityEvents] = await Promise.all([
    safeRows(ctx, req.adminDb, 'user_sessions', (q) => q.select('*').eq('user_id', req.params.id).order('last_seen_at', { ascending: false }).limit(30)),
    safeRows(ctx, req.adminDb, 'user_devices', (q) => q.select('*').eq('user_id', req.params.id).order('last_seen_at', { ascending: false }).limit(30)),
    safeRows(ctx, req.adminDb, 'audit_logs', (q) => q.select('*').eq('user_id', req.params.id).order('created_at', { ascending: false }).limit(30)),
    safeRows(ctx, req.adminDb, 'user_security_events', (q) => q.select('*').eq('user_id', req.params.id).order('created_at', { ascending: false }).limit(30)),
  ])
  await recordAdminAudit(req, 'admin.user.inspected', 'user', req.params.id)
  res.json({ data: { user, sessions, devices, auditLogs, securityEvents, unavailableTables: Array.from(ctx.unavailable).sort() } })
})

router.patch('/users/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  const updates = req.body || {}
  if (isOwnerEmail(updates.email)) {
    jsonError(res, 400, 'OWNER_IMMUTABLE', 'Owner account cannot be modified through bulk user actions')
    return
  }

  const allowed: Record<string, unknown> = {}
  for (const key of ['name', 'full_name', 'role', 'tier', 'tenant_id', 'account_status', 'mfa_required', 'max_keys_per_day', 'max_vault_storage']) {
    if (Object.prototype.hasOwnProperty.call(updates, key)) allowed[key] = updates[key]
  }
  allowed.updated_at = new Date().toISOString()

  try {
    const { data, error } = await req.adminDb.from('profiles').update(allowed).eq('id', id).select('*').single()
    if (error) throw error
    if (allowed.tenant_id) {
      await req.adminDb.from('organization_members').upsert({
        organization_id: allowed.tenant_id,
        user_id: id,
        role: allowed.role || 'member',
        status: 'active',
        updated_at: new Date().toISOString(),
      }, { onConflict: 'organization_id,user_id' })
    }
    await recordAdminAudit(req, 'admin.user.updated', 'user', id, { fields: Object.keys(allowed) })
    res.json({ data: { profile: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_USER_UPDATE_FAILED', error instanceof Error ? error.message : 'Failed to update user')
  }
})

router.delete('/users/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  if (id === req.adminUser!.id) {
    jsonError(res, 400, 'OWNER_IMMUTABLE', 'The owner account cannot delete itself')
    return
  }
  try {
    const targetProfile = await req.adminDb
      .from('profiles')
      .select('id,email,name,full_name,role,account_status')
      .eq('id', id)
      .maybeSingle()
    assertNoSupabaseError(targetProfile, 'Failed to load target user before delete')

    await Promise.allSettled([
      req.adminDb.from('organization_members').delete().eq('user_id', id),
      req.adminDb.from('user_sessions').delete().eq('user_id', id),
      req.adminDb.from('user_devices').delete().eq('user_id', id),
      req.adminDb.from('billing_subscriptions').delete().eq('user_id', id),
      req.adminDb.from('billing_notifications').delete().eq('user_id', id),
    ])
    assertNoSupabaseError(
      await req.adminDb.from('profiles').delete().eq('id', id),
      'Failed to delete user profile'
    )
    assertNoSupabaseError(
      await req.adminDb.auth.admin.deleteUser(id),
      'Failed to delete auth user'
    )
    await recordAdminAudit(req, 'admin.user.deleted', 'user', id, {
      targetUserId: id,
      targetEmail: targetProfile.data?.email || null,
      targetName: targetProfile.data?.full_name || targetProfile.data?.name || null,
      previousRole: targetProfile.data?.role || null,
      previousAccountStatus: targetProfile.data?.account_status || null,
      status: 'completed',
    })
    res.json({ data: { id, deleted: true } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_USER_DELETE_FAILED', error instanceof Error ? error.message : 'Failed to delete user')
  }
})

router.post('/users/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, '').toLowerCase()
  if (!action) {
    jsonError(res, 400, 'VALIDATION_ERROR', 'Action is required')
    return
  }
  if (id === req.adminUser!.id && ['suspend', 'disable', 'delete', 'force_logout'].includes(action)) {
    jsonError(res, 400, 'OWNER_IMMUTABLE', 'The owner account cannot run this action against itself')
    return
  }

  try {
    const authResult = await req.adminDb.auth.admin.getUserById(id).catch(() => ({ data: { user: null } }))
    const authUser = authResult?.data?.user
    const targetProfile = await req.adminDb
      .from('profiles')
      .select('id,email,name,full_name,role,tier,account_status,mfa_required,tenant_id')
      .eq('id', id)
      .maybeSingle()
    assertNoSupabaseError(targetProfile, 'Failed to load target user profile')
    const targetName = targetProfile.data?.full_name || targetProfile.data?.name || null
    const targetEmail = targetProfile.data?.email || authUser?.email || null
    const appMetadata = { ...(authUser?.app_metadata || {}) }
    const userMetadata = { ...(authUser?.user_metadata || {}) }
    let responsePayload: Record<string, unknown> = {
      action,
      status: 'completed',
      targetUserId: id,
      targetEmail,
      targetName,
      previousAccountStatus: targetProfile.data?.account_status || null,
      previousRole: targetProfile.data?.role || null,
      previousMfaRequired: targetProfile.data?.mfa_required ?? null,
    }

    if (['suspend', 'disable', 'restore'].includes(action)) {
      const accountStatus = action === 'restore' ? 'active' : action === 'suspend' ? 'suspended' : 'disabled'
      assertNoSupabaseError(
        await req.adminDb
          .from('profiles')
          .update({ account_status: accountStatus, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select('id,account_status')
          .single(),
        `Failed to ${action} user profile`
      )
      assertNoSupabaseError(
        await req.adminDb.auth.admin.updateUserById(id, {
          app_metadata: { ...appMetadata, account_status: accountStatus },
          ban_duration: accountStatus === 'active' ? 'none' : '876000h',
        }),
        `Failed to ${action} auth user`
      )
      responsePayload.accountStatus = accountStatus
    } else if (action === 'reset_password') {
      const email = targetEmail || authUser?.email
      if (!email) throw new Error('Target user email is unavailable')
      const link = await req.adminDb.auth.admin.generateLink({ type: 'recovery', email })
      assertNoSupabaseError(link, 'Failed to generate password recovery link')
      responsePayload.recoveryLink = link.data?.properties?.action_link || null
    } else if (action === 'force_logout') {
      const revokedAt = new Date().toISOString()
      assertNoSupabaseError(
        await req.adminDb
          .from('user_sessions')
          .update({ revoked_at: revokedAt, revoked_reason: 'admin_force_logout' })
          .eq('user_id', id)
          .is('revoked_at', null),
        'Failed to revoke active user sessions'
      )
      assertNoSupabaseError(
        await req.adminDb
          .from('admin_session_revocations')
          .insert({ user_id: id, revoked_by: req.adminUser!.id, reason: 'admin_force_logout', created_at: revokedAt }),
        'Failed to record session revocation'
      )
      assertNoSupabaseError(
        await req.adminDb.auth.admin.updateUserById(id, { user_metadata: { ...userMetadata, force_logout_after: revokedAt } }),
        'Failed to update force logout marker'
      )
      responsePayload.revokedAt = revokedAt
    } else if (action === 'mfa_enable' || action === 'mfa_disable') {
      const mfaRequired = action === 'mfa_enable'
      assertNoSupabaseError(
        await req.adminDb
          .from('profiles')
          .update({ mfa_required: mfaRequired, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select('id,mfa_required')
          .single(),
        'Failed to update MFA requirement'
      )
      assertNoSupabaseError(
        await req.adminDb.auth.admin.updateUserById(id, { user_metadata: { ...userMetadata, mfa_required: mfaRequired } }),
        'Failed to update auth MFA requirement'
      )
      responsePayload.mfaRequired = mfaRequired
    } else if (action === 'assign_role') {
      const role = textValue(req.body?.role, 'user')
      assertNoSupabaseError(
        await req.adminDb
          .from('profiles')
          .update({ role, updated_at: new Date().toISOString() })
          .eq('id', id)
          .select('id,role')
          .single(),
        'Failed to update user role'
      )
      assertNoSupabaseError(
        await req.adminDb.auth.admin.updateUserById(id, { app_metadata: { ...appMetadata, role } }),
        'Failed to update auth user role'
      )
      responsePayload.role = role
    } else {
      jsonError(res, 400, 'UNKNOWN_ACTION', `Unsupported user action: ${action}`)
      return
    }

    await recordAdminAudit(req, `admin.user.${action}`, 'user', id, responsePayload)
    res.json({ data: responsePayload })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_USER_ACTION_FAILED', error instanceof Error ? error.message : 'Failed to run user action')
  }
})

router.post('/users/:id/subscription', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, 'activate').toLowerCase()
  const now = new Date()
  const expiresAt = textValue(req.body?.expiresAt, '') || new Date(now.getTime() + 30 * 24 * 60 * 60_000).toISOString()
  const plan = textValue(req.body?.plan, 'Pro')
  const status = ['cancel', 'deactivate'].includes(action)
    ? 'canceled'
    : action === 'approve'
      ? 'approved'
      : action === 'activate'
        ? 'active'
        : ''
  if (!status) {
    jsonError(res, 400, 'UNKNOWN_SUBSCRIPTION_ACTION', `Unsupported user subscription action: ${action}`)
    return
  }

  try {
    const profile = await req.adminDb
      .from('profiles')
      .select('id,email,name,full_name,tier,tenant_id')
      .eq('id', id)
      .maybeSingle()
    assertNoSupabaseError(profile, 'Failed to load user profile for subscription')
    if (!profile.data) throw new Error('User profile not found for subscription')

    const existingSubscription = await req.adminDb
      .from('billing_subscriptions')
      .select('*')
      .eq('user_id', id)
      .maybeSingle()
    assertNoSupabaseError(existingSubscription, 'Failed to load existing subscription')
    const existingMetadata = billingMetadata(existingSubscription.data)
    const billingCycle = textValue(req.body?.interval || existingSubscription.data?.billing_cycle, 'monthly')
    const payload = {
      user_id: id,
      tenant_id: textValue(req.body?.tenantId || profile.data.tenant_id || existingSubscription.data?.tenant_id, '') || null,
      plan,
      status,
      billing_cycle: billingCycle,
      plan_interval: billingCycle,
      seats: numberValue(req.body?.seats ?? existingSubscription.data?.seats, 1),
      amount_cents: numberValue(req.body?.amountCents ?? existingSubscription.data?.amount_cents, planAmountCents(plan, billingCycle)),
      currency: textValue(req.body?.currency || existingSubscription.data?.currency, 'USD').toUpperCase(),
      current_period_end: expiresAt,
      renewal_date: expiresAt,
      approval_status: action === 'approve' ? 'approved' : existingSubscription.data?.approval_status || 'not_required',
      canceled_at: ['cancel', 'deactivate'].includes(action) ? new Date().toISOString() : null,
      metadata: {
        ...existingMetadata,
        adminAction: action,
        customPlan: req.body?.customPlan || existingMetadata.customPlan || null,
        updatedBy: req.adminUser!.id,
        updatedByEmail: req.adminUser!.email || null,
        updatedAt: new Date().toISOString(),
      },
      updated_at: new Date().toISOString(),
    }
    const upsertResult = await req.adminDb
      .from('billing_subscriptions')
      .upsert(payload, { onConflict: 'user_id' })
      .select('*')
      .single()
    assertNoSupabaseError(upsertResult, 'Failed to manage subscription')
    await syncBillingEntitlements(req.adminDb, upsertResult.data, plan, status)
    const context = await loadSubscriptionContext(req.adminDb, upsertResult.data)
    await recordAdminAudit(req, `admin.subscription.${action}`, 'subscription', upsertResult.data?.id || id, subscriptionAuditDetails(existingSubscription.data || upsertResult.data, context.profile, context.tenant, {
      result: 'completed',
      action,
      nextStatus: status,
      nextPlan: plan,
      nextRenewalDate: expiresAt,
      operation: existingSubscription.data ? 'updated_existing_subscription' : 'created_subscription',
    }))
    const data = upsertResult.data
    res.json({ data: { subscription: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_SUBSCRIPTION_UPDATE_FAILED', error instanceof Error ? error.message : 'Failed to manage subscription')
  }
})

router.get('/tenants', async (req: AdminRequest, res) => {
  const ctx: SafeContext = { unavailable: new Set() }
  const { page, limit } = parsePagination(req)
  const search = cleanSearch(req.query.search)
  const status = textValue(req.query.status, '')
  const plan = textValue(req.query.plan, '')
  const region = textValue(req.query.region, '')
  try {
    const { data, error } = await req.adminDb.from('organizations').select('*').order('updated_at', { ascending: false }).limit(1000)
    if (error) throw error
    const enriched = await Promise.all((data || []).map((tenant: any) => enrichTenant(ctx, req.adminDb, tenant)))
    const filtered = enriched.filter((tenant: any) => {
      const searchable = `${tenant.name || ''} ${tenant.slug || ''} ${tenant.domain || ''} ${tenant.id || ''}`.toLowerCase()
      if (search && !searchable.includes(search.toLowerCase())) return false
      if (status && status !== 'all' && String(tenant.status || '').toLowerCase() !== status.toLowerCase()) return false
      if (plan && plan !== 'all' && String(tenant.plan || '').toLowerCase() !== plan.toLowerCase()) return false
      if (region && region !== 'all' && String(tenant.region || '').toLowerCase() !== region.toLowerCase()) return false
      return true
    })
    const from = (page - 1) * limit
    const tenants = filtered.slice(from, from + limit)
    const stats = {
      totalTenants: enriched.length,
      activeTenants: enriched.filter((tenant: any) => tenant.status === 'active').length,
      trialTenants: enriched.filter((tenant: any) => tenant.status === 'trial' || tenant.trialSubscriptions > 0).length,
      suspendedTenants: enriched.filter((tenant: any) => ['suspended', 'disabled'].includes(String(tenant.status || '').toLowerCase())).length,
      totalUsers: enriched.reduce((sum: number, tenant: any) => sum + numberValue(tenant.totalUsers, 0), 0),
      totalDevices: enriched.reduce((sum: number, tenant: any) => sum + numberValue(tenant.devices, 0), 0),
      tenantGrowthPercent: 0,
    }
    res.json({ data: { tenants, stats, pagination: { page, limit, total: filtered.length, totalPages: Math.ceil(filtered.length / limit) }, unavailableTables: Array.from(ctx.unavailable).sort(), generatedAt: new Date().toISOString() } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_TENANTS_QUERY_FAILED', error instanceof Error ? error.message : 'Failed to load tenants')
  }
})

router.post('/tenants', async (req: AdminRequest, res) => {
  const name = textValue(req.body?.name, '')
  if (!name) {
    jsonError(res, 400, 'VALIDATION_ERROR', 'Tenant name is required')
    return
  }
  const slug = textValue(req.body?.slug, name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''))
  try {
    const { data, error } = await req.adminDb.from('organizations').insert({
      name,
      slug,
      owner_user_id: req.body?.ownerUserId || null,
      status: 'active',
      plan: textValue(req.body?.plan, 'starter'),
      quota_users: numberValue(req.body?.quotaUsers, 5),
      quota_storage_gb: numberValue(req.body?.quotaStorageGb, 5),
      metadata: recordOf(req.body?.metadata),
    }).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.tenant.created', 'tenant', data.id, { name, slug })
    res.status(201).json({ data: { tenant: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_TENANT_CREATE_FAILED', error instanceof Error ? error.message : 'Failed to create tenant')
  }
})

router.patch('/tenants/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  const updates: Record<string, unknown> = {}
  for (const key of ['name', 'slug', 'status', 'plan', 'quota_users', 'quota_storage_gb', 'readiness_score', 'security_score', 'metadata']) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) updates[key] = req.body[key]
  }
  updates.updated_at = new Date().toISOString()
  try {
    const { data, error } = await req.adminDb.from('organizations').update(updates).eq('id', id).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.tenant.updated', 'tenant', id, { fields: Object.keys(updates) })
    res.json({ data: { tenant: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_TENANT_UPDATE_FAILED', error instanceof Error ? error.message : 'Failed to update tenant')
  }
})

router.post('/tenants/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, '').toLowerCase()
  const status = action === 'disable' ? 'disabled' : action === 'enable' ? 'active' : undefined
  if (!status && action !== 'set_quota') {
    jsonError(res, 400, 'UNKNOWN_ACTION', `Unsupported tenant action: ${action}`)
    return
  }

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() }
  if (status) updates.status = status
  if (action === 'set_quota') {
    updates.quota_users = numberValue(req.body?.quotaUsers, 5)
    updates.quota_storage_gb = numberValue(req.body?.quotaStorageGb, 5)
  }

  try {
    const { data, error } = await req.adminDb.from('organizations').update(updates).eq('id', id).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, `admin.tenant.${action}`, 'tenant', id, updates)
    res.json({ data: { tenant: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_TENANT_ACTION_FAILED', error instanceof Error ? error.message : 'Failed to run tenant action')
  }
})

router.get('/subscriptions', async (req: AdminRequest, res) => {
  const { page, limit } = parsePagination(req)
  try {
    const payload = await buildAdminSubscriptionsPayload(req.adminDb, req.query, page, limit)
    res.json({ data: payload })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_SUBSCRIPTIONS_QUERY_FAILED', error instanceof Error ? error.message : 'Failed to load subscriptions')
  }
})

router.post('/subscriptions/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, '').toLowerCase()
  if (!['approve', 'activate', 'deactivate', 'upgrade', 'downgrade', 'extend', 'cancel', 'renewal_reminder', 'delete'].includes(action)) {
    jsonError(res, 400, 'UNKNOWN_ACTION', `Unsupported subscription action: ${action}`)
    return
  }

  try {
    const existingSubscription = await req.adminDb
      .from('billing_subscriptions')
      .select('*')
      .eq('id', id)
      .maybeSingle()
    assertNoSupabaseError(existingSubscription, 'Failed to load subscription')
    if (!existingSubscription.data) {
      jsonError(res, 404, 'SUBSCRIPTION_NOT_FOUND', 'Subscription not found')
      return
    }

    const context = await loadSubscriptionContext(req.adminDb, existingSubscription.data)
    const existingMetadata = billingMetadata(existingSubscription.data)
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() }
    const previousRenewal = billingRenewalDate(existingSubscription.data)
    const currentPeriodBase = previousRenewal
      ? Math.max(Date.now(), new Date(previousRenewal).getTime())
      : Date.now()

    if (action === 'approve') {
      updates.approval_status = 'approved'
      updates.status = 'approved'
    } else if (action === 'activate') {
      updates.status = 'active'
      updates.canceled_at = null
      updates.cancelled_at = null
      updates.cancel_at_period_end = false
    } else if (action === 'deactivate') {
      updates.status = 'inactive'
      updates.cancel_at_period_end = false
    } else if (action === 'upgrade') {
      const plan = textValue(req.body?.plan, 'Elite')
      const cycle = billingCycleFor(existingSubscription.data)
      updates.plan = plan
      updates.status = 'active'
      updates.amount_cents = numberValue(req.body?.amountCents, planAmountCents(plan, cycle))
      updates.currency = textValue(req.body?.currency || existingSubscription.data.currency, 'USD').toUpperCase()
    } else if (action === 'downgrade') {
      const plan = textValue(req.body?.plan, 'Starter')
      const cycle = billingCycleFor(existingSubscription.data)
      updates.plan = plan
      updates.status = 'active'
      updates.amount_cents = numberValue(req.body?.amountCents, planAmountCents(plan, cycle))
      updates.currency = textValue(req.body?.currency || existingSubscription.data.currency, 'USD').toUpperCase()
    } else if (action === 'extend') {
      const days = Math.max(1, numberValue(req.body?.days, 30))
      const nextRenewalDate = new Date(currentPeriodBase + days * 24 * 60 * 60_000).toISOString()
      updates.current_period_end = nextRenewalDate
      updates.renewal_date = nextRenewalDate
      updates.expires_at = nextRenewalDate
    } else if (action === 'cancel') {
      updates.status = 'canceled'
      updates.canceled_at = new Date().toISOString()
      updates.cancelled_at = updates.canceled_at
      updates.cancel_at_period_end = false
      updates.auto_renew = false
    } else if (action === 'renewal_reminder') {
      updates.metadata = {
        ...existingMetadata,
        renewalReminderSentAt: new Date().toISOString(),
        renewalReminderSentBy: req.adminUser!.id,
        renewalReminderSentByEmail: req.adminUser!.email || null,
      }
    } else if (action === 'delete') {
      const deleteResult = await req.adminDb
        .from('billing_subscriptions')
        .delete()
        .eq('id', id)
        .select('id')
        .single()
      assertNoSupabaseError(deleteResult, 'Failed to delete subscription')
      await syncBillingEntitlements(req.adminDb, existingSubscription.data, 'free', 'deleted')
      await recordAdminAudit(req, 'admin.subscription.deleted', 'subscription', id, subscriptionAuditDetails(existingSubscription.data, context.profile, context.tenant, {
        result: 'completed',
        action,
        nextStatus: 'deleted',
        nextPlan: 'free',
        deleted: true,
      }))
      res.json({ data: { id, deleted: true } })
      return
    }

    if (Object.prototype.hasOwnProperty.call(updates, 'plan')) {
      updates.plan = textValue(updates.plan, existingSubscription.data.plan || 'starter')
    }
    if (!Object.prototype.hasOwnProperty.call(updates, 'metadata')) {
      updates.metadata = {
        ...existingMetadata,
        lastAdminAction: action,
        lastAdminActionAt: new Date().toISOString(),
        lastAdminActionBy: req.adminUser!.id,
        lastAdminActionByEmail: req.adminUser!.email || null,
      }
    }

    const updateResult = await req.adminDb
      .from('billing_subscriptions')
      .update(updates)
      .eq('id', id)
      .select('*')
      .single()
    assertNoSupabaseError(updateResult, 'Failed to run subscription action')

    const nextPlan = textValue(updateResult.data?.plan, existingSubscription.data.plan || 'free')
    const nextStatus = textValue(updateResult.data?.status, existingSubscription.data.status || 'inactive')
    if (updateResult.data?.user_id || updateResult.data?.tenant_id) {
      await syncBillingEntitlements(req.adminDb, updateResult.data, nextPlan, nextStatus)
    }

    await recordAdminAudit(req, `admin.subscription.${action}`, 'subscription', id, subscriptionAuditDetails(existingSubscription.data, context.profile, context.tenant, {
      result: 'completed',
      action,
      nextStatus,
      nextPlan,
      nextRenewalDate: billingRenewalDate(updateResult.data),
      changedFields: Object.keys(updates).filter((key) => key !== 'updated_at'),
    }))
    res.json({ data: { subscription: updateResult.data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_SUBSCRIPTION_ACTION_FAILED', error instanceof Error ? error.message : 'Failed to run subscription action')
  }
})

router.get('/security', async (req: AdminRequest, res) => {
  try {
    res.json({ data: await buildAdminSecurityPayload(req.adminDb) })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_SECURITY_QUERY_FAILED', error instanceof Error ? error.message : 'Failed to load security dashboard')
  }
})

router.post('/security/policies', async (req: AdminRequest, res) => {
  const policyKey = textValue(req.body?.policyKey || req.body?.policy_key, '')
  const name = textValue(req.body?.name, '')
  if (!policyKey || !name) {
    jsonError(res, 400, 'VALIDATION_ERROR', 'Policy key and name are required')
    return
  }
  try {
    const { data, error } = await req.adminDb.from('admin_governance_policies').upsert({
      policy_key: policyKey,
      name,
      category: textValue(req.body?.category, 'access'),
      status: textValue(req.body?.status, 'enabled'),
      enforcement_level: textValue(req.body?.enforcementLevel || req.body?.enforcement_level, 'monitor'),
      description: textValue(req.body?.description, ''),
      config: recordOf(req.body?.config),
      updated_by: req.adminUser!.id,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'policy_key' }).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.security.policy_saved', 'policy', data.id, { policyKey })
    res.json({ data: { policy: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_POLICY_SAVE_FAILED', error instanceof Error ? error.message : 'Failed to save policy')
  }
})

router.post('/security/evidence', async (req: AdminRequest, res) => {
  const title = textValue(req.body?.title, 'Administrator evidence package')
  const framework = textValue(req.body?.framework, 'QGuardHelix Governance')
  try {
    const payload = {
      title,
      framework,
      status: 'generated',
      evidence_type: textValue(req.body?.evidenceType || req.body?.evidence_type, 'admin_snapshot'),
      generated_by: req.adminUser!.id,
      metadata: recordOf(req.body?.metadata),
      created_at: new Date().toISOString(),
    }
    const { data, error } = await req.adminDb.from('admin_compliance_evidence').insert(payload).select('*').single()
    if (error) throw error
    await recordAdminAudit(req, 'admin.governance.evidence_generated', 'compliance_evidence', data.id, { title, framework })
    res.status(201).json({ data: { evidence: data } })
  } catch (error) {
    jsonError(res, 500, 'ADMIN_EVIDENCE_CREATE_FAILED', error instanceof Error ? error.message : 'Failed to generate evidence')
  }
})

router.get('/activities', async (req: AdminRequest, res) => {
  const ctx: SafeContext = { unavailable: new Set() }
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(String(req.query.limit || '50'), 10) || 50))
  const [adminAudit, auditLogs, securityEvents, migrationEvents, subscriptions, roles] = await Promise.all([
    safeRows(ctx, req.adminDb, 'admin_audit_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(limit)),
    safeRows(ctx, req.adminDb, 'audit_logs', (q) => q.select('*').order('created_at', { ascending: false }).limit(limit)),
    safeRows(ctx, req.adminDb, 'security_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(limit)),
    safeRows(ctx, req.adminDb, 'migration_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(limit)),
    safeRows(ctx, req.adminDb, 'billing_subscriptions', (q) => q.select('*').order('updated_at', { ascending: false }).limit(limit)),
    safeRows(ctx, req.adminDb, 'admin_roles', (q) => q.select('*').order('updated_at', { ascending: false }).limit(limit)),
  ])
  const fallbackAuditLogs = adminAudit.length
    ? auditLogs.filter((row: any) => !recordOf(row.details).adminAudit)
    : auditLogs
  const activities = [
    ...adminAudit.map((row: any) => normalizeAdminAuditActivity(row)),
    ...fallbackAuditLogs.map((row: any) => normalizeGenericActivity(row, 'audit_logs')),
    ...securityEvents.map((row: any) => normalizeGenericActivity(row, 'security_events', {
      title: row.event_type || 'security event',
      detail: row.message || row.resource_name,
      severity: row.severity || 'info',
      createdAt: row.created_at,
    })),
    ...migrationEvents.map((row: any) => normalizeGenericActivity(row, 'migration_events', {
      title: row.event_type || 'migration event',
      detail: row.message,
      severity: row.severity || 'info',
      createdAt: row.created_at,
    })),
    ...subscriptions.map((row: any) => normalizeGenericActivity(row, 'billing_subscriptions', {
      title: `Subscription ${row.status || 'updated'}`,
      detail: row.plan || row.user_id,
      createdAt: row.updated_at || row.created_at,
    })),
    ...roles.map((row: any) => normalizeGenericActivity(row, 'admin_roles', {
      title: `Role ${row.status || 'updated'}`,
      detail: row.name || row.role_key,
      createdAt: row.updated_at || row.created_at,
    })),
  ].sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()).slice(0, limit)

  res.json({ data: { activities, unavailableTables: Array.from(ctx.unavailable).sort() } })
})

router.get('/stream', async (req: AdminRequest, res) => {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  const send = (event: string, data: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }

  send('admin-connected', {
    owner: req.adminUser!.email,
    timestamp: new Date().toISOString(),
  })
  await recordAdminAudit(req, 'admin.stream.connected', 'admin_dashboard')

  const push = async () => {
    try {
      const [stats, roles, subscriptions, security] = await Promise.all([
        buildAdminStats(req.adminDb),
        buildAdminRolesPayload(req.adminDb, {}, 1, DEFAULT_LIMIT),
        buildAdminSubscriptionsPayload(req.adminDb, {}, 1, 10),
        buildAdminSecurityPayload(req.adminDb),
      ])
      const tenants = await (async () => {
        const ctx: SafeContext = { unavailable: new Set() }
        const { data, error } = await req.adminDb.from('organizations').select('*').order('updated_at', { ascending: false }).limit(1000)
        if (error) return { tenants: [], stats: {}, pagination: { page: 1, limit: DEFAULT_LIMIT, total: 0, totalPages: 0 }, unavailableTables: ['organizations'], generatedAt: new Date().toISOString() }
        const enriched = await Promise.all((data || []).map((tenant: any) => enrichTenant(ctx, req.adminDb, tenant)))
        return {
          tenants: enriched.slice(0, DEFAULT_LIMIT),
          stats: {
            totalTenants: enriched.length,
            activeTenants: enriched.filter((tenant: any) => tenant.status === 'active').length,
            trialTenants: enriched.filter((tenant: any) => tenant.status === 'trial' || tenant.trialSubscriptions > 0).length,
            suspendedTenants: enriched.filter((tenant: any) => ['suspended', 'disabled'].includes(String(tenant.status || '').toLowerCase())).length,
            totalUsers: enriched.reduce((sum: number, tenant: any) => sum + numberValue(tenant.totalUsers, 0), 0),
            totalDevices: enriched.reduce((sum: number, tenant: any) => sum + numberValue(tenant.devices, 0), 0),
            tenantGrowthPercent: 0,
          },
          pagination: { page: 1, limit: DEFAULT_LIMIT, total: enriched.length, totalPages: Math.ceil(enriched.length / DEFAULT_LIMIT) },
          unavailableTables: Array.from(ctx.unavailable).sort(),
          generatedAt: new Date().toISOString(),
        }
      })()
      send('admin-stats', stats)
      send('admin-roles', roles)
      send('admin-tenants', tenants)
      send('admin-subscriptions', subscriptions)
      send('admin-security', security)
    } catch (error) {
      send('admin-error', { message: error instanceof Error ? error.message : 'Admin stream update failed' })
    }
  }

  await push()
  const interval = setInterval(push, 10_000)
  const heartbeat = setInterval(() => send('admin-heartbeat', { timestamp: new Date().toISOString() }), 30_000)

  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

export default router
