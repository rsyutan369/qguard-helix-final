import { createHash } from 'node:crypto'
import { Router, Request, Response, NextFunction } from 'express'
import type { User } from '@supabase/supabase-js'
import { getServerUser, getServiceClient, getToken, revokeUserTokensIssuedBefore } from '@/lib/supabase-server'
import { isOwnerEmail } from '@/lib/admin-access'
import { isAccessGrantingStatus } from '@/lib/subscription-access'
import {
  buildUserDirectory,
  describeUserAgent,
  directoryFacets,
  directoryToCsv,
  normalizeRoleKey as normalizeDirectoryRoleKey,
  queryUserDirectory,
  roleLabel,
  type AuthDirectoryRow,
  type AuthSource,
  type DirectoryQuery,
  type UserDirectory,
} from '@/lib/admin/user-directory'
import {
  RESERVED_ROLE_KEYS,
  ROLE_STATUSES,
  buildRoleCatalog,
  normalizePermissions,
  normalizeRoleKey as normalizeCatalogRoleKey,
  queryRoleCatalog,
  type CatalogRole,
  type RoleCatalog,
  type RoleDefinition,
  type SophiaEffect,
} from '@/lib/admin/role-catalog'
import { TENANT_SLUG_PATTERN, buildTenantDirectory, queryTenantDirectory, slugify, type TenantDirectory } from '@/lib/admin/tenant-directory'
import { buildBillingConsole, queryBillingRows, type BillingConsole, type BillingRow } from '@/lib/admin/billing-console'
import { buildSecurityPosture, listedCriticalVulnerabilities, type SecurityEventRow, type SecurityPosture, type SecurityWindow, type VulnerabilityRow } from '@/lib/admin/security-posture'
import {
  ENFORCEMENT_LEVELS,
  POLICY_CATEGORIES,
  POLICY_KEY_PATTERN,
  POLICY_STATUSES,
  VERIFIED_POLICY_KEYS,
  buildGovernanceModel,
  type GovernanceModel,
} from '@/lib/admin/governance'
import { HISTORY_CSV_COLUMNS, normalizeAdminAuditRow, normalizePlatformEvent, type HistoryEntry, type HistorySource } from '@/lib/admin/admin-history'
import { canonicalJson, modelVersion, toCsv } from '@/lib/admin/model-utils'
import { planChargeCents } from '@/lib/billing/plan-pricing'
import {
  invoiceAmountCents,
  normalizePlanTier,
  planChangeAuditAction,
  subscriptionChargeCents,
} from '@/lib/billing/revenue-model'
import { ROLE_CAPABILITIES, ROLE_LABELS as COPILOT_ROLE_LABELS, normalizeRole as normalizeCopilotRole } from './copilot-knowledge'
import { cancelSubscription } from './paypal'
import { readClientIp } from './runtime/client-ip'
import { streamTokenFromRequest } from './runtime/stream-tickets'

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
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

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

function percent(value: number, total: number): number {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return 0
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)))
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

function assertNoSupabaseError(result: any, fallback: string) {
  if (result?.error) throw new Error(result.error.message || fallback)
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

  // Admin audit never makes the primary operation fail — but a failed write is
  // logged, never swallowed (supabase-js returns { error }, it does not throw).
  try {
    const { error } = await db.from('admin_audit_events').insert(payload)
    if (error) console.error(`[admin] audit ${action} not recorded in admin_audit_events:`, error.message)
  } catch (err) {
    console.error(`[admin] audit ${action} not recorded in admin_audit_events:`, err instanceof Error ? err.message : err)
  }

  // audit_logs.entity_id is a uuid column; non-uuid entity ids stay in details.
  const uuidEntityId = entityId && UUID_PATTERN.test(entityId) ? entityId : null
  try {
    const { error } = await db.from('audit_logs').insert({
      user_id: actor.id,
      action,
      entity_type: entityType,
      entity_id: uuidEntityId,
      details: { ...details, adminAudit: true, actorEmail: actor.email || null, entityId: entityId || null },
      created_at: payload.created_at,
    })
    if (error) console.error(`[admin] audit ${action} not recorded in audit_logs:`, error.message)
  } catch (err) {
    console.error(`[admin] audit ${action} not recorded in audit_logs:`, err instanceof Error ? err.message : err)
  }
}

/**
 * Admin actions -> the billing_subscriptions.status vocabulary the database
 * CHECK constraint allows ('active','trial','expired','suspended',
 * 'pending_renewal','cancelled','past_due','incomplete'). The console used to
 * write 'approved', 'inactive' and 'canceled', which the constraint rejects,
 * so Approve / Deactivate / Cancel failed on every click.
 */
const ADMIN_ACTION_STATUS: Record<string, string> = {
  approve: 'active',
  activate: 'active',
  deactivate: 'suspended',
  cancel: 'cancelled',
}

/** A subscription whose billing a payment provider owns. */
function providerManaged(subscription: any): 'paypal' | 'google_play' | null {
  const provider = textValue(subscription?.provider, '').toLowerCase()
  return provider === 'paypal' || provider === 'google_play' ? provider : null
}

const PROVIDER_MANAGED_MESSAGE: Record<'paypal' | 'google_play', string> = {
  paypal: 'This subscription is billed by PayPal. Changing its plan, period or access here would disagree with what PayPal charges the customer: the customer changes plan from Settings > Billing, and administrators can only cancel it.',
  google_play: 'This subscription is billed by Google Play. Plan, period and cancellation are managed in the Play Console; the platform syncs them via RTDN.',
}

/**
 * Mirror an admin change into the CUSTOMER'S billing trail + notifications, so
 * the customer's Settings > Billing, the Admin console and Revenue
 * Intelligence all see the same event. Failures are logged, never swallowed.
 */
async function recordCustomerBillingEvent(req: AdminRequest, previous: any, next: any, adminAction: string) {
  const db = req.adminDb
  const userId = textValue(next?.user_id || previous?.user_id, '')
  if (!db || !userId) return
  const fromPlan = previous?.plan ?? null
  const toPlan = next?.plan ?? fromPlan
  const fromStatus = previous?.status ?? null
  const toStatus = next?.status ?? null
  const planAction = planChangeAuditAction(fromPlan, toPlan)
  const action = planAction
    || (toStatus && toStatus !== fromStatus
      ? toStatus === 'cancelled' ? 'subscription.cancelled'
        : toStatus === 'suspended' ? 'subscription.suspended'
          : isAccessGrantingStatus(toStatus) ? 'subscription.activated'
            : 'subscription.status_changed'
      : adminAction === 'deleted' ? 'subscription.deleted' : 'subscription.admin_updated')
  // Customer-facing wording (Settings > Billing trail + notifications): a verb, never a raw status token.
  const CUSTOMER_EVENT_LABEL: Record<string, string> = {
    'subscription.cancelled': 'Subscription cancelled',
    'subscription.suspended': 'Subscription suspended',
    'subscription.activated': 'Subscription activated',
    'subscription.deleted': 'Subscription record deleted',
    'subscription.admin_updated': 'Subscription updated',
  }
  const label = planAction
    ? `Plan changed ${fromPlan} to ${toPlan}`
    : CUSTOMER_EVENT_LABEL[action] || `Subscription status changed to ${String(toStatus || adminAction).replace(/_/g, ' ')}`
  try {
    const { error } = await db.from('billing_audit_events').insert({
      user_id: userId,
      action,
      message: `${label} by a QGuard administrator`,
      ip_address: readClientIp(req),
      user_agent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
      metadata: {
        source: 'admin',
        adminAction,
        actorUserId: req.adminUser?.id ?? null,
        actorEmail: req.adminUser?.email ?? null,
        fromPlan,
        toPlan,
        fromStatus,
        toStatus,
        subscriptionId: next?.id || previous?.id || null,
      },
    })
    if (error) console.error(`[admin] customer billing audit ${action} not recorded:`, error.message)
  } catch (err) {
    console.error(`[admin] customer billing audit ${action} not recorded:`, err instanceof Error ? err.message : err)
  }
  if (adminAction === 'renewal_reminder') return
  try {
    const { error } = await db.from('billing_notifications').insert({
      user_id: userId,
      type: 'subscription',
      severity: ['cancelled', 'suspended'].includes(String(toStatus)) || adminAction === 'deleted' ? 'warning' : 'info',
      title: 'Subscription updated',
      message: adminAction === 'deleted'
        ? 'Your subscription record was removed by a QGuard administrator.'
        : `A QGuard administrator updated your subscription: ${toPlan || 'plan unchanged'} (${String(toStatus || 'status unchanged').replace(/_/g, ' ')}).`,
    })
    if (error) console.error('[admin] customer billing notification not recorded:', error.message)
  } catch (err) {
    console.error('[admin] customer billing notification not recorded:', err instanceof Error ? err.message : err)
  }
}

// EventSource cannot send an Authorization header, so /stream authenticates
// with a short-lived single-use `?ticket=` (runtime/stream-tickets.ts).
// The owner's JWT itself is never accepted in a URL.
function isStreamRequest(req: Request): boolean {
  return (req.originalUrl || req.url || '').split('?')[0].endsWith('/stream')
}

async function requireOwner(req: AdminRequest, res: Response, next: NextFunction) {
  const token = isStreamRequest(req) ? streamTokenFromRequest(req) : getToken(req)
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
      // Path only: stream routes authenticate with ?token=<JWT>, which must
      // never be persisted in an audit row.
      details: { path: (req.originalUrl || '').split('?')[0] },
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

function groupByDay(rows: any[], dateFields: string[], days = 7) {
  const now = new Date()
  const buckets = Array.from({ length: days }, (_unused, index) => {
    const date = new Date(now.getTime() - (days - index - 1) * 24 * 60 * 60_000)
    const key = date.toISOString().slice(0, 10)
    return { key, label: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }), count: 0 }
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
  // Per-cycle list price from the ONE plan catalog (src/lib/billing/plan-pricing.ts).
  // This used to be a hardcoded copy of the price table that had to be edited in
  // lockstep with every repricing.
  const tier = normalizePlanTier(plan)
  if (!tier) return 0
  const text = cycle.toLowerCase()
  return planChargeCents(tier, text.includes('annual') || text.includes('year') ? 'yearly' : 'monthly')
}

function subscriptionAmountCents(subscription: any, _invoices: any[] = []) {
  // Contracted amount_cents, else the catalog list price — the shared rule in
  // src/lib/billing/revenue-model.ts. The latest-invoice fallback this replaced
  // turned a one-off prorated charge into the subscription's recurring price.
  const metadata = billingMetadata(subscription)
  const legacy = numberValue(subscription?.amount ?? subscription?.price_cents ?? metadata.amountCents ?? metadata.amount_cents ?? metadata.priceCents ?? metadata.price_cents, NaN)
  const { cents } = subscriptionChargeCents({
    plan: subscription?.plan ?? null,
    billing_cycle: billingCycleFor(subscription),
    amount_cents: numberValue(subscription?.amount_cents, 0) > 0 ? subscription.amount_cents : (Number.isFinite(legacy) && legacy > 0 ? legacy : null),
  })
  return cents
}

function billingEntitlementTier(plan: unknown, status: unknown) {
  const normalizedStatus = textValue(status, '').toLowerCase()
  if (['canceled', 'cancelled', 'inactive', 'deleted', 'suspended', 'expired'].includes(normalizedStatus)) return 'free'
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

// ---------------------------------------------------------------------------
// Users directory — ONE model (src/lib/admin/user-directory.ts), ONE loader.
// The Users table, its KPIs, filters, facets, CSV export, the Overview "Total
// Users" card and the SSE `admin-users` frame all read this computation.
// ---------------------------------------------------------------------------

const DIRECTORY_PAGE_SIZE = 1000
const DIRECTORY_MAX_PAGES = 50
const USER_DIRECTORY_TTL_MS = 5_000
let userDirectoryCache: { at: number; promise: Promise<UserDirectory> } | null = null

/** Open admin streams, told to push fresh frames after any console write. */
const consoleChangeListeners = new Set<() => void>()

/** After ANY admin write: drop every cached model and push to open consoles. */
function invalidateAdminModels() {
  userDirectoryCache = null
  consoleModelCache.clear()
  streamBundleCache = null
  for (const listener of consoleChangeListeners) listener()
}

/** Every row of a table, in PostgREST-sized pages (max_rows caps .limit at 1000). */
async function pagedSelect(db: any, table: string, columns: string, notes: string[], required = false, build?: (query: any) => any): Promise<any[]> {
  const rows: any[] = []
  for (let page = 0; page < DIRECTORY_MAX_PAGES; page += 1) {
    const from = page * DIRECTORY_PAGE_SIZE
    const base = db.from(table).select(columns)
    const { data, error } = await (build ? build(base) : base).order('id', { ascending: true }).range(from, from + DIRECTORY_PAGE_SIZE - 1)
    if (error) {
      if (required) throw new Error(`${table} could not be read: ${error.message}`)
      notes.push(`${table} unavailable (${error.code || 'error'}): ${error.message}`)
      return []
    }
    rows.push(...(data || []))
    if (!data || data.length < DIRECTORY_PAGE_SIZE) return rows
  }
  notes.push(`${table}: read ceiling of ${DIRECTORY_MAX_PAGES * DIRECTORY_PAGE_SIZE} rows reached — counts are a lower bound`)
  return rows
}

/** Supabase Auth identity via the service-role RPC; admin-API fallback. */
async function loadAuthDirectory(db: any, notes: string[]): Promise<{ rows: AuthDirectoryRow[]; source: AuthSource }> {
  const rows: AuthDirectoryRow[] = []
  for (let page = 0; page < DIRECTORY_MAX_PAGES; page += 1) {
    const from = page * DIRECTORY_PAGE_SIZE
    const { data, error } = await db.rpc('admin_user_auth_directory')
      .order('user_id', { ascending: true })
      .range(from, from + DIRECTORY_PAGE_SIZE - 1)
    if (error) {
      notes.push(`admin_user_auth_directory RPC failed (${error.code || 'error'}): ${error.message}`)
      return loadAuthDirectoryFromAdminApi(db, notes)
    }
    rows.push(...((data || []) as AuthDirectoryRow[]))
    if (!data || data.length < DIRECTORY_PAGE_SIZE) return { rows, source: 'rpc' }
  }
  notes.push(`Supabase Auth: read ceiling of ${DIRECTORY_MAX_PAGES * DIRECTORY_PAGE_SIZE} accounts reached — counts are a lower bound`)
  return { rows, source: 'rpc' }
}

async function loadAuthDirectoryFromAdminApi(db: any, notes: string[]): Promise<{ rows: AuthDirectoryRow[]; source: AuthSource }> {
  try {
    const rows: AuthDirectoryRow[] = []
    for (let page = 1; page <= DIRECTORY_MAX_PAGES; page += 1) {
      const { data, error } = await db.auth.admin.listUsers({ page, perPage: DIRECTORY_PAGE_SIZE })
      if (error) throw error
      const users: any[] = data?.users || []
      for (const user of users) {
        const factors: any[] | null = Array.isArray(user.factors) ? user.factors : null
        const verified = factors ? factors.filter((factor) => factor?.status === 'verified') : null
        rows.push({
          user_id: user.id,
          email: user.email ?? null,
          created_at: user.created_at ?? null,
          last_sign_in_at: user.last_sign_in_at ?? null,
          email_confirmed_at: user.email_confirmed_at ?? null,
          invited_at: user.invited_at ?? null,
          banned_until: user.banned_until ?? null,
          is_anonymous: Boolean(user.is_anonymous),
          providers: Array.isArray(user.app_metadata?.providers) ? user.app_metadata.providers : [],
          app_role: typeof user.app_metadata?.role === 'string' ? user.app_metadata.role : null,
          session_count: null,
          aal2_session_count: null,
          last_session_activity_at: null,
          last_session_ip: null,
          last_session_user_agent: null,
          mfa_verified_factors: verified ? verified.length : null,
          mfa_factor_types: verified ? Array.from(new Set(verified.map((factor) => String(factor.factor_type)))) : [],
        })
      }
      if (users.length < DIRECTORY_PAGE_SIZE) break
    }
    return { rows, source: 'admin_api' }
  } catch (err) {
    notes.push(`Supabase Auth admin API failed: ${err instanceof Error ? err.message : String(err)}`)
    return { rows: [], source: 'unavailable' }
  }
}

async function computeUserDirectory(db: any): Promise<UserDirectory> {
  const notes: string[] = []
  const [profiles, subscriptions, organizations, memberships, auth] = await Promise.all([
    pagedSelect(db, 'profiles', 'id,email,name,full_name,role,tier,tenant_id,account_status,mfa_required,created_at,updated_at', notes, true),
    // Plan access is a core column: rendering "No plan" because billing could
    // not be read would be a fabricated answer, so this read is required too.
    pagedSelect(db, 'billing_subscriptions', 'id,user_id,plan,status,provider,billing_cycle,current_period_end,cancel_at_period_end,metadata,updated_at', notes, true),
    pagedSelect(db, 'organizations', 'id,name,slug,status', notes),
    pagedSelect(db, 'organization_members', 'id,organization_id,user_id,role,status', notes),
    loadAuthDirectory(db, notes),
  ])
  return buildUserDirectory({
    profiles,
    auth: auth.rows,
    authSource: auth.source,
    subscriptions,
    organizations,
    memberships,
    notes,
  })
}

/** Single-flight, 5s-TTL cached directory; failures are never cached. */
function loadUserDirectory(db: any, options: { fresh?: boolean } = {}): Promise<UserDirectory> {
  const now = Date.now()
  if (!options.fresh && userDirectoryCache && now - userDirectoryCache.at < USER_DIRECTORY_TTL_MS) {
    return userDirectoryCache.promise
  }
  const entry = { at: now, promise: computeUserDirectory(db) }
  userDirectoryCache = entry
  entry.promise.catch(() => {
    if (userDirectoryCache === entry) userDirectoryCache = null
  })
  return entry.promise
}

function directoryQueryFrom(query: Request['query']): DirectoryQuery {
  const pick = (key: string) => (typeof query[key] === 'string' ? String(query[key]).slice(0, 200) : undefined)
  return {
    search: pick('search'),
    role: pick('role'),
    tenant: pick('tenant') || pick('tenantId'),
    plan: pick('plan') || pick('tier'),
    status: pick('status'),
    activity: pick('activity'),
    mfa: pick('mfa'),
    sort: pick('sort'),
    order: pick('order'),
    page: Number(pick('page')) || 1,
    limit: Number(pick('limit')) || DEFAULT_LIMIT,
  }
}

/** Roles a user may be given — the role catalogue's assignable set (one source). */
async function loadAssignableRoles(db: any) {
  const catalog = await loadRoleCatalog(db)
  return catalog.roles
    .filter((role) => role.assignable)
    .map((role) => ({ key: role.key, label: role.name, description: role.description || `Sophia: ${role.sophia.label}`, type: role.type }))
    .sort((a, b) => (a.key === 'user' ? -1 : b.key === 'user' ? 1 : a.label.localeCompare(b.label)))
}

async function buildAdminStats(db: any) {
  const ctx: SafeContext = { unavailable: new Set() }
  const since24h = new Date(Date.now() - 24 * 60 * 60_000).toISOString()
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString()

  const [
    totalUsers,
    profileRows,
    tenantRows,
    subscriptions,
    scanSessions,
    securityEvents,
    migrationJobs,
    vulnerabilities,
    complianceEvidence,
    auditRows,
    usageRows,
    directory,
    billing,
  ] = await Promise.all([
    safeCount(ctx, db, 'profiles'),
    safeRows(ctx, db, 'profiles', (q) => q.select('*').order('created_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'organizations', (q) => q.select('*').order('updated_at', { ascending: false }).limit(500)),
    // Only feeds the 7-day "Subscription changes" chart; every subscription
    // COUNT below comes from the Plans & Billing model (a full, paged read).
    safeRows(ctx, db, 'billing_subscriptions', (q) => q.select('id,created_at,updated_at').gte('updated_at', since7d).order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'pqc_scan_sessions', (q) => q.select('*').order('created_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'security_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'migration_jobs', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'vulnerabilities', (q) => q.select('*').order('updated_at', { ascending: false }).limit(2000)),
    safeRows(ctx, db, 'compliance_evidence', (q) => q.select('*').order('updated_at', { ascending: false }).limit(1000)),
    safeRows(ctx, db, 'admin_audit_events', (q) => q.select('*').order('created_at', { ascending: false }).limit(100)),
    safeRows(ctx, db, 'billing_usage_events', (q) => q.select('*').gte('created_at', since7d).order('created_at', { ascending: false }).limit(3000)),
    // User KPIs come from the Users directory — the same computation the Users
    // tab renders — so "Total Users" / sessions cannot disagree across tabs.
    loadUserDirectory(db).catch((error) => {
      console.error('[admin] user directory unavailable for stats:', error instanceof Error ? error.message : error)
      return null
    }),
    // Subscription + payment KPIs come from the Plans & Billing model — the
    // same computation that tab and Revenue Intelligence publish.
    loadBillingConsole(db).catch((error) => {
      console.error('[admin] billing model unavailable for stats:', error instanceof Error ? error.message : error)
      return null
    }),
  ])

  // Cash COLLECTED in the last 7 days: charges the provider collected (a later
  // refund does not un-collect one), in the reporting currency, by payment
  // time. Unknown (null) when the billing model could not be read — never $0.
  const since7dMs = Date.parse(since7d)
  const collected7dCents = billing
    ? billing.invoices
      .filter((invoice) => (invoice.status === 'paid' || invoice.status === 'refunded') && invoice.currency === 'USD')
      .filter((invoice) => invoice.paidAt !== null && Date.parse(invoice.paidAt) >= since7dMs)
      .reduce((sum, invoice) => sum + invoice.amountCents, 0)
    : null
  const billingByStatus = billing ? billing.stats.byStatus : null
  const completedJobs = migrationJobs.filter((row: any) => ['completed', 'done', 'success'].includes(String(row.status || '').toLowerCase()))
  const runningJobs = migrationJobs.filter((row: any) => ['running', 'in_progress', 'pending', 'queued'].includes(String(row.status || '').toLowerCase()))
  const scansInProgress = scanSessions.filter((row: any) => ['running', 'scanning', 'in_progress', 'queued'].includes(String(row.status || '').toLowerCase())).length
  const completedScans = scanSessions.filter((row: any) => ['completed', 'done', 'success'].includes(String(row.status || '').toLowerCase()))
  const criticalAlerts = securityEvents.filter((row: any) => ['critical', 'high'].includes(String(row.severity || '').toLowerCase())).length
  const failedLogins = securityEvents.filter((row: any) => /failed|denied|suspicious/i.test(`${row.event_type || ''} ${row.message || ''}`)).length
  // Unmeasured is null, never 0: an account with no score is not a 0% account,
  // and no migration jobs is not "0% migrated".
  const scoredProfiles = profileRows.filter((row: any) => row.q_score !== null && row.q_score !== undefined && Number.isFinite(Number(row.q_score)))
  const averageProfileScore = scoredProfiles.length
    ? Math.round(scoredProfiles.reduce((sum: number, row: any) => sum + Number(row.q_score), 0) / scoredProfiles.length)
    : null
  const migrationProgress = migrationJobs.length ? percent(completedJobs.length, migrationJobs.length) : null
  const compliancePassed = complianceEvidence.filter((row: any) => ['passed', 'complete', 'compliant', 'approved'].includes(String(row.status || '').toLowerCase())).length
  const userStats = directory?.stats || null

  return {
    timestamp: new Date().toISOString(),
    kpis: {
      totalUsers: userStats ? userStats.totalUsers : totalUsers,
      activeUsers: userStats ? userStats.activity.active30d : null,
      administratorUsers: userStats ? userStats.administrators : null,
      mfaEnabledUsers: userStats ? userStats.mfa.enrolled : null,
      unassignedUsers: userStats ? userStats.noTenant : null,
      newUsersLast30d: userStats ? userStats.newLast30d : null,
      activeTenants: tenantRows.filter((row: any) => userStatus(row) !== 'disabled').length,
      totalTenants: tenantRows.length,
      // Access-granting subscriptions (active / trial / pending renewal) — the
      // old filter matched 'trialing' and 'approved', statuses the database
      // never stores, so trials and pending renewals were not counted.
      activeSubscriptions: billing ? billing.stats.grantingAccess : null,
      payingSubscriptions: billing ? billing.plans.reduce((sum, plan) => sum + plan.paying, 0) : null,
      trialSubscriptions: billingByStatus ? billingByStatus.trial || 0 : null,
      pastDueSubscriptions: billing ? billing.stats.pastDue : null,
      mrrCents: billing ? billing.stats.mrrCents : null,
      subscriptionRevenue: collected7dCents,
      expiredPlans: billingByStatus ? billingByStatus.expired || 0 : null,
      activeNowUsers: userStats ? userStats.activity.activeNow : null,
      dormantUsers: userStats ? userStats.activity.dormant : null,
      neverSignedInUsers: userStats ? userStats.activity.never : null,
      suspendedUsers: userStats ? userStats.status.suspended : null,
      disabledUsers: userStats ? userStats.status.disabled : null,
      pendingVerificationUsers: userStats ? userStats.status.pending_verification : null,
      usersWithPlanAccess: userStats ? userStats.access.withAccess : null,
      // Live Supabase Auth sessions (public.user_sessions is only written when a
      // user opens Settings; it is not a session store).
      activeSessions: userStats ? userStats.liveSessions : null,
      pqcReadinessScore: averageProfileScore,
      migrationProgress,
      scansInProgress,
      completedScans: completedScans.length,
      criticalAlerts,
      failedLogins,
      complianceScore: complianceEvidence.length ? percent(compliancePassed, complianceEvidence.length) : null,
      migrationJobs: migrationJobs.length,
      usageEvents: usageRows.length,
    },
    summaries: {
      subscriptionStatus: billingByStatus
        ? (Object.entries(billingByStatus) as Array<[string, number]>).map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count)
        : [],
      accountStatus: userStats
        ? (Object.entries(userStats.status) as Array<[string, number]>).map(([label, count]) => ({ label, count }))
        : [],
      planAccess: userStats
        ? [
          ...(Object.entries(userStats.access.byTier) as Array<[string, number]>).map(([label, count]) => ({ label, count })),
          { label: 'no plan access', count: userStats.access.noAccess },
        ]
        : [],
      userActivity: userStats
        ? [
          { label: 'active now', count: userStats.activity.activeNow },
          { label: 'active in 30 days', count: userStats.activity.active30d },
          { label: 'dormant', count: userStats.activity.dormant },
          { label: 'never signed in', count: userStats.activity.never },
        ]
        : [],
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
    },
    realtime: {
      source: 'supabase',
      unavailableTables: [
        ...Array.from(ctx.unavailable),
        ...(directory ? [] : ['user directory (profiles / Supabase Auth)']),
        ...(billing ? [] : ['billing model (billing_subscriptions / billing_invoices)']),
      ].sort(),
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

// ---------------------------------------------------------------------------
// Users routes
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60_000
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const ADMIN_PASSWORD_MIN = 12
const ADMIN_PASSWORD_MAX = 128
/** Supabase Auth ban length for suspend/disable (~100 years = until restored). */
const INDEFINITE_BAN = '876000h'

class AdminHttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

function sendAdminError(res: Response, error: unknown, fallbackCode: string, fallbackMessage: string) {
  if (error instanceof AdminHttpError) {
    jsonError(res, error.status, error.code, error.message)
    return
  }
  jsonError(res, 500, fallbackCode, error instanceof Error ? error.message : fallbackMessage)
}

function requireUserId(id: string) {
  if (!UUID_PATTERN.test(id)) throw new AdminHttpError(400, 'INVALID_USER_ID', 'User id must be a UUID')
}

type TargetUser = {
  id: string
  profile: any | null
  authUser: any | null
  email: string
  name: string | null
  isOwner: boolean
}

/** The target account from BOTH stores — owner protection keys off its real email. */
async function loadTargetUser(db: any, id: string): Promise<TargetUser> {
  requireUserId(id)
  const [profileResult, authResult] = await Promise.all([
    db.from('profiles').select('id,email,name,full_name,role,tier,tenant_id,account_status,mfa_required').eq('id', id).maybeSingle(),
    db.auth.admin.getUserById(id),
  ])
  assertNoSupabaseError(profileResult, 'Failed to load the user profile')
  const authUser = authResult?.data?.user || null
  if (authResult?.error && !/not.?found/i.test(String(authResult.error.message || ''))) {
    throw new Error(`Failed to load the Supabase Auth account: ${authResult.error.message}`)
  }
  if (!profileResult.data && !authUser) throw new AdminHttpError(404, 'USER_NOT_FOUND', 'User not found')
  const email = textValue(profileResult.data?.email || authUser?.email, '')
  return {
    id,
    profile: profileResult.data || null,
    authUser,
    email,
    name: textValue(profileResult.data?.full_name || profileResult.data?.name, '') || null,
    isOwner: isOwnerEmail(email),
  }
}

function targetAuditDetails(target: TargetUser, details: Record<string, unknown> = {}) {
  return {
    targetType: 'user',
    targetUserId: target.id,
    targetEmail: target.email || null,
    targetName: target.name,
    ...details,
  }
}

/** Where a password-recovery link should land (the app's /reset-password page). */
function siteOrigin(req: Request): string {
  const candidates = [
    process.env.VITE_PUBLIC_APP_URL,
    process.env.PUBLIC_APP_URL,
    typeof req.headers.origin === 'string' ? req.headers.origin : '',
    `${req.protocol}://${req.get('host')}`,
  ]
  for (const candidate of candidates) {
    try {
      const url = new URL(textValue(candidate, ''))
      if (url.protocol === 'https:' || url.protocol === 'http:') return url.origin
    } catch {
      // try the next candidate
    }
  }
  return ''
}

async function recordUserSecurityEvent(
  req: AdminRequest,
  userId: string,
  eventType: string,
  severity: 'info' | 'success' | 'warning' | 'critical',
  message: string,
  metadata: Record<string, unknown> = {},
) {
  const { error } = await req.adminDb.from('user_security_events').insert({
    user_id: userId,
    event_type: eventType,
    severity,
    message,
    metadata: { source: 'admin', actorEmail: req.adminUser?.email || null, actorIp: readClientIp(req), ...metadata },
  })
  if (error) console.error(`[admin] user security event ${eventType} not recorded:`, error.message)
}

/**
 * End every session of a user, for real: delete their Supabase Auth sessions
 * (refresh tokens cascade, so no device can mint a new access token) and make
 * the API reject access tokens issued before now (they are verified locally).
 */
async function endAllSessions(req: AdminRequest, userId: string, reason: string, metadata: Record<string, unknown> = {}) {
  const db = req.adminDb
  const revokedAt = new Date()
  const warnings: string[] = []
  const rpc = await db.rpc('admin_revoke_user_sessions', { p_user_id: userId })
  const sessionsEnded: number | null = rpc.error ? null : Number(rpc.data ?? 0)
  if (rpc.error) warnings.push(`Supabase Auth sessions were not revoked: ${rpc.error.message}`)
  revokeUserTokensIssuedBefore(userId, revokedAt.getTime())
  const record = await db.from('admin_session_revocations').insert({
    user_id: userId,
    revoked_by: req.adminUser!.id,
    reason,
    metadata: { ...metadata, sessionsEnded },
    created_at: revokedAt.toISOString(),
  })
  if (record.error) warnings.push(`Revocation not recorded: ${record.error.message}`)
  // Settings' device list (public.user_sessions) must agree with the revocation.
  const legacy = await db.from('user_sessions')
    .update({ revoked_at: revokedAt.toISOString(), revoked_reason: reason })
    .eq('user_id', userId)
    .is('revoked_at', null)
  if (legacy.error) warnings.push(`Settings device sessions not marked revoked: ${legacy.error.message}`)
  return { sessionsEnded, revokedAt: revokedAt.toISOString(), warnings, rpcFailed: Boolean(rpc.error) }
}

/**
 * The ONE admin write path for a user's plan (Users tab + user creation).
 * Refuses provider-billed subscriptions, the owner, and past period ends.
 */
async function applyAdminSubscription(req: AdminRequest, userId: string, body: Record<string, unknown>) {
  const db = req.adminDb
  const action = textValue(body.action, 'activate').toLowerCase()
  const status = ADMIN_ACTION_STATUS[action] || ''
  if (!status) throw new AdminHttpError(400, 'UNKNOWN_SUBSCRIPTION_ACTION', `Unsupported subscription action: ${action}`)

  const profile = await db.from('profiles').select('id,email,name,full_name,tier,tenant_id').eq('id', userId).maybeSingle()
  assertNoSupabaseError(profile, 'Failed to load the user profile')
  if (!profile.data) throw new AdminHttpError(404, 'USER_NOT_FOUND', 'User profile not found')
  if (isOwnerEmail(profile.data.email)) {
    throw new AdminHttpError(400, 'OWNER_HAS_FULL_ACCESS', 'The owner account has full platform access by design and never carries a subscription.')
  }

  const existingSubscription = await db.from('billing_subscriptions').select('*').eq('user_id', userId).maybeSingle()
  assertNoSupabaseError(existingSubscription, 'Failed to load the existing subscription')
  const existing = existingSubscription.data || null
  const managed = providerManaged(existing)
  if (managed && isAccessGrantingStatus(existing?.status)) {
    throw new AdminHttpError(409, 'PROVIDER_MANAGED', PROVIDER_MANAGED_MESSAGE[managed])
  }
  if (!existing && (action === 'deactivate' || action === 'cancel')) {
    throw new AdminHttpError(404, 'NO_SUBSCRIPTION', 'This user has no subscription to change.')
  }

  const plan = normalizePlanTier(textValue(body.plan, '') || textValue(existing?.plan, ''))
  if (!plan) throw new AdminHttpError(400, 'INVALID_PLAN', 'Plan must be Starter, Basic, Pro or Elite')
  const billingCycle = textValue(body.interval || existing?.billing_cycle, 'monthly').toLowerCase().includes('annual') ? 'annual' : 'monthly'

  const now = Date.now()
  const expiresInput = textValue(body.expiresAt, '')
  let expiresAt: string
  if (expiresInput) {
    const ms = Date.parse(expiresInput)
    if (!Number.isFinite(ms)) throw new AdminHttpError(400, 'INVALID_PERIOD_END', 'Period end is not a valid date')
    if (status === 'active' && ms <= now) throw new AdminHttpError(400, 'INVALID_PERIOD_END', 'Period end must be in the future to grant access')
    expiresAt = new Date(ms).toISOString()
  } else if (status === 'active') {
    expiresAt = new Date(now + (billingCycle === 'annual' ? 365 : 30) * DAY_MS).toISOString()
  } else {
    expiresAt = existing?.current_period_end || new Date(now).toISOString()
  }

  // A plan or cycle change re-prices from the catalogue; an unchanged plan
  // keeps its recorded amount (never a stale price on a different plan).
  const planChanged = !existing || existing.plan !== plan || billingCycleFor(existing) !== billingCycle
  const amountCents = body.amountCents !== undefined
    ? Math.max(0, Math.round(numberValue(body.amountCents, 0)))
    : planChanged ? planAmountCents(plan, billingCycle) : numberValue(existing?.amount_cents, planAmountCents(plan, billingCycle))
  const existingMetadata = billingMetadata(existing)
  const nowIso = new Date(now).toISOString()
  // Granting a plan by hand on a row a payment provider used to bill (it has
  // lapsed — the active case was refused above) makes it a MANUAL grant. Left
  // as 'paypal' it was classified provider-billed and counted in MRR although
  // PayPal no longer charges the customer.
  const takeover = managed && status === 'active'
    ? {
      provider: 'manual',
      provider_subscription_id: null,
      auto_renew: false,
    }
    : {}
  const payload = {
    user_id: userId,
    ...takeover,
    // NOT NULL + unique. Every writer mints one (paypal_…, gp_…, test-sub-…);
    // an admin grant on a user with no row previously failed on this column.
    subscription_id: textValue(existing?.subscription_id, '') || `admin_${userId}`,
    tenant_id: textValue(body.tenantId || profile.data.tenant_id || existing?.tenant_id, '') || null,
    plan,
    status,
    billing_cycle: billingCycle,
    plan_interval: billingCycle,
    seats: Math.max(1, Math.round(numberValue(body.seats ?? existing?.seats, 1))),
    amount_cents: amountCents,
    currency: textValue(body.currency || existing?.currency, 'USD').toUpperCase(),
    current_period_end: expiresAt,
    renewal_date: expiresAt,
    cancel_at_period_end: status === 'active' ? false : existing?.cancel_at_period_end ?? false,
    approval_status: action === 'approve' ? 'approved' : existing?.approval_status || 'not_required',
    canceled_at: action === 'cancel' ? nowIso : null,
    cancelled_at: action === 'cancel' ? nowIso : null,
    metadata: {
      ...existingMetadata,
      adminAction: action,
      ...(managed && status === 'active'
        ? { previousProvider: existing?.provider ?? null, previousProviderSubscriptionId: existing?.provider_subscription_id ?? null, providerReplacedAt: nowIso }
        : {}),
      customPlan: body.customPlan || existingMetadata.customPlan || null,
      updatedBy: req.adminUser!.id,
      updatedByEmail: req.adminUser!.email || null,
      updatedAt: nowIso,
    },
    updated_at: nowIso,
  }
  const upsertResult = await db.from('billing_subscriptions').upsert(payload, { onConflict: 'user_id' }).select('*').single()
  assertNoSupabaseError(upsertResult, 'Failed to save the subscription')
  await syncBillingEntitlements(db, upsertResult.data, plan, status)
  const context = await loadSubscriptionContext(db, upsertResult.data)
  await recordAdminAudit(req, `admin.subscription.${action}`, 'subscription', upsertResult.data?.id || userId, subscriptionAuditDetails(existing || upsertResult.data, context.profile, context.tenant, {
    result: 'completed',
    action,
    nextStatus: status,
    nextPlan: plan,
    nextBillingCycle: billingCycle,
    nextRenewalDate: expiresAt,
    operation: existing ? 'updated_existing_subscription' : 'created_subscription',
  }))
  await recordCustomerBillingEvent(req, existing, upsertResult.data, action)
  return upsertResult.data
}

router.get('/users', async (req: AdminRequest, res) => {
  try {
    const [directory, assignableRoles] = await Promise.all([
      loadUserDirectory(req.adminDb),
      loadAssignableRoles(req.adminDb),
    ])
    const result = queryUserDirectory(directory, directoryQueryFrom(req.query))
    res.json({
      data: {
        users: result.users,
        pagination: result.pagination,
        stats: directory.stats,
        integrity: directory.integrity,
        sources: directory.sources,
        facets: directoryFacets(directory.users),
        assignableRoles,
        version: directory.version,
        generatedAt: directory.generatedAt,
      },
    })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USERS_QUERY_FAILED', 'Failed to load users')
  }
})

router.get('/users/export', async (req: AdminRequest, res) => {
  try {
    const format = req.query.format === 'json' ? 'json' : 'csv'
    const directory = await loadUserDirectory(req.adminDb, { fresh: true })
    const query = directoryQueryFrom(req.query)
    const { matched } = queryUserDirectory(directory, { ...query, page: 1, limit: 100 })
    const filters = { search: query.search || null, role: query.role || 'all', tenant: query.tenant || 'all', plan: query.plan || 'all', status: query.status || 'all', activity: query.activity || 'all', mfa: query.mfa || 'all' }
    await recordAdminAudit(req, 'admin.users.exported', 'user_directory', null, { format, rows: matched.length, filters, status: 'completed' })
    const stamp = directory.generatedAt.slice(0, 19).replace(/[:T]/g, '-')
    res.setHeader('Cache-Control', 'no-store')
    if (format === 'json') {
      res.setHeader('Content-Disposition', `attachment; filename="qguard-users-${stamp}.json"`)
      res.json({ generatedAt: directory.generatedAt, filters, rows: matched.length, stats: directory.stats, integrity: directory.integrity, sources: directory.sources, users: matched })
      return
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="qguard-users-${stamp}.csv"`)
    res.send(directoryToCsv(matched))
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USERS_EXPORT_FAILED', 'Failed to export users')
  }
})

router.post('/users', async (req: AdminRequest, res) => {
  const body = req.body || {}
  const email = textValue(body.email, '').toLowerCase()
  const password = typeof body.password === 'string' ? body.password : ''
  const name = textValue(body.name, '').slice(0, 120)
  const role = normalizeDirectoryRoleKey(body.role) || 'user'
  const tenantId = textValue(body.tenantId, '') || null
  const planInput = textValue(body.plan, 'none').toLowerCase()
  const mfaRequired = body.mfaRequired === true

  try {
    if (!EMAIL_PATTERN.test(email)) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Enter a valid email address')
    if (isOwnerEmail(email)) throw new AdminHttpError(400, 'OWNER_RESERVED', 'The owner account cannot be created from the console')
    if (password.length < ADMIN_PASSWORD_MIN || password.length > ADMIN_PASSWORD_MAX) {
      throw new AdminHttpError(400, 'WEAK_PASSWORD', `Temporary password must be ${ADMIN_PASSWORD_MIN}-${ADMIN_PASSWORD_MAX} characters`)
    }
    const roles = await loadAssignableRoles(req.adminDb)
    if (!roles.some((candidate) => candidate.key === role)) throw new AdminHttpError(400, 'INVALID_ROLE', `Role "${role}" is not an active, assignable role`)
    if (tenantId) {
      if (!UUID_PATTERN.test(tenantId)) throw new AdminHttpError(400, 'INVALID_TENANT', 'Tenant id must be a UUID')
      await assertTenantCapacity(req.adminDb, tenantId, null)
    }
    const plan = planInput === 'none' ? null : normalizePlanTier(planInput)
    if (planInput !== 'none' && !plan) throw new AdminHttpError(400, 'INVALID_PLAN', 'Plan must be none, Starter, Basic, Pro or Elite')

    const created = await req.adminDb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: name },
      app_metadata: { role },
    })
    if (created.error) {
      const message = String(created.error.message || '')
      if (/already|registered|exists/i.test(message)) throw new AdminHttpError(409, 'EMAIL_IN_USE', 'An account with this email already exists')
      throw new Error(message || 'Failed to create the Supabase Auth account')
    }
    const userId = created.data.user?.id
    if (!userId) throw new Error('Supabase Auth did not return the new user id')

    // The auth trigger creates the profile row; set the managed columns on it.
    const profileWrite = await req.adminDb.from('profiles').upsert({
      id: userId,
      email,
      name: name || null,
      full_name: name || null,
      role,
      tenant_id: tenantId,
      mfa_required: mfaRequired,
      account_status: 'active',
      last_admin_action_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }, { onConflict: 'id' }).select('id').single()
    if (profileWrite.error) {
      // Never leave a half-provisioned account behind.
      await req.adminDb.auth.admin.deleteUser(userId).catch(() => undefined)
      throw new Error(`Profile could not be provisioned: ${profileWrite.error.message}`)
    }

    const warnings: string[] = []
    if (tenantId) {
      const membership = await req.adminDb.from('organization_members').upsert({
        organization_id: tenantId,
        user_id: userId,
        role: role === 'user' ? 'member' : role,
        status: 'active',
        updated_at: new Date().toISOString(),
      }, { onConflict: 'organization_id,user_id' })
      if (membership.error) warnings.push(`Tenant membership not recorded: ${membership.error.message}`)
    }
    let subscription: any = null
    if (plan) {
      try {
        subscription = await applyAdminSubscription(req, userId, { action: 'activate', plan, interval: body.interval })
      } catch (err) {
        warnings.push(`Account created, but the ${plan} plan was not granted: ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    await recordAdminAudit(req, 'admin.user.created', 'user', userId, {
      targetType: 'user',
      targetUserId: userId,
      targetEmail: email,
      targetName: name || null,
      role,
      tenantId,
      plan: subscription?.plan || null,
      mfaRequired,
      warnings,
      status: warnings.length ? 'completed_with_warnings' : 'completed',
    })
    invalidateAdminModels()
    res.status(201).json({ data: { userId, email, plan: subscription?.plan || null, warnings } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USER_CREATE_FAILED', 'Failed to create user')
  }
})

router.get('/users/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  const live = req.query.live === '1'
  try {
    requireUserId(id)
    const directory = await loadUserDirectory(req.adminDb)
    const user = directory.users.find((candidate) => candidate.id === id)
    if (!user) throw new AdminHttpError(404, 'USER_NOT_FOUND', 'User not found')

    const db = req.adminDb
    const [sessionsResult, securityEvents, adminTrail, billingTrail] = await Promise.all([
      directory.sources.sessionsMeasured ? db.rpc('admin_user_auth_sessions', { p_user_id: id }) : Promise.resolve(null),
      optionalRows(db, 'user_security_events', (q) => q.select('id,event_type,severity,message,ip_address,user_agent,metadata,created_at').eq('user_id', id).order('created_at', { ascending: false }).limit(25)),
      optionalRows(db, 'admin_audit_events', (q) => q.select('id,action,actor_email,entity_type,entity_id,details,ip_address,created_at')
        .or(`entity_id.eq.${id},details->>targetUserId.eq.${id}`)
        .neq('action', 'admin.user.inspected')
        .order('created_at', { ascending: false })
        .limit(25)),
      optionalRows(db, 'billing_audit_events', (q) => q.select('id,action,message,metadata,created_at').eq('user_id', id).order('created_at', { ascending: false }).limit(15)),
    ])
    const sessionsMeasured = Boolean(sessionsResult && !sessionsResult.error)
    const sessions = sessionsMeasured
      ? (sessionsResult.data || []).map((row: any) => ({
        id: row.session_id,
        createdAt: row.created_at,
        lastActivityAt: row.last_activity_at,
        notAfter: row.not_after,
        aal: row.aal,
        ip: row.ip,
        userAgent: row.user_agent,
        device: describeUserAgent(row.user_agent),
        refreshCount: row.refresh_count,
      }))
      : null
    if (!live) await recordAdminAudit(req, 'admin.user.inspected', 'user', id, { targetType: 'user', targetUserId: id, targetEmail: user.email, targetName: user.name || null })
    res.json({
      data: {
        user,
        sessions,
        sessionsMeasured,
        securityEvents,
        adminTrail: adminTrail.map((row: any) => normalizeAdminAuditRow(row)),
        billingTrail,
        version: directory.version,
        generatedAt: directory.generatedAt,
      },
    })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USER_DETAIL_FAILED', 'Failed to load user')
  }
})

router.patch('/users/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  const body = req.body || {}
  try {
    const target = await loadTargetUser(req.adminDb, id)
    if (!target.profile) throw new AdminHttpError(409, 'PROFILE_MISSING', 'This auth account has no profile row to update')
    const update: Record<string, unknown> = {}
    const changes: Record<string, { from: unknown; to: unknown }> = {}
    const warnings: string[] = []

    if (Object.prototype.hasOwnProperty.call(body, 'name')) {
      const name = textValue(body.name, '').slice(0, 120) || null
      update.full_name = name
      update.name = name
      changes.name = { from: target.name, to: name }
    }

    let nextRole: string | null = null
    if (Object.prototype.hasOwnProperty.call(body, 'role')) {
      if (target.isOwner) throw new AdminHttpError(400, 'OWNER_IMMUTABLE', 'The owner role is fixed to the owner account')
      const role = normalizeDirectoryRoleKey(body.role)
      const roles = await loadAssignableRoles(req.adminDb)
      if (!roles.some((candidate) => candidate.key === role)) throw new AdminHttpError(400, 'INVALID_ROLE', `Role "${role || 'empty'}" is not an active, assignable role`)
      update.role = role
      nextRole = role
      changes.role = { from: target.profile.role || 'user', to: role }
    }

    let nextTenantId: string | null | undefined
    if (Object.prototype.hasOwnProperty.call(body, 'tenantId')) {
      const tenantId = textValue(body.tenantId, '') || null
      if (tenantId) {
        if (!UUID_PATTERN.test(tenantId)) throw new AdminHttpError(400, 'INVALID_TENANT', 'Tenant id must be a UUID')
        if (tenantId !== textValue(target.profile.tenant_id, '')) await assertTenantCapacity(req.adminDb, tenantId, id)
      }
      update.tenant_id = tenantId
      nextTenantId = tenantId
      changes.tenantId = { from: target.profile.tenant_id || null, to: tenantId }
    }

    if (!Object.keys(update).length) throw new AdminHttpError(400, 'NO_CHANGES', 'Nothing to update (name, role or tenantId)')
    update.last_admin_action_at = new Date().toISOString()
    const result = await req.adminDb.from('profiles').update(update).eq('id', id).select('id,role,tenant_id,full_name').single()
    assertNoSupabaseError(result, 'Failed to update the user profile')

    if (nextRole && target.authUser) {
      // Keep the Supabase Auth app_metadata role in step with the profile.
      const auth = await req.adminDb.auth.admin.updateUserById(id, { app_metadata: { ...(target.authUser.app_metadata || {}), role: nextRole } })
      if (auth.error) warnings.push(`Supabase Auth role not synced: ${auth.error.message}`)
    }
    if (nextTenantId !== undefined) {
      const previousTenant = textValue(target.profile.tenant_id, '')
      if (previousTenant && previousTenant !== nextTenantId) {
        const removed = await req.adminDb.from('organization_members').delete().eq('organization_id', previousTenant).eq('user_id', id)
        if (removed.error) warnings.push(`Previous tenant membership not removed: ${removed.error.message}`)
      }
      if (nextTenantId) {
        const membershipRole = nextRole || normalizeDirectoryRoleKey(target.profile.role) || 'member'
        const membership = await req.adminDb.from('organization_members').upsert({
          organization_id: nextTenantId,
          user_id: id,
          role: membershipRole === 'user' ? 'member' : membershipRole,
          status: 'active',
          updated_at: new Date().toISOString(),
        }, { onConflict: 'organization_id,user_id' })
        if (membership.error) warnings.push(`Tenant membership not recorded: ${membership.error.message}`)
      }
    }

    await recordAdminAudit(req, 'admin.user.updated', 'user', id, targetAuditDetails(target, {
      changes,
      changedFields: Object.keys(changes),
      warnings,
      status: warnings.length ? 'completed_with_warnings' : 'completed',
    }))
    invalidateAdminModels()
    res.json({ data: { userId: id, changes, warnings } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USER_UPDATE_FAILED', 'Failed to update user')
  }
})

router.delete('/users/:id', async (req: AdminRequest, res) => {
  const id = req.params.id
  try {
    const target = await loadTargetUser(req.adminDb, id)
    if (target.isOwner || id === req.adminUser!.id) throw new AdminHttpError(400, 'OWNER_IMMUTABLE', 'The owner account cannot be deleted')
    const confirmEmail = textValue(req.body?.confirmEmail, '').toLowerCase()
    if (!target.email || confirmEmail !== target.email.toLowerCase()) {
      throw new AdminHttpError(400, 'CONFIRMATION_REQUIRED', 'Type the user\'s email address to confirm deletion')
    }

    const subscription = await req.adminDb.from('billing_subscriptions').select('id,plan,status,provider').eq('user_id', id).maybeSingle()
    assertNoSupabaseError(subscription, 'Failed to check the user subscription')
    const managed = providerManaged(subscription.data)
    if (managed && isAccessGrantingStatus(subscription.data?.status)) {
      // Deleting the account would orphan a live provider billing agreement —
      // the customer would keep being charged. Cancel billing first.
      throw new AdminHttpError(409, 'ACTIVE_PROVIDER_SUBSCRIPTION', `This user has an active ${managed === 'paypal' ? 'PayPal' : 'Google Play'} subscription. Cancel it in Plans & Billing before deleting the account, so the customer is not charged again.`)
    }

    const sessions = await endAllSessions(req, id, 'admin_user_deleted')
    // Deleting the auth user cascades to profiles, billing_subscriptions,
    // organization_members and user_sessions (all ON DELETE CASCADE).
    if (target.authUser) {
      const deleted = await req.adminDb.auth.admin.deleteUser(id)
      if (deleted.error) throw new Error(`Supabase Auth account not deleted: ${deleted.error.message}`)
    }
    const leftover = await req.adminDb.from('profiles').delete().eq('id', id)
    assertNoSupabaseError(leftover, 'Failed to remove the profile row')
    // Tables keyed by user_id without a foreign key.
    const cleanup = await Promise.all([
      req.adminDb.from('user_devices').delete().eq('user_id', id),
      req.adminDb.from('billing_notifications').delete().eq('user_id', id),
    ])
    const warnings = [...sessions.warnings, ...cleanup.filter((result: any) => result.error).map((result: any) => `Cleanup: ${result.error.message}`)]

    await recordAdminAudit(req, 'admin.user.deleted', 'user', id, targetAuditDetails(target, {
      previousRole: target.profile?.role || null,
      previousAccountStatus: target.profile?.account_status || null,
      previousSubscription: subscription.data ? { plan: subscription.data.plan, status: subscription.data.status, provider: subscription.data.provider } : null,
      sessionsEnded: sessions.sessionsEnded,
      warnings,
      status: warnings.length ? 'completed_with_warnings' : 'completed',
    }))
    invalidateAdminModels()
    res.json({ data: { id, deleted: true, sessionsEnded: sessions.sessionsEnded, warnings } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USER_DELETE_FAILED', 'Failed to delete user')
  }
})

const USER_ACTION_ALIASES: Record<string, string> = { mfa_enable: 'mfa_require', mfa_disable: 'mfa_relax' }
const OWNER_BLOCKED_ACTIONS = new Set(['suspend', 'disable', 'force_logout'])

router.post('/users/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const rawAction = textValue(req.body?.action, '').toLowerCase()
  const action = USER_ACTION_ALIASES[rawAction] || rawAction
  const reason = textValue(req.body?.reason, '').slice(0, 500) || null
  try {
    if (!action) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Action is required')
    const target = await loadTargetUser(req.adminDb, id)
    if ((target.isOwner || id === req.adminUser!.id) && OWNER_BLOCKED_ACTIONS.has(action)) {
      throw new AdminHttpError(400, 'OWNER_IMMUTABLE', 'The owner account cannot be suspended, disabled or signed out from the console')
    }
    const db = req.adminDb
    const nowIso = new Date().toISOString()
    const warnings: string[] = []
    const result: Record<string, unknown> = { action, targetUserId: id }

    if (action === 'suspend' || action === 'disable' || action === 'restore') {
      const accountStatus = action === 'restore' ? 'active' : action === 'suspend' ? 'suspended' : 'disabled'
      const outcome = await setAccountStatus(req, target, accountStatus, reason)
      if (outcome.sessionsEnded !== null) result.sessionsEnded = outcome.sessionsEnded
      warnings.push(...outcome.warnings)
      result.accountStatus = accountStatus
      result.previousAccountStatus = outcome.previousStatus
    } else if (action === 'force_logout') {
      const sessions = await endAllSessions(req, id, 'admin_force_logout', { reason })
      if (sessions.rpcFailed) throw new Error(sessions.warnings[0] || 'Supabase Auth sessions were not revoked')
      warnings.push(...sessions.warnings)
      await recordUserSecurityEvent(req, id, 'session.revoked_all', 'warning',
        `All sessions were signed out by a QGuard administrator${reason ? `: ${reason}` : ''}`,
        { reason, sessionsEnded: sessions.sessionsEnded })
      result.sessionsEnded = sessions.sessionsEnded
      result.revokedAt = sessions.revokedAt
    } else if (action === 'reset_password') {
      if (!target.email) throw new AdminHttpError(409, 'EMAIL_MISSING', 'This account has no email address')
      const delivery = req.body?.delivery === 'link' ? 'link' : 'email'
      const origin = siteOrigin(req)
      const redirectTo = origin ? `${origin}/reset-password` : undefined
      if (delivery === 'email') {
        const sent = await db.auth.resetPasswordForEmail(target.email, redirectTo ? { redirectTo } : undefined)
        if (sent.error) {
          const rateLimited = sent.error.status === 429 || /rate limit/i.test(String(sent.error.message || ''))
          throw new AdminHttpError(rateLimited ? 429 : 502, rateLimited ? 'EMAIL_RATE_LIMITED' : 'EMAIL_NOT_SENT',
            rateLimited
              ? 'Supabase Auth email rate limit reached — try again later, or generate a one-time recovery link instead.'
              : `The reset email was not sent: ${sent.error.message}`)
        }
        result.delivery = 'email'
        result.sentTo = target.email
      } else {
        const link = await db.auth.admin.generateLink({ type: 'recovery', email: target.email, options: redirectTo ? { redirectTo } : undefined })
        assertNoSupabaseError(link, 'Failed to generate a password recovery link')
        const actionLink = link.data?.properties?.action_link || null
        if (!actionLink) throw new Error('Supabase Auth returned no recovery link')
        result.delivery = 'link'
        // Returned to the owner once; NEVER written to an audit row.
        result.recoveryLink = actionLink
      }
      await recordUserSecurityEvent(req, id, 'password.reset_initiated', 'info',
        delivery === 'email' ? 'A QGuard administrator sent a password reset email' : 'A QGuard administrator generated a one-time password recovery link',
        { delivery })
    } else if (action === 'mfa_require' || action === 'mfa_relax') {
      if (!target.profile) throw new AdminHttpError(409, 'PROFILE_MISSING', 'This auth account has no profile row')
      const mfaRequired = action === 'mfa_require'
      const profile = await db.from('profiles')
        .update({ mfa_required: mfaRequired, last_admin_action_at: nowIso })
        .eq('id', id)
        .select('id,mfa_required')
        .single()
      assertNoSupabaseError(profile, 'Failed to update the MFA policy')
      result.mfaRequired = mfaRequired
    } else if (action === 'verify_email') {
      if (!target.authUser) throw new AdminHttpError(409, 'AUTH_ACCOUNT_MISSING', 'This profile has no Supabase Auth account')
      if (target.authUser.email_confirmed_at) throw new AdminHttpError(409, 'ALREADY_VERIFIED', 'This email address is already confirmed')
      const auth = await db.auth.admin.updateUserById(id, { email_confirm: true })
      if (auth.error) throw new Error(`Email was not confirmed: ${auth.error.message}`)
      await recordUserSecurityEvent(req, id, 'email.confirmed_by_admin', 'info', 'Email address confirmed by a QGuard administrator')
      result.emailConfirmed = true
    } else {
      throw new AdminHttpError(400, 'UNKNOWN_ACTION', `Unsupported user action: ${rawAction}`)
    }

    const { recoveryLink: _link, ...auditable } = result
    await recordAdminAudit(req, `admin.user.${action}`, 'user', id, targetAuditDetails(target, {
      ...auditable,
      reason,
      previousRole: target.profile?.role || null,
      previousMfaRequired: target.profile?.mfa_required ?? null,
      warnings,
      status: warnings.length ? 'completed_with_warnings' : 'completed',
    }))
    invalidateAdminModels()
    res.json({ data: { ...result, warnings } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_USER_ACTION_FAILED', 'Failed to run the user action')
  }
})

router.post('/users/:id/subscription', async (req: AdminRequest, res) => {
  try {
    requireUserId(req.params.id)
    const subscription = await applyAdminSubscription(req, req.params.id, req.body || {})
    invalidateAdminModels()
    res.json({ data: { subscription } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_SUBSCRIPTION_UPDATE_FAILED', 'Failed to manage subscription')
  }
})

// ---------------------------------------------------------------------------
// Console models — Roles, Tenants, Plans & Billing, Security, Governance,
// History. Each tab reads ONE pure model (src/lib/admin/*), computed once per
// 5s window and shared by its API route, the SSE stream and its exports.
// ---------------------------------------------------------------------------

const CONSOLE_MODEL_TTL_MS = 5_000
const consoleModelCache = new Map<string, { at: number; promise: Promise<unknown> }>()

function cachedConsoleModel<T>(key: string, compute: () => Promise<T>): Promise<T> {
  const now = Date.now()
  const hit = consoleModelCache.get(key)
  if (hit && now - hit.at < CONSOLE_MODEL_TTL_MS) return hit.promise as Promise<T>
  const entry = { at: now, promise: compute() as Promise<unknown> }
  consoleModelCache.set(key, entry)
  entry.promise.catch(() => {
    if (consoleModelCache.get(key) === entry) consoleModelCache.delete(key)
  })
  return entry.promise as Promise<T>
}

/**
 * Edit forms send every field; the audit trail must name only the ones whose
 * stored value actually changes ('' / null are the same empty, numeric strings
 * from `numeric` columns equal their numbers).
 */
function sameStoredValue(a: unknown, b: unknown): boolean {
  const norm = (value: unknown) => {
    if (value === '' || value === undefined) return null
    if (typeof value === 'string' && /^-?\d+(\.\d+)?$/.test(value)) return Number(value)
    return value
  }
  return canonicalJson(norm(a)) === canonicalJson(norm(b))
}

const ROLE_DEFINITIONS: RoleDefinition[] = SYSTEM_ROLE_DEFINITIONS.map((definition) => ({
  role_key: definition.role_key,
  name: definition.name,
  description: definition.description,
  role_type: 'system' as const,
  permission_scope: definition.permission_scope,
  permissions: definition.permissions,
}))

/** What a role REALLY changes today: the Sophia copilot capability set. */
function sophiaEffectFor(roleKey: string, isOwner: boolean): SophiaEffect {
  const role = normalizeCopilotRole(roleKey === 'user' ? null : roleKey, isOwner)
  return { role, label: COPILOT_ROLE_LABELS[role], capabilities: { ...ROLE_CAPABILITIES[role] } }
}

function loadRoleCatalog(db: any): Promise<RoleCatalog> {
  return cachedConsoleModel('roles', async () => {
    const notes: string[] = []
    const [directory, rows, tenants] = await Promise.all([
      loadUserDirectory(db),
      pagedSelect(db, 'admin_roles', 'id,role_key,name,description,role_type,status,tenant_id,permission_scope,permissions,metadata,created_at,updated_at', notes, true),
      pagedSelect(db, 'organizations', 'id,name', notes),
    ])
    return buildRoleCatalog({
      rows,
      definitions: ROLE_DEFINITIONS,
      holders: directory.users.map((user) => ({ id: user.id, email: user.email, name: user.name, role: user.role, isOwner: user.isOwner })),
      tenants,
      sophiaFor: sophiaEffectFor,
    })
  })
}

function loadTenantDirectory(db: any): Promise<TenantDirectory> {
  return cachedConsoleModel('tenants', async () => {
    const notes: string[] = []
    const [directory, organizations, memberships] = await Promise.all([
      loadUserDirectory(db),
      pagedSelect(db, 'organizations', 'id,name,slug,owner_user_id,status,plan,quota_users,quota_storage_gb,metadata,created_at,updated_at', notes, true),
      pagedSelect(db, 'organization_members', 'id,organization_id,user_id,role,status', notes),
    ])
    return buildTenantDirectory({
      organizations,
      memberships,
      users: directory.users,
      unassignedUsers: directory.stats.noTenant,
      sessionsMeasured: directory.sources.sessionsMeasured,
    })
  })
}

function loadBillingConsole(db: any): Promise<BillingConsole> {
  return cachedConsoleModel('billing', async () => {
    const notes: string[] = []
    const [directory, subscriptions, invoices, paymentMethods, tenants] = await Promise.all([
      loadUserDirectory(db),
      pagedSelect(db, 'billing_subscriptions', '*', notes, true),
      pagedSelect(db, 'billing_invoices', 'id,user_id,invoice_id,provider_invoice_id,transaction_id,payment_date,amount_paid_cents,tax_cents,currency,payment_method_summary,subscription_plan,status,receipt_url,hosted_invoice_url,metadata,created_at,updated_at', notes, true),
      pagedSelect(db, 'billing_payment_methods', 'id,user_id,provider,brand,last4,exp_month,exp_year,is_default,updated_at', notes, false, (q: any) => q.is('removed_at', null)),
      pagedSelect(db, 'organizations', 'id,name', notes),
    ])
    return buildBillingConsole({ subscriptions, invoices, paymentMethods, users: directory.users, tenants })
  })
}

async function optionalTableRows(db: any, table: string, build: (query: any) => any): Promise<any[] | null> {
  try {
    const { data, error } = await build(db.from(table))
    if (error) return null
    return data || []
  } catch {
    return null
  }
}

function parseSecurityWindow(value: unknown): SecurityWindow {
  return value === '7d' || value === '30d' ? value : '24h'
}

function loadSecurityPosture(db: any, window: SecurityWindow): Promise<SecurityPosture> {
  return cachedConsoleModel(`security:${window}`, async () => {
    const notes: string[] = []
    const since = new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString()
    const recent = (q: any) => q.gte('created_at', since)
    const [directory, platformEvents, accountEvents, vulnerabilities, adminAudit, collectors, scannerAgents, integrations, sensors, connectors] = await Promise.all([
      loadUserDirectory(db),
      pagedSelect(db, 'security_events', 'id,event_type,severity,message,user_id,created_at', notes, false, recent),
      pagedSelect(db, 'user_security_events', 'id,event_type,severity,message,user_id,created_at', notes, false, recent),
      pagedSelect(db, 'vulnerabilities', 'id,title,severity,status,source,asset_id,created_at', notes),
      pagedSelect(db, 'admin_audit_events', 'id,action,actor_email,entity_type,entity_id,details,ip_address,created_at', notes, false, (q: any) => q.gte('created_at', since)),
      optionalTableRows(db, 'collector_agents', (q) => q.select('status,last_seen_at').limit(1000)),
      optionalTableRows(db, 'scanner_agents', (q) => q.select('status,last_seen_at').is('revoked_at', null).limit(1000)),
      optionalTableRows(db, 'service_integrations', (q) => q.select('status,updated_at').limit(1000)),
      optionalTableRows(db, 'sensor_nodes', (q) => q.select('status,updated_at').limit(1000)),
      optionalTableRows(db, 'connector_accounts', (q) => q.select('status,updated_at').limit(1000)),
    ])
    const events: SecurityEventRow[] = [
      ...platformEvents.map((row: any) => ({ ...row, source: 'platform' as const })),
      ...accountEvents.map((row: any) => ({ ...row, source: 'account' as const })),
    ]
    const seen = (rows: any[] | null) => rows ? rows.map((row) => ({ status: row.status ?? null, last_seen_at: row.last_seen_at ?? row.updated_at ?? null })) : null
    // Name the affected asset of each open critical finding (the control lists them).
    const criticalAssetIds = Array.from(new Set(listedCriticalVulnerabilities(vulnerabilities as VulnerabilityRow[])
      .filter((row) => row.asset_id)
      .map((row) => String(row.asset_id))))
    const assetNames = new Map<string, string>()
    if (criticalAssetIds.length) {
      const assets = await db.from('assets').select('id,name').in('id', criticalAssetIds)
      if (assets.error) notes.push(`assets: ${assets.error.message}`)
      for (const asset of assets.data || []) if (asset.name) assetNames.set(String(asset.id), String(asset.name))
    }
    return buildSecurityPosture({
      window,
      directory,
      events,
      vulnerabilities: vulnerabilities.map((row: any) => ({ ...row, asset_name: row.asset_id ? assetNames.get(String(row.asset_id)) ?? null : null })),
      adminAudit: adminAudit.sort((a: any, b: any) => String(b.created_at).localeCompare(String(a.created_at))),
      infrastructure: [
        { key: 'collector_agents', label: 'Collector agents', rows: seen(collectors) },
        { key: 'scanner_agents', label: 'Scanner agents', rows: seen(scannerAgents) },
        { key: 'service_integrations', label: 'Integrations', rows: seen(integrations) },
        { key: 'sensor_nodes', label: 'Sensors', rows: seen(sensors) },
        { key: 'connector_accounts', label: 'Source connectors', rows: seen(connectors) },
      ],
    })
  })
}

function sha3Hex(value: unknown): string {
  return createHash('sha3-256').update(canonicalJson(value)).digest('hex')
}

async function adminAuditExtent(db: any) {
  const [countResult, oldestResult] = await Promise.all([
    db.from('admin_audit_events').select('id', { count: 'exact', head: true }),
    db.from('admin_audit_events').select('created_at').order('created_at', { ascending: true }).limit(1).maybeSingle(),
  ])
  return { count: countResult.count || 0, oldestAt: oldestResult.data?.created_at || null }
}

function loadGovernanceModel(db: any): Promise<GovernanceModel> {
  return cachedConsoleModel('governance', async () => {
    const notes: string[] = []
    const [directory, security, policies, evidence, audit] = await Promise.all([
      loadUserDirectory(db),
      loadSecurityPosture(db, '30d'),
      pagedSelect(db, 'admin_governance_policies', 'id,policy_key,name,category,status,enforcement_level,description,config,updated_by,created_at,updated_at', notes, true),
      pagedSelect(db, 'admin_compliance_evidence', 'id,title,framework,evidence_type,status,generated_by,metadata,created_at', notes, true),
      adminAuditExtent(db),
    ])
    return buildGovernanceModel({
      policies,
      evidence,
      controls: security.controls,
      deniedAttempts30d: security.summary.blockedAdminAttempts,
      audit,
      emailById: new Map(directory.users.map((user) => [user.id, user.email])),
      verifyHash: (snapshot, expected) => sha3Hex(snapshot) === expected,
    })
  })
}

/** History headline (7 days) + a version that moves with every new audit row. */
function loadHistoryStats(db: any) {
  return cachedConsoleModel('history', async () => {
    const notes: string[] = []
    const since = new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString()
    const [rows, latest, extent] = await Promise.all([
      pagedSelect(db, 'admin_audit_events', 'id,action,actor_email,details,created_at', notes, true, (q: any) => q.gte('created_at', since)),
      db.from('admin_audit_events').select('id,created_at').order('created_at', { ascending: false }).limit(1).maybeSingle(),
      adminAuditExtent(db),
    ])
    const entries = rows.map((row: any) => normalizeAdminAuditRow(row))
    const byCategory: Record<string, number> = {}
    for (const entry of entries) byCategory[entry.category] = (byCategory[entry.category] || 0) + 1
    const changes = entries.filter((entry: HistoryEntry) => entry.category !== 'views')
    const stats = {
      last7d: changes.length,
      views7d: byCategory.views || 0,
      byCategory,
      actors7d: new Set(changes.map((entry: HistoryEntry) => entry.actor).filter(Boolean)).size,
      blocked7d: changes.filter((entry: HistoryEntry) => entry.result === 'blocked' || entry.result === 'failed').length,
      totalRecords: extent.count,
      oldestAt: extent.oldestAt,
      latestAt: latest.data?.created_at || null,
    }
    return { stats, version: modelVersion({ total: extent.count, latest: latest.data?.id || null }), generatedAt: new Date().toISOString() }
  })
}

/**
 * Set an account's status the ONE way: Supabase Auth ban first (the
 * enforcement), then the profile (rolled back on failure), then end every
 * session when blocking. Used by the Users actions and tenant suspension.
 */
async function setAccountStatus(req: AdminRequest, target: TargetUser, accountStatus: 'active' | 'suspended' | 'disabled', reason: string | null) {
  const db = req.adminDb
  if (!target.authUser) throw new AdminHttpError(409, 'AUTH_ACCOUNT_MISSING', 'This profile has no Supabase Auth account to block or restore')
  if (!target.profile) throw new AdminHttpError(409, 'PROFILE_MISSING', 'This auth account has no profile row')
  const previousStatus = textValue(target.profile.account_status, 'active')
  const auth = await db.auth.admin.updateUserById(target.id, {
    ban_duration: accountStatus === 'active' ? 'none' : INDEFINITE_BAN,
    app_metadata: { ...(target.authUser.app_metadata || {}), account_status: accountStatus },
  })
  if (auth.error) throw new Error(`Supabase Auth was not updated: ${auth.error.message}`)
  const profile = await db.from('profiles')
    .update({ account_status: accountStatus, last_admin_action_at: new Date().toISOString() })
    .eq('id', target.id)
    .select('id,account_status')
    .single()
  if (profile.error) {
    await db.auth.admin.updateUserById(target.id, {
      ban_duration: previousStatus === 'active' ? 'none' : INDEFINITE_BAN,
      app_metadata: { ...(target.authUser.app_metadata || {}), account_status: previousStatus },
    }).catch(() => undefined)
    throw new Error(`Profile status was not updated (Supabase Auth change rolled back): ${profile.error.message}`)
  }
  const warnings: string[] = []
  let sessionsEnded: number | null = null
  if (accountStatus !== 'active') {
    const sessions = await endAllSessions(req, target.id, `admin_${accountStatus === 'suspended' ? 'suspend' : 'disable'}`, { reason })
    sessionsEnded = sessions.sessionsEnded
    warnings.push(...sessions.warnings)
  }
  await recordUserSecurityEvent(req, target.id,
    accountStatus === 'active' ? 'account.restored' : `account.${accountStatus}`,
    accountStatus === 'active' ? 'success' : 'warning',
    accountStatus === 'active'
      ? 'Account access restored by a QGuard administrator'
      : `Account ${accountStatus} by a QGuard administrator${reason ? `: ${reason}` : ''}`,
    { reason })
  return { previousStatus, sessionsEnded, warnings }
}

/** Refuse to put a user into a tenant that is at its user quota. */
async function assertTenantCapacity(db: any, tenantId: string, joiningUserId: string | null) {
  const tenant = await db.from('organizations').select('id,name,quota_users,status').eq('id', tenantId).maybeSingle()
  assertNoSupabaseError(tenant, 'Failed to check the tenant')
  if (!tenant.data) throw new AdminHttpError(400, 'INVALID_TENANT', 'Tenant not found')
  const quota = numberValue(tenant.data.quota_users, 0)
  if (quota <= 0) return tenant.data
  let members = db.from('profiles').select('id', { count: 'exact', head: true }).eq('tenant_id', tenantId)
  if (joiningUserId) members = members.neq('id', joiningUserId)
  const { count, error } = await members
  if (error) throw new Error(`Failed to count tenant members: ${error.message}`)
  if ((count || 0) >= quota) {
    throw new AdminHttpError(409, 'TENANT_QUOTA_REACHED', `${tenant.data.name} is at its user quota (${count} of ${quota}). Raise the quota in Tenants first.`)
  }
  return tenant.data
}

/** Evidence = measured state, generated here — never figures sent by a browser. */
async function buildEvidenceSnapshot(req: AdminRequest) {
  const db = req.adminDb
  const [directory, roles, tenants, billing, security, governance, audit] = await Promise.all([
    loadUserDirectory(db, { fresh: true }),
    loadRoleCatalog(db),
    loadTenantDirectory(db),
    loadBillingConsole(db),
    loadSecurityPosture(db, '30d'),
    loadGovernanceModel(db),
    adminAuditExtent(db),
  ])
  return {
    schema: 'qguard.admin.evidence/v1',
    generatedAt: new Date().toISOString(),
    generatedBy: { id: req.adminUser!.id, email: req.adminUser!.email || null },
    users: { stats: directory.stats, integrity: directory.integrity, sources: { auth: directory.sources.auth, sessionsMeasured: directory.sources.sessionsMeasured, mfaMeasured: directory.sources.mfaMeasured } },
    roles: { stats: roles.stats, integrity: roles.integrity },
    tenants: { stats: tenants.stats, integrity: tenants.integrity },
    billing: { stats: billing.stats, integrity: billing.integrity },
    security: {
      window: security.window,
      summary: security.summary,
      controls: security.controls.map((control) => ({ id: control.id, label: control.label, status: control.status, measured: control.measured, affected: control.affected.map((item) => item.label) })),
    },
    policies: governance.policies.map((policy) => ({ key: policy.key, name: policy.name, status: policy.status, enforcementLevel: policy.enforcementLevel, verification: policy.verification })),
    audit,
  }
}

// ---------------------------------------------------------------------------
// Roles routes
// ---------------------------------------------------------------------------

function pickQuery(query: Request['query'], key: string): string | undefined {
  return typeof query[key] === 'string' ? String(query[key]).slice(0, 200) : undefined
}

function roleAuditPayload(role: CatalogRole | null, details: Record<string, unknown> = {}) {
  return {
    targetType: 'role',
    targetName: role?.name || null,
    roleKey: role?.key || null,
    roleType: role?.type || null,
    holders: role?.holders ?? null,
    ...details,
  }
}

async function findCatalogRoleById(db: any, id: string) {
  if (!UUID_PATTERN.test(id)) throw new AdminHttpError(400, 'INVALID_ROLE_ID', 'Role id must be a UUID')
  const catalog = await loadRoleCatalog(db)
  const role = catalog.roles.find((candidate) => candidate.id === id)
  if (!role) throw new AdminHttpError(404, 'ROLE_NOT_FOUND', 'Role not found')
  return role
}

async function validateRoleTenant(db: any, value: unknown) {
  const tenantId = textValue(value, '') || null
  if (!tenantId) return null
  if (!UUID_PATTERN.test(tenantId)) throw new AdminHttpError(400, 'INVALID_TENANT', 'Tenant id must be a UUID')
  const tenant = await db.from('organizations').select('id').eq('id', tenantId).maybeSingle()
  assertNoSupabaseError(tenant, 'Failed to check the tenant')
  if (!tenant.data) throw new AdminHttpError(400, 'INVALID_TENANT', 'Tenant not found')
  return tenantId
}

router.get('/roles', async (req: AdminRequest, res) => {
  try {
    const catalog = await loadRoleCatalog(req.adminDb)
    const result = queryRoleCatalog(catalog, {
      search: pickQuery(req.query, 'search'),
      type: pickQuery(req.query, 'type'),
      status: pickQuery(req.query, 'status'),
      tenant: pickQuery(req.query, 'tenant'),
      usage: pickQuery(req.query, 'usage'),
      page: Number(pickQuery(req.query, 'page')) || 1,
      limit: Number(pickQuery(req.query, 'limit')) || DEFAULT_LIMIT,
    })
    res.json({ data: { roles: result.rows, pagination: result.pagination, stats: catalog.stats, integrity: catalog.integrity, version: catalog.version, generatedAt: catalog.generatedAt } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_ROLES_QUERY_FAILED', 'Failed to load roles')
  }
})

router.post('/roles', async (req: AdminRequest, res) => {
  const body = req.body || {}
  try {
    const name = textValue(body.name, '').slice(0, 80)
    if (!name) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Role name is required')
    const key = normalizeCatalogRoleKey(body.key || name)
    if (!key || key.length > 64) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Role key must be 1-64 letters, digits or underscores')
    if (key === 'user' || RESERVED_ROLE_KEYS.has(key) || SYSTEM_ROLE_DEFINITIONS.some((definition) => definition.role_key === key)) {
      throw new AdminHttpError(409, 'ROLE_KEY_RESERVED', `"${key}" is a built-in or system role key`)
    }
    const { permissions, invalid } = normalizePermissions(body.permissions)
    if (invalid.length) throw new AdminHttpError(400, 'INVALID_PERMISSIONS', `Invalid permission pattern(s): ${invalid.join(', ')} — use dotted patterns such as security.read or audit.*`)
    const tenantId = await validateRoleTenant(req.adminDb, body.tenantId)
    const existing = await req.adminDb.from('admin_roles').select('id').eq('role_key', key).maybeSingle()
    assertNoSupabaseError(existing, 'Failed to check the role key')
    if (existing.data) throw new AdminHttpError(409, 'ROLE_EXISTS', `A role with key "${key}" already exists`)
    const status = ROLE_STATUSES.includes(body.status) ? body.status : 'active'
    const payload = {
      role_key: key,
      name,
      description: textValue(body.description, '').slice(0, 500) || null,
      role_type: 'custom',
      status,
      tenant_id: tenantId,
      permission_scope: textValue(body.scope, '').slice(0, 40) || (permissions.includes('*') ? 'All' : 'Custom'),
      permission_count: permissions.length,
      permissions,
      metadata: {},
      created_by: req.adminUser!.id,
      updated_by: req.adminUser!.id,
    }
    const created = await req.adminDb.from('admin_roles').insert(payload).select('id').single()
    assertNoSupabaseError(created, 'Failed to create the role')
    await recordAdminAudit(req, 'admin.role.created', 'role', created.data.id, { targetType: 'role', targetName: name, roleKey: key, permissions, tenantId, status: 'completed' })
    invalidateAdminModels()
    res.status(201).json({ data: { id: created.data.id, key } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_ROLE_CREATE_FAILED', 'Failed to create role')
  }
})

router.patch('/roles/:id', async (req: AdminRequest, res) => {
  const body = req.body || {}
  try {
    const role = await findCatalogRoleById(req.adminDb, req.params.id)
    if (role.protected) throw new AdminHttpError(400, 'ROLE_PROTECTED', 'System and built-in roles cannot be edited from the console')
    const update: Record<string, unknown> = { updated_by: req.adminUser!.id, updated_at: new Date().toISOString() }
    const changes: Record<string, { from: unknown; to: unknown }> = {}
    if (Object.prototype.hasOwnProperty.call(body, 'name')) {
      const name = textValue(body.name, '').slice(0, 80)
      if (!name) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Role name cannot be empty')
      update.name = name
      changes.name = { from: role.name, to: name }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'description')) {
      update.description = textValue(body.description, '').slice(0, 500) || null
      changes.description = { from: role.description, to: update.description }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'scope')) {
      update.permission_scope = textValue(body.scope, '').slice(0, 40) || 'Custom'
      changes.scope = { from: role.scope, to: update.permission_scope }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'permissions')) {
      const { permissions, invalid } = normalizePermissions(body.permissions)
      if (invalid.length) throw new AdminHttpError(400, 'INVALID_PERMISSIONS', `Invalid permission pattern(s): ${invalid.join(', ')}`)
      update.permissions = permissions
      update.permission_count = permissions.length
      changes.permissions = { from: role.permissions, to: permissions }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'tenantId')) {
      update.tenant_id = await validateRoleTenant(req.adminDb, body.tenantId)
      changes.tenantId = { from: role.tenantId, to: update.tenant_id }
    }
    for (const [field, change] of Object.entries(changes)) if (sameStoredValue(change.from, change.to)) delete changes[field]
    if (!Object.keys(changes).length) throw new AdminHttpError(400, 'NO_CHANGES', 'Nothing changed')
    const result = await req.adminDb.from('admin_roles').update(update).eq('id', role.id).select('id').single()
    assertNoSupabaseError(result, 'Failed to update the role')
    await recordAdminAudit(req, 'admin.role.updated', 'role', role.id, roleAuditPayload(role, { changes, changedFields: Object.keys(changes), status: 'completed' }))
    invalidateAdminModels()
    res.json({ data: { id: role.id, changes } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_ROLE_UPDATE_FAILED', 'Failed to update role')
  }
})

router.post('/roles/:id/actions', async (req: AdminRequest, res) => {
  const action = textValue(req.body?.action, '').toLowerCase()
  try {
    const role = await findCatalogRoleById(req.adminDb, req.params.id)
    if (role.protected) throw new AdminHttpError(400, 'ROLE_PROTECTED', 'System and built-in roles cannot be changed from the console')
    if (action === 'delete') {
      if (role.holders > 0) throw new AdminHttpError(409, 'ROLE_IN_USE', `${role.name} is held by ${role.holders} user(s). Reassign them in Users first.`)
      if (textValue(req.body?.confirmKey, '') !== role.key) throw new AdminHttpError(400, 'CONFIRMATION_REQUIRED', `Type the role key "${role.key}" to confirm deletion`)
      const deleted = await req.adminDb.from('admin_roles').delete().eq('id', role.id).select('id').single()
      assertNoSupabaseError(deleted, 'Failed to delete the role')
      await recordAdminAudit(req, 'admin.role.deleted', 'role', role.id, roleAuditPayload(role, { status: 'completed' }))
      invalidateAdminModels()
      res.json({ data: { id: role.id, deleted: true } })
      return
    }
    const nextStatus = action === 'activate' ? 'active' : action === 'deactivate' ? 'inactive' : action === 'archive' ? 'archived' : ''
    if (!nextStatus) throw new AdminHttpError(400, 'UNKNOWN_ROLE_ACTION', `Unsupported role action: ${action}`)
    if (role.status === nextStatus) throw new AdminHttpError(409, 'NO_CHANGE', `${role.name} is already ${nextStatus}`)
    const result = await req.adminDb.from('admin_roles').update({ status: nextStatus, updated_by: req.adminUser!.id, updated_at: new Date().toISOString() }).eq('id', role.id).select('id').single()
    assertNoSupabaseError(result, 'Failed to update the role status')
    await recordAdminAudit(req, `admin.role.${action}`, 'role', role.id, roleAuditPayload(role, {
      previousStatus: role.status,
      nextStatus,
      stillHeldBy: nextStatus === 'active' ? 0 : role.holders,
      status: nextStatus !== 'active' && role.holders > 0 ? 'completed_with_warnings' : 'completed',
    }))
    invalidateAdminModels()
    res.json({ data: { id: role.id, status: nextStatus, stillHeldBy: nextStatus === 'active' ? 0 : role.holders, warnings: nextStatus !== 'active' && role.holders > 0 ? [`${role.holders} user(s) still hold this role; it can no longer be assigned to anyone new.`] : [] } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_ROLE_ACTION_FAILED', 'Failed to update role')
  }
})

// ---------------------------------------------------------------------------
// Tenants routes
// ---------------------------------------------------------------------------

async function findTenant(db: any, id: string) {
  if (!UUID_PATTERN.test(id)) throw new AdminHttpError(400, 'INVALID_TENANT_ID', 'Tenant id must be a UUID')
  const directory = await loadTenantDirectory(db)
  const tenant = directory.tenants.find((candidate) => candidate.id === id)
  if (!tenant) throw new AdminHttpError(404, 'TENANT_NOT_FOUND', 'Tenant not found')
  return tenant
}

/**
 * organizations.quota_users / quota_storage_gb are NOT NULL (schema defaults
 * apply on insert): a quota can be changed but never cleared to "unlimited".
 */
function tenantQuota(value: unknown, label: string, max: number): number | null {
  if (value === null || value === '' || value === undefined) return null
  const num = Math.floor(Number(value))
  if (!Number.isFinite(num) || num < 1 || num > max) throw new AdminHttpError(400, 'INVALID_QUOTA', `${label} must be a whole number between 1 and ${max}`)
  return num
}

async function validateTenantOwner(db: any, value: unknown) {
  const ownerId = textValue(value, '') || null
  if (!ownerId) return null
  if (!UUID_PATTERN.test(ownerId)) throw new AdminHttpError(400, 'INVALID_OWNER', 'Owner must be a user id')
  const directory = await loadUserDirectory(db)
  if (!directory.users.some((user) => user.id === ownerId)) throw new AdminHttpError(400, 'INVALID_OWNER', 'Owner account not found')
  return ownerId
}

function tenantMetadataPatch(existing: Record<string, unknown>, body: Record<string, unknown>) {
  const next = { ...existing }
  for (const key of ['domain', 'region'] as const) {
    if (!Object.prototype.hasOwnProperty.call(body, key)) continue
    const value = textValue(body[key], '').toLowerCase().slice(0, 120)
    if (value && key === 'domain' && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(value)) throw new AdminHttpError(400, 'INVALID_DOMAIN', 'Domain must look like example.com')
    if (value) next[key] = value
    else delete next[key]
  }
  return next
}

router.get('/tenants', async (req: AdminRequest, res) => {
  try {
    const directory = await loadTenantDirectory(req.adminDb)
    const result = queryTenantDirectory(directory, {
      search: pickQuery(req.query, 'search'),
      status: pickQuery(req.query, 'status'),
      quota: pickQuery(req.query, 'quota'),
      page: Number(pickQuery(req.query, 'page')) || 1,
      limit: Number(pickQuery(req.query, 'limit')) || DEFAULT_LIMIT,
    })
    res.json({ data: { tenants: result.rows, pagination: result.pagination, stats: directory.stats, integrity: directory.integrity, version: directory.version, generatedAt: directory.generatedAt } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_TENANTS_QUERY_FAILED', 'Failed to load tenants')
  }
})

router.post('/tenants', async (req: AdminRequest, res) => {
  const body = req.body || {}
  try {
    const name = textValue(body.name, '').slice(0, 120)
    if (!name) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Tenant name is required')
    const slug = (textValue(body.slug, '') ? textValue(body.slug, '').toLowerCase() : slugify(name))
    if (!TENANT_SLUG_PATTERN.test(slug)) throw new AdminHttpError(400, 'INVALID_SLUG', 'Slug must be 1-64 lowercase letters, digits or hyphens')
    const ownerId = await validateTenantOwner(req.adminDb, body.ownerUserId)
    const payload: Record<string, unknown> = {
      name,
      slug,
      owner_user_id: ownerId,
      status: 'active',
      metadata: tenantMetadataPatch({}, body),
    }
    // Unset quotas are OMITTED so the schema defaults apply (explicit NULL violates NOT NULL).
    const quotaUsers = tenantQuota(body.quotaUsers, 'User quota', 100000)
    const quotaStorageGb = tenantQuota(body.quotaStorageGb, 'Storage quota', 100000)
    if (quotaUsers !== null) payload.quota_users = quotaUsers
    if (quotaStorageGb !== null) payload.quota_storage_gb = quotaStorageGb
    const created = await req.adminDb.from('organizations').insert(payload).select('id,quota_users,quota_storage_gb').single()
    if (created.error?.code === '23505') throw new AdminHttpError(409, 'SLUG_TAKEN', `The slug "${slug}" is already used by another tenant`)
    assertNoSupabaseError(created, 'Failed to create the tenant')
    await recordAdminAudit(req, 'admin.tenant.created', 'tenant', created.data.id, { targetType: 'tenant', targetName: name, slug, ownerUserId: ownerId, quotaUsers: created.data.quota_users, quotaStorageGb: Number(created.data.quota_storage_gb), status: 'completed' })
    invalidateAdminModels()
    res.status(201).json({ data: { id: created.data.id, slug } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_TENANT_CREATE_FAILED', 'Failed to create tenant')
  }
})

router.patch('/tenants/:id', async (req: AdminRequest, res) => {
  const body = req.body || {}
  try {
    const tenant = await findTenant(req.adminDb, req.params.id)
    const current = await req.adminDb.from('organizations').select('name,slug,owner_user_id,quota_users,quota_storage_gb,metadata').eq('id', tenant.id).single()
    assertNoSupabaseError(current, 'Failed to load the tenant')
    const update: Record<string, unknown> = { updated_at: new Date().toISOString() }
    const changes: string[] = []
    if (Object.prototype.hasOwnProperty.call(body, 'name')) {
      const name = textValue(body.name, '').slice(0, 120)
      if (!name) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Tenant name cannot be empty')
      update.name = name
      changes.push('name')
    }
    if (Object.prototype.hasOwnProperty.call(body, 'slug')) {
      const slug = textValue(body.slug, '').toLowerCase()
      if (!TENANT_SLUG_PATTERN.test(slug)) throw new AdminHttpError(400, 'INVALID_SLUG', 'Slug must be 1-64 lowercase letters, digits or hyphens')
      update.slug = slug
      changes.push('slug')
    }
    if (Object.prototype.hasOwnProperty.call(body, 'ownerUserId')) {
      update.owner_user_id = await validateTenantOwner(req.adminDb, body.ownerUserId)
      changes.push('owner')
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotaUsers')) {
      const quota = tenantQuota(body.quotaUsers, 'User quota', 100000)
      if (quota === null) throw new AdminHttpError(400, 'QUOTA_REQUIRED', 'A tenant always has a user quota — set a number instead of clearing it')
      if (quota < tenant.members) throw new AdminHttpError(409, 'QUOTA_BELOW_MEMBERS', `${tenant.name} already has ${tenant.members} member(s); the quota cannot be lower`)
      update.quota_users = quota
      changes.push('quotaUsers')
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotaStorageGb')) {
      const quota = tenantQuota(body.quotaStorageGb, 'Storage quota', 100000)
      if (quota === null) throw new AdminHttpError(400, 'QUOTA_REQUIRED', 'A tenant always has a storage quota — set a number instead of clearing it')
      update.quota_storage_gb = quota
      changes.push('quotaStorageGb')
    }
    if (Object.prototype.hasOwnProperty.call(body, 'domain') || Object.prototype.hasOwnProperty.call(body, 'region')) {
      update.metadata = tenantMetadataPatch(recordOf(current.data?.metadata), body)
      changes.push('metadata')
    }
    const TENANT_CHANGE_COLUMN: Record<string, string> = { name: 'name', slug: 'slug', owner: 'owner_user_id', quotaUsers: 'quota_users', quotaStorageGb: 'quota_storage_gb', metadata: 'metadata' }
    const stored = recordOf(current.data)
    for (const change of [...changes]) {
      const column = TENANT_CHANGE_COLUMN[change]
      if (column && sameStoredValue(stored[column], update[column])) {
        delete update[column]
        changes.splice(changes.indexOf(change), 1)
      }
    }
    if (!changes.length) throw new AdminHttpError(400, 'NO_CHANGES', 'Nothing changed')
    const result = await req.adminDb.from('organizations').update(update).eq('id', tenant.id).select('id').single()
    if (result.error?.code === '23505') throw new AdminHttpError(409, 'SLUG_TAKEN', 'That slug is already used by another tenant')
    assertNoSupabaseError(result, 'Failed to update the tenant')
    await recordAdminAudit(req, 'admin.tenant.updated', 'tenant', tenant.id, { targetType: 'tenant', targetName: tenant.name, changedFields: changes, status: 'completed' })
    invalidateAdminModels()
    res.json({ data: { id: tenant.id, changedFields: changes } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_TENANT_UPDATE_FAILED', 'Failed to update tenant')
  }
})

router.post('/tenants/:id/actions', async (req: AdminRequest, res) => {
  const body = req.body || {}
  const action = textValue(body.action, '').toLowerCase()
  const reason = textValue(body.reason, '').slice(0, 500) || null
  try {
    const tenant = await findTenant(req.adminDb, req.params.id)
    const db = req.adminDb
    if (action === 'delete') {
      if (tenant.members > 0) throw new AdminHttpError(409, 'TENANT_HAS_MEMBERS', `${tenant.name} still has ${tenant.members} member(s). Move them to another tenant (or none) in Users first.`)
      if (textValue(body.confirmName, '') !== tenant.name) throw new AdminHttpError(400, 'CONFIRMATION_REQUIRED', `Type the tenant name "${tenant.name}" to confirm deletion`)
      const deleted = await db.from('organizations').delete().eq('id', tenant.id).select('id').single()
      assertNoSupabaseError(deleted, 'Failed to delete the tenant')
      await recordAdminAudit(req, 'admin.tenant.deleted', 'tenant', tenant.id, { targetType: 'tenant', targetName: tenant.name, status: 'completed' })
      invalidateAdminModels()
      res.json({ data: { id: tenant.id, deleted: true } })
      return
    }
    if (action !== 'suspend' && action !== 'restore') throw new AdminHttpError(400, 'UNKNOWN_TENANT_ACTION', `Unsupported tenant action: ${action}`)
    const nextStatus = action === 'suspend' ? 'suspended' : 'active'
    if (tenant.status === nextStatus) throw new AdminHttpError(409, 'NO_CHANGE', `${tenant.name} is already ${nextStatus}`)
    const directory = await loadUserDirectory(db, { fresh: true })
    const warnings: string[] = []
    const affected: string[] = []
    const current = await db.from('organizations').select('metadata').eq('id', tenant.id).single()
    assertNoSupabaseError(current, 'Failed to load the tenant')
    const metadata = recordOf(current.data?.metadata)
    if (action === 'suspend' && body.applyToMembers === true) {
      // Block every active, non-owner member through the Users suspend path.
      for (const member of directory.users.filter((user) => user.tenantId === tenant.id && !user.isOwner && user.status !== 'suspended' && user.status !== 'disabled')) {
        try {
          const target = await loadTargetUser(db, member.id)
          const outcome = await setAccountStatus(req, target, 'suspended', `Tenant ${tenant.name} suspended${reason ? `: ${reason}` : ''}`)
          warnings.push(...outcome.warnings)
          affected.push(member.id)
        } catch (err) {
          warnings.push(`${member.email} was not suspended: ${err instanceof Error ? err.message : String(err)}`)
        }
      }
      metadata.suspendedMemberIds = affected
    }
    if (action === 'restore') {
      // Restore only the members this tenant suspension blocked.
      const ids = Array.isArray(metadata.suspendedMemberIds) ? (metadata.suspendedMemberIds as unknown[]).map(String) : []
      if (body.applyToMembers !== false) {
        for (const id of ids) {
          const member = directory.users.find((user) => user.id === id)
          if (!member || member.status !== 'suspended') continue
          try {
            const target = await loadTargetUser(db, id)
            const outcome = await setAccountStatus(req, target, 'active', null)
            warnings.push(...outcome.warnings)
            affected.push(id)
          } catch (err) {
            warnings.push(`${member.email} was not restored: ${err instanceof Error ? err.message : String(err)}`)
          }
        }
      }
      delete metadata.suspendedMemberIds
    }
    if (reason) metadata.lastStatusReason = reason
    const result = await db.from('organizations').update({ status: nextStatus, metadata, updated_at: new Date().toISOString() }).eq('id', tenant.id).select('id').single()
    assertNoSupabaseError(result, 'Failed to update the tenant status')
    await recordAdminAudit(req, `admin.tenant.${action}`, 'tenant', tenant.id, { targetType: 'tenant', targetName: tenant.name, previousStatus: tenant.status, nextStatus, reason, membersAffected: affected.length, warnings, status: warnings.length ? 'completed_with_warnings' : 'completed' })
    invalidateAdminModels()
    res.json({ data: { id: tenant.id, status: nextStatus, membersAffected: affected.length, warnings } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_TENANT_ACTION_FAILED', 'Failed to run the tenant action')
  }
})

// ---------------------------------------------------------------------------
// Plans & Billing routes
// ---------------------------------------------------------------------------

const BILLING_CSV_COLUMNS: Array<{ header: string; value: (row: BillingRow) => unknown }> = [
  { header: 'Subscription ID', value: (row) => row.id },
  { header: 'Email', value: (row) => row.user?.email },
  { header: 'Plan', value: (row) => row.plan },
  { header: 'Status', value: (row) => row.status },
  { header: 'Grants access', value: (row) => row.grantsAccess },
  { header: 'Billing class', value: (row) => row.revenueClass },
  { header: 'Provider', value: (row) => row.providerLabel },
  { header: 'Cycle', value: (row) => row.billingCycle },
  { header: 'Price (cents)', value: (row) => row.amountCents },
  { header: 'Currency', value: (row) => row.currency },
  { header: 'MRR (cents)', value: (row) => row.mrrCents },
  { header: 'Renewal', value: (row) => row.renewal },
  { header: 'Period end (UTC)', value: (row) => row.periodEnd },
  { header: 'Tenant', value: (row) => row.tenantName },
]

function billingQueryFrom(query: Request['query']) {
  return {
    search: pickQuery(query, 'search'),
    status: pickQuery(query, 'status'),
    plan: pickQuery(query, 'plan'),
    revenueClass: pickQuery(query, 'class'),
    page: Number(pickQuery(query, 'page')) || 1,
    limit: Number(pickQuery(query, 'limit')) || DEFAULT_LIMIT,
  }
}

router.get('/billing', async (req: AdminRequest, res) => {
  try {
    const [model, events] = await Promise.all([
      loadBillingConsole(req.adminDb),
      optionalRows(req.adminDb, 'billing_audit_events', (q) => q.select('id,user_id,action,message,metadata,created_at').order('created_at', { ascending: false }).limit(50)),
    ])
    const result = queryBillingRows(model, billingQueryFrom(req.query))
    const directory = await loadUserDirectory(req.adminDb)
    const emails = new Map(directory.users.map((user) => [user.id, user.email]))
    res.json({
      data: {
        subscriptions: result.rows,
        pagination: result.pagination,
        stats: model.stats,
        integrity: model.integrity,
        plans: model.plans,
        invoices: model.invoices.slice(0, 50),
        invoicesTotal: model.invoices.length,
        paymentMethods: model.paymentMethods,
        events: events.map((row: any) => normalizePlatformEvent(row, 'billing', emails.get(row.user_id) || null)),
        version: model.version,
        generatedAt: model.generatedAt,
      },
    })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_BILLING_QUERY_FAILED', 'Failed to load billing')
  }
})

router.get('/billing/export', async (req: AdminRequest, res) => {
  try {
    const model = await loadBillingConsole(req.adminDb)
    const rows = queryBillingRows(model, { ...billingQueryFrom(req.query), page: 1, limit: 100000 }).rows
    await recordAdminAudit(req, 'admin.billing.exported', 'billing', null, { rows: rows.length, status: 'completed' })
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="qguard-subscriptions-${model.generatedAt.slice(0, 19).replace(/[:T]/g, '-')}.csv"`)
    res.send(toCsv(BILLING_CSV_COLUMNS, rows))
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_BILLING_EXPORT_FAILED', 'Failed to export subscriptions')
  }
})

router.post('/subscriptions/:id/actions', async (req: AdminRequest, res) => {
  const id = req.params.id
  const action = textValue(req.body?.action, '').toLowerCase()
  try {
    if (!UUID_PATTERN.test(id)) throw new AdminHttpError(400, 'INVALID_SUBSCRIPTION_ID', 'Subscription id must be a UUID')
    if (!['approve', 'extend', 'cancel', 'notify', 'delete'].includes(action)) {
      throw new AdminHttpError(400, 'UNKNOWN_ACTION', action === 'upgrade' || action === 'downgrade' || action === 'activate' || action === 'deactivate'
        ? 'Plan and access changes go through Manage plan (POST /users/:id/subscription) — the one subscription writer.'
        : `Unsupported subscription action: ${action}`)
    }
    const db = req.adminDb
    const existing = await db.from('billing_subscriptions').select('*').eq('id', id).maybeSingle()
    assertNoSupabaseError(existing, 'Failed to load the subscription')
    if (!existing.data) throw new AdminHttpError(404, 'SUBSCRIPTION_NOT_FOUND', 'Subscription not found')
    const subscription = existing.data
    const managed = providerManaged(subscription)
    const grants = isAccessGrantingStatus(subscription.status)
    const context = await loadSubscriptionContext(db, subscription)
    const nowIso = new Date().toISOString()

    if (action === 'notify') {
      const periodEnd = billingRenewalDate(subscription)
      const when = periodEnd ? new Date(periodEnd).toISOString().slice(0, 10) : null
      const message = !grants
        ? `Your ${subscription.plan} plan is not active. Renew from Settings > Billing to restore access.`
        : subscription.cancel_at_period_end
          ? `Your ${subscription.plan} plan ends on ${when}. Renew from Settings > Billing to keep access.`
          : `Your ${subscription.plan} plan ${managed ? 'renews' : 'runs until'} ${when || 'the end of the current period'}.`
      const notification = await db.from('billing_notifications').insert({ user_id: subscription.user_id, type: 'subscription', severity: 'info', title: 'Subscription reminder', message })
      assertNoSupabaseError(notification, 'The reminder was not delivered')
      const trail = await db.from('billing_audit_events').insert({ user_id: subscription.user_id, action: 'subscription.reminder_sent', message: `Reminder sent by a QGuard administrator: ${message}`, metadata: { source: 'admin', actorEmail: req.adminUser!.email || null, subscriptionId: id } })
      if (trail.error) console.error('[admin] billing reminder not recorded in the billing trail:', trail.error.message)
      await recordAdminAudit(req, 'admin.subscription.notify', 'subscription', id, subscriptionAuditDetails(subscription, context.profile, context.tenant, { message, status: 'completed' }))
      invalidateAdminModels()
      res.json({ data: { id, delivered: 'in-app notification (Settings > Billing)', message } })
      return
    }

    if (action === 'delete') {
      if (managed && grants) throw new AdminHttpError(409, 'PROVIDER_MANAGED', 'Cancel this provider-billed subscription before deleting its record — the provider would keep charging a customer the platform no longer knows about.')
      const confirmEmail = textValue(req.body?.confirmEmail, '').toLowerCase()
      if (!context.profile?.email || confirmEmail !== String(context.profile.email).toLowerCase()) throw new AdminHttpError(400, 'CONFIRMATION_REQUIRED', "Type the customer's email to confirm deletion")
      const deleted = await db.from('billing_subscriptions').delete().eq('id', id).select('id').single()
      assertNoSupabaseError(deleted, 'Failed to delete the subscription')
      await syncBillingEntitlements(db, subscription, 'free', 'deleted')
      await recordAdminAudit(req, 'admin.subscription.deleted', 'subscription', id, subscriptionAuditDetails(subscription, context.profile, context.tenant, { status: 'completed', deleted: true }))
      await recordCustomerBillingEvent(req, subscription, null, 'deleted')
      invalidateAdminModels()
      res.json({ data: { id, deleted: true } })
      return
    }

    const updates: Record<string, unknown> = { updated_at: nowIso }
    if (action === 'approve') {
      if (!textValue(subscription.approval_status, '') || ['approved', 'not_required'].includes(String(subscription.approval_status))) throw new AdminHttpError(409, 'NO_APPROVAL_PENDING', 'This subscription has no approval pending')
      if (managed) throw new AdminHttpError(409, 'PROVIDER_MANAGED', PROVIDER_MANAGED_MESSAGE[managed])
      updates.approval_status = 'approved'
      updates.status = 'active'
    } else if (action === 'extend') {
      if (managed) throw new AdminHttpError(409, 'PROVIDER_MANAGED', PROVIDER_MANAGED_MESSAGE[managed])
      if (!grants) throw new AdminHttpError(409, 'NOT_ACTIVE', 'Only a subscription that grants access can be extended — grant the plan with Manage plan first.')
      const days = Math.floor(numberValue(req.body?.days, 0))
      if (days < 1 || days > 366) throw new AdminHttpError(400, 'INVALID_DAYS', 'Extend by 1-366 days')
      const base = Math.max(Date.now(), new Date(billingRenewalDate(subscription) || Date.now()).getTime())
      const next = new Date(base + days * DAY_MS).toISOString()
      updates.current_period_end = next
      updates.renewal_date = next
      updates.expires_at = next
    } else if (action === 'cancel') {
      if (!grants) throw new AdminHttpError(409, 'NOT_ACTIVE', 'This subscription is not active')
      if (managed === 'google_play') throw new AdminHttpError(409, 'PROVIDER_MANAGED', PROVIDER_MANAGED_MESSAGE.google_play)
      if (managed === 'paypal' && subscription.provider_subscription_id) {
        // Stop PayPal billing FIRST; never mark cancelled what PayPal still charges.
        try {
          await cancelSubscription(subscription.provider_subscription_id, 'Cancelled by a QGuard administrator')
        } catch (err: any) {
          if (err?.status !== 422) throw new AdminHttpError(502, 'PROVIDER_CANCEL_FAILED', `PayPal did not confirm the cancellation, so nothing was changed: ${err?.message || 'PayPal error'}`)
        }
      }
      updates.status = 'cancelled'
      updates.canceled_at = nowIso
      updates.cancelled_at = nowIso
      updates.cancel_at_period_end = false
      updates.auto_renew = false
    }
    updates.metadata = { ...billingMetadata(subscription), lastAdminAction: action, lastAdminActionAt: nowIso, lastAdminActionByEmail: req.adminUser!.email || null }
    const result = await db.from('billing_subscriptions').update(updates).eq('id', id).select('*').single()
    assertNoSupabaseError(result, 'Failed to update the subscription')
    await syncBillingEntitlements(db, result.data, result.data.plan, result.data.status)
    await recordAdminAudit(req, `admin.subscription.${action}`, 'subscription', id, subscriptionAuditDetails(subscription, context.profile, context.tenant, {
      nextStatus: result.data.status,
      nextRenewalDate: billingRenewalDate(result.data),
      changedFields: Object.keys(updates).filter((key) => key !== 'updated_at' && key !== 'metadata'),
      status: 'completed',
    }))
    await recordCustomerBillingEvent(req, subscription, result.data, action)
    invalidateAdminModels()
    res.json({ data: { subscription: { id, status: result.data.status, periodEnd: billingRenewalDate(result.data) } } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_SUBSCRIPTION_ACTION_FAILED', 'Failed to run the subscription action')
  }
})

// ---------------------------------------------------------------------------
// Security + Governance routes
// ---------------------------------------------------------------------------

router.get('/security', async (req: AdminRequest, res) => {
  try {
    res.json({ data: await loadSecurityPosture(req.adminDb, parseSecurityWindow(req.query.window)) })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_SECURITY_QUERY_FAILED', 'Failed to load security posture')
  }
})

router.get('/governance', async (req: AdminRequest, res) => {
  try {
    res.json({ data: await loadGovernanceModel(req.adminDb) })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_GOVERNANCE_QUERY_FAILED', 'Failed to load governance')
  }
})

function policyFields(body: Record<string, unknown>, partial: boolean) {
  const fields: Record<string, unknown> = {}
  const has = (key: string) => Object.prototype.hasOwnProperty.call(body, key)
  if (!partial || has('name')) {
    const name = textValue(body.name, '').slice(0, 120)
    if (!name) throw new AdminHttpError(400, 'VALIDATION_ERROR', 'Policy name is required')
    fields.name = name
  }
  if (!partial || has('category')) {
    const category = textValue(body.category, 'operations').toLowerCase()
    if (!(POLICY_CATEGORIES as readonly string[]).includes(category)) throw new AdminHttpError(400, 'INVALID_CATEGORY', `Category must be one of ${POLICY_CATEGORIES.join(', ')}`)
    fields.category = category
  }
  if (!partial || has('status')) {
    const status = textValue(body.status, 'enabled').toLowerCase()
    if (!(POLICY_STATUSES as readonly string[]).includes(status)) throw new AdminHttpError(400, 'INVALID_STATUS', 'Status must be enabled or disabled')
    fields.status = status
  }
  if (!partial || has('enforcementLevel')) {
    const level = textValue(body.enforcementLevel, 'monitor').toLowerCase()
    if (!(ENFORCEMENT_LEVELS as readonly string[]).includes(level)) throw new AdminHttpError(400, 'INVALID_LEVEL', `Enforcement level must be one of ${ENFORCEMENT_LEVELS.join(', ')}`)
    fields.enforcement_level = level
  }
  if (!partial || has('description')) fields.description = textValue(body.description, '').slice(0, 1000)
  return fields
}

router.post('/governance/policies', async (req: AdminRequest, res) => {
  const body = req.body || {}
  try {
    const fields = policyFields(body, false)
    const key = textValue(body.key, '').toLowerCase() || slugify(String(fields.name))
    if (!POLICY_KEY_PATTERN.test(key)) throw new AdminHttpError(400, 'INVALID_KEY', 'Policy key must be lowercase letters, digits and hyphens')
    const existing = await req.adminDb.from('admin_governance_policies').select('id').eq('policy_key', key).maybeSingle()
    assertNoSupabaseError(existing, 'Failed to check the policy key')
    if (existing.data) throw new AdminHttpError(409, 'POLICY_EXISTS', `A policy with key "${key}" already exists`)
    const created = await req.adminDb.from('admin_governance_policies').insert({ ...fields, policy_key: key, config: {}, updated_by: req.adminUser!.id }).select('id').single()
    assertNoSupabaseError(created, 'Failed to create the policy')
    await recordAdminAudit(req, 'admin.governance.policy_created', 'policy', created.data.id, { targetType: 'policy', targetName: fields.name, policyKey: key, status: 'completed' })
    invalidateAdminModels()
    res.status(201).json({ data: { id: created.data.id, key } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_POLICY_CREATE_FAILED', 'Failed to create policy')
  }
})

router.patch('/governance/policies/:id', async (req: AdminRequest, res) => {
  try {
    if (!UUID_PATTERN.test(req.params.id)) throw new AdminHttpError(400, 'INVALID_POLICY_ID', 'Policy id must be a UUID')
    const current = await req.adminDb.from('admin_governance_policies').select('id,policy_key,name,category,status,enforcement_level,description').eq('id', req.params.id).maybeSingle()
    assertNoSupabaseError(current, 'Failed to load the policy')
    if (!current.data) throw new AdminHttpError(404, 'POLICY_NOT_FOUND', 'Policy not found')
    const fields = policyFields(req.body || {}, true)
    const stored = recordOf(current.data)
    for (const field of Object.keys(fields)) if (sameStoredValue(stored[field], fields[field])) delete fields[field]
    if (!Object.keys(fields).length) throw new AdminHttpError(400, 'NO_CHANGES', 'Nothing changed')
    const result = await req.adminDb.from('admin_governance_policies').update({ ...fields, updated_by: req.adminUser!.id, updated_at: new Date().toISOString() }).eq('id', req.params.id).select('id').single()
    assertNoSupabaseError(result, 'Failed to update the policy')
    await recordAdminAudit(req, 'admin.governance.policy_updated', 'policy', req.params.id, { targetType: 'policy', targetName: current.data.name, policyKey: current.data.policy_key, changedFields: Object.keys(fields), status: 'completed' })
    invalidateAdminModels()
    res.json({ data: { id: req.params.id, changedFields: Object.keys(fields) } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_POLICY_UPDATE_FAILED', 'Failed to update policy')
  }
})

router.delete('/governance/policies/:id', async (req: AdminRequest, res) => {
  try {
    if (!UUID_PATTERN.test(req.params.id)) throw new AdminHttpError(400, 'INVALID_POLICY_ID', 'Policy id must be a UUID')
    const current = await req.adminDb.from('admin_governance_policies').select('id,policy_key,name').eq('id', req.params.id).maybeSingle()
    assertNoSupabaseError(current, 'Failed to load the policy')
    if (!current.data) throw new AdminHttpError(404, 'POLICY_NOT_FOUND', 'Policy not found')
    if (VERIFIED_POLICY_KEYS.has(current.data.policy_key)) throw new AdminHttpError(400, 'POLICY_PROTECTED', 'Platform-verified policies can be disabled but not deleted')
    if (textValue(req.body?.confirmKey, '') !== current.data.policy_key) throw new AdminHttpError(400, 'CONFIRMATION_REQUIRED', `Type the policy key "${current.data.policy_key}" to confirm deletion`)
    const deleted = await req.adminDb.from('admin_governance_policies').delete().eq('id', req.params.id).select('id').single()
    assertNoSupabaseError(deleted, 'Failed to delete the policy')
    await recordAdminAudit(req, 'admin.governance.policy_deleted', 'policy', req.params.id, { targetType: 'policy', targetName: current.data.name, policyKey: current.data.policy_key, status: 'completed' })
    invalidateAdminModels()
    res.json({ data: { id: req.params.id, deleted: true } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_POLICY_DELETE_FAILED', 'Failed to delete policy')
  }
})

router.post('/governance/evidence', async (req: AdminRequest, res) => {
  try {
    const title = textValue(req.body?.title, '').slice(0, 160) || `Administration evidence — ${new Date().toISOString().slice(0, 10)}`
    const snapshot = await buildEvidenceSnapshot(req)
    const hash = { algorithm: 'SHA3-256', value: sha3Hex(snapshot) }
    const summary = {
      users: snapshot.users.stats.totalUsers,
      controlsPassing: snapshot.security.summary.controlsPassing,
      controlsMeasured: snapshot.security.summary.controlsMeasured,
      policiesNotMet: snapshot.policies.filter((policy) => policy.verification.state === 'not_met').length,
      mrrCents: snapshot.billing.stats.mrrCents,
      auditRecords: snapshot.audit.count,
    }
    const created = await req.adminDb.from('admin_compliance_evidence').insert({
      title,
      framework: 'QGuard administration controls',
      evidence_type: 'measured_snapshot',
      status: 'generated',
      generated_by: req.adminUser!.id,
      metadata: { snapshot, hash, summary },
    }).select('id').single()
    assertNoSupabaseError(created, 'Failed to store the evidence package')
    await recordAdminAudit(req, 'admin.governance.evidence_generated', 'compliance_evidence', created.data.id, { targetType: 'evidence', targetName: title, sha3_256: hash.value, status: 'completed' })
    invalidateAdminModels()
    res.status(201).json({ data: { id: created.data.id, hash, summary } })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_EVIDENCE_CREATE_FAILED', 'Failed to generate evidence')
  }
})

router.get('/governance/evidence/:id', async (req: AdminRequest, res) => {
  try {
    if (!UUID_PATTERN.test(req.params.id)) throw new AdminHttpError(400, 'INVALID_EVIDENCE_ID', 'Evidence id must be a UUID')
    const row = await req.adminDb.from('admin_compliance_evidence').select('*').eq('id', req.params.id).maybeSingle()
    assertNoSupabaseError(row, 'Failed to load the evidence package')
    if (!row.data) throw new AdminHttpError(404, 'EVIDENCE_NOT_FOUND', 'Evidence package not found')
    const metadata = recordOf(row.data.metadata)
    const hash = recordOf(metadata.hash)
    const recomputed = metadata.snapshot !== undefined ? sha3Hex(metadata.snapshot) : null
    await recordAdminAudit(req, 'admin.governance.evidence_downloaded', 'compliance_evidence', req.params.id, { targetType: 'evidence', targetName: row.data.title, status: 'completed' })
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Content-Disposition', `attachment; filename="qguard-evidence-${req.params.id.slice(0, 8)}.json"`)
    res.json({
      id: row.data.id,
      title: row.data.title,
      framework: row.data.framework,
      createdAt: row.data.created_at,
      hash: hash.value ? hash : null,
      verification: { recomputedSha3_256: recomputed, intact: Boolean(recomputed && hash.value === recomputed) },
      snapshot: metadata.snapshot ?? null,
    })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_EVIDENCE_READ_FAILED', 'Failed to read the evidence package')
  }
})

// ---------------------------------------------------------------------------
// History routes
// ---------------------------------------------------------------------------

/** SQL mirror of admin-history adminActionCategory (keep in step). */
const notView = (q: any) => q.not('action', 'like', '%.viewed').not('action', 'like', '%.stream.connected').not('action', 'like', '%.inspected')
const HISTORY_CATEGORY_PATTERNS: Record<string, (query: any) => any> = {
  users: (q) => q.like('action', 'admin.user%').not('action', 'like', '%export%'),
  roles: (q) => q.like('action', 'admin.role.%'),
  tenants: (q) => q.like('action', 'admin.tenant.%'),
  billing: (q) => q.or('action.like.admin.subscription.%,action.like.admin.billing.%,action.like.revenue.%').not('action', 'like', '%export%').not('action', 'like', '%.access_denied'),
  governance: (q) => q.or('action.like.admin.governance.%,action.like.admin.security.policy%'),
  security: (q) => q.like('action', '%.access_denied'),
  exports: (q) => q.like('action', '%export%'),
  views: (q) => q.or('action.like.%.viewed,action.like.%.stream.connected,action.like.%.inspected'),
}

function historySearchTerm(value: unknown) {
  // PostgREST or()/ilike grammar: drop characters that would change the filter.
  return textValue(value, '').replace(/[,()*%\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80)
}

function historyQueryFrom(query: Request['query']) {
  const source = pickQuery(query, 'source')
  return {
    source: (source === 'security' || source === 'billing' || source === 'migration' ? source : 'admin') as HistorySource,
    category: pickQuery(query, 'category') || 'all',
    actor: historySearchTerm(pickQuery(query, 'actor')),
    search: historySearchTerm(pickQuery(query, 'search')),
    since: textValue(pickQuery(query, 'since'), ''),
    until: textValue(pickQuery(query, 'until'), ''),
    includeViews: pickQuery(query, 'includeViews') === '1',
    page: Math.max(1, Number(pickQuery(query, 'page')) || 1),
    limit: Math.min(MAX_LIMIT, Math.max(1, Number(pickQuery(query, 'limit')) || DEFAULT_LIMIT)),
  }
}

async function queryHistory(db: any, q: ReturnType<typeof historyQueryFrom>, emails: Map<string, string>): Promise<{ entries: HistoryEntry[]; total: number }> {
  const from = (q.page - 1) * q.limit
  const dateOk = (value: string) => value && Number.isFinite(Date.parse(value))
  if (q.source === 'admin') {
    let query = db.from('admin_audit_events').select('id,action,actor_email,entity_type,entity_id,details,ip_address,created_at', { count: 'exact' })
    if (q.category !== 'all' && HISTORY_CATEGORY_PATTERNS[q.category]) query = HISTORY_CATEGORY_PATTERNS[q.category](query)
    if (q.category !== 'views' && (q.category !== 'all' || !q.includeViews)) query = notView(query)
    if (q.actor) query = query.ilike('actor_email', `%${q.actor}%`)
    if (q.search) query = query.or(`action.ilike.%${q.search}%,actor_email.ilike.%${q.search}%,entity_id.ilike.%${q.search}%,entity_type.ilike.%${q.search}%`)
    if (dateOk(q.since)) query = query.gte('created_at', new Date(q.since).toISOString())
    if (dateOk(q.until)) query = query.lte('created_at', new Date(q.until).toISOString())
    const { data, count, error } = await query.order('created_at', { ascending: false }).range(from, from + q.limit - 1)
    if (error) throw new Error(`admin_audit_events: ${error.message}`)
    return { entries: (data || []).map((row: any) => normalizeAdminAuditRow(row)), total: count || 0 }
  }
  const tables = q.source === 'security'
    ? [['security_events', 'id,user_id,event_type,severity,message,metadata,created_at'], ['user_security_events', 'id,user_id,event_type,severity,message,ip_address,metadata,created_at']]
    : q.source === 'billing'
      ? [['billing_audit_events', 'id,user_id,action,message,ip_address,metadata,created_at']]
      : [['migration_events', 'id,user_id,migration_id,event_type,severity,message,metadata,created_at']]
  const results = await Promise.all(tables.map(async ([table, columns]) => {
    let query = db.from(table).select(columns, { count: 'exact' })
    const typeColumn = table === 'billing_audit_events' ? 'action' : 'event_type'
    if (q.search) query = query.or(`${typeColumn}.ilike.%${q.search}%,message.ilike.%${q.search}%`)
    if (dateOk(q.since)) query = query.gte('created_at', new Date(q.since).toISOString())
    if (dateOk(q.until)) query = query.lte('created_at', new Date(q.until).toISOString())
    // Merged sources: read enough of each to fill this page after merging.
    const { data, count, error } = await query.order('created_at', { ascending: false }).range(0, from + q.limit - 1)
    if (error) throw new Error(`${table}: ${error.message}`)
    return { rows: (data || []) as any[], count: count || 0 }
  }))
  const merged = results.flatMap((result) => result.rows)
    .map((row) => normalizePlatformEvent(row, q.source as Exclude<HistorySource, 'admin'>, emails.get(row.user_id) || null))
    .sort((a, b) => String(b.at || '').localeCompare(String(a.at || '')))
  return { entries: merged.slice(from, from + q.limit), total: results.reduce((sum, result) => sum + result.count, 0) }
}

router.get('/history', async (req: AdminRequest, res) => {
  try {
    const q = historyQueryFrom(req.query)
    const [directory, headline] = await Promise.all([loadUserDirectory(req.adminDb), loadHistoryStats(req.adminDb)])
    const emails = new Map(directory.users.map((user) => [user.id, user.email]))
    const { entries, total } = await queryHistory(req.adminDb, q, emails)
    res.json({
      data: {
        entries,
        pagination: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
        stats: headline.stats,
        version: headline.version,
        generatedAt: headline.generatedAt,
      },
    })
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_HISTORY_QUERY_FAILED', 'Failed to load history')
  }
})

router.get('/history/export', async (req: AdminRequest, res) => {
  try {
    const q = { ...historyQueryFrom(req.query), page: 1, limit: MAX_LIMIT }
    const directory = await loadUserDirectory(req.adminDb)
    const emails = new Map(directory.users.map((user) => [user.id, user.email]))
    const entries: HistoryEntry[] = []
    let total = 0
    // Page through the filter (bounded) so the export is the whole result.
    for (let page = 1; page <= 100; page += 1) {
      const result = await queryHistory(req.adminDb, { ...q, page }, emails)
      total = result.total
      entries.push(...result.entries)
      if (entries.length >= total || !result.entries.length) break
    }
    await recordAdminAudit(req, 'admin.history.exported', 'history', null, { source: q.source, category: q.category, rows: entries.length, truncated: entries.length < total, status: 'completed' })
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="qguard-admin-history-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv"`)
    res.send(toCsv(HISTORY_CSV_COLUMNS, entries))
  } catch (error) {
    sendAdminError(res, error, 'ADMIN_HISTORY_EXPORT_FAILED', 'Failed to export history')
  }
})

// ---------------------------------------------------------------------------
// Stream bundle — ONE computation per window shared by every open console.
// Each tab gets a small {version, stats} frame; a client refetches its own
// (filtered, paged) view only when that tab's version changes.
// ---------------------------------------------------------------------------

const STREAM_BUNDLE_TTL_MS = 8_000
let streamBundleCache: { at: number; promise: ReturnType<typeof computeStreamBundle> } | null = null

async function computeStreamBundle(db: any) {
  const [directory, stats, roles, tenants, billing, security, governance, history] = await Promise.all([
    loadUserDirectory(db),
    buildAdminStats(db),
    loadRoleCatalog(db),
    loadTenantDirectory(db),
    loadBillingConsole(db),
    loadSecurityPosture(db, '24h'),
    loadGovernanceModel(db),
    loadHistoryStats(db),
  ])
  const frames: Array<[string, unknown]> = [
    ['admin-users', { version: directory.version, stats: directory.stats, integrity: directory.integrity, sources: directory.sources, generatedAt: directory.generatedAt }],
    ['admin-stats', stats],
    ['admin-roles', { version: roles.version, stats: roles.stats, integrity: roles.integrity, generatedAt: roles.generatedAt }],
    ['admin-tenants', { version: tenants.version, stats: tenants.stats, integrity: tenants.integrity, generatedAt: tenants.generatedAt }],
    ['admin-billing', { version: billing.version, stats: billing.stats, integrity: billing.integrity, generatedAt: billing.generatedAt }],
    ['admin-security', { version: security.version, window: security.window, summary: security.summary, generatedAt: security.generatedAt }],
    ['admin-governance', { version: governance.version, stats: governance.stats, generatedAt: governance.generatedAt }],
    ['admin-history', { version: history.version, stats: history.stats, generatedAt: history.generatedAt }],
  ]
  return { frames }
}

/** Single-flight, 8s-TTL; failures are never cached. */
function loadStreamBundle(db: any) {
  const now = Date.now()
  if (streamBundleCache && now - streamBundleCache.at < STREAM_BUNDLE_TTL_MS) return streamBundleCache.promise
  const entry = { at: now, promise: computeStreamBundle(db) }
  streamBundleCache = entry
  entry.promise.catch(() => {
    if (streamBundleCache === entry) streamBundleCache = null
  })
  return entry.promise
}

router.get('/stream', async (req: AdminRequest, res) => {
  res.status(200)
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache, no-transform')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('X-Accel-Buffering', 'no')
  res.flushHeaders?.()

  let closed = false
  let interval: ReturnType<typeof setInterval> | undefined
  let heartbeat: ReturnType<typeof setInterval> | undefined
  const send = (event: string, data: unknown) => {
    if (closed) return
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  }
  const cleanup = () => {
    closed = true
    consoleChangeListeners.delete(pushNow)
    if (interval) clearInterval(interval)
    if (heartbeat) clearInterval(heartbeat)
  }
  // Registered BEFORE the first await: a console that disconnects while the
  // first frames are being computed must still release its timers and its
  // change listener (it used to leak both for the life of the process).
  req.on('close', cleanup)

  send('admin-connected', {
    owner: req.adminUser!.email,
    timestamp: new Date().toISOString(),
  })
  await recordAdminAudit(req, 'admin.stream.connected', 'admin_dashboard')

  let pushing = false
  const push = async () => {
    if (closed || pushing) return
    pushing = true
    try {
      // The stream outlives the token it was opened with: re-verify every tick
      // (cached locally, ~1ms) so a signed-out, expired or revoked owner
      // session stops receiving platform data.
      const current = await getServerUser(req.adminToken || '')
      if (!current || !isOwnerEmail(current.email)) {
        send('admin-reauth', { message: 'Owner session expired or was revoked — reconnect with a fresh session.' })
        cleanup()
        res.end()
        return
      }
      // Each tab: {version, stats}. A client refetches its own (filtered,
      // paged) view only when that tab's version changes — never per tick.
      const { frames } = await loadStreamBundle(req.adminDb)
      for (const [event, data] of frames) send(event, data)
    } catch (error) {
      send('admin-error', { message: error instanceof Error ? error.message : 'Admin stream update failed' })
    } finally {
      pushing = false
    }
  }

  // A write in ANY console pushes fresh frames to every open console now,
  // instead of on the next 10s tick (debounced so a burst pushes once).
  let pushQueued = false
  function pushNow() {
    if (closed || pushQueued) return
    pushQueued = true
    setTimeout(() => {
      pushQueued = false
      void push()
    }, 250)
  }

  await push()
  if (closed) return
  consoleChangeListeners.add(pushNow)
  interval = setInterval(() => void push(), 10_000)
  heartbeat = setInterval(() => send('admin-heartbeat', { timestamp: new Date().toISOString() }), 30_000)
})

export default router
