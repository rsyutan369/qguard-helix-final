// Owner Admin > Users — the ONE user-directory model.
//
// Every figure the Users console shows (KPI cards, table columns, filters,
// facets, exports, the Overview "Total Users" card) is derived here, from the
// authoritative records only:
//
//   Supabase Auth (via the service-role RPC admin_user_auth_directory):
//     sign-in, e-mail confirmation, bans, live sessions + last activity, MFA.
//   public.profiles: name, access role, tenant, account_status, MFA policy.
//   public.billing_subscriptions: plan entitlement (entitlementFromRecords —
//     the same rule the API gateway enforces).
//   public.organizations / organization_members: tenant name + tenant role.
//
// Unmeasured renders as null ("Unknown"), never as 0. Pure and isomorphic:
// the API builds it, the frontend imports its types (the wire contract cannot
// drift), and tools/admin-users-check.ts asserts its invariants.

import { isOwnerEmail } from '@/lib/admin-access'
import { classifySubscription, providerLabel } from '@/lib/billing/revenue-model'
import {
  TIER_LABEL,
  entitlementFromRecords,
  normalizeTier,
  type AccessTier,
} from '@/lib/subscription-access'

/** A user counts as "active now" when a session was used within this window. */
export const ACTIVE_NOW_WINDOW_MS = 60 * 60_000
/** ...and as "active" when it signed in or refreshed within this window. */
export const ACTIVE_WINDOW_DAYS = 30
const DAY_MS = 24 * 60 * 60_000

// ---------------------------------------------------------------------------
// Input records (the columns the API selects)
// ---------------------------------------------------------------------------

export interface AuthDirectoryRow {
  user_id: string
  email: string | null
  created_at: string | null
  last_sign_in_at: string | null
  email_confirmed_at: string | null
  invited_at: string | null
  banned_until: string | null
  is_anonymous?: boolean | null
  providers?: string[] | null
  app_role?: string | null
  /** null when the source could not measure sessions (admin-API fallback). */
  session_count: number | null
  aal2_session_count?: number | null
  last_session_activity_at: string | null
  last_session_ip: string | null
  last_session_user_agent: string | null
  /** null when the source could not measure MFA factors. */
  mfa_verified_factors: number | null
  mfa_factor_types?: string[] | null
}

export interface ProfileRecord {
  id: string
  email?: string | null
  name?: string | null
  full_name?: string | null
  role?: string | null
  tier?: string | null
  tenant_id?: string | null
  account_status?: string | null
  mfa_required?: boolean | null
  created_at?: string | null
  updated_at?: string | null
}

export interface SubscriptionRecordLite {
  id: string
  user_id: string
  plan?: string | null
  status?: string | null
  provider?: string | null
  billing_cycle?: string | null
  current_period_end?: string | null
  cancel_at_period_end?: boolean | null
  metadata?: Record<string, unknown> | null
  updated_at?: string | null
}

export interface OrganizationRecord {
  id: string
  name?: string | null
  slug?: string | null
  status?: string | null
}

export interface MembershipRecord {
  organization_id: string
  user_id: string
  role?: string | null
  status?: string | null
}

/** How identity data was obtained — disclosed in the UI, never hidden. */
export type AuthSource = 'rpc' | 'admin_api' | 'unavailable'

export interface DirectoryInput {
  profiles: ProfileRecord[]
  auth: AuthDirectoryRow[]
  authSource: AuthSource
  subscriptions: SubscriptionRecordLite[]
  organizations: OrganizationRecord[]
  memberships: MembershipRecord[]
  /** Source notes gathered while loading (ceilings hit, tables missing...). */
  notes?: string[]
  now?: number
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

export type DirectoryAccountStatus = 'active' | 'pending_verification' | 'suspended' | 'disabled'
export type DirectoryActivity = 'active_now' | 'active_30d' | 'dormant' | 'never'
export type DirectoryMfaState = 'enrolled' | 'required_not_enrolled' | 'not_enrolled' | 'unknown'
export type DirectoryAccessClass = 'owner' | 'provider' | 'manual' | 'complimentary' | 'none'

export interface DirectoryUser {
  id: string
  displayId: string
  email: string
  name: string
  isOwner: boolean
  role: string
  roleLabel: string
  roleSource: 'owner' | 'profile' | 'auth_metadata' | 'default'
  isAdministrator: boolean
  tenantId: string | null
  tenantName: string | null
  tenantSlug: string | null
  tenantStatus: string | null
  tenantRole: string | null
  status: DirectoryAccountStatus
  /** Raw profiles.account_status, for the drawer. */
  profileStatus: string | null
  bannedUntil: string | null
  /** Why the profile and Supabase Auth disagree about this account, if they do. */
  statusDrift: string | null
  access: {
    tier: AccessTier
    tierLabel: string
    isActive: boolean
    status: string | null
    source: 'owner' | 'subscription' | 'none'
    accessClass: DirectoryAccessClass
    accessClassReason: string
    provider: string | null
    providerLabel: string | null
    providerManaged: boolean
    subscriptionId: string | null
    billingCycle: string | null
    periodEnd: string | null
    cancelAtPeriodEnd: boolean
    /** profiles.tier mirror, and why it disagrees with the entitlement. */
    profileTier: string | null
    tierDrift: string | null
  }
  sessions: {
    /** null = not measured (never 0-by-default). */
    count: number | null
    aal2Count: number | null
    lastActivityAt: string | null
    lastIp: string | null
    lastUserAgent: string | null
    lastDevice: string | null
  }
  lastSignInAt: string | null
  lastActivityAt: string | null
  activity: DirectoryActivity
  mfa: {
    state: DirectoryMfaState
    enrolledFactors: number | null
    factorTypes: string[]
    required: boolean
  }
  emailConfirmedAt: string | null
  invitedAt: string | null
  providers: string[]
  createdAt: string | null
  updatedAt: string | null
  hasProfile: boolean
  hasAuthAccount: boolean
}

export interface DirectoryStats {
  totalUsers: number
  newLast30d: number
  newPrev30d: number
  activity: { activeNow: number; active30d: number; dormant: number; never: number }
  status: Record<DirectoryAccountStatus, number>
  statusDrift: number
  access: {
    withAccess: number
    noAccess: number
    byTier: Record<'starter' | 'basic' | 'pro' | 'elite', number>
    byClass: Record<DirectoryAccessClass, number>
    tierDrift: number
  }
  mfa: {
    /** null when MFA could not be measured. */
    enrolled: number | null
    notEnrolled: number | null
    required: number
    requiredNotEnrolled: number | null
  }
  administrators: number
  noTenant: number
  /** Sum of live auth sessions; null when sessions could not be measured. */
  liveSessions: number | null
  usersWithSessions: number | null
}

export interface DirectoryIntegrityCheck {
  id: string
  label: string
  ok: boolean
  detail: string
}

export interface DirectorySources {
  auth: AuthSource
  sessionsMeasured: boolean
  mfaMeasured: boolean
  notes: string[]
}

export interface UserDirectory {
  users: DirectoryUser[]
  stats: DirectoryStats
  integrity: DirectoryIntegrityCheck[]
  sources: DirectorySources
  /** Changes only when an underlying record changes (drives SSE refetches). */
  version: string
  generatedAt: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function lower(value: unknown): string {
  return text(value).toLowerCase()
}

function timeOf(value: string | null | undefined): number | null {
  if (!value) return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

function latest(...values: Array<string | null | undefined>): string | null {
  let best: string | null = null
  let bestMs = -Infinity
  for (const value of values) {
    const ms = timeOf(value)
    if (ms !== null && ms > bestMs) {
      best = new Date(ms).toISOString()
      bestMs = ms
    }
  }
  return best
}

export function normalizeRoleKey(value: unknown): string {
  return lower(value).replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
}

const ROLE_LABELS: Record<string, string> = {
  owner: 'Owner',
  super_admin: 'Super Admin',
  security_admin: 'Security Admin',
  tenant_admin: 'Tenant Admin',
  admin: 'Admin',
  auditor: 'Auditor',
  user: 'User',
  member: 'Member',
}

export function roleLabel(roleKey: string): string {
  return ROLE_LABELS[roleKey] || roleKey.split('_').filter(Boolean).map((part) => part[0].toUpperCase() + part.slice(1)).join(' ') || 'User'
}

export function isAdministratorRole(roleKey: string): boolean {
  return roleKey === 'owner' || /(^|_)admin($|_)/.test(roleKey)
}

export function userDisplayId(id: string): string {
  return `USR_${id.replace(/-/g, '').slice(0, 7).toUpperCase()}`
}

/** A human label for a session's user agent — honest about scripts. */
export function describeUserAgent(ua: string | null | undefined): string | null {
  const value = text(ua)
  if (!value) return null
  if (/^node\b|node-fetch|undici|axios|python-requests|curl\//i.test(value)) return 'API / script client'
  if (/okhttp/i.test(value)) return 'Android app'
  const browser = /Edg\//.test(value) ? 'Edge'
    : /OPR\//.test(value) ? 'Opera'
      : /Firefox\//.test(value) ? 'Firefox'
        : /Chrome\//.test(value) ? 'Chrome'
          : /Safari\//.test(value) ? 'Safari'
            : null
  const os = /Windows NT/.test(value) ? 'Windows'
    : /Android/.test(value) ? 'Android'
      : /(iPhone|iPad|iPod)/.test(value) ? 'iOS'
        : /Mac OS X|Macintosh/.test(value) ? 'macOS'
          : /Linux/.test(value) ? 'Linux'
            : null
  if (browser && os) return `${browser} on ${os}`
  return browser || os || 'Unrecognised client'
}

function fnv1a(input: string): string {
  let hash = 0x811c9dc5
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

export function buildUserDirectory(input: DirectoryInput): UserDirectory {
  const now = input.now ?? Date.now()
  const authMeasured = input.authSource !== 'unavailable'
  const sessionsMeasured = input.authSource === 'rpc'
  const mfaMeasured = input.authSource !== 'unavailable'
    && input.auth.every((row) => row.mfa_verified_factors !== null)

  const authById = new Map(input.auth.map((row) => [String(row.user_id), row]))
  const profileById = new Map(input.profiles.map((row) => [String(row.id), row]))
  const subscriptionByUser = new Map<string, SubscriptionRecordLite>()
  for (const row of input.subscriptions) {
    const current = subscriptionByUser.get(row.user_id)
    // One row per user is enforced by a unique index; if a legacy duplicate
    // exists, the newest wins — the same row the gateway reads.
    if (!current || (timeOf(row.updated_at) ?? 0) > (timeOf(current.updated_at) ?? 0)) {
      subscriptionByUser.set(row.user_id, row)
    }
  }
  const orgById = new Map(input.organizations.map((row) => [String(row.id), row]))
  const membershipsByUser = new Map<string, MembershipRecord[]>()
  for (const row of input.memberships) {
    const list = membershipsByUser.get(row.user_id) || []
    list.push(row)
    membershipsByUser.set(row.user_id, list)
  }

  const ids = new Set<string>([...profileById.keys(), ...(authMeasured ? authById.keys() : [])])
  const users: DirectoryUser[] = []
  const versionParts: string[] = []

  for (const id of ids) {
    const profile = profileById.get(id) || null
    const auth = authById.get(id) || null
    const subscription = subscriptionByUser.get(id) || null
    const email = text(profile?.email) || text(auth?.email)
    const isOwner = isOwnerEmail(email)

    // --- role -------------------------------------------------------------
    const profileRole = normalizeRoleKey(profile?.role)
    const authRole = normalizeRoleKey(auth?.app_role)
    const role = isOwner ? 'owner' : profileRole || authRole || 'user'
    const roleSource: DirectoryUser['roleSource'] = isOwner ? 'owner' : profileRole ? 'profile' : authRole ? 'auth_metadata' : 'default'

    // --- tenant -----------------------------------------------------------
    const tenantId = text(profile?.tenant_id) || null
    const org = tenantId ? orgById.get(tenantId) || null : null
    const memberships = membershipsByUser.get(id) || []
    const membership = (tenantId && memberships.find((row) => row.organization_id === tenantId)) || memberships[0] || null

    // --- account status (profile x Supabase Auth ban) ----------------------
    const profileStatus = lower(profile?.account_status) || null
    const bannedUntil = auth?.banned_until || null
    const bannedMs = timeOf(bannedUntil)
    const banned = bannedMs !== null && bannedMs > now
    let status: DirectoryAccountStatus
    if (profileStatus === 'disabled') status = 'disabled'
    else if (profileStatus === 'suspended') status = 'suspended'
    else if (banned) status = 'suspended'
    else if (authMeasured && auth && !auth.email_confirmed_at) status = 'pending_verification'
    else status = 'active'

    let statusDrift: string | null = null
    if (authMeasured && !auth) statusDrift = 'Profile row has no Supabase Auth account (orphaned profile)'
    else if (!profile) statusDrift = 'Supabase Auth account has no profile row'
    else if (authMeasured && (profileStatus === 'suspended' || profileStatus === 'disabled') && !banned) {
      statusDrift = `Profile is ${profileStatus} but Supabase Auth still allows sign-in`
    } else if (banned && profileStatus !== 'suspended' && profileStatus !== 'disabled') {
      statusDrift = 'Supabase Auth blocks sign-in (banned) but the profile is marked active'
    }

    // --- access (the gateway's entitlement rule) ---------------------------
    const entitlement = entitlementFromRecords({ isOwner, subscription, profileTier: profile?.tier })
    const classification = subscription ? classifySubscription({ provider: subscription.provider ?? null, metadata: subscription.metadata ?? null }) : null
    const accessClass: DirectoryAccessClass = isOwner ? 'owner' : classification ? classification.revenueClass : 'none'
    const provider = lower(subscription?.provider) || null
    const profileTier = lower(profile?.tier) || null
    const mirroredTier = normalizeTier(profileTier)
    let tierDrift: string | null = null
    if (!isOwner) {
      if (entitlement.source === 'subscription' && entitlement.isActive && mirroredTier !== entitlement.tier) {
        tierDrift = `profiles.tier is "${profileTier || 'empty'}" but the subscription grants ${entitlement.tier === 'none' ? 'no plan' : TIER_LABEL[entitlement.tier as keyof typeof TIER_LABEL]}`
      } else if (entitlement.source === 'none' && mirroredTier !== 'none') {
        tierDrift = `profiles.tier is "${profileTier}" but there is no subscription, so it grants nothing`
      }
    }

    // --- sessions + activity -----------------------------------------------
    const sessionCount = sessionsMeasured && auth ? Number(auth.session_count ?? 0) : null
    const lastSessionActivity = auth?.last_session_activity_at || null
    const lastSignInAt = auth?.last_sign_in_at || null
    const lastActivityAt = latest(lastSessionActivity, lastSignInAt)
    const lastActivityMs = timeOf(lastActivityAt)
    const activity: DirectoryActivity = lastActivityMs === null ? 'never'
      : now - lastActivityMs <= ACTIVE_NOW_WINDOW_MS ? 'active_now'
        : now - lastActivityMs <= ACTIVE_WINDOW_DAYS * DAY_MS ? 'active_30d'
          : 'dormant'

    // --- MFA ---------------------------------------------------------------
    const mfaRequired = Boolean(profile?.mfa_required)
    const enrolledFactors = auth && auth.mfa_verified_factors !== null ? Number(auth.mfa_verified_factors) : null
    const mfaState: DirectoryMfaState = enrolledFactors === null ? 'unknown'
      : enrolledFactors > 0 ? 'enrolled'
        : mfaRequired ? 'required_not_enrolled'
          : 'not_enrolled'

    const name = text(profile?.full_name) || text(profile?.name)

    users.push({
      id,
      displayId: userDisplayId(id),
      email,
      name,
      isOwner,
      role,
      roleLabel: roleLabel(role),
      roleSource,
      isAdministrator: isAdministratorRole(role),
      tenantId,
      tenantName: text(org?.name) || null,
      tenantSlug: text(org?.slug) || null,
      tenantStatus: text(org?.status) || null,
      tenantRole: text(membership?.role) || null,
      status,
      profileStatus,
      bannedUntil,
      statusDrift,
      access: {
        tier: entitlement.tier,
        tierLabel: isOwner ? 'Owner · Elite' : entitlement.tier === 'none' ? 'No plan' : TIER_LABEL[entitlement.tier as keyof typeof TIER_LABEL],
        isActive: entitlement.isActive,
        status: entitlement.status,
        source: entitlement.source,
        accessClass,
        accessClassReason: isOwner ? 'Platform owner — full access, never billed'
          : classification ? classification.reason
            : 'No billing_subscriptions row — the account has no plan access',
        provider,
        providerLabel: provider ? providerLabel(provider) : null,
        providerManaged: provider === 'paypal' || provider === 'google_play',
        subscriptionId: subscription?.id || null,
        billingCycle: subscription?.billing_cycle || null,
        periodEnd: subscription?.current_period_end || null,
        cancelAtPeriodEnd: Boolean(subscription?.cancel_at_period_end),
        profileTier,
        tierDrift,
      },
      sessions: {
        count: sessionCount,
        aal2Count: sessionsMeasured && auth ? Number(auth.aal2_session_count ?? 0) : null,
        lastActivityAt: lastSessionActivity,
        lastIp: auth?.last_session_ip || null,
        lastUserAgent: auth?.last_session_user_agent || null,
        lastDevice: describeUserAgent(auth?.last_session_user_agent),
      },
      lastSignInAt,
      lastActivityAt,
      activity,
      mfa: {
        state: mfaState,
        enrolledFactors,
        factorTypes: auth?.mfa_factor_types || [],
        required: mfaRequired,
      },
      emailConfirmedAt: auth?.email_confirmed_at || null,
      invitedAt: auth?.invited_at || null,
      providers: auth?.providers || [],
      createdAt: auth?.created_at || profile?.created_at || null,
      updatedAt: profile?.updated_at || null,
      hasProfile: Boolean(profile),
      hasAuthAccount: Boolean(auth),
    })

    versionParts.push([
      id, email, name, role, tenantId, membership?.role, profileStatus, bannedUntil, profile?.tier, mfaRequired,
      subscription?.plan, subscription?.status, subscription?.provider, subscription?.current_period_end, subscription?.cancel_at_period_end,
      sessionCount, lastSessionActivity, lastSignInAt, enrolledFactors, auth?.email_confirmed_at, org?.name,
    ].map((value) => (value === null || value === undefined ? '' : String(value))).join('|'))
  }

  users.sort((a, b) => (timeOf(b.lastActivityAt) ?? -1) - (timeOf(a.lastActivityAt) ?? -1) || a.email.localeCompare(b.email))

  const stats = computeStats(users, now, { sessionsMeasured, mfaMeasured })
  const integrity = computeIntegrity(users, stats, input, { authMeasured, sessionsMeasured, mfaMeasured })
  const notes = [...(input.notes || [])]
  if (input.authSource === 'admin_api') notes.push('Session activity unavailable: the admin_user_auth_directory RPC is not installed (apply supabase/admin-user-directory.sql). Sign-in, bans and MFA come from the Auth admin API.')
  if (input.authSource === 'unavailable') notes.push('Supabase Auth could not be read — sign-in, sessions, bans and MFA are Unknown.')

  versionParts.sort()
  return {
    users,
    stats,
    integrity,
    sources: { auth: input.authSource, sessionsMeasured, mfaMeasured, notes },
    version: fnv1a(versionParts.join('\n')),
    generatedAt: new Date(now).toISOString(),
  }
}

function computeStats(users: DirectoryUser[], now: number, measured: { sessionsMeasured: boolean; mfaMeasured: boolean }): DirectoryStats {
  const count = (predicate: (user: DirectoryUser) => boolean) => users.reduce((sum, user) => sum + (predicate(user) ? 1 : 0), 0)
  const createdWithin = (fromDays: number, toDays: number) => count((user) => {
    const created = timeOf(user.createdAt)
    return created !== null && created > now - toDays * DAY_MS && created <= now - fromDays * DAY_MS
  })
  const activeNow = count((user) => user.activity === 'active_now')
  return {
    totalUsers: users.length,
    newLast30d: createdWithin(0, 30),
    newPrev30d: createdWithin(30, 60),
    activity: {
      activeNow,
      active30d: activeNow + count((user) => user.activity === 'active_30d'),
      dormant: count((user) => user.activity === 'dormant'),
      never: count((user) => user.activity === 'never'),
    },
    status: {
      active: count((user) => user.status === 'active'),
      pending_verification: count((user) => user.status === 'pending_verification'),
      suspended: count((user) => user.status === 'suspended'),
      disabled: count((user) => user.status === 'disabled'),
    },
    statusDrift: count((user) => Boolean(user.statusDrift)),
    access: {
      withAccess: count((user) => user.access.isActive),
      noAccess: count((user) => !user.access.isActive),
      byTier: {
        starter: count((user) => user.access.isActive && user.access.tier === 'starter'),
        basic: count((user) => user.access.isActive && user.access.tier === 'basic'),
        pro: count((user) => user.access.isActive && user.access.tier === 'pro'),
        elite: count((user) => user.access.isActive && user.access.tier === 'elite'),
      },
      byClass: {
        owner: count((user) => user.access.accessClass === 'owner'),
        provider: count((user) => user.access.accessClass === 'provider'),
        manual: count((user) => user.access.accessClass === 'manual'),
        complimentary: count((user) => user.access.accessClass === 'complimentary'),
        none: count((user) => user.access.accessClass === 'none'),
      },
      tierDrift: count((user) => Boolean(user.access.tierDrift)),
    },
    mfa: {
      enrolled: measured.mfaMeasured ? count((user) => user.mfa.state === 'enrolled') : null,
      notEnrolled: measured.mfaMeasured ? count((user) => user.mfa.state === 'not_enrolled' || user.mfa.state === 'required_not_enrolled') : null,
      required: count((user) => user.mfa.required),
      requiredNotEnrolled: measured.mfaMeasured ? count((user) => user.mfa.state === 'required_not_enrolled') : null,
    },
    administrators: count((user) => user.isAdministrator),
    noTenant: count((user) => !user.tenantId),
    liveSessions: measured.sessionsMeasured ? users.reduce((sum, user) => sum + (user.sessions.count ?? 0), 0) : null,
    usersWithSessions: measured.sessionsMeasured ? count((user) => (user.sessions.count ?? 0) > 0) : null,
  }
}

function computeIntegrity(
  users: DirectoryUser[],
  stats: DirectoryStats,
  input: DirectoryInput,
  measured: { authMeasured: boolean; sessionsMeasured: boolean; mfaMeasured: boolean },
): DirectoryIntegrityCheck[] {
  const orphanProfiles = users.filter((user) => !user.hasAuthAccount && user.hasProfile).length
  const missingProfiles = users.filter((user) => user.hasAuthAccount && !user.hasProfile).length
  const statusSum = Object.values(stats.status).reduce((sum, value) => sum + value, 0)
  const tierSum = Object.values(stats.access.byTier).reduce((sum, value) => sum + value, 0)
  const classSum = Object.values(stats.access.byClass).reduce((sum, value) => sum + value, 0)
  const activitySum = stats.activity.active30d + stats.activity.dormant + stats.activity.never
  const owners = users.filter((user) => user.isOwner).length

  return [
    {
      id: 'auth-profile-parity',
      label: 'Auth accounts ↔ profiles',
      ok: measured.authMeasured && orphanProfiles === 0 && missingProfiles === 0,
      detail: !measured.authMeasured
        ? 'Supabase Auth unreadable — parity not verified'
        : orphanProfiles === 0 && missingProfiles === 0
          ? `${input.auth.length} auth accounts = ${input.profiles.length} profiles`
          : `${orphanProfiles} profile(s) without an auth account, ${missingProfiles} auth account(s) without a profile`,
    },
    {
      id: 'status-partition',
      label: 'Status buckets sum to total',
      ok: statusSum === stats.totalUsers,
      detail: `${statusSum} of ${stats.totalUsers}`,
    },
    {
      id: 'access-partition',
      label: 'Plan buckets sum to total',
      ok: tierSum + stats.access.noAccess === stats.totalUsers && classSum === stats.totalUsers,
      detail: `${tierSum} with access + ${stats.access.noAccess} without = ${tierSum + stats.access.noAccess} of ${stats.totalUsers}`,
    },
    {
      id: 'activity-partition',
      label: 'Activity buckets sum to total',
      ok: activitySum === stats.totalUsers,
      detail: `${activitySum} of ${stats.totalUsers}`,
    },
    {
      id: 'status-drift',
      label: 'Profile status agrees with Supabase Auth',
      ok: stats.statusDrift === 0,
      detail: stats.statusDrift === 0 ? 'No account disagrees' : `${stats.statusDrift} account(s) disagree — open the row for the reason`,
    },
    {
      id: 'owner-account',
      label: 'Owner account present',
      ok: owners === 1,
      detail: owners === 1 ? 'Exactly one owner account' : `${owners} owner accounts found`,
    },
    {
      id: 'measurement',
      label: 'Sessions and MFA measured from Supabase Auth',
      ok: measured.sessionsMeasured && measured.mfaMeasured,
      detail: measured.sessionsMeasured && measured.mfaMeasured
        ? 'admin_user_auth_directory RPC'
        : measured.authMeasured ? 'Partial: sessions not measured' : 'Not measured',
    },
  ]
}

// ---------------------------------------------------------------------------
// Query (filter / sort / page) — the same predicate for the table and exports
// ---------------------------------------------------------------------------

export interface DirectoryQuery {
  search?: string
  role?: string
  tenant?: string
  plan?: string
  status?: string
  activity?: string
  mfa?: string
  sort?: string
  order?: string
  page?: number
  limit?: number
}

export const DIRECTORY_SORTS = ['last_activity', 'created', 'name', 'email', 'sessions', 'plan'] as const

const TIER_RANK_ORDER: Record<string, number> = { none: 0, starter: 1, basic: 2, pro: 3, elite: 4 }

export function filterDirectoryUsers(users: DirectoryUser[], query: DirectoryQuery): DirectoryUser[] {
  const search = lower(query.search)
  const role = lower(query.role)
  const tenant = text(query.tenant)
  const plan = lower(query.plan)
  const status = lower(query.status)
  const activity = lower(query.activity)
  const mfa = lower(query.mfa)

  return users.filter((user) => {
    if (search) {
      const haystack = `${user.name} ${user.email} ${user.id} ${user.displayId} ${user.tenantName || ''}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    if (role && role !== 'all') {
      if (role === 'administrators' ? !user.isAdministrator : user.role !== role) return false
    }
    if (tenant && tenant !== 'all') {
      if (tenant === 'unassigned' ? Boolean(user.tenantId) : user.tenantId !== tenant) return false
    }
    if (plan && plan !== 'all') {
      if (plan === 'no_access') { if (user.access.isActive) return false }
      else if (['owner', 'provider', 'manual', 'complimentary'].includes(plan)) { if (user.access.accessClass !== plan) return false }
      else if (!(user.access.isActive && user.access.tier === plan)) return false
    }
    if (status && status !== 'all') {
      if (status === 'drift' ? !user.statusDrift : user.status !== status) return false
    }
    if (activity && activity !== 'all') {
      if (activity === 'active_30d' ? !(user.activity === 'active_now' || user.activity === 'active_30d') : user.activity !== activity) return false
    }
    if (mfa && mfa !== 'all') {
      if (mfa === 'not_enrolled' ? !(user.mfa.state === 'not_enrolled' || user.mfa.state === 'required_not_enrolled') : user.mfa.state !== mfa) return false
    }
    return true
  })
}

export function sortDirectoryUsers(users: DirectoryUser[], sort = 'last_activity', order = 'desc'): DirectoryUser[] {
  const direction = order === 'asc' ? 1 : -1
  const byTime = (value: string | null) => timeOf(value) ?? -Infinity
  return [...users].sort((a, b) => {
    let delta = 0
    if (sort === 'created') delta = byTime(a.createdAt) - byTime(b.createdAt)
    else if (sort === 'name') delta = (a.name || a.email).localeCompare(b.name || b.email)
    else if (sort === 'email') delta = a.email.localeCompare(b.email)
    else if (sort === 'sessions') delta = (a.sessions.count ?? -1) - (b.sessions.count ?? -1)
    else if (sort === 'plan') delta = (a.access.isActive ? TIER_RANK_ORDER[a.access.tier] : -1) - (b.access.isActive ? TIER_RANK_ORDER[b.access.tier] : -1)
    else delta = byTime(a.lastActivityAt) - byTime(b.lastActivityAt)
    return delta * direction || a.email.localeCompare(b.email)
  })
}

export interface DirectoryFacets {
  roles: Array<{ key: string; label: string; count: number }>
  tenants: Array<{ id: string; name: string; count: number }>
}

export function directoryFacets(users: DirectoryUser[]): DirectoryFacets {
  const roles = new Map<string, number>()
  const tenants = new Map<string, { name: string; count: number }>()
  for (const user of users) {
    roles.set(user.role, (roles.get(user.role) || 0) + 1)
    if (user.tenantId) {
      const entry = tenants.get(user.tenantId) || { name: user.tenantName || user.tenantId, count: 0 }
      entry.count += 1
      tenants.set(user.tenantId, entry)
    }
  }
  return {
    roles: Array.from(roles.entries()).map(([key, count]) => ({ key, label: roleLabel(key), count })).sort((a, b) => a.label.localeCompare(b.label)),
    tenants: Array.from(tenants.entries()).map(([id, entry]) => ({ id, ...entry })).sort((a, b) => a.name.localeCompare(b.name)),
  }
}

export function queryUserDirectory(directory: UserDirectory, query: DirectoryQuery) {
  const limit = Math.min(100, Math.max(1, Math.floor(Number(query.limit) || 25)))
  const filtered = sortDirectoryUsers(filterDirectoryUsers(directory.users, query), query.sort, query.order)
  const totalPages = Math.max(1, Math.ceil(filtered.length / limit))
  const page = Math.min(totalPages, Math.max(1, Math.floor(Number(query.page) || 1)))
  const from = (page - 1) * limit
  return {
    users: filtered.slice(from, from + limit),
    matched: filtered,
    pagination: { page, limit, total: filtered.length, totalPages },
  }
}

// ---------------------------------------------------------------------------
// Export (CSV) — full filtered set, formula-injection safe
// ---------------------------------------------------------------------------

function csvCell(value: unknown): string {
  let cell = value === null || value === undefined ? '' : String(value)
  // Neutralise spreadsheet formulas (=, +, -, @, tab, CR) — CSV injection.
  if (/^[=+\-@\t\r]/.test(cell)) cell = `'${cell}`
  return /[",\n\r]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell
}

export const DIRECTORY_CSV_COLUMNS: Array<{ header: string; value: (user: DirectoryUser) => unknown }> = [
  { header: 'User ID', value: (user) => user.id },
  { header: 'Name', value: (user) => user.name },
  { header: 'Email', value: (user) => user.email },
  { header: 'Role', value: (user) => user.roleLabel },
  { header: 'Status', value: (user) => user.status },
  { header: 'Status drift', value: (user) => user.statusDrift },
  { header: 'Plan', value: (user) => user.access.tierLabel },
  { header: 'Plan access', value: (user) => (user.access.isActive ? 'granted' : 'none') },
  { header: 'Subscription status', value: (user) => user.access.status },
  { header: 'Billing', value: (user) => user.access.accessClass },
  { header: 'Provider', value: (user) => user.access.providerLabel },
  { header: 'Period end (UTC)', value: (user) => user.access.periodEnd },
  { header: 'Tenant', value: (user) => user.tenantName },
  { header: 'Tenant role', value: (user) => user.tenantRole },
  { header: 'MFA', value: (user) => user.mfa.state },
  { header: 'MFA required by policy', value: (user) => user.mfa.required },
  { header: 'Live sessions', value: (user) => user.sessions.count },
  { header: 'Last activity (UTC)', value: (user) => user.lastActivityAt },
  { header: 'Last sign-in (UTC)', value: (user) => user.lastSignInAt },
  { header: 'Last IP', value: (user) => user.sessions.lastIp },
  { header: 'Last device', value: (user) => user.sessions.lastDevice },
  { header: 'Email confirmed (UTC)', value: (user) => user.emailConfirmedAt },
  { header: 'Created (UTC)', value: (user) => user.createdAt },
]

export function directoryToCsv(users: DirectoryUser[]): string {
  const lines = [DIRECTORY_CSV_COLUMNS.map((column) => csvCell(column.header)).join(',')]
  for (const user of users) lines.push(DIRECTORY_CSV_COLUMNS.map((column) => csvCell(column.value(user))).join(','))
  return `﻿${lines.join('\r\n')}\r\n`
}
