// Owner Admin > Tenants — the ONE tenant model.
//
// Members, their status, plan access, MFA and live sessions are read from the
// Users directory (so Tenants and Users agree by construction). Nothing is
// invented: a tenant with no recorded domain or region shows none (the old
// console printed `<slug>.qguard.app` and `us-east-1` for every tenant and then
// let you filter on those made-up values).

import type { DirectoryUser } from './user-directory'
import { latestIso, lower, modelVersion, paginate, text, type IntegrityCheck } from './model-utils'

export interface OrganizationRow {
  id: string
  name: string | null
  slug: string | null
  owner_user_id: string | null
  status: string | null
  plan: string | null
  quota_users: number | null
  quota_storage_gb: number | string | null
  metadata: Record<string, unknown> | null
  created_at: string | null
  updated_at: string | null
}

export interface MembershipRow {
  organization_id: string
  user_id: string
  role: string | null
  status: string | null
}

export type TenantStatus = 'active' | 'suspended' | 'disabled'

export interface CatalogTenant {
  id: string
  name: string
  slug: string
  status: TenantStatus
  /** organizations.plan — written by billing sync; a label, not an entitlement. */
  planLabel: string | null
  domain: string | null
  region: string | null
  owner: { id: string; email: string; name: string } | null
  ownerMissing: boolean
  members: number
  membersActive: number
  membersBlocked: number
  membersWithAccess: number
  membersMfa: number
  liveSessions: number | null
  quotaUsers: number | null
  quotaStorageGb: number | null
  quotaUsedPercent: number | null
  overQuota: boolean
  /** Membership rows that disagree with profiles.tenant_id. */
  membershipDrift: number
  memberSample: Array<{ id: string; email: string; name: string; status: string; role: string }>
  lastActivityAt: string | null
  suspendedMemberIds: string[]
  createdAt: string | null
  updatedAt: string | null
}

export interface TenantStats {
  total: number
  byStatus: Record<TenantStatus, number>
  members: number
  unassignedUsers: number
  overQuota: number
  withoutOwner: number
  membershipDrift: number
}

export interface TenantDirectory {
  tenants: CatalogTenant[]
  stats: TenantStats
  integrity: IntegrityCheck[]
  version: string
  generatedAt: string
}

export const TENANT_SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/

export function slugify(value: string): string {
  return lower(value).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64)
}

function tenantStatus(value: unknown): TenantStatus {
  const status = lower(value)
  return status === 'suspended' || status === 'disabled' ? status : 'active'
}

function positiveNumber(value: unknown): number | null {
  const num = Number(value)
  return Number.isFinite(num) && num > 0 ? num : null
}

export function buildTenantDirectory(input: {
  organizations: OrganizationRow[]
  memberships: MembershipRow[]
  users: DirectoryUser[]
  unassignedUsers: number
  sessionsMeasured: boolean
  now?: number
}): TenantDirectory {
  const now = input.now ?? Date.now()
  const usersById = new Map(input.users.map((user) => [user.id, user]))
  const membersByTenant = new Map<string, DirectoryUser[]>()
  for (const user of input.users) {
    if (!user.tenantId) continue
    const list = membersByTenant.get(user.tenantId) || []
    list.push(user)
    membersByTenant.set(user.tenantId, list)
  }

  const tenants: CatalogTenant[] = input.organizations.map((org) => {
    const members = membersByTenant.get(org.id) || []
    const metadata = org.metadata || {}
    const owner = org.owner_user_id ? usersById.get(org.owner_user_id) || null : null
    const quotaUsers = positiveNumber(org.quota_users)
    const memberIds = new Set(members.map((member) => member.id))
    const membershipRows = input.memberships.filter((row) => row.organization_id === org.id)
    const membershipDrift = membershipRows.filter((row) => !memberIds.has(row.user_id)).length
      + members.filter((member) => !membershipRows.some((row) => row.user_id === member.id)).length
    const suspended = Array.isArray((metadata as Record<string, unknown>).suspendedMemberIds)
      ? ((metadata as Record<string, unknown>).suspendedMemberIds as unknown[]).map(String)
      : []
    return {
      id: org.id,
      name: text(org.name) || 'Unnamed tenant',
      slug: text(org.slug),
      status: tenantStatus(org.status),
      planLabel: text(org.plan) || null,
      domain: text((metadata as Record<string, unknown>).domain) || null,
      region: text((metadata as Record<string, unknown>).region) || null,
      owner: owner ? { id: owner.id, email: owner.email, name: owner.name } : null,
      ownerMissing: Boolean(org.owner_user_id && !owner),
      members: members.length,
      membersActive: members.filter((member) => member.status === 'active').length,
      membersBlocked: members.filter((member) => member.status === 'suspended' || member.status === 'disabled').length,
      membersWithAccess: members.filter((member) => member.access.isActive).length,
      membersMfa: members.filter((member) => member.mfa.state === 'enrolled').length,
      liveSessions: input.sessionsMeasured ? members.reduce((sum, member) => sum + (member.sessions.count ?? 0), 0) : null,
      quotaUsers,
      quotaStorageGb: positiveNumber(org.quota_storage_gb),
      quotaUsedPercent: quotaUsers ? Math.round((members.length / quotaUsers) * 100) : null,
      overQuota: quotaUsers !== null && members.length > quotaUsers,
      membershipDrift,
      memberSample: members.slice(0, 8).map((member) => ({ id: member.id, email: member.email, name: member.name, status: member.status, role: member.roleLabel })),
      lastActivityAt: latestIso(...members.map((member) => member.lastActivityAt)),
      suspendedMemberIds: suspended,
      createdAt: org.created_at,
      updatedAt: org.updated_at,
    }
  }).sort((a, b) => a.name.localeCompare(b.name))

  const count = (predicate: (tenant: CatalogTenant) => boolean) => tenants.reduce((sum, tenant) => sum + (predicate(tenant) ? 1 : 0), 0)
  const stats: TenantStats = {
    total: tenants.length,
    byStatus: { active: count((t) => t.status === 'active'), suspended: count((t) => t.status === 'suspended'), disabled: count((t) => t.status === 'disabled') },
    members: tenants.reduce((sum, tenant) => sum + tenant.members, 0),
    unassignedUsers: input.unassignedUsers,
    overQuota: count((t) => t.overQuota),
    withoutOwner: count((t) => !t.owner),
    membershipDrift: tenants.reduce((sum, tenant) => sum + tenant.membershipDrift, 0),
  }
  const orphanedMembers = input.users.filter((user) => user.tenantId && !input.organizations.some((org) => org.id === user.tenantId)).length
  const integrity: IntegrityCheck[] = [
    { id: 'members-partition', label: 'Tenant members + unassigned = all users', ok: stats.members + stats.unassignedUsers + orphanedMembers === input.users.length, detail: `${stats.members} members + ${stats.unassignedUsers} unassigned = ${stats.members + stats.unassignedUsers} of ${input.users.length}` },
    { id: 'membership-rows', label: 'Membership rows agree with profiles', ok: stats.membershipDrift === 0, detail: stats.membershipDrift ? `${stats.membershipDrift} membership row(s) disagree with profiles.tenant_id` : 'All agree' },
    { id: 'quota', label: 'No tenant over its user quota', ok: stats.overQuota === 0, detail: stats.overQuota ? `${stats.overQuota} tenant(s) over quota` : 'Within quota' },
  ]
  const model = { tenants, stats, integrity }
  return { ...model, version: modelVersion(model), generatedAt: new Date(now).toISOString() }
}

export interface TenantQuery {
  search?: string
  status?: string
  quota?: string
  page?: number
  limit?: number
}

export function queryTenantDirectory(directory: TenantDirectory, query: TenantQuery) {
  const search = lower(query.search)
  const filtered = directory.tenants.filter((tenant) => {
    if (search && !`${tenant.name} ${tenant.slug} ${tenant.id} ${tenant.domain || ''} ${tenant.owner?.email || ''}`.toLowerCase().includes(search)) return false
    if (query.status && query.status !== 'all' && tenant.status !== query.status) return false
    if (query.quota === 'over' && !tenant.overQuota) return false
    if (query.quota === 'no_owner' && tenant.owner) return false
    return true
  })
  return paginate(filtered, query.page, query.limit)
}
