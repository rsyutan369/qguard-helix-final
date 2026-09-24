import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { useConsoleResource } from '@/hooks/use-console-resource'
import type {
  DirectoryFacets,
  DirectoryIntegrityCheck,
  DirectorySources,
  DirectoryStats,
  DirectoryUser,
} from '@/lib/admin/user-directory'
import type { CatalogRole, RoleCatalogStats } from '@/lib/admin/role-catalog'
import type { CatalogTenant, TenantStats } from '@/lib/admin/tenant-directory'
import type { BillingConsole, BillingInvoice, BillingRow, BillingStats, PlanCatalogEntry } from '@/lib/admin/billing-console'
import type { SecurityPosture } from '@/lib/admin/security-posture'
import type { GovernanceModel } from '@/lib/admin/governance'
import type { HistoryEntry } from '@/lib/admin/admin-history'
import type { IntegrityCheck } from '@/lib/admin/model-utils'

/** A row of the Users directory — the wire type is the model type (no drift). */
export type AdminUser = DirectoryUser

export type AdminUserSession = {
  id: string
  createdAt: string | null
  lastActivityAt: string | null
  notAfter: string | null
  aal: string | null
  ip: string | null
  userAgent: string | null
  device: string | null
  refreshCount: number | null
}

export type AdminUserDetail = {
  user: AdminUser
  /** null when sessions could not be measured (never an empty list by default). */
  sessions: AdminUserSession[] | null
  sessionsMeasured: boolean
  securityEvents: Array<Record<string, unknown>>
  adminTrail: HistoryEntry[]
  billingTrail: Array<Record<string, unknown>>
  version: string
  generatedAt: string
}

export type AssignableRole = { key: string; label: string; description: string; type: string }

export type UserDirectoryQuery = {
  search: string
  role: string
  tenant: string
  plan: string
  status: string
  activity: string
  mfa: string
  sort: string
  order: 'asc' | 'desc'
}

export const DEFAULT_USER_QUERY: UserDirectoryQuery = {
  search: '',
  role: 'all',
  tenant: 'all',
  plan: 'all',
  status: 'all',
  activity: 'all',
  mfa: 'all',
  sort: 'last_activity',
  order: 'desc',
}

export type UsersDirectoryMeta = {
  stats: DirectoryStats
  integrity: DirectoryIntegrityCheck[]
  sources: DirectorySources
  facets: DirectoryFacets
  assignableRoles: AssignableRole[]
  version: string
  generatedAt: string
}

export type AdminNotice = { id: number; tone: 'success' | 'error' | 'info'; title: string; message?: string }

export type MutationOutcome<T> = { ok: true; data: T; error?: undefined } | { ok: false; data?: undefined; error: string }

export type Pagination = {
  page: number
  limit: number
  total: number
  totalPages: number
}

export type AdminStats = {
  timestamp: string
  kpis: Record<string, number | null>
  summaries: Record<string, Array<{ label: string; count: number }>>
  charts: Record<string, Array<{ label: string; count: number }>>
  recent: Record<string, Array<Record<string, unknown>>>
  realtime: {
    source: string
    unavailableTables: string[]
    generatedAt: string
  }
}

export type RolesPayload = { roles: CatalogRole[]; pagination: Pagination; stats: RoleCatalogStats; integrity: IntegrityCheck[]; version: string; generatedAt: string }
export type TenantsPayload = { tenants: CatalogTenant[]; pagination: Pagination; stats: TenantStats; integrity: IntegrityCheck[]; version: string; generatedAt: string }
export type BillingPayload = {
  subscriptions: BillingRow[]
  pagination: Pagination
  stats: BillingStats
  integrity: IntegrityCheck[]
  plans: PlanCatalogEntry[]
  invoices: BillingInvoice[]
  invoicesTotal: number
  paymentMethods: BillingConsole['paymentMethods']
  events: HistoryEntry[]
  version: string
  generatedAt: string
}
export type SecurityPayload = SecurityPosture
export type GovernancePayload = GovernanceModel
export type HistoryStats = {
  last7d: number
  views7d: number
  byCategory: Record<string, number>
  actors7d: number
  blocked7d: number
  totalRecords: number
  oldestAt: string | null
  latestAt: string | null
}
export type HistoryPayload = { entries: HistoryEntry[]; pagination: Pagination; stats: HistoryStats; version: string; generatedAt: string }

type UsersPayload = UsersDirectoryMeta & {
  users: AdminUser[]
  pagination: Pagination
}

/** The `admin-users` SSE frame: KPIs + a change version, never the table. */
type UsersStreamFrame = {
  version: string
  stats: DirectoryStats
  integrity: DirectoryIntegrityCheck[]
  sources: DirectorySources
  generatedAt: string
}

const defaultPagination: Pagination = { page: 1, limit: 25, total: 0, totalPages: 0 }

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback
}

export function useAdminDashboard() {
  const { session } = useAuth()
  const token = session?.access_token || ''
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [usersDirectory, setUsersDirectory] = useState<UsersDirectoryMeta | null>(null)
  const [userQuery, setUserQueryState] = useState<UserDirectoryQuery>(DEFAULT_USER_QUERY)
  const [usersLoading, setUsersLoading] = useState(false)
  const [usersError, setUsersError] = useState<string | null>(null)
  const [usersPagination, setUsersPagination] = useState<Pagination>(defaultPagination)
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [selectedUserDetail, setSelectedUserDetail] = useState<AdminUserDetail | null>(null)
  const [userDetailLoading, setUserDetailLoading] = useState(false)
  const [userDetailError, setUserDetailError] = useState<string | null>(null)
  const [notices, setNotices] = useState<AdminNotice[]>([])
  const [loading, setLoading] = useState(true)
  const [mutating, setMutating] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const [usersLiveUpdatedAt, setUsersLiveUpdatedAt] = useState<string | null>(null)
  const [liveAt, setLiveAt] = useState<string | null>(null)
  const streamRef = useRef<EventSource | null>(null)
  const userQueryRef = useRef(userQuery)
  const usersPageRef = useRef(1)
  const usersRequestSeq = useRef(0)
  const usersVersionRef = useRef<string | null>(null)
  const selectedUserIdRef = useRef<string | null>(null)
  const noticeSeq = useRef(0)
  userQueryRef.current = userQuery

  const authHeaders = useMemo(() => ({
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  }), [token])

  const apiFetch = useCallback(async <T,>(path: string, init: RequestInit = {}): Promise<T> => {
    if (!token) throw new Error('Owner session is not ready')
    const response = await fetch(path, {
      ...init,
      headers: {
        ...authHeaders,
        ...(init.headers || {}),
      },
    })
    const json = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(json?.error?.message || json?.message || `Admin request failed (HTTP ${response.status})`)
    }
    return json.data as T
  }, [authHeaders, token])

  // --- Console tabs (one resource each) --------------------------------------
  const roles = useConsoleResource<RolesPayload, { search: string; type: string; status: string; usage: string }>({
    path: '/api/v1/admin/roles', defaults: { search: '', type: 'all', status: 'all', usage: 'all' }, fetcher: apiFetch, limit: 25,
  })
  const tenants = useConsoleResource<TenantsPayload, { search: string; status: string; quota: string }>({
    path: '/api/v1/admin/tenants', defaults: { search: '', status: 'all', quota: 'all' }, fetcher: apiFetch, limit: 25,
  })
  const billing = useConsoleResource<BillingPayload, { search: string; status: string; plan: string; class: string }>({
    path: '/api/v1/admin/billing', defaults: { search: '', status: 'all', plan: 'all', class: 'all' }, fetcher: apiFetch, limit: 25,
  })
  const security = useConsoleResource<SecurityPayload, { window: string }>({
    path: '/api/v1/admin/security', defaults: { window: '24h' }, fetcher: apiFetch, debounceMs: 0,
  })
  const governance = useConsoleResource<GovernancePayload, Record<string, string>>({
    path: '/api/v1/admin/governance', defaults: {}, fetcher: apiFetch,
  })
  const history = useConsoleResource<HistoryPayload, { source: string; category: string; actor: string; search: string; since: string; includeViews: string }>({
    path: '/api/v1/admin/history', defaults: { source: 'admin', category: 'all', actor: '', search: '', since: '', includeViews: '0' }, fetcher: apiFetch, limit: 25,
  })
  const resources = useRef({ roles, tenants, billing, security, governance, history })
  resources.current = { roles, tenants, billing, security, governance, history }

  const pushNotice = useCallback((notice: Omit<AdminNotice, 'id'>) => {
    noticeSeq.current += 1
    const id = noticeSeq.current
    setNotices((current) => [...current.slice(-3), { ...notice, id }])
  }, [])

  const dismissNotice = useCallback((id: number) => {
    setNotices((current) => current.filter((notice) => notice.id !== id))
  }, [])

  const refreshStats = useCallback(async () => {
    const data = await apiFetch<AdminStats>('/api/v1/admin/stats')
    setStats(data)
  }, [apiFetch])

  const refreshUsers = useCallback(async (page?: number) => {
    const query = userQueryRef.current
    const targetPage = page ?? usersPageRef.current
    const requestId = ++usersRequestSeq.current
    setUsersLoading(true)
    try {
      const params = new URLSearchParams({
        page: String(targetPage),
        limit: String(defaultPagination.limit),
        ...query,
      })
      const data = await apiFetch<UsersPayload>(`/api/v1/admin/users?${params}`)
      // Only the newest request may write (debounced search can overlap).
      if (requestId !== usersRequestSeq.current) return
      const { users: rows, pagination, ...meta } = data
      setUsers(rows)
      setUsersPagination(pagination)
      usersPageRef.current = pagination.page
      setUsersDirectory(meta)
      usersVersionRef.current = meta.version
      setUsersLiveUpdatedAt(meta.generatedAt)
      setUsersError(null)
    } catch (err) {
      if (requestId === usersRequestSeq.current) setUsersError(errorMessage(err, 'Unable to load users'))
      throw err
    } finally {
      if (requestId === usersRequestSeq.current) setUsersLoading(false)
    }
  }, [apiFetch])

  const loadUserDetail = useCallback(async (userId: string, options: { live?: boolean } = {}) => {
    try {
      const data = await apiFetch<AdminUserDetail>(`/api/v1/admin/users/${encodeURIComponent(userId)}${options.live ? '?live=1' : ''}`)
      if (selectedUserIdRef.current !== userId) return
      setSelectedUserDetail(data)
      setUserDetailError(null)
    } catch (err) {
      if (selectedUserIdRef.current !== userId) return
      const message = errorMessage(err, 'Unable to load user')
      // The account was deleted elsewhere: close the drawer instead of showing stale data.
      if (/not found/i.test(message)) {
        selectedUserIdRef.current = null
        setSelectedUserId(null)
        setSelectedUserDetail(null)
        return
      }
      setUserDetailError(message)
    }
  }, [apiFetch])

  const openUserDetail = useCallback((userId: string) => {
    selectedUserIdRef.current = userId
    setSelectedUserId(userId)
    setSelectedUserDetail(null)
    setUserDetailError(null)
    setUserDetailLoading(true)
    void loadUserDetail(userId).finally(() => {
      if (selectedUserIdRef.current === userId) setUserDetailLoading(false)
    })
  }, [loadUserDetail])

  const closeUserDetail = useCallback(() => {
    selectedUserIdRef.current = null
    setSelectedUserId(null)
    setSelectedUserDetail(null)
    setUserDetailError(null)
    setUserDetailLoading(false)
  }, [])

  const refreshUserDetail = useCallback(async () => {
    const userId = selectedUserIdRef.current
    if (!userId) return
    setUserDetailLoading(true)
    await loadUserDetail(userId, { live: true })
    if (selectedUserIdRef.current === userId) setUserDetailLoading(false)
  }, [loadUserDetail])

  const setUserQuery = useCallback((patch: Partial<UserDirectoryQuery>) => {
    setUserQueryState((current) => ({ ...current, ...patch }))
  }, [])

  const resetUserQuery = useCallback(() => {
    setUserQueryState((current) => ({ ...DEFAULT_USER_QUERY, sort: current.sort, order: current.order }))
  }, [])

  // Latest refreshers, read by the stream handlers and refreshAll so neither
  // has to be re-created (and re-run) when a filter changes.
  const refreshers = useRef({ refreshStats, refreshUsers, loadUserDetail })
  refreshers.current = { refreshStats, refreshUsers, loadUserDetail }

  const refreshAll = useCallback(async () => {
    if (!token) return
    setError(null)
    setLoading(true)
    const current = refreshers.current
    const tabs = Object.values(resources.current).filter((resource) => resource.isActive())
    const results = await Promise.allSettled([
      current.refreshStats(),
      current.refreshUsers(1),
      ...tabs.map((resource) => resource.refresh()),
    ])
    const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
    if (failed) setError(errorMessage(failed.reason, 'Unable to load admin dashboard'))
    setLoading(false)
  }, [token])

  useEffect(() => {
    void refreshAll()
  }, [refreshAll])

  // Users filters refresh ONLY the users list, from page 1 (value-compared).
  const lastUserQueryKey = useRef<string | null>(null)
  useEffect(() => {
    const key = JSON.stringify(userQuery)
    if (lastUserQueryKey.current === null || lastUserQueryKey.current === key) {
      lastUserQueryKey.current = key
      return undefined
    }
    lastUserQueryKey.current = key
    const handle = window.setTimeout(() => void refreshers.current.refreshUsers(1).catch(() => undefined), 250)
    return () => window.clearTimeout(handle)
  }, [userQuery])

  useEffect(() => {
    if (!token) return undefined
    streamRef.current?.close()
    const stream = new EventSource(`/api/v1/admin/stream?token=${encodeURIComponent(token)}`)
    streamRef.current = stream
    const parse = <T,>(event: Event, label: string): T | null => {
      try {
        return JSON.parse((event as MessageEvent).data) as T
      } catch {
        setError(`Unable to parse the admin ${label} stream frame`)
        return null
      }
    }
    const live = () => {
      setSseConnected(true)
      setLiveAt(new Date().toISOString())
    }

    stream.onopen = () => setSseConnected(true)
    stream.addEventListener('admin-connected', () => setSseConnected(true))
    stream.addEventListener('admin-users', (event) => {
      const frame = parse<UsersStreamFrame>(event, 'users')
      if (!frame) return
      live()
      setUsersLiveUpdatedAt(frame.generatedAt)
      setUsersDirectory((current) => (current ? { ...current, stats: frame.stats, integrity: frame.integrity, sources: frame.sources, version: frame.version, generatedAt: frame.generatedAt } : current))
      // Refetch the visible (filtered, paged) table only when a record changed.
      if (usersVersionRef.current !== null && frame.version !== usersVersionRef.current) {
        usersVersionRef.current = frame.version
        void refreshers.current.refreshUsers().catch(() => undefined)
        const openUserId = selectedUserIdRef.current
        if (openUserId) void refreshers.current.loadUserDetail(openUserId, { live: true })
      }
    })
    stream.addEventListener('admin-stats', (event) => {
      const data = parse<AdminStats>(event, 'overview')
      if (!data) return
      setStats(data)
      live()
    })
    const versioned: Array<[string, keyof typeof resources.current]> = [
      ['admin-roles', 'roles'],
      ['admin-tenants', 'tenants'],
      ['admin-billing', 'billing'],
      ['admin-governance', 'governance'],
      ['admin-history', 'history'],
    ]
    for (const [eventName, key] of versioned) {
      stream.addEventListener(eventName, (event) => {
        const frame = parse<{ version: string }>(event, key)
        if (!frame) return
        live()
        resources.current[key].onStreamVersion(frame.version)
      })
    }
    stream.addEventListener('admin-security', (event) => {
      const frame = parse<{ version: string; window: string }>(event, 'security')
      if (!frame) return
      live()
      // The stream carries the 24h window; another window refetches on change.
      const securityResource = resources.current.security
      if (securityResource.query.window === frame.window) securityResource.onStreamVersion(frame.version)
    })
    stream.addEventListener('admin-error', (event) => {
      const data = parse<{ message?: string }>(event, 'error')
      setError(data?.message || 'Admin stream reported an error')
    })
    stream.addEventListener('admin-reauth', (event) => {
      const data = parse<{ message?: string }>(event, 'session')
      // Stop auto-reconnecting with a dead token; a refreshed session token
      // re-runs this effect and opens a new stream.
      stream.close()
      setSseConnected(false)
      setError(data?.message || 'Owner session expired — sign in again to resume live telemetry.')
    })
    stream.onerror = () => setSseConnected(false)

    return () => {
      stream.close()
      if (streamRef.current === stream) streamRef.current = null
    }
  }, [token])

  /**
   * Every console mutation: one busy label, a success/warning/error notice,
   * and an immediate refresh of what it changed (the SSE push then refreshes
   * any other open tab whose model moved). The outcome is returned so dialogs
   * can stay open and show the error.
   */
  const runMutation = useCallback(async <T,>(
    label: string,
    operation: () => Promise<T>,
    describe: (data: T) => { title: string; message?: string },
    refresh: Array<'users' | keyof typeof resources.current> = [],
    targetUserId: string | null = null,
  ): Promise<MutationOutcome<T>> => {
    setMutating(label)
    try {
      const data = await operation()
      pushNotice({ tone: 'success', ...describe(data) })
      const warnings = (data as { warnings?: unknown } | null)?.warnings
      if (Array.isArray(warnings) && warnings.length) {
        pushNotice({ tone: 'info', title: 'Completed with warnings', message: warnings.map(String).join(' · ') })
      }
      await Promise.all(refresh.map((key) => {
        if (key === 'users') return refreshers.current.refreshUsers().catch(() => undefined)
        const resource = resources.current[key]
        return resource.isActive() ? resource.refresh() : Promise.resolve()
      }))
      if (targetUserId && selectedUserIdRef.current === targetUserId) await refreshers.current.loadUserDetail(targetUserId, { live: true })
      return { ok: true, data }
    } catch (err) {
      const message = errorMessage(err, `${label} failed`)
      pushNotice({ tone: 'error', title: 'Action failed', message })
      return { ok: false, error: message }
    } finally {
      setMutating(null)
    }
  }, [pushNotice])

  const send = useCallback(<T,>(path: string, method: string, body?: unknown) => apiFetch<T>(path, { method, body: body === undefined ? undefined : JSON.stringify(body) }), [apiFetch])

  // --- Users -------------------------------------------------------------------
  const createUser = useCallback((payload: Record<string, unknown>) => runMutation(
    'create-user',
    () => send<{ userId: string; email: string; plan: string | null; warnings: string[] }>('/api/v1/admin/users', 'POST', payload),
    (data) => ({ title: 'User created', message: `${data.email}${data.plan ? ` · ${data.plan} plan granted` : ' · no plan'}` }),
    ['users'],
  ), [runMutation, send])

  const updateUser = useCallback((userId: string, payload: Record<string, unknown>) => runMutation(
    `update:${userId}`,
    () => send<{ changes: Record<string, { from: unknown; to: unknown }>; warnings: string[] }>(`/api/v1/admin/users/${encodeURIComponent(userId)}`, 'PATCH', payload),
    (data) => ({ title: 'User updated', message: Object.keys(data.changes || {}).join(', ') || undefined }),
    ['users'],
    userId,
  ), [runMutation, send])

  const deleteUser = useCallback(async (userId: string, confirmEmail: string) => {
    const outcome = await runMutation(
      `delete:${userId}`,
      () => send<{ id: string; sessionsEnded: number | null; warnings: string[] }>(`/api/v1/admin/users/${encodeURIComponent(userId)}`, 'DELETE', { confirmEmail }),
      () => ({ title: 'User deleted', message: confirmEmail }),
      ['users'],
    )
    if (outcome.ok && selectedUserIdRef.current === userId) {
      selectedUserIdRef.current = null
      setSelectedUserId(null)
      setSelectedUserDetail(null)
    }
    return outcome
  }, [runMutation, send])

  const userAction = useCallback((userId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(
    `${action}:${userId}`,
    () => send<Record<string, unknown> & { warnings?: string[]; recoveryLink?: string; sessionsEnded?: number | null; sentTo?: string }>(`/api/v1/admin/users/${encodeURIComponent(userId)}/actions`, 'POST', { action, ...payload }),
    (data) => {
      const sessions = typeof data.sessionsEnded === 'number' ? `${data.sessionsEnded} session${data.sessionsEnded === 1 ? '' : 's'} ended` : undefined
      switch (action) {
        case 'suspend': return { title: 'User suspended', message: sessions }
        case 'disable': return { title: 'User disabled', message: sessions }
        case 'restore': return { title: 'Access restored' }
        case 'force_logout': return { title: 'Signed out everywhere', message: sessions }
        case 'reset_password': return data.recoveryLink
          ? { title: 'Recovery link generated', message: 'Single use — share it only with the account holder.' }
          : { title: 'Reset email sent', message: data.sentTo }
        case 'mfa_require': return { title: 'MFA now required by policy' }
        case 'mfa_relax': return { title: 'MFA requirement removed' }
        case 'verify_email': return { title: 'Email marked as verified' }
        default: return { title: 'Action completed' }
      }
    },
    ['users'],
    userId,
  ), [runMutation, send])

  const manageUserSubscription = useCallback((userId: string, payload: Record<string, unknown>) => runMutation(
    `subscription:${userId}`,
    () => send<{ subscription: Record<string, unknown> }>(`/api/v1/admin/users/${encodeURIComponent(userId)}/subscription`, 'POST', payload),
    (data) => ({ title: 'Plan updated', message: `${String(data.subscription?.plan || '')} · ${String(data.subscription?.status || '').replace(/_/g, ' ')}` }),
    ['users', 'billing'],
    userId,
  ), [runMutation, send])

  /** Authenticated file download (exports, evidence packages). */
  const download = useCallback(async (label: string, path: string, fallbackName: string) => {
    if (!token) return
    setMutating(label)
    try {
      const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) {
        const json = await response.json().catch(() => ({}))
        throw new Error(json?.error?.message || `Download failed (HTTP ${response.status})`)
      }
      const blob = await response.blob()
      const filename = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '')?.[1] || fallbackName
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
      pushNotice({ tone: 'success', title: 'Downloaded', message: filename })
    } catch (err) {
      pushNotice({ tone: 'error', title: 'Download failed', message: errorMessage(err, 'Download failed') })
    } finally {
      setMutating(null)
    }
  }, [pushNotice, token])

  const exportUsers = useCallback((format: 'csv' | 'json') => download(
    `export-users-${format}`,
    `/api/v1/admin/users/export?${new URLSearchParams({ ...userQueryRef.current, format })}`,
    `qguard-users.${format}`,
  ), [download])

  /** Every tenant (not the Tenants tab's current page) for assignment pickers. */
  const loadTenantOptions = useCallback(async () => {
    const data = await apiFetch<TenantsPayload>('/api/v1/admin/tenants?page=1&limit=100')
    return data.tenants.map((tenant) => ({ id: tenant.id, name: tenant.name, status: tenant.status }))
  }, [apiFetch])

  /** One account from the directory (for dialogs opened outside the Users tab). */
  const loadDirectoryUser = useCallback(async (userId: string) => (
    (await apiFetch<AdminUserDetail>(`/api/v1/admin/users/${encodeURIComponent(userId)}?live=1`)).user
  ), [apiFetch])

  /** Every account (id + email) for owner pickers. */
  const loadUserOptions = useCallback(async () => {
    const data = await apiFetch<UsersPayload>('/api/v1/admin/users?page=1&limit=100&sort=email&order=asc')
    return data.users.map((user) => ({ id: user.id, email: user.email, name: user.name }))
  }, [apiFetch])

  // --- Roles -------------------------------------------------------------------
  const createRole = useCallback((payload: Record<string, unknown>) => runMutation(
    'create-role',
    () => send<{ id: string; key: string }>('/api/v1/admin/roles', 'POST', payload),
    (data) => ({ title: 'Role created', message: data.key }),
    ['roles'],
  ), [runMutation, send])

  const updateRole = useCallback((roleId: string, payload: Record<string, unknown>) => runMutation(
    `role:${roleId}`,
    () => send<{ id: string; changes: Record<string, unknown> }>(`/api/v1/admin/roles/${roleId}`, 'PATCH', payload),
    (data) => ({ title: 'Role updated', message: Object.keys(data.changes || {}).join(', ') }),
    ['roles'],
  ), [runMutation, send])

  const roleAction = useCallback((roleId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(
    `role:${roleId}`,
    () => send<{ id: string; status?: string; deleted?: boolean; warnings?: string[] }>(`/api/v1/admin/roles/${roleId}/actions`, 'POST', { action, ...payload }),
    (data) => ({ title: data.deleted ? 'Role deleted' : `Role ${data.status || 'updated'}` }),
    ['roles'],
  ), [runMutation, send])

  // --- Tenants -----------------------------------------------------------------
  const createTenant = useCallback((payload: Record<string, unknown>) => runMutation(
    'create-tenant',
    () => send<{ id: string; slug: string }>('/api/v1/admin/tenants', 'POST', payload),
    (data) => ({ title: 'Tenant created', message: data.slug }),
    ['tenants'],
  ), [runMutation, send])

  const updateTenant = useCallback((tenantId: string, payload: Record<string, unknown>) => runMutation(
    `tenant:${tenantId}`,
    () => send<{ id: string; changedFields: string[] }>(`/api/v1/admin/tenants/${tenantId}`, 'PATCH', payload),
    (data) => ({ title: 'Tenant updated', message: data.changedFields.join(', ') }),
    ['tenants'],
  ), [runMutation, send])

  const tenantAction = useCallback((tenantId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(
    `tenant:${tenantId}`,
    () => send<{ id: string; status?: string; deleted?: boolean; membersAffected?: number; warnings?: string[] }>(`/api/v1/admin/tenants/${tenantId}/actions`, 'POST', { action, ...payload }),
    (data) => ({
      title: data.deleted ? 'Tenant deleted' : action === 'suspend' ? 'Tenant suspended' : 'Tenant restored',
      message: data.membersAffected ? `${data.membersAffected} member account(s) ${action === 'suspend' ? 'suspended' : 'restored'}` : undefined,
    }),
    ['tenants', 'users'],
  ), [runMutation, send])

  // --- Billing -----------------------------------------------------------------
  const subscriptionAction = useCallback((subscriptionId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(
    `subscription-action:${subscriptionId}`,
    () => send<Record<string, unknown>>(`/api/v1/admin/subscriptions/${subscriptionId}/actions`, 'POST', { action, ...payload }),
    (data) => ({
      title: action === 'notify' ? 'Reminder delivered' : action === 'extend' ? 'Period extended' : action === 'cancel' ? 'Subscription cancelled' : action === 'delete' ? 'Subscription record deleted' : 'Subscription approved',
      message: typeof data.delivered === 'string' ? data.delivered : undefined,
    }),
    ['billing', 'users'],
  ), [runMutation, send])

  const exportBilling = useCallback(() => download(
    'export-billing',
    `/api/v1/admin/billing/export?${new URLSearchParams(resources.current.billing.query)}`,
    'qguard-subscriptions.csv',
  ), [download])

  // --- Governance --------------------------------------------------------------
  const createPolicy = useCallback((payload: Record<string, unknown>) => runMutation(
    'create-policy',
    () => send<{ id: string; key: string }>('/api/v1/admin/governance/policies', 'POST', payload),
    (data) => ({ title: 'Policy created', message: data.key }),
    ['governance'],
  ), [runMutation, send])

  const updatePolicy = useCallback((policyId: string, payload: Record<string, unknown>) => runMutation(
    `policy:${policyId}`,
    () => send<{ id: string; changedFields: string[] }>(`/api/v1/admin/governance/policies/${policyId}`, 'PATCH', payload),
    (data) => ({ title: 'Policy updated', message: data.changedFields.join(', ') }),
    ['governance'],
  ), [runMutation, send])

  const deletePolicy = useCallback((policyId: string, confirmKey: string) => runMutation(
    `policy:${policyId}`,
    () => send<{ id: string }>(`/api/v1/admin/governance/policies/${policyId}`, 'DELETE', { confirmKey }),
    () => ({ title: 'Policy deleted', message: confirmKey }),
    ['governance'],
  ), [runMutation, send])

  const generateEvidence = useCallback((title: string) => runMutation(
    'generate-evidence',
    () => send<{ id: string; hash: { algorithm: string; value: string } }>('/api/v1/admin/governance/evidence', 'POST', { title }),
    (data) => ({ title: 'Evidence package generated', message: `${data.hash.algorithm} ${data.hash.value.slice(0, 16)}…` }),
    ['governance'],
  ), [runMutation, send])

  const downloadEvidence = useCallback((evidenceId: string) => download(
    `evidence:${evidenceId}`,
    `/api/v1/admin/governance/evidence/${evidenceId}`,
    `qguard-evidence-${evidenceId.slice(0, 8)}.json`,
  ), [download])

  // --- History -----------------------------------------------------------------
  const exportHistory = useCallback(() => download(
    'export-history',
    `/api/v1/admin/history/export?${new URLSearchParams(resources.current.history.query)}`,
    'qguard-admin-history.csv',
  ), [download])

  return {
    stats,
    users,
    usersDirectory,
    usersLoading,
    usersError,
    userQuery,
    setUserQuery,
    resetUserQuery,
    usersPagination,
    selectedUserId,
    selectedUserDetail,
    userDetailLoading,
    userDetailError,
    openUserDetail,
    closeUserDetail,
    refreshUserDetail,
    roles,
    tenants,
    billing,
    security,
    governance,
    history,
    notices,
    pushNotice,
    dismissNotice,
    loading,
    mutating,
    error,
    setError,
    sseConnected,
    usersLiveUpdatedAt,
    liveAt,
    refreshAll,
    refreshUsers,
    createUser,
    updateUser,
    deleteUser,
    userAction,
    manageUserSubscription,
    exportUsers,
    loadTenantOptions,
    loadUserOptions,
    loadDirectoryUser,
    createRole,
    updateRole,
    roleAction,
    createTenant,
    updateTenant,
    tenantAction,
    subscriptionAction,
    exportBilling,
    createPolicy,
    updatePolicy,
    deletePolicy,
    generateEvidence,
    downloadEvidence,
    exportHistory,
  }
}

export type AdminDashboard = ReturnType<typeof useAdminDashboard>
