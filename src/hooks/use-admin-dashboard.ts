import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAuth } from '@/contexts/auth-context'

export type AdminUser = {
  id: string
  email: string
  name: string
  role: string
  status: string
  tier: string
  tenantId: string | null
  tenantName: string | null
  tenantSlug?: string | null
  tenantRole?: string | null
  tenantStatus?: string | null
  mfaRequired: boolean
  subscriptionStatus: string
  subscriptionPlan: string
  subscriptionInterval: string
  subscriptionExpiresAt: string | null
  qScore: number
  maxKeysPerDay: number
  maxVaultStorage: number
  activeSessions: number
  idleSessions: number
  deviceCount: number
  trustedDevices: number
  lastSeenAt: string | null
  lastIpAddress: string | null
  lastSignInAt: string | null
  emailConfirmedAt: string | null
  authProvider: string
  createdAt: string | null
  updatedAt: string | null
  loginHistory: Array<Record<string, unknown>>
  devices: Array<Record<string, unknown>>
  metadata: Record<string, unknown>
}

export type AdminTenant = {
  id: string
  name: string
  slug: string
  status: string
  plan: string
  domain?: string
  region?: string
  regionLabel?: string
  quota_users: number
  quota_storage_gb: number
  readiness_score: number
  security_score: number
  totalUsers?: number
  activeUsers?: number
  members: number
  activeMembers: number
  activeSubscriptions: number
  trialSubscriptions?: number
  subscriptions?: number
  devices?: number
  activeDevices?: number
  sessions?: number
  scans: number
  securityEvents: number
  renewalDate?: string | null
  createdBy?: string | null
  lastActivityAt?: string | null
  metadata?: Record<string, unknown>
  updated_at: string
  created_at: string
}

export type AdminTenantStats = {
  totalTenants: number
  activeTenants: number
  trialTenants: number
  suspendedTenants: number
  totalUsers: number
  totalDevices: number
  tenantGrowthPercent: number
}

export type AdminSubscription = {
  id: string
  user_id: string
  tenant_id?: string | null
  plan: string
  status: string
  billing_cycle?: string
  plan_interval?: string
  seats?: number
  amountCents?: number
  mrrCents?: number
  currency?: string
  renewalDate?: string | null
  daysUntilRenewal?: number | null
  totalUsers?: number
  totalDevices?: number
  latestInvoiceStatus?: string | null
  domain?: string | null
  region?: string
  regionLabel?: string
  current_period_end?: string | null
  expires_at?: string | null
  approval_status?: string | null
  updated_at?: string | null
  created_at?: string | null
  profile?: { id?: string; email?: string; name?: string; full_name?: string; tier?: string } | null
  tenant?: { id?: string; name?: string; slug?: string; domain?: string; region?: string; regionLabel?: string } | null
  invoices?: Array<Record<string, unknown>>
  paymentMethods?: Array<Record<string, unknown>>
}

export type AdminBillingStats = {
  totalMrrCents: number
  totalTenants: number
  activeSubscriptions: number
  pastDue: number
  pastDueAmountCents: number
  nextBillingDate: string | null
  nextBillingDays: number | null
  mrrGrowthPercent: number
}

export type AdminBillingSummary = {
  currentBalanceCents: number
  pastDueCents: number
  creditsCents: number
  totalBilledYtdCents: number
  totalPaidYtdCents: number
}

export type AdminUpcomingInvoice = {
  id: string
  tenantName: string
  dueDate: string | null
  amountCents: number
  currency: string
}

export type AdminPaymentMethod = {
  id: string
  userId?: string
  brand: string
  last4: string
  expMonth: number | null
  expYear: number | null
  isDefault: boolean
  updatedAt: string | null
}

export type AdminRole = {
  id: string
  roleKey: string
  name: string
  description: string
  type: string
  status: string
  tenantId: string | null
  tenantName: string | null
  users: number
  permissionScope: string
  permissionCount: number
  permissions: string[]
  protected: boolean
  icon: string
  createdAt: string | null
  updatedAt: string | null
  metadata: Record<string, unknown>
}

export type AdminRoleStats = {
  totalRoles: number
  customRoles: number
  systemRoles: number
  rolesInUse: number
  orphanedRoles: number
  customRolesPercent: number
  systemRolesPercent: number
  rolesInUsePercent: number
  roleGrowthPercent: number
}

export type AdminStats = {
  timestamp: string
  kpis: Record<string, number>
  summaries: Record<string, Array<{ label: string; count: number }>>
  charts: Record<string, Array<{ label: string; count: number }>>
  recent: Record<string, Array<Record<string, unknown>>>
  realtime: {
    source: string
    unavailableTables: string[]
    generatedAt: string
  }
}

export type AdminSecurity = {
  securityEvents: Array<Record<string, unknown>>
  userSecurityEvents: Array<Record<string, unknown>>
  sessions: Array<Record<string, unknown>>
  devices: Array<Record<string, unknown>>
  policies: Array<Record<string, unknown>>
  evidence: Array<Record<string, unknown>>
  metrics: Record<string, number>
  posture?: Array<{ label: string; score: number }>
  threatActivity?: Array<Record<string, number | string>>
  topThreats?: Array<{ title: string; detail: string; severity: string; count: number }>
  adminOverview?: Array<{ role: string; count: number }>
  adminAccessStatus?: Array<{ status: string; count: number }>
  recentAdminActivities?: Array<Record<string, unknown>>
  criticalAlerts?: Array<Record<string, unknown>>
  complianceStatus?: Array<{ label: string; status: string; score: number }>
  systemHealth?: {
    dataCollectors?: { healthy: number; total: number }
    integrations?: { healthy: number; total: number }
    sensors?: { healthy: number; total: number }
    storage?: { usedGb: number; totalGb: number }
  }
  unavailableTables: string[]
  generatedAt?: string
}

export type AdminActivity = {
  id?: string
  source: string
  severity: string
  title: string
  detail?: string
  created_at?: string
  actorEmail?: string
  actorId?: string | null
  administrator?: string
  action?: string
  targetType?: string
  targetId?: string
  target?: string
  result?: string
  ipAddress?: string | null
  row: Record<string, unknown>
}

type Pagination = {
  page: number
  limit: number
  total: number
  totalPages: number
}

type UsersPayload = {
  users: AdminUser[]
  pagination: Pagination
  unavailableTables: string[]
}

type TenantsPayload = {
  tenants: AdminTenant[]
  stats?: AdminTenantStats
  pagination: Pagination
  unavailableTables: string[]
  generatedAt?: string
}

type SubscriptionsPayload = {
  subscriptions: AdminSubscription[]
  stats?: AdminBillingStats
  summary?: AdminBillingSummary
  upcomingInvoices?: AdminUpcomingInvoice[]
  paymentMethods?: AdminPaymentMethod[]
  pagination: Pagination
  unavailableTables: string[]
  generatedAt?: string
}

type RolesPayload = {
  roles: AdminRole[]
  stats: AdminRoleStats
  pagination: Pagination
  unavailableTables: string[]
  generatedAt: string
}

const defaultPagination: Pagination = { page: 1, limit: 25, total: 0, totalPages: 0 }

export function useAdminDashboard() {
  const { session } = useAuth()
  const token = session?.access_token || ''
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [roles, setRoles] = useState<AdminRole[]>([])
  const [roleStats, setRoleStats] = useState<AdminRoleStats | null>(null)
  const [tenants, setTenants] = useState<AdminTenant[]>([])
  const [tenantStats, setTenantStats] = useState<AdminTenantStats | null>(null)
  const [subscriptions, setSubscriptions] = useState<AdminSubscription[]>([])
  const [subscriptionStats, setSubscriptionStats] = useState<AdminBillingStats | null>(null)
  const [billingSummary, setBillingSummary] = useState<AdminBillingSummary | null>(null)
  const [upcomingInvoices, setUpcomingInvoices] = useState<AdminUpcomingInvoice[]>([])
  const [paymentMethods, setPaymentMethods] = useState<AdminPaymentMethod[]>([])
  const [security, setSecurity] = useState<AdminSecurity | null>(null)
  const [activities, setActivities] = useState<AdminActivity[]>([])
  const [selectedUserDetail, setSelectedUserDetail] = useState<Record<string, unknown> | null>(null)
  const [usersPagination, setUsersPagination] = useState<Pagination>(defaultPagination)
  const [rolesPagination, setRolesPagination] = useState<Pagination>({ ...defaultPagination, limit: 10 })
  const [tenantsPagination, setTenantsPagination] = useState<Pagination>({ ...defaultPagination, limit: 10 })
  const [subscriptionsPagination, setSubscriptionsPagination] = useState<Pagination>({ ...defaultPagination, limit: 10 })
  const [searchQuery, setSearchQuery] = useState('')
  const [tierFilter, setTierFilter] = useState('all')
  const [roleFilter, setRoleFilter] = useState('all')
  const [tenantFilter, setTenantFilter] = useState('all')
  const [userStatusFilter, setUserStatusFilter] = useState('all')
  const [roleSearch, setRoleSearch] = useState('')
  const [roleTenantFilter, setRoleTenantFilter] = useState('all')
  const [roleTypeFilter, setRoleTypeFilter] = useState('all')
  const [roleStatusFilter, setRoleStatusFilter] = useState('all')
  const [subscriptionSearch, setSubscriptionSearch] = useState('')
  const [subscriptionStatusFilter, setSubscriptionStatusFilter] = useState('all')
  const [subscriptionPlanFilter, setSubscriptionPlanFilter] = useState('all')
  const [subscriptionRegionFilter, setSubscriptionRegionFilter] = useState('all')
  const [tenantSearch, setTenantSearch] = useState('')
  const [tenantStatusFilter, setTenantStatusFilter] = useState('all')
  const [tenantPlanFilter, setTenantPlanFilter] = useState('all')
  const [tenantRegionFilter, setTenantRegionFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [mutating, setMutating] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [sseConnected, setSseConnected] = useState(false)
  const [usersLiveUpdatedAt, setUsersLiveUpdatedAt] = useState<string | null>(null)
  const [rolesLiveUpdatedAt, setRolesLiveUpdatedAt] = useState<string | null>(null)
  const [tenantsLiveUpdatedAt, setTenantsLiveUpdatedAt] = useState<string | null>(null)
  const [subscriptionsLiveUpdatedAt, setSubscriptionsLiveUpdatedAt] = useState<string | null>(null)
  const [securityLiveUpdatedAt, setSecurityLiveUpdatedAt] = useState<string | null>(null)
  const [lastActionLink, setLastActionLink] = useState<string | null>(null)
  const streamRef = useRef<EventSource | null>(null)
  const liveUsersRefreshRef = useRef<() => void>(() => undefined)
  const liveRolesRefreshRef = useRef<() => void>(() => undefined)
  const liveTenantsRefreshRef = useRef<() => void>(() => undefined)
  const liveSubscriptionsRefreshRef = useRef<() => void>(() => undefined)
  const liveSecurityRefreshRef = useRef<() => void>(() => undefined)

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
      throw new Error(json?.error?.message || json?.message || 'Admin request failed')
    }
    return json.data as T
  }, [authHeaders, token])

  const refreshStats = useCallback(async () => {
    const data = await apiFetch<AdminStats>('/api/v1/admin/stats')
    setStats(data)
  }, [apiFetch])

  const refreshUsers = useCallback(async (page = usersPagination.page) => {
    const params = new URLSearchParams({
      page: String(page),
      limit: String(usersPagination.limit),
      search: searchQuery,
      tier: tierFilter,
      role: roleFilter,
      tenantId: tenantFilter,
      status: userStatusFilter,
      sort: 'created_at',
      order: 'desc',
    })
    const data = await apiFetch<UsersPayload>(`/api/v1/admin/users?${params}`)
    setUsers(data.users)
    setUsersPagination(data.pagination)
    setUsersLiveUpdatedAt(new Date().toISOString())
  }, [apiFetch, roleFilter, searchQuery, tenantFilter, tierFilter, userStatusFilter, usersPagination.limit, usersPagination.page])

  const refreshRoles = useCallback(async (page = rolesPagination.page) => {
    const params = new URLSearchParams({
      page: String(page),
      limit: String(rolesPagination.limit),
      search: roleSearch,
      tenantId: roleTenantFilter,
      type: roleTypeFilter,
      status: roleStatusFilter,
      sort: 'name',
      order: 'asc',
    })
    const data = await apiFetch<RolesPayload>(`/api/v1/admin/roles?${params}`)
    setRoles(data.roles)
    setRoleStats(data.stats)
    setRolesPagination(data.pagination)
    setRolesLiveUpdatedAt(data.generatedAt || new Date().toISOString())
  }, [apiFetch, roleSearch, roleStatusFilter, roleTenantFilter, roleTypeFilter, rolesPagination.limit, rolesPagination.page])

  const refreshTenants = useCallback(async (page = tenantsPagination.page) => {
    const params = new URLSearchParams({
      page: String(page),
      limit: String(tenantsPagination.limit),
      search: tenantSearch,
      status: tenantStatusFilter,
      plan: tenantPlanFilter,
      region: tenantRegionFilter,
    })
    const data = await apiFetch<TenantsPayload>(`/api/v1/admin/tenants?${params}`)
    setTenants(data.tenants)
    if (data.stats) setTenantStats(data.stats)
    setTenantsPagination(data.pagination)
    setTenantsLiveUpdatedAt(data.generatedAt || new Date().toISOString())
  }, [apiFetch, tenantPlanFilter, tenantRegionFilter, tenantSearch, tenantStatusFilter, tenantsPagination.limit, tenantsPagination.page])

  const refreshSubscriptions = useCallback(async (page = subscriptionsPagination.page) => {
    const params = new URLSearchParams({
      page: String(page),
      limit: String(subscriptionsPagination.limit),
      search: subscriptionSearch,
      status: subscriptionStatusFilter,
      plan: subscriptionPlanFilter,
      region: subscriptionRegionFilter,
    })
    const data = await apiFetch<SubscriptionsPayload>(`/api/v1/admin/subscriptions?${params}`)
    setSubscriptions(data.subscriptions)
    if (data.stats) setSubscriptionStats(data.stats)
    if (data.summary) setBillingSummary(data.summary)
    if (data.upcomingInvoices) setUpcomingInvoices(data.upcomingInvoices)
    if (data.paymentMethods) setPaymentMethods(data.paymentMethods)
    setSubscriptionsPagination(data.pagination)
    setSubscriptionsLiveUpdatedAt(data.generatedAt || new Date().toISOString())
  }, [apiFetch, subscriptionPlanFilter, subscriptionRegionFilter, subscriptionSearch, subscriptionStatusFilter, subscriptionsPagination.limit, subscriptionsPagination.page])

  const refreshSecurity = useCallback(async () => {
    const data = await apiFetch<AdminSecurity>('/api/v1/admin/security')
    setSecurity(data)
    setSecurityLiveUpdatedAt(data.generatedAt || new Date().toISOString())
  }, [apiFetch])

  const refreshActivities = useCallback(async () => {
    const data = await apiFetch<{ activities: AdminActivity[] }>('/api/v1/admin/activities?limit=80')
    setActivities(data.activities)
  }, [apiFetch])

  const refreshAll = useCallback(async () => {
    if (!token) return
    setError(null)
    setLoading(true)
    try {
      await Promise.all([
        refreshStats(),
        refreshUsers(1),
        refreshRoles(1),
        refreshTenants(1),
        refreshSubscriptions(1),
        refreshSecurity(),
        refreshActivities(),
      ])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load admin dashboard')
    } finally {
      setLoading(false)
    }
  }, [refreshActivities, refreshRoles, refreshSecurity, refreshStats, refreshSubscriptions, refreshTenants, refreshUsers, token])

  useEffect(() => {
    void refreshAll()
  }, [refreshAll])

  useEffect(() => {
    liveUsersRefreshRef.current = () => {
      void Promise.all([
        refreshUsers(usersPagination.page),
        refreshSecurity(),
        refreshActivities(),
      ]).catch((err) => setError(err instanceof Error ? err.message : 'Unable to refresh live admin users'))
    }
    liveRolesRefreshRef.current = () => {
      void Promise.all([
        refreshRoles(rolesPagination.page),
        refreshActivities(),
      ]).catch((err) => setError(err instanceof Error ? err.message : 'Unable to refresh live admin roles'))
    }
    liveTenantsRefreshRef.current = () => {
      void Promise.all([
        refreshTenants(tenantsPagination.page),
        refreshActivities(),
      ]).catch((err) => setError(err instanceof Error ? err.message : 'Unable to refresh live admin tenants'))
    }
    liveSubscriptionsRefreshRef.current = () => {
      void Promise.all([
        refreshSubscriptions(subscriptionsPagination.page),
        refreshActivities(),
      ]).catch((err) => setError(err instanceof Error ? err.message : 'Unable to refresh live admin billing'))
    }
    liveSecurityRefreshRef.current = () => {
      void Promise.all([
        refreshSecurity(),
        refreshActivities(),
      ]).catch((err) => setError(err instanceof Error ? err.message : 'Unable to refresh live admin security'))
    }
  }, [refreshActivities, refreshRoles, refreshSecurity, refreshSubscriptions, refreshTenants, refreshUsers, rolesPagination.page, subscriptionsPagination.page, tenantsPagination.page, usersPagination.page])

  useEffect(() => {
    if (!token) return
    streamRef.current?.close()
    const stream = new EventSource(`/api/v1/admin/stream?token=${encodeURIComponent(token)}`)
    streamRef.current = stream

    stream.addEventListener('admin-connected', () => setSseConnected(true))
    stream.addEventListener('admin-stats', (event) => {
      try {
        setStats(JSON.parse((event as MessageEvent).data) as AdminStats)
        setSseConnected(true)
        liveUsersRefreshRef.current()
      } catch {
        setError('Unable to parse admin telemetry stream')
      }
    })
    stream.addEventListener('admin-roles', (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as RolesPayload
        setRoleStats(data.stats)
        setRolesLiveUpdatedAt(data.generatedAt || new Date().toISOString())
        setSseConnected(true)
        liveRolesRefreshRef.current()
      } catch {
        setError('Unable to parse admin role telemetry stream')
      }
    })
    stream.addEventListener('admin-tenants', (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as TenantsPayload
        if (data.stats) setTenantStats(data.stats)
        setTenantsLiveUpdatedAt(data.generatedAt || new Date().toISOString())
        setSseConnected(true)
        liveTenantsRefreshRef.current()
      } catch {
        setError('Unable to parse admin tenant telemetry stream')
      }
    })
    stream.addEventListener('admin-subscriptions', (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as SubscriptionsPayload
        if (data.stats) setSubscriptionStats(data.stats)
        if (data.summary) setBillingSummary(data.summary)
        if (data.upcomingInvoices) setUpcomingInvoices(data.upcomingInvoices)
        if (data.paymentMethods) setPaymentMethods(data.paymentMethods)
        setSubscriptionsLiveUpdatedAt(data.generatedAt || new Date().toISOString())
        setSseConnected(true)
        liveSubscriptionsRefreshRef.current()
      } catch {
        setError('Unable to parse admin billing telemetry stream')
      }
    })
    stream.addEventListener('admin-security', (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data) as AdminSecurity
        setSecurity(data)
        setSecurityLiveUpdatedAt(data.generatedAt || new Date().toISOString())
        setSseConnected(true)
        liveSecurityRefreshRef.current()
      } catch {
        setError('Unable to parse admin security telemetry stream')
      }
    })
    stream.addEventListener('admin-error', (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data)
        setError(data.message || 'Admin stream reported an error')
      } catch {
        setError('Admin stream reported an error')
      }
    })
    stream.onerror = () => setSseConnected(false)

    return () => {
      stream.close()
      if (streamRef.current === stream) streamRef.current = null
    }
  }, [token])

  const runMutation = useCallback(async <T,>(label: string, operation: () => Promise<T>, refresh: () => Promise<unknown> = refreshAll) => {
    setMutating(label)
    setError(null)
    try {
      const result = await operation()
      await refresh()
      if (refresh !== refreshAll) {
        await refreshActivities()
      }
      return result
    } catch (err) {
      setError(err instanceof Error ? err.message : `${label} failed`)
      return undefined
    } finally {
      setMutating(null)
    }
  }, [refreshActivities, refreshAll])

  const createUser = useCallback((payload: Record<string, unknown>) => runMutation('create-user', () =>
    apiFetch('/api/v1/admin/users', { method: 'POST', body: JSON.stringify(payload) })
  ), [apiFetch, runMutation])

  const inspectUser = useCallback(async (userId: string) => {
    setMutating(`inspect-${userId}`)
    try {
      const data = await apiFetch<Record<string, unknown>>(`/api/v1/admin/users/${userId}`)
      setSelectedUserDetail(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to inspect user')
    } finally {
      setMutating(null)
    }
  }, [apiFetch])

  const updateUser = useCallback((userId: string, payload: Record<string, unknown>) => runMutation(`update-${userId}`, () =>
    apiFetch(`/api/v1/admin/users/${userId}`, { method: 'PATCH', body: JSON.stringify(payload) }), () => refreshUsers()
  ), [apiFetch, refreshUsers, runMutation])

  const deleteUser = useCallback((userId: string) => runMutation(`delete-${userId}`, () =>
    apiFetch(`/api/v1/admin/users/${userId}`, { method: 'DELETE' }), () => refreshUsers(1)
  ), [apiFetch, refreshUsers, runMutation])

  const userAction = useCallback(async (userId: string, action: string, payload: Record<string, unknown> = {}) => {
    const result = await runMutation(`${action}-${userId}`, () =>
      apiFetch<{ recoveryLink?: string }>(`/api/v1/admin/users/${userId}/actions`, {
        method: 'POST',
        body: JSON.stringify({ action, ...payload }),
      }), () => refreshUsers()
    )
    if (result?.recoveryLink) setLastActionLink(result.recoveryLink)
    return result
  }, [apiFetch, refreshUsers, runMutation])

  const manageUserSubscription = useCallback((userId: string, payload: Record<string, unknown>) => runMutation(`subscription-${userId}`, () =>
    apiFetch(`/api/v1/admin/users/${userId}/subscription`, { method: 'POST', body: JSON.stringify(payload) }), refreshAll
  ), [apiFetch, refreshAll, runMutation])

  const createRole = useCallback((payload: Record<string, unknown>) => runMutation('create-role', () =>
    apiFetch('/api/v1/admin/roles', { method: 'POST', body: JSON.stringify(payload) }), () => refreshRoles(1)
  ), [apiFetch, refreshRoles, runMutation])

  const updateRole = useCallback((roleId: string, payload: Record<string, unknown>) => runMutation(`role-${roleId}`, () =>
    apiFetch(`/api/v1/admin/roles/${roleId}`, { method: 'PATCH', body: JSON.stringify(payload) }), () => refreshRoles()
  ), [apiFetch, refreshRoles, runMutation])

  const roleAction = useCallback((roleId: string, action: string) => runMutation(`${action}-${roleId}`, () =>
    apiFetch(`/api/v1/admin/roles/${roleId}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }), () => refreshRoles()
  ), [apiFetch, refreshRoles, runMutation])

  const createTenant = useCallback((payload: Record<string, unknown>) => runMutation('create-tenant', () =>
    apiFetch('/api/v1/admin/tenants', { method: 'POST', body: JSON.stringify(payload) }), () => refreshTenants(1)
  ), [apiFetch, refreshTenants, runMutation])

  const updateTenant = useCallback((tenantId: string, payload: Record<string, unknown>) => runMutation(`tenant-${tenantId}`, () =>
    apiFetch(`/api/v1/admin/tenants/${tenantId}`, { method: 'PATCH', body: JSON.stringify(payload) }), () => refreshTenants()
  ), [apiFetch, refreshTenants, runMutation])

  const tenantAction = useCallback((tenantId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(`${action}-${tenantId}`, () =>
    apiFetch(`/api/v1/admin/tenants/${tenantId}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action, ...payload }),
    }), () => refreshTenants()
  ), [apiFetch, refreshTenants, runMutation])

  const subscriptionAction = useCallback((subscriptionId: string, action: string, payload: Record<string, unknown> = {}) => runMutation(`${action}-${subscriptionId}`, () =>
    apiFetch(`/api/v1/admin/subscriptions/${subscriptionId}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action, ...payload }),
    }), refreshAll
  ), [apiFetch, refreshAll, runMutation])

  const savePolicy = useCallback((payload: Record<string, unknown>) => runMutation('save-policy', () =>
    apiFetch('/api/v1/admin/security/policies', { method: 'POST', body: JSON.stringify(payload) }), refreshSecurity
  ), [apiFetch, refreshSecurity, runMutation])

  const generateEvidence = useCallback((payload: Record<string, unknown>) => runMutation('generate-evidence', () =>
    apiFetch('/api/v1/admin/security/evidence', { method: 'POST', body: JSON.stringify(payload) }), refreshSecurity
  ), [apiFetch, refreshSecurity, runMutation])

  const exportReport = useCallback(() => {
    const payload = {
      generatedAt: new Date().toISOString(),
      stats,
      users,
      roles,
      roleStats,
      tenants,
      tenantStats,
      subscriptions,
      subscriptionStats,
      billingSummary,
      upcomingInvoices,
      paymentMethods,
      security,
      activities,
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `qguard-admin-report-${new Date().toISOString().slice(0, 10)}.json`
    link.click()
    URL.revokeObjectURL(url)
  }, [activities, billingSummary, paymentMethods, roleStats, roles, security, stats, subscriptionStats, subscriptions, tenantStats, tenants, upcomingInvoices, users])

  return {
    stats,
    users,
    roles,
    roleStats,
    tenants,
    tenantStats,
    subscriptions,
    subscriptionStats,
    billingSummary,
    upcomingInvoices,
    paymentMethods,
    security,
    activities,
    selectedUserDetail,
    setSelectedUserDetail,
    usersPagination,
    rolesPagination,
    tenantsPagination,
    subscriptionsPagination,
    searchQuery,
    setSearchQuery,
    tierFilter,
    setTierFilter,
    roleFilter,
    setRoleFilter,
    tenantFilter,
    setTenantFilter,
    userStatusFilter,
    setUserStatusFilter,
    roleSearch,
    setRoleSearch,
    roleTenantFilter,
    setRoleTenantFilter,
    roleTypeFilter,
    setRoleTypeFilter,
    roleStatusFilter,
    setRoleStatusFilter,
    tenantSearch,
    setTenantSearch,
    tenantStatusFilter,
    setTenantStatusFilter,
    tenantPlanFilter,
    setTenantPlanFilter,
    tenantRegionFilter,
    setTenantRegionFilter,
    subscriptionSearch,
    setSubscriptionSearch,
    subscriptionStatusFilter,
    setSubscriptionStatusFilter,
    subscriptionPlanFilter,
    setSubscriptionPlanFilter,
    subscriptionRegionFilter,
    setSubscriptionRegionFilter,
    loading,
    mutating,
    error,
    setError,
    sseConnected,
    usersLiveUpdatedAt,
    rolesLiveUpdatedAt,
    tenantsLiveUpdatedAt,
    subscriptionsLiveUpdatedAt,
    securityLiveUpdatedAt,
    lastActionLink,
    setLastActionLink,
    refreshAll,
    refreshUsers,
    refreshRoles,
    refreshTenants,
    refreshSubscriptions,
    createUser,
    inspectUser,
    updateUser,
    deleteUser,
    userAction,
    manageUserSubscription,
    createRole,
    updateRole,
    roleAction,
    createTenant,
    updateTenant,
    tenantAction,
    subscriptionAction,
    savePolicy,
    generateEvidence,
    exportReport,
  }
}
