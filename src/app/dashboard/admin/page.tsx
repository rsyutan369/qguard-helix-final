import { type FormEvent, type ReactNode, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bell,
  Building2,
  Bug,
  Calendar,
  CheckCircle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Crown,
  Download,
  FileCheck,
  Filter,
  HelpCircle,
  Lock,
  LockKeyhole,
  MoreVertical,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  UserCog,
  UserPlus,
  UserRound,
  UserX,
  Users,
  Wifi,
  WifiOff,
  CreditCard,
  Upload,
} from 'lucide-react'
import { AdminRoute } from '@/components/admin-route'
import {
  AdminStats,
  AdminRole,
  AdminRoleStats,
  AdminBillingStats,
  AdminBillingSummary,
  AdminPaymentMethod,
  AdminSubscription,
  AdminTenant,
  AdminTenantStats,
  AdminUpcomingInvoice,
  AdminUser,
  AdminActivity,
  useAdminDashboard,
} from '@/hooks/use-admin-dashboard'

type AdminTab = 'overview' | 'users' | 'roles' | 'tenants' | 'subscriptions' | 'security' | 'governance' | 'history'

const tabs: Array<{ id: AdminTab; label: string; icon: typeof Activity }> = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'roles', label: 'Roles', icon: Shield },
  { id: 'tenants', label: 'Tenants', icon: Building2 },
  { id: 'subscriptions', label: 'Plans & Billing', icon: CreditCard },
  { id: 'security', label: 'Security', icon: ShieldAlert },
  { id: 'governance', label: 'Governance', icon: ShieldCheck },
  { id: 'history', label: 'History', icon: Radio },
]

function formatNumber(value?: number) {
  return new Intl.NumberFormat('en-US').format(Number(value || 0))
}

function formatCurrency(value?: number) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(Number(value || 0) / 100)
}

function formatDate(value?: string | null) {
  if (!value) return 'Not recorded'
  return new Date(value).toLocaleString()
}

function normalizeText(value?: string | null) {
  return value ? value.replace(/_/g, ' ') : 'none'
}

function StatusBadge({ value }: { value?: string | null }) {
  const normalized = String(value || 'none').toLowerCase()
  const tone = normalized.includes('active') || normalized.includes('approved') || normalized.includes('complete')
    ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200'
    : normalized.includes('critical') || normalized.includes('failed') || normalized.includes('disabled') || normalized.includes('canceled')
      ? 'border-red-400/30 bg-red-500/10 text-red-200'
      : 'border-[var(--qg-border)] bg-white/[0.04] text-[var(--qg-text-secondary)]'

  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.08em] ${tone}`}>
      {normalizeText(value)}
    </span>
  )
}

function KpiCard({ icon: Icon, label, value, sub }: { icon: typeof Activity; label: string; value: string; sub?: string }) {
  return (
    <div className="q-card p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--qg-border)] bg-white/[0.04] text-[var(--color-gold)]">
          <Icon className="h-5 w-5" />
        </div>
        <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--qg-text-muted)]">Live</span>
      </div>
      <div className="font-mono text-2xl font-black text-[var(--qg-text-primary)]">{value}</div>
      <div className="mt-1 text-xs font-bold uppercase tracking-[0.12em] text-[var(--qg-text-secondary)]">{label}</div>
      {sub && <div className="mt-3 text-xs text-[var(--qg-text-muted)]">{sub}</div>}
    </div>
  )
}

function MiniBars({ data, label }: { data?: Array<{ label: string; count: number }>; label: string }) {
  const rows = data || []
  const max = Math.max(1, ...rows.map((row) => row.count))
  return (
    <div className="q-card p-5">
      <div className="mb-4 flex items-center justify-between gap-4">
        <h3 className="text-sm font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{label}</h3>
        <LineLabel value={`${rows.length} points`} />
      </div>
      <div className="space-y-3">
        {rows.length === 0 ? (
          <EmptyState label="No live records yet" />
        ) : rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[84px_1fr_42px] items-center gap-3 text-xs">
            <span className="truncate text-[var(--qg-text-muted)]">{row.label}</span>
            <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full bg-gradient-to-r from-[var(--color-gold)] to-white" style={{ width: `${Math.max(5, (row.count / max) * 100)}%` }} />
            </div>
            <span className="text-right font-mono text-[var(--qg-text-primary)]">{row.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function LineLabel({ value }: { value: string }) {
  return <span className="rounded-full border border-[var(--qg-border)] px-2.5 py-1 font-mono text-[10px] text-[var(--qg-text-muted)]">{value}</span>
}

function EmptyState({ label }: { label: string }) {
  return <div className="rounded-lg border border-dashed border-[var(--qg-border)] p-4 text-center text-xs text-[var(--qg-text-muted)]">{label}</div>
}

function PaginationControls({ page, totalPages, onPage }: { page: number; totalPages: number; onPage: (page: number) => void }) {
  return (
    <div className="flex items-center justify-end gap-2">
      <button type="button" className="q-btn q-btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft className="h-4 w-4" />
        Previous
      </button>
      <span className="font-mono text-xs text-[var(--qg-text-muted)]">Page {page} of {Math.max(1, totalPages)}</span>
      <button type="button" className="q-btn q-btn-ghost" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
        Next
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  )
}

function AdminDashboardContent() {
  const admin = useAdminDashboard()
  const [activeTab, setActiveTab] = useState<AdminTab>('overview')
  const [newUser, setNewUser] = useState({ email: '', password: '', name: '', role: 'user', tier: 'free', tenantId: '', mfaRequired: false })
  const [newRole, setNewRole] = useState({ name: '', description: '', permissionScope: 'Security', permissionCount: 24, tenantId: '', status: 'active' })
  const [newTenant, setNewTenant] = useState({ name: '', slug: '', plan: 'free', quotaUsers: 5, quotaStorageGb: 5 })
  const [policy, setPolicy] = useState({ policyKey: 'owner-mfa-enforcement', name: 'Owner MFA Enforcement', category: 'access', status: 'enabled', enforcementLevel: 'enforce', description: 'Require MFA for privileged administration and high-risk tenant changes.' })
  const kpis = admin.stats?.kpis || {}

  const visibleTablesMissing = useMemo(() => {
    const missing = new Set<string>()
    admin.stats?.realtime?.unavailableTables?.forEach((table) => missing.add(table))
    admin.security?.unavailableTables?.forEach((table) => missing.add(table))
    return Array.from(missing).slice(0, 6)
  }, [admin.security?.unavailableTables, admin.stats?.realtime?.unavailableTables])

  const handleCreateUser = async (event: FormEvent) => {
    event.preventDefault()
    const result = await admin.createUser({ ...newUser, email: newUser.email.trim(), tenantId: newUser.tenantId || null })
    if (result) setNewUser({ email: '', password: '', name: '', role: 'user', tier: 'free', tenantId: '', mfaRequired: false })
  }

  const handleCreateTenant = async (event: FormEvent) => {
    event.preventDefault()
    const tenantName = newTenant.name.trim()
    if (!tenantName) {
      admin.setError('Tenant name is required')
      setActiveTab('tenants')
      return
    }

    const result = await admin.createTenant({
      ...newTenant,
      name: tenantName,
      slug: newTenant.slug.trim(),
      quotaUsers: Math.max(1, Number(newTenant.quotaUsers) || 1),
      quotaStorageGb: Math.max(1, Number(newTenant.quotaStorageGb) || 1),
    })
    if (result) setNewTenant({ name: '', slug: '', plan: 'free', quotaUsers: 5, quotaStorageGb: 5 })
  }

  const handleCreateRole = async (event: FormEvent) => {
    event.preventDefault()
    const roleName = newRole.name.trim()
    if (!roleName) {
      admin.setError('Role name is required')
      setActiveTab('roles')
      return
    }

    const result = await admin.createRole({
      ...newRole,
      name: roleName,
      description: newRole.description.trim(),
      tenantId: newRole.tenantId || null,
      permissionCount: Math.max(0, Number(newRole.permissionCount) || 0),
    })
    if (result) setNewRole({ name: '', description: '', permissionScope: 'Security', permissionCount: 24, tenantId: '', status: 'active' })
  }

  return (
    <section className="dashboard-gold min-h-full px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1560px] space-y-6">
        <header className="q-card p-6">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-[var(--qg-border)] bg-white/[0.04] px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--color-gold)]">
                <Crown className="h-3.5 w-3.5" />
                Owner Administrator
              </div>
              <h1 className="text-3xl font-black tracking-normal text-[var(--qg-text-primary)]">QGuardHelix Platform Administration</h1>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-[var(--qg-text-secondary)]">
                Centralized owner-only controls for users, tenants, subscriptions, security operations, governance, audit evidence, and live platform telemetry.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-xs font-bold ${admin.sseConnected ? 'border-emerald-400/30 text-emerald-200' : 'border-red-400/30 text-red-200'}`}>
                {admin.sseConnected ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
                {admin.sseConnected ? 'SSE Live' : 'SSE Reconnecting'}
              </span>
              <button type="button" className="q-btn q-btn-ghost" onClick={() => void admin.refreshAll()} disabled={admin.loading || !!admin.mutating}>
                <RefreshCw className={`h-4 w-4 ${admin.loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button type="button" className="q-btn q-btn-primary" onClick={admin.exportReport}>
                <Download className="h-4 w-4" />
                Export Report
              </button>
            </div>
          </div>
        </header>

        {admin.error && (
          <div className="rounded-lg border border-red-400/30 bg-red-500/10 p-4 text-sm text-red-100">
            {admin.error}
          </div>
        )}

        {admin.lastActionLink && (
          <div className="rounded-lg border border-[var(--qg-border)] bg-white/[0.04] p-4 text-sm text-[var(--qg-text-secondary)]">
            Password recovery link generated:
            <a className="ml-2 break-all text-[var(--color-gold)]" href={admin.lastActionLink}>{admin.lastActionLink}</a>
            <button type="button" className="q-btn q-btn-ghost ml-3" onClick={() => admin.setLastActionLink(null)}>Dismiss</button>
          </div>
        )}

        {visibleTablesMissing.length > 0 && (
          <div className="rounded-lg border border-amber-400/30 bg-amber-500/10 p-4 text-xs text-amber-100">
            Some Supabase tables are not available yet: {visibleTablesMissing.join(', ')}. Apply the admin schema migration to unlock the full operational view.
          </div>
        )}

        <nav className="adm-tabs flex flex-wrap gap-2 p-1">
          {tabs.map((tab) => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button key={tab.id} type="button" className={`q-btn ${isActive ? 'q-btn-primary' : 'q-btn-ghost'}`} onClick={() => setActiveTab(tab.id)}>
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>

        {admin.loading && !admin.stats ? (
          <div className="q-card p-8 text-center text-sm text-[var(--qg-text-secondary)]">Loading owner telemetry from Supabase...</div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                  <KpiCard icon={Users} label="Total Users" value={formatNumber(kpis.totalUsers)} sub={`${formatNumber(kpis.activeSessions)} active sessions`} />
                  <KpiCard icon={Building2} label="Active Tenants" value={formatNumber(kpis.activeTenants)} sub={`${formatNumber(kpis.totalTenants)} total organizations`} />
                  <KpiCard icon={CreditCard} label="Subscription Revenue" value={formatCurrency(kpis.subscriptionRevenue)} sub={`${formatNumber(kpis.activeSubscriptions)} active subscriptions`} />
                  <KpiCard icon={ShieldCheck} label="PQC Readiness" value={`${formatNumber(kpis.pqcReadinessScore)}%`} sub={`${formatNumber(kpis.migrationProgress)}% migration progress`} />
                  <KpiCard icon={AlertTriangle} label="Security Alerts" value={formatNumber(kpis.criticalAlerts)} sub={`${formatNumber(kpis.failedLogins)} failed login signals`} />
                </div>
                <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
                  <MiniBars label="User Growth" data={admin.stats?.charts?.userGrowth} />
                  <MiniBars label="Tenant Activity Heatmap" data={admin.stats?.charts?.tenantActivity} />
                  <MiniBars label="Vulnerability Trend" data={admin.stats?.charts?.vulnerabilityTrend} />
                  <MiniBars label="Subscription Changes" data={admin.stats?.charts?.subscriptionChanges} />
                </div>
                <div className="grid gap-4 lg:grid-cols-3">
                  <SummaryCard title="Subscription Mix" rows={admin.stats?.summaries?.subscriptionStatus} />
                  <SummaryCard title="Scan Status" rows={admin.stats?.summaries?.scanStatus} />
                  <SummaryCard title="Compliance Status" rows={admin.stats?.summaries?.complianceStatus} />
                </div>
              </div>
            )}

            {activeTab === 'users' && (
              <UsersTab
                stats={admin.stats}
                users={admin.users}
                tenants={admin.tenants}
                pagination={admin.usersPagination}
                searchQuery={admin.searchQuery}
                roleFilter={admin.roleFilter}
                tenantFilter={admin.tenantFilter}
                subscriptionFilter={admin.tierFilter}
                userStatusFilter={admin.userStatusFilter}
                setSearchQuery={admin.setSearchQuery}
                setRoleFilter={admin.setRoleFilter}
                setTenantFilter={admin.setTenantFilter}
                setSubscriptionFilter={admin.setTierFilter}
                setUserStatusFilter={admin.setUserStatusFilter}
                refreshUsers={admin.refreshUsers}
                newUser={newUser}
                setNewUser={setNewUser}
                onCreateUser={handleCreateUser}
                inspectUser={admin.inspectUser}
                updateUser={admin.updateUser}
                deleteUser={admin.deleteUser}
                userAction={admin.userAction}
                manageUserSubscription={admin.manageUserSubscription}
                selectedUserDetail={admin.selectedUserDetail}
                closeDetail={() => admin.setSelectedUserDetail(null)}
                mutating={admin.mutating}
                sseConnected={admin.sseConnected}
                usersLiveUpdatedAt={admin.usersLiveUpdatedAt}
              />
            )}

            {activeTab === 'roles' && (
              <RolesTab
                roles={admin.roles}
                stats={admin.roleStats}
                tenants={admin.tenants}
                pagination={admin.rolesPagination}
                search={admin.roleSearch}
                tenantFilter={admin.roleTenantFilter}
                typeFilter={admin.roleTypeFilter}
                statusFilter={admin.roleStatusFilter}
                setSearch={admin.setRoleSearch}
                setTenantFilter={admin.setRoleTenantFilter}
                setTypeFilter={admin.setRoleTypeFilter}
                setStatusFilter={admin.setRoleStatusFilter}
                refreshRoles={admin.refreshRoles}
                newRole={newRole}
                setNewRole={setNewRole}
                onCreateRole={handleCreateRole}
                updateRole={admin.updateRole}
                roleAction={admin.roleAction}
                mutating={admin.mutating}
                sseConnected={admin.sseConnected}
                rolesLiveUpdatedAt={admin.rolesLiveUpdatedAt}
              />
            )}

            {activeTab === 'tenants' && (
              <TenantsTab
                tenants={admin.tenants}
                stats={admin.tenantStats}
                pagination={admin.tenantsPagination}
                tenantSearch={admin.tenantSearch}
                setTenantSearch={admin.setTenantSearch}
                statusFilter={admin.tenantStatusFilter}
                setStatusFilter={admin.setTenantStatusFilter}
                planFilter={admin.tenantPlanFilter}
                setPlanFilter={admin.setTenantPlanFilter}
                regionFilter={admin.tenantRegionFilter}
                setRegionFilter={admin.setTenantRegionFilter}
                refreshTenants={admin.refreshTenants}
                newTenant={newTenant}
                setNewTenant={setNewTenant}
                onCreateTenant={handleCreateTenant}
                updateTenant={admin.updateTenant}
                tenantAction={admin.tenantAction}
                mutating={admin.mutating}
                sseConnected={admin.sseConnected}
                tenantsLiveUpdatedAt={admin.tenantsLiveUpdatedAt}
              />
            )}

            {activeTab === 'subscriptions' && (
              <SubscriptionsTab
                subscriptions={admin.subscriptions}
                stats={admin.subscriptionStats}
                summary={admin.billingSummary}
                upcomingInvoices={admin.upcomingInvoices}
                paymentMethods={admin.paymentMethods}
                pagination={admin.subscriptionsPagination}
                search={admin.subscriptionSearch}
                setSearch={admin.setSubscriptionSearch}
                statusFilter={admin.subscriptionStatusFilter}
                setStatusFilter={admin.setSubscriptionStatusFilter}
                planFilter={admin.subscriptionPlanFilter}
                setPlanFilter={admin.setSubscriptionPlanFilter}
                regionFilter={admin.subscriptionRegionFilter}
                setRegionFilter={admin.setSubscriptionRegionFilter}
                refreshSubscriptions={admin.refreshSubscriptions}
                subscriptionAction={admin.subscriptionAction}
                sseConnected={admin.sseConnected}
                subscriptionsLiveUpdatedAt={admin.subscriptionsLiveUpdatedAt}
                exportReport={admin.exportReport}
                mutating={admin.mutating}
              />
            )}

            {activeTab === 'security' && (
              <SecurityTab
                security={admin.security}
                savePolicy={admin.savePolicy}
                policy={policy}
                setPolicy={setPolicy}
                refreshSecurity={admin.refreshSecurity}
                sseConnected={admin.sseConnected}
                securityLiveUpdatedAt={admin.securityLiveUpdatedAt}
              />
            )}

            {activeTab === 'governance' && (
              <GovernanceTab security={admin.security} generateEvidence={admin.generateEvidence} stats={admin.stats} />
            )}

            {activeTab === 'history' && (
              <HistoryTab activities={admin.activities} exportReport={admin.exportReport} />
            )}
          </>
        )}
      </div>
    </section>
  )
}

function SummaryCard({ title, rows }: { title: string; rows?: Array<{ label: string; count: number }> }) {
  const total = Math.max(1, ...(rows || []).map((row) => row.count))
  return (
    <div className="q-card p-5">
      <h3 className="mb-4 text-sm font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{title}</h3>
      <div className="space-y-3">
        {!rows?.length ? <EmptyState label="No records found" /> : rows.map((row) => (
          <div key={row.label} className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="capitalize text-[var(--qg-text-secondary)]">{normalizeText(row.label)}</span>
              <span className="font-mono text-[var(--qg-text-primary)]">{row.count}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full bg-[var(--color-gold)]" style={{ width: `${Math.max(4, (row.count / total) * 100)}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function compactRole(value: string) {
  const normalized = value.replace(/_/g, ' ').trim()
  if (/owner|ceo|super/i.test(normalized)) return 'CEO'
  if (/security/i.test(normalized)) return 'Security Admin'
  if (/tenant/i.test(normalized)) return 'Tenant Admin'
  if (/admin/i.test(normalized)) return 'Admin'
  if (/auditor/i.test(normalized)) return 'Auditor'
  return normalized || 'User'
}

function userInitials(user: AdminUser) {
  const source = user.name || user.email || 'User'
  const parts = source.split(/[.\s@_-]+/).filter(Boolean)
  return (parts.slice(0, 2).map((part) => part[0]).join('') || 'U').toUpperCase()
}

function userDisplayId(user: AdminUser) {
  return `USR_${user.id.replace(/-/g, '').slice(0, 7)}`
}

function userRoleTone(role: string) {
  const label = compactRole(role).toLowerCase()
  if (label.includes('security')) return 'border-red-400/30 bg-red-500/10 text-red-300'
  if (label.includes('admin') || label.includes('ceo')) return 'border-violet-400/30 bg-violet-500/15 text-violet-200'
  if (label.includes('auditor')) return 'border-cyan-400/30 bg-cyan-500/10 text-cyan-200'
  return 'border-blue-400/30 bg-blue-500/10 text-blue-200'
}

function planTone(plan: string) {
  const normalized = plan.toLowerCase()
  if (normalized.includes('elite')) return 'border-violet-400/30 bg-violet-500/15 text-violet-200'
  if (normalized.includes('pro')) return 'border-blue-400/30 bg-blue-500/15 text-blue-200'
  if (normalized.includes('starter')) return 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200'
  return 'border-slate-500/40 bg-slate-500/10 text-slate-200'
}

function activeTone(status: string) {
  const normalized = status.toLowerCase()
  if (normalized.includes('active') || normalized.includes('approved')) return 'border-emerald-400/25 bg-emerald-500/10 text-emerald-200'
  if (normalized.includes('inactive') || normalized.includes('suspended') || normalized.includes('disabled')) return 'border-amber-400/30 bg-amber-500/10 text-amber-200'
  return 'border-slate-500/40 bg-slate-500/10 text-slate-200'
}

function formatShortDateTime(value?: string | null) {
  if (!value) return { date: 'Not recorded', time: 'No login', ip: 'IP: unknown' }
  const date = new Date(value)
  return {
    date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
    time: date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    ip: 'IP: unknown',
  }
}

function timeAgo(value?: string | null) {
  if (!value) return 'not yet'
  const diff = Math.max(0, Date.now() - new Date(value).getTime())
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hr ago`
  return `${Math.floor(hours / 24)} days ago`
}

function percentLabel(value: number, total: number) {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return '0%'
  return `${Math.max(0, Math.min(100, Math.round((value / total) * 100)))}%`
}

function EnterpriseUserKpi({ icon: Icon, label, value, sub, tone }: {
  icon: typeof Activity
  label: string
  value: string
  sub: string
  tone: 'blue' | 'emerald' | 'violet' | 'amber'
}) {
  const tones = {
    blue: 'from-blue-500/25 text-blue-300 shadow-blue-500/20',
    emerald: 'from-emerald-500/25 text-emerald-300 shadow-emerald-500/20',
    violet: 'from-violet-500/25 text-violet-300 shadow-violet-500/20',
    amber: 'from-amber-500/25 text-amber-300 shadow-amber-500/20',
  }

  return (
    <div className="rounded-lg border border-[#153056] bg-[linear-gradient(135deg,rgba(11,32,74,0.92),rgba(4,14,34,0.98))] p-5 shadow-[0_18px_48px_rgba(0,0,0,0.25)]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-bold text-slate-300">{label}</div>
          <div className="mt-2 font-mono text-3xl font-black leading-none text-white">{value}</div>
          <div className="mt-3 text-xs font-semibold text-slate-400">{sub}</div>
        </div>
        <div className={`flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br ${tones[tone]} shadow-lg`}>
          <Icon className="h-7 w-7" />
        </div>
      </div>
    </div>
  )
}

function EnterpriseSelect({ value, onChange, children, label }: {
  value: string
  onChange: (value: string) => void
  children: ReactNode
  label: string
}) {
  return (
    <label className="relative min-w-[138px] flex-1 xl:flex-none">
      <span className="sr-only">{label}</span>
      <select
        className="h-11 w-full appearance-none rounded-lg border border-[#17335d] bg-[#07162d] px-4 pr-9 text-sm font-bold text-slate-200 outline-none transition focus:border-blue-400"
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
    </label>
  )
}

function UserRoleBadge({ role, tenantRole }: { role: string; tenantRole?: string | null }) {
  return (
    <div className="space-y-2">
      <span className={`inline-flex rounded-md border px-3 py-1.5 text-xs font-black uppercase ${userRoleTone(role)}`}>
        {compactRole(role)}
      </span>
      <div className="flex items-center gap-1.5 text-xs text-slate-400">
        <Shield className="h-3 w-3 text-violet-400" />
        {tenantRole ? compactRole(tenantRole) : 'Unassigned'}
      </div>
    </div>
  )
}

function SubscriptionBadge({ user }: { user: AdminUser }) {
  const plan = user.subscriptionPlan || user.tier || 'free'
  const status = user.subscriptionStatus || 'none'
  return (
    <span className={`inline-flex flex-col rounded-md border px-3 py-2 text-xs font-black uppercase leading-tight ${planTone(plan)}`}>
      <span>{plan.replace(/_/g, ' ')}</span>
      <span className="mt-1 text-[11px] font-semibold normal-case opacity-85">{normalizeText(status)}</span>
    </span>
  )
}

function MfaBadge({ enabled }: { enabled: boolean }) {
  return (
    <div className={`mx-auto flex h-10 w-10 items-center justify-center rounded-full ${enabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-500/15 text-slate-300'}`}>
      <ShieldCheck className="h-5 w-5" />
    </div>
  )
}

function EnterpriseStatus({ status }: { status: string }) {
  const active = /active|approved/i.test(status)
  return (
    <span className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-black ${activeTone(status)}`}>
      <span className={`h-2 w-2 rounded-full ${active ? 'bg-emerald-400' : 'bg-amber-400'}`} />
      {normalizeText(status)}
    </span>
  )
}

function UserActionsMenu(props: {
  user: AdminUser
  inspectUser: (userId: string) => Promise<void>
  deleteUser: (userId: string) => Promise<unknown>
  userAction: (userId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
  manageUserSubscription: (userId: string, payload: Record<string, unknown>) => Promise<unknown>
}) {
  const user = props.user

  return (
    <details className="relative">
      <summary className="flex h-10 w-10 cursor-pointer list-none items-center justify-center rounded-lg border border-[#18335e] bg-[#071831] text-slate-300 transition hover:border-blue-400 hover:text-white [&::-webkit-details-marker]:hidden">
        <MoreVertical className="h-4 w-4" />
      </summary>
      <div className="absolute right-0 z-20 mt-2 w-52 rounded-lg border border-[#18335e] bg-[#061329] p-2 shadow-2xl">
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.inspectUser(user.id)}>Inspect details</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, 'suspend')}>Suspend user</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, 'disable')}>Disable user</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, 'restore')}>Restore user</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, 'reset_password')}>Reset password</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, 'force_logout')}>Force logout</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.userAction(user.id, user.mfaRequired ? 'mfa_disable' : 'mfa_enable')}>{user.mfaRequired ? 'Relax MFA' : 'Require MFA'}</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void props.manageUserSubscription(user.id, { action: 'approve', plan: 'Pro', interval: 'monthly' })}>Approve Pro subscription</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-red-300 hover:bg-red-500/10" onClick={() => window.confirm(`Delete ${user.email}?`) && void props.deleteUser(user.id)}>Delete user</button>
      </div>
    </details>
  )
}

function UsersTab(props: {
  stats: AdminStats | null
  users: AdminUser[]
  tenants: AdminTenant[]
  pagination: { page: number; totalPages: number; total?: number; limit?: number }
  searchQuery: string
  roleFilter: string
  tenantFilter: string
  subscriptionFilter: string
  userStatusFilter: string
  setSearchQuery: (value: string) => void
  setRoleFilter: (value: string) => void
  setTenantFilter: (value: string) => void
  setSubscriptionFilter: (value: string) => void
  setUserStatusFilter: (value: string) => void
  refreshUsers: (page?: number) => Promise<void>
  newUser: { email: string; password: string; name: string; role: string; tier: string; tenantId: string; mfaRequired: boolean }
  setNewUser: (value: { email: string; password: string; name: string; role: string; tier: string; tenantId: string; mfaRequired: boolean }) => void
  onCreateUser: (event: FormEvent) => Promise<void>
  inspectUser: (userId: string) => Promise<void>
  updateUser: (userId: string, payload: Record<string, unknown>) => Promise<unknown>
  deleteUser: (userId: string) => Promise<unknown>
  userAction: (userId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
  manageUserSubscription: (userId: string, payload: Record<string, unknown>) => Promise<unknown>
  selectedUserDetail: Record<string, unknown> | null
  closeDetail: () => void
  mutating: string | null
  sseConnected: boolean
  usersLiveUpdatedAt: string | null
}) {
  const [showCreateUser, setShowCreateUser] = useState(false)
  const selectedUser = props.selectedUserDetail?.user as AdminUser | undefined
  const sessions = (props.selectedUserDetail?.sessions as Array<Record<string, unknown>>) || []
  const devices = (props.selectedUserDetail?.devices as Array<Record<string, unknown>>) || []
  const securityEvents = (props.selectedUserDetail?.securityEvents as Array<Record<string, unknown>>) || []
  const kpis = props.stats?.kpis || {}
  const totalUsers = Number(kpis.totalUsers || props.pagination.total || props.users.length || 0)
  const activeUsers = Number(kpis.activeUsers || 0)
  const administratorUsers = Number(kpis.administratorUsers || props.users.filter((user) => /admin|owner|ceo/i.test(user.role)).length)
  const mfaEnabledUsers = Number(kpis.mfaEnabledUsers || props.users.filter((user) => user.mfaRequired).length)
  const unassignedUsers = Number(kpis.unassignedUsers || props.users.filter((user) => !user.tenantId).length)
  const pageSize = props.pagination.limit || 25
  const pageStart = totalUsers ? ((props.pagination.page - 1) * pageSize) + 1 : 0
  const pageEnd = Math.min(totalUsers, (props.pagination.page - 1) * pageSize + props.users.length)
  const activeFilters = [props.roleFilter, props.tenantFilter, props.subscriptionFilter, props.userStatusFilter].filter((value) => value && value !== 'all').length
  const lastUpdated = props.usersLiveUpdatedAt || props.stats?.timestamp || null

  return (
    <div className="space-y-5 rounded-lg border border-[#0f274d] bg-[#020a18] p-0 text-slate-200 shadow-[0_30px_80px_rgba(0,0,0,0.35)]">
      <div className="border-b border-[#0f274d] px-5 py-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h2 className="text-2xl font-black tracking-normal text-white">Users</h2>
            <p className="mt-1 text-sm text-slate-400">Manage platform users, access, roles, and security settings.</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#132b52] bg-[#061329] px-4 text-sm font-bold text-slate-300 hover:border-blue-400">
              <HelpCircle className="h-4 w-4" />
              Help
            </button>
            <button type="button" className="relative inline-flex h-10 w-10 items-center justify-center rounded-lg border border-[#132b52] bg-[#061329] text-slate-300 hover:border-blue-400">
              <Bell className="h-5 w-5" />
              {Number(kpis.criticalAlerts || 0) > 0 && (
                <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-black text-white">{Math.min(99, Number(kpis.criticalAlerts || 0))}</span>
              )}
            </button>
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-5 text-sm font-black text-white shadow-lg shadow-violet-600/25 hover:bg-violet-500" onClick={() => setShowCreateUser((value) => !value)}>
              <Plus className="h-4 w-4" />
              Add User
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 px-5 md:grid-cols-2 xl:grid-cols-5">
        <EnterpriseUserKpi icon={UserRound} label="Total Users" value={formatNumber(totalUsers)} sub={`${Number(kpis.userGrowthPercent || 0) >= 0 ? '+' : ''}${formatNumber(kpis.userGrowthPercent)}% vs last month`} tone="blue" />
        <EnterpriseUserKpi icon={CheckCircle} label="Active Users" value={formatNumber(activeUsers)} sub={`${percentLabel(activeUsers, totalUsers)} of total users`} tone="emerald" />
        <EnterpriseUserKpi icon={ShieldCheck} label="Administrators" value={formatNumber(administratorUsers)} sub={`${percentLabel(administratorUsers, totalUsers)} of total users`} tone="violet" />
        <EnterpriseUserKpi icon={Lock} label="MFA Enabled" value={formatNumber(mfaEnabledUsers)} sub={`${percentLabel(mfaEnabledUsers, Math.max(1, activeUsers || totalUsers))} of active users`} tone="blue" />
        <EnterpriseUserKpi icon={UserX} label="Unassigned Users" value={formatNumber(unassignedUsers)} sub="Pending role assignment" tone="amber" />
      </div>

      {showCreateUser && (
        <form className="mx-5 grid gap-3 rounded-lg border border-[#17335d] bg-[#061329] p-4 lg:grid-cols-[1.3fr_1fr_1fr_1fr_auto]" onSubmit={props.onCreateUser}>
          <input className="q-input" placeholder="User email" value={props.newUser.email} required onChange={(event) => props.setNewUser({ ...props.newUser, email: event.target.value })} />
          <input className="q-input" placeholder="Full name" value={props.newUser.name} onChange={(event) => props.setNewUser({ ...props.newUser, name: event.target.value })} />
          <input className="q-input" placeholder="Temporary password" type="password" value={props.newUser.password} required onChange={(event) => props.setNewUser({ ...props.newUser, password: event.target.value })} />
          <select className="q-select" value={props.newUser.tier} onChange={(event) => props.setNewUser({ ...props.newUser, tier: event.target.value })}>
            <option value="starter">Starter</option>
            <option value="pro">Pro</option>
            <option value="elite">Elite</option>
          </select>
          <button className="q-btn q-btn-primary" type="submit" disabled={props.mutating === 'create-user'}><UserPlus className="h-4 w-4" />Create</button>
          <select className="q-select lg:col-span-2" value={props.newUser.role} onChange={(event) => props.setNewUser({ ...props.newUser, role: event.target.value })}>
            <option value="user">User</option>
            <option value="tenant_admin">Tenant Admin</option>
            <option value="security_admin">Security Admin</option>
            <option value="auditor">Auditor</option>
          </select>
          <select className="q-select lg:col-span-2" value={props.newUser.tenantId} onChange={(event) => props.setNewUser({ ...props.newUser, tenantId: event.target.value })}>
            <option value="">No tenant assignment</option>
            {props.tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </select>
          <label className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <input type="checkbox" checked={props.newUser.mfaRequired} onChange={(event) => props.setNewUser({ ...props.newUser, mfaRequired: event.target.checked })} />
            Require MFA
          </label>
        </form>
      )}

      <div className="flex flex-col gap-3 px-5 xl:flex-row xl:items-center">
        <div className="relative min-w-[280px] flex-1">
          <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
          <input className="h-11 w-full rounded-lg border border-[#17335d] bg-[#07162d] pl-12 pr-4 text-sm font-semibold text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-blue-400" placeholder="Search users by name, email, or ID..." value={props.searchQuery} onChange={(event) => props.setSearchQuery(event.target.value)} />
        </div>
        <EnterpriseSelect label="Role filter" value={props.roleFilter} onChange={props.setRoleFilter}>
          <option value="all">All Roles</option>
          <option value="user">User</option>
          <option value="tenant_admin">Tenant Admin</option>
          <option value="security_admin">Security Admin</option>
          <option value="admin">Admin</option>
          <option value="auditor">Auditor</option>
          <option value="owner">Owner</option>
        </EnterpriseSelect>
        <EnterpriseSelect label="Tenant filter" value={props.tenantFilter} onChange={props.setTenantFilter}>
          <option value="all">All Tenants</option>
          <option value="unassigned">Unassigned</option>
          {props.tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </EnterpriseSelect>
        <EnterpriseSelect label="Subscription filter" value={props.subscriptionFilter} onChange={props.setSubscriptionFilter}>
          <option value="all">All Subscriptions</option>
          <option value="starter">Starter</option>
          <option value="pro">Pro</option>
          <option value="elite">Elite</option>
        </EnterpriseSelect>
        <EnterpriseSelect label="Status filter" value={props.userStatusFilter} onChange={props.setUserStatusFilter}>
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="suspended">Suspended</option>
          <option value="disabled">Disabled</option>
        </EnterpriseSelect>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400" onClick={() => void props.refreshUsers(1)}>
          <Filter className="h-4 w-4" />
          Filters
          <span className="rounded-full bg-blue-600 px-2 py-0.5 text-xs text-white">{activeFilters}</span>
        </button>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400">
          <Upload className="h-4 w-4" />
          Export
          <ChevronDown className="h-4 w-4" />
        </button>
      </div>

      <div className="mx-5 overflow-x-auto rounded-lg border border-[#12305a]">
        <table className="min-w-[1220px] w-full border-collapse text-left">
          <thead className="bg-[#0b1d3a] text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-4 font-black">User</th>
              <th className="px-4 py-4 font-black">Role</th>
              <th className="px-4 py-4 font-black">Tenant</th>
              <th className="px-4 py-4 font-black">Subscription</th>
              <th className="px-4 py-4 font-black">Sessions</th>
              <th className="px-4 py-4 text-center font-black">MFA</th>
              <th className="px-4 py-4 font-black">Last Sign-In</th>
              <th className="px-4 py-4 font-black">Status</th>
              <th className="px-4 py-4 text-center font-black">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#12305a] bg-[#041227]">
            {props.users.length === 0 ? (
              <tr><td colSpan={9} className="px-4 py-8"><EmptyState label="No users found" /></td></tr>
            ) : props.users.map((user) => {
              const signIn = formatShortDateTime(user.lastSeenAt || user.lastSignInAt)
              const isMutating = props.mutating?.includes(user.id)
              return (
                <tr key={user.id} className="transition hover:bg-[#092044]">
                  <td className="px-4 py-4">
                    <button type="button" className="flex min-w-[210px] items-center gap-3 text-left" onClick={() => void props.inspectUser(user.id)}>
                      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-blue-600 to-violet-700 font-mono text-sm font-black text-white">{userInitials(user)}</span>
                      <span className="min-w-0">
                        <span className="block truncate font-bold text-slate-100">{user.name || user.email.split('@')[0]}</span>
                        <span className="block truncate text-xs text-slate-400">{user.email}</span>
                        <span className="block truncate font-mono text-xs text-slate-400">ID: {userDisplayId(user)}</span>
                      </span>
                    </button>
                  </td>
                  <td className="px-4 py-4"><UserRoleBadge role={user.role} tenantRole={user.tenantRole} /></td>
                  <td className="px-4 py-4 text-sm text-slate-300">
                    <div>{user.tenantName || 'Unassigned'}</div>
                    <div className="text-xs text-slate-500">{user.tenantStatus || user.tenantSlug || 'No tenant'}</div>
                  </td>
                  <td className="px-4 py-4"><SubscriptionBadge user={user} /></td>
                  <td className="px-4 py-4 font-mono text-sm leading-6 text-slate-300">
                    <div>{formatNumber(user.activeSessions)} active</div>
                    <div>{formatNumber(user.idleSessions)} idle</div>
                    <div>{formatNumber(user.deviceCount)} devices</div>
                  </td>
                  <td className="px-4 py-4 text-center"><MfaBadge enabled={user.mfaRequired} /></td>
                  <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                    <div>{signIn.date}</div>
                    <div>{signIn.time}</div>
                    <div className="font-mono text-xs text-slate-500">{user.lastIpAddress ? `IP: ${user.lastIpAddress}` : signIn.ip}</div>
                  </td>
                  <td className="px-4 py-4"><EnterpriseStatus status={user.status} /></td>
                  <td className="px-4 py-4">
                    <div className="flex justify-center opacity-100">
                      {isMutating ? (
                        <RefreshCw className="h-5 w-5 animate-spin text-blue-300" />
                      ) : (
                        <UserActionsMenu user={user} inspectUser={props.inspectUser} deleteUser={props.deleteUser} userAction={props.userAction} manageUserSubscription={props.manageUserSubscription} />
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <div className="flex flex-col gap-3 border-t border-[#12305a] bg-[#041227] px-4 py-3 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
          <span>Showing {formatNumber(pageStart)} to {formatNumber(pageEnd)} of {formatNumber(totalUsers)} users</span>
          <PaginationControls page={props.pagination.page} totalPages={props.pagination.totalPages} onPage={(page) => void props.refreshUsers(page)} />
        </div>
      </div>

      <div className="mx-5 mb-5 flex flex-col gap-3 rounded-lg border border-[#0f274d] bg-[#07162d] px-5 py-3 text-xs font-semibold text-slate-400 md:flex-row md:items-center md:justify-between">
        <span className="inline-flex items-center gap-2"><Activity className="h-4 w-4" />All times shown in UTC</span>
        <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" />Security and audit logs are enabled</span>
        <span className="inline-flex items-center gap-2"><Lock className="h-4 w-4" />Data is encrypted in transit and at rest</span>
        <span className="inline-flex items-center gap-2">Last updated: {timeAgo(lastUpdated)} <RefreshCw className={`h-4 w-4 ${props.sseConnected ? 'text-blue-300' : 'text-amber-300'}`} /></span>
      </div>

      {selectedUser && (
        <div className="mx-5 mb-5 rounded-lg border border-[#17335d] bg-[#061329] p-5">
          <div className="mb-5 flex items-center justify-between gap-4">
            <div>
              <h3 className="text-lg font-black text-white">{selectedUser.email}</h3>
              <p className="text-sm text-slate-400">{selectedUser.name || 'No name'} &middot; {selectedUser.tenantName || 'No tenant'} &middot; {selectedUser.subscriptionStatus}</p>
            </div>
            <button type="button" className="q-btn q-btn-ghost" onClick={props.closeDetail}>Close</button>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <DetailList title="Login History" rows={securityEvents} empty="No recent login events" />
            <DetailList title="Trusted Devices" rows={devices} empty="No trusted devices recorded" />
            <DetailList title="Active Sessions" rows={sessions} empty="No active session records" />
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <select className="q-select" defaultValue={selectedUser.role} onChange={(event) => void props.updateUser(selectedUser.id, { role: event.target.value })}>
              <option value="user">User</option>
              <option value="tenant_admin">Tenant Admin</option>
              <option value="security_admin">Security Admin</option>
              <option value="auditor">Auditor</option>
              <option value="admin">Admin</option>
            </select>
            <select className="q-select" defaultValue={selectedUser.tier} onChange={(event) => void props.updateUser(selectedUser.id, { tier: event.target.value })}>
              <option value="starter">Starter</option>
              <option value="pro">Pro</option>
              <option value="elite">Elite</option>
            </select>
            <button type="button" className="q-btn q-btn-primary" disabled={props.mutating === `inspect-${selectedUser.id}`} onClick={() => void props.inspectUser(selectedUser.id)}>
              <RefreshCw className="h-4 w-4" />
              Refresh Detail
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function roleTypeTone(type: string) {
  return type === 'system'
    ? 'border-violet-400/30 bg-violet-500/15 text-violet-200'
    : 'border-blue-400/30 bg-blue-500/15 text-blue-200'
}

function roleIconTone(role: AdminRole) {
  const key = `${role.roleKey} ${role.permissionScope} ${role.icon}`.toLowerCase()
  if (key.includes('super') || key.includes('crown')) return 'from-violet-600 to-purple-800 text-violet-100'
  if (key.includes('security') || key.includes('shield')) return 'from-blue-600 to-cyan-800 text-blue-100'
  if (key.includes('tenant')) return 'from-cyan-600 to-teal-800 text-cyan-100'
  if (key.includes('compliance')) return 'from-violet-600 to-indigo-800 text-violet-100'
  if (key.includes('read')) return 'from-amber-500 to-yellow-800 text-amber-100'
  if (key.includes('incident')) return 'from-emerald-600 to-green-800 text-emerald-100'
  return 'from-slate-600 to-blue-900 text-slate-100'
}

function RoleIcon({ role }: { role: AdminRole }) {
  const key = `${role.roleKey} ${role.permissionScope} ${role.icon}`.toLowerCase()
  const Icon = key.includes('super') || key.includes('crown')
    ? Crown
    : key.includes('read')
      ? Lock
      : key.includes('tenant')
        ? UserCog
        : key.includes('security') || key.includes('shield')
          ? ShieldCheck
          : key.includes('incident')
            ? Activity
            : Users

  return (
    <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br ${roleIconTone(role)}`}>
      <Icon className="h-5 w-5" />
    </span>
  )
}

function RoleActionsMenu({ role, roleAction }: {
  role: AdminRole
  roleAction: (roleId: string, action: string) => Promise<unknown>
}) {
  const protectedRole = role.protected || role.type === 'system'
  const status = String(role.status || '').toLowerCase()
  const primaryAction = status === 'active' ? 'deactivate' : 'activate'
  const primaryLabel = status === 'active' ? 'Deactivate role' : status === 'archived' ? 'Restore role' : 'Activate role'
  const roleInUse = role.users > 0

  return (
    <details className="relative">
      <summary className="flex h-10 w-10 cursor-pointer list-none items-center justify-center rounded-lg border border-[#18335e] bg-[#071831] text-slate-300 transition hover:border-blue-400 hover:text-white [&::-webkit-details-marker]:hidden">
        <MoreVertical className="h-4 w-4" />
      </summary>
      <div className="absolute right-0 z-20 mt-2 w-48 rounded-lg border border-[#18335e] bg-[#061329] p-2 shadow-2xl">
        {protectedRole ? (
          <div className="rounded-md px-3 py-2 text-xs font-bold text-slate-400">System role protected</div>
        ) : (
          <>
            <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void roleAction(role.id, primaryAction)}>
              {primaryLabel}
            </button>
            {status !== 'archived' && (
              <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void roleAction(role.id, 'archive')}>Archive role</button>
            )}
            <button
              type="button"
              className={`w-full rounded-md px-3 py-2 text-left text-xs font-bold ${roleInUse ? 'cursor-not-allowed text-slate-500 opacity-60' : 'text-red-300 hover:bg-red-500/10'}`}
              disabled={roleInUse}
              title={roleInUse ? `Assigned to ${role.users} user${role.users === 1 ? '' : 's'}` : `Delete ${role.name}`}
              onClick={() => !roleInUse && window.confirm(`Delete ${role.name}?`) && void roleAction(role.id, 'delete')}
            >
              Delete role
            </button>
          </>
        )}
      </div>
    </details>
  )
}

function RolesTab(props: {
  roles: AdminRole[]
  stats: AdminRoleStats | null
  tenants: AdminTenant[]
  pagination: { page: number; totalPages: number; total?: number; limit?: number }
  search: string
  tenantFilter: string
  typeFilter: string
  statusFilter: string
  setSearch: (value: string) => void
  setTenantFilter: (value: string) => void
  setTypeFilter: (value: string) => void
  setStatusFilter: (value: string) => void
  refreshRoles: (page?: number) => Promise<void>
  newRole: { name: string; description: string; permissionScope: string; permissionCount: number; tenantId: string; status: string }
  setNewRole: (value: { name: string; description: string; permissionScope: string; permissionCount: number; tenantId: string; status: string }) => void
  onCreateRole: (event: FormEvent) => Promise<void>
  updateRole: (roleId: string, payload: Record<string, unknown>) => Promise<unknown>
  roleAction: (roleId: string, action: string) => Promise<unknown>
  mutating: string | null
  sseConnected: boolean
  rolesLiveUpdatedAt: string | null
}) {
  const [showCreateRole, setShowCreateRole] = useState(false)
  const totalRoles = Number(props.stats?.totalRoles || props.pagination.total || props.roles.length || 0)
  const customRoles = Number(props.stats?.customRoles || props.roles.filter((role) => role.type === 'custom').length)
  const systemRoles = Number(props.stats?.systemRoles || props.roles.filter((role) => role.type === 'system').length)
  const rolesInUse = Number(props.stats?.rolesInUse || props.roles.filter((role) => role.users > 0).length)
  const orphanedRoles = Number(props.stats?.orphanedRoles || props.roles.filter((role) => role.users === 0).length)
  const pageSize = props.pagination.limit || 10
  const pageStart = totalRoles ? ((props.pagination.page - 1) * pageSize) + 1 : 0
  const pageEnd = Math.min(totalRoles, (props.pagination.page - 1) * pageSize + props.roles.length)
  const activeFilters = [props.tenantFilter, props.typeFilter, props.statusFilter].filter((value) => value && value !== 'all').length

  return (
    <div className="space-y-5 rounded-lg border border-[#0f274d] bg-[#020a18] p-0 text-slate-200 shadow-[0_30px_80px_rgba(0,0,0,0.35)]">
      <div className="border-b border-[#0f274d] px-5 py-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h2 className="text-2xl font-black tracking-normal text-white">Roles</h2>
            <p className="mt-1 text-sm text-slate-400">Define and manage user roles, permissions, and access levels across the platform.</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#132b52] bg-[#061329] px-4 text-sm font-bold text-slate-300 hover:border-blue-400">
              <HelpCircle className="h-4 w-4" />
              Help
            </button>
            <button type="button" className="relative inline-flex h-10 w-10 items-center justify-center rounded-lg border border-[#132b52] bg-[#061329] text-slate-300 hover:border-blue-400">
              <Bell className="h-5 w-5" />
              <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-black text-white">12</span>
            </button>
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-5 text-sm font-black text-white shadow-lg shadow-violet-600/25 hover:bg-violet-500" onClick={() => setShowCreateRole((value) => !value)}>
              <Plus className="h-4 w-4" />
              Create Role
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 px-5 md:grid-cols-2 xl:grid-cols-5">
        <EnterpriseUserKpi icon={Users} label="Total Roles" value={formatNumber(totalRoles)} sub={`${Number(props.stats?.roleGrowthPercent || 0) >= 0 ? '+' : ''}${formatNumber(props.stats?.roleGrowthPercent)}% vs last month`} tone="violet" />
        <EnterpriseUserKpi icon={Users} label="Custom Roles" value={formatNumber(customRoles)} sub={`${formatNumber(props.stats?.customRolesPercent)}% of total roles`} tone="blue" />
        <EnterpriseUserKpi icon={ShieldCheck} label="System Roles" value={formatNumber(systemRoles)} sub={`${formatNumber(props.stats?.systemRolesPercent)}% of total roles`} tone="blue" />
        <EnterpriseUserKpi icon={CheckCircle} label="Roles in Use" value={formatNumber(rolesInUse)} sub={`${formatNumber(props.stats?.rolesInUsePercent)}% of total roles`} tone="emerald" />
        <EnterpriseUserKpi icon={UserX} label="Orphaned Roles" value={formatNumber(orphanedRoles)} sub="Not assigned to any user" tone="amber" />
      </div>

      {showCreateRole && (
        <form className="mx-5 grid gap-3 rounded-lg border border-[#17335d] bg-[#061329] p-4 lg:grid-cols-[1.2fr_1.6fr_1fr_1fr_auto]" onSubmit={props.onCreateRole}>
          <input className="q-input" placeholder="Role name" value={props.newRole.name} required onChange={(event) => props.setNewRole({ ...props.newRole, name: event.target.value })} />
          <input className="q-input" placeholder="Description" value={props.newRole.description} onChange={(event) => props.setNewRole({ ...props.newRole, description: event.target.value })} />
          <select className="q-select" value={props.newRole.permissionScope} onChange={(event) => props.setNewRole({ ...props.newRole, permissionScope: event.target.value })}>
            <option value="Security">Security</option>
            <option value="Compliance">Compliance</option>
            <option value="Tenant">Tenant</option>
            <option value="Read Only">Read Only</option>
            <option value="Custom">Custom</option>
          </select>
          <input className="q-input" type="number" min={0} value={props.newRole.permissionCount} onChange={(event) => props.setNewRole({ ...props.newRole, permissionCount: Number(event.target.value) })} />
          <button className="q-btn q-btn-primary" type="submit" disabled={props.mutating === 'create-role'}><Plus className="h-4 w-4" />Create</button>
          <select className="q-select lg:col-span-2" value={props.newRole.tenantId} onChange={(event) => props.setNewRole({ ...props.newRole, tenantId: event.target.value })}>
            <option value="">Platform role</option>
            {props.tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </select>
          <select className="q-select lg:col-span-2" value={props.newRole.status} onChange={(event) => props.setNewRole({ ...props.newRole, status: event.target.value })}>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </form>
      )}

      <div className="flex flex-col gap-3 px-5 xl:flex-row xl:items-center">
        <div className="relative min-w-[300px] flex-1">
          <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
          <input className="h-11 w-full rounded-lg border border-[#17335d] bg-[#07162d] pl-12 pr-4 text-sm font-semibold text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-blue-400" placeholder="Search roles by name or description..." value={props.search} onChange={(event) => props.setSearch(event.target.value)} />
        </div>
        <EnterpriseSelect label="Tenant filter" value={props.tenantFilter} onChange={props.setTenantFilter}>
          <option value="all">All Tenants</option>
          <option value="platform">Platform</option>
          {props.tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </EnterpriseSelect>
        <EnterpriseSelect label="Type filter" value={props.typeFilter} onChange={props.setTypeFilter}>
          <option value="all">All Types</option>
          <option value="system">System</option>
          <option value="custom">Custom</option>
        </EnterpriseSelect>
        <EnterpriseSelect label="Status filter" value={props.statusFilter} onChange={props.setStatusFilter}>
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
          <option value="archived">Archived</option>
        </EnterpriseSelect>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400" onClick={() => void props.refreshRoles(1)}>
          <Filter className="h-4 w-4" />
          Filters
          <span className="rounded-full bg-blue-600 px-2 py-0.5 text-xs text-white">{activeFilters}</span>
        </button>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400">
          <Upload className="h-4 w-4" />
          Export
          <ChevronDown className="h-4 w-4" />
        </button>
      </div>

      <div className="mx-5 overflow-x-auto rounded-lg border border-[#12305a]">
        <table className="min-w-[1120px] w-full border-collapse text-left">
          <thead className="bg-[#0b1d3a] text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-4 font-black">Role</th>
              <th className="px-4 py-4 font-black">Type</th>
              <th className="px-4 py-4 font-black">Users</th>
              <th className="px-4 py-4 font-black">Description</th>
              <th className="px-4 py-4 font-black">Permissions</th>
              <th className="px-4 py-4 font-black">Status</th>
              <th className="px-4 py-4 text-center font-black">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#12305a] bg-[#041227]">
            {props.roles.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8"><EmptyState label="No roles found" /></td></tr>
            ) : props.roles.map((role) => {
              const mutating = props.mutating?.includes(role.id)
              return (
                <tr key={role.id} className="transition hover:bg-[#092044]">
                  <td className="px-4 py-4">
                    <div className="flex min-w-[260px] items-center gap-3">
                      <RoleIcon role={role} />
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate font-bold text-slate-100">{role.name}</span>
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-black ${roleTypeTone(role.type)}`}>{role.type === 'system' ? 'System' : 'Custom'}</span>
                        </div>
                        <div className="mt-1 truncate text-xs text-slate-400">{role.tenantName || (role.tenantId ? 'Tenant scoped' : role.permissionScope === 'All' ? 'Full platform access' : `${role.permissionScope} access`)}</div>
                        <div className="font-mono text-xs text-slate-500">ID: role_{role.roleKey}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-slate-300">{role.type === 'system' ? 'System' : 'Custom'}</td>
                  <td className="px-4 py-4 font-mono text-sm leading-6 text-slate-300">
                    <div className="text-base font-black text-white">{formatNumber(role.users)}</div>
                    <div className="font-sans text-xs text-slate-400">users</div>
                  </td>
                  <td className="max-w-[330px] px-4 py-4 text-sm leading-6 text-slate-300">{role.description}</td>
                  <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                    <div className="font-bold text-slate-100">{role.permissionScope}</div>
                    <div className="text-xs text-slate-400">{formatNumber(role.permissionCount)} permissions</div>
                  </td>
                  <td className="px-4 py-4"><EnterpriseStatus status={role.status} /></td>
                  <td className="px-4 py-4">
                    <div className="flex justify-center">
                      {mutating ? (
                        <RefreshCw className="h-5 w-5 animate-spin text-blue-300" />
                      ) : (
                        <RoleActionsMenu role={role} roleAction={props.roleAction} />
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <div className="flex flex-col gap-3 border-t border-[#12305a] bg-[#041227] px-4 py-3 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
          <span>Showing {formatNumber(pageStart)} to {formatNumber(pageEnd)} of {formatNumber(totalRoles)} roles</span>
          <PaginationControls page={props.pagination.page} totalPages={props.pagination.totalPages} onPage={(page) => void props.refreshRoles(page)} />
        </div>
      </div>

      <div className="mx-5 mb-5 grid gap-3 rounded-lg border border-[#0f274d] bg-[#07162d] px-5 py-3 text-xs font-semibold text-slate-400 md:grid-cols-4">
        <span className="inline-flex items-center gap-2"><Activity className="h-4 w-4" />All times shown in UTC</span>
        <span className="inline-flex items-center gap-2"><Lock className="h-4 w-4" />Data is encrypted in transit and at rest</span>
        <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" />Security and audit logs are enabled</span>
        <span className="inline-flex items-center justify-end gap-2">Last updated: {timeAgo(props.rolesLiveUpdatedAt)} <RefreshCw className={`h-4 w-4 ${props.sseConnected ? 'text-blue-300' : 'text-amber-300'}`} /></span>
      </div>
    </div>
  )
}

function DetailList({ title, rows, empty }: { title: string; rows: Array<Record<string, unknown>>; empty: string }) {
  return (
    <div className="rounded-lg border border-[var(--qg-border)] bg-white/[0.03] p-4">
      <h4 className="mb-3 text-xs font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{title}</h4>
      <div className="space-y-2">
        {rows.length === 0 ? <EmptyState label={empty} /> : rows.slice(0, 6).map((row, index) => (
          <div key={String(row.id || index)} className="rounded-md border border-[var(--qg-border)] bg-black/10 p-3">
            <div className="text-xs font-bold text-[var(--qg-text-primary)]">{String(row.event_type || row.device_name || row.session_id || row.id || 'Record')}</div>
            <div className="mt-1 font-mono text-[10px] text-[var(--qg-text-muted)]">{formatDate(String(row.created_at || row.last_seen_at || row.updated_at || ''))}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function tenantInitials(tenant: AdminTenant) {
  const parts = tenant.name.split(/\s+/).filter(Boolean)
  return (parts.slice(0, 2).map((part) => part[0]).join('') || tenant.slug?.slice(0, 2) || 'TN').toUpperCase()
}

function tenantDisplayId(tenant: AdminTenant) {
  return `tenant_${tenant.id.replace(/-/g, '').slice(0, 8)}`
}

function tenantFlag(region?: string) {
  if (!region) return ''
  if (region.startsWith('ap-southeast-2')) return '🇦🇺'
  if (region.startsWith('ap-southeast-1')) return '🇸🇬'
  if (region.startsWith('eu-west')) return '🇬🇧'
  if (region.startsWith('ca-central')) return '🇨🇦'
  if (region.startsWith('us-')) return '🇺🇸'
  return ''
}

function tenantRegionLabel(region?: string) {
  if (!region) return 'Global'
  if (region.startsWith('ap-southeast-2')) return 'Australia'
  if (region.startsWith('ap-southeast-1')) return 'Singapore'
  if (region.startsWith('eu-west')) return 'United Kingdom'
  if (region.startsWith('ca-central')) return 'Canada'
  if (region.startsWith('us-')) return 'United States'
  return region.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function tenantAvatarTone(index: number) {
  const tones = [
    'from-blue-600 to-cyan-800',
    'from-violet-700 to-purple-900',
    'from-cyan-600 to-teal-800',
    'from-amber-600 to-orange-900',
    'from-red-600 to-orange-900',
    'from-yellow-500 to-amber-800',
  ]
  return tones[index % tones.length]
}

function TenantPlanBadge({ plan }: { plan: string }) {
  const normalized = plan.toLowerCase()
  const tone = normalized.includes('elite')
    ? 'border-violet-400/30 bg-violet-500/15 text-violet-200'
    : normalized.includes('pro')
      ? 'border-blue-400/30 bg-blue-500/15 text-blue-200'
      : 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200'

  return <span className={`inline-flex rounded-md border px-3 py-1 text-[11px] font-black uppercase ${tone}`}>{normalizeText(plan)}</span>
}

function TenantActionsMenu({ tenant, updateTenant, tenantAction }: {
  tenant: AdminTenant
  updateTenant: (tenantId: string, payload: Record<string, unknown>) => Promise<unknown>
  tenantAction: (tenantId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
}) {
  const disabled = ['disabled', 'suspended'].includes(String(tenant.status || '').toLowerCase())

  return (
    <details className="relative">
      <summary className="flex h-10 w-10 cursor-pointer list-none items-center justify-center rounded-lg border border-[#18335e] bg-[#071831] text-slate-300 transition hover:border-blue-400 hover:text-white [&::-webkit-details-marker]:hidden">
        <MoreVertical className="h-4 w-4" />
      </summary>
      <div className="absolute right-0 z-20 mt-2 w-52 rounded-lg border border-[#18335e] bg-[#061329] p-2 shadow-2xl">
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void tenantAction(tenant.id, disabled ? 'enable' : 'disable')}>
          {disabled ? 'Enable tenant' : 'Suspend tenant'}
        </button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void updateTenant(tenant.id, { plan: 'elite' })}>Upgrade to Elite</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void tenantAction(tenant.id, 'set_quota', { quotaUsers: Number(tenant.quota_users || 5) + 5, quotaStorageGb: Number(tenant.quota_storage_gb || 5) + 25 })}>Increase quota</button>
      </div>
    </details>
  )
}

function TenantsTab(props: {
  tenants: AdminTenant[]
  stats: AdminTenantStats | null
  pagination: { page: number; totalPages: number; total?: number; limit?: number }
  tenantSearch: string
  setTenantSearch: (value: string) => void
  statusFilter: string
  setStatusFilter: (value: string) => void
  planFilter: string
  setPlanFilter: (value: string) => void
  regionFilter: string
  setRegionFilter: (value: string) => void
  refreshTenants: (page?: number) => Promise<void>
  newTenant: { name: string; slug: string; plan: string; quotaUsers: number; quotaStorageGb: number }
  setNewTenant: (value: { name: string; slug: string; plan: string; quotaUsers: number; quotaStorageGb: number }) => void
  onCreateTenant: (event: FormEvent) => Promise<void>
  updateTenant: (tenantId: string, payload: Record<string, unknown>) => Promise<unknown>
  tenantAction: (tenantId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
  mutating: string | null
  sseConnected: boolean
  tenantsLiveUpdatedAt: string | null
}) {
  const [showCreateTenant, setShowCreateTenant] = useState(false)
  const tenantName = props.newTenant.name.trim()
  const totalTenants = Number(props.stats?.totalTenants || props.pagination.total || props.tenants.length || 0)
  const activeTenants = Number(props.stats?.activeTenants || props.tenants.filter((tenant) => tenant.status === 'active').length)
  const trialTenants = Number(props.stats?.trialTenants || props.tenants.filter((tenant) => tenant.status === 'trial' || Number(tenant.trialSubscriptions || 0) > 0).length)
  const suspendedTenants = Number(props.stats?.suspendedTenants || props.tenants.filter((tenant) => ['suspended', 'disabled'].includes(tenant.status)).length)
  const totalUsers = Number(props.stats?.totalUsers || props.tenants.reduce((sum, tenant) => sum + Number(tenant.totalUsers || tenant.members || 0), 0))
  const totalDevices = Number(props.stats?.totalDevices || props.tenants.reduce((sum, tenant) => sum + Number(tenant.devices || 0), 0))
  const pageSize = props.pagination.limit || 10
  const pageStart = totalTenants ? ((props.pagination.page - 1) * pageSize) + 1 : 0
  const pageEnd = Math.min(totalTenants, (props.pagination.page - 1) * pageSize + props.tenants.length)
  const activeFilters = [props.statusFilter, props.planFilter, props.regionFilter].filter((value) => value && value !== 'all').length

  return (
    <div className="space-y-5 rounded-lg border border-[#0f274d] bg-[#020a18] p-0 text-slate-200 shadow-[0_30px_80px_rgba(0,0,0,0.35)]">
      <div className="border-b border-[#0f274d] px-5 py-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h2 className="text-2xl font-black tracking-normal text-white">Tenants</h2>
            <p className="mt-1 text-sm text-slate-400">Manage organizations, their configurations, and access across the platform.</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#132b52] bg-[#061329] px-4 text-sm font-bold text-slate-300 hover:border-blue-400">
              <HelpCircle className="h-4 w-4" />
              Help
            </button>
            <button type="button" className="relative inline-flex h-10 w-10 items-center justify-center rounded-lg border border-[#132b52] bg-[#061329] text-slate-300 hover:border-blue-400">
              <Bell className="h-5 w-5" />
              <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-black text-white">12</span>
            </button>
            <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-5 text-sm font-black text-white shadow-lg shadow-violet-600/25 hover:bg-violet-500" onClick={() => setShowCreateTenant((value) => !value)}>
              <Plus className="h-4 w-4" />
              Add Tenant
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 px-5 md:grid-cols-2 xl:grid-cols-6">
        <EnterpriseUserKpi icon={Building2} label="Total Tenants" value={formatNumber(totalTenants)} sub={`${Number(props.stats?.tenantGrowthPercent || 0) >= 0 ? '+' : ''}${formatNumber(props.stats?.tenantGrowthPercent)}% vs last month`} tone="violet" />
        <EnterpriseUserKpi icon={CheckCircle} label="Active Tenants" value={formatNumber(activeTenants)} sub={`${percentLabel(activeTenants, totalTenants)} of total tenants`} tone="emerald" />
        <EnterpriseUserKpi icon={Activity} label="Trial Tenants" value={formatNumber(trialTenants)} sub={`${percentLabel(trialTenants, totalTenants)} of total tenants`} tone="blue" />
        <EnterpriseUserKpi icon={AlertTriangle} label="Suspended Tenants" value={formatNumber(suspendedTenants)} sub={`${percentLabel(suspendedTenants, totalTenants)} of total tenants`} tone="amber" />
        <EnterpriseUserKpi icon={Users} label="Total Users" value={formatNumber(totalUsers)} sub="Across all tenants" tone="blue" />
        <EnterpriseUserKpi icon={Wifi} label="Total Devices" value={formatNumber(totalDevices)} sub="Across all tenants" tone="violet" />
      </div>

      {showCreateTenant && (
        <form className="mx-5 grid gap-3 rounded-lg border border-[#17335d] bg-[#061329] p-4 md:grid-cols-[1.4fr_1fr_1fr_1fr_1fr_auto]" onSubmit={props.onCreateTenant}>
          <input className="q-input" placeholder="Organization name" value={props.newTenant.name} required aria-invalid={!tenantName} onChange={(event) => props.setNewTenant({ ...props.newTenant, name: event.target.value })} />
          <input className="q-input" placeholder="Slug" value={props.newTenant.slug} onChange={(event) => props.setNewTenant({ ...props.newTenant, slug: event.target.value })} />
          <select className="q-select" value={props.newTenant.plan} onChange={(event) => props.setNewTenant({ ...props.newTenant, plan: event.target.value })}>
            <option value="starter">Starter</option>
            <option value="pro">Pro</option>
            <option value="elite">Elite</option>
          </select>
          <input className="q-input" type="number" min={1} value={props.newTenant.quotaUsers} onChange={(event) => props.setNewTenant({ ...props.newTenant, quotaUsers: Number(event.target.value) })} />
          <input className="q-input" type="number" min={1} value={props.newTenant.quotaStorageGb} onChange={(event) => props.setNewTenant({ ...props.newTenant, quotaStorageGb: Number(event.target.value) })} />
          <button className="q-btn q-btn-primary" type="submit" disabled={!tenantName || props.mutating === 'create-tenant'}><Building2 className="h-4 w-4" />Create</button>
        </form>
      )}

      <div className="flex flex-col gap-3 px-5 xl:flex-row xl:items-center">
        <div className="relative min-w-[300px] flex-1">
          <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
          <input className="h-11 w-full rounded-lg border border-[#17335d] bg-[#07162d] pl-12 pr-4 text-sm font-semibold text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-blue-400" placeholder="Search tenants by name, domain, or ID..." value={props.tenantSearch} onChange={(event) => props.setTenantSearch(event.target.value)} />
        </div>
        <EnterpriseSelect label="Status filter" value={props.statusFilter} onChange={props.setStatusFilter}>
          <option value="all">All Statuses</option>
          <option value="active">Active</option>
          <option value="trial">Trial</option>
          <option value="suspended">Suspended</option>
          <option value="disabled">Disabled</option>
        </EnterpriseSelect>
        <EnterpriseSelect label="Plan filter" value={props.planFilter} onChange={props.setPlanFilter}>
          <option value="all">All Plans</option>
          <option value="starter">Starter</option>
          <option value="pro">Pro</option>
          <option value="elite">Elite</option>
        </EnterpriseSelect>
        <EnterpriseSelect label="Region filter" value={props.regionFilter} onChange={props.setRegionFilter}>
          <option value="all">All Regions</option>
          <option value="us-east-1">US East</option>
          <option value="us-west-2">US West</option>
          <option value="ap-southeast-1">Singapore</option>
          <option value="ap-southeast-2">Australia</option>
          <option value="eu-west-2">United Kingdom</option>
          <option value="ca-central-1">Canada</option>
        </EnterpriseSelect>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400" onClick={() => void props.refreshTenants(1)}>
          <Filter className="h-4 w-4" />
          More Filters
          <ChevronDown className="h-4 w-4" />
          {activeFilters > 0 && <span className="rounded-full bg-blue-600 px-2 py-0.5 text-xs text-white">{activeFilters}</span>}
        </button>
        <button type="button" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-[#17335d] bg-[#07162d] px-5 text-sm font-black text-slate-200 hover:border-blue-400">
          <Upload className="h-4 w-4" />
          Export
          <ChevronDown className="h-4 w-4" />
        </button>
      </div>

      <div className="mx-5 overflow-x-auto rounded-lg border border-[#12305a]">
        <table className="min-w-[1200px] w-full border-collapse text-left">
          <thead className="bg-[#0b1d3a] text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-4 font-black">Tenant</th>
              <th className="px-4 py-4 font-black">Plan</th>
              <th className="px-4 py-4 font-black">Users</th>
              <th className="px-4 py-4 font-black">Devices</th>
              <th className="px-4 py-4 font-black">Status</th>
              <th className="px-4 py-4 font-black">Region</th>
              <th className="px-4 py-4 font-black">Created On</th>
              <th className="px-4 py-4 font-black">Last Activity</th>
              <th className="px-4 py-4 text-center font-black">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#12305a] bg-[#041227]">
            {props.tenants.length === 0 ? (
              <tr><td colSpan={9} className="px-4 py-8"><EmptyState label="No tenants found" /></td></tr>
            ) : props.tenants.map((tenant, index) => {
              const mutating = props.mutating?.includes(tenant.id)
              return (
                <tr key={tenant.id} className="transition hover:bg-[#092044]">
                  <td className="px-4 py-4">
                    <div className="flex min-w-[250px] items-center gap-3">
                      <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br ${tenantAvatarTone(index)} font-mono text-sm font-black text-white`}>{tenantInitials(tenant)}</span>
                      <div className="min-w-0">
                        <div className="truncate font-bold text-slate-100">{tenant.name}</div>
                        <div className="truncate text-xs text-slate-400">{tenant.domain || tenant.slug}</div>
                        <div className="font-mono text-xs text-slate-500">ID: {tenantDisplayId(tenant)}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <TenantPlanBadge plan={tenant.plan || 'starter'} />
                    <div className="mt-2 text-xs text-slate-400">Renews on</div>
                    <div className="text-xs text-slate-300">{formatShortDateTime(tenant.renewalDate).date}</div>
                  </td>
                  <td className="px-4 py-4 font-mono text-sm leading-6 text-slate-300">
                    <div className="text-base font-black text-white">{formatNumber(tenant.totalUsers || tenant.members || 0)}</div>
                    <div className="font-sans text-xs text-slate-400">Active <span className="ml-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" /></div>
                  </td>
                  <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                    <div className="font-mono text-base text-white">{formatNumber(tenant.devices || 0)}</div>
                    <div className="text-xs text-slate-400">Managed</div>
                  </td>
                  <td className="px-4 py-4"><EnterpriseStatus status={tenant.status || 'active'} /></td>
                  <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                    <div>{tenantFlag(tenant.region)} {tenant.regionLabel || tenantRegionLabel(tenant.region)}</div>
                    <div className="font-mono text-xs text-slate-400">{tenant.region || 'global'}</div>
                  </td>
                  <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                    <div>{formatShortDateTime(tenant.created_at).date}</div>
                    <div className="text-xs text-slate-400">by {tenant.createdBy || 'System'}</div>
                  </td>
                  <td className="px-4 py-4 text-sm text-slate-300">
                    <span className={`mr-2 inline-block h-2 w-2 rounded-full ${['suspended', 'disabled'].includes(String(tenant.status).toLowerCase()) ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                    {timeAgo(tenant.lastActivityAt || tenant.updated_at)}
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex justify-center">
                      {mutating ? <RefreshCw className="h-5 w-5 animate-spin text-blue-300" /> : <TenantActionsMenu tenant={tenant} updateTenant={props.updateTenant} tenantAction={props.tenantAction} />}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <div className="flex flex-col gap-3 border-t border-[#12305a] bg-[#041227] px-4 py-3 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
          <span>Showing {formatNumber(pageStart)} to {formatNumber(pageEnd)} of {formatNumber(totalTenants)} tenants</span>
          <PaginationControls page={props.pagination.page} totalPages={props.pagination.totalPages} onPage={(page) => void props.refreshTenants(page)} />
        </div>
      </div>

      <div className="mx-5 mb-5 grid gap-3 rounded-lg border border-[#0f274d] bg-[#07162d] px-5 py-3 text-xs font-semibold text-slate-400 md:grid-cols-4">
        <span className="inline-flex items-center gap-2"><Activity className="h-4 w-4" />All times shown in UTC</span>
        <span className="inline-flex items-center gap-2"><Lock className="h-4 w-4" />Data is encrypted in transit and at rest</span>
        <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" />Security and audit logs are enabled</span>
        <span className="inline-flex items-center justify-end gap-2">Last updated: {timeAgo(props.tenantsLiveUpdatedAt)} <RefreshCw className={`h-4 w-4 ${props.sseConnected ? 'text-blue-300' : 'text-amber-300'}`} /></span>
      </div>
    </div>
  )
}

function formatBillingCurrency(cents?: number, currency = 'USD') {
  const value = Number(cents || 0)
  const decimals = Math.abs(value % 100) > 0 ? 2 : 0
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency || 'USD',
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(value / 100)
}

function subscriptionTenantName(subscription: AdminSubscription) {
  return subscription.tenant?.name || subscription.profile?.full_name || subscription.profile?.name || subscription.profile?.email || 'Unassigned tenant'
}

function subscriptionDomain(subscription: AdminSubscription) {
  return subscription.tenant?.domain || subscription.domain || subscription.profile?.email || 'No billing domain'
}

function subscriptionDisplayId(subscription: AdminSubscription) {
  const source = subscription.tenant_id || subscription.id
  return `tenant_${source.replace(/-/g, '').slice(0, 8)}`
}

function subscriptionInitials(subscription: AdminSubscription) {
  const source = subscriptionTenantName(subscription)
  const parts = source.split(/[.\s@_-]+/).filter(Boolean)
  return (parts.slice(0, 2).map((part) => part[0]).join('') || 'PB').toUpperCase()
}

function subscriptionStatusTone(status: string) {
  const normalized = status.toLowerCase()
  if (normalized.includes('past_due') || normalized.includes('overdue') || normalized.includes('failed')) return 'border-red-400/25 bg-red-500/10 text-red-300'
  if (normalized.includes('active') || normalized.includes('approved') || normalized.includes('trial')) return 'border-emerald-400/25 bg-emerald-500/10 text-emerald-300'
  return 'border-amber-400/30 bg-amber-500/10 text-amber-200'
}

function BillingMetricCard({ label, value, sub, icon: Icon, tone = 'blue' }: {
  label: string
  value: string
  sub?: string
  icon: typeof Activity
  tone?: 'blue' | 'emerald' | 'violet' | 'red'
}) {
  const glow = tone === 'emerald'
    ? 'bg-emerald-500/15 text-emerald-300'
    : tone === 'violet'
      ? 'bg-violet-500/15 text-violet-300'
      : tone === 'red'
        ? 'bg-red-500/15 text-red-300'
        : 'bg-blue-500/15 text-blue-300'
  const subTone = sub?.startsWith('$') || sub?.includes('Past') ? 'text-red-300' : 'text-slate-400'

  return (
    <div className="relative min-h-[112px] overflow-hidden rounded-lg border border-[#12305a] bg-gradient-to-br from-[#071a35] to-[#061327] p-4 shadow-[0_16px_38px_rgba(0,0,0,0.28)]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-slate-400">{label}</div>
          <div className="mt-2 flex items-end gap-1 font-mono text-2xl font-black text-white">{value}</div>
          {sub && <div className={`mt-2 text-xs font-semibold ${subTone}`}>{sub}</div>}
        </div>
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full ${glow}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {label === 'Total MRR' && (
        <div className="absolute bottom-0 right-5 flex h-8 items-end gap-1 opacity-80">
          {[10, 15, 9, 22, 18, 29].map((height, index) => <span key={index} className="w-4 rounded-t-full bg-violet-400/70" style={{ height }} />)}
        </div>
      )}
    </div>
  )
}

function BillingStatus({ status }: { status: string }) {
  const normalized = normalizeText(status)
  const critical = /past due|failed|canceled|cancelled/i.test(normalized)
  return (
    <span className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-black ${subscriptionStatusTone(status)}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${critical ? 'bg-red-400' : 'bg-emerald-400'}`} />
      {normalized}
    </span>
  )
}

function BillingActionsMenu({ subscription, subscriptionAction }: {
  subscription: AdminSubscription
  subscriptionAction: (subscriptionId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
}) {
  const status = String(subscription.status || '').toLowerCase()
  const plan = String(subscription.plan || '').toLowerCase()
  const isActive = /active|approved|trial/.test(status)
  const isCanceled = /canceled|cancelled/.test(status)
  const approvalStatus = String(subscription.approval_status || '').toLowerCase()
  const needsApproval = Boolean(approvalStatus && !['approved', 'not_required'].includes(approvalStatus))
  const proAction = plan === 'elite' ? 'downgrade' : 'upgrade'

  return (
    <details className="relative">
      <summary className="flex h-10 w-10 cursor-pointer list-none items-center justify-center rounded-lg border border-[#18335e] bg-[#071831] text-slate-300 transition hover:border-blue-400 hover:text-white [&::-webkit-details-marker]:hidden">
        <MoreVertical className="h-4 w-4" />
      </summary>
      <div className="absolute right-0 z-20 mt-2 w-52 rounded-lg border border-[#18335e] bg-[#061329] p-2 shadow-2xl">
        {needsApproval && (
          <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, 'approve')}>
            Approve subscription
          </button>
        )}
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, isActive ? 'deactivate' : 'activate')}>
          {isActive ? 'Deactivate subscription' : 'Activate subscription'}
        </button>
        {plan !== 'elite' && (
          <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, 'upgrade', { plan: 'Elite' })}>Move to Elite</button>
        )}
        {plan !== 'pro' && (
          <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, proAction, { plan: 'Pro' })}>Move to Pro</button>
        )}
        {plan !== 'starter' && (
          <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, 'downgrade', { plan: 'Starter' })}>Downgrade to Starter</button>
        )}
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, 'extend', { days: 30 })}>Extend 30 days</button>
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => void subscriptionAction(subscription.id, 'renewal_reminder')}>Send reminder</button>
        {!isCanceled && (
          <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-red-300 hover:bg-red-500/10" onClick={() => window.confirm(`Cancel ${subscriptionTenantName(subscription)} subscription?`) && void subscriptionAction(subscription.id, 'cancel')}>Cancel subscription</button>
        )}
        <button type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-red-300 hover:bg-red-500/10" onClick={() => window.confirm(`Delete ${subscriptionTenantName(subscription)} subscription record?`) && void subscriptionAction(subscription.id, 'delete')}>Delete record</button>
      </div>
    </details>
  )
}

function BillingSummaryPanel({ summary }: { summary: AdminBillingSummary | null }) {
  const rows = [
    ['Current Balance', summary?.currentBalanceCents || 0, 'text-emerald-300'],
    ['Past Due', summary?.pastDueCents || 0, 'text-red-300'],
    ['Credits', summary?.creditsCents || 0, 'text-emerald-300'],
    ['Total Billed (YTD)', summary?.totalBilledYtdCents || 0, 'text-slate-200'],
    ['Total Paid (YTD)', summary?.totalPaidYtdCents || 0, 'text-slate-400'],
  ] as const

  return (
    <div className="rounded-lg border border-[#12305a] bg-[#07162d] p-4">
      <div className="mb-4 flex items-center gap-2 text-sm font-black text-white"><CreditCard className="h-4 w-4 text-blue-300" />Billing Summary</div>
      <div className="space-y-3">
        {rows.map(([label, amount, tone], index) => (
          <div key={label} className={`${index === 3 ? 'border-t border-[#12305a] pt-4' : ''} flex items-center justify-between gap-4 text-xs`}>
            <span className="text-slate-400">{label}</span>
            <span className={`font-mono font-black ${tone}`}>{formatBillingCurrency(amount)}</span>
          </div>
        ))}
      </div>
      <button type="button" className="mt-5 flex h-10 w-full items-center justify-center gap-2 rounded-md bg-violet-600 text-xs font-black text-white transition hover:bg-violet-500">
        View Billing History <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  )
}

function UpcomingInvoicesPanel({ invoices }: { invoices: AdminUpcomingInvoice[] }) {
  return (
    <div className="rounded-lg border border-[#12305a] bg-[#07162d] p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-black text-white"><FileCheck className="h-4 w-4 text-blue-300" />Upcoming Invoices</div>
        <button type="button" className="text-xs font-bold text-blue-300">View All</button>
      </div>
      <div className="space-y-3">
        {invoices.length === 0 ? <EmptyState label="No upcoming invoices" /> : invoices.map((invoice) => (
          <div key={invoice.id} className="grid grid-cols-[1fr_auto_auto] items-center gap-3 text-xs">
            <span className="truncate text-slate-300">{invoice.tenantName}</span>
            <span className="whitespace-nowrap text-slate-400">{formatShortDateTime(invoice.dueDate).date}</span>
            <span className="font-mono font-bold text-slate-200">{formatBillingCurrency(invoice.amountCents, invoice.currency)}</span>
          </div>
        ))}
      </div>
      {invoices.length > 0 && (
        <div className="mt-4 flex items-center justify-between border-t border-[#12305a] pt-3 text-xs font-black text-slate-200">
          <span>Total ({invoices.length})</span>
          <span>{formatBillingCurrency(invoices.reduce((sum, invoice) => sum + Number(invoice.amountCents || 0), 0))}</span>
        </div>
      )}
    </div>
  )
}

function PaymentMethodsPanel({ methods }: { methods: AdminPaymentMethod[] }) {
  return (
    <div className="rounded-lg border border-[#12305a] bg-[#07162d] p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-black text-white"><CreditCard className="h-4 w-4 text-blue-300" />Payment Methods</div>
        <button type="button" className="text-xs font-bold text-violet-300">Manage</button>
      </div>
      <div className="space-y-3">
        {methods.length === 0 ? <EmptyState label="No payment methods" /> : methods.map((method) => {
          const exp = method.expMonth && method.expYear ? `${String(method.expMonth).padStart(2, '0')}/${String(method.expYear).slice(-2)}` : 'Not recorded'
          return (
            <div key={method.id} className="flex items-center justify-between gap-3 rounded-lg border border-[#12305a] bg-[#061329] p-3">
              <div className="flex items-center gap-3">
                <span className="flex h-8 w-12 items-center justify-center rounded bg-blue-900/70 font-mono text-xs font-black text-white">{method.brand.toUpperCase().slice(0, 5)}</span>
                <div>
                  <div className="font-mono text-xs font-black text-white">•••• •••• •••• {method.last4 || '0000'}</div>
                  <div className="text-xs text-slate-400">Expires {exp}</div>
                </div>
              </div>
              {method.isDefault ? <span className="rounded-md bg-violet-500/20 px-2 py-1 text-[10px] font-black text-violet-200">Primary</span> : <ChevronRight className="h-4 w-4 text-slate-500" />}
            </div>
          )
        })}
      </div>
      <button type="button" className="mt-4 flex h-9 w-full items-center justify-center gap-2 rounded-md border border-violet-500/40 text-xs font-black text-violet-200 transition hover:bg-violet-500/10">
        <Plus className="h-4 w-4" />Add Payment Method
      </button>
    </div>
  )
}

function SubscriptionsTab(props: {
  subscriptions: AdminSubscription[]
  stats: AdminBillingStats | null
  summary: AdminBillingSummary | null
  upcomingInvoices: AdminUpcomingInvoice[]
  paymentMethods: AdminPaymentMethod[]
  pagination: { page: number; limit?: number; total?: number; totalPages: number }
  search: string
  setSearch: (value: string) => void
  statusFilter: string
  setStatusFilter: (value: string) => void
  planFilter: string
  setPlanFilter: (value: string) => void
  regionFilter: string
  setRegionFilter: (value: string) => void
  refreshSubscriptions: (page?: number) => Promise<void>
  subscriptionAction: (subscriptionId: string, action: string, payload?: Record<string, unknown>) => Promise<unknown>
  sseConnected: boolean
  subscriptionsLiveUpdatedAt: string | null
  exportReport: () => void
  mutating: string | null
}) {
  const [billingSection, setBillingSection] = useState('Subscriptions')
  const stats = props.stats
  const totalRows = Number(props.pagination.total || props.subscriptions.length)
  const pageStart = totalRows === 0 ? 0 : ((props.pagination.page - 1) * Number(props.pagination.limit || 10)) + 1
  const pageEnd = Math.min(totalRows, pageStart + props.subscriptions.length - 1)
  const nextBilling = stats?.nextBillingDate ? formatShortDateTime(stats.nextBillingDate).date : 'Not scheduled'
  const nextBillingSub = Number.isFinite(Number(stats?.nextBillingDays)) ? `In ${Math.max(0, Number(stats?.nextBillingDays))} days` : 'Awaiting renewal'
  const sections = ['Subscriptions', 'Plans', 'Invoices', 'Payment Methods', 'Billing History', 'Coupons & Credits', 'Usage']

  return (
    <div className="overflow-hidden rounded-lg border border-[#12305a] bg-[#020b19] shadow-[0_24px_80px_rgba(0,0,0,0.35)]">
      <div className="flex flex-col gap-4 border-b border-[#12305a] bg-gradient-to-r from-[#06162d] to-[#020b19] px-5 py-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white">Plans & Billing</h2>
          <p className="mt-1 text-sm text-slate-400">Manage subscriptions, view billing details, and track usage across your organization.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 transition hover:border-blue-400"><HelpCircle className="h-4 w-4" />Help</button>
          <button type="button" className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-[#12305a] bg-[#061329] text-slate-200 transition hover:border-blue-400">
            <Bell className="h-4 w-4" />
            <span className="absolute -right-1 -top-1 rounded-full bg-rose-500 px-1.5 text-[10px] font-black text-white">12</span>
          </button>
          <details className="relative">
            <summary className="flex h-10 cursor-pointer list-none items-center gap-2 rounded-lg bg-violet-600 px-4 text-sm font-black text-white transition hover:bg-violet-500 [&::-webkit-details-marker]:hidden">
              <Plus className="h-4 w-4" />Change Plan <ChevronDown className="h-4 w-4" />
            </summary>
            <div className="absolute right-0 z-20 mt-2 w-48 rounded-lg border border-[#18335e] bg-[#061329] p-2 shadow-2xl">
              {['all', 'starter', 'pro', 'elite'].map((plan) => (
                <button key={plan} type="button" className="w-full rounded-md px-3 py-2 text-left text-xs font-bold text-slate-200 hover:bg-white/10" onClick={() => props.setPlanFilter(plan)}>
                  {plan === 'all' ? 'All plans' : normalizeText(plan)}
                </button>
              ))}
            </div>
          </details>
        </div>
      </div>

      <div className="grid gap-4 p-5 lg:grid-cols-5">
        <BillingMetricCard label="Total MRR" value={formatBillingCurrency(stats?.totalMrrCents || 0)} sub={`↑ ${formatNumber(stats?.mrrGrowthPercent || 0)}% vs last month`} icon={CreditCard} tone="violet" />
        <BillingMetricCard label="Total Tenants" value={formatNumber(stats?.totalTenants || 0)} sub="Active Subscriptions" icon={Building2} />
        <BillingMetricCard label="Active Subscriptions" value={formatNumber(stats?.activeSubscriptions || 0)} sub={`${percentLabel(Number(stats?.activeSubscriptions || 0), Math.max(1, Number(stats?.totalTenants || 0)))} of total tenants`} icon={CheckCircle} tone="emerald" />
        <BillingMetricCard label="Past Due" value={formatNumber(stats?.pastDue || 0)} sub={formatBillingCurrency(stats?.pastDueAmountCents || 0)} icon={AlertTriangle} tone="red" />
        <BillingMetricCard label="Next Billing" value={nextBilling} sub={nextBillingSub} icon={FileCheck} tone="violet" />
      </div>

      <div className="grid gap-4 px-5 pb-5 lg:grid-cols-3">
        <BillingSummaryPanel summary={props.summary} />
        <UpcomingInvoicesPanel invoices={props.upcomingInvoices} />
        <PaymentMethodsPanel methods={props.paymentMethods} />
      </div>

      <div className="flex flex-wrap gap-6 border-b border-[#12305a] px-5">
        {sections.map((section) => (
          <button
            key={section}
            type="button"
            className={`border-b-2 px-1 py-3 text-sm font-bold transition ${billingSection === section ? 'border-violet-400 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
            onClick={() => setBillingSection(section)}
          >
            {section}
          </button>
        ))}
      </div>

      <div className="p-5">
        <div className="min-w-0 space-y-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(220px,1.3fr)_140px_140px_140px_96px_110px]">
            <label className="relative">
              <span className="sr-only">Search billing records</span>
              <input className="h-10 w-full rounded-lg border border-[#12305a] bg-[#061329] pl-4 pr-10 text-sm text-slate-200 outline-none transition placeholder:text-slate-500 focus:border-blue-400" value={props.search} onChange={(event) => props.setSearch(event.target.value)} placeholder="Search tenants by name, domain, or ID..." />
              <Search className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            </label>
            <select className="h-10 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 outline-none focus:border-blue-400" value={props.statusFilter} onChange={(event) => props.setStatusFilter(event.target.value)}>
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="approved">Approved</option>
              <option value="trialing">Trialing</option>
              <option value="past_due">Past Due</option>
              <option value="canceled">Canceled</option>
              <option value="cancelled">Cancelled</option>
            </select>
            <select className="h-10 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 outline-none focus:border-blue-400" value={props.planFilter} onChange={(event) => props.setPlanFilter(event.target.value)}>
              <option value="all">All Plans</option>
              <option value="starter">Starter</option>
              <option value="pro">Pro</option>
              <option value="elite">Elite</option>
            </select>
            <select className="h-10 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 outline-none focus:border-blue-400" value={props.regionFilter} onChange={(event) => props.setRegionFilter(event.target.value)}>
              <option value="all">All Regions</option>
              <option value="us-east-1">US East</option>
              <option value="us-west-2">US West</option>
              <option value="eu-west-2">Europe</option>
              <option value="ap-southeast-1">Singapore</option>
              <option value="ap-southeast-2">Australia</option>
            </select>
            <button type="button" className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] text-sm font-black text-slate-200 transition hover:border-blue-400" onClick={() => void props.refreshSubscriptions(1)}><Filter className="h-4 w-4" />Filters</button>
            <button type="button" className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] text-sm font-black text-slate-200 transition hover:border-blue-400" onClick={props.exportReport}><Upload className="h-4 w-4" />Export</button>
          </div>

          <div className="overflow-hidden rounded-lg border border-[#12305a] bg-[#061329]">
            <div className="overflow-x-auto">
              <table className="min-w-[1060px] w-full border-collapse">
                <thead className="bg-[#0a203d] text-left text-xs font-black uppercase tracking-[0.04em] text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Tenant</th>
                    <th className="px-4 py-3">Plan</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Users / Devices</th>
                    <th className="px-4 py-3">Renewal Date</th>
                    <th className="px-4 py-3">Amount</th>
                    <th className="px-4 py-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#12305a] text-sm">
                  {props.subscriptions.length === 0 ? (
                    <tr><td colSpan={7} className="px-4 py-8"><EmptyState label="No subscription records found" /></td></tr>
                  ) : props.subscriptions.map((subscription, index) => {
                    const renewalDate = subscription.renewalDate || subscription.current_period_end || subscription.expires_at
                    const days = Number(subscription.daysUntilRenewal ?? 0)
                    const overdue = renewalDate && days < 0
                    const cycle = subscription.billing_cycle || subscription.plan_interval || 'monthly'
                    const mutating = props.mutating?.includes(subscription.id)

                    return (
                      <tr key={subscription.id} className="transition hover:bg-blue-500/[0.04]">
                        <td className="px-4 py-4">
                          <div className="flex min-w-0 items-center gap-3">
                            <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br ${tenantAvatarTone(index)} font-mono text-sm font-black text-white`}>{subscriptionInitials(subscription)}</span>
                            <div className="min-w-0">
                              <div className="truncate font-bold text-slate-100">{subscriptionTenantName(subscription)}</div>
                              <div className="truncate text-xs text-slate-400">{subscriptionDomain(subscription)}</div>
                              <div className="font-mono text-xs text-slate-500">ID: {subscriptionDisplayId(subscription)}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <TenantPlanBadge plan={subscription.plan || 'starter'} />
                          <div className="mt-2 text-xs text-slate-300">{normalizeText(cycle)}</div>
                        </td>
                        <td className="px-4 py-4"><BillingStatus status={subscription.status || 'inactive'} /></td>
                        <td className="px-4 py-4 font-mono text-sm leading-6 text-slate-300">
                          <div className="text-base font-black text-white">{formatNumber(subscription.totalUsers || subscription.seats || 1)} <span className="mx-2 text-slate-500">/</span> {formatNumber(subscription.totalDevices || 0)}</div>
                          <div className="grid grid-cols-2 gap-3 font-sans text-xs text-slate-400"><span>Users</span><span>Devices</span></div>
                        </td>
                        <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                          <div>{formatShortDateTime(renewalDate).date}</div>
                          <div className={`text-xs ${overdue ? 'text-red-300' : days <= 20 ? 'text-amber-300' : 'text-slate-400'}`}>
                            {overdue ? `Overdue by ${Math.abs(days)} days` : renewalDate ? `In ${Math.max(0, days)} days` : 'No schedule'}
                          </div>
                        </td>
                        <td className="px-4 py-4 text-sm leading-6 text-slate-300">
                          <div className="font-mono font-black text-white">{formatBillingCurrency(subscription.amountCents || 0, subscription.currency || 'USD')}</div>
                          <div className="text-xs text-slate-400">{subscription.currency || 'USD'} / {cycle.includes('annual') || cycle.includes('year') ? 'year' : 'month'}</div>
                        </td>
                        <td className="px-4 py-4">
                          <div className="flex justify-center">
                            {mutating ? <RefreshCw className="h-5 w-5 animate-spin text-blue-300" /> : <BillingActionsMenu subscription={subscription} subscriptionAction={props.subscriptionAction} />}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex flex-col gap-3 border-t border-[#12305a] bg-[#041227] px-4 py-3 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
              <span>Showing {formatNumber(pageStart)} to {formatNumber(pageEnd)} of {formatNumber(totalRows)} subscriptions</span>
              <PaginationControls page={props.pagination.page} totalPages={props.pagination.totalPages} onPage={(page) => void props.refreshSubscriptions(page)} />
            </div>
          </div>

          <div className="grid gap-3 rounded-lg border border-[#0f274d] bg-[#07162d] px-5 py-3 text-xs font-semibold text-slate-400 md:grid-cols-4">
            <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" />All payments are secured</span>
            <span className="inline-flex items-center gap-2"><Lock className="h-4 w-4 text-emerald-300" />PCI DSS compliant</span>
            <span className="inline-flex items-center gap-2"><Shield className="h-4 w-4 text-blue-300" />SOC 2 Type II certified</span>
            <span className="inline-flex items-center justify-end gap-2">Last updated: {timeAgo(props.subscriptionsLiveUpdatedAt)} <RefreshCw className={`h-4 w-4 ${props.sseConnected ? 'text-blue-300' : 'text-amber-300'}`} /></span>
          </div>
        </div>
      </div>
    </div>
  )
}

function securityMetric(metrics: Record<string, number> | undefined, key: string) {
  return Number(metrics?.[key] || 0)
}

function securitySeverityTone(severity?: string) {
  const normalized = String(severity || 'info').toLowerCase()
  if (normalized.includes('critical') || normalized.includes('high')) return 'border-red-400/20 bg-red-500/10 text-red-300'
  if (normalized.includes('medium')) return 'border-amber-400/20 bg-amber-500/10 text-amber-300'
  if (normalized.includes('low')) return 'border-emerald-400/20 bg-emerald-500/10 text-emerald-300'
  return 'border-blue-400/20 bg-blue-500/10 text-blue-300'
}

function sparkPath(values: number[], width = 112, height = 36) {
  const safe = values.length ? values : [0]
  const max = Math.max(1, ...safe)
  return safe.map((value, index) => {
    const x = safe.length === 1 ? width : (index / (safe.length - 1)) * width
    const y = height - ((value / max) * (height - 8)) - 4
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')
}

function SecuritySparkline({ values, color }: { values: number[]; color: string }) {
  return (
    <svg viewBox="0 0 112 36" className="h-9 w-28">
      <path d={sparkPath(values)} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function SecurityMetricCard({ icon: Icon, label, value, sub, detail, tone, values }: {
  icon: typeof Activity
  label: string
  value: string
  sub?: string
  detail?: ReactNode
  tone: 'violet' | 'red' | 'amber' | 'blue' | 'emerald'
  values: number[]
}) {
  const tones = {
    violet: { wrap: 'bg-violet-500/15 text-violet-300', line: '#8b5cf6' },
    red: { wrap: 'bg-red-500/15 text-red-300', line: '#ef4444' },
    amber: { wrap: 'bg-amber-500/15 text-amber-300', line: '#f59e0b' },
    blue: { wrap: 'bg-blue-500/15 text-blue-300', line: '#3b82f6' },
    emerald: { wrap: 'bg-emerald-500/15 text-emerald-300', line: '#10b981' },
  }[tone]

  return (
    <div className="min-h-[132px] overflow-hidden rounded-lg border border-[#12305a] bg-gradient-to-br from-[#071a35] to-[#061327] p-4 shadow-[0_16px_38px_rgba(0,0,0,0.28)]">
      <div className="flex items-start gap-3">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full ${tones.wrap}`}>
          <Icon className="h-6 w-6" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-slate-400">{label}</div>
          <div className="mt-2 font-mono text-2xl font-black text-white">{value}</div>
          {sub && <div className="mt-2 text-xs font-bold text-slate-400">{sub}</div>}
          {detail && <div className="mt-2 text-xs font-bold">{detail}</div>}
        </div>
      </div>
      <div className="mt-2 flex justify-end">
        <SecuritySparkline values={values} color={tones.line} />
      </div>
    </div>
  )
}

function SecurityPanel({ title, action, children, className = '' }: { title: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-[#12305a] bg-[#061329] p-4 shadow-[0_16px_38px_rgba(0,0,0,0.22)] ${className}`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h3 className="text-sm font-black text-white">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  )
}

function SecurityRadar({ posture }: { posture: Array<{ label: string; score: number }> }) {
  const rows = posture.length ? posture : []
  const center = 120
  const radius = 86
  const points = rows.map((item, index) => {
    const angle = (-90 + (360 / rows.length) * index) * (Math.PI / 180)
    const scaled = radius * (Number(item.score || 0) / 100)
    return `${center + Math.cos(angle) * scaled},${center + Math.sin(angle) * scaled}`
  }).join(' ')
  const grid = [0.25, 0.5, 0.75, 1].map((ratio) => rows.map((_item, index) => {
    const angle = (-90 + (360 / rows.length) * index) * (Math.PI / 180)
    return `${center + Math.cos(angle) * radius * ratio},${center + Math.sin(angle) * radius * ratio}`
  }).join(' '))

  return (
    <div className="grid gap-3 md:grid-cols-[260px_1fr]">
      <svg viewBox="0 0 240 240" className="mx-auto h-64 w-64">
        {grid.map((poly, index) => <polygon key={index} points={poly} fill="none" stroke="#1d3154" strokeWidth="1" />)}
        {rows.map((_item, index) => {
          const angle = (-90 + (360 / rows.length) * index) * (Math.PI / 180)
          return <line key={index} x1={center} y1={center} x2={center + Math.cos(angle) * radius} y2={center + Math.sin(angle) * radius} stroke="#1d3154" strokeWidth="1" />
        })}
        {points && <polygon points={points} fill="rgba(124,58,237,0.24)" stroke="#8b5cf6" strokeWidth="3" />}
        {rows.map((item, index) => {
          const angle = (-90 + (360 / rows.length) * index) * (Math.PI / 180)
          const x = center + Math.cos(angle) * radius * (Number(item.score || 0) / 100)
          const y = center + Math.sin(angle) * radius * (Number(item.score || 0) / 100)
          return <circle key={item.label} cx={x} cy={y} r="4" fill="#8b5cf6" />
        })}
      </svg>
      <div className="grid grid-cols-2 content-center gap-3 text-xs">
        {rows.map((item) => (
          <div key={item.label} className="rounded-lg border border-[#12305a] bg-[#07162d] p-3">
            <div className="font-bold text-slate-300">{item.label}</div>
            <div className="mt-1 font-mono text-lg font-black text-white">{formatNumber(item.score)}%</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ThreatActivityChart({ data }: { data: Array<Record<string, number | string>> }) {
  const rows = data.length ? data : [{ label: '00:00', critical: 0, high: 0, medium: 0, low: 0, info: 0 }]
  const series = [
    ['critical', '#ef4444'],
    ['high', '#f59e0b'],
    ['medium', '#facc15'],
    ['low', '#10b981'],
    ['info', '#3b82f6'],
  ] as const
  const width = 540
  const height = 220
  const padding = 30
  const max = Math.max(1, ...rows.flatMap((row) => series.map(([key]) => Number(row[key] || 0))))
  const pathFor = (key: string) => rows.map((row, index) => {
    const x = padding + (index / Math.max(1, rows.length - 1)) * (width - padding * 2)
    const y = height - padding - (Number(row[key] || 0) / max) * (height - padding * 2)
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-[260px] w-full">
        {[0, 1, 2, 3, 4].map((step) => {
          const y = padding + step * ((height - padding * 2) / 4)
          return <line key={step} x1={padding} y1={y} x2={width - padding} y2={y} stroke="#1d3154" strokeDasharray="3 3" />
        })}
        {rows.map((row, index) => {
          const x = padding + (index / Math.max(1, rows.length - 1)) * (width - padding * 2)
          return (
            <g key={String(row.label)}>
              <line x1={x} y1={padding} x2={x} y2={height - padding} stroke="#132948" strokeDasharray="3 3" />
              <text x={x} y={height - 8} textAnchor="middle" fill="#94a3b8" fontSize="11">{String(row.label)}</text>
            </g>
          )
        })}
        {series.map(([key, color]) => <path key={key} d={pathFor(key)} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />)}
      </svg>
      <div className="flex flex-wrap gap-4 text-xs font-bold text-slate-400">
        {series.map(([key, color]) => <span key={key} className="inline-flex items-center gap-2"><span className="h-1.5 w-4 rounded-full" style={{ background: color }} />{normalizeText(key)}</span>)}
      </div>
    </div>
  )
}

function SecurityDonut({ rows, center, sub }: { rows: Array<{ label: string; count: number }>; center: string; sub: string }) {
  const total = Math.max(1, rows.reduce((sum, row) => sum + Number(row.count || 0), 0))
  const colors = ['#8b5cf6', '#ef4444', '#3b82f6', '#10b981', '#facc15', '#64748b']
  const circumference = 2 * Math.PI * 42
  let offset = 0

  return (
    <div className="grid items-center gap-4 md:grid-cols-[150px_1fr]">
      <svg viewBox="0 0 120 120" className="h-40 w-40">
        <circle cx="60" cy="60" r="42" fill="none" stroke="#142b4e" strokeWidth="18" />
        {rows.map((row, index) => {
          const length = (Number(row.count || 0) / total) * circumference
          const circle = <circle key={row.label} cx="60" cy="60" r="42" fill="none" stroke={colors[index % colors.length]} strokeWidth="18" strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={-offset} transform="rotate(-90 60 60)" />
          offset += length
          return circle
        })}
        <text x="60" y="58" textAnchor="middle" fill="#fff" fontSize="20" fontWeight="800">{center}</text>
        <text x="60" y="74" textAnchor="middle" fill="#94a3b8" fontSize="9">{sub}</text>
      </svg>
      <div className="space-y-3">
        {rows.map((row, index) => (
          <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-3 text-sm">
            <span className="inline-flex items-center gap-2 text-slate-300"><span className="h-2 w-2 rounded-full" style={{ background: colors[index % colors.length] }} />{row.label}</span>
            <span className="font-mono font-black text-white">{formatNumber(row.count)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SecurityTab({ security, savePolicy, policy, setPolicy, refreshSecurity, sseConnected, securityLiveUpdatedAt }: {
  security: ReturnType<typeof useAdminDashboard>['security']
  savePolicy: (payload: Record<string, unknown>) => Promise<unknown>
  policy: { policyKey: string; name: string; category: string; status: string; enforcementLevel: string; description: string }
  setPolicy: (value: { policyKey: string; name: string; category: string; status: string; enforcementLevel: string; description: string }) => void
  refreshSecurity: () => Promise<void>
  sseConnected: boolean
  securityLiveUpdatedAt: string | null
}) {
  const metrics = security?.metrics || {}
  const activity = security?.threatActivity || []
  const posture = security?.posture || []
  const adminOverview = security?.adminOverview || []
  const adminStatus = security?.adminAccessStatus || []
  const totalAdmins = securityMetric(metrics, 'adminAccounts')
  const totalStatus = Math.max(1, adminStatus.reduce((sum, row) => sum + Number(row.count || 0), 0))
  const score = securityMetric(metrics, 'securityScore')
  const threatSpark = activity.map((row) => Number(row.critical || 0) + Number(row.high || 0) + Number(row.medium || 0) + Number(row.low || 0))
  const vulnSpark = activity.map((row) => Number(row.critical || 0) + Number(row.high || 0))
  const scoreSpark = posture.map((row) => Number(row.score || 0))
  const infoSpark = activity.map((row) => Number(row.info || 0))
  const mfaCoverage = securityMetric(metrics, 'mfaCoverage')

  const addSecurityWidget = () => {
    const next = {
      ...policy,
      policyKey: 'security-dashboard-widget',
      name: 'Security dashboard widget',
      category: 'security',
      status: 'enabled',
      enforcementLevel: 'monitor',
      description: 'Owner-managed security dashboard widget configuration.',
    }
    setPolicy(next)
    void savePolicy(next)
  }

  return (
    <div className="overflow-hidden rounded-lg border border-[#12305a] bg-[#020b19] shadow-[0_24px_80px_rgba(0,0,0,0.35)]">
      <div className="flex flex-col gap-4 border-b border-[#12305a] bg-gradient-to-r from-[#06162d] to-[#020b19] px-5 py-4 xl:flex-row xl:items-center xl:justify-between">
        <div>
          <h2 className="text-2xl font-black tracking-tight text-white">Security Dashboard</h2>
          <p className="mt-1 text-sm text-slate-400">Real-time security posture and administrator overview</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200"><Calendar className="h-4 w-4" />Last 24 hours <ChevronDown className="h-4 w-4" /></button>
          <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 transition hover:border-blue-400" onClick={() => void refreshSecurity()}><RefreshCw className="h-4 w-4" />Refresh</button>
          <button type="button" className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#12305a] bg-[#061329] px-4 text-sm font-bold text-slate-200 transition hover:border-blue-400" onClick={addSecurityWidget}><Plus className="h-4 w-4" />Add Widget</button>
          <button type="button" className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#12305a] bg-[#061329] text-slate-200"><HelpCircle className="h-4 w-4" /></button>
          <button type="button" className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-[#12305a] bg-[#061329] text-slate-200">
            <Bell className="h-4 w-4" />
            <span className="absolute -right-1 -top-1 rounded-full bg-rose-500 px-1.5 text-[10px] font-black text-white">12</span>
          </button>
          <div className="rounded-lg border border-[#12305a] bg-[#061329] px-4 py-2 text-sm">
            <div className="font-black text-white">Super Admin</div>
            <div className="text-xs text-slate-400">Full Access</div>
          </div>
        </div>
      </div>

      <div className="grid gap-4 p-5 xl:grid-cols-6">
        <SecurityMetricCard icon={ShieldCheck} label="Security Score" value={`${formatNumber(score)} / 100`} sub="Excellent" tone="violet" values={scoreSpark} detail={<span className="text-blue-300">↑ 8 pts vs yesterday</span>} />
        <SecurityMetricCard icon={Target} label="Active Threats" value={formatNumber(securityMetric(metrics, 'activeThreats'))} tone="red" values={threatSpark} detail={<span><span className="text-red-300">High: {formatNumber(securityMetric(metrics, 'highThreats'))}</span><span className="ml-3 text-amber-300">Medium: {formatNumber(securityMetric(metrics, 'mediumThreats'))}</span><span className="ml-3 text-emerald-300">Low: {formatNumber(securityMetric(metrics, 'lowThreats'))}</span></span>} />
        <SecurityMetricCard icon={Bug} label="Critical Vulnerabilities" value={formatNumber(securityMetric(metrics, 'criticalVulnerabilities'))} sub="↓ 15% vs yesterday" tone="amber" values={vulnSpark} />
        <SecurityMetricCard icon={Users} label="Users" value={formatNumber(securityMetric(metrics, 'users'))} sub={`↑ ${formatNumber(securityMetric(metrics, 'usersDelta'))} vs yesterday`} tone="blue" values={infoSpark} />
        <SecurityMetricCard icon={Crown} label="Admin Accounts" value={formatNumber(totalAdmins)} sub="All privileged accounts" tone="violet" values={adminOverview.map((row) => Number(row.count || 0))} />
        <SecurityMetricCard icon={LockKeyhole} label="MFA Coverage" value={`${formatNumber(mfaCoverage)}%`} sub="↑ 6% vs yesterday" tone="emerald" values={[mfaCoverage, ...scoreSpark]} />
      </div>

      <div className="grid gap-4 px-5 pb-5 xl:grid-cols-2">
        <SecurityPanel title="Security Posture Overview" action={<select className="h-8 rounded-md border border-[#12305a] bg-[#061329] px-3 text-xs font-bold text-slate-300"><option>NIST CSF 2.0</option></select>}>
          <SecurityRadar posture={posture} />
        </SecurityPanel>
        <SecurityPanel title="Threat Activity" action={<select className="h-8 rounded-md border border-[#12305a] bg-[#061329] px-3 text-xs font-bold text-slate-300"><option>By Severity</option></select>}>
          <ThreatActivityChart data={activity} />
        </SecurityPanel>
      </div>

      <div className="grid gap-4 px-5 pb-5 xl:grid-cols-2">
        <SecurityPanel title="Top Threats" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <div className="space-y-3">
            <div className="grid grid-cols-[1fr_90px_52px] gap-3 border-b border-[#12305a] pb-2 text-xs font-black uppercase text-slate-500">
              <span>Threat</span><span>Severity</span><span className="text-right">Count</span>
            </div>
            {(security?.topThreats || []).length === 0 ? <EmptyState label="No active threat telemetry" /> : security!.topThreats!.map((threat) => (
              <div key={threat.title} className="grid grid-cols-[1fr_90px_52px] items-center gap-3 text-sm">
                <div className="min-w-0">
                  <div className="truncate font-bold text-slate-200">{threat.title}</div>
                  <div className="truncate text-xs text-slate-500">{threat.detail}</div>
                </div>
                <span className={`inline-flex justify-center rounded-md border px-2 py-1 text-xs font-black ${securitySeverityTone(threat.severity)}`}>{normalizeText(threat.severity)}</span>
                <span className="text-right font-mono font-black text-slate-200">{formatNumber(threat.count)}</span>
              </div>
            ))}
          </div>
        </SecurityPanel>
        <SecurityPanel title="Administrator Overview" action={<button type="button" className="text-xs font-bold text-blue-300">View All Admins</button>}>
          <SecurityDonut rows={adminOverview} center={formatNumber(totalAdmins)} sub="Total Admins" />
        </SecurityPanel>
      </div>

      <div className="grid gap-4 px-5 pb-5 xl:grid-cols-2">
        <SecurityPanel title="Admin Access by Status" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <SecurityDonut rows={adminStatus} center={formatNumber(totalAdmins)} sub="Admin Accounts" />
        </SecurityPanel>
        <SecurityPanel title="Recent Admin Activities" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <div className="space-y-3">
            {(security?.recentAdminActivities || []).length === 0 ? <EmptyState label="No recent admin activity" /> : security!.recentAdminActivities!.map((activity) => (
              <div key={String(activity.id)} className="grid grid-cols-[1fr_92px_72px_90px] items-center gap-3 text-xs">
                <div className="min-w-0">
                  <div className="truncate font-bold text-slate-200">{String(activity.title || 'Admin activity')}</div>
                  <div className="truncate text-slate-500">{String(activity.detail || 'Security operation')}</div>
                </div>
                <span className="rounded-md bg-white/[0.06] px-2 py-1 text-center font-bold text-slate-300">{String(activity.tag || 'Security')}</span>
                <span className="text-slate-400">{timeAgo(String(activity.createdAt || ''))}</span>
                <span className="truncate text-right font-mono text-slate-400">{String(activity.ip || 'unknown')}</span>
              </div>
            ))}
          </div>
        </SecurityPanel>
      </div>

      <div className="grid gap-4 px-5 pb-5 xl:grid-cols-2">
        <SecurityPanel title="Critical Alerts" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <div className="space-y-3">
            {(security?.criticalAlerts || []).length === 0 ? <EmptyState label="No critical alerts in the selected window" /> : security!.criticalAlerts!.map((alert) => (
              <div key={String(alert.id)} className="grid grid-cols-[1fr_64px] items-center gap-3 text-xs">
                <div className="truncate text-slate-300"><AlertTriangle className="mr-2 inline h-4 w-4 text-red-400" />{String(alert.title || alert.detail || 'Critical alert')}</div>
                <span className="text-right text-slate-500">{timeAgo(String(alert.createdAt || ''))}</span>
              </div>
            ))}
          </div>
        </SecurityPanel>
        <SecurityPanel title="Compliance Status" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <div className="grid gap-3 md:grid-cols-3">
            {(security?.complianceStatus || []).map((item) => (
              <div key={item.label} className="rounded-lg border border-[#12305a] bg-[#07162d] p-3 text-center">
                <ShieldCheck className="mx-auto h-6 w-6 text-emerald-300" />
                <div className="mt-2 text-xs font-black text-slate-200">{item.label}</div>
                <div className="text-xs text-emerald-300">{item.status}</div>
                <div className="mx-auto mt-2 h-1.5 w-20 overflow-hidden rounded-full bg-white/10">
                  <div className="h-full rounded-full bg-emerald-400" style={{ width: `${Math.max(0, Math.min(100, item.score))}%` }} />
                </div>
                <div className="mt-1 font-mono text-xs font-black text-emerald-300">{formatNumber(item.score)}%</div>
              </div>
            ))}
          </div>
        </SecurityPanel>
      </div>

      <div className="px-5 pb-5">
        <SecurityPanel title="System Health" action={<button type="button" className="text-xs font-bold text-blue-300">View All</button>}>
          <div className="grid gap-3 md:grid-cols-4">
            {[
              ['Data Collectors', security?.systemHealth?.dataCollectors?.healthy || 0, security?.systemHealth?.dataCollectors?.total || 0, 'Healthy'],
              ['Integrations', security?.systemHealth?.integrations?.healthy || 0, security?.systemHealth?.integrations?.total || 0, 'Healthy'],
              ['Sensors', security?.systemHealth?.sensors?.healthy || 0, security?.systemHealth?.sensors?.total || 0, 'Healthy'],
              ['Storage', security?.systemHealth?.storage?.usedGb || 0, security?.systemHealth?.storage?.totalGb || 5, 'Used'],
            ].map(([label, healthy, total, state]) => (
              <div key={String(label)} className="border-r border-[#12305a] pr-3 last:border-r-0">
                <div className="text-xs text-slate-500">{String(label)}</div>
                <div className="mt-2 font-mono text-xl font-black text-white">{formatNumber(Number(healthy))} / {formatNumber(Number(total))}</div>
                <div className={`mt-1 text-xs font-bold ${String(state) === 'Used' ? 'text-amber-300' : 'text-emerald-300'}`}>● {String(state)}</div>
              </div>
            ))}
          </div>
        </SecurityPanel>
      </div>

      <div className="mx-5 mb-5 grid gap-3 rounded-lg border border-[#0f274d] bg-[#07162d] px-5 py-3 text-xs font-semibold text-slate-400 md:grid-cols-4">
        <span className="inline-flex items-center gap-2"><Activity className="h-4 w-4" />All times shown in UTC</span>
        <span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" />Security telemetry is live</span>
        <span className="inline-flex items-center gap-2"><Wifi className={`h-4 w-4 ${sseConnected ? 'text-emerald-300' : 'text-amber-300'}`} />SSE {sseConnected ? 'connected' : 'reconnecting'}</span>
        <span className="inline-flex items-center justify-end gap-2">Last updated: {timeAgo(securityLiveUpdatedAt)} <RefreshCw className={`h-4 w-4 ${sseConnected ? 'text-blue-300' : 'text-amber-300'}`} /></span>
      </div>
    </div>
  )
}

function GovernanceTab({ security, generateEvidence, stats }: {
  security: ReturnType<typeof useAdminDashboard>['security']
  generateEvidence: (payload: Record<string, unknown>) => Promise<unknown>
  stats: ReturnType<typeof useAdminDashboard>['stats']
}) {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <KpiCard icon={ShieldCheck} label="Compliance Score" value={`${formatNumber(stats?.kpis?.complianceScore)}%`} />
        <KpiCard icon={FileCheck} label="Evidence Packages" value={formatNumber(security?.evidence?.length)} />
        <KpiCard icon={UserCog} label="Governance Policies" value={formatNumber(security?.policies?.length)} />
      </div>
      <div className="q-card p-5">
        <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-black text-[var(--qg-text-primary)]">Compliance Evidence Generation</h3>
            <p className="text-sm text-[var(--qg-text-secondary)]">Generate an owner-stamped operational evidence record from the live dashboard state.</p>
          </div>
          <button type="button" className="q-btn q-btn-primary" onClick={() => void generateEvidence({ title: 'Owner compliance evidence snapshot', framework: 'QGuardHelix Enterprise Governance', metadata: { kpis: stats?.kpis || {} } })}>
            <FileCheck className="h-4 w-4" />
            Generate Evidence
          </button>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <EventList title="Policies" rows={security?.policies || []} />
          <EventList title="Evidence" rows={security?.evidence || []} />
        </div>
      </div>
    </div>
  )
}

function historyRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function historyText(value: unknown, fallback: string) {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function historyLabel(value: unknown, fallback: string) {
  const normalized = historyText(value, fallback).replace(/^admin\./, '').replace(/[._-]+/g, ' ').trim()
  return normalized
    ? normalized.replace(/\b\w/g, (letter) => letter.toUpperCase())
    : fallback
}

function historyActor(activity: AdminActivity) {
  const row = historyRecord(activity.row)
  const details = historyRecord(row.details)
  return historyText(activity.actorEmail || activity.administrator || row.actor_email || details.actorEmail || row.user_email || row.user_id, 'Unknown administrator')
}

function historyTarget(activity: AdminActivity) {
  const row = historyRecord(activity.row)
  const details = historyRecord(row.details)
  return historyText(activity.target || details.targetEmail || details.targetName || row.entity_id || row.resource_name || row.name || row.id, 'Platform')
}

function historyTargetMeta(activity: AdminActivity) {
  const row = historyRecord(activity.row)
  const details = historyRecord(row.details)
  const type = historyLabel(activity.targetType || row.entity_type || details.targetType || activity.source, 'Record')
  const id = historyText(activity.targetId || row.entity_id || details.targetUserId, '')
  return id ? `${type} ${id}` : type
}

function HistoryTab({ activities, exportReport }: { activities: AdminActivity[]; exportReport: () => void }) {
  const administratorActions = activities.filter((activity) => (
    activity.source === 'admin_audit' || String(activity.action || '').startsWith('admin.')
  ))
  const userActions = administratorActions.filter((activity) => String(activity.action || '').includes('.user.'))
  const latestAction = activities[0]?.created_at

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        <KpiCard icon={Radio} label="History Records" value={formatNumber(activities.length)} />
        <KpiCard icon={UserCog} label="Admin Actions" value={formatNumber(administratorActions.length)} />
        <KpiCard icon={Users} label="User Actions" value={formatNumber(userActions.length)} sub={timeAgo(latestAction)} />
      </div>

      <div className="q-card overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-[var(--qg-border)] p-5 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-black text-[var(--qg-text-primary)]">Administrator Audit History</h3>
            <p className="text-sm text-[var(--qg-text-secondary)]">Who performed each action, what changed, and when it happened.</p>
          </div>
          <button type="button" className="q-btn q-btn-primary" onClick={exportReport}><Download className="h-4 w-4" />Export</button>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-[var(--qg-border)]">
            <thead className="bg-white/[0.03] text-left text-[11px] font-black uppercase tracking-[0.12em] text-[var(--qg-text-muted)]">
              <tr>
                <th className="px-5 py-3">When</th>
                <th className="px-5 py-3">Administrator</th>
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Target</th>
                <th className="px-5 py-3">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--qg-border)]">
              {activities.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-6">
                    <EmptyState label="No administrator history found" />
                  </td>
                </tr>
              ) : activities.map((activity, index) => (
                <tr key={activity.id || `${activity.source}-${activity.created_at || index}`} className="align-top transition hover:bg-white/[0.03]">
                  <td className="whitespace-nowrap px-5 py-4">
                    <div className="font-mono text-xs font-bold text-[var(--qg-text-primary)]">{formatDate(activity.created_at)}</div>
                    <div className="mt-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--qg-text-muted)]">{timeAgo(activity.created_at)}</div>
                  </td>
                  <td className="px-5 py-4">
                    <div className="max-w-[220px] truncate text-sm font-bold text-[var(--qg-text-primary)]">{historyActor(activity)}</div>
                    <div className="mt-1 text-[11px] uppercase tracking-[0.08em] text-[var(--qg-text-muted)]">{historyText(activity.ipAddress, 'IP not captured')}</div>
                  </td>
                  <td className="px-5 py-4">
                    <div className="text-sm font-black text-[var(--qg-text-primary)]">{historyLabel(activity.action || activity.title, 'Activity')}</div>
                    <div className="mt-1 max-w-[320px] text-xs text-[var(--qg-text-secondary)]">{activity.detail || 'Recorded administrator activity'}</div>
                  </td>
                  <td className="px-5 py-4">
                    <div className="max-w-[260px] break-words text-sm font-bold text-[var(--qg-text-primary)]">{historyTarget(activity)}</div>
                    <div className="mt-1 break-all font-mono text-[11px] text-[var(--qg-text-muted)]">{historyTargetMeta(activity)}</div>
                  </td>
                  <td className="whitespace-nowrap px-5 py-4">
                    <StatusBadge value={activity.result || activity.severity || 'recorded'} />
                    <div className="mt-2 text-[11px] font-bold uppercase tracking-[0.08em] text-[var(--qg-text-muted)]">{historyLabel(activity.source, 'Source')}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function EventList({ title, rows }: { title: string; rows: unknown[] }) {
  return (
    <div className="rounded-lg border border-[var(--qg-border)] bg-white/[0.03] p-4">
      <h4 className="mb-3 text-xs font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{title}</h4>
      <div className="space-y-2">
        {rows.length === 0 ? <EmptyState label="No live records found" /> : rows.slice(0, 12).map((item, index) => {
          const row = item && typeof item === 'object' && !Array.isArray(item) ? item as Record<string, unknown> : {}
          return (
            <div key={String(row.id || row.created_at || index)} className="rounded-lg border border-[var(--qg-border)] bg-black/10 p-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-bold text-[var(--qg-text-primary)]">{String(row.title || row.action || row.event_type || row.policy_key || row.name || row.source || 'Activity')}</div>
                  <div className="mt-1 truncate text-xs text-[var(--qg-text-secondary)]">{String(row.detail || row.message || row.description || row.status || row.entity_type || 'Supabase record')}</div>
                </div>
                <StatusBadge value={String(row.severity || row.status || row.source || 'info')} />
              </div>
              <div className="mt-2 font-mono text-[10px] text-[var(--qg-text-muted)]">{formatDate(String(row.created_at || row.updated_at || ''))}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function AdminDashboard() {
  return (
    <AdminRoute>
      <AdminDashboardContent />
    </AdminRoute>
  )
}
