import { useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Building2,
  Crown,
  CreditCard,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
  Wifi,
  WifiOff,
} from 'lucide-react'
import { AdminRoute } from '@/components/admin-route'
import { useAdminDashboard } from '@/hooks/use-admin-dashboard'
import { UsersTab } from './_users/UsersTab'
import { RolesTab } from './_roles/RolesTab'
import { TenantsTab } from './_tenants/TenantsTab'
import { BillingTab } from './_billing/BillingTab'
import { SecurityTab } from './_security/SecurityTab'
import { GovernanceTab } from './_governance/GovernanceTab'
import { HistoryTab } from './_history/HistoryTab'
import { Notices } from './_shared/console'

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

function formatNumber(value?: number | null) {
  // null = explicitly not measured (e.g. sessions when Supabase Auth is unreadable).
  if (value === null) return '—'
  return new Intl.NumberFormat('en-US').format(Number(value || 0))
}

function formatCurrency(value?: number | null) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(Number(value || 0) / 100)
}

function normalizeText(value?: string | null) {
  return value ? value.replace(/_/g, ' ') : 'none'
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

function EmptyNote({ label }: { label: string }) {
  return <div className="rounded-lg border border-dashed border-[var(--qg-border)] p-4 text-center text-xs text-[var(--qg-text-muted)]">{label}</div>
}

function MiniBars({ data, label }: { data?: Array<{ label: string; count: number }>; label: string }) {
  const rows = data || []
  const max = Math.max(1, ...rows.map((row) => row.count))
  return (
    <div className="q-card p-5">
      <div className="mb-4 flex items-center justify-between gap-4">
        <h3 className="text-sm font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{label}</h3>
        <span className="rounded-full border border-[var(--qg-border)] px-2.5 py-1 font-mono text-[10px] text-[var(--qg-text-muted)]">last 7 days</span>
      </div>
      <div className="space-y-3">
        {rows.length === 0 ? (
          <EmptyNote label="No records yet" />
        ) : rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[84px_1fr_42px] items-center gap-3 text-xs">
            <span className="truncate text-[var(--qg-text-muted)]">{row.label}</span>
            <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full bg-gradient-to-r from-[var(--color-gold)] to-white" style={{ width: `${row.count ? Math.max(5, (row.count / max) * 100) : 0}%` }} />
            </div>
            <span className="text-right font-mono text-[var(--qg-text-primary)]">{row.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SummaryCard({ title, rows }: { title: string; rows?: Array<{ label: string; count: number }> }) {
  const total = Math.max(1, ...(rows || []).map((row) => row.count))
  return (
    <div className="q-card p-5">
      <h3 className="mb-4 text-sm font-black uppercase tracking-[0.14em] text-[var(--qg-text-primary)]">{title}</h3>
      <div className="space-y-3">
        {!rows?.length ? <EmptyNote label="No records found" /> : rows.map((row) => (
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

function AdminDashboardContent() {
  const admin = useAdminDashboard()
  const [activeTab, setActiveTab] = useState<AdminTab>('overview')
  const kpis = admin.stats?.kpis || {}

  const missingTables = useMemo(() => (admin.stats?.realtime?.unavailableTables || []).slice(0, 6), [admin.stats?.realtime?.unavailableTables])

  // Cross-tab navigation: a count in one tab opens the matching rows in Users.
  const openUsers = (patch: Parameters<typeof admin.setUserQuery>[0]) => {
    admin.resetUserQuery()
    admin.setUserQuery(patch)
    setActiveTab('users')
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
                Owner-only control of users, roles, tenants, plans and billing, security posture, governance evidence and the administrator audit trail — every figure measured, every action audited.
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
            </div>
          </div>
        </header>

        {admin.error && (
          <div className="flex items-start gap-3 rounded-lg border border-red-400/30 bg-red-500/10 p-4 text-sm text-red-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1">{admin.error}</span>
            <button type="button" className="q-btn q-btn-ghost" onClick={() => admin.setError(null)}>Dismiss</button>
          </div>
        )}

        {missingTables.length > 0 && (
          <div className="rounded-lg border border-amber-400/30 bg-amber-500/10 p-4 text-xs text-amber-100">
            Some Supabase tables are not available yet: {missingTables.join(', ')}. Apply the admin schema migration to unlock the full operational view.
          </div>
        )}

        <nav className="adm-tabs flex flex-wrap gap-2 p-1" aria-label="Administration sections">
          {tabs.map((tab) => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button key={tab.id} type="button" aria-current={isActive ? 'page' : undefined} className={`q-btn ${isActive ? 'q-btn-primary' : 'q-btn-ghost'}`} onClick={() => setActiveTab(tab.id)}>
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>

        {activeTab === 'overview' && (
          admin.loading && !admin.stats ? (
            <div className="q-card p-8 text-center text-sm text-[var(--qg-text-secondary)]">Loading platform overview…</div>
          ) : (
            <div className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                <KpiCard icon={Users} label="Total Users" value={formatNumber(kpis.totalUsers)} sub={kpis.activeSessions === null ? 'Live sessions not measured' : `${formatNumber(kpis.activeSessions)} live sessions · ${formatNumber(kpis.activeUsers)} active in 30 days`} />
                <KpiCard icon={Building2} label="Tenants" value={formatNumber(kpis.totalTenants)} sub={`${formatNumber(kpis.activeTenants)} not disabled`} />
                <KpiCard icon={CreditCard} label="Collected · 7 days" value={formatCurrency(kpis.subscriptionRevenue)} sub={`${formatNumber(kpis.activeSubscriptions)} active subscriptions`} />
                <KpiCard icon={ShieldCheck} label="Migration progress" value={`${formatNumber(kpis.migrationProgress)}%`} sub={`${formatNumber(kpis.completedScans)} completed scans`} />
                <KpiCard icon={AlertTriangle} label="Critical / high events" value={formatNumber(kpis.criticalAlerts)} sub="security_events · latest 1000" />
              </div>
              <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
                <MiniBars label="New users" data={admin.stats?.charts?.userGrowth} />
                <MiniBars label="Admin + security events" data={admin.stats?.charts?.tenantActivity} />
                <MiniBars label="Vulnerability updates" data={admin.stats?.charts?.vulnerabilityTrend} />
                <MiniBars label="Subscription changes" data={admin.stats?.charts?.subscriptionChanges} />
              </div>
              <div className="grid gap-4 lg:grid-cols-3">
                <SummaryCard title="Subscription status" rows={admin.stats?.summaries?.subscriptionStatus} />
                <SummaryCard title="Scan status" rows={admin.stats?.summaries?.scanStatus} />
                <SummaryCard title="Compliance evidence status" rows={admin.stats?.summaries?.complianceStatus} />
              </div>
            </div>
          )
        )}

        {activeTab === 'users' && <UsersTab admin={admin} />}
        {activeTab === 'roles' && <RolesTab admin={admin} onViewHolders={(role) => openUsers({ role })} />}
        {activeTab === 'tenants' && <TenantsTab admin={admin} onViewMembers={(tenant) => openUsers({ tenant })} />}
        {activeTab === 'subscriptions' && <BillingTab admin={admin} />}
        {activeTab === 'security' && <SecurityTab admin={admin} onOpenUser={(email) => openUsers({ search: email })} />}
        {activeTab === 'governance' && <GovernanceTab admin={admin} />}
        {activeTab === 'history' && <HistoryTab admin={admin} />}
      </div>
      <Notices admin={admin} />
    </section>
  )
}

export default function AdminDashboard() {
  return (
    <AdminRoute>
      <AdminDashboardContent />
    </AdminRoute>
  )
}
