import { useMemo, useState } from 'react'
import {
  AlertTriangle,
  ArrowDownWideNarrow,
  ArrowUpWideNarrow,
  Ban,
  Building2,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CreditCard,
  Download,
  Eye,
  KeyRound,
  Lock,
  LogOut,
  MailCheck,
  MoreHorizontal,
  PauseCircle,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserCog,
  UserRound,
  Users,
  Activity,
  X,
  Info,
} from 'lucide-react'
import { DEFAULT_USER_QUERY, type AdminDashboard, type AdminUser, type UserDirectoryQuery } from '@/hooks/use-admin-dashboard'
import { ActionMenu, Chip, SelectField, VIEWER_TIME_ZONE, formatCount, initials, timeAgo, useNow, type MenuEntry } from '../_shared/primitives'
import { ActivityCell, MfaBadge, PlanBadge, RoleBadge, StatusBadge } from './badges'
import { UserDialogs, type UserDialogState } from './UserDialogs'
import { UserDetailDrawer } from './UserDetailDrawer'
import { Kpi } from '../_shared/console'

const MENU_ICON = 'h-4 w-4'

export function UsersTab({ admin }: { admin: AdminDashboard }) {
  const [dialog, setDialog] = useState<UserDialogState | null>(null)
  const now = useNow()
  const meta = admin.usersDirectory
  const stats = meta?.stats
  const query = admin.userQuery
  const pagination = admin.usersPagination
  const activeFilterCount = (Object.keys(DEFAULT_USER_QUERY) as Array<keyof UserDirectoryQuery>)
    .filter((key) => key !== 'sort' && key !== 'order' && query[key] !== DEFAULT_USER_QUERY[key]).length
  const failingChecks = meta?.integrity.filter((check) => !check.ok) || []

  const toggleFilter = (patch: Partial<UserDirectoryQuery>) => {
    const [key, value] = Object.entries(patch)[0] as [keyof UserDirectoryQuery, string]
    admin.setUserQuery({ [key]: query[key] === value ? DEFAULT_USER_QUERY[key] : value })
  }

  const menuFor = useMemo(() => (user: AdminUser): MenuEntry[] => {
    const ownerReason = 'The owner account is protected'
    const blocked = user.status === 'suspended' || user.status === 'disabled'
    const entries: MenuEntry[] = [
      { kind: 'item', label: 'View details', icon: <Eye className={MENU_ICON} />, onSelect: () => admin.openUserDetail(user.id) },
      { kind: 'group', label: 'Access' },
      { kind: 'item', label: 'Change role…', description: `Currently ${user.roleLabel}`, icon: <UserCog className={MENU_ICON} />, disabled: user.isOwner, disabledReason: 'The owner role is fixed', onSelect: () => setDialog({ kind: 'role', user }) },
      { kind: 'item', label: 'Assign tenant…', description: user.tenantName ? `Currently ${user.tenantName}` : 'No tenant', icon: <Building2 className={MENU_ICON} />, onSelect: () => setDialog({ kind: 'tenant', user }) },
      { kind: 'item', label: 'Manage plan…', description: user.access.providerManaged && user.access.isActive ? `Billed by ${user.access.providerLabel} — view only` : `Currently ${user.access.tierLabel}`, icon: <CreditCard className={MENU_ICON} />, disabled: user.isOwner, disabledReason: 'The owner has full access by design', onSelect: () => setDialog({ kind: 'plan', user }) },
      { kind: 'group', label: 'Security' },
      {
        kind: 'item',
        label: 'Sign out everywhere…',
        description: user.sessions.count === null ? 'Session count not measured' : `${formatCount(user.sessions.count)} live session${user.sessions.count === 1 ? '' : 's'}`,
        icon: <LogOut className={MENU_ICON} />,
        disabled: user.isOwner || user.sessions.count === 0,
        disabledReason: user.isOwner ? ownerReason : 'No live sessions',
        onSelect: () => setDialog({ kind: 'force_logout', user }),
      },
      { kind: 'item', label: 'Reset password…', description: 'Email a reset link or generate one', icon: <KeyRound className={MENU_ICON} />, disabled: !user.email, disabledReason: 'No email address', onSelect: () => setDialog({ kind: 'reset_password', user }) },
      user.mfa.required
        ? { kind: 'item', label: 'Remove MFA requirement…', icon: <ShieldOff className={MENU_ICON} />, onSelect: () => setDialog({ kind: 'mfa', user, action: 'mfa_relax' }) }
        : { kind: 'item', label: 'Require MFA…', description: user.mfa.state === 'enrolled' ? 'Already enrolled' : 'Flag until an authenticator is enrolled', icon: <ShieldCheck className={MENU_ICON} />, onSelect: () => setDialog({ kind: 'mfa', user, action: 'mfa_require' }) },
    ]
    if (user.status === 'pending_verification') {
      entries.push({ kind: 'item', label: 'Mark email verified…', icon: <MailCheck className={MENU_ICON} />, onSelect: () => setDialog({ kind: 'verify_email', user }) })
    }
    entries.push({ kind: 'group', label: 'Account' })
    if (blocked || (user.bannedUntil && Date.parse(user.bannedUntil) > Date.now())) {
      entries.push({ kind: 'item', label: 'Restore access…', description: 'Lift the sign-in block', icon: <CheckCircle2 className={MENU_ICON} />, onSelect: () => setDialog({ kind: 'status', user, action: 'restore' }) })
    }
    if (user.status !== 'suspended') {
      entries.push({ kind: 'item', label: 'Suspend…', description: 'Temporary block, ends sessions', icon: <PauseCircle className={MENU_ICON} />, disabled: user.isOwner, disabledReason: ownerReason, onSelect: () => setDialog({ kind: 'status', user, action: 'suspend' }) })
    }
    if (user.status !== 'disabled') {
      entries.push({ kind: 'item', label: 'Disable…', description: 'Long-term block, ends sessions', icon: <Ban className={MENU_ICON} />, disabled: user.isOwner, disabledReason: ownerReason, onSelect: () => setDialog({ kind: 'status', user, action: 'disable' }) })
    }
    entries.push(
      { kind: 'separator' },
      { kind: 'item', label: 'Delete user…', description: 'Permanent', danger: true, icon: <Trash2 className={MENU_ICON} />, disabled: user.isOwner, disabledReason: ownerReason, onSelect: () => setDialog({ kind: 'delete', user }) },
    )
    return entries
  }, [admin])

  const pageStart = pagination.total ? (pagination.page - 1) * pagination.limit + 1 : 0
  const pageEnd = Math.min(pagination.total, (pagination.page - 1) * pagination.limit + admin.users.length)
  // Until the first directory arrives (and nothing failed) the table is loading —
  // never "No users", which would be a false empty state.
  const initialLoading = !meta && !admin.usersError

  return (
    <div className="qgu space-y-5">
      {/* Header */}
      <div className="qgu-panel flex flex-col gap-4 p-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-black qgu-strong">Users</h2>
            <span className="inline-flex items-center gap-2 text-xs font-bold qgu-soft" role="status">
              <span className={`qgu-dot ${admin.sseConnected ? 'qgu-dot--live' : 'qgu-dot--off'}`} />
              {admin.sseConnected ? `Live · updated ${timeAgo(admin.usersLiveUpdatedAt, now)}` : 'Live updates reconnecting'}
            </span>
          </div>
          <p className="mt-1 text-sm qgu-soft">Every account on the platform — sign-in state, sessions and MFA from Supabase Auth, plan access from billing, controlled from one place.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ActionMenu
            label="Export users"
            trigger={<Download className="h-4 w-4" />}
            busy={Boolean(admin.mutating?.startsWith('export-users'))}
            entries={[
              { kind: 'group', label: `Export ${formatCount(pagination.total)} matching user${pagination.total === 1 ? '' : 's'}` },
              { kind: 'item', label: 'CSV (spreadsheet)', description: 'All matching rows, not just this page', icon: <Download className={MENU_ICON} />, onSelect: () => void admin.exportUsers('csv') },
              { kind: 'item', label: 'JSON (with KPIs + integrity)', description: 'Full directory model for evidence', icon: <Download className={MENU_ICON} />, onSelect: () => void admin.exportUsers('json') },
            ]}
          />
          <button type="button" className="qgu-btn" onClick={() => void admin.refreshUsers().catch(() => undefined)} disabled={admin.usersLoading}>
            <RefreshCw className={`h-4 w-4 ${admin.usersLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button type="button" className="qgu-btn qgu-btn--primary" onClick={() => setDialog({ kind: 'create' })}>
            <Plus className="h-4 w-4" />
            Add user
          </button>
        </div>
      </div>

      {/* KPIs — exact over the whole directory; click to filter */}
      {initialLoading ? (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }, (_, index) => <div key={index} className="qgu-skeleton h-[118px]" />)}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
          <Kpi icon={<Users className="h-4 w-4" />} label="Total users" value={formatCount(stats.totalUsers)} sub={`+${formatCount(stats.newLast30d)} joined in the last 30 days`} onClick={() => admin.resetUserQuery()} active={activeFilterCount === 0} />
          <Kpi
            icon={<Activity className="h-4 w-4" />}
            label="Active · 30 days"
            value={formatCount(stats.activity.active30d)}
            sub={`${formatCount(stats.activity.activeNow)} in the last hour · ${formatCount(stats.activity.never)} never signed in`}
            onClick={() => toggleFilter({ activity: 'active_30d' })}
            active={query.activity === 'active_30d'}
          />
          <Kpi
            icon={<KeyRound className="h-4 w-4" />}
            label="Plan access"
            value={formatCount(stats.access.withAccess)}
            sub={`${formatCount(stats.access.noAccess)} without a plan · ${formatCount(stats.access.byClass.complimentary + stats.access.byClass.manual)} comp/manual`}
            onClick={() => toggleFilter({ plan: 'no_access' })}
            active={query.plan === 'no_access'}
          />
          <Kpi
            icon={<ShieldCheck className="h-4 w-4" />}
            label="MFA enrolled"
            value={stats.mfa.enrolled === null ? '—' : `${formatCount(stats.mfa.enrolled)} / ${formatCount(stats.totalUsers)}`}
            sub={stats.mfa.enrolled === null ? 'Not measured (Supabase Auth unreadable)' : stats.mfa.requiredNotEnrolled ? `${formatCount(stats.mfa.requiredNotEnrolled)} required but not enrolled` : `${formatCount(stats.mfa.required)} required by policy`}
            subTone={stats.mfa.requiredNotEnrolled ? 'warn' : undefined}
            onClick={() => toggleFilter({ mfa: stats.mfa.requiredNotEnrolled ? 'required_not_enrolled' : 'not_enrolled' })}
            active={query.mfa !== 'all'}
          />
          <Kpi
            icon={<Lock className="h-4 w-4" />}
            label="Blocked"
            value={formatCount(stats.status.suspended + stats.status.disabled)}
            sub={stats.statusDrift ? `${formatCount(stats.statusDrift)} with status drift` : `${formatCount(stats.status.pending_verification)} unverified email`}
            subTone={stats.statusDrift ? 'warn' : undefined}
            onClick={() => toggleFilter({ status: stats.statusDrift ? 'drift' : 'suspended' })}
            active={query.status !== 'all'}
          />
          <Kpi
            icon={<LogOut className="h-4 w-4" />}
            label="Live sessions"
            value={formatCount(stats.liveSessions)}
            sub={stats.liveSessions === null ? 'Not measured — RPC unavailable' : `across ${formatCount(stats.usersWithSessions)} user${stats.usersWithSessions === 1 ? '' : 's'} · ${formatCount(stats.administrators)} admin${stats.administrators === 1 ? '' : 's'}`}
          />
        </div>
      ) : null}

      {/* Integrity + provenance */}
      {meta && (failingChecks.length > 0 || meta.sources.notes.length > 0) ? (
        <div className="qgu-banner" role="status">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="space-y-1">
            {failingChecks.map((check) => <div key={check.id}><strong>{check.label}:</strong> {check.detail}</div>)}
            {meta.sources.notes.map((note) => <div key={note}>{note}</div>)}
          </div>
        </div>
      ) : meta ? (
        <details className="group text-xs qgu-muted">
          <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 [&::-webkit-details-marker]:hidden">
            <Chip tone="ok" icon={<CheckCircle2 className="h-3.5 w-3.5" />}>Reconciled</Chip>
            <span>All {meta.integrity.length} integrity checks pass — {meta.integrity[0]?.detail}.</span>
            <span className="underline decoration-dotted underline-offset-2 group-open:hidden">Show checks</span>
          </summary>
          <ul className="qgu-inset mt-2 grid gap-1.5 p-3 sm:grid-cols-2">
            {meta.integrity.map((check) => (
              <li key={check.id} className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 qgu-tone-ok" />
                <span><span className="font-semibold qgu-soft">{check.label}:</span> {check.detail}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      {/* Toolbar */}
      <div className="qgu-panel space-y-3 p-4">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 qgu-muted" aria-hidden />
            <input
              className="qgu-field pl-9 pr-9"
              aria-label="Search users"
              placeholder="Search by name, email, user ID (USR_…) or tenant"
              value={query.search}
              onChange={(event) => admin.setUserQuery({ search: event.target.value })}
            />
            {query.search && (
              <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 qgu-muted hover:opacity-80" aria-label="Clear search" onClick={() => admin.setUserQuery({ search: '' })}>
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <SelectField label="Sort users" value={query.sort} onChange={(value) => admin.setUserQuery({ sort: value })} className="min-w-[170px]">
              <option value="last_activity">Sort: Last activity</option>
              <option value="created">Sort: Date joined</option>
              <option value="name">Sort: Name</option>
              <option value="email">Sort: Email</option>
              <option value="sessions">Sort: Live sessions</option>
              <option value="plan">Sort: Plan</option>
            </SelectField>
            <button type="button" className="qgu-btn qgu-btn--icon" aria-label={query.order === 'desc' ? 'Descending — switch to ascending' : 'Ascending — switch to descending'} onClick={() => admin.setUserQuery({ order: query.order === 'desc' ? 'asc' : 'desc' })}>
              {query.order === 'desc' ? <ArrowDownWideNarrow className="h-4 w-4" /> : <ArrowUpWideNarrow className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
          <SelectField label="Role filter" value={query.role} onChange={(value) => admin.setUserQuery({ role: value })}>
            <option value="all">All roles</option>
            <option value="administrators">Administrators</option>
            {(meta?.facets.roles || []).map((role) => <option key={role.key} value={role.key}>{role.label} ({role.count})</option>)}
          </SelectField>
          <SelectField label="Tenant filter" value={query.tenant} onChange={(value) => admin.setUserQuery({ tenant: value })}>
            <option value="all">All tenants</option>
            <option value="unassigned">No tenant ({formatCount(stats?.noTenant)})</option>
            {(meta?.facets.tenants || []).map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name} ({tenant.count})</option>)}
          </SelectField>
          <SelectField label="Plan filter" value={query.plan} onChange={(value) => admin.setUserQuery({ plan: value })}>
            <option value="all">All plans</option>
            <option value="no_access">No plan access ({formatCount(stats?.access.noAccess)})</option>
            <optgroup label="Plan (with access)">
              <option value="starter">Starter ({formatCount(stats?.access.byTier.starter)})</option>
              <option value="basic">Basic ({formatCount(stats?.access.byTier.basic)})</option>
              <option value="pro">Pro ({formatCount(stats?.access.byTier.pro)})</option>
              <option value="elite">Elite ({formatCount(stats?.access.byTier.elite)})</option>
            </optgroup>
            <optgroup label="Billing">
              <option value="provider">Billed by a provider ({formatCount(stats?.access.byClass.provider)})</option>
              <option value="complimentary">Complimentary ({formatCount(stats?.access.byClass.complimentary)})</option>
              <option value="manual">Manual — not billed ({formatCount(stats?.access.byClass.manual)})</option>
              <option value="owner">Owner ({formatCount(stats?.access.byClass.owner)})</option>
            </optgroup>
          </SelectField>
          <SelectField label="Status filter" value={query.status} onChange={(value) => admin.setUserQuery({ status: value })}>
            <option value="all">All statuses</option>
            <option value="active">Active ({formatCount(stats?.status.active)})</option>
            <option value="pending_verification">Unverified email ({formatCount(stats?.status.pending_verification)})</option>
            <option value="suspended">Suspended ({formatCount(stats?.status.suspended)})</option>
            <option value="disabled">Disabled ({formatCount(stats?.status.disabled)})</option>
            <option value="drift">Status drift ({formatCount(stats?.statusDrift)})</option>
          </SelectField>
          <SelectField label="Activity filter" value={query.activity} onChange={(value) => admin.setUserQuery({ activity: value })}>
            <option value="all">Any activity</option>
            <option value="active_now">Active in last hour ({formatCount(stats?.activity.activeNow)})</option>
            <option value="active_30d">Active ≤ 30 days ({formatCount(stats?.activity.active30d)})</option>
            <option value="dormant">Dormant &gt; 30 days ({formatCount(stats?.activity.dormant)})</option>
            <option value="never">Never signed in ({formatCount(stats?.activity.never)})</option>
          </SelectField>
          <SelectField label="MFA filter" value={query.mfa} onChange={(value) => admin.setUserQuery({ mfa: value })}>
            <option value="all">Any MFA state</option>
            <option value="enrolled">MFA enrolled ({formatCount(stats?.mfa.enrolled)})</option>
            <option value="not_enrolled">Not enrolled ({formatCount(stats?.mfa.notEnrolled)})</option>
            <option value="required_not_enrolled">Required, not enrolled ({formatCount(stats?.mfa.requiredNotEnrolled)})</option>
          </SelectField>
        </div>
        {activeFilterCount > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-xs qgu-soft">
            <span>{formatCount(pagination.total)} of {formatCount(stats?.totalUsers)} users match {activeFilterCount} filter{activeFilterCount === 1 ? '' : 's'}</span>
            <button type="button" className="qgu-btn qgu-btn--ghost min-h-0 px-2 py-1 text-xs" onClick={admin.resetUserQuery}>
              <X className="h-3.5 w-3.5" />
              Clear filters
            </button>
          </div>
        )}
      </div>

      {/* Table */}
      <div className="qgu-panel overflow-hidden">
        {admin.usersError && (
          <div className="qgu-banner qgu-banner--bad m-4" role="alert">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1">Users could not be loaded: {admin.usersError}</span>
            <button type="button" className="qgu-btn min-h-0 px-3 py-1 text-xs" onClick={() => void admin.refreshUsers().catch(() => undefined)}>Retry</button>
          </div>
        )}
        <div className="max-h-[70vh] overflow-auto">
          <table className="qgu-table min-w-[1180px]">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Role &amp; tenant</th>
                <th scope="col">Plan &amp; access</th>
                <th scope="col">Last activity</th>
                <th scope="col" className="text-right">Sessions</th>
                <th scope="col">MFA</th>
                <th scope="col">Status</th>
                <th scope="col" className="text-right"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody aria-busy={admin.usersLoading}>
              {initialLoading ? (
                Array.from({ length: 5 }, (_, index) => (
                  <tr key={index}>
                    <td colSpan={8}><div className="qgu-skeleton h-10" /></td>
                  </tr>
                ))
              ) : admin.users.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center">
                    <UserRound className="mx-auto h-8 w-8 qgu-muted" />
                    <p className="mt-3 text-sm font-bold qgu-strong">{activeFilterCount ? 'No users match these filters' : 'No users yet'}</p>
                    <p className="mt-1 text-xs qgu-muted">{activeFilterCount ? 'Widen or clear the filters to see more accounts.' : 'Accounts appear here as soon as someone registers or you add one.'}</p>
                    <button type="button" className="qgu-btn mt-4" onClick={activeFilterCount ? admin.resetUserQuery : () => setDialog({ kind: 'create' })}>
                      {activeFilterCount ? 'Clear filters' : 'Add user'}
                    </button>
                  </td>
                </tr>
              ) : admin.users.map((user) => {
                const busy = Boolean(admin.mutating && admin.mutating.endsWith(`:${user.id}`))
                return (
                  <tr key={user.id} data-selected={admin.selectedUserId === user.id}>
                    <td>
                      <button type="button" className="flex min-w-[230px] max-w-[300px] items-center gap-3 text-left" onClick={() => admin.openUserDetail(user.id)}>
                        <span className="qgu-avatar">{initials(user.name, user.email)}</span>
                        <span className="min-w-0">
                          <span className="flex items-center gap-2">
                            <span className={`truncate font-bold ${user.name ? 'qgu-strong' : 'qgu-soft italic'}`}>{user.name || 'No name set'}</span>
                            {user.isOwner && <Chip tone="violet">Owner</Chip>}
                          </span>
                          <span className="block truncate text-xs qgu-soft">{user.email || 'No email'}</span>
                          <span className="block font-mono text-[11px] qgu-muted">{user.displayId}</span>
                        </span>
                      </button>
                    </td>
                    <td>
                      <div className="flex flex-col items-start gap-1.5">
                        <RoleBadge user={user} />
                        <span className="text-xs qgu-soft">{user.tenantName || <span className="qgu-muted">No tenant</span>}{user.tenantRole ? <span className="qgu-muted"> · {user.tenantRole}</span> : null}</span>
                      </div>
                    </td>
                    <td><PlanBadge user={user} /></td>
                    <td><ActivityCell user={user} now={now} /></td>
                    <td className="text-right font-mono font-bold qgu-num">
                      {user.sessions.count === null ? <span className="qgu-muted" title="Not measured">—</span> : formatCount(user.sessions.count)}
                    </td>
                    <td><MfaBadge user={user} /></td>
                    <td><StatusBadge user={user} /></td>
                    <td className="text-right">
                      {busy ? (
                        <span className="inline-flex h-9 w-9 items-center justify-center"><RefreshCw className="h-4 w-4 animate-spin qgu-tone-info" /></span>
                      ) : (
                        <ActionMenu label={`Actions for ${user.email}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(user)} />
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <div className="flex flex-col gap-3 border-t px-4 py-3 text-sm md:flex-row md:items-center md:justify-between" style={{ borderColor: 'var(--qgu-border)' }}>
          <span className="qgu-soft qgu-num">
            {pagination.total
              ? <>Showing {formatCount(pageStart)}–{formatCount(pageEnd)} of {formatCount(pagination.total)} {activeFilterCount ? 'matching ' : ''}user{pagination.total === 1 ? '' : 's'}{activeFilterCount && stats ? ` (${formatCount(stats.totalUsers)} total)` : ''}</>
              : 'No users to show'}
          </span>
          <div className="flex items-center gap-2">
            <button type="button" className="qgu-btn" disabled={pagination.page <= 1 || admin.usersLoading} onClick={() => void admin.refreshUsers(pagination.page - 1).catch(() => undefined)}>
              <ChevronLeft className="h-4 w-4" />
              Previous
            </button>
            <span className="font-mono text-xs qgu-muted">Page {pagination.page} of {Math.max(1, pagination.totalPages)}</span>
            <button type="button" className="qgu-btn" disabled={pagination.page >= pagination.totalPages || admin.usersLoading} onClick={() => void admin.refreshUsers(pagination.page + 1).catch(() => undefined)}>
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Provenance */}
      <p className="flex items-start gap-2 text-xs qgu-muted">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          Times are shown in your time zone ({VIEWER_TIME_ZONE}); exports use UTC. Sign-in, sessions, bans and MFA come from Supabase Auth
          {meta?.sources.auth === 'rpc' ? ' (admin_user_auth_directory)' : meta?.sources.auth === 'admin_api' ? ' (admin API — sessions not measured)' : ''}; plan access uses the same entitlement rule the API enforces
          (billing_subscriptions, owner bypass). Every change here is audited and pushed to all open consoles over SSE.
        </span>
      </p>

      <UserDetailDrawer admin={admin} menuFor={menuFor} onSignOutAll={(user) => setDialog({ kind: 'force_logout', user })} />
      <UserDialogs admin={admin} dialog={dialog} onClose={() => setDialog(null)} />

    </div>
  )
}
