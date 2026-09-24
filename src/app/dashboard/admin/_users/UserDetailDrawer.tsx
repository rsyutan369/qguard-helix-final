import { type ReactNode, useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, Copy, LogOut, MonitorSmartphone, MoreHorizontal, RefreshCw, X } from 'lucide-react'
import type { AdminDashboard, AdminUser } from '@/hooks/use-admin-dashboard'
import { ActionMenu, Chip, formatCount, formatDate, formatDateTime, initials, timeAgo, useNow, type MenuEntry, type Tone } from '../_shared/primitives'
import { ACTIVITY_META, MfaBadge, PlanBadge, RoleBadge, StatusBadge, accessClassLabel } from './badges'

type DrawerTab = 'overview' | 'sessions' | 'security' | 'activity'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,140px)_minmax(0,1fr)] gap-3 border-b py-2.5 text-sm last:border-b-0" style={{ borderColor: 'var(--qgu-border)' }}>
      <dt className="qgu-muted">{label}</dt>
      <dd className="min-w-0 break-words qgu-strong">{children}</dd>
    </div>
  )
}

function Section({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="qgu-panel p-4">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h4 className="text-xs font-black uppercase tracking-[0.12em] qgu-muted">{title}</h4>
        {action}
      </div>
      {children}
    </section>
  )
}

function severityTone(value: unknown): Tone {
  const severity = String(value || '').toLowerCase()
  if (severity === 'critical' || severity === 'high') return 'bad'
  if (severity === 'warning' || severity === 'medium') return 'warn'
  if (severity === 'success') return 'ok'
  return 'info'
}

function CopyId({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="inline-flex max-w-full items-center gap-1.5 font-mono text-xs qgu-soft hover:underline"
      title="Copy user id"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        }).catch(() => undefined)
      }}
    >
      <span className="truncate">{value}</span>
      <Copy className="h-3 w-3 shrink-0" />
      {copied && <span className="qgu-tone-ok">copied</span>}
    </button>
  )
}

export function UserDetailDrawer({ admin, menuFor, onSignOutAll }: {
  admin: AdminDashboard
  menuFor: (user: AdminUser) => MenuEntry[]
  onSignOutAll: (user: AdminUser) => void
}) {
  const [tab, setTab] = useState<DrawerTab>('overview')
  const now = useNow()
  const detail = admin.selectedUserDetail
  const open = Boolean(admin.selectedUserId)
  // While the detail request is in flight, show the row we already have.
  const user: AdminUser | undefined = detail?.user || admin.users.find((row) => row.id === admin.selectedUserId)

  useEffect(() => {
    setTab('overview')
  }, [admin.selectedUserId])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !document.querySelector('.qgu-dialog')) admin.closeUserDetail()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [admin, open])

  if (!open) return null

  const sessions = detail?.sessions ?? null
  const tabs: Array<{ id: DrawerTab; label: string }> = [
    { id: 'overview', label: 'Overview' },
    { id: 'sessions', label: `Sessions${user?.sessions.count !== null && user?.sessions.count !== undefined ? ` (${user.sessions.count})` : ''}` },
    { id: 'security', label: 'Security' },
    { id: 'activity', label: 'Activity' },
  ]

  return createPortal(
    <div className="qgu">
      <div className="qgu-overlay" onClick={admin.closeUserDetail} />
      <aside className="qgu-drawer" role="dialog" aria-modal="true" aria-label={user ? `User ${user.email}` : 'User details'}>
        <header className="border-b px-5 py-4" style={{ borderColor: 'var(--qgu-border)' }}>
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-3">
              <span className="qgu-avatar h-12 w-12 text-sm">{user ? initials(user.name, user.email) : '…'}</span>
              <div className="min-w-0">
                <h3 className="truncate text-lg font-black qgu-strong">{user?.name || user?.email || 'Loading…'}</h3>
                {user?.name && <p className="truncate text-sm qgu-soft">{user.email}</p>}
                {user && <CopyId value={user.id} />}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button type="button" className="qgu-btn qgu-btn--icon" onClick={() => void admin.refreshUserDetail()} disabled={admin.userDetailLoading} aria-label="Refresh user">
                <RefreshCw className={`h-4 w-4 ${admin.userDetailLoading ? 'animate-spin' : ''}`} />
              </button>
              {user && <ActionMenu label={`Actions for ${user.email}`} trigger={<MoreHorizontal className="h-4 w-4" />} entries={menuFor(user).filter((entry) => !(entry.kind === 'item' && entry.label === 'View details'))} />}
              <button type="button" className="qgu-btn qgu-btn--icon" onClick={admin.closeUserDetail} aria-label="Close">
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
          {user && (
            <div className="mt-3 flex flex-wrap gap-2">
              <RoleBadge user={user} />
              <StatusBadge user={user} />
              <PlanBadge user={user} compact />
              <MfaBadge user={user} />
            </div>
          )}
        </header>

        <nav className="qgu-tabs" role="tablist" aria-label="User detail sections">
          {tabs.map((item) => (
            <button key={item.id} id={`qgu-tab-${item.id}`} type="button" role="tab" aria-selected={tab === item.id} aria-controls={`qgu-panel-${item.id}`} className="qgu-tab" onClick={() => setTab(item.id)}>
              {item.label}
            </button>
          ))}
        </nav>

        <div id={`qgu-panel-${tab}`} role="tabpanel" aria-labelledby={`qgu-tab-${tab}`} className="flex-1 space-y-4 overflow-y-auto p-5">
          {admin.userDetailError && (
            <div className="qgu-banner qgu-banner--bad" role="alert">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{admin.userDetailError}</span>
            </div>
          )}
          {!user ? (
            <div className="space-y-3">
              {[0, 1, 2, 3].map((index) => <div key={index} className="qgu-skeleton h-16" />)}
            </div>
          ) : tab === 'overview' ? (
            <>
              {(user.statusDrift || user.access.tierDrift) && (
                <div className="qgu-banner">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <div className="space-y-1">
                    {user.statusDrift && <div><strong>Status drift:</strong> {user.statusDrift}.</div>}
                    {user.access.tierDrift && <div><strong>Plan mirror drift:</strong> {user.access.tierDrift}.</div>}
                  </div>
                </div>
              )}
              <Section title="Account">
                <dl>
                  <Row label="Status">{user.status.replace(/_/g, ' ')}{user.profileStatus && user.profileStatus !== user.status ? <span className="qgu-muted"> (profile: {user.profileStatus})</span> : null}</Row>
                  <Row label="Sign-in blocked">{user.bannedUntil && Date.parse(user.bannedUntil) > now ? `Yes — Supabase Auth ban until ${formatDate(user.bannedUntil)}` : 'No'}</Row>
                  <Row label="Email">{user.email}{user.emailConfirmedAt ? <span className="qgu-muted"> · confirmed {formatDate(user.emailConfirmedAt)}</span> : <span className="qgu-tone-warn"> · not confirmed</span>}</Row>
                  <Row label="Sign-in methods">{user.providers.length ? user.providers.join(', ') : '—'}</Row>
                  <Row label="Created">{formatDateTime(user.createdAt)}</Row>
                  <Row label="Last sign-in">{user.lastSignInAt ? `${formatDateTime(user.lastSignInAt)} (${timeAgo(user.lastSignInAt, now)})` : 'Never'}</Row>
                  <Row label="Last activity">{user.lastActivityAt ? `${formatDateTime(user.lastActivityAt)} · ${ACTIVITY_META[user.activity].label}` : 'Never'}</Row>
                </dl>
              </Section>
              <Section title="Access">
                <dl>
                  <Row label="Role">{user.roleLabel} <span className="qgu-muted">· source: {user.roleSource.replace(/_/g, ' ')}</span></Row>
                  <Row label="Tenant">{user.tenantName || <span className="qgu-muted">No tenant</span>}{user.tenantRole ? <span className="qgu-muted"> · {user.tenantRole}</span> : null}</Row>
                  <Row label="Plan">{user.access.tierLabel} <span className={user.access.isActive ? 'qgu-tone-ok' : 'qgu-tone-warn'}>· {user.access.isActive ? 'access granted' : 'no access'}</span></Row>
                  <Row label="Subscription">{user.access.source === 'subscription' ? `${String(user.access.status || 'unknown').replace(/_/g, ' ')}${user.access.billingCycle ? ` · ${user.access.billingCycle}` : ''}` : user.isOwner ? 'Not applicable — owner bypass' : 'None'}</Row>
                  <Row label="Billing">{accessClassLabel(user)?.label || '—'}<div className="text-xs qgu-muted">{user.access.accessClassReason}</div></Row>
                  {user.access.periodEnd && <Row label={user.access.cancelAtPeriodEnd ? 'Access ends' : 'Period end'}>{formatDateTime(user.access.periodEnd)} ({timeAgo(user.access.periodEnd, now)})</Row>}
                </dl>
              </Section>
            </>
          ) : tab === 'sessions' ? (
            <Section
              title="Live Supabase Auth sessions"
              action={user.sessions.count ? (
                <button type="button" className="qgu-btn qgu-btn--danger" disabled={user.isOwner} title={user.isOwner ? 'The owner cannot be signed out from the console' : undefined} onClick={() => onSignOutAll(user)}>
                  <LogOut className="h-4 w-4" />
                  Sign out all
                </button>
              ) : undefined}
            >
              {sessions === null ? (
                <p className="text-sm qgu-muted">
                  {detail ? 'Sessions were not measured: the admin_user_auth_sessions RPC is unavailable (apply supabase/admin-user-directory.sql).' : 'Loading sessions…'}
                </p>
              ) : sessions.length === 0 ? (
                <p className="text-sm qgu-muted">No live sessions — the user is signed out on every device.</p>
              ) : (
                <ul className="space-y-2">
                  {sessions.map((session) => (
                    <li key={session.id} className="qgu-inset flex items-start gap-3 p-3">
                      <MonitorSmartphone className="mt-0.5 h-4 w-4 shrink-0 qgu-muted" />
                      <div className="min-w-0 flex-1 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-bold qgu-strong">{session.device || 'Unknown client'}</span>
                          <Chip tone={session.aal === 'aal2' ? 'ok' : 'neutral'}>{session.aal === 'aal2' ? 'MFA verified' : 'Password only'}</Chip>
                        </div>
                        <div className="mt-1 text-xs qgu-muted">
                          {session.ip || 'IP unknown'} · signed in {formatDateTime(session.createdAt)} · last active {timeAgo(session.lastActivityAt, now)}
                          {typeof session.refreshCount === 'number' ? ` · ${session.refreshCount} refresh${session.refreshCount === 1 ? '' : 'es'}` : ''}
                        </div>
                        {session.userAgent && <div className="mt-1 truncate font-mono text-[11px] qgu-muted" title={session.userAgent}>{session.userAgent}</div>}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-xs qgu-muted">A session stays live until the user signs out, it is revoked, or its refresh token is unused past the project&apos;s inactivity limit. Last activity is the latest token refresh (about hourly while a tab is open).</p>
            </Section>
          ) : tab === 'security' ? (
            <>
              <Section title="Multi-factor authentication">
                <dl>
                  <Row label="Enrollment"><MfaBadge user={user} /></Row>
                  <Row label="Policy">{user.mfa.required ? 'MFA required (policy flag — not enforced at sign-in yet)' : 'Not required'}</Row>
                  <Row label="MFA sessions">{user.sessions.aal2Count === null ? 'Not measured' : `${formatCount(user.sessions.aal2Count)} of ${formatCount(user.sessions.count)} sessions verified with MFA`}</Row>
                </dl>
              </Section>
              <Section title="Security events">
                {!detail ? (
                  <div className="qgu-skeleton h-14" />
                ) : detail.securityEvents.length === 0 ? (
                  <p className="text-sm qgu-muted">No security events recorded for this user.</p>
                ) : (
                  <ul className="space-y-2">
                    {detail.securityEvents.map((event, index) => (
                      <li key={String(event.id || index)} className="qgu-inset p-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <Chip tone={severityTone(event.severity)}>{String(event.severity || 'info')}</Chip>
                          <span className="font-mono text-xs qgu-soft">{String(event.event_type || 'event')}</span>
                          <span className="ml-auto text-xs qgu-muted">{timeAgo(String(event.created_at || ''), now)}</span>
                        </div>
                        {Boolean(event.message) && <p className="mt-1.5 qgu-strong">{String(event.message)}</p>}
                        {Boolean(event.ip_address) && <p className="mt-1 text-xs qgu-muted">IP {String(event.ip_address)}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
            </>
          ) : (
            <>
              <Section title="Administrator actions on this user">
                {!detail ? (
                  <div className="qgu-skeleton h-14" />
                ) : detail.adminTrail.length === 0 ? (
                  <p className="text-sm qgu-muted">No administrator has changed this account.</p>
                ) : (
                  <ul className="space-y-2">
                    {detail.adminTrail.map((entry, index) => (
                      <li key={entry.id || index} className="qgu-inset p-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-bold qgu-strong">{entry.actionLabel}</span>
                          <Chip tone={/fail|blocked/i.test(entry.result) ? 'bad' : entry.result === 'warning' ? 'warn' : 'ok'}>{entry.result.replace(/_/g, ' ')}</Chip>
                          <span className="ml-auto text-xs qgu-muted" title={formatDateTime(entry.at)}>{timeAgo(entry.at, now)}</span>
                        </div>
                        <p className="mt-1 text-xs qgu-muted">by {entry.actor || 'Administrator'}{entry.actorIp ? ` · ${entry.actorIp}` : ''}{entry.detail ? ` · ${entry.detail}` : ''}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
              <Section title="Billing trail">
                {!detail ? (
                  <div className="qgu-skeleton h-14" />
                ) : detail.billingTrail.length === 0 ? (
                  <p className="text-sm qgu-muted">No billing events for this user.</p>
                ) : (
                  <ul className="space-y-2">
                    {detail.billingTrail.map((event, index) => (
                      <li key={String(event.id || index)} className="qgu-inset p-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs qgu-soft">{String(event.action || 'billing')}</span>
                          <span className="ml-auto text-xs qgu-muted">{timeAgo(String(event.created_at || ''), now)}</span>
                        </div>
                        {Boolean(event.message) && <p className="mt-1 qgu-strong">{String(event.message)}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
            </>
          )}
        </div>
      </aside>
    </div>,
    document.body,
  )
}
