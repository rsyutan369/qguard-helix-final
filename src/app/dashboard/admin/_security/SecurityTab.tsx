import { type ReactNode, useEffect } from 'react'
import { AlertTriangle, Bug, CheckCircle2, CircleDashed, Crown, Lock, RefreshCw, ServerCog, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react'
import type { AdminDashboard } from '@/hooks/use-admin-dashboard'
import type { SecurityControl, SecurityPosture } from '@/lib/admin/security-posture'
import { Chip, SelectField, formatCount, formatDateTime, timeAgo, useNow, type Tone } from '../_shared/primitives'
import { ConsoleHeader, EmptyState, ErrorBanner, Kpi, KpiGrid, Panel, ProvenanceNote } from '../_shared/console'

const CONTROL_META: Record<SecurityControl['status'], { label: string; tone: Tone; icon: ReactNode }> = {
  pass: { label: 'Pass', tone: 'ok', icon: <CheckCircle2 className="h-3.5 w-3.5" /> },
  fail: { label: 'Fail', tone: 'bad', icon: <XCircle className="h-3.5 w-3.5" /> },
  warn: { label: 'Review', tone: 'warn', icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  unknown: { label: 'Not measured', tone: 'neutral', icon: <CircleDashed className="h-3.5 w-3.5" /> },
}

const SEVERITY_TONE: Record<string, Tone> = { critical: 'bad', high: 'bad', warning: 'warn', info: 'info', success: 'ok' }
const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--qgu-bad-text)',
  high: 'var(--qg-orange, #f97316)',
  warning: 'var(--qgu-warn-text)',
  info: 'var(--qgu-info-text)',
  success: 'var(--qgu-ok-text)',
}
const SERIES = ['critical', 'high', 'warning', 'info', 'success'] as const

function Timeline({ posture }: { posture: SecurityPosture }) {
  const max = Math.max(1, ...posture.timeline.map((bucket) => SERIES.reduce((sum, key) => sum + bucket[key], 0)))
  const daily = posture.window !== '24h'
  return (
    <div>
      <div className="flex h-40 items-end gap-1.5" role="img" aria-label={`Security events per ${daily ? 'period' : '2 hours'}, ${posture.windowLabel.toLowerCase()}`}>
        {posture.timeline.map((bucket) => {
          const total = SERIES.reduce((sum, key) => sum + bucket[key], 0)
          const start = new Date(bucket.start)
          const label = daily ? start.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : start.toLocaleTimeString('en-US', { hour: 'numeric' })
          return (
            <div key={bucket.start} className="flex min-w-0 flex-1 flex-col items-center gap-1" title={`${label}: ${total} event(s)`}>
              <div className="flex w-full flex-col-reverse overflow-hidden rounded-md" style={{ height: `${Math.max(2, (total / max) * 128)}px`, background: total ? undefined : 'var(--qgu-inset)' }}>
                {SERIES.map((key) => bucket[key] ? <div key={key} style={{ height: `${(bucket[key] / total) * 100}%`, background: SEVERITY_COLOR[key] }} /> : null)}
              </div>
              <span className="w-full truncate text-center text-[10px] qgu-muted">{label}</span>
            </div>
          )
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] qgu-soft">
        {SERIES.map((key) => (
          <span key={key} className="inline-flex items-center gap-1.5"><span className="h-2 w-3 rounded-sm" style={{ background: SEVERITY_COLOR[key] }} />{key} ({posture.summary.events[key]})</span>
        ))}
      </div>
    </div>
  )
}

export function SecurityTab({ admin, onOpenUser }: { admin: AdminDashboard; onOpenUser: (email: string) => void }) {
  const resource = admin.security
  const { data, query } = resource
  const now = useNow()
  const { ensureLoaded } = resource
  useEffect(() => { ensureLoaded() }, [ensureLoaded])
  const summary = data?.summary

  return (
    <div className="qgu space-y-5">
      <ConsoleHeader
        title="Security"
        description="Measured controls, real platform events and open findings. Nothing here is graded that was not measured."
        admin={admin}
        updatedAt={data?.generatedAt}
        actions={(
          <>
            <SelectField label="Time window" value={query.window} onChange={(value) => resource.setQuery({ window: value })} className="min-w-[170px]">
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </SelectField>
            <button type="button" className="qgu-btn" onClick={() => void resource.refresh()} disabled={resource.loading}>
              <RefreshCw className={`h-4 w-4 ${resource.loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </>
        )}
      />

      {resource.error && <ErrorBanner message={`Security posture could not be loaded: ${resource.error}`} onRetry={() => void resource.refresh()} />}

      <KpiGrid loading={!summary}>
        {summary && (
          <>
            <Kpi icon={<ShieldCheck className="h-4 w-4" />} label="Controls passing" value={`${summary.controlsPassing} / ${summary.controlsMeasured}`} sub={summary.controlsFailing ? `${summary.controlsFailing} failing` : 'none failing'} subTone={summary.controlsFailing ? 'bad' : 'ok'} />
            <Kpi icon={<Crown className="h-4 w-4" />} label="Admins without MFA" value={summary.administratorsWithoutMfa === null ? '—' : formatCount(summary.administratorsWithoutMfa)} sub={`of ${summary.administrators} administrator(s)`} subTone={summary.administratorsWithoutMfa ? 'bad' : undefined} />
            <Kpi icon={<Bug className="h-4 w-4" />} label="Open critical / high" value={formatCount(summary.openVulnerabilities.critical + summary.openVulnerabilities.high)} sub={`${summary.openVulnerabilities.critical} critical · ${summary.openVulnerabilities.high} high · ${summary.openVulnerabilities.warning + summary.openVulnerabilities.info} lower`} subTone={summary.openVulnerabilities.critical ? 'bad' : undefined} />
            <Kpi icon={<ShieldAlert className="h-4 w-4" />} label={`Events · ${query.window}`} value={formatCount(summary.eventsTotal)} sub={summary.attentionEvents ? `${summary.attentionEvents} critical/high` : 'none critical/high'} subTone={summary.attentionEvents ? 'bad' : undefined} />
            <Kpi icon={<Lock className="h-4 w-4" />} label="Blocked admin access" value={formatCount(summary.blockedAdminAttempts)} sub="non-owner attempts · 30 days" />
            <Kpi icon={<ShieldCheck className="h-4 w-4" />} label="MFA coverage" value={summary.mfaCoveragePercent === null ? '—' : `${summary.mfaCoveragePercent}%`} sub="of all accounts enrolled" subTone={summary.mfaCoveragePercent !== null && summary.mfaCoveragePercent < 50 ? 'warn' : undefined} />
          </>
        )}
      </KpiGrid>

      <Panel title="Controls" action={<span className="text-xs qgu-muted">each result is a measurement, with the accounts it names</span>}>
        {!data ? <div className="qgu-skeleton h-40" /> : (
          <ul className="divide-y" style={{ borderColor: 'var(--qgu-border)' }}>
            {data.controls.map((control) => {
              const meta = CONTROL_META[control.status]
              return (
                <li key={control.id} className="grid gap-2 py-3 md:grid-cols-[120px_minmax(0,1fr)]" style={{ borderColor: 'var(--qgu-border)' }}>
                  <div><Chip tone={meta.tone} icon={meta.icon}>{meta.label}</Chip></div>
                  <div className="min-w-0">
                    <div className="text-sm font-bold qgu-strong">{control.label}</div>
                    <div className="text-xs qgu-soft">{control.measured}</div>
                    {control.remediation && <div className="mt-1 text-xs qgu-muted">→ {control.remediation}</div>}
                    {control.affected.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {control.affected.map((item) => (
                          control.category === 'vulnerability'
                            ? <Chip key={item.id} tone="neutral">{item.label}</Chip>
                            : <button key={item.id} type="button" className="qgu-chip hover:underline" onClick={() => onOpenUser(item.label)} title="Open in Users">{item.label}</button>
                        ))}
                      </div>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </Panel>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-2">
        <Panel title={`Security events — ${data?.windowLabel.toLowerCase() || ''}`}>
          {!data ? <div className="qgu-skeleton h-40" /> : data.summary.eventsTotal === 0 ? (
            <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="No security events in this window" body="Platform events (scans, agents, migrations) and account events (sign-up, profile, billing, admin actions on the account) appear here as they are recorded." />
          ) : <Timeline posture={data} />}
        </Panel>
        <Panel title="Event types in window">
          {!data ? <div className="qgu-skeleton h-40" /> : data.eventTypes.length === 0 ? (
            <EmptyState title="No events" />
          ) : (
            <div className="overflow-x-auto">
            <table className="qgu-table">
              <thead><tr><th>Event type</th><th>Source</th><th className="text-right">Count</th><th>Worst</th><th>Latest</th></tr></thead>
              <tbody>
                {data.eventTypes.map((row) => (
                  <tr key={`${row.source}:${row.type}`}>
                    <td className="font-mono text-xs qgu-strong">{row.type}</td>
                    <td className="text-xs qgu-soft">{row.source === 'platform' ? 'Platform' : 'Account'}</td>
                    <td className="text-right font-mono font-bold qgu-num">{row.count}</td>
                    <td><Chip tone={SEVERITY_TONE[row.worst]}>{row.worst}</Chip></td>
                    <td className="text-xs qgu-muted" title={formatDateTime(row.latestAt)}>{timeAgo(row.latestAt, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-2">
        <Panel title="Needs attention (critical / high events)">
          {!data ? <div className="qgu-skeleton h-24" /> : data.attention.length === 0 ? (
            <EmptyState icon={<CheckCircle2 className="h-6 w-6" />} title="Nothing critical or high in this window" />
          ) : (
            <ul className="space-y-2">
              {data.attention.map((event) => (
                <li key={event.id} className="qgu-inset p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Chip tone={SEVERITY_TONE[event.severity]}>{event.severity}</Chip>
                    <span className="font-mono text-xs qgu-soft">{event.type}</span>
                    <span className="ml-auto text-xs qgu-muted">{timeAgo(event.at, now)}</span>
                  </div>
                  {event.message && <p className="mt-1 qgu-strong">{event.message}</p>}
                  {event.email && <p className="mt-0.5 text-xs qgu-muted">{event.email}</p>}
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Administrators">
          {!data ? <div className="qgu-skeleton h-24" /> : data.administrators.length === 0 ? (
            <EmptyState title="No administrator accounts" />
          ) : (
            <div className="overflow-x-auto">
            <table className="qgu-table">
              <thead><tr><th>Account</th><th>Role</th><th>MFA</th><th>Status</th><th className="text-right">Sessions</th><th>Last activity</th></tr></thead>
              <tbody>
                {data.administrators.map((admin_) => (
                  <tr key={admin_.id}>
                    <td className="text-xs"><button type="button" className="font-bold qgu-strong hover:underline" onClick={() => onOpenUser(admin_.email)}>{admin_.email}</button></td>
                    <td className="text-xs qgu-soft">{admin_.role}</td>
                    <td><Chip tone={admin_.mfa === 'enrolled' ? 'ok' : admin_.mfa === 'unknown' ? 'neutral' : 'bad'}>{admin_.mfa === 'enrolled' ? 'Enrolled' : admin_.mfa === 'unknown' ? 'Unknown' : 'Not enrolled'}</Chip></td>
                    <td className="text-xs qgu-soft">{admin_.status.replace(/_/g, ' ')}</td>
                    <td className="text-right font-mono qgu-num">{admin_.sessions === null ? '—' : admin_.sessions}</td>
                    <td className="text-xs qgu-muted">{timeAgo(admin_.lastActivityAt, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-2">
        <Panel title="Recent administrator changes">
          {!data ? <div className="qgu-skeleton h-24" /> : data.adminActivity.length === 0 ? (
            <EmptyState title="No administrator changes recorded" />
          ) : (
            <ul className="space-y-2">
              {data.adminActivity.map((entry) => (
                <li key={entry.id} className="flex flex-wrap items-center gap-2 text-xs">
                  <Chip tone={entry.result === 'blocked' || entry.result === 'failed' ? 'bad' : entry.result === 'warning' ? 'warn' : 'ok'}>{entry.result}</Chip>
                  <span className="font-bold qgu-strong">{entry.actionLabel}</span>
                  <span className="truncate qgu-soft">{entry.target || ''}</span>
                  <span className="ml-auto qgu-muted">{entry.actor || '—'} · {timeAgo(entry.at, now)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Collection infrastructure">
          {!data ? <div className="qgu-skeleton h-24" /> : (
            <ul className="grid gap-2 sm:grid-cols-2">
              {data.infrastructure.map((item) => (
                <li key={item.key} className="qgu-inset flex items-start gap-3 p-3 text-sm">
                  <ServerCog className="mt-0.5 h-4 w-4 shrink-0 qgu-muted" />
                  <div>
                    <div className="font-bold qgu-strong">{item.label}</div>
                    <div className="text-xs qgu-muted">
                      {item.state === 'unavailable' ? 'Table unavailable' : item.state === 'not_configured' ? 'None configured' : `${item.healthy} of ${item.total} healthy${item.stale ? ` · ${item.stale} not seen in 24 h` : ''}`}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <ProvenanceNote>
        Controls read the Users directory (Supabase Auth sessions, bans, MFA factors), the vulnerabilities table and the admin audit trail. Events are security_events (platform) and user_security_events (account) with their recorded severities. No compliance framework status is claimed here — see Governance for policy verification.
      </ProvenanceNote>
    </div>
  )
}
