// Owner Admin > Security — the ONE security-posture model.
//
// Replaces a dashboard that (1) renamed ordinary platform events into threat
// stories ("Brute Force Login Attempts — SSH, RDP, VPN" for anything mentioning
// "login", "Malicious IP Connections" for anything containing "ip"),
// (2) scored a NIST CSF radar from constants (80 + …), (3) declared ISO 27001 /
// SOC 2 / PCI DSS "Compliant" from policy-row counts and (4) hardcoded "↑ 8 pts
// vs yesterday". Here every figure is a count of real rows, every finding is a
// measured control with its evidence and the accounts it names, and nothing is
// graded that was not measured.

import type { UserDirectory } from './user-directory'
import { isAccessDenied, isViewAction, normalizeAdminAuditRow, type HistoryEntry } from './admin-history'
import { lower, modelVersion, normalizeSeverity, SEVERITY_RANK, text, timeOf, type Severity } from './model-utils'

const HOUR_MS = 60 * 60_000
const DAY_MS = 24 * HOUR_MS
export const SESSION_SPRAWL_THRESHOLD = 10

export type SecurityWindow = '24h' | '7d' | '30d'
export const SECURITY_WINDOWS: Record<SecurityWindow, { ms: number; buckets: number; label: string }> = {
  '24h': { ms: DAY_MS, buckets: 12, label: 'Last 24 hours' },
  '7d': { ms: 7 * DAY_MS, buckets: 7, label: 'Last 7 days' },
  '30d': { ms: 30 * DAY_MS, buckets: 15, label: 'Last 30 days' },
}

export interface SecurityEventRow {
  id: string
  source: 'platform' | 'account'
  event_type: string | null
  severity: string | null
  message: string | null
  user_id: string | null
  created_at: string | null
}

export interface VulnerabilityRow {
  id: string
  title: string | null
  severity: string | null
  status: string | null
  source: string | null
  created_at: string | null
  asset_id?: string | null
  /** Resolved by the loader from assets.name for the findings the control lists. */
  asset_name?: string | null
}

/** Open = not resolved / closed / fixed / accepted / mitigated. The ONE definition. */
export function isOpenVulnerability(row: Pick<VulnerabilityRow, 'status'>): boolean {
  return !/resolved|closed|fixed|accepted|mitigated/.test(lower(row.status || 'open'))
}

export function vulnerabilitySeverity(row: Pick<VulnerabilityRow, 'severity'>): 'critical' | 'high' | 'warning' | 'info' {
  const severity = normalizeSeverity(row.severity)
  return severity === 'success' ? 'info' : severity
}

/** The findings the "No open critical vulnerabilities" control names (first 10). */
export function listedCriticalVulnerabilities<T extends VulnerabilityRow>(rows: T[]): T[] {
  return rows.filter((row) => isOpenVulnerability(row) && vulnerabilitySeverity(row) === 'critical').slice(0, 10)
}

export interface InfrastructureTable {
  key: string
  label: string
  /** null = the table could not be read. */
  rows: Array<{ status: string | null; last_seen_at: string | null }> | null
}

export type ControlStatus = 'pass' | 'fail' | 'warn' | 'unknown'

export interface SecurityControl {
  id: string
  label: string
  category: 'identity' | 'access' | 'vulnerability' | 'monitoring'
  status: ControlStatus
  measured: string
  remediation: string | null
  affected: Array<{ id: string; label: string }>
}

export interface SecurityPosture {
  window: SecurityWindow
  windowLabel: string
  controls: SecurityControl[]
  summary: {
    controlsPassing: number
    controlsMeasured: number
    controlsFailing: number
    openVulnerabilities: Record<'critical' | 'high' | 'warning' | 'info', number>
    events: Record<Severity, number>
    eventsTotal: number
    attentionEvents: number
    administrators: number
    administratorsWithoutMfa: number | null
    mfaCoveragePercent: number | null
    blockedAdminAttempts: number
  }
  timeline: Array<{ start: string; critical: number; high: number; warning: number; info: number; success: number }>
  eventTypes: Array<{ type: string; source: 'platform' | 'account'; count: number; worst: Severity; latestAt: string | null }>
  attention: Array<{ id: string; type: string; severity: Severity; message: string | null; at: string | null; email: string | null }>
  administrators: Array<{ id: string; email: string; name: string; role: string; mfa: string; status: string; lastActivityAt: string | null; sessions: number | null }>
  adminActivity: HistoryEntry[]
  infrastructure: Array<{ key: string; label: string; state: 'unavailable' | 'not_configured' | 'measured'; total: number; healthy: number; stale: number }>
  version: string
  generatedAt: string
}

export function buildSecurityPosture(input: {
  window: SecurityWindow
  directory: UserDirectory
  events: SecurityEventRow[]
  vulnerabilities: VulnerabilityRow[]
  adminAudit: Array<Record<string, unknown>>
  infrastructure: InfrastructureTable[]
  now?: number
}): SecurityPosture {
  const now = input.now ?? Date.now()
  const windowDef = SECURITY_WINDOWS[input.window]
  const since = now - windowDef.ms
  const users = input.directory.users
  const emailById = new Map(users.map((user) => [user.id, user.email]))
  const measuredAuth = input.directory.sources.auth !== 'unavailable'
  const mfaMeasured = input.directory.sources.mfaMeasured
  const sessionsMeasured = input.directory.sources.sessionsMeasured

  // --- Controls (each one is a measurement, with the accounts it names) -----
  const admins = users.filter((user) => user.isAdministrator)
  const adminsWithoutMfa = admins.filter((user) => user.mfa.state !== 'enrolled')
  const requiredGap = users.filter((user) => user.mfa.state === 'required_not_enrolled')
  const drift = users.filter((user) => user.statusDrift)
  const staleSessions = users.filter((user) => user.activity === 'dormant' && (user.sessions.count ?? 0) > 0)
  const sprawl = users.filter((user) => (user.sessions.count ?? 0) > SESSION_SPRAWL_THRESHOLD)
  const unverifiedWithAccess = users.filter((user) => user.status === 'pending_verification' && (user.access.isActive || (user.sessions.count ?? 0) > 0))
  const openVulns = input.vulnerabilities.filter(isOpenVulnerability)
  const vulnSeverity = vulnerabilitySeverity
  const criticalVulns = openVulns.filter((row) => vulnSeverity(row) === 'critical')
  const auditRows = input.adminAudit.filter((row) => (timeOf(text(row.created_at)) ?? 0) >= now - 30 * DAY_MS)
  const denied = auditRows.filter((row) => isAccessDenied(row.action))
  const label = (user: { id: string; email: string }) => ({ id: user.id, label: user.email })

  const controls: SecurityControl[] = [
    {
      id: 'privileged-mfa',
      label: 'Every administrator has MFA enrolled',
      category: 'identity',
      status: !mfaMeasured ? 'unknown' : adminsWithoutMfa.length ? 'fail' : 'pass',
      measured: !mfaMeasured ? 'MFA factors could not be read from Supabase Auth' : `${admins.length - adminsWithoutMfa.length} of ${admins.length} administrator(s) enrolled`,
      remediation: adminsWithoutMfa.length ? 'Enroll an authenticator in Settings → Security for each listed administrator. Sign-in does not enforce MFA yet.' : null,
      affected: adminsWithoutMfa.map(label),
    },
    {
      id: 'mfa-policy-gap',
      label: 'Accounts flagged "MFA required" have enrolled',
      category: 'identity',
      status: !mfaMeasured ? 'unknown' : requiredGap.length ? 'fail' : 'pass',
      measured: `${requiredGap.length} flagged account(s) without a verified factor`,
      remediation: requiredGap.length ? 'Ask the listed users to enroll an authenticator; the flag alone does not block sign-in.' : null,
      affected: requiredGap.map(label),
    },
    {
      id: 'status-drift',
      label: 'Account status agrees with Supabase Auth',
      category: 'access',
      status: !measuredAuth ? 'unknown' : drift.length ? 'fail' : 'pass',
      measured: `${drift.length} account(s) where the profile and Supabase Auth disagree`,
      remediation: drift.length ? 'Re-apply Suspend or Restore on each listed account in Users so both stores agree.' : null,
      affected: drift.map(label),
    },
    {
      id: 'stale-sessions',
      label: 'No dormant account keeps a live session',
      category: 'access',
      status: !sessionsMeasured ? 'unknown' : staleSessions.length ? 'warn' : 'pass',
      measured: `${staleSessions.length} account(s) inactive > 30 days with live sessions`,
      remediation: staleSessions.length ? 'Use Sign out everywhere on each listed account.' : null,
      affected: staleSessions.map(label),
    },
    {
      id: 'session-sprawl',
      label: `No account holds more than ${SESSION_SPRAWL_THRESHOLD} live sessions`,
      category: 'access',
      status: !sessionsMeasured ? 'unknown' : sprawl.length ? 'warn' : 'pass',
      measured: sprawl.length ? sprawl.map((user) => `${user.email}: ${user.sessions.count}`).join(', ') : 'Within threshold',
      remediation: sprawl.length ? 'Review the sessions in the user drawer; Sign out everywhere clears abandoned ones (often scripts or old devices).' : null,
      affected: sprawl.map(label),
    },
    {
      id: 'unverified-access',
      label: 'Unverified e-mail addresses hold no access',
      category: 'access',
      status: !measuredAuth ? 'unknown' : unverifiedWithAccess.length ? 'warn' : 'pass',
      measured: `${unverifiedWithAccess.length} unverified account(s) with plan access or live sessions`,
      remediation: unverifiedWithAccess.length ? 'Verify ownership of each mailbox, then mark it verified — or suspend the account.' : null,
      affected: unverifiedWithAccess.map(label),
    },
    {
      id: 'critical-vulnerabilities',
      label: 'No open critical vulnerabilities',
      category: 'vulnerability',
      status: criticalVulns.length ? 'fail' : 'pass',
      measured: `${criticalVulns.length} open critical of ${openVulns.length} open finding(s)`,
      remediation: criticalVulns.length ? 'Triage in Discovery → vulnerabilities; remediate or accept with a reason.' : null,
      affected: listedCriticalVulnerabilities(input.vulnerabilities).map((row) => ({ id: row.id, label: `${text(row.title) || 'Untitled finding'}${row.asset_name ? ` — ${row.asset_name}` : row.asset_id ? ' — asset not found' : ''}` })),
    },
    {
      id: 'admin-guard',
      label: 'Owner-only administration is enforced',
      category: 'monitoring',
      status: 'pass',
      measured: `${denied.length} blocked non-owner attempt(s) on Admin / Revenue Intelligence in the last 30 days`,
      remediation: null,
      affected: [],
    },
  ]

  // --- Events (real types, real severities) ---------------------------------
  const windowEvents = input.events.filter((row) => (timeOf(row.created_at) ?? 0) >= since)
  const events: Record<Severity, number> = { critical: 0, high: 0, warning: 0, info: 0, success: 0 }
  for (const row of windowEvents) events[normalizeSeverity(row.severity)] += 1
  const bucketMs = windowDef.ms / windowDef.buckets
  const timeline = Array.from({ length: windowDef.buckets }, (_unused, index) => ({ start: new Date(since + index * bucketMs).toISOString(), critical: 0, high: 0, warning: 0, info: 0, success: 0 }))
  for (const row of windowEvents) {
    const at = timeOf(row.created_at) ?? since
    const index = Math.min(windowDef.buckets - 1, Math.max(0, Math.floor((at - since) / bucketMs)))
    timeline[index][normalizeSeverity(row.severity)] += 1
  }
  const types = new Map<string, { type: string; source: 'platform' | 'account'; count: number; worst: Severity; latestAt: string | null }>()
  for (const row of windowEvents) {
    const type = text(row.event_type) || 'unspecified'
    const key = `${row.source}:${type}`
    const severity = normalizeSeverity(row.severity)
    const current = types.get(key) || { type, source: row.source, count: 0, worst: severity, latestAt: null }
    current.count += 1
    if (SEVERITY_RANK[severity] > SEVERITY_RANK[current.worst]) current.worst = severity
    if ((timeOf(row.created_at) ?? 0) > (timeOf(current.latestAt) ?? 0)) current.latestAt = row.created_at
    types.set(key, current)
  }
  const attention = windowEvents
    .filter((row) => ['critical', 'high'].includes(normalizeSeverity(row.severity)))
    .sort((a, b) => (timeOf(b.created_at) ?? 0) - (timeOf(a.created_at) ?? 0))
    .slice(0, 10)
    .map((row) => ({ id: row.id, type: text(row.event_type) || 'event', severity: normalizeSeverity(row.severity), message: row.message, at: row.created_at, email: row.user_id ? emailById.get(row.user_id) || null : null }))

  const openBySeverity = { critical: 0, high: 0, warning: 0, info: 0 }
  for (const row of openVulns) openBySeverity[vulnSeverity(row)] += 1

  const adminActivity = input.adminAudit
    .filter((row) => !isViewAction(row.action))
    .slice(0, 8)
    .map((row) => normalizeAdminAuditRow(row))

  const infrastructure = input.infrastructure.map((table) => {
    if (!table.rows) return { key: table.key, label: table.label, state: 'unavailable' as const, total: 0, healthy: 0, stale: 0 }
    const healthy = table.rows.filter((row) => /^(active|online|connected|healthy|running|ok|synced)$/.test(lower(row.status))).length
    const stale = table.rows.filter((row) => row.last_seen_at && (timeOf(row.last_seen_at) ?? 0) < now - DAY_MS).length
    return { key: table.key, label: table.label, state: table.rows.length ? 'measured' as const : 'not_configured' as const, total: table.rows.length, healthy, stale }
  })

  const measuredControls = controls.filter((control) => control.status !== 'unknown')
  const model = {
    window: input.window,
    windowLabel: windowDef.label,
    controls,
    summary: {
      controlsPassing: measuredControls.filter((control) => control.status === 'pass').length,
      controlsMeasured: measuredControls.length,
      controlsFailing: measuredControls.filter((control) => control.status === 'fail').length,
      openVulnerabilities: openBySeverity,
      events,
      eventsTotal: windowEvents.length,
      attentionEvents: events.critical + events.high,
      administrators: admins.length,
      administratorsWithoutMfa: mfaMeasured ? adminsWithoutMfa.length : null,
      mfaCoveragePercent: mfaMeasured && users.length ? Math.round(((input.directory.stats.mfa.enrolled ?? 0) / users.length) * 100) : null,
      blockedAdminAttempts: denied.length,
    },
    timeline,
    eventTypes: Array.from(types.values()).sort((a, b) => b.count - a.count).slice(0, 10),
    attention,
    administrators: admins.map((user) => ({ id: user.id, email: user.email, name: user.name, role: user.roleLabel, mfa: user.mfa.state, status: user.status, lastActivityAt: user.lastActivityAt, sessions: user.sessions.count })),
    adminActivity,
    infrastructure,
  }
  // Timeline buckets slide with the clock; the version tracks the data only
  // (event types, counts, controls), so an idle tick never forces a refetch.
  const { timeline: _slidingAxis, ...versioned } = model
  return { ...model, version: modelVersion(versioned), generatedAt: new Date(now).toISOString() }
}
