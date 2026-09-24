// Owner Admin > History — administrator audit trail vocabulary + normalisation.
//
// History shows EVENTS only. The old feed also turned the current state of
// billing_subscriptions / admin_roles rows into "Subscription active" / "Role
// active" entries stamped with updated_at — records presented as actions that
// no one performed. Every row here is an admin_audit_events record (or, when
// requested, a platform event from its own event table).

import { lower, text } from './model-utils'

export type HistoryCategory = 'users' | 'roles' | 'tenants' | 'billing' | 'governance' | 'security' | 'exports' | 'views' | 'other'
export type HistorySource = 'admin' | 'security' | 'billing' | 'migration'

/**
 * Read-only console traffic (Admin + Revenue Intelligence share this audit
 * table): recorded for accountability, hidden by default. The SQL filters in
 * api-server/admin.ts HISTORY_CATEGORY_PATTERNS mirror these suffixes.
 */
export const VIEW_ACTION_SUFFIXES = ['.viewed', '.stream.connected', '.inspected'] as const

export function isViewAction(action: unknown): boolean {
  const value = lower(action)
  return VIEW_ACTION_SUFFIXES.some((suffix) => value.endsWith(suffix))
}

/** Non-owner attempts refused by an owner-only surface (admin or revenue). */
export function isAccessDenied(action: unknown): boolean {
  return lower(action).endsWith('.access_denied')
}

export function adminActionCategory(action: unknown): HistoryCategory {
  const value = lower(action)
  if (isViewAction(value)) return 'views'
  if (isAccessDenied(value)) return 'security'
  if (value.includes('export')) return 'exports'
  if (value.startsWith('admin.user.') || value.startsWith('admin.users.')) return 'users'
  if (value.startsWith('admin.role.')) return 'roles'
  if (value.startsWith('admin.tenant.')) return 'tenants'
  if (value.startsWith('admin.subscription.') || value.startsWith('admin.billing.') || value.startsWith('revenue.')) return 'billing'
  if (value.startsWith('admin.governance.') || value.startsWith('admin.security.policy') || value.startsWith('admin.policy.')) return 'governance'
  return 'other'
}

// Some audit actions are recorded as imperative verbs (admin.subscription.activate);
// a history reads in the past tense, so the final verb is rendered as what happened.
const PAST_TENSE: Record<string, string> = {
  activate: 'activated', deactivate: 'deactivated', suspend: 'suspended', restore: 'restored', extend: 'extended',
  cancel: 'cancelled', notify: 'notified', approve: 'approved', archive: 'archived', delete: 'deleted', block: 'blocked',
  unblock: 'unblocked', enable: 'enabled', disable: 'disabled', revoke: 'revoked', resend: 'resent', reset: 'reset',
  export: 'exported',
}

export function actionLabel(action: unknown): string {
  const words = text(action).replace(/^admin\./, '').replace(/[._-]+/g, ' ').trim().split(' ').filter(Boolean)
  if (!words.length) return 'Event'
  const last = words.length - 1
  words[last] = PAST_TENSE[words[last].toLowerCase()] ?? words[last]
  return words.join(' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

export interface HistoryEntry {
  id: string
  at: string | null
  source: HistorySource
  category: HistoryCategory | 'platform'
  action: string
  actionLabel: string
  actor: string | null
  actorIp: string | null
  target: string | null
  targetType: string | null
  targetId: string | null
  result: string
  detail: string | null
  severity: string
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

/** One admin_audit_events row -> a history entry (no invented fields). */
export function normalizeAdminAuditRow(row: Record<string, unknown>): HistoryEntry {
  const details = record(row.details)
  const action = text(row.action) || 'admin.event'
  const targetEmail = text(details.targetEmail)
  const targetName = text(details.targetName)
  const target = targetName && targetEmail ? `${targetName} (${targetEmail})` : targetEmail || targetName || text(details.name) || text(details.policyKey) || text(details.title) || null
  const status = lower(details.status || details.result)
  const result = status === 'completed_with_warnings' ? 'warning'
    : /blocked|denied/.test(status) || isAccessDenied(action) ? 'blocked'
      : /fail|error/.test(status) ? 'failed'
        : status || 'recorded'
  const reason = text(details.reason)
  const changed = Array.isArray(details.changedFields) ? (details.changedFields as unknown[]).map(String).join(', ') : ''
  return {
    id: text(row.id) || `${action}-${text(row.created_at)}`,
    at: text(row.created_at) || null,
    source: 'admin',
    category: adminActionCategory(action),
    action,
    actionLabel: actionLabel(action),
    actor: text(row.actor_email) || text(details.actorEmail) || null,
    actorIp: text(row.ip_address) || null,
    target,
    targetType: text(row.entity_type) || text(details.targetType) || null,
    targetId: text(row.entity_id) || text(details.targetUserId) || null,
    result,
    detail: [changed && `changed: ${changed}`, reason && `reason: ${reason}`, text(details.path) && `path: ${text(details.path)}`].filter(Boolean).join(' · ') || null,
    severity: result === 'blocked' || result === 'failed' ? 'warning' : 'info',
  }
}

/** A platform event row (security_events, user_security_events, billing_audit_events, migration_events). */
export function normalizePlatformEvent(row: Record<string, unknown>, source: Exclude<HistorySource, 'admin'>, userEmail: string | null): HistoryEntry {
  const action = text(row.event_type) || text(row.action) || 'event'
  const metadata = record(row.metadata)
  return {
    id: `${source}-${text(row.id)}`,
    at: text(row.created_at) || null,
    source,
    category: 'platform',
    action,
    actionLabel: actionLabel(action),
    actor: text(metadata.actorEmail) || userEmail,
    actorIp: text(row.ip_address) || text(metadata.actorIp) || null,
    target: userEmail,
    targetType: source === 'billing' ? 'subscription' : source === 'migration' ? 'migration' : 'account',
    targetId: text(row.user_id) || text(row.migration_id) || null,
    result: 'recorded',
    detail: text(row.message) || null,
    severity: lower(row.severity) || 'info',
  }
}

export const HISTORY_CSV_COLUMNS: Array<{ header: string; value: (entry: HistoryEntry) => unknown }> = [
  { header: 'When (UTC)', value: (entry) => entry.at },
  { header: 'Source', value: (entry) => entry.source },
  { header: 'Category', value: (entry) => entry.category },
  { header: 'Action', value: (entry) => entry.action },
  { header: 'Actor', value: (entry) => entry.actor },
  { header: 'Actor IP', value: (entry) => entry.actorIp },
  { header: 'Target', value: (entry) => entry.target },
  { header: 'Target type', value: (entry) => entry.targetType },
  { header: 'Target ID', value: (entry) => entry.targetId },
  { header: 'Result', value: (entry) => entry.result },
  { header: 'Detail', value: (entry) => entry.detail },
]
