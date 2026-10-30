/**
 * Audit trail normaliser (§7).
 *
 * The tenant's audit history is spread over a dozen tables that each spell an
 * "event" differently. This module reduces all of them to one `AuditEvent`
 * shape with a consistent category, actor, outcome and severity, so the vault's
 * timeline is genuinely chronological across sources and can be searched and
 * filtered as one series.
 *
 * `appendOnlySource` is set ONLY for tables the platform never updates in place.
 * It is a statement about the write path, not a cryptographic guarantee — the
 * tamper-evidence claim comes from the evidence anchors (see `integrity.ts`),
 * and the UI must not upgrade one into the other.
 */

import { isoOrNull, ms, recordOf, str, type Row } from './subjects'
import type { AuditCategory, AuditEvent, GovernanceSeverity } from './types'

/**
 * Tables with no UPDATE path in the platform: rows are inserted once and never
 * rewritten. Everything else can be modified, so its audit rows are not claimed
 * to be append-only.
 */
const APPEND_ONLY_TABLES = new Set(['audit_logs', 'vault_audit_logs', 'security_events', 'auth_events', 'user_security_events', 'migration_events', 'qrng_events'])

function severityFrom(value: unknown, fallback: GovernanceSeverity = 'low'): GovernanceSeverity {
  const text = str(value).toLowerCase()
  if (text.includes('critical')) return 'critical'
  if (text.includes('high') || text === 'error') return 'high'
  if (text.includes('medium') || text.includes('moderate') || text === 'warning' || text === 'warn') return 'medium'
  if (text.includes('low') || text.includes('info')) return 'low'
  return fallback
}

const FAILURE_PATTERN = /\bfail(ed|ure)?\b|\berror\b|\bdenied\b|\brejected\b|\bunauthorized\b|\binvalid\b|\bblocked\b/i
const DENIED_PATTERN = /\bdenied\b|\bforbidden\b|\bunauthorized\b|\brejected\b/i

/**
 * Normalises separators before a word-boundary match.
 *
 * `\b` treats `_` as a WORD character, so `/\bfail(ed|ure)?\b/` does not match
 * inside `login_failed` — and every platform action name is snake_case
 * (`login_failed`, `scan_failed`, `key_rotation_failed`, `access_denied`).
 * Without this, a failed login was classified as a SUCCESS in the audit
 * timeline and never counted by the audit-failure control. Splitting on
 * `_ - .` first is what makes the boundary land where a reader expects it.
 */
export function normalizeForMatch(text: string): string {
  return String(text || '').replace(/[_.-]+/g, ' ')
}

/** True when the text describes a failed / denied operation. */
export function looksLikeFailure(text: string): boolean {
  return FAILURE_PATTERN.test(normalizeForMatch(text))
}

function outcomeFrom(text: string): AuditEvent['outcome'] {
  const normalized = normalizeForMatch(text)
  if (DENIED_PATTERN.test(normalized)) return 'denied'
  if (FAILURE_PATTERN.test(normalized)) return 'failure'
  return 'success'
}

function titleCase(value: string): string {
  const text = value.replace(/[_.-]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return ''
  return text.replace(/\b\w/g, (char) => char.toUpperCase())
}

export interface AuditInputs {
  now: number
  assetById: Map<string, Row>
  auditLogs: Row[]
  vaultAuditLogs: Row[]
  securityEvents: Row[]
  userSecurityEvents: Row[]
  authEvents: Row[]
  migrationEvents: Row[]
  scanSessions: Row[]
  complianceEvidence: Row[]
  scannerAlerts: Row[]
  generatedKeys: Row[]
  certificates: Row[]
  assets: Row[]
  /** Cap per source so one noisy table cannot crowd out the timeline. */
  capPerSource?: number
}

/**
 * Classifies a platform audit action into a governance audit category.
 *
 * Ordered most-specific first: "policy" before "asset" so
 * "update_asset_policy" lands under policy change rather than asset change.
 */
function categorize(action: string, entityType: string): AuditCategory {
  const text = `${action} ${entityType}`.toLowerCase()
  if (/policy|rule|allowlist|threshold|governance/.test(text)) return 'policy'
  if (/evidence|attestation|anchor/.test(text)) return 'evidence'
  if (/compliance|control|framework|requirement/.test(text)) return 'compliance'
  if (/login|logout|signin|sign_in|auth|mfa|session|password|token/.test(text)) return 'authentication'
  if (/key|kms|qkms|rotate|entropy|qrng/.test(text)) return 'key'
  if (/cert|x509|pki|issuer/.test(text)) return 'certificate'
  if (/vault|file|upload|download|share|encrypt|decrypt/.test(text)) return 'vault'
  if (/scan|discovery|collector|agent/.test(text)) return 'scan'
  if (/migration|remediat|cutover|rollback/.test(text)) return 'migration'
  if (/finding|vulnerab|exposure|alert/.test(text)) return 'finding'
  if (/asset|inventory|component/.test(text)) return 'asset'
  if (/admin|role|permission|user|invite|billing|subscription|settings/.test(text)) return 'administration'
  return 'access'
}

const CATEGORY_CONTROLS: Record<AuditCategory, string[]> = {
  authentication: ['CTL-AUD-01'],
  administration: ['CTL-AUD-01', 'CTL-AUD-02'],
  policy: ['CTL-GOV-01', 'CTL-AUD-01'],
  asset: ['CTL-INV-01', 'CTL-AUD-01'],
  scan: ['CTL-MON-01', 'CTL-AUD-01'],
  finding: ['CTL-VUL-01', 'CTL-AUD-01'],
  compliance: ['CTL-EVD-02', 'CTL-AUD-01'],
  evidence: ['CTL-AUD-03', 'CTL-AUD-04'],
  migration: ['CTL-PQC-02', 'CTL-AUD-01'],
  key: ['CTL-KEY-02', 'CTL-AUD-01'],
  certificate: ['CTL-CRT-02', 'CTL-AUD-01'],
  vault: ['CTL-DAT-01', 'CTL-AUD-01'],
  access: ['CTL-AUD-01'],
}

/**
 * Normalises every audit-relevant source into one chronological series.
 *
 * Sources that are lifecycle STATE rather than events (certificates, keys,
 * assets) contribute only their creation and terminal transitions, so the
 * timeline records what actually happened rather than re-listing inventory.
 */
export function buildAuditEvents(inputs: AuditInputs): AuditEvent[] {
  const cap = inputs.capPerSource ?? 400
  const events: AuditEvent[] = []
  const push = (event: AuditEvent) => {
    events.push(event)
  }

  /* ---- Platform audit log ------------------------------------------ */
  for (const row of inputs.auditLogs.slice(0, cap)) {
    const details = recordOf(row.details)
    const action = str(row.action) || 'audit_action'
    const entityType = str(row.entity_type)
    const category = categorize(action, entityType)
    const text = `${action} ${JSON.stringify(details)}`
    push({
      id: `audit_logs:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category,
      action: titleCase(action),
      actor: 'Tenant user',
      actorType: 'user',
      subject: entityType ? `${titleCase(entityType)}${str(row.entity_id) ? ` ${str(row.entity_id).slice(0, 8)}` : ''}` : 'Platform',
      subjectType: entityType || 'platform',
      outcome: outcomeFrom(text),
      severity: looksLikeFailure(text) ? 'medium' : 'low',
      detail: Object.entries(details)
        .filter(([, value]) => typeof value === 'string' || typeof value === 'number')
        .slice(0, 4)
        .map(([key, value]) => `${key}: ${value}`)
        .join(' · '),
      ipAddress: str(row.ip_address) || null,
      source: { table: 'audit_logs', recordId: str(row.id) },
      assetId: entityType.toLowerCase() === 'asset' ? str(row.entity_id) || null : null,
      evidenceId: `audit:audit_logs:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS[category],
      frameworkIds: [],
      href: '/dashboard/audit-vault',
      appendOnlySource: APPEND_ONLY_TABLES.has('audit_logs'),
    })
  }

  /* ---- Vault audit log --------------------------------------------- */
  for (const row of inputs.vaultAuditLogs.slice(0, cap)) {
    const metadata = recordOf(row.metadata)
    const eventType = str(row.event_type) || str(row.operation) || 'vault_operation'
    const result = str(row.result || row.status || metadata.result || metadata.status)
    const category = categorize(eventType, str(row.resource_type))
    push({
      id: `vault_audit_logs:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category: category === 'access' ? 'vault' : category,
      action: titleCase(eventType),
      actor: 'Vault owner',
      actorType: 'user',
      subject: str(row.resource_type) || str(row.file_id) || 'Vault object',
      subjectType: str(row.resource_type) || 'vault_object',
      outcome: outcomeFrom(`${eventType} ${result}`),
      severity: severityFrom(row.severity, looksLikeFailure(`${eventType} ${result}`) ? 'medium' : 'low'),
      detail: str(row.description || row.details) || result,
      ipAddress: str(row.ip_address) || null,
      source: { table: 'vault_audit_logs', recordId: str(row.id) },
      assetId: null,
      evidenceId: `audit:vault_audit_logs:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS[category === 'access' ? 'vault' : category],
      frameworkIds: [],
      href: '/dashboard/audit-vault',
      appendOnlySource: true,
    })
  }

  /* ---- Security + auth events --------------------------------------- */
  const pushSecurity = (row: Row, table: string, defaultCategory: AuditCategory) => {
    const eventType = str(row.event_type) || str(row.action) || 'security_event'
    const message = str(row.message)
    const category = categorize(eventType, str(row.resource_type)) || defaultCategory
    const text = `${eventType} ${message}`
    push({
      id: `${table}:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category,
      action: titleCase(eventType),
      actor: str(row.ip_address) ? `Session from ${str(row.ip_address)}` : 'Account activity',
      actorType: 'user',
      subject: str(row.resource_name) || str(row.resource_type) || 'Account',
      subjectType: str(row.resource_type) || 'account',
      outcome: outcomeFrom(text),
      severity: severityFrom(row.severity, looksLikeFailure(text) ? 'medium' : 'low'),
      detail: message || str(row.user_agent),
      ipAddress: str(row.ip_address) || null,
      source: { table, recordId: str(row.id) },
      assetId: str(row.asset_id) || null,
      evidenceId: null,
      controlIds: CATEGORY_CONTROLS[category],
      frameworkIds: [],
      href: '/dashboard/audit-vault',
      appendOnlySource: APPEND_ONLY_TABLES.has(table),
    })
  }
  for (const row of inputs.securityEvents.slice(0, cap)) pushSecurity(row, 'security_events', 'access')
  for (const row of inputs.userSecurityEvents.slice(0, cap)) pushSecurity(row, 'user_security_events', 'authentication')
  for (const row of inputs.authEvents.slice(0, cap)) pushSecurity(row, 'auth_events', 'authentication')

  /* ---- Migration events ---------------------------------------------- */
  for (const row of inputs.migrationEvents.slice(0, cap)) {
    const eventType = str(row.event_type) || 'migration_event'
    const message = str(row.message)
    push({
      id: `migration_events:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category: 'migration',
      action: titleCase(eventType),
      actor: 'Migration orchestrator',
      actorType: 'platform',
      subject: str(row.migration_id) ? `Migration ${str(row.migration_id).slice(0, 8)}` : 'Migration',
      subjectType: 'migration_job',
      outcome: outcomeFrom(`${eventType} ${message}`),
      severity: severityFrom(row.severity),
      detail: message,
      ipAddress: null,
      source: { table: 'migration_events', recordId: str(row.id) },
      assetId: null,
      evidenceId: null,
      controlIds: CATEGORY_CONTROLS.migration,
      frameworkIds: [],
      href: '/dashboard/live-migration',
      appendOnlySource: true,
    })
  }

  /* ---- Scan lifecycle -------------------------------------------------- */
  for (const row of inputs.scanSessions.slice(0, Math.floor(cap / 2))) {
    const status = str(row.status).toLowerCase()
    const at = isoOrNull(row.completed_at || row.updated_at || row.started_at || row.created_at)
    push({
      id: `pqc_scan_sessions:${str(row.id)}`,
      at,
      category: 'scan',
      action: /fail|error|cancel/.test(status) ? 'Discovery Scan Failed' : /complete/.test(status) ? 'Discovery Scan Completed' : 'Discovery Scan Started',
      actor: 'PQC scanner',
      actorType: 'platform',
      subject: str(row.target_scope) || 'Tenant estate',
      subjectType: 'scan_session',
      outcome: /fail|error|cancel/.test(status) ? 'failure' : 'success',
      severity: /fail|error/.test(status) ? 'high' : 'low',
      detail: `${str(row.scanned_assets) || 0}/${str(row.total_assets) || 0} target(s) · ${str(row.findings_count) || 0} finding(s)`,
      ipAddress: null,
      source: { table: 'pqc_scan_sessions', recordId: str(row.id) },
      assetId: null,
      evidenceId: `scan:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS.scan,
      frameworkIds: [],
      href: '/dashboard/scanner',
      appendOnlySource: false,
    })
  }

  /* ---- Compliance evidence changes -------------------------------------- */
  for (const row of inputs.complianceEvidence.slice(0, Math.floor(cap / 2))) {
    const created = ms(row.created_at)
    const updated = ms(row.updated_at)
    const changed = updated > created + 1000
    push({
      id: `compliance_evidence:${str(row.id)}`,
      at: isoOrNull(row.updated_at || row.created_at),
      category: 'compliance',
      action: changed ? 'Compliance Evidence Updated' : 'Compliance Evidence Recorded',
      actor: 'Tenant attestation',
      actorType: 'user',
      subject: `${str(row.framework) || 'Framework'} ${str(row.control_id) || ''}`.trim(),
      subjectType: 'compliance_evidence',
      outcome: /fail|non[-\s]?compliant/i.test(str(row.status)) ? 'failure' : 'success',
      severity: /fail|non[-\s]?compliant/i.test(str(row.status)) ? 'medium' : 'low',
      detail: str(row.description) || `Status: ${str(row.status) || 'unrecorded'}`,
      ipAddress: null,
      source: { table: 'compliance_evidence', recordId: str(row.id) },
      assetId: str(row.asset_id) || null,
      evidenceId: `attestation:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS.compliance,
      frameworkIds: [],
      href: '/dashboard/regulatory-mapping',
      appendOnlySource: false,
    })
  }

  /* ---- Collector alert state changes ------------------------------------- */
  for (const row of inputs.scannerAlerts.slice(0, Math.floor(cap / 2))) {
    const status = str(row.status).toLowerCase()
    const resolved = /resolved|closed|suppressed|acknowledged/.test(status)
    push({
      id: `scanner_alerts:${str(row.id)}`,
      at: isoOrNull(row.updated_at || row.created_at),
      category: 'finding',
      action: resolved ? 'Finding Resolved' : 'Finding Raised',
      actor: 'Collector agent',
      actorType: 'agent',
      subject: str(row.title) || str(row.category) || 'Collector alert',
      subjectType: 'scanner_alert',
      outcome: resolved ? 'success' : 'informational',
      severity: severityFrom(row.severity),
      detail: str(row.message) || str(row.recommendation),
      ipAddress: null,
      source: { table: 'scanner_alerts', recordId: str(row.id) },
      assetId: null,
      evidenceId: `finding:scanner_alerts:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS.finding,
      frameworkIds: [],
      href: '/dashboard/agents',
      appendOnlySource: false,
    })
  }

  /* ---- Key lifecycle transitions ------------------------------------------ */
  for (const row of inputs.generatedKeys.slice(0, Math.floor(cap / 2))) {
    const revokedAt = isoOrNull(row.revoked_at)
    push({
      id: `generated_keys:created:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category: 'key',
      action: str(row.rotated_from) ? 'Key Rotated' : 'Key Generated',
      actor: 'QKMS',
      actorType: 'platform',
      subject: str(row.algorithm) || 'Managed key',
      subjectType: 'generated_key',
      outcome: 'success',
      severity: 'low',
      detail: `${str(row.bit_length) || '—'} bits · entropy ${str(row.entropy_source) || 'not recorded'}`,
      ipAddress: null,
      source: { table: 'generated_keys', recordId: str(row.id) },
      assetId: null,
      evidenceId: `key:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS.key,
      frameworkIds: [],
      href: '/dashboard/qkms/lifecycle',
      appendOnlySource: false,
    })
    if (revokedAt) {
      push({
        id: `generated_keys:revoked:${str(row.id)}`,
        at: revokedAt,
        category: 'key',
        action: 'Key Revoked',
        actor: 'QKMS',
        actorType: 'platform',
        subject: str(row.algorithm) || 'Managed key',
        subjectType: 'generated_key',
        outcome: 'success',
        severity: 'medium',
        detail: 'Key material revoked and withdrawn from service.',
        ipAddress: null,
        source: { table: 'generated_keys', recordId: str(row.id) },
        assetId: null,
        evidenceId: `key:${str(row.id)}`,
        controlIds: CATEGORY_CONTROLS.key,
        frameworkIds: [],
        href: '/dashboard/qkms/lifecycle',
        appendOnlySource: false,
      })
    }
  }

  /* ---- Certificate expiry as a governance event ---------------------------- */
  for (const row of inputs.certificates.slice(0, Math.floor(cap / 2))) {
    const expiry = ms(row.not_after)
    if (!expiry || expiry > inputs.now) continue
    push({
      id: `certificates:expired:${str(row.id)}`,
      at: new Date(expiry).toISOString(),
      category: 'certificate',
      action: 'Certificate Expired',
      actor: 'PKI monitor',
      actorType: 'platform',
      subject: str(row.name) || str(row.subject) || 'Certificate',
      subjectType: 'certificate',
      outcome: 'failure',
      severity: 'critical',
      detail: `${str(row.algorithm) || 'algorithm not recorded'} · issued by ${str(row.issuer) || 'unknown issuer'}`,
      ipAddress: null,
      source: { table: 'certificates', recordId: str(row.id) },
      assetId: str(row.asset_id) || null,
      evidenceId: `certificate:${str(row.id)}`,
      controlIds: CATEGORY_CONTROLS.certificate,
      frameworkIds: [],
      href: '/dashboard/certificate-telemetry',
      appendOnlySource: false,
    })
  }

  /* ---- Asset registration -------------------------------------------------- */
  for (const row of inputs.assets.slice(0, Math.floor(cap / 2))) {
    push({
      id: `assets:${str(row.id)}`,
      at: isoOrNull(row.created_at),
      category: 'asset',
      action: 'Asset Discovered',
      actor: 'Discovery engine',
      actorType: 'platform',
      subject: str(row.name) || 'Asset',
      subjectType: str(row.type) || 'asset',
      outcome: 'success',
      severity: 'low',
      detail: [str(row.environment), str(row.region), str(row.criticality)].filter(Boolean).join(' · '),
      ipAddress: null,
      source: { table: 'assets', recordId: str(row.id) },
      assetId: str(row.id) || null,
      evidenceId: null,
      controlIds: CATEGORY_CONTROLS.asset,
      frameworkIds: [],
      href: '/dashboard/assets',
      appendOnlySource: false,
    })
  }

  events.sort((a, b) => ms(b.at) - ms(a.at))
  // Guard against a duplicate id reaching the UI as a React key collision.
  const seen = new Set<string>()
  return events.filter((event) => {
    if (seen.has(event.id)) return false
    seen.add(event.id)
    return true
  })
}
