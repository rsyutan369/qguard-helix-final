// Owner Admin > Governance — policies checked against evidence, and evidence
// packages that can be verified.
//
// A policy row saying `enforcement_level = 'enforce'` is a claim. Each known
// policy is checked against a measurement (e.g. "Privileged MFA requirement" is
// compared with the administrators' real MFA enrollment — and reported NOT MET,
// because sign-in does not enforce MFA). Policies without an automated check are
// labelled "Attested", never "Compliant". Evidence packages are generated on the
// server from measured state and fingerprinted (SHA3-256 over canonical JSON),
// replacing a button that stored whatever KPIs the browser sent.

import type { SecurityControl } from './security-posture'
import { lower, modelVersion, text, timeOf, type IntegrityCheck } from './model-utils'

export const POLICY_CATEGORIES = ['access', 'identity', 'data', 'retention', 'billing', 'operations'] as const
export const POLICY_STATUSES = ['enabled', 'disabled'] as const
export const ENFORCEMENT_LEVELS = ['enforce', 'monitor', 'advisory'] as const
export const POLICY_KEY_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/

/** Policies the platform can verify automatically; they cannot be deleted. */
export const VERIFIED_POLICY_KEYS = new Set(['owner-only-admin-dashboard', 'privileged-mfa-required', 'admin-audit-retention'])

export interface PolicyRow {
  id: string
  policy_key: string | null
  name: string | null
  category: string | null
  status: string | null
  enforcement_level: string | null
  description: string | null
  config: Record<string, unknown> | null
  updated_by: string | null
  created_at: string | null
  updated_at: string | null
}

export interface EvidenceRow {
  id: string
  title: string | null
  framework: string | null
  evidence_type: string | null
  status: string | null
  generated_by: string | null
  metadata: Record<string, unknown> | null
  created_at: string | null
}

export type VerificationState = 'met' | 'not_met' | 'enforced_by_platform' | 'attested' | 'disabled' | 'unknown'

export interface GovernancePolicy {
  id: string
  key: string
  name: string
  category: string
  status: 'enabled' | 'disabled'
  enforcementLevel: string
  description: string
  builtin: boolean
  verification: { state: VerificationState; detail: string; mechanism: string | null }
  updatedAt: string | null
  updatedBy: string | null
}

export interface GovernanceEvidence {
  id: string
  title: string
  framework: string
  type: string
  createdAt: string | null
  generatedBy: string | null
  hash: { algorithm: string; value: string } | null
  /** Recomputed on read: does the stored snapshot still match its fingerprint? */
  intact: boolean | null
  summary: Record<string, unknown> | null
}

export interface GovernanceModel {
  policies: GovernancePolicy[]
  evidence: GovernanceEvidence[]
  stats: {
    policies: number
    enabled: number
    met: number
    notMet: number
    enforcedByPlatform: number
    attested: number
    evidence: number
    evidenceIntact: number
    latestEvidenceAt: string | null
    auditRecords: number
    oldestAuditAt: string | null
  }
  integrity: IntegrityCheck[]
  version: string
  generatedAt: string
}

export function buildGovernanceModel(input: {
  policies: PolicyRow[]
  evidence: EvidenceRow[]
  controls: SecurityControl[]
  deniedAttempts30d: number
  audit: { count: number; oldestAt: string | null }
  emailById: Map<string, string>
  verifyHash: (snapshot: unknown, expected: string) => boolean
  now?: number
}): GovernanceModel {
  const now = input.now ?? Date.now()
  const control = (id: string) => input.controls.find((row) => row.id === id) || null

  const policies: GovernancePolicy[] = input.policies.map((row): GovernancePolicy => {
    const key = lower(row.policy_key)
    const status = lower(row.status) === 'disabled' ? 'disabled' : 'enabled'
    let verification: GovernancePolicy['verification']
    if (status === 'disabled') {
      verification = { state: 'disabled', detail: 'Policy is disabled — not evaluated.', mechanism: null }
    } else if (key === 'owner-only-admin-dashboard') {
      verification = {
        state: 'enforced_by_platform',
        detail: `${input.deniedAttempts30d} blocked non-owner attempt(s) in the last 30 days.`,
        mechanism: 'API guard requireOwner on /api/v1/admin/* and the dashboard owner gate',
      }
    } else if (key === 'privileged-mfa-required') {
      const mfa = control('privileged-mfa')
      verification = !mfa || mfa.status === 'unknown'
        ? { state: 'unknown', detail: 'MFA enrollment could not be measured.', mechanism: null }
        : mfa.status === 'pass'
          ? { state: 'met', detail: `${mfa.measured}. Note: sign-in does not enforce MFA; this is measured compliance.`, mechanism: 'Measured from Supabase Auth MFA factors' }
          : { state: 'not_met', detail: `${mfa.measured}${mfa.affected.length ? ` — without MFA: ${mfa.affected.map((item) => item.label).join(', ')}` : ''}. Sign-in does not enforce MFA.`, mechanism: 'Measured from Supabase Auth MFA factors' }
    } else if (key === 'admin-audit-retention') {
      verification = {
        state: input.audit.count > 0 ? 'met' : 'unknown',
        detail: input.audit.count > 0
          ? `${input.audit.count} administrator audit record(s) retained since ${input.audit.oldestAt ? new Date(input.audit.oldestAt).toISOString().slice(0, 10) : 'unknown'}; no deletion job exists.`
          : 'No audit records found to verify retention.',
        mechanism: 'admin_audit_events (append-only from the admin API)',
      }
    } else {
      verification = { state: 'attested', detail: 'No automated check exists for this policy — it is an attestation.', mechanism: null }
    }
    return {
      id: row.id,
      key,
      name: text(row.name) || key,
      category: lower(row.category) || 'operations',
      status,
      enforcementLevel: lower(row.enforcement_level) || 'monitor',
      description: text(row.description),
      builtin: VERIFIED_POLICY_KEYS.has(key),
      verification,
      updatedAt: row.updated_at || row.created_at,
      updatedBy: row.updated_by ? input.emailById.get(row.updated_by) || row.updated_by : null,
    }
  }).sort((a, b) => Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name))

  const evidence: GovernanceEvidence[] = input.evidence.map((row) => {
    const metadata = row.metadata || {}
    const hash = metadata.hash && typeof metadata.hash === 'object' ? metadata.hash as { algorithm?: string; value?: string } : null
    const snapshot = (metadata as Record<string, unknown>).snapshot
    const intact = hash?.value && snapshot !== undefined ? input.verifyHash(snapshot, hash.value) : null
    return {
      id: row.id,
      title: text(row.title) || 'Evidence package',
      framework: text(row.framework) || 'Internal',
      type: text(row.evidence_type) || 'snapshot',
      createdAt: row.created_at,
      generatedBy: row.generated_by ? input.emailById.get(row.generated_by) || row.generated_by : null,
      hash: hash?.value ? { algorithm: text(hash.algorithm) || 'SHA3-256', value: hash.value } : null,
      intact,
      summary: metadata.summary && typeof metadata.summary === 'object' ? metadata.summary as Record<string, unknown> : null,
    }
  }).sort((a, b) => (timeOf(b.createdAt) ?? 0) - (timeOf(a.createdAt) ?? 0))

  const count = (predicate: (policy: GovernancePolicy) => boolean) => policies.reduce((sum, policy) => sum + (predicate(policy) ? 1 : 0), 0)
  const stats = {
    policies: policies.length,
    enabled: count((p) => p.status === 'enabled'),
    met: count((p) => p.verification.state === 'met'),
    notMet: count((p) => p.verification.state === 'not_met'),
    enforcedByPlatform: count((p) => p.verification.state === 'enforced_by_platform'),
    attested: count((p) => p.verification.state === 'attested'),
    evidence: evidence.length,
    evidenceIntact: evidence.filter((row) => row.intact === true).length,
    latestEvidenceAt: evidence[0]?.createdAt || null,
    auditRecords: input.audit.count,
    oldestAuditAt: input.audit.oldestAt,
  }
  const tampered = evidence.filter((row) => row.intact === false)
  const integrity: IntegrityCheck[] = [
    { id: 'evidence-intact', label: 'Every evidence package matches its fingerprint', ok: tampered.length === 0, detail: tampered.length ? `${tampered.length} package(s) no longer match their SHA3-256 fingerprint` : `${stats.evidenceIntact} verified, ${evidence.length - stats.evidenceIntact} without a fingerprint` },
    { id: 'policies-evaluated', label: 'Every enabled policy has a verification state', ok: policies.every((p) => p.verification.state !== 'unknown' || p.status === 'disabled'), detail: `${count((p) => p.verification.state === 'unknown')} policy(ies) could not be evaluated` },
  ]
  const model = { policies, evidence, stats, integrity }
  return { ...model, version: modelVersion(model), generatedAt: new Date(now).toISOString() }
}
