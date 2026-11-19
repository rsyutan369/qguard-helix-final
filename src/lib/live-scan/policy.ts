/**
 * Real Time Scanning — the central severity and finding policy.
 *
 * Every severity, finding type, exposure class and "which node does this
 * finding belong to" decision is made HERE, once. Components never hardcode a
 * severity; they read the finding's own fields, which this module set.
 *
 * Engine findings keep the engine's own threat level (the scanner already
 * scored them with its detection rules); this module only maps that verdict
 * onto the live vocabulary and onto the graph.
 */

import type { ExposureClass, FindingType, NodeStatus, Severity } from './types'

export const POLICY_ID = 'qguard-live-quantum-policy'
export const POLICY_VERSION = '1.1.0'

export type EngineThreat = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE'

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
}

export const EXPOSURE_LABEL: Record<ExposureClass, string> = {
  'quantum-migration': 'Quantum migration exposure',
  misconfiguration: 'Existing misconfiguration',
  'invalid-cryptography': 'Already-invalid cryptography',
  'unsupported-capability': 'Unsupported capability',
  'unknown-migration-status': 'Unknown migration status',
}

export const FINDING_TYPE_LABEL: Record<FindingType, string> = {
  QUANTUM_VULNERABLE_PUBLIC_KEY: 'Quantum-vulnerable public key',
  CLASSICAL_KEY_EXCHANGE_OBSERVED: 'Classical key establishment',
  CLASSICAL_SIGNATURE_DEPENDENCY: 'Classical signature dependency',
  CERTIFICATE_EXPIRED: 'Certificate expired',
  CERTIFICATE_EXPIRING: 'Certificate expiring',
  CERTIFICATE_CHAIN_INVALID: 'Certificate chain invalid',
  UNTRUSTED_CERTIFICATE_AUTHORITY: 'Untrusted certificate authority',
  HOSTNAME_VALIDATION_FAILED: 'Hostname validation failed',
  LEGACY_TLS_CONFIGURATION: 'Legacy TLS configuration',
  PQC_READINESS_UNKNOWN: 'PQC readiness unknown',
  PQC_MIGRATION_REQUIRED: 'PQC migration required',
  VENDOR_MIGRATION_DEPENDENCY: 'Vendor migration dependency',
  CERTIFICATE_HYGIENE: 'Certificate hygiene',
  DNS_POLICY_GAP: 'DNS policy gap',
  SCAN_INCOMPLETE: 'Scan incomplete',
  CRYPTO_POSTURE: 'Cryptographic posture',
}

export function severityFromThreat(threat: EngineThreat): Severity {
  switch (threat) {
    case 'CRITICAL': return 'critical'
    case 'HIGH': return 'high'
    case 'MEDIUM': return 'medium'
    case 'LOW': return 'low'
    default: return 'info'
  }
}

/** Which graph entity a finding is attached to. */
export type FindingAnchor = 'certificate' | 'key-establishment' | 'endpoint' | 'asset' | 'application'

export interface EngineFindingShape {
  phase: string
  category: string
  algorithm: string
  threatLevel: EngineThreat
  description?: string
}

export interface FindingClassification {
  type: FindingType
  exposure: ExposureClass
  severity: Severity
  anchor: FindingAnchor
}

const DEPRECATED_PROTOCOL = /\bssl\s*v?[23](\.0)?\b|\btls\s*v?1(\.[01])?(?![.\d])/i
const ASYMMETRIC_CATEGORY = /^(rsa|ecc|asymmetric|dsa|dh|signature|certificate signature)$/i

/**
 * Map one engine finding onto the live finding vocabulary.
 *
 * Order matters: the most specific evidence wins (an expired certificate is an
 * expiry finding even though it was raised in the certificate phase that also
 * produces public-key findings).
 */
export function classifyEngineFinding(finding: EngineFindingShape): FindingClassification {
  const severity = severityFromThreat(finding.threatLevel)
  const category = finding.category.trim()
  const algorithm = finding.algorithm.trim()
  const phase = finding.phase.trim()

  if (/expired/i.test(algorithm)) {
    return { type: 'CERTIFICATE_EXPIRED', exposure: 'invalid-cryptography', severity, anchor: 'certificate' }
  }
  if (/expir/i.test(algorithm)) {
    return { type: 'CERTIFICATE_EXPIRING', exposure: 'misconfiguration', severity, anchor: 'certificate' }
  }
  if (category === 'Connectivity' || /repository scan error/i.test(category)) {
    return { type: 'SCAN_INCOMPLETE', exposure: 'unknown-migration-status', severity, anchor: 'endpoint' }
  }
  if (category === 'DNS Security') {
    return { type: 'DNS_POLICY_GAP', exposure: 'misconfiguration', severity, anchor: 'asset' }
  }
  if (category === 'Certificate Revocation' || category === 'Certificate Transparency') {
    return { type: 'CERTIFICATE_HYGIENE', exposure: 'misconfiguration', severity, anchor: 'certificate' }
  }
  if (/key exchange|key agreement|rsa-kex|^dh$|dhe-|ecdhe-/i.test(category) || phase === 'key-exchange') {
    if (/^(unknown(?: key exchange)?|n\/?a|none|unavailable)$/i.test(algorithm)) {
      return { type: 'PQC_READINESS_UNKNOWN', exposure: 'unknown-migration-status', severity, anchor: 'key-establishment' }
    }
    if (/ml[- ]?kem/i.test(algorithm)) {
      return { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'key-establishment' }
    }
    return { type: 'CLASSICAL_KEY_EXCHANGE_OBSERVED', exposure: 'quantum-migration', severity, anchor: 'key-establishment' }
  }
  /* Detection-rule results arrive as "Rule (<category>)"; the rule's own
     category is the routing key. */
  const rule = /^rule \((.+)\)$/i.exec(category)?.[1]?.toLowerCase() ?? null
  if (DEPRECATED_PROTOCOL.test(algorithm) && (/protocol/i.test(category) || phase === 'tls-handshake')) {
    return { type: 'LEGACY_TLS_CONFIGURATION', exposure: 'invalid-cryptography', severity, anchor: 'endpoint' }
  }
  if (/protocol/i.test(category)) {
    // A modern protocol (TLS 1.2) flagged for not being 1.3 is posture, not legacy.
    return { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity: /^tlsv?1\.[23]$/i.test(algorithm) ? 'info' : severity, anchor: 'endpoint' }
  }
  if (rule) {
    if (/certificate/.test(rule)) {
      return /rsa|ecc|ecdsa|oid|key size|quantum/i.test(algorithm)
        ? { type: 'QUANTUM_VULNERABLE_PUBLIC_KEY', exposure: 'quantum-migration', severity, anchor: 'certificate' }
        : { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'certificate' }
    }
    if (/tls/.test(rule)) {
      return /deprecated|ssl/i.test(algorithm)
        ? { type: 'LEGACY_TLS_CONFIGURATION', exposure: 'invalid-cryptography', severity, anchor: 'endpoint' }
        : /key exchange|dh param/i.test(algorithm)
          ? { type: 'CLASSICAL_KEY_EXCHANGE_OBSERVED', exposure: 'quantum-migration', severity, anchor: 'key-establishment' }
          : { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'endpoint' }
    }
    if (/pqc|quantum/.test(rule)) return { type: 'PQC_MIGRATION_REQUIRED', exposure: 'quantum-migration', severity, anchor: 'asset' }
    if (/app|api|header|jwt/.test(rule)) return { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'application' }
  }
  if (/cipher/i.test(category) || phase === 'cipher-enum' || /^tls/i.test(category)) {
    return { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'endpoint' }
  }
  if (/signature/i.test(category)) {
    return { type: 'CLASSICAL_SIGNATURE_DEPENDENCY', exposure: 'quantum-migration', severity, anchor: 'certificate' }
  }
  if (phase === 'cert-analysis' && (ASYMMETRIC_CATEGORY.test(category) || (/^certificate$/i.test(category) && /rsa|ecdsa|ec |dsa/i.test(algorithm)))) {
    return { type: 'QUANTUM_VULNERABLE_PUBLIC_KEY', exposure: 'quantum-migration', severity, anchor: 'certificate' }
  }
  if (/nist compliance/i.test(category)) {
    return { type: 'PQC_MIGRATION_REQUIRED', exposure: 'quantum-migration', severity, anchor: 'asset' }
  }
  if (/pqc-readiness|long-term-quantum-risk|post-quantum|pqc/i.test(category)) {
    return { type: 'PQC_MIGRATION_REQUIRED', exposure: 'quantum-migration', severity, anchor: 'asset' }
  }
  if (phase === 'header-inspection' || phase === 'deep-scan' || /header|api|webcrypto|jwt|app-crypto|library|dependency/i.test(category)) {
    return {
      type: ASYMMETRIC_CATEGORY.test(category) ? 'PQC_MIGRATION_REQUIRED' : 'CRYPTO_POSTURE',
      exposure: ASYMMETRIC_CATEGORY.test(category) ? 'quantum-migration' : 'misconfiguration',
      severity,
      anchor: 'application',
    }
  }
  if (phase === 'cert-analysis') {
    return { type: 'CRYPTO_POSTURE', exposure: 'misconfiguration', severity, anchor: 'certificate' }
  }
  return { type: 'CRYPTO_POSTURE', exposure: ASYMMETRIC_CATEGORY.test(category) ? 'quantum-migration' : 'misconfiguration', severity, anchor: 'asset' }
}

/**
 * Node status implied by the worst open finding on it. Quantum-migration
 * exposure stays orange even at high severity unless the scanner rated it
 * critical: classical RSA/ECC is an exposure to plan for, not an incident.
 */
export function statusForFinding(severity: Severity, exposure: ExposureClass): NodeStatus {
  if (exposure === 'unknown-migration-status') return 'unknown'
  if (severity === 'critical') return 'critical'
  if (exposure === 'invalid-cryptography' && (severity === 'high' || severity === 'medium')) return 'critical'
  if (severity === 'high' && exposure !== 'quantum-migration') return 'critical'
  if (severity === 'info') return 'observed'
  return 'exposure'
}

const STATUS_RANK: Record<NodeStatus, number> = {
  validated: 0, observed: 1, active: 1, unknown: 2, exposure: 3, failed: 4, critical: 5,
}

/** Worst-of for status roll-ups; `unknown` outranks the good states. */
export function worseStatus(a: NodeStatus, b: NodeStatus): NodeStatus {
  return STATUS_RANK[b] > STATUS_RANK[a] ? b : a
}

/**
 * Display title for an engine finding: the specific finding type when the
 * policy recognised one, otherwise the engine's own category — a generic
 * "posture" label would hide what the rule actually measured.
 */
export function engineFindingTitle(type: FindingType, category: string, algorithm: string): string {
  if (type !== 'CRYPTO_POSTURE') return `${FINDING_TYPE_LABEL[type]}: ${algorithm}`
  const rule = /^rule \((.+)\)$/i.exec(category.trim())?.[1]
  const label = (rule ?? category).trim()
  return `${label.charAt(0).toUpperCase()}${label.slice(1)}: ${algorithm}`
}

/** Deterministic finding identity: one node per distinct issue, shared across targets. */
export function findingKey(parts: { type: FindingType; algorithm: string; severity: Severity; scope: string }): string {
  return `${parts.type}|${parts.algorithm.toLowerCase().replace(/\s+/g, ' ').trim()}|${parts.severity}|${parts.scope}`
}
