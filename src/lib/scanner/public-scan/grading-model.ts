/**
 * QGuard Helix — Public Quantum Exposure Assessment™
 * Grading Model — the single source of truth for the weighted scoring model,
 * the score→grade mapping, and the grade meanings shown to the user.
 *
 * This mirrors the published Security Grade Reference (opened from "How the
 * Grading Works") field for field: the same 12 weighted categories, the same
 * score thresholds, the same rating/risk-level vocabulary. A user comparing
 * the live report against that reference document must never find a
 * discrepancy — this file is what guarantees that.
 */

import { findControl, resolveKeyExchange } from './controls'
import type { ControlState, PublicScanEvidence, RiskBand, ScoreComponent, SecurityGrade } from './types'

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)))

// ─── Weighted Scoring Model ─────────────────────────────────────────────────

export interface ScoreCategoryDef {
  key: string
  label: string
  weight: number
  description: string
}

/** 12 categories, weights sum to exactly 100 — the published model. */
export const SCORE_CATEGORY_DEFS: ScoreCategoryDef[] = [
  { key: 'tls-configuration', label: 'TLS Configuration', weight: 18, description: 'TLS versions, protocol strength and best practices' },
  { key: 'cipher-suites', label: 'Cipher Suites', weight: 15, description: 'Cipher strength, key sizes, AEAD usage, legacy ciphers' },
  { key: 'certificates', label: 'Certificates', weight: 12, description: 'Validity, chain quality, key size, algorithms, expiration' },
  { key: 'key-exchange', label: 'Key Exchange', weight: 12, description: 'Key exchange strength, hybrid PQ, named groups' },
  { key: 'forward-secrecy', label: 'Forward Secrecy', weight: 10, description: 'PFS support (ECDHE, DHE, Hybrid PQ)' },
  { key: 'http-security-headers', label: 'HTTP Security Headers', weight: 8, description: 'HSTS, CSP, COOP, COEP, XFO and related headers' },
  { key: 'hsts', label: 'HSTS', weight: 5, description: 'HSTS presence, max-age, preload, subdomains' },
  { key: 'ocsp-stapling', label: 'OCSP Stapling', weight: 5, description: 'Stapling enabled, response status' },
  { key: 'certificate-transparency', label: 'Certificate Transparency', weight: 3, description: 'SCTs present, valid, embedded in cert' },
  { key: 'dns-caa', label: 'DNS CAA', weight: 4, description: 'CAA records presence and policy strength' },
  { key: 'cryptographic-algorithms', label: 'Cryptographic Algorithms', weight: 5, description: 'Use of modern, secure and PQC algorithms' },
  { key: 'post-quantum-readiness', label: 'Post-Quantum Readiness', weight: 3, description: 'Hybrid PQ support, algorithms observed' },
]

// Fail fast on a mis-typed weight rather than silently publishing a grade off
// a model that doesn't actually sum to 100 — this is the number the whole
// report is built on.
if (SCORE_CATEGORY_DEFS.reduce((sum, def) => sum + def.weight, 0) !== 100) {
  throw new Error('SCORE_CATEGORY_DEFS weights must sum to 100')
}

export const CLASSICAL_CATEGORY_KEYS = SCORE_CATEGORY_DEFS.filter(
  (def) => def.key !== 'cryptographic-algorithms' && def.key !== 'post-quantum-readiness',
).map((def) => def.key)

// ─── Score → Grade mapping ───────────────────────────────────────────────────

export interface GradeRow {
  min: number
  max: number
  grade: SecurityGrade
  rating: string
  riskLevel: RiskBand
  color: string
  meaning: string
}

/** Risk severity, lowest to highest — used to compare/escalate a risk level. */
export const RISK_ORDER: RiskBand[] = ['Very Low', 'Low', 'Moderate', 'Elevated', 'High', 'Critical', 'Not assessable']

/**
 * Risk-level palette, independent of the grade-color table above (a risk
 * level is not always paired with a grade — e.g. before grading, or the
 * critical-finding escalation floor). Every RiskBand value is covered
 * explicitly so a new/renamed value fails typechecking here rather than
 * silently falling through to a wrong color at the call site.
 */
export const RISK_COLOR: Record<RiskBand, string> = {
  'Very Low': '#10b981',
  Low: '#22c55e',
  Moderate: '#eab308',
  Elevated: '#f97316',
  High: '#ef4444',
  Critical: '#991b1b',
  'Not assessable': '#94a3b8',
}

/** Score-to-Grade Mapping, verbatim from the published reference. */
export const SCORE_GRADE_TABLE: GradeRow[] = [
  { min: 98, max: 100, grade: 'A+', rating: 'Elite', riskLevel: 'Very Low', color: '#10b981', meaning: 'Excellent security posture with modern cryptography and strong PQ readiness.' },
  { min: 94, max: 97, grade: 'A', rating: 'Excellent', riskLevel: 'Very Low', color: '#22c55e', meaning: 'Secure configuration with only minor optimization opportunities.' },
  { min: 90, max: 93, grade: 'A-', rating: 'Excellent', riskLevel: 'Low', color: '#22c55e', meaning: 'Strong deployment with a few recommended improvements.' },
  { min: 85, max: 89, grade: 'B+', rating: 'Good', riskLevel: 'Low', color: '#22d3ee', meaning: 'Secure overall, but some controls should be modernized.' },
  { min: 80, max: 84, grade: 'B', rating: 'Good', riskLevel: 'Moderate', color: '#22d3ee', meaning: 'Good security posture with several improvement opportunities.' },
  { min: 75, max: 79, grade: 'B-', rating: 'Fair', riskLevel: 'Moderate', color: '#3b82f6', meaning: 'Acceptable today, but migration planning should begin.' },
  { min: 70, max: 74, grade: 'C+', rating: 'Fair', riskLevel: 'Elevated', color: '#eab308', meaning: 'Security is adequate but has multiple weaknesses.' },
  { min: 65, max: 69, grade: 'C', rating: 'Fair', riskLevel: 'Elevated', color: '#f97316', meaning: 'Noticeable exposure and aging cryptography.' },
  { min: 60, max: 64, grade: 'C-', rating: 'Weak', riskLevel: 'High', color: '#f97316', meaning: 'Multiple issues requiring remediation.' },
  { min: 50, max: 59, grade: 'D', rating: 'Weak', riskLevel: 'High', color: '#ef4444', meaning: 'Outdated or incomplete security controls.' },
  { min: 0, max: 49, grade: 'F', rating: 'Critical', riskLevel: 'Critical', color: '#991b1b', meaning: 'Severe weaknesses requiring immediate attention.' },
]

export function scoreToGrade(score: number): GradeRow {
  const clamped = clamp(score)
  return (
    SCORE_GRADE_TABLE.find((row) => clamped >= row.min && clamped <= row.max) ??
    SCORE_GRADE_TABLE[SCORE_GRADE_TABLE.length - 1]
  )
}

/**
 * The gauge's colored arc, ascending 0→100 — literally `SCORE_GRADE_TABLE`
 * re-ordered, not a separate hand-picked ramp. Whatever color the arc shows
 * under the pointer at a given score IS the color `scoreToGrade` assigns that
 * score; the two can never disagree because they read the same table.
 */
export const GAUGE_ARC_BANDS: Array<{ from: number; to: number; color: string }> = [...SCORE_GRADE_TABLE]
  .sort((a, b) => a.min - b.min)
  .map((row, index, ascending) => ({
    from: row.min,
    to: index === ascending.length - 1 ? 100 : ascending[index + 1].min,
    color: row.color,
  }))

/**
 * The six ratings a grade can carry, each with the color of its *best* (lowest
 * risk) grade — used for the gauge legend. The legend's label vocabulary is
 * exactly `ExecutiveSummary.gradeLabel`'s vocabulary, so highlighting the
 * active chip is a plain string match, not a re-derived score range that could
 * drift from the table that actually produced the rating.
 */
export const RATING_TIERS: Array<{ rating: string; color: string }> = (() => {
  const ascendingByBestScore = [...SCORE_GRADE_TABLE].sort((a, b) => b.max - a.max)
  const seen = new Set<string>()
  const tiers: Array<{ rating: string; color: string }> = []
  for (const row of ascendingByBestScore) {
    if (seen.has(row.rating)) continue
    seen.add(row.rating)
    tiers.push({ rating: row.rating, color: row.color })
  }
  return tiers.reverse() // worst → best, matching the gauge's left-to-right sweep
})()

// ─── Category scorers not backed 1:1 by a single control ────────────────────

/**
 * Key Exchange strength: distinct from Forward Secrecy. This scores WHICH
 * mechanism was negotiated (hybrid PQ > strong classical > weak > none), not
 * merely whether ephemeral key agreement is present at all.
 */
function keyExchangeScore(evidence: PublicScanEvidence): number | null {
  if (!evidence.tls) return null
  if (evidence.keyAgreement.hybridGroups.length) return 100
  if (evidence.keyAgreement.classicalGroups.length) return 70
  const kex = evidence.tls.keyExchange ?? ''
  if (/ecdhe|x25519|ffdhe/i.test(kex)) return 65
  if (/dhe/i.test(kex)) return 55
  if (/rsa/i.test(kex)) return 15
  // TLS 1.3 guarantees ephemeral key agreement even when the named-group probe
  // could not resolve which group — Node never exposes it for 1.3.
  return evidence.tls.tlsVersion === 'TLSv1.3' ? 65 : 30
}

/**
 * Cryptographic Algorithms: the share of everything the Cryptographic
 * Intelligence engine catalogued (cipher, cert key, signature hash, protocol,
 * key-agreement group) that classifies as Quantum Safe or Hybrid rather than
 * Classical, Legacy or Deprecated.
 */
function cryptographicAlgorithmsScore(evidence: PublicScanEvidence): number | null {
  const algorithms = evidence.engines?.crypto?.data?.algorithms ?? []
  if (!algorithms.length) return null
  const points = algorithms.reduce((sum, algorithm) => {
    if (algorithm.classification === 'Quantum Safe' || algorithm.classification === 'Hybrid') return sum + 100
    if (algorithm.classification === 'Classical') return sum + 55
    if (algorithm.classification === 'Legacy') return sum + 25
    return sum + 5 // Deprecated
  }, 0)
  return clamp(points / algorithms.length)
}

/** Certificates: blends the algorithm/trust score (65%) with lifecycle hygiene (35%). */
function certificatesScore(controls: ControlState[]): number | null {
  const algorithm = findControl(controls, 'certificate-algorithm')?.score ?? null
  const lifetime = findControl(controls, 'certificate-lifetime')?.score ?? null
  if (algorithm === null && lifetime === null) return null
  if (algorithm === null) return lifetime
  if (lifetime === null) return algorithm
  return clamp(algorithm * 0.65 + lifetime * 0.35)
}

// ─── Category aggregation ─────────────────────────────────────────────────────

/**
 * The published 12-category weighted model, computed from live evidence.
 *
 * Eight of the twelve categories pass an existing granular control's score
 * straight through; Certificates blends two related controls. Cryptographic
 * Algorithms and Post-Quantum Readiness are computed here directly from the
 * Cryptographic Intelligence engine and the dedicated PQ-readiness scorer, so
 * the number shown in this decomposition always matches the number shown on
 * the Post-Quantum Readiness stat elsewhere in the report — one calculation,
 * never two.
 */
export function buildScoreCategories(
  evidence: PublicScanEvidence,
  controls: ControlState[],
  postQuantumReadinessScore: number,
): ScoreComponent[] {
  const rawScore = (key: string): number | null => findControl(controls, key)?.score ?? null
  const observedOf = (key: string) => findControl(controls, key)?.observed ?? 'not observed'
  const detailOf = (key: string) => findControl(controls, key)?.detail ?? ''

  const cert = evidence.certificate
  const extras = evidence.certificateExtras
  const algorithms = evidence.engines?.crypto?.data?.algorithms ?? []
  // Post-quantum readiness (and the categories derived alongside it) cannot be
  // determined without a completed handshake — same "unobservable, not zero"
  // rule as every other dimension.
  const pqApplicable = evidence.tls !== null

  const rows: Array<{ key: string; score: number | null; observed: string; detail: string }> = [
    { key: 'tls-configuration', score: rawScore('tls-version'), observed: observedOf('tls-version'), detail: detailOf('tls-version') },
    { key: 'cipher-suites', score: rawScore('cipher-suite'), observed: observedOf('cipher-suite'), detail: detailOf('cipher-suite') },
    {
      key: 'certificates',
      score: certificatesScore(controls),
      observed: cert
        ? `${cert.publicKeyAlgorithm} · ${extras ? `${extras.validityDays}-day lifetime` : 'lifetime unknown'}`
        : 'not observed',
      detail: 'Blend of certificate algorithm/trust (65%) and lifecycle hygiene (35%)',
    },
    {
      key: 'key-exchange',
      score: keyExchangeScore(evidence),
      observed: evidence.tls ? resolveKeyExchange(evidence) : 'not observed',
      detail: 'Strength of the negotiated or accepted key-agreement mechanism',
    },
    { key: 'forward-secrecy', score: rawScore('forward-secrecy'), observed: observedOf('forward-secrecy'), detail: detailOf('forward-secrecy') },
    { key: 'http-security-headers', score: rawScore('http-security'), observed: observedOf('http-security'), detail: detailOf('http-security') },
    { key: 'hsts', score: rawScore('hsts'), observed: observedOf('hsts'), detail: detailOf('hsts') },
    { key: 'ocsp-stapling', score: rawScore('ocsp-stapling'), observed: observedOf('ocsp-stapling'), detail: detailOf('ocsp-stapling') },
    { key: 'certificate-transparency', score: rawScore('certificate-transparency'), observed: observedOf('certificate-transparency'), detail: detailOf('certificate-transparency') },
    { key: 'dns-caa', score: rawScore('dns-caa'), observed: observedOf('dns-caa'), detail: detailOf('dns-caa') },
    {
      key: 'cryptographic-algorithms',
      score: pqApplicable ? cryptographicAlgorithmsScore(evidence) : null,
      observed: algorithms.length ? `${algorithms.length} algorithms observed` : 'not observed',
      detail: 'Share of observed algorithms classified Quantum Safe or Hybrid',
    },
    {
      key: 'post-quantum-readiness',
      score: pqApplicable ? postQuantumReadinessScore : null,
      observed: pqApplicable ? `${postQuantumReadinessScore}% readiness` : 'not observed',
      detail: 'Hybrid post-quantum key agreement and signature observations',
    },
  ]

  const defByKey = new Map(SCORE_CATEGORY_DEFS.map((def) => [def.key, def]))
  return rows.map((row) => {
    const def = defByKey.get(row.key)
    if (!def) throw new Error(`Unknown score category key: ${row.key}`)
    return {
      key: row.key,
      label: def.label,
      score: row.score ?? 0,
      weight: def.weight,
      applicable: row.score !== null,
      observed: row.observed,
      detail: row.detail,
    }
  })
}
