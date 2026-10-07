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

import type { RiskBand, SecurityGrade } from './types'

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

/**
 * Weighted mean over the categories that were actually measured.
 *
 * Inapplicable categories are excluded and their weight redistributed across the
 * rest — never scored as 0 (a claim the evidence does not support) and never as
 * 100 (a claim it supports even less). Shared so every surface that grades on
 * this model aggregates it identically.
 */
export function weightedCategoryScore(
  components: Array<{ score: number; weight: number; applicable: boolean }>,
): number {
  const scored = components.filter((component) => component.applicable)
  const totalWeight = scored.reduce((sum, component) => sum + component.weight, 0)
  if (!totalWeight) return 0
  return clamp(scored.reduce((sum, component) => sum + component.score * component.weight, 0) / totalWeight)
}

// ─── Post-quantum readiness model ────────────────────────────────────────────

/**
 * Signals the post-quantum readiness model scores. Deliberately primitive
 * booleans/numbers rather than an evidence object, so the public-edge scanner
 * and the authenticated estate scanner can both feed it from their own very
 * different evidence and still land on the SAME number for the same host.
 */
export interface PostQuantumSignals {
  /** A hybrid/PQ key-agreement group was actually negotiated or accepted. */
  hybridObserved: boolean
  /** A post-quantum signature algorithm appears in the served chain. */
  pqSignatureObserved: boolean
  /** TLS 1.3 is offered — the protocol hybrid groups deploy on. */
  tls13Offered: boolean
  /** Leaf certificate lifetime in days, when known. */
  certificateValidityDays: number | null
  /** Certificate Transparency participation observed. */
  certificateTransparency: boolean
  /** HSTS present AND hardened. */
  hstsEnforced: boolean
}

/**
 * Post-quantum readiness, 0-100. Deliberately conservative: a host scores 0
 * unless a hybrid/PQ group or PQ signature actually appears. Crypto-agility
 * signals earn a small "ready to move" allowance — the capability to migrate,
 * never a readiness claim.
 *
 * Weights: hybrid key agreement 55, PQ signature 30, TLS 1.3 12,
 * short-lived certificates 8, CT 3, enforced HSTS 3.
 */
export function postQuantumReadinessFromSignals(signals: PostQuantumSignals): {
  score: number
  reasons: string[]
} {
  const reasons: string[] = []
  let score = 0

  if (signals.hybridObserved) {
    score += 55
    reasons.push('Hybrid post-quantum key agreement negotiated in the TLS handshake.')
  } else {
    reasons.push('No hybrid or post-quantum key agreement offered.')
  }

  if (signals.pqSignatureObserved) {
    score += 30
    reasons.push('Post-quantum signature algorithm present in the served certificate chain.')
  } else {
    reasons.push('Certificate chain is signed with classical algorithms only.')
  }

  if (signals.tls13Offered) {
    score += 12
    reasons.push('TLS 1.3 is the protocol PQ hybrid groups deploy on — the prerequisite is met.')
  }
  if (signals.certificateValidityDays !== null && signals.certificateValidityDays > 0 && signals.certificateValidityDays <= 100) {
    score += 8
    reasons.push('Short-lived automated certificates enable fast algorithm rollover.')
  }
  if (signals.certificateTransparency) {
    score += 3
    reasons.push('Certificate Transparency participation supports auditable re-issuance.')
  }
  if (signals.hstsEnforced) {
    score += 3
    reasons.push('Enforced HTTPS narrows the downgrade path during a hybrid rollout.')
  }

  return { score: clamp(score), reasons }
}

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
 * re-ordered, not a separate hand-picked ramp.
 *
 * SEMANTICS: each band is half-open `[from, to)` so the drawn segments abut with
 * no hairline gap; only the final band includes its upper bound. Do NOT look a
 * score up in this array with an inclusive `score <= to` test — at every
 * boundary that returns the band *below* (score 70 would resolve to C rather
 * than C+). Use `arcBandColorFor()` instead, which is defined as the grade's own
 * colour and therefore cannot disagree with `scoreToGrade`.
 */
export const GAUGE_ARC_BANDS: Array<{ from: number; to: number; color: string }> = [...SCORE_GRADE_TABLE]
  .sort((a, b) => a.min - b.min)
  .map((row, index, ascending) => ({
    from: row.min,
    to: index === ascending.length - 1 ? 100 : ascending[index + 1].min,
    color: row.color,
  }))

/**
 * Colour of the arc segment a given score falls in.
 *
 * Defined as the grade's own colour rather than by searching the band array, so
 * "the colour under the pointer" and "the colour of the grade" are the same
 * value by construction and cannot drift apart.
 */
export function arcBandColorFor(score: number): string {
  return scoreToGrade(score).color
}

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

/* ─── Category scoring lives elsewhere now ───────────────────────────────────

   `buildScoreCategories` and its four private scorers used to sit here. They
   were ONE of two implementations of the twelve categories above — the other
   being `web-scanner/published-scoring.ts` — and fed byte-identical evidence
   for test.openquantumsafe.org the two disagreed on six of twelve categories,
   publishing B · Good against B- · Fair for the same endpoint at the same
   moment.

   There is now exactly one implementation, in
   `src/lib/scanner/published-categories.ts`, and both surfaces delegate to it:

     /public-scan         public-scan/score-categories.ts   -> buildScoreCategories
     /dashboard/scanner   web-scanner/published-scoring.ts  -> buildPublishedCategories

   This file keeps only the published STANDARD — the weight table, the grade
   table, the gauge bands and the post-quantum readiness model — which is what
   both surfaces agree on and what `published-categories.ts` imports. Putting an
   adapter back in here would close a module cycle, and would quietly re-open the
   door to a second opinion.

   `tools/surface-parity-check.ts` fails if a second opinion ever appears. */
