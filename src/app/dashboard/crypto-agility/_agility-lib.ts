/**
 * Crypto Agility Command Center — presentation library.
 *
 * Pure client-side helpers only: tone mapping, formatting, filtering, sorting,
 * CSV export and URL query-state. Every NUMBER shown on the page comes from the
 * server-side agility engine; nothing is computed or invented here.
 */

import { quotedCsvCell as csvCell } from '@/lib/csv'
import type {
  AgilityAssetRow,
  AgilityDomain,
  AgilityState,
  ControlDomain,
  CryptoAgilityIntelligence,
  MigrationReadinessState,
  ReplaceabilityClass,
  ResponsibilityRow,
  Severity,
} from '@/lib/crypto-agility/agility-intelligence'
import {
  AGILITY_STATE_LABEL,
  MIGRATION_READINESS_LABEL,
  REPLACEABILITY_LABEL,
} from '@/lib/crypto-agility/agility-intelligence'

export type Tone = 'good' | 'warning' | 'critical' | 'neutral' | 'info' | 'ai'

export const CYAN = '#22d3ee'
export const GREEN = '#34d399'
export const AMBER = '#fbbf24'
export const RED = '#f87171'
export const BLUE = '#60a5fa'
export const VIOLET = '#a78bfa'
export const SLATE = '#94a3b8'

export const TONE_HEX: Record<Tone, string> = {
  good: GREEN,
  warning: AMBER,
  critical: RED,
  neutral: CYAN,
  info: BLUE,
  ai: VIOLET,
}

/**
 * State → tone. `unknown` is deliberately NEUTRAL-SLATE, never green: an
 * unmeasured implementation must never read as safe.
 */
export const STATE_TONE: Record<AgilityState, Tone> = {
  agile: 'good',
  conditional: 'warning',
  rigid: 'warning',
  blocked: 'critical',
  unknown: 'info',
}

export const STATE_HEX: Record<AgilityState, string> = {
  agile: GREEN,
  conditional: AMBER,
  rigid: '#fb923c',
  blocked: RED,
  unknown: SLATE,
}

/** Accessibility: risk is never communicated by colour alone (§37). */
export const STATE_GLYPH: Record<AgilityState, string> = {
  agile: '●',
  conditional: '◐',
  rigid: '◑',
  blocked: '■',
  unknown: '?',
}

export const READINESS_TONE: Record<MigrationReadinessState, Tone> = {
  ready: 'good',
  conditional: 'warning',
  blocked: 'critical',
  unknown: 'info',
}

export const REPLACEABILITY_TONE: Record<ReplaceabilityClass, Tone> = {
  configuration: 'good',
  library: 'warning',
  code: 'warning',
  architecture: 'critical',
  vendor: 'critical',
  unknown: 'info',
}

/** Traffic-light glyphs from the guideline's replaceability test (§13). */
export const REPLACEABILITY_GLYPH: Record<ReplaceabilityClass, string> = {
  configuration: '🟢',
  library: '🟡',
  code: '🟠',
  architecture: '🔴',
  vendor: '⚫',
  unknown: '⚪',
}

export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'critical',
  high: 'warning',
  medium: 'warning',
  low: 'good',
  info: 'info',
}

export const CONTROL_DOMAIN_TONE: Record<ControlDomain, Tone> = {
  customer: 'good',
  provider: 'info',
  ecosystem: 'ai',
}

export { AGILITY_STATE_LABEL, MIGRATION_READINESS_LABEL, REPLACEABILITY_LABEL }

/* ------------------------------------------------------------------ */
/* Formatters                                                          */
/* ------------------------------------------------------------------ */

export function numberFmt(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return new Intl.NumberFormat('en-US').format(Math.round(value))
}

/** Renders an unmeasured value honestly — never as 0. */
export function scoreFmt(value: number | null | undefined, suffix = ''): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return 'Unknown'
  return `${Math.round(value)}${suffix}`
}

export function pctFmt(value: number | null | undefined): string {
  return scoreFmt(value, '%')
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return 'never'
  const diff = Date.now() - then
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return 'No assessment recorded'
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return 'No assessment recorded'
  return date.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })
}

export function clampPct(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

/* ------------------------------------------------------------------ */
/* Filtering + sorting (client-side over the delivered page)           */
/* ------------------------------------------------------------------ */

export interface AgilityFilters {
  search: string
  state: AgilityState | 'all'
  readiness: MigrationReadinessState | 'all'
  replaceability: ReplaceabilityClass | 'all'
  environment: string
  owner: string
  controlDomain: ControlDomain | 'all'
  algorithm: string
}

export const EMPTY_FILTERS: AgilityFilters = {
  search: '',
  state: 'all',
  readiness: 'all',
  replaceability: 'all',
  environment: 'all',
  owner: 'all',
  controlDomain: 'all',
  algorithm: 'all',
}

export type AssetSortKey = 'agility' | 'risk' | 'dependencies' | 'blockers' | 'name'

export function filterAssets(rows: AgilityAssetRow[], filters: AgilityFilters): AgilityAssetRow[] {
  const search = filters.search.trim().toLowerCase()
  return rows.filter((row) => {
    if (search) {
      const haystack = `${row.name} ${row.type} ${row.owner} ${row.environment} ${row.currentAlgorithms.join(' ')} ${row.targetAlgorithms.join(' ')}`.toLowerCase()
      if (!haystack.includes(search)) return false
    }
    if (filters.state !== 'all' && row.agilityState !== filters.state) return false
    if (filters.readiness !== 'all' && row.readiness !== filters.readiness) return false
    if (filters.replaceability !== 'all' && row.replaceability !== filters.replaceability) return false
    if (filters.environment !== 'all' && row.environment !== filters.environment) return false
    if (filters.owner !== 'all' && row.owner !== filters.owner) return false
    if (filters.controlDomain !== 'all' && row.controlDomain !== filters.controlDomain) return false
    if (filters.algorithm !== 'all' && !row.currentAlgorithms.some((a) => a.toUpperCase() === filters.algorithm.toUpperCase())) return false
    return true
  })
}

export function sortAssets(rows: AgilityAssetRow[], key: AssetSortKey, direction: 'asc' | 'desc'): AgilityAssetRow[] {
  const sign = direction === 'asc' ? 1 : -1
  const sorted = [...rows]
  sorted.sort((a, b) => {
    switch (key) {
      case 'risk':
        return sign * (a.riskScore - b.riskScore)
      case 'dependencies':
        return sign * (a.dependencies - b.dependencies)
      case 'blockers':
        return sign * (a.blockers - b.blockers || a.couplingFindings - b.couplingFindings)
      case 'name':
        return sign * a.name.localeCompare(b.name)
      default: {
        // Unmeasured assets sink to the end in either direction — an unknown is
        // not "most agile" and must not top the list.
        const av = a.agilityScore ?? Number.POSITIVE_INFINITY
        const bv = b.agilityScore ?? Number.POSITIVE_INFINITY
        if (!Number.isFinite(av) && !Number.isFinite(bv)) return 0
        if (!Number.isFinite(av)) return 1
        if (!Number.isFinite(bv)) return -1
        return sign * (av - bv)
      }
    }
  })
  return sorted
}

export function filterResponsibility(rows: ResponsibilityRow[], filters: AgilityFilters): ResponsibilityRow[] {
  const search = filters.search.trim().toLowerCase()
  return rows.filter((row) => {
    if (filters.controlDomain !== 'all' && row.controlDomain !== filters.controlDomain) return false
    if (filters.state !== 'all' && row.agilityState !== filters.state) return false
    if (search && !`${row.finding} ${row.asset} ${row.owner} ${row.userAction}`.toLowerCase().includes(search)) return false
    return true
  })
}

/* ------------------------------------------------------------------ */
/* URL query-state (§25 — filters survive a reload / shared link)      */
/* ------------------------------------------------------------------ */

const QUERY_KEYS: Array<keyof AgilityFilters> = ['search', 'state', 'readiness', 'replaceability', 'environment', 'owner', 'controlDomain', 'algorithm']

export function filtersFromSearchParams(search: string): AgilityFilters {
  const params = new URLSearchParams(search)
  const next: AgilityFilters = { ...EMPTY_FILTERS }
  for (const key of QUERY_KEYS) {
    const value = params.get(key)
    // Values are validated by the consuming filter functions (an unknown value
    // simply matches nothing), so a hand-edited URL can never crash the page.
    if (value) (next as unknown as Record<string, string>)[key] = value
  }
  return next
}

export function filtersToSearchParams(filters: AgilityFilters): string {
  const params = new URLSearchParams()
  for (const key of QUERY_KEYS) {
    const value = filters[key]
    if (value && value !== 'all' && value !== '') params.set(key, String(value))
  }
  const query = params.toString()
  return query ? `?${query}` : ''
}

export function activeFilterCount(filters: AgilityFilters): number {
  return QUERY_KEYS.reduce((count, key) => {
    const value = filters[key]
    return value && value !== 'all' && value !== '' ? count + 1 : count
  }, 0)
}

/* ------------------------------------------------------------------ */
/* Export                                                              */
/* ------------------------------------------------------------------ */

export function downloadTextFile(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export function assetsToCsv(rows: AgilityAssetRow[]): string {
  const header = [
    'Asset',
    'Type',
    'Environment',
    'Owner',
    'Criticality',
    'Agility State',
    'Agility Score',
    'Coupling Assessed',
    'Replaceability',
    'Migration Readiness',
    'Current Algorithms',
    'Target Algorithms',
    'Dependencies',
    'Blockers',
    'Coupling Findings',
    'Components',
    'Vulnerable Components',
    'Risk Score',
    'Control Domain',
    'Migration Status',
    'Next Action',
    'Basis',
  ]
  const lines = rows.map((r) =>
    [
      r.name,
      r.type,
      r.environment,
      r.owner,
      r.businessCriticality,
      AGILITY_STATE_LABEL[r.agilityState],
      r.agilityScore === null ? 'Insufficient Evidence' : r.agilityScore,
      r.hasEvidence ? (r.couplingAssessed ? 'Yes' : 'No — edge evidence only') : 'No evidence',
      r.replaceabilityLabel,
      r.readinessLabel,
      r.currentAlgorithms.join(' | '),
      r.targetAlgorithms.join(' | '),
      r.dependencies,
      r.blockers,
      r.couplingFindings,
      r.componentCount,
      r.vulnerableComponentCount,
      r.riskScore,
      r.controlDomain,
      r.migrationStatus,
      r.nextAction,
      r.basis,
    ]
      .map(csvCell)
      .join(','),
  )
  return [header.map(csvCell).join(','), ...lines].join('\n')
}

export function replaceabilityToCsv(intel: CryptoAgilityIntelligence): string {
  const header = ['Current Algorithm', 'Classification', 'Proposed Replacement', 'Standard', 'Assets', 'Instances', 'Replaceability', 'Dependencies', 'Migration Complexity', 'Compatibility', 'Risk', 'Status', 'Basis']
  const lines = intel.replaceability.map((r) =>
    [r.currentAlgorithm, r.classification, r.proposedReplacement, r.standard, r.assets, r.instances, r.replaceabilityLabel, r.dependencies, r.migrationComplexity, r.compatibility, r.risk, AGILITY_STATE_LABEL[r.status], r.basis]
      .map(csvCell)
      .join(','),
  )
  return [header.map(csvCell).join(','), ...lines].join('\n')
}

export function responsibilityToCsv(rows: ResponsibilityRow[]): string {
  const header = ['Finding', 'Asset', 'Owner', 'User Action', 'Priority', 'Control Domain', 'Status', 'Occurrences', 'Agility State']
  const lines = rows.map((r) =>
    [r.finding, r.asset, r.owner, r.userAction, r.priority, r.controlDomainLabel, r.status, r.occurrences, AGILITY_STATE_LABEL[r.agilityState]].map(csvCell).join(','),
  )
  return [header.map(csvCell).join(','), ...lines].join('\n')
}

/* ------------------------------------------------------------------ */
/* Sophia question builders (grounded in the tenant's own numbers)     */
/* ------------------------------------------------------------------ */

export function sophiaQuestionsFor(intel: CryptoAgilityIntelligence | null): string[] {
  if (!intel) return ['Why is our crypto agility score low?']
  const weakest = intel.domains.filter((d) => d.score !== null).sort((a, b) => (a.score as number) - (b.score as number))[0]
  const topBlocker = intel.blockers[0]
  const questions = [
    'Why is our crypto agility score what it is?',
    'What are our biggest migration blockers?',
    'Which applications are cryptographically rigid?',
    'Which vendor dependencies are blocking PQC migration?',
    'Which remediation would improve our agility score the most?',
    'Show me all customer-controlled blockers.',
    'Which assets should we migrate first?',
  ]
  if (weakest) questions.unshift(`Why is our ${weakest.label} only ${weakest.score}/100?`)
  if (topBlocker) questions.push(`What happens if we resolve the ${topBlocker.categoryLabel.toLowerCase()} blockers?`)
  const worstAlgo = intel.replaceability.find((r) => r.classification === 'vulnerable')
  if (worstAlgo) questions.push(`What would happen if we replaced ${worstAlgo.currentAlgorithm} with ${worstAlgo.proposedReplacement}?`)
  return questions.slice(0, 9)
}

/** Grounding context handed to Sophia alongside a question. */
export function sophiaContextFor(intel: CryptoAgilityIntelligence | null): string {
  if (!intel) return 'Crypto Agility Command Center'
  return [
    'Crypto Agility Command Center',
    `agility score ${scoreFmt(intel.score.agilityScore)}`,
    `migration readiness ${pctFmt(intel.score.migrationReadinessPct)}`,
    `${intel.score.assetsEvaluated} assets evaluated`,
    `${intel.score.criticalBlockers} critical/high blockers`,
  ].join(' · ')
}

/* ------------------------------------------------------------------ */
/* Domain helpers                                                      */
/* ------------------------------------------------------------------ */

export function domainTone(domain: AgilityDomain): Tone {
  if (domain.score === null) return 'info'
  if (domain.score >= 75) return 'good'
  if (domain.score >= 45) return 'warning'
  return 'critical'
}

export function confidenceLabel(confidence: AgilityDomain['confidence']): string {
  switch (confidence) {
    case 'high':
      return 'High confidence'
    case 'medium':
      return 'Medium confidence'
    case 'low':
      return 'Low confidence'
    default:
      return 'No evidence'
  }
}
