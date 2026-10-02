/**
 * Enterprise report DOCUMENT model — a format-neutral description of a premium
 * report: cover, executive summary, ordered sections made of typed blocks,
 * decision register, validation and an integrity seal.
 *
 * Why blocks: every exporter (PDF, Word, Excel, PowerPoint, HTML, CSV, JSON)
 * renders the same block list natively — a bar chart is a list of labelled
 * values, not a picture — so charts stay vector, stay accessible, and are
 * guaranteed to show the numbers the tables show. A block never computes; it
 * only presents values the report builder already derived.
 *
 * Pure types + tiny helpers; no renderer imports.
 */
import type { ReportBranding, ReportTable } from './schemas/ReportSchema'
import type { IntegritySeal } from './ReportIntegrity'

export type BlockTone = 'critical' | 'high' | 'medium' | 'low' | 'good' | 'info' | 'neutral' | 'warning'

export interface DocumentFact {
  label: string
  value: string
}

export interface DocumentKpi {
  label: string
  value: string
  detail?: string
  tone?: BlockTone
}

export interface BarItem {
  label: string
  value: number
  /** Hex colour of the mark. Text never wears it — labels stay in ink. */
  color: string
  detail?: string
}

export interface StackSegment {
  label: string
  value: number
  color: string
}

/**
 * Table cell emphasis: the renderer paints a status pill for these columns.
 * The pill carries the TEXT too, so status is never colour-only.
 */
export interface TableEmphasis {
  column: number
  kind: 'severity' | 'status' | 'band' | 'priority'
}

export type DocumentBlock =
  | { type: 'paragraph'; text: string; tone?: 'normal' | 'muted' | 'lead' }
  | { type: 'kpis'; items: DocumentKpi[] }
  | { type: 'bars'; title: string; caption?: string; items: BarItem[]; unit?: string }
  | { type: 'stacked'; title: string; caption?: string; segments: StackSegment[]; total: number; unit?: string }
  | { type: 'table'; table: ReportTable; widths?: number[]; emphasis?: TableEmphasis[]; note?: string; wide?: boolean }
  | { type: 'callout'; tone: BlockTone; title: string; text: string }
  | { type: 'bullets'; items: string[] }
  | { type: 'facts'; items: DocumentFact[] }
  | { type: 'dossier'; dossier: AssetDossier }

export interface AssetDossier {
  id: string
  title: string
  subtitle: string
  badges: Array<{ label: string; tone: BlockTone }>
  facts: DocumentFact[]
  summary: string
  tables: Array<{ table: ReportTable; widths?: number[]; emphasis?: TableEmphasis[]; note?: string }>
}

export interface DocumentSection {
  id: string
  title: string
  intro?: string
  blocks: DocumentBlock[]
  /** Start the section on a new page in paginated formats. */
  pageBreak?: boolean
}

export interface DecisionEntry {
  priority: 'P1' | 'P2' | 'P3'
  decision: string
  rationale: string
  evidence: string
  owner: string
}

export interface ValidationEntry {
  check: string
  status: 'pass' | 'warn' | 'fail'
  detail: string
}

export interface DocumentValidation {
  status: 'pass' | 'warn' | 'fail'
  /** 0–100 quality score: every WARN costs 8 points, every FAIL 30. */
  score: number
  checks: ValidationEntry[]
}

export interface ReportDocument {
  branding: ReportBranding
  template: { key: string; name: string; audience: string }
  cover: {
    eyebrow: string
    title: string
    subtitle: string
    scopeLine: string
    facts: DocumentFact[]
  }
  summary: {
    headline: string
    paragraphs: string[]
    highlights: DocumentKpi[]
  }
  sections: DocumentSection[]
  decisions: DecisionEntry[]
  validation: DocumentValidation
  /** Evidence sources, definitions and methodology lines printed in the closing section. */
  provenance: string[]
  integrity?: IntegritySeal
}

export const TONE_HEX: Record<BlockTone, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#16A34A',
  good: '#16A34A',
  info: '#2478FF',
  warning: '#D97706',
  neutral: '#64748B',
}

/** Tone for a status/severity word, so every renderer paints the same pill. */
export function toneForLabel(value: string): BlockTone {
  const text = String(value || '').toLowerCase()
  if (/critical|quantum-vulnerable|vulnerable|fail/.test(text)) return 'critical'
  if (/\bhigh\b/.test(text)) return 'high'
  if (/\bstale\b/.test(text)) return 'warning'
  if (/elevated|medium|moderate|review|warn|aging/.test(text)) return 'medium'
  if (/pqc-ready|ready|pass|match|fresh|safe|current/.test(text)) return 'good'
  if (/\blow\b|minimal/.test(text)) return 'low'
  return 'neutral'
}

/**
 * Tone of an emphasised table cell. ONE mapping for every renderer, so a
 * "Critical" cell is the same red in the PDF, the Word file and the deck.
 */
export function cellTone(kind: TableEmphasis['kind'], value: unknown): BlockTone {
  const text = String(value ?? '').trim()
  if (kind === 'priority') return text === 'P1' ? 'critical' : text === 'P2' ? 'medium' : text === 'P3' ? 'low' : 'neutral'
  if (kind === 'severity') {
    const lower = text.toLowerCase()
    if (lower === 'critical') return 'critical'
    if (lower === 'high') return 'high'
    if (lower === 'medium') return 'medium'
    if (lower === 'low') return 'low'
    if (lower === 'safe') return 'good'
    if (text === 'P1') return 'critical'
    if (text === 'P2') return 'medium'
    if (text === 'P3') return 'low'
    return 'neutral'
  }
  return toneForLabel(text)
}

export function validationScore(checks: ValidationEntry[]): DocumentValidation {
  const warns = checks.filter((c) => c.status === 'warn').length
  const fails = checks.filter((c) => c.status === 'fail').length
  const score = Math.max(0, 100 - warns * 8 - fails * 30)
  return { status: fails ? 'fail' : warns ? 'warn' : 'pass', score, checks }
}
