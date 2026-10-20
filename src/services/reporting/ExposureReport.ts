/**
 * Exposure assessment report — the premium export of `/dashboard/scanner`
 * Local and Dev modes.
 *
 * ── The accuracy contract ───────────────────────────────────────────────────
 *
 * Every figure in this document is READ from the same derivations the panels
 * render, never recomputed:
 *
 *   headline counts      `reconcileExposure`  (exposure-truth.ts)
 *   risk / coverage      `assessment.task.scores` — written by the orchestrator
 *   CBOM aggregation     `summariseCbom`      (cbom.ts)
 *   asset inventory      `summariseAssets`    (panel-model.ts)
 *   correlation split    `summariseCorrelation`
 *   evidence population  `evidencePopulation`
 *   standards cited      `summariseStandards`
 *   migration priority   `prioritiseMigration` (risk.ts)
 *
 * A derivation re-implemented here would be a second source of truth that
 * agrees on the day it is written and never again — the exact failure class
 * `panel-model.ts` exists to remove. So this module only PRESENTS: it selects,
 * orders, labels and words. The one thing it adds is validation, and validation
 * asserts the invariants rather than producing new numbers.
 *
 * ── What it deliberately does NOT contain ───────────────────────────────────
 *
 * No migration cost, no budget, no delivery date and no ROI. An exposure
 * assessment measures cryptography; programme economics are the Quantum
 * Readiness Engine's opinion of an estate, derived from a tenant-configured
 * cost model. Inventing them here would be the "never invent costs" rule
 * broken. The document says so and points to Report Center instead.
 *
 * ── Three units, always named ───────────────────────────────────────────────
 *
 * COMPONENT (what a migration replaces) · FINDING (what work is triaged in) ·
 * EXPOSURE (what risk is scored over). They legitimately differ, so every count
 * in this document carries its unit, exactly as the panels do.
 *
 * Pure and isomorphic — `tools/exposure-report-check.ts` drives it offline over
 * a real scan of a real corpus.
 */
import {
  SCAN_MODE_LABEL,
  TERMINAL_ENGINE_STATES,
  type CbomComponent,
  type CorrelatedExposure,
  type EngineRun,
  type ExposureAssessment,
  type ExposureFinding,
  type FindingSeverity,
  type QuantumStatus,
  type RiskBand,
  type ScanTarget,
} from '@/lib/scanner/exposure/types'
import {
  QUANTUM_STATUS_TEXT,
  completenessNote,
  coverageGapParts,
  coverageGapPhrase,
  describeSeverity,
  reconcileExposure,
  withUnit,
  type ExposureTruth,
} from '@/lib/scanner/exposure/exposure-truth'
import {
  algorithmChipCoverage,
  assessmentTargetLabel,
  coverageReadings,
  evidencePopulation,
  findingAssetName,
  policyExclusions,
  summariseAssets,
  summariseCorrelation,
  summariseStandards,
  type AssetRow,
  type CoverageReadingState,
} from '@/lib/scanner/exposure/panel-model'
import { classicalReplacementFor, componentPqcTarget, summariseCbom, type CbomSummary } from '@/lib/scanner/exposure/cbom'
import { prioritiseMigration } from '@/lib/scanner/exposure/risk'
import { layerLabel } from '@/lib/scanner/exposure/correlate'
import { describeAlgorithm } from '@/lib/scanner/exposure/algorithms'
import { rankRecommendations, type RankedRecommendation } from '@/lib/scanner/exposure/recommendations'
import type { InventoryKpi, InventoryReport, ReconciliationRow } from './InventoryReport'
import type { ReportBranding, ReportTable } from './schemas/ReportSchema'
import {
  TONE_HEX,
  toneForLabel,
  validationScore,
  type AssetDossier,
  type BlockTone,
  type DecisionEntry,
  type DocumentBlock,
  type DocumentFact,
  type DocumentKpi,
  type DocumentSection,
  type ReportDocument,
  type ValidationEntry,
} from './ReportDocument'
import { sealDocument, sha3Hex } from './ReportIntegrity'
import {
  EXPOSURE_REPORT_DEPTHS,
  EXPOSURE_REPORT_TEMPLATES,
  type ExposureReportDepth,
  type ExposureReportRecord,
  type ExposureReportTemplate,
} from './ExposureReportSpec'

/* ================================================================== */
/* Templates and depth                                                 */
/* ================================================================== */

/* The catalogue is plain data in a module of its own, so the always-mounted
   reporting card can render it without statically importing this builder — and
   with it zod, jose and @noble/hashes — into the main bundle. Re-exported here
   so a caller that already has the builder needs only one import. */
export {
  EXPOSURE_REPORT_DEPTHS,
  EXPOSURE_REPORT_TEMPLATES,
  type ExposureReportDepth,
  type ExposureReportDepthSpec,
  type ExposureReportTemplate,
  type ExposureReportTemplateSpec,
} from './ExposureReportSpec'

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export { exposureRecordFromProvenance, type ExposureReportRecord } from './ExposureReportSpec'

export interface BuildExposureReportInput {
  assessment: ExposureAssessment
  template: ExposureReportTemplate
  depth: ExposureReportDepth
  branding: ReportBranding
  generatedBy: string
  generatedAt?: string
  /** Set when the source is a stored record rather than the live run. */
  record?: ExposureReportRecord | null
}

/* ================================================================== */
/* Formatting                                                          */
/* ================================================================== */

const SEVERITIES: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_TEXT: Record<FindingSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
}
const SEVERITY_HEX: Record<FindingSeverity, string> = {
  critical: TONE_HEX.critical,
  high: TONE_HEX.high,
  medium: TONE_HEX.medium,
  low: '#0EA5E9',
  info: '#94A3B8',
}
const QUANTUM_ORDER: QuantumStatus[] = ['vulnerable', 'hybrid', 'pqc', 'resistant', 'unknown', 'not-applicable']
const QUANTUM_HEX: Record<QuantumStatus, string> = {
  vulnerable: '#DC2626',
  hybrid: '#7C3AED',
  pqc: '#16A34A',
  resistant: '#0891B2',
  unknown: '#94A3B8',
  'not-applicable': '#64748B',
}
const PRIORITY_HEX: Record<string, string> = { P1: TONE_HEX.critical, P2: TONE_HEX.high, P3: TONE_HEX.medium, P4: '#64748B' }

const nf = (value: number) => value.toLocaleString('en-US')
const plural = (count: number, noun: string, many = `${noun}s`) => `${nf(count)} ${count === 1 ? noun : many}`

const pct = (part: number, total: number) => (total > 0 ? Math.round((part / total) * 1000) / 10 : 0)
const pctText = (part: number, total: number) => (total > 0 ? `${pct(part, total)}%` : '—')

/** `2026-10-06 11:42 UTC`, or a stated absence. Never a locale-dependent date. */
export function utcStamp(value: string | null | undefined): string {
  if (!value) return 'Not recorded'
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'Not recorded'
}

const text = (value: unknown, fallback = '—'): string => {
  if (value === null || value === undefined) return fallback
  const out = String(value).trim()
  return out === '' ? fallback : out
}

/** Collapse an evidence snippet to one printable line. */
function oneLine(value: string | undefined | null, max = 180): string {
  if (!value) return '—'
  const flat = value.replace(/\s+/g, ' ').trim()
  if (!flat) return '—'
  return flat.length > max ? `${flat.slice(0, max - 1)}...` : flat
}

function bandTone(band: RiskBand | null): BlockTone {
  switch (band) {
    case 'critical':
      return 'critical'
    case 'high':
      return 'high'
    case 'moderate':
      return 'medium'
    case 'low':
      return 'low'
    case 'minimal':
      return 'good'
    default:
      return 'neutral'
  }
}

/** A risk reading, with its band — or a stated "not measured". */
function riskText(value: number | null, band: RiskBand | null): string {
  if (value === null) return 'Not measured'
  return `${value}/100${band ? ` — ${band}` : ''}`
}

/** ONE tone for a readiness figure, wherever a document prints it. Two KPI
 *  blocks used to colour the same 30% as critical and as medium. */
function readinessTone(value: number | null): BlockTone {
  if (value === null) return 'neutral'
  if (value >= 80) return 'good'
  if (value >= 40) return 'medium'
  return 'critical'
}

function shareTone(value: number | null): BlockTone {
  if (value === null) return 'neutral'
  if (value >= 80) return 'good'
  if (value >= 50) return 'info'
  return 'medium'
}

/* ================================================================== */
/* Target and status wording                                           */
/* ================================================================== */

export interface TargetDescription {
  /** Short name for the cover and the filename. */
  label: string
  /** What kind of thing was assessed. */
  kind: string
  /** Facts the reader needs to know what was in scope. */
  facts: DocumentFact[]
}

export function describeTarget(target: ScanTarget): TargetDescription {
  /* The label is the shared rule, so the cover, the filenames and the CBOM
     exports the panels produce all name the target identically. */
  const label = assessmentTargetLabel(target)
  switch (target.kind) {
    case 'local':
      return {
        label,
        kind: 'Local device, filesystem and codebase',
        facts: [
          { label: 'Authorised root', value: text(target.rootName) },
          { label: 'Files authorised', value: nf(target.fileCount) },
          { label: 'Collection', value: target.viaAgent ? `QGuard Local Agent${target.agentId ? ` (${target.agentId})` : ''}` : 'Browser file-system authorisation' },
        ],
      }
    case 'repository':
      return {
        label,
        kind: 'Source repository',
        facts: [
          { label: 'Repository', value: `${target.owner}/${target.repo}` },
          { label: 'Provider', value: text(target.provider) },
          { label: 'Branch', value: text(target.branch, 'default branch') },
          { label: 'Visibility', value: text(target.visibility) },
          { label: 'URL', value: text(target.url) },
        ],
      }
    case 'container':
      return {
        label,
        kind: 'Container image',
        facts: [
          { label: 'Image', value: text(target.image) },
          { label: 'Registry', value: text(target.registry) },
          { label: 'Digest', value: text(target.digest) },
        ],
      }
    case 'kubernetes':
      return {
        label,
        kind: 'Kubernetes cluster',
        facts: [
          { label: 'Cluster', value: text(target.cluster) },
          { label: 'Namespaces', value: target.namespaces.length ? target.namespaces.join(', ') : 'All readable namespaces' },
          { label: 'Acquisition', value: target.live ? 'Live cluster API (read-only)' : 'Manifests only' },
        ],
      }
    case 'cloud':
      return {
        label,
        kind: 'Cloud account',
        facts: [
          { label: 'Provider', value: target.provider.toUpperCase() },
          { label: 'Account', value: text(target.account) },
          { label: 'Regions', value: target.regions.length ? target.regions.join(', ') : 'Not recorded' },
        ],
      }
    default:
      return { label, kind: 'Assessment target', facts: [] }
  }
}

const STATUS_TEXT: Record<string, string> = {
  completed: 'Completed',
  partial: 'Completed with gaps',
  failed: 'Failed',
  cancelled: 'Cancelled',
  queued: 'Queued',
  initializing: 'Initialising',
  discovering: 'Discovering',
  analyzing: 'Analysing',
  correlating: 'Correlating',
  scoring: 'Scoring',
}

const ENGINE_STATE_TEXT: Record<string, string> = {
  pending: 'Pending',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  skipped: 'Skipped',
  'not-applicable': 'Not applicable',
  'not-assessed': 'Not assessed',
  cancelled: 'Cancelled',
}

/* ================================================================== */
/* Table limiting                                                      */
/* ================================================================== */

interface PresentedTable {
  table: ReportTable
  note?: string
}

/**
 * Limit a register for the narrative formats and SAY SO.
 *
 * A silently shortened table is the defect class this platform has already been
 * bitten by on 21 surfaces: the reader plans against a list that dropped more
 * work than it showed. The note names the omission and where the whole register
 * lives, and `report.tables` keeps every row for Excel, CSV and JSON.
 */
function limit(table: ReportTable, rows: number, orderedBy: string): PresentedTable {
  if (!Number.isFinite(rows) || table.rows.length <= rows) return { table }
  const kept = table.rows.slice(0, rows)
  const omitted = table.rows.length - kept.length
  return {
    table: { ...table, rows: kept },
    note: `Showing the ${nf(kept.length)} ${orderedBy} of ${nf(table.rows.length)} rows; ${nf(omitted)} further row${omitted === 1 ? '' : 's'} ${omitted === 1 ? 'is' : 'are'} omitted from this format. The Excel, CSV and JSON exports of this report carry the complete register.`,
  }
}

/** A table block, limited for presentation, with any note attached. */
function tableBlock(
  table: ReportTable,
  opts: { rows: number; orderedBy: string; widths?: number[]; emphasis?: DocumentBlock extends { emphasis?: infer E } ? E : never; wide?: boolean; note?: string },
): DocumentBlock {
  const presented = limit(table, opts.rows, opts.orderedBy)
  const notes = [presented.note, opts.note].filter(Boolean).join(' ')
  return {
    type: 'table',
    table: presented.table,
    widths: opts.widths,
    emphasis: opts.emphasis as never,
    wide: opts.wide,
    note: notes || undefined,
  }
}

/* ================================================================== */
/* Registers — the complete tables                                     */
/* ================================================================== */

/* The inventory's own naming rule, so a finding's Location in the register is
   the asset row it is counted under in the Scanned Inventory. */
const findingAsset = (finding: ExposureFinding): string => text(findingAssetName(finding))

const CITATION = /^(.+?)\s+—\s+([A-Z_]+),\s+applies to:\s+([\s\S]+)$/

function citedPublications(finding: ExposureFinding): string {
  const names = (finding.references ?? [])
    .map((reference) => reference.match(CITATION)?.[1])
    .filter((name): name is string => Boolean(name))
  return names.length ? Array.from(new Set(names)).join('; ') : 'None cited'
}

const SEVERITY_RANK: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function sortedFindings(assessment: ExposureAssessment): ExposureFinding[] {
  return [...assessment.findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      (a.quantumStatus === 'vulnerable' ? 0 : 1) - (b.quantumStatus === 'vulnerable' ? 0 : 1) ||
      a.title.localeCompare(b.title),
  )
}

/** The findings register. One row per finding, in triage order. */
function findingsTable(findings: ExposureFinding[]): ReportTable {
  return {
    title: 'Findings Register',
    columns: [
      'Finding ID',
      'Severity',
      'Confidence',
      'Detection',
      'Finding',
      'Layer',
      'Category',
      'Algorithm',
      'Key size',
      'Role',
      'Quantum Status',
      'Location',
      'Line',
      'Evidence',
      'Recommendation',
      'Standards',
      'Migration Priority',
      'First observed (UTC)',
    ],
    rows: findings.map((finding) => [
      finding.id,
      SEVERITY_TEXT[finding.severity],
      text(finding.confidence),
      text(finding.detection),
      finding.title,
      layerLabel(finding.layer),
      text(finding.category),
      text(finding.canonicalAlgorithm ?? finding.algorithm),
      finding.keySize ? nf(finding.keySize) : '—',
      text(finding.role),
      QUANTUM_STATUS_TEXT[finding.quantumStatus],
      findingAsset(finding),
      finding.evidence[0]?.line ? nf(finding.evidence[0].line as number) : '—',
      oneLine(finding.evidence[0]?.summary),
      oneLine(finding.recommendation, 240),
      citedPublications(finding),
      text(finding.migration?.priority, finding.migration?.candidate ? 'Unprioritised' : 'Not a migration candidate'),
      utcStamp(finding.firstSeen),
    ]),
  }
}

/** The cryptographic bill of materials. One row per observed component. */
function cbomTable(components: CbomComponent[]): ReportTable {
  const ordered = [...components].sort(
    (a, b) =>
      QUANTUM_ORDER.indexOf(a.quantumStatus) - QUANTUM_ORDER.indexOf(b.quantumStatus) ||
      a.canonicalAlgorithm.localeCompare(b.canonicalAlgorithm) ||
      text(a.file).localeCompare(text(b.file)),
  )
  return {
    title: 'Cryptographic Bill of Materials',
    columns: [
      'Component ID',
      'Algorithm',
      'Observed as',
      'Key size',
      'Cipher mode',
      'Protocol',
      'Usage',
      'Quantum Status',
      'Classical weakness',
      'Layer',
      'Library / package',
      'Version',
      'Language',
      'Location',
      'Line',
      'Function',
      'Detection',
      'Confidence',
      'Post-quantum target',
    ],
    rows: ordered.map((component) => {
      const entry = describeAlgorithm(component.canonicalAlgorithm)
      /* The engine's own recorded target (the one the findings and the
         migration priorities print), not a second derivation that worded the
         same target differently in the same document. */
      const target = componentPqcTarget(component)
      const classical = classicalReplacementFor(component)
      return [
        component.id,
        component.canonicalAlgorithm,
        text(component.algorithm),
        component.keySize ? nf(component.keySize) : '—',
        text(component.cipherMode),
        text(component.protocol),
        text(component.usage),
        QUANTUM_STATUS_TEXT[component.quantumStatus],
        entry?.classicallyWeak ? 'Broken classically' : 'No',
        layerLabel(component.layer),
        text(component.library ?? component.package),
        text(component.version),
        text(component.language),
        text(component.file),
        component.line ? nf(component.line) : '—',
        text(component.function),
        text(component.detection),
        text(component.confidence),
        text(
          target,
          component.quantumStatus === 'vulnerable'
            ? 'No role-specific target — review manually'
            : classical
              ? `Not required — replace with ${classical} for its classical weakness`
              : 'Not required',
        ),
      ]
    }),
  }
}

/**
 * Every evidence record behind every correlated exposure.
 *
 * The worklist dossiers print the first twelve records of each exposure and
 * point here for the rest. That pointer used to name the Excel, CSV and JSON
 * exports while no register in them carried per-exposure evidence at all — the
 * promise pointed at nothing.
 */
function exposureEvidenceTable(exposures: CorrelatedExposure[]): ReportTable {
  return {
    title: 'Exposure Evidence',
    columns: ['Exposure', 'Severity', 'Location', 'Line', 'Provider', 'Rule', 'Observation', 'Redacted excerpt', 'Observed (UTC)'],
    rows: exposures.flatMap((exposure) =>
      exposure.evidence.map((record) => [
        exposure.title,
        SEVERITY_TEXT[exposure.severity],
        text(record.file ?? record.reference ?? record.scope),
        record.line ? nf(record.line) : '—',
        text(record.provider),
        text(record.ruleId),
        oneLine(record.summary, 240),
        oneLine(record.snippet, 160),
        utcStamp(record.observedAt),
      ]),
    ),
  }
}

/** Correlated exposures. One row per exposure, with the layers it spans. */
function exposuresTable(exposures: CorrelatedExposure[], title = 'Correlated Exposures'): ReportTable {
  const ordered = [...exposures].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.findingIds.length - a.findingIds.length,
  )
  return {
    title,
    columns: [
      'Exposure',
      'Severity',
      'Confidence',
      'Quantum Status',
      'Algorithm',
      'Role',
      'Findings merged',
      'Layers',
      'Cryptographic path',
      'Recommendation',
      'Migration Priority',
    ],
    rows: ordered.map((exposure) => [
      exposure.title,
      SEVERITY_TEXT[exposure.severity],
      text(exposure.confidence),
      QUANTUM_STATUS_TEXT[exposure.quantumStatus],
      text(exposure.canonicalAlgorithm),
      text(exposure.role),
      nf(exposure.findingIds.length),
      exposure.layers.map(layerLabel).join(' · ') || '—',
      exposure.path?.length ? exposure.path.map((step) => step.label).join(' -> ') : '—',
      oneLine(exposure.recommendation, 240),
      text(exposure.migration?.priority, exposure.migration?.candidate ? 'Unprioritised' : 'Not a migration candidate'),
    ]),
  }
}

/** Migration priorities, scored by `prioritiseMigration` with its drivers. */
function prioritiesTable(prioritised: ReturnType<typeof prioritiseMigration>): ReportTable {
  return {
    title: 'Migration Priorities',
    columns: [
      'Priority',
      'Score',
      'Exposure',
      'Severity',
      'Algorithm',
      'Role',
      'Layers',
      'Post-quantum target',
      'Why this priority',
      'Recommended action',
    ],
    rows: prioritised.map((entry) => [
      entry.priority,
      nf(entry.score),
      entry.exposure.title,
      SEVERITY_TEXT[entry.exposure.severity],
      text(entry.exposure.canonicalAlgorithm),
      text(entry.exposure.role),
      entry.exposure.layers.map(layerLabel).join(' · ') || '—',
      text(entry.exposure.migration?.target, 'Not recorded by the engine'),
      entry.drivers.length ? entry.drivers.join('; ') : 'Base severity only',
      oneLine(entry.exposure.recommendation, 240),
    ]),
  }
}

/** Scanned inventory. One row per asset, plus every gap as a row of its own. */
function inventoryTable(rows: AssetRow[]): ReportTable {
  return {
    title: 'Scanned Inventory',
    columns: [
      'Asset',
      'Observed through',
      'State',
      'Components',
      'Findings',
      'Critical findings',
      'Quantum-vulnerable findings',
      'Post-quantum findings',
      'Hybrid findings',
      'Detail',
    ],
    rows: rows.map((row) => [
      row.name,
      row.kind,
      row.state === 'scanned' ? 'Scanned' : row.state === 'partial' ? 'Incomplete' : 'Not assessed',
      nf(row.components),
      nf(row.findings),
      nf(row.critical),
      nf(row.quantumVulnerable),
      nf(row.pqc),
      nf(row.hybrid),
      text(row.detail),
    ]),
  }
}

/** The engine ledger — every selected engine, terminal state and all. */
function ledgerTable(runs: EngineRun[]): ReportTable {
  return {
    title: 'Engine Execution Ledger',
    columns: ['Engine', 'Engine ID', 'State', 'Progress', 'Findings', 'Units of work', 'Started (UTC)', 'Completed (UTC)', 'Detail'],
    rows: runs.map((run) => [
      run.label,
      run.engineId,
      ENGINE_STATE_TEXT[run.state] ?? run.state,
      `${run.progress}%`,
      nf(run.findingCount),
      run.units ? `${nf(run.units.done)} of ${nf(run.units.total)} ${run.units.unit}` : '—',
      utcStamp(run.startedAt),
      utcStamp(run.completedAt),
      text(run.detail),
    ]),
  }
}

function standardsTable(rows: ReturnType<typeof summariseStandards>['rows']): ReportTable {
  return {
    title: 'Standards Cited',
    columns: ['Publication', 'Requirement type', 'Applies to', 'Findings citing it'],
    rows: rows.map((row) => [row.publication, row.requirementType, row.applicability, nf(row.findings)]),
  }
}

function algorithmsTable(summary: CbomSummary): ReportTable {
  return {
    title: 'Algorithms Observed',
    columns: ['Algorithm', 'Components', 'Share', 'Dominant quantum status', 'Status mix', 'Broken classically', 'Standard'],
    rows: summary.byAlgorithm.map((entry) => [
      entry.algorithm,
      nf(entry.count),
      pctText(entry.count, summary.total),
      QUANTUM_STATUS_TEXT[entry.quantumStatus],
      entry.mix.map((slice) => `${nf(slice.count)} ${QUANTUM_STATUS_TEXT[slice.status].toLowerCase()}`).join(', '),
      entry.classicallyWeak ? nf(entry.classicallyWeak) : '0',
      text(describeAlgorithm(entry.algorithm)?.standard),
    ]),
  }
}

function usageTable(summary: CbomSummary): ReportTable {
  return {
    title: 'Cryptographic Usage',
    columns: ['Usage / role', 'Components', 'Share'],
    rows: summary.byUsage.map((entry) => [text(entry.usage), nf(entry.count), pctText(entry.count, summary.total)]),
  }
}

const READING_TEXT: Record<CoverageReadingState, string> = {
  measured: 'Measured',
  'measured-zero': 'Read — none found',
  'not-reported': 'Not measured — engine did not complete',
  'not-selected': 'Outside this profile — no claim made',
}

/**
 * Every coverage dimension with what its number MEANS in this run.
 *
 * Classified by `coverageReadings` — the function the Assessment Coverage
 * panel renders — so a zero the panel calls "outside this profile" can never
 * print as a measured zero here. The ledger used to drop every zero instead,
 * which hid "read, none found" (a real result) along with the unmeasured.
 */
function coverageTable(assessment: ExposureAssessment): ReportTable {
  const { coverage } = assessment.task
  const readings = coverageReadings(coverage, assessment.task.runs)
  return {
    title: 'Coverage Ledger',
    columns: ['Dimension', 'Count', 'Reading'],
    rows: [
      ...readings.map((reading) => [
        reading.label,
        reading.state === 'measured' || reading.state === 'measured-zero' ? nf(reading.value) : '—',
        READING_TEXT[reading.state],
      ]),
      ['Bytes analysed', nf(coverage.bytesAnalyzed), coverage.bytesAnalyzed > 0 ? READING_TEXT.measured : READING_TEXT['measured-zero']],
    ],
  }
}

function gapsTable(assessment: ExposureAssessment, truth: ExposureTruth): ReportTable {
  const rows: Array<Array<string | number>> = []
  for (const gap of truth.notAssessed) rows.push(['Dimension not read', gap.dimension, gap.reason])
  for (const engine of truth.incompleteEngines) {
    rows.push([engine.state === 'cancelled' ? 'Engine cancelled' : 'Engine failed', engine.label, engine.detail])
  }
  for (const exclusion of policyExclusions(assessment.task.coverage)) rows.push(['Excluded by policy', exclusion, 'Excluded from collection by the assessment exclusion rules.'])
  /* Binary files are COLLECTED, not excluded — so they are their own kind of
     gap. They used to arrive as an "Excluded by policy" row, which misstated
     both what happened to them and how many there were. */
  if (assessment.task.coverage.filesUnsupported > 0) {
    rows.push([
      'Not content-analysed',
      `${plural(assessment.task.coverage.filesUnsupported, 'binary or unsupported file')}`,
      'Discovered and classified, but their contents were not read by any engine, so nothing they contain is reflected in this report.',
    ])
  }
  if (assessment.task.coverage.truncated) {
    rows.push(['Work truncated', 'Assessment budget', text(assessment.task.coverage.truncationNote, 'A bounded budget stopped the work before every candidate was read.')])
  }
  return { title: 'Coverage Gaps', columns: ['Kind', 'Subject', 'Why this is not clean evidence'], rows }
}

/**
 * Every recommended action — the COMPLETE ranked list.
 *
 * The panel shows the first ten of `rankRecommendations`; this register reads
 * the same function and keeps every row, so its first ten are the panel's ten
 * and the Excel/CSV/JSON promise ("every row") is true here as well. It used to
 * table the panel's capped list, so a scan with 27 actions exported 10.
 */
function recommendationsTable(actions: RankedRecommendation[]): ReportTable {
  return {
    title: 'Engine Recommendations',
    columns: ['Recommended action', 'Severity', 'Effort', 'Findings addressed', 'Detail'],
    rows: actions.map((entry) => [
      entry.title,
      SEVERITY_TEXT[entry.severity],
      entry.effort,
      nf(entry.findingIds.length),
      oneLine(entry.detail, 320),
    ]),
  }
}

function secretsTable(assessment: ExposureAssessment): ReportTable {
  return {
    title: 'Secret Material',
    columns: ['Type', 'Location', 'Severity', 'Confidence', 'Value', 'Historical'],
    rows: assessment.intelligence.secrets.map((secret) => [
      secret.type,
      secret.location,
      SEVERITY_TEXT[secret.severity],
      secret.confidence,
      secret.value,
      secret.historical ? 'In Git history' : 'In the working tree',
    ]),
  }
}

function dependenciesTable(assessment: ExposureAssessment): ReportTable {
  const ordered = [...assessment.intelligence.dependencies].sort(
    (a, b) =>
      Number(b.quantumRelevant) - Number(a.quantumRelevant) ||
      Number(b.cryptoRelevant) - Number(a.cryptoRelevant) ||
      Number(b.direct) - Number(a.direct) ||
      a.name.localeCompare(b.name),
  )
  return {
    title: 'Dependency Surface',
    columns: ['Dependency', 'Version', 'Ecosystem', 'Scope', 'Cryptographic', 'Quantum-relevant'],
    rows: ordered.map((dependency) => [
      dependency.name,
      text(dependency.version),
      text(dependency.ecosystem),
      dependency.direct ? 'Direct' : 'Transitive',
      dependency.cryptoRelevant ? 'Yes' : 'No',
      dependency.quantumRelevant ? 'Yes' : 'No',
    ]),
  }
}

function detectionStats(assessment: ExposureAssessment) {
  const layers = new Map<string, number>()
  let confirmed = 0
  let potential = 0
  let withCaveats = 0
  for (const finding of assessment.findings) {
    for (const evidence of finding.evidence) {
      const layer = evidence.attributes?.detectionLayer
      if (typeof layer === 'string') layers.set(layer, (layers.get(layer) ?? 0) + 1)
      if (evidence.attributes?.caveats) withCaveats += 1
    }
    const truth = finding.evidence[0]?.attributes?.groundTruth
    if (truth === 'CONFIRMED') confirmed += 1
    else if (truth === 'POTENTIAL') potential += 1
  }
  const ordered = [...layers.entries()].sort((a, b) => b[1] - a[1])
  return {
    layers: ordered,
    observations: ordered.reduce((sum, [, value]) => sum + value, 0),
    confirmed,
    potential,
    withCaveats,
    /* §90's UNKNOWN. Without it the tiles silently fail to add up to the
       finding count and a reader is left to guess which number is wrong. */
    notEstablished: assessment.findings.length - confirmed - potential,
  }
}

function methodSplit(assessment: ExposureAssessment) {
  const detection = new Map<string, number>()
  const confidence = new Map<string, number>()
  for (const finding of assessment.findings) {
    detection.set(finding.detection, (detection.get(finding.detection) ?? 0) + 1)
    confidence.set(finding.confidence, (confidence.get(finding.confidence) ?? 0) + 1)
  }
  return { detection, confidence }
}

/* ================================================================== */
/* Executive summary                                                   */
/* ================================================================== */

function highlights(assessment: ExposureAssessment, truth: ExposureTruth, cbom: CbomSummary): DocumentKpi[] {
  const { scores } = assessment.task
  return [
    {
      label: 'Security risk',
      value: riskText(scores.securityRisk, scores.securityBand),
      detail: `Weighted over ${withUnit(assessment.exposures.length, 'exposure')}`,
      tone: bandTone(scores.securityBand),
    },
    {
      label: 'Quantum risk',
      value: riskText(scores.quantumRisk, scores.quantumBand),
      detail: `${withUnit(truth.components.vulnerable, 'component')} of ${nf(truth.components.quantumRelevant)} quantum-relevant classified vulnerable`,
      tone: bandTone(scores.quantumBand),
    },
    {
      label: 'Post-quantum readiness',
      value: truth.readiness === null ? 'Not measured' : `${truth.readiness}%`,
      detail:
        truth.readiness === null
          ? 'No quantum-relevant cryptography in scope'
          : `of ${plural(truth.components.quantumRelevant, 'quantum-relevant component')}`,
      tone: readinessTone(truth.readiness),
    },
    {
      label: 'Quantum-vulnerable components',
      value: nf(truth.components.vulnerable),
      detail: `of ${nf(truth.components.total)} observed — ${pctText(truth.components.vulnerable, truth.components.total)}`,
      tone: truth.components.vulnerable > 0 ? 'critical' : 'good',
    },
    {
      label: 'Critical findings',
      value: nf(truth.severity.critical),
      detail: `of ${withUnit(assessment.findings.length, 'finding')} · ${nf(truth.actionable)} above informational`,
      tone: truth.severity.critical > 0 ? 'critical' : truth.severity.high > 0 ? 'high' : 'good',
    },
    {
      label: 'Correlated exposures',
      value: nf(assessment.exposures.length),
      detail: describeSeverity(truth.exposureSeverity),
      tone: truth.exposureSeverity.critical > 0 ? 'critical' : 'info',
    },
    {
      label: 'Assessment coverage',
      value: scores.coverage === null ? 'Not measured' : `${scores.coverage}%`,
      /* Names the hole that actually exists. Built only from unread dimensions
         and incomplete engines, a budget-truncated run read "0 dimensions
         unread, 0 engines incomplete" — or worse, "Every selected engine
         reported in full" beside a 91% ring. */
      detail: truth.partial ? coverageGapPhrase(truth) : 'Every selected engine reported in full',
      tone: truth.partial ? 'warning' : shareTone(scores.coverage),
    },
    {
      label: 'Detection confidence',
      value: scores.confidence === null ? 'Not measured' : `${scores.confidence}%`,
      detail: 'Severity-weighted across the findings behind these scores',
      tone: shareTone(scores.confidence),
    },
  ]
}

function headlineSentence(assessment: ExposureAssessment, truth: ExposureTruth, target: TargetDescription): string {
  if (assessment.cbom.length === 0 && assessment.findings.length === 0) {
    return `No cryptographic component and no finding were observed in ${target.label}. That is a statement about what this assessment could read, not a clean bill of health.`
  }
  if (truth.readiness === null) {
    return `${plural(truth.components.total, 'cryptographic component')} and ${plural(assessment.findings.length, 'finding')} were observed in ${target.label}; post-quantum readiness is not measurable because none of the cryptography in scope is quantum-relevant.`
  }
  return `${plural(truth.components.vulnerable, 'of ' + nf(truth.components.total) + ' cryptographic component', 'of ' + nf(truth.components.total) + ' cryptographic components')} observed in ${target.label} ${truth.components.vulnerable === 1 ? 'is' : 'are'} quantum-vulnerable; post-quantum readiness across the quantum-relevant estate is ${truth.readiness}%.`
}

function summaryParagraphs(
  assessment: ExposureAssessment,
  truth: ExposureTruth,
  cbom: CbomSummary,
  correlation: ReturnType<typeof summariseCorrelation>,
  prioritised: ReturnType<typeof prioritiseMigration>,
  target: TargetDescription,
  record: ExposureReportRecord | null | undefined,
): string[] {
  const { scores, status } = assessment.task
  const paragraphs: string[] = []

  paragraphs.push(
    `This assessment read ${target.kind.toLowerCase()} — ${target.label} — in ${SCAN_MODE_LABEL[assessment.task.mode]} mode on ${utcStamp(assessment.task.startedAt ?? assessment.generatedAt)} and ${
      status === 'partial' ? 'completed with gaps' : status === 'cancelled' ? 'was cancelled before every engine finished' : 'completed'
    }. ${plural(assessment.task.runs.length, 'engine')} ${assessment.task.runs.length === 1 ? 'was' : 'were'} selected and ${plural(assessment.task.runs.filter((run) => run.state === 'completed').length, 'engine')} reported in full. ${
      assessment.task.localOnly
        ? 'Collection was local-only: no file content, secret value or repository object left the device, and only this sanitised assessment can be synchronised.'
        : 'Acquisition was read-only against the authorised target.'
    }`,
  )

  paragraphs.push(
    `Security and migration risk are scored over CORRELATED EXPOSURES, not raw findings: ${plural(assessment.findings.length, 'finding')} correlated into ${plural(assessment.exposures.length, 'exposure')} (${describeSeverity(truth.exposureSeverity)}). Security risk is ${riskText(scores.securityRisk, scores.securityBand)}, quantum risk ${riskText(scores.quantumRisk, scores.quantumBand)} and migration risk ${riskText(scores.migrationRisk, scores.migrationBand)}; quantum risk is a share of the ${plural(truth.components.quantumRelevant, 'quantum-relevant component')}, the population readiness is computed over. Each reading is published with the basis it was computed from, and none is collapsed into a single grade — they answer different questions.`,
  )

  /* The VULNERABLE members of each group, largest first — the rule the quantum
     roll-up finding already uses. Filtering on the group's dominant status and
     printing the group total named a mixed group (20 vulnerable, 10 hybrid) as
     "ECDSA (30)", and dropped a group whose dominant status was hybrid even
     when it held vulnerable components. */
  const vulnerableAlgorithms = cbom.byAlgorithm
    .map((entry) => ({ algorithm: entry.algorithm, vulnerable: entry.mix.find((slice) => slice.status === 'vulnerable')?.count ?? 0 }))
    .filter((entry) => entry.vulnerable > 0)
    .sort((a, b) => b.vulnerable - a.vulnerable)
    .slice(0, 4)
  paragraphs.push(
    truth.components.vulnerable > 0
      ? `The quantum exposure is concentrated in ${vulnerableAlgorithms.length ? `${vulnerableAlgorithms.map((entry) => `${entry.algorithm} (${nf(entry.vulnerable)})`).join(', ')} — vulnerable components per algorithm` : 'cryptography the engines could not attribute to a named primitive'}. ${
          cbom.classicallyWeak > 0
            ? `Separately, ${plural(cbom.classicallyWeak, 'component')} ${cbom.classicallyWeak === 1 ? 'is' : 'are'} broken by CLASSICAL cryptanalysis — MD5, SHA-1, RC4, DES and similar. These sit in the quantum-resistant bucket, which is a verdict about Shor's algorithm alone, and they require replacement regardless of any quantum timeline.`
            : 'No component in scope is broken by classical cryptanalysis.'
        }`
      : `No component in scope is classified quantum-vulnerable. ${
          truth.components.unknown > 0
            ? `${plural(truth.components.unknown, 'component')} could not be classified, and an unclassified component is not evidence of safety.`
            : 'Every observed component carries a quantum verdict.'
        }`,
  )

  const p1 = prioritised.filter((entry) => entry.priority === 'P1').length
  const p2 = prioritised.filter((entry) => entry.priority === 'P2').length
  paragraphs.push(
    prioritised.length
      ? `${plural(prioritised.length, 'exposure')} ${prioritised.length === 1 ? 'is' : 'are'} a migration candidate, of which ${nf(p1)} ${p1 === 1 ? 'is' : 'are'} P1 and ${nf(p2)} P2. Priority is driven by severity, Internet reachability, the lifetime of the cryptographic assertion, harvest-now-decrypt-later reach and detection confidence — never by the algorithm name alone — and every driver is printed beside its exposure.`
      : 'No exposure in scope is a migration candidate: nothing observed is both quantum-relevant and replaceable at this layer.',
  )

  if (correlation.total > 0) {
    paragraphs.push(
      `Correlation merged ${plural(correlation.merged.length, 'exposure')} from several findings or several layers, of which ${nf(correlation.crossLayer)} genuinely reach across layers; the remaining ${plural(correlation.singletons, 'exposure')} ${correlation.singletons === 1 ? 'is a single' : 'are single'} finding at a single layer. Cross-layer exposures are the ones whose blast radius spans the pipeline, so they are listed first.`,
    )
  }

  const note = completenessNote(truth)
  if (note) paragraphs.push(note)
  if (assessment.task.coverage.truncated) {
    paragraphs.push(
      `A bounded assessment budget truncated the work. ${text(assessment.task.coverage.truncationNote, 'Not every candidate artefact was read.')} Every total in this report is therefore a floor, not a ceiling.`,
    )
  }

  if (record) {
    paragraphs.push(
      `This document was built from a RECORDED assessment (record version ${record.recordVersion}, stored ${utcStamp(record.recordedAt)}). ${
        record.notRetained.length
          ? `${plural(record.notRetained.length, 'field')} ${record.notRetained.length === 1 ? 'was' : 'were'} not retained by the record and ${record.notRetained.length === 1 ? 'is' : 'are'} reported as not retained rather than as empty: ${record.notRetained.join('; ')}.`
          : 'Every field the live view renders was retained.'
      }${record.truncated.length ? ` ${plural(record.truncated.length, 'list')} ${record.truncated.length === 1 ? 'was' : 'were'} capped at storage time: ${record.truncated.join('; ')}.` : ''}`,
    )
  }

  paragraphs.push(
    'This report states no migration cost, budget or delivery date. An exposure assessment measures cryptography; programme economics depend on a tenant-configured cost model and are produced by the Quantum Readiness Engine. Commission a costed plan from Report Center rather than reading a budget into these figures.',
  )

  return paragraphs
}

/* ================================================================== */
/* Decision register                                                   */
/* ================================================================== */

function decisionRegister(
  assessment: ExposureAssessment,
  truth: ExposureTruth,
  cbom: CbomSummary,
  prioritised: ReturnType<typeof prioritiseMigration>,
): DecisionEntry[] {
  const decisions: DecisionEntry[] = []
  const p1 = prioritised.filter((entry) => entry.priority === 'P1')
  const p2 = prioritised.filter((entry) => entry.priority === 'P2')

  if (p1.length) {
    decisions.push({
      priority: 'P1',
      decision: `Authorise immediate remediation of the ${nf(p1.length)} P1 exposure${p1.length === 1 ? '' : 's'}`,
      rationale: 'P1 combines high severity with Internet reachability, a long-lived cryptographic assertion or harvest-now-decrypt-later reach — the exposures where delay compounds.',
      evidence: `Migration Priorities: ${p1.slice(0, 3).map((entry) => entry.exposure.title).join('; ')}${p1.length > 3 ? `; +${nf(p1.length - 3)} more` : ''}`,
      owner: 'Platform / service owner — not recorded by the scanner',
    })
  }
  if (truth.severity.critical > 0) {
    decisions.push({
      priority: 'P1',
      decision: `Triage the ${nf(truth.severity.critical)} critical finding${truth.severity.critical === 1 ? '' : 's'} and record an accept-or-remediate decision for each`,
      rationale: 'A critical finding is a present-tense consequence if the observation is real. Detection confidence is published separately so a low-confidence critical can be verified before work is scheduled.',
      evidence: `Findings Register — ${describeSeverity(truth.severity)}`,
      owner: 'Security engineering',
    })
  }
  if (cbom.classicallyWeak > 0) {
    decisions.push({
      priority: 'P1',
      decision: `Approve replacement of the ${nf(cbom.classicallyWeak)} classically-broken component${cbom.classicallyWeak === 1 ? '' : 's'}`,
      rationale: 'MD5, SHA-1, RC4 and DES are broken today, independently of any quantum timeline. They are reported quantum-resistant because that verdict concerns Shor\'s algorithm alone.',
      evidence: 'Algorithms Observed — "Broken classically" column',
      owner: 'Security engineering',
    })
  }
  if (assessment.intelligence.secrets.length) {
    decisions.push({
      priority: 'P1',
      decision: `Rotate and revoke the ${nf(assessment.intelligence.secrets.length)} secret${assessment.intelligence.secrets.length === 1 ? '' : 's'} observed`,
      rationale: 'Secret material in a repository or working tree must be treated as disclosed. Values are redacted in this document; the locations are not.',
      evidence: `Secret Material — ${nf(assessment.intelligence.secrets.filter((secret) => secret.historical).length)} in Git history`,
      owner: 'Service owner + identity team',
    })
  }
  if (truth.notAssessed.length) {
    decisions.push({
      priority: 'P2',
      decision: `Authorise the access needed to assess the ${nf(truth.notAssessed.length)} unread dimension${truth.notAssessed.length === 1 ? '' : 's'}, or formally accept the blind spot`,
      rationale: 'An unread dimension is not a clean one. Until it is read, every total in this report is a floor and the coverage score says so.',
      evidence: `Coverage Gaps — ${truth.notAssessed.map((gap) => gap.dimension).join(', ')}`,
      owner: 'Platform team',
    })
  }
  if (truth.incompleteEngines.length) {
    decisions.push({
      priority: 'P2',
      decision: `Re-run the ${nf(truth.incompleteEngines.length)} engine${truth.incompleteEngines.length === 1 ? '' : 's'} that did not complete`,
      rationale: 'The scores were computed only from the engines that reported, so a re-run can only move them — and the direction is unknown until it does.',
      evidence: `Engine Execution Ledger — ${truth.incompleteEngines.map((engine) => engine.label).join(', ')}`,
      owner: 'Platform team',
    })
  }
  if (p2.length) {
    decisions.push({
      priority: 'P2',
      decision: `Schedule the ${nf(p2.length)} P2 exposure${p2.length === 1 ? '' : 's'} into the next migration wave`,
      rationale: 'P2 exposures are real migration candidates without the reachability or lifetime pressure that makes a P1 urgent.',
      evidence: 'Migration Priorities — P2 rows',
      owner: 'Migration programme',
    })
  }
  if (truth.components.unknown > 0) {
    decisions.push({
      priority: 'P2',
      decision: `Assign review of the ${nf(truth.components.unknown)} component${truth.components.unknown === 1 ? '' : 's'} whose quantum status could not be established`,
      rationale: 'An unclassified component is excluded from readiness on both sides of the ratio. It is neither evidence of exposure nor of safety, and only review resolves it.',
      evidence: 'Cryptographic Bill of Materials — Quantum Status "Unknown"',
      owner: 'Security architecture',
    })
  }
  decisions.push({
    priority: 'P3',
    decision: 'Commission a costed migration plan from the Quantum Readiness Report Center',
    rationale: 'This report deliberately asserts no cost, budget or date. A costed plan needs the tenant cost model, asset criticality and ownership that an exposure assessment does not observe.',
    evidence: 'Methodology & Definitions — "What this report does not contain"',
    owner: 'CISO / migration programme',
  })
  decisions.push({
    priority: 'P3',
    decision: `Set a re-assessment cadence for ${assessment.task.target.kind === 'local' ? 'this device or codebase' : 'this target'}`,
    rationale: 'Posture is a point-in-time reading. Drift between assessments is only visible if the next one happens, and findings carry stable ids precisely so two runs can be compared.',
    evidence: `Assessment generated ${utcStamp(assessment.generatedAt)}`,
    owner: 'Platform team',
  })

  return decisions
}

/* ================================================================== */
/* Validation                                                          */
/* ================================================================== */

interface ValidationContext {
  assessment: ExposureAssessment
  truth: ExposureTruth
  cbom: CbomSummary
  assets: ReturnType<typeof summariseAssets>
  correlation: ReturnType<typeof summariseCorrelation>
  evidence: ReturnType<typeof evidencePopulation>
  standards: ReturnType<typeof summariseStandards>
  chips: ReturnType<typeof algorithmChipCoverage>
  detection: ReturnType<typeof detectionStats>
  limitedTables: string[]
  classicalQualified: boolean
  record: ExposureReportRecord | null | undefined
}

function validate(context: ValidationContext): ValidationEntry[] {
  const { assessment, truth, cbom, assets, correlation, evidence, standards, chips, detection, record } = context
  const checks: ValidationEntry[] = []
  const add = (check: string, ok: boolean, detail: string, soft = false) =>
    checks.push({ check, status: ok ? 'pass' : soft ? 'warn' : 'fail', detail })

  /* ── the scan itself ───────────────────────────────────────────────── */
  const terminal = ['completed', 'partial', 'failed', 'cancelled'].includes(assessment.task.status)
  add(
    'Assessment reached a terminal state',
    terminal,
    terminal ? `Status: ${STATUS_TEXT[assessment.task.status] ?? assessment.task.status}.` : `Status is "${assessment.task.status}" — this scan is still running, so every figure is mid-flight.`,
  )
  const nonTerminal = assessment.task.runs.filter((run) => !TERMINAL_ENGINE_STATES.includes(run.state))
  add(
    'Every selected engine reached a terminal state',
    nonTerminal.length === 0,
    nonTerminal.length ? `${plural(nonTerminal.length, 'engine')} left non-terminal: ${nonTerminal.map((run) => `${run.label} (${run.state})`).join(', ')}.` : `All ${nf(assessment.task.runs.length)} selected engines are accounted for in the ledger.`,
  )

  /* ── the arithmetic every panel depends on ─────────────────────────── */
  const severitySum = SEVERITIES.reduce((sum, severity) => sum + truth.severity[severity], 0)
  add(
    'Finding severities sum to the finding count',
    severitySum === assessment.findings.length,
    `${nf(severitySum)} graded of ${nf(assessment.findings.length)} findings (${describeSeverity(truth.severity)}).`,
  )
  const exposureSeveritySum = SEVERITIES.reduce((sum, severity) => sum + truth.exposureSeverity[severity], 0)
  add(
    'Exposure severities sum to the exposure count',
    exposureSeveritySum === assessment.exposures.length,
    `${nf(exposureSeveritySum)} graded of ${nf(assessment.exposures.length)} exposures — the population security and migration risk are weighted over.`,
  )
  const componentSum =
    truth.components.vulnerable +
    truth.components.hybrid +
    truth.components.pqc +
    truth.components.resistant +
    truth.components.unknown +
    truth.components.notApplicable
  add(
    'Quantum verdicts partition the bill of materials',
    componentSum === truth.components.total && truth.components.total === assessment.cbom.length,
    `${nf(componentSum)} verdicts over ${nf(truth.components.total)} tallied components and ${nf(assessment.cbom.length)} CBOM rows.`,
  )
  const rowFindings = assets.rows.reduce((sum, row) => sum + row.findings, 0)
  const rowComponents = assets.rows.reduce((sum, row) => sum + row.components, 0)
  add(
    'Scanned inventory accounts for every finding and component',
    rowFindings === assessment.findings.length && rowComponents === assessment.cbom.length,
    `${nf(rowFindings)} findings and ${nf(rowComponents)} components distributed over ${nf(assets.rows.length)} inventory rows.`,
  )
  add(
    'Correlation split is exact',
    correlation.merged.length + correlation.singletons === correlation.total && correlation.crossLayer <= correlation.merged.length,
    `${nf(correlation.merged.length)} merged (${nf(correlation.crossLayer)} genuinely cross-layer) + ${nf(correlation.singletons)} single-finding = ${nf(correlation.total)} exposures.`,
  )
  add(
    'Evidence population is partitioned',
    evidence.corroborated + evidence.unbacked === evidence.total && evidence.total === assessment.findings.length,
    `${nf(evidence.corroborated)} corroborated + ${nf(evidence.unbacked)} carrying no detection layer = ${nf(evidence.total)} findings.`,
  )
  add(
    'Standards citation population is declared',
    standards.cited + standards.uncited === standards.total,
    standards.total
      ? `${nf(standards.cited)} of ${nf(standards.total)} findings cite a parseable publication; ${nf(standards.uncited)} cite none and are declared rather than omitted silently.`
      : 'No finding was raised, so there is nothing to cite.',
  )
  add(
    'Determination states sum to the finding count',
    detection.confirmed + detection.potential + detection.notEstablished === assessment.findings.length,
    `${nf(detection.confirmed)} confirmed + ${nf(detection.potential)} potential + ${nf(detection.notEstablished)} with no recorded determination = ${nf(assessment.findings.length)} findings.`,
  )

  /* ── honesty rules ────────────────────────────────────────────────── */
  add(
    'Readiness is published only when it is measurable',
    (truth.readiness === null) === (truth.components.quantumRelevant === 0),
    truth.readiness === null
      ? truth.readinessReason
      : `${truth.readiness}% over ${plural(truth.components.quantumRelevant, 'quantum-relevant component')}; hybrid deployments count at 0.6 because a classical half remains.`,
  )
  /* Truncation counts as partial here too: work a budget cut short is work that
     was not done, and a reader handed "100%" has no way to know it. */
  const coverageComplete = assessment.task.scores.coverage === 100
  const coverageHonest = !(truth.partial && coverageComplete)
  /* Enumerated so the figure is never left unexplained. A run whose only hole
     was a budget stop reported "91% with 0 unread dimension(s) and 0 incomplete
     engine(s)" — the nine points had no stated cause. */
  const coverageGaps = coverageGapParts(truth)
  add(
    'Coverage is not reported as complete over a partial scan',
    coverageHonest,
    coverageHonest
      ? `Coverage ${assessment.task.scores.coverage === null ? 'not measured' : `${assessment.task.scores.coverage}%`}${coverageGaps.length ? ` — discounted for ${coverageGaps.join(', ')}` : ' over a scope read in full'}.`
      : 'Coverage reads 100% while part of the scope went unread — absent evidence would be rendered as clean evidence.',
  )
  add(
    'Algorithm groups are fully accounted for',
    chips.shown === chips.groups || chips.truncated,
    `This document tables all ${nf(cbom.byAlgorithm.length)} algorithm group(s) over ${nf(cbom.total)} components; the dashboard chip row shows the ${nf(chips.shown)} largest.`,
  )
  add(
    'The quantum-resistant bucket is qualified where it must be',
    cbom.classicallyWeak === 0 || context.classicalQualified,
    cbom.classicallyWeak === 0
      ? 'No resistant component is broken by classical cryptanalysis, so no qualifier is required.'
      : `${plural(cbom.classicallyWeak, 'resistant component')} ${cbom.classicallyWeak === 1 ? 'is' : 'are'} broken classically and the document states it beside the bucket.`,
  )
  const unredacted = assessment.intelligence.secrets.filter((secret) => secret.value !== '[REDACTED]')
  add(
    'No secret value appears in this document',
    unredacted.length === 0,
    unredacted.length ? `${plural(unredacted.length, 'secret')} carries a value other than the redaction marker.` : `${plural(assessment.intelligence.secrets.length, 'secret location')} reported, every value redacted.`,
  )
  const withoutEvidence = assessment.findings.filter((finding) => finding.evidence.length === 0)
  add(
    'Every finding carries evidence',
    withoutEvidence.length === 0,
    withoutEvidence.length ? `${plural(withoutEvidence.length, 'finding')} has no evidence entry.` : `All ${nf(assessment.findings.length)} findings carry at least one evidence record.`,
  )

  /* ── soft findings a reader should still see ───────────────────────── */
  add(
    'Assessment coverage is complete',
    !truth.partial,
    truth.partial ? (completenessNote(truth) ?? 'This scan is partial.') : 'Every selected engine reported and every dimension in scope was read.',
    true,
  )
  add(
    'Work was not truncated by the assessment budget',
    !assessment.task.coverage.truncated,
    assessment.task.coverage.truncated
      ? text(assessment.task.coverage.truncationNote, 'A bounded budget stopped the work early, so every total is a floor.')
      : 'The assessment read every candidate artefact within budget.',
    true,
  )
  /* The same rule the CBOM register prints, so this check and the column it
     is about can never disagree on which rows lack a target. */
  const unmapped = assessment.cbom.filter((component) => component.quantumStatus === 'vulnerable' && !componentPqcTarget(component))
  add(
    'Every vulnerable component has a role-appropriate post-quantum target',
    unmapped.length === 0,
    unmapped.length
      ? `${plural(unmapped.length, 'vulnerable component')} ${unmapped.length === 1 ? 'has' : 'have'} no role-specific target — the role is unknown or outside the NIST mapping, so the register says "review manually" rather than naming an algorithm that may be the wrong class.`
      : 'Key establishment maps to ML-KEM (FIPS 203); signatures, certificates and code signing map to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).',
    true,
  )
  add(
    'Registers are presented in full in this format',
    context.limitedTables.length === 0,
    context.limitedTables.length
      ? `${plural(context.limitedTables.length, 'register')} shortened for this format: ${context.limitedTables.join(', ')}. The Excel, CSV and JSON exports carry every row.`
      : 'Every register is presented complete in this format.',
    true,
  )
  if (record) {
    add(
      'Record provenance is declared',
      true,
      `Built from a stored record (version ${record.recordVersion}, ${utcStamp(record.recordedAt)}). ${
        record.notRetained.length ? `Not retained: ${record.notRetained.join('; ')}.` : 'Every field was retained.'
      }${record.truncated.length ? ` Capped at storage time: ${record.truncated.join('; ')}.` : ''}`,
    )
  }

  return checks
}

/* ================================================================== */
/* Shared section builders                                             */
/* ================================================================== */

function severityBars(truth: ExposureTruth, total: number): DocumentBlock {
  return {
    type: 'bars',
    title: 'Findings by severity',
    caption: `Counting FINDINGS — the unit work is triaged in. ${nf(total)} in total, of which ${nf(truth.actionable)} are above informational.`,
    unit: 'findings',
    items: SEVERITIES.map((severity) => ({
      label: SEVERITY_TEXT[severity],
      value: truth.severity[severity],
      color: SEVERITY_HEX[severity],
      detail: pctText(truth.severity[severity], total),
    })),
  }
}

function postureStack(truth: ExposureTruth): DocumentBlock {
  return {
    type: 'stacked',
    title: 'Cryptographic posture',
    caption: `Counting COMPONENTS — the unit a migration replaces. Readiness is computed over the ${nf(truth.components.quantumRelevant)} quantum-relevant components only; symmetric and hash primitives are excluded from both sides of the ratio.`,
    unit: 'components',
    total: truth.components.total,
    segments: QUANTUM_ORDER.filter((status) => tallyFor(truth, status) > 0).map((status) => ({
      label: QUANTUM_STATUS_TEXT[status],
      value: tallyFor(truth, status),
      color: QUANTUM_HEX[status],
    })),
  }
}

function tallyFor(truth: ExposureTruth, status: QuantumStatus): number {
  switch (status) {
    case 'vulnerable':
      return truth.components.vulnerable
    case 'hybrid':
      return truth.components.hybrid
    case 'pqc':
      return truth.components.pqc
    case 'resistant':
      return truth.components.resistant
    case 'not-applicable':
      return truth.components.notApplicable
    default:
      return truth.components.unknown
  }
}

function layerBars(assessment: ExposureAssessment): DocumentBlock | null {
  const byLayer = assessment.intelligence.byLayer.filter((entry) => entry.findings > 0 || entry.components > 0)
  if (!byLayer.length) return null
  return {
    type: 'bars',
    title: 'Findings by detection layer',
    caption: 'Where each observation was made. A layer is an attribute of the observation, never the identity of the asset.',
    unit: 'findings',
    items: byLayer.map((entry) => ({
      label: layerLabel(entry.layer),
      value: entry.findings,
      color: entry.critical > 0 ? TONE_HEX.critical : TONE_HEX.info,
      detail: `${nf(entry.components)} component(s)${entry.critical ? ` · ${nf(entry.critical)} critical` : ''}`,
    })),
  }
}

function riskBlocks(assessment: ExposureAssessment, truth: ExposureTruth): DocumentBlock[] {
  const { scores } = assessment.task
  const blocks: DocumentBlock[] = [
    {
      type: 'facts',
      items: [
        { label: 'Security risk', value: riskText(scores.securityRisk, scores.securityBand) },
        { label: 'Quantum risk', value: riskText(scores.quantumRisk, scores.quantumBand) },
        { label: 'Migration risk', value: riskText(scores.migrationRisk, scores.migrationBand) },
        { label: 'Coverage', value: scores.coverage === null ? 'Not measured' : `${scores.coverage}%` },
        { label: 'Detection confidence', value: scores.confidence === null ? 'Not measured' : `${scores.confidence}%` },
      ],
    },
  ]
  if (truth.scoreUnitNote) blocks.push({ type: 'paragraph', text: truth.scoreUnitNote, tone: 'muted' })
  if (scores.basis.length) blocks.push({ type: 'bullets', items: scores.basis })
  blocks.push({
    type: 'callout',
    tone: 'info',
    title: 'Five readings, deliberately not one grade',
    text: 'Security, quantum and migration risk answer different questions and are never collapsed into a single number. Coverage says how much of the target was actually read, and confidence how sure the engines are about the findings behind the other three. A high risk score over low coverage is a different situation from a high score over complete coverage, and one number cannot say which you are looking at.',
  })
  return blocks
}

function coverageSection(assessment: ExposureAssessment, truth: ExposureTruth, rows: number): DocumentSection {
  const { coverage } = assessment.task
  const gaps = gapsTable(assessment, truth)
  const blocks: DocumentBlock[] = [
    {
      type: 'facts',
      items: [
        { label: 'Coverage score', value: assessment.task.scores.coverage === null ? 'Not measured' : `${assessment.task.scores.coverage}%` },
        { label: 'Files discovered / analysed', value: `${nf(coverage.filesDiscovered)} / ${nf(coverage.filesAnalyzed)}` },
        { label: 'Files skipped / unsupported', value: `${nf(coverage.filesSkipped)} / ${nf(coverage.filesUnsupported)}` },
        { label: 'Dimensions not read', value: nf(truth.notAssessed.length) },
        { label: 'Engines incomplete', value: nf(truth.incompleteEngines.length) },
        { label: 'Work truncated', value: coverage.truncated ? 'Yes — totals are a floor' : 'No' },
      ],
    },
    tableBlock(coverageTable(assessment), { rows: Number.POSITIVE_INFINITY, orderedBy: 'dimensions' }),
  ]
  if (gaps.rows.length) {
    blocks.push(
      tableBlock(gaps, {
        rows,
        orderedBy: 'gaps',
        widths: [16, 26, 58],
        note: 'A dimension that could not be read is recorded as not assessed, with its reason. It is never reported as a pass and never counted as a zero.',
      }),
    )
  } else {
    blocks.push({
      type: 'callout',
      tone: 'good',
      title: 'No coverage gap recorded',
      text: 'Every engine selected for this assessment reported, every dimension in scope was read, and no exclusion or budget limit applied. The totals in this report are totals, not floors.',
    })
  }
  return {
    id: 'coverage',
    title: 'Assessment Coverage & Limits',
    intro: 'What was read, what was not, and why. Absent evidence is not clean evidence.',
    blocks,
    pageBreak: true,
  }
}

function methodologySection(assessment: ExposureAssessment, truth: ExposureTruth, target: TargetDescription): DocumentSection {
  return {
    id: 'methodology',
    title: 'Methodology & Definitions',
    intro: 'How every figure in this document was produced, and what each word means.',
    blocks: [
      {
        type: 'facts',
        items: [
          { label: 'Mode', value: `${SCAN_MODE_LABEL[assessment.task.mode]} — ${target.kind}` },
          { label: 'Profile', value: text(assessment.task.profileId) },
          { label: 'Engines selected', value: nf(assessment.task.runs.length) },
          { label: 'Scan identifier', value: assessment.task.scanId },
          { label: 'Evidence window', value: `${utcStamp(assessment.task.startedAt)} -> ${utcStamp(assessment.task.completedAt ?? assessment.generatedAt)}` },
          { label: 'Schema version', value: String(assessment.schemaVersion) },
        ],
      },
      {
        type: 'bullets',
        items: [
          'COMPONENT: one cryptographic primitive in one place — the unit a migration replaces. The bill of materials counts components.',
          'FINDING: one issue worth acting on — the unit work is triaged in. Several findings can attach to one component, so the two counts legitimately differ.',
          'EXPOSURE: several findings that are one underlying issue, merged by correlation — the unit security and migration risk are weighted over. Quantum risk, like readiness, is a share of quantum-relevant COMPONENTS.',
          'SEVERITY is the consequence if the observation is real; CONFIDENCE is how sure the engine is that it is real. They are never collapsed into one number.',
          'DETECTION METHOD is published: observed (the artefact itself was read), inferred (derived from something observed), potential (a pattern matched but context does not prove the cryptography is used), unknown.',
          'QUANTUM STATUS is role-aware, not algorithm-alone: AES-256 protecting data at rest is resistant, while RSA-2048 signing is vulnerable. "Not applicable" exists so a non-cryptographic finding is never given a quantum verdict.',
          'QUANTUM RESISTANT means "not broken by Shor\'s algorithm" and nothing more. A classically broken primitive such as MD5 or RC4 is resistant by that definition and is flagged separately.',
          'POST-QUANTUM READINESS is a share of the quantum-relevant components only. Hybrid deployments count at 0.6 because a classical half remains to be retired. It is null — not zero — when nothing quantum-relevant was observed.',
          'POST-QUANTUM TARGETS follow NIST roles: ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures, certificates and code signing; AES-256-GCM with an ML-KEM-wrapped data key for bulk encryption. ML-KEM is never named as a signature replacement.',
          'NOT ASSESSED is a dimension the assessment could not read, recorded with its reason. It is never rendered as a pass or a zero.',
        ],
      },
      {
        type: 'callout',
        tone: 'warning',
        title: 'What this report does not contain',
        text: 'No migration cost, budget, delivery date or return on investment. An exposure assessment measures cryptography; programme economics depend on a tenant-configured cost model, asset criticality and ownership that this assessment does not observe. Ownership is likewise absent — the scanner records where cryptography is, not who owns it; the Assets & CBOM register holds owner, environment and criticality. Commission a costed plan from the Quantum Readiness Report Center.',
      },
      {
        type: 'paragraph',
        text: truth.readinessReason,
        tone: 'muted',
      },
    ],
    pageBreak: true,
  }
}

/* ================================================================== */
/* Builder                                                             */
/* ================================================================== */

export function buildExposureReport(input: BuildExposureReportInput): InventoryReport {
  const { assessment, template, depth, branding, generatedBy, record } = input
  const spec = EXPOSURE_REPORT_TEMPLATES.find((candidate) => candidate.key === template) || EXPOSURE_REPORT_TEMPLATES[0]
  const depthSpec = EXPOSURE_REPORT_DEPTHS.find((candidate) => candidate.key === depth) || EXPOSURE_REPORT_DEPTHS[1]
  const rows = depthSpec.rows
  const generatedAt = input.generatedAt || new Date().toISOString()

  /* Everything below is READ. Nothing in this builder recomputes a count. */
  const truth = reconcileExposure(assessment)
  const cbom = summariseCbom(assessment.cbom)
  const assets = summariseAssets(assessment)
  const correlation = summariseCorrelation(assessment.exposures)
  const evidence = evidencePopulation(assessment)
  const standards = summariseStandards(assessment)
  const chips = algorithmChipCoverage(assessment)
  const detection = detectionStats(assessment)
  const prioritised = prioritiseMigration(assessment.exposures)
  /* The complete ranked action list — the panel's ten are its first ten. */
  const actions = rankRecommendations({ findings: assessment.findings, exposures: assessment.exposures })
  const target = describeTarget(assessment.task.target)
  const findings = sortedFindings(assessment)

  const reportId = `XR-${generatedAt.slice(0, 10).replace(/-/g, '')}-${sha3Hex(`${assessment.task.scanId}|${template}|${depth}|${generatedAt}`)
    .slice(0, 8)
    .toUpperCase()}`

  /* Complete registers — these are the Excel sheets and the CSV blocks, and
     they are never truncated whatever presentation depth is chosen. */
  const registers: ReportTable[] = []
  const pushRegister = (table: ReportTable) => {
    if (table.rows.length) registers.push(table)
  }

  const limitedTables: string[] = []
  const present = (
    table: ReportTable,
    opts: { widths?: number[]; emphasis?: Array<{ column: number; kind: 'severity' | 'status' | 'band' | 'priority' }>; orderedBy: string; wide?: boolean; note?: string; rows?: number },
  ): DocumentBlock => {
    const budget = opts.rows ?? rows
    if (Number.isFinite(budget) && table.rows.length > budget) limitedTables.push(table.title)
    return tableBlock(table, { ...opts, rows: budget, emphasis: opts.emphasis as never })
  }

  const sections: DocumentSection[] = []
  let classicalQualified = false

  const classicalCallout = (): DocumentBlock | null => {
    if (cbom.classicallyWeak === 0) return null
    classicalQualified = true
    return {
      type: 'callout',
      tone: 'critical',
      title: `${nf(cbom.classicallyWeak)} of the ${nf(truth.components.resistant)} quantum-resistant components are broken classically`,
      text: `"Quantum resistant" is a verdict about Shor's algorithm and nothing else. ${plural(cbom.classicallyWeak, 'component')} in that bucket uses a primitive already broken by classical cryptanalysis — MD5, SHA-1, RC4, DES, 3DES, Blowfish or similar. These require replacement regardless of any quantum timeline, and reading the resistant count as an all-clear would invert what the evidence says.`,
    }
  }

  const unitNoteBlock = (): DocumentBlock | null =>
    truth.unitNote ? { type: 'paragraph', text: truth.unitNote, tone: 'muted' } : null

  const push = (section: DocumentSection) => sections.push(section)
  const compact = (blocks: Array<DocumentBlock | null>): DocumentBlock[] => blocks.filter((block): block is DocumentBlock => block !== null)

  /* ── Scope (technical / compliance) ───────────────────────────────── */
  const scopeSection = (): DocumentSection => ({
    id: 'scope',
    title: 'Scope & Methodology',
    intro: `${SCAN_MODE_LABEL[assessment.task.mode]} mode assessment of ${target.label}.`,
    blocks: compact([
      { type: 'facts', items: [...target.facts, { label: 'Scan identifier', value: assessment.task.scanId }, { label: 'Status', value: STATUS_TEXT[assessment.task.status] ?? assessment.task.status }, { label: 'Started', value: utcStamp(assessment.task.startedAt) }, { label: 'Completed', value: utcStamp(assessment.task.completedAt) }] },
      assessment.intelligence.facts.length
        ? { type: 'facts', items: assessment.intelligence.facts.map((fact) => ({ label: fact.label, value: fact.detail ? `${fact.value} — ${fact.detail}` : fact.value })) }
        : null,
      assessment.intelligence.languages.length
        ? {
            type: 'bars',
            title: 'Languages in scope',
            unit: 'files',
            caption: `Detected across ${nf(assessment.task.coverage.filesAnalyzed)} analysed files.`,
            items: assessment.intelligence.languages.slice(0, 12).map((entry) => ({ label: entry.language, value: entry.files, color: TONE_HEX.info })),
          }
        : null,
      assessment.intelligence.frameworks.length
        ? { type: 'bullets', items: [`Frameworks and platforms detected: ${assessment.intelligence.frameworks.join(', ')}.`] }
        : null,
      assessment.task.localOnly
        ? {
            type: 'callout',
            tone: 'good',
            title: 'Local-only collection',
            text: 'Files were read through the browser\'s own file-system authorisation and analysed in a Web Worker on the device. No file content, secret value or Git object was uploaded. This document was rendered in the same browser session.',
          }
        : null,
    ]),
    pageBreak: true,
  })

  /* ── Template bodies ──────────────────────────────────────────────── */

  if (template === 'executive') {
    push({
      id: 'dashboard',
      title: 'Executive Dashboard',
      intro: 'The reading of this assessment, with every count carrying the unit it was measured in.',
      blocks: compact([
        { type: 'kpis', items: highlights(assessment, truth, cbom) },
        severityBars(truth, assessment.findings.length),
        postureStack(truth),
        layerBars(assessment),
        unitNoteBlock(),
      ]),
    })
    push({ id: 'risk', title: 'Risk Decomposition', intro: 'What each score was computed over, and why it reads as it does.', blocks: riskBlocks(assessment, truth) })
    push({
      id: 'quantum',
      title: 'Quantum Exposure',
      intro: `Counting cryptographic components — the unit a migration replaces. ${truth.readiness === null ? 'Readiness is not measurable in this scope.' : `Readiness ${truth.readiness}%.`}`,
      blocks: compact([
        present(algorithmsTable(cbom), { orderedBy: 'largest groups', widths: [20, 10, 8, 18, 24, 10, 10], emphasis: [{ column: 3, kind: 'status' }], rows: Number.POSITIVE_INFINITY }),
        cbom.byUsage.length ? present(usageTable(cbom), { orderedBy: 'most used roles', widths: [52, 24, 24], rows: Number.POSITIVE_INFINITY }) : null,
        classicalCallout(),
        truth.components.unknown > 0
          ? {
              type: 'callout',
              tone: 'warning',
              title: `${plural(truth.components.unknown, 'component')} could not be classified`,
              text: 'An unclassified component is excluded from readiness on both sides of the ratio — it is neither evidence of exposure nor of safety. Review resolves it; silence does not.',
            }
          : null,
      ]),
      pageBreak: true,
    })
    push({
      id: 'priorities',
      title: 'Priority Exposures',
      intro: prioritised.length
        ? `${plural(prioritised.length, 'exposure')} ${prioritised.length === 1 ? 'is a migration candidate' : 'are migration candidates'}, ordered by a score built from severity, reachability, assertion lifetime and detection confidence.`
        : 'No exposure in scope is a migration candidate.',
      blocks: prioritised.length
        ? [present(prioritiesTable(prioritised), { orderedBy: 'highest-priority', widths: [6, 5, 20, 8, 9, 9, 10, 12, 11, 10], emphasis: [{ column: 0, kind: 'priority' }, { column: 3, kind: 'severity' }] })]
        : [{ type: 'callout', tone: 'good', title: 'Nothing queued for migration', text: 'No correlated exposure in scope is both quantum-relevant and replaceable at the layer it was observed. That is a statement about this scope, not about the estate.' }],
      pageBreak: true,
    })
    push({
      id: 'actions',
      title: 'Recommended Actions',
      intro: actions.length
        ? `${plural(actions.length, 'distinct action')} ${actions.length === 1 ? 'was' : 'were'} produced by this assessment, most severe first — the dashboard panel shows the first ${nf(Math.min(actions.length, assessment.intelligence.recommendations.length))}. Each is backed by the findings it addresses.`
        : 'This assessment produced no recommended action.',
      blocks: actions.length
        ? [present(recommendationsTable(actions), { orderedBy: 'most severe', widths: [26, 9, 8, 9, 48], emphasis: [{ column: 1, kind: 'severity' }] })]
        : [{ type: 'paragraph', text: 'No recommendation was raised. With findings present this would itself be a defect; with none, it is the correct outcome for this scope.', tone: 'muted' }],
    })
    push(coverageSection(assessment, truth, rows))
    push(methodologySection(assessment, truth, target))
  }

  if (template === 'technical') {
    push(scopeSection())
    push({
      id: 'ledger',
      title: 'Engine Execution Ledger',
      intro: `Every engine selected for this assessment, with the state it reached. ${plural(assessment.task.runs.length, 'engine')} selected; ${nf(assessment.task.runs.filter((run) => run.state === 'completed').length)} completed.`,
      blocks: compact([
        present(ledgerTable(assessment.task.runs), { orderedBy: 'engines', widths: [18, 14, 10, 7, 7, 13, 11, 11, 9], emphasis: [{ column: 2, kind: 'status' }], rows: Number.POSITIVE_INFINITY }),
        {
          type: 'paragraph',
          text: 'An engine always reaches a terminal state. "Not applicable" means the target carries nothing for that engine to read; "not assessed" means it could not be read and the reason is recorded; "failed" means the dimension is incomplete rather than clean.',
          tone: 'muted',
        },
      ]),
    })
    push({
      id: 'posture',
      title: 'Posture Analysis',
      blocks: compact([
        { type: 'kpis', items: highlights(assessment, truth, cbom) },
        severityBars(truth, assessment.findings.length),
        postureStack(truth),
        layerBars(assessment),
        unitNoteBlock(),
        classicalCallout(),
        ...riskBlocks(assessment, truth),
      ]),
      pageBreak: true,
    })
    push({
      id: 'cbom',
      title: 'Cryptographic Bill of Materials',
      intro: `${plural(assessment.cbom.length, 'component')} across ${plural(cbom.byAlgorithm.length, 'algorithm group')}.`,
      blocks: compact([
        present(algorithmsTable(cbom), { orderedBy: 'largest groups', widths: [20, 10, 8, 18, 24, 10, 10], emphasis: [{ column: 3, kind: 'status' }], rows: Number.POSITIVE_INFINITY }),
        cbom.byUsage.length ? present(usageTable(cbom), { orderedBy: 'most used roles', widths: [52, 24, 24], rows: Number.POSITIVE_INFINITY }) : null,
        assessment.cbom.length
          ? present(cbomTable(assessment.cbom), { orderedBy: 'most exposed', emphasis: [{ column: 7, kind: 'status' }], wide: true })
          : { type: 'callout', tone: 'warning', title: 'No cryptographic component observed', text: 'No component reached the bill of materials in this scope. That is a statement about what was read, not evidence that no cryptography exists.' },
      ]),
      pageBreak: true,
    })
    push({
      id: 'findings',
      title: 'Findings Register',
      intro: `${plural(assessment.findings.length, 'finding')} in triage order (${describeSeverity(truth.severity)}).`,
      blocks: assessment.findings.length
        ? [present(findingsTable(findings), { orderedBy: 'highest-severity', emphasis: [{ column: 1, kind: 'severity' }, { column: 16, kind: 'priority' }], wide: true })]
        : [{ type: 'callout', tone: 'good', title: 'No finding raised', text: 'The engines that reported raised no finding in this scope. Read this together with Assessment Coverage & Limits: an unread dimension raises no finding either.' }],
      pageBreak: true,
    })
    push({
      id: 'exposures',
      title: 'Correlated Exposures',
      intro: correlation.total
        ? `${plural(correlation.total, 'exposure')} in total: ${nf(correlation.merged.length)} merged from several findings or layers (${nf(correlation.crossLayer)} genuinely cross-layer) and ${nf(correlation.singletons)} single-finding, single-layer.`
        : 'Correlation produced no exposure.',
      blocks: correlation.total
        ? compact([
            present(exposuresTable(correlation.merged, 'Merged Exposures'), { orderedBy: 'highest-severity', widths: [18, 7, 7, 10, 8, 8, 6, 10, 12, 14], emphasis: [{ column: 1, kind: 'severity' }], note: 'An exposure merges findings that are one underlying issue. Cross-layer exposures carry the blast radius across the pipeline.' }),
            correlation.singletons
              ? present(exposuresTable(assessment.exposures.filter((exposure) => exposure.findingIds.length === 1 && exposure.layers.length <= 1), 'Single-Finding Exposures'), {
                  orderedBy: 'highest-severity',
                  widths: [18, 7, 7, 10, 8, 8, 6, 10, 12, 14],
                  emphasis: [{ column: 1, kind: 'severity' }],
                  note: 'These are still exposures, and every score in this report counts them. They are tabled separately because nothing was merged into them.',
                })
              : null,
          ])
        : [{ type: 'paragraph', text: 'No correlated exposure was produced, which follows from there being no finding to correlate.', tone: 'muted' }],
      pageBreak: true,
    })
    push({
      id: 'inventory',
      title: 'Scanned Inventory',
      intro: `${plural(assets.rows.length, 'row')}: ${nf(assets.scanned)} carrying evidence and ${nf(assets.gaps)} standing for a gap. A further ${plural(assets.clean, 'analysed file')} produced neither a finding nor a component and therefore has no row.`,
      blocks: compact([
        present(inventoryTable(assets.rows), { orderedBy: 'most exposed', widths: [26, 14, 9, 7, 7, 7, 8, 7, 7, 8], emphasis: [{ column: 2, kind: 'status' }] }),
        {
          type: 'paragraph',
          text: 'An asset is identified by what it is, never by the detection layer that observed it — every layer it was seen through is listed in "Observed through". The quantum columns count FINDINGS; the component column counts components. Hybrid is listed separately from post-quantum because a hybrid deployment still carries a classical half.',
          tone: 'muted',
        },
      ]),
      pageBreak: true,
    })
    push({
      id: 'detection',
      title: 'How This Was Detected',
      intro: 'The provenance of every observation behind the figures above.',
      blocks: compact([
        {
          type: 'kpis',
          items: [
            { label: 'Confirmed', value: nf(detection.confirmed), detail: 'Direct evidence corroborated at more than one layer', tone: 'good' },
            { label: 'Potential', value: nf(detection.potential), detail: 'Suggestive, not conclusive', tone: 'medium' },
            { label: 'No determination recorded', value: nf(detection.notEstablished), detail: 'The engine recorded no ground-truth state', tone: 'neutral' },
            { label: 'Detection layers', value: nf(detection.layers.length), detail: 'Independent methods that contributed', tone: 'info' },
            { label: 'Observations with caveats', value: nf(detection.withCaveats), detail: 'Carrying a recorded doubt', tone: 'neutral' },
            { label: 'Corroborated findings', value: `${nf(evidence.corroborated)} of ${nf(evidence.total)}`, detail: `${nf(evidence.unbacked)} carry no detection layer at all`, tone: evidence.unbacked ? 'medium' : 'good' },
          ],
        },
        detection.layers.length
          ? {
              type: 'bars',
              title: 'Observations per detection layer',
              unit: 'observations',
              caption: `${nf(detection.observations)} observations across ${nf(detection.layers.length)} layers. A lexical match alone never reaches high confidence; API semantics, configuration directives and parsed structures do, because they establish what the cryptography is used FOR.`,
              items: detection.layers.map(([layer, count]) => ({ label: layer, value: count, color: layer === 'lexical' ? '#94A3B8' : TONE_HEX.info })),
            }
          : null,
        {
          type: 'table',
          table: {
            title: 'Detection method and confidence',
            columns: ['Dimension', 'Value', 'Findings', 'Share'],
            rows: [
              ...[...methodSplit(assessment).detection.entries()].map(([key, value]) => ['Detection method', key, nf(value), pctText(value, assessment.findings.length)] as Array<string | number>),
              ...[...methodSplit(assessment).confidence.entries()].map(([key, value]) => ['Confidence', key, nf(value), pctText(value, assessment.findings.length)] as Array<string | number>),
            ],
          },
          widths: [26, 26, 24, 24],
        },
      ]),
    })
    if (assessment.intelligence.secrets.length) {
      push({
        id: 'secrets',
        title: 'Secret Material',
        intro: `${plural(assessment.intelligence.secrets.length, 'secret')} observed, ${nf(assessment.intelligence.secrets.filter((secret) => secret.historical).length)} of them in Git history. Every value is redacted; the locations are not.`,
        blocks: [
          present(secretsTable(assessment), { orderedBy: 'highest-severity', widths: [18, 38, 11, 11, 11, 11], emphasis: [{ column: 2, kind: 'severity' }] }),
          {
            type: 'callout',
            tone: 'critical',
            title: 'Treat every location as disclosed',
            text: 'A secret observed in a repository or working tree must be rotated and revoked, not removed. A secret found in Git history remains retrievable from every clone of that repository.',
          },
        ],
      })
    }
    if (assessment.intelligence.dependencies.length) {
      const crypto = assessment.intelligence.dependencies.filter((dependency) => dependency.cryptoRelevant || dependency.quantumRelevant)
      push({
        id: 'dependencies',
        title: 'Dependency Surface',
        intro: `${plural(assessment.intelligence.dependencies.length, 'dependency')} resolved, of which ${nf(crypto.length)} ${crypto.length === 1 ? 'is' : 'are'} cryptographically relevant.`,
        blocks: [
          present(dependenciesTable(assessment), { orderedBy: 'most cryptographically relevant', widths: [34, 14, 14, 12, 13, 13], emphasis: [{ column: 5, kind: 'status' }] }),
          {
            type: 'paragraph',
            text: 'A dependency is cryptographically relevant when it provides or configures cryptography, and quantum-relevant when what it provides is asymmetric key establishment, a signature scheme or certificate handling. Both verdicts are inferred from the package, so they are reported as inference, not observation.',
            tone: 'muted',
          },
        ],
        pageBreak: true,
      })
    }
    push(coverageSection(assessment, truth, rows))
    push(methodologySection(assessment, truth, target))
  }

  if (template === 'remediation') {
    push({
      id: 'priorities',
      title: 'Remediation Priorities',
      intro: prioritised.length
        ? `${plural(prioritised.length, 'exposure')} ${prioritised.length === 1 ? 'is a migration candidate' : 'are migration candidates'}. Priority is driven by severity, Internet reachability, the lifetime of the cryptographic assertion, harvest-now-decrypt-later reach and detection confidence — never by the algorithm name alone.`
        : 'No exposure in scope is a migration candidate.',
      blocks: compact([
        {
          type: 'kpis',
          items: [
            { label: 'P1 — now', value: nf(prioritised.filter((entry) => entry.priority === 'P1').length), detail: 'Severity plus reachability or assertion lifetime', tone: 'critical' },
            { label: 'P2 — next wave', value: nf(prioritised.filter((entry) => entry.priority === 'P2').length), detail: 'Real candidates without urgency pressure', tone: 'high' },
            { label: 'P3 — scheduled', value: nf(prioritised.filter((entry) => entry.priority === 'P3').length), detail: 'Plan into routine change', tone: 'medium' },
            { label: 'P4 — verify first', value: nf(prioritised.filter((entry) => entry.priority === 'P4').length), detail: 'Low detection confidence — confirm before scheduling', tone: 'neutral' },
            { label: 'Quantum-vulnerable components', value: nf(truth.components.vulnerable), detail: `of ${nf(truth.components.total)} observed`, tone: truth.components.vulnerable ? 'critical' : 'good' },
            { label: 'Post-quantum readiness', value: truth.readiness === null ? 'Not measured' : `${truth.readiness}%`, detail: 'Share of the quantum-relevant components', tone: readinessTone(truth.readiness) },
          ],
        },
        prioritised.length
          ? present(prioritiesTable(prioritised), { orderedBy: 'highest-priority', widths: [6, 5, 20, 8, 9, 9, 10, 12, 11, 10], emphasis: [{ column: 0, kind: 'priority' }, { column: 3, kind: 'severity' }] })
          : { type: 'callout', tone: 'good', title: 'Nothing queued for migration', text: 'No correlated exposure in scope is both quantum-relevant and replaceable at the layer it was observed.' },
      ]),
      pageBreak: true,
    })

    const worklist = prioritised.slice(0, Number.isFinite(rows) ? Math.max(6, Math.min(rows, 60)) : prioritised.length)
    if (worklist.length < prioritised.length) limitedTables.push('Exposure Worklists')
    push({
      id: 'worklists',
      title: 'Exposure Worklists',
      intro: `One dossier per exposure, highest priority first${worklist.length < prioritised.length ? ` — ${nf(worklist.length)} of ${nf(prioritised.length)} shown in this format` : ''}.`,
      blocks: worklist.length
        ? worklist.map((entry) => ({ type: 'dossier' as const, dossier: exposureDossier(entry) }))
        : [{ type: 'paragraph', text: 'No exposure requires remediation in this scope.', tone: 'muted' }],
      pageBreak: true,
    })

    push({
      id: 'recommendations',
      title: 'Engine Recommendations',
      intro: actions.length
        ? `${plural(actions.length, 'distinct action')}, most severe first.`
        : 'No recommendation was raised.',
      blocks: actions.length
        ? [present(recommendationsTable(actions), { orderedBy: 'most severe', widths: [26, 9, 8, 9, 48], emphasis: [{ column: 1, kind: 'severity' }] })]
        : [{ type: 'paragraph', text: 'No recommendation was raised in this scope.', tone: 'muted' }],
    })

    const weak = assessment.cbom.filter((component) => describeAlgorithm(component.canonicalAlgorithm)?.classicallyWeak === true)
    push({
      id: 'classical',
      title: 'Classical Weaknesses',
      intro: weak.length
        ? `${plural(weak.length, 'component')} uses a primitive already broken by classical cryptanalysis. These need replacing regardless of any quantum timeline.`
        : 'No component in scope uses a classically broken primitive.',
      blocks: compact([
        weak.length ? present(cbomTable(weak), { orderedBy: 'most exposed', emphasis: [{ column: 7, kind: 'status' }], wide: true }) : null,
        weak.length ? classicalCallout() : { type: 'callout', tone: 'good', title: 'No classically broken primitive', text: 'Every component in the quantum-resistant bucket is also sound against classical cryptanalysis.' },
      ]),
      pageBreak: true,
    })

    const unclassified = assessment.cbom.filter((component) => component.quantumStatus === 'unknown')
    push({
      id: 'unclassified',
      title: 'Unclassified Cryptography',
      intro: unclassified.length
        ? `${plural(unclassified.length, 'component')} carries no quantum verdict. Each is excluded from readiness on both sides of the ratio and needs review, not assumption.`
        : 'Every observed component carries a quantum verdict.',
      blocks: unclassified.length
        ? [present(cbomTable(unclassified), { orderedBy: 'first observed', wide: true })]
        : [{ type: 'callout', tone: 'good', title: 'Nothing unclassified', text: 'Every component the assessment observed was classified, so readiness is computed over the whole quantum-relevant population.' }],
    })

    const safe = assessment.cbom.filter((component) => component.quantumStatus === 'pqc' || component.quantumStatus === 'hybrid')
    push({
      id: 'safe',
      title: 'Already Quantum-Safe',
      intro: safe.length
        ? `${plural(truth.components.pqc, 'post-quantum component')} and ${plural(truth.components.hybrid, 'hybrid component')} are already deployed. Hybrid is counted at 0.6 towards readiness because a classical half remains to be retired — it is substantial progress, not a finished migration.`
        : 'No post-quantum or hybrid cryptography was observed in this scope.',
      blocks: safe.length
        ? [present(cbomTable(safe), { orderedBy: 'post-quantum first', emphasis: [{ column: 7, kind: 'status' }], wide: true })]
        : [{ type: 'paragraph', text: 'Nothing in scope is post-quantum or hybrid yet. Where readiness is published as a percentage, that percentage is this population over the quantum-relevant total.', tone: 'muted' }],
    })

    push(coverageSection(assessment, truth, rows))
    push(methodologySection(assessment, truth, target))
  }

  if (template === 'compliance') {
    push(scopeSection())
    /* An auditor needs the posture as well as the provenance. Without this
       section the dossier reported "Quantum Resistant: N" with no qualifier,
       so an estate whose resistant bucket is MD5 and RC4 read as an all-clear
       in the one document written for the people least able to spot it. */
    push({
      id: 'posture',
      title: 'Cryptographic Posture',
      intro: 'What the assessment observed, in the units it was measured in.',
      blocks: compact([
        { type: 'kpis', items: highlights(assessment, truth, cbom) },
        postureStack(truth),
        severityBars(truth, assessment.findings.length),
        unitNoteBlock(),
        classicalCallout(),
      ]),
      pageBreak: true,
    })
    push({
      id: 'standards',
      title: 'Standards Cited',
      intro: standards.rows.length
        ? `${plural(standards.rows.length, 'publication')} cited across ${nf(standards.cited)} of ${nf(standards.total)} findings. ${nf(standards.uncited)} finding${standards.uncited === 1 ? '' : 's'} cite${standards.uncited === 1 ? 's' : ''} no publication this panel can parse and ${standards.uncited === 1 ? 'is' : 'are'} absent from the table rather than ranked below it.`
        : 'No finding cites a publication.',
      blocks: standards.rows.length
        ? [
            present(standardsTable(standards.rows), { orderedBy: 'most cited', widths: [30, 16, 40, 14], rows: Number.POSITIVE_INFINITY }),
            {
              type: 'paragraph',
              text: 'The count is DISTINCT findings, which is the unit the column is labelled in. Counting references instead turns it into a citation tally the moment one finding cites two clauses of the same publication — so the per-row totals legitimately sum to more than the finding count.',
              tone: 'muted',
            },
          ]
        : [{ type: 'callout', tone: 'warning', title: 'No standard cited', text: 'No finding in this scope carries a parseable publication citation. With findings present this is a gap in the evidence chain, not a clean result.' }],
      pageBreak: true,
    })
    push({
      id: 'evidence',
      title: 'Evidence Quality',
      intro: 'How sure the platform is about each observation, and on what basis.',
      blocks: compact([
        {
          type: 'kpis',
          items: [
            { label: 'Corroborated findings', value: `${nf(evidence.corroborated)} of ${nf(evidence.total)}`, detail: 'Carrying at least one recorded detection layer', tone: evidence.unbacked ? 'medium' : 'good' },
            { label: 'No detection layer', value: nf(evidence.unbacked), detail: 'Cannot be corroborated at all — absent from the matrix, not ranked below it', tone: evidence.unbacked ? 'warning' : 'good' },
            { label: 'Confirmed', value: nf(detection.confirmed), detail: 'Direct evidence, corroborated at more than one layer', tone: 'good' },
            { label: 'Potential', value: nf(detection.potential), detail: 'Suggestive, not conclusive', tone: 'medium' },
            { label: 'Detection confidence', value: assessment.task.scores.confidence === null ? 'Not measured' : `${assessment.task.scores.confidence}%`, detail: 'Severity-weighted across the findings', tone: shareTone(assessment.task.scores.confidence) },
            { label: 'Observations with caveats', value: nf(detection.withCaveats), detail: 'Carrying a recorded doubt', tone: 'neutral' },
          ],
        },
        {
          type: 'table',
          table: {
            title: 'Detection method and confidence',
            columns: ['Dimension', 'Value', 'Findings', 'Share'],
            rows: [
              ...[...methodSplit(assessment).detection.entries()].map(([key, value]) => ['Detection method', key, nf(value), pctText(value, assessment.findings.length)] as Array<string | number>),
              ...[...methodSplit(assessment).confidence.entries()].map(([key, value]) => ['Confidence', key, nf(value), pctText(value, assessment.findings.length)] as Array<string | number>),
            ],
          },
          widths: [26, 26, 24, 24],
        },
        {
          type: 'bullets',
          items: [
            'SEVERITY is the consequence if the observation is real; CONFIDENCE is how sure the engine is that it is real. An auditor reading only severity will over-state the certainty of the record.',
            'An INFERRED finding is never presented as an observation, and a POTENTIAL match is capped in severity precisely because the surrounding context does not prove the cryptography is used.',
            'A finding with no evidence cannot be constructed: evidence is a required field of the record.',
          ],
        },
      ]),
      pageBreak: true,
    })
    push({
      id: 'observations',
      title: 'Control Observations',
      intro: assessment.findings.length
        ? `Every finding with the publications it cites, in triage order (${describeSeverity(truth.severity)}).`
        : 'No finding was raised.',
      blocks: assessment.findings.length
        ? [present(findingsTable(findings), { orderedBy: 'highest-severity', emphasis: [{ column: 1, kind: 'severity' }], wide: true })]
        : [{ type: 'callout', tone: 'good', title: 'No finding raised', text: 'The engines that reported raised no finding. Read this with Coverage Gaps: an unread dimension raises no finding either.' }],
      pageBreak: true,
    })
    push({
      id: 'gaps',
      title: 'Coverage Gaps',
      intro: 'Every edge of this record, stated as an edge.',
      blocks: coverageSection(assessment, truth, rows).blocks,
      pageBreak: true,
    })
    push({
      id: 'record',
      title: 'Record Provenance',
      intro: record ? `Built from a stored assessment record, version ${record.recordVersion}.` : 'Built from a live assessment held in this browser session.',
      blocks: record
        ? compact([
            { type: 'facts', items: [{ label: 'Recorded at', value: utcStamp(record.recordedAt) }, { label: 'Record version', value: String(record.recordVersion) }, { label: 'Fields not retained', value: nf(record.notRetained.length) }, { label: 'Lists capped at storage', value: nf(record.truncated.length) }] },
            record.rehydrated.length ? { type: 'bullets', items: record.rehydrated.map((item) => `Read from the record: ${item}`) } : null,
            record.recomputed.length ? { type: 'bullets', items: record.recomputed.map((item) => `Recomputed with the same functions a live view uses: ${item}`) } : null,
            record.notRetained.length
              ? { type: 'callout', tone: 'warning', title: `${plural(record.notRetained.length, 'field')} not retained`, text: `${record.notRetained.join('; ')}. These are reported as not retained rather than as empty — a field the record did not keep must never read as a field the scan found nothing in.` }
              : null,
            record.truncated.length ? { type: 'callout', tone: 'warning', title: `${plural(record.truncated.length, 'list')} capped at storage time`, text: record.truncated.join('; ') } : null,
          ])
        : [
            {
              type: 'callout',
              tone: 'good',
              title: 'Live assessment',
              text: `This document was built from the assessment held in the browser session that ran it, generated ${utcStamp(assessment.generatedAt)}. Nothing was read back from storage, so no field is subject to a retention limit.`,
            },
          ],
    })
    push(methodologySection(assessment, truth, target))
  }

  /* ── Registers: complete, for Excel / CSV / JSON ──────────────────── */
  pushRegister(findingsTable(findings))
  pushRegister(cbomTable(assessment.cbom))
  pushRegister(exposuresTable(assessment.exposures))
  pushRegister(exposureEvidenceTable(assessment.exposures))
  pushRegister(prioritiesTable(prioritised))
  pushRegister(inventoryTable(assets.rows))
  pushRegister(ledgerTable(assessment.task.runs))
  pushRegister(algorithmsTable(cbom))
  pushRegister(usageTable(cbom))
  pushRegister(standardsTable(standards.rows))
  pushRegister(recommendationsTable(actions))
  pushRegister(secretsTable(assessment))
  pushRegister(dependenciesTable(assessment))
  pushRegister(coverageTable(assessment))
  pushRegister(gapsTable(assessment, truth))

  /* ── Decisions, validation, cover ─────────────────────────────────── */
  const decisions = decisionRegister(assessment, truth, cbom, prioritised)
  const checks = validate({
    assessment,
    truth,
    cbom,
    assets,
    correlation,
    evidence,
    standards,
    chips,
    detection,
    limitedTables: Array.from(new Set(limitedTables)),
    classicalQualified,
    record,
  })
  const validation = validationScore(checks)

  const statusWord = STATUS_TEXT[assessment.task.status] ?? assessment.task.status
  const scopeLine = `${SCAN_MODE_LABEL[assessment.task.mode]} assessment of ${target.label} — ${withUnit(assessment.findings.length, 'finding')}, ${plural(assessment.exposures.length, 'correlated exposure')}, ${plural(assessment.cbom.length, 'cryptographic component')}${truth.partial ? ' (partial coverage)' : ''}`

  const summaryHighlights = highlights(assessment, truth, cbom)
  const document: ReportDocument = {
    branding,
    template: { key: spec.key, name: spec.name, audience: spec.audience },
    cover: {
      eyebrow: `${SCAN_MODE_LABEL[assessment.task.mode]} Mode Exposure Assessment`,
      title: spec.name,
      subtitle: `${branding.companyName}${branding.businessUnit ? ` — ${branding.businessUnit}` : ''}`,
      scopeLine,
      facts: [
        { label: 'Report ID', value: reportId },
        { label: 'Version', value: branding.reportVersion || '1.0' },
        { label: 'Generated', value: utcStamp(generatedAt) },
        { label: 'Generated by', value: generatedBy || 'QGuard Helix' },
        { label: 'Report owner', value: branding.reportOwner || 'Not recorded' },
        { label: 'Reviewer', value: branding.reviewer || 'Not recorded' },
        { label: 'Assessment target', value: `${target.label} — ${target.kind}` },
        { label: 'Assessment status', value: statusWord },
        { label: 'Scan identifier', value: assessment.task.scanId },
        { label: 'Evidence as of', value: utcStamp(assessment.task.completedAt ?? assessment.generatedAt) },
        { label: 'Presented depth', value: `${depthSpec.label} — ${depthSpec.detail}` },
        { label: 'Source', value: record ? `Stored assessment record v${record.recordVersion}` : 'Live assessment in this browser session' },
      ],
    },
    summary: {
      headline: headlineSentence(assessment, truth, target),
      paragraphs: summaryParagraphs(assessment, truth, cbom, correlation, prioritised, target, record),
      highlights: summaryHighlights,
    },
    sections,
    decisions,
    validation,
    provenance: [
      `Every figure derives from the authorised ${SCAN_MODE_LABEL[assessment.task.mode]} mode assessment ${assessment.task.scanId}, read through the same derivations the dashboard renders (exposure-truth, panel-model, cbom, risk). No value is simulated, sampled or projected.`,
      'Counts are published in three units and each is named where it appears: COMPONENT (what a migration replaces), FINDING (what work is triaged in) and EXPOSURE (what risk is scored over). Several findings can attach to one component, so the counts legitimately differ.',
      'Risk, coverage and confidence are the orchestrator\'s own scores with the basis it published; this document never recomputes them. Post-quantum readiness is a share of the quantum-relevant components, with hybrid at 0.6, and is reported as not measured rather than as 0% when nothing quantum-relevant was observed.',
      'No migration cost, budget, delivery date or ROI is asserted anywhere in this document. Ownership, environment and asset criticality are not observed by an exposure assessment and are not reported.',
      assessment.task.localOnly
        ? 'Collection was local-only: file content, secret values and repository objects never left the device, and this document was rendered in the same browser session.'
        : 'Acquisition was read-only against the authorised target; credentials are never recorded in an assessment.',
      ...(record ? [`Built from a stored record (version ${record.recordVersion}, ${utcStamp(record.recordedAt)}). Fields the record did not retain are named in Record Provenance and are never rendered as empty results.`] : []),
      ...(branding.customNotes ? [branding.customNotes] : []),
    ],
  }

  const kpis: InventoryKpi[] = summaryHighlights.map((item) => ({ label: item.label, value: item.value, detail: item.detail }))

  /* ── Reconciliation: the exported document against the dashboard ──── */
  const reconciliation: ReconciliationRow[] = []
  const addRecon = (metric: string, dashboard: string | number, exported: string | number) =>
    reconciliation.push({ metric, dashboard: String(dashboard), exported: String(exported), matches: String(dashboard) === String(exported) })

  const exportedFindings = registers.find((table) => table.title === 'Findings Register')?.rows.length ?? 0
  const exportedCbom = registers.find((table) => table.title === 'Cryptographic Bill of Materials')?.rows.length ?? 0
  const exportedExposures = registers.find((table) => table.title === 'Correlated Exposures')?.rows.length ?? 0
  const exportedInventory = registers.find((table) => table.title === 'Scanned Inventory')?.rows.length ?? 0
  const exportedLedger = registers.find((table) => table.title === 'Engine Execution Ledger')?.rows.length ?? 0

  addRecon('Findings (status bar) = findings register rows', assessment.findings.length, exportedFindings)
  addRecon('Cryptographic components (status bar) = CBOM rows', assessment.cbom.length, exportedCbom)
  addRecon('Correlated exposures (status bar) = exposure register rows', assessment.exposures.length, exportedExposures)
  addRecon('Scanned inventory rows (panel) = inventory register rows', assets.rows.length, exportedInventory)
  addRecon('Engines selected (ledger) = ledger register rows', assessment.task.runs.length, exportedLedger)
  addRecon(
    'Quantum-vulnerable COMPONENTS (Quantum Exposure panel) = vulnerable CBOM rows',
    truth.components.vulnerable,
    (registers.find((table) => table.title === 'Cryptographic Bill of Materials')?.rows.filter((row) => row[7] === QUANTUM_STATUS_TEXT.vulnerable).length ?? 0),
  )
  addRecon(
    'Quantum-vulnerable FINDINGS (findings filter) = vulnerable findings register rows',
    truth.findings.vulnerable,
    (registers.find((table) => table.title === 'Findings Register')?.rows.filter((row) => row[10] === QUANTUM_STATUS_TEXT.vulnerable).length ?? 0),
  )
  addRecon(
    'Critical findings (severity donut) = critical findings register rows',
    truth.severity.critical,
    (registers.find((table) => table.title === 'Findings Register')?.rows.filter((row) => row[1] === SEVERITY_TEXT.critical).length ?? 0),
  )
  addRecon('Algorithm groups (CBOM panel) = algorithm register rows', cbom.byAlgorithm.length, registers.find((table) => table.title === 'Algorithms Observed')?.rows.length ?? 0)
  addRecon('Post-quantum readiness (Quantum Exposure panel)', truth.readiness === null ? 'Not measured' : `${truth.readiness}%`, truth.readiness === null ? 'Not measured' : `${truth.readiness}%`)
  addRecon('Security risk (Risk Decomposition panel)', riskText(assessment.task.scores.securityRisk, assessment.task.scores.securityBand), riskText(assessment.task.scores.securityRisk, assessment.task.scores.securityBand))
  addRecon('Coverage (Risk Decomposition panel)', assessment.task.scores.coverage === null ? 'Not measured' : `${assessment.task.scores.coverage}%`, assessment.task.scores.coverage === null ? 'Not measured' : `${assessment.task.scores.coverage}%`)
  addRecon('Dimensions not assessed (Coverage panel) = coverage gap rows of that kind', truth.notAssessed.length, gapsTable(assessment, truth).rows.filter((row) => row[0] === 'Dimension not read').length)
  /* The panel shows the head of the ranked action list; the register is the
     whole list. Both halves of that claim are checked, in order. */
  const shownActions = assessment.intelligence.recommendations
  addRecon(
    'Recommended actions (panel) = leading rows of the action register, in order',
    shownActions.length,
    shownActions.filter((entry, index) => actions[index]?.title === entry.title).length,
  )
  addRecon(
    'Distinct actions (panel denominator) = action register rows',
    assessment.intelligence.recommendationCandidates ?? shownActions.length,
    registers.find((table) => table.title === 'Engine Recommendations')?.rows.length ?? 0,
  )
  addRecon(
    'Evidence records across exposures = exposure evidence register rows',
    assessment.exposures.reduce((sum, exposure) => sum + exposure.evidence.length, 0),
    registers.find((table) => table.title === 'Exposure Evidence')?.rows.length ?? 0,
  )

  const tables: ReportTable[] = [
    ...registers,
    { title: 'Executive Decision Register', columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], rows: decisions.map((entry) => [entry.priority, entry.decision, entry.rationale, entry.evidence, entry.owner]) },
    { title: 'Report Validation', columns: ['Check', 'Result', 'Detail'], rows: checks.map((check) => [check.check, check.status.toUpperCase(), check.detail]) },
  ]

  const slugTarget = target.label.replace(/[^a-z0-9.-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'assessment'
  const report: InventoryReport = {
    meta: {
      kind: 'exposure',
      title: spec.name,
      subtitle: `${SCAN_MODE_LABEL[assessment.task.mode]} mode exposure assessment — ${target.label}`,
      generatedAt,
      companyName: branding.companyName || 'QGuard Helix',
      classification: branding.classification || 'CONFIDENTIAL',
      scopeNote: scopeLine,
      provenance: `Source: QGuard Helix Exposure Assessment Engine, ${SCAN_MODE_LABEL[assessment.task.mode]} mode, scan ${assessment.task.scanId}${record ? ` (stored record v${record.recordVersion})` : ''}.`,
      filenameSlug: `${assessment.task.mode}-exposure-${template}-${slugTarget}`,
      reportId,
      version: branding.reportVersion || '1.0',
      generatedBy,
      dataAsOf: assessment.task.completedAt ?? assessment.generatedAt,
    },
    kpis,
    tables,
    reconciliation,
    notes: document.provenance,
    document,
  }

  /* Sealed last, over everything a reader can see. The seal is excluded
     wherever it appears, so anyone holding the JSON export can recompute the
     digest — see `canonicalExposureReport`. */
  report.integrity = sealDocument(canonicalExposureReport(report), { reportId, kind: 'exposure-assessment' })
  report.document!.integrity = report.integrity
  return report
}

/** One remediation dossier per prioritised exposure. */
function exposureDossier(entry: ReturnType<typeof prioritiseMigration>[number]): AssetDossier {
  const { exposure, priority, score, drivers } = entry
  const target = exposure.migration?.target
  const evidenceRows = exposure.evidence.slice(0, 12).map((record) => [
    text(record.file ?? record.reference ?? record.scope),
    record.line ? nf(record.line) : '—',
    text(record.provider),
    oneLine(record.summary, 200),
    oneLine(record.snippet, 120),
    utcStamp(record.observedAt),
  ])
  return {
    id: exposure.key,
    title: exposure.title,
    subtitle: `${priority} · priority score ${nf(score)} · ${exposure.layers.map(layerLabel).join(' · ') || 'single layer'}`,
    badges: [
      { label: priority, tone: priority === 'P1' ? 'critical' : priority === 'P2' ? 'high' : priority === 'P3' ? 'medium' : 'neutral' },
      { label: SEVERITY_TEXT[exposure.severity], tone: toneForLabel(SEVERITY_TEXT[exposure.severity]) },
      { label: QUANTUM_STATUS_TEXT[exposure.quantumStatus], tone: exposure.quantumStatus === 'vulnerable' ? 'critical' : exposure.quantumStatus === 'pqc' ? 'good' : 'info' },
      { label: `${exposure.confidence} confidence`, tone: exposure.confidence === 'high' ? 'good' : exposure.confidence === 'medium' ? 'medium' : 'warning' },
    ],
    facts: [
      { label: 'Algorithm', value: text(exposure.canonicalAlgorithm) },
      { label: 'Role', value: text(exposure.role) },
      { label: 'Findings merged', value: nf(exposure.findingIds.length) },
      { label: 'Layers spanned', value: exposure.layers.length ? `${nf(exposure.layers.length)} — ${exposure.layers.map(layerLabel).join(', ')}` : 'One' },
      { label: 'Post-quantum target', value: text(target, 'Not recorded by the engine — confirm the role before selecting one') },
      { label: 'Complexity', value: text(exposure.migration?.complexity) },
      { label: 'Blast radius', value: exposure.migration?.blastRadius !== undefined ? nf(exposure.migration.blastRadius) : 'Not recorded' },
      { label: 'Why this priority', value: drivers.length ? drivers.join('; ') : 'Base severity only' },
    ],
    summary: oneLine(exposure.recommendation, 420) === '—'
      ? 'The engine recorded no recommendation for this exposure. Confirm the cryptographic role before selecting a replacement: a role-blind substitution is how a key-exchange gets told to adopt a signature scheme.'
      : oneLine(exposure.recommendation, 420),
    tables: evidenceRows.length
      ? [
          {
            table: { title: 'Evidence', columns: ['Location', 'Line', 'Provider', 'Observation', 'Redacted excerpt', 'Observed (UTC)'], rows: evidenceRows },
            widths: [24, 6, 10, 30, 18, 12],
            note:
              exposure.evidence.length > evidenceRows.length
                ? `${plural(exposure.evidence.length - evidenceRows.length, 'further evidence record')} for this exposure ${exposure.evidence.length - evidenceRows.length === 1 ? 'is' : 'are'} in the Exposure Evidence register of the Excel, CSV and JSON exports.`
                : undefined,
          },
        ]
      : [],
  }
}

/** The exact string the integrity digest is computed over. */
export function canonicalExposureReport(report: InventoryReport): string {
  return JSON.stringify(report, (key, value) => (key === 'integrity' ? undefined : value))
}
