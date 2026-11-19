/**
 * Asset & CBOM assessment report — the premium export of /dashboard/assets.
 *
 * Built ONLY from `AssetRegister` rows (src/lib/assets/asset-register.ts), the
 * same derivation the page renders. The builder never re-queries, never
 * re-counts on a different key and never estimates: a figure in the document
 * is the figure on the screen for the same scope, and the Reconciliation and
 * Validation sections prove it on the document's own face.
 *
 * It deliberately does NOT model migration cost, waves or timelines. Those are
 * the Quantum Readiness Engine's opinion of the estate; this is a register of
 * what was measured. The document says so and points to Report Center instead
 * of inventing a budget (Report_Generation_Skills: "never invent costs").
 *
 * Pure and isomorphic — `tools/asset-report-check.ts` drives it offline.
 */
import {
  COMPONENT_CLASS_LABEL,
  PQC_STATUS_META,
  REGISTER_BANDS,
  STALE_AFTER_HOURS,
  summarizeRows,
  type AssetRegister,
  type AssetRegisterRow,
  type RegisterComponent,
  type RegisterTotals,
  type SeverityOrUnrated,
} from '@/lib/assets/asset-register'
import type { InventoryKpi, InventoryReport, ReconciliationRow } from './InventoryReport'
import type { ReportBranding, ReportProvenance, ReportTable } from './schemas/ReportSchema'
import {
  TONE_HEX,
  toneForLabel,
  validationScore,
  type AssetDossier,
  type BlockTone,
  type DecisionEntry,
  type DocumentBlock,
  type DocumentKpi,
  type DocumentSection,
  type ReportDocument,
  type TableEmphasis,
  type ValidationEntry,
} from './ReportDocument'
import { sealDocument, sha3Hex } from './ReportIntegrity'

/* ================================================================== */
/* Templates                                                           */
/* ================================================================== */

export type AssetReportTemplate = 'executive' | 'technical' | 'remediation'

export interface AssetReportTemplateSpec {
  key: AssetReportTemplate
  name: string
  audience: string
  description: string
  sections: string[]
}

export const ASSET_REPORT_TEMPLATES: AssetReportTemplateSpec[] = [
  {
    key: 'executive',
    name: 'Executive Asset Brief',
    audience: 'CISO · Board · Risk committee',
    description: 'Board-ready posture of the selected assets: where the quantum exposure sits, what to fix first and the decisions required.',
    sections: ['Executive Summary', 'Executive Dashboard', 'Asset Risk Overview', 'Top Exposures', 'Recommended Actions', 'Decision Register', 'Methodology', 'Validation & Integrity'],
  },
  {
    key: 'technical',
    name: 'Technical Asset & CBOM Register',
    audience: 'Security engineering · Architecture · Audit',
    description: 'Complete per-asset dossiers, the full cryptographic bill of materials and configuration findings, reconciled to the dashboard.',
    sections: ['Executive Summary', 'Scope & Methodology', 'Posture Analysis', 'Asset Register', 'Asset Dossiers', 'Cryptographic Bill of Materials', 'Configuration Findings', 'Consolidated Exposures', 'Decision Register', 'Validation & Integrity'],
  },
  {
    key: 'remediation',
    name: 'PQC Remediation Worklist',
    audience: 'Platform teams · Asset owners',
    description: 'Prioritised remediation per asset: evidence, recommended action, PQC target and the platform module that executes each change.',
    sections: ['Executive Summary', 'Remediation Priorities', 'Asset Worklists', 'Evidence Freshness', 'PQC-Ready Assets', 'Decision Register', 'Validation & Integrity'],
  },
]

/* ================================================================== */
/* Inputs                                                              */
/* ================================================================== */

export type AssetReportScopeType = 'selection' | 'filtered' | 'all'

export interface AssetReportScope {
  type: AssetReportScopeType
  /** How the user chose the rows, e.g. `2 selected assets` or `search "google"`. */
  description: string
}

export interface BuildAssetReportInput {
  register: AssetRegister
  /** The in-scope rows, exactly as the page resolved them. */
  rows: AssetRegisterRow[]
  scope: AssetReportScope
  template: AssetReportTemplate
  branding: ReportBranding
  generatedBy: string
  generatedAt?: string
  provenance?: Omit<ReportProvenance, 'validationStatus'>
}

/* ================================================================== */
/* Formatting                                                          */
/* ================================================================== */

const SEVERITY_ORDER: SeverityOrUnrated[] = ['critical', 'high', 'medium', 'low', 'unrated']
const SEVERITY_LABEL: Record<SeverityOrUnrated | 'safe', string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unrated: 'Unrated',
  safe: 'Safe',
}
const SEVERITY_HEX: Record<SeverityOrUnrated, string> = {
  critical: TONE_HEX.critical,
  high: TONE_HEX.high,
  medium: TONE_HEX.medium,
  low: TONE_HEX.low,
  unrated: '#94A3B8',
}
const POSTURE_HEX = { vulnerable: '#DC2626', unclassified: '#94A3B8', ready: '#16A34A', notMeasured: '#64748B' }
const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, unrated: 1, safe: 0 }

const plural = (n: number, noun: string, many = `${noun}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? noun : many}`
const pct = (part: number, total: number) => (total > 0 ? Math.round((part / total) * 1000) / 10 : 0)
const pctText = (part: number, total: number) => (total > 0 ? `${pct(part, total)}%` : '—')

export function utcStamp(value: string | null | undefined): string {
  if (!value) return 'Not recorded'
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'Not recorded'
}

const ownerText = (row: AssetRegisterRow) => row.owner || 'Unassigned'
const orDash = (value: string | null | undefined) => (value && String(value).trim() ? String(value) : '—')

/* ================================================================== */
/* Consolidated exposures — one row per ROOT CAUSE, never per raw row  */
/* ================================================================== */

export interface ConsolidatedExposure {
  key: string
  riskBearing: string
  classLabel: string
  worstSeverity: SeverityOrUnrated
  components: number
  instances: number
  assets: string[]
  recommendation: string
  pqcTarget: string
  route: string
  priority: 'P1' | 'P2' | 'P3'
}

function mostFrequent(values: Array<string | null | undefined>): string | null {
  const counts = new Map<string, number>()
  for (const value of values) {
    const text = String(value || '').trim()
    if (!text) continue
    counts.set(text, (counts.get(text) || 0) + 1)
  }
  let best: string | null = null
  let bestCount = 0
  for (const [value, count] of counts) {
    if (count > bestCount || (count === bestCount && best !== null && value.length > best.length)) {
      best = value
      bestCount = count
    }
  }
  return best
}

function priorityFor(severity: SeverityOrUnrated): 'P1' | 'P2' | 'P3' {
  return severity === 'critical' || severity === 'high' ? 'P1' : severity === 'medium' ? 'P2' : 'P3'
}

/**
 * Consolidate the vulnerable components of the scope by the primitive that
 * carries the risk. Σ exposure.components === Σ vulnerable components — a
 * consolidation that changes the total is using the wrong key.
 */
export function consolidateExposures(rows: AssetRegisterRow[]): ConsolidatedExposure[] {
  const groups = new Map<string, { members: Array<{ component: RegisterComponent; asset: string }> }>()
  for (const row of rows) {
    for (const component of row.componentList) {
      if (component.posture !== 'vulnerable') continue
      const key = `${component.componentClass}|${component.riskBearing.trim().toLowerCase()}`
      const group = groups.get(key) || { members: [] }
      group.members.push({ component, asset: row.name })
      groups.set(key, group)
    }
  }
  const exposures: ConsolidatedExposure[] = []
  for (const [key, { members }] of groups) {
    const first = members[0].component
    const worst = members.reduce<SeverityOrUnrated>((acc, { component }) => {
      const severity = component.severity === 'safe' ? 'unrated' : component.severity
      return SEVERITY_RANK[severity] > SEVERITY_RANK[acc] ? severity : acc
    }, 'unrated')
    exposures.push({
      key,
      riskBearing: first.riskBearing,
      classLabel: first.classLabel,
      worstSeverity: worst,
      components: members.length,
      instances: members.reduce((sum, { component }) => sum + component.instances, 0),
      assets: Array.from(new Set(members.map((m) => m.asset))).sort(),
      recommendation: mostFrequent(members.map((m) => m.component.recommendation)) || 'Review against the NIST PQC migration policy and assign remediation ownership.',
      pqcTarget: mostFrequent(members.map((m) => (m.component.pqcReplacement ? targetLabel(m.component) : null))) || 'Pending classification',
      route: mostFrequent(members.map((m) => m.component.remediationRoute)) || '/dashboard/pqc-orchestration',
      priority: priorityFor(worst),
    })
  }
  return exposures.sort(
    (a, b) =>
      SEVERITY_RANK[b.worstSeverity] - SEVERITY_RANK[a.worstSeverity] ||
      b.assets.length - a.assets.length ||
      b.components - a.components ||
      a.riskBearing.localeCompare(b.riskBearing),
  )
}

/* ================================================================== */
/* Visual blocks — values only, never recomputed                       */
/* ================================================================== */

function postureStack(t: RegisterTotals, caption?: string): DocumentBlock {
  return {
    type: 'stacked',
    title: 'Cryptographic component posture',
    caption: caption || `${plural(t.components.total, 'component')} measured on ${plural(t.assets, 'asset')}. Each component has exactly one posture, so the segments partition the total.`,
    total: t.components.total,
    unit: 'components',
    segments: [
      { label: 'Quantum-vulnerable', value: t.components.vulnerable, color: POSTURE_HEX.vulnerable },
      { label: 'Unclassified', value: t.components.unclassified, color: POSTURE_HEX.unclassified },
      { label: 'PQC-ready', value: t.components.pqcReady, color: POSTURE_HEX.ready },
    ],
  }
}

function severityBars(t: RegisterTotals): DocumentBlock {
  return {
    type: 'bars',
    title: 'Quantum-vulnerable components by severity',
    caption: `Severity as graded by the scanner for each of the ${plural(t.components.vulnerable, 'quantum-vulnerable component')}. Bars sum to that total.`,
    unit: 'components',
    items: SEVERITY_ORDER.filter((key) => key !== 'unrated' || t.vulnerableSeverity.unrated > 0).map((key) => ({
      label: SEVERITY_LABEL[key],
      value: t.vulnerableSeverity[key],
      color: SEVERITY_HEX[key],
    })),
  }
}

function statusBars(t: RegisterTotals): DocumentBlock {
  const order = ['quantum-vulnerable', 'needs-review', 'not-measured', 'pqc-ready'] as const
  const color = { 'quantum-vulnerable': POSTURE_HEX.vulnerable, 'needs-review': '#D97706', 'not-measured': POSTURE_HEX.notMeasured, 'pqc-ready': POSTURE_HEX.ready }
  return {
    type: 'bars',
    title: 'Assets by PQC status',
    caption: 'Decided only from measured components: PQC-ready requires every component to be classified quantum-safe.',
    unit: 'assets',
    items: order.map((key) => ({ label: PQC_STATUS_META[key].label, value: t.pqcStatus[key], color: color[key] })),
  }
}

function bandBars(t: RegisterTotals): DocumentBlock {
  const present = REGISTER_BANDS.filter((band) => t.bands[band.key] > 0)
  return {
    type: 'bars',
    title: 'Assets by scanner risk band',
    caption: `Canonical platform risk bands (Critical ≥ 80, High ≥ 60, Elevated ≥ 40, Moderate ≥ 20). ${present.length < REGISTER_BANDS.length ? 'Bands with no assets are omitted.' : ''}`.trim(),
    unit: 'assets',
    items: present.map((band) => ({ label: band.label, value: t.bands[band.key], color: band.hex })),
  }
}

function classTable(t: RegisterTotals): DocumentBlock {
  return {
    type: 'table',
    table: {
      title: 'Posture by component class',
      columns: ['Component class', 'Components', 'Quantum-vulnerable', 'PQC-ready', 'Unclassified', 'Vulnerable share'],
      rows: t.classes.map((c) => [c.label, c.components, c.vulnerable, c.pqcReady, c.unclassified, pctText(c.vulnerable, c.components)]),
    },
    widths: [30, 14, 18, 13, 13, 12],
    note: t.classes.some((c) => c.key === 'other')
      ? `"${COMPONENT_CLASS_LABEL.other}" are rows the CBOM counts as components whose algorithm field names no primitive the platform decomposer can parse (in practice finding titles). They are counted exactly as the CBOM and the Quantum Readiness Engine count them.`
      : undefined,
  }
}

function highlights(t: RegisterTotals): DocumentKpi[] {
  const criticalHigh = t.vulnerableSeverity.critical + t.vulnerableSeverity.high
  return [
    { label: 'Assets in scope', value: t.assets.toLocaleString('en-US'), detail: `${t.pqcStatus['quantum-vulnerable']} with vulnerable cryptography`, tone: 'info' },
    { label: 'Crypto components', value: t.components.total.toLocaleString('en-US'), detail: `${t.components.instances.toLocaleString('en-US')} observations`, tone: 'neutral' },
    { label: 'Quantum-vulnerable', value: t.components.vulnerable.toLocaleString('en-US'), detail: `${pctText(t.components.vulnerable, t.components.total)} of components`, tone: t.components.vulnerable ? 'critical' : 'good' },
    { label: 'Critical + high', value: criticalHigh.toLocaleString('en-US'), detail: `${t.vulnerableSeverity.critical} critical · ${t.vulnerableSeverity.high} high`, tone: criticalHigh ? 'high' : 'good' },
    { label: 'PQC-ready', value: t.components.pqcReady.toLocaleString('en-US'), detail: `${pctText(t.components.pqcReady, t.components.total)} of components`, tone: 'good' },
    {
      label: 'Highest scanner risk',
      value: t.risk.max === null ? 'Not assessed' : `${t.risk.max}/100`,
      detail: t.risk.maxAsset ? `${t.risk.maxAsset} · mean ${t.risk.mean ?? '—'}` : 'No risk evidence in scope',
      tone: t.risk.max === null ? 'neutral' : toneForLabel(REGISTER_BANDS.find((b) => t.bands[b.key] > 0)?.label || ''),
    },
  ]
}

/* ================================================================== */
/* Tables                                                              */
/* ================================================================== */

const ASSET_REGISTER_COLUMNS = [
  'Asset', 'Target', 'Type', 'Owner', 'Environment', 'Internet-facing', 'PQC Status', 'Components', 'Quantum-vulnerable', 'PQC-ready', 'Unclassified',
  'Critical', 'High', 'Medium', 'Low', 'Worst Severity', 'Scanner Risk', 'Risk Band', 'Last Scanned (UTC)', 'Evidence Age', 'Freshness',
  'Lifecycle Stage', 'Open Actions', 'Configuration Findings', 'Detection Signals',
]

function assetRegisterTable(rows: AssetRegisterRow[]): ReportTable {
  return {
    title: 'Asset Register',
    columns: ASSET_REGISTER_COLUMNS,
    rows: rows.map((row) => [
      row.name,
      row.target,
      row.typeLabel,
      ownerText(row),
      orDash(row.environment),
      row.internetFacing ? 'Yes' : 'No',
      row.pqcStatusLabel,
      row.components.total,
      row.components.vulnerable,
      row.components.pqcReady,
      row.components.unclassified,
      row.vulnerableSeverity.critical,
      row.vulnerableSeverity.high,
      row.vulnerableSeverity.medium,
      row.vulnerableSeverity.low,
      row.worstComponentSeverity ? SEVERITY_LABEL[row.worstComponentSeverity] : '—',
      row.riskScore === null ? 'Not assessed' : row.riskScore,
      row.risk.label,
      utcStamp(row.lastScanned),
      row.freshness.label,
      labelFreshness(row.freshness.state),
      row.lifecycle?.label || '—',
      row.lifecycle?.openActions ?? '—',
      row.posture.total,
      row.detectionSignals,
    ]),
  }
}

/**
 * The register as PRINTED (PDF, Word, deck, HTML). Twenty-five columns do not
 * fit a page — narrow columns wrap one character per line — so print carries
 * the columns a reader acts on, with fixed widths. The complete register is in
 * `report.tables` (Excel, CSV, JSON), and the printed table says so.
 */
function assetRegisterPrintBlock(rows: AssetRegisterRow[]): DocumentBlock {
  return {
    type: 'table',
    wide: true,
    table: {
      title: 'Asset register',
      columns: ['Asset', 'Owner', 'PQC status', 'Comp.', 'Vuln.', 'Ready', 'Crit.', 'High', 'Worst', 'Scanner risk', 'Last scanned (UTC)', 'Freshness', 'Lifecycle'],
      rows: rows.map((row) => [
        `${row.name}${row.internetFacing ? ' (internet-facing)' : ''}`,
        ownerText(row),
        PQC_STATUS_META[row.pqcStatus].short,
        row.components.total,
        row.components.vulnerable,
        row.components.pqcReady,
        row.vulnerableSeverity.critical,
        row.vulnerableSeverity.high,
        row.worstComponentSeverity ? SEVERITY_LABEL[row.worstComponentSeverity] : '—',
        row.riskScore === null ? 'Not assessed' : `${row.riskScore} · ${row.risk.label}`,
        utcStamp(row.lastScanned).replace(' UTC', ''),
        labelFreshness(row.freshness.state),
        row.lifecycle?.label || '—',
      ]),
    },
    widths: [17, 8, 9, 5, 5, 5, 5, 5, 7, 9, 10, 9, 8],
    emphasis: [{ column: 2, kind: 'status' }, { column: 8, kind: 'severity' }, { column: 11, kind: 'status' }],
    note: 'Printed columns are the ones owners act on. The Excel, CSV and JSON exports carry the complete 25-column register (target, environment, criticality, medium/low counts, evidence age, open actions, configuration findings and detection signals).',
  }
}

function cbomPrintBlock(rows: AssetRegisterRow[]): DocumentBlock {
  return {
    type: 'table',
    wide: true,
    table: {
      title: 'Cryptographic bill of materials',
      columns: ['Asset', 'Component', 'Risk-bearing primitive', 'Key size', 'Posture', 'Severity', 'Inst.', 'PQC target', 'Recommended action'],
      rows: rows.flatMap((row) =>
        row.componentList.map((c) => [
          row.name,
          c.name,
          c.riskBearing,
          orDash(c.keySize),
          shortPosture(c),
          SEVERITY_LABEL[c.severity],
          c.instances,
          targetLabel(c),
          orDash(c.recommendation),
        ]),
      ),
    },
    widths: [11, 22, 13, 5, 9, 7, 4, 13, 16],
    emphasis: [{ column: 4, kind: 'status' }, { column: 5, kind: 'severity' }],
    note: 'Evidence text, component class, remediation module and last-seen time for every component are in the Excel, CSV and JSON exports.',
  }
}

function labelFreshness(state: AssetRegisterRow['freshness']['state']) {
  return state === 'fresh' ? 'Current (< 24h)' : state === 'aging' ? 'Aging (24–72h)' : state === 'stale' ? `Stale (> ${STALE_AFTER_HOURS}h)` : 'No timestamp'
}

function assetOverviewTable(rows: AssetRegisterRow[]): { table: ReportTable; widths: number[]; emphasis: TableEmphasis[] } {
  return {
    table: {
      title: 'Asset risk overview',
      columns: ['Asset', 'PQC status', 'Vulnerable / components', 'Worst severity', 'Scanner risk', 'Owner', 'Last scanned'],
      rows: rows.map((row) => [
        `${row.name}${row.internetFacing ? ' (internet-facing)' : ''}`,
        PQC_STATUS_META[row.pqcStatus].short,
        `${row.components.vulnerable} / ${row.components.total}`,
        row.worstComponentSeverity ? SEVERITY_LABEL[row.worstComponentSeverity] : '—',
        row.riskScore === null ? 'Not assessed' : `${row.riskScore}/100 · ${row.risk.label}`,
        ownerText(row),
        `${utcStamp(row.lastScanned).replace(' UTC', '')} (${row.freshness.label})`,
      ]),
    },
    widths: [24, 12, 13, 11, 14, 11, 15],
    emphasis: [{ column: 1, kind: 'status' }, { column: 3, kind: 'severity' }],
  }
}

const CBOM_COLUMNS = ['Asset', 'Component', 'Class', 'Algorithm', 'Risk-bearing Primitive', 'Key Size', 'Posture', 'Severity', 'Instances', 'PQC Target', 'PQC Target Source', 'Recommended Action', 'Evidence', 'Remediation Module', 'Last Seen (UTC)']

/** The PQC target as printed — a corrected target says so. */
function targetLabel(component: RegisterComponent) {
  if (!component.pqcReplacement) return '—'
  return component.pqcTargetSource === 'corrected' ? `${component.pqcReplacement} (corrected)` : component.pqcReplacement
}

function shortPosture(component: RegisterComponent) {
  return component.posture === 'vulnerable' ? 'Vulnerable' : component.posture === 'pqc-ready' ? 'PQC-ready' : 'Unclassified'
}

function postureLabel(component: RegisterComponent) {
  return component.posture === 'vulnerable' ? 'Quantum-vulnerable' : component.posture === 'pqc-ready' ? 'PQC-ready' : 'Unclassified'
}

function cbomTable(rows: AssetRegisterRow[]): ReportTable {
  return {
    title: 'Cryptographic Bill of Materials',
    columns: CBOM_COLUMNS,
    rows: rows.flatMap((row) =>
      row.componentList.map((c) => [
        row.name,
        c.name,
        c.classLabel,
        c.algorithm,
        c.riskBearing,
        orDash(c.keySize),
        postureLabel(c),
        SEVERITY_LABEL[c.severity],
        c.instances,
        orDash(c.pqcReplacement),
        c.pqcTargetSource === 'corrected' ? 'Corrected (stored target named the wrong primitive class)' : c.pqcTargetSource === 'derived' ? 'Derived (canonical FIPS mapping)' : c.pqcTargetSource === 'scanner' ? 'Scanner' : '—',
        orDash(c.recommendation),
        orDash(c.evidence),
        c.remediationRoute,
        utcStamp(c.lastSeen),
      ]),
    ),
  }
}

function postureFindingsTable(rows: AssetRegisterRow[]): ReportTable {
  return {
    title: 'Configuration & Policy Findings',
    columns: ['Asset', 'Observation', 'Severity', 'Flagged', 'Instances', 'Recommendation', 'Last Seen (UTC)'],
    rows: rows.flatMap((row) =>
      row.postureList.map((p) => [row.name, p.name, SEVERITY_LABEL[p.severity], p.posture === 'vulnerable' ? 'Yes' : 'No', p.instances, orDash(p.recommendation), utcStamp(p.lastSeen)]),
    ),
  }
}

function exposuresTable(exposures: ConsolidatedExposure[], title = 'Consolidated Exposures'): ReportTable {
  return {
    title,
    columns: ['Priority', 'Risk-bearing Primitive', 'Class', 'Worst Severity', 'Components', 'Instances', 'Assets', 'Recommended Action', 'PQC Target', 'Remediation Module'],
    rows: exposures.map((e) => [e.priority, e.riskBearing, e.classLabel, SEVERITY_LABEL[e.worstSeverity], e.components, e.instances, e.assets.join(', '), e.recommendation, e.pqcTarget, e.route]),
  }
}

/* ================================================================== */
/* Narrative — every sentence is a function of the numbers             */
/* ================================================================== */

function executiveSummary(scopeRows: AssetRegisterRow[], t: RegisterTotals, register: AssetRegister, scope: AssetReportScope, exposures: ConsolidatedExposure[]) {
  const c = t.components
  const vulnerableAssets = t.pqcStatus['quantum-vulnerable']
  const criticalHigh = t.vulnerableSeverity.critical + t.vulnerableSeverity.high
  let headline: string
  if (t.assets === 0) headline = 'No assets are in scope for this report.'
  else if (c.total === 0) headline = `No cryptographic components have been measured on the ${plural(t.assets, 'asset')} in scope.`
  else if (c.vulnerable > 0) {
    headline = `${vulnerableAssets} of ${plural(t.assets, 'asset')} in scope rely on quantum-vulnerable cryptography: ${c.vulnerable} of ${plural(c.total, 'measured component')} (${pctText(c.vulnerable, c.total)}) require modernization${t.vulnerableSeverity.critical ? `, ${t.vulnerableSeverity.critical} of them rated critical` : ''}.`
  } else if (c.pqcReady === c.total) headline = `All ${plural(c.total, 'measured component')} across ${plural(t.assets, 'asset')} are classified quantum-safe.`
  else headline = `${plural(c.unclassified, 'component')} must be classified before PQC readiness can be confirmed.`

  const range = t.oldestScan && t.latestScan
    ? t.oldestScan === t.latestScan
      ? ` on ${utcStamp(t.latestScan)}`
      : ` between ${utcStamp(t.oldestScan)} and ${utcStamp(t.latestScan)}`
    : ''
  const paragraphs: string[] = []
  paragraphs.push(
    `This report covers ${scope.description}: ${plural(t.assets, 'asset')} and ${plural(c.total, 'cryptographic component')} measured by authorized scans${range}. ` +
      (c.total
        ? `${c.pqcReady} (${pctText(c.pqcReady, c.total)}) already use quantum-safe cryptography; ${c.vulnerable} (${pctText(c.vulnerable, c.total)}) use legacy public-key cryptography that a cryptographically relevant quantum computer is expected to break${c.unclassified ? `; ${c.unclassified} could not be classified` : ''}.`
        : 'No component-level evidence exists yet for the assets in scope.'),
  )

  const qr = register.qrFigures
  const riskSentence = t.risk.max === null
    ? 'None of the assets in scope carries scanner risk evidence yet.'
    : `Scanner risk reaches ${t.risk.max}/100 on ${t.risk.maxAsset}, with a mean of ${t.risk.mean}/100 across ${plural(t.risk.assessed, 'assessed asset')}.`
  const severitySentence = c.vulnerable
    ? ` Of the vulnerable components, ${t.vulnerableSeverity.critical} are critical, ${t.vulnerableSeverity.high} high, ${t.vulnerableSeverity.medium} medium and ${t.vulnerableSeverity.low} low${t.vulnerableSeverity.unrated ? ` (${t.vulnerableSeverity.unrated} unrated)` : ''}.`
    : ''
  const qrSentence = qr && qr.hasData && qr.readiness !== null
    ? ` At tenant level the Quantum Readiness Engine rates readiness ${qr.readiness}/100${qr.readinessLevel ? ` (${qr.readinessLevel})` : ''} and quantum risk ${qr.risk ?? '—'}/100 — an estate-wide measure reported beside, not substituted for, the per-asset scanner scores.`
    : ''
  paragraphs.push(`${riskSentence}${severitySentence}${qrSentence}`)

  const hotClasses = t.classes.filter((cls) => cls.vulnerable > 0).slice(0, 2)
  if (hotClasses.length && exposures.length) {
    const top = exposures[0]
    paragraphs.push(
      `Exposure concentrates in ${hotClasses.map((cls) => `${cls.label.toLowerCase()} (${cls.vulnerable} of ${cls.components} vulnerable)`).join(' and ')}. ` +
        `The leading root cause is ${top.riskBearing} in ${top.classLabel.toLowerCase()}, found on ${plural(top.assets.length, 'asset')} at ${SEVERITY_LABEL[top.worstSeverity].toLowerCase()} severity.`,
    )
  }

  if (criticalHigh > 0) {
    const internetFacingVulnerable = scopeRows.filter((row) => row.internetFacing && row.components.vulnerable > 0).length
    paragraphs.push(
      `Start with the ${plural(criticalHigh, 'critical and high-severity component')}${internetFacingVulnerable ? ` on the ${plural(internetFacingVulnerable, 'internet-facing asset')} in scope` : ''}, beginning with ${exposures[0]?.riskBearing ?? 'the leading root cause'}. Every exposure in this report lists its PQC target and the platform module that executes the change.`,
    )
  } else if (c.vulnerable > 0) {
    paragraphs.push(t.vulnerableSeverity.unrated
      ? 'Some vulnerable components have no severity rating. Confirm their priority before scheduling remediation.'
      : `The recorded vulnerable components are medium or low severity. Begin with ${exposures[0]?.riskBearing ?? 'the leading root cause'}.`)
  }

  const stale = t.freshness.stale
  const freshness = stale
    ? `Evidence for ${stale} of ${plural(t.assets, 'asset')} is older than ${STALE_AFTER_HOURS} hours — re-scan before approving changes on the strength of this report.`
    : t.freshness.unknown
      ? `${plural(t.freshness.unknown, 'asset')} carries no scan timestamp.`
      : `All in-scope evidence is less than ${STALE_AFTER_HOURS} hours old.`
  const owners = t.owners.unassigned ? ` ${t.owners.unassigned} of ${plural(t.assets, 'asset')} have no recorded owner.` : ''
  paragraphs.push(`${freshness}${owners}`)
  paragraphs.push('Use Quantum Readiness Reports to review assessment and migration evidence for these assets.')

  return { headline, paragraphs, highlights: highlights(t) }
}

function decisionRegister(rows: AssetRegisterRow[], t: RegisterTotals, exposures: ConsolidatedExposure[]): DecisionEntry[] {
  const decisions: DecisionEntry[] = []
  const owners = Array.from(new Set(rows.filter((r) => r.components.vulnerable > 0).map((r) => r.owner).filter(Boolean))) as string[]
  const ownerLine = owners.length ? owners.join(', ') : 'Unassigned — see owner decision'
  const vulnerableAssets = rows.filter((r) => r.components.vulnerable > 0)
  if (t.components.vulnerable > 0) {
    const transport = rows.reduce((sum, row) => sum + row.componentList.filter((c) => c.posture === 'vulnerable' && (c.componentClass === 'cipher-suite' || c.componentClass === 'key-exchange' || c.componentClass === 'protocol')).length, 0)
    decisions.push({
      priority: t.vulnerableSeverity.critical + t.vulnerableSeverity.high > 0 ? 'P1' : 'P2',
      decision: `Approve PQC remediation of ${plural(t.components.vulnerable, 'quantum-vulnerable component')} across ${plural(vulnerableAssets.length, 'asset')}.`,
      rationale: `${t.vulnerableSeverity.critical} critical and ${t.vulnerableSeverity.high} high-severity components were recorded.${transport ? ` ${transport} vulnerable components relate to transport cryptography. Evaluate data sensitivity, retention and transmission exposure before rating HNDL risk.` : ''}`,
      evidence: `${exposures.length} consolidated root cause(s); leading: ${exposures[0]?.riskBearing ?? '—'}.`,
      owner: ownerLine,
    })
  }
  const internetFacing = vulnerableAssets.filter((r) => r.internetFacing)
  if (internetFacing.length) {
    decisions.push({
      priority: 'P1',
      decision: `Prioritise the ${plural(internetFacing.length, 'internet-facing asset')} with quantum-vulnerable cryptography.`,
      rationale: 'Publicly reachable endpoints are where encrypted traffic can be recorded by any party for later decryption.',
      evidence: internetFacing.map((r) => `${r.name} (${r.components.vulnerable} vulnerable)`).join('; '),
      owner: Array.from(new Set(internetFacing.map(ownerText))).join(', '),
    })
  }
  if (t.owners.unassigned > 0) {
    decisions.push({
      priority: 'P2',
      decision: `Assign accountable owners to ${plural(t.owners.unassigned, 'asset')}.`,
      rationale: 'Remediation cannot be scheduled, approved or verified without an accountable owner.',
      evidence: rows.filter((r) => !r.owner).map((r) => r.name).join(', '),
      owner: 'Security leadership',
    })
  }
  if (t.freshness.stale > 0) {
    decisions.push({
      priority: 'P2',
      decision: `Re-scan ${plural(t.freshness.stale, 'asset')} whose evidence is older than ${STALE_AFTER_HOURS} hours before approving changes.`,
      rationale: 'Certificates, cipher configuration and deployments may have changed since the last measurement.',
      evidence: rows.filter((r) => r.freshness.state === 'stale').map((r) => `${r.name} (${r.freshness.label})`).join('; '),
      owner: Array.from(new Set(rows.filter((r) => r.freshness.state === 'stale').map(ownerText))).join(', '),
    })
  }
  if (t.components.unclassified > 0) {
    decisions.push({
      priority: 'P2',
      decision: `Classify ${plural(t.components.unclassified, 'component')} that the scanner could not grade.`,
      rationale: 'An unclassified component can be neither counted as PQC-ready nor planned for migration.',
      evidence: rows.filter((r) => r.components.unclassified > 0).map((r) => `${r.name} (${r.components.unclassified})`).join('; '),
      owner: Array.from(new Set(rows.filter((r) => r.components.unclassified > 0).map(ownerText))).join(', '),
    })
  }
  if (t.pqcStatus['not-measured'] > 0) {
    decisions.push({
      priority: 'P3',
      decision: `Complete discovery for ${plural(t.pqcStatus['not-measured'], 'asset')} with no measured cryptography.`,
      rationale: 'An asset with no measured components cannot be assessed for quantum exposure.',
      evidence: rows.filter((r) => r.pqcStatus === 'not-measured').map((r) => r.name).join(', '),
      owner: Array.from(new Set(rows.filter((r) => r.pqcStatus === 'not-measured').map(ownerText))).join(', '),
    })
  }
  if (t.pqcStatus['pqc-ready'] > 0) {
    decisions.push({
      priority: 'P3',
      decision: `Keep ${plural(t.pqcStatus['pqc-ready'], 'PQC-ready asset')} under periodic re-validation.`,
      rationale: 'Readiness is a measurement, not a permanent state — configuration drift can reintroduce classical cryptography.',
      evidence: rows.filter((r) => r.pqcStatus === 'pqc-ready').map((r) => r.name).join(', '),
      owner: Array.from(new Set(rows.filter((r) => r.pqcStatus === 'pqc-ready').map(ownerText))).join(', '),
    })
  }
  return decisions
}

function recommendedActions(exposures: ConsolidatedExposure[], limit: number): DocumentBlock {
  const shown = exposures.slice(0, limit)
  return {
      type: 'table',
      table: {
        title: 'Recommended actions',
        columns: ['Priority', 'Action', 'Why (evidence)', 'PQC target', 'Executed in'],
        rows: shown.map((e) => [
          e.priority,
          `Replace ${e.riskBearing} (${e.classLabel.toLowerCase()}) on ${plural(e.assets.length, 'asset')}`,
          `${plural(e.components, 'component')} (${e.instances} observations), worst ${SEVERITY_LABEL[e.worstSeverity].toLowerCase()}: ${e.recommendation}`,
          e.pqcTarget,
          e.route,
        ]),
      },
      widths: [8, 26, 36, 15, 15],
      emphasis: [{ column: 0, kind: 'severity' }],
      note: exposures.length > shown.length ? `Top ${shown.length} of ${exposures.length} consolidated root causes, by severity then breadth. The complete list is in the Technical register and the Excel export.` : undefined,
  }
}

/* ================================================================== */
/* Dossiers                                                            */
/* ================================================================== */

function dossierFor(row: AssetRegisterRow, mode: 'technical' | 'remediation'): AssetDossier {
  const badges: AssetDossier['badges'] = [
    { label: PQC_STATUS_META[row.pqcStatus].label, tone: row.pqcStatus === 'pqc-ready' ? 'good' : row.pqcStatus === 'quantum-vulnerable' ? 'critical' : row.pqcStatus === 'needs-review' ? 'medium' : 'neutral' },
    { label: row.riskScore === null ? 'Risk not assessed' : `Risk ${row.riskScore}/100 · ${row.risk.label}`, tone: toneForLabel(row.risk.label) },
    { label: labelFreshness(row.freshness.state), tone: row.freshness.state === 'stale' ? 'warning' : row.freshness.state === 'fresh' ? 'good' : 'neutral' },
  ]
  if (row.internetFacing) badges.push({ label: 'Internet-facing', tone: 'info' })
  if (row.scanning.active) badges.push({ label: `Scanning now${row.scanning.progress !== null ? ` · ${Math.round(row.scanning.progress)}%` : ''}`, tone: 'info' })

  const facts = [
    { label: 'Owner', value: ownerText(row) },
    { label: 'Environment', value: orDash(row.environment) },
    { label: 'Criticality', value: orDash(row.criticality) },
    { label: 'TLS version', value: orDash(row.tlsVersion) },
    { label: 'Components', value: `${row.components.total} (${row.components.vulnerable} vulnerable · ${row.components.pqcReady} PQC-ready · ${row.components.unclassified} unclassified)` },
    { label: 'Worst component', value: row.worstComponentSeverity ? SEVERITY_LABEL[row.worstComponentSeverity] : '—' },
    { label: 'Last scanned', value: `${utcStamp(row.lastScanned)} (${row.freshness.label})` },
    { label: 'Lifecycle', value: row.lifecycle ? `${row.lifecycle.label} · ${row.lifecycle.openActions} open action(s) · validation ${row.lifecycle.validationStatus}` : 'Workflow status unavailable in this snapshot' },
    { label: 'Configuration findings', value: `${row.posture.total} (${row.posture.flagged} flagged)` },
    { label: 'Detection signals', value: `${row.detectionSignals} raw scanner rows behind these components` },
  ]

  const tables: AssetDossier['tables'] = []
  if (mode === 'technical') {
    tables.push({
      table: {
        title: `Cryptographic components — ${row.name}`,
        columns: ['Severity', 'Component', 'Class', 'Risk-bearing primitive', 'Key size', 'Posture', 'Inst.', 'PQC target'],
        rows: row.componentList.map((c) => [SEVERITY_LABEL[c.severity], c.name, c.classLabel, c.riskBearing, orDash(c.keySize), shortPosture(c), c.instances, targetLabel(c)]),
      },
      widths: [9, 27, 12, 17, 7, 11, 5, 12],
      emphasis: [{ column: 0, kind: 'severity' }, { column: 5, kind: 'status' }],
    })
    if (row.postureList.length) {
      tables.push({
        table: {
          title: `Configuration findings — ${row.name}`,
          columns: ['Severity', 'Observation', 'Inst.', 'Recommendation'],
          rows: row.postureList.map((p) => [SEVERITY_LABEL[p.severity], p.name, p.instances, orDash(p.recommendation)]),
        },
        widths: [10, 36, 6, 48],
        emphasis: [{ column: 0, kind: 'severity' }],
      })
    }
  } else {
    const work = row.componentList.filter((c) => c.posture !== 'pqc-ready')
    tables.push({
      table: {
        title: `Remediation worklist — ${row.name}`,
        columns: ['Priority', 'Severity', 'Component', 'Risk-bearing primitive', 'Recommended action', 'PQC target', 'Executed in'],
        rows: work.map((c) => [
          c.posture === 'unclassified' ? 'P2' : priorityFor(c.severity === 'safe' ? 'unrated' : c.severity),
          SEVERITY_LABEL[c.severity],
          c.name,
          c.riskBearing,
          orDash(c.recommendation),
          targetLabel(c),
          c.remediationRoute,
        ]),
      },
      widths: [8, 9, 22, 15, 24, 11, 11],
      emphasis: [{ column: 1, kind: 'severity' }],
      note: work.length === 0 ? 'No components require remediation on this asset.' : undefined,
    })
  }
  return {
    id: row.id,
    title: row.name,
    subtitle: `${row.typeLabel} · ${row.target}`,
    badges,
    facts,
    summary: row.pqcStatusReason,
    tables,
  }
}

/* ================================================================== */
/* Validation                                                          */
/* ================================================================== */

function validate(rows: AssetRegisterRow[], t: RegisterTotals, register: AssetRegister, exposures: ConsolidatedExposure[], sections: DocumentSection[], scope: AssetReportScope): ValidationEntry[] {
  const checks: ValidationEntry[] = []
  const add = (check: string, ok: boolean, detail: string, soft = false) => checks.push({ check, status: ok ? 'pass' : soft ? 'warn' : 'fail', detail })

  add('Scope contains at least one asset', rows.length > 0, rows.length ? `${plural(rows.length, 'asset')} in scope (${scope.description}).` : 'Nothing selected — the report would describe an empty scope.')
  const ids = new Set(rows.map((r) => r.id))
  add('No duplicate assets', ids.size === rows.length, ids.size === rows.length ? 'Every asset appears once.' : `${rows.length - ids.size} duplicate row(s).`)

  const componentSum = t.components.vulnerable + t.components.pqcReady + t.components.unclassified
  add('Component posture partitions the total', componentSum === t.components.total, `${t.components.vulnerable} + ${t.components.pqcReady} + ${t.components.unclassified} = ${componentSum} of ${t.components.total}.`)
  const severitySum = SEVERITY_ORDER.reduce((sum, key) => sum + t.vulnerableSeverity[key], 0)
  add('Severity bars sum to the vulnerable total', severitySum === t.components.vulnerable, `${severitySum} graded of ${t.components.vulnerable} vulnerable components.`)
  const statusSum = Object.values(t.pqcStatus).reduce((a, b) => a + b, 0)
  add('Every asset has exactly one PQC status', statusSum === t.assets, `${statusSum} statuses for ${t.assets} assets.`)
  const exposureSum = exposures.reduce((sum, e) => sum + e.components, 0)
  add('Consolidated exposures preserve the vulnerable total', exposureSum === t.components.vulnerable, `${exposureSum} components across ${exposures.length} root cause(s) = ${t.components.vulnerable} vulnerable.`)

  // Every table in the document that claims to list per-asset rows lists them all.
  const registerTable = sections.flatMap((s) => s.blocks).find((b) => b.type === 'table' && (b.table.title === 'Asset register' || b.table.title === 'Asset risk overview'))
  if (registerTable && registerTable.type === 'table') {
    add('Asset table lists every asset in scope', registerTable.table.rows.length === rows.length, `${registerTable.table.rows.length} row(s) for ${rows.length} asset(s).`)
  }

  const diverged = register.checks.filter((c) => c.status === 'diverged')
  add(
    'Estate figures reconcile with the CBOM',
    diverged.length === 0,
    diverged.length ? diverged.map((c) => `${c.label}: ${c.expected} vs ${c.actual}`).join('; ') : `${register.checks.length}/${register.checks.length} register checks match the scanner headline.`,
    true,
  )
  add(
    'Quantum Readiness Engine agreement',
    register.qr.state === 'match',
    register.qr.detail,
    true,
  )
  add(
    'Evidence is current',
    t.freshness.stale === 0 && t.freshness.unknown === 0,
    t.freshness.stale || t.freshness.unknown
      ? `${t.freshness.stale} stale (> ${STALE_AFTER_HOURS}h) and ${t.freshness.unknown} untimestamped asset(s) in scope.`
      : `All ${plural(t.assets, 'asset')} measured within ${STALE_AFTER_HOURS} hours.`,
    true,
  )
  const corrected = rows.reduce((sum, row) => sum + row.componentList.filter((c) => c.pqcTargetSource === 'corrected').length, 0)
  add(
    'PQC targets match each component role',
    true,
    corrected
      ? `${plural(corrected, 'stored scanner target')} named ML-KEM (key establishment) for a certificate or signature and ${corrected === 1 ? 'was' : 'were'} corrected to the FIPS 204 signature target — marked "(corrected)".`
      : 'Every stored target matches its component role (ML-KEM for key establishment, ML-DSA / SLH-DSA for signatures).',
  )
  const unparsed = t.classes.find((c) => c.key === 'other')?.components || 0
  add(
    'Every counted component names a parseable primitive',
    unparsed === 0,
    unparsed ? `${plural(unparsed, 'counted component')} name no parseable primitive (finding titles counted by the CBOM predicate) — labelled "${COMPONENT_CLASS_LABEL.other}".` : 'Every component decomposes to a cryptographic primitive.',
    true,
  )
  add(
    'No contradictory posture flags',
    t.contradictoryFlags === 0,
    t.contradictoryFlags ? `${plural(t.contradictoryFlags, 'component')} carry conflicting flags and are counted as unclassified.` : 'No component carries conflicting posture flags.',
    true,
  )
  return checks
}

/* ================================================================== */
/* Builder                                                             */
/* ================================================================== */

export function buildAssetReport(input: BuildAssetReportInput): InventoryReport {
  const { register, rows, scope, template, branding, generatedBy } = input
  const spec = ASSET_REPORT_TEMPLATES.find((candidate) => candidate.key === template) || ASSET_REPORT_TEMPLATES[0]
  const generatedAt = input.generatedAt || new Date().toISOString()
  const t = summarizeRows(rows)
  const exposures = consolidateExposures(rows)
  const summary = executiveSummary(rows, t, register, scope, exposures)
  const decisions = decisionRegister(rows, t, exposures)
  const byRisk = [...rows].sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || b.components.vulnerable - a.components.vulnerable || a.name.localeCompare(b.name))
  const reportId = input.provenance?.reportId ?? `AR-${generatedAt.slice(0, 10).replace(/-/g, '')}-${sha3Hex(`${generatedAt}|${template}|${rows.map((r) => r.id).join(',')}`).slice(0, 8).toUpperCase()}`

  const methodologyBlocks: DocumentBlock[] = [
    {
      type: 'facts',
      items: [
        { label: 'Scope', value: `${scope.description} — ${plural(t.assets, 'asset')} of ${plural(register.rows.length, 'asset')} in the estate` },
        { label: 'Evidence window', value: t.oldestScan ? `${utcStamp(t.oldestScan)} → ${utcStamp(t.latestScan)}` : 'No scan timestamps in scope' },
        { label: 'Snapshot computed', value: utcStamp(register.generatedAt) },
        { label: 'Source', value: 'Authorized scanner evidence: crypto_inventory, pqc_scan_results, crypto_exposures, assets' },
      ],
    },
    {
      type: 'bullets',
      items: [
        'Component: one cryptographic primitive, suite, protocol, certificate or library observed on an asset, grouped exactly as the CBOM Explorer groups it. Instances count how often it was observed.',
        'Configuration finding: a scanner finding about the asset (e.g. missing OCSP stapling). Findings are listed separately and never counted as components.',
        'Quantum-vulnerable: the scanner classified the component as breakable by a cryptographically relevant quantum computer. PQC-ready: classified quantum-safe. Unclassified: neither — requires review.',
        'PQC-ready asset: every measured component is classified quantum-safe. An asset with no measured components is "Not measured", never ready.',
        'Scanner risk: the per-asset 0–100 score recorded by the scanner, banded with the platform risk table. The Quantum Readiness Engine score is a separate, tenant-wide measure and is reported beside it, never substituted for it.',
        `Freshness: current < 24h, aging 24–${STALE_AFTER_HOURS}h, stale > ${STALE_AFTER_HOURS}h since the newest observation of the asset.`,
        'PQC targets follow NIST roles: ML-KEM (FIPS 203) replaces key establishment only; certificates and signatures move to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). A stored target that names the wrong class is corrected and marked "(corrected)".',
      ],
    },
  ]
  if (register.qrFigures && register.qrFigures.hasData) {
    methodologyBlocks.push({
      type: 'callout',
      tone: register.qr.state === 'match' ? 'good' : 'warning',
      title: register.qr.label,
      text: register.qr.detail,
    })
  }

  const sections: DocumentSection[] = []
  const overview = assetOverviewTable(byRisk)

  if (template === 'executive') {
    sections.push({
      id: 'dashboard',
      title: 'Executive Dashboard',
      intro: 'Posture of the assets in scope at a glance. Every chart is backed by the numbers shown beside it.',
      blocks: [postureStack(t), severityBars(t), statusBars(t), bandBars(t)],
    })
    sections.push({
      id: 'assets',
      title: 'Asset Risk Overview',
      intro: 'Every asset in scope, highest scanner risk first.',
      blocks: [{ type: 'table', table: overview.table, widths: overview.widths, emphasis: overview.emphasis }],
    })
    sections.push({
      id: 'exposures',
      title: 'Top Exposures',
      intro: 'Vulnerable components consolidated by the primitive that carries the risk, so one root cause appears once however many assets share it.',
      blocks: exposures.length
        ? [{
            type: 'table',
            table: exposuresTable(exposures.slice(0, 10), 'Top exposures by root cause'),
            widths: [7, 17, 11, 9, 8, 7, 12, 15, 8, 6],
            emphasis: [{ column: 3, kind: 'severity' }],
            note: exposures.length > 10 ? `Top 10 of ${exposures.length} root causes. The complete list is in the Technical register and the Excel export.` : undefined,
          }]
        : [{ type: 'callout', tone: 'neutral', title: 'No recorded quantum-vulnerable components', text: 'Review the source coverage and classification checks for evidence gaps.' }],
    })
    const actions = recommendedActions(exposures, 8)
    sections.push({
      id: 'actions',
      title: 'Recommended Actions',
      intro: 'Derived from the consolidated exposures above — each action names its evidence, its PQC target and the module that executes it.',
      blocks: exposures.length ? [actions] : [{ type: 'paragraph', text: 'No component-level remediation was derived from the classified evidence in this snapshot.', tone: 'muted' }],
    })
    sections.push({ id: 'methodology', title: 'Methodology & Evidence', blocks: methodologyBlocks })
  } else if (template === 'technical') {
    sections.push({ id: 'scope', title: 'Scope & Methodology', blocks: methodologyBlocks })
    sections.push({
      id: 'posture',
      title: 'Posture Analysis',
      blocks: [postureStack(t), classTable(t), severityBars(t), statusBars(t), bandBars(t)],
    })
    sections.push({
      id: 'register',
      title: 'Asset Register',
      intro: 'One row per asset. Components are cryptography only; configuration findings are counted separately.',
      blocks: [assetRegisterPrintBlock(byRisk)],
      pageBreak: true,
    })
    sections.push({
      id: 'dossiers',
      title: 'Asset Dossiers',
      intro: 'Per-asset profile with its full component list and configuration findings.',
      blocks: byRisk.map((row) => ({ type: 'dossier' as const, dossier: dossierFor(row, 'technical') })),
      pageBreak: true,
    })
    sections.push({
      id: 'cbom',
      title: 'Cryptographic Bill of Materials',
      intro: `All ${plural(t.components.total, 'component')} of the assets in scope, with evidence and PQC target.`,
      blocks: [cbomPrintBlock(byRisk)],
      pageBreak: true,
    })
    const findingsTable = postureFindingsTable(byRisk)
    sections.push({
      id: 'findings',
      title: 'Configuration & Policy Findings',
      intro: 'Scanner findings about the assets. They record posture, not cryptography, and are never counted as components.',
      blocks: findingsTable.rows.length
        ? [{ type: 'table', table: findingsTable, widths: [16, 30, 9, 8, 7, 18, 12], emphasis: [{ column: 2, kind: 'severity' }] }]
        : [{ type: 'paragraph', text: 'No configuration findings recorded for the assets in scope.', tone: 'muted' }],
    })
    sections.push({
      id: 'exposures',
      title: 'Consolidated Exposures',
      blocks: exposures.length
        ? [{ type: 'table', table: exposuresTable(exposures), widths: [7, 17, 11, 9, 8, 7, 12, 15, 8, 6], emphasis: [{ column: 3, kind: 'severity' }] }]
        : [{ type: 'paragraph', text: 'No quantum-vulnerable components in scope.', tone: 'muted' }],
    })
  } else {
    sections.push({
      id: 'priorities',
      title: 'Remediation Priorities',
      intro: 'Root causes in execution order: severity first, then how many assets share them.',
      blocks: exposures.length
        ? [{ type: 'table', table: exposuresTable(exposures, 'Remediation priorities'), widths: [7, 17, 11, 9, 8, 7, 12, 15, 8, 6], emphasis: [{ column: 3, kind: 'severity' }] }]
        : [{ type: 'callout', tone: 'neutral', title: 'No recorded remediation priorities', text: 'Review assets without measurements and components requiring classification.' }],
    })
    const workRows = byRisk.filter((row) => row.components.vulnerable + row.components.unclassified > 0)
    sections.push({
      id: 'worklists',
      title: 'Asset Worklists',
      intro: `${plural(workRows.length, 'asset')} with components that require remediation or classification.`,
      blocks: workRows.length
        ? workRows.map((row) => ({ type: 'dossier' as const, dossier: dossierFor(row, 'remediation') }))
        : [{ type: 'paragraph', text: 'No asset in scope has components that require remediation.', tone: 'muted' }],
      pageBreak: true,
    })
    sections.push({
      id: 'freshness',
      title: 'Evidence Freshness',
      intro: `Re-scan assets older than ${STALE_AFTER_HOURS} hours before approving changes.`,
      blocks: [{
        type: 'table',
        table: {
          title: 'Evidence freshness',
          columns: ['Asset', 'Last scanned (UTC)', 'Age', 'Freshness', 'Owner'],
          rows: [...rows].sort((a, b) => (a.lastScannedMs || 0) - (b.lastScannedMs || 0)).map((row) => [row.name, utcStamp(row.lastScanned), row.freshness.label, labelFreshness(row.freshness.state), ownerText(row)]),
        },
        widths: [30, 22, 14, 18, 16],
        emphasis: [{ column: 3, kind: 'status' }],
      }],
    })
    const ready = byRisk.filter((row) => row.pqcStatus === 'pqc-ready')
    sections.push({
      id: 'ready',
      title: 'PQC-Ready Assets',
      blocks: ready.length
        ? [{ type: 'table', table: { title: 'Scanner-validated PQC-ready assets', columns: ['Asset', 'Components', 'Last scanned (UTC)', 'Owner'], rows: ready.map((row) => [row.name, row.components.total, utcStamp(row.lastScanned), ownerText(row)]) }, widths: [40, 15, 25, 20] }]
        : [{ type: 'paragraph', text: 'No asset in scope is PQC-ready yet: readiness requires every measured component to be classified quantum-safe.', tone: 'muted' }],
    })
  }

  const checks = validate(rows, t, register, exposures, sections, scope)
  if (input.provenance) {
    for (const { source, status, detail } of input.provenance.dataCompleteness) {
      checks.push({ check: source, status: status === 'available' ? 'pass' : 'warn', detail })
    }
  }
  const validation = validationScore(checks)
  const snapshot: ReportProvenance | undefined = input.provenance && {
    ...input.provenance,
    validationStatus: validation.status === 'pass' ? 'validated' : 'incomplete',
  }
  const snapshotFacts = snapshot ? [
    { label: 'Report ID', value: reportId },
    { label: 'Organization ID', value: snapshot.organizationId ?? 'Unavailable' },
    { label: 'Workspace owner ID', value: snapshot.workspaceOwnerId },
    { label: 'Snapshot timestamp', value: snapshot.snapshotAt },
    { label: 'Asset inventory version (SHA3-256)', value: snapshot.assetInventoryVersion ?? 'Unavailable' },
    { label: 'CBOM version (SHA3-256)', value: snapshot.cbomVersion ?? 'Unavailable' },
    { label: 'Assessment ID', value: snapshot.assessmentId ?? 'Unavailable' },
    { label: 'Validation status', value: snapshot.validationStatus === 'validated' ? 'Validated' : 'Incomplete' },
  ] : []
  const snapshotTables: ReportTable[] = snapshot ? [
    { title: 'Snapshot provenance', columns: ['Field', 'Value'], rows: snapshotFacts.map(({ label, value }) => [label, value]) },
    { title: 'Source completeness', columns: ['Source', 'Status', 'Detail'], rows: snapshot.dataCompleteness.map(({ source, status, detail }) => [source, status, detail]) },
  ] : []
  if (snapshot) sections.push({
    id: 'snapshot-provenance', title: 'Snapshot Provenance',
    intro: 'Source versions identify the authenticated workspace inventory that was read when the report was generated.',
    blocks: snapshotTables.map((table) => ({ type: 'table', table })),
  })

  const scopeLine = scope.type === 'all'
    ? `Full estate — all ${plural(t.assets, 'asset')}`
    : `${plural(t.assets, 'asset')} of ${register.rows.length} (${scope.description})`

  const document: ReportDocument = {
    branding,
    template: { key: spec.key, name: spec.name, audience: spec.audience },
    cover: {
      eyebrow: 'Asset & CBOM Assessment',
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
        { label: 'Assessment scope', value: scopeLine },
        { label: 'Evidence as of', value: utcStamp(t.latestScan) },
      ],
    },
    summary,
    sections,
    decisions,
    validation,
    provenance: [
      'Every figure derives from authorized scans of the tenant estate, read through the same asset register the dashboard renders. No value is simulated, sampled or projected.',
      'Components are counted with the CBOM Explorer\'s grouping and predicate; per-asset totals reconcile to the CBOM headline (see Reconciliation).',
      'Scanner risk and the Quantum Readiness Engine score are different measurements of different populations; both are labelled with their source.',
      ...(branding.customNotes ? [branding.customNotes] : []),
    ],
  }

  const kpis: InventoryKpi[] = summary.highlights.map((h) => ({ label: h.label, value: h.value, detail: h.detail }))

  const reconciliation: ReconciliationRow[] = []
  const addRecon = (metric: string, dashboard: number, exported: number) => reconciliation.push({ metric, dashboard: String(dashboard), exported: String(exported), matches: dashboard === exported })
  const registerRows = assetRegisterTable(byRisk)
  const cbomRows = cbomTable(byRisk)
  addRecon('Assets in scope (dashboard selection) = asset register rows', t.assets, registerRows.rows.length)
  addRecon('Components in scope = CBOM rows exported', t.components.total, cbomRows.rows.length)
  addRecon('Quantum-vulnerable components = vulnerable CBOM rows', t.components.vulnerable, cbomRows.rows.filter((r) => r[6] === 'Quantum-vulnerable').length)
  addRecon('PQC-ready components = PQC-ready CBOM rows', t.components.pqcReady, cbomRows.rows.filter((r) => r[6] === 'PQC-ready').length)
  if (scope.type === 'all') {
    addRecon('Assets = scanner headline', register.headline.totalAssets, t.assets)
    addRecon('Components (+ unattributed) = CBOM headline', register.headline.totalComponents, t.components.total + register.unattributed.components)
    addRecon('Quantum-vulnerable (+ unattributed) = CBOM headline', register.headline.vulnerableComponents, t.components.vulnerable + register.unattributed.vulnerable)
    const qr = register.qrFigures
    if (qr && qr.hasData && qr.components !== null) {
      addRecon('Components = Quantum Readiness Engine', qr.components, t.components.total + register.unattributed.components)
      if (qr.vulnerableComponents !== null) addRecon('Quantum-vulnerable = Quantum Readiness Engine', qr.vulnerableComponents, t.components.vulnerable + register.unattributed.vulnerable)
    }
  }

  const tables: ReportTable[] = [
    ...snapshotTables,
    registerRows,
    cbomRows,
    postureFindingsTable(byRisk),
    exposuresTable(exposures),
    { title: 'Decision Register', columns: ['Priority', 'Decision', 'Rationale', 'Evidence', 'Owner'], rows: decisions.map((d) => [d.priority, d.decision, d.rationale, d.evidence, d.owner]) },
    { title: 'Report Validation', columns: ['Check', 'Result', 'Detail'], rows: checks.map((c) => [c.check, c.status.toUpperCase(), c.detail]) },
  ]

  const report: InventoryReport = {
    meta: {
      kind: 'assets',
      title: spec.name,
      subtitle: `Asset & CBOM assessment — ${scopeLine}`,
      generatedAt,
      companyName: branding.companyName || 'QGuard Helix',
      classification: branding.classification || 'CONFIDENTIAL',
      scopeNote: scope.type === 'all' ? `Complete asset register — all ${plural(t.assets, 'asset')}.` : `Scoped report — ${scopeLine}.`,
      provenance: 'Source: QGuard Helix authorized scanner intelligence (assets, crypto_inventory, pqc_scan_results, crypto_exposures), rendered through the shared asset register.',
      filenameSlug: `asset-${template}-report`,
      reportId,
      version: branding.reportVersion || '1.0',
      generatedBy,
      dataAsOf: t.latestScan,
      snapshot,
    },
    kpis,
    tables,
    reconciliation,
    notes: document.provenance,
    document,
  }

  // Seal last, over everything a reader can see. The seal is excluded wherever
  // it appears (top level AND the document copy), so the digest can be
  // recomputed from the exported JSON by anyone: see `canonicalAssetReport`.
  const canonical = canonicalAssetReport(report)
  report.integrity = input.provenance
    ? { algorithm: 'SHA3-256', hash: sha3Hex(canonical), signedAt: generatedAt, verificationToken: '' }
    : sealDocument(canonical, { reportId, kind: 'asset-inventory' })
  report.document!.integrity = report.integrity
  return report
}

/** The exact string the integrity digest is computed over. */
export function canonicalAssetReport(report: InventoryReport): string {
  return JSON.stringify(report, (key, value) => {
    if (key === 'integrity') return undefined
    if (!report.meta.snapshot || value === null || typeof value !== 'object' || Array.isArray(value)) return value
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0))
  })
}

/** Tone helper for renderers that colour a PQC status or severity word. */
export function statusTone(label: string): BlockTone {
  return toneForLabel(label)
}
