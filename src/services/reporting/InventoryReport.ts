/**
 * Asset & CBOM inventory export model — one document model, four renderers.
 *
 * Pure and dependency-free so the builder can be exercised offline by
 * `tools/inventory-export-check.ts` and cannot drift from what the dashboards
 * render.
 *
 * ── Why this is separate from EnterpriseAssessmentReport ────────────────────
 * The assessment report is an *opinion* about an estate: scores, roadmap, risk
 * narrative, certification. An inventory export is a *register*: every asset and
 * every cryptographic component, with the evidence that produced it. Forcing the
 * register into the assessment schema would either drop columns or invent
 * sections, so this defines its own minimal model — but it reuses the SAME
 * `ReportTable` primitive the assessment exporters consume, so table rendering
 * stays one implementation.
 *
 * ── The accuracy contract ───────────────────────────────────────────────────
 * The builder is handed the exact arrays the page is rendering (already
 * filtered / selected) plus the snapshot summary the page's KPI cards read. It
 * never re-queries and never recomputes a headline: an export that disagrees
 * with the screen it was launched from is worse than no export. Every document
 * carries a Reconciliation table stating dashboard value vs exported row count
 * so a reader can verify the match without trusting us.
 */
import type { ReportTable } from './schemas/ReportSchema'
import type { ReportDocument } from './ReportDocument'
import type { IntegritySeal } from './ReportIntegrity'
import { isCryptographicComponent as isCanonicalCryptographicComponent } from '@/lib/scanner/finding-identity'
import { algorithmFamily } from '@/lib/governance/subjects'

/**
 * Document kinds that share this model and the exporters behind it. The
 * exporters are format renderers, not inventory-specific, so any surface that
 * can express itself as KPIs + tables + a reconciliation block gets PDF,
 * Excel, Word, HTML, CSV and JSON for free rather than growing a second
 * export stack.
 */
export type InventoryReportKind = 'assets' | 'cbom' | 'migration' | 'exposure'

export interface InventoryKpi {
  label: string
  value: string
  detail?: string
}

export interface ReconciliationRow {
  metric: string
  dashboard: string
  exported: string
  matches: boolean
}

export interface InventoryReport {
  meta: {
    kind: InventoryReportKind
    title: string
    subtitle: string
    generatedAt: string
    companyName: string
    classification: string
    scopeNote: string
    /** Where every figure came from, printed in the document. */
    provenance: string
    /** Filename stem for the exported file. Defaults per kind. */
    filenameSlug?: string
    /** Stable document id (printed on the cover and in the integrity seal). */
    reportId?: string
    version?: string
    generatedBy?: string
    /** Newest scan evidence the document describes — "data as of". */
    dataAsOf?: string | null
  }
  kpis: InventoryKpi[]
  tables: ReportTable[]
  reconciliation: ReconciliationRow[]
  notes: string[]
  /**
   * Premium enterprise document. When present the exporters render the full
   * report layout (cover, contents, executive summary, sections, decisions,
   * validation, integrity); when absent they render the register layout the
   * CBOM, QKMS and Live Migration exports have always used.
   */
  document?: ReportDocument
  /** SHA3-256 seal over the canonical document (see ReportIntegrity.ts). */
  integrity?: IntegritySeal
}

/* ------------------------------------------------------------------ */
/* Inputs — deliberately loose: these are the page's own row objects   */
/* ------------------------------------------------------------------ */

export interface InventorySummary {
  totalAssets: number
  totalComponents: number
  vulnerableAssets: number
  vulnerableComponents: number
  pqcReadyComponents: number
  criticalFindings: number
  totalFindings: number
  riskScore: number
  qScore: number
}

export interface AssetRow {
  id?: unknown
  name?: unknown
  type?: unknown
  domain?: unknown
  url?: unknown
  ipAddress?: unknown
  riskLevel?: unknown
  riskScore?: unknown
  qScore?: unknown
  complianceStatus?: unknown
  status?: unknown
  lastScanned?: unknown
  findingsCount?: unknown
  vulnerableCount?: unknown
  cryptography?: unknown
  vulnerabilities?: unknown
}

export interface CbomRow {
  id?: unknown
  component?: unknown
  type?: unknown
  algorithm?: unknown
  keySize?: unknown
  status?: unknown
  isVulnerable?: unknown
  isQuantumSafe?: unknown
  pqcReplacement?: unknown
  instances?: unknown
  sourceAsset?: unknown
  /** Asset id the component was observed on — used to scope an asset export. */
  sourceAssetId?: unknown
  detectionMethod?: unknown
  lastScannedDate?: unknown
  riskSeverity?: unknown
  evidence?: unknown
  recommendation?: unknown
}

export interface InventoryBuildInput {
  kind: InventoryReportKind
  summary: InventorySummary
  /** Rows exactly as the dashboard is showing them (post-filter / selection). */
  assets: AssetRow[]
  cbom: CbomRow[]
  /** Total rows before the user's filter, so the scope note is honest. */
  totalAssetsBeforeFilter: number
  totalCbomBeforeFilter: number
  companyName?: string
  classification?: string
  generatedAt?: string
  lastScanAt?: string | null
  /** True when the user exported a filtered / selected subset. */
  filtered?: boolean
  filterDescription?: string
}

const text = (value: unknown, fallback = '—'): string => {
  if (value === null || value === undefined) return fallback
  const s = String(value).trim()
  return s === '' ? fallback : s
}
const num = (value: unknown): number => {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
const yesNo = (value: unknown): string => (value === true ? 'Yes' : value === false ? 'No' : '—')
const dateLabel = (value: unknown): string => {
  const s = text(value, '')
  if (!s) return '—'
  const t = Date.parse(s)
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : s
}

/**
 * Rows that record POSTURE (a scanner finding such as "Rule (Certificate Risk):
 * No OCSP Stapling") are tabled separately from cryptographic components — the
 * same split the CBOM Explorer and the API apply, so the export cannot
 * contradict them.
 *
 * Delegates to the ONE canonical predicate (`finding-identity.ts`). This module
 * used to keep its own class-prefix list, which had drifted: it missed agent
 * rows (`key_exchange: X25519` — underscore) and the "Web Crypto
 * (Post-Quantum)" library class, so real components were exported under
 * "Configuration & Policy Observations" while the dashboard counted them.
 */
export function isCryptographicComponent(row: CbomRow): boolean {
  return isCanonicalCryptographicComponent(
    { name: row.component, algorithm: row.algorithm, item_type: row.type },
    algorithmFamily,
  )
}

/* ------------------------------------------------------------------ */
/* Builder                                                             */
/* ------------------------------------------------------------------ */

export function buildInventoryReport(input: InventoryBuildInput): InventoryReport {
  const generatedAt = input.generatedAt || new Date().toISOString()
  const companyName = input.companyName || 'QGuard Helix'
  const classification = input.classification || 'Confidential'
  const isAssets = input.kind === 'assets'

  const cryptoRows = input.cbom.filter(isCryptographicComponent)
  const postureRows = input.cbom.filter((row) => !isCryptographicComponent(row))

  const scopeNote = input.filtered
    ? `Filtered view — ${isAssets ? `${input.assets.length} of ${input.totalAssetsBeforeFilter} asset(s)` : `${input.cbom.length} of ${input.totalCbomBeforeFilter} component(s)`} exported${input.filterDescription ? ` (${input.filterDescription})` : ''}.`
    : isAssets
      ? `Complete asset register — all ${input.assets.length} discovered asset(s).`
      : `Complete cryptographic bill of materials — all ${input.cbom.length} component(s).`

  /* ---- KPIs: read from the snapshot the dashboard cards read ---- */
  const kpis: InventoryKpi[] = isAssets
    ? [
        { label: 'Assets Discovered', value: String(input.summary.totalAssets) },
        { label: 'Assets With Exposure', value: String(input.summary.vulnerableAssets), detail: 'Quantum-vulnerable' },
        { label: 'Crypto Components', value: String(input.summary.totalComponents) },
        { label: 'Critical Findings', value: String(input.summary.criticalFindings) },
        { label: 'Posture Score', value: `${input.summary.qScore}/100`, detail: `Risk ${input.summary.riskScore}/100` },
      ]
    : [
        { label: 'Crypto Components', value: String(input.summary.totalComponents) },
        { label: 'PQC-Ready', value: String(input.summary.pqcReadyComponents), detail: pct(input.summary.pqcReadyComponents, input.summary.totalComponents) },
        { label: 'Quantum-Vulnerable', value: String(input.summary.vulnerableComponents), detail: pct(input.summary.vulnerableComponents, input.summary.totalComponents) },
        { label: 'Critical Findings', value: String(input.summary.criticalFindings) },
        { label: 'Source Assets', value: String(input.summary.totalAssets) },
      ]

  /* ---- Tables ---- */
  const tables: ReportTable[] = []

  if (isAssets) {
    tables.push({
      title: 'Asset Inventory',
      columns: ['Asset', 'Type', 'Endpoint', 'Risk Level', 'Risk', 'Q-Score', 'Compliance', 'Status', 'Components', 'Vulnerable', 'Findings', 'Last Scanned'],
      rows: input.assets.map((asset) => [
        text(asset.name),
        text(asset.type),
        text(asset.url ?? asset.domain ?? asset.ipAddress),
        text(asset.riskLevel),
        String(num(asset.riskScore)),
        String(num(asset.qScore)),
        text(asset.complianceStatus),
        text(asset.status),
        String(Array.isArray(asset.cryptography) ? asset.cryptography.length : 0),
        String(num(asset.vulnerableCount)),
        String(num(asset.findingsCount)),
        dateLabel(asset.lastScanned),
      ]),
    })

    // Per-asset cryptography, so the register is auditable to the algorithm.
    const cryptoByAsset: string[][] = []
    for (const asset of input.assets) {
      const algorithms = Array.isArray(asset.cryptography) ? (asset.cryptography as unknown[]) : []
      for (const algorithm of algorithms) {
        cryptoByAsset.push([text(asset.name), text(algorithm), text(asset.riskLevel), dateLabel(asset.lastScanned)])
      }
    }
    if (cryptoByAsset.length) {
      tables.push({
        title: 'Cryptography Observed Per Asset',
        columns: ['Asset', 'Algorithm / Observation', 'Asset Risk Level', 'Last Scanned'],
        rows: cryptoByAsset,
      })
    }
  }

  if (cryptoRows.length) {
    tables.push({
      title: isAssets ? 'Cryptographic Components (CBOM)' : 'Cryptographic Bill of Materials',
      columns: ['Component', 'Type', 'Algorithm', 'Key Size', 'Status', 'Vulnerable', 'PQC-Ready', 'Instances', 'Source Asset', 'Detection', 'PQC Replacement', 'Last Scanned'],
      rows: cryptoRows.map((row) => [
        text(row.component),
        text(row.type),
        text(row.algorithm),
        text(row.keySize),
        text(row.status),
        yesNo(row.isVulnerable),
        yesNo(row.isQuantumSafe),
        String(num(row.instances) || 1),
        text(row.sourceAsset),
        text(row.detectionMethod),
        text(row.pqcReplacement),
        dateLabel(row.lastScannedDate),
      ]),
    })

    // Algorithm rollup — instance-weighted, mirroring the on-screen chart.
    const rollup = new Map<string, { components: number; instances: number; vulnerable: number; pqcReady: number }>()
    for (const row of cryptoRows) {
      const key = text(row.algorithm, 'Unspecified')
      const entry = rollup.get(key) || { components: 0, instances: 0, vulnerable: 0, pqcReady: 0 }
      entry.components += 1
      entry.instances += num(row.instances) || 1
      if (row.isVulnerable === true) entry.vulnerable += 1
      if (row.isQuantumSafe === true) entry.pqcReady += 1
      rollup.set(key, entry)
    }
    tables.push({
      title: 'Algorithm Summary',
      columns: ['Algorithm', 'Components', 'Instances', 'Quantum-Vulnerable', 'PQC-Ready'],
      rows: Array.from(rollup.entries())
        .sort((a, b) => b[1].instances - a[1].instances)
        .map(([algorithm, entry]) => [algorithm, String(entry.components), String(entry.instances), String(entry.vulnerable), String(entry.pqcReady)]),
    })
  }

  if (postureRows.length) {
    // Kept, but never mixed into the algorithm tables: these record posture.
    tables.push({
      title: 'Configuration & Policy Observations',
      columns: ['Observation', 'Type', 'Severity', 'Instances', 'Source Asset', 'Recommendation'],
      rows: postureRows.map((row) => [
        text(row.component),
        text(row.type),
        text(row.riskSeverity),
        String(num(row.instances) || 1),
        text(row.sourceAsset),
        text(row.recommendation),
      ]),
    })
  }

  /* ---- Reconciliation: prove the export matches the screen ---- */
  const reconciliation: ReconciliationRow[] = []
  const addRecon = (metric: string, dashboard: number, exported: number) =>
    reconciliation.push({ metric, dashboard: String(dashboard), exported: String(exported), matches: dashboard === exported })

  if (isAssets && !input.filtered) addRecon('Assets discovered', input.summary.totalAssets, input.assets.length)
  if (!input.filtered) {
    addRecon('Crypto components', input.summary.totalComponents, input.cbom.length)
    addRecon('Quantum-vulnerable components', input.summary.vulnerableComponents, input.cbom.filter((r) => r.isVulnerable === true).length)
    addRecon('PQC-ready components', input.summary.pqcReadyComponents, input.cbom.filter((r) => r.isQuantumSafe === true).length)
  }
  reconciliation.push({
    metric: 'Cryptographic vs posture rows',
    dashboard: `${cryptoRows.length} + ${postureRows.length}`,
    exported: String(input.cbom.length),
    matches: cryptoRows.length + postureRows.length === input.cbom.length,
  })

  const notes = [
    'Every row in this document originates from an authorized scan of the tenant estate. No value is simulated, sampled or projected.',
    'Configuration and policy observations are tabled separately from cryptographic components: they record posture, not an algorithm, and must not be counted on an algorithm axis.',
    input.lastScanAt ? `Most recent scan evidence: ${dateLabel(input.lastScanAt)}.` : 'No completed scan recorded for this tenant.',
    input.filtered
      ? 'This is a FILTERED export. Estate-wide reconciliation rows are omitted because the exported subset is intentionally smaller than the estate.'
      : 'Reconciliation compares dashboard KPI values against the exported row counts; every row must read MATCH.',
  ]

  return {
    meta: {
      kind: input.kind,
      title: isAssets ? 'Asset Inventory Report' : 'Cryptographic Bill of Materials (CBOM)',
      subtitle: isAssets
        ? 'Discovered assets, cryptographic exposure and scan evidence'
        : 'Cryptographic components, PQC readiness and detection evidence',
      generatedAt,
      companyName,
      classification,
      scopeNote,
      provenance:
        'Source: QGuard Helix authorized scanner intelligence (crypto_inventory, crypto_exposures, pqc_scan_results, certificates), reconciled with the Quantum Readiness Engine.',
    },
    kpis,
    tables,
    reconciliation,
    notes,
  }
}

function pct(part: number, total: number): string {
  if (!total) return '—'
  return `${Math.round((part / total) * 100)}% of ${total}`
}
