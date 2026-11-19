import type { buildScannerIntelligence, MergedScannerFinding } from './scanner'
import type { buildSnapshot } from './quantum-readiness'
import { GENERIC_FINDING_TEXT } from '@/lib/scanner/finding-identity'
import { READINESS_WEIGHTS, readinessPostureMeasured } from '@/lib/migration/asset-intelligence'
import {
  EVIDENCE_UNAVAILABLE,
  evidenceAssessmentReportSchema,
  type EvidenceAssessmentReport,
  type ReportBranding,
  type ReportKind,
  type ReportProvenance,
  type ReportTable,
} from '@/services/reporting/schemas/ReportSchema'

type ScannerSnapshot = Awaited<ReturnType<typeof buildScannerIntelligence>>
type Assessment = Awaited<ReturnType<typeof buildSnapshot>>
type Coverage = ReportProvenance['dataCompleteness']
type Kpi = EvidenceAssessmentReport['kpis'][number]

type ScannerAsset = {
  id: string
  name: string
  type: string | null
  environment: string | null
  registrationSource?: 'registered' | 'scanner-evidence'
  pqcStatus: string
  riskScore: number | null
  internetFacing: boolean
  lastScanned?: string | null
  lastScannedSource?: string
  status?: string | null
  tlsVersion?: string | null
  componentCount: number
}

type Component = {
  id: string
  sourceAssetId?: string | null
  component?: string
  type?: string
  algorithm?: string
  keySize?: number | null
  protocol?: string | null
  isVulnerable?: boolean
  isQuantumSafe?: boolean
  contradictoryFlags?: boolean
  lastScannedDate?: string | null
}

const TITLES: Record<ReportKind, string> = {
  executive: 'Executive Quantum Readiness Report',
  technical: 'Technical Quantum Readiness Report',
  compliance: 'Quantum Readiness and Compliance Evidence',
  migration: 'PQC Migration Evidence Report',
}

const SEVERITY_VALUES = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
} as const
type GradedSeverity = typeof SEVERITY_VALUES[keyof typeof SEVERITY_VALUES]

const FINDING_SOURCES = ['crypto_inventory', 'crypto_exposures', 'pqc_scan_results', 'pqc_scan_sessions', 'vulnerabilities']

class InvalidReportAssetScope extends Error {
  constructor() {
    super('The selected report scope no longer matches the active registered asset inventory. Refresh the asset list and select the scope again.')
    this.name = 'InvalidReportAssetScope'
  }
}
export { InvalidReportAssetScope }

function text(value: unknown) {
  if (typeof value !== 'string' || !value.trim()) return EVIDENCE_UNAVAILABLE
  // Omit URL credentials and parameters from exported asset names and scanner labels.
  return value.trim().replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, (url) => {
    try {
      const parsed = new URL(url)
      return `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`
    } catch {
      return '[URL omitted]'
    }
  })
}

function rowsById<T extends { id: string }>(rows: T[]): T[] {
  return [...new Map(rows.filter(({ id }) => Boolean(id)).map((row) => [row.id, row])).values()]
}

function scannerAssets(scanner: ScannerSnapshot) {
  return rowsById<ScannerAsset>(scanner.assets.assets)
}

function isRegistered(asset: ScannerAsset) {
  return asset.registrationSource === 'registered'
}

function posture(asset: ScannerAsset) {
  return asset.componentCount > 0 ? text(asset.pqcStatus) : 'Not measured'
}

function listRegisteredAssets(assets: ScannerAsset[]) {
  return assets.filter(isRegistered).map((asset) => ({
    key: asset.id,
    name: text(asset.name),
    assetType: text(asset.type),
    environment: text(asset.environment),
    posture: posture(asset),
    riskScore: asset.riskScore != null && Number.isFinite(asset.riskScore) ? asset.riskScore : null,
    internetFacing: asset.internetFacing === true,
  }))
}

export function listReportScopeAssets(scanner: ScannerSnapshot) {
  return listRegisteredAssets(scannerAssets(scanner))
}

function componentPosture(entry: Component) {
  if (entry.contradictoryFlags || (entry.isVulnerable && entry.isQuantumSafe)) return 'Conflicting source classifications'
  if (entry.isVulnerable) return 'Quantum-vulnerable'
  if (entry.isQuantumSafe) return 'PQC-ready (scanner-classified)'
  return 'Unclassified'
}

function sourceStatus(coverage: Coverage, sources: string[]): Coverage[number]['status'] {
  const entries = sources.map((source) => coverage.find((entry) => entry.source === source)?.status)
  if (entries.every((entry) => entry === 'available')) return 'available'
  if (entries.every((entry) => entry == null || entry === 'missing')) return 'missing'
  return 'partial'
}

function observedCount(value: number, status: Coverage[number]['status']) {
  if (status === 'available') return value
  if (value === 0) return EVIDENCE_UNAVAILABLE
  return `${value.toLocaleString('en-US')} observed · partial`
}

function findingSeverity(finding: MergedScannerFinding): GradedSeverity | undefined {
  return SEVERITY_VALUES[finding.threatLevel as keyof typeof SEVERITY_VALUES]
}

function addAssessment(
  assessment: Assessment | null,
  scanner: ScannerSnapshot,
  selectedIds: Set<string> | null,
  coverage: Coverage,
  kpis: Kpi[],
  tables: ReportTable[],
) {
  const assessmentCoverage = assessment?.reportReadCoverage ?? []
  const evidence = assessment?.reportEvidence
  const addCoverage = (source: string, status: Coverage[number]['status'], detail: string) => {
    coverage.push({ source, status, detail })
  }
  if (!assessment || !evidence) {
    addCoverage('Readiness assessment', 'missing', 'A fresh readiness evaluation could not be captured.')
    return
  }

  const certificateStatus = sourceStatus(assessmentCoverage, ['certificates'])
  const certificates = rowsById(evidence.certificates).filter(({ assetId }) => !selectedIds || selectedIds.has(assetId))
  kpis.push({ label: 'Certificate records', value: observedCount(certificates.length, certificateStatus), tone: 'neutral' })
  tables.push({
    title: 'Recorded certificates',
    columns: ['Certificate ID', 'Asset ID', 'Name', 'Signature algorithm', 'Key bits', 'Issuer', 'Expiry', 'Recorded status'],
    rows: certificates.map((row) => [
      row.id, text(row.assetId), text(row.name), text(row.algorithm), row.keySize ?? EVIDENCE_UNAVAILABLE,
      text(row.issuer), text(row.notAfter), text(row.status),
    ]),
  })
  const includedSources = new Set(['certificates', 'generated_keys', 'runtime_crypto_events', 'vault_files'])
  coverage.push(...assessmentCoverage
    .filter(({ source }) => includedSources.has(source) && (!selectedIds || source === 'certificates'))
    .map((entry) => ({ ...entry, source: `${entry.source} (assessment)` })))

  if (selectedIds) {
    addCoverage('Readiness assessment', 'missing', 'The platform’s readiness and HNDL scores are workspace-wide. No asset-scoped evaluation was recorded for this selection.')
    return
  }

  const keys = rowsById(evidence.keys)
  kpis.push({ label: 'Generated key records', value: observedCount(keys.length, sourceStatus(assessmentCoverage, ['generated_keys'])), tone: 'neutral' })
  tables.push({
    title: 'Generated key inventory',
    columns: ['Key record ID', 'Algorithm', 'Key bits', 'Recorded status'],
    rows: keys.map((row) => [row.id, text(row.algorithm), row.bitLength ?? EVIDENCE_UNAVAILABLE, text(row.status)]),
  })

  const reconcile = assessment.persistence === 'database'
    && assessment.inventory.cryptoComponents === scanner.summary.totalComponents
    && assessment.inventory.vulnerableComponents === scanner.summary.vulnerableComponents
    && assessment.inventory.pqcReadyComponents === scanner.summary.pqcReadyComponents
    && assessment.inventory.assetsAssessed === scanner.summary.totalAssets
    && Object.entries(assessment.riskDistribution).every(([severity, count]) =>
      count === scanner.severityCounts[severity as GradedSeverity])
  const measured = readinessPostureMeasured({ cryptoComponents: scanner.summary.totalComponents, findings: scanner.severityCounts })
  const sourceReadsComplete = sourceStatus(scanner.sourceCoverage ?? [], ['assets', ...FINDING_SOURCES]) === 'available'
  const readinessAvailable = reconcile && measured && sourceReadsComplete
    && sourceStatus(assessmentCoverage, ['assets', 'runtime_crypto_events']) === 'available'
  const hndlAvailable = readinessAvailable && sourceStatus(assessmentCoverage, ['vault_files']) === 'available'
  addCoverage(
    'Readiness assessment',
    readinessAvailable ? 'available' : measured ? 'partial' : 'missing',
    readinessAvailable ? 'Captured from the shared assessment calculation. Asset, CBOM and severity figures reconciled.'
      : measured ? 'The assessment inputs were incomplete or differed from the captured register, CBOM or severity counts. Scores are unavailable.'
        : 'No graded findings or cryptographic components supported a workspace posture score.',
  )
  addCoverage(
    'HNDL assessment',
    hndlAvailable ? 'available' : 'missing',
    hndlAvailable ? 'A modeled risk score based on the captured workspace evidence.'
      : 'A validated workspace assessment and complete vault and runtime reads are required for this score.',
  )
  kpis.push(
    { label: 'Quantum readiness score', value: readinessAvailable ? assessment.scores.quantumReadiness : 'Not measured', ...(readinessAvailable ? { unit: '/100', level: assessment.scores.quantumReadinessLevel } : {}), tone: 'neutral' },
    { label: 'Quantum risk score', value: readinessAvailable ? assessment.scores.quantumRisk : 'Not measured', ...(readinessAvailable ? { unit: '/100', level: assessment.scores.quantumRiskLevel } : {}), tone: 'neutral' },
    { label: 'Modeled HNDL risk score', value: hndlAvailable ? assessment.scores.hndlRisk : 'Not measured', ...(hndlAvailable ? { unit: '/100', level: assessment.scores.hndlRiskLevel } : {}), tone: 'neutral' },
  )
  if (readinessAvailable) {
    const runtimeMeasured = evidence.hndlBasis.runtimeEvents > 0
    const runtimeWeight = runtimeMeasured ? READINESS_WEIGHTS.runtimeVisibility : 0
    const denominator = READINESS_WEIGHTS.pqcAdoption + READINESS_WEIGHTS.riskPosture + runtimeWeight
    tables.push({
      title: 'Readiness and risk assessment basis',
      columns: ['Input', 'Reported value', 'Basis'],
      rows: [
        ['Latest assessment evidence timestamp', text(assessment.lastAssessmentAt), 'Newest recorded scan or runtime evidence'],
        ['Latest completed scan session', evidence.scanSessionId ?? EVIDENCE_UNAVAILABLE, 'pqc_scan_sessions record ID'],
        ['PQC adoption', `${assessment.scores.pqcAdoption}%`, `${(100 * READINESS_WEIGHTS.pqcAdoption / denominator).toFixed(1)}% of the readiness blend`],
        ['Quantum-risk score', `${assessment.scores.quantumRisk}/100`, '45% severity pressure, 40% vulnerable component share, 15% internet-facing asset share'],
        ['Inverse risk', `${100 - assessment.scores.quantumRisk}/100`, `${(100 * READINESS_WEIGHTS.riskPosture / denominator).toFixed(1)}% of the readiness blend`],
        ['Runtime evidence', runtimeMeasured ? evidence.hndlBasis.runtimeEvents : 'Not measured', runtimeMeasured ? `${(100 * runtimeWeight / denominator).toFixed(1)}% of the readiness blend` : 'Excluded from the readiness blend'],
      ],
    })
  }
  if (hndlAvailable) {
    const { runtimeEvents, hndlEvents, vaultFiles, classicalVaultFiles, internetFacing, assetCount } = evidence.hndlBasis
    const { vulnerableComponents, totalComponents } = scanner.summary
    tables.push({
      title: 'HNDL risk assessment basis',
      columns: ['Input', 'Flagged', 'Measured population', 'Model weight'],
      rows: [
        ['Quantum-vulnerable CBOM components', vulnerableComponents, totalComponents, '40%'],
        ['Runtime observations marked HNDL risk', hndlEvents, runtimeEvents, '25%'],
        ['Vault files without PQC-classified protection', classicalVaultFiles, vaultFiles, '20%'],
        ['Internet-facing assets', internetFacing, assetCount, '15%'],
      ],
    })
  }
}

export interface ReadinessReportInput {
  scanner: ScannerSnapshot
  assessment: Assessment | null
  assetIds: string[] | null
  branding: ReportBranding
  kind: ReportKind
  generatedBy: string
  provenance: ReportProvenance
  supplemental?: { tables: ReportTable[]; dataCompleteness: Coverage }
}

export function buildReadinessReportModel(input: ReadinessReportInput): EvidenceAssessmentReport {
  const { scanner, assessment, assetIds, branding, kind, generatedBy, provenance, supplemental } = input
  const allAssets = scannerAssets(scanner)
  const registry = listRegisteredAssets(allAssets)
  const registeredIds = new Set(registry.map(({ key }) => key))
  const selectedIds = assetIds === null ? null : new Set(assetIds)
  if (selectedIds && (!selectedIds.size || [...selectedIds].some((id) => !registeredIds.has(id)))) {
    throw new InvalidReportAssetScope()
  }
  const matchesScope = (id: string) => !selectedIds || selectedIds.has(id)
  const assets = allAssets.filter(({ id }) => matchesScope(id))
  const assetNames = new Map(assets.map((asset) => [asset.id, text(asset.name)]))
  const scopeAssets = registry.filter(({ key }) => matchesScope(key))
  const components = rowsById<Component>(scanner.cbom.entries).filter((entry) => !selectedIds || (!!entry.sourceAssetId && matchesScope(entry.sourceAssetId)))
  const inScope = (finding: MergedScannerFinding) => {
    if (!selectedIds) return true
    const ids = finding.assetIds ?? []
    return ids.length > 0 && ids.every(matchesScope)
  }
  const graded = scanner.findings.filter(findingSeverity)
  const reportFindings = graded.filter(inScope)
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  const findings = reportFindings.map((finding) => {
    const severity = findingSeverity(finding)!
    severityCounts[severity] += 1
    const links = (finding.assetIds ?? []).map((id) => assetNames.get(id)).filter((name): name is string => !!name)
    const ids = [...new Set(finding.evidenceIds ?? [])]
    const recommendation = text(finding.recommendation)
    return {
      id: finding.id,
      title: text(finding.algorithm || finding.category),
      severity,
      evidence: [`Recorded observation: ${text(finding.category)}`, `Location: ${text(finding.location)}`, `Method: ${text(finding.detectionMethod)}`, ids.length > 0 ? `Source record IDs: ${ids.join(', ')}` : 'Source row identifier unavailable'].join('\n'),
      affectedAssets: [...new Set(links)],
      recommendation: GENERIC_FINDING_TEXT.has(recommendation.toLowerCase()) ? EVIDENCE_UNAVAILABLE : recommendation,
      source: [...new Set(finding.sources?.length ? finding.sources : [finding.source])].map(text).join(', '),
      detectedAt: finding.detectedAt || finding.timestamp || null,
    }
  })
  const coverage: Coverage = [...(scanner.sourceCoverage ?? []), ...(provenance.dataCompleteness ?? []), ...(supplemental?.dataCompleteness ?? [])]
  const assetStatus = sourceStatus(coverage, ['assets'])
  const cbomStatus = sourceStatus(coverage, ['crypto_inventory'])
  let findingStatus = sourceStatus(coverage, FINDING_SOURCES)
  const excludedUnattributed = selectedIds && graded.some((finding) => {
    const ids = finding.assetIds ?? []
    return ids.length === 0 || (ids.some(matchesScope) && !ids.every(matchesScope))
  })
  if (excludedUnattributed) {
    findingStatus = findingStatus === 'missing' ? 'missing' : 'partial'
    coverage.push({ source: 'Scoped finding attribution', status: 'partial', detail: 'Excluded observations without a unique in-scope association. The reported count covers only attributable observations.' })
  }
  const vulnerableComponents = components.filter((entry) => componentPosture(entry) === 'Quantum-vulnerable').length
  const readyComponents = components.filter((entry) => componentPosture(entry) === 'PQC-ready (scanner-classified)').length
  const algorithms = new Map<string, number>()
  for (const component of components) {
    const key = text(component.algorithm)
    algorithms.set(key, (algorithms.get(key) ?? 0) + 1)
  }

  const kpis: Kpi[] = [
    { label: 'Registered assets', value: observedCount(scopeAssets.length, assetStatus), tone: 'neutral' },
    { label: 'Assets & CBOM register rows', value: observedCount(assets.length, assetStatus), tone: 'neutral' },
    { label: 'Cryptographic components', value: observedCount(components.length, cbomStatus), tone: 'neutral' },
    { label: 'Quantum-vulnerable components', value: observedCount(vulnerableComponents, cbomStatus), tone: vulnerableComponents ? 'high' : 'neutral' },
    { label: 'PQC-classified components', value: observedCount(readyComponents, cbomStatus), tone: 'neutral' },
    { label: 'Graded scanner observations', value: observedCount(findings.length, findingStatus), tone: 'neutral' },
  ]
  const tables: ReportTable[] = [
    {
      title: 'Assets & CBOM register',
      columns: ['Asset ID', 'Asset', 'Type', 'Registration', 'Status', 'Environment', 'Cryptographic posture', 'Observed TLS', 'Last scan'],
      rows: assets.map((asset) => [asset.id, text(asset.name), text(asset.type), isRegistered(asset) ? 'Registered' : 'Scanner evidence', text(asset.status), text(asset.environment), posture(asset), text(asset.tlsVersion), asset.lastScannedSource === 'asset-record' ? EVIDENCE_UNAVAILABLE : text(asset.lastScanned)]),
    },
    {
      title: 'CBOM algorithm distribution',
      columns: ['Recorded algorithm', 'Unique components'],
      rows: [...algorithms.entries()].sort(([a, aCount], [b, bCount]) => bCount - aCount || a.localeCompare(b)),
    },
    {
      title: 'Cryptographic bill of materials',
      columns: ['Component record ID', 'Asset ID', 'Asset', 'Component', 'Type', 'Algorithm', 'Key bits', 'Protocol', 'Posture', 'Last observed'],
      rows: components.map((entry) => [
        entry.id, text(entry.sourceAssetId), assetNames.get(entry.sourceAssetId ?? '') ?? EVIDENCE_UNAVAILABLE,
        text(entry.component), text(entry.type), text(entry.algorithm), entry.keySize ?? EVIDENCE_UNAVAILABLE,
        text(entry.protocol), componentPosture(entry), text(entry.lastScannedDate),
      ]),
    },
    {
      title: 'Finding severity distribution',
      columns: ['Severity', 'Observed findings'],
      rows: findingStatus === 'missing' && !findings.length ? [] : Object.entries(severityCounts),
    },
  ]

  addAssessment(assessment, scanner, selectedIds, coverage, kpis, tables)
  tables.push(...(supplemental?.tables ?? []))

  const countNarrative = (status: Coverage[number]['status'], count: number, noun: string) => status === 'available'
    ? `${count.toLocaleString('en-US')} ${noun}`
    : status === 'missing' && count === 0 ? `${noun} unavailable` : `${count.toLocaleString('en-US')} ${noun} observed (partial)`
  const executiveSummary = [
    `Captured ${countNarrative(assetStatus, scopeAssets.length, 'registered assets')}, ${countNarrative(cbomStatus, components.length, 'CBOM components')}, and ${countNarrative(findingStatus, findings.length, 'graded scanner observations')}.`,
    'Finding severity is the scanner’s grade for the recorded observation. Current migration and validation status comes from execution records when available.',
  ].join(' ')
  const dataCompleteness = [...new Map(coverage.map((entry) => [entry.source, entry])).values()]
  const validationStatus = provenance.validationStatus === 'validated' && dataCompleteness.length > 0
    && dataCompleteness.every((entry) => entry.status === 'available') ? 'validated' : 'incomplete'

  return evidenceAssessmentReportSchema.parse({
    meta: {
      id: provenance.reportId,
      kind,
      title: TITLES[kind],
      generatedAt: provenance.snapshotAt,
      generatedBy,
      version: branding.reportVersion,
      tenantScoped: true,
      sourceGeneratedAt: scanner.generatedAt,
    },
    scope: {
      type: selectedIds ? 'custom' : 'full',
      selectedAssetCount: scopeAssets.length,
      totalAssetCount: registry.length,
      assets: scopeAssets,
      note: selectedIds ? 'Selected registered assets' : 'Full workspace assessment',
      methodology: selectedIds
        ? 'CBOM components, certificates and findings require source associations to the selected asset IDs. Workspace scores are omitted for custom scope.'
        : 'Registered assets exclude archived, deleted, and scanner-evidence-only identities. The Assets & CBOM register and CBOM retain scanner evidence attributed to the workspace.',
    },
    branding,
    executiveSummary,
    kpis,
    findings,
    tables,
    provenance: { ...provenance, validationStatus, dataCompleteness },
  })
}
