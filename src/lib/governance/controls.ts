/**
 * Control evaluation engine.
 *
 * Each control in the catalog is scored against the tenant's real evidence.
 * There is exactly one rule for every evaluator here:
 *
 *   If the population is empty, the control is NOT ASSESSED.
 *
 * It is never "compliant" (nothing broken) and never "non-compliant" (nothing
 * proven). That single discipline is what stops a tenant with no certificates
 * from reading as certificate-compliant, and a tenant with no runtime collector
 * from reading as a runtime failure.
 *
 * Where a control restates something the platform already computes — quantum
 * risk, PQC adoption, vulnerable components — the value is taken from the
 * canonical Quantum Readiness snapshot rather than recomputed, so Compliance
 * cannot publish a different number from Quantum Readiness for the same fact.
 */

import { CONTROL_CATALOG, FRAMEWORKS_BY_CONTROL, REQUIREMENTS_BY_CONTROL } from './catalog'
import { looksLikeFailure } from './audit'
import { severityOrder } from './policy'
import {
  ALGORITHM_FAMILY_LABEL,
  assetIsInternetFacing,
  clampPercent,
  daysBetween,
  ms,
  newest,
  num,
  recordOf,
  str,
  type CryptoSubject,
  type Row,
  type SubjectSet,
} from './subjects'
import { freshnessOf } from './evidence'
import type {
  ControlDefinition,
  ControlException,
  ControlRecord,
  ControlStatus,
  ControlSubject,
  EvidenceRecord,
  GovernanceSeverity,
  PolicyRecord,
} from './types'

/* ------------------------------------------------------------------ */
/* Canonical snapshot surface the engine depends on                     */
/* ------------------------------------------------------------------ */

/**
 * The subset of the Quantum Readiness snapshot governance reads.
 *
 * Declared structurally so this module stays isomorphic and testable offline —
 * the server passes the real snapshot, a test passes a literal.
 */
export interface CanonicalSnapshot {
  hasData: boolean
  scores: {
    quantumReadiness: number
    quantumRisk: number
    pqcAdoption: number
  }
  inventory: {
    assetsAssessed: number
    certificatesAnalyzed: number
    keysDiscovered: number
    cryptoComponents: number
    vulnerableComponents: number
    pqcReadyComponents: number
    quantumVulnerableAssets: number
    pqcReadyAssets: number
    hybridAssets: number
  }
  riskDistribution: { critical: number; high: number; medium: number; low: number }
  telemetry: { latestRuntimeEventAt: string | null; latestEventAt: string | null }
}

export interface ControlEvaluationInputs {
  now: number
  snapshot: CanonicalSnapshot
  subjects: SubjectSet
  policies: PolicyRecord[]
  evidence: EvidenceRecord[]
  assets: Row[]
  scanSessions: Row[]
  scanResults: Row[]
  vulnerabilities: Row[]
  scannerAlerts: Row[]
  cryptoExposures: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  agentHeartbeats: Row[]
  migrationJobs: Row[]
  migrationPlans: Row[]
  auditLogs: Row[]
  vaultAuditLogs: Row[]
  securityEvents: Row[]
  authEvents: Row[]
  complianceEvidence: Row[]
  /** Rows from governance_control_assessments — owner/exception overrides. */
  assessments: Row[] | null
  /** True when the evidence-anchor store answered. */
  anchoringAvailable: boolean
}

/* ------------------------------------------------------------------ */
/* Evaluation result                                                   */
/* ------------------------------------------------------------------ */

interface Evaluation {
  measured: boolean
  /** In-scope subjects. 0 with measured=true is only valid for tenant-level controls. */
  population: number
  satisfied: number
  failing: ControlSubject[]
  passing: ControlSubject[]
  /** Overrides the population-derived score when a control is scalar. */
  scoreOverride?: number | null
  basis: string
  lastValidatedAt: string | null
  /** Escalates severity beyond the population-derived default. */
  severityFloor?: GovernanceSeverity
}

const SAMPLE = 10

function subjectFrom(subject: CryptoSubject, pass: boolean, reason: string, severity: GovernanceSeverity | null): ControlSubject {
  return {
    id: subject.id,
    label: subject.label,
    type: subject.kind,
    pass,
    reason,
    assetId: subject.assetId,
    severity,
    href: subject.href,
    source: subject.source,
    observedAt: subject.observedAt,
  }
}

function rowSubject(input: {
  id: string
  label: string
  type: string
  pass: boolean
  reason: string
  assetId?: string | null
  severity?: GovernanceSeverity | null
  href?: string | null
  table: string
  recordId: string
  observedAt?: string | null
}): ControlSubject {
  return {
    id: input.id,
    label: input.label,
    type: input.type,
    pass: input.pass,
    reason: input.reason,
    assetId: input.assetId ?? null,
    severity: input.severity ?? null,
    href: input.href ?? null,
    source: { table: input.table, recordId: input.recordId },
    observedAt: input.observedAt ?? null,
  }
}

function unmeasured(basis: string): Evaluation {
  return { measured: false, population: 0, satisfied: 0, failing: [], passing: [], basis, lastValidatedAt: null }
}

/** Splits a subject list into pass/fail with a shared reason builder. */
function partition(
  subjects: CryptoSubject[],
  test: (subject: CryptoSubject) => { pass: boolean; reason: string; severity?: GovernanceSeverity },
): { failing: ControlSubject[]; passing: ControlSubject[]; satisfied: number } {
  const failing: ControlSubject[] = []
  const passing: ControlSubject[] = []
  for (const subject of subjects) {
    const result = test(subject)
    const record = subjectFrom(subject, result.pass, result.reason, result.pass ? null : result.severity ?? 'medium')
    if (result.pass) passing.push(record)
    else failing.push(record)
  }
  return { failing, passing, satisfied: passing.length }
}

/** Turns policy-engine violations into control subjects, keeping one producer. */
function fromPolicies(
  policies: PolicyRecord[],
  policyIds: string[],
  populationLabel: string,
): Evaluation {
  const scoped = policies.filter((policy) => policyIds.includes(policy.id))
  const measurable = scoped.filter((policy) => policy.measured)
  if (!measurable.length) {
    const disabled = scoped.filter((policy) => policy.enforcement === 'disabled')
    return unmeasured(
      disabled.length === scoped.length && scoped.length > 0
        ? `Every governing policy rule is disabled, so no ${populationLabel} is evaluated.`
        : `No ${populationLabel} with the evidence this control needs has been discovered yet.`,
    )
  }
  const population = measurable.reduce((sum, policy) => sum + policy.evaluated, 0)
  const failing: ControlSubject[] = []
  for (const policy of measurable) {
    for (const item of policy.violationSample) {
      failing.push({
        id: item.id,
        label: item.subject,
        type: item.subjectType,
        pass: false,
        reason: `${item.observed} — expected ${item.expected}`,
        assetId: item.assetId,
        severity: item.severity,
        href: item.href,
        source: item.source,
        observedAt: item.detectedAt,
      })
    }
  }
  const violations = measurable.reduce((sum, policy) => sum + policy.violations, 0)
  const satisfied = Math.max(0, population - violations)
  const worstSeverity = measurable.reduce<GovernanceSeverity>(
    (worst, policy) => (policy.violations > 0 && severityOrder(policy.severity) > severityOrder(worst) ? policy.severity : worst),
    'low',
  )
  return {
    measured: true,
    population,
    satisfied,
    failing,
    passing: [],
    basis: measurable.map((policy) => policy.basis).join(' '),
    lastValidatedAt: newest(...measurable.map((policy) => policy.lastEvaluatedAt)),
    severityFloor: violations > 0 ? worstSeverity : undefined,
  }
}

/* ------------------------------------------------------------------ */
/* Evaluators                                                          */
/* ------------------------------------------------------------------ */

type Evaluator = (inputs: ControlEvaluationInputs) => Evaluation

const EVALUATORS: Record<string, Evaluator> = {
  /* ---- Inventory -------------------------------------------------- */
  assetCryptoCoverage(inputs) {
    const assets = inputs.assets.filter((asset) => str(asset.status).toLowerCase() !== 'archived')
    if (!assets.length) return unmeasured('No assets have been discovered for this tenant yet.')
    const covered = new Set<string>()
    for (const subject of inputs.subjects.all) if (subject.assetId) covered.add(subject.assetId)
    for (const row of inputs.scanResults) if (str(row.asset_id)) covered.add(str(row.asset_id))
    for (const row of inputs.cryptoExposures) if (str(row.asset_id)) covered.add(str(row.asset_id))

    const failing: ControlSubject[] = []
    const passing: ControlSubject[] = []
    for (const asset of assets) {
      const id = str(asset.id)
      const pass = covered.has(id)
      const record = rowSubject({
        id: `asset:${id}`,
        label: str(asset.name) || 'Asset',
        type: str(asset.type) || 'asset',
        pass,
        reason: pass ? 'Cryptographic evidence is bound to this asset.' : 'No cryptographic component, certificate, finding or runtime observation is bound to this asset.',
        assetId: id,
        severity: pass ? null : 'medium',
        href: '/dashboard/assets',
        table: 'assets',
        recordId: id,
        observedAt: str(asset.updated_at) || str(asset.created_at) || null,
      })
      if (pass) passing.push(record)
      else failing.push(record)
    }
    return {
      measured: true,
      population: assets.length,
      satisfied: passing.length,
      failing,
      passing,
      basis: `${passing.length} of ${assets.length} active asset(s) carry cryptographic evidence.`,
      lastValidatedAt: newest(...assets.map((asset) => asset.updated_at)),
    }
  },

  cbomAlgorithmIdentification(inputs) {
    const components = inputs.subjects.components
    if (!components.length) return unmeasured('No cryptographic components have been inventoried yet.')
    const { failing, passing, satisfied } = partition(components, (subject) => {
      const classified = subject.family !== 'unknown' && Boolean(subject.algorithm)
      return {
        pass: classified,
        reason: classified
          ? `Classified as ${ALGORITHM_FAMILY_LABEL[subject.family]}.`
          : subject.algorithm
            ? `Algorithm "${subject.algorithm}" could not be classified.`
            : 'No algorithm recorded on this component.',
        severity: 'medium' as GovernanceSeverity,
      }
    })
    return {
      measured: true,
      population: components.length,
      satisfied,
      failing,
      passing,
      basis: `${satisfied} of ${components.length} inventoried component(s) resolve to a known algorithm family.`,
      lastValidatedAt: newest(...components.map((subject) => subject.observedAt)),
    }
  },

  assetOwnership(inputs) {
    const assets = inputs.assets.filter((asset) => str(asset.status).toLowerCase() !== 'archived')
    if (!assets.length) return unmeasured('No assets have been discovered for this tenant yet.')
    const failing: ControlSubject[] = []
    const passing: ControlSubject[] = []
    for (const asset of assets) {
      const metadata = recordOf(asset.metadata)
      const owner = str(asset.service_owner) || str(metadata.owner) || str(metadata.team) || str(metadata.service_owner)
      const pass = Boolean(owner)
      const record = rowSubject({
        id: `asset-owner:${str(asset.id)}`,
        label: str(asset.name) || 'Asset',
        type: str(asset.type) || 'asset',
        pass,
        reason: pass ? `Owner: ${owner}` : 'No service owner recorded — remediation cannot be assigned.',
        assetId: str(asset.id),
        severity: pass ? null : 'low',
        href: '/dashboard/assets',
        table: 'assets',
        recordId: str(asset.id),
        observedAt: str(asset.updated_at) || null,
      })
      if (pass) passing.push(record)
      else failing.push(record)
    }
    return {
      measured: true,
      population: assets.length,
      satisfied: passing.length,
      failing,
      passing,
      basis: `${passing.length} of ${assets.length} active asset(s) record an accountable owner.`,
      lastValidatedAt: newest(...assets.map((asset) => asset.updated_at)),
    }
  },

  /* ---- Algorithm policy -------------------------------------------- */
  forbiddenAlgorithms: (inputs) => fromPolicies(inputs.policies, ['POL-ALG-FORBIDDEN'], 'cryptographic subject'),
  keyStrength: (inputs) => fromPolicies(inputs.policies, ['POL-KEY-RSA', 'POL-KEY-EC', 'POL-KEY-SYMMETRIC'], 'key-bearing subject'),
  approvedAlgorithms: (inputs) => fromPolicies(inputs.policies, ['POL-ALG-APPROVED'], 'classified subject'),

  /* ---- Transport ---------------------------------------------------- */
  tlsMinimumVersion: (inputs) => fromPolicies(inputs.policies, ['POL-TLS-MIN'], 'measured transport observation'),
  forwardSecrecy: (inputs) => fromPolicies(inputs.policies, ['POL-TLS-FS'], 'measured transport observation'),

  /* ---- Certificates -------------------------------------------------- */
  certificateInventory(inputs) {
    const certificates = inputs.subjects.certificates
    if (!certificates.length) return unmeasured('No certificates have been discovered yet.')
    const { failing, passing, satisfied } = partition(certificates, (subject) => {
      const pass = Boolean(subject.meta.notAfter)
      return {
        pass,
        reason: pass ? `Expires ${str(subject.meta.notAfter).slice(0, 10)}.` : 'No expiry date recorded — lifecycle risk cannot be measured.',
        severity: 'medium' as GovernanceSeverity,
      }
    })
    return {
      measured: true,
      population: certificates.length,
      satisfied,
      failing,
      passing,
      basis: `${satisfied} of ${certificates.length} certificate(s) record an expiry date.`,
      lastValidatedAt: newest(...certificates.map((subject) => subject.observedAt)),
    }
  },

  certificateExpiry: (inputs) => fromPolicies(inputs.policies, ['POL-CERT-RENEWAL'], 'certificate with a recorded expiry'),
  certificateAlgorithm: (inputs) => fromPolicies(inputs.policies, ['POL-CERT-SIGALG'], 'certificate with a recorded algorithm'),

  /* ---- Keys ---------------------------------------------------------- */
  keyInventory(inputs) {
    const keys = inputs.subjects.keys
    if (!keys.length) return unmeasured('No managed key material has been recorded yet.')
    const { failing, passing, satisfied } = partition(keys, (subject) => {
      const status = str(subject.meta.status)
      const pass = Boolean(status) && status.toLowerCase() !== 'unknown'
      return {
        pass,
        reason: pass ? `Lifecycle state: ${status}.` : 'No lifecycle state recorded for this key.',
        severity: 'low' as GovernanceSeverity,
      }
    })
    return {
      measured: true,
      population: keys.length,
      satisfied,
      failing,
      passing,
      basis: `${satisfied} of ${keys.length} managed key(s) record a lifecycle state.`,
      lastValidatedAt: newest(...keys.map((subject) => subject.observedAt)),
    }
  },

  keyLifecycle: (inputs) => fromPolicies(inputs.policies, ['POL-KEY-LIFECYCLE'], 'active managed key'),
  keyEntropy: (inputs) => fromPolicies(inputs.policies, ['POL-KEY-ENTROPY'], 'managed key'),

  /* ---- Data ---------------------------------------------------------- */
  dataAtRest: (inputs) => fromPolicies(inputs.policies, ['POL-DATA-REST'], 'stored object'),
  cleartextOperations: (inputs) => fromPolicies(inputs.policies, ['POL-RUNTIME-CLEARTEXT'], 'runtime transport observation'),

  /* ---- Post-quantum --------------------------------------------------- */
  quantumVulnerabilityIdentified(inputs) {
    const total = inputs.snapshot.inventory.cryptoComponents
    if (!total) return unmeasured('No cryptographic components have been discovered, so quantum vulnerability cannot be assessed.')
    const classified = inputs.snapshot.inventory.vulnerableComponents + inputs.snapshot.inventory.pqcReadyComponents
    const unclassified = Math.max(0, total - classified)
    const failing = inputs.subjects.components
      .filter((subject) => subject.posture === 'unknown')
      .slice(0, 200)
      .map((subject) => subjectFrom(subject, false, subject.algorithm ? `Posture unknown for "${subject.algorithm}".` : 'No algorithm recorded.', 'medium'))
    return {
      measured: true,
      population: total,
      satisfied: classified,
      failing,
      passing: [],
      basis: `${classified} of ${total} cryptographic component(s) have a classified quantum posture (${unclassified} unclassified). Counts mirror the Quantum Readiness assessment.`,
      lastValidatedAt: inputs.snapshot.telemetry.latestEventAt,
    }
  },

  migrationPlanCoverage(inputs) {
    const vulnerableAssets = inputs.snapshot.inventory.quantumVulnerableAssets
    if (!vulnerableAssets) {
      if (!inputs.snapshot.hasData) return unmeasured('No cryptographic evidence exists yet, so migration coverage cannot be assessed.')
      return {
        measured: true,
        population: 0,
        satisfied: 0,
        failing: [],
        passing: [],
        scoreOverride: 100,
        basis: 'No quantum-vulnerable assets are recorded, so there is nothing requiring a migration plan.',
        lastValidatedAt: inputs.snapshot.telemetry.latestEventAt,
      }
    }
    const plannedAssetIds = new Set<string>()
    for (const job of inputs.migrationJobs) if (str(job.asset_id)) plannedAssetIds.add(str(job.asset_id))
    for (const plan of inputs.migrationPlans) {
      const metadata = recordOf(plan.metadata)
      const ids = Array.isArray(metadata.assetIds) ? metadata.assetIds : Array.isArray(metadata.asset_ids) ? metadata.asset_ids : []
      for (const id of ids) if (str(id)) plannedAssetIds.add(str(id))
    }

    // Score against the canonical vulnerable-asset count so the denominator is
    // the one Quantum Readiness publishes, not a locally recomputed set.
    const vulnerableRows = inputs.assets.filter((asset) => {
      const id = str(asset.id)
      return inputs.subjects.all.some((subject) => subject.assetId === id && subject.posture === 'vulnerable')
    })
    const failing: ControlSubject[] = []
    let covered = 0
    for (const asset of vulnerableRows) {
      const id = str(asset.id)
      if (plannedAssetIds.has(id)) {
        covered += 1
        continue
      }
      failing.push(
        rowSubject({
          id: `plan-gap:${id}`,
          label: str(asset.name) || 'Asset',
          type: str(asset.type) || 'asset',
          pass: false,
          reason: 'Quantum-vulnerable asset with no migration plan or job.',
          assetId: id,
          severity: assetIsInternetFacing(asset) ? 'critical' : 'high',
          href: '/dashboard/migration-planner',
          table: 'assets',
          recordId: id,
          observedAt: str(asset.updated_at) || null,
        }),
      )
    }
    const population = Math.max(vulnerableAssets, vulnerableRows.length)
    const satisfied = Math.min(population, covered)
    return {
      measured: true,
      population,
      satisfied,
      failing,
      passing: [],
      basis: `${satisfied} of ${population} quantum-vulnerable asset(s) are covered by a migration plan or job.`,
      lastValidatedAt: newest(...inputs.migrationJobs.map((job) => job.updated_at || job.created_at)),
      severityFloor: failing.some((item) => item.severity === 'critical') ? 'critical' : failing.length ? 'high' : undefined,
    }
  },

  pqcAdoption(inputs) {
    const total = inputs.snapshot.inventory.cryptoComponents
    if (!total) return unmeasured('No cryptographic components have been discovered, so adoption cannot be measured.')
    const pqcReady = inputs.snapshot.inventory.pqcReadyComponents
    const failing = inputs.subjects.all
      .filter((subject) => subject.posture === 'vulnerable')
      .slice(0, 200)
      .map((subject) =>
        subjectFrom(subject, false, `${subject.algorithm || ALGORITHM_FAMILY_LABEL[subject.family]} is quantum-vulnerable.`, 'high'),
      )
    return {
      measured: true,
      population: total,
      satisfied: pqcReady,
      failing,
      passing: [],
      // Uses the canonical adoption score so this control cannot disagree with
      // the Quantum Readiness "PQC Adoption" tile.
      scoreOverride: Math.round(inputs.snapshot.scores.pqcAdoption),
      basis: `PQC adoption ${Math.round(inputs.snapshot.scores.pqcAdoption)}% — ${pqcReady} of ${total} component(s) are post-quantum or hybrid. Value taken from the Quantum Readiness assessment.`,
      lastValidatedAt: inputs.snapshot.telemetry.latestEventAt,
    }
  },

  internetFacingPqc: (inputs) => fromPolicies(inputs.policies, ['POL-PQC-EXPOSED'], 'classified internet-facing subject'),

  cryptoAgility(inputs) {
    const vulnerable = inputs.snapshot.inventory.vulnerableComponents
    const algorithmChanges = inputs.migrationJobs.filter((job) => {
      const status = str(job.status).toLowerCase()
      return /complete|done|success|migrated/.test(status) && Boolean(str(job.target_algorithm))
    })
    if (!vulnerable && !algorithmChanges.length) {
      return unmeasured('No quantum-vulnerable components and no completed algorithm changes — agility has nothing to demonstrate against yet.')
    }
    const population = Math.max(1, vulnerable + algorithmChanges.length)
    const satisfied = algorithmChanges.length
    const failing = vulnerable
      ? [
          rowSubject({
            id: 'agility:pending',
            label: `${vulnerable} quantum-vulnerable component(s) awaiting replacement`,
            type: 'component',
            pass: false,
            reason: 'Algorithm replacement has not yet been demonstrated for these components.',
            severity: 'medium',
            href: '/dashboard/crypto-agility',
            table: 'crypto_inventory',
            recordId: 'aggregate',
          }),
        ]
      : []
    return {
      measured: true,
      population,
      satisfied,
      failing,
      passing: [],
      basis: `${algorithmChanges.length} completed algorithm change(s) against ${vulnerable} component(s) still requiring replacement.`,
      lastValidatedAt: newest(...algorithmChanges.map((job) => job.completed_at || job.updated_at)),
    }
  },

  /* ---- Monitoring ------------------------------------------------------ */
  scanCadence(inputs) {
    const completed = inputs.scanSessions.filter((session) => /complete/i.test(str(session.status)))
    if (!completed.length) {
      return unmeasured('No discovery scan has completed yet, so cadence cannot be measured.')
    }
    const latest = newest(...completed.map((session) => session.completed_at || session.updated_at || session.created_at))
    const ageDays = latest ? daysBetween(ms(latest), inputs.now) : null
    const cadenceDays = 30
    const pass = ageDays !== null && ageDays <= cadenceDays
    return {
      measured: true,
      population: 1,
      satisfied: pass ? 1 : 0,
      failing: pass
        ? []
        : [
            rowSubject({
              id: 'scan-cadence',
              label: 'Discovery cadence',
              type: 'scan',
              pass: false,
              reason: ageDays === null ? 'Last completed scan has no timestamp.' : `Last completed scan was ${ageDays} day(s) ago, beyond the ${cadenceDays}-day cadence.`,
              severity: 'medium',
              href: '/dashboard/scanner',
              table: 'pqc_scan_sessions',
              recordId: 'latest',
              observedAt: latest,
            }),
          ],
      passing: [],
      scoreOverride: pass ? 100 : 0,
      basis: latest
        ? `Last completed discovery scan ${ageDays} day(s) ago against a ${cadenceDays}-day cadence.`
        : 'Completed scans exist but none records a timestamp.',
      lastValidatedAt: latest,
    }
  },

  runtimeMonitoring(inputs) {
    const latest = inputs.snapshot.telemetry.latestRuntimeEventAt
    const hasCollectors = inputs.scannerAgents.length > 0 || inputs.connectorAccounts.length > 0
    if (!latest && !hasCollectors) {
      return unmeasured('No runtime collector or connector is configured, so runtime monitoring is not measured.')
    }
    if (!latest) {
      return {
        measured: true,
        population: 1,
        satisfied: 0,
        failing: [
          rowSubject({
            id: 'runtime-monitoring',
            label: 'Runtime cryptographic telemetry',
            type: 'telemetry',
            pass: false,
            reason: `${inputs.scannerAgents.length} collector(s) and ${inputs.connectorAccounts.length} connector(s) are configured but no runtime cryptographic event has been received.`,
            severity: 'high',
            href: '/dashboard/runtime-telemetry',
            table: 'runtime_crypto_events',
            recordId: 'none',
          }),
        ],
        passing: [],
        scoreOverride: 0,
        basis: 'Collectors are configured but no runtime cryptographic telemetry has arrived.',
        lastValidatedAt: null,
      }
    }
    const ageHours = Math.floor((inputs.now - ms(latest)) / 3_600_000)
    const pass = ageHours <= 24
    return {
      measured: true,
      population: 1,
      satisfied: pass ? 1 : 0,
      failing: pass
        ? []
        : [
            rowSubject({
              id: 'runtime-monitoring',
              label: 'Runtime cryptographic telemetry',
              type: 'telemetry',
              pass: false,
              reason: `Newest runtime observation is ${ageHours}h old — beyond the 24h freshness window.`,
              severity: 'medium',
              href: '/dashboard/runtime-telemetry',
              table: 'runtime_crypto_events',
              recordId: 'latest',
              observedAt: latest,
            }),
          ],
      passing: [],
      scoreOverride: pass ? 100 : 0,
      basis: `Newest runtime cryptographic observation is ${ageHours}h old (24h freshness window).`,
      lastValidatedAt: latest,
    }
  },

  collectorHealth(inputs) {
    const sources = [
      ...inputs.scannerAgents.map((agent) => ({ row: agent, kind: 'collector', table: 'scanner_agents' })),
      ...inputs.connectorAccounts.map((connector) => ({ row: connector, kind: 'connector', table: 'connector_accounts' })),
    ]
    if (!sources.length) return unmeasured('No collectors or connectors are configured for this tenant.')
    const windowMs = 60 * 60 * 1000
    const failing: ControlSubject[] = []
    const passing: ControlSubject[] = []
    for (const source of sources) {
      const row = source.row
      const lastSeen = ms(row.last_seen_at || row.last_sync_at || row.updated_at)
      const status = str(row.status).toLowerCase()
      const healthy = (lastSeen > 0 && inputs.now - lastSeen <= windowMs) || /online|active|healthy|connected|running|synced/.test(status)
      const record = rowSubject({
        id: `${source.table}:${str(row.id)}`,
        label: str(row.name) || str(row.display_name) || str(row.hostname) || str(row.provider) || source.kind,
        type: source.kind,
        pass: healthy,
        reason: healthy
          ? `Reporting (status ${status || 'active'}).`
          : lastSeen
            ? `Last report ${Math.floor((inputs.now - lastSeen) / 3_600_000)}h ago.`
            : 'Never reported.',
        severity: healthy ? null : 'medium',
        href: source.kind === 'collector' ? '/dashboard/scanner?tab=agents' : '/dashboard/multi-cloud-telemetry',
        table: source.table,
        recordId: str(row.id),
        observedAt: lastSeen ? new Date(lastSeen).toISOString() : null,
      })
      if (healthy) passing.push(record)
      else failing.push(record)
    }
    return {
      measured: true,
      population: sources.length,
      satisfied: passing.length,
      failing,
      passing,
      basis: `${passing.length} of ${sources.length} evidence source(s) reported inside the 1h heartbeat window.`,
      lastValidatedAt: newest(...sources.map((source) => source.row.last_seen_at || source.row.last_sync_at || source.row.updated_at)),
    }
  },

  /* ---- Remediation ------------------------------------------------------- */
  findingSla(inputs) {
    const slaDays = 30
    interface Candidate {
      id: string
      table: string
      title: string
      severity: GovernanceSeverity
      status: string
      openedAt: number
      assetId: string | null
      href: string
    }
    const candidates: Candidate[] = []
    const gradeSeverity = (value: unknown): GovernanceSeverity | null => {
      const text = str(value).toLowerCase()
      if (text.includes('critical')) return 'critical'
      if (text.includes('high')) return 'high'
      return null
    }
    for (const row of inputs.vulnerabilities) {
      const severity = gradeSeverity(row.severity)
      if (!severity) continue
      candidates.push({
        id: `vulnerabilities:${str(row.id)}`,
        table: 'vulnerabilities',
        title: str(row.title) || 'Vulnerability',
        severity,
        status: str(row.status) || 'open',
        openedAt: ms(row.created_at),
        assetId: str(row.asset_id) || null,
        href: '/dashboard/quantum-readiness/risk-analysis',
      })
    }
    for (const row of inputs.scannerAlerts) {
      const severity = gradeSeverity(row.severity)
      if (!severity) continue
      candidates.push({
        id: `scanner_alerts:${str(row.id)}`,
        table: 'scanner_alerts',
        title: str(row.title) || str(row.category) || 'Collector alert',
        severity,
        status: str(row.status) || 'open',
        openedAt: ms(row.created_at),
        assetId: null,
        href: '/dashboard/scanner?tab=agents',
      })
    }
    for (const row of inputs.cryptoExposures) {
      const severity = gradeSeverity(row.severity)
      if (!severity) continue
      candidates.push({
        id: `crypto_exposures:${str(row.id)}`,
        table: 'crypto_exposures',
        title: str(row.exposure_type) || 'Cryptographic exposure',
        severity,
        status: 'open',
        openedAt: ms(row.created_at),
        assetId: str(row.asset_id) || null,
        href: '/dashboard/crypto-exposure',
      })
    }
    if (!candidates.length) {
      return unmeasured('No critical or high findings have been recorded, so remediation timeliness is not measured.')
    }
    const failing: ControlSubject[] = []
    let satisfied = 0
    for (const candidate of candidates) {
      const resolved = /resolved|closed|fixed|remediated|mitigated|false[_\s-]?positive|accepted|suppressed/i.test(candidate.status)
      if (resolved) {
        satisfied += 1
        continue
      }
      const ageDays = candidate.openedAt ? daysBetween(candidate.openedAt, inputs.now) : null
      if (ageDays !== null && ageDays <= slaDays) {
        satisfied += 1
        continue
      }
      failing.push(
        rowSubject({
          id: candidate.id,
          label: candidate.title,
          type: 'finding',
          pass: false,
          reason: ageDays === null ? 'Open finding with no recorded open date.' : `Open for ${ageDays} day(s), beyond the ${slaDays}-day remediation window.`,
          assetId: candidate.assetId,
          severity: candidate.severity,
          href: candidate.href,
          table: candidate.table,
          recordId: candidate.id.split(':')[1] || candidate.id,
          observedAt: candidate.openedAt ? new Date(candidate.openedAt).toISOString() : null,
        }),
      )
    }
    return {
      measured: true,
      population: candidates.length,
      satisfied,
      failing,
      passing: [],
      basis: `${satisfied} of ${candidates.length} critical/high finding(s) are resolved or inside the ${slaDays}-day remediation window.`,
      lastValidatedAt: newest(...candidates.map((candidate) => (candidate.openedAt ? new Date(candidate.openedAt).toISOString() : null))),
      severityFloor: failing.some((item) => item.severity === 'critical') ? 'critical' : failing.length ? 'high' : undefined,
    }
  },

  findingOwnership(inputs) {
    const ownerByAsset = new Map<string, string>()
    for (const asset of inputs.assets) {
      const metadata = recordOf(asset.metadata)
      const owner = str(asset.service_owner) || str(metadata.owner) || str(metadata.team)
      if (owner) ownerByAsset.set(str(asset.id), owner)
    }
    const open: Array<{ id: string; table: string; title: string; assetId: string; severity: GovernanceSeverity; href: string; at: string | null }> = []
    const isOpen = (status: unknown) => !/resolved|closed|fixed|remediated|mitigated|false[_\s-]?positive|accepted|suppressed/i.test(str(status))
    for (const row of inputs.vulnerabilities) {
      if (!isOpen(row.status)) continue
      open.push({
        id: `vulnerabilities:${str(row.id)}`,
        table: 'vulnerabilities',
        title: str(row.title) || 'Vulnerability',
        assetId: str(row.asset_id),
        severity: /critical/i.test(str(row.severity)) ? 'critical' : /high/i.test(str(row.severity)) ? 'high' : 'medium',
        href: '/dashboard/quantum-readiness/risk-analysis',
        at: str(row.created_at) || null,
      })
    }
    for (const row of inputs.scanResults) {
      const threat = str(row.threat_level).toLowerCase()
      if (!threat.includes('critical') && !threat.includes('high')) continue
      open.push({
        id: `pqc_scan_results:${str(row.id)}`,
        table: 'pqc_scan_results',
        title: `${str(row.algorithm) || 'Quantum-vulnerable algorithm'} detected`,
        assetId: str(row.asset_id),
        severity: threat.includes('critical') ? 'critical' : 'high',
        href: '/dashboard/quantum-readiness/risk-analysis',
        at: str(row.created_at) || null,
      })
    }
    if (!open.length) return unmeasured('No open findings are recorded, so ownership attribution is not measured.')
    const failing: ControlSubject[] = []
    let satisfied = 0
    for (const finding of open) {
      const owner = finding.assetId ? ownerByAsset.get(finding.assetId) : ''
      if (owner) {
        satisfied += 1
        continue
      }
      failing.push(
        rowSubject({
          id: finding.id,
          label: finding.title,
          type: 'finding',
          pass: false,
          reason: finding.assetId ? 'Mapped asset has no recorded owner.' : 'Finding is not mapped to any asset.',
          assetId: finding.assetId || null,
          severity: finding.severity,
          href: finding.href,
          table: finding.table,
          recordId: finding.id.split(':')[1] || finding.id,
          observedAt: finding.at,
        }),
      )
    }
    return {
      measured: true,
      population: open.length,
      satisfied,
      failing,
      passing: [],
      basis: `${satisfied} of ${open.length} open finding(s) resolve to an asset with an accountable owner.`,
      lastValidatedAt: newest(...open.map((finding) => finding.at)),
    }
  },

  /* ---- Audit & evidence -------------------------------------------------- */
  auditLogging(inputs) {
    const total = inputs.auditLogs.length + inputs.vaultAuditLogs.length + inputs.securityEvents.length + inputs.authEvents.length
    if (!total) return unmeasured('No audit records exist for this tenant yet.')
    const latest = newest(
      ...inputs.auditLogs.map((row) => row.created_at),
      ...inputs.vaultAuditLogs.map((row) => row.created_at),
      ...inputs.securityEvents.map((row) => row.created_at),
      ...inputs.authEvents.map((row) => row.created_at),
    )
    const ageDays = latest ? daysBetween(ms(latest), inputs.now) : null
    const pass = ageDays !== null && ageDays <= 7
    return {
      measured: true,
      population: 1,
      satisfied: pass ? 1 : 0,
      failing: pass
        ? []
        : [
            rowSubject({
              id: 'audit-logging',
              label: 'Audit record freshness',
              type: 'audit',
              pass: false,
              reason: ageDays === null ? 'Audit records exist but none records a timestamp.' : `Newest audit record is ${ageDays} day(s) old.`,
              severity: 'medium',
              href: '/dashboard/audit-vault',
              table: 'audit_logs',
              recordId: 'latest',
              observedAt: latest,
            }),
          ],
      passing: [],
      scoreOverride: pass ? 100 : 0,
      basis: `${total} audit record(s) across 4 source(s); newest ${ageDays === null ? 'undated' : `${ageDays} day(s) old`} against a 7-day activity window.`,
      lastValidatedAt: latest,
    }
  },

  auditFailures(inputs) {
    // Matched through the SHARED normaliser: `\b` treats `_` as a word
    // character, so a raw pattern never matches inside `login_failed` — and
    // every platform action name is snake_case. See audit.ts for the full note.
    const rows: Array<{ id: string; table: string; label: string; text: string; at: string | null }> = []
    for (const row of inputs.auditLogs) {
      rows.push({ id: `audit_logs:${str(row.id)}`, table: 'audit_logs', label: str(row.action) || 'Audit record', text: `${str(row.action)} ${JSON.stringify(recordOf(row.details))}`, at: str(row.created_at) || null })
    }
    for (const row of inputs.vaultAuditLogs) {
      rows.push({ id: `vault_audit_logs:${str(row.id)}`, table: 'vault_audit_logs', label: str(row.event_type) || 'Vault audit record', text: `${str(row.event_type)} ${str(row.result || row.status)}`, at: str(row.created_at) || null })
    }
    for (const row of inputs.securityEvents) {
      rows.push({ id: `security_events:${str(row.id)}`, table: 'security_events', label: str(row.event_type) || 'Security event', text: `${str(row.event_type)} ${str(row.message)}`, at: str(row.created_at) || null })
    }
    if (!rows.length) return unmeasured('No audit records exist for this tenant yet.')
    const failing: ControlSubject[] = []
    let satisfied = 0
    for (const row of rows) {
      if (!looksLikeFailure(row.text)) {
        satisfied += 1
        continue
      }
      failing.push(
        rowSubject({
          id: row.id,
          label: row.label,
          type: 'audit',
          pass: false,
          reason: 'Audit record shows a failed or denied operation.',
          severity: 'medium',
          href: '/dashboard/audit-vault',
          table: row.table,
          recordId: row.id.split(':')[1] || row.id,
          observedAt: row.at,
        }),
      )
    }
    return {
      measured: true,
      population: rows.length,
      satisfied,
      failing,
      passing: [],
      basis: `${failing.length} of ${rows.length} audit record(s) show a failed or denied operation.`,
      lastValidatedAt: newest(...rows.map((row) => row.at)),
    }
  },

  evidenceIntegrity(inputs) {
    if (!inputs.anchoringAvailable) {
      return unmeasured('The evidence anchor store is not available, so integrity cannot be established. Apply the governance schema to enable anchoring.')
    }
    const anchored = inputs.evidence.filter((record) => record.integrity.state === 'verified' || record.integrity.state === 'mismatch')
    if (!anchored.length) {
      return {
        measured: true,
        population: inputs.evidence.length,
        satisfied: 0,
        failing: inputs.evidence.slice(0, SAMPLE).map((record) =>
          rowSubject({
            id: record.id,
            label: record.title,
            type: record.kind,
            pass: false,
            reason: 'Evidence has never been anchored, so later modification would not be detectable.',
            assetId: record.assetId,
            severity: 'medium',
            href: '/dashboard/audit-vault',
            table: record.source.table,
            recordId: record.source.recordId,
            observedAt: record.occurredAt,
          }),
        ),
        passing: [],
        basis: `${inputs.evidence.length} evidence record(s) exist and none has been anchored — anchor them to make modification detectable.`,
        lastValidatedAt: null,
      }
    }
    const mismatched = anchored.filter((record) => record.integrity.state === 'mismatch')
    return {
      measured: true,
      population: inputs.evidence.length,
      satisfied: anchored.length - mismatched.length,
      failing: [
        ...mismatched.slice(0, SAMPLE).map((record) =>
          rowSubject({
            id: record.id,
            label: record.title,
            type: record.kind,
            pass: false,
            reason: 'Recomputed digest differs from the anchored digest — the source record changed after anchoring.',
            assetId: record.assetId,
            severity: 'critical',
            href: '/dashboard/audit-vault',
            table: record.source.table,
            recordId: record.source.recordId,
            observedAt: record.occurredAt,
          }),
        ),
        ...inputs.evidence
          .filter((record) => record.integrity.state === 'unanchored')
          .slice(0, SAMPLE)
          .map((record) =>
            rowSubject({
              id: record.id,
              label: record.title,
              type: record.kind,
              pass: false,
              reason: 'Not anchored — no earlier digest exists to compare against.',
              assetId: record.assetId,
              severity: 'low',
              href: '/dashboard/audit-vault',
              table: record.source.table,
              recordId: record.source.recordId,
              observedAt: record.occurredAt,
            }),
          ),
      ],
      passing: [],
      basis: `${anchored.length - mismatched.length} of ${inputs.evidence.length} evidence record(s) verify against an anchored digest; ${mismatched.length} mismatch.`,
      lastValidatedAt: newest(...anchored.map((record) => record.integrity.anchoredAt)),
      severityFloor: mismatched.length ? 'critical' : undefined,
    }
  },

  evidenceRetention(inputs) {
    const scoped = inputs.evidence.filter((record) => record.retention.state !== 'unspecified')
    if (!scoped.length) return unmeasured('No evidence carries a retention window yet.')
    const failing = scoped
      .filter((record) => record.retention.state === 'expired')
      .slice(0, 200)
      .map((record) =>
        rowSubject({
          id: record.id,
          label: record.title,
          type: record.kind,
          pass: false,
          reason: `Past its ${record.retention.periodDays}-day retention window (expired ${record.retention.expiresAt?.slice(0, 10)}).`,
          assetId: record.assetId,
          severity: 'medium',
          href: '/dashboard/audit-vault',
          table: record.source.table,
          recordId: record.source.recordId,
          observedAt: record.occurredAt,
        }),
      )
    const expired = scoped.filter((record) => record.retention.state === 'expired').length
    return {
      measured: true,
      population: scoped.length,
      satisfied: scoped.length - expired,
      failing,
      passing: [],
      basis: `${scoped.length - expired} of ${scoped.length} evidence record(s) are inside their retention window.`,
      lastValidatedAt: newest(...scoped.map((record) => record.occurredAt)),
    }
  },

  evidenceFreshness(inputs) {
    const scoped = inputs.evidence.filter((record) => record.freshness !== 'unknown')
    if (!scoped.length) return unmeasured('No dated evidence exists yet, so freshness cannot be measured.')
    const stale = scoped.filter((record) => record.freshness === 'stale')
    return {
      measured: true,
      population: scoped.length,
      satisfied: scoped.length - stale.length,
      failing: stale.slice(0, 200).map((record) =>
        rowSubject({
          id: record.id,
          label: record.title,
          type: record.kind,
          pass: false,
          reason: `Evidence is ${record.ageDays} day(s) old — beyond the 90-day staleness threshold.`,
          assetId: record.assetId,
          severity: 'medium',
          href: record.href,
          table: record.source.table,
          recordId: record.source.recordId,
          observedAt: record.occurredAt,
        }),
      ),
      passing: [],
      basis: `${scoped.length - stale.length} of ${scoped.length} dated evidence record(s) are newer than 90 days.`,
      lastValidatedAt: newest(...scoped.map((record) => record.occurredAt)),
    }
  },

  attestedEvidence(inputs) {
    // GUARD: the population below comes from the CATALOG, which is a constant.
    // Without this gate a tenant with no evidence at all scored 0% here — a
    // fabricated failure — and that 0 flowed into the headline compliance
    // score, so an empty tenant published a real-looking number. Nothing is in
    // scope for attestation until the tenant has some governance evidence.
    if (!inputs.evidence.length) {
      return unmeasured('No governance evidence exists yet, so no framework is in scope for attestation.')
    }
    // The population is the frameworks the catalog governs; a framework passes
    // when the tenant recorded at least one attestation naming it.
    const attestedFrameworkIds = new Set<string>()
    for (const record of inputs.evidence) {
      if (record.kind !== 'attestation') continue
      for (const frameworkId of record.frameworkIds) attestedFrameworkIds.add(frameworkId)
    }
    const frameworkIds = new Set<string>()
    for (const list of FRAMEWORKS_BY_CONTROL.values()) for (const id of list) frameworkIds.add(id)
    const population = frameworkIds.size
    if (!population) return unmeasured('No frameworks are in scope.')
    const satisfied = [...frameworkIds].filter((id) => attestedFrameworkIds.has(id)).length
    return {
      measured: true,
      population,
      satisfied,
      failing: [...frameworkIds]
        .filter((id) => !attestedFrameworkIds.has(id))
        .map((id) =>
          rowSubject({
            id: `framework:${id}`,
            label: id,
            type: 'framework',
            pass: false,
            reason: 'No stored attestation evidence names this framework — status rests on derived platform signals only.',
            severity: 'low',
            href: '/dashboard/regulatory-mapping',
            table: 'compliance_evidence',
            recordId: id,
          }),
        ),
      passing: [],
      basis: `${satisfied} of ${population} in-scope framework(s) carry at least one stored attestation record.`,
      lastValidatedAt: newest(...inputs.complianceEvidence.map((row) => row.updated_at || row.created_at)),
    }
  },

  /* ---- Governance -------------------------------------------------------- */
  policyEnforcement(inputs) {
    const policies = inputs.policies
    if (!policies.length) return unmeasured('No cryptographic policy rules are defined.')
    // GUARD: the policy rulebook ships enabled by default, so counting enabled
    // rules on a tenant with nothing to govern scored a clean 100% — the
    // "100 from nothing" trap, and it made an empty tenant's headline
    // compliance score non-null. A rulebook governing an empty estate is not
    // an enforcement measurement.
    if (!inputs.snapshot.hasData) {
      return unmeasured('No cryptographic estate exists yet, so policy enforcement has nothing to govern.')
    }
    const failing = policies
      .filter((policy) => policy.enforcement === 'disabled')
      .map((policy) =>
        rowSubject({
          id: `policy:${policy.id}`,
          label: policy.title,
          type: 'policy',
          pass: false,
          reason: 'Rule is disabled — nothing is evaluated against it.',
          severity: policy.severity,
          href: '/dashboard/quantum-governance',
          table: 'governance_policies',
          recordId: policy.id,
          observedAt: policy.updatedAt,
        }),
      )
    return {
      measured: true,
      population: policies.length,
      satisfied: policies.length - failing.length,
      failing,
      passing: [],
      basis: `${policies.length - failing.length} of ${policies.length} cryptographic policy rule(s) are enforced or monitored.`,
      lastValidatedAt: newest(...policies.map((policy) => policy.updatedAt || policy.lastEvaluatedAt)),
    }
  },

  exceptionGovernance(inputs) {
    const rows = inputs.assessments
    if (rows === null) {
      return unmeasured('The control assessment store is not available, so exceptions cannot be governed. Apply the governance schema to enable them.')
    }
    const exceptions = rows.filter((row) => Boolean(str(row.exception_reason)))
    if (!exceptions.length) {
      return {
        measured: true,
        population: 0,
        satisfied: 0,
        failing: [],
        passing: [],
        scoreOverride: 100,
        basis: 'No control exceptions have been recorded, so none can be unapproved or expired.',
        lastValidatedAt: null,
      }
    }
    const failing: ControlSubject[] = []
    let satisfied = 0
    for (const row of exceptions) {
      const approver = str(row.exception_approved_by)
      const expiry = ms(row.exception_expires_at)
      const expired = Boolean(expiry) && expiry < inputs.now
      if (approver && expiry && !expired) {
        satisfied += 1
        continue
      }
      failing.push(
        rowSubject({
          id: `exception:${str(row.control_id)}`,
          label: str(row.control_id) || 'Control exception',
          type: 'exception',
          pass: false,
          reason: !approver ? 'Exception has no recorded approver.' : expired ? 'Exception expired and has not been renewed.' : 'Exception has no expiry date.',
          severity: expired ? 'high' : 'medium',
          href: '/dashboard/compliance',
          table: 'governance_control_assessments',
          recordId: str(row.id),
          observedAt: str(row.updated_at) || null,
        }),
      )
    }
    return {
      measured: true,
      population: exceptions.length,
      satisfied,
      failing,
      passing: [],
      basis: `${satisfied} of ${exceptions.length} control exception(s) record an approver and a live expiry.`,
      lastValidatedAt: newest(...exceptions.map((row) => row.updated_at || row.created_at)),
    }
  },

  quantumRiskThreshold: (inputs) => fromPolicies(inputs.policies, ['POL-RISK-THRESHOLD'], 'tenant risk measurement'),
}

/* ------------------------------------------------------------------ */
/* Assembly                                                            */
/* ------------------------------------------------------------------ */

function statusFrom(evaluation: Evaluation, score: number | null): ControlStatus {
  if (!evaluation.measured) return 'not-assessed'
  if (score === null) return 'not-assessed'
  if (score >= 100) return 'compliant'
  if (score <= 0) return 'non-compliant'
  return 'partial'
}

function severityFor(evaluation: Evaluation, status: ControlStatus): GovernanceSeverity | null {
  if (status === 'compliant' || status === 'not-assessed' || status === 'not-applicable') return null
  if (evaluation.severityFloor) return evaluation.severityFloor
  const worst = evaluation.failing.reduce<GovernanceSeverity>(
    (best, subject) => (subject.severity && severityOrder(subject.severity) > severityOrder(best) ? subject.severity : best),
    'low',
  )
  return worst
}

function ownerFor(definition: ControlDefinition, assessments: Row[] | null): { owner: string | null; source: ControlRecord['ownerSource'] } {
  const row = (assessments || []).find((entry) => str(entry.control_id) === definition.id)
  const assigned = str(row?.owner)
  if (assigned) return { owner: assigned, source: 'assigned' }
  return { owner: null, source: 'unassigned' }
}

function exceptionFor(definition: ControlDefinition, assessments: Row[] | null, now: number): ControlException | null {
  const row = (assessments || []).find((entry) => str(entry.control_id) === definition.id && str(entry.exception_reason))
  if (!row) return null
  const expiresAt = ms(row.exception_expires_at)
  return {
    id: str(row.id),
    reason: str(row.exception_reason),
    approvedBy: str(row.exception_approved_by) || 'Not recorded',
    approvedAt: str(row.exception_approved_at) || null,
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    expired: Boolean(expiresAt) && expiresAt < now,
  }
}

/**
 * Evaluates every catalog control against the tenant's evidence.
 *
 * A control with a live, approved exception is reported `not-applicable` and
 * excluded from the aggregate score — but the exception itself becomes a
 * governed object (CTL-GOV-02), so scoping something out is never free.
 */
export function evaluateControls(inputs: ControlEvaluationInputs): ControlRecord[] {
  return CONTROL_CATALOG.map((definition) => {
    const evaluator = EVALUATORS[definition.evaluator]
    const evaluation: Evaluation = evaluator
      ? evaluator(inputs)
      : unmeasured('No evaluator is registered for this control.')

    const score =
      evaluation.scoreOverride !== undefined
        ? evaluation.scoreOverride
        : evaluation.measured && evaluation.population > 0
          ? clampPercent((evaluation.satisfied / evaluation.population) * 100)
          : evaluation.measured
            ? 100
            : null

    const exception = exceptionFor(definition, inputs.assessments, inputs.now)
    const liveException = exception && !exception.expired
    const status: ControlStatus = liveException ? 'not-applicable' : statusFrom(evaluation, score)

    const failing = evaluation.failing
    const affectedAssetIds = [...new Set(failing.map((subject) => subject.assetId).filter((id): id is string => Boolean(id)))]
    const evidenceIds = inputs.evidence.filter((record) => record.controlIds.includes(definition.id)).map((record) => record.id)
    const findingIds = failing.filter((subject) => subject.type === 'finding').map((subject) => subject.id)

    const lastValidatedAt = evaluation.lastValidatedAt
    const { state: evidenceFreshness, ageDays } = freshnessOf(lastValidatedAt, inputs.now)
    const { owner, source: ownerSource } = ownerFor(definition, inputs.assessments)

    return {
      id: definition.id,
      code: definition.code,
      title: definition.title,
      objective: definition.objective,
      criterion: definition.criterion,
      domain: definition.domain,
      status,
      score: liveException ? null : score,
      measured: evaluation.measured,
      basis: liveException
        ? `Scoped out by an approved exception${exception?.expiresAt ? ` until ${exception.expiresAt.slice(0, 10)}` : ''}. ${evaluation.basis}`
        : evaluation.basis,
      population: evaluation.population,
      satisfied: evaluation.satisfied,
      failing: Math.max(0, evaluation.population - evaluation.satisfied),
      severity: liveException ? null : severityFor(evaluation, status),
      owner,
      ownerSource,
      requirementIds: REQUIREMENTS_BY_CONTROL.get(definition.id) || [],
      frameworkIds: FRAMEWORKS_BY_CONTROL.get(definition.id) || [],
      affectedAssetIds,
      affectedAssetCount: affectedAssetIds.length,
      findingIds: findingIds.slice(0, 50),
      evidenceIds: evidenceIds.slice(0, 50),
      failingSubjects: failing
        .slice()
        .sort((a, b) => severityOrder(b.severity || 'low') - severityOrder(a.severity || 'low'))
        .slice(0, SAMPLE),
      passingSample: evaluation.passing.slice(0, 4),
      lastValidatedAt,
      evidenceFreshness,
      evidenceAgeDays: ageDays,
      remediationRoute: definition.remediationRoute,
      evidenceSources: definition.evidenceSources,
      weight: definition.weight,
      exception,
    }
  })
}

/**
 * Every failing subject for one control — the paged drill-down feed.
 * The dashboard payload carries only a bounded sample; this returns the lot.
 */
export function failingSubjectsFor(controlId: string, inputs: ControlEvaluationInputs): ControlSubject[] {
  const definition = CONTROL_CATALOG.find((control) => control.id === controlId)
  if (!definition) return []
  const evaluator = EVALUATORS[definition.evaluator]
  if (!evaluator) return []
  return evaluator(inputs).failing
}

export { num, str }
