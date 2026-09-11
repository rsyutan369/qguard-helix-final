/**
 * Unified evidence model (§9).
 *
 * One `EvidenceRecord` shape for every governance surface, so the same object
 * is what Compliance cites for a control, what Regulatory Mapping counts for a
 * requirement, and what the Audit Vault verifies and retains. There is exactly
 * one producer — this module — which is why a control's evidence count can never
 * disagree with the vault's.
 *
 * Every record is traceable to tenant, asset, scan, finding, control, framework,
 * requirement, policy, actor, timestamp, source and integrity metadata.
 */

import { buildIntegrity } from './integrity'
import { resolveFrameworkId, FRAMEWORKS_BY_CONTROL, REQUIREMENTS_BY_CONTROL } from './catalog'
import { daysBetween, isoOrNull, ms, num, recordOf, str, type Row } from './subjects'
import type {
  EvidenceCustodyEntry,
  EvidenceKind,
  EvidenceRecord,
  FreshnessState,
  GovernanceSeverity,
  RetentionState,
} from './types'

/* ------------------------------------------------------------------ */
/* Retention + freshness policy                                        */
/* ------------------------------------------------------------------ */

/**
 * Default retention windows per evidence class, in days.
 *
 * These are the platform's defaults, applied so an auditor can see when a record
 * falls out of its window. They describe the PLATFORM's retention intent — not a
 * guarantee that the underlying row is deleted on schedule, which is why the
 * state is reported as an expiry against the window rather than as deletion.
 */
export const RETENTION_DAYS: Record<EvidenceKind, number | null> = {
  attestation: 2555, // 7 years — audit attestation
  audit: 2555,
  finding: 1095, // 3 years
  scan: 730,
  certificate: 1095,
  key: 2555,
  inventory: 730,
  runtime: 90,
  migration: 1095,
  vault: 2555,
  policy: 2555,
}

/** Evidence older than this is stale for compliance purposes. */
export const FRESH_DAYS = 30
export const AGING_DAYS = 90

export function freshnessOf(occurredAt: string | null, now: number): { state: FreshnessState; ageDays: number | null } {
  const at = ms(occurredAt)
  if (!at) return { state: 'unknown', ageDays: null }
  const ageDays = Math.max(0, daysBetween(at, now))
  if (ageDays <= FRESH_DAYS) return { state: 'fresh', ageDays }
  if (ageDays <= AGING_DAYS) return { state: 'aging', ageDays }
  return { state: 'stale', ageDays }
}

function retentionFor(kind: EvidenceKind, occurredAt: string | null, now: number) {
  const periodDays = RETENTION_DAYS[kind] ?? null
  const at = ms(occurredAt)
  if (!periodDays || !at) {
    return { periodDays, expiresAt: null, state: 'unspecified' as RetentionState, policyId: 'platform-default-retention' }
  }
  const expiry = at + periodDays * 86_400_000
  const daysLeft = daysBetween(now, expiry)
  const state: RetentionState = daysLeft < 0 ? 'expired' : daysLeft <= 90 ? 'expiring' : 'active'
  return { periodDays, expiresAt: new Date(expiry).toISOString(), state, policyId: 'platform-default-retention' }
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface EvidenceInputs {
  now: number
  assetById: Map<string, Row>
  complianceEvidence: Row[]
  scanSessions: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  vulnerabilities: Row[]
  scannerAlerts: Row[]
  scannerEvidence: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  generatedKeys: Row[]
  runtimeEvents: Row[]
  migrationJobs: Row[]
  vaultFiles: Row[]
  vaultAuditLogs: Row[]
  auditLogs: Row[]
  /** evidenceId → anchored digest. Null when the anchor store is unavailable. */
  anchors: Map<string, { digest: string; anchoredAt: string | null }> | null
  /** Bound on how many rows of each class become evidence records. */
  caps?: Partial<Record<EvidenceKind, number>>
}

const DEFAULT_CAPS: Record<EvidenceKind, number> = {
  attestation: 600,
  scan: 200,
  finding: 700,
  inventory: 500,
  certificate: 400,
  key: 300,
  runtime: 400,
  migration: 300,
  vault: 300,
  audit: 600,
  policy: 100,
}

function severityFrom(value: unknown): GovernanceSeverity | null {
  const text = str(value).toLowerCase()
  if (text.includes('critical')) return 'critical'
  if (text.includes('high')) return 'high'
  if (text.includes('medium') || text.includes('moderate')) return 'medium'
  if (text.includes('low') || text.includes('info')) return 'low'
  return null
}

/* ------------------------------------------------------------------ */
/* Builder                                                             */
/* ------------------------------------------------------------------ */

/**
 * Normalises every governance-relevant tenant row into the unified evidence
 * model, computing integrity, retention, freshness and custody for each.
 *
 * The `controlIds` on each record are the platform's mapping of an evidence
 * CLASS to the controls it can support — the control evaluators separately
 * decide whether that evidence actually satisfies the control. Frameworks and
 * requirements are then derived from the controls through the catalog, so the
 * traceability chain is never hand-maintained in two places.
 */
export function buildEvidence(inputs: EvidenceInputs): EvidenceRecord[] {
  const { now, anchors } = inputs
  const caps = { ...DEFAULT_CAPS, ...(inputs.caps || {}) }
  const records: EvidenceRecord[] = []

  const assetName = (assetId: unknown, fallback = ''): string => {
    const asset = inputs.assetById.get(str(assetId))
    return str(asset?.name) || fallback
  }

  const push = (input: {
    id: string
    kind: EvidenceKind
    title: string
    description: string
    statusLabel?: string | null
    outcome: EvidenceRecord['outcome']
    severity?: GovernanceSeverity | null
    table: string
    recordId: string
    collector: string
    actor?: string
    actorType?: EvidenceRecord['actorType']
    occurredAt: string | null
    recordedAt?: string | null
    assetId?: string | null
    scanId?: string | null
    findingId?: string | null
    controlIds: string[]
    frameworkIds?: string[]
    policyIds?: string[]
    href?: string | null
    /** Fields whose change should invalidate the integrity digest. */
    digestPayload: Record<string, unknown>
    custody?: EvidenceCustodyEntry[]
  }) => {
    const occurredAt = input.occurredAt
    const { state: freshness, ageDays } = freshnessOf(occurredAt, now)
    const controlIds = [...new Set(input.controlIds)]
    const derivedFrameworks = new Set<string>(input.frameworkIds || [])
    const requirementIds = new Set<string>()
    for (const controlId of controlIds) {
      for (const frameworkId of FRAMEWORKS_BY_CONTROL.get(controlId) || []) derivedFrameworks.add(frameworkId)
      for (const requirementId of REQUIREMENTS_BY_CONTROL.get(controlId) || []) requirementIds.add(requirementId)
    }

    records.push({
      id: input.id,
      kind: input.kind,
      title: input.title,
      description: input.description,
      statusLabel: input.statusLabel ?? null,
      outcome: input.outcome,
      severity: input.severity ?? null,
      source: { table: input.table, recordId: input.recordId, collector: input.collector },
      actor: input.actor || 'QGuard Helix platform',
      actorType: input.actorType || 'platform',
      occurredAt,
      recordedAt: input.recordedAt ?? occurredAt,
      assetId: input.assetId ?? null,
      assetName: input.assetId ? assetName(input.assetId, 'Unmapped asset') : null,
      scanId: input.scanId ?? null,
      findingId: input.findingId ?? null,
      controlIds,
      frameworkIds: [...derivedFrameworks],
      requirementIds: [...requirementIds],
      policyIds: input.policyIds || [],
      integrity: buildIntegrity(input.id, input.digestPayload, anchors, now),
      retention: retentionFor(input.kind, occurredAt, now),
      freshness,
      ageDays,
      custody:
        input.custody ||
        [
          {
            at: occurredAt,
            actor: input.actor || 'QGuard Helix platform',
            action: 'observed',
            source: input.collector,
          },
        ],
      href: input.href ?? null,
    })
  }

  /* ---- Stored attestations (the only human-recorded evidence) ------ */
  for (const row of inputs.complianceEvidence.slice(0, caps.attestation)) {
    const framework = str(row.framework)
    const frameworkId = resolveFrameworkId(framework)
    const status = str(row.status)
    const passing = /pass|met|compliant|approved|complete|accepted|verified/i.test(status) && !/non[-\s]?compliant|fail/i.test(status)
    push({
      id: `attestation:${str(row.id)}`,
      kind: 'attestation',
      title: `${framework || 'Framework'} ${str(row.control_id)}`.trim() || 'Compliance attestation',
      description: str(row.description) || `Recorded ${str(row.evidence_type) || 'attestation'} evidence.`,
      statusLabel: status || null,
      outcome: passing ? 'supporting' : /fail|non[-\s]?compliant|gap/i.test(status) ? 'contradicting' : 'informational',
      table: 'compliance_evidence',
      recordId: str(row.id),
      collector: 'compliance attestation',
      actorType: 'user',
      actor: 'Tenant attestation',
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      assetId: str(row.asset_id) || null,
      controlIds: ['CTL-EVD-02', 'CTL-EVD-01', 'CTL-AUD-04'],
      frameworkIds: frameworkId ? [frameworkId] : [],
      href: '/dashboard/regulatory-mapping',
      digestPayload: {
        framework,
        controlId: str(row.control_id),
        status,
        evidenceType: str(row.evidence_type),
        description: str(row.description),
        assetId: str(row.asset_id),
        updatedAt: str(row.updated_at),
      },
      custody: [
        { at: isoOrNull(row.created_at), actor: 'Tenant attestation', action: 'recorded', source: 'compliance_evidence' },
        ...(ms(row.updated_at) > ms(row.created_at)
          ? [{ at: isoOrNull(row.updated_at), actor: 'Tenant attestation', action: 'updated', source: 'compliance_evidence' }]
          : []),
      ],
    })
  }

  /* ---- Discovery scans -------------------------------------------- */
  for (const row of inputs.scanSessions.slice(0, caps.scan)) {
    const status = str(row.status).toLowerCase()
    const findings = num(row.findings_count)
    const failed = /fail|error|cancel|blocked/.test(status)
    push({
      id: `scan:${str(row.id)}`,
      kind: 'scan',
      title: failed ? 'Discovery scan failed' : /complete/.test(status) ? 'Discovery scan completed' : 'Discovery scan in progress',
      description: `${num(row.scanned_assets)}/${num(row.total_assets)} target(s) scanned · ${findings} finding${findings === 1 ? '' : 's'}${str(row.target_scope) ? ` · scope ${str(row.target_scope)}` : ''}`,
      statusLabel: str(row.status) || null,
      outcome: failed ? 'contradicting' : 'supporting',
      severity: failed ? 'high' : null,
      table: 'pqc_scan_sessions',
      recordId: str(row.id),
      collector: 'PQC scanner',
      actorType: 'platform',
      occurredAt: isoOrNull(row.completed_at || row.updated_at || row.started_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      scanId: str(row.id),
      controlIds: ['CTL-MON-01', 'CTL-INV-01', 'CTL-EVD-01'],
      href: '/dashboard/scanner',
      digestPayload: {
        status: str(row.status),
        findings,
        totalAssets: num(row.total_assets),
        scannedAssets: num(row.scanned_assets),
        completedAt: str(row.completed_at),
      },
    })
  }

  /* ---- Findings (the contradicting evidence class) ----------------- */
  const pushFinding = (row: Row, table: string, collector: string, options: {
    title: string
    description: string
    severity: GovernanceSeverity | null
    status: string
    assetId: string | null
    occurredAt: string | null
    recordedAt: string | null
    controlIds: string[]
    href: string
    digestPayload: Record<string, unknown>
  }) => {
    const resolved = /resolved|closed|fixed|remediated|mitigated|false[_\s-]?positive|accepted|suppressed/i.test(options.status)
    push({
      id: `finding:${table}:${str(row.id)}`,
      kind: 'finding',
      title: options.title,
      description: options.description,
      statusLabel: options.status || null,
      outcome: resolved ? 'supporting' : 'contradicting',
      severity: options.severity,
      table,
      recordId: str(row.id),
      collector,
      actorType: 'platform',
      occurredAt: options.occurredAt,
      recordedAt: options.recordedAt,
      assetId: options.assetId,
      findingId: str(row.id),
      controlIds: options.controlIds,
      href: options.href,
      digestPayload: options.digestPayload,
    })
  }

  for (const row of inputs.scanResults.slice(0, Math.floor(caps.finding * 0.4))) {
    pushFinding(row, 'pqc_scan_results', 'PQC scanner', {
      title: `${str(row.algorithm) || 'Quantum-vulnerable algorithm'} detected`,
      description: str(row.description) || str(row.finding_type) || 'Scanner finding.',
      severity: severityFrom(row.threat_level),
      status: 'open',
      assetId: str(row.asset_id) || null,
      occurredAt: isoOrNull(row.created_at),
      recordedAt: isoOrNull(row.created_at),
      controlIds: ['CTL-PQC-01', 'CTL-VUL-01', 'CTL-ALG-01'],
      href: '/dashboard/quantum-readiness/risk-analysis',
      digestPayload: {
        algorithm: str(row.algorithm),
        threatLevel: str(row.threat_level),
        findingType: str(row.finding_type),
        assetId: str(row.asset_id),
      },
    })
  }

  for (const row of inputs.vulnerabilities.slice(0, Math.floor(caps.finding * 0.25))) {
    pushFinding(row, 'vulnerabilities', 'vulnerability intelligence', {
      title: str(row.title) || 'Vulnerability finding',
      description: str(row.description) || `Source: ${str(row.source) || 'unknown'}`,
      severity: severityFrom(row.severity),
      status: str(row.status) || 'open',
      assetId: str(row.asset_id) || null,
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      controlIds: ['CTL-VUL-01', 'CTL-VUL-02'],
      href: '/dashboard/quantum-readiness/risk-analysis',
      digestPayload: {
        title: str(row.title),
        severity: str(row.severity),
        status: str(row.status),
        assetId: str(row.asset_id),
      },
    })
  }

  for (const row of inputs.cryptoExposures.slice(0, Math.floor(caps.finding * 0.2))) {
    pushFinding(row, 'crypto_exposures', 'crypto exposure engine', {
      title: str(row.exposure_type) || 'Cryptographic exposure',
      description: str(row.description) || str(row.detected_value) || 'Cryptographic exposure recorded.',
      severity: severityFrom(row.severity),
      status: 'open',
      assetId: str(row.asset_id) || null,
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      controlIds: ['CTL-ALG-01', 'CTL-VUL-01'],
      href: '/dashboard/crypto-exposure',
      digestPayload: {
        exposureType: str(row.exposure_type),
        severity: str(row.severity),
        detectedValue: str(row.detected_value),
        assetId: str(row.asset_id),
      },
    })
  }

  for (const row of inputs.scannerAlerts.slice(0, Math.floor(caps.finding * 0.15))) {
    pushFinding(row, 'scanner_alerts', 'collector agent', {
      title: str(row.title) || str(row.category) || 'Collector alert',
      description: str(row.message) || str(row.recommendation) || 'Collector alert recorded.',
      severity: severityFrom(row.severity),
      status: str(row.status) || 'open',
      assetId: null,
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      controlIds: ['CTL-MON-03', 'CTL-VUL-01'],
      href: '/dashboard/scanner?tab=agents',
      digestPayload: {
        title: str(row.title),
        severity: str(row.severity),
        status: str(row.status),
        category: str(row.category),
      },
    })
  }

  /* ---- Inventory --------------------------------------------------- */
  for (const row of inputs.cryptoInventory.slice(0, caps.inventory)) {
    const quantumSafe = row.is_quantum_safe === true
    push({
      id: `inventory:${str(row.id)}`,
      kind: 'inventory',
      title: str(row.name) || str(row.algorithm) || 'Cryptographic component',
      description: `${str(row.item_type) || 'component'}${str(row.algorithm) ? ` · ${str(row.algorithm)}` : ''}${num(row.key_size) ? ` · ${num(row.key_size)} bits` : ''}`,
      statusLabel: quantumSafe ? 'quantum-safe' : row.is_vulnerable === true ? 'quantum-vulnerable' : null,
      outcome: row.is_vulnerable === true && !quantumSafe ? 'contradicting' : 'supporting',
      table: 'crypto_inventory',
      recordId: str(row.id),
      collector: 'CBOM discovery',
      occurredAt: isoOrNull(row.discovered_at || row.created_at),
      assetId: str(row.asset_id) || null,
      controlIds: ['CTL-INV-01', 'CTL-INV-02', 'CTL-ALG-01', 'CTL-ALG-02', 'CTL-PQC-01'],
      href: '/dashboard/cbom-explorer',
      digestPayload: {
        algorithm: str(row.algorithm),
        keySize: num(row.key_size),
        protocol: str(row.protocol),
        isVulnerable: row.is_vulnerable === true,
        isQuantumSafe: quantumSafe,
        assetId: str(row.asset_id),
      },
    })
  }

  /* ---- Certificates ------------------------------------------------ */
  for (const row of inputs.certificates.slice(0, caps.certificate)) {
    const expiry = ms(row.not_after)
    const expired = Boolean(expiry) && expiry < now
    push({
      id: `certificate:${str(row.id)}`,
      kind: 'certificate',
      title: str(row.name) || str(row.subject) || 'Certificate',
      description: `${str(row.algorithm) || 'algorithm not recorded'}${str(row.issuer) ? ` · issued by ${str(row.issuer)}` : ''}${expiry ? ` · expires ${new Date(expiry).toISOString().slice(0, 10)}` : ''}`,
      statusLabel: str(row.status) || (expired ? 'expired' : null),
      outcome: expired || row.is_expiring_soon === true ? 'contradicting' : 'supporting',
      severity: expired ? 'critical' : row.is_expiring_soon === true ? 'high' : null,
      table: 'certificates',
      recordId: str(row.id),
      collector: 'PKI discovery',
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      assetId: str(row.asset_id) || null,
      controlIds: ['CTL-CRT-01', 'CTL-CRT-02', 'CTL-CRT-03'],
      href: '/dashboard/pki-visibility',
      digestPayload: {
        subject: str(row.subject),
        issuer: str(row.issuer),
        algorithm: str(row.algorithm),
        keySize: num(row.key_size),
        notAfter: str(row.not_after),
        status: str(row.status),
      },
    })
  }

  /* ---- Keys -------------------------------------------------------- */
  for (const row of inputs.generatedKeys.slice(0, caps.key)) {
    const status = str(row.status) || 'active'
    push({
      id: `key:${str(row.id)}`,
      kind: 'key',
      title: str(row.algorithm) || 'Managed key',
      description: `${num(row.bit_length) ? `${num(row.bit_length)} bits · ` : ''}entropy ${str(row.entropy_source) || 'not recorded'} · status ${status}`,
      statusLabel: status,
      outcome: /revoked|compromised|expired/i.test(status) ? 'contradicting' : 'supporting',
      table: 'generated_keys',
      recordId: str(row.id),
      collector: 'QKMS',
      occurredAt: isoOrNull(row.updated_at || row.created_at),
      controlIds: ['CTL-KEY-01', 'CTL-KEY-02', 'CTL-KEY-03'],
      href: '/dashboard/qkms/inventory',
      digestPayload: {
        algorithm: str(row.algorithm),
        bitLength: num(row.bit_length),
        status,
        entropySource: str(row.entropy_source),
        expiresAt: str(row.expires_at),
        revokedAt: str(row.revoked_at),
      },
      custody: [
        { at: isoOrNull(row.created_at), actor: 'QKMS', action: 'generated', source: 'generated_keys' },
        ...(row.rotated_from ? [{ at: isoOrNull(row.created_at), actor: 'QKMS', action: 'rotated from predecessor', source: 'generated_keys' }] : []),
        ...(row.revoked_at ? [{ at: isoOrNull(row.revoked_at), actor: 'QKMS', action: 'revoked', source: 'generated_keys' }] : []),
      ],
    })
  }

  /* ---- Runtime telemetry ------------------------------------------- */
  for (const row of inputs.runtimeEvents.slice(0, caps.runtime)) {
    const risky = row.is_legacy === true || row.downgrade_detected === true || row.shadow_crypto === true
    push({
      id: `runtime:${str(row.id)}`,
      kind: 'runtime',
      title: str(row.event_type) || str(row.operation_type) || 'Runtime cryptographic observation',
      description: `${str(row.asset_name) || str(row.host) || 'endpoint'}${str(row.tls_version) ? ` · ${str(row.tls_version)}` : ''}${str(row.algorithm) || str(row.cipher_suite) ? ` · ${str(row.algorithm) || str(row.cipher_suite)}` : ''}`,
      statusLabel: risky ? 'policy deviation' : 'observed',
      outcome: risky ? 'contradicting' : 'supporting',
      severity: severityFrom(row.severity),
      table: 'runtime_crypto_events',
      recordId: str(row.id),
      collector: 'runtime collector',
      actorType: 'agent',
      actor: str(row.agent_id) ? `Collector ${str(row.agent_id).slice(0, 8)}` : 'Runtime collector',
      occurredAt: isoOrNull(row.observed_at || row.created_at),
      assetId: str(row.asset_id) || null,
      controlIds: ['CTL-MON-02', 'CTL-TLS-01', 'CTL-TLS-02', 'CTL-DAT-02'],
      href: '/dashboard/runtime-crypto-intel',
      digestPayload: {
        eventType: str(row.event_type),
        tlsVersion: str(row.tls_version),
        algorithm: str(row.algorithm),
        cipherSuite: str(row.cipher_suite),
        isPqc: row.is_pqc === true,
        isLegacy: row.is_legacy === true,
        observedAt: str(row.observed_at),
      },
    })
  }

  /* ---- Migration (remediation evidence) ----------------------------- */
  for (const row of inputs.migrationJobs.slice(0, caps.migration)) {
    const status = str(row.status).toLowerCase()
    const complete = /complete|done|success|migrated/.test(status)
    push({
      id: `migration:${str(row.id)}`,
      kind: 'migration',
      title: complete ? 'Migration completed' : `Migration ${status || 'recorded'}`,
      description: `${str(row.name) || str(row.job_type) || 'Migration job'}${str(row.target_algorithm) ? ` → ${str(row.target_algorithm)}` : ''}`,
      statusLabel: str(row.status) || null,
      outcome: complete ? 'supporting' : /fail/.test(status) ? 'contradicting' : 'informational',
      severity: /fail/.test(status) ? 'high' : null,
      table: 'migration_jobs',
      recordId: str(row.id),
      collector: 'migration orchestrator',
      occurredAt: isoOrNull(row.completed_at || row.updated_at || row.created_at),
      recordedAt: isoOrNull(row.created_at),
      assetId: str(row.asset_id) || null,
      controlIds: ['CTL-PQC-02', 'CTL-PQC-05', 'CTL-VUL-01'],
      href: '/dashboard/live-migration',
      digestPayload: {
        status: str(row.status),
        targetAlgorithm: str(row.target_algorithm),
        assetId: str(row.asset_id),
        completedAt: str(row.completed_at),
      },
    })
  }

  /* ---- Vault objects ------------------------------------------------ */
  for (const row of inputs.vaultFiles.slice(0, caps.vault)) {
    const encrypted = /encrypted|complete|processed|sealed/i.test(str(row.encryption_status))
    push({
      id: `vault:${str(row.id)}`,
      kind: 'vault',
      title: str(row.original_filename) || 'Stored object',
      description: `${str(row.encryption_algorithm) || 'algorithm not recorded'} · ${str(row.encryption_status) || 'status not recorded'}`,
      statusLabel: str(row.encryption_status) || null,
      outcome: encrypted ? 'supporting' : 'contradicting',
      severity: encrypted ? null : 'high',
      table: 'vault_files',
      recordId: str(row.id),
      collector: 'Quantum Vault',
      actorType: 'user',
      actor: 'Vault owner',
      occurredAt: isoOrNull(row.updated_at || row.encrypted_at || row.uploaded_at || row.created_at),
      recordedAt: isoOrNull(row.uploaded_at || row.created_at),
      controlIds: ['CTL-DAT-01'],
      href: '/dashboard/encryption-monitoring',
      digestPayload: {
        filename: str(row.original_filename),
        encryptionStatus: str(row.encryption_status),
        encryptionAlgorithm: str(row.encryption_algorithm),
        signatureStatus: str(row.signature_status),
      },
      custody: [
        { at: isoOrNull(row.uploaded_at || row.created_at), actor: 'Vault owner', action: 'uploaded', source: 'vault_files' },
        ...(row.encrypted_at ? [{ at: isoOrNull(row.encrypted_at), actor: 'Quantum Vault', action: 'encrypted', source: 'vault_files' }] : []),
      ],
    })
  }

  /* ---- Audit records as evidence ------------------------------------ */
  const auditCap = Math.floor(caps.audit / 2)
  for (const row of inputs.auditLogs.slice(0, auditCap)) {
    const details = recordOf(row.details)
    push({
      id: `audit:audit_logs:${str(row.id)}`,
      kind: 'audit',
      title: str(row.action) || 'Audit record',
      description: `${str(row.entity_type) || 'entity'}${str(row.entity_id) ? ` ${str(row.entity_id).slice(0, 8)}` : ''}`,
      outcome: /fail|denied|error/i.test(`${str(row.action)} ${JSON.stringify(details)}`) ? 'contradicting' : 'supporting',
      table: 'audit_logs',
      recordId: str(row.id),
      collector: 'platform audit log',
      actorType: 'user',
      actor: 'Tenant user',
      occurredAt: isoOrNull(row.created_at),
      controlIds: ['CTL-AUD-01', 'CTL-AUD-02', 'CTL-AUD-04'],
      href: '/dashboard/audit-vault',
      digestPayload: {
        action: str(row.action),
        entityType: str(row.entity_type),
        entityId: str(row.entity_id),
        createdAt: str(row.created_at),
        details,
      },
    })
  }
  for (const row of inputs.vaultAuditLogs.slice(0, auditCap)) {
    const metadata = recordOf(row.metadata)
    const result = str(row.result || row.status || metadata.result || metadata.status)
    push({
      id: `audit:vault_audit_logs:${str(row.id)}`,
      kind: 'audit',
      title: str(row.event_type) || str(row.operation) || 'Vault audit record',
      description: str(row.description || row.details) || `${str(row.resource_type) || 'vault resource'}`,
      statusLabel: result || null,
      outcome: /fail|denied|error|destroy/i.test(`${str(row.event_type)} ${result}`) ? 'contradicting' : 'supporting',
      table: 'vault_audit_logs',
      recordId: str(row.id),
      collector: 'vault audit log',
      actorType: 'user',
      actor: 'Vault owner',
      occurredAt: isoOrNull(row.created_at),
      controlIds: ['CTL-AUD-01', 'CTL-AUD-02', 'CTL-AUD-04'],
      href: '/dashboard/audit-vault',
      digestPayload: {
        eventType: str(row.event_type),
        result,
        resourceType: str(row.resource_type),
        createdAt: str(row.created_at),
      },
    })
  }

  records.sort((a, b) => ms(b.occurredAt) - ms(a.occurredAt))
  return records
}
