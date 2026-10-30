import { randomUUID } from 'crypto'
import { Router, Request, Response, NextFunction } from 'express'
import type { SupabaseClient } from '@supabase/supabase-js'
import { createAuthClient, getServerUser, getToken } from '@/lib/supabase-server'
import { streamLiveSnapshot } from './live-snapshot-stream'
import { createSourceLedger, type SourceLedger } from './source-ledger'
import { probeIdentityInfrastructure } from '@/lib/scanner/identity/identity-probe'
import { assetProbeTarget, buildIdentityModel } from '@/lib/pqauth/identity-model'
import { identityReportToRows } from '@/lib/pqauth/identity-persistence'
import type {
  PQAuthActiveRun,
  PQAuthAlgorithmExposure,
  PQAuthComplianceRow,
  PQAuthCountRow,
  PQAuthMode,
  PQAuthRow,
  PQAuthRuntimeMetric,
  PQAuthSnapshot,
  PQAuthSourceHealth,
} from '@/types/pqauth-dashboard'

/**
 * PQAuth™ Identity Migration Engine — API.
 *
 *   GET  /api/v1/dashboard/pqauth[/:mode]      one tenant snapshot (all modes share it)
 *   GET  /api/v1/dashboard/pqauth/stream       live snapshot (SSE, fingerprint de-duplicated)
 *   POST /api/v1/dashboard/pqauth/discovery/run  probe the tenant's authorized hosts for identity metadata
 *
 * Audit fixes carried by this file (see qguard-common-issues-fixes):
 *   • The bearer token is read from the Authorization header ONLY. The old
 *     `?token=` fallback let the stream and REST routes skip the Pro
 *     subscription gate, which reads only the header.
 *   • Rows leave through `projectRow`, an allow-list. Spreading raw rows sent
 *     session-token hashes, agent token hashes, IPs and user agents to the
 *     browser and into the JSON export.
 *   • Pattern matching reads descriptive fields only (`structuredText`), never
 *     the whole row: hex hashes and UUIDs made "F5" and "Entra" appear in
 *     tenants that run neither.
 *   • The stream is fingerprinted. It used to emit an update every 8 s whether
 *     or not anything changed, so each open tab re-downloaded ~1 MB.
 */

type AuthedRequest = Request & {
  user?: { id: string; email?: string | null }
  token?: string
}

const MODES = new Set<PQAuthMode>([
  'overview',
  'discovery',
  'trust-graph',
  'token-intelligence',
  'exposure-analysis',
  'compatibility',
  'digital-twin',
  'migration-center',
  'runtime-telemetry',
  'compliance',
  'qkms',
])

const ALGORITHM_PATTERNS = [
  { id: 'rsa', label: 'RSA', family: 'Classical public-key', regex: /\bRSA(?:[-_\s]?(1024|2048|3072|4096))?\b|\b(RS|PS)(256|384|512)\b/i, replacement: 'ML-DSA for signatures; ML-KEM for key establishment', risk: 'Shor-vulnerable' },
  { id: 'ecdsa', label: 'ECDSA', family: 'Certificate and token signatures', regex: /\bECDSA\b|\bES(256|384|512)\b/i, replacement: 'ML-DSA signing', risk: 'Shor-vulnerable' },
  { id: 'eddsa', label: 'EdDSA', family: 'Token signatures', regex: /\bEdDSA\b|\bEd25519\b|\bEd448\b/i, replacement: 'ML-DSA signing', risk: 'Shor-vulnerable' },
  { id: 'ecdh', label: 'ECDH / X25519', family: 'Key agreement', regex: /\bECDHE?\b|\bX25519\b(?!\s*\+?\s*ML-?KEM)|\bX448\b/i, replacement: 'ML-KEM (hybrid X25519MLKEM768 during transition)', risk: 'Shor-vulnerable' },
  { id: 'dh', label: 'Finite-field DH', family: 'Key agreement', regex: /\bDHE?\b(?!-)|\bdiffie[-\s]?hellman\b/i, replacement: 'ML-KEM key establishment', risk: 'Shor-vulnerable' },
] as const

const COMPLIANCE_FRAMEWORKS = [
  'NIST CSF',
  'NIST SP 800-208',
  'NIST IR 8547',
  'NSA CNSA 2.0',
  'PCI-DSS',
  'ISO 27001',
  'SOC 2',
  'FedRAMP',
] as const

/* ------------------------------------------------------------------ */
/* Auth — Authorization header only                                    */
/* ------------------------------------------------------------------ */

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = getToken(req)
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }
  const user = await getServerUser(token)
  if (!user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  }
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function recordOf(value: unknown): Record<string, unknown> {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function textValue(value: unknown, fallback = '') {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function dateMs(value: unknown) {
  const ms = new Date(String(value || '')).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function latestDate(...values: unknown[]) {
  const valid = values.map(dateMs).filter(Boolean).sort((a, b) => b - a)
  return valid.length ? new Date(valid[0]).toISOString() : null
}

function rowTimestamp(row: any) {
  return row?.observed_at
    || row?.last_seen_at
    || row?.updated_at
    || row?.completed_at
    || row?.discovered_at
    || row?.created_at
    || row?.timestamp
}

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function severityRank(value: unknown) {
  const lower = String(value || '').toLowerCase()
  if (lower.includes('critical')) return 4
  if (lower.includes('high')) return 3
  if (lower.includes('medium') || lower.includes('moderate')) return 2
  if (lower.includes('low') || lower.includes('info')) return 1
  return 0
}

/**
 * The descriptive fields of a row — what a person would read. Pattern matching
 * runs against this, never against the serialised row: ids, hashes and
 * fingerprints contain substrings ("f5", "dh", "rsa") that are not evidence.
 */
function structuredText(row: any): string {
  const metadata = recordOf(row?.metadata)
  return [
    row?.name, row?.title, row?.algorithm, row?.asset_name, row?.finding_type, row?.event_type,
    row?.operation_type, row?.category, row?.type, row?.description, row?.message, row?.detail,
    row?.framework, row?.control, row?.requirement, row?.key_exchange_algorithm, row?.protocol,
    metadata.algorithm, metadata.framework, metadata.control,
  ].filter((v) => typeof v === 'string' && v).join(' ')
}

const EMAIL_RE = /([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g

/** Data minimisation for free text that may carry an identity: mask local parts. */
function minimise(value: unknown, max = 240): string | null {
  const text = typeof value === 'string' ? value.trim() : ''
  if (!text) return null
  return text.replace(EMAIL_RE, '$1•••@$2').slice(0, max)
}

/**
 * Allow-list projection. A source row is NEVER spread into the payload:
 * user_sessions carries session_token_hash, scanner_agents token_hash, and
 * several tables ip_address / user_agent / session_id.
 */
function projectRow(row: any, sourceTable: string): PQAuthRow {
  const metadata = recordOf(row?.metadata)
  const name = textValue(row?.name, textValue(row?.title, textValue(row?.asset_name, textValue(metadata.name, textValue(row?.event_type, sourceTable.replace(/_/g, ' '))))))
  return {
    id: textValue(row?.id, `${sourceTable}:${name}`),
    sourceTable,
    name: minimise(name, 160) || sourceTable,
    type: textValue(row?.type, textValue(row?.asset_type, textValue(row?.finding_type, textValue(row?.operation_type, textValue(row?.category))))) || null,
    status: textValue(row?.status) || null,
    severity: textValue(row?.severity, textValue(row?.threat_level, textValue(row?.risk_level))) || null,
    algorithm: textValue(row?.algorithm) || null,
    assetId: textValue(row?.asset_id, textValue(metadata.assetId, textValue(metadata.asset_id))) || null,
    detail: minimise(row?.description ?? row?.message ?? row?.detail ?? row?.evidence),
    lastUpdated: rowTimestamp(row) || null,
  }
}

/** Sources shown in the page's evidence strip, in display order, with their labels. */
const SOURCE_LABELS: Array<[string, string]> = [
  ['assets', 'Asset inventory'],
  ['identity_providers', 'Identity providers'],
  ['identity_signing_keys', 'Identity signing keys'],
  ['identity_trust_relationships', 'Identity trust'],
  ['identity_discovery_probes', 'Discovery probes'],
  ['certificates', 'Certificates'],
  ['migration_jobs', 'Migration jobs'],
  ['runtime_crypto_events', 'Runtime crypto events'],
  ['crypto_inventory', 'Crypto inventory'],
  ['crypto_exposures', 'Crypto exposures'],
  ['asset_relationships', 'Asset relationships'],
  ['auth_events', 'Auth events'],
  ['compliance_evidence', 'Compliance evidence'],
  ['qkms_keys', 'QKMS keys'],
]

/**
 * The evidence strip, from the platform's source ledger (#64): a failed read
 * is `unavailable` — its empty list is not a measurement of zero.
 */
function sourceHealthFrom(ledger: SourceLedger, rowsByTable: Map<string, any[]>): PQAuthSourceHealth[] {
  const byKey = new Map(ledger.reads.map((read) => [read.key, read]))
  return SOURCE_LABELS.flatMap(([table, label]) => {
    const read = byKey.get(table)
    if (!read) return []
    return [{
      id: table,
      label,
      table,
      count: read.rows,
      latestAt: latestDate(...(rowsByTable.get(table) ?? []).map(rowTimestamp)),
      state: read.state,
    }]
  })
}

const PQC_ALGORITHM_RE = /ml-?kem|ml-?dsa|slh-?dsa|sphincs|kyber|dilithium|falcon/i

/** PQC-ready ONLY from an explicit flag or a named PQC algorithm — never from the word "pqc". */
function isPqcReady(row: any) {
  return row?.is_quantum_safe === true || row?.pqc_ready === true || PQC_ALGORITHM_RE.test(textValue(row?.algorithm))
}

function isClassical(row: any) {
  return !isPqcReady(row) && ALGORITHM_PATTERNS.some((pattern) => pattern.regex.test(`${textValue(row?.algorithm)} ${textValue(row?.name)}`))
}

function buildAlgorithms(rows: Array<{ row: any; table: string }>): PQAuthAlgorithmExposure[] {
  return ALGORITHM_PATTERNS
    .map((algorithm) => {
      const matches = rows.filter(({ row }) => algorithm.regex.test(structuredText(row)))
      return {
        id: algorithm.id,
        label: algorithm.label,
        family: algorithm.family,
        replacement: algorithm.replacement,
        risk: algorithm.risk,
        count: matches.length,
        sourceTables: Array.from(new Set(matches.map(({ table }) => table))),
        latestAt: latestDate(...matches.map(({ row }) => rowTimestamp(row))),
      }
    })
    .filter((algorithm) => algorithm.count > 0)
}

/* ------------------------------------------------------------------ */
/* Evidence-honesty derivations (pure — covered by tools/pqauth-check)  */
/* ------------------------------------------------------------------ */

/**
 * A framework is scored only from evidence that names THAT framework.
 * Previously an unmatched framework borrowed the tenant's unrelated
 * compliance/audit/security row count and presented it as its own evidence,
 * attributing other frameworks' records to this one. Unmatched now reports Not
 * Assessed with zero evidence, as the governance contract requires.
 */
export function deriveComplianceRows(complianceEvidence: Array<Record<string, unknown>>, complianceBase: number): PQAuthComplianceRow[] {
  return COMPLIANCE_FRAMEWORKS.map((framework) => {
    const regex = new RegExp(framework.replace(/[.\s-]+/g, '.*'), 'i')
    const matches = complianceEvidence.filter((row) => regex.test(structuredText(row)))
    const assessed = matches.length > 0
    return {
      id: framework.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      label: framework,
      score: assessed ? clamp(complianceBase + Math.min(10, matches.length * 3)) : 0,
      evidence: assessed ? `${matches.length} evidence record(s)` : 'No framework-specific evidence',
      evidenceCount: matches.length,
      sourceTables: assessed ? Array.from(new Set(matches.map((row) => String(row.sourceTable || 'compliance_evidence')))) : [],
      latestAt: assessed ? latestDate(...matches.map(rowTimestamp)) : null,
      assessed,
    }
  })
}

/**
 * Runtime identity telemetry — MEASURED ONLY.
 *
 * These five tiles describe what the identity layer DID at runtime, so each is
 * derived from runtime/auth event rows only. Static inventory counts
 * (certificates held, vulnerable components discovered, algorithms present) are
 * deliberately NOT substituted: doing so previously published the
 * quantum-vulnerable-algorithm count as "Trust Failures" and the vulnerable
 * component count as "Identity Drift", inventing runtime failures that were
 * never observed. With no runtime evidence the tiles report unmeasured and the
 * UI shows "Awaiting telemetry" rather than a zero that reads as clean.
 */
export function deriveRuntimeMetrics(runtimeIdentityRows: Array<Record<string, unknown>>, runtimeEvents: Array<Record<string, unknown>>): PQAuthRuntimeMetric[] {
  const truthy = (value: unknown) => value === true || value === 'true' || value === 1 || value === '1'
  const hasIdentityTelemetry = runtimeIdentityRows.length > 0
  const tokenValidationEvents = runtimeIdentityRows.filter((row) => /jwt|jws|jwe|token|assertion|sign|verify|introspect/i.test(structuredText(row))).length
  const certificateUsageEvents = new Set(
    runtimeEvents.map((row) => String(row.certificate_fingerprint || '')).filter((fingerprint) => fingerprint.length > 0),
  ).size
  const trustFailureEvents = runtimeIdentityRows.filter(
    (row) => truthy(row.downgrade_detected) || /fail|failure|error|denied|reject|invalid|expired|revoked|untrusted|unauthori/i.test(`${structuredText(row)} ${String(row.status || '')}`),
  ).length
  const identityDriftEvents = runtimeIdentityRows.filter(
    (row) => truthy(row.shadow_crypto) || truthy(row.is_legacy) || /drift|unexpected|unapproved|policy.?violation|deviat/i.test(structuredText(row)),
  ).length
  return [
    { id: 'runtime-events', label: 'Runtime Events', value: runtimeIdentityRows.length, detail: 'authentication, authorization, session and token events observed', measured: hasIdentityTelemetry },
    { id: 'token-validation', label: 'Token Validation', value: tokenValidationEvents, detail: 'JWT, JWS, JWE and assertion operations observed at runtime', measured: hasIdentityTelemetry },
    { id: 'certificate-usage', label: 'Certificate Usage', value: certificateUsageEvents, detail: 'distinct certificates actually presented in runtime events', measured: runtimeEvents.length > 0 },
    { id: 'trust-failures', label: 'Trust Failures', value: trustFailureEvents, detail: 'downgrades, rejections and validation failures observed', measured: hasIdentityTelemetry },
    { id: 'identity-drift', label: 'Identity Drift', value: identityDriftEvents, detail: 'shadow or legacy cryptography observed on identity paths', measured: hasIdentityTelemetry },
  ]
}

function countRow(id: string, label: string, count: number, detail: string, sourceTables: string[], status?: string): PQAuthCountRow {
  return { id, label, count, detail, sourceTables, status: status ?? (count > 0 ? 'active' : 'waiting') }
}

/* ------------------------------------------------------------------ */
/* Identity discovery runs (in-process)                                */
/* ------------------------------------------------------------------ */

/** Hosts probed per run — each costs ≤ 5 well-known requests + 1 JWKS fetch per provider. */
const MAX_HOSTS_PER_RUN = 25
const RUN_CONCURRENCY = 3
/** A finished run stays visible this long so the page can show its outcome. */
const RUN_VISIBLE_MS = 5 * 60 * 1000
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Runs execute in this API process. One run per tenant at a time: a second
 * request while one is in flight is refused (409) rather than doubling the
 * outbound probe traffic against the same hosts.
 */
const activeRuns = new Map<string, PQAuthActiveRun>()

function visibleRun(userId: string): PQAuthActiveRun | null {
  const run = activeRuns.get(userId)
  if (!run) return null
  if (run.status === 'running') return { ...run }
  if (run.finishedAt && Date.now() - dateMs(run.finishedAt) <= RUN_VISIBLE_MS) return { ...run }
  return null
}

async function recordAudit(client: SupabaseClient, userId: string, action: string, runId: string, details: Record<string, unknown>) {
  const { error } = await client.from('audit_logs').insert({
    user_id: userId,
    action,
    entity_type: 'identity_discovery',
    entity_id: UUID_RE.test(runId) ? runId : null,
    details,
  })
  if (error) console.warn('[pqauth] audit insert failed:', error.message)
}

async function persistIdentityReport(client: SupabaseClient, write: ReturnType<typeof identityReportToRows>): Promise<number> {
  if (write.probes.length) {
    const { error } = await client.from('identity_discovery_probes').insert(write.probes)
    if (error) throw new Error(`identity_discovery_probes: ${error.message}`)
  }
  let providers = 0
  for (const provider of write.providers) {
    const { data, error } = await client
      .from('identity_providers')
      .upsert(provider.row, { onConflict: 'user_id,issuer' })
      .select('id')
      .single()
    if (error || !data) throw new Error(`identity_providers: ${error?.message || 'no id returned'}`)
    providers += 1
    const providerId = (data as { id: string }).id
    if (provider.keys.length) {
      const { error: keyError } = await client
        .from('identity_signing_keys')
        .upsert(provider.keys.map((key) => ({ ...key, provider_id: providerId })), { onConflict: 'provider_id,key_id' })
      if (keyError) throw new Error(`identity_signing_keys: ${keyError.message}`)
    }
    if (provider.declaredTrust) {
      const trust: Record<string, unknown> = { ...provider.declaredTrust, target_provider_id: providerId }
      const { data: existing } = await client
        .from('identity_trust_relationships')
        .select('id')
        .eq('user_id', String(trust.user_id))
        .eq('source_asset_id', String(trust.source_asset_id))
        .eq('target_provider_id', providerId)
        .eq('relationship_type', 'TRUSTS')
        .limit(1)
      const existingId = (existing as Array<{ id: string }> | null)?.[0]?.id
      const { error: trustError } = existingId
        ? await client.from('identity_trust_relationships').update({ evidence: trust.evidence, source_url: trust.source_url, last_seen_at: trust.last_seen_at }).eq('id', existingId)
        : await client.from('identity_trust_relationships').insert(trust)
      if (trustError) throw new Error(`identity_trust_relationships: ${trustError.message}`)
    }
  }
  return providers
}

async function executeRun(token: string, userId: string, run: PQAuthActiveRun, targets: Array<{ assetId: string; host: string }>) {
  const client = createAuthClient(token)
  if (!client) {
    run.status = 'failed'
    run.error = 'Database connection failed'
    run.finishedAt = new Date().toISOString()
    return
  }
  const failures: string[] = []
  const queue = [...targets]
  const worker = async () => {
    for (let target = queue.shift(); target; target = queue.shift()) {
      run.currentHost = target.host
      try {
        const report = await probeIdentityInfrastructure(target.host)
        const write = identityReportToRows(report, {
          userId,
          assetId: target.assetId,
          assetHost: target.host,
          runId: run.runId,
          observedAt: new Date().toISOString(),
        })
        run.providersFound += await persistIdentityReport(client, write)
      } catch (error: any) {
        failures.push(`${target.host}: ${error?.message || 'probe failed'}`)
        console.warn('[pqauth] identity discovery failed for', target.host, error?.message || error)
      } finally {
        run.hostsDone += 1
        invalidateSnapshot(userId)
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(RUN_CONCURRENCY, targets.length) }, worker))
  run.currentHost = null
  run.finishedAt = new Date().toISOString()
  run.status = failures.length === targets.length ? 'failed' : 'completed'
  run.error = failures.length ? `${failures.length} host(s) could not be recorded: ${failures.slice(0, 2).join('; ')}` : null
  invalidateSnapshot(userId)
  await recordAudit(client, userId, 'pqauth.identity_discovery.completed', run.runId, {
    hosts: targets.length,
    providers_found: run.providersFound,
    failures: failures.length,
  })
}

/* ------------------------------------------------------------------ */
/* Snapshot                                                            */
/* ------------------------------------------------------------------ */

async function buildPQAuthSnapshot(token: string, userId: string): Promise<PQAuthSnapshot> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Database connection failed')
  const own = (q: any) => q.eq('user_id', userId)
  const tenant = (q: any) => q.eq('tenant_id', userId)
  const ledger = createSourceLedger('PQAuth')
  const rowsByTable = new Map<string, any[]>()
  // Every read goes through the shared ledger, so a failed query is published
  // as `unavailable` rather than as zero rows.
  const read = async (table: string, limit: number, build: (query: any) => any): Promise<any[]> => {
    const label = SOURCE_LABELS.find(([key]) => key === table)?.[1] ?? table
    const rows = await ledger.read(client, table, label, limit, (q: any) => build(q.select('*')).limit(limit))
    rowsByTable.set(table, rows)
    return rows
  }

  const [
    assets, relationships, cryptoInventory, cryptoExposures, vulnerabilities, certificates, generatedKeys,
    runtimeEvents, scannerAlerts, scanResults, migrationJobs, complianceEvidence, securityEvents, authEvents,
    userSessions, userSecurityEvents, qkmsKeys, qkmsRotationJobs,
    identityProviders, identitySigningKeys, identityTrust, identityProbes,
  ] = await Promise.all([
    read('assets', 2500, (q) => own(q).order('updated_at', { ascending: false })),
    read('asset_relationships', 1800, (q) => own(q).order('created_at', { ascending: false })),
    read('crypto_inventory', 3000, (q) => own(q).order('discovered_at', { ascending: false })),
    read('crypto_exposures', 2500, (q) => own(q).order('updated_at', { ascending: false })),
    read('vulnerabilities', 2200, (q) => own(q).order('updated_at', { ascending: false })),
    read('certificates', 2200, (q) => own(q).order('updated_at', { ascending: false })),
    read('generated_keys', 2200, (q) => own(q).order('created_at', { ascending: false })),
    read('runtime_crypto_events', 5000, (q) => own(q).order('observed_at', { ascending: false })),
    read('scanner_alerts', 1800, (q) => own(q).order('created_at', { ascending: false })),
    read('pqc_scan_results', 3000, (q) => own(q).order('created_at', { ascending: false })),
    read('migration_jobs', 1400, (q) => own(q).order('updated_at', { ascending: false })),
    read('compliance_evidence', 1800, (q) => own(q).order('updated_at', { ascending: false })),
    read('security_events', 1800, (q) => own(q).order('created_at', { ascending: false })),
    read('auth_events', 1800, (q) => own(q).order('created_at', { ascending: false })),
    read('user_sessions', 1200, (q) => own(q).order('last_seen_at', { ascending: false })),
    read('user_security_events', 1200, (q) => own(q).order('created_at', { ascending: false })),
    read('qkms_keys', 1800, (q) => tenant(q).order('updated_at', { ascending: false })),
    read('qkms_rotation_jobs', 1200, (q) => tenant(q).order('updated_at', { ascending: false })),
    read('identity_providers', 500, (q) => own(q).order('last_seen_at', { ascending: false })),
    read('identity_signing_keys', 2000, (q) => own(q).order('last_seen_at', { ascending: false })),
    read('identity_trust_relationships', 2000, (q) => own(q).order('last_seen_at', { ascending: false })),
    read('identity_discovery_probes', 3000, (q) => own(q).order('observed_at', { ascending: false })),
  ])

  const identity = buildIdentityModel({
    assets: assets,
    providers: identityProviders,
    signingKeys: identitySigningKeys,
    trustRelationships: identityTrust,
    probes: identityProbes,
    assetRelationships: relationships,
    certificates: certificates,
    migrationJobs: migrationJobs,
    runtimeEvents: runtimeEvents,
    activeRun: visibleRun(userId),
  })

  /* ---- Estate crypto (Exposure Analysis) ---------------------------- */
  const componentRows = [
    ...cryptoInventory.map((row) => ({ row, table: 'crypto_inventory' })),
    ...certificates.map((row) => ({ row, table: 'certificates' })),
    ...generatedKeys.map((row) => ({ row, table: 'generated_keys' })),
    ...qkmsKeys.map((row) => ({ row, table: 'qkms_keys' })),
  ]
  const findingRows = [
    ...cryptoExposures.map((row) => ({ row, table: 'crypto_exposures' })),
    ...vulnerabilities.map((row) => ({ row, table: 'vulnerabilities' })),
    ...scannerAlerts.map((row) => ({ row, table: 'scanner_alerts' })),
    ...scanResults.map((row) => ({ row, table: 'pqc_scan_results' })),
  ]
  const algorithms = buildAlgorithms([...componentRows, ...findingRows])
  const vulnerableComponents = componentRows.filter(({ row }) => isClassical(row))
  const pqcReadyComponents = componentRows.filter(({ row }) => isPqcReady(row)).length
  const exposureRows = [
    ...vulnerableComponents,
    ...findingRows.filter(({ row }) => ALGORITHM_PATTERNS.some((p) => p.regex.test(structuredText(row)))),
  ]
    .sort((a, b) => dateMs(rowTimestamp(b.row)) - dateMs(rowTimestamp(a.row)))
    .slice(0, 80)
    .map(({ row, table }) => projectRow(row, table))

  /* ---- Runtime identity telemetry ------------------------------------ */
  const identityPath = /auth|jwt|token|sign|verify|certificate|identity|session|saml|oidc|oauth/i
  const runtimeIdentity = [
    ...runtimeEvents.filter((row) => identityPath.test(structuredText(row))).map((row) => ({ row, table: 'runtime_crypto_events' })),
    ...authEvents.map((row) => ({ row, table: 'auth_events' })),
    ...userSessions.map((row) => ({ row, table: 'user_sessions' })),
    ...userSecurityEvents.map((row) => ({ row, table: 'user_security_events' })),
    ...securityEvents.filter((row) => /auth|identity|session|token|mfa/i.test(structuredText(row))).map((row) => ({ row, table: 'security_events' })),
  ].sort((a, b) => dateMs(rowTimestamp(b.row)) - dateMs(rowTimestamp(a.row)))
  const runtimeMetrics = deriveRuntimeMetrics(runtimeIdentity.map(({ row }) => row), runtimeEvents)

  /* ---- Compliance ------------------------------------------------------ */
  const readinessScore = componentRows.length ? clamp((pqcReadyComponents / componentRows.length) * 100) : 0
  const complianceRows = deriveComplianceRows(
    complianceEvidence.map((row) => ({ ...row, sourceTable: 'compliance_evidence' })),
    readinessScore,
  )

  /* ---- QKMS identity key domains (key tables only) -------------------- */
  const keyRows = [...qkmsKeys, ...generatedKeys]
  const keyMatches = (regex: RegExp) => keyRows.filter((row) => regex.test(`${structuredText(row)} ${textValue(row.purpose)} ${textValue(row.key_usage)} ${textValue(row.usage)}`)).length
  const qkmsKeyDomains = [
    countRow('signing-keys', 'Signing Keys', keyMatches(/sign|ml-dsa|slh-dsa|ecdsa|eddsa|\brs\d|\bes\d/i), 'keys whose recorded purpose or algorithm is signing', ['qkms_keys', 'generated_keys']),
    countRow('identity-provider-keys', 'Identity Provider Keys', identity.tokens.keys.filter((k) => k.lifecycle === 'published').length, 'public JWKS keys observed by identity discovery', ['identity_signing_keys']),
    countRow('tls-keys', 'TLS / Key-Establishment Keys', keyMatches(/tls|ml-kem|kyber|x25519|ecdh|key.?exchange/i), 'keys whose recorded purpose or algorithm is key establishment', ['qkms_keys', 'generated_keys']),
    countRow('certificate-keys', 'Certificates', certificates.length, 'certificates in the tenant inventory', ['certificates']),
    countRow('machine-identity-keys', 'Machine Identity Keys', keyMatches(/machine|workload|service.?account|device|agent/i), 'keys recorded for workloads, devices or service accounts', ['qkms_keys', 'generated_keys']),
  ]
  const certAndKeys = [...certificates, ...keyRows]
  const lifecycleControls = [
    countRow('ownership', 'Ownership', keyRows.filter((row) => textValue(row.owner) || textValue(row.owner_id) || textValue(row.service_owner)).length, 'keys with a recorded owner', ['qkms_keys', 'generated_keys']),
    countRow('rotation', 'Rotation', qkmsRotationJobs.length, 'recorded rotation jobs', ['qkms_rotation_jobs']),
    countRow('expiration', 'Expiration', certAndKeys.filter((row) => row.not_after || row.expires_at || row.expiration_date).length, 'certificates and keys with a recorded expiry', ['certificates', 'qkms_keys', 'generated_keys']),
    countRow('revocation', 'Revocation', certAndKeys.filter((row) => /revoked|disabled|compromised|destroyed/i.test(textValue(row.status))).length, 'revoked, disabled or compromised material', ['certificates', 'qkms_keys', 'generated_keys']),
    countRow('pqc-readiness', 'PQC Readiness', pqcReadyComponents, 'components with an explicit PQC flag or a named PQC algorithm', ['crypto_inventory', 'certificates', 'qkms_keys', 'generated_keys']),
  ]

  const hasEvidence = [assets, identityProviders, identityProbes, cryptoInventory, certificates, runtimeEvents].some((read) => read.length > 0)

  return {
    generatedAt: new Date().toISOString(),
    mode: 'tenant',
    hasEvidence,
    identity,
    algorithms,
    exposureRows,
    runtimeEvents: runtimeIdentity.slice(0, 60).map(({ row, table }) => projectRow(row, table)),
    runtimeMetrics,
    complianceRows,
    qkmsKeyDomains,
    lifecycleControls,
    sourceHealth: sourceHealthFrom(ledger, rowsByTable),
    metrics: {
      totalAssets: assets.length,
      totalComponents: componentRows.length,
      totalFindings: findingRows.length,
      criticalFindings: findingRows.filter(({ row }) => severityRank(row.severity ?? row.threat_level ?? row.risk_level) >= 4).length,
      vulnerableComponents: vulnerableComponents.length,
      pqcReadyComponents,
      classicalExposureSignals: algorithms.reduce((sum, a) => sum + a.count, 0),
      certificateSignals: certificates.length,
      qkmsKeySignals: keyRows.length,
    },
  }
}

/* Per-tenant single-flight cache. Every mode reads the same snapshot, so a
 * user moving between the seven pages (or with several tabs open) builds it
 * once per TTL instead of once per request. */
const SNAPSHOT_TTL_MS = 15_000
const snapshotCache = new Map<string, { at: number; promise: Promise<PQAuthSnapshot> }>()

function invalidateSnapshot(userId: string) {
  snapshotCache.delete(userId)
}

function cachedSnapshot(token: string, userId: string, force = false): Promise<PQAuthSnapshot> {
  const cached = snapshotCache.get(userId)
  if (!force && cached && Date.now() - cached.at < SNAPSHOT_TTL_MS) return cached.promise
  const promise = buildPQAuthSnapshot(token, userId)
  snapshotCache.set(userId, { at: Date.now(), promise })
  // A failed build is never cached.
  promise.catch(() => {
    if (snapshotCache.get(userId)?.promise === promise) snapshotCache.delete(userId)
  })
  return promise
}

/* ------------------------------------------------------------------ */
/* Routes                                                              */
/* ------------------------------------------------------------------ */

const router = Router()
router.use(requireAuth)

router.get('/stream', (req: AuthedRequest, res: Response) => {
  if (!req.user || !req.token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  }
  const { token } = req
  const userId = req.user.id
  streamLiveSnapshot(req, res, {
    event: 'pqauth-update',
    // Cached: most ticks are a cache read; a discovery run invalidates the
    // cache after every host, so its progress reaches the page within a tick.
    build: () => cachedSnapshot(token, userId),
    intervalMs: 5_000,
  })
})

router.post('/discovery/run', async (req: AuthedRequest, res: Response) => {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    const userId = req.user.id
    const current = activeRuns.get(userId)
    if (current?.status === 'running') {
      return res.status(409).json({ error: { code: 'DISCOVERY_RUNNING', message: 'An identity discovery run is already in progress for this tenant.' }, data: current })
    }

    const requested = (req.body as { assetIds?: unknown } | undefined)?.assetIds
    if (requested !== undefined && (!Array.isArray(requested) || requested.length > MAX_HOSTS_PER_RUN || !requested.every((id) => typeof id === 'string' && UUID_RE.test(id)))) {
      return res.status(400).json({ error: { code: 'INVALID_ASSETS', message: `assetIds must be an array of at most ${MAX_HOSTS_PER_RUN} asset UUIDs.` } })
    }

    const client = createAuthClient(req.token)
    if (!client) return res.status(500).json({ error: { code: 'DB_UNAVAILABLE', message: 'Database connection failed' } })
    // Only the caller's own assets are probe candidates (user_id filter + RLS).
    let query = client.from('assets').select('id,name,type,metadata').eq('user_id', userId)
    if (Array.isArray(requested) && requested.length) query = query.in('id', requested as string[])
    const { data: assets, error } = await query.limit(2500)
    if (error) return res.status(500).json({ error: { code: 'ASSETS_UNAVAILABLE', message: error.message } })

    const seen = new Set<string>()
    const targets: Array<{ assetId: string; host: string }> = []
    for (const asset of assets || []) {
      const target = assetProbeTarget(asset)
      if (!target.eligible || !target.host || seen.has(target.host)) continue
      seen.add(target.host)
      targets.push({ assetId: String((asset as { id: string }).id), host: target.host })
    }
    if (!targets.length) {
      return res.status(422).json({ error: { code: 'NO_ELIGIBLE_TARGETS', message: 'None of the selected assets has a public hostname that identity discovery may probe.' } })
    }
    const selected = targets.slice(0, MAX_HOSTS_PER_RUN)

    const run: PQAuthActiveRun = {
      runId: randomUUID(),
      status: 'running',
      startedAt: new Date().toISOString(),
      finishedAt: null,
      hostsTotal: selected.length,
      hostsDone: 0,
      currentHost: null,
      providersFound: 0,
      error: targets.length > selected.length ? `${targets.length - selected.length} further host(s) exceed the ${MAX_HOSTS_PER_RUN}-host limit for one run.` : null,
    }
    activeRuns.set(userId, run)
    invalidateSnapshot(userId)
    await recordAudit(client, userId, 'pqauth.identity_discovery.started', run.runId, { hosts: selected.map((t) => t.host) })

    void executeRun(req.token, userId, run, selected).catch((err) => {
      run.status = 'failed'
      run.error = err instanceof Error ? err.message : 'Discovery run failed'
      run.finishedAt = new Date().toISOString()
      invalidateSnapshot(userId)
    })
    return res.status(202).json({ data: run })
  } catch (error: any) {
    console.error('PQAuth discovery run error:', error)
    return res.status(500).json({ error: { code: 'DISCOVERY_FAILED', message: error?.message || 'Failed to start identity discovery' } })
  }
})

async function serveSnapshot(req: AuthedRequest, res: Response, mode: string) {
  try {
    if (!req.user || !req.token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
    if (!MODES.has(mode as PQAuthMode)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'PQAuth page not found' } })
    }
    const data = await cachedSnapshot(req.token, req.user.id, req.query.refresh === '1')
    return res.json({ data: { ...data, mode } })
  } catch (error: any) {
    console.error('PQAuth dashboard error:', error)
    return res.status(500).json({ error: { code: 'PQAUTH_SNAPSHOT_FAILED', message: error?.message || 'Failed to fetch PQAuth dashboard data' } })
  }
}

router.get('/', (req: AuthedRequest, res: Response) => serveSnapshot(req, res, 'overview'))
router.get('/:mode', (req: AuthedRequest, res: Response) => serveSnapshot(req, res, String(req.params.mode || 'overview')))

export default router
