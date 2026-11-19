/**
 * Encryption Monitoring engine — data-protection intelligence.
 *
 * Pure and isomorphic, like the TLS/PKI engine: the Express router, the
 * dashboard and any offline check tool run the SAME function over the SAME
 * rows.
 *
 * ── Boundary with the TLS/PKI suite ────────────────────────────────────────
 * These two consoles read the same tenant tables and must not double-count.
 * The split is by WHAT THE PRIMITIVE PROTECTS:
 *
 *   TLS Telemetry / Protocol Analytics / PKI Visibility
 *       protocol versions · cipher-suite negotiation · key agreement ·
 *       signatures · certificates                                (TRANSPORT)
 *
 *   Encryption Monitoring (this module)
 *       standalone symmetric ciphers · hashes · MACs · KDFs ·
 *       key material · data-at-rest policy · vault · application crypto (DATA)
 *
 * A TLS cipher suite is therefore NOT decomposed into this page. Its bulk
 * cipher is a transport fact owned by Protocol Analytics, and pulling
 * `AES_256_GCM` out of `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` to count here is
 * both a double count and the precise move that once made the platform publish
 * AES-256-GCM as a critical quantum vulnerability.
 *
 * ── Counting discipline ────────────────────────────────────────────────────
 * `crypto_inventory`, `scanner_evidence` and `runtime_crypto_events` are
 * OBSERVATION stores. `crypto_exposures`, `pqc_scan_results` and
 * `scanner_alerts` are three storage views of one finding and are merged on
 * `findingIdentityKey`, never summed. The previous page summed all seven and
 * reported 564 "events" on a 2-asset tenant.
 */

import { analyzeCryptoObservation } from '@/lib/crypto/suite-anatomy'
import { findingIdentityKey, namesCryptography, observationClass } from '@/lib/scanner/finding-identity'
import type { AssetMigrationRecord } from '@/lib/migration/asset-intelligence'
import { STRENGTH_LABEL, matchesCnsa2Primitive, needsAction, severityForStrength, strengthOf, UNKNOWN_STRENGTH } from './strength'
import type {
  AlgorithmRow,
  AtRestCoverage,
  AtRestRecord,
  DataProtectionPosture,
  EncryptionFinding,
  EncryptionIntelligence,
  EncryptionObservation,
  EvidenceRef,
  EvidenceSource,
  KeyInventory,
  KeyLifecycle,
  KeyRecord,
  OperationProfile,
  PipelineStatus,
  ProtectionLayer,
  RiskLevel,
  Severity,
  StrengthProfile,
  TelemetryHealth,
  VaultProtection,
} from './types'

type Row = Record<string, unknown>

const DAY_MS = 86_400_000

/* ------------------------------------------------------------------ */
/* Local scalar helpers                                                */
/* ------------------------------------------------------------------ */

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

function recordOf(value: unknown): Record<string, unknown> {
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {}
    } catch {
      return {}
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

function isoOrNull(value: unknown): string | null {
  const ms = Date.parse(str(value))
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null
}

function dateMs(value: unknown): number {
  const ms = Date.parse(str(value))
  return Number.isFinite(ms) ? ms : 0
}

function latestIso(...values: unknown[]): string | null {
  let best = 0
  for (const value of values) {
    const ms = dateMs(value)
    if (ms > best) best = ms
  }
  return best ? new Date(best).toISOString() : null
}

function percentOf(value: number, total: number): number {
  return total > 0 ? clamp((value / total) * 100) : 0
}

function pick(record: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = str(record[key])
    if (value) return value
  }
  return ''
}

function normalizeSeverity(value: unknown): Severity {
  const lower = str(value).toLowerCase()
  if (lower.includes('critical')) return 'critical'
  if (lower.includes('high') || lower === 'error' || lower === 'failed') return 'high'
  if (lower.includes('medium') || lower.includes('moderate') || lower === 'warning') return 'medium'
  return 'low'
}

function severityRank(value: Severity | null | undefined): number {
  if (value === 'critical') return 4
  if (value === 'high') return 3
  if (value === 'medium') return 2
  if (value === 'low') return 1
  return 0
}

function riskLevelFor(score: number): RiskLevel {
  if (score <= 0) return 'none'
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

function uniq<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function titleCase(value: unknown, fallback = ''): string {
  const text = str(value).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return fallback
  return text.replace(/\b\w/g, (char) => char.toUpperCase())
}

/* ------------------------------------------------------------------ */
/* Layer classification                                                */
/* ------------------------------------------------------------------ */

const KDF_RE = /PBKDF2|ARGON2|SCRYPT|BCRYPT|\bHKDF\b|\bKDF\b|PASSWORD[-_ ]?HASH/i

/**
 * A bare protocol version, which belongs to the transport console.
 *
 * A library manifest or config file can DECLARE a protocol ("TLS 1.2"), and the
 * application-evidence branch would otherwise file it as application crypto —
 * putting a protocol version in an algorithm inventory with no strength verdict
 * that could meaningfully attach to it.
 */
function isProtocolName(value: string): boolean {
  const text = str(value).trim()
  return /^(TLS|SSL|DTLS)[-_ ]?v?\d(\.\d)?$/i.test(text) || /^(TLS|SSL|HTTPS|SSH|QUIC)$/i.test(text)
}
const MAC_RE = /HMAC|POLY1305|\bCMAC\b|\bGMAC\b|\bMAC\b/i

const STORAGE_ENCRYPTION_EVIDENCE = new Set([
  'cloud-storage-encryption-policy',
  'cloud-database-crypto-policy',
  'database-crypto-policy',
  'container-crypto-policy',
])

const AT_REST_EVIDENCE = new Set([
  ...STORAGE_ENCRYPTION_EVIDENCE,
  'cloud-kms-policy',
  'cloud-hsm-policy',
  'hsm-integration',
  'cloud-iam-key-policy',
])

/** Agent evidence types that describe crypto declared by application code. */
const APPLICATION_EVIDENCE = new Set(['crypto-library', 'package-manifest', 'jwt-algorithm', 'config-reference'])

/** Scanner observation classes this page owns. Transport classes are excluded. */
const OWNED_OBSERVATION_CLASSES = new Set(['symmetric encryption', 'hash', 'mac', 'kdf'])

/**
 * Which data-protection layer a named primitive belongs to, or `null` when the
 * primitive belongs to the TLS/PKI suite instead.
 *
 * Returning `null` for transport primitives is what keeps the two consoles from
 * counting the same observation twice.
 */
function layerFor(algorithm: string, itemType: string, componentName: string): ProtectionLayer | null {
  const value = str(algorithm)
  if (!value) return null

  const type = str(itemType).toLowerCase()
  if (type === 'library') return 'application'

  // A scanner record carries its own class prefix; trust it when present.
  const cls = observationClass(componentName)
  if (cls === 'certificate' || cls === 'certificate signature' || cls === 'key exchange' || cls === 'post-quantum key agreement') return null
  if (cls === 'protocol' || cls === 'protocol support' || cls === 'cipher suite') return null

  if (KDF_RE.test(value)) return 'kdf'
  if (MAC_RE.test(value)) return 'mac'

  // Ask the canonical decomposer what this actually is. A cipher-suite string
  // is transport and is declined here.
  const anatomy = analyzeCryptoObservation(
    { algorithm: value, name: componentName || undefined, itemType },
    componentName ? namesCryptography(componentName) : true,
  )
  if (anatomy.kind === 'symmetric') return 'symmetric'
  if (anatomy.kind === 'hash') return type === 'hash' || /HASH|DIGEST/i.test(componentName) ? 'hash' : 'hash'
  // Everything else — cipher-suite, key-exchange, signature, certificate,
  // protocol, policy — is owned elsewhere.
  return null
}

/** Canonical display label for a primitive, so one algorithm is one row. */
function canonicalAlgorithm(value: string): string {
  const text = str(value)
    .replace(/\s*\((certificate|signature|key exchange|cipher suite|symmetric encryption|hash)\)\s*$/i, '')
    .replace(/[_]+/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
  if (!text) return 'Unknown'
  const upper = text.toUpperCase()
  // Fold the spellings the sources produce for the same primitive.
  if (/^AES-?256-?GCM$/.test(upper)) return 'AES-256-GCM'
  if (/^AES-?128-?GCM$/.test(upper)) return 'AES-128-GCM'
  if (/^AES-?256-?CBC$/.test(upper)) return 'AES-256-CBC'
  if (/^AES-?128-?CBC$/.test(upper)) return 'AES-128-CBC'
  if (/^CHACHA20-?POLY1305$/.test(upper)) return 'ChaCha20-Poly1305'
  if (/^SHA-?(\d{3})$/.test(upper)) return `SHA-${upper.match(/(\d{3})/)![1]}`
  if (/^SHA3-?(\d{3})$/.test(upper)) return `SHA3-${upper.match(/(\d{3})/)![1]}`
  if (/^SHA-?1$/.test(upper)) return 'SHA-1'
  if (/^MD5$/.test(upper)) return 'MD5'
  return text
}

/* ------------------------------------------------------------------ */
/* Inputs                                                              */
/* ------------------------------------------------------------------ */

export interface EncryptionInputs {
  assets: AssetMigrationRecord[]
  snapshot: {
    quantumReadiness: number
    quantumRisk: number
    quantumRiskLevel: string
    hndlRisk: number
    hndlRiskLevel: string
    assetsAssessed: number
  }
  cryptoInventory: Row[]
  runtimeEvents: Row[]
  scannerEvidence: Row[]
  generatedKeys: Row[]
  vaultFiles: Row[]
  cryptoExposures: Row[]
  scanResults: Row[]
  scannerAlerts: Row[]
  securityEvents: Row[]
  scanSessions: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  truncated?: boolean
  now?: number
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildEncryptionIntelligence(inputs: EncryptionInputs): EncryptionIntelligence {
  const now = inputs.now ?? Date.now()
  const assetById = new Map(inputs.assets.map((asset) => [asset.id, asset]))
  const assetByName = new Map<string, AssetMigrationRecord | null>()
  for (const asset of inputs.assets) {
    const name = asset.name.trim().toLowerCase()
    if (name) assetByName.set(name, assetByName.has(name) ? null : asset)
  }

  const resolveAsset = (assetId: unknown, name: unknown) => {
    const id = str(assetId)
    if (id) return assetById.get(id) ?? null
    return assetByName.get(str(name).trim().toLowerCase()) ?? null
  }

  /* ---------------------------------------------------------------- */
  /* 1. Observations                                                   */
  /* ---------------------------------------------------------------- */

  const observations: EncryptionObservation[] = []
  const seen = new Set<string>()

  const addObservation = (input: {
    layer: ProtectionLayer
    algorithm: string
    assetId: string | null
    assetName: string
    location: string
    operation: string | null
    observedAt: string | null
    evidence: EvidenceRef
    occurrences?: number
  }) => {
    const label = canonicalAlgorithm(input.algorithm)
    if (!label || label === 'Unknown') return

    // One primitive per (layer, algorithm, asset, location). The same AES-256
    // reported by a scan and by an agent on the same file is one observation.
    const key = `${input.layer}|${label.toLowerCase()}|${input.assetId || input.assetName}|${input.location.toLowerCase()}`
    const existing = observations.find((row) => row.id === `obs:${key}`)
    if (existing) {
      existing.occurrences += input.occurrences ?? 1
      existing.observedAt = latestIso(existing.observedAt, input.observedAt)
      if (!existing.operation && input.operation) existing.operation = input.operation
      return
    }
    if (seen.has(key)) return
    seen.add(key)

    const anatomy = analyzeCryptoObservation({ algorithm: label }, true)
    observations.push({
      id: `obs:${key}`,
      layer: input.layer,
      observed: label,
      family: anatomy.family || label,
      strength: strengthOf(label, input.layer),
      assetId: input.assetId,
      assetName: input.assetName,
      location: input.location,
      operation: input.operation,
      occurrences: input.occurrences ?? 1,
      observedAt: input.observedAt,
      evidence: input.evidence,
    })
  }

  /* ---- crypto_inventory: the scanner's component inventory --------- */
  for (const item of inputs.cryptoInventory) {
    const metadata = recordOf(item.metadata)
    const componentName = str(item.name)
    const algorithm = str(item.algorithm)
    const layer = layerFor(algorithm, str(item.item_type), componentName)
    if (!layer) continue

    const asset = resolveAsset(item.asset_id, pick(metadata, ['assetName', 'target']))
    const observedAt = isoOrNull(item.discovered_at) || isoOrNull(item.created_at)

    addObservation({
      layer,
      algorithm,
      assetId: asset?.id ?? (str(item.asset_id) || null),
      assetName: asset?.name || pick(metadata, ['target', 'assetName']) || 'Unassigned',
      location: pick(metadata, ['location', 'target', 'file', 'path']) || componentName || 'Inventory',
      operation: null,
      observedAt,
      evidence: {
        source: 'crypto-inventory',
        recordId: str(item.id),
        table: 'crypto_inventory',
        observedAt,
        detail: componentName || `${layer} primitive`,
      },
    })
  }

  /* ---- runtime_crypto_events: operations on data ------------------- */
  let runtimeReportsOperations = false
  const operationCounts = new Map<string, number>()

  for (const event of inputs.runtimeEvents) {
    const operation = str(event.operation_type).toLowerCase()
    // Transport negotiation is owned by the TLS console.
    if (operation === 'key_exchange') continue

    const metadata = recordOf(event.metadata)
    if (metadata.observationKind === 'scan-evidence' || metadata.evidenceId || metadata.evidenceType ||
      metadata.evidenceClass === 'library-presence' || metadata.evidenceClass === 'certificate') continue
    const asset = resolveAsset(event.asset_id, event.asset_name)
    const observedAt = isoOrNull(event.observed_at) || isoOrNull(event.created_at)

    if (operation && operation !== 'other' && operation !== 'discovery') {
      runtimeReportsOperations = true
      operationCounts.set(operation, (operationCounts.get(operation) || 0) + 1)
    }

    const algorithm = str(event.algorithm)
    if (!algorithm) continue
    // Never take the cipher_suite column here — that is transport.
    if (algorithm === str(event.cipher_suite) || algorithm === str(event.tls_version)) continue

    const layer = layerFor(algorithm, '', str(event.event_type))
    if (!layer) continue

    addObservation({
      layer,
      algorithm,
      assetId: asset?.id ?? null,
      assetName: asset?.name || str(event.asset_name) || str(event.host) || 'Unassigned',
      location: str(event.process_name) || str(event.host) || pick(metadata, ['file', 'path']) || 'Runtime',
      operation: operation && operation !== 'other' ? operation : null,
      observedAt,
      evidence: {
        source: 'runtime-telemetry',
        recordId: str(event.id),
        table: 'runtime_crypto_events',
        observedAt,
        detail: `${titleCase(event.event_type, 'Runtime observation')}${operation ? ` · ${titleCase(operation)}` : ''}`,
      },
    })
  }

  /* ---- scanner_evidence: agent observations ------------------------ */
  const atRestRecords: AtRestRecord[] = []

  for (const item of inputs.scannerEvidence) {
    const evidenceType = str(item.evidence_type).toLowerCase()
    const raw = recordOf(item.raw_evidence)
    const binding = recordOf(raw.binding)
    const asset = resolveAsset(item.asset_id || (binding.attribution === 'bound' ? binding.assetId : null), item.asset_name)
    const observedAt = isoOrNull(item.observed_at) || isoOrNull(item.processed_at) || isoOrNull(item.created_at)
    const algorithm = str(item.observed_algorithm)

    const evidence: EvidenceRef = {
      source: 'agent-scan',
      recordId: str(item.id),
      table: 'scanner_evidence',
      observedAt,
      detail: `${titleCase(item.evidence_type, 'Agent evidence')} on ${str(item.asset_name) || str(item.host) || 'host'}`,
    }

    /* At-rest and key-custody policy. */
    if (AT_REST_EVIDENCE.has(evidenceType)) {
      const encryptedRaw = raw.encrypted ?? raw.encryption_enabled ?? raw.encryptionEnabled ?? raw.atRestEncryption
      const encrypted = STORAGE_ENCRYPTION_EVIDENCE.has(evidenceType) && asset && observedAt && typeof encryptedRaw === 'boolean'
        ? encryptedRaw
        : null
      const strength = algorithm ? strengthOf(algorithm, 'at-rest') : null
      atRestRecords.push({
        id: `atrest:${str(item.id)}`,
        surface: titleCase(evidenceType.replace(/-/g, ' '), 'Storage surface'),
        assetId: asset?.id ?? null,
        assetName: asset?.name || str(item.asset_name) || str(item.target) || 'Unassigned',
        algorithm: algorithm || null,
        strength,
        encrypted,
        keyCustody:
          pick(raw, ['keyCustody', 'key_custody', 'keyManagement', 'key_management']) ||
          (/kms|hsm/.test(evidenceType) ? 'Provider-managed KMS/HSM' : 'Not recorded'),
        detail: pick(raw, ['detail', 'description', 'policy', 'summary']) || titleCase(evidenceType.replace(/-/g, ' ')),
        evidence,
        observedAt,
      })
      if (algorithm) {
        const layer = layerFor(algorithm, '', '')
        if (layer) {
          addObservation({
            layer,
            algorithm,
            assetId: asset?.id ?? null,
            assetName: asset?.name || str(item.asset_name) || 'Unassigned',
            location: titleCase(evidenceType.replace(/-/g, ' ')),
            operation: null,
            observedAt,
            evidence,
          })
        }
      }
      continue
    }

    /* Application-declared crypto — libraries, JWT algorithms, config. */
    if (APPLICATION_EVIDENCE.has(evidenceType)) {
      if (!algorithm || isProtocolName(algorithm)) continue
      addObservation({
        layer: 'application',
        algorithm,
        assetId: asset?.id ?? null,
        assetName: asset?.name || str(item.asset_name) || 'Unassigned',
        location: pick(raw, ['package', 'library', 'file', 'path', 'module']) || titleCase(evidenceType.replace(/-/g, ' ')),
        operation: null,
        observedAt,
        evidence,
      })
      continue
    }

    /* Anything else: include only when it names a primitive this page owns. */
    if (!algorithm) continue
    const layer = layerFor(algorithm, '', '')
    if (!layer) continue
    addObservation({
      layer,
      algorithm,
      assetId: asset?.id ?? null,
      assetName: asset?.name || str(item.asset_name) || 'Unassigned',
      location: str(item.target) || str(item.host) || 'Agent evidence',
      operation: null,
      observedAt,
      evidence,
    })
  }

  /* ---------------------------------------------------------------- */
  /* 2. Algorithm rollups                                              */
  /* ---------------------------------------------------------------- */

  const rollup = (layers: ProtectionLayer[]): AlgorithmRow[] => {
    const scoped = observations.filter((row) => layers.includes(row.layer))
    const total = scoped.length
    const groups = new Map<string, EncryptionObservation[]>()
    for (const row of scoped) {
      const bucket = groups.get(row.observed)
      if (bucket) bucket.push(row)
      else groups.set(row.observed, [row])
    }
    return [...groups.entries()]
      .map(([label, rows]) => ({
        label,
        layer: rows[0].layer,
        strength: rows[0].strength,
        observations: rows.reduce((sum, row) => sum + row.occurrences, 0),
        assetIds: uniq(rows.map((row) => row.assetId).filter(Boolean) as string[]),
        assetNames: uniq(rows.map((row) => row.assetName).filter(Boolean)),
        operations: uniq(rows.map((row) => row.operation).filter(Boolean) as string[]),
        percent: percentOf(rows.length, total),
        firstObservedAt: rows.map((row) => row.observedAt).filter(Boolean).sort()[0] ?? null,
        lastObservedAt: latestIso(...rows.map((row) => row.observedAt)),
        evidence: rows.slice(0, 6).map((row) => row.evidence),
      }))
      .sort((a, b) => b.observations - a.observations || a.label.localeCompare(b.label))
  }

  const symmetric = rollup(['symmetric'])
  const hashes = rollup(['hash'])
  const macs = rollup(['mac'])
  const kdfs = rollup(['kdf'])
  const application = rollup(['application'])

  /* ---------------------------------------------------------------- */
  /* 3. Key material                                                   */
  /* ---------------------------------------------------------------- */

  const keys = buildKeyInventory(inputs.generatedKeys, now)

  /* ---------------------------------------------------------------- */
  /* 4. Data at rest + vault                                           */
  /* ---------------------------------------------------------------- */

  const atRest = buildAtRestCoverage(atRestRecords, inputs.assets.length)
  const vault = buildVaultProtection(inputs.vaultFiles)

  /* ---------------------------------------------------------------- */
  /* 5. Operations                                                     */
  /* ---------------------------------------------------------------- */

  const operations = buildOperationProfile({
    runtimeEvents: inputs.runtimeEvents,
    counts: operationCounts,
    measured: runtimeReportsOperations,
    now,
  })

  /* ---------------------------------------------------------------- */
  /* 6. Findings                                                       */
  /* ---------------------------------------------------------------- */

  const findings = buildFindings({ observations, keys, atRest, vault, inputs, assetById })

  /* ---------------------------------------------------------------- */
  /* 7. Posture                                                        */
  /* ---------------------------------------------------------------- */

  const allRows = [...symmetric, ...hashes, ...macs, ...kdfs]
  const cnsaComparable = [...symmetric, ...hashes].filter((row) => row.strength.strength !== 'unknown')
  const cnsaAssessed = cnsaComparable.length
  const cnsaPassing = cnsaComparable.filter((row) => matchesCnsa2Primitive(row.label, row.layer)).length
  /*
   * Coverage counts DISTINCT TENANT ASSETS, never observation labels. Keying on
   * `assetId || assetName` counted hosts, process names and file paths as
   * assets and reported 8 "assets with evidence" on a 2-asset estate — a
   * coverage figure above 100% that the clamp then quietly hid.
   *
   * Observations that never resolved to a tenant asset are real evidence, so
   * they are reported separately rather than dropped or silently promoted.
   */
  const assetsWithEvidence = uniq(observations.map((row) => row.assetId).filter(Boolean) as string[]).length
  const unattributedObservations = observations.filter((row) => !row.assetId).length
  const assetsTotal = Math.max(inputs.snapshot.assetsAssessed, inputs.assets.length)

  const posture: DataProtectionPosture = {
    algorithmsObserved: allRows.length + application.length,
    observationsAnalysed: observations.length,
    quantumSafeAlgorithms: allRows.filter((row) => row.strength.strength === 'quantum-safe' || row.strength.strength === 'post-quantum').length,
    adequateAlgorithms: allRows.filter((row) => row.strength.strength === 'adequate').length,
    weakenedAlgorithms: allRows.filter((row) => row.strength.strength === 'weakened').length,
    quantumVulnerableAlgorithms: [...allRows, ...application].filter((row) => row.strength.strength === 'quantum-vulnerable').length,
    brokenAlgorithms: [...allRows, ...application].filter((row) => row.strength.strength === 'broken').length,
    cnsa2CompliancePercent: percentOf(cnsaPassing, cnsaAssessed),
    cnsa2Assessed: cnsaAssessed,
    keysManaged: keys.total,
    keysAtRisk: keys.keys.filter((key) => key.riskLevel === 'critical' || key.riskLevel === 'high').length,
    atRestAssetsCovered: atRest.assetsCovered,
    atRestCoveragePercent: atRest.coveragePercent,
    vaultFilesProtected: vault.encrypted,
    quantumReadinessScore: clamp(inputs.snapshot.quantumReadiness),
    quantumRiskScore: clamp(inputs.snapshot.quantumRisk),
    quantumRiskLevel: inputs.snapshot.quantumRiskLevel || 'Unknown',
    hndlRiskScore: clamp(inputs.snapshot.hndlRisk),
    hndlRiskLevel: inputs.snapshot.hndlRiskLevel || 'Unknown',
    assetsWithEvidence,
    assetsTotal,
    unattributedObservations,
    evidenceCoveragePercent: percentOf(assetsWithEvidence, Math.max(1, assetsTotal)),
  }

  /* ---------------------------------------------------------------- */
  /* 8. Telemetry health + timeline                                    */
  /* ---------------------------------------------------------------- */

  const telemetry = buildTelemetryHealth({ inputs, observations, now })
  const timeline = buildTimeline({ observations, runtimeEvents: inputs.runtimeEvents, findings, now })

  const latestEvidenceAt = latestIso(
    ...observations.slice(0, 200).map((row) => row.observedAt),
    telemetry.lastRuntimeEventAt,
    telemetry.lastScanAt,
    telemetry.lastKeyEventAt,
    telemetry.lastVaultActivityAt,
  )

  return {
    generatedAt: new Date(now).toISOString(),
    latestEvidenceAt,
    hasData: observations.length > 0 || keys.total > 0 || vault.files > 0 || atRest.records.length > 0,
    posture,
    observations,
    symmetric,
    hashes,
    macs,
    kdfs,
    application,
    keys,
    atRest,
    vault,
    operations,
    findings,
    telemetry,
    timeline,
  }
}

/* ================================================================== */
/* Key inventory                                                       */
/* ================================================================== */

function buildKeyInventory(rows: Row[], now: number): KeyInventory {
  const keys: KeyRecord[] = rows.map((row) => {
    const label = recordOf(row.label)
    const metadata = recordOf(row.metadata)
    const algorithm = str(row.algorithm).replace(/^PKI-/i, '') || 'Unknown'
    const bitLength = num(row.bit_length) || null
    const expiresAt = isoOrNull(row.expires_at)
    const revokedAt = isoOrNull(row.revoked_at)
    const daysToExpiry = expiresAt ? Math.floor((dateMs(expiresAt) - now) / DAY_MS) : null
    const status = str(row.status).toLowerCase()

    const lifecycle: KeyLifecycle = revokedAt || status === 'revoked'
      ? 'revoked'
      : status === 'rotated'
        ? 'rotated'
        : daysToExpiry !== null && daysToExpiry < 0
          ? 'expired'
          : daysToExpiry !== null && daysToExpiry <= 30
            ? 'expiring'
            : status === 'active' || !status
              ? 'active'
              : 'unknown'

    const strength = strengthOf(bitLength ? `${algorithm}-${bitLength}` : algorithm, 'key-material')
    // `quality_score` is stored 0-1 by the QRNG generator.
    const rawQuality = Number(row.quality_score)
    const qualityScore = Number.isFinite(rawQuality) && rawQuality > 0 ? Math.min(1, rawQuality) : null

    let riskScore = 8
    if (lifecycle === 'expired') riskScore = 92
    else if (lifecycle === 'revoked') riskScore = 70
    else if (lifecycle === 'expiring') riskScore = 58
    else if (lifecycle === 'unknown') riskScore = 30
    if (strength.strength === 'broken') riskScore += 25
    else if (strength.strength === 'weakened') riskScore += 15
    if (qualityScore !== null && qualityScore < 0.8) riskScore += 12
    if (!expiresAt) riskScore += 10
    riskScore = clamp(riskScore)

    return {
      id: str(row.id),
      label: pick(label, ['name', 'label', 'common_name']) || str(row.fingerprint).slice(0, 16) || 'Key',
      algorithm,
      bitLength,
      strength,
      entropySource: str(row.entropy_source) || 'Not recorded',
      qualityScore,
      lifecycle,
      createdAt: isoOrNull(row.created_at),
      expiresAt,
      daysToExpiry,
      revokedAt,
      rotatedFromId: str(row.rotated_from) || null,
      fingerprint: str(row.fingerprint) || pick(metadata, ['fingerprint']) || null,
      riskLevel: riskLevelFor(riskScore),
      riskScore,
    }
  })

  const lifecycle: Record<KeyLifecycle, number> = {
    active: 0,
    expiring: 0,
    expired: 0,
    revoked: 0,
    rotated: 0,
    unknown: 0,
  }
  for (const key of keys) lifecycle[key.lifecycle] += 1

  const sources = new Map<string, number>()
  for (const key of keys) sources.set(key.entropySource, (sources.get(key.entropySource) || 0) + 1)

  const qualities = keys.map((key) => key.qualityScore).filter((value): value is number => value !== null)

  return {
    measured: keys.length > 0,
    total: keys.length,
    keys: keys.sort((a, b) => b.riskScore - a.riskScore || a.label.localeCompare(b.label)),
    lifecycle,
    entropySources: [...sources.entries()]
      .map(([label, count]) => ({ label, count, percent: percentOf(count, keys.length) }))
      .sort((a, b) => b.count - a.count),
    // Only rotations with an actual `rotated_from` link. The previous page
    // reported 338 rotations on a tenant holding zero keys.
    rotationsObserved: keys.filter((key) => key.rotatedFromId).length,
    withoutExpiry: keys.filter((key) => !key.expiresAt).length,
    averageQuality: qualities.length ? qualities.reduce((sum, value) => sum + value, 0) / qualities.length : null,
  }
}

/* ================================================================== */
/* Data at rest                                                        */
/* ================================================================== */

function buildAtRestCoverage(records: AtRestRecord[], assetTotal: number): AtRestCoverage {
  const assetsCovered = new Set(records.filter((row) => row.encrypted !== null).map((row) => row.assetId).filter(Boolean)).size
  return {
    measured: assetsCovered > 0,
    records: records.sort((a, b) => (a.encrypted === false ? -1 : 1) - (b.encrypted === false ? -1 : 1)).slice(0, 200),
    encrypted: records.filter((row) => row.encrypted === true).length,
    unencrypted: records.filter((row) => row.encrypted === false).length,
    undetermined: records.filter((row) => row.encrypted === null).length,
    assetsCovered,
    coveragePercent: percentOf(assetsCovered, Math.max(1, assetTotal)),
  }
}

/* ================================================================== */
/* Vault                                                               */
/* ================================================================== */

function buildVaultProtection(rows: Row[]): VaultProtection {
  const algorithms = new Map<string, number>()
  let encrypted = 0
  let signatureVerified = 0
  let signatureUnverified = 0
  let totalBytes = 0
  let lastActivityAt: string | null = null

  for (const row of rows) {
    const status = str(row.encryption_status).toLowerCase()
    if (status === 'encrypted' || status === 'complete' || status === 'completed') encrypted += 1
    const algorithm = str(row.encryption_algorithm)
    if (algorithm) algorithms.set(algorithm, (algorithms.get(algorithm) || 0) + 1)
    const signature = str(row.signature_status).toLowerCase()
    if (signature === 'verified') signatureVerified += 1
    else signatureUnverified += 1
    totalBytes += num(row.encrypted_size) || num(row.original_size)
    lastActivityAt = latestIso(lastActivityAt, row.updated_at, row.created_at)
  }

  return {
    measured: rows.length > 0,
    files: rows.length,
    encrypted,
    signatureVerified,
    signatureUnverified,
    algorithms: [...algorithms.entries()]
      .map(([label, count]) => ({ label, count, strength: strengthOf(label, 'vault') }))
      .sort((a, b) => b.count - a.count),
    totalBytes,
    lastActivityAt,
  }
}

/* ================================================================== */
/* Operations                                                          */
/* ================================================================== */

function buildOperationProfile(input: {
  runtimeEvents: Row[]
  counts: Map<string, number>
  measured: boolean
  now: number
}): OperationProfile {
  const total = [...input.counts.values()].reduce((sum, value) => sum + value, 0)

  const start = new Date(input.now)
  start.setHours(0, 0, 0, 0)
  const timeline: OperationProfile['timeline'] = []
  for (let index = 13; index >= 0; index -= 1) {
    const dayStart = start.getTime() - index * DAY_MS
    const dayEnd = dayStart + DAY_MS
    const bucket = input.runtimeEvents.filter((event) => {
      const ms = dateMs(event.observed_at ?? event.created_at)
      return ms >= dayStart && ms < dayEnd
    })
    const countOf = (name: string) => bucket.filter((event) => str(event.operation_type).toLowerCase() === name).length
    timeline.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString(),
      encrypt: countOf('encryption'),
      decrypt: countOf('decryption'),
      sign: countOf('signing'),
      verify: countOf('verification'),
      other: bucket.filter((event) => {
        const op = str(event.operation_type).toLowerCase()
        return op === 'key_usage' || op === 'other' || !op
      }).length,
    })
  }

  return {
    measured: input.measured,
    total,
    byOperation: [...input.counts.entries()]
      .map(([operation, count]) => ({ operation: titleCase(operation), count, percent: percentOf(count, total) }))
      .sort((a, b) => b.count - a.count),
    timeline,
  }
}

/* ================================================================== */
/* Findings                                                            */
/* ================================================================== */

function buildFindings(input: {
  observations: EncryptionObservation[]
  keys: KeyInventory
  atRest: AtRestCoverage
  vault: VaultProtection
  inputs: EncryptionInputs
  assetById: Map<string, AssetMigrationRecord>
}): EncryptionFinding[] {
  const map = new Map<string, EncryptionFinding>()

  const add = (finding: Omit<EncryptionFinding, 'instances'> & { instances?: number }) => {
    const existing = map.get(finding.id)
    if (existing) {
      existing.instances += finding.instances ?? 1
      existing.lastObservedAt = latestIso(existing.lastObservedAt, finding.lastObservedAt)
      if (severityRank(finding.severity) > severityRank(existing.severity)) existing.severity = finding.severity
      for (const ref of finding.evidence) if (existing.evidence.length < 12) existing.evidence.push(ref)
      return
    }
    map.set(finding.id, { ...finding, instances: finding.instances ?? 1 })
  }

  /* ---- weak or broken primitives, from measured observations ------- */
  for (const observation of input.observations) {
    if (!needsAction(observation.strength)) continue
    /*
     * Keyed on the tenant ASSET, not the observation label. Unattributed
     * observations (a library on an unmapped host, a process with no binding)
     * collapse onto one finding whose `instances` counts the locations —
     * otherwise the same RSA-2048 library produced six identical rows that read
     * as duplicates and inflated the open-finding count.
     */
    const scope = observation.assetId || 'unattributed'
    const id = `enc-finding:${observation.layer}:${observation.observed.toLowerCase().replace(/[^a-z0-9]+/g, '-')}:${scope}`
    add({
      id,
      title: `${observation.observed} — ${STRENGTH_LABEL[observation.strength.strength]}`,
      layer: observation.layer,
      severity: severityForStrength(observation.strength),
      assetId: observation.assetId,
      assetName: observation.assetId ? observation.assetName : 'Unattributed (no asset binding)',
      observed: observation.observed,
      impact: observation.strength.rationale,
      remediation: observation.strength.target
        ? `Replace with ${observation.strength.target} (${observation.strength.standard}).`
        : `Bring this primitive in line with ${observation.strength.standard}.`,
      standard: observation.strength.standard,
      quantumRelevance:
        observation.strength.strength === 'broken'
          ? 'Already broken by classical cryptanalysis — a quantum computer is not required, and this should not wait for a PQC programme.'
          : observation.strength.strength === 'quantum-vulnerable'
            ? 'Sound against classical attack today, but recovered outright by Shor on a CRQC. Prioritise by how long this data must stay confidential (harvest-now-decrypt-later).'
            : `Grover reduces the effective security to ~${observation.strength.quantumBits ?? '?'} bits. Weakened, not broken: there is no quantum attack that reads this data today.`,
      evidence: [observation.evidence],
      firstObservedAt: observation.observedAt,
      lastObservedAt: observation.observedAt,
    })
  }

  /* ---- key material ------------------------------------------------ */
  for (const key of input.keys.keys) {
    const problems: Array<{ title: string; severity: Severity; impact: string; remediation: string }> = []
    if (key.lifecycle === 'expired') {
      problems.push({
        title: `Expired key still present: ${key.label}`,
        severity: 'critical',
        impact: 'An expired key remains usable by anything that does not check validity, and its continued presence hides whether a replacement is actually in service.',
        remediation: 'Confirm the successor key is in use, then revoke and remove this one.',
      })
    } else if (key.lifecycle === 'revoked') {
      problems.push({
        title: `Revoked key still in inventory: ${key.label}`,
        severity: 'high',
        impact: 'Revoked key material that is still stored can be reintroduced by a rollback or a stale configuration.',
        remediation: 'Destroy the key material and record the destruction in the audit trail.',
      })
    } else if (key.lifecycle === 'expiring') {
      problems.push({
        title: `Key expires in ${Math.max(0, key.daysToExpiry ?? 0)} day(s): ${key.label}`,
        severity: 'medium',
        impact: 'Anything depending on this key fails when it expires.',
        remediation: 'Rotate now and verify the dependants pick up the new key.',
      })
    }
    if (!key.expiresAt) {
      problems.push({
        title: `Key has no expiry recorded: ${key.label}`,
        severity: 'medium',
        impact: 'A key with no expiry never forces a rotation, so compromise has an unbounded window.',
        remediation: 'Set an expiry consistent with your crypto-period policy (NIST SP 800-57).',
      })
    }
    if (key.qualityScore !== null && key.qualityScore < 0.8) {
      problems.push({
        title: `Low entropy quality (${Math.round(key.qualityScore * 100)}%): ${key.label}`,
        severity: 'high',
        impact: 'Key material generated from a weak entropy source narrows the search space an attacker has to cover.',
        remediation: 'Regenerate from a QRNG or a validated hardware entropy source.',
      })
    }

    for (const problem of problems) {
      add({
        id: `enc-finding:key:${problem.title.slice(0, 40).toLowerCase().replace(/[^a-z0-9]+/g, '-')}:${key.id}`,
        title: problem.title,
        layer: 'key-material',
        severity: problem.severity,
        assetId: null,
        assetName: 'Key store',
        observed: `${key.algorithm}${key.bitLength ? `-${key.bitLength}` : ''}`,
        impact: problem.impact,
        remediation: problem.remediation,
        standard: 'NIST SP 800-57',
        quantumRelevance:
          key.strength.strength === 'broken'
            ? key.strength.rationale
            : 'Key lifecycle hygiene is independent of quantum threat, but stale key material also blocks a clean PQC migration.',
        evidence: [
          {
            source: 'key-store',
            recordId: key.id,
            table: 'generated_keys',
            observedAt: key.createdAt,
            detail: `${key.algorithm} · ${key.entropySource} · ${key.lifecycle}`,
          },
        ],
        firstObservedAt: key.createdAt,
        lastObservedAt: key.createdAt,
      })
    }
  }

  /* ---- unencrypted storage ----------------------------------------- */
  for (const record of input.atRest.records) {
    if (record.encrypted !== false) continue
    add({
      id: `enc-finding:at-rest:${record.id}`,
      title: `Storage surface without encryption at rest: ${record.surface}`,
      layer: 'at-rest',
      severity: 'critical',
      assetId: record.assetId,
      assetName: record.assetName,
      observed: record.algorithm || 'No encryption recorded',
      impact: 'Data on this surface is readable to anyone who obtains the underlying storage — no cryptographic control applies.',
      remediation: 'Enable encryption at rest with AES-256-GCM and customer-managed keys where the provider supports it.',
      standard: 'CNSA 2.0 / FIPS 140-3',
      quantumRelevance: 'Unencrypted data needs no quantum computer to read. This outranks every PQC migration item on the same asset.',
      evidence: [record.evidence],
      firstObservedAt: record.observedAt,
      lastObservedAt: record.observedAt,
    })
  }

  /* ---- scanner-reported findings, merged not summed ---------------- */
  const scannerRows: Array<{
    table: string
    source: EvidenceSource
    id: string
    title: string
    description: string
    remediation: string
    algorithm: string
    severity: unknown
    assetId: string
    at: string | null
  }> = []

  for (const row of input.inputs.cryptoExposures) {
    scannerRows.push({
      table: 'crypto_exposures',
      source: 'exposure',
      id: str(row.id),
      title: titleCase(row.exposure_type, 'Cryptographic exposure'),
      description: str(row.description),
      remediation: '',
      algorithm: str(row.detected_value),
      severity: row.severity,
      assetId: str(row.asset_id),
      at: isoOrNull(row.updated_at) || isoOrNull(row.created_at),
    })
  }
  for (const row of input.inputs.scanResults) {
    scannerRows.push({
      table: 'pqc_scan_results',
      source: 'scan-finding',
      id: str(row.id),
      title: titleCase(row.finding_type, 'Scan finding'),
      description: str(row.description),
      remediation: str(row.remediation),
      algorithm: str(row.algorithm),
      severity: row.threat_level,
      assetId: str(row.asset_id),
      at: isoOrNull(row.created_at),
    })
  }
  for (const row of input.inputs.scannerAlerts) {
    const metadata = recordOf(row.metadata)
    scannerRows.push({
      table: 'scanner_alerts',
      source: 'agent-scan',
      id: str(row.id),
      title: str(row.title) || titleCase(row.category, 'Collector alert'),
      description: str(row.message),
      remediation: str(row.recommendation),
      algorithm: pick(metadata, ['algorithm', 'observedAlgorithm']),
      severity: row.severity,
      assetId: pick(metadata, ['assetId', 'asset_id']),
      at: isoOrNull(row.updated_at) || isoOrNull(row.created_at),
    })
  }

  for (const row of scannerRows) {
    // Only findings this page owns. A TLS protocol finding belongs to the
    // transport console, and repeating it here is the duplication the previous
    // implementation was built on.
    const layer = dataProtectionLayerForFinding(`${row.title} ${row.description} ${row.algorithm}`, row.algorithm)
    if (!layer) continue

    const strengthOfRow = row.algorithm ? strengthOf(row.algorithm, layer) : UNKNOWN_STRENGTH

    /*
     * The scanner writes a `pqc_scan_results` row for EVERY observation it
     * grades, including the ones it grades SAFE. Those are inventory records,
     * not findings: surfacing "Symmetric Encryption: AES-256-GCM" in a findings
     * list invites exactly the reading this page exists to prevent — that
     * something is wrong with AES-256-GCM. The primitive is already reported in
     * the algorithm inventory above, with its strength.
     */
    const gradesWell = strengthOfRow.strength === 'quantum-safe' || strengthOfRow.strength === 'post-quantum'
    if (gradesWell && severityRank(normalizeSeverity(row.severity)) <= 1) continue

    const asset = row.assetId ? input.assetById.get(row.assetId) : undefined
    const identity = findingIdentityKey({
      algorithm: row.algorithm || row.title,
      location: asset?.hostname || '',
      scanTarget: asset?.hostname || asset?.name || '',
      detectionMethod: row.table,
    })
    const strength = strengthOfRow

    add({
      id: `enc-finding:scanner:${identity}`,
      title: row.algorithm && !row.title.toLowerCase().includes(row.algorithm.toLowerCase()) ? `${row.title}: ${row.algorithm}` : row.title,
      layer,
      severity: normalizeSeverity(row.severity),
      assetId: row.assetId || null,
      assetName: asset?.name || 'Estate-wide',
      observed: row.algorithm || row.title,
      impact: row.description || strength.rationale,
      remediation: row.remediation || (strength.target ? `Replace with ${strength.target}.` : `Align with ${strength.standard}.`),
      standard: strength.standard,
      quantumRelevance:
        strength.strength === 'broken'
          ? 'Broken classically — remediate independently of any PQC programme.'
          : strength.strength === 'quantum-vulnerable'
            ? 'Shor-breakable on a CRQC; sound classically today. Prioritise by data confidentiality lifetime.'
          : strength.quantumBits !== null
            ? `Grover reduces effective security to ~${strength.quantumBits} bits — weakened, not broken.`
            : 'Quantum impact could not be quantified for this observation.',
      evidence: [
        {
          source: row.source,
          recordId: row.id,
          table: row.table,
          observedAt: row.at,
          detail: row.description || row.title,
        },
      ],
      firstObservedAt: row.at,
      lastObservedAt: row.at,
    })
  }

  return [...map.values()].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.lastObservedAt) - dateMs(a.lastObservedAt),
  )
}

/**
 * Which data-protection layer a scanner finding belongs to, or `null` when it
 * belongs to the transport console instead.
 */
function dataProtectionLayerForFinding(text: string, algorithm: string): ProtectionLayer | null {
  const lower = text.toLowerCase()

  // Transport and PKI findings are owned by the TLS suite.
  if (/tls|ssl|handshake|cipher suite|certificate|x509|issuer|key exchange|ecdhe|downgrade|hsts|ocsp/.test(lower)) return null

  if (/at rest|at-rest|unencrypted|plaintext|storage|bucket|database encryption|volume|disk/.test(lower)) return 'at-rest'
  if (/key rotation|key management|kms|hsm|entropy|key material|crypto-?period/.test(lower)) return 'key-material'
  if (/password|pbkdf|argon|scrypt|bcrypt|derivation|\bkdf\b/.test(lower)) return 'kdf'
  if (/\bhmac\b|\bmac\b|poly1305/.test(lower)) return 'mac'
  if (/hash|digest|sha-?1|md5|sha-?256|sha-?3/.test(lower)) return 'hash'
  if (/library|package|dependenc|jwt|config/.test(lower)) return 'application'

  // Fall back to what the algorithm itself is, when one was named.
  if (algorithm) return layerFor(algorithm, '', '')
  return null
}

/* ================================================================== */
/* Telemetry health                                                    */
/* ================================================================== */

function buildTelemetryHealth(input: {
  inputs: EncryptionInputs
  observations: EncryptionObservation[]
  now: number
}): TelemetryHealth {
  const { inputs: raw, observations, now } = input

  const agentsOnline = raw.scannerAgents.filter((agent) => {
    const status = str(agent.status).toLowerCase()
    const seen = dateMs(agent.last_seen_at)
    return status === 'online' || status === 'active' || (seen > 0 && now - seen < 10 * 60_000)
  }).length
  const connectorsActive = raw.connectorAccounts.filter((account) => /active|connected|ok/i.test(str(account.status))).length
  const runningScans = raw.scanSessions.filter((session) => /running|in_progress|scanning|queued/i.test(str(session.status))).length

  const lastRuntimeEventAt = latestIso(...raw.runtimeEvents.slice(0, 200).map((row) => row.observed_at ?? row.created_at))
  const lastScanAt = latestIso(...raw.scanSessions.slice(0, 100).map((row) => row.completed_at ?? row.updated_at ?? row.created_at))
  const lastKeyEventAt = latestIso(...raw.generatedKeys.slice(0, 100).map((row) => row.updated_at ?? row.created_at))
  const lastVaultActivityAt = latestIso(...raw.vaultFiles.slice(0, 100).map((row) => row.updated_at ?? row.created_at))

  const runtimeFresh = lastRuntimeEventAt ? now - dateMs(lastRuntimeEventAt) < 15 * 60_000 : false

  let pipelineStatus: PipelineStatus
  if (runtimeFresh) pipelineStatus = 'live'
  else if (runningScans > 0) pipelineStatus = 'scan-running'
  else if (observations.length && (lastRuntimeEventAt || lastScanAt)) {
    const newest = Math.max(dateMs(lastRuntimeEventAt), dateMs(lastScanAt))
    pipelineStatus = now - newest < 24 * 3_600_000 ? 'inventory-only' : 'stale'
  } else if (observations.length) pipelineStatus = 'inventory-only'
  else if (raw.scannerAgents.length || raw.connectorAccounts.length) pipelineStatus = 'awaiting-telemetry'
  else pipelineStatus = 'no-collectors'

  const sourceCounts: Record<string, number> = {
    assets: raw.assets.length,
    crypto_inventory: raw.cryptoInventory.length,
    runtime_crypto_events: raw.runtimeEvents.length,
    scanner_evidence: raw.scannerEvidence.length,
    generated_keys: raw.generatedKeys.length,
    vault_files: raw.vaultFiles.length,
    crypto_exposures: raw.cryptoExposures.length,
    pqc_scan_results: raw.scanResults.length,
    scanner_alerts: raw.scannerAlerts.length,
    security_events: raw.securityEvents.length,
    scanner_agents: raw.scannerAgents.length,
    connector_accounts: raw.connectorAccounts.length,
  }

  // Named explicitly so a zero on the page is always attributable to a missing
  // source rather than being read as a clean result.
  const absentSources = Object.entries(sourceCounts)
    .filter(([, count]) => count === 0)
    .map(([table]) => table)

  return {
    pipelineStatus,
    agentsOnline,
    agentsTotal: raw.scannerAgents.length,
    connectorsActive,
    connectorsTotal: raw.connectorAccounts.length,
    runningScans,
    lastScanAt,
    lastRuntimeEventAt,
    lastKeyEventAt,
    lastVaultActivityAt,
    sourceCounts,
    truncated: Boolean(raw.truncated),
    absentSources,
  }
}

/* ================================================================== */
/* Timeline                                                            */
/* ================================================================== */

function buildTimeline(input: {
  observations: EncryptionObservation[]
  runtimeEvents: Row[]
  findings: EncryptionFinding[]
  now: number
}): EncryptionIntelligence['timeline'] {
  const start = new Date(input.now)
  start.setHours(0, 0, 0, 0)
  const buckets: EncryptionIntelligence['timeline'] = []
  for (let index = 13; index >= 0; index -= 1) {
    const dayStart = start.getTime() - index * DAY_MS
    const dayEnd = dayStart + DAY_MS
    const inRange = (value: unknown) => {
      const ms = dateMs(value)
      return ms >= dayStart && ms < dayEnd
    }
    buckets.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString(),
      observations: input.observations.filter((row) => inRange(row.observedAt)).length,
      operations: input.runtimeEvents.filter((event) => {
        const op = str(event.operation_type).toLowerCase()
        return op && op !== 'other' && op !== 'discovery' && op !== 'key_exchange' && inRange(event.observed_at ?? event.created_at)
      }).length,
      findings: input.findings.filter((finding) => inRange(finding.lastObservedAt)).length,
    })
  }
  return buckets
}
