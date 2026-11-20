/**
 * TLS & PKI intelligence engine.
 *
 * Pure and isomorphic: the Express routers, the four dashboards and any offline
 * check tool run the SAME function over the SAME rows, so the number a page
 * prints is the number the API computed and the number a report would quote.
 *
 * ---------------------------------------------------------------------------
 * Source-of-truth discipline
 * ---------------------------------------------------------------------------
 * `crypto_inventory`, `crypto_exposures` and `pqc_scan_results` are three
 * STORAGE VIEWS of the same scanner observation (documented in
 * `scanner/finding-identity.ts`). Summing them triple-counts one cipher suite.
 * So this engine assigns each table exactly one job:
 *
 *   OBSERVATIONS (what cryptography is in use)
 *     - `runtime_crypto_events`  runtime agent measurements  (primary)
 *     - `crypto_inventory`       scanner component inventory (primary)
 *     - `scanner_evidence`       agent raw evidence          (primary)
 *
 *   FINDINGS (what is wrong)
 *     - `crypto_exposures`, `pqc_scan_results`, `scanner_alerts`
 *       merged into one list keyed by finding identity, never summed.
 *
 * Asset identity, posture and migration state come from `buildPortfolio()`, the
 * same record Migration Planner, Assets and Runtime Crypto Intelligence read -
 * which is what keeps an asset from being "quantum vulnerable" on one page and
 * "PQC ready" on the next.
 */

import { countTelemetrySources } from '@/lib/telemetry/source-health'
import { isFailingValidation, isPassingValidation, isSimulationJob } from '@/lib/migration/job-safety'
import type { AssetMigrationRecord } from '@/lib/migration/asset-intelligence'
import { isDerivedScanObservation } from '@/lib/telemetry/evidence-identity'
import { findingIdentityKey, namesCryptography, observationClass, richerText } from '@/lib/scanner/finding-identity'
import {
  certificatePosture,
  certificateWeaknesses,
  clamp,
  classifyEndpointPosture,
  classifyObservation,
  dateMs,
  endpointIdFor,
  isLegacyVersion,
  isoOrNull,
  isPqcAdopted,
  latestIso,
  needsRemediation,
  normalizeHost,
  normalizeSeverity,
  num,
  percentOf,
  pick,
  pickNumber,
  portOf,
  recordOf,
  remediationFor,
  riskLevelFor,
  severityRank,
  str,
  titleCase,
  uniq,
  versionRank,
  type ObservationKind,
} from './classify'
import type {
  CertificateLifecycle,
  ConfigurationDrift,
  DistributionRow,
  EvidenceRef,
  EvidenceSource,
  OrchestrationActionKind,
  OrchestrationItem,
  OrchestrationState,
  OrchestrationStatus,
  PipelineStatus,
  PkiCertificate,
  PqcPosture,
  PqcTlsPosture,
  ProtocolAnalytics,
  Severity,
  TelemetryHealth,
  TlsEndpoint,
  TlsFinding,
  TlsObservation,
  TlsPkiIntelligence,
  TlsVersionLabel,
  TrustChainNode,
} from './types'
import { observationBasisFor } from './types'

type Row = Record<string, unknown>
const SSH_PROTOCOL = /^ssh(?:$|[\s_-])/i

function certificateAlgorithms(metadata: Row, algorithm: unknown) {
  const recorded = str(algorithm) || pick(metadata, ['algorithm'])
  // Older imports sometimes stored the issuer's signature in the generic algorithm field.
  const legacySignature = /^(?:(?:sha[\d-]+|md5)\s*with\s*\w|(?:ecdsa|rsa|dsa)[\s_-]+with[\s_-]+sha|rsassa-pss)/i.test(recorded)
  return {
    publicKeyAlgorithm: pick(metadata, ['public_key_algorithm', 'publicKeyAlgorithm', 'key_algorithm']) || (legacySignature ? '' : recorded),
    signatureAlgorithm: pick(metadata, ['signature_algorithm', 'signatureAlgorithm', 'sig_alg']) || (legacySignature ? recorded : null),
  }
}

const DAY_MS = 86_400_000

export interface TlsPkiInputs {
  /** Canonical per-asset record from `buildPortfolio()`. */
  assets: AssetMigrationRecord[]
  /** Estate-wide scores from `buildSnapshot()` - published verbatim. */
  snapshot: {
    quantumReadiness: number
    quantumRisk: number
    quantumRiskLevel: string
    assetsAssessed: number
  }
  runtimeEvents: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  scannerEvidence: Row[]
  scanResults: Row[]
  cryptoExposures: Row[]
  scannerAlerts: Row[]
  securityEvents: Row[]
  migrationJobs: Row[]
  migrationPlans: Row[]
  scanSessions: Row[]
  scannerAgents: Row[]
  connectorAccounts: Row[]
  agentHeartbeats: Row[]
  validationLogs: Row[]
  queuedAssetIds: string[]
  /** Set when any detail query hit its row cap. */
  truncated?: boolean
  now?: number
}

/* ================================================================== */
/* Working types                                                       */
/* ================================================================== */

interface EndpointDraft {
  id: string
  assetId: string | null
  name: string
  host: string
  port: number | null
  assetType: string
  environment: string
  owner: string
  internetFacing: boolean
  assetRecord: AssetMigrationRecord | null
  observations: TlsObservation[]
  observationBatches: Map<string, { observedAt: string | null; observations: Map<string, TlsObservation> }>
  certificateIds: Set<string>
  findingIds: Set<string>
  sources: Set<EvidenceSource>
}

interface RuntimeHandshake {
  endpointId: string
  count: number | null
  failed: boolean
  failureMeasured: boolean
  downgrade: boolean | null
}

interface CertificateDraft {
  id: string
  name: string
  subject: string
  san: Set<string>
  issuer: string
  serialNumber: string | null
  fingerprint: string | null
  assetId: string | null
  assetName: string
  endpointId: string | null
  publicKeyAlgorithm: string
  keySize: number | null
  signatureAlgorithm: string | null
  notBefore: string | null
  notAfter: string | null
  status: string
  revoked: boolean
  sources: Set<EvidenceSource>
  evidence: EvidenceRef[]
  lastObservedAt: string | null
}

/* ================================================================== */
/* Engine                                                              */
/* ================================================================== */

export function buildTlsPkiIntelligence(inputs: TlsPkiInputs): TlsPkiIntelligence {
  const now = inputs.now ?? Date.now()
  const queued = new Set(inputs.queuedAssetIds.map(str).filter(Boolean))

  /* ---------------------------------------------------------------- */
  /* 1. Endpoint index, seeded from the canonical asset portfolio      */
  /* ---------------------------------------------------------------- */

  const endpoints = new Map<string, EndpointDraft>()
  const hostAssets = new Map<string, Set<string>>()
  const assetById = new Map<string, AssetMigrationRecord>()

  const registerHost = (host: string, assetId: string) => {
    const key = normalizeHost(host)
    if (!key) return
    const matches = hostAssets.get(key) || new Set()
    matches.add(assetId)
    hostAssets.set(key, matches)
  }

  for (const asset of inputs.assets) {
    assetById.set(asset.id, asset)
    registerHost(asset.hostname, asset.id)
    registerHost(asset.name, asset.id)
  }

  /** Bind ownership independently of listener identity. An asset can serve several hosts and ports. */
  const resolveEndpoint = (
    assetId: unknown,
    host: unknown,
    fallbackName: unknown,
    port?: unknown,
  ): EndpointDraft | null => {
    const observedHost = normalizeHost(host)
    const matches = hostAssets.get(observedHost)
    const explicitAssetId = str(assetId)
    const bound = explicitAssetId ? assetById.get(explicitAssetId) : matches?.size === 1 ? assetById.get([...matches][0]) : undefined
    const normalized = observedHost || normalizeHost(bound?.hostname) || normalizeHost(bound?.name) || normalizeHost(fallbackName)
    if (!normalized) return null
    const addr = str(host) || str(bound?.hostname)
    const listenerPort = portOf(port) ?? portOf(addr) ?? (/^(?:https|wss):\/\//i.test(addr) ? 443 : null)
    const id = endpointIdFor(bound?.id, normalized, listenerPort)
    const known = endpoints.get(id)
    if (known) return known
    const draft: EndpointDraft = {
      id,
      assetId: bound?.id ?? null,
      name: bound?.name || str(fallbackName) || normalized,
      host: normalized,
      port: listenerPort,
      assetType: bound?.type ?? 'Unmanaged endpoint',
      environment: bound?.environment ?? 'unknown',
      owner: bound?.owner ?? 'Unassigned',
      internetFacing: bound?.internetFacing ?? false,
      assetRecord: bound ?? null,
      observations: [],
      observationBatches: new Map(),
      certificateIds: new Set(),
      findingIds: new Set(),
      sources: new Set(),
    }
    endpoints.set(id, draft)
    return draft
  }

  /* ---------------------------------------------------------------- */
  /* 2. Observations                                                   */
  /* ---------------------------------------------------------------- */

  const observations: TlsObservation[] = []
  /** (endpoint | kind | value) -> index, so the same fact merges. */
  const observationIndex = new Map<string, number>()
  const datedObservations = new Map<string, TlsObservation>()
  const runtimeHandshakes = new Map<string, RuntimeHandshake>()

  const addObservation = (input: {
    endpoint: EndpointDraft
    kind: ObservationKind | null
    algorithm: unknown
    componentName?: unknown
    itemType?: unknown
    protocolHint?: unknown
    keySize?: unknown
    severity?: unknown
    observedAt: string | null
    evidence: EvidenceRef
    batchId?: string
    failed?: boolean
    downgrade?: boolean
  }) => {
    const classified = classifyObservation({
      algorithm: input.algorithm,
      componentName: input.componentName,
      itemType: input.itemType,
      protocol: input.protocolHint,
      keySize: input.keySize,
    })
    if (!classified) return

    const kind = input.kind ?? classified.kind
    const observed = str(input.algorithm)
    const key = `${input.endpoint.id}|${kind}|${observed.toLowerCase()}`
    const row: TlsObservation = {
      id: `obs:${input.endpoint.id}:${kind}:${observed.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`,
      endpointId: input.endpoint.id,
      assetId: input.endpoint.assetId,
      kind,
      observed,
      family: classified.family,
      posture: classified.posture,
      forwardSecrecy: classified.forwardSecrecy,
      severity: input.severity ? normalizeSeverity(input.severity) : classified.weaknesses.length ? 'medium' : null,
      observedAt: input.observedAt,
      evidence: input.evidence,
      basis: observationBasisFor(input.evidence.source),
      handshakes: null,
      failed: Boolean(input.failed),
      downgrade: Boolean(input.downgrade),
    }
    const existing = observationIndex.get(key)
    if (existing === undefined) {
      observationIndex.set(key, observations.length)
      observations.push(row)
      input.endpoint.observations.push(row)
    } else if (dateMs(row.observedAt) >= dateMs(observations[existing].observedAt)) {
      // Keep the displayed timestamp and evidence provenance from the same row.
      Object.assign(observations[existing], row)
    }

    const day = row.observedAt ? new Date(row.observedAt) : null
    if (day) {
      day.setUTCHours(0, 0, 0, 0)
      datedObservations.set(`${day.toISOString()}|${key}`, { ...row })
    }
    if (!row.failed && ['protocol', 'cipher-suite', 'key-exchange'].includes(kind)) {
      const batchId = input.batchId ?? `${input.evidence.source}:${input.observedAt ?? 'undated'}`
      const batches = input.endpoint.observationBatches
      const batch = batches.get(batchId) ?? { observedAt: null, observations: new Map<string, TlsObservation>() }
      batch.observedAt = latestIso(batch.observedAt, row.observedAt)
      batch.observations.set(key, { ...row })
      batches.set(batchId, batch)
    }
    input.endpoint.sources.add(input.evidence.source)
  }

  /* ---- runtime_crypto_events: the only source of live handshakes --- */
  for (const event of inputs.runtimeEvents) {
    // A runtime event only belongs on a TLS console when it describes
    // TRANSPORT. The agent also reports library inventory, key material and
    // process observations on the same table: measured on a live tenant, a
    // `crypto_library` event naming "RSA-2048" on host "e2e-fixture" minted a
    // phantom TLS endpoint, gave it a quantum-vulnerable verdict, and then sat
    // in the denominator of every percentage on the page. Nine such rows turned
    // a two-asset estate into eleven "TLS endpoints".
    if (!isTransportEvent(event) || isDerivedScanObservation(event)) continue

    const metadata = recordOf(event.metadata)
    const host = pick(metadata, ['sni', 'server_name', 'serverName']) || str(event.host) || pick(metadata, ['hostname', 'domain'])
    const endpoint = resolveEndpoint(event.asset_id, host, event.asset_name, event.port)
    if (!endpoint) continue

    const observedAt = isoOrNull(event.observed_at) || isoOrNull(event.created_at)
    const handshakes = pickNumber(metadata, ['connections', 'connection_count', 'connectionCount', 'handshakes', 'handshake_count', 'sessions'])
    const eventType = str(event.event_type)
    const hasHandshake = /handshake|negotiat/i.test(eventType) || typeof metadata.handshake_failed === 'boolean'
    const failed = metadata.handshake_failed === true || (hasHandshake && /fail|reject|refused|timeout|alert/i.test(eventType))
    const downgrade = metadata.verifiedPqcFallback === true
    const recordId = str(event.id)
    if (recordId && (hasHandshake || handshakes !== null || downgrade)) {
      runtimeHandshakes.set(recordId, {
        endpointId: endpoint.id,
        count: handshakes !== null && handshakes >= 0 ? handshakes : hasHandshake ? 1 : null,
        failed,
        failureMeasured: hasHandshake,
        downgrade: typeof metadata.verifiedPqcFallback === 'boolean' ? downgrade : null,
      })
    }
    const batchId = `runtime:${recordId || observedAt}`

    const evidence: EvidenceRef = {
      source: 'runtime-telemetry',
      recordId: str(event.id),
      table: 'runtime_crypto_events',
      observedAt,
      detail: `${titleCase(event.event_type, 'Runtime observation')} on ${endpoint.host}${event.port ? `:${num(event.port)}` : ''}`,
    }

    const version = str(event.tls_version)
    if (version) {
      addObservation({ endpoint, kind: 'protocol', algorithm: version, protocolHint: event.protocol, observedAt, evidence, batchId, failed, downgrade, severity: event.severity })
    }
    const suite = str(event.cipher_suite)
    if (suite) {
      addObservation({ endpoint, kind: 'cipher-suite', algorithm: suite, protocolHint: event.protocol, observedAt, evidence, batchId, failed, downgrade, severity: event.severity })
    }
    const kex = str(event.key_exchange_algorithm)
    if (kex) {
      addObservation({ endpoint, kind: 'key-exchange', algorithm: kex, protocolHint: event.protocol, observedAt, evidence, batchId, failed, downgrade, severity: event.severity })
    }
    const algorithm = str(event.algorithm)
    // Only file the generic column when it adds something the specific columns
    // did not already state, otherwise one handshake counts three times.
    if (algorithm && algorithm !== suite && algorithm !== kex && algorithm !== version) {
      addObservation({
        endpoint,
        kind: null,
        algorithm,
        protocolHint: event.protocol,
        keySize: event.key_size,
        observedAt,
        evidence,
        batchId,
        failed,
        downgrade,
        severity: event.severity,
      })
    }
  }

  /* ---- crypto_inventory: scanner component inventory --------------- */
  const ssh = new Map<string, ProtocolAnalytics['ssh'][number]>()
  for (const item of inputs.cryptoInventory) {
    const metadata = recordOf(item.metadata)
    if (SSH_PROTOCOL.test(str(item.protocol))) {
      const category = str(metadata.category) || str(item.name).split(':', 1)[0]
      const kind = category === 'SSH Key Exchange' ? 'Key exchange' : category === 'SSH Host Key' ? 'Host key' : 'Banner'
      const raw = recordOf(metadata.raw)
      const version = /^SSH-(\d+(?:\.\d+)?)-/.exec(str(raw.banner))?.[1] ?? null
      const algorithm = kind === 'Banner' ? null : str(item.algorithm) || null
      const asset = assetById.get(str(item.asset_id))
      const target = pick(metadata, ['target', 'host', 'hostname']) || asset?.hostname || asset?.name || ''
      const id = str(item.id)
      if (id && target && (algorithm || version)) {
        const key = JSON.stringify([asset?.id, target, kind, algorithm, version])
        const observedAt = isoOrNull(item.discovered_at) || isoOrNull(item.created_at)
        if (!ssh.has(key) || dateMs(observedAt) > dateMs(ssh.get(key)?.observedAt)) {
          ssh.set(key, { id, assetId: asset?.id ?? null, target, version, algorithm, kind, observedAt })
        }
      }
      continue
    }
    // Deliberately NOT `metadata.location`: in the scanner's schema that is a
    // code or file location ("TLS Configuration", "package.json"), not a host.
    // Treating it as one turned finding labels into TLS endpoints.
    const host = pick(metadata, ['target', 'host', 'hostname', 'domain', 'sni'])
    if (!host && !assetById.has(str(item.asset_id))) continue
    const endpoint = resolveEndpoint(item.asset_id, host, item.name, metadata.port)
    if (!endpoint) continue

    const observedAt = isoOrNull(item.discovered_at) || isoOrNull(item.created_at)
    const componentName = str(item.name)
    const scan = pick(metadata, ['scanSessionId', 'scan_session_id', 'scanId'])
    const batchId = scan ? `scan:${scan}` : undefined
    const evidence: EvidenceRef = {
      source: 'crypto-inventory',
      recordId: str(item.id),
      table: 'crypto_inventory',
      observedAt,
      detail: componentName || 'Cryptographic component',
    }

    addObservation({
      endpoint,
      kind: null,
      algorithm: item.algorithm,
      componentName,
      itemType: item.item_type,
      protocolHint: item.protocol,
      keySize: item.key_size,
      severity: item.exposure_level,
      observedAt,
      batchId,
      evidence,
    })

    // `protocol` on an inventory row is a version the scanner's probe completed
    // a handshake on. The scanner enumerates versions one at a time, so this is
    // what the server ACCEPTS when offered — not what clients negotiate.
    const version = str(item.protocol)
    if (version) {
      addObservation({
        endpoint,
        kind: 'protocol',
        algorithm: version,
        componentName: `Protocol: ${version}`,
        observedAt,
        batchId,
        evidence: { ...evidence, detail: `${version} accepted by ${endpoint.host} when the scanner offered it` },
      })
    }
  }

  /* ---- scanner_evidence: agent raw evidence ------------------------ */
  for (const item of inputs.scannerEvidence) {
    const raw = recordOf(item.raw_evidence)

    // Agents file every kind of cryptographic observation on this table.
    // "Crypto Library" and "Config Reference" rows name a package or a settings
    // key, not a negotiated connection: on a live tenant they minted seven
    // phantom "TLS endpoints" (`e2e-fixture`, `qguard-e2e-*`) out of agent test
    // fixtures, each carrying a quantum-vulnerable verdict.
    if (!isTransportEvidence(item, raw)) continue

    const host = pick(raw, ['sni', 'server_name']) || str(item.host) || str(item.target) || pick(raw, ['host', 'hostname', 'domain'])
    const endpoint = resolveEndpoint(raw.asset_id ?? raw.assetId, host, item.asset_name, item.port)
    if (!endpoint) continue

    const observedAt = isoOrNull(item.observed_at) || isoOrNull(item.processed_at) || isoOrNull(item.created_at)
    const scan = pick(raw, ['scanSessionId', 'scan_session_id', 'scanId'])
    const batchId = scan ? `scan:${scan}` : undefined
    const evidence: EvidenceRef = {
      source: 'agent-scan',
      recordId: str(item.id),
      table: 'scanner_evidence',
      observedAt,
      detail: `${titleCase(item.evidence_type, 'Agent evidence')} from ${titleCase(item.source_type, 'collector')}`,
    }

    const algorithm = str(item.observed_algorithm)
    if (algorithm) {
      addObservation({
        endpoint,
        kind: null,
        algorithm,
        componentName: str(raw.componentName) || undefined,
        protocolHint: item.protocol,
        keySize: raw.keySize,
        observedAt,
        evidence,
      })
    }
    const version = str(item.protocol) || pick(raw, ['tlsVersion', 'tls_version', 'protocolVersion'])
    if (version) {
      addObservation({
        endpoint,
        kind: 'protocol',
        algorithm: version,
        componentName: `Protocol: ${version}`,
        observedAt,
        evidence,
      })
    }
    const suite = pick(raw, ['cipherSuite', 'cipher_suite', 'negotiatedCipher'])
    if (suite) {
      addObservation({ endpoint, kind: 'cipher-suite', algorithm: suite, componentName: `Cipher Suite: ${suite}`, observedAt, evidence })
    }
    const kex = pick(raw, ['keyExchange', 'key_exchange', 'namedGroup', 'named_group', 'group'])
    if (kex) {
      addObservation({ endpoint, kind: 'key-exchange', algorithm: kex, componentName: `Key Exchange: ${kex}`, observedAt, evidence })
    }
  }

  /* ---------------------------------------------------------------- */
  /* 3. Certificates                                                   */
  /* ---------------------------------------------------------------- */

  const certificateDrafts = new Map<string, CertificateDraft>()

  const certificateKey = (serial: string, subject: string, issuer: string, fingerprint: string) => {
    if (fingerprint) return `cert:fp:${fingerprint.toLowerCase().replace(/[^a-z0-9]/g, '')}`
    if (serial && issuer) {
      const issuerKey = issuer.trim().toLowerCase().replace(/\s*([,=])\s*/g, '$1')
      return `cert:sn:${encodeURIComponent(issuerKey)}:${serial.toLowerCase().replace(/[^a-z0-9]/g, '')}`
    }
    // Fall back to the NORMALISED common names. The sources spell a
    // distinguished name three different ways for the same certificate -
    // "CN=www.cloudflare.com", "https://www.cloudflare.com/" and
    // "www.cloudflare.com"; the issuer likewise arrives as the RFC 4514 form
    // "C=US O=Google Trust Services CN=WE1" and as the comma-joined value list
    // "US, Google Trust Services, WE1". Keying on the raw strings made one
    // certificate into three records and one CA into two authority paths.
    const composite = `${commonNameOf(subject)}|${commonNameOf(issuer)}`
    return composite.replace(/^\|$/, '') ? `cert:cn:${composite.replace(/[^a-z0-9|.\-*]/g, '')}` : ''
  }

  const upsertCertificate = (input: {
    serial: string
    subject: string
    issuer: string
    fingerprint: string
    name: string
    san: string[]
    assetId: string | null
    assetName: string
    endpointId: string | null
    publicKeyAlgorithm: string
    keySize: number | null
    signatureAlgorithm: string | null
    notBefore: string | null
    notAfter: string | null
    status: string
    revoked: boolean
    source: EvidenceSource
    evidence: EvidenceRef
    observedAt: string | null
  }) => {
    const key = certificateKey(input.serial, input.subject, input.issuer, input.fingerprint)
    if (!key) return null

    const existing = certificateDrafts.get(key)
    if (!existing) {
      const draft: CertificateDraft = {
        id: key,
        name: input.name || input.subject || 'Certificate',
        subject: input.subject,
        san: new Set(input.san.filter(Boolean)),
        issuer: input.issuer,
        serialNumber: input.serial || null,
        fingerprint: input.fingerprint || null,
        assetId: input.assetId,
        assetName: input.assetName,
        endpointId: input.endpointId,
        publicKeyAlgorithm: input.publicKeyAlgorithm,
        keySize: input.keySize,
        signatureAlgorithm: input.signatureAlgorithm,
        notBefore: input.notBefore,
        notAfter: input.notAfter,
        status: input.status,
        revoked: input.revoked,
        sources: new Set([input.source]),
        evidence: [input.evidence],
        lastObservedAt: input.observedAt,
      }
      certificateDrafts.set(key, draft)
      return draft
    }

    // Merge: richer identity wins, evidence accumulates, never overwrite a
    // measured field with an empty one.
    existing.sources.add(input.source)
    if (existing.evidence.length < 12) existing.evidence.push(input.evidence)
    existing.lastObservedAt = latestIso(existing.lastObservedAt, input.observedAt)
    existing.subject = richerText(existing.subject, input.subject)
    existing.issuer = richerText(existing.issuer, input.issuer)
    existing.name = richerText(existing.name, input.name)
    for (const entry of input.san) if (entry) existing.san.add(entry)
    if (!existing.serialNumber && input.serial) existing.serialNumber = input.serial
    if (!existing.fingerprint && input.fingerprint) existing.fingerprint = input.fingerprint
    if (!existing.assetId && input.assetId) existing.assetId = input.assetId
    if (!existing.endpointId && input.endpointId) existing.endpointId = input.endpointId
    if (existing.assetName === 'Unassigned' && input.assetName) existing.assetName = input.assetName
    if (!existing.publicKeyAlgorithm && input.publicKeyAlgorithm) existing.publicKeyAlgorithm = input.publicKeyAlgorithm
    if (!existing.keySize && input.keySize) existing.keySize = input.keySize
    if (!existing.signatureAlgorithm && input.signatureAlgorithm) existing.signatureAlgorithm = input.signatureAlgorithm
    if (!existing.notBefore && input.notBefore) existing.notBefore = input.notBefore
    if (!existing.notAfter && input.notAfter) existing.notAfter = input.notAfter
    existing.revoked = existing.revoked || input.revoked
    return existing
  }

  for (const cert of inputs.certificates) {
    const metadata = recordOf(cert.metadata)
    const subject = str(cert.subject) || pick(metadata, ['subject', 'common_name', 'cn']) || str(cert.name)
    const issuer = str(cert.issuer) || pick(metadata, ['issuer', 'issuer_cn', 'ca'])
    const host = pick(metadata, ['target', 'host', 'hostname', 'domain', 'sni']) || subject
    const endpoint = resolveEndpoint(cert.asset_id, host, cert.name)
    const observedAt = isoOrNull(cert.updated_at) || isoOrNull(cert.created_at)
    const sanRaw = metadata.san ?? metadata.subject_alt_names ?? metadata.subjectAltNames
    const san = Array.isArray(sanRaw) ? sanRaw.map(str).filter(Boolean) : str(sanRaw) ? str(sanRaw).split(/[,\s]+/).filter(Boolean) : []

    const draft = upsertCertificate({
      serial: str(cert.serial_number) || pick(metadata, ['serial_number', 'serial']),
      subject,
      issuer,
      fingerprint: pick(metadata, ['fingerprint', 'sha256', 'thumbprint']),
      name: str(cert.name) || subject,
      san,
      assetId: str(cert.asset_id) || null,
      assetName: endpoint?.name || 'Unassigned',
      endpointId: endpoint?.id || null,
      ...certificateAlgorithms(metadata, cert.algorithm),
      keySize: num(cert.key_size) || pickNumber(metadata, ['key_size', 'bits']),
      notBefore: isoOrNull(cert.not_before),
      notAfter: isoOrNull(cert.not_after),
      status: str(cert.status) || 'active',
      revoked: str(cert.status).toLowerCase() === 'revoked',
      source: 'certificate-store',
      evidence: {
        source: 'certificate-store',
        recordId: str(cert.id),
        table: 'certificates',
        observedAt,
        detail: `Certificate record for ${subject || 'unnamed subject'}`,
      },
      observedAt,
    })
    if (draft && endpoint) endpoint.certificateIds.add(draft.id)
  }

  /* ---- certificate rows the scanner filed into crypto_inventory ---- */
  for (const item of inputs.cryptoInventory) {
    const componentName = str(item.name)
    if (observationClass(componentName) !== 'certificate') continue
    const metadata = recordOf(item.metadata)
    const subject = pick(metadata, ['subject', 'common_name', 'cn', 'target']) || componentName.replace(/^certificate:\s*/i, '')
    const issuer = pick(metadata, ['issuer', 'issuer_cn', 'ca'])
    const host = pick(metadata, ['target', 'host', 'hostname', 'domain'])
    const endpoint = resolveEndpoint(item.asset_id, host, subject)
    const observedAt = isoOrNull(item.discovered_at) || isoOrNull(item.created_at)

    const draft = upsertCertificate({
      serial: pick(metadata, ['serial_number', 'serial']),
      subject,
      issuer,
      fingerprint: pick(metadata, ['fingerprint', 'sha256']),
      name: subject,
      san: [],
      assetId: str(item.asset_id) || null,
      assetName: endpoint?.name || 'Unassigned',
      endpointId: endpoint?.id || null,
      ...certificateAlgorithms(metadata, item.algorithm),
      keySize: num(item.key_size) || null,
      notBefore: isoOrNull(pick(metadata, ['not_before', 'valid_from'])),
      notAfter: isoOrNull(pick(metadata, ['not_after', 'valid_to', 'expires_at'])),
      status: pick(metadata, ['status']) || 'active',
      revoked: false,
      source: 'crypto-inventory',
      evidence: {
        source: 'crypto-inventory',
        recordId: str(item.id),
        table: 'crypto_inventory',
        observedAt,
        detail: componentName,
      },
      observedAt,
    })
    if (draft && endpoint) endpoint.certificateIds.add(draft.id)
  }

  /* ---- second merge pass: identity-less records -------------------- */
  /*
   * A record with neither a serial number nor a fingerprint carries no proof of
   * its own identity, so the first pass has to key it on its name. When a
   * properly identified certificate on the SAME endpoint already covers that
   * name — exactly, or through its wildcard — the two describe one physical
   * certificate observed twice.
   *
   * Measured on a live tenant this is what separated "*.badssl.com" (serial
   * 065BE…, from the certificate store) from "tls-v1-2.badssl.com" (no serial,
   * from the scan), and split one Cloudflare leaf into three records named
   * "CN=www.cloudflare.com", "www.cloudflare.com" and
   * "https://www.cloudflare.com/". Five "certificates" on a two-certificate
   * estate.
   *
   * Deliberately conservative: it merges only INTO a record that has identity
   * material, and only within one endpoint. Two nameless records never merge
   * with each other, and nothing merges across endpoints.
   */
  {
    const identified = [...certificateDrafts.values()].filter((draft) => draft.serialNumber || draft.fingerprint)
    for (const [key, draft] of [...certificateDrafts.entries()]) {
      if (draft.serialNumber || draft.fingerprint) continue

      const host = draft.endpointId ? endpoints.get(draft.endpointId)?.host || '' : ''
      const candidates = identified.filter((other) => {
        if (other.id === draft.id) return false
        if (other.endpointId && draft.endpointId && other.endpointId !== draft.endpointId) return false
        if (!other.endpointId && !draft.endpointId) return false
        if (draft.issuer && other.issuer && commonNameOf(draft.issuer) !== commonNameOf(other.issuer)) return false
        if (draft.notAfter && other.notAfter && dateMs(draft.notAfter) !== dateMs(other.notAfter)) return false

        const names = [other.subject, other.name, ...other.san]
        const draftNames = [draft.subject, draft.name].filter(Boolean)
        // The identified certificate must cover one of this record's names, or
        // the endpoint host both were observed on.
        return (
          draftNames.some((candidateName) => names.some((n) => nameCovers(n, candidateName))) ||
          (Boolean(host) && names.some((n) => nameCovers(n, host)) && draftNames.some((n) => nameCovers(n, host) || normalizeHost(n) === normalizeHost(host)))
        )
      })
      if (candidates.length !== 1) continue
      const candidate = candidates[0]

      candidate.sources = new Set([...candidate.sources, ...draft.sources])
      for (const ref of draft.evidence) if (candidate.evidence.length < 12) candidate.evidence.push(ref)
      candidate.lastObservedAt = latestIso(candidate.lastObservedAt, draft.lastObservedAt)
      for (const entry of draft.san) candidate.san.add(entry)
      if (!candidate.assetId && draft.assetId) candidate.assetId = draft.assetId
      if (!candidate.endpointId && draft.endpointId) candidate.endpointId = draft.endpointId
      if (!candidate.notAfter && draft.notAfter) candidate.notAfter = draft.notAfter
      if (!candidate.notBefore && draft.notBefore) candidate.notBefore = draft.notBefore
      if (!candidate.signatureAlgorithm && draft.signatureAlgorithm) candidate.signatureAlgorithm = draft.signatureAlgorithm
      if (!candidate.keySize && draft.keySize) candidate.keySize = draft.keySize

      certificateDrafts.delete(key)
      // Re-point the endpoint's certificate list at the surviving record.
      for (const endpoint of endpoints.values()) {
        if (endpoint.certificateIds.delete(draft.id)) endpoint.certificateIds.add(candidate.id)
      }
    }
  }

  /* ---- finalise certificates -------------------------------------- */
  const certificates: PkiCertificate[] = [...certificateDrafts.values()].map((draft) => {
    const notAfterMs = draft.notAfter ? dateMs(draft.notAfter) : 0
    const daysToExpiry = notAfterMs ? Math.floor((notAfterMs - now) / DAY_MS) : null
    const statusLower = draft.status.toLowerCase()

    const lifecycle: CertificateLifecycle = draft.revoked || statusLower === 'revoked'
      ? 'revoked'
      : dateMs(draft.notBefore) > now
        ? 'not-yet-valid'
      : daysToExpiry === null
        ? 'unknown'
        : daysToExpiry < 0
          ? 'expired'
          : daysToExpiry <= 30
            ? 'expiring'
            : 'valid'

    const subject = draft.subject
    const issuer = draft.issuer
    const selfSigned = Boolean(subject && issuer && subject.toLowerCase() === issuer.toLowerCase())
    const posture = certificatePosture(draft.publicKeyAlgorithm, draft.signatureAlgorithm, draft.keySize)
    const weaknesses = certificateWeaknesses({
      algorithm: draft.publicKeyAlgorithm,
      signatureAlgorithm: draft.signatureAlgorithm,
      keySize: draft.keySize,
      selfSigned,
      daysToExpiry,
      lifecycle,
    })

    let riskScore = 10
    if (lifecycle === 'expired') riskScore = 95
    else if (lifecycle === 'revoked' || lifecycle === 'not-yet-valid') riskScore = 88
    else if (daysToExpiry !== null && daysToExpiry <= 7) riskScore = 82
    else if (lifecycle === 'expiring') riskScore = 64
    else if (daysToExpiry !== null && daysToExpiry <= 90) riskScore = 38
    else if (lifecycle === 'unknown') riskScore = 30

    if (posture === 'quantum-vulnerable') riskScore += 14
    if (selfSigned) riskScore += 12
    if (weaknesses.some((w) => /collision-broken|below the 2048/.test(w))) riskScore += 18
    if (!draft.assetId) riskScore += 4
    riskScore = clamp(riskScore)

    return {
      id: draft.id,
      name: draft.name,
      subject: subject || 'Unknown subject',
      san: [...draft.san].slice(0, 24),
      issuer: issuer || 'Unknown issuer',
      serialNumber: draft.serialNumber,
      fingerprint: draft.fingerprint,
      assetId: draft.assetId,
      assetName: draft.assetName || 'Unassigned',
      endpointId: draft.endpointId,
      publicKeyAlgorithm: draft.publicKeyAlgorithm || 'Not observed',
      algorithmLabel: algorithmLabelFor(draft.publicKeyAlgorithm, draft.keySize),
      keySize: draft.keySize,
      signatureAlgorithm: draft.signatureAlgorithm,
      notBefore: draft.notBefore,
      notAfter: draft.notAfter,
      daysToExpiry,
      lifecycle,
      posture,
      selfSigned,
      unknownIssuer: !issuer,
      riskLevel: riskLevelFor(riskScore),
      riskScore,
      migrationPriority: clamp(riskScore * 0.6 + (posture === 'quantum-vulnerable' ? 40 : 0)),
      sources: [...draft.sources],
      evidence: draft.evidence,
      lastObservedAt: draft.lastObservedAt,
    } satisfies PkiCertificate
  })

  const certificateById = new Map(certificates.map((cert) => [cert.id, cert]))

  /* ---------------------------------------------------------------- */
  /* 4. Trust chains                                                   */
  /* ---------------------------------------------------------------- */

  const trustChains = buildTrustChains(certificates)

  /* ---------------------------------------------------------------- */
  /* 5. Findings                                                       */
  /* ---------------------------------------------------------------- */

  const findingMap = new Map<string, TlsFinding>()

  const addFinding = (finding: Omit<TlsFinding, 'instances'> & { instances?: number }) => {
    const existing = findingMap.get(finding.id)
    if (existing) {
      existing.instances += finding.instances ?? 1
      existing.lastObservedAt = latestIso(existing.lastObservedAt, finding.lastObservedAt)
      existing.firstObservedAt =
        existing.firstObservedAt && finding.firstObservedAt
          ? dateMs(existing.firstObservedAt) <= dateMs(finding.firstObservedAt)
            ? existing.firstObservedAt
            : finding.firstObservedAt
          : existing.firstObservedAt || finding.firstObservedAt
      if (severityRank(finding.severity) > severityRank(existing.severity)) existing.severity = finding.severity
      existing.impact = richerText(existing.impact, finding.impact)
      existing.remediation = richerText(existing.remediation, finding.remediation)
      for (const ref of finding.evidence) if (existing.evidence.length < 12) existing.evidence.push(ref)
      return existing
    }
    const row: TlsFinding = { ...finding, instances: finding.instances ?? 1 }
    findingMap.set(row.id, row)
    return row
  }

  /* ---- derived from measured observations -------------------------- */
  for (const endpoint of endpoints.values()) {
    for (const observation of endpoint.observations) {
      const classified = classifyObservation({ algorithm: observation.observed })
      if (!classified) continue
      for (const weakness of classified.weaknesses) {
        const remediation = remediationFor(observation.kind, classified.family, observation.observed)
        const category =
          observation.kind === 'protocol'
            ? 'protocol'
            : observation.kind === 'key-exchange'
              ? 'key-exchange'
              : observation.kind === 'certificate' || observation.kind === 'signature'
                ? 'certificate'
                : 'cipher'
        const id = `tls-finding:${category}:${weakness.slice(0, 48).toLowerCase().replace(/[^a-z0-9]+/g, '-')}:${endpoint.id}`
        const finding = addFinding({
          id,
          title: weakness,
          category,
          severity: weaknessSeverity(weakness),
          endpointId: endpoint.id,
          assetId: endpoint.assetId,
          assetName: endpoint.name,
          observed: observation.observed,
          impact: impactFor(category, observation.observed),
          remediation: `Move to ${remediation.target}. ${remediation.rationale}`,
          standard: remediation.standard,
          evidence: [observation.evidence],
          firstObservedAt: observation.observedAt,
          lastObservedAt: observation.observedAt,
          migrationStatus: endpoint.assetRecord?.migrationStatus || 'not_started',
        })
        endpoint.findingIds.add(finding.id)
      }

      if (isPqcAdopted(observation.posture)) continue
    }
  }

  /* ---- certificate findings ---------------------------------------- */
  for (const cert of certificates) {
    const weaknesses = certificateWeaknesses({
      algorithm: cert.publicKeyAlgorithm,
      signatureAlgorithm: cert.signatureAlgorithm,
      keySize: cert.keySize,
      selfSigned: cert.selfSigned,
      daysToExpiry: cert.daysToExpiry,
      lifecycle: cert.lifecycle,
    })
    if (cert.posture === 'quantum-vulnerable') {
      weaknesses.push(`${cert.publicKeyAlgorithm} certificate key is Shor-breakable`)
    }
    for (const weakness of weaknesses) {
      const remediation = remediationFor('certificate', cert.publicKeyAlgorithm, cert.publicKeyAlgorithm)
      const id = `tls-finding:certificate:${weakness.slice(0, 48).toLowerCase().replace(/[^a-z0-9]+/g, '-')}:${cert.id}`
      const finding = addFinding({
        id,
        title: weakness,
        category: 'certificate',
        certificateId: cert.id,
        severity: weaknessSeverity(weakness),
        endpointId: cert.endpointId,
        assetId: cert.assetId,
        assetName: cert.assetName,
        observed: `${cert.algorithmLabel} · ${cert.subject}`,
        impact:
          cert.lifecycle === 'expired'
            ? 'Clients will reject the connection or users will be trained to click through warnings.'
            : 'A forged or expired certificate breaks authentication of this endpoint.',
        remediation: `Reissue with ${remediation.target}. ${remediation.rationale}`,
        standard: remediation.standard,
        evidence: cert.evidence.slice(0, 4),
        firstObservedAt: cert.notBefore,
        lastObservedAt: cert.lastObservedAt,
        migrationStatus: cert.assetId ? assetById.get(cert.assetId)?.migrationStatus || 'not_started' : 'not_started',
      })
      if (cert.endpointId) endpoints.get(cert.endpointId)?.findingIds.add(finding.id)
    }
  }

  /* ---- scanner-reported findings, merged not summed ---------------- */
  const scannerFindingRows: Array<{
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
    componentName: string
  }> = []

  for (const row of inputs.cryptoExposures) {
    if (SSH_PROTOCOL.test(str(row.exposure_type)) || /^SSH endpoint advertises /i.test(str(row.description))) continue
    scannerFindingRows.push({
      table: 'crypto_exposures',
      source: 'exposure',
      id: str(row.id),
      title: labelCase(row.exposure_type, 'Cryptographic exposure'),
      description: str(row.description),
      remediation: '',
      algorithm: str(row.detected_value),
      severity: row.severity,
      assetId: str(row.asset_id),
      at: isoOrNull(row.updated_at) || isoOrNull(row.created_at),
      componentName: titleCase(row.exposure_type, ''),
    })
  }
  for (const row of inputs.scanResults) {
    if (SSH_PROTOCOL.test(str(row.finding_type))) continue
    scannerFindingRows.push({
      table: 'pqc_scan_results',
      source: 'scan-finding',
      id: str(row.id),
      title: labelCase(row.finding_type, 'Scan finding'),
      description: str(row.description),
      remediation: str(row.remediation),
      algorithm: str(row.algorithm),
      severity: row.threat_level,
      assetId: str(row.asset_id),
      at: isoOrNull(row.created_at),
      componentName: `${str(row.finding_type)}: ${str(row.algorithm)}`,
    })
  }
  for (const row of inputs.scannerAlerts) {
    const metadata = recordOf(row.metadata)
    // Collector-health alerts ("Scanner agent offline") and findings an agent
    // made from a config file, library or process are not transport findings.
    // The first was admitted because its recommendation mentions "outbound
    // HTTPS", the second because its remediation names ML-KEM; both then sat in
    // the TLS finding totals and spiked the telemetry timeline on the day the
    // heartbeat job touched them.
    if (!isTransportAlert(row, metadata)) continue
    scannerFindingRows.push({
      table: 'scanner_alerts',
      source: 'agent-scan',
      id: str(row.id),
      title: str(row.title) || labelCase(row.category, 'Collector alert'),
      description: str(row.message),
      remediation: str(row.recommendation),
      algorithm: pick(metadata, ['algorithm', 'observedAlgorithm', 'cipherSuite']),
      severity: row.severity,
      assetId: pick(metadata, ['assetId', 'asset_id']),
      at: isoOrNull(row.updated_at) || isoOrNull(row.created_at),
      componentName: `${str(row.category)}: ${pick(metadata, ['algorithm'])}`,
    })
  }

  for (const row of scannerFindingRows) {
    // Relevance is judged on what the finding SAYS it is, not on remediation
    // prose: advice that mentions HTTPS or ML-KEM does not make a finding a
    // transport finding.
    const haystack = `${row.title} ${row.description} ${row.algorithm} ${row.remediation}`
    if (!isTransportRelevant(`${row.title} ${row.description} ${row.algorithm}`)) continue

    const asset = row.assetId ? assetById.get(row.assetId) : undefined
    const endpoint = row.assetId ? endpoints.get(`asset:${row.assetId}`) : undefined

    // The canonical identity key: (algorithm, subject host, measurement method).
    // `crypto_exposures`, `pqc_scan_results` and `scanner_alerts` are storage
    // views of one observation, and the shared module already treats a storage
    // table name as "no method", so the same finding stored three ways
    // collapses onto one row - exactly as CBOM and the QR Engine see it.
    const identity = findingIdentityKey({
      algorithm: row.algorithm || row.title,
      location: endpoint?.host || asset?.hostname || '',
      scanTarget: asset?.hostname || asset?.name || '',
      detectionMethod: row.table,
    })
    const id = `tls-finding:scanner:${identity}`

    const category = categoryForFinding(haystack, row.algorithm)
    const remediation = remediationFor(
      category === 'protocol' ? 'protocol' : category === 'certificate' ? 'certificate' : 'key-exchange',
      row.algorithm,
      row.algorithm,
    )

    const finding = addFinding({
      id,
      title: scannerFindingTitle(row.title, row.algorithm, category),
      category,
      severity: normalizeSeverity(row.severity),
      endpointId: endpoint?.id ?? null,
      assetId: row.assetId || null,
      assetName: asset?.name || endpoint?.name || 'Estate-wide',
      observed: row.algorithm || row.title,
      impact: row.description || impactFor(category, row.algorithm),
      remediation: row.remediation || `Move to ${remediation.target}. ${remediation.rationale}`,
      standard: remediation.standard,
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
      migrationStatus: asset?.migrationStatus || 'not_started',
    })
    if (endpoint) endpoint.findingIds.add(finding.id)
  }

  const findings = [...findingMap.values()].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || dateMs(b.lastObservedAt) - dateMs(a.lastObservedAt),
  )
  const findingById = new Map(findings.map((finding) => [finding.id, finding]))

  /* ---------------------------------------------------------------- */
  /* 6. Finalise endpoints                                             */
  /* ---------------------------------------------------------------- */

  const migrationJobsByAsset = new Map<string, Row[]>()
  for (const job of inputs.migrationJobs) {
    const assetId = str(job.asset_id)
    if (!assetId) continue
    const bucket = migrationJobsByAsset.get(assetId)
    if (bucket) bucket.push(job)
    else migrationJobsByAsset.set(assetId, [job])
  }

  const finalEndpoints: TlsEndpoint[] = []
  for (const draft of endpoints.values()) {
    const batches = [...draft.observationBatches.values()]
    const latestTransportAt = Math.max(0, ...batches.map((batch) => dateMs(batch.observedAt)))
    const currentTransport = batches.filter((batch) => dateMs(batch.observedAt) === latestTransportAt)
      .flatMap((batch) => [...batch.observations.values()])
    const observationsForEndpoint = [
      ...draft.observations.filter((row) => !['protocol', 'cipher-suite', 'key-exchange'].includes(row.kind)),
      ...currentTransport,
    ]
    const versions = uniq(
      observationsForEndpoint
        .filter((row) => row.kind === 'protocol')
        .map((row) => (row.family as TlsVersionLabel) || 'Unknown'),
    ).filter(Boolean) as TlsVersionLabel[]

    const bestVersion = versions.length
      ? versions.slice().sort((a, b) => versionRank(b) - versionRank(a))[0]
      : null

    const cipherSuites = uniq(observationsForEndpoint.filter((row) => row.kind === 'cipher-suite').map((row) => row.observed))
    const keyExchange = uniq(observationsForEndpoint.filter((row) => row.kind === 'key-exchange').map((row) => row.observed))
    const signatures = uniq(
      observationsForEndpoint.filter((row) => row.kind === 'signature' || row.kind === 'certificate').map((row) => row.observed),
    )

    const fsValues = observationsForEndpoint.map((row) => row.forwardSecrecy).filter((value) => value !== null) as boolean[]
    const forwardSecrecy = fsValues.length ? fsValues.every(Boolean) : null

    // A TLS 1.3 suite (TLS_AES_256_GCM_SHA384) names only the AEAD and hash:
    // its key exchange is negotiated separately. Counting such a suite as
    // key-agreement evidence would let the page state a quantum posture it did
    // not measure, which is the exact trap `suite-anatomy.ts` documents.
    const namesKeyAgreement = cipherSuites.some((suite) => /_WITH_/i.test(suite) || /ECDHE|DHE|X25519|ML-?KEM|KYBER/i.test(suite))
    const hasKeyExchangeEvidence = keyExchange.length > 0 || namesKeyAgreement

    const posture = classifyEndpointPosture({
      observationPostures: currentTransport.map((row) => row.posture),
      bestVersion,
      observedVersions: versions,
      hasKeyExchangeEvidence,
      hasAnyEvidence: currentTransport.length > 0,
      assetPosture: draft.assetRecord?.posture ?? null,
      migrationCompleted: (draft.assetRecord?.migrationStatus || '') === 'completed',
    })

    /**
     * Transport evidence is what makes an endpoint countable in a TLS
     * percentage. A row backed only by a certificate or a signature is a real
     * PKI record, but it says nothing about what the endpoint NEGOTIATES, so
     * including it in "TLS 1.3 adoption" would compute a share against a
     * denominator that never had a protocol version to begin with.
     */
    const transportRows = observationsForEndpoint.filter(
      (row) => row.kind === 'protocol' || row.kind === 'cipher-suite' || row.kind === 'key-exchange',
    )
    const hasTransportEvidence = transportRows.length > 0
    const transportBases = new Set(transportRows.map((row) => row.basis))
    const transportBasis: TlsEndpoint['transportBasis'] = !hasTransportEvidence
      ? null
      : transportBases.has('live-traffic')
        ? transportBases.size > 1 ? 'mixed' : 'live-traffic'
        : 'scanner-probe'

    const endpointFindings = [...draft.findingIds].map((id) => findingById.get(id)).filter(Boolean) as TlsFinding[]
    const criticalFindings = endpointFindings.filter((row) => row.severity === 'critical').length
    const highFindings = endpointFindings.filter((row) => row.severity === 'high').length

    const certs = [...draft.certificateIds].map((id) => certificateById.get(id)).filter(Boolean) as PkiCertificate[]
    const expiryValues = certs.map((cert) => cert.daysToExpiry).filter((value): value is number => typeof value === 'number')
    const daysToExpiry = expiryValues.length ? Math.min(...expiryValues) : null

    let riskScore = 0
    if (posture.posture === 'legacy') riskScore = 92
    else if (posture.posture === 'quantum-vulnerable') riskScore = 74
    else if (posture.posture === 'migration-required') riskScore = 58
    else if (posture.posture === 'hybrid-ready') riskScore = 22
    else if (posture.posture === 'pqc-ready') riskScore = 10
    else if (posture.posture === 'quantum-safe') riskScore = 14
    else riskScore = 40 // unknown: uncertainty is risk, not safety
    riskScore += criticalFindings * 6 + highFindings * 3
    if (draft.internetFacing) riskScore += 8
    if (daysToExpiry !== null && daysToExpiry <= 30) riskScore += 10
    riskScore = clamp(riskScore)

    const handshakeValues = [...runtimeHandshakes.values()]
      .filter((row) => row.endpointId === draft.id)
      .map((row) => row.count)
      .filter((value): value is number => typeof value === 'number')
    const handshakeCount = handshakeValues.length ? handshakeValues.reduce((sum, value) => sum + value, 0) : null

    const jobs = draft.assetId ? migrationJobsByAsset.get(draft.assetId) || [] : []
    const activeJob = jobs.find((job) => ['running', 'in_progress', 'validating', 'queued'].includes(str(job.status).toLowerCase()))

    finalEndpoints.push({
      id: draft.id,
      assetId: draft.assetId,
      name: draft.name,
      host: draft.host,
      port: draft.port,
      assetType: draft.assetType,
      environment: draft.environment,
      owner: draft.owner,
      internetFacing: draft.internetFacing,
      negotiatedVersion: bestVersion,
      observedVersions: versions.sort((a, b) => versionRank(b) - versionRank(a)),
      cipherSuites,
      keyExchange,
      signatureAlgorithms: signatures,
      forwardSecrecy,
      posture: posture.posture,
      postureReason: posture.reason,
      riskLevel: riskLevelFor(riskScore),
      riskScore,
      quantumVulnerable: draft.assetRecord ? draft.assetRecord.posture === 'vulnerable' : posture.posture === 'quantum-vulnerable',
      certificateIds: [...draft.certificateIds],
      daysToExpiry,
      findingIds: [...draft.findingIds],
      criticalFindings,
      highFindings,
      migrationStatus: draft.assetRecord?.migrationStatus || (activeJob ? str(activeJob.status) : 'not_started'),
      migrationProgressPct: draft.assetRecord?.migrationProgressPct ?? num(activeJob?.progress),
      queued: draft.assetId ? queued.has(draft.assetId) : false,
      remediationActions: remediationActionsFor(posture.posture, bestVersion, cipherSuites, certs),
      lastObservedAt: latestIso(
        ...observationsForEndpoint.map((row) => row.observedAt),
        ...certs.map((cert) => cert.lastObservedAt),
      ),
      evidenceSources: [...draft.sources],
      observationCount: observationsForEndpoint.length,
      handshakeCount,
      hasTransportEvidence,
      transportBasis,
    })
  }

  finalEndpoints.sort((a, b) => b.riskScore - a.riskScore || a.name.localeCompare(b.name))
  const endpointById = new Map(finalEndpoints.map((endpoint) => [endpoint.id, endpoint]))

  /* ---------------------------------------------------------------- */
  /* 7. Protocol analytics                                             */
  /* ---------------------------------------------------------------- */

  const protocol = buildProtocolAnalytics({
    observations,
    datedObservations: [...datedObservations.values()],
    endpoints: finalEndpoints,
    runtimeHandshakes: [...runtimeHandshakes.values()],
    ssh: [...ssh.values()].sort((a, b) => dateMs(b.observedAt) - dateMs(a.observedAt)),
    now,
  })

  /* ---------------------------------------------------------------- */
  /* 8. Posture                                                        */
  /* ---------------------------------------------------------------- */

  /**
   * The denominator for every TLS percentage is endpoints with TRANSPORT
   * evidence — a protocol version, a suite or a key agreement.
   *
   * An endpoint known only through a certificate is a real PKI record and is
   * counted on the PKI surfaces, but it has never been observed negotiating
   * anything, so including it here would compute "TLS 1.3 adoption" against
   * rows that could never have had a protocol version.
   */
  const measured = finalEndpoints.filter((endpoint) => endpoint.hasTransportEvidence)
  const measuredAssetCount = new Set(measured.flatMap((endpoint) => endpoint.assetId ? [endpoint.assetId] : [])).size
  const totalAssets = Math.max(inputs.snapshot.assetsAssessed, inputs.assets.length)
  const countVersion = (version: TlsVersionLabel) => measured.filter((endpoint) => endpoint.negotiatedVersion === version).length

  const hybridEndpoints = measured.filter((endpoint) => endpoint.posture === 'hybrid-ready').length
  const pqcEndpoints = measured.filter((endpoint) => endpoint.posture === 'pqc-ready').length
  const classicalOnly = measured.filter(
    (endpoint) => endpoint.posture === 'quantum-vulnerable' || endpoint.posture === 'legacy' || endpoint.posture === 'migration-required',
  ).length

  const kexObservations = observations.filter((row) => row.kind === 'key-exchange' || row.kind === 'cipher-suite')
  const posture: PqcTlsPosture = {
    tlsEnabledAssets: measured.length,
    assetsWithoutTransportEvidence: Math.max(0, totalAssets - measuredAssetCount),
    tls13Endpoints: countVersion('TLS 1.3'),
    tls12Endpoints: countVersion('TLS 1.2'),
    // ANY observed deprecated version, not merely the best one. An endpoint
    // whose best version is TLS 1.2 but which still answers on TLS 1.0 is a
    // legacy endpoint: the downgrade path is what matters, not the ceiling.
    // Reading only the ceiling is what let this tile print "0 — no deprecated
    // protocol observed" on the same screen as an anomaly panel reporting one.
    legacyEndpoints: measured.filter((endpoint) => endpoint.observedVersions.some(isLegacyVersion)).length,
    unknownVersionEndpoints: measured.filter((endpoint) => !endpoint.negotiatedVersion || endpoint.negotiatedVersion === 'Unknown').length,
    hybridEndpoints,
    pqcEndpoints,
    classicalOnlyEndpoints: classicalOnly,
    // Every measured endpoint whose key agreement is classical-only. `posture`
    // is exclusive (a legacy endpoint is "legacy", not "quantum-vulnerable"),
    // so counting only that one posture printed "0 quantum vulnerable" beside
    // "2 classical-only" for the same endpoints — a legacy endpoint negotiates
    // classical key agreement too.
    quantumVulnerableEndpoints: classicalOnly,
    x25519Observations: kexObservations.filter((row) => /X25519|CURVE25519/i.test(row.observed) && !/ML-?KEM/i.test(row.observed)).length,
    hybridMlKemObservations: kexObservations.filter((row) => row.posture === 'hybrid-ready').length,
    mlKemObservations: kexObservations.filter((row) => /ML-?KEM|KYBER/i.test(row.observed)).length,
    weakCipherEndpoints: measured.filter((endpoint) =>
      endpoint.findingIds.some((id) => findingById.get(id)?.category === 'cipher'),
    ).length,
    certificatesAtRisk: certificates.filter((cert) => cert.riskLevel === 'critical' || cert.riskLevel === 'high').length,
    certificatesExpiring30d: certificates.filter((cert) => cert.lifecycle === 'expiring').length,
    certificatesExpired: certificates.filter((cert) => cert.lifecycle === 'expired').length,
    migrationReadyEndpoints: measured.filter((endpoint) => endpoint.posture === 'pqc-ready' || endpoint.posture === 'hybrid-ready').length,
    remediationRequiredEndpoints: measured.filter((endpoint) => needsRemediation(endpoint.posture)).length,
    pqcAdoptionPercent: percentOf(hybridEndpoints + pqcEndpoints, measured.length),
    quantumReadinessScore: clamp(inputs.snapshot.quantumReadiness),
    quantumRiskScore: clamp(inputs.snapshot.quantumRisk),
    quantumRiskLevel: inputs.snapshot.quantumRiskLevel || 'Unknown',
    transportCoveragePercent: percentOf(measuredAssetCount, Math.max(1, totalAssets)),
  }

  /* ---------------------------------------------------------------- */
  /* 9. Orchestration                                                  */
  /* ---------------------------------------------------------------- */

  const orchestration = buildOrchestration({
    endpoints: finalEndpoints,
    findings,
    certificates,
    certificateById,
    findingById,
    assetById,
    migrationJobs: inputs.migrationJobs,
    migrationPlans: inputs.migrationPlans,
    validationLogs: inputs.validationLogs,
    securityEvents: inputs.securityEvents,
    endpointById,
    queued,
  })

  /* ---------------------------------------------------------------- */
  /* 10. Telemetry health                                              */
  /* ---------------------------------------------------------------- */

  const telemetry = buildTelemetryHealth({ inputs, observations, certificates, now })

  /* ---------------------------------------------------------------- */
  /* 11. Timeline                                                      */
  /* ---------------------------------------------------------------- */

  const timeline = buildTimeline({ observations: [...datedObservations.values()], certificates, findings, now })

  const latestEvidenceAt = latestIso(
    ...observations.map((row) => row.observedAt),
    ...certificates.map((cert) => cert.lastObservedAt),
    ...findings.map((row) => row.lastObservedAt),
  )

  return {
    generatedAt: new Date(now).toISOString(),
    latestEvidenceAt,
    hasData: measured.length > 0 || certificates.length > 0 || observations.length > 0,
    posture,
    endpoints: finalEndpoints,
    observations,
    certificates: certificates.sort((a, b) => b.riskScore - a.riskScore || a.subject.localeCompare(b.subject)),
    trustChains,
    findings,
    protocol,
    orchestration,
    telemetry,
    timeline,
    pki: {
      lifecycle: {
        valid: certificates.filter((cert) => cert.lifecycle === 'valid').length,
        expiring: certificates.filter((cert) => cert.lifecycle === 'expiring').length,
        expired: certificates.filter((cert) => cert.lifecycle === 'expired').length,
        revoked: certificates.filter((cert) => cert.lifecycle === 'revoked').length,
        notYetValid: certificates.filter((cert) => cert.lifecycle === 'not-yet-valid').length,
        unknown: certificates.filter((cert) => cert.lifecycle === 'unknown').length,
      },
      expiryBuckets: buildExpiryBuckets(certificates),
      issuers: buildIssuerRollup(certificates),
      algorithmDistribution: buildCertificateAlgorithms(certificates),
    },
  }
}

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

/** TLS-bearing ports, used only as a corroborating signal, never on its own. */
const TLS_PORTS = new Set([443, 465, 587, 636, 989, 990, 993, 995, 8443, 9443, 4433])

/**
 * Does this runtime event describe TRANSPORT cryptography?
 *
 * `runtime_crypto_events` is a general-purpose agent table: it carries TLS
 * handshakes, but also library inventory, key generation, process observations
 * and file-level findings. Only the transport rows belong on a TLS console.
 *
 * The test is positive evidence, never absence: a row qualifies because it
 * NAMES a protocol version, a suite, a key agreement or a certificate, or
 * because its protocol/port/event type says transport. A row that merely fails
 * to say otherwise does not qualify.
 */
function isTransportEvent(event: Row): boolean {
  if (SSH_PROTOCOL.test(str(event.protocol))) return false
  if (str(event.tls_version) || str(event.cipher_suite) || str(event.key_exchange_algorithm)) return true
  if (str(event.certificate_fingerprint)) return true

  const protocol = str(event.protocol).toLowerCase()
  if (/tls|ssl|https|quic|dtls|ldaps|smtps|imaps|pop3s|ftps|mtls/.test(protocol)) return true

  const kind = `${str(event.event_type)} ${str(event.operation_type)} ${str(event.source_type)}`.toLowerCase()
  if (/handshake|tls|ssl|certificate|cert_|_cert|negotiat|cipher|session_resum|alpn|sni/.test(kind)) return true

  // A TLS port alone is weak evidence, so it must be paired with an event that
  // is at least about a connection rather than about a file or a package.
  const port = Number(event.port)
  if (Number.isFinite(port) && TLS_PORTS.has(port) && /connect|network|socket|traffic|endpoint|service/.test(kind)) return true

  return false
}

/**
 * Does this agent evidence row describe TRANSPORT or PKI?
 *
 * Same positive-evidence rule as `isTransportEvent`: the row qualifies because
 * its evidence type, protocol, port or payload says transport or certificate —
 * never merely because it failed to say otherwise.
 */
function isTransportEvidence(item: Row, raw: Record<string, unknown>): boolean {
  if (SSH_PROTOCOL.test(str(item.protocol)) || SSH_PROTOCOL.test(str(raw.protocol))) return false
  const kind = `${str(item.evidence_type)} ${str(item.source_type)}`.toLowerCase()

  // Explicitly non-transport agent evidence classes.
  if (/librar|package|dependenc|config reference|file|process|registry|keystore entry/.test(kind)) {
    // A library row can still matter if it carried an actual handshake payload.
    if (!pick(raw, ['tlsVersion', 'tls_version', 'cipherSuite', 'cipher_suite', 'namedGroup', 'named_group'])) return false
  }

  if (/tls|ssl|certificate|cert|handshake|transport|endpoint|listener|https/.test(kind)) return true

  const protocol = str(item.protocol).toLowerCase()
  if (/tls|ssl|https|quic|dtls|ldaps|smtps|imaps|pop3s|ftps/.test(protocol)) return true

  if (pick(raw, ['tlsVersion', 'tls_version', 'cipherSuite', 'cipher_suite', 'namedGroup', 'named_group', 'group', 'keyExchange', 'key_exchange'])) {
    return true
  }

  const port = Number(item.port)
  if (Number.isFinite(port) && TLS_PORTS.has(port)) return true

  return false
}

/**
 * A readable title for a scanner-reported finding.
 *
 * `finding_type` is a CATEGORY, not a sentence: the scanner stores "RSA",
 * "Weak TLS", "Certificate". Title-casing it alone produced a findings list
 * reading "Rsa / Rsa / Rsa / Rsa" — four genuinely distinct findings (different
 * suites) that looked like one row repeated, so an operator could not tell them
 * apart or trust the count. Naming the measured value restores the distinction.
 */
function scannerFindingTitle(rawTitle: string, algorithm: string, category: TlsFinding['category']): string {
  const title = str(rawTitle)
  const value = str(algorithm)
  const noun =
    category === 'protocol'
      ? 'protocol'
      : category === 'certificate'
        ? 'certificate'
        : category === 'key-exchange'
          ? 'key agreement'
          : category === 'cipher'
            ? 'cipher suite'
            : 'configuration'

  // No measured value to name, or the title already contains it: leave as-is.
  if (!value || title.toLowerCase().includes(value.toLowerCase())) return title || `Transport ${noun} finding`

  // A short category-shaped title ("RSA", "Weak TLS") gains the value it is
  // about; a title that is already a sentence keeps its own wording.
  if (title.length <= 24 && !/\s\w+\s\w+/.test(title)) {
    return `${labelCase(title)} ${noun}: ${value}`
  }
  return `${title} (${value})`
}

function weaknessSeverity(weakness: string): Severity {
  const text = weakness.toLowerCase()
  if (/broken|expired|rfc 8996|below the 2048|collision/.test(text)) return 'critical'
  if (/no forward secrecy|static key agreement|revoked|shor-breakable/.test(text)) return 'high'
  if (/cbc|self-signed|expires in/.test(text)) return 'medium'
  return 'low'
}

function impactFor(category: string, observed: string): string {
  switch (category) {
    case 'protocol':
      return `Clients can negotiate ${observed || 'a deprecated protocol'}, exposing the session to downgrade and known protocol attacks.`
    case 'cipher':
      return 'The negotiated record layer can be attacked without breaking the key exchange.'
    case 'key-exchange':
      return 'Traffic captured today can be decrypted once a cryptographically relevant quantum computer exists (harvest-now, decrypt-later).'
    case 'certificate':
      return 'Endpoint authentication can be forged or will fail outright, breaking trust in the service.'
    default:
      return 'Cryptographic configuration on this endpoint does not meet the target posture.'
  }
}

/**
 * Title-case a scanner label WITHOUT destroying acronyms.
 *
 * `titleCase("RSA")` returns "Rsa", which is how the findings list came to read
 * "Rsa / Rsa / Rsa / Rsa" — four genuinely distinct findings that looked like
 * one row repeated. Tokens already in all-caps (RSA, TLS, SHA, ECDSA, PKI) are
 * the scanner's own spelling and are left exactly as written.
 */
/**
 * Reduce a distinguished name, URL or bare hostname to its common name.
 *
 * Handles every spelling the tenant's own sources produce for one identity:
 *
 *   "CN=www.cloudflare.com"                        -> www.cloudflare.com
 *   "C=US O=Google Trust Services CN=WE1"          -> we1
 *   "US, Google Trust Services, WE1"               -> we1
 *   "https://www.cloudflare.com/"                  -> www.cloudflare.com
 *
 * The comma-joined form comes from the scanner, which stores
 * `Object.values(issuer).join(', ')` and so drops the attribute names; the CN
 * is conventionally last. Returns '' when there is nothing to key on, so the
 * caller can decline to merge rather than merging everything nameless together.
 */
export function commonNameOf(value: unknown): string {
  const text = str(value)
  if (!text) return ''

  const cn = text.match(/CN\s*=\s*([^,/]+)/i)
  if (cn) return cn[1].trim().toLowerCase()

  const stripped = text
    .replace(/^[a-z0-9+.-]+:\/\//i, '')
    .replace(/[/?#].*$/, '')
    .trim()

  if (stripped.includes(',')) {
    const parts = stripped.split(',').map((part) => part.trim()).filter(Boolean)
    if (parts.length) return parts[parts.length - 1].toLowerCase()
  }
  return stripped.toLowerCase()
}

/**
 * One display label for a public key: algorithm plus size, never doubled.
 *
 * The sources already embed the size in the algorithm string ("RSA-2048") and
 * the scanner appends its own class prefix ("ECDSA P-256 (Certificate)"), so
 * appending `key_size` unconditionally rendered "RSA-2048-2048" and
 * "ECDSA P-256 (Certificate)-256" in the inventory and in the algorithm chart.
 * Computing it once here means every surface prints the same string.
 */
function algorithmLabelFor(algorithm: string, keySize: number | null): string {
  const base = str(algorithm)
    .replace(/\s*\((certificate|signature|key exchange|cipher suite)\)\s*$/i, '')
    // One spelling per curve, so the algorithm chart groups "ECDSA-P256" and
    // "ECDSA P-256" — the same key from two sources — into one bar.
    .replace(/\b(ECDSA|ECDH|EC)[\s-]*P[\s-]?(256|384|521)\b/i, (_all, family: string, bits: string) => `${family.toUpperCase()} P-${bits}`)
    .replace(/\bprime256v1\b/i, 'ECDSA P-256')
    .replace(/\bsecp256r1\b/i, 'ECDSA P-256')
    .replace(/\bsecp384r1\b/i, 'ECDSA P-384')
    .replace(/\bsecp521r1\b/i, 'ECDSA P-521')
    .replace(/\s+/g, ' ')
    .trim()
  if (!base) return 'Not observed'
  if (!keySize) return base
  // Already states the size in any spelling — RSA-2048, ECDSA-P256, P-256,
  // secp384r1, Ed25519 — so appending it again would print "RSA-2048-2048".
  if (base.includes(String(keySize))) return base
  // Named curves carry their strength in the curve name, not a bit count.
  if (/P-?\d{3}|secp\d+|curve|25519|448|brainpool/i.test(base)) return base
  return `${base}-${keySize}`
}

/** Does a certificate name (possibly a wildcard) cover this host? */
function nameCovers(certificateName: string, host: string): boolean {
  const name = commonNameOf(certificateName)
  const target = normalizeHost(host)
  if (!name || !target) return false
  if (name === target) return true
  if (name.startsWith('*.')) {
    const suffix = name.slice(1) // ".badssl.com"
    return target.endsWith(suffix) && target.slice(0, -suffix.length).length > 0
  }
  return false
}

const CRYPTO_ACRONYMS = new Set([
  'RSA', 'DSA', 'ECDSA', 'EDDSA', 'ECDH', 'ECDHE', 'DHE', 'DH', 'KEM', 'KDF', 'MAC', 'HMAC',
  'AES', 'DES', '3DES', 'RC4', 'CBC', 'GCM', 'CCM', 'CTR', 'SHA', 'SHA1', 'SHA2', 'SHA3', 'MD5',
  'TLS', 'SSL', 'DTLS', 'MTLS', 'HTTPS', 'HTTP', 'SSH', 'IKE', 'IPSEC', 'QUIC',
  'PKI', 'CA', 'CRL', 'OCSP', 'CSR', 'SAN', 'SNI', 'JA3', 'X509', 'CT', 'HSTS', 'CAA',
  'PQC', 'HNDL', 'PFS', 'JWT', 'API', 'DNS', 'NIST', 'FIPS', 'OID', 'ECC', 'CVE', 'URL', 'IP',
])

/**
 * Human-readable label for a stored scanner value, preserving cryptographic
 * acronyms.
 *
 * Two upstream spellings have to survive this: the scanner writes categories in
 * caps (`RSA`, `MAC`) while exposures are stored lowercase (`rsa`, `weak_tls`).
 * A plain title-case reads the first as "Rsa" and the second as "Rsa" too, so
 * the findings list rendered "Rsa / Rsa / Rsa / Rsa" — four genuinely distinct
 * findings that looked like one row repeated. This uppercases known acronyms
 * whatever casing they arrive in, and leaves everything else title-cased.
 *
 * Display only: the stored value is never modified.
 */
function labelCase(value: unknown, fallback = ''): string {
  const text = str(value).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return fallback
  return text
    .split(' ')
    .map((word) => {
      const upper = word.toUpperCase()
      if (CRYPTO_ACRONYMS.has(upper)) return upper
      // Already all-caps and longer than one character: the writer's own
      // spelling, so leave it alone rather than re-casing an unknown acronym.
      if (word.length > 1 && word === upper) return word
      return word.charAt(0).toUpperCase() + word.slice(1)
    })
    .join(' ')
}

/**
 * Which part of the transport a finding is about.
 *
 * Asks the canonical decomposer what the measured ALGORITHM is before falling
 * back to reading the surrounding prose. Guessing from the whole text is the
 * same trap `suite-anatomy.ts` documents: the narrative for
 * `TLS_RSA_WITH_AES_256_CBC_SHA` mentions "forward secrecy", so a text-only
 * rule filed a cipher suite under "key agreement".
 */
function categoryForFinding(text: string, algorithm?: string): TlsFinding['category'] {
  const measured = str(algorithm)
  if (measured) {
    const classified = classifyObservation({ algorithm: measured })
    if (classified) {
      if (classified.kind === 'protocol') return 'protocol'
      if (classified.kind === 'cipher-suite') return 'cipher'
      if (classified.kind === 'key-exchange') return 'key-exchange'
      if (classified.kind === 'certificate' || classified.kind === 'signature') return 'certificate'
    }
  }

  const lower = text.toLowerCase()
  if (/certificate|x509|x\.509|issuer|expir|revok|chain|\bca\b/.test(lower)) return 'certificate'
  if (/tls 1\.|sslv|protocol|handshake|downgrade|renegotiat/.test(lower)) return 'protocol'
  if (/key exchange|key agreement|ecdhe|\bdhe\b|ml-kem|kyber|x25519|forward secrecy/.test(lower)) return 'key-exchange'
  if (/cipher|aes|chacha|rc4|3des|cbc|gcm/.test(lower)) return 'cipher'
  if (/quantum|shor|grover|pqc|harvest/.test(lower)) return 'quantum'
  return 'configuration'
}

/**
 * Does this finding actually concern transport or PKI?
 *
 * The four pages are a TLS/PKI console, not a general findings list: a Python
 * dependency CVE belongs on Vulnerabilities. Being explicit here is what stops
 * the certificate inventory filling with library rows.
 */
/**
 * Word-bounded on purpose: `dhe`, `kem`, `sni` and `ja3` as bare substrings
 * matched "adhere", "kemp", "snippet" and asset ids.
 */
export function isTransportRelevant(text: string): boolean {
  return /\b(tls|ssl|https|certificates?|cert|x\.?509|cipher(?:[- ]suites?)?|handshake|issuer|chain|pki|hsts|ocsp|sni|ja3|ecdhe|dhe|forward secrecy|downgrade|ldaps|smtps|imaps)\b|key[- ]exchange|key agreement|\b(ml-?kem|x25519mlkem768)\b/i.test(
    text,
  )
}

const NON_TRANSPORT_ALERT_CATEGORY = /heartbeat|agent[- ]?health|collector|enrol|install|update|license|quota/i
const NON_TRANSPORT_EVIDENCE = /config[- ]?reference|crypto[- ]?librar|librar|package|dependenc|file|process|registry|source[- ]?code/i

/**
 * Does a scanner alert describe a transport / PKI observation?
 *
 * Agent-health alerts are excluded by category; agent findings are excluded
 * when their own evidence says it came from a config file, a library, a
 * package, a process or source code — the same classes `isTransportEvidence`
 * already refuses to turn into endpoints.
 */
export function isTransportAlert(row: Row, metadata: Record<string, unknown>): boolean {
  if (NON_TRANSPORT_ALERT_CATEGORY.test(str(row.category))) return false
  const evidence = recordOf(metadata.evidence)
  const evidenceSource = `${str(evidence.source)} ${str(metadata.evidenceType)} ${str(metadata.evidence_type)}`
  if (NON_TRANSPORT_EVIDENCE.test(evidenceSource)) return false
  return true
}

function remediationActionsFor(
  posture: PqcPosture,
  version: TlsVersionLabel | null,
  cipherSuites: string[],
  certs: PkiCertificate[],
): string[] {
  const actions: string[] = []
  if (isLegacyVersion(version)) actions.push('Disable TLS 1.0/1.1 and require TLS 1.2 minimum')
  if (version && version !== 'TLS 1.3' && version !== 'Unknown') actions.push('Enable TLS 1.3')
  if (posture === 'quantum-vulnerable' || posture === 'migration-required') {
    actions.push('Enable hybrid X25519MLKEM768 key agreement')
  }
  if (cipherSuites.some((suite) => /CBC|3DES|RC4/i.test(suite))) actions.push('Remove CBC / 3DES / RC4 suites')
  if (certs.some((cert) => cert.lifecycle === 'expired' || cert.lifecycle === 'expiring')) {
    actions.push('Replace expiring or expired certificate')
  }
  if (certs.some((cert) => cert.posture === 'quantum-vulnerable')) actions.push('Reissue certificate with ML-DSA-65')
  return uniq(actions)
}

/* ---- PKI rollups --------------------------------------------------- */
/*
 * Grouping certificates by issuer, algorithm and expiry horizon is MODEL logic,
 * not presentation: the same rollup has to be identical wherever it is read.
 * Computing it here (rather than in the Express projection) also means the
 * route layer imports only the builder, which keeps the module graph a single
 * direction and avoids the cold-start binding failure a cross-module helper
 * import produced on the first request after every server start.
 */

function buildExpiryBuckets(certificates: PkiCertificate[]) {
  const total = certificates.length
  const bucket = (label: string, predicate: (cert: PkiCertificate) => boolean) => {
    const matched = certificates.filter(predicate)
    return {
      label,
      count: matched.length,
      percent: total ? Math.round((matched.length / total) * 100) : 0,
      certificateIds: matched.slice(0, 200).map((cert) => cert.id),
    }
  }
  return [
    bucket('Expired', (cert) => cert.lifecycle === 'expired'),
    bucket('0-7 days', (cert) => cert.daysToExpiry !== null && cert.daysToExpiry >= 0 && cert.daysToExpiry <= 7),
    bucket('8-30 days', (cert) => cert.daysToExpiry !== null && cert.daysToExpiry > 7 && cert.daysToExpiry <= 30),
    bucket('31-90 days', (cert) => cert.daysToExpiry !== null && cert.daysToExpiry > 30 && cert.daysToExpiry <= 90),
    bucket('90+ days', (cert) => cert.daysToExpiry !== null && cert.daysToExpiry > 90),
    bucket('No expiry recorded', (cert) => cert.daysToExpiry === null),
  ]
}

function buildIssuerRollup(certificates: PkiCertificate[]) {
  // Group by the CA's normalised common name, not its raw string. The sources
  // spell one authority two ways - the RFC 4514 form
  // "C=US O=Google Trust Services CN=WE1" and the comma-joined value list
  // "US, Google Trust Services, WE1" - which listed a single CA as two issuers
  // with one certificate each instead of one issuer with two.
  const groups = new Map<string, { label: string; certs: PkiCertificate[] }>()
  for (const cert of certificates) {
    const raw = cert.issuer || 'Unknown issuer'
    const key = commonNameOf(raw) || raw.toLowerCase()
    const bucket = groups.get(key)
    if (bucket) {
      bucket.certs.push(cert)
      // Keep the most informative spelling for display.
      if (raw.length > bucket.label.length) bucket.label = raw
    } else {
      groups.set(key, { label: raw, certs: [cert] })
    }
  }
  return [...groups.values()]
    .map(({ label: issuer, certs }) => ({
      issuer,
      certificates: certs.length,
      expiring: certs.filter((cert) => cert.lifecycle === 'expiring').length,
      expired: certs.filter((cert) => cert.lifecycle === 'expired').length,
      quantumVulnerable: certs.filter((cert) => cert.posture === 'quantum-vulnerable').length,
      pqcReady: certs.filter((cert) => cert.posture === 'pqc-ready' || cert.posture === 'hybrid-ready').length,
      averageRisk: Math.round(certs.reduce((sum, cert) => sum + cert.riskScore, 0) / Math.max(1, certs.length)),
      certificateIds: certs.slice(0, 200).map((cert) => cert.id),
    }))
    .sort((a, b) => b.certificates - a.certificates || b.averageRisk - a.averageRisk)
}

function buildCertificateAlgorithms(certificates: PkiCertificate[]) {
  const groups = new Map<string, { count: number; posture: PkiCertificate['posture']; ids: string[] }>()
  for (const cert of certificates) {
    const key = cert.algorithmLabel
    const entry = groups.get(key) || { count: 0, posture: cert.posture, ids: [] }
    entry.count += 1
    if (entry.ids.length < 200) entry.ids.push(cert.id)
    groups.set(key, entry)
  }
  const total = certificates.length
  return [...groups.entries()]
    .map(([label, entry]) => ({
      label,
      count: entry.count,
      percent: total ? Math.round((entry.count / total) * 100) : 0,
      posture: entry.posture,
      certificateIds: entry.ids,
    }))
    .sort((a, b) => b.count - a.count)
}

/* ---- trust chains ------------------------------------------------- */

function buildTrustChains(certificates: PkiCertificate[]): TrustChainNode[] {
  if (!certificates.length) return []

  const normalize = (value: string) => value.toLowerCase().replace(/\s+/g, ' ').trim()
  /** subject -> the certificate that IS that subject (i.e. a measured CA). */
  const bySubject = new Map<string, PkiCertificate>()
  for (const cert of certificates) {
    // Index under both the raw subject and its common name: an issuer field
    // written as a full DN must still resolve to the certificate whose subject
    // was recorded as a bare hostname.
    for (const key of [normalize(cert.subject), commonNameOf(cert.subject)]) {
      if (key && !bySubject.has(key)) bySubject.set(key, cert)
    }
  }

  const nodeFor = (label: string, kind: TrustChainNode['kind'], measuredCert: PkiCertificate | null): TrustChainNode => ({
    id: measuredCert ? `chain:${measuredCert.id}` : `chain:issuer:${normalize(label).replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`,
    label,
    kind,
    posture: measuredCert ? measuredCert.posture : 'unknown',
    certificateIds: measuredCert ? [measuredCert.id] : [],
    endpointIds: [],
    children: [],
    measured: Boolean(measuredCert),
  })

  const roots = new Map<string, TrustChainNode>()

  for (const cert of certificates) {
    const issuerKey = commonNameOf(cert.issuer) || normalize(cert.issuer)
    const issuerCert = issuerKey && issuerKey !== normalize(cert.subject) ? bySubject.get(issuerKey) : undefined

    // The CA layer: a measured issuer certificate, otherwise an inferred node
    // built from the issuer STRING and clearly marked as unmeasured.
    const caLabel = cert.selfSigned ? `${cert.subject} (self-signed)` : cert.issuer || 'Unknown issuer'
    // Key on the CA's common name so the two spellings of one authority produce
    // one path, matching the issuer rollup on the PKI page exactly.
    const caKey = commonNameOf(caLabel) || normalize(caLabel)
    let ca = roots.get(caKey)
    if (!ca) {
      // Root only when the CA certificate is held and self-issued (or the leaf
      // itself is self-signed). An issuer known by NAME only is an issuing CA:
      // public roots may not sign subscriber certificates directly (CA/B Forum
      // BR §6.1.7). Defaulting it to "root" labelled every intermediate a root.
      const kind: TrustChainNode['kind'] = cert.selfSigned
        ? 'root'
        : issuerCert
          ? normalize(issuerCert.issuer) !== normalize(issuerCert.subject) ? 'intermediate' : 'root'
          : 'intermediate'
      ca = nodeFor(caLabel, kind, issuerCert || (cert.selfSigned ? cert : null))
      roots.set(caKey, ca)
    }

    const leaf = nodeFor(cert.subject || cert.name, 'leaf', cert)
    if (cert.endpointId) leaf.endpointIds.push(cert.endpointId)
    if (!cert.selfSigned || !ca.measured) ca.children.push(leaf)
    if (cert.endpointId && !ca.endpointIds.includes(cert.endpointId)) ca.endpointIds.push(cert.endpointId)
    if (!ca.certificateIds.includes(cert.id) && cert.selfSigned) ca.certificateIds.push(cert.id)
  }

  return [...roots.values()].sort((a, b) => b.children.length - a.children.length || a.label.localeCompare(b.label))
}

/* ---- protocol analytics ------------------------------------------- */

function buildProtocolAnalytics(input: {
  ssh: ProtocolAnalytics['ssh']
  observations: TlsObservation[]
  datedObservations: TlsObservation[]
  endpoints: TlsEndpoint[]
  runtimeHandshakes: Array<{ endpointId: string; failed: boolean; failureMeasured: boolean; downgrade: boolean | null }>
  now: number
}): ProtocolAnalytics {
  const { observations, endpoints } = input

  const distribution = (kind: TlsObservation['kind'] | TlsObservation['kind'][], label?: (row: TlsObservation) => string): DistributionRow[] => {
    const kinds = Array.isArray(kind) ? kind : [kind]
    const rows = observations.filter((row) => kinds.includes(row.kind))
    const total = rows.length
    const groups = new Map<string, { count: number; posture: PqcPosture; endpoints: Set<string> }>()
    for (const row of rows) {
      const key = label ? label(row) : row.family || row.observed
      const entry = groups.get(key) || { count: 0, posture: row.posture, endpoints: new Set<string>() }
      entry.count += 1
      entry.endpoints.add(row.endpointId)
      // Worst posture wins so a family is never softened by one good member.
      if (postureWeight(row.posture) > postureWeight(entry.posture)) entry.posture = row.posture
      groups.set(key, entry)
    }
    return [...groups.entries()]
      .map(([labelText, entry]) => ({
        label: labelText,
        count: entry.count,
        percent: percentOf(entry.count, total),
        posture: entry.posture,
        endpointIds: [...entry.endpoints],
      }))
      .sort((a, b) => b.count - a.count)
  }

  const fsRows = observations.filter((row) => row.kind === 'cipher-suite' || row.kind === 'key-exchange' || row.kind === 'protocol')
  const forwardSecrecy = {
    withFs: fsRows.filter((row) => row.forwardSecrecy === true).length,
    withoutFs: fsRows.filter((row) => row.forwardSecrecy === false).length,
    notApplicable: fsRows.filter((row) => row.forwardSecrecy === null).length,
  }

  const downgradeEndpointIds = uniq(input.runtimeHandshakes.filter((row) => row.downgrade === true).map((row) => row.endpointId))
  const handshakeFailures = input.runtimeHandshakes.filter((row) => row.failed).length

  const anomalies: ProtocolAnalytics['anomalies'] = []
  const mixedVersion = endpoints.filter(
    (endpoint) =>
      endpoint.observedVersions.length > 1 &&
      endpoint.observedVersions.some(isLegacyVersion) &&
      endpoint.observedVersions.some((version) => !isLegacyVersion(version) && version !== 'Unknown'),
  )
  if (mixedVersion.length) {
    anomalies.push({
      id: 'anomaly:mixed-version',
      title: 'Endpoint accepts both modern and deprecated protocol versions',
      detail: `${mixedVersion.length} endpoint(s) still answer on TLS 1.0/1.1 alongside a modern version, which keeps a downgrade path open.`,
      severity: 'high',
      endpointIds: mixedVersion.map((endpoint) => endpoint.id),
    })
  }
  const tls13NoHybrid = endpoints.filter(
    (endpoint) => endpoint.negotiatedVersion === 'TLS 1.3' && endpoint.posture !== 'hybrid-ready' && endpoint.posture !== 'pqc-ready',
  )
  if (tls13NoHybrid.length) {
    anomalies.push({
      id: 'anomaly:tls13-classical',
      title: 'TLS 1.3 endpoints negotiating classical groups only',
      detail: `${tls13NoHybrid.length} endpoint(s) already run TLS 1.3 and can adopt X25519MLKEM768 without a protocol change - the cheapest post-quantum win available.`,
      severity: 'medium',
      endpointIds: tls13NoHybrid.map((endpoint) => endpoint.id),
    })
  }
  const noFs = endpoints.filter((endpoint) => endpoint.forwardSecrecy === false)
  if (noFs.length) {
    anomalies.push({
      id: 'anomaly:no-forward-secrecy',
      title: 'Endpoints without forward secrecy',
      detail: `${noFs.length} endpoint(s) negotiate a static key agreement, so any recorded session stays decryptable if the long-term key is ever recovered.`,
      severity: 'critical',
      endpointIds: noFs.map((endpoint) => endpoint.id),
    })
  }
  const unknownPosture = endpoints.filter((endpoint) => endpoint.observationCount > 0 && endpoint.posture === 'unknown')
  if (unknownPosture.length) {
    anomalies.push({
      id: 'anomaly:undetermined-kex',
      title: 'Transport observed but key agreement undetermined',
      detail: `${unknownPosture.length} endpoint(s) reported cryptography without naming the key agreement, so their quantum posture cannot be stated. Run an agent scan to resolve them.`,
      severity: 'medium',
      endpointIds: unknownPosture.map((endpoint) => endpoint.id),
    })
  }

  /* ---- adoption trend over real observation timestamps ------------- */
  const trend: ProtocolAnalytics['adoptionTrend'] = []
  const start = new Date(input.now)
  start.setHours(0, 0, 0, 0)
  for (let index = 13; index >= 0; index -= 1) {
    const dayStart = start.getTime() - index * DAY_MS
    const dayEnd = dayStart + DAY_MS
    const bucket = input.datedObservations.filter((row) => {
      const ms = dateMs(row.observedAt)
      return ms >= dayStart && ms < dayEnd
    })
    trend.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString(),
      pqc: bucket.filter((row) => row.posture === 'pqc-ready').length,
      hybrid: bucket.filter((row) => row.posture === 'hybrid-ready').length,
      classical: bucket.filter((row) => row.posture === 'quantum-vulnerable' || row.posture === 'legacy').length,
    })
  }

  return {
    ssh: input.ssh,
    basis: 'observations',
    totalObservations: observations.length,
    versionDistribution: distribution('protocol', (row) => row.family || 'Unknown'),
    cipherDistribution: distribution('cipher-suite', (row) => row.observed),
    keyExchangeDistribution: distribution('key-exchange', (row) => row.family || row.observed),
    signatureDistribution: distribution(['signature', 'certificate'], (row) => row.family || row.observed),
    forwardSecrecy,
    // Same rule as `posture.legacyEndpoints`: ANY observed deprecated version.
    // Two surfaces deriving 'legacy' differently is how one page reported a
    // TLS 1.0 endpoint while the tile beside it reported none.
    legacyEndpointIds: endpoints.filter((endpoint) => endpoint.observedVersions.some(isLegacyVersion)).map((endpoint) => endpoint.id),
    handshakeFailures,
    handshakeFailuresMeasured: input.runtimeHandshakes.some((row) => row.failureMeasured),
    downgradeEndpointIds,
    downgradeMeasured: input.runtimeHandshakes.some((row) => row.downgrade !== null),
    anomalies,
    adoptionTrend: trend,
  }
}

function postureWeight(posture: PqcPosture): number {
  switch (posture) {
    case 'legacy':
      return 6
    case 'quantum-vulnerable':
      return 5
    case 'migration-required':
      return 4
    case 'unknown':
      return 3
    case 'hybrid-ready':
      return 2
    case 'pqc-ready':
      return 1
    default:
      return 0
  }
}

/* ---- orchestration ------------------------------------------------ */

function buildOrchestration(input: {
  endpoints: TlsEndpoint[]
  findings: TlsFinding[]
  certificates: PkiCertificate[]
  certificateById: Map<string, PkiCertificate>
  findingById: Map<string, TlsFinding>
  assetById: Map<string, AssetMigrationRecord>
  endpointById: Map<string, TlsEndpoint>
  migrationJobs: Row[]
  migrationPlans: Row[]
  validationLogs: Row[]
  securityEvents: Row[]
  queued: Set<string>
}): OrchestrationState {
  const items: OrchestrationItem[] = []
  const migrationJobs = input.migrationJobs.filter((job) => !isSimulationJob(job))
  const latestValidation = new Map<string, Row>()
  for (const row of input.validationLogs) {
    const jobId = str(row.migration_id)
    if (!jobId) continue
    const previous = latestValidation.get(jobId)
    if (!previous || dateMs(row.created_at) > dateMs(previous.created_at)) latestValidation.set(jobId, row)
  }
  const latestScopedJob = new Map<string, Row>()
  const jobScopeKey = (assetId: string, endpointId: string, action: string) => JSON.stringify([assetId, endpointId, action])
  for (const job of migrationJobs) {
    const metadata = recordOf(job.metadata)
    const key = jobScopeKey(str(job.asset_id), str(metadata.endpointId || metadata.endpoint_id), str(metadata.remediationAction || metadata.action))
    const previous = latestScopedJob.get(key)
    if (!previous || dateMs(job.updated_at ?? job.created_at) > dateMs(previous.updated_at ?? previous.created_at)) latestScopedJob.set(key, job)
  }

  const jobStatusFor = (assetId: string | null, endpointId: string, action: OrchestrationActionKind): { status: OrchestrationStatus; detail: string; progress: number; at: string | null } => {
    if (!assetId) return { status: 'not-started', detail: 'Endpoint is not bound to a managed asset.', progress: 0, at: null }
    const latest = latestScopedJob.get(jobScopeKey(assetId, endpointId, action))

    if (latest) {
      const raw = str(latest.status).toLowerCase()
      const at = isoOrNull(latest.updated_at) || isoOrNull(latest.created_at)
      const progress = clamp(num(latest.progress))
      if (raw === 'completed' || raw === 'succeeded') {
        const result = latestValidation.get(str(latest.id))
        if (isFailingValidation(result?.status)) {
          return { status: 'failed', detail: 'The latest post-change validation recorded a failure.', progress, at: isoOrNull(result?.created_at) ?? at }
        }
        return { status: 'validating', detail: 'The job completed. Current observations still show this remediation is needed.', progress, at }
      }
      if (raw === 'failed' || raw === 'error') return { status: 'failed', detail: 'Last migration job failed - review the job log.', progress, at }
      if (raw === 'rolled_back' || raw === 'rolledback') return { status: 'rolled-back', detail: 'Change was rolled back.', progress, at }
      if (raw === 'validating' || raw === 'verification') return { status: 'validating', detail: 'Post-change validation in progress.', progress, at }
      if (raw === 'running' || raw === 'in_progress') return { status: 'in-progress', detail: 'Migration job running.', progress, at }
      if (raw === 'queued' || raw === 'pending') return { status: 'planned', detail: 'Migration job queued for execution.', progress, at }
    }

    if (input.queued.has(assetId)) {
      return { status: 'ready', detail: 'Queued in the Migration Planner and ready for a plan.', progress: 0, at: null }
    }
    return { status: 'not-started', detail: 'No remediation started for this endpoint.', progress: 0, at: null }
  }

  for (const endpoint of input.endpoints) {
    const endpointFindings = endpoint.findingIds.map((id) => input.findingById.get(id)).filter(Boolean) as TlsFinding[]
    const certs = endpoint.certificateIds.map((id) => input.certificateById.get(id)).filter(Boolean) as PkiCertificate[]
    const asset = endpoint.assetId ? input.assetById.get(endpoint.assetId) : undefined

    const actions: Array<{ kind: OrchestrationActionKind; label: string; change: string; current: string; target: string; standard: string; severity: Severity }> = []

    // Reads the FLOOR, not the ceiling. An endpoint preferring TLS 1.2 while
    // still answering on TLS 1.0 needs the deprecated versions disabled — and
    // testing `negotiatedVersion` (the best one) skipped that critical item
    // entirely, so the queue offered only "Enable TLS 1.3" for an endpoint the
    // posture strip was simultaneously calling Legacy.
    const legacyOffered = endpoint.observedVersions.filter(isLegacyVersion)
    if (legacyOffered.length) {
      actions.push({
        kind: 'tls-upgrade',
        label: 'Disable deprecated TLS versions',
        change: `Disable ${legacyOffered.join(', ')} and require TLS 1.2 minimum, TLS 1.3 preferred.`,
        current: endpoint.observedVersions.join(', ') || 'Not observed',
        target: 'TLS 1.3 (TLS 1.2 floor)',
        standard: 'RFC 8996 / RFC 8446',
        severity: 'critical',
      })
    }
    if (!legacyOffered.length && endpoint.negotiatedVersion === 'TLS 1.2') {
      actions.push({
        kind: 'tls-upgrade',
        label: 'Enable TLS 1.3',
        change: 'Enable TLS 1.3 on this listener - it is a prerequisite for hybrid ML-KEM key agreement.',
        current: 'TLS 1.2',
        target: 'TLS 1.3',
        standard: 'RFC 8446',
        severity: 'medium',
      })
    }

    if (endpoint.cipherSuites.some((suite) => /CBC|3DES|RC4|_DES_/i.test(suite))) {
      actions.push({
        kind: 'cipher-update',
        label: 'Remove legacy cipher suites',
        change: 'Restrict the suite list to AEAD suites (AES-GCM / ChaCha20-Poly1305).',
        current: endpoint.cipherSuites.filter((suite) => /CBC|3DES|RC4|_DES_/i.test(suite)).join(', '),
        target: 'TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256',
        standard: 'NIST SP 800-52 Rev. 2',
        severity: 'high',
      })
    }

    if (endpoint.posture === 'quantum-vulnerable' || endpoint.posture === 'migration-required') {
      actions.push({
        kind: 'hybrid-tls-enablement',
        label: 'Enable hybrid post-quantum key agreement',
        change: 'Add X25519MLKEM768 to the supported groups list ahead of the classical groups.',
        current: endpoint.keyExchange.join(', ') || 'Classical key agreement observed',
        target: 'X25519MLKEM768',
        standard: 'FIPS 203 / RFC 9370',
        severity: endpoint.internetFacing ? 'high' : 'medium',
      })
    }

    const certAtRisk = certs.filter((cert) => cert.lifecycle === 'expired' || cert.lifecycle === 'expiring' || cert.lifecycle === 'revoked')
    if (certAtRisk.length) {
      actions.push({
        kind: 'certificate-replacement',
        label: 'Replace certificate',
        change: certAtRisk
          .map((cert) => `${cert.subject} (${cert.lifecycle}${typeof cert.daysToExpiry === 'number' ? `, ${cert.daysToExpiry}d` : ''})`)
          .join('; '),
        current: certAtRisk.map((cert) => cert.lifecycle).join(', '),
        target: 'Valid certificate with at least 90 days remaining',
        standard: 'CA/Browser Forum BR',
        severity: certAtRisk.some((cert) => cert.lifecycle === 'expired') ? 'critical' : 'high',
      })
    }

    const quantumCerts = certs.filter((cert) => cert.posture === 'quantum-vulnerable')
    if (quantumCerts.length) {
      actions.push({
        kind: 'pqc-migration',
        label: 'Reissue certificate with a post-quantum signature',
        change: `Reissue ${quantumCerts.length} certificate(s) using ML-DSA-65, or a hybrid ECDSA P-256 + ML-DSA-65 chain during transition.`,
        current: quantumCerts.map((cert) => cert.publicKeyAlgorithm).join(', '),
        target: 'ML-DSA-65',
        standard: 'FIPS 204',
        severity: 'medium',
      })
    }

    const configFindings = endpointFindings.filter((finding) => finding.category === 'configuration')
    if (configFindings.length) {
      actions.push({
        kind: 'configuration-remediation',
        label: 'Resolve transport configuration findings',
        change: configFindings
          .slice(0, 3)
          .map((finding) => finding.title)
          .join('; '),
        current: `${configFindings.length} open configuration finding(s)`,
        target: 'No open transport configuration findings',
        standard: 'NIST SP 800-52 Rev. 2',
        severity: configFindings.reduce<Severity>((worst, finding) => (severityRank(finding.severity) > severityRank(worst) ? finding.severity : worst), 'low'),
      })
    }

    if (!actions.length) continue


    for (const action of actions) {
      const state = jobStatusFor(endpoint.assetId, endpoint.id, action.kind)
      const severity = action.severity
      const priority =
        severityRank(severity) * 20 +
        (endpoint.internetFacing ? 15 : 0) +
        Math.round(endpoint.riskScore / 5) +
        (asset ? Math.round(asset.priorityScore / 10) : 0)

      const availableActions: OrchestrationItem['availableActions'] = ['evidence']
      if (endpoint.assetId) {
        availableActions.push(endpoint.queued ? 'unqueue' : 'queue')
        availableActions.push('plan')
      }
      if (endpoint.host) availableActions.push('rescan')

      items.push({
        id: `orch:${endpoint.id}:${action.kind}`,
        endpointId: endpoint.id,
        assetId: endpoint.assetId,
        assetName: endpoint.name,
        host: endpoint.host,
        environment: endpoint.environment,
        internetFacing: endpoint.internetFacing,
        action: action.kind,
        actionLabel: action.label,
        changeSummary: action.change,
        currentState: action.current,
        targetState: action.target,
        standard: action.standard,
        status: state.status,
        statusDetail: state.detail,
        progressPct: state.progress,
        queued: endpoint.queued,
        priority: clamp(priority),
        severity,
        riskScore: endpoint.riskScore,
        blastRadius: asset?.blastRadius ?? 0,
        estimatedEffortHours: asset?.estimatedEffortHours ?? 0,
        findingIds: endpointFindings.filter((finding) => matchesAction(finding, action.kind)).map((finding) => finding.id),
        certificateIds: action.kind === 'certificate-replacement' || action.kind === 'pqc-migration' ? certs.map((cert) => cert.id) : [],
        evidence: endpointFindings.slice(0, 3).flatMap((finding) => finding.evidence.slice(0, 2)),
        availableActions,
        blockedReason: endpoint.assetId ? null : 'Endpoint is not linked to a managed asset, so it cannot be queued for migration. Bind it on the Assets page first.',
        lastChangeAt: state.at,
      })
    }
  }

  items.sort((a, b) => b.priority - a.priority || b.riskScore - a.riskScore)

  const statusCounts: Record<OrchestrationStatus, number> = {
    'not-started': 0,
    planned: 0,
    ready: 0,
    'in-progress': 0,
    validating: 0,
    completed: 0,
    failed: 0,
    'rolled-back': 0,
  }
  for (const item of items) statusCounts[item.status] += 1

  /* ---- configuration drift, measured only -------------------------- */
  const drift: ConfigurationDrift[] = []
  for (const event of input.securityEvents) {
    const metadata = recordOf(event.metadata)
    const previous = pick(metadata, ['previous', 'previousValue', 'before', 'from'])
    const current = pick(metadata, ['current', 'currentValue', 'after', 'to'])
    if (!previous || !current || previous === current) continue
    const text = `${str(event.event_type)} ${str(event.message)} ${previous} ${current}`
    if (!isTransportRelevant(text)) continue
    const endpoint = input.endpoints.find((row) => row.assetId && row.assetId === str(event.asset_id))
    drift.push({
      id: `drift:${str(event.id)}`,
      assetId: endpoint?.assetId ?? null,
      endpointId: endpoint?.id || '',
      assetName: endpoint?.name || str(event.resource_name) || 'Unknown asset',
      detail: str(event.message) || titleCase(event.event_type, 'Configuration change'),
      previous,
      current,
      detectedAt: isoOrNull(event.created_at),
      severity: normalizeSeverity(event.severity),
    })
  }

  /* ---- real migration jobs on TLS/PKI endpoints -------------------- */
  const tlsAssetIds = new Set(input.endpoints.flatMap((endpoint) =>
    endpoint.assetId && (endpoint.hasTransportEvidence || endpoint.certificateIds.length > 0) ? [endpoint.assetId] : []))
  const jobsForTls = migrationJobs.filter((job) => tlsAssetIds.has(str(job.asset_id)))
  const activeJobCount = jobsForTls.filter((job) =>
    ['running', 'in_progress', 'validating', 'queued', 'pending'].includes(str(job.status).toLowerCase())).length
  const activeJobs = jobsForTls
    .map((job) => ({
      id: str(job.id),
      assetId: str(job.asset_id) || null,
      assetName: input.assetById.get(str(job.asset_id))?.name || str(job.name) || 'Migration job',
      jobType: titleCase(job.job_type, 'Migration'),
      status: str(job.status) || 'unknown',
      progress: clamp(num(job.progress)),
      targetAlgorithm: str(job.target_algorithm) || 'Not specified',
      updatedAt: isoOrNull(job.updated_at) || isoOrNull(job.created_at),
    }))
    .sort((a, b) => dateMs(b.updatedAt) - dateMs(a.updatedAt))
    .slice(0, 40)

  const plans = input.migrationPlans.filter((plan) => Array.isArray(plan.selected_asset_ids) &&
    plan.selected_asset_ids.some((id) => tlsAssetIds.has(str(id)))).slice(0, 20).map((plan) => {
    const metadata = recordOf(plan.metadata)
    const selected = Array.isArray(plan.selected_asset_ids) ? plan.selected_asset_ids.length : 0
    return {
      id: str(plan.id),
      name: pick(metadata, ['name']) || 'Migration plan',
      status: str(plan.status) || 'unknown',
      assetCount: selected,
      updatedAt: isoOrNull(plan.updated_at) || isoOrNull(plan.created_at),
    }
  })

  const jobById = new Map(jobsForTls.map((job) => [str(job.id), job]))
  const validationRows = [...latestValidation].filter(([id]) => jobById.has(id)).map(([, row]) => row)
  const passed = validationRows.filter((row) => isPassingValidation(row.status) &&
    ['completed', 'succeeded'].includes(str(jobById.get(str(row.migration_id))?.status).toLowerCase()))
  const queuedAssetIds = [...tlsAssetIds].filter((id) => input.queued.has(id))
  const validation = {
    validated: passed.length,
    pending: validationRows.filter((row) => ['pending', 'running', 'validating'].includes(str(row.status).toLowerCase())).length,
    failed: validationRows.filter((row) => isFailingValidation(row.status)).length,
    lastValidatedAt: latestIso(...passed.map((row) => row.created_at ?? row.updated_at)),
  }

  return {
    items,
    statusCounts,
    queueDepth: queuedAssetIds.length,
    queuedAssetIds,
    activeJobCount,
    drift: drift.sort((a, b) => dateMs(b.detectedAt) - dateMs(a.detectedAt)),
    driftMeasured: input.securityEvents.length > 0,
    activeJobs,
    plans,
    validation,
  }
}

function matchesAction(finding: TlsFinding, action: OrchestrationActionKind): boolean {
  switch (action) {
    case 'tls-upgrade':
      return finding.category === 'protocol'
    case 'cipher-update':
      return finding.category === 'cipher'
    case 'hybrid-tls-enablement':
    case 'key-exchange-migration':
      return finding.category === 'key-exchange' || finding.category === 'quantum'
    case 'certificate-replacement':
    case 'pqc-migration':
      return finding.category === 'certificate'
    default:
      return finding.category === 'configuration'
  }
}

/* ---- telemetry health --------------------------------------------- */

function buildTelemetryHealth(input: {
  inputs: TlsPkiInputs
  observations: TlsObservation[]
  certificates: PkiCertificate[]
  now: number
}): TelemetryHealth {
  const { inputs: raw, observations, certificates, now } = input

  const { agentsOnline, connectorsActive, runningScans } = countTelemetrySources(raw, now)

  const lastRuntimeEventAt = latestIso(...raw.runtimeEvents.slice(0, 200).map((row) => row.observed_at ?? row.created_at))
  const lastScanAt = latestIso(...raw.scanSessions.slice(0, 100).map((row) => row.completed_at ?? row.updated_at ?? row.created_at))
  const lastCertificateObservationAt = latestIso(...certificates.slice(0, 200).map((cert) => cert.lastObservedAt))
  const lastConfigurationChangeAt = latestIso(
    ...raw.securityEvents
      .filter((event) => /config|policy|tls|cipher|certificate/i.test(str(event.event_type)))
      .slice(0, 100)
      .map((event) => event.created_at),
  )

  const runtimeFresh = lastRuntimeEventAt ? dateMs(lastRuntimeEventAt) <= now && now - dateMs(lastRuntimeEventAt) < 15 * 60_000 : false

  let pipelineStatus: PipelineStatus
  if (runtimeFresh) pipelineStatus = 'live'
  else if (runningScans > 0) pipelineStatus = 'scan-running'
  else if (observations.length && (lastRuntimeEventAt || lastScanAt)) {
    const newest = Math.max(dateMs(lastRuntimeEventAt), dateMs(lastScanAt))
    pipelineStatus = now - newest < 24 * 3_600_000 ? 'inventory-only' : 'stale'
  } else if (certificates.length || observations.length) pipelineStatus = 'inventory-only'
  else if (raw.scannerAgents.length || raw.connectorAccounts.length) pipelineStatus = 'awaiting-telemetry'
  else pipelineStatus = 'no-collectors'

  return {
    pipelineStatus,
    agentsOnline,
    agentsTotal: raw.scannerAgents.length,
    connectorsActive,
    connectorsTotal: raw.connectorAccounts.length,
    runningScans,
    lastScanAt,
    lastRuntimeEventAt,
    lastCertificateObservationAt,
    lastConfigurationChangeAt,
    sourceCounts: {
      assets: raw.assets.length,
      runtime_crypto_events: raw.runtimeEvents.length,
      crypto_inventory: raw.cryptoInventory.length,
      certificates: raw.certificates.length,
      scanner_evidence: raw.scannerEvidence.length,
      pqc_scan_results: raw.scanResults.length,
      crypto_exposures: raw.cryptoExposures.length,
      scanner_alerts: raw.scannerAlerts.length,
      security_events: raw.securityEvents.length,
      migration_jobs: raw.migrationJobs.length,
      scanner_agents: raw.scannerAgents.length,
      connector_accounts: raw.connectorAccounts.length,
    },
    truncated: Boolean(raw.truncated),
  }
}

/* ---- timeline ------------------------------------------------------ */

function buildTimeline(input: {
  observations: TlsObservation[]
  certificates: PkiCertificate[]
  findings: TlsFinding[]
  now: number
}): TlsPkiIntelligence['timeline'] {
  const start = new Date(input.now)
  start.setHours(0, 0, 0, 0)
  const buckets: TlsPkiIntelligence['timeline'] = []
  for (let index = 13; index >= 0; index -= 1) {
    const dayStart = start.getTime() - index * DAY_MS
    const dayEnd = dayStart + DAY_MS
    const inRange = (value: string | null) => {
      const ms = dateMs(value)
      return ms >= dayStart && ms < dayEnd
    }
    buckets.push({
      label: new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      date: new Date(dayStart).toISOString(),
      observations: input.observations.filter((row) => inRange(row.observedAt)).length,
      certificates: input.certificates.filter((cert) => inRange(cert.lastObservedAt)).length,
      findings: input.findings.filter((finding) => inRange(finding.lastObservedAt)).length,
    })
  }
  return buckets
}
