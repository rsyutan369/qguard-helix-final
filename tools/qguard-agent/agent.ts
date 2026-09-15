import { createHash, X509Certificate } from 'node:crypto'
import { promises as fs, readFileSync } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import { collectNativeRuntimeEvents, nativeRuntimeCollectorsEnabled, type NativeRuntimeEvent } from './native-runtime-collectors.ts'
import {
  MANDATORY_PQC_CONFIG_VALUES,
  MANDATORY_PQC_STACK,
  mandatoryPqcStackMetadata,
  matchesMandatoryConfigValue,
} from '../../src/lib/crypto/mandatory-pqc-stack.ts'
import { KNOWLEDGE_BASE_VERSION } from '../../src/lib/crypto/knowledge-base/ground-truth.ts'
import { findAlgorithm } from '../../src/lib/crypto/knowledge-base/algorithms.ts'
import { classifyAgentEvidence } from '../../src/lib/crypto/agent-evidence-verdict.ts'
import { findLibrary } from '../../src/lib/crypto/knowledge-base/apis.ts'
import {
  describeControlPlaneFailure,
  readAgentEnvironment,
  validateControlPlane,
} from '../../src/lib/agent-installer/agent-environment.ts'
import { RULE_SET_VERSION } from '../../src/lib/crypto/knowledge-base/rules.ts'

type EvidenceConfidence = 'high' | 'medium' | 'low'
type EvidenceType =
  | 'tls-certificate'
  | 'tls-protocol'
  | 'tls-cipher'
  | 'ssh-metadata'
  | 'pki-metadata'
  | 'vpn-crypto-profile'
  | 'api-gateway-crypto-policy'
  | 'load-balancer-crypto-policy'
  | 'kubernetes-crypto-policy'
  | 'service-mesh-crypto-policy'
  | 'hsm-integration'
  | 'trust-store'
  | 'cloud-kms-policy'
  | 'cloud-hsm-policy'
  | 'cloud-certificate-manager'
  | 'cloud-database-crypto-policy'
  | 'cloud-storage-encryption-policy'
  | 'cloud-iam-key-policy'
  | 'cdn-tls-policy'
  | 'web-application-crypto-policy'
  | 'saas-crypto-policy'
  | 'network-device-crypto-policy'
  | 'database-crypto-policy'
  | 'container-crypto-policy'
  | 'package-manifest'
  | 'config-reference'
  | 'jwt-algorithm'
  | 'crypto-library'

interface AgentPolicy {
  enabled: boolean
  intervalSeconds: number
  allowedTargets: string[]
  allowedPaths: string[]
  scanTypes: string[]
  alertThreshold: string
}

interface ScannerEvidence {
  evidenceType: EvidenceType
  assetName: string
  assetType?: string | null
  target?: string | null
  host?: string | null
  port?: number | null
  protocol?: string | null
  observedAlgorithm?: string | null
  keySize?: number | null
  certificateFingerprint?: string | null
  filePath?: string | null
  packageName?: string | null
  packageVersion?: string | null
  confidence?: EvidenceConfidence
  rawEvidence?: Record<string, unknown>
  observedAt?: string
}

interface RuntimeCryptoEvent {
  eventType: string
  operationType: string
  assetName: string
  assetType?: string | null
  host?: string | null
  port?: number | null
  protocol?: string | null
  tlsVersion?: string | null
  cipherSuite?: string | null
  keyExchangeAlgorithm?: string | null
  algorithm?: string | null
  keySize?: number | null
  certificateFingerprint?: string | null
  packageName?: string | null
  packageVersion?: string | null
  processName?: string | null
  processId?: number | null
  isPqc?: boolean
  isLegacy?: boolean
  downgradeDetected?: boolean
  shadowCrypto?: boolean
  hndlRisk?: boolean
  severity?: 'critical' | 'high' | 'moderate' | 'medium' | 'low' | 'safe'
  riskScore?: number
  metadata?: Record<string, unknown>
  observedAt?: string
}

interface ScanTarget {
  original: string
  type: 'tls' | 'ssh'
  host: string
  port: number
  protocol: string
}

interface RemediationJob {
  id: string
  assetId?: string | null
  name: string
  jobType?: string
  status: string
  targetAlgorithm?: string | null
  strategy?: string | null
  progress?: number
  adapter?: string
  target?: string | null
  filePath?: string | null
  metadata?: Record<string, unknown>
}

interface RemediationValidation {
  passed: boolean
  hndlRiskRemaining: boolean
  hndlRiskCount: number
  evidenceCount: number
  scanned: boolean
  validatedAt: string
  notes?: string
  rollbackRequired?: boolean
  rollbackPerformed?: boolean
}

interface RemediationAttemptResult {
  executed: boolean
  manualRequired: boolean
  reason: string
  changedFiles: string[]
  targetPath?: string | null
  backupPath?: string | null
  snapshot?: Record<string, unknown> | null
}

const DEFAULT_API_URL = 'http://localhost:3000'
const MAX_CONFIG_BYTES = 512 * 1024
const MAX_FILES_PER_ROOT = 200
const DEFAULT_SCAN_TYPES = [
  'tls',
  'certificates',
  'pki',
  'ssh',
  'packages',
  'configs',
  'libraries',
  'vpn',
  'kubernetes',
  'service_mesh',
  'api_gateway',
  'load_balancer',
  'hsm',
  'cloud',
  'cloud_kms',
  'cloud_hsm',
  'cloud_database',
  'cloud_storage',
  'cloud_load_balancer',
  'web_application',
  'public_tls',
  'api',
  'cdn',
  'saas',
  'database',
  'network_device',
  'containers',
  'runtime',
]
const PACKAGE_MANIFEST_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'requirements.txt',
  'pyproject.toml',
  'poetry.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'go.mod',
  'Cargo.toml',
  'packages.config',
  'Directory.Packages.props',
])
const CONFIG_EXTENSIONS = new Set(['.conf', '.config', '.cfg', '.json', '.yaml', '.yml', '.toml', '.ini', '.cnf', '.ovpn', '.xml', '.properties', '.tf', '.hcl'])
const SSH_KEY_FILE_NAMES = new Set(['authorized_keys', 'known_hosts', 'id_rsa.pub', 'id_ecdsa.pub', 'id_ed25519.pub'])
const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', 'dist', 'build', '.next', 'coverage', '.turbo', '.cache'])

/**
 * Configuration file support.
 *
 * Installed deployments (systemd, the Windows startup task, containers) cannot
 * rely on an interactive shell's environment, so the agent reads a KEY=value
 * configuration file written by the installer at 0600/SYSTEM-only permissions
 * and merges it into process.env BEFORE any credential is resolved. An explicit
 * environment variable always wins over the file so operators can override a
 * single setting without editing the installed config.
 */
function configFileCandidates(): string[] {
  const explicit = process.env.QGUARD_CONFIG
  const candidates: string[] = []
  if (explicit) candidates.push(explicit)
  if (process.platform === 'win32') {
    const programData = process.env.ProgramData || 'C:\\ProgramData'
    candidates.push(path.join(programData, 'QGuardHelix', 'Agent', 'agent.env'))
  } else {
    candidates.push('/etc/qguard-agent/agent.env')
    candidates.push('/opt/qguard-agent/agent.env')
  }
  candidates.push(path.join(process.cwd(), 'qguard-agent.env'))
  return candidates
}

function loadConfigFile(): string | null {
  for (const candidate of configFileCandidates()) {
    let contents: string
    try {
      contents = readFileSync(candidate, 'utf8')
    } catch {
      continue
    }
    for (const rawLine of contents.split(/\r?\n/)) {
      const line = rawLine.trim()
      if (!line || line.startsWith('#')) continue
      const separator = line.indexOf('=')
      if (separator <= 0) continue
      const key = line.slice(0, separator).trim()
      const value = line.slice(separator + 1).trim().replace(/^["']|["']$/g, '')
      if (!key.startsWith('QGUARD_')) continue
      if (process.env[key] === undefined || process.env[key] === '') process.env[key] = value
    }
    return candidate
  }
  return null
}

const CONFIG_FILE_PATH = loadConfigFile()

function csvEnv(name: string): string[] {
  return (process.env[name] || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

const API_URL = (process.env.QGUARD_API_URL || DEFAULT_API_URL).replace(/\/+$/, '')
const AGENT_ID = process.env.QGUARD_AGENT_ID || ''
const AGENT_TOKEN = process.env.QGUARD_AGENT_TOKEN || ''
/** Injected at bundle time by tools/build-agent-release.mjs; falls back for `tsx` runs. */
const AGENT_VERSION = process.env.QGUARD_AGENT_BUILD_VERSION || process.env.QGUARD_AGENT_VERSION || '1.5.2'
const AGENT_ROLE = (process.env.QGUARD_AGENT_ROLE || 'collector').toLowerCase()
const REMEDIATION_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_REMEDIATION || '')
const CONFIG_PATCHES_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_CONFIG_PATCHES || '')
const MIGRATION_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_MIGRATION || '')
const MAX_REMEDIATION_JOBS = Math.max(1, Math.min(5, Number(process.env.QGUARD_MAX_REMEDIATION_JOBS || 2)))
const AGENT_STARTED_AT = Date.now()

/*
 * Control-plane security gate (spec §2, §3, §61, §62).
 *
 * The agent refuses to run against a control plane that does not match its
 * declared environment. This is the check that makes
 * `QGUARD_ENVIRONMENT=production` + `http://localhost:3000` impossible rather
 * than merely discouraged: an agent that believes it is in production while
 * talking plaintext to loopback will accept whatever answers on that port, and
 * every guarantee downstream — signed commands, tenant isolation, revocation —
 * assumes the control plane is the real one.
 *
 * Fails CLOSED and exits, because the alternative is an agent running on a
 * production host with its trust anchor pointed somewhere unverified.
 */
const AGENT_ENVIRONMENT = readAgentEnvironment(process.env.QGUARD_ENVIRONMENT)

function assertSecureControlPlane(): void {
  const validation = validateControlPlane(API_URL, AGENT_ENVIRONMENT)
  for (const warning of validation.warnings) {
    console.warn(`[qguard-agent] ${warning}`)
  }
  if (validation.ok) return
  console.error(describeControlPlaneFailure(validation))
  console.error('[qguard-agent] Refusing to start. No telemetry was sent and no host was read.')
  process.exit(78) // EX_CONFIG
}

/** Counters surfaced through heartbeat telemetry (spec §24 — agent health). */
const agentHealth = {
  scanCount: 0,
  errorCount: 0,
  lastScanStartedAt: null as string | null,
  lastScanDurationMs: null as number | null,
  lastError: null as string | null,
  currentJob: null as string | null,
  queueDepth: 0,
}

function isoNow() {
  return new Date().toISOString()
}

/**
 * Host health snapshot. Deliberately limited to process/host resource counters —
 * no user, file or personal data is collected (spec §24).
 */
function hostHealthTelemetry(): Record<string, unknown> {
  const totalMemory = os.totalmem()
  const freeMemory = os.freemem()
  const load = os.loadavg()
  const cpus = os.cpus() || []
  const memoryUsage = process.memoryUsage()
  return {
    agentVersion: AGENT_VERSION,
    agentRole: AGENT_ROLE,
    configSource: CONFIG_FILE_PATH ? 'config-file' : 'environment',
    host: {
      hostname: os.hostname(),
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      cpuCount: cpus.length,
      cpuModel: cpus[0]?.model || null,
      uptimeSeconds: Math.round(os.uptime()),
      loadAverage1m: Number.isFinite(load[0]) ? Number(load[0].toFixed(2)) : null,
    },
    memory: {
      totalBytes: totalMemory,
      freeBytes: freeMemory,
      usedPercent: totalMemory > 0 ? Math.round(((totalMemory - freeMemory) / totalMemory) * 100) : null,
      agentRssBytes: memoryUsage.rss,
      agentHeapUsedBytes: memoryUsage.heapUsed,
    },
    process: {
      pid: process.pid,
      nodeVersion: process.versions.node,
      agentUptimeSeconds: Math.round((Date.now() - AGENT_STARTED_AT) / 1000),
    },
    counters: {
      scanCount: agentHealth.scanCount,
      errorCount: agentHealth.errorCount,
      queueDepth: agentHealth.queueDepth,
      lastScanStartedAt: agentHealth.lastScanStartedAt,
      lastScanDurationMs: agentHealth.lastScanDurationMs,
      lastError: agentHealth.lastError,
      currentJob: agentHealth.currentJob,
    },
    capabilities: {
      remediation: REMEDIATION_ENABLED,
      configPatches: CONFIG_PATCHES_ENABLED,
      migration: MIGRATION_ENABLED,
      /* Native runtime collection is decided per scan (by the requested scan
         types) unless the operator forces it, so the capability is reported as
         the operator's setting rather than as a flat yes/no this function
         cannot honestly answer outside a scan. */
      nativeRuntimeCollectors:
        process.env.QGUARD_NATIVE_RUNTIME_ENABLED == null
          ? 'per-scan'
          : /^(1|true|yes|on)$/i.test(String(process.env.QGUARD_NATIVE_RUNTIME_ENABLED))
            ? 'forced-on'
            : 'forced-off',
    },
    /* Which rule set produced this agent's findings (spec §51, §85).
       An agent running an older build classifies with an older knowledge base,
       so two agents can legitimately disagree about the same host. Without this
       the console cannot tell that apart from an estate that actually changed,
       and the natural conclusion — "the scanner is inconsistent" — is wrong. */
    engine: {
      knowledgeBaseVersion: KNOWLEDGE_BASE_VERSION,
      ruleSetVersion: RULE_SET_VERSION,
    },
  }
}

function requireEnrollment() {
  /* Security gate first: an unenrolled agent pointed at an insecure control
     plane should be told about the control plane, because that is the problem
     that survives fixing the credentials. */
  assertSecureControlPlane()
  if (!AGENT_ID || !AGENT_TOKEN) {
    console.error('QGuard agent is not enrolled. Set QGUARD_AGENT_ID and QGUARD_AGENT_TOKEN before running.')
    console.error('Install a generated package from the Qguard Helix Agent Center (/downloads), or set the')
    console.error('variables manually: QGUARD_AGENT_ID=<id> QGUARD_AGENT_TOKEN=<token> npm run agent:scan')
    process.exit(1)
  }
}

async function requestJson<T>(pathName: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${pathName}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      'user-agent': `qguard-helix-agent/${AGENT_VERSION} (${AGENT_ROLE}; ${os.platform()}-${os.arch()})`,
      'x-qguard-agent-id': AGENT_ID,
      'x-qguard-agent-token': AGENT_TOKEN,
      'x-qguard-agent-version': AGENT_VERSION,
      ...(init.headers || {}),
    },
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message = payload?.error?.message || response.statusText || 'Agent API request failed'
    throw new Error(`${response.status} ${message}`)
  }
  return payload as T
}

/** Commands queued for this agent by the control plane (scan now, upgrade, disable). */
interface AgentCommand {
  id: string
  type: string
  queuedAt?: string
  payload?: Record<string, unknown>
}

let pendingCommands: AgentCommand[] = []

async function pullPolicy(): Promise<AgentPolicy> {
  const payload = await requestJson<{ data?: { policy?: Partial<AgentPolicy>; commands?: AgentCommand[] } }>(
    '/api/v1/agent-scanner/agent/policy',
  )
  const policy = payload.data?.policy || {}
  // The policy poll doubles as the command channel — one round trip, no extra endpoint.
  pendingCommands = Array.isArray(payload.data?.commands) ? payload.data!.commands! : []
  agentHealth.queueDepth = pendingCommands.length
  return {
    enabled: policy.enabled !== false,
    intervalSeconds: Math.max(30, Math.min(60, Number(policy.intervalSeconds || 60))),
    allowedTargets: Array.isArray(policy.allowedTargets) ? policy.allowedTargets.map(String) : [],
    allowedPaths: Array.isArray(policy.allowedPaths) ? policy.allowedPaths.map(String) : [],
    scanTypes: Array.isArray(policy.scanTypes) ? policy.scanTypes.map(String) : DEFAULT_SCAN_TYPES,
    alertThreshold: String(policy.alertThreshold || 'moderate'),
  }
}

async function acknowledgeCommand(
  commandId: string,
  status: 'running' | 'completed' | 'failed',
  result?: Record<string, unknown>,
  error?: string,
) {
  try {
    await requestJson('/api/v1/agent-scanner/agent/commands/' + encodeURIComponent(commandId) + '/ack', {
      method: 'POST',
      body: JSON.stringify({ status, result: result || null, error: error || null, observedAt: isoNow() }),
    })
  } catch (ackError) {
    // Never let an acknowledgement failure abort the work that already succeeded.
    console.warn(`Command acknowledgement failed for ${commandId}: ${(ackError as Error).message}`)
  }
}

async function sendHeartbeat(status: string, telemetry: Record<string, unknown> = {}) {
  await requestJson('/api/v1/agent-scanner/agent/heartbeat', {
    method: 'POST',
    body: JSON.stringify({
      status,
      hostname: os.hostname(),
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
      version: AGENT_VERSION,
      telemetry: { ...hostHealthTelemetry(), ...telemetry },
    }),
  })
}

/**
 * Streams a named scan stage to the control plane so the Agent Center can render
 * live progress (spec §33). Failures are swallowed: progress reporting must never
 * be able to fail a scan that is otherwise succeeding.
 */
async function reportScanStage(stage: string, progress: number, message: string, metadata: Record<string, unknown> = {}) {
  const clamped = Math.max(0, Math.min(100, Math.round(progress)))
  try {
    await requestJson('/api/v1/agent-scanner/agent/scan-progress', {
      method: 'POST',
      body: JSON.stringify({ stage, progress: clamped, message, metadata, observedAt: isoNow() }),
    })
  } catch {
    // Control plane unreachable for this frame; the next heartbeat carries the state.
  }
}

async function sendTelemetry(eventType: string, message: string, metadata: Record<string, unknown> = {}) {
  await requestJson('/api/v1/agent-scanner/agent/telemetry', {
    method: 'POST',
    body: JSON.stringify({
      eventType,
      message,
      metadata,
      observedAt: isoNow(),
    }),
  })
}

/**
 * The outcome of one upload. A scan that collected evidence but could not
 * publish all of it is DEGRADED, not failed: the distinction is what stops a
 * single rejected batch from destroying an otherwise complete scan.
 */
interface UploadOutcome {
  attempted: number
  accepted: number
  rejected: number
  outOfPolicy: boolean
  error: string | null
}

const EMPTY_UPLOAD: UploadOutcome = { attempted: 0, accepted: 0, rejected: 0, outOfPolicy: false, error: null }

/**
 * Publishes a batch and returns what happened instead of throwing.
 *
 * An upload failure — a policy rejection, a validation error, an unreachable
 * control plane — must never abort a scan that has already done its work. The
 * caller records the outcome, the scan still reaches a terminal state, and the
 * Agent Center shows the real reason rather than a bar frozen mid-flight.
 */
async function publishBatch(
  pathName: string,
  body: Record<string, unknown>,
  attempted: number,
): Promise<UploadOutcome> {
  if (attempted === 0) return { ...EMPTY_UPLOAD }
  try {
    const payload = await requestJson<{ data?: Record<string, unknown> }>(pathName, {
      method: 'POST',
      body: JSON.stringify(body),
    })
    const data = payload?.data || {}
    const rejected = Number(data.rejectedEventCount ?? data.rejectedEvidenceCount ?? 0) || 0
    const accepted = Number(
      data.acceptedEventCount ?? data.evidenceCount ?? (data.evidence as Record<string, unknown> | undefined)?.evidenceCount ?? 0,
    ) || Math.max(0, attempted - rejected)
    return {
      attempted,
      accepted: Boolean(data.outOfPolicy) ? 0 : accepted,
      rejected: Boolean(data.outOfPolicy) ? attempted : rejected,
      outOfPolicy: Boolean(data.outOfPolicy),
      error: null,
    }
  } catch (error) {
    return { attempted, accepted: 0, rejected: 0, outOfPolicy: false, error: (error as Error).message }
  }
}

async function uploadEvidence(evidence: ScannerEvidence[]): Promise<UploadOutcome> {
  return publishBatch('/api/v1/agent-scanner/agent/evidence', { evidence }, evidence.length)
}

async function uploadRuntimeEvents(events: RuntimeCryptoEvent[]): Promise<UploadOutcome> {
  return publishBatch('/api/v1/agent-scanner/agent/runtime-events', { events }, events.length)
}

async function pullRemediationJobs(): Promise<RemediationJob[]> {
  const payload = await requestJson<{ data?: { jobs?: RemediationJob[] } }>('/api/v1/agent-scanner/agent/remediation/jobs')
  return Array.isArray(payload.data?.jobs) ? payload.data.jobs : []
}

async function postRemediationEvent(
  jobId: string,
  payload: {
    eventType: string
    status: string
    progress: number
    message: string
    metadata?: Record<string, unknown>
    validation?: Partial<RemediationValidation>
    evidence?: ScannerEvidence[]
  },
) {
  return requestJson('/api/v1/agent-scanner/agent/remediation/jobs/' + encodeURIComponent(jobId) + '/event', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

function parseTarget(raw: string): ScanTarget | null {
  const value = raw.trim()
  if (!value) return null

  try {
    const url = value.includes('://') ? new URL(value) : new URL(`tls://${value}`)
    const protocol = url.protocol.replace(':', '').toLowerCase()
    const host = url.hostname
    if (!host) return null

    if (protocol === 'ssh') {
      return { original: value, type: 'ssh', host, port: Number(url.port || 22), protocol: 'ssh' }
    }

    if (protocol === 'https' || protocol === 'tls') {
      return { original: value, type: 'tls', host, port: Number(url.port || 443), protocol: 'tls' }
    }

    if (protocol === 'http') {
      return { original: value, type: 'tls', host, port: Number(url.port || 443), protocol: 'tls' }
    }
  } catch {
    const [host, port] = value.split(':')
    if (!host) return null
    return { original: value, type: Number(port) === 22 ? 'ssh' : 'tls', host, port: Number(port || 443), protocol: Number(port) === 22 ? 'ssh' : 'tls' }
  }

  return null
}

function tlsProtocolToAlgorithm(protocol: string | null) {
  if (!protocol) return null
  return protocol.replace(/^TLSv/i, 'TLS-')
}

function runtimeOperationType(evidence: ScannerEvidence) {
  const text = `${evidence.evidenceType} ${evidence.observedAlgorithm || ''} ${evidence.protocol || ''}`.toLowerCase()
  if (text.includes('cipher') || text.includes('encrypt') || text.includes('aes')) return 'encryption'
  if (text.includes('jwt') || text.includes('sign')) return 'signing'
  if (text.includes('package') || text.includes('config') || text.includes('library')) return 'discovery'
  if (text.includes('tls') || text.includes('ssh') || text.includes('kex') || text.includes('rsa') || text.includes('dh')) return 'key_exchange'
  return 'other'
}

/*
 * Delegates to the ONE classifier (`src/lib/crypto/agent-evidence-verdict.ts`).
 *
 * This used to be a set of substring regexes over the STRINGIFIED evidence
 * record. `dsa` matched ML-DSA and SLH-DSA, `ssl` matched OpenSSL, `fallback`
 * matched the policy field `classicalFallback` — and because the whole
 * `rawEvidence` blob was searched, every record carrying MANDATORY_PQC_STACK
 * inherited all three. The agent's own post-patch success attestation carries
 * it, so a remediation that WORKED scored critical, validated as failed, and
 * was automatically rolled back. See the module header for all six defects.
 */
function runtimeFlags(evidence: ScannerEvidence) {
  const verdict = classifyAgentEvidence({
    evidenceType: evidence.evidenceType,
    observedAlgorithm: evidence.observedAlgorithm,
    protocol: evidence.protocol,
    host: evidence.host,
    target: evidence.target,
    keySize: evidence.keySize,
    packageName: evidence.packageName,
    rawEvidence: evidence.rawEvidence as Record<string, unknown> | null | undefined,
  })
  return {
    isPqc: verdict.isPqc,
    isLegacy: verdict.isLegacy,
    downgradeDetected: verdict.downgradeDetected,
    shadowCrypto: verdict.shadowCrypto,
    hndlRisk: verdict.hndlRisk,
    severity: verdict.severity as RuntimeCryptoEvent['severity'],
    riskScore: verdict.riskScore,
    /* Published next to the verdict so a reviewer can see why, not just what. */
    verdictRationale: verdict.rationale,
    classifiedAlgorithm: verdict.algorithm,
    quantumStatus: verdict.quantumStatus,
  }
}

function runtimeEventFromEvidence(evidence: ScannerEvidence): RuntimeCryptoEvent {
  /* The explanation travels in metadata, not as extra top-level event columns. */
  const { verdictRationale, classifiedAlgorithm, quantumStatus, ...flags } = runtimeFlags(evidence)
  const processId = Number(evidence.rawEvidence?.processId || evidence.rawEvidence?.process_id)
  return {
    eventType: evidence.evidenceType,
    operationType: runtimeOperationType(evidence),
    assetName: evidence.assetName,
    assetType: evidence.assetType,
    host: evidence.host,
    port: evidence.port,
    protocol: evidence.protocol,
    tlsVersion: evidence.evidenceType === 'tls-protocol' ? evidence.observedAlgorithm : evidence.protocol,
    cipherSuite: evidence.evidenceType === 'tls-cipher' ? evidence.observedAlgorithm : null,
    keyExchangeAlgorithm: evidence.evidenceType === 'ssh-metadata' ? evidence.observedAlgorithm : null,
    algorithm: evidence.observedAlgorithm,
    keySize: evidence.keySize,
    certificateFingerprint: evidence.certificateFingerprint,
    packageName: evidence.packageName,
    packageVersion: evidence.packageVersion,
    processName: typeof evidence.rawEvidence?.processName === 'string'
      ? evidence.rawEvidence.processName
      : typeof evidence.rawEvidence?.process_name === 'string'
        ? evidence.rawEvidence.process_name
        : null,
    processId: Number.isFinite(processId) ? processId : null,
    ...flags,
    metadata: {
      evidenceType: evidence.evidenceType,
      target: evidence.target,
      filePath: evidence.filePath,
      confidence: evidence.confidence,
      verdictRationale,
      classifiedAlgorithm,
      quantumStatus,
      ...(evidence.rawEvidence || {}),
    },
    observedAt: evidence.observedAt || isoNow(),
  }
}

function runtimeEventsEnabled(scanTypes: Set<string>) {
  return scanTypes.has('runtime') || DEFAULT_SCAN_TYPES.some((type) => scanTypes.has(type))
}

function normalizeKeyAlgorithm(keyType: string | undefined, details: Record<string, unknown> = {}) {
  const type = String(keyType || '').toLowerCase()
  const modulusLength = Number(details.modulusLength || 0)
  const namedCurve = String(details.namedCurve || '').toLowerCase()

  if (type === 'rsa' || type === 'rsa-pss') {
    if (modulusLength <= 1024) return { algorithm: 'RSA-1024', keySize: modulusLength || 1024 }
    if (modulusLength >= 4096) return { algorithm: 'RSA-4096', keySize: modulusLength || 4096 }
    return { algorithm: 'RSA-2048', keySize: modulusLength || 2048 }
  }
  if (type === 'ec') {
    if (namedCurve.includes('384')) return { algorithm: 'ECDSA-P384', keySize: 384 }
    if (namedCurve.includes('secp256k1')) return { algorithm: 'ECC-secp256k1', keySize: 256 }
    return { algorithm: 'ECDSA-P256', keySize: 256 }
  }
  if (type.includes('ed25519')) return { algorithm: 'Ed25519', keySize: 256 }
  if (type.includes('x25519')) return { algorithm: 'X25519', keySize: 256 }

  return { algorithm: keyType || 'unknown', keySize: null }
}

async function scanTlsTarget(target: ScanTarget): Promise<ScannerEvidence[]> {
  return new Promise((resolve, reject) => {
    // Discovery probe, not a data channel: this handshake only OBSERVES the
    // endpoint's negotiated protocol/cipher/certificate so the scanner can
    // inventory misconfigured, self-signed, and legacy endpoints — the exact
    // assets it exists to find. No application data is sent over this socket.
    // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
    const socket = tls.connect({
      host: target.host,
      port: target.port,
      servername: target.host,
      rejectUnauthorized: false,
      timeout: 10_000,
    })

    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error(`TLS scan timed out for ${target.host}:${target.port}`))
    }, 12_000)

    socket.once('secureConnect', () => {
      clearTimeout(timer)
      const observedAt = isoNow()
      const peer = socket.getPeerCertificate(true)
      const cipher = socket.getCipher()
      const protocol = socket.getProtocol()
      const evidence: ScannerEvidence[] = []

      if (peer && 'raw' in peer && peer.raw) {
        const cert = new X509Certificate(peer.raw as Buffer)
        const keyDetails = normalizeKeyAlgorithm(cert.publicKey.asymmetricKeyType, cert.publicKey.asymmetricKeyDetails as Record<string, unknown>)
        evidence.push({
          evidenceType: 'tls-certificate',
          assetName: target.host,
          assetType: 'tls_endpoint',
          target: target.original,
          host: target.host,
          port: target.port,
          protocol: 'TLS',
          observedAlgorithm: keyDetails.algorithm,
          keySize: keyDetails.keySize,
          certificateFingerprint: cert.fingerprint256,
          confidence: 'high',
          rawEvidence: {
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.validFrom,
            validTo: cert.validTo,
            serialNumber: cert.serialNumber,
            publicKeyType: cert.publicKey.asymmetricKeyType,
            publicKeyDetails: cert.publicKey.asymmetricKeyDetails,
          },
          observedAt,
        })
      }

      const protocolAlgorithm = tlsProtocolToAlgorithm(protocol)
      if (protocolAlgorithm) {
        evidence.push({
          evidenceType: 'tls-protocol',
          assetName: target.host,
          assetType: 'tls_endpoint',
          target: target.original,
          host: target.host,
          port: target.port,
          protocol: protocol || 'TLS',
          observedAlgorithm: protocolAlgorithm,
          confidence: 'high',
          rawEvidence: { protocol },
          observedAt,
        })
      }

      if (cipher?.name) {
        evidence.push({
          evidenceType: 'tls-cipher',
          assetName: target.host,
          assetType: 'tls_endpoint',
          target: target.original,
          host: target.host,
          port: target.port,
          protocol: protocol || 'TLS',
          observedAlgorithm: cipher.standardName || cipher.name,
          confidence: 'high',
          rawEvidence: cipher as unknown as Record<string, unknown>,
          observedAt,
        })
      }

      socket.end()
      resolve(evidence)
    })

    socket.once('timeout', () => {
      clearTimeout(timer)
      socket.destroy()
      reject(new Error(`TLS socket timed out for ${target.host}:${target.port}`))
    })
    socket.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

function parseNameList(buffer: Buffer, offset: number) {
  if (offset + 4 > buffer.length) return { values: [] as string[], offset: buffer.length }
  const length = buffer.readUInt32BE(offset)
  const start = offset + 4
  const end = start + length
  if (end > buffer.length) return { values: [] as string[], offset: buffer.length }
  return { values: buffer.toString('utf8', start, end).split(',').filter(Boolean), offset: end }
}

function parseSshKexInit(data: Buffer) {
  if (data.length < 6) return null
  const packetLength = data.readUInt32BE(0)
  const paddingLength = data.readUInt8(4)
  const payloadStart = 5
  const payloadEnd = 4 + packetLength - paddingLength
  if (payloadEnd <= payloadStart || payloadEnd > data.length) return null
  const payload = data.subarray(payloadStart, payloadEnd)
  if (payload[0] !== 20) return null

  let offset = 17
  const kex = parseNameList(payload, offset)
  offset = kex.offset
  const hostKey = parseNameList(payload, offset)
  return { kexAlgorithms: kex.values, hostKeyAlgorithms: hostKey.values }
}

function sshAlgorithmToObserved(algorithm: string) {
  const lower = algorithm.toLowerCase()
  if (lower.includes('sntrup') || lower.includes('ml-kem') || lower.includes('kyber')) return 'ML-KEM'
  if (lower.includes('diffie-hellman-group1')) return 'DH-1024'
  if (lower.includes('diffie-hellman')) return 'DH-2048'
  if (lower.includes('ecdh') || lower.includes('nistp256')) return 'ECDSA-P256'
  if (lower.includes('nistp384')) return 'ECDSA-P384'
  if (lower.includes('curve25519')) return 'X25519'
  if (lower.includes('ssh-rsa') || lower.includes('rsa')) return 'RSA-2048'
  if (lower.includes('ssh-dss') || lower.includes('dsa')) return 'DSA-1024'
  if (lower.includes('ed25519')) return 'Ed25519'
  return algorithm
}

async function scanSshTarget(target: ScanTarget): Promise<ScannerEvidence[]> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: target.host, port: target.port })
    const chunks: Buffer[] = []
    let banner: string | null = null
    const observedAt = isoNow()
    const timer = setTimeout(() => {
      socket.destroy()
      if (banner) {
        resolve([{
          evidenceType: 'ssh-metadata',
          assetName: target.host,
          assetType: 'ssh_endpoint',
          target: target.original,
          host: target.host,
          port: target.port,
          protocol: 'SSH',
          observedAlgorithm: 'SSH metadata unavailable',
          confidence: 'low',
          rawEvidence: { banner },
          observedAt,
        }])
        return
      }
      reject(new Error(`SSH scan timed out for ${target.host}:${target.port}`))
    }, 10_000)

    socket.on('data', (chunk) => {
      chunks.push(chunk)
      const combined = Buffer.concat(chunks)
      const asText = combined.toString('utf8')
      if (!banner && asText.includes('\n')) {
        banner = asText.split(/\r?\n/)[0]
        socket.write('SSH-2.0-QGuard_LocalAgent\r\n')
      }

      const binaryStart = combined.findIndex((byte) => byte === 0 && banner !== null)
      const possiblePacket = binaryStart >= 0 ? combined.subarray(binaryStart) : Buffer.alloc(0)
      const parsed = parseSshKexInit(possiblePacket)
      if (!parsed) return

      clearTimeout(timer)
      socket.end()
      const algorithms = [
        ...parsed.kexAlgorithms.slice(0, 20).map((algorithm) => ({ algorithm, category: 'key-exchange' })),
        ...parsed.hostKeyAlgorithms.slice(0, 20).map((algorithm) => ({ algorithm, category: 'host-key' })),
      ]
      resolve(algorithms.map(({ algorithm, category }) => ({
        evidenceType: 'ssh-metadata',
        assetName: target.host,
        assetType: 'ssh_endpoint',
        target: target.original,
        host: target.host,
        port: target.port,
        protocol: 'SSH',
        observedAlgorithm: sshAlgorithmToObserved(algorithm),
        confidence: 'high',
        rawEvidence: { banner, advertisedAlgorithm: algorithm, category },
        observedAt,
      })))
    })

    socket.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    socket.once('close', () => {
      if (!banner) return
      clearTimeout(timer)
      resolve([{
        evidenceType: 'ssh-metadata',
        assetName: target.host,
        assetType: 'ssh_endpoint',
        target: target.original,
        host: target.host,
        port: target.port,
        protocol: 'SSH',
        observedAlgorithm: 'SSH metadata unavailable',
        confidence: 'low',
        rawEvidence: { banner },
        observedAt,
      }])
    })
  })
}

async function walkFiles(root: string, maxDepth = 4) {
  const files: string[] = []
  const resolvedRoot = path.resolve(root)

  async function visit(current: string, depth: number) {
    if (files.length >= MAX_FILES_PER_ROOT || depth > maxDepth) return
    let entries
    try {
      entries = await fs.readdir(current, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      if (files.length >= MAX_FILES_PER_ROOT) return
      const fullPath = path.join(current, entry.name)
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) await visit(fullPath, depth + 1)
      } else if (entry.isFile()) {
        files.push(fullPath)
      }
    }
  }

  await visit(resolvedRoot, 0)
  return files
}

/**
 * What a dependency actually proves.
 *
 * This function used to map package names to a specific algorithm AND key size:
 * `openssl` -> RSA-2048, `libsodium` -> RSA-2048, `bcrypt` -> SHA-256,
 * `crypto-js` -> AES-128. Every one of those was fabricated, and three were
 * simply wrong — libsodium ships no RSA at all, bcrypt is Blowfish-based rather
 * than SHA-256, and no manifest anywhere states a key size.
 *
 * A dependency proves that a LIBRARY IS PRESENT. That is availability, not
 * usage: OpenSSL provides dozens of algorithms and a project that depends on it
 * may use one of them or none. Reporting "RSA-2048, medium confidence" from a
 * line in a lockfile invents both the algorithm and the key size, and those
 * invented rows then flow into the CBOM, the vulnerable-component count and the
 * migration plan as though something had been measured.
 *
 * So the evidence is now the library, classified through the shared knowledge
 * base (which models `providesAlgorithms` as availability by design), with the
 * algorithm named only where the package name itself states one — `ml-kem-768`
 * does, `openssl` does not.
 */
function packageAlgorithmEvidence(
  packageName: string,
): { algorithm: string; evidenceType: EvidenceType; confidence: EvidenceConfidence; library?: string; provides?: string[]; note?: string } | null {
  const raw = String(packageName || '').trim()
  if (!raw) return null

  /* 1. Is the package a library we know? A catalogue hit is an EXACT name or
        alias match, which is a more specific signal than an algorithm name
        happening to appear inside the package name — `ssh2` is the ssh2
        library, not an observation of the SSH protocol. So the library
        catalogue is consulted first. */
  const library = findLibrary(raw)
  if (library) {
    return {
      algorithm: library.canonicalName,
      evidenceType: 'crypto-library',
      /* Low, and deliberately so. A manifest entry is the weakest evidence the
         platform accepts: it establishes capability and nothing else. */
      confidence: 'low',
      library: library.canonicalName,
      provides: library.providesAlgorithms,
      note: library.pqcCapable
        ? `${library.canonicalName} is present and ships post-quantum primitives. Availability only — whether they are used cannot be determined from a manifest.`
        : `${library.canonicalName} is present. It provides ${library.providesAlgorithms.length} algorithm(s); a manifest cannot say which, if any, are used.`,
    }
  }

  /* 2. Otherwise, does the package NAME state an algorithm? A dependency called
        `ml-kem-768` is evidence of ML-KEM in a way that one called `openssl`
        is not. */
  const named = findAlgorithm(raw)
  if (named) {
    return {
      algorithm: named.canonicalName,
      evidenceType: 'crypto-library',
      /* Still not "high": the package is declared, not proven to be called. */
      confidence: 'medium',
      library: raw,
      note: `The package name states ${named.canonicalName}. The dependency is declared; this is not proof that it is invoked at runtime.`,
    }
  }

  return null
}

function isPackageManifest(fileName: string) {
  return PACKAGE_MANIFEST_NAMES.has(fileName) || fileName.endsWith('.csproj') || fileName.endsWith('.fsproj') || fileName.endsWith('.vbproj')
}

async function scanPackageManifest(filePath: string): Promise<ScannerEvidence[]> {
  const observedAt = isoNow()
  const fileName = path.basename(filePath)
  const evidence: ScannerEvidence[] = []

  if (fileName !== 'package.json') {
    const stat = await fs.stat(filePath).catch(() => null)
    if (!stat || stat.size > MAX_CONFIG_BYTES) return evidence
    const content = await fs.readFile(filePath, 'utf8').catch(() => '')
    const lines = content.split(/\r?\n/)
    const candidates = [
      'cryptography',
      'pycryptodome',
      'pycrypto',
      'pyjwt',
      'jose',
      'jose4j',
      'jjwt',
      'go-jose',
      'jsonwebtoken',
      'node-forge',
      'node-rsa',
      'crypto-js',
      'elliptic',
      'bouncycastle',
      'portable.bouncycastle',
      'bcprov',
      'openssl',
      'libressl',
      'boringssl',
      'wolfssl',
      'libsodium',
      'mbedtls',
      'gnutls',
      'liboqs',
      'oqs-provider',
      'oqs-openssl',
      'botan',
      'ring',
      'rustls',
      'system.security.cryptography',
      'microsoft.identitymodel.tokens',
    ]
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index].toLowerCase()
      const candidate = candidates.find((item) => line.includes(item))
      if (!candidate) continue
      const match = packageAlgorithmEvidence(candidate)
      if (!match) continue
      evidence.push({
        evidenceType: match.evidenceType,
        assetName: path.basename(path.dirname(filePath)) || fileName,
        assetType: 'application',
        filePath,
        packageName: candidate,
        observedAlgorithm: match.algorithm,
        confidence: match.confidence,
        rawEvidence: {
          manifest: filePath,
          line: index + 1,
          packageName: candidate,
          redacted: true,
        },
        observedAt,
      })
    }
    return evidence
  }

  try {
    const raw = await fs.readFile(filePath, 'utf8')
    const parsed = JSON.parse(raw)
    const dependencyGroups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
    for (const group of dependencyGroups) {
      const dependencies = parsed[group]
      if (!dependencies || typeof dependencies !== 'object') continue
      for (const [name, version] of Object.entries(dependencies)) {
        const match = packageAlgorithmEvidence(name)
        if (!match) continue
        evidence.push({
          evidenceType: match.evidenceType,
          assetName: parsed.name || path.basename(path.dirname(filePath)),
          assetType: 'application',
          filePath,
          packageName: name,
          packageVersion: String(version),
          observedAlgorithm: match.algorithm,
          confidence: match.confidence,
          rawEvidence: {
            manifest: filePath,
            dependencyGroup: group,
            packageName: name,
            packageVersion: String(version),
          },
          observedAt,
        })
      }
    }
  } catch (error) {
    console.warn(`Unable to parse package manifest ${filePath}: ${(error as Error).message}`)
  }

  return evidence
}

/*
 * Order matters: `scanConfigFile` takes the FIRST rule that matches a line and
 * stops. The post-quantum and hybrid rules therefore have to come first.
 *
 * They used not to. `TLS_GROUPS=X25519MLKEM768:X25519` matched the X25519 rule
 * and was recorded as plain X25519; `SIGNATURE_ALGORITHM=Ed25519 + ML-DSA-65`
 * matched the Ed25519 rule and was recorded as plain Ed25519. Both are the
 * values the Patcher itself writes, so a SUCCESSFULLY remediated file re-read
 * as four quantum-vulnerable primitives, validation failed, and the correct
 * configuration was rolled back. A line naming both halves of a hybrid is
 * evidence of the hybrid, not of its classical half.
 */
const CONFIG_PATTERNS: Array<{ pattern: RegExp; algorithm: string; label: string }> = [
  { pattern: /\b(X25519MLKEM768|SecP256r1MLKEM768|P256MLKEM768|X25519Kyber768)\b/i, algorithm: 'X25519MLKEM768', label: 'Hybrid PQC key exchange group reference' },
  { pattern: /\b(mlkem768x25519-sha256|sntrup761x25519-sha512(@openssh\.com)?)\b/i, algorithm: 'X25519MLKEM768', label: 'Hybrid PQC SSH key exchange reference' },
  { pattern: /\b(ed25519|ssh-ed25519)\b[^\r\n]*\bML[-_ ]?DSA\b|\bML[-_ ]?DSA\b[^\r\n]*\b(ed25519|ssh-ed25519)\b/i, algorithm: 'Ed25519 + ML-DSA-65', label: 'Hybrid PQC signature reference' },
  { pattern: /\b(ML[-_ ]?KEM|Kyber)\b/i, algorithm: 'ML-KEM-768', label: 'PQC KEM reference' },
  { pattern: /\b(ML[-_ ]?DSA|Dilithium)\b/i, algorithm: 'ML-DSA-65', label: 'PQC signature reference' },
  { pattern: /\b(SLH[-_ ]?DSA|SPHINCS)\b/i, algorithm: 'SLH-DSA-SHA2-128s', label: 'PQC stateless-hash signature reference' },
  { pattern: /\b(OQS|liboqs|oqsprovider|oqs-provider)\b/i, algorithm: 'ML-KEM-768', label: 'PQC provider reference' },
  { pattern: /\bRSA[-_ ]?(1024|2048|3072|4096)?\b/i, algorithm: 'RSA-2048', label: 'RSA reference' },
  { pattern: /\bECDSA[-_ ]?(P-?256|P-?384|nistp256|nistp384)?\b/i, algorithm: 'ECDSA-P256', label: 'ECDSA reference' },
  { pattern: /\b(ECDH|Diffie[-_ ]?Hellman|DHE)\b/i, algorithm: 'DH-2048', label: 'DH/ECDH reference' },
  { pattern: /\bssh-rsa\b/i, algorithm: 'RSA-2048', label: 'SSH RSA host/user key reference' },
  { pattern: /\bssh-dss\b/i, algorithm: 'DSA-1024', label: 'SSH DSA key reference' },
  { pattern: /\b(ed25519|ssh-ed25519)\b/i, algorithm: 'Ed25519', label: 'Ed25519 key reference' },
  { pattern: /\b(X25519|curve25519)\b/i, algorithm: 'X25519', label: 'X25519 key exchange reference' },
  { pattern: /\bSHA[-_ ]?1\b/i, algorithm: 'SHA-1', label: 'SHA-1 reference' },
  { pattern: /\bMD5\b/i, algorithm: 'MD5', label: 'MD5 reference' },
  { pattern: /\b(3DES|DES|RC4)\b/i, algorithm: '3DES', label: 'Weak cipher suite reference' },
  { pattern: /\bAES[-_ ]?128\b/i, algorithm: 'AES-128', label: 'AES-128 reference' },
  { pattern: /\bAES[-_ ]?256\b/i, algorithm: 'AES-256', label: 'AES-256 reference' },
  { pattern: /\bTLSv?1\.0\b/i, algorithm: 'TLS-1.0', label: 'TLS 1.0 reference' },
  { pattern: /\bTLSv?1\.1\b/i, algorithm: 'TLS-1.1', label: 'TLS 1.1 reference' },
  { pattern: /\bTLSv?1\.2\b/i, algorithm: 'TLS-1.2', label: 'TLS 1.2 reference' },
  { pattern: /\bTLSv?1\.3\b/i, algorithm: 'TLS-1.3', label: 'TLS 1.3 reference' },
  { pattern: /\bRS256|RS384|RS512\b/i, algorithm: 'RSA-2048', label: 'RSA JWT signing reference' },
  { pattern: /\bES256|ES384|ES512\b/i, algorithm: 'ECDSA-P256', label: 'ECDSA JWT signing reference' },
]

function configEvidenceTypeFor(filePath: string, line: string): EvidenceType {
  const text = `${filePath} ${line}`.toLowerCase()
  if (/rds|aurora|cloud sql|azure sql|cosmos|spanner|dynamodb|cloud database|database/.test(text)) return 'cloud-database-crypto-policy'
  if (/s3|bucket|blob|object storage|cloud storage|storage account/.test(text)) return 'cloud-storage-encryption-policy'
  if (/cloudhsm|hsm cluster|pkcs11|nshield|luna/.test(text)) return 'cloud-hsm-policy'
  if (/kms|key vault|cloud kms|oci vault|alibaba kms|aliyun kms/.test(text)) return 'cloud-kms-policy'
  if (/acm|certificate manager|private ca|managed certificate/.test(text)) return 'cloud-certificate-manager'
  if (/cloudfront|cloudflare|akamai|fastly|cdn|front.?door/.test(text)) return 'cdn-tls-policy'
  if (/saas|salesforce|servicenow|workday|zendesk|shopify|saml|oidc/.test(text)) return 'saas-crypto-policy'
  if (/postgres|mysql|mariadb|sql server|oracle db|mongodb/.test(text)) return 'database-crypto-policy'
  if (/router|switch|firewall|f5|big-ip|netscaler|fortinet|palo alto|checkpoint/.test(text)) return 'network-device-crypto-policy'
  if (/container|dockerfile|image|registry|podman/.test(text)) return 'container-crypto-policy'
  if (/website|web app|customer portal|ecommerce|e-commerce|reverse proxy|public tls/.test(text)) return 'web-application-crypto-policy'
  if (/openvpn|wireguard|ipsec|strongswan|ikev2|ssl vpn|vpn/.test(text)) return 'vpn-crypto-profile'
  if (/ingress|gateway api|cert-manager|clusterissuer|issuer|kubernetes|k8s|namespace/.test(text)) return 'kubernetes-crypto-policy'
  if (/istio|linkerd|consul|service.?mesh|destinationrule|peerauthentication|mtls/.test(text)) return 'service-mesh-crypto-policy'
  if (/api.?gateway|kong|apigee|nginx|envoy|traefik|haproxy/.test(text)) return 'api-gateway-crypto-policy'
  if (/load.?balancer|alb|elb|nlb|front.?door|cloudfront|cdn/.test(text)) return 'load-balancer-crypto-policy'
  if (/hsm|pkcs11|cloudhsm|key.?vault|kms|nshield|luna/.test(text)) return 'hsm-integration'
  if (/truststore|keystore|cacerts|root.?ca|certificate.?authority|pki/.test(text)) return 'trust-store'
  if (/cert|certificate|issuer|csr|x509|pki/.test(text)) return 'pki-metadata'
  if (/jwt|\b(RS|ES)\d{3}\b/i.test(line)) return 'jwt-algorithm'
  return 'config-reference'
}

function configAssetTypeFor(filePath: string, line: string) {
  const text = `${filePath} ${line}`.toLowerCase()
  if (/aws|azure|gcp|google cloud|oracle cloud|oci|alibaba|aliyun|cloudhsm|cloud kms|key vault|rds|aurora|cloud sql|bucket|blob|cloudfront|front.?door/.test(text)) return 'cloud_infrastructure'
  if (/website|web app|customer portal|ecommerce|e-commerce|reverse proxy|cdn|cloudflare|akamai|fastly|public tls/.test(text)) return 'web_application'
  if (/saas|salesforce|servicenow|workday|zendesk|shopify|saml|oidc/.test(text)) return 'saas_application'
  if (/postgres|mysql|mariadb|sql server|oracle db|mongodb|database/.test(text)) return 'database'
  if (/router|switch|firewall|f5|big-ip|netscaler|fortinet|palo alto|checkpoint/.test(text)) return 'network_device'
  if (/container|dockerfile|image|registry|podman/.test(text)) return 'container'
  if (/openvpn|wireguard|ipsec|strongswan|vpn/.test(text)) return 'vpn'
  if (/ingress|gateway api|cert-manager|kubernetes|k8s|service.?mesh|istio|linkerd|consul/.test(text)) return 'kubernetes'
  if (/api.?gateway|nginx|envoy|traefik|haproxy|load.?balancer|alb|elb|cdn|cloudfront/.test(text)) return 'network_edge'
  if (/hsm|pkcs11|kms|key.?vault/.test(text)) return 'hsm'
  if (/cert|certificate|issuer|truststore|keystore|pki/.test(text)) return 'pki'
  return 'application'
}

async function scanConfigFile(filePath: string): Promise<ScannerEvidence[]> {
  const stat = await fs.stat(filePath).catch(() => null)
  if (!stat || stat.size > MAX_CONFIG_BYTES) return []
  const extension = path.extname(filePath).toLowerCase()
  if (!CONFIG_EXTENSIONS.has(extension)) return []
  if (path.basename(filePath).startsWith('.env')) return []

  const content = await fs.readFile(filePath, 'utf8').catch(() => '')
  if (!content) return []

  const evidence: ScannerEvidence[] = []
  const observedAt = isoNow()
  const lines = content.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    for (const rule of CONFIG_PATTERNS) {
      if (!rule.pattern.test(line)) continue
      /* A line that already holds the prescribed value is the approved end
         state, not an unremediated finding — see matchesMandatoryConfigValue. */
      const conformant = matchesMandatoryConfigValue(line)
      evidence.push({
        evidenceType: configEvidenceTypeFor(filePath, line),
        assetName: path.basename(path.dirname(filePath)) || path.basename(filePath),
        assetType: configAssetTypeFor(filePath, line),
        filePath,
        observedAlgorithm: rule.algorithm,
        confidence: 'medium',
        rawEvidence: {
          filePath,
          line: index + 1,
          label: rule.label,
          redacted: true,
          ...(conformant
            ? {
                policyConformant: true,
                policyKey: conformant.key,
                ...(conformant.residualNote ? { acceptedResidual: conformant.residualNote } : {}),
              }
            : {}),
        },
        observedAt,
      })
      break
    }
  }

  return evidence
}

async function scanSshKeyFile(filePath: string): Promise<ScannerEvidence[]> {
  const stat = await fs.stat(filePath).catch(() => null)
  if (!stat || stat.size > MAX_CONFIG_BYTES) return []

  const content = await fs.readFile(filePath, 'utf8').catch(() => '')
  if (!content) return []

  const evidence: ScannerEvidence[] = []
  const observedAt = isoNow()
  const lines = content.split(/\r?\n/).slice(0, 500)
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim()
    if (!line || line.startsWith('#')) continue
    const algorithm = line.includes('ssh-rsa')
      ? 'RSA-2048'
      : line.includes('ssh-dss')
        ? 'DSA-1024'
        : line.includes('ecdsa-sha2')
          ? 'ECDSA-P256'
          : line.includes('ssh-ed25519')
            ? 'Ed25519'
            : null
    if (!algorithm) continue
    evidence.push({
      evidenceType: 'ssh-metadata',
      assetName: path.basename(filePath),
      assetType: 'ssh_key_policy',
      filePath,
      protocol: 'SSH',
      observedAlgorithm: algorithm,
      confidence: 'high',
      rawEvidence: {
        filePath,
        line: index + 1,
        keyAlgorithmObserved: true,
        redacted: true,
      },
      observedAt,
    })
  }

  return evidence
}

async function scanAllowedPath(root: string, scanTypes: Set<string>) {
  const evidence: ScannerEvidence[] = []
  const files = await walkFiles(root)

  for (const filePath of files) {
    const fileName = path.basename(filePath)
    if ((scanTypes.has('packages') || scanTypes.has('libraries')) && isPackageManifest(fileName)) {
      evidence.push(...await scanPackageManifest(filePath))
    }
    if (scanTypes.has('configs')) {
      evidence.push(...await scanConfigFile(filePath))
    }
    if (scanTypes.has('ssh') && (SSH_KEY_FILE_NAMES.has(fileName) || /\.pub$/i.test(fileName))) {
      evidence.push(...await scanSshKeyFile(filePath))
    }
  }

  return evidence
}

function metadataRecord(job: RemediationJob) {
  return job.metadata && typeof job.metadata === 'object' ? job.metadata : {}
}

function firstString(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  return null
}

function scannableTarget(raw: string | null) {
  if (!raw) return null
  const value = raw.trim()
  if (!value || /^hndl\s+remediation/i.test(value)) return null
  if (/\s/.test(value) && !value.includes('://')) return null
  return value
}

function remediationTargetFromJob(job: RemediationJob) {
  const metadata = metadataRecord(job)
  return scannableTarget(firstString(
    job.target,
    metadata.target,
    metadata.endpoint,
    metadata.url,
    metadata.host,
    metadata.location,
  ))
}

function remediationFilePathFromJob(job: RemediationJob) {
  const metadata = metadataRecord(job)
  return firstString(job.filePath, metadata.filePath, metadata.file_path, metadata.path, metadata.configPath, metadata.config_path)
}

function remediationAssetName(job: RemediationJob) {
  const metadata = metadataRecord(job)
  return firstString(metadata.assetName, metadata.asset_name, job.target, job.name) || 'HNDL remediation target'
}

function adapterForJob(job: RemediationJob) {
  const metadata = metadataRecord(job)
  const text = [
    job.adapter,
    job.jobType,
    job.name,
    metadata.assetType,
    metadata.asset_type,
    metadata.provider,
    metadata.filePath,
    metadata.path,
    remediationTargetFromJob(job),
  ].filter(Boolean).join(' ').toLowerCase()

  if (/kubernetes|k8s|cluster|ingress|helm|namespace/.test(text)) return 'kubernetes'
  if (/container|docker|image|registry|podman/.test(text)) return 'container'
  if (/aws|azure|gcp|cloud|load balancer|alb|elb|cdn|cloudfront|gateway/.test(text)) return 'cloud'
  if (/iam|identity|access|oauth|oidc|saml|jwt|credential|secret|key vault|kms/.test(text)) return 'identity_access'
  if (/repo|source|code|package|dependency|manifest|config|library|application/.test(text)) return 'code_application'
  if (/https?:\/\/|website|web app|tls|ssl|ssh|protocol|certificate|cipher/.test(text)) return 'network_protocol'
  return 'universal'
}

function remediationPlan(job: RemediationJob) {
  const adapter = adapterForJob(job)
  const stack = mandatoryPqcStackMetadata(job.targetAlgorithm, `${adapter} ${job.jobType || ''} ${job.name || ''}`)
  const targetAlgorithm = String(stack.targetAlgorithm)
  const common = [
    'Claim the tenant-scoped remediation workflow and capture an immutable audit event.',
    'Run pre-change discovery against the authorized target or local asset evidence.',
    `Prepare a ${targetAlgorithm} remediation plan for the detected HNDL exposure.`,
    `Use OpenSSL 3.x with OQS Provider/liboqs integration points where this agent or connector owns the TLS or signing configuration.`,
    `Enforce TLS ${MANDATORY_PQC_STACK.tls.keyExchange}, signatures ${MANDATORY_PQC_STACK.signatures.hybrid}, encryption ${MANDATORY_PQC_STACK.encryption.symmetric}, KDF ${MANDATORY_PQC_STACK.kdf.primary}, and hashes ${MANDATORY_PQC_STACK.hashes.join(' / ')}.`,
    'Execute only policy-approved local actions or wait for the owning platform connector/operator.',
    'Rescan the target and close the job only when validation proves no active HNDL risk remains.',
  ]

  if (adapter === 'network_protocol') {
    return [
      ...common,
      'For TLS/SSH endpoints, move the endpoint behind a PQC/hybrid-capable termination layer or update the owning service cryptographic profile.',
    ]
  }
  if (adapter === 'cloud') {
    return [
      ...common,
      'For cloud assets, apply the approved PQC/hybrid profile through the cloud connector, load balancer, CDN, KMS, or certificate automation plane.',
    ]
  }
  if (adapter === 'kubernetes') {
    return [
      ...common,
      'For Kubernetes assets, update ingress, service mesh, certificate issuer, or workload crypto configuration through the cluster delivery pipeline.',
    ]
  }
  if (adapter === 'container') {
    return [
      ...common,
      'For containers, update the image or runtime configuration, rebuild, redeploy, and verify the running endpoint after rollout.',
    ]
  }
  if (adapter === 'identity_access') {
    return [
      ...common,
      'For identity assets, migrate signing, token, and key-management policies through the identity provider or key management connector.',
    ]
  }
  return common
}

function normalizePathForCompare(value: string) {
  return path.resolve(value).replace(/\\/g, '/').toLowerCase()
}

function fileAllowedByPolicy(filePath: string, policy: AgentPolicy) {
  if (policy.allowedPaths.length === 0) return false
  const normalized = normalizePathForCompare(filePath)
  return policy.allowedPaths.some((allowedPath) => {
    const root = normalizePathForCompare(allowedPath)
    return normalized === root || normalized.startsWith(`${root}/`)
  })
}

function positiveConfigValidationEvidence(job: RemediationJob, filePath: string): ScannerEvidence {
  return {
    evidenceType: 'config-reference',
    assetName: remediationAssetName(job),
    assetType: adapterForJob(job),
    filePath,
    observedAlgorithm: 'No active HNDL crypto reference detected',
    confidence: 'medium',
    rawEvidence: {
      remediationValidation: true,
      hndlRisk: false,
      validationMethod: 'authorized local config rescan',
      redacted: true,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: mandatoryPqcStackMetadata(job.targetAlgorithm, `${adapterForJob(job)} ${job.name || ''}`),
    },
    observedAt: isoNow(),
  }
}

async function collectRemediationValidationEvidence(job: RemediationJob, policy: AgentPolicy) {
  const evidence: ScannerEvidence[] = []
  let scanned = false
  let probeFailure: string | null = null
  const target = remediationTargetFromJob(job)
  const parsedTarget = target ? parseTarget(target) : null

  // Network probes are discovery, not a gate: an unreachable target (asset
  // names are not always resolvable hosts from this agent) must not abort the
  // remediation — local file evidence and connector validation still apply.
  if (parsedTarget) {
    try {
      if (parsedTarget.type === 'tls') evidence.push(...await scanTlsTarget(parsedTarget))
      if (parsedTarget.type === 'ssh') evidence.push(...await scanSshTarget(parsedTarget))
      scanned = true
    } catch (error) {
      probeFailure = `${parsedTarget.host}:${parsedTarget.port} probe failed: ${(error as Error).message}`
      console.warn(`Remediation probe skipped for ${job.name}: ${probeFailure}`)
    }
  }

  const filePath = remediationFilePathFromJob(job)
  if (filePath && fileAllowedByPolicy(filePath, policy)) {
    scanned = true
    const fileEvidence = await scanConfigFile(filePath)
    evidence.push(...fileEvidence)
    if (fileEvidence.length === 0) evidence.push(positiveConfigValidationEvidence(job, filePath))
  }

  return { evidence, scanned, probeFailure }
}

function validationFromEvidence(evidence: ScannerEvidence[], scanned: boolean): RemediationValidation {
  const riskCount = evidence.filter((item) => {
    /* A row that holds the value the approved policy prescribes is the intended
       end state. It is still published as the primitive it is, so the CBOM and
       HNDL surfaces keep seeing the residual; it just does not count as a
       remediation failure, which is what used to roll the patch back. */
    if ((item.rawEvidence as Record<string, unknown> | undefined)?.policyConformant === true) return false
    const flags = runtimeFlags(item)
    return flags.hndlRisk || flags.downgradeDetected || (flags.isLegacy && (flags.severity === 'critical' || flags.severity === 'high'))
  }).length

  return {
    passed: scanned && riskCount === 0,
    hndlRiskRemaining: riskCount > 0 || !scanned,
    hndlRiskCount: riskCount,
    evidenceCount: evidence.length,
    scanned,
    validatedAt: isoNow(),
    notes: scanned ? undefined : 'No policy-authorized validation probe was available for this asset.',
  }
}

function remediationStateFromEvidence(evidence: ScannerEvidence[], scanned: boolean) {
  const tlsProtocol = evidence.find((item) => item.evidenceType === 'tls-protocol')
  const tlsCertificate = evidence.find((item) => item.evidenceType === 'tls-certificate')
  const tlsCipher = evidence.find((item) => item.evidenceType === 'tls-cipher')
  const sshMetadata = evidence.find((item) => item.evidenceType === 'ssh-metadata')
  const libraryEvidence = evidence.filter((item) => item.evidenceType === 'crypto-library' || item.evidenceType === 'package-manifest')
  const configEvidence = evidence.filter((item) => item.evidenceType.includes('policy') || item.evidenceType === 'config-reference')
  const algorithms = Array.from(new Set(evidence.map((item) => item.observedAlgorithm).filter(Boolean))).slice(0, 16)

  return {
    capturedAt: isoNow(),
    scanned,
    evidenceCount: evidence.length,
    tlsVersion: tlsProtocol?.observedAlgorithm || tlsProtocol?.protocol || null,
    certificate: tlsCertificate?.observedAlgorithm
      ? `${tlsCertificate.observedAlgorithm}${tlsCertificate.keySize ? `-${tlsCertificate.keySize}` : ''}`
      : null,
    certificateFingerprint: tlsCertificate?.certificateFingerprint || null,
    cipherSuite: tlsCipher?.observedAlgorithm || null,
    sshHostKey: sshMetadata?.observedAlgorithm || null,
    cryptographicLibraries: libraryEvidence.slice(0, 12).map((item) => ({
      name: item.packageName || item.assetName,
      version: item.packageVersion || null,
      algorithm: item.observedAlgorithm || null,
    })),
    configurationEvidence: configEvidence.slice(0, 12).map((item) => ({
      type: item.evidenceType,
      asset: item.assetName,
      algorithm: item.observedAlgorithm || null,
      filePath: item.filePath || null,
    })),
    algorithms,
  }
}

function verificationFromValidation(validation: RemediationValidation) {
  return {
    migrationSuccessful: validation.passed === true,
    certificateValid: validation.passed === true && validation.scanned === true,
    serviceReachable: validation.scanned === true,
    rollbackRequired: validation.passed !== true,
    hndlRiskRemaining: validation.hndlRiskRemaining,
    hndlRiskCount: validation.hndlRiskCount,
    evidenceCount: validation.evidenceCount,
    verifiedAt: validation.validatedAt,
  }
}

function sha256Text(value: string) {
  return createHash('sha256').update(value).digest('hex')
}

function cryptoPolicySnapshot(content: string) {
  const lower = content.toLowerCase()
  return {
    tls12: /\btlsv?1\.2\b/i.test(content),
    tls13: /\btlsv?1\.3\b/i.test(content),
    rsa: /\brsa|ssh-rsa|rs256/i.test(content),
    ecc: /\becdsa|ecdh|es256|secp|nistp/i.test(content),
    hybridKem: /ml-kem|kyber|x25519.*ml-kem|hybrid/i.test(lower),
    mlDsa: /ml-dsa|dilithium/i.test(lower),
    weakCipher: /3des|des|rc4|md5|sha-?1/i.test(lower),
  }
}

async function rollbackLocalConfigRemediation(execution: {
  executed?: boolean
  backupPath?: string | null
  targetPath?: string | null
  snapshot?: Record<string, unknown>
}) {
  if (!execution.executed || !execution.backupPath || !execution.targetPath) {
    return { rollbackPerformed: false, rollbackRequired: true, reason: 'No restorable configuration snapshot was available.' }
  }

  await fs.copyFile(execution.backupPath, execution.targetPath)
  const restored = await fs.readFile(execution.targetPath, 'utf8').catch(() => '')
  return {
    rollbackPerformed: true,
    rollbackRequired: true,
    reason: 'Validation failed; original configuration snapshot was restored automatically.',
    restoredAt: isoNow(),
    targetPath: execution.targetPath,
    backupPath: execution.backupPath,
    restoredHash: sha256Text(restored),
    snapshot: execution.snapshot || null,
  }
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function replaceConfigStringValue(content: string, keys: string[], value: string, filePath: string) {
  const ext = path.extname(filePath).toLowerCase()
  const quoteRequired = ['.json', '.toml'].includes(ext)
  let next = content

  for (const key of keys) {
    const escaped = escapeRegex(key)
    if (quoteRequired) {
      next = next.replace(new RegExp(`(\\b${escaped}\\b\\s*[:=]\\s*["'])[^"'\r\n]+(["'])`, 'gi'), `$1${value}$2`)
    } else {
      next = next.replace(new RegExp(`(\\b${escaped}\\b\\s*[:=]\\s*)(["'])?[^"'\r\n#;]+(["'])?`, 'gi'), (_match, prefix, openQuote = '', closeQuote = '') => {
        const quote = openQuote || closeQuote
        return `${prefix}${quote}${value}${quote}`
      })
    }
  }

  return next
}

function patchKnownSafeCryptoToggles(content: string, filePath: string) {
  let next = content
  next = next.replace(/(\bPQC_ENABLED\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bPOST_QUANTUM_ENABLED\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bTLS_HYBRID_KEM\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bHYBRID_KEM\s*[:=]\s*)false\b/gi, '$1true')
  next = replaceConfigStringValue(next, ['TLS_GROUPS', 'TLS_CURVES', 'SSL_GROUPS'], MANDATORY_PQC_CONFIG_VALUES.tlsGroups, filePath)
  next = replaceConfigStringValue(next, ['KEM_ALGORITHM', 'PQC_KEM'], MANDATORY_PQC_CONFIG_VALUES.kemAlgorithm, filePath)
  next = replaceConfigStringValue(next, ['TLS_KEM_GROUP'], MANDATORY_PQC_CONFIG_VALUES.tlsKemGroup, filePath)
  next = replaceConfigStringValue(next, ['SIGNATURE_ALGORITHM', 'TLS_SIGNATURE_ALGORITHM'], MANDATORY_PQC_CONFIG_VALUES.signatureAlgorithm, filePath)
  next = replaceConfigStringValue(next, ['PQC_SIGNATURE', 'ML_DSA_ALGORITHM'], MANDATORY_PQC_CONFIG_VALUES.pqcSignature, filePath)
  next = replaceConfigStringValue(next, ['SYMMETRIC_CIPHER', 'CIPHER_SUITE', 'ENCRYPTION_ALGORITHM'], MANDATORY_PQC_CONFIG_VALUES.symmetricCipher, filePath)
  next = replaceConfigStringValue(next, ['KDF', 'KDF_ALGORITHM'], MANDATORY_PQC_CONFIG_VALUES.kdf, filePath)
  next = replaceConfigStringValue(next, ['HASH_ALGORITHM', 'DIGEST_ALGORITHM'], MANDATORY_PQC_CONFIG_VALUES.hashAlgorithm, filePath)
  next = replaceConfigStringValue(next, ['INTEGRITY_HASH'], MANDATORY_PQC_CONFIG_VALUES.integrityHash, filePath)
  next = replaceConfigStringValue(next, ['OPENSSL_PROVIDER'], MANDATORY_PQC_CONFIG_VALUES.opensslProvider, filePath)
  next = replaceConfigStringValue(next, ['OPENSSL_CONF'], MANDATORY_PQC_CONFIG_VALUES.opensslConf, filePath)
  next = replaceConfigStringValue(next, ['OQS_LIBRARIES', 'PQC_LIBRARIES'], MANDATORY_PQC_CONFIG_VALUES.oqsLibraries, filePath)
  next = replaceConfigStringValue(next, ['OQS_PROVIDER_MODULE'], MANDATORY_PQC_CONFIG_VALUES.oqsProviderModule, filePath)
  next = next.replace(/(\bssl_protocols\s+)[^;\r\n]+;?/gi, '$1TLSv1.3;')
  next = next.replace(/(\bssl_ecdh_curve\s+)[^;\r\n]+;?/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.tlsGroups};`)
  next = next.replace(/(\bssl_conf_command\s+Groups\s+)[^;\r\n]+;?/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.tlsGroups};`)
  next = next.replace(/(\bssl_ciphers\s+)[^;\r\n]+;?/gi, '$1TLS_AES_256_GCM_SHA384;')
  next = next.replace(/(\bssl_protocols\s+.*?)(TLSv1(?:\.0)?\s+|TLSv1\.1\s+|TLSv1\.2\s+)/gi, '$1TLSv1.3 ')
  /*
   * SSH directives take SSH primitive names. `KexAlgorithms` used to be given
   * MANDATORY_PQC_CONFIG_VALUES.tlsGroups ("X25519MLKEM768:X25519"), which is
   * TLS group syntax: sshd rejects the file and refuses to start, so the patch
   * broke the host and then failed its own validation.
   */
  next = next.replace(/(\bHostKeyAlgorithms\s+)[^\r\n]+/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.sshHostKeyAlgorithms}`)
  next = next.replace(/(\bPubkeyAcceptedAlgorithms\s+)[^\r\n]+/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.sshPubkeyAcceptedAlgorithms}`)
  next = next.replace(/(\bKexAlgorithms\s+)[^\r\n]+/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.sshKexAlgorithms}`)
  next = next.replace(/(\btls-version-min\s+)[^\r\n]+/gi, '$1TLSv1.3')
  next = next.replace(/(\btls-ciphersuites\s+)[^\r\n]+/gi, '$1TLS_AES_256_GCM_SHA384')
  next = replaceConfigStringValue(next, ['CERTIFICATE_PROFILE', 'PKI_PROFILE'], 'Hybrid Ed25519 + ML-DSA', filePath)
  next = replaceConfigStringValue(next, ['KEY_EXCHANGE_PROFILE', 'VPN_KEX_PROFILE'], MANDATORY_PQC_CONFIG_VALUES.tlsGroups, filePath)

  const ext = path.extname(filePath).toLowerCase()
  const lineAppendSafe = ['.cfg', '.ini', '.properties'].includes(ext)
  if (lineAppendSafe && next !== content && !/QGuard mandatory PQC stack/i.test(next)) {
    next += [
      '',
      '# QGuard mandatory PQC stack',
      `PQC_ENABLED=${MANDATORY_PQC_CONFIG_VALUES.pqcEnabled}`,
      `POST_QUANTUM_ENABLED=${MANDATORY_PQC_CONFIG_VALUES.postQuantumEnabled}`,
      `TLS_HYBRID_KEM=${MANDATORY_PQC_CONFIG_VALUES.hybridKemEnabled}`,
      `TLS_GROUPS=${MANDATORY_PQC_CONFIG_VALUES.tlsGroups}`,
      `KEM_ALGORITHM=${MANDATORY_PQC_CONFIG_VALUES.kemAlgorithm}`,
      `SIGNATURE_ALGORITHM=${MANDATORY_PQC_CONFIG_VALUES.signatureAlgorithm}`,
      `SYMMETRIC_CIPHER=${MANDATORY_PQC_CONFIG_VALUES.symmetricCipher}`,
      `KDF=${MANDATORY_PQC_CONFIG_VALUES.kdf}`,
      `HASH_ALGORITHM=${MANDATORY_PQC_CONFIG_VALUES.hashAlgorithm}`,
      `INTEGRITY_HASH=${MANDATORY_PQC_CONFIG_VALUES.integrityHash}`,
      `OPENSSL_PROVIDER=${MANDATORY_PQC_CONFIG_VALUES.opensslProvider}`,
      `OPENSSL_CONF=${MANDATORY_PQC_CONFIG_VALUES.opensslConf}`,
      `OQS_LIBRARIES=${MANDATORY_PQC_CONFIG_VALUES.oqsLibraries}`,
      `OQS_PROVIDER_MODULE=${MANDATORY_PQC_CONFIG_VALUES.oqsProviderModule}`,
      '',
    ].join(os.EOL)
  }
  return next
}

async function applyLocalConfigRemediation(job: RemediationJob, policy: AgentPolicy): Promise<RemediationAttemptResult> {
  const filePath = remediationFilePathFromJob(job)
  if (!filePath) {
    return { executed: false, manualRequired: true, reason: 'No local config file was attached to this remediation job.', changedFiles: [] as string[] }
  }
  if (!CONFIG_PATCHES_ENABLED) {
    return { executed: false, manualRequired: true, reason: 'Safe local config patching is disabled. Set QGUARD_ENABLE_CONFIG_PATCHES=true after reviewing the policy scope.', changedFiles: [] as string[] }
  }
  if (!fileAllowedByPolicy(filePath, policy)) {
    return { executed: false, manualRequired: true, reason: 'The target file is outside this agent policy allowedPaths scope.', changedFiles: [] as string[] }
  }

  const stat = await fs.stat(filePath).catch(() => null)
  if (!stat || !stat.isFile() || stat.size > MAX_CONFIG_BYTES || path.basename(filePath).startsWith('.env')) {
    return { executed: false, manualRequired: true, reason: 'The target file is not eligible for guarded local patching.', changedFiles: [] as string[] }
  }

  const before = await fs.readFile(filePath, 'utf8')
  const after = patchKnownSafeCryptoToggles(before, filePath)
  if (after === before) {
    return { executed: false, manualRequired: true, reason: 'No known safe PQC/TLS toggle was found for automatic patching.', changedFiles: [] as string[] }
  }

  const backupPath = `${filePath}.qguard-backup-${Date.now()}`
  await fs.copyFile(filePath, backupPath)
  await fs.writeFile(filePath, after, 'utf8')
  const snapshot = {
    type: 'configuration-snapshot',
    targetPath: filePath,
    backupPath,
    createdAt: isoNow(),
    beforeHash: sha256Text(before),
    afterHash: sha256Text(after),
    beforeBytes: Buffer.byteLength(before),
    afterBytes: Buffer.byteLength(after),
    beforePolicy: cryptoPolicySnapshot(before),
    afterPolicy: cryptoPolicySnapshot(after),
    certificateBackup: null,
    keyBackupMetadata: null,
    tlsPolicySnapshot: cryptoPolicySnapshot(before),
  }
  return {
    executed: true,
    manualRequired: false,
    reason: 'Applied guarded local crypto configuration patch and created a backup.',
    changedFiles: [filePath, backupPath],
    targetPath: filePath,
    backupPath,
    snapshot,
  }
}

async function attemptRemediation(job: RemediationJob, policy: AgentPolicy): Promise<RemediationAttemptResult> {
  if (!REMEDIATION_ENABLED) {
    return {
      executed: false,
      manualRequired: true,
      reason: 'Guarded remediation execution is disabled. Set QGUARD_ENABLE_REMEDIATION=true on an enrolled agent after approving the change window.',
      changedFiles: [] as string[],
    }
  }

  const adapter = adapterForJob(job)
  if (['code_application', 'container', 'kubernetes', 'universal'].includes(adapter)) {
    return applyLocalConfigRemediation(job, policy)
  }

  return {
    executed: false,
    manualRequired: true,
    reason: `${adapter} remediation requires the owning platform connector or operator credentials; the agent will validate after the change is applied.`,
    changedFiles: [] as string[],
  }
}

async function executeRemediationJob(job: RemediationJob, policy: AgentPolicy) {
  const adapter = adapterForJob(job)
  const stack = mandatoryPqcStackMetadata(job.targetAlgorithm, `${adapter} ${job.jobType || ''} ${job.name || ''}`)
  const plan = remediationPlan(job)
  await postRemediationEvent(job.id, {
    eventType: 'agent-remediation-started',
    status: 'running',
    progress: Math.max(10, job.progress || 0),
    message: `QGuard agent started guarded HNDL remediation for ${job.name}.`,
    metadata: {
      adapter,
      target: remediationTargetFromJob(job),
      filePath: remediationFilePathFromJob(job),
      plan,
      remediationEnabled: REMEDIATION_ENABLED,
      configPatchesEnabled: CONFIG_PATCHES_ENABLED,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: stack,
    },
  })

  const precheck = await collectRemediationValidationEvidence(job, policy)
  const precheckValidation = validationFromEvidence(precheck.evidence, precheck.scanned)
  const beforeState = remediationStateFromEvidence(precheck.evidence, precheck.scanned)
  await postRemediationEvent(job.id, {
    eventType: 'agent-remediation-precheck',
    status: 'running',
    progress: 25,
    message: precheckValidation.hndlRiskRemaining
      ? `Precheck confirmed active HNDL exposure on ${job.name}.`
      : `Precheck found no active HNDL exposure on ${job.name}.`,
    metadata: {
      adapter,
      workflowStage: 'ANALYZE',
      precheckValidation,
      beforeState,
      probeFailure: precheck.probeFailure,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: stack,
    },
    validation: precheckValidation,
    evidence: precheck.evidence,
  })

  if (precheckValidation.passed) {
    await postRemediationEvent(job.id, {
      eventType: 'agent-remediation-validated',
      status: 'completed',
      progress: 100,
      message: `HNDL remediation already validated for ${job.name}; no active exposure remains.`,
      metadata: {
        adapter,
        workflowStage: 'VALIDATE',
        plan,
        alreadyRemediated: true,
        beforeState,
        afterState: beforeState,
        verification: verificationFromValidation(precheckValidation),
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: stack,
      },
      validation: precheckValidation,
      evidence: precheck.evidence,
    })
    return
  }

  const execution = await attemptRemediation(job, policy)
  await postRemediationEvent(job.id, {
    eventType: execution.executed ? 'agent-remediation-executed' : 'agent-remediation-manual-required',
    status: execution.manualRequired ? 'manual_required' : 'running',
    progress: execution.manualRequired ? 55 : 70,
    message: execution.executed
      ? `Guarded remediation action executed for ${job.name}.`
      : `Manual or connector-backed remediation is required for ${job.name}: ${execution.reason}`,
    metadata: {
      adapter,
      workflowStage: execution.manualRequired ? 'APPROVE' : 'PATCH',
      plan,
      reason: execution.reason,
      changedFiles: execution.changedFiles,
      snapshot: execution.snapshot || null,
      beforeState,
      remediationEnabled: REMEDIATION_ENABLED,
      configPatchesEnabled: CONFIG_PATCHES_ENABLED,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: stack,
    },
  })

  const validationProbe = await collectRemediationValidationEvidence(job, policy)
  const validation = validationFromEvidence(validationProbe.evidence, validationProbe.scanned)
  const afterState = remediationStateFromEvidence(validationProbe.evidence, validationProbe.scanned)
  const verification = verificationFromValidation(validation)
  await postRemediationEvent(job.id, {
    eventType: 'agent-remediation-validation',
    status: validation.passed ? 'completed' : execution.manualRequired ? 'manual_required' : 'failed',
    progress: validation.passed ? 100 : 85,
    message: validation.passed
      ? `Rescan proved HNDL remediation for ${job.name}.`
      : `Rescan still shows active HNDL risk for ${job.name}; remediation remains open.`,
    metadata: {
      adapter,
      workflowStage: 'VALIDATE',
      plan,
      reason: validation.notes || execution.reason,
      changedFiles: execution.changedFiles,
      snapshot: execution.snapshot || null,
      beforeState,
      afterState,
      verification,
      probeFailure: validationProbe.probeFailure,
      mandatoryPqcStack: MANDATORY_PQC_STACK,
      cryptographicStack: stack,
    },
    validation,
    evidence: validationProbe.evidence,
  })

  if (!validation.passed && execution.executed && !execution.manualRequired) {
    const rollback = await rollbackLocalConfigRemediation(execution)
    await postRemediationEvent(job.id, {
      eventType: 'agent-remediation-rollback',
      status: 'failed',
      progress: 95,
      message: rollback.rollbackPerformed
        ? `Validation failed for ${job.name}; original configuration snapshot was restored.`
        : `Validation failed for ${job.name}; rollback could not restore automatically: ${rollback.reason}`,
      metadata: {
        adapter,
        workflowStage: 'ROLLBACK',
        plan,
        beforeState,
        failedAfterState: afterState,
        verification: { ...verification, rollbackRequired: true },
        rollback,
        snapshot: execution.snapshot || null,
        mandatoryPqcStack: MANDATORY_PQC_STACK,
        cryptographicStack: stack,
      },
      validation: {
        ...validation,
        rollbackRequired: true,
        rollbackPerformed: rollback.rollbackPerformed,
      },
      evidence: validationProbe.evidence,
    })
  }
}

async function executePendingRemediations(policy: AgentPolicy) {
  try {
    const jobs = (await pullRemediationJobs()).slice(0, MAX_REMEDIATION_JOBS)
    if (jobs.length === 0) return 0
    await sendTelemetry('agent_remediation_jobs_received', `Received ${jobs.length} HNDL remediation job(s)`, {
      jobIds: jobs.map((job) => job.id),
    })
    for (const job of jobs) {
      try {
        await executeRemediationJob(job, policy)
      } catch (error) {
        await postRemediationEvent(job.id, {
          eventType: 'agent-remediation-error',
          status: 'failed',
          progress: Math.max(0, Math.min(95, Number(job.progress || 0))),
          message: `HNDL remediation worker failed for ${job.name}: ${(error as Error).message}`,
          metadata: {
            adapter: adapterForJob(job),
            error: (error as Error).message,
          },
        }).catch(() => undefined)
        console.warn(`Remediation worker failed for ${job.name}: ${(error as Error).message}`)
      }
    }
    return jobs.length
  } catch (error) {
    await sendTelemetry('agent_remediation_poll_failed', 'Remediation job polling failed', {
      error: (error as Error).message,
    }).catch(() => undefined)
    console.warn(`Remediation polling failed: ${(error as Error).message}`)
    return 0
  }
}

/**
 * Runs one scan and GUARANTEES a terminal state.
 *
 * Every exit path — success, failure, or a crash inside a collector — emits a
 * final progress frame and a terminal heartbeat phase. Without this, an error
 * anywhere after the last reported stage left the Agent Center rendering that
 * stage forever: a scan that had already died still showed
 * "Calculating quantum exposure - 85%", and its session never closed.
 */
async function scanOnce(policyOverride?: AgentPolicy) {
  const startedAt = Date.now()
  try {
    const result = await runScanCycle(policyOverride)
    return result
  } catch (error) {
    const message = (error as Error).message || 'Scan failed'
    agentHealth.errorCount += 1
    agentHealth.lastError = message
    agentHealth.lastScanDurationMs = Date.now() - startedAt

    // Terminal frame first: the operator must never be left watching a bar that
    // stopped moving with no explanation of why.
    await reportScanStage('scan_failed', 100, `Scan failed: ${message}`, {
      failed: true,
      error: message,
      durationMs: agentHealth.lastScanDurationMs,
    })
    // Terminal phase second: this is what closes the scan session in the
    // Agent Center's scan history.
    await sendHeartbeat('error', {
      phase: 'failed',
      error: message,
      durationMs: agentHealth.lastScanDurationMs,
    }).catch(() => undefined)
    await sendTelemetry('agent_scan_failed', 'Local scanner evidence collection failed', {
      error: message,
      durationMs: agentHealth.lastScanDurationMs,
    }).catch(() => undefined)
    throw error
  }
}

async function runScanCycle(policyOverride?: AgentPolicy) {
  requireEnrollment()
  const policy = policyOverride || await pullPolicy()
  if (!policy.enabled) {
    await sendHeartbeat('disabled', { reason: 'policy_disabled' })
    console.log('Agent policy is disabled. No scan performed.')
    return
  }

  const scanStartedAt = Date.now()
  agentHealth.lastScanStartedAt = isoNow()

  const scanTypes = new Set(policy.scanTypes.map((item) => item.toLowerCase()))
  await sendHeartbeat('scanning', { phase: 'starting', allowedTargets: policy.allowedTargets.length, allowedPaths: policy.allowedPaths.length })
  await sendTelemetry('agent_scan_started', 'Local scanner evidence collection started', {
    scanTypes: [...scanTypes],
    allowedTargets: policy.allowedTargets.length,
    allowedPaths: policy.allowedPaths.length,
  })
  await reportScanStage('connecting', 2, 'Connecting to agent', {
    hostname: os.hostname(),
    scanTypes: [...scanTypes],
  })
  await reportScanStage('system_inventory', 8, 'Collecting system inventory', {
    platform: `${os.platform()} ${os.release()} ${os.arch()}`,
    cpuCount: (os.cpus() || []).length,
  })

  const evidence: ScannerEvidence[] = []
  const targetCount = policy.allowedTargets.length
  let targetsDone = 0

  if (targetCount > 0) {
    await reportScanStage('discovering_cryptography', 15, 'Discovering cryptography on authorized targets', { targets: targetCount })
  }

  for (const rawTarget of policy.allowedTargets) {
    const target = parseTarget(rawTarget)
    if (!target) continue
    try {
      if (target.type === 'tls' && scanTypes.has('tls')) {
        console.log(`Scanning TLS metadata for ${target.host}:${target.port}`)
        evidence.push(...await scanTlsTarget(target))
      }
      if (target.type === 'ssh' && scanTypes.has('ssh')) {
        console.log(`Scanning SSH metadata for ${target.host}:${target.port}`)
        evidence.push(...await scanSshTarget(target))
      }
    } catch (error) {
      agentHealth.errorCount += 1
      agentHealth.lastError = (error as Error).message
      await sendTelemetry('agent_target_scan_failed', `Target scan failed: ${target.original}`, {
        target: target.original,
        error: (error as Error).message,
      })
      console.warn(`Target scan failed for ${target.original}: ${(error as Error).message}`)
    }
    targetsDone += 1
    // 15% -> 45% across the authorised target sweep (TLS certificates + SSH).
    await reportScanStage(
      target.type === 'ssh' ? 'analyzing_tls' : 'inspecting_certificates',
      15 + Math.round((targetsDone / Math.max(1, targetCount)) * 30),
      target.type === 'ssh' ? `Analyzing SSH key exchange on ${target.host}` : `Inspecting certificates and TLS on ${target.host}`,
      { target: target.original, evidenceSoFar: evidence.length },
    )
  }

  const pathCount = policy.allowedPaths.length
  let pathsDone = 0
  if (pathCount > 0) {
    await reportScanStage('discovering_cryptography', 50, 'Discovering cryptography in authorized paths', { paths: pathCount })
  }

  for (const root of policy.allowedPaths) {
    try {
      console.log(`Scanning authorized local path ${root}`)
      evidence.push(...await scanAllowedPath(root, scanTypes))
    } catch (error) {
      agentHealth.errorCount += 1
      agentHealth.lastError = (error as Error).message
      await sendTelemetry('agent_path_scan_failed', `Path scan failed: ${root}`, {
        path: root,
        error: (error as Error).message,
      })
      console.warn(`Path scan failed for ${root}: ${(error as Error).message}`)
    }
    pathsDone += 1
    // 50% -> 70% across the authorised filesystem sweep.
    await reportScanStage(
      'discovering_cryptography',
      50 + Math.round((pathsDone / Math.max(1, pathCount)) * 20),
      `Scanned authorized path ${root}`,
      { path: root, evidenceSoFar: evidence.length },
    )
  }

  await reportScanStage('building_cbom', 75, 'Building CBOM from collected evidence', { evidenceCount: evidence.length })
  const evidenceUpload = await uploadEvidence(evidence)
  await reportScanStage('calculating_exposure', 85, 'Calculating quantum exposure', {
    evidenceCount: evidence.length,
    evidenceAccepted: evidenceUpload.accepted,
    evidenceRejected: evidenceUpload.rejected,
  })
  const evidenceRuntimeEvents = runtimeEventsEnabled(scanTypes) ? evidence.map(runtimeEventFromEvidence) : []
  let nativeRuntimeEvents: NativeRuntimeEvent[] = []
  let nativeCollectorDiagnostics: unknown[] = []

  if (nativeRuntimeCollectorsEnabled(scanTypes)) {
    try {
      const nativeRun = await collectNativeRuntimeEvents({
        allowedTargets: policy.allowedTargets,
        allowedPaths: policy.allowedPaths,
        scanTypes: [...scanTypes],
        intervalSeconds: policy.intervalSeconds,
      })
      nativeRuntimeEvents = nativeRun.events
      nativeCollectorDiagnostics = nativeRun.diagnostics
      await sendTelemetry('agent_native_runtime_capture', 'Native runtime collector cycle completed', {
        nativeRuntimeEvents: nativeRuntimeEvents.length,
        collectors: nativeCollectorDiagnostics,
      })
    } catch (error) {
      nativeCollectorDiagnostics = [{ status: 'error', message: (error as Error).message }]
      await sendTelemetry('agent_native_runtime_failed', 'Native runtime collector cycle failed', {
        error: (error as Error).message,
      }).catch(() => undefined)
      console.warn(`Native runtime collection failed: ${(error as Error).message}`)
    }
  }

  const runtimeEvents = [...evidenceRuntimeEvents, ...nativeRuntimeEvents]
  const runtimeUpload = await uploadRuntimeEvents(runtimeEvents)
  // Anything the control plane declined is reported, never hidden and never
  // fatal. `outOfPolicy` is the operator's signal that this agent has no
  // authorised scope beyond its own host.
  const uploadErrors = [evidenceUpload.error, runtimeUpload.error].filter(Boolean) as string[]
  const rejectedByPolicy = evidenceUpload.rejected + runtimeUpload.rejected
  await reportScanStage('publishing_findings', 92, 'Publishing findings to the control plane', {
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    accepted: evidenceUpload.accepted + runtimeUpload.accepted,
    rejectedByPolicy,
    outOfPolicy: evidenceUpload.outOfPolicy || runtimeUpload.outOfPolicy,
    uploadErrors,
  })
  const remediationJobs = await executePendingRemediations(policy)

  agentHealth.scanCount += 1
  agentHealth.lastScanDurationMs = Date.now() - scanStartedAt

  const degraded = uploadErrors.length > 0
  await sendHeartbeat(degraded ? 'degraded' : 'active', {
    phase: 'completed',
    degraded,
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    nativeRuntimeEventCount: nativeRuntimeEvents.length,
    nativeCollectors: nativeCollectorDiagnostics,
    acceptedByControlPlane: evidenceUpload.accepted + runtimeUpload.accepted,
    rejectedByPolicy,
    outOfPolicy: evidenceUpload.outOfPolicy || runtimeUpload.outOfPolicy,
    uploadErrors,
    remediationJobs,
  })
  await sendTelemetry('agent_scan_completed', 'Local scanner evidence collection completed', {
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    nativeRuntimeEventCount: nativeRuntimeEvents.length,
    remediationJobs,
    durationMs: agentHealth.lastScanDurationMs,
  })
  await reportScanStage(
    'scan_complete',
    100,
    degraded
      ? `Scan complete with ${uploadErrors.length} publish error(s)`
      : rejectedByPolicy > 0
        ? `Scan complete - ${rejectedByPolicy} observation(s) outside authorized scope`
        : 'Scan complete',
    {
      evidenceCount: evidence.length,
      runtimeEventCount: runtimeEvents.length,
      accepted: evidenceUpload.accepted + runtimeUpload.accepted,
      rejectedByPolicy,
      outOfPolicy: evidenceUpload.outOfPolicy || runtimeUpload.outOfPolicy,
      degraded,
      uploadErrors,
      remediationJobs,
      durationMs: agentHealth.lastScanDurationMs,
    },
  )
  // Report what the control plane ACCEPTED, not what was collected: claiming an
  // upload that was rejected is how a broken pipeline looks healthy in a log.
  console.log(
    `QGuard agent scan complete. Collected ${evidence.length} evidence record(s) and ${runtimeEvents.length} runtime event(s); ` +
    `control plane accepted ${evidenceUpload.accepted + runtimeUpload.accepted}` +
    (rejectedByPolicy > 0 ? `, declined ${rejectedByPolicy} as out of authorized scope` : '') +
    (uploadErrors.length > 0 ? `; ${uploadErrors.length} publish error(s): ${uploadErrors.join('; ')}` : '') +
    `. Processed ${remediationJobs} remediation job(s).`,
  )
  if (evidenceUpload.outOfPolicy || runtimeUpload.outOfPolicy) {
    console.log('No observation was in authorized scope. Add authorized targets or paths to this agent in the Agent Center to widen what it may report.')
  }
  return {
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    acceptedCount: evidenceUpload.accepted + runtimeUpload.accepted,
    rejectedByPolicy,
    degraded,
    remediationJobs,
  }
}

/**
 * Executes the commands the control plane queued for this agent. Each command is
 * acknowledged with a running -> completed/failed transition so the Agent Center
 * can show real execution state rather than an optimistic "requested".
 */
async function drainCommands(policy: AgentPolicy): Promise<{ scanned: boolean }> {
  if (pendingCommands.length === 0) return { scanned: false }
  const commands = [...pendingCommands]
  pendingCommands = []
  let scanned = false

  for (const command of commands) {
    agentHealth.currentJob = `${command.type}:${command.id}`
    await acknowledgeCommand(command.id, 'running')
    try {
      switch (command.type) {
        case 'scan':
        case 'rescan_validation': {
          const result = await scanOnce(policy)
          scanned = true
          await acknowledgeCommand(command.id, 'completed', result || {})
          break
        }
        case 'disable': {
          await sendHeartbeat('disabled', { reason: 'operator_disabled', commandId: command.id })
          await acknowledgeCommand(command.id, 'completed', { disabled: true })
          console.log('Agent disabled by operator command; collection paused until re-enabled.')
          break
        }
        case 'enable': {
          await sendHeartbeat('active', { reason: 'operator_enabled', commandId: command.id })
          await acknowledgeCommand(command.id, 'completed', { enabled: true })
          break
        }
        case 'upgrade': {
          // The agent never self-replaces its binary: an upgrade is applied by the
          // platform's own installer/service manager, which verifies the signed
          // digest first (spec §22 — no arbitrary binaries pushed to agents).
          const targetVersion = String(command.payload?.targetVersion || '')
          await acknowledgeCommand(command.id, 'completed', {
            acknowledged: true,
            currentVersion: AGENT_VERSION,
            targetVersion,
            appliesVia: process.platform === 'win32' ? 'scheduled-task reinstall' : 'systemd package reinstall',
            note: 'Re-run the generated installer to apply. The runtime does not self-replace.',
          })
          console.log(`Upgrade to ${targetVersion || 'latest'} acknowledged. Re-run the installer to apply it.`)
          break
        }
        default: {
          await acknowledgeCommand(command.id, 'failed', undefined, `Unsupported command type: ${command.type}`)
        }
      }
    } catch (error) {
      agentHealth.errorCount += 1
      agentHealth.lastError = (error as Error).message
      await acknowledgeCommand(command.id, 'failed', undefined, (error as Error).message)
      console.warn(`Command ${command.type} (${command.id}) failed: ${(error as Error).message}`)
    } finally {
      agentHealth.currentJob = null
    }
  }

  return { scanned }
}

async function watch() {
  requireEnrollment()
  for (;;) {
    let intervalSeconds = 60
    try {
      const policy = await pullPolicy()
      intervalSeconds = Number(policy.intervalSeconds || 60)
      // Operator-queued work runs first so "Run scan" feels immediate. If it
      // already ran a full scan, this cycle's scheduled scan is redundant —
      // running it anyway would double every evidence upload.
      const { scanned } = await drainCommands(policy)
      if (!policy.enabled) {
        await sendHeartbeat('disabled', { reason: 'policy_disabled' })
      } else if (!scanned) {
        await scanOnce(policy)
      }
    } catch (error) {
      // A single failed cycle must never terminate a supervised service: log it,
      // report it, and try again on the next interval.
      agentHealth.errorCount += 1
      agentHealth.lastError = (error as Error).message
      console.error(`Scan cycle failed: ${(error as Error).message}`)
      try {
        await sendHeartbeat('error', { error: (error as Error).message })
      } catch {
        // Control plane unreachable — retry on the next cycle.
      }
    }
    const intervalMs = Math.max(30, Math.min(60, intervalSeconds)) * 1000
    console.log(`Next scan scheduled in ${Math.round(intervalMs / 1000)} seconds.`)
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}

async function printStatus() {
  requireEnrollment()
  const policy = await pullPolicy()
  console.log(`QGuard Helix Agent ${AGENT_VERSION} (${AGENT_ROLE})`)
  console.log(`  Agent ID       : ${AGENT_ID}`)
  console.log(`  Control plane  : ${API_URL}`)
  console.log(`  Config source  : ${CONFIG_FILE_PATH || 'environment variables'}`)
  console.log(`  Policy enabled : ${policy.enabled}`)
  console.log(`  Interval       : ${policy.intervalSeconds}s`)
  console.log(`  Allowed targets: ${policy.allowedTargets.length}`)
  console.log(`  Allowed paths  : ${policy.allowedPaths.length}`)
  console.log(`  Scan types     : ${policy.scanTypes.join(', ') || 'none'}`)
  console.log(`  Queued commands: ${pendingCommands.length}`)
  await sendHeartbeat('active', { phase: 'status_check' })
  console.log('  Heartbeat      : delivered')
}

async function main() {
  const mode = process.argv[2] || 'scan'
  if (mode === 'watch') {
    await watch()
    return
  }
  if (mode === 'scan') {
    requireEnrollment()
    const policy = await pullPolicy()
    const { scanned } = await drainCommands(policy)
    if (!scanned) await scanOnce(policy)
    return
  }
  if (mode === 'status') {
    await printStatus()
    return
  }
  if (mode === 'version' || mode === '--version' || mode === '-v') {
    console.log(AGENT_VERSION)
    return
  }

  console.error('Usage: qguard-agent <scan|watch|status|version>')
  process.exit(1)
}

main().catch(async (error) => {
  console.error((error as Error).stack || (error as Error).message)
  try {
    await sendHeartbeat('error', { error: (error as Error).message })
  } catch {
    // The backend may be unreachable; keep the original error visible.
  }
  process.exit(1)
})
