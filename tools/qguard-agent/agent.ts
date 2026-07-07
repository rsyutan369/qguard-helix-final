import { createHash, X509Certificate } from 'node:crypto'
import { promises as fs } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import { collectNativeRuntimeEvents, nativeRuntimeCollectorsEnabled, type NativeRuntimeEvent } from './native-runtime-collectors.ts'
import {
  MANDATORY_PQC_CONFIG_VALUES,
  MANDATORY_PQC_STACK,
  mandatoryPqcStackMetadata,
} from '../../src/lib/crypto/mandatory-pqc-stack.ts'

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

const API_URL = (process.env.QGUARD_API_URL || DEFAULT_API_URL).replace(/\/+$/, '')
const AGENT_ID = process.env.QGUARD_AGENT_ID || ''
const AGENT_TOKEN = process.env.QGUARD_AGENT_TOKEN || ''
const REMEDIATION_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_REMEDIATION || '')
const CONFIG_PATCHES_ENABLED = /^(1|true|yes)$/i.test(process.env.QGUARD_ENABLE_CONFIG_PATCHES || '')
const MAX_REMEDIATION_JOBS = Math.max(1, Math.min(5, Number(process.env.QGUARD_MAX_REMEDIATION_JOBS || 2)))

function isoNow() {
  return new Date().toISOString()
}

function requireEnrollment() {
  if (!AGENT_ID || !AGENT_TOKEN) {
    console.error('QGuard agent is not enrolled. Set QGUARD_AGENT_ID and QGUARD_AGENT_TOKEN before running.')
    console.error(`Enroll from the dashboard API, then run: QGUARD_AGENT_ID=<id> QGUARD_AGENT_TOKEN=<token> npm run agent:scan`)
    process.exit(1)
  }
}

async function requestJson<T>(pathName: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${pathName}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      'user-agent': `qguard-local-agent/${process.env.npm_package_version || '0.1.0'}`,
      'x-qguard-agent-id': AGENT_ID,
      'x-qguard-agent-token': AGENT_TOKEN,
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

async function pullPolicy(): Promise<AgentPolicy> {
  const payload = await requestJson<{ data?: { policy?: Partial<AgentPolicy> } }>('/api/v1/agent-scanner/agent/policy')
  const policy = payload.data?.policy || {}
  return {
    enabled: policy.enabled !== false,
    intervalSeconds: Math.max(30, Math.min(60, Number(policy.intervalSeconds || 60))),
    allowedTargets: Array.isArray(policy.allowedTargets) ? policy.allowedTargets.map(String) : [],
    allowedPaths: Array.isArray(policy.allowedPaths) ? policy.allowedPaths.map(String) : [],
    scanTypes: Array.isArray(policy.scanTypes) ? policy.scanTypes.map(String) : DEFAULT_SCAN_TYPES,
    alertThreshold: String(policy.alertThreshold || 'moderate'),
  }
}

async function sendHeartbeat(status: string, telemetry: Record<string, unknown> = {}) {
  await requestJson('/api/v1/agent-scanner/agent/heartbeat', {
    method: 'POST',
    body: JSON.stringify({
      status,
      hostname: os.hostname(),
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
      version: process.env.npm_package_version || '0.1.0',
      telemetry,
    }),
  })
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

async function uploadEvidence(evidence: ScannerEvidence[]) {
  if (evidence.length === 0) return
  await requestJson('/api/v1/agent-scanner/agent/evidence', {
    method: 'POST',
    body: JSON.stringify({ evidence }),
  })
}

async function uploadRuntimeEvents(events: RuntimeCryptoEvent[]) {
  if (events.length === 0) return
  await requestJson('/api/v1/agent-scanner/agent/runtime-events', {
    method: 'POST',
    body: JSON.stringify({ events }),
  })
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

function runtimeFlags(evidence: ScannerEvidence) {
  const text = `${evidence.evidenceType} ${evidence.observedAlgorithm || ''} ${evidence.protocol || ''} ${JSON.stringify(evidence.rawEvidence || {})}`.toLowerCase()
  const isPqc = /ml-kem|ml-dsa|kyber|dilithium|sphincs|sntrup|pqc|post-quantum|hybrid/.test(text)
  const isLegacy = /rsa|ecdsa|ecc|ecdh|dsa|dh-|diffie|sha-?1|md5|3des|des|rc4|ssl|tls-?1\.[01]|aes-128-cbc/.test(text)
  const downgradeDetected = /downgrade|fallback|ssl|tls-?1\.[01]/.test(text)
  const shadowCrypto = ['package-manifest', 'config-reference', 'crypto-library', 'jwt-algorithm'].includes(evidence.evidenceType)
  const hndlRisk = isLegacy && Boolean(evidence.host || evidence.target) && /rsa|ecdsa|ecc|dh|tls|certificate/.test(text)
  const severity: RuntimeCryptoEvent['severity'] = downgradeDetected || hndlRisk || (evidence.keySize && evidence.keySize <= 1024)
    ? 'critical'
    : isLegacy
      ? 'high'
      : shadowCrypto
        ? 'moderate'
        : isPqc
          ? 'safe'
          : 'low'
  const riskScore = severity === 'critical' ? 92 : severity === 'high' ? 74 : severity === 'moderate' ? 55 : severity === 'low' ? 28 : 5
  return { isPqc, isLegacy, downgradeDetected, shadowCrypto, hndlRisk, severity, riskScore }
}

function runtimeEventFromEvidence(evidence: ScannerEvidence): RuntimeCryptoEvent {
  const flags = runtimeFlags(evidence)
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

function packageAlgorithmEvidence(packageName: string): { algorithm: string; evidenceType: EvidenceType; confidence: EvidenceConfidence } | null {
  const name = packageName.toLowerCase()
  if (name.includes('liboqs') || name.includes('oqs-provider') || name.includes('oqsprovider') || name.includes('oqs-openssl')) return { algorithm: 'ML-KEM-768', evidenceType: 'crypto-library', confidence: 'high' }
  if (name.includes('ml-kem') || name.includes('ml_dsa') || name.includes('ml-dsa') || name.includes('kyber') || name.includes('dilithium')) return { algorithm: 'ML-KEM', evidenceType: 'crypto-library', confidence: 'high' }
  if (name === 'jsonwebtoken' || name.includes('jwt')) return { algorithm: 'RSA-2048', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name === 'jose') return { algorithm: 'ECDSA-P256', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name.includes('node-rsa') || name.includes('node-forge') || name.includes('openssl')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('elliptic') || name.includes('secp256k1')) return { algorithm: 'ECC-P256', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('crypto-js')) return { algorithm: 'AES-128', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('ssh2')) return { algorithm: 'Ed25519', evidenceType: 'crypto-library', confidence: 'low' }
  if (name.includes('bcrypt') || name.includes('argon2') || name.includes('scrypt')) return { algorithm: 'SHA-256', evidenceType: 'crypto-library', confidence: 'low' }
  if (name.includes('cryptography') || name.includes('pycryptodome') || name.includes('pycrypto')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('pyjwt') || name.includes('jjwt') || name.includes('jose4j') || name.includes('go-jose')) return { algorithm: 'RSA-2048', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name.includes('bouncycastle') || name.includes('bcprov') || name.includes('portable.bouncycastle') || name.includes('botan') || name.includes('ring') || name.includes('rustls')) return { algorithm: 'ECDSA-P256', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('openssl') || name.includes('libressl') || name.includes('boringssl')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('wolfssl') || name.includes('libsodium') || name.includes('mbedtls') || name.includes('gnutls') || name.includes('system.security.cryptography') || name.includes('microsoft.identitymodel.tokens')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
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

const CONFIG_PATTERNS: Array<{ pattern: RegExp; algorithm: string; label: string }> = [
  { pattern: /\bRSA[-_ ]?(1024|2048|3072|4096)?\b/i, algorithm: 'RSA-2048', label: 'RSA reference' },
  { pattern: /\bECDSA[-_ ]?(P-?256|P-?384|nistp256|nistp384)?\b/i, algorithm: 'ECDSA-P256', label: 'ECDSA reference' },
  { pattern: /\b(ECDH|Diffie[-_ ]?Hellman|DHE)\b/i, algorithm: 'DH-2048', label: 'DH/ECDH reference' },
  { pattern: /\bssh-rsa\b/i, algorithm: 'RSA-2048', label: 'SSH RSA host/user key reference' },
  { pattern: /\bssh-dss\b/i, algorithm: 'DSA-1024', label: 'SSH DSA key reference' },
  { pattern: /\b(ed25519|ssh-ed25519)\b/i, algorithm: 'Ed25519', label: 'Ed25519 key reference' },
  { pattern: /\b(X25519|curve25519)\b/i, algorithm: 'X25519', label: 'X25519 key exchange reference' },
  { pattern: /\b(ML[-_ ]?KEM|Kyber|OQS|liboqs|oqsprovider|oqs-provider)\b/i, algorithm: 'ML-KEM-768', label: 'PQC KEM reference' },
  { pattern: /\b(ML[-_ ]?DSA|Dilithium|SPHINCS)\b/i, algorithm: 'ML-DSA-65', label: 'PQC signature reference' },
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
  next = next.replace(/(\bHostKeyAlgorithms\s+)[^\r\n]+/gi, '$1ssh-ed25519,rsa-sha2-512,rsa-sha2-256')
  next = next.replace(/(\bPubkeyAcceptedAlgorithms\s+)[^\r\n]+/gi, '$1ssh-ed25519,rsa-sha2-512,rsa-sha2-256')
  next = next.replace(/(\bKexAlgorithms\s+)[^\r\n]+/gi, `$1${MANDATORY_PQC_CONFIG_VALUES.tlsGroups}`)
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

async function scanOnce() {
  requireEnrollment()
  const policy = await pullPolicy()
  if (!policy.enabled) {
    await sendHeartbeat('disabled', { reason: 'policy_disabled' })
    console.log('Agent policy is disabled. No scan performed.')
    return
  }

  const scanTypes = new Set(policy.scanTypes.map((item) => item.toLowerCase()))
  await sendHeartbeat('active', { phase: 'starting', allowedTargets: policy.allowedTargets.length, allowedPaths: policy.allowedPaths.length })
  await sendTelemetry('agent_scan_started', 'Local scanner evidence collection started', {
    scanTypes: [...scanTypes],
    allowedTargets: policy.allowedTargets.length,
    allowedPaths: policy.allowedPaths.length,
  })

  const evidence: ScannerEvidence[] = []

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
      await sendTelemetry('agent_target_scan_failed', `Target scan failed: ${target.original}`, {
        target: target.original,
        error: (error as Error).message,
      })
      console.warn(`Target scan failed for ${target.original}: ${(error as Error).message}`)
    }
  }

  for (const root of policy.allowedPaths) {
    try {
      console.log(`Scanning authorized local path ${root}`)
      evidence.push(...await scanAllowedPath(root, scanTypes))
    } catch (error) {
      await sendTelemetry('agent_path_scan_failed', `Path scan failed: ${root}`, {
        path: root,
        error: (error as Error).message,
      })
      console.warn(`Path scan failed for ${root}: ${(error as Error).message}`)
    }
  }

  await uploadEvidence(evidence)
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
  await uploadRuntimeEvents(runtimeEvents)
  const remediationJobs = await executePendingRemediations(policy)
  await sendHeartbeat('active', {
    phase: 'completed',
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    nativeRuntimeEventCount: nativeRuntimeEvents.length,
    nativeCollectors: nativeCollectorDiagnostics,
    remediationJobs,
  })
  await sendTelemetry('agent_scan_completed', 'Local scanner evidence collection completed', {
    evidenceCount: evidence.length,
    runtimeEventCount: runtimeEvents.length,
    nativeRuntimeEventCount: nativeRuntimeEvents.length,
    remediationJobs,
  })
  console.log(`QGuard agent scan complete. Uploaded ${evidence.length} evidence record(s), ${runtimeEvents.length} runtime event(s), and processed ${remediationJobs} remediation job(s).`)
}

async function watch() {
  requireEnrollment()
  for (;;) {
    const policy = await pullPolicy()
    await scanOnce()
    const intervalMs = Math.max(30, Math.min(60, Number(policy.intervalSeconds || 60))) * 1000
    console.log(`Next scan scheduled in ${Math.round(intervalMs / 1000)} seconds.`)
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}

async function main() {
  const mode = process.argv[2] || 'scan'
  if (mode === 'watch') {
    await watch()
    return
  }
  if (mode === 'scan') {
    await scanOnce()
    return
  }

  console.error('Usage: npm run agent:scan or npm run agent:watch')
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
