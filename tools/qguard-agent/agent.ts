import { X509Certificate } from 'node:crypto'
import { promises as fs } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'

type EvidenceConfidence = 'high' | 'medium' | 'low'
type EvidenceType =
  | 'tls-certificate'
  | 'tls-protocol'
  | 'tls-cipher'
  | 'ssh-metadata'
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
}

const DEFAULT_API_URL = 'http://localhost:3000'
const MAX_CONFIG_BYTES = 512 * 1024
const MAX_FILES_PER_ROOT = 200
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
])
const CONFIG_EXTENSIONS = new Set(['.conf', '.config', '.cfg', '.json', '.yaml', '.yml', '.toml', '.ini'])
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
    intervalSeconds: Math.max(60, Math.min(86_400, Number(policy.intervalSeconds || 300))),
    allowedTargets: Array.isArray(policy.allowedTargets) ? policy.allowedTargets.map(String) : [],
    allowedPaths: Array.isArray(policy.allowedPaths) ? policy.allowedPaths.map(String) : [],
    scanTypes: Array.isArray(policy.scanTypes) ? policy.scanTypes.map(String) : ['tls', 'ssh', 'packages', 'configs'],
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
    processName: os.hostname(),
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
  return scanTypes.has('runtime') || ['tls', 'ssh', 'packages', 'configs'].some((type) => scanTypes.has(type))
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
  if (name === 'jsonwebtoken' || name.includes('jwt')) return { algorithm: 'RSA-2048', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name === 'jose') return { algorithm: 'ECDSA-P256', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name.includes('node-rsa') || name.includes('node-forge') || name.includes('openssl')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('elliptic') || name.includes('secp256k1')) return { algorithm: 'ECC-P256', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('crypto-js')) return { algorithm: 'AES-128', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('ssh2')) return { algorithm: 'Ed25519', evidenceType: 'crypto-library', confidence: 'low' }
  if (name.includes('bcrypt') || name.includes('argon2') || name.includes('scrypt')) return { algorithm: 'SHA-256', evidenceType: 'crypto-library', confidence: 'low' }
  if (name.includes('cryptography') || name.includes('pycryptodome') || name.includes('pycrypto')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('pyjwt') || name.includes('jjwt') || name.includes('jose4j') || name.includes('go-jose')) return { algorithm: 'RSA-2048', evidenceType: 'jwt-algorithm', confidence: 'medium' }
  if (name.includes('bouncycastle') || name.includes('bcprov') || name.includes('botan') || name.includes('ring') || name.includes('rustls')) return { algorithm: 'ECDSA-P256', evidenceType: 'crypto-library', confidence: 'medium' }
  if (name.includes('openssl') || name.includes('libressl') || name.includes('boringssl')) return { algorithm: 'RSA-2048', evidenceType: 'crypto-library', confidence: 'medium' }
  return null
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
      'bcprov',
      'openssl',
      'libressl',
      'boringssl',
      'botan',
      'ring',
      'rustls',
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
  { pattern: /\bSHA[-_ ]?1\b/i, algorithm: 'SHA-1', label: 'SHA-1 reference' },
  { pattern: /\bMD5\b/i, algorithm: 'MD5', label: 'MD5 reference' },
  { pattern: /\bAES[-_ ]?128\b/i, algorithm: 'AES-128', label: 'AES-128 reference' },
  { pattern: /\bAES[-_ ]?256\b/i, algorithm: 'AES-256', label: 'AES-256 reference' },
  { pattern: /\bTLSv?1\.0\b/i, algorithm: 'TLS-1.0', label: 'TLS 1.0 reference' },
  { pattern: /\bTLSv?1\.1\b/i, algorithm: 'TLS-1.1', label: 'TLS 1.1 reference' },
  { pattern: /\bTLSv?1\.2\b/i, algorithm: 'TLS-1.2', label: 'TLS 1.2 reference' },
  { pattern: /\bRS256|RS384|RS512\b/i, algorithm: 'RSA-2048', label: 'RSA JWT signing reference' },
  { pattern: /\bES256|ES384|ES512\b/i, algorithm: 'ECDSA-P256', label: 'ECDSA JWT signing reference' },
]

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
        evidenceType: line.toLowerCase().includes('jwt') || /\b(RS|ES)\d{3}\b/i.test(line) ? 'jwt-algorithm' : 'config-reference',
        assetName: path.basename(path.dirname(filePath)) || path.basename(filePath),
        assetType: 'application',
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

async function scanAllowedPath(root: string, scanTypes: Set<string>) {
  const evidence: ScannerEvidence[] = []
  const files = await walkFiles(root)

  for (const filePath of files) {
    const fileName = path.basename(filePath)
    if (scanTypes.has('packages') && PACKAGE_MANIFEST_NAMES.has(fileName)) {
      evidence.push(...await scanPackageManifest(filePath))
    }
    if (scanTypes.has('configs')) {
      evidence.push(...await scanConfigFile(filePath))
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
  const targetAlgorithm = job.targetAlgorithm || 'ML-KEM-768 hybrid'
  const common = [
    'Claim the tenant-scoped remediation workflow and capture an immutable audit event.',
    'Run pre-change discovery against the authorized target or local asset evidence.',
    `Prepare a ${targetAlgorithm} remediation plan for the detected HNDL exposure.`,
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
    },
    observedAt: isoNow(),
  }
}

async function collectRemediationValidationEvidence(job: RemediationJob, policy: AgentPolicy) {
  const evidence: ScannerEvidence[] = []
  let scanned = false
  const target = remediationTargetFromJob(job)
  const parsedTarget = target ? parseTarget(target) : null

  if (parsedTarget) {
    scanned = true
    if (parsedTarget.type === 'tls') evidence.push(...await scanTlsTarget(parsedTarget))
    if (parsedTarget.type === 'ssh') evidence.push(...await scanSshTarget(parsedTarget))
  }

  const filePath = remediationFilePathFromJob(job)
  if (filePath && fileAllowedByPolicy(filePath, policy)) {
    scanned = true
    const fileEvidence = await scanConfigFile(filePath)
    evidence.push(...fileEvidence)
    if (fileEvidence.length === 0) evidence.push(positiveConfigValidationEvidence(job, filePath))
  }

  return { evidence, scanned }
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

function patchKnownSafeCryptoToggles(content: string) {
  let next = content
  next = next.replace(/(\bPQC_ENABLED\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bPOST_QUANTUM_ENABLED\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bTLS_HYBRID_KEM\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bHYBRID_KEM\s*[:=]\s*)false\b/gi, '$1true')
  next = next.replace(/(\bssl_protocols\s+)[^;\r\n]+/gi, '$1TLSv1.2 TLSv1.3')
  return next
}

async function applyLocalConfigRemediation(job: RemediationJob, policy: AgentPolicy) {
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
  const after = patchKnownSafeCryptoToggles(before)
  if (after === before) {
    return { executed: false, manualRequired: true, reason: 'No known safe PQC/TLS toggle was found for automatic patching.', changedFiles: [] as string[] }
  }

  const backupPath = `${filePath}.qguard-backup-${Date.now()}`
  await fs.copyFile(filePath, backupPath)
  await fs.writeFile(filePath, after, 'utf8')
  return { executed: true, manualRequired: false, reason: 'Applied guarded local crypto configuration patch and created a backup.', changedFiles: [filePath, backupPath] }
}

async function attemptRemediation(job: RemediationJob, policy: AgentPolicy) {
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
    },
  })

  const precheck = await collectRemediationValidationEvidence(job, policy)
  const precheckValidation = validationFromEvidence(precheck.evidence, precheck.scanned)
  await postRemediationEvent(job.id, {
    eventType: 'agent-remediation-precheck',
    status: 'running',
    progress: 25,
    message: precheckValidation.hndlRiskRemaining
      ? `Precheck confirmed active HNDL exposure on ${job.name}.`
      : `Precheck found no active HNDL exposure on ${job.name}.`,
    metadata: { adapter, precheckValidation },
    validation: precheckValidation,
    evidence: precheck.evidence,
  })

  if (precheckValidation.passed) {
    await postRemediationEvent(job.id, {
      eventType: 'agent-remediation-validated',
      status: 'completed',
      progress: 100,
      message: `HNDL remediation already validated for ${job.name}; no active exposure remains.`,
      metadata: { adapter, plan, alreadyRemediated: true },
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
      plan,
      reason: execution.reason,
      changedFiles: execution.changedFiles,
      remediationEnabled: REMEDIATION_ENABLED,
      configPatchesEnabled: CONFIG_PATCHES_ENABLED,
    },
  })

  const validationProbe = await collectRemediationValidationEvidence(job, policy)
  const validation = validationFromEvidence(validationProbe.evidence, validationProbe.scanned)
  await postRemediationEvent(job.id, {
    eventType: 'agent-remediation-validation',
    status: validation.passed ? 'completed' : execution.manualRequired ? 'manual_required' : 'failed',
    progress: validation.passed ? 100 : 85,
    message: validation.passed
      ? `Rescan proved HNDL remediation for ${job.name}.`
      : `Rescan still shows active HNDL risk for ${job.name}; remediation remains open.`,
    metadata: {
      adapter,
      plan,
      reason: validation.notes || execution.reason,
      changedFiles: execution.changedFiles,
    },
    validation,
    evidence: validationProbe.evidence,
  })
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
  const runtimeEvents = runtimeEventsEnabled(scanTypes) ? evidence.map(runtimeEventFromEvidence) : []
  await uploadRuntimeEvents(runtimeEvents)
  const remediationJobs = await executePendingRemediations(policy)
  await sendHeartbeat('active', { phase: 'completed', evidenceCount: evidence.length, runtimeEventCount: runtimeEvents.length, remediationJobs })
  await sendTelemetry('agent_scan_completed', 'Local scanner evidence collection completed', { evidenceCount: evidence.length, runtimeEventCount: runtimeEvents.length, remediationJobs })
  console.log(`QGuard agent scan complete. Uploaded ${evidence.length} evidence record(s); processed ${remediationJobs} remediation job(s).`)
}

async function watch() {
  requireEnrollment()
  for (;;) {
    const policy = await pullPolicy()
    await scanOnce()
    const intervalMs = Math.max(60, Number(policy.intervalSeconds || 300)) * 1000
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
