import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import { LAB_BASELINE, LAB_PRIMITIVES, LAB_TLS_GROUPS, tlsCertificateFor, type LabAsset, type LabCapabilities, type LabConfiguration, type LabResult } from '@/lib/migration/sandbox-lab'

type WorkerTask = Pick<LabResult, 'profile' | 'operation'> & {
  level: 'execution' | 'emulation'
  algorithm?: string
  keySize?: number
  group?: string
  protocol?: string
  certificateType?: string
  certificateSize?: number
}
type WorkerMessage =
  | { type: 'operation'; data: string }
  | { type: 'result'; data: LabResult }
  | { type: 'capabilities'; data: LabCapabilities }

export const LAB_TIMEOUT_MS = 20_000
const maxOutput = 128 * 1024

export function runLabWorker(
  input: { probe: true } | { tasks: WorkerTask[] },
  onFrame: (message: WorkerMessage) => void,
  signal?: AbortSignal,
  timeoutMs = LAB_TIMEOUT_MS,
): Promise<void> {
  if (signal?.aborted) return Promise.reject(new Error('Lab process cancelled.'))
  const script = resolve(process.cwd(), 'src/api-server/sandbox-lab-worker.mjs')
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, ['--permission', `--allow-fs-read=${script}`, '--max-old-space-size=64', script, JSON.stringify(input)], {
      env: process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot || 'C:\\Windows' } : {},
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    })
    let pending = ''
    let received = 0
    let failure: Error | undefined
    const terminate = (message: string) => {
      failure ??= new Error(message)
      child.kill()
    }
    const cancel = () => terminate('Lab process cancelled.')
    const timer = setTimeout(() => terminate('Lab process exceeded its wall-clock limit.'), timeoutMs)
    signal?.addEventListener('abort', cancel, { once: true })
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk: string) => {
      received += Buffer.byteLength(chunk)
      if (received > maxOutput) return terminate('Lab process exceeded its output limit.')
      if (failure) return
      pending += chunk
      let boundary = pending.indexOf('\n')
      while (boundary >= 0) {
        const line = pending.slice(0, boundary)
        pending = pending.slice(boundary + 1)
        boundary = pending.indexOf('\n')
        try { onFrame(JSON.parse(line) as WorkerMessage) }
        catch { return terminate('Lab process returned an invalid evidence frame.') }
      }
    })
    child.once('error', () => { failure = new Error('The isolated lab process could not start.') })
    child.once('close', (code) => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', cancel)
      if (failure) reject(failure)
      else if (code !== 0 || pending.trim()) reject(new Error('The isolated lab process exited before finishing its evidence.'))
      else resolveRun()
    })
  })
}

let probe: { expires: number; promise: Promise<LabCapabilities> } | undefined
export function labCapabilities() {
  if (probe && probe.expires > Date.now()) return probe.promise
  const promise = (async (): Promise<LabCapabilities> => {
    const unavailable: LabCapabilities = {
      provider: `Node ${process.version} / OpenSSL ${process.versions.openssl}`,
      worker: false,
      primitives: Object.fromEntries(LAB_PRIMITIVES.map((name) => [name, false])) as LabCapabilities['primitives'],
      tlsGroups: Object.fromEntries(LAB_TLS_GROUPS.map((name) => [name, false])) as LabCapabilities['tlsGroups'],
      tlsCertificates: Object.fromEntries(LAB_TLS_GROUPS.map((name) => [name, { ecdsa: false, 'ml-dsa-65': false, 'ml-dsa-87': false }])) as LabCapabilities['tlsCertificates'],
    }
    let capabilities = unavailable
    try {
      await runLabWorker({ probe: true }, (frame) => { if (frame.type === 'capabilities') capabilities = frame.data })
      return capabilities
    } catch {
      return unavailable
    }
  })()
  probe = { expires: Date.now() + 300_000, promise }
  return promise
}

function classicalProfile(algorithm: string, sizes: number[], category?: string) {
  const raw = algorithm.toUpperCase()
  if (/\bRSA\b/.test(raw) && (category === 'signature' || !category)) {
    const bits = [2048, 3072, 4096].find((size) => sizes.includes(size) || raw.includes(String(size)))
    return bits ? { algorithm: 'rsa', keySize: bits } : null
  }
  if (/ED25519/.test(raw)) return { algorithm: 'ed25519' }
  if (/X25519/.test(raw) && !/MLKEM/.test(raw)) return { algorithm: 'x25519' }
  if (/ECDSA|ECDH/.test(raw)) {
    const bits = [256, 384].find((size) => sizes.includes(size) || raw.includes(String(size)))
    return bits ? { algorithm: /ECDSA/.test(raw) ? 'ec' : 'ecdh', keySize: bits } : null
  }
  if (/^AES[-_ ]?(128|256)[-_ ]GCM$/.test(raw)) return { algorithm: /128/.test(raw) ? 'aes-128-gcm' : 'aes-256-gcm' }
  if (raw === 'SHA3-256' || /^SHA-?256$/.test(raw)) return { algorithm: raw === 'SHA3-256' ? 'sha3-256' : 'sha256' }
  return null
}

export function buildLabTasks(asset: LabAsset, config: LabConfiguration) {
  const tasks: WorkerTask[] = []
  const results: LabResult[] = []
  const missing = (level: 'execution' | 'emulation', operation: string, detail: string) => results.push({
    level, operation, profile: LAB_BASELINE, status: 'not_tested', detail, observedAt: new Date().toISOString(),
    issues: [{ severity: 'medium', component: asset.name, explanation: detail, impact: 'A like-for-like comparison is incomplete.', remediation: 'Collect the algorithm role, parameters, and protocol configuration from the asset owner or a new assessment.', blocks: true }],
  })
  if (config.testDetected) {
    const observed = asset.algorithms.filter((row) => row.classification === 'vulnerable')
    const tested = new Set<string>()
    for (const row of observed.slice(0, 8)) {
      const baseline = classicalProfile(row.algorithm, row.keySizes, row.category)
      if (!baseline) {
        missing('execution', row.algorithm, 'The recorded parameters are incomplete or the detected primitive has no allowed baseline adapter.')
        continue
      }
      const key = JSON.stringify(baseline)
      if (tested.has(key)) continue
      tested.add(key)
      tasks.push({ level: 'execution', profile: LAB_BASELINE, operation: row.algorithm, ...baseline })
    }
    if (!observed.length) missing('execution', 'Baseline primitive', 'No vulnerable primitive and role were available in the current assessment.')
  }
  for (const algorithm of config.primitives) tasks.push({ level: 'execution', profile: algorithm, operation: 'Verify primitive', algorithm })
  if (config.compareTlsBaseline) {
    const tls = asset.tlsConfiguration
    const protocol = tls.protocols.includes('TLS 1.3') || tls.protocols.includes('TLSv1.3') ? 'TLSv1.3'
      : tls.protocols.includes('TLS 1.2') || tls.protocols.includes('TLSv1.2') ? 'TLSv1.2' : null
    const names = ['X25519MLKEM768', 'SecP384r1MLKEM1024', 'X25519', 'secp256r1', 'secp384r1']
    const group = names.find((name) => tls.keyExchange.some((value) => value.toLowerCase() === name.toLowerCase()))
    const cert = asset.certificates[0]
    const identity = cert ? classicalProfile(cert.algorithm, [cert.keySize]) : null
    if (protocol && group && identity && ['ec', 'rsa', 'ed25519'].includes(identity.algorithm)) {
      tasks.push({ level: 'emulation', profile: LAB_BASELINE, operation: 'Emulate observed TLS settings', protocol, group, certificateType: identity.algorithm, certificateSize: identity.keySize })
    } else {
      missing('emulation', 'Recorded TLS profile', 'A supported TLS version, an exact observed key agreement group, and a reproducible certificate algorithm and size are required for a baseline handshake.')
    }
  }
  const proposedCertificate = tlsCertificateFor(config)
  for (const group of config.tlsGroups) {
    tasks.push({
      level: 'emulation', profile: group, operation: 'TLS 1.3 handshake and encrypted echo',
      protocol: 'TLSv1.3', group, certificateType: proposedCertificate === 'ecdsa' ? 'ec' : proposedCertificate,
    })
  }
  return { tasks, results }
}

export function analyzeLabProposal(asset: LabAsset, configuration: LabConfiguration): LabResult {
  const issues: NonNullable<LabResult['issues']> = []
  const add = (component: string, explanation: string, impact: string, remediation: string, blocks: boolean) =>
    issues.push({ severity: blocks ? 'medium' : 'info', component, explanation, impact, remediation, blocks })
  if (asset.dependencies.length) {
    add('Recorded dependencies', `${asset.dependencies.length} linked service(s) appear in assessment evidence.`, 'Peers may fail negotiation or verification after cutover.', 'Identify each terminating proxy, application and downstream consumer. Validate them with representative binaries and trust stores.', true)
  }
  if (asset.certificates.length) {
    add('Certificate chain', `${asset.certificates.length} certificate record(s) were captured.`, 'Certificate issuance, chain size, and relying-party support may affect rollout.', 'Verify CA issuance, chain validation, and client support with a test-only certificate chain.', true)
  }
  if (!asset.algorithms.length) {
    add('Cryptographic configuration', 'No algorithm was resolved in the recorded asset assessment.', 'A replacement cannot be compared against the observed baseline.', 'Scan the asset and confirm implementation details with the owner.', true)
  }
  if (configuration.tlsGroups.length) {
    add('Transport', 'A hybrid TLS 1.3 profile was selected.', 'Larger key shares may affect intermediaries and constrained paths.', 'Measure representative handshake sizes, connectivity, and legacy peer behavior on the intended provider.', false)
  }
  add('Application and provider', 'The inventory supplies observed algorithms and relationships. Runtime library versions and complete deployment settings may require confirmation.', 'An operation can pass in the lab while the deployment remains incompatible.', 'Confirm provider version, dependencies and baseline load in a representative staging environment.', false)
  return {
    level: 'analysis', profile: 'Selected migration scenario', operation: 'Evaluate recorded risks and coverage',
    status: 'estimated', observedAt: new Date().toISOString(), issues,
    detail: `Based on ${asset.algorithms.length} observed algorithm record(s), ${asset.findings.length} recorded finding(s), and ${asset.dependencies.length} recorded dependency link(s). Production overhead and compatibility require representative tests.`,
  }
}
