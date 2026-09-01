import { spawn } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

type Severity = 'critical' | 'high' | 'moderate' | 'medium' | 'low' | 'safe'

export interface NativeCollectorPolicy {
  allowedTargets: string[]
  allowedPaths: string[]
  scanTypes: string[]
  intervalSeconds?: number
}

export interface NativeRuntimeEvent {
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
  severity?: Severity
  riskScore?: number
  metadata?: Record<string, unknown>
  observedAt?: string
}

interface NativeCollectorDiagnostic {
  collectorId: string
  supported: boolean
  events: number
  status: 'collected' | 'unsupported' | 'error'
  message?: string
}

export interface NativeCollectorRun {
  events: NativeRuntimeEvent[]
  diagnostics: NativeCollectorDiagnostic[]
}

interface NativeRuntimeCollector {
  id: string
  supported(): Promise<boolean>
  collect(captureMs: number): Promise<NativeRuntimeEvent[]>
}

type CommandResult = {
  stdout: string
  stderr: string
  code: number | null
  timedOut: boolean
}

const HOSTNAME = os.hostname()
const PLATFORM = os.platform()
const DEFAULT_CAPTURE_SECONDS = 8
const MAX_NATIVE_EVENTS = 500
const MAX_PROCESS_ROWS = 350
const MAX_CERTIFICATE_ROWS = 120

/**
 * WHAT KIND of observation a collector made. The class decides what may be
 * claimed from it — a loaded library is evidence that cryptography is PRESENT,
 * never evidence that a specific weak algorithm is in USE.
 */
type EvidenceClass =
  /** A crypto library or provider is loaded in a process. Presence only. */
  | 'library-presence'
  /** An X.509 certificate whose algorithms are stated by the platform store. */
  | 'certificate'
  /** An observed crypto/TLS API invocation (ETW, eBPF uprobe). */
  | 'crypto-api-call'
  /** Supplied verbatim by an operator-configured external collector. */
  | 'external'

/**
 * Crypto library families, matched on the MODULE name.
 *
 * These identify which provider is present. They deliberately say nothing about
 * algorithm strength: `libssl` present is not `SSLv3` in use.
 */
const CRYPTO_LIBRARY_SIGNALS = [
  { pattern: /\b(?:openssl|libssl|libcrypto|boringssl|libressl)\b/i, algorithm: 'OpenSSL-compatible crypto library' },
  { pattern: /\b(?:schannel|capi2|cng|bcrypt|ncrypt|crypt32)\b/i, algorithm: 'Windows Crypto API (CNG/Schannel)' },
  { pattern: /\b(?:gnutls|mbedtls|wolfssl|nss|rustls|botan|libsodium|libgcrypt)\b/i, algorithm: 'Runtime crypto library' },
  { pattern: /\b(?:oqs|liboqs|pqclean)\b/i, algorithm: 'Post-quantum crypto library' },
  { pattern: /\b(?:keystore|truststore|pkcs11|hsm|kms)\b/i, algorithm: 'Key store or key management integration' },
]

/**
 * Algorithms this agent is allowed to NAME, matched against a STATED algorithm
 * field only - never against a file path, a command line or a module map. A
 * path containing "OpenSSL" says a library is present; it does not name an
 * algorithm, and treating it as one published criticals nobody observed.
 */
const ALGORITHM_SIGNALS: Array<{ pattern: RegExp; kind: 'pqc' | 'vulnerable' | 'broken' | 'symmetric' }> = [
  { pattern: /\b(?:ml-kem|ml-dsa|slh-dsa|kyber|dilithium|sphincs\+?|falcon|sntrup\d*)\b/i, kind: 'pqc' },
  { pattern: /\b(?:rsa|dsa|ecc|ec|ecdsa|ecdh|ecdhe|dhe|diffie-?hellman|ed25519|x25519|id-ecpublickey|secp\d+r?\d*|prime256v1|nistp\d+)\b/i, kind: 'vulnerable' },
  { pattern: /\b(?:md5|sha-?1|rc4|des|3des|triple-?des)\b/i, kind: 'broken' },
  { pattern: /\b(?:aes|chacha20|poly1305|sha-?(?:256|384|512)|sha3)\b/i, kind: 'symmetric' },
]

/**
 * Crypto provider DLLs worth recording when a Windows process has loaded one.
 * Passed to PowerShell through the environment, never string-interpolated.
 */
const WINDOWS_CRYPTO_MODULE_FILTER =
  '^(libssl|libcrypto|ssleay32|libeay32|bcrypt|bcryptprimitives|ncrypt|ncryptsslp|crypt32|cryptsp|cryptbase|schannel|sspicli|mssign32|wintrust|libgcrypt|nss3|softokn3|freebl3|gnutls|mbedtls|wolfssl|botan|libsodium|liboqs)'

/** Protocol versions, matched only where a version was actually observed. */
const WEAK_PROTOCOL = /\b(?:sslv?[23]|tls\s*1\.[01]|tlsv1(?:\.[01])?)\b/i

/** Any stated protocol version, used to read a version out of an event message. */
const STATED_PROTOCOL = /\b(?:ssl\s*v?[23]|dtls\s*v?1(?:\.[0-3])?|tls\s*v?1(?:\.[0-3])?)\b/i

/** Hex digests carry no meaning and must never be pattern-matched for crypto. */
const HEX_DIGEST = /\b[0-9a-f]{32,}\b/gi

function boolEnv(name: string, defaultValue = false) {
  const value = process.env[name]
  if (value == null || value === '') return defaultValue
  return /^(1|true|yes|on)$/i.test(value)
}

function numberEnv(name: string, fallback: number, min: number, max: number) {
  const value = Number(process.env[name] || fallback)
  if (!Number.isFinite(value)) return fallback
  return Math.max(min, Math.min(max, value))
}

function isoNow() {
  return new Date().toISOString()
}

function cleanString(value: unknown, max = 500) {
  if (typeof value !== 'string') return null
  const trimmed = value.replace(/\u0000/g, ' ').trim()
  return trimmed ? trimmed.slice(0, max) : null
}

function safeHash(value: unknown) {
  const text = String(value || '')
  if (!text) return null
  return createHash('sha256').update(text).digest('hex')
}

function toNumber(value: unknown) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function allowedPathFor(value: unknown, policy: NativeCollectorPolicy) {
  const filePath = cleanString(value, 1000)
  if (!filePath) return null
  const normalized = path.resolve(filePath).replace(/\\/g, '/').toLowerCase()
  for (const root of policy.allowedPaths || []) {
    const normalizedRoot = path.resolve(root).replace(/\\/g, '/').toLowerCase()
    if (normalized === normalizedRoot || normalized.startsWith(`${normalizedRoot}/`)) return filePath
  }
  return null
}

/** Strips hex digests so a random hash can never look like an algorithm name. */
function withoutDigests(text: string) {
  return String(text || '').replace(HEX_DIGEST, ' ')
}

/**
 * Extracts a protocol version from free text, or null when none is stated.
 * Returning null is the point: no version observed means no version claimed,
 * and therefore no downgrade verdict is possible.
 */
function statedProtocol(text: unknown) {
  const match = STATED_PROTOCOL.exec(withoutDigests(String(text || '')))
  return match ? match[0].replace(/\s+/g, ' ').trim().toUpperCase() : null
}

function cryptoMatches(text: string) {
  const clean = withoutDigests(text)
  return CRYPTO_LIBRARY_SIGNALS
    .filter((signal) => signal.pattern.test(clean))
    .map((signal) => signal.algorithm)
}

/**
 * Derives the crypto posture of ONE observation.
 *
 * The rule this enforces: a claim requires the evidence for that claim.
 *
 *  - `isLegacy` / `isPqc` need a STATED algorithm. The presence of a crypto
 *    library says a provider is loaded, not which algorithm ran.
 *  - `downgradeDetected` needs an OBSERVED protocol version. It was previously
 *    derived from the substring "ssl", so every process linked against OpenSSL
 *    was published as a critical TLS downgrade - a fabricated critical from no
 *    protocol evidence at all.
 *  - `shadowCrypto` means cryptography outside the declared inventory. A host
 *    agent cannot know what was declared, so it never asserts this; the control
 *    plane decides it during reconciliation.
 *  - `hndlRisk` needs quantum-vulnerable key establishment on data in transit,
 *    not merely a loaded library.
 *
 * Anything not established stays false, and a presence-only observation carries
 * `low` severity: it is inventory, not a vulnerability.
 */
function classifyObservation(input: {
  evidenceClass: EvidenceClass
  algorithm?: string | null
  protocol?: string | null
  host?: string | null
}): Pick<NativeRuntimeEvent, 'isPqc' | 'isLegacy' | 'downgradeDetected' | 'shadowCrypto' | 'hndlRisk' | 'severity' | 'riskScore'> {
  const algorithmText = withoutDigests(input.algorithm || '')
  const protocolText = withoutDigests(input.protocol || '')

  const kinds = new Set(
    ALGORITHM_SIGNALS.filter((signal) => signal.pattern.test(algorithmText)).map((signal) => signal.kind),
  )
  const isPqc = kinds.has('pqc')
  const broken = kinds.has('broken')
  // A PQC algorithm is not legacy even when a hybrid name also names a classical half.
  const isLegacy = !isPqc && (kinds.has('vulnerable') || broken)

  // Only a genuinely observed protocol version can assert a downgrade.
  const downgradeDetected = Boolean(protocolText) && WEAK_PROTOCOL.test(protocolText)

  // Harvest-now-decrypt-later needs quantum-vulnerable key establishment
  // protecting data in transit - never inferred from an inventory row.
  const hndlRisk =
    kinds.has('vulnerable') &&
    !isPqc &&
    (input.evidenceClass === 'certificate' || input.evidenceClass === 'crypto-api-call') &&
    Boolean(protocolText || input.evidenceClass === 'certificate')

  const severity: Severity = broken
    ? 'critical'
    : downgradeDetected
      ? 'high'
      : isLegacy
        ? 'high'
        : isPqc
          ? 'safe'
          : 'low'

  const riskScore = severity === 'critical' ? 92 : severity === 'high' ? 74 : severity === 'safe' ? 5 : 20

  return {
    isPqc,
    isLegacy,
    downgradeDetected,
    // Never asserted by the agent - see the note above.
    shadowCrypto: false,
    hndlRisk,
    severity,
    riskScore,
  }
}

function normalizeOperation(text: string) {
  if (/ssl_connect|ssl_accept|handshake|schannel|tls|cipher/i.test(text)) return 'tls_handshake'
  if (/encrypt|decrypt|evp_|cipher|aes|gcm|cbc/i.test(text)) return 'encryption'
  if (/sign|verify|jwt|saml|certificate|x509|pki/i.test(text)) return 'signing_or_certificate'
  if (/key|kms|hsm|keystore|truststore|bcrypt|ncrypt|cng/i.test(text)) return 'key_usage'
  if (/process|library|module|dll|so|dylib/i.test(text)) return 'process_crypto_inventory'
  return 'runtime_crypto_observation'
}

function eventFromSignal(input: {
  collector: string
  /** What kind of observation this is - decides what may be claimed from it. */
  evidenceClass: EvidenceClass
  eventType: string
  operationType?: string
  processName?: unknown
  processId?: unknown
  assetName?: unknown
  assetType?: string
  host?: unknown
  algorithm?: unknown
  /** A protocol version ONLY where one was genuinely observed. */
  protocol?: unknown
  certificateFingerprint?: unknown
  filePath?: unknown
  text: string
  observedAt?: unknown
  metadata?: Record<string, unknown>
}): NativeRuntimeEvent {
  const filePath = cleanString(input.filePath, 1000)
  const processName = cleanString(input.processName, 255)
  const algorithm = cleanString(input.algorithm, 120) || cryptoMatches(input.text)[0] || 'Runtime crypto signal'
  const protocol = cleanString(input.protocol, 80)
  const host = cleanString(input.host, 255) || HOSTNAME
  // Classified from the STATED algorithm and protocol, never from the raw text.
  const flags = classifyObservation({
    evidenceClass: input.evidenceClass,
    algorithm,
    protocol,
    host,
  })
  return {
    eventType: input.eventType,
    operationType: input.operationType || normalizeOperation(input.text),
    assetName: cleanString(input.assetName, 255) || processName || host,
    assetType: input.assetType || 'host_process',
    host,
    protocol,
    tlsVersion: protocol,
    algorithm,
    certificateFingerprint: cleanString(input.certificateFingerprint, 255),
    processName,
    processId: toNumber(input.processId),
    ...flags,
    metadata: {
      collector: input.collector,
      evidenceClass: input.evidenceClass,
      nativeRuntime: true,
      filePath,
      textHash: safeHash(input.text),
      ...input.metadata,
    },
    observedAt: cleanString(input.observedAt, 80) || isoNow(),
  }
}

function parseJsonRecords(output: string): Record<string, unknown>[] {
  const trimmed = output.trim()
  if (!trimmed) return []
  try {
    const parsed = JSON.parse(trimmed)
    return Array.isArray(parsed) ? parsed.filter((item) => item && typeof item === 'object') : [parsed].filter((item) => item && typeof item === 'object')
  } catch {
    return trimmed
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.startsWith('{') && line.endsWith('}'))
      .map((line) => {
        try {
          return JSON.parse(line)
        } catch {
          return null
        }
      })
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
  }
}

function runCommand(
  command: string,
  args: string[],
  timeoutMs: number,
  shell = false,
  extraEnv?: Record<string, string>,
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      shell,
      windowsHide: true,
      env: extraEnv ? { ...process.env, ...extraEnv } : process.env,
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    let finished = false
    const timer = setTimeout(() => {
      if (finished) return
      finished = true
      child.kill()
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), code: null, timedOut: true })
    }, timeoutMs)

    child.stdout?.on('data', (chunk) => stdout.push(Buffer.from(chunk)))
    child.stderr?.on('data', (chunk) => stderr.push(Buffer.from(chunk)))
    child.on('error', (error) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: String(error.message), code: null, timedOut: false })
    })
    child.on('close', (code) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), code, timedOut: false })
    })
  })
}

async function commandAvailable(command: string, args: string[] = ['--version']) {
  const result = await runCommand(command, args, 2_500)
  return result.code === 0 || Boolean(result.stdout.trim())
}

class ExternalNativeRuntimeCollector implements NativeRuntimeCollector {
  id = 'external-native-runtime'

  async supported() {
    return Boolean(process.env.QGUARD_NATIVE_RUNTIME_COMMAND)
  }

  async collect(captureMs: number) {
    const command = process.env.QGUARD_NATIVE_RUNTIME_COMMAND
    if (!command) return []
    const result = await runCommand(command, [], captureMs, true)
    return parseJsonRecords(result.stdout)
      .slice(0, MAX_NATIVE_EVENTS)
      .map((row) => eventFromSignal({
        collector: this.id,
        evidenceClass: 'external',
        eventType: cleanString(row.eventType || row.event_type, 120) || 'native-runtime-event',
        operationType: cleanString(row.operationType || row.operation_type, 120) || undefined,
        processName: row.processName || row.process_name || row.comm,
        processId: row.processId || row.process_id || row.pid,
        assetName: row.assetName || row.asset_name || row.host || HOSTNAME,
        assetType: cleanString(row.assetType || row.asset_type, 120) || 'host_process',
        host: row.host || HOSTNAME,
        algorithm: row.algorithm || row.cipherSuite || row.cipher_suite || row.probe,
        protocol: row.protocol || row.tlsVersion || row.tls_version,
        certificateFingerprint: row.certificateFingerprint || row.certificate_fingerprint,
        filePath: row.filePath || row.file_path || row.executablePath || row.executable_path,
        text: JSON.stringify(row),
        observedAt: row.observedAt || row.observed_at || row.timeCreated || row.timestamp,
        metadata: {
          sourceCommand: 'QGUARD_NATIVE_RUNTIME_COMMAND',
          filePath: cleanString(row.filePath || row.file_path || row.executablePath || row.executable_path, 1000),
          provider: cleanString(row.provider || row.providerName, 255),
          probe: cleanString(row.probe, 255),
        },
      }))
  }
}

class ProcessInventoryCollector implements NativeRuntimeCollector {
  id = `${PLATFORM}-process-crypto-inventory`

  constructor(private policy: NativeCollectorPolicy) {}

  async supported() {
    return PLATFORM === 'linux' || PLATFORM === 'darwin' || PLATFORM === 'win32'
  }

  async collect(_captureMs = 0) {
    if (PLATFORM === 'win32') return this.collectWindows()
    return this.collectProcfs()
  }

  private async collectProcfs() {
    if (PLATFORM !== 'linux') return []
    const entries = await fs.readdir('/proc').catch(() => [])
    const events: NativeRuntimeEvent[] = []
    for (const entry of entries) {
      if (events.length >= MAX_PROCESS_ROWS) break
      if (!/^\d+$/.test(entry)) continue
      const pid = Number(entry)
      const base = `/proc/${entry}`
      const comm = cleanString(await fs.readFile(`${base}/comm`, 'utf8').catch(() => ''), 255)
      const cmdline = cleanString((await fs.readFile(`${base}/cmdline`).catch(() => Buffer.alloc(0))).toString('utf8').replace(/\u0000/g, ' '), 1000)
      const exePath = await fs.readlink(`${base}/exe`).catch(() => null)
      const policyPath = allowedPathFor(exePath, this.policy)
      const maps = cleanString(await fs.readFile(`${base}/maps`, 'utf8').catch(() => ''), 20_000)
      const text = `${comm || ''} ${cmdline || ''} ${exePath || ''} ${maps || ''}`
      const signals = cryptoMatches(text)
      if (signals.length === 0) continue
      events.push(eventFromSignal({
        collector: this.id,
        // A loaded library is INVENTORY: it proves a provider is present, not
        // that a weak algorithm ran. No algorithm or protocol is claimed.
        evidenceClass: 'library-presence',
        eventType: 'process-crypto-usage',
        processName: comm || path.basename(String(exePath || 'process')),
        processId: pid,
        assetName: comm || HOSTNAME,
        host: HOSTNAME,
        filePath: policyPath || exePath || undefined,
        text,
        metadata: {
          filePath: policyPath || cleanString(exePath, 1000),
          executablePathObserved: Boolean(exePath),
          policyPathMatched: Boolean(policyPath),
          signals: Array.from(new Set(signals)).slice(0, 8),
          commandLineRedacted: Boolean(cmdline),
          loadedModuleMapObserved: Boolean(maps),
        },
      }))
    }
    return events
  }

  /**
   * Windows counterpart to reading /proc/<pid>/maps: enumerate the modules each
   * process has actually LOADED.
   *
   * The executable path alone cannot show that a process uses cryptography -
   * `node.exe` reveals nothing about libssl. Matching crypto names against the
   * path and command line instead produced findings out of coincidence
   * ("OpenSSL" in a folder name) while missing every process that genuinely
   * loads a crypto provider. Loaded modules are the real evidence.
   */
  private async collectWindows() {
    const command = [
      '$out = @();',
      'foreach ($p in Get-Process -ErrorAction SilentlyContinue) {',
      '  try {',
      '    $mods = @($p.Modules | Where-Object { $_.ModuleName -match $env:QGUARD_MODULE_FILTER } | Select-Object -First 12 -ExpandProperty ModuleName);',
      '  } catch { $mods = @() }',
      '  if ($mods.Count -gt 0) {',
      '    $out += [pscustomobject]@{ ProcessId = $p.Id; Name = $p.ProcessName; ExecutablePath = $p.Path; Modules = $mods }',
      '  }',
      '}',
      '$out | Select-Object -First 350 | ConvertTo-Json -Compress -Depth 4',
    ].join(' ')

    const result = await runCommand(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command],
      20_000,
      false,
      // The provider filter lives in the environment so no operator-controlled
      // value is ever interpolated into the command string.
      { QGUARD_MODULE_FILTER: WINDOWS_CRYPTO_MODULE_FILTER },
    )

    const rows = parseJsonRecords(result.stdout)
    const events: NativeRuntimeEvent[] = []
    for (const row of rows.slice(0, MAX_PROCESS_ROWS)) {
      const executablePath = cleanString(row.ExecutablePath || row.executablePath, 1000)
      const processName = cleanString(row.Name || row.name, 255)
      const modules = Array.isArray(row.Modules)
        ? row.Modules.map((item: unknown) => cleanString(item, 255)).filter(Boolean) as string[]
        : ([cleanString(row.Modules, 255)].filter(Boolean) as string[])
      if (modules.length === 0) continue

      // Classification reads the MODULE names - the observed artifact - not the
      // process path, so a folder called "OpenSSL" proves nothing on its own.
      const moduleText = modules.join(' ')
      const signals = cryptoMatches(moduleText)
      if (signals.length === 0) continue

      const policyPath = allowedPathFor(executablePath, this.policy)
      events.push(eventFromSignal({
        collector: this.id,
        evidenceClass: 'library-presence',
        eventType: 'process-crypto-usage',
        processName,
        processId: row.ProcessId || row.processId,
        assetName: processName || HOSTNAME,
        host: HOSTNAME,
        filePath: policyPath || executablePath || undefined,
        algorithm: signals[0],
        text: moduleText,
        metadata: {
          filePath: policyPath || executablePath,
          policyPathMatched: Boolean(policyPath),
          signals: Array.from(new Set(signals)).slice(0, 8),
          loadedCryptoModules: modules.slice(0, 12),
          loadedModuleMapObserved: true,
        },
      }))
    }
    return events
  }
}

class LinuxEbpfCollector implements NativeRuntimeCollector {
  id = 'linux-ebpf-crypto-api'

  async supported() {
    if (PLATFORM !== 'linux') return false
    if (process.env.QGUARD_EBPF_COMMAND) return true
    return commandAvailable('bpftrace')
  }

  async collect(captureMs: number) {
    if (process.env.QGUARD_EBPF_COMMAND) {
      const result = await runCommand(process.env.QGUARD_EBPF_COMMAND, [], captureMs, true)
      return this.eventsFromRows(parseJsonRecords(result.stdout), 'QGUARD_EBPF_COMMAND')
    }

    const script = [
      'uprobe:/usr/lib*/**/libssl.so*:SSL_connect,',
      'uprobe:/usr/lib*/**/libssl.so*:SSL_accept,',
      'uprobe:/usr/lib*/**/libssl.so*:SSL_read,',
      'uprobe:/usr/lib*/**/libssl.so*:SSL_write,',
      'uprobe:/usr/lib*/**/libcrypto.so*:EVP_EncryptInit_ex,',
      'uprobe:/usr/lib*/**/libcrypto.so*:EVP_DecryptInit_ex,',
      'uprobe:/usr/lib*/**/libcrypto.so*:EVP_DigestInit_ex',
      '{ printf("{\\"probe\\":\\"%s\\",\\"pid\\":%d,\\"processName\\":\\"%s\\",\\"timestampNs\\":%llu}\\n", probe, pid, comm, nsecs); }',
    ].join(' ')
    const result = await runCommand('bpftrace', ['-q', '-e', script], captureMs)
    return this.eventsFromRows(parseJsonRecords(result.stdout), 'bpftrace')
  }

  private eventsFromRows(rows: Record<string, unknown>[], source: string) {
    return rows.slice(0, MAX_NATIVE_EVENTS).map((row) => {
      const probe = cleanString(row.probe, 255) || 'ebpf-crypto-probe'
      return eventFromSignal({
        collector: this.id,
        evidenceClass: 'crypto-api-call',
        eventType: 'ebpf-crypto-call',
        processName: row.processName || row.process_name || row.comm,
        processId: row.pid || row.processId || row.process_id,
        assetName: row.processName || row.comm || HOSTNAME,
        host: HOSTNAME,
        algorithm: probe,
        text: `${probe} ${JSON.stringify(row)}`,
        observedAt: row.observedAt || row.observed_at,
        metadata: {
          probe,
          source,
          captureMode: 'linux-ebpf',
          kernelTimestampNs: toNumber(row.timestampNs || row.timestamp_ns),
        },
      })
    })
  }
}

class WindowsEtwCollector implements NativeRuntimeCollector {
  id = 'windows-etw-crypto-events'

  async supported() {
    if (PLATFORM !== 'win32') return false
    return true
  }

  async collect(captureMs: number) {
    if (process.env.QGUARD_ETW_COMMAND) {
      const result = await runCommand(process.env.QGUARD_ETW_COMMAND, [], captureMs, true)
      return this.eventsFromRows(parseJsonRecords(result.stdout), 'QGUARD_ETW_COMMAND')
    }

    const seconds = Math.max(5, Math.ceil(captureMs / 1000))
    const command = [
      `$since = (Get-Date).AddSeconds(-${seconds});`,
      "$logs = @('Microsoft-Windows-CAPI2/Operational','System','Application');",
      '$rows = foreach ($log in $logs) {',
      "  Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction SilentlyContinue |",
      "  Where-Object { $_.ProviderName -match 'CAPI2|Schannel|CNG|Crypto|Certificate|Kernel-Process' -or $_.Message -match 'certificate|crypto|cipher|TLS|key|Schannel|CNG|CAPI' } |",
      '  Select-Object -First 200 @{n="LogName";e={$log}},ProviderName,Id,LevelDisplayName,TimeCreated,ProcessId,@{n="MessageHash";e={ [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$_.Message))).Replace("-","").ToLower() }},@{n="MessagePreview";e={ if ($_.Message) { $_.Message.Substring(0, [Math]::Min(180, $_.Message.Length)) } else { "" } }}',
      '}',
      '$rows | Select-Object -First 300 | ConvertTo-Json -Compress -Depth 4',
    ].join(' ')

    const result = await runCommand('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], Math.max(8_000, captureMs))
    return this.eventsFromRows(parseJsonRecords(result.stdout), 'Get-WinEvent')
  }

  private eventsFromRows(rows: Record<string, unknown>[], source: string) {
    return rows.slice(0, MAX_NATIVE_EVENTS).map((row) => {
      const provider = cleanString(row.ProviderName || row.providerName || row.provider, 255) || 'Windows ETW'
      const preview = cleanString(row.MessagePreview || row.messagePreview || row.message, 500) || ''
      const eventText = `${provider} ${row.Id || ''} ${preview}`
      return eventFromSignal({
        collector: this.id,
        evidenceClass: 'crypto-api-call',
        eventType: 'etw-crypto-event',
        processId: row.ProcessId || row.processId,
        assetName: HOSTNAME,
        assetType: 'windows_host',
        host: HOSTNAME,
        algorithm: provider,
        // Only a version the event actually states; otherwise null.
        protocol: statedProtocol(preview),
        text: eventText,
        observedAt: row.TimeCreated || row.timeCreated || row.observedAt,
        metadata: {
          source,
          provider,
          eventId: row.Id || row.id,
          level: cleanString(row.LevelDisplayName || row.level, 80),
          logName: cleanString(row.LogName || row.logName, 255),
          messageHash: cleanString(row.MessageHash || row.messageHash, 128) || safeHash(preview),
          messagePreviewRedacted: Boolean(preview),
          captureMode: 'windows-etw',
        },
      })
    })
  }
}

class CertificateStoreCollector implements NativeRuntimeCollector {
  id = `${PLATFORM}-certificate-store`

  constructor(private policy: NativeCollectorPolicy) {}

  async supported() {
    return PLATFORM === 'linux' || PLATFORM === 'darwin' || PLATFORM === 'win32'
  }

  async collect(_captureMs = 0) {
    if (PLATFORM === 'win32') return this.collectWindowsCertificates()
    return this.collectLocalCertificates()
  }

  private async collectWindowsCertificates() {
    const command = [
      "$stores = @('Cert:\\LocalMachine\\My','Cert:\\CurrentUser\\My','Cert:\\LocalMachine\\Root','Cert:\\CurrentUser\\Root');",
      '$rows = foreach ($store in $stores) {',
      '  Get-ChildItem $store -ErrorAction SilentlyContinue | Select-Object -First 120 @{n="Store";e={$store}},Subject,Issuer,Thumbprint,NotAfter,HasPrivateKey,@{n="PublicKeyAlgorithm";e={$_.PublicKey.Oid.FriendlyName}},@{n="SignatureAlgorithm";e={$_.SignatureAlgorithm.FriendlyName}}',
      '}',
      '$rows | Select-Object -First 240 | ConvertTo-Json -Compress -Depth 4',
    ].join(' ')
    const result = await runCommand('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], 12_000)
    return parseJsonRecords(result.stdout).slice(0, MAX_CERTIFICATE_ROWS).map((row) => {
      const text = `${row.Subject || ''} ${row.Issuer || ''} ${row.PublicKeyAlgorithm || ''} ${row.SignatureAlgorithm || ''}`
      return eventFromSignal({
        collector: this.id,
        evidenceClass: 'certificate',
        eventType: 'certificate-store-discovery',
        operationType: 'certificate_discovery',
        assetName: row.Subject || HOSTNAME,
        assetType: 'certificate',
        host: HOSTNAME,
        algorithm: row.PublicKeyAlgorithm || row.SignatureAlgorithm || 'Certificate',
        certificateFingerprint: row.Thumbprint,
        text,
        observedAt: isoNow(),
        metadata: {
          store: cleanString(row.Store, 255),
          issuerHash: safeHash(row.Issuer),
          subjectHash: safeHash(row.Subject),
          notAfter: cleanString(row.NotAfter, 80),
          hasPrivateKey: Boolean(row.HasPrivateKey),
          keyUsageVerified: Boolean(row.HasPrivateKey),
        },
      })
    })
  }

  private async collectLocalCertificates() {
    const roots = [
      ...this.policy.allowedPaths,
      ...(boolEnv('QGUARD_SCAN_SYSTEM_CERTS')
        ? ['/etc/ssl/certs', '/etc/pki/tls/certs', '/etc/letsencrypt/live', '/usr/local/share/ca-certificates']
        : []),
    ]
    const files: string[] = []
    for (const root of roots) {
      await this.collectCertificateFiles(root, files)
      if (files.length >= MAX_CERTIFICATE_ROWS) break
    }

    const events: NativeRuntimeEvent[] = []
    for (const filePath of files.slice(0, MAX_CERTIFICATE_ROWS)) {
      const content = await fs.readFile(filePath, 'utf8').catch(() => '')
      const blocks = content.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []
      for (const block of blocks.slice(0, 2)) {
        try {
          const cert = new X509Certificate(block)
          const publicKey = cert.publicKey
          const details = publicKey.asymmetricKeyDetails as Record<string, unknown> | undefined
          const algorithm = cleanString(publicKey.asymmetricKeyType, 80) || 'certificate'
          const keySize = toNumber(details?.modulusLength || details?.namedCurve)
          events.push(eventFromSignal({
            collector: this.id,
            evidenceClass: 'certificate',
            eventType: 'certificate-store-discovery',
            operationType: 'certificate_discovery',
            assetName: cert.subject || path.basename(filePath),
            assetType: 'certificate',
            host: HOSTNAME,
            algorithm,
            certificateFingerprint: cert.fingerprint256,
            filePath,
            text: `${cert.subject} ${cert.issuer} ${algorithm} ${cert.validTo}`,
            metadata: {
              filePath,
              issuerHash: safeHash(cert.issuer),
              subjectHash: safeHash(cert.subject),
              validFrom: cert.validFrom,
              validTo: cert.validTo,
              keySize,
              keyUsageVerified: false,
            },
          }))
        } catch {
          // Ignore malformed or non-X509 PEM blocks.
        }
      }
    }
    return events
  }

  private async collectCertificateFiles(root: string, files: string[], depth = 0): Promise<void> {
    if (!root || files.length >= MAX_CERTIFICATE_ROWS || depth > 3) return
    const stat = await fs.stat(root).catch(() => null)
    if (!stat) return
    if (stat.isFile()) {
      if (/\.(pem|crt|cer)$/i.test(root)) files.push(root)
      return
    }
    if (!stat.isDirectory()) return
    const entries = await fs.readdir(root, { withFileTypes: true }).catch(() => [])
    for (const entry of entries) {
      if (files.length >= MAX_CERTIFICATE_ROWS) return
      const fullPath = path.join(root, entry.name)
      if (entry.isDirectory()) await this.collectCertificateFiles(fullPath, files, depth + 1)
      if (entry.isFile() && /\.(pem|crt|cer)$/i.test(entry.name)) files.push(fullPath)
    }
  }
}

export function nativeRuntimeCollectorsEnabled(scanTypes: Set<string>) {
  if (process.env.QGUARD_NATIVE_RUNTIME_ENABLED != null) return boolEnv('QGUARD_NATIVE_RUNTIME_ENABLED')
  return scanTypes.has('runtime') || scanTypes.has('native') || scanTypes.has('ebpf') || scanTypes.has('etw')
}

export async function collectNativeRuntimeEvents(policy: NativeCollectorPolicy): Promise<NativeCollectorRun> {
  const scanTypes = new Set(policy.scanTypes.map((item) => item.toLowerCase()))
  if (!nativeRuntimeCollectorsEnabled(scanTypes)) return { events: [], diagnostics: [] }

  const captureSeconds = numberEnv('QGUARD_NATIVE_CAPTURE_SECONDS', DEFAULT_CAPTURE_SECONDS, 3, 60)
  const captureMs = captureSeconds * 1000
  const collectors: NativeRuntimeCollector[] = [
    new ExternalNativeRuntimeCollector(),
    new ProcessInventoryCollector(policy),
    new CertificateStoreCollector(policy),
    PLATFORM === 'linux' ? new LinuxEbpfCollector() : null,
    PLATFORM === 'win32' ? new WindowsEtwCollector() : null,
  ].filter(Boolean) as NativeRuntimeCollector[]

  const events: NativeRuntimeEvent[] = []
  const diagnostics: NativeCollectorDiagnostic[] = []

  for (const collector of collectors) {
    try {
      const supported = await collector.supported()
      if (!supported) {
        diagnostics.push({ collectorId: collector.id, supported: false, events: 0, status: 'unsupported' })
        continue
      }
      const collected = await collector.collect(captureMs)
      const remaining = Math.max(0, MAX_NATIVE_EVENTS - events.length)
      events.push(...collected.slice(0, remaining))
      diagnostics.push({ collectorId: collector.id, supported: true, events: collected.length, status: 'collected' })
    } catch (error) {
      diagnostics.push({
        collectorId: collector.id,
        supported: true,
        events: 0,
        status: 'error',
        message: error instanceof Error ? error.message : 'native collector failed',
      })
    }
  }

  return { events: events.slice(0, MAX_NATIVE_EVENTS), diagnostics }
}
