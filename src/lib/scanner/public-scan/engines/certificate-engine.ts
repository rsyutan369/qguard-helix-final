/**
 * QGuard Helix — Certificate Intelligence Engine
 *
 * X.509 chain analysis: issuer, leaf and intermediates, SAN/CN, public key,
 * signature algorithm, key size, validity, OCSP stapling and responder, CRL
 * distribution points, embedded SCTs (Certificate Transparency), must-staple,
 * and real chain-trust verification.
 *
 * Chain trust is taken from Node's own verification result
 * (`socket.authorized` / `socket.authorizationError`), never inferred from the
 * issuer's name. The socket connects permissively so that expired, self-signed
 * and untrusted chains can still be *read* — which is the whole point of an
 * assessment — while the verdict itself remains truthful.
 */

import tls from 'node:tls'
import net from 'node:net'
import crypto from 'node:crypto'
import { safeLookup } from '../safe-dns'
import type { CertificateInfo } from '../../web-scanner/types'
import { parseCertificateFromPeer } from '../../web-scanner/certificate-parser'
import {
  type Evidence,
  type EngineResult,
  type ObservationSink,
  clampScore,
  observationEmitter,
  retryTransient,
  runEngine,
} from './contract'

const PROBE_TIMEOUT = 8_000

/** DER-encoded OIDs read directly from the raw certificate. */
const SCT_OID_DER = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02])
const MUST_STAPLE_OID_DER = Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18])

export interface ChainEntry {
  subject: string
  issuer: string
  publicKeyAlgorithm: string
  publicKeySize: number
  signatureAlgorithm: string
  validTo: string
  isExpired: boolean
  isRoot: boolean
}

export interface CertificateIntelligence {
  certificate: CertificateInfo | null

  commonName: string | null
  subjectAltNames: string[]
  sanCount: number
  isWildcard: boolean
  wildcardNames: string[]

  issuerOrganization: string | null
  issuerCommonName: string | null
  chain: ChainEntry[]
  chainDepth: number

  chainTrusted: boolean | null
  trustError: string | null
  isSelfSigned: boolean
  isExpired: boolean
  hostnameMatches: boolean | null

  publicKeyAlgorithm: string | null
  publicKeySize: number
  signatureAlgorithm: string | null

  validFrom: string | null
  validTo: string | null
  validityDays: number
  daysRemaining: number

  ocspStapled: boolean
  ocspUri: string | null
  /**
   * Whether the advertised responder actually answered. `not-advertised` and
   * `unreachable` are different failures and must not be flattened: one is a
   * certificate that never promised revocation, the other is one that promised
   * it and cannot deliver.
   */
  ocspResponderState: OcspResponderState
  ocspResponderDetail: string | null
  mustStaple: boolean
  crlDistributionPoints: string[]

  signedCertificateTimestamps: boolean
  sctCount: number

  serialNumber: string | null
  fingerprint256: string | null
  error: string | null
}

export function emptyCertificate(error: string | null = null): CertificateIntelligence {
  return {
    certificate: null,
    commonName: null,
    subjectAltNames: [],
    sanCount: 0,
    isWildcard: false,
    wildcardNames: [],
    issuerOrganization: null,
    issuerCommonName: null,
    chain: [],
    chainDepth: 0,
    chainTrusted: null,
    trustError: null,
    isSelfSigned: false,
    isExpired: false,
    hostnameMatches: null,
    publicKeyAlgorithm: null,
    publicKeySize: 0,
    signatureAlgorithm: null,
    validFrom: null,
    validTo: null,
    validityDays: 0,
    daysRemaining: 0,
    ocspStapled: false,
    ocspUri: null,
    ocspResponderState: 'not-probed',
    ocspResponderDetail: null,
    mustStaple: false,
    crlDistributionPoints: [],
    signedCertificateTimestamps: false,
    sctCount: 0,
    serialNumber: null,
    fingerprint256: null,
    error,
  }
}

// ─── DER helpers ──────────────────────────────────────────────────────────────

function readDerLength(buf: Buffer, lengthStart: number): { length: number; valueStart: number } | null {
  if (lengthStart >= buf.length) return null
  const first = buf[lengthStart]
  if (first < 0x80) return { length: first, valueStart: lengthStart + 1 }
  const byteCount = first & 0x7f
  if (byteCount === 0 || byteCount > 4 || lengthStart + byteCount >= buf.length) return null
  let length = 0
  for (let i = 1; i <= byteCount; i += 1) length = (length << 8) | buf[lengthStart + i]
  return { length, valueStart: lengthStart + 1 + byteCount }
}

/**
 * Count SCT entries embedded in the leaf. The extension wraps a 2-byte total
 * length followed by length-prefixed SCTs; counting the prefixes answers
 * "is this certificate in public CT logs, and how many".
 */
export function countSctEntries(raw: Buffer): number {
  const oidIndex = raw.indexOf(SCT_OID_DER)
  if (oidIndex < 0) return 0

  let cursor = oidIndex + SCT_OID_DER.length
  const limit = Math.min(raw.length, cursor + 16)
  while (cursor < limit && raw[cursor] !== 0x04) cursor += 1
  if (cursor >= limit) return 1 // extension present but unparsable

  const outer = readDerLength(raw, cursor + 1)
  if (!outer) return 1
  let listCursor = outer.valueStart
  if (raw[listCursor] === 0x04) {
    const inner = readDerLength(raw, listCursor + 1)
    if (inner) listCursor = inner.valueStart
  }
  if (listCursor + 2 > raw.length) return 1

  const totalLength = raw.readUInt16BE(listCursor)
  const listEnd = Math.min(raw.length, listCursor + 2 + totalLength)
  let entryCursor = listCursor + 2
  let count = 0
  while (entryCursor + 2 <= listEnd && count < 16) {
    const entryLength = raw.readUInt16BE(entryCursor)
    if (entryLength <= 0) break
    entryCursor += 2 + entryLength
    count += 1
  }
  return count || 1
}

/** A DN attribute may be multi-valued; collapse to a single display string. */
function dnField(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value[0] ?? null
  return value ?? null
}

function parseSubjectAltNames(raw: string | undefined): string[] {
  if (!raw) return []
  return raw
    .split(',')
    .map((entry) => entry.trim().replace(/^(DNS|IP Address|URI|email):/i, '').trim())
    .filter(Boolean)
}

/** RFC 6125 hostname matching, including single-label wildcards. */
export function hostnameMatchesCertificate(host: string, names: string[]): boolean {
  const target = host.toLowerCase()
  return names.some((entry) => {
    const name = entry.toLowerCase()
    if (name === target) return true
    if (!name.startsWith('*.')) return false
    const suffix = name.slice(1) // ".example.com"
    if (!target.endsWith(suffix)) return false
    // A wildcard matches exactly one label.
    const remainder = target.slice(0, target.length - suffix.length)
    return remainder.length > 0 && !remainder.includes('.')
  })
}

function buildChain(peer: tls.DetailedPeerCertificate | undefined): ChainEntry[] {
  const chain: ChainEntry[] = []
  let current = peer
  const seen = new Set<string>()

  while (current && Object.keys(current).length > 0) {
    const fingerprint = current.fingerprint256 || current.fingerprint || String(chain.length)
    if (seen.has(fingerprint)) break
    seen.add(fingerprint)

    const subject = dnField(current.subject?.CN) ?? dnField(current.subject?.O) ?? 'unknown'
    const issuer = dnField(current.issuer?.CN) ?? dnField(current.issuer?.O) ?? 'unknown'
    let algorithm = 'unknown'
    let size = 0
    try {
      if (current.raw) {
        const x509 = new crypto.X509Certificate(current.raw)
        algorithm = x509.publicKey.asymmetricKeyType ?? 'unknown'
        const details = x509.publicKey.asymmetricKeyDetails as
          | { modulusLength?: number; namedCurve?: string }
          | undefined
        size = details?.modulusLength ?? (details?.namedCurve?.match(/(\d{3})/)?.[1] ? Number(details.namedCurve.match(/(\d{3})/)![1]) : 0)
      }
    } catch {
      /* chain entry metadata is best-effort */
    }

    chain.push({
      subject,
      issuer,
      publicKeyAlgorithm: algorithm,
      publicKeySize: size,
      signatureAlgorithm: 'unknown',
      validTo: current.valid_to ?? '',
      isExpired: current.valid_to ? new Date(current.valid_to) < new Date() : false,
      isRoot: subject === issuer,
    })

    const next = current.issuerCertificate
    if (!next || next === current) break
    current = next
  }

  return chain
}

// ─── Probe ────────────────────────────────────────────────────────────────────

interface CertProbe {
  peer: (tls.DetailedPeerCertificate & { raw?: Buffer; subjectaltname?: string; infoAccess?: Record<string, string[]> }) | null
  authorized: boolean | null
  authorizationError: string | null
  ocspStapled: boolean
  error: string | null
}

function probeCertificate(host: string, port: number): Promise<CertProbe> {
  return new Promise((resolve) => {
    let settled = false
    let ocspStapled = false

    const finish = (value: CertProbe) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        /* already torn down */
      }
      resolve(value)
    }

    // `requestOCSP` is a real Node option missing from @types/node.
    const options = {
      host,
      port,
      servername: net.isIP(host) ? undefined : host,
      lookup: safeLookup,
      // nosemgrep: bypass-tls-verification -- assessment probe, not a client.
      // An assessment must be able to READ expired, self-signed and untrusted
      // chains; refusing them would report "Not observable" for properties that
      // are plainly observable. Node still verifies and reports the verdict on
      // socket.authorized, which is what this engine publishes as chain trust.
      rejectUnauthorized: false,
      requestOCSP: true,
      timeout: PROBE_TIMEOUT,
    } as tls.ConnectionOptions

    const socket = tls.connect(options, () =>
      finish({
        peer: socket.getPeerCertificate(true) as CertProbe['peer'],
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        ocspStapled,
        error: null,
      }),
    )

    socket.on('OCSPResponse', (response: Buffer) => {
      ocspStapled = Buffer.isBuffer(response) && response.length > 0
    })
    socket.on('error', (err) =>
      finish({ peer: null, authorized: null, authorizationError: null, ocspStapled: false, error: (err as Error).message }),
    )
    socket.on('timeout', () =>
      finish({ peer: null, authorized: null, authorizationError: null, ocspStapled: false, error: 'Certificate probe timed out' }),
    )

    const timer = setTimeout(
      () =>
        finish({ peer: null, authorized: null, authorizationError: null, ocspStapled: false, error: 'Certificate probe timed out' }),
      PROBE_TIMEOUT,
    )
  })
}

// ─── OCSP responder liveness ──────────────────────────────────────────────────

const OCSP_PROBE_TIMEOUT_MS = 6_000

export type OcspResponderState = 'reachable' | 'unreachable' | 'not-advertised' | 'not-probed'

/**
 * Is the advertised OCSP responder actually answering?
 *
 * The certificate telling us where the responder lives is not the same claim as
 * the responder being alive. A published-but-dead responder is a real and
 * common failure: clients that soft-fail revocation silently lose revocation
 * checking entirely, and until now this scanner reported that endpoint
 * identically to one with a healthy responder.
 *
 * This is a liveness probe, NOT a revocation check. A real revocation query
 * needs a DER-encoded OCSPRequest for this specific serial, which is outside
 * what an anonymous edge assessment should be issuing. So the claim made is
 * exactly the claim measured: the responder answered, or it did not.
 */
async function probeOcspResponder(
  uri: string | null,
): Promise<{ state: OcspResponderState; detail: string; statusCode: number | null }> {
  if (!uri) return { state: 'not-advertised', detail: 'No OCSP responder in the certificate', statusCode: null }

  let parsed: URL
  try {
    parsed = new URL(uri)
  } catch {
    return { state: 'not-probed', detail: 'Responder URI could not be parsed', statusCode: null }
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { state: 'not-probed', detail: `Unsupported responder scheme ${parsed.protocol}`, statusCode: null }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), OCSP_PROBE_TIMEOUT_MS)
  try {
    const response = await fetch(parsed.toString(), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: { accept: 'application/ocsp-response' },
    })
    // Any HTTP answer proves the responder is serving. RFC 6960 responders
    // routinely return 400 for a GET with no encoded request — that is the
    // responder replying, which is exactly what is being measured.
    return {
      state: 'reachable',
      detail: `Responder answered HTTP ${response.status}`,
      statusCode: response.status,
    }
  } catch (err) {
    const reason = (err as Error).name === 'AbortError' ? 'timed out' : (err as Error).message
    return { state: 'unreachable', detail: `Responder did not answer (${reason})`, statusCode: null }
  } finally {
    clearTimeout(timer)
  }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

export async function runCertificateEngine(
  host: string,
  port: number,
  onObservation?: ObservationSink,
): Promise<EngineResult<CertificateIntelligence>> {
  return runEngine('certificate-intelligence', emptyCertificate(), async () => {
    const evidence: Evidence[] = []
    const notes: string[] = []
    const emit = observationEmitter(onObservation)

    // Hosts under load reset the first connection often enough that a single
    // attempt loses the chain entirely, which would down-rank issuer, OCSP, CT
    // and lifetime to Unknown for reasons unrelated to the target's posture.
    const probe = await retryTransient(
      () => probeCertificate(host, port),
      (value) => value.peer !== null,
      350,
    )

    if (!probe.peer || Object.keys(probe.peer).length === 0) {
      const data = emptyCertificate(probe.error ?? 'No certificate presented')
      notes.push('Certificate chain unavailable; certificate controls report Unknown.')
      emit({
        surface: 'certificate',
        label: 'Certificate chain',
        detail: probe.error ?? 'No certificate presented',
        status: 'critical',
        severity: 'high',
      })
      return { data, ok: false, confidence: 0, evidence, notes, error: data.error }
    }

    const peer = probe.peer
    const raw = peer.raw
    const sans = parseSubjectAltNames(peer.subjectaltname)
    const chain = buildChain(peer)
    const now = Date.now()
    const validTo = peer.valid_to ? new Date(peer.valid_to) : null
    const validFrom = peer.valid_from ? new Date(peer.valid_from) : null

    let parsed: CertificateInfo | null = null
    try {
      parsed = parseCertificateFromPeer(peer)
    } catch {
      notes.push('Certificate parsed partially; some X.509 fields were unreadable.')
    }

    const infoAccess = peer.infoAccess ?? {}
    const crlPoints = Array.isArray((peer as { crlDistributionPoints?: string[] }).crlDistributionPoints)
      ? ((peer as { crlDistributionPoints?: string[] }).crlDistributionPoints as string[])
      : []
    const sctCount = raw ? countSctEntries(raw) : 0

    const data: CertificateIntelligence = {
      certificate: parsed,
      commonName: dnField(peer.subject?.CN),
      subjectAltNames: sans,
      sanCount: sans.length,
      isWildcard: sans.some((name) => name.startsWith('*.')),
      wildcardNames: sans.filter((name) => name.startsWith('*.')),
      issuerOrganization: dnField(peer.issuer?.O),
      issuerCommonName: dnField(peer.issuer?.CN),
      chain,
      chainDepth: chain.length,
      chainTrusted: probe.authorized,
      trustError: probe.authorizationError,
      isSelfSigned: parsed?.isSelfSigned ?? JSON.stringify(peer.subject) === JSON.stringify(peer.issuer),
      isExpired: validTo ? validTo.getTime() < now : false,
      hostnameMatches: sans.length ? hostnameMatchesCertificate(host, sans) : null,
      publicKeyAlgorithm: parsed?.publicKeyAlgorithm ?? null,
      publicKeySize: parsed?.publicKeySize ?? 0,
      signatureAlgorithm: parsed?.signatureAlgorithm ?? null,
      validFrom: peer.valid_from ?? null,
      validTo: peer.valid_to ?? null,
      validityDays:
        validTo && validFrom
          ? Math.max(0, Math.floor((validTo.getTime() - validFrom.getTime()) / 86_400_000))
          : 0,
      daysRemaining: validTo ? Math.max(0, Math.floor((validTo.getTime() - now) / 86_400_000)) : 0,
      ocspStapled: probe.ocspStapled,
      ocspUri: infoAccess['OCSP - URI']?.[0] ?? null,
      // Filled in below by the live responder probe.
      ocspResponderState: 'not-probed',
      ocspResponderDetail: null,
      mustStaple: raw ? raw.includes(MUST_STAPLE_OID_DER) : false,
      crlDistributionPoints: crlPoints.slice(0, 4),
      signedCertificateTimestamps: sctCount > 0,
      sctCount,
      serialNumber: peer.serialNumber ?? null,
      fingerprint256: peer.fingerprint256 ?? null,
      error: null,
    }

    evidence.push({
      label: 'Leaf certificate',
      observedValue: `${data.publicKeyAlgorithm ?? 'unknown key'} · signed with ${data.signatureAlgorithm ?? 'unknown'}`,
      detectionMethod: 'X.509 certificate',
      evidenceSource: `serial ${data.serialNumber ?? 'unknown'}`,
      confidence: 100,
    })
    evidence.push({
      label: 'Chain trust',
      observedValue:
        probe.authorized === true
          ? 'verified against the public root store'
          : `verification failed: ${probe.authorizationError ?? 'unknown reason'}`,
      detectionMethod: 'Chain verification',
      evidenceSource: 'Node TLS chain validation',
      confidence: 100,
    })
    evidence.push({
      label: 'Subject alternative names',
      observedValue: sans.slice(0, 8).join(', ') || 'none',
      detectionMethod: 'X.509 extension',
      evidenceSource: 'subjectAltName',
      confidence: 100,
    })
    evidence.push({
      label: 'Certificate Transparency',
      observedValue: sctCount ? `${sctCount} embedded SCT${sctCount === 1 ? '' : 's'}` : 'no embedded SCTs',
      detectionMethod: 'X.509 extension',
      evidenceSource: 'OID 1.3.6.1.4.1.11129.2.4.2',
      confidence: 100,
    })
    evidence.push({
      label: 'OCSP stapling',
      observedValue: probe.ocspStapled ? 'stapled response returned' : 'no staple in handshake',
      detectionMethod: 'OCSP staple',
      evidenceSource: data.ocspUri ?? 'no responder advertised',
      confidence: 100,
    })

    emit({
      surface: 'certificate',
      label: 'Chain trust',
      detail:
        probe.authorized === true
          ? `Valid chain · ${chain.length} certificate(s) · ${data.daysRemaining}d remaining`
          : `Chain not verified: ${probe.authorizationError ?? 'unknown reason'}`,
      status: probe.authorized === true ? 'pass' : 'critical',
      severity: probe.authorized === true ? 'none' : 'high',
      verdict: probe.authorized === true ? 'Valid chain' : 'Untrusted chain',
    })
    emit({
      surface: 'ocsp',
      label: 'OCSP stapling',
      detail: probe.ocspStapled
        ? 'Stapled response returned in the handshake'
        : data.ocspUri
          ? 'Responder published, response not stapled'
          : 'No OCSP responder in the certificate',
      status: probe.ocspStapled ? 'pass' : data.ocspUri ? 'warning' : 'info',
      severity: probe.ocspStapled ? 'none' : data.ocspUri ? 'low' : 'info',
      verdict: probe.ocspStapled ? 'Secure' : data.ocspUri ? 'Not stapled' : 'No responder',
    })

    // Live responder liveness — a real request, made only when the certificate
    // actually advertises a responder.
    const responder = await probeOcspResponder(data.ocspUri)
    data.ocspResponderState = responder.state
    data.ocspResponderDetail = responder.detail
    evidence.push({
      label: 'OCSP responder liveness',
      observedValue: responder.detail,
      detectionMethod: 'OCSP staple',
      evidenceSource: data.ocspUri ?? 'no responder advertised',
      confidence: responder.state === 'not-probed' ? 40 : 100,
    })
    if (responder.state === 'unreachable') {
      notes.push(
        `The certificate advertises an OCSP responder at ${data.ocspUri} but it did not answer. Clients that soft-fail revocation will not be checking revocation for this endpoint.`,
      )
    }
    if (data.ocspUri) {
      emit({
        surface: 'ocsp',
        label: 'Responder liveness',
        detail: responder.detail,
        status: responder.state === 'reachable' ? 'pass' : responder.state === 'unreachable' ? 'warning' : 'info',
        severity: responder.state === 'unreachable' ? 'medium' : 'none',
      })
    }
    emit({
      surface: 'ocsp',
      label: 'Certificate Transparency',
      detail: sctCount ? `${sctCount} embedded SCT(s) logged` : 'No embedded CT SCTs',
      status: sctCount ? 'pass' : 'warning',
      severity: sctCount ? 'none' : 'low',
    })

    if (data.hostnameMatches === false) {
      notes.push(`Certificate does not cover ${host}; clients will reject the name.`)
    }

    return { data, ok: true, confidence: clampScore(parsed ? 100 : 75), evidence, notes, error: null }
  })
}
