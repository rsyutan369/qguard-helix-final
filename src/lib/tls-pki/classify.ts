/**
 * TLS & PKI classification - the single reading of a transport observation.
 *
 * Everything here delegates the hard part to `analyzeCryptoObservation()` in
 * `src/lib/crypto/suite-anatomy.ts`. That module exists precisely because
 * substring-matching a cipher-suite string classifies whichever primitive the
 * pattern happens to hit first, and every consumer that did so published
 * something false (see its header for the measured examples).
 *
 * The previous TLS dashboards did exactly that:
 *
 *     isWeakTls(text) = /ssl|tls 1\.[01]|rc4|3des|des|cbc|sha1|md5|.../
 *
 * On a live tenant that predicate matched `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`
 * (correctly, for the CBC/SHA-1 parts) but ALSO matched the string "OpenSSL
 * 3.0.13" and any finding whose description contained the word "des" inside
 * another word. It then applied the verdict to the WHOLE observation.
 *
 * So: decompose first, classify the PART, never the whole string.
 */

import { analyzeCryptoObservation, type SuiteAnatomy } from '@/lib/crypto/suite-anatomy'
import { namesCryptography, observationClass } from '@/lib/scanner/finding-identity'
import type {
  PqcPosture,
  RiskLevel,
  Severity,
  TlsVersionLabel,
} from './types'
import { TLS_VERSION_ORDER } from './types'

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

export function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

export function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

export function clamp(value: number, min = 0, max = 100): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, Math.round(value)))
}

export function recordOf(value: unknown): Record<string, unknown> {
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

export function isoOrNull(value: unknown): string | null {
  const ms = Date.parse(str(value))
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null
}

export function dateMs(value: unknown): number {
  const ms = Date.parse(str(value))
  return Number.isFinite(ms) ? ms : 0
}

export function latestIso(...values: Array<unknown>): string | null {
  let best = 0
  for (const value of values) {
    const ms = dateMs(value)
    if (ms > best) best = ms
  }
  return best ? new Date(best).toISOString() : null
}

export function percentOf(value: number, total: number): number {
  return total > 0 ? clamp((value / total) * 100) : 0
}

/** First non-empty string among the given keys of a record. */
export function pick(record: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = str(record[key])
    if (value) return value
  }
  return ''
}

export function pickNumber(record: Record<string, unknown>, keys: string[]): number | null {
  for (const key of keys) {
    const value = Number(record[key])
    if (Number.isFinite(value) && value > 0) return value
  }
  return null
}

export function normalizeSeverity(value: unknown): Severity {
  const lower = str(value).toLowerCase()
  if (lower.includes('critical')) return 'critical'
  if (lower.includes('high') || lower === 'error' || lower === 'failed') return 'high'
  if (lower.includes('medium') || lower.includes('moderate') || lower === 'warning') return 'medium'
  return 'low'
}

export function severityRank(value: Severity | null | undefined): number {
  if (value === 'critical') return 4
  if (value === 'high') return 3
  if (value === 'medium') return 2
  if (value === 'low') return 1
  return 0
}

export function riskLevelFor(score: number): RiskLevel {
  if (score <= 0) return 'none'
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

/* ------------------------------------------------------------------ */
/* Host normalisation - the endpoint identity primitive                */
/* ------------------------------------------------------------------ */

/**
 * Reduce anything host-shaped to a comparable key.
 *
 * `https://Example.COM:443/login`, `example.com` and `EXAMPLE.com.` must all
 * produce `example.com`, or the same endpoint appears three times and every
 * per-endpoint percentage is computed against an inflated denominator.
 */
export function normalizeHost(value: unknown): string {
  let text = str(value).toLowerCase()
  if (!text) return ''
  text = text.replace(/^[a-z0-9+.-]+:\/\//, '')
  text = text.split('/')[0]
  text = text.split('?')[0]
  // Strip a trailing port but keep the address of an IPv6 listener intact.
  if (text.startsWith('[')) text = text.replace(/(\]):\d+$/, '$1')
  else if ((text.match(/:/g) || []).length === 1) text = text.replace(/:\d+$/, '')
  text = text.replace(/\.$/, '')
  return text.trim()
}

export function portOf(value: unknown): number | null {
  const direct = Number(value)
  if (Number.isFinite(direct) && direct > 0 && direct < 65536) return Math.round(direct)
  const text = str(value)
  if ((text.replace(/^[a-z0-9+.-]+:\/\//i, '').split(/[/?#]/, 1)[0].match(/:/g) || []).length > 1 && !text.includes(']')) return null
  const match = text.match(/:(\d{1,5})(?:[/?#]|$)/)
  if (match) {
    const parsed = Number(match[1])
    if (Number.isFinite(parsed) && parsed > 0 && parsed < 65536) return parsed
  }
  return null
}

/** Canonical endpoint id. Asset binding wins, so scans and runtime agree. */
export function endpointIdFor(assetId: string | null | undefined, host: string, port: number | null = null): string {
  const asset = str(assetId)
  const normalized = normalizeHost(host)
  const listener = normalized ? `${encodeURIComponent(normalized)}:${port ?? 'unknown-port'}` : ''
  if (asset) return listener ? `asset:${asset}:${listener}` : `asset:${asset}`
  return listener ? `host:${listener}` : ''
}

/* ------------------------------------------------------------------ */
/* Protocol versions                                                   */
/* ------------------------------------------------------------------ */

/**
 * Parse a TLS/SSL version out of a measured string.
 *
 * Returns `null` rather than guessing. `Unknown` is reserved for observations
 * that clearly ARE a protocol record but whose version could not be read - the
 * two states mean different things on the dashboard and must not merge.
 */
export function parseTlsVersion(value: unknown): TlsVersionLabel | null {
  // Normalise the spellings the sources actually produce:
  //   openssl "TLSv1.2" · scanner "TLS 1.2" · agent "TLS_1_2" · nmap "TLSv1"
  // The bare "TLSv1" form carries no minor number and MEANS TLS 1.0 (RFC 2246).
  // Failing to read it is not cosmetic: it kept a deprecated protocol out of
  // the legacy count while the anomaly panel, reading the same evidence a
  // different way, reported it — two panels contradicting each other on one
  // page, which is exactly what this module exists to prevent.
  const text = str(value).toUpperCase().replace(/[_\s-]+/g, '')
  if (!text) return null
  if (/TLSV?1\.3|TLS13/.test(text)) return 'TLS 1.3'
  if (/TLSV?1\.2|TLS12/.test(text)) return 'TLS 1.2'
  if (/TLSV?1\.1|TLS11/.test(text)) return 'TLS 1.1'
  if (/TLSV?1\.0|TLS10|^TLSV1$|^TLS1$/.test(text)) return 'TLS 1.0'
  // SSL 2.0 and 3.0 are both long dead; they share the oldest bucket so a
  // single "deprecated protocol" row cannot be read as two different risks.
  if (/SSLV?3(\.0)?|SSL30|SSLV?2(\.0)?/.test(text)) return 'SSL 3.0'
  if (/^TLS$|^SSL$|^HTTPS$/.test(text)) return 'Unknown'
  return null
}

export function versionRank(version: TlsVersionLabel | null): number {
  if (!version || version === 'Unknown') return -1
  return TLS_VERSION_ORDER.indexOf(version as (typeof TLS_VERSION_ORDER)[number])
}

/** RFC 8996 deprecates TLS 1.0 and 1.1; SSL 3.0 was deprecated by RFC 7568. */
export function isLegacyVersion(version: TlsVersionLabel | null): boolean {
  return version === 'TLS 1.0' || version === 'TLS 1.1' || version === 'SSL 3.0'
}

/* ------------------------------------------------------------------ */
/* Observation classification                                          */
/* ------------------------------------------------------------------ */

export type ObservationKind = 'protocol' | 'cipher-suite' | 'key-exchange' | 'signature' | 'certificate'

export interface ClassifiedObservation {
  kind: ObservationKind
  family: string
  posture: PqcPosture
  forwardSecrecy: boolean | null
  anatomy: SuiteAnatomy
  /**
   * Weakness reasons that are actually determined by the decomposed parts.
   * Empty means "no weakness found in what we could read", which is NOT the
   * same as "strong" - the caller must not treat an empty list as a pass.
   */
  weaknesses: string[]
}

const HYBRID_KEX_RE = /X25519MLKEM|SECP256R1MLKEM|X25519.*ML-?KEM|ML-?KEM.*X25519|P256.*ML-?KEM/i
const PQ_KEX_RE = /ML-?KEM|KYBER/i
const PQ_SIG_RE = /ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS|FALCON/i

/** Map the decomposer's quantum class onto the four-page posture vocabulary. */
function postureFromAnatomy(anatomy: SuiteAnatomy, raw: string): PqcPosture {
  if (anatomy.quantumClass === 'hybrid' || HYBRID_KEX_RE.test(raw)) return 'hybrid-ready'
  if (anatomy.quantumClass === 'safe') {
    // A symmetric primitive or hash being quantum-resistant does not make the
    // endpoint post-quantum; only a PQ key agreement or PQ signature does.
    if (anatomy.kind === 'key-exchange' || anatomy.kind === 'signature') return 'pqc-ready'
    return 'quantum-safe'
  }
  if (anatomy.quantumClass === 'vulnerable') return 'quantum-vulnerable'
  return 'unknown'
}

/** Weaknesses that the DECOMPOSED parts genuinely establish. */
function weaknessesOf(anatomy: SuiteAnatomy, raw: string): string[] {
  const found: string[] = []
  const bulk = str(anatomy.bulk).toUpperCase()
  const mac = str(anatomy.mac).toUpperCase()
  const kex = str(anatomy.keyExchange).toUpperCase()
  const auth = str(anatomy.authentication).toUpperCase()

  if (/^(3DES|DES|RC4)$/.test(bulk)) found.push(`${anatomy.bulk} bulk cipher is broken (RFC 8429 / RFC 7465)`)
  if (/CBC/.test(bulk)) found.push(`${anatomy.bulk} uses CBC mode - vulnerable to padding-oracle classes; prefer AEAD`)
  if (/^SHA-1$|^MD5$/.test(mac)) found.push(`${anatomy.mac} MAC/hash is collision-broken`)
  if (anatomy.forwardSecrecy === false) {
    found.push(
      kex === 'RSA' || /RSA/.test(anatomy.family)
        ? 'RSA key transport - no forward secrecy, so recorded traffic stays decryptable once the key is broken'
        : 'Static key agreement - no forward secrecy',
    )
  }
  if (/^RSA-?1024$/.test(auth) || /RSA-1024/.test(anatomy.family)) found.push('RSA-1024 is below the 2048-bit floor')
  if (anatomy.kind === 'protocol' && isLegacyVersion(parseTlsVersion(raw))) {
    found.push(`${raw} is deprecated by RFC 8996`)
  }
  return found
}

/**
 * Classify one measured cryptographic string in transport context.
 *
 * `componentName` is the scanner's own class-prefixed record name
 * ("Cipher Suite: TLS_...", "Rule (Tls Config): ..."). It gates the decomposer
 * so that a policy finding never gets read as an algorithm.
 */
export function classifyObservation(input: {
  algorithm: unknown
  componentName?: unknown
  itemType?: unknown
  protocol?: unknown
  keySize?: unknown
}): ClassifiedObservation | null {
  const raw = str(input.algorithm)
  if (!raw) return null

  const componentName = str(input.componentName)
  // When the record carries a scanner class prefix, trust it. When it does not
  // (runtime agent columns such as `cipher_suite`), the column itself already
  // states the class, so the gate defaults open.
  const isCrypto = componentName ? namesCryptography(componentName) : true
  if (!isCrypto) return null

  const anatomy = analyzeCryptoObservation(
    { algorithm: raw, name: componentName || undefined, itemType: input.itemType, protocol: input.protocol },
    true,
  )

  // A protocol version can arrive either as the algorithm itself or via the
  // scanner class prefix. Handle it before anything else so `TLS 1.2` is never
  // mistaken for a cipher.
  const version = parseTlsVersion(raw)
  const classPrefix = observationClass(componentName)
  if (anatomy.kind === 'protocol' || (version && version !== 'Unknown' && /^(protocol|protocol support)$/.test(classPrefix))) {
    const label = version && version !== 'Unknown' ? version : raw
    return {
      kind: 'protocol',
      family: label,
      // A protocol version alone never establishes post-quantum posture: TLS
      // 1.3 with X25519 is still classical. Only the key agreement decides.
      posture: isLegacyVersion(version) ? 'legacy' : 'unknown',
      forwardSecrecy: version === 'TLS 1.3' ? true : null,
      anatomy,
      weaknesses: weaknessesOf(anatomy, raw),
    }
  }

  if (anatomy.kind === 'policy') return null

  const kind: ObservationKind =
    anatomy.kind === 'cipher-suite'
      ? 'cipher-suite'
      : anatomy.kind === 'key-exchange'
        ? 'key-exchange'
        : anatomy.kind === 'certificate'
          ? 'certificate'
          : anatomy.kind === 'signature'
            ? 'signature'
            : 'cipher-suite'

  // The suite decomposer deliberately hardcodes `quantumClass: 'vulnerable'`
  // for classic TLS 1.2-style suites because their key exchange decides it.
  // A hybrid group negotiated alongside such a suite is carried on the separate
  // key-exchange observation, so we do not second-guess it here.
  let posture = postureFromAnatomy(anatomy, raw)
  if (kind === 'signature' || kind === 'certificate') {
    if (PQ_SIG_RE.test(raw)) posture = 'pqc-ready'
  }
  if (kind === 'key-exchange') {
    if (HYBRID_KEX_RE.test(raw)) posture = 'hybrid-ready'
    else if (PQ_KEX_RE.test(raw)) posture = 'pqc-ready'
  }

  const keySize = num(input.keySize, 0)
  const weaknesses = weaknessesOf(anatomy, raw)
  if (/RSA/i.test(anatomy.family) && keySize > 0 && keySize < 2048) {
    weaknesses.push(`RSA-${keySize} is below the 2048-bit minimum (NIST SP 800-57)`)
  }

  return {
    kind,
    family: anatomy.family || raw,
    posture,
    forwardSecrecy: anatomy.forwardSecrecy,
    anatomy,
    weaknesses,
  }
}

/* ------------------------------------------------------------------ */
/* Endpoint posture                                                    */
/* ------------------------------------------------------------------ */

export interface EndpointPostureInput {
  /** Postures of every observation measured on the endpoint. */
  observationPostures: PqcPosture[]
  /** Highest version observed - what the endpoint prefers. */
  bestVersion: TlsVersionLabel | null
  /** EVERY protocol version observed, because the floor decides legacy risk. */
  observedVersions: TlsVersionLabel[]
  hasKeyExchangeEvidence: boolean
  hasAnyEvidence: boolean
  /** The Quantum Readiness / Migration Planner reading for the bound asset. */
  assetPosture: 'pqc' | 'hybrid' | 'vulnerable' | null
  migrationCompleted: boolean
}

export interface EndpointPostureResult {
  posture: PqcPosture
  reason: string
}

/**
 * Decide one endpoint's posture.
 *
 * Ordering matters and encodes the honesty rules:
 *   1. No evidence at all is `unknown`, never "safe". Absence of a finding is
 *      not a clean bill of health.
 *   2. A deprecated protocol version outranks a good key exchange: an endpoint
 *      still accepting TLS 1.0 is `legacy` whatever else it also supports.
 *   3. Post-quantum and hybrid require KEY-AGREEMENT evidence. AES-256-GCM
 *      being quantum-resistant does not make an endpoint quantum-safe.
 *   4. Otherwise the endpoint is classical, and whether it reads as
 *      `quantum-vulnerable` or `migration-required` follows the estate-wide
 *      asset posture so this page and Migration Planner never disagree.
 */
export function classifyEndpointPosture(input: EndpointPostureInput): EndpointPostureResult {
  if (!input.hasAnyEvidence) {
    return { posture: 'unknown', reason: 'No transport evidence captured for this endpoint yet.' }
  }

  // Checks EVERY observed version, not just the best one. An endpoint whose
  // ceiling is TLS 1.2 but which still answers on TLS 1.0 is a legacy endpoint:
  // the downgrade path is the risk, not the ceiling. Reading only the ceiling is
  // what let a posture tile print "no deprecated protocol observed" on the same
  // screen as an anomaly panel reporting exactly that.
  const legacyVersions = input.observedVersions.filter(isLegacyVersion)
  if (legacyVersions.length) {
    const ceiling = input.bestVersion && !isLegacyVersion(input.bestVersion) ? input.bestVersion : null
    return {
      posture: 'legacy',
      reason: ceiling
        ? `Still accepts ${legacyVersions.join(', ')} alongside ${ceiling}, so a downgrade path remains open (RFC 8996 deprecates it).`
        : `Highest observed protocol is ${legacyVersions.join(', ')}, deprecated by RFC 8996.`,
    }
  }

  const set = new Set(input.observationPostures)

  // Hybrid is checked BEFORE pure post-quantum. When an endpoint offers both a
  // hybrid group and a bare ML-KEM group, the protection it actually delivers is
  // the hybrid one - part of the shared secret still rests on X25519. Reporting
  // "PQC Ready" there would overstate the posture.
  if (set.has('hybrid-ready')) {
    return {
      posture: 'hybrid-ready',
      reason: 'Hybrid X25519 + ML-KEM key agreement observed - the classical and post-quantum shares are both present.',
    }
  }
  if (set.has('pqc-ready') && input.hasKeyExchangeEvidence) {
    return { posture: 'pqc-ready', reason: 'Post-quantum key agreement or signature observed on this endpoint.' }
  }

  if (set.has('quantum-vulnerable')) {
    if (input.assetPosture === 'vulnerable' || !input.assetPosture) {
      return {
        posture: 'quantum-vulnerable',
        reason: 'Classical key agreement or signature observed - Shor-breakable once a CRQC exists.',
      }
    }
    return {
      posture: 'migration-required',
      reason: 'Classical transport cryptography observed while the asset is already partway through migration.',
    }
  }

  if (set.has('quantum-safe') && !input.hasKeyExchangeEvidence) {
    return {
      posture: 'unknown',
      reason: 'Only symmetric or hash primitives observed - the key agreement, which decides quantum posture, was not measured.',
    }
  }

  return {
    posture: 'unknown',
    reason: 'Transport evidence exists but does not determine the key agreement.',
  }
}

/** Postures that count as adopted post-quantum protection. */
export function isPqcAdopted(posture: PqcPosture): boolean {
  return posture === 'pqc-ready' || posture === 'hybrid-ready'
}

/** Postures that require operator action. */
export function needsRemediation(posture: PqcPosture): boolean {
  return posture === 'legacy' || posture === 'quantum-vulnerable' || posture === 'migration-required'
}

export const POSTURE_LABEL: Record<PqcPosture, string> = {
  'quantum-safe': 'Quantum Safe',
  'pqc-ready': 'PQC Ready',
  'hybrid-ready': 'Hybrid Ready',
  'migration-required': 'Migration Required',
  'quantum-vulnerable': 'Quantum Vulnerable',
  legacy: 'Legacy',
  unknown: 'Unknown',
}

export const POSTURE_TONE: Record<PqcPosture, 'good' | 'warning' | 'critical' | 'neutral' | 'info'> = {
  'quantum-safe': 'good',
  'pqc-ready': 'good',
  'hybrid-ready': 'info',
  'migration-required': 'warning',
  'quantum-vulnerable': 'critical',
  legacy: 'critical',
  unknown: 'neutral',
}

/* ------------------------------------------------------------------ */
/* Certificate posture                                                 */
/* ------------------------------------------------------------------ */

export function certificatePosture(algorithm: string, signatureAlgorithm: string | null, keySize: number | null): PqcPosture {
  const anatomy = analyzeCryptoObservation({ algorithm, itemType: 'certificate' }, true)
  const subjectClassical = !PQ_SIG_RE.test(algorithm) && (anatomy.quantumClass === 'vulnerable' || Boolean(keySize && /RSA/i.test(algorithm)))
  const issuerClassical = signatureAlgorithm !== null && !PQ_SIG_RE.test(signatureAlgorithm) && /RSA|ECDSA|\bDSA\b|ED25519|ED448|SHA-?1|MD5/i.test(signatureAlgorithm)
  if (subjectClassical || issuerClassical) return 'quantum-vulnerable'
  return PQ_SIG_RE.test(algorithm) && signatureAlgorithm !== null && PQ_SIG_RE.test(signatureAlgorithm)
    ? 'pqc-ready'
    : 'unknown'
}

/** Weaknesses a certificate's own fields establish. */
export function certificateWeaknesses(input: {
  algorithm: string
  signatureAlgorithm: string | null
  keySize: number | null
  selfSigned: boolean
  daysToExpiry: number | null
  lifecycle: string
}): string[] {
  const found: string[] = []
  if (/SHA-?1|MD5/i.test(input.signatureAlgorithm || '')) {
    found.push(`${input.signatureAlgorithm} signature is collision-broken (RFC 6194)`)
  }
  if (/RSA/i.test(input.algorithm) && input.keySize && input.keySize < 2048) {
    found.push(`RSA-${input.keySize} public key is below the 2048-bit minimum`)
  }
  if (input.selfSigned) found.push('Self-signed - outside any managed trust hierarchy')
  if (input.lifecycle === 'expired') found.push('Certificate has expired')
  else if (input.lifecycle === 'revoked') found.push('Certificate is revoked but still present in inventory')
  else if (input.lifecycle === 'not-yet-valid') found.push('Certificate is not yet valid')
  else if (typeof input.daysToExpiry === 'number' && input.daysToExpiry <= 30) {
    found.push(`Expires in ${Math.max(0, input.daysToExpiry)} day(s)`)
  }
  return found
}

/* ------------------------------------------------------------------ */
/* Remediation targets                                                 */
/* ------------------------------------------------------------------ */

export interface RemediationTarget {
  target: string
  standard: string
  rationale: string
}

/**
 * The NIST-approved replacement for a measured primitive.
 *
 * Deliberately explicit rather than a generic "migrate to PQC" string, because
 * an operator has to type the actual algorithm into a config file.
 */
export function remediationFor(kind: ObservationKind, family: string, observed: string): RemediationTarget {
  const text = `${family} ${observed}`.toUpperCase()

  if (kind === 'protocol') {
    return {
      target: 'TLS 1.3',
      standard: 'RFC 8446 / RFC 8996',
      rationale: 'TLS 1.3 removes static RSA key transport, CBC modes and renegotiation, and is the only version that can negotiate hybrid ML-KEM groups.',
    }
  }
  if (kind === 'certificate' || kind === 'signature') {
    if (/RSA|ECDSA|ED25519|ED448|DSA/.test(text)) {
      return {
        target: 'ML-DSA-65 (or hybrid ECDSA P-256 + ML-DSA-65)',
        standard: 'FIPS 204',
        rationale: 'RSA and elliptic-curve signatures are forgeable by a CRQC via Shor. ML-DSA is the NIST-standardised lattice signature.',
      }
    }
    return { target: 'ML-DSA-65', standard: 'FIPS 204', rationale: 'Post-quantum digital signature standard.' }
  }
  if (kind === 'key-exchange' || kind === 'cipher-suite') {
    if (/RSA KEY TRANSPORT|STATIC/.test(text)) {
      return {
        target: 'X25519MLKEM768',
        standard: 'FIPS 203 / RFC 9370',
        rationale: 'Static RSA key transport has no forward secrecy at all: recorded traffic is decryptable retroactively. Hybrid ML-KEM restores forward secrecy and adds post-quantum protection in one change.',
      }
    }
    return {
      target: 'X25519MLKEM768 (hybrid)',
      standard: 'FIPS 203',
      rationale: 'ECDHE and X25519 are Shor-breakable. The hybrid group keeps the classical guarantee while adding ML-KEM-768.',
    }
  }
  return { target: 'ML-KEM-768 / ML-DSA-65', standard: 'FIPS 203 / FIPS 204', rationale: 'NIST post-quantum standards.' }
}

/* ------------------------------------------------------------------ */
/* Text helpers used by the projections                                */
/* ------------------------------------------------------------------ */

export function titleCase(value: unknown, fallback = ''): string {
  const text = str(value).replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return fallback
  return text.replace(/\b\w/g, (char) => char.toUpperCase())
}

/** Unique, order-preserving. */
export function uniq<T>(values: T[]): T[] {
  return [...new Set(values)]
}
