/**
 * QGuard Web Scanner — X.509 Certificate Parser
 * Parses TLS certificates and extracts cryptographic metadata with OID classification
 */

import * as crypto from 'node:crypto'
import type * as tls from 'node:tls'
import type { CertificateInfo, CertificateChainEntry, OidClassification } from './types'
import { classifySignatureAlgorithm, lookupOid, OID_DATABASE } from './oid-database'

/**
 * The OIDs in `detectedOids` that merely RESTATE facts already reported by the
 * dedicated public-key and signature findings.
 *
 * ONE FACT, ONE FINDING. `detectedOids` is a complete parse of the certificate,
 * so for a single ECDSA P-256 leaf it contains `ecPublicKey` (the key's
 * algorithm), `secp256r1 (P-256)` (that same key's curve) and
 * `ecdsa-with-SHA256` (the signature) — every one of which is also reported by
 * the certificate finding or the signature finding. Emitting all of them turned
 * one certificate, carrying two facts, into five separate HIGH findings. That
 * inflated the headline count, the per-surface severity mass and every mean
 * computed over the evidence list, and it is why the Certificates & Keys card
 * could not read better than "Critical" for any certificate on the public
 * internet.
 *
 * Exported so the rule can be exercised directly by
 * `tools/scanner-scoring-check.ts` instead of only through a live scan.
 */
export function leafRestatedOids(
  cert: Pick<CertificateInfo, 'publicKeyOid' | 'publicKeyCurveOid' | 'signatureOid'>,
): Set<string> {
  return new Set(
    [cert.publicKeyOid, cert.publicKeyCurveOid, cert.signatureOid].filter(
      (oid): oid is string => Boolean(oid),
    ),
  )
}

/**
 * Parse a certificate from Node.js TLS PeerCertificate object
 */
export function parseCertificateFromPeer(
  peerCert: tls.PeerCertificate & { raw?: Buffer; issuerCertificate?: tls.PeerCertificate }
): CertificateInfo {
  // Extract subject and issuer
  const subject: Record<string, string> = {}
  const issuer: Record<string, string> = {}

  if (peerCert.subject) {
    for (const [key, value] of Object.entries(peerCert.subject)) {
      subject[key] = String(value)
    }
  }

  if (peerCert.issuer) {
    for (const [key, value] of Object.entries(peerCert.issuer)) {
      issuer[key] = String(value)
    }
  }

  // Determine if self-signed
  const isSelfSigned = JSON.stringify(peerCert.subject) === JSON.stringify(peerCert.issuer)

  // Parse dates
  const validFrom = peerCert.valid_from || ''
  const validTo = peerCert.valid_to || ''
  const isExpired = validTo ? new Date(validTo) < new Date() : false

  // Extract public key info using X509Certificate if raw DER is available
  let publicKeyAlgorithm = 'unknown'
  let publicKeySize = 0
  let signatureAlgorithm = 'unknown'
  let signatureOid = ''
  /* Recorded alongside `detectedOids` so the orchestrator can tell which parsed
     OIDs merely RESTATE the leaf's own key — the SPKI algorithm and its named
     curve — and are therefore already reported by the dedicated public-key
     finding. See `CertificateInfo.publicKeyOid`. */
  let publicKeyOid: string | null = null
  let publicKeyCurveOid: string | null = null
  let detectedOids: OidClassification[] = []

  if (peerCert.raw) {
    try {
      const x509 = new crypto.X509Certificate(peerCert.raw)

      // Extract public key info
      const pubKey = x509.publicKey
      publicKeyAlgorithm = pubKey.asymmetricKeyType || 'unknown'
      publicKeySize = getKeySize(pubKey)

      // Format the algorithm name
      publicKeyAlgorithm = formatPublicKeyAlgorithm(publicKeyAlgorithm, publicKeySize)

      // Extract signature algorithm by reading the signatureAlgorithm OID directly from the
      // certificate DER. Node's X509Certificate.toString() returns PEM (base64) — NOT OpenSSL
      // text — so it carries no "Signature Algorithm:" line; we parse the real cert bytes.
      const sigOid = extractSignatureAlgorithmOidFromDer(peerCert.raw)
      if (sigOid) {
        const sigEntry = lookupOid(sigOid)
        signatureAlgorithm = sigEntry?.name || sigOid
        signatureOid = sigOid
        if (sigEntry && !detectedOids.some((o) => o.oid === sigEntry.oid)) {
          detectedOids.push(sigEntry)
        }
      } else {
        signatureAlgorithm = extractSignatureAlgorithmFromBasic(peerCert)
        const sigOidEntry = classifySignatureAlgorithm(signatureAlgorithm)
        if (sigOidEntry) {
          signatureOid = sigOidEntry.oid
          if (!detectedOids.some((o) => o.oid === sigOidEntry.oid)) detectedOids.push(sigOidEntry)
        }
      }

      // Detect public key algorithm OID
      const pubKeyOid = getPublicKeyOid(publicKeyAlgorithm)
      if (pubKeyOid) {
        publicKeyOid = pubKeyOid
        const pubKeyEntry = lookupOid(pubKeyOid)
        if (pubKeyEntry && !detectedOids.some(o => o.oid === pubKeyEntry.oid)) {
          detectedOids.push(pubKeyEntry)
        }
      }

      // Check for EC curve OIDs
      if (pubKey.asymmetricKeyType === 'ec') {
        const curveOid = detectEcCurveOid(pubKey)
        if (curveOid) {
          publicKeyCurveOid = curveOid
          const curveEntry = lookupOid(curveOid)
          if (curveEntry && !detectedOids.some(o => o.oid === curveEntry.oid)) {
            detectedOids.push(curveEntry)
          }
        }
      }
    } catch {
      // Fallback to basic certificate fields
      signatureAlgorithm = extractSignatureAlgorithmFromBasic(peerCert)
    }
  } else {
    signatureAlgorithm = extractSignatureAlgorithmFromBasic(peerCert)
  }

  // If we still couldn't get OIDs, try to infer from algorithm names
  if (detectedOids.length === 0) {
    detectedOids = inferOidsFromAlgorithms(publicKeyAlgorithm, signatureAlgorithm)
    // The inferred set restates the same two facts, so the leaf-key OID has to
    // be recorded here too or the dedup filter silently stops working on every
    // certificate whose DER did not parse.
    publicKeyOid = publicKeyOid ?? getPublicKeyOid(publicKeyAlgorithm)
  }

  // Walk the certificate chain
  const chain = walkCertificateChain(peerCert)

  return {
    subject,
    issuer,
    publicKeyAlgorithm,
    publicKeySize,
    signatureAlgorithm,
    signatureOid,
    publicKeyOid,
    publicKeyCurveOid,
    validFrom,
    validTo,
    serialNumber: peerCert.serialNumber || '',
    fingerprint: peerCert.fingerprint256 || peerCert.fingerprint || '',
    isExpired,
    isSelfSigned,
    chain,
    detectedOids,
  }
}

/**
 * Get the key size from a KeyObject
 */
function getKeySize(pubKey: crypto.KeyObject): number {
  try {
    const details = pubKey.asymmetricKeyDetails
    if (!details) return 0

    // RSA and DSA have modulusLength
    if ('modulusLength' in details) return details.modulusLength as number

    // EC has namedCurve — infer size from curve name
    if ('namedCurve' in details) {
      const curve = details.namedCurve as string
      if (curve.includes('256') || curve === 'prime256v1') return 256
      if (curve.includes('384')) return 384
      if (curve.includes('521')) return 521
      if (curve === 'secp256k1') return 256
    }

    // DH has primeLength
    if ('primeLength' in details) return details.primeLength as number

    return 0
  } catch {
    return 0
  }
}

/**
 * Format the public key algorithm name for display
 */
function formatPublicKeyAlgorithm(algType: string, keySize: number): string {
  switch (algType) {
    case 'rsa':
      return `RSA-${keySize}`
    case 'ec':
      return `ECDSA P-${keySize}`
    case 'dsa':
      return `DSA-${keySize}`
    case 'dh':
      return `DH-${keySize}`
    case 'ed25519':
      return 'Ed25519'
    case 'ed448':
      return 'Ed448'
    case 'x25519':
      return 'X25519'
    case 'x448':
      return 'X448'
    default:
      return keySize > 0 ? `${algType.toUpperCase()}-${keySize}` : algType.toUpperCase()
  }
}

/**
 * Get the OID for a public key algorithm
 */
function getPublicKeyOid(algorithm: string): string | null {
  const normalized = algorithm.toLowerCase()
  if (normalized.startsWith('rsa')) return '1.2.840.113549.1.1.1'
  if (normalized.startsWith('ecdsa') || normalized.startsWith('ec')) return '1.2.840.10045.2.1'
  if (normalized.startsWith('dsa')) return '1.2.840.10040.4.1'
  if (normalized.startsWith('dh')) return '1.2.840.113549.1.3.1'
  return null
}

/**
 * Detect the EC curve OID from a KeyObject
 */
function detectEcCurveOid(pubKey: crypto.KeyObject): string | null {
  try {
    const details = pubKey.asymmetricKeyDetails
    if (!details || !('namedCurve' in details)) return null

    const curve = details.namedCurve as string
    const curveMap: Record<string, string> = {
      'prime256v1': '1.2.840.10045.3.1.7',
      'P-256': '1.2.840.10045.3.1.7',
      'secp256r1': '1.2.840.10045.3.1.7',
      'secp384r1': '1.3.132.0.34',
      'P-384': '1.3.132.0.34',
      'secp521r1': '1.3.132.0.35',
      'P-521': '1.3.132.0.35',
    }

    return curveMap[curve] || null
  } catch {
    return null
  }
}

/** Read a DER TLV length at `pos`; returns the content length and the header byte count. */
function readDerLen(buf: Buffer, pos: number): { length: number; headerLen: number } {
  const first = buf[pos]
  if (first < 0x80) return { length: first, headerLen: 1 }
  const numBytes = first & 0x7f
  let length = 0
  for (let i = 0; i < numBytes; i++) length = length * 256 + buf[pos + 1 + i]
  return { length, headerLen: 1 + numBytes }
}

/** Decode DER OBJECT IDENTIFIER content bytes into dotted-decimal string. */
function decodeDerOid(bytes: Buffer): string {
  if (bytes.length === 0) return ''
  const first = bytes[0]
  const arcs: number[] = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80]
  let value = 0
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f)
    if ((bytes[i] & 0x80) === 0) {
      arcs.push(value)
      value = 0
    }
  }
  return arcs.join('.')
}

/**
 * Parse the certificate's `signatureAlgorithm` OID straight from the DER bytes.
 * X.509 = SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm AlgorithmIdentifier, signatureValue }.
 * We skip tbsCertificate and read the OID from the second AlgorithmIdentifier — evidence-based,
 * unlike Node's X509Certificate which exposes no signature-algorithm getter.
 */
function extractSignatureAlgorithmOidFromDer(raw: Buffer): string | null {
  try {
    let pos = 0
    if (raw[pos] !== 0x30) return null // outer Certificate SEQUENCE
    pos += 1 + readDerLen(raw, pos + 1).headerLen
    if (raw[pos] !== 0x30) return null // tbsCertificate SEQUENCE
    const tbs = readDerLen(raw, pos + 1)
    pos += 1 + tbs.headerLen + tbs.length // skip the entire tbsCertificate
    if (raw[pos] !== 0x30) return null // signatureAlgorithm AlgorithmIdentifier SEQUENCE
    pos += 1 + readDerLen(raw, pos + 1).headerLen
    if (raw[pos] !== 0x06) return null // OBJECT IDENTIFIER
    const oid = readDerLen(raw, pos + 1)
    const start = pos + 1 + oid.headerLen
    return decodeDerOid(raw.subarray(start, start + oid.length))
  } catch {
    return null
  }
}

/**
 * Extract signature algorithm from X509Certificate toString() output
 */
function extractSignatureAlgorithmFromText(certText: string): string {
  // Look for "Signature Algorithm:" line
  const match = certText.match(/Signature Algorithm:\s*(.+)/i)
  if (match) return match[1].trim()

  return 'unknown'
}

/**
 * Fallback: extract signature algorithm from basic PeerCertificate fields
 */
function extractSignatureAlgorithmFromBasic(
  peerCert: tls.PeerCertificate & { sigalg?: string }
): string {
  // Some Node.js versions expose sigalg
  if (peerCert.sigalg) return peerCert.sigalg

  // No reliable signature-algorithm source. Do NOT assume a default (evidence-based only).
  return 'unknown'
}

/**
 * Infer OIDs from algorithm name strings when raw cert parsing fails
 */
function inferOidsFromAlgorithms(
  pubKeyAlg: string,
  sigAlg: string
): OidClassification[] {
  const results: OidClassification[] = []
  const normalized = pubKeyAlg.toLowerCase()
  const sigNormalized = sigAlg.toLowerCase()

  // Public key algorithm OIDs
  if (normalized.startsWith('rsa')) {
    const entry = lookupOid('1.2.840.113549.1.1.1')
    if (entry) results.push(entry)
  } else if (normalized.includes('ec') || normalized.includes('ecdsa')) {
    const entry = lookupOid('1.2.840.10045.2.1')
    if (entry) results.push(entry)
  } else if (normalized.startsWith('dsa')) {
    const entry = lookupOid('1.2.840.10040.4.1')
    if (entry) results.push(entry)
  }

  // Signature algorithm OIDs
  const sigEntry = classifySignatureAlgorithm(sigAlg)
  if (sigEntry && !results.some(r => r.oid === sigEntry.oid)) {
    results.push(sigEntry)
  }

  return results
}

/**
 * Walk the certificate chain from peer certificate
 */
function walkCertificateChain(
  peerCert: tls.PeerCertificate & { issuerCertificate?: tls.PeerCertificate }
): CertificateChainEntry[] {
  const chain: CertificateChainEntry[] = []
  const visited = new Set<string>()
  let current: (tls.PeerCertificate & { issuerCertificate?: tls.PeerCertificate }) | undefined = peerCert

  while (current && chain.length < 10) {
    const serial = current.serialNumber || ''
    if (visited.has(serial)) break // Prevent loops (self-signed root)
    visited.add(serial)

    let sigAlg = 'unknown'
    let pubKeyAlg = 'unknown'
    let pubKeySize = 0

    if (current.raw) {
      try {
        const x509 = new crypto.X509Certificate(current.raw)
        const pubKey = x509.publicKey
        pubKeyAlg = formatPublicKeyAlgorithm(pubKey.asymmetricKeyType || 'unknown', getKeySize(pubKey))
        pubKeySize = getKeySize(pubKey)
        const certText = x509.toString()
        sigAlg = extractSignatureAlgorithmFromText(certText)
      } catch {
        // Use defaults
      }
    }

    chain.push({
      subject: formatDN(current.subject as unknown as Record<string, string>),
      issuer: formatDN(current.issuer as unknown as Record<string, string>),
      signatureAlgorithm: sigAlg,
      publicKeyAlgorithm: pubKeyAlg,
      publicKeySize: pubKeySize,
      validTo: current.valid_to || '',
      isExpired: current.valid_to ? new Date(current.valid_to) < new Date() : false,
    })

    current = current.issuerCertificate
  }

  return chain
}

/**
 * Format a Distinguished Name object as a string
 */
function formatDN(dn: Record<string, string> | undefined): string {
  if (!dn) return 'unknown'
  const parts: string[] = []
  if (dn.CN) parts.push(`CN=${dn.CN}`)
  if (dn.O) parts.push(`O=${dn.O}`)
  if (dn.OU) parts.push(`OU=${dn.OU}`)
  if (dn.C) parts.push(`C=${dn.C}`)
  return parts.join(', ') || 'unknown'
}

/**
 * Analyze certificate chain for quantum vulnerability distribution
 */
export function analyzeCertificateChainQuantumRisk(chain: CertificateChainEntry[]): {
  chainDepth: number
  weakLinks: { position: number; algorithm: string; issue: string }[]
  strongestLink: string
  weakestLink: string
  overallChainRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE'
} {
  const weakLinks: { position: number; algorithm: string; issue: string }[] = []
  let worstRisk = 0

  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i]
    let risk = 0

    // Check signature algorithm
    const sig = entry.signatureAlgorithm.toLowerCase()
    if (sig.includes('md5') || sig.includes('md2')) {
      weakLinks.push({ position: i, algorithm: entry.signatureAlgorithm, issue: 'Classically broken hash' })
      risk = 5
    } else if (sig.includes('sha1')) {
      weakLinks.push({ position: i, algorithm: entry.signatureAlgorithm, issue: 'Deprecated SHA-1 signature' })
      risk = 4
    }

    // Check public key algorithm
    const alg = entry.publicKeyAlgorithm.toLowerCase()
    if (alg.includes('rsa') && entry.publicKeySize <= 1024) {
      weakLinks.push({ position: i, algorithm: entry.publicKeyAlgorithm, issue: 'RSA-1024 quantum-breakable in minutes' })
      risk = Math.max(risk, 5)
    } else if (alg.includes('rsa') && entry.publicKeySize <= 2048) {
      weakLinks.push({ position: i, algorithm: entry.publicKeyAlgorithm, issue: 'RSA-2048 quantum-vulnerable' })
      risk = Math.max(risk, 3)
    } else if (alg.includes('ec') || alg.includes('ecdsa')) {
      weakLinks.push({ position: i, algorithm: entry.publicKeyAlgorithm, issue: 'ECC quantum-vulnerable via ECDLP' })
      risk = Math.max(risk, 3)
    }

    // Check expiry
    if (entry.isExpired) {
      weakLinks.push({ position: i, algorithm: 'Expired', issue: 'Certificate in chain has expired' })
      risk = Math.max(risk, 4)
    }

    worstRisk = Math.max(worstRisk, risk)
  }

  let overallChainRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' = 'SAFE'
  if (worstRisk >= 5) overallChainRisk = 'CRITICAL'
  else if (worstRisk >= 4) overallChainRisk = 'HIGH'
  else if (worstRisk >= 3) overallChainRisk = 'MEDIUM'
  else if (worstRisk >= 2) overallChainRisk = 'LOW'

  const algorithms = chain.map(c => c.publicKeyAlgorithm).filter(Boolean)
  const strongestLink = algorithms.find(a => a.toLowerCase().includes('4096') || a.toLowerCase().includes('384')) || algorithms[0] || 'unknown'
  const weakestLink = algorithms.find(a => a.toLowerCase().includes('1024') || a.toLowerCase().includes('md5')) || algorithms[algorithms.length - 1] || 'unknown'

  return {
    chainDepth: chain.length,
    weakLinks,
    strongestLink,
    weakestLink,
    overallChainRisk,
  }
}

/**
 * Calculate certificate validity risk metrics
 */
export function calculateCertValidityMetrics(certInfo: CertificateInfo): {
  daysRemaining: number
  validityDays: number
  isNearExpiry: boolean
  renewalUrgency: 'IMMEDIATE' | 'SOON' | 'PLANNED' | 'OK'
} {
  const now = new Date()
  const validTo = new Date(certInfo.validTo)
  const validFrom = new Date(certInfo.validFrom)

  const daysRemaining = Math.max(0, Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)))
  const validityDays = Math.floor((validTo.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24))
  const isNearExpiry = daysRemaining <= 30

  let renewalUrgency: 'IMMEDIATE' | 'SOON' | 'PLANNED' | 'OK' = 'OK'
  if (daysRemaining <= 0) renewalUrgency = 'IMMEDIATE'
  else if (daysRemaining <= 14) renewalUrgency = 'IMMEDIATE'
  else if (daysRemaining <= 30) renewalUrgency = 'SOON'
  else if (daysRemaining <= 90) renewalUrgency = 'PLANNED'

  return { daysRemaining, validityDays, isNearExpiry, renewalUrgency }
}
