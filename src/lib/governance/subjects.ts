/**
 * Cryptographic subjects — the normalised things governance judges.
 *
 * The policy engine and the control evaluators must look at the SAME
 * population, or a policy violation count and a control failure count for the
 * same rule will disagree. This module is that single population: every
 * cryptographic component, certificate, managed key and measured transport
 * observation the tenant has, reduced to one shape.
 *
 * Algorithm classification is delegated to the canonical
 * `classifyAlgorithm` used by the Quantum Readiness snapshot and the Migration
 * Planner, so "quantum-vulnerable" means exactly the same thing here as it does
 * on every other page.
 */

import { classifyAlgorithm } from '@/lib/migration/asset-intelligence'

export type Row = Record<string, unknown>

export type SubjectKind = 'component' | 'certificate' | 'key' | 'transport' | 'object'

export type AlgorithmFamily =
  | 'ml-kem'
  | 'ml-dsa'
  | 'slh-dsa'
  | 'hybrid'
  | 'rsa'
  | 'ecdsa'
  | 'ecdh'
  | 'dh'
  | 'dsa'
  | 'aes'
  | 'chacha'
  | '3des'
  | 'des'
  | 'rc4'
  | 'sha2'
  | 'sha3'
  | 'sha1'
  | 'md5'
  | 'unknown'

export interface CryptoSubject {
  id: string
  kind: SubjectKind
  label: string
  /** Raw algorithm string as recorded. */
  algorithm: string
  family: AlgorithmFamily
  /** Canonical posture: pqc | hybrid | vulnerable | unknown. */
  posture: ReturnType<typeof classifyAlgorithm>
  keySize: number | null
  protocol: string
  tlsVersion: string
  keyExchange: string
  assetId: string | null
  assetName: string
  environment: string
  internetFacing: boolean
  observedAt: string | null
  source: { table: string; recordId: string }
  href: string | null
  /** Extra raw fields specific evaluators need without re-querying. */
  meta: Record<string, unknown>
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

export function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : value === null || value === undefined ? '' : String(value).trim()
}

export function num(value: unknown, fallback = 0): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
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

export function ms(value: unknown): number {
  const parsed = Date.parse(str(value))
  return Number.isFinite(parsed) ? parsed : 0
}

export function isoOrNull(value: unknown): string | null {
  const parsed = ms(value)
  return parsed ? new Date(parsed).toISOString() : null
}

export function newest(...values: unknown[]): string | null {
  let best = 0
  for (const value of values) {
    const parsed = ms(value)
    if (parsed > best) best = parsed
  }
  return best ? new Date(best).toISOString() : null
}

export function clampPercent(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

export function daysBetween(from: number, to: number): number {
  return Math.floor((to - from) / 86_400_000)
}

/* ------------------------------------------------------------------ */
/* Algorithm family                                                    */
/* ------------------------------------------------------------------ */

/**
 * Classifies the algorithm FAMILY from a raw label.
 *
 * Matching is anchored on token boundaries. A loose substring match is what
 * previously let "OpenSSL" register as SSL and `TLS_AES_256_GCM_SHA384` register
 * as SHA-3, so every pattern here requires a real token break.
 */
export function algorithmFamily(raw: string): AlgorithmFamily {
  const text = ` ${String(raw || '').toUpperCase().replace(/[_+]/g, ' ')} `
  if (/\bML[-\s]?KEM\b|\bKYBER\b/.test(text)) return 'ml-kem'
  if (/\bML[-\s]?DSA\b|\bDILITHIUM\b/.test(text)) return 'ml-dsa'
  if (/\bSLH[-\s]?DSA\b|\bSPHINCS\b/.test(text)) return 'slh-dsa'
  if (/\bHYBRID\b|\bX25519[-\s]?ML[-\s]?KEM\b|\bSECP256R1MLKEM\b|\bX25519MLKEM\b/.test(text)) return 'hybrid'
  if (/\bMD5\b/.test(text)) return 'md5'
  if (/\bSHA[-\s]?1\b|\bSHA1\b/.test(text)) return 'sha1'
  if (/\bSHA[-\s]?3\b|\bSHA3-(224|256|384|512)\b|\bSHAKE(128|256)\b/.test(text)) return 'sha3'
  if (/\bSHA[-\s]?(224|256|384|512)\b|\bSHA2\b/.test(text)) return 'sha2'
  if (/\bRC4\b|\bARCFOUR\b/.test(text)) return 'rc4'
  if (/\b3DES\b|\bTRIPLE[-\s]?DES\b|\bDES[-\s]?EDE3\b/.test(text)) return '3des'
  if (/\bDES\b/.test(text)) return 'des'
  if (/\bAES\b/.test(text)) return 'aes'
  if (/\bCHACHA20?\b|\bPOLY1305\b/.test(text)) return 'chacha'
  if (/\bECDSA\b|\bED25519\b|\bED448\b/.test(text)) return 'ecdsa'
  if (/\bECDHE?\b|\bX25519\b|\bX448\b|\bSECP\d+R1\b|\bPRIME256V1\b|\bP-?(256|384|521)\b/.test(text)) return 'ecdh'
  if (/\bRSA\b/.test(text)) return 'rsa'
  if (/\bDHE?\b|\bDIFFIE\b/.test(text)) return 'dh'
  if (/\bDSA\b/.test(text)) return 'dsa'
  return 'unknown'
}

export const ALGORITHM_FAMILY_LABEL: Record<AlgorithmFamily, string> = {
  'ml-kem': 'ML-KEM (FIPS 203)',
  'ml-dsa': 'ML-DSA (FIPS 204)',
  'slh-dsa': 'SLH-DSA (FIPS 205)',
  hybrid: 'Hybrid (classical + PQC)',
  rsa: 'RSA',
  ecdsa: 'ECDSA / EdDSA',
  ecdh: 'ECDH / X25519',
  dh: 'Finite-field Diffie-Hellman',
  dsa: 'DSA',
  aes: 'AES',
  chacha: 'ChaCha20-Poly1305',
  '3des': 'Triple DES',
  des: 'DES',
  rc4: 'RC4',
  sha2: 'SHA-2',
  sha3: 'SHA-3',
  sha1: 'SHA-1',
  md5: 'MD5',
  unknown: 'Unclassified',
}

/** Asymmetric families whose key size is measured in modulus / curve bits. */
export const ASYMMETRIC_FAMILIES: AlgorithmFamily[] = ['rsa', 'dh', 'dsa', 'ecdsa', 'ecdh']

/** Families that provide post-quantum security on their own. */
export const PQC_FAMILIES: AlgorithmFamily[] = ['ml-kem', 'ml-dsa', 'slh-dsa']

/* ------------------------------------------------------------------ */
/* Internet exposure                                                   */
/* ------------------------------------------------------------------ */

export function assetIsInternetFacing(asset: Row | undefined): boolean {
  if (!asset) return false
  const environment = str(asset.environment).toLowerCase()
  if (['public', 'internet', 'dmz', 'external', 'edge'].some((token) => environment.includes(token))) return true
  const meta = recordOf(asset.metadata)
  if (meta.internet_facing === true || meta.public === true) return true
  const exposure = str(meta.exposure || meta.exposure_level).toLowerCase()
  if (/internet|public|external/.test(exposure)) return true
  const type = str(asset.type).toLowerCase()
  if (/web|domain|tls|endpoint|site|host|gateway|cdn|proxy|load|dns|ingress|api/.test(type)) return true
  const name = str(asset.name)
  if (/^https?:\/\//i.test(name) || /\.[a-z]{2,}(?::\d+)?$/i.test(name)) return true
  return false
}

/* ------------------------------------------------------------------ */
/* Subject construction                                                */
/* ------------------------------------------------------------------ */

export interface SubjectInputs {
  assets: Row[]
  cryptoInventory: Row[]
  certificates: Row[]
  generatedKeys: Row[]
  runtimeEvents: Row[]
  vaultFiles: Row[]
}

export interface SubjectSet {
  all: CryptoSubject[]
  components: CryptoSubject[]
  certificates: CryptoSubject[]
  keys: CryptoSubject[]
  transport: CryptoSubject[]
  objects: CryptoSubject[]
  assetById: Map<string, Row>
}

/**
 * Builds the normalised subject population once per model.
 *
 * Transport subjects are ONLY created from observations that actually recorded a
 * negotiated protocol or key exchange. An event with no transport measurement is
 * not a "TLS endpoint with unknown version" — it is not in the transport
 * population at all, which is what keeps the TLS controls from scoring silence.
 */
export function buildSubjects(inputs: SubjectInputs): SubjectSet {
  const assetById = new Map<string, Row>()
  for (const asset of inputs.assets) {
    const id = str(asset.id)
    if (id) assetById.set(id, asset)
  }

  const nameFor = (assetId: unknown, fallback: string) => {
    const asset = assetById.get(str(assetId))
    return str(asset?.name) || fallback
  }
  const envFor = (assetId: unknown, fallback = '') => {
    const asset = assetById.get(str(assetId))
    return str(asset?.environment) || fallback
  }
  const exposedFor = (assetId: unknown) => assetIsInternetFacing(assetById.get(str(assetId)))

  const components: CryptoSubject[] = inputs.cryptoInventory.map((row) => {
    const algorithm = str(row.algorithm)
    const protocol = str(row.protocol)
    return {
      id: `component:${str(row.id)}`,
      kind: 'component' as const,
      label: str(row.name) || algorithm || str(row.item_type) || 'Cryptographic component',
      algorithm,
      family: algorithmFamily(`${algorithm} ${protocol}`),
      posture: classifyAlgorithm(`${algorithm} ${protocol}`),
      keySize: num(row.key_size) || null,
      protocol,
      tlsVersion: '',
      keyExchange: '',
      assetId: str(row.asset_id) || null,
      assetName: nameFor(row.asset_id, 'Unmapped asset'),
      environment: envFor(row.asset_id),
      internetFacing: exposedFor(row.asset_id),
      observedAt: isoOrNull(row.discovered_at || row.created_at),
      source: { table: 'crypto_inventory', recordId: str(row.id) },
      href: '/dashboard/cbom-explorer',
      meta: {
        itemType: str(row.item_type),
        isVulnerable: row.is_vulnerable === true,
        isQuantumSafe: row.is_quantum_safe === true,
        exposureLevel: str(row.exposure_level),
      },
    }
  })

  const certificates: CryptoSubject[] = inputs.certificates.map((row) => {
    const algorithm = str(row.algorithm)
    return {
      id: `certificate:${str(row.id)}`,
      kind: 'certificate' as const,
      label: str(row.name) || str(row.subject) || 'Certificate',
      algorithm,
      family: algorithmFamily(algorithm),
      posture: classifyAlgorithm(algorithm),
      keySize: num(row.key_size) || null,
      protocol: 'x509',
      tlsVersion: '',
      keyExchange: '',
      assetId: str(row.asset_id) || null,
      assetName: nameFor(row.asset_id, str(row.subject) || 'Unmapped asset'),
      environment: envFor(row.asset_id),
      internetFacing: exposedFor(row.asset_id),
      observedAt: isoOrNull(row.updated_at || row.created_at),
      source: { table: 'certificates', recordId: str(row.id) },
      href: '/dashboard/pki-visibility',
      meta: {
        issuer: str(row.issuer),
        subject: str(row.subject),
        notAfter: isoOrNull(row.not_after),
        status: str(row.status),
        isQuantumSafe: row.is_quantum_safe === true,
        isExpiringSoon: row.is_expiring_soon === true,
      },
    }
  })

  const keys: CryptoSubject[] = inputs.generatedKeys.map((row) => {
    const algorithm = str(row.algorithm)
    const label = recordOf(row.label)
    return {
      id: `key:${str(row.id)}`,
      kind: 'key' as const,
      label: str(label.purpose) || str(label.common_name) || algorithm || 'Managed key',
      algorithm,
      family: algorithmFamily(algorithm),
      posture: classifyAlgorithm(algorithm),
      keySize: num(row.bit_length) || null,
      protocol: '',
      tlsVersion: '',
      keyExchange: '',
      assetId: null,
      assetName: 'Key management',
      environment: '',
      internetFacing: false,
      observedAt: isoOrNull(row.updated_at || row.created_at),
      source: { table: 'generated_keys', recordId: str(row.id) },
      href: '/dashboard/qkms/inventory',
      meta: {
        status: str(row.status),
        entropySource: str(row.entropy_source),
        qualityScore: num(row.quality_score) || null,
        expiresAt: isoOrNull(row.expires_at),
        revokedAt: isoOrNull(row.revoked_at),
        rotatedFrom: str(row.rotated_from),
        createdAt: isoOrNull(row.created_at),
      },
    }
  })

  const transport: CryptoSubject[] = []
  for (const row of inputs.runtimeEvents) {
    const tlsVersion = str(row.tls_version)
    const keyExchange = str(row.key_exchange_algorithm)
    const cipherSuite = str(row.cipher_suite)
    const protocol = str(row.protocol)
    const algorithm = str(row.algorithm) || keyExchange || cipherSuite
    const measuredTransport = Boolean(tlsVersion || keyExchange || cipherSuite)
    if (!measuredTransport) continue
    transport.push({
      id: `transport:${str(row.id)}`,
      kind: 'transport',
      label: str(row.asset_name) || str(row.host) || nameFor(row.asset_id, 'Observed endpoint'),
      algorithm,
      family: algorithmFamily(`${algorithm} ${cipherSuite} ${keyExchange}`),
      posture: classifyAlgorithm(`${algorithm} ${keyExchange} ${cipherSuite}`),
      keySize: num(row.key_size) || null,
      protocol,
      tlsVersion,
      keyExchange,
      assetId: str(row.asset_id) || null,
      assetName: str(row.asset_name) || nameFor(row.asset_id, str(row.host) || 'Observed endpoint'),
      environment: envFor(row.asset_id),
      internetFacing: exposedFor(row.asset_id) || /https|tls|443/i.test(`${protocol} ${str(row.host)}`),
      observedAt: isoOrNull(row.observed_at || row.created_at),
      source: { table: 'runtime_crypto_events', recordId: str(row.id) },
      href: '/dashboard/runtime-crypto-intel',
      meta: {
        cipherSuite,
        isPqc: row.is_pqc === true,
        isLegacy: row.is_legacy === true,
        downgradeDetected: row.downgrade_detected === true,
        shadowCrypto: row.shadow_crypto === true,
        hndlRisk: row.hndl_risk === true,
        operationType: str(row.operation_type),
        eventType: str(row.event_type),
        severity: str(row.severity),
        host: str(row.host),
      },
    })
  }

  const objects: CryptoSubject[] = inputs.vaultFiles
    .filter((row) => row.is_deleted !== true)
    .map((row) => {
      const algorithm = str(row.encryption_algorithm)
      return {
        id: `object:${str(row.id)}`,
        kind: 'object' as const,
        label: str(row.original_filename) || 'Stored object',
        algorithm,
        family: algorithmFamily(algorithm),
        posture: classifyAlgorithm(algorithm),
        keySize: null,
        protocol: '',
        tlsVersion: '',
        keyExchange: '',
        assetId: null,
        assetName: 'Quantum Vault',
        environment: '',
        internetFacing: false,
        observedAt: isoOrNull(row.updated_at || row.encrypted_at || row.uploaded_at || row.created_at),
        source: { table: 'vault_files', recordId: str(row.id) },
        href: '/dashboard/encryption-monitoring',
        meta: {
          encryptionStatus: str(row.encryption_status),
          signatureStatus: str(row.signature_status),
          keyRotationStatus: str(row.key_rotation_status),
          mimeType: str(row.mime_type),
          size: num(row.original_size) || null,
        },
      }
    })

  return {
    all: [...components, ...certificates, ...keys, ...transport, ...objects],
    components,
    certificates,
    keys,
    transport,
    objects,
    assetById,
  }
}
