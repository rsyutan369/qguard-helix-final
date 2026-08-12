import { Router, Request, Response, NextFunction } from 'express'
import { randomBytes } from 'node:crypto'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server'
import { buildSnapshot } from './quantum-readiness'
import { buildReportModel } from '@/services/reporting/ReportEvidence'
import { brandingSchema } from '@/services/reporting/schemas/ReportSchema'
import type {
  CertificateAlgorithm,
  CertificateAsset,
  CertificationAdvisor,
  CertificationDashboard,
  CertificationLevel,
  CertificationPolicy,
  CertificateStatus,
  EligibilityCheck,
  EligibilityResult,
  PublicCertificateVerification,
  QuantumTrustCertificate,
} from '@/types/quantum-certification'
import { LEVEL_LABELS } from '@/types/quantum-certification'

/**
 * Quantum Trust Certification Engine™
 *
 * Issues, validates, monitors, renews, suspends and revokes evidence-driven
 * Post-Quantum Readiness certificates. Eligibility is COMPUTED from the live
 * Quantum Readiness snapshot (buildSnapshot) and the self-validated enterprise
 * report model (buildReportModel) — the same published criteria the Report
 * Center's Executive Certification Summary prints — extended with the
 * certification policy's algorithm/expiry/drift rules. A certificate is never
 * asserted: if any required check fails the engine returns remediation
 * recommendations instead of issuing.
 *
 * Integrity: each certificate persists its canonical JSON payload, its
 * SHA3-256 hash and an ML-DSA-65 (FIPS 204) signature from the platform
 * issuer key. The public verification endpoint recomputes the hash from the
 * stored canonical payload and verifies the signature live on every lookup —
 * tamper detection is structural, not a status flag.
 *
 * Tenant writes use the caller's JWT client so RLS remains the enforcement
 * point; only the issuer signing key and the public portal use the service
 * role.
 */

const router = Router()
export const certificateVerificationRouter = Router()

export const CERTIFICATION_ENGINE_VERSION = '1.0.0'
const ISSUER_NAME = 'QGuard Helix — Quantum Trust Certification Engine™'
const CERT_ID_PREFIX = 'QTH'
// The Quantum Trust Certificate table. NOTE: deliberately NOT `certificates` —
// that name is the platform's existing X.509/TLS certificate INVENTORY table
// (INVENTORY_CERT_TABLE), which this engine reads read-only for the expired-cert
// eligibility criterion. Keeping them separate prevents a schema collision and
// keeps issued trust certificates isolated from discovered X.509 certs.
const CERT_TABLE = 'quantum_trust_certificates'
const INVENTORY_CERT_TABLE = 'certificates'
const MONITOR_WRITE_INTERVAL_MS = 6 * 60 * 60 * 1000 // persist a validation row at most every 6h per cert
const EXPIRY_NOTICE_DAYS = 30

type AuthedRequest = Request & { user?: { id: string; email?: string | null }; token?: string }

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  // Header-only auth (Authorization: Bearer) — no query-string fallback; the
  // SSE stream is consumed via fetch()+ReadableStream, never EventSource.
  const token = getToken(req)
  if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } })
  const user = await getServerUser(token)
  if (!user) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token' } })
  ;(req as AuthedRequest).user = user
  ;(req as AuthedRequest).token = token
  next()
}
router.use(requireAuth)

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
function str(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value)
}
function num(value: unknown): number {
  const n = Number(value)
  return Number.isFinite(n) ? n : 0
}
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}
function clientIp(req: Request): string {
  const fwd = str(req.headers['x-forwarded-for']).split(',')[0].trim()
  return fwd || req.socket?.remoteAddress || ''
}

/** Deterministic JSON with sorted keys — the canonical form that gets hashed and signed. */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v)).join(',')}]`
  const rec = value as Record<string, unknown>
  const keys = Object.keys(rec).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(rec[k])}`).join(',')}}`
}
export function hashCanonical(payload: unknown): { canonical: string; hashHex: string; bytes: Uint8Array } {
  const canonical = canonicalize(payload)
  const bytes = new TextEncoder().encode(canonical)
  return { canonical, hashHex: toHex(sha3_256(bytes)), bytes }
}

/**
 * Offline-testable signing roundtrip helpers (used by tools/certification-check.ts).
 * A random ML-DSA-65 keypair is derived from a seed exactly as the live issuer key.
 */
export function testSignPayload(seedHex: string, payload: unknown): { hashHex: string; signatureHex: string; publicKeyHex: string } {
  const seed = fromHex(seedHex)
  const keys = ml_dsa65.keygen(seed)
  const { hashHex, bytes } = hashCanonical(payload)
  const signatureHex = toHex(ml_dsa65.sign(bytes, keys.secretKey))
  return { hashHex, signatureHex, publicKeyHex: toHex(keys.publicKey) }
}
export function testVerifyPayload(publicKeyHex: string, payload: unknown, signatureHex: string): { integrityOk: boolean; signatureOk: boolean; hashHex: string } {
  const { hashHex, bytes } = hashCanonical(payload)
  return { integrityOk: true, signatureOk: verifySignature(publicKeyHex, bytes, signatureHex), hashHex }
}

// Missing-table detection: before the schema SQL is applied every query fails
// with "relation ... does not exist" — surface schemaReady:false instead of 500s.
function isMissingTable(error: unknown): boolean {
  const message = str((error as { message?: string })?.message || error)
  return /relation .* does not exist|Could not find the table|schema cache/i.test(message)
}

// certificate_id collision: nextCertificateId() derives a sequential id from a
// row COUNT, which is not atomic under concurrent issuance (two requests can
// read the same count before either insert commits — a double-click on
// "Issue Certificate", or a renew racing a fresh issue). Detect the resulting
// unique-constraint violation so the caller can regenerate and retry instead
// of surfacing a raw Postgres error.
function isCertificateIdConflict(error: unknown): boolean {
  const code = str((error as { code?: string })?.code)
  const message = str((error as { message?: string })?.message || error)
  return code === '23505' || /duplicate key value violates unique constraint.*certificate_id/i.test(message)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function rows(client: any, table: string, build: (q: any) => any, onMissing?: () => void): Promise<Record<string, unknown>[]> {
  try {
    const { data, error } = await build(client.from(table))
    if (error) {
      if (isMissingTable(error)) onMissing?.()
      else console.warn(`quantum-certification ${table} query skipped:`, error.message || error)
      return []
    }
    return (data as Record<string, unknown>[]) || []
  } catch (error) {
    console.warn(`quantum-certification ${table} query failed:`, (error as Error)?.message || error)
    return []
  }
}

/* ------------------------------------------------------------------ */
/* Verification origin (mirrors ReportQr.verificationOrigin)           */
/* ------------------------------------------------------------------ */
function verificationOrigin(): string {
  const configured = process.env.CERT_VERIFICATION_ORIGIN || process.env.VITE_CERT_VERIFICATION_ORIGIN
  if (configured) return configured.replace(/\/+$/, '')
  return 'https://qguardhelix.com'
}
function verificationUrlFor(certificateId: string): string {
  return `${verificationOrigin()}/verify-certificate/${encodeURIComponent(certificateId)}`
}

/* ------------------------------------------------------------------ */
/* Issuer signing key (ML-DSA-65) — service-role-only table            */
/* ------------------------------------------------------------------ */
interface IssuerKey {
  keyId: string
  seed: Uint8Array
  publicKeyHex: string
}
let issuerKeyCache: IssuerKey | null = null

async function loadIssuerKey(): Promise<IssuerKey | null> {
  if (issuerKeyCache) return issuerKeyCache
  const service = getServiceClient()
  if (!service) return null
  try {
    const { data, error } = await service
      .from('certificate_signing_keys')
      .select('key_id, seed_hex, public_key_hex, active')
      .eq('active', true)
      .order('created_at', { ascending: true })
      .limit(1)
    if (error) {
      if (!isMissingTable(error)) console.warn('signing key load failed:', error.message)
      return null
    }
    if (data && data.length) {
      const row = data[0]
      issuerKeyCache = { keyId: str(row.key_id), seed: fromHex(str(row.seed_hex)), publicKeyHex: str(row.public_key_hex) }
      return issuerKeyCache
    }
    // First use: generate the platform issuer keypair and persist the seed.
    const seed = new Uint8Array(randomBytes(32))
    const keys = ml_dsa65.keygen(seed)
    const keyId = `qtc-issuer-${new Date().getFullYear()}-${toHex(new Uint8Array(randomBytes(4)))}`
    const publicKeyHex = toHex(keys.publicKey)
    const { error: insertError } = await service.from('certificate_signing_keys').insert({
      key_id: keyId,
      algorithm: 'ML-DSA-65',
      seed_hex: toHex(seed),
      public_key_hex: publicKeyHex,
      active: true,
    })
    if (insertError) {
      console.warn('signing key persist failed:', insertError.message)
      return null
    }
    issuerKeyCache = { keyId, seed, publicKeyHex }
    return issuerKeyCache
  } catch (error) {
    console.warn('signing key unavailable:', (error as Error)?.message || error)
    return null
  }
}

function signCanonical(key: IssuerKey, canonicalBytes: Uint8Array): string {
  const { secretKey } = ml_dsa65.keygen(key.seed)
  return toHex(ml_dsa65.sign(canonicalBytes, secretKey))
}
function verifySignature(publicKeyHex: string, canonicalBytes: Uint8Array, signatureHex: string): boolean {
  try {
    return ml_dsa65.verify(fromHex(signatureHex), canonicalBytes, fromHex(publicKeyHex))
  } catch {
    return false
  }
}

/* ------------------------------------------------------------------ */
/* Certification policy                                                */
/* ------------------------------------------------------------------ */
export const DEFAULT_POLICY: CertificationPolicy = {
  minReadiness: 90,
  maxCriticalFindings: 0,
  maxHndlRisk: 25,
  maxResidualRisk: 25, // "Low" band of levelFromRisk
  minConfidence: 95,
  minPqcAdoption: 85,
  maxVulnerableComponents: 0,
  maxExpiredCertificates: 0,
  disallowedAlgorithms: ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'SHA-1', 'SHA1', 'MD5', '3DES', 'DES', 'RC4', 'TLS 1.0', 'TLS1.0', 'TLS 1.1', 'TLS1.1'],
  validityDays: 365,
}

// Platform floors — tenants can tighten their policy, never loosen it below
// these published minimums (prevents self-certification by policy edit).
const POLICY_FLOORS: CertificationPolicy = { ...DEFAULT_POLICY }

function clampPolicy(raw: unknown): CertificationPolicy {
  const rec = (raw && typeof raw === 'object' ? raw : {}) as Partial<Record<keyof CertificationPolicy, unknown>>
  const pick = (key: keyof CertificationPolicy, floorIsMin: boolean): number => {
    const fallback = DEFAULT_POLICY[key] as number
    const value = num(rec[key] ?? fallback)
    const floor = POLICY_FLOORS[key] as number
    return floorIsMin ? Math.max(floor, value) : Math.min(floor, value)
  }
  return {
    minReadiness: pick('minReadiness', true),
    maxCriticalFindings: pick('maxCriticalFindings', false),
    maxHndlRisk: pick('maxHndlRisk', false),
    maxResidualRisk: pick('maxResidualRisk', false),
    minConfidence: pick('minConfidence', true),
    minPqcAdoption: pick('minPqcAdoption', true),
    maxVulnerableComponents: pick('maxVulnerableComponents', false),
    maxExpiredCertificates: pick('maxExpiredCertificates', false),
    disallowedAlgorithms: Array.from(new Set([...DEFAULT_POLICY.disallowedAlgorithms, ...(Array.isArray(rec.disallowedAlgorithms) ? rec.disallowedAlgorithms.map(str) : [])])),
    validityDays: Math.min(365, Math.max(30, num(rec.validityDays ?? DEFAULT_POLICY.validityDays))),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function loadPolicy(client: any, userId: string, missing: { schema: boolean }): Promise<CertificationPolicy> {
  const policyRows = await rows(client, 'certificate_policies', (q) => q.select('rules').eq('user_id', userId).limit(1), () => {
    missing.schema = true
  })
  return clampPolicy(policyRows[0]?.rules)
}

/* ------------------------------------------------------------------ */
/* Trust score + level engine                                          */
/* ------------------------------------------------------------------ */
type Snapshot = Awaited<ReturnType<typeof buildSnapshot>>

export function computeTrustScore(input: {
  readiness: number
  pqcAdoption: number
  quantumRisk: number
  hndlRisk: number
  confidence: number
  validationPass: boolean
  cryptoAgility: boolean
}): number {
  // Weighted 0–1000 Quantum Trust Score™: readiness 30%, PQC adoption 20%,
  // inverse quantum risk 15%, inverse HNDL 15%, evidence confidence 10%,
  // validation + crypto agility 10%.
  const parts =
    input.readiness * 3 +
    input.pqcAdoption * 2 +
    (100 - input.quantumRisk) * 1.5 +
    (100 - input.hndlRisk) * 1.5 +
    input.confidence * 1 +
    (input.validationPass ? 50 : 0) +
    (input.cryptoAgility ? 50 : 0)
  return Math.max(0, Math.min(1000, Math.round(parts)))
}

export function levelForScore(
  trustScore: number,
  context: { hybridImplemented: boolean; assessments: number; eligible: boolean; issuable: boolean },
): CertificationLevel | null {
  // Nothing is issued without measured evidence — a certificate over an empty
  // estate would attest to nothing.
  if (!context.issuable) return null

  // BRONZE is a baseline ATTESTATION, not a certification: it records the
  // posture that was actually measured (including unmet criteria) so a tenant
  // has a verifiable starting point on day one. It deliberately does not
  // require the certification criteria — `certified` stays false and the
  // artifact says so.
  if (!context.eligible) return 'bronze'

  // SILVER and above are CERTIFICATION grade: every required criterion must
  // pass, plus the weighted score band and hybrid-PQC production evidence.
  // Diamond additionally requires demonstrated continuous assessment.
  if (trustScore >= 950 && context.hybridImplemented && context.assessments >= 3) return 'diamond'
  if (trustScore >= 900 && context.hybridImplemented) return 'platinum'
  if (trustScore >= 800 && context.hybridImplemented) return 'gold'
  if (trustScore >= 700 && context.hybridImplemented) return 'silver'
  return 'bronze'
}

/* ------------------------------------------------------------------ */
/* Eligibility rules engine                                            */
/* ------------------------------------------------------------------ */
export interface EvidenceBundle {
  snapshot: Snapshot
  report: ReturnType<typeof buildReportModel>
  expiredCertificates: number
  cryptoStack: CertificateAlgorithm[]
  certifiedAssets: CertificateAsset[]
  disallowedHits: string[]
  assessments: number
  latestAssessmentId: string
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function gatherEvidence(client: any, token: string, userId: string): Promise<EvidenceBundle> {
  const snapshot = await buildSnapshot(token, userId)
  const report = buildReportModel(snapshot, brandingSchema.parse({}), 'executive', ISSUER_NAME)

  // Expired X.509/TLS certificates in the tenant inventory. This reads the
  // platform's existing `certificates` INVENTORY table (columns not_before/
  // not_after/…) — NOT the Quantum Trust Certificate table (CERT_TABLE). A cert
  // is expired when its not_after is in the past.
  const nowIso = new Date().toISOString()
  let expiredCertificates = 0
  try {
    const { count, error } = await client
      .from(INVENTORY_CERT_TABLE)
      .select('id', { count: 'exact', head: true })
      .eq('user_id', userId)
      .lt('not_after', nowIso)
    if (!error && typeof count === 'number') expiredCertificates = count
  } catch {
    /* certificate inventory table optional */
  }

  // Verified cryptographic stack — only algorithms observed in the tenant's
  // crypto inventory (is_quantum_safe / hybrid markers), grouped by category.
  const inventory = await rows(client, 'crypto_inventory', (q) =>
    q.select('algorithm, key_size, protocol, item_type, name, is_quantum_safe, is_vulnerable').eq('user_id', userId).limit(1000),
  )
  const cryptoStack = deriveCryptoStack(inventory)
  const disallowedHits = deriveDisallowedHits(inventory, snapshot)

  // Certified assets from the exposure graph (same per-asset posture model the
  // Quantum Exposure Graph™ renders).
  const certifiedAssets: CertificateAsset[] = (snapshot.exposureGraph?.nodes || [])
    .map((node) => ({
      name: str(node.label),
      type: str(node.type) || 'asset',
      environment: str(node.environment) || 'unknown',
      posture: str(node.posture) || 'unknown',
      riskScore: num(node.riskScore),
      internetFacing: Boolean(node.internetFacing),
    }))
    .slice(0, 200)

  const sessions = await rows(client, 'pqc_scan_sessions', (q) =>
    q.select('id, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(10),
  )

  return {
    snapshot,
    report,
    expiredCertificates,
    cryptoStack,
    certifiedAssets,
    disallowedHits,
    assessments: Math.max(sessions.length, num(snapshot.telemetry?.scanSessions)),
    latestAssessmentId: str(sessions[0]?.id),
  }
}

/**
 * Canonical quantum-safe algorithm catalog, ordered MOST SPECIFIC FIRST — the
 * first match wins and an algorithm lands in exactly one category. Previously
 * every pattern was tested against every row, so "ML-DSA/SLH-DSA/Falcon"
 * printed twice (once as a FIPS 204 signature, once as a FIPS 205 stateless
 * signature) from a single observation.
 *
 * Patterns are anchored on token boundaries. The loose `/SHA3/` used before
 * matched the substring inside "SHA384", which is why the TLS 1.3 cipher suite
 * TLS_AES_256_GCM_SHA384 was certified as a "FIPS 202 hash".
 */
const STACK_CATEGORIES: Array<{ category: string; standard: string; match: RegExp }> = [
  // Hybrid key establishment before plain ML-KEM so the hybrid name is kept.
  { category: 'Hybrid Key Establishment', standard: 'FIPS 203 + RFC 7748', match: /X25519[\s+_-]*ML[\s_-]*KEM|ML[\s_-]*KEM[\s+_-]*X25519|SECP256R1MLKEM|X25519KYBER/i },
  { category: 'Key Establishment', standard: 'FIPS 203', match: /\bML[\s_-]*KEM\b|\bKYBER\b/i },
  // ML-DSA before SLH-DSA: a combined library string such as
  // "ML-DSA/SLH-DSA/Falcon" should report its primary, general-purpose
  // signature scheme. A bare "SLH-DSA" does not match the ML-DSA pattern, so
  // stateless signatures are still categorised correctly on their own.
  { category: 'Digital Signatures', standard: 'FIPS 204', match: /\bML[\s_-]*DSA\b|\bDILITHIUM\b/i },
  { category: 'Stateless Signatures', standard: 'FIPS 205', match: /\bSLH[\s_-]*DSA\b|\bSPHINCS\b/i },
  { category: 'Digital Signatures', standard: 'FIPS 206 (draft)', match: /\bFALCON\b|\bFN[\s_-]*DSA\b/i },
  // TLS 1.3 suites are cipher suites, not bare primitives — name them as such.
  { category: 'TLS 1.3 Cipher Suite', standard: 'RFC 8446', match: /^TLS_(AES|CHACHA20)/i },
  { category: 'Symmetric Encryption', standard: 'FIPS 197 / SP 800-38D', match: /\bAES[\s_-]?256\b|\bAES[\s_-]?256[\s_-]?GCM\b/i },
  { category: 'Hashing', standard: 'FIPS 202', match: /\bSHA[\s_-]?3\b|\bSHA3-(224|256|384|512)\b|\bSHAKE(128|256)\b/i },
  { category: 'Hashing', standard: 'FIPS 180-4', match: /\bSHA[\s_-]?(256|384|512)\b/i },
  { category: 'Key Derivation', standard: 'SP 800-56C', match: /\bHKDF\b/i },
]

/**
 * Strings the scanner writes into `crypto_inventory.algorithm` that are NOT
 * algorithms — finding titles, gap descriptions and posture verdicts such as
 * "No Hybrid TLS", "Missing Crypto Agility", "HNDL Risk: HIGH".
 *
 * These must never reach the certificate. "No Hybrid TLS" previously passed the
 * quantum-safe test purely because it contains the substring "Hybrid", so a
 * finding stating the estate has NO hybrid TLS was printed on the certificate
 * as verified hybrid-TLS evidence — the exact inverse of the truth.
 */
const NON_ALGORITHM = /^(no|missing|weak|deprecated|expired|unsupported|insecure|classical|wide|long-term|legacy)\b|\b(gap|deadline|risk:|grade\s+[a-f]\b|attack surface|disclosure|not\s+\S+-signed|below\b|detected|strategy|compliance|policy|stapling|pinning|enabled|available)\b/i

/** Trailing annotations the scanner appends; the standard is added separately. */
const ALGORITHM_NOISE = /\s*\((?:FIPS[^)]*|Certificate|Signature|Key Exchange|\d+-bit)\)\s*$/i

function normalizeAlgorithmName(raw: string): string {
  return raw.replace(ALGORITHM_NOISE, '').replace(/\s+/g, ' ').trim()
}

/**
 * The certificate's "Verified Quantum Algorithm Stack" — quantum-safe
 * primitives ACTUALLY observed in the tenant's cryptographic inventory.
 *
 * Two independent conditions must hold, so neither a mislabelled row nor a
 * pattern false-positive alone can put an entry on a signed certificate:
 *   1. the scanner flagged the row `is_quantum_safe = true`, and
 *   2. the name matches the canonical catalog above.
 */
export function deriveCryptoStack(inventory: Record<string, unknown>[]): CertificateAlgorithm[] {
  const seen = new Map<string, CertificateAlgorithm & { instances: number; protocols: Set<string> }>()

  for (const row of inventory) {
    // Condition 1: the inventory itself must assert quantum-safety. No name
    // heuristic may override this — that escape hatch is what admitted the
    // negative findings.
    if (row.is_quantum_safe !== true || row.is_vulnerable === true) continue

    const rawAlgorithm = str(row.algorithm).trim()
    if (!rawAlgorithm || NON_ALGORITHM.test(rawAlgorithm)) continue

    const algorithm = normalizeAlgorithmName(rawAlgorithm)
    if (!algorithm) continue

    // Condition 2: single-category assignment, most specific first.
    const spec = STACK_CATEGORIES.find((c) => c.match.test(algorithm))
    if (!spec) continue

    const key = `${spec.category}:${algorithm.toUpperCase()}`
    const existing = seen.get(key)
    const protocol = str(row.protocol).trim()
    if (existing) {
      existing.instances += 1
      if (protocol) existing.protocols.add(protocol)
      continue
    }
    seen.set(key, {
      category: spec.category,
      algorithm,
      standard: spec.standard,
      verified: true,
      evidence: '',
      instances: 1,
      protocols: new Set(protocol ? [protocol] : []),
    })
  }

  // Evidence names the real observation count and protocols — a reader can
  // check the claim against the CBOM instead of taking the badge on trust.
  return Array.from(seen.values())
    .sort((a, b) => b.instances - a.instances || a.category.localeCompare(b.category))
    .slice(0, 24)
    .map(({ instances, protocols, ...entry }) => ({
      ...entry,
      evidence: `Observed ${instances}× in the cryptographic inventory${protocols.size ? ` over ${Array.from(protocols).sort().join(', ')}` : ''}`,
    }))
}

function deriveDisallowedHits(inventory: Record<string, unknown>[], snapshot: Snapshot): string[] {
  const hits = new Set<string>()
  const disallowed = DEFAULT_POLICY.disallowedAlgorithms
  const scan = (text: string, context: string) => {
    const upper = text.toUpperCase()
    for (const bad of disallowed) {
      const token = bad.toUpperCase()
      // Word-ish boundary so "RSA" doesn't match inside e.g. "PARSA".
      const re = new RegExp(`(^|[^A-Z0-9])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^A-Z0-9]|$)`)
      if (re.test(upper)) hits.add(`${bad} (${context})`)
    }
  }
  for (const row of inventory) {
    if (row.is_vulnerable === true || row.is_quantum_safe !== true) {
      const label = `${str(row.algorithm)} ${str(row.protocol)}`.trim()
      if (label) scan(label, str(row.component) || 'crypto inventory')
    }
  }
  for (const finding of snapshot.criticalFindings || []) {
    scan(`${str(finding.algorithm)} ${str(finding.title)}`, str(finding.asset) || 'scan finding')
  }
  return Array.from(hits).slice(0, 20)
}

export function evaluateEligibility(evidence: EvidenceBundle, policy: CertificationPolicy): EligibilityResult {
  const { snapshot, report } = evidence
  const s = snapshot.scores
  const confidence = num(report.confidenceSummary?.assessmentConfidencePct)
  const residualRisk = num(report.riskForecast?.residualRisk)
  const residualLevel = str(report.certification?.residualRiskLevel) || (residualRisk <= 25 ? 'Low' : 'Elevated')
  const validationPass = report.reportValidation?.overall === 'PASS'
  const critical = num(snapshot.riskDistribution?.critical)
  const hybridImplemented = num(snapshot.inventory?.hybridAssets) > 0 || evidence.cryptoStack.some((a) => /hybrid|\+/i.test(a.algorithm))
  const cryptoAgility = Boolean(report.cryptoPolicy?.activeProfile)

  // ---- Shared Responsibility adjustment --------------------------------
  // Certification must reward what the customer CAN control and never penalize
  // an organization because a provider or the wider ecosystem (Cloudflare, AWS,
  // browsers…) has not finished its own migration. We gate on customer-controlled
  // readiness and customer-attributable critical findings. Provider/ecosystem
  // critical counts from the ownership model are a LOWER bound (bounded sample),
  // so subtracting them yields a CONSERVATIVE (never under-penalizing) customer
  // critical count — certification integrity is preserved.
  const sr = snapshot.sharedResponsibility
  const customerReadiness = sr ? num(sr.readiness?.customer?.score) : s.quantumReadiness
  const provEcoCritical = sr ? num(sr.severityByDomain?.provider?.critical) + num(sr.severityByDomain?.ecosystem?.critical) : 0
  const customerCritical = Math.max(0, critical - provEcoCritical)
  const providerDependencyCount = sr ? num(sr.totals?.provider) + num(sr.totals?.ecosystem) : 0
  const waitingDependencyCount = sr ? num(sr.totals?.waiting) : 0

  const checks: EligibilityCheck[] = [
    {
      id: 'readiness',
      criterion: 'Customer-Controlled Quantum Readiness',
      required: `≥ ${policy.minReadiness}/100`,
      actual: `${customerReadiness}/100 (customer-controlled) · ${s.quantumReadiness}/100 overall`,
      met: customerReadiness >= policy.minReadiness,
      severity: 'required',
      evidence: 'Shared Responsibility model — customer-controlled readiness (provider/ecosystem lag excluded)',
      remediation: 'Complete the customer-controlled migration waves (origin TLS, internal PKI, key management, applications). Provider/ecosystem dependencies do not block certification.',
    },
    {
      id: 'critical-vulns',
      criterion: 'Critical Customer-Controlled Vulnerabilities',
      required: `≤ ${policy.maxCriticalFindings}`,
      actual: `${customerCritical} customer-controlled critical finding(s)${provEcoCritical > 0 ? ` (${provEcoCritical} provider/ecosystem critical(s) excluded)` : ''}`,
      met: customerCritical <= policy.maxCriticalFindings,
      severity: 'required',
      evidence: 'PQC scan findings + Shared Responsibility ownership classification',
      remediation: 'Remediate every customer-controlled critical finding in Quantum Risk Analysis, then re-scan. Provider/ecosystem criticals are tracked but not penalized.',
    },
    {
      id: 'hndl',
      criterion: 'Harvest-Now-Decrypt-Later Exposure',
      required: `≤ ${policy.maxHndlRisk}/100`,
      actual: `${s.hndlRisk}/100 (${s.hndlRiskLevel})`,
      met: s.hndlRisk <= policy.maxHndlRisk,
      severity: 'required',
      evidence: 'HNDL Assessment (harvest-now intelligence)',
      remediation: 'Move long-lived sensitive data flows to hybrid PQC transport and enable perfect forward secrecy — see the Harvest Now remediation center.',
    },
    {
      id: 'residual-risk',
      criterion: 'Residual Risk',
      required: `Low (≤ ${policy.maxResidualRisk}/100)`,
      actual: `${residualRisk}/100 (${residualLevel})`,
      met: residualRisk <= policy.maxResidualRisk,
      severity: 'required',
      evidence: 'Enterprise report risk forecast (post-programme)',
      remediation: 'Complete the remaining migration waves; residual risk is recomputed from measured wave outcomes.',
    },
    {
      id: 'confidence',
      criterion: 'Assessment Confidence',
      required: `≥ ${policy.minConfidence}%`,
      actual: `${confidence}%`,
      met: confidence >= policy.minConfidence,
      severity: 'required',
      evidence: 'Evidence-confidence model (per-source coverage)',
      remediation: 'Connect the missing evidence sources (runtime telemetry, key inventory, cloud connectors) so the assessment covers the full estate.',
    },
    {
      id: 'pqc-adoption',
      criterion: 'PQC Adoption',
      required: `≥ ${policy.minPqcAdoption}%`,
      actual: `${s.pqcAdoption}%`,
      met: s.pqcAdoption >= policy.minPqcAdoption,
      severity: 'required',
      evidence: 'CBOM component posture (quantum-safe / hybrid share)',
      remediation: 'Migrate remaining classical components to ML-KEM / ML-DSA / hybrid suites per the Migration Planner.',
    },
    {
      id: 'disallowed-algorithms',
      criterion: 'Disallowed Legacy Algorithms',
      required: 'None (RSA, ECC, SHA-1, 3DES, TLS 1.0/1.1 disallowed)',
      actual: evidence.disallowedHits.length ? `${evidence.disallowedHits.length} hit(s): ${evidence.disallowedHits.slice(0, 3).join('; ')}${evidence.disallowedHits.length > 3 ? '…' : ''}` : 'None detected',
      met: evidence.disallowedHits.length === 0,
      severity: 'required',
      evidence: 'Cryptographic inventory + scan findings algorithm scan',
      remediation: 'Retire every disallowed algorithm; replace legacy RSA/ECC key exchange and signatures with hybrid PQC equivalents.',
    },
    {
      id: 'vulnerable-components',
      criterion: 'Quantum-Vulnerable Components',
      required: `≤ ${policy.maxVulnerableComponents}`,
      actual: `${num(snapshot.inventory?.vulnerableComponents)} component(s)`,
      met: num(snapshot.inventory?.vulnerableComponents) <= policy.maxVulnerableComponents,
      severity: 'required',
      evidence: 'CBOM (cryptographic bill of materials)',
      remediation: 'Track component-level remediation in the CBOM Explorer until no vulnerable components remain.',
    },
    {
      id: 'expired-certificates',
      criterion: 'Expired Certificates',
      required: `≤ ${policy.maxExpiredCertificates}`,
      actual: `${evidence.expiredCertificates} expired`,
      met: evidence.expiredCertificates <= policy.maxExpiredCertificates,
      severity: 'required',
      evidence: 'Certificate inventory (not_after)',
      remediation: 'Renew or retire expired certificates; enable managed rotation in PKI Visibility.',
    },
    {
      id: 'validation',
      criterion: 'Report Self-Validation',
      required: 'PASS',
      actual: str(report.reportValidation?.overall) || 'UNAVAILABLE',
      met: validationPass,
      severity: 'required',
      evidence: 'Enterprise report validation engine (cross-section consistency)',
      remediation: 'Regenerate the assessment; validation failures indicate inconsistent or incomplete evidence.',
    },
    {
      id: 'crypto-agility',
      criterion: 'Crypto Agility',
      required: 'Policy-driven algorithm profile active',
      actual: cryptoAgility ? `Enabled (${str(report.cryptoPolicy?.activeProfile)})` : 'Not configured',
      met: cryptoAgility,
      severity: 'advisory',
      evidence: 'Crypto policy engine (active profile)',
      remediation: 'Activate a crypto policy profile so algorithms are swappable without per-system code changes.',
    },
    {
      id: 'shared-responsibility',
      criterion: 'Provider / Ecosystem Dependencies (non-blocking)',
      required: 'Tracked — does not block certification',
      actual: `${providerDependencyCount} provider/ecosystem finding(s), ${waitingDependencyCount} waiting on an upstream roadmap`,
      met: true,
      severity: 'advisory',
      evidence: 'Shared Responsibility Migration Intelligence™ ownership model',
      remediation: 'Monitor provider and ecosystem post-quantum roadmaps in Migration Intelligence™. These are recorded for transparency but never penalize your certification.',
    },
  ]

  const required = checks.filter((c) => c.severity === 'required')
  const requiredMet = required.filter((c) => c.met).length
  const eligible = snapshot.hasData && requiredMet === required.length

  /* Issuance floor for the Bronze baseline attestation. Deliberately minimal —
     it asks only "did we actually measure this estate?", not "is it safe". An
     assessment must have run and produced at least one assessed asset or
     catalogued crypto component, otherwise the certificate would attest to an
     empty scan. This floor is NOT policy-configurable: loosening it would
     allow an attestation over no evidence at all. */
  const measuredAssets = num(snapshot.inventory?.assetsAssessed)
  const measuredComponents = num(snapshot.inventory?.cryptoComponents)
  const issuable = Boolean(snapshot.hasData) && measuredAssets + measuredComponents > 0

  const trustScore = computeTrustScore({
    // Customer-controlled readiness drives the trust score so provider/ecosystem
    // lag never suppresses an organization's certification standing.
    readiness: customerReadiness,
    pqcAdoption: s.pqcAdoption,
    quantumRisk: s.quantumRisk,
    hndlRisk: s.hndlRisk,
    confidence,
    validationPass,
    cryptoAgility,
  })
  const level = levelForScore(trustScore, { hybridImplemented, assessments: evidence.assessments, eligible, issuable })

  const recommendations = checks
    .filter((c) => !c.met)
    .map((c) => ({
      title: `Resolve: ${c.criterion}`,
      detail: `${c.remediation} (required ${c.required}, currently ${c.actual})`,
      severity: c.severity === 'required' ? 'critical' : 'medium',
      route: c.id === 'hndl' ? '/dashboard/harvest-now' : c.id === 'vulnerable-components' ? '/dashboard/cbom' : c.id === 'expired-certificates' ? '/dashboard/pki-visibility' : '/dashboard/quantum-readiness/risk-analysis',
    }))

  return {
    eligible,
    issuable,
    evaluatedAt: new Date().toISOString(),
    hasData: Boolean(snapshot.hasData),
    requiredTotal: required.length,
    requiredMet,
    trustScore,
    level,
    levelLabel: level ? LEVEL_LABELS[level] : 'Awaiting Assessment',
    checks,
    recommendations,
    policy,
  }
}

/* ------------------------------------------------------------------ */
/* Scope derivation (evidence-verified areas only)                     */
/* ------------------------------------------------------------------ */
/**
 * Scope lines carry the measured COUNT that justified each entry, so a reader
 * can reconcile the certificate against the CBOM rather than trust a bare
 * label. A domain is only in scope because N of them were actually scanned.
 */
function deriveScope(snapshot: Snapshot): string[] {
  const inv = snapshot.inventory
  const internetFacing = (snapshot.exposureGraph?.nodes || []).filter((n) => n.internetFacing).length
  const scope: string[] = []
  const add = (label: string, count: number, unit: string) => {
    if (count > 0) scope.push(`${label} (${count} ${unit}${count === 1 ? '' : 's'})`)
  }
  add('Internet-Facing Assets', internetFacing, 'asset')
  add('PKI & Certificate Infrastructure', num(inv?.certificatesAnalyzed), 'certificate')
  add('TLS / Transport Security', num(inv?.domainsScanned), 'endpoint')
  add('Cloud & Infrastructure', num(inv?.cloudAccounts), 'account')
  add('Identity & Access Management', num(inv?.identitiesAnalyzed), 'identity')
  add('Cryptographic Inventory (CBOM)', num(inv?.cryptoComponents), 'component')
  add('Key Management Systems', num(inv?.keysDiscovered), 'key')
  add('Application & API Security', num(inv?.assetsAssessed), 'asset')
  return scope
}

/* ------------------------------------------------------------------ */
/* Certificate id + row mapping                                        */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function nextCertificateId(client: any, attempt = 0): Promise<string> {
  const year = new Date().getFullYear()
  let count = 0
  try {
    const { count: c } = await client.from(CERT_TABLE).select('id', { count: 'exact', head: true })
    count = typeof c === 'number' ? c : 0
  } catch {
    /* fall through to random suffix */
  }
  // The count-then-insert sequence below is not atomic, so a retry after a
  // unique-constraint collision (see isCertificateIdConflict) must not just
  // recompute the same count-derived id — that would collide again. From
  // attempt 1 onward, widen the id with a short random tag so it cannot match
  // the id that just won the race.
  const sequence = String(count + 1).padStart(6, '0')
  const suffix = attempt > 0 ? `-${Math.random().toString(36).slice(2, 6)}` : ''
  return `${CERT_ID_PREFIX}-${year}-${sequence}${suffix}`
}

function mapCertificateRow(row: Record<string, unknown>, extras?: { signature?: Record<string, unknown> | null; algorithms?: Record<string, unknown>[]; assets?: Record<string, unknown>[] }): QuantumTrustCertificate {
  const level = str(row.level) as CertificationLevel
  /* Read from the SIGNED canonical payload, not a mutable column — the
     certified/baseline distinction must be the one the signature covers.
     Certificates issued before this field existed are Silver+ only (Bronze was
     unreachable without full eligibility), so absence means certified. */
  const payload = (row.payload && typeof row.payload === 'object' ? row.payload : {}) as Record<string, unknown>
  // Legacy certificates predate this field. All of them required full
  // eligibility to be issued at all, so their absence means certified.
  const certified = payload.certified === undefined ? true : payload.certified === true
  return {
    certificateId: str(row.certificate_id),
    organization: str(row.organization),
    organizationLogo: row.organization_logo ? str(row.organization_logo) : null,
    status: str(row.status) as CertificateStatus,
    level,
    levelLabel: LEVEL_LABELS[level] || str(row.level),
    certified,
    criteriaMet: num(payload.criteriaMet),
    criteriaTotal: num(payload.criteriaTotal) || 10,
    trustScore: num(row.trust_score),
    overallReadiness: num(row.overall_readiness),
    quantumRisk: num(row.quantum_risk),
    hndlRisk: num(row.hndl_risk),
    residualRisk: num(row.residual_risk),
    residualRiskLevel: str(row.residual_risk_level),
    assessmentConfidence: num(row.assessment_confidence),
    pqcAdoption: num(row.pqc_adoption),
    issuedAt: str(row.issued_at),
    expiresAt: str(row.expires_at),
    assessmentId: str(row.assessment_id),
    assessmentVersion: str(row.assessment_version),
    scope: Array.isArray(row.scope) ? (row.scope as string[]).map(str) : [],
    cryptoStack: (extras?.algorithms || []).map((a) => ({
      category: str(a.category),
      algorithm: str(a.algorithm),
      standard: str(a.standard),
      verified: a.verified !== false,
      evidence: str(a.evidence),
    })),
    certifiedAssets: (extras?.assets || []).map((a) => ({
      name: str(a.asset_name),
      type: str(a.asset_type),
      environment: str(a.environment),
      posture: str(a.posture),
      riskScore: num(a.risk_score),
      internetFacing: a.internet_facing === true,
    })),
    certificateHash: str(row.certificate_hash),
    verificationUrl: str(row.verification_url) || verificationUrlFor(str(row.certificate_id)),
    signature: extras?.signature
      ? {
          algorithm: str(extras.signature.algorithm),
          signatureHex: str(extras.signature.signature_hex),
          publicKeyHex: str(extras.signature.public_key_hex),
          keyId: str(extras.signature.key_id),
          certificateHash: str(extras.signature.certificate_hash),
          signedAt: str(extras.signature.signed_at),
          chain: Array.isArray(extras.signature.chain) ? (extras.signature.chain as CertificateSignatureChain[]) : [],
        }
      : null,
    renewedFrom: row.renewed_from ? str(row.renewed_from) : null,
    suspendedReason: row.suspended_reason ? str(row.suspended_reason) : null,
    revokedReason: row.revoked_reason ? str(row.revoked_reason) : null,
    lastValidatedAt: row.last_validated_at ? str(row.last_validated_at) : null,
  }
}
type CertificateSignatureChain = { role: string; name: string; algorithm: string }

/* ------------------------------------------------------------------ */
/* Audit + history writers (auth-scoped client → RLS enforced)         */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeAudit(client: any, userId: string, args: { certificateId?: string; action: string; detail: string; actorEmail?: string; ip?: string }) {
  try {
    await client.from('certificate_audit').insert({
      user_id: userId,
      certificate_id: args.certificateId || null,
      action: args.action,
      detail: args.detail.slice(0, 2000),
      actor_email: args.actorEmail || '',
      ip_address: args.ip || '',
    })
  } catch {
    /* audit best-effort; never blocks the action */
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeHistory(client: any, userId: string, certificateId: string, event: string, detail: string, actor: string) {
  try {
    await client.from('certificate_history').insert({ user_id: userId, certificate_id: certificateId, event, detail: detail.slice(0, 2000), actor })
  } catch {
    /* history best-effort */
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function writeNotification(client: any, userId: string, certificateId: string, kind: string, message: string) {
  try {
    await client.from('certificate_notifications').insert({ user_id: userId, certificate_id: certificateId, kind, message: message.slice(0, 1000) })
  } catch {
    /* notification best-effort */
  }
}

/* ------------------------------------------------------------------ */
/* Continuous monitoring — re-validate the active certificate          */
/* ------------------------------------------------------------------ */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function monitorCertificate(client: any, userId: string, cert: Record<string, unknown>, eligibility: EligibilityResult, actorEmail: string) {
  const certificateId = str(cert.certificate_id)
  const status = str(cert.status)
  const now = Date.now()

  // Lazy expiry.
  if ((status === 'active' || status === 'suspended') && new Date(str(cert.expires_at)).getTime() < now) {
    await client.from(CERT_TABLE).update({ status: 'expired' }).eq('certificate_id', certificateId).eq('user_id', userId)
    await writeHistory(client, userId, certificateId, 'expired', 'Certificate passed its expiration date.', 'system')
    await writeNotification(client, userId, certificateId, 'expired', `Certificate ${certificateId} has expired. Run a reassessment to renew.`)
    cert.status = 'expired'
    return
  }
  if (status !== 'active') return

  // Expiring-soon notification (once).
  const daysLeft = Math.ceil((new Date(str(cert.expires_at)).getTime() - now) / 86400000)
  if (daysLeft <= EXPIRY_NOTICE_DAYS && daysLeft > 0) {
    const existing = await rows(client, 'certificate_notifications', (q) =>
      q.select('id').eq('user_id', userId).eq('certificate_id', certificateId).eq('kind', 'expiring_soon').limit(1),
    )
    if (!existing.length) {
      await writeNotification(client, userId, certificateId, 'expiring_soon', `Certificate ${certificateId} expires in ${daysLeft} day(s). Schedule a reassessment to renew.`)
    }
  }

  // Drift: the live estate no longer meets the published criteria → suspend.
  if (eligibility.hasData && !eligibility.eligible) {
    const failed = eligibility.checks.filter((c) => c.severity === 'required' && !c.met).map((c) => c.criterion)
    const reason = `Continuous monitoring detected drift — failed criteria: ${failed.join(', ')}`
    await client
      .from(CERT_TABLE)
      .update({ status: 'suspended', suspended_reason: reason.slice(0, 1000), last_validated_at: new Date().toISOString() })
      .eq('certificate_id', certificateId)
      .eq('user_id', userId)
    await writeHistory(client, userId, certificateId, 'suspended', reason, 'system')
    await writeNotification(client, userId, certificateId, 'drift_detected', `Certificate ${certificateId} suspended: ${reason}. Remediate and re-validate to reinstate.`)
    await writeAudit(client, userId, { certificateId, action: 'suspended', detail: reason, actorEmail })
    cert.status = 'suspended'
    cert.suspended_reason = reason
    return
  }

  // Healthy: refresh last_validated_at + persist a validation row (throttled).
  const lastValidated = cert.last_validated_at ? new Date(str(cert.last_validated_at)).getTime() : 0
  if (now - lastValidated > MONITOR_WRITE_INTERVAL_MS) {
    const validatedAt = new Date().toISOString()
    await client.from(CERT_TABLE).update({ last_validated_at: validatedAt }).eq('certificate_id', certificateId).eq('user_id', userId)
    try {
      await client.from('certificate_validation').insert({
        user_id: userId,
        certificate_id: certificateId,
        eligible: eligibility.eligible,
        trust_score: eligibility.trustScore,
        level: eligibility.level,
        required_met: eligibility.requiredMet,
        required_total: eligibility.requiredTotal,
        checks: eligibility.checks,
        trigger: 'monitoring',
      })
      await writeHistory(client, userId, certificateId, 'validated', `Continuous monitoring re-validated the certificate (${eligibility.requiredMet}/${eligibility.requiredTotal} criteria, trust score ${eligibility.trustScore}/1000).`, 'system')
    } catch {
      /* validation record best-effort */
    }
    cert.last_validated_at = validatedAt
  }
}

/* ------------------------------------------------------------------ */
/* AI advisor explanation (deterministic, evidence-grounded)           */
/* ------------------------------------------------------------------ */
function buildAdvisor(eligibility: EligibilityResult, certificate: QuantumTrustCertificate | null, report: ReturnType<typeof buildReportModel>): CertificationAdvisor {
  if (!eligibility.hasData) {
    return {
      headline: 'No assessment evidence yet',
      verdict: 'no_evidence',
      explanation: ['No discovery scan has produced certifiable evidence for this tenant. Certification eligibility is computed from measured evidence, never asserted.'],
      businessImpact: [],
      nextSteps: [
        { title: 'Run a PQC discovery scan', detail: 'Populate the Quantum Readiness Assessment Engine™ with real cryptographic evidence.', route: '/dashboard/scanner' },
      ],
    }
  }
  const failed = eligibility.checks.filter((c) => c.severity === 'required' && !c.met)
  const passed = eligibility.checks.filter((c) => c.met)
  const roi = report.roiAnalysis
  const businessImpact: string[] = []
  if (certificate?.status === 'active') {
    businessImpact.push(`An active ${certificate.levelLabel} certificate (trust score ${certificate.trustScore}/1000) provides publicly verifiable, evidence-based proof of post-quantum readiness for customers, auditors and regulators.`)
  }
  for (const risk of (report.executiveBlock?.topBusinessRisks || []).slice(0, 3)) {
    if (risk.risk) businessImpact.push(`Risk surface under certification scope: ${risk.risk} (${risk.level}).`)
  }
  if (roi && num(roi.roiMultiple) > 0) {
    businessImpact.push(`The underlying migration programme carries a ${roi.roiMultiple}× expected return; certification converts that investment into demonstrable market trust.`)
  }

  if (eligibility.eligible) {
    return {
      headline: certificate?.status === 'active' ? `Certified — ${eligibility.levelLabel}` : `Eligible for ${eligibility.levelLabel} certification`,
      verdict: certificate?.status === 'active' ? 'certified' : 'eligible',
      explanation: [
        `All ${eligibility.requiredTotal} required criteria are met by measured evidence (${passed.length}/${eligibility.checks.length} total checks passing).`,
        `The weighted Quantum Trust Score™ is ${eligibility.trustScore}/1000, which maps to the ${(eligibility.level || 'bronze').toUpperCase()} level (${eligibility.levelLabel}).`,
        'Certification remains subject to continuous monitoring: every new assessment automatically re-validates the certificate and suspends it if drift is detected.',
      ],
      businessImpact,
      nextSteps: certificate?.status === 'active'
        ? [
            { title: 'Share the verification URL', detail: 'Customers and auditors can verify the certificate integrity and signature live on the public portal.', route: '/dashboard/quantum-certification' },
            { title: 'Maintain continuous evidence', detail: 'Keep scans and telemetry current so monitoring re-validation continues to pass.', route: '/dashboard/scanner' },
          ]
        : [
            { title: 'Issue the certificate', detail: 'Generate, sign and publish the Quantum Trust Certificate™ from the current evidence.', route: '/dashboard/quantum-certification' },
          ],
    }
  }
  // Baseline path: evidence exists but certification criteria are unmet. The
  // tenant CAN issue a Bronze attestation of measured posture today, and the
  // copy must be explicit that it is not a quantum-secure certification.
  if (eligibility.issuable) {
    return {
      headline: certificate?.status === 'active'
        ? `Baseline attested — ${eligibility.levelLabel}`
        : `Ready to issue your Initial Readiness attestation (Bronze)`,
      verdict: certificate?.status === 'active' ? 'eligible' : 'not_eligible',
      explanation: [
        `${eligibility.requiredMet}/${eligibility.requiredTotal} certification criteria pass, so a Bronze Initial Readiness attestation can be issued now. It records the posture actually measured — it does NOT assert the estate is quantum-safe.`,
        `Full certification (Silver and above) remains blocked by: ${failed.map((c) => c.criterion).join(', ')}.`,
        ...failed.slice(0, 3).map((c) => `${c.criterion}: required ${c.required}, measured ${c.actual} — ${c.remediation}`),
        `Weighted Quantum Trust Score™ is ${eligibility.trustScore}/1000. Silver needs ≥700 plus hybrid PQC evidence and every required criterion met.`,
      ],
      businessImpact,
      nextSteps: certificate?.status === 'active'
        ? [
            { title: 'Close the certification gaps', detail: `Resolve the ${failed.length} unmet criteri${failed.length === 1 ? 'on' : 'a'} to upgrade from baseline attestation to Silver certification.`, route: '/dashboard/quantum-readiness/risk-analysis' },
            { title: 'Keep evidence current', detail: 'Continuous monitoring re-validates the attestation on every assessment.', route: '/dashboard/scanner' },
          ]
        : [
            { title: 'Issue your Initial Readiness attestation', detail: 'Generate a signed, publicly verifiable record of your measured baseline — your starting point for the migration programme.', route: '/dashboard/quantum-certification' },
            { title: 'Then close the gaps', detail: `${failed.length} criteri${failed.length === 1 ? 'on' : 'a'} stand between you and Silver certification.`, route: '/dashboard/quantum-readiness/risk-analysis' },
          ],
    }
  }

  return {
    headline: 'No assessment evidence yet — run a discovery scan',
    verdict: 'no_evidence',
    explanation: [
      'A certificate attests to measured evidence. No assessed assets or catalogued cryptographic components exist for this tenant yet, so there is nothing to attest to.',
      'Run a discovery scan; once any asset or crypto component is measured you can issue a Bronze Initial Readiness attestation immediately.',
    ],
    businessImpact,
    nextSteps: eligibility.recommendations.slice(0, 4).map((r) => ({ title: r.title, detail: r.detail, route: r.route })),
  }
}

/* ------------------------------------------------------------------ */
/* Dashboard payload assembly                                          */
/* ------------------------------------------------------------------ */
export async function buildCertificationDashboard(token: string, userId: string, actorEmail: string): Promise<CertificationDashboard> {
  const client = createAuthClient(token)
  if (!client) throw new Error('Supabase unavailable')
  const missing = { schema: false }

  const policy = await loadPolicy(client, userId, missing)
  const evidence = await gatherEvidence(client, token, userId)
  const eligibility = evaluateEligibility(evidence, policy)

  const certRows = await rows(
    client,
    CERT_TABLE,
    (q) => q.select('*').eq('user_id', userId).order('issued_at', { ascending: false }).limit(25),
    () => {
      missing.schema = true
    },
  )

  // Continuous monitoring on the latest non-superseded certificate.
  const latest = certRows.find((c) => str(c.status) !== 'superseded') || null
  if (latest) await monitorCertificate(client, userId, latest, eligibility, actorEmail)

  const latestId = latest ? str(latest.certificate_id) : ''
  const [signatureRows, algorithmRows, assetRows, historyRows, notificationRows, downloadRows, validationRows] = await Promise.all([
    latestId ? rows(client, 'certificate_signatures', (q) => q.select('*').eq('user_id', userId).eq('certificate_id', latestId).limit(1)) : Promise.resolve([]),
    latestId ? rows(client, 'certificate_algorithms', (q) => q.select('*').eq('user_id', userId).eq('certificate_id', latestId).limit(50)) : Promise.resolve([]),
    latestId ? rows(client, 'certificate_assets', (q) => q.select('*').eq('user_id', userId).eq('certificate_id', latestId).limit(200)) : Promise.resolve([]),
    rows(client, 'certificate_history', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(40)),
    rows(client, 'certificate_notifications', (q) => q.select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(20)),
    rows(client, 'certificate_downloads', (q) => q.select('certificate_id, format, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(20)),
    rows(client, 'certificate_validation', (q) => q.select('trust_score, eligible, created_at').eq('user_id', userId).order('created_at', { ascending: true }).limit(60)),
  ])

  // Verification activity for this tenant's certificates (service role — the
  // logs table is portal-written and not tenant-readable via RLS).
  const service = getServiceClient()
  let verificationActivity: CertificationDashboard['verificationActivity'] = []
  if (service && certRows.length) {
    const ids = certRows.map((c) => str(c.certificate_id))
    const logs = await rows(service, 'certificate_verification_logs', (q) => q.select('certificate_id, result, lookup_by, created_at').in('certificate_id', ids).order('created_at', { ascending: false }).limit(20))
    verificationActivity = logs.map((l) => ({ certificateId: str(l.certificate_id), result: str(l.result), lookupBy: str(l.lookup_by), createdAt: str(l.created_at) }))
  }

  const certificate = latest ? mapCertificateRow(latest, { signature: (signatureRows[0] as Record<string, unknown>) || null, algorithms: algorithmRows, assets: assetRows }) : null
  const advisor = buildAdvisor(eligibility, certificate, evidence.report)

  const trend = validationRows.map((v) => ({
    label: new Date(str(v.created_at)).toLocaleDateString('en-US', { month: 'short', day: '2-digit' }),
    trustScore: num(v.trust_score),
    readiness: Math.round(num(v.trust_score) / 10),
  }))
  if (!trend.length && eligibility.hasData) {
    trend.push({ label: 'Now', trustScore: eligibility.trustScore, readiness: evidence.snapshot.scores.quantumReadiness })
  }

  const expiresAt = certificate && (certificate.status === 'active' || certificate.status === 'suspended') ? certificate.expiresAt : null
  const daysRemaining = expiresAt ? Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86400000)) : null

  const issuerKey = await loadIssuerKey()

  return {
    generatedAt: new Date().toISOString(),
    hasData: eligibility.hasData,
    eligibility,
    certificate,
    certificates: certRows.map((c) => mapCertificateRow(c)),
    history: historyRows.map((h) => ({ id: str(h.id), certificateId: str(h.certificate_id), event: str(h.event), detail: str(h.detail), actor: str(h.actor), createdAt: str(h.created_at) })),
    notifications: notificationRows.map((n) => ({ id: str(n.id), certificateId: str(n.certificate_id), kind: str(n.kind), message: str(n.message), read: n.read === true, createdAt: str(n.created_at) })),
    verificationActivity,
    downloads: downloadRows.map((d) => ({ certificateId: str(d.certificate_id), format: str(d.format), createdAt: str(d.created_at) })),
    trend,
    renewal: { expiresAt, daysRemaining, autoRenewEligible: Boolean(certificate && eligibility.eligible) },
    advisor,
    issuer: issuerKey ? { name: ISSUER_NAME, keyId: issuerKey.keyId, algorithm: 'ML-DSA-65 (FIPS 204)', publicKeyHex: issuerKey.publicKeyHex } : null,
    schemaReady: !missing.schema,
  }
}

/* ------------------------------------------------------------------ */
/* Issuance                                                            */
/* ------------------------------------------------------------------ */
type IssueSuccess = { ok: true; certificate: QuantumTrustCertificate }
type IssueFailure = { ok: false; status: number; code: string; message: string; eligibility?: EligibilityResult }
type IssueResult = IssueSuccess | IssueFailure
function isIssueFailure(result: IssueResult): result is IssueFailure {
  return !result.ok
}

async function issueCertificate(args: {
  token: string
  userId: string
  actorEmail: string
  ip: string
  organization: string
  organizationLogo: string | null
  renewedFrom?: string | null
}): Promise<IssueResult> {
  const client = createAuthClient(args.token)
  if (!client) return { ok: false, status: 500, code: 'SUPABASE_UNAVAILABLE', message: 'Data layer unavailable' }
  const missing = { schema: false }

  /* Stage timings. Issuance is the engine's slowest call — a full evidence
     rebuild, ML-DSA-65 signing and eight writes — and the first call after a
     server restart also pays for cold module compilation. When a tenant reports
     a slow or stuck "Issuing…", these lines name the stage instead of leaving
     it to guesswork. */
  const t0 = Date.now()
  let last = t0
  const stages: string[] = []
  const mark = (stage: string) => {
    const now = Date.now()
    stages.push(`${stage}=${now - last}ms`)
    last = now
  }

  const policy = await loadPolicy(client, args.userId, missing)
  mark('policy')
  const evidence = await gatherEvidence(client, args.token, args.userId)
  mark('evidence')
  const eligibility = evaluateEligibility(evidence, policy)
  mark('eligibility')

  // Persist the eligibility run (issue trigger) — best effort.
  try {
    await client.from('certificate_validation').insert({
      user_id: args.userId,
      certificate_id: null,
      eligible: eligibility.eligible,
      trust_score: eligibility.trustScore,
      level: eligibility.level,
      required_met: eligibility.requiredMet,
      required_total: eligibility.requiredTotal,
      checks: eligibility.checks,
      trigger: args.renewedFrom ? 'renewal' : 'issue',
    })
  } catch (error) {
    if (isMissingTable(error)) missing.schema = true
  }

  if (missing.schema) {
    return { ok: false, status: 503, code: 'SCHEMA_NOT_APPLIED', message: 'Certification tables missing — run supabase/quantum-certification-schema.sql in the Supabase SQL Editor.' }
  }
  // Only the evidence FLOOR gates issuance. A tenant that fails certification
  // criteria still receives a Bronze baseline attestation stating its measured
  // posture and its unmet criteria — it simply is not marked `certified`.
  if (!eligibility.issuable) {
    return {
      ok: false,
      status: 422,
      code: 'NO_EVIDENCE',
      message: 'No assessment evidence yet — run a discovery scan first. A certificate cannot attest to an unmeasured estate.',
      eligibility,
    }
  }

  const issuerKey = await loadIssuerKey()
  if (!issuerKey) return { ok: false, status: 503, code: 'SIGNING_KEY_UNAVAILABLE', message: 'Issuer signing key unavailable — apply the schema and retry.' }
  mark('issuer-key')

  const level = eligibility.level || 'bronze'
  const issuedAt = new Date()
  const expiresAt = new Date(issuedAt.getTime() + policy.validityDays * 86400000)
  const s = evidence.snapshot.scores
  const confidence = num(evidence.report.confidenceSummary?.assessmentConfidencePct)
  const residualRisk = num(evidence.report.riskForecast?.residualRisk)
  const scope = deriveScope(evidence.snapshot)
  const residualLevel = str(evidence.report.certification?.residualRiskLevel) || (residualRisk <= 25 ? 'Low' : 'Elevated')

  // certificate_id is derived from a row COUNT (nextCertificateId), which is
  // not atomic under concurrent issuance — two requests can read the same
  // count before either insert commits (a double-click on "Issue
  // Certificate", or a renewal racing a fresh issue) and generate the same
  // id, which the database then rejects on the certificate_id UNIQUE
  // constraint. Retry with a freshly regenerated (and, from attempt 1,
  // entropy-widened) id + re-signed payload rather than surfacing that as a
  // failure — the id is embedded in the signed payload, so a retry cannot
  // reuse the previous hash/signature.
  let certificateId = ''
  let verificationUrl = ''
  let canonicalPayload: Record<string, unknown> = {}
  let hashHex = ''
  let signatureHex = ''
  const MAX_ID_ATTEMPTS = 5
  for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt++) {
    certificateId = await nextCertificateId(client, attempt)
    verificationUrl = verificationUrlFor(certificateId)

    // Canonical signed payload — the integrity source of truth.
    canonicalPayload = {
      certificateId,
      organization: args.organization,
      level,
      /* Inside the signed payload so the distinction is tamper-evident: a Bronze
         baseline cannot be edited into a certification claim without breaking
         the ML-DSA-65 signature the public portal verifies. */
      certified: eligibility.eligible,
      criteriaMet: eligibility.requiredMet,
      criteriaTotal: eligibility.requiredTotal,
      trustScore: eligibility.trustScore,
      overallReadiness: s.quantumReadiness,
      quantumRisk: s.quantumRisk,
      hndlRisk: s.hndlRisk,
      residualRisk,
      assessmentConfidence: confidence,
      pqcAdoption: s.pqcAdoption,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      assessmentId: evidence.latestAssessmentId,
      assessmentVersion: `QTC-${CERTIFICATION_ENGINE_VERSION}`,
      scope,
      cryptoStack: evidence.cryptoStack.map((a) => ({ category: a.category, algorithm: a.algorithm, standard: a.standard })),
      certifiedAssetCount: evidence.certifiedAssets.length,
      issuer: ISSUER_NAME,
      verificationUrl,
    }
    const { canonical, hashHex: h, bytes } = hashCanonical(canonicalPayload)
    hashHex = h
    signatureHex = signCanonical(issuerKey, bytes)
    void canonical

    const { error: insertError } = await client.from(CERT_TABLE).insert({
      user_id: args.userId,
      certificate_id: certificateId,
      organization: args.organization,
      organization_logo: args.organizationLogo,
      status: 'active',
      level,
      trust_score: eligibility.trustScore,
      overall_readiness: s.quantumReadiness,
      quantum_risk: s.quantumRisk,
      hndl_risk: s.hndlRisk,
      residual_risk: residualRisk,
      residual_risk_level: residualLevel,
      assessment_confidence: confidence,
      pqc_adoption: s.pqcAdoption,
      assessment_id: evidence.latestAssessmentId,
      assessment_version: `QTC-${CERTIFICATION_ENGINE_VERSION}`,
      scope,
      payload: canonicalPayload,
      certificate_hash: hashHex,
      verification_url: verificationUrl,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      renewed_from: args.renewedFrom || null,
      last_validated_at: issuedAt.toISOString(),
    })
    if (!insertError) break
    if (isMissingTable(insertError)) return { ok: false, status: 503, code: 'SCHEMA_NOT_APPLIED', message: 'Certification tables missing — run supabase/quantum-certification-schema.sql.' }
    if (!isCertificateIdConflict(insertError) || attempt === MAX_ID_ATTEMPTS - 1) {
      return { ok: false, status: 500, code: 'ISSUE_FAILED', message: insertError.message }
    }
    console.warn(`[certification] certificate_id collision on ${certificateId}, retrying (attempt ${attempt + 1}/${MAX_ID_ATTEMPTS})`)
  }
  mark('sign')

  const chain = [
    { role: 'issuer', name: ISSUER_NAME, algorithm: 'ML-DSA-65 (FIPS 204)' },
    { role: 'platform', name: 'QGuard Helix™', algorithm: 'SHA3-256 integrity' },
  ]
  await client.from('certificate_signatures').insert({
    user_id: args.userId,
    certificate_id: certificateId,
    algorithm: 'ML-DSA-65',
    signature_hex: signatureHex,
    public_key_hex: issuerKey.publicKeyHex,
    key_id: issuerKey.keyId,
    certificate_hash: hashHex,
    signed_at: issuedAt.toISOString(),
    chain,
  })
  if (evidence.cryptoStack.length) {
    await client.from('certificate_algorithms').insert(
      evidence.cryptoStack.map((a) => ({ user_id: args.userId, certificate_id: certificateId, category: a.category, algorithm: a.algorithm, standard: a.standard, verified: a.verified, evidence: a.evidence })),
    )
  }
  if (evidence.certifiedAssets.length) {
    await client.from('certificate_assets').insert(
      evidence.certifiedAssets.map((a) => ({ user_id: args.userId, certificate_id: certificateId, asset_name: a.name, asset_type: a.type, environment: a.environment, posture: a.posture, risk_score: a.riskScore, internet_facing: a.internetFacing })),
    )
  }

  // Supersede the previous certificate on renewal.
  if (args.renewedFrom) {
    await client.from(CERT_TABLE).update({ status: 'superseded' }).eq('certificate_id', args.renewedFrom).eq('user_id', args.userId)
    await writeHistory(client, args.userId, args.renewedFrom, 'superseded', `Superseded by ${certificateId}.`, args.actorEmail)
  }

  const event = args.renewedFrom ? 'renewed' : 'issued'
  await writeHistory(client, args.userId, certificateId, event, `${event === 'renewed' ? 'Renewal' : 'Certificate'} issued at ${level.toUpperCase()} level (trust score ${eligibility.trustScore}/1000, ${eligibility.requiredMet}/${eligibility.requiredTotal} criteria).`, args.actorEmail)
  await writeAudit(client, args.userId, { certificateId, action: event, detail: `Level ${level}, trust score ${eligibility.trustScore}/1000, expires ${expiresAt.toISOString()}`, actorEmail: args.actorEmail, ip: args.ip })
  if (args.renewedFrom) await writeNotification(client, args.userId, certificateId, 'renewed', `Certificate renewed as ${certificateId} (${LEVEL_LABELS[level]}).`)

  mark('writes')

  // Read back in parallel — these four are independent, and running them
  // sequentially added four round-trips to the slowest call in the engine.
  const [certRow, sigRow, algoRows, assetRows] = await Promise.all([
    rows(client, CERT_TABLE, (q) => q.select('*').eq('user_id', args.userId).eq('certificate_id', certificateId).limit(1)),
    rows(client, 'certificate_signatures', (q) => q.select('*').eq('user_id', args.userId).eq('certificate_id', certificateId).limit(1)),
    rows(client, 'certificate_algorithms', (q) => q.select('*').eq('user_id', args.userId).eq('certificate_id', certificateId).limit(50)),
    rows(client, 'certificate_assets', (q) => q.select('*').eq('user_id', args.userId).eq('certificate_id', certificateId).limit(200)),
  ])
  mark('readback')
  console.info(`[certification] issued ${certificateId} (${level}) in ${Date.now() - t0}ms — ${stages.join(' ')}`)

  return { ok: true, certificate: mapCertificateRow(certRow[0] || {}, { signature: (sigRow[0] as Record<string, unknown>) || null, algorithms: algoRows, assets: assetRows }) }
}

/* ------------------------------------------------------------------ */
/* Routes — tenant (auth + basic tier via subscription gateway)        */
/* ------------------------------------------------------------------ */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const data = await buildCertificationDashboard(token!, user!.id, user!.email || '')
    res.json({ data })
  } catch (error) {
    console.error('quantum-certification dashboard failed:', error)
    res.status(500).json({ error: { code: 'CERTIFICATION_ERROR', message: 'Unable to build certification dashboard' } })
  }
})

router.get('/stream', async (req: Request, res: Response) => {
  const { token, user } = req as AuthedRequest
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })
  let closed = false
  const send = async () => {
    if (closed) return
    try {
      const data = await buildCertificationDashboard(token!, user!.id, user!.email || '')
      res.write(`event: certification-update\ndata: ${JSON.stringify(data)}\n\n`)
    } catch {
      res.write(`event: certification-error\ndata: {}\n\n`)
    }
  }
  await send()
  const interval = setInterval(send, 20000)
  const heartbeat = setInterval(() => {
    if (!closed) res.write(': keep-alive\n\n')
  }, 10000)
  req.on('close', () => {
    closed = true
    clearInterval(interval)
    clearInterval(heartbeat)
  })
})

router.post('/issue', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const organization = str(req.body?.organization).trim().slice(0, 160)
    const logo = str(req.body?.organizationLogo)
    if (!organization) return res.status(400).json({ error: { code: 'VALIDATION', message: 'organization is required' } })
    // Logo must be a bounded data URL (no external fetches, no oversized payloads).
    const organizationLogo = /^data:image\/(png|jpe?g|svg\+xml|webp);base64,/.test(logo) && logo.length <= 400_000 ? logo : null
    const result = await issueCertificate({ token: token!, userId: user!.id, actorEmail: user!.email || '', ip: clientIp(req), organization, organizationLogo })
    if (isIssueFailure(result)) return res.status(result.status).json({ error: { code: result.code, message: result.message, eligibility: result.eligibility } })
    res.status(201).json({ data: result.certificate })
  } catch (error) {
    console.error('certificate issue failed:', error)
    res.status(500).json({ error: { code: 'ISSUE_FAILED', message: 'Unable to issue certificate' } })
  }
})

router.post('/:certificateId/renew', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const certificateId = str(req.params.certificateId)
    const existing = await rows(client, CERT_TABLE, (q) => q.select('*').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(1))
    if (!existing.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
    const result = await issueCertificate({
      token: token!,
      userId: user!.id,
      actorEmail: user!.email || '',
      ip: clientIp(req),
      organization: str(existing[0].organization),
      organizationLogo: existing[0].organization_logo ? str(existing[0].organization_logo) : null,
      renewedFrom: certificateId,
    })
    if (isIssueFailure(result)) return res.status(result.status).json({ error: { code: result.code, message: result.message, eligibility: result.eligibility } })
    res.status(201).json({ data: result.certificate })
  } catch (error) {
    console.error('certificate renew failed:', error)
    res.status(500).json({ error: { code: 'RENEW_FAILED', message: 'Unable to renew certificate' } })
  }
})

async function transitionStatus(req: Request, res: Response, target: CertificateStatus, event: string, requireStatus?: CertificateStatus[]) {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const certificateId = str(req.params.certificateId)
    const reason = str(req.body?.reason).trim().slice(0, 1000) || `${event} by certificate owner`
    const existing = await rows(client, CERT_TABLE, (q) => q.select('certificate_id, status').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(1))
    if (!existing.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
    const current = str(existing[0].status) as CertificateStatus
    if (requireStatus && !requireStatus.includes(current)) {
      return res.status(409).json({ error: { code: 'INVALID_STATE', message: `Cannot ${event} a ${current} certificate` } })
    }
    const patch: Record<string, unknown> = { status: target }
    if (target === 'revoked') patch.revoked_reason = reason
    if (target === 'suspended') patch.suspended_reason = reason
    if (target === 'active') {
      // Reinstatement requires the estate to currently pass all criteria.
      const policy = await loadPolicy(client, user!.id, { schema: false })
      const evidence = await gatherEvidence(client, token!, user!.id)
      const eligibility = evaluateEligibility(evidence, policy)
      if (!eligibility.eligible) {
        return res.status(422).json({ error: { code: 'NOT_ELIGIBLE', message: 'Reinstatement blocked — current evidence fails required criteria. Remediate and re-validate.', eligibility } })
      }
      patch.suspended_reason = null
      patch.last_validated_at = new Date().toISOString()
    }
    const { error } = await client.from(CERT_TABLE).update(patch).eq('certificate_id', certificateId).eq('user_id', user!.id)
    if (error) return res.status(500).json({ error: { code: 'UPDATE_FAILED', message: error.message } })
    await writeHistory(client, user!.id, certificateId, event, reason, user!.email || 'owner')
    await writeAudit(client, user!.id, { certificateId, action: event, detail: reason, actorEmail: user!.email || '', ip: clientIp(req) })
    if (target === 'revoked') await writeNotification(client, user!.id, certificateId, 'revoked', `Certificate ${certificateId} was revoked: ${reason}`)
    if (target === 'suspended') await writeNotification(client, user!.id, certificateId, 'suspended', `Certificate ${certificateId} was suspended: ${reason}`)
    if (target === 'active') await writeNotification(client, user!.id, certificateId, 'reinstated', `Certificate ${certificateId} was reinstated after passing re-validation.`)
    res.json({ data: { certificateId, status: target } })
  } catch (error) {
    console.error(`certificate ${event} failed:`, error)
    res.status(500).json({ error: { code: 'TRANSITION_FAILED', message: `Unable to ${event} certificate` } })
  }
}

router.post('/:certificateId/suspend', (req, res) => transitionStatus(req, res, 'suspended', 'suspended', ['active']))
router.post('/:certificateId/revoke', (req, res) => transitionStatus(req, res, 'revoked', 'revoked', ['active', 'suspended']))
router.post('/:certificateId/reinstate', (req, res) => transitionStatus(req, res, 'active', 'reinstated', ['suspended']))

router.post('/:certificateId/download-event', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const certificateId = str(req.params.certificateId)
    const format = str(req.body?.format)
    if (!['pdf', 'png', 'svg', 'json', 'audit-package', 'executive-summary'].includes(format)) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'Invalid format' } })
    }
    const existing = await rows(client, CERT_TABLE, (q) => q.select('certificate_id').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(1))
    if (!existing.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
    await client.from('certificate_downloads').insert({ user_id: user!.id, certificate_id: certificateId, format })
    await writeHistory(client, user!.id, certificateId, 'downloaded', `Exported as ${format.toUpperCase()}.`, user!.email || 'owner')
    await writeAudit(client, user!.id, { certificateId, action: 'downloaded', detail: format, actorEmail: user!.email || '', ip: clientIp(req) })
    res.json({ data: { recorded: true } })
  } catch (error) {
    console.error('download event failed:', error)
    res.status(500).json({ error: { code: 'DOWNLOAD_LOG_FAILED', message: 'Unable to record download' } })
  }
})

/** Machine-readable certificate + audit package (JSON). */
router.get('/:certificateId/package', async (req: Request, res: Response) => {
  try {
    const { token, user } = req as AuthedRequest
    const client = createAuthClient(token!)
    const certificateId = str(req.params.certificateId)
    const certRow = await rows(client, CERT_TABLE, (q) => q.select('*').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(1))
    if (!certRow.length) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Certificate not found' } })
    const [sig, algos, assets, history, validations] = await Promise.all([
      rows(client, 'certificate_signatures', (q) => q.select('*').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(1)),
      rows(client, 'certificate_algorithms', (q) => q.select('*').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(50)),
      rows(client, 'certificate_assets', (q) => q.select('*').eq('user_id', user!.id).eq('certificate_id', certificateId).limit(200)),
      rows(client, 'certificate_history', (q) => q.select('event, detail, actor, created_at').eq('user_id', user!.id).eq('certificate_id', certificateId).order('created_at', { ascending: true }).limit(200)),
      rows(client, 'certificate_validation', (q) => q.select('eligible, trust_score, level, required_met, required_total, trigger, created_at').eq('user_id', user!.id).eq('certificate_id', certificateId).order('created_at', { ascending: true }).limit(100)),
    ])
    const certificate = mapCertificateRow(certRow[0], { signature: (sig[0] as Record<string, unknown>) || null, algorithms: algos, assets })
    res.json({
      data: {
        format: 'qguard-helix-quantum-trust-certificate/1.0',
        certificate,
        canonicalPayload: certRow[0].payload,
        lifecycle: history,
        validationHistory: validations,
        verification: {
          url: certificate.verificationUrl,
          instructions: 'Recompute SHA3-256 over the canonical payload (sorted-key JSON) — it must equal certificateHash. Verify the ML-DSA-65 signature over the same bytes with the issuer public key, or use the public verification portal.',
        },
      },
    })
  } catch (error) {
    console.error('certificate package failed:', error)
    res.status(500).json({ error: { code: 'PACKAGE_FAILED', message: 'Unable to build audit package' } })
  }
})

/* ------------------------------------------------------------------ */
/* Public verification portal (NO auth, rate-limited, service role)    */
/* ------------------------------------------------------------------ */
const RATE_LIMIT = { windowMs: 60_000, max: 30 }
const rateBuckets = new Map<string, { count: number; resetAt: number }>()
function rateLimited(ip: string): boolean {
  const now = Date.now()
  const bucket = rateBuckets.get(ip)
  if (!bucket || bucket.resetAt < now) {
    rateBuckets.set(ip, { count: 1, resetAt: now + RATE_LIMIT.windowMs })
    if (rateBuckets.size > 10_000) {
      for (const [key, value] of rateBuckets) if (value.resetAt < now) rateBuckets.delete(key)
    }
    return false
  }
  bucket.count += 1
  return bucket.count > RATE_LIMIT.max
}

function statusDetail(status: string, expiresAt: string): string {
  switch (status) {
    case 'active':
      return `Valid — continuously monitored; expires ${new Date(expiresAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}.`
    case 'suspended':
      return 'Suspended — continuous monitoring detected the estate no longer meets the published certification criteria.'
    case 'revoked':
      return 'Revoked — this certificate is no longer valid.'
    case 'expired':
      return 'Expired — a reassessment is required for renewal.'
    case 'superseded':
      return 'Superseded — a newer certificate has been issued for this organization.'
    default:
      return ''
  }
}

certificateVerificationRouter.get('/lookup', async (req: Request, res: Response) => {
  const ip = clientIp(req)
  if (rateLimited(ip)) return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many verification requests — retry in a minute' } })
  const service = getServiceClient()
  if (!service) return res.status(503).json({ error: { code: 'UNAVAILABLE', message: 'Verification service unavailable' } })
  const company = str(req.query.company).trim().slice(0, 120)
  if (!company) return res.status(400).json({ error: { code: 'VALIDATION', message: 'company query parameter required' } })
  const found = await rows(service, CERT_TABLE, (q) =>
    q
      .select('certificate_id, organization, status, level, trust_score, issued_at, expires_at')
      .ilike('organization', `%${company.replace(/[%_]/g, '')}%`)
      .neq('status', 'superseded')
      .order('issued_at', { ascending: false })
      .limit(10),
  )
  res.json({
    data: found.map((c) => ({
      certificateId: str(c.certificate_id),
      organization: str(c.organization),
      status: str(c.status),
      level: str(c.level),
      trustScore: num(c.trust_score),
      issuedAt: str(c.issued_at),
      expiresAt: str(c.expires_at),
    })),
  })
})

certificateVerificationRouter.get('/:certificateId', async (req: Request, res: Response) => {
  const ip = clientIp(req)
  if (rateLimited(ip)) return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many verification requests — retry in a minute' } })
  const service = getServiceClient()
  if (!service) return res.status(503).json({ error: { code: 'UNAVAILABLE', message: 'Verification service unavailable' } })
  const certificateId = str(req.params.certificateId).trim().slice(0, 40)
  const lookupBy = str(req.query.via) === 'qr' ? 'qr' : 'certificate_id'

  const found = await rows(service, CERT_TABLE, (q) => q.select('*').eq('certificate_id', certificateId).limit(1))
  const logVerification = async (result: string) => {
    try {
      await service.from('certificate_verification_logs').insert({
        certificate_id: certificateId,
        result,
        lookup_by: lookupBy,
        ip_address: ip,
        user_agent: str(req.headers['user-agent']).slice(0, 300),
      })
    } catch {
      /* log best-effort */
    }
  }

  if (!found.length) {
    await logVerification('not_found')
    const notFound: PublicCertificateVerification = {
      found: false,
      certificateId,
      organization: '',
      status: 'not_found',
      statusDetail: 'No certificate with this ID exists in the QGuard Helix registry.',
      level: null,
      levelLabel: '',
      certified: false,
      criteriaMet: 0,
      criteriaTotal: 0,
      trustScore: 0,
      overallReadiness: 0,
      pqcAdoption: 0,
      residualRiskLevel: '',
      issuedAt: null,
      expiresAt: null,
      assessmentVersion: '',
      certificateHash: '',
      signatureAlgorithm: '',
      signatureValid: null,
      integrityValid: null,
      lastValidatedAt: null,
      certifiedAlgorithms: [],
      verifiedAt: new Date().toISOString(),
    }
    return res.status(404).json({ data: notFound })
  }

  const cert = found[0]
  // Lazy expiry on public lookups too.
  let status = str(cert.status) as CertificateStatus
  if ((status === 'active' || status === 'suspended') && new Date(str(cert.expires_at)).getTime() < Date.now()) {
    status = 'expired'
    await service.from(CERT_TABLE).update({ status: 'expired' }).eq('certificate_id', certificateId)
  }

  // Structural integrity + live signature verification from the stored
  // canonical payload — tampering with any persisted field breaks one of them.
  const { hashHex, bytes } = hashCanonical(cert.payload || {})
  const integrityValid = hashHex === str(cert.certificate_hash)
  const sigRows = await rows(service, 'certificate_signatures', (q) => q.select('algorithm, signature_hex, public_key_hex').eq('certificate_id', certificateId).limit(1))
  const signatureValid = sigRows.length ? verifySignature(str(sigRows[0].public_key_hex), bytes, str(sigRows[0].signature_hex)) : null
  const algoRows = await rows(service, 'certificate_algorithms', (q) => q.select('category, algorithm, standard').eq('certificate_id', certificateId).limit(24))

  await logVerification(integrityValid && signatureValid !== false ? status : 'tampered')

  const level = str(cert.level) as CertificationLevel
  // Read the certified/baseline flag from the SIGNED payload verified above,
  // never from a mutable column — the public claim must be the signed one.
  const signedPayload = (cert.payload && typeof cert.payload === 'object' ? cert.payload : {}) as Record<string, unknown>
  const certified = signedPayload.certified === undefined ? true : signedPayload.certified === true
  const payload: PublicCertificateVerification = {
    found: true,
    certificateId,
    organization: str(cert.organization),
    status,
    statusDetail: integrityValid && signatureValid !== false ? statusDetail(status, str(cert.expires_at)) : 'INTEGRITY FAILURE — the stored certificate does not match its cryptographic hash/signature.',
    level,
    levelLabel: LEVEL_LABELS[level] || str(cert.level),
    certified,
    criteriaMet: num(signedPayload.criteriaMet),
    criteriaTotal: num(signedPayload.criteriaTotal) || 10,
    trustScore: num(cert.trust_score),
    overallReadiness: num(cert.overall_readiness),
    pqcAdoption: num(cert.pqc_adoption),
    residualRiskLevel: str(cert.residual_risk_level),
    issuedAt: str(cert.issued_at),
    expiresAt: str(cert.expires_at),
    assessmentVersion: str(cert.assessment_version),
    certificateHash: str(cert.certificate_hash),
    signatureAlgorithm: sigRows.length ? `${str(sigRows[0].algorithm)} (FIPS 204)` : 'ML-DSA-65 (FIPS 204)',
    signatureValid,
    integrityValid,
    lastValidatedAt: cert.last_validated_at ? str(cert.last_validated_at) : null,
    certifiedAlgorithms: algoRows.map((a) => ({ category: str(a.category), algorithm: str(a.algorithm), standard: str(a.standard) })),
    verifiedAt: new Date().toISOString(),
  }
  res.json({ data: payload })
})

export default router
