/**
 * Agent request signing — application-layer integrity and replay protection
 * for every agent → control-plane request, above TLS.
 *
 * TLS protects the hop it terminates on. Enterprise networks routinely
 * terminate it early (TLS-inspection proxies trusted through a corporate CA),
 * and anything that can read that plaintext can read the agent's bearer token
 * too. A signature made with a key that never leaves the agent host is what
 * keeps such a party from altering telemetry or forging requests.
 *
 * Scheme `qgs1`:
 *   canonical = "QGUARD-AGENT-REQUEST-V1" \n METHOD \n /api/v1/... path+query \n
 *               agentId \n timestamp(ms) \n nonce \n SHA3-256(body bytes, hex)
 *   signed with Ed25519 always, and ML-DSA-65 (FIPS 204) as well when the
 *   runtime provides it — a hybrid signature, valid only if EVERY algorithm
 *   the control plane has bound for the agent verifies.
 *
 * Keys are generated on the agent host and bound to the agent on first use
 * (`scanner_agents.signing_public_keys`). From then on a request signed by any
 * other key, or missing a bound algorithm, is refused — so stripping the
 * ML-DSA half or the whole signature is a refusal, not a downgrade.
 *
 * Server- and agent-side only (node:crypto). Never import from browser code.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from 'node:crypto'

export const SIGNATURE_SCHEME = 'qgs1'
const CANONICAL_PREFIX = 'QGUARD-AGENT-REQUEST-V1'

export const SIGNING_ALGORITHMS = ['ed25519', 'ml-dsa-65'] as const
export type SigningAlgorithm = (typeof SIGNING_ALGORITHMS)[number]

/** Request headers. Public keys travel with every request so binding needs no extra round trip. */
export const SIGNATURE_HEADERS = {
  scheme: 'x-qguard-signature-scheme',
  timestamp: 'x-qguard-timestamp',
  nonce: 'x-qguard-nonce',
  contentDigest: 'x-qguard-content-sha3-256',
  signature: (alg: SigningAlgorithm) => `x-qguard-signature-${alg}`,
  publicKey: (alg: SigningAlgorithm) => `x-qguard-public-key-${alg}`,
} as const

/** Accepted distance between the agent's clock and the control plane's. */
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
/** A nonce must be remembered at least as long as its timestamp stays acceptable (both directions). */
export const NONCE_RETENTION_MS = 2 * MAX_CLOCK_SKEW_MS

const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/
const HEX_64 = /^[0-9a-f]{64}$/

export function sha3Hex(body: string | Uint8Array | null | undefined): string {
  return createHash('sha3-256').update(body ?? '').digest('hex')
}

/**
 * The part of the URL that is signed: from `/api/v1/` onward, query included.
 * A reverse proxy may prefix or strip a mount path in front of it; the API
 * path itself is what both ends agree on.
 */
export function signedPath(urlOrPath: string): string | null {
  const index = urlOrPath.indexOf('/api/v1/')
  return index === -1 ? null : urlOrPath.slice(index)
}

export interface CanonicalRequest {
  method: string
  path: string
  agentId: string
  timestamp: string
  nonce: string
  contentDigest: string
}

export function canonicalString(request: CanonicalRequest): string {
  return [CANONICAL_PREFIX, request.method.toUpperCase(), request.path, request.agentId, request.timestamp, request.nonce, request.contentDigest].join('\n')
}

/** Which algorithms this runtime can generate and verify. Ed25519 is in every supported Node; ML-DSA from 24.x. */
export function supportedAlgorithms(): SigningAlgorithm[] {
  const out: SigningAlgorithm[] = ['ed25519']
  try {
    generateKeyPairSync('ml-dsa-65' as never)
    out.push('ml-dsa-65')
  } catch {
    // Older OpenSSL / Node: hybrid signing unavailable, Ed25519 alone.
  }
  return out
}

/** SHA3-256 of the SPKI DER — the key's stable identity in logs, the database and the UI. */
export function keyFingerprint(publicKeyDer: Uint8Array): string {
  return createHash('sha3-256').update(publicKeyDer).digest('hex')
}

export interface AgentKeyPair {
  algorithm: SigningAlgorithm
  privateKey: KeyObject
  publicKeyDer: Buffer
}

export function generateAgentKeyPair(algorithm: SigningAlgorithm): AgentKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync(algorithm as never) as unknown as { privateKey: KeyObject; publicKey: KeyObject }
  return { algorithm, privateKey, publicKeyDer: publicKey.export({ type: 'spki', format: 'der' }) as Buffer }
}

/** Headers an agent attaches to one request. Only the exact bytes in `body` are covered. */
export function signRequest(input: {
  method: string
  url: string
  agentId: string
  body: string | null | undefined
  keys: AgentKeyPair[]
  now?: number
}): Record<string, string> {
  const path = signedPath(input.url)
  if (!path) throw new Error(`Refusing to sign a request outside /api/v1/: ${input.url}`)
  const canonical: CanonicalRequest = {
    method: input.method,
    path,
    agentId: input.agentId,
    timestamp: String(input.now ?? Date.now()),
    nonce: randomBytes(24).toString('base64url'),
    contentDigest: sha3Hex(input.body),
  }
  const message = Buffer.from(canonicalString(canonical), 'utf8')
  const headers: Record<string, string> = {
    [SIGNATURE_HEADERS.scheme]: SIGNATURE_SCHEME,
    [SIGNATURE_HEADERS.timestamp]: canonical.timestamp,
    [SIGNATURE_HEADERS.nonce]: canonical.nonce,
    [SIGNATURE_HEADERS.contentDigest]: canonical.contentDigest,
  }
  for (const key of input.keys) {
    headers[SIGNATURE_HEADERS.signature(key.algorithm)] = sign(null, message, key.privateKey).toString('base64')
    headers[SIGNATURE_HEADERS.publicKey(key.algorithm)] = key.publicKeyDer.toString('base64')
  }
  return headers
}

export type SignatureFailure =
  | 'unsigned'
  | 'unknown-scheme'
  | 'bad-timestamp'
  | 'stale'
  | 'bad-nonce'
  | 'replayed'
  | 'digest-mismatch'
  | 'path-mismatch'
  | 'bad-public-key'
  | 'bad-signature'
  | 'missing-bound-algorithm'
  | 'key-mismatch'

export const SIGNATURE_FAILURE_MESSAGE: Record<SignatureFailure, string> = {
  unsigned: 'Request is not signed.',
  'unknown-scheme': 'Unsupported request-signature scheme.',
  'bad-timestamp': 'Signature timestamp is missing or malformed.',
  stale: `Signature timestamp is outside the ±${MAX_CLOCK_SKEW_MS / 60000} minute window — check the host clock (NTP).`,
  'bad-nonce': 'Signature nonce is missing or malformed.',
  replayed: 'This signed request was already received (replay refused).',
  'digest-mismatch': 'Request body does not match its signed digest — it was altered in transit.',
  'path-mismatch': 'Request path does not match the signed path.',
  'bad-public-key': 'A signing public key is malformed.',
  'bad-signature': 'Request signature does not verify.',
  'missing-bound-algorithm': 'A signature algorithm bound to this agent is missing from the request (downgrade refused).',
  'key-mismatch': 'Request is signed by a key that is not bound to this agent.',
}

/** Public keys bound to an agent: algorithm → base64 SPKI DER. */
export type BoundKeys = Partial<Record<SigningAlgorithm, string>>

/*
 * A plain interface, NOT a discriminated union: under this project's
 * `strict: false` a union does not narrow on the `ok` literal (the same trap
 * agent-installer.ts's ControlPlaneGate documents). Success fields are set
 * when `ok`, `failure` when not.
 */
export interface VerificationResult {
  ok: boolean
  failure?: SignatureFailure
  /** The algorithm a failure concerns, when there is one. */
  algorithm?: SigningAlgorithm
  /** Algorithms whose signature verified, in canonical order. */
  algorithms?: SigningAlgorithm[]
  /** Keys presented and verified — what to bind when the agent has no binding yet. */
  presentedKeys?: BoundKeys
  fingerprints?: Partial<Record<SigningAlgorithm, string>>
  contentDigest?: string
  timestamp?: number
  nonce?: string
}

type HeaderBag = Record<string, string | string[] | undefined>

function header(headers: HeaderBag, name: string): string {
  const value = headers[name]
  return (Array.isArray(value) ? value[0] : value) || ''
}

/**
 * Verify one request. Pure apart from `nonceSeen`, which the caller backs with
 * its replay store. `bound` null means the agent has no binding yet: every
 * presented key must verify and the result's `presentedKeys` is what to bind.
 */
export function verifyRequest(input: {
  method: string
  originalUrl: string
  agentId: string
  headers: HeaderBag
  rawBody: Uint8Array | null | undefined
  bound: BoundKeys | null
  /** Algorithms this control plane can verify; others are ignored, never bound. */
  verifiable: SigningAlgorithm[]
  now?: number
  /** Returns true when the nonce was already seen for this agent; records it otherwise. */
  nonceSeen: (agentId: string, nonce: string, timestamp: number) => boolean
}): VerificationResult {
  const now = input.now ?? Date.now()
  const scheme = header(input.headers, SIGNATURE_HEADERS.scheme)
  if (!scheme) return { ok: false, failure: 'unsigned' }
  if (scheme !== SIGNATURE_SCHEME) return { ok: false, failure: 'unknown-scheme' }

  const timestampText = header(input.headers, SIGNATURE_HEADERS.timestamp)
  const timestamp = /^\d{13}$/.test(timestampText) ? Number(timestampText) : NaN
  if (!Number.isFinite(timestamp)) return { ok: false, failure: 'bad-timestamp' }
  if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) return { ok: false, failure: 'stale' }

  const nonce = header(input.headers, SIGNATURE_HEADERS.nonce)
  if (!NONCE_PATTERN.test(nonce)) return { ok: false, failure: 'bad-nonce' }

  const contentDigest = header(input.headers, SIGNATURE_HEADERS.contentDigest)
  if (!HEX_64.test(contentDigest) || contentDigest !== sha3Hex(input.rawBody)) return { ok: false, failure: 'digest-mismatch' }

  const path = signedPath(input.originalUrl)
  if (!path) return { ok: false, failure: 'path-mismatch' }

  const message = Buffer.from(canonicalString({ method: input.method, path, agentId: input.agentId, timestamp: timestampText, nonce, contentDigest }), 'utf8')
  const presentedKeys: BoundKeys = {}
  const fingerprints: Partial<Record<SigningAlgorithm, string>> = {}
  const algorithms: SigningAlgorithm[] = []

  for (const algorithm of SIGNING_ALGORITHMS) {
    const signature = header(input.headers, SIGNATURE_HEADERS.signature(algorithm))
    const publicKey = header(input.headers, SIGNATURE_HEADERS.publicKey(algorithm))
    const boundKey = input.bound?.[algorithm]
    if (!signature && !publicKey) {
      if (boundKey) return { ok: false, failure: 'missing-bound-algorithm', algorithm }
      continue
    }
    if (!input.verifiable.includes(algorithm)) {
      // Cannot be checked here; must never become part of a binding.
      if (boundKey) return { ok: false, failure: 'missing-bound-algorithm', algorithm }
      continue
    }
    if (boundKey && boundKey !== publicKey) return { ok: false, failure: 'key-mismatch', algorithm }
    let der: Buffer
    let key: KeyObject
    try {
      der = Buffer.from(publicKey, 'base64')
      key = createPublicKey({ key: der, format: 'der', type: 'spki' })
      if (key.asymmetricKeyType !== algorithm) return { ok: false, failure: 'bad-public-key', algorithm }
    } catch {
      return { ok: false, failure: 'bad-public-key', algorithm }
    }
    let valid = false
    try {
      valid = verify(null, message, key, Buffer.from(signature, 'base64'))
    } catch {
      valid = false
    }
    if (!valid) return { ok: false, failure: 'bad-signature', algorithm }
    presentedKeys[algorithm] = publicKey
    fingerprints[algorithm] = keyFingerprint(der)
    algorithms.push(algorithm)
  }

  // Ed25519 is the floor: an ML-DSA-only signature is never accepted on its own.
  if (!algorithms.includes('ed25519')) return { ok: false, failure: input.bound ? 'missing-bound-algorithm' : 'unsigned', algorithm: 'ed25519' }
  // Replay check last: a forged request must not be able to burn a legitimate nonce.
  if (input.nonceSeen(input.agentId, nonce, timestamp)) return { ok: false, failure: 'replayed' }

  return { ok: true, algorithms, presentedKeys, fingerprints, contentDigest, timestamp, nonce }
}

/**
 * In-process replay store: nonce per agent, kept for NONCE_RETENTION_MS,
 * bounded per agent so a flood cannot exhaust memory. Each API instance has its
 * own — see AGENT_SECURITY.md for the multi-instance trade-off.
 */
export function createNonceStore(maxPerAgent = 5000) {
  const seen = new Map<string, Map<string, number>>()
  return (agentId: string, nonce: string, timestamp: number): boolean => {
    const now = Date.now()
    let nonces = seen.get(agentId)
    if (!nonces) {
      nonces = new Map()
      seen.set(agentId, nonces)
    }
    for (const [value, at] of nonces) {
      if (now - at <= NONCE_RETENTION_MS && nonces.size <= maxPerAgent) break
      nonces.delete(value)
    }
    if (nonces.has(nonce)) return true
    nonces.set(nonce, Math.max(now, timestamp))
    return false
  }
}
