/**
 * Identity Discovery — structured extraction of identity infrastructure.
 *
 * ── Why this module exists ─────────────────────────────────────────────────
 * The scanner already probes `/.well-known/openid-configuration`,
 * `/.well-known/jwks.json` and the OAuth endpoints. But it converted everything
 * it found into flat finding strings:
 *
 *     "RSA RS256 (kid: abc123)"
 *
 * and threw the structure away — the issuer, the endpoints, the key ids, the
 * supported algorithms, the grant types, the response modes. Nothing downstream
 * could answer "which identity provider is this, and what signs its tokens?"
 *
 * So the PQAuth module had nothing structured to read and fell back to
 * regex-matching the text of every crypto row, which classified a TLS test
 * domain as an identity asset and invented a "Microsoft Entra ID" that the
 * tenant does not have.
 *
 * This module keeps the findings exactly as they are — they feed the CBOM
 * correctly — and additionally emits RECORDS: typed, stable-keyed, evidence-
 * bearing identity objects that PQAuth can build on.
 *
 * ── The rule that shapes every extractor below ─────────────────────────────
 * DISCOVERY REPORTS WHAT THE DOCUMENT SAYS. An OIDC discovery document that
 * advertises `RS256` tells us the provider SUPPORTS RS256, not that it USES it.
 * A JWKS key with `"use":"sig"` tells us the key signs. Anything not stated is
 * `null` — never inferred, never defaulted. Every record carries the URL it was
 * read from so a reviewer can verify it.
 *
 * ── Cryptographic accuracy (spec §29) ──────────────────────────────────────
 * JWT algorithms are SIGNATURE algorithms. RS256 migrates to ML-DSA, never to
 * ML-KEM. Key establishment (`*_encryption_alg_values_supported`) is where
 * ML-KEM applies. The two are tracked separately and are never conflated.
 *
 * Pure and dependency-free: no network, no database. The caller fetches; this
 * module parses. That makes it offline-testable
 * (`tools/identity-discovery-check.ts`).
 */

/* ================================================================== */
/* Vocabulary                                                          */
/* ================================================================== */

export type IdentityProtocol = 'oidc' | 'oauth2' | 'saml2'

export type IdentityKeyUse = 'signature' | 'encryption' | 'unspecified'

/** Post-quantum posture of an identity primitive. */
export type IdentityQuantumClass = 'safe' | 'hybrid' | 'vulnerable' | 'unknown'

/** What the algorithm is FOR — conflating these is the classic PQC error. */
export type CryptoPurpose = 'signature' | 'key-encapsulation' | 'symmetric' | 'hash' | 'unknown'

export interface AlgorithmClassification {
  algorithm: string
  purpose: CryptoPurpose
  quantumClass: IdentityQuantumClass
  /** The NIST replacement for THIS purpose. Never ML-KEM for a signature. */
  pqcTarget: string | null
  standard: string | null
  rationale: string
}

export interface DiscoveryEvidence {
  /** The exact URL the record was read from. */
  sourceUrl: string
  /** `oidc-discovery` | `jwks` | `oauth-as-metadata` | `saml-metadata` */
  method: string
  observedAt: string
  /** HTTP status of the probe, when the caller supplies it. */
  httpStatus: number | null
}

export interface IdentitySigningKey {
  /** Stable within a provider: the JWKS `kid`, or a derived fingerprint. */
  keyId: string
  /** JWK key type: RSA | EC | OKP | oct */
  keyType: string
  /** JWK `alg`, when the document states one. null = not stated. */
  algorithm: string | null
  use: IdentityKeyUse
  /** RSA modulus size / EC curve size in bits, when derivable. */
  keySize: number | null
  curve: string | null
  classification: AlgorithmClassification
  evidence: DiscoveryEvidence
}

export interface IdentityEndpoint {
  kind: string
  url: string
  /** true when the endpoint URL is not HTTPS — a real finding, not a guess. */
  insecureTransport: boolean
}

export interface IdentityProviderRecord {
  /** Stable identity: the issuer, which is the protocol's own primary key. */
  issuer: string
  protocol: IdentityProtocol
  /** Human label derived from the issuer host — never a vendor guess. */
  displayName: string
  /** Vendor, ONLY when the issuer host proves it. null otherwise. */
  vendor: string | null
  host: string
  endpoints: IdentityEndpoint[]
  /** Token-signing algorithms the document advertises as SUPPORTED. */
  signingAlgorithmsSupported: string[]
  /** Key-establishment algorithms for encrypted tokens (JWE). */
  keyEncryptionAlgorithmsSupported: string[]
  /** Content-encryption algorithms for encrypted tokens (JWE). */
  contentEncryptionAlgorithmsSupported: string[]
  grantTypesSupported: string[]
  responseTypesSupported: string[]
  scopesSupported: string[]
  jwksUri: string | null
  signingKeys: IdentitySigningKey[]
  /** Worst quantum posture across the signing primitives actually observed. */
  quantumClass: IdentityQuantumClass
  evidence: DiscoveryEvidence
}

export interface IdentityDiscoveryResult {
  providers: IdentityProviderRecord[]
  /** Endpoints that answered but whose document could not be parsed. */
  unparsed: Array<{ sourceUrl: string; reason: string }>
  /** Probes that ran and found nothing — proof of absence, not of failure. */
  probedWithoutResult: string[]
}

/* ================================================================== */
/* Algorithm classification                                            */
/* ================================================================== */

const upper = (value: unknown) => String(value ?? '').trim().toUpperCase()

/**
 * Classify a JOSE algorithm identifier (RFC 7518 + RFC 8037 + drafts).
 *
 * The `purpose` field is load-bearing: `alg` in a JWS header is a SIGNATURE
 * algorithm, `alg` in a JWE header is a KEY-MANAGEMENT algorithm, and `enc` is
 * content encryption. They share a field name and mean entirely different
 * things, which is exactly how "RS256 migrates to ML-KEM" gets written.
 */
export function classifyJoseAlgorithm(raw: unknown, context: CryptoPurpose = 'unknown'): AlgorithmClassification {
  const algorithm = String(raw ?? '').trim()
  const value = upper(algorithm)

  const unknownResult: AlgorithmClassification = {
    algorithm: algorithm || 'unstated',
    purpose: context,
    quantumClass: 'unknown',
    pqcTarget: null,
    standard: null,
    rationale: 'The document did not state an algorithm, so its posture cannot be determined.',
  }
  if (!value) return unknownResult

  /* ---- Post-quantum signatures ------------------------------------- */
  if (/^ML-?DSA|DILITHIUM/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'safe',
      pqcTarget: null, standard: 'FIPS 204',
      rationale: 'ML-DSA is a NIST-standardised post-quantum signature algorithm.',
    }
  }
  if (/^SLH-?DSA|SPHINCS/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'safe',
      pqcTarget: null, standard: 'FIPS 205',
      rationale: 'SLH-DSA is a NIST-standardised stateless hash-based signature algorithm.',
    }
  }
  /* ---- Post-quantum / hybrid key establishment ---------------------- */
  if (/ML-?KEM|KYBER/.test(value)) {
    const hybrid = /X25519|P-?256|SECP/.test(value)
    return {
      algorithm, purpose: 'key-encapsulation', quantumClass: hybrid ? 'hybrid' : 'safe',
      pqcTarget: null, standard: 'FIPS 203',
      rationale: hybrid
        ? 'Hybrid key establishment combining a classical curve with ML-KEM.'
        : 'ML-KEM is the NIST-standardised post-quantum key-encapsulation mechanism.',
    }
  }

  /* ---- Classical JWS signature algorithms --------------------------- */
  // RS*/PS* = RSA, ES* = ECDSA, EdDSA = Ed25519/Ed448. All broken by Shor.
  if (/^(RS|PS)(256|384|512)$/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65 (hybrid with RSA during transition)', standard: 'FIPS 204',
      rationale: 'RSA signatures are broken by Shor\'s algorithm. Token signatures must migrate to ML-DSA.',
    }
  }
  if (/^ES(256|384|512|256K)$/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65 (hybrid with ECDSA during transition)', standard: 'FIPS 204',
      rationale: 'ECDSA signatures are broken by Shor\'s algorithm. Token signatures must migrate to ML-DSA.',
    }
  }
  if (/^EDDSA$/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65 (hybrid with Ed25519 during transition)', standard: 'FIPS 204',
      rationale: 'Ed25519/Ed448 signatures are broken by Shor\'s algorithm.',
    }
  }
  /* HMAC token signing is symmetric: Grover halves the strength, it is not
   * broken by Shor. Calling it quantum-vulnerable alongside RSA is wrong. */
  if (/^HS(256|384|512)$/.test(value)) {
    const bits = Number(value.slice(2))
    return {
      algorithm, purpose: 'signature',
      quantumClass: bits >= 384 ? 'safe' : 'unknown',
      pqcTarget: bits >= 384 ? null : 'HS512, or migrate to asymmetric ML-DSA',
      standard: 'RFC 7518',
      rationale: bits >= 384
        ? 'HMAC is symmetric: Grover halves its strength, leaving an adequate post-quantum margin at this size.'
        : 'HMAC is symmetric and not broken by Shor, but HS256 retains only ~128-bit classical / 64-bit post-quantum strength. Shared-secret signing also cannot be verified by third parties.',
    }
  }
  if (/^NONE$/.test(value)) {
    return {
      algorithm, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65', standard: 'RFC 7518',
      rationale: 'The "none" algorithm disables signature verification entirely. This is an unauthenticated token, a critical flaw independent of any quantum threat.',
    }
  }

  /* ---- JWE key management ------------------------------------------- */
  if (/^RSA-OAEP|^RSA1_5/.test(value)) {
    return {
      algorithm, purpose: 'key-encapsulation', quantumClass: 'vulnerable',
      pqcTarget: 'ML-KEM-768 (hybrid X25519MLKEM768)', standard: 'FIPS 203',
      rationale: 'RSA key transport is broken by Shor\'s algorithm. Encrypted-token key establishment must migrate to ML-KEM.',
    }
  }
  if (/^ECDH-ES/.test(value)) {
    return {
      algorithm, purpose: 'key-encapsulation', quantumClass: 'vulnerable',
      pqcTarget: 'ML-KEM-768 (hybrid X25519MLKEM768)', standard: 'FIPS 203',
      rationale: 'Elliptic-curve key agreement is broken by Shor\'s algorithm.',
    }
  }
  if (/^A(128|192|256)KW$|^A(128|192|256)GCMKW$|^DIR$/.test(value)) {
    return {
      algorithm, purpose: 'key-encapsulation',
      quantumClass: /256/.test(value) || value === 'DIR' ? 'safe' : 'unknown',
      pqcTarget: /256/.test(value) || value === 'DIR' ? null : 'A256KW',
      standard: 'RFC 7518',
      rationale: 'Symmetric key wrapping is not broken by Shor; Grover halves its strength, so 256-bit retains an adequate margin.',
    }
  }

  /* ---- JWE content encryption --------------------------------------- */
  if (/^A(128|192|256)(GCM|CBC-HS\d+)$/.test(value)) {
    const strong = /256/.test(value)
    return {
      algorithm, purpose: 'symmetric',
      quantumClass: strong ? 'safe' : 'unknown',
      pqcTarget: strong ? null : 'A256GCM',
      standard: 'RFC 7518',
      rationale: strong
        ? 'AES-256 content encryption retains a 128-bit post-quantum margin under Grover.'
        : 'AES-128 retains only ~64-bit post-quantum strength under Grover.',
    }
  }

  return { ...unknownResult, algorithm }
}

/** Worst-wins across observed primitives. `unknown` never reads as safe. */
const CLASS_RANK: Record<IdentityQuantumClass, number> = { vulnerable: 3, unknown: 2, hybrid: 1, safe: 0 }

export function worstQuantumClass(classes: IdentityQuantumClass[]): IdentityQuantumClass {
  if (!classes.length) return 'unknown'
  return classes.reduce((worst, current) => (CLASS_RANK[current] > CLASS_RANK[worst] ? current : worst), 'safe')
}

/* ================================================================== */
/* Helpers                                                             */
/* ================================================================== */

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return String(url || '').replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
  }
}

function isHttps(url: string): boolean {
  return /^https:\/\//i.test(String(url || ''))
}

const strArray = (value: unknown): string[] =>
  Array.isArray(value) ? value.map((v) => String(v ?? '').trim()).filter(Boolean) : []

/**
 * Vendor identification from the issuer host ONLY.
 *
 * The audit found "Microsoft Entra ID" reported for a tenant that has none —
 * invented by matching the word "entra" somewhere in a crypto row's text. A
 * vendor is named here only when the issuer host itself is that vendor's
 * documented domain. Anything else returns null: an unrecognised provider is
 * unrecognised, not guessed.
 */
const VENDOR_HOSTS: Array<[RegExp, string]> = [
  [/(^|\.)login\.microsoftonline\.com$|(^|\.)sts\.windows\.net$|(^|\.)ciamlogin\.com$/, 'Microsoft Entra ID'],
  [/(^|\.)accounts\.google\.com$|(^|\.)googleapis\.com$/, 'Google Identity'],
  [/(^|\.)okta\.com$|(^|\.)oktapreview\.com$/, 'Okta'],
  [/(^|\.)auth0\.com$/, 'Auth0'],
  [/(^|\.)amazoncognito\.com$/, 'Amazon Cognito'],
  [/(^|\.)onelogin\.com$/, 'OneLogin'],
  [/(^|\.)pingone\.com$|(^|\.)pingidentity\.com$/, 'Ping Identity'],
  [/(^|\.)forgerock\.io$/, 'ForgeRock'],
  [/(^|\.)cloudflareaccess\.com$/, 'Cloudflare Access'],
  [/(^|\.)duosecurity\.com$/, 'Duo'],
  [/(^|\.)jumpcloud\.com$/, 'JumpCloud'],
]

export function vendorForIssuer(issuer: string): string | null {
  const host = hostOf(issuer)
  if (!host) return null
  for (const [pattern, vendor] of VENDOR_HOSTS) if (pattern.test(host)) return vendor
  // Keycloak advertises itself in its issuer PATH (`/realms/<name>`), which is
  // part of the protocol contract rather than a guess.
  if (/\/realms\/[^/]+$/.test(String(issuer || ''))) return 'Keycloak'
  return null
}

/* ================================================================== */
/* JWKS                                                                */
/* ================================================================== */

/** Base64url length → RSA modulus bits. `n` is the big-endian modulus. */
function rsaBitsFromModulus(n: unknown): number | null {
  const value = String(n ?? '').replace(/[^A-Za-z0-9_-]/g, '')
  if (!value) return null
  // 4 base64 chars encode 3 bytes; base64url here is unpadded.
  const bytes = Math.floor((value.length * 3) / 4)
  if (bytes <= 0) return null
  // Round to the nearest conventional modulus size.
  const bits = bytes * 8
  for (const size of [1024, 2048, 3072, 4096, 8192]) {
    if (Math.abs(bits - size) <= 16) return size
  }
  return bits
}

const CURVE_BITS: Record<string, number> = {
  'P-256': 256, 'P-384': 384, 'P-521': 521, secp256k1: 256, Ed25519: 256, Ed448: 448, X25519: 256, X448: 448,
}

function keyUseOf(jwk: Record<string, unknown>): IdentityKeyUse {
  const use = String(jwk.use ?? '').trim().toLowerCase()
  if (use === 'sig') return 'signature'
  if (use === 'enc') return 'encryption'
  const ops = strArray(jwk.key_ops).map((o) => o.toLowerCase())
  if (ops.includes('sign') || ops.includes('verify')) return 'signature'
  if (ops.includes('encrypt') || ops.includes('decrypt') || ops.includes('wrapkey') || ops.includes('unwrapkey')) return 'encryption'
  return 'unspecified'
}

/**
 * Parse a JWKS document into signing-key records.
 *
 * A key with no `alg` is reported with `algorithm: null` and classified from its
 * key TYPE instead — an RSA key is Shor-vulnerable whether or not the document
 * says `RS256`. What is never done is invent an `alg` the document did not
 * state.
 */
export function parseJwks(document: unknown, evidence: DiscoveryEvidence): IdentitySigningKey[] {
  const doc = (document ?? {}) as Record<string, unknown>
  const keys = Array.isArray(doc.keys) ? doc.keys : []
  const out: IdentitySigningKey[] = []

  for (let index = 0; index < keys.length; index += 1) {
    const jwk = (keys[index] ?? {}) as Record<string, unknown>
    const kty = String(jwk.kty ?? '').trim()
    if (!kty) continue

    const alg = String(jwk.alg ?? '').trim() || null
    const crv = String(jwk.crv ?? '').trim() || null
    const use = keyUseOf(jwk)

    let keySize: number | null = null
    if (kty === 'RSA') keySize = rsaBitsFromModulus(jwk.n)
    else if (crv) keySize = CURVE_BITS[crv] ?? null

    // Classify by the stated `alg` when present; otherwise by key type, which
    // is still decisive for the quantum question.
    let classification: AlgorithmClassification
    if (alg) {
      classification = classifyJoseAlgorithm(alg, use === 'encryption' ? 'key-encapsulation' : 'signature')
    } else if (kty === 'RSA') {
      classification = {
        algorithm: keySize ? `RSA-${keySize}` : 'RSA',
        purpose: use === 'encryption' ? 'key-encapsulation' : 'signature',
        quantumClass: 'vulnerable',
        pqcTarget: use === 'encryption' ? 'ML-KEM-768 (hybrid X25519MLKEM768)' : 'ML-DSA-65 (hybrid with RSA during transition)',
        standard: use === 'encryption' ? 'FIPS 203' : 'FIPS 204',
        rationale: 'RSA is broken by Shor\'s algorithm. The document did not state an algorithm; the key type is decisive.',
      }
    } else if (kty === 'EC' || kty === 'OKP') {
      classification = {
        algorithm: crv ? `${kty === 'OKP' ? 'EdDSA' : 'ECDSA'} ${crv}` : kty,
        purpose: use === 'encryption' ? 'key-encapsulation' : 'signature',
        quantumClass: 'vulnerable',
        pqcTarget: use === 'encryption' ? 'ML-KEM-768 (hybrid X25519MLKEM768)' : 'ML-DSA-65',
        standard: use === 'encryption' ? 'FIPS 203' : 'FIPS 204',
        rationale: 'Elliptic-curve primitives are broken by Shor\'s algorithm. The document did not state an algorithm; the key type is decisive.',
      }
    } else if (kty === 'oct') {
      classification = {
        algorithm: 'Symmetric (oct)',
        purpose: 'signature',
        quantumClass: 'unknown',
        pqcTarget: null,
        standard: 'RFC 7518',
        rationale: 'A symmetric key is not broken by Shor. Its strength depends on a size the JWKS does not publish.',
      }
    } else {
      classification = classifyJoseAlgorithm(null, 'unknown')
    }

    out.push({
      keyId: String(jwk.kid ?? '').trim() || `${kty.toLowerCase()}-${index}`,
      keyType: kty,
      algorithm: alg,
      use,
      keySize,
      curve: crv,
      classification,
      evidence,
    })
  }

  return out
}

/* ================================================================== */
/* OIDC discovery (OpenID Connect Discovery 1.0)                       */
/* ================================================================== */

const OIDC_ENDPOINT_FIELDS: Array<[string, string]> = [
  ['authorization_endpoint', 'authorization'],
  ['token_endpoint', 'token'],
  ['userinfo_endpoint', 'userinfo'],
  ['jwks_uri', 'jwks'],
  ['registration_endpoint', 'registration'],
  ['introspection_endpoint', 'introspection'],
  ['revocation_endpoint', 'revocation'],
  ['end_session_endpoint', 'end-session'],
  ['device_authorization_endpoint', 'device-authorization'],
  ['pushed_authorization_request_endpoint', 'pushed-authorization'],
]

/**
 * Parse an OIDC discovery document (or an RFC 8414 OAuth authorization-server
 * metadata document — the schemas overlap by design).
 *
 * Returns null when the document has no `issuer`, because the issuer IS the
 * provider's identity under both specs. A document without one is not an
 * identity provider we can name, and inventing a name from the probed host is
 * how a CDN 404 page becomes an "identity provider".
 */
export function parseOidcDiscovery(
  document: unknown,
  evidence: DiscoveryEvidence,
  jwks?: IdentitySigningKey[],
): IdentityProviderRecord | null {
  const doc = (document ?? {}) as Record<string, unknown>
  const issuer = String(doc.issuer ?? '').trim()
  if (!issuer) return null

  const endpoints: IdentityEndpoint[] = []
  for (const [field, kind] of OIDC_ENDPOINT_FIELDS) {
    const url = String(doc[field] ?? '').trim()
    if (!url) continue
    endpoints.push({ kind, url, insecureTransport: !isHttps(url) })
  }

  const signingAlgorithmsSupported = Array.from(new Set([
    ...strArray(doc.id_token_signing_alg_values_supported),
    ...strArray(doc.userinfo_signing_alg_values_supported),
    ...strArray(doc.request_object_signing_alg_values_supported),
    ...strArray(doc.token_endpoint_auth_signing_alg_values_supported),
  ]))
  const keyEncryptionAlgorithmsSupported = Array.from(new Set([
    ...strArray(doc.id_token_encryption_alg_values_supported),
    ...strArray(doc.userinfo_encryption_alg_values_supported),
    ...strArray(doc.request_object_encryption_alg_values_supported),
  ]))
  const contentEncryptionAlgorithmsSupported = Array.from(new Set([
    ...strArray(doc.id_token_encryption_enc_values_supported),
    ...strArray(doc.userinfo_encryption_enc_values_supported),
    ...strArray(doc.request_object_encryption_enc_values_supported),
  ]))

  // The provider's posture is decided by the primitives actually OBSERVED in
  // its JWKS where one was read, because that is what really signs its tokens.
  // Advertised support is a weaker signal and is used only as a fallback.
  const observed = (jwks ?? []).filter((key) => key.use !== 'encryption')
  const classes: IdentityQuantumClass[] = observed.length
    ? observed.map((key) => key.classification.quantumClass)
    : signingAlgorithmsSupported.map((alg) => classifyJoseAlgorithm(alg, 'signature').quantumClass)

  // A discovery document is a protocol contract: if it declares OIDC-specific
  // fields it is OIDC, otherwise it is a bare OAuth 2.0 authorization server.
  const isOidc = Boolean(
    doc.userinfo_endpoint ||
    doc.id_token_signing_alg_values_supported ||
    strArray(doc.scopes_supported).includes('openid'),
  )

  return {
    issuer,
    protocol: isOidc ? 'oidc' : 'oauth2',
    displayName: hostOf(issuer) || issuer,
    vendor: vendorForIssuer(issuer),
    host: hostOf(issuer),
    endpoints,
    signingAlgorithmsSupported,
    keyEncryptionAlgorithmsSupported,
    contentEncryptionAlgorithmsSupported,
    grantTypesSupported: strArray(doc.grant_types_supported),
    responseTypesSupported: strArray(doc.response_types_supported),
    scopesSupported: strArray(doc.scopes_supported),
    jwksUri: String(doc.jwks_uri ?? '').trim() || null,
    signingKeys: jwks ?? [],
    quantumClass: worstQuantumClass(classes),
    evidence,
  }
}

/* ================================================================== */
/* SAML 2.0 metadata                                                   */
/* ================================================================== */

/**
 * Parse SAML 2.0 metadata XML.
 *
 * Deliberately a narrow, regex-based reader rather than a full XML parser: the
 * scanner must never execute or expand untrusted XML (XXE / billion-laughs), so
 * it extracts only the four facts it needs and ignores everything else.
 */
export function parseSamlMetadata(xml: unknown, evidence: DiscoveryEvidence): IdentityProviderRecord | null {
  const text = String(xml ?? '')
  if (!/<(md:)?EntityDescriptor/i.test(text)) return null

  const entityId = text.match(/entityID\s*=\s*["']([^"']+)["']/i)?.[1]?.trim()
  if (!entityId) return null

  const endpoints: IdentityEndpoint[] = []
  const ssoPattern = /<(?:md:)?SingleSignOnService[^>]*Location\s*=\s*["']([^"']+)["']/gi
  const sloPattern = /<(?:md:)?SingleLogoutService[^>]*Location\s*=\s*["']([^"']+)["']/gi
  for (const match of text.matchAll(ssoPattern)) endpoints.push({ kind: 'saml-sso', url: match[1], insecureTransport: !isHttps(match[1]) })
  for (const match of text.matchAll(sloPattern)) endpoints.push({ kind: 'saml-slo', url: match[1], insecureTransport: !isHttps(match[1]) })

  // SAML signature algorithms are declared as XML-DSig URIs.
  const algorithms = Array.from(
    new Set(Array.from(text.matchAll(/Algorithm\s*=\s*["']([^"']+)["']/gi), (m) => m[1])),
  )
  const signingAlgorithmsSupported = algorithms
    .filter((uri) => /#(rsa|ecdsa|dsa|hmac)-?/i.test(uri) || /xmldsig|xmlenc/i.test(uri))
    .map(samlAlgorithmLabel)

  const classes = signingAlgorithmsSupported.map((alg) => classifySamlAlgorithm(alg).quantumClass)

  return {
    // SAML's entityID is the protocol's own primary key, the same role `issuer`
    // plays in OIDC. Both are stored in one column so a provider reachable over
    // both protocols is one record, not two.
    issuer: entityId,
    protocol: 'saml2',
    displayName: hostOf(entityId) || entityId,
    vendor: vendorForIssuer(entityId),
    host: hostOf(entityId),
    endpoints,
    signingAlgorithmsSupported,
    keyEncryptionAlgorithmsSupported: [],
    contentEncryptionAlgorithmsSupported: [],
    grantTypesSupported: [],
    responseTypesSupported: [],
    scopesSupported: [],
    jwksUri: null,
    signingKeys: [],
    quantumClass: worstQuantumClass(classes),
    evidence,
  }
}

function samlAlgorithmLabel(uri: string): string {
  const tail = uri.split('#').pop() ?? uri
  return tail.replace(/^rsa-/, 'RSA-').replace(/^ecdsa-/, 'ECDSA-').replace(/^hmac-/, 'HMAC-')
}

export function classifySamlAlgorithm(label: string): AlgorithmClassification {
  const value = upper(label)
  if (/^RSA-|^RSASSA/.test(value)) {
    return {
      algorithm: label, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65', standard: 'FIPS 204',
      rationale: 'RSA XML signatures are broken by Shor\'s algorithm.',
    }
  }
  if (/^ECDSA/.test(value)) {
    return {
      algorithm: label, purpose: 'signature', quantumClass: 'vulnerable',
      pqcTarget: 'ML-DSA-65', standard: 'FIPS 204',
      rationale: 'ECDSA XML signatures are broken by Shor\'s algorithm.',
    }
  }
  if (/SHA1|SHA-1|MD5/.test(value)) {
    return {
      algorithm: label, purpose: 'hash', quantumClass: 'vulnerable',
      pqcTarget: 'SHA3-256', standard: 'FIPS 202',
      rationale: 'SHA-1 and MD5 have practical collision attacks today, independent of any quantum threat.',
    }
  }
  if (/AES256|AES-256/.test(value)) {
    return {
      algorithm: label, purpose: 'symmetric', quantumClass: 'safe',
      pqcTarget: null, standard: 'FIPS 197',
      rationale: 'AES-256 retains a 128-bit post-quantum margin under Grover.',
    }
  }
  return {
    algorithm: label, purpose: 'unknown', quantumClass: 'unknown',
    pqcTarget: null, standard: null,
    rationale: 'Algorithm URI not recognised; posture undetermined.',
  }
}

/* ================================================================== */
/* Assembly                                                            */
/* ================================================================== */

export interface RawProbe {
  /** The URL that was probed. */
  url: string
  /** `oidc-discovery` | `jwks` | `oauth-as-metadata` | `saml-metadata` */
  method: string
  httpStatus: number | null
  /** Parsed JSON, or raw XML text for SAML. null when the probe returned nothing. */
  body: unknown
  observedAt: string
}

/**
 * Assemble discovery results from a set of completed probes.
 *
 * Providers are keyed by ISSUER, so the same provider reached through several
 * probe paths is one record. JWKS keys are attached to the provider whose
 * `jwks_uri` they were fetched from — never to whichever provider happens to be
 * first, which would misattribute keys on a multi-tenant host.
 */
export function assembleIdentityDiscovery(probes: RawProbe[]): IdentityDiscoveryResult {
  const unparsed: Array<{ sourceUrl: string; reason: string }> = []
  const probedWithoutResult: string[] = []

  // Index JWKS documents by the URL they came from.
  const jwksByUrl = new Map<string, IdentitySigningKey[]>()
  for (const probe of probes) {
    if (probe.method !== 'jwks') continue
    const evidence: DiscoveryEvidence = { sourceUrl: probe.url, method: probe.method, observedAt: probe.observedAt, httpStatus: probe.httpStatus }
    const keys = parseJwks(probe.body, evidence)
    if (keys.length) jwksByUrl.set(probe.url, keys)
    else if (probe.body) unparsed.push({ sourceUrl: probe.url, reason: 'JWKS document contained no usable keys' })
    else probedWithoutResult.push(probe.url)
  }

  const byIssuer = new Map<string, IdentityProviderRecord>()

  for (const probe of probes) {
    const evidence: DiscoveryEvidence = { sourceUrl: probe.url, method: probe.method, observedAt: probe.observedAt, httpStatus: probe.httpStatus }

    if (probe.method === 'oidc-discovery' || probe.method === 'oauth-as-metadata') {
      if (!probe.body) { probedWithoutResult.push(probe.url); continue }
      const partial = parseOidcDiscovery(probe.body, evidence)
      if (!partial) { unparsed.push({ sourceUrl: probe.url, reason: 'Document declared no issuer, so no provider identity could be established' }); continue }
      // Attach only the JWKS this provider actually points at.
      const keys = partial.jwksUri ? jwksByUrl.get(partial.jwksUri) ?? [] : []
      const complete = parseOidcDiscovery(probe.body, evidence, keys)!
      const existing = byIssuer.get(complete.issuer)
      byIssuer.set(complete.issuer, existing ? mergeProviders(existing, complete) : complete)
      continue
    }

    if (probe.method === 'saml-metadata') {
      if (!probe.body) { probedWithoutResult.push(probe.url); continue }
      const record = parseSamlMetadata(probe.body, evidence)
      if (!record) { unparsed.push({ sourceUrl: probe.url, reason: 'Not a parseable SAML EntityDescriptor' }); continue }
      const existing = byIssuer.get(record.issuer)
      byIssuer.set(record.issuer, existing ? mergeProviders(existing, record) : record)
    }
  }

  return {
    providers: Array.from(byIssuer.values()).sort((a, b) => a.issuer.localeCompare(b.issuer)),
    unparsed,
    probedWithoutResult,
  }
}

function mergeProviders(a: IdentityProviderRecord, b: IdentityProviderRecord): IdentityProviderRecord {
  const union = (x: string[], y: string[]) => Array.from(new Set([...x, ...y]))
  const endpoints = [...a.endpoints]
  for (const endpoint of b.endpoints) {
    if (!endpoints.some((e) => e.kind === endpoint.kind && e.url === endpoint.url)) endpoints.push(endpoint)
  }
  const signingKeys = [...a.signingKeys]
  for (const key of b.signingKeys) {
    if (!signingKeys.some((k) => k.keyId === key.keyId)) signingKeys.push(key)
  }
  const merged: IdentityProviderRecord = {
    ...a,
    // OIDC is the richer contract; never downgrade a known OIDC provider to oauth2.
    protocol: a.protocol === 'oidc' || b.protocol === 'oidc' ? 'oidc' : a.protocol,
    vendor: a.vendor ?? b.vendor,
    endpoints,
    signingAlgorithmsSupported: union(a.signingAlgorithmsSupported, b.signingAlgorithmsSupported),
    keyEncryptionAlgorithmsSupported: union(a.keyEncryptionAlgorithmsSupported, b.keyEncryptionAlgorithmsSupported),
    contentEncryptionAlgorithmsSupported: union(a.contentEncryptionAlgorithmsSupported, b.contentEncryptionAlgorithmsSupported),
    grantTypesSupported: union(a.grantTypesSupported, b.grantTypesSupported),
    responseTypesSupported: union(a.responseTypesSupported, b.responseTypesSupported),
    scopesSupported: union(a.scopesSupported, b.scopesSupported),
    jwksUri: a.jwksUri ?? b.jwksUri,
    signingKeys,
  }
  const observed = signingKeys.filter((k) => k.use !== 'encryption')
  merged.quantumClass = worstQuantumClass(
    observed.length
      ? observed.map((k) => k.classification.quantumClass)
      : merged.signingAlgorithmsSupported.map((alg) => classifyJoseAlgorithm(alg, 'signature').quantumClass),
  )
  return merged
}

/* ================================================================== */
/* Probe plan                                                          */
/* ================================================================== */

/**
 * The well-known paths worth probing on a host, in priority order.
 *
 * Kept small and standards-based: every path here is defined by a published
 * specification, so a hit is meaningful and a miss is proof of absence rather
 * than a failed guess.
 */
export const IDENTITY_PROBE_PLAN: Array<{ path: string; method: string }> = [
  { path: '/.well-known/openid-configuration', method: 'oidc-discovery' },
  { path: '/.well-known/oauth-authorization-server', method: 'oauth-as-metadata' },
  // Microsoft Entra / ADFS federation metadata.
  { path: '/FederationMetadata/2007-06/FederationMetadata.xml', method: 'saml-metadata' },
  // Common SAML IdP metadata locations.
  { path: '/saml/metadata', method: 'saml-metadata' },
  { path: '/simplesaml/saml2/idp/metadata.php', method: 'saml-metadata' },
]

/** JWKS is probed only at the `jwks_uri` a discovery document actually names. */
export function jwksProbeFor(provider: { jwksUri: string | null }): string | null {
  return provider.jwksUri
}
