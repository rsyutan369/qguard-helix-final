/**
 * Scanner finding identity — pure and dependency-free.
 *
 * Deliberately free of Express, Supabase and any other runtime import (the same
 * discipline as `scanner-module-ledger.ts`) so the rule that decides "are these
 * two rows the same observation?" can be exercised offline by
 * `tools/scanner-finding-identity-check.ts` and shared rather than reimplemented.
 *
 * WHY THIS EXISTS
 * ---------------
 * The scanner persists every detection to `pqc_scan_results`, `crypto_exposures`
 * and `crypto_inventory`, AND keeps it in the scan session's own findings array.
 * Those are four STORAGE VIEWS of one observation, and each writer labels it
 * differently:
 *
 *   | stored in            | location                                | category      |
 *   |----------------------|-----------------------------------------|---------------|
 *   | crypto_exposures     | "www.cloudflare.com"                    | "rsa"         |
 *   | pqc_scan_results     | "www.cloudflare.com"                    | "Cipher Suite"|
 *   | crypto_inventory     | "www.cloudflare.com"                    | "algorithm"   |
 *   | scan session findings| "Cipher Suite — https://www.cloudflare…"| "Cipher Suite"|
 *
 * Keying a merge on `source`, `category` or the raw `location` therefore treats
 * one cipher suite as four findings. Measured on a live two-asset tenant that
 * inflated the reported total from 66 real observations to 255, and with it
 * `criticalFindings`, `severityCounts`, the Quantum Readiness risk distribution
 * and the workflow rail — every one of which reads this list.
 *
 * Identity is a property of the OBSERVATION: what was found (algorithm), where
 * (subject host) and how (detection method).
 */

export type FindingIdentityInput = {
  algorithm?: string | null
  location?: string | null
  detectionMethod?: string | null
  /** Target of the scan/asset this finding belongs to; resolves subject-less locations. */
  scanTarget?: string | null
}

/**
 * Labels that identify WHERE a finding was read from rather than HOW it was
 * measured. A detection method that is really a table name must not split one
 * observation into several.
 */
export const FINDING_STORAGE_SOURCES = new Set([
  'crypto_exposures',
  'pqc_scan_results',
  'crypto_inventory',
  'vulnerabilities',
  'scanner-evidence',
  'cbom-inventory',
])

/**
 * Reduce a location (or scan target) to a bare host, or '' when it carries no
 * target at all.
 *
 * Handles the three shapes the writers produce: a bare hostname, a URL, and the
 * "<label> — <target>" form. Rule-derived session findings use their rule id as
 * the location ("Detection Rule TLS-008") and so contain no target — those
 * return '' and the caller falls back to the scan target.
 */
export function normalizeFindingSubject(raw: string) {
  const text = String(raw || '')
  // "<label> — <target>" keeps only the target half.
  const tail = text.includes('—') ? text.slice(text.lastIndexOf('—') + 1) : text
  const host = tail
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
  const looksLikeHost = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)
  const looksLikeIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host)
  return looksLikeHost || looksLikeIp ? host : ''
}

/** Canonical subject (host / target) a finding was observed on. */
export function findingSubject(finding: FindingIdentityInput) {
  return (
    normalizeFindingSubject(String(finding.location || '')) ||
    normalizeFindingSubject(String(finding.scanTarget || '')) ||
    String(finding.location || '').trim().toLowerCase()
  )
}

/**
 * The merge key: (algorithm, subject, measurement method). Two rows sharing it
 * describe the same physical observation regardless of which table they came
 * from or what that table chose to call the category.
 */
export function findingIdentityKey(finding: FindingIdentityInput) {
  const method = String(finding.detectionMethod || '').trim().toLowerCase()
  return [
    String(finding.algorithm || '').trim().toLowerCase(),
    findingSubject(finding),
    FINDING_STORAGE_SOURCES.has(method) ? '' : method,
  ].join('|')
}

/**
 * Placeholder strings the writers substitute when a row has no real narrative.
 * They must never win over actual analyst text during a merge.
 */
export const GENERIC_FINDING_TEXT = new Set([
  'stored scanner result',
  'scanner evidence linked this exposure to the asset.',
  'cryptographic exposure linked to this asset.',
  'crypto exposure record linked to this asset.',
  'open vulnerability record linked to this asset.',
  'crypto inventory marked this component as vulnerable.',
  'create a pqc remediation plan for this exposure.',
  'create a pqc remediation plan for this vulnerability.',
  'review against nist pqc migration policy',
])

/**
 * Observation classes whose record NAMES an actual cryptographic algorithm,
 * protocol or suite.
 *
 * The scanner writes BOTH measured cryptography and policy/configuration
 * findings into `crypto_inventory`, and for the latter the `algorithm` column
 * holds the finding TITLE ("No Certificate Pinning", "No CAA Issuance Policy",
 * "Regulatory Compliance Gap"). Every consumer that treats that column as an
 * algorithm produces nonsense — the CBOM chart plotted rule names on an
 * algorithm axis, and the Migration Sandbox seeded a simulation named
 * "No CAA Issuance Policy -> ML-KEM-768", i.e. a DNS policy gap "migrated" to a
 * key-encapsulation mechanism.
 *
 * The scanner labels every record with its own class prefix ("Cipher Suite: …",
 * "Rule (Tls Config): …"), so this reads that label rather than guessing what an
 * algorithm name looks like. An unrecognised class is treated as posture — the
 * safe direction, since a consumer then never mistakes it for cryptography.
 */
export const CRYPTO_OBSERVATION_CLASSES = [
  'cipher suite',
  'symmetric encryption',
  'asymmetric encryption',
  'certificate',
  'certificate signature',
  'signature',
  'key exchange',
  'post-quantum key agreement',
  'protocol',
  'protocol support',
  'hash',
  'mac',
  'kdf',
]

/** The scanner's class prefix for a record, e.g. "Cipher Suite: X" -> "cipher suite". */
export function observationClass(componentName: unknown) {
  const text = String(componentName || '').trim()
  const prefix = text.includes(':') ? text.slice(0, text.indexOf(':')) : text
  // "Key Exchange (Harvest Now Decrypt Later)" -> "key exchange"
  // Underscores are normalised because the agent collector writes its module id
  // (`key_exchange: RSA-2048`) where the web scanner writes a display category
  // (`Key Exchange: RSA-2048`). Without this, every agent-collected component
  // read as non-cryptographic.
  return prefix.replace(/\s*\(.*$/, '').replace(/_/g, ' ').trim().toLowerCase()
}

/** True when the record's class prefix names a cryptographic observation. */
export function namesCryptography(componentName: unknown) {
  return CRYPTO_OBSERVATION_CLASSES.includes(observationClass(componentName))
}

/* ------------------------------------------------------------------ */
/* Cryptographic component vs. scanner finding                         */
/* ------------------------------------------------------------------ */

/**
 * `crypto_inventory` is written by three different producers, and one of them
 * stores a FINDING in the same shape as a cryptographic component:
 *
 *   • `scanner.ts` writes `algorithm: finding.algorithm` for EVERY rule it
 *     fires, so a policy rule lands with algorithm "No Certificate Pinning",
 *     "Regulatory Compliance Gap" or "No OCSP Stapling";
 *   • `agent-scanner.ts` writes `${moduleId}: ${algorithm}` (`key_exchange:`,
 *     `ssh:`, `library:`) and `PQC-ready: ${algorithm}`.
 *
 * Counting the findings as components inflates the CBOM headline and, because
 * they are also written `is_vulnerable: true`, inflates "quantum-vulnerable"
 * on both sides of the ratio: a tenant whose 178 rows were 101 findings
 * published "178 cryptographic components, 160 quantum-vulnerable" (90%) where
 * the cryptography itself was 77 components / 59 vulnerable (77%).
 *
 * Identification is POSITIVE ONLY: a row counts as a cryptographic component
 * when something about it actually names cryptography. Nothing is excluded by
 * guessing that its text "looks like a finding" — that heuristic would silently
 * drop real components the moment a producer changed its wording.
 */

/** TLS/SSL/SSH/IPsec protocol versions are legitimate CBOM components. */
const CRYPTO_PROTOCOL_PATTERN =
  /\b(TLS|SSL|DTLS|SSH|IPSEC|IKE|QUIC|WPA|KERBEROS)\s*[-_ ]?V?\d/i

/** A TLS/SSL cipher-suite identifier, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. */
const CIPHER_SUITE_PATTERN = /^(TLS|SSL)[_-][A-Z0-9_]+$/i

/**
 * Algorithm tokens the canonical family classifier misses because it is anchored
 * on word boundaries: `sha256WithRSAEncryption` (the standard X.509 signature
 * name) and `X25519MLKEM768` (a hybrid group) carry the algorithm as an
 * internal token with no separator around it.
 *
 * Deliberately NOT included: bare "PQC", "quantum", "certificate", "key". Those
 * words appear in finding TITLES — "No PQC Certificate", "Quantum-Vulnerable
 * OIDs", "No Certificate Pinning" — and matching them would count a finding as
 * a cryptographic component, which is the exact defect this predicate exists to
 * prevent.
 */
const CRYPTO_ALGORITHM_TOKEN_PATTERN = new RegExp(
  [
    'RSAENCRYPTION', 'RSASSA', 'WITHRSA',
    'MLKEM', 'MLDSA', 'SLHDSA',
    '\\bKYBER\\b', '\\bDILITHIUM\\b', '\\bSPHINCS\\b', '\\bFALCON\\b',
    '\\bX25519\\b', '\\bX448\\b', '\\bED25519\\b', '\\bED448\\b',
    '\\bSECP\\d+R1\\b', '\\bPRIME256V1\\b',
    '\\bHMAC\\b', '\\bHKDF\\b', '\\bPBKDF2\\b', '\\bARGON2\\b', '\\bBCRYPT\\b', '\\bSCRYPT\\b',
    '\\bPOLY1305\\b', '\\bCURVE25519\\b',
  ].join('|'),
  'i',
)

/**
 * True when a `crypto_inventory` row describes actual cryptography rather than
 * a scanner finding about the estate.
 *
 * `classify` is the canonical algorithm-family classifier, injected so this
 * module stays free of a dependency cycle with the governance engine.
 */
export function isCryptographicComponent(
  row: { name?: unknown; algorithm?: unknown; item_type?: unknown; protocol?: unknown },
  classify: (raw: string) => string,
): boolean {
  const algorithm = String(row.algorithm ?? '').trim()
  const name = String(row.name ?? '').trim()
  // The algorithm value with any class prefix removed, e.g.
  // "Cipher Suite: TLS_AES_128" -> "TLS_AES_128".
  const bare = algorithm || (name.includes(':') ? name.slice(name.indexOf(':') + 1).trim() : name)

  // 1. It names a real algorithm family (RSA, AES, ML-KEM, SHA-2, …).
  if (classify(bare) !== 'unknown') return true
  // 2. It carries an algorithm token the family classifier cannot see.
  if (CRYPTO_ALGORITHM_TOKEN_PATTERN.test(bare)) return true
  // 3. It names a cryptographic protocol version (TLSv1.2, SSHv2, …).
  if (CRYPTO_PROTOCOL_PATTERN.test(bare)) return true
  // 4. It is a cipher-suite identifier.
  if (CIPHER_SUITE_PATTERN.test(bare.replace(/\s+/g, ''))) return true
  // 5. Its class prefix is a known cryptographic observation class — this is
  //    what keeps a bare "Certificate: leaf" row (no algorithm recorded yet)
  //    counted, while "certificate-risk: No Certificate Pinning" is not.
  if (name && namesCryptography(name)) return true
  return false
}

/**
 * Count DISTINCT graded observations across the three tables that store them.
 *
 * `crypto_exposures`, `pqc_scan_results` and `scanner_alerts` are storage views
 * of the same scanner observations. Summing their per-severity counts — which
 * the Migration Sandbox used to do — counts one cipher suite up to three times:
 * measured on a live tenant it reported 22 critical / 50 high where the
 * de-duplicated view held 13 / 30, so the sandbox disagreed with CBOM, Assets,
 * the QR Engine and the workflow rail about the same estate.
 */
export function severityWeight(value: unknown) {
  const text = String(value || '').toLowerCase()
  if (text.includes('critical')) return 4
  if (text.includes('high')) return 3
  if (text.includes('medium') || text.includes('moderate')) return 2
  if (text.includes('low')) return 1
  return 0
}

export function dedupeGradedObservations(rows: Array<{
  algorithm?: unknown
  subject?: unknown
  detectionMethod?: unknown
  severity?: unknown
}>) {
  const strongest = new Map<string, number>()
  for (const row of rows) {
    // Deliberately (algorithm, subject) WITHOUT the detection method, unlike
    // `findingIdentityKey`. These rows come from tables that do not all record
    // one: `crypto_exposures` has no detection-method column, so including it
    // would give that copy an empty method, a different key, and leave the same
    // cipher suite counted twice. For a per-severity EXPOSURE count the unit is
    // "this algorithm on this asset", which is also the unit CBOM components and
    // the QR Engine use. The scanner's finding LIST keeps the method, because
    // there the same algorithm measured two ways is two pieces of evidence.
    const key = [
      String(row.algorithm || '').trim().toLowerCase(),
      normalizeFindingSubject(String(row.subject || '')) || String(row.subject || '').trim().toLowerCase(),
    ].join('|')
    strongest.set(key, Math.max(strongest.get(key) ?? 0, severityWeight(row.severity)))
  }
  const values = [...strongest.values()]
  return {
    critical: values.filter((w) => w === 4).length,
    high: values.filter((w) => w === 3).length,
    medium: values.filter((w) => w === 2).length,
    low: values.filter((w) => w === 1).length,
    total: values.length,
  }
}

/**
 * The more informative of two descriptive strings.
 *
 * Severity is decided by the strongest merged copy, but narrative fields are
 * not: the highest-severity copy is often the terse `crypto_exposures` row while
 * the scan session's copy holds the analyst explanation. Keeping the richer text
 * means nothing a user would read is lost to the merge.
 */
export function richerText(current?: string | null, next?: string | null) {
  const a = String(current || '').trim()
  const b = String(next || '').trim()
  const aGeneric = !a || GENERIC_FINDING_TEXT.has(a.toLowerCase())
  const bGeneric = !b || GENERIC_FINDING_TEXT.has(b.toLowerCase())
  if (aGeneric && !bGeneric) return b
  if (bGeneric && !aGeneric) return a
  return b.length > a.length ? b : a
}
