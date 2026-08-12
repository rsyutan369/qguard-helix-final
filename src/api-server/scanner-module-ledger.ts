/**
 * Scanner module ledger — the authoritative execution model for
 * /api/v1/scanner/stream.
 *
 * WHY THIS EXISTS
 * ---------------
 * The Discovery Workflow used to report "Transport & Ciphers · SKIPPED" and
 * "Certificates & Keys · SKIPPED" on runs that had demonstrably measured both
 * surfaces, and on a truncated run it reported almost every surface as skipped.
 * None of that was a rendering bug. Three separate defects produced it:
 *
 *  1. Two catalogued modules — the key exchange scanner and the signature
 *     algorithm scanner — had NO producer. Nothing in the pipeline ever emitted
 *     a state for them, so they sat at `Queued` for the whole run and the
 *     dashboard, finding them unresolved after the run ended, painted the whole
 *     surface grey.
 *  2. The web-scanner module id → catalog id table matched on loose substrings,
 *     so "Detection Rules Engine" published the *hash algorithm scanner's*
 *     state, masking the fact that the real hash module never ran.
 *  3. A module's outcome was inferred by sniffing the substring "skipped" out
 *     of a free-text error field. A module that legitimately had nothing to
 *     measure and a module that crashed were indistinguishable, and neither
 *     carried a reason the operator could act on.
 *
 * The rules below are the fix, isolated from Express and Supabase so they can
 * be exercised directly by `tools/scanner-module-ledger-check.ts`.
 *
 * INVARIANTS
 * ----------
 *  • Every catalogued module reaches a terminal state before the run's terminal
 *    frame is emitted: Completed, No findings, Failed or Skipped.
 *  • `Skipped` ALWAYS carries a human-readable reason. It means "does not apply
 *    to these targets", never "we lost track of it".
 *  • A module that never reported but WAS applicable is Failed, not Skipped —
 *    an execution gap is reported as an execution gap.
 *  • Exactly one module owns each finding, and it is the module that produced
 *    it, so per-module counts sum to the assessment total.
 */

export type ScannerModuleStatus = 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Skipped' | 'No findings'

/** The catalogued modules, in execution order. */
export const SCANNER_MODULE_CATALOG: Array<{ id: string; name: string }> = [
  { id: 'target-validation', name: 'Target Authorization & Validation' },
  { id: 'dns-security-scanner', name: 'DNS security scanner (CAA/DNSSEC)' },
  { id: 'tls-protocol-scanner', name: 'TLS protocol scanner' },
  { id: 'certificate-scanner', name: 'Certificate scanner' },
  { id: 'cipher-suite-scanner', name: 'Cipher suite scanner' },
  { id: 'key-exchange-scanner', name: 'Key exchange scanner' },
  /* Named-group probing is its OWN module, not a footnote of the key-exchange
     scanner. It answers a different question (which groups the endpoint will
     accept, each offered in isolation) with a different method and a different
     cost — dozens of extra handshakes — so it needs its own terminal state and
     its own reason when it cannot run. */
  { id: 'pq-key-agreement-scanner', name: 'Post-quantum key agreement prober' },
  { id: 'signature-algorithm-scanner', name: 'Signature algorithm scanner' },
  { id: 'hash-algorithm-scanner', name: 'Hash algorithm scanner' },
  { id: 'revocation-transparency-scanner', name: 'Revocation & transparency scanner (OCSP/CT)' },
  { id: 'edge-infrastructure-scanner', name: 'Edge infrastructure scanner' },
  { id: 'ssh-host-key-scanner', name: 'SSH host key scanner' },
  { id: 'jwt-signing-scanner', name: 'JWT signing algorithm scanner' },
  { id: 'dependency-crypto-scanner', name: 'Dependency crypto scanner' },
  { id: 'crypto-detection-rules', name: 'Cryptographic detection rules engine' },
  { id: 'cbom-generator', name: 'CBOM generator' },
  { id: 'scanner2-module-registry', name: 'Scanner_2 module registry' },
  { id: 'scanner2-fingerprint-matcher', name: 'Scanner_2 fingerprint matcher' },
  { id: 'scanner2-detection-rules', name: 'Scanner_2 detection rules engine' },
  { id: 'scanner2-hndl-analyzer', name: 'Scanner_2 HNDL analyzer' },
  { id: 'scanner2-correlation-engine', name: 'Scanner_2 correlation engine' },
  { id: 'scanner2-pqc-migration-engine', name: 'Scanner_2 PQC migration engine' },
  { id: 'scanner2-risk-qscore-engine', name: 'Scanner_2 risk/Q-score engine' },
  { id: 'risk-scoring-engine', name: 'Risk scoring engine' },
  { id: 'crypto-exposure-graph-builder', name: 'Crypto exposure graph builder' },
  { id: 'asset-inventory-synchronizer', name: 'Asset inventory synchronizer' },
  { id: 'audit-history-logger', name: 'Audit/history logger' },
]

export const CATALOG_MODULE_IDS: ReadonlySet<string> = new Set(SCANNER_MODULE_CATALOG.map((module) => module.id))

/**
 * Web-scanner module id → catalog module id.
 *
 * EXACT ids only in this table; the substring fallback in `mapWebModule` exists
 * purely so a module added to the orchestrator before this table is updated
 * still publishes state instead of vanishing.
 */
export const WEB_MODULE_TO_CATALOG: Record<string, string> = {
  'target-parser': 'target-validation',
  'dns-security-analyzer': 'dns-security-scanner',
  'pq-key-agreement-analyzer': 'pq-key-agreement-scanner',
  'revocation-transparency-analyzer': 'revocation-transparency-scanner',
  'edge-infrastructure-analyzer': 'edge-infrastructure-scanner',
  'tls-analyzer': 'tls-protocol-scanner',
  'key-exchange-analyzer': 'key-exchange-scanner',
  'certificate-parser': 'certificate-scanner',
  'signature-algorithm-analyzer': 'signature-algorithm-scanner',
  'hash-algorithm-analyzer': 'hash-algorithm-scanner',
  'cipher-suite-analyzer': 'cipher-suite-scanner',
  'api-security-scanner': 'jwt-signing-scanner',
  'web-crypto-scanner': 'dependency-crypto-scanner',
  'github-scanner': 'dependency-crypto-scanner',
  'detection-rules': 'crypto-detection-rules',
  'risk-scoring-engine': 'risk-scoring-engine',
  'pqc-recommendations': 'risk-scoring-engine',
  'report-generator': 'audit-history-logger',
}

export function mapWebModule(moduleId?: unknown, moduleName?: unknown, phase?: unknown): string | null {
  const rawId = String(moduleId || '')
  const exact = WEB_MODULE_TO_CATALOG[rawId]
  if (exact) return exact

  const id = rawId.toLowerCase()
  const name = String(moduleName || '').toLowerCase()
  const p = String(phase || '').toLowerCase()
  if (id.includes('target-parser') || p.includes('dns')) return 'target-validation'
  if (name.includes('key exchange') || p.includes('key-exchange')) return 'key-exchange-scanner'
  if (name.includes('signature')) return 'signature-algorithm-scanner'
  if (name.includes('hash')) return 'hash-algorithm-scanner'
  if (id.includes('tls') || name.includes('tls') || p.includes('tls')) return 'tls-protocol-scanner'
  if (id.includes('certificate') || name.includes('certificate') || p.includes('cert')) return 'certificate-scanner'
  if (id.includes('cipher') || name.includes('cipher') || p.includes('cipher')) return 'cipher-suite-scanner'
  if (id.includes('api-security') || name.includes('api')) return 'jwt-signing-scanner'
  if (id.includes('web-crypto') || id.includes('github') || name.includes('repository') || p.includes('repo')) return 'dependency-crypto-scanner'
  if (id.includes('detection-rules')) return 'crypto-detection-rules'
  if (id.includes('risk-scoring') || id.includes('pqc-recommendations')) return 'risk-scoring-engine'
  if (id.includes('report')) return 'audit-history-logger'
  return null
}

/**
 * Finding → the catalog module that OWNS it.
 *
 * Order matters: the most specific category wins. "Certificate Signature" is
 * the signature analyzer's output, not the chain parser's, so the signature
 * test runs before the certificate test.
 */
export function moduleIdForFinding(finding: { category: string; detectionMethod: string; algorithm: string }): string {
  const category = finding.category.toLowerCase()
  const method = (finding.detectionMethod || '').toLowerCase()
  const algorithm = (finding.algorithm || '').toLowerCase()

  if (category.includes('ssh')) return 'ssh-host-key-scanner'

  /* Code-origin categories are qualified by their SOURCE, not by the algorithm
     class inside the parentheses: "Source Code (asymmetric)", "Web Crypto
     (hash)", "Source Code (signature)". They must be claimed before the
     algorithm-class tests below, or "Web Crypto (hash)" is filed under the
     certificate hash analyzer — an observation from a JavaScript bundle
     attributed to the TLS certificate chain.

     `detectionMethod` here is the PHASE the finding was emitted in, which is a
     statement about pipeline position, not provenance. A `method.includes('deep')`
     clause used to live in this list and it routed the AES-256-GCM cipher-suite
     observation — emitted during the `deep-scan` phase — onto the Code &
     Dependencies surface. Being the only finding there, and SAFE, it scored that
     surface 100/100 "Elite" on a target whose source code had never been read.
     Every genuine code finding is already claimed by its category above, so the
     phase test bought nothing and cost the surface its meaning.

     A `method.includes('repo')` clause went the same way, and for a sharper
     reason: the phase name "report-generation" CONTAINS "repo", so every finding
     emitted while the report was being composed was also filed under the code
     scanner. Ownership is decided by what a finding IS, never by when it was
     produced — which is why nothing below reads `detectionMethod`. */
  if (
    category.includes('source code') ||
    category.includes('web crypto') ||
    category.includes('repository') ||
    category.includes('dependency')
  ) {
    return 'dependency-crypto-scanner'
  }
  if (category.includes('rule (')) return 'crypto-detection-rules'

  /* Public-edge categories are claimed BEFORE the generic algorithm-class tests
     below, because their names collide with them: "Certificate Revocation" and
     "Certificate Transparency" both contain "certificate" and would otherwise
     be filed under the chain parser, and "Post-Quantum Key Agreement" would
     fall through to the risk engine's catch-all. A finding must be owned by the
     module that produced it or the per-module counts stop summing to the
     assessment total. */
  if (category.includes('post-quantum key agreement')) return 'pq-key-agreement-scanner'
  if (category.includes('revocation') || category.includes('transparency')) {
    return 'revocation-transparency-scanner'
  }
  if (category.includes('dns')) return 'dns-security-scanner'

  if (category.includes('signature')) return 'signature-algorithm-scanner'
  if (category === 'oid (hash)' || category.includes('hash')) return 'hash-algorithm-scanner'
  if (category.includes('key exchange')) return 'key-exchange-scanner'
  // `includes('symmetric')` also matches "asymmetric"; the symmetric-encryption
  // surface is matched exactly so an RSA observation is never filed as a cipher
  // suite.
  if (category.includes('cipher') || category === 'symmetric encryption') return 'cipher-suite-scanner'
  if (category.includes('certificate') || category.startsWith('oid (')) return 'certificate-scanner'
  if (category.includes('api') || category.includes('security headers') || algorithm.includes('jwt')) return 'jwt-signing-scanner'
  if (category.includes('protocol') || category.includes('connectivity')) return 'tls-protocol-scanner'
  if (algorithm.includes('sha') || algorithm.includes('md5')) return 'hash-algorithm-scanner'
  return 'risk-scoring-engine'
}

/** Everything a module's terminal frame resolves to. */
export interface ModuleOutcome {
  status: ScannerModuleStatus
  error: string | null
  reason: string | null
  notApplicable: boolean
}

/**
 * Turn a web-scanner `module-complete` frame into a catalog module state.
 *
 * `not-applicable: <reason>` is the orchestrator's explicit signal. Anything
 * else in the error field is a real error, and an error accompanied by evidence
 * is a completed measurement with a caveat rather than a failure.
 */
export function classifyModuleOutcome(errorText: string | null, findingCount: number): ModuleOutcome {
  const text = (errorText || '').trim()
  if (!text) {
    return {
      status: findingCount === 0 ? 'No findings' : 'Completed',
      error: null,
      reason: null,
      notApplicable: false,
    }
  }

  const lower = text.toLowerCase()
  const naMatch = text.match(/^not-applicable:\s*(.+)$/i) || text.match(/^skipped:\s*(.+)$/i)
  if (naMatch) {
    return { status: 'Skipped', error: null, reason: naMatch[1].trim(), notApplicable: true }
  }
  if (lower.startsWith('skipped')) {
    return { status: 'Skipped', error: null, reason: text.replace(/^skipped\s*/i, '').trim() || text, notApplicable: true }
  }
  if (findingCount > 0) {
    return { status: 'Completed', error: null, reason: `Completed with a caveat: ${text}`, notApplicable: false }
  }
  return { status: 'Failed', error: text, reason: text, notApplicable: false }
}

/**
 * Which catalog modules cannot apply to a given set of authorized targets, and
 * why. Used to close out the ledger so no module is ever left `Queued` — the
 * state the dashboard used to render as an unexplained "Skipped".
 */
export function moduleApplicability(targets: Array<{ type: string }>): Record<string, string> {
  const types = new Set(targets.map((target) => target.type))
  const hasSsh = types.has('ssh')
  const hasNetwork = targets.some((target) => target.type !== 'ssh' && target.type !== 'github')
  const hasRepo = types.has('github')
  const hasUrl = types.has('url')
  const typeList = Array.from(types).join(', ') || 'none'

  const reasons: Record<string, string> = {}
  const transportReason = `no TLS endpoint was in scope for this run (target types: ${typeList})`
  if (!hasNetwork) {
    for (const moduleId of [
      'tls-protocol-scanner',
      'certificate-scanner',
      'cipher-suite-scanner',
      'key-exchange-scanner',
      'pq-key-agreement-scanner',
      'signature-algorithm-scanner',
      'hash-algorithm-scanner',
      'revocation-transparency-scanner',
    ]) {
      reasons[moduleId] = transportReason
    }
    reasons['dns-security-scanner'] = `no resolvable host was in scope for this run (target types: ${typeList})`
    reasons['edge-infrastructure-scanner'] = `no HTTP origin was in scope for this run (target types: ${typeList})`
  }
  if (!hasSsh) reasons['ssh-host-key-scanner'] = `no SSH target was authorized for this run (target types: ${typeList})`
  if (!hasNetwork) reasons['jwt-signing-scanner'] = `token and header analysis needs an HTTP endpoint (target types: ${typeList})`
  if (!hasRepo && !hasUrl) {
    reasons['dependency-crypto-scanner'] = `no repository or page was in scope to read application cryptography from (target types: ${typeList})`
  }
  return reasons
}
