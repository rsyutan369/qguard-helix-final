/**
 * Offline verification for the scanner's module execution ledger.
 *
 * This is the regression suite for the "Discovery Workflow shows SKIPPED"
 * class of defect. It proves, without a server or a network, that:
 *
 *   • every module the web-scan orchestrator emits maps to a real catalog
 *     module — so no module can silently have zero producers again,
 *   • every catalog module HAS a producer (an orchestrator module, an
 *     applicability rule, or the API layer's own lifecycle),
 *   • a module outcome is classified as Completed / No findings / Failed /
 *     Not-applicable-with-a-reason, never an unexplained skip,
 *   • finding ownership is total and unique, and the per-module counts sum to
 *     the assessment total,
 *   • closing the ledger leaves NO module unresolved, for every target mix.
 *
 *   npx tsx tools/scanner-module-ledger-check.ts
 */
import {
  CATALOG_MODULE_IDS,
  SCANNER_MODULE_CATALOG,
  WEB_MODULE_TO_CATALOG,
  classifyModuleOutcome,
  mapWebModule,
  moduleApplicability,
  moduleIdForFinding,
  type ScannerModuleStatus,
} from '../src/api-server/scanner-module-ledger'
import {
  MODULE_NODE,
  SCANNER_NODE_MODULES,
  nodeForFindingCategory,
} from '../src/app/dashboard/scanner_dashboard/_intel'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/* ------------------------------------------------------------------ routing */

/**
 * Every module id the orchestrator emits `module-start` / `module-complete`
 * for. Kept in sync by hand with `src/lib/scanner/web-scanner/scan-orchestrator.ts`;
 * the mapping assertion below is what catches drift.
 */
const ORCHESTRATOR_MODULE_IDS = [
  'target-parser',
  'dns-security-analyzer',
  'pq-key-agreement-analyzer',
  'revocation-transparency-analyzer',
  'edge-infrastructure-analyzer',
  'tls-analyzer',
  'key-exchange-analyzer',
  'certificate-parser',
  'signature-algorithm-analyzer',
  'hash-algorithm-analyzer',
  'cipher-suite-analyzer',
  'api-security-scanner',
  'web-crypto-scanner',
  'github-scanner',
  'detection-rules',
  'risk-scoring-engine',
  'pqc-recommendations',
  'report-generator',
]

function verifyRouting() {
  console.log('\n=== Web-scanner module routing ===')

  for (const id of ORCHESTRATOR_MODULE_IDS) {
    const mapped = mapWebModule(id, id, '')
    assert(
      mapped !== null && CATALOG_MODULE_IDS.has(mapped),
      `"${id}" routes to a real catalog module (${mapped ?? 'UNMAPPED'})`,
    )
  }

  // The three modules that had no producer at all, and produced the reported bug.
  assert(mapWebModule('key-exchange-analyzer') === 'key-exchange-scanner', 'Key exchange analyzer now feeds the key exchange scanner')
  assert(mapWebModule('signature-algorithm-analyzer') === 'signature-algorithm-scanner', 'Signature analyzer now feeds the signature scanner')
  assert(mapWebModule('hash-algorithm-analyzer') === 'hash-algorithm-scanner', 'Hash analyzer now feeds the hash scanner')

  // The mis-routing that hid the gap.
  assert(
    mapWebModule('detection-rules') !== 'hash-algorithm-scanner',
    'Detection rules no longer masquerade as the hash algorithm scanner',
  )
  assert(mapWebModule('detection-rules') === 'crypto-detection-rules', 'Detection rules have their own catalog module')

  assert(
    Object.values(WEB_MODULE_TO_CATALOG).every((id) => CATALOG_MODULE_IDS.has(id)),
    'Every routing-table target is a catalog module',
  )
}

/* --------------------------------------------------------------- producers */

/**
 * Modules the API layer drives itself (not via the web scan): the Scanner_2
 * pass, persistence and the run-level engines.
 */
const API_DRIVEN_MODULES = [
  'target-validation',
  'ssh-host-key-scanner',
  'cbom-generator',
  'scanner2-module-registry',
  'scanner2-fingerprint-matcher',
  'scanner2-detection-rules',
  'scanner2-hndl-analyzer',
  'scanner2-correlation-engine',
  'scanner2-pqc-migration-engine',
  'scanner2-risk-qscore-engine',
  'risk-scoring-engine',
  'crypto-exposure-graph-builder',
  'asset-inventory-synchronizer',
  'audit-history-logger',
]

function verifyEveryModuleHasAProducer() {
  console.log('\n=== Every catalog module has a producer ===')
  const producedByWeb = new Set(Object.values(WEB_MODULE_TO_CATALOG))
  const producedByApi = new Set(API_DRIVEN_MODULES)

  for (const module of SCANNER_MODULE_CATALOG) {
    const covered = producedByWeb.has(module.id) || producedByApi.has(module.id)
    assert(covered, `"${module.name}" has a producer`)
  }
}

/* ------------------------------------------------------------ classification */

function verifyOutcomeClassification() {
  console.log('\n=== Module outcome classification ===')

  const clean = classifyModuleOutcome(null, 4)
  assert(clean.status === 'Completed' && clean.reason === null, 'Evidence with no error → Completed')

  const empty = classifyModuleOutcome(null, 0)
  assert(empty.status === 'No findings', 'No evidence and no error → No findings (a measurement, not a gap)')

  const na = classifyModuleOutcome('not-applicable: cipher suite enumeration requires a completed TLS handshake', 0)
  assert(na.status === 'Skipped', 'Explicit not-applicable → Skipped')
  assert(na.notApplicable === true, 'Not-applicable is flagged as such')
  assert(
    na.reason === 'cipher suite enumeration requires a completed TLS handshake',
    `The reason survives verbatim (${na.reason})`,
  )
  assert(na.error === null, 'A not-applicable module carries no error')

  const legacy = classifyModuleOutcome('Skipped: certificate metadata unavailable', 0)
  assert(legacy.status === 'Skipped' && legacy.reason === 'certificate metadata unavailable', 'Legacy "Skipped:" form still parses, with its reason')

  const broke = classifyModuleOutcome('ECONNREFUSED 10.0.0.1:443', 0)
  assert(broke.status === 'Failed', 'A real error with no evidence → Failed')
  assert(broke.error === 'ECONNREFUSED 10.0.0.1:443', 'The error text is preserved for the operator')

  const caveat = classifyModuleOutcome('TLS Analyzer timed out after 45000ms', 6)
  assert(caveat.status === 'Completed', 'An error alongside evidence → Completed with a caveat, not Failed')
  assert((caveat.reason ?? '').startsWith('Completed with a caveat'), 'The caveat is recorded')

  // The invariant the whole change exists to enforce.
  for (const [error, count] of [
    [null, 0],
    [null, 3],
    ['not-applicable: no TLS endpoint', 0],
    ['Skipped: legacy', 0],
    ['boom', 0],
    ['boom', 2],
  ] as Array<[string | null, number]>) {
    const outcome = classifyModuleOutcome(error, count)
    assert(
      outcome.status !== 'Skipped' || Boolean(outcome.reason),
      `Skipped always carries a reason (error=${String(error)}, findings=${count})`,
    )
  }
}

/* -------------------------------------------------------- finding ownership */

/** Every category the live scanners emit, with the module that produces it. */
const CATEGORY_OWNERS: Array<[string, string]> = [
  ['Key Exchange', 'key-exchange-scanner'],
  ['Key Exchange (Harvest Now Decrypt Later)', 'key-exchange-scanner'],
  ['Protocol', 'tls-protocol-scanner'],
  ['Protocol Support', 'tls-protocol-scanner'],
  ['Connectivity', 'tls-protocol-scanner'],
  ['Cipher Suite', 'cipher-suite-scanner'],
  ['Symmetric Encryption', 'cipher-suite-scanner'],
  ['Certificate', 'certificate-scanner'],
  ['Certificate Signature', 'signature-algorithm-scanner'],
  ['OID (RSA)', 'certificate-scanner'],
  ['OID (ECC)', 'certificate-scanner'],
  ['OID (HASH)', 'hash-algorithm-scanner'],
  ['SSH Host Key', 'ssh-host-key-scanner'],
  /* The API probe emits two classes of observation and they belong to two
     surfaces. HSTS and Information Disclosure are application-layer facts; only
     signing material is identity. While both were owned by the JWT scanner, the
     Identity & Tokens card reported "2 findings" for an endpoint that issues no
     tokens, directly above its own "nothing to read" empty state. */
  ['API Security', 'http-security-scanner'],
  ['Security Headers', 'http-security-scanner'],
  ['Cookie Security', 'http-security-scanner'],
  ['Source Code (asymmetric)', 'dependency-crypto-scanner'],
  ['Web Crypto (hash)', 'dependency-crypto-scanner'],
  ['Repository Access', 'dependency-crypto-scanner'],
  ['Repository Scan Error', 'dependency-crypto-scanner'],
  ['Rule (Post Quantum)', 'crypto-detection-rules'],
  ['NIST Compliance', 'risk-scoring-engine'],
]

function verifyFindingOwnership() {
  console.log('\n=== Finding ownership ===')

  for (const [category, expected] of CATEGORY_OWNERS) {
    const owner = moduleIdForFinding({ category, detectionMethod: 'scan', algorithm: 'RSA-2048' })
    assert(owner === expected, `"${category}" → ${expected} (got ${owner})`)
  }

  /* Ownership must not depend on the PHASE a finding was emitted in.
     `detectionMethod` carries the pipeline phase, and a `method.includes('deep')`
     clause used to route anything emitted during `deep-scan` to the dependency
     scanner. That is how the AES-256-GCM cipher-suite observation ended up as the
     ONLY finding on the Code & Dependencies surface and — being SAFE — scored it
     "Elite 100" for a target whose source code had never been read.

     Asserted across every phase name the orchestrator uses, so no future finding
     can inherit a surface from where it happened to be emitted. */
  const PHASES = ['initializing', 'edge-intelligence', 'tls-handshake', 'key-exchange', 'cert-analysis', 'cipher-enum', 'header-inspection', 'deep-scan', 'repo-scan', 'risk-calculation', 'report-generation']
  for (const [category, expected] of CATEGORY_OWNERS) {
    for (const phase of PHASES) {
      const owner = moduleIdForFinding({ category, detectionMethod: phase, algorithm: 'AES-256-GCM' })
      assert(
        owner === expected,
        `"${category}" is owned by ${expected} regardless of phase (phase=${phase} gave ${owner})`,
      )
    }
  }

  /* The exact regression, stated as itself: a negotiated cipher suite belongs to
     the transport surface, never to Code & Dependencies. */
  assert(
    nodeForFindingCategory('Symmetric Encryption', 'cipher-enum', 'AES-256-GCM') === 'transport',
    'a negotiated cipher suite is transport evidence, not code evidence',
  )
  assert(
    nodeForFindingCategory('Symmetric Encryption', 'deep-scan', 'AES-256-GCM') === 'transport',
    'and stays transport evidence even if emitted during the client-code phase',
  )

  // Ownership must be total: every category resolves to a catalog module.
  for (const [category] of CATEGORY_OWNERS) {
    const owner = moduleIdForFinding({ category, detectionMethod: '', algorithm: '' })
    assert(CATALOG_MODULE_IDS.has(owner), `"${category}" resolves inside the catalog`)
  }
  assert(
    CATALOG_MODULE_IDS.has(moduleIdForFinding({ category: 'Something Unforeseen', detectionMethod: '', algorithm: '' })),
    'An unrecognised category still resolves to a catalog module',
  )

  // The specific mis-attribution that emptied the signature scanner: a
  // certificate signature whose algorithm NAME contains "sha" must belong to
  // the signature analyzer, not the hash analyzer.
  assert(
    moduleIdForFinding({
      category: 'Certificate Signature',
      detectionMethod: 'certificate-scan',
      algorithm: 'sha256WithRSAEncryption (Signature)',
    }) === 'signature-algorithm-scanner',
    'sha256WithRSAEncryption signatures belong to the signature scanner, not the hash scanner',
  )

  // Counts must tally: per-module sums equal the total finding count.
  const findings = CATEGORY_OWNERS.map(([category], index) => ({
    id: `f${index}`,
    category,
    detectionMethod: 'scan',
    algorithm: 'RSA-2048',
  }))
  const ledger = new Map<string, number>()
  for (const finding of findings) {
    const owner = moduleIdForFinding(finding)
    ledger.set(owner, (ledger.get(owner) ?? 0) + 1)
  }
  const summed = Array.from(ledger.values()).reduce((sum, value) => sum + value, 0)
  assert(summed === findings.length, `Per-module counts sum to the total (${summed}/${findings.length})`)
}

/* ---------------------------------------------------------- ledger closure */

interface LedgerModule {
  id: string
  name: string
  status: ScannerModuleStatus
  reason: string | null
}

/**
 * Reproduces `closeModuleLedger` from the stream route: no module may be left
 * Queued or Running, and a Skipped must always carry a reason.
 */
function closeLedger(modules: LedgerModule[], targets: Array<{ type: string }>, abortReason: string | null) {
  const applicability = moduleApplicability(targets)
  for (const module of modules) {
    if (module.status !== 'Queued' && module.status !== 'Running') continue
    const reason = applicability[module.id]
    if (reason && module.status === 'Queued') {
      module.status = 'Skipped'
      module.reason = reason
      continue
    }
    const failure = abortReason
      ? `Scan ended before this module reported: ${abortReason}`
      : 'Module did not report a terminal state before the run finished'
    module.status = 'Failed'
    module.reason = failure
  }
  return modules
}

function freshLedger(): LedgerModule[] {
  return SCANNER_MODULE_CATALOG.map((module) => ({ id: module.id, name: module.name, status: 'Queued' as ScannerModuleStatus, reason: null }))
}

function verifyLedgerClosure() {
  console.log('\n=== Ledger closure — no module left unresolved ===')

  const mixes: Array<[string, Array<{ type: string }>]> = [
    ['single URL', [{ type: 'url' }]],
    ['domain only', [{ type: 'domain' }]],
    ['GitHub repo only', [{ type: 'github' }]],
    ['SSH only', [{ type: 'ssh' }]],
    ['URL + repo + SSH', [{ type: 'url' }, { type: 'github' }, { type: 'ssh' }]],
    ['IP only', [{ type: 'ip' }]],
  ]

  for (const [label, targets] of mixes) {
    const closed = closeLedger(freshLedger(), targets, null)
    const unresolved = closed.filter((module) => module.status === 'Queued' || module.status === 'Running')
    assert(unresolved.length === 0, `${label}: no module left Queued/Running`)

    const unexplained = closed.filter((module) => module.status === 'Skipped' && !module.reason)
    assert(unexplained.length === 0, `${label}: every Skipped carries a reason`)

    const skipped = closed.filter((module) => module.status === 'Skipped')
    assert(
      skipped.every((module) => (module.reason ?? '').length > 20),
      `${label}: reasons are operator-readable sentences`,
    )
  }

  // A GitHub-only run must not claim the transport modules failed — they do not
  // apply, and the reason says so.
  const repoOnly = closeLedger(freshLedger(), [{ type: 'github' }], null)
  const tls = repoOnly.find((module) => module.id === 'tls-protocol-scanner')!
  assert(tls.status === 'Skipped', 'Repo-only run: TLS scanner is Not applicable, not Failed')
  assert((tls.reason ?? '').includes('no TLS endpoint'), `Repo-only run: the reason names the cause (${tls.reason})`)

  // An SSH-only run must not claim the repository scanner ran.
  const sshOnly = closeLedger(freshLedger(), [{ type: 'ssh' }], null)
  const dep = sshOnly.find((module) => module.id === 'dependency-crypto-scanner')!
  assert(dep.status === 'Skipped' && Boolean(dep.reason), `SSH-only run: dependency scanner is explained (${dep.reason})`)

  // A URL run reaches every surface: nothing may be declared inapplicable
  // except the SSH probe.
  const urlOnly = closeLedger(freshLedger(), [{ type: 'url' }], null)
  const urlSkipped = urlOnly.filter((module) => module.status === 'Skipped').map((module) => module.id)
  assert(
    urlSkipped.length === 1 && urlSkipped[0] === 'ssh-host-key-scanner',
    `URL run: only the SSH probe is inapplicable (${urlSkipped.join(', ') || 'none'})`,
  )

  // THE REGRESSION. On a URL scan the transport and certificate surfaces must
  // be applicable, so an unreported module there is reported as an execution
  // failure — never quietly downgraded to "skipped".
  for (const id of ['key-exchange-scanner', 'signature-algorithm-scanner', 'hash-algorithm-scanner', 'cipher-suite-scanner']) {
    const module = urlOnly.find((entry) => entry.id === id)!
    assert(module.status === 'Failed', `URL run: unreported "${id}" is Failed, not Skipped`)
  }

  // A cut-short run names the abort cause on every unresolved module.
  const aborted = closeLedger(freshLedger(), [{ type: 'url' }], 'cancelled by operator')
  const abortedFailures = aborted.filter((module) => module.status === 'Failed')
  assert(
    abortedFailures.length > 0 && abortedFailures.every((module) => (module.reason ?? '').includes('cancelled by operator')),
    'Cancelled run: every unresolved module names the abort cause',
  )
}

/* ------------------------------------------------- catalog ↔ surface map -- */

/**
 * The six Discovery Workflow surfaces must partition the catalog exactly.
 *
 * A module missing from the map is invisible on the rail; a module in two
 * surfaces is double-counted. Either one desynchronises the rail, Discovery
 * Coverage and Module Execution Flow from each other.
 */
function verifySurfacePartition() {
  console.log('\n=== Discovery surfaces partition the module catalog ===')

  const assigned = Object.values(SCANNER_NODE_MODULES).flat()
  const seen = new Map<string, number>()
  for (const id of assigned) seen.set(id, (seen.get(id) ?? 0) + 1)

  for (const module of SCANNER_MODULE_CATALOG) {
    assert(seen.get(module.id) === 1, `"${module.name}" belongs to exactly one surface (${seen.get(module.id) ?? 0})`)
  }
  assert(
    assigned.length === SCANNER_MODULE_CATALOG.length,
    `No surface references a module outside the catalog (${assigned.length} assigned / ${SCANNER_MODULE_CATALOG.length} catalogued)`,
  )
  for (const id of assigned) {
    assert(CATALOG_MODULE_IDS.has(id), `Surface module "${id}" exists in the catalog`)
  }

  /* Finding → surface must go through finding → module → surface, so a node
     card's finding list and its modules' counts describe the same set. */
  for (const [category, expectedModule] of CATEGORY_OWNERS) {
    const surface = nodeForFindingCategory(category, 'scan', 'RSA-2048')
    assert(
      surface === MODULE_NODE[expectedModule],
      `"${category}" lands on the surface of its owning module (${surface} / ${MODULE_NODE[expectedModule]})`,
    )
  }
}

/* ------------------------------------------------------------------- driver */

verifyRouting()
verifySurfacePartition()
verifyEveryModuleHasAProducer()
verifyOutcomeClassification()
verifyFindingOwnership()
verifyLedgerClosure()

console.log('')
if (failures > 0) {
  console.error(`${failures} scanner module ledger check(s) FAILED.`)
  process.exit(1)
}
console.log('All scanner module ledger checks passed.')
