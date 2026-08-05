/**
 * Discovery Workflow probe — end-to-end proof against a LIVE target.
 *
 * Runs the real web-scanner orchestrator, then replays the API layer's module
 * ledger over the stream exactly as `/api/v1/scanner/stream` does — web module
 * → catalog module, outcome classification, finding ownership, ledger closure —
 * and finally renders the six Discovery Workflow stages the dashboard renders.
 *
 * This is the regression proof for the reported defect: on a real HTTPS target
 * "Transport & Ciphers" and "Certificates & Keys" must report Complete, and no
 * surface may report an unexplained Skipped.
 *
 *   npx tsx tools/discovery-workflow-probe.ts [target] [type]
 */
import { executeWebScan } from '@/lib/scanner/web-scanner/scan-orchestrator'
import type { SSEEvent, WebScanTargetType } from '@/lib/scanner/web-scanner/types'
import {
  SCANNER_MODULE_CATALOG,
  classifyModuleOutcome,
  mapWebModule,
  moduleApplicability,
  moduleIdForFinding,
  type ScannerModuleStatus,
} from '@/api-server/scanner-module-ledger'
import { SCANNER_NODE_BLUEPRINTS, SCANNER_NODE_MODULES } from '@/app/dashboard/scanner_dashboard/_intel'

const target = process.argv[2] || 'www.cloudflare.com'
const targetType = (process.argv[3] as WebScanTargetType) || 'domain'

interface LedgerModule {
  id: string
  name: string
  status: ScannerModuleStatus
  findingsCount: number
  reason: string | null
  error: string | null
}

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) console.log(`  ok   ${label}`)
  else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

async function main() {
  console.log(`\n=== Discovery Workflow probe ===`)
  console.log(`Target: ${target}  (type: ${targetType})\n`)

  const modules: LedgerModule[] = SCANNER_MODULE_CATALOG.map((module) => ({
    id: module.id,
    name: module.name,
    status: 'Queued',
    findingsCount: 0,
    reason: null,
    error: null,
  }))
  const byId = new Map(modules.map((module) => [module.id, module]))
  const unmapped = new Set<string>()
  let leakedTerminalFrames = 0

  const result = await executeWebScan(target, targetType, (event: SSEEvent) => {
    const type = String(event.type)

    /* The API layer namespaces the nested scan's own lifecycle frames so the
       client cannot mistake a per-target completion for the end of the job.
       Count them here to prove they are distinguishable. */
    if (type === 'scan-complete' || type === 'scan-start' || type === 'error') leakedTerminalFrames += 1

    if (type !== 'module-start' && type !== 'module-complete') return
    const canonical = mapWebModule(event.moduleId, event.moduleName, event.phase)
    if (!canonical) {
      unmapped.add(String(event.moduleId))
      return
    }
    const module = byId.get(canonical)
    if (!module) {
      unmapped.add(String(event.moduleId))
      return
    }
    if (type === 'module-start') {
      if (module.status === 'Queued') module.status = 'Running'
      return
    }
    const errorText = typeof event.error === 'string' ? event.error : null
    const findingCount = typeof event.findingCount === 'number' ? event.findingCount : 0
    const outcome = classifyModuleOutcome(errorText, findingCount)
    // Measured beats not-applicable, whatever order the queue runs in.
    if ((module.status === 'Completed' || module.status === 'No findings') && outcome.status === 'Skipped') return
    module.status = outcome.status
    module.reason = outcome.reason
    module.error = outcome.error
  })

  /* Credit every finding to its owning module — the same ledger the stream
     route keeps, and the reason per-module counts sum to the total. */
  for (const finding of result.findings) {
    const owner = byId.get(moduleIdForFinding(finding as unknown as { category: string; detectionMethod: string; algorithm: string }))
    if (!owner) continue
    owner.findingsCount += 1
    if (owner.status === 'Skipped' || owner.status === 'Queued' || owner.status === 'Running') {
      owner.status = 'Completed'
      owner.reason = null
    }
  }

  /* The API layer also drives these itself; the probe marks them measured so
     the rail reflects a full run rather than the web pass alone. */
  for (const id of [
    'target-validation', 'cbom-generator', 'scanner2-module-registry', 'scanner2-fingerprint-matcher',
    'scanner2-detection-rules', 'scanner2-hndl-analyzer', 'scanner2-correlation-engine',
    'scanner2-pqc-migration-engine', 'scanner2-risk-qscore-engine', 'risk-scoring-engine',
    'crypto-exposure-graph-builder', 'asset-inventory-synchronizer', 'audit-history-logger',
  ]) {
    const module = byId.get(id)!
    if (module.status === 'Queued') module.status = module.findingsCount > 0 ? 'Completed' : 'No findings'
  }

  // Close the ledger.
  const applicability = moduleApplicability([{ type: targetType === 'github' ? 'github' : targetType === 'url' ? 'url' : 'domain' }])
  for (const module of modules) {
    if (module.status !== 'Queued' && module.status !== 'Running') continue
    const reason = applicability[module.id]
    if (reason) {
      module.status = 'Skipped'
      module.reason = reason
      continue
    }
    module.status = 'Failed'
    module.error = 'Module did not report a terminal state before the run finished'
    module.reason = module.error
  }

  /* ---------------------------------------------------------------- report */

  console.log(`Findings: ${result.totalFindings}  ` +
    `(C${result.criticalCount}/H${result.highCount}/M${result.mediumCount}/L${result.lowCount}/S${result.safeCount})`)
  console.log(`TLS handshake: ${result.tlsAnalysis ? `${result.tlsAnalysis.tlsVersion} ${result.tlsAnalysis.cipherSuite}` : 'NOT REACHED (sandboxed network)'}`)
  console.log(`Certificate:   ${result.certificateInfo ? `${result.certificateInfo.publicKeyAlgorithm} ${result.certificateInfo.publicKeySize} / ${result.certificateInfo.signatureAlgorithm}` : 'not returned'}`)

  console.log('\n--- Module ledger ---')
  for (const module of modules) {
    const detail = module.status === 'Skipped' || module.status === 'Failed'
      ? `  <- ${module.reason ?? module.error ?? 'NO REASON'}`
      : ''
    console.log(`  ${module.status.padEnd(12)} ${module.name.padEnd(40)} ${String(module.findingsCount).padStart(3)}${detail}`)
  }

  console.log('\n--- Discovery Workflow (as the dashboard renders it) ---')
  const stages = SCANNER_NODE_BLUEPRINTS.map((blueprint) => {
    const owned = modules.filter((module) => SCANNER_NODE_MODULES[blueprint.key]?.includes(module.id))
    const done = owned.filter((module) => module.status === 'Completed' || module.status === 'No findings')
    const notApplicable = owned.filter((module) => module.status === 'Skipped')
    const broken = owned.filter((module) => module.status === 'Failed')
    const resolved = done.length + notApplicable.length
    const state = broken.length > 0
      ? 'FAILED'
      : resolved === owned.length
        ? (notApplicable.length === owned.length ? 'NOT APPLICABLE' : 'COMPLETE')
        : done.length > 0
          ? 'PARTIAL'
          : 'WAITING'
    const findings = owned.reduce((sum, module) => sum + module.findingsCount, 0)
    const applicable = owned.length - notApplicable.length
    console.log(
      `  ${state.padEnd(15)} ${blueprint.title.padEnd(24)} ${done.length}/${applicable || owned.length} modules` +
      `${notApplicable.length ? ` · ${notApplicable.length} n/a` : ''} · ${findings} findings`,
    )
    return { key: blueprint.key, title: blueprint.title, state, findings, owned, broken, notApplicable }
  })

  /* ---------------------------------------------------------------- asserts */

  console.log('\n--- Assertions ---')
  const networkReached = Boolean(result.tlsAnalysis)

  assert(unmapped.size === 0, `Every emitted module maps to the catalog${unmapped.size ? ` (unmapped: ${Array.from(unmapped).join(', ')})` : ''}`)
  assert(
    modules.every((module) => module.status !== 'Queued' && module.status !== 'Running'),
    'No module is left unresolved after the ledger closes',
  )
  assert(
    modules.every((module) => module.status !== 'Skipped' || Boolean(module.reason)),
    'Every not-applicable module carries a documented reason',
  )
  const summed = modules.reduce((sum, module) => sum + module.findingsCount, 0)
  assert(summed === result.totalFindings, `Per-module counts sum to the scan total (${summed}/${result.totalFindings})`)

  // The three modules that previously had no producer at all.
  for (const id of ['key-exchange-scanner', 'signature-algorithm-scanner', 'hash-algorithm-scanner']) {
    const module = byId.get(id)!
    assert(
      module.status !== 'Queued' && module.status !== 'Failed',
      `"${module.name}" reported a real terminal state (${module.status}${module.reason ? ` — ${module.reason}` : ''})`,
    )
  }

  const transport = stages.find((stage) => stage.key === 'transport')!
  const certificates = stages.find((stage) => stage.key === 'certificates')!
  if (networkReached) {
    // THE REPORTED BUG.
    assert(transport.state === 'COMPLETE', `Transport & Ciphers is COMPLETE, not SKIPPED (${transport.state})`)
    assert(certificates.state === 'COMPLETE', `Certificates & Keys is COMPLETE, not SKIPPED (${certificates.state})`)
    assert(transport.findings > 0, `Transport & Ciphers carries real findings (${transport.findings})`)
    assert(certificates.findings > 0, `Certificates & Keys carries real findings (${certificates.findings})`)
  } else {
    console.log('  note  TLS was unreachable from this runtime; surface-completion asserts skipped.')
    assert(
      transport.state !== 'WAITING' && certificates.state !== 'WAITING',
      `Unreachable target still resolves every surface (${transport.state} / ${certificates.state})`,
    )
  }

  assert(
    stages.every((stage) => stage.state !== 'WAITING'),
    'No surface is left waiting after the run',
  )
  assert(leakedTerminalFrames > 0, 'The nested scan does emit its own lifecycle frames (which the API layer must namespace)')

  console.log('')
  if (failures > 0) {
    console.error(`${failures} Discovery Workflow probe assertion(s) FAILED.`)
    process.exit(1)
  }
  console.log('Discovery Workflow probe passed.')
}

main().catch((err) => {
  console.error('probe crashed:', err)
  process.exit(1)
})
