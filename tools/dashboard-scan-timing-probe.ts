/**
 * Dashboard scanner timing probe.
 *
 * Runs the authenticated orchestrator's web-scan pipeline (`executeWebScan`)
 * against a live target and prints the wall-clock cost of every phase and
 * module, so a claim about where /dashboard/scanner spends its time is a
 * measurement rather than an estimate. No Supabase, no auth — the persistence
 * layer is excluded on purpose so the scanning cost is isolated.
 *
 *   npx tsx tools/dashboard-scan-timing-probe.ts example.com domain
 */

import { executeWebScan } from '../src/lib/scanner/web-scanner/scan-orchestrator'
import type { WebScanTargetType } from '../src/lib/scanner/web-scanner/types'

const target = process.argv[2] || 'example.com'
const targetType = (process.argv[3] || 'domain') as WebScanTargetType

async function main() {
  const t0 = Date.now()
  const at = () => ((Date.now() - t0) / 1000).toFixed(2).padStart(6)
  const phaseStart = new Map<string, number>()
  const moduleStart = new Map<string, number>()
  const moduleCost: Array<{ id: string; seconds: number; findings: number; error: string | null }> = []
  const phaseCost: Array<{ phase: string; seconds: number }> = []
  let findings = 0

  console.log(`\n=== dashboard scan timing: ${target} (${targetType}) ===\n`)

  const result = await executeWebScan(target, targetType, (event) => {
    if (event.type === 'phase-start') {
      phaseStart.set(String(event.phase), Date.now())
      console.log(`[${at()}s] PHASE  ▶ ${event.phase}`)
    }
    if (event.type === 'phase-complete') {
      const started = phaseStart.get(String(event.phase)) ?? t0
      const seconds = (Date.now() - started) / 1000
      phaseCost.push({ phase: String(event.phase), seconds })
      console.log(`[${at()}s] PHASE  ■ ${event.phase} (${seconds.toFixed(2)}s)`)
    }
    if (event.type === 'module-start') {
      moduleStart.set(String(event.moduleId), Date.now())
    }
    if (event.type === 'module-complete') {
      const id = String(event.moduleId)
      const started = moduleStart.get(id) ?? t0
      const seconds = (Date.now() - started) / 1000
      const error = typeof event.error === 'string' ? event.error : null
      moduleCost.push({ id, seconds, findings: Number(event.findingCount ?? 0), error })
      console.log(
        `[${at()}s]   module ${id.padEnd(34)} ${seconds.toFixed(2).padStart(6)}s  findings=${event.findingCount ?? 0}${error ? `  ← ${error.slice(0, 70)}` : ''}`,
      )
    }
    if (event.type === 'finding') findings += 1
  })

  const total = Date.now() - t0

  console.log(`\n--- phases by cost ---`)
  for (const entry of [...phaseCost].sort((a, b) => b.seconds - a.seconds)) {
    console.log(`  ${entry.seconds.toFixed(2).padStart(7)}s  ${entry.phase}`)
  }

  console.log(`\n--- modules by cost ---`)
  for (const entry of [...moduleCost].sort((a, b) => b.seconds - a.seconds).slice(0, 12)) {
    console.log(`  ${entry.seconds.toFixed(2).padStart(7)}s  ${entry.id.padEnd(34)} findings=${entry.findings}`)
  }

  console.log(`\n  findings streamed : ${findings}`)
  console.log(`  findings in result: ${result.findings.length}`)
  console.log(`  risk score        : ${result.overallRiskScore} (${result.riskLevel})`)
  console.log(`  quantum readiness : ${result.quantumReadinessScore} (${result.quantumReadinessLevel})`)
  console.log(`\n=== TOTAL ${(total / 1000).toFixed(2)}s ===\n`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
