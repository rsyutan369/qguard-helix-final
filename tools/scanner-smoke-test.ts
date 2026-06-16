/**
 * Scanner smoke test — proves the web-scanner engine performs REAL detection
 * end-to-end against a live target (no mocks). Run:
 *   npx tsx tools/scanner-smoke-test.ts [target] [type]
 * Defaults to tls-v1-2.badssl.com (forces legacy TLS 1.2 + classical cert).
 */
import { executeWebScan } from '@/lib/scanner/web-scanner/scan-orchestrator'
import type { SSEEvent, WebScanTargetType } from '@/lib/scanner/web-scanner/types'

const target = process.argv[2] || 'tls-v1-2.badssl.com'
const targetType = (process.argv[3] as WebScanTargetType) || 'domain'

async function main() {
  console.log(`\n=== QGuard web-scanner smoke test ===`)
  console.log(`Target: ${target}  (type: ${targetType})\n`)

  const phases = new Set<string>()
  let eventCount = 0

  const result = await executeWebScan(target, targetType, (event: SSEEvent) => {
    eventCount++
    const t = (event as { type?: string }).type
    if (t === 'phase-start' || t === 'module-start') {
      const name = (event as { phase?: string; module?: string }).phase
        || (event as { module?: string }).module
      if (name) phases.add(String(name))
    }
  })

  console.log(`SSE events streamed: ${eventCount}`)
  console.log(`Scan phases/modules exercised: ${phases.size}`)
  console.log(`Scan duration: ${result.scanDuration}ms\n`)

  console.log(`--- SUMMARY (real, computed from live scan) ---`)
  console.log(`  totalFindings:        ${result.totalFindings}`)
  console.log(`  critical/high/med/low: ${result.criticalCount}/${result.highCount}/${result.mediumCount}/${result.lowCount}`)
  console.log(`  safe (PQC/quantum-ok): ${result.safeCount}`)
  console.log(`  overallRiskScore:     ${result.overallRiskScore}  (${result.riskLevel})`)
  console.log(`  quantumReadiness:     ${result.quantumReadinessScore}  (${result.quantumReadinessLevel})`)

  const tls = result.tlsAnalysis
  if (tls) {
    console.log(`\n--- TLS (live handshake) ---`)
    console.log(`  protocol: ${(tls as { tlsVersion?: string }).tlsVersion ?? 'n/a'}`)
  }
  const cert = result.certificateInfo as unknown as { subject?: Record<string, string>; signatureAlgorithm?: string; publicKeyAlgorithm?: string; publicKeySize?: number } | null
  if (cert) {
    const subj = cert.subject?.CN || (cert.subject ? JSON.stringify(cert.subject) : 'n/a')
    console.log(`\n--- Certificate (live) ---`)
    console.log(`  subject: ${subj}`)
    console.log(`  sigAlg:  ${cert.signatureAlgorithm ?? 'n/a'}  pubKey: ${cert.publicKeyAlgorithm ?? 'n/a'} ${cert.publicKeySize ?? ''}`)
  }

  console.log(`\n--- TOP FINDINGS (evidence-based) ---`)
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SAFE: 4 } as Record<string, number>
  result.findings
    .slice()
    .sort((a, b) => (order[a.threatLevel] ?? 9) - (order[b.threatLevel] ?? 9))
    .slice(0, 8)
    .forEach((f, i) => {
      console.log(`  ${i + 1}. [${f.threatLevel}] ${f.algorithm} — ${f.category}`)
      console.log(`     where: ${f.location}`)
      console.log(`     quantum break: ${f.quantumBreakTime} | classical: ${f.classicalBreakTime}`)
      if (f.pqcRecommendation) {
        const rec = f.pqcRecommendation as { recommendedAlgorithm?: string; migrationPath?: string }
        console.log(`     PQC fix: ${rec.recommendedAlgorithm ?? f.recommendation}`)
      } else {
        console.log(`     fix: ${f.recommendation}`)
      }
    })

  console.log(`\n=== smoke test complete — ${result.totalFindings} real findings from ${target} ===\n`)
}

main().catch((err) => {
  console.error('Smoke test failed:', err)
  process.exit(1)
})
