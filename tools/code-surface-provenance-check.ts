/**
 * "Code & Dependencies" provenance audit.
 *
 * Answers one question with evidence rather than a label: when /dashboard/scanner
 * reports a posture for the CODE & DEPENDENCIES surface, what was actually
 * measured — and does every finding routed there genuinely come from application
 * code, or from somewhere else that happens to share a routing rule?
 *
 *   npx tsx tools/code-surface-provenance-check.ts https://www.cloudflare.com url
 */

import { executeWebScan } from '../src/lib/scanner/web-scanner/scan-orchestrator'
import { scanWebCrypto } from '../src/lib/scanner/web-scanner/web-crypto-scanner'
import { moduleIdForFinding } from '../src/api-server/scanner-module-ledger'
import { nodeForFindingCategory, scoreNodes } from '../src/app/dashboard/scanner_dashboard/_intel'
import type { WebScanTargetType } from '../src/lib/scanner/web-scanner/types'
import type { DefensiveFinding } from '../src/app/dashboard/scanner_dashboard/_types'

const target = process.argv[2] || 'https://www.cloudflare.com'
const targetType = (process.argv[3] || 'url') as WebScanTargetType

/** Mirrors `normalizeWebFinding` in src/api-server/scanner.ts. */
function normalize(finding: any): DefensiveFinding {
  return {
    id: finding.id,
    algorithm: finding.algorithm,
    category: finding.category,
    location: finding.location,
    threatLevel: finding.threatLevel,
    status: 'open',
    description: finding.description,
    recommendation: finding.recommendation,
    pqcReplacement: null,
    keySize: null,
    evidence: `${finding.phase}: ${finding.location}`,
    detectionMethod: finding.phase,
    source: 'web-scanner',
    raw: finding,
  } as DefensiveFinding
}

async function main() {
  console.log(`\n=== CODE & DEPENDENCIES provenance — ${target} (${targetType}) ===\n`)

  /* 1. What does the client-side code scanner ACTUALLY see on its own? */
  console.log('1. Direct scanWebCrypto() result — the only code-reading module on a URL target')
  const web = await scanWebCrypto(target)
  console.log(`   pages fetched     : ${web.pagesScanned}`)
  console.log(`   scripts analysed  : ${web.scriptsAnalyzed}`)
  console.log(`   crypto patterns   : ${web.patterns.length}`)
  for (const pattern of web.patterns.slice(0, 8)) {
    console.log(`     · ${pattern.algorithm} — ${pattern.source}:${pattern.line}`)
  }

  /* 2. Run the real orchestrator and see what lands on the code surface. */
  console.log('\n2. Full orchestrator run — findings routed to the code surface')
  const moduleStates = new Map<string, { status: string; error: string | null }>()
  const result = await executeWebScan(target, targetType, (event) => {
    if (event.type === 'module-complete') {
      moduleStates.set(String(event.moduleId), {
        status: typeof event.error === 'string' ? 'error/na' : 'completed',
        error: typeof event.error === 'string' ? event.error : null,
      })
    }
  })

  const findings = result.findings.map(normalize)
  const codeFindings = findings.filter(
    (finding) => nodeForFindingCategory(finding.category, finding.detectionMethod, finding.algorithm) === 'code',
  )

  console.log(`   total findings            : ${findings.length}`)
  console.log(`   routed to the code surface: ${codeFindings.length}`)
  for (const finding of codeFindings) {
    console.log(
      `     · ${String(finding.algorithm).padEnd(26)} category="${finding.category}" detectionMethod="${finding.detectionMethod}"`,
    )
    console.log(`       location: ${finding.location}`)
    console.log(`       owner   : ${moduleIdForFinding(finding as any)}`)
  }

  /* 3. The score the card shows for that surface. */
  const nodeScores = scoreNodes(findings)
  console.log(`\n3. Node score the hero card renders for "code": ${nodeScores.code ?? '(no score — not measured)'}`)

  /* 4. Was any of it actually application code? */
  const fromRealCode = codeFindings.filter((finding) => {
    const category = String(finding.category).toLowerCase()
    return category.includes('web crypto') || category.includes('source code') || category.includes('repository')
  })
  console.log(`\n4. Of those, genuinely from application code : ${fromRealCode.length}`)
  const misattributed = codeFindings.filter((finding) => !fromRealCode.includes(finding))
  console.log(`   attributed to code but measured elsewhere  : ${misattributed.length}`)
  for (const finding of misattributed) {
    console.log(`     ! ${finding.algorithm} — really from ${finding.location}`)
  }

  console.log(`\n   web-crypto module state: ${JSON.stringify(moduleStates.get('web-crypto-scanner'))}`)
  console.log(`   repo module state      : ${JSON.stringify(moduleStates.get('github-scanner'))}\n`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
