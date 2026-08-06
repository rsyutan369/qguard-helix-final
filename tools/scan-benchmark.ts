/**
 * Scan benchmark — median of N runs per target.
 *
 * Single-run timings on a noisy network are not evidence: the same host has
 * measured 3.7s and 28.9s minutes apart on this machine. Medians over repeated
 * runs are what a performance claim can honestly rest on.
 *
 *   npx tsx tools/scan-benchmark.ts [runs] [host ...]
 */

import { runScanEngines } from '../src/lib/scanner/public-scan/engines'

const RUNS = Number(process.argv[2] || 3)
const TARGETS = process.argv.slice(3).length
  ? process.argv.slice(3)
  : ['example.com', 'www.cloudflare.com', 'www.wikipedia.org', 'github.com', 'tls-v1-2.badssl.com:1012']

const median = (values: number[]) => {
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

async function main() {
  console.log(`\n${RUNS} run(s) per target — median wall clock\n`)
  console.log(
    `${'target'.padEnd(30)} ${'median'.padStart(8)} ${'min'.padStart(8)} ${'max'.padStart(8)} ${'hs'.padStart(4)}  hybrid / verdict`,
  )
  console.log('-'.repeat(104))

  for (const entry of TARGETS) {
    const [host, rawPort] = entry.split(':')
    const port = Number(rawPort || 443)
    const totals: number[] = []
    let handshakes = 0
    let verdict = ''
    let inconclusive = 0

    for (let run = 0; run < RUNS; run += 1) {
      const t0 = Date.now()
      try {
        const bundle = await runScanEngines({ host, port })
        totals.push(Date.now() - t0)
        handshakes = bundle.tls.data.groupHandshakes
        inconclusive = bundle.tls.data.inconclusiveGroups.length
        verdict = bundle.tls.data.hybridGroups.join(',') || bundle.tls.data.classicalGroups.join(',') || 'none accepted'
      } catch (err) {
        totals.push(Date.now() - t0)
        verdict = `ERROR ${(err as Error).message.slice(0, 30)}`
      }
      // Space runs so one run's connections are not still draining into the next.
      await new Promise((resolve) => setTimeout(resolve, 1_500))
    }

    console.log(
      `${entry.padEnd(30)} ${(median(totals) / 1000).toFixed(2).padStart(7)}s ` +
        `${(Math.min(...totals) / 1000).toFixed(2).padStart(7)}s ${(Math.max(...totals) / 1000).toFixed(2).padStart(7)}s ` +
        `${String(handshakes).padStart(4)}  ${verdict}${inconclusive ? ` (+${inconclusive} inconclusive)` : ''}`,
    )
  }
  console.log('')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
