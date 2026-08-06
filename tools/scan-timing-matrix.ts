/**
 * Scan timing matrix — wall clock across a spread of real endpoints.
 *
 * The point is the SPREAD, not any single number: a CDN edge 15ms away and a
 * distant origin that silently drops an unknown key_share have wildly different
 * costs for the same sequential probe plan, and only the second one tells you
 * whether the budget holds.
 *
 *   npx tsx tools/scan-timing-matrix.ts [host ...]
 */

import { runScanEngines } from '../src/lib/scanner/public-scan/engines'

const TARGETS = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      'www.cloudflare.com',
      'example.com',
      'www.wikipedia.org',
      'github.com',
      'www.ietf.org',
      'tls-v1-2.badssl.com:1012',
      'expired.badssl.com',
    ]

async function main() {
  console.log(
    `\n${'target'.padEnd(30)} ${'total'.padStart(8)} ${'tls'.padStart(8)} ${'dns'.padStart(8)} ${'cert'.padStart(8)} ${'http'.padStart(8)}  hs  protocols`,
  )
  console.log('-'.repeat(110))

  for (const entry of TARGETS) {
    const [host, rawPort] = entry.split(':')
    const port = Number(rawPort || 443)
    const t0 = Date.now()
    try {
      const bundle = await runScanEngines({ host, port })
      const total = (Date.now() - t0) / 1000
      console.log(
        `${entry.padEnd(30)} ${total.toFixed(2).padStart(7)}s ${(bundle.tls.durationMs / 1000).toFixed(2).padStart(7)}s ` +
          `${(bundle.dns.durationMs / 1000).toFixed(2).padStart(7)}s ${(bundle.certificate.durationMs / 1000).toFixed(2).padStart(7)}s ` +
          `${(bundle.http.durationMs / 1000).toFixed(2).padStart(7)}s ${String(bundle.tls.data.groupHandshakes).padStart(3)}  ` +
          `${bundle.tls.data.supportedProtocols.join(',') || 'none'}`,
      )
    } catch (err) {
      console.log(`${entry.padEnd(30)} FAILED after ${((Date.now() - t0) / 1000).toFixed(2)}s — ${(err as Error).message}`)
    }
  }
  console.log('')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
