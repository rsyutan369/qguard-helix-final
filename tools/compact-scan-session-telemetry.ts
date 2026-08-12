/**
 * Compacts already-stored pqc_scan_sessions.metadata.telemetry rows.
 *
 *   npx tsx tools/compact-scan-session-telemetry.ts            # dry run (default)
 *   npx tsx tools/compact-scan-session-telemetry.ts --apply    # writes changes
 *
 * WHY THIS EXISTS
 * ---------------
 * Sessions written before `persistableTelemetry` landed embedded the scan's
 * large payloads (`results`, `moduleStates`, `enterpriseScanner2`, …) inside
 * every buffered telemetry event, even though metadata already stores each of
 * them once. Rows reached ~850KB. New scans are written lean automatically;
 * this backfills the historical rows so scan history stops paying for them.
 *
 * WHAT IT CHANGES
 * ---------------
 * ONLY `metadata.telemetry`, and only by removing per-event copies of keys the
 * same metadata object still holds at top level. `results`, `moduleStates`,
 * `summary`, `errors`, `targets` and every other metadata key are written back
 * untouched, so no scan evidence is lost — the duplicates are.
 *
 * This rewrites stored rows. It runs as a dry run unless --apply is passed, and
 * prints exactly what each row would lose before you commit to it.
 */

import fs from 'node:fs'
import path from 'node:path'
import { persistableTelemetry } from '../src/lib/scanner/session-payload'

const APPLY = process.argv.includes('--apply')
const ROOT = path.resolve(import.meta.dirname, '..')

function loadEnv() {
  const file = path.join(ROOT, '.env')
  if (!fs.existsSync(file)) throw new Error('.env not found')
  const out: Record<string, string> = {}
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue
    const i = trimmed.indexOf('=')
    out[trimmed.slice(0, i).trim()] = trimmed.slice(i + 1).trim().replace(/^["']|["']$/g, '')
  }
  return out
}

const env = loadEnv()
const BASE = env.VITE_SUPABASE_URL
const KEY = env.SUPABASE_SERVICE_ROLE_KEY
if (!BASE || !KEY) throw new Error('VITE_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required')

const headers = { apikey: KEY, Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }
const kb = (value: unknown) => Buffer.byteLength(JSON.stringify(value ?? null)) / 1024

async function main() {
  console.log(`\nMode: ${APPLY ? 'APPLY (rows will be rewritten)' : 'DRY RUN (nothing is written)'}\n`)

  const res = await fetch(`${BASE}/rest/v1/pqc_scan_sessions?select=id,created_at,metadata&order=created_at.desc`, { headers })
  if (!res.ok) throw new Error(`read failed: ${res.status} ${await res.text()}`)
  const rows = await res.json() as { id: string; created_at: string; metadata: Record<string, unknown> | null }[]

  let before = 0
  let after = 0
  let rewritten = 0
  let skipped = 0

  for (const row of rows) {
    const metadata = row.metadata
    const sizeBefore = kb(metadata)
    before += sizeBefore

    const telemetry = metadata && Array.isArray(metadata.telemetry) ? metadata.telemetry as Record<string, unknown>[] : null
    if (!metadata || !telemetry) { after += sizeBefore; skipped++; continue }

    const compacted = { ...metadata, telemetry: persistableTelemetry(telemetry) }
    const sizeAfter = kb(compacted)
    after += sizeAfter

    // Below ~1KB of savings the rewrite is not worth the row churn.
    if (sizeBefore - sizeAfter < 1) { skipped++; continue }

    console.log(`  ${row.id.slice(0, 8)}  ${String(row.created_at).slice(0, 19)}  ${sizeBefore.toFixed(0)}KB -> ${sizeAfter.toFixed(0)}KB  (-${(sizeBefore - sizeAfter).toFixed(0)}KB)`)

    if (APPLY) {
      const patch = await fetch(`${BASE}/rest/v1/pqc_scan_sessions?id=eq.${row.id}`, {
        method: 'PATCH',
        headers: { ...headers, Prefer: 'return=minimal' },
        body: JSON.stringify({ metadata: compacted }),
      })
      if (!patch.ok) { console.log(`     WRITE FAILED ${patch.status} ${await patch.text()}`); continue }
    }
    rewritten++
  }

  console.log(
    `\n${rows.length} session(s): ${rewritten} ${APPLY ? 'rewritten' : 'would be rewritten'}, ${skipped} unchanged.` +
    `\nStored metadata ${(before / 1024).toFixed(2)}MB -> ${(after / 1024).toFixed(2)}MB` +
    `${APPLY ? '' : '\n\nRe-run with --apply to write these changes.'}\n`,
  )
}

main().catch((error) => { console.error(error); process.exit(1) })
