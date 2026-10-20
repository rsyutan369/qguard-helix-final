/**
 * Dev mode LIVE check — a real repository, the running API, every report format.
 *
 *   npx tsx tools/exposure-dev-live-check.ts [baseUrl] [repositoryUrl] [email]
 *
 * Defaults: http://localhost:3000, https://github.com/paulmillr/noble-post-quantum
 * (a post-quantum library: ML-KEM, ML-DSA, SLH-DSA, Falcon and hybrid KEMs — the
 * exact shape of codebase that exposed the DSA/ElGamal and inventory defects)
 * and the seeded Pro QA account. Uses the `quick` profile so one run costs
 * under ~45 GitHub API requests from an unauthenticated server.
 *
 * Read-only: the scan is never synchronised, so nothing is written to the
 * tenant. The admin magic-link session it mints is signed out at the end.
 *
 * It asserts on the RESULT, end to end:
 *   • the live assessment's CBOM, inventory, coverage and action list obey the
 *     rules the panels render (no phantom ElGamal, inventory reaches the CBOM,
 *     the sync re-derivation rebuilds the same CBOM, actions ranked once)
 *   • the API's CBOM route refuses a token-less navigation — the reason the
 *     Dev panel now exports client-side
 *   • all four templates × seven formats, built from THIS assessment, carry the
 *     same report id and SHA3-256 digest, reconcile completely, and their
 *     contents — read back from the PDF, DOCX, PPTX, XLSX, HTML, CSV and JSON
 *     bytes — hold the registers and figures the dashboard shows
 */
import 'dotenv/config'
import fs from 'node:fs'
import path from 'node:path'
import { createClient } from '@supabase/supabase-js'
import JSZip from 'jszip'
import { unzlibSync } from 'fflate'
import { buildCbom } from '../src/lib/scanner/exposure/cbom'
import { coverageReadings } from '../src/lib/scanner/exposure/panel-model'
import { reconcileExposure } from '../src/lib/scanner/exposure/exposure-truth'
import { RECOMMENDATION_LIMIT, rankRecommendations } from '../src/lib/scanner/exposure/recommendations'
import type { ExposureAssessment } from '../src/lib/scanner/exposure/types'
import { buildExposureReport, canonicalExposureReport, EXPOSURE_REPORT_TEMPLATES } from '../src/services/reporting/ExposureReport'
import { sha3Hex } from '../src/services/reporting/ReportIntegrity'
import { brandingSchema } from '../src/services/reporting/schemas/ReportSchema'
import { DOCUMENT_FORMATS, exportDocument } from '../src/services/reporting/exporters/DocumentExporters'

const BASE = process.argv[2] || process.env.EXPOSURE_LIVE_ORIGIN || 'http://localhost:3000'
const REPOSITORY = process.argv[3] || 'https://github.com/paulmillr/noble-post-quantum'
const EMAIL = process.argv[4] || process.env.EXPOSURE_LIVE_EMAIL || 'teslagreat101@gmail.com'
const SUPA = process.env.VITE_SUPABASE_URL || ''
if (!SUPA || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.VITE_SUPABASE_ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}
const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })

let passed = 0
const failures: string[] = []
function check(ok: boolean, label: string, detail = '') {
  if (ok) passed += 1
  else failures.push(`${label}${detail ? ` — ${detail}` : ''}`)
  console.log(`  ${ok ? '\x1b[32mok  \x1b[0m' : '\x1b[31mFAIL\x1b[0m'} ${label}${detail && !ok ? ` \x1b[2m(${detail})\x1b[0m` : ''}`)
}
const section = (title: string) => console.log(`\n\x1b[36m── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}\x1b[0m`)
const nf = (value: number) => value.toLocaleString('en-US')

/** Text drawn by pdf-lib: hex strings inside FlateDecode content streams. */
function pdfText(bytes: Buffer): string {
  const out: string[] = []
  const source = bytes.toString('latin1')
  const streamRe = /stream\r?\n/g
  let match: RegExpExecArray | null
  while ((match = streamRe.exec(source)) !== null) {
    const start = match.index + match[0].length
    const end = source.indexOf('endstream', start)
    if (end < 0) break
    const raw = bytes.subarray(start, end)
    let decoded: string
    try {
      decoded = Buffer.from(unzlibSync(new Uint8Array(raw))).toString('latin1')
    } catch {
      decoded = raw.toString('latin1')
    }
    for (const hex of decoded.matchAll(/<([0-9A-Fa-f]+)>\s*Tj/g)) out.push(Buffer.from(hex[1], 'hex').toString('latin1'))
    for (const literal of decoded.matchAll(/\(((?:\\.|[^\\)])*)\)\s*Tj/g)) out.push(literal[1])
    streamRe.lastIndex = end
  }
  return out.join(' ')
}

async function main() {
  console.log(`\x1b[1mDev mode LIVE check\x1b[0m\n  origin     : ${BASE}\n  repository : ${REPOSITORY}\n  account    : ${EMAIL}`)

  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw new Error(`generateLink: ${error.message}`)
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as { properties: { hashed_token: string } }).properties.hashed_token, type: 'magiclink' })
  if (otpError || !otp.session) throw new Error(`verifyOtp: ${otpError?.message}`)
  const token = otp.session.access_token
  const auth = { Authorization: `Bearer ${token}` }

  try {
    /* ═══════════════════════════════════════ 1. the export route's auth ═══ */
    section('1. The API CBOM route refuses a token-less navigation')
    const bare = await fetch(`${BASE}/api/v1/exposure/scans/probe/cbom?format=cyclonedx`)
    check(bare.status === 401, `GET …/cbom with no bearer token → ${bare.status} (a browser link or window.open sends none)`)

    /* ═══════════════════════════════════════════════ 2. a real Dev scan ═══ */
    section('2. A real Dev scan through the running API')
    const started = await fetch(`${BASE}/api/v1/exposure/scans`, {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ repositoryUrl: REPOSITORY, profileId: 'quick' }),
    })
    const startBody = await started.json()
    check(started.status === 202, `scan accepted (${started.status})`, JSON.stringify(startBody).slice(0, 200))
    const scanId = startBody?.data?.scanId as string | undefined
    if (!scanId) throw new Error('no scanId')

    let assessment: ExposureAssessment | null = null
    let status = 'queued'
    const deadline = Date.now() + 300_000
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2_500))
      const poll = await fetch(`${BASE}/api/v1/exposure/scans/${encodeURIComponent(scanId)}`, { headers: auth })
      const body = await poll.json()
      status = body?.data?.status ?? status
      if (body?.data?.assessment) {
        assessment = body.data.assessment as ExposureAssessment
        break
      }
      if (status === 'failed' || status === 'cancelled') throw new Error(`scan ${status}: ${body?.data?.error}`)
    }
    if (!assessment) throw new Error(`scan did not complete (last status ${status})`)
    const truth = reconcileExposure(assessment)
    console.log(`  status ${assessment.task.status} · ${nf(assessment.findings.length)} findings · ${nf(assessment.exposures.length)} exposures · ${nf(assessment.cbom.length)} components · ${nf(assessment.inventory?.length ?? 0)} inventory · readiness ${truth.readiness ?? '—'}%`)

    /* ═══════════════════════════════════ 3. the assessment the panels show ═══ */
    section('3. The live assessment obeys the panel rules')
    const algorithms = assessment.cbom.map((component) => component.canonicalAlgorithm)
    check(!algorithms.includes('ElGamal'), 'no phantom ElGamal component in a post-quantum library', [...new Set(algorithms)].join(', '))
    check(algorithms.includes('ML-DSA') && algorithms.includes('ML-KEM'), 'ML-DSA and ML-KEM are inventoried as post-quantum')
    check(Array.isArray(assessment.inventory), 'the server assessment carries its inventory observations (the sync payload re-derives from them)')
    check(
      buildCbom([...assessment.findings, ...(assessment.inventory ?? [])]).length === assessment.cbom.length,
      'findings + inventory rebuild exactly the CBOM the panel shows — what /scans/:id/sync will persist',
    )
    check(!assessment.findings.some((finding) => finding.category === 'Cryptographic Inventory'), 'no inventory observation is counted as a finding')
    const ranked = rankRecommendations({ findings: assessment.findings, exposures: assessment.exposures })
    check(
      assessment.intelligence.recommendations.length === Math.min(RECOMMENDATION_LIMIT, ranked.length) &&
        assessment.intelligence.recommendations.every((entry, index) => ranked[index]?.title === entry.title),
      `the panel's actions are the head of the one ranked list (${assessment.intelligence.recommendations.length} of ${ranked.length})`,
    )
    check((assessment.intelligence.recommendationCandidates ?? -1) === ranked.length, 'the panel denominator is the full list length')
    const runIds = new Set(assessment.task.runs.map((run) => run.engineId))
    const readings = coverageReadings(assessment.task.coverage, assessment.task.runs)
    check(
      readings.filter((reading) => reading.state === 'not-selected').every((reading) => reading.producers.every((id) => !runIds.has(id))),
      `${readings.filter((reading) => reading.state === 'not-selected').length} dimensions read "outside this profile", and no engine that measures them ran`,
    )
    check(
      truth.severity.critical + truth.severity.high + truth.severity.medium + truth.severity.low + truth.severity.info === assessment.findings.length,
      'finding severities partition the findings',
    )

    /* ═══════════════════════════════ 4. every template × every format ═══ */
    section('4. 4 templates × 7 formats, built from this live assessment')
    const outDir = path.join(import.meta.dirname, '..', '.report-smoke', 'exposure-live')
    fs.mkdirSync(outDir, { recursive: true })
    const branding = brandingSchema.parse({ companyName: 'QGuard Live Check' })

    for (const spec of EXPOSURE_REPORT_TEMPLATES) {
      const report = buildExposureReport({ assessment, template: spec.key, depth: 'standard', branding, generatedBy: EMAIL })
      const id = report.meta.reportId!
      const hash = report.integrity!.hash
      check(sha3Hex(canonicalExposureReport(report)) === hash, `${spec.key}: the seal recomputes from the report body`)
      const mismatched = report.reconciliation.filter((row) => !row.matches)
      check(mismatched.length === 0, `${spec.key}: ${report.reconciliation.length} reconciliation rows match the dashboard`, mismatched.map((row) => `${row.metric}: ${row.dashboard} vs ${row.exported}`).join('; '))
      check(report.document!.validation.checks.every((entry) => entry.status !== 'fail'), `${spec.key}: no validation check fails (quality ${report.document!.validation.score}/100)`)

      for (const format of DOCUMENT_FORMATS) {
        const result = await exportDocument(report, format)
        const bytes = Buffer.from(await result.blob.arrayBuffer())
        fs.writeFileSync(path.join(outDir, `${spec.key}-${result.filename}`), bytes)
        let body = ''
        if (format === 'pdf') body = pdfText(bytes)
        else if (format === 'docx' || format === 'pptx') {
          const zip = await JSZip.loadAsync(bytes)
          const parts = Object.keys(zip.files).filter((name) => (format === 'docx' ? /^word\/(document|header\d*|footer\d*)\.xml$/ : /^ppt\/slides\/slide\d+\.xml$/).test(name))
          body = (await Promise.all(parts.map((name) => zip.file(name)!.async('string')))).join(' ').replace(/<[^>]+>/g, ' ')
        } else if (format === 'xlsx') {
          const ExcelJS = (await import('exceljs')).default
          const workbook = new ExcelJS.Workbook()
          await workbook.xlsx.load(bytes as unknown as ArrayBuffer)
          const short = report.tables.filter((table) => {
            const sheet = workbook.worksheets.find((candidate) => candidate.name.startsWith(table.title.replace(/[\\/*?:[\]]/g, ' ').slice(0, 26)))
            return !sheet || sheet.actualRowCount < table.rows.length + 1
          })
          check(short.length === 0, `${spec.key} xlsx: every one of ${report.tables.length} registers is a complete sheet`, short.map((table) => table.title).join(', '))
          body = String(workbook.keywords ?? '')
        } else body = bytes.toString('utf8')

        const carriesId = body.includes(id)
        check(carriesId, `${spec.key} ${format}: carries report id ${id}${format === 'xlsx' ? ' (workbook keywords)' : ''}`)
        if (format === 'html' || format === 'csv' || format === 'json') {
          check(body.includes(hash), `${spec.key} ${format}: carries the SHA3-256 digest`)
        }
        if (format === 'csv') {
          const missing = report.tables.filter((table) => !body.includes(`# ${table.title} (${table.rows.length} rows)`))
          check(missing.length === 0, `${spec.key} csv: every register is present with its full row count`, missing.map((table) => table.title).join(', '))
        }
        if (format === 'json') {
          const parsed = JSON.parse(body)
          check(parsed.integrity?.hash === hash && parsed.meta?.reportId === id, `${spec.key} json: id and seal survive the round trip`)
        }
        if (format === 'pdf' || format === 'docx' || format === 'html') {
          /* The headline figures a reader quotes, as the panel renders them. */
          const expected = [nf(assessment.findings.length), nf(assessment.cbom.length)]
          check(expected.every((figure) => body.includes(figure)), `${spec.key} ${format}: states ${expected.join(' findings / ')} components`)
        }
      }
    }
    console.log(`\n  artefacts: ${outDir}`)
  } finally {
    await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }

  console.log(`\n${failures.length === 0 ? '\x1b[32m✓' : '\x1b[31m✗'} ${passed} passed, ${failures.length} failed\x1b[0m`)
  if (failures.length) {
    for (const failure of failures) console.log(`  - ${failure}`)
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
