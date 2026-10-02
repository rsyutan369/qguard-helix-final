/**
 * /dashboard/assets LIVE check — real tenants, real API, real stream.
 *
 *   npx tsx tools/assets-live-check.ts [baseUrl] [email,email,…]
 *
 * Signs in by admin magic link (no passwords; every session is signed out),
 * reads the payloads the page renders and asserts on the RESULT:
 *
 *   • the asset payload carries the register contract (components split from
 *     findings, pqcStatus, owner, internetFacing, lastScannedSource)
 *   • every register reconciliation check matches the scanner headline
 *   • no component is a scanner finding (the canonical predicate)
 *   • "last scanned" is never earlier than the asset's own newest evidence
 *   • the QR Engine agrees (or the page says it diverged)
 *   • the SSE stream sends one full snapshot, then small "unchanged" frames
 *   • full-estate and single-asset reports reconcile and never FAIL validation
 *
 * Needs the dev server (default http://localhost:3001) and service-role creds.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { isCryptographicComponent } from '../src/lib/scanner/finding-identity'
import { algorithmFamily } from '../src/lib/governance/subjects'
import { buildAssetRegister } from '../src/lib/assets/asset-register'
import { buildAssetReport } from '../src/services/reporting/AssetReport'
import { brandingSchema } from '../src/services/reporting/schemas/ReportSchema'

const BASE = process.argv[2] || process.env.ASSETS_CHECK_ORIGIN || 'http://localhost:3001'
const EMAILS = (process.argv[3] || process.env.ASSETS_CHECK_EMAILS || 'threathunter369@gmail.com,zachmatthew369@gmail.com,teslagreat101@gmail.com')
  .split(',').map((e) => e.trim()).filter(Boolean)
const SUPA = process.env.VITE_SUPABASE_URL || ''
if (!SUPA || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.VITE_SUPABASE_ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}
const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })

let failures = 0
function assert(name: string, ok: boolean, detail = '') {
  if (!ok) failures += 1
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(66)} ${detail}`)
}

async function session(email: string) {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpErr) throw new Error(`verifyOtp(${email}): ${otpErr.message}`)
  return { anon, token: data.session!.access_token }
}

async function getJson(path: string, token: string) {
  const res = await fetch(BASE + path, { headers: { Authorization: `Bearer ${token}` } })
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`)
  return (await res.json()).data
}

async function streamFrames(token: string, waitMs: number) {
  const res = await fetch(`${BASE}/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`)
  const frames: Array<{ event: string; bytes: number; fingerprint?: string }> = []
  if (!res.ok || !res.body) return { status: res.status, frames }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    const chunk = await Promise.race([
      reader.read(),
      new Promise<{ done: true; value?: undefined }>((resolve) => setTimeout(() => resolve({ done: true }), Math.max(1, deadline - Date.now()))),
    ])
    if (chunk.done && !chunk.value) break
    buffer += decoder.decode(chunk.value, { stream: true })
    let idx: number
    while ((idx = buffer.indexOf('\n\n')) >= 0) {
      const raw = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      const event = /^event: (.+)$/m.exec(raw)?.[1]
      if (!event) continue
      const data = raw.split('\n').filter((l) => l.startsWith('data: ')).map((l) => l.slice(6)).join('\n')
      let fingerprint: string | undefined
      try { fingerprint = JSON.parse(data).fingerprint } catch { /* ignore */ }
      frames.push({ event, bytes: data.length, fingerprint })
    }
  }
  try { await reader.cancel() } catch { /* closed */ }
  return { status: res.status, frames }
}

async function main() {
  console.log(`\n=== /dashboard/assets live check (${BASE}) ===`)
  for (const email of EMAILS) {
    console.log(`\n[${email}]`)
    const { anon, token } = await session(email)
    try {
      const [intel, qr, workflow] = await Promise.all([
        getJson('/api/v1/scanner/intelligence', token),
        getJson('/api/v1/quantum-readiness', token),
        getJson('/api/v1/migration-workflow', token).catch(() => null),
      ])
      const assets: any[] = intel.assets?.assets || []
      const first = assets[0] || {}
      assert('payload carries the register contract', assets.length === 0 || ['pqcStatus', 'componentCounts', 'postureObservations', 'owner', 'internetFacing', 'lastScannedSource'].every((k) => k in first), Object.keys(first).length ? '' : 'no assets')
      assert('payload carries a content fingerprint', typeof intel.fingerprint === 'string' && intel.fingerprint.length === 40)

      const register = buildAssetRegister({
        snapshot: intel,
        qr: { resolved: true, hasData: Boolean(qr?.hasData), readiness: qr?.scores?.quantumReadiness ?? null, readinessLevel: qr?.scores?.quantumReadinessLevel ?? null, risk: qr?.scores?.quantumRisk ?? null, components: qr?.inventory?.cryptoComponents ?? null, vulnerableComponents: qr?.inventory?.vulnerableComponents ?? null },
        workflowStates: workflow?.assetStates || [],
      })
      for (const c of register.checks) assert(`register: ${c.label}`, c.status === 'match', `${c.expected} vs ${c.actual}`)
      assert('QR Engine agreement', register.qr.state === 'match' || register.qr.state === 'no-evidence', register.qr.detail)

      const findingsAsComponents = assets.flatMap((a) => (a.cryptoInventory || []).filter((row: any) => !isCryptographicComponent(row, algorithmFamily)))
      assert('no scanner finding is served as a component', findingsAsComponents.length === 0, `${findingsAsComponents.length} found`)
      const lateEvidence = assets.filter((a) => {
        const last = Date.parse(a.lastScanned || '') || 0
        const newest = [...(a.cryptoInventory || []), ...(a.postureObservations || [])].reduce((m: number, r: any) => Math.max(m, Date.parse(r.last_seen_at || r.discovered_at || r.created_at || '') || 0), 0)
        return a.lastScannedSource !== 'asset-record' && newest > last + 1000
      })
      assert('"last scanned" is never older than the asset\'s own evidence', lateEvidence.length === 0, lateEvidence.map((a) => a.name).join(', '))
      const unvalidatedReady = register.rows.filter((r) => r.pqcStatus === 'pqc-ready' && (r.components.total === 0 || r.components.pqcReady !== r.components.total))
      assert('PQC-ready is only granted when every component is quantum-safe', unvalidatedReady.length === 0)

      // Stream: one full snapshot, then change-only confirmations.
      const { status, frames } = await streamFrames(token, 18_500)
      const full = frames.filter((f) => f.event === 'scanner-intelligence')
      const unchanged = frames.filter((f) => f.event === 'scanner-intelligence-unchanged')
      assert('stream answers 200', status === 200)
      assert('stream opens with one full snapshot', full.length >= 1 && typeof full[0].fingerprint === 'string', `${full.length} full, ${(full[0]?.bytes || 0) / 1024 | 0} KB`)
      if ((intel.summary?.activeScans || 0) === 0) {
        assert('idle stream sends only small "unchanged" frames after that', full.length === 1 && unchanged.length >= 1 && unchanged.every((f) => f.bytes < 2048), `${unchanged.length} unchanged, ${full.length - 1} extra full`)
      } else {
        console.log('  SKIP  an active scan is running — full frames are expected every tick')
      }

      if (register.rows.length) {
        const branding = brandingSchema.parse({ companyName: 'Live Check' })
        const fullReport = buildAssetReport({ register, rows: register.rows, scope: { type: 'all', description: 'the full estate' }, template: 'technical', branding, generatedBy: 'assets-live-check' })
        assert('full-estate report reconciles', fullReport.reconciliation.every((r) => r.matches), fullReport.reconciliation.filter((r) => !r.matches).map((r) => r.metric).join('; '))
        assert('full-estate report never FAILs validation', fullReport.document!.validation.status !== 'fail', `${fullReport.document!.validation.status} ${fullReport.document!.validation.score}`)
        const one = register.rows[0]
        const single = buildAssetReport({ register, rows: [one], scope: { type: 'selection', description: `the asset ${one.name}` }, template: 'executive', branding, generatedBy: 'assets-live-check' })
        assert('single-asset report states ITS numbers, not the estate\'s', single.document!.summary.highlights[1].value === one.components.total.toLocaleString('en-US'), `${single.document!.summary.highlights[1].value} vs ${one.components.total}`)
        assert('single-asset report reconciles', single.reconciliation.every((r) => r.matches))
      }
    } catch (err) {
      failures += 1
      console.log(`  FAIL  ${(err as Error).message}`)
    } finally {
      await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
    }
  }
  console.log(failures ? `\n✗ ${failures} CHECK(S) FAILED\n` : '\n✓ /dashboard/assets IS ACCURATE ON LIVE TENANTS\n')
  process.exit(failures ? 1 : 0)
}

main()
