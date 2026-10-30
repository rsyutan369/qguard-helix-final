/**
 * PQAuth™ LIVE check — real tenants, real API, real stream. Read-only.
 *
 *   npx tsx tools/pqauth-live-check.ts [baseUrl] [email,email,…]
 *
 * Signs in by admin magic link (every session is signed out afterwards) and
 * asserts on what the seven PQAuth pages actually receive. Each assertion is a
 * defect the 2026-10-28 deep audit found on live tenants:
 *
 *   • `?token=` in the URL served the full snapshot to a BASIC tenant: the
 *     subscription gate reads only the Authorization header.
 *   • Raw rows were spread into the payload: session-token hashes, agent token
 *     hashes, IPs and user agents reached the browser and the JSON export.
 *   • Regex over serialised rows invented "Microsoft Entra ID" and "F5" for
 *     tenants running neither, and called crypto rows "tokens".
 *   • The stream re-sent ~1 MB every 8 s whether or not anything changed.
 *   • Vulnerable components (406) exceeded total components (153).
 *
 * It never starts a discovery run, so it causes no outbound probing.
 * Needs the dev server (default http://localhost:3000) and service-role creds.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const BASE = process.argv[2] || process.env.PQAUTH_CHECK_ORIGIN || 'http://localhost:3000'
const EMAILS = (process.argv[3] || process.env.PQAUTH_CHECK_EMAILS || 'teslagreat101@gmail.com,zachmatthew369@gmail.com,threathunter369@gmail.com')
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
  console.log(`  ${ok ? '✓' : '✗ FAIL'} ${name}${detail ? ` — ${detail}` : ''}`)
}

const SENSITIVE_KEYS = ['session_token_hash', 'token_hash', 'ip_address', 'user_agent', 'token_ref', 'session_id', 'private_key', 'secret']

async function signIn(email: string) {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpErr) throw new Error(`verifyOtp(${email}): ${otpErr.message}`)
  return { anon, token: data.session!.access_token }
}

async function streamFrames(token: string, waitMs: number) {
  const controller = new AbortController()
  const frames: Array<{ event: string; bytes: number }> = []
  const timer = setTimeout(() => controller.abort(), waitMs)
  try {
    const res = await fetch(`${BASE}/api/v1/dashboard/pqauth/stream`, { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal })
    const reader = res.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let i
      while ((i = buffer.indexOf('\n\n')) >= 0) {
        const frame = buffer.slice(0, i)
        buffer = buffer.slice(i + 2)
        const event = /event: (.*)/.exec(frame)?.[1]
        if (event) frames.push({ event, bytes: frame.length })
      }
    }
  } catch { /* aborted on purpose */ } finally {
    clearTimeout(timer)
  }
  return frames
}

async function main() {
  console.log(`PQAuth live check against ${BASE}\n`)
  for (const email of EMAILS) {
    const { anon, token } = await signIn(email)
    console.log(`[${email.replace(/(.).*@/, '$1•••@')}]`)
    try {
      const viaQuery = await fetch(`${BASE}/api/v1/dashboard/pqauth/overview?token=${encodeURIComponent(token)}`)
      assert('a token in the URL is refused (no subscription-gate bypass)', viaQuery.status === 401, `HTTP ${viaQuery.status}`)
      const streamViaQuery = await fetch(`${BASE}/api/v1/dashboard/pqauth/stream?token=${encodeURIComponent(token)}`)
      assert('the stream refuses a token in the URL', streamViaQuery.status === 401, `HTTP ${streamViaQuery.status}`)
      await streamViaQuery.body?.cancel().catch(() => undefined)

      const res = await fetch(`${BASE}/api/v1/dashboard/pqauth/overview`, { headers: { Authorization: `Bearer ${token}` } })
      if (res.status === 403) {
        const body = await res.json()
        assert('a tenant below Pro is refused by the subscription gate', body?.error?.code === 'SUBSCRIPTION_REQUIRED', body?.error?.code)
        continue
      }
      assert('the snapshot loads with the Authorization header', res.ok, `HTTP ${res.status}`)
      const raw = await res.text()
      const data = JSON.parse(raw).data
      const id = data.identity

      const leaked = SENSITIVE_KEYS.filter((k) => raw.includes(`"${k}"`))
      assert('no credential-adjacent field reaches the browser', leaked.length === 0, leaked.join(', ') || 'none')
      assert('the payload is bounded', raw.length < 400 * 1024, `${(raw.length / 1024).toFixed(0)} KB`)
      assert('no vendor is invented from row text', !/Microsoft Entra|"F5"|NIST PQC Deadline/.test(raw))
      assert('every provider comes from identity_providers with an issuer', id.providers.every((p: any) => p.issuer && p.sourceUrl))
      assert('a named vendor matches its issuer host', id.providers.every((p: any) => !p.vendor || (p.host && p.issuer.includes(p.host))))

      const nodeIds = new Set(id.graph.nodes.map((n: any) => n.id))
      assert('every trust edge joins existing nodes and cites a source', id.graph.edges.every((e: any) => nodeIds.has(e.from) && nodeIds.has(e.to) && e.sourceTable && e.evidence))
      assert('no edge is drawn without identity records', id.providers.length > 0 || id.graph.edges.every((e: any) => e.sourceTable !== 'identity_providers'))

      const m = data.metrics
      assert('vulnerable components never exceed total components', m.vulnerableComponents <= m.totalComponents, `${m.vulnerableComponents}/${m.totalComponents}`)
      assert('readiness is null when no key is classified', id.readiness.coverage !== null || (id.readiness.safeKeys + id.readiness.hybridKeys + id.readiness.vulnerableKeys) === 0)
      assert('no identity migration job is "validated" without a later discovery', id.migration.jobs.every((j: any) => j.state !== 'validated' || j.validation.status === 'validated'))
      assert('sandbox jobs are excluded from production counts', Object.values(id.migration.counts).reduce((s: number, n: any) => s + n, 0) === id.migration.jobs.filter((j: any) => !j.simulation).length)
      assert('every compatibility issue answers the five questions', id.compatibility.issues.every((i: any) => i.component && i.issue && i.why && i.cause && i.remediation))
      assert('the twin reports an explicit sync state', ['in-sync', 'partial', 'stale', 'drift', 'never-synced'].includes(id.twin.sync.status), id.twin.sync.status)
      assert('discovery scope explains every asset', id.discovery.scope.every((s: any) => s.reason))

      const frames = await streamFrames(token, 11_500)
      const full = frames.filter((f) => f.event === 'pqauth-update')
      const unchanged = frames.filter((f) => f.event === 'pqauth-update-unchanged')
      assert('the stream sends one full frame, then small unchanged frames', full.length === 1 && unchanged.length >= 1 && unchanged.every((f) => f.bytes < 400),
        frames.map((f) => `${f.event}:${f.bytes}B`).join(', '))
    } finally {
      await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
    }
    console.log('')
  }
  console.log(failures ? `✗ ${failures} CHECK(S) FAILED` : '✓ PQAUTH IS EVIDENCE-HONEST ON LIVE TENANTS')
  process.exit(failures ? 1 : 0)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
