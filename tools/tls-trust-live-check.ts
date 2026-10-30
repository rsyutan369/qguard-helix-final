/**
 * TLS / PKI / Encryption / Trust LIVE check — real tenants, real API, real stream. Read-only.
 *
 *   npx tsx tools/tls-trust-live-check.ts [baseUrl] [email,email,…]
 *
 * Covers the seven pages of Technical_Audit_3: tls-telemetry, pki-visibility,
 * protocol-analytics, encryption-monitoring, tls-orchestrator, trust-dashboard,
 * trust-state-discovery. Each assertion is a defect found on live tenants:
 *
 *   • `?token=` served all seven Pro pages to a BASIC tenant.
 *   • Failed reads were silent (`safeRows` → []); the payload now carries `reads`.
 *   • Streams re-sent the whole payload on every 15s recompute.
 *   • Agent-heartbeat alerts were counted as TLS findings.
 *   • Issuers known only by name were published as ROOT CAs.
 *   • "Quantum-vulnerable endpoints" excluded legacy endpoints.
 *
 * Sessions are created by admin magic link and signed out afterwards.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const BASE = process.argv[2] || process.env.TLS_TRUST_CHECK_ORIGIN || 'http://localhost:3000'
const EMAILS = (process.argv[3] || 'teslagreat101@gmail.com,zachmatthew369@gmail.com,threathunter369@gmail.com').split(',').map((e) => e.trim()).filter(Boolean)
const SUPA = process.env.VITE_SUPABASE_URL || ''
if (!SUPA || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.VITE_SUPABASE_ANON_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / VITE_SUPABASE_ANON_KEY in .env')
  process.exit(1)
}
const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })

const PAGES: Array<{ page: string; event: string }> = [
  { page: 'tls-telemetry', event: 'tls-pki' },
  { page: 'pki-visibility', event: 'tls-pki' },
  { page: 'protocol-analytics', event: 'tls-pki' },
  { page: 'tls-orchestrator', event: 'tls-pki' },
  { page: 'encryption-monitoring', event: 'encryption-intel' },
  { page: 'trust-dashboard', event: 'trust-fabric' },
  { page: 'trust-state-discovery', event: 'trust-fabric' },
]
const SENSITIVE = ['session_token_hash', 'token_hash', 'ip_address', 'user_agent', 'token_ref', 'private_key', 'secret', 'raw_evidence']

let failures = 0
function assert(name: string, ok: boolean, detail = '') {
  if (!ok) failures += 1
  console.log(`  ${ok ? '✓' : '✗ FAIL'} ${name}${detail ? ` — ${detail}` : ''}`)
}

async function signIn(email: string) {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) throw new Error(`generateLink(${email}): ${error.message}`)
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: otpErr } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpErr) throw new Error(`verifyOtp(${email}): ${otpErr.message}`)
  return { anon, token: data.session!.access_token }
}

async function streamFrames(path: string, token: string, waitMs: number) {
  const controller = new AbortController()
  const frames: Array<{ event: string; bytes: number }> = []
  const timer = setTimeout(() => controller.abort(), waitMs)
  try {
    const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, signal: controller.signal })
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
        // A second frame proves the re-check path; stop as soon as it arrives.
        if (frames.length >= 2) controller.abort()
      }
    }
  } catch { /* aborted on purpose */ } finally {
    clearTimeout(timer)
  }
  return frames
}

async function main() {
  console.log(`TLS / PKI / Encryption / Trust live check against ${BASE}\n`)
  for (const email of EMAILS) {
    const { anon, token } = await signIn(email)
    console.log(`[${email.replace(/(.).*@/, '$1•••@')}]`)
    try {
      for (const { page, event } of PAGES) {
        const path = `/api/v1/dashboard/${page}`
        const viaQuery = await fetch(`${BASE}${path}?token=${encodeURIComponent(token)}`)
        await viaQuery.body?.cancel().catch(() => undefined)
        const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } })
        if (res.status === 403) {
          const body = await res.json()
          assert(`${page}: ?token= refused and the plan gate holds`, viaQuery.status === 401 && body?.error?.code === 'SUBSCRIPTION_REQUIRED', `query ${viaQuery.status}, header ${res.status}`)
          continue
        }
        assert(`${page}: ?token= refused`, viaQuery.status === 401, `HTTP ${viaQuery.status}`)
        const raw = await res.text()
        const d = JSON.parse(raw).data
        const leaked = SENSITIVE.filter((k) => raw.includes(`"${k}"`))
        assert(`${page}: no credential-adjacent field in the payload`, leaked.length === 0, leaked.join(',') || 'none')
        const unavailable = (d.reads ?? []).filter((r: any) => r.state === 'unavailable').map((r: any) => r.key)
        assert(`${page}: every source read is published and none failed`, Array.isArray(d.reads) && d.reads.length > 0 && unavailable.length === 0, `${d.reads?.length ?? 0} reads${unavailable.length ? `, unavailable: ${unavailable.join(',')}` : ''}`)

        if (d.posture?.classicalOnlyEndpoints !== undefined) {
          assert(`${page}: quantum-vulnerable endpoints = classical-only endpoints`, d.posture.quantumVulnerableEndpoints === d.posture.classicalOnlyEndpoints, `${d.posture.quantumVulnerableEndpoints}/${d.posture.classicalOnlyEndpoints}`)
        }
        if (Array.isArray(d.trustChains)) {
          const fakeRoots = d.trustChains.filter((n: any) => n.kind === 'root' && !n.measured)
          assert(`${page}: no unmeasured issuer is labelled a root`, fakeRoots.length === 0, fakeRoots.map((n: any) => n.label).join(' | '))
        }
        if (Array.isArray(d.nodes)) {
          const fakeRootCas = d.nodes.filter((n: any) => n.kind === 'root-ca' && !n.measured)
          assert(`${page}: no unmeasured CA is a root-ca node`, fakeRootCas.length === 0, fakeRootCas.map((n: any) => n.label).join(' | '))
        }
        if (Array.isArray(d.findings)) {
          const health = d.findings.filter((f: any) => /scanner agent offline|heartbeat/i.test(f.title))
          assert(`${page}: no collector-health alert is presented as a finding`, health.length === 0, health.map((f: any) => f.title).join(' | '))
        }
        if (Array.isArray(d.endpoints)) {
          assert(`${page}: every measured endpoint states its transport basis`, d.endpoints.filter((e: any) => e.hasTransportEvidence).every((e: any) => ['live-traffic', 'scanner-probe', 'mixed'].includes(e.transportBasis)))
        }

        // Up to 25s: a tick that lands after the 15s model cache expired recomputes before answering.
        const frames = await streamFrames(`${path}/stream`, token, 25_000)
        const full = frames.filter((f) => f.event === event)
        const unchanged = frames.filter((f) => f.event === `${event}-unchanged`)
        assert(`${page}: stream sends one full frame, then small unchanged frames`, full.length === 1 && unchanged.length >= 1 && unchanged.every((f) => f.bytes < 400),
          frames.map((f) => `${f.event}:${f.bytes}B`).join(', '))
      }
    } finally {
      await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
    }
    console.log('')
  }
  console.log(failures ? `✗ ${failures} CHECK(S) FAILED` : '✓ TLS / PKI / ENCRYPTION / TRUST PAGES ARE EVIDENCE-HONEST ON LIVE TENANTS')
  process.exit(failures ? 1 : 0)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
