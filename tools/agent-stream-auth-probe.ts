/**
 * Live probe: the agent-scanner SSE stream authenticates by header only.
 *
 *   npx tsx tools/agent-stream-auth-probe.ts [email] [origin]
 *
 * Signs a throwaway magic-link session for the QA user and checks
 * GET /api/v1/agent-scanner/stream four ways:
 *   1. no credentials              → 401
 *   2. token in `?token=` only     → 401  (a URL token lands in access logs)
 *   3. `Authorization: Bearer`     → 200 text/event-stream + an agent-scanner-sync frame
 *   4. garbage bearer              → 401
 * The session is signed out (revoked) at the end. Exit code 1 on any failure.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const EMAIL = process.argv[2] || 'zachmatthew369@gmail.com'
const BASE = process.argv[3] || 'http://localhost:3000'
const SUPA = process.env.VITE_SUPABASE_URL!
const URL_ = `${BASE}/api/v1/agent-scanner/stream`

let failures = 0
function check(ok: boolean, label: string, detail: string) {
  if (!ok) failures += 1
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  ${detail}`)
}

/** Opens the stream, reads until a named frame or the deadline, then aborts. */
async function probe(url: string, headers: Record<string, string>, waitMs = 20_000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), waitMs)
  try {
    const res = await fetch(url, { headers: { Accept: 'text/event-stream', ...headers }, signal: controller.signal })
    const type = res.headers.get('content-type') || ''
    let firstEvent: string | null = null
    if (res.ok && res.body && type.includes('text/event-stream')) {
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (!firstEvent) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const match = buffer.match(/^event:\s*(\S+)/m)
        if (match) firstEvent = match[1]
      }
    } else {
      await res.text().catch(() => '')
    }
    return { status: res.status, type, firstEvent }
  } catch (error) {
    return { status: 0, type: '', firstEvent: null, error: error instanceof Error ? error.message : String(error) }
  } finally {
    clearTimeout(timer)
    controller.abort()
  }
}

async function main() {
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: otp, error: otpError } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError) throw otpError
  const token = otp.session!.access_token

  try {
    const none = await probe(URL_, {})
    check(none.status === 401, 'no credentials', `status=${none.status}`)

    const query = await probe(`${URL_}?token=${encodeURIComponent(token)}`, {})
    check(query.status === 401, '?token= only', `status=${query.status}`)

    const header = await probe(URL_, { Authorization: `Bearer ${token}` })
    check(
      header.status === 200 && header.type.includes('text/event-stream') && header.firstEvent === 'agent-scanner-sync',
      'Authorization header',
      `status=${header.status} type=${header.type || '-'} firstEvent=${header.firstEvent || '-'}`,
    )

    const garbage = await probe(URL_, { Authorization: 'Bearer not-a-real-token' })
    check(garbage.status === 401, 'garbage bearer', `status=${garbage.status}`)
  } finally {
    await admin.auth.admin.signOut(token).catch(() => undefined)
  }

  console.log(failures ? `\n✗ ${failures} check(s) failed` : '\n✓ agent-scanner stream accepts the Authorization header only')
  process.exit(failures ? 1 : 0)
}

main().catch((error) => { console.error(error); process.exit(1) })
