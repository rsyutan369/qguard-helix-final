/**
 * Admin + Settings + Revenue Intelligence — cross-page consistency and the
 * fixes from the Admin_Revenue_Audit (2026-11-12).
 *
 *   npx tsx tools/admin-revenue-audit-check.ts            (default base http://localhost:3000)
 *   AUDIT_CHECK_BASE=http://localhost:3002 npx tsx tools/admin-revenue-audit-check.ts
 *
 * Proves, against the running API and the real database:
 *   1. Admin Overview KPIs equal the Users directory and Plans & Billing
 *      models, which equal Revenue Intelligence (one number everywhere).
 *   2. Overview subscription counts equal an independent read of
 *      billing_subscriptions (access-granting = active | trial | pending_renewal).
 *   3. Revenue MRR movement reconciles (starting + new + expansion −
 *      contraction − churned = MRR) and NRR is null or a percentage.
 *   4. The owner JWT is refused in a query string outside /stream on the
 *      Admin and Profile APIs (it stays accepted on /stream).
 *   5. Settings session revocation: the current session cannot be revoked;
 *      revoking ANOTHER session ends the Supabase Auth session for real
 *      (its refresh token stops working) — or, when the SQL function is not
 *      installed, answers 503 and changes nothing.
 *
 * Writes: audit rows the API records for its own reads, plus one extra Auth
 * session for the owner that the check creates and then revokes itself.
 */
import 'dotenv/config'
import assert from 'node:assert/strict'
import { createClient } from '@supabase/supabase-js'
import { ADMIN_OWNER_EMAIL } from '@/lib/admin-access'

const BASE = process.env.AUDIT_CHECK_BASE || 'http://localhost:3000'
const URL_ = process.env.VITE_SUPABASE_URL || ''
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ANON = process.env.VITE_SUPABASE_ANON_KEY || ''

let passed = 0
let failed = 0
async function check(name: string, fn: () => Promise<void> | void) {
  try {
    await fn()
    passed += 1
    console.log(`PASS  ${name}`)
  } catch (err) {
    failed += 1
    console.log(`FAIL  ${name}\n      ${err instanceof Error ? err.message : String(err)}`)
  }
}

const anonClient = () => createClient(URL_, ANON, { auth: { persistSession: false, autoRefreshToken: false } })

async function ownerSession() {
  const admin = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: ADMIN_OWNER_EMAIL })
  if (error) throw new Error(`generateLink: ${error.message}`)
  const client = anonClient()
  const { data, error: otpError } = await client.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (otpError || !data.session) throw new Error(`verifyOtp: ${otpError?.message}`)
  return { token: data.session.access_token, refresh: data.session.refresh_token }
}

async function call(method: string, path: string, token: string | null, init: { query?: boolean } = {}) {
  const url = init.query && token ? `${BASE}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}` : `${BASE}${path}`
  const response = await fetch(url, { method, headers: !init.query && token ? { Authorization: `Bearer ${token}` } : {} })
  const json = await response.json().catch(() => ({}))
  return { status: response.status, json: json as any }
}

async function main() {
  if (!URL_ || !SERVICE || !ANON) throw new Error('VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY are required')
  const db = createClient(URL_, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } })
  const owner = await ownerSession()

  const [stats, users, billing, revenue] = await Promise.all([
    call('GET', '/api/v1/admin/stats', owner.token),
    call('GET', '/api/v1/admin/users?page=1&limit=1', owner.token),
    call('GET', '/api/v1/admin/billing?page=1&limit=1', owner.token),
    call('GET', '/api/v1/revenue/snapshot?fresh=1', owner.token),
  ])

  await check('APIs answer 200 for the owner', () => {
    for (const [name, result] of Object.entries({ stats, users, billing, revenue })) assert.equal(result.status, 200, `${name}: HTTP ${result.status}`)
  })

  const k = stats.json.data?.kpis || {}
  const u = users.json.data?.stats
  const b = billing.json.data?.stats
  const r = revenue.json.data

  await check('Overview user KPIs = Users directory (total, active, suspended, disabled, unverified, never)', () => {
    assert.equal(k.totalUsers, u.totalUsers)
    assert.equal(k.activeUsers, u.activity.active30d)
    assert.equal(k.activeNowUsers, u.activity.activeNow)
    assert.equal(k.neverSignedInUsers, u.activity.never)
    assert.equal(k.suspendedUsers, u.status.suspended)
    assert.equal(k.disabledUsers, u.status.disabled)
    assert.equal(k.pendingVerificationUsers, u.status.pending_verification)
    assert.equal(k.activeSessions, u.liveSessions)
  })

  await check('Overview subscription KPIs = Plans & Billing (access, past due, MRR)', () => {
    assert.equal(k.activeSubscriptions, b.grantingAccess)
    assert.equal(k.pastDueSubscriptions, b.pastDue)
    assert.equal(k.mrrCents, b.mrrCents)
    assert.equal(k.expiredPlans, b.byStatus.expired || 0)
    assert.equal(k.trialSubscriptions, b.byStatus.trial || 0)
  })

  await check('Plans & Billing MRR = Revenue Intelligence MRR; paying subscribers agree', () => {
    assert.equal(b.mrrCents, r.kpis.mrrCents)
    assert.equal(k.payingSubscriptions, r.subscriptionAnalytics.payingActive)
  })

  await check('Overview subscription counts = an independent read of billing_subscriptions', async () => {
    const { data, error } = await db.from('billing_subscriptions').select('status').range(0, 9999)
    if (error) throw new Error(error.message)
    const rows = data || []
    const granting = rows.filter((row: any) => ['active', 'trial', 'pending_renewal'].includes(String(row.status).toLowerCase())).length
    assert.equal(k.activeSubscriptions, granting)
    assert.equal(k.expiredPlans, rows.filter((row: any) => row.status === 'expired').length)
    const summary = Object.fromEntries((stats.json.data.summaries.subscriptionStatus as Array<{ label: string; count: number }>).map((row) => [row.label, row.count]))
    assert.equal(Object.values(summary).reduce((sum: number, value) => sum + Number(value), 0), rows.length)
  })

  await check('Overview 7-day collected = USD paid/refunded invoices of the last 7 days (independent read)', async () => {
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString()
    const { data, error } = await db.from('billing_invoices').select('status,currency,amount_paid_cents,payment_date,created_at').range(0, 9999)
    if (error) throw new Error(error.message)
    const expected = (data || [])
      .filter((row: any) => ['paid', 'refunded'].includes(String(row.status).toLowerCase()) && String(row.currency || 'USD').toUpperCase() === 'USD')
      .filter((row: any) => (row.payment_date || row.created_at) >= since)
      .reduce((sum: number, row: any) => sum + Math.max(0, Math.round(Number(row.amount_paid_cents) || 0)), 0)
    assert.equal(k.subscriptionRevenue, expected)
  })

  await check('Unmeasured overview figures are null, never a fabricated 0', () => {
    if (k.migrationJobs === 0) assert.equal(k.migrationProgress, null)
    for (const key of ['activeSubscriptions', 'mrrCents', 'subscriptionRevenue']) assert.ok(k[key] === null || typeof k[key] === 'number', key)
  })

  await check('Revenue MRR movement reconciles and NRR is null or a percentage', () => {
    const m = r.mrrMovement
    assert.ok(m, 'mrrMovement missing from the snapshot')
    assert.equal(m.startingMrrCents + m.newMrrCents + m.expansionMrrCents - m.contractionMrrCents - m.churnedMrrCents, r.kpis.mrrCents)
    assert.equal(m.endingMrrCents, r.kpis.mrrCents)
    if (m.startingMrrCents === 0) assert.equal(m.nrrPct, null)
    else assert.equal(typeof m.nrrPct, 'number')
    assert.equal(r.kpis.nrrPct, m.nrrPct)
    const recon = r.reconciliation.checks.find((c: any) => c.id === 'mrr-movement')
    assert.ok(recon?.ok, 'mrr-movement reconciliation check missing or failing')
  })

  await check('Admin API refuses the JWT in a query string outside /stream', async () => {
    const refused = await call('GET', '/api/v1/admin/stats', owner.token, { query: true })
    assert.equal(refused.status, 401)
  })

  const mint = async (stream: string, token: string | null = owner.token) => {
    const response = await fetch(`${BASE}/api/v1/stream-tickets`, {
      method: 'POST',
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), 'Content-Type': 'application/json' },
      body: JSON.stringify({ stream }),
    })
    return { status: response.status, json: await response.json().catch(() => ({})) as any }
  }
  const openStatus = async (url: string) => {
    const controller = new AbortController()
    const response = await fetch(url, { signal: controller.signal })
    const type = response.headers.get('content-type') || ''
    controller.abort()
    return { status: response.status, type }
  }

  await check('Stream tickets: header auth required; unknown stream refused', async () => {
    assert.equal((await mint('admin', null)).status, 401)
    assert.equal((await mint('admin', 'forged.token.value')).status, 401)
    assert.equal((await mint('nope')).status, 400)
  })

  await check('Every audited stream refuses the JWT in its URL (admin, revenue, profile, billing)', async () => {
    for (const stream of ['admin', 'revenue', 'profile', 'billing']) {
      const url = `${BASE}/api/v1/${stream}/stream?token=${encodeURIComponent(owner.token)}`
      const result = await openStatus(url)
      // admin/revenue answer 401; profile/billing answer an SSE "error" frame and close.
      if (result.status === 200) {
        const body = await (await fetch(url)).text()
        assert.match(body, /event: error/, `${stream} accepted the JWT from the URL`)
      } else {
        assert.equal(result.status, 401, `${stream}: HTTP ${result.status}`)
      }
    }
  })

  await check('Stream tickets: valid once, for one stream only, then refused', async () => {
    const ticket = (await mint('admin')).json.data
    assert.ok(typeof ticket.ticket === 'string' && ticket.ticket.length >= 40, 'ticket too short')
    assert.ok(!ticket.ticket.includes('.'), 'a ticket must be opaque, not a JWT')
    const first = await openStatus(`${BASE}${ticket.path}?ticket=${encodeURIComponent(ticket.ticket)}`)
    assert.equal(first.status, 200)
    assert.match(first.type, /text\/event-stream/)
    const replay = await openStatus(`${BASE}${ticket.path}?ticket=${encodeURIComponent(ticket.ticket)}`)
    assert.equal(replay.status, 401, 'a used ticket was accepted again')
    const forRevenue = (await mint('revenue')).json.data
    const wrongStream = await openStatus(`${BASE}/api/v1/admin/stream?ticket=${encodeURIComponent(forRevenue.ticket)}`)
    assert.equal(wrongStream.status, 401, 'a revenue ticket opened the admin stream')
  })

  await check('Stream tickets open the profile and billing streams (connected frame)', async () => {
    for (const stream of ['profile', 'billing']) {
      const ticket = (await mint(stream)).json.data
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 15_000)
      const response = await fetch(`${BASE}${ticket.path}?ticket=${encodeURIComponent(ticket.ticket)}`, { signal: controller.signal })
      const reader = response.body!.getReader()
      const { value } = await reader.read()
      controller.abort()
      clearTimeout(timer)
      assert.match(new TextDecoder().decode(value), /event: connected/, `${stream} did not connect with a ticket`)
    }
  })

  await check('Profile API refuses the JWT in a query string outside /stream', async () => {
    const refused = await call('GET', '/api/v1/profile', owner.token, { query: true })
    assert.equal(refused.status, 401)
  })

  // ---- Settings session revocation -----------------------------------------
  const bundle = await call('GET', '/api/v1/profile', owner.token)
  await check('Settings lists the current session once, keyed on the Auth session', async () => {
    assert.equal(bundle.status, 200)
    const current = (bundle.json.data.sessions as any[]).filter((s) => s.current)
    assert.equal(current.length, 1)
    // A refreshed access token for the SAME auth session must not add a row.
    const client = anonClient()
    const { data, error } = await client.auth.setSession({ access_token: owner.token, refresh_token: owner.refresh })
    if (error || !data.session) throw new Error(`setSession: ${error?.message}`)
    const { data: refreshed, error: refreshError } = await client.auth.refreshSession()
    if (refreshError || !refreshed.session) throw new Error(`refresh: ${refreshError?.message}`)
    owner.token = refreshed.session.access_token
    owner.refresh = refreshed.session.refresh_token
    const again = await call('GET', '/api/v1/profile', owner.token)
    const currentAgain = (again.json.data.sessions as any[]).filter((s) => s.current)
    assert.equal(currentAgain.length, 1)
    assert.equal(currentAgain[0].id, current[0].id, 'token refresh created a new session row')
  })

  await check('Settings refuses to revoke the session in use', async () => {
    const fresh = await call('GET', '/api/v1/profile', owner.token)
    const current = (fresh.json.data.sessions as any[]).find((s) => s.current)
    const result = await call('DELETE', `/api/v1/profile/sessions/${current.id}`, owner.token)
    assert.equal(result.status, 400)
    assert.equal(result.json.error?.code, 'CURRENT_SESSION')
  })

  await check('Settings revokes ANOTHER session for real (or refuses with 503 and changes nothing)', async () => {
    const second = await ownerSession()
    const seen = await call('GET', '/api/v1/profile', second.token)
    const secondRow = (seen.json.data.sessions as any[]).find((s) => s.current)
    assert.ok(secondRow, 'second session not listed')
    const result = await call('DELETE', `/api/v1/profile/sessions/${secondRow.id}`, owner.token)
    if (result.status === 503) {
      assert.equal(result.json.error?.code, 'SESSION_REVOCATION_UNAVAILABLE')
      const still = await call('GET', '/api/v1/profile', owner.token)
      assert.ok((still.json.data.sessions as any[]).some((s) => s.id === secondRow.id), 'a refused revoke must not hide the row')
      console.log('      note: qguard_revoke_auth_session is not installed — apply supabase/settings-session-revocation.sql')
      // Clean up the extra session we created.
      const client = anonClient()
      await client.auth.setSession({ access_token: second.token, refresh_token: second.refresh })
      await client.auth.signOut({ scope: 'local' })
      return
    }
    assert.equal(result.status, 200, JSON.stringify(result.json))
    assert.equal(result.json.data.authSessionEnded, true)
    const client = anonClient()
    const { error } = await client.auth.refreshSession({ refresh_token: second.refresh })
    assert.ok(error, 'the revoked session can still refresh its token')
  })

  console.log(`\n${passed} passed, ${failed} failed`)
  if (failed) process.exit(1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
