/**
 * Live end-to-end check of the subscription pipeline on the real project:
 *
 *   billing_subscriptions write ──trigger──► user_entitlements (same transaction)
 *        └─ Supabase Realtime ──► a signed-in client (the messaging app's path)
 *   billing Edge Function /api/v1/subscriptions/* with a real user session
 *   RLS: a client cannot write its own subscription or entitlements
 *
 *   npx tsx tools/billing-e2e-live-check.ts
 *
 * Creates ONE disposable auth user (qguard-billing-e2e-*@example.com), gives it
 * a complimentary 'manual' row flagged e2e (never revenue), and deletes the
 * user at the end — the cascade removes every row it created. Reads the
 * service key from the root .env; never prints a secret.
 */
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createClient } from '@supabase/supabase-js'

const env = Object.fromEntries(
  readFileSync(new URL('../.env', import.meta.url), 'utf8').split(/\r?\n/).filter((line) => /^[A-Z_0-9]+=/.test(line))
    .map((line) => { const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1).replace(/^["']|["']$/g, '')] }),
) as Record<string, string>
const URL_ = env.VITE_SUPABASE_URL
const BILLING = `${URL_}/functions/v1/billing`
const admin = createClient(URL_, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })

const results: Array<{ name: string; ok: boolean; detail?: string }> = []
async function check(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    await fn()
    results.push({ name, ok: true })
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) })
  }
}
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function main() {
  const email = `qguard-billing-e2e-${randomBytes(4).toString('hex')}@example.com`
  const password = randomBytes(18).toString('base64url')
  const created = await admin.auth.admin.createUser({ email, password, email_confirm: true })
  if (created.error || !created.data.user) throw new Error(`create user failed: ${created.error?.message}`)
  const userId = created.data.user.id
  try {
    const client = createClient(URL_, env.VITE_SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
    const signedIn = await client.auth.signInWithPassword({ email, password })
    if (signedIn.error || !signedIn.data.session) throw new Error(`sign-in failed: ${signedIn.error?.message}`)
    const token = signedIn.data.session.access_token
    const api = (method: string, path: string, body?: unknown) => fetch(`${BILLING}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })

    // A new account: paid tiers only, so no access and no entitlement.
    const me0 = await api('GET', '/api/v1/subscriptions/me')
    const me0Body = await me0.json() as { data: any }
    await check('new account: no subscription, no access, no entitlements (no free tier)', () => {
      assert.equal(me0.status, 200)
      assert.equal(me0Body.data.subscription, null)
      assert.equal(me0Body.data.access, false)
      assert.deepEqual(me0Body.data.entitlements.keys, [])
    })
    await check('new account: a 64-hex obfuscated Play account id is issued and recorded server-side', async () => {
      assert.match(me0Body.data.playAccountId, /^[0-9a-f]{64}$/)
      assert.notEqual(me0Body.data.playAccountId, userId)
      const { data } = await admin.from('billing_play_accounts').select('obfuscated_account_id').eq('user_id', userId).maybeSingle()
      assert.equal(data?.obfuscated_account_id, me0Body.data.playAccountId)
    })
    // Which gate applies depends on whether the Play secrets are set (/health).
    const health = await fetch(`${BILLING}/health`).then((r) => r.json()).catch(() => ({})) as { data?: { playVerification?: boolean } }
    const playConfigured = health.data?.playVerification === true
    const verify = await api('POST', '/api/v1/subscriptions/verify', { purchaseToken: 'a'.repeat(60) })
    const verifyBody = await verify.json() as { error?: { code: string; message?: string } }
    const restore = await api('POST', '/api/v1/subscriptions/restore', { purchaseTokens: [] })
    if (!playConfigured) {
      await check('verify: refused honestly while Google Play credentials are not configured (503, nothing granted)', () => {
        assert.equal(verify.status, 503)
        assert.equal(verifyBody.error?.code, 'PLAY_NOT_CONFIGURED')
      })
      await check('restore: same gate as verify', () => assert.equal(restore.status, 503))
    } else {
      // A fake token reaches Google. "Not found" proves the service account
      // authenticated AND has Play Console permission for the package; a
      // 401/403 from Google (permissions not applied yet) or a rejected
      // service-account key surfaces as PLAY_VERIFY_FAILED (502) instead.
      await check('verify: Google Play answers a fake token with "purchase not found" (credentials + permissions work)', () => {
        assert.notEqual(verifyBody.error?.code, 'PLAY_VERIFY_FAILED',
          'PLAY_VERIFY_FAILED — Google refused the call: Play Console permissions not applied yet (wait and retry), or the service-account key is wrong; see the billing function logs')
        assert.equal(verify.status, 400, `status ${verify.status} ${JSON.stringify(verifyBody)}`)
        assert.equal(verifyBody.error?.code, 'PURCHASE_NOT_FOUND')
      })
      await check('restore: with nothing to restore, answers 200 and checks nothing', async () => {
        assert.equal(restore.status, 200)
        const body = await restore.json() as { data?: { checked?: number; restored?: number } }
        assert.equal(body.data?.checked, 0)
        assert.equal(body.data?.restored, 0)
      })
      await check('verify: a rejected token grants nothing', async () => {
        const me = await api('GET', '/api/v1/subscriptions/me')
        const meBody = await me.json() as { data: any }
        assert.equal(meBody.data.subscription, null)
        assert.equal(meBody.data.access, false)
      })
    }

    // Realtime: subscribe as the user BEFORE the server-side write.
    const events: Array<{ type: string; key: string; enabled: boolean }> = []
    await client.realtime.setAuth(token)
    const channel = client.channel(`e2e-entitlements-${userId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'user_entitlements', filter: `user_id=eq.${userId}` }, (payload) => {
        const row = (payload.new ?? {}) as { entitlement_key?: string; is_enabled?: boolean }
        events.push({ type: payload.eventType, key: String(row.entitlement_key ?? ''), enabled: Boolean(row.is_enabled) })
      })
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('realtime subscribe timed out')), 15_000)
      channel.subscribe((status) => {
        if (status === 'SUBSCRIBED') { clearTimeout(timer); resolve() }
        if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') { clearTimeout(timer); reject(new Error(`realtime ${status}`)) }
      })
    })

    // Server-side activation (the shape a verified purchase writes), flagged e2e/complimentary.
    const insert = await admin.from('billing_subscriptions').insert({
      user_id: userId, subscription_id: `e2e_${userId}`, provider: 'manual', plan: 'Pro', status: 'active', billing_cycle: 'monthly',
      metadata: { complimentary: true, e2e: true, source: 'tools/billing-e2e-live-check.ts' },
    })
    await check('server write accepted', () => assert.equal(insert.error, null))
    for (let i = 0; i < 40 && events.filter((e) => e.enabled).length < 30; i += 1) await sleep(250)
    await check('realtime: the signed-in client receives the 30 Pro entitlements pushed by the database', () => {
      assert.equal(new Set(events.filter((e) => e.enabled).map((e) => e.key)).size, 30)
      assert.ok(events.some((e) => e.key === 'quantum_messaging'))
      assert.ok(!events.some((e) => e.key === 'qkms'), 'Elite-only keys are not granted to Pro')
    })
    const me1 = await (await api('GET', '/api/v1/subscriptions/me')).json() as { data: any }
    await check('/me reflects the verified plan, access and entitlements', () => {
      assert.equal(me1.data.subscription.plan, 'Pro')
      assert.equal(me1.data.access, true)
      assert.equal(me1.data.entitlements.keys.length, 30)
      assert.equal(me1.data.subscription.providerLabel, 'QGuard (complimentary)')
    })
    await check('database paywall rule agrees (qguard_has_messaging_access)', async () => {
      const { data, error } = await client.rpc('qguard_has_messaging_access', { uid: userId })
      assert.equal(error, null)
      assert.equal(data, true)
    })

    // RLS: the client cannot escalate.
    const selfUpgrade = await client.from('billing_subscriptions').update({ plan: 'Elite' }).eq('user_id', userId).select('id')
    await check('rls: a client cannot change its own subscription', () => assert.equal((selfUpgrade.data ?? []).length, 0))
    const selfGrant = await client.from('user_entitlements').insert({ user_id: userId, entitlement_key: 'qkms', is_enabled: true })
    await check('rls: a client cannot grant itself an entitlement', () => assert.ok(selfGrant.error))

    // Expiry: entitlements are withdrawn and the client hears it.
    const before = events.length
    await admin.from('billing_subscriptions').update({ status: 'expired' }).eq('user_id', userId)
    for (let i = 0; i < 40 && events.slice(before).filter((e) => !e.enabled).length < 30; i += 1) await sleep(250)
    await check('realtime: expiry withdraws every entitlement and reaches the client', () => {
      assert.equal(new Set(events.slice(before).filter((e) => !e.enabled).map((e) => e.key)).size, 30)
    })
    const ent = await (await api('GET', '/api/v1/subscriptions/entitlements')).json() as { data: any }
    await check('/entitlements is empty after expiry; the account itself remains', () => {
      assert.deepEqual(ent.data.keys, [])
    })
    const history = await (await api('GET', '/api/v1/subscriptions/history')).json() as { data: any }
    await check('/history shows the audited grant and removal', () => {
      const actions = (history.data.events as Array<{ action: string }>).map((e) => e.action)
      assert.ok(actions.includes('entitlement.granted'), actions.join(','))
      assert.ok(actions.includes('entitlement.removed'), actions.join(','))
    })
    await client.removeChannel(channel)
  } finally {
    const removed = await admin.auth.admin.deleteUser(userId)
    const leftovers = await Promise.all(['billing_subscriptions', 'user_entitlements', 'billing_play_accounts', 'billing_audit_events']
      .map(async (table) => [table, (await admin.from(table).select('user_id', { count: 'exact', head: true }).eq('user_id', userId)).count] as const))
    await check('cleanup: the disposable user and every row it created are gone', () => {
      assert.equal(removed.error, null)
      for (const [table, count] of leftovers) assert.equal(count, 0, table)
    })
  }

  let failed = 0
  for (const result of results) {
    console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.name}${result.detail ? `\n      ${result.detail}` : ''}`)
    if (!result.ok) failed += 1
  }
  console.log(`\n${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

void main()
