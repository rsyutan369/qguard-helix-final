/**
 * Offline + live checks for the `device-link` Edge Function.
 *
 *   npx tsx tools/device-link-edge-check.ts          # pure logic (no network)
 *   npx tsx tools/device-link-edge-check.ts --live   # also probe the deployed function
 *
 * The live probe never sends a user token: it proves routing, CORS, the auth
 * gates and that an unauthenticated device can open (and poll) a link request.
 */
import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import {
  claimView,
  clientIp,
  credentialMethodFor,
  decodeJwtClaims,
  e164,
  generateLinkCode,
  generateSecret,
  isSecret,
  normalizeLinkCode,
  normalizePlatform,
  parseSmsHookPayload,
  routeOf,
  sanitizeLabel,
  sha256Hex,
  twilioConfig,
  twilioMessageForm,
  verifyStandardWebhook,
} from '../supabase/functions/device-link/logic'

let passed = 0
async function check(name: string, run: () => void | Promise<void>) {
  await run()
  passed += 1
  console.log(`  ok  ${name}`)
}

const headers = (values: Record<string, string>) => ({ get: (name: string) => values[name.toLowerCase()] ?? null })

async function offline() {
  console.log('device-link logic')

  await check('routes resolve after the function name', () => {
    assert.equal(routeOf('https://x.supabase.co/functions/v1/device-link/start'), '/start')
    assert.equal(routeOf('https://x.supabase.co/functions/v1/device-link/claim/'), '/claim')
    assert.equal(routeOf('https://x.supabase.co/functions/v1/device-link'), '/')
  })

  await check('codes are 60-bit Crockford, grouped, and round-trip through normalisation', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 500; i += 1) {
      const code = generateLinkCode()
      assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)
      assert.equal(normalizeLinkCode(code), code)
      seen.add(code)
    }
    assert.equal(seen.size, 500, 'codes must not repeat')
  })

  await check('typed codes forgive case, spacing and look-alike letters', () => {
    assert.equal(normalizeLinkCode('ab1c d2ef-g3hj'), 'AB1C-D2EF-G3HJ')
    assert.equal(normalizeLinkCode('OOOO-IIII-LLLL'), '0000-1111-1111')
    assert.equal(normalizeLinkCode('ABCD-EFGH-JKM'), null, 'too short')
    assert.equal(normalizeLinkCode('ABCD-EFGH-JKMU'), null, 'U is not in the alphabet')
    assert.equal(normalizeLinkCode(42), null)
  })

  await check('secrets are 256-bit base64url', () => {
    const secret = generateSecret()
    assert.ok(isSecret(secret))
    assert.equal(Buffer.from(secret, 'base64url').length, 32)
    assert.ok(!isSecret('short'))
  })

  await check('sha256Hex matches node:crypto', async () => {
    const { createHash } = await import('node:crypto')
    assert.equal(await sha256Hex('qguard'), createHash('sha256').update('qguard').digest('hex'))
  })

  await check('labels cannot smuggle control or bidi-override characters', () => {
    assert.equal(sanitizeLabel('Work‮exe.pdf\n laptop'), 'Workexe.pdf laptop')
    assert.equal(sanitizeLabel(''), 'New device')
    assert.equal(sanitizeLabel('x'.repeat(200)).length, 64)
    assert.equal(normalizePlatform('Windows'), 'windows')
    assert.equal(normalizePlatform('toaster'), 'unknown')
  })

  await check('client IP comes from the first forwarded hop and is validated', () => {
    assert.equal(clientIp(headers({ 'x-forwarded-for': '203.0.113.9, 10.0.0.1' })), '203.0.113.9')
    assert.equal(clientIp(headers({ 'x-forwarded-for': '2001:db8::1' })), '2001:db8::1')
    assert.equal(clientIp(headers({ 'x-forwarded-for': '<script>' })), null)
    assert.equal(clientIp(headers({})), null)
  })

  await check('credential method: confirmed email first, then confirmed phone, never a placeholder', () => {
    const at = '2026-10-21T00:00:00Z'
    assert.equal(credentialMethodFor({ email: 'a@b.co', email_confirmed_at: at }), 'email_token')
    assert.equal(credentialMethodFor({ email: 'a@b.co', email_confirmed_at: null, phone: '15551234567', phone_confirmed_at: at }), 'sms_code')
    assert.equal(credentialMethodFor({ email: 'id@qguard.local', email_confirmed_at: at, phone: '15551234567', phone_confirmed_at: at }), 'sms_code')
    assert.equal(credentialMethodFor({ phone: '15551234567', phone_confirmed_at: null }), null)
    assert.equal(credentialMethodFor({}), null)
    assert.equal(e164('15551234567'), '+15551234567')
  })

  await check('claim view: pending, expiry, grace after approval, terminal states', () => {
    const now = Date.parse('2026-10-21T10:00:00Z')
    const future = '2026-10-21T10:01:00Z'
    const past = '2026-10-21T09:59:00Z'
    assert.deepEqual(claimView({ status: 'pending', expires_at: future }, now), { status: 'pending', expiresAt: future })
    assert.deepEqual(claimView({ status: 'pending', expires_at: past }, now), { status: 'expired' })
    assert.deepEqual(claimView({ status: 'approved', expires_at: past }, now), { status: 'ready' }, 'within grace')
    assert.deepEqual(claimView({ status: 'approved', expires_at: '2026-10-21T09:50:00Z' }, now), { status: 'expired' })
    assert.deepEqual(claimView({ status: 'rejected', expires_at: future }, now), { status: 'rejected' })
    assert.deepEqual(claimView({ status: 'consumed', expires_at: future }, now), { status: 'used' })
    assert.deepEqual(claimView({ status: 'claiming', expires_at: future }, now), { status: 'used' })
    assert.deepEqual(claimView({ status: 'failed', expires_at: future, failure_reason: 'sms_rate_limited' }, now), { status: 'failed', reason: 'sms_rate_limited' })
  })

  await check('JWT claims decode without verification (getUser verifies first)', () => {
    const payload = Buffer.from(JSON.stringify({ sub: 'u', aal: 'aal2' })).toString('base64url')
    assert.equal(decodeJwtClaims(`h.${payload}.s`).aal, 'aal2')
    assert.deepEqual(decodeJwtClaims('garbage'), {})
  })

  await check('Standard Webhooks signatures verify, and tampering / staleness / wrong key fail', async () => {
    const key = randomBytes(32)
    const secret = `v1,whsec_${key.toString('base64')}`
    const body = JSON.stringify({ user: { id: '00000000-0000-4000-8000-000000000001', phone: '15551234567' }, sms: { otp: '123456' } })
    const id = 'msg_1'
    const ts = 1_800_000_000
    const sig = createHmac('sha256', key).update(`${id}.${ts}.${body}`).digest('base64')
    const good = headers({ 'webhook-id': id, 'webhook-timestamp': String(ts), 'webhook-signature': `v1,bogus v1,${sig}` })
    assert.equal(await verifyStandardWebhook(secret, good, body, ts + 10), true)
    assert.equal(await verifyStandardWebhook(secret, good, body.replace('123456', '654321'), ts + 10), false, 'tampered body')
    assert.equal(await verifyStandardWebhook(secret, good, body, ts + 3600), false, 'stale')
    assert.equal(await verifyStandardWebhook(`v1,whsec_${randomBytes(32).toString('base64')}`, good, body, ts), false, 'wrong key')
    assert.equal(await verifyStandardWebhook(secret, headers({}), body, ts), false, 'no headers')
  })

  await check('SMS hook payloads are strictly parsed', () => {
    const userId = '00000000-0000-4000-8000-000000000001'
    assert.deepEqual(parseSmsHookPayload({ user: { id: userId, phone: '15551234567' }, sms: { otp: '123456' } }), { userId, phone: '+15551234567', otp: '123456' })
    assert.equal(parseSmsHookPayload({ user: { id: 'nope', phone: '1' }, sms: { otp: '123456' } }), null)
    assert.equal(parseSmsHookPayload({ user: { id: userId, phone: '15551234567' }, sms: { otp: '12ab' } }), null)
    assert.equal(parseSmsHookPayload(null), null)
  })

  await check('Twilio config needs a sender and prefers a messaging service', () => {
    const env = (values: Record<string, string>) => (key: string) => values[key]
    assert.equal(twilioConfig(env({ TWILIO_ACCOUNT_SID: 'AC1', TWILIO_AUTH_TOKEN: 't' })), null)
    const config = twilioConfig(env({ TWILIO_ACCOUNT_SID: 'AC1', TWILIO_AUTH_TOKEN: 't', TWILIO_MESSAGING_SERVICE_SID: 'MG1', TWILIO_FROM_NUMBER: '+1555' }))!
    const form = twilioMessageForm(config, '+15551234567', 'hi')
    assert.equal(form.get('MessagingServiceSid'), 'MG1')
    assert.equal(form.get('From'), null)
  })
}

function supabaseUrlAndAnon(): { url: string; anon: string } {
  const text = readFileSync(new URL('../qguard-messaging/.env.local', import.meta.url), 'utf8')
  const read = (key: string) => (new RegExp(`^${key}=(.*)$`, 'm').exec(text)?.[1] ?? '').replace(/["\r]/g, '').trim()
  return { url: read('VITE_SUPABASE_URL'), anon: read('VITE_SUPABASE_ANON_KEY') }
}

async function live() {
  const { url, anon } = supabaseUrlAndAnon()
  const base = `${url}/functions/v1/device-link`
  const post = (route: string, body: unknown, token?: string) =>
    fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: anon, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    })
  console.log(`device-link live probe → ${base}`)

  await check('health answers with configuration booleans only', async () => {
    const response = await fetch(`${base}/health`, { headers: { apikey: anon } })
    assert.equal(response.status, 200)
    const body = await response.json()
    assert.deepEqual(Object.keys(body).sort(), ['ok', 'smsHook', 'twilio'])
  })

  await check('CORS preflight is answered', async () => {
    const response = await fetch(`${base}/start`, { method: 'OPTIONS' })
    assert.equal(response.status, 204)
    assert.equal(response.headers.get('access-control-allow-origin'), '*')
  })

  let opened: { linkId: string; code: string; claimSecret: string } | null = null
  await check('an unauthenticated device can open a link request', async () => {
    const response = await post('/start', { label: 'edge-check probe', platform: 'linux' })
    assert.equal(response.status, 200)
    opened = await response.json()
    assert.ok(normalizeLinkCode(opened!.code))
    assert.ok(isSecret(opened!.claimSecret))
  })

  await check('polling with the claim secret reports pending; a wrong secret looks like no request', async () => {
    const good = await (await post('/claim', { linkId: opened!.linkId, claimSecret: opened!.claimSecret })).json()
    assert.equal(good.status, 'pending')
    const bad = await post('/claim', { linkId: opened!.linkId, claimSecret: generateSecret() })
    assert.equal(bad.status, 404)
  })

  await check('approver routes refuse a caller with no session', async () => {
    for (const route of ['/inspect', '/approve', '/reject', '/status', '/complete']) {
      const response = await post(route, { code: opened!.code })
      assert.equal(response.status, 401, route)
    }
  })

  await check('the SMS hook refuses an unsigned delivery', async () => {
    const response = await post('/sms-hook', { user: {}, sms: {} })
    assert.ok([401, 500].includes(response.status), `got ${response.status}`)
  })
}

await offline()
if (process.argv.includes('--live')) await live()
console.log(`\n${passed} checks passed`)
