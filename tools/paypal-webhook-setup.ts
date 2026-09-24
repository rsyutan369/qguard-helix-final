/**
 * Register (or reuse) the PayPal webhook that activates subscriptions.
 *
 * The billing Edge Function (supabase/functions/billing) receives PayPal events
 * at /functions/v1/billing/api/v1/paypal/webhook and verifies each one against
 * PAYPAL_WEBHOOK_ID. Until this runs, no webhook exists for the app's REST
 * credentials, so PayPal never tells QGuard that a subscription was paid.
 *
 * Idempotent: an existing webhook for the same URL is reused and its event list
 * brought up to date. Writes the webhook id into .env (PAYPAL_WEBHOOK_ID only —
 * no other line is touched) and prints it for the Edge Function secrets.
 * Webhook ids are identifiers, not secrets; the PayPal client secret is read
 * from .env and never printed.
 *
 * Usage:  npx tsx tools/paypal-webhook-setup.ts [--dry-run]
 */
import 'dotenv/config'
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const PROJECT_REF = 'xsbdlahuecadzfajlvis'
const WEBHOOK_URL = `https://${PROJECT_REF}.supabase.co/functions/v1/billing/api/v1/paypal/webhook`
// Exactly the events the billing function handles.
const EVENT_TYPES = [
  'BILLING.SUBSCRIPTION.ACTIVATED',
  'BILLING.SUBSCRIPTION.UPDATED',
  'BILLING.SUBSCRIPTION.CANCELLED',
  'BILLING.SUBSCRIPTION.SUSPENDED',
  'BILLING.SUBSCRIPTION.EXPIRED',
  'BILLING.SUBSCRIPTION.PAYMENT.FAILED',
  'PAYMENT.SALE.COMPLETED',
  'PAYMENT.SALE.REFUNDED',
  'PAYMENT.SALE.REVERSED',
]

const ENV = String(process.env.PAYPAL_ENV || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live'
const BASE = ENV === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'
const CLIENT_ID = process.env.PAYPAL_CLIENT_ID || ''
const SECRET = process.env.PAYPAL_SECRET_KEY || process.env.PAYPAL_CLIENT_SECRET || ''
const DRY_RUN = process.argv.includes('--dry-run')

async function paypal(token: string | null, pathname: string, init: { method?: string; body?: unknown } = {}): Promise<any> {
  const response = await fetch(`${BASE}${pathname}`, {
    method: init.method ?? 'GET',
    headers: token
      ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
      : { 'Content-Type': 'application/json' },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  })
  const text = await response.text()
  const json = text ? JSON.parse(text) : {}
  if (!response.ok) throw new Error(`${init.method ?? 'GET'} ${pathname} failed (HTTP ${response.status}): ${json?.message ?? text}`)
  return json
}

async function token(): Promise<string> {
  const response = await fetch(`${BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  })
  const json: any = await response.json().catch(() => ({}))
  if (!response.ok || !json?.access_token) throw new Error(`PayPal authentication failed (HTTP ${response.status})`)
  return json.access_token
}

/** Replace only the PAYPAL_WEBHOOK_ID line, preserving the file's line endings. */
function writeWebhookIdToEnv(id: string): string | null {
  const envPath = path.resolve(process.cwd(), '.env')
  const original = readFileSync(envPath, 'utf8')
  const line = /^PAYPAL_WEBHOOK_ID=[^\r\n]*/m
  const previous = original.match(line)?.[0].slice('PAYPAL_WEBHOOK_ID='.length) ?? null
  const eol = original.includes('\r\n') ? '\r\n' : '\n'
  const updated = line.test(original)
    ? original.replace(line, `PAYPAL_WEBHOOK_ID=${id}`)
    : `${original}${original.endsWith(eol) ? '' : eol}PAYPAL_WEBHOOK_ID=${id}${eol}`
  if (updated !== original) writeFileSync(envPath, updated, 'utf8')
  return previous
}

async function main() {
  if (!CLIENT_ID || !SECRET) throw new Error('PAYPAL_CLIENT_ID / PAYPAL_SECRET_KEY are missing from .env')
  const accessToken = await token()
  const listed = await paypal(accessToken, '/v1/notifications/webhooks')
  const existing = (listed.webhooks ?? []).find((hook: any) => hook.url === WEBHOOK_URL)

  let webhookId: string
  if (existing) {
    webhookId = existing.id
    const have = new Set((existing.event_types ?? []).map((event: any) => event.name))
    const missing = EVENT_TYPES.filter((name) => !have.has(name))
    console.log(`Reusing webhook ${webhookId} (${ENV}) -> ${WEBHOOK_URL}`)
    if (missing.length && !DRY_RUN) {
      await paypal(accessToken, `/v1/notifications/webhooks/${webhookId}`, {
        method: 'PATCH',
        body: [{ op: 'replace', path: '/event_types', value: EVENT_TYPES.map((name) => ({ name })) }],
      })
      console.log(`  added event types: ${missing.join(', ')}`)
    }
  } else if (DRY_RUN) {
    console.log(`[dry-run] would create a ${ENV} webhook -> ${WEBHOOK_URL}`)
    return
  } else {
    const created = await paypal(accessToken, '/v1/notifications/webhooks', {
      method: 'POST',
      body: { url: WEBHOOK_URL, event_types: EVENT_TYPES.map((name) => ({ name })) },
    })
    webhookId = created.id
    console.log(`Created ${ENV} webhook ${webhookId} -> ${WEBHOOK_URL}`)
  }

  if (DRY_RUN) return
  const previous = writeWebhookIdToEnv(webhookId)
  console.log(previous === webhookId
    ? '.env PAYPAL_WEBHOOK_ID already current'
    : `.env PAYPAL_WEBHOOK_ID updated (${previous ? `was ${previous}` : 'was unset'})`)
  console.log(`\nEdge Function secret:  PAYPAL_WEBHOOK_ID=${webhookId}`)
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
})
