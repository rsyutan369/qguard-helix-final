/**
 * Copy the billing configuration from .env into the `billing` Edge Function's
 * secrets, without ever printing a value.
 *
 * Needs the Supabase CLI to be logged in once (`npx supabase login`), or
 * SUPABASE_ACCESS_TOKEN in the environment.
 *
 * Set SUPABASE_PROJECT_REF explicitly. Preview by default, or use --apply.
 *
 * Only the keys the function reads are sent. The temporary env file lives in
 * the OS temp directory for the duration of the CLI call and is always deleted.
 */
import 'dotenv/config'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const PROJECT_REF = (process.env.SUPABASE_PROJECT_REF ?? '').trim()
const TIERS = ['STARTER', 'BASIC', 'PRO', 'ELITE']
const CYCLES = ['MONTHLY', 'YEARLY']
const REQUIRED = [
  'PAYPAL_CLIENT_ID',
  'PAYPAL_SECRET_KEY',
  'PAYPAL_WEBHOOK_ID',
  ...TIERS.flatMap((tier) => CYCLES.map((cycle) => `PAYPAL_PLAN_${tier}_${cycle}`)),
]

function quoted(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function main() {
  if (!/^[a-z0-9]{20}$/.test(PROJECT_REF) || process.env.VITE_SUPABASE_URL?.replace(/\/$/, '') !== `https://${PROJECT_REF}.supabase.co`) {
    throw new Error('Set SUPABASE_PROJECT_REF to the project identified by VITE_SUPABASE_URL before pushing billing secrets')
  }
  const values: Record<string, string> = {}
  const missing: string[] = []
  for (const key of REQUIRED) {
    const value = (process.env[key] ?? '').trim()
    if (value) values[key] = value
    else missing.push(key)
  }
  if (missing.length) {
    console.error(`Missing from .env: ${missing.join(', ')}`)
    process.exit(1)
  }
  if (/\s/.test(values.PAYPAL_WEBHOOK_ID) || values.PAYPAL_WEBHOOK_ID.length > 40) {
    console.error('PAYPAL_WEBHOOK_ID is not a webhook id — run `npx tsx tools/paypal-webhook-setup.ts` first.')
    process.exit(1)
  }
  values.PAYPAL_ENV = String(process.env.PAYPAL_ENV || 'live').trim().toLowerCase() === 'sandbox' ? 'sandbox' : 'live'
  values.APP_ORIGIN = (process.env.APP_ORIGIN || 'https://qguardhelix.com').trim()

  console.log(`Secrets for ${PROJECT_REF}/billing: ${Object.keys(values).join(', ')}`)
  if (!process.argv.includes('--apply') || process.argv.includes('--dry-run')) return

  const dir = mkdtempSync(path.join(tmpdir(), 'qguard-billing-'))
  const file = path.join(dir, 'billing.env')
  try {
    writeFileSync(file, Object.entries(values).map(([key, value]) => `${key}=${quoted(value)}`).join('\n') + '\n', { mode: 0o600 })
    const result = spawnSync('npx', ['--yes', 'supabase@latest', 'secrets', 'set', '--env-file', file, '--project-ref', PROJECT_REF], {
      stdio: 'inherit',
      shell: process.platform === 'win32',
    })
    if (result.status !== 0) {
      console.error('supabase secrets set failed — is the CLI logged in? (npx supabase login)')
      process.exit(result.status ?? 1)
    }
    console.log(`Billing secrets updated. Check: GET https://${PROJECT_REF}.supabase.co/functions/v1/billing/health`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

main()
