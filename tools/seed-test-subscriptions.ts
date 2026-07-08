/**
 * Seed test subscriptions for QA of the tier-based access control.
 *
 *   npx tsx tools/seed-test-subscriptions.ts
 *
 * Uses the service-role key to upsert an ACTIVE billing_subscriptions row and
 * set profiles.tier for a fixed set of test accounts. Idempotent (upsert on the
 * unique user_id index). Accounts must already have registered (exist in
 * auth.users); unregistered emails are reported and skipped.
 *
 * This ONLY touches the listed emails. Everyone else is unaffected and still
 * requires a real subscription.
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || ''
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''

if (!URL || !SERVICE_KEY) {
  console.error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY in .env')
  process.exit(1)
}

const ACCOUNTS: Array<{ email: string; plan: 'Starter' | 'Basic' | 'Pro' | 'Elite' }> = [
  { email: 'cybersniper26@gmail.com', plan: 'Starter' },
  { email: 'threathunter369@gmail.com', plan: 'Basic' },
  { email: 'teslagreat101@gmail.com', plan: 'Pro' },
  { email: 'zachmatthew369@gmail.com', plan: 'Elite' }, // owner (also auto-Elite via admin-access)
]

const admin = createClient(URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })

async function findUserId(email: string): Promise<string | null> {
  const target = email.trim().toLowerCase()
  // Page through auth users (fine for a test project's size).
  for (let page = 1; page <= 20; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 })
    if (error) throw error
    const users = (data?.users ?? []) as Array<{ id: string; email?: string | null }>
    const match = users.find((u) => (u.email || '').toLowerCase() === target)
    if (match) return match.id
    if (users.length < 200) break
  }
  return null
}

async function seed() {
  const now = new Date()
  const periodEnd = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
  const results: string[] = []

  for (const { email, plan } of ACCOUNTS) {
    try {
      const userId = await findUserId(email)
      if (!userId) {
        results.push(`SKIP   ${email.padEnd(28)} -> not registered yet (no auth.users row)`)
        continue
      }

      const { error: subError } = await admin.from('billing_subscriptions').upsert(
        {
          user_id: userId,
          subscription_id: `test-sub-${userId}`,
          provider: 'manual_test',
          provider_subscription_id: `TEST-${plan.toUpperCase()}-${userId.slice(0, 8)}`,
          plan,
          status: 'active',
          billing_cycle: 'monthly',
          auto_renew: true,
          cancel_at_period_end: false,
          renewal_date: periodEnd.toISOString(),
          account_created_at: now.toISOString(),
          current_period_start: now.toISOString(),
          current_period_end: periodEnd.toISOString(),
          metadata: { seeded: true, purpose: 'tier-access-qa' },
          updated_at: now.toISOString(),
        },
        { onConflict: 'user_id' },
      )
      if (subError) {
        results.push(`FAIL   ${email.padEnd(28)} -> ${subError.message}`)
        continue
      }

      const { error: profileError } = await admin
        .from('profiles')
        .update({ tier: plan.toLowerCase(), updated_at: now.toISOString() })
        .eq('id', userId)
      const tierNote = profileError ? ` (profiles.tier not updated: ${profileError.message})` : ''
      results.push(`OK     ${email.padEnd(28)} -> ${plan} active${tierNote}`)
    } catch (err) {
      results.push(`ERROR  ${email.padEnd(28)} -> ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  console.log('\n=== Test subscription seeding ===')
  for (const line of results) console.log(line)
  console.log('\nDone. Non-listed accounts still require a subscription.')
}

seed().catch((e) => {
  console.error(e)
  process.exit(1)
})
