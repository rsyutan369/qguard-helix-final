/**
 * Realtime publication probe — verifies whether postgres_changes events are
 * delivered for the Quantum Readiness evidence tables (i.e. whether the tables
 * are members of the `supabase_realtime` publication).
 *
 * Method: subscribe with the service-role client to INSERT events on
 * public.assets, insert a probe row, wait up to 8 s for the event, then delete
 * the probe row. Read-only for every other table.
 *
 *   npx tsx realtime-probe.ts   (from repo root: npx tsx <scratchpad>/realtime-probe.ts)
 */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const url = process.env.VITE_SUPABASE_URL || ''
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const PROBE_NAME = `realtime-probe-${Date.now()}`

async function main() {
  if (!url || !serviceKey) throw new Error('Missing VITE_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY')
  const admin = createClient(url, serviceKey, { auth: { persistSession: false } })

  // Use the report-check user so RLS-scoped cleanup is deterministic.
  const { data: userList } = await admin.auth.admin.listUsers({ page: 1, perPage: 10 })
  const users = (userList?.users ?? []) as Array<{ id: string; email?: string | null }>
  const user = users.find((u) => u.email === 'cybersniper26@gmail.com') || users[0]
  if (!user) throw new Error('No user found to attribute the probe row to')

  let received = false
  const channel = admin
    .channel('probe-assets')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'assets' }, (payload) => {
      const name = (payload.new as { name?: string })?.name
      if (name === PROBE_NAME) received = true
    })

  const subscribed = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), 10000)
    channel.subscribe((status) => {
      if (status === 'SUBSCRIBED') {
        clearTimeout(timer)
        resolve(true)
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        clearTimeout(timer)
        resolve(false)
      }
    })
  })
  console.log(`subscribe: ${subscribed ? 'SUBSCRIBED' : 'FAILED'}`)
  if (!subscribed) {
    await admin.removeChannel(channel)
    process.exit(2)
  }

  const { data: inserted, error: insErr } = await admin
    .from('assets')
    .insert({ user_id: user.id, name: PROBE_NAME, type: 'probe', environment: 'development', status: 'inactive' })
    .select('id')
    .single()
  if (insErr) throw new Error(`probe insert failed: ${insErr.message}`)

  await new Promise((resolve) => setTimeout(resolve, 8000))

  if (inserted?.id) await admin.from('assets').delete().eq('id', inserted.id)
  await admin.removeChannel(channel)

  console.log(`postgres_changes delivery for public.assets: ${received ? 'DELIVERED ✓ (table is in supabase_realtime)' : 'NOT DELIVERED ✗ (table is NOT in the supabase_realtime publication — run supabase/quantum-readiness-realtime.sql)'}`)
  process.exit(received ? 0 : 1)
}

main().catch((e) => {
  console.error('PROBE FAILED:', e?.message || e)
  process.exit(3)
})
