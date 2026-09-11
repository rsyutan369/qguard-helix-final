import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { writeFileSync } from 'node:fs'

async function main() {
  const client = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
    auth: { persistSession: false },
  })

  const { data: sessions, error } = await client
    .from('pqc_scan_sessions')
    .select('id, user_id, targets, status, created_at, completed_at, summary, metadata')
    .order('created_at', { ascending: false })
    .limit(60)
  if (error) throw error

  const match = (sessions ?? []).filter((s: any) =>
    JSON.stringify(s.targets ?? '').toLowerCase().includes('primevideo'),
  )
  console.log('sessions total:', sessions?.length, '| primevideo:', match.length)
  for (const s of (match.length ? match : sessions ?? []).slice(0, 8)) {
    console.log('-', s.id, s.status, s.created_at, JSON.stringify(s.targets))
  }

  const chosen: any = match[0] ?? sessions?.[0]
  if (!chosen) return
  console.log('\n=== CHOSEN', chosen.id, chosen.status, JSON.stringify(chosen.targets))
  console.log('summary:', JSON.stringify(chosen.summary))

  const { data: results, error: rerr } = await client
    .from('pqc_scan_results')
    .select('*')
    .eq('scan_session_id', chosen.id)
  if (rerr) console.log('results error:', rerr.message)
  console.log('\nresults:', results?.length)
  const out = process.argv[2] || 'scan-dump.json'
  writeFileSync(out, JSON.stringify({ session: chosen, results }, null, 2))
  console.log('written ->', out)
}
main().catch((e) => { console.error(e); process.exit(1) })
