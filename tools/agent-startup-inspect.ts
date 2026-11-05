/** Read-only startup diagnostics. Never prints enrollment tokens or signing keys. */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data, error } = await db.from('scanner_agents')
  .select('id,name,hostname,platform,version,status,last_seen_at,revoked_at,metadata')
  .or('hostname.eq.TestVM,name.ilike.TestVM%')
if (error) throw error
for (const row of data || []) {
  const { data: events, error: eventError } = await db.from('agent_heartbeats')
    .select('observed_at,status,telemetry').eq('agent_id', row.id)
    .order('observed_at', { ascending: false }).limit(10)
  console.log(JSON.stringify({
    agent: { id: row.id, name: row.name, hostname: row.hostname, platform: row.platform, version: row.version, status: row.status, lastSeen: row.last_seen_at, revoked: row.revoked_at },
    events: (events || []).map((entry) => ({ at: entry.observed_at, status: entry.status, phase: entry.telemetry?.phase, detail: entry.telemetry?.detail, error: entry.telemetry?.error })),
    eventReadError: eventError?.message,
  }, null, 2))
}
