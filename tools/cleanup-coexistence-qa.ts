/** Recover only orphan execution rows from this check's explicitly named QA agents. */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data, error } = await db.from('migration_execution').select('id,user_id,metadata').eq('metadata->>source', 'agent-remediation').ilike('metadata->>agentName', 'QA coexistence %')
if (error && !/42P01|PGRST205/.test(error.code)) throw error
let removed = 0
for (const row of data || []) {
  if (!/^QA coexistence (collector|scanner|patcher|operator) \d+$/.test(row.metadata?.agentName || '')) continue
  const account = await db.auth.admin.getUserById(row.user_id)
  if (!account.error || account.error.status !== 404) continue
  const result = await db.from('migration_execution').delete().eq('id', row.id).eq('user_id', row.user_id)
  if (result.error) throw result.error
  removed++
}
console.log(`Removed ${removed} marked orphan QA execution rows; no active tenant was changed.`)
