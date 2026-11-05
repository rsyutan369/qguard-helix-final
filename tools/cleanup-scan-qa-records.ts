import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { cleanupQaTenant } from './qa-tenant-cleanup'
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data, error } = await db.from('scanner_agents').select('id,user_id,metadata,name').contains('metadata', { source: 'isolated-scan-observability-qa', qa_fixture: true })
if (error) throw error
const ids = [...new Set((data || []).filter((agent) => agent.name === 'QA Windows collector' && agent.metadata?.qa_fixture === true).map((agent) => agent.user_id))]
for (const id of ids) await cleanupQaTenant(db, id)
console.log(`Removed retained inventory from ${ids.length} explicitly marked QA fixtures.`)
