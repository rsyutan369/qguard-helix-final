import 'dotenv/config'
import { createClient, type User } from '@supabase/supabase-js'
import { cleanupQaTenant } from './qa-tenant-cleanup'
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data, error } = await db.auth.admin.listUsers({ page: 1, perPage: 1000 })
if (error) throw new Error(`QA account lookup failed: ${error.message}`)
const users = (data.users as User[]).filter((user) => user.user_metadata?.qa_fixture === true && /^scan-qa-[a-f0-9-]+@example\.test$/.test(user.email || ''))
console.log(`Marked scan QA accounts remaining: ${users.length}`)
for (const user of users) {
  await cleanupQaTenant(db, user.id)
  console.log('Removed marked QA account and verified inventory cleanup.')
}
