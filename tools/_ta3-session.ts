// TEMP: mint (or revoke) a QA browser session for headless verification. Deleted after the audit.
import 'dotenv/config'
import { readFileSync, writeFileSync, rmSync } from 'fs'
import { createClient } from '@supabase/supabase-js'
const SUPA = process.env.VITE_SUPABASE_URL!
const OUT = process.argv[3]
;(async () => {
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  if (process.argv[2] === 'revoke') {
    const { session } = JSON.parse(readFileSync(OUT, 'utf8'))
    await anon.auth.setSession({ access_token: session.access_token, refresh_token: session.refresh_token })
    const { error } = await anon.auth.signOut({ scope: 'local' })
    rmSync(OUT, { force: true })
    console.log('revoked:', error ? error.message : 'ok')
    return
  }
  const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const email = process.argv[2] || 'zachmatthew369@gmail.com'
  const { data: link } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  const { data } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  writeFileSync(OUT, JSON.stringify({ key: `sb-${new URL(SUPA).hostname.split('.')[0]}-auth-token`, session: data.session }))
  console.log('session written for', email.slice(0, 6))
})()
