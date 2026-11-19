/** Scratch: dump the payload shapes behind the five discovery/migration pages. */
import 'dotenv/config'
import { writeFileSync, mkdirSync } from 'node:fs'
import { createClient } from '@supabase/supabase-js'

const BASE = process.env.ORIGIN || 'http://localhost:3000'
const EMAIL = process.argv[2] || 'zachmatthew369@gmail.com'
const OUT = process.argv[3] || '.'
const SUPA = process.env.VITE_SUPABASE_URL!
const admin = createClient(SUPA, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })

async function main() {
  const { data: link, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email: EMAIL })
  if (error) throw error
  const anon = createClient(SUPA, process.env.VITE_SUPABASE_ANON_KEY!, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error: e2 } = await anon.auth.verifyOtp({ token_hash: (link as any).properties.hashed_token, type: 'magiclink' })
  if (e2) throw e2
  const token = data.session!.access_token
  mkdirSync(OUT, { recursive: true })
  const paths: Record<string, string> = {
    intel: '/api/v1/scanner/intelligence',
    qr: '/api/v1/quantum-readiness',
    mi: '/api/v1/migration-intelligence',
    plan: '/api/v1/migration-planner',
    planAssets: '/api/v1/migration-planner/assets?limit=400&sort=priority&posture=all&environment=all&priority=all&status=all&search=',
    queue: '/api/v1/migration-planner/queue',
    plans: '/api/v1/migration-planner/plans',
    sandbox: '/api/v1/sandbox/snapshot',
    workflow: '/api/v1/migration-workflow',
  }
  try {
    for (const [name, path] of Object.entries(paths)) {
      const t = Date.now()
      const res = await fetch(BASE + path, { headers: { Authorization: `Bearer ${token}` } })
      const text = await res.text()
      writeFileSync(`${OUT}/${name}.json`, text)
      let keys = ''
      try {
        const json = JSON.parse(text)
        const body = json.data && typeof json.data === 'object' ? json.data : json
        keys = Object.keys(body).join(',')
      } catch { /* not json */ }
      console.log(`${name.padEnd(11)} ${res.status} ${String(text.length).padStart(8)}B ${String(Date.now() - t).padStart(6)}ms  ${keys.slice(0, 400)}`)
    }
  } finally {
    await anon.auth.signOut({ scope: 'local' }).catch(() => undefined)
  }
}
main().catch((err) => { console.error(err); process.exit(1) })
