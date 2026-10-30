import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
const admin = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
;(async () => {
  const { data } = await admin.from('scanner_alerts').select('category,title,message,recommendation,metadata').limit(500)
  const by = new Map<string, number>()
  for (const r of data || []) by.set(String(r.category), (by.get(String(r.category)) || 0) + 1)
  console.log('categories:', JSON.stringify([...by]))
  for (const r of (data || []).filter((x: any) => /offline|heartbeat|agent/i.test(`${x.title}`)).slice(0, 2)) console.log('agent alert:', JSON.stringify({ c: r.category, t: r.title, m: String(r.message).slice(0, 160), rec: String(r.recommendation).slice(0, 160), meta: Object.keys(r.metadata || {}) }))
  for (const r of (data || []).filter((x: any) => /RSA detected/i.test(`${x.title}`)).slice(0, 1)) console.log('rsa alert:', JSON.stringify({ c: r.category, t: r.title, m: String(r.message).slice(0, 200), rec: String(r.recommendation).slice(0, 200), meta: r.metadata && Object.fromEntries(Object.entries(r.metadata).slice(0, 8)) }).slice(0, 700))
})()
