import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data: agents, error } = await db.from('scanner_agents').select('id,user_id,name,hostname,platform,metadata,revoked_at')
if (error) throw error
for (const agent of agents || []) {
  if (agent.hostname !== 'TestVM') continue
  const { data: assets, error: assetError } = await db.from('assets').select('id,name,type,status,metadata').eq('user_id', agent.user_id).limit(4000)
  if (assetError) throw assetError
  const own = (assets || []).filter((asset) => (asset.metadata?.scanSources || []).some((source: any) => source.agentId === agent.id) || asset.metadata?.boundAgentId === agent.id)
  const counts: Record<string, number | null> = {}
  for (const table of ['crypto_inventory', 'crypto_exposures', 'pqc_scan_results', 'scanner_evidence', 'certificates']) {
    const read = await db.from(table).select('id', { head: true, count: 'exact' }).eq('user_id', agent.user_id)
    counts[table] = read.count
  }
  console.log(JSON.stringify({ agent: { id: agent.id, tenant: agent.user_id, name: agent.name, hostname: agent.hostname, platform: agent.platform, binding: agent.metadata?.binding || null, deviceProfile: agent.metadata?.deviceProfileAssetId || null }, assets: { total: assets?.length, attributedToAgent: own.length, unrelated: (assets || []).filter((asset) => !own.some((item) => item.id === asset.id)).map((asset) => ({ id: asset.id, name: asset.name, source: asset.metadata?.source })) }, counts }))
}
