/** Consolidate one explicitly selected agent. Dry run unless --apply is supplied. */
import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import fs from 'node:fs'
import path from 'node:path'
import { consolidateAgentDeviceProfile } from '../src/api-server/agent-device-profiles'
import { exclusivelyObservedByAgent } from '../src/lib/agent-installer/device-profile'

const args = process.argv.slice(2)
const agentId = args[args.indexOf('--agent-id') + 1]
if (!args.includes('--agent-id') || !/^[a-f0-9-]{36}$/i.test(agentId || '')) throw new Error('Provide --agent-id <uuid>; add --apply after reviewing the dry run.')
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data: agent, error } = await db.from('scanner_agents').select('id,user_id,name,hostname,platform,metadata').eq('id', agentId).single()
if (error || !agent) throw new Error('The selected agent could not be read')
const { data: assets, error: assetError } = await db.from('assets').select('*').eq('user_id', agent.user_id).limit(4000)
if (assetError) throw assetError
const candidates = (assets || []).filter((asset) => exclusivelyObservedByAgent(asset, agent) && !asset.metadata?.deviceProfile)
const counts: Record<string, number | null> = {}
const originalIds: Record<string, string[]> = {}
for (const table of ['crypto_inventory', 'crypto_exposures', 'pqc_scan_results', 'scanner_evidence', 'certificates']) {
  const read = await db.from(table).select('id', { count: 'exact' }).eq('user_id', agent.user_id).limit(10000)
  if (read.error) throw read.error
  counts[table] = read.count
  originalIds[table] = (read.data || []).map((row) => row.id)
}
console.log(JSON.stringify({ mode: args.includes('--apply') ? 'apply' : 'dry-run', agentId, hostname: agent.hostname, agentName: agent.name, deviceSubjects: candidates.length, unrelatedAssets: (assets?.length || 0) - candidates.length, before: counts }))
if (args.includes('--apply')) {
  const dir = path.resolve('artifacts/device-profile-consolidation')
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, `${agentId}-${Date.now()}-before.json`), JSON.stringify({ agent, assets, counts, originalIds }, null, 2))
  const result = await consolidateAgentDeviceProfile(db, agent)
  const verified: Record<string, number> = {}
  for (const [table, ids] of Object.entries(originalIds)) {
    // PostgREST URLs are bounded; scanner_evidence is checked by count instead.
    if (ids.length > 300) {
      const total = await db.from(table).select('id', { count: 'exact', head: true }).eq('user_id', agent.user_id)
      if (total.error || (total.count || 0) < (counts[table] || 0)) throw new Error(`Evidence count decreased in ${table}`)
      verified[table] = total.count || 0
    } else {
      const read = await db.from(table).select('id', { count: 'exact', head: true }).eq('user_id', agent.user_id).in('id', ids)
      if (read.error || read.count !== ids.length) throw new Error(`Original record identifiers could not be verified in ${table}`)
      verified[table] = read.count || 0
    }
  }
  const { data: after } = await db.from('assets').select('id,name,status,metadata').eq('user_id', agent.user_id)
  const unrelated = (assets || []).filter((asset) => !candidates.some((item) => item.id === asset.id) && !asset.metadata?.deviceProfile)
  if (unrelated.some((asset) => !after?.some((row) => row.id === asset.id && row.name === asset.name))) throw new Error('An unrelated asset changed unexpectedly')
  const visible = (after || []).filter((asset) => !asset.metadata?.consolidatedIntoAssetId)
  const report = { ...result, originalRecordsPreserved: verified, operationalAssets: visible.map((asset) => ({ id: asset.id, name: asset.name })), retainedAuditAliases: (after || []).filter((asset) => asset.metadata?.consolidatedIntoAssetId === result.assetId).length }
  fs.writeFileSync(path.join(dir, `${agentId}-after.json`), JSON.stringify(report, null, 2))
  console.log(JSON.stringify(report))
}
