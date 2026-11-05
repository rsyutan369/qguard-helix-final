import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'
import { buildScannerIntelligence } from '../src/api-server/scanner'
import { buildAssetRegister } from '../src/lib/assets/asset-register'
import fs from 'node:fs'
import path from 'node:path'
const id = process.argv[2]
if (!id || !/^[a-f0-9-]{36}$/i.test(id)) throw new Error('An explicit agent UUID is required')
const db = createClient(process.env.VITE_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, { auth: { persistSession: false } })
const { data: agent, error } = await db.from('scanner_agents').select('id,user_id,hostname,metadata').eq('id', id).single()
if (error || !agent) throw new Error('Agent not found')
const snapshot = await buildScannerIntelligence(process.env.SUPABASE_SERVICE_ROLE_KEY!, agent.user_id)
const register = buildAssetRegister({ snapshot })
const row = register.rows.find((asset) => asset.id === agent.metadata.deviceProfileAssetId)
if (!row) throw new Error('The canonical device profile is not present in the actual scanner projection')
const report = { operationalAssetCount: register.rows.length, assets: register.rows.map((asset) => asset.name),
  device: { id: row.id, name: row.name, status: row.pqcStatus, risk: row.riskScore, allComponents: row.componentList.length, configurationFindings: row.postureList.length, subjectsRetained: row.deviceProfile?.subjects },
  componentSubjects: row.componentList.slice(0, 4).map((component) => ({ name: component.name, subject: component.observedSubject, posture: component.posture })),
}
fs.mkdirSync(path.resolve('artifacts/device-profile-consolidation'), { recursive: true })
fs.writeFileSync(path.resolve('artifacts/device-profile-consolidation/current-view.json'), JSON.stringify(report, null, 2))
console.log(JSON.stringify(report))
