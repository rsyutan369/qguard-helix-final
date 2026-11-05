import { createHash } from 'node:crypto'
import { updateTenantRow } from './tenant-row-update'
import type { SupabaseClient } from '@supabase/supabase-js'
import type { AgentBinding } from '@/lib/agent-installer/agent-binding'
import { mergeScanSources, scanSourceFor } from '@/lib/assets/scan-provenance'
import { exclusivelyObservedByAgent, observationDescriptor, observationSubject, profileName, record } from '@/lib/agent-installer/device-profile'
import { isCryptographicComponent } from '@/lib/scanner/finding-identity'
import { algorithmFamily } from '@/lib/governance/subjects'

type Row = Record<string, any>
const locks = new Map<string, Promise<AgentBinding>>()
const profileId = (agent: Row) => {
  const hex = createHash('sha256').update(`qguard:device-profile:v1:${agent.user_id}:${agent.id}`).digest('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`
}
const missing = (error: any) => /42P01|42703|PGRST204|PGRST205/.test(String(error?.code || ''))

async function allRows(client: SupabaseClient, table: string, userId: string, configure: (query: any) => any = (query) => query): Promise<Row[]> {
  const rows: Row[] = []
  for (let offset = 0; ; offset += 1000) {
    const { data, error } = await configure(client.from(table).select('*').eq('user_id', userId)).order('id').range(offset, offset + 999)
    if (error) throw new Error(`${table}: ${error.message}`)
    rows.push(...(data || []))
    if (!data || data.length < 1000) return rows
  }
}

/** A stable tenant-and-agent id prevents simultaneous first uploads making two devices. */
export async function ensureAgentDeviceProfile(client: SupabaseClient, agent: Row): Promise<AgentBinding> {
  const key = `${agent.user_id}:${agent.id}`
  if (locks.has(key)) return locks.get(key)!
  const operation = (async (): Promise<AgentBinding> => {
    const id = profileId(agent)
    const { data: existing, error: readError } = await client.from('assets').select('*').eq('user_id', agent.user_id).eq('id', id).maybeSingle()
    if (readError) throw new Error('Unable to resolve the agent device profile')
    if (existing && existing.metadata?.deviceProfile?.agentId !== agent.id) throw new Error('The device profile identifier is already in use')
    const now = new Date().toISOString()
    const name = existing?.name || profileName(agent)
    if (!existing) {
      const { error } = await client.from('assets').upsert({
        id, user_id: agent.user_id, name, type: 'device', status: 'active',
        environment: agent.metadata?.environment || null,
        metadata: { createdVia: 'agent-device-profile', bindingKind: 'server', scannerEvidence: true,
          deviceProfile: { agentId: agent.id, hostname: agent.hostname, agentName: agent.name },
          scanSources: [scanSourceFor({ sourceType: 'local-agent', assetType: 'device', observedAt: now }, agent)] },
      }, { onConflict: 'id', ignoreDuplicates: true })
      if (error) throw new Error('Unable to create the agent device profile')
    }
    const binding: AgentBinding = { assetId: id, assetName: name, kind: 'server', path: null, attribution: 'bound', boundAt: now, boundBy: agent.user_id, createdForBinding: true }
    const saved = await updateTenantRow(client, 'scanner_agents', agent.user_id, agent.id, (fresh) => ({ metadata: { ...fresh.metadata, deviceProfileAssetId: id, assetId: id, assetName: name, assetType: 'device', binding } }))
    agent.metadata = saved.metadata
    return binding
  })()
  locks.set(key, operation)
  try { return await operation } finally { locks.delete(key) }
}

/** Persist ungraded but real cryptographic observations; unknown stays unclassified. */
export async function materializeDeviceObservations(client: SupabaseClient, agent: Row, binding: AgentBinding, evidence: Row[], existingRows?: Row[]) {
  const inventory = existingRows || await allRows(client, 'crypto_inventory', agent.user_id, (query) => query.eq('asset_id', binding.assetId))
  const represented = new Set(inventory.filter((item) => isCryptographicComponent(item, algorithmFamily)).map((item) => observationSubject(record(item.metadata).evidenceRecord || {})).filter(Boolean))
  const rows: Row[] = []
  for (const evidenceRow of evidence) {
    const descriptor = observationDescriptor(evidenceRow)
    const subject = observationSubject(evidenceRow)
    if (!descriptor || !subject || represented.has(subject)) continue
    represented.add(subject)
    const normalized = {
      ...evidenceRow, id: evidenceRow.id, agentId: evidenceRow.agentId || evidenceRow.agent_id || agent.id,
      assetName: evidenceRow.assetName || evidenceRow.asset_name, evidenceType: evidenceRow.evidenceType || evidenceRow.evidence_type,
      certificateFingerprint: evidenceRow.certificateFingerprint || evidenceRow.certificate_fingerprint,
      filePath: evidenceRow.filePath || evidenceRow.file_path,
      rawEvidence: evidenceRow.rawEvidence || evidenceRow.raw_evidence || {},
    }
    rows.push({ user_id: agent.user_id, asset_id: binding.assetId, item_type: descriptor.itemType, name: descriptor.name,
      algorithm: descriptor.algorithm, key_size: evidenceRow.keySize || evidenceRow.key_size || null, protocol: evidenceRow.protocol || null,
      is_vulnerable: false, is_quantum_safe: false, exposure_level: 'unknown',
      discovered_at: evidenceRow.observedAt || evidenceRow.observed_at || new Date().toISOString(),
      metadata: { source: `agent:${agent.name || agent.id}`, evidenceRecord: normalized, discoveredTarget: normalized.assetName,
        observationOnly: true, evidence: `Observed ${normalized.evidenceType} on ${normalized.assetName || agent.hostname}. Cryptographic posture has not been classified by a detection rule.`,
        recommendation: 'Review the observed cryptography and collect any missing algorithm or key-size evidence.' },
    })
  }
  for (let offset = 0; offset < rows.length; offset += 200) {
    const { error } = await client.from('crypto_inventory').insert(rows.slice(offset, offset + 200))
    if (error) throw new Error('Unable to persist observed device components')
  }
  return rows.length
}

/** Idempotent, non-destructive consolidation; original asset rows remain audit aliases. */
export async function consolidateAgentDeviceProfile(client: SupabaseClient, agent: Row) {
  const binding = await ensureAgentDeviceProfile(client, agent)
  const assets = await allRows(client, 'assets', agent.user_id)
  const profile = assets.find((asset) => asset.id === binding.assetId)!
  const children = assets.filter((asset) => asset.id !== binding.assetId && exclusivelyObservedByAgent(asset, agent))
  const ids = children.map((asset) => asset.id)
  const counts: Record<string, number> = {}
  // Keep row IDs, evidence metadata, timestamps and history intact; only their
  // current inventory attribution changes. Each update is tenant-scoped.
  for (const table of ['crypto_inventory', 'crypto_exposures', 'pqc_scan_results', 'vulnerabilities', 'certificates', 'runtime_crypto_events', 'scanner_alerts']) {
    if (!ids.length) { counts[table] = 0; continue }
    const { count, error } = await client.from(table).update({ asset_id: binding.assetId }, { count: 'exact' }).eq('user_id', agent.user_id).in('asset_id', ids)
    if (error && !missing(error)) throw new Error(`Device consolidation paused at ${table}: ${error.message}`)
    if (!error) counts[table] = count || 0
  }
  const now = new Date().toISOString()
  const oldSubjects = record(profile.metadata).deviceProfile?.subjects || []
  const subjects = [...new Map([...oldSubjects, ...children.map((asset) => ({ id: asset.id, name: asset.name, type: asset.type }))].map((asset: Row) => [asset.id, asset])).values()]
  const allSources = children.flatMap((asset) => Array.isArray(asset.metadata?.scanSources) ? asset.metadata.scanSources : [])
  const risks = [profile, ...children].map((asset) => asset.metadata?.riskScore == null ? NaN : Number(asset.metadata.riskScore)).filter(Number.isFinite)
  const worstRisk = risks.length ? Math.max(...risks) : null
  const { error: profileError } = await client.from('assets').update({
    metadata: { ...profile.metadata, deviceProfile: { ...profile.metadata.deviceProfile, consolidatedAt: now, subjects },
      scanSources: mergeScanSources(profile.metadata?.scanSources, allSources),
      ...(worstRisk === null ? {} : { riskScore: worstRisk, qScore: 100 - worstRisk }),
      agentBinding: { ...profile.metadata?.agentBinding, attribution: 'bound', targetRisk: { ...profile.metadata?.agentBinding?.targetRisk, ...Object.fromEntries(children.filter((asset) => asset.metadata?.riskScore != null).map((asset) => [asset.name, asset.metadata.riskScore])) } },
      last_scanned_at: children.map((asset) => asset.metadata?.last_scanned_at).filter(Boolean).sort().at(-1) || profile.metadata?.last_scanned_at },
  }).eq('user_id', agent.user_id).eq('id', binding.assetId)
  if (profileError) throw new Error('Unable to save the consolidated device profile')
  // Archive only after evidence references and the audit index have been saved.
  for (const asset of children) {
    if (asset.metadata?.consolidatedIntoAssetId === binding.assetId) continue
    const { error } = await client.from('assets').update({ status: 'archived', metadata: { ...asset.metadata, consolidatedIntoAssetId: binding.assetId, consolidation: { at: now, reason: 'agent-device-profile', originalStatus: asset.status, agentId: agent.id } } }).eq('user_id', agent.user_id).eq('id', asset.id)
    if (error) throw new Error('Device consolidation could not archive an audit alias')
  }
  const evidence = await allRows(client, 'scanner_evidence', agent.user_id, (query) => query.eq('agent_id', agent.id))
  const observedComponents = await materializeDeviceObservations(client, agent, binding, evidence)
  return { assetId: binding.assetId, assetName: binding.assetName, consolidatedAssets: ids.length, moved: counts, observedComponents }
}
