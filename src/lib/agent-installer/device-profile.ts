import { isCryptographicComponent } from '@/lib/scanner/finding-identity'
import { algorithmFamily } from '@/lib/governance/subjects'

type Row = Record<string, any>
export const record = (value: unknown): Row => value && typeof value === 'object' ? value as Row : {}

/** Source attribution is identity; a similar asset name alone is never enough. */
export function exclusivelyObservedByAgent(asset: Row, agent: Row): boolean {
  if (asset.user_id && asset.user_id !== agent.user_id) return false
  const metadata = record(asset.metadata)
  if (metadata.bindingTarget && metadata.createdVia !== 'agent-device-profile') return false
  const sources = Array.isArray(metadata.scanSources) ? metadata.scanSources : []
  const ids = new Set(sources.map((source: Row) => source.agentId).filter(Boolean))
  if (ids.size) return ids.size === 1 && ids.has(agent.id) && sources.every((source: Row) => source.agentId === agent.id)
  return metadata.boundAgentId === agent.id || metadata.agentId === agent.id
}

export function profileName(agent: Row): string {
  const hostname = String(agent.hostname || '').trim()
  return hostname && hostname !== 'pending-customer-install' ? hostname : String(agent.name || 'Agent device')
}

/** Only a terminal alias pointing at a present, same-tenant profile may be folded. */
export function deviceAliasMap(assets: Row[]): Map<string, string> {
  const byId = new Map(assets.map((asset) => [asset.id, asset]))
  const aliases = new Map<string, string>()
  for (const asset of assets) {
    const target = byId.get(record(asset.metadata).consolidatedIntoAssetId)
    if (target && asset.user_id && target.id !== asset.id && target.user_id === asset.user_id && record(target.metadata).deviceProfile) aliases.set(asset.id, target.id)
  }
  return aliases
}

/** Retained aliases remain available for audits; operational inventory counts profiles. */
export function foldDeviceAssetGraph<T extends { assets: Row[]; inventory: Row[]; exposures: Row[]; results: Row[]; vulnerabilities: Row[] }>(graph: T): T {
  const aliases = deviceAliasMap(graph.assets)
  if (!aliases.size) return graph
  const remap = (rows: Row[]) => rows.map((row) => aliases.has(row.asset_id) ? { ...row, asset_id: aliases.get(row.asset_id) } : row)
  return { ...graph, assets: graph.assets.filter((asset) => !aliases.has(asset.id)), inventory: remap(graph.inventory), exposures: remap(graph.exposures), results: remap(graph.results), vulnerabilities: remap(graph.vulnerabilities) }
}

/** The observed subject distinguishes certificates/files after their host is consolidated. */
export function observationSubject(evidence: Row): string {
  const raw = record(evidence.rawEvidence || evidence.raw_evidence)
  return String(evidence.certificateFingerprint || evidence.certificate_fingerprint || raw.certificateFingerprint || evidence.filePath || evidence.file_path || evidence.assetName || evidence.asset_name || evidence.packageName || evidence.package_name || evidence.host || '')
}

export function observationDescriptor(evidence: Row) {
  const raw = record(evidence.rawEvidence || evidence.raw_evidence)
  const evidenceType = String(evidence.evidenceType || evidence.evidence_type || '')
  const assetType = String(evidence.assetType || evidence.asset_type || '')
  const eventType = String(raw.eventType || raw.originalEventType || '')
  const algorithm = String(evidence.observedAlgorithm || evidence.observed_algorithm || 'Unknown')
  const subject = String(evidence.assetName || evidence.asset_name || evidence.filePath || evidence.file_path || evidence.packageName || evidence.package_name || 'Observed cryptography')
  if (/certificate/.test(`${evidenceType} ${assetType} ${eventType}`) || evidence.certificateFingerprint || evidence.certificate_fingerprint) return { itemType: 'certificate', name: `Certificate: ${subject}`, algorithm }
  if (evidenceType === 'key-file') return { itemType: 'key', name: `Cryptographic key: ${subject}`, algorithm }
  if ((evidenceType === 'crypto-library' || evidenceType === 'package-manifest') && (evidence.packageName || evidence.package_name || raw.evidenceClass === 'library')) return { itemType: 'library', name: `Crypto library: ${evidence.packageName || evidence.package_name || subject}`, algorithm }
  if (isCryptographicComponent({ algorithm }, algorithmFamily)) return { itemType: /protocol|tls|ssh/.test(evidenceType) ? 'protocol' : 'algorithm', name: `Observed cryptography: ${subject} · ${algorithm}`, algorithm }
  return null
}
