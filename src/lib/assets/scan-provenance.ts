/** Source labels describe recorded discovery context, never a guess from a host name. */
type RecordValue = Record<string, unknown>
const rec = (value: unknown): RecordValue => value && typeof value === 'object' ? value as RecordValue : {}
const text = (value: unknown) => typeof value === 'string' ? value.trim() : ''

export const SCAN_SOURCE_LABELS = {
  'windows-device': 'Windows device', 'linux-device': 'Linux device', 'macos-device': 'macOS device',
  'virtual-machine': 'Virtual machine', cloud: 'Cloud resource', kubernetes: 'Kubernetes',
  'web-application': 'Web application / endpoint', 'github-repository': 'GitHub repository',
  repository: 'Source repository', device: 'Device / host', unknown: 'Source not recorded',
} as const
export type ScanSourceKind = keyof typeof SCAN_SOURCE_LABELS
export interface AssetScanSource {
  kind: ScanSourceKind
  label: string
  sourceType: string
  agentId: string | null
  agentName: string | null
  collectorHost: string | null
  collectorPlatform: string | null
  systemModel?: string | null
  connectorId: string | null
  observedAt: string | null
  scanSessionId?: string | null
}

export function scanSourceFor(evidence: RecordValue, agent?: RecordValue, connector?: RecordValue): AssetScanSource {
  const raw = rec(evidence.rawEvidence || evidence.metadata)
  const hostIdentity = rec(rec(rec(agent?.metadata).lastTelemetry).host)
  const type = text(evidence.assetType || evidence.type).toLowerCase()
  const platform = text(agent?.platform || raw.platform || raw.os).toLowerCase()
  const sourceType = text(evidence.sourceType || evidence.source_type)
  const target = text(evidence.target || raw.repositoryUrl || raw.repository_url || evidence.url)
  const observedHost = text(evidence.host).toLowerCase()
  const collectorHost = text(agent?.hostname).toLowerCase()
  const remoteHost = Boolean(observedHost && collectorHost && observedHost !== collectorHost && !['localhost', '127.0.0.1', '::1'].includes(observedHost))
  let hostname = ''
  try { hostname = new URL(target).hostname.toLowerCase() } catch { /* Local paths are not URLs. */ }
  let kind: ScanSourceKind = 'unknown'
  if (hostname === 'github.com' && /repo|repository|source|git/.test(`${type} ${text(evidence.evidenceType)}`)) kind = 'github-repository'
  else if (/kubernetes|k8s|kube-cluster|kube-service/.test(type) || raw.kubernetesNamespace || raw.kubernetesResource || raw.clusterResource) kind = 'kubernetes'
  else if (/virtual.machine|^vm$/.test(type) || rec(raw.virtualization).detected === true) kind = 'virtual-machine'
  else if (/cloud|aws|azure|gcp|alibaba/.test(`${sourceType} ${type} ${text(connector?.provider)}`)) kind = 'cloud'
  else if (/repository|^repo$|source-code/.test(type)) kind = 'repository'
  else if (/website|web.app|web.service|tls.endpoint|https.endpoint|^api$|^endpoint$/.test(type)) kind = 'web-application'
  else if (agent?.id || /host|server|device/.test(type)) {
    kind = remoteHost ? 'device' : hostIdentity.kubernetes === true ? 'kubernetes' : rec(hostIdentity.virtualization).detected === true ? 'virtual-machine' : /win32|windows/.test(platform) ? 'windows-device' : /linux/.test(platform) ? 'linux-device' : /darwin|macos/.test(platform) ? 'macos-device' : 'device'
  } else if (/web|url|public.scan/.test(sourceType)) kind = 'web-application'
  return {
    kind, label: SCAN_SOURCE_LABELS[kind], sourceType: sourceType || 'scanner',
    agentId: text(agent?.id || evidence.agentId || evidence.agent_id) || null,
    agentName: text(agent?.name) || null,
    collectorHost: text(agent?.hostname) || null,
    collectorPlatform: text(agent?.platform) || null,
    systemModel: [text(hostIdentity.manufacturer), text(hostIdentity.model)].filter(Boolean).join(' · ') || null,
    connectorId: text(connector?.id || evidence.connectorAccountId || evidence.connector_account_id) || null,
    observedAt: text(evidence.observedAt || evidence.observed_at) || null,
  }
}

export function mergeScanSources(previous: unknown, incoming: AssetScanSource[]): AssetScanSource[] {
  const rows = Array.isArray(previous) ? previous as AssetScanSource[] : []
  const merged = new Map<string, AssetScanSource>()
  for (const row of [...rows, ...incoming]) {
    if (!row || !Object.hasOwn(SCAN_SOURCE_LABELS, row.kind)) continue
    const key = `${row.kind}:${row.agentId || ''}:${row.connectorId || ''}:${row.sourceType}`
    const prior = merged.get(key)
    if (!prior || (Date.parse(row.observedAt || '') || 0) >= (Date.parse(prior.observedAt || '') || 0)) merged.set(key, { ...row, label: SCAN_SOURCE_LABELS[row.kind] })
  }
  return [...merged.values()]
}

/** Legacy assets derive labels from their persisted evidence, without rewriting history. */
export function assetScanSources(asset: RecordValue): AssetScanSource[] {
  const metadata = rec(asset.metadata)
  const incoming: AssetScanSource[] = []
  for (const row of Array.isArray(asset.cryptoInventory) ? asset.cryptoInventory : []) {
    const evidence = rec(rec(rec(row).metadata).evidenceRecord)
    const recorded = rec(rec(evidence.rawEvidence).scanSource)
    if (Object.hasOwn(SCAN_SOURCE_LABELS, text(recorded.kind))) incoming.push(recorded as unknown as AssetScanSource)
    else if (evidence.agentId || evidence.sourceType) incoming.push(scanSourceFor(evidence))
  }
  let sources = mergeScanSources(metadata.scanSources, incoming)
  if (!sources.length) {
    const fallback = scanSourceFor({ type: asset.type, target: asset.url || asset.domain || metadata.target, sourceType: metadata.source, rawEvidence: metadata })
    sources = [fallback]
  }
  return sources
}
