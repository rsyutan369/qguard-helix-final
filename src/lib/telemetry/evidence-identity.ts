import { recordOf, str, type AssetMigrationRecord, type Row } from '@/lib/migration/asset-intelligence'

export function normalizeEvidenceLabel(value: unknown): string {
  return str(value).trim().toLowerCase()
}

/** Match explicit IDs first. A missing or ambiguous alias cannot claim an asset. */
export function buildEvidenceAssetResolver(assets: AssetMigrationRecord[]) {
  const byId = new Map(assets.map((asset) => [asset.id, asset]))
  const byAlias = new Map<string, AssetMigrationRecord | null>()
  for (const asset of assets) {
    for (const alias of [asset.name, asset.hostname].map(normalizeEvidenceLabel).filter(Boolean)) {
      const previous = byAlias.get(alias)
      byAlias.set(alias, previous === undefined || previous?.id === asset.id ? asset : null)
    }
  }
  return (row: Row): AssetMigrationRecord | null => {
    const id = str(row.asset_id)
    if (id) return byId.get(id) ?? null
    const matches = new Map<string, AssetMigrationRecord>()
    for (const alias of [row.asset_name, row.host, row.target].map(normalizeEvidenceLabel).filter(Boolean)) {
      const asset = byAlias.get(alias)
      if (asset) matches.set(asset.id, asset)
    }
    return matches.size === 1 ? matches.values().next().value ?? null : null
  }
}

/** Scan evidence converted to a runtime row retains its original evidence ID. */
export function isDerivedScanObservation(row: Row): boolean {
  const metadata = recordOf(row.metadata)
  return metadata.observationKind === 'scan-evidence' || Boolean(str(metadata.evidenceId || metadata.evidenceType))
}

/** Keep historical runtime observations with an explicit operational event type. */
export function isRuntimeOperationObservation(row: Row): boolean {
  if (isDerivedScanObservation(row)) return false
  const metadata = recordOf(row.metadata)
  if (metadata.evidenceClass === 'library-presence' || metadata.evidenceClass === 'certificate') return false
  const event = normalizeEvidenceLabel(row.event_type).replace(/[_ ]/g, '-')
  if (/(discovery|inventory|manifest|config|certificate-file|library|probe|metadata)/.test(event)) return false
  return metadata.observationKind === 'runtime-observation'
    || /(^|-)(handshake|sign|verify|encrypt|decrypt|key-exchange|encapsulat(?:e|ion)|decapsulat(?:e|ion)|crypto-call)(-|$)/.test(event)
}

/** Formatting aliases are equivalent. Algorithm families and parameter sets differ. */
export function primitiveIdentity(value: unknown): string {
  return normalizeEvidenceLabel(value).replace(/[\s_-]+/g, '')
}
