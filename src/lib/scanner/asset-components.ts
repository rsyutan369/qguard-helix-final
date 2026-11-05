/**
 * Per-asset cryptographic components — pure and dependency-free.
 *
 * Same discipline as `finding-identity.ts`: no Express, no Supabase, so the rule
 * that decides "what does this asset's CBOM contain?" runs identically in the
 * API (`buildAssetsPayload`), in the browser and in the offline check tools.
 *
 * WHY THIS EXISTS
 * ---------------
 * `crypto_inventory` holds BOTH measured cryptography and scanner findings about
 * the estate ("Rule (App Crypto): Wide Crypto Attack Surface", "Rule (Tls Config):
 * Classical-Only Key Exchange"). The CBOM headline already excluded the findings
 * (`isCryptographicComponent`), but the per-asset register did not, so the Assets
 * page printed "Quantum-Vulnerable Components 8 — matches QR Engine & CBOM" above
 * an asset row reading "20 vulnerable of 25" for the SAME single asset. Measured
 * on three live tenants: Σ per-asset vulnerable 20/38/71 against headlines of
 * 8/14/33 — roughly half of every asset's "components" were findings.
 *
 * The fix is structural rather than a second filter: the per-asset component list
 * is grouped with the CBOM's own key (`cbomComponentKey`) after the CBOM's own
 * predicate, so Σ per-asset components equals the CBOM total by construction.
 * Finding rows are not discarded — they are returned as `posture` observations,
 * which is what they are.
 */

import { isCryptographicComponent } from './finding-identity'

/** A `crypto_inventory` row, loosely typed — writers disagree on optional columns. */
export type InventoryRow = {
  id?: string
  asset_id?: string | null
  name?: string | null
  item_type?: string | null
  algorithm?: string | null
  key_size?: number | string | null
  protocol?: string | null
  exposure_level?: string | null
  is_vulnerable?: boolean | null
  is_quantum_safe?: boolean | null
  discovered_at?: string | null
  created_at?: string | null
  updated_at?: string | null
  metadata?: Record<string, unknown> | null
  [key: string]: unknown
}

/** A grouped row: the representative observation plus how often it was seen. */
export type GroupedInventoryRow = InventoryRow & {
  instances: number
  /** Newest evidence timestamp across every row folded into this group. */
  last_seen_at: string | null
}

export type ComponentPosture = 'vulnerable' | 'pqc-ready' | 'unclassified'

/**
 * The CBOM grouping key. `buildCbomPayload` groups on exactly this string, and
 * the per-asset register must too — two different keys for "one component" is
 * how the same asset reads 12 components on one page and 13 on another.
 */
export function cbomComponentKey(item: Pick<InventoryRow, 'asset_id' | 'item_type' | 'algorithm' | 'name' | 'metadata'>) {
  const evidence = (item.metadata?.evidenceRecord || {}) as Record<string, unknown>
  const subject = evidence.agentId || evidence.agent_id
    ? evidence.certificateFingerprint || evidence.certificate_fingerprint || evidence.filePath || evidence.file_path || item.metadata?.discoveredTarget || evidence.assetName || evidence.asset_name || ''
    : ''
  return `${item.asset_id}:${item.item_type}:${item.algorithm}:${item.name}${subject ? `:${subject}` : ''}`
}

/**
 * Posture of ONE component, as a partition: every component is exactly one of
 * vulnerable / pqc-ready / unclassified, so the three counts always sum to the
 * total. A row flagged BOTH vulnerable and quantum-safe is contradictory; it is
 * read as pqc-ready here and surfaced by `contradictoryFlags` so a reconciliation
 * can state the divergence instead of silently counting the row twice.
 */
export function componentPosture(row: Pick<InventoryRow, 'is_vulnerable' | 'is_quantum_safe'>): ComponentPosture {
  if (row.is_quantum_safe) return 'pqc-ready'
  if (row.is_vulnerable) return 'vulnerable'
  return 'unclassified'
}

export function contradictoryFlags(row: Pick<InventoryRow, 'is_vulnerable' | 'is_quantum_safe'>) {
  return Boolean(row.is_vulnerable && row.is_quantum_safe)
}

/** The observation time of a row — when the scanner saw it, not when it was edited. */
export function evidenceTimestamp(row: Pick<InventoryRow, 'discovered_at' | 'created_at' | 'updated_at' | 'metadata'>): number {
  const metadata = (row.metadata || {}) as Record<string, unknown>
  const candidates = [row.discovered_at, row.created_at, metadata.detectedAt, metadata.timestamp, row.updated_at]
  for (const candidate of candidates) {
    const ms = Date.parse(String(candidate || ''))
    if (Number.isFinite(ms)) return ms
  }
  return 0
}

function groupRows(rows: InventoryRow[]): GroupedInventoryRow[] {
  const grouped = new Map<string, GroupedInventoryRow>()
  for (const row of rows) {
    const key = cbomComponentKey(row)
    const seen = evidenceTimestamp(row)
    const existing = grouped.get(key)
    if (existing) {
      // Representative = first row seen, exactly as `buildCbomPayload` keeps it
      // (rows arrive newest-first), so the evidence text a reader sees on the
      // Assets page is the text the CBOM Explorer shows for the same component.
      existing.instances += 1
      const current = Date.parse(String(existing.last_seen_at || '')) || 0
      if (seen > current) existing.last_seen_at = new Date(seen).toISOString()
      continue
    }
    grouped.set(key, {
      ...row,
      metadata: { ...(row.metadata || {}) },
      instances: 1,
      last_seen_at: seen ? new Date(seen).toISOString() : null,
    })
  }
  return Array.from(grouped.values())
}

const SEVERITY_WEIGHT: Record<string, number> = { critical: 5, high: 4, moderate: 3, medium: 3, low: 2, safe: 0 }

function severityWeight(value: unknown) {
  const text = String(value || '').toLowerCase()
  for (const [token, weight] of Object.entries(SEVERITY_WEIGHT)) if (text.includes(token)) return weight
  return 1
}

/** Vulnerable first, then by stored severity, then newest — the reading order. */
function byUrgency(a: GroupedInventoryRow, b: GroupedInventoryRow) {
  const postureRank = (row: GroupedInventoryRow) => ({ vulnerable: 2, unclassified: 1, 'pqc-ready': 0 })[componentPosture(row)]
  const delta = postureRank(b) - postureRank(a)
  if (delta) return delta
  const severity = severityWeight(b.exposure_level) - severityWeight(a.exposure_level)
  if (severity) return severity
  return (Date.parse(String(b.last_seen_at || '')) || 0) - (Date.parse(String(a.last_seen_at || '')) || 0)
}

export type AssetInventoryPartition = {
  /** Cryptographic components, grouped exactly as the CBOM groups them. */
  components: GroupedInventoryRow[]
  /** Scanner findings stored in `crypto_inventory` — posture, not cryptography. */
  posture: GroupedInventoryRow[]
  counts: {
    components: number
    vulnerable: number
    pqcReady: number
    unclassified: number
    posture: number
    contradictory: number
  }
  /** Newest evidence timestamp across BOTH lists (ms, 0 when none). */
  latestEvidenceMs: number
}

/**
 * Split one asset's `crypto_inventory` rows into cryptographic components and
 * posture observations, each grouped with the CBOM key.
 *
 * `classify` is the canonical algorithm-family classifier (`algorithmFamily`),
 * injected so this module stays free of the governance import graph — the same
 * contract `isCryptographicComponent` already has.
 */
export function partitionAssetInventory(rows: InventoryRow[], classify: (raw: string) => string): AssetInventoryPartition {
  const componentRows: InventoryRow[] = []
  const postureRows: InventoryRow[] = []
  let latestEvidenceMs = 0
  for (const row of rows) {
    latestEvidenceMs = Math.max(latestEvidenceMs, evidenceTimestamp(row))
    if (isCryptographicComponent(row, classify)) componentRows.push(row)
    else postureRows.push(row)
  }
  const components = groupRows(componentRows).sort(byUrgency)
  const posture = groupRows(postureRows).sort(byUrgency)
  const counts = {
    components: components.length,
    vulnerable: components.filter((row) => componentPosture(row) === 'vulnerable').length,
    pqcReady: components.filter((row) => componentPosture(row) === 'pqc-ready').length,
    unclassified: components.filter((row) => componentPosture(row) === 'unclassified').length,
    posture: posture.length,
    contradictory: components.filter(contradictoryFlags).length,
  }
  return { components, posture, counts, latestEvidenceMs }
}
