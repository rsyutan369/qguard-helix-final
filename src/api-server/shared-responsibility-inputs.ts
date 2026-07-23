import type { OwnershipFindingInput } from '@/lib/shared-responsibility'

/**
 * Shared ownership-input adapter.
 *
 * The single place that turns the canonical scanner-intelligence findings (+ a
 * snapshot fallback) into normalized `OwnershipFindingInput[]`. BOTH the
 * `/api/v1/migration-intelligence` router and `buildSnapshot`'s embedded
 * shared-responsibility block use this adapter, so the ownership classification
 * they produce is IDENTICAL — the Report Center, Executive strip and the
 * flagship Migration Intelligence dashboard can never drift apart.
 */

const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
const recordOf = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}

export interface AssetContext {
  type?: string
  environment?: string
  provider?: string
  host?: string
}

/** Index scanner-intelligence assets by name + id for finding enrichment. */
export function buildAssetIndex(intel: unknown): Map<string, AssetContext> {
  const index = new Map<string, AssetContext>()
  const assets = (recordOf(recordOf(intel).assets).assets as unknown[]) || []
  for (const raw of assets) {
    const a = recordOf(raw)
    const meta = recordOf(a.metadata)
    const ctx: AssetContext = {
      type: str(a.type) || undefined,
      environment: str(meta.environment) || str(meta.env) || str(a.region) || str(meta.region) || undefined,
      provider: str(meta.provider) || str(meta.cloud_provider) || str(meta.cloud) || undefined,
      host: str(a.url) || str(a.domain) || str(meta.authorized_target) || str(a.name) || undefined,
    }
    const name = str(a.name).toLowerCase()
    if (name) index.set(name, ctx)
    const id = str(a.id).toLowerCase()
    if (id) index.set(id, ctx)
  }
  return index
}

/** Strip a trailing :port so a finding location matches an asset name. */
export function assetKeyFromLocation(location: string): string {
  return location.toLowerCase().trim().replace(/:\d+$/, '')
}

const HNDL_RE = /hndl|harvest|long[-\s]?lived|store now/i

/**
 * Adapt scanner-intelligence findings (with a snapshot critical-findings
 * fallback) into ownership inputs. `intel` is the raw buildScannerIntelligence
 * result; `snapshotLike` need only carry `criticalFindings` for the fallback.
 */
export function buildOwnershipInputs(intel: unknown, snapshotLike: unknown, limit = 1500): OwnershipFindingInput[] {
  const assetIndex = buildAssetIndex(intel)
  const inputs: OwnershipFindingInput[] = []
  const seen = new Set<string>()
  const push = (input: OwnershipFindingInput) => {
    const key = input.id || `${input.algorithm}|${input.location}|${input.severity}`
    if (seen.has(key)) return
    seen.add(key)
    inputs.push(input)
  }

  const findings = (recordOf(intel).findings as unknown[]) || []
  for (const raw of findings) {
    const f = recordOf(raw)
    const location = str(f.location)
    const asset = assetIndex.get(assetKeyFromLocation(location)) || assetIndex.get(location.toLowerCase()) || {}
    const description = str(f.description)
    push({
      id: str(f.id) || `finding-${inputs.length}`,
      title: `${str(f.algorithm) || str(f.category) || 'Cryptographic finding'}${location ? ` — ${location}` : ''}`,
      description,
      algorithm: str(f.algorithm) || undefined,
      category: str(f.category) || undefined,
      location: location || undefined,
      assetName: location || undefined,
      assetType: asset.type,
      environment: asset.environment,
      provider: asset.provider,
      host: asset.host || location || undefined,
      severity: str(f.threatLevel) || 'medium',
      isHNDL: HNDL_RE.test(`${description} ${str(f.category)}`),
      detectionMethod: str(f.detectionMethod) || undefined,
      evidenceSource: str(f.source) || undefined,
      metadata: { evidence: str(f.evidence) || undefined },
      observedAt: str(f.detectedAt) || str(f.timestamp) || null,
    })
    if (inputs.length >= limit) break
  }

  // Fallback / supplement — the snapshot's collapsed critical findings carry
  // environment + assetType even when scanner intelligence is unavailable.
  if (inputs.length === 0) {
    const critical = (recordOf(snapshotLike).criticalFindings as unknown[]) || []
    for (const raw of critical) {
      const f = recordOf(raw)
      push({
        id: str(f.id) || `snap-${inputs.length}`,
        title: str(f.title) || undefined,
        algorithm: str(f.algorithm) || undefined,
        category: str(f.assetType) || undefined,
        location: str(f.asset) || undefined,
        assetName: str(f.asset) || undefined,
        assetType: str(f.assetType) || undefined,
        environment: str(f.environment) || undefined,
        severity: str(f.severity) || 'high',
        detectionMethod: 'Quantum Readiness snapshot',
        evidenceSource: 'Quantum Readiness Assessment Engine',
        observedAt: str(f.detectedAt) || null,
      })
    }
  }

  return inputs
}
