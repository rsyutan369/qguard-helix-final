import type { OwnershipFindingInput } from '@/lib/shared-responsibility'
import { normaliseAsset } from '@/lib/estate/model'

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
  name?: string
  owner?: string | null
  type?: string
  environment?: string
  provider?: string
  host?: string
}

/** Index authoritative scanner asset IDs for finding enrichment. */
export function buildAssetIndex(intel: unknown): Map<string, AssetContext> {
  const index = new Map<string, AssetContext>()
  const assets = (recordOf(recordOf(intel).assets).assets as unknown[]) || []
  for (const raw of assets) {
    const a = recordOf(raw)
    const meta = recordOf(a.metadata)
    const asset = normaliseAsset({ ...a, service_owner: a.serviceOwner })
    const ctx: AssetContext = {
      name: asset.name,
      owner: asset.owner,
      type: asset.type.replace(/_/g, '-') || undefined,
      environment: asset.environmentRaw || undefined,
      provider: str(meta.provider) || str(meta.cloud_provider) || str(meta.cloud) || undefined,
      host: str(a.url) || str(a.domain) || str(meta.authorized_target) || str(a.name) || undefined,
    }
    const id = str(a.id)
    if (id) index.set(id, ctx)
  }
  return index
}

const HNDL_RE = /hndl|harvest|long[-\s]?lived|store now/i

/**
 * Adapt scanner-intelligence findings (with a snapshot critical-findings
 * fallback) into ownership inputs. `intel` is the raw buildScannerIntelligence
 * result; `snapshotLike` need only carry `criticalFindings` for the fallback.
 */
export const OWNERSHIP_INPUT_LIMIT = 1500

export function buildOwnershipInputs(intel: unknown, snapshotLike: unknown, limit = OWNERSHIP_INPUT_LIMIT): OwnershipFindingInput[] {
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
    const ids = Array.isArray(f.assetIds) ? [...new Set(f.assetIds.filter((id): id is string => typeof id === 'string' && Boolean(id)))] : []
    const assetId = ids.length === 1 ? ids[0] : ids.length === 0 ? str(f.assetId) : ''
    const asset = assetIndex.get(assetId)
    const description = str(f.description)
    push({
      id: str(f.id) || `finding-${inputs.length}`,
      title: `${str(f.algorithm) || str(f.category) || 'Cryptographic finding'}${location ? ` — ${location}` : ''}`,
      description,
      algorithm: str(f.algorithm) || undefined,
      category: str(f.category) || undefined,
      location: location || undefined,
      assetId: asset ? assetId : undefined,
      assetName: asset?.name || location || undefined,
      assetOwner: asset?.owner || undefined,
      assetType: asset?.type,
      environment: asset?.environment,
      provider: asset?.provider,
      host: asset?.host || str(f.scanTarget) || location || undefined,
      protocol: str(recordOf(f.raw).protocol) || undefined,
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
