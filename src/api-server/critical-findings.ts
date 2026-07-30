/**
 * Critical / high evidence consolidation.
 *
 * The scanner emits one finding per detected instance and records the same host
 * through several detection channels, so one cryptographic exposure arrives as
 * `qguardhelix.com`, `qguardhelix.com:443` and `Cipher Suite -
 * https://qguardhelix.com`. Keying the collapse on that raw location made the
 * Quantum Readiness evidence table print rows that were indistinguishable once
 * the asset column was truncated.
 *
 * This module is the single collapse used by `buildSnapshot`, so every consumer
 * of `snapshot.criticalFindings` (Quantum Readiness pages, HNDL, exposure graph,
 * certification and the reporting engine) sees the same consolidated evidence.
 * Pure and dependency-free so it can be verified offline
 * (`tools/report-dedup-check.ts`).
 */

import { assetDisplayLabel, canonicalAssetLabel } from '@/lib/shared-responsibility'

export interface RawCriticalFinding {
  id: string
  title: string
  asset: string
  assetType: string
  environment: string
  severity: string
  algorithm: string
  detectedAt: string | null
  instances?: number
}

export interface CollapsedCriticalFinding extends RawCriticalFinding {
  /** Raw scanner instances consolidated into this record (>= 1). */
  instances: number
  /** Every raw detection location merged into this record (bounded). */
  locations: string[]
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function severityRank(severity: string): number {
  return SEVERITY_RANK[String(severity ?? '').toLowerCase()] ?? 0;
}

/**
 * Collapse identical evidence into one record per
 * `algorithm + canonical asset + environment + severity`.
 *
 * The canonical asset reduces every detection-channel spelling of a host to the
 * bare host, so the same exposure on the same asset is one record — while
 * genuinely different assets, and evidence channels that carry no host at all
 * (e.g. `Detection Rule TLS-006`), stay separate. Each record keeps its true
 * instance count, every merged location, and the EARLIEST detection timestamp so
 * the evidence remains traceable and the trend stays honest.
 */
export function collapseCriticalFindings(raw: RawCriticalFinding[]): CollapsedCriticalFinding[] {
  const byKey = new Map<string, CollapsedCriticalFinding>();

  for (const finding of raw) {
    const asset = finding.asset || 'Unknown asset';
    const assetKey = canonicalAssetLabel(asset) || asset.toLowerCase();
    const identity = (finding.algorithm || finding.title || 'unknown').toLowerCase();
    const key = `${identity}|${assetKey}|${String(finding.environment ?? '').toLowerCase()}|${String(finding.severity ?? '').toLowerCase()}`;
    const instances = Math.max(1, Math.round(Number(finding.instances)) || 1);
    const existing = byKey.get(key);

    if (!existing) {
      byKey.set(key, {
        ...finding,
        // Display the canonical host rather than whichever detection channel
        // happened to be seen first; non-host evidence labels stay verbatim.
        asset: assetDisplayLabel(asset) || asset,
        instances,
        locations: [asset],
      });
      continue;
    }

    existing.instances += instances;
    if (existing.locations.length < 12 && !existing.locations.includes(asset)) existing.locations.push(asset);
    if (finding.detectedAt && (!existing.detectedAt || finding.detectedAt < existing.detectedAt)) {
      existing.detectedAt = finding.detectedAt;
    }
    // Prefer a concrete asset type / environment over an unknown placeholder.
    if (existing.assetType === 'asset' && finding.assetType && finding.assetType !== 'asset') {
      existing.assetType = finding.assetType;
    }
  }

  return Array.from(byKey.values()).sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      b.instances - a.instances ||
      a.asset.localeCompare(b.asset) ||
      a.algorithm.localeCompare(b.algorithm),
  );
}
