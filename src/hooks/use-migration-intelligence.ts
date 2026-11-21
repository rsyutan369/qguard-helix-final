'use client';

import { useLiveResource, type LiveTransport } from '@/hooks/use-live-resource';
import type { SharedResponsibilityIntelligence } from '@/lib/shared-responsibility';
import type { MigrationAssetScope, MigrationIntelligenceCoverage } from '@/lib/migration/intelligence-scope';

export type LoadState = 'loading' | 'success' | 'error';

export interface MigrationIntelligence extends SharedResponsibilityIntelligence {
  baseline?: { quantumReadiness: number; quantumReadinessLevel: string } | null;
  assetScope: MigrationAssetScope | null;
  coverage: MigrationIntelligenceCoverage | null;
}

const emptyBucket = () => ({ critical: 0, high: 0, medium: 0, low: 0 });
const emptyReadiness = (domain: 'overall' | 'customer' | 'provider' | 'ecosystem') => ({
  domain,
  score: 0,
  level: 'Not Started',
  total: 0,
  resolved: 0,
  actionable: 0,
  blocked: 0,
});

export const EMPTY_MIGRATION_INTELLIGENCE: MigrationIntelligence = {
  generatedAt: '',
  hasData: false,
  totals: { findings: 0, customer: 0, provider: 0, ecosystem: 0, actionable: 0, waiting: 0, blocked: 0, resolved: 0 },
  readiness: {
    overall: emptyReadiness('overall'),
    customer: emptyReadiness('customer'),
    provider: emptyReadiness('provider'),
    ecosystem: emptyReadiness('ecosystem'),
  },
  domainDistribution: { customer: 0, provider: 0, ecosystem: 0 },
  severityByDomain: { customer: emptyBucket(), provider: emptyBucket(), ecosystem: emptyBucket() },
  matrix: [],
  findings: [],
  blockers: [],
  waves: [],
  widgets: {
    customerFindings: 0,
    providerFindings: 0,
    vendorFindings: 0,
    browserDependencies: 0,
    cloudDependencies: 0,
    migrationBlockers: 0,
    actionableFindings: 0,
    waitingDependencies: 0,
    migrationProgress: 0,
    providerReadiness: 0,
  },
  providerBreakdown: [],
  edgeOrigin: { providerFrontedAssets: 0, edgeManaged: 0, originCustomerControlled: 0, summary: '' },
  attribution: { attributed: 0, unattributed: 0, avgConfidence: 0 },
  baseline: null,
  assetScope: null,
  coverage: null,
};

const REALTIME_TABLES = [
  'assets', 'asset_relationships', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_inventory', 'crypto_exposures',
  'certificates', 'generated_keys', 'runtime_crypto_events', 'connector_accounts', 'migration_jobs',
] as const;

const normalize = (raw: Record<string, unknown>): MigrationIntelligence =>
  ({ ...EMPTY_MIGRATION_INTELLIGENCE, ...raw }) as MigrationIntelligence;

/** The route answers with the bare model; a body without `totals` is not one. */
const unwrap = (body: unknown) =>
  body && typeof body === 'object' && 'totals' in body ? body : null;

export interface MigrationIntelligenceResource {
  data: MigrationIntelligence;
  state: LoadState;
  error: string | null;
  /** True while the server stream is open and has answered. */
  sseConnected: boolean;
  transport: LiveTransport;
  /** Last time the server confirmed the model on screen is current. */
  lastVerifiedAt: string | null;
  refresh: (options?: unknown) => Promise<void>;
}

/**
 * useMigrationIntelligence — the Shared Responsibility Quantum Migration
 * Intelligence model from /api/v1/migration-intelligence, kept live.
 *
 * Runs on the shared live-resource client, so it behaves like every other live
 * dashboard: the stream's first frame is the initial load (the model is no
 * longer downloaded twice on mount), unchanged re-checks cost a few bytes and
 * advance `lastVerifiedAt`, a failed build keeps the last good model on screen,
 * reconnects back off 2 s → 30 s, and the bearer token never enters a URL.
 * Every value is tenant-scoped real data classified into customer / provider /
 * ecosystem ownership domains.
 */
export function useMigrationIntelligence(assetId: string | null = null): MigrationIntelligenceResource {
  const query = assetId ? `?asset=${encodeURIComponent(assetId)}` : '';
  return useLiveResource<MigrationIntelligence>({
    url: '/api/v1/migration-intelligence' + query,
    streamUrl: '/api/v1/migration-intelligence/stream' + query,
    event: 'migration-intelligence',
    empty: EMPTY_MIGRATION_INTELLIGENCE,
    normalize,
    unwrap,
    validate: (raw) => Boolean(raw.totals && raw.readiness && raw.widgets && Array.isArray(raw.matrix)
      && Array.isArray(raw.findings) && Array.isArray(raw.blockers) && Array.isArray(raw.waves)
      && (assetId ? (raw.assetScope as MigrationAssetScope | null)?.id === assetId : !raw.assetScope)),
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'migration-intel',
  });
}
