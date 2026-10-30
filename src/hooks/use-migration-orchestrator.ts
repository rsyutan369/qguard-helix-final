import { useLiveResource, type LiveResource } from '@/hooks/use-live-resource';
import type { OrchestrationMetrics, OrchestrationSnapshot } from '@/types/migration-orchestrator';

/**
 * useMigrationOrchestrator — live PQC orchestration state for the Migration
 * Timeline and PQC Orchestration pages.
 *
 * A thin wrapper over `useLiveResource`: the stream's first frame is the
 * initial load, REST is the fallback, unchanged frames advance
 * `lastVerifiedAt` without re-rendering, and the bearer token travels in the
 * Authorization header. The previous hook downloaded the snapshot twice on
 * mount, applied every frame, and kept no error message.
 */

const EMPTY_METRICS: OrchestrationMetrics = {
  total: 0,
  simulationsExcluded: 0,
  phases: {
    'awaiting-approval': 0, rejected: 0, blocked: 0, ready: 0, executing: 0, validating: 0,
    paused: 0, completed: 0, failed: 0, rollback: 0, cancelled: 0,
  },
  completed: 0,
  verified: 0,
  completedUnverified: 0,
  completedValidationFailed: 0,
  completionPct: null,
  verifiedPct: null,
  assets: { total: 0, verified: 0, inFlight: 0, needsAttention: 0 },
  executors: { fleetReadable: false, enrolled: null, migrationCapable: null, remediationCapable: null, online: null },
  staleExecutions: 0,
  retryEligible: 0,
  awaitingApproval: 0,
  blocked: 0,
  avgDurationSeconds: null,
  completedLast24h: 0,
  connectors: { healthy: 0, total: 0 },
};

export const EMPTY_ORCHESTRATOR: OrchestrationSnapshot = {
  generatedAt: '',
  hasData: false,
  metrics: EMPTY_METRICS,
  jobs: [],
  jobsListed: 0,
  jobsTruncated: false,
  plans: [],
  throughput: [],
  events: [],
  agents: [],
  sources: { jobs: 'ok', plans: 'ok', agents: 'ok', validations: 'ok', events: 'ok', connectors: 'ok', assets: 'ok' },
  scopeNote: '',
};

const REALTIME_TABLES = ['migration_jobs', 'migration_events', 'migration_validation_logs', 'migration_plans'] as const;

export function useMigrationOrchestrator(): LiveResource<OrchestrationSnapshot> {
  return useLiveResource<OrchestrationSnapshot>({
    url: '/api/v1/migration-orchestrator',
    streamUrl: '/api/v1/migration-orchestrator/stream',
    event: 'orchestrator',
    empty: EMPTY_ORCHESTRATOR,
    normalize: (raw) => ({
      ...EMPTY_ORCHESTRATOR,
      ...(raw as Partial<OrchestrationSnapshot>),
      metrics: { ...EMPTY_METRICS, ...((raw as Partial<OrchestrationSnapshot>).metrics || {}) },
    }),
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'orchestrator',
  });
}
