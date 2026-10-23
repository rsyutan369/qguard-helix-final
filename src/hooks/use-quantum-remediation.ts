import { useLiveResource, type LiveLoadState } from './use-live-resource';
import type { RemediationPlan } from '@/types/quantum-remediation';

/**
 * useQuantumRemediation — live Intelligent Quantum Remediation Engine™ state.
 *
 * The tenant-scoped Q-REMEDY remediation plan from /api/v1/quantum-remediation,
 * live over its fingerprinted stream (see use-live-resource.ts) plus Supabase
 * realtime on the evidence tables the plan derives from — so the Certification Readiness Score updates
 * automatically as vulnerabilities are resolved and assets are rescanned.
 */

export type LoadState = LiveLoadState;

export const EMPTY_PLAN: RemediationPlan = {
  generatedAt: '',
  hasData: false,
  certificationReadinessPct: 0,
  certificationEligible: false,
  trustScore: 0,
  levelLabel: 'Not Eligible',
  requiredMet: 0,
  requiredTotal: 10,
  quantumReadiness: 0,
  quantumRisk: 0,
  hndlRisk: 0,
  pqcAdoption: 0,
  estimatedCertificationDate: null,
  estimatedCompletionWeeks: 0,
  parallelWorkstreams: 1,
  criteria: [],
  requirements: [],
  actions: [],
  ladder: [],
  queues: { critical: 0, high: 0, medium: 0, low: 0 },
  quickWins: [],
  criticalBlockers: [],
  vendorActions: [],
  replacementsRequired: [],
  advisor: [],
  progress: {
    totalActions: 0,
    openActions: 0,
    inProgressActions: 0,
    resolvedActions: 0,
    completionPct: 0,
    migrationJobsCompleted: 0,
    migrationJobsRunning: 0,
    recentlyFixed: [],
    upcomingTasks: [],
  },
  assetsByRisk: [],
  remainingVulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
  readinessTrend: [],
  methodology: {
    name: '',
    version: '',
    summary: '',
    scoreFormula: '',
    priorityFactors: [],
    simulation: '',
    honesty: '',
  },
};

// Evidence tables whose mutations change the plan (scan findings, CBOM,
// certificates, migration execution, asset inventory).
const REALTIME_TABLES = ['pqc_scan_results', 'crypto_inventory', 'certificates', 'migration_jobs', 'assets'] as const;

export function useQuantumRemediation() {
  const live = useLiveResource<RemediationPlan>({
    url: '/api/v1/quantum-remediation',
    streamUrl: '/api/v1/quantum-remediation/stream',
    event: 'remediation-update',
    empty: EMPTY_PLAN,
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'qrem',
  });
  return { plan: live.data, state: live.state, error: live.error, sseConnected: live.sseConnected, lastVerifiedAt: live.lastVerifiedAt, refresh: live.refresh };
}
