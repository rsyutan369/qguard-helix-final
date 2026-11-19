'use client';

import { useLiveResource } from '@/hooks/use-live-resource';
import type { SharedResponsibilityIntelligence } from '@/lib/shared-responsibility';

/* ------------------------------------------------------------------ */
/* Types — the migration plan contract from /api/v1/migration-planner */
/* ------------------------------------------------------------------ */
export type LoadState = 'loading' | 'success' | 'error';

export interface MigrationStage {
  key: string;
  label: string;
  status: string;
  progressPct: number;
  assetCount: number;
  riskReductionPct: number;
  dependencies: string[];
  durationWeeks: number;
  evidence: string;
}

export interface MigrationWave {
  wave: number;
  name: string;
  assets: string[];
  owner: string;
  durationWeeks: number;
  costUsd: number;
  dependencies: string[];
  riskReductionPct: number;
  status: string;
  priority: string;
}

export interface ReadinessDomain {
  domain: string;
  score: number;
  riskLevel: string;
  owner: string;
  actions: string;
  complexity: string;
}

export interface MigrationStrategy {
  key: string;
  name: string;
  summary: string;
  costUsd: number;
  timelineWeeks: number;
  riskReductionPct: number;
  operationalRisk: string;
  downtimeProbabilityPct: number;
  complianceImpactPct: number;
  successProbabilityPct: number;
  recommended: boolean;
}

export interface WhatIfScenario {
  scenario: string;
  riskReductionPct: number;
  costUsd: number;
  timelineLabel: string;
  complianceIncreasePct: number;
  /** Measured scope this scenario buys — scenarios overlap and must not be summed. */
  coverage?: string;
  componentsCovered?: number;
}

export interface MigrationBlocker {
  id: string;
  title: string;
  severity: string;
  impact: string;
  resolution: string;
  affectedAssets: string[];
}

export interface TimelinePhase {
  phase: string;
  owner: string;
  riskLevel: string;
  durationWeeks: number;
  startDate: string;
  endDate: string;
  completionPct: number;
  dependencies: string[];
}

export interface RiskCategory {
  key: string;
  label: string;
  score: number;
}

export interface MigrationPlan {
  generatedAt: string | null;
  lastScanAt: string | null;
  hasData: boolean;
  hero: {
    readinessScore: number;
    readinessLevel: string;
    assetsRequiringMigration: number;
    vulnerableComponents: number;
    durationWeeks: number;
    durationLabel: string;
    costUsd: number;
    costLabel: string;
    riskReductionPct: number;
    hndlExposure: string;
    hndlScore: number;
    pqcAdoption: number;
    criticalFindingsRemaining: number;
    quantumRisk: number;
    assetsAssessed: number;
  };
  stages: MigrationStage[];
  advisor: {
    recommendation: string;
    reason: string;
    affectedAssets: string[];
    riskReductionPct: number;
    costUsd: number;
    timelineWeeks: number;
    complexity: string;
    successProbabilityPct: number;
    confidencePct: number;
    deepLink: string;
  };
  waves: MigrationWave[];
  dependencyGraph: {
    nodes: Array<{ id: string; label: string; type: string; environment: string; riskScore: number; posture: string; internetFacing: boolean }>;
    edges: Array<{ source: string; target: string; type: string }>;
  };
  dependencyAnalysis: { chains: Array<{ path: string; blastRadius: number; complexity: string }>; failurePoints: string[]; summary: string };
  businessImpact: {
    customerFacingSystems: number;
    missionCriticalSystems: number;
    revenueImpact: string;
    operationalImpact: string;
    complianceImpact: string;
    reputationalImpact: string;
    financialImpact: string;
    thirdPartyDependencies: number;
    hndlExposure: string;
    quantumExposureWindow: string;
  };
  readinessDomains: ReadinessDomain[];
  strategies: MigrationStrategy[];
  whatIf: WhatIfScenario[];
  blockers: MigrationBlocker[];
  heatmap: {
    ready: number;
    needsValidation: number;
    needsUpgrade: number;
    blocked: number;
    unknown: number;
    rows: Array<{ asset: string; type: string; environment: string; riskScore: number; state: string }>;
  };
  timeline: TimelinePhase[];
  compliance: Array<{ framework: string; control: string; status: string; detail: string }>;
  costForecast: {
    lines: Array<{ category: string; costUsd: number }>;
    totalUsd: number;
    projectedRiskReductionValueUsd: number;
    /** Categories with no supporting inventory — reported, never costed. */
    excludedCategories?: Array<{ category: string; reason: string; route?: string }>;
    assumptions?: string;
    blendedRateUsd?: number;
    hoursPerWeek?: number;
    totalHours?: number;
    valueBasis?: string;
    financialExposureUsd?: number;
    budget?: { budgetUsd: number; estimateUsd: number; varianceUsd: number; variancePct: number; status: 'within-budget' | 'over-budget' } | null;
  };
  riskEngine: { categories: RiskCategory[]; overall: number; overallLevel: string; explanation: string };
  riskForecast: { currentRisk: number; targetRisk: number; reductionPct: number; residualRisk: number; month12: number; month24: number; month36: number };
  migrationJobs: Array<{ id: string; status: string; progress: number; jobType: string; updatedAt: string }>;
  evidence: { sources: string[]; note: string };
  /** Shared Responsibility dependency-ordered 7-wave roadmap + tri-part readiness. */
  sharedResponsibility?: SharedResponsibilityIntelligence;
}

export const EMPTY_PLAN: MigrationPlan = {
  generatedAt: null,
  lastScanAt: null,
  hasData: false,
  hero: {
    readinessScore: 0, readinessLevel: 'Not Started', assetsRequiringMigration: 0, vulnerableComponents: 0,
    durationWeeks: 0, durationLabel: 'Evidence Not Available', costUsd: 0, costLabel: 'Evidence Not Available',
    riskReductionPct: 0, hndlExposure: 'Minimal', hndlScore: 0, pqcAdoption: 0, criticalFindingsRemaining: 0, quantumRisk: 0, assetsAssessed: 0,
  },
  stages: [],
  advisor: { recommendation: '', reason: '', affectedAssets: [], riskReductionPct: 0, costUsd: 0, timelineWeeks: 0, complexity: '', successProbabilityPct: 0, confidencePct: 0, deepLink: '/dashboard/quantum-readiness/ai-migration-advisor' },
  waves: [],
  dependencyGraph: { nodes: [], edges: [] },
  dependencyAnalysis: { chains: [], failurePoints: [], summary: '' },
  businessImpact: { customerFacingSystems: 0, missionCriticalSystems: 0, revenueImpact: 'Low', operationalImpact: 'Low', complianceImpact: 'Low', reputationalImpact: 'Low', financialImpact: 'Evidence Not Available', thirdPartyDependencies: 0, hndlExposure: 'Minimal', quantumExposureWindow: 'Evidence Not Available' },
  readinessDomains: [],
  strategies: [],
  whatIf: [],
  blockers: [],
  heatmap: { ready: 0, needsValidation: 0, needsUpgrade: 0, blocked: 0, unknown: 0, rows: [] },
  timeline: [],
  compliance: [],
  costForecast: { lines: [], totalUsd: 0, projectedRiskReductionValueUsd: 0, excludedCategories: [], assumptions: '', budget: null },
  riskEngine: { categories: [], overall: 0, overallLevel: 'Moderate', explanation: '' },
  riskForecast: { currentRisk: 0, targetRisk: 0, reductionPct: 0, residualRisk: 0, month12: 0, month24: 0, month36: 0 },
  migrationJobs: [],
  evidence: { sources: [], note: '' },
};

const REALTIME_TABLES = [
  'assets', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_inventory', 'crypto_exposures',
  'certificates', 'generated_keys', 'migration_jobs', 'migration_events', 'migration_plans', 'migration_validation_logs',
];

/**
 * useMigrationPlan — fetches the enterprise migration plan, keeps it live via a
 * dedicated SSE stream and Supabase realtime table subscriptions, and exposes
 * loading/error/connection state. Every value is tenant-scoped real data that
 * mirrors the QR pages and scanner intelligence.
 */
export function useMigrationPlan() {
  const resource = useLiveResource<MigrationPlan>({
    url: '/api/v1/migration-planner',
    streamUrl: '/api/v1/migration-planner/stream',
    event: 'migration-plan',
    empty: EMPTY_PLAN,
    normalize: (raw) => {
      const next = raw as Partial<MigrationPlan>;
      return { ...EMPTY_PLAN, ...next, hero: { ...EMPTY_PLAN.hero, ...next.hero } };
    },
    realtimeTables: REALTIME_TABLES,
    channelPrefix: 'migration-plan',
  });
  return {
    plan: resource.data,
    state: resource.state,
    error: resource.error,
    sseConnected: resource.sseConnected,
    transport: resource.transport,
    lastVerifiedAt: resource.lastVerifiedAt,
    refresh: resource.refresh,
  };
}
