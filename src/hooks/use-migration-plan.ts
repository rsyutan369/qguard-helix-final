'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
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
    criticalAssetsRemaining: number;
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
  costForecast: { lines: Array<{ category: string; costUsd: number }>; totalUsd: number; projectedRiskReductionValueUsd: number };
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
    riskReductionPct: 0, hndlExposure: 'Minimal', hndlScore: 0, pqcAdoption: 0, criticalAssetsRemaining: 0, quantumRisk: 0, assetsAssessed: 0,
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
  costForecast: { lines: [], totalUsd: 0, projectedRiskReductionValueUsd: 0 },
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
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [plan, setPlan] = useState<MigrationPlan>(EMPTY_PLAN);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((data: Partial<MigrationPlan> | null) => {
    setPlan({ ...EMPTY_PLAN, ...(data || {}), hero: { ...EMPTY_PLAN.hero, ...(data?.hero || {}) } });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_PLAN);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/migration-planner', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('Migration plan load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load migration plan');
      setState('error');
    }
  }, [token, apply]);

  const queueRefresh = useCallback(() => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void refresh();
    }, 400);
  }, [refresh]);

  useEffect(() => () => { if (refreshTimer.current) clearTimeout(refreshTimer.current); }, []);

  useEffect(() => {
    if (!token || !user) {
      apply(EMPTY_PLAN);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh, apply]);

  // Dedicated SSE stream over fetch() + Authorization header. EventSource cannot
  // set request headers, which forces the bearer token into the URL query string
  // where it leaks into access logs / proxies / browser history. Reading the
  // text/event-stream body via a ReadableStream lets us authenticate with a
  // header and keep the token out of the URL entirely.
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    const parseFrame = (frame: string) => {
      let eventName = 'message';
      const dataLines: string[] = [];
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
        // lines starting with ':' are heartbeats/comments — ignored
      }
      if (eventName === 'migration-plan' && dataLines.length) {
        try {
          apply(JSON.parse(dataLines.join('\n')));
          setState('success');
          setError(null);
        } catch {
          /* ignore malformed frame */
        }
      }
    };

    const connect = async () => {
      try {
        const response = await fetch('/api/v1/migration-planner/stream', {
          headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        setSseConnected(true);
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            parseFrame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf('\n\n');
          }
        }
        throw new Error('stream ended');
      } catch {
        if (cancelled || controller.signal.aborted) return;
        setSseConnected(false);
        if (retry) clearTimeout(retry);
        retry = setTimeout(() => void connect(), 10000);
      }
    };

    void connect();
    return () => {
      cancelled = true;
      controller.abort();
      if (retry) clearTimeout(retry);
      setSseConnected(false);
    };
  }, [token, apply]);

  // Supabase realtime — refresh on any tenant migration / scan mutation
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`migration-plan-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  return { plan, state, error, sseConnected, refresh };
}
