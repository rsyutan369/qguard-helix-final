'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

/* ------------------------------------------------------------------ */
/* Types — the HNDL contract from /api/v1/harvest-now                 */
/* ------------------------------------------------------------------ */
export type LoadState = 'loading' | 'success' | 'error';
export type CryptoClass = 'vulnerable' | 'hybrid' | 'safe' | 'unknown';

export interface HndlBanner {
  threatLevel: string;
  hndlExposureScore: number;
  hndlExposureLevel: string;
  criticalFindings: number;
  quantumExposureWindow: string;
  estimatedFutureDecryptableTb: number;
  migrationDeadlineYear: number;
  yearsToDeadline: number;
  headline: string;
}

export interface ExposureTier {
  id: string;
  label: string;
  kind: string;
  total: number;
  vulnerable: number;
  cryptoClass: CryptoClass;
  detail: string;
}

export interface ExposureNode {
  id: string;
  label: string;
  type: string;
  environment: string;
  riskScore: number;
  cryptoClass: CryptoClass;
  internetFacing: boolean;
  algorithms: string[];
  affectedDataDetail: string;
  migrationPlan: string;
}

export interface TheaterRegion {
  key: string;
  region: string;
  x: number;
  y: number;
  assets: number;
  vulnerableAssets: number;
  avgRisk: number;
  cloudProviders: string[];
  severity: string;
}

export interface HarvestValueRow {
  key: string;
  label: string;
  inScope: boolean;
  assetCount: number;
  exposureScore: number;
  confidentialityLifetimeYears: number;
  confidentialityLabel: string;
  adversaryInterestScore: number;
  estimatedFutureValue: string;
  regulation: string;
}

export interface ShelfLifeRow {
  dataType: string;
  retentionRequirement: string;
  confidentialityYears: number;
  dataExpiresYear: number;
  quantumRiskWindow: string;
  exceedsCrqc: boolean;
  inScope: boolean;
  assetCount: number;
}

export interface BreakTimelineYear {
  year: number;
  projectedRisk: number;
  milestone: string;
  critical: boolean;
}

export interface ForwardSecrecy {
  coveragePct: number;
  assetsProtected: number;
  assetsUnprotected: number;
  totalTransport: number;
  nonPfsBreakdown: Array<{ type: string; count: number }>;
  topUnprotected: Array<{ asset: string; algorithm: string; protocol: string; reason: string }>;
  hasEvidence: boolean;
}

export interface ExposureMatrixRow {
  algorithm: string;
  assetCount: number;
  instanceCount: number;
  businessCriticality: string;
  exposure: string;
  cryptoClass: CryptoClass;
  migrationPriority: string;
  priorityRank: number;
  internetFacing: boolean;
}

export interface CapturedDataLine {
  key: string;
  label: string;
  unit: number;
  gb: number;
  tb: number;
}

export interface MigrationReadiness {
  readinessScore: number;
  readinessLevel: string;
  pqcReady: number;
  hybridReady: number;
  legacyOnly: number;
  migrationBlocked: number;
  migrationInProgress: number;
  migrationCompleted: number;
  pqcAdoptionPct: number;
  recommendation: string;
}

export interface AdversaryInterestRow {
  key: string;
  sector: string;
  interestScore: number;
  level: string;
  assetsInSector: number;
  inScope: boolean;
}

export interface ThreatActorRow {
  key: string;
  actor: string;
  interestScore: number;
  level: string;
  targetedAssets: string[];
  targetedAssetCount: number;
  motivation: string;
}

export interface IntelligenceFeedItem {
  id: string;
  date: string;
  source: string;
  category: string;
  title: string;
  detail: string;
  impact: string;
}

export interface TopFindingRow {
  id: string;
  asset: string;
  algorithm: string;
  severity: string;
  dataLifetimeYears: number;
  dataLifetimeLabel: string;
  riskWindow: string;
  exceedsCrqc: boolean;
  migrationPriority: string;
  environment: string;
  detectedAt: string | null;
}

export interface RemediationAction {
  key: string;
  label: string;
  affectedAssets: number;
  riskReductionPct: number;
  effort: string;
  completion: string;
  href: string;
  requires: string;
  inScope: boolean;
}

export interface HndlIntelligence {
  generatedAt: string | null;
  lastScanAt: string | null;
  hasData: boolean;
  connected: boolean;
  banner: HndlBanner;
  exposureGraph: { tiers: ExposureTier[]; nodes: ExposureNode[]; edges: Array<{ source: string; target: string; type: string }>; legend: { safe: string; hybrid: string; vulnerable: string } };
  theater: { regions: TheaterRegion[]; totalRegions: number; highValueTargets: number; summary: string };
  harvestValue: HarvestValueRow[];
  shelfLife: ShelfLifeRow[];
  breakTimeline: {
    currentYear: number; crqcYear: number; migrationDeadlineYear: number; migrationCompletionYear: number;
    yearsRemaining: number; currentRisk: number; projectedRiskAtCrqc: number; years: BreakTimelineYear[];
  };
  forwardSecrecy: ForwardSecrecy;
  exposureMatrix: ExposureMatrixRow[];
  capturedData: { lines: CapturedDataLine[]; totalTb: number; totalGb: number; hasEvidence: boolean };
  futureDecryptable: {
    totalDataAtRiskTb: number; projectedDecryptableTb: number; highValueDataPct: number;
    criticalConfidentialAssets: number; vulnerableSharePct: number; trend: Array<{ label: string; decryptableTb: number }>; hasEvidence: boolean;
  };
  migrationReadiness: MigrationReadiness;
  adversaryInterest: AdversaryInterestRow[];
  threatActors: ThreatActorRow[];
  intelligenceFeed: IntelligenceFeedItem[];
  topFindings: TopFindingRow[];
  remediationCenter: RemediationAction[];
  scores: { hndlRisk: number; hndlRiskLevel: string; quantumRisk: number; quantumReadiness: number; cryptoExposure: number; pqcAdoption: number };
  inventory: {
    assetsAssessed: number; quantumVulnerableAssets: number; vulnerableComponents: number; cryptoComponents: number;
    certificatesAnalyzed: number; keysDiscovered: number; domainsScanned: number; dataRepositories: number;
  };
  evidence: { sources: string[]; note: string };
}

export const EMPTY_HNDL: HndlIntelligence = {
  generatedAt: null,
  lastScanAt: null,
  hasData: false,
  connected: false,
  banner: { threatLevel: 'Unknown', hndlExposureScore: 0, hndlExposureLevel: 'Minimal', criticalFindings: 0, quantumExposureWindow: 'Evidence Not Available', estimatedFutureDecryptableTb: 0, migrationDeadlineYear: 2030, yearsToDeadline: 0, headline: '' },
  exposureGraph: { tiers: [], nodes: [], edges: [], legend: { safe: 'Quantum Safe', hybrid: 'Hybrid', vulnerable: 'Vulnerable' } },
  theater: { regions: [], totalRegions: 0, highValueTargets: 0, summary: '' },
  harvestValue: [],
  shelfLife: [],
  breakTimeline: { currentYear: new Date().getFullYear(), crqcYear: 2030, migrationDeadlineYear: 2029, migrationCompletionYear: 2029, yearsRemaining: 0, currentRisk: 0, projectedRiskAtCrqc: 0, years: [] },
  forwardSecrecy: { coveragePct: 0, assetsProtected: 0, assetsUnprotected: 0, totalTransport: 0, nonPfsBreakdown: [], topUnprotected: [], hasEvidence: false },
  exposureMatrix: [],
  capturedData: { lines: [], totalTb: 0, totalGb: 0, hasEvidence: false },
  futureDecryptable: { totalDataAtRiskTb: 0, projectedDecryptableTb: 0, highValueDataPct: 0, criticalConfidentialAssets: 0, vulnerableSharePct: 0, trend: [], hasEvidence: false },
  migrationReadiness: { readinessScore: 0, readinessLevel: 'Not Started', pqcReady: 0, hybridReady: 0, legacyOnly: 0, migrationBlocked: 0, migrationInProgress: 0, migrationCompleted: 0, pqcAdoptionPct: 0, recommendation: '' },
  adversaryInterest: [],
  threatActors: [],
  intelligenceFeed: [],
  topFindings: [],
  remediationCenter: [],
  scores: { hndlRisk: 0, hndlRiskLevel: 'Minimal', quantumRisk: 0, quantumReadiness: 0, cryptoExposure: 0, pqcAdoption: 0 },
  inventory: { assetsAssessed: 0, quantumVulnerableAssets: 0, vulnerableComponents: 0, cryptoComponents: 0, certificatesAnalyzed: 0, keysDiscovered: 0, domainsScanned: 0, dataRepositories: 0 },
  evidence: { sources: [], note: '' },
};

const REALTIME_TABLES = [
  'assets', 'pqc_scan_results', 'pqc_scan_sessions', 'crypto_inventory', 'crypto_exposures',
  'certificates', 'generated_keys', 'runtime_crypto_events', 'migration_jobs',
];

/**
 * useHarvestNow — fetches the enterprise HNDL intelligence model, keeps it live
 * via a dedicated SSE stream (header-authenticated fetch — token never in URL)
 * and Supabase realtime table subscriptions, and exposes loading/error/connection
 * state. Every value is tenant-scoped real data derived from scanned assets,
 * CBOM, certificates and runtime crypto telemetry.
 */
export function useHarvestNow() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [data, setData] = useState<HndlIntelligence>(EMPTY_HNDL);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const apply = useCallback((next: Partial<HndlIntelligence> | null) => {
    setData({ ...EMPTY_HNDL, ...(next || {}) });
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      apply(EMPTY_HNDL);
      setState('success');
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/harvest-now', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      apply(payload.data || {});
      setState('success');
      setError(null);
    } catch (err) {
      console.error('HNDL intelligence load failed:', err);
      setError(err instanceof Error ? err.message : 'Unable to load HNDL intelligence');
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
      apply(EMPTY_HNDL);
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
      if (eventName === 'hndl-intelligence' && dataLines.length) {
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
        const response = await fetch('/api/v1/harvest-now/stream', {
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

  // Supabase realtime — refresh on any tenant scan / crypto mutation
  useEffect(() => {
    if (!user) return;
    const channels = REALTIME_TABLES.map((table) =>
      supabase
        .channel(`hndl-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => { for (const channel of channels) supabase.removeChannel(channel); };
  }, [user, queueRefresh]);

  return { data, state, error, sseConnected, refresh };
}
