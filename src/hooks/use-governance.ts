'use client';

/**
 * Data contract for the Enterprise Governance Command Layer.
 *
 * Four pages — Compliance, Quantum Governance, Audit Vault, Regulatory Mapping —
 * are projections of one backend model. This hook is the only place any of them
 * talks to it, which is what makes their numbers agree by construction.
 *
 * Authenticated REST and SSE snapshots share the tenant model. The common
 * live client validates frames, scopes state to the signed-in user and
 * falls back to polling while it reconnects.
 */

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveModel } from './use-live-resource';
import type { AssetComplianceScope } from '@/lib/governance/asset-scope';
import type {
  AssetComplianceRecord,
  AuditEvent,
  ControlDomain,
  ControlRecord,
  ControlStatus,
  ControlSubject,
  EvidenceRecord,
  FrameworkRecord,
  GovernanceFacets,
  GovernanceGap,
  GovernanceIntelligence,
  GovernanceScore,
  GovernanceTelemetry,
  GovernanceTrendPoint,
  PolicyRecord,
  PolicyViolation,
  ReconciliationReport,
  RequirementRecord,
} from '@/lib/governance/types';

export type LoadState = 'loading' | 'success' | 'error';
export type GovernanceView = 'compliance' | 'quantum' | 'audit' | 'regulatory';

/* ------------------------------------------------------------------ */
/* Payload shapes — mirror projectView() in src/api-server/governance.ts */
/* ------------------------------------------------------------------ */

/** The bounded control row every table renders; full record is one fetch away. */
export interface ControlSummary {
  id: string;
  code: string;
  title: string;
  domain: ControlDomain;
  status: ControlStatus;
  score: number | null;
  measured: boolean;
  severity: ControlRecord['severity'];
  population: number;
  satisfied: number;
  failing: number;
  owner: string | null;
  ownerSource: ControlRecord['ownerSource'];
  frameworkIds: string[];
  requirementIds: string[];
  affectedAssetCount: number;
  lastValidatedAt: string | null;
  evidenceFreshness: ControlRecord['evidenceFreshness'];
  evidenceAgeDays: number | null;
  remediationRoute: string;
  basis: string;
  weight: number;
  hasException: boolean;
}

export interface DomainRollupRow {
  domain: ControlDomain;
  controls: number;
  measured: number;
  compliant: number;
  failing: number;
  unassessed: number;
  score: number | null;
  failingSubjects: number;
}

interface CommonPayload {
  generatedAt: string;
  latestEvidenceAt: string | null;
  hasData: boolean;
  stale: boolean;
  staleSinceHours: number | null;
  scores: GovernanceIntelligence['scores'];
  totals: GovernanceIntelligence['totals'];
  telemetry: GovernanceTelemetry;
  facets: GovernanceFacets;
  reconciliation: ReconciliationReport;
}

export interface CompliancePayload extends CommonPayload {
  view: 'compliance';
  controls: ControlSummary[];
  controlIndex: Array<{ id: string; code: string; title: string; status: ControlStatus; domain: ControlDomain }>;
  gaps: GovernanceGap[];
  frameworks: FrameworkRecord[];
  assets: AssetComplianceRecord[];
  evidence: EvidenceRecord[];
  trend: GovernanceTrendPoint[];
  domainRollup: DomainRollupRow[];
  requirementSummary: Array<{
    id: string;
    frameworkId: string;
    code: string;
    title: string;
    status: ControlStatus;
    score: number | null;
    measured: boolean;
  }>;
}

export interface QuantumGovernancePayload extends CommonPayload {
  view: 'quantum';
  policies: PolicyRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  assets: AssetComplianceRecord[];
  trend: GovernanceTrendPoint[];
  domainRollup: DomainRollupRow[];
  posture: {
    cryptoComponents: number;
    vulnerableComponents: number;
    pqcReadyComponents: number;
    certificates: number;
    keys: number;
    criticalFindings: number;
  };
}

export interface AuditVaultPayload extends CommonPayload {
  view: 'audit';
  auditEvents: AuditEvent[];
  evidence: EvidenceRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  trend: GovernanceTrendPoint[];
  integrity: {
    verified: number;
    mismatch: number;
    unanchored: number;
    unavailable: number;
    total: number;
    available: boolean;
    claim: string;
  };
  retention: { active: number; expiring: number; expired: number; unspecified: number; total: number };
  custodyRollup: Array<{ collector: string; count: number }>;
}

export interface RegulatoryPayload extends CommonPayload {
  view: 'regulatory';
  frameworks: FrameworkRecord[];
  requirements: RequirementRecord[];
  controls: ControlSummary[];
  gaps: GovernanceGap[];
  evidence: EvidenceRecord[];
  assets: AssetComplianceRecord[];
  trend: GovernanceTrendPoint[];
}

export type GovernancePayload = CompliancePayload | QuantumGovernancePayload | AuditVaultPayload | RegulatoryPayload;

/* ---- drill-down shapes ---- */

export interface ControlDetail {
  control: ControlRecord;
  definition: {
    id: string;
    code: string;
    title: string;
    objective: string;
    criterion: string;
    evidenceSources: string[];
    remediationRoute: string;
  } | null;
  requirements: RequirementRecord[];
  frameworks: FrameworkRecord[];
  evidence: EvidenceRecord[];
  policies: PolicyRecord[];
  assets: AssetComplianceRecord[];
  auditEvents: AuditEvent[];
  gaps: GovernanceGap[];
}

export interface FrameworkDetail {
  framework: FrameworkRecord;
  definition: { reference: string; scope: string; authority: string; version: string } | null;
  requirements: RequirementRecord[];
  controls: ControlSummary[];
  evidence: EvidenceRecord[];
  gaps: GovernanceGap[];
}

export interface RequirementDetail {
  requirement: RequirementRecord;
  definition: { summary: string; code: string } | null;
  framework: FrameworkRecord | null;
  controls: ControlSummary[];
  evidence: EvidenceRecord[];
}

export interface EvidenceDetail {
  evidence: EvidenceRecord;
  controls: ControlSummary[];
  requirements: RequirementRecord[];
  frameworks: FrameworkRecord[];
  asset: AssetComplianceRecord | null;
  auditEvents: AuditEvent[];
}

export interface AuditEventDetail {
  event: AuditEvent;
  evidence: EvidenceRecord | null;
  controls: ControlSummary[];
  asset: AssetComplianceRecord | null;
  related: AuditEvent[];
}

export interface AssetComplianceDetail {
  asset: AssetComplianceRecord;
  failingControls: ControlSummary[];
  evidence: EvidenceRecord[];
  auditEvents: AuditEvent[];
  gaps: GovernanceGap[];
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */

export const GOVERNANCE_API_BASE: Record<GovernanceView, string> = {
  compliance: '/api/v1/dashboard/compliance',
  quantum: '/api/v1/dashboard/quantum-governance',
  audit: '/api/v1/dashboard/audit-vault',
  regulatory: '/api/v1/dashboard/regulatory-mapping',
};

export const GOVERNANCE_ROUTE: Record<GovernanceView, string> = {
  compliance: '/dashboard/compliance',
  quantum: '/dashboard/quantum-governance',
  audit: '/dashboard/audit-vault',
  regulatory: '/dashboard/regulatory-mapping',
};

/**
 * Tables whose mutation can change what these pages show.
 *
 * Deliberately the union across all four views: an attestation write must nudge
 * Quantum Governance (its evidence-coverage tile) as well as Regulatory
 * Mapping, or the two pages drift apart until the next 10s push — which is
 * exactly the disagreement this layer exists to remove.
 */
const REALTIME_TABLES = [
  'assets',
  'crypto_inventory',
  'crypto_exposures',
  'certificates',
  'generated_keys',
  'runtime_crypto_events',
  'pqc_scan_sessions',
  'pqc_scan_results',
  'vulnerabilities',
  'scanner_alerts',
  'scanner_evidence',
  'agent_heartbeats',
  'scanner_agents',
  'connector_accounts',
  'migration_jobs',
  'migration_plans',
  'migration_events',
  'compliance_evidence',
  'audit_logs',
  'vault_audit_logs',
  'vault_files',
  'security_events',
  'user_security_events',
  'auth_events',
  'governance_policies',
  'governance_evidence_anchors',
  'governance_control_assessments',
] as const;

export interface UseGovernanceResult<T extends GovernancePayload> {
  data: T | null;
  state: LoadState;
  error: string | null;
  /** True only while the stream is genuinely open. Never "live" on stale data. */
  live: boolean;
  lastSyncedAt: string | null;
  /** Increments on every applied frame, so paged tables can refresh in step. */
  revision: number;
  refresh: (force?: boolean) => Promise<void>;
  reconnect: () => void;
}

export function useGovernanceView<T extends GovernancePayload>(view: GovernanceView): UseGovernanceResult<T> {
  const url = GOVERNANCE_API_BASE[view];
  const model = useLiveModel<T>({
    url,
    streamUrl: `${url}/stream`,
    event: 'governance',
    channelPrefix: `governance-${view}`,
    realtimeTables: REALTIME_TABLES,
    validate: (payload) => payload.view === view &&
      typeof payload.generatedAt === 'string' && Number.isFinite(Date.parse(payload.generatedAt)) &&
      Boolean(payload.totals && payload.telemetry && payload.scores && payload.facets),
  });
  return {
    data: model.data,
    state: model.state,
    error: model.error,
    live: model.live,
    lastSyncedAt: model.lastVerifiedAt,
    revision: model.data ? Date.parse(model.data.generatedAt) : 0,
    refresh: model.refresh,
    reconnect: model.reconnect,
  };
}

export function useGovernanceAccount() {
  const { user, session } = useAuth();
  const accountId = user && session?.user.id === user.id ? user.id : null;
  return { accountId, token: accountId ? session?.access_token : undefined };
}

export function useAssetComplianceScope(assetIds: string[]) {
  const ids = [...new Set(assetIds)].sort();
  const query = new URLSearchParams({ assets: ids.join(',') });
  const path = `${GOVERNANCE_API_BASE.compliance}/asset-scope`;
  return useLiveModel<AssetComplianceScope>({
    url: `${path}?${query}`,
    streamUrl: `${path}/stream?${query}`,
    event: 'asset-compliance',
    channelPrefix: 'asset-compliance',
    realtimeTables: REALTIME_TABLES,
    validate: (value) => {
      if (typeof value.generatedAt !== 'string' || !Number.isFinite(Date.parse(value.generatedAt))) return false;
      if (!Array.isArray(value.assets) || value.assets.length !== ids.length ||
          JSON.stringify(value.assets.map((asset) => asset?.id).sort()) !== JSON.stringify(ids)) return false;
      return ['controls', 'requirements', 'evidence', 'findings', 'violations', 'auditEvents', 'remediation', 'unavailableSources']
        .every((key) => Array.isArray(value[key]));
    },
  });
}

/* ------------------------------------------------------------------ */
/* Named wrappers — one per page                                       */
/* ------------------------------------------------------------------ */

export const useComplianceCommandCenter = () => useGovernanceView<CompliancePayload>('compliance');
export const useQuantumGovernance = () => useGovernanceView<QuantumGovernancePayload>('quantum');
export const useAuditVault = () => useGovernanceView<AuditVaultPayload>('audit');
export const useRegulatoryMapping = () => useGovernanceView<RegulatoryPayload>('regulatory');

/* ------------------------------------------------------------------ */
/* Lazy drill-down (§15)                                               */
/* ------------------------------------------------------------------ */

/**
 * Fetches the full investigation record for one governance object.
 *
 * The dashboard payloads deliberately do not ship every failing subject for
 * every control; the drawer asks for the one the user actually opened. An
 * in-flight request is aborted when a newer one starts, so rapid clicking
 * through a table cannot land an older response on a newer drawer.
 */
export function useGovernanceDetail(view: GovernanceView) {
  const { token } = useGovernanceAccount();
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const inFlight = useRef<AbortController | null>(null);

  useLayoutEffect(
    () => () => {
      inFlight.current?.abort();
    },
    [token, view],
  );

  const load = useCallback(
    async <R,>(path: string): Promise<R | null> => {
      if (!token) return null;
      inFlight.current?.abort();
      const controller = new AbortController();
      inFlight.current = controller;
      setLoading(true);
      setDetailError(null);
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (controller.signal.aborted) return null;
        if (!payload?.data) throw new Error('Governance detail response was empty');
        return payload.data as R;
      } catch (err) {
        if (controller.signal.aborted) return null;
        console.error('Governance detail load failed:', err);
        setDetailError(err instanceof Error ? err.message : 'Unable to load detail');
        return null;
      } finally {
        if (inFlight.current === controller) {
          inFlight.current = null;
          setLoading(false);
        }
      }
    },
    [token, view],
  );

  const loadControl = useCallback((id: string) => load<ControlDetail>(`/controls/${encodeURIComponent(id)}`), [load]);
  const loadFramework = useCallback((id: string) => load<FrameworkDetail>(`/frameworks/${encodeURIComponent(id)}`), [load]);
  const loadRequirement = useCallback((id: string) => load<RequirementDetail>(`/requirements/${encodeURIComponent(id)}`), [load]);
  const loadEvidence = useCallback((id: string) => load<EvidenceDetail>(`/evidence/${encodeURIComponent(id)}`), [load]);
  const loadAuditEvent = useCallback((id: string) => load<AuditEventDetail>(`/audit-events/${encodeURIComponent(id)}`), [load]);
  const loadAsset = useCallback((id: string) => load<AssetComplianceDetail>(`/assets/${encodeURIComponent(id)}`), [load]);

  return { loadControl, loadFramework, loadRequirement, loadEvidence, loadAuditEvent, loadAsset, loading, detailError };
}

/* ------------------------------------------------------------------ */
/* Server-side paged tables (§12)                                      */
/* ------------------------------------------------------------------ */

export interface PagedQuery {
  [key: string]: string | number | undefined;
}

/**
 * Server-side search, filter, sort and paging.
 *
 * Large estates must never ship thousands of rows to the browser to display
 * fifty. Filtering happens on the API against the cached model, so paging costs
 * nothing extra and every page of results is derived from the same snapshot the
 * KPI strip was computed from.
 *
 * `revision` is bumped by the view hook whenever the live model updates, so an
 * open table refreshes in step with the rest of the page.
 */
export function useGovernancePagedResource<T>(
  view: GovernanceView,
  path: string,
  key: string,
  query: PagedQuery,
  revision: number,
  enabled = true,
) {
  const { accountId, token } = useGovernanceAccount();
  const serialized = JSON.stringify(query);
  const scope = accountId && enabled ? JSON.stringify([accountId, view, path, key, serialized]) : null;
  const [result, setResult] = useState<{
    scope: string;
    rows: T[];
    extra: Record<string, unknown>;
    total: number;
  } | null>(null);
  const [request, setRequest] = useState<{ scope: string; loading: boolean; error: string | null } | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const retry = useCallback(() => setRetryCount((count) => count + 1), []);

  useEffect(() => {
    if (!token || !scope) return;
    const controller = new AbortController();
    setRequest({ scope, loading: true, error: null });
    const timer = setTimeout(async () => {
      try {
        const params = new URLSearchParams();
        for (const [name, value] of Object.entries(JSON.parse(serialized) as PagedQuery)) {
          if (value === undefined || value === '' || value === 'all') continue;
          params.set(name, String(value));
        }
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}?${params.toString()}`, {
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (controller.signal.aborted) return;
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        if (!Array.isArray(payload.data?.[key]) || !Number.isSafeInteger(payload.data?.total) || payload.data.total < 0) {
          throw new Error('Governance inventory response was incomplete');
        }
        setResult({ scope, rows: payload.data[key] as T[], extra: payload.data, total: payload.data.total });
        setRequest({ scope, loading: false, error: null });
      } catch (err) {
        if (controller.signal.aborted) return;
        console.error('Governance table load failed:', err);
        setRequest({ scope, loading: false, error: err instanceof Error ? err.message : 'Unable to load rows' });
      }
      // Debounced so typing in the search box does not fire a request per keystroke.
    }, 250);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token, scope, view, path, key, serialized, revision, retryCount]);

  const current = scope && result?.scope === scope ? result : null;
  const currentRequest = scope && request?.scope === scope ? request : null;
  return {
    rows: current?.rows ?? [],
    extra: current?.extra ?? {},
    total: current?.total ?? 0,
    loading: Boolean(token && scope && (currentRequest?.loading ?? true)),
    error: currentRequest?.error ?? null,
    retry,
  };
}

/* ------------------------------------------------------------------ */
/* Governance actions (§6 policy management, §7 evidence integrity)    */
/* ------------------------------------------------------------------ */

export interface GovernanceActionResult<T> {
  ok: boolean;
  data: T | null;
  message: string;
}

/**
 * Write actions that change governance state.
 *
 * Each returns a structured result rather than throwing, so the UI can show the
 * backend's own message — including the "apply the governance schema" guidance
 * when a store is not yet available — instead of a generic failure.
 */
export function useGovernanceActions(view: GovernanceView) {
  const { token } = useGovernanceAccount();
  const [pending, setPending] = useState<string | null>(null);

  const post = useCallback(
    async <T,>(path: string, body: unknown, method: 'POST' | 'PATCH' = 'POST'): Promise<GovernanceActionResult<T>> => {
      if (!token) return { ok: false, data: null, message: 'Not authenticated' };
      setPending(path);
      try {
        const response = await fetch(`${GOVERNANCE_API_BASE[view]}${path}`, {
          method,
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body ?? {}),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          return { ok: false, data: null, message: payload?.error?.message || `HTTP ${response.status}` };
        }
        return { ok: true, data: (payload.data ?? null) as T, message: String(payload?.data?.message || 'Done') };
      } catch (err) {
        return { ok: false, data: null, message: err instanceof Error ? err.message : 'Request failed' };
      } finally {
        setPending(null);
      }
    },
    [token, view],
  );

  const anchorEvidence = useCallback(
    (input: { evidenceIds?: string[]; scope?: 'unanchored' | 'all' }) =>
      post<{ anchored: number; reanchored: number; total: number; message: string }>('/evidence/anchor', input),
    [post],
  );

  const verifyEvidence = useCallback(
    (evidenceId: string) =>
      post<{
        evidenceId: string;
        recomputedDigest: string;
        anchoredDigest: string | null;
        firstDigest: string | null;
        anchoredAt: string | null;
        reanchorCount: number;
        state: EvidenceRecord['integrity']['state'];
        assurance: string;
        verifiedAt: string;
      }>('/evidence/verify', { evidenceId }),
    [post],
  );

  const updatePolicy = useCallback(
    (
      policyId: string,
      input: { enforcement?: string; severity?: string; parameters?: Record<string, unknown>; note?: string },
    ) => post<{ policy: PolicyRecord | null }>(`/policies/${encodeURIComponent(policyId)}`, input, 'PATCH'),
    [post],
  );

  const updateControlAssessment = useCallback(
    (
      controlId: string,
      input: {
        owner?: string;
        ownerEmail?: string;
        reviewNote?: string;
        attest?: boolean;
        exceptionReason?: string;
        exceptionApprovedBy?: string;
        exceptionExpiresAt?: string;
      },
    ) => post<{ control: ControlRecord | null }>(`/controls/${encodeURIComponent(controlId)}/assessment`, input, 'PATCH'),
    [post],
  );

  return { anchorEvidence, verifyEvidence, updatePolicy, updateControlAssessment, pending };
}

/* ------------------------------------------------------------------ */
/* Shared filter state (§14)                                           */
/* ------------------------------------------------------------------ */

export interface GovernanceFilters {
  search: string;
  status: string;
  domain: string;
  framework: string;
  requirement: string;
  severity: string;
  owner: string;
  environment: string;
  criticality: string;
  exposure: string;
  freshness: string;
  kind: string;
  outcome: string;
  integrity: string;
  retention: string;
  category: string;
  enforcement: string;
  actorType: string;
  asset: string;
  control: string;
  range: string;
  sort: string;
}

export const EMPTY_GOVERNANCE_FILTERS: GovernanceFilters = {
  search: '',
  status: 'all',
  domain: 'all',
  framework: 'all',
  requirement: 'all',
  severity: 'all',
  owner: 'all',
  environment: 'all',
  criticality: 'all',
  exposure: 'all',
  freshness: 'all',
  kind: 'all',
  outcome: 'all',
  integrity: 'all',
  retention: 'all',
  category: 'all',
  enforcement: 'all',
  actorType: 'all',
  asset: '',
  control: 'all',
  range: 'all',
  sort: '',
};

/**
 * One filter object shared by every widget and table on a page, so a framework
 * chosen in the header narrows the chart and the table together rather than
 * only one of them (§14: "filters must produce consistent results").
 *
 * The filter names are identical across all four pages, which is what lets a
 * drill-down carry its context to the next page through the URL.
 */
export function useGovernanceFilters(initial?: Partial<GovernanceFilters>) {
  const [filters, setFilters] = useState<GovernanceFilters>({ ...EMPTY_GOVERNANCE_FILTERS, ...initial });

  const setFilter = useCallback((key: keyof GovernanceFilters, value: string) => {
    setFilters((current) => (current[key] === value ? current : { ...current, [key]: value }));
  }, []);

  const reset = useCallback(() => setFilters({ ...EMPTY_GOVERNANCE_FILTERS, ...initial }), [initial]);

  const activeCount = useMemo(
    () =>
      (Object.keys(filters) as Array<keyof GovernanceFilters>).filter((key) => {
        if (key === 'sort') return false;
        const value = filters[key];
        return value !== '' && value !== 'all';
      }).length,
    [filters],
  );

  return { filters, setFilter, setFilters, reset, activeCount };
}

export type { ControlSubject, PolicyViolation, GovernanceScore };
