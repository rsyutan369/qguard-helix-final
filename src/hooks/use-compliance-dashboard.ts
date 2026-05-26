'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';

export type ComplianceTone = 'gold' | 'green' | 'red' | 'muted';

export type ComplianceCertificateRow = {
  algorithm: string;
  issuedTo: string;
  issuedOn: string;
  expiresOn: string;
  status: 'Active' | 'Expired' | 'Expiring Soon';
};

export type CompliancePolicyRow = {
  name: string;
  category: string;
  status: 'Compliant' | 'Review';
  lastReviewed: string;
};

export type ComplianceFrameworkAlignment = {
  name: string;
  score: number;
};

export type ComplianceMaturityLevel = {
  label: string;
  value: number;
  color: string;
};

export type ComplianceTrendPoint = {
  label: string;
  value: number;
};

export type ComplianceGovernancePolicyRow = {
  name: string;
  category: string;
  status: 'Enforced' | 'Draft';
  coverage: number;
  updated: string;
};

export type CompliancePolicyViolation = {
  id?: string;
  title: string;
  detail: string;
  severity: 'High' | 'Medium' | 'Low';
  time: string;
  type: 'warning' | 'info';
};

export type ComplianceRequirementBreakdown = {
  label: string;
  value: number;
  color: string;
};

export type ComplianceCapabilityHighlight = {
  label: string;
  detail: string;
  iconKey: 'shield' | 'audit' | 'check' | 'target' | 'clipboard' | 'building';
};

export type ComplianceTelemetryEvent = {
  id: string;
  source: string;
  title: string;
  detail: string;
  severity: string;
  timestamp: string | null;
};

export type ComplianceDashboardSnapshot = {
  generatedAt: string;
  source: {
    mode: string;
    latestActivityAt: string | null;
    latestScanAt: string | null;
    tables: Record<string, number>;
  };
  metrics: {
    complianceScore: number;
    qScore: number;
    readinessScore: number;
    validationScore: number;
    policyAdherence: number;
    totalAssets: number;
    totalComponents: number;
    vulnerableAssets: number;
    vulnerableComponents: number;
    quantumSecuredAssets: number;
    pqcReadyComponents: number;
    criticalFindings: number;
    highFindings: number;
    openFindings: number;
    totalCertificates: number;
    activeCertificates: number;
    expiredCertificates: number;
    expiringCertificates: number;
    totalPolicies: number;
    enforcedPolicies: number;
    activeScans: number;
    completedScans: number;
    activeMigrationJobs: number;
    completedMigrationJobs: number;
    failedMigrationJobs: number;
    migrationCompletionRate: number;
    hybridDeployments: number;
    mlKemDeployments: number;
    mlDsaDeployments: number;
    keyCount: number;
    secureKeys: number;
    auditEvents: number;
    runtimeEvents24h: number;
    hndlExposures: number;
    remediatedItems: number;
    scannerAgents: number;
    trustDependencies: number;
  };
  checklist: Array<{ label: string; complete: boolean; detail?: string }>;
  certificates: ComplianceCertificateRow[];
  policies: CompliancePolicyRow[];
  frameworkAlignment: ComplianceFrameworkAlignment[];
  maturityLevels: ComplianceMaturityLevel[];
  policyTrend: ComplianceTrendPoint[];
  governancePolicyMatrix: ComplianceGovernancePolicyRow[];
  policyViolations: CompliancePolicyViolation[];
  requirementBreakdown: ComplianceRequirementBreakdown[];
  capabilityHighlights: ComplianceCapabilityHighlight[];
  telemetry: ComplianceTelemetryEvent[];
};

const EMPTY_SNAPSHOT: ComplianceDashboardSnapshot = {
  generatedAt: '',
  source: {
    mode: 'empty',
    latestActivityAt: null,
    latestScanAt: null,
    tables: {},
  },
  metrics: {
    complianceScore: 0,
    qScore: 0,
    readinessScore: 0,
    validationScore: 0,
    policyAdherence: 0,
    totalAssets: 0,
    totalComponents: 0,
    vulnerableAssets: 0,
    vulnerableComponents: 0,
    quantumSecuredAssets: 0,
    pqcReadyComponents: 0,
    criticalFindings: 0,
    highFindings: 0,
    openFindings: 0,
    totalCertificates: 0,
    activeCertificates: 0,
    expiredCertificates: 0,
    expiringCertificates: 0,
    totalPolicies: 0,
    enforcedPolicies: 0,
    activeScans: 0,
    completedScans: 0,
    activeMigrationJobs: 0,
    completedMigrationJobs: 0,
    failedMigrationJobs: 0,
    migrationCompletionRate: 0,
    hybridDeployments: 0,
    mlKemDeployments: 0,
    mlDsaDeployments: 0,
    keyCount: 0,
    secureKeys: 0,
    auditEvents: 0,
    runtimeEvents24h: 0,
    hndlExposures: 0,
    remediatedItems: 0,
    scannerAgents: 0,
    trustDependencies: 0,
  },
  checklist: [],
  certificates: [],
  policies: [],
  frameworkAlignment: [],
  maturityLevels: [],
  policyTrend: [],
  governancePolicyMatrix: [],
  policyViolations: [],
  requirementBreakdown: [],
  capabilityHighlights: [],
  telemetry: [],
};

const CACHE_PREFIX = 'qguard-compliance-dashboard:v1:';

function normalizeSnapshot(payload: unknown): ComplianceDashboardSnapshot {
  const snapshot = (payload || {}) as Partial<ComplianceDashboardSnapshot>;
  return {
    ...EMPTY_SNAPSHOT,
    ...snapshot,
    source: { ...EMPTY_SNAPSHOT.source, ...(snapshot.source || {}), tables: { ...(snapshot.source?.tables || {}) } },
    metrics: { ...EMPTY_SNAPSHOT.metrics, ...(snapshot.metrics || {}) },
    checklist: Array.isArray(snapshot.checklist) ? snapshot.checklist : [],
    certificates: Array.isArray(snapshot.certificates) ? snapshot.certificates : [],
    policies: Array.isArray(snapshot.policies) ? snapshot.policies : [],
    frameworkAlignment: Array.isArray(snapshot.frameworkAlignment) ? snapshot.frameworkAlignment : [],
    maturityLevels: Array.isArray(snapshot.maturityLevels) ? snapshot.maturityLevels : [],
    policyTrend: Array.isArray(snapshot.policyTrend) ? snapshot.policyTrend : [],
    governancePolicyMatrix: Array.isArray(snapshot.governancePolicyMatrix) ? snapshot.governancePolicyMatrix : [],
    policyViolations: Array.isArray(snapshot.policyViolations) ? snapshot.policyViolations : [],
    requirementBreakdown: Array.isArray(snapshot.requirementBreakdown) ? snapshot.requirementBreakdown : [],
    capabilityHighlights: Array.isArray(snapshot.capabilityHighlights) ? snapshot.capabilityHighlights : [],
    telemetry: Array.isArray(snapshot.telemetry) ? snapshot.telemetry : [],
  };
}

function hasData(snapshot: ComplianceDashboardSnapshot) {
  return Boolean(
    snapshot.metrics.totalAssets ||
    snapshot.metrics.totalComponents ||
    snapshot.metrics.totalPolicies ||
    snapshot.metrics.auditEvents ||
    snapshot.certificates.length ||
    snapshot.policies.length ||
    snapshot.frameworkAlignment.length ||
    snapshot.telemetry.length,
  );
}

function readCache(key: string | null) {
  if (!key || typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const snapshot = normalizeSnapshot(JSON.parse(raw));
    return hasData(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}

function writeCache(key: string | null, snapshot: ComplianceDashboardSnapshot) {
  if (!key || typeof window === 'undefined' || !hasData(snapshot)) return;
  try {
    window.localStorage.setItem(key, JSON.stringify(snapshot));
  } catch {
    // Ignore browser storage restrictions.
  }
}

export function useComplianceDashboard() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<ComplianceDashboardSnapshot>(EMPTY_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const streamRef = useRef<EventSource | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cacheKey = useMemo(() => {
    const tenantKey =
      session?.user?.app_metadata?.tenant_id ||
      session?.user?.app_metadata?.organization_id ||
      session?.user?.user_metadata?.tenant_id ||
      session?.user?.user_metadata?.organization_id ||
      'default-tenant';
    const userKey = session?.user?.id || token?.slice(0, 24);
    return userKey ? `${CACHE_PREFIX}${tenantKey}:${userKey}` : null;
  }, [
    session?.user?.app_metadata?.organization_id,
    session?.user?.app_metadata?.tenant_id,
    session?.user?.id,
    session?.user?.user_metadata?.organization_id,
    session?.user?.user_metadata?.tenant_id,
    token,
  ]);

  const applySnapshot = useCallback((next: ComplianceDashboardSnapshot) => {
    setSnapshot(next);
    writeCache(cacheKey, next);
  }, [cacheKey]);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_SNAPSHOT);
      setLoading(false);
      setError(null);
      setConnected(false);
      return;
    }

    try {
      setLoading((current) => current && !hasData(readCache(cacheKey) || EMPTY_SNAPSHOT));
      const response = await fetch('/api/v1/dashboard/compliance', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      applySnapshot(normalizeSnapshot(payload.data));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load compliance dashboard telemetry');
    } finally {
      setLoading(false);
    }
  }, [applySnapshot, cacheKey, token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 250);
  }, [refresh]);

  useEffect(() => {
    if (!token) {
      setSnapshot(EMPTY_SNAPSHOT);
      setLoading(false);
      return;
    }

    const cached = readCache(cacheKey);
    if (cached) {
      setSnapshot(cached);
      setLoading(false);
    } else {
      setLoading(true);
    }

    void refresh();
  }, [cacheKey, refresh, token]);

  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'asset_relationships',
      'crypto_inventory',
      'crypto_exposures',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'migration_jobs',
      'migration_events',
      'runtime_crypto_events',
      'security_events',
      'compliance_evidence',
      'certificates',
      'generated_keys',
      'vulnerabilities',
      'scanner_alerts',
      'scanner_agents',
      'vault_audit_logs',
    ];

    const channels = tables.map((table) => supabase
      .channel(`compliance-dashboard-${table}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` },
        queueRefresh,
      )
      .subscribe());

    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [queueRefresh, user]);

  useEffect(() => {
    if (!token) {
      streamRef.current?.close();
      setConnected(false);
      return;
    }

    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const close = () => {
      streamRef.current?.close();
      streamRef.current = null;
      setConnected(false);
    };

    const startPolling = () => {
      if (pollTimer) return;
      pollTimer = setInterval(() => void refresh(), 10000);
    };

    const connect = () => {
      close();
      const stream = new EventSource(`/api/v1/dashboard/compliance/stream?token=${encodeURIComponent(token)}`);
      streamRef.current = stream;

      stream.addEventListener('compliance-connected', () => {
        setConnected(true);
        setError(null);
      });

      stream.addEventListener('compliance-update', (event) => {
        try {
          const next = normalizeSnapshot(JSON.parse((event as MessageEvent).data));
          applySnapshot(next);
          setLoading(false);
          setConnected(true);
          setError(null);
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Unable to parse compliance telemetry stream');
        }
      });

      stream.onerror = () => {
        close();
        startPolling();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 15000);
      };
    };

    connect();
    return () => {
      close();
      if (retryTimer) clearTimeout(retryTimer);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [applySnapshot, refresh, token]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
  }, []);

  return { snapshot, loading, error, connected, refresh };
}

export { EMPTY_SNAPSHOT as EMPTY_COMPLIANCE_DASHBOARD_SNAPSHOT };
