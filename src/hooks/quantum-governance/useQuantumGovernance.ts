import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import type {
  ComplianceControl,
  CryptoAsset,
  GovernanceEvidence,
  GovernanceKPI,
  GovernanceWorkflow,
  OwnershipRecord,
  PkiDebtItem,
  PqcMigrationStep,
  VendorReadiness,
} from '@/types/quantum-governance';

type SnapshotRow = {
  id: string;
  domain?: string;
  title?: string;
  subject?: string;
  subjectType?: string;
  framework?: string;
  control?: string;
  status?: string;
  severity?: string;
  score?: number;
  compliant?: boolean;
  pqcReady?: boolean;
  timestamp?: string | null;
  source?: string;
  detail?: string;
};

type GovernanceSnapshot = {
  generatedAt?: string | null;
  latestActivityAt?: string | null;
  metrics?: Record<string, number>;
  domainRows?: Array<{ label: string; coverage: number; riskScore: number; latestSeen: string | null }>;
  regulatoryRows?: Array<{ framework: string; control: string; coverage: number; findings: number; latestSeen: string | null }>;
  auditRows?: Array<{ id: string; event: string; actor: string; source: string; timestamp: string | null }>;
  alerts?: Array<{ id: string; title: string; detail: string; severity: string; timestamp: string | null; source: string; domain: string }>;
  recommendations?: Array<{ id: string; title: string; detail: string; impact: string; count: number }>;
  inventory?: SnapshotRow[];
  sourceDistribution?: Array<{ label: string; count: number }>;
};

const emptySnapshot: GovernanceSnapshot = {};

function clamp(value: number, min = 0, max = 100) {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, Math.round(value)));
}

function severity(value: unknown): GovernanceKPI['severity'] {
  const lower = String(value || '').toLowerCase();
  if (lower === 'critical') return 'critical';
  if (lower === 'high') return 'high';
  if (lower === 'medium' || lower === 'moderate' || lower === 'warning') return 'medium';
  return 'low';
}

function trend(value: number): GovernanceKPI['trend'] {
  if (value > 0) return 'up';
  if (value < 0) return 'down';
  return 'stable';
}

function percent(value: unknown) {
  return `${clamp(Number(value) || 0)}%`;
}

function displayDate(value: string | null | undefined) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Awaiting telemetry';
  return date.toISOString().slice(0, 10);
}

function assetStatus(value: unknown): CryptoAsset['status'] {
  const lower = String(value || '').toLowerCase();
  if (/revoked|deleted|disabled|blocked/.test(lower)) return 'revoked';
  if (/deprecated|legacy|restricted|vulnerable/.test(lower)) return 'deprecated';
  if (/rotation|renew|expir/.test(lower)) return 'rotation_due';
  return 'active';
}

function workflowPriority(value: unknown): GovernanceWorkflow['priority'] {
  const level = severity(value);
  return level === 'low' ? 'medium' : level;
}

function adaptSnapshot(snapshot: GovernanceSnapshot) {
  const metrics = snapshot.metrics || {};
  const generatedAt = snapshot.generatedAt || new Date().toISOString();
  const governanceScore = clamp((
    Number(metrics.policyScore || 0) +
    Number(metrics.policyCoverage || 0) +
    Number(metrics.complianceScore || 0) +
    Number(metrics.vaultIntegrityScore || 0) +
    Number(metrics.pqcReadiness || 0) +
    Number(metrics.encryptedCoverage || 0)
  ) / 6);

  const kpis: GovernanceKPI[] = [
    { label: 'Governance Score', value: percent(governanceScore), severity: severity(governanceScore < 50 ? 'high' : governanceScore < 75 ? 'medium' : 'low'), trend: trend(Number(metrics.evidenceDelta || 0)), updatedAt: generatedAt },
    { label: 'Policy Coverage', value: percent(metrics.policyCoverage), severity: severity(Number(metrics.policyCoverage || 0) < 60 ? 'high' : 'low'), trend: trend(Number(metrics.evidenceDelta || 0)), updatedAt: generatedAt },
    { label: 'PQC Readiness', value: percent(metrics.pqcReadiness), severity: severity(Number(metrics.pqcReadiness || 0) < 40 ? 'critical' : Number(metrics.pqcReadiness || 0) < 70 ? 'medium' : 'low'), trend: 'stable', updatedAt: generatedAt },
    { label: 'High-Risk Findings', value: Number(metrics.highRiskFindings || 0), severity: severity(Number(metrics.highRiskFindings || 0) > 0 ? 'high' : 'low'), trend: Number(metrics.highRiskFindings || 0) > 0 ? 'up' : 'stable', updatedAt: generatedAt },
    { label: 'Compliance Score', value: percent(metrics.complianceScore), severity: severity(Number(metrics.complianceScore || 0) < 70 ? 'medium' : 'low'), trend: 'stable', updatedAt: generatedAt },
    { label: 'Evidence Objects', value: Number(metrics.totalEvidence || 0), severity: 'low', trend: trend(Number(metrics.evidenceDelta || 0)), updatedAt: generatedAt },
  ];

  const inventory: CryptoAsset[] = (snapshot.inventory || []).slice(0, 24).map((row) => ({
    id: row.id,
    name: row.subject || row.title || 'Governance asset',
    environment: row.source || row.domain || 'Tenant telemetry',
    businessOwner: row.framework || 'Governance',
    technicalOwner: row.subjectType || row.domain || 'Telemetry owner',
    criticality: severity(row.severity),
    dataClassification: row.framework || 'Governance evidence',
    algorithm: row.detail || row.title || 'Observed control',
    keyType: row.domain || 'Governance signal',
    protocol: row.control || row.status || 'Control',
    lastRotation: displayDate(row.timestamp),
    nextRotation: row.compliant ? 'Current' : 'Review required',
    pqcReadiness: row.pqcReady ? 100 : 0,
    riskScore: clamp(Number(row.score || 0)),
    status: assetStatus(row.status),
  }));

  const ownership: OwnershipRecord[] = (snapshot.domainRows || []).slice(0, 12).map((row) => ({
    domain: row.label,
    businessOwner: 'Governance',
    technicalOwner: 'Telemetry',
    securityOwner: 'Security',
    lastReview: displayDate(row.latestSeen),
    status: row.coverage >= 80 ? 'compliant' : row.coverage > 0 ? 'review_required' : 'unowned',
  }));

  const pkiDebt: PkiDebtItem[] = (snapshot.alerts || []).slice(0, 12).map((row) => ({
    id: row.id,
    type: row.domain || row.source,
    description: row.detail || row.title,
    impact: severity(row.severity),
    blockingPqc: /pqc|quantum|algorithm|certificate|key|vulnerability/i.test(`${row.title} ${row.detail}`),
    status: /manual/i.test(row.detail) ? 'manual' : /unknown/i.test(row.detail) ? 'unknown' : /stale/i.test(row.detail) ? 'stale' : 'vulnerable',
  }));

  const migrationTasks: PqcMigrationStep[] = (snapshot.inventory || [])
    .filter((row) => /migration|remediation|pqc|quantum/i.test(`${row.domain} ${row.title} ${row.detail}`))
    .slice(0, 12)
    .map((row) => ({
      id: row.id,
      asset: row.subject || row.title || 'Migration subject',
      stage: row.compliant ? 'monitor' : 'prioritize',
      targetAlgorithm: /ml-kem|ml-dsa|hybrid|pqc/i.test(row.detail || '') ? row.detail || 'PQC hybrid' : 'PQC target pending',
      deadline: displayDate(row.timestamp),
      status: row.compliant ? 'completed' : 'in_progress',
    }));

  const compliance: ComplianceControl[] = (snapshot.regulatoryRows || []).slice(0, 16).map((row) => ({
    framework: row.framework,
    controlId: row.control,
    name: `${row.framework} ${row.control}`,
    status: row.coverage >= 90 ? 'implemented' : row.coverage > 0 ? 'partial' : 'needs_review',
    evidenceStatus: row.findings > 0 ? 'missing' : row.latestSeen ? 'attached' : 'expired',
  }));

  const vendors: VendorReadiness[] = (snapshot.sourceDistribution || [])
    .filter((row) => /connector|vendor|supplier|cloud|account/i.test(row.label))
    .slice(0, 8)
    .map((row) => ({
      name: row.label,
      product: 'Connected telemetry source',
      pqcRoadmap: row.count > 0,
      hybridSupport: row.count > 0,
      targetDate: 'Telemetry driven',
      riskRating: row.count > 0 ? 'low' : 'high',
      status: row.count > 0 ? 'roadmap_confirmed' : 'unknown',
    }));

  const workflows: GovernanceWorkflow[] = (snapshot.recommendations || []).slice(0, 12).map((row) => ({
    id: row.id,
    type: row.title,
    assignee: 'Governance owner',
    priority: workflowPriority(row.impact),
    status: row.count > 0 ? 'open' : 'completed',
    dueDate: displayDate(snapshot.latestActivityAt),
  }));

  const evidence: GovernanceEvidence[] = (snapshot.auditRows || []).slice(0, 12).map((row) => ({
    id: row.id,
    name: row.event,
    type: row.source,
    uploadedAt: displayDate(row.timestamp),
    owner: row.actor,
  }));

  return { kpis, inventory, ownership, pkiDebt, migrationTasks, compliance, vendors, workflows, evidence };
}

export function useQuantumGovernance() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [loading, setLoading] = useState(true);
  const [snapshot, setSnapshot] = useState<GovernanceSnapshot>(emptySnapshot);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const streamRef = useRef<EventSource | null>(null);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(emptySnapshot);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/v1/dashboard/quantum-governance', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSnapshot(payload.data || emptySnapshot);
    } catch (error) {
      console.error('Quantum governance load failed:', error);
      setSnapshot(emptySnapshot);
    } finally {
      setLoading(false);
    }
  }, [token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 300);
  }, [refresh]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'runtime_crypto_events',
      'scanner_evidence',
      'scanner_alerts',
      'pqc_scan_sessions',
      'pqc_scan_results',
      'vulnerabilities',
      'crypto_inventory',
      'crypto_exposures',
      'certificates',
      'generated_keys',
      'scanner_agents',
      'scanner_agent_policies',
      'connector_accounts',
      'agent_heartbeats',
      'vault_files',
      'vault_audit_logs',
      'audit_logs',
      'compliance_evidence',
      'migration_jobs',
      'security_events',
      'user_security_events',
      'auth_events',
      'qrng_events',
    ];
    const channels = tables.map((table) => supabase
      .channel(`quantum-governance-${table}`)
      .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
      .subscribe());
    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [queueRefresh, user]);

  useEffect(() => {
    if (!token) return;
    const stream = new EventSource(`/api/v1/dashboard/quantum-governance/stream?token=${encodeURIComponent(token)}`);
    streamRef.current = stream;
    stream.addEventListener('quantum-governance-connected', queueRefresh);
    stream.addEventListener('quantum-governance-update', queueRefresh);
    stream.onerror = () => queueRefresh();
    return () => {
      stream.close();
      streamRef.current = null;
    };
  }, [queueRefresh, token]);

  useEffect(() => () => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    streamRef.current?.close();
  }, []);

  return { loading, refresh, ...adaptSnapshot(snapshot) };
}
