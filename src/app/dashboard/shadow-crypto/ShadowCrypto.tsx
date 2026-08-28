'use client';

import { useMemo, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircuitBoard,
  Eye,
  FileCode2,
  Fingerprint,
  GitBranch,
  KeyRound,
  Layers,
  LockKeyhole,
  Network,
  Radar,
  RefreshCw,
  Route,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TriangleAlert,
  UnlockKeyhole,
} from 'lucide-react';
import { useScannerIntelligence, type ScannerFinding } from '@/lib/scanner/use-scanner-intelligence';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import {
  DiscoveryPage,
  DiscoveryHeader,
  DiscoveryMetric,
  DiscoveryEmpty,
  StaleAssessmentBanner,
  TruncationNote,
  panelClass,
  subtlePanelClass,
} from '../_components/discovery/shell';

type Metric = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: 'gold' | 'red' | 'orange' | 'green';
};

type Finding = {
  asset: string;
  owner: string;
  source: string;
  implementation: string;
  evidence: string;
  severity: 'Critical' | 'High' | 'Medium';
  policy: 'Undocumented' | 'Non-Compliant' | 'Exception Required';
  action: string;
};

type FindingFilter = 'All' | 'Non-Compliant' | 'Undocumented' | 'Critical';

type Source = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  coverage: number;
};

type PolicyControl = {
  control: string;
  expected: string;
  drift: string;
  status: 'Enforced' | 'Gap' | 'Review';
};

/* Discovery-suite surface — identical to CBOM Explorer. */
const GLASS_PANEL_CLASSES = panelClass;

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(Math.max(0, Number(value) || 0));
}

function formatPercent(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function percentOf(value: number, total: number) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

function normalizeDisplayText(value: unknown, fallback: string) {
  const text = String(value ?? '').trim();
  if (!text) return fallback;

  return text
    .replace(/\u00e2\u20ac\u201d|\u00e2\u20ac\u201c|[\u2013\u2014]/g, ' - ')
    .replace(/\u00e2\u20ac\u2122/g, "'")
    .replace(/\u00e2\u20ac\u0153|\u00e2\u20ac\u009d/g, '"')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function normalizeSeverity(finding: ScannerFinding): Finding['severity'] {
  const threat = String(finding.threatLevel || finding.severity || '').toUpperCase();
  if (threat === 'CRITICAL') return 'Critical';
  if (threat === 'HIGH') return 'High';
  return 'Medium';
}

function normalizePolicy(finding: ScannerFinding): Finding['policy'] {
  const status = `${finding.status || ''} ${finding.evidence || ''}`.toLowerCase();
  if (status.includes('unknown') || status.includes('undocumented') || status.includes('manual')) return 'Undocumented';
  if (status.includes('exception') || normalizeSeverity(finding) === 'Medium') return 'Exception Required';
  return 'Non-Compliant';
}

function uniqueAlgorithms(entries: any[], matcher: (entry: any) => boolean) {
  const algorithms = Array.from(new Set(entries.filter(matcher).map((entry) => entry.algorithm).filter(Boolean)));
  return algorithms.length > 0 ? algorithms.slice(0, 4).join(', ') : 'No drift detected';
}

const playbooks = [
  { label: 'Open policy exception', detail: 'Route business-approved temporary crypto to governance.' },
  { label: 'Create remediation task', detail: 'Send finding to migration planner with PQC replacement.' },
  { label: 'Quarantine implementation', detail: 'Block unknown algorithm path from production promotion.' },
  { label: 'Refresh CBOM evidence', detail: 'Resync scanner results, source evidence, and exposure map.' },
];

const FINDING_FILTERS: FindingFilter[] = ['All', 'Non-Compliant', 'Undocumented', 'Critical'];

/** Map the page's semantic tones onto the shared discovery metric tones. */
function metricTone(tone: Metric['tone']): 'amber' | 'red' | 'green' | 'cyan' {
  if (tone === 'red') return 'red';
  if (tone === 'orange') return 'amber';
  if (tone === 'green') return 'green';
  return 'amber';
}


function severityClasses(severity: Finding['severity']) {
  switch (severity) {
    case 'Critical':
      return 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300';
    case 'High':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-600 dark:text-orange-300';
    default:
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:border-amber-400/30 dark:text-amber-300';
  }
}

function policyClasses(policy: Finding['policy']) {
  switch (policy) {
    case 'Non-Compliant':
      return 'text-red-600 dark:text-red-300';
    case 'Undocumented':
      return 'text-[var(--qg-amber)]';
    default:
      return 'text-amber-700 dark:text-amber-300';
  }
}

function controlStatusClasses(status: PolicyControl['status']) {
  switch (status) {
    case 'Gap':
      return 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300';
    case 'Review':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:border-amber-400/30 dark:text-amber-300';
    default:
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300';
  }
}

function SectionTitle({ icon: Icon, children }: { icon: LucideIcon; children: string }) {
  return (
    <h2 className="relative z-10 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-[var(--qg-dashboard-text-soft)]">
      <Icon className="h-4 w-4 text-[var(--qg-amber)]" />
      {children}
    </h2>
  );
}

export default function ShadowCrypto() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();
  const [activeFindingFilter, setActiveFindingFilter] = useState<FindingFilter>('All');
  const vulnerableEntries = useMemo(() => data.cbom.entries.filter((entry: any) => entry.isVulnerable), [data.cbom.entries]);
  const totalEvidence = Math.max(1, data.findings.length + data.cbom.stats.totalComponents + data.telemetry.length);
  const correlatedPercent = data.findings.length > 0
    ? percentOf(Math.min(data.findings.length, data.cbom.stats.totalComponents), data.findings.length)
    : percentOf(data.cbom.stats.totalComponents, Math.max(1, data.summary.totalComponents));

  const metrics = useMemo<Metric[]>(() => [
    {
      label: 'Shadow Implementations',
      value: formatNumber(data.summary.vulnerableComponents),
      detail: 'Undocumented or vulnerable crypto paths',
      icon: Eye,
      tone: data.summary.vulnerableComponents > 0 ? 'gold' : 'green',
    },
    {
      label: 'Policy Violations',
      value: formatNumber(data.severityCounts.critical + data.severityCounts.high + data.severityCounts.medium),
      detail: 'Non-compliant primitives',
      icon: ShieldAlert,
      tone: data.severityCounts.critical + data.severityCounts.high > 0 ? 'red' : 'green',
    },
    {
      label: 'Quantum Exposure',
      value: formatNumber(data.summary.vulnerableAssets),
      detail: 'Harvest-now targets',
      icon: UnlockKeyhole,
      tone: data.summary.vulnerableAssets > 0 ? 'orange' : 'green',
    },
    {
      label: 'Auto Correlated',
      value: formatPercent(correlatedPercent),
      detail: 'Matched to CBOM evidence',
      icon: CheckCircle2,
      tone: correlatedPercent >= 80 ? 'green' : 'gold',
    },
  ], [correlatedPercent, data]);

  const findings = useMemo<Finding[]>(() => {
    const priorityFindings = data.findings.filter((finding) => {
      const threat = String(finding.threatLevel || '').toUpperCase();
      const status = String(finding.status || '').toLowerCase();
      return ['CRITICAL', 'HIGH', 'MEDIUM'].includes(threat) || status.includes('vulner') || status.includes('deprecated') || status.includes('misconfigured');
    });

    const fromFindings = priorityFindings.map((finding) => ({
      asset: normalizeDisplayText(finding.location || finding.target || finding.category, 'Unknown asset'),
      owner: 'Tenant scope',
      source: normalizeDisplayText(finding.source, 'scanner telemetry'),
      implementation: normalizeDisplayText(finding.algorithm || finding.category, 'Unknown cryptographic implementation'),
      evidence: normalizeDisplayText(finding.evidence, 'Stored scanner evidence'),
      severity: normalizeSeverity(finding),
      policy: normalizePolicy(finding),
      action: normalizeDisplayText(finding.recommendation, 'Create remediation task'),
    }));

    const fromCbom = vulnerableEntries.map((entry: any) => ({
      asset: normalizeDisplayText(entry.sourceAsset || entry.component, 'Unknown asset'),
      owner: 'Tenant scope',
      source: normalizeDisplayText(entry.detectionMethod, 'CBOM inventory'),
      implementation: normalizeDisplayText(entry.algorithm || entry.component, 'Unknown cryptographic implementation'),
      evidence: normalizeDisplayText(entry.evidence, 'Stored CBOM evidence'),
      severity: entry.riskSeverity === 'critical' ? 'Critical' : entry.riskSeverity === 'high' ? 'High' : 'Medium',
      policy: entry.status === 'Unknown / requires manual review' ? 'Undocumented' : 'Non-Compliant',
      action: normalizeDisplayText(entry.recommendation || entry.pqcReplacement, 'Schedule PQC migration'),
    } as Finding));

    /*
     * The FULL deduplicated set. It was previously capped at 20 here, before
     * the filter ran — so "Critical" showed only the criticals that happened to
     * fall inside the first twenty rows, and its count was wrong for any estate
     * with more than twenty shadow findings. Filtering must see everything;
     * only the RENDER is bounded, and that bound is disclosed.
     */
    return [...fromFindings, ...fromCbom]
      .filter((finding, index, all) => index === all.findIndex((item) => `${item.asset}:${item.implementation}:${item.evidence}` === `${finding.asset}:${finding.implementation}:${finding.evidence}`));
  }, [data.findings, vulnerableEntries]);

  const filteredFindings = useMemo(() => {
    if (activeFindingFilter === 'All') return findings;
    if (activeFindingFilter === 'Critical') return findings.filter((finding) => finding.severity === 'Critical');
    return findings.filter((finding) => finding.policy === activeFindingFilter);
  }, [activeFindingFilter, findings]);

  /** Rows actually rendered. The remainder is disclosed beneath the table. */
  const FINDINGS_PAGE = 20;
  const visibleFindings = useMemo(() => filteredFindings.slice(0, FINDINGS_PAGE), [filteredFindings]);

  /** Per-filter counts, computed over the FULL set so every tab is truthful. */
  const filterCounts = useMemo(() => ({
    All: findings.length,
    Critical: findings.filter((f) => f.severity === 'Critical').length,
    Undocumented: findings.filter((f) => f.policy === 'Undocumented').length,
    'Non-Compliant': findings.filter((f) => f.policy === 'Non-Compliant').length,
  }) as Record<FindingFilter, number>, [findings]);

  /** Newest scan behind this view — the page's honest measurement age. */
  const measuredAt = data.generatedAt || null;

  const hasScanEvidence = data.mode !== 'none' && (
    data.summary.totalComponents > 0 ||
    data.summary.totalAssets > 0 ||
    data.findings.length > 0 ||
    data.cbom.entries.length > 0 ||
    data.history.history.length > 0
  );

  const sources = useMemo<Source[]>(() => [
    {
      label: 'Agent Evidence',
      value: formatNumber(data.history.history.reduce((sum: number, entry: any) => sum + (entry.moduleStates?.length || 0), 0)),
      detail: 'scanner modules and validated evidence',
      icon: ScanSearch,
      coverage: percentOf(data.history.history.length, Math.max(1, data.summary.completedScans)),
    },
    {
      label: 'CBOM Inventory',
      value: formatNumber(data.cbom.stats.totalComponents),
      detail: 'known cryptographic components',
      icon: Layers,
      coverage: percentOf(data.cbom.stats.totalComponents, totalEvidence),
    },
    {
      label: 'Runtime Telemetry',
      value: formatNumber(data.runtime.operations),
      detail: 'live handshakes and scanner events',
      icon: Activity,
      coverage: percentOf(data.telemetry.length, totalEvidence),
    },
    {
      label: 'Code Patterns',
      value: formatNumber(data.findings.filter((finding) => String(finding.source || finding.evidence || '').toLowerCase().includes('code')).length),
      detail: 'source evidence and embedded crypto calls',
      icon: FileCode2,
      coverage: percentOf(data.findings.filter((finding) => String(finding.source || finding.evidence || '').toLowerCase().includes('code')).length, totalEvidence),
    },
  ], [data, totalEvidence]);

  const policyControls = useMemo<PolicyControl[]>(() => {
    const entries = data.cbom.entries || [];
    const gapStatus = (drift: string): PolicyControl['status'] => drift === 'No drift detected' ? 'Enforced' : 'Gap';
    const reviewStatus = (drift: string): PolicyControl['status'] => drift === 'No drift detected' ? 'Enforced' : 'Review';
    const signatures = uniqueAlgorithms(entries, (entry) => /rsa|ecdsa|dsa/i.test(String(entry.algorithm || '')) && entry.isVulnerable);
    const keyExchange = uniqueAlgorithms(entries, (entry) => /dh|ecdh|ecdhe|rsa/i.test(String(entry.algorithm || entry.type || '')) && entry.isVulnerable);
    const symmetric = uniqueAlgorithms(entries, (entry) => /cbc|des|rc4|aes-128/i.test(String(entry.algorithm || '')) && entry.isVulnerable);
    const entropy = data.findings.some((finding) => /entropy|random|rng/i.test(`${finding.evidence || ''} ${finding.category || ''}`)) ? 'Weak entropy evidence present' : 'No drift detected';
    const certificates = uniqueAlgorithms(entries, (entry) => String(entry.type || '').toLowerCase().includes('certificate') && entry.isVulnerable);
    return [
      { control: 'Approved signatures', expected: 'ML-DSA-44 or ML-DSA-65', drift: signatures, status: gapStatus(signatures) },
      { control: 'Key exchange', expected: 'ML-KEM-768 hybrid', drift: keyExchange, status: gapStatus(keyExchange) },
      { control: 'Symmetric encryption', expected: 'AES-256-GCM', drift: symmetric, status: reviewStatus(symmetric) },
      { control: 'Entropy sources', expected: 'crypto-safe RNG only', drift: entropy, status: entropy === 'No drift detected' ? 'Enforced' : 'Gap' },
      { control: 'Certificate trust', expected: 'PQC-ready certificate lifecycle', drift: certificates, status: reviewStatus(certificates) },
      { control: 'Evidence lineage', expected: 'CBOM linked', drift: `${formatPercent(correlatedPercent)} linked`, status: correlatedPercent >= 80 ? 'Enforced' : 'Review' },
    ];
  }, [correlatedPercent, data.cbom.entries, data.findings]);

  const radarItems = useMemo(() => {
    const entries = data.cbom.entries || [];
    const total = Math.max(1, entries.length);
    return [
      { label: 'Hardcoded keys', value: percentOf(entries.filter((entry: any) => /key/i.test(String(entry.type || entry.algorithm || '')) && entry.isVulnerable).length, total), icon: KeyRound },
      { label: 'Deprecated libraries', value: percentOf(entries.filter((entry: any) => /library|deprecated/i.test(String(entry.type || entry.status || '')) && entry.isVulnerable).length, total), icon: TerminalSquare },
      { label: 'Protocol fallback', value: percentOf(entries.filter((entry: any) => /protocol|tls|ssl|dh/i.test(String(entry.type || entry.algorithm || '')) && entry.isVulnerable).length, total), icon: Route },
      { label: 'Weak entropy', value: percentOf(data.findings.filter((finding) => /entropy|random|rng/i.test(`${finding.evidence || ''} ${finding.category || ''}`)).length, Math.max(1, data.findings.length)), icon: Fingerprint },
      { label: 'Unmanaged certificates', value: percentOf(entries.filter((entry: any) => /certificate/i.test(String(entry.type || '')) && !entry.isQuantumSafe).length, total), icon: LockKeyhole },
    ];
  }, [data.cbom.entries, data.findings]);

  return (
    <DiscoveryPage>
      <WorkflowRail activeStage="discovery" tone="adaptive" />
      <DiscoveryHeader
        title="Shadow Crypto"
        subtitle="Undocumented and non-compliant cryptographic implementations, correlated across scanner evidence, CBOM inventory, runtime telemetry and policy drift."
        connected={connected}
        measuredAt={measuredAt}
        reconciledNote="Derived from the same scanner intelligence as CBOM"
        actions={
          <>
            <a
              href="/dashboard/scanner"
              className="inline-flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs font-bold text-blue-300 transition hover:border-blue-400/60"
            >
              <ScanSearch className="h-4 w-4" />
              Launch Sweep
            </a>
            <button
              type="button"
              onClick={refresh}
              className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-4 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)] transition hover:border-[var(--qg-amber)]/45"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              {connected ? 'Sync Evidence' : 'Load Evidence'}
            </button>
          </>
        }
      />

      <StaleAssessmentBanner measuredAt={measuredAt} />

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm font-semibold text-red-600 dark:text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => {
          const Icon = metric.icon;

          return (
            <DiscoveryMetric
              key={metric.label}
              label={metric.label}
              value={metric.value}
              detail={metric.detail}
              icon={Icon}
              tone={metricTone(metric.tone)}
            />
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-6">
        <section className={`${GLASS_PANEL_CLASSES} selection:bg-transparent selection:text-current p-6`}>
          <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <SectionTitle icon={ShieldAlert}>Priority Shadow Findings</SectionTitle>
            <div className="flex flex-wrap gap-2">
              {FINDING_FILTERS.map((filter) => (
                <button
                  key={filter}
                  type="button"
                  onClick={() => setActiveFindingFilter(filter)}
                  className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition ${
                    activeFindingFilter === filter
                      ? 'border-[var(--qg-amber)]/50 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
                      : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)] hover:border-[var(--qg-amber)]/35 hover:text-[var(--qg-dashboard-text)]'
                  }`}
                >
                  {filter}
                  {/* Counted over the FULL finding set, so a tab never advertises
                      a number the truncated table cannot account for. */}
                  <span className="font-mono opacity-70">{filterCounts[filter] ?? 0}</span>
                </button>
              ))}
            </div>
          </div>

          <div className={`relative z-10 mt-5 overflow-x-auto ${subtlePanelClass}`}>
            <table className="w-full min-w-[980px] border-collapse text-left">
              <thead>
                <tr className="border-b border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)]">
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Asset</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Source</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Implementation</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Severity</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Policy</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--qg-card-border)]">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center">
                      {loading ? (
                        <span className="text-xs font-black uppercase tracking-widest text-[var(--qg-text-muted)]">Loading scanner evidence…</span>
                      ) : !hasScanEvidence ? (
                        <div className="mx-auto flex max-w-md flex-col items-center gap-3">
                          <ScanSearch className="h-8 w-8 text-[var(--qg-amber)]/70" />
                          <div className="text-sm font-black uppercase tracking-widest text-[var(--qg-dashboard-text-soft)]">No scan evidence yet</div>
                          <p className="text-xs font-medium normal-case tracking-normal text-[var(--qg-text-muted)]">
                            Shadow Crypto correlates discovered cryptography from scanner runs, CBOM inventory, and runtime telemetry. Run your first scan to start surfacing undocumented or non-compliant crypto.
                          </p>
                          <a href="/dashboard/scanner" className="mt-1 inline-flex items-center gap-2 rounded-lg border border-[var(--qg-amber)]/40 bg-[var(--qg-amber)]/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-amber)] transition hover:border-[var(--qg-amber)]/70 hover:bg-[var(--qg-amber)]/20">
                            <ScanSearch className="h-3.5 w-3.5" /> Run a Scan
                          </a>
                        </div>
                      ) : activeFindingFilter === 'All' ? (
                        <span className="text-xs font-black uppercase tracking-widest text-emerald-500 dark:text-emerald-300/70">No shadow crypto detected — all discovered cryptography is documented and policy-compliant.</span>
                      ) : (
                        <span className="text-xs font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{`No ${activeFindingFilter.toLowerCase()} shadow crypto findings match this tenant scan.`}</span>
                      )}
                    </td>
                  </tr>
                ) : visibleFindings.map((finding) => (
                  <tr key={`${finding.asset}-${finding.implementation}-${finding.evidence}`} className="group/row border-b border-[var(--qg-card-border)] transition last:border-0 hover:bg-[var(--qg-card-bg)]">
                    <td className="p-4">
                      <div className="font-bold text-[var(--qg-dashboard-text)] group-hover/row:text-[var(--qg-amber)]">{finding.asset}</div>
                      <div className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--qg-text-muted)]">{finding.owner}</div>
                    </td>
                    <td className="p-4 text-xs font-semibold text-[var(--qg-dashboard-text-soft)]">{finding.source}</td>
                    <td className="p-4">
                      <div className="text-xs font-bold text-[var(--qg-dashboard-text)]">{finding.implementation}</div>
                      <div className="mt-1 max-w-[270px] truncate font-mono text-[10px] text-[var(--qg-text-muted)]">{finding.evidence}</div>
                    </td>
                    <td className="p-4">
                      <span className={`inline-flex rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider ${severityClasses(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className={`p-4 text-xs font-black ${policyClasses(finding.policy)}`}>{finding.policy}</td>
                    <td className="p-4">
                      <button className="inline-flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-amber)] transition hover:text-[var(--qg-dashboard-text)]">
                        {finding.action}
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <TruncationNote
              shown={visibleFindings.length}
              total={filteredFindings.length}
              noun={activeFindingFilter === 'All' ? 'shadow findings' : `${activeFindingFilter.toLowerCase()} shadow findings`}
              rank="highest-severity"
              to="/dashboard/cbom"
            />
          </div>
        </section>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={GitBranch}>Evidence Correlation</SectionTitle>
          <div className="relative z-10 mt-5 space-y-4">
            {sources.map((source) => {
              const Icon = source.icon;

              return (
                <div key={source.label} className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex min-w-0 items-center gap-3">
                      <Icon className="h-4 w-4 shrink-0 text-[var(--qg-amber)]" />
                      <div>
                        <div className="text-xs font-black uppercase tracking-wider text-[var(--qg-dashboard-text)]">{source.label}</div>
                        <div className="mt-1 text-[10px] font-semibold text-[var(--qg-text-muted)]">{source.detail}</div>
                      </div>
                    </div>
                    <div className="text-sm font-black text-[var(--qg-amber)]">{source.value}</div>
                  </div>
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full bg-[var(--qg-amber)]" style={{ width: `${source.coverage}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={Network}>Detection Surface</SectionTitle>
          <div className="relative z-10 mt-6 space-y-4">
            {radarItems.map((item) => {
              const Icon = item.icon;

              return (
                <div key={item.label} className="grid grid-cols-[150px_1fr_42px] items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-[var(--qg-amber)]" />
                    <span className="text-xs font-semibold text-white/60">{item.label}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-gold/45 to-gold shadow-[0_0_10px_rgba(255,211,107,0.5)]"
                      style={{ width: `${item.value}%` }}
                    />
                  </div>
                  <div className="text-right font-mono text-xs font-black text-[var(--qg-dashboard-text-soft)]">{item.value}%</div>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_390px]">
        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={ShieldCheck}>Policy Alignment Matrix</SectionTitle>
          <div className="relative z-10 mt-5 grid gap-3 md:grid-cols-2">
            {policyControls.map((control) => (
              <div key={control.control} className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-black text-[var(--qg-dashboard-text)]">{control.control}</div>
                    <div className="mt-2 text-xs font-semibold text-[var(--qg-text-muted)]">Expected: {control.expected}</div>
                    <div className="mt-1 text-xs font-semibold text-[var(--qg-text-muted)]">Observed: {control.drift}</div>
                  </div>
                  <span className={`shrink-0 rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider ${controlStatusClasses(control.status)}`}>
                    {control.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={CircuitBoard}>Response Playbooks</SectionTitle>
          <div className="relative z-10 mt-5 space-y-3">
            {playbooks.map((playbook, index) => (
              <button
                key={playbook.label}
                className="w-full rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-4 text-left transition hover:border-[var(--qg-amber)]/30 hover:bg-[var(--qg-card-bg)]"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[10px] font-black text-[var(--qg-amber)]">
                    {index + 1}
                  </div>
                  <div>
                    <div className="text-sm font-black text-[var(--qg-dashboard-text)]">{playbook.label}</div>
                    <div className="mt-1 text-xs font-semibold leading-relaxed text-[var(--qg-text-muted)]">{playbook.detail}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </section>
      </div>
    </DiscoveryPage>
  );
}
