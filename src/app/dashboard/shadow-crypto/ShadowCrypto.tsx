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

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-xl border border-slate-200/80 bg-white/72 text-slate-950 shadow-[inset_0_1px_0_rgba(255,255,255,0.92),0_18px_45px_rgba(15,23,42,0.08)] backdrop-blur-xl transition-all duration-500 hover:-translate-y-1 hover:border-cyan-300/80 hover:bg-white/88 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.95),0_22px_55px_rgba(15,23,42,0.12),0_0_42px_rgba(0,197,235,0.18)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-cyan-300/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(0,197,235,0.55)] group-hover:before:via-cyan-300 after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-cyan-300/12 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-cyan-300/20 group-hover:after:blur-[36px] dark:border-[#FFD36B]/20 dark:bg-[#0f1428]/45 dark:text-white dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] dark:hover:border-[#FFD36B]/70 dark:hover:bg-[#0f1428]/65 dark:hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] dark:before:via-[#FFF4C0]/70 dark:group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] dark:group-hover:before:via-[#FFF4C0] dark:after:bg-[#FFD36B]/10 dark:group-hover:after:bg-[#FFD36B]/25';

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

function toneClasses(tone: Metric['tone']) {
  switch (tone) {
    case 'red':
      return 'border-red-500/30 bg-red-500/10 text-red-600 shadow-[0_0_24px_rgba(248,113,113,0.14)] dark:border-red-400/30 dark:text-red-300';
    case 'orange':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-600 shadow-[0_0_24px_rgba(251,146,60,0.14)] dark:border-orange-400/30 dark:text-orange-300';
    case 'green':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 shadow-[0_0_24px_rgba(52,211,153,0.14)] dark:border-emerald-400/30 dark:text-emerald-300';
    default:
      return 'border-gold/30 bg-gold/10 text-gold shadow-[0_0_24px_rgba(255,211,107,0.16)]';
  }
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
      return 'text-gold';
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
    <h2 className="relative z-10 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-slate-600 dark:text-white/60">
      <Icon className="h-4 w-4 text-gold" />
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

    return [...fromFindings, ...fromCbom]
      .filter((finding, index, all) => index === all.findIndex((item) => `${item.asset}:${item.implementation}:${item.evidence}` === `${finding.asset}:${finding.implementation}:${finding.evidence}`))
      .slice(0, 20);
  }, [data.findings, vulnerableEntries]);

  const filteredFindings = useMemo(() => {
    if (activeFindingFilter === 'All') return findings;
    if (activeFindingFilter === 'Critical') return findings.filter((finding) => finding.severity === 'Critical');
    return findings.filter((finding) => finding.policy === activeFindingFilter);
  }, [activeFindingFilter, findings]);

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
    <div className="animate-in space-y-6 p-4 text-slate-950 fade-in duration-700 dark:text-white lg:p-8">
      <header className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-3">
            <div className="rounded bg-gold/10 border border-gold/20 p-2">
              <Radar className="h-6 w-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
            </div>
            <h1 className="text-3xl font-black uppercase leading-none tracking-tight text-slate-950 dark:text-white">
              Shadow <span className="text-gold">Crypto</span>
            </h1>
          </div>
          <p className="max-w-3xl text-sm font-medium text-slate-600 dark:text-white/50">
            Identify undocumented or non-compliant cryptographic implementations across scanner evidence, CBOM inventory, runtime telemetry, and policy drift.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <a href="/dashboard/scanner" className="flex items-center gap-2 rounded-lg border border-gold/30 bg-gold/10 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70 hover:bg-gold/20">
            <ScanSearch className="h-4 w-4" />
            Launch Sweep
          </a>
          <button onClick={refresh} className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white/70 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-slate-600 transition hover:border-cyan-300 hover:text-slate-950 dark:border-white/10 dark:bg-white/5 dark:text-white/60 dark:hover:border-gold/30 dark:hover:text-white">
            <RefreshCw className={`h-4 w-4 text-gold ${loading ? 'animate-spin' : ''}`} />
            {connected ? 'Sync Evidence' : 'Load Evidence'}
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-600 dark:text-red-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => {
          const Icon = metric.icon;

          return (
            <section key={metric.label} className={`${GLASS_PANEL_CLASSES} p-5`}>
              <div className="relative z-10 flex items-center justify-between gap-4">
                <div>
                  <span className="block text-[9px] font-bold uppercase tracking-widest text-slate-500 dark:text-white/40">{metric.label}</span>
                  <span className="mt-3 block text-3xl font-black leading-none text-slate-950 dark:text-white">{metric.value}</span>
                  <span className="mt-3 block text-[10px] font-black uppercase tracking-wider text-slate-500 dark:text-white/35">{metric.detail}</span>
                </div>
                <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border ${toneClasses(metric.tone)}`}>
                  <Icon className="h-7 w-7" />
                </div>
              </div>
            </section>
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
                  className={`rounded-lg border px-3 py-2 text-[10px] font-black uppercase tracking-wider transition ${
                    activeFindingFilter === filter
                      ? 'border-gold/50 bg-gold/10 text-gold'
                      : 'border-slate-200 bg-white/70 text-slate-600 hover:border-cyan-300 hover:text-slate-950 dark:border-white/10 dark:bg-white/[0.03] dark:text-white/40 dark:hover:border-gold/30 dark:hover:text-white/70'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>

          <div className="relative z-10 mt-5 overflow-x-auto rounded-xl border border-slate-200/80 bg-white/75 selection:bg-transparent selection:text-current dark:border-white/5 dark:bg-transparent">
            <table className="w-full min-w-[980px] border-collapse text-left">
              <thead>
                <tr className="border-b border-slate-200/80 bg-slate-50/80 dark:border-gold/15 dark:bg-gold/[0.03]">
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Asset</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Source</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Implementation</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Severity</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Policy</th>
                  <th className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:text-white/40">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70 dark:divide-white/5">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-10 text-center">
                      {loading ? (
                        <span className="text-xs font-black uppercase tracking-widest text-slate-500 dark:text-white/30">Loading scanner evidence…</span>
                      ) : !hasScanEvidence ? (
                        <div className="mx-auto flex max-w-md flex-col items-center gap-3">
                          <ScanSearch className="h-8 w-8 text-gold/70" />
                          <div className="text-sm font-black uppercase tracking-widest text-slate-700 dark:text-white/60">No scan evidence yet</div>
                          <p className="text-xs font-medium normal-case tracking-normal text-slate-500 dark:text-white/40">
                            Shadow Crypto correlates discovered cryptography from scanner runs, CBOM inventory, and runtime telemetry. Run your first scan to start surfacing undocumented or non-compliant crypto.
                          </p>
                          <a href="/dashboard/scanner" className="mt-1 inline-flex items-center gap-2 rounded-lg border border-gold/40 bg-gold/10 px-4 py-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70 hover:bg-gold/20">
                            <ScanSearch className="h-3.5 w-3.5" /> Run a Scan
                          </a>
                        </div>
                      ) : activeFindingFilter === 'All' ? (
                        <span className="text-xs font-black uppercase tracking-widest text-emerald-500 dark:text-emerald-300/70">No shadow crypto detected — all discovered cryptography is documented and policy-compliant.</span>
                      ) : (
                        <span className="text-xs font-black uppercase tracking-widest text-slate-500 dark:text-white/30">{`No ${activeFindingFilter.toLowerCase()} shadow crypto findings match this tenant scan.`}</span>
                      )}
                    </td>
                  </tr>
                ) : filteredFindings.map((finding) => (
                  <tr key={`${finding.asset}-${finding.implementation}-${finding.evidence}`} className="group/row bg-white/45 transition hover:bg-cyan-50/75 dark:bg-transparent dark:hover:bg-gold/[0.04]">
                    <td className="p-4">
                      <div className="font-bold text-slate-950 group-hover/row:text-gold dark:text-white/85">{finding.asset}</div>
                      <div className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-white/30">{finding.owner}</div>
                    </td>
                    <td className="p-4 text-xs font-semibold text-slate-600 dark:text-white/55">{finding.source}</td>
                    <td className="p-4">
                      <div className="text-xs font-bold text-slate-800 dark:text-white/75">{finding.implementation}</div>
                      <div className="mt-1 max-w-[270px] truncate font-mono text-[10px] text-slate-500 dark:text-white/35">{finding.evidence}</div>
                    </td>
                    <td className="p-4">
                      <span className={`inline-flex rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider ${severityClasses(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className={`p-4 text-xs font-black ${policyClasses(finding.policy)}`}>{finding.policy}</td>
                    <td className="p-4">
                      <button className="inline-flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:text-slate-950 dark:hover:text-white">
                        {finding.action}
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
                <div key={source.label} className="rounded-lg border border-white/5 bg-white/[0.02] p-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex min-w-0 items-center gap-3">
                      <Icon className="h-4 w-4 shrink-0 text-gold" />
                      <div>
                        <div className="text-xs font-black uppercase tracking-wider text-white/75">{source.label}</div>
                        <div className="mt-1 text-[10px] font-semibold text-white/35">{source.detail}</div>
                      </div>
                    </div>
                    <div className="text-sm font-black text-gold">{source.value}</div>
                  </div>
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full bg-gold shadow-[0_0_10px_rgba(255,211,107,0.7)]" style={{ width: `${source.coverage}%` }} />
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
                    <Icon className="h-4 w-4 text-gold" />
                    <span className="text-xs font-semibold text-white/60">{item.label}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-gold/45 to-gold shadow-[0_0_10px_rgba(255,211,107,0.5)]"
                      style={{ width: `${item.value}%` }}
                    />
                  </div>
                  <div className="text-right font-mono text-xs font-black text-white/55">{item.value}%</div>
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
              <div key={control.control} className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-black text-white/85">{control.control}</div>
                    <div className="mt-2 text-xs font-semibold text-white/40">Expected: {control.expected}</div>
                    <div className="mt-1 text-xs font-semibold text-white/35">Observed: {control.drift}</div>
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
                className="w-full rounded-lg border border-white/5 bg-white/[0.02] p-4 text-left transition hover:border-gold/30 hover:bg-gold/[0.05]"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-gold/30 bg-gold/10 text-[10px] font-black text-gold">
                    {index + 1}
                  </div>
                  <div>
                    <div className="text-sm font-black text-white/85">{playbook.label}</div>
                    <div className="mt-1 text-xs font-semibold leading-relaxed text-white/40">{playbook.detail}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </section>
      </div>

    </div>
  );
}
