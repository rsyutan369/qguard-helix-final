import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Bell,
  CalendarClock,
  ChevronDown,
  CircleHelp,
  Database,
  Download,
  ExternalLink,
  FileArchive,
  Filter,
  Gauge,
  Info,
  Layers,
  LineChart,
  ListFilter,
  Loader2,
  PackagePlus,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  CheckCircle2,
  GitCompareArrows,
  type LucideIcon,
  Zap,
} from 'lucide-react';
import { useScannerIntelligence, type ScannerFinding } from '@/lib/scanner/use-scanner-intelligence';
import { InventoryExportMenu } from '../_components/InventoryExportMenu';
import { useQuantumReadiness, readinessTone } from '@/app/dashboard/quantum-readiness/_shared';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { namesCryptography as sharedNamesCryptography } from '@/lib/scanner/finding-identity';

type CbomEntry = {
  id: string;
  component: string;
  type: string;
  algorithm: string;
  keySize: number | string | null;
  status: string;
  isVulnerable: boolean;
  isQuantumSafe: boolean;
  pqcReplacement: string | null;
  instances: number;
  sourceAsset: string;
  sourceAssetId: string;
  detectionMethod: string;
  lastScannedDate: string;
  riskSeverity: string;
  evidence: string;
  recommendation: string | null;
  metadata: Record<string, unknown>;
};

type TrendPoint = {
  label: string;
  value: number;
};

const TABS = [
  'Overview',
  'Inventory',
  'PQC Readiness',
  'Vulnerabilities',
  'Certificates',
  'Key Management',
  'Reports',
  'History',
] as const;

type CbomTab = (typeof TABS)[number];

const WEAK_ALGORITHMS = new Set(['MD5', 'SHA-1', 'SHA1', 'RSA < 2048', 'RSA-1024', '3DES', 'RC4', 'DES', 'DSA', 'ECDSA', 'ECDH', 'RSA']);

const panelClass =
  'relative overflow-hidden rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] shadow-[var(--qg-panel-shadow)] backdrop-blur-xl transition-all duration-300';

const subtlePanelClass =
  'rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)]';

function numberFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

function percent(value: number, total: number) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 1000) / 10));
}

function formatDate(value?: string | null) {
  if (!value) return 'Awaiting scan';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (date.getFullYear() < 2000) return 'Awaiting scan';
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function shortDate(value?: string | null) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  if (date.getFullYear() < 2000) return 'N/A';
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

function normalizeSeverity(value?: string | null) {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('critical')) return 'Critical';
  if (normalized.includes('high')) return 'High';
  if (normalized.includes('medium') || normalized.includes('moderate')) return 'Medium';
  if (normalized.includes('low')) return 'Low';
  if (normalized.includes('safe')) return 'Low';
  return 'Medium';
}

function riskRank(value?: string | null) {
  const severity = normalizeSeverity(value);
  if (severity === 'Critical') return 4;
  if (severity === 'High') return 3;
  if (severity === 'Medium') return 2;
  if (severity === 'Low') return 1;
  return 0;
}

function riskBadgeClass(value?: string | null) {
  const severity = normalizeSeverity(value);
  if (severity === 'Critical') return 'border-red-500/25 bg-red-500/15 text-red-600 dark:text-red-300';
  if (severity === 'High') return 'border-orange-500/25 bg-orange-500/15 text-orange-600 dark:text-orange-300';
  if (severity === 'Medium') return 'border-amber-500/25 bg-amber-500/15 text-amber-700 dark:text-amber-300';
  return 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300';
}

function readinessBadge(entry: CbomEntry) {
  if (entry.isQuantumSafe) return { label: 'PQC Ready', className: 'border-emerald-500/25 bg-emerald-500/12 text-emerald-600 dark:text-emerald-300' };
  if (entry.isVulnerable) return { label: 'Not PQC Ready', className: 'border-orange-500/25 bg-orange-500/12 text-orange-600 dark:text-orange-300' };
  return { label: 'In Progress', className: 'border-blue-500/25 bg-blue-500/12 text-blue-600 dark:text-blue-300' };
}

function entryKeySize(entry: CbomEntry) {
  const metadata = entry.metadata || {};
  return String(entry.keySize || metadata.keySize || metadata.strength || 'N/A');
}

function entryPurpose(entry: CbomEntry) {
  const metadata = entry.metadata || {};
  return String(metadata.purpose || metadata.service || entry.type || 'Cryptographic service');
}

function assetType(entry: CbomEntry, assets: any[]) {
  const asset = assets.find((item) => item.id === entry.sourceAssetId);
  return String(asset?.type || entry.metadata?.assetType || entry.type || 'Asset');
}

function algorithmLabel(value?: string | null) {
  return String(value || 'Unknown').trim() || 'Unknown';
}

function latestScanAt(history: any[], generatedAt?: string) {
  const latest = history[0];
  const fallback = generatedAt && new Date(generatedAt).getFullYear() >= 2000 ? generatedAt : null;
  return latest?.completedAt || latest?.startedAt || latest?.created_at || fallback;
}

/**
 * Per-scan PQC readiness, measured.
 *
 * This used to plot each scan's Q-Score (100 − riskScore) under the label "PQC
 * Readiness Score" — a different measurement entirely — and, when a scan had no
 * score at all, substituted the CURRENT readiness so an unmeasured run drew a
 * point that looked measured. Both are gone: a scan contributes a point only
 * when it actually recorded a component count, and the value is the share of
 * those components that were PQC-ready.
 */
function buildTrend(history: any[]): TrendPoint[] {
  return [...history]
    .filter((entry: any) => Number(entry?.detectedComponents) > 0)
    .reverse()
    .slice(-8)
    .map((entry: any) => ({
      label: shortDate(entry?.completedAt || entry?.startedAt || entry?.created_at).split(',')[0],
      value: percent(Number(entry.pqcReadyFindings || 0), Number(entry.detectedComponents)),
    }));
}

/**
 * Observation classes whose `algorithm` field names an actual cryptographic
 * algorithm, protocol or suite.
 *
 * The scanner writes BOTH measured cryptography and policy/configuration
 * findings into `crypto_inventory`, and for the latter the `algorithm` column
 * holds the finding TITLE ("No Certificate Pinning", "Regulatory Compliance
 * Gap"). Charting all of it as "Algorithm Distribution" put rule names on an
 * algorithm axis. The scanner labels every row with its own class prefix
 * ("Cipher Suite: …", "Rule (Tls Config): …"), so this reads that label rather
 * than guessing what an algorithm name looks like. An unrecognised class is
 * treated as a posture observation — the safe direction, since the chart then
 * never claims a non-algorithm is an algorithm.
 */
const CRYPTO_OBSERVATION_CLASSES = [
  'cipher suite',
  'symmetric encryption',
  'asymmetric encryption',
  'certificate',
  'certificate signature',
  'signature',
  'key exchange',
  'post-quantum key agreement',
  'protocol',
  'protocol support',
  'hash',
  'mac',
  'kdf',
];

function observationClass(entry: CbomEntry) {
  const component = String(entry.component || '').trim();
  const prefix = component.includes(':') ? component.slice(0, component.indexOf(':')) : component;
  // "Key Exchange (Harvest Now Decrypt Later)" → "key exchange"
  return prefix.replace(/\s*\(.*$/, '').trim().toLowerCase();
}

function namesCryptography(entry: CbomEntry) {
  return CRYPTO_OBSERVATION_CLASSES.includes(observationClass(entry));
}

function buildAlgorithmDistribution(entries: CbomEntry[], limit = 6) {
  const grouped = new Map<string, number>();
  let total = 0;
  entries.forEach((entry) => {
    const count = Number(entry.instances || 1);
    total += count;
    const label = algorithmLabel(entry.algorithm);
    grouped.set(label, (grouped.get(label) || 0) + count);
  });

  const ranked = Array.from(grouped, ([algorithm, count]) => ({ algorithm, count })).sort((a, b) => b.count - a.count);
  const top = ranked.slice(0, limit);
  const remainder = total - top.reduce((sum, item) => sum + item.count, 0);
  // The donut used to show only the top 6 and label their sum "Total", so 12
  // instances stood in for a 66-component estate and every percentage was of
  // the wrong denominator. The remainder is now an explicit slice.
  const slices = remainder > 0
    ? [...top, { algorithm: `Other (${ranked.length - top.length} more)`, count: remainder }]
    : top;

  return { slices, total, distinct: ranked.length };
}

/**
 * Riskiest algorithms across the CBOM inventory.
 *
 * Counts COMPONENTS only. It previously folded the scanner findings list into
 * the same tally, so an algorithm present on one component could be counted
 * several times over — two populations summed into one number.
 */
function buildRiskyAlgorithms(entries: CbomEntry[]) {
  const grouped = new Map<string, { algorithm: string; count: number; severity: string }>();

  entries.forEach((entry) => {
    const weak = WEAK_ALGORITHMS.has(algorithmLabel(entry.algorithm).toUpperCase());
    if (!entry.isVulnerable && !weak && riskRank(entry.riskSeverity) < 2) return;
    const label = algorithmLabel(entry.algorithm);
    const severity = entry.riskSeverity || (weak ? 'High' : 'Medium');
    const existing = grouped.get(label);
    grouped.set(label, {
      algorithm: label,
      count: (existing?.count || 0) + Number(entry.instances || 1),
      severity: !existing || riskRank(severity) > riskRank(existing.severity) ? normalizeSeverity(severity) : existing.severity,
    });
  });

  return Array.from(grouped.values())
    .sort((a, b) => riskRank(b.severity) - riskRank(a.severity) || b.count - a.count)
    .slice(0, 5);
}

/**
 * Screening indicators against control families that depend on cryptographic
 * posture.
 *
 * These are NOT compliance verdicts — the platform's Compliance dashboard owns
 * those, with the control evidence behind them. What this panel can honestly
 * say is which CBOM measurement each family is gated on and whether that
 * measurement currently passes, so every row carries the criterion and the
 * measured basis it was decided from instead of a bare "Compliant".
 */
function buildComplianceRows(totalComponents: number, pqcReady: number, atRiskComponents: number, criticalFindings: number) {
  const readiness = percent(pqcReady, totalComponents);
  const rows = [
    {
      label: 'PCI DSS 4.0',
      criterion: 'No at-risk cryptographic components',
      basis: `${numberFmt(atRiskComponents)} at-risk of ${numberFmt(totalComponents)} components`,
      met: atRiskComponents === 0,
    },
    {
      label: 'NIST SP 800-131A',
      criterion: 'PQC-ready share at or above 90%',
      basis: `${readiness}% PQC-ready (${numberFmt(pqcReady)} of ${numberFmt(totalComponents)})`,
      met: readiness >= 90,
    },
    {
      label: 'ISO/IEC 27001',
      criterion: 'No critical cryptographic findings',
      basis: `${numberFmt(criticalFindings)} critical finding${criticalFindings === 1 ? '' : 's'}`,
      met: criticalFindings === 0,
    },
    {
      label: 'CIS Controls 8',
      criterion: 'No at-risk cryptographic components',
      basis: `${numberFmt(atRiskComponents)} at-risk of ${numberFmt(totalComponents)} components`,
      met: atRiskComponents === 0,
    },
  ];

  return rows.map((row) => ({
    ...row,
    // With no inventory there is nothing to screen against — that is not a pass
    // and not a failure, and must not be rendered as either.
    status: totalComponents === 0 ? 'No evidence' : row.met ? 'Indicator met' : 'Indicator not met',
  }));
}

function distributionGradient(items: { algorithm: string; count: number }[], total: number) {
  const colors = ['#3867d6', '#64748b', '#f59e0b', '#2fbf8f', '#8b5cf6', '#475569'];
  if (!items.length || !total) return 'conic-gradient(rgba(148,163,184,0.2) 0deg 360deg)';
  let cursor = 0;
  const stops = items.map((item, index) => {
    const degrees = (item.count / total) * 360;
    const start = cursor;
    const end = cursor + degrees;
    cursor = end;
    return `${colors[index % colors.length]} ${start}deg ${end}deg`;
  });
  if (cursor < 360) stops.push(`rgba(71,85,105,0.4) ${cursor}deg 360deg`);
  return `conic-gradient(${stops.join(', ')})`;
}

function LineTrendChart({ points }: { points: TrendPoint[] }) {
  const safePoints = points.length ? points : [{ label: 'Current', value: 0 }];
  const width = 360;
  const height = 160;
  const plot = safePoints.map((point, index) => {
    const x = safePoints.length === 1 ? 22 : 22 + (index / (safePoints.length - 1)) * (width - 44);
    const y = height - 24 - (Math.max(0, Math.min(100, point.value)) / 100) * (height - 48);
    return { ...point, x, y };
  });
  const d = plot.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-full w-full" role="img" aria-label="PQC readiness trend">
      {[25, 50, 75, 100].map((tick) => {
        const y = height - 24 - (tick / 100) * (height - 48);
        return (
          <g key={tick}>
            <line x1="22" x2={width - 10} y1={y} y2={y} stroke="var(--qg-card-border)" strokeDasharray="3 4" />
            <text x="0" y={y + 3} fill="var(--qg-text-muted)" fontSize="10">{tick}</text>
          </g>
        );
      })}
      <path d={d} fill="none" stroke="var(--qg-amber)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      {plot.map((point) => (
        <circle key={`${point.label}-${point.x}`} cx={point.x} cy={point.y} r="4" fill="var(--qg-amber)" stroke="var(--qg-dashboard-bg)" strokeWidth="2" />
      ))}
      {plot.map((point, index) => (
        index % Math.max(1, Math.ceil(plot.length / 4)) === 0 || index === plot.length - 1
          ? <text key={`${point.label}-${index}`} x={point.x - 16} y={height - 5} fill="var(--qg-text-muted)" fontSize="10">{point.label}</text>
          : null
      ))}
    </svg>
  );
}

function ReadinessGauge({ score, hasScore = true }: { score: number; hasScore?: boolean }) {
  const safeScore = hasScore ? Math.max(0, Math.min(100, Math.round(score || 0))) : 0;
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (safeScore / 100) * circumference;
  // Unmeasured is not zero: with no readiness score the dial reads "—" rather
  // than a 0 that would be indistinguishable from a measured worst case.
  const band = !hasScore ? 'Awaiting Data' : safeScore >= 80 ? 'Good' : safeScore >= 50 ? 'Fair' : 'Low';

  return (
    <div className="grid gap-4 sm:grid-cols-[130px_1fr] sm:items-center">
      <div className="relative mx-auto h-32 w-32">
        <svg viewBox="0 0 110 110" className="-rotate-90">
          <circle cx="55" cy="55" r="42" fill="none" stroke="rgba(148,163,184,0.14)" strokeWidth="12" />
          <circle
            cx="55"
            cy="55"
            r="42"
            fill="none"
            stroke="var(--qg-amber)"
            strokeLinecap="round"
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-4xl font-black text-[var(--qg-dashboard-text)]">{hasScore ? safeScore : '—'}</div>
            <div className="text-[10px] text-[var(--qg-text-muted)]">/100</div>
            <div className="mt-1 text-xs font-black text-[var(--qg-amber)]">{band}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Discloses that a panel shows only the head of a longer list. Renders nothing
 * when the list fits, so a small estate stays clean.
 */
function TruncationNote({ shown, total, noun, rank }: { shown: number; total: number; noun: string; rank?: string }) {
  if (!Number.isFinite(total) || total <= shown) return null;
  return (
    <div className="pt-1 text-[10px] text-[var(--qg-text-muted)]">
      Showing {rank ? `the ${numberFmt(shown)} ${rank}` : numberFmt(shown)} of {numberFmt(total)} {noun}.
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="grid min-h-[120px] place-items-center rounded-md border border-dashed border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-4 text-center text-xs font-bold text-[var(--qg-text-muted)]">
      {label}
    </div>
  );
}

function DashboardMetric({
  label,
  value,
  detail,
  icon: Icon,
  tone = 'cyan',
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: LucideIcon;
  tone?: 'cyan' | 'amber' | 'green' | 'red' | 'blue';
}) {
  const toneClass =
    tone === 'green' ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300' :
    tone === 'red' ? 'border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-300' :
    tone === 'amber' ? 'border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]' :
    tone === 'blue' ? 'border-blue-500/25 bg-blue-500/10 text-blue-600 dark:text-blue-300' :
    'border-cyan-500/25 bg-cyan-500/10 text-cyan-600 dark:text-cyan-300';

  return (
    <div className={`${subtlePanelClass} p-4`}>
      <div className="flex items-center gap-3">
        <span className={`grid h-10 w-10 place-items-center rounded-md border ${toneClass}`}>
          <Icon className="h-4 w-4" />
        </span>
        <div>
          <div className="text-[10px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">{label}</div>
          <div className="text-xl font-black text-[var(--qg-dashboard-text)]">{typeof value === 'number' ? numberFmt(value) : value}</div>
          <div className="mt-0.5 text-[10px] text-[var(--qg-text-muted)]">{detail}</div>
        </div>
      </div>
    </div>
  );
}

function DashboardAction({
  label,
  detail,
  icon: Icon,
  to,
  onClick,
}: {
  label: string;
  detail: string;
  icon: LucideIcon;
  to?: string;
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className="grid h-9 w-9 place-items-center rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]">
        <Icon className="h-4 w-4" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-black text-[var(--qg-dashboard-text)]">{label}</span>
        <span className="block text-[10px] text-[var(--qg-text-muted)]">{detail}</span>
      </span>
      <ExternalLink className="ml-auto h-3.5 w-3.5 shrink-0 text-[var(--qg-text-muted)]" />
    </>
  );
  const className = 'flex w-full items-center gap-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-3 text-left transition hover:border-[var(--qg-amber)]/45 hover:bg-[var(--qg-card-bg)]';
  if (to) return <Link to={to} className={className}>{content}</Link>;
  return <button type="button" onClick={onClick} className={className}>{content}</button>;
}

function EntryEvidenceList({
  entries,
  assets,
  emptyLabel,
  limit = 6,
}: {
  entries: CbomEntry[];
  assets: any[];
  emptyLabel: string;
  limit?: number;
}) {
  if (entries.length === 0) return <EmptyState label={emptyLabel} />;

  return (
    <div className="space-y-2">
      {entries.slice(0, limit).map((entry) => {
        const readiness = readinessBadge(entry);
        return (
          <div key={entry.id} className={`${subtlePanelClass} p-3`}>
            <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
              <div className="min-w-0">
                <div className="truncate text-sm font-black text-[var(--qg-dashboard-text)]">{entry.component || entry.sourceAsset || 'Cryptographic component'}</div>
                <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">
                  {entry.sourceAsset || 'Unknown asset'} - {assetType(entry, assets)} - {entryPurpose(entry)}
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <span className={`rounded border px-2 py-1 text-[10px] font-black ${readiness.className}`}>{readiness.label}</span>
                <span className={`rounded border px-2 py-1 text-[10px] font-black ${riskBadgeClass(entry.riskSeverity)}`}>{normalizeSeverity(entry.riskSeverity)}</span>
              </div>
            </div>
            <div className="mt-3 grid gap-2 text-[10px] text-[var(--qg-text-muted)] md:grid-cols-3">
              <span className="font-mono">ALG: <strong className="text-[var(--qg-dashboard-text)]">{algorithmLabel(entry.algorithm)}</strong></span>
              <span className="font-mono">KEY: <strong className="text-[var(--qg-dashboard-text)]">{entryKeySize(entry)}</strong></span>
              <span className="font-mono">SEEN: <strong className="text-[var(--qg-dashboard-text)]">{shortDate(entry.lastScannedDate)}</strong></span>
            </div>
            {(entry.recommendation || entry.pqcReplacement) && (
              <div className="mt-3 rounded border border-[var(--qg-amber)]/25 bg-[var(--qg-amber)]/10 px-3 py-2 text-[11px] font-semibold text-[var(--qg-dashboard-text-soft)]">
                {entry.recommendation || `Recommended target: ${entry.pqcReplacement}`}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function FindingEvidenceList({
  findings,
  emptyLabel,
  limit = 6,
}: {
  findings: ScannerFinding[];
  emptyLabel: string;
  limit?: number;
}) {
  if (findings.length === 0) return <EmptyState label={emptyLabel} />;

  return (
    <div className="space-y-2">
      {findings.slice(0, limit).map((finding, index) => (
        <div key={String(finding.id || `${finding.algorithm}-${index}`)} className={`${subtlePanelClass} p-3`}>
          <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
            <div>
              <div className="text-sm font-black text-[var(--qg-dashboard-text)]">{String(finding.algorithm || finding.category || 'Cryptographic finding')}</div>
              <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">{String(finding.location || finding.source || 'scanner evidence')}</div>
            </div>
            <span className={`rounded border px-2 py-1 text-[10px] font-black ${riskBadgeClass(String(finding.threatLevel || finding.status || 'Medium'))}`}>
              {normalizeSeverity(String(finding.threatLevel || finding.status || 'Medium'))}
            </span>
          </div>
          <p className="mt-3 text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)]">
            {String(finding.evidence || finding.recommendation || 'Finding is synchronized from authenticated scanner telemetry.')}
          </p>
        </div>
      ))}
    </div>
  );
}

function FocusedTabDashboard({
  activeTab,
  entries,
  assets,
  findings,
  history,
  telemetry,
  certificateEntries,
  keyEntries,
  vulnerabilityEntries,
  readinessBacklog,
  trendPoints,
  complianceRows,
  totalAssets,
  totalComponents,
  pqcReady,
  inProgress,
  notPqcReady,
  atRiskComponents,
  criticalFindings,
  readinessScore,
  readinessMeasured,
  loading,
  exportSnapshot,
  refresh,
}: {
  activeTab: Exclude<CbomTab, 'Overview'>;
  entries: CbomEntry[];
  assets: any[];
  findings: ScannerFinding[];
  history: any[];
  telemetry: any[];
  certificateEntries: CbomEntry[];
  keyEntries: CbomEntry[];
  vulnerabilityEntries: CbomEntry[];
  readinessBacklog: CbomEntry[];
  trendPoints: TrendPoint[];
  complianceRows: { label: string; criterion: string; basis: string; met: boolean; status: string }[];
  totalAssets: number;
  totalComponents: number;
  pqcReady: number;
  inProgress: number;
  notPqcReady: number;
  atRiskComponents: number;
  criticalFindings: number;
  readinessScore: number;
  readinessMeasured: boolean;
  loading: boolean;
  exportSnapshot: () => void;
  refresh: () => void;
}) {
  const headerCopy: Record<Exclude<CbomTab, 'Overview'>, { label: string; description: string }> = {
    Inventory: {
      label: 'Tenant Cryptographic Inventory',
      description: 'Authoritative CBOM asset, component, algorithm, and service inventory synchronized from authenticated scanner runs.',
    },
    'PQC Readiness': {
      label: 'PQC Readiness Command View',
      description: 'Migration readiness, algorithm modernization backlog, and post-quantum replacement evidence for discovered cryptographic assets.',
    },
    Vulnerabilities: {
      label: 'Cryptographic Vulnerability Operations',
      description: 'Tenant-scoped weak algorithms, high-risk findings, and remediation queues correlated from scanner findings and CBOM evidence.',
    },
    Certificates: {
      label: 'Certificate And TLS Intelligence',
      description: 'Certificate, TLS, PKI, and trust-chain exposure view for post-quantum migration planning and lifecycle control.',
    },
    'Key Management': {
      label: 'Key Management Control Plane',
      description: 'Key exchange, signing, KEM, and algorithm rotation candidates mapped from runtime inventory and scan discoveries.',
    },
    Reports: {
      label: 'Compliance Evidence And Reports',
      description: 'Export-ready tenant CBOM evidence, compliance status, synchronization integrity, and activity snapshots.',
    },
    History: {
      label: 'Scan History And Runtime Events',
      description: 'Latest authorized scans, SSE telemetry, and scanner event evidence across the authenticated tenant workspace.',
    },
  };

  const title = headerCopy[activeTab];

  return (
    <section className={`${panelClass} p-4 md:p-5`}>
      <div className="mb-5 flex flex-col gap-3 border-b border-[var(--qg-card-border)] pb-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="text-[10px] font-black uppercase tracking-[0.25em] text-[var(--qg-amber)]">{activeTab}</div>
          <h2 className="mt-1 text-xl font-black text-[var(--qg-dashboard-text)]">{title.label}</h2>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-[var(--qg-dashboard-text-soft)]">{title.description}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={refresh} className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-2 text-xs font-bold text-[var(--qg-dashboard-text-soft)]">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Sync Now
          </button>
          <button type="button" onClick={exportSnapshot} className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-3 py-2 text-xs font-black text-[var(--qg-amber)]">
            <Download className="h-4 w-4" />
            Export Evidence
          </button>
        </div>
      </div>

      {activeTab === 'Inventory' && (
        <EntryEvidenceList entries={entries} assets={assets} emptyLabel="No tenant inventory has been synchronized yet. Start an authorized scan to populate assets and components." />
      )}

      {activeTab === 'PQC Readiness' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className={`${subtlePanelClass} p-4 xl:col-span-4`}>
            <ReadinessGauge score={readinessScore} hasScore={readinessMeasured} />
            <div className="mt-4 space-y-2">
              {[
                ['PQC Ready', pqcReady, 'text-emerald-600 dark:text-emerald-300'],
                ['In Progress', inProgress, 'text-blue-600 dark:text-blue-300'],
                ['Not PQC Ready', notPqcReady, 'text-orange-600 dark:text-orange-300'],
              ].map(([label, value, color]) => (
                <div key={String(label)} className="flex items-center justify-between rounded border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                  <span>{label}</span>
                  <span className={`font-black ${color}`}>{numberFmt(Number(value))}</span>
                </div>
              ))}
              <div className="flex items-center justify-between rounded border border-red-500/25 bg-red-500/8 px-3 py-2 text-xs">
                <span>At Risk <span className="text-[10px] text-[var(--qg-text-muted)]">(subset of Not PQC Ready)</span></span>
                <span className="font-black text-red-600 dark:text-red-300">{numberFmt(atRiskComponents)}</span>
              </div>
              <p className="text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
                Component scope — {numberFmt(totalComponents)} cryptographic components across {numberFmt(totalAssets)} asset{totalAssets === 1 ? '' : 's'}.
                Separately, {numberFmt(criticalFindings)} scanner finding{criticalFindings === 1 ? '' : 's'} {criticalFindings === 1 ? 'is' : 'are'} graded Critical.
              </p>
            </div>
            <DashboardAction to="/dashboard/migration-planner" icon={PackagePlus} label="Open Migration Planner" detail="Create phased PQC remediation workstreams" />
          </div>
          <div className="xl:col-span-8">
            <div className={`${subtlePanelClass} mb-3 p-4`}>
              <div className="mb-2 flex items-center justify-between text-xs">
                <span className="font-black uppercase tracking-wider">PQC-Ready Share Per Scan</span>
                <span className="text-[var(--qg-text-muted)]">{trendPoints.length} measured scan{trendPoints.length === 1 ? '' : 's'}</span>
              </div>
              {trendPoints.length === 0
                ? <EmptyState label="No completed scan has recorded a component count yet, so there is no readiness trend to plot." />
                : <div className="h-44"><LineTrendChart points={trendPoints} /></div>}
            </div>
            <EntryEvidenceList entries={readinessBacklog} assets={assets} emptyLabel="No PQC readiness backlog exists for the synchronized tenant inventory." />
          </div>
        </div>
      )}

      {activeTab === 'Vulnerabilities' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className="grid gap-3 md:grid-cols-2 xl:col-span-4">
            <DashboardMetric icon={AlertTriangle} label="At-Risk Components" value={atRiskComponents} detail="Vulnerable CBOM components graded Medium or worse" tone="red" />
            <DashboardMetric icon={ShieldAlert} label="Vulnerable Components" value={vulnerabilityEntries.length} detail="Quantum or weak-crypto exposure" tone="amber" />
            <DashboardMetric icon={Bell} label="Findings" value={findings.length} detail="De-duplicated scanner observations" tone="red" />
            <DashboardMetric icon={Zap} label="Critical Findings" value={criticalFindings} detail="Immediate remediation candidates" tone="red" />
            <div className="md:col-span-2">
              <DashboardAction to="/dashboard/quantum-readiness/risk-analysis" icon={ExternalLink} label="Open Quantum Risk Analysis" detail="Review remediation priority and risk evidence" />
            </div>
          </div>
          <div className="space-y-3 xl:col-span-8">
            <FindingEvidenceList findings={findings} emptyLabel="No scanner findings are currently synchronized for this tenant." />
            <EntryEvidenceList entries={vulnerabilityEntries} assets={assets} emptyLabel="No vulnerable CBOM rows detected in synchronized inventory." limit={4} />
          </div>
        </div>
      )}

      {activeTab === 'Certificates' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className="grid gap-3 md:grid-cols-2 xl:col-span-4">
            <DashboardMetric icon={FileArchive} label="Certificate / TLS Rows" value={certificateEntries.length} detail={`of ${numberFmt(totalComponents)} CBOM rows matching certificate, TLS or PKI evidence`} tone="cyan" />
            <DashboardMetric icon={ShieldAlert} label="Weak Trust Items" value={certificateEntries.filter((entry) => entry.isVulnerable || riskRank(entry.riskSeverity) >= 2).length} detail="Of those, vulnerable or graded Medium+" tone="amber" />
            <DashboardMetric icon={ShieldCheck} label="PQC-Ready Trust" value={certificateEntries.filter((entry) => entry.isQuantumSafe).length} detail="Of those, marked quantum safe" tone="green" />
            <DashboardMetric icon={CalendarClock} label="Scans In History" value={history.length} detail="Authorized scans this view draws on" tone="blue" />
            <div className="md:col-span-2">
              <DashboardAction to="/dashboard/pki" icon={ExternalLink} label="Open PKI Operations" detail="Manage certificates, policy, and lifecycle tasks" />
            </div>
          </div>
          <div className="xl:col-span-8">
            <EntryEvidenceList entries={certificateEntries} assets={assets} emptyLabel="No certificate, TLS, or PKI rows are available yet. Run a scanner job with certificate discovery enabled." />
          </div>
        </div>
      )}

      {activeTab === 'Key Management' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className="grid gap-3 md:grid-cols-2 xl:col-span-4">
            <DashboardMetric icon={Gauge} label="Key-Control Rows" value={keyEntries.length} detail={`of ${numberFmt(totalComponents)} CBOM rows matching KEM, key-exchange or signing evidence`} tone="cyan" />
            <DashboardMetric icon={ShieldAlert} label="Rotation Candidates" value={keyEntries.filter((entry) => entry.isVulnerable || entry.pqcReplacement).length} detail="Of those, carrying a PQC replacement or risk evidence" tone="amber" />
            <DashboardMetric icon={ShieldCheck} label="Quantum-Safe Keys" value={keyEntries.filter((entry) => entry.isQuantumSafe).length} detail="Of those, marked PQC ready" tone="green" />
            <DashboardMetric icon={Activity} label="Key Events" value={telemetry.filter((event: any) => /key|kem|rotation|signature/i.test(`${event.message} ${event.type} ${event.event}`)).length} detail={`of ${numberFmt(telemetry.length)} recorded scan telemetry events`} tone="blue" />
            <div className="md:col-span-2">
              <DashboardAction to="/dashboard/keys" icon={ExternalLink} label="Open Key Management" detail="Generate, rotate, and monitor cryptographic keys" />
            </div>
          </div>
          <div className="xl:col-span-8">
            <EntryEvidenceList entries={keyEntries} assets={assets} emptyLabel="No key-management CBOM records have been synchronized yet." />
          </div>
        </div>
      )}

      {activeTab === 'Reports' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className="grid gap-3 md:grid-cols-2 xl:col-span-5">
            <DashboardMetric icon={FileArchive} label="Reportable CBOM Rows" value={entries.length} detail="Exported from the current synchronized snapshot" tone="cyan" />
            <DashboardMetric icon={ListFilter} label="Screening Indicators" value={complianceRows.length} detail={`${complianceRows.filter((row) => row.met).length} currently met`} tone="blue" />
            <DashboardMetric icon={LineChart} label="Telemetry Events" value={telemetry.length} detail="Runtime events included in evidence" tone="amber" />
            <DashboardMetric icon={CalendarClock} label="Scan Records" value={history.length} detail="Historical scan runs included in export" tone="green" />
            <div className="md:col-span-2 grid gap-2 md:grid-cols-2">
              <DashboardAction icon={Download} label="Export CBOM JSON" detail="Download the current synchronized tenant evidence pack" onClick={exportSnapshot} />
              <DashboardAction to="/dashboard/compliance" icon={ExternalLink} label="Open Compliance Dashboard" detail="Review mapped policy and assurance controls" />
            </div>
          </div>
          <div className="space-y-3 xl:col-span-7">
            <div className={`${subtlePanelClass} p-4`}>
              <div className="mb-1 text-xs font-black uppercase tracking-wider text-[var(--qg-dashboard-text)]">Cryptographic Screening Indicators</div>
              <p className="mb-3 text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
                Each row states the CBOM measurement the control family is gated on and how that measurement currently reads.
                These are screening indicators, not compliance verdicts — control evidence and attestation live in the Compliance dashboard.
              </p>
              <div className="space-y-2">
                {complianceRows.map((row) => (
                  <div key={row.label} className="rounded border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-bold">{row.label}</span>
                      <span className={
                        row.status === 'Indicator met' ? 'shrink-0 font-black text-emerald-600 dark:text-emerald-300'
                          : row.status === 'Indicator not met' ? 'shrink-0 font-black text-[var(--qg-amber)]'
                            : 'shrink-0 font-black text-[var(--qg-text-muted)]'
                      }>{row.status}</span>
                    </div>
                    <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">{row.criterion} — {row.basis}</div>
                  </div>
                ))}
              </div>
            </div>
            <EntryEvidenceList entries={entries.slice(0, 6)} assets={assets} emptyLabel="No CBOM rows are available for report generation yet." />
          </div>
        </div>
      )}

      {activeTab === 'History' && (
        <div className="grid gap-3 xl:grid-cols-12">
          <div className="space-y-3 xl:col-span-7">
            {history.length === 0 ? (
              <EmptyState label="No authenticated scan history is available yet." />
            ) : (
              <TruncationNote shown={8} total={history.length} noun="recorded scans" rank="most recent" />
            )}
            {history.slice(0, 8).map((scan: any) => (
              <div key={scan.scanId || scan.id} className={`${subtlePanelClass} p-4`}>
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <div className="text-sm font-black text-[var(--qg-dashboard-text)]">{scan.target || 'Authorized target'}</div>
                    <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">{shortDate(scan.completedAt || scan.startedAt)} - {numberFmt(Number(scan.detectedComponents || 0))} components - {numberFmt(Number(scan.vulnerableFindings || 0))} vulnerable</div>
                  </div>
                  <span className="rounded border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-dashboard-text-soft)]">{scan.status || 'recorded'}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="space-y-3 xl:col-span-5">
            <DashboardAction to="/dashboard/scanner" icon={Activity} label="Start New Scan" detail="Create a new authorized CBOM scan job" />
            <div className={`${subtlePanelClass} p-4`}>
              <div className="mb-1 text-xs font-black uppercase tracking-wider text-[var(--qg-dashboard-text)]">Scanner Runtime Events</div>
              <p className="mb-3 text-[10px] text-[var(--qg-text-muted)]">
                Telemetry recorded during past scans, newest first — not a live feed.
              </p>
              {telemetry.length === 0 ? (
                <EmptyState label="No scan has recorded runtime telemetry yet." />
              ) : (
                <div className="space-y-2">
                  <TruncationNote shown={6} total={telemetry.length} noun="telemetry events" rank="most recent" />
                  {telemetry.slice(0, 6).map((event: any, index: number) => (
                    <div key={String(event.id || `${event.timestamp}-${index}`)} className="rounded border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3 text-xs">
                      <div className="font-bold text-[var(--qg-dashboard-text)]">{String(event.message || event.event || event.type || 'Telemetry event')}</div>
                      <div className="mt-1 flex justify-between text-[10px] text-[var(--qg-text-muted)]">
                        <span>{shortDate(event.timestamp || event.created_at || event.startedAt)}</span>
                        {/* `event.status` is the scan's lifecycle phase when the event
                            was emitted ("running"), not a severity — rendering it in a
                            severity slot made every stored event of a completed scan
                            read "running". */}
                        <span>{event.severity ? String(event.severity) : `phase: ${String(event.status || 'n/a')}`}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default function CbomExplorer() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const { data, loading, error, connected, refresh } = useScannerIntelligence({ live: autoRefresh });
  // Quantum Readiness & Assessment Engine snapshot — the platform's canonical
  // readiness/risk authority. CBOM's component inventory comes from the scanner
  // snapshot; the headline Quantum Readiness score, risk and PQC adoption are
  // read from THIS so the page reconciles with the QR Engine instead of showing
  // a divergent local number.
  const qr = useQuantumReadiness();
  const [activeTab, setActiveTab] = useState<CbomTab>('Overview');
  const [query, setQuery] = useState('');
  const [assetFilter, setAssetFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);
  const pageSize = 5;

  const entries = (data.cbom.entries || []) as CbomEntry[];
  const assets = data.assets.assets || [];
  const findings = data.findings || [];
  const history = data.history.history || [];
  const telemetry = data.telemetry || [];
  const stats = data.cbom.stats || { totalComponents: 0, quantumVulnerableComponents: 0, pqcReadyComponents: 0, totalInstances: 0 };

  // ---- Component scope --------------------------------------------------------
  // ONE decision about which population every component figure describes: the
  // backend's grouped CBOM stats when the snapshot carries them, otherwise the
  // rows this page received. Never a per-field `||` between the two — that is a
  // scope decision in disguise, and is how two panels end up describing
  // different populations while each looks locally correct.
  const hasComponentStats = Number(stats.totalComponents) > 0;
  const totalAssets = Number(data.summary.totalAssets) || assets.length;
  const totalComponents = hasComponentStats ? Number(stats.totalComponents) : entries.length;
  const pqcReady = hasComponentStats ? Number(stats.pqcReadyComponents) : entries.filter((entry) => entry.isQuantumSafe).length;
  const vulnerableComponents = hasComponentStats ? Number(stats.quantumVulnerableComponents) : entries.filter((entry) => entry.isVulnerable).length;
  // PQC-ready / not-ready / in-progress PARTITION the component universe, so
  // the Overview legend's percentages always add to 100.
  const notPqcReady = vulnerableComponents;
  const inProgress = Math.max(0, totalComponents - pqcReady - notPqcReady);

  // At-risk COMPONENTS — vulnerable components carrying a Medium-or-worse
  // exposure level. Component scope, so it can never exceed totalComponents.
  // This used to be that count PLUS `summary.criticalFindings`, a finding-level
  // number: adding two populations is what made a 66-component estate report
  // "At Risk 100" and a 100% at-risk share.
  const atRiskComponents = entries.filter((entry) => entry.isVulnerable && riskRank(entry.riskSeverity) >= 2).length;
  const criticalFindings = Number(data.summary.criticalFindings || 0);
  const readinessPercent = percent(pqcReady, totalComponents);

  // --- Quantum Readiness Engine reconciliation ---------------------------------
  // The QR Engine is the platform's readiness/risk authority. Until its snapshot
  // has actually resolved, this page has NO opinion on those scores and must say
  // so: rendering `quantumRisk = 0` while waiting printed a perfect score on a
  // lower-is-better scale, and claiming "In sync with QR" with an empty QR
  // column asserted an agreement nothing had been compared for.
  const qrHasData = qr.snapshot.hasData;
  const qrResolved = qr.state === 'success';
  const qrScores = qr.snapshot.scores;
  const qrInventory = qr.snapshot.inventory;
  const readinessScore = qrHasData ? qrScores.quantumReadiness : readinessPercent;
  const readinessLevel = qrHasData
    ? qrScores.quantumReadinessLevel
    : qrResolved ? 'No assessment evidence' : 'Awaiting assessment';
  const quantumRisk = qrHasData ? qrScores.quantumRisk : null;
  const pqcAdoption = qrHasData ? Math.round(qrScores.pqcAdoption) : readinessPercent;
  const qrLive = qr.sseConnected;
  // Do CBOM's component counts agree with the QR Engine's inventory? (Both derive
  // from the same scanner snapshot, so this should hold — surfaced as an explicit
  // integrity check rather than an assumption.)
  // Tolerance absorbs benign grouped-vs-raw component differences (±1 or 2%);
  // a real divergence (e.g. the old finding-level 113 vs 39 components) still flags.
  const withinTolerance = (a: number, b: number) => Math.abs(a - b) <= Math.max(1, Math.round(Math.max(a, b) * 0.02));
  const reconciliation = [
    { label: 'Crypto Components', cbom: totalComponents, qr: Number(qrInventory.cryptoComponents || 0) },
    { label: 'Vulnerable', cbom: vulnerableComponents, qr: Number(qrInventory.vulnerableComponents || 0) },
    { label: 'PQC-Ready', cbom: pqcReady, qr: Number(qrInventory.pqcReadyComponents || 0) },
  ].map((row) => ({ ...row, match: qrHasData ? withinTolerance(row.cbom, row.qr) : null }));
  const reconciliationState: 'match' | 'diverged' | 'pending' | 'no-evidence' = !qrHasData
    ? (qrResolved ? 'no-evidence' : 'pending')
    : reconciliation.every((row) => row.match) ? 'match' : 'diverged';
  // Charted over the rows whose `algorithm` really names cryptography; the
  // policy/configuration rows are counted separately and stated, never silently
  // plotted on an algorithm axis.
  const cryptoEntries = useMemo(() => entries.filter(namesCryptography), [entries]);
  const riskyAlgorithms = useMemo(() => buildRiskyAlgorithms(cryptoEntries), [cryptoEntries]);
  const postureEntryCount = entries.length - cryptoEntries.length;
  const algorithmDistribution = useMemo(() => buildAlgorithmDistribution(cryptoEntries), [cryptoEntries]);
  const trendPoints = useMemo(() => buildTrend(history), [history]);
  const latestScan = latestScanAt(history, data.generatedAt);
  const complianceRows = buildComplianceRows(totalComponents, pqcReady, atRiskComponents, criticalFindings);
  const hasSynchronizedData = Boolean(entries.length || assets.length || findings.length || history.length || telemetry.length || totalComponents);
  const isInitialSyncing = loading && !hasSynchronizedData;
  const certificateEntries = useMemo(
    () => entries.filter((entry) => /cert|tls|x509|pki|certificate|trust/i.test(`${entry.type} ${entry.component} ${entry.algorithm} ${entry.evidence}`)),
    [entries],
  );
  const keyEntries = useMemo(
    () => entries.filter((entry) => /key|kem|rsa|ecdsa|ecdh|dsa|ml-kem|ml-dsa|signature|signing/i.test(`${entry.type} ${entry.component} ${entry.algorithm} ${entry.evidence}`)),
    [entries],
  );
  const vulnerabilityEntries = useMemo(
    () => entries.filter((entry) => entry.isVulnerable || riskRank(entry.riskSeverity) >= 2 || WEAK_ALGORITHMS.has(algorithmLabel(entry.algorithm).toUpperCase())),
    [entries],
  );
  const readinessBacklog = useMemo(
    () => entries
      .filter((entry) => !entry.isQuantumSafe || entry.pqcReplacement)
      .sort((a, b) => riskRank(b.riskSeverity) - riskRank(a.riskSeverity)),
    [entries],
  );

  const assetOptions = useMemo(() => Array.from(new Set(entries.map((entry) => entry.sourceAsset).filter(Boolean))).sort(), [entries]);
  const typeOptions = useMemo(() => Array.from(new Set(entries.map((entry) => entry.type).filter(Boolean))).sort(), [entries]);
  const statusOptions = ['PQC Ready', 'Not PQC Ready', 'In Progress'];

  const tabFilteredEntries = useMemo(() => {
    if (activeTab === 'PQC Readiness') return entries;
    if (activeTab === 'Vulnerabilities') return vulnerabilityEntries;
    if (activeTab === 'Certificates') return certificateEntries;
    if (activeTab === 'Key Management') return keyEntries;
    return entries;
  }, [activeTab, certificateEntries, entries, keyEntries, vulnerabilityEntries]);

  const filteredEntries = useMemo(() => {
    const q = query.trim().toLowerCase();
    return tabFilteredEntries.filter((entry) => {
      const readiness = readinessBadge(entry).label;
      if (q && ![
        entry.component,
        entry.algorithm,
        entry.sourceAsset,
        entry.type,
        entry.evidence,
        entry.detectionMethod,
      ].some((value) => String(value || '').toLowerCase().includes(q))) return false;
      if (assetFilter !== 'all' && entry.sourceAsset !== assetFilter) return false;
      if (typeFilter !== 'all' && entry.type !== typeFilter) return false;
      if (statusFilter !== 'all' && readiness !== statusFilter) return false;
      return true;
    });
  }, [assetFilter, query, statusFilter, tabFilteredEntries, typeFilter]);

  const maxPage = Math.max(1, Math.ceil(filteredEntries.length / pageSize));
  const safePage = Math.min(page, maxPage);
  const pagedEntries = filteredEntries.slice((safePage - 1) * pageSize, safePage * pageSize);

  const exportSnapshot = () => {
    const payload = {
      generatedAt: data.generatedAt,
      mode: data.mode,
      summary: data.summary,
      cbom: { entries, stats },
      assets,
      findings,
      telemetry,
      history,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `qguard-cbom-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const metricCards = [
    { label: 'Total Assets', value: totalAssets, detail: `${numberFmt(data.summary.vulnerableAssets)} with open exposure`, icon: Database, tone: 'blue' },
    { label: 'Crypto Components', value: totalComponents, detail: `${numberFmt(Number(stats.totalInstances || totalComponents))} observed instances`, icon: Layers, tone: 'blue' },
    { label: 'PQC Ready', value: pqcReady, detail: `${readinessPercent}% of components`, icon: ShieldCheck, tone: 'green' },
    { label: 'Not PQC Ready', value: notPqcReady, detail: `${percent(notPqcReady, totalComponents)}% of components`, icon: ShieldAlert, tone: 'orange' },
    // Component scope, stated. Findings are a different population and get their
    // own card rather than being added into this one.
    { label: 'At-Risk Components', value: atRiskComponents, detail: `${numberFmt(criticalFindings)} critical of ${numberFmt(findings.length)} findings`, icon: AlertTriangle, tone: 'red' },
  ];

  const focusedTabDashboard = activeTab === 'Overview' ? null : (
    <FocusedTabDashboard
      activeTab={activeTab}
      entries={entries}
      assets={assets}
      findings={findings}
      history={history}
      telemetry={telemetry}
      certificateEntries={certificateEntries}
      keyEntries={keyEntries}
      vulnerabilityEntries={vulnerabilityEntries}
      readinessBacklog={readinessBacklog}
      trendPoints={trendPoints}
      complianceRows={complianceRows}
      totalAssets={totalAssets}
      totalComponents={totalComponents}
      pqcReady={pqcReady}
      inProgress={inProgress}
      notPqcReady={notPqcReady}
      atRiskComponents={atRiskComponents}
      criticalFindings={criticalFindings}
      readinessScore={readinessScore}
      readinessMeasured={qrHasData}
      loading={loading}
      exportSnapshot={exportSnapshot}
      refresh={refresh}
    />
  );

  return (
    <div
      className="min-h-screen space-y-4 p-4 text-[var(--qg-dashboard-text)] md:p-6"
      style={{
        background:
          'radial-gradient(circle at 18% 8%, color-mix(in srgb, var(--qg-cyan) 14%, transparent), transparent 34%), radial-gradient(circle at 82% 18%, color-mix(in srgb, var(--qg-amber) 10%, transparent), transparent 30%), linear-gradient(180deg, var(--qg-dashboard-bg), var(--qg-dashboard-bg-soft))',
      }}
    >
      <WorkflowRail activeStage="cbom" tone="adaptive" />
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-black tracking-tight text-[var(--qg-dashboard-text)] md:text-3xl">
              CBOM Explorer
            </h1>
            <Info className="h-4 w-4 text-[var(--qg-text-muted)]" />
          </div>
          <p className="mt-1 text-sm text-[var(--qg-dashboard-text-soft)]">
            Cryptography Bill of Materials - real authorized scan inventory with PQC readiness analysis.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-black uppercase tracking-widest">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${connected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
              {connected ? 'Live Telemetry' : 'Cached'}
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--qg-cyan)]/25 bg-[var(--qg-cyan)]/10 px-2 py-0.5 text-[var(--qg-cyan)]">
              <Sparkles className="h-3 w-3" /> Reconciled with Quantum Readiness Engine
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-blue-500/30 bg-blue-500/10 px-4 py-2 text-xs font-bold text-blue-300 transition hover:border-blue-400/60">
            <Target className="h-4 w-4" />
            Scan Targets
          </Link>
          <Link to="/dashboard/scanner" className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/40 bg-[var(--qg-amber)] px-4 py-2 text-xs font-black text-[var(--qg-on-accent)] shadow-[0_0_18px_color-mix(in_srgb,var(--qg-amber)_28%,transparent)] transition hover:brightness-110">
            <Plus className="h-4 w-4" />
            Add Target
          </Link>
          <InventoryExportMenu
            label={`Export ${filteredEntries.length === entries.length ? `${entries.length} components` : `${filteredEntries.length} shown`}`}
            disabled={entries.length === 0}
            build={() => ({
              kind: 'cbom' as const,
              summary: {
                totalAssets: data.summary.totalAssets,
                totalComponents: data.summary.totalComponents,
                vulnerableAssets: data.summary.vulnerableAssets,
                vulnerableComponents: data.summary.vulnerableComponents,
                pqcReadyComponents: data.summary.pqcReadyComponents,
                criticalFindings: data.summary.criticalFindings,
                totalFindings: data.summary.totalFindings,
                riskScore: data.summary.riskScore,
                qScore: data.summary.qScore,
              },
              assets,
              cbom: filteredEntries,
              totalAssetsBeforeFilter: assets.length,
              totalCbomBeforeFilter: entries.length,
              generatedAt: new Date().toISOString(),
              lastScanAt: latestScan || data.generatedAt || null,
              filtered: filteredEntries.length !== entries.length,
              filterDescription: [query && `search "${query}"`, assetFilter !== 'all' && `asset ${assetFilter}`, typeFilter !== 'all' && `type ${typeFilter}`, statusFilter !== 'all' && `status ${statusFilter}`]
                .filter(Boolean)
                .join(', '),
            })}
          />
          <button type="button" className="relative inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] text-[var(--qg-dashboard-text-soft)]">
            <Bell className="h-4 w-4" />
            {atRiskComponents > 0 && (
              <span
                title={`${numberFmt(atRiskComponents)} at-risk cryptographic components`}
                className="absolute -right-1 -top-1 rounded-full bg-[var(--qg-amber)] px-1.5 text-[9px] font-black text-[var(--qg-on-accent)]"
              >
                {atRiskComponents > 9 ? '9+' : atRiskComponents}
              </span>
            )}
          </button>
          <button type="button" className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] text-[var(--qg-dashboard-text-soft)]">
            <CircleHelp className="h-4 w-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-col gap-3 border-b border-[var(--qg-card-border)] pb-3 xl:flex-row xl:items-center xl:justify-between">
        <nav className="flex gap-1 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              type="button"
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                setPage(1);
              }}
              className={`whitespace-nowrap border-b-2 px-3 py-2 text-xs font-bold transition ${
                activeTab === tab
                  ? 'border-[var(--qg-amber)] text-[var(--qg-amber)]'
                  : 'border-transparent text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]'
              }`}
            >
              {tab}
            </button>
          ))}
        </nav>
        <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--qg-text-muted)]">
          <span>Last Scan: {formatDate(latestScan)}</span>
          <button type="button" onClick={refresh} className="inline-flex items-center gap-1 text-[var(--qg-dashboard-text-soft)]">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <span className="h-5 w-px bg-[var(--qg-card-border)]" />
          <button type="button" onClick={() => setAutoRefresh((value) => !value)} className="inline-flex items-center gap-2">
            Auto Refresh
            <span className={`relative h-5 w-9 rounded-full border transition ${autoRefresh ? 'border-[var(--qg-amber)] bg-[var(--qg-amber)]/30' : 'border-[var(--qg-card-border)] bg-[var(--qg-card-bg)]'}`}>
              <span className={`absolute top-0.5 h-4 w-4 rounded-full transition ${autoRefresh ? 'left-4 bg-[var(--qg-amber)]' : 'left-0.5 bg-[var(--qg-text-muted)]'}`} />
            </span>
          </button>
          <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-[10px] font-bold uppercase ${autoRefresh && connected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${autoRefresh && connected ? 'bg-emerald-400' : 'bg-[var(--qg-text-muted)]'}`} />
            {autoRefresh && connected ? 'Live SSE' : 'Manual'}
          </span>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {isInitialSyncing && (
        <div className="flex flex-col gap-2 rounded-lg border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 p-3 text-xs font-bold text-[var(--qg-dashboard-text-soft)] md:flex-row md:items-center md:justify-between">
          <span className="inline-flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-[var(--qg-amber)]" />
            Synchronizing authenticated CBOM telemetry from backend APIs and live scanner events.
          </span>
          <span className="text-[10px] uppercase tracking-wider text-[var(--qg-text-muted)]">Dashboard remains usable while sync completes</span>
        </div>
      )}

      <section className="grid gap-3 lg:grid-cols-5">
        {metricCards.map((card, index) => {
          const Icon = card.icon;
          const toneClass =
            card.tone === 'green' ? 'from-emerald-500/25 text-emerald-300' :
            card.tone === 'orange' ? 'from-orange-500/25 text-orange-300' :
            card.tone === 'red' ? 'from-red-500/25 text-red-300' :
            'from-blue-500/25 text-blue-300';
          return (
            <motion.div
              key={card.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.04 }}
              className={`${panelClass} p-4`}
            >
              <div className="flex items-center gap-3">
                <div className={`grid h-12 w-12 place-items-center rounded-full bg-gradient-to-br ${toneClass} to-transparent`}>
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--qg-text-muted)]">{card.label}</div>
                  <div className="text-2xl font-black text-[var(--qg-dashboard-text)]">{numberFmt(card.value)}</div>
                  <div className="mt-0.5 text-[10px] text-[var(--qg-text-muted)]">{card.detail}</div>
                </div>
              </div>
            </motion.div>
          );
        })}
      </section>

      {/* Quantum Readiness Engine reconciliation — the headline readiness/risk are
          read from the QR Engine snapshot and the component counts are checked
          against it, so this page can never silently diverge from QR. */}
      <section className={`${panelClass} p-4 md:p-5`}>
        <div className="grid gap-5 lg:grid-cols-[1.1fr_1.5fr_1.05fr]">
          <div>
            <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-[var(--qg-cyan)]">
              <Sparkles className="h-3.5 w-3.5" /> Quantum Readiness Engine
            </div>
            <div className="mt-2 flex items-end gap-2">
              {qrHasData ? (
                <>
                  <span className="text-4xl font-black" style={{ color: readinessTone(readinessScore) }}>{Math.round(readinessScore)}</span>
                  <span className="mb-1 text-xs text-[var(--qg-text-muted)]">/100 · {readinessLevel}</span>
                </>
              ) : (
                <>
                  <span className="text-4xl font-black text-[var(--qg-text-muted)]">—</span>
                  <span className="mb-1 text-xs text-[var(--qg-text-muted)]">{readinessLevel}</span>
                </>
              )}
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[var(--qg-muted-panel)]">
              {qrHasData && (
                <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(0, Math.min(100, readinessScore))}%`, background: readinessTone(readinessScore) }} />
              )}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {/* An unresolved risk score renders as "—", never as 0: on a
                  lower-is-better scale a placeholder zero reads as a perfect posture. */}
              <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">
                Quantum Risk {quantumRisk === null ? '—' : `${quantumRisk}/100`}
              </span>
              <span className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-2 py-1 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">PQC Adoption {pqcAdoption}%</span>
            </div>
            {!qrHasData && (
              <p className="mt-2 text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
                {qrResolved
                  ? 'The Quantum Readiness Engine has no assessment evidence for this tenant yet. Component counts below are CBOM-only.'
                  : 'Waiting for the Quantum Readiness Engine assessment. Readiness and risk are withheld until it responds.'}
              </p>
            )}
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">
                <GitCompareArrows className="h-3.5 w-3.5" /> Inventory Reconciliation
              </span>
              {/* A verdict is only claimed once there is something to compare.
                  With no QR snapshot the badge previously read "In sync with QR"
                  beside three empty QR cells. */}
              <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-black uppercase ${
                reconciliationState === 'match' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : reconciliationState === 'diverged' ? 'border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]'
                    : 'border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] text-[var(--qg-text-muted)]'
              }`}>
                {reconciliationState === 'match' ? <CheckCircle2 className="h-3 w-3" /> : reconciliationState === 'diverged' ? <AlertTriangle className="h-3 w-3" /> : <CircleHelp className="h-3 w-3" />}
                {reconciliationState === 'match' ? 'In sync with QR'
                  : reconciliationState === 'diverged' ? 'Diverged from QR'
                    : reconciliationState === 'no-evidence' ? 'No QR evidence' : 'Awaiting QR'}
              </span>
            </div>
            <div className="overflow-hidden rounded-lg border border-[var(--qg-card-border)]">
              <div className="grid grid-cols-[1.4fr_1fr_1fr_auto] bg-[var(--qg-muted-panel)] px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]">
                <span>Metric</span><span className="text-right">CBOM</span><span className="text-right">QR Engine</span><span className="pl-3" />
              </div>
              {reconciliation.map((row) => (
                <div key={row.label} className="grid grid-cols-[1.4fr_1fr_1fr_auto] items-center border-t border-[var(--qg-card-border)] px-3 py-2 text-xs">
                  <span className="font-bold text-[var(--qg-dashboard-text)]">{row.label}</span>
                  <span className="text-right font-black text-[var(--qg-dashboard-text)]">{numberFmt(row.cbom)}</span>
                  <span className="text-right font-mono text-[var(--qg-dashboard-text-soft)]">{qrHasData ? numberFmt(row.qr) : '—'}</span>
                  <span className="pl-3">
                    {row.match === null
                      ? <CircleHelp className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
                      : row.match
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        : <AlertTriangle className="h-3.5 w-3.5 text-[var(--qg-amber)]" />}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col justify-between gap-3">
            <div className="space-y-2">
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-[var(--qg-text-muted)]">Live Telemetry</div>
              <div className="flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
                <span className="font-bold text-[var(--qg-dashboard-text-soft)]">Scanner CBOM stream</span>
                <span className={`ml-auto text-[10px] font-black uppercase ${connected ? 'text-emerald-300' : 'text-[var(--qg-text-muted)]'}`}>{connected ? 'Live' : 'Idle'}</span>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs">
                <span className={`h-2 w-2 rounded-full ${qrLive ? 'bg-emerald-400 animate-pulse' : 'bg-[var(--qg-text-muted)]'}`} />
                <span className="font-bold text-[var(--qg-dashboard-text-soft)]">QR assessment stream</span>
                <span className={`ml-auto text-[10px] font-black uppercase ${qrLive ? 'text-emerald-300' : 'text-[var(--qg-text-muted)]'}`}>{qrLive ? 'Live' : 'Idle'}</span>
              </div>
            </div>
            <Link to="/dashboard/quantum-readiness" className="inline-flex items-center justify-center gap-2 rounded-md border border-[var(--qg-cyan)]/35 bg-[var(--qg-cyan)]/10 px-3 py-2 text-[11px] font-black uppercase tracking-wider text-[var(--qg-cyan)] transition hover:border-[var(--qg-cyan)]/70">
              <ExternalLink className="h-3.5 w-3.5" /> Open Quantum Readiness
            </Link>
          </div>
        </div>
      </section>

      {activeTab === 'Overview' ? (
      <section className="grid gap-3 xl:grid-cols-12">
        <div className={`${panelClass} p-4 xl:col-span-6`}>
          <div className="mb-3 flex items-center gap-2 text-sm font-bold">
            Quantum Readiness Score <span className="text-[10px] font-black uppercase text-[var(--qg-text-muted)]">· {readinessLevel}</span> <Info className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
          </div>
          <ReadinessGauge score={readinessScore} hasScore={qrHasData} />
          {/* These three PARTITION the component universe and therefore add to
              100%. "At Risk" is a subset of Not PQC Ready, not a fourth slice —
              listing it alongside them (with a findings count folded in) is what
              produced a legend reading 6.1 / 0 / 93.9 / 100 %. */}
          <div className="mt-4 space-y-2">
            {[
              ['PQC Ready', pqcReady, 'bg-emerald-400'],
              ['In Progress', inProgress, 'bg-blue-400'],
              ['Not PQC Ready', notPqcReady, 'bg-orange-400'],
            ].map(([label, value, color]) => (
              <div key={String(label)} className="grid grid-cols-[1fr_auto] items-center gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${color}`} />
                  <span>{label}</span>
                </div>
                <span>{percent(Number(value), Math.max(1, totalComponents))}% ({numberFmt(Number(value))})</span>
              </div>
            ))}
            <div className="grid grid-cols-[1fr_auto] items-center gap-2 border-t border-[var(--qg-card-border)] pt-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-red-400" />
                <span>At Risk <span className="text-[10px] text-[var(--qg-text-muted)]">· of Not PQC Ready</span></span>
              </div>
              <span>{percent(atRiskComponents, Math.max(1, totalComponents))}% ({numberFmt(atRiskComponents)})</span>
            </div>
            <p className="text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
              Component scope across the tenant estate. Score and level come from the Quantum Readiness Engine.
            </p>
          </div>
          <Link to="/dashboard/migration-planner" className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-md border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-3 py-2 text-xs font-black text-[var(--qg-amber)]">
            <PackagePlus className="h-4 w-4" />
            View Recommendations
            <ChevronDown className="h-3.5 w-3.5" />
          </Link>
        </div>

        <div className={`${panelClass} p-4 xl:col-span-6`}>
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold">PQC-Ready Share Per Scan</div>
            <span className="rounded-md border border-[var(--qg-card-border)] px-2 py-1 text-[10px] text-[var(--qg-text-muted)]">{trendPoints.length} measured scan{trendPoints.length === 1 ? '' : 's'}</span>
          </div>
          {trendPoints.length === 0 ? (
            <EmptyState label="No completed scan has recorded a component count yet, so there is no readiness trend to plot." />
          ) : (
            <>
              <div className="h-[210px]">
                <LineTrendChart points={trendPoints} />
              </div>
              <div className="mt-2 flex justify-center gap-2 text-xs text-[var(--qg-text-muted)]">
                <span className="mt-1 h-0.5 w-4 bg-[var(--qg-amber)]" />
                PQC-ready components ÷ components detected, per scan
              </div>
            </>
          )}
        </div>

        <div className={`${panelClass} p-4 xl:col-span-8`}>
          <div className="mb-1 flex items-center gap-2 text-sm font-bold">
            Algorithm Distribution <Info className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
          </div>
          <p className="mb-3 text-[10px] text-[var(--qg-text-muted)]">
            {numberFmt(algorithmDistribution.total)} instance{algorithmDistribution.total === 1 ? '' : 's'} across {numberFmt(algorithmDistribution.distinct)} algorithm{algorithmDistribution.distinct === 1 ? '' : 's'}.
            {postureEntryCount > 0 && ` ${numberFmt(postureEntryCount)} policy and configuration observation${postureEntryCount === 1 ? '' : 's'} are excluded — they record posture, not an algorithm.`}
          </p>
          {algorithmDistribution.slices.length === 0 ? (
            <EmptyState label="No cryptographic algorithms have been inventoried yet. Policy and configuration observations are listed under Inventory." />
          ) : (
            <div className="grid gap-5 md:grid-cols-[190px_1fr]">
              <div className="relative mx-auto h-44 w-44 rounded-full" style={{ background: distributionGradient(algorithmDistribution.slices, algorithmDistribution.total) }}>
                <div className="absolute inset-9 grid place-items-center rounded-full bg-[var(--qg-dashboard-bg)] text-center shadow-inner">
                  <div>
                    <div className="text-2xl font-black">{numberFmt(algorithmDistribution.total)}</div>
                    <div className="text-[10px] text-[var(--qg-text-muted)]">Instances</div>
                  </div>
                </div>
              </div>
              <div className="space-y-3">
                {algorithmDistribution.slices.map((item, index) => {
                  const colors = ['bg-blue-500', 'bg-slate-500', 'bg-amber-500', 'bg-emerald-500', 'bg-violet-500', 'bg-slate-600'];
                  return (
                    <div key={item.algorithm} className="grid grid-cols-[1fr_auto] items-center gap-3 text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`h-3 w-3 rounded-full ${colors[index % colors.length]}`} />
                        <span>{item.algorithm}</span>
                      </div>
                      <span className="text-[var(--qg-text-muted)]">{percent(item.count, algorithmDistribution.total)}% ({numberFmt(item.count)})</span>
                    </div>
                  );
                })}
                <button type="button" onClick={() => setActiveTab('Inventory')} className="mt-2 inline-flex items-center gap-1 text-xs font-bold text-[var(--qg-amber)]">
                  View All Algorithms <ExternalLink className="h-3 w-3" />
                </button>
              </div>
            </div>
          )}
        </div>

        <div className={`${panelClass} p-4 xl:col-span-4`}>
          <div className="mb-3 flex items-center gap-2 text-sm font-bold">
            Top Risky Algorithms <Info className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
          </div>
          {riskyAlgorithms.length === 0 ? (
            <EmptyState label="No risky algorithms detected." />
          ) : (
            <div className="space-y-2">
              {riskyAlgorithms.map((item) => (
                <div key={item.algorithm} className="flex items-center justify-between rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] px-3 py-2 text-xs">
                  <span>{item.algorithm}</span>
                  <span className={`rounded px-2 py-1 text-[10px] font-bold ${riskBadgeClass(item.severity)}`}>{item.severity}</span>
                </div>
              ))}
              <button type="button" onClick={() => setActiveTab('Vulnerabilities')} className="mt-2 inline-flex items-center gap-1 text-xs font-bold text-[var(--qg-amber)]">
                View Vulnerabilities <ExternalLink className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
      </section>
      ) : activeTab === 'Inventory' ? null : (
        focusedTabDashboard
      )}

      <section className="grid gap-3 xl:grid-cols-12">
        <div className={`${panelClass} xl:col-span-12`}>
          <div className="border-b border-[var(--qg-card-border)] p-4">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex items-center gap-2 text-sm font-bold">
                {activeTab === 'History' ? 'Scan History' : 'Recent Inventory'} <Info className="h-3.5 w-3.5 text-[var(--qg-text-muted)]" />
              </div>
              <div className="flex flex-wrap gap-2">
                <div className="relative min-w-[220px] flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--qg-text-muted)]" />
                  <input
                    value={query}
                    onChange={(event) => {
                      setQuery(event.target.value);
                      setPage(1);
                    }}
                    placeholder="Search assets, algorithms, components..."
                    className="w-full rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] py-2 pl-9 pr-3 text-xs text-[var(--qg-dashboard-text)] outline-none placeholder:text-[var(--qg-text-muted)] focus:border-[var(--qg-amber)]/50"
                  />
                </div>
                <select value={assetFilter} onChange={(event) => { setAssetFilter(event.target.value); setPage(1); }} className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs text-[var(--qg-dashboard-text)]">
                  <option value="all">All Assets</option>
                  {assetOptions.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
                <select value={typeFilter} onChange={(event) => { setTypeFilter(event.target.value); setPage(1); }} className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs text-[var(--qg-dashboard-text)]">
                  <option value="all">All Types</option>
                  {typeOptions.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
                <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); setPage(1); }} className="rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 py-2 text-xs text-[var(--qg-dashboard-text)]">
                  <option value="all">All Status</option>
                  {statusOptions.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
                <button type="button" className="inline-flex items-center gap-2 rounded-md border border-[var(--qg-amber)]/35 px-3 py-2 text-xs font-bold text-[var(--qg-amber)]">
                  <Filter className="h-4 w-4" />
                  Filters
                </button>
              </div>
            </div>
          </div>

          {activeTab === 'History' ? (
            <div className="p-4">
              {history.length === 0 ? (
                <EmptyState label="No authenticated scans have been recorded for this tenant yet." />
              ) : (
                <div className="space-y-2">
                  <TruncationNote shown={8} total={history.length} noun="recorded scans" rank="most recent" />
                  {history.slice(0, 8).map((scan: any) => (
                    <div key={scan.scanId || scan.id} className="grid gap-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-3 md:grid-cols-[1fr_auto_auto] md:items-center">
                      <div>
                        <div className="text-sm font-bold">{scan.target || 'Authorized target'}</div>
                        <div className="mt-1 text-xs text-[var(--qg-text-muted)]">{shortDate(scan.completedAt || scan.startedAt)} - {numberFmt(Number(scan.detectedComponents || 0))} components - {numberFmt(Number(scan.vulnerableFindings || 0))} vulnerable</div>
                      </div>
                      <span className="rounded border border-[var(--qg-card-border)] px-2 py-1 text-[10px] font-bold uppercase text-[var(--qg-text-muted)]">{scan.status || 'recorded'}</span>
                      <span className="text-xs font-bold text-[var(--qg-amber)]">Q-Score {Math.round(Number(scan.qScore || scan.summary?.qScore || 0))}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-[980px] w-full border-collapse text-left text-xs">
                  <thead className="border-b border-[var(--qg-card-border)] text-[10px] uppercase tracking-wider text-[var(--qg-text-muted)]">
                    <tr>
                      <th className="px-4 py-3">Asset</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Component / Service</th>
                      <th className="px-4 py-3">Algorithm</th>
                      <th className="px-4 py-3">Purpose</th>
                      <th className="px-4 py-3">Key Size / Strength</th>
                      <th className="px-4 py-3">PQC Readiness</th>
                      <th className="px-4 py-3">Risk Level</th>
                      <th className="px-4 py-3">Last Seen</th>
                      <th className="px-4 py-3" />
                    </tr>
                  </thead>
                  <tbody>
                    {pagedEntries.length === 0 ? (
                      <tr>
                        <td colSpan={10} className="px-4 py-14">
                          <EmptyState label={
                            entries.length === 0
                              ? isInitialSyncing
                                ? 'No local CBOM cache is available yet. Live scanner events and backend results will populate this table as soon as they arrive.'
                                : 'No CBOM inventory exists yet. Start an authorized scan to populate this dashboard.'
                              : 'No CBOM rows match the current filters.'
                          } />
                        </td>
                      </tr>
                    ) : pagedEntries.map((entry) => {
                      const readiness = readinessBadge(entry);
                      return (
                        <tr key={entry.id} className="border-b border-[var(--qg-card-border)] transition hover:bg-[var(--qg-muted-panel)]">
                          <td className="px-4 py-3">
                            <div className="font-bold">{entry.sourceAsset || 'Unknown asset'}</div>
                            <div className="text-[10px] text-[var(--qg-text-muted)]">{String(entry.metadata?.ipAddress || entry.metadata?.target || entry.sourceAssetId || '')}</div>
                          </td>
                          <td className="px-4 py-3">
                            <span className="rounded bg-[var(--qg-chip-bg)] px-2 py-1 text-[10px]">{assetType(entry, assets)}</span>
                          </td>
                          <td className="px-4 py-3">{entry.component}</td>
                          <td className="px-4 py-3 font-mono">{entry.algorithm}</td>
                          <td className="px-4 py-3">{entryPurpose(entry)}</td>
                          <td className="px-4 py-3 font-mono">{entryKeySize(entry)}</td>
                          <td className="px-4 py-3"><span className={`rounded px-2 py-1 text-[10px] font-bold ${readiness.className}`}>{readiness.label}</span></td>
                          <td className="px-4 py-3"><span className={`rounded px-2 py-1 text-[10px] font-bold ${riskBadgeClass(entry.riskSeverity)}`}>{normalizeSeverity(entry.riskSeverity)}</span></td>
                          <td className="px-4 py-3 text-[var(--qg-text-muted)]">{shortDate(entry.lastScannedDate)}</td>
                          <td className="px-4 py-3 text-right text-[var(--qg-text-muted)]">...</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="flex flex-col gap-3 border-t border-[var(--qg-card-border)] p-4 text-xs text-[var(--qg-text-muted)] md:flex-row md:items-center md:justify-between">
                <span>Showing {filteredEntries.length === 0 ? 0 : (safePage - 1) * pageSize + 1} to {Math.min(safePage * pageSize, filteredEntries.length)} of {numberFmt(filteredEntries.length)} results</span>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={safePage <= 1} className="rounded border border-[var(--qg-card-border)] px-3 py-2 disabled:opacity-40">Prev</button>
                  {Array.from({ length: Math.min(5, maxPage) }, (_, index) => index + 1).map((item) => (
                    <button key={item} type="button" onClick={() => setPage(item)} className={`rounded border px-3 py-2 ${safePage === item ? 'border-[var(--qg-amber)] text-[var(--qg-amber)]' : 'border-[var(--qg-card-border)]'}`}>{item}</button>
                  ))}
                  <button type="button" onClick={() => setPage((value) => Math.min(maxPage, value + 1))} disabled={safePage >= maxPage} className="rounded border border-[var(--qg-card-border)] px-3 py-2 disabled:opacity-40">Next</button>
                </div>
              </div>
            </>
          )}
        </div>

      </section>

      {activeTab === 'Inventory' && focusedTabDashboard}
    </div>
  );
}
