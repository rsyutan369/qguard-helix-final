import { AnimatePresence, motion } from 'framer-motion';
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  Bell,
  Building2,
  Check,
  ChevronDown,
  ClipboardCheck,
  Eye,
  FileCheck2,
  FileText,
  Gauge,
  Info,
  KeyRound,
  Landmark,
  LineChart,
  ListChecks,
  LockKeyhole,
  Radar,
  RefreshCw,
  ScrollText,
  Shield,
  ShieldCheck,
  Sparkles,
  Target,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import {
  useComplianceDashboard,
  type ComplianceCapabilityHighlight,
  type ComplianceCertificateRow,
  type ComplianceDashboardSnapshot,
  type ComplianceFrameworkAlignment,
  type ComplianceGovernancePolicyRow,
  type ComplianceMaturityLevel,
  type CompliancePolicyRow,
  type CompliancePolicyViolation,
  type ComplianceRequirementBreakdown,
  type ComplianceTrendPoint,
} from '@/hooks/use-compliance-dashboard';

type Tone = 'gold' | 'green' | 'red' | 'muted';

type MetricCard = {
  title: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: Tone;
};

type ComplianceModalKey = 'frameworks' | 'maturity' | 'trend' | 'policies' | 'violations' | 'evidence';

type ComplianceModalContent = {
  title: string;
  eyebrow: string;
  summary: string;
  icon: LucideIcon;
  metrics: Array<{ label: string; value: string; tone: Tone }>;
  bullets: string[];
};

const cx = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(' ');

const particles = Array.from({ length: 36 }, (_, index) => ({
  left: `${(index * 17 + 8) % 100}%`,
  top: `${(index * 29 + 13) % 94}%`,
  delay: (index % 9) * 0.28,
  duration: 6 + (index % 6),
  size: index % 5 === 0 ? 3 : 2,
}));

const toneClasses: Record<Tone, string> = {
  gold: 'text-[#FFD36B] drop-shadow-[0_0_8px_rgba(255,211,107,0.34)]',
  green: 'text-[#4DFF88] drop-shadow-[0_0_8px_rgba(77,255,136,0.28)]',
  red: 'text-[#FF4D5A] drop-shadow-[0_0_8px_rgba(255,77,90,0.28)]',
  muted: 'text-white/64 drop-shadow-[0_0_8px_rgba(255,255,255,0.10)]',
};

const capabilityIconMap: Record<ComplianceCapabilityHighlight['iconKey'], LucideIcon> = {
  shield: ShieldCheck,
  audit: ScrollText,
  check: BadgeCheck,
  target: Target,
  clipboard: ClipboardCheck,
  building: Building2,
};

function pct(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function integer(value: number) {
  return Math.round(Number(value) || 0).toLocaleString();
}

function readableDateTime(value?: string | null) {
  if (!value) return 'Awaiting telemetry';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Awaiting telemetry';
  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function readinessLabel(score: number) {
  if (score >= 90) return 'Optimal';
  if (score >= 75) return 'Ready';
  if (score >= 50) return 'Review';
  if (score > 0) return 'At Risk';
  return 'Awaiting Data';
}

function complianceTone(score: number): Tone {
  if (score >= 80) return 'green';
  if (score >= 50) return 'gold';
  if (score > 0) return 'red';
  return 'muted';
}

function buildMetricCards(snapshot: ComplianceDashboardSnapshot): MetricCard[] {
  const { metrics: m } = snapshot;
  return [
    {
      title: 'Post-Quantum Compliance',
      value: pct(m.complianceScore),
      detail: `${integer(m.auditEvents)} evidence and audit signals`,
      icon: ShieldCheck,
      tone: complianceTone(m.complianceScore),
    },
    {
      title: 'Certificate Status',
      value: `${pct(m.totalCertificates ? (m.activeCertificates / m.totalCertificates) * 100 : 0)} Active`,
      detail: `${integer(m.activeCertificates)} active | ${integer(m.expiredCertificates)} expired | ${integer(m.expiringCertificates)} expiring`,
      icon: FileCheck2,
      tone: m.expiredCertificates > 0 ? 'red' : m.expiringCertificates > 0 ? 'gold' : 'green',
    },
    {
      title: 'Policy Adherence',
      value: pct(m.policyAdherence),
      detail: `${integer(m.enforcedPolicies)} of ${integer(m.totalPolicies)} controls enforced`,
      icon: ClipboardCheck,
      tone: complianceTone(m.policyAdherence),
    },
    {
      title: 'Quantum Risk',
      value: `Q-${integer(m.qScore)}`,
      detail: `${integer(m.criticalFindings)} critical | ${integer(m.highFindings)} high findings`,
      icon: Radar,
      tone: m.criticalFindings > 0 ? 'red' : m.highFindings > 0 ? 'gold' : 'green',
    },
    {
      title: 'Migration State',
      value: pct(m.migrationCompletionRate),
      detail: `${integer(m.activeMigrationJobs)} active | ${integer(m.failedMigrationJobs)} failed jobs`,
      icon: ScrollText,
      tone: m.failedMigrationJobs > 0 ? 'red' : m.activeMigrationJobs > 0 ? 'gold' : 'green',
    },
    {
      title: 'Key Management',
      value: `${integer(m.secureKeys)} Secure`,
      detail: `${integer(m.keyCount)} generated keys | ${integer(m.mlKemDeployments + m.mlDsaDeployments)} PQC deployments`,
      icon: KeyRound,
      tone: m.keyCount === 0 ? 'muted' : m.secureKeys >= m.keyCount ? 'green' : 'gold',
    },
  ];
}

function buildModalContent(snapshot: ComplianceDashboardSnapshot): Record<ComplianceModalKey, ComplianceModalContent> {
  const { metrics: m } = snapshot;
  const avgFramework = snapshot.frameworkAlignment.length
    ? Math.round(snapshot.frameworkAlignment.reduce((sum, row) => sum + row.score, 0) / snapshot.frameworkAlignment.length)
    : 0;
  const openGaps = snapshot.frameworkAlignment.filter((row) => row.score < 75).length + m.criticalFindings + m.highFindings;
  const latestTrend = snapshot.policyTrend[snapshot.policyTrend.length - 1]?.value || m.complianceScore;
  const previousTrend = snapshot.policyTrend[Math.max(0, snapshot.policyTrend.length - 2)]?.value || latestTrend;

  return {
    frameworks: {
      title: 'Policy Framework Alignment',
      eyebrow: 'Live Control Mapping',
      summary: 'Framework coverage is correlated from authenticated assets, CBOM inventory, runtime telemetry, certificates, migration jobs, and compliance evidence.',
      icon: Landmark,
      metrics: [
        { label: 'Average Alignment', value: pct(avgFramework), tone: complianceTone(avgFramework) },
        { label: 'Mapped Controls', value: integer(snapshot.frameworkAlignment.length), tone: 'green' },
        { label: 'Open Gaps', value: integer(openGaps), tone: openGaps ? 'red' : 'green' },
      ],
      bullets: [
        `${integer(m.totalAssets)} assets and ${integer(m.totalComponents)} cryptographic components are in scope.`,
        `${integer(m.pqcReadyComponents)} components currently show PQC-ready or quantum-safe status.`,
        `Latest activity was synchronized at ${readableDateTime(snapshot.source.latestActivityAt)}.`,
      ],
    },
    maturity: {
      title: 'Policy Maturity Model',
      eyebrow: 'Operating Model',
      summary: 'Maturity reflects evidence freshness, active monitoring, enforced controls, migration progress, and unresolved quantum exposure.',
      icon: Gauge,
      metrics: [
        { label: 'Compliance Score', value: pct(m.complianceScore), tone: complianceTone(m.complianceScore) },
        { label: 'Validation Score', value: pct(m.validationScore), tone: complianceTone(m.validationScore) },
        { label: 'Runtime Events 24h', value: integer(m.runtimeEvents24h), tone: m.runtimeEvents24h ? 'green' : 'muted' },
      ],
      bullets: [
        `${integer(m.enforcedPolicies)} governance controls are currently enforced.`,
        `${integer(m.activeScans)} discovery scans and ${integer(m.activeMigrationJobs)} migration jobs are active.`,
        `${integer(m.scannerAgents)} scanner agents are contributing posture data.`,
      ],
    },
    trend: {
      title: 'Policy Compliance Over Time',
      eyebrow: 'Live Seven-Day Trend',
      summary: 'The trend is generated from real compliance evidence, migration completions, scan output, and risk events observed in the current tenant scope.',
      icon: LineChart,
      metrics: [
        { label: 'Current', value: pct(latestTrend), tone: complianceTone(latestTrend) },
        { label: 'Previous', value: pct(previousTrend), tone: complianceTone(previousTrend) },
        { label: 'Change', value: `${latestTrend - previousTrend >= 0 ? '+' : ''}${latestTrend - previousTrend}%`, tone: latestTrend >= previousTrend ? 'green' : 'red' },
      ],
      bullets: [
        `${integer(m.completedScans)} completed scans are represented in the compliance window.`,
        `${integer(m.remediatedItems)} remediation and migration events improved the current posture.`,
        `${integer(m.hndlExposures)} Harvest Now, Decrypt Later signals remain in scope.`,
      ],
    },
    policies: {
      title: 'Governance Policy Matrix',
      eyebrow: 'Policy Registry',
      summary: 'Policies are derived from active controls, evidence rows, cryptographic inventory coverage, certificate posture, runtime monitoring, and audit retention.',
      icon: ListChecks,
      metrics: [
        { label: 'Enforced', value: integer(m.enforcedPolicies), tone: 'green' },
        { label: 'Total Controls', value: integer(m.totalPolicies), tone: 'gold' },
        { label: 'Policy Score', value: pct(m.policyAdherence), tone: complianceTone(m.policyAdherence) },
      ],
      bullets: [
        `${integer(m.vulnerableComponents)} vulnerable cryptographic components are reflected in control status.`,
        `${integer(m.trustDependencies)} external or internal dependency links affect trust posture.`,
        `${integer(m.auditEvents)} audit and evidence signals are retained for reviewers.`,
      ],
    },
    violations: {
      title: 'Policy Violations',
      eyebrow: 'Exception Queue',
      summary: 'Violations are correlated across exposures, vulnerabilities, compliance evidence, scanner alerts, certificates, HNDL signals, and migration failures.',
      icon: AlertTriangle,
      metrics: [
        { label: 'Critical', value: integer(m.criticalFindings), tone: m.criticalFindings ? 'red' : 'green' },
        { label: 'High', value: integer(m.highFindings), tone: m.highFindings ? 'gold' : 'green' },
        { label: 'Open Items', value: integer(m.openFindings), tone: m.openFindings ? 'red' : 'green' },
      ],
      bullets: [
        `${integer(m.vulnerableAssets)} assets currently carry vulnerable or exposed cryptographic posture.`,
        `${integer(m.expiredCertificates + m.expiringCertificates)} certificate lifecycle issues require review.`,
        `${integer(m.failedMigrationJobs)} migration workflows are failed or need rollback review.`,
      ],
    },
    evidence: {
      title: 'Compliance Requirements Evidence',
      eyebrow: 'Evidence Vault',
      summary: 'Requirement evidence combines policy state, asset scope, certificate health, runtime observations, migration records, and audit trail completeness.',
      icon: FileCheck2,
      metrics: [
        { label: 'Overall Compliance', value: pct(m.complianceScore), tone: complianceTone(m.complianceScore) },
        { label: 'Evidence Items', value: integer(m.auditEvents), tone: 'gold' },
        { label: 'Non-Compliant', value: integer(m.criticalFindings + m.highFindings), tone: m.criticalFindings + m.highFindings ? 'red' : 'green' },
      ],
      bullets: [
        `${integer(m.quantumSecuredAssets)} assets are currently counted as quantum-secured.`,
        `${integer(m.hybridDeployments)} hybrid deployments are visible in telemetry.`,
        `${integer(m.mlKemDeployments)} ML-KEM and ${integer(m.mlDsaDeployments)} ML-DSA deployment signals are recorded.`,
      ],
    },
  };
}

function GlassPanel({
  children,
  className,
  delay = 0,
  as = 'section',
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
  as?: 'section' | 'div';
}) {
  const Component = motion[as];

  return (
    <Component
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, delay, ease: 'easeOut' }}
      className={cx(
        'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 p-5 text-white backdrop-blur-xl transition-all duration-500',
        'shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)]',
        'hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10',
        'before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0]',
        'after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px]',
        className,
      )}
    >
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.08),transparent_28%,rgba(255,211,107,0.04)_58%,transparent)] opacity-60" />
      <div className="relative z-10">{children}</div>
    </Component>
  );
}

function PanelTitle({ icon: Icon, title, action }: { icon?: LucideIcon; title: string; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <div className="flex min-w-0 items-center gap-2">
        {Icon && (
          <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md border border-[#FFD36B]/25 bg-[#FFD36B]/10 text-[#FFD36B] shadow-[0_0_18px_rgba(255,211,107,0.18)]">
            <Icon className="h-3.5 w-3.5" />
          </span>
        )}
        <h2 className="truncate text-sm font-black uppercase text-[#FFE8A8]">{title}</h2>
      </div>
      {action}
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-dashed border-[#FFD36B]/18 bg-white/[0.025] p-5 text-center text-sm font-semibold text-white/45">
      {text}
    </div>
  );
}

function GoldShieldBadge({
  showMetric = true,
  compact = false,
  className,
  score = 0,
  label = 'Awaiting Data',
}: {
  showMetric?: boolean;
  compact?: boolean;
  className?: string;
  score?: number;
  label?: string;
}) {
  return (
    <div
      className={cx(
        'relative mx-auto aspect-[1509/1042] shrink-0 overflow-hidden',
        compact ? 'w-24 max-w-full' : 'w-full max-w-[260px]',
        className,
      )}
    >
      <div className="absolute inset-0 rounded-full bg-[#FFD36B]/12 blur-2xl" />
      <img
        src="/Gold_Shield.png"
        alt="Gold compliance shield"
        className="relative z-10 h-full w-full object-contain drop-shadow-[0_0_24px_rgba(255,179,0,0.28)]"
        loading="eager"
      />
      <div className="absolute inset-0 z-20 grid place-items-center">
        {showMetric ? (
          <div className="translate-y-[3%] text-center">
            <div className="font-mono text-4xl font-black leading-none text-white drop-shadow-[0_0_16px_rgba(255,211,107,0.75)]">{pct(score)}</div>
            <div className="mt-1 text-xs font-black uppercase text-[#FFE8A8] drop-shadow-[0_0_10px_rgba(255,211,107,0.6)]">{label}</div>
            <Check className="mx-auto mt-2 h-7 w-7 text-[#FFD36B] drop-shadow-[0_0_12px_rgba(255,211,107,0.9)]" />
          </div>
        ) : (
          <Check className="h-9 w-9 translate-y-[4%] text-[#FFD36B] drop-shadow-[0_0_12px_rgba(255,211,107,0.8)]" />
        )}
      </div>
    </div>
  );
}

function MiniAnalyticsGraph({ trend }: { trend: ComplianceTrendPoint[] }) {
  const safeTrend = trend.length ? trend : [{ label: 'Current', value: 0 }];
  const values = safeTrend.map((point) => Math.max(0, Math.min(100, point.value)));
  const xFor = (index: number) => 4 + (safeTrend.length <= 1 ? 0 : (index / (safeTrend.length - 1)) * 206);
  const yFor = (value: number) => 64 - (value / 100) * 56;
  const points = values.map((value, index) => `${xFor(index)},${yFor(value)}`).join(' ');

  return (
    <div className="relative h-24 min-w-[210px] overflow-hidden rounded-lg border border-[#FFD36B]/10 p-3 glass-panel">
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(255,211,107,0.08),transparent)]" />
      <svg className="relative h-full w-full" viewBox="0 0 220 72" aria-label="Policy trend graph">
        {[24, 48, 72, 96, 120, 144, 168, 192].map((x) => (
          <line key={x} x1={x} y1="14" x2={x} y2="68" stroke="rgba(255,211,107,0.08)" />
        ))}
        <polyline points={points} fill="none" stroke="#FFD36B" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <polyline points={`${points} 210,72 4,72`} fill="rgba(255,211,107,0.10)" stroke="none" />
        {points.split(' ').map((point) => {
          const [cxPoint, cyPoint] = point.split(',');
          return <circle key={point} cx={cxPoint} cy={cyPoint} r="3" fill="#FFE8A8" stroke="#FFB300" strokeWidth="1.4" />;
        })}
      </svg>
    </div>
  );
}

function OverviewCard({ snapshot }: { snapshot: ComplianceDashboardSnapshot }) {
  const { metrics } = snapshot;
  const overviewStats = [
    { label: 'Compliant', value: integer(metrics.enforcedPolicies), tone: 'green' as Tone },
    { label: 'Violations', value: integer(metrics.openFindings), tone: metrics.openFindings ? 'red' as Tone : 'green' as Tone },
    { label: 'Pending', value: integer(metrics.activeScans + metrics.activeMigrationJobs), tone: metrics.activeScans + metrics.activeMigrationJobs ? 'gold' as Tone : 'muted' as Tone },
    { label: 'Controls', value: integer(metrics.totalPolicies), tone: 'gold' as Tone },
  ];

  return (
    <GlassPanel delay={0.08} className="min-h-[260px]">
      <PanelTitle icon={Shield} title="Quantum Compliance Overview" />
      <div className="grid gap-5 xl:grid-cols-[240px_1fr]">
        <div className="flex min-w-0 items-center justify-center rounded-lg border border-[#FFD36B]/10 px-2 py-3 glass-panel">
          <GoldShieldBadge score={metrics.complianceScore} label={readinessLabel(metrics.complianceScore)} />
        </div>

        <div className="flex min-w-0 flex-col justify-between gap-5">
          <div className="grid gap-4 md:grid-cols-[1fr_230px]">
            <div className="flex items-center gap-4 rounded-lg border border-[#FFD36B]/10 bg-white/[0.03] p-4">
              <div className="grid h-12 w-12 shrink-0 place-items-center rounded-lg border border-[#FFD36B]/25 bg-[#FFD36B]/10 text-[#FFD36B]">
                <FileText className="h-6 w-6" />
              </div>
              <div>
                <div className="text-xs font-bold uppercase text-white/70">Authoritative Controls</div>
                <div className="font-mono text-5xl font-black leading-none text-white">{integer(metrics.totalPolicies)}</div>
              </div>
            </div>
            <MiniAnalyticsGraph trend={snapshot.policyTrend} />
          </div>

          <div className="grid gap-3 sm:grid-cols-4">
            {overviewStats.map((item) => (
              <div key={item.label} className="rounded-lg border border-[#FFD36B]/10 p-3 text-center glass-panel">
                <div className="text-[11px] font-bold uppercase text-white/60">{item.label}</div>
                <div className={cx('mt-2 font-mono text-3xl font-black', toneClasses[item.tone])}>{item.value}</div>
                <div
                  className={cx(
                    'mx-auto mt-2 h-1 w-14 rounded-full',
                    item.tone === 'green' && 'bg-[#4DFF88] shadow-[0_0_12px_rgba(77,255,136,0.8)]',
                    item.tone === 'red' && 'bg-[#FF4D5A] shadow-[0_0_12px_rgba(255,77,90,0.8)]',
                    item.tone === 'gold' && 'bg-[#FFD36B] shadow-[0_0_12px_rgba(255,211,107,0.9)]',
                    item.tone === 'muted' && 'bg-white/45',
                  )}
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </GlassPanel>
  );
}

function SecurityStatusCard({ snapshot }: { snapshot: ComplianceDashboardSnapshot }) {
  const { metrics } = snapshot;
  const label = readinessLabel(metrics.complianceScore);

  return (
    <GlassPanel delay={0.14} className="min-h-[260px]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-lg font-black uppercase text-[#FFD36B]">Q-Security Status: {label}</div>
          <div className="mt-4 font-mono text-xl text-[#FFE8A8]">{pct(metrics.complianceScore)} Compliance</div>
        </div>
        <div className="mr-1 shrink-0 self-start rounded-lg border border-[#FFD36B]/12 p-1.5 glass-panel">
          <GoldShieldBadge compact showMetric={false} score={metrics.complianceScore} label={label} />
        </div>
      </div>

      <div className="mt-5">
        <div className="h-5 overflow-hidden rounded-full border border-[#FFD36B]/30 p-0.5 shadow-[inset_0_0_16px_rgba(0,0,0,0.65)] glass-panel">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${metrics.complianceScore}%` }}
            transition={{ duration: 1.1, delay: 0.3, ease: 'easeOut' }}
            className="relative h-full rounded-full bg-[linear-gradient(90deg,#FFB300,#FFF0B3,#FFD36B,#FFB300)] shadow-[0_0_22px_rgba(255,179,0,0.7)]"
          >
            <span className="absolute inset-0 compliance-shimmer rounded-full" />
          </motion.div>
        </div>
      </div>

      <div className="my-5 h-px bg-gradient-to-r from-transparent via-[#FFD36B]/22 to-transparent" />

      <div className="space-y-3">
        {[
          `${integer(metrics.quantumSecuredAssets)} quantum-secured assets, ${integer(metrics.vulnerableAssets)} vulnerable assets in scope.`,
          `${integer(metrics.mlKemDeployments)} ML-KEM and ${integer(metrics.mlDsaDeployments)} ML-DSA deployment signals synchronized.`,
          `${integer(metrics.auditEvents)} audit and compliance evidence events retained.`,
        ].map((item) => (
          <div key={item} className="flex items-center gap-3 text-sm text-white/72">
            <span className="h-2.5 w-2.5 rounded-full bg-[#4DFF88] shadow-[0_0_14px_rgba(77,255,136,0.82)]" />
            <span>{item}</span>
          </div>
        ))}
      </div>
    </GlassPanel>
  );
}

function MetricTile({ metric, index }: { metric: MetricCard; index: number }) {
  const Icon = metric.icon;

  return (
    <GlassPanel as="div" delay={0.18 + index * 0.04} className="min-h-[132px] p-4">
      <div className="flex items-start gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-lg border border-[#FFD36B]/24 bg-[#FFD36B]/9 text-[#FFD36B] shadow-[0_0_22px_rgba(255,211,107,0.12)]">
          <Icon className="h-[22px] w-[22px]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="max-w-[12rem] text-[13px] font-black uppercase leading-tight text-white/88">{metric.title}</div>
          <div className={cx('mt-1.5 whitespace-nowrap font-mono text-[clamp(1rem,1.45vw,1.25rem)] font-black leading-none', toneClasses[metric.tone])}>
            {metric.value}
          </div>
          <div className="mt-2 max-w-[11rem] text-xs leading-snug text-white/62">{metric.detail}</div>
        </div>
      </div>
    </GlassPanel>
  );
}

function ChecklistPanel({ items }: { items: ComplianceDashboardSnapshot['checklist'] }) {
  const completed = items.filter((item) => item.complete).length;

  return (
    <GlassPanel delay={0.2} className="min-h-[350px]">
      <PanelTitle
        icon={ClipboardCheck}
        title="Compliance Checklist"
        action={<span className="font-mono text-xs font-black text-[#FFD36B]">{completed} / {items.length || 0} COMPLETE</span>}
      />

      <div className="grid items-center gap-6 xl:grid-cols-[minmax(320px,0.95fr)_minmax(360px,1.05fr)]">
        <div className="relative min-w-0">
          <div className="relative mx-auto aspect-[1484/1060] w-full max-w-[460px] overflow-hidden rounded-lg border border-[#FFD36B]/18 p-2 shadow-[inset_0_0_28px_rgba(255,211,107,0.05),0_0_28px_rgba(255,211,107,0.10)] glass-panel">
            <div className="pointer-events-none absolute inset-0 rounded-lg bg-[radial-gradient(circle_at_50%_74%,rgba(255,211,107,0.14),transparent_58%)]" />
            <img
              src="/compliance.png"
              alt="Quantum compliance verification shield"
              className="relative z-10 h-full w-full rounded-md object-contain"
              loading="eager"
            />
            <div className="pointer-events-none absolute inset-x-8 bottom-4 h-px bg-gradient-to-r from-transparent via-[#FFD36B]/45 to-transparent" />
          </div>
        </div>

        <div className="rounded-lg border border-[#FFD36B]/10 p-3 glass-panel">
          {items.length === 0 && <EmptyState text="No compliance checklist signals are available yet. Run discovery or connect telemetry to populate this control list." />}
          {items.map((item) => (
            <div
              key={item.label}
              className="group/check flex items-center gap-3 border-b border-[#FFD36B]/10 px-2 py-3 last:border-b-0 hover:bg-[#FFD36B]/6"
            >
              <span
                className={cx(
                  'grid h-5 w-5 shrink-0 place-items-center rounded-full border',
                  item.complete
                    ? 'border-[#4DFF88]/70 bg-[#4DFF88]/10 text-[#4DFF88] shadow-[0_0_12px_rgba(77,255,136,0.24)]'
                    : 'border-[#FFD36B]/55 bg-[#FFD36B]/5 text-[#FFD36B]',
                )}
              >
                {item.complete ? <Check className="h-3.5 w-3.5" /> : <span className="h-2 w-2 rounded-full border border-current" />}
              </span>
              <span className="min-w-0 flex-1 text-sm font-semibold text-white/78 group-hover/check:text-white">
                {item.label}
                {item.detail && <span className="mt-0.5 block text-xs font-medium text-white/45">{item.detail}</span>}
              </span>
              {item.complete ? <Check className="h-4 w-4 text-[#4DFF88]" /> : <AlertTriangle className="h-4 w-4 text-[#FFD36B]" />}
            </div>
          ))}
        </div>
      </div>
    </GlassPanel>
  );
}

function StatusPill({ status }: { status: ComplianceCertificateRow['status'] }) {
  const config = {
    Active: 'border-[#4DFF88]/25 bg-[#4DFF88]/12 text-[#4DFF88]',
    Expired: 'border-[#FF4D5A]/25 bg-[#FF4D5A]/12 text-[#FF4D5A]',
    'Expiring Soon': 'border-[#FFD36B]/28 bg-[#FFD36B]/12 text-[#FFD36B]',
  }[status];

  return <span className={cx('inline-flex rounded-md border px-2.5 py-1 text-xs font-bold', config)}>{status}</span>;
}

function EnterpriseTable({
  title,
  icon,
  children,
}: {
  title: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <GlassPanel delay={0.28} className="p-0">
      <div className="px-5 pt-4">
        <PanelTitle
          icon={icon}
          title={title}
          action={
            <button
              type="button"
              title={`View all ${title.toLowerCase()}`}
              className="inline-flex items-center gap-2 rounded-md border border-[#FFD36B]/24 bg-[#FFD36B]/8 px-3 py-1.5 text-xs font-bold text-[#FFD36B] transition hover:bg-[#FFD36B]/14"
            >
              View All
              <ChevronDown className="h-3.5 w-3.5 -rotate-90" />
            </button>
          }
        />
      </div>
      <div className="overflow-x-auto px-5 pb-4">{children}</div>
    </GlassPanel>
  );
}

function CertificateTable({ rows }: { rows: ComplianceCertificateRow[] }) {
  return (
    <EnterpriseTable title="Digital Certificate Status" icon={BadgeCheck}>
      <table className="w-full min-w-[620px] border-collapse text-left">
        <thead>
          <tr className="border-y border-[#FFD36B]/16 bg-[#FFD36B]/8">
            {['Algorithm', 'Issued To', 'Issued On', 'Expires On', 'Status'].map((header) => (
              <th key={header} className="px-3 py-2.5 text-xs font-black uppercase text-[#FFE8A8]">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cert) => (
            <tr key={`${cert.algorithm}-${cert.issuedTo}-${cert.status}`} className="border-b border-[#FFD36B]/8 transition hover:bg-[#FFD36B]/7">
              <td className="px-3 py-2.5 font-mono text-xs text-white/82">{cert.algorithm}</td>
              <td className="px-3 py-2.5 text-xs text-white/70">{cert.issuedTo}</td>
              <td className="px-3 py-2.5 font-mono text-xs text-white/68">{cert.issuedOn}</td>
              <td className="px-3 py-2.5 font-mono text-xs text-white/68">{cert.expiresOn}</td>
              <td className="px-3 py-2.5">
                <StatusPill status={cert.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <EmptyState text="No certificate telemetry has been recorded for this account yet." />}
    </EnterpriseTable>
  );
}

function PolicyTable({ rows }: { rows: CompliancePolicyRow[] }) {
  return (
    <EnterpriseTable title="Governance Policies" icon={ShieldCheck}>
      <table className="w-full min-w-[620px] border-collapse text-left">
        <thead>
          <tr className="border-y border-[#FFD36B]/16 bg-[#FFD36B]/8">
            {['Policy Name', 'Category', 'Status', 'Last Reviewed'].map((header) => (
              <th key={header} className="px-3 py-2.5 text-xs font-black uppercase text-[#FFE8A8]">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((policy, index) => (
            <tr key={`${policy.name}-${index}`} className="border-b border-[#FFD36B]/8 transition hover:bg-[#FFD36B]/7">
              <td className="px-3 py-2.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-white/82">
                  <FileText className="h-3.5 w-3.5 text-[#FFD36B]" />
                  {policy.name}
                </div>
              </td>
              <td className="px-3 py-2.5 text-xs text-white/68">{policy.category}</td>
              <td className="px-3 py-2.5">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-[#4DFF88]/20 bg-[#4DFF88]/10 px-2.5 py-1 text-xs font-bold text-[#4DFF88]">
                  <Check className="h-3 w-3" />
                  {policy.status}
                </span>
              </td>
              <td className="px-3 py-2.5 font-mono text-xs text-white/68">{policy.lastReviewed}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <EmptyState text="No compliance policies or evidence rows have been synchronized yet." />}
    </EnterpriseTable>
  );
}

function GoldActionButton({
  label,
  onClick,
  title,
}: {
  label: string;
  onClick: () => void;
  title?: string;
}) {
  return (
    <button
      type="button"
      title={title ?? label}
      onClick={onClick}
      className="inline-flex h-9 w-full items-center justify-center gap-2 rounded-md border border-[#FFD36B]/18 bg-[#FFD36B]/8 px-3 text-xs font-black text-[#FFD36B] transition hover:border-[#FFD36B]/38 hover:bg-[#FFD36B]/14 focus:outline-none focus:ring-2 focus:ring-[#FFD36B]/40"
    >
      <span className="truncate">{label}</span>
      <ArrowRight className="h-3.5 w-3.5 shrink-0" />
    </button>
  );
}

function ComplianceDetailModal({
  active,
  onClose,
  contentMap,
}: {
  active: ComplianceModalKey | null;
  onClose: () => void;
  contentMap: Record<ComplianceModalKey, ComplianceModalContent>;
}) {
  const content = active ? contentMap[active] : null;
  const Icon = content?.icon ?? Info;

  return (
    <AnimatePresence>
      {content && (
        <motion.div
          key={active}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[80] grid place-items-center p-4 glass-panel"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.24, ease: 'easeOut' }}
            role="dialog"
            aria-modal="true"
            aria-labelledby="compliance-modal-title"
            className="relative max-h-[min(86vh,720px)] w-full max-w-3xl overflow-y-auto rounded-lg border border-[#FFD36B]/25 bg-[#070A14]/96 p-5 text-white shadow-[0_0_70px_rgba(255,211,107,0.18)]"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#FFF4C0]/70 to-transparent" />
            <button
              type="button"
              title="Close detail panel"
              onClick={onClose}
              className="absolute right-4 top-4 grid h-9 w-9 place-items-center rounded-md border border-white/10 bg-white/[0.03] text-white/60 transition hover:border-[#FFD36B]/28 hover:text-[#FFD36B] focus:outline-none focus:ring-2 focus:ring-[#FFD36B]/40"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-start gap-4 pr-12">
              <div className="grid h-12 w-12 shrink-0 place-items-center rounded-lg border border-[#FFD36B]/24 bg-[#FFD36B]/10 text-[#FFD36B] shadow-[0_0_22px_rgba(255,211,107,0.16)]">
                <Icon className="h-6 w-6" />
              </div>
              <div className="min-w-0">
                <div className="text-[11px] font-black uppercase text-[#FFD36B]/78">{content.eyebrow}</div>
                <h2 id="compliance-modal-title" className="mt-1 text-2xl font-black leading-tight text-[#FFE8A8]">
                  {content.title}
                </h2>
                <p className="mt-3 max-w-2xl text-sm leading-6 text-white/70">{content.summary}</p>
              </div>
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {content.metrics.map((metric) => (
                <div key={metric.label} className="rounded-lg border border-[#FFD36B]/10 bg-white/[0.03] p-3">
                  <div className="text-[11px] font-bold uppercase text-white/50">{metric.label}</div>
                  <div className={cx('mt-2 font-mono text-3xl font-black leading-none', toneClasses[metric.tone])}>{metric.value}</div>
                </div>
              ))}
            </div>

            <div className="mt-6 rounded-lg border border-[#FFD36B]/10 p-4 glass-panel">
              <div className="mb-3 text-xs font-black uppercase text-[#FFE8A8]">Executive Notes</div>
              <div className="space-y-3">
                {content.bullets.map((bullet) => (
                  <div key={bullet} className="flex gap-3 text-sm leading-6 text-white/72">
                    <Check className="mt-1 h-4 w-4 shrink-0 text-[#4DFF88]" />
                    <span>{bullet}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function FrameworkRadar({ items }: { items: ComplianceFrameworkAlignment[] }) {
  const safeItems = items.length ? items : [{ name: 'Awaiting Evidence', score: 0 }];

  return (
    <div className="relative mx-auto aspect-square w-full max-w-[230px]">
      <div className="absolute inset-3 rounded-full border border-[#FFD36B]/12" />
      <div className="absolute inset-8 rounded-full border border-[#FFD36B]/18" />
      <div className="absolute inset-14 rounded-full border border-[#FFD36B]/24" />
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" aria-label="Framework radar alignment">
        {[0, 30, 60, 90, 120, 150].map((angle) => (
          <line
            key={angle}
            x1="50"
            y1="50"
            x2={50 + Math.cos((angle * Math.PI) / 180) * 42}
            y2={50 + Math.sin((angle * Math.PI) / 180) * 42}
            stroke="rgba(255,211,107,0.16)"
            strokeWidth="0.55"
          />
        ))}
        <polygon
          points="50,21 72,34 72,63 50,78 28,63 28,34"
          fill="rgba(255,211,107,0.10)"
          stroke="rgba(255,211,107,0.70)"
          strokeWidth="1.8"
        />
        <polygon points="50,28 64,38 64,59 50,69 36,59 36,38" fill="rgba(255,179,0,0.20)" stroke="rgba(255,244,192,0.50)" />
      </svg>
      {safeItems.map((framework, index) => {
        const angle = (index / safeItems.length) * Math.PI * 2 - Math.PI / 2;
        const left = 50 + Math.cos(angle) * 41;
        const top = 50 + Math.sin(angle) * 41;

        return (
          <span
            key={framework.name}
            title={`${framework.name}: ${framework.score}%`}
            className="absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#FFE8A8] bg-[#FFD36B] shadow-[0_0_16px_rgba(255,211,107,0.92)]"
            style={{ left: `${left}%`, top: `${top}%` }}
          />
        );
      })}
      <div className="absolute inset-0 grid place-items-center">
        <div className="grid h-16 w-16 place-items-center rounded-lg border border-[#FFD36B]/34 text-[#FFD36B] shadow-[inset_0_0_20px_rgba(255,211,107,0.10),0_0_28px_rgba(255,211,107,0.22)] glass-panel">
          <Landmark className="h-9 w-9" />
        </div>
      </div>
    </div>
  );
}

function PolicyFrameworkAlignmentPanel({ onOpen, alignment }: { onOpen: () => void; alignment: ComplianceFrameworkAlignment[] }) {
  const safeAlignment = alignment.length ? alignment : [{ name: 'Awaiting Evidence', score: 0 }];

  return (
    <GlassPanel delay={0.32} className="min-h-[350px]">
      <PanelTitle icon={Landmark} title="Policy Framework Alignment" />

      <div className="grid gap-5 sm:grid-cols-[minmax(160px,0.85fr)_minmax(220px,1fr)] xl:grid-cols-1">
        <FrameworkRadar items={safeAlignment} />

        <div className="flex min-w-0 flex-col justify-center gap-3">
          {safeAlignment.map((framework) => (
            <div key={framework.name} className="grid grid-cols-[minmax(118px,1fr)_minmax(78px,0.9fr)_44px] items-center gap-3">
              <div className="truncate text-xs font-bold text-white/72">{framework.name}</div>
              <div className="h-1.5 overflow-hidden rounded-full bg-[#FFD36B]/8">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${framework.score}%` }}
                  transition={{ duration: 0.85, delay: 0.35, ease: 'easeOut' }}
                  className="h-full rounded-full bg-[linear-gradient(90deg,#4D3910,#FFD36B)] shadow-[0_0_12px_rgba(255,211,107,0.55)]"
                />
              </div>
              <div className="text-right font-mono text-sm font-black text-[#FFE8A8]">{framework.score}%</div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-5">
        <GoldActionButton label="View All Frameworks" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function PolicyMaturityPanel({ onOpen, levels, score }: { onOpen: () => void; levels: ComplianceMaturityLevel[]; score: number }) {
  const safeLevels = levels.length ? levels : [{ label: 'Level 1 - Initial', value: 0, color: '#2B210B' }];
  const currentLevel = score >= 90 ? 5 : score >= 70 ? 4 : score >= 45 ? 3 : score >= 20 ? 2 : 1;
  const currentLabel = currentLevel === 5 ? 'Optimized' : currentLevel === 4 ? 'Managed' : currentLevel === 3 ? 'Defined' : currentLevel === 2 ? 'Repeatable' : 'Initial';

  return (
    <GlassPanel delay={0.36} className="min-h-[350px]">
      <PanelTitle icon={Gauge} title="Policy Maturity Model" />

      <div className="grid items-center gap-5 sm:grid-cols-[minmax(180px,0.85fr)_minmax(220px,1fr)] xl:grid-cols-1">
        <div className="relative mx-auto aspect-square w-full max-w-[230px] rounded-full border border-[#FFD36B]/18 p-4">
          <div
            className="absolute inset-4 rounded-full shadow-[0_0_36px_rgba(255,211,107,0.14)]"
            style={{
              background:
                `conic-gradient(#FFD36B 0% ${Math.max(0, Math.min(100, score))}%, rgba(255,211,107,0.08) ${Math.max(0, Math.min(100, score))}% 100%)`,
            }}
          />
          <div className="absolute inset-[28%] rounded-full border border-[#FFD36B]/18 bg-[#070A14] shadow-[inset_0_0_28px_rgba(255,211,107,0.10)]" />
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="text-xs font-bold text-[#FFD36B]/80">Level</div>
              <div className="font-mono text-6xl font-black leading-none text-white drop-shadow-[0_0_18px_rgba(255,211,107,0.48)]">{currentLevel}</div>
              <div className="mt-1 text-xs font-bold text-white/68">{currentLabel}</div>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          {safeLevels.map((level) => (
            <div key={level.label} className="grid grid-cols-[18px_minmax(0,1fr)_42px] items-center gap-3 text-sm">
              <span className="h-2.5 w-2.5 rounded-sm border border-[#FFD36B]/35" style={{ backgroundColor: level.color }} />
              <span className="truncate text-white/70">{level.label}</span>
              <span className="text-right font-mono text-xs font-black text-white/72">{level.value}%</span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-5">
        <GoldActionButton label="View Maturity Model" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function PolicyTrendPanel({ onOpen, trend }: { onOpen: () => void; trend: ComplianceTrendPoint[] }) {
  const safeTrend = trend.length ? trend : [{ label: 'Current', value: 0 }];
  const width = 430;
  const height = 224;
  const left = 42;
  const right = 416;
  const top = 20;
  const bottom = 152;
  const xFor = (index: number) => left + (safeTrend.length <= 1 ? 0 : (index / (safeTrend.length - 1)) * (right - left));
  const yFor = (value: number) => bottom - (value / 100) * (bottom - top);
  const points = safeTrend.map((point, index) => `${xFor(index)},${yFor(point.value)}`).join(' ');
  const areaPoints = `${points} ${xFor(safeTrend.length - 1)},${bottom} ${xFor(0)},${bottom}`;
  const current = safeTrend[safeTrend.length - 1]?.value || 0;
  const previous = safeTrend[Math.max(0, safeTrend.length - 2)]?.value || current;

  return (
    <GlassPanel delay={0.4} className="min-h-[350px]">
      <PanelTitle icon={LineChart} title="Policy Compliance Over Time" />

      <div className="rounded-lg border border-[#FFD36B]/10 p-2 glass-panel">
        <svg className="h-[220px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Policy compliance trend">
          {[0, 25, 50, 75, 100].map((tick) => {
            const y = yFor(tick);
            return (
              <g key={tick}>
                <line x1={left} y1={y} x2={right} y2={y} stroke="rgba(255,211,107,0.12)" strokeWidth="1" />
                <text x="8" y={y + 4} fill="rgba(255,255,255,0.62)" fontSize="11" fontFamily="monospace">
                  {tick}%
                </text>
              </g>
            );
          })}
          <polygon points={areaPoints} fill="rgba(255,179,0,0.18)" />
          <polyline points={points} fill="none" stroke="#FFD36B" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          {safeTrend.map((point, index) => (
            <g key={point.label}>
              <circle cx={xFor(index)} cy={yFor(point.value)} r="4" fill="#FFE8A8" stroke="#FFB300" strokeWidth="2" />
              <text x={xFor(index)} y="196" textAnchor="middle" fill="rgba(255,255,255,0.58)" fontSize="10" fontFamily="monospace">
                {point.label}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="mt-3 grid grid-cols-3 overflow-hidden rounded-lg border border-[#FFD36B]/10 bg-white/[0.03]">
        {[
          { label: 'Current', value: pct(current), tone: complianceTone(current) },
          { label: 'Previous', value: pct(previous), tone: complianceTone(previous) },
          { label: 'Change', value: `${current - previous >= 0 ? '+' : ''}${current - previous}%`, tone: current >= previous ? 'green' as Tone : 'red' as Tone },
        ].map((stat) => (
          <div key={stat.label} className="border-r border-[#FFD36B]/10 p-3 text-center last:border-r-0">
            <div className="text-[11px] font-black uppercase text-[#FFD36B]/78">{stat.label}</div>
            <div className={cx('mt-1 font-mono text-2xl font-black leading-none', toneClasses[stat.tone])}>{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-3">
        <GoldActionButton label="View Trend Evidence" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function GovernanceStatusBadge({ status }: { status: ComplianceGovernancePolicyRow['status'] }) {
  const config =
    status === 'Enforced'
      ? 'border-[#4DFF88]/24 bg-[#4DFF88]/10 text-[#4DFF88]'
      : 'border-[#FFD36B]/26 bg-[#FFD36B]/10 text-[#FFD36B]';

  return <span className={cx('inline-flex rounded-md border px-2 py-1 text-[11px] font-black', config)}>{status}</span>;
}

function GovernancePolicyMatrixPanel({ onOpen, rows }: { onOpen: () => void; rows: ComplianceGovernancePolicyRow[] }) {
  return (
    <GlassPanel delay={0.44} className="min-h-[350px] p-0">
      <div className="px-5 pt-4">
        <PanelTitle icon={ListChecks} title="Governance Policies" />
      </div>
      <div className="overflow-x-auto px-5">
        <table className="w-full min-w-[680px] border-collapse text-left">
          <thead>
            <tr className="border-y border-[#FFD36B]/12 bg-[#FFD36B]/7">
              {['Policy Name', 'Category', 'Status', 'Coverage', 'Last Updated', 'Action'].map((header) => (
                <th key={header} className="px-2.5 py-2 text-[10px] font-black uppercase text-[#FFE8A8]">
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((policy) => (
              <tr key={policy.name} className="border-b border-[#FFD36B]/8 hover:bg-[#FFD36B]/6">
                <td className="px-2.5 py-2.5 text-xs font-semibold text-white/82">{policy.name}</td>
                <td className="px-2.5 py-2.5 text-xs text-white/62">{policy.category}</td>
                <td className="px-2.5 py-2.5">
                  <GovernanceStatusBadge status={policy.status} />
                </td>
                <td className="px-2.5 py-2.5 font-mono text-xs font-black text-white/78">{policy.coverage}%</td>
                <td className="px-2.5 py-2.5 font-mono text-[11px] text-white/58">{policy.updated}</td>
                <td className="px-2.5 py-2.5">
                  <button
                    type="button"
                    title={`Inspect ${policy.name}`}
                    onClick={onOpen}
                    className="grid h-7 w-7 place-items-center rounded-md border border-[#FFD36B]/16 bg-[#FFD36B]/8 text-[#FFD36B] transition hover:border-[#FFD36B]/36 hover:bg-[#FFD36B]/14 focus:outline-none focus:ring-2 focus:ring-[#FFD36B]/35"
                  >
                    <Eye className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <EmptyState text="No governance policy controls have been synchronized yet." />}
      </div>
      <div className="p-5 pt-4">
        <GoldActionButton label="View All Policies" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function SeverityBadge({ severity }: { severity: CompliancePolicyViolation['severity'] }) {
  const config = {
    High: 'border-[#FF4D5A]/28 bg-[#FF4D5A]/12 text-[#FF6A73]',
    Medium: 'border-[#FFD36B]/30 bg-[#FFD36B]/10 text-[#FFD36B]',
    Low: 'border-[#4DFF88]/25 bg-[#4DFF88]/10 text-[#4DFF88]',
  }[severity];

  return <span className={cx('inline-flex rounded-md border px-2.5 py-1 text-xs font-black', config)}>{severity}</span>;
}

function PolicyViolationsPanel({ onOpen, rows }: { onOpen: () => void; rows: CompliancePolicyViolation[] }) {
  return (
    <GlassPanel delay={0.48} className="min-h-[350px]">
      <PanelTitle icon={AlertTriangle} title="Policy Violations" />

      <div className="space-y-1">
        {rows.length === 0 && <EmptyState text="No open compliance violations are currently correlated from live telemetry." />}
        {rows.map((violation) => {
          const Icon = violation.type === 'warning' ? AlertTriangle : Info;
          const iconClass = violation.severity === 'Low' ? 'text-[#65CFFF] border-[#65CFFF]/35 bg-[#65CFFF]/8' : 'text-[#FFD36B] border-[#FFD36B]/35 bg-[#FFD36B]/8';

          return (
            <div key={violation.title} className="grid grid-cols-[34px_minmax(0,1fr)_70px_54px] items-center gap-3 border-b border-[#FFD36B]/8 py-3 last:border-b-0">
              <div className={cx('grid h-7 w-7 place-items-center rounded-md border', iconClass)}>
                <Icon className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="truncate text-sm font-bold text-white/84">{violation.title}</div>
                <div className="truncate text-xs text-white/55">{violation.detail}</div>
              </div>
              <SeverityBadge severity={violation.severity} />
              <div className="text-right font-mono text-[11px] text-white/50">{violation.time}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-4">
        <GoldActionButton label="View All Violations" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function ComplianceRequirementsPanel({
  onOpen,
  className,
  rows,
  score,
}: {
  onOpen: () => void;
  className?: string;
  rows: ComplianceRequirementBreakdown[];
  score: number;
}) {
  const safeRows = rows.length ? rows : [{ label: 'Awaiting Evidence', value: 0, color: '#B8B8B8' }];
  const total = Math.max(1, safeRows.reduce((sum, item) => sum + item.value, 0));
  const compliant = safeRows.find((item) => item.label.toLowerCase().includes('compliant') && !item.label.toLowerCase().includes('non'))?.value || 0;
  const compliantDegrees = Math.round((compliant / total) * 100);

  return (
    <GlassPanel delay={0.52} className={cx('min-h-[350px]', className)}>
      <PanelTitle icon={FileCheck2} title="Compliance Requirements" />

      <div className="grid items-center gap-5 sm:grid-cols-[minmax(190px,0.86fr)_minmax(220px,1fr)] 2xl:grid-cols-1">
        <div className="relative mx-auto aspect-square w-full max-w-[245px] rounded-full border border-[#FFD36B]/12 p-3">
          <div
            className="absolute inset-3 rounded-full shadow-[0_0_42px_rgba(77,255,136,0.14)]"
            style={{
              background:
                `conic-gradient(#42D95B 0% ${compliantDegrees}%, #FFCF33 ${compliantDegrees}% ${Math.max(compliantDegrees, Math.min(100, compliantDegrees + 14))}%, #FF5D52 ${Math.max(compliantDegrees, Math.min(100, compliantDegrees + 14))}% 100%)`,
            }}
          />
          <div className="absolute inset-[29%] rounded-full border border-[#FFD36B]/14 bg-[#070A14] shadow-[inset_0_0_28px_rgba(0,0,0,0.85)]" />
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="font-mono text-4xl font-black leading-none text-white">{pct(score)}</div>
              <div className="mt-1 text-xs font-bold text-white/62">Overall Compliance</div>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {safeRows.map((requirement) => {
            const percentage = Math.round((requirement.value / total) * 100);

            return (
              <div key={requirement.label} className="grid grid-cols-[18px_minmax(0,1fr)_82px] items-center gap-3">
                <span className="h-3 w-3 rounded-sm shadow-[0_0_12px_rgba(255,255,255,0.12)]" style={{ backgroundColor: requirement.color }} />
                <span className="truncate text-sm text-white/72">{requirement.label}</span>
                <span className="text-right font-mono text-sm text-white/78">
                  {requirement.value} ({percentage}%)
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-5">
        <GoldActionButton label="View Compliance Evidence" onClick={onOpen} />
      </div>
    </GlassPanel>
  );
}

function CapabilityRail({ highlights }: { highlights: ComplianceCapabilityHighlight[] }) {
  const safeHighlights = highlights.length ? highlights : [];

  return (
    <div className="grid overflow-hidden rounded-lg border border-[#FFD36B]/18 text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.05),0_0_30px_rgba(255,211,107,0.10)] sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6 glass-panel">
      {safeHighlights.length === 0 && (
        <div className="col-span-full p-4">
          <EmptyState text="Compliance capability telemetry will appear after scans, runtime events, or audit evidence are synchronized." />
        </div>
      )}
      {safeHighlights.map((item) => {
        const Icon = capabilityIconMap[item.iconKey] || ShieldCheck;

        return (
          <div key={item.label} className="flex min-w-0 items-center gap-3 border-b border-r border-[#FFD36B]/10 p-4 last:border-r-0 2xl:border-b-0">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-[#FFD36B]/28 bg-[#FFD36B]/10 text-[#FFD36B]">
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="truncate text-xs font-black uppercase text-[#FFD36B]">{item.label}</div>
              <div className="mt-1 truncate text-xs text-white/58">{item.detail}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PolicyIntelligenceSection({ onOpen, snapshot }: { onOpen: (key: ComplianceModalKey) => void; snapshot: ComplianceDashboardSnapshot }) {
  return (
    <section className="space-y-4" aria-labelledby="policy-intelligence-heading">
      <div className="flex flex-col gap-3 rounded-lg border border-[#FFD36B]/14 px-4 py-3 sm:flex-row sm:items-center sm:justify-between glass-panel">
        <div className="min-w-0">
          <div className="text-[11px] font-black uppercase text-[#FFD36B]/74">Governance Intelligence</div>
          <h2 id="policy-intelligence-heading" className="mt-1 text-xl font-black uppercase leading-tight text-[#FFE8A8]">
            Policy Control Center
          </h2>
        </div>
        <div className="inline-flex w-fit items-center gap-2 rounded-md border border-[#4DFF88]/20 bg-[#4DFF88]/8 px-3 py-2 text-xs font-black text-[#4DFF88]">
          <span className="h-2 w-2 rounded-full bg-[#4DFF88] shadow-[0_0_12px_rgba(77,255,136,0.8)]" />
          Continuous Evidence Sync
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <PolicyFrameworkAlignmentPanel alignment={snapshot.frameworkAlignment} onOpen={() => onOpen('frameworks')} />
        <PolicyMaturityPanel levels={snapshot.maturityLevels} score={snapshot.metrics.complianceScore} onOpen={() => onOpen('maturity')} />
        <PolicyTrendPanel trend={snapshot.policyTrend} onOpen={() => onOpen('trend')} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2 2xl:grid-cols-[minmax(0,1.15fr)_minmax(330px,0.85fr)_minmax(330px,0.95fr)]">
        <GovernancePolicyMatrixPanel rows={snapshot.governancePolicyMatrix} onOpen={() => onOpen('policies')} />
        <PolicyViolationsPanel rows={snapshot.policyViolations} onOpen={() => onOpen('violations')} />
        <ComplianceRequirementsPanel rows={snapshot.requirementBreakdown} score={snapshot.metrics.complianceScore} onOpen={() => onOpen('evidence')} className="xl:col-span-2 2xl:col-span-1" />
      </div>

      <CapabilityRail highlights={snapshot.capabilityHighlights} />
    </section>
  );
}

function BackgroundAtmosphere() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      <div className="absolute inset-0 bg-[#050816]" />
      <div className="absolute -right-24 -top-36 h-[560px] w-[560px] rounded-full border border-[#FFD36B]/18 bg-[radial-gradient(circle,rgba(255,211,107,0.20),rgba(255,179,0,0.06)_38%,transparent_68%)] shadow-[0_0_120px_rgba(255,179,0,0.22)]" />
      <div className="absolute left-1/4 top-0 h-80 w-[520px] bg-[radial-gradient(circle,rgba(255,211,107,0.13),transparent_68%)] blur-3xl" />
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,211,107,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(255,211,107,0.04)_1px,transparent_1px)] bg-[size:48px_48px] opacity-50" />
      <svg className="absolute right-0 top-0 h-[360px] w-[700px] opacity-70" viewBox="0 0 700 360">
        <path d="M45 140 168 62 286 122 430 38 622 84" fill="none" stroke="rgba(255,211,107,0.33)" strokeWidth="1" />
        <path d="M110 262 286 122 372 238 622 84 670 186" fill="none" stroke="rgba(255,211,107,0.18)" strokeWidth="1" />
        <path d="M168 62 372 238 430 38" fill="none" stroke="rgba(255,211,107,0.16)" strokeWidth="1" />
        {[45, 168, 286, 430, 622, 110, 372, 670].map((x, index) => (
          <circle
            key={`${x}-${index}`}
            cx={x}
            cy={[140, 62, 122, 38, 84, 262, 238, 186][index]}
            r={index % 3 === 0 ? 4 : 2.8}
            fill="#FFD36B"
            opacity="0.88"
          />
        ))}
      </svg>
      {particles.map((particle) => (
        <motion.span
          key={`${particle.left}-${particle.top}`}
          className="absolute rounded-full bg-[#FFD36B] shadow-[0_0_14px_rgba(255,211,107,0.95)]"
          style={{ left: particle.left, top: particle.top, width: particle.size, height: particle.size }}
          animate={{ y: [0, -14, 0], opacity: [0.15, 0.85, 0.15] }}
          transition={{ duration: particle.duration, delay: particle.delay, repeat: Infinity, ease: 'easeInOut' }}
        />
      ))}
    </div>
  );
}

function Header({
  snapshot,
  loading,
  error,
  connected,
  onRefresh,
}: {
  snapshot: ComplianceDashboardSnapshot;
  loading: boolean;
  error: string | null;
  connected: boolean;
  onRefresh: () => void;
}) {
  const alertCount = snapshot.metrics.criticalFindings + snapshot.metrics.highFindings + snapshot.metrics.failedMigrationJobs;

  return (
    <header className="relative z-10 mb-5 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
      <div>
        <motion.h1
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55 }}
          className="text-4xl font-black leading-none text-[#FFE8A8] drop-shadow-[0_0_24px_rgba(255,211,107,0.34)] md:text-6xl"
        >
          Qguard Helix
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, delay: 0.08 }}
          className="mt-2 text-base font-medium text-white/82"
        >
          Unified real-time governance, compliance, and quantum-readiness command layer
        </motion.p>
        <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-black uppercase tracking-[0.12em] text-white/45">
          <span>Latest Scan: {readableDateTime(snapshot.source.latestScanAt)}</span>
          <span className="text-[#FFD36B]/50">/</span>
          <span>Activity: {readableDateTime(snapshot.source.latestActivityAt)}</span>
          {error && <span className="text-[#FF6A73]">/ {error}</span>}
        </div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.55, delay: 0.1 }}
        className="flex flex-wrap items-center gap-3"
      >
        <button
          type="button"
          title="Compliance notifications"
          className="inline-flex h-12 items-center gap-2 rounded-lg border border-[#FFD36B]/22 px-4 text-[#FFD36B] transition hover:border-[#FFD36B]/45 hover:bg-[#FFD36B]/10 glass-panel"
        >
          <Bell className="h-5 w-5" />
          <span className="grid h-5 min-w-5 place-items-center rounded-full bg-[#FFD36B] px-1 font-mono text-xs font-black text-[#050816]">{integer(alertCount)}</span>
        </button>
        <button
          type="button"
          title="Refresh compliance telemetry"
          onClick={onRefresh}
          className="inline-flex h-12 items-center gap-2 rounded-lg border border-[#FFD36B]/22 px-4 text-white/85 transition hover:border-[#FFD36B]/45 hover:bg-[#FFD36B]/10 glass-panel"
        >
          <RefreshCw className={cx('h-5 w-5 text-[#FFD36B]', loading && 'animate-spin')} />
          <span className="text-sm font-bold">REFRESH</span>
        </button>
        <button
          type="button"
          title="Live compliance stream status"
          className="inline-flex h-12 items-center gap-2 rounded-lg border border-[#4DFF88]/22 px-4 text-[#4DFF88] transition hover:border-[#4DFF88]/45 hover:bg-[#4DFF88]/10 glass-panel"
        >
          {connected ? <Wifi className="h-5 w-5" /> : <WifiOff className="h-5 w-5" />}
          <span className="text-sm font-black">{connected ? 'LIVE' : 'SYNCING'}</span>
          <ChevronDown className="h-4 w-4 -rotate-90" />
        </button>
      </motion.div>
    </header>
  );
}

export default function ComplianceDashboard() {
  const [activeModal, setActiveModal] = useState<ComplianceModalKey | null>(null);
  const { snapshot, loading, error, connected, refresh } = useComplianceDashboard();
  const metricCards = useMemo(() => buildMetricCards(snapshot), [snapshot]);
  const modalContent = useMemo(() => buildModalContent(snapshot), [snapshot]);

  return (
    <div className="compliance-page relative min-h-screen overflow-hidden bg-[#050816] p-4 text-white sm:p-5 lg:p-6">
      <BackgroundAtmosphere />

      <div className="relative z-10 mx-auto max-w-[1420px]">
        <Header snapshot={snapshot} loading={loading} error={error} connected={connected} onRefresh={refresh} />

        {loading && !snapshot.generatedAt && (
          <div className="mb-4 flex items-center gap-3 rounded-lg border border-[#FFD36B]/18 bg-[#FFD36B]/8 px-4 py-3 text-sm font-black text-[#FFE8A8] shadow-[0_0_28px_rgba(255,211,107,0.10)] glass-panel">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Synchronizing compliance telemetry from assets, CBOM, migration, runtime, and audit pipelines...
          </div>
        )}

        <main className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(340px,0.95fr)]">
            <OverviewCard snapshot={snapshot} />
            <SecurityStatusCard snapshot={snapshot} />
          </div>

          <div className="grid gap-4 xl:grid-cols-[minmax(300px,0.9fr)_minmax(0,1.9fr)]">
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-2">
              {metricCards.map((metric, index) => (
                <div key={metric.title}>
                  <MetricTile metric={metric} index={index} />
                </div>
              ))}
            </div>
            <ChecklistPanel items={snapshot.checklist} />
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <CertificateTable rows={snapshot.certificates} />
            <PolicyTable rows={snapshot.policies} />
          </div>

          <PolicyIntelligenceSection onOpen={setActiveModal} snapshot={snapshot} />

          <div className="flex flex-wrap items-center justify-center gap-5 pb-1 pt-1 text-sm font-semibold text-[#FFD36B]/86">
            {[
              { icon: LockKeyhole, label: 'End-to-End Quantum-Secure' },
              { icon: Activity, label: 'Zero Trust by Design' },
              { icon: Sparkles, label: 'Future Ready' },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <span key={item.label} className="inline-flex items-center gap-2">
                  <Icon className="h-4 w-4" />
                  {item.label}
                </span>
              );
            })}
          </div>
        </main>
      </div>

      <ComplianceDetailModal active={activeModal} onClose={() => setActiveModal(null)} contentMap={modalContent} />

      <style>{`
        .compliance-page,
        .compliance-page * {
          letter-spacing: 0;
        }

        .compliance-page {
          isolation: isolate;
        }

        .compliance-shimmer {
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.55), transparent);
          transform: translateX(-100%);
          animation: complianceShimmer 2.8s ease-in-out infinite;
        }

        @keyframes complianceShimmer {
          0% {
            transform: translateX(-120%);
          }
          58%, 100% {
            transform: translateX(120%);
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .compliance-page *,
          .compliance-page *::before,
          .compliance-page *::after {
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            scroll-behavior: auto !important;
          }
        }
      `}</style>
    </div>
  );
}
