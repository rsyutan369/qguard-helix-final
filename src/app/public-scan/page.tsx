/**
 * Public Quantum Exposure Assessment™ — /public-scan
 *
 * The anonymous front door to QGuard Helix. Runs the platform's real TLS +
 * public-edge scanner modules against a domain, renders an executive-grade
 * assessment of what is publicly observable, and presents the authenticated
 * Enterprise capabilities as locked previews for Basic / Pro / Elite plans.
 *
 * Data source: /api/v1/public-scan/stream (SSE, no authentication).
 */
'use client';

import React from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Download,
  FileJson,
  FileSpreadsheet,
  Globe,
  Hourglass,
  Link2,
  Loader2,
  Lock,
  Printer,
  Radar,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Users,
  XCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { usePublicScan } from '@/hooks/use-public-scan';
import type { PublicScanReport } from '@/lib/scanner/public-scan/types';
import { ACCENT, Panel, QuantumField, Reveal, SectionLabel } from './_ui';
import { QuantumScanHero } from './_qve';
import { ExposureModeTabs } from '@/components/exposure/ExposureModeTabs';
import { useExposureAccess } from '@/hooks/use-exposure-access';
import type { ScanMode } from '@/lib/scanner/exposure/types';
import {
  AssessmentScopePanel,
  AttackSurface,
  CryptoIntelligencePanel,
  EncryptionScore,
  EnterpriseModules,
  EnterpriseReportPreview,
  ExecutiveSummary,
  FootprintEstimator,
  GovernanceReadiness,
  HandshakeFlow,
  PublicFindings,
  QuantumTimeline,
  Recommendations,
  SophiaInsight,
} from './_sections';

/**
 * The public website (`npm run build:public`, src/PublicApp.tsx) ships the Web
 * assessment only. Local and Dev run the full exposure engine in the browser,
 * so they are loaded on demand here and compiled out of the website build:
 * the constant is replaced at build time and the dead `import()` is dropped.
 */
const WEBSITE_EDITION = import.meta.env.VITE_SITE_EDITION === 'public';

const LocalAssessmentPanel = WEBSITE_EDITION
  ? null
  : React.lazy(() => import('@/components/exposure/LocalAssessmentPanel').then((m) => ({ default: m.LocalAssessmentPanel })));
const DevAssessmentPanel = WEBSITE_EDITION
  ? null
  : React.lazy(() => import('@/components/exposure/DevAssessmentPanel').then((m) => ({ default: m.DevAssessmentPanel })));

function PanelLoading() {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-[13px] text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" />
      Loading assessment…
    </div>
  );
}

/* ---------------------------------------------------------------- chrome --- */

/**
 * Product navigation — signed-in only.
 *
 * Every destination here except this page lives under /dashboard, which is
 * authenticated. Showing them to a visitor advertises rooms they cannot enter
 * and sends them to a login bounce, so the nav is rendered only once the
 * session is known to exist. `/public-scan` itself stays reachable to everyone
 * — it is the front door, not a member area.
 */
const NAV_LINKS = [
  { label: 'Dashboard', to: '/dashboard' },
  { label: 'Scanners', to: '/public-scan', active: true },
  { label: 'Reports', to: '/dashboard/quantum-readiness/reports' },
  { label: 'Monitoring', to: '/dashboard/runtime-telemetry' },
  { label: 'Governance', to: '/dashboard/quantum-governance' },
];

function TopNav() {
  /* Fail closed: the nav appears only when a session is CONFIRMED. While the
     session is still resolving the visitor is treated as anonymous, so the
     links can never flash up for someone who is not signed in. */
  const { user, loading: authLoading } = useAuth();
  const signedIn = Boolean(user) && !authLoading;
  const [scrolled, setScrolled] = React.useState(false);
  React.useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header
      className={cn(
        'sticky top-0 z-50 border-b transition-colors duration-300',
        scrolled ? 'border-white/[0.08] bg-[#050810]/90 backdrop-blur-2xl' : 'border-white/[0.05] bg-[#050810]/60 backdrop-blur-xl',
      )}
    >
      <div className="mx-auto flex h-16 max-w-[92rem] items-center justify-between gap-4 px-4 sm:px-6">
        <Link to="/" className="flex min-w-0 items-center gap-2.5 no-underline">
          <img src="/NEW_LOGO.png" alt="QGuard Helix" className="h-9 w-auto shrink-0 object-contain" />
          <span className="hidden flex-col leading-none sm:flex">
            <span className="whitespace-nowrap text-[15px] font-black tracking-wide text-white">QGUARD HELIX</span>
            <span className="mt-1 whitespace-nowrap font-mono text-[8.5px] font-bold uppercase tracking-[0.26em] text-cyan-400/80">
              Quantum Security Platform
            </span>
          </span>
        </Link>

        {signedIn && (
          <nav className="hidden items-center gap-1 lg:flex" aria-label="Platform">
            {NAV_LINKS.map((link) => (
              <Link
                key={link.label}
                to={link.to}
                className={cn(
                  'rounded-lg px-3.5 py-2 text-[13px] font-semibold no-underline transition-colors',
                  link.active
                    ? 'bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/25'
                    : 'text-slate-400 hover:text-white',
                )}
              >
                {link.label}
              </Link>
            ))}
          </nav>
        )}

        {/* The actions mirror the nav. Offering "Sign in" to someone already
            signed in is the same defect in the other direction, so the signed-in
            visitor gets the way back into the platform instead. */}
        <div className="flex items-center gap-2">
          {signedIn ? (
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3.5 py-2 text-[13px] font-bold text-cyan-300 no-underline transition-colors hover:bg-cyan-400/15"
            >
              Open dashboard
            </Link>
          ) : (
            <>
              <Link
                to="/login"
                className="hidden rounded-lg border border-white/10 px-3.5 py-2 text-[13px] font-semibold text-slate-300 no-underline transition-colors hover:border-cyan-400/30 hover:text-cyan-300 sm:inline-flex"
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="grid h-9 w-9 shrink-0 place-items-center rounded-full border border-cyan-400/30 bg-cyan-400/10 font-mono text-[11px] font-black text-cyan-300 no-underline"
                aria-label="Create an account"
              >
                QH
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

/** Engine reason strings already end in a full stop; a template that appends one
 *  produced "…the host is down.. Scores below are…" on screen. */
function endWithPeriod(text: string | null | undefined): string {
  if (!text) return '';
  return /[.!?]$/.test(text.trim()) ? text.trim() : `${text.trim()}.`;
}

/* ------------------------------------------------------------ scan rail --- */

/**
 * `unavailable` is deliberately NOT rose, and deliberately not a cross.
 *
 * A module that could not run — because the port never accepted a TCP connection
 * — has made no claim about the target. Painting it the same red as a failed
 * control turned "we could not reach this endpoint" into four rows that read as
 * "this endpoint failed four security checks". Amber with a dash says what
 * actually happened: nothing was measured here.
 */
const STAGE_STATE_STYLE = {
  waiting: { color: ACCENT.slate, label: 'Waiting' },
  running: { color: ACCENT.cyan, label: 'Running' },
  complete: { color: ACCENT.emerald, label: 'Complete' },
  failed: { color: ACCENT.rose, label: 'Failed' },
  unavailable: { color: ACCENT.amber, label: 'Not Measured' },
  skipped: { color: ACCENT.slate, label: 'Skipped' },
} as const;

/** Whole seconds remaining from a server estimate, counting down between updates. */
function useCountdown(seconds: number | null, receivedAt: number | null): number | null {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (seconds === null || receivedAt === null) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [seconds, receivedAt]);
  if (seconds === null || receivedAt === null) return null;
  return Math.max(0, Math.ceil(seconds - (now - receivedAt) / 1000));
}

function formatWait(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
}

/**
 * The visitor's place in line, said plainly.
 *
 * The scanner used to refuse everyone past its sixth concurrent assessment. It
 * now holds them in a fair line, and this is what makes waiting acceptable:
 * the position, how many are running, and an estimate that is labelled as one.
 */
function QueueNotice({ queue }: { queue: NonNullable<ReturnType<typeof usePublicScan>['queue']> }) {
  const remaining = useCountdown(queue.estimatedWaitSeconds, queue.receivedAt) ?? queue.estimatedWaitSeconds;
  return (
    <div className="mx-4 mt-3 rounded-xl border border-cyan-400/20 bg-cyan-400/[0.05] px-3.5 py-3" role="status" aria-live="polite">
      <p className="flex items-center gap-2 text-[12.5px] font-bold text-cyan-100">
        <Hourglass className="h-3.5 w-3.5 shrink-0 text-cyan-300" aria-hidden />
        {queue.position === 1 ? 'You are next in line' : `You are #${queue.position} in line`}
      </p>
      <p className="mt-1 text-[11.5px] leading-relaxed text-slate-400">
        {queue.running} of {queue.capacity} assessments are running. Yours starts automatically —{' '}
        {remaining > 0 ? `in about ${formatWait(remaining)}` : 'any moment now'}. Keep this page open; closing it gives up
        your place.
      </p>
    </div>
  );
}

function ScanRail({
  stages,
  progress,
  state,
  queue,
  sharedViewers,
}: {
  stages: ReturnType<typeof usePublicScan>['stages'];
  progress: number;
  state: ReturnType<typeof usePublicScan>['state'];
  queue: ReturnType<typeof usePublicScan>['queue'];
  sharedViewers: ReturnType<typeof usePublicScan>['sharedViewers'];
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
        <SectionLabel>Quantum Exposure Assessment</SectionLabel>
        {state === 'scanning' && (
          <span className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] font-bold text-cyan-300">
            <Loader2 className="h-3 w-3 animate-spin" />
            {queue ? 'Waiting' : `${progress}%`}
          </span>
        )}
      </div>
      {state === 'scanning' && queue && <QueueNotice queue={queue} />}
      {/* Said, because a shared scan can be several seconds in when this
          visitor arrives — without it the rail looks like it skipped stages. */}
      {state === 'scanning' && sharedViewers !== null && (
        <p className="mx-4 mt-3 flex items-start gap-2 rounded-lg border border-violet-400/20 bg-violet-400/[0.05] px-3 py-2 text-[11.5px] leading-relaxed text-violet-100/85">
          <Users className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-300" aria-hidden />
          <span>
            Someone else is already assessing this site, so you are watching that same live scan
            {sharedViewers > 1 ? ` with ${sharedViewers - 1} other visitor${sharedViewers === 2 ? '' : 's'}` : ''} — the results are identical and it costs you nothing.
          </span>
        </p>
      )}
      <p className="px-4 pt-3 font-mono text-[9.5px] uppercase tracking-[0.16em] text-slate-500">
        Public Internet Scan
      </p>

      <ol className="space-y-1 px-4 py-3">
        {stages.map((stage, index) => {
          const style = STAGE_STATE_STYLE[stage.state];
          return (
            <li key={stage.key} className="flex items-start gap-3 py-1.5">
              <span
                className="relative grid h-7 w-7 shrink-0 place-items-center rounded-full border text-[11px] font-black transition-colors"
                style={{
                  borderColor: `${style.color}55`,
                  backgroundColor: `${style.color}14`,
                  color: style.color,
                }}
              >
                {stage.state === 'complete' ? (
                  <Check className="h-3.5 w-3.5" />
                ) : stage.state === 'failed' ? (
                  <XCircle className="h-3.5 w-3.5" />
                ) : (
                  index + 1
                )}
                {stage.state === 'running' && (
                  <motion.span
                    className="absolute inset-0 rounded-full border"
                    style={{ borderColor: style.color }}
                    animate={{ scale: [1, 1.35], opacity: [0.6, 0] }}
                    transition={{ duration: 1.4, repeat: Infinity, ease: 'easeOut' }}
                  />
                )}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <p
                    className="truncate text-[13px] font-bold"
                    style={{ color: stage.state === 'waiting' ? '#94a3b8' : '#e2e8f0' }}
                  >
                    {stage.label}
                  </p>
                  <span className="shrink-0 font-mono text-[9px] uppercase tracking-widest" style={{ color: style.color }}>
                    {style.label}
                  </span>
                </div>
                <p className="truncate text-[11px] text-slate-500" title={stage.detail || stage.description}>
                  {stage.detail || stage.description}
                </p>
              </div>
            </li>
          );
        })}
      </ol>

      <div className="h-1 w-full bg-white/[0.05]">
        <motion.div
          className="h-full bg-gradient-to-r from-cyan-400 to-violet-500"
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
        />
      </div>
    </Panel>
  );
}

/* --------------------------------------------------------------- exports --- */

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function toCsv(report: PublicScanReport): string {
  const escape = (value: string) => `"${String(value).replace(/"/g, '""')}"`;
  const header = ['Control', 'Finding', 'Status', 'Severity', 'Business Impact', 'Quantum Impact', 'Next Step', 'Evidence'];
  const rows = report.findings.map((finding) =>
    [
      finding.control,
      finding.finding,
      finding.status,
      finding.severity,
      finding.businessImpact,
      finding.quantumImpact,
      finding.nextStep,
      finding.evidence,
    ]
      .map(escape)
      .join(','),
  );
  return [header.join(','), ...rows].join('\n');
}

function ExportBar({ report }: { report: PublicScanReport }) {
  const [copied, setCopied] = React.useState(false);
  const slug = report.target.host.replace(/[^a-z0-9.-]/gi, '_');

  const shareLink = async () => {
    const url = `${window.location.origin}/public-scan?target=${encodeURIComponent(report.target.host)}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2200);
    } catch {
      window.prompt('Copy this assessment link:', url);
    }
  };

  const actions = [
    {
      label: 'Executive PDF',
      icon: Download,
      locked: false,
      onClick: () => window.print(),
      hint: 'Print to PDF — public findings only',
    },
    {
      label: 'JSON',
      icon: FileJson,
      locked: false,
      onClick: () => downloadBlob(`qguard-public-scan-${slug}.json`, JSON.stringify(report, null, 2), 'application/json'),
      hint: 'Full machine-readable report',
    },
    {
      label: 'CSV',
      icon: FileSpreadsheet,
      locked: false,
      onClick: () => downloadBlob(`qguard-public-findings-${slug}.csv`, toCsv(report), 'text/csv'),
      hint: 'Public findings table',
    },
    {
      label: copied ? 'Link copied' : 'Share Link',
      icon: copied ? Check : Link2,
      locked: false,
      onClick: shareLink,
      hint: 'Shareable assessment URL',
    },
    { label: 'Print', icon: Printer, locked: false, onClick: () => window.print(), hint: 'Print this assessment' },
    { label: 'Enterprise Exports', icon: Lock, locked: true, onClick: undefined, hint: 'DOCX, PPTX, XLSX, signed evidence pack' },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2">
      {actions.map((action) =>
        action.locked ? (
          <Link
            key={action.label}
            to="/register"
            title={action.hint}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.02] px-3 py-1.5 text-[11.5px] font-semibold text-slate-500 no-underline transition-colors hover:border-violet-400/30 hover:text-violet-300"
          >
            <action.icon className="h-3.5 w-3.5" />
            {action.label}
          </Link>
        ) : (
          <button
            key={action.label}
            type="button"
            onClick={action.onClick}
            title={action.hint}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11.5px] font-semibold text-slate-300 transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
          >
            <action.icon className="h-3.5 w-3.5" />
            {action.label}
          </button>
        ),
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ page --- */

export default function PublicScanPage() {
  // The whole result is kept (not just the destructured fields) because the QVE
  // hero consumes the live stream object directly to drive its event store.
  const scanResult = usePublicScan();
  const { state, stages, report, error, progress, scan, reset, queue, sharedViewers, refusal } = scanResult;
  /* Ticks only while a refusal names a retry time; null otherwise. */
  const retryIn = useCountdown(refusal?.retryAfterSeconds ?? null, refusal?.receivedAt ?? null);
  const [target, setTarget] = React.useState('');
  const resultsRef = React.useRef<HTMLDivElement>(null);

  /* Three assessment modes on one page (§3). Web keeps the whole existing
     surface untouched; Local and Dev mount their own panels in its place. The
     mode is deep-linkable and is reflected into the URL without a navigation,
     so a shared link opens on the tab the sender was looking at. */
  const [mode, setMode] = React.useState<ScanMode>('web');

  /* Lock badges on the tabs. The tabs stay CLICKABLE when locked — the panel
     behind them is the feature disclosure that makes the case for the plan, so
     a visitor who cannot scan should still be able to read what a scan does. */
  const localAccess = useExposureAccess('local', !WEBSITE_EDITION);
  const devAccess = useExposureAccess('dev', !WEBSITE_EDITION);
  const lockedModes = React.useMemo(() => {
    const locked: Partial<Record<ScanMode, string>> = {};
    if (!localAccess.loading && !localAccess.allowed) locked.local = localAccess.message;
    if (!devAccess.loading && !devAccess.allowed) locked.dev = devAccess.message;
    return locked;
  }, [localAccess.loading, localAccess.allowed, localAccess.message, devAccess.loading, devAccess.allowed, devAccess.message]);

  // Deep-linkable assessments: /public-scan?target=example.com runs on load.
  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedMode = params.get('mode');
    if (!WEBSITE_EDITION && (requestedMode === 'local' || requestedMode === 'dev')) setMode(requestedMode);

    const preset = params.get('target');
    if (preset) {
      setMode('web');
      setTarget(preset);
      scan(preset);
    }
    // Intentionally on-mount only — a query change is a full navigation here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const changeMode = React.useCallback((next: ScanMode) => {
    setMode(next);
    const url = new URL(window.location.href);
    if (next === 'web') url.searchParams.delete('mode');
    else url.searchParams.set('mode', next);
    window.history.replaceState(null, '', url.toString());
  }, []);

  React.useEffect(() => {
    if (state === 'complete' && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [state]);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    scan(target);
  };

  return (
    <div className="min-h-screen text-slate-200 antialiased">
      <QuantumField />
      <TopNav />

      {/* overflow-x-clip is the backstop: the findings table and handshake rail
          scroll inside their own containers, and nothing may push the page
          sideways on a phone. */}
      <main className="mx-auto max-w-[92rem] overflow-x-clip px-4 pb-24 pt-6 sm:px-6">
        {/* ── Assessment mode: Web / Local / Dev (§3) ──────────────────── */}
        {!WEBSITE_EDITION && (
          <div className="mb-5">
            <ExposureModeTabs value={mode} onChange={changeMode} locked={lockedModes} scope="public-scan" />
          </div>
        )}

        {mode === 'local' && LocalAssessmentPanel && (
          <div role="tabpanel" id="exposure-panel-local" aria-labelledby="exposure-tab-local">
            <React.Suspense fallback={<PanelLoading />}>
              <LocalAssessmentPanel upsellSlot={<EnterpriseUpsell />} />
            </React.Suspense>
          </div>
        )}

        {mode === 'dev' && DevAssessmentPanel && (
          <div role="tabpanel" id="exposure-panel-dev" aria-labelledby="exposure-tab-dev">
            <React.Suspense fallback={<PanelLoading />}>
              <DevAssessmentPanel upsellSlot={<EnterpriseUpsell />} />
            </React.Suspense>
          </div>
        )}

        {mode === 'web' && (
        <div role="tabpanel" id="exposure-panel-web" aria-labelledby="exposure-tab-web">
        {/* ── Hero: Enterprise Quantum Real-Time Visualization Engine™ ──
            The hero is now owned end-to-end by the QVE subsystem (_qve/): the
            live beam network, holographic Quantum Core, GPU packet engine,
            event timeline and infrastructure strip all read from one scan-event
            store fed by this page's real SSE stream. The workflow rail and the
            enterprise CTA are passed through as a slot so they keep their exact
            position, markup and behaviour. Nothing below this block changed. */}
        <QuantumScanHero
          scan={scanResult}
          report={report}
          target={target}
          onTargetChange={setTarget}
          onSubmit={submit}
          railSlot={
            <>
              <ScanRail stages={stages} progress={progress} state={state} queue={queue} sharedViewers={sharedViewers} />

              <Panel className="overflow-hidden border-violet-400/15">
                <div className="px-4 py-4">
                  <h3 className="text-[15px] font-black leading-tight text-white">
                    Unlock Full Enterprise Assessment
                  </h3>
                  <p className="mt-2 text-[12px] leading-relaxed text-slate-400">
                    Analyze your entire infrastructure, source code, cryptographic inventory and migration readiness.
                  </p>
                  <Link
                    to="/register"
                    className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-cyan-400 px-4 py-2.5 text-[13px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
                  >
                    Explore Enterprise Platform <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              </Panel>
            </>
          }
        />

        {/* ── Status bar ──────────────────────────────────────────────── */}
        <AnimatePresence mode="wait">
          {(state === 'complete' || state === 'error') && (
            <motion.div
              key={state}
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.35 }}
              className="mt-5"
            >
              <Panel className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  {state === 'complete' && !report?.degraded ? (
                    <CheckCircle2 className="h-4.5 w-4.5 shrink-0 text-emerald-400" />
                  ) : (
                    <ShieldAlert
                      className={cn(
                        'h-4.5 w-4.5 shrink-0',
                        state === 'complete' ? 'text-amber-400' : 'text-rose-400',
                      )}
                    />
                  )}
                  <span className="text-[13.5px] font-bold text-white">
                    {state !== 'complete'
                      ? refusal
                        ? 'Assessment not started'
                        : 'Assessment could not complete'
                      : report?.degraded
                        ? 'Scan completed with limited evidence'
                        : 'Scan Completed'}
                  </span>
                  {/* The server's own reason, in full — a refusal names its cause
                      and when to retry, which a truncated line would cut off. */}
                  <span className={cn('text-[12px] text-slate-500', refusal ? 'min-w-0 whitespace-normal' : 'truncate')}>
                    {state === 'complete' && report
                      ? `${report.target.displayUrl} · ${new Date(report.completedAt).toUTCString().replace('GMT', 'UTC')}${report.cached ? ' · cached' : ''}`
                      : error}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {state === 'complete' && report && <ExportBar report={report} />}
                  {refusal && retryIn !== null && target.trim() && (
                    <button
                      type="button"
                      disabled={retryIn > 0}
                      onClick={() => scan(target)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/[0.08] px-3 py-1.5 text-[11.5px] font-bold text-cyan-200 transition-colors hover:bg-cyan-400/[0.14] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      {retryIn > 0 ? `Try again in ${formatWait(retryIn)}` : 'Try again'}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={reset}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-1.5 text-[11.5px] font-semibold text-slate-400 transition-colors hover:text-white"
                  >
                    <RotateCcw className="h-3.5 w-3.5" /> New scan
                  </button>
                </div>
              </Panel>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Degraded / unreachable notice ───────────────────────────────
            An unreachable endpoint gets its OWN headline. "Partial assessment ·
            scores below are computed only from the dimensions that could be
            observed" is true but misleading when the answer is that NO dimension
            was observed and there are no scores below. The reason string already
            ends in a full stop, so this no longer appends a second one. */}
        {report?.degraded && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.06] px-4 py-3">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <p className="text-[12.5px] leading-relaxed text-amber-100/85">
              {report.unreachable ? (
                <>
                  <strong className="font-bold">
                    No assessment was possible — {report.target.host} did not answer on port {report.target.port}.
                  </strong>{' '}
                  {endWithPeriod(report.degradedReason)} No TLS handshake, certificate or HTTP evidence could be
                  collected, so no cryptographic verdict is published for this target. Nothing below is a finding
                  about its cryptography. If the service is reachable only from inside your network, assess it with
                  the authenticated platform instead.
                </>
              ) : (
                <>
                  <strong className="font-bold">Partial assessment.</strong> {endWithPeriod(report.degradedReason)}{' '}
                  Scores below are computed only from the dimensions that could be observed — unmeasurable controls
                  are excluded rather than scored as failures.
                </>
              )}
            </p>
          </div>
        )}

        {/* ── Results ─────────────────────────────────────────────────── */}
        {report ? (
          <div ref={resultsRef} className="mt-5 space-y-5 scroll-mt-24">
            <Reveal>
              <ExecutiveSummary report={report} />
            </Reveal>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,0.85fr)_minmax(0,1fr)]">
              <Reveal>
                <EncryptionScore report={report} />
              </Reveal>
              <Reveal delay={0.05}>
                <AttackSurface report={report} />
              </Reveal>
              <Reveal delay={0.1}>
                <CryptoIntelligencePanel report={report} />
              </Reveal>
            </div>

            <Reveal>
              <HandshakeFlow report={report} />
            </Reveal>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.75fr)_minmax(0,1fr)]">
              <Reveal>
                <PublicFindings report={report} />
              </Reveal>
              <Reveal delay={0.05}>
                <QuantumTimeline report={report} />
              </Reveal>
            </div>

            <Reveal>
              <Recommendations report={report} />
            </Reveal>

            <div className="grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-[minmax(0,1.65fr)_minmax(0,1fr)]">
              <Reveal>
                <FootprintEstimator report={report} />
              </Reveal>
              <Reveal delay={0.05}>
                <GovernanceReadiness report={report} />
              </Reveal>
            </div>

            <Reveal>
              <SophiaInsight report={report} />
            </Reveal>

            <Reveal>
              <AssessmentScopePanel report={report} />
            </Reveal>

            <Reveal>
              <EnterpriseModules />
            </Reveal>

            <Reveal>
              <EnterpriseReportPreview />
            </Reveal>

            <Reveal>
              <FinalCta />
            </Reveal>
          </div>
        ) : (
          <EmptyState state={state} />
        )}
        </div>
        )}
      </main>

      <PublicScanFooter />
    </div>
  );
}

/* ----------------------------------------------------------- upsell slot --- */

/** The enterprise CTA the Web rail already carried, reused by Local and Dev. */
function EnterpriseUpsell() {
  return (
    <Panel className="overflow-hidden border-violet-400/15">
      <div className="px-4 py-4">
        <h3 className="text-[15px] font-black leading-tight text-white">Unlock Full Enterprise Assessment</h3>
        <p className="mt-2 text-[12px] leading-relaxed text-slate-400">
          Persist every assessment into a governed cryptographic inventory, correlate it with runtime telemetry and turn it
          into an evidence-backed post-quantum migration programme.
        </p>
        <Link
          to="/register"
          className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-500 to-cyan-400 px-4 py-2.5 text-[13px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
        >
          Explore Enterprise Platform <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------ empty state -- */

function EmptyState({ state }: { state: ReturnType<typeof usePublicScan>['state'] }) {
  if (state === 'scanning') {
    return (
      <div className="mt-5 grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
        {[0, 1, 2].map((index) => (
          <Panel key={index} className="h-56 overflow-hidden">
            <motion.div
              className="h-full w-full bg-gradient-to-r from-transparent via-white/[0.045] to-transparent"
              animate={{ x: ['-100%', '100%'] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'linear', delay: index * 0.18 }}
            />
          </Panel>
        ))}
      </div>
    );
  }

  return (
    <div className="mt-5 grid grid-cols-[minmax(0,1fr)] gap-5 lg:grid-cols-3">
      {[
        {
          icon: ShieldCheck,
          title: 'Real edge evidence',
          body: 'The same TLS and public-scanner modules that power the authenticated platform, run against your public endpoint.',
        },
        {
          icon: Sparkles,
          title: 'Post-quantum readiness',
          body: 'Named key-agreement groups are probed individually, so hybrid ML-KEM support is proven rather than assumed.',
        },
        {
          icon: Lock,
          title: 'Honest about limits',
          body: 'Source code, internal PKI, key management and governance cannot be seen from the Internet — they are reported as Unknown.',
        },
      ].map((card, index) => (
        <Reveal key={card.title} delay={index * 0.07}>
          <Panel className="h-full px-5 py-5">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/[0.08] text-cyan-300">
              <card.icon className="h-5 w-5" />
            </span>
            <h3 className="mt-3.5 text-[15px] font-black text-white">{card.title}</h3>
            <p className="mt-1.5 text-[12.5px] leading-relaxed text-slate-400">{card.body}</p>
          </Panel>
        </Reveal>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------- cta --- */

function FinalCta() {
  return (
    <Panel className="relative overflow-hidden border-cyan-400/20">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: 'radial-gradient(ellipse at 30% 0%, rgba(34,211,238,0.12), transparent 60%)' }}
      />
      <div className="relative grid grid-cols-[minmax(0,1fr)] items-center gap-6 px-6 py-8 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <div>
          <SectionLabel>Unlock Full Assessment</SectionLabel>
          <h2 className="mt-3 text-2xl font-black tracking-tight text-white sm:text-3xl">
            The public edge is a fraction of your cryptographic estate.
          </h2>
          <p className="mt-3 max-w-2xl text-[13.5px] leading-relaxed text-slate-400">
            An authenticated Enterprise Assessment discovers cryptography across source code, internal PKI, key
            management, cloud workloads, databases and machine identities — then turns it into a governed,
            evidence-backed post-quantum migration programme.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link
              to="/register"
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-400 to-violet-500 px-5 py-2.5 text-[13px] font-black text-[#04060e] no-underline transition-opacity hover:opacity-90"
            >
              Request Enterprise Assessment <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              to="/quantum-readiness-assessment"
              className="inline-flex items-center gap-2 rounded-lg border border-white/[0.1] px-5 py-2.5 text-[13px] font-bold text-slate-300 no-underline transition-colors hover:border-cyan-400/30 hover:text-cyan-300"
            >
              How the assessment works
            </Link>
          </div>
        </div>
        <div className="grid gap-2.5">
          {[
            { tier: 'Basic', body: 'Quantum Readiness, CBOM, Scanner, Migration Planner & Sandbox', color: ACCENT.cyan },
            { tier: 'Pro', body: 'Source-code discovery, runtime telemetry, ecosystem & PQAuth', color: ACCENT.violet },
            { tier: 'Elite', body: 'QKMS trust anchor, governance, audit vault & regulatory mapping', color: ACCENT.amber },
          ].map((plan) => (
            <div
              key={plan.tier}
              className="flex items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3"
            >
              <span
                className="mt-0.5 rounded-md px-2 py-0.5 font-mono text-[9.5px] font-black uppercase tracking-widest"
                style={{ backgroundColor: `${plan.color}1c`, color: plan.color }}
              >
                {plan.tier}
              </span>
              <p className="text-[12px] leading-snug text-slate-400">{plan.body}</p>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

/* ---------------------------------------------------------------- footer --- */

function PublicScanFooter() {
  return (
    <footer className="relative z-10 border-t border-white/[0.06] bg-[#050810]/70 px-6 py-10 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[92rem] flex-col gap-6 md:flex-row md:items-start md:justify-between">
        <div className="max-w-md">
          <Link to="/" className="flex items-center gap-2.5 no-underline">
            <img src="/NEW_LOGO.png" alt="" className="h-9 w-auto object-contain" />
            <span className="text-[15px] font-black tracking-wide text-white">QGUARD HELIX</span>
          </Link>
          <p className="mt-3 text-[12px] leading-relaxed text-slate-500">
            The Public Quantum Exposure Assessment analyzes publicly observable TLS, certificate, DNS and HTTP
            metadata only. It is not a substitute for an authenticated cryptographic discovery of your estate.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
          {[
            {
              title: 'Assessment',
              links: [
                { label: 'Quantum Readiness', to: '/quantum-readiness-assessment' },
                { label: 'PQC Solutions', to: '/pqc-solutions' },
                { label: 'Migration Platform', to: '/post-quantum-migration-platform' },
              ],
            },
            {
              title: 'Platform',
              links: [
                { label: 'Dashboard', to: '/dashboard' },
                { label: 'QGuard Messaging', to: '/qguard-messaging' },
                { label: 'Documentation', to: '/docs' },
              ],
            },
            {
              title: 'Get started',
              links: [
                { label: 'Sign in', to: '/login' },
                { label: 'Create account', to: '/register' },
                { label: 'Verify a certificate', to: '/verify-certificate' },
              ],
            },
          ].map((column) => (
            <div key={column.title}>
              <h3 className="font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400">
                {column.title}
              </h3>
              <ul className="mt-2.5 space-y-1.5">
                {column.links.map((link) => (
                  <li key={link.label}>
                    <Link to={link.to} className="text-[12.5px] text-slate-500 no-underline transition-colors hover:text-cyan-300">
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
      <p className="mx-auto mt-8 max-w-[92rem] border-t border-white/[0.06] pt-5 text-[11.5px] text-slate-600">
        &copy; {new Date().getFullYear()} QGuard Helix. Quantum Exposure Assessment™, Cryptographic Governance
        Center™, Runtime Crypto Telemetry™, Migration Sandbox™ and Sophia AI Security Copilot™ are trademarks of
        QGuard Helix.
      </p>
    </footer>
  );
}
