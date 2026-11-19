'use client';

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, Navigate, Outlet, useLocation } from 'react-router-dom';
import ReactECharts from 'echarts-for-react';
import type { EChartsOption } from 'echarts';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Crown,
  Download,
  Info,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { isOwnerEmail } from '@/lib/admin-access';
import { cn } from '@/lib/utils';
import {
  providerLabel,
  type ActivityEntry,
  type AlertEntry,
  type CustomerRow,
  type InvoiceLedgerRow,
  type RevenueClass,
  type RevenueSnapshot,
  type SubscriberRow,
  type TimelineBucket,
} from '@/lib/billing/revenue-model';
import {
  AMBER,
  BLUE,
  CYAN,
  EMERALD,
  GOLD,
  GREEN,
  RED,
  SLATE,
  VIOLET,
  EmptyState,
  Panel,
  SectionTitle,
} from '@/app/dashboard/quantum-readiness/_shared';
import { openTicketedEventSource } from '@/lib/stream-ticket';

export type { RevenueSnapshot, TimelineBucket, CustomerRow, SubscriberRow, InvoiceLedgerRow, ActivityEntry, AlertEntry, RevenueClass };

/* ------------------------------------------------------------------ */
/* Formatters (USD, UTC — the model's reporting basis)                 */
/* ------------------------------------------------------------------ */

export const PLAN_COLORS: Record<string, string> = { Starter: BLUE, Basic: VIOLET, Pro: CYAN, Elite: GOLD };

export function moneyFmt(cents: number | null | undefined, currency = 'USD'): string {
  if (cents === null || cents === undefined || !Number.isFinite(cents)) return '—';
  const value = cents / 100;
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      notation: Math.abs(value) >= 1_000_000 ? 'compact' : 'standard',
      minimumFractionDigits: Math.abs(value) >= 1_000_000 ? 0 : 2,
      maximumFractionDigits: 2,
    }).format(value);
  } catch {
    return `${value.toFixed(2)} ${currency}`;
  }
}

export function pctFmt(value: number | null | undefined, signed = true): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${signed && value > 0 ? '+' : ''}${value}%`;
}

export function countFmt(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-US').format(value);
}

export function dateFmt(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
}

export function dateTimeFmt(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? '—'
    : `${date.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })} UTC`;
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return '';
  const at = new Date(value).getTime();
  if (!Number.isFinite(at)) return '';
  const seconds = Math.round((Date.now() - at) / 1000);
  if (seconds < 0) return 'scheduled';
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export const STATUS_COLORS: Record<string, string> = {
  active: EMERALD, trial: CYAN, pending_renewal: AMBER, past_due: RED, suspended: RED, cancelled: SLATE,
  expired: RED, incomplete: AMBER, paid: EMERALD, failed: RED, refunded: AMBER, pending: SLATE,
};

export function StatusPill({ value }: { value: string | null }) {
  const key = String(value || '').toLowerCase();
  const color = STATUS_COLORS[key] ?? SLATE;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" style={{ color, backgroundColor: `${color}14`, border: `1px solid ${color}38` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
      {key.replace(/_/g, ' ') || '—'}
    </span>
  );
}

const CLASS_META: Record<RevenueClass, { label: string; color: string }> = {
  provider: { label: 'Billed', color: EMERALD },
  manual: { label: 'Manual', color: AMBER },
  complimentary: { label: 'Comp / test', color: SLATE },
};

export function ClassPill({ value, title }: { value: RevenueClass | null; title?: string }) {
  if (!value) return <span className="text-white/35">—</span>;
  const meta = CLASS_META[value];
  return (
    <span title={title} className="inline-flex whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" style={{ color: meta.color, backgroundColor: `${meta.color}14`, border: `1px solid ${meta.color}38` }}>
      {meta.label}
    </span>
  );
}

export { providerLabel };

/* ------------------------------------------------------------------ */
/* Data provider — one snapshot + one live stream for all six pages    */
/* ------------------------------------------------------------------ */

export type LoadStatus = 'loading' | 'ready' | 'error';
export type StreamState = 'connecting' | 'live' | 'stale' | 'reconnecting';

interface ExportState {
  key: string;
  status: 'running' | 'done' | 'error';
  message: string;
}

interface RevenueContextValue {
  snapshot: RevenueSnapshot | null;
  status: LoadStatus;
  error: string | null;
  stream: StreamState;
  lastFrameAt: number | null;
  refreshing: boolean;
  refresh: (fresh?: boolean) => Promise<void>;
  exportReport: (report: string, format: 'csv' | 'json') => Promise<void>;
  exportState: ExportState | null;
  dismissExport: () => void;
  openCustomer: (userId: string) => void;
}

/** Exported for tools/revenue-intelligence-render-check.tsx, which renders every page state. */
export const RevenueContext = createContext<RevenueContextValue | null>(null);
export type { RevenueContextValue };

/** Snapshot freshness: a frame (snapshot or heartbeat) is due every 10–25s. */
const STALE_AFTER_MS = 40_000;

function isNewer(next: RevenueSnapshot, current: RevenueSnapshot | null): boolean {
  return !current || Date.parse(next.generatedAt) >= Date.parse(current.generatedAt);
}

function useRevenueIntelligenceState(onOpenCustomer: (userId: string) => void, enabled: boolean): RevenueContextValue {
  const { session } = useAuth();
  // A primitive dependency: supabase-js re-emits a NEW session object on tab
  // focus, and keying on the object would tear the stream down each time.
  // `enabled` is false for a non-owner: the layout redirects them, and no
  // snapshot request or stream may be opened in the meantime.
  const token = enabled ? session?.access_token ?? null : null;
  const tokenRef = useRef(token);
  tokenRef.current = token;

  const [snapshot, setSnapshot] = useState<RevenueSnapshot | null>(null);
  const [status, setStatus] = useState<LoadStatus>('loading');
  const [error, setError] = useState<string | null>(null);
  const [stream, setStream] = useState<StreamState>('connecting');
  const [lastFrameAt, setLastFrameAt] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [exportState, setExportState] = useState<ExportState | null>(null);
  const requestSeq = useRef(0);

  const apply = useCallback((next: RevenueSnapshot) => {
    // REST and SSE both deliver snapshots; never let an older one overwrite a newer one.
    setSnapshot((current) => (isNewer(next, current) ? next : current));
    setStatus('ready');
    setError(null);
    setLastFrameAt(Date.now());
  }, []);

  const refresh = useCallback(async (fresh = false) => {
    const current = tokenRef.current;
    if (!current) return;
    const seq = ++requestSeq.current;
    setRefreshing(true);
    try {
      const response = await fetch(`/api/v1/revenue/snapshot${fresh ? '?fresh=1' : ''}`, {
        headers: { Authorization: `Bearer ${current}` },
        cache: 'no-store',
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `Revenue API answered HTTP ${response.status}`);
      if (seq === requestSeq.current) apply(payload.data as RevenueSnapshot);
    } catch (err) {
      if (seq !== requestSeq.current) return;
      setError(err instanceof Error ? err.message : 'Revenue intelligence failed to load');
      // Keep the last good snapshot on screen (with an error banner) rather
      // than replacing real figures with nothing.
      setStatus((prev) => (prev === 'ready' ? 'ready' : 'error'));
    } finally {
      if (seq === requestSeq.current) setRefreshing(false);
    }
  }, [apply]);

  useEffect(() => {
    if (token) void refresh();
    // refresh reads the token through a ref; only a token change re-runs this.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    if (!token) return;
    let disposed = false;
    let source: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const schedule = (delay: number) => {
      if (disposed) return;
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = setTimeout(connect, delay);
    };

    function connect() {
      if (disposed) return;
      source?.close();
      setStream(attempt === 0 ? 'connecting' : 'reconnecting');
      // A single-use ticket per connection: the JWT never enters the URL.
      void openTicketedEventSource('revenue', token!).then((es) => {
      if (disposed) { es.close(); return; }
      source = es;
      es.addEventListener('revenue-connected', () => {
        attempt = 0;
        setStream('live');
        setLastFrameAt(Date.now());
      });
      es.addEventListener('revenue-snapshot', (event) => {
        try {
          apply(JSON.parse((event as MessageEvent).data) as RevenueSnapshot);
          setStream('live');
        } catch {
          // A malformed frame is ignored; the next frame (≤10s) supersedes it.
        }
      });
      es.addEventListener('revenue-heartbeat', () => {
        setLastFrameAt(Date.now());
        setStream('live');
      });
      es.addEventListener('revenue-error', (event) => {
        try {
          setError(JSON.parse((event as MessageEvent).data)?.message || 'Live revenue update failed');
        } catch {
          setError('Live revenue update failed');
        }
      });
      es.addEventListener('revenue-reauth', () => {
        // The session token expired server-side. supabase-js refreshes it and
        // the new token restarts this effect; until then retry gently.
        es.close();
        setStream('reconnecting');
        schedule(5_000);
      });
      es.onerror = () => {
        es.close();
        attempt += 1;
        setStream('reconnecting');
        schedule(Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5)) + Math.round(Math.random() * 500));
      };
      }).catch(() => {
        if (disposed) return;
        attempt += 1;
        setStream('reconnecting');
        schedule(Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5)) + Math.round(Math.random() * 500));
      });
    }

    connect();
    return () => {
      disposed = true;
      if (retryTimer) clearTimeout(retryTimer);
      source?.close();
    };
  }, [token, apply]);

  // Stale detection: "Live" must mean frames are actually arriving.
  useEffect(() => {
    const timer = setInterval(() => {
      setStream((current) => (current === 'live' && lastFrameAt !== null && Date.now() - lastFrameAt > STALE_AFTER_MS ? 'stale' : current));
    }, 5_000);
    return () => clearInterval(timer);
  }, [lastFrameAt]);

  useEffect(() => {
    if (exportState?.status !== 'done') return;
    const timer = setTimeout(() => setExportState(null), 7_000);
    return () => clearTimeout(timer);
  }, [exportState]);

  const exportReport = useCallback(async (report: string, format: 'csv' | 'json') => {
    const key = `${report}.${format}`;
    const current = tokenRef.current;
    if (!current) {
      setExportState({ key, status: 'error', message: 'Your session has expired — sign in again to export.' });
      return;
    }
    setExportState({ key, status: 'running', message: `Preparing the ${report} report (${format.toUpperCase()})…` });
    try {
      // Header-authenticated fetch + blob download: the session JWT never
      // appears in a URL, browser history, server log or Referer.
      const response = await fetch(`/api/v1/revenue/export?report=${encodeURIComponent(report)}&format=${format}`, {
        headers: { Authorization: `Bearer ${current}` },
        cache: 'no-store',
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.error?.message || `Export failed (HTTP ${response.status})`);
      }
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const filename = /filename="([^"]+)"/.exec(disposition)?.[1] || `qguard-${report}-report.${format}`;
      const rows = response.headers.get('X-Report-Rows');
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      // Revoking synchronously can cancel the download in some browsers.
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
      setExportState({ key, status: 'done', message: `Downloaded ${filename}${rows ? ` · ${countFmt(Number(rows))} rows` : ''}` });
    } catch (err) {
      setExportState({ key, status: 'error', message: err instanceof Error ? err.message : 'Export failed' });
    }
  }, []);

  return {
    snapshot,
    status,
    error,
    stream,
    lastFrameAt,
    refreshing,
    refresh,
    exportReport,
    exportState,
    dismissExport: () => setExportState(null),
    openCustomer: onOpenCustomer,
  };
}

export function useRevenue(): RevenueContextValue {
  const value = useContext(RevenueContext);
  if (!value) throw new Error('useRevenue must be used inside <RevenueIntelligenceLayout>');
  return value;
}

/**
 * Route layout for /dashboard/revenue-intelligence/*. Owner-gated (the API
 * enforces the same rule on every request), holds the ONE data provider so
 * moving between the six pages keeps the live stream and the snapshot.
 */
export function RevenueIntelligenceLayout() {
  const { user, loading } = useAuth();
  const [customerId, setCustomerId] = useState<string | null>(null);
  const value = useRevenueIntelligenceState(setCustomerId, !loading && isOwnerEmail(user?.email));

  if (!loading && !isOwnerEmail(user?.email)) return <Navigate to="/dashboard" replace />;

  return (
    <RevenueContext.Provider value={value}>
      <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
        <div className="mx-auto max-w-[1560px] space-y-4">
          <RevenueSubnav />
          <Outlet />
        </div>
      </div>
      <ExportToast />
      {customerId ? <CustomerDrawer userId={customerId} onClose={() => setCustomerId(null)} /> : null}
    </RevenueContext.Provider>
  );
}

/* ------------------------------------------------------------------ */
/* Navigation + page frame                                             */
/* ------------------------------------------------------------------ */

export const REVENUE_PAGES: Array<{ label: string; short: string; path: string }> = [
  { label: 'Executive Overview', short: 'Overview', path: '/dashboard/revenue-intelligence' },
  { label: 'Revenue Analytics', short: 'Revenue', path: '/dashboard/revenue-intelligence/revenue' },
  { label: 'Subscription Analytics', short: 'Subscriptions', path: '/dashboard/revenue-intelligence/subscriptions' },
  { label: 'Customer Analytics', short: 'Customers', path: '/dashboard/revenue-intelligence/customers' },
  { label: 'Payment Analytics', short: 'Payments', path: '/dashboard/revenue-intelligence/payments' },
  { label: 'Forecast & Reports', short: 'Forecast', path: '/dashboard/revenue-intelligence/forecast' },
];

function RevenueSubnav() {
  const location = useLocation();
  const current = location.pathname.replace(/\/+$/, '');
  return (
    <nav aria-label="Revenue Intelligence pages" className="-mx-1 flex gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
      {REVENUE_PAGES.map((page) => {
        const active = current === page.path;
        return (
          <Link
            key={page.path}
            to={page.path}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'whitespace-nowrap rounded-md border px-3 py-1.5 text-[11px] font-bold no-underline transition focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/60',
              active
                ? 'border-emerald-400/50 bg-emerald-500/15 text-emerald-200'
                : 'border-white/8 bg-black/20 text-white/55 hover:border-emerald-400/35 hover:text-emerald-200',
            )}
          >
            {page.short}
          </Link>
        );
      })}
    </nav>
  );
}

export function ActionButton({
  icon: Icon,
  children,
  onClick,
  busy,
  disabled,
  title,
}: {
  icon: LucideIcon;
  children: ReactNode;
  onClick: () => void;
  busy?: boolean;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      aria-busy={busy || undefined}
      className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 bg-black/22 px-3 text-xs font-bold text-white/75 transition hover:border-emerald-400/45 hover:bg-emerald-500/10 hover:text-emerald-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/60 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
      {children}
    </button>
  );
}

/** Refresh + optional export, shared by every page header. */
export function PageActions({ report }: { report?: string }) {
  const { refresh, refreshing, exportReport, exportState } = useRevenue();
  const exporting = exportState?.status === 'running';
  return (
    <>
      <ActionButton icon={RefreshCw} onClick={() => void refresh(true)} busy={refreshing} title="Rebuild from the billing database now">
        Refresh
      </ActionButton>
      {report ? (
        <ActionButton icon={Download} onClick={() => void exportReport(report, 'csv')} busy={exporting && exportState?.key === `${report}.csv`} disabled={exporting}>
          Export CSV
        </ActionButton>
      ) : null}
    </>
  );
}

function StreamBadge({ stream }: { stream: StreamState }) {
  const meta = {
    live: { label: 'Live', className: 'border-emerald-400/30 text-emerald-200', icon: Wifi },
    connecting: { label: 'Connecting', className: 'border-cyan-400/30 text-cyan-200', icon: Loader2 },
    reconnecting: { label: 'Reconnecting', className: 'border-amber-400/30 text-amber-200', icon: WifiOff },
    stale: { label: 'Stale — no update in 40s', className: 'border-amber-400/40 text-amber-200', icon: AlertTriangle },
  }[stream];
  const Icon = meta.icon;
  return (
    <span role="status" className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-2 text-[11px] font-bold', meta.className)}>
      <Icon className={cn('h-3.5 w-3.5', stream === 'connecting' && 'animate-spin')} aria-hidden="true" />
      {meta.label}
    </span>
  );
}

function LoadingState() {
  return (
    <div aria-busy="true" aria-label="Loading revenue intelligence" className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="h-[118px] animate-pulse rounded-lg border border-white/6 bg-white/[0.03]" />
        ))}
      </div>
      <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr_1fr]">
        {Array.from({ length: 3 }).map((_, index) => (
          <div key={index} className="h-[300px] animate-pulse rounded-lg border border-white/6 bg-white/[0.03]" />
        ))}
      </div>
      <p className="text-center text-[11px] text-white/35">Reading billing subscriptions, invoices and accounts…</p>
    </div>
  );
}

function Notice({ tone, icon: Icon, title, children, action }: { tone: 'error' | 'warning' | 'info'; icon: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  const tones = {
    error: 'border-red-400/30 bg-red-500/[0.08] text-red-100',
    warning: 'border-amber-400/25 bg-amber-400/[0.07] text-amber-100/90',
    info: 'border-cyan-400/20 bg-cyan-400/[0.05] text-cyan-50/85',
  };
  return (
    <div role={tone === 'error' ? 'alert' : 'note'} className={cn('flex flex-col gap-2 rounded-md border px-4 py-3 text-sm sm:flex-row sm:items-start sm:justify-between', tones[tone])}>
      <div className="flex min-w-0 items-start gap-2.5">
        <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <div className="min-w-0">
          <div className="font-bold">{title}</div>
          {children ? <div className="mt-0.5 text-[12px] leading-relaxed opacity-85">{children}</div> : null}
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

/**
 * Page frame. Renders children ONLY when a real snapshot exists: while
 * loading it shows a skeleton, on a first-load failure an error with Retry —
 * never a dashboard of zeros that reads as "no revenue".
 */
export function RevenuePage({
  title,
  subtitle,
  report,
  children,
}: {
  title: string;
  subtitle: string;
  report?: string;
  children: (snapshot: RevenueSnapshot) => ReactNode;
}) {
  const { snapshot, status, error, stream, refresh, refreshing } = useRevenue();
  const excluded = snapshot ? snapshot.subscriptionAnalytics.byClass.complimentary + snapshot.subscriptionAnalytics.byClass.manual : 0;

  return (
    <div className="space-y-4">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-500/[0.07] px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-emerald-300">
            <Crown className="h-3.5 w-3.5" aria-hidden="true" />
            Revenue Intelligence™ · Owner Only
          </div>
          <h1 className="text-2xl font-semibold tracking-normal text-white">{title}</h1>
          <p className="mt-1 max-w-3xl text-sm text-white/58">{subtitle}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <StreamBadge stream={stream} />
          <PageActions report={report} />
        </div>
      </header>

      {status === 'loading' && !snapshot ? <LoadingState /> : null}

      {status === 'error' && !snapshot ? (
        <Notice
          tone="error"
          icon={AlertTriangle}
          title="Revenue intelligence could not be loaded"
          action={<ActionButton icon={RefreshCw} onClick={() => void refresh(true)} busy={refreshing}>Retry</ActionButton>}
        >
          {error || 'The revenue API did not answer.'} No figures are shown until the billing data can be read — check the API server and the Supabase service-role configuration if this persists.
        </Notice>
      ) : null}

      {snapshot ? (
        <>
          {error ? (
            <Notice tone="warning" icon={AlertTriangle} title="Showing the last successful snapshot" action={<ActionButton icon={RefreshCw} onClick={() => void refresh(true)} busy={refreshing}>Retry</ActionButton>}>
              {error} · Data as of {dateTimeFmt(snapshot.generatedAt)}.
            </Notice>
          ) : null}

          {snapshot.coverage.unavailableTables.length ? (
            <Notice tone="error" icon={AlertTriangle} title="Some billing sources could not be read — affected figures are incomplete">
              Unreadable: {snapshot.coverage.unavailableTables.join(', ')}. Totals below exclude those sources rather than guessing.
            </Notice>
          ) : null}
          {snapshot.coverage.truncatedTables.length ? (
            <Notice tone="warning" icon={AlertTriangle} title="Read ceiling reached">
              {snapshot.coverage.truncatedTables.join(', ')} hit the per-build row ceiling; totals cover the most recent rows only. Raise the ceiling in src/api-server/revenue.ts before relying on all-time figures.
            </Notice>
          ) : null}

          {!snapshot.hasData ? (
            <Notice tone="info" icon={Info} title="No billing evidence yet">
              Every figure is computed from real subscriptions and invoices. This dashboard populates the moment the first PayPal or Google Play payment lands — the payment webhooks write billing_subscriptions / billing_invoices and the live stream updates this page without a refresh.
            </Notice>
          ) : excluded > 0 ? (
            <Notice tone="info" icon={ShieldCheck} title={`${countFmt(excluded)} subscription${excluded === 1 ? ' is' : 's are'} excluded from revenue`}>
              {snapshot.subscriptionAnalytics.byClass.complimentary > 0 ? `${countFmt(snapshot.subscriptionAnalytics.byClass.complimentary)} test / complimentary grant${snapshot.subscriptionAnalytics.byClass.complimentary === 1 ? '' : 's'}` : null}
              {snapshot.subscriptionAnalytics.byClass.complimentary > 0 && snapshot.subscriptionAnalytics.byClass.manual > 0 ? ' and ' : null}
              {snapshot.subscriptionAnalytics.byClass.manual > 0 ? `${countFmt(snapshot.subscriptionAnalytics.byClass.manual)} manually managed subscription${snapshot.subscriptionAnalytics.byClass.manual === 1 ? '' : 's'}` : null}
              {' '}grant access but have never been charged by a payment provider, so they count toward subscription totals and never toward MRR, ARR or revenue.
            </Notice>
          ) : null}

          {snapshot.currencyExclusions.length ? (
            <Notice tone="warning" icon={AlertTriangle} title="Non-USD payments are excluded from USD totals">
              {snapshot.currencyExclusions.map((entry) => `${countFmt(entry.invoices)} × ${entry.currency} (${moneyFmt(entry.cents, entry.currency)})`).join(', ')}. There is no exchange-rate source, so they are listed under Revenue by Currency instead of being summed as dollars.
            </Notice>
          ) : null}

          {children(snapshot)}

          <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-3 text-[11px] text-white/35">
            <span className="inline-flex items-center gap-2">
              <span className={cn('h-2 w-2 rounded-full', stream === 'live' ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'animate-pulse bg-amber-300')} aria-hidden="true" />
              {stream === 'live' ? 'Live stream connected — checked every 10 seconds, pushed on change' : 'Live stream not connected — Refresh reads the database directly'}
            </span>
            <ReconciliationBadge snapshot={snapshot} />
            <span>Figures in {snapshot.reportingCurrency} · calendar {snapshot.timezone} · as of {dateTimeFmt(snapshot.generatedAt)}</span>
          </footer>
        </>
      ) : null}
    </div>
  );
}

function ReconciliationBadge({ snapshot }: { snapshot: RevenueSnapshot }) {
  const failed = snapshot.reconciliation.checks.filter((check) => !check.ok);
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 font-bold', failed.length ? 'text-red-300' : 'text-emerald-300/80')}
      title={snapshot.reconciliation.checks.map((check) => `${check.ok ? 'OK' : 'MISMATCH'} · ${check.label}`).join('\n')}
    >
      {failed.length ? <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" /> : <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />}
      {failed.length
        ? `${failed.length} reconciliation mismatch${failed.length === 1 ? '' : 'es'}: ${failed.map((check) => check.label).join('; ')}`
        : `Cross-page reconciliation: ${snapshot.reconciliation.checks.length}/${snapshot.reconciliation.checks.length} checks pass`}
    </span>
  );
}

function ExportToast() {
  const context = useContext(RevenueContext);
  const state = context?.exportState;
  if (!state) return null;
  const tone = state.status === 'error' ? 'border-red-400/40 bg-[#1a0b0e] text-red-100' : state.status === 'done' ? 'border-emerald-400/40 bg-[#07170f] text-emerald-100' : 'border-cyan-400/30 bg-[#06131b] text-cyan-100';
  const Icon = state.status === 'error' ? AlertTriangle : state.status === 'done' ? CheckCircle2 : Loader2;
  return (
    <div role={state.status === 'error' ? 'alert' : 'status'} className={cn('fixed bottom-5 right-5 z-[60] flex max-w-sm items-start gap-2.5 rounded-lg border px-4 py-3 text-[12px] shadow-2xl', tone)}>
      <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', state.status === 'running' && 'animate-spin')} aria-hidden="true" />
      <span className="min-w-0 flex-1 leading-relaxed">{state.message}</span>
      {state.status !== 'running' ? (
        <button type="button" onClick={context?.dismissExport} aria-label="Dismiss" className="rounded p-0.5 text-white/50 transition hover:text-white">
          <X className="h-3.5 w-3.5" />
        </button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* KPI card that knows "not measured" from zero                        */
/* ------------------------------------------------------------------ */

export function Kpi({
  label,
  value,
  detail,
  color,
  icon: Icon,
  unmeasured,
}: {
  label: string;
  value: string;
  detail: string;
  color: string;
  icon?: LucideIcon;
  /** When set, the value is not a measurement; the reason replaces the detail. */
  unmeasured?: string | null;
}) {
  const muted = Boolean(unmeasured);
  return (
    <Panel className="min-h-[118px] p-4">
      <div className="flex h-full items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.08em]" style={{ color: muted ? '#94A3B8' : color }}>
            {Icon ? <Icon className="h-3.5 w-3.5" aria-hidden="true" /> : null}
            <span className="truncate">{label}</span>
          </div>
          <div className={cn('mt-3 text-2xl font-semibold', muted ? 'text-white/45' : 'text-white')}>{muted ? '—' : value}</div>
          <div className="mt-1 line-clamp-2 text-[10px] font-bold" style={{ color: muted ? '#94A3B8' : color }} title={unmeasured || detail}>
            {muted ? unmeasured : detail}
          </div>
        </div>
        {Icon ? (
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${muted ? SLATE : color}40`, color: muted ? SLATE : color, backgroundColor: `${muted ? SLATE : color}12` }} aria-hidden="true">
            <Icon className="h-5 w-5" />
          </span>
        ) : null}
      </div>
    </Panel>
  );
}

/** Horizontal bars in money (cents precision; a $1 plan is not rounded away). */
export function MoneyBars({ rows, colorFor, empty }: { rows: Array<{ label: string; cents: number; sub?: string }>; colorFor?: (label: string) => string; empty: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  const ceiling = Math.max(1, ...rows.map((row) => Math.abs(row.cents)));
  return (
    <div className="space-y-3.5">
      {rows.map((row) => {
        const color = colorFor ? colorFor(row.label) : BLUE;
        return (
          <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 text-xs">
            <span className="truncate text-white/72">
              {row.label}
              {row.sub ? <span className="ml-1.5 text-[10px] text-white/35">{row.sub}</span> : null}
            </span>
            <span className="text-right font-mono text-white/80">{moneyFmt(row.cents)}</span>
            <div className="col-span-2 h-2 overflow-hidden rounded-full bg-white/5">
              <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(100, (Math.abs(row.cents) / ceiling) * 100)}%`, backgroundColor: color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function CountBars({ rows, colorFor, empty, unit }: { rows: Array<{ label: string; value: number }>; colorFor?: (label: string) => string; empty: string; unit?: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  const ceiling = Math.max(1, ...rows.map((row) => row.value));
  return (
    <div className="space-y-3.5">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 text-xs">
          <span className="truncate text-white/72">{row.label}</span>
          <span className="text-right font-mono text-white/80">{countFmt(row.value)}{unit ? ` ${unit}` : ''}</span>
          <div className="col-span-2 h-2 overflow-hidden rounded-full bg-white/5">
            <div className="h-full rounded-full transition-all duration-700" style={{ width: `${(row.value / ceiling) * 100}%`, backgroundColor: colorFor ? colorFor(row.label) : BLUE }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export const providerColor = (label: string) => (label === 'PayPal' ? BLUE : label === 'Google Play' ? GREEN : label === 'Stripe' ? VIOLET : SLATE);

/* ------------------------------------------------------------------ */
/* Sortable, paginated table                                           */
/* ------------------------------------------------------------------ */

export interface Column<Row> {
  key: string;
  header: string;
  render: (row: Row) => ReactNode;
  sortValue?: (row: Row) => string | number | null;
  align?: 'left' | 'right';
}

export function DataTable<Row>({
  rows,
  columns,
  rowKey,
  empty,
  pageSize = 25,
  initialSort,
  onRowClick,
  rowLabel,
}: {
  rows: Row[];
  columns: Array<Column<Row>>;
  rowKey: (row: Row) => string;
  empty: string;
  pageSize?: number;
  initialSort?: { key: string; direction: 'asc' | 'desc' };
  onRowClick?: (row: Row) => void;
  /** Accessible name for the row action ("Open customer …"). */
  rowLabel?: (row: Row) => string;
}) {
  const [sort, setSort] = useState(initialSort ?? null);
  const [page, setPage] = useState(0);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((entry) => entry.key === sort.key);
    if (!column?.sortValue) return rows;
    const direction = sort.direction === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const left = column.sortValue!(a);
      const right = column.sortValue!(b);
      if (left === right) return 0;
      if (left === null || left === undefined) return 1;
      if (right === null || right === undefined) return -1;
      return (left < right ? -1 : 1) * direction;
    });
  }, [rows, columns, sort]);

  const pages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, pages - 1);
  useEffect(() => {
    if (page > pages - 1) setPage(pages - 1);
  }, [page, pages]);
  const visible = sorted.slice(safePage * pageSize, safePage * pageSize + pageSize);

  if (!rows.length) return <EmptyState label={empty} />;

  const toggle = (key: string) => {
    setPage(0);
    setSort((current) => (current?.key === key ? { key, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { key, direction: 'desc' }));
  };

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-xs">
          <thead>
            <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/40">
              {columns.map((column) => {
                const active = sort?.key === column.key;
                return (
                  <th
                    key={column.key}
                    scope="col"
                    aria-sort={active ? (sort!.direction === 'asc' ? 'ascending' : 'descending') : undefined}
                    className={cn('pb-2 pr-4 font-black', column.align === 'right' && 'text-right')}
                  >
                    {column.sortValue ? (
                      <button type="button" onClick={() => toggle(column.key)} className={cn('inline-flex items-center gap-1 uppercase tracking-[0.08em] transition hover:text-white/75 focus:outline-none focus-visible:text-white', active && 'text-emerald-200')}>
                        {column.header}
                        {active ? (sort!.direction === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />) : <ArrowUpDown className="h-3 w-3 opacity-40" />}
                      </button>
                    ) : column.header}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr
                key={rowKey(row)}
                className={cn('border-b border-white/5 text-white/75 transition hover:bg-white/[0.03]', onRowClick && 'cursor-pointer focus-within:bg-white/[0.04]')}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={onRowClick ? (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onRowClick(row); } } : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                aria-label={onRowClick && rowLabel ? rowLabel(row) : undefined}
              >
                {columns.map((column) => (
                  <td key={column.key} className={cn('py-2.5 pr-4 align-middle', column.align === 'right' && 'text-right')}>{column.render(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-white/45">
        <span>
          {countFmt(safePage * pageSize + 1)}–{countFmt(Math.min(sorted.length, (safePage + 1) * pageSize))} of {countFmt(sorted.length)}
        </span>
        {pages > 1 ? (
          <div className="flex items-center gap-1.5">
            <button type="button" onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0} aria-label="Previous page" className="rounded border border-white/10 p-1 transition hover:border-emerald-400/40 disabled:opacity-30">
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span>Page {safePage + 1} of {pages}</span>
            <button type="button" onClick={() => setPage(Math.min(pages - 1, safePage + 1))} disabled={safePage >= pages - 1} aria-label="Next page" className="rounded border border-white/10 p-1 transition hover:border-emerald-400/40 disabled:opacity-30">
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** "Showing N of M" for ledgers the snapshot bounds (KPIs always use every row). */
export function LedgerLimitNote({ shown, total, noun, report }: { shown: number; total: number; noun: string; report: string }) {
  const { exportReport } = useRevenue();
  if (total <= shown) return null;
  return (
    <p className="mt-2 text-[11px] text-white/40">
      The live view carries the {countFmt(shown)} most recent {noun} of {countFmt(total)}. Every KPI on this page is computed over all {countFmt(total)};{' '}
      <button type="button" onClick={() => void exportReport(report, 'csv')} className="font-bold text-emerald-300 underline-offset-2 hover:underline">export the full ledger</button>.
    </p>
  );
}

export function SearchBox({ value, onChange, placeholder, label }: { value: string; onChange: (value: string) => void; placeholder: string; label: string }) {
  return (
    <input
      type="search"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      aria-label={label}
      className="h-8 w-full rounded-md border border-white/10 bg-black/30 px-2.5 text-[11px] text-white/85 outline-none placeholder:text-white/25 focus:border-emerald-400/50 sm:w-56"
    />
  );
}

export function SelectBox({ value, onChange, options, label }: { value: string; onChange: (value: string) => void; options: Array<{ value: string; label: string }>; label: string }) {
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-label={label}
      className="h-8 rounded-md border border-white/10 bg-black/30 px-2 text-[11px] text-white/75 outline-none focus:border-emerald-400/50"
    >
      {options.map((option) => (
        <option key={option.value} value={option.value} className="bg-[#0B1526]">{option.label}</option>
      ))}
    </select>
  );
}

/* ------------------------------------------------------------------ */
/* ECharts (dark, enterprise)                                          */
/* ------------------------------------------------------------------ */

const AXIS_STYLE = {
  axisLine: { lineStyle: { color: 'rgba(255,255,255,0.14)' } },
  axisLabel: { color: 'rgba(255,255,255,0.55)', fontSize: 10 },
  splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
};
const TOOLTIP = { trigger: 'axis' as const, backgroundColor: '#0B1526', borderColor: 'rgba(59,130,246,0.35)', textStyle: { color: '#E2E8F0', fontSize: 11 } };
const dollarAxis = (value: number) => (Math.abs(value) >= 1000 ? `$${(value / 1000).toFixed(1)}k` : `$${value}`);
const dollars = (cents: number | null) => (cents === null ? null : Math.round(cents) / 100);

export function Chart({ option, height = 260, label }: { option: EChartsOption; height?: number; label: string }) {
  return (
    <div role="img" aria-label={label}>
      <ReactECharts option={option} style={{ height, width: '100%' }} notMerge lazyUpdate opts={{ renderer: 'svg' }} />
    </div>
  );
}

export function revenueTimelineOption(timeline: TimelineBucket[]): EChartsOption {
  return {
    backgroundColor: 'transparent',
    grid: { left: 56, right: 16, top: 30, bottom: 26 },
    tooltip: { ...TOOLTIP, valueFormatter: (value) => moneyFmt(Number(value) * 100) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: timeline.map((bucket) => (bucket.complete ? bucket.label : `${bucket.label} (MTD)`)), ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: dollarAxis } },
    series: [
      {
        name: 'Net revenue', type: 'line', smooth: true, symbolSize: 5, data: timeline.map((bucket) => dollars(bucket.netCents)),
        lineStyle: { color: EMERALD, width: 2.4 }, itemStyle: { color: EMERALD },
        areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(52,211,153,0.28)' }, { offset: 1, color: 'rgba(52,211,153,0.02)' }] } },
      },
      { name: 'Gross collected', type: 'line', smooth: true, symbolSize: 4, data: timeline.map((bucket) => dollars(bucket.grossCents)), lineStyle: { color: BLUE, width: 1.6, type: 'dashed' }, itemStyle: { color: BLUE } },
      { name: 'Refunds', type: 'bar', barWidth: 8, data: timeline.map((bucket) => dollars(bucket.refundedCents)), itemStyle: { color: 'rgba(239,68,68,0.65)', borderRadius: [3, 3, 0, 0] } },
    ],
  };
}

export function mrrTrendOption(timeline: TimelineBucket[]): EChartsOption {
  return {
    backgroundColor: 'transparent',
    grid: { left: 56, right: 16, top: 30, bottom: 26 },
    tooltip: { ...TOOLTIP, valueFormatter: (value) => moneyFmt(Number(value) * 100) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: timeline.map((bucket) => bucket.label), ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: dollarAxis } },
    series: [
      { name: 'Month-end MRR', type: 'line', step: 'end', data: timeline.map((bucket) => dollars(bucket.endingMrrCents)), lineStyle: { color: CYAN, width: 2.2 }, itemStyle: { color: CYAN } },
      { name: 'New MRR', type: 'bar', barWidth: 9, data: timeline.map((bucket) => dollars(bucket.newMrrCents)), itemStyle: { color: 'rgba(52,211,153,0.7)', borderRadius: [3, 3, 0, 0] } },
    ],
  };
}

export function growthBarsOption(timeline: TimelineBucket[]): EChartsOption {
  return {
    backgroundColor: 'transparent',
    grid: { left: 40, right: 16, top: 30, bottom: 26 },
    tooltip: TOOLTIP,
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: timeline.map((bucket) => bucket.label), ...AXIS_STYLE },
    yAxis: { type: 'value', minInterval: 1, ...AXIS_STYLE },
    series: [
      { name: 'New sign-ups', type: 'bar', barWidth: 8, data: timeline.map((bucket) => bucket.newSignups), itemStyle: { color: GREEN, borderRadius: [3, 3, 0, 0] } },
      { name: 'New billed subscriptions', type: 'bar', barWidth: 8, data: timeline.map((bucket) => bucket.newSubscriptions), itemStyle: { color: BLUE, borderRadius: [3, 3, 0, 0] } },
      { name: 'Churned subscriptions', type: 'bar', barWidth: 8, data: timeline.map((bucket) => bucket.churnedSubscriptions), itemStyle: { color: 'rgba(239,68,68,0.7)', borderRadius: [3, 3, 0, 0] } },
    ],
  };
}

/** Actual completed months, month-to-date, and the projection — three distinct series. */
export function forecastOption(snapshot: RevenueSnapshot): EChartsOption {
  const { timeline, forecast } = snapshot;
  const completed = timeline.filter((bucket) => bucket.complete);
  const future = forecast.horizon.filter((month) => !month.isCurrentMonth);
  const current = forecast.horizon.find((month) => month.isCurrentMonth) ?? null;
  const labels = [...completed.map((bucket) => bucket.label), ...(current ? [current.label] : []), ...future.map((month) => month.label)];
  const actual = [...completed.map((bucket) => dollars(bucket.netCents)), ...(current ? [null] : []), ...future.map(() => null)];
  const monthToDate = [...completed.map(() => null), ...(current ? [dollars(current.actualToDateCents)] : []), ...future.map(() => null)];
  const projected = forecast.revenueProjectionAvailable
    ? [
      ...completed.slice(0, -1).map(() => null),
      completed.length ? dollars(completed[completed.length - 1].netCents) : null,
      ...(current ? [dollars(current.projectedNetCents)] : []),
      ...future.map((month) => dollars(month.projectedNetCents)),
    ]
    : [];
  return {
    backgroundColor: 'transparent',
    grid: { left: 56, right: 16, top: 30, bottom: 26 },
    tooltip: { ...TOOLTIP, valueFormatter: (value) => (value === null || value === undefined ? '—' : moneyFmt(Number(value) * 100)) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: labels, ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: dollarAxis } },
    series: [
      { name: 'Actual (completed months)', type: 'line', smooth: true, data: actual, lineStyle: { color: EMERALD, width: 2.4 }, itemStyle: { color: EMERALD } },
      { name: 'Actual (month to date)', type: 'scatter', symbolSize: 10, data: monthToDate, itemStyle: { color: GOLD } },
      ...(projected.length ? [{ name: 'Forecast (linear trend)', type: 'line' as const, smooth: true, data: projected, lineStyle: { color: CYAN, width: 2, type: 'dashed' as const }, itemStyle: { color: CYAN } }] : []),
    ],
  };
}

export function mrrForecastOption(snapshot: RevenueSnapshot): EChartsOption {
  const horizon = snapshot.forecast.horizon;
  return {
    backgroundColor: 'transparent',
    grid: { left: 56, right: 16, top: 30, bottom: 26 },
    tooltip: { ...TOOLTIP, valueFormatter: (value) => (value === null || value === undefined ? '—' : moneyFmt(Number(value) * 100)) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: ['Now', ...horizon.map((month) => month.label)], ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: dollarAxis } },
    series: [
      { name: 'Optimistic (assumption)', type: 'line', data: [dollars(snapshot.kpis.mrrCents), ...horizon.map((month) => dollars(month.projectedMrrHighCents))], lineStyle: { color: GREEN, width: 1.4, type: 'dotted' }, itemStyle: { color: GREEN }, symbolSize: 4 },
      { name: 'Base (measured churn + new MRR)', type: 'line', data: [dollars(snapshot.kpis.mrrCents), ...horizon.map((month) => dollars(month.projectedMrrCents))], lineStyle: { color: CYAN, width: 2.2, type: 'dashed' }, itemStyle: { color: CYAN } },
      { name: 'Conservative (assumption)', type: 'line', data: [dollars(snapshot.kpis.mrrCents), ...horizon.map((month) => dollars(month.projectedMrrLowCents))], lineStyle: { color: AMBER, width: 1.4, type: 'dotted' }, itemStyle: { color: AMBER }, symbolSize: 4 },
    ],
  };
}

/* ------------------------------------------------------------------ */
/* Shared panels                                                       */
/* ------------------------------------------------------------------ */

export function DataGapsPanel({ gaps, title = 'Not yet measured (no fabricated data)' }: { gaps: RevenueSnapshot['dataGaps']; title?: string }) {
  if (!gaps.length) return null;
  return (
    <Panel className="p-4">
      <SectionTitle>{title}</SectionTitle>
      <div className="space-y-2.5">
        {gaps.map((gap) => (
          <div key={gap.metric} className="rounded-md border border-white/8 bg-white/[0.02] px-3 py-2">
            <div className="text-[11px] font-bold text-white/75">{gap.metric}</div>
            <div className="mt-0.5 text-[11px] leading-relaxed text-white/45">{gap.reason}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

const SEVERITY_COLOR: Record<string, string> = { success: EMERALD, critical: RED, warning: AMBER, info: CYAN };

export function ActivityFeed({ activity, limit = 8 }: { activity: ActivityEntry[]; limit?: number }) {
  const { openCustomer } = useRevenue();
  if (!activity.length) return <EmptyState label="No billing activity yet." hint="Payments, refunds, failures and subscription changes stream here live." />;
  return (
    <ul className="space-y-2">
      {activity.slice(0, limit).map((entry) => {
        const color = SEVERITY_COLOR[entry.severity] ?? SLATE;
        return (
          <li key={entry.id} className="flex items-start justify-between gap-3 rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
            <div className="min-w-0">
              <div className="truncate text-[11px] font-bold" style={{ color: entry.severity === 'critical' ? RED : 'rgba(255,255,255,0.82)' }}>{entry.title}</div>
              <div className="truncate text-[10px] text-white/40">
                {entry.userId ? (
                  <button type="button" onClick={() => openCustomer(entry.userId!)} className="font-semibold text-white/60 hover:text-emerald-200">{entry.email || entry.userId.slice(0, 8)}</button>
                ) : null}
                {entry.userId && entry.detail ? ' · ' : null}
                {entry.detail}
              </div>
            </div>
            <div className="shrink-0 text-right">
              {entry.amountCents !== null ? <div className="font-mono text-[11px] font-bold" style={{ color }}>{moneyFmt(entry.amountCents)}</div> : null}
              <div className="text-[10px] text-white/35" title={dateTimeFmt(entry.at)}>{timeAgo(entry.at)}</div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function AlertsPanel({ alerts, limit = 6 }: { alerts: AlertEntry[]; limit?: number }) {
  const { openCustomer } = useRevenue();
  if (!alerts.length) return <EmptyState label="No billing alerts." hint="Failed payments, cancellations, expirations and refunds raise alerts here." />;
  return (
    <ul className="space-y-2">
      {alerts.slice(0, limit).map((alert) => {
        const color = SEVERITY_COLOR[alert.severity] ?? CYAN;
        return (
          <li key={alert.id} className="flex items-start gap-2.5 rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
            <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[11px] font-bold text-white/82">{alert.title}</span>
                <span className="shrink-0 text-[10px] text-white/35" title={dateTimeFmt(alert.at)}>{timeAgo(alert.at)}</span>
              </div>
              <div className="mt-0.5 text-[10px] leading-relaxed text-white/45">
                {alert.userId ? (
                  <button type="button" onClick={() => openCustomer(alert.userId!)} className="mr-1 font-semibold text-white/60 hover:text-emerald-200">{alert.email || alert.userId.slice(0, 8)}:</button>
                ) : null}
                {alert.message}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/* ------------------------------------------------------------------ */
/* Customer drawer — one customer's full billing record                 */
/* ------------------------------------------------------------------ */

interface CustomerDetail {
  userId: string;
  profile: { email: string | null; name: string | null; tier: string | null; createdAt: string | null } | null;
  customer: CustomerRow | null;
  subscriptions: SubscriberRow[];
  invoices: InvoiceLedgerRow[];
  activity: ActivityEntry[];
  notifications: AlertEntry[];
  invoicesTruncated: boolean;
}

function CustomerDrawer({ userId, onClose }: { userId: string; onClose: () => void }) {
  const { session } = useAuth();
  const token = session?.access_token ?? null;
  const [detail, setDetail] = useState<CustomerDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    setDetail(null);
    setError(null);
    fetch(`/api/v1/revenue/customers/${encodeURIComponent(userId)}`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal, cache: 'no-store' })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setDetail(payload.data as CustomerDetail);
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : 'Failed to load the customer');
      });
    return () => controller.abort();
    // `token` is a primitive; a refreshed token re-reads the record.
  }, [userId, token, attempt]);

  // `onClose` is a fresh closure on every layout render (every live frame); read
  // it through a ref so focus is taken once, on open, not every 10 seconds.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseRef.current();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      previousFocus?.focus?.();
    };
  }, []);

  const customer = detail?.customer ?? null;
  const email = detail?.profile?.email || customer?.email || userId;

  return (
    <div className="fixed inset-0 z-[70] flex justify-end" role="dialog" aria-modal="true" aria-label={`Customer ${email}`}>
      <button type="button" aria-label="Close customer details" className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} tabIndex={-1} />
      <aside className="relative flex h-full w-full max-w-[640px] flex-col overflow-hidden border-l border-emerald-400/20 bg-[#050b15] shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-white/8 px-5 py-4">
          <div className="min-w-0">
            <div className="text-[10px] font-black uppercase tracking-[0.14em] text-emerald-300">Customer record</div>
            <h2 className="mt-1 truncate text-lg font-semibold text-white">{email}</h2>
            {detail?.profile?.name ? <p className="truncate text-xs text-white/50">{detail.profile.name}</p> : null}
            <p className="mt-0.5 font-mono text-[10px] text-white/30">{userId}</p>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close" className="rounded-md border border-white/10 p-1.5 text-white/60 transition hover:border-emerald-400/40 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {!detail && !error ? (
            <div className="flex items-center gap-2 text-sm text-white/50" aria-busy="true"><Loader2 className="h-4 w-4 animate-spin" /> Loading billing record…</div>
          ) : null}
          {error ? (
            <Notice tone="error" icon={AlertTriangle} title="The customer record could not be loaded" action={<ActionButton icon={RefreshCw} onClick={() => setAttempt((value) => value + 1)}>Retry</ActionButton>}>
              {error}
            </Notice>
          ) : null}
          {detail ? (
            <>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {[
                  { label: 'Lifetime net', value: moneyFmt(customer?.lifetimeNetCents ?? 0) },
                  { label: 'MRR', value: moneyFmt(customer?.mrrCents ?? 0) },
                  { label: 'Paid invoices', value: countFmt(customer?.paidInvoices ?? 0) },
                  { label: 'Failed payments', value: countFmt(customer?.failedPayments ?? 0) },
                ].map((stat) => (
                  <div key={stat.label} className="rounded-md border border-white/8 bg-white/[0.02] px-3 py-2">
                    <div className="text-[10px] font-bold uppercase tracking-wide text-white/40">{stat.label}</div>
                    <div className="mt-1 font-mono text-sm font-semibold text-white">{stat.value}</div>
                  </div>
                ))}
              </div>

              <section>
                <SectionTitle>Subscription</SectionTitle>
                {detail.subscriptions.length ? detail.subscriptions.map((sub) => (
                  <div key={sub.id} className="grid grid-cols-2 gap-x-4 gap-y-1.5 rounded-md border border-white/8 bg-white/[0.02] p-3 text-[11px]">
                    <span className="text-white/45">Plan</span><span className="font-bold" style={{ color: PLAN_COLORS[sub.plan || ''] ?? SLATE }}>{sub.plan || '—'}</span>
                    <span className="text-white/45">Status</span><span><StatusPill value={sub.status} /></span>
                    <span className="text-white/45">Revenue class</span><span><ClassPill value={sub.revenueClass} title={sub.classReason} /></span>
                    <span className="text-white/45">Provider</span><span>{sub.providerLabel}</span>
                    <span className="text-white/45">Cycle</span><span>{sub.billingCycle === 'annual' ? 'Yearly' : 'Monthly'}</span>
                    <span className="text-white/45">Monthly value</span><span className="font-mono">{moneyFmt(sub.monthlyValueCents)} <span className="text-white/35">({sub.priceSource})</span></span>
                    <span className="text-white/45">Customer since</span><span>{dateFmt(sub.since)}</span>
                    <span className="text-white/45">Renews / ends</span><span>{dateFmt(sub.renewalDate)}{sub.cancelAtPeriodEnd ? ' · ends at period end' : ''}</span>
                    <span className="col-span-2 mt-1 text-[10px] leading-relaxed text-white/40">{sub.classReason}</span>
                  </div>
                )) : <EmptyState label="No subscription record." />}
              </section>

              <section>
                <SectionTitle>Payments ({countFmt(detail.invoices.length)}{detail.invoicesTruncated ? '+' : ''})</SectionTitle>
                {detail.invoices.length ? (
                  <ul className="space-y-1.5">
                    {detail.invoices.map((invoice) => (
                      <li key={invoice.id} className="flex items-center justify-between gap-3 rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                        <div className="min-w-0">
                          <div className="font-semibold text-white/80">{dateTimeFmt(invoice.paidAt)}</div>
                          <div className="truncate font-mono text-[10px] text-white/35">{invoice.method || 'Payment'} · {invoice.invoiceId}</div>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <span className="font-mono font-bold text-white/85">{moneyFmt(invoice.amountCents, invoice.currency)}</span>
                          {invoice.refundedCents > 0 ? <span className="font-mono text-amber-300">−{moneyFmt(invoice.refundedCents, invoice.currency)}</span> : null}
                          <StatusPill value={invoice.status} />
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : <EmptyState label="No payments recorded for this customer." />}
              </section>

              <section>
                <SectionTitle>Billing history</SectionTitle>
                {detail.activity.length ? (
                  <ol className="space-y-1.5 border-l border-white/10 pl-3">
                    {detail.activity.map((entry) => (
                      <li key={entry.id} className="text-[11px]">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold" style={{ color: SEVERITY_COLOR[entry.severity] ?? 'rgba(255,255,255,0.8)' }}>{entry.title}</span>
                          <span className="shrink-0 text-[10px] text-white/35">{dateTimeFmt(entry.at)}</span>
                        </div>
                        {entry.detail ? <div className="text-[10px] text-white/40">{entry.detail}</div> : null}
                      </li>
                    ))}
                  </ol>
                ) : <EmptyState label="No billing events recorded." hint="Subscription changes, payments and refunds are audited from the moment they happen." />}
              </section>

              <section>
                <SectionTitle>Notifications sent</SectionTitle>
                {detail.notifications.length ? (
                  <ul className="space-y-1.5">
                    {detail.notifications.map((note) => (
                      <li key={note.id} className="rounded-md border border-white/6 bg-white/[0.02] px-3 py-2 text-[11px]">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-white/80">{note.title}</span>
                          <span className="shrink-0 text-[10px] text-white/35">{dateTimeFmt(note.at)}</span>
                        </div>
                        <div className="text-[10px] text-white/45">{note.message}</div>
                      </li>
                    ))}
                  </ul>
                ) : <EmptyState label="No billing notifications sent to this customer." />}
              </section>
              <p className="text-[10px] text-white/30">Viewing this record is written to the owner audit trail (admin_audit_events).</p>
            </>
          ) : null}
        </div>
      </aside>
    </div>
  );
}
