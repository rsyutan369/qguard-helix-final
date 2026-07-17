'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, Navigate, useLocation } from 'react-router-dom';
import ReactECharts from 'echarts-for-react';
import type { EChartsOption } from 'echarts';
import { Crown, Wifi, WifiOff } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { isOwnerEmail } from '@/lib/admin-access';
import { cn } from '@/lib/utils';
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

/* ------------------------------------------------------------------ */
/* Snapshot contract — mirrors src/api-server/revenue.ts               */
/* ------------------------------------------------------------------ */

export interface RevenueTimelineBucket {
  month: string;
  label: string;
  grossCents: number;
  refundedCents: number;
  netCents: number;
  payments: number;
  newSubscriptions: number;
  newCustomers: number;
}

export interface RevenueSnapshot {
  generatedAt: string | null;
  hasData: boolean;
  unavailableTables: string[];
  dataGaps: Array<{ metric: string; reason: string }>;
  kpis: {
    totalRevenueCents: number;
    grossRevenueCents: number;
    netRevenueCents: number;
    refundedCents: number;
    lifetimeRevenueCents: number;
    mrrCents: number;
    arrCents: number;
    arpuCents: number;
    ltvCents: number | null;
    revenueGrowthPct: number | null;
    activeSubscribers: number;
    subscriptionHealthScore: number | null;
    churnPct: number | null;
    retentionPct: number | null;
  };
  windows: {
    todayCents: number;
    yesterdayCents: number;
    thisWeekCents: number;
    thisMonthCents: number;
    lastMonthCents: number;
    thisQuarterCents: number;
    thisYearCents: number;
    allTimeCents: number;
  };
  timeline: RevenueTimelineBucket[];
  revenueByProvider: Array<{ label: string; cents: number; count: number }>;
  revenueByPlanInvoiced: Array<{ label: string; cents: number; count: number }>;
  revenueByCurrency: Array<{ label: string; cents: number; count: number }>;
  paymentAnalytics: {
    successful: number;
    failed: number;
    refunds: number;
    pending: number;
    successRatePct: number | null;
    averagePaymentCents: number;
    totalPayments: number;
    refundedCents: number;
  };
  subscriptionAnalytics: {
    total: number;
    active: number;
    trial: number;
    pendingRenewal: number;
    pastDue: number;
    suspended: number;
    cancelled: number;
    expired: number;
    incomplete: number;
    renewing: number;
    endingAtPeriodEnd: number;
    renewalRatePct: number | null;
    upgrades30d: number;
    downgrades30d: number;
    churnPct: number | null;
    retentionPct: number | null;
    healthScore: number | null;
    healthComponents: { activeSharePct: number; renewalPct: number; paymentSuccessPct: number; retentionPct: number };
    planBreakdown: Array<{ plan: string; total: number; active: number; trial: number; cancelled: number; mrrCents: number; invoicedCents: number }>;
  };
  customerAnalytics: {
    totalUsers: number;
    totalCustomers: number;
    activeCustomers: number;
    inactiveCustomers: number;
    trialUsers: number;
    cancelledCustomers: number;
    newCustomers30d: number;
    enterpriseCustomers: number;
    arpuCents: number;
    ltvCents: number | null;
    averageCustomerValueCents: number;
    customerGrowthPct: number | null;
  };
  customers: Array<{
    userId: string; email: string | null; name: string | null; plan: string | null; status: string | null;
    provider: string | null; billingCycle: string | null; since: string | null; renewalDate: string | null; lifetimeCents: number;
  }>;
  subscribers: Array<{
    id: string; userId: string; email: string | null; plan: string; status: string; provider: string | null;
    billingCycle: string; autoRenew: boolean; cancelAtPeriodEnd: boolean; since: string; renewalDate: string | null; mrrCents: number;
  }>;
  invoices: Array<{
    id: string; invoiceId: string; userId: string; email: string | null; plan: string;
    amountCents: number; currency: string; method: string | null; status: string; at: string;
  }>;
  activity: Array<{ at: string; kind: 'audit' | 'payment'; title: string; detail: string; amountCents: number | null; severity: string }>;
  alerts: Array<{ id: string; at: string; type: string; severity: string; title: string; message: string }>;
  forecast: {
    methodology: string;
    confidence: string;
    observedMonths: number;
    horizon: Array<{ month: string; label: string; projectedNetCents: number; projectedNewSubscriptions: number; projectedMrrCents: number }>;
    projectedArrCents: number;
  };
}

export const EMPTY_REVENUE: RevenueSnapshot = {
  generatedAt: null,
  hasData: false,
  unavailableTables: [],
  dataGaps: [],
  kpis: {
    totalRevenueCents: 0, grossRevenueCents: 0, netRevenueCents: 0, refundedCents: 0, lifetimeRevenueCents: 0,
    mrrCents: 0, arrCents: 0, arpuCents: 0, ltvCents: null, revenueGrowthPct: null,
    activeSubscribers: 0, subscriptionHealthScore: null, churnPct: null, retentionPct: null,
  },
  windows: { todayCents: 0, yesterdayCents: 0, thisWeekCents: 0, thisMonthCents: 0, lastMonthCents: 0, thisQuarterCents: 0, thisYearCents: 0, allTimeCents: 0 },
  timeline: [],
  revenueByProvider: [],
  revenueByPlanInvoiced: [],
  revenueByCurrency: [],
  paymentAnalytics: { successful: 0, failed: 0, refunds: 0, pending: 0, successRatePct: null, averagePaymentCents: 0, totalPayments: 0, refundedCents: 0 },
  subscriptionAnalytics: {
    total: 0, active: 0, trial: 0, pendingRenewal: 0, pastDue: 0, suspended: 0, cancelled: 0, expired: 0, incomplete: 0,
    renewing: 0, endingAtPeriodEnd: 0, renewalRatePct: null, upgrades30d: 0, downgrades30d: 0, churnPct: null, retentionPct: null,
    healthScore: null, healthComponents: { activeSharePct: 0, renewalPct: 0, paymentSuccessPct: 0, retentionPct: 0 }, planBreakdown: [],
  },
  customerAnalytics: {
    totalUsers: 0, totalCustomers: 0, activeCustomers: 0, inactiveCustomers: 0, trialUsers: 0, cancelledCustomers: 0,
    newCustomers30d: 0, enterpriseCustomers: 0, arpuCents: 0, ltvCents: null, averageCustomerValueCents: 0, customerGrowthPct: null,
  },
  customers: [],
  subscribers: [],
  invoices: [],
  activity: [],
  alerts: [],
  forecast: { methodology: '', confidence: 'insufficient-history', observedMonths: 0, horizon: [], projectedArrCents: 0 },
};

/* ------------------------------------------------------------------ */
/* Formatters + palette                                                */
/* ------------------------------------------------------------------ */

export const PLAN_COLORS: Record<string, string> = { Starter: BLUE, Basic: VIOLET, Pro: CYAN, Elite: GOLD };
export const PROVIDER_COLORS: Record<string, string> = { PayPal: BLUE, 'Google Play': GREEN, Manual: SLATE };

export function moneyFmt(cents: number | null | undefined): string {
  if (cents === null || cents === undefined) return '—';
  const value = cents / 100;
  return new Intl.NumberFormat('en-US', {
    style: 'currency', currency: 'USD',
    notation: Math.abs(value) >= 1_000_000 ? 'compact' : 'standard',
    maximumFractionDigits: 2,
  }).format(value);
}

export function pctFmt(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return `${value > 0 ? '+' : ''}${value}%`;
}

export function dateFmt(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function timeAgo(value: string | null): string {
  if (!value) return '';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export const STATUS_COLORS: Record<string, string> = {
  active: EMERALD, trial: CYAN, pending_renewal: AMBER, past_due: RED,
  suspended: RED, cancelled: SLATE, expired: RED, incomplete: AMBER, paid: EMERALD, failed: RED, refunded: AMBER, pending: SLATE,
};

export function StatusPill({ value }: { value: string | null }) {
  const key = String(value || '').toLowerCase();
  const color = STATUS_COLORS[key] ?? SLATE;
  return (
    <span className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" style={{ color, backgroundColor: `${color}14`, border: `1px solid ${color}38` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {key.replace(/_/g, ' ') || '—'}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* ECharts helpers (dark, enterprise)                                  */
/* ------------------------------------------------------------------ */

const AXIS_STYLE = {
  axisLine: { lineStyle: { color: 'rgba(255,255,255,0.14)' } },
  axisLabel: { color: 'rgba(255,255,255,0.55)', fontSize: 10 },
  splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)' } },
};

export function Chart({ option, height = 260 }: { option: EChartsOption; height?: number }) {
  return <ReactECharts option={option} style={{ height, width: '100%' }} notMerge lazyUpdate theme={undefined} opts={{ renderer: 'svg' }} />;
}

/** Area/line chart of the monthly revenue timeline (gross / net / refunds). */
export function revenueTimelineOption(timeline: RevenueTimelineBucket[]): EChartsOption {
  return {
    backgroundColor: 'transparent',
    grid: { left: 52, right: 16, top: 30, bottom: 26 },
    tooltip: { trigger: 'axis', backgroundColor: '#0B1526', borderColor: 'rgba(59,130,246,0.35)', textStyle: { color: '#E2E8F0', fontSize: 11 }, valueFormatter: (value) => moneyFmt(Number(value) * 100) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: timeline.map((bucket) => bucket.label), ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: (value: number) => `$${value >= 1000 ? `${(value / 1000).toFixed(0)}k` : value}` } },
    series: [
      {
        name: 'Net Revenue', type: 'line', smooth: true, symbolSize: 5,
        data: timeline.map((bucket) => Math.round(bucket.netCents) / 100),
        lineStyle: { color: EMERALD, width: 2.4 }, itemStyle: { color: EMERALD },
        areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(52,211,153,0.28)' }, { offset: 1, color: 'rgba(52,211,153,0.02)' }] } },
      },
      { name: 'Gross', type: 'line', smooth: true, symbolSize: 4, data: timeline.map((bucket) => Math.round(bucket.grossCents) / 100), lineStyle: { color: BLUE, width: 1.6, type: 'dashed' }, itemStyle: { color: BLUE } },
      { name: 'Refunded', type: 'bar', barWidth: 8, data: timeline.map((bucket) => Math.round(bucket.refundedCents) / 100), itemStyle: { color: 'rgba(239,68,68,0.65)', borderRadius: [3, 3, 0, 0] } },
    ],
  };
}

/** Grouped bars: new customers vs new subscriptions per month. */
export function growthBarsOption(timeline: RevenueTimelineBucket[]): EChartsOption {
  return {
    backgroundColor: 'transparent',
    grid: { left: 40, right: 16, top: 30, bottom: 26 },
    tooltip: { trigger: 'axis', backgroundColor: '#0B1526', borderColor: 'rgba(59,130,246,0.35)', textStyle: { color: '#E2E8F0', fontSize: 11 } },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: timeline.map((bucket) => bucket.label), ...AXIS_STYLE },
    yAxis: { type: 'value', minInterval: 1, ...AXIS_STYLE },
    series: [
      { name: 'New Customers', type: 'bar', barWidth: 9, data: timeline.map((bucket) => bucket.newCustomers), itemStyle: { color: GREEN, borderRadius: [3, 3, 0, 0] } },
      { name: 'New Subscriptions', type: 'bar', barWidth: 9, data: timeline.map((bucket) => bucket.newSubscriptions), itemStyle: { color: BLUE, borderRadius: [3, 3, 0, 0] } },
    ],
  };
}

/** Actual net revenue + projected continuation (forecast band). */
export function forecastOption(snapshot: RevenueSnapshot): EChartsOption {
  const actualLabels = snapshot.timeline.map((bucket) => bucket.label);
  const futureLabels = snapshot.forecast.horizon.map((bucket) => bucket.label);
  const actual = snapshot.timeline.map((bucket) => Math.round(bucket.netCents) / 100);
  const projected = [
    ...Array(Math.max(0, actual.length - 1)).fill(null),
    actual[actual.length - 1] ?? null,
    ...snapshot.forecast.horizon.map((bucket) => Math.round(bucket.projectedNetCents) / 100),
  ];
  return {
    backgroundColor: 'transparent',
    grid: { left: 52, right: 16, top: 30, bottom: 26 },
    tooltip: { trigger: 'axis', backgroundColor: '#0B1526', borderColor: 'rgba(59,130,246,0.35)', textStyle: { color: '#E2E8F0', fontSize: 11 }, valueFormatter: (value) => (value === null ? '—' : moneyFmt(Number(value) * 100)) },
    legend: { top: 0, textStyle: { color: 'rgba(255,255,255,0.6)', fontSize: 10 }, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: [...actualLabels, ...futureLabels], ...AXIS_STYLE },
    yAxis: { type: 'value', ...AXIS_STYLE, axisLabel: { ...AXIS_STYLE.axisLabel, formatter: (value: number) => `$${value >= 1000 ? `${(value / 1000).toFixed(0)}k` : value}` } },
    series: [
      { name: 'Actual Net Revenue', type: 'line', smooth: true, data: actual, lineStyle: { color: EMERALD, width: 2.4 }, itemStyle: { color: EMERALD } },
      { name: 'Projected (linear trend)', type: 'line', smooth: true, data: projected, lineStyle: { color: CYAN, width: 2, type: 'dashed' }, itemStyle: { color: CYAN } },
    ],
  };
}

/* ------------------------------------------------------------------ */
/* Data hook — snapshot fetch + owner SSE stream                       */
/* ------------------------------------------------------------------ */

export type LoadState = 'loading' | 'success' | 'error';

export function useRevenueIntelligence() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<RevenueSnapshot>(EMPTY_REVENUE);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const streamRef = useRef<EventSource | null>(null);

  const applySnapshot = useCallback((data: Partial<RevenueSnapshot>) => {
    setSnapshot({
      ...EMPTY_REVENUE,
      ...data,
      kpis: { ...EMPTY_REVENUE.kpis, ...(data.kpis || {}) },
      windows: { ...EMPTY_REVENUE.windows, ...(data.windows || {}) },
      paymentAnalytics: { ...EMPTY_REVENUE.paymentAnalytics, ...(data.paymentAnalytics || {}) },
      subscriptionAnalytics: { ...EMPTY_REVENUE.subscriptionAnalytics, ...(data.subscriptionAnalytics || {}) },
      customerAnalytics: { ...EMPTY_REVENUE.customerAnalytics, ...(data.customerAnalytics || {}) },
      forecast: { ...EMPTY_REVENUE.forecast, ...(data.forecast || {}) },
    });
    setState('success');
    setError(null);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const response = await fetch('/api/v1/revenue/snapshot', { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      applySnapshot(payload.data || {});
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load revenue intelligence');
      setState('error');
    }
  }, [token, applySnapshot]);

  useEffect(() => {
    if (!token || !user) return;
    void refresh();
  }, [token, user, refresh]);

  // Live: the owner-gated SSE stream pushes the FULL rebuilt snapshot every 10s
  // (client-side Supabase realtime cannot see other users' billing rows under
  // RLS, so the service-role stream is the correct live channel here).
  useEffect(() => {
    if (!token) return;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      streamRef.current?.close();
      const stream = new EventSource(`/api/v1/revenue/stream?token=${encodeURIComponent(token)}`);
      streamRef.current = stream;
      stream.onopen = () => setSseConnected(true);
      stream.onerror = () => {
        setSseConnected(false);
        stream.close();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10_000);
      };
      stream.addEventListener('revenue-snapshot', (event) => {
        try {
          applySnapshot(JSON.parse((event as MessageEvent).data));
        } catch {
          // Malformed frame — the next push corrects it.
        }
      });
    };
    connect();
    return () => {
      if (retryTimer) clearTimeout(retryTimer);
      streamRef.current?.close();
      streamRef.current = null;
      setSseConnected(false);
    };
  }, [token, applySnapshot]);

  const exportReport = useCallback((report: string, format: 'csv' | 'json') => {
    if (!token) return;
    const url = `/api/v1/revenue/export?report=${encodeURIComponent(report)}&format=${format}&token=${encodeURIComponent(token)}`;
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = '';
    anchor.click();
  }, [token]);

  return { snapshot, state, error, sseConnected, refresh, exportReport };
}

/* ------------------------------------------------------------------ */
/* Navigation + shell                                                  */
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
  return (
    <div className="-mx-1 flex gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
      {REVENUE_PAGES.map((page) => {
        const active = location.pathname === page.path;
        return (
          <Link
            key={page.path}
            to={page.path}
            className={cn(
              'whitespace-nowrap rounded-md border px-3 py-1.5 text-[11px] font-bold no-underline transition',
              active
                ? 'border-emerald-400/50 bg-emerald-500/15 text-emerald-200'
                : 'border-white/8 bg-black/20 text-white/55 hover:border-emerald-400/35 hover:text-emerald-200',
            )}
          >
            {page.short}
          </Link>
        );
      })}
    </div>
  );
}

export function RevenueShell({
  title,
  subtitle,
  actions,
  sseConnected,
  state,
  snapshot,
  children,
}: {
  title: string;
  subtitle: string;
  actions?: ReactNode;
  sseConnected: boolean;
  state: LoadState;
  snapshot: RevenueSnapshot;
  children: ReactNode;
}) {
  const { user, loading } = useAuth();
  // OWNER-ONLY, exactly like /dashboard/admin: no subscription tier unlocks
  // Revenue Intelligence; the backend enforces the same rule on every request.
  if (!loading && !isOwnerEmail(user?.email)) {
    return <Navigate to="/dashboard" replace />;
  }
  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1560px] space-y-4">
        <RevenueSubnav />
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-500/[0.07] px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-emerald-300">
              <Crown className="h-3.5 w-3.5" />
              Revenue Intelligence™ · Owner Only
            </div>
            <h1 className="text-2xl font-semibold tracking-normal text-white">{title}</h1>
            <p className="mt-1 max-w-3xl text-sm text-white/58">{subtitle}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <span className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-2 text-[11px] font-bold', sseConnected ? 'border-emerald-400/30 text-emerald-200' : 'border-amber-400/30 text-amber-200')}>
              {sseConnected ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
              {sseConnected ? 'Live' : 'Reconnecting'}
            </span>
            {actions}
          </div>
        </header>

        {!snapshot.hasData && state === 'success' ? (
          <div className="rounded-md border border-amber-400/25 bg-amber-400/[0.07] px-4 py-3 text-sm text-amber-100/90">
            No billing evidence yet. Every figure on this dashboard is computed from real subscriptions and invoices —
            it populates automatically the moment your first PayPal or Google Play payment lands (webhooks write
            billing_subscriptions / billing_invoices, and the live stream updates this page without a refresh).
          </div>
        ) : null}

        {state === 'error' ? (
          <div className="rounded-md border border-red-400/30 bg-red-500/[0.08] px-4 py-3 text-sm text-red-200">
            Revenue intelligence failed to load. Retry from the browser, and verify the API server + Supabase service
            role configuration if it persists.
          </div>
        ) : null}

        {children}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-amber-300 animate-pulse')} />
            {sseConnected ? 'Live revenue stream connected — updates every 10 seconds' : 'Connecting live revenue stream'}
          </span>
          <span>Last synchronized: {snapshot.generatedAt ? new Date(snapshot.generatedAt).toLocaleString() : '—'}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Shared panels                                                       */
/* ------------------------------------------------------------------ */

/** Honest "no evidence" panel: metrics we refuse to fabricate. */
export function DataGapsPanel({ gaps }: { gaps: RevenueSnapshot['dataGaps'] }) {
  if (!gaps.length) return null;
  return (
    <Panel className="p-4">
      <SectionTitle>Not yet measured (no fabricated data)</SectionTitle>
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

export function ActivityFeed({ activity, limit = 8 }: { activity: RevenueSnapshot['activity']; limit?: number }) {
  if (!activity.length) return <EmptyState label="No billing activity yet." hint="Payments, renewals, and billing events stream here live." />;
  return (
    <div className="space-y-2">
      {activity.slice(0, limit).map((entry, index) => {
        const color = STATUS_COLORS[entry.severity] ?? (entry.severity === 'success' ? EMERALD : entry.severity === 'critical' ? RED : entry.severity === 'warning' ? AMBER : SLATE);
        return (
          <div key={`${entry.at}-${index}`} className="flex items-start justify-between gap-3 rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
            <div className="min-w-0">
              <div className="truncate text-[11px] font-bold text-white/82" style={entry.severity === 'critical' ? { color: RED } : undefined}>{entry.title}</div>
              <div className="truncate text-[10px] text-white/40">{entry.detail}</div>
            </div>
            <div className="shrink-0 text-right">
              {entry.amountCents !== null ? <div className="font-mono text-[11px] font-bold" style={{ color }}>{moneyFmt(entry.amountCents)}</div> : null}
              <div className="text-[10px] text-white/35">{timeAgo(entry.at)}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function AlertsPanel({ alerts, limit = 6 }: { alerts: RevenueSnapshot['alerts']; limit?: number }) {
  if (!alerts.length) return <EmptyState label="No billing alerts." hint="Failed payments, expirations, and refunds raise alerts here." />;
  return (
    <div className="space-y-2">
      {alerts.slice(0, limit).map((alert) => {
        const color = alert.severity === 'critical' ? RED : alert.severity === 'warning' ? AMBER : alert.severity === 'success' ? EMERALD : CYAN;
        return (
          <div key={alert.id} className="flex items-start gap-2.5 rounded-md border border-white/6 bg-white/[0.02] px-3 py-2">
            <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[11px] font-bold text-white/82">{alert.title}</span>
                <span className="shrink-0 text-[10px] text-white/35">{timeAgo(alert.at)}</span>
              </div>
              <div className="mt-0.5 text-[10px] leading-relaxed text-white/45">{alert.message}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Simple enterprise data table (headers + rows of nodes). */
export function DataTable({ headers, rows, empty }: { headers: string[]; rows: ReactNode[][]; empty: string }) {
  if (!rows.length) return <EmptyState label={empty} />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-[10px] uppercase tracking-[0.08em] text-white/40">
            {headers.map((header) => (
              <th key={header} className="pb-2 pr-4 font-black">{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cells, rowIndex) => (
            <tr key={rowIndex} className="border-b border-white/5 text-white/75 transition hover:bg-white/[0.03]">
              {cells.map((cell, cellIndex) => (
                <td key={cellIndex} className="py-2.5 pr-4 align-middle">{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
