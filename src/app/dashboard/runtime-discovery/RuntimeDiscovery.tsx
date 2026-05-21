'use client';

import { useMemo } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  Bell,
  Box,
  Clock3,
  Globe2,
  KeyRound,
  Layers,
  Lock,
  MapPin,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Users,
  Wifi,
} from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';

type MetricCard = {
  label: string;
  value: string;
  unit?: string;
  caption: string;
  icon: LucideIcon;
  danger?: boolean;
};

type MiniMetric = {
  label: string;
  value: string;
  delta: string;
  icon: LucideIcon;
  danger?: boolean;
};

type AssetRow = {
  name: string;
  type: string;
  algorithm: string;
  discoveredAt: string;
  status: string;
  risk: 'Low' | 'Medium' | 'High';
};

type AuditEvent = {
  time: string;
  message: string;
  tone: 'muted' | 'gold' | 'green';
};

type DiscoveryBreakdown = {
  label: string;
  value: number;
  percent: string;
  color: string;
};

type ContextRow = {
  label: string;
  value: string;
  icon: LucideIcon;
  badge?: boolean;
};

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(Math.max(0, Number(value) || 0));
}

function formatPercent(value: number) {
  return `${Math.max(0, Math.min(100, Math.round(Number(value) || 0)))}%`;
}

function formatDateTime(value?: string) {
  if (!value) return 'No scanner data';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatClock(value?: string) {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'N/A';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function riskLabel(scoreOrLevel: number | string | undefined): AssetRow['risk'] {
  if (typeof scoreOrLevel === 'string') {
    const level = scoreOrLevel.toLowerCase();
    if (level.includes('critical') || level.includes('high')) return 'High';
    if (level.includes('medium')) return 'Medium';
    return 'Low';
  }
  const score = Number(scoreOrLevel || 0);
  if (score >= 70) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

function DonutChart({ breakdown, total }: { breakdown: DiscoveryBreakdown[]; total: number }) {
  const size = 184;
  const strokeWidth = 30;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const safeTotal = Math.max(1, total);

  return (
    <div className="relative h-[184px] w-[184px] shrink-0">
      <svg className="h-full w-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={strokeWidth} />
        {breakdown.map((item) => {
          const length = (item.value / safeTotal) * circumference;
          const circle = (
            <circle
              key={item.label}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={item.color}
              strokeWidth={strokeWidth}
              strokeDasharray={`${Math.max(length - 3, 0)} ${circumference}`}
              strokeDashoffset={-offset}
              className="transition-all duration-300"
              style={{ filter: `drop-shadow(0 0 9px ${item.color}55)` }}
            />
          );
          offset += length;
          return circle;
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center rounded-full">
        <span className="text-3xl font-black leading-none text-white">{formatNumber(total)}</span>
        <span className="mt-2 text-xs font-semibold text-white/50">Total</span>
      </div>
    </div>
  );
}

function SectionTitle({ icon: Icon, children }: { icon?: LucideIcon; children: string }) {
  return (
    <h2 className="relative z-10 flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.22em] text-gold">
      {Icon ? <Icon className="h-4 w-4" /> : null}
      {children}
    </h2>
  );
}

export default function RuntimeDiscovery() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();

  const latestHistory = data.history.history[0];
  const previousHistory = data.history.history[1];
  const latestGeneratedAt = data.generatedAt && data.generatedAt !== new Date(0).toISOString() ? data.generatedAt : latestHistory?.startedAt;
  const latestComponentCount = Number(latestHistory?.summary?.totalFindings || latestHistory?.detectedComponents || data.summary.totalComponents || 0);
  const previousComponentCount = Number(previousHistory?.summary?.totalFindings || previousHistory?.detectedComponents || 0);
  const componentDelta = previousComponentCount > 0
    ? `${latestComponentCount >= previousComponentCount ? '+' : ''}${Math.round(((latestComponentCount - previousComponentCount) / previousComponentCount) * 100)}%`
    : '0%';

  const metrics = useMemo<MetricCard[]>(() => [
    {
      label: 'Telemetry Age',
      value: data.telemetry[0]?.timestamp ? String(Math.max(0, Math.round((Date.now() - Date.parse(data.telemetry[0].timestamp)) / 1000))) : '0',
      unit: 's',
      caption: 'Latest Runtime Event',
      icon: Activity,
      danger: Boolean(data.telemetry[0]?.timestamp && Date.now() - Date.parse(data.telemetry[0].timestamp) > 120000),
    },
    {
      label: 'Throughput',
      value: formatNumber(data.runtime.operations),
      unit: 'events',
      caption: 'Scanner Telemetry Events',
      icon: Wifi,
    },
    {
      label: 'Discovered Assets',
      value: formatNumber(data.summary.totalAssets),
      caption: 'Authorized Cryptographic Assets',
      icon: Box,
    },
    {
      label: 'Quantum Risk',
      value: String(data.summary.riskScore),
      unit: '/100',
      caption: 'Risk Score',
      icon: ShieldAlert,
      danger: data.summary.riskScore >= 60,
    },
  ], [data]);

  const miniMetrics = useMemo<MiniMetric[]>(() => [
    { label: 'Active Sessions', value: formatNumber(data.summary.activeScans), delta: componentDelta, icon: Users },
    { label: 'Encrypted Channels', value: formatNumber(data.runtime.encryptedChannels), delta: componentDelta, icon: Lock },
    { label: 'Key Rotations', value: formatNumber(data.runtime.keyRotations), delta: componentDelta, icon: KeyRound },
    { label: 'Alerts', value: formatNumber(data.runtime.alerts), delta: componentDelta, icon: Bell, danger: data.runtime.alerts > 0 },
    { label: 'Compliance Score', value: `${data.runtime.complianceScore}%`, delta: componentDelta, icon: Shield },
  ], [componentDelta, data]);

  const discoveryBreakdown = useMemo<DiscoveryBreakdown[]>(() => {
    const entries = data.cbom.entries || [];
    const count = (matcher: (entry: any) => boolean) => entries.filter(matcher).length;
    const certificates = count((entry) => String(entry.type || '').toLowerCase().includes('certificate'));
    const keys = count((entry) => String(entry.type || '').toLowerCase().includes('key'));
    const protocols = count((entry) => String(entry.type || '').toLowerCase().includes('protocol') || String(entry.algorithm || '').toLowerCase().includes('tls'));
    const endpoints = data.assets.assets.length;
    const other = Math.max(0, entries.length - certificates - keys - protocols);
    const rows = [
      { label: 'Certificates', value: certificates, color: '#FFD36B' },
      { label: 'Keys', value: keys, color: '#b99b4a' },
      { label: 'Protocols', value: protocols, color: '#d8b957' },
      { label: 'Endpoints', value: endpoints, color: '#8a743d' },
      { label: 'Other', value: other, color: '#6f6f64' },
    ];
    const total = Math.max(1, rows.reduce((sum, item) => sum + item.value, 0));
    return rows.map((item) => ({ ...item, percent: formatPercent((item.value / total) * 100) }));
  }, [data.assets.assets.length, data.cbom.entries]);

  const discoveryTotal = discoveryBreakdown.reduce((sum, item) => sum + item.value, 0);

  const bars = useMemo(() => {
    const samples = data.history.history.slice(0, 33).reverse().map((entry: any) => Number(entry.summary?.totalFindings || entry.detectedComponents || 0));
    const max = Math.max(1, ...samples);
    const normalized = samples.map((value) => Math.max(8, Math.round((value / max) * 100)));
    return normalized.length > 0 ? normalized : [0, 0, 0, 0, 0, 0, 0, 0];
  }, [data.history.history]);

  const contextRows = useMemo<ContextRow[]>(() => {
    const primaryAsset = data.assets.assets[0];
    const topAlgorithm = data.cbom.entries[0]?.algorithm || data.exposure.nodes[0]?.algorithm || 'No algorithm detected';
    return [
      { label: 'Encryption Protocol', value: String(topAlgorithm), icon: Lock },
      { label: 'Primary Node', value: primaryAsset?.name || latestHistory?.target || 'No asset scanned', icon: Server },
      { label: 'Persistence', value: data.mode === 'database' ? 'Database' : 'Memory fallback', icon: Globe2, badge: true },
      { label: 'Scope', value: data.summary.totalAssets > 0 ? 'Tenant isolated' : 'Awaiting scan', icon: MapPin, badge: true },
    ];
  }, [data, latestHistory?.target]);

  const auditEvents = useMemo<AuditEvent[]>(() => {
    const events = data.telemetry.slice(0, 6).map((event: any) => {
      const level = String(event.level || event.severity || '').toLowerCase();
      return {
        time: formatClock(event.timestamp || latestGeneratedAt),
        message: String(event.message || event.event || event.type || 'Runtime telemetry event'),
        tone: level.includes('error') || level.includes('warn') ? 'gold' : level.includes('success') || level.includes('complete') ? 'green' : 'muted',
      } as AuditEvent;
    });
    return events.length > 0 ? events : [{ time: formatClock(latestGeneratedAt), message: 'No live runtime telemetry has been recorded for this tenant yet.', tone: 'muted' }];
  }, [data.telemetry, latestGeneratedAt]);

  const assets = useMemo<AssetRow[]>(() => (
    data.assets.assets.slice(0, 8).map((asset: any) => ({
      name: asset.name || 'Unknown asset',
      type: asset.type || 'Unknown',
      algorithm: asset.cryptography?.[0] || asset.cryptoInventory?.[0]?.algorithm || 'Manual review',
      discoveredAt: formatDateTime(asset.lastScanned),
      status: asset.status || 'Observed',
      risk: riskLabel(asset.riskLevel || asset.riskScore),
    }))
  ), [data.assets.assets]);

  return (
    <div className="p-4 lg:p-8 space-y-6 animate-in fade-in duration-700 text-white font-mono">
      <header className="flex flex-col gap-5 border-b border-gold/15 pb-6 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-center gap-4">
          <div className="rounded-xl border border-gold/30 bg-gold/10 p-3 text-gold shadow-[0_0_26px_rgba(255,211,107,0.22)]">
            <Sparkles className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-3xl font-black uppercase leading-none tracking-[0.16em] text-gold drop-shadow-[0_0_18px_rgba(255,211,107,0.38)] md:text-4xl">
              Runtime Discovery
            </h1>
            <p className="mt-3 text-xs font-semibold tracking-wide text-white/45">
              Real-time discovery of cryptographic assets and communications.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-6">
          <button
            onClick={refresh}
            className="flex h-10 items-center gap-3 rounded-lg border border-gold/25 bg-[#0f1428]/55 px-4 text-[10px] font-black uppercase tracking-[0.16em] text-gold shadow-[0_0_20px_rgba(255,211,107,0.12)] transition hover:border-gold/60 hover:bg-gold/10"
          >
            <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]' : 'bg-amber-300 shadow-[0_0_12px_rgba(252,211,77,0.55)]'}`} />
            {connected ? 'Live Sync' : loading ? 'Syncing' : 'Snapshot'}
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <div className="h-10 w-px bg-gold/20" />
          <div className="flex items-center gap-3">
            <Clock3 className="h-7 w-7 text-gold" />
            <div>
              <div className="text-sm font-black tracking-widest text-white/80">{formatClock(latestGeneratedAt)}</div>
              <div className="text-xs font-bold text-white/35">{formatDateTime(latestGeneratedAt)}</div>
            </div>
          </div>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">
          {error}
        </div>
      )}

      <div className="space-y-6">
        {/* Row 1 */}
        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
          {metrics.map((metric) => {
            const Icon = metric.icon;

            return (
              <section key={metric.label} className={`${GLASS_PANEL_CLASSES} min-h-[140px] p-6`}>
                <div className="relative z-10 flex items-center gap-5">
                  <div className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-full border ${metric.danger ? 'border-red-400/35 bg-red-500/10 text-red-300 shadow-[0_0_24px_rgba(248,113,113,0.15)]' : 'border-gold/30 bg-gold/10 text-gold shadow-[0_0_24px_rgba(255,211,107,0.16)]'}`}>
                    <Icon className="h-8 w-8" />
                  </div>
                  <div className="min-w-0">
                    <div className={`text-[10px] font-black uppercase leading-relaxed tracking-[0.14em] [overflow-wrap:anywhere] ${metric.danger ? 'text-red-300' : 'text-gold'}`}>{metric.label}</div>
                    <div className={`mt-3 text-2xl font-black tracking-wide 2xl:text-3xl ${metric.danger ? 'text-red-300' : 'text-white'}`}>
                      {metric.value}
                      {metric.unit ? <span className={`ml-1 text-sm ${metric.danger ? 'text-red-300/70' : 'text-gold'}`}>{metric.unit}</span> : null}
                    </div>
                    <div className="mt-3 text-xs font-semibold leading-relaxed text-white/40">{metric.caption}</div>
                  </div>
                </div>
              </section>
            );
          })}
        </div>

        {/* Row 2 */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <section className={`${GLASS_PANEL_CLASSES} min-h-[330px] p-6`}>
            <div className="relative z-10 flex items-center justify-between gap-4">
              <SectionTitle icon={Activity}>Live Operations Activity</SectionTitle>
              <button className="flex h-9 items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 text-[10px] font-bold text-white/70 transition hover:border-gold/40 hover:bg-gold/10 hover:text-gold">
                Last 24 Hours
                <span className="text-gold/70">v</span>
              </button>
            </div>

            <div className="relative z-10 mt-7 h-56">
              <div className="absolute inset-0 flex flex-col justify-between">
                {[4, 3, 2, 1, 0].map((tick) => (
                  <div key={tick} className="flex items-center gap-4">
                    <span className="w-8 text-xs font-semibold text-white/45">{tick === 0 ? '0' : `${tick * 2}K`}</span>
                    <span className="h-px flex-1 border-t border-dashed border-white/10" />
                  </div>
                ))}
              </div>
              <div className="absolute inset-x-12 bottom-7 top-2 flex items-end justify-between gap-2">
                {bars.map((height, index) => (
                  <div key={index} className="flex flex-1 items-end justify-center">
                    <div
                      className="w-full max-w-[11px] rounded-t bg-gradient-to-t from-gold/10 via-gold/55 to-[#FFD36B] shadow-[0_0_16px_rgba(255,211,107,0.38)] transition duration-300 hover:scale-y-105 hover:opacity-100"
                      style={{ height: `${height}%`, opacity: index % 5 === 0 ? 1 : 0.78 }}
                    />
                  </div>
                ))}
              </div>
              <div className="absolute inset-x-12 bottom-0 flex justify-between text-xs font-semibold text-white/45">
                <span>08:00</span>
                <span>12:00</span>
                <span>16:00</span>
                <span>20:00</span>
                <span>00:00</span>
                <span>04:00</span>
                <span>08:00</span>
              </div>
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} min-h-[330px] p-6`}>
            <div className="relative z-10 flex items-center justify-between">
              <SectionTitle>Real-Time Audit Events</SectionTitle>
              <button className="rounded-md border border-gold/20 bg-gold/10 px-3 py-1.5 text-[10px] font-black text-gold transition hover:bg-gold/20">
                View All
              </button>
            </div>
            <div className="relative z-10 mt-5 max-h-[252px] space-y-4 overflow-hidden pr-2">
              <div className="absolute bottom-2 left-[7px] top-3 w-px bg-gradient-to-b from-gold/70 via-gold/30 to-transparent" />
              {auditEvents.map((event) => (
                <div key={`${event.time}-${event.message}`} className="relative grid grid-cols-[16px_1fr] gap-4">
                  <span className={`relative z-10 mt-4 h-2.5 w-2.5 rounded-full ${event.tone === 'green' ? 'bg-emerald-400' : 'bg-gold'} shadow-[0_0_12px_rgba(255,211,107,0.75)]`} />
                  <div>
                    <div className="text-[10px] font-semibold text-white/35">{event.time}</div>
                    <p className={`mt-1 text-xs font-semibold leading-relaxed ${event.tone === 'gold' ? 'text-gold' : event.tone === 'green' ? 'text-white/75' : 'text-white/70'}`}>
                      {event.message}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        {/* Row 3 */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <section className={`${GLASS_PANEL_CLASSES} min-h-[300px] p-6`}>
            <SectionTitle>Asset Discovery Breakdown</SectionTitle>
            <div className="relative z-10 mt-7 flex flex-col items-center gap-6 2xl:flex-row 2xl:justify-center">
              <DonutChart breakdown={discoveryBreakdown} total={discoveryTotal} />
              <div className="w-full max-w-sm space-y-4">
                {discoveryBreakdown.map((item) => (
                  <div key={item.label} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4">
                    <div className="flex items-center gap-3">
                      <span className="h-3 w-3 rounded-sm shadow-[0_0_12px_currentColor]" style={{ backgroundColor: item.color, color: item.color }} />
                      <span className="text-xs font-semibold text-white/70">{item.label}</span>
                    </div>
                    <span className="text-xs font-bold text-white/55">
                      {item.value} ({item.percent})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} min-h-[300px] p-6`}>
            <SectionTitle icon={Layers}>Infrastructure Context</SectionTitle>
            <div className="relative z-10 mt-6 space-y-5">
              {contextRows.map((row) => {
                const Icon = row.icon;

                return (
                  <div key={row.label} className="flex items-center justify-between gap-4 border-b border-white/5 pb-4 last:border-b-0 last:pb-0">
                    <div className="flex min-w-0 items-center gap-3">
                      <Icon className="h-4 w-4 shrink-0 text-gold" />
                      <span className="truncate text-xs font-black uppercase tracking-[0.14em] text-white/70">{row.label}</span>
                    </div>
                    <span className={`shrink-0 rounded-md px-2 py-1 text-xs font-black ${row.badge ? 'bg-gold/10 text-gold' : 'bg-white/10 text-white/70'}`}>
                      {row.value}
                    </span>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        {/* Row 4 */}
        <div className="grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {miniMetrics.map((metric) => {
            const Icon = metric.icon;

            return (
              <section key={metric.label} className={`${GLASS_PANEL_CLASSES} p-5`}>
                <div className="relative z-10 flex items-center gap-4">
                  <Icon className={`h-8 w-8 shrink-0 ${metric.danger ? 'text-red-300' : 'text-gold'}`} />
                  <div className="min-w-0">
                    <div className={`text-[10px] font-black uppercase leading-relaxed tracking-[0.12em] [overflow-wrap:anywhere] ${metric.danger ? 'text-red-300' : 'text-gold'}`}>{metric.label}</div>
                    <div className={`mt-3 text-2xl font-black ${metric.danger ? 'text-red-300' : 'text-white'}`}>
                      {metric.value}
                      <span className="ml-2 text-sm text-emerald-400">{metric.delta}</span>
                    </div>
                    <div className="mt-2 text-xs font-semibold text-white/35">vs last 24h</div>
                  </div>
                </div>
              </section>
            );
          })}
        </div>

        {/* Row 5 */}
        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle>Recently Discovered Assets</SectionTitle>
          <div className="relative z-10 mt-5 overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-left">
              <thead>
                <tr className="border-b border-white/10 text-[10px] font-black uppercase tracking-[0.18em] text-gold">
                  <th className="py-3">Asset Name</th>
                  <th className="py-3">Type</th>
                  <th className="py-3">Algorithm</th>
                  <th className="py-3">Discovered At</th>
                  <th className="py-3">Status</th>
                  <th className="py-3">Risk Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-xs font-black uppercase tracking-widest text-white/30">
                      No runtime assets have been discovered for this tenant yet.
                    </td>
                  </tr>
                ) : assets.map((asset) => (
                  <tr key={`${asset.name}-${asset.type}-${asset.algorithm}`} className="text-xs font-semibold text-white/65 transition hover:bg-gold/[0.04]">
                    <td className="py-3.5 text-white/80">{asset.name}</td>
                    <td className="py-3.5">{asset.type}</td>
                    <td className="py-3.5">{asset.algorithm}</td>
                    <td className="py-3.5">{asset.discoveredAt}</td>
                    <td className="py-3.5">
                      <span className="inline-flex items-center gap-2 text-white/70">
                        <span className="h-2 w-2 rounded-full bg-emerald-400" />
                        {asset.status}
                      </span>
                    </td>
                    <td className={`py-3.5 font-black ${asset.risk === 'High' ? 'text-red-300' : asset.risk === 'Medium' ? 'text-amber-300' : 'text-emerald-400'}`}>
                      {asset.risk}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
