'use client';

import { useMemo } from 'react';
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Brain,
  Building2,
  Database,
  Eye,
  FileSearch,
  Fingerprint,
  GitBranch,
  Globe2,
  Layers,
  LineChart,
  Network,
  Radar,
  RefreshCw,
  ScanSearch,
  Shield,
  Sparkles,
  Target,
  Timer,
} from 'lucide-react';
import { useScannerIntelligence } from '@/lib/scanner/use-scanner-intelligence';

type Metric = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
  tone: 'gold' | 'green' | 'red' | 'orange';
};

type AssetInsight = {
  asset: string;
  owner: string;
  environment: string;
  intelligence: string;
  signal: string;
  risk: 'Critical' | 'High' | 'Medium';
  priority: string;
};

const GLASS_PANEL_CLASSES =
  'group relative overflow-hidden rounded-xl border border-[#FFD36B]/20 bg-[#0f1428]/45 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(255,211,107,0.03),0_0_40px_rgba(255,211,107,0.14)] transition-all duration-500 hover:-translate-y-1 hover:border-[#FFD36B]/70 hover:bg-[#0f1428]/65 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.3),inset_0_-24px_60px_rgba(255,211,107,0.15),0_8px_30px_rgba(0,0,0,0.5),0_0_60px_rgba(255,211,107,0.5),0_0_120px_rgba(255,211,107,0.2)] hover:z-10 before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-[#FFF4C0]/70 before:to-transparent before:transition-all before:duration-500 group-hover:before:opacity-100 group-hover:before:shadow-[0_0_15px_rgba(255,211,107,0.9)] group-hover:before:via-[#FFF4C0] after:pointer-events-none after:absolute after:-right-24 after:-top-24 after:h-48 after:w-48 after:rounded-full after:bg-[#FFD36B]/10 after:blur-3xl after:transition-all after:duration-500 group-hover:after:opacity-100 group-hover:after:bg-[#FFD36B]/25 group-hover:after:blur-[36px] text-white';

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

function assetRisk(asset: any): AssetInsight['risk'] {
  const score = Number(asset.riskScore || 0);
  const level = String(asset.riskLevel || '').toLowerCase();
  if (score >= 80 || level.includes('critical')) return 'Critical';
  if (score >= 60 || level.includes('high')) return 'High';
  return 'Medium';
}

function assetEnvironment(asset: any) {
  const metadata = asset.metadata || {};
  if (metadata.environment) return String(metadata.environment);
  const target = String(asset.url || asset.domain || asset.name || '').toLowerCase();
  if (target.includes('prod') || target.includes('www') || target.startsWith('https://')) return 'Production';
  if (target.includes('stage')) return 'Staging';
  if (target.includes('dev')) return 'Development';
  return 'Tenant scope';
}

function clusterIcon(label: string) {
  const lower = label.toLowerCase();
  if (lower.includes('database') || lower.includes('data')) return Database;
  if (lower.includes('identity') || lower.includes('auth')) return Fingerprint;
  if (lower.includes('repo') || lower.includes('ci')) return GitBranch;
  return Globe2;
}

function toneClass(tone: Metric['tone']) {
  switch (tone) {
    case 'red':
      return 'border-red-400/30 bg-red-500/10 text-red-300';
    case 'orange':
      return 'border-orange-400/30 bg-orange-500/10 text-orange-300';
    case 'green':
      return 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300';
    default:
      return 'border-gold/30 bg-gold/10 text-gold';
  }
}

function riskClass(risk: AssetInsight['risk']) {
  if (risk === 'Critical') return 'border-red-500/30 bg-red-500/10 text-red-300';
  if (risk === 'High') return 'border-orange-500/30 bg-orange-500/10 text-orange-300';
  return 'border-amber-400/30 bg-amber-400/10 text-amber-300';
}

function SectionTitle({ icon: Icon, children }: { icon: LucideIcon; children: string }) {
  return (
    <h2 className="relative z-10 flex items-center gap-2 text-xs font-black uppercase tracking-[0.2em] text-white/60">
      <Icon className="h-4 w-4 text-gold" />
      {children}
    </h2>
  );
}

export default function AssetIntelligence() {
  const { data, loading, error, connected, refresh } = useScannerIntelligence();

  const unknownOwners = data.assets.assets.filter((asset: any) => !asset.metadata?.owner && !asset.metadata?.businessOwner).length;
  const criticalAssets = data.assets.assets.filter((asset: any) => assetRisk(asset) === 'Critical').length;
  const evidenceQuality = percentOf(
    data.cbom.stats.totalComponents + data.telemetry.length + data.history.history.length,
    Math.max(1, data.summary.totalComponents + data.summary.completedScans + data.runtime.operations),
  );

  const metrics = useMemo<Metric[]>(() => [
    { label: 'Assets Profiled', value: formatNumber(data.summary.totalAssets), detail: 'CBOM-linked records', icon: Layers, tone: 'gold' },
    { label: 'Critical Context', value: formatNumber(criticalAssets), detail: 'business-impact assets', icon: AlertTriangle, tone: criticalAssets > 0 ? 'red' : 'green' },
    { label: 'PQC Ready', value: formatPercent(data.summary.pqcReadiness), detail: 'migration-ready posture', icon: Shield, tone: data.summary.pqcReadiness >= 80 ? 'green' : 'orange' },
    { label: 'Unknown Owners', value: formatNumber(unknownOwners), detail: 'needs accountability', icon: Eye, tone: unknownOwners > 0 ? 'orange' : 'green' },
  ], [criticalAssets, data.summary.pqcReadiness, data.summary.totalAssets, unknownOwners]);

  const insights = useMemo<AssetInsight[]>(() => (
    [...data.assets.assets]
      .sort((a: any, b: any) => Number(b.riskScore || 0) - Number(a.riskScore || 0))
      .slice(0, 10)
      .map((asset: any) => {
        const inventory = asset.cryptoInventory || [];
        const topCrypto = inventory.find((entry: any) => entry.is_vulnerable) || inventory[0];
        const vulnerableCount = Number(asset.vulnerableCount || 0);
        return {
          asset: asset.name || 'Unknown asset',
          owner: asset.metadata?.owner || asset.metadata?.businessOwner || 'Unassigned',
          environment: assetEnvironment(asset),
          intelligence: `${vulnerableCount} vulnerable of ${asset.findingsCount || inventory.length || 0} crypto components; primary algorithm ${topCrypto?.algorithm || asset.cryptography?.[0] || 'manual review'}.`,
          signal: [
            inventory.length > 0 ? 'CBOM inventory' : null,
            data.telemetry.length > 0 ? 'runtime telemetry' : null,
            data.history.history.length > 0 ? 'scanner history' : null,
          ].filter(Boolean).join(', ') || 'Awaiting scanner evidence',
          risk: assetRisk(asset),
          priority: vulnerableCount > 0 ? String(topCrypto?.metadata?.pqcReplacement || topCrypto?.metadata?.recommendation || 'Create PQC remediation task') : 'Monitor and keep evidence current',
        };
      })
  ), [data.assets.assets, data.history.history.length, data.telemetry.length]);

  const clusters = useMemo(() => {
    const grouped = new Map<string, { label: string; assets: number; riskTotal: number; icon: LucideIcon }>();
    for (const asset of data.assets.assets) {
      const label = String(asset.type || 'Unclassified assets');
      const existing = grouped.get(label) || { label, assets: 0, riskTotal: 0, icon: clusterIcon(label) };
      existing.assets += 1;
      existing.riskTotal += Number(asset.riskScore || 0);
      grouped.set(label, existing);
    }
    const rows = Array.from(grouped.values()).map((item) => ({
      ...item,
      risk: item.assets > 0 ? Math.round(item.riskTotal / item.assets) : 0,
    }));
    return rows.length > 0 ? rows.slice(0, 6) : [{ label: 'No scanned assets', assets: 0, risk: 0, icon: Globe2 }];
  }, [data.assets.assets]);

  const signals = useMemo(() => [
    { label: 'Scanner evidence', value: formatPercent(percentOf(data.history.history.length, Math.max(1, data.summary.completedScans))), icon: ScanSearch },
    { label: 'CBOM completeness', value: formatPercent(percentOf(data.cbom.stats.totalComponents, Math.max(1, data.summary.totalComponents))), icon: FileSearch },
    { label: 'Runtime coverage', value: formatPercent(percentOf(data.runtime.operations, Math.max(1, data.runtime.operations + data.summary.totalAssets))), icon: Activity },
    { label: 'Owner mapping', value: formatPercent(percentOf(data.summary.totalAssets - unknownOwners, Math.max(1, data.summary.totalAssets))), icon: Building2 },
  ], [data, unknownOwners]);

  const forecastCards = useMemo(() => [
    {
      icon: LineChart,
      title: 'Risk Forecast',
      value: formatPercent(Math.max(0, 100 - data.summary.riskScore)),
      detail: 'projected posture if current PQC-ready components remain stable',
    },
    {
      icon: Timer,
      title: 'SLA Pressure',
      value: formatNumber(data.severityCounts.critical + data.severityCounts.high),
      detail: 'critical and high assets requiring near-term remediation review',
    },
    {
      icon: Database,
      title: 'Evidence Quality',
      value: formatPercent(evidenceQuality),
      detail: 'scanner, CBOM, telemetry, and history records linked',
    },
  ], [data.severityCounts.critical, data.severityCounts.high, data.summary.riskScore, evidenceQuality]);

  return (
    <div className="p-4 lg:p-8 space-y-6 animate-in fade-in duration-700 text-white">
      <header className="flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-3">
            <div className="rounded bg-gold/10 border border-gold/20 p-2">
              <Brain className="h-6 w-6 text-gold drop-shadow-[0_0_6px_rgba(255,211,107,0.4)]" />
            </div>
            <h1 className="text-3xl font-black uppercase leading-none tracking-tight text-white">
              Asset <span className="text-gold">Intelligence</span>
            </h1>
          </div>
          <p className="max-w-3xl text-sm font-medium text-white/50">
            Enrich cryptographic assets with business context, ownership, exposure, migration readiness, and evidence confidence.
          </p>
        </div>
        <button onClick={refresh} className="flex items-center gap-2 rounded-lg border border-gold/30 bg-gold/10 px-4 py-2.5 text-[10px] font-black uppercase tracking-wider text-gold transition hover:border-gold/70 hover:bg-gold/20">
          <Sparkles className="h-4 w-4" />
          {connected ? 'Intelligence Graph Active' : 'Load Intelligence'}
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/25 bg-red-500/10 p-4 text-sm font-semibold text-red-300">
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
                  <span className="block text-[9px] font-bold uppercase tracking-widest text-white/40">{metric.label}</span>
                  <span className="mt-3 block text-3xl font-black leading-none text-white">{metric.value}</span>
                  <span className="mt-3 block text-[10px] font-black uppercase tracking-wider text-white/35">{metric.detail}</span>
                </div>
                <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border ${toneClass(metric.tone)}`}>
                  <Icon className="h-7 w-7" />
                </div>
              </div>
            </section>
          );
        })}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]">
        <section className={`${GLASS_PANEL_CLASSES} p-6`}>
          <SectionTitle icon={Target}>Priority Intelligence Queue</SectionTitle>
          <div className="relative z-10 mt-5 overflow-x-auto">
            <table className="w-full min-w-[900px] border-collapse text-left">
              <thead>
                <tr className="border-b border-gold/15 bg-gold/[0.03]">
                  {['Asset', 'Context Intelligence', 'Signal', 'Risk', 'Priority'].map((header) => (
                    <th key={header} className="p-4 text-[10px] font-black uppercase tracking-[0.18em] text-white/40">{header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {insights.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-10 text-center text-xs font-black uppercase tracking-widest text-white/30">
                      No asset intelligence has been generated for this tenant yet.
                    </td>
                  </tr>
                ) : insights.map((insight) => (
                  <tr key={`${insight.asset}-${insight.owner}-${insight.environment}`} className="group/row transition hover:bg-gold/[0.04]">
                    <td className="p-4">
                      <div className="font-bold text-white/85 group-hover/row:text-gold">{insight.asset}</div>
                      <div className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-white/30">{insight.owner} / {insight.environment}</div>
                    </td>
                    <td className="p-4 text-xs font-semibold leading-relaxed text-white/60">{insight.intelligence}</td>
                    <td className="p-4 text-xs font-semibold text-white/45">{insight.signal}</td>
                    <td className="p-4">
                      <span className={`rounded border px-2 py-1 text-[9px] font-black uppercase tracking-wider ${riskClass(insight.risk)}`}>{insight.risk}</span>
                    </td>
                    <td className="p-4">
                      <button className="inline-flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-gold transition hover:text-white">
                        {insight.priority}
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="space-y-6">
          <section className={`${GLASS_PANEL_CLASSES} p-6`}>
            <SectionTitle icon={Radar}>Intelligence Signals</SectionTitle>
            <div className="relative z-10 mt-5 space-y-4">
              {signals.map((signal) => {
                const Icon = signal.icon;
                return (
                  <div key={signal.label} className="flex items-center justify-between rounded-lg border border-white/5 bg-white/[0.02] p-3">
                    <div className="flex items-center gap-3">
                      <Icon className="h-4 w-4 text-gold" />
                      <span className="text-xs font-black uppercase tracking-wider text-white/65">{signal.label}</span>
                    </div>
                    <span className="font-mono text-sm font-black text-gold">{signal.value}</span>
                  </div>
                );
              })}
            </div>
          </section>

          <section className={`${GLASS_PANEL_CLASSES} p-6`}>
            <SectionTitle icon={Network}>Asset Clusters</SectionTitle>
            <div className="relative z-10 mt-5 space-y-4">
              {clusters.map((cluster) => {
                const Icon = cluster.icon;
                return (
                  <div key={cluster.label}>
                    <div className="mb-2 flex items-center justify-between gap-4">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-gold" />
                        <span className="text-xs font-bold text-white/70">{cluster.label}</span>
                      </div>
                      <span className="text-xs font-semibold text-white/35">{cluster.assets} assets</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-white/5">
                      <div className="h-full rounded-full bg-gradient-to-r from-gold/40 to-gold shadow-[0_0_10px_rgba(255,211,107,0.55)]" style={{ width: `${cluster.risk}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </aside>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {forecastCards.map((item) => {
          const Icon = item.icon;
          return (
            <section key={item.title} className={`${GLASS_PANEL_CLASSES} p-5`}>
              <div className="relative z-10 flex items-center gap-4">
                <div className="rounded border border-gold/20 bg-gold/10 p-3">
                  <Icon className="h-6 w-6 text-gold" />
                </div>
                <div>
                  <div className="text-[10px] font-black uppercase tracking-wider text-white/45">{item.title}</div>
                  <div className="mt-1 text-2xl font-black text-white">{item.value}</div>
                  <div className="mt-1 text-xs font-semibold text-white/35">{item.detail}</div>
                </div>
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
