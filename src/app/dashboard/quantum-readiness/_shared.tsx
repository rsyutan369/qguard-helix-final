'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, type LucideIcon } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { cn } from '@/lib/utils';

/* ------------------------------------------------------------------ */
/* Palette                                                            */
/* ------------------------------------------------------------------ */
export const RED = '#EF4444';
export const ORANGE = '#F97316';
export const AMBER = '#F59E0B';
export const GOLD = '#FBBF24';
export const GREEN = '#22C55E';
export const EMERALD = '#34D399';
export const TEAL = '#14B8A6';
export const BLUE = '#2478FF';
export const CYAN = '#22D3EE';
export const VIOLET = '#A855F7';
export const SLATE = '#64748B';

/* ------------------------------------------------------------------ */
/* Types — the single contract shared by every sub-page              */
/* ------------------------------------------------------------------ */
export type LoadState = 'loading' | 'success' | 'error';

export interface QuantumReadinessSnapshot {
  generatedAt: string | null;
  lastAssessmentAt: string | null;
  assessmentProgress: number;
  assessmentStatus: 'not_started' | 'in_progress' | 'complete' | string;
  hasData: boolean;
  scores: {
    quantumReadiness: number;
    quantumReadinessLevel: string;
    quantumRisk: number;
    quantumRiskLevel: string;
    hndlRisk: number;
    hndlRiskLevel: string;
    cryptoExposure: number;
    cryptoExposureLevel: string;
    migrationComplexity: number;
    migrationComplexityLevel: string;
    migrationEffort: number;
    pqcAdoption: number;
  };
  inventory: {
    assetsAssessed: number;
    certificatesAnalyzed: number;
    keysDiscovered: number;
    trustRelationships: number;
    domainsScanned: number;
    identitiesAnalyzed: number;
    cloudAccounts: number;
    dataRepositories: number;
    pqcReadyAssets: number;
    hybridAssets: number;
    quantumVulnerableAssets: number;
    cryptoComponents: number;
    vulnerableComponents: number;
    pqcReadyComponents: number;
  };
  riskDistribution: { critical: number; high: number; medium: number; low: number };
  readinessFactors: Array<{ label: string; score: number }>;
  riskFactors: Array<{ label: string; score: number; severity: string }>;
  criticalFindings: Array<{
    id: string;
    title: string;
    asset: string;
    assetType: string;
    environment: string;
    severity: string;
    algorithm: string;
    detectedAt: string | null;
  }>;
  recommendedActions: Array<{ id: string; title: string; detail: string; severity: string; route: string }>;
  topRiskAssets: Array<{
    asset: string;
    assetType: string;
    environment: string;
    owner: string;
    riskScore: number;
    status: string;
  }>;
  exposureGraph: {
    nodes: Array<{
      id: string;
      label: string;
      type: string;
      environment: string;
      riskScore: number;
      posture: 'pqc' | 'hybrid' | 'vulnerable' | string;
      internetFacing: boolean;
    }>;
    edges: Array<{ source: string; target: string; type: string }>;
  };
  riskTrend: Array<{ label: string; readiness: number; risk: number }>;
  estimates: { migrationTimelineWeeks: number; migrationCostUsd: number };
  telemetry: {
    runtimeEvents: number;
    scanResults: number;
    scanSessions: number;
    securityEvents: number;
    certificates: number;
    keys: number;
    assets: number;
    connectors: number;
    latestEventAt: string | null;
  };
}

export const EMPTY_SNAPSHOT: QuantumReadinessSnapshot = {
  generatedAt: null,
  lastAssessmentAt: null,
  assessmentProgress: 0,
  assessmentStatus: 'not_started',
  hasData: false,
  scores: {
    quantumReadiness: 0,
    quantumReadinessLevel: 'Not Started',
    quantumRisk: 0,
    quantumRiskLevel: 'Minimal',
    hndlRisk: 0,
    hndlRiskLevel: 'Minimal',
    cryptoExposure: 0,
    cryptoExposureLevel: 'Minimal',
    migrationComplexity: 0,
    migrationComplexityLevel: 'Minimal',
    migrationEffort: 0,
    pqcAdoption: 0,
  },
  inventory: {
    assetsAssessed: 0,
    certificatesAnalyzed: 0,
    keysDiscovered: 0,
    trustRelationships: 0,
    domainsScanned: 0,
    identitiesAnalyzed: 0,
    cloudAccounts: 0,
    dataRepositories: 0,
    pqcReadyAssets: 0,
    hybridAssets: 0,
    quantumVulnerableAssets: 0,
    cryptoComponents: 0,
    vulnerableComponents: 0,
    pqcReadyComponents: 0,
  },
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
  readinessFactors: [],
  riskFactors: [],
  criticalFindings: [],
  recommendedActions: [],
  topRiskAssets: [],
  exposureGraph: { nodes: [], edges: [] },
  riskTrend: [],
  estimates: { migrationTimelineWeeks: 0, migrationCostUsd: 0 },
  telemetry: {
    runtimeEvents: 0,
    scanResults: 0,
    scanSessions: 0,
    securityEvents: 0,
    certificates: 0,
    keys: 0,
    assets: 0,
    connectors: 0,
    latestEventAt: null,
  },
};

/* ------------------------------------------------------------------ */
/* Formatters                                                         */
/* ------------------------------------------------------------------ */
export function integerFmt(value: number) {
  return new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(value) || 0)));
}

export function compactFmt(value: number) {
  return new Intl.NumberFormat('en-US', {
    notation: value >= 100000 ? 'compact' : 'standard',
    maximumFractionDigits: value >= 100000 ? 1 : 0,
  }).format(Math.max(0, Number(value) || 0));
}

export function percentLabel(value: number) {
  return `${Math.round(Number(value) || 0)}%`;
}

export function currencyFmt(value: number) {
  if (!value) return '$0';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    notation: value >= 1_000_000 ? 'compact' : 'standard',
    maximumFractionDigits: value >= 1_000_000 ? 2 : 0,
  }).format(value);
}

export function longDate(value: string | null) {
  if (!value) return 'No assessment yet';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'No assessment yet';
  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function relativeTime(value: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  const diff = Date.now() - date.getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

export function riskTone(score: number) {
  if (score >= 80) return RED;
  if (score >= 60) return ORANGE;
  if (score >= 40) return GOLD;
  if (score >= 20) return GREEN;
  return TEAL;
}

export function readinessTone(score: number) {
  if (score >= 85) return EMERALD;
  if (score >= 65) return GREEN;
  if (score >= 45) return GOLD;
  if (score >= 25) return ORANGE;
  return RED;
}

export function severityColor(value: string) {
  const text = (value || '').toLowerCase();
  if (text.includes('critical')) return RED;
  if (text.includes('high') || text.includes('elevated')) return ORANGE;
  if (text.includes('medium') || text.includes('moderate')) return GOLD;
  if (text.includes('low')) return GREEN;
  return TEAL;
}

/* ------------------------------------------------------------------ */
/* Panel + primitive UI                                               */
/* ------------------------------------------------------------------ */
export const PANEL_CLASSES =
  'group relative overflow-hidden rounded-lg border border-blue-400/12 bg-[#07101D]/70 backdrop-blur-xl shadow-[inset_0_1px_0_rgba(255,255,255,0.08),inset_0_-24px_60px_rgba(36,120,255,0.035),0_0_34px_rgba(0,0,0,0.34)] transition duration-500 hover:-translate-y-0.5 hover:border-blue-400/40 hover:bg-[#0A1728]/84 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_16px_46px_rgba(0,0,0,0.48),0_0_48px_rgba(36,120,255,0.20)] before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-blue-300/45 before:to-transparent';

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn(PANEL_CLASSES, className)}>
      <div className="relative z-10 h-full">{children}</div>
    </section>
  );
}

export function SectionTitle({ children, suffix }: { children: ReactNode; suffix?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="text-xs font-black uppercase tracking-[0.10em] text-white">{children}</h2>
      {suffix}
    </div>
  );
}

export function EmptyState({ label, hint }: { label: string; hint?: string }) {
  return (
    <div className="flex min-h-[140px] flex-col items-center justify-center gap-1 rounded-md border border-dashed border-white/10 bg-white/[0.02] px-4 text-center">
      <span className="text-xs font-semibold text-white/45">{label}</span>
      {hint ? <span className="text-[11px] text-white/30">{hint}</span> : null}
    </div>
  );
}

export function HeaderButton({
  icon: Icon,
  children,
  onClick,
  active,
}: {
  icon: LucideIcon;
  children: ReactNode;
  onClick?: () => void;
  active?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex h-10 items-center gap-2 rounded-md border px-3 text-xs font-bold transition',
        active
          ? 'border-blue-400/50 bg-blue-500/15 text-blue-200'
          : 'border-white/10 bg-black/22 text-white/75 hover:border-blue-400/45 hover:bg-blue-500/10 hover:text-blue-200',
      )}
    >
      <Icon className="h-4 w-4" />
      {children}
    </button>
  );
}

export function PrimaryButton({
  icon: Icon,
  children,
  onClick,
  disabled,
}: {
  icon?: LucideIcon;
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex h-10 items-center gap-2 rounded-md border border-blue-400/40 bg-gradient-to-r from-blue-600/80 to-blue-500/70 px-4 text-xs font-bold text-white shadow-[0_8px_24px_rgba(36,120,255,0.25)] transition hover:from-blue-500 hover:to-blue-400 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {Icon ? <Icon className="h-4 w-4" /> : null}
      {children}
    </button>
  );
}

export function Badge({ children, color }: { children: ReactNode; color: string }) {
  return (
    <span
      className="inline-flex items-center rounded px-2 py-0.5 text-[10px] font-black uppercase tracking-wide"
      style={{ color, backgroundColor: `${color}1a`, border: `1px solid ${color}40` }}
    >
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Charts                                                             */
/* ------------------------------------------------------------------ */
export function Ring({
  value,
  color,
  size = 72,
  stroke = 9,
  children,
}: {
  value: number;
  color: string;
  size?: number;
  stroke?: number;
  children?: ReactNode;
}) {
  const safe = Math.max(0, Math.min(100, Number(value) || 0));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={circumference - (safe / 100) * circumference}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
      </svg>
      {children ? <div className="absolute inset-0 grid place-items-center text-center">{children}</div> : null}
    </div>
  );
}

export function ScoreGauge({
  label,
  score,
  level,
  color,
  suffix = '/100',
}: {
  label: string;
  score: number;
  level: string;
  color: string;
  suffix?: string;
}) {
  return (
    <div className="flex items-center gap-4">
      <Ring value={score} color={color} size={92} stroke={10}>
        <div>
          <div className="text-2xl font-semibold text-white">{integerFmt(score)}</div>
          <div className="text-[9px] font-bold uppercase tracking-wide text-white/45">{suffix.replace('/', '/ ')}</div>
        </div>
      </Ring>
      <div className="min-w-0">
        <div className="text-[10px] font-black uppercase tracking-[0.10em] text-white/45">{label}</div>
        <div className="mt-1 text-sm font-bold" style={{ color }}>
          {level}
        </div>
      </div>
    </div>
  );
}

export function MetricCard({
  label,
  value,
  suffix,
  detail,
  color,
  ring,
  icon: Icon,
}: {
  label: string;
  value: string;
  suffix?: string;
  detail: string;
  color: string;
  ring?: number;
  icon?: LucideIcon;
}) {
  return (
    <Panel className="min-h-[118px] p-4">
      <div className="flex h-full items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.08em]" style={{ color }}>
            {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
            <span className="truncate">{label}</span>
          </div>
          <div className="mt-3 flex items-baseline gap-1">
            <span className="text-2xl font-semibold text-white">{value}</span>
            {suffix ? <span className="text-xs font-semibold text-white/50">{suffix}</span> : null}
          </div>
          <div className="mt-1 truncate text-[10px] font-bold" style={{ color }}>
            {detail}
          </div>
        </div>
        {typeof ring === 'number' ? (
          <Ring value={ring} color={color} size={58} stroke={7} />
        ) : Icon ? (
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-md border" style={{ borderColor: `${color}40`, color, backgroundColor: `${color}12` }}>
            <Icon className="h-5 w-5" />
          </span>
        ) : null}
      </div>
    </Panel>
  );
}

export function BarList({
  rows,
  colorFor,
  max,
  unit = '',
}: {
  rows: Array<{ label: string; value: number; sub?: string }>;
  colorFor?: (row: { label: string; value: number }) => string;
  max?: number;
  unit?: string;
}) {
  if (!rows.length) return <EmptyState label="No data available yet." />;
  const ceiling = max ?? Math.max(100, ...rows.map((r) => r.value));
  return (
    <div className="space-y-3.5">
      {rows.map((row) => {
        const color = colorFor ? colorFor(row) : BLUE;
        return (
          <div key={row.label} className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 text-xs">
            <span className="truncate text-white/72">{row.label}</span>
            <span className="text-right font-mono text-white/70">
              {integerFmt(row.value)}
              {unit}
            </span>
            <div className="col-span-2 h-2 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${Math.min(100, (row.value / ceiling) * 100)}%`, backgroundColor: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function TrendChart({ points }: { points: Array<{ label: string; readiness: number; risk: number }> }) {
  const width = 820;
  const height = 240;
  const pad = 34;
  if (!points.length) {
    return <EmptyState label="No historical assessment data yet." hint="Run repeat scans to build a readiness trend." />;
  }
  const line = (values: number[]) =>
    values
      .map((value, index) => {
        const x = pad + (values.length <= 1 ? 0 : (index / (values.length - 1)) * (width - pad * 2));
        const y = pad + (height - pad * 2) - (clampScore(value) / 100) * (height - pad * 2);
        return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(' ');
  const series = [
    { label: 'Readiness', values: points.map((p) => p.readiness), color: EMERALD },
    { label: 'Risk', values: points.map((p) => p.risk), color: RED },
  ];
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-5 text-[10px] text-white/62">
        {series.map((item) => (
          <span key={item.label} className="inline-flex items-center gap-2">
            <span className="h-2 w-3 rounded-sm" style={{ backgroundColor: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      <svg className="h-[240px] w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Readiness and risk over time">
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = pad + (height - pad * 2) - (tick / 100) * (height - pad * 2);
          return (
            <g key={tick}>
              <line x1={pad} x2={width - pad} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x={8} y={y + 4} fill="rgba(255,255,255,0.4)" fontSize="10">
                {tick}
              </text>
            </g>
          );
        })}
        {series.map((item) => (
          <g key={item.label}>
            <path d={line(item.values)} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            {item.values.map((value, index) => {
              const x = pad + (item.values.length <= 1 ? 0 : (index / (item.values.length - 1)) * (width - pad * 2));
              const y = pad + (height - pad * 2) - (clampScore(value) / 100) * (height - pad * 2);
              return <circle key={`${item.label}-${index}`} cx={x} cy={y} r="2.6" fill={item.color} />;
            })}
          </g>
        ))}
        {points.map((point, index) => {
          const x = pad + (points.length <= 1 ? 0 : (index / (points.length - 1)) * (width - pad * 2));
          return (
            <text key={`${point.label}-${index}`} x={x} y={height - 8} textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="10">
              {point.label}
            </text>
          );
        })}
      </svg>
    </div>
  );
}

function clampScore(value: number) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}

export function Donut({
  segments,
  centerValue,
  centerLabel,
  centerColor,
}: {
  segments: Array<{ label: string; value: number; color: string }>;
  centerValue: string;
  centerLabel: string;
  centerColor: string;
}) {
  const total = Math.max(1, segments.reduce((sum, s) => sum + s.value, 0));
  let offset = 0;
  const C = 2 * Math.PI * 42;
  return (
    <div className="grid grid-cols-[160px_1fr] items-center gap-5">
      <div className="relative grid h-40 w-40 place-items-center">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="16" />
          {segments.map((seg) => {
            const value = Math.max(0, seg.value);
            const dash = `${(value / total) * C} ${C}`;
            const strokeOffset = -offset;
            offset += (value / total) * C;
            return (
              <circle key={seg.label} cx="60" cy="60" r="42" fill="none" stroke={seg.color} strokeWidth="16" strokeDasharray={dash} strokeDashoffset={strokeOffset} />
            );
          })}
        </svg>
        <div className="absolute text-center">
          <div className="text-3xl font-semibold text-white">{centerValue}</div>
          <div className="text-[10px] font-bold" style={{ color: centerColor }}>
            {centerLabel}
          </div>
        </div>
      </div>
      <div className="space-y-2">
        {segments.map((seg) => (
          <div key={seg.label} className="grid grid-cols-[12px_1fr_46px] items-center gap-2 text-[11px]">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: seg.color }} />
            <span className="truncate text-white/72">{seg.label}</span>
            <span className="text-right font-mono text-white/72">{integerFmt(seg.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Cross-page navigation                                              */
/* ------------------------------------------------------------------ */
export const QR_PAGES: Array<{ label: string; short: string; path: string }> = [
  { label: 'Overview', short: 'Overview', path: '/dashboard/quantum-readiness' },
  { label: 'Command Center', short: 'Command', path: '/dashboard/quantum-readiness/command-center' },
  { label: 'Executive Dashboard', short: 'Executive', path: '/dashboard/quantum-readiness/executive' },
  { label: 'Quantum Exposure Graph™', short: 'Exposure Graph', path: '/dashboard/quantum-readiness/exposure-graph' },
  { label: 'Quantum Risk Analysis', short: 'Risk Analysis', path: '/dashboard/quantum-readiness/risk-analysis' },
  { label: 'AI Executive Advisor™', short: 'AI Executive', path: '/dashboard/quantum-readiness/ai-executive-advisor' },
  { label: 'AI Migration Advisor™', short: 'AI Migration', path: '/dashboard/quantum-readiness/ai-migration-advisor' },
  { label: 'Digital Twin™', short: 'Digital Twin', path: '/dashboard/quantum-readiness/digital-twin' },
  { label: 'Report Center', short: 'Reports', path: '/dashboard/quantum-readiness/reports' },
];

export function QuantumReadinessSubnav() {
  const location = useLocation();
  return (
    <div className="-mx-1 flex gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
      {QR_PAGES.map((page) => {
        const active = location.pathname === page.path;
        return (
          <Link
            key={page.path}
            to={page.path}
            className={cn(
              'whitespace-nowrap rounded-md border px-3 py-1.5 text-[11px] font-bold no-underline transition',
              active
                ? 'border-blue-400/50 bg-blue-500/15 text-blue-200'
                : 'border-white/8 bg-black/20 text-white/55 hover:border-blue-400/35 hover:text-blue-200',
            )}
          >
            {page.short}
          </Link>
        );
      })}
    </div>
  );
}

export function ViewAllLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="inline-flex items-center gap-1 text-xs font-bold text-blue-300 no-underline transition hover:text-blue-200">
      {children} <ChevronRight className="h-3.5 w-3.5" />
    </Link>
  );
}

/* ------------------------------------------------------------------ */
/* Page shell                                                         */
/* ------------------------------------------------------------------ */
export function QuantumReadinessShell({
  title,
  subtitle,
  badge,
  actions,
  sseConnected,
  state,
  snapshot,
  children,
}: {
  title: string;
  subtitle: string;
  badge?: ReactNode;
  actions?: ReactNode;
  sseConnected: boolean;
  state: LoadState;
  snapshot: QuantumReadinessSnapshot;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1560px] space-y-4">
        <QuantumReadinessSubnav />

        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-semibold tracking-normal text-white">{title}</h1>
              {badge}
            </div>
            <p className="mt-1 max-w-3xl text-sm text-white/58">{subtitle}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">{actions}</div>
        </header>

        {!snapshot.hasData && state === 'success' ? (
          <div className="rounded-md border border-amber-400/25 bg-amber-400/[0.07] px-4 py-3 text-sm text-amber-100/90">
            No assessment evidence found for this tenant yet. KPIs below reflect empty state. Run a PQC discovery scan or
            connect cryptographic inventory to populate the Quantum Readiness Assessment Engine™.
          </div>
        ) : null}

        {children}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span
              className={cn('h-2 w-2 rounded-full', sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-amber-300 animate-pulse')}
            />
            {sseConnected ? 'Live telemetry, metrics stream & table subscriptions connected' : 'Connecting live assessment streams'}
          </span>
          <span>Last synchronized: {longDate(snapshot.lastAssessmentAt || snapshot.generatedAt)}</span>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Data hook — real Supabase aggregation + SSE + realtime             */
/* ------------------------------------------------------------------ */
export function useQuantumReadiness() {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [snapshot, setSnapshot] = useState<QuantumReadinessSnapshot>(EMPTY_SNAPSHOT);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [sseConnected, setSseConnected] = useState(false);
  const streamsRef = useRef<EventSource[]>([]);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const closeStreams = useCallback(() => {
    for (const stream of streamsRef.current) stream.close();
    streamsRef.current = [];
    setSseConnected(false);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) {
      setSnapshot(EMPTY_SNAPSHOT);
      setState('success');
      setError(null);
      return;
    }
    setState((current) => (current === 'success' ? current : 'loading'));
    try {
      const response = await fetch('/api/v1/quantum-readiness', {
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      const data = payload.data || {};
      setSnapshot({
        ...EMPTY_SNAPSHOT,
        ...data,
        scores: { ...EMPTY_SNAPSHOT.scores, ...(data.scores || {}) },
        inventory: { ...EMPTY_SNAPSHOT.inventory, ...(data.inventory || {}) },
        riskDistribution: { ...EMPTY_SNAPSHOT.riskDistribution, ...(data.riskDistribution || {}) },
        exposureGraph: { ...EMPTY_SNAPSHOT.exposureGraph, ...(data.exposureGraph || {}) },
        estimates: { ...EMPTY_SNAPSHOT.estimates, ...(data.estimates || {}) },
        telemetry: { ...EMPTY_SNAPSHOT.telemetry, ...(data.telemetry || {}) },
      });
      setState('success');
      setError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to load quantum readiness assessment';
      console.error('Quantum readiness load failed:', err);
      setError(message);
      setState('error');
    }
  }, [token]);

  const queueRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      void refresh();
    }, 300);
  }, [refresh]);

  useEffect(
    () => () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    },
    [],
  );

  useEffect(() => {
    if (!token || !user) {
      setSnapshot(EMPTY_SNAPSHOT);
      setState('success');
      return;
    }
    void refresh();
  }, [token, user, refresh]);

  // Supabase realtime — refresh on any tenant evidence mutation.
  useEffect(() => {
    if (!user) return;
    const tables = [
      'assets',
      'asset_relationships',
      'scan_sessions',
      'scan_results',
      'web_scan_findings',
      'certificates',
      'generated_keys',
      'crypto_exposures',
      'runtime_crypto_events',
      'migration_assessments',
      'migration_logs',
    ];
    const channels = tables.map((table) =>
      supabase
        .channel(`quantum-readiness-${table}`)
        .on('postgres_changes', { event: '*', schema: 'public', table, filter: `user_id=eq.${user.id}` }, queueRefresh)
        .subscribe(),
    );
    return () => {
      for (const channel of channels) supabase.removeChannel(channel);
    };
  }, [user, queueRefresh]);

  // SSE — reuse existing metrics + scanner streams.
  useEffect(() => {
    if (!token) {
      closeStreams();
      return;
    }
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      closeStreams();
      const metricsStream = new EventSource(`/api/v1/metrics/stream?token=${encodeURIComponent(token)}`);
      streamsRef.current = [metricsStream];
      const markOpen = () => setSseConnected(true);
      const scheduleReconnect = () => {
        setSseConnected(false);
        closeStreams();
        if (retryTimer) clearTimeout(retryTimer);
        retryTimer = setTimeout(connect, 10000);
      };
      const refreshFromStream = () => queueRefresh();
      metricsStream.onopen = markOpen;
      metricsStream.onerror = scheduleReconnect;
      metricsStream.addEventListener('metrics-update', refreshFromStream);
      metricsStream.addEventListener('runtime-crypto-update', refreshFromStream);
      metricsStream.addEventListener('scan-complete', refreshFromStream);
    };
    connect();
    return () => {
      if (retryTimer) clearTimeout(retryTimer);
      closeStreams();
    };
  }, [token, queueRefresh, closeStreams]);

  const downloadJson = useCallback(
    (filenamePrefix: string, payload: unknown = snapshot) => {
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    },
    [snapshot],
  );

  return { snapshot, state, error, sseConnected, refresh, downloadJson };
}

export function useReadinessMemo(snapshot: QuantumReadinessSnapshot) {
  return useMemo(() => {
    const { scores, inventory, riskDistribution } = snapshot;
    const totalAssets = Math.max(1, inventory.assetsAssessed);
    return {
      pqcReadyPct: Math.round((inventory.pqcReadyAssets / totalAssets) * 100),
      vulnerablePct: Math.round((inventory.quantumVulnerableAssets / totalAssets) * 100),
      totalFindings: riskDistribution.critical + riskDistribution.high + riskDistribution.medium + riskDistribution.low,
      readinessColor: readinessTone(scores.quantumReadiness),
      riskColor: riskTone(scores.quantumRisk),
    };
  }, [snapshot]);
}
