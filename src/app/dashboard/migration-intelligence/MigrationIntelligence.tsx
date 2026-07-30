'use client';

import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Scale, Shield, Cloud, Globe, UserCog, RefreshCw, Radio, AlertTriangle, CheckCircle2,
  Clock, Layers, Network, ChevronRight, ChevronLeft, ChevronsLeft, ChevronsRight,
  Building2, X, ArrowRight, Gauge,
  Workflow, ShieldCheck, Info, Server, Wifi, Route, type LucideIcon,
} from 'lucide-react';
import { useMigrationIntelligence } from '@/hooks/use-migration-intelligence';
import { migrationDependencyLabel } from '@/lib/shared-responsibility';
import type {
  OwnershipFinding, ResponsibilityDomain, FindingPriority, MigrationDependencyStatus,
} from '@/lib/shared-responsibility';
import {
  Panel, SectionTitle, EmptyState, HeaderButton, Badge, Ring, ScoreGauge, MetricCard,
  integerFmt, readinessTone,
  RED, ORANGE, AMBER, GREEN, EMERALD, BLUE, CYAN, VIOLET, SLATE,
} from '@/app/dashboard/quantum-readiness/_shared';

/* ------------------------------------------------------------------ */
/* Domain + priority presentation                                     */
/* ------------------------------------------------------------------ */
const DOMAIN_META: Record<ResponsibilityDomain, { label: string; short: string; color: string; icon: LucideIcon; blurb: string }> = {
  customer: { label: 'Customer-Controlled', short: 'Customer', color: CYAN, icon: UserCog, blurb: 'You own the asset — directly actionable today.' },
  provider: { label: 'Provider-Controlled', short: 'Provider', color: BLUE, icon: Cloud, blurb: 'Managed by a cloud / edge / SaaS provider.' },
  ecosystem: { label: 'Ecosystem-Dependent', short: 'Ecosystem', color: VIOLET, icon: Globe, blurb: 'Depends on browsers, OS, hardware or standards.' },
};

const PRIORITY_COLOR: Record<FindingPriority, string> = {
  critical: RED, high: ORANGE, medium: AMBER, low: BLUE, informational: SLATE,
};

function depColor(status: MigrationDependencyStatus): string {
  if (status === 'ready') return EMERALD;
  if (status === 'blocked') return RED;
  return AMBER;
}

function severityBucketColor(kind: 'critical' | 'high' | 'medium' | 'low'): string {
  return kind === 'critical' ? RED : kind === 'high' ? ORANGE : kind === 'medium' ? AMBER : BLUE;
}

/** Findings shown per page in the Shared Responsibility Matrix. */
const MATRIX_PAGE_SIZE = 10;

/**
 * Compact page window with first/last anchors and ellipsis gaps — e.g.
 * `[1, 'gap', 4, 5, 6, 'gap', 15]`. Keeps the control to a fixed width no
 * matter how many findings exist.
 */
function pageWindow(current: number, total: number): Array<number | 'gap'> {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: Array<number | 'gap'> = [1];
  const left = Math.max(2, current - 1);
  const right = Math.min(total - 1, current + 1);
  if (left > 2) pages.push('gap');
  for (let p = left; p <= right; p += 1) pages.push(p);
  if (right < total - 1) pages.push('gap');
  pages.push(total);
  return pages;
}

/* ------------------------------------------------------------------ */
/* Small charts                                                       */
/* ------------------------------------------------------------------ */
function Donut({ segments, size = 150 }: { segments: Array<{ label: string; value: number; color: string }>; size?: number }) {
  const total = segments.reduce((a, s) => a + s.value, 0);
  const stroke = 20;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} fill="none" />
        {total > 0 &&
          segments.map((s) => {
            const frac = s.value / total;
            const dash = frac * c;
            const el = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                stroke={s.color}
                strokeWidth={stroke}
                fill="none"
                strokeDasharray={`${dash} ${c - dash}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                style={{ transition: 'stroke-dasharray 0.7s ease' }}
              />
            );
            offset += dash;
            return el;
          })}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-2xl font-semibold text-white">{integerFmt(total)}</div>
          <div className="text-[9px] font-black uppercase tracking-wide text-white/45">Findings</div>
        </div>
      </div>
    </div>
  );
}

function StackedSeverityBar({ bucket }: { bucket: { critical: number; high: number; medium: number; low: number } }) {
  const total = bucket.critical + bucket.high + bucket.medium + bucket.low;
  const parts: Array<{ kind: 'critical' | 'high' | 'medium' | 'low'; value: number }> = [
    { kind: 'critical', value: bucket.critical },
    { kind: 'high', value: bucket.high },
    { kind: 'medium', value: bucket.medium },
    { kind: 'low', value: bucket.low },
  ];
  return (
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-white/5">
      {total === 0 ? null : parts.map((p) => (
        <div key={p.kind} style={{ width: `${(p.value / total) * 100}%`, backgroundColor: severityBucketColor(p.kind) }} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
export default function MigrationIntelligence() {
  const navigate = useNavigate();
  const { data, state, error, sseConnected, refresh } = useMigrationIntelligence();
  const [domainFilter, setDomainFilter] = useState<'all' | ResponsibilityDomain>('all');
  const [selected, setSelected] = useState<OwnershipFinding | null>(null);
  const [matrixPage, setMatrixPage] = useState(1);

  const readiness = data.readiness;
  const w = data.widgets;

  const filteredMatrix = useMemo(
    () => (domainFilter === 'all' ? data.matrix : data.matrix.filter((r) => r.domain === domainFilter)),
    [data.matrix, domainFilter],
  );

  // Pagination — 10 findings per page. Clamp on render so a shrinking dataset
  // (filter change / live refresh) can never strand the view on an empty page.
  const matrixTotal = filteredMatrix.length;
  const matrixTotalPages = Math.max(1, Math.ceil(matrixTotal / MATRIX_PAGE_SIZE));
  const matrixCurrentPage = Math.min(matrixPage, matrixTotalPages);
  const matrixStart = (matrixCurrentPage - 1) * MATRIX_PAGE_SIZE;
  const pagedMatrix = filteredMatrix.slice(matrixStart, matrixStart + MATRIX_PAGE_SIZE);

  // Reset to the first page whenever the ownership filter changes.
  useEffect(() => {
    setMatrixPage(1);
  }, [domainFilter]);

  const openFinding = (findingId: string) => {
    const baseId = findingId.split(':')[0];
    const finding = data.findings.find((f) => f.id === baseId) || null;
    if (finding) setSelected(finding);
  };

  if (state === 'loading' && !data.hasData) {
    return (
      <div className="grid min-h-[70vh] place-items-center">
        <div className="flex items-center gap-3 text-white/60">
          <RefreshCw className="h-5 w-5 animate-spin" />
          <span className="text-sm font-semibold">Classifying cryptographic ownership…</span>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300">
            <Scale className="h-6 w-6" />
          </span>
          <div>
            <h1 className="text-xl font-black tracking-tight text-white sm:text-2xl">
              Shared Responsibility Migration Intelligence™
            </h1>
            <p className="mt-0.5 max-w-2xl text-xs text-white/55">
              Every finding classified by ownership — who owns it, who can fix it, what it depends on, and what to do next.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wide ${
              sseConnected ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300' : 'border-white/10 bg-black/20 text-white/45'
            }`}
          >
            <Radio className="h-3 w-3" /> {sseConnected ? 'Live' : 'Reconnecting'}
          </span>
          <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
          <HeaderButton icon={Route} onClick={() => navigate('/dashboard/migration-planner')}>Planner</HeaderButton>
        </div>
      </div>

      {error && !data.hasData ? (
        <Panel className="p-5">
          <div className="flex items-center gap-2 text-sm text-red-300">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        </Panel>
      ) : !data.hasData ? (
        <Panel className="p-8">
          <EmptyState
            label="No cryptographic findings to classify yet."
            hint="Run a PQC scan or connect a provider account. Findings will be classified into customer, provider and ecosystem ownership as evidence arrives."
          />
        </Panel>
      ) : (
        <div className="space-y-6">
          {/* Tri-part readiness */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Where progress can actually be made</span>}>
              Quantum Readiness — Shared Responsibility Breakdown
            </SectionTitle>
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
              <ScoreGauge label="Overall Readiness" score={readiness.overall.score} level={readiness.overall.level} color={readinessTone(readiness.overall.score)} />
              <ScoreGauge label="Customer Readiness" score={readiness.customer.score} level={readiness.customer.level} color={CYAN} />
              <ScoreGauge label="Provider Readiness" score={readiness.provider.score} level={readiness.provider.level} color={BLUE} />
              <ScoreGauge label="Ecosystem Readiness" score={readiness.ecosystem.score} level={readiness.ecosystem.level} color={VIOLET} />
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-white/45">
              Overall readiness reflects the whole estate. The domain scores show how ready each ownership area is — so executives
              see where their teams can drive progress today (customer) versus what depends on providers or the wider ecosystem.
            </p>
          </Panel>

          {/* Widget grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
            <MetricCard label="Customer Findings" value={integerFmt(w.customerFindings)} detail="You can remediate" color={CYAN} icon={UserCog} />
            <MetricCard label="Provider Findings" value={integerFmt(w.providerFindings)} detail="Provider-managed" color={BLUE} icon={Cloud} />
            <MetricCard label="Vendor / SaaS" value={integerFmt(w.vendorFindings)} detail="Partner dependencies" color={VIOLET} icon={Building2} />
            <MetricCard label="Cloud Dependencies" value={integerFmt(w.cloudDependencies)} detail="Edge / LB / managed" color={BLUE} icon={Server} />
            <MetricCard label="Browser Dependencies" value={integerFmt(w.browserDependencies)} detail="Await browser support" color={VIOLET} icon={Globe} />
            <MetricCard label="Actionable Now" value={integerFmt(w.actionableFindings)} detail="Customer-actionable" color={EMERALD} icon={CheckCircle2} ring={readiness.overall.total ? Math.round((w.actionableFindings / Math.max(1, readiness.overall.total)) * 100) : 0} />
            <MetricCard label="Migration Blockers" value={integerFmt(w.migrationBlockers)} detail="Gated on a dependency" color={RED} icon={AlertTriangle} />
            <MetricCard label="Waiting Dependencies" value={integerFmt(w.waitingDependencies)} detail="Provider / ecosystem" color={AMBER} icon={Clock} />
            <MetricCard label="Provider Readiness" value={integerFmt(w.providerReadiness)} suffix="/100" detail="PQ roadmap posture" color={BLUE} icon={Gauge} ring={w.providerReadiness} />
            <MetricCard label="Migration Progress" value={integerFmt(w.migrationProgress)} suffix="/100" detail="Overall readiness" color={readinessTone(w.migrationProgress)} icon={Workflow} ring={w.migrationProgress} />
          </div>

          {/* Ownership distribution + severity per responsibility */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Panel className="p-5">
              <SectionTitle>Ownership Distribution</SectionTitle>
              <div className="flex items-center gap-6">
                <Donut
                  segments={[
                    { label: 'Customer', value: data.domainDistribution.customer, color: CYAN },
                    { label: 'Provider', value: data.domainDistribution.provider, color: BLUE },
                    { label: 'Ecosystem', value: data.domainDistribution.ecosystem, color: VIOLET },
                  ]}
                />
                <div className="flex-1 space-y-3">
                  {(['customer', 'provider', 'ecosystem'] as ResponsibilityDomain[]).map((d) => {
                    const meta = DOMAIN_META[d];
                    const count = data.domainDistribution[d];
                    const Icon = meta.icon;
                    return (
                      <div key={d} className="flex items-start gap-2.5">
                        <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md" style={{ backgroundColor: `${meta.color}18`, color: meta.color }}>
                          <Icon className="h-4 w-4" />
                        </span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-white">{integerFmt(count)}</span>
                            <span className="text-[11px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                          </div>
                          <div className="truncate text-[11px] text-white/45">{meta.blurb}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Panel>

            <Panel className="p-5">
              <SectionTitle suffix={<LegendSeverity />}>Severity by Responsibility</SectionTitle>
              <div className="space-y-4">
                {(['customer', 'provider', 'ecosystem'] as ResponsibilityDomain[]).map((d) => {
                  const meta = DOMAIN_META[d];
                  const bucket = data.severityByDomain[d];
                  const total = bucket.critical + bucket.high + bucket.medium + bucket.low;
                  return (
                    <div key={d}>
                      <div className="mb-1.5 flex items-center justify-between text-[11px]">
                        <span className="font-bold" style={{ color: meta.color }}>{meta.label}</span>
                        <span className="font-mono text-white/50">
                          {integerFmt(total)} · C{bucket.critical} H{bucket.high} M{bucket.medium} L{bucket.low}
                        </span>
                      </div>
                      <StackedSeverityBar bucket={bucket} />
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>

          {/* Edge vs Origin intelligence */}
          <Panel className="p-5">
            <SectionTitle suffix={<Badge color={data.edgeOrigin.providerFrontedAssets > 0 ? BLUE : SLATE}>{integerFmt(data.edgeOrigin.providerFrontedAssets)} provider-fronted</Badge>}>
              TLS Intelligence — Edge vs Origin
            </SectionTitle>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-blue-400/20 bg-blue-500/[0.06] p-4">
                <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-blue-300">
                  <Wifi className="h-4 w-4" /> Edge (Provider-Managed)
                </div>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  {integerFmt(data.edgeOrigin.edgeManaged)} public TLS endpoints terminate at a provider edge. The edge certificate is
                  provider-managed — monitor the provider roadmap; no customer edge change is required.
                </p>
              </div>
              <div className="rounded-lg border border-cyan-400/20 bg-cyan-500/[0.06] p-4">
                <div className="flex items-center gap-2 text-[11px] font-black uppercase tracking-wide text-cyan-300">
                  <Server className="h-4 w-4" /> Origin (Customer-Controlled)
                </div>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  {integerFmt(data.edgeOrigin.originCustomerControlled)} origins behind those edges are customer-controlled and can be
                  hardened today — upgrade the origin TLS library and deploy an ML-KEM hybrid (X25519+ML-KEM).
                </p>
              </div>
            </div>
            {data.edgeOrigin.summary ? <p className="mt-3 text-[11px] text-white/45">{data.edgeOrigin.summary}</p> : null}
          </Panel>

          {/* Shared Responsibility Matrix */}
          <Panel className="p-5">
            <SectionTitle
              suffix={
                <div className="flex items-center gap-1.5">
                  {(['all', 'customer', 'provider', 'ecosystem'] as const).map((f) => (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setDomainFilter(f)}
                      className={`rounded px-2 py-1 text-[10px] font-black uppercase tracking-wide transition ${
                        domainFilter === f ? 'bg-white/15 text-white' : 'bg-white/[0.03] text-white/45 hover:text-white/70'
                      }`}
                    >
                      {f === 'all' ? 'All' : DOMAIN_META[f].short}
                    </button>
                  ))}
                </div>
              }
            >
              Shared Responsibility Matrix
            </SectionTitle>
            {filteredMatrix.length === 0 ? (
              <EmptyState label="No findings in this ownership domain." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-[10px] font-black uppercase tracking-wide text-white/40">
                      <th className="py-2 pr-3">Finding</th>
                      <th className="py-2 pr-3">Asset</th>
                      <th className="py-2 pr-3">Owner</th>
                      <th className="py-2 pr-3">Action</th>
                      <th className="py-2 pr-3 text-right">Inst.</th>
                      <th className="py-2 pr-3">Priority</th>
                      <th className="py-2 pr-3">Status</th>
                      <th className="py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {pagedMatrix.map((row) => {
                      const meta = DOMAIN_META[row.domain];
                      const occurrences = Math.max(1, row.occurrences ?? 1);
                      return (
                        <tr
                          key={row.findingId}
                          className="cursor-pointer border-b border-white/5 transition hover:bg-white/[0.03]"
                          onClick={() => openFinding(row.findingId)}
                        >
                          <td className="max-w-[220px] py-2.5 pr-3">
                            <div className="flex items-center gap-2">
                              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} />
                              <span className="truncate font-semibold text-white/85" title={row.finding}>{row.finding}</span>
                            </div>
                          </td>
                          <td className="max-w-[180px] py-2.5 pr-3">
                            <span className="block truncate text-white/60" title={(row.detectionLabels ?? [row.asset]).join(' · ')}>{row.asset}</span>
                          </td>
                          <td className="py-2.5 pr-3"><span className="font-semibold" style={{ color: meta.color }}>{row.owner}</span></td>
                          <td className="max-w-[240px] py-2.5 pr-3"><span className="line-clamp-2 text-white/60">{row.action}</span></td>
                          <td className="py-2.5 pr-3 text-right font-mono text-white/55">{occurrences}</td>
                          <td className="py-2.5 pr-3"><Badge color={PRIORITY_COLOR[row.priority]}>{row.priority}</Badge></td>
                          <td className="py-2.5 pr-3"><span className="text-white/65">{row.status}</span></td>
                          <td className="py-2.5 text-white/30"><ChevronRight className="h-4 w-4" /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <MatrixPagination
                  total={matrixTotal}
                  currentPage={matrixCurrentPage}
                  totalPages={matrixTotalPages}
                  rangeStart={matrixStart}
                  shown={pagedMatrix.length}
                  onPage={(p) => setMatrixPage(Math.min(Math.max(1, p), matrixTotalPages))}
                />
              </div>
            )}
          </Panel>

          {/* Blockers + 7-wave roadmap */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Panel className="p-5">
              <SectionTitle suffix={<Badge color={data.blockers.length ? RED : EMERALD}>{integerFmt(data.blockers.length)}</Badge>}>Migration Blockers</SectionTitle>
              {data.blockers.length === 0 ? (
                <EmptyState label="No high-impact blockers." hint="High/critical findings gated on an upstream dependency appear here." />
              ) : (
                <div className="space-y-2.5">
                  {data.blockers.slice(0, 8).map((b) => (
                    <button
                      key={b.id}
                      type="button"
                      onClick={() => setSelected(b)}
                      className="flex w-full items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-left transition hover:border-white/20"
                    >
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md" style={{ backgroundColor: `${depColor(b.migrationDependencyStatus)}18`, color: depColor(b.migrationDependencyStatus) }}>
                        <AlertTriangle className="h-4 w-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs font-semibold text-white/85">{b.title}</div>
                        <div className="truncate text-[11px] text-white/45">{b.ownerType} · {migrationDependencyLabel(b.migrationDependencyStatus)}</div>
                      </div>
                      <Badge color={depColor(b.migrationDependencyStatus)}>{migrationDependencyLabel(b.migrationDependencyStatus)}</Badge>
                    </button>
                  ))}
                </div>
              )}
            </Panel>

            <Panel className="p-5">
              <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Dependency-ordered</span>}>Migration Roadmap — 7 Waves</SectionTitle>
              <div className="space-y-2">
                {data.waves.map((wave) => {
                  const meta = wave.domain === 'mixed' ? { color: SLATE } : DOMAIN_META[wave.domain];
                  const statusColor = wave.status === 'ready' ? EMERALD : wave.status === 'complete' ? GREEN : wave.status === 'blocked' ? RED : AMBER;
                  return (
                    <div key={wave.wave} className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-2.5">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md text-xs font-black" style={{ backgroundColor: `${meta.color}18`, color: meta.color }}>
                        {wave.wave}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-xs font-bold text-white/85">{wave.name}</span>
                          <span className="text-[10px] font-mono text-white/40">{integerFmt(wave.findingCount)}</span>
                        </div>
                        <div className="truncate text-[10px] text-white/40">{wave.description}</div>
                      </div>
                      <div className="text-right">
                        <Badge color={statusColor}>{wave.status}</Badge>
                        <div className="mt-0.5 text-[9px] text-white/35">{wave.estimatedTimeline}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>

          {/* Provider readiness breakdown */}
          <Panel className="p-5">
            <SectionTitle suffix={<span className="text-[10px] font-bold uppercase tracking-wide text-white/40">Evidence-attributed</span>}>Provider &amp; Ecosystem Readiness</SectionTitle>
            {data.providerBreakdown.length === 0 ? (
              <EmptyState label="No providers attributed yet." hint="Connect a provider account or capture TLS/header evidence to attribute findings." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-[10px] font-black uppercase tracking-wide text-white/40">
                      <th className="py-2 pr-3">Provider / Technology</th>
                      <th className="py-2 pr-3">Domain</th>
                      <th className="py-2 pr-3">Findings</th>
                      <th className="py-2 pr-3">PQ Roadmap</th>
                      <th className="py-2 pr-3">Customer Influence</th>
                      <th className="py-2">Attribution Conf.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.providerBreakdown.slice(0, 20).map((p) => {
                      const meta = DOMAIN_META[p.domain];
                      const roadmapColor = p.pqRoadmapStatus === 'shipping' ? EMERALD : p.pqRoadmapStatus === 'in_progress' ? BLUE : p.pqRoadmapStatus === 'announced' ? AMBER : SLATE;
                      return (
                        <tr key={p.providerId} className="border-b border-white/5">
                          <td className="py-2.5 pr-3 font-semibold text-white/85">{p.name}</td>
                          <td className="py-2.5 pr-3"><span className="font-semibold" style={{ color: meta.color }}>{meta.short}</span></td>
                          <td className="py-2.5 pr-3 font-mono text-white/70">{integerFmt(p.count)}</td>
                          <td className="py-2.5 pr-3"><Badge color={roadmapColor}>{p.pqRoadmapStatus.replace('_', ' ')}</Badge></td>
                          <td className="py-2.5 pr-3 capitalize text-white/60">{p.customerInfluence}</td>
                          <td className="py-2.5 text-white/60">{integerFmt(p.avgConfidence)}%</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <div className="mt-4 flex flex-wrap items-center gap-4 border-t border-white/8 pt-3 text-[11px] text-white/45">
              <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5 text-emerald-400" /> {integerFmt(data.attribution.attributed)} attributed</span>
              <span className="inline-flex items-center gap-1.5"><Info className="h-3.5 w-3.5 text-white/40" /> {integerFmt(data.attribution.unattributed)} unattributed (honest — evidence-driven only)</span>
              <span className="inline-flex items-center gap-1.5"><Gauge className="h-3.5 w-3.5 text-cyan-400" /> {integerFmt(data.attribution.avgConfidence)}% avg confidence</span>
            </div>
          </Panel>
        </div>
      )}

      {selected ? <FindingDrawer finding={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function LegendSeverity() {
  return (
    <div className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-wide text-white/40">
      {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: severityBucketColor(k) }} /> {k[0]}
        </span>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Premium matrix paginator — 10 findings / page                       */
/* ------------------------------------------------------------------ */
const PAGE_NAV_BASE =
  'grid h-8 w-8 place-items-center rounded-md border border-white/10 bg-white/[0.03] text-white/55 transition hover:border-cyan-400/40 hover:bg-cyan-500/10 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-30 disabled:hover:border-white/10 disabled:hover:bg-white/[0.03] disabled:hover:text-white/55';

function PageNav({ label, disabled, onClick, icon: Icon }: { label: string; disabled: boolean; onClick: () => void; icon: LucideIcon }) {
  return (
    <button type="button" aria-label={label} title={label} disabled={disabled} onClick={onClick} className={PAGE_NAV_BASE}>
      <Icon className="h-4 w-4" />
    </button>
  );
}

function MatrixPagination({
  total,
  currentPage,
  totalPages,
  rangeStart,
  shown,
  onPage,
}: {
  total: number;
  currentPage: number;
  totalPages: number;
  rangeStart: number;
  shown: number;
  onPage: (page: number) => void;
}) {
  const firstRow = total === 0 ? 0 : rangeStart + 1;
  const lastRow = rangeStart + shown;
  return (
    <div className="mt-4 flex flex-col gap-3 border-t border-white/8 pt-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-[11px] text-white/45">
        Showing <span className="font-mono font-semibold text-white/75">{integerFmt(firstRow)}</span>–
        <span className="font-mono font-semibold text-white/75">{integerFmt(lastRow)}</span> of{' '}
        <span className="font-mono font-semibold text-white/75">{integerFmt(total)}</span> findings
        <span className="ml-1 text-white/30">· {MATRIX_PAGE_SIZE} per page</span>
      </p>

      {totalPages > 1 ? (
        <nav aria-label="Findings pagination" className="flex items-center gap-1.5">
          <PageNav label="First page" icon={ChevronsLeft} disabled={currentPage <= 1} onClick={() => onPage(1)} />
          <PageNav label="Previous page" icon={ChevronLeft} disabled={currentPage <= 1} onClick={() => onPage(currentPage - 1)} />

          <div className="flex items-center gap-1">
            {pageWindow(currentPage, totalPages).map((entry, i) =>
              entry === 'gap' ? (
                <span key={`gap-${i}`} className="px-1 text-[11px] font-bold text-white/25" aria-hidden="true">
                  …
                </span>
              ) : (
                <button
                  key={entry}
                  type="button"
                  aria-label={`Page ${entry}`}
                  aria-current={entry === currentPage ? 'page' : undefined}
                  onClick={() => onPage(entry)}
                  className={
                    entry === currentPage
                      ? 'h-8 min-w-[2rem] rounded-md border border-cyan-400/50 bg-cyan-500/15 px-2 text-[11px] font-black text-cyan-200 shadow-[0_0_16px_rgba(34,211,238,0.18)]'
                      : 'h-8 min-w-[2rem] rounded-md border border-white/10 bg-white/[0.03] px-2 text-[11px] font-bold text-white/55 transition hover:border-cyan-400/40 hover:bg-cyan-500/10 hover:text-cyan-200'
                  }
                >
                  {entry}
                </button>
              ),
            )}
          </div>

          <PageNav label="Next page" icon={ChevronRight} disabled={currentPage >= totalPages} onClick={() => onPage(currentPage + 1)} />
          <PageNav label="Last page" icon={ChevronsRight} disabled={currentPage >= totalPages} onClick={() => onPage(totalPages)} />
        </nav>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Finding drill-down drawer — ownership, dependency chain, edge/origin */
/* ------------------------------------------------------------------ */
function FindingDrawer({ finding, onClose }: { finding: OwnershipFinding; onClose: () => void }) {
  const meta = DOMAIN_META[finding.domain];
  const Icon = meta.icon;
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <motion.div
        initial={{ x: 40, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.2 }}
        className="h-full w-full max-w-xl overflow-y-auto border-l border-white/10 bg-[#0b1220] p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-lg" style={{ backgroundColor: `${meta.color}18`, color: meta.color }}>
              <Icon className="h-5 w-5" />
            </span>
            <div>
              <div className="text-[10px] font-black uppercase tracking-wide" style={{ color: meta.color }}>{meta.label}</div>
              <h3 className="text-sm font-bold text-white">{finding.title}</h3>
            </div>
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1.5 text-white/50 hover:bg-white/10 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="mb-4 text-xs leading-relaxed text-white/60">{finding.description}</p>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <Field label="Owner" value={finding.ownerType} />
          <Field label="Responsible Party" value={finding.responsibleParty} />
          <Field label="Customer Actionable" value={finding.actionability.label} valueColor={finding.customerActionable === 'yes' ? EMERALD : finding.customerActionable === 'partial' ? AMBER : SLATE} />
          <Field label="Priority" value={finding.priority} valueColor={PRIORITY_COLOR[finding.priority]} />
          <Field label="Business Impact" value={finding.businessImpact.level} />
          <Field label="Migration Complexity" value={finding.migrationComplexity} />
          <Field label="Estimated Effort" value={finding.estimatedEffort} />
          <Field label="Estimated Timeline" value={finding.estimatedTimeline} />
        </div>

        {/* Recommended action */}
        <div className="mt-5 rounded-lg border border-cyan-400/20 bg-cyan-500/[0.05] p-3">
          <div className="mb-1 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-cyan-300">
            <ArrowRight className="h-3.5 w-3.5" /> Recommended Action
          </div>
          <p className="text-xs leading-relaxed text-white/70">{finding.recommendedAction}</p>
        </div>

        {/* Migration dependency chain */}
        <div className="mt-5">
          <div className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/50">
            <Network className="h-3.5 w-3.5" /> Migration Dependency Chain
          </div>
          <div className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
            <div className="mb-2 text-[11px] text-white/55">{finding.dependencyChain.summary}</div>
            <div className="flex flex-wrap items-center gap-1.5">
              {finding.dependencyChain.nodes.map((node, i) => (
                <span key={node.id} className="inline-flex items-center gap-1.5">
                  <span
                    className="rounded px-2 py-1 text-[10px] font-bold"
                    style={{
                      backgroundColor: node.blocking ? `${RED}18` : node.status === 'complete' ? `${EMERALD}14` : 'rgba(255,255,255,0.05)',
                      color: node.blocking ? RED : node.status === 'complete' ? EMERALD : 'rgba(255,255,255,0.7)',
                      border: `1px solid ${node.blocking ? `${RED}40` : 'rgba(255,255,255,0.08)'}`,
                    }}
                    title={node.note}
                  >
                    {node.label}
                  </span>
                  {i < finding.dependencyChain.nodes.length - 1 ? <ChevronRight className="h-3 w-3 text-white/25" /> : null}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Edge / origin */}
        {finding.edgeOrigin ? (
          <div className="mt-5">
            <div className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/50">
              <Layers className="h-3.5 w-3.5" /> TLS Layers (Edge vs Origin)
            </div>
            <div className="space-y-2">
              {finding.edgeOrigin.layers.map((layer) => (
                <div key={layer.layer} className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold capitalize text-white/80">{layer.layer} · {layer.owner}</span>
                    <Badge color={layer.domain === 'customer' ? CYAN : BLUE}>{layer.customerControl === 'yes' ? 'Customer' : 'Provider'}</Badge>
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-white/55">{layer.recommendation}</p>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {/* Confidence + evidence */}
        <div className="mt-5">
          <div className="mb-2 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-white/50">
            <Shield className="h-3.5 w-3.5" /> Evidence &amp; Confidence
          </div>
          <div className="grid grid-cols-2 gap-3">
            <ConfBar label="Overall" value={finding.confidence.overall} />
            <ConfBar label="Ownership" value={finding.confidence.ownership} />
            <ConfBar label="Actionability" value={finding.confidence.actionability} />
            <ConfBar label="Provider Attribution" value={finding.confidence.providerAttribution} />
          </div>
          <div className="mt-3 space-y-1 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-[11px] text-white/55">
            <div><span className="text-white/40">Detection:</span> {finding.evidence.detectionMethod}</div>
            <div><span className="text-white/40">Source:</span> {finding.evidence.evidenceSource}</div>
            <div><span className="text-white/40">Attribution:</span> {finding.evidence.providerAttributionReason}</div>
          </div>
          {finding.references.length ? (
            <div className="mt-2 flex flex-wrap gap-2">
              {finding.references.map((r) => (
                <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="text-[11px] text-cyan-300 underline decoration-dotted hover:text-cyan-200">
                  {r.label}
                </a>
              ))}
            </div>
          ) : null}
        </div>
      </motion.div>
    </div>
  );
}

function Field({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-white/[0.02] p-2.5">
      <div className="text-[9px] font-black uppercase tracking-wide text-white/40">{label}</div>
      <div className="mt-0.5 truncate text-xs font-semibold capitalize" style={{ color: valueColor || 'rgba(255,255,255,0.85)' }} title={value}>{value}</div>
    </div>
  );
}

function ConfBar({ label, value }: { label: string; value: number }) {
  const color = value >= 80 ? EMERALD : value >= 60 ? BLUE : value >= 40 ? AMBER : SLATE;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-[10px]">
        <span className="text-white/45">{label}</span>
        <span className="font-mono text-white/60">{integerFmt(value)}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/5">
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(100, value)}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
