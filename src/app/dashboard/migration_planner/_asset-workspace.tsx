'use client';

/**
 * Migration Planner — Asset-Centric Migration Workspace.
 *
 * An enterprise asset selector plus a full per-asset migration dossier. While an
 * asset is selected the workspace renders THAT asset only: every panel, score,
 * recommendation, timeline and dependency belongs to the selected asset, so an
 * operator is never confused about which estate the numbers describe.
 *
 * All data arrives from /api/v1/migration-planner (see use-migration-assets),
 * which derives it from the same engine as the Quantum Readiness snapshot —
 * nothing here recomputes or reshapes a security metric client-side.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Boxes,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  Clock,
  Fingerprint,
  Gauge,
  Globe,
  KeyRound,
  Layers,
  ListOrdered,
  Lock,
  Network,
  Radio,
  RotateCcw,
  Rocket,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  TrendingUp,
  Undo2,
  UserCheck,
  X,
  type LucideIcon,
} from 'lucide-react';
import {
  Badge,
  EmptyState,
  HeaderButton,
  Panel,
  PrimaryButton,
  Ring,
  SectionTitle,
  integerFmt,
  longDate,
  percentLabel,
  readinessTone,
  riskTone,
  severityColor,
  RED,
  ORANGE,
  AMBER,
  GOLD,
  GREEN,
  EMERALD,
  TEAL,
  BLUE,
  CYAN,
  VIOLET,
} from '@/app/dashboard/quantum-readiness/_shared';
import type {
  AssetDossier,
  AssetFilters,
  AssetSummaryRecord,
  PortfolioSummary,
  QueueEntry,
} from '@/hooks/use-migration-assets';

const SLATEISH = '#64748B';

export function levelTone(level: string): string {
  const l = (level || '').toLowerCase();
  if (l.includes('critical')) return RED;
  if (l.includes('high') || l.includes('elevated')) return ORANGE;
  if (l.includes('medium') || l.includes('moderate')) return GOLD;
  if (l.includes('low') || l.includes('minimal')) return GREEN;
  return TEAL;
}

const POSTURE_TONE: Record<string, string> = { pqc: EMERALD, hybrid: AMBER, vulnerable: RED, unknown: SLATEISH };

function statusTone(status: string): string {
  const s = status.toLowerCase();
  if (s.includes('fail')) return RED;
  if (s.includes('complete')) return EMERALD;
  if (s.includes('progress') || s.includes('validat')) return BLUE;
  if (s.includes('queue') || s.includes('plan')) return GOLD;
  return SLATEISH;
}

/* ------------------------------------------------------------------ */
/* Small primitives                                                    */
/* ------------------------------------------------------------------ */

function Stat({ label, value, tone, hint, highlight }: { label: string; value: ReactNode; tone?: string; hint?: string; highlight?: boolean }) {
  return (
    <div
      className={`rounded-lg border p-3 transition-colors duration-500 ${
        highlight ? 'border-cyan-300/60 bg-cyan-400/[0.08]' : 'border-white/8 bg-white/[0.025]'
      }`}
    >
      <div className="truncate text-base font-semibold" style={{ color: tone || '#fff' }}>{value}</div>
      <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-wide text-white/45">{label}</div>
      {hint ? <div className="mt-0.5 truncate text-[10px] text-white/35">{hint}</div> : null}
    </div>
  );
}

function MiniBar({ value, tone }: { value: number; tone: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.max(0, Math.min(100, value))}%`, backgroundColor: tone }} />
    </div>
  );
}

function Chip({ children, tone = SLATEISH }: { children: ReactNode; tone?: string }) {
  return (
    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wide" style={{ color: tone, backgroundColor: `${tone}1a` }}>
      {children}
    </span>
  );
}

function SkeletonBlock({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg border border-white/5 bg-white/[0.04] ${className}`} />;
}

/* ------------------------------------------------------------------ */
/* Asset selector rail                                                 */
/* ------------------------------------------------------------------ */

/**
 * Windowing is only worth its complexity on large estates, and a hardcoded row
 * height is a layout bug waiting to happen (chips wrap, fonts and zoom differ,
 * so a guessed height clips the card). So: render the list normally below the
 * threshold, and above it window using a row height MEASURED from a real card.
 */
const VIRTUALIZE_THRESHOLD = 60;
const FALLBACK_ROW_HEIGHT = 156;
const ROW_GAP = 8;
const WINDOW_OVERSCAN = 6;

function AssetCard({
  asset,
  active,
  onSelect,
  onQueue,
}: {
  asset: AssetSummaryRecord;
  active: boolean;
  onSelect: () => void;
  onQueue: () => void;
}) {
  const postureTone = POSTURE_TONE[asset.posture] || SLATEISH;
  return (
    <div
      role="option"
      aria-selected={active}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onSelect();
        }
      }}
      className={`group cursor-pointer rounded-xl border p-3 transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60 ${
        active
          ? 'border-cyan-400/60 bg-cyan-400/[0.09] shadow-[0_0_0_1px_rgba(34,211,238,0.25),0_10px_30px_-12px_rgba(34,211,238,0.5)]'
          : 'border-white/8 bg-white/[0.025] hover:border-cyan-400/35 hover:bg-white/[0.045]'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-[13px] font-bold text-white/90">{asset.name}</span>
            {asset.internetFacing ? <Globe className="h-3 w-3 shrink-0 text-orange-300" aria-label="Internet-facing" /> : null}
          </div>
          <div className="truncate text-[10px] text-white/45">
            {asset.type}
            {asset.hostname && asset.hostname !== 'Evidence Not Available' ? ` · ${asset.hostname}` : ''}
          </div>
        </div>
        <button
          type="button"
          aria-label={asset.queued ? 'Already queued' : 'Add to migration queue'}
          onClick={(event) => {
            event.stopPropagation();
            onQueue();
          }}
          disabled={asset.queued}
          className={`shrink-0 rounded-md border px-1.5 py-1 text-[9px] font-black uppercase transition ${
            asset.queued
              ? 'border-emerald-400/40 bg-emerald-400/10 text-emerald-300'
              : 'border-white/12 bg-black/25 text-white/50 hover:border-cyan-400/50 hover:text-cyan-200'
          }`}
        >
          {asset.queued ? 'Queued' : '+ Queue'}
        </button>
      </div>

      {/* Single line by design: the badge row must not wrap, or cards would have
          different heights and the windowed list's row math would drift. */}
      <div className="mt-2 flex flex-nowrap items-center gap-1.5 overflow-hidden">
        <span className="shrink-0"><Chip tone={levelTone(asset.priority)}>{asset.priority}</Chip></span>
        <span className="shrink-0"><Chip tone={postureTone}>{asset.postureLabel}</Chip></span>
        <span className="shrink-0"><Chip tone={statusTone(asset.migrationStatus)}>{asset.migrationStatus}</Chip></span>
        <span className="truncate text-[9px] uppercase tracking-wide text-white/35">{asset.environment}</span>
      </div>

      <div className="mt-2 grid grid-cols-3 gap-2">
        <div>
          <div className="flex items-center justify-between text-[9px] text-white/40">
            <span>Readiness</span>
            <span className="font-mono" style={{ color: readinessTone(asset.readinessScore) }}>{integerFmt(asset.readinessScore)}</span>
          </div>
          <MiniBar value={asset.readinessScore} tone={readinessTone(asset.readinessScore)} />
        </div>
        <div>
          <div className="flex items-center justify-between text-[9px] text-white/40">
            <span>Risk</span>
            <span className="font-mono" style={{ color: riskTone(asset.riskScore) }}>{integerFmt(asset.riskScore)}</span>
          </div>
          <MiniBar value={asset.riskScore} tone={riskTone(asset.riskScore)} />
        </div>
        <div>
          <div className="flex items-center justify-between text-[9px] text-white/40">
            <span>HNDL</span>
            <span className="font-mono" style={{ color: riskTone(asset.hndlScore) }}>{integerFmt(asset.hndlScore)}</span>
          </div>
          <MiniBar value={asset.hndlScore} tone={riskTone(asset.hndlScore)} />
        </div>
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] text-white/40">
        <span className="truncate">{asset.cryptoPostureSummary}</span>
        <span className="shrink-0 pl-2">{asset.estimatedDurationLabel}</span>
      </div>
    </div>
  );
}

export function AssetSelectorRail({
  assets,
  total,
  totalUnfiltered,
  summary,
  environments,
  filters,
  setFilters,
  selectedId,
  onSelect,
  onQueue,
  loading,
  queue,
  onDequeue,
  onReorder,
  onApplyRecommended,
  onDispatchQueue,
  busy,
}: {
  assets: AssetSummaryRecord[];
  total: number;
  totalUnfiltered: number;
  summary: PortfolioSummary;
  environments: string[];
  filters: AssetFilters;
  setFilters: (next: AssetFilters) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onQueue: (id: string) => void;
  loading: boolean;
  queue: QueueEntry[];
  onDequeue: (id: string) => void;
  onReorder: (ids: string[]) => void;
  onApplyRecommended: () => void;
  onDispatchQueue: () => void;
  busy: string | null;
}) {
  const [tab, setTab] = useState<'assets' | 'queue'>('assets');
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(720);
  const [rowHeight, setRowHeight] = useState(FALLBACK_ROW_HEIGHT);
  const listRef = useRef<HTMLDivElement | null>(null);
  const measureRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = listRef.current;
    if (!node) return;
    const observer = new ResizeObserver(() => setViewportHeight(node.clientHeight || 720));
    observer.observe(node);
    setViewportHeight(node.clientHeight || 720);
    return () => observer.disconnect();
  }, [tab]);

  // Measure a real card so the windowing math matches what the browser actually
  // lays out. A guessed height clips the card against the next row / panel edge.
  useEffect(() => {
    const node = measureRef.current;
    if (!node) return;
    const apply = () => {
      const measured = Math.round(node.getBoundingClientRect().height);
      if (measured > 0) setRowHeight((current) => (Math.abs(current - (measured + ROW_GAP)) > 1 ? measured + ROW_GAP : current));
    };
    const observer = new ResizeObserver(apply);
    observer.observe(node);
    apply();
    return () => observer.disconnect();
  }, [tab, assets.length]);

  // Below the threshold the list renders in full — exact layout, no math to get
  // wrong. Above it, window the rows to keep large estates smooth.
  const virtualized = assets.length > VIRTUALIZE_THRESHOLD;
  const startIndex = virtualized ? Math.max(0, Math.floor(scrollTop / rowHeight) - WINDOW_OVERSCAN) : 0;
  const endIndex = virtualized
    ? Math.min(assets.length, Math.ceil((scrollTop + viewportHeight) / rowHeight) + WINDOW_OVERSCAN)
    : assets.length;
  const visible = assets.slice(startIndex, endIndex);

  const move = useCallback(
    (index: number, direction: -1 | 1) => {
      const next = [...queue.map((entry) => entry.assetId)];
      const target = index + direction;
      if (target < 0 || target >= next.length) return;
      [next[index], next[target]] = [next[target], next[index]];
      onReorder(next);
    },
    [queue, onReorder],
  );

  const select = (patch: Partial<AssetFilters>) => setFilters({ ...filters, ...patch });

  return (
    // Height is viewport-relative and always fits: a fixed min-height taller
    // than the screen would push the last cards below the fold while the panel
    // clipped them. On xl the rail sticks and spans the viewport minus its own
    // top/bottom inset; below xl it is a bounded, self-scrolling column.
    <Panel className="h-[calc(100dvh-2rem)] min-h-[380px] overflow-hidden xl:sticky xl:top-4">
      {/*
        Panel renders its children inside its own wrapper div, so the flex column
        has to live HERE — putting `flex flex-col` on Panel itself leaves these
        children in a block container, where `flex-1` does nothing and the list
        grows past the panel and gets clipped by its overflow-hidden.
      */}
      <div className="flex h-full min-h-0 flex-col">
      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-white/8 p-2">
        {([
          ['assets', `Assets ${totalUnfiltered ? `(${integerFmt(totalUnfiltered)})` : ''}`],
          ['queue', `Queue ${queue.length ? `(${queue.length})` : ''}`],
        ] as Array<['assets' | 'queue', string]>).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`flex-1 rounded-lg px-3 py-2 text-[11px] font-black uppercase tracking-wide transition ${
              tab === key ? 'bg-cyan-400/12 text-cyan-200' : 'text-white/45 hover:text-white/75'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'assets' ? (
        <>
          {/* Search + filters */}
          <div className="space-y-2 border-b border-white/8 p-3">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
              <input
                value={filters.search}
                onChange={(event) => select({ search: event.target.value })}
                placeholder="Search assets, hosts, owners…"
                aria-label="Search assets"
                className="h-9 w-full rounded-lg border border-white/10 bg-black/30 pl-8 pr-3 text-xs text-white outline-none transition placeholder:text-white/30 focus:border-cyan-400/50"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              {([
                ['posture', ['all', 'vulnerable', 'hybrid', 'pqc'], 'Posture'],
                ['priority', ['all', 'critical', 'high', 'medium', 'low'], 'Priority'],
                ['status', ['all', 'not started', 'queued', 'in progress', 'validating', 'completed', 'failed'], 'Status'],
                ['sort', ['priority', 'risk', 'readiness', 'effort', 'name'], 'Sort'],
              ] as Array<[keyof AssetFilters, string[], string]>).map(([key, options, label]) => (
                <label key={key} className="block">
                  <span className="sr-only">{label}</span>
                  <select
                    value={filters[key]}
                    onChange={(event) => select({ [key]: event.target.value } as Partial<AssetFilters>)}
                    aria-label={label}
                    className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[11px] font-semibold text-white/75 outline-none transition focus:border-cyan-400/50"
                  >
                    {options.map((option) => (
                      <option key={option} value={option} className="bg-[#0b1120]">
                        {option === 'all' ? `${label}: All` : `${label}: ${option.replace(/\b\w/g, (c) => c.toUpperCase())}`}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <label className="col-span-2 block">
                <span className="sr-only">Environment</span>
                <select
                  value={filters.environment}
                  onChange={(event) => select({ environment: event.target.value })}
                  aria-label="Environment"
                  className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[11px] font-semibold text-white/75 outline-none transition focus:border-cyan-400/50"
                >
                  <option value="all" className="bg-[#0b1120]">Environment: All</option>
                  {environments.map((environment) => (
                    <option key={environment} value={environment} className="bg-[#0b1120]">Environment: {environment}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 text-[9px]">
              <Chip tone={RED}>{integerFmt(summary.quantumVulnerable)} vulnerable</Chip>
              <Chip tone={AMBER}>{integerFmt(summary.hybrid)} hybrid</Chip>
              <Chip tone={EMERALD}>{integerFmt(summary.pqcReady)} PQC-ready</Chip>
              <Chip tone={CYAN}>{integerFmt(summary.averageReadiness)} avg readiness</Chip>
            </div>
          </div>

          {/*
            List. `min-h-0` is required: a flex item defaults to
            min-height:auto, so without it this list grows to its content height
            instead of shrinking inside the panel — and the panel's
            overflow-hidden then clips the last cards instead of scrolling them.
          */}
          <div
            ref={listRef}
            onScroll={(event) => setScrollTop((event.target as HTMLDivElement).scrollTop)}
            className="min-h-0 flex-1 overflow-y-auto p-2"
            role="listbox"
            aria-label="Discovered assets"
          >
            {loading && !assets.length ? (
              <div className="space-y-2">
                {[0, 1, 2, 3, 4].map((index) => <SkeletonBlock key={index} className="h-28" />)}
              </div>
            ) : assets.length ? (
              // Cards are never forced into a fixed-height slot — they size to
              // their own content, so nothing can be clipped by the row or the
              // panel edge. When virtualized, the spacer + offset use the
              // MEASURED row height purely to place the rendered window.
              <div style={virtualized ? { height: assets.length * rowHeight, position: 'relative' } : undefined}>
                <div
                  style={virtualized ? { position: 'absolute', top: startIndex * rowHeight, left: 0, right: 0 } : undefined}
                  className="space-y-2 px-0.5"
                >
                  {visible.map((asset, index) => (
                    <div key={asset.id} ref={index === 0 ? measureRef : undefined}>
                      <AssetCard
                        asset={asset}
                        active={asset.id === selectedId}
                        onSelect={() => onSelect(asset.id)}
                        onQueue={() => onQueue(asset.id)}
                      />
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <EmptyState label="No assets match these filters." hint="Clear the filters, or run a discovery scan to populate the estate." />
            )}
          </div>
          <div className="border-t border-white/8 px-3 py-2 text-[10px] text-white/35">
            Showing {integerFmt(Math.min(assets.length, total))} of {integerFmt(total)} matching · {integerFmt(totalUnfiltered)} discovered
          </div>
        </>
      ) : (
        /* Queue tab */
        <>
          <div className="flex flex-wrap gap-2 border-b border-white/8 p-3">
            <HeaderButton icon={ListOrdered} onClick={onApplyRecommended}>
              {busy === 'prioritize' ? 'Sorting…' : 'Apply Recommended Order'}
            </HeaderButton>
            <PrimaryButton icon={Rocket} onClick={onDispatchQueue} disabled={!queue.length || busy === 'dispatch'}>
              {busy === 'dispatch' ? 'Dispatching…' : `Migrate Queue (${queue.length})`}
            </PrimaryButton>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {queue.length ? (
              <div className="space-y-2">
                {queue.map((entry, index) => (
                  <div key={entry.assetId} className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex min-w-0 items-start gap-2">
                        <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-cyan-400/12 text-[11px] font-black text-cyan-200">{entry.sequence}</span>
                        <div className="min-w-0">
                          <button type="button" onClick={() => onSelect(entry.assetId)} className="block max-w-full truncate text-left text-xs font-bold text-white/85 hover:text-cyan-200">
                            {entry.name}
                          </button>
                          <div className="truncate text-[10px] text-white/40">{entry.type} · {entry.environment}</div>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <button type="button" aria-label="Move up" disabled={index === 0} onClick={() => move(index, -1)} className="rounded border border-white/10 p-1 text-white/50 transition hover:text-cyan-200 disabled:opacity-30">
                          <ArrowUp className="h-3 w-3" />
                        </button>
                        <button type="button" aria-label="Move down" disabled={index === queue.length - 1} onClick={() => move(index, 1)} className="rounded border border-white/10 p-1 text-white/50 transition hover:text-cyan-200 disabled:opacity-30">
                          <ArrowDown className="h-3 w-3" />
                        </button>
                        <button type="button" aria-label="Remove from queue" onClick={() => onDequeue(entry.assetId)} className="rounded border border-white/10 p-1 text-white/50 transition hover:border-red-400/50 hover:text-red-300">
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <Chip tone={levelTone(entry.priority)}>{entry.priority}</Chip>
                      <Chip tone={statusTone(entry.migrationStatus)}>{entry.migrationStatus}</Chip>
                      <Chip tone={POSTURE_TONE[entry.posture] || SLATEISH}>{entry.postureLabel}</Chip>
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[10px] text-white/45">
                      <span>Duration <span className="font-mono text-white/70">{entry.estimatedDurationLabel}</span></span>
                      <span>Readiness <span className="font-mono" style={{ color: readinessTone(entry.readinessScore) }}>{integerFmt(entry.readinessScore)}</span></span>
                      <span>Dependencies <span className="font-mono text-white/70">{integerFmt(entry.dependencies)}</span></span>
                      <span>Success <span className="font-mono" style={{ color: EMERALD }}>{percentLabel(entry.successProbabilityPct)}</span></span>
                      <span className="col-span-2 truncate">Validation <span className="text-white/70">{entry.validationState}</span></span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState label="The migration queue is empty." hint="Select an asset and choose “Queue for Migration” to build an execution sequence." />
            )}
          </div>
        </>
      )}
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Portfolio overview (shown when no asset is selected)                */
/* ------------------------------------------------------------------ */

export function AssetPortfolioOverview({
  summary,
  recommendedOrder,
  reconciliation,
  onSelect,
  onQueue,
}: {
  summary: PortfolioSummary;
  recommendedOrder: Array<{ rank: number; assetId: string; name: string; priority: string; priorityScore: number; riskScore: number; rationale: string }>;
  reconciliation: {
    snapshot: { assetsAssessed: number; quantumVulnerableAssets: number; pqcReadyAssets: number; hybridAssets: number; vulnerableComponents: number };
    portfolio: { assetsAssessed: number; quantumVulnerableAssets: number; pqcReadyAssets: number; hybridAssets: number; vulnerableComponents: number };
    aligned: boolean;
    note: string;
  };
  onSelect: (id: string) => void;
  onQueue: (id: string) => void;
}) {
  return (
    <div className="space-y-4">
      <Panel className="p-5">
        <SectionTitle suffix={<Badge color={CYAN}>Asset-centric</Badge>}>Migration Portfolio</SectionTitle>
        <p className="mb-4 text-xs leading-relaxed text-white/55">
          Select an asset on the left to review its own migration intelligence — readiness, cryptography, vulnerabilities,
          dependencies, downtime, rollback and approvals — then queue it or send it straight to Live Migration.
        </p>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Assets discovered" value={integerFmt(summary.total)} tone={CYAN} />
          <Stat label="Quantum-vulnerable" value={integerFmt(summary.quantumVulnerable)} tone={RED} />
          <Stat label="Hybrid / in progress" value={integerFmt(summary.hybrid)} tone={AMBER} />
          <Stat label="PQC-ready" value={integerFmt(summary.pqcReady)} tone={EMERALD} />
          <Stat label="Critical priority" value={integerFmt(summary.criticalPriority)} tone={ORANGE} hint={`${integerFmt(summary.highPriority)} high`} />
          <Stat label="Queued" value={integerFmt(summary.queued)} tone={VIOLET} hint={`${integerFmt(summary.completed)} completed`} />
        </div>
      </Panel>

      <Panel className="p-5">
        <SectionTitle suffix={<span className="text-[11px] text-white/40">Ranked by composite migration priority</span>}>
          Recommended Migration Order
        </SectionTitle>
        {recommendedOrder.length ? (
          <div className="space-y-2">
            {recommendedOrder.slice(0, 12).map((row) => (
              <div key={row.assetId} className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.025] p-3 transition hover:border-cyan-400/35">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-cyan-400/12 text-[11px] font-black text-cyan-200">{row.rank}</span>
                <button type="button" onClick={() => onSelect(row.assetId)} className="min-w-0 flex-1 text-left">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-xs font-bold text-white/85">{row.name}</span>
                    <Chip tone={levelTone(row.priority)}>{row.priority}</Chip>
                    <span className="font-mono text-[10px] text-white/40">score {integerFmt(row.priorityScore)}</span>
                    <span className="font-mono text-[10px]" style={{ color: riskTone(row.riskScore) }}>risk {integerFmt(row.riskScore)}</span>
                  </div>
                  <div className="truncate text-[10px] text-white/45">{row.rationale}</div>
                </button>
                <button
                  type="button"
                  onClick={() => onQueue(row.assetId)}
                  className="shrink-0 rounded-md border border-white/12 bg-black/25 px-2 py-1 text-[9px] font-black uppercase text-white/55 transition hover:border-cyan-400/50 hover:text-cyan-200"
                >
                  + Queue
                </button>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState label="No ranked assets yet." hint="Run a discovery scan so assets carry cryptographic evidence." />
        )}
      </Panel>

      <Panel className="p-5">
        <SectionTitle suffix={<Badge color={reconciliation.aligned ? EMERALD : AMBER}>{reconciliation.aligned ? 'Asset posture in sync' : 'Review posture'}</Badge>}>
          Cross-Module Data Consistency
        </SectionTitle>
        <p className="mb-3 text-[11px] leading-relaxed text-white/50">{reconciliation.note}</p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-xs">
            <thead>
              <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                <th className="pb-2.5 font-black">Metric</th>
                <th className="pb-2.5 font-black">Quantum Readiness / Reports</th>
                <th className="pb-2.5 font-black">Asset Portfolio</th>
                <th className="pb-2.5 font-black">Match</th>
              </tr>
            </thead>
            <tbody>
              {([
                ['Quantum-vulnerable assets', reconciliation.snapshot.quantumVulnerableAssets, reconciliation.portfolio.quantumVulnerableAssets, true],
                ['Hybrid / in-progress assets', reconciliation.snapshot.hybridAssets, reconciliation.portfolio.hybridAssets, true],
                ['PQC-ready assets', reconciliation.snapshot.pqcReadyAssets, reconciliation.portfolio.pqcReadyAssets, true],
                ['Assets assessed', reconciliation.snapshot.assetsAssessed, reconciliation.portfolio.assetsAssessed, false],
                ['Quantum-vulnerable components', reconciliation.snapshot.vulnerableComponents, reconciliation.portfolio.vulnerableComponents, false],
              ] as Array<[string, number, number, boolean]>).map(([label, left, right, strict]) => (
                <tr key={label} className="border-b border-white/5 text-white/70">
                  <td className="py-2 font-medium text-white/82">{label}</td>
                  <td className="py-2 font-mono">{integerFmt(left)}</td>
                  <td className="py-2 font-mono">{integerFmt(right)}</td>
                  <td className="py-2">
                    {left === right ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-black" style={{ color: EMERALD }}>
                        <CheckCircle2 className="h-3 w-3" /> IDENTICAL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-black" style={{ color: strict ? RED : AMBER }}>
                        <AlertTriangle className="h-3 w-3" /> {integerFmt(Math.abs(left - right))} {strict ? 'apart' : 'different basis'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[10px] leading-snug text-white/35">
          The three posture rows are the strict invariant — the same engine derives them for both columns, so they must be
          identical. “Assets assessed” and component counts are measured on two bases (exact tenant-wide count and
          scanner-expanded CBOM view versus rows bound to individual assets); both figures are shown rather than silently
          reconciled.
        </p>
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Asset dossier                                                       */
/* ------------------------------------------------------------------ */

function DossierPanel({ title, icon: Icon, suffix, children, className }: { title: string; icon?: LucideIcon; suffix?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <Panel className={`p-5 ${className || ''}`}>
      <SectionTitle suffix={suffix}>
        <span className="inline-flex items-center gap-2">
          {Icon ? <Icon className="h-4 w-4 text-cyan-300/70" /> : null}
          {title}
        </span>
      </SectionTitle>
      {children}
    </Panel>
  );
}

export function AssetDossierView({
  asset,
  position,
  loading,
  changedFields,
  onQueue,
  onDispatch,
  onClear,
  busy,
}: {
  asset: AssetDossier;
  position: { recommendedRank: number | null; totalRanked: number; rationale: string; riskPercentile: number } | null;
  loading: boolean;
  changedFields: string[];
  onQueue: () => void;
  onDispatch: () => void;
  onClear: () => void;
  busy: string | null;
}) {
  const changed = useMemo(() => new Set(changedFields), [changedFields]);
  const postureTone = POSTURE_TONE[asset.posture] || SLATEISH;

  return (
    <div className={`space-y-4 transition-opacity duration-200 ${loading ? 'opacity-60' : 'opacity-100'}`}>
      {/* Identity + primary actions */}
      <Panel className="overflow-hidden">
        <div className="border-b border-white/8 bg-gradient-to-r from-cyan-500/[0.07] via-transparent to-transparent p-5">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate text-xl font-semibold text-white">{asset.name}</h2>
                <Badge color={levelTone(asset.priority)}>{asset.priority} priority</Badge>
                <Badge color={postureTone}>{asset.postureLabel}</Badge>
                <Badge color={statusTone(asset.migrationStatus)}>{asset.migrationStatus}</Badge>
                {asset.internetFacing ? <Badge color={ORANGE}>Internet-facing</Badge> : null}
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-white/50">
                <span className="inline-flex items-center gap-1"><Boxes className="h-3 w-3" />{asset.type}</span>
                <span className="inline-flex items-center gap-1"><Globe className="h-3 w-3" />{asset.hostname}</span>
                <span className="inline-flex items-center gap-1"><Layers className="h-3 w-3" />{asset.environment}</span>
                <span className="inline-flex items-center gap-1"><UserCheck className="h-3 w-3" />{asset.owner}</span>
                <span className="inline-flex items-center gap-1"><ShieldAlert className="h-3 w-3" />Criticality {asset.businessCriticality}</span>
                {asset.region && asset.region !== 'Evidence Not Available' ? <span>{asset.region}</span> : null}
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-white/35">
                <span className="inline-flex items-center gap-1 font-mono"><Fingerprint className="h-3 w-3" />{asset.id}</span>
                <span>Last evidence {longDate(asset.lastEvidenceAt)}</span>
                {position?.recommendedRank ? <span>Recommended rank #{position.recommendedRank} of {position.totalRanked}</span> : null}
                {asset.tags.map((tag) => <Chip key={tag} tone={TEAL}>{tag}</Chip>)}
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <HeaderButton icon={X} onClick={onClear}>Clear selection</HeaderButton>
              <HeaderButton icon={ListOrdered} onClick={onQueue} active={asset.queued}>
                {asset.queued ? 'In queue' : 'Queue for Migration'}
              </HeaderButton>
              <PrimaryButton icon={Rocket} onClick={onDispatch} disabled={busy === 'dispatch' || !asset.hasEvidence}>
                {busy === 'dispatch' ? 'Sending…' : 'Send to Live Migration'}
              </PrimaryButton>
            </div>
          </div>
          {!asset.hasEvidence ? (
            <div className="mt-3 rounded-lg border border-amber-400/25 bg-amber-400/[0.07] px-3 py-2 text-[11px] text-amber-100/90">
              This asset has been discovered but carries no cryptographic evidence yet. Run a PQC discovery scan before planning its migration.
            </div>
          ) : null}
          {changedFields.length ? (
            <div className="mt-3 inline-flex items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-400/[0.08] px-3 py-1.5 text-[11px] text-cyan-100">
              <Radio className="h-3 w-3" />
              Live update received — {changedFields.length} value{changedFields.length === 1 ? '' : 's'} changed while you were reviewing.
            </div>
          ) : null}
        </div>

        {/* Headline scores */}
        <div className="grid grid-cols-1 gap-4 p-5 md:grid-cols-[auto_1fr]">
          <div className="flex items-center gap-5">
            <Ring value={asset.readinessScore} color={readinessTone(asset.readinessScore)} size={110} stroke={11}>
              <div>
                <div className="text-2xl font-semibold text-white">{integerFmt(asset.readinessScore)}</div>
                <div className="text-[9px] uppercase tracking-wide text-white/45">Readiness</div>
              </div>
            </Ring>
            <div className="space-y-1">
              <div className="text-sm font-bold" style={{ color: readinessTone(asset.readinessScore) }}>{asset.readinessLevel}</div>
              <div className="text-[11px] text-white/45">Migration risk</div>
              <div className="text-lg font-semibold" style={{ color: riskTone(asset.riskAnalysis.overall) }}>
                {integerFmt(asset.riskAnalysis.overall)}<span className="text-[11px] text-white/35">/100 {asset.riskAnalysis.overallLevel}</span>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
            <Stat label="Asset risk" value={integerFmt(asset.riskScore)} tone={riskTone(asset.riskScore)} hint={asset.riskLevel} highlight={changed.has('riskScore')} />
            <Stat label="HNDL exposure" value={integerFmt(asset.hndlScore)} tone={riskTone(asset.hndlScore)} hint={asset.hndlLevel} highlight={changed.has('hndlScore')} />
            <Stat label="Priority score" value={integerFmt(asset.priorityScore)} tone={levelTone(asset.priority)} hint={asset.priority} highlight={changed.has('priorityScore')} />
            <Stat label="Success probability" value={percentLabel(asset.successProbabilityPct)} tone={EMERALD} hint="Modelled outcome" highlight={changed.has('successProbabilityPct')} />
            <Stat label="Estimated effort" value={asset.estimatedDurationLabel} tone={BLUE} hint={`${integerFmt(asset.estimatedEffortHours)} engineer-hours`} />
            <Stat label="Estimated downtime" value={asset.estimatedDowntime} tone={GOLD} />
            <Stat label="Crypto components" value={integerFmt(asset.componentCount)} tone={CYAN} hint={`${integerFmt(asset.vulnerableComponentCount)} vulnerable · ${integerFmt(asset.pqcComponentCount)} PQC`} highlight={changed.has('componentCount') || changed.has('vulnerableComponentCount')} />
            <Stat label="Migration status" value={asset.migrationStatus} tone={statusTone(asset.migrationStatus)} hint={`${integerFmt(asset.migrationProgressPct)}% complete`} highlight={changed.has('migrationStatus')} />
          </div>
        </div>
      </Panel>

      {/* Why this priority */}
      <DossierPanel title="Why This Asset Ranks Here" icon={TrendingUp} suffix={<Badge color={levelTone(asset.priority)}>{integerFmt(asset.priorityScore)}/100</Badge>}>
        <p className="mb-3 text-[11px] text-white/50">{position?.rationale || 'Composite of the enterprise prioritisation factors below.'}</p>
        <div className="space-y-2">
          {asset.priorityFactors.map((factor) => (
            <div key={factor.key} className="grid grid-cols-[1fr_auto] items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
              <div className="min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[11px] font-bold text-white/80">{factor.label}</span>
                  <span className="shrink-0 font-mono text-[10px] text-white/40">weight {factor.weight}%</span>
                </div>
                <div className="mt-1"><MiniBar value={factor.score} tone={riskTone(factor.score)} /></div>
                <div className="mt-1 truncate text-[10px] text-white/40">{factor.evidence}</div>
              </div>
              <div className="text-right">
                <div className="font-mono text-sm font-semibold" style={{ color: riskTone(factor.score) }}>{integerFmt(factor.score)}</div>
                <div className="text-[9px] text-white/35">+{factor.contribution.toFixed(1)}</div>
              </div>
            </div>
          ))}
        </div>
      </DossierPanel>

      {/* Cryptography */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="Current Cryptography & PQC Targets" icon={KeyRound} className="xl:col-span-7" suffix={<span className="text-[11px] text-white/40">{asset.algorithms.length} algorithm(s)</span>}>
          {asset.algorithms.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Algorithm</th>
                    <th className="pb-2.5 font-black">Class</th>
                    <th className="pb-2.5 font-black">Seen</th>
                    <th className="pb-2.5 font-black">PQC Target</th>
                    <th className="pb-2.5 font-black">Standard</th>
                  </tr>
                </thead>
                <tbody>
                  {asset.algorithms.map((algorithm) => {
                    const tone = algorithm.classification === 'vulnerable' ? RED : algorithm.classification === 'pqc' ? EMERALD : algorithm.classification === 'hybrid' ? AMBER : SLATEISH;
                    return (
                      <tr key={algorithm.algorithm} className="border-b border-white/5 align-top text-white/70">
                        <td className="py-2 font-medium text-white/85">
                          {algorithm.algorithm}
                          {algorithm.keySizes.length ? <span className="ml-1 font-mono text-[10px] text-white/40">{algorithm.keySizes.join('/')}-bit</span> : null}
                        </td>
                        <td className="py-2"><Chip tone={tone}>{algorithm.classification}</Chip></td>
                        <td className="py-2 font-mono">{integerFmt(algorithm.instances)}</td>
                        <td className="py-2 text-[11px]" style={{ color: algorithm.classification === 'pqc' ? EMERALD : CYAN }}>{algorithm.target}</td>
                        <td className="py-2 text-[10px] text-white/45">{algorithm.standard}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No cryptographic algorithms resolved for this asset." hint="Scan the asset to build its cryptographic bill of materials." />
          )}
        </DossierPanel>

        <DossierPanel title="Quantum Vulnerabilities" icon={ShieldAlert} className="xl:col-span-5" suffix={<Badge color={severityColor('critical')}>{integerFmt(asset.severityCounts.critical + asset.severityCounts.high)} critical/high</Badge>}>
          <div className="mb-3 grid grid-cols-4 gap-2">
            {([
              ['Critical', asset.severityCounts.critical, RED],
              ['High', asset.severityCounts.high, ORANGE],
              ['Medium', asset.severityCounts.medium, GOLD],
              ['Low', asset.severityCounts.low, GREEN],
            ] as Array<[string, number, string]>).map(([label, value, tone]) => (
              <div key={label} className="rounded-lg border border-white/8 bg-white/[0.02] p-2 text-center">
                <div className="text-lg font-semibold" style={{ color: tone }}>{integerFmt(value)}</div>
                <div className="text-[9px] uppercase tracking-wide text-white/40">{label}</div>
              </div>
            ))}
          </div>
          {asset.findings.length ? (
            <div className="max-h-[320px] space-y-2 overflow-y-auto pr-1">
              {asset.findings.map((finding) => {
                const tone = severityColor(finding.severity);
                return (
                  <div key={finding.id} className="rounded-lg border border-white/8 bg-white/[0.02] p-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-[11px] font-bold text-white/85">{finding.title}</span>
                      <Chip tone={tone}>{finding.severity}</Chip>
                    </div>
                    <div className="mt-1 line-clamp-2 text-[10px] text-white/45">{finding.description}</div>
                    <div className="mt-1 flex items-center justify-between text-[9px] text-white/30">
                      <span>{finding.source}{finding.instances > 1 ? ` · ${finding.instances} instances` : ''}</span>
                      <span>{longDate(finding.detectedAt)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState label="No quantum vulnerabilities recorded for this asset." />
          )}
        </DossierPanel>
      </section>

      {/* Recommendations + risk analysis */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="PQC Recommendations" icon={Sparkles} className="xl:col-span-7">
          <div className="space-y-2.5">
            {asset.recommendations.map((recommendation) => {
              const tone = severityColor(recommendation.severity);
              return (
                <div key={recommendation.id} className="rounded-lg border border-white/8 bg-white/[0.025] p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-bold text-white/85">{recommendation.title}</span>
                    <div className="flex items-center gap-1.5">
                      <Chip tone={tone}>{recommendation.severity}</Chip>
                      <Chip tone={SLATEISH}>{recommendation.effort} effort</Chip>
                    </div>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-white/55">{recommendation.detail}</p>
                  <div className="mt-1 text-[10px]" style={{ color: CYAN }}>{recommendation.standard}</div>
                </div>
              );
            })}
          </div>
        </DossierPanel>

        <DossierPanel title="Asset Risk Analysis" icon={Gauge} className="xl:col-span-5" suffix={<Badge color={riskTone(asset.riskAnalysis.overall)}>{asset.riskAnalysis.overallLevel}</Badge>}>
          <div className="space-y-2">
            {asset.riskAnalysis.categories.map((category) => (
              <div key={category.key} className="grid grid-cols-[1fr_auto] items-center gap-2 text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="w-28 shrink-0 truncate text-white/65">{category.label}</span>
                  <div className="flex-1"><MiniBar value={category.score} tone={riskTone(category.score)} /></div>
                </div>
                <span className="font-mono text-white/70">{integerFmt(category.score)}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-white/50">{asset.riskAnalysis.explanation}</p>
        </DossierPanel>
      </section>

      {/* Certificates + TLS */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="Certificates" icon={Lock} className="xl:col-span-7" suffix={<span className="text-[11px] text-white/40">{asset.certificates.length}</span>}>
          {asset.certificates.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Certificate</th><th className="pb-2.5 font-black">Algorithm</th>
                    <th className="pb-2.5 font-black">Issuer</th><th className="pb-2.5 font-black">Expires</th><th className="pb-2.5 font-black">PQC</th>
                  </tr>
                </thead>
                <tbody>
                  {asset.certificates.map((certificate) => {
                    const expiryTone = certificate.daysToExpiry === null ? SLATEISH : certificate.daysToExpiry < 0 ? RED : certificate.daysToExpiry <= 30 ? ORANGE : certificate.daysToExpiry <= 90 ? GOLD : GREEN;
                    return (
                      <tr key={certificate.id} className="border-b border-white/5 text-white/70">
                        <td className="max-w-[180px] truncate py-2 font-medium text-white/85">{certificate.name}</td>
                        <td className="py-2">{certificate.algorithm}{certificate.keySize ? <span className="ml-1 font-mono text-[10px] text-white/40">{certificate.keySize}</span> : null}</td>
                        <td className="max-w-[140px] truncate py-2">{certificate.issuer}</td>
                        <td className="py-2 font-mono" style={{ color: expiryTone }}>
                          {certificate.daysToExpiry === null ? '—' : certificate.daysToExpiry < 0 ? 'Expired' : `${integerFmt(certificate.daysToExpiry)}d`}
                        </td>
                        <td className="py-2"><Chip tone={certificate.quantumSafe ? EMERALD : RED}>{certificate.quantumSafe ? 'Quantum-safe' : 'Classical'}</Chip></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No certificates bound to this asset." hint="Connect the PKI inventory to score certificate lifecycle risk." />
          )}
        </DossierPanel>

        <DossierPanel title="TLS / Transport Configuration" icon={Network} className="xl:col-span-5">
          <p className="mb-3 text-[11px] text-white/55">{asset.tlsConfiguration.summary}</p>
          <div className="space-y-2.5">
            {([
              ['Protocols', asset.tlsConfiguration.protocols],
              ['Key exchange', asset.tlsConfiguration.keyExchange],
              ['Cipher suites', asset.tlsConfiguration.cipherSuites],
            ] as Array<[string, string[]]>).map(([label, values]) => (
              <div key={label}>
                <div className="text-[9px] font-black uppercase tracking-wide text-white/40">{label}</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {values.length ? values.map((value) => (
                    <span key={value} className="rounded border border-white/10 bg-black/25 px-1.5 py-0.5 font-mono text-[10px] text-white/60">{value}</span>
                  )) : <span className="text-[10px] text-white/30">Not observed</span>}
                </div>
              </div>
            ))}
            <div className="rounded-lg border border-white/8 bg-white/[0.02] p-2.5 text-[11px] text-white/60">{asset.tlsConfiguration.forwardSecrecy}</div>
          </div>
        </DossierPanel>
      </section>

      {/* Dependencies + business impact */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="Dependencies & Blast Radius" icon={Network} className="xl:col-span-7" suffix={<Badge color={asset.blastRadius > 6 ? ORANGE : TEAL}>{integerFmt(asset.blastRadius)} relationships</Badge>}>
          {asset.dependencies.length ? (
            <div className="max-h-[280px] space-y-2 overflow-y-auto pr-1">
              {asset.dependencies.map((dependency) => (
                <div key={`${dependency.direction}-${dependency.id}`} className="flex items-center gap-3 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                  <Chip tone={dependency.direction === 'upstream' ? VIOLET : BLUE}>{dependency.direction}</Chip>
                  <span className="min-w-0 flex-1 truncate text-[11px] font-medium text-white/80">{dependency.name}</span>
                  <span className="text-[10px] text-white/40">{dependency.relationship}</span>
                  <Chip tone={POSTURE_TONE[dependency.posture] || SLATEISH}>{dependency.posture}</Chip>
                  <span className="font-mono text-[10px]" style={{ color: riskTone(dependency.riskScore) }}>{integerFmt(dependency.riskScore)}</span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="No trust relationships recorded for this asset." hint="Dependency mapping populates from the trust fabric discovery." />
          )}
        </DossierPanel>

        <DossierPanel title="Business Impact" icon={TrendingUp} className="xl:col-span-5">
          <div className="grid grid-cols-2 gap-2.5">
            <Stat label="Revenue impact" value={asset.businessImpact.revenueImpact} tone={levelTone(asset.businessImpact.revenueImpact)} />
            <Stat label="Operational impact" value={asset.businessImpact.operationalImpact} tone={levelTone(asset.businessImpact.operationalImpact)} />
            <Stat label="Compliance impact" value={asset.businessImpact.complianceImpact} tone={levelTone(asset.businessImpact.complianceImpact)} />
            <Stat label="Dependent systems" value={integerFmt(asset.businessImpact.dependents)} tone={VIOLET} />
            <Stat label="Customer-facing" value={asset.businessImpact.customerFacing ? 'Yes' : 'No'} tone={asset.businessImpact.customerFacing ? ORANGE : GREEN} />
            <Stat label="Business criticality" value={asset.businessCriticality} tone={levelTone(asset.businessCriticality)} />
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-white/50">{asset.businessImpact.summary}</p>
        </DossierPanel>
      </section>

      {/* Compatibility + rollback + approvals */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="Compatibility Analysis" icon={ShieldCheck} className="xl:col-span-4" suffix={<Badge color={asset.compatibility.score >= 75 ? EMERALD : asset.compatibility.score >= 50 ? GOLD : RED}>{asset.compatibility.level}</Badge>}>
          <div className="mb-3 flex items-center gap-3">
            <Ring value={asset.compatibility.score} color={asset.compatibility.score >= 75 ? EMERALD : asset.compatibility.score >= 50 ? GOLD : RED} size={72} stroke={8}>
              <div className="text-base font-semibold text-white">{integerFmt(asset.compatibility.score)}</div>
            </Ring>
            <div className="text-[11px] text-white/50">Hybrid interoperability confidence for the target PQC stack.</div>
          </div>
          <ul className="space-y-1.5">
            {asset.compatibility.notes.map((note) => (
              <li key={note} className="flex gap-2 text-[11px] leading-relaxed text-white/55">
                <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-cyan-300/60" />{note}
              </li>
            ))}
          </ul>
        </DossierPanel>

        <DossierPanel title="Rollback Strategy" icon={Undo2} className="xl:col-span-4" suffix={<Badge color={asset.rollbackStrategy.available ? EMERALD : SLATEISH}>{asset.rollbackStrategy.available ? 'Available' : 'Unavailable'}</Badge>}>
          <div className="mb-2 flex flex-wrap items-center gap-2 text-[11px]">
            <span className="font-bold text-white/80">{asset.rollbackStrategy.strategy}</span>
            <Chip tone={CYAN}>{asset.rollbackStrategy.recoveryObjective}</Chip>
          </div>
          <ol className="space-y-1.5">
            {asset.rollbackStrategy.steps.map((step, index) => (
              <li key={step} className="flex gap-2 text-[11px] leading-relaxed text-white/55">
                <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded bg-white/8 text-[9px] font-black text-white/60">{index + 1}</span>
                {step}
              </li>
            ))}
          </ol>
          <div className="mt-3 flex items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2 text-[11px] text-white/55">
            <RotateCcw className="h-3.5 w-3.5 shrink-0 text-cyan-300/70" />
            Estimated downtime: <span className="font-semibold text-white/75">{asset.estimatedDowntime}</span>
          </div>
        </DossierPanel>

        <DossierPanel title="Required Approvals" icon={UserCheck} className="xl:col-span-4" suffix={<Badge color={AMBER}>{asset.requiredApprovals.filter((a) => a.required).length} required</Badge>}>
          <div className="space-y-2">
            {asset.requiredApprovals.map((approval) => (
              <div key={approval.role} className="rounded-lg border border-white/8 bg-white/[0.02] p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-bold text-white/85">{approval.role}</span>
                  <Chip tone={approval.required ? AMBER : SLATEISH}>{approval.required ? 'Required' : 'Advisory'}</Chip>
                </div>
                <div className="mt-1 text-[10px] leading-relaxed text-white/45">{approval.reason}</div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[10px] leading-snug text-white/35">
            Sign-off is recorded through the planner's Approval Workflow, which writes to the same migration plan the workflow rail reads.
          </p>
        </DossierPanel>
      </section>

      {/* Timeline + compliance */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel title="Asset Migration Timeline" icon={CalendarClock} className="xl:col-span-7" suffix={<span className="text-[11px] text-white/40">{asset.estimatedDurationLabel} total</span>}>
          {asset.timeline.length ? (
            <div className="space-y-2">
              {asset.timeline.map((phase, index) => (
                <div key={phase.phase} className="grid grid-cols-[120px_1fr_auto] items-center gap-3 rounded-lg border border-white/8 bg-white/[0.025] p-3">
                  <div>
                    <div className="text-xs font-bold text-white/85">{index + 1}. {phase.phase}</div>
                    <div className="text-[10px] text-white/40">{phase.owner}</div>
                  </div>
                  <div>
                    <MiniBar value={(phase.durationHours / Math.max(1, asset.estimatedEffortHours)) * 100} tone={BLUE} />
                    <div className="mt-1 truncate text-[10px] text-white/40">{phase.description}</div>
                  </div>
                  <span className="shrink-0 font-mono text-[11px] text-white/60"><Clock className="mr-1 inline h-3 w-3" />{integerFmt(phase.durationHours)}h</span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState label="No timeline available." hint="A timeline is generated once the asset carries cryptographic evidence." />
          )}
        </DossierPanel>

        <DossierPanel title="Compliance Impact" icon={ShieldCheck} className="xl:col-span-5">
          <div className="space-y-2">
            {asset.compliance.map((row) => {
              const tone = row.status === 'aligned' ? GREEN : row.status === 'partial' ? GOLD : row.status === 'gap' ? RED : SLATEISH;
              return (
                <div key={`${row.framework}-${row.control}`} className="rounded-lg border border-white/8 bg-white/[0.02] p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[11px] font-bold text-white/85">{row.framework}</span>
                    <Chip tone={tone}>{row.status}</Chip>
                  </div>
                  <div className="text-[10px] text-white/45">{row.control}</div>
                  <div className="mt-1 text-[10px] leading-relaxed text-white/40">{row.detail}</div>
                </div>
              );
            })}
          </div>
        </DossierPanel>
      </section>

      {/* Execution + evidence */}
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <DossierPanel
          title="Execution & Validation"
          icon={Rocket}
          className="xl:col-span-7"
          suffix={
            <Badge color={asset.validation.validated ? EMERALD : asset.validation.cutoverBlocked ? RED : AMBER}>
              {asset.validation.validated ? 'Validated' : asset.validation.cutoverBlocked ? 'Cutover blocked' : 'No blockers · not yet validated'}
            </Badge>
          }
        >
          <div className="mb-3 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            <Stat label="Migration jobs" value={integerFmt(asset.jobs.length)} tone={CYAN} />
            <Stat label="Progress" value={percentLabel(asset.migrationProgressPct)} tone={statusTone(asset.migrationStatus)} />
            <Stat label="Validation records" value={integerFmt(asset.validation.records)} tone={VIOLET} hint={asset.validation.lastStatus} />
            <Stat label="Last validated" value={asset.validation.lastAt ? longDate(asset.validation.lastAt) : '—'} tone={TEAL} />
          </div>
          <p className="mb-3 text-[11px] text-white/50">
            {asset.migrationStatusDetail}
            {asset.validation.cutoverBlocked ? <span className="ml-1 font-semibold" style={{ color: RED }}>{asset.validation.blockerReason}</span> : null}
            {!asset.validation.validated && !asset.validation.cutoverBlocked
              ? ' No cutover blockers are open, but this asset has not produced a passing validation record yet.'
              : null}
          </p>
          {asset.jobs.length ? (
            <div className="space-y-2">
              {asset.jobs.map((job) => {
                const tone = statusTone(job.status);
                return (
                  <div key={job.id} className="grid grid-cols-[1fr_110px_auto] items-center gap-3 rounded-lg border border-white/8 bg-white/[0.025] p-2.5 text-xs">
                    <div className="min-w-0">
                      <div className="truncate font-medium text-white/80">{job.jobType}</div>
                      <div className="truncate text-[10px] text-white/40">→ {job.targetAlgorithm}</div>
                    </div>
                    <MiniBar value={job.progress} tone={tone} />
                    <Chip tone={tone}>{job.status}</Chip>
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState label="No migration jobs for this asset yet." hint="Send the asset to Live Migration to create its execution jobs." />
          )}
        </DossierPanel>

        <DossierPanel title="Evidence & Data Lineage" icon={Fingerprint} className="xl:col-span-5">
          <p className="mb-3 text-[11px] leading-relaxed text-white/55">{asset.evidence.note}</p>
          <div className="grid grid-cols-2 gap-2.5">
            <Stat label="CBOM components" value={integerFmt(asset.evidence.components)} tone={CYAN} />
            <Stat label="Scan findings" value={integerFmt(asset.evidence.scanResults)} tone={ORANGE} />
            <Stat label="Exposures" value={integerFmt(asset.evidence.exposures)} tone={RED} />
            <Stat label="Runtime events" value={integerFmt(asset.evidence.runtimeEvents)} tone={VIOLET} />
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {asset.evidence.sources.length ? asset.evidence.sources.map((source) => <Chip key={source} tone={TEAL}>{source}</Chip>) : <span className="text-[10px] text-white/30">No evidence sources</span>}
          </div>
          <p className="mt-3 text-[10px] leading-snug text-white/35">
            Asset ID, risk score, posture, algorithms, certificates and dependencies on this page are the identical records the
            Scanner, Assets inventory, Quantum Readiness, Reports, Governance and Sophia AI Copilot read.
          </p>
        </DossierPanel>
      </section>
    </div>
  );
}

export function AssetDossierSkeleton() {
  return (
    <div className="space-y-4">
      <SkeletonBlock className="h-64" />
      <SkeletonBlock className="h-56" />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <SkeletonBlock className="h-72 xl:col-span-7" />
        <SkeletonBlock className="h-72 xl:col-span-5" />
      </div>
    </div>
  );
}
