'use client';

import { useEffect, useMemo, useState, type ElementType, type ReactNode } from 'react';
import {
  Activity,
  ArrowRight,
  Boxes,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  Clock,
  Crosshair,
  Database,
  Globe2,
  HardDriveDownload,
  KeyRound,
  Layers,
  Lock,
  Network,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Target,
  TrendingUp,
} from 'lucide-react';
import { useHarvestNow, type CryptoClass } from '@/hooks/use-harvest-now';

/* ------------------------------------------------------------------ */
/* Formatters & tone helpers                                          */
/* ------------------------------------------------------------------ */
const fmt = (n: number) => new Intl.NumberFormat('en-US').format(Math.max(0, Math.round(Number(n) || 0)));
const pct = (n: number) => `${Math.max(0, Math.min(100, Math.round(Number(n) || 0)))}%`;
const tbFmt = (n: number) => {
  const v = Math.max(0, Number(n) || 0);
  if (v >= 1024) return `${(v / 1024).toFixed(2)} PB`;
  return `${v.toFixed(2)} TB`;
};
const utcClock = (value: unknown) => {
  const d = value ? new Date(String(value)) : new Date();
  return (Number.isFinite(d.getTime()) ? d : new Date()).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC', timeZoneName: 'short' });
};

type Tone = 'red' | 'amber' | 'green' | 'cyan' | 'muted';

function classTone(c: CryptoClass): Tone {
  if (c === 'vulnerable') return 'red';
  if (c === 'hybrid') return 'amber';
  if (c === 'safe') return 'green';
  return 'muted';
}
function levelTone(level: string): Tone {
  const l = (level || '').toLowerCase();
  if (/critical/.test(l)) return 'red';
  if (/high|elevated/.test(l)) return 'amber';
  if (/medium|moderate|guarded/.test(l)) return 'cyan';
  if (/low|none|minimal|quantum safe|safe/.test(l)) return 'green';
  return 'muted';
}
const TONE_TEXT: Record<Tone, string> = {
  red: 'text-red-300', amber: 'text-amber-300', green: 'text-emerald-300', cyan: 'text-cyan-300', muted: 'text-white/55',
};
const TONE_DOT: Record<Tone, string> = {
  red: 'bg-red-400 shadow-[0_0_10px_rgba(248,113,113,0.9)]',
  amber: 'bg-amber-400 shadow-[0_0_10px_rgba(251,191,36,0.85)]',
  green: 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.85)]',
  cyan: 'bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.85)]',
  muted: 'bg-white/30',
};
const TONE_BADGE: Record<Tone, string> = {
  red: 'border-red-500/50 bg-red-500/12 text-red-300',
  amber: 'border-amber-400/50 bg-amber-500/12 text-amber-300',
  green: 'border-emerald-400/50 bg-emerald-500/12 text-emerald-300',
  cyan: 'border-cyan-400/45 bg-cyan-500/12 text-cyan-300',
  muted: 'border-white/15 bg-white/5 text-white/55',
};
const TONE_BAR: Record<Tone, string> = {
  red: 'bg-gradient-to-r from-red-500 to-red-400',
  amber: 'bg-gradient-to-r from-amber-500 to-amber-400',
  green: 'bg-gradient-to-r from-emerald-500 to-emerald-400',
  cyan: 'bg-gradient-to-r from-cyan-500 to-cyan-400',
  muted: 'bg-white/25',
};
const TONE_STROKE: Record<Tone, string> = { red: '#f87171', amber: '#fbbf24', green: '#34d399', cyan: '#22d3ee', muted: '#64748b' };

const PANEL = 'hndl-panel group relative overflow-hidden rounded-lg border border-cyan-400/15 bg-[#05080f]/75 shadow-[inset_0_1px_0_rgba(255,255,255,0.05),0_0_22px_rgba(8,16,30,0.55)] backdrop-blur-xl transition-all duration-300 hover:border-cyan-400/40';

/* ------------------------------------------------------------------ */
/* Presentational primitives                                          */
/* ------------------------------------------------------------------ */
function SectionHeader({ icon: Icon, children, action, tone = 'cyan' }: { icon: ElementType; children: string; action?: string; tone?: Tone }) {
  return (
    <div className="relative z-10 mb-2.5 flex items-center justify-between gap-3 border-b border-white/8 pb-2">
      <h2 className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.16em] text-white/80">
        <Icon className={`h-3.5 w-3.5 ${TONE_TEXT[tone]}`} />
        {children}
      </h2>
      {action && <span className={`text-[9px] font-black uppercase tracking-[0.16em] ${TONE_TEXT[tone]}`}>{action}</span>}
    </div>
  );
}

function Bar({ value, tone, label, right }: { value: number; tone: Tone; label?: string; right?: string }) {
  return (
    <div className="space-y-1">
      {(label || right) && (
        <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.08em] text-white/55">
          <span className="truncate">{label}</span>
          <span className={TONE_TEXT[tone]}>{right}</span>
        </div>
      )}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
        <div className={`h-full rounded-full ${TONE_BAR[tone]}`} style={{ width: pct(value) }} />
      </div>
    </div>
  );
}

function Ring({ value, tone, label, sub, size = 116 }: { value: number; tone: Tone; label: string; sub?: string; size?: number }) {
  const r = (size - 14) / 2;
  const circ = 2 * Math.PI * r;
  const safe = Math.max(0, Math.min(100, value));
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="7" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={TONE_STROKE[tone]} strokeWidth="7" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={circ - (safe / 100) * circ} style={{ filter: `drop-shadow(0 0 6px ${TONE_STROKE[tone]}88)`, transition: 'stroke-dashoffset 600ms ease' }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <p className={`text-2xl font-black ${TONE_TEXT[tone]}`}>{Math.round(safe)}<span className="text-xs">%</span></p>
          <p className="mt-0.5 text-[9px] font-black uppercase tracking-[0.14em] text-white/50">{label}</p>
          {sub && <p className="text-[9px] font-bold text-white/40">{sub}</p>}
        </div>
      </div>
    </div>
  );
}

function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-black uppercase tracking-[0.1em] ${TONE_BADGE[tone]}`}>{children}</span>;
}

function Stat({ label, value, tone = 'cyan', sub }: { label: string; value: string | number; tone?: Tone; sub?: string }) {
  return (
    <div className="rounded-md border border-white/8 bg-black/30 px-3 py-2">
      <p className="text-[9px] font-black uppercase tracking-[0.14em] text-white/45">{label}</p>
      <p className={`mt-0.5 text-lg font-black ${TONE_TEXT[tone]}`}>{value}</p>
      {sub && <p className="text-[9px] font-bold text-white/40">{sub}</p>}
    </div>
  );
}

function EmptyState({ children }: { children: string }) {
  return (
    <div className="grid place-items-center rounded-md border border-dashed border-white/12 bg-black/20 px-4 py-6 text-center">
      <div>
        <Database className="mx-auto h-5 w-5 text-white/30" />
        <p className="mt-2 text-[10px] font-bold uppercase tracking-[0.12em] text-white/45">{children}</p>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Next-escalation live countdown (to next UTC hour boundary)         */
/* ------------------------------------------------------------------ */
function useEscalationCountdown() {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);
  const nextHour = Math.ceil(now / 3_600_000) * 3_600_000;
  const remaining = Math.max(0, nextHour - now);
  const totalSeconds = Math.floor(remaining / 1000);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return [h, m, s].map((p) => String(p).padStart(2, '0')).join(':');
}

/* ================================================================== */
/* Page                                                               */
/* ================================================================== */
export default function HarvestNow() {
  const { data, state, error, sseConnected, refresh } = useHarvestNow();
  const countdown = useEscalationCountdown();
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const banner = data.banner;
  const bannerTone = levelTone(banner.threatLevel);
  const alert = data.hasData && (banner.threatLevel === 'Critical' || banner.threatLevel === 'High');

  const selected = useMemo(() => data.exposureGraph.nodes.find((n) => n.id === selectedNode) || null, [data.exposureGraph.nodes, selectedNode]);

  const loading = state === 'loading' && !data.hasData;

  return (
    <div className="hndl-shell min-h-full bg-[var(--qg-dashboard-bg)] p-3 text-[var(--qg-dashboard-text)] md:p-4">
      <style>{`
        .hndl-shell {
          background:
            radial-gradient(circle at 16% 6%, rgba(239,68,68,0.16), transparent 26%),
            radial-gradient(circle at 84% 4%, rgba(34,211,238,0.12), transparent 24%),
            radial-gradient(circle at 50% 120%, rgba(34,211,238,0.08), transparent 40%),
            linear-gradient(180deg, #01030a 0%, #04060f 48%, #01030a 100%);
        }
        .hndl-panel::before {
          content: ""; position: absolute; inset: 0; pointer-events: none;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.05), transparent 20%, transparent 80%, rgba(34,211,238,0.06)),
            repeating-linear-gradient(90deg, rgba(255,255,255,0.018) 0 1px, transparent 1px 44px);
          opacity: 0.7;
        }
        .hndl-grid {
          background-image:
            linear-gradient(rgba(34,211,238,0.06) 1px, transparent 1px),
            linear-gradient(90deg, rgba(34,211,238,0.06) 1px, transparent 1px);
          background-size: 30px 30px;
        }
        .hndl-grid-red {
          background-image:
            linear-gradient(rgba(239,68,68,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(239,68,68,0.08) 1px, transparent 1px);
        }
        .hndl-hero-alert { animation: hndlRedPulse 2.6s ease-in-out infinite; }
        @keyframes hndlRedPulse {
          0%,100% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 0 26px rgba(239,68,68,0.18); }
          50% { box-shadow: inset 0 1px 0 rgba(255,255,255,0.12), 0 0 40px rgba(239,68,68,0.36); }
        }
        .hndl-radar::after {
          content: ""; position: absolute; inset: 0; border-radius: inherit; pointer-events: none;
          background: conic-gradient(from 0deg, transparent 0deg, rgba(34,211,238,0.14) 40deg, transparent 80deg);
          animation: hndlSweep 5s linear infinite;
        }
        @keyframes hndlSweep { to { transform: rotate(360deg); } }
        .hndl-flow { stroke-dasharray: 6 8; animation: hndlFlow 1.8s linear infinite; }
        @keyframes hndlFlow { to { stroke-dashoffset: -42; } }
        .hndl-scan { animation: hndlScan 5s linear infinite; }
        @keyframes hndlScan { from { transform: translateY(-100%); } to { transform: translateY(220%); } }
        .qg-theme-light .hndl-shell {
          background:
            radial-gradient(circle at 18% 6%, rgba(0,197,235,0.16), transparent 28%),
            linear-gradient(180deg, var(--qg-dashboard-bg) 0%, var(--qg-dashboard-bg-soft) 100%);
          color: var(--qg-dashboard-text);
        }
        .qg-theme-light .hndl-panel {
          background: linear-gradient(135deg, rgba(255,255,255,0.92), rgba(236,249,255,0.82)) !important;
          border-color: var(--qg-card-border) !important; color: var(--qg-dashboard-text) !important;
          box-shadow: var(--qg-panel-shadow) !important;
        }
        .qg-theme-light .hndl-shell [class*="bg-black/"],
        .qg-theme-light .hndl-shell [class*="bg-[#05080f]"] { background-color: rgba(255,255,255,0.72) !important; }
        .qg-theme-light .hndl-shell [class*="text-white/"] { color: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .hndl-shell .text-white { color: var(--qg-dashboard-text) !important; }
        .qg-theme-light .hndl-shell .text-red-300, .qg-theme-light .hndl-shell .text-red-400 { color: #dc2626 !important; }
        .qg-theme-light .hndl-shell .text-amber-300 { color: #b45309 !important; }
        .qg-theme-light .hndl-shell .text-emerald-300 { color: #047857 !important; }
        .qg-theme-light .hndl-shell .text-cyan-300, .qg-theme-light .hndl-shell .text-cyan-400 { color: #0e7490 !important; }
        .qg-theme-light .hndl-shell svg text { fill: var(--qg-dashboard-text-soft) !important; }
        .qg-theme-light .hndl-shell [class*="border-white/"] { border-color: var(--qg-card-border) !important; }
      `}</style>

      <div className="mx-auto grid max-w-[1700px] gap-3">
        {/* ---------- Top bar ---------- */}
        <header className="grid gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(360px,1fr)_150px_160px_150px_48px]">
          <div className={`${PANEL} sm:col-span-2 xl:col-span-1`}>
            <div className="relative z-10 flex min-h-[54px] items-center gap-3 px-3.5 py-2">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-red-400/40 bg-red-500/12 text-red-300">
                <Radar className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <h1 className="text-base font-black uppercase leading-none tracking-[0.08em] text-white md:text-lg">Harvest Now, Decrypt Later</h1>
                <p className="mt-1 text-[9px] font-black uppercase tracking-[0.18em] text-cyan-300/70">Quantum Threat Operations Center</p>
              </div>
            </div>
          </div>
          <div className={PANEL}>
            <div className="relative z-10 flex min-h-[54px] flex-col justify-center px-3 py-2">
              <p className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">System Time</p>
              <p className="mt-1 font-mono text-xs font-black text-cyan-300">{utcClock(data.generatedAt)}</p>
            </div>
          </div>
          <div className={PANEL}>
            <div className="relative z-10 flex min-h-[54px] items-center gap-2 px-3 py-2">
              <span className={`h-2 w-2 rounded-full ${sseConnected ? TONE_DOT.green : TONE_DOT.amber}`} />
              <div>
                <p className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">Telemetry Link</p>
                <p className={`mt-0.5 text-xs font-black uppercase ${sseConnected ? 'text-emerald-300' : 'text-amber-300'}`}>{sseConnected ? 'Live SSE' : state === 'error' ? 'Reconnecting' : 'Syncing'}</p>
              </div>
            </div>
          </div>
          <div className={PANEL}>
            <div className="relative z-10 flex min-h-[54px] flex-col justify-center px-3 py-2">
              <p className="text-[9px] font-black uppercase tracking-[0.16em] text-white/40">Migration Deadline</p>
              <p className="mt-0.5 text-xs font-black uppercase text-amber-300">{banner.migrationDeadlineYear} · {banner.yearsToDeadline}y left</p>
            </div>
          </div>
          <button type="button" onClick={refresh} className={`${PANEL} relative z-10 grid min-h-[54px] place-items-center text-white/60 hover:text-cyan-300`} aria-label="Refresh">
            <RefreshCw className={`h-4 w-4 ${state === 'loading' ? 'animate-spin' : ''}`} />
          </button>
        </header>

        {error && (
          <div className="rounded-lg border border-red-400/30 bg-red-500/10 px-4 py-3 text-sm font-semibold text-red-200">{error}</div>
        )}

        {/* ============ SECTION 1 — Quantum Threat Banner ============ */}
        <section className={`${PANEL} ${alert ? 'hndl-hero-alert border-red-500/40' : ''} min-h-[150px]`}>
          <div className={`hndl-grid ${alert ? 'hndl-grid-red' : ''} absolute inset-0 opacity-60`} />
          {alert && <div className="hndl-scan pointer-events-none absolute inset-x-0 top-0 h-12 bg-gradient-to-b from-red-400/12 to-transparent" />}
          <div className="relative z-10 grid gap-3 p-3.5 lg:grid-cols-[auto_1fr_auto] lg:items-center">
            <div className="flex items-center gap-3">
              <div className={`grid h-16 w-16 place-items-center rounded-lg border ${alert ? 'border-red-500/50 bg-red-500/12' : 'border-emerald-400/45 bg-emerald-500/10'}`}>
                {alert ? <ShieldAlert className="h-8 w-8 text-red-300" /> : <ShieldCheck className="h-8 w-8 text-emerald-300" />}
              </div>
              <div>
                <Badge tone={bannerTone}><Siren className="h-3 w-3" /> {data.hasData ? `${banner.threatLevel} Threat` : 'Awaiting Scan'}</Badge>
                <h2 className="mt-1.5 text-xl font-black uppercase leading-none tracking-[0.04em] text-white md:text-2xl">Harvest Now, Decrypt Later</h2>
                <p className="mt-1 max-w-[460px] text-[11px] font-semibold leading-4 text-white/55">{banner.headline}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="HNDL Exposure" value={`${banner.hndlExposureScore}/100`} tone={levelTone(banner.hndlExposureLevel)} sub={banner.hndlExposureLevel} />
              <Stat label="Critical Findings" value={fmt(banner.criticalFindings)} tone={banner.criticalFindings > 0 ? 'red' : 'green'} sub="quantum-vulnerable" />
              <Stat label="Future Decryptable" value={tbFmt(banner.estimatedFutureDecryptableTb)} tone="amber" sub="est. at risk" />
              <Stat label="Exposure Window" value={banner.quantumExposureWindow} tone={bannerTone} sub="to CRQC" />
            </div>

            <div className="flex flex-col items-stretch gap-2">
              <div className={`rounded-lg border px-3 py-2 text-center ${alert ? 'border-red-500/35 bg-red-500/8' : 'border-cyan-400/30 bg-cyan-500/8'}`}>
                <p className="text-[9px] font-black uppercase tracking-[0.16em] text-white/45">Next Escalation Cycle</p>
                <p className={`font-mono text-2xl font-black tracking-[0.08em] ${alert ? 'text-red-300' : 'text-cyan-300'}`}>{countdown}</p>
              </div>
              <div className="flex gap-2">
                <a href="#exposure-matrix" className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-md border border-cyan-400/50 bg-cyan-500/10 text-[10px] font-black uppercase tracking-[0.1em] text-cyan-200 transition hover:bg-cyan-500/20"><Activity className="h-3.5 w-3.5" /> Review Exposure</a>
                <a href="/dashboard/migration-planner?source=harvest-now" className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-md border border-amber-400/50 bg-amber-500/10 text-[10px] font-black uppercase tracking-[0.1em] text-amber-200 transition hover:bg-amber-500/20"><ArrowRight className="h-3.5 w-3.5" /> Begin Migration</a>
              </div>
            </div>
          </div>
        </section>

        {loading ? (
          <div className={`${PANEL} grid place-items-center py-16`}>
            <div className="text-center">
              <Radar className="mx-auto h-8 w-8 animate-pulse text-cyan-300" />
              <p className="mt-3 text-xs font-black uppercase tracking-[0.16em] text-white/55">Synchronizing quantum threat telemetry…</p>
            </div>
          </div>
        ) : !data.hasData ? (
          <section className={`${PANEL} p-6`}>
            <div className="mx-auto max-w-lg text-center">
              <ShieldCheck className="mx-auto h-10 w-10 text-cyan-300" />
              <h2 className="mt-3 text-lg font-black uppercase tracking-[0.06em] text-white">No HNDL Evidence Yet</h2>
              <p className="mt-2 text-xs font-semibold leading-5 text-white/55">{data.evidence.note || 'Run a discovery scan to populate the Quantum Threat Operations Center with your real cryptographic exposure, harvestable data and migration intelligence.'}</p>
              <a href="/dashboard/scanner" className="mt-4 inline-flex h-10 items-center gap-2 rounded-md border border-cyan-400/50 bg-cyan-500/10 px-5 text-xs font-black uppercase tracking-[0.1em] text-cyan-200 transition hover:bg-cyan-500/20"><Radar className="h-4 w-4" /> Launch Discovery Scan</a>
            </div>
          </section>
        ) : (
          <>
            {/* ===== Row 1: Quantum Exposure Graph | Global Quantum Exposure Theater ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 2 — Quantum Exposure Graph */}
              <section className={`${PANEL} min-h-[320px]`}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Network} action={`${data.exposureGraph.nodes.length} nodes`}>Quantum Exposure Graph™</SectionHeader>
                  <div className="space-y-1.5">
                    {data.exposureGraph.tiers.map((tier, i) => {
                      const tone = classTone(tier.cryptoClass);
                      return (
                        <div key={tier.id} className="relative">
                          {i < data.exposureGraph.tiers.length - 1 && <div className="absolute left-4 top-9 h-2 w-px bg-cyan-400/25" />}
                          <div className="flex items-center gap-2.5 rounded-md border border-white/8 bg-black/25 px-2.5 py-1.5">
                            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${TONE_DOT[tone]}`} />
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center justify-between gap-2">
                                <p className="truncate text-[11px] font-black uppercase tracking-[0.08em] text-white/85">{tier.label}</p>
                                <span className="text-[10px] font-black text-white/55">{fmt(tier.total)}</span>
                              </div>
                              <p className="truncate text-[9px] font-semibold text-white/40">{tier.detail}</p>
                            </div>
                            {tier.vulnerable > 0 && <Badge tone="red">{tier.vulnerable} vuln</Badge>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-2.5 border-t border-white/8 pt-2">
                    <p className="mb-1.5 text-[9px] font-black uppercase tracking-[0.14em] text-white/40">Top Exposure Nodes · click for detail</p>
                    <div className="flex flex-wrap gap-1.5">
                      {data.exposureGraph.nodes.slice(0, 12).map((n) => {
                        const tone = classTone(n.cryptoClass);
                        return (
                          <button key={n.id} type="button" onClick={() => setSelectedNode(n.id === selectedNode ? null : n.id)} className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold transition ${n.id === selectedNode ? 'border-cyan-400/70 bg-cyan-500/15 text-cyan-200' : TONE_BADGE[tone]}`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${TONE_DOT[tone]}`} />
                            <span className="max-w-[120px] truncate">{n.label}</span>
                          </button>
                        );
                      })}
                    </div>
                    {selected && (
                      <div className="mt-2 rounded-md border border-cyan-400/30 bg-cyan-500/8 p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <p className="truncate text-[11px] font-black text-cyan-200">{selected.label}</p>
                          <Badge tone={classTone(selected.cryptoClass)}>{selected.cryptoClass}</Badge>
                        </div>
                        <p className="mt-1 text-[9px] font-bold text-white/45">{selected.type} · {selected.environment} · risk {selected.riskScore}{selected.internetFacing ? ' · internet-facing' : ''}</p>
                        {selected.algorithms.length > 0 && <p className="mt-1 text-[9px] font-semibold text-white/55">Algorithms: {selected.algorithms.join(', ')}</p>}
                        <p className="mt-1 text-[9px] font-semibold text-amber-300/80">{selected.affectedDataDetail} · {selected.migrationPlan}</p>
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {/* SECTION 3 — Global Quantum Exposure Theater */}
              <section className={`${PANEL} min-h-[320px]`}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Globe2} action={`${data.theater.totalRegions} regions`}>Global Quantum Exposure Theater™</SectionHeader>
                  <div className="hndl-radar relative min-h-[240px] overflow-hidden rounded-lg border border-cyan-400/20 bg-black/40">
                    <svg className="absolute inset-0 h-full w-full opacity-50" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
                      <path className="hndl-flow" d="M22 24 C40 14, 60 16, 84 26" fill="none" stroke="rgba(34,211,238,0.5)" strokeWidth="0.4" />
                      <path className="hndl-flow" d="M16 32 C38 44, 60 40, 85 30" fill="none" stroke="rgba(239,68,68,0.4)" strokeWidth="0.4" />
                      <path className="hndl-flow" d="M27 22 C45 30, 65 50, 85 56" fill="none" stroke="rgba(251,191,36,0.35)" strokeWidth="0.35" />
                    </svg>
                    {data.theater.regions.length === 0 ? (
                      <div className="absolute inset-0 grid place-items-center"><EmptyState>No regional telemetry</EmptyState></div>
                    ) : data.theater.regions.map((r) => {
                      const tone = levelTone(r.severity);
                      return (
                        <div key={r.key} className="group/region absolute z-10 -translate-x-1/2 -translate-y-1/2" style={{ left: `${r.x}%`, top: `${r.y}%` }}>
                          <span className={`block h-3 w-3 rounded-full ${TONE_DOT[tone]} ring-2 ring-black/40`} />
                          <span className={`absolute left-1/2 top-1/2 -z-10 -translate-x-1/2 -translate-y-1/2 rounded-full ${TONE_BAR[tone]} opacity-25`} style={{ width: 10 + r.vulnerableAssets * 6, height: 10 + r.vulnerableAssets * 6 }} />
                          <div className="pointer-events-none absolute left-4 top-0 hidden w-40 rounded border border-cyan-400/30 bg-black/85 p-1.5 text-[9px] font-bold text-white/70 shadow-lg group-hover/region:block">
                            <p className="truncate text-cyan-200">{r.region}</p>
                            <p className="text-white/50">{r.assets} assets · {r.vulnerableAssets} vulnerable</p>
                            <p className={TONE_TEXT[tone]}>Avg risk {r.avgRisk} · {r.severity}</p>
                            {r.cloudProviders.length > 0 && <p className="text-white/40">{r.cloudProviders.join(', ')}</p>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-2 grid grid-cols-3 gap-2">
                    <Stat label="Regions" value={fmt(data.theater.totalRegions)} tone="cyan" />
                    <Stat label="High-Value Targets" value={fmt(data.theater.highValueTargets)} tone="red" />
                    <Stat label="Vulnerable Regions" value={fmt(data.theater.regions.filter((r) => r.vulnerableAssets > 0).length)} tone="amber" />
                  </div>
                </div>
              </section>
            </div>

            {/* ===== Row 2: Forward Secrecy Coverage | Harvest Value Engine ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 7 — Forward Secrecy Coverage */}
              <section className={`${PANEL} min-h-[320px]`}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Lock} tone={data.forwardSecrecy.coveragePct >= 70 ? 'green' : 'red'}>Forward Secrecy Coverage™</SectionHeader>
                  <div className="flex items-center justify-center py-1">
                    <Ring value={data.forwardSecrecy.coveragePct} tone={data.forwardSecrecy.coveragePct >= 70 ? 'green' : data.forwardSecrecy.coveragePct >= 40 ? 'amber' : 'red'} label="PFS Coverage" />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Stat label="Protected" value={fmt(data.forwardSecrecy.assetsProtected)} tone="green" />
                    <Stat label="Unprotected" value={fmt(data.forwardSecrecy.assetsUnprotected)} tone="red" />
                  </div>
                  <div className="mt-2 space-y-1">
                    {data.forwardSecrecy.nonPfsBreakdown.length === 0 ? (
                      <p className="text-center text-[10px] font-bold text-emerald-300/70">No non-PFS configurations detected</p>
                    ) : data.forwardSecrecy.nonPfsBreakdown.map((b) => (
                      <div key={b.type} className="flex items-center justify-between rounded border border-white/8 bg-black/25 px-2 py-1">
                        <span className="text-[10px] font-bold uppercase tracking-[0.06em] text-white/65">{b.type}</span>
                        <Badge tone="red">{b.count}</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {/* SECTION 4 — Harvest Value Engine */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Target} tone="amber">Harvest Value Engine™</SectionHeader>
                  <div className="space-y-1.5">
                    {data.harvestValue.map((h) => {
                      const tone = levelTone(h.estimatedFutureValue);
                      return (
                        <div key={h.key} className={`rounded-md border bg-black/25 px-2.5 py-1.5 ${h.inScope ? 'border-white/10' : 'border-white/5 opacity-55'}`}>
                          <div className="flex items-center justify-between gap-2">
                            <p className="truncate text-[11px] font-black uppercase tracking-[0.06em] text-white/85">{h.label}</p>
                            <Badge tone={tone}>{h.estimatedFutureValue}</Badge>
                          </div>
                          <div className="mt-1 grid grid-cols-3 gap-1.5 text-[9px] font-bold">
                            <span className="text-white/45">Exposure <span className={TONE_TEXT[tone]}>{h.exposureScore}</span></span>
                            <span className="text-white/45">Lifetime <span className="text-cyan-300">{h.confidentialityLifetimeYears}y</span></span>
                            <span className="text-white/45">Adversary <span className="text-red-300">{h.adversaryInterestScore}</span></span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </section>
            </div>

            {/* ===== Row 3: Data Shelf-Life Analyzer | Quantum Break Timeline ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 5 — Data Shelf-Life Analyzer */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={CalendarClock} tone="cyan" action="vs CRQC 2030">Data Shelf-Life Analyzer™</SectionHeader>
                  <div className="space-y-1">
                    {data.shelfLife.map((s) => (
                      <div key={s.dataType} className={`flex items-center justify-between gap-2 rounded-md border bg-black/25 px-2.5 py-1.5 ${s.exceedsCrqc ? 'border-red-500/30' : 'border-white/8'}`}>
                        <div className="min-w-0">
                          <p className="truncate text-[11px] font-black uppercase tracking-[0.06em] text-white/85">{s.dataType}</p>
                          <p className="text-[9px] font-semibold text-white/40">{s.retentionRequirement} · expires {s.dataExpiresYear}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-black text-cyan-300">{s.confidentialityYears}y</p>
                          {s.exceedsCrqc && <span className="text-[8px] font-black uppercase tracking-[0.08em] text-red-300">{s.quantumRiskWindow}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {/* SECTION 6 — Quantum Break Timeline */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Clock} tone="red">Quantum Break Timeline™</SectionHeader>
                  <div className="mb-2 grid grid-cols-3 gap-2">
                    <Stat label="Now" value={data.breakTimeline.currentYear} tone="cyan" />
                    <Stat label="CRQC" value={data.breakTimeline.crqcYear} tone="red" />
                    <Stat label="Target" value={data.breakTimeline.migrationCompletionYear} tone="amber" />
                  </div>
                  <div className="space-y-1.5">
                    {data.breakTimeline.years.map((y) => {
                      const tone: Tone = y.projectedRisk >= 75 ? 'red' : y.projectedRisk >= 50 ? 'amber' : 'cyan';
                      return (
                        <div key={y.year} className="flex items-center gap-2">
                          <span className={`w-9 shrink-0 text-[10px] font-black ${y.critical ? 'text-red-300' : 'text-white/55'}`}>{y.year}</span>
                          <div className="flex-1"><Bar value={y.projectedRisk} tone={tone} /></div>
                          <span className={`w-8 shrink-0 text-right text-[10px] font-black ${TONE_TEXT[tone]}`}>{y.projectedRisk}</span>
                        </div>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-[9px] font-semibold leading-3 text-white/40">{data.breakTimeline.years.find((y) => y.critical)?.milestone || 'Projected quantum risk growth toward CRQC.'}</p>
                </div>
              </section>
            </div>

            {/* ===== SECTION 8 — Cryptographic Exposure Matrix ===== */}
            <section id="exposure-matrix" className={PANEL}>
              <div className="relative z-10 p-3">
                <SectionHeader icon={Layers} tone="red" action={`${data.exposureMatrix.length} algorithms`}>Cryptographic Exposure Matrix™</SectionHeader>
                {data.exposureMatrix.length === 0 ? <EmptyState>No cryptographic inventory</EmptyState> : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[640px] border-collapse text-left">
                      <thead>
                        <tr className="border-b border-white/10 text-[9px] font-black uppercase tracking-[0.12em] text-white/45">
                          <th className="px-2 py-1.5">Algorithm</th>
                          <th className="px-2 py-1.5">Assets</th>
                          <th className="px-2 py-1.5">Instances</th>
                          <th className="px-2 py-1.5">Criticality</th>
                          <th className="px-2 py-1.5">Exposure</th>
                          <th className="px-2 py-1.5">Migration Priority</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.exposureMatrix.map((m) => {
                          const tone = classTone(m.cryptoClass);
                          const prTone = levelTone(m.migrationPriority);
                          return (
                            <tr key={m.algorithm} className="border-b border-white/5 text-[11px] font-semibold text-white/75 transition hover:bg-white/4">
                              <td className="px-2 py-1.5"><span className="inline-flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${TONE_DOT[tone]}`} />{m.algorithm}{m.internetFacing && <Crosshair className="h-3 w-3 text-red-300" />}</span></td>
                              <td className="px-2 py-1.5 font-black text-white">{fmt(m.assetCount)}</td>
                              <td className="px-2 py-1.5 text-white/55">{fmt(m.instanceCount)}</td>
                              <td className="px-2 py-1.5"><Badge tone={levelTone(m.businessCriticality)}>{m.businessCriticality}</Badge></td>
                              <td className="px-2 py-1.5"><span className={TONE_TEXT[tone]}>{m.exposure}</span></td>
                              <td className="px-2 py-1.5"><Badge tone={prTone}>{m.migrationPriority}</Badge></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </section>

            {/* ===== Row 5: Estimated Captured Data | Future Decryptable Data ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 9 — Estimated Captured Data */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={HardDriveDownload} tone="amber">Estimated Captured Data™</SectionHeader>
                  {!data.capturedData.hasEvidence ? <EmptyState>No harvestable data sources</EmptyState> : (
                    <>
                      <div className="space-y-1">
                        {data.capturedData.lines.filter((l) => l.gb > 0).map((l) => (
                          <div key={l.key} className="flex items-center justify-between text-[10px] font-bold">
                            <span className="text-white/55">{l.label}</span>
                            <span className="text-amber-300">{tbFmt(l.tb)}</span>
                          </div>
                        ))}
                      </div>
                      <div className="mt-2 border-t border-white/8 pt-2 text-center">
                        <p className="text-[9px] font-black uppercase tracking-[0.14em] text-white/45">Total Captured Volume</p>
                        <p className="text-2xl font-black text-amber-300">{tbFmt(data.capturedData.totalTb)}</p>
                      </div>
                    </>
                  )}
                </div>
              </section>

              {/* SECTION 10 — Estimated Future Decryptable Data */}
              <section className={`${PANEL} border-red-500/25`}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={TrendingUp} tone="red">Future Decryptable Data™</SectionHeader>
                  <div className="text-center">
                    <p className="text-[9px] font-black uppercase tracking-[0.14em] text-white/45">Projected Decryptable Volume</p>
                    <p className="text-3xl font-black text-red-300">{tbFmt(data.futureDecryptable.projectedDecryptableTb)}</p>
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    <Stat label="Data At Risk" value={tbFmt(data.futureDecryptable.totalDataAtRiskTb)} tone="amber" />
                    <Stat label="High-Value" value={pct(data.futureDecryptable.highValueDataPct)} tone="red" />
                    <Stat label="Critical Assets" value={fmt(data.futureDecryptable.criticalConfidentialAssets)} tone="red" />
                    <Stat label="Vuln Share" value={pct(data.futureDecryptable.vulnerableSharePct)} tone="amber" />
                  </div>
                  {data.futureDecryptable.trend.length > 1 && (
                    <div className="mt-2 flex h-10 items-end gap-1">
                      {data.futureDecryptable.trend.map((t, i) => {
                        const max = Math.max(...data.futureDecryptable.trend.map((x) => x.decryptableTb), 0.01);
                        return <div key={i} className="flex-1 rounded-t bg-gradient-to-t from-red-500/40 to-red-400" style={{ height: `${Math.max(6, (t.decryptableTb / max) * 100)}%` }} title={`${t.label}: ${tbFmt(t.decryptableTb)}`} />;
                      })}
                    </div>
                  )}
                </div>
              </section>
            </div>

            {/* ===== Row 6: Quantum Migration Readiness | Adversary Interest Score ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 11 — Quantum Migration Readiness */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Boxes} tone="green">Quantum Migration Readiness™</SectionHeader>
                  <div className="flex items-center justify-center py-1">
                    <Ring value={data.migrationReadiness.readinessScore} tone={levelTone(data.migrationReadiness.readinessLevel)} label="Readiness" sub={data.migrationReadiness.readinessLevel} size={104} />
                  </div>
                  <div className="grid grid-cols-3 gap-1.5">
                    <Stat label="PQC Ready" value={fmt(data.migrationReadiness.pqcReady)} tone="green" />
                    <Stat label="Hybrid" value={fmt(data.migrationReadiness.hybridReady)} tone="amber" />
                    <Stat label="Legacy" value={fmt(data.migrationReadiness.legacyOnly)} tone="red" />
                    <Stat label="In Progress" value={fmt(data.migrationReadiness.migrationInProgress)} tone="cyan" />
                    <Stat label="Completed" value={fmt(data.migrationReadiness.migrationCompleted)} tone="green" />
                    <Stat label="Blocked" value={fmt(data.migrationReadiness.migrationBlocked)} tone="red" />
                  </div>
                  <p className="mt-2 text-[9px] font-semibold leading-3 text-white/45">{data.migrationReadiness.recommendation}</p>
                </div>
              </section>

              {/* SECTION 12 — Adversary Interest Score */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Crosshair} tone="red">Adversary Interest Score™</SectionHeader>
                  <div className="space-y-1.5">
                    {data.adversaryInterest.length === 0 ? <EmptyState>No sector telemetry</EmptyState> : data.adversaryInterest.map((a) => (
                      <div key={a.key}><Bar value={a.interestScore} tone={levelTone(a.level)} label={a.sector} right={`${a.interestScore}`} /></div>
                    ))}
                  </div>
                </div>
              </section>
            </div>

            {/* ===== Row 7: Threat Actors Most Interested | Strategic Intelligence Feed ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 13 — Threat Actors Most Interested */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Target} tone="red">Threat Actors Most Interested™</SectionHeader>
                  <div className="space-y-1.5">
                    {data.threatActors.length === 0 ? <EmptyState>No exposure intelligence</EmptyState> : data.threatActors.map((a) => (
                      <div key={a.key} className="rounded-md border border-white/8 bg-black/25 px-2.5 py-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <p className="truncate text-[11px] font-black uppercase tracking-[0.05em] text-white/85">{a.actor}</p>
                          <Badge tone={levelTone(a.level)}>{a.interestScore}</Badge>
                        </div>
                        <p className="mt-0.5 text-[9px] font-semibold leading-3 text-white/45">{a.motivation}</p>
                        {a.targetedAssetCount > 0 && <p className="mt-0.5 text-[9px] font-bold text-cyan-300/70">Targets: {a.targetedAssetCount} asset(s)</p>}
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              {/* SECTION 14 — Strategic Intelligence Feed */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={Activity} tone="cyan" action="PQC ecosystem">Strategic Intelligence Feed™</SectionHeader>
                  <div className="max-h-[320px] space-y-1.5 overflow-y-auto pr-1">
                    {data.intelligenceFeed.map((it) => (
                      <div key={it.id} className="rounded-md border border-white/8 bg-black/25 px-2.5 py-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[9px] font-black uppercase tracking-[0.1em] text-cyan-300">{it.source}</span>
                          <span className="text-[8px] font-bold text-white/35">{it.date}</span>
                        </div>
                        <p className="mt-0.5 text-[10px] font-black text-white/85">{it.title}</p>
                        <p className="text-[9px] font-semibold leading-3 text-white/45">{it.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            </div>

            {/* ===== Row 8: Top HNDL Findings | Remediation Center ===== */}
            <div className="grid gap-3 xl:grid-cols-2">
              {/* SECTION 15 — Top HNDL Findings */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={ShieldAlert} tone="red" action={`${data.topFindings.length}`}>Top HNDL Findings™</SectionHeader>
                  {data.topFindings.length === 0 ? <EmptyState>No HNDL findings</EmptyState> : (
                    <div className="max-h-[320px] space-y-1.5 overflow-y-auto pr-1">
                      {data.topFindings.map((f) => (
                        <div key={f.id} className={`rounded-md border bg-black/25 px-2.5 py-1.5 ${f.exceedsCrqc ? 'border-red-500/30' : 'border-white/8'}`}>
                          <div className="flex items-center justify-between gap-2">
                            <p className="truncate font-mono text-[10px] font-black text-red-300">{f.algorithm}</p>
                            <Badge tone={levelTone(f.migrationPriority)}>{f.migrationPriority}</Badge>
                          </div>
                          <p className="truncate text-[9px] font-semibold text-white/55">{f.asset}</p>
                          <div className="mt-0.5 flex items-center justify-between text-[9px] font-bold">
                            <span className="text-white/40">{f.dataLifetimeLabel}</span>
                            <span className={f.exceedsCrqc ? 'text-red-300' : 'text-cyan-300'}>{f.riskWindow}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>

              {/* SECTION 16 — Remediation Center */}
              <section className={PANEL}>
                <div className="relative z-10 p-3">
                  <SectionHeader icon={KeyRound} tone="green" action="action plan">Remediation Center™</SectionHeader>
                  <div className="max-h-[320px] space-y-1.5 overflow-y-auto pr-1">
                    {data.remediationCenter.map((a) => (
                      <a key={a.key} href={a.href} className={`block rounded-md border bg-black/25 px-2.5 py-1.5 transition hover:border-cyan-400/40 hover:bg-cyan-500/5 ${a.inScope ? 'border-white/10' : 'border-white/5 opacity-55'}`}>
                        <div className="flex items-center justify-between gap-2">
                          <p className="truncate text-[11px] font-black uppercase tracking-[0.05em] text-white/85">{a.label}</p>
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-white/35" />
                        </div>
                        <p className="text-[9px] font-semibold text-white/40">{a.requires}</p>
                        <div className="mt-1 grid grid-cols-3 gap-1 text-[9px] font-bold">
                          <span className="text-white/45">Assets <span className="text-cyan-300">{fmt(a.affectedAssets)}</span></span>
                          <span className="text-white/45">Risk <span className="text-emerald-300">-{a.riskReductionPct}%</span></span>
                          <span className="text-white/45">Effort <span className="text-amber-300">{a.effort}</span></span>
                        </div>
                      </a>
                    ))}
                  </div>
                </div>
              </section>
            </div>

            {/* ===== Evidence footer ===== */}
            <section className={`${PANEL}`}>
              <div className="relative z-10 flex flex-wrap items-center justify-between gap-3 px-3.5 py-2.5">
                <div className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-[0.1em] text-white/45">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" />
                  <span>Evidence: {data.evidence.sources.join(' · ')}</span>
                </div>
                <p className="max-w-[60%] text-right text-[9px] font-semibold text-white/40">{data.evidence.note}</p>
              </div>
            </section>
          </>
        )}

        <footer className="py-1 text-center">
          <p className="text-[10px] font-black uppercase tracking-[0.3em] text-cyan-300/40">Dominate Today · Defeat Tomorrow · Protect Forever</p>
        </footer>
      </div>
    </div>
  );
}
