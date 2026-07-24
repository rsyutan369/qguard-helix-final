'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode, type MouseEvent } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, ArrowRight, BadgeCheck, Calendar, ChevronDown, CircuitBoard,
  Clock3, Download, FileJson, GitBranch, Gauge, Layers, ListChecks,
  Search, ShieldCheck, Store, Terminal, Workflow, Zap,
  ZoomIn, ZoomOut, Maximize2, Server, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { OrchestratorSnapshot } from '@/types/migration-orchestrator';
import { Panel, Sparkline, RadialGauge, Bar, TONE, type Tone } from '../_components/executive/primitives';
import { SectionCard, Chip, AnimatedStat } from '../migration_timeline/_ops-sections';
import {
  CYAN, TONE_HEX, numberFmt, pct, downloadTextFile,
  workflowsToCsv, ORCH_STANDARDS,
  type OpsTone, type AutomationKpi, type CommandField, type PipelineStage, type OrchWorkflow,
  type DagNode, type DagEdge, type CabRecord, type KanbanColumn, type KanbanColumnId,
  type WorkflowTemplate, type ScheduleEntry, type AutomationPolicy, type AnalyticSeries,
  type OrchEvent, type ComplianceRow,
} from './_orch-lib';

function tc(tone: OpsTone) {
  const t = TONE[tone as Tone];
  return { text: t.text, soft: t.soft, border: t.border, dot: t.dot, hex: TONE_HEX[tone] };
}

/* ================================================================== */
/* 1 — Executive Automation Summary                                   */
/* ================================================================== */

export function ExecAutomationSummary({ kpis, onDrill }: { kpis: AutomationKpi[]; onDrill: (route: string) => void }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7">
      {kpis.map((kpi) => {
        const t = tc(kpi.tone);
        return (
          <button key={kpi.key} type="button" onClick={() => onDrill(kpi.route)} title={kpi.basis} className="group/kpi text-left">
            <Panel className="h-full p-3.5 transition-transform group-hover/kpi:-translate-y-0.5">
              <div className="flex items-start justify-between gap-1">
                <div className="min-w-0">
                  <div className="truncate text-[8px] font-black uppercase tracking-wider text-white/45">{kpi.label}</div>
                  <AnimatedStat text={kpi.value} className="mt-1.5 block text-xl font-black leading-none text-white" />
                  <div className={cn('mt-1 truncate text-[8.5px] font-bold', t.text)}>{kpi.detail}</div>
                </div>
                {kpi.live && <span className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />}
              </div>
              <div className="mt-1.5 h-[26px] opacity-80"><Sparkline values={kpi.spark.length > 1 ? kpi.spark : [0, kpi.spark[0] ?? 0]} color={t.hex} height={26} /></div>
            </Panel>
          </button>
        );
      })}
    </div>
  );
}

/* ================================================================== */
/* 2 — Automation Command Center ribbon                               */
/* ================================================================== */

export function CommandCenterRibbon({ fields }: { fields: CommandField[] }) {
  return (
    <Panel className="relative overflow-hidden p-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(120%_120%_at_0%_0%,rgba(34,211,238,0.10),transparent_55%)]" />
      <div className="relative mb-3 flex items-center gap-2">
        <CircuitBoard className="h-4 w-4 text-cyan-300" />
        <span className="text-[11px] font-black uppercase tracking-[0.18em] text-white/85">Automation Command Center</span>
        <span className="ml-auto text-[9px] font-mono uppercase tracking-widest text-white/30">Live Operations Ribbon</span>
      </div>
      <div className="relative grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {fields.map((f) => {
          const t = tc(f.tone);
          return (
            <div key={f.label} className={cn('rounded-lg border bg-white/[0.02] px-3 py-2', t.border)}>
              <div className="text-[7.5px] font-black uppercase leading-tight tracking-wider text-white/40">{f.label}</div>
              <div className={cn('mt-0.5 truncate text-[13px] font-black', t.text)}>{f.value}</div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/* ================================================================== */
/* 3 — Global Orchestration Pipeline                                  */
/* ================================================================== */

const PIPE_STATUS: Record<PipelineStage['status'], { tone: OpsTone; label: string }> = {
  complete: { tone: 'good', label: 'Complete' }, active: { tone: 'neutral', label: 'Active' },
  pending: { tone: 'warning', label: 'Pending' }, blocked: { tone: 'critical', label: 'Blocked' },
};

export function PipelinePanel({ stages }: { stages: PipelineStage[] }) {
  const [open, setOpen] = useState<string | null>(stages.find((s) => s.status === 'active')?.id ?? null);
  return (
    <SectionCard title="Global Orchestration Pipeline" icon={Workflow} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{stages.filter((s) => s.status === 'complete').length}/{stages.length} stages</span>}>
      <div className="space-y-1.5">
        {stages.map((stage, i) => {
          const meta = PIPE_STATUS[stage.status];
          const t = tc(meta.tone);
          const isOpen = open === stage.id;
          return (
            <div key={stage.id} className={cn('rounded-lg border bg-white/[0.02]', t.border)}>
              <button type="button" onClick={() => setOpen(isOpen ? null : stage.id)} className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 p-2.5 text-left">
                <span className="font-mono text-[8px] text-white/30">{String(i + 1).padStart(2, '0')}</span>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[11px] font-black uppercase tracking-wide text-white/85">{stage.label}</span>
                    <Chip tone={meta.tone}>{meta.label}</Chip>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <div className="h-1 w-24 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full" style={{ width: `${stage.progress}%`, backgroundColor: t.hex }} /></div>
                    <span className="truncate text-[9px] text-white/40">{stage.detail}</span>
                  </div>
                </div>
                <ChevronDown className={cn('h-4 w-4 text-white/40 transition-transform', isOpen && 'rotate-180')} />
              </button>
              <AnimatePresence initial={false}>
                {isOpen && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                    <div className="grid grid-cols-2 gap-2 border-t border-white/10 p-3 md:grid-cols-4">
                      <MiniField label="Owner" value={stage.owner} />
                      <MiniField label="Duration" value={stage.duration} />
                      <MiniField label="Validation" value={stage.validation} />
                      <MiniField label="Rollback" value={stage.rollback} />
                      <div className="col-span-2 md:col-span-4">
                        <div className="mb-1 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">Policies</div>
                        <div className="flex flex-wrap gap-1">{stage.standards.map((s) => <Chip key={s} tone="info">{s}</Chip>)}</div>
                      </div>
                      <a href={stage.route} className="col-span-2 inline-flex w-fit items-center gap-1 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[8.5px] font-black uppercase tracking-wider text-cyan-300 md:col-span-4">Open module <ArrowRight className="h-3 w-3" /></a>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

function MiniField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-black/20 p-2">
      <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/70">{label}</div>
      <div className="mt-0.5 text-[10px] font-semibold text-white/70">{value}</div>
    </div>
  );
}

/* ================================================================== */
/* 5 — Workflow Command Console                                        */
/* ================================================================== */

export function WorkflowConsole({ workflow, orch }: { workflow: OrchWorkflow | null; orch: OrchestratorSnapshot }) {
  const m = orch.metrics;
  const infra: Array<[string, string]> = [
    ['CPU', m.agentCpuPct != null ? `${Math.round(m.agentCpuPct)}%` : '—'],
    ['Memory', m.agentMemoryPct != null ? `${Math.round(m.agentMemoryPct)}%` : '—'],
    ['Network', m.networkLatencyMs != null ? `${Math.round(m.networkLatencyMs)}ms` : '—'],
    ['Worker Util', pct(m.workerUtilizationPct)],
    ['In-Flight', numberFmt(m.inFlight)],
    ['Queue Depth', numberFmt(m.queueDepth)],
  ];
  return (
    <SectionCard title="Workflow Command Console" icon={Terminal} live={m.running > 0} right={<Chip tone={m.running > 0 ? 'neutral' : 'info'}>{m.running > 0 ? 'Executing' : 'Standby'}</Chip>}>
      {!workflow ? (
        <div className="rounded-lg border border-white/5 bg-black/20 p-6 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No active workflow. Console populates when a job enters execution.</div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-black text-white">{workflow.name}</span>
              <Chip tone={workflow.tone}>{workflow.phaseLabel}</Chip>
              <Chip tone={workflow.priority === 'Critical' ? 'critical' : workflow.priority === 'High' ? 'warning' : 'neutral'}>{workflow.priority}</Chip>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <div className="h-1.5 flex-1"><Bar value={workflow.progress} color={CYAN} height={6} /></div>
              <span className="text-[11px] font-black text-white">{pct(workflow.progress)}</span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-[9px] font-semibold sm:grid-cols-3">
              <ConsoleField label="Current Node" value={workflow.phaseLabel} />
              <ConsoleField label="Wave" value={workflow.wave} />
              <ConsoleField label="Agent" value={workflow.agent} />
              <ConsoleField label="Operator" value={workflow.operator} />
              <ConsoleField label="ETA" value={workflow.eta} />
              <ConsoleField label="Retries" value={String(workflow.retryCount)} />
              <ConsoleField label="Validation" value={pct(workflow.validationPct)} tone="good" />
              <ConsoleField label="Rollback" value={workflow.rollback} tone="good" />
              <ConsoleField label="Risk" value={workflow.risk.label} tone={workflow.risk.tone} />
              <ConsoleField label="Algorithms" value={`${workflow.currentAlgo} → ${workflow.targetAlgo}`} />
              <ConsoleField label="Dependencies" value={numberFmt(workflow.dependencies)} />
              <ConsoleField label="AI Confidence" value={pct(workflow.aiConfidence)} tone="neutral" />
            </div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/20 p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><Server className="h-3 w-3" />Runtime Resources</div>
            <div className="grid grid-cols-2 gap-2">
              {infra.map(([label, value]) => (
                <div key={label} className="rounded-lg border border-white/5 bg-white/[0.02] p-2">
                  <div className="text-[7.5px] font-black uppercase tracking-wider text-white/40">{label}</div>
                  <div className="mt-0.5 text-[13px] font-black text-white">{value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </SectionCard>
  );
}

function ConsoleField({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: OpsTone }) {
  const t = tc(tone);
  return (
    <div className="min-w-0">
      <span className="text-white/30">{label}: </span>
      <span className={cn('font-bold', tone === 'neutral' ? 'text-white/75' : t.text)}>{value}</span>
    </div>
  );
}

/* ================================================================== */
/* 6 — CAB Approval Center                                            */
/* ================================================================== */

export function CabApprovalCenter({ cab }: { cab: CabRecord }) {
  const rows: Array<[string, string, OpsTone?]> = [
    ['RFC Number', cab.rfc], ['Change Request', cab.change], ['Approver', cab.approver],
    ['Approver Team', cab.approverTeam], ['Maintenance Window', cab.window],
    ['Business Owner', cab.businessOwner], ['Technical Owner', cab.technicalOwner],
    ['Security Approval', cab.securityApproval, cab.securityApproval === 'Approved' ? 'good' : 'warning'],
    ['Compliance Approval', cab.complianceApproval, cab.complianceApproval === 'Approved' ? 'good' : 'warning'],
  ];
  const checks: Array<[string, boolean]> = [
    ['Rollback Tested', cab.rollbackTested], ['Validation Complete', cab.validationComplete], ['Emergency Change', cab.emergency],
  ];
  return (
    <SectionCard title="CAB Approval Center" icon={BadgeCheck} right={<Chip tone={cab.pending > 0 ? 'warning' : 'good'}>{cab.pending > 0 ? `${cab.pending} pending` : 'Clear'}</Chip>}>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.3fr_1fr]">
        <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          {rows.map(([label, value, tone]) => (
            <div key={label} className="rounded-lg border border-white/5 bg-black/20 px-3 py-2">
              <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/70">{label}</div>
              <div className={cn('mt-0.5 truncate text-[11px] font-bold', tone ? tc(tone).text : 'text-white/80')}>{value}</div>
            </div>
          ))}
        </div>
        <div className="space-y-3">
          <div className="rounded-xl border border-white/10 bg-black/20 p-3">
            <div className="mb-1.5 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">Risk Rating</div>
            <div className="flex items-center gap-3">
              <RadialGauge value={cab.riskRating.label === 'Critical' ? 90 : cab.riskRating.label === 'High' ? 68 : cab.riskRating.label === 'Medium' ? 45 : 20} color={tc(cab.riskRating.tone).hex} size={64} label={cab.riskRating.label} />
              <div className="space-y-1.5">
                {checks.map(([label, ok]) => (
                  <div key={label} className="flex items-center gap-1.5 text-[9px] font-bold">
                    <span className={cn('h-1.5 w-1.5 rounded-full', ok ? 'bg-emerald-400' : 'bg-white/25')} />
                    <span className={ok ? 'text-white/70' : 'text-white/35'}>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/20 p-3">
            <div className="mb-1.5 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">Integrations</div>
            <div className="flex flex-wrap gap-1.5">
              <Chip tone="warning">ServiceNow · {cab.serviceNow}</Chip>
              <Chip tone="warning">Jira · {cab.jira}</Chip>
            </div>
            <div className="mt-2 flex gap-2">
              <button type="button" className="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-3 py-1.5 text-[8.5px] font-black uppercase tracking-wider text-emerald-300 transition hover:bg-emerald-500/20">Approve</button>
              <a href="/dashboard/migration-planner" className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-[8.5px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300">Review Plan</a>
            </div>
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 8 — Workflow Queue (enterprise table)                              */
/* ================================================================== */

type QueueFilter = { search: string; priority: string; phase: string };
const QUEUE_PAGE = 10;

export function WorkflowQueue({ workflows, onSelect }: { workflows: OrchWorkflow[]; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState<QueueFilter>({ search: '', priority: 'all', phase: 'all' });
  const [sort, setSort] = useState<'priority' | 'progress' | 'name'>('priority');
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    const q = filter.search.trim().toLowerCase();
    const out = workflows.filter((w) => {
      if (filter.priority !== 'all' && w.priority !== filter.priority) return false;
      if (filter.phase !== 'all' && w.kanban !== filter.phase) return false;
      if (q && !`${w.name} ${w.asset} ${w.agent} ${w.wave}`.toLowerCase().includes(q)) return false;
      return true;
    });
    out.sort((a, b) => sort === 'name' ? a.name.localeCompare(b.name) : sort === 'progress' ? b.progress - a.progress : b.priorityScore - a.priorityScore);
    return out;
  }, [workflows, filter, sort]);

  useEffect(() => { setPage(0); }, [filter, sort]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / QUEUE_PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const rows = filtered.slice(safePage * QUEUE_PAGE, safePage * QUEUE_PAGE + QUEUE_PAGE);
  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const exportCsv = () => downloadTextFile(`qguard-workflows-${Date.now()}.csv`, workflowsToCsv(filtered), 'text/csv;charset=utf-8');
  const exportJson = () => downloadTextFile(`qguard-workflows-${Date.now()}.json`, JSON.stringify(filtered, null, 2), 'application/json;charset=utf-8');

  return (
    <SectionCard title="Workflow Queue" icon={ListChecks} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{numberFmt(filtered.length)} of {numberFmt(workflows.length)}</span>}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/30" />
          <input value={filter.search} onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))} placeholder="Search workflows…" className="w-48 rounded-lg border border-white/10 bg-black/30 py-1.5 pl-7 pr-2 text-[10px] text-white placeholder:text-white/25 focus:border-cyan-400/50 focus:outline-none" />
        </div>
        <Select value={filter.priority} onChange={(v) => setFilter((f) => ({ ...f, priority: v }))} options={[['all', 'All Priority'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']]} />
        <Select value={filter.phase} onChange={(v) => setFilter((f) => ({ ...f, phase: v }))} options={[['all', 'All Phase'], ['queued', 'Queued'], ['scheduled', 'Scheduled'], ['running', 'Running'], ['waiting-approval', 'Waiting Approval'], ['validation', 'Validation'], ['completed', 'Completed'], ['failed', 'Failed'], ['rollback', 'Rollback']]} />
        <Select value={sort} onChange={(v) => setSort(v as typeof sort)} options={[['priority', 'Sort: Priority'], ['progress', 'Sort: Progress'], ['name', 'Sort: Name']]} />
        <button type="button" onClick={exportCsv} className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300"><Download className="h-3 w-3" />CSV</button>
        <button type="button" onClick={exportJson} className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-[9px] font-black uppercase tracking-wider text-white/60 transition hover:text-cyan-300"><FileJson className="h-3 w-3" />JSON</button>
      </div>

      {selected.size > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5">
          <span className="text-[10px] font-black uppercase tracking-wider text-cyan-200">{selected.size} selected</span>
          <button type="button" onClick={() => downloadTextFile(`qguard-workflows-selected-${Date.now()}.json`, JSON.stringify(workflows.filter((w) => selected.has(w.id)), null, 2), 'application/json')} className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold text-white/70 hover:text-cyan-300">Export</button>
          <a href="/dashboard/live-migration" className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-bold text-white/70 hover:text-cyan-300">Run</a>
          <button type="button" onClick={() => setSelected(new Set())} className="ml-auto text-[9px] font-bold text-white/40 hover:text-white">Clear</button>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] text-left">
          <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70">
            <tr>
              <th className="px-2 py-2"></th>
              {['Workflow', 'Wave', 'Env', 'Agent', 'Priority', 'Risk', 'Phase', 'Progress', 'Validation', 'Sim', 'AI', 'ETA'].map((h) => <th key={h} className="whitespace-nowrap px-2 py-2">{h}</th>)}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/60">
            {rows.length === 0 ? (
              <tr><td colSpan={13} className="py-8 text-center text-white/30">No workflows match. Scanner findings materialize workflows automatically.</td></tr>
            ) : rows.map((w) => (
              <tr key={w.id} className="transition hover:bg-cyan-500/[0.05]">
                <td className="px-2 py-2"><input type="checkbox" checked={selected.has(w.id)} onChange={() => toggle(w.id)} className="accent-cyan-400" /></td>
                <td className="max-w-[180px] cursor-pointer truncate px-2 py-2 text-white/85" onClick={() => onSelect(w.id)}>{w.name}</td>
                <td className="px-2 py-2">{w.wave}</td>
                <td className="px-2 py-2">{w.environment}</td>
                <td className="max-w-[100px] truncate px-2 py-2 font-mono text-[9px]">{w.agent}</td>
                <td className={cn('px-2 py-2 font-black', tc(w.priority === 'Critical' ? 'critical' : w.priority === 'High' ? 'warning' : 'neutral').text)}>{w.priority}</td>
                <td className={cn('px-2 py-2 font-black', tc(w.risk.tone).text)}>{w.risk.label}</td>
                <td className={cn('whitespace-nowrap px-2 py-2', tc(w.tone).text)}>{w.phaseLabel}</td>
                <td className="px-2 py-2"><div className="flex items-center gap-1.5"><div className="h-1 w-12"><Bar value={w.progress} color={tc(w.tone).hex} height={4} /></div><span className="text-[9px]">{pct(w.progress)}</span></div></td>
                <td className="px-2 py-2">{pct(w.validationPct)}</td>
                <td className="px-2 py-2">{w.simulation}</td>
                <td className="px-2 py-2">{pct(w.aiConfidence)}</td>
                <td className="px-2 py-2">{w.eta}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pageCount > 1 && (
        <div className="mt-3 flex items-center justify-between text-[9px] font-bold uppercase tracking-wider text-white/40">
          <span>Page {safePage + 1} of {pageCount}</span>
          <div className="flex gap-1">
            <button type="button" disabled={safePage === 0} onClick={() => setPage((p) => Math.max(0, p - 1))} className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-white/60 disabled:opacity-30">Prev</button>
            <button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-white/60 disabled:opacity-30">Next</button>
          </div>
        </div>
      )}
    </SectionCard>
  );
}

function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: Array<[string, string]> }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className="rounded-lg border border-white/10 bg-black/30 px-2 py-1.5 text-[10px] font-bold text-white/70 focus:border-cyan-400/50 focus:outline-none">
      {options.map(([v, l]) => <option key={v} value={v} className="bg-[#0b1120]">{l}</option>)}
    </select>
  );
}

/* ================================================================== */
/* 4 — Workflow Execution DAG (zoom / pan)                            */
/* ================================================================== */

export function ExecutionDag({ nodes, edges, onSelectNode }: { nodes: DagNode[]; edges: DagEdge[]; onSelectNode: (id: string) => void }) {
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const drag = useRef<{ x: number; y: number; ox: number; oy: number } | null>(null);
  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const onDown = (e: MouseEvent) => { drag.current = { x: e.clientX, y: e.clientY, ox: offset.x, oy: offset.y }; };
  const onMove = (e: MouseEvent) => {
    if (!drag.current) return;
    setOffset({ x: drag.current.ox + (e.clientX - drag.current.x), y: drag.current.oy + (e.clientY - drag.current.y) });
  };
  const onUp = () => { drag.current = null; };
  const reset = () => { setScale(1); setOffset({ x: 0, y: 0 }); };

  return (
    <SectionCard
      title="Workflow Execution DAG"
      icon={GitBranch}
      right={
        <div className="flex items-center gap-1">
          <span className="mr-2 flex items-center gap-1 text-[8px] font-black uppercase tracking-wider text-cyan-300/70"><span className="h-1 w-4 rounded-full bg-cyan-400" />critical path</span>
          <IconBtn onClick={() => setScale((s) => Math.min(2, s + 0.15))} icon={ZoomIn} />
          <IconBtn onClick={() => setScale((s) => Math.max(0.6, s - 0.15))} icon={ZoomOut} />
          <IconBtn onClick={reset} icon={Maximize2} />
        </div>
      }
    >
      <div
        className="relative h-[440px] cursor-grab overflow-hidden rounded-xl border border-white/10 bg-[#070b18]/40 active:cursor-grabbing"
        onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}
      >
        <div className="absolute left-1/2 top-0 origin-top" style={{ width: 520, height: 440, transform: `translateX(-50%) translate(${offset.x}px, ${offset.y}px) scale(${scale})` }}>
          <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 105" preserveAspectRatio="none" aria-hidden="true">
            {edges.map((edge) => {
              const from = nodeMap.get(edge.from); const to = nodeMap.get(edge.to);
              if (!from || !to) return null;
              const critical = from.critical && to.critical && !edge.branch;
              const midY = (from.y + to.y) / 2;
              return <path key={`${edge.from}-${edge.to}`} d={`M ${from.x} ${from.y} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y}`} fill="none" stroke={critical ? CYAN : 'rgba(148,163,184,0.4)'} strokeWidth={critical ? '0.7' : '0.5'} vectorEffect="non-scaling-stroke" opacity={critical ? 0.9 : 0.6} />;
            })}
          </svg>
          {nodes.map((n) => {
            const t = tc(n.tone);
            return (
              <button key={n.id} type="button" onClick={() => onSelectNode(n.id)} className="absolute -translate-x-1/2 -translate-y-1/2" style={{ left: `${n.x}%`, top: `${(n.y / 105) * 100}%` }}>
                <div className={cn('flex min-w-[92px] flex-col items-center rounded-lg border-2 bg-[#0b1120] px-2.5 py-1.5 shadow-lg transition hover:scale-105', n.critical && 'ring-1 ring-cyan-400/40')} style={{ borderColor: t.hex }}>
                  <span className="text-[9px] font-black text-white">{n.label}</span>
                  <span className="text-[7px] font-bold uppercase tracking-wider" style={{ color: t.hex }}>{n.status}</span>
                </div>
              </button>
            );
          })}
        </div>
        <div className="pointer-events-none absolute bottom-2 left-3 text-[8px] font-mono uppercase tracking-widest text-white/25">drag to pan · zoom {Math.round(scale * 100)}%</div>
      </div>
    </SectionCard>
  );
}

function IconBtn({ onClick, icon: Icon }: { onClick: () => void; icon: LucideIcon }) {
  return <button type="button" onClick={onClick} className="rounded-md border border-white/10 bg-white/5 p-1.5 text-white/60 transition hover:border-cyan-400/40 hover:text-cyan-300"><Icon className="h-3.5 w-3.5" /></button>;
}

/* ================================================================== */
/* 9 — Orchestrator Live Telemetry (engine metrics + agents)          */
/* ================================================================== */

export function OrchestratorTelemetry({ orch, live }: { orch: OrchestratorSnapshot; live: boolean }) {
  const m = orch.metrics;
  const tiles: Array<[string, string, OpsTone]> = [
    ['Throughput', m.throughputPerMin != null ? `${m.throughputPerMin.toFixed(1)}/min` : '—', 'neutral'],
    ['Worker Util', pct(m.workerUtilizationPct), 'neutral'],
    ['Active Workers', numberFmt(m.activeWorkers), 'info'],
    ['Agents Online', `${m.agentsOnline}/${m.agentsOnline + m.agentsDegraded + m.agentsOffline || 1}`, m.agentsOffline > 0 ? 'warning' : 'good'],
    ['Reclaimed Leases', numberFmt(m.reclaimedLeases), 'neutral'],
    ['Dead-Letter', numberFmt(m.deadLetter), m.deadLetter > 0 ? 'critical' : 'good'],
  ];
  return (
    <SectionCard title="Live Telemetry" icon={Activity} live={live} right={<Chip tone="info">tier {orch.scaleTier}</Chip>}>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {tiles.map(([label, value, tone]) => (
          <div key={label} className="rounded-lg border border-white/5 bg-black/20 p-2.5">
            <div className="text-[8px] font-black uppercase tracking-wider text-white/40">{label}</div>
            <div className={cn('mt-1 text-base font-black', tc(tone).text)}>{value}</div>
          </div>
        ))}
      </div>
      {orch.agents.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[520px] text-left">
            <thead className="border-b border-white/10 text-[8px] font-black uppercase tracking-widest text-cyan-300/70"><tr>{['Agent', 'Status', 'Leased Jobs', 'Last Seen'].map((h) => <th key={h} className="px-2 py-2">{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-white/5 text-[10px] font-semibold text-white/60">
              {orch.agents.slice(0, 8).map((a) => (
                <tr key={a.id}>
                  <td className="px-2 py-2 text-white/80">{a.name}</td>
                  <td className={cn('px-2 py-2 font-black uppercase', a.status === 'online' ? 'text-emerald-400' : a.status === 'degraded' ? 'text-amber-400' : 'text-white/40')}>{a.status}</td>
                  <td className="px-2 py-2">{a.leasedJobs}</td>
                  <td className="px-2 py-2 font-mono text-[9px] text-white/45">{a.lastSeenAt ? new Date(a.lastSeenAt).toLocaleTimeString('en-US', { hour12: false }) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

/* ================================================================== */
/* 14 — Automation Analytics                                         */
/* ================================================================== */

export function AutomationAnalytics({ series }: { series: AnalyticSeries[] }) {
  return (
    <SectionCard title="Automation Analytics" icon={Gauge}>
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
        {series.map((s) => {
          const t = tc(s.tone);
          return (
            <div key={s.key} className="rounded-xl border border-white/5 bg-black/20 p-3">
              <div className="text-[8px] font-black uppercase leading-tight tracking-wider text-white/40">{s.label}</div>
              <div className={cn('mt-1 text-lg font-black', t.text)}>{s.value}</div>
              <div className="mt-1.5 h-[26px]">
                {s.series.length > 1 ? <Sparkline values={s.series} color={t.hex} height={26} /> : <div className="flex h-full items-center text-[8px] font-mono uppercase tracking-widest text-white/20">{s.measured ? 'point-in-time' : 'no series'}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 15 — Kanban Task Board (drag & drop)                              */
/* ================================================================== */

export function KanbanBoard({ columns, onMove, onSelect }: { columns: KanbanColumn[]; onMove: (id: string, col: KanbanColumnId) => void; onSelect: (id: string) => void }) {
  const [dragId, setDragId] = useState<string | null>(null);
  const [over, setOver] = useState<KanbanColumnId | null>(null);
  return (
    <SectionCard title="Task Board" icon={Layers} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{columns.reduce((s, c) => s + c.workflows.length, 0)} tasks</span>}>
      <div className="overflow-x-auto">
        <div className="flex min-w-[1100px] gap-2.5">
          {columns.map((col) => {
            const t = tc(col.tone);
            return (
              <div
                key={col.id}
                onDragOver={(e) => { e.preventDefault(); setOver(col.id); }}
                onDragLeave={() => setOver((o) => (o === col.id ? null : o))}
                onDrop={() => { if (dragId) onMove(dragId, col.id); setDragId(null); setOver(null); }}
                className={cn('flex-1 rounded-xl border bg-white/[0.02] p-2 transition', over === col.id ? 'border-cyan-400/60 bg-cyan-500/[0.06]' : t.border)}
              >
                <div className="mb-2 flex items-center justify-between px-1">
                  <span className={cn('text-[9px] font-black uppercase tracking-wider', t.text)}>{col.label}</span>
                  <span className="rounded-full bg-white/10 px-1.5 text-[9px] font-black text-white/60">{col.workflows.length}</span>
                </div>
                <div className="space-y-1.5">
                  {col.workflows.length === 0 ? (
                    <div className="rounded-lg border border-dashed border-white/10 py-4 text-center text-[8px] font-bold uppercase tracking-widest text-white/20">empty</div>
                  ) : col.workflows.slice(0, 12).map((w) => (
                    <div
                      key={w.id}
                      draggable
                      onDragStart={() => setDragId(w.id)}
                      onDragEnd={() => setDragId(null)}
                      onClick={() => onSelect(w.id)}
                      className="cursor-grab rounded-lg border border-white/10 bg-black/30 p-2 transition hover:border-cyan-400/40 active:cursor-grabbing"
                    >
                      <div className="flex items-center gap-1.5">
                        <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', tc(w.priority === 'Critical' ? 'critical' : w.priority === 'High' ? 'warning' : 'neutral').dot)} />
                        <span className="truncate text-[9px] font-bold text-white/80">{w.asset}</span>
                      </div>
                      <div className="mt-1 flex items-center justify-between text-[7.5px] font-bold uppercase tracking-wider text-white/35">
                        <span>{w.wave}</span><span>{pct(w.progress)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 16 — Live Event Stream                                            */
/* ================================================================== */

export function EventStreamPanel({ events }: { events: OrchEvent[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);
  const [cat, setCat] = useState<string>('all');
  const cats = useMemo(() => ['all', ...Array.from(new Set(events.map((e) => e.category)))], [events]);
  const shown = useMemo(() => (cat === 'all' ? events : events.filter((e) => e.category === cat)), [events, cat]);

  useEffect(() => {
    if (paused || shown.length === 0) return;
    const el = ref.current; if (!el) return;
    let raf = 0;
    const step = () => { if (el.scrollHeight - el.clientHeight - el.scrollTop < 1) el.scrollTop = 0; else el.scrollTop += 0.35; raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [paused, shown.length]);

  return (
    <SectionCard title="Live Event Stream" icon={Zap} live={events.length > 0} right={
      <div className="flex items-center gap-2">
        <select value={cat} onChange={(e) => setCat(e.target.value)} className="rounded-md border border-white/10 bg-black/30 px-1.5 py-0.5 text-[8.5px] font-bold text-white/60 focus:outline-none">
          {cats.map((c) => <option key={c} value={c} className="bg-[#0b1120]">{c}</option>)}
        </select>
        <button type="button" onClick={() => setPaused((p) => !p)} className="text-[8.5px] font-black uppercase tracking-wider text-white/40 hover:text-cyan-300">{paused ? 'Resume' : 'Pause'}</button>
      </div>
    }>
      <div ref={ref} onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)} className="max-h-[320px] space-y-1 overflow-y-auto pr-1">
        {shown.length === 0 ? (
          <div className="py-8 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No events.</div>
        ) : shown.map((e) => {
          const t = tc(e.tone);
          return (
            <div key={e.id} className="flex items-start gap-2 rounded-lg border border-white/5 bg-black/20 px-2.5 py-1.5">
              <span className="w-14 shrink-0 font-mono text-[8.5px] text-white/35">{e.time}</span>
              <span className={cn('w-16 shrink-0 rounded px-1 text-center text-[7.5px] font-black uppercase tracking-wider', t.soft, t.text)}>{e.category}</span>
              <span className="min-w-0 flex-1 truncate text-[10px] font-semibold text-white/65">{e.message}</span>
              <span className="hidden w-24 shrink-0 truncate text-right font-mono text-[8px] text-white/30 sm:block">{e.asset}</span>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 10 — Automation Marketplace                                       */
/* ================================================================== */

export function MarketplacePanel({ templates, onSelect }: { templates: WorkflowTemplate[]; onSelect: (id: string) => void }) {
  return (
    <SectionCard title="Automation Marketplace" icon={Store} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{templates.length} templates</span>}>
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {templates.map((t) => (
          <button key={t.id} type="button" onClick={() => onSelect(t.id)} className="group/tpl rounded-xl border border-white/10 bg-white/[0.02] p-3 text-left transition hover:border-cyan-400/40 hover:bg-white/[0.04]">
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-[11px] font-black text-white/90">{t.name}</span>
              {t.matches > 0 && <span className="shrink-0 rounded-full bg-cyan-500/15 px-1.5 text-[8px] font-black text-cyan-300">{numberFmt(t.matches)} match</span>}
            </div>
            <p className="mt-1 line-clamp-2 text-[9px] font-semibold leading-relaxed text-white/45">{t.description}</p>
            <div className="mt-2 flex flex-wrap gap-1 text-[7.5px] font-bold uppercase tracking-wider text-white/40">
              <span className="rounded border border-white/10 px-1 py-0.5">{t.duration}</span>
              <span className="rounded border border-white/10 px-1 py-0.5">{t.validationSteps} checks</span>
              <span className="rounded border border-white/10 px-1 py-0.5">{t.approvals}</span>
            </div>
            <div className="mt-1.5 flex items-center gap-1 text-[8.5px] font-black uppercase tracking-wider text-cyan-300 opacity-0 transition group-hover/tpl:opacity-100">Deploy <ArrowRight className="h-3 w-3" /></div>
          </button>
        ))}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 11 — Enterprise Scheduler                                         */
/* ================================================================== */

const SCHED_ICON: Record<ScheduleEntry['type'], LucideIcon> = { wave: Layers, recurring: Clock3, freeze: ShieldCheck };

export function SchedulerPanel({ entries }: { entries: ScheduleEntry[] }) {
  return (
    <SectionCard title="Enterprise Scheduler" icon={Calendar} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{entries.length} windows</span>}>
      <div className="relative space-y-2 pl-4">
        <div className="absolute bottom-2 left-[7px] top-2 w-px bg-gradient-to-b from-cyan-400/50 to-transparent" />
        {entries.map((e) => {
          const t = tc(e.tone);
          const Icon = SCHED_ICON[e.type];
          return (
            <div key={e.id} className="relative">
              <span className={cn('absolute -left-[13px] top-2 h-2.5 w-2.5 rounded-full border-2 border-[#0b1120]', t.dot)} />
              <div className={cn('rounded-lg border bg-white/[0.02] p-2.5', t.border)}>
                <div className="flex items-center gap-2">
                  <Icon className={cn('h-3.5 w-3.5', t.text)} />
                  <span className="text-[11px] font-black text-white/85">{e.title}</span>
                  <Chip tone={e.tone}>{e.status}</Chip>
                  <span className="ml-auto font-mono text-[8.5px] text-white/40">{e.window}</span>
                </div>
                <div className="mt-1 pl-5 text-[9px] font-semibold text-white/45">{e.detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 12 — Automation Policies                                          */
/* ================================================================== */

export function PoliciesPanel({ policies, onToggle }: { policies: AutomationPolicy[]; onToggle: (id: string) => void }) {
  return (
    <SectionCard title="Automation Policies" icon={CircuitBoard} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{policies.filter((p) => p.enabled).length}/{policies.length} active</span>}>
      <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
        {policies.map((p) => {
          const t = tc(p.tone);
          return (
            <div key={p.id} className={cn('rounded-xl border bg-white/[0.02] p-3', p.enabled ? t.border : 'border-white/5 opacity-60')}>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={cn('text-[11px] font-black', t.text)}>{p.condition}</span>
                  </div>
                  {p.matches > 0 && <span className="mt-1 inline-block rounded-full bg-cyan-500/15 px-1.5 text-[8px] font-black text-cyan-300">{numberFmt(p.matches)} matching component(s)</span>}
                </div>
                <button type="button" onClick={() => onToggle(p.id)} className={cn('relative h-4 w-7 shrink-0 rounded-full transition', p.enabled ? 'bg-cyan-500/60' : 'bg-white/15')}>
                  <span className={cn('absolute top-0.5 h-3 w-3 rounded-full bg-white transition-all', p.enabled ? 'left-3.5' : 'left-0.5')} />
                </button>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {p.actions.map((a, i) => (
                  <span key={i} className="inline-flex items-center gap-1 rounded border border-white/10 bg-black/20 px-1.5 py-0.5 text-[8px] font-bold text-white/55">
                    {i > 0 && <ArrowRight className="h-2.5 w-2.5 text-white/25" />}{a}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 text-[8px] font-semibold text-white/25">Policy-driven automation — match counts are live scanner evidence. Enabling a rule schedules the action chain on matching assets.</div>
    </SectionCard>
  );
}

/* ================================================================== */
/* 17 — Compliance Mapping                                           */
/* ================================================================== */

export function ComplianceMapPanel({ rows }: { rows: ComplianceRow[] }) {
  return (
    <SectionCard title="Compliance Mapping" icon={ShieldCheck} right={<span className="text-[9px] font-mono uppercase tracking-widest text-white/30">{ORCH_STANDARDS.length} frameworks</span>}>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {rows.map((r) => {
          const t = tc(r.tone);
          return (
            <div key={r.standard} className={cn('rounded-lg border bg-white/[0.02] p-2.5', t.border)}>
              <div className="truncate text-[9px] font-black text-white/80">{r.standard}</div>
              <div className={cn('mt-1 text-[10px] font-black uppercase tracking-wider', t.text)}>{r.status}</div>
              <div className="mt-1.5"><Bar value={r.coverage} color={t.hex} height={3} /></div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* Re-exported reusable sections (identical look + logic across command centers). */
export { DigitalTwinPanel, AuditTrailPanel, AiRecommendationsPanel, type OpsRecommendation } from '../migration_timeline/_ops-sections';
