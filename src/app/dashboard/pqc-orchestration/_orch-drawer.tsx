'use client';

import { useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, ArrowRight, ShieldCheck, Terminal, RotateCcw, FileText, Activity, GitBranch,
  Sparkles, Store, ScrollText, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { TONE, type Tone } from '../_components/executive/primitives';
import { TONE_HEX, pct, numberFmt, type OpsTone, type OrchWorkflow, type WorkflowTemplate, type DagNode } from './_orch-lib';
import type { OpsRecommendation } from '../migration_timeline/_ops-sections';

export type OrchSelection =
  | { kind: 'workflow'; workflow: OrchWorkflow }
  | { kind: 'template'; template: WorkflowTemplate }
  | { kind: 'node'; node: DagNode }
  | { kind: 'rec'; rec: OpsRecommendation };

function tc(tone: OpsTone) {
  const t = TONE[tone as Tone];
  return { text: t.text, soft: t.soft, border: t.border, dot: t.dot, hex: TONE_HEX[tone] };
}

interface DrawerModel {
  title: string;
  subtitle: string;
  badges: Array<{ label: string; tone: OpsTone }>;
  groups: Array<{ label: string; icon: LucideIcon; rows: Array<{ k: string; v: string }> }>;
  compliance: string[];
  actions: Array<{ label: string; href: string }>;
  scripts?: { migrate: string[]; rollback: string[] };
  sophia?: string;
}

function scriptsFor(target: string): { migrate: string[]; rollback: string[] } {
  return {
    migrate: [
      '# Hybrid PQC automation workflow (snapshot-backed, zero-downtime)',
      'qguard snapshot create --asset $ASSET',
      `qguard workflow run --target "${target}" --strategy hybrid`,
      'qguard validate --interop --tls-handshake --cert-chain',
      'qguard cutover promote --canary 10% --observe 15m',
      'qguard cutover promote --full',
    ],
    rollback: ['qguard rollback --asset $ASSET --to-snapshot latest', 'qguard validate --post-rollback'],
  };
}

function buildModel(sel: OrchSelection): DrawerModel {
  if (sel.kind === 'workflow') {
    const w = sel.workflow;
    return {
      title: w.name,
      subtitle: `${w.wave} · ${w.environment}`,
      badges: [
        { label: w.phaseLabel, tone: w.tone },
        { label: w.priority, tone: w.priority === 'Critical' ? 'critical' : w.priority === 'High' ? 'warning' : 'info' },
        { label: `Sim ${w.simulation}`, tone: w.simulation === 'PASS' ? 'good' : 'warning' },
      ],
      groups: [
        { label: 'Overview', icon: FileText, rows: [
          { k: 'Asset', v: w.asset }, { k: 'Business Unit', v: w.businessUnit }, { k: 'Wave', v: w.wave },
          { k: 'Progress', v: pct(w.progress) }, { k: 'AI Confidence', v: pct(w.aiConfidence) },
        ]},
        { label: 'Execution', icon: Activity, rows: [
          { k: 'Phase', v: w.phaseLabel }, { k: 'Agent', v: w.agent }, { k: 'Operator', v: w.operator },
          { k: 'ETA', v: w.eta }, { k: 'Retries', v: String(w.retryCount) }, { k: 'Blocked By', v: numberFmt(w.blockedBy) },
        ]},
        { label: 'Algorithms', icon: ShieldCheck, rows: [
          { k: 'Current', v: w.currentAlgo }, { k: 'Target', v: w.targetAlgo },
        ]},
        { label: 'Validation & Rollback', icon: RotateCcw, rows: [
          { k: 'Validation', v: pct(w.validationPct) }, { k: 'Rollback', v: w.rollback },
          { k: 'Simulation', v: w.simulation }, { k: 'Risk', v: w.risk.label },
        ]},
        { label: 'Dependencies', icon: GitBranch, rows: [
          { k: 'Dependencies', v: numberFmt(w.dependencies) }, { k: 'Assets', v: numberFmt(w.assets) },
        ]},
      ],
      compliance: [w.compliance, 'CNSA 2.0'],
      actions: [
        { label: 'Open in Live Migration', href: '/dashboard/live-migration' },
        { label: 'View Plan', href: '/dashboard/migration-planner' },
      ],
      scripts: scriptsFor(w.targetAlgo),
      sophia: w.risk.label === 'Critical' || w.risk.label === 'High'
        ? `High-priority workflow — schedule ${w.targetAlgo} rollout in the next maintenance window.`
        : 'Nominal — proceed on the standard automation track.',
    };
  }
  if (sel.kind === 'template') {
    const t = sel.template;
    return {
      title: t.name,
      subtitle: `Automation Template · ${t.matches} matching component(s)`,
      badges: [{ label: t.duration, tone: 'neutral' }, { label: `${t.validationSteps} checks`, tone: 'info' }],
      groups: [
        { label: 'Template', icon: Store, rows: [
          { k: 'Description', v: t.description }, { k: 'Estimated Duration', v: t.duration },
          { k: 'Required Approvals', v: t.approvals }, { k: 'Rollback Strategy', v: t.rollback },
          { k: 'Validation Steps', v: String(t.validationSteps) }, { k: 'Live Matches', v: numberFmt(t.matches) },
        ]},
        { label: 'Supported Platforms', icon: GitBranch, rows: t.platforms.map((p) => ({ k: '•', v: p })) },
      ],
      compliance: t.compliance,
      actions: [{ label: 'Deploy Workflow', href: '/dashboard/migration-planner' }],
    };
  }
  if (sel.kind === 'node') {
    const n = sel.node;
    return {
      title: n.label,
      subtitle: `DAG node · ${n.status}`,
      badges: [{ label: n.critical ? 'Critical path' : 'Branch', tone: n.critical ? 'neutral' : 'info' }, { label: n.status, tone: n.tone }],
      groups: [
        { label: 'Node', icon: GitBranch, rows: [{ k: 'Status', v: n.status }, { k: 'Detail', v: n.detail }, { k: 'Critical Path', v: n.critical ? 'Yes' : 'No' }] },
      ],
      compliance: ['NIST SP 1800-38'],
      actions: [{ label: 'Open Migration Timeline', href: '/dashboard/migration-timeline' }],
    };
  }
  const rec = sel.rec;
  return {
    title: rec.title,
    subtitle: `Sophia AI · ${rec.category}`,
    badges: [{ label: rec.priority <= 1 ? 'Critical' : rec.priority === 2 ? 'High' : 'Medium', tone: rec.priority <= 1 ? 'critical' : rec.priority === 2 ? 'warning' : 'ai' }],
    groups: [
      { label: 'Recommendation', icon: Sparkles, rows: [
        { k: 'Reasoning', v: rec.description }, { k: 'Recommended Action', v: rec.action }, { k: 'Estimated Effort', v: rec.estimatedEffort },
      ]},
    ],
    compliance: ['NIST SP 1800-38'],
    actions: [{ label: 'Apply', href: rec.route }],
    sophia: rec.description,
  };
}

export function WorkflowDrawer({ selection, onClose }: { selection: OrchSelection | null; onClose: () => void }) {
  useEffect(() => {
    if (!selection) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selection, onClose]);

  const model = useMemo(() => (selection ? buildModel(selection) : null), [selection]);

  return (
    <AnimatePresence>
      {selection && model && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
          <motion.aside
            initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', stiffness: 320, damping: 34 }}
            className="fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col border-l border-cyan-400/20 bg-[#0a0f1e] shadow-[-20px_0_60px_rgba(0,0,0,0.6)]"
            role="dialog" aria-modal="true"
          >
            <div className="flex items-start justify-between gap-3 border-b border-white/10 p-4">
              <div className="min-w-0">
                <div className="truncate text-sm font-black text-white">{model.title}</div>
                <div className="mt-0.5 truncate text-[10px] font-semibold text-white/40">{model.subtitle}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {model.badges.map((b, i) => {
                    const t = tc(b.tone);
                    return <span key={i} className={cn('rounded-md border px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider', t.text, t.soft, t.border)}>{b.label}</span>;
                  })}
                </div>
              </div>
              <button type="button" onClick={onClose} className="shrink-0 rounded-lg border border-white/10 bg-white/5 p-1.5 text-white/50 transition hover:text-white"><X className="h-4 w-4" /></button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              {model.sophia && (
                <div className="rounded-xl border border-violet-400/25 bg-violet-500/[0.06] p-3">
                  <div className="mb-1 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-wider text-violet-300"><Sparkles className="h-3 w-3" />Sophia Analysis</div>
                  <p className="text-[11px] font-semibold leading-relaxed text-white/60">{model.sophia}</p>
                </div>
              )}

              {model.groups.map((group) => (
                <div key={group.label}>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><group.icon className="h-3 w-3" />{group.label}</div>
                  <div className="space-y-1 rounded-xl border border-white/5 bg-black/20 p-3">
                    {group.rows.map((row, i) => (
                      <div key={`${row.k}-${i}`} className="flex items-start justify-between gap-3 text-[10px]">
                        <span className="shrink-0 font-bold text-white/35">{row.k}</span>
                        <span className="text-right font-semibold text-white/75">{row.v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {model.scripts && (
                <div>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><Terminal className="h-3 w-3" />Workflow Plan Preview</div>
                  <pre className="overflow-x-auto rounded-xl border border-white/5 bg-black/40 p-3 text-[9px] leading-relaxed text-emerald-300/80">{model.scripts.migrate.join('\n')}</pre>
                  <div className="mb-1.5 mt-2 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><RotateCcw className="h-3 w-3" />Rollback Plan</div>
                  <pre className="overflow-x-auto rounded-xl border border-white/5 bg-black/40 p-3 text-[9px] leading-relaxed text-amber-300/80">{model.scripts.rollback.join('\n')}</pre>
                  <div className="mt-1 text-[8px] font-semibold text-white/25">Preview generated from target algorithm. Execution runs server-side via Live Migration Ops.</div>
                </div>
              )}

              <div>
                <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><ScrollText className="h-3 w-3" />Compliance Mapping</div>
                <div className="flex flex-wrap gap-1.5">
                  {model.compliance.map((s) => <span key={s} className="rounded-md border border-blue-500/25 bg-blue-500/10 px-2 py-0.5 text-[8.5px] font-black uppercase tracking-wider text-blue-300">{s}</span>)}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 border-t border-white/10 p-4">
              {model.actions.map((a) => (
                <a key={a.label} href={a.href} className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-1.5 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">{a.label}<ArrowRight className="h-3 w-3" /></a>
              ))}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

/* Command palette is identical across both command centers. */
export { CommandPalette, type Command } from '../migration_timeline/_ops-drawer';
