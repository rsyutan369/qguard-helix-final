'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, ArrowRight, ShieldCheck, Terminal, RotateCcw, FileText, Activity, Users,
  GitBranch, BadgeCheck, ScrollText, Sparkles, Command, CornerDownLeft, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { TONE, type Tone } from '../_components/executive/primitives';
import {
  TONE_HEX, pct, numberFmt, type OpsTone, type TimelineCard, type AssetRow,
  type LiveJob, type DepNode,
} from './_ops-lib';
import type { OpsRecommendation } from './_ops-sections';

export type DrawerSelection =
  | { kind: 'timeline'; card: TimelineCard }
  | { kind: 'asset'; row: AssetRow }
  | { kind: 'job'; job: LiveJob }
  | { kind: 'node'; node: DepNode }
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

function buildModel(sel: DrawerSelection): DrawerModel {
  if (sel.kind === 'timeline') {
    const c = sel.card;
    return {
      title: c.title,
      subtitle: `${c.wave} · ${c.owner}`,
      badges: [
        { label: c.status, tone: c.status === 'completed' ? 'good' : c.status === 'failed' ? 'critical' : 'neutral' },
        { label: c.priority, tone: c.priority === 'Critical' ? 'critical' : c.priority === 'High' ? 'warning' : 'info' },
        { label: `Twin ${c.digitalTwin}`, tone: c.digitalTwin === 'PASS' ? 'good' : 'warning' },
      ],
      groups: [
        { label: 'Overview', icon: FileText, rows: [
          { k: 'Description', v: c.description },
          { k: 'Business Impact', v: c.businessImpact }, { k: 'Risk', v: c.risk.label },
          { k: 'Confidence', v: pct(c.confidence) }, { k: 'Progress', v: pct(c.progress) },
        ]},
        { label: 'Affected Assets & Dependencies', icon: Users, rows: [
          { k: 'Affected Assets', v: numberFmt(c.assets) }, { k: 'Dependencies', v: numberFmt(c.dependencies) },
          { k: 'Scanner Evidence', v: c.scannerEvidence },
        ]},
        { label: 'Algorithms', icon: ShieldCheck, rows: [
          { k: 'Current', v: c.currentAlgo }, { k: 'Target', v: c.targetAlgo },
        ]},
        { label: 'Validation & Rollback', icon: RotateCcw, rows: [
          { k: 'Validation', v: c.validation }, { k: 'Rollback', v: c.rollback },
          { k: 'Downtime', v: c.downtime }, { k: 'Evidence Source', v: c.evidenceSource },
        ]},
      ],
      compliance: c.policy,
      actions: [
        { label: 'Open in Live Migration', href: '/dashboard/live-migration' },
        { label: 'View Migration Plan', href: '/dashboard/migration-planner' },
      ],
      scripts: scriptsFor(c.targetAlgo),
      sophia: c.sophia,
    };
  }
  if (sel.kind === 'asset') {
    const r = sel.row;
    return {
      title: r.name,
      subtitle: `${r.type} · ${r.environment}`,
      badges: [
        { label: r.status, tone: r.status === 'completed' ? 'good' : r.status === 'failed' ? 'critical' : 'neutral' },
        { label: r.criticality, tone: r.risk.tone },
        { label: r.wave, tone: 'info' },
      ],
      groups: [
        { label: 'Overview', icon: FileText, rows: [
          { k: 'Owner', v: r.owner }, { k: 'Business Unit', v: r.businessUnit },
          { k: 'Application', v: r.application }, { k: 'Environment', v: r.environment },
          { k: 'Last Updated', v: r.lastUpdated },
        ]},
        { label: 'Cryptography', icon: ShieldCheck, rows: [
          { k: 'Current', v: r.currentCrypto }, { k: 'Target', v: r.targetCrypto },
          { k: 'Certificate', v: r.certificate }, { k: 'TLS', v: r.tls },
        ]},
        { label: 'Change Management', icon: BadgeCheck, rows: [
          { k: 'CAB Approval', v: r.cabApproval }, { k: 'Maintenance Window', v: r.window },
          { k: 'Rollback', v: r.rollback }, { k: 'Validation', v: r.validation },
        ]},
        { label: 'Dependencies & Risk', icon: GitBranch, rows: [
          { k: 'Dependencies', v: numberFmt(r.dependencies) }, { k: 'Risk Score', v: `${r.riskScore}/100` },
          { k: 'Priority', v: r.priority }, { k: 'Evidence', v: r.evidence },
        ]},
      ],
      compliance: [r.policy],
      actions: [
        { label: 'View Asset', href: `/dashboard/assets?asset=${encodeURIComponent(r.id)}` },
        { label: 'Rescan', href: '/dashboard/scanner' },
        { label: 'Plan Migration', href: '/dashboard/migration-planner' },
      ],
      scripts: scriptsFor(r.targetCrypto),
    };
  }
  if (sel.kind === 'job') {
    const j = sel.job;
    return {
      title: `Job ${j.id}`,
      subtitle: `${j.asset} · ${j.migrationType}`,
      badges: [
        { label: j.health, tone: j.health === 'healthy' ? 'good' : j.health === 'failed' ? 'critical' : 'warning' },
        { label: String(j.phase).replace('_', ' '), tone: 'neutral' },
      ],
      groups: [
        { label: 'Live State', icon: Activity, rows: [
          { k: 'Migration', v: pct(j.migrationPct) }, { k: 'Validation', v: pct(j.validationPct) },
          { k: 'Latency', v: j.latency }, { k: 'Duration', v: j.duration },
          { k: 'Downtime', v: j.downtime }, { k: 'Retries', v: String(j.retryCount) },
        ]},
        { label: 'Assignment', icon: Users, rows: [
          { k: 'Operator', v: j.operator }, { k: 'Business Unit', v: j.businessUnit },
        ]},
        { label: 'Algorithms', icon: ShieldCheck, rows: [
          { k: 'Current', v: j.currentAlgo }, { k: 'Target', v: j.targetAlgo },
        ]},
      ],
      compliance: ['NIST SP 800-208', 'CNSA 2.0'],
      actions: [{ label: 'Open Orchestrator', href: '/dashboard/live-migration' }],
      scripts: scriptsFor(j.targetAlgo),
    };
  }
  if (sel.kind === 'node') {
    const n = sel.node;
    return {
      title: n.label,
      subtitle: `Migration order #${n.migrationOrder}`,
      badges: [{ label: `${n.risk}/100 risk`, tone: n.risk >= 65 ? 'critical' : n.risk >= 35 ? 'warning' : 'good' }],
      groups: [
        { label: 'Blast Radius', icon: GitBranch, rows: [
          { k: 'Affected Systems', v: `${n.blastRadius}` }, { k: 'Components', v: n.detail },
          { k: 'Migration Order', v: `#${n.migrationOrder}` }, { k: 'Estimated Downtime', v: '0s (hybrid)' },
        ]},
        { label: 'Algorithms', icon: ShieldCheck, rows: [{ k: 'Path', v: n.algorithms }] },
      ],
      compliance: ['NIST SP 1800-38'],
      actions: [{ label: 'Open Exposure Graph', href: '/dashboard/crypto_exposure_map' }],
    };
  }
  const rec = sel.rec;
  return {
    title: rec.title,
    subtitle: `Sophia AI · ${rec.category}`,
    badges: [{ label: rec.priority <= 1 ? 'Critical' : rec.priority === 2 ? 'High' : 'Medium', tone: rec.priority <= 1 ? 'critical' : rec.priority === 2 ? 'warning' : 'ai' }],
    groups: [
      { label: 'Recommendation', icon: Sparkles, rows: [
        { k: 'Rationale', v: rec.description }, { k: 'Recommended Action', v: rec.action },
        { k: 'Estimated Effort', v: rec.estimatedEffort },
      ]},
    ],
    compliance: ['NIST SP 1800-38'],
    actions: [{ label: 'Apply', href: rec.route }],
    sophia: rec.description,
  };
}

function scriptsFor(target: string): { migrate: string[]; rollback: string[] } {
  return {
    migrate: [
      '# Hybrid PQC cutover (zero-downtime, snapshot-backed)',
      'qguard snapshot create --asset $ASSET   # pre-change crypto-state backup',
      `qguard migrate enable-hybrid --target "${target}"`,
      'qguard validate --interop --tls-handshake --cert-chain',
      'qguard cutover promote --canary 10% --observe 15m',
      'qguard cutover promote --full',
    ],
    rollback: [
      '# Automated rollback from verified snapshot',
      'qguard rollback --asset $ASSET --to-snapshot latest',
      'qguard validate --post-rollback',
    ],
  };
}

export function DetailsDrawer({ selection, onClose }: { selection: DrawerSelection | null; onClose: () => void }) {
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
                  <div className="mb-1 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-wider text-violet-300"><Sparkles className="h-3 w-3" />Sophia Insight</div>
                  <p className="text-[11px] font-semibold leading-relaxed text-white/60">{model.sophia}</p>
                </div>
              )}

              {model.groups.map((group) => (
                <div key={group.label}>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><group.icon className="h-3 w-3" />{group.label}</div>
                  <div className="space-y-1 rounded-xl border border-white/5 bg-black/20 p-3">
                    {group.rows.map((row) => (
                      <div key={row.k} className="flex items-start justify-between gap-3 text-[10px]">
                        <span className="shrink-0 font-bold text-white/35">{row.k}</span>
                        <span className="text-right font-semibold text-white/75">{row.v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {model.scripts && (
                <div>
                  <div className="mb-1.5 flex items-center gap-1.5 text-[9px] font-black uppercase tracking-widest text-cyan-300/70"><Terminal className="h-3 w-3" />Migration Plan Preview</div>
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

/* ------------------------------------------------------------------ */
/* Command palette                                                     */
/* ------------------------------------------------------------------ */

export interface Command {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => `${c.label} ${c.hint ?? ''}`.toLowerCase().includes(q));
  }, [query, commands]);

  useEffect(() => { if (open) { setQuery(''); setActive(0); setTimeout(() => inputRef.current?.focus(), 30); } }, [open]);
  useEffect(() => { setActive(0); }, [query]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(filtered.length - 1, a + 1)); }
      if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
      if (e.key === 'Enter') { e.preventDefault(); const cmd = filtered[active]; if (cmd) { cmd.run(); onClose(); } }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, active, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-sm" />
          <motion.div initial={{ opacity: 0, y: -20, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -20, scale: 0.98 }} className="fixed left-1/2 top-24 z-[70] w-full max-w-lg -translate-x-1/2 px-4">
            <div className="overflow-hidden rounded-2xl border border-cyan-400/20 bg-[#0a0f1e] shadow-[0_30px_80px_rgba(0,0,0,0.7)]">
              <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
                <Command className="h-4 w-4 text-cyan-300" />
                <input ref={inputRef} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Jump to section, run action…" className="flex-1 bg-transparent text-sm text-white placeholder:text-white/30 focus:outline-none" />
                <kbd className="rounded border border-white/15 px-1.5 py-0.5 text-[8px] font-black uppercase text-white/40">Esc</kbd>
              </div>
              <div className="max-h-[320px] overflow-y-auto p-2">
                {filtered.length === 0 ? (
                  <div className="py-6 text-center text-[10px] font-black uppercase tracking-widest text-white/30">No matching commands.</div>
                ) : filtered.map((cmd, i) => (
                  <button
                    key={cmd.id}
                    type="button"
                    onMouseEnter={() => setActive(i)}
                    onClick={() => { cmd.run(); onClose(); }}
                    className={cn('flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition', i === active ? 'bg-cyan-500/15' : 'hover:bg-white/5')}
                  >
                    <span className={cn('text-[11px] font-bold', i === active ? 'text-cyan-200' : 'text-white/70')}>{cmd.label}</span>
                    <span className="flex items-center gap-2">
                      {cmd.hint && <span className="text-[8px] font-black uppercase tracking-wider text-white/25">{cmd.hint}</span>}
                      {i === active && <CornerDownLeft className="h-3 w-3 text-cyan-300" />}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
