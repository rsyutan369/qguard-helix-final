'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  AlertTriangle, ArrowRight, Beaker, Calculator, ExternalLink, Loader2, Play, Sparkles, X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Bar, TONE, type Tone as PrimitiveTone } from '../_components/executive/primitives';
import type {
  AgilityAssetRow, AgilityBlocker, AgilityDomain, AgilityKpi, ChangeImpactPreview,
  CouplingFinding, CouplingNode, CryptoAgilityIntelligence, ReplaceabilityRow, RuntimeCryptoEvent,
} from '@/lib/crypto-agility/agility-intelligence';
import { AGILITY_STATE_DEFINITION, CONTROL_DOMAIN_LABEL, COUPLING_LAYER_LABEL } from '@/lib/crypto-agility/agility-intelligence';
import {
  AGILITY_STATE_LABEL, CONTROL_DOMAIN_TONE, MIGRATION_READINESS_LABEL, READINESS_TONE,
  REPLACEABILITY_GLYPH, REPLACEABILITY_LABEL, REPLACEABILITY_TONE, SEVERITY_TONE, STATE_GLYPH,
  STATE_TONE, TONE_HEX, confidenceLabel, domainTone, numberFmt, pctFmt, relativeTime, scoreFmt,
  type Tone,
} from './_agility-lib';
import { Chip, StateChip } from './_agility-sections';

/* ================================================================== */
/* Selection model                                                     */
/* ================================================================== */

export type AgilitySelection =
  | { kind: 'asset'; asset: AgilityAssetRow }
  | { kind: 'domain'; domain: AgilityDomain }
  | { kind: 'blocker'; blocker: AgilityBlocker }
  | { kind: 'coupling'; finding: CouplingFinding }
  | { kind: 'replaceability'; row: ReplaceabilityRow }
  | { kind: 'node'; node: CouplingNode }
  | { kind: 'event'; event: RuntimeCryptoEvent }
  | { kind: 'kpi'; kpi: AgilityKpi };

/* ================================================================== */
/* Drawer shell                                                        */
/* ================================================================== */

function DrawerShell({ title, subtitle, tone, onClose, children, footer }: {
  title: string; subtitle: string; tone: Tone; onClose: () => void; children: ReactNode; footer?: ReactNode;
}) {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const t = TONE[tone as PrimitiveTone];

  return (
    <>
      <motion.div
        initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 z-[70] bg-black/55 backdrop-blur-[2px]"
        onClick={onClose}
        aria-hidden="true"
      />
      <motion.div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        initial={reduce ? false : { x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', stiffness: 380, damping: 36 }}
        className="fixed right-0 top-0 z-[71] flex h-full w-full max-w-[560px] flex-col border-l border-white/10 bg-[#080e1b] shadow-[0_0_80px_rgba(0,0,0,0.7)] outline-none"
      >
        <div className={cn('flex items-start justify-between gap-3 border-b border-white/10 p-4', t.soft)}>
          <div className="min-w-0">
            <h2 className={cn('truncate text-[15px] font-black leading-tight', t.text)}>{title}</h2>
            <p className="mt-0.5 truncate text-[10px] font-semibold uppercase tracking-wider text-white/40">{subtitle}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close details" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-white/45 transition hover:bg-white/10 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 space-y-3 overflow-y-auto p-4 scrollbar-thin">{children}</div>
        {footer && <div className="border-t border-white/10 bg-black/30 p-3">{footer}</div>}
      </motion.div>
    </>
  );
}

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
      <div className="text-[8px] font-black uppercase tracking-widest text-cyan-300/60">{label}</div>
      <div className={cn('mt-0.5 break-words text-[11px] font-bold text-white/80', mono && 'font-mono')}>{value}</div>
    </div>
  );
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[9px] font-black uppercase tracking-[0.16em] text-white/40">{title}</div>
      {children}
    </div>
  );
}

function LinkButton({ href, children, primary }: { href: string; children: ReactNode; primary?: boolean }) {
  return (
    <a
      href={href}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 text-[9px] font-black uppercase tracking-wider no-underline transition',
        primary ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25' : 'border-white/12 bg-white/5 text-white/60 hover:border-cyan-400/40 hover:text-cyan-300',
      )}
    >
      {children}
    </a>
  );
}

/* ================================================================== */
/* Detail drawer                                                       */
/* ================================================================== */

export function AgilityDrawer({
  selection, onClose, onAsk, onSimulate,
}: {
  selection: AgilitySelection | null;
  onClose: () => void;
  onAsk: (question: string) => void;
  onSimulate: (assetId: string) => void;
}) {
  return (
    <AnimatePresence>
      {selection && <DrawerBody selection={selection} onClose={onClose} onAsk={onAsk} onSimulate={onSimulate} />}
    </AnimatePresence>
  );
}

function DrawerBody({ selection, onClose, onAsk, onSimulate }: {
  selection: AgilitySelection; onClose: () => void; onAsk: (question: string) => void; onSimulate: (assetId: string) => void;
}) {
  if (selection.kind === 'asset') {
    const a = selection.asset;
    return (
      <DrawerShell
        title={a.name}
        subtitle={`${a.type} · ${a.environment} · owner ${a.owner}`}
        tone={STATE_TONE[a.agilityState]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => onSimulate(a.id)} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">
              <Beaker className="h-3 w-3" /> Test change impact
            </button>
            <LinkButton href={`/dashboard/migration-planner?asset=${encodeURIComponent(a.id)}`}>Open Migration Planner</LinkButton>
            <LinkButton href={`/dashboard/assets?asset=${encodeURIComponent(a.id)}`}>View asset</LinkButton>
            <button type="button" onClick={() => onAsk(`For the asset "${a.name}": why is its crypto agility state ${AGILITY_STATE_LABEL[a.agilityState]}, and what is the fastest way to make it configuration-replaceable?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-1.5">
          <StateChip state={a.agilityState} />
          <Chip tone={REPLACEABILITY_TONE[a.replaceability]} glyph={REPLACEABILITY_GLYPH[a.replaceability]}>{a.replaceabilityLabel}</Chip>
          <Chip tone={READINESS_TONE[a.readiness]}>{MIGRATION_READINESS_LABEL[a.readiness]}</Chip>
          <Chip tone={CONTROL_DOMAIN_TONE[a.controlDomain]}>{CONTROL_DOMAIN_LABEL[a.controlDomain]}</Chip>
          {a.internetFacing && <Chip tone="warning">Internet-facing</Chip>}
          {a.hasEvidence && !a.couplingAssessed && (
            <Chip tone="warning" title="Only transport/certificate evidence exists — application-level coupling was never assessed.">Coupling not assessed</Chip>
          )}
        </div>

        {a.hasEvidence && !a.couplingAssessed && (
          <div className="rounded-lg border border-amber-400/25 bg-amber-500/[0.07] p-2.5">
            <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-amber-300">
              <AlertTriangle className="h-3 w-3" /> Assessed from the edge only
            </div>
            <p className="mt-1 text-[10.5px] leading-relaxed text-white/55">
              This asset carries transport and certificate evidence but no source, library or runtime visibility. Nothing here could have revealed hard-coded cryptography inside the application, so the absence of coupling findings is <strong className="text-white/75">not</strong> evidence of decoupling. Its verdict is capped at Conditional until a source or agent scan runs.
            </p>
            <a href="/dashboard/scanner" className="mt-1.5 inline-flex items-center gap-1 rounded border border-amber-400/40 bg-amber-500/10 px-2 py-1 text-[8.5px] font-black uppercase tracking-wider text-amber-200 no-underline">
              Run a source / agent scan <ArrowRight className="h-2.5 w-2.5" />
            </a>
          </div>
        )}

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Field label="Agility score" value={scoreFmt(a.agilityScore, '/100')} mono />
          <Field label="Risk score" value={`${a.riskScore}/100`} mono />
          <Field label="Priority" value={a.priority} />
          <Field label="Dependencies" value={numberFmt(a.dependencies)} mono />
          <Field label="Components" value={`${numberFmt(a.componentCount)} (${numberFmt(a.vulnerableComponentCount)} vulnerable)`} mono />
          <Field label="Migration status" value={a.migrationStatus} />
          <Field label="Criticality" value={a.businessCriticality} />
          <Field label="Coupling findings" value={numberFmt(a.couplingFindings)} mono />
          <Field label="Last evidence" value={relativeTime(a.lastEvidenceAt)} />
        </div>

        <Block title="Current → target cryptography">
          <div className="space-y-1">
            <div className="rounded-lg border border-white/8 bg-black/25 px-2.5 py-2">
              <div className="font-mono text-[11px] text-white/75">{a.currentAlgorithms.join(', ') || 'No algorithm resolved'}</div>
              <div className="mt-1 font-mono text-[11px] text-cyan-300">→ {a.targetAlgorithms.join(', ') || 'No replacement required'}</div>
            </div>
          </div>
        </Block>

        {a.blockerReasons.length > 0 && (
          <Block title="What is blocking the change">
            <ul className="space-y-1">
              {a.blockerReasons.map((reason, index) => (
                <li key={index} className="flex items-start gap-2 rounded-lg border border-amber-400/20 bg-amber-500/[0.06] px-2.5 py-1.5 text-[10.5px] leading-relaxed text-white/65">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </Block>
        )}

        <Block title="Derivation">
          <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/45">{a.basis}</p>
        </Block>
      </DrawerShell>
    );
  }

  if (selection.kind === 'domain') {
    const d = selection.domain;
    const tone = domainTone(d);
    return (
      <DrawerShell
        title={d.label}
        subtitle={`Weight ${d.weight} · ${confidenceLabel(d.confidence)}`}
        tone={tone}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href={d.route} primary>Open owning module <ExternalLink className="h-3 w-3" /></LinkButton>
            <button type="button" onClick={() => onAsk(`Why is our ${d.label} scored ${d.score === null ? 'as Insufficient Evidence' : `${d.score}/100`}? What would raise it fastest?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[11px] leading-relaxed text-white/60">{d.question}</p>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Field label="Score" value={d.score === null ? 'Insufficient Evidence' : `${d.score}/100`} mono />
          <Field label="Agility state" value={AGILITY_STATE_LABEL[d.state]} />
          <Field label="Evidence coverage" value={`${d.evidenceCoverage}%`} mono />
          <Field label="Risk" value={d.risk === null ? 'Unknown' : `${d.risk}/100 (${d.riskLevel})`} mono />
          <Field label="Blockers" value={numberFmt(d.blockers)} mono />
          <Field label="Affected assets" value={numberFmt(d.affectedAssets)} mono />
        </div>

        {d.score !== null && (
          <Block title="Improvement opportunity">
            <div className="rounded-lg border border-emerald-400/20 bg-emerald-500/[0.06] p-2.5">
              <div className="font-mono text-[18px] font-black text-emerald-300">+{d.improvementOpportunity} pts</div>
              <p className="mt-0.5 text-[10px] text-white/45">Maximum headline-score gain if this domain reached 100/100, given its weight of {d.weight}.</p>
            </div>
          </Block>
        )}

        <Block title="Evidence basis">
          <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/55">{d.basis}</p>
        </Block>

        {d.actions.length > 0 && (
          <Block title="Recommended actions">
            <ul className="space-y-1">
              {d.actions.map((action, index) => (
                <li key={index} className="flex items-start gap-2 rounded-lg border border-cyan-400/20 bg-cyan-500/[0.05] px-2.5 py-1.5 text-[10.5px] leading-relaxed text-white/65">
                  <ArrowRight className="mt-0.5 h-3 w-3 shrink-0 text-cyan-300" />
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </Block>
        )}
      </DrawerShell>
    );
  }

  if (selection.kind === 'blocker') {
    const b = selection.blocker;
    return (
      <DrawerShell
        title={b.title}
        subtitle={`${b.categoryLabel} · ${b.count} finding(s)`}
        tone={SEVERITY_TONE[b.severity]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href={b.route} primary>Remediate <ArrowRight className="h-3 w-3" /></LinkButton>
            <LinkButton href="/dashboard/quantum-remediation">Create remediation plan</LinkButton>
            <button type="button" onClick={() => onAsk(`What is the fastest way to clear our ${b.categoryLabel.toLowerCase()} blockers, and which assets should we start with?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-1.5">
          <Chip tone={SEVERITY_TONE[b.severity]}>{b.severity}</Chip>
          <Chip tone={CONTROL_DOMAIN_TONE[b.controlDomain]}>{CONTROL_DOMAIN_LABEL[b.controlDomain]}</Chip>
          <Chip tone="info">{b.count} finding(s)</Chip>
        </div>

        <Block title="Business impact"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/60">{b.businessImpact}</p></Block>
        <Block title="Recommended remediation"><p className="rounded-lg border border-cyan-400/20 bg-cyan-500/[0.05] p-2.5 text-[10.5px] leading-relaxed text-white/65">{b.remediation}</p></Block>

        <div className="grid grid-cols-2 gap-2">
          <Field label="Owner" value={b.owner} />
          <Field label="Affected assets" value={numberFmt(b.affectedAssetIds.length)} mono />
        </div>

        {b.affectedAssets.length > 0 && (
          <Block title="Affected assets">
            <div className="flex flex-wrap gap-1">
              {b.affectedAssets.map((asset) => (
                <span key={asset} className="rounded border border-white/10 bg-black/25 px-2 py-1 font-mono text-[9.5px] text-white/55">{asset}</span>
              ))}
            </div>
          </Block>
        )}

        <Block title="Evidence basis"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/45">{b.basis}</p></Block>
      </DrawerShell>
    );
  }

  if (selection.kind === 'coupling') {
    const f = selection.finding;
    return (
      <DrawerShell
        title={f.title}
        subtitle={`${f.asset} · ${f.environment}`}
        tone={SEVERITY_TONE[f.severity]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href={f.route} primary>Open asset <ArrowRight className="h-3 w-3" /></LinkButton>
            {f.assetId && !f.assetId.startsWith('cert:') && !f.assetId.startsWith('sr:') && (
              <button type="button" onClick={() => onSimulate(f.assetId)} className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25">
                <Beaker className="h-3 w-3" /> Test change impact
              </button>
            )}
            <button type="button" onClick={() => onAsk(`Explain this crypto coupling finding on ${f.asset}: "${f.title}" (evidence: ${f.evidence}). What is the remediation and how much would it improve our agility score?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-1.5">
          <Chip tone={SEVERITY_TONE[f.severity]}>{f.severity}</Chip>
          <Chip tone={CONTROL_DOMAIN_TONE[f.controlDomain]}>{CONTROL_DOMAIN_LABEL[f.controlDomain]}</Chip>
          <Chip tone="info">{f.type}</Chip>
        </div>

        <Block title="Evidence">
          <div className="rounded-lg border border-white/8 bg-black/30 p-2.5">
            <div className="break-all font-mono text-[10.5px] text-cyan-300/80">{f.evidence}</div>
            <div className="mt-1 text-[9px] uppercase tracking-wider text-white/30">Source: {f.evidenceSource}</div>
          </div>
        </Block>

        <div className="grid grid-cols-2 gap-2">
          <Field label="Owner" value={f.owner} />
          <Field label="Dependencies" value={numberFmt(f.dependencyCount)} mono />
          <Field label="Agility impact" value={`${f.agilityImpact}/100`} mono />
          <Field label="Impact class" value={f.agilityImpactLabel} />
        </div>

        <div><Bar value={f.agilityImpact} color={TONE_HEX[SEVERITY_TONE[f.severity]]} height={6} /></div>

        <Block title="Recommended remediation"><p className="rounded-lg border border-cyan-400/20 bg-cyan-500/[0.05] p-2.5 text-[10.5px] leading-relaxed text-white/65">{f.remediation}</p></Block>
      </DrawerShell>
    );
  }

  if (selection.kind === 'replaceability') {
    const r = selection.row;
    return (
      <DrawerShell
        title={`${r.currentAlgorithm} → ${r.proposedReplacement}`}
        subtitle={`${r.standard} · ${r.assets} asset(s), ${r.instances} instance(s)`}
        tone={REPLACEABILITY_TONE[r.replaceability]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href="/dashboard/migration-planner" primary>Open Migration Planner</LinkButton>
            <LinkButton href="/dashboard/migration-sandbox">Run in Migration Sandbox</LinkButton>
            <button type="button" onClick={() => onAsk(`What would happen if we replaced ${r.currentAlgorithm} with ${r.proposedReplacement} across our estate?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-1.5">
          <Chip tone={REPLACEABILITY_TONE[r.replaceability]} glyph={REPLACEABILITY_GLYPH[r.replaceability]}>{r.replaceabilityLabel}</Chip>
          <StateChip state={r.status} />
          <Chip tone={SEVERITY_TONE[r.risk]}>{r.risk} risk</Chip>
          <Chip tone="info">{r.migrationComplexity} complexity</Chip>
        </div>

        <Block title="Why this replacement"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/60">{r.rationale}</p></Block>

        <Block title="Replaceability breakdown (per asset)">
          <div className="space-y-1">
            {(Object.entries(r.breakdown) as Array<[keyof typeof r.breakdown, number]>).filter(([, count]) => count > 0).map(([klass, count]) => (
              <div key={klass} className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-black/25 px-2.5 py-1.5">
                <span className="flex items-center gap-1.5 text-[10.5px] font-bold text-white/70">
                  <span aria-hidden="true">{REPLACEABILITY_GLYPH[klass]}</span>{REPLACEABILITY_LABEL[klass]}
                </span>
                <span className="font-mono text-[11px] font-black text-white/80">{count}</span>
              </div>
            ))}
          </div>
          <p className="mt-1.5 text-[9.5px] leading-relaxed text-white/35">The matrix row adopts the hardest verdict — a swap is only as easy as its most constrained instance.</p>
        </Block>

        <div className="grid grid-cols-2 gap-2">
          <Field label="Dependencies" value={numberFmt(r.dependencies)} mono />
          <Field label="Compatibility" value={r.compatibilityScore === null ? 'Unknown' : `${r.compatibilityScore}/100`} mono />
        </div>

        {r.assetNames.length > 0 && (
          <Block title="Assets running this algorithm">
            <div className="flex flex-wrap gap-1">
              {r.assetNames.map((name) => <span key={name} className="rounded border border-white/10 bg-black/25 px-2 py-1 font-mono text-[9.5px] text-white/55">{name}</span>)}
            </div>
          </Block>
        )}

        <Block title="Derivation"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/45">{r.basis}</p></Block>
      </DrawerShell>
    );
  }

  if (selection.kind === 'node') {
    const n = selection.node;
    return (
      <DrawerShell
        title={n.label}
        subtitle={`${COUPLING_LAYER_LABEL[n.layer]} · ${n.assetCount} asset(s)`}
        tone={STATE_TONE[n.agilityState]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href={n.route} primary>Open module <ExternalLink className="h-3 w-3" /></LinkButton>
            <button type="button" onClick={() => onAsk(`In our crypto dependency graph, "${n.label}" (${COUPLING_LAYER_LABEL[n.layer]}) is ${AGILITY_STATE_LABEL[n.agilityState]}. What depends on it and what must change first?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-1.5">
          <StateChip state={n.agilityState} />
          <Chip tone={REPLACEABILITY_TONE[n.replaceability]} glyph={REPLACEABILITY_GLYPH[n.replaceability]}>{REPLACEABILITY_LABEL[n.replaceability]}</Chip>
          <Chip tone={CONTROL_DOMAIN_TONE[n.controlDomain]}>{CONTROL_DOMAIN_LABEL[n.controlDomain]}</Chip>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Layer" value={COUPLING_LAYER_LABEL[n.layer]} />
          <Field label="Algorithm" value={n.algorithm} mono />
          <Field label="Risk" value={`${n.risk}/100`} mono />
          <Field label="Assets on this node" value={numberFmt(n.assetCount)} mono />
        </div>
        <Block title="Detail"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/60">{n.detail}</p></Block>
        <Block title="Agility state"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/45">{AGILITY_STATE_DEFINITION[n.agilityState]}</p></Block>
      </DrawerShell>
    );
  }

  if (selection.kind === 'event') {
    const e = selection.event;
    return (
      <DrawerShell
        title={e.eventType}
        subtitle={`${e.asset} · ${relativeTime(e.observedAt)}`}
        tone={SEVERITY_TONE[e.severity]}
        onClose={onClose}
        footer={
          <div className="flex flex-wrap gap-2">
            <LinkButton href={e.route} primary>Investigate <ArrowRight className="h-3 w-3" /></LinkButton>
            <LinkButton href="/dashboard/telemetry-correlation">Correlate telemetry</LinkButton>
            <button type="button" onClick={() => onAsk(`Investigate this runtime crypto event on ${e.asset}: ${e.eventType} (${e.algorithm}). Is it a policy violation, and what should we do?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
              <Sparkles className="h-3 w-3" /> Ask Sophia
            </button>
          </div>
        }
      >
        <div className="grid grid-cols-2 gap-2">
          <Field label="Timestamp" value={e.observedAt ? new Date(e.observedAt).toLocaleString() : 'Unknown'} />
          <Field label="Asset" value={e.asset} />
          <Field label="Algorithm" value={e.algorithm} mono />
          <Field label="Source" value={e.source} />
          <Field label="Severity" value={e.severity} />
          <Field label="Status" value={e.status} />
        </div>
      </DrawerShell>
    );
  }

  const k = selection.kpi;
  return (
    <DrawerShell
      title={k.label}
      subtitle={k.detail}
      tone={k.tone as Tone}
      onClose={onClose}
      footer={<LinkButton href={k.route} primary>Open detail <ArrowRight className="h-3 w-3" /></LinkButton>}
    >
      <div className="rounded-lg border border-white/8 bg-black/25 p-3">
        <div className="text-[28px] font-black leading-none text-white">{k.value}</div>
        <div className="mt-1 text-[10px] text-white/45">{k.detail}</div>
      </div>
      <Block title="How this is derived"><p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10.5px] leading-relaxed text-white/55">{k.basis}</p></Block>
    </DrawerShell>
  );
}

/* ================================================================== */
/* Scoring explainer                                                   */
/* ================================================================== */

export function ScoreExplainer({ intel, open, onClose }: { intel: CryptoAgilityIntelligence; open: boolean; onClose: () => void }) {
  const reduce = useReducedMotion();
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[80] bg-black/60 backdrop-blur-[2px]" onClick={onClose} aria-hidden="true" />
          <motion.div
            role="dialog" aria-modal="true" aria-label="How the Crypto Agility Score is calculated"
            initial={reduce ? false : { opacity: 0, scale: 0.97, y: 12 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.97, y: 12 }}
            className="fixed left-1/2 top-1/2 z-[81] max-h-[86vh] w-[min(760px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-2xl border border-white/12 bg-[#080e1b] shadow-[0_0_90px_rgba(0,0,0,0.75)]"
          >
            <div className="flex items-center justify-between gap-3 border-b border-white/10 bg-cyan-500/[0.07] p-4">
              <div className="flex items-center gap-2">
                <Calculator className="h-4 w-4 text-cyan-300" />
                <h2 className="text-[14px] font-black text-white">How the Crypto Agility Score is calculated</h2>
              </div>
              <button type="button" onClick={onClose} aria-label="Close" className="grid h-8 w-8 place-items-center rounded-lg text-white/45 hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></button>
            </div>

            <div className="max-h-[calc(86vh-60px)] space-y-3 overflow-y-auto p-4 scrollbar-thin">
              <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/[0.06] p-3">
                <div className="font-mono text-[11px] leading-relaxed text-cyan-100">{intel.score.formula}</div>
              </div>

              <p className="text-[11px] leading-relaxed text-white/60">{intel.score.explanation}</p>

              <div className="grid grid-cols-3 gap-2">
                <Field label="Measured weight" value={`${intel.score.scoredWeight}%`} mono />
                <Field label="Blocker penalty" value={`−${intel.score.blockerPenalty}`} mono />
                <Field label="Evidence coverage" value={`${intel.evidenceCoverage}%`} mono />
              </div>

              <Block title="Domain contributions">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[520px] border-collapse text-left">
                    <thead>
                      <tr className="border-b border-white/10">
                        {['Domain', 'Weight', 'Score', 'Contribution'].map((h) => (
                          <th key={h} scope="col" className="px-2 py-1.5 text-[8.5px] font-black uppercase tracking-wider text-cyan-300/70">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {intel.score.components.map((component) => (
                        <tr key={component.label} title={component.basis}>
                          <td className="px-2 py-1.5 text-[10.5px] font-bold text-white/75">{component.label}</td>
                          <td className="px-2 py-1.5 font-mono text-[10px] text-white/50">{component.weight}</td>
                          <td className="px-2 py-1.5 font-mono text-[10px]" style={{ color: component.score === null ? 'rgba(255,255,255,0.3)' : '#e2e8f0' }}>
                            {component.score === null ? 'Insufficient Evidence' : component.score}
                          </td>
                          <td className="px-2 py-1.5 font-mono text-[10px] text-cyan-300">{component.score === null ? '—' : `${component.contribution}`}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Block>

              <Block title="Evidence sources">
                <div className="flex flex-wrap gap-1">
                  {intel.evidence.sources.length ? intel.evidence.sources.map((source) => (
                    <span key={source} className="rounded border border-white/10 bg-black/25 px-2 py-1 text-[9.5px] text-white/55">{source}</span>
                  )) : <span className="text-[10px] text-white/35">No evidence source connected.</span>}
                </div>
                <p className="mt-1.5 text-[10px] leading-relaxed text-white/40">{intel.evidence.note}</p>
              </Block>

              <div className="rounded-lg border border-amber-400/25 bg-amber-500/[0.06] p-3">
                <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider text-amber-300"><AlertTriangle className="h-3 w-3" /> Reading the score honestly</div>
                <p className="mt-1 text-[10.5px] leading-relaxed text-white/55">
                  The score describes what has been <strong className="text-white/75">measured</strong>. Domains without evidence are excluded and their weight renormalised rather than scored as zero, so an estate with thin coverage can read well while carrying unmeasured rigidity. Coverage and confidence are shown alongside the score for exactly that reason — and <strong className="text-white/75">Unknown never means safe</strong>.
                </p>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

/* ================================================================== */
/* Change test — sandbox hand-off                                      */
/* ================================================================== */

export function ChangeTestPanel({
  open, assetId, assets, token, onClose, onAsk,
}: {
  open: boolean;
  assetId: string | null;
  assets: AgilityAssetRow[];
  token: string | undefined;
  onClose: () => void;
  onAsk: (question: string) => void;
}) {
  const [selectedAsset, setSelectedAsset] = useState<string>(assetId ?? '');
  const [fromAlgorithm, setFromAlgorithm] = useState('');
  const [toAlgorithm, setToAlgorithm] = useState('');
  const [preview, setPreview] = useState<ChangeImpactPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState<string | null>(null);
  const reduce = useReducedMotion();

  useEffect(() => {
    if (assetId) setSelectedAsset(assetId);
  }, [assetId]);

  const asset = useMemo(() => assets.find((a) => a.id === selectedAsset) ?? null, [assets, selectedAsset]);

  const loadPreview = useCallback(async () => {
    if (!token || !selectedAsset) return;
    setLoading(true);
    setError(null);
    setSubmitted(null);
    try {
      const response = await fetch('/api/v1/crypto-agility/impact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ assetId: selectedAsset, fromAlgorithm: fromAlgorithm || undefined, toAlgorithm: toAlgorithm || undefined }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setPreview(payload.data.preview as ChangeImpactPreview);
    } catch (err) {
      setPreview(null);
      setError(err instanceof Error ? err.message : 'Impact preview unavailable');
    } finally {
      setLoading(false);
    }
  }, [token, selectedAsset, fromAlgorithm, toAlgorithm]);

  useEffect(() => {
    if (open && selectedAsset) void loadPreview();
    // Re-run only when the panel opens or the asset changes; algorithm edits are
    // applied by the explicit "Recompute" action so typing does not spam the API.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, selectedAsset]);

  /** Hands the change to the REAL Migration Sandbox digital twin. */
  const runSimulation = async () => {
    if (!token || !preview) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/sandbox/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          assetIds: [preview.assetId],
          fromAlgo: preview.fromAlgorithm,
          toAlgo: preview.toAlgorithm,
          migrationType: 'crypto_agility_change',
          simulationType: 'full_enterprise_migration',
        }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setSubmitted('Simulation queued in the Migration Sandbox digital twin.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not queue the sandbox simulation');
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <AnimatePresence>
      <motion.div initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[80] bg-black/60 backdrop-blur-[2px]" onClick={onClose} aria-hidden="true" />
      <motion.div
        role="dialog" aria-modal="true" aria-label="Test a cryptographic change"
        initial={reduce ? false : { opacity: 0, scale: 0.97, y: 12 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.97, y: 12 }}
        className="fixed left-1/2 top-1/2 z-[81] max-h-[88vh] w-[min(820px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-2xl border border-white/12 bg-[#080e1b] shadow-[0_0_90px_rgba(0,0,0,0.75)]"
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/10 bg-cyan-500/[0.07] p-4">
          <div className="flex items-center gap-2">
            <Beaker className="h-4 w-4 text-cyan-300" />
            <div>
              <h2 className="text-[14px] font-black text-white">Test Crypto Change</h2>
              <p className="text-[9.5px] uppercase tracking-wider text-white/40">Deterministic impact projection · simulation runs in the Migration Sandbox</p>
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="grid h-8 w-8 place-items-center rounded-lg text-white/45 hover:bg-white/10 hover:text-white"><X className="h-4 w-4" /></button>
        </div>

        <div className="max-h-[calc(88vh-60px)] space-y-3 overflow-y-auto p-4 scrollbar-thin">
          {/* Change definition */}
          <div className="grid gap-2 sm:grid-cols-3">
            <label className="block">
              <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Asset</span>
              <select
                value={selectedAsset}
                onChange={(e) => setSelectedAsset(e.target.value)}
                className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none"
              >
                <option value="" className="bg-[#0b1120]">Select an asset…</option>
                {assets.filter((a) => a.hasEvidence).slice(0, 300).map((a) => (
                  <option key={a.id} value={a.id} className="bg-[#0b1120]">{a.name}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Current algorithm</span>
              <select
                value={fromAlgorithm}
                onChange={(e) => setFromAlgorithm(e.target.value)}
                className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none"
              >
                <option value="" className="bg-[#0b1120]">Auto (highest-risk primitive)</option>
                {(asset?.currentAlgorithms ?? []).map((a) => <option key={a} value={a} className="bg-[#0b1120]">{a}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-[8px] font-black uppercase tracking-widest text-cyan-300/60">Proposed algorithm</span>
              <select
                value={toAlgorithm}
                onChange={(e) => setToAlgorithm(e.target.value)}
                className="h-8 w-full rounded-lg border border-white/10 bg-black/30 px-2 text-[10.5px] text-white/80 focus:border-cyan-400/50 focus:outline-none"
              >
                <option value="" className="bg-[#0b1120]">Platform NIST target</option>
                {(asset?.targetAlgorithms ?? []).map((a) => <option key={a} value={a} className="bg-[#0b1120]">{a}</option>)}
              </select>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void loadPreview()}
              disabled={!selectedAsset || loading}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/5 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-white/65 transition hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-40"
            >
              {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Calculator className="h-3 w-3" />} Recompute impact
            </button>
            {!selectedAsset && <span className="text-[10px] text-white/35">Select an asset to project the change.</span>}
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-[10.5px] text-red-200">{error}</div>
          )}

          {loading && !preview && (
            <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-14 animate-pulse rounded-lg border border-white/8 bg-white/[0.03]" />)}</div>
          )}

          {preview && (
            <>
              <div className="rounded-lg border border-cyan-400/25 bg-cyan-500/[0.06] p-3">
                <div className="font-mono text-[12px] font-black text-white">
                  {preview.fromAlgorithm} <span className="text-cyan-300">→</span> {preview.toAlgorithm}
                </div>
                <div className="mt-0.5 text-[10px] text-white/45">{preview.asset}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                <Field label="Assets affected" value={numberFmt(preview.assetsAffected)} mono />
                <Field label="Dependencies" value={numberFmt(preview.dependencies)} mono />
                <Field label="Compatibility" value={`${preview.compatibility} (${preview.compatibilityScore}/100)`} />
                <Field label="Migration risk" value={`${preview.migrationRisk} (${preview.migrationRiskScore}/100)`} />
                <Field label="Replaceability" value={REPLACEABILITY_LABEL[preview.replaceability]} />
                <Field label="Trust impact" value={preview.trustImpact} />
              </div>

              <Block title="Potential failures">
                <div className="space-y-1">
                  {preview.potentialFailures.map((failure, index) => (
                    <div key={index} className={cn('rounded-lg border bg-white/[0.015] px-2.5 py-2', TONE[SEVERITY_TONE[failure.severity] as PrimitiveTone].border)}>
                      <div className="flex items-center gap-1.5">
                        <span className={cn('text-[10.5px] font-black', TONE[SEVERITY_TONE[failure.severity] as PrimitiveTone].text)}>{failure.label}</span>
                        <Chip tone={SEVERITY_TONE[failure.severity]}>{failure.severity}</Chip>
                      </div>
                      <p className="mt-0.5 text-[10px] leading-relaxed text-white/45">{failure.detail}</p>
                    </div>
                  ))}
                </div>
              </Block>

              {preview.expectedRemediation.length > 0 && (
                <Block title="Expected remediation">
                  <ul className="space-y-1">
                    {preview.expectedRemediation.map((item, index) => (
                      <li key={index} className="flex items-start gap-2 rounded-lg border border-white/8 bg-black/25 px-2.5 py-1.5 text-[10.5px] text-white/60">
                        <ArrowRight className="mt-0.5 h-3 w-3 shrink-0 text-cyan-300" /><span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Block>
              )}

              <p className="rounded-lg border border-white/8 bg-black/25 p-2.5 text-[10px] leading-relaxed text-white/40">{preview.basis}</p>

              {submitted && (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-[10.5px] text-emerald-200">
                  {submitted} <a href="/dashboard/migration-sandbox" className="underline">Open the sandbox to watch it run.</a>
                </div>
              )}

              <div className="flex flex-wrap gap-2 border-t border-white/10 pt-3">
                <button
                  type="button"
                  onClick={() => void runSimulation()}
                  disabled={submitting}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 disabled:opacity-40"
                >
                  {submitting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />} Run simulation in Sandbox
                </button>
                <LinkButton href="/dashboard/migration-planner">Open Migration Planner</LinkButton>
                <button type="button" onClick={() => onAsk(`What would happen if we replaced ${preview.fromAlgorithm} with ${preview.toAlgorithm} on ${preview.asset}?`)} className="inline-flex items-center gap-1.5 rounded-lg border border-violet-400/40 bg-violet-500/10 px-3 py-2 text-[9px] font-black uppercase tracking-wider text-violet-200 transition hover:bg-violet-500/20">
                  <Sparkles className="h-3 w-3" /> Ask Sophia
                </button>
              </div>
            </>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

/* ================================================================== */
/* Command palette                                                     */
/* ================================================================== */

export interface Command {
  id: string;
  label: string;
  hint: string;
  run: () => void;
}

export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => `${c.label} ${c.hint}`.toLowerCase().includes(q));
  }, [commands, query]);

  useEffect(() => { setIndex(0); }, [query]);
  useEffect(() => { if (open) { setQuery(''); setTimeout(() => inputRef.current?.focus(), 30); } }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return; }
      if (event.key === 'ArrowDown') { event.preventDefault(); setIndex((i) => Math.min(filtered.length - 1, i + 1)); }
      if (event.key === 'ArrowUp') { event.preventDefault(); setIndex((i) => Math.max(0, i - 1)); }
      if (event.key === 'Enter') { event.preventDefault(); filtered[index]?.run(); onClose(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, filtered, index, onClose]);

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-[90] bg-black/60 backdrop-blur-[2px]" onClick={onClose} aria-hidden="true" />
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="fixed left-1/2 top-[16vh] z-[91] w-[min(560px,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-xl border border-white/12 bg-[#080e1b] shadow-[0_0_70px_rgba(0,0,0,0.7)]">
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Jump to a section or module…"
          aria-label="Command search"
          className="w-full border-b border-white/10 bg-transparent px-4 py-3 text-[12px] text-white/85 placeholder:text-white/30 focus:outline-none"
        />
        <div className="max-h-[320px] overflow-y-auto py-1 scrollbar-thin">
          {filtered.length === 0 && <div className="px-4 py-6 text-center text-[11px] text-white/35">No matching command</div>}
          {filtered.map((command, i) => (
            <button
              key={command.id}
              type="button"
              onMouseEnter={() => setIndex(i)}
              onClick={() => { command.run(); onClose(); }}
              className={cn('flex w-full items-center justify-between gap-3 px-4 py-2 text-left transition', i === index ? 'bg-cyan-500/12 text-cyan-200' : 'text-white/65 hover:bg-white/5')}
            >
              <span className="truncate text-[11.5px] font-semibold">{command.label}</span>
              <span className="shrink-0 rounded border border-white/10 px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider text-white/30">{command.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
