import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert, Lightbulb, ArrowRight, ExternalLink, FileCheck2,
  ChevronDown, Gauge, BookMarked, Layers, AlertTriangle,
  Target, ListChecks, Microscope, Briefcase, Route, Network,
  Unplug, RotateCcw, TrendingDown, Radar, Cpu,
} from 'lucide-react';
import { SophiaAvatar } from './SophiaAvatar';
import type { CopilotAnswer, CopilotRiskLevel, CopilotToolRun } from '@/types/copilot';

/**
 * SophiaMessage — renders one structured CopilotAnswer.
 *
 * For deep-investigation (investigate-mode) answers it renders the full
 * consultant report: objective, key findings, risk outlook, evidence, root
 * cause, business impact, technical analysis, dependency-safe migration
 * strategy (numbered steps with rationale + breakage), dependencies, potential
 * breakages, rollback strategy, recommendations, proactive findings, next
 * actions, reasoning trace, standards and a confidence meter. Direct-mode
 * answers render the focused subset. Every deep link routes into its module.
 */

const RISK_STYLE: Record<CopilotRiskLevel, { label: string; chip: string; bar: string }> = {
  critical: { label: 'Critical', chip: 'bg-red-500/15 text-red-300 border-red-500/40', bar: 'bg-red-500' },
  high: { label: 'High', chip: 'bg-orange-500/15 text-orange-300 border-orange-500/40', bar: 'bg-orange-500' },
  medium: { label: 'Medium', chip: 'bg-amber-500/15 text-amber-300 border-amber-500/40', bar: 'bg-amber-400' },
  low: { label: 'Low', chip: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40', bar: 'bg-emerald-500' },
  info: { label: 'Informational', chip: 'bg-sky-500/15 text-sky-300 border-sky-500/40', bar: 'bg-sky-500' },
};

const PRIORITY_STYLE: Record<string, string> = {
  immediate: 'bg-red-500/15 text-red-300 border-red-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-200 border-amber-500/40',
  low: 'bg-slate-500/15 text-slate-300 border-slate-500/40',
};

/**
 * Aggregate tool runs into user-facing data sources — one chip per platform
 * module (via the backend-stamped `source` label), best status wins. Raw tool
 * identifiers, row counts and timings are backend internals and never render.
 */
type SourceStatus = 'ok' | 'empty' | 'denied' | 'error';
function aggregateSources(runs: CopilotToolRun[]): Array<{ label: string; status: SourceStatus }> {
  const rank: Record<SourceStatus, number> = { ok: 3, denied: 2, error: 1, empty: 0 };
  const fallbackLabel = (moduleId: string) => moduleId.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  const map = new Map<string, SourceStatus>();
  for (const run of runs) {
    const label = run.source || fallbackLabel(run.module);
    const status: SourceStatus = run.status in rank ? (run.status as SourceStatus) : 'empty';
    const prev = map.get(label);
    if (prev === undefined || rank[status] > rank[prev]) map.set(label, status);
  }
  return [...map.entries()].map(([label, status]) => ({ label, status }));
}

const SOURCE_STATUS_SUFFIX: Record<SourceStatus, string> = {
  ok: '',
  empty: ' · no data yet',
  denied: ' · restricted',
  error: ' · unavailable',
};

function SectionTitle({ icon: Icon, children }: { icon: typeof ShieldAlert; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">
      <Icon className="h-3.5 w-3.5 text-cyan-300/80" />
      <span>{children}</span>
    </div>
  );
}

export function SophiaMessage({ answer }: { answer: CopilotAnswer }) {
  const [showReasoning, setShowReasoning] = useState(false);
  const risk = RISK_STYLE[answer.risk.level] || RISK_STYLE.info;

  return (
    <div className="space-y-3.5">
      {/* Summary */}
      <div className="rounded-xl border border-blue-400/20 bg-gradient-to-br from-blue-500/[0.07] to-violet-500/[0.04] p-4">
        <div className="mb-2 flex items-center gap-2">
          <SophiaAvatar active={false} size={24} />
          <span className="text-[10px] font-black uppercase tracking-[0.2em] text-cyan-300/80">Sophia</span>
          {answer.mode === 'investigate' && !answer.blocked && (
            <span className="flex items-center gap-1 rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-cyan-300">
              <Radar className="h-3 w-3" /> Deep investigation
            </span>
          )}
          {answer.blocked && (
            <span className="ml-auto flex items-center gap-1 rounded-md border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-red-300">
              <AlertTriangle className="h-3 w-3" /> Blocked
            </span>
          )}
        </div>
        {answer.objective && (
          <div className="mb-2.5 flex items-start gap-2 rounded-lg border border-slate-700/40 bg-slate-950/40 px-2.5 py-1.5">
            <Target className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300/70" />
            <p className="text-[11px] leading-relaxed text-slate-400"><span className="font-semibold text-slate-300">What you’re asking:</span> {answer.objective}</p>
          </div>
        )}
        <p className="text-[13px] leading-relaxed text-slate-100">{answer.summary}</p>
      </div>

      {/* Key findings */}
      {answer.keyFindings && answer.keyFindings.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={ListChecks}>Key findings</SectionTitle>
          <ul className="space-y-1 rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
            {answer.keyFindings.map((finding, i) => (
              <li key={i} className="flex gap-2 text-[12px] leading-relaxed text-slate-200">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-cyan-400/70" />
                <span>{finding}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Risk outlook — before → after */}
      {answer.riskOutlook && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
          <SectionTitle icon={TrendingDown}>Risk outlook</SectionTitle>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${(RISK_STYLE[answer.riskOutlook.before] || RISK_STYLE.info).chip}`}>{(RISK_STYLE[answer.riskOutlook.before] || RISK_STYLE.info).label} now</span>
            <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${(RISK_STYLE[answer.riskOutlook.after] || RISK_STYLE.info).chip}`}>{(RISK_STYLE[answer.riskOutlook.after] || RISK_STYLE.info).label} after remediation</span>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-slate-400">{answer.riskOutlook.detail}</p>
        </div>
      )}

      {/* Risk + confidence */}
      {(answer.risk.level !== 'info' || answer.risk.drivers.length > 0) && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${risk.chip}`}>
              {risk.label} risk{typeof answer.risk.score === 'number' ? ` · ${answer.risk.score}/100` : ''}
            </span>
            {answer.risk.drivers.slice(0, 3).map((driver, i) => (
              <span key={i} className="text-[11px] text-slate-400">• {driver}</span>
            ))}
          </div>
        </div>
      )}

      {/* Evidence */}
      {answer.evidence.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={FileCheck2}>Evidence</SectionTitle>
          <div className="grid gap-2 sm:grid-cols-2">
            {answer.evidence.map((item, i) => {
              const inner = (
                <div className="h-full rounded-lg border border-slate-700/50 bg-slate-900/40 p-2.5 transition-colors hover:border-cyan-400/40 hover:bg-slate-900/70">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{item.module}</span>
                    {item.deepLink && <ExternalLink className="h-3 w-3 text-slate-600" />}
                  </div>
                  <div className="mt-1 text-[12px] font-semibold text-slate-100">{item.value}</div>
                  <div className="text-[11px] text-slate-400">{item.label}</div>
                  {item.detail && <div className="mt-0.5 text-[10px] text-slate-500">{item.detail}</div>}
                </div>
              );
              return item.deepLink ? (
                <Link key={i} to={item.deepLink} className="no-underline">{inner}</Link>
              ) : (
                <div key={i}>{inner}</div>
              );
            })}
          </div>
        </div>
      )}

      {/* Root cause */}
      {answer.rootCause && (
        <div className="space-y-2">
          <SectionTitle icon={Microscope}>Root cause</SectionTitle>
          <p className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3 text-[12px] leading-relaxed text-slate-300">{answer.rootCause}</p>
        </div>
      )}

      {/* Business impact */}
      {answer.businessImpact && (
        <div className="space-y-2">
          <SectionTitle icon={Briefcase}>Business impact</SectionTitle>
          <p className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3 text-[12px] leading-relaxed text-slate-300">{answer.businessImpact}</p>
        </div>
      )}

      {/* Technical analysis */}
      {answer.technicalAnalysis && answer.technicalAnalysis.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={Cpu}>Technical analysis</SectionTitle>
          <ul className="space-y-1.5 rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
            {answer.technicalAnalysis.map((line, i) => (
              <li key={i} className="flex gap-2 text-[12px] leading-relaxed text-slate-300">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-blue-400/70" />
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Migration strategy — dependency-safe ordered steps */}
      {answer.migrationStrategy && answer.migrationStrategy.steps.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <SectionTitle icon={Route}>Recommended migration order</SectionTitle>
            <div className="flex items-center gap-2 text-[9px] text-slate-500">
              {typeof answer.migrationStrategy.estimatedEffortPct === 'number' && (
                <span className="rounded border border-slate-700/50 px-1.5 py-0.5 font-semibold text-slate-400">~{answer.migrationStrategy.estimatedEffortPct}% effort remaining</span>
              )}
              {answer.migrationStrategy.estimatedTimeline && (
                <span className="hidden rounded border border-slate-700/50 px-1.5 py-0.5 font-semibold text-slate-400 sm:inline">{answer.migrationStrategy.estimatedTimeline}</span>
              )}
            </div>
          </div>
          <ol className="space-y-2">
            {answer.migrationStrategy.steps.map((step) => {
              const body = (
                <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3 transition-colors hover:border-cyan-400/40">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-cyan-400/40 bg-cyan-500/10 text-[10px] font-black text-cyan-200">{step.order}</span>
                    <span className="text-[12px] font-semibold text-slate-100">{step.title}</span>
                    {step.deepLink && <ExternalLink className="ml-auto h-3 w-3 text-slate-600" />}
                  </div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{step.rationale}</p>
                  {step.breaksIf && (
                    <p className="mt-1.5 flex items-start gap-1.5 rounded border border-amber-500/25 bg-amber-500/[0.07] px-2 py-1 text-[10px] leading-relaxed text-amber-200/90">
                      <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" /><span><span className="font-semibold">If out of order:</span> {step.breaksIf}</span>
                    </p>
                  )}
                </div>
              );
              return (
                <li key={step.order}>
                  {step.deepLink ? <Link to={step.deepLink} className="block no-underline">{body}</Link> : body}
                </li>
              );
            })}
          </ol>
        </div>
      )}

      {/* Dependencies */}
      {answer.dependencies && answer.dependencies.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={Network}>Dependencies &amp; relationships</SectionTitle>
          <ul className="grid gap-1.5 rounded-lg border border-slate-700/50 bg-slate-900/40 p-3 sm:grid-cols-2">
            {answer.dependencies.map((dep, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-relaxed text-slate-300">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-violet-400/70" />
                <span>{dep}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Potential breakages */}
      {answer.potentialBreakages && answer.potentialBreakages.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={Unplug}>What could break</SectionTitle>
          <ul className="space-y-1.5 rounded-lg border border-amber-500/25 bg-amber-500/[0.05] p-3">
            {answer.potentialBreakages.map((brk, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-relaxed text-amber-100/90">
                <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-400/80" />
                <span>{brk}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Rollback strategy */}
      {answer.rollbackStrategy && (
        <div className="space-y-2">
          <SectionTitle icon={RotateCcw}>Rollback strategy</SectionTitle>
          <p className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3 text-[12px] leading-relaxed text-slate-300">{answer.rollbackStrategy}</p>
        </div>
      )}

      {/* Recommendations */}
      {answer.recommendations.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={Lightbulb}>Recommendations</SectionTitle>
          <div className="space-y-2">
            {answer.recommendations.map((rec, i) => (
              <div key={i} className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-[12px] font-semibold text-slate-100">{rec.title}</span>
                  <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider ${PRIORITY_STYLE[rec.priority] || PRIORITY_STYLE.medium}`}>
                    {rec.priority}
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{rec.detail}</p>
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                  {rec.standards.map((std, j) => (
                    <span key={j} className="rounded border border-blue-400/25 bg-blue-500/10 px-1.5 py-0.5 text-[9px] font-semibold text-blue-200">{std}</span>
                  ))}
                  {rec.deepLink && (
                    <Link to={rec.deepLink} className="ml-auto flex items-center gap-1 text-[10px] font-bold text-cyan-300 no-underline hover:text-cyan-200">
                      Open <ArrowRight className="h-3 w-3" />
                    </Link>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Proactive findings — "while investigating, I also detected…" */}
      {answer.proactiveFindings && answer.proactiveFindings.length > 0 && (
        <div className="space-y-2 rounded-xl border border-cyan-400/20 bg-cyan-500/[0.04] p-3">
          <SectionTitle icon={Radar}>While investigating, I also detected</SectionTitle>
          <div className="space-y-1.5">
            {answer.proactiveFindings.map((finding, i) => {
              const style = RISK_STYLE[finding.severity] || RISK_STYLE.info;
              const body = (
                <div className="flex items-start gap-2 rounded-lg border border-slate-700/50 bg-slate-900/40 p-2.5 transition-colors hover:border-cyan-400/40">
                  <span className={`mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wider ${style.chip}`}>{finding.severity}</span>
                  <span className="text-[11px] leading-relaxed text-slate-300">{finding.text}</span>
                  {finding.deepLink && <ExternalLink className="ml-auto mt-0.5 h-3 w-3 shrink-0 text-slate-600" />}
                </div>
              );
              return finding.deepLink ? (
                <Link key={i} to={finding.deepLink} className="block no-underline">{body}</Link>
              ) : (
                <div key={i}>{body}</div>
              );
            })}
          </div>
        </div>
      )}

      {/* Next actions */}
      {answer.nextActions.length > 0 && (
        <div className="space-y-2">
          <SectionTitle icon={ArrowRight}>Next actions</SectionTitle>
          <div className="flex flex-wrap gap-2">
            {answer.nextActions.map((action, i) => (
              <Link
                key={i}
                to={action.path}
                title={action.reason}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[11px] font-bold text-cyan-200 no-underline transition-colors hover:bg-cyan-500/20"
              >
                {action.label} <ArrowRight className="h-3 w-3" />
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Reasoning (collapsible) */}
      {(answer.reasoning.length > 0 || answer.toolRuns.length > 0) && (
        <div className="rounded-lg border border-slate-700/40 bg-slate-900/30">
          <button
            onClick={() => setShowReasoning((s) => !s)}
            className="flex w-full items-center gap-2 px-3 py-2 text-left"
          >
            <Layers className="h-3.5 w-3.5 text-slate-500" />
            <span className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">Reasoning &amp; sources</span>
            <span className="ml-auto text-[10px] text-slate-500">{answer.toolRuns.length} data source(s)</span>
            <ChevronDown className={`h-3.5 w-3.5 text-slate-500 transition-transform ${showReasoning ? 'rotate-180' : ''}`} />
          </button>
          {showReasoning && (
            <div className="space-y-2 border-t border-slate-700/40 px-3 py-2.5">
              <ol className="space-y-1">
                {answer.reasoning.map((step, i) => (
                  <li key={i} className="flex gap-2 text-[11px] text-slate-400">
                    <span className="text-cyan-400/60">{i + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
              {answer.toolRuns.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {aggregateSources(answer.toolRuns).map((s, i) => (
                    <span
                      key={i}
                      className={`rounded border px-1.5 py-0.5 text-[9px] font-semibold ${
                        s.status === 'ok' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          : s.status === 'empty' ? 'border-slate-600/40 bg-slate-800/40 text-slate-400'
                          : s.status === 'denied' ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                          : 'border-red-500/30 bg-red-500/10 text-red-300'
                      }`}
                    >
                      {s.label}{SOURCE_STATUS_SUFFIX[s.status]}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Footer: standards, related pages, confidence */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-slate-700/40 pt-3">
        {answer.standards.length > 0 && (
          <div className="flex items-center gap-1.5">
            <BookMarked className="h-3 w-3 text-slate-500" />
            <span className="text-[9px] text-slate-500">{answer.standards.slice(0, 4).join(' · ')}</span>
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Gauge className="h-3.5 w-3.5 text-cyan-300/70" />
          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
            <div className={`h-full ${risk.bar}`} style={{ width: `${answer.confidence.score}%`, background: 'linear-gradient(90deg,#22d3ee,#3b82f6)' }} />
          </div>
          <span className="text-[10px] font-bold text-cyan-200" title={answer.confidence.basis}>{answer.confidence.score}% confidence</span>
        </div>
      </div>

      {/* Related pages */}
      {answer.relatedPages.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-600">Related:</span>
          {answer.relatedPages.map((page, i) => (
            <Link key={i} to={page.path} className="rounded border border-slate-700/50 px-1.5 py-0.5 text-[10px] text-slate-400 no-underline transition-colors hover:border-cyan-400/40 hover:text-cyan-300">
              {page.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

export default SophiaMessage;
