'use client';

import { useNavigate } from 'react-router-dom';
import { ArrowRight, CheckCircle2, CircleDashed, Loader2, OctagonAlert } from 'lucide-react';
import { useMigrationWorkflow } from '@/hooks/use-migration-workflow';
import type { WorkflowStage, WorkflowStageId } from '@/types/migration-workflow';

/**
 * WorkflowRail — the shared Post-Quantum Migration Workflow™ stepper.
 *
 * Embedded across every module that participates in the lifecycle
 * (Discovery → CBOM → Assessment → Risk → Remediation → Planning → Approval →
 * Execution → Validation → Monitoring → Certification) so users always see
 * where they are in the end-to-end journey and can jump to the module that
 * owns any stage. All stage states come from one server-computed source of
 * truth, so indicators can never disagree between pages.
 *
 * `activeStage` highlights the stage the embedding page owns.
 * `tone` matches the host page: 'dark' for the fixed-dark security dashboards,
 * 'adaptive' for the enterprise-theme discovery dashboards that switch between
 * light and dark via the app theme toggle (light classes + dark: variants).
 */

const STATUS_COLORS: Record<WorkflowStage['status'], string> = {
  complete: '#34D399',
  active: '#22D3EE',
  pending: '#64748B',
  blocked: '#EF4444',
};

/** Active-stage TEXT colour from the theme token, so it stays legible on the light (parchment) theme. */
const ACTIVE_TEXT = 'var(--qg-accent-cyan, #22D3EE)';

function StageIcon({ stage }: { stage: WorkflowStage }) {
  const color = STATUS_COLORS[stage.status];
  if (stage.status === 'complete') return <CheckCircle2 className="h-3.5 w-3.5" style={{ color }} />;
  if (stage.status === 'blocked') return <OctagonAlert className="h-3.5 w-3.5" style={{ color }} />;
  if (stage.status === 'active') return <Loader2 className="h-3.5 w-3.5 animate-[spin_3s_linear_infinite]" style={{ color }} />;
  return <CircleDashed className="h-3.5 w-3.5" style={{ color }} />;
}

export function WorkflowRail({ activeStage, tone = 'dark' }: { activeStage: WorkflowStageId; tone?: 'dark' | 'adaptive' }) {
  const navigate = useNavigate();
  const { workflow, state } = useMigrationWorkflow();

  // Auxiliary overlay: render nothing until real state exists; never break the host page.
  if (state !== 'success' || !workflow) return null;

  const dark = tone === 'dark';
  const shell = dark
    ? 'border-white/10 bg-[#07101D]/90 text-white'
    : 'border-slate-200 bg-white text-slate-900 shadow-sm dark:border-white/10 dark:bg-[#07101D]/90 dark:text-white dark:shadow-none';
  const subtext = dark ? 'text-white/45' : 'text-slate-500 dark:text-white/45';
  const divider = dark ? 'border-white/8' : 'border-slate-200 dark:border-white/8';
  const stageBase = dark ? 'hover:bg-white/[0.05]' : 'hover:bg-slate-50 dark:hover:bg-white/[0.05]';
  const track = dark ? 'bg-white/10' : 'bg-slate-200 dark:bg-white/10';
  const stageText = dark ? 'text-white/75' : 'text-slate-700 dark:text-white/75';

  return (
    <div className={`rounded-md border px-3.5 py-2.5 ${shell}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2">
        <div className="flex items-center gap-2.5">
          <span className={`text-[10px] font-black uppercase tracking-[0.1em] ${subtext}`}>Post-Quantum Migration Workflow™</span>
          {/* Text uses the theme token (cyan on dark, parchment accent on light): the raw #22D3EE measured 1.5:1 on parchment. */}
          <span className="text-[11px] font-bold" style={{ color: ACTIVE_TEXT }}>
            {workflow.overallProgressPct}% complete
          </span>
          <span className={`hidden text-[11px] sm:inline ${subtext}`}>
            · Certification readiness {workflow.certificationReadinessPct}%
          </span>
        </div>
        <button
          type="button"
          onClick={() => navigate(workflow.nextAction.route)}
          className={`inline-flex max-w-full items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-bold transition ${
            dark
              ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200 hover:bg-cyan-400/20'
              : 'border-cyan-600/40 bg-cyan-50 text-cyan-700 hover:bg-cyan-100 dark:border-cyan-400/40 dark:bg-cyan-400/10 dark:text-cyan-200 dark:hover:bg-cyan-400/20'
          }`}
          title={workflow.nextAction.detail}
        >
          <span className="truncate">Next: {workflow.nextAction.title}</span>
          <ArrowRight className="h-3 w-3 shrink-0" />
        </button>
      </div>

      <div className={`-mx-1 flex items-stretch gap-1 overflow-x-auto border-t pt-2 ${divider}`}>
        {workflow.stages.map((stage, index) => {
          const isHere = stage.id === activeStage;
          const isCurrent = stage.id === workflow.currentStageId;
          const color = STATUS_COLORS[stage.status];
          return (
            <button
              key={stage.id}
              type="button"
              onClick={() => navigate(stage.route)}
              title={`${stage.label} — ${stage.kpi}\n${stage.detail}`}
              className={`group relative flex min-w-[86px] flex-1 flex-col gap-1 rounded px-1.5 py-1 text-left transition ${stageBase}`}
              style={isHere ? { outline: `1px solid ${STATUS_COLORS.active}66`, backgroundColor: dark ? 'rgba(34,211,238,0.06)' : 'rgba(34,211,238,0.07)' } : undefined}
            >
              <span className="flex items-center gap-1.5">
                <StageIcon stage={stage} />
                <span className={`truncate text-[10px] font-bold ${stageText}`}>
                  {index + 1}. {stage.shortLabel}
                </span>
                {isCurrent ? (
                  <span className="rounded px-1 text-[8px] font-black uppercase" style={{ color: ACTIVE_TEXT, backgroundColor: `${STATUS_COLORS.active}1f` }}>
                    Now
                  </span>
                ) : null}
              </span>
              <span className={`truncate text-[9px] ${subtext}`}>{stage.kpi}</span>
              <span className={`h-1 overflow-hidden rounded-full ${track}`}>
                <span className="block h-full rounded-full transition-all duration-700" style={{ width: `${stage.progressPct}%`, backgroundColor: color }} />
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default WorkflowRail;
