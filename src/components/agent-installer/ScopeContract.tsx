import { useMemo } from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleSlash,
  Lock,
  Minus,
  ShieldCheck,
  ShieldOff,
  XCircle,
} from 'lucide-react';
import { agentRole } from '@/lib/agent-installer/agent-release';
import {
  AGENT_SCAN_MODULES,
  AGENT_SCAN_PRESETS,
  PATH_ISSUE_COPY,
  SCAN_MODULE_GROUP_LABEL,
  resolveWriteAuthority,
  type ModuleScopePlan,
  type ModuleScopeState,
  type ScanModuleGroup,
  type ScopePlan,
} from '@/lib/agent-installer/agent-scope';
import type { EnrolledAgentRecord } from '@/hooks/use-agent-installer';

/**
 * Scope-contract presentation shared by the deployment wizard and the agent
 * detail drawer. It renders `planAgentScope` output and computes nothing of its
 * own, so the promise made before deployment and the statement shown after it
 * are the same function over the same inputs.
 */

const STATE_STYLE: Record<ModuleScopeState, { chip: string; label: string }> = {
  active: { chip: 'border-cyan-400/45 bg-cyan-400/[0.12] text-cyan-100', label: 'Active' },
  idle: { chip: 'border-amber-400/45 bg-amber-400/[0.1] text-amber-100', label: 'Needs scope' },
  'via-configs': { chip: 'border-white/12 bg-white/[0.03] text-white/55', label: 'Via Config files' },
  off: { chip: 'border-white/10 bg-white/[0.02] text-white/45 hover:text-white/75 hover:border-white/20', label: 'Off' },
  'plan-locked': { chip: 'border-white/[0.07] bg-transparent text-white/25', label: 'Plan' },
  'role-excluded': { chip: 'border-white/[0.07] bg-transparent text-white/25', label: 'Role' },
};

function StateGlyph({ state }: { state: ModuleScopeState }) {
  if (state === 'active') return <CheckCircle2 aria-hidden className="h-3.5 w-3.5 text-cyan-300" />;
  if (state === 'idle') return <AlertTriangle aria-hidden className="h-3.5 w-3.5 text-amber-300" />;
  if (state === 'via-configs') return <Minus aria-hidden className="h-3.5 w-3.5 text-white/40" />;
  if (state === 'plan-locked') return <Lock aria-hidden className="h-3 w-3 text-white/30" />;
  if (state === 'role-excluded') return <CircleSlash aria-hidden className="h-3 w-3 text-white/25" />;
  return <span aria-hidden className="h-3 w-3 rounded-full border border-white/25" />;
}

/** Every module is shown, including excluded ones, so an operator learns what exists. */
export function ModuleScopeGrid({
  plan,
  onToggle,
  lockedLabel = 'Pro',
}: {
  plan: ScopePlan;
  onToggle?: (id: string) => void;
  lockedLabel?: string;
}) {
  const groups = useMemo(() => {
    const byGroup = new Map<ScanModuleGroup, ModuleScopePlan[]>();
    for (const module of plan.modules) {
      const list = byGroup.get(module.group) || [];
      list.push(module);
      byGroup.set(module.group, list);
    }
    return [...byGroup.entries()];
  }, [plan.modules]);

  return (
    <div className="space-y-3.5">
      {groups.map(([group, modules]) => (
        <div key={group}>
          <div className="flex flex-wrap items-center justify-between gap-x-2">
            <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-white/35">{SCAN_MODULE_GROUP_LABEL[group]}</div>
            {group === 'surface' ? <div className="text-[10px] text-white/30">Narrows configuration collection to one platform</div> : null}
          </div>
          <div className="mt-1.5 grid grid-cols-[minmax(0,1fr)] gap-1.5 sm:grid-cols-2">
            {modules.map((module) => {
              const style = STATE_STYLE[module.state];
              const interactive = Boolean(onToggle) && module.state !== 'plan-locked' && module.state !== 'role-excluded';
              const selected = module.state === 'active' || module.state === 'idle';
              const definition = AGENT_SCAN_MODULES.find((item) => item.id === module.id);
              return (
                <button
                  key={module.id}
                  type="button"
                  disabled={!interactive}
                  aria-pressed={selected}
                  onClick={() => interactive && onToggle?.(module.id)}
                  title={definition?.does}
                  className={`flex min-w-0 items-start gap-2 rounded-lg border px-2.5 py-2 text-left transition disabled:cursor-not-allowed ${style.chip}`}
                >
                  <span className="mt-0.5 grid h-3.5 w-3.5 shrink-0 place-items-center">
                    <StateGlyph state={module.state} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center justify-between gap-2">
                      <span className="truncate text-[11.5px] font-bold">{module.label}</span>
                      <span className="shrink-0 text-[9.5px] font-black uppercase tracking-[0.1em] opacity-70">
                        {module.state === 'plan-locked' ? lockedLabel : style.label}
                      </span>
                    </span>
                    {module.state === 'idle' || module.state === 'via-configs' || module.state === 'role-excluded' ? (
                      <span className="mt-0.5 block text-[10.5px] leading-snug opacity-80">{module.detail}</span>
                    ) : null}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

/** One tap applies a whole module set, clamped to role and plan. */
export function ScanPresetRail({
  current,
  onSelect,
  carriedFrom,
}: {
  current: string;
  onSelect: (presetId: string) => void;
  carriedFrom?: string | null;
}) {
  const active = AGENT_SCAN_PRESETS.find((preset) => preset.id === current);
  return (
    <div>
      <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Scan preset">
        {AGENT_SCAN_PRESETS.map((preset) => {
          const on = preset.id === current;
          return (
            <button
              key={preset.id}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => onSelect(preset.id)}
              className={`rounded-lg border px-2.5 py-1 text-[11px] font-bold transition ${
                on
                  ? 'border-violet-400/50 bg-violet-400/[0.14] text-violet-100'
                  : 'border-white/10 bg-white/[0.02] text-white/50 hover:border-white/20 hover:text-white/80'
              }`}
            >
              {preset.label}
            </button>
          );
        })}
        <span
          className={`rounded-lg border px-2.5 py-1 text-[11px] font-bold ${
            current === 'custom' ? 'border-violet-400/50 bg-violet-400/[0.14] text-violet-100' : 'border-dashed border-white/10 text-white/30'
          }`}
        >
          Custom
        </span>
      </div>
      <p className="mt-1.5 text-[11px] leading-relaxed text-white/40">
        {current === 'custom' ? 'Your own module selection.' : active?.summary}
        {carriedFrom ? <span className="text-violet-200/70"> Carried over from your Local assessment profile “{carriedFrom}”.</span> : null}
      </p>
    </div>
  );
}

/** Each allowed target, parsed exactly as the agent runtime will parse it. */
export function TargetPreviewList({ plan }: { plan: ScopePlan }) {
  if (plan.targets.length === 0) return null;
  return (
    <ul className="mt-2 flex flex-wrap gap-1.5">
      {plan.targets.map((item) => (
        <li
          key={item.raw}
          className={`inline-flex max-w-full items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[10.5px] ${
            item.parsed ? 'border-white/12 bg-white/[0.03] text-white/70' : 'border-rose-400/35 bg-rose-400/[0.08] text-rose-200'
          }`}
        >
          <span className={`font-sans text-[9px] font-black uppercase tracking-wider ${item.parsed ? 'text-cyan-300' : 'text-rose-300'}`}>
            {item.parsed ? item.parsed.type : 'invalid'}
          </span>
          <span className="truncate">{item.parsed ? `${item.parsed.host}:${item.parsed.port}` : item.raw}</span>
        </li>
      ))}
    </ul>
  );
}

export function PathPreviewList({ plan }: { plan: ScopePlan }) {
  const flagged = plan.paths.filter((item) => item.issue);
  if (flagged.length === 0) return null;
  return (
    <ul className="mt-2 space-y-1">
      {flagged.map((item) => (
        <li key={item.raw} className="flex items-start gap-1.5 text-[11px] leading-snug text-amber-100/80">
          <AlertTriangle aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
          <span>
            <code className="font-mono text-amber-100">{item.raw}</code> — {item.issue ? PATH_ISSUE_COPY[item.issue] : ''}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** What this agent will do, what it will never do, and what is wrong as stated. */
export function ScopeContractPanel({ plan, role, compact = false }: { plan: ScopePlan; role: string; compact?: boolean }) {
  const definition = agentRole(role);
  return (
    <div className="rounded-xl border border-white/10 bg-black/30">
      <div className="flex items-center justify-between gap-2 border-b border-white/8 px-4 py-2.5">
        <span className="text-[11px] font-black uppercase tracking-[0.14em] text-white/60">Scope contract</span>
        <span className="font-mono text-[10px] text-white/35">
          {plan.activeModules} active · {plan.idleModules} idle
        </span>
      </div>
      <div className="space-y-3 px-4 py-3">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wide text-emerald-300/80">{definition.label} will</div>
          {plan.will.length === 0 ? (
            <p className="mt-1 text-[11.5px] text-white/40">Nothing yet — no selected module has anything to read.</p>
          ) : (
            <ul className="mt-1 space-y-1">
              {plan.will.map((line) => (
                <li key={line} className="flex gap-1.5 text-[11.5px] leading-snug text-white/75">
                  <CheckCircle2 aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        {!compact ? (
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wide text-white/40">It will not</div>
            <ul className="mt-1 space-y-1">
              {plan.wont.map((line) => (
                <li key={line} className="flex gap-1.5 text-[11.5px] leading-snug text-white/50">
                  <Ban aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-white/30" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {plan.blockers.length > 0 ? (
          <div className="rounded-lg border border-rose-400/30 bg-rose-400/[0.07] px-3 py-2">
            {plan.blockers.map((line) => (
              <p key={line} className="flex gap-1.5 text-[11.5px] leading-snug text-rose-100">
                <XCircle aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-rose-300" />
                <span>{line}</span>
              </p>
            ))}
          </div>
        ) : null}
        {plan.warnings.length > 0 ? (
          <div className="rounded-lg border border-amber-400/25 bg-amber-400/[0.05] px-3 py-2">
            {plan.warnings.map((line) => (
              <p key={line} className="flex gap-1.5 text-[11px] leading-snug text-amber-100/85">
                <AlertTriangle aria-hidden className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
                <span>{line}</span>
              </p>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function WriteAuthorityBadges({
  remediation,
  migration,
  mutates,
  operator,
}: {
  remediation: boolean;
  migration: boolean;
  mutates: boolean;
  operator: boolean;
}) {
  if (!mutates) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-2 py-0.5 text-[10px] font-black uppercase text-emerald-200">
        <ShieldCheck aria-hidden className="h-3 w-3" /> Read-only role
      </span>
    );
  }
  return (
    <span className="inline-flex flex-wrap gap-1">
      <span
        className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-black uppercase ${
          remediation ? 'border-amber-400/35 bg-amber-400/10 text-amber-200' : 'border-white/12 bg-white/[0.03] text-white/50'
        }`}
      >
        {remediation ? <ShieldOff aria-hidden className="h-3 w-3" /> : <ShieldCheck aria-hidden className="h-3 w-3" />}
        Remediation {remediation ? 'authorised' : 'not authorised'}
      </span>
      {operator ? (
        <span
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-black uppercase ${
            migration ? 'border-rose-400/35 bg-rose-400/10 text-rose-200' : 'border-white/12 bg-white/[0.03] text-white/50'
          }`}
        >
          Migration {migration ? 'authorised' : 'not authorised'}
        </span>
      ) : null}
    </span>
  );
}

export interface RequestedConfiguration {
  role: string;
  scanTypes: string[];
  allowedTargets: string[];
  allowedPaths: string[];
  intervalSeconds: number;
  alertThreshold: string;
  remediationAuthorized: boolean;
  migrationAuthorized: boolean;
  assetId: string | null;
  assetName: string | null;
}

type CheckRow = { label: string; requested: string; applied: string; ok: boolean; note?: string };

const listLabel = (values: string[]) => (values.length === 0 ? 'none' : values.join(', '));
const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && [...a].sort().join('|') === [...b].sort().join('|');

/**
 * Proof that what the operator selected is what the control plane stored:
 * the request compared against the agent row the enrolment endpoint returned —
 * the row the agent pulls its policy from — so every adjustment (plan clamp,
 * role ceiling, asset binding) is visible the moment it happens.
 */
export function AppliedConfigurationCheck({ requested, agent }: { requested: RequestedConfiguration; agent: EnrolledAgentRecord | null }) {
  if (!agent) {
    return (
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4 text-[11.5px] text-white/50">
        The control plane did not return the stored agent record, so the applied configuration cannot be shown here. Open the
        agent from the table to review it.
      </div>
    );
  }

  const policy = agent.policy || {};
  const metadata = (agent.metadata || {}) as Record<string, unknown>;
  const appliedTypes = Array.isArray(policy.scanTypes) ? policy.scanTypes.map(String) : [];
  const appliedTargets = Array.isArray(policy.allowedTargets) ? policy.allowedTargets.map(String) : [];
  const appliedPaths = Array.isArray(policy.allowedPaths) ? policy.allowedPaths.map(String) : [];
  const deniedByPlan = Array.isArray(metadata.scanTypesDeniedByPlan) ? (metadata.scanTypesDeniedByPlan as string[]) : [];
  const deniedByRole = Array.isArray(metadata.scanTypesDeniedByRole) ? (metadata.scanTypesDeniedByRole as string[]) : [];
  const appliedRole = String(metadata.role || '');
  const authority = resolveWriteAuthority(appliedRole || requested.role, agent.capabilities || {}, metadata);
  const mutates = agentRole(requested.role).mutatesTargets;

  const rows: CheckRow[] = [
    { label: 'Agent type', requested: agentRole(requested.role).label, applied: appliedRole ? agentRole(appliedRole).label : 'unresolved', ok: appliedRole === requested.role },
    {
      label: 'Scan modules',
      requested: `${requested.scanTypes.length} selected`,
      applied: `${appliedTypes.length} enforced`,
      ok: sameSet(requested.scanTypes, appliedTypes),
      note:
        deniedByPlan.length || deniedByRole.length
          ? [
              deniedByPlan.length ? `Not in your plan: ${listLabel(deniedByPlan)}.` : '',
              deniedByRole.length ? `Not part of this role: ${listLabel(deniedByRole)}.` : '',
            ].filter(Boolean).join(' ')
          : undefined,
    },
    { label: 'Allowed targets', requested: String(requested.allowedTargets.length), applied: String(appliedTargets.length), ok: sameSet(requested.allowedTargets, appliedTargets) },
    { label: 'Allowed paths', requested: String(requested.allowedPaths.length), applied: String(appliedPaths.length), ok: sameSet(requested.allowedPaths, appliedPaths) },
    {
      label: 'Heartbeat interval',
      requested: `${requested.intervalSeconds}s`,
      applied: policy.intervalSeconds ? `${Number(policy.intervalSeconds)}s` : '—',
      ok: Number(policy.intervalSeconds) === requested.intervalSeconds,
    },
    { label: 'Alert threshold', requested: requested.alertThreshold, applied: String(policy.alertThreshold || '—'), ok: String(policy.alertThreshold) === requested.alertThreshold },
    ...(mutates
      ? [{
          label: 'Remediation authority',
          requested: requested.remediationAuthorized ? 'authorised' : 'not authorised',
          applied: authority.remediation ? 'authorised' : 'not authorised',
          ok: authority.remediation === requested.remediationAuthorized,
        }]
      : [{
          label: 'Write authority',
          requested: 'read-only',
          applied: authority.remediation || authority.migration ? 'can write' : 'read-only',
          ok: !authority.remediation && !authority.migration,
        }]),
    ...(requested.role === 'operator'
      ? [{
          label: 'Migration authority',
          requested: requested.migrationAuthorized ? 'authorised' : 'not authorised',
          applied: authority.migration ? 'authorised' : 'not authorised',
          ok: authority.migration === (requested.migrationAuthorized && requested.remediationAuthorized),
        }]
      : []),
    {
      label: 'Assigned asset',
      requested: requested.assetName || 'not linked',
      applied: String(metadata.assetName || 'not linked'),
      ok: (requested.assetId || null) === ((metadata.assetId as string | null) || null),
    },
  ];

  const adjusted = rows.filter((row) => !row.ok).length;

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/8 px-4 py-2.5">
        <span className="text-[11px] font-black uppercase tracking-[0.14em] text-white/60">Applied by the control plane</span>
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-black uppercase ${
            adjusted === 0 ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200' : 'border-amber-400/30 bg-amber-400/10 text-amber-200'
          }`}
        >
          {adjusted === 0 ? 'Every selection applied' : `${adjusted} adjusted`}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[460px] text-left text-[11.5px]">
          <thead>
            <tr className="text-[10px] uppercase tracking-wide text-white/35">
              <th className="px-4 py-2 font-bold">Setting</th>
              <th className="px-2 py-2 font-bold">You selected</th>
              <th className="px-2 py-2 font-bold">Enforced</th>
              <th className="px-4 py-2 text-right font-bold">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {rows.map((row) => (
              <tr key={row.label} className="align-top text-white/70">
                <td className="px-4 py-2 font-bold text-white/80">{row.label}</td>
                <td className="px-2 py-2">{row.requested}</td>
                <td className="px-2 py-2">
                  {row.applied}
                  {row.note ? <span className="mt-0.5 block text-[10.5px] leading-snug text-amber-200/80">{row.note}</span> : null}
                </td>
                <td className="px-4 py-2 text-right">
                  {row.ok ? (
                    <CheckCircle2 aria-label="Applied as selected" className="ml-auto h-4 w-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle aria-label="Adjusted by the control plane" className="ml-auto h-4 w-4 text-amber-300" />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
