'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  BellRing,
  CheckCircle2,
  ChevronDown,
  Circle,
  Clock,
  Code2,
  Copy,
  KeyRound,
  Loader2,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  TriangleAlert,
  XCircle,
} from 'lucide-react';
import { mandatoryPqcStackMetadata } from '@/lib/crypto/mandatory-pqc-stack';
import { agentRole } from '@/lib/agent-installer/agent-release';
import { planAgentScope } from '@/lib/agent-installer/agent-scope';
import { useAgentEntitlement } from '@/hooks/use-agent-entitlement';
import {
  agentDisplayStatus,
  agentHealthScore,
  useAgentCollector,
  type AgentPolicyInput,
  type CollectorAgent,
  type PolicyDenied,
} from '@/hooks/use-agent-collector';
import { ModuleScopeGrid, PathPreviewList, ScopeContractPanel, TargetPreviewList } from '@/components/agent-installer/ScopeContract';

/**
 * Collector Settings — the Agents Collector page's Settings section.
 *
 * Owns collector CONFIGURATION: enablement, heartbeat interval, alert
 * threshold, scan modules and the authorised targets/paths, applied to one
 * collector or to every active one. It receives the page's single
 * `useAgentCollector` instance rather than opening its own, so there is one
 * REST snapshot and one `agent-scanner-sync` stream for the whole page.
 *
 * What is applied is what the agent runs:
 *  - modules come from the runtime's own catalogue (AGENT_SCAN_MODULES via
 *    planAgentScope), marked against the agent's role and the server-verified
 *    plan entitlement, so nothing offered here is silently dropped;
 *  - the server clamps again and the removals are reported per collector;
 *  - each collector shows whether it has PULLED the changed policy yet
 *    (policyUpdatedAt / policyDeliveredAt), not merely that it was saved.
 */

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]';
const NOTICE = 'border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] text-[var(--qg-notice-text)]';
const MANDATORY_STACK = mandatoryPqcStackMetadata();

const ALERT_THRESHOLDS = [
  { id: 'low', label: 'Low', detail: 'Alert on every vulnerable finding' },
  { id: 'moderate', label: 'Moderate', detail: 'Moderate severity and above' },
  { id: 'high', label: 'High', detail: 'High and critical only' },
  { id: 'critical', label: 'Critical', detail: 'Critical findings only' },
];
const INTERVALS = [30, 45, 60];

type CollectorApi = ReturnType<typeof useAgentCollector>;
type Toast = (tone: 'ok' | 'bad', text: string) => void;
type ApplyResult = { id: string; name: string; ok: boolean; message?: string; denied?: PolicyDenied };

function relTime(value?: string | null): string {
  if (!value) return '—';
  const diff = Date.now() - Date.parse(value);
  if (!Number.isFinite(diff)) return '—';
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}

const isActiveAgent = (a: CollectorAgent) => !a.revoked_at && String(a.status || '').toLowerCase() !== 'revoked';
const roleOf = (a: CollectorAgent | null) => agentRole(typeof a?.metadata?.role === 'string' ? (a.metadata.role as string) : 'collector');

/** Normalize a collector's stored policy (camel or snake) into the editable form. */
function policyFromAgent(agent: CollectorAgent | null): AgentPolicyInput {
  const p = (agent?.policy || {}) as Record<string, unknown>;
  const arr = (a: unknown, b: unknown): string[] => (Array.isArray(a) ? (a as string[]) : Array.isArray(b) ? (b as string[]) : []);
  return {
    enabled: p.enabled !== false,
    intervalSeconds: Math.max(30, Math.min(60, Number(p.intervalSeconds || p.interval_seconds || 60))),
    allowedTargets: arr(p.allowedTargets, p.allowed_targets),
    allowedPaths: arr(p.allowedPaths, p.allowed_paths),
    scanTypes: arr(p.scanTypes, p.scan_types),
    alertThreshold: String(p.alertThreshold || p.alert_threshold || 'moderate'),
  };
}

/** Order-insensitive identity of a policy, for dirty checks. */
function policyKey(policy: AgentPolicyInput): string {
  return JSON.stringify({ ...policy, scanTypes: [...policy.scanTypes].sort(), allowedTargets: [...policy.allowedTargets], allowedPaths: [...policy.allowedPaths] });
}

/**
 * Whether the agent has pulled its current policy. Read from the receipts the
 * control plane writes: policyUpdatedAt on every change (and at enrolment),
 * policyDeliveredAt the first time /agent/policy hands the changed policy out.
 */
export function policyDelivery(agent: CollectorAgent): { label: string; tone: 'ok' | 'warn' | 'idle'; detail: string } {
  const meta = (agent.metadata || {}) as Record<string, unknown>;
  const updated = typeof meta.policyUpdatedAt === 'string' ? meta.policyUpdatedAt : null;
  const delivered = typeof meta.policyDeliveredAt === 'string' ? meta.policyDeliveredAt : null;
  if (!isActiveAgent(agent)) return { label: 'Revoked', tone: 'idle', detail: 'A revoked collector receives no policy.' };
  if (!updated) return { label: 'Not tracked', tone: 'idle', detail: 'This policy predates delivery receipts. The agent re-reads its policy on every check-in.' };
  if (delivered && delivered >= updated) return { label: 'In effect', tone: 'ok', detail: `The agent pulled this policy ${relTime(delivered)}.` };
  if (!agent.last_seen_at) return { label: 'Awaiting install', tone: 'warn', detail: 'Applies on the agent’s first check-in after it is installed.' };
  return { label: 'Pending check-in', tone: 'warn', detail: `Changed ${relTime(updated)}. The agent picks it up on its next policy poll.` };
}

function DeliveryBadge({ agent }: { agent: CollectorAgent }) {
  const d = policyDelivery(agent);
  const tone = d.tone === 'ok'
    ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300'
    : d.tone === 'warn'
      ? 'border-amber-400/30 bg-amber-400/10 text-amber-200'
      : 'border-white/10 bg-white/[0.04] text-white/50';
  return (
    <span title={d.detail} className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold ${tone}`}>
      {d.tone === 'ok' ? <CheckCircle2 className="h-3 w-3" /> : <Clock className="h-3 w-3" />} {d.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    Online: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
    Offline: 'border-red-400/30 bg-red-400/10 text-red-300',
    Waiting: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    Unhealthy: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
    Updating: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
    Revoked: 'border-white/10 bg-white/[0.04] text-white/40',
  };
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${map[status] || 'border-white/10 bg-white/[0.04] text-white/55'}`}>{status}</span>;
}

export function CollectorSettings({ collector, onToast }: { collector: CollectorApi; onToast: Toast }) {
  const entitlement = useAgentEntitlement();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [applyMode, setApplyMode] = useState<'selected' | 'all'>('selected');
  const [form, setForm] = useState<AgentPolicyInput>(policyFromAgent(null));
  // What the form was loaded from: the dirty check and the "changed elsewhere" notice compare against it.
  const [baseline, setBaseline] = useState<{ agentId: string | null; key: string }>({ agentId: null, key: '' });
  const [changedElsewhere, setChangedElsewhere] = useState(false);
  const [saving, setSaving] = useState(false);
  const [results, setResults] = useState<ApplyResult[]>([]);
  const [apiOpen, setApiOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const manageable = collector.agents.filter(isActiveAgent);
  const selectedAgent = collector.agents.find((a) => a.id === selectedId) || null;
  const savedPolicy = useMemo(() => policyFromAgent(selectedAgent), [selectedAgent]);
  const savedKey = policyKey(savedPolicy);
  const dirty = baseline.agentId === selectedId && policyKey(form) !== baseline.key;

  // Default to the first active collector once the fleet loads.
  useEffect(() => {
    if (!selectedId && collector.agents.length) setSelectedId((manageable[0] || collector.agents[0]).id);
  }, [collector.agents, manageable, selectedId]);

  /* Load the selected collector's stored policy into the form — on selection,
     and whenever it changes server-side while the form holds no edits. An
     edit in progress is never overwritten; the operator is told instead. */
  useEffect(() => {
    if (!selectedId) return;
    if (baseline.agentId !== selectedId || !dirty) {
      if (baseline.agentId === selectedId && baseline.key === savedKey) return;
      setForm(savedPolicy);
      setBaseline({ agentId: selectedId, key: savedKey });
      setChangedElsewhere(false);
    } else if (baseline.key !== savedKey) {
      setChangedElsewhere(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, savedKey]);

  const reload = useCallback(() => {
    setForm(savedPolicy);
    setBaseline({ agentId: selectedId, key: savedKey });
    setChangedElsewhere(false);
  }, [savedPolicy, savedKey, selectedId]);

  const role = roleOf(selectedAgent);
  const planPermitted = entitlement.scanTypes.length ? entitlement.scanTypes : null;
  const plan = useMemo(
    () => planAgentScope({
      role: role.id,
      scanTypes: form.scanTypes,
      allowedTargets: form.allowedTargets,
      allowedPaths: form.allowedPaths,
      planPermitted,
      remediationAuthorized: selectedAgent?.metadata?.remediationAuthorized === true,
      migrationAuthorized: selectedAgent?.metadata?.migrationAuthorized === true,
    }),
    [role.id, form.scanTypes, form.allowedTargets, form.allowedPaths, planPermitted, selectedAgent],
  );

  const targets = applyMode === 'all' ? manageable : selectedAgent && isActiveAgent(selectedAgent) ? [selectedAgent] : [];
  const blockers = form.enabled ? plan.blockers : form.scanTypes.length ? [] : ['Select at least one scan module.'];
  const canApply = targets.length > 0 && blockers.length === 0 && (applyMode === 'all' || dirty);

  const parseLines = (text: string): string[] => text.split(/\r?\n|,/).map((t) => t.trim()).filter(Boolean);
  const toggleModule = (id: string) => setForm((c) => ({ ...c, scanTypes: c.scanTypes.includes(id) ? c.scanTypes.filter((x) => x !== id) : [...c.scanTypes, id] }));

  const applyPolicy = useCallback(async () => {
    if (!targets.length || blockers.length) return;
    if (applyMode === 'all' && !window.confirm(
      `Replace the policy on ${targets.length} active collector${targets.length === 1 ? '' : 's'}?\n\nEach one's modules, targets and paths will be replaced with this configuration. Modules a collector's role or your plan excludes are removed for that collector and reported.`,
    )) return;
    setSaving(true);
    /* Move the baseline to what is being sent BEFORE saving: updatePolicy
       refetches the fleet before it returns, and the stored (possibly
       role/plan-clamped) copy must then load as the saved state rather than
       read as somebody else's concurrent change. Restored if the save fails. */
    const previousBaseline = baseline;
    setBaseline({ agentId: selectedId, key: policyKey(form) });
    const next: ApplyResult[] = [];
    for (const agent of targets) {
      const result = await collector.updatePolicy(agent.id, form);
      next.push({ id: agent.id, name: agent.name || agent.id, ok: result.ok, message: result.message, denied: result.denied });
    }
    setSaving(false);
    setResults(next);
    if (next.some((r) => r.id === selectedId && !r.ok)) setBaseline(previousBaseline);
    const failed = next.filter((r) => !r.ok).length;
    const adjusted = next.filter((r) => r.ok && r.denied && (r.denied.plan.length || r.denied.role.length || r.denied.unknown.length)).length;
    onToast(failed ? 'bad' : 'ok', failed
      ? `Applied to ${next.length - failed} of ${next.length} collectors — ${failed} failed.`
      : `Policy saved on ${next.length} collector${next.length === 1 ? '' : 's'}${adjusted ? ` (${adjusted} adjusted to role or plan)` : ''}. Agents pick it up on their next check-in.`);
  }, [targets, blockers.length, applyMode, collector, form, selectedId, onToast, baseline]);

  const openAlerts = collector.alerts.filter((a) => !['resolved', 'closed', 'suppressed'].includes(String(a.status || 'open').toLowerCase()));

  const stackGroups = useMemo(() => [
    { title: 'Libraries', items: MANDATORY_STACK.requiredLibraries },
    { title: 'Key Establishment', items: [MANDATORY_STACK.keyExchange.primary, MANDATORY_STACK.keyExchange.hybrid] },
    { title: 'Signatures', items: [MANDATORY_STACK.signatures.primary, MANDATORY_STACK.signatures.hybrid] },
    { title: 'Data Protection', items: [MANDATORY_STACK.encryption.symmetric, MANDATORY_STACK.kdf.primary, ...MANDATORY_STACK.hashes] },
    { title: 'TLS Policy', items: [MANDATORY_STACK.tls.minProtocol, `${MANDATORY_STACK.tls.preferredGroup} preferred`, 'Hybrid TLS enabled'] },
    { title: 'High Security Profile', items: [MANDATORY_STACK.highSecurityProfile.keyExchange, ...MANDATORY_STACK.highSecurityProfile.signatures] },
  ], []);

  if (collector.state === 'loading' && !collector.agents.length) {
    return (
      <div className={`${PANEL} flex items-center gap-2 p-6 text-sm text-white/50`}>
        <Loader2 className="h-4 w-4 animate-spin" /> Loading collector settings…
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {!collector.agents.length ? (
        <div className={`${PANEL} flex flex-col items-center gap-2 px-6 py-12 text-center`}>
          <Server className="h-8 w-8 text-white/25" />
          <p className="max-w-md text-sm text-white/55">No collectors yet. Deploy one from the Overview section — its policy can then be tuned here.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(340px,0.75fr)]">
          {/* Policy editor */}
          <div className={`${PANEL} p-5`}>
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><SlidersHorizontal className="h-4 w-4 text-cyan-300" /> Collector Policy</h3>
                <p className="mt-0.5 text-[11px] text-white/40">
                  Editing <span className="font-bold text-white/70">{selectedAgent?.name || '—'}</span> · {role.label} role
                  {dirty ? <span className="ml-2 rounded-full border border-cyan-400/30 px-1.5 py-0.5 text-[9px] font-black uppercase text-cyan-200">Unsaved changes</span> : null}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <select aria-label="Apply to" value={applyMode} onChange={(e) => setApplyMode(e.target.value as 'selected' | 'all')} className="appearance-none rounded-lg border border-white/12 bg-white/[0.03] px-3 py-1.5 pr-8 text-xs font-bold text-white/75 outline-none focus:border-cyan-400/50">
                    <option value="selected">Apply to selected collector</option>
                    <option value="all">Apply to all active collectors</option>
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/40" />
                </div>
                <span className="rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5 text-[11px] font-bold tabular-nums text-white/45">{targets.length} target{targets.length === 1 ? '' : 's'}</span>
              </div>
            </div>

            {changedElsewhere ? (
              <div role="status" className={`mb-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-[12px] ${NOTICE}`}>
                <span className="inline-flex items-center gap-2"><TriangleAlert className="h-4 w-4" /> This collector&apos;s policy changed since you started editing.</span>
                <button type="button" onClick={reload} className="rounded-lg border border-[var(--qg-notice-border)] px-2.5 py-1 text-[11px] font-black">Load the saved policy</button>
              </div>
            ) : null}

            {/* Enabled + interval + threshold */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex items-center justify-between gap-3 rounded-xl border border-white/8 bg-white/[0.02] p-3.5 sm:col-span-2">
                <span>
                  <span className="block text-xs font-bold text-white/75">Scanning enabled</span>
                  <span className="mt-0.5 block text-[11px] text-white/40">Off: the agent keeps checking in but performs no scan until re-enabled.</span>
                </span>
                <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((c) => ({ ...c, enabled: e.target.checked }))} className="h-5 w-5 accent-cyan-400" aria-label="Scanning enabled" />
              </label>
              <div>
                <span className="mb-1.5 block text-xs font-bold text-white/60">Check-in interval</span>
                <div role="radiogroup" aria-label="Check-in interval" className="grid grid-cols-3 gap-1.5">
                  {INTERVALS.map((seconds) => {
                    const on = form.intervalSeconds === seconds;
                    return (
                      <button key={seconds} type="button" role="radio" aria-checked={on} onClick={() => setForm((c) => ({ ...c, intervalSeconds: seconds }))}
                        className={`rounded-lg border px-2 py-2 text-xs font-bold tabular-nums transition ${on ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/8 bg-white/[0.02] text-white/60 hover:border-white/20'}`}>
                        {seconds}s
                      </button>
                    );
                  })}
                </div>
                <span className="mt-1 block text-[10px] text-white/35">How often the agent heartbeats and re-reads this policy.</span>
              </div>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Alert threshold</span>
                <div className="relative">
                  <select value={form.alertThreshold} onChange={(e) => setForm((c) => ({ ...c, alertThreshold: e.target.value }))} className="w-full appearance-none rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none focus:border-cyan-400/50">
                    {ALERT_THRESHOLDS.map((t) => <option key={t.id} value={t.id}>{t.label} — {t.detail}</option>)}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
                </div>
                <span className="mt-1 block text-[10px] text-white/35">Vulnerable findings at or above this severity raise alerts.</span>
              </label>
            </div>

            {/* Modules */}
            <div className="mt-5">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-bold text-white/60">Scan modules</span>
                <span className="text-[11px] text-white/40">{form.scanTypes.length} selected · {plan.activeModules} will collect</span>
              </div>
              <ModuleScopeGrid plan={plan} onToggle={toggleModule} />
              {applyMode === 'all' ? (
                <p className="mt-2 text-[11px] text-white/40">Shown for the {role.label} role. Each collector keeps only the modules its own role and your plan allow — removals are reported below.</p>
              ) : null}
            </div>

            {/* Targets + paths */}
            <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Authorized targets</span>
                <textarea
                  rows={5}
                  value={form.allowedTargets.join('\n')}
                  onChange={(e) => setForm((c) => ({ ...c, allowedTargets: parseLines(e.target.value) }))}
                  placeholder={'api.customer.com:443\nssh://server.customer.com:22'}
                  className="w-full resize-y rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 font-mono text-xs text-white/80 outline-none focus:border-cyan-400/50"
                />
                <span className="mt-1 block text-[10px] text-white/35">TLS (host:port, https://) and SSH (ssh://) endpoints the agent may probe — one per line.</span>
                <TargetPreviewList plan={plan} />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">Authorized paths</span>
                <textarea
                  rows={5}
                  value={form.allowedPaths.join('\n')}
                  onChange={(e) => setForm((c) => ({ ...c, allowedPaths: parseLines(e.target.value) }))}
                  placeholder={'/etc/nginx\nC:\\inetpub\\certs'}
                  className="w-full resize-y rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 font-mono text-xs text-white/80 outline-none focus:border-cyan-400/50"
                />
                <span className="mt-1 block text-[10px] text-white/35">Absolute folders or files the agent may read on its host.</span>
                <PathPreviewList plan={plan} />
              </label>
            </div>

            <div className="mt-5">
              <ScopeContractPanel plan={plan} role={role.id} compact />
            </div>

            {blockers.length ? (
              <div role="alert" className={`mt-4 rounded-lg border px-3 py-2 text-[12px] ${NOTICE}`}>
                {blockers.map((b) => <div key={b} className="flex items-center gap-2"><TriangleAlert className="h-4 w-4 shrink-0" /> {b}</div>)}
              </div>
            ) : null}

            {/* Actions */}
            <div className="mt-5 flex flex-wrap items-center gap-2">
              <button type="button" onClick={() => void applyPolicy()} disabled={saving || collector.busy || !canApply} className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-gradient-to-r from-cyan-500/80 to-blue-500/70 px-4 py-2.5 text-sm font-black text-white shadow-lg transition hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50">
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                {applyMode === 'all' ? `Apply to ${targets.length} collector${targets.length === 1 ? '' : 's'}` : 'Apply policy'}
              </button>
              <button type="button" onClick={reload} disabled={!dirty && !changedElsewhere} className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-40">
                <RotateCcw className="h-4 w-4" /> Discard changes
              </button>
              <button
                type="button"
                onClick={() => { navigator.clipboard?.writeText(JSON.stringify(form, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1600); }}
                className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/70 transition hover:text-cyan-200"
              >
                {copied ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <Copy className="h-4 w-4" />} {copied ? 'Copied' : 'Copy as JSON'}
              </button>
            </div>

            {results.length ? (
              <div className="mt-4 rounded-xl border border-white/8 bg-white/[0.02]">
                <div className="flex items-center justify-between border-b border-white/8 px-3.5 py-2">
                  <span className="text-[10px] font-black uppercase tracking-[0.12em] text-white/45">Last apply</span>
                  <button type="button" onClick={() => setResults([])} className="text-[11px] font-bold text-white/40 hover:text-white/70">Dismiss</button>
                </div>
                <ul className="divide-y divide-white/5">
                  {results.map((r) => {
                    const agent = collector.agents.find((a) => a.id === r.id);
                    const removed = r.denied ? [...r.denied.role.map((m) => `${m} (role)`), ...r.denied.plan.map((m) => `${m} (plan)`), ...r.denied.unknown.map((m) => `${m} (unknown)`)] : [];
                    return (
                      <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2 text-[12px]">
                        <span className="inline-flex min-w-0 items-center gap-2">
                          {r.ok ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" /> : <XCircle className="h-4 w-4 shrink-0 text-red-300" />}
                          <span className="truncate font-bold text-white/80">{r.name}</span>
                          {!r.ok ? <span className="truncate text-red-200">{r.message}</span> : removed.length ? <span className="truncate text-white/45">removed {removed.join(', ')}</span> : null}
                        </span>
                        {r.ok && agent ? <DeliveryBadge agent={agent} /> : null}
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}
          </div>

          {/* Right column */}
          <div className="space-y-4">
            <div className={`${PANEL} p-5`}>
              <div className="mb-3 flex items-center justify-between">
                <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Server className="h-4 w-4 text-cyan-300" /> Selected Collector</h3>
                {selectedAgent ? <StatusBadge status={agentDisplayStatus(selectedAgent)} /> : null}
              </div>
              <div className="relative mb-3">
                <select aria-label="Selected collector" value={selectedId || ''} onChange={(e) => setSelectedId(e.target.value || null)} className="w-full appearance-none rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none focus:border-cyan-400/50">
                  {collector.agents.map((a) => <option key={a.id} value={a.id}>{a.name || a.id}{isActiveAgent(a) ? '' : ' (revoked)'}</option>)}
                </select>
                <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
              </div>
              {selectedAgent ? (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      ['Role', role.label],
                      ['Environment', String(selectedAgent.metadata?.environment || 'production')],
                      ['Health', `${agentHealthScore(selectedAgent)}/100`],
                      ['Last seen', relTime(selectedAgent.last_seen_at)],
                    ].map(([k, v]) => (
                      <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                        <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                        <div className="mt-0.5 truncate text-sm font-semibold capitalize text-white/85">{v}</div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-2 flex items-start justify-between gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                    <div className="min-w-0">
                      <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">Policy delivery</div>
                      <div className="mt-0.5 text-[11px] leading-snug text-white/55">{policyDelivery(selectedAgent).detail}</div>
                    </div>
                    <DeliveryBadge agent={selectedAgent} />
                  </div>
                </>
              ) : null}
              {selectedAgent && isActiveAgent(selectedAgent) ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  <button type="button" onClick={async () => { const r = await collector.rotateToken(selectedAgent.id); onToast(r.ok ? 'ok' : 'bad', r.ok ? 'New token generated below — copy it now.' : r.message || 'Failed'); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-amber-400/40 hover:text-amber-200">
                    <KeyRound className="h-3.5 w-3.5" /> Rotate token
                  </button>
                  <button type="button" onClick={async () => { if (!window.confirm(`Revoke ${selectedAgent.name}? It stops being accepted immediately.`)) return; const r = await collector.revokeCollector(selectedAgent.id); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Revoked' : 'Failed')); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-orange-400/40 hover:text-orange-200">
                    <Shield className="h-3.5 w-3.5" /> Revoke
                  </button>
                  <button type="button" onClick={async () => { if (!window.confirm('Delete this collector permanently? This cannot be undone.')) return; const r = await collector.deleteCollector(selectedAgent.id); if (r.ok) setSelectedId(null); onToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Deleted' : 'Failed')); }} className="inline-flex items-center gap-1.5 rounded-lg border border-red-400/25 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/20">
                    <Trash2 className="h-3.5 w-3.5" /> Delete
                  </button>
                </div>
              ) : null}
              {collector.oneTimeToken && collector.oneTimeToken.agentId === selectedId ? (
                <div className={`mt-3 rounded-xl border p-3 ${NOTICE}`}>
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide"><KeyRound className="h-3 w-3" /> One-time token · shown once</div>
                  <div className="flex items-center gap-2">
                    <code className="qg-force-dark flex-1 break-all rounded-lg border border-white/12 bg-black/40 px-2.5 py-1.5 font-mono text-[11px] text-emerald-200">{collector.oneTimeToken.token}</code>
                    <button type="button" aria-label="Copy token" onClick={() => { navigator.clipboard?.writeText(collector.oneTimeToken!.token); onToast('ok', 'Token copied.'); }} className="rounded-lg border border-white/12 bg-white/[0.04] px-2 py-1.5 text-[11px] font-bold text-white/70 hover:text-cyan-200"><Copy className="h-3.5 w-3.5" /></button>
                  </div>
                </div>
              ) : null}
            </div>

            {/* Fleet rollout */}
            <div className={`${PANEL} p-5`}>
              <h3 className="mb-1 inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Activity className="h-4 w-4 text-cyan-300" /> Policy Rollout</h3>
              <p className="mb-3 text-[11px] text-white/40">Whether each collector has pulled its current policy.</p>
              <ul className="space-y-1.5">
                {manageable.map((agent) => {
                  const p = policyFromAgent(agent);
                  return (
                    <li key={agent.id}>
                      <button type="button" onClick={() => setSelectedId(agent.id)} className={`flex w-full items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left transition ${agent.id === selectedId ? 'border-cyan-400/35 bg-cyan-400/[0.06]' : 'border-white/8 bg-white/[0.02] hover:border-white/20'}`}>
                        <span className="min-w-0">
                          <span className="block truncate text-[12px] font-bold text-white/85">{agent.name}</span>
                          <span className="block truncate text-[10px] text-white/40">{p.enabled ? `${p.scanTypes.length} modules · ${p.allowedTargets.length + p.allowedPaths.length} scope · ${p.intervalSeconds}s` : 'Scanning disabled'}</span>
                        </span>
                        <DeliveryBadge agent={agent} />
                      </button>
                    </li>
                  );
                })}
              </ul>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-white/8 pt-3 text-[11px] text-white/45">
                <span>{collector.sseConnected ? 'Live stream connected' : 'Live stream reconnecting'} · synced {relTime(collector.lastSyncAt)}</span>
                <div className="flex gap-2">
                  <button type="button" onClick={async () => { let ok = 0; for (const a of openAlerts.slice(0, 25)) { const r = await collector.acknowledgeAlert(a.id); if (r.ok) ok += 1; } onToast('ok', `Acknowledged ${ok} alert(s).`); }} disabled={!openAlerts.length} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/70 transition hover:text-cyan-200 disabled:opacity-40">
                    <BellRing className="h-3.5 w-3.5" /> Acknowledge {Math.min(openAlerts.length, 25)} alert{openAlerts.length === 1 ? '' : 's'}
                  </button>
                  <button type="button" onClick={() => void collector.refresh()} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-bold text-white/70 transition hover:text-cyan-200">
                    <RefreshCw className={`h-3.5 w-3.5 ${collector.busy ? 'animate-spin' : ''}`} /> Sync now
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Standards */}
      <div className={`${PANEL} p-5`}>
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-emerald-300" />
          <h3 className="text-sm font-black uppercase tracking-wide text-white/80">Security Standards</h3>
        </div>
        <p className="mt-1 text-sm text-white/50">The mandatory post-quantum cryptographic stack collectors and patchers enforce and migrate toward — NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NSA CNSA 2.0.</p>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {stackGroups.map((g) => (
            <div key={g.title} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="mb-2 text-[11px] font-black uppercase tracking-wide text-emerald-300/80">{g.title}</div>
              <ul className="space-y-1">
                {g.items.filter(Boolean).map((item, i) => (
                  <li key={i} className="flex items-center gap-2 text-[12px] text-white/70"><Circle className="h-1.5 w-1.5 fill-emerald-400 text-emerald-400" /> {item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Advanced: API references */}
      <div className={`${PANEL} overflow-hidden`}>
        <button type="button" onClick={() => setApiOpen((v) => !v)} aria-expanded={apiOpen} className="flex w-full items-center justify-between px-5 py-4 text-left">
          <span className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/70"><Code2 className="h-4 w-4" /> Tenant API References</span>
          <ChevronDown className={`h-4 w-4 text-white/45 transition ${apiOpen ? 'rotate-180' : ''}`} />
        </button>
        {apiOpen ? (
          <div className="border-t border-white/8 px-5 py-4">
            <div className="grid grid-cols-1 gap-2 font-mono text-[11px] text-white/55 md:grid-cols-2 xl:grid-cols-3">
              {[
                'POST /api/v1/agent-scanner/agents/enroll',
                'GET  /api/v1/agent-scanner/agents',
                'GET  /api/v1/agent-scanner/stream',
                'PUT  /api/v1/agent-scanner/agents/{id}/policy',
                'PUT  /api/v1/agent-scanner/agents/{id}/binding',
                'POST /api/v1/agent-scanner/agents/{id}/token/rotate',
                'POST /api/v1/agent-scanner/agent/heartbeat',
                'GET  /api/v1/agent-scanner/agent/policy',
                'POST /api/v1/agent-scanner/agent/evidence',
                'POST /api/v1/agent-scanner/agent/runtime-events',
                'POST /api/v1/agent-scanner/alerts/{id}/acknowledge',
                'GET  /api/v1/agent-scanner/remediation/patch-options',
              ].map((route) => (
                <div key={route} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">{route}</div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
