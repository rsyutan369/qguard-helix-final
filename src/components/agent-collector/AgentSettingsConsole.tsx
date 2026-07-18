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
  Gauge,
  KeyRound,
  Loader2,
  RefreshCw,
  Save,
  Server,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Wifi,
  WifiOff,
  XCircle,
} from 'lucide-react';
import { mandatoryPqcStackMetadata } from '@/lib/crypto/mandatory-pqc-stack';
import {
  agentDisplayStatus,
  agentHealthScore,
  isAgentOnline,
  useAgentCollector,
  type AgentPolicyInput,
  type CollectorAgent,
} from '@/hooks/use-agent-collector';

/**
 * AgentSettingsConsole — the redesigned Scanner → Settings surface.
 *
 * Complements the Agent Collector Console: it shares the SAME
 * `useAgentCollector` hook (identical REST + `agent-scanner-sync` SSE, RBAC,
 * audit, telemetry), so collector state, live sync and lifecycle actions stay
 * consistent across both tabs. This surface owns collector *configuration* —
 * policy scope, heartbeat, alert threshold, authorized targets/paths, apply to
 * one or all collectors — plus the enforced post-quantum Security Standards.
 * Zero backend changes.
 */

const PANEL = 'rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]';
const MANDATORY_STACK = mandatoryPqcStackMetadata();

// Granular scan-scope ids the backend agent policy understands (scan_types).
const POLICY_SCAN_TYPES: Array<{ id: string; label: string; detail: string }> = [
  { id: 'tls', label: 'TLS', detail: 'Protocols, ciphers, key exchange' },
  { id: 'certificates', label: 'Certificates', detail: 'X.509 chains & expiry' },
  { id: 'pki', label: 'PKI', detail: 'Trust stores & issuers' },
  { id: 'ssh', label: 'SSH', detail: 'Host & authorized keys' },
  { id: 'vpn', label: 'VPN', detail: 'IPsec, OpenVPN, WireGuard' },
  { id: 'libraries', label: 'Libraries', detail: 'OpenSSL, OQS, JVM, .NET' },
  { id: 'configs', label: 'Configs', detail: 'Crypto policy files' },
  { id: 'packages', label: 'Packages', detail: 'Manifests & versions' },
  { id: 'kubernetes', label: 'Kubernetes', detail: 'Ingress & cert-manager' },
  { id: 'cloud', label: 'Cloud', detail: 'AWS, Azure, GCP, OCI' },
  { id: 'cloud_kms', label: 'Cloud KMS', detail: 'Key vault & KMS policy' },
  { id: 'hsm', label: 'HSM/KMS', detail: 'PKCS#11, KMS, vault' },
  { id: 'database', label: 'Databases', detail: 'DB TLS, certs, keys' },
  { id: 'web_application', label: 'Web Apps', detail: 'Websites & portals' },
  { id: 'api', label: 'APIs', detail: 'API crypto & signing' },
  { id: 'runtime', label: 'Runtime', detail: 'Handshake & drift events' },
];

const ALERT_THRESHOLDS = ['low', 'moderate', 'high', 'critical'];

function fmtDate(value?: string | null): string {
  if (!value) return 'Never';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? 'Unknown' : d.toLocaleString();
}
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

export default function AgentSettingsConsole() {
  const collector = useAgentCollector(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [applyMode, setApplyMode] = useState<'selected' | 'all'>('selected');
  const [form, setForm] = useState<AgentPolicyInput>(policyFromAgent(null));
  const [savingAll, setSavingAll] = useState(false);
  const [toast, setToast] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null);
  const [apiOpen, setApiOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const showToast = useCallback((tone: 'ok' | 'bad', text: string) => {
    setToast({ tone, text });
    setTimeout(() => setToast(null), 3200);
  }, []);

  // Default the selection to the first collector once loaded.
  useEffect(() => {
    if (!selectedId && collector.agents.length) setSelectedId(collector.agents[0].id);
  }, [collector.agents, selectedId]);

  const selectedAgent = collector.agents.find((a) => a.id === selectedId) || null;
  const manageableAgents = collector.agents.filter((a) => !a.revoked_at && String(a.status || '').toLowerCase() !== 'revoked');

  const loadPolicy = useCallback((agent: CollectorAgent | null) => {
    setForm(policyFromAgent(agent));
  }, []);

  const targetCount = applyMode === 'all' ? manageableAgents.length : selectedAgent && !selectedAgent.revoked_at ? 1 : 0;
  const scopeCount = form.allowedTargets.length + form.allowedPaths.length;
  const canSave = targetCount > 0 && form.scanTypes.length > 0 && (!form.enabled || scopeCount > 0);

  const parseLines = (text: string): string[] => text.split(/\r?\n|,/).map((t) => t.trim()).filter(Boolean);

  const applyPolicy = useCallback(async () => {
    const targets = applyMode === 'all' ? manageableAgents : selectedAgent && !selectedAgent.revoked_at ? [selectedAgent] : [];
    if (!targets.length) { showToast('bad', 'Select an active collector or switch to “All active collectors”.'); return; }
    if (form.scanTypes.length === 0 || (form.enabled && scopeCount === 0)) { showToast('bad', 'Add at least one scan scope and one authorized target or path.'); return; }
    setSavingAll(true);
    let ok = 0;
    for (const agent of targets) {
      const result = await collector.updatePolicy(agent.id, form);
      if (result.ok) ok += 1;
    }
    setSavingAll(false);
    showToast(ok === targets.length ? 'ok' : 'bad', ok === targets.length ? `Policy applied to ${ok} collector${ok === 1 ? '' : 's'}.` : `Applied to ${ok}/${targets.length} — some failed.`);
  }, [applyMode, manageableAgents, selectedAgent, form, scopeCount, collector, showToast]);

  const openAlerts = collector.alerts.filter((a) => !['resolved', 'closed', 'suppressed'].includes(String(a.status || 'open').toLowerCase()));

  const stackGroups = useMemo(() => [
    { title: 'Libraries', items: MANDATORY_STACK.requiredLibraries },
    { title: 'Key Establishment', items: [MANDATORY_STACK.keyExchange.primary, MANDATORY_STACK.keyExchange.hybrid] },
    { title: 'Signatures', items: [MANDATORY_STACK.signatures.primary, MANDATORY_STACK.signatures.hybrid] },
    { title: 'Data Protection', items: [MANDATORY_STACK.encryption.symmetric, MANDATORY_STACK.kdf.primary, ...MANDATORY_STACK.hashes] },
    { title: 'TLS Policy', items: [MANDATORY_STACK.tls.minProtocol, `${MANDATORY_STACK.tls.preferredGroup} preferred`, 'Hybrid TLS enabled'] },
    { title: 'High Security Profile', items: [MANDATORY_STACK.highSecurityProfile.keyExchange, ...MANDATORY_STACK.highSecurityProfile.signatures] },
  ], []);

  const summaryCards = [
    { label: 'Registered', value: collector.summary.registered },
    { label: 'Online', value: collector.summary.online },
    { label: 'Revoked', value: collector.summary.revoked },
    { label: 'Open Alerts', value: openAlerts.length },
    { label: 'Evidence', value: collector.summary.evidenceCount },
    { label: 'Connectors', value: collector.connectors.length },
  ];

  return (
    <div className="space-y-5">
      {toast ? (
        <div role="status" className={`fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold shadow-2xl backdrop-blur-xl ${toast.tone === 'ok' ? 'border-emerald-400/30 bg-emerald-500/15 text-emerald-100' : 'border-red-400/30 bg-red-500/15 text-red-100'}`}>
          {toast.tone === 'ok' ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />} {toast.text}
        </div>
      ) : null}

      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h2 className="text-xl font-black tracking-tight text-white">Collector Settings</h2>
          <p className="mt-1 text-sm text-white/50">Configure collector policy, scan scope and post-quantum enforcement — applied live to your agents.</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-[11px] font-bold text-white/60">
            {collector.sseConnected ? <Wifi className="h-3.5 w-3.5 text-emerald-300" /> : <WifiOff className="h-3.5 w-3.5 text-amber-300" />}
            {collector.sseConnected ? 'Live' : 'Reconnecting'}
          </span>
          <button type="button" onClick={() => void collector.refresh()} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-1.5 text-xs font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200">
            <RefreshCw className={`h-3.5 w-3.5 ${collector.busy ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {collector.error ? (
        <div className="flex items-start gap-2 rounded-xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" /> <span>{collector.error}</span>
        </div>
      ) : null}

      {/* Summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {summaryCards.map((c) => (
          <div key={c.label} className={`${PANEL} p-4`}>
            <div className="text-3xl font-black tabular-nums text-white">{c.value}</div>
            <div className="mt-1 text-[11px] font-bold uppercase tracking-wide text-white/40">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(340px,0.8fr)]">
        {/* Policy editor */}
        <div className={`${PANEL} p-5`}>
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><SlidersHorizontal className="h-4 w-4 text-cyan-300" /> Collector Policy</h3>
            <div className="flex items-center gap-2">
              <div className="relative">
                <select value={applyMode} onChange={(e) => setApplyMode(e.target.value as 'selected' | 'all')} className="appearance-none rounded-lg border border-white/12 bg-white/[0.03] px-3 py-1.5 pr-8 text-xs font-bold text-white/75 outline-none focus:border-cyan-400/50">
                  <option value="selected" className="bg-[#0b1120]">Selected collector</option>
                  <option value="all" className="bg-[#0b1120]">All active collectors</option>
                </select>
                <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/40" />
              </div>
              <span className="rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5 text-[11px] font-bold text-white/45">{targetCount} target{targetCount === 1 ? '' : 's'}</span>
            </div>
          </div>

          {/* Enabled + interval + threshold */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="flex items-center justify-between gap-3 rounded-xl border border-white/8 bg-white/[0.02] p-3.5 sm:col-span-2">
              <span>
                <span className="block text-xs font-bold text-white/75">Policy Enabled</span>
                <span className="mt-0.5 block text-[11px] text-white/40">Server-side enforcement of collector scanning and evidence.</span>
              </span>
              <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((c) => ({ ...c, enabled: e.target.checked }))} className="h-5 w-5 accent-cyan-400" aria-label="Policy enabled" />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Heartbeat Interval (seconds)</span>
              <input type="number" min={30} max={60} step={30} value={form.intervalSeconds} onChange={(e) => setForm((c) => ({ ...c, intervalSeconds: Math.max(30, Math.min(60, Number(e.target.value) || 60)) }))} className="w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none focus:border-cyan-400/50" />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Alert Threshold</span>
              <div className="relative">
                <select value={form.alertThreshold} onChange={(e) => setForm((c) => ({ ...c, alertThreshold: e.target.value }))} className="w-full appearance-none rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm capitalize text-white outline-none focus:border-cyan-400/50">
                  {ALERT_THRESHOLDS.map((t) => <option key={t} value={t} className="bg-[#0b1120] capitalize">{t}</option>)}
                </select>
                <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
              </div>
            </label>
          </div>

          {/* Scan scope */}
          <div className="mt-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-bold text-white/60">Scan Scope</span>
              <span className="text-[11px] text-white/40">{form.scanTypes.length} selected</span>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-4">
              {POLICY_SCAN_TYPES.map((st) => {
                const on = form.scanTypes.includes(st.id);
                return (
                  <button
                    key={st.id}
                    type="button"
                    onClick={() => setForm((c) => ({ ...c, scanTypes: on ? c.scanTypes.filter((x) => x !== st.id) : Array.from(new Set([...c.scanTypes, st.id])) }))}
                    aria-pressed={on}
                    className={`rounded-xl border px-3 py-2 text-left transition ${on ? 'border-cyan-400/40 bg-cyan-400/[0.08]' : 'border-white/8 bg-white/[0.02] hover:border-white/20'}`}
                  >
                    <span className={`flex items-center gap-1.5 text-xs font-bold ${on ? 'text-cyan-200' : 'text-white/70'}`}>
                      {on ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Circle className="h-3.5 w-3.5 text-white/30" />} {st.label}
                    </span>
                    <span className="mt-0.5 block text-[10px] text-white/40">{st.detail}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Targets + paths */}
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Authorized Targets</span>
              <textarea
                rows={5}
                value={form.allowedTargets.join('\n')}
                onChange={(e) => setForm((c) => ({ ...c, allowedTargets: parseLines(e.target.value) }))}
                placeholder={'api.customer.com:443\nssh://server.customer.com:22\narn:aws:...'}
                className="w-full resize-none rounded-xl border border-white/12 bg-black/30 px-3.5 py-2.5 font-mono text-xs text-white/80 outline-none focus:border-cyan-400/50"
              />
              <span className="mt-1 block text-[10px] text-white/35">Allowlist: URLs, host:port, SSH URLs, ARNs, K8s resources, KMS/HSM keys, cert IDs.</span>
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Authorized Paths</span>
              <textarea
                rows={5}
                value={form.allowedPaths.join('\n')}
                onChange={(e) => setForm((c) => ({ ...c, allowedPaths: parseLines(e.target.value) }))}
                placeholder={'/etc/nginx/conf\n/opt/customer-api/config'}
                className="w-full resize-none rounded-xl border border-white/12 bg-black/30 px-3.5 py-2.5 font-mono text-xs text-white/80 outline-none focus:border-cyan-400/50"
              />
              <span className="mt-1 block text-[10px] text-white/35">Filesystem allowlist visible to the installed collector, service account, or sidecar.</span>
            </label>
          </div>

          {/* Actions */}
          <div className="mt-5 flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => void applyPolicy()} disabled={savingAll || !canSave} className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/40 bg-gradient-to-r from-cyan-500/80 to-blue-500/70 px-4 py-2.5 text-sm font-black text-white shadow-lg transition hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50">
              {savingAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Apply Policy
            </button>
            <button type="button" onClick={() => loadPolicy(selectedAgent)} disabled={!selectedAgent} className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-40">
              Load Selected
            </button>
            <button
              type="button"
              onClick={() => { navigator.clipboard?.writeText(JSON.stringify(form, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1600); }}
              className="inline-flex items-center gap-2 rounded-xl border border-white/12 bg-white/[0.04] px-4 py-2.5 text-sm font-bold text-white/70 transition hover:text-cyan-200"
            >
              {copied ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <Copy className="h-4 w-4" />} {copied ? 'Copied' : 'Copy Policy'}
            </button>
          </div>
        </div>

        {/* Right column: selected collector + sync */}
        <div className="space-y-4">
          <div className={`${PANEL} p-5`}>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Server className="h-4 w-4 text-cyan-300" /> Selected Collector</h3>
              {selectedAgent ? <StatusBadge status={agentDisplayStatus(selectedAgent)} /> : <span className="text-[11px] text-white/35">None</span>}
            </div>
            <div className="relative mb-3">
              <select value={selectedId || ''} onChange={(e) => { const id = e.target.value || null; setSelectedId(id); loadPolicy(collector.agents.find((a) => a.id === id) || null); }} className="w-full appearance-none rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none focus:border-cyan-400/50">
                <option value="" className="bg-[#0b1120]">No collector selected</option>
                {collector.agents.map((a) => <option key={a.id} value={a.id} className="bg-[#0b1120]">{a.name || a.id}</option>)}
              </select>
              <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40" />
            </div>
            {selectedAgent ? (
              <div className="grid grid-cols-2 gap-2">
                {[
                  ['Environment', String(selectedAgent.metadata?.environment || 'production')],
                  ['Health', `${agentHealthScore(selectedAgent)}/100`],
                  ['Last Seen', relTime(selectedAgent.last_seen_at)],
                  ['Scope', `${policyFromAgent(selectedAgent).allowedTargets.length + policyFromAgent(selectedAgent).allowedPaths.length} item(s)`],
                ].map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                    <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                    <div className="mt-0.5 truncate text-sm font-semibold text-white/85">{v}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-white/8 bg-white/[0.02] p-4 text-sm text-white/40">No collector selected. Create one from the Agent Collectors tab.</div>
            )}
            {selectedAgent && !selectedAgent.revoked_at ? (
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={async () => { const r = await collector.rotateToken(selectedAgent.id); showToast(r.ok ? 'ok' : 'bad', r.ok ? 'New token generated below — copy it now.' : r.message || 'Failed'); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-amber-400/40 hover:text-amber-200">
                  <KeyRound className="h-3.5 w-3.5" /> Rotate
                </button>
                <button type="button" onClick={async () => { const r = await collector.revokeCollector(selectedAgent.id); showToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Revoked' : 'Failed')); }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-orange-400/40 hover:text-orange-200">
                  <Shield className="h-3.5 w-3.5" /> Revoke
                </button>
                <button type="button" onClick={async () => { if (!window.confirm('Delete this collector permanently?')) return; const r = await collector.deleteCollector(selectedAgent.id); if (r.ok) setSelectedId(null); showToast(r.ok ? 'ok' : 'bad', r.message || (r.ok ? 'Deleted' : 'Failed')); }} className="inline-flex items-center gap-1.5 rounded-lg border border-red-400/25 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/20">
                  <Trash2 className="h-3.5 w-3.5" /> Delete
                </button>
              </div>
            ) : null}
            {collector.oneTimeToken ? (
              <div className="mt-3 rounded-xl border border-amber-400/25 bg-amber-400/[0.06] p-3">
                <div className="mb-1 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wide text-amber-200"><KeyRound className="h-3 w-3" /> One-Time Token · shown once</div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 break-all rounded-lg border border-white/12 bg-black/40 px-2.5 py-1.5 font-mono text-[11px] text-emerald-200">{collector.oneTimeToken.token}</code>
                  <button type="button" onClick={() => { navigator.clipboard?.writeText(collector.oneTimeToken!.token); showToast('ok', 'Token copied.'); }} className="rounded-lg border border-white/12 bg-white/[0.04] px-2 py-1.5 text-[11px] font-bold text-white/70 hover:text-cyan-200"><Copy className="h-3.5 w-3.5" /></button>
                </div>
              </div>
            ) : null}
          </div>

          {/* Sync & alerts */}
          <div className={`${PANEL} p-5`}>
            <h3 className="mb-3 inline-flex items-center gap-2 text-sm font-black uppercase tracking-wide text-white/80"><Activity className="h-4 w-4 text-cyan-300" /> Live Sync & Alerts</h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                ['Live Stream', collector.sseConnected ? 'Connected' : 'Reconnecting'],
                ['Last Sync', relTime(collector.lastSyncAt)],
                ['Connectors', String(collector.connectors.length)],
                ['Open Alerts', String(openAlerts.length)],
              ].map(([k, v]) => (
                <div key={k} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                  <div className="text-[10px] font-bold uppercase tracking-wide text-white/35">{k}</div>
                  <div className="mt-0.5 truncate text-sm font-semibold text-white/85">{v}</div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <button type="button" onClick={async () => { if (!openAlerts.length) { showToast('bad', 'No open alerts.'); return; } let ok = 0; for (const a of openAlerts.slice(0, 25)) { const r = await collector.acknowledgeAlert(a.id); if (r.ok) ok += 1; } showToast('ok', `Acknowledged ${ok} alert(s).`); }} disabled={!openAlerts.length} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200 disabled:opacity-40">
                <BellRing className="h-3.5 w-3.5" /> Acknowledge Alerts
              </button>
              <button type="button" onClick={() => void collector.refresh()} className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-xs font-bold text-white/75 transition hover:border-cyan-400/40 hover:text-cyan-200">
                <RefreshCw className="h-3.5 w-3.5" /> Sync Now
              </button>
            </div>
          </div>
        </div>
      </div>

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
        <button type="button" onClick={() => setApiOpen((v) => !v)} className="flex w-full items-center justify-between px-5 py-4 text-left">
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
                'POST /api/v1/agent-scanner/agents/{id}/token/rotate',
                'POST /api/v1/agent-scanner/agent/heartbeat',
                'POST /api/v1/agent-scanner/agent/runtime-events',
                'POST /api/v1/agent-scanner/agent/evidence',
                'GET  /api/v1/agent-scanner/agent/remediation/jobs',
                'POST /api/v1/agent-scanner/remediation/operator-actions',
                'POST /api/v1/agent-scanner/alerts/{id}/acknowledge',
                'GET  /api/v1/agent-scanner/remediation/patch-options',
              ].map((route) => (
                <div key={route} className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">{route}</div>
              ))}
            </div>
          </div>
        ) : null}
      </div>

      {collector.state === 'loading' && !collector.agents.length ? (
        <div className="flex items-center gap-2 text-xs text-white/40"><Clock className="h-3.5 w-3.5" /> <Gauge className="h-3.5 w-3.5" /> Loading collector settings…</div>
      ) : null}
    </div>
  );
}
