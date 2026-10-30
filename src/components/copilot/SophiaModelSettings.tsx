import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  X, KeyRound, ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertTriangle, CircleDashed,
  Loader2, Eye, EyeOff, RefreshCw, Trash2, Power, Lock, Sparkles, Database, Cpu, ExternalLink, Crown,
} from 'lucide-react';
import { useCopilotLlm } from '@/hooks/use-copilot-llm';
import {
  COPILOT_LLM_PROVIDERS,
  MODEL_ID_PATTERN,
  endpointSpec,
  type CopilotLlmProviderId,
  type CopilotLlmProviderSpec,
  type CopilotLlmProviderStatus,
} from '@/lib/copilot-llm-catalog';

/**
 * SophiaModelSettings — bring-your-own-key model connections.
 *
 * A tenant connects their own Anthropic / OpenAI / Hermes / Kimi / GLM /
 * DeepSeek key. The key is verified live, sealed server-side, and the verified
 * model becomes the engine that writes Sophia's analysis. Sophia's platform
 * engine still gathers every fact (tenant-isolated, RBAC-scoped), so the model
 * only ever sees the evidence the user could already see.
 */

const CUSTOM_MODEL = '__custom__';

type StatusKey = CopilotLlmProviderStatus['status'];
const STATUS_META: Record<StatusKey, { label: string; className: string; Icon: typeof CheckCircle2 }> = {
  verified: { label: 'Verified', className: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-300', Icon: CheckCircle2 },
  unverified: { label: 'Not verified', className: 'border-slate-500/40 bg-slate-500/10 text-slate-300', Icon: CircleDashed },
  invalid: { label: 'Key rejected', className: 'border-red-500/40 bg-red-500/10 text-red-300', Icon: XCircle },
  error: { label: 'Last call failed', className: 'border-amber-500/40 bg-amber-500/10 text-amber-200', Icon: AlertTriangle },
  not_configured: { label: 'Not connected', className: 'border-slate-700/60 bg-slate-900/40 text-slate-400', Icon: CircleDashed },
};

function StatusBadge({ status }: { status: StatusKey }) {
  const meta = STATUS_META[status];
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${meta.className}`}>
      <meta.Icon className="h-3 w-3" /> {meta.label}
    </span>
  );
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${Math.round(n / 1000)}k`;
  return n.toLocaleString();
}

function formatWhen(iso: string | null): string {
  if (!iso) return 'Never';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? 'Never' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function ProviderTile({ spec, status, selected, onSelect }: {
  spec: CopilotLlmProviderSpec; status?: CopilotLlmProviderStatus; selected: boolean; onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`group relative flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition-all ${selected ? 'border-cyan-400/60 bg-cyan-500/[0.08] shadow-[0_0_0_1px_rgba(34,211,238,0.25)]' : 'border-slate-700/50 bg-slate-900/40 hover:border-slate-500/60 hover:bg-slate-900/70'}`}
    >
      <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-gradient-to-br ${spec.accent} text-[11px] font-black tracking-wide text-slate-50`}>
        {spec.monogram}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-bold text-slate-100">{spec.label}</span>
          {status?.active && <span className="rounded bg-cyan-400/20 px-1.5 py-px text-[8px] font-black uppercase tracking-wider text-cyan-200">Active</span>}
        </span>
        <span className="block truncate text-[10px] text-slate-500">{status?.configured ? `${status.model} · key …${status.keyHint}` : spec.vendor}</span>
      </span>
      {status?.configured && (
        status.status === 'verified'
          ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-label="Verified" />
          : status.status === 'invalid'
            ? <XCircle className="h-4 w-4 shrink-0 text-red-400" aria-label="Key rejected" />
            : <AlertTriangle className="h-4 w-4 shrink-0 text-amber-300" aria-label={STATUS_META[status.status].label} />
      )}
    </button>
  );
}

export function SophiaModelSettings({ open, onClose, onChanged }: { open: boolean; onClose: () => void; onChanged?: () => void }) {
  const llm = useCopilotLlm(open);
  const { settings, state, busy } = llm;
  const [selected, setSelected] = useState<CopilotLlmProviderId>('anthropic');
  const [endpoint, setEndpoint] = useState('');
  const [modelChoice, setModelChoice] = useState('');
  const [customModel, setCustomModel] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [consent, setConsent] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);

  const spec = COPILOT_LLM_PROVIDERS.find((p) => p.id === selected)!;
  const status = settings?.providers.find((p) => p.provider === selected);
  const active = settings?.providers.find((p) => p.active) || null;
  const activeSpec = active ? COPILOT_LLM_PROVIDERS.find((p) => p.id === active.provider) : null;
  const locked = settings ? !settings.entitled : false;
  const sealingOff = settings?.encryption === 'unavailable';
  const canEdit = !!settings && !locked && !sealingOff;

  // Open on the active provider (or the first connected one) so the user lands on what is live.
  useEffect(() => {
    if (!open || !settings) return;
    const first = settings.providers.find((p) => p.active) || settings.providers.find((p) => p.configured);
    if (first) setSelected(first.provider);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, settings === null]);

  // Re-seed the form whenever the provider (or its stored configuration) changes.
  useEffect(() => {
    const ep = endpointSpec(spec, status?.endpoint);
    setEndpoint(ep.id);
    const storedModel = status?.model || ep.models[0]?.id || '';
    const known = ep.models.some((m) => m.id === storedModel);
    setModelChoice(known ? storedModel : CUSTOM_MODEL);
    setCustomModel(known ? '' : storedModel);
    setApiKey('');
    setShowKey(false);
    setConsent(false);
    setConfirmRemove(false);
  }, [selected, status?.endpoint, status?.model, spec]);

  // A result message belongs to the provider it was about.
  useEffect(() => { setNotice(null); }, [selected]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // Never keep a typed key around after the dialog closes.
  useEffect(() => { if (!open) { setApiKey(''); setShowKey(false); } }, [open]);

  const ep = useMemo(() => endpointSpec(spec, endpoint), [spec, endpoint]);
  const model = modelChoice === CUSTOM_MODEL ? customModel.trim() : modelChoice;
  const modelValid = MODEL_ID_PATTERN.test(model);
  const hasNewKey = apiKey.trim().length > 0;
  const configChanged = !!status?.configured && (status.model !== model || status.endpoint !== endpoint);
  const canSubmit = canEdit && modelValid && (hasNewKey ? consent : configChanged);

  if (!open) return null;

  const finish = (result: { ok: boolean; message?: string }, okText: string) => {
    setNotice(result.ok ? { tone: 'ok', text: result.message ? `${okText} · ${result.message}` : okText } : { tone: 'error', text: result.message || 'Request failed' });
    if (result.ok) { setApiKey(''); setShowKey(false); setConsent(false); onChanged?.(); }
  };

  const submit = async () => {
    if (!canSubmit) return;
    const result = await llm.saveConnection({ provider: selected, model, endpoint, apiKey: hasNewKey ? apiKey.trim() : undefined, consent });
    finish(result, `${spec.label} connected — Sophia now writes with ${model}`);
  };

  const verify = async () => finish(await llm.verifyConnection(selected), 'Connection verified');
  const activate = async () => finish(await llm.setActive(selected), `${spec.label} is now the active engine`);
  const deactivate = async () => finish(await llm.setActive(null), 'Sophia is using the platform engine only');
  const remove = async () => {
    if (!confirmRemove) { setConfirmRemove(true); return; }
    finish(await llm.removeConnection(selected), `${spec.label} disconnected and its key deleted`);
  };

  return (
    <div className="fixed inset-0 z-[80] flex items-stretch justify-center bg-slate-950/70 p-0 backdrop-blur-sm sm:items-center sm:p-6" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="sophia-models-title"
        className="flex max-h-[100dvh] w-full max-w-5xl flex-col overflow-hidden border border-slate-700/60 bg-[#070b16] shadow-2xl shadow-cyan-950/40 focus:outline-none sm:max-h-[90vh] sm:rounded-2xl"
      >
        {/* Header */}
        <div className="relative flex items-start gap-3 border-b border-slate-700/50 bg-gradient-to-r from-cyan-500/[0.07] via-blue-500/[0.05] to-violet-500/[0.07] px-5 py-4">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-500/10"><Cpu className="h-5 w-5 text-cyan-300" /></span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="sophia-models-title" className="text-[16px] font-black tracking-tight text-slate-50">AI Models</h2>
              <span className="inline-flex items-center gap-1 rounded bg-gradient-to-r from-amber-400/20 to-orange-500/20 px-2 py-0.5 text-[9px] font-black uppercase tracking-wider text-amber-200"><Crown className="h-3 w-3" /> Pro &amp; Elite</span>
            </div>
            <p className="mt-0.5 text-[12px] text-slate-400">Connect your own model account. Sophia gathers the evidence from your tenant; your model writes the analysis from that evidence only.</p>
          </div>
          <button onClick={onClose} className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-100" aria-label="Close"><X className="h-4 w-4" /></button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden scrollbar-thin">
          {/* Active engine + trust strip */}
          <div className="grid gap-3 border-b border-slate-800/80 px-5 py-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
            <div className="rounded-xl border border-slate-700/50 bg-slate-900/40 p-3">
              <div className="text-[9px] font-black uppercase tracking-[0.2em] text-slate-500">Active engine</div>
              {state === 'loading' && !settings ? (
                <div className="mt-2 flex items-center gap-2 text-[12px] text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading connections…</div>
              ) : active && activeSpec ? (
                <div className="mt-1.5 flex items-center gap-2.5">
                  <span className={`flex h-8 w-8 items-center justify-center rounded-lg border border-white/10 bg-gradient-to-br ${activeSpec.accent} text-[10px] font-black text-slate-50`}>{activeSpec.monogram}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px] font-bold text-slate-100">{activeSpec.label}</div>
                    <div className="truncate text-[11px] text-slate-500">{active.model}</div>
                  </div>
                  <button onClick={deactivate} disabled={busy !== null} className="inline-flex items-center gap-1 rounded-lg border border-slate-600/60 px-2.5 py-1.5 text-[11px] font-semibold text-slate-300 transition-colors hover:border-slate-400 hover:text-slate-100 disabled:opacity-50" title="Stop using a connected model and answer with the platform engine only">
                    <Power className="h-3.5 w-3.5" /> Use platform engine
                  </button>
                </div>
              ) : (
                <div className="mt-1.5">
                  <div className="flex items-center gap-2 text-[13px] font-bold text-slate-200"><Sparkles className="h-4 w-4 text-cyan-300" /> Sophia platform engine</div>
                  <p className="mt-0.5 text-[11px] text-slate-500">Evidence-based answers built from your tenant’s modules. Connect a model below to add a written analysis on top.</p>
                </div>
              )}
            </div>
            <ol className="grid gap-2 sm:grid-cols-3">
              {[
                { Icon: Database, title: '1 · Evidence', text: 'Sophia queries your modules — tenant-isolated and scoped to your role.' },
                { Icon: Cpu, title: '2 · Your model', text: 'Receives only that evidence pack, with secrets redacted, under your own account.' },
                { Icon: ShieldCheck, title: '3 · Verified', text: 'Every figure it writes is checked against the evidence; anything that doesn’t trace back is flagged.' },
              ].map(({ Icon, title, text }) => (
                <li key={title} className="rounded-xl border border-slate-700/40 bg-slate-900/30 p-2.5">
                  <div className="flex items-center gap-1.5 text-[11px] font-bold text-slate-200"><Icon className="h-3.5 w-3.5 text-cyan-300/80" /> {title}</div>
                  <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">{text}</p>
                </li>
              ))}
            </ol>
          </div>

          {/* Plan / configuration banners */}
          {state === 'error' && !settings && (
            <div className="mx-5 mt-4 flex items-center justify-between gap-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-[12px] text-red-300">
              <span>Could not load your model connections.</span>
              <button onClick={() => llm.load()} className="inline-flex items-center gap-1 font-semibold text-red-200 hover:text-white"><RefreshCw className="h-3.5 w-3.5" /> Retry</button>
            </div>
          )}
          {locked && (
            <div className="mx-5 mt-4 flex flex-wrap items-center gap-3 rounded-xl border border-amber-400/30 bg-gradient-to-r from-amber-500/10 to-orange-500/5 px-4 py-3">
              <Lock className="h-5 w-5 shrink-0 text-amber-300" />
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-bold text-amber-100">Your own AI models are a Pro and Elite feature</div>
                <p className="text-[11px] text-amber-200/70">Your plan: {settings?.tier === 'none' ? 'no active plan' : settings?.tier}. Sophia’s platform engine stays fully available.</p>
              </div>
              <Link to="/dashboard/settings" onClick={onClose} className="rounded-lg bg-gradient-to-r from-amber-400 to-orange-500 px-3 py-1.5 text-[12px] font-bold text-slate-950 no-underline">Upgrade plan</Link>
            </div>
          )}
          {sealingOff && !locked && (
            <div className="mx-5 mt-4 flex items-start gap-2.5 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-[12px] text-red-200">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <span><strong>Key storage is not configured on this server.</strong> An administrator must set <code className="rounded bg-black/40 px-1">COPILOT_BYOK_SECRET</code> (32+ random characters) before keys can be stored.</span>
            </div>
          )}
          {settings && !locked && !sealingOff && (settings.encryption === 'derived' || settings.storage === 'memory') && (
            <div className="mx-5 mt-4 flex items-start gap-2.5 rounded-xl border border-amber-400/30 bg-amber-500/[0.07] px-4 py-2.5 text-[11px] text-amber-200/90">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                {settings.encryption === 'derived' && <>Development mode: keys are sealed with a key derived from the service-role secret. Set <code className="rounded bg-black/40 px-1">COPILOT_BYOK_SECRET</code> before production. </>}
                {settings.storage === 'memory' && <>The <code className="rounded bg-black/40 px-1">copilot_llm_providers</code> table is not applied — connections live in server memory and are lost on restart (apply <code className="rounded bg-black/40 px-1">supabase/sophia-byok-schema.sql</code>).</>}
              </span>
            </div>
          )}

          {/* Providers + detail */}
          <div className="grid gap-4 px-5 py-4 lg:grid-cols-[minmax(0,280px)_minmax(0,1fr)]">
            <div className="space-y-1.5" role="list" aria-label="Model providers">
              {COPILOT_LLM_PROVIDERS.map((p) => (
                <div role="listitem" key={p.id}>
                  <ProviderTile spec={p} status={settings?.providers.find((s) => s.provider === p.id)} selected={p.id === selected} onSelect={() => setSelected(p.id)} />
                </div>
              ))}
            </div>

            <div className="min-w-0 rounded-2xl border border-slate-700/50 bg-slate-900/30 p-4">
              <div className="flex flex-wrap items-start gap-3">
                <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-gradient-to-br ${spec.accent} text-[13px] font-black text-slate-50`}>{spec.monogram}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-[15px] font-black text-slate-50">{spec.label}</h3>
                    <StatusBadge status={status?.status || 'not_configured'} />
                    {status?.active && <span className="rounded-md border border-cyan-400/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-200">Active engine</span>}
                  </div>
                  <p className="mt-0.5 text-[12px] text-slate-400">{spec.tagline}</p>
                </div>
                <a href={spec.consoleUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-300 no-underline hover:text-cyan-200">Get a key <ExternalLink className="h-3 w-3" /></a>
              </div>

              {status?.lastError && status.status !== 'verified' && (
                <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/[0.07] px-3 py-2 text-[11px] text-red-200"><span className="font-bold">Last error:</span> {status.lastError}</div>
              )}

              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Endpoint</span>
                  <select value={endpoint} disabled={!canEdit} onChange={(e) => { setEndpoint(e.target.value); const next = endpointSpec(spec, e.target.value); setModelChoice(next.models[0]?.id || CUSTOM_MODEL); }} className="h-10 w-full rounded-lg border border-slate-700/60 bg-slate-950/60 px-2.5 text-[12px] text-slate-100 focus:border-cyan-400/60 focus:outline-none disabled:opacity-60">
                    {spec.endpoints.map((e) => <option key={e.id} value={e.id}>{e.label}</option>)}
                  </select>
                </label>
                <label className="block">
                  <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Model</span>
                  <select value={modelChoice} disabled={!canEdit} onChange={(e) => setModelChoice(e.target.value)} className="h-10 w-full rounded-lg border border-slate-700/60 bg-slate-950/60 px-2.5 text-[12px] text-slate-100 focus:border-cyan-400/60 focus:outline-none disabled:opacity-60">
                    {ep.models.map((m) => <option key={m.id} value={m.id}>{m.label}{m.note ? ` — ${m.note}` : ''}</option>)}
                    <option value={CUSTOM_MODEL}>Custom model id…</option>
                  </select>
                </label>
              </div>
              {modelChoice === CUSTOM_MODEL && (
                <label className="mt-3 block">
                  <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Custom model id</span>
                  <input value={customModel} disabled={!canEdit} onChange={(e) => setCustomModel(e.target.value)} placeholder="e.g. a newer model your account has access to" className={`h-10 w-full rounded-lg border bg-slate-950/60 px-3 font-mono text-[12px] text-slate-100 placeholder:font-sans placeholder:text-slate-600 focus:outline-none ${customModel && !modelValid ? 'border-red-500/60' : 'border-slate-700/60 focus:border-cyan-400/60'}`} />
                  {customModel && !modelValid && <span className="mt-1 block text-[10px] text-red-300">Letters, digits and . _ : / - only (max 100).</span>}
                </label>
              )}

              <label className="mt-3 block">
                <span className="mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  <span>{status?.configured ? 'Replace API key' : 'API key'}</span>
                  {status?.keyHint && <span className="font-mono normal-case tracking-normal text-slate-500">stored key …{status.keyHint}</span>}
                </span>
                <div className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-950/60 px-3 focus-within:border-cyan-400/60">
                  <KeyRound className="h-4 w-4 shrink-0 text-slate-500" />
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    disabled={!canEdit}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={status?.configured ? 'Leave blank to keep the stored key' : spec.keyHint}
                    autoComplete="off"
                    spellCheck={false}
                    name={`sophia-${spec.id}-api-key`}
                    className="h-10 min-w-0 flex-1 bg-transparent font-mono text-[12px] text-slate-100 placeholder:font-sans placeholder:text-slate-600 focus:outline-none disabled:opacity-60"
                  />
                  <button type="button" onClick={() => setShowKey((v) => !v)} disabled={!apiKey} className="text-slate-500 hover:text-slate-200 disabled:opacity-30" aria-label={showKey ? 'Hide key' : 'Show key'}>
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                <span className="mt-1 block text-[10px] text-slate-500">Sent once over your authenticated session, verified with {spec.vendor}, then sealed with AES-256-GCM on the server. It is never shown again.</span>
              </label>

              {hasNewKey && (
                <label className="mt-3 flex cursor-pointer items-start gap-2.5 rounded-lg border border-slate-700/50 bg-slate-950/40 px-3 py-2.5">
                  <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5 h-4 w-4 accent-cyan-400" />
                  <span className="text-[11px] leading-relaxed text-slate-300">
                    I authorise sending this tenant’s platform evidence (asset names, findings, statuses and scores I can see) to <strong>{spec.vendor}</strong> under my own account, subject to {spec.vendor}’s data terms. Secret-shaped values are redacted first.
                  </span>
                </label>
              )}

              {notice && (
                <div role="status" className={`mt-3 flex items-start gap-2 rounded-lg border px-3 py-2 text-[12px] ${notice.tone === 'ok' ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200' : 'border-red-500/40 bg-red-500/10 text-red-200'}`}>
                  {notice.tone === 'ok' ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0" />}
                  <span className="min-w-0 break-words">{notice.text}</span>
                </div>
              )}

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <button
                  onClick={submit}
                  disabled={!canSubmit || busy !== null}
                  className="inline-flex h-10 items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 text-[12px] font-bold text-white shadow-lg shadow-cyan-900/30 transition-opacity disabled:opacity-40"
                >
                  {busy === selected ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  {busy === selected ? 'Verifying with provider…' : status?.configured ? (hasNewKey ? 'Verify & replace key' : 'Verify & save changes') : 'Verify & connect'}
                </button>
                {status?.configured && !status.active && status.status !== 'invalid' && (
                  <button onClick={activate} disabled={busy !== null} className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-cyan-400/40 bg-cyan-500/10 px-3 text-[12px] font-semibold text-cyan-200 transition-colors hover:bg-cyan-500/20 disabled:opacity-40">
                    <Power className="h-4 w-4" /> Use this model
                  </button>
                )}
                {status?.configured && (
                  <button onClick={verify} disabled={busy !== null || !canEdit} className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-slate-600/60 px-3 text-[12px] font-semibold text-slate-300 transition-colors hover:border-slate-400 hover:text-slate-100 disabled:opacity-40">
                    <RefreshCw className="h-4 w-4" /> Re-verify
                  </button>
                )}
                {status?.configured && (
                  <button onClick={remove} disabled={busy !== null} className={`ml-auto inline-flex h-10 items-center gap-1.5 rounded-lg border px-3 text-[12px] font-semibold transition-colors disabled:opacity-40 ${confirmRemove ? 'border-red-500/60 bg-red-500/15 text-red-200' : 'border-slate-700/60 text-slate-400 hover:border-red-500/50 hover:text-red-300'}`}>
                    <Trash2 className="h-4 w-4" /> {confirmRemove ? 'Confirm — delete key' : 'Disconnect'}
                  </button>
                )}
              </div>
              {hasNewKey && !consent && canEdit && <p className="mt-2 text-[10px] text-slate-500">Tick the authorisation above to connect.</p>}

              {status?.configured && (
                <dl className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-800/80 pt-3 sm:grid-cols-4">
                  {[
                    { k: 'Requests', v: formatCount(status.requestCount) },
                    { k: 'Tokens in / out', v: `${formatCount(status.inputTokens)} / ${formatCount(status.outputTokens)}` },
                    { k: 'Last used', v: formatWhen(status.lastUsedAt) },
                    { k: 'Last verified', v: formatWhen(status.lastVerifiedAt) },
                  ].map(({ k, v }) => (
                    <div key={k} className="min-w-0 rounded-lg bg-slate-950/40 px-2.5 py-2">
                      <dt className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{k}</dt>
                      <dd className="mt-0.5 truncate text-[12px] font-semibold text-slate-200">{v}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>
          </div>
        </div>

        <div className="border-t border-slate-800/80 px-5 py-2.5 text-[10px] text-slate-500">
          Keys are per user and never leave the server unsealed. Every connect, verify, switch and disconnect is written to your audit log. Your model can suggest and explain — it cannot change anything; actions still need your approval in the platform.
        </div>
      </div>
    </div>
  );
}
