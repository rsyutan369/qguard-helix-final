'use client';

import { useMemo, useState } from 'react';
import {
  AppWindow,
  ArrowRight,
  Building2,
  CheckCircle2,
  Database,
  FileText,
  Folder,
  FolderPlus,
  GitBranch,
  Globe,
  HardDrive,
  IdCard,
  Layers,
  Link2,
  Loader2,
  Radar,
  RefreshCw,
  Search,
  Server,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';
import {
  BINDING_ATTRIBUTIONS,
  BINDING_KINDS,
  bindingKind,
  bindingNameIssue,
  bindingPathIssue,
  type AgentBindingRequest,
  type BindingAttribution,
  type BindingKindId,
} from '@/lib/agent-installer/agent-binding';
import type { BindingConflict, BindingTarget, LoadState } from '@/hooks/use-agent-collector';

/* ------------------------------------------------------------------ */
/* Draft state — what the operator is choosing, before it is sent      */
/* ------------------------------------------------------------------ */
export type BindingMode = 'existing' | 'new' | 'none';

export type BindingDraft = {
  mode: BindingMode;
  assetId: string | null;
  name: string;
  kind: BindingKindId;
  path: string;
  owner: string;
  description: string;
  attribution: BindingAttribution;
};

export const EMPTY_BINDING_DRAFT: BindingDraft = {
  mode: 'existing',
  assetId: null,
  name: '',
  kind: 'application',
  path: '',
  owner: '',
  description: '',
  attribution: 'bound',
};

const KIND_ICONS: Record<BindingKindId, LucideIcon> = {
  application: AppWindow,
  server: Server,
  service: Globe,
  folder: Folder,
  file: FileText,
  repository: GitBranch,
  profile: IdCard,
  environment: Layers,
  'business-unit': Building2,
};

/** Icon for a binding kind or an asset type, falling back to a generic asset. */
export function bindingIcon(kindOrType: string | null | undefined): LucideIcon {
  const known = bindingKind(kindOrType);
  if (known) return KIND_ICONS[known.id];
  const type = String(kindOrType || '').toLowerCase();
  if (/host|server|vm|endpoint|machine/.test(type)) return Server;
  if (/api|service|web|domain|url/.test(type)) return Globe;
  if (/repo|git|source/.test(type)) return GitBranch;
  if (/file|cert|key/.test(type)) return FileText;
  return HardDrive;
}

function findByName(targets: BindingTarget[], name: string) {
  const wanted = name.trim().toLowerCase();
  return wanted ? targets.find((t) => t.name.trim().toLowerCase() === wanted) || null : null;
}

/**
 * Why this draft cannot be submitted, or null when it can. The server applies
 * the same rules (agent-binding.ts); checking here just answers sooner.
 */
export function bindingDraftIssue(draft: BindingDraft, targets: BindingTarget[]): string | null {
  if (draft.mode === 'none') return null;
  if (draft.mode === 'existing') return draft.assetId ? null : 'Choose an asset to bind this agent to, or pick another option.';
  const nameIssue = bindingNameIssue(draft.name);
  if (nameIssue) return nameIssue;
  if (findByName(targets, draft.name)) return `An asset named "${draft.name.trim()}" already exists — bind to it instead.`;
  return bindingPathIssue(draft.kind, draft.path);
}

export function bindingRequestFromDraft(draft: BindingDraft): AgentBindingRequest {
  if (draft.mode === 'existing' && draft.assetId) {
    return { mode: 'existing', assetId: draft.assetId, attribution: draft.attribution };
  }
  if (draft.mode === 'new') {
    return {
      mode: 'new',
      name: draft.name.trim(),
      kind: draft.kind,
      path: bindingKind(draft.kind)?.needsPath ? draft.path.trim() : undefined,
      owner: draft.owner.trim() || undefined,
      description: draft.description.trim() || undefined,
      attribution: draft.attribution,
    };
  }
  return { mode: 'none' };
}

/** The name the draft will file findings under, for previews. */
export function bindingDraftLabel(draft: BindingDraft, targets: BindingTarget[]): string | null {
  if (draft.mode === 'existing') return targets.find((t) => t.id === draft.assetId)?.name || null;
  if (draft.mode === 'new') return draft.name.trim() || null;
  return null;
}

/* ------------------------------------------------------------------ */
/* Picker                                                              */
/* ------------------------------------------------------------------ */
const INPUT = 'w-full rounded-xl border border-white/12 bg-white/[0.03] px-3.5 py-2.5 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-cyan-400/50';

const MODES: Array<{ id: BindingMode; label: string; detail: string; icon: LucideIcon }> = [
  { id: 'existing', label: 'Existing asset', detail: 'Bind to an asset already in your inventory', icon: Database },
  { id: 'new', label: 'Create new target', detail: 'Name an application, folder, file, profile …', icon: FolderPlus },
  { id: 'none', label: 'Open discovery', detail: 'Each host or file found becomes its own asset', icon: Radar },
];

const CRITICALITY_TONE: Record<string, string> = {
  critical: 'border-red-400/30 text-red-300',
  high: 'border-orange-400/30 text-orange-300',
  medium: 'border-amber-400/30 text-amber-200',
  low: 'border-emerald-400/30 text-emerald-300',
};

export function AssetBindingPicker({
  value,
  onChange,
  targets,
  targetsState,
  onReloadTargets,
  conflict,
  agentName,
  currentAssetId,
}: {
  value: BindingDraft;
  onChange: (next: BindingDraft) => void;
  targets: BindingTarget[];
  targetsState: LoadState;
  onReloadTargets: () => void;
  /** A name clash the server reported on the last submit. */
  conflict?: BindingConflict | null;
  agentName: string;
  /** When rebinding: the asset the agent is bound to now, marked in the list. */
  currentAssetId?: string | null;
}) {
  const [search, setSearch] = useState('');
  const set = (patch: Partial<BindingDraft>) => onChange({ ...value, ...patch });

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter((t) =>
      [t.name, t.type, t.binding_kind, t.environment, t.service_owner, t.ip_address, t.binding_path]
        .some((field) => String(field || '').toLowerCase().includes(q)),
    );
  }, [targets, search]);

  const kindMeta = bindingKind(value.kind);
  const nameClash = value.mode === 'new' ? findByName(targets, value.name) : null;
  const clash = nameClash || (value.mode === 'new' && conflict ? { ...conflict, agents: [] } as BindingTarget : null);
  const pathIssue = value.mode === 'new' && value.path ? bindingPathIssue(value.kind, value.path) : null;
  const label = bindingDraftLabel(value, targets);
  const useExisting = (id: string) => onChange({ ...value, mode: 'existing', assetId: id });

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2.5">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-cyan-400/25 bg-cyan-400/10">
          <Link2 className="h-4 w-4 text-cyan-300" />
        </span>
        <div>
          <div className="text-sm font-black text-white/90">Bind findings to</div>
          <p className="mt-0.5 text-[11px] leading-relaxed text-white/45">
            Choose where this agent&apos;s findings are filed. Every CBOM entry, exposure, certificate and alert it reports is
            recorded against the target you pick here — only assets in your tenant can be chosen, and the binding is re-verified
            server-side on every upload.
          </p>
        </div>
      </div>

      {/* Mode */}
      <div role="radiogroup" aria-label="Binding mode" className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        {MODES.map((mode) => {
          const Icon = mode.icon;
          const active = value.mode === mode.id;
          const count = mode.id === 'existing' && targetsState === 'success' ? targets.length : null;
          return (
            <button
              key={mode.id}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => set({ mode: mode.id })}
              className={`group rounded-xl border px-3.5 py-3 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400 ${
                active ? 'border-cyan-400/45 bg-cyan-400/10 shadow-[0_0_0_1px_rgba(34,211,238,0.15)]' : 'border-white/10 bg-white/[0.02] hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={`inline-flex items-center gap-2 text-sm font-bold ${active ? 'text-cyan-200' : 'text-white/80'}`}>
                  <Icon className="h-4 w-4" /> {mode.label}
                </span>
                {count !== null ? (
                  <span className="rounded-full border border-white/10 px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-white/45">{count}</span>
                ) : null}
              </div>
              <div className="mt-1 text-[11px] text-white/45">{mode.detail}</div>
            </button>
          );
        })}
      </div>

      {/* Existing asset */}
      {value.mode === 'existing' ? (
        <div className="rounded-xl border border-white/10 bg-white/[0.02]">
          <div className="flex items-center gap-2 border-b border-white/8 px-3 py-2">
            <Search className="h-4 w-4 shrink-0 text-white/35" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name, type, environment, owner or address"
              aria-label="Search assets"
              className="w-full bg-transparent py-1 text-sm text-white outline-none placeholder:text-white/30"
            />
            <button
              type="button"
              onClick={onReloadTargets}
              className="rounded-lg p-1.5 text-white/40 transition hover:text-cyan-200"
              aria-label="Reload assets"
              title="Reload assets"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${targetsState === 'loading' ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {targetsState === 'loading' && targets.length === 0 ? (
            <div className="flex items-center gap-2 px-4 py-6 text-sm text-white/50">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading your asset inventory…
            </div>
          ) : targetsState === 'error' ? (
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-4 text-sm text-[var(--qg-notice-text)]">
              <span className="inline-flex items-center gap-2"><TriangleAlert className="h-4 w-4 text-amber-300" /> Your asset inventory could not be loaded.</span>
              <button type="button" onClick={() => set({ mode: 'new' })} className="rounded-lg border border-white/12 px-2.5 py-1 text-[11px] font-bold text-white/70 hover:text-cyan-200">
                Create a new target instead
              </button>
            </div>
          ) : targets.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-6 py-7 text-center">
              <Database className="h-6 w-6 text-white/25" />
              <p className="max-w-sm text-[12px] text-white/50">No assets in your inventory yet. Create a named target for this agent, or let it discover assets on its own.</p>
              <button type="button" onClick={() => set({ mode: 'new' })} className="mt-1 inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-black text-cyan-200 hover:bg-cyan-400/20">
                <FolderPlus className="h-3.5 w-3.5" /> Create new target
              </button>
            </div>
          ) : filtered.length === 0 ? (
            <p className="px-4 py-5 text-center text-[12px] text-white/45">No assets match &ldquo;{search}&rdquo;.</p>
          ) : (
            <ul role="listbox" aria-label="Assets" className="max-h-64 divide-y divide-white/5 overflow-y-auto">
              {filtered.slice(0, 200).map((asset) => {
                const Icon = bindingIcon(asset.binding_kind || asset.type);
                const selected = value.assetId === asset.id;
                const kindLabel = bindingKind(asset.binding_kind)?.label || asset.type || 'Asset';
                const meta = [kindLabel, asset.environment, asset.service_owner, asset.binding_path || asset.ip_address].filter(Boolean).join(' · ');
                return (
                  <li key={asset.id}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={selected}
                      onClick={() => set({ assetId: asset.id })}
                      className={`flex w-full items-center gap-3 px-3.5 py-2.5 text-left transition ${selected ? 'bg-cyan-400/10' : 'hover:bg-white/[0.03]'}`}
                    >
                      <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg border ${selected ? 'border-cyan-400/40 bg-cyan-400/10 text-cyan-200' : 'border-white/10 bg-white/[0.03] text-white/50'}`}>
                        <Icon className="h-4 w-4" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          <span className={`truncate text-sm font-bold ${selected ? 'text-cyan-100' : 'text-white/85'}`}>{asset.name}</span>
                          {currentAssetId === asset.id ? (
                            <span className="shrink-0 rounded-full border border-cyan-400/30 px-1.5 py-0.5 text-[9px] font-black uppercase text-cyan-200">Current</span>
                          ) : null}
                        </span>
                        <span className="block truncate text-[11px] capitalize text-white/40">{meta}</span>
                      </span>
                      <span className="flex shrink-0 items-center gap-1.5">
                        {asset.criticality ? (
                          <span className={`rounded-full border px-1.5 py-0.5 text-[9px] font-black uppercase ${CRITICALITY_TONE[String(asset.criticality).toLowerCase()] || 'border-white/10 text-white/45'}`}>
                            {asset.criticality}
                          </span>
                        ) : null}
                        {asset.agents.length > 0 ? (
                          <span className="rounded-full border border-white/10 px-1.5 py-0.5 text-[9px] font-bold text-white/50" title={asset.agents.map((a) => a.name).join(', ')}>
                            {asset.agents.length} agent{asset.agents.length === 1 ? '' : 's'}
                          </span>
                        ) : null}
                        {selected ? <CheckCircle2 className="h-4 w-4 text-cyan-300" /> : null}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {filtered.length > 200 ? (
            <p className="border-t border-white/8 px-4 py-2 text-[11px] text-white/40">Showing the first 200 of {filtered.length} — refine the search to find the rest.</p>
          ) : null}
        </div>
      ) : null}

      {/* New target */}
      {value.mode === 'new' ? (
        <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div>
            <span className="mb-2 block text-xs font-bold text-white/60">What is it?</span>
            <div role="radiogroup" aria-label="Target kind" className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {BINDING_KINDS.map((kind) => {
                const Icon = KIND_ICONS[kind.id];
                const active = value.kind === kind.id;
                return (
                  <button
                    key={kind.id}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    onClick={() => set({ kind: kind.id })}
                    title={kind.hint}
                    className={`flex items-center gap-2 rounded-lg border px-2.5 py-2 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400 ${
                      active ? 'border-cyan-400/45 bg-cyan-400/10 text-cyan-100' : 'border-white/8 bg-white/[0.02] text-white/65 hover:border-white/20'
                    }`}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    <span className="min-w-0">
                      <span className="block truncate text-xs font-bold">{kind.label}</span>
                      <span className="block truncate text-[10px] text-white/40">{kind.hint}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className={`grid grid-cols-1 gap-4 ${kindMeta?.needsPath ? 'sm:grid-cols-2' : ''}`}>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Target name</span>
              <input
                value={value.name}
                onChange={(e) => set({ name: e.target.value })}
                className={INPUT}
                placeholder={value.kind === 'profile' ? 'PCI Cardholder Estate' : value.kind === 'folder' ? 'Nginx config' : 'Payments API'}
                maxLength={120}
              />
            </label>
            {kindMeta?.needsPath ? (
              <label className="block">
                <span className="mb-1.5 block text-xs font-bold text-white/60">{kindMeta.pathLabel}</span>
                <input
                  value={value.path}
                  onChange={(e) => set({ path: e.target.value })}
                  className={`${INPUT} font-mono text-[13px]`}
                  placeholder={kindMeta.pathPlaceholder}
                />
                {pathIssue ? <span className="mt-1 block text-[11px] text-[var(--qg-notice-text)]">{pathIssue}</span> : null}
              </label>
            ) : null}
          </div>

          {clash ? (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-3 py-2 text-[12px] text-[var(--qg-notice-text)]">
              <span className="inline-flex items-center gap-2">
                <TriangleAlert className="h-4 w-4 text-amber-300" /> &ldquo;{clash.name}&rdquo; already exists in your inventory.
              </span>
              <button type="button" onClick={() => useExisting(clash.id)} className="rounded-lg border border-[var(--qg-notice-border)] bg-[var(--qg-notice-bg)] px-2.5 py-1 text-[11px] font-black text-[var(--qg-notice-text)] hover:opacity-80">
                Bind to the existing asset
              </button>
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Owner <span className="font-normal text-white/30">(optional)</span></span>
              <input value={value.owner} onChange={(e) => set({ owner: e.target.value })} className={INPUT} placeholder="Platform Security · jane@acme.com" />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs font-bold text-white/60">Description <span className="font-normal text-white/30">(optional)</span></span>
              <input value={value.description} onChange={(e) => set({ description: e.target.value })} className={INPUT} placeholder="What this target covers" maxLength={500} />
            </label>
          </div>
          {kindMeta?.needsPath ? (
            <p className="text-[11px] leading-relaxed text-white/40">
              The path labels the target; it does not widen what the agent may read. Add it to the agent&apos;s allowed paths for the
              agent to scan it.
            </p>
          ) : null}
        </div>
      ) : null}

      {/* Open discovery */}
      {value.mode === 'none' ? (
        <div className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-[12px] leading-relaxed text-white/55">
          Findings are filed under each host, file or package the agent observes, creating assets as it goes. You can bind this
          agent to a target later from its details drawer.
        </div>
      ) : null}

      {/* Attribution */}
      {value.mode !== 'none' ? (
        <div role="radiogroup" aria-label="How findings are attributed" className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {BINDING_ATTRIBUTIONS.map((item) => {
            const active = value.attribution === item.id;
            return (
              <button
                key={item.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => set({ attribution: item.id })}
                className={`rounded-xl border px-3.5 py-3 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400 ${
                  active ? 'border-cyan-400/40 bg-cyan-400/[0.07]' : 'border-white/8 bg-white/[0.02] hover:border-white/20'
                }`}
              >
                <span className="flex items-center gap-2">
                  {/* currentColor, so the theme layer's remap of the text colour carries the dot too. */}
                  <span className={`grid h-4 w-4 place-items-center rounded-full border ${active ? 'border-current text-cyan-200' : 'border-white/25'}`}>
                    {active ? <span className="h-2 w-2 rounded-full bg-current" /> : null}
                  </span>
                  <span className={`text-xs font-bold ${active ? 'text-cyan-100' : 'text-white/80'}`}>{item.label}</span>
                </span>
                <span className="mt-1 block pl-6 text-[11px] leading-relaxed text-white/45">{item.detail}</span>
              </button>
            );
          })}
        </div>
      ) : null}

      {/* Preview */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-white/8 bg-white/[0.02] px-3.5 py-2.5 text-[11px] font-bold">
        <span className="text-white/40">Preview</span>
        <span className="rounded-lg border border-white/12 bg-white/[0.03] px-2.5 py-1 text-white/75">{agentName.trim() || 'This agent'}</span>
        <ArrowRight className="h-3.5 w-3.5 text-white/30" />
        {value.mode === 'none' ? (
          <span className="rounded-lg border border-white/12 bg-white/[0.03] px-2.5 py-1 text-white/60">Each discovered host, file or package</span>
        ) : label ? (
          <span className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-2.5 py-1 text-cyan-100">
            {(() => {
              const Icon = value.mode === 'new' ? KIND_ICONS[value.kind] : bindingIcon(targets.find((t) => t.id === value.assetId)?.binding_kind || targets.find((t) => t.id === value.assetId)?.type);
              return <Icon className="h-3.5 w-3.5" />;
            })()}
            {label}
          </span>
        ) : (
          <span className="rounded-lg border border-dashed border-white/15 px-2.5 py-1 text-white/40">Choose a target</span>
        )}
        {value.mode !== 'none' && label ? (
          <span className="text-white/40">{value.attribution === 'bound' ? '· all findings filed here' : '· discovered assets grouped here'}</span>
        ) : null}
      </div>
    </div>
  );
}
