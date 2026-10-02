'use client';

/**
 * Asset register table and the per-asset detail panel.
 *
 * Rows are `AssetRegisterRow`s — already derived — so a figure in a row, in the
 * page's KPIs and in an exported report is the same value.
 */

import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ChevronDown,
  Code2,
  ExternalLink,
  FileText,
  Globe,
  Globe2,
  KeyRound,
  Radio,
  RefreshCw,
  Server,
  type LucideIcon,
} from 'lucide-react';
import type { AssetRegisterRow, RegisterComponent } from '@/lib/assets/asset-register';
import {
  BandPill,
  FreshnessLabel,
  MiniStack,
  SeverityBadge,
  SeverityChips,
  StatusBadge,
  absoluteTime,
  nf,
  relativeAge,
} from './_register-ui';

function typeIcon(type: string): LucideIcon {
  const lower = type.toLowerCase();
  if (/web|api|site|domain|tls|endpoint|gateway/.test(lower)) return Globe;
  if (/repo|code|source|library|package/.test(lower)) return Code2;
  if (/key|kms|hsm|cert/.test(lower)) return KeyRound;
  return Server;
}

const TH = 'px-2.5 py-3 text-left text-[10px] font-black uppercase tracking-[0.14em] text-[var(--qg-dashboard-text-soft)]';
const TD = 'border-t border-[var(--qg-card-border)] px-2.5 py-3 align-top';

export function AssetTable({
  rows,
  now,
  expandedId,
  onToggleExpand,
  selectedIds,
  onToggleSelect,
  onReportAsset,
}: {
  rows: AssetRegisterRow[];
  now: number;
  expandedId: string | null;
  onToggleExpand: (id: string) => void;
  selectedIds: Set<string>;
  onToggleSelect: (id: string) => void;
  onReportAsset: (row: AssetRegisterRow) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[980px] table-fixed border-collapse text-left">
        <caption className="sr-only">Asset register — one row per asset, cryptographic components only</caption>
        <colgroup>
          <col className="w-9" />
          <col className="w-[27%]" />
          <col className="w-[118px]" />
          <col className="w-[17%]" />
          <col className="w-[13%]" />
          <col className="w-[14%]" />
          <col className="w-[11%]" />
          <col className="w-[104px]" />
        </colgroup>
        <thead>
          <tr>
            <th className={TH} scope="col"><span className="sr-only">Select</span></th>
            <th className={TH} scope="col">Asset</th>
            <th className={TH} scope="col">PQC status</th>
            <th className={TH} scope="col">Components</th>
            <th className={TH} scope="col">Scanner risk</th>
            <th className={TH} scope="col">Owner · lifecycle</th>
            <th className={TH} scope="col">Last scanned</th>
            <th className={`${TH} text-right`} scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const Icon = typeIcon(row.type);
            const expanded = expandedId === row.id;
            const selected = selectedIds.has(row.id);
            return (
              <Fragment key={row.id}>
                <tr className={`transition-colors ${expanded ? 'bg-[var(--qg-muted-panel)]' : 'hover:bg-[var(--qg-muted-panel)]/70'} ${selected ? 'shadow-[inset_3px_0_0_var(--qg-amber)]' : ''}`}>
                  <td className={TD}>
                    <input
                      type="checkbox"
                      checked={selected}
                      onChange={() => onToggleSelect(row.id)}
                      aria-label={`Select ${row.name} for a report`}
                      className="mt-2 h-4 w-4 rounded border-[var(--qg-card-border)] accent-[var(--qg-amber)]"
                    />
                  </td>
                  <td className={TD}>
                    <button type="button" onClick={() => onToggleExpand(row.id)} aria-expanded={expanded} className="group flex w-full min-w-0 items-start gap-3 text-left">
                      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-[var(--qg-amber)]/25 bg-[var(--qg-amber)]/10 text-[var(--qg-amber)]"><Icon className="h-4 w-4" aria-hidden /></span>
                      <span className="min-w-0">
                        <span className="flex items-center gap-1.5">
                          <span className="truncate text-sm font-black text-[var(--qg-dashboard-text)] group-hover:text-[var(--qg-amber)]">{row.name}</span>
                          <ChevronDown className={`h-3.5 w-3.5 shrink-0 text-[var(--qg-text-muted)] transition-transform ${expanded ? 'rotate-180' : ''}`} aria-hidden />
                        </span>
                        <span className="block truncate font-mono text-[10px] text-[var(--qg-text-muted)]" title={row.target}>{row.target}</span>
                        <span className="mt-1 flex flex-wrap items-center gap-1">
                          <span className="rounded border border-[var(--qg-card-border)] px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)]">{row.typeLabel}</span>
                          {row.internetFacing ? <span className="inline-flex items-center gap-1 rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wider text-cyan-700 dark:text-cyan-200"><Globe2 className="h-3 w-3" aria-hidden />Internet-facing</span> : null}
                          {row.scanning.active ? <span className="inline-flex items-center gap-1 rounded border border-emerald-500/35 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wider text-emerald-700 dark:text-emerald-200"><Radio className="h-3 w-3 animate-pulse" aria-hidden />Scanning{row.scanning.progress !== null ? ` ${Math.round(row.scanning.progress)}%` : ''}</span> : null}
                          {row.evidenceOnly ? <span className="rounded border border-slate-400/30 px-1.5 py-0.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-text-muted)]" title="Discovered from scanner evidence; no asset record has been created yet.">Evidence only</span> : null}
                        </span>
                      </span>
                    </button>
                  </td>
                  <td className={TD}>
                    <StatusBadge status={row.pqcStatus} reason={row.pqcStatusReason} compact />
                  </td>
                  <td className={TD}>
                    <div className="text-[12px] font-black text-[var(--qg-dashboard-text)]">
                      {nf(row.components.vulnerable)} <span className="font-bold text-[var(--qg-text-muted)]">vulnerable of {nf(row.components.total)}</span>
                    </div>
                    <div className="mt-1.5"><MiniStack vulnerable={row.components.vulnerable} unclassified={row.components.unclassified} ready={row.components.pqcReady} total={row.components.total} /></div>
                    <div className="mt-1.5"><SeverityChips counts={row.vulnerableSeverity} /></div>
                  </td>
                  <td className={TD}>
                    <BandPill band={row.risk} score={row.riskScore} />
                    {row.worstComponentSeverity ? <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">Worst component: {row.worstComponentSeverity}</div> : null}
                  </td>
                  <td className={TD}>
                    <div className="truncate">
                      {row.owner ? <span className="text-[12px] font-bold text-[var(--qg-dashboard-text)]">{row.owner}</span> : <span className="text-[11px] italic text-[var(--qg-text-muted)]">Unassigned owner</span>}
                      {row.environment ? <span className="ml-1 text-[10px] text-[var(--qg-text-muted)]">· {row.environment}</span> : null}
                    </div>
                    {row.lifecycle ? (
                      <div className="mt-1 text-[10.5px] leading-snug">
                        <span className="font-black text-[var(--qg-dashboard-text)]">{row.lifecycle.label}</span>
                        <span className="block text-[10px] text-[var(--qg-text-muted)]">{row.lifecycle.openActions ? `${row.lifecycle.openActions} open action${row.lifecycle.openActions === 1 ? '' : 's'}` : row.lifecycle.validationStatus}</span>
                      </div>
                    ) : <div className="mt-1 text-[10px] text-[var(--qg-text-muted)]">Not in workflow</div>}
                  </td>
                  <td className={TD}>
                    <FreshnessLabel state={row.freshness.state} lastScanned={row.lastScanned} now={now} />
                  </td>
                  <td className={`${TD} text-right`}>
                    <div className="flex flex-wrap items-center justify-end gap-1.5">
                      <button type="button" onClick={() => onToggleExpand(row.id)} className="rounded-md border border-[var(--qg-amber)]/30 bg-[var(--qg-amber)]/10 px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-amber)]">{expanded ? 'Hide' : 'Details'}</button>
                      <Link to={`/dashboard/cbom?asset=${encodeURIComponent(row.name)}`} className="rounded-md px-2 py-1 text-[10px] font-black uppercase text-[var(--qg-dashboard-text-soft)] no-underline hover:text-[var(--qg-amber)]">CBOM</Link>
                      <button type="button" onClick={() => onReportAsset(row)} title={`Report on ${row.name}`} className="rounded-md p-1 text-[var(--qg-dashboard-text-soft)] hover:text-[var(--qg-amber)]"><FileText className="h-4 w-4" aria-hidden /><span className="sr-only">Report on {row.name}</span></button>
                    </div>
                  </td>
                </tr>
                {expanded ? (
                  <tr>
                    <td colSpan={8} className="border-t border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-0">
                      <AssetDetail row={row} now={now} onReport={() => onReportAsset(row)} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Detail                                                              */
/* ------------------------------------------------------------------ */

type DetailTab = 'action' | 'all' | 'findings';
const VISIBLE_COMPONENTS = 12;

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-t border-[var(--qg-card-border)] py-2 first:border-t-0">
      <span className="shrink-0 text-[10px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{label}</span>
      <span className="min-w-0 text-right text-[11px] text-[var(--qg-dashboard-text)]">{children}</span>
    </div>
  );
}

function ComponentTable({ components, assetName, showRemediate }: { components: RegisterComponent[]; assetName: string; showRemediate: boolean }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? components : components.slice(0, VISIBLE_COMPONENTS);
  if (!components.length) return null;
  return (
    <div>
      <div className="overflow-x-auto rounded-lg border border-[var(--qg-card-border)]">
        <table className="w-full min-w-[640px] border-collapse text-left text-[11px]">
          <thead className="bg-[var(--qg-card-bg)]">
            <tr>
              {['Severity', 'Component', 'Risk-bearing primitive', 'PQC target', 'Recommended action'].map((column) => (
                <th key={column} scope="col" className="px-3 py-2 text-[9px] font-black uppercase tracking-widest text-[var(--qg-text-muted)]">{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((component) => (
              <tr key={component.id} className="border-t border-[var(--qg-card-border)] align-top">
                <td className="px-3 py-2"><SeverityBadge severity={component.severity} /></td>
                <td className="max-w-[260px] px-3 py-2">
                  <div className="break-words font-bold text-[var(--qg-dashboard-text)]">{component.name}</div>
                  <div className="text-[10px] text-[var(--qg-text-muted)]">{component.classLabel}{component.keySize ? ` · ${component.keySize}-bit` : ''}{component.instances > 1 ? ` · ${component.instances} observations` : ''}</div>
                </td>
                <td className="px-3 py-2 text-[var(--qg-dashboard-text-soft)]">{component.riskBearing}</td>
                <td className="max-w-[200px] px-3 py-2 text-[var(--qg-dashboard-text)]">
                  {component.pqcReplacement ?? '—'}
                  {component.pqcTargetSource === 'corrected' ? (
                    <span title="The stored scanner target named ML-KEM (key establishment) for a certificate or signature. Signatures migrate to ML-DSA / SLH-DSA (FIPS 204/205)." className="ml-1 rounded border border-amber-500/40 bg-amber-500/10 px-1 py-px text-[8.5px] font-black uppercase text-amber-800 dark:text-amber-200">corrected</span>
                  ) : null}
                </td>
                <td className="max-w-[300px] px-3 py-2 text-[var(--qg-dashboard-text-soft)]">
                  {component.recommendation ?? '—'}
                  <div className="mt-1.5 flex flex-wrap items-center gap-2">
                    {showRemediate && component.posture !== 'pqc-ready' ? (
                      <Link
                        to={`${component.remediationRoute}?${new URLSearchParams({ source: 'assets', action: 'remediate', asset: assetName, algorithm: component.algorithm, severity: component.severity }).toString()}`}
                        title={`Opens ${component.remediationRoute}, the module that executes this change`}
                        className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-[var(--qg-amber)]/35 bg-[var(--qg-amber)]/10 px-2 py-0.5 text-[9px] font-black uppercase tracking-wider text-[var(--qg-amber)] no-underline hover:border-[var(--qg-amber)]/70"
                      >
                        <ExternalLink className="h-3 w-3" aria-hidden /> Remediate
                      </Link>
                    ) : null}
                    {component.evidence ? (
                      <details className="min-w-0">
                        <summary className="cursor-pointer text-[10px] font-bold text-[var(--qg-text-muted)]">Evidence</summary>
                        <p className="mt-1 whitespace-pre-wrap break-words text-[10px] text-[var(--qg-text-muted)]">{component.evidence}</p>
                      </details>
                    ) : null}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {components.length > VISIBLE_COMPONENTS ? (
        <div className="mt-2 flex items-center gap-2 text-[10px] text-[var(--qg-text-muted)]">
          <span>{showAll ? `Showing all ${components.length}.` : `Showing the ${VISIBLE_COMPONENTS} most urgent of ${components.length}.`}</span>
          <button type="button" onClick={() => setShowAll((value) => !value)} className="font-black uppercase text-[var(--qg-amber)]">{showAll ? 'Show fewer' : 'Show all'}</button>
        </div>
      ) : null}
    </div>
  );
}

export function AssetDetail({ row, now, onReport }: { row: AssetRegisterRow; now: number; onReport: () => void }) {
  const needsAction = row.componentList.filter((c) => c.posture !== 'pqc-ready');
  const [tab, setTab] = useState<DetailTab>(needsAction.length ? 'action' : 'all');
  const tabs: Array<{ id: DetailTab; label: string; count: number }> = [
    { id: 'action', label: 'Needs action', count: needsAction.length },
    { id: 'all', label: 'All components', count: row.componentList.length },
    { id: 'findings', label: 'Configuration findings', count: row.postureList.length },
  ];
  const corrected = row.componentList.filter((c) => c.pqcTargetSource === 'corrected').length;
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-5 p-4 xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-[10px] font-black uppercase tracking-[0.18em] text-[var(--qg-text-muted)]">Asset profile</div>
            <div className="mt-1 break-words text-base font-black text-[var(--qg-dashboard-text)]">{row.name}</div>
          </div>
          <StatusBadge status={row.pqcStatus} compact />
        </div>
        <p className="mb-3 rounded-md border border-[var(--qg-card-border)] bg-[var(--qg-muted-panel)] p-2.5 text-[11px] font-semibold leading-relaxed text-[var(--qg-dashboard-text)]">{row.pqcStatusReason}</p>
        <Fact label="Target"><span className="break-all font-mono">{row.target}</span></Fact>
        <Fact label="Type">{row.typeLabel}</Fact>
        <Fact label="Owner">{row.owner ?? <span className="italic text-[var(--qg-text-muted)]">Unassigned</span>}</Fact>
        <Fact label="Environment">{row.environment ?? '—'}</Fact>
        <Fact label="Criticality">{row.criticality ?? '—'}</Fact>
        <Fact label="Exposure">{row.internetFacing ? 'Internet-facing' : 'Internal / not public'}</Fact>
        <Fact label="TLS version">{row.tlsVersion ?? '—'}</Fact>
        <Fact label="Scanner risk"><BandPill band={row.risk} score={row.riskScore} /></Fact>
        <Fact label="Last scanned">
          <span title={absoluteTime(row.lastScanned)}>{relativeAge(row.lastScanned, now) ?? 'No timestamp'}</span>
          <div className="text-[10px] text-[var(--qg-text-muted)]">{absoluteTime(row.lastScanned)} · newest evidence row</div>
        </Fact>
        <Fact label="Lifecycle">{row.lifecycle ? `${row.lifecycle.label} · ${row.lifecycle.openActions} open · ${row.lifecycle.validationStatus}` : 'Not tracked by the workflow'}</Fact>
        <Fact label="Detection signals"><span title="Raw scanner rows (all tables) behind these components and findings, before de-duplication.">{nf(row.detectionSignals)}</span></Fact>
        <div className="mt-4 grid grid-cols-2 gap-2">
          <button type="button" onClick={onReport} className="inline-flex items-center justify-center gap-1.5 rounded-md bg-[var(--qg-amber)] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-on-accent)] hover:brightness-110"><FileText className="h-3.5 w-3.5" aria-hidden />Report</button>
          <Link to="/dashboard/scanner" className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[var(--qg-card-border)] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-[var(--qg-dashboard-text-soft)] no-underline hover:border-[var(--qg-amber)]/45"><RefreshCw className="h-3.5 w-3.5" aria-hidden />Rescan</Link>
        </div>
      </aside>

      <div className="min-w-0">
        <div className="mb-3 flex flex-wrap items-center gap-1 border-b border-[var(--qg-card-border)]" role="tablist" aria-label={`${row.name} components`}>
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={tab === item.id}
              onClick={() => setTab(item.id)}
              className={`-mb-px border-b-2 px-3 py-2 text-[11px] font-black transition ${tab === item.id ? 'border-[var(--qg-amber)] text-[var(--qg-amber)]' : 'border-transparent text-[var(--qg-text-muted)] hover:text-[var(--qg-dashboard-text)]'}`}
            >
              {item.label} <span className="ml-1 rounded bg-[var(--qg-muted-panel)] px-1.5 text-[10px]">{item.count}</span>
            </button>
          ))}
        </div>
        <div role="tabpanel">
          {tab === 'action' ? (
            needsAction.length ? (
              <ComponentTable components={needsAction} assetName={row.name} showRemediate />
            ) : (
              <p className="rounded-lg border border-emerald-500/25 bg-emerald-500/8 p-4 text-sm font-semibold text-emerald-700 dark:text-emerald-200">
                {row.components.total ? 'Every measured component on this asset is classified quantum-safe. Keep it under periodic re-validation.' : 'No cryptographic components have been measured on this asset yet — run an authorized scan.'}
              </p>
            )
          ) : null}
          {tab === 'all' ? (
            row.componentList.length ? <ComponentTable components={row.componentList} assetName={row.name} showRemediate /> : <p className="text-sm text-[var(--qg-text-muted)]">No cryptographic components measured.</p>
          ) : null}
          {tab === 'findings' ? (
            row.postureList.length ? (
              <>
                <p className="mb-2 text-[11px] text-[var(--qg-text-muted)]">Scanner findings about this asset (configuration and policy). They are listed here, never counted as components.</p>
                <ComponentTable components={row.postureList} assetName={row.name} showRemediate={false} />
              </>
            ) : (
              <p className="text-sm text-[var(--qg-text-muted)]">No configuration findings recorded for this asset.</p>
            )
          ) : null}
          {corrected ? (
            <p className="mt-3 text-[10px] leading-relaxed text-[var(--qg-text-muted)]">
              {corrected} stored PQC target{corrected === 1 ? '' : 's'} on this asset named ML-KEM for a certificate or signature and {corrected === 1 ? 'is' : 'are'} shown corrected to the FIPS 204 signature target. ML-KEM (FIPS 203) replaces key establishment only.
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
