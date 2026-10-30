'use client';

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Grid3X3, Info, ListChecks } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AMBER, RED, SLATE, fmtInt } from '../_components/intel/kit';
import type { PQAuthCompatIssue, PQAuthCompatStatus, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import { COMPAT_META, Card, CompatBadge, EvidenceUrl, FilterChips, Notice, PROTOCOL_LABEL, Reveal, RouteLink, th, ink } from './_ui';

const SEVERITY_HEX = { critical: RED, high: '#fb923c', medium: AMBER, low: SLATE } as const;

export function CompatibilityView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { compatibility, providers } = snapshot.identity;
  const [severity, setSeverity] = useState<'all' | PQAuthCompatIssue['severity']>('all');
  const [focus, setFocus] = useState<string | null>(null);

  const issues = useMemo(
    () => compatibility.issues.filter((i) => (severity === 'all' || i.severity === severity) && (!focus || i.id === focus || i.providerId === focus)),
    [compatibility.issues, severity, focus],
  );

  if (!compatibility.rows.length) {
    return (
      <Card title="PQC compatibility assessment" icon={CheckCircle2}>
        <Notice tone="info" icon={Info} title="Nothing has been assessed">
          Compatibility is concluded only from configuration evidence: the keys a provider publishes, the algorithms its metadata advertises, its endpoints and its
          host certificate. An integration is never marked compatible because it appears in an inventory. Discover an identity provider to begin.
        </Notice>
        <div className="mt-3"><RouteLink to="/dashboard/pqauth/discovery">Run identity discovery</RouteLink></div>
      </Card>
    );
  }

  const sevCount = (s: PQAuthCompatIssue['severity']) => compatibility.issues.filter((i) => i.severity === s).length;

  return (
    <div className="space-y-4">
      <Reveal className="grid grid-cols-2 gap-2.5 md:grid-cols-5">
        {(Object.keys(COMPAT_META) as PQAuthCompatStatus[]).map((status) => {
          const meta = COMPAT_META[status];
          return (
            <div key={status} className="rounded-xl border bg-white/[0.02] p-3" style={{ borderColor: `${meta.hex}40` }} title={meta.hint}>
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-black uppercase tracking-[0.14em]" style={{ color: ink(meta.hex) }}>{meta.glyph} {meta.label}</span>
                <span className="font-mono text-[18px] font-black" style={{ color: ink(meta.hex) }}>{fmtInt(compatibility.counts[status])}</span>
              </div>
              <p className="mt-1 text-[10px] leading-snug text-white/50">{meta.hint}</p>
            </div>
          );
        })}
      </Reveal>

      <Reveal delay={0.04}>
        <Card title="Compatibility matrix" icon={Grid3X3} meta={`${compatibility.rows.length} provider(s) × ${compatibility.dimensions.length} checks`}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-separate border-spacing-0">
              <thead>
                <tr>
                  <th className={th('sticky left-0 z-10 bg-[#0b1424]')}>Provider</th>
                  {compatibility.dimensions.map((d) => <th key={d.id} className={th()} title={d.description}>{d.label}</th>)}
                </tr>
              </thead>
              <tbody>
                {compatibility.rows.map((row) => (
                  <tr key={row.providerId}>
                    <th scope="row" className="sticky left-0 z-10 border-t border-white/[0.06] bg-[#0b1424] px-3 py-2.5 text-left align-top">
                      <div className="text-[11.5px] font-bold text-white">{row.providerLabel}</div>
                      <div className="text-[10px] font-normal text-white/50">{PROTOCOL_LABEL[row.protocol] ?? row.protocol}</div>
                    </th>
                    {compatibility.dimensions.map((d) => {
                      const cell = row.cells[d.id];
                      if (!cell) return <td key={d.id} className="border-t border-white/[0.06] px-3 py-2.5" />;
                      const issueId = `${row.providerId}:${d.id}`;
                      const hasIssue = compatibility.issues.some((i) => i.id === issueId);
                      return (
                        <td key={d.id} className="border-t border-white/[0.06] px-2 py-2 align-top">
                          <button
                            type="button"
                            disabled={!hasIssue}
                            onClick={() => setFocus((c) => (c === issueId ? null : issueId))}
                            aria-pressed={focus === issueId}
                            className={cn('w-full rounded-lg border border-transparent p-2 text-left transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70', hasIssue && 'hover:border-white/15 hover:bg-white/[0.03]', focus === issueId && 'border-cyan-400/40 bg-cyan-500/[0.06]')}
                          >
                            <CompatBadge value={cell.status} />
                            <div className="mt-1 text-[10px] leading-snug text-white/50">{cell.summary}</div>
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-white/50">
            Select a non-passing cell to see its explanation below. “Not verified” means no evidence was observed — it is never shown as compatible.
          </p>
        </Card>
      </Reveal>

      <Reveal delay={0.08}>
        <Card
          title="Issues and remediation"
          icon={ListChecks}
          meta={`${issues.length} shown`}
          action={focus ? <button type="button" onClick={() => setFocus(null)} className="text-[9.5px] font-black uppercase tracking-wider text-cyan-200 hover:underline">Clear selection</button> : null}
        >
          <div className="mb-3">
            <FilterChips label="Severity" value={severity} onChange={setSeverity} options={[
              { key: 'all', label: 'All', count: compatibility.issues.length },
              { key: 'critical', label: 'Critical', count: sevCount('critical') },
              { key: 'high', label: 'High', count: sevCount('high') },
              { key: 'medium', label: 'Medium', count: sevCount('medium') },
              { key: 'low', label: 'Low', count: sevCount('low') },
            ]} />
          </div>
          {issues.length ? (
            <ul className="space-y-3">
              {issues.map((issue) => {
                const provider = providers.find((p) => p.id === issue.providerId);
                return (
                  <li key={issue.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <h3 className="text-[12.5px] font-black text-white">{issue.component}</h3>
                      <span className="flex items-center gap-1.5">
                        <CompatBadge value={issue.status} />
                        <span className="rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider" style={{ borderColor: `${SEVERITY_HEX[issue.severity]}55`, color: ink(SEVERITY_HEX[issue.severity]) }}>{issue.severity}</span>
                      </span>
                    </div>
                    <dl className="mt-3 grid gap-2.5 md:grid-cols-2">
                      <QA n={1} q="Affected component" a={issue.component} />
                      <QA n={2} q="The compatibility issue" a={issue.issue} />
                      <QA n={3} q="Why it matters" a={issue.why} />
                      <QA n={4} q="Cause / limitation" a={issue.cause} />
                      <div className="md:col-span-2"><QA n={5} q="Supported remediation" a={issue.remediation} highlight /></div>
                    </dl>
                    <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-white/[0.06] pt-2.5 text-[10px] text-white/50">
                      <span>Evidence: {issue.evidence}</span>
                      {issue.sourceUrl ? <EvidenceUrl url={issue.sourceUrl} /> : null}
                    </div>
                    {provider ? (
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-white/45">
                        <span className="font-black uppercase tracking-wider text-white/50">Dependency</span>
                        <span>{provider.dependentAssetIds.length} relying asset(s)</span>
                        <ArrowRight className="h-3 w-3" aria-hidden="true" />
                        <span className="font-semibold text-white/70">{provider.vendor ?? provider.displayName}</span>
                        <ArrowRight className="h-3 w-3" aria-hidden="true" />
                        <span>{provider.publishedKeyCount} signing key(s)</span>
                        <Link to={`/dashboard/pqauth/trust-graph?focus=provider:${provider.id}`} className="ml-auto text-cyan-300 no-underline hover:underline">View blast radius</Link>
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/50">
              {compatibility.issues.length ? 'No issue matches the selection.' : 'No compatibility issue was found in the evidence collected.'}
            </p>
          )}
        </Card>
      </Reveal>
    </div>
  );
}

function QA({ n, q, a, highlight }: { n: number; q: string; a: string; highlight?: boolean }) {
  return (
    <div className={cn('rounded-lg border p-2.5', highlight ? 'border-emerald-400/25 bg-emerald-500/[0.05]' : 'border-white/[0.07] bg-black/10')}>
      <dt className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/50">{n}. {q}</dt>
      <dd className={cn('mt-1 text-[11px] leading-relaxed', highlight ? 'text-emerald-200' : 'text-white/70')}>{a}</dd>
    </div>
  );
}
