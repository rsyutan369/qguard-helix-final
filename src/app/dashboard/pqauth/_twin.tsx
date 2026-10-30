'use client';

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, Boxes, Calculator, FlaskConical, GitBranch, RefreshCw, Server } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AMBER, GREEN, SLATE, VIOLET, fmtInt, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type { PQAuthSnapshot } from '@/types/pqauth-dashboard';
import { AgeBadge, Badge, Card, ClassBadge, Notice, Reveal, RouteLink, fmtBytes, td, th, ink } from './_ui';

const SYNC_META = {
  'in-sync': { label: 'In sync', hex: GREEN, glyph: '✓', hint: 'Every modelled provider matches its latest observation.' },
  drift: { label: 'Drift detected', hex: AMBER, glyph: '◐', hint: 'Recorded and newly observed state disagree.' },
  stale: { label: 'Stale', hex: AMBER, glyph: '◔', hint: 'The newest observation is older than 7 days.' },
  'never-synced': { label: 'Never synchronised', hex: SLATE, glyph: '○', hint: 'No discovery has run.' },
  partial: { label: 'Partially synchronised', hex: AMBER, glyph: '◑', hint: 'Some hosts could not be fully read; the model has gaps.' },
} as const;

export function TwinView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { twin, providers } = snapshot.identity;
  const lastSeen = (providerId: string) => providers.find((p) => p.id === providerId)?.lastSeenAt ?? null;
  const applicable = twin.scenarios.filter((s) => s.applicable);
  const [scenarioId, setScenarioId] = useState<string>(applicable[0]?.id ?? twin.scenarios[0]?.id ?? '');
  const scenario = twin.scenarios.find((s) => s.id === scenarioId) ?? twin.scenarios[0];
  const sync = SYNC_META[twin.sync.status];

  return (
    <div className="space-y-4">
      {/* ---- Observed state --------------------------------------------- */}
      <Reveal>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
          <Card title="Twin synchronisation" icon={RefreshCw}>
            <div className="flex items-center gap-3">
              <span className="grid h-12 w-12 place-items-center rounded-full border-2 font-mono text-[18px] font-black" style={{ borderColor: sync.hex, color: ink(sync.hex) }} aria-hidden="true">{sync.glyph}</span>
              <div>
                <div className="text-[15px] font-black" style={{ color: ink(sync.hex) }}>{sync.label}</div>
                <div className="text-[10.5px] text-white/45" title={fullTimestamp(twin.sync.lastSyncAt)}>{twin.sync.lastSyncAt ? `Last observation ${relativeTime(twin.sync.lastSyncAt)}` : 'No observation'}</div>
              </div>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-white/55">{twin.sync.detail}</p>
            <div className="mt-3 rounded-xl border border-white/10 bg-white/[0.02] p-3 text-[10.5px] leading-relaxed text-white/45">
              <b className="text-white/70">How the twin is built.</b> It is a read model, rebuilt on every refresh from the identity discovery records (providers, JWKS
              keys, trust relationships, probes), certificates and migration jobs. It never contacts a provider itself and no simulated change is ever written back to
              it — model changes and real configuration changes cannot be confused.
            </div>
            <div className="mt-3"><RouteLink to="/dashboard/pqauth/discovery" tone="ghost">Resynchronise via discovery</RouteLink></div>
          </Card>

          <Card title="Modelled identity topology" icon={Boxes} meta={`${twin.entities.length} provider(s) · observed state`}>
            {twin.entities.length ? (
              <ul className="space-y-2.5">
                {twin.entities.map((e) => (
                  <li key={e.providerId} className={cn('rounded-xl border bg-white/[0.02] p-3', e.conflicts.length ? 'border-amber-400/35' : 'border-white/10')}>
                    <div className="grid items-center gap-2 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1.2fr)_auto_minmax(0,1fr)]">
                      <div className="rounded-lg bg-white/[0.03] px-2.5 py-2 text-center">
                        <div className="font-mono text-[16px] font-black text-white">{fmtInt(e.dependents)}</div>
                        <div className="text-[9px] font-black uppercase tracking-wider text-white/50">relying assets</div>
                      </div>
                      <ArrowRight className="mx-auto hidden h-4 w-4 text-white/50 md:block" aria-hidden="true" />
                      <Link to={`/dashboard/pqauth/trust-graph?focus=provider:${e.providerId}`} className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 no-underline transition hover:border-cyan-400/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                        <div className="truncate text-[12px] font-black text-white">{e.label}</div>
                        <div className="mt-1 flex flex-wrap gap-1"><ClassBadge value={e.quantumClass} /><AgeBadge age={e.age} at={lastSeen(e.providerId)} /></div>
                      </Link>
                      <ArrowRight className="mx-auto hidden h-4 w-4 text-white/50 md:block" aria-hidden="true" />
                      <div className="rounded-lg bg-white/[0.03] px-2.5 py-2 text-center">
                        <div className="font-mono text-[16px] font-black text-white">{fmtInt(e.keys)}<span className="text-[11px] text-red-300">{e.vulnerableKeys ? ` · ${e.vulnerableKeys}●` : ''}</span></div>
                        <div className="text-[9px] font-black uppercase tracking-wider text-white/50">signing keys</div>
                      </div>
                    </div>
                    {e.conflicts.map((c, i) => <p key={i} className="mt-2 flex gap-1.5 text-[10.5px] text-amber-200"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />{c}</p>)}
                    {e.assetId ? <div className="mt-2 text-right"><Link to="/dashboard/assets" className="text-[10px] text-cyan-300 no-underline hover:underline"><Server className="mr-1 inline h-3 w-3" aria-hidden="true" />Real asset</Link></div> : null}
                  </li>
                ))}
              </ul>
            ) : (
              <Notice tone="info" icon={GitBranch} title="Nothing to model yet">
                The twin mirrors discovered identity providers. Once discovery records one, its relying assets, signing keys and posture appear here.
              </Notice>
            )}
          </Card>
        </div>
      </Reveal>

      {twin.conflicts.length ? (
        <Reveal delay={0.04}>
          <Card title="Conflicts between recorded and observed state" icon={AlertTriangle} meta={`${twin.conflicts.length}`}>
            <ul className="space-y-2">
              {twin.conflicts.map((c, i) => (
                <li key={`${c.providerId}-${i}`} className="rounded-lg border border-amber-400/25 bg-amber-500/[0.04] p-3 text-[11px] text-white/70">
                  <span className="mr-2 text-[9px] font-black uppercase tracking-wider text-amber-300">{c.kind.replace(/-/g, ' ')}</span>{c.detail}
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      ) : null}

      {/* ---- Simulation ----------------------------------------------- */}
      <Reveal delay={0.08}>
        <section aria-label="Simulation workbench" className="rounded-2xl border-2 border-dashed border-violet-400/40 bg-violet-500/[0.03] p-4 lg:p-5">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-violet-200">
              <FlaskConical className="h-4 w-4" aria-hidden="true" />Simulation workbench
            </h2>
            <Badge meta={{ label: 'Simulation · projected, not applied', hex: VIOLET, glyph: '⚗', hint: 'Nothing on this panel is observed or applied to any system.' }} />
          </div>
          <Notice tone="simulation" icon={FlaskConical} title="Every figure below is a projection">
            Scenarios apply published FIPS 203 / 204 / 205 parameter sizes to the keys the twin observed. They predict size and blast-radius impact; they do not
            change any provider, and no prediction here is an observed fact.
          </Notice>

          <div role="tablist" aria-label="Scenarios" className="mt-4 flex flex-wrap gap-1.5">
            {twin.scenarios.map((s) => (
              <button key={s.id} type="button" role="tab" aria-selected={s.id === scenario?.id} onClick={() => setScenarioId(s.id)}
                className={cn('rounded-lg border px-3 py-2 text-left text-[10.5px] font-bold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-300/70',
                  s.id === scenario?.id ? 'border-violet-400/60 bg-violet-500/15 text-violet-200' : 'border-white/12 bg-white/[0.03] text-white/55 hover:text-white/80', !s.applicable && 'opacity-50')}>
                {s.label}<span className="ml-1.5 text-[9px] font-black uppercase tracking-wider text-white/50">{s.standard}</span>
              </button>
            ))}
          </div>

          {scenario ? (
            <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
              <Card title={scenario.label} icon={Calculator} meta={scenario.applicable ? `${scenario.totals.providers} provider(s) · ${scenario.totals.keys} key(s)` : 'not applicable'}>
                <p className="mb-3 text-[11px] leading-relaxed text-white/55">{scenario.description}</p>
                {scenario.applicable ? (
                  <>
                    <div className="mb-3 grid grid-cols-3 gap-2 text-center">
                      <div className="rounded-lg bg-white/[0.03] p-2"><div className="font-mono text-[16px] font-black text-violet-200">+{fmtBytes(scenario.totals.maxDeltaBytes)}</div><div className="text-[9px] font-black uppercase tracking-wider text-white/50">max per-token growth</div></div>
                      <div className="rounded-lg bg-white/[0.03] p-2"><div className="font-mono text-[16px] font-black text-white">{fmtInt(scenario.totals.keys)}</div><div className="text-[9px] font-black uppercase tracking-wider text-white/50">keys affected</div></div>
                      <div className="rounded-lg bg-white/[0.03] p-2"><div className="font-mono text-[16px] font-black text-white">{fmtInt(scenario.totals.dependents)}</div><div className="text-[9px] font-black uppercase tracking-wider text-white/50">relying assets</div></div>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full min-w-[560px]">
                        <thead><tr className="border-b border-white/10"><th className={th()}>Provider</th><th className={th('text-right')}>Keys</th><th className={th()}>Signature segment (encoded)</th><th className={th('text-right')}>Δ token</th><th className={th('text-right')}>Δ JWKS</th></tr></thead>
                        <tbody>
                          {scenario.impacts.map((i) => (
                            <tr key={i.providerId} className="border-b border-white/[0.05] last:border-0">
                              <td className={td('font-semibold text-white')}>{i.providerLabel}<div className="text-[10px] font-normal text-white/50">{i.dependents} relying asset(s)</div></td>
                              <td className={td('text-right font-mono')}>{i.keysAffected}</td>
                              <td className={td('font-mono text-[10.5px]')}>{fmtBytes(i.currentEncodedBytes)} <ArrowRight className="mx-1 inline h-3 w-3 text-white/50" aria-hidden="true" /> <span className="text-violet-200">{fmtBytes(i.projectedEncodedBytes)}</span></td>
                              <td className={td('text-right font-mono text-amber-200')}>+{fmtBytes(i.deltaBytes)}</td>
                              <td className={td('text-right font-mono text-white/55')}>{i.jwksDeltaBytes ? `+${fmtBytes(i.jwksDeltaBytes)}` : '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className="mt-2 text-[10.5px] text-white/45">{scenario.reason}</p>
                  </>
                ) : (
                  <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/50">{scenario.reason}</p>
                )}
              </Card>
              <Card title="Computed from" icon={Calculator} meta="traceable inputs">
                <ul className="space-y-2">
                  {scenario.inputs.map((input, i) => <li key={i} className="rounded-lg border border-white/[0.07] bg-black/10 p-2.5 text-[10.5px] leading-relaxed text-white/60">{input}</li>)}
                </ul>
                <p className="mt-3 text-[10px] leading-relaxed text-white/50">
                  Signatures (ML-DSA, SLH-DSA) and key establishment (ML-KEM) are modelled separately — a signing key is never given an ML-KEM target.
                </p>
              </Card>
            </div>
          ) : null}
        </section>
      </Reveal>
    </div>
  );
}
