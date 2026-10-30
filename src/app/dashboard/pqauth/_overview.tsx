'use client';

import { Link } from 'react-router-dom';
import {
  AlertTriangle, CheckCircle2, Fingerprint, GitBranch, KeyRound, ListChecks, Network, ScanSearch, ShieldCheck, Workflow,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { AMBER, CYAN, GREEN, RED, SLATE, VIOLET, fmtInt, relativeTime } from '../_components/intel/kit';
import type { PQAuthSnapshot } from '@/types/pqauth-dashboard';
import { Card, ClassBadge, GATE_META, PROTOCOL_LABEL, Reveal, RouteLink, StatLink, td, th, ink } from './_ui';

const PRIORITY_HEX = { critical: RED, high: '#fb923c', medium: AMBER, low: SLATE } as const;

/**
 * PQAuth Command Center — the summary of the six modules below it.
 *
 * Every card reads a value the identity model computed for its module and links
 * to that module, so a number here is always the same number on its own page.
 */
export function OverviewView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { identity } = snapshot;
  const { readiness, discovery, tokens, graph, compatibility, migration, twin, providers } = identity;
  const vulnerableKeys = tokens.keys.filter((k) => k.lifecycle === 'published' && k.use !== 'encryption' && k.quantumClass === 'vulnerable').length;
  const publishedSigning = tokens.keys.filter((k) => k.lifecycle === 'published' && k.use !== 'encryption').length;
  const openIssues = compatibility.issues.length;
  const criticalHigh = compatibility.issues.filter((i) => i.severity === 'critical' || i.severity === 'high').length;
  const productionJobs = migration.jobs.filter((j) => !j.simulation).length;
  const trustEdges = graph.edges.filter((e) => e.type === 'TRUSTS' || e.type === 'PUBLISHES').length;
  const exposure = readiness.coverage === null
    ? { word: 'No data', hex: SLATE }
    : readiness.coverage >= 80 ? { word: 'Low exposure', hex: GREEN } : readiness.coverage >= 40 ? { word: 'Moderate exposure', hex: AMBER } : { word: 'High exposure', hex: RED };

  const lifecycle = [
    { label: 'Discover', status: discovery.runs.length ? 'complete' : 'not-started', to: '/dashboard/pqauth/discovery', detail: discovery.lastRunAt ? `Last run ${relativeTime(discovery.lastRunAt)}` : 'No run yet' },
    ...migration.gates.map((gate) => ({ label: gate.label, status: gate.status, to: gate.href ?? '/dashboard/pqauth/migration-center', detail: gate.evidence })),
  ] as Array<{ label: string; status: keyof typeof GATE_META; to: string; detail: string }>;

  return (
    <div className="space-y-4">
      <Reveal className="grid gap-4 xl:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        <Card title="Identity PQC readiness" icon={ShieldCheck} meta="published token-signing keys">
          <div className="flex flex-col items-center gap-3 sm:flex-row xl:flex-col">
            <ReadinessDial coverage={readiness.coverage} word={exposure.word} hex={exposure.hex} />
            <div className="w-full space-y-1.5 text-[11px]">
              {([
                ['safe', readiness.safeKeys],
                ['hybrid', readiness.hybridKeys],
                ['vulnerable', readiness.vulnerableKeys],
                ['unknown', readiness.unknownKeys],
              ] as const).map(([cls, count]) => (
                <div key={cls} className="flex items-center justify-between gap-2">
                  <ClassBadge value={cls} />
                  <span className="font-mono text-white/70">{fmtInt(count)}</span>
                </div>
              ))}
              <p className="pt-1 text-[10px] leading-relaxed text-white/50">
                Share of classified signing keys that are post-quantum or hybrid. Undetermined keys are excluded, never counted as safe.
                {readiness.coverage === null ? ' No key has been classified yet.' : ''}
              </p>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <StatLink icon={Fingerprint} label="Identity providers" value={fmtInt(providers.length)} color={CYAN} to="/dashboard/pqauth/discovery"
            detail={providers.length ? `${providers.filter((p) => p.quantumClass === 'vulnerable').length} quantum-vulnerable · ${providers.filter((p) => p.age === 'stale').length} stale` : discovery.runs.length ? 'Discovery found no provider metadata' : 'Run identity discovery'} />
          <StatLink icon={KeyRound} label="Classical signing keys" value={fmtInt(vulnerableKeys)} color={vulnerableKeys ? RED : GREEN} to="/dashboard/pqauth/token-intelligence"
            detail={publishedSigning ? `of ${fmtInt(publishedSigning)} published signing keys` : 'No JWKS keys observed'} />
          <StatLink icon={Network} label="Trust relationships" value={fmtInt(trustEdges)} color={VIOLET} to="/dashboard/pqauth/trust-graph"
            detail={`${graph.edges.filter((e) => e.confidence === 'declared').length} declared · ${graph.edges.filter((e) => e.confidence === 'unresolved').length} unresolved`} />
          <StatLink icon={CheckCircle2} label="Compatibility issues" value={fmtInt(openIssues)} color={criticalHigh ? RED : openIssues ? AMBER : GREEN} to="/dashboard/pqauth/compatibility"
            detail={`${criticalHigh} critical or high · ${compatibility.counts['not-verified']} checks not verified`} />
          <StatLink icon={Workflow} label="Identity migration" value={`${fmtInt(migration.counts.validated)}/${fmtInt(productionJobs)}`} color={migration.counts.failed ? RED : CYAN} to="/dashboard/pqauth/migration-center"
            detail={productionJobs ? `validated of ${productionJobs} job(s) · ${migration.counts.completed} awaiting validation` : `No identity-scoped job (${migration.tenantJobCount} tenant job(s) elsewhere)`} />
          <StatLink icon={GitBranch} label="Digital twin" value={twin.sync.status.replace(/-/g, ' ')} color={twin.sync.status === 'in-sync' ? GREEN : twin.sync.status === 'never-synced' ? SLATE : AMBER} to="/dashboard/pqauth/digital-twin"
            detail={twin.sync.lastSyncAt ? `Synced from discovery ${relativeTime(twin.sync.lastSyncAt)}` : 'Not synchronised'} />
        </div>
      </Reveal>

      <Reveal delay={0.05}>
        <Card title="Identity migration lifecycle" icon={ListChecks} meta="every step is gated by evidence">
          <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-8">
            {lifecycle.map((step, index) => {
              const meta = GATE_META[step.status];
              return (
                <li key={step.label}>
                  <Link to={step.to} className="group flex h-full flex-col rounded-xl border border-white/10 bg-white/[0.02] p-3 no-underline transition hover:border-cyan-400/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
                    <span className="flex items-center gap-2">
                      <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border font-mono text-[10px] font-black" style={{ borderColor: `${meta.hex}66`, color: ink(meta.hex), backgroundColor: `${meta.hex}14` }} aria-hidden="true">
                        {meta.glyph === '○' ? index + 1 : meta.glyph}
                      </span>
                      <span className="text-[10.5px] font-black uppercase tracking-wider text-white/80">{step.label}</span>
                    </span>
                    <span className="mt-1.5 text-[9px] font-black uppercase tracking-wider" style={{ color: ink(meta.hex) }}>{meta.label}</span>
                    <span className="mt-1 line-clamp-3 text-[10px] leading-snug text-white/45">{step.detail}</span>
                  </Link>
                </li>
              );
            })}
          </ol>
        </Card>
      </Reveal>

      <Reveal delay={0.1} className="grid gap-4 xl:grid-cols-2">
        <Card title="Recommended next actions" icon={AlertTriangle} meta="ranked from current evidence">
          <ol className="space-y-2">
            {identity.nextActions.map((action) => (
              <li key={action.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-[12px] font-bold text-white">{action.title}</div>
                    {action.detail ? <p className="mt-1 text-[11px] leading-relaxed text-white/50">{action.detail}</p> : null}
                  </div>
                  <span className="shrink-0 rounded-full border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider" style={{ borderColor: `${PRIORITY_HEX[action.priority]}55`, color: ink(PRIORITY_HEX[action.priority]) }}>
                    {action.priority}
                  </span>
                </div>
                <div className="mt-2"><RouteLink to={action.href} tone="ghost">Go</RouteLink></div>
              </li>
            ))}
          </ol>
        </Card>

        <Card title="Discovered identity providers" icon={ScanSearch} meta={`${providers.length} recorded`} action={<RouteLink to="/dashboard/pqauth/discovery" tone="ghost">Discovery</RouteLink>}>
          {providers.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[460px]">
                <thead><tr className="border-b border-white/10"><th className={th()}>Provider</th><th className={th()}>Protocol</th><th className={th()}>Posture</th><th className={th('text-right')}>Keys</th></tr></thead>
                <tbody>
                  {providers.slice(0, 8).map((p) => (
                    <tr key={p.id} className="border-b border-white/[0.05] last:border-0">
                      <td className={td()}>
                        <Link to={`/dashboard/pqauth/trust-graph?focus=provider:${p.id}`} className="font-semibold text-white no-underline hover:text-cyan-200">{p.vendor ?? p.displayName}</Link>
                        <div className="truncate font-mono text-[10px] text-white/50" title={p.issuer}>{p.issuer}</div>
                      </td>
                      <td className={td()}>{PROTOCOL_LABEL[p.protocol] ?? p.protocol}</td>
                      <td className={td()}><ClassBadge value={p.quantumClass} /></td>
                      <td className={td('text-right font-mono')}>{p.publishedKeyCount}{p.vulnerableKeyCount ? <span className="text-red-300"> · {p.vulnerableKeyCount}●</span> : null}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className={cn('rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] leading-relaxed text-white/50')}>
              {discovery.runs.length
                ? 'Discovery has run and no host published OIDC, OAuth 2.0 or SAML metadata at the standard locations. Nothing is shown because nothing was found.'
                : 'No identity discovery has run yet. Providers appear here only once their metadata is read from a host you own.'}
            </p>
          )}
        </Card>
      </Reveal>
    </div>
  );
}

/** Readiness ring. `null` renders an em dash and an empty track — never a 0% arc. */
function ReadinessDial({ coverage, word, hex }: { coverage: number | null; word: string; hex: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative grid h-[136px] w-[136px] shrink-0 place-items-center" role="img" aria-label={coverage === null ? 'Readiness: no classified keys' : `Readiness ${coverage}% — ${word}`}>
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(127,127,127,0.18)" strokeWidth="9" />
        {coverage !== null ? (
          <circle cx="60" cy="60" r={r} fill="none" stroke={hex} strokeWidth="9" strokeLinecap="round" strokeDasharray={c}
            strokeDashoffset={c - (c * Math.max(0, Math.min(100, coverage))) / 100} style={{ transition: 'stroke-dashoffset 700ms ease' }} />
        ) : null}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="font-mono text-[32px] font-black leading-none" style={{ color: ink(hex) }}>{coverage === null ? '—' : `${coverage}%`}</div>
          <div className="mt-1 text-[9.5px] font-black uppercase tracking-[0.14em]" style={{ color: ink(hex) }}>{word}</div>
          <div className="mt-0.5 text-[9px] text-white/50">post-quantum or hybrid</div>
        </div>
      </div>
    </div>
  );
}
