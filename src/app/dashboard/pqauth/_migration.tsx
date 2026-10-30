'use client';

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { AlertTriangle, ArrowRight, CheckCircle2, ClipboardList, FlaskConical, GitPullRequest, Lightbulb, ShieldCheck, Workflow } from 'lucide-react';
import { cn } from '@/lib/utils';
import { GREEN, RED, SLATE, VIOLET, fmtInt, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type { PQAuthJobState, PQAuthMigrationJob, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import {
  Badge, Card, ClassBadge, DetailDrawer, Field, FilterChips, GATE_META, JOB_META, JobBadge, Notice, Reveal, RouteLink, td, th,
  ink,
} from './_ui';

const STATES: PQAuthJobState[] = ['proposed', 'queued', 'executing', 'completed', 'validated', 'failed'];

const VALIDATION_META = {
  validated: { label: 'Validated', hex: GREEN, glyph: '✓', hint: 'A discovery after completion observed the target posture.' },
  'awaiting-rediscovery': { label: 'Awaiting re-discovery', hex: '#fbbf24', glyph: '◔', hint: 'Not yet confirmed by observation.' },
  regressed: { label: 'Not effective', hex: RED, glyph: '✕', hint: 'Re-discovery after completion still observed classical keys.' },
  'not-applicable': { label: 'Not applicable', hex: SLATE, glyph: '–', hint: 'Validation applies to completed production jobs.' },
} as const;

export function MigrationView({ snapshot }: { snapshot: PQAuthSnapshot }) {
  const { migration, providers, tokens } = snapshot.identity;
  const reduce = useReducedMotion();
  const [state, setState] = useState<'all' | PQAuthJobState | 'simulation'>('all');
  const [open, setOpen] = useState<PQAuthMigrationJob | null>(null);
  const production = migration.jobs.filter((j) => !j.simulation);
  const sandbox = migration.jobs.filter((j) => j.simulation);
  const jobs = useMemo(() => migration.jobs.filter((j) => state === 'all' || (state === 'simulation' ? j.simulation : !j.simulation && j.state === state)), [migration.jobs, state]);
  const total = Math.max(1, production.length);

  // Recommendations: one per vulnerable provider WITHOUT a production job. Labelled as recommendations, never as plans.
  const recommendations = providers
    .filter((p) => p.vulnerableKeyCount > 0 && !production.some((j) => j.assetId && j.assetId === p.assetId))
    .map((p) => {
      const keys = tokens.keys.filter((k) => k.providerId === p.id && k.lifecycle === 'published' && k.quantumClass === 'vulnerable');
      return { provider: p, current: Array.from(new Set(keys.map((k) => k.displayAlgorithm))), target: Array.from(new Set(keys.map((k) => k.pqcTarget).filter(Boolean))) as string[] };
    });

  return (
    <div className="space-y-4">
      <Reveal>
        <Card title="Identity migration workflow" icon={Workflow} meta="assess → monitor, each gate earned from evidence">
          <ol className="grid gap-2 md:grid-cols-4 xl:grid-cols-7">
            {migration.gates.map((gate, index) => {
              const meta = GATE_META[gate.status];
              const body = (
                <>
                  <div className="flex items-center gap-2">
                    <span className="grid h-6 w-6 place-items-center rounded-full border font-mono text-[10px] font-black" style={{ borderColor: `${meta.hex}66`, color: ink(meta.hex), backgroundColor: `${meta.hex}14` }} aria-hidden="true">{meta.glyph === '○' ? index + 1 : meta.glyph}</span>
                    <span className="text-[10.5px] font-black uppercase tracking-wider text-white/80">{gate.label}</span>
                  </div>
                  <div className="mt-1.5 text-[9px] font-black uppercase tracking-wider" style={{ color: ink(meta.hex) }}>{meta.label}</div>
                  <p className="mt-1 text-[10px] leading-snug text-white/50">{gate.evidence}</p>
                  <p className="mt-1 text-[9.5px] leading-snug text-white/50">{gate.description}</p>
                </>
              );
              return (
                <li key={gate.id} className="relative">
                  {gate.href ? (
                    <Link to={gate.href} className="block h-full rounded-xl border bg-white/[0.02] p-3 no-underline transition hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70" style={{ borderColor: `${meta.hex}40` }}>{body}</Link>
                  ) : <div className="h-full rounded-xl border bg-white/[0.02] p-3" style={{ borderColor: `${meta.hex}40` }}>{body}</div>}
                </li>
              );
            })}
          </ol>
        </Card>
      </Reveal>

      <Reveal delay={0.04}>
        <Card title="Job state distribution" icon={ClipboardList} meta={`${production.length} production · ${sandbox.length} sandbox · ${migration.tenantJobCount} tenant jobs in total`}>
          <div className="flex h-3 overflow-hidden rounded-full bg-white/[0.05]" role="img" aria-label={STATES.map((s) => `${JOB_META[s].label}: ${migration.counts[s]}`).join(', ')}>
            {STATES.map((s) => migration.counts[s] ? <span key={s} style={{ width: `${(migration.counts[s] / total) * 100}%`, backgroundColor: JOB_META[s].hex }} /> : null)}
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
            {STATES.map((s) => (
              <div key={s} className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5" title={JOB_META[s].hint}>
                <div className="text-[9px] font-black uppercase tracking-wider" style={{ color: ink(JOB_META[s].hex) }}>{JOB_META[s].glyph} {JOB_META[s].label}</div>
                <div className="mt-1 font-mono text-[18px] font-black text-white">{fmtInt(migration.counts[s])}</div>
                <p className="text-[9.5px] leading-snug text-white/50">{JOB_META[s].hint}</p>
              </div>
            ))}
          </div>
        </Card>
      </Reveal>

      <Reveal delay={0.08}>
        <Card title="Identity migration jobs" icon={GitPullRequest} meta={`${jobs.length} shown`} action={<RouteLink to="/dashboard/migration-planner" tone="ghost">Migration Planner</RouteLink>}>
          {migration.jobs.length ? (
            <>
              <div className="mb-3">
                <FilterChips label="Job state" value={state} onChange={setState} options={[
                  { key: 'all', label: 'All', count: migration.jobs.length },
                  ...STATES.map((s) => ({ key: s, label: JOB_META[s].label, count: migration.counts[s] })),
                  { key: 'simulation' as const, label: 'Sandbox', count: sandbox.length },
                ]} />
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[900px]">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className={th()}>Job / asset</th><th className={th()}>Current → target</th><th className={th()}>State</th>
                      <th className={th()}>Validation</th><th className={th()}>Role check</th><th className={th()}>Rollback</th><th className={th('text-right')}>Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((job) => (
                      <tr key={job.id} className="cursor-pointer border-b border-white/[0.05] transition hover:bg-white/[0.03]" onClick={() => setOpen(job)}>
                        <td className={td()}>
                          <button type="button" onClick={(e) => { e.stopPropagation(); setOpen(job); }} className="text-left font-semibold text-white hover:text-cyan-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">{job.name}</button>
                          <div className="text-[10px] text-white/50">{job.assetName ?? 'asset'} · {job.jobType?.replace(/_/g, ' ') ?? 'job'}</div>
                          {job.simulation ? <div className="mt-1"><Badge meta={{ label: 'Sandbox · simulation', hex: VIOLET, glyph: '⚗', hint: 'Dry-run / sandbox job — never a production change.' }} /></div> : null}
                        </td>
                        <td className={td('font-mono text-[10.5px]')}>
                          <span className="text-white/60">{job.sourceAlgorithm ?? 'not recorded'}</span> <ArrowRight className="mx-1 inline h-3 w-3 text-white/50" aria-hidden="true" /> <span className="text-violet-200">{job.targetAlgorithm ?? 'not recorded'}</span>
                        </td>
                        <td className={td()}>
                          <JobBadge value={job.state} />
                          {job.state === 'executing' && job.progress !== null ? (
                            <div className="mt-1.5 h-1 w-24 overflow-hidden rounded-full bg-white/8" role="progressbar" aria-valuenow={job.progress} aria-valuemin={0} aria-valuemax={100} aria-label="Executor-reported progress">
                              <motion.div className="h-full rounded-full bg-violet-400" initial={false} animate={{ width: `${Math.max(0, Math.min(100, job.progress))}%` }} transition={reduce ? { duration: 0 } : { duration: 0.5 }} />
                            </div>
                          ) : null}
                        </td>
                        <td className={td()}><Badge meta={VALIDATION_META[job.validation.status]} /></td>
                        <td className={td()}>
                          {job.roleCheck.ok === false
                            ? <span className="inline-flex items-center gap-1 text-[10.5px] font-bold text-red-300" title={job.roleCheck.detail}><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />Wrong primitive</span>
                            : job.roleCheck.ok ? <span className="inline-flex items-center gap-1 text-[10.5px] text-emerald-300" title={job.roleCheck.detail}><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />Correct role</span>
                              : <span className="text-[10.5px] text-white/50" title={job.roleCheck.detail}>Undetermined</span>}
                        </td>
                        <td className={td('text-[10.5px]')}>{job.rollback.available ? <span className="text-emerald-300">Snapshot recorded</span> : <span className="text-white/50">None recorded</span>}</td>
                        <td className={td('text-right text-white/45')} title={fullTimestamp(job.updatedAt)}>{relativeTime(job.updatedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <Notice tone="info" icon={ClipboardList} title="No migration job targets an identity asset">
              {migration.tenantJobCount
                ? `${migration.tenantJobCount} migration job(s) exist in this tenant, but none is on an asset that hosts or trusts a discovered identity provider.`
                : 'No migration job exists in this tenant yet.'}{' '}
              Plan identity work in the Migration Planner; jobs appear here once they reference an identity asset.
            </Notice>
          )}
        </Card>
      </Reveal>

      {recommendations.length ? (
        <Reveal delay={0.12}>
          <Card title="Recommended targets — not yet planned" icon={Lightbulb} meta="recommendations, not plans">
            <ul className="grid gap-3 md:grid-cols-2">
              {recommendations.map(({ provider, current, target }) => (
                <li key={provider.id} className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[12px] font-black text-white">{provider.vendor ?? provider.displayName}</span>
                    <ClassBadge value={provider.quantumClass} />
                  </div>
                  <div className="mt-2 font-mono text-[10.5px] text-white/60">{current.join(', ')} <ArrowRight className="mx-1 inline h-3 w-3" aria-hidden="true" /> <span className="text-violet-200">{target.join(', ') || 'ML-DSA-65'}</span></div>
                  <p className="mt-1.5 text-[10px] leading-relaxed text-white/50">
                    {provider.vulnerableKeyCount} classical signing key(s); {provider.dependentAssetIds.length} relying asset(s). Signatures move to ML-DSA (FIPS 204) — ML-KEM applies only to encrypted-token key management and TLS key exchange.
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <RouteLink to="/dashboard/pqauth/digital-twin" tone="ghost">Simulate first</RouteLink>
                    <RouteLink to="/dashboard/migration-planner" tone="ghost">Plan in Migration Planner</RouteLink>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </Reveal>
      ) : null}

      <DetailDrawer open={Boolean(open)} onClose={() => setOpen(null)} title={open?.name ?? ''} subtitle={open ? `${open.assetName ?? 'asset'} · ${open.rawStatus}` : undefined}>
        {open ? <JobDetail job={open} /> : null}
      </DetailDrawer>
    </div>
  );
}

function JobDetail({ job }: { job: PQAuthMigrationJob }) {
  const timeline = [
    { label: 'Started', at: job.startedAt },
    { label: 'Reported complete', at: job.completedAt },
    { label: 'Last update', at: job.updatedAt },
  ];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        <JobBadge value={job.state} />
        <Badge meta={VALIDATION_META[job.validation.status]} />
        {job.simulation ? <Badge meta={{ label: 'Sandbox · simulation', hex: VIOLET, glyph: '⚗', hint: 'Never a production change.' }} /> : null}
      </div>
      {job.simulation ? (
        <Notice tone="simulation" icon={FlaskConical} title="Simulation — no production change">This job ran in the Migration Sandbox. Its outcome is not counted as migration progress and is never validated against production.</Notice>
      ) : null}

      <section aria-label="Before and after configuration" className="grid grid-cols-2 gap-2">
        <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
          <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/50">Current</div>
          <div className="mt-1 font-mono text-[12px] text-white">{job.sourceAlgorithm ?? 'Not recorded'}</div>
        </div>
        <div className="rounded-xl border border-violet-400/30 bg-violet-500/[0.05] p-3">
          <div className="text-[8.5px] font-black uppercase tracking-[0.16em] text-violet-200">Target</div>
          <div className="mt-1 font-mono text-[12px] text-violet-200">{job.targetAlgorithm ?? 'Not recorded'}</div>
        </div>
      </section>

      <Notice tone={job.roleCheck.ok === false ? 'critical' : 'info'} icon={job.roleCheck.ok === false ? AlertTriangle : ShieldCheck} title={job.roleCheck.ok === false ? 'Target does not preserve the security property' : 'Cryptographic role check'}>
        {job.roleCheck.detail}
      </Notice>

      <dl>
        <Field label="Validation">{job.validation.detail}</Field>
        <Field label="Rollback">{job.rollback.detail}</Field>
        <Field label="Progress">{job.progress !== null ? `${job.progress}% (executor-reported)` : 'Not reported'}</Field>
        <Field label="Job type">{job.jobType ?? '—'}</Field>
      </dl>

      <div>
        <div className="mb-1.5 text-[8.5px] font-black uppercase tracking-[0.18em] text-white/50">Execution history</div>
        <ol className="space-y-1.5 border-l border-white/10 pl-3">
          {timeline.map((t) => (
            <li key={t.label} className={cn('text-[11px]', t.at ? 'text-white/70' : 'text-white/50')}>
              <span className="font-bold">{t.label}</span> · {t.at ? fullTimestamp(t.at) : 'not recorded'}
            </li>
          ))}
          <li className={cn('text-[11px]', job.validation.status === 'validated' ? 'text-emerald-300' : 'text-white/50')}>
            <span className="font-bold">Validated by re-discovery</span> · {job.validation.status === 'validated' ? 'confirmed' : 'not yet'}
          </li>
        </ol>
      </div>
      <div className="flex flex-wrap gap-1.5">
        <RouteLink to="/dashboard/live-migration" tone="ghost">Live Migration Ops</RouteLink>
        <RouteLink to="/dashboard/pqauth/discovery" tone="ghost">Re-run discovery</RouteLink>
      </div>
    </div>
  );
}
