'use client';

/**
 * Execution-history / audit drawer for one migration job, shared by PQC
 * Orchestration and Migration Timeline.
 *
 * Holds a job ID, never a copy of a row (issue #36): the job is resolved from
 * the live snapshot on every render, and its full event log and validation
 * records are read from `GET /api/v1/migration-orchestrator/jobs/:id` with the
 * session token in the Authorization header. Read-only — every action links to
 * the module that owns it (Live Migration re-checks approval and takes the
 * pre-change snapshot).
 */
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { ExternalLink, History, RefreshCw, ShieldCheck, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/auth-context';
import { isFailingValidation, isPassingValidation } from '@/lib/migration/job-safety';
import { VERIFICATION_LABEL, jobDisplayStatus, type OrchestrationJob } from '@/lib/migration/orchestration-model';
import { EmptyRow, fullTimestamp, relativeTime } from '../_components/intel/kit';
import { GateStrip, PathBadge, PathLine, StatusBadge, TONE_CHIP } from './_orch-ui';

type Row = Record<string, unknown>;

interface JobDetail {
  job: OrchestrationJob | null;
  events: Row[];
  validations: Row[];
  sources: { events: 'ok' | 'unavailable'; validations: 'ok' | 'unavailable' };
}

type LoadState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ok'; detail: JobDetail }
  | { status: 'not-found' }
  | { status: 'error'; message: string };

function text(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value);
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-[8.5px] font-black uppercase tracking-[0.16em] text-white/45">{label}</dt>
      <dd className="mt-0.5 text-[12px] leading-snug text-white/80">{children}</dd>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-[9px] font-black uppercase tracking-[0.18em] text-cyan-300/85">{title}</h3>
      {children}
    </section>
  );
}

export function JobDrawer({ jobId, jobs, onClose }: { jobId: string | null; jobs: OrchestrationJob[]; onClose: () => void }) {
  const { session } = useAuth();
  const token = session?.access_token;
  const [load, setLoad] = useState<LoadState>({ status: 'idle' });
  const [reloadKey, setReloadKey] = useState(0);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!jobId) { setLoad({ status: 'idle' }); return; }
    if (!token) { setLoad({ status: 'error', message: 'No active session — sign in again to read the job history.' }); return; }
    const controller = new AbortController();
    setLoad({ status: 'loading' });
    fetch(`/api/v1/migration-orchestrator/jobs/${encodeURIComponent(jobId)}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    })
      .then(async (response) => {
        const body = await response.json().catch(() => ({}));
        if (controller.signal.aborted) return;
        if (response.status === 404) { setLoad({ status: 'not-found' }); return; }
        if (!response.ok) { setLoad({ status: 'error', message: body?.error?.message || `HTTP ${response.status}` }); return; }
        const data = (body?.data || {}) as Partial<JobDetail>;
        setLoad({
          status: 'ok',
          detail: {
            job: data.job ?? null,
            events: Array.isArray(data.events) ? data.events : [],
            validations: Array.isArray(data.validations) ? data.validations : [],
            sources: { events: data.sources?.events ?? 'ok', validations: data.sources?.validations ?? 'ok' },
          },
        });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setLoad({ status: 'error', message: error instanceof Error ? error.message : 'Request failed' });
      });
    return () => controller.abort();
  }, [jobId, token, reloadKey]);

  useEffect(() => {
    if (!jobId) return;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [jobId, onClose]);

  const retry = useCallback(() => setReloadKey((k) => k + 1), []);

  if (!jobId) return null;
  const job = jobs.find((row) => row.id === jobId) ?? (load.status === 'ok' ? load.detail.job : null);
  const display = job ? jobDisplayStatus(job) : null;
  const titleId = `job-drawer-title-${jobId}`;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-labelledby={titleId} className="flex h-full w-full max-w-[560px] flex-col overflow-y-auto border-l border-white/12 bg-[#0b1424] shadow-2xl">
        <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-white/10 bg-[#0b1424] px-5 py-4">
          <div className="min-w-0">
            <h2 id={titleId} className="text-[15px] font-black leading-snug text-white">{job?.name || `Migration job ${jobId.slice(0, 8)}`}</h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              {display ? <StatusBadge status={display} /> : null}
              {job ? <span className="text-[10.5px] text-white/50">{job.assetName} · {job.sourceLabel}</span> : null}
            </div>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close job details" className="rounded-lg border border-white/12 bg-white/[0.04] p-1.5 text-white/60 transition hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </header>

        <div className="space-y-5 px-5 py-5">
          {!job ? (
            <EmptyRow>
              {load.status === 'loading' ? 'Loading this job…' : 'This job is not in the current snapshot (it may be beyond the 200 most urgent listed, or it was removed).'}
            </EmptyRow>
          ) : (
            <>
              <div className={cn('rounded-xl border p-3.5', display === 'verified' ? TONE_CHIP.emerald : display && ['failed', 'validation-failed', 'executor-silent', 'rejected'].includes(display) ? TONE_CHIP.red : TONE_CHIP.cyan)}>
                <div className="text-[8.5px] font-black uppercase tracking-[0.16em]">Where it stands</div>
                <p className="mt-1 text-[12px] leading-relaxed text-white/80">{job.headline}</p>
                <div className="mt-2 text-[8.5px] font-black uppercase tracking-[0.16em]">What moves it</div>
                <p className="mt-1 text-[12px] leading-relaxed text-white/80">{job.nextAction}</p>
              </div>

              <Section title="Execution gates">
                <GateStrip gates={job.gates} />
              </Section>

              <Section title="Migration path">
                <div className="flex flex-wrap items-center gap-2"><PathLine job={job} /><PathBadge check={job.pathCheck} /></div>
                <p className="text-[11px] leading-relaxed text-white/60">{job.pathNote}</p>
              </Section>

              <Section title="Executor & verification">
                <dl className="grid grid-cols-2 gap-3">
                  <Field label="Assigned agent">{job.executor.assignedAgent || <span className="text-white/45">Not claimed</span>}</Field>
                  <Field label="Heartbeat">
                    {job.executor.online === null
                      ? <span className="text-white/50">? Unknown{job.executor.assignedAgentId ? ' — fleet unreadable' : ''}</span>
                      : job.executor.online ? <span className="text-emerald-300">● Checking in</span> : <span className="text-red-300">! Not checking in</span>}
                    {job.executor.lastSeenAt ? <span className="block text-[10px] text-white/45">last seen {relativeTime(job.executor.lastSeenAt)}</span> : null}
                  </Field>
                  <Field label="Verification">
                    <span className={job.verification === 'passed' ? 'text-emerald-300' : job.verification === 'failed' ? 'text-red-300' : 'text-amber-300'}>
                      {job.verification === 'passed' ? '✓ ' : job.verification === 'failed' ? '✕ ' : '◑ '}{VERIFICATION_LABEL[job.verification]}
                    </span>
                    <span className="block text-[10px] text-white/45">{job.validationRecords} validation record{job.validationRecords === 1 ? '' : 's'}{job.verifiedAt ? ` · ${fullTimestamp(job.verifiedAt)}` : ''}</span>
                  </Field>
                  <Field label="Executor progress">{job.progress === null ? <span className="text-white/45">Not reported</span> : `${job.progress}% (executor-reported)`}</Field>
                </dl>
              </Section>

              {job.phase === 'failed' ? (
                <Section title="Failure">
                  <div className={cn('rounded-xl border p-3', TONE_CHIP.red)}>
                    <p className="text-[12px] leading-relaxed text-white/80">{job.failureReason || 'The executor did not record a failure reason.'}</p>
                    <p className="mt-2 text-[10.5px] text-white/60">
                      {job.retry === 'eligible'
                        ? 'Retry-eligible: an operator may retry it from Live Migration, which re-checks approval first. Nothing retries automatically.'
                        : 'Not retry-eligible yet: the work has no recorded approval. Approve it before any retry.'}
                    </p>
                  </div>
                </Section>
              ) : null}

              <Section title="Recorded timestamps">
                <dl className="grid grid-cols-2 gap-3">
                  <Field label="Recorded">{fullTimestamp(job.createdAt)}</Field>
                  <Field label="Started">{job.startedAt ? fullTimestamp(job.startedAt) : <span className="text-white/45">Not started</span>}</Field>
                  <Field label="Completed">{job.completedAt ? fullTimestamp(job.completedAt) : <span className="text-white/45">Not completed</span>}</Field>
                  <Field label="Last update">{fullTimestamp(job.updatedAt)}</Field>
                  {job.sequence?.phaseIndex ? (
                    <Field label="Plan phase">
                      Phase {job.sequence.phaseIndex}{job.sequence.totalPhases ? ` of ${job.sequence.totalPhases}` : ''}{job.sequence.phaseName ? ` · ${job.sequence.phaseName}` : ''}
                      {job.sequence.waitingForPriorPhase ? <span className="block text-[10px] text-blue-300">‖ waits for the prior phase (recorded gate)</span> : null}
                    </Field>
                  ) : null}
                  <Field label="Approval">
                    {job.approval.approved
                      ? <>✓ {job.approval.approvedBy || 'Recorded'}{job.approval.approvedAt ? <span className="block text-[10px] text-white/45">{fullTimestamp(job.approval.approvedAt)}</span> : null}</>
                      : !job.approval.readable ? <span className="text-white/50">? Unreadable</span> : <span className="text-blue-300">◷ {job.approval.state === 'rejected' ? 'Rejected' : 'Not approved'}</span>}
                  </Field>
                </dl>
              </Section>
            </>
          )}

          <Section title="Execution history">
            {load.status === 'loading' ? <EmptyRow>Loading the event log…</EmptyRow> : null}
            {load.status === 'not-found' ? <EmptyRow>No job with this id is visible to your account (404). It may have been removed.</EmptyRow> : null}
            {load.status === 'error' ? (
              <div className={cn('flex flex-wrap items-center gap-2 rounded-lg border p-3 text-[11px]', TONE_CHIP.red)}>
                <span className="flex-1">The job history could not be loaded: {load.message}. This is not an empty history.</span>
                <button type="button" onClick={retry} className="inline-flex items-center gap-1 rounded border border-red-400/40 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300/70">
                  <RefreshCw className="h-3 w-3" aria-hidden="true" /> Retry
                </button>
              </div>
            ) : null}
            {load.status === 'ok' ? (
              load.detail.sources.events === 'unavailable'
                ? <EmptyRow>The event log could not be read — not "no events".</EmptyRow>
                : load.detail.events.length === 0
                  ? <EmptyRow>No events are recorded for this job yet.</EmptyRow>
                  : (
                    <ol className="space-y-1.5" aria-label="Events, newest first">
                      {load.detail.events.map((event) => {
                        const severity = text(event.severity).toLowerCase();
                        const tone = /error|critical|fail/.test(severity) ? 'text-red-300' : /warn/.test(severity) ? 'text-amber-300' : 'text-white/55';
                        return (
                          <li key={text(event.id)} className="flex gap-2.5 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                            <History className={cn('mt-0.5 h-3.5 w-3.5 shrink-0', tone)} aria-hidden="true" />
                            <div className="min-w-0 flex-1">
                              <div className="text-[11.5px] leading-snug text-white/80">{text(event.message) || text(event.event_type)}</div>
                              <div className="mt-0.5 font-mono text-[9.5px] text-white/45">
                                {text(event.event_type)} · <span className={tone}>{severity || 'info'}</span> · {fullTimestamp(text(event.created_at))}
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ol>
                  )
            ) : null}
          </Section>

          <Section title="Validation records">
            {load.status === 'ok' ? (
              load.detail.sources.validations === 'unavailable'
                ? <EmptyRow>Validation records could not be read — verification is unknown, not failed.</EmptyRow>
                : load.detail.validations.length === 0
                  ? <EmptyRow>No validation record exists for this job. Completion without one is not verification.</EmptyRow>
                  : (
                    <ol className="space-y-1.5" aria-label="Validation records, newest first">
                      {load.detail.validations.map((row) => {
                        const status = text(row.status);
                        const pass = isPassingValidation(status);
                        const fail = !pass && isFailingValidation(status);
                        const evidence = (row.evidence && typeof row.evidence === 'object' ? row.evidence : {}) as Row;
                        return (
                          <li key={text(row.id)} className="flex gap-2.5 rounded-lg border border-white/8 bg-white/[0.02] px-3 py-2">
                            <ShieldCheck className={cn('mt-0.5 h-3.5 w-3.5 shrink-0', pass ? 'text-emerald-300' : fail ? 'text-red-300' : 'text-white/45')} aria-hidden="true" />
                            <div className="min-w-0 flex-1">
                              <div className="text-[11.5px] text-white/80">
                                <span className={pass ? 'text-emerald-300' : fail ? 'text-red-300' : 'text-white/60'}>{pass ? '✓ Passed' : fail ? '✕ Failed' : `○ ${status || 'recorded'} (not a pass)`}</span>
                                {' · '}{text(row.validation_type) || 'validation'}
                              </div>
                              <div className="mt-0.5 font-mono text-[9.5px] text-white/45">
                                {fullTimestamp(text(row.created_at))}
                                {evidence.evidenceCount !== undefined ? ` · ${text(evidence.evidenceCount)} evidence item(s)` : ''}
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ol>
                  )
            ) : load.status === 'loading' ? <EmptyRow>Loading validation records…</EmptyRow> : null}
          </Section>
        </div>

        {job ? (
          <footer className="mt-auto flex flex-wrap gap-2 border-t border-white/10 px-5 py-4">
            <a href={job.links.liveMigration} className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-cyan-400/45 bg-cyan-500/15 px-3 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:bg-cyan-500/25">
              Live Migration <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </a>
            {job.links.planner ? (
              <a href={job.links.planner} className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-3 text-[9.5px] font-black uppercase tracking-wider text-white/65 no-underline hover:bg-white/[0.08]">Migration Planner</a>
            ) : null}
            {job.links.asset ? (
              <a href={job.links.asset} className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-3 text-[9.5px] font-black uppercase tracking-wider text-white/65 no-underline hover:bg-white/[0.08]">Asset</a>
            ) : null}
            <a href="/downloads" className="inline-flex min-h-[34px] items-center gap-1 rounded-lg border border-white/12 bg-white/[0.04] px-3 text-[9.5px] font-black uppercase tracking-wider text-white/65 no-underline hover:bg-white/[0.08]">Agent Center</a>
          </footer>
        ) : null}
      </div>
    </div>
  );
}
