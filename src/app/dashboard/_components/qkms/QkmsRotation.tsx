'use client';

/**
 * Key Rotation Center — the operational work-order plane.
 *
 * ── What this page will and will not claim ─────────────────────────────────
 * QKMS does not hold the private material of a key it discovered on your
 * estate, so it cannot perform the cryptographic rotation. What it does — and
 * what these work orders record — is govern the operation end to end:
 *
 *     Request → Approve → Execute → Validate → Complete (with evidence)
 *
 * Transitions are enforced server-side, so a work order cannot jump from
 * `requested` to `completed` and manufacture a rotation nobody performed. A
 * completed order with no validation evidence is reported as
 * `awaiting validation`, not as a success — and the migration gate reads
 * VALIDATION REQUIRED rather than MIGRATED because of it.
 *
 * The predecessor rendered a nine-step "workflow" whose steps advanced on their
 * own and a "Start Dry Run" button that called an endpoint ignoring its key
 * argument. Neither existed in the backend.
 */

import { useCallback, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, ClipboardList, Network, RefreshCw, ShieldCheck, Timer } from 'lucide-react';
import { useKeyRotation, useKeyQuery, useQkmsActions } from '@/hooks/use-qkms';
import { ROTATION_LABEL } from '@/lib/qkms/types';
import type { RotationJobStatus, RotationState } from '@/lib/qkms/types';
import { KeyDrawer } from './KeyDrawer';
import {
  ActionButton,
  BarRow,
  ExplainBox,
  ExportMenu,
  FilterSelect,
  JobStatusBadge,
  KeyTable,
  Kpi,
  Notice,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  QkmsShell,
  SectionLabel,
  absoluteTime,
  fmtNumber,
  relativeTime,
  useNotice,
  whenRelative,
  useQkmsExport,
  type KeyColumn,
} from './shell';

const COLUMNS: KeyColumn[] = [
  'key', 'algorithm', 'owner', 'asset', 'environment', 'version',
  'rotation', 'lastRotated', 'expiry', 'posture', 'risk',
];

/** The governed order of the work-order lifecycle, for the stepper. */
const STAGES: Array<{ status: RotationJobStatus; label: string; detail: string }> = [
  { status: 'requested', label: 'Requested', detail: 'A rotation obligation has been raised and recorded.' },
  { status: 'approved', label: 'Approved', detail: 'An owner has authorised the change.' },
  { status: 'in-progress', label: 'Executing', detail: 'The rotation is being carried out on the owning system.' },
  { status: 'awaiting-validation', label: 'Validating', detail: 'Rotation reported complete; post-rotation evidence outstanding.' },
  { status: 'completed', label: 'Completed', detail: 'Validated and closed, with a new key version recorded.' },
];

const ROTATION_STATES: RotationState[] = ['healthy', 'due', 'overdue', 'in-progress', 'failed', 'never-rotated', 'not-applicable', 'unknown'];

export default function QkmsRotation() {
  const { data, state, error, live, verifiedAt, refresh, reconnect } = useKeyRotation();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [jobFilter, setJobFilter] = useState('');
  const [validationDetail, setValidationDetail] = useState<Record<string, string>>({});

  // No default rotation filter: landing on an empty queue because nothing is
  // overdue hides the estate the operator came to look at. Highest risk first,
  // then filter down.
  const query = useKeyQuery({ limit: 25, sort: 'risk', dir: 'desc' }, data?.generatedAt ?? null);
  const actions = useQkmsActions(() => { void refresh(true); query.reload(); });
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const posture = data?.posture;
  const jobs = useMemo(
    () => (data?.jobs ?? []).filter((job) => !jobFilter || job.status === jobFilter),
    [data, jobFilter],
  );

  const stateRows = useMemo(
    () => ROTATION_STATES
      .map((rotationState) => ({
        label: ROTATION_LABEL[rotationState],
        state: rotationState,
        count: data?.stateCounts[rotationState] ?? 0,
      }))
      .filter((row) => row.count > 0),
    [data],
  );
  const stateTotal = stateRows.reduce((sum, row) => sum + row.count, 0);

  return (
    <QkmsShell
      icon={RefreshCw}
      title="Rotation"
      accent="Center"
      subtitle="Which keys owe a rotation, the governed work orders that carry them out, and the post-rotation evidence that proves each one actually happened."
      live={live}
      state={state}
      error={error}
      hasData={data?.hasData ?? false}
      generatedAt={data?.generatedAt ?? null}
      verifiedAt={verifiedAt}
      latestEvidenceAt={data?.latestEvidenceAt ?? null}
      telemetry={data?.telemetry ?? null}
      nav={data?.nav ?? null}
      onRefresh={() => { void refresh(true); query.reload(); }}
      onReconnect={reconnect}
      actions={<ExportMenu onExport={onExport} busy={exporter.busy} />}
    >
      <Notice notice={notice} onDismiss={dismiss} />

      {posture ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Kpi
            label="Rotation health"
            value={posture.healthPercent === null ? '—' : `${posture.healthPercent}%`}
            unmeasured={posture.healthPercent === null}
            detail={`${fmtNumber(posture.governedKeys)} key(s) have a determinable rotation state`}
            tone={(posture.healthPercent ?? 0) >= 80 ? 'good' : (posture.healthPercent ?? 0) >= 50 ? 'warning' : 'critical'}
            hint="The denominator excludes keys with no creation, rotation or expiry evidence. Counting them as healthy is how missing governance came to look like a clean result."
          />
          <Kpi
            label="Overdue"
            value={fmtNumber(posture.overdue)}
            detail={`${fmtNumber(posture.due)} due soon · ${fmtNumber(posture.neverRotated)} never rotated`}
            tone={posture.overdue > 0 ? 'critical' : 'good'}
          />
          <Kpi
            label="Work orders open"
            value={fmtNumber(posture.jobsActive)}
            detail={`${fmtNumber(posture.jobsCompleted)} completed · ${fmtNumber(posture.jobsFailed)} failed`}
            tone={posture.jobsActive > 0 ? 'info' : 'neutral'}
          />
          <Kpi
            label="Work-order success"
            value={posture.successRate === null ? '—' : `${posture.successRate}%`}
            unmeasured={posture.successRate === null}
            detail={posture.successRate === null ? 'No work order has terminated yet' : `of ${fmtNumber(posture.jobsCompleted + posture.jobsFailed)} terminated order(s)`}
            tone={(posture.successRate ?? 100) >= 90 ? 'good' : 'warning'}
          />
        </div>
      ) : null}

      {/* ---- State + blast radius ------------------------------------ */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel className="xl:col-span-2">
          <SectionLabel icon={Timer} hint="Every key's rotation state, from the one state machine that Lifecycle and Risk Analysis also read.">
            Rotation state
          </SectionLabel>
          {stateRows.length ? (
            <div className="space-y-0.5">
              {stateRows.map((row) => (
                <BarRow
                  key={row.state}
                  label={row.label}
                  count={row.count}
                  percent={stateTotal ? Math.round((row.count / stateTotal) * 100) : 0}
                  tone={
                    row.state === 'overdue' || row.state === 'failed' || row.state === 'blocked' ? 'critical'
                      : row.state === 'due' || row.state === 'never-rotated' ? 'warning'
                        : row.state === 'healthy' ? 'good' : 'neutral'
                  }
                  onClick={() => query.update({ rotation: row.state })}
                  title={`Filter the queue to ${row.label}`}
                />
              ))}
            </div>
          ) : <PanelEmpty>No rotation state has been determined for any key.</PanelEmpty>}

          {(data?.stateCounts.unknown ?? 0) > 0 ? (
            <ExplainBox tone="warning" title={`${fmtNumber(data!.stateCounts.unknown)} key(s) have no determinable rotation state`}>
              These keys carry no creation, rotation or expiry evidence, so there is nothing to measure a rotation obligation against.
              They are excluded from rotation health rather than counted as healthy. Bring them under QKMS governance to establish an interval.
            </ExplainBox>
          ) : null}
        </Panel>

        <Panel>
          <SectionLabel icon={Network} hint="Assets, certificates and jobs that a rotation of the current queue would touch.">
            Queue impact
          </SectionLabel>
          {posture ? (
            <div className="space-y-2">
              <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Keys in queue</div>
                <div className="mt-1 text-2xl font-black tabular-nums text-white">{fmtNumber(data?.queueTotal ?? 0)}</div>
              </div>
              <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Blast radius</div>
                <div className="mt-1 text-2xl font-black tabular-nums text-white">{fmtNumber(posture.blastRadius)}</div>
                <p className="mt-1 text-[10px] leading-snug text-white/40">
                  Dependent assets, certificates and migration jobs bound to the keys awaiting rotation.
                </p>
              </div>
              <div className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Next rotation due</div>
                <div className="mt-1 text-[13px] font-black text-white" title={absoluteTime(posture.nextDueAt)}>
                  {posture.nextDueAt ? whenRelative(posture.nextDueAt) : 'No interval established'}
                </div>
              </div>
            </div>
          ) : null}
        </Panel>
      </div>

      {/* ---- Queue --------------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={ClipboardList}
          meta={<span>{fmtNumber(query.page?.keys.length ?? 0)} shown · {fmtNumber(query.page?.total ?? 0)} match · highest risk first</span>}
          hint="Raising an order records the obligation, its owner, its blast radius and its evidence. It does not perform the cryptography."
        >
          Rotation queue
        </SectionLabel>

        <div className="mb-3 flex flex-wrap gap-2">
          <FilterSelect
            label="State"
            value={query.query.rotation || ''}
            onChange={(value) => query.update({ rotation: value as RotationState | '' })}
            options={[
              { value: '', label: 'All states' },
              ...ROTATION_STATES.map((rotationState) => ({ value: rotationState, label: ROTATION_LABEL[rotationState] })),
            ]}
          />
          <FilterSelect
            label="Risk"
            value={query.query.risk || ''}
            onChange={(value) => query.update({ risk: value })}
            options={[
              { value: '', label: 'Any risk' },
              ...['critical', 'high', 'medium', 'low', 'none'].map((value) => ({ value, label: value })),
            ]}
          />
        </div>

        <div className={query.loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
          <KeyTable
            keys={query.page?.keys ?? []}
            columns={COLUMNS}
            onSelect={setSelectedKey}
            selectedId={selectedKey}
            sort={query.query.sort}
            dir={query.query.dir}
            onSort={(sortKey) => query.update({ sort: sortKey, dir: query.query.sort === sortKey && query.query.dir === 'desc' ? 'asc' : 'desc' })}
            minWidth={1400}
            emptyMessage="No key matches this rotation filter."
            actions={(key) => (
              <ActionButton
                label="Raise order"
                icon={RefreshCw}
                tone="info"
                busy={actions.pending === `rotate:${key.id}`}
                onClick={async () => {
                  const result = await actions.requestRotation(key.id);
                  show(result.ok, result.message);
                }}
              />
            )}
          />
        </div>
        <Pager offset={query.query.offset ?? 0} limit={query.query.limit ?? 25} total={query.page?.total ?? 0} onChange={query.setOffset} />
      </Panel>

      {/* ---- Work orders --------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={ShieldCheck}
          meta={<span>{fmtNumber(jobs.length)} shown · {fmtNumber(data?.jobsTotal ?? 0)} total</span>}
          hint="Transitions are validated on the server. A work order cannot skip execution or validation."
        >
          Rotation work orders
        </SectionLabel>

        <div className="mb-3 flex flex-wrap gap-2">
          <FilterSelect
            label="Status"
            value={jobFilter}
            onChange={setJobFilter}
            options={[
              { value: '', label: 'All statuses' },
              ...STAGES.map((stage) => ({ value: stage.status, label: stage.label })),
              { value: 'failed', label: 'Failed' },
              { value: 'cancelled', label: 'Cancelled' },
            ]}
          />
        </div>

        {jobs.length ? (
          <ul className="space-y-2.5">
            {jobs.map((job) => {
              const stageIndex = STAGES.findIndex((stage) => stage.status === job.status);
              const terminalBad = job.status === 'failed' || job.status === 'cancelled';
              return (
                <li key={job.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <button
                        type="button"
                        onClick={() => job.keyId && setSelectedKey(job.keyId)}
                        disabled={!job.keyId}
                        className="truncate text-[12px] font-black text-cyan-300 hover:text-cyan-200 disabled:text-white/60"
                      >
                        {job.keyLabel}
                      </button>
                      <p className="mt-0.5 text-[10.5px] leading-snug text-white/45">{job.reason}</p>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                      <Pill tone={job.priority === 'critical' || job.priority === 'high' ? 'critical' : 'neutral'}>{job.priority}</Pill>
                      <JobStatusBadge status={job.status} />
                    </div>
                  </div>

                  {/* Stage tracker — reflects the persisted status only. */}
                  {!terminalBad ? (
                    <ol className="mt-2.5 flex flex-wrap gap-1">
                      {STAGES.map((stage, index) => {
                        const done = stageIndex >= 0 && index < stageIndex;
                        const current = stage.status === job.status;
                        return (
                          <li
                            key={stage.status}
                            title={stage.detail}
                            className={`flex items-center gap-1 rounded-md border px-2 py-1 text-[9.5px] font-black uppercase tracking-wider ${
                              current ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200'
                                : done ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300'
                                  : 'border-white/10 bg-black/20 text-white/30'
                            }`}
                          >
                            {done ? <CheckCircle2 className="h-3 w-3" aria-hidden="true" /> : null}
                            {stage.label}
                          </li>
                        );
                      })}
                    </ol>
                  ) : (
                    <div className="mt-2.5 flex items-center gap-2 rounded-md border border-red-500/25 bg-red-500/10 px-2.5 py-1.5 text-[10.5px] text-red-200">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                      {job.failureReason || (job.status === 'cancelled' ? 'Work order cancelled.' : 'Work order failed.')}
                    </div>
                  )}

                  <div className="mt-2 grid gap-2 text-[10.5px] text-white/45 sm:grid-cols-2 lg:grid-cols-4">
                    <span>Requested {relativeTime(job.requestedAt)}{job.requestedBy ? ` by ${job.requestedBy}` : ''}</span>
                    <span>{job.approvedBy ? `Approved by ${job.approvedBy}` : 'Not yet approved'}</span>
                    <span>
                      {job.previousVersion !== null ? `v${job.previousVersion}` : '—'}
                      {' → '}
                      {job.newVersion !== null ? `v${job.newVersion}` : '—'}
                    </span>
                    <span>{job.completedAt ? `Closed ${relativeTime(job.completedAt)}` : 'Open'}</span>
                  </div>

                  <div className={`mt-2 rounded-md border px-2.5 py-1.5 text-[10.5px] leading-snug ${
                    job.validationStatus === 'passed' ? 'border-emerald-400/25 bg-emerald-500/5 text-emerald-200/85'
                      : job.validationStatus === 'failed' ? 'border-red-500/25 bg-red-500/5 text-red-200/85'
                        : 'border-amber-400/25 bg-amber-500/5 text-amber-200/85'
                  }`}>
                    <span className="font-black uppercase tracking-wider">Validation: {job.validationStatus.replace(/-/g, ' ')}</span>
                    <span className="ml-1.5">{job.validationDetail}</span>
                  </div>

                  {job.allowedTransitions.length ? (
                    <div className="mt-2.5 space-y-2">
                      {job.allowedTransitions.includes('completed') ? (
                        <input
                          value={validationDetail[job.id] || ''}
                          onChange={(event) => setValidationDetail((current) => ({ ...current, [job.id]: event.target.value }))}
                          placeholder="Post-rotation validation evidence (required to close as validated)"
                          className="h-8 w-full rounded-md border border-white/12 bg-black/30 px-2.5 text-[11px] text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                        />
                      ) : null}
                      <div className="flex flex-wrap gap-1.5">
                        {job.allowedTransitions.map((target) => (
                          <ActionButton
                            key={target}
                            label={target.replace(/-/g, ' ')}
                            tone={target === 'failed' || target === 'cancelled' ? 'critical' : target === 'completed' ? 'good' : 'info'}
                            busy={actions.pending === `job:${job.id}`}
                            onClick={async () => {
                              const result = await actions.transitionJob(
                                job.id,
                                target,
                                target === 'completed' ? { validationDetail: validationDetail[job.id] || '' } : undefined,
                              );
                              show(result.ok, result.message);
                            }}
                          />
                        ))}
                      </div>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : (
          <PanelEmpty>
            {(data?.jobsTotal ?? 0) > 0
              ? 'No work order matches this status.'
              : 'No rotation work order has been raised. Select a key in the queue above and raise one to begin a governed rotation.'}
          </PanelEmpty>
        )}

        <ExplainBox tone="neutral" title="What a rotation work order is">
          QKMS holds key metadata, not key material. A work order records the rotation obligation, its approval, its execution and
          its post-rotation validation evidence — and mints a new key version when it closes as validated. It never reports a
          rotation this platform did not observe.
        </ExplainBox>
      </Panel>

      <KeyDrawer keyId={selectedKey} syncTo={data?.generatedAt ?? null} onClose={() => setSelectedKey(null)} onChanged={() => { void refresh(true); query.reload(); }} />
    </QkmsShell>
  );
}
