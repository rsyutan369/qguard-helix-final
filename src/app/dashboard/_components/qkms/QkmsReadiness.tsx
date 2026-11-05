'use client';

/**
 * PQC Key Readiness & Migration Gate.
 *
 * Two rules govern everything on this page:
 *
 *  1. Readiness is EVIDENCE-driven. A key counts as ready when its observed
 *     material is post-quantum or hybrid — never because a PQC algorithm is
 *     merely available to it.
 *
 *  2. Not-applicable is not zero. An estate with no signature keys has no
 *     ML-DSA readiness; it does not have 0% ML-DSA readiness. Every band
 *     carries its own denominator and renders "Not applicable" when that
 *     denominator is empty.
 *
 * The gate implements all six states of the brief, and each decision states
 * why, what evidence supports it, what blocks it, and what to do next.
 */

import { useCallback, useState } from 'react';
import { FileClock, Layers, Radar, ShieldCheck, Sparkles } from 'lucide-react';
import { usePqcKeyReadiness, useKeyQuery, useQkmsActions } from '@/hooks/use-qkms';
import type { GatePrecheck, MigrationGateState } from '@/lib/qkms/types';
import { KeyDrawer } from './KeyDrawer';
import { GateField, MeasuredBar, MeasuredGauge } from './motion';
import {
  ActionButton,
  BarRow,
  distributionTone,
  gateTone,
  ExplainBox,
  ExportMenu,
  GateBadge,
  KeyTable,
  Kpi,
  Measured,
  Notice,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  QkmsShell,
  SectionLabel,
  TONE,
  fmtNumber,
  relativeTime,
  useNotice,
  useQkmsExport,
  type KeyColumn,
} from './shell';

const COLUMNS: KeyColumn[] = [
  'key', 'algorithm', 'type', 'owner', 'asset', 'environment',
  'posture', 'requirement', 'lifecycle', 'custody', 'risk',
];

const GATE_MEANING: Record<MigrationGateState, string> = {
  BLOCKED: 'A hard precondition fails. Migrating over it would carry the defect forward into the migrated estate.',
  NOT_READY: 'No hard blocker remains, but prerequisites are outstanding — ownership, custody or rotation posture is not yet provable.',
  READY: 'Every precheck passes. The estate can begin its post-quantum migration.',
  MIGRATION_IN_PROGRESS: 'Migration or rotation work is open against this key estate. The gate stays open while that work completes.',
  MIGRATED: 'Everything that required migration is post-quantum or hybrid, every precheck passes, and the change is evidenced.',
  VALIDATION_REQUIRED: 'Migration completed but its evidence is incomplete. A migration is not proven until it is validated.',
};

const DECISION_TONE = {
  pass: 'good',
  warn: 'warning',
  block: 'critical',
  'not-evaluated': 'neutral',
} as const;

export default function QkmsReadiness() {
  const { data, state, error, live, verifiedAt, refresh, reconnect } = usePqcKeyReadiness();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [precheckFilter, setPrecheckFilter] = useState<GatePrecheck | null>(null);

  const query = useKeyQuery({ limit: 25, sort: 'risk', dir: 'desc', requirement: 'required' }, data?.generatedAt ?? null);
  const actions = useQkmsActions(() => { void refresh(true); query.reload(); });
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const readiness = data?.readiness;
  const gate = readiness?.gate;
  const metrics = data?.metrics;

  return (
    <QkmsShell
      icon={ShieldCheck}
      title="PQC Key"
      accent="Readiness"
      subtitle="Which key material is already post-quantum, which still has to move, and whether the estate can pass the migration gate — measured from observed algorithms, never from availability."
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
      actions={
        <>
          <ActionButton
            label="Run precheck"
            icon={Radar}
            tone="info"
            busy={actions.pending === 'precheck'}
            onClick={async () => {
              const result = await actions.runPrecheck();
              show(result.ok, result.message);
            }}
          />
          <ExportMenu onExport={onExport} busy={exporter.busy} />
        </>
      }
    >
      <Notice notice={notice} onDismiss={dismiss} />

      {/* ---- The gate ------------------------------------------------ */}
      {gate ? (
        <Panel>
          <GateField tone={gateTone(gate.state)} live={live} />
          <div className="relative">
          <SectionLabel
            icon={ShieldCheck}
            meta={gate.score !== null ? <span>{gate.score}% of prechecks pass · evaluated {relativeTime(gate.evaluatedAt)}</span> : undefined}
            hint="Six states, each with its own evidence requirement. The gate is a decision an auditor can follow, not a score."
          >
            Migration gate
          </SectionLabel>

          <div className="flex flex-wrap items-center gap-4">
            <MeasuredGauge value={gate.score} tone={gateTone(gate.state)} label="Prechecks" />
            <div className="min-w-0 flex-1">
              <GateBadge state={gate.state} />
              <p className="mt-2 text-[12.5px] font-semibold leading-relaxed text-white/80">{gate.why}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-white/45">{GATE_MEANING[gate.state]}</p>
            </div>
          </div>

          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <div>
              <h3 className="text-[9px] font-black uppercase tracking-wider text-red-300/80">Blocking</h3>
              {gate.blockers.length ? (
                <ul className="mt-1.5 space-y-1">
                  {gate.blockers.map((blocker) => (
                    <li key={blocker} className="rounded-md border border-red-500/20 bg-red-500/5 px-2.5 py-1.5 text-[11px] leading-snug text-red-200/85">
                      {blocker}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1.5 rounded-md border border-emerald-400/20 bg-emerald-500/5 px-2.5 py-1.5 text-[11px] text-emerald-200/85">
                  Nothing is blocking the gate.
                </p>
              )}
            </div>

            <div>
              <h3 className="text-[9px] font-black uppercase tracking-wider text-white/35">Required to proceed</h3>
              {gate.requiredActions.length ? (
                <ol className="mt-1.5 space-y-1">
                  {gate.requiredActions.map((action, index) => (
                    <li key={action} className="flex gap-2 rounded-md border border-white/10 bg-black/25 px-2.5 py-1.5 text-[11px] leading-snug text-white/65">
                      <span className="font-mono text-cyan-300">{index + 1}.</span>
                      {action}
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="mt-1.5 rounded-md border border-white/10 bg-black/25 px-2.5 py-1.5 text-[11px] text-white/50">
                  No action is outstanding.
                </p>
              )}
            </div>
          </div>

          {gate.evidence.length ? (
            <div className="mt-3">
              <h3 className="text-[9px] font-black uppercase tracking-wider text-white/35">Supporting evidence</h3>
              <ul className="mt-1.5 flex flex-wrap gap-1.5">
                {gate.evidence.map((ref, index) => (
                  <li key={`${ref.table}-${ref.recordId}-${index}`} className="rounded-md border border-white/10 bg-black/25 px-2 py-1 font-mono text-[9.5px] text-white/45" title={ref.detail}>
                    {ref.table}:{ref.recordId.slice(0, 10)} · {relativeTime(ref.observedAt)}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          </div>
        </Panel>
      ) : null}

      {/* ---- KPIs ---------------------------------------------------- */}
      {metrics && readiness ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Kpi
            label="Overall readiness"
            value={readiness.overall === null ? '—' : `${readiness.overall}%`}
            unmeasured={readiness.overall === null}
            detail={readiness.decisionScope
              ? `${fmtNumber(readiness.verifiedReady)} of ${fmtNumber(readiness.decisionScope)} key(s) needing a quantum decision are evidenced PQC or hybrid`
              : 'No key needs a post-quantum decision'}
            tone={(readiness.overall ?? 0) >= 80 ? 'good' : 'warning'}
            hint="Symmetric and hash keys are excluded from the denominator: they were never at Shor risk, and including them would inflate readiness with material that never had to move."
          />
          <Kpi
            label="Post-quantum keys"
            value={fmtNumber(metrics.pqcReadyKeys)}
            detail={`${fmtNumber(metrics.hybridKeys)} additional hybrid composite(s)${metrics.declaredPqcKeys ? ` · ${fmtNumber(metrics.declaredPqcKeys)} declared, unverified` : ''}`}
            tone="good"
            hint="Counted only when a scan, certificate or this platform's key generation evidences the algorithm. Registry declarations alone are listed as unverified and excluded from readiness."
          />
          <Kpi
            label="Migration required"
            value={fmtNumber(metrics.keysRequiringMigration)}
            detail={`${fmtNumber(metrics.quantumVulnerableKeys)} quantum-vulnerable · ${fmtNumber(metrics.deprecatedKeys)} deprecated`}
            tone={metrics.keysRequiringMigration > 0 ? 'warning' : 'good'}
          />
          <Kpi
            label="Audit evidence"
            value={fmtNumber(metrics.auditEvidenceRecords)}
            detail="Records available to evidence the migration"
            tone={metrics.auditEvidenceRecords > 0 ? 'good' : 'warning'}
          />
        </div>
      ) : null}

      {/* ---- Readiness bands ----------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Sparkles}
          hint="Each band has its own denominator. A band with no applicable key reads 'Not applicable' — never 0%."
        >
          Readiness by algorithm family
        </SectionLabel>
        {readiness?.bands.length ? (
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {readiness.bands.map((band) => {
              const notApplicable = band.applicable === 0;
              const tone = notApplicable ? 'neutral' : (band.percent ?? 0) >= 80 ? 'good' : (band.percent ?? 0) >= 40 ? 'warning' : 'critical';
              return (
                <div key={band.key} className={`rounded-lg border p-3 ${TONE[tone].border} ${TONE[tone].soft}`}>
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="text-[11px] font-black uppercase tracking-wider text-white">{band.label}</h3>
                    <span className={`shrink-0 font-mono text-lg font-black tabular-nums ${TONE[tone].text}`}>
                      <Measured value={band.percent} fallback="N/A" />
                    </span>
                  </div>
                  {!notApplicable ? (
                    <div className="mt-2"><MeasuredBar percent={band.percent ?? 0} tone={tone} /></div>
                  ) : null}
                  <p className="mt-2 text-[10.5px] leading-snug text-white/50">{band.detail}</p>
                  {!notApplicable ? (
                    <p className="mt-1 font-mono text-[9.5px] text-white/30">
                      {band.ready} evidenced ready / {band.applicable} applicable
                      {band.declared ? <span className="ml-1 text-amber-300" title="PQC by registry declaration only — no scan or certificate confirms it, so it is not counted ready.">· {band.declared} declared, unverified</span> : null}
                    </p>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : <PanelEmpty>No readiness band applies to this estate yet.</PanelEmpty>}
      </Panel>

      {/* ---- Prechecks ----------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Layers}
          meta={precheckFilter ? <button type="button" onClick={() => { setPrecheckFilter(null); query.update({ ids: '', requirement: 'required' }); }} className="text-cyan-300 hover:text-cyan-200">Clear</button> : undefined}
        >
          Gate prechecks
        </SectionLabel>
        {gate?.prechecks.length ? (
          <ul className="space-y-1.5">
            {gate.prechecks.map((precheck) => {
              const tone = DECISION_TONE[precheck.decision];
              const selectable = precheck.keyIds.length > 0;
              return (
                <li key={precheck.id}>
                  <button
                    type="button"
                    disabled={!selectable}
                    onClick={() => {
                      setPrecheckFilter(precheck);
                      query.update({ ids: precheck.keyIds.join(','), requirement: '' });
                    }}
                    className={`w-full rounded-lg border p-3 text-left transition disabled:cursor-default ${TONE[tone].border} ${TONE[tone].soft} ${selectable ? 'hover:brightness-125' : ''} ${precheckFilter?.id === precheck.id ? 'ring-2 ring-cyan-300/60' : ''}`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[11.5px] font-black text-white">{precheck.label}</span>
                      <div className="flex items-center gap-2">
                        {precheck.count > 0 ? <span className="font-mono text-[10.5px] tabular-nums text-white/50">{fmtNumber(precheck.count)}</span> : null}
                        <Pill tone={tone}>{precheck.decision.replace(/-/g, ' ')}</Pill>
                      </div>
                    </div>
                    <p className="mt-1.5 text-[11px] leading-snug text-white/60">{precheck.detail}</p>
                    {precheck.requiredAction ? (
                      <p className="mt-1 text-[10.5px] leading-snug text-cyan-300/80">{precheck.requiredAction}</p>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        ) : <PanelEmpty>No precheck could be evaluated.</PanelEmpty>}
      </Panel>

      {/* ---- Keys requiring migration -------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Sparkles}
          meta={<span>{fmtNumber(query.page?.keys.length ?? 0)} shown · {fmtNumber(query.page?.total ?? 0)} match</span>}
        >
          {precheckFilter ? `Keys failing: ${precheckFilter.label}` : 'Keys requiring migration'}
        </SectionLabel>
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
            emptyMessage={
              precheckFilter
                ? 'No key fails this precheck.'
                : 'No key currently requires a post-quantum migration.'
            }
          />
        </div>
        <Pager offset={query.query.offset ?? 0} limit={query.query.limit ?? 25} total={query.page?.total ?? 0} onChange={query.setOffset} />
      </Panel>

      {/* ---- Posture distribution + evidence ------------------------- */}
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel>
          <SectionLabel icon={Layers}>Posture distribution</SectionLabel>
          {data?.distributions.postures.length ? (
            <div className="space-y-0.5">
              {data.distributions.postures.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={distributionTone(row)}
                />
              ))}
            </div>
          ) : <PanelEmpty>No key posture has been classified.</PanelEmpty>}

          <ExplainBox tone="neutral" title="How posture is decided">
            Classification runs on the algorithm alone, through the platform&rsquo;s shared cipher decomposer. Symmetric and hash
            primitives are scored on Grover, asymmetric primitives on Shor — a 256-bit symmetric key is never reported as a
            quantum vulnerability, and ML-DSA is never reported as deprecated.
          </ExplainBox>
        </Panel>

        <Panel>
          <SectionLabel icon={FileClock} meta={<span>{fmtNumber(data?.audit.length ?? 0)}</span>}>
            Migration audit evidence
          </SectionLabel>
          {data?.audit.length ? (
            <ol className="space-y-1.5">
              {data.audit.map((entry) => (
                <li key={entry.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-[10px] text-cyan-300">{entry.eventType}</span>
                    <span className="font-mono text-[9.5px] text-white/35">{relativeTime(entry.at)}</span>
                  </div>
                  <p className="mt-1 truncate text-[11px] text-white/65" title={entry.title}>{entry.title}</p>
                  {entry.keyLabel ? (
                    <button type="button" onClick={() => entry.keyId && setSelectedKey(entry.keyId)} className="mt-0.5 truncate text-[9.5px] text-white/35 hover:text-cyan-300">
                      {entry.keyLabel}
                    </button>
                  ) : null}
                </li>
              ))}
            </ol>
          ) : (
            <PanelEmpty>
              No audit evidence exists yet. The gate cannot report MIGRATED without it — a migration is not proven until it is evidenced.
            </PanelEmpty>
          )}
        </Panel>
      </div>

      <KeyDrawer keyId={selectedKey} syncTo={data?.generatedAt ?? null} onClose={() => setSelectedKey(null)} onChanged={() => { void refresh(true); query.reload(); }} />
    </QkmsShell>
  );
}
