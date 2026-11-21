'use client';

/**
 * Regulatory Mapping.
 *
 * The control-mapping engine: every framework, its requirements, the platform
 * controls that satisfy them, and the evidence behind each status —
 *
 *   Regulation → Requirement → Control → Asset → Finding → Evidence
 *
 * Frameworks and requirements come from a declarative catalog
 * (src/lib/governance/catalog.ts). Adding a framework is a data change there —
 * no page here changes. What is NEVER hardcoded is the RESULT: a framework's
 * score is always an evaluation of tenant evidence, and a framework with no
 * measurable control reads "Not assessed" rather than borrowing another
 * framework's number.
 */

import { useMemo, useState } from 'react';
import {
  BookMarked,
  Building2,
  FileCheck2,
  Landmark,
  RefreshCw,
  Scale,
  Search,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  FilterSelect,
  Pager,
  SearchInput,
  SectionLabel,
  TableShell,
  Td,
  Th,
} from '../_components/observability/primitives';
import {
  Basis,
  ConnectionChip,
  CountTile,
  CoverageBar,
  FilterBar,
  FreshnessChip,
  GapCard,
  GOV_SHELL_CLASS,
  GOV_SHELL_CSS,
  GovernanceError,
  GovernanceHeader,
  GovernanceModuleNav,
  GovernanceProvenance,
  GovernanceSkeleton,
  NoEvidenceState,
  NoMatches,
  Panel,
  PanelEmpty,
  Pill,
  ReconciliationPanel,
  ScoreSkeleton,
  ScoreTile,
  StaleBanner,
  StatusBadge,
  TONE,
  fmtNumber,
  relativeTime,
  riseStyle,
  scoreCell,
} from '../_components/governance/primitives';
import { GovernanceDrawers, type DrawerTarget } from '../_components/governance/drawers';
import {
  useGovernanceFilters,
  useGovernancePagedResource,
  useRegulatoryMapping,
  type ControlSummary,
} from '@/hooks/use-governance';
import type { EvidenceRecord, GovernanceGap, RequirementRecord } from '@/lib/governance/types';

const CATEGORY_LABEL: Record<string, string> = {
  standard: 'Standard',
  regulation: 'Regulation',
  certification: 'Certification',
  directive: 'Directive',
};

export default function RegulatoryMapping() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useRegulatoryMapping();
  const { filters, setFilter, reset, activeCount } = useGovernanceFilters();
  const [target, setTarget] = useState<DrawerTarget>(null);
  const [requirementOffset, setRequirementOffset] = useState(0);
  const [controlOffset, setControlOffset] = useState(0);
  const [evidenceOffset, setEvidenceOffset] = useState(0);

  const requirements = useGovernancePagedResource<RequirementRecord>(
    'regulatory',
    '/requirements',
    'requirements',
    { limit: 25, offset: requirementOffset, search: filters.search, framework: filters.framework, status: filters.status },
    revision,
  );

  const controls = useGovernancePagedResource<ControlSummary>(
    'regulatory',
    '/controls',
    'controls',
    { limit: 20, offset: controlOffset, search: filters.search, framework: filters.framework, status: filters.status, domain: filters.domain },
    revision,
  );

  const evidence = useGovernancePagedResource<EvidenceRecord>(
    'regulatory',
    '/evidence',
    'evidence',
    { limit: 20, offset: evidenceOffset, search: filters.search, framework: filters.framework, kind: 'attestation' },
    revision,
  );

  const gaps = useGovernancePagedResource<GovernanceGap>(
    'regulatory',
    '/gaps',
    'gaps',
    { limit: 8, offset: 0, framework: filters.framework, severity: filters.severity },
    revision,
  );

  const frameworkOptions = useMemo(
    () => [
      { value: 'all', label: 'All frameworks' },
      ...(data?.frameworks ?? []).map((framework) => ({ value: framework.id, label: framework.shortName })),
    ],
    [data?.frameworks],
  );
  const domainOptions = useMemo(
    () => [
      { value: 'all', label: 'All domains' },
      ...(data?.facets.domains ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.domains],
  );

  const selectedFramework = useMemo(
    () => (filters.framework !== 'all' ? data?.frameworks.find((framework) => framework.id === filters.framework) ?? null : null),
    [data?.frameworks, filters.framework],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Landmark} title="Regulatory" accent="Mapping" subtitle="Mapping your evidence onto framework requirements…" />
        <ScoreSkeleton count={4} />
        <GovernanceSkeleton rows={5} height={64} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Landmark} title="Regulatory" accent="Mapping" subtitle="Frameworks, requirements and their control coverage." />
        <GovernanceError message={error || 'The governance model could not be computed.'} onRetry={reconnect} />
      </div>
    );
  }

  if (!data) return null;

  const { scores, totals } = data;
  const measuredFrameworks = data.frameworks.filter((framework) => framework.measured);
  const attestedFrameworks = data.frameworks.filter((framework) => framework.attestedEvidenceCount > 0);

  return (
    <div className={GOV_SHELL_CLASS}>
      <style>{GOV_SHELL_CSS}</style>

      <GovernanceHeader
        icon={Landmark}
        title="Regulatory"
        accent="Mapping"
        subtitle="Regulation → requirement → control → asset → finding → evidence, for every framework in scope. Statuses are evaluated from your own evidence — a framework with nothing measurable reads “Not assessed”, never a borrowed score."
        right={
          <>
            <ConnectionChip live={live} lastSyncedAt={lastSyncedAt} onReconnect={reconnect} />
            <button
              type="button"
              onClick={() => setTarget({ kind: 'reconciliation' })}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
            >
              <Scale className="h-3 w-3" aria-hidden="true" /> Reconcile
            </button>
            <button
              type="button"
              onClick={() => void refresh(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
            >
              <RefreshCw className="h-3 w-3" aria-hidden="true" /> Refresh
            </button>
          </>
        }
      />

      <GovernanceModuleNav />

      {error ? <GovernanceError message={error} onRetry={reconnect} /> : null}
      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void refresh(true)} /> : null}

      {(data.telemetry.absentSources.length > 0 || data.telemetry.truncated) && (
        <div role="status" className="rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg-strong)] px-4 py-3 text-sm">
          <strong>Evidence coverage is limited.</strong> Review the source coverage below before interpreting these results.
        </div>
      )}

      {!data.hasData && data.telemetry.absentSources.length === 0 ? (
        <NoEvidenceState
          title="No evidence to map yet"
          detail="The framework catalog is loaded and every requirement is mapped to platform controls. Those controls have nothing to evaluate until your estate is discovered."
          actions={[
            { label: 'Run a discovery scan', href: '/dashboard/scanner', primary: true },
            { label: 'Open compliance', href: '/dashboard/compliance' },
          ]}
        />
      ) : null}

      {/* ---- Scores ---------------------------------------------------- */}
      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
        <ScoreTile score={scores.compliance} />
        <ScoreTile score={scores.controlCoverage} />
        <ScoreTile score={scores.evidenceCoverage} />
        <ScoreTile score={scores.evidenceFreshness} />
      </section>

      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <CountTile label="Frameworks" value={totals.frameworks} detail={`${measuredFrameworks.length} assessable`} tone="neutral" hint="Frameworks in the catalog. “Assessable” means at least one of their controls has tenant evidence." />
        <CountTile label="Requirements" value={totals.requirements} tone="neutral" hint="Framework requirements mapped to platform controls." />
        <CountTile label="Controls" value={totals.controls} detail={`${totals.controlsMeasured} measured`} tone="neutral" hint="Platform controls in the catalog and how many could be evaluated." />
        <CountTile
          label="Failing controls"
          value={totals.controlsFailing}
          tone={totals.controlsFailing > 0 ? 'critical' : 'good'}
          onOpen={() => { setFilter('status', 'non-compliant'); setControlOffset(0); }}
          hint="Controls where every in-scope subject fails. Click to filter."
        />
        <CountTile
          label="Missing evidence"
          value={totals.controlsUnassessed}
          tone="neutral"
          onOpen={() => { setFilter('status', 'not-assessed'); setRequirementOffset(0); setControlOffset(0); }}
          hint="Controls with no tenant evidence. Connect the source to bring the requirements they serve into scope."
        />
        <CountTile
          label="Stored attestations"
          value={data.evidence.length ? evidence.total || data.evidence.length : 0}
          detail={`${attestedFrameworks.length} framework${attestedFrameworks.length === 1 ? '' : 's'} attested`}
          tone={attestedFrameworks.length > 0 ? 'good' : 'warning'}
          hint="Evidence rows your tenant recorded naming a framework — as distinct from evidence the platform derived."
        />
      </section>

      {/* ---- Framework cards -------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={BookMarked}
          meta={`${data.frameworks.length} frameworks`}
          hint="Each card shows compliance over the framework's measurable controls, and separately how much of it is measurable at all. Both matter: 100% over two of forty requirements is not compliance."
        >
          Framework coverage
        </SectionLabel>
        <div className="grid gap-2.5 md:grid-cols-2 xl:grid-cols-3">
          {data.frameworks.map((framework, index) => (
            <button
              key={framework.id}
              type="button"
              onClick={() => setTarget({ kind: 'framework', id: framework.id })}
              style={riseStyle(index)}
              className="gov-rise rounded-xl border border-white/10 bg-white/[0.02] p-3.5 text-left transition hover:border-white/25 hover:bg-white/[0.05]"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="truncate text-[12.5px] font-bold text-white">{framework.shortName}</h3>
                  <p className="mt-0.5 truncate text-[9.5px] font-semibold uppercase tracking-wider text-white/35">
                    {framework.authority} · {CATEGORY_LABEL[framework.category] || framework.category}
                  </p>
                </div>
                <div className="shrink-0 text-right">{scoreCell(framework.score, framework.measured)}</div>
              </div>

              <div className="mt-2.5 flex h-1.5 overflow-hidden rounded-full bg-white/8">
                {framework.requirementsCompliant > 0 ? (
                  <span style={{ width: `${(framework.requirementsCompliant / framework.requirementsTotal) * 100}%`, backgroundColor: TONE.good.hex }} />
                ) : null}
                {framework.requirementsPartial > 0 ? (
                  <span style={{ width: `${(framework.requirementsPartial / framework.requirementsTotal) * 100}%`, backgroundColor: TONE.warning.hex }} />
                ) : null}
                {framework.requirementsFailing > 0 ? (
                  <span style={{ width: `${(framework.requirementsFailing / framework.requirementsTotal) * 100}%`, backgroundColor: TONE.critical.hex }} />
                ) : null}
                {framework.requirementsUnassessed > 0 ? (
                  <span style={{ width: `${(framework.requirementsUnassessed / framework.requirementsTotal) * 100}%`, backgroundColor: TONE.neutral.hex }} />
                ) : null}
              </div>

              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <StatusBadge status={framework.status} size="sm" />
                <Pill tone="neutral" title="Requirements the platform can assess with today's evidence.">
                  {framework.coverage}% assessable
                </Pill>
                {framework.attestedEvidenceCount > 0 ? (
                  <Pill tone="info" title={`${framework.attestedEvidenceCount} stored attestation(s) name this framework.`}>
                    {framework.attestedEvidenceCount} attested
                  </Pill>
                ) : null}
              </div>

              <dl className="mt-2 grid grid-cols-4 gap-1.5 text-center">
                {[
                  { label: 'OK', value: framework.requirementsCompliant, tone: 'good' as const },
                  { label: 'Partial', value: framework.requirementsPartial, tone: 'warning' as const },
                  { label: 'Fail', value: framework.requirementsFailing, tone: 'critical' as const },
                  { label: 'N/A', value: framework.requirementsUnassessed, tone: 'neutral' as const },
                ].map((entry) => (
                  <div key={entry.label} className="rounded-md border border-white/[0.06] bg-black/20 py-1">
                    <dd className={cn('font-mono text-[12px] font-black tabular-nums', TONE[entry.tone].text)}>{entry.value}</dd>
                    <dt className="text-[8.5px] font-black uppercase tracking-wider text-white/30">{entry.label}</dt>
                  </div>
                ))}
              </dl>

              <p className="mt-2 text-[9.5px] text-white/30">Last validated {relativeTime(framework.lastValidatedAt)}</p>
            </button>
          ))}
        </div>
        <Basis>
          Requirement wording is paraphrased for this platform; each framework card links to its authoritative reference.
          Adding a framework is a catalog change — this page needs no modification to render it.
        </Basis>
      </Panel>

      {/* ---- Filters --------------------------------------------------- */}
      <FilterBar activeCount={activeCount} onReset={() => { reset(); setRequirementOffset(0); setControlOffset(0); setEvidenceOffset(0); }}>
        <SearchInput
          value={filters.search}
          onChange={(value) => { setFilter('search', value); setRequirementOffset(0); setControlOffset(0); }}
          placeholder="Search requirements, controls, attestations…"
        />
        <FilterSelect label="Framework" value={filters.framework} onChange={(value) => { setFilter('framework', value); setRequirementOffset(0); setControlOffset(0); setEvidenceOffset(0); }} options={frameworkOptions} />
        <FilterSelect
          label="Status"
          value={filters.status}
          onChange={(value) => { setFilter('status', value); setRequirementOffset(0); setControlOffset(0); }}
          options={[
            { value: 'all', label: 'All statuses' },
            { value: 'non-compliant', label: 'Non-compliant' },
            { value: 'partial', label: 'Partially compliant' },
            { value: 'compliant', label: 'Compliant' },
            { value: 'not-assessed', label: 'Not assessed' },
          ]}
        />
        <FilterSelect label="Domain" value={filters.domain} onChange={(value) => { setFilter('domain', value); setControlOffset(0); }} options={domainOptions} />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          onChange={(value) => setFilter('severity', value)}
          options={[
            { value: 'all', label: 'Any severity' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
      </FilterBar>

      {selectedFramework ? (
        <Panel>
          <SectionLabel icon={Building2} meta={selectedFramework.version} hint="Scope of the currently filtered framework.">
            {selectedFramework.name}
          </SectionLabel>
          <p className="text-[11.5px] leading-relaxed text-white/55">{selectedFramework.scope}</p>
          <CoverageBar
            compliant={selectedFramework.requirementsCompliant}
            partial={selectedFramework.requirementsPartial}
            failing={selectedFramework.requirementsFailing}
            unassessed={selectedFramework.requirementsUnassessed}
            onSegment={(status) => { setFilter('status', status); setRequirementOffset(0); }}
          />
        </Panel>
      ) : null}

      {/* ---- Requirement mapping --------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={FileCheck2}
          meta={requirements.total ? `${fmtNumber(requirements.total)} requirements` : undefined}
          hint="Every requirement, the controls that satisfy it, and how many of those controls could be measured. Click a row to walk down to its controls and evidence."
        >
          Requirement mapping
        </SectionLabel>
        {requirements.error ? <GovernanceError message={requirements.error} onRetry={requirements.retry} /> : requirements.loading && !requirements.rows.length ? (
          <GovernanceSkeleton rows={5} height={40} />
        ) : requirements.rows.length ? (
          <>
            <TableShell minWidth={1000}>
              <thead>
                <tr>
                  <Th>Requirement</Th>
                  <Th>Framework</Th>
                  <Th align="right">Score</Th>
                  <Th>Status</Th>
                  <Th align="right">Controls</Th>
                  <Th align="right">Evidence</Th>
                  <Th>Validated</Th>
                </tr>
              </thead>
              <tbody>
                {requirements.rows.map((requirement) => {
                  const framework = data.frameworks.find((entry) => entry.id === requirement.frameworkId);
                  return (
                    <tr
                      key={requirement.id}
                      onClick={() => setTarget({ kind: 'requirement', id: requirement.id })}
                      className="cursor-pointer transition hover:bg-white/[0.03]"
                    >
                      <Td>
                        <div className="font-mono text-[9.5px] text-cyan-300/70">{requirement.code}</div>
                        <div className="font-semibold text-white/85">{requirement.title}</div>
                        <div className="mt-0.5 line-clamp-1 text-[10px] text-white/35">{requirement.summary}</div>
                      </Td>
                      <Td className="text-white/55">{framework?.shortName || requirement.frameworkId}</Td>
                      <Td align="right">{scoreCell(requirement.score, requirement.measured)}</Td>
                      <Td>
                        <StatusBadge status={requirement.status} size="sm" />
                      </Td>
                      <Td align="right" className="font-mono tabular-nums text-white/60">
                        {requirement.controlsMeasured}/{requirement.controlsTotal}
                        {requirement.controlsFailing > 0 ? <span className="ml-1 text-red-300">({requirement.controlsFailing} fail)</span> : null}
                      </Td>
                      <Td align="right" className="font-mono tabular-nums text-white/50">
                        {requirement.evidenceCount || '—'}
                      </Td>
                      <Td>
                        <FreshnessChip state={requirement.evidenceFreshness} />
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </TableShell>
            <Pager offset={requirementOffset} limit={25} total={requirements.total} onChange={setRequirementOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No requirements in scope.</PanelEmpty>
        )}
        <Basis>
          A requirement is scored over the controls that could be measured for it. Where controls are unmeasured, the count
          column says so rather than the score silently absorbing them.
        </Basis>
      </Panel>

      {/* ---- Control mapping -------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Search}
          meta={controls.total ? `${fmtNumber(controls.total)} controls` : undefined}
          hint="Platform controls and how many framework requirements each one serves. One control failing can move several frameworks at once."
        >
          Control mapping
        </SectionLabel>
        {controls.error ? <GovernanceError message={controls.error} onRetry={controls.retry} /> : controls.loading && !controls.rows.length ? (
          <GovernanceSkeleton rows={5} height={38} />
        ) : controls.rows.length ? (
          <>
            <TableShell minWidth={900}>
              <thead>
                <tr>
                  <Th>Control</Th>
                  <Th align="right">Score</Th>
                  <Th>Status</Th>
                  <Th align="right">Requirements</Th>
                  <Th align="right">Frameworks</Th>
                  <Th align="right">Failing / scope</Th>
                  <Th>Evidence</Th>
                </tr>
              </thead>
              <tbody>
                {controls.rows.map((control) => (
                  <tr key={control.id} onClick={() => setTarget({ kind: 'control', id: control.id })} className="cursor-pointer transition hover:bg-white/[0.03]">
                    <Td>
                      <div className="font-mono text-[9.5px] text-cyan-300/70">{control.code}</div>
                      <div className="font-semibold text-white/85">{control.title}</div>
                    </Td>
                    <Td align="right">{scoreCell(control.score, control.measured)}</Td>
                    <Td>
                      <StatusBadge status={control.status} size="sm" />
                    </Td>
                    <Td align="right" className="font-mono tabular-nums text-white/60">{control.requirementIds.length}</Td>
                    <Td align="right" className="font-mono tabular-nums text-white/60">{control.frameworkIds.length}</Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {control.measured ? (
                        <span className={control.failing > 0 ? 'text-red-300' : 'text-emerald-300'}>
                          {fmtNumber(control.failing)} / {fmtNumber(control.population)}
                        </span>
                      ) : (
                        <span className="text-white/25">—</span>
                      )}
                    </Td>
                    <Td>
                      <FreshnessChip state={control.evidenceFreshness} ageDays={control.evidenceAgeDays} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={controlOffset} limit={20} total={controls.total} onChange={setControlOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No controls in scope.</PanelEmpty>
        )}
      </Panel>

      {/* ---- Attestations ------------------------------------------------ */}
      <Panel>
        <SectionLabel
          icon={FileCheck2}
          meta={evidence.total ? `${fmtNumber(evidence.total)} attestations` : undefined}
          href="/dashboard/audit-vault"
          hint="Evidence your tenant recorded against a named framework control — as distinct from evidence the platform derived from scans and telemetry."
        >
          Stored attestations
        </SectionLabel>
        {evidence.error ? <GovernanceError message={evidence.error} onRetry={evidence.retry} /> : evidence.loading && !evidence.rows.length ? (
          <GovernanceSkeleton rows={4} height={38} />
        ) : evidence.rows.length ? (
          <>
            <TableShell minWidth={880}>
              <thead>
                <tr>
                  <Th>Attestation</Th>
                  <Th>Status on record</Th>
                  <Th>Asset</Th>
                  <Th>Outcome</Th>
                  <Th>Recorded</Th>
                  <Th>Freshness</Th>
                </tr>
              </thead>
              <tbody>
                {evidence.rows.map((record) => (
                  <tr key={record.id} onClick={() => setTarget({ kind: 'evidence', id: record.id })} className="cursor-pointer transition hover:bg-white/[0.03]">
                    <Td>
                      <div className="font-semibold text-white/85">{record.title}</div>
                      <div className="line-clamp-1 text-[10px] text-white/35">{record.description}</div>
                    </Td>
                    <Td className="text-white/55">{record.statusLabel || '—'}</Td>
                    <Td className={record.assetName ? 'text-white/60' : 'text-white/25'}>{record.assetName || '—'}</Td>
                    <Td>
                      <Pill tone={record.outcome === 'contradicting' ? 'critical' : record.outcome === 'supporting' ? 'good' : 'neutral'}>
                        {record.outcome === 'contradicting' ? 'Contradicts' : record.outcome === 'supporting' ? 'Supports' : 'Info'}
                      </Pill>
                    </Td>
                    <Td className="font-mono text-[10px] text-white/45">{relativeTime(record.occurredAt)}</Td>
                    <Td>
                      <FreshnessChip state={record.freshness} ageDays={record.ageDays} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={evidenceOffset} limit={20} total={evidence.total} onChange={setEvidenceOffset} />
          </>
        ) : (
          <PanelEmpty>
            No stored attestations yet. Framework statuses on this page rest entirely on derived platform signals — real
            measurements, but not auditor-facing attestations.
          </PanelEmpty>
        )}
      </Panel>

      {/* ---- Regulatory gaps --------------------------------------------- */}
      {gaps.error ? <GovernanceError message={gaps.error} onRetry={gaps.retry} /> : gaps.rows.length ? (
        <Panel>
          <SectionLabel icon={Scale} meta={`${fmtNumber(gaps.total)} gaps`} hint="Gaps ordered by severity, each stating which frameworks it affects and what closing it changes.">
            Regulatory gaps
          </SectionLabel>
          <div className="grid gap-2.5 lg:grid-cols-2">
            {gaps.rows.map((gap, index) => (
              <GapCard key={gap.id} gap={gap} index={index} onOpen={gap.controlIds.length ? () => setTarget({ kind: 'control', id: gap.controlIds[0] }) : undefined} />
            ))}
          </div>
        </Panel>
      ) : null}

      <GovernanceProvenance telemetry={data.telemetry} />

      <GovernanceDrawers
        view="regulatory"
        target={target}
        onTarget={setTarget}
        revision={revision}
        reconciliation={<ReconciliationPanel report={data.reconciliation} />}
      />
    </div>
  );
}
