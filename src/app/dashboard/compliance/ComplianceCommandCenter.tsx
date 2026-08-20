'use client';

/**
 * Compliance Command Center.
 *
 * The decision layer for "are we compliant, where are we not, and what closes
 * the gap". Every status on this page is produced by evaluating a control
 * against the tenant's real evidence — there are no framework scores derived
 * from other framework scores, and no maturity curve derived from arithmetic on
 * a headline number.
 *
 * The page is deliberately built around THREE numbers rather than one:
 *   Compliance Score   how well the controls we can measure are doing
 *   Control Coverage   how much of the control set we can measure at all
 *   Evidence Freshness whether that measurement still describes today's estate
 *
 * A single "92% compliant" tile on a tenant where only four controls could be
 * assessed is the fabrication this layout exists to prevent.
 */

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ClipboardCheck,
  Database,
  FileSearch,
  Layers,
  RefreshCw,
  Scale,
  ShieldCheck,
  Target,
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
  ActivityTrend,
  Basis,
  CONTROL_DOMAIN_LABEL,
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
  SeverityBadge,
  StatusBadge,
  StaleBanner,
  TONE,
  fmtNumber,
  relativeTime,
  riseStyle,
  scoreCell,
} from '../_components/governance/primitives';
import { GovernanceDrawers, type DrawerTarget } from '../_components/governance/drawers';
import {
  useComplianceCommandCenter,
  useGovernanceFilters,
  useGovernancePagedResource,
  type ControlSummary,
} from '@/hooks/use-governance';
import type { AssetComplianceRecord, ControlStatus, GovernanceGap } from '@/lib/governance/types';

export default function ComplianceCommandCenter() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useComplianceCommandCenter();
  const { filters, setFilter, reset, activeCount } = useGovernanceFilters();
  const [target, setTarget] = useState<DrawerTarget>(null);
  const [controlOffset, setControlOffset] = useState(0);
  const [assetOffset, setAssetOffset] = useState(0);
  const [gapOffset, setGapOffset] = useState(0);

  /* Server-side paged tables — a large estate never ships every row. */
  const controls = useGovernancePagedResource<ControlSummary>(
    'compliance',
    '/controls',
    'controls',
    {
      limit: 25,
      offset: controlOffset,
      search: filters.search,
      status: filters.status,
      domain: filters.domain,
      framework: filters.framework,
      severity: filters.severity,
      freshness: filters.freshness,
      sort: filters.sort,
    },
    revision,
  );

  const assets = useGovernancePagedResource<AssetComplianceRecord>(
    'compliance',
    '/assets',
    'assets',
    {
      limit: 15,
      offset: assetOffset,
      search: filters.search,
      status: filters.status === 'partial' ? 'all' : filters.status,
      environment: filters.environment,
      owner: filters.owner,
      criticality: filters.criticality,
      exposure: filters.exposure,
    },
    revision,
  );

  const gaps = useGovernancePagedResource<GovernanceGap>(
    'compliance',
    '/gaps',
    'gaps',
    { limit: 12, offset: gapOffset, search: filters.search, severity: filters.severity, domain: filters.domain, framework: filters.framework },
    revision,
  );

  const openControl = useCallback((id: string) => setTarget({ kind: 'control', id }), []);
  const filterByStatus = useCallback(
    (status: ControlStatus) => {
      setFilter('status', status);
      setControlOffset(0);
      document.getElementById('control-inventory')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },
    [setFilter],
  );

  const frameworkOptions = useMemo(
    () => [
      { value: 'all', label: 'All frameworks' },
      ...(data?.facets.frameworks ?? []).map((entry) => ({ value: entry.id, label: entry.label })),
    ],
    [data?.facets.frameworks],
  );
  const domainOptions = useMemo(
    () => [
      { value: 'all', label: 'All domains' },
      ...(data?.facets.domains ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.domains],
  );
  const ownerOptions = useMemo(
    () => [
      { value: 'all', label: 'All owners' },
      ...(data?.facets.owners ?? []).slice(0, 20).map((entry) => ({ value: entry.id.toLowerCase(), label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.owners],
  );
  const environmentOptions = useMemo(
    () => [
      { value: 'all', label: 'All environments' },
      ...(data?.facets.environments ?? []).slice(0, 20).map((entry) => ({ value: entry.id.toLowerCase(), label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.environments],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader
          icon={ClipboardCheck}
          title="Compliance"
          accent="Command Center"
          subtitle="Evaluating cryptographic controls against your tenant evidence…"
        />
        <ScoreSkeleton />
        <GovernanceSkeleton rows={4} height={110} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={ClipboardCheck} title="Compliance" accent="Command Center" subtitle="Control coverage, gaps and the evidence behind each status." />
        <GovernanceError message={error || 'The governance model could not be computed.'} onRetry={reconnect} />
      </div>
    );
  }

  if (!data) return null;

  const { scores, totals } = data;

  return (
    <div className={GOV_SHELL_CLASS}>
      <style>{GOV_SHELL_CSS}</style>

      <GovernanceHeader
        icon={ClipboardCheck}
        title="Compliance"
        accent="Command Center"
        subtitle="Every control below is evaluated against your own assets, scans, certificates, keys, telemetry and attestations. Controls with no evidence read “Not assessed” — never as a pass or a failure."
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

      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void refresh(true)} /> : null}

      {!data.hasData ? (
        <NoEvidenceState
          title="No compliance evidence yet"
          detail="Compliance status is derived from your own cryptographic estate. Run a discovery scan or connect a collector, and every control that gains evidence moves from “Not assessed” into scope automatically."
          actions={[
            { label: 'Run a discovery scan', href: '/dashboard/scanner', primary: true },
            { label: 'Deploy a collector', href: '/downloads' },
            { label: 'Connect a cloud account', href: '/dashboard/multi-cloud-telemetry' },
          ]}
        />
      ) : null}

      {/* ---- Executive metrics ------------------------------------- */}
      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5">
        <ScoreTile score={scores.compliance} />
        <ScoreTile score={scores.controlCoverage} />
        <ScoreTile score={scores.evidenceCoverage} />
        <ScoreTile score={scores.evidenceFreshness} />
        <ScoreTile score={scores.policyAdherence} />
      </section>

      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <CountTile
          label="Critical gaps"
          value={totals.criticalGaps}
          detail="Severity-critical findings"
          tone={totals.criticalGaps > 0 ? 'critical' : 'good'}
          onOpen={() => document.getElementById('gap-analysis')?.scrollIntoView({ behavior: 'smooth' })}
          hint="Governance gaps whose worst failing subject is critical. Click to jump to the gap analysis."
        />
        <CountTile
          label="Failing controls"
          value={totals.controlsFailing}
          detail={`of ${totals.controls} in catalog`}
          tone={totals.controlsFailing > 0 ? 'critical' : 'good'}
          onOpen={() => filterByStatus('non-compliant')}
          hint="Controls where every in-scope subject fails. Click to filter the control inventory."
        />
        <CountTile
          label="Partially compliant"
          value={totals.controlsPartial}
          tone={totals.controlsPartial > 0 ? 'warning' : 'good'}
          onOpen={() => filterByStatus('partial')}
          hint="Controls where some subjects pass and others do not."
        />
        <CountTile
          label="Not assessed"
          value={totals.controlsUnassessed}
          detail="Missing evidence"
          tone="neutral"
          onOpen={() => filterByStatus('not-assessed')}
          hint="Controls with no tenant evidence. Not failures — connect the source to bring them into scope."
        />
        <CountTile
          label="Open findings"
          value={totals.openFindings}
          detail={`${totals.criticalFindings} critical`}
          tone={totals.criticalFindings > 0 ? 'critical' : totals.openFindings > 0 ? 'warning' : 'good'}
          hint="Unresolved findings recorded as contradicting evidence. Critical count mirrors the Quantum Readiness assessment."
        />
        <CountTile
          label="Policy violations"
          value={totals.policyViolations}
          detail={`${totals.policiesEnforced} of ${totals.policies} rules active`}
          tone={totals.criticalPolicyViolations > 0 ? 'critical' : totals.policyViolations > 0 ? 'warning' : 'good'}
          onOpen={() => setTarget(null)}
          hint="Subject-level violations of the cryptographic policy rules. Manage the rules on Quantum Governance."
        />
      </section>

      {/* ---- Control status distribution + trend -------------------- */}
      <section className="grid gap-3 xl:grid-cols-[1.15fr_1fr]">
        <Panel>
          <SectionLabel icon={Target} hint="Every control in the catalog, grouped by evaluated status. “Not assessed” is drawn as its own segment because folding it into either end would misstate the position.">
            Control status
          </SectionLabel>
          <CoverageBar
            compliant={totals.controlsCompliant}
            partial={totals.controlsPartial}
            failing={totals.controlsFailing}
            unassessed={totals.controlsUnassessed}
            notApplicable={totals.controlsNotApplicable}
            onSegment={filterByStatus}
          />
          <Basis>
            {scores.compliance.basis} Coverage: {scores.controlCoverage.basis}
          </Basis>
        </Panel>

        <Panel>
          <SectionLabel icon={Layers} hint="Governance activity per day over the last 30 days. Days before your first observation are hatched rather than drawn as zero.">
            Governance activity
          </SectionLabel>
          <ActivityTrend
            points={data.trend}
            series={[
              { key: 'evidence', label: 'Evidence recorded', tone: 'neutral', value: (point) => point.evidence },
              { key: 'opened', label: 'Findings opened', tone: 'critical', value: (point) => point.findingsOpened },
              { key: 'resolved', label: 'Findings resolved', tone: 'good', value: (point) => point.findingsResolved },
            ]}
          />
          <Basis>
            Counted from the timestamps on your own evidence and audit records. Policy violations are point-in-time, so
            they are shown only on the current day rather than back-filled as invented history.
          </Basis>
        </Panel>
      </section>

      {/* ---- Domain rollup ------------------------------------------ */}
      <Panel>
        <SectionLabel
          icon={ShieldCheck}
          meta={`${data.domainRollup.length} domains`}
          hint="Weighted control score per governance domain, over the controls in that domain that could be measured."
        >
          Control domains
        </SectionLabel>
        {data.domainRollup.length ? (
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
            {data.domainRollup.map((row, index) => (
              <button
                key={row.domain}
                type="button"
                onClick={() => {
                  setFilter('domain', row.domain);
                  setControlOffset(0);
                  document.getElementById('control-inventory')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }}
                style={riseStyle(index)}
                className="gov-rise rounded-lg border border-white/8 bg-white/[0.02] p-3 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-bold text-white/80">{CONTROL_DOMAIN_LABEL[row.domain]}</span>
                  {scoreCell(row.score, row.measured > 0)}
                </div>
                <div className="mt-2 flex h-1.5 overflow-hidden rounded-full bg-white/8">
                  {row.compliant > 0 ? <span style={{ width: `${(row.compliant / row.controls) * 100}%`, backgroundColor: TONE.good.hex }} /> : null}
                  {row.failing > 0 ? <span style={{ width: `${(row.failing / row.controls) * 100}%`, backgroundColor: TONE.critical.hex }} /> : null}
                  {row.unassessed > 0 ? <span style={{ width: `${(row.unassessed / row.controls) * 100}%`, backgroundColor: TONE.neutral.hex }} /> : null}
                </div>
                <div className="mt-1.5 flex flex-wrap gap-x-3 text-[9.5px] font-semibold text-white/40">
                  <span>{row.controls} controls</span>
                  <span>{row.measured} assessed</span>
                  {row.failingSubjects > 0 ? <span className="text-red-300/80">{fmtNumber(row.failingSubjects)} failing subjects</span> : null}
                </div>
              </button>
            ))}
          </div>
        ) : (
          <PanelEmpty>No controls in scope.</PanelEmpty>
        )}
      </Panel>

      {/* ---- Global filters ----------------------------------------- */}
      <FilterBar activeCount={activeCount} onReset={() => { reset(); setControlOffset(0); setAssetOffset(0); setGapOffset(0); }}>
        <SearchInput value={filters.search} onChange={(value) => { setFilter('search', value); setControlOffset(0); }} placeholder="Search controls, assets, gaps…" />
        <FilterSelect
          label="Status"
          value={filters.status}
          onChange={(value) => { setFilter('status', value); setControlOffset(0); }}
          options={[
            { value: 'all', label: 'All statuses' },
            { value: 'non-compliant', label: 'Non-compliant' },
            { value: 'partial', label: 'Partially compliant' },
            { value: 'compliant', label: 'Compliant' },
            { value: 'not-assessed', label: 'Not assessed' },
            { value: 'not-applicable', label: 'Not applicable' },
          ]}
        />
        <FilterSelect label="Domain" value={filters.domain} onChange={(value) => { setFilter('domain', value); setControlOffset(0); }} options={domainOptions} />
        <FilterSelect label="Framework" value={filters.framework} onChange={(value) => { setFilter('framework', value); setControlOffset(0); }} options={frameworkOptions} />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          onChange={(value) => { setFilter('severity', value); setControlOffset(0); }}
          options={[
            { value: 'all', label: 'Any severity' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <FilterSelect
          label="Evidence"
          value={filters.freshness}
          onChange={(value) => { setFilter('freshness', value); setControlOffset(0); }}
          options={[
            { value: 'all', label: 'Any freshness' },
            { value: 'fresh', label: 'Fresh (≤30d)' },
            { value: 'aging', label: 'Aging (≤90d)' },
            { value: 'stale', label: 'Stale (>90d)' },
            { value: 'unknown', label: 'Undated' },
          ]}
        />
        <FilterSelect label="Environment" value={filters.environment} onChange={(value) => { setFilter('environment', value); setAssetOffset(0); }} options={environmentOptions} />
        <FilterSelect label="Owner" value={filters.owner} onChange={(value) => { setFilter('owner', value); setAssetOffset(0); }} options={ownerOptions} />
      </FilterBar>

      {/* ---- Control inventory -------------------------------------- */}
      <Panel id="control-inventory">
        <SectionLabel
          icon={ClipboardCheck}
          meta={controls.total ? `${fmtNumber(controls.total)} controls` : undefined}
          hint="Every control, its evaluated status, the population it was measured over and the evidence age behind it. Click a row for the full derivation and its failing subjects."
        >
          Control inventory
        </SectionLabel>
        {controls.loading && !controls.rows.length ? (
          <GovernanceSkeleton rows={5} height={40} />
        ) : controls.rows.length ? (
          <>
            <TableShell minWidth={980}>
              <thead>
                <tr>
                  <Th>Control</Th>
                  <Th>Domain</Th>
                  <Th align="right">Score</Th>
                  <Th>Status</Th>
                  <Th align="right">Failing / scope</Th>
                  <Th>Owner</Th>
                  <Th>Evidence</Th>
                  <Th align="right">Frameworks</Th>
                </tr>
              </thead>
              <tbody>
                {controls.rows.map((control) => (
                  <tr
                    key={control.id}
                    onClick={() => openControl(control.id)}
                    className="cursor-pointer transition hover:bg-white/[0.03]"
                  >
                    <Td>
                      <div className="font-mono text-[9.5px] text-cyan-300/70">{control.code}</div>
                      <div className="font-semibold text-white/85">{control.title}</div>
                      <div className="mt-0.5 line-clamp-1 text-[10px] text-white/35" title={control.basis}>
                        {control.basis}
                      </div>
                    </Td>
                    <Td className="text-white/55">{CONTROL_DOMAIN_LABEL[control.domain]}</Td>
                    <Td align="right">{scoreCell(control.score, control.measured)}</Td>
                    <Td>
                      <StatusBadge status={control.status} size="sm" />
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {control.measured ? (
                        <span className={control.failing > 0 ? 'text-red-300' : 'text-emerald-300'}>
                          {fmtNumber(control.failing)} / {fmtNumber(control.population)}
                        </span>
                      ) : (
                        <span className="text-white/25">—</span>
                      )}
                    </Td>
                    <Td className={control.owner ? 'text-white/70' : 'text-white/30'}>{control.owner || 'Unassigned'}</Td>
                    <Td>
                      <FreshnessChip state={control.evidenceFreshness} ageDays={control.evidenceAgeDays} />
                    </Td>
                    <Td align="right" className="font-mono tabular-nums text-white/50">
                      {control.frameworkIds.length}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={controlOffset} limit={25} total={controls.total} onChange={setControlOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No controls in scope.</PanelEmpty>
        )}
        <Basis>
          Scores are weighted over MEASURED controls only. A control with no evidence is excluded from both the numerator
          and the denominator, and is counted in Control Coverage instead.
        </Basis>
      </Panel>

      {/* ---- Gap analysis ------------------------------------------- */}
      <Panel id="gap-analysis">
        <SectionLabel
          icon={FileSearch}
          meta={gaps.total ? `${fmtNumber(gaps.total)} gaps` : undefined}
          hint="Missing controls, failing controls, expired evidence, unmapped assets and policy violations — ordered by severity and by how much closing each one changes."
        >
          Compliance gap analysis
        </SectionLabel>
        {gaps.loading && !gaps.rows.length ? (
          <GovernanceSkeleton rows={3} height={120} />
        ) : gaps.rows.length ? (
          <>
            <div className="grid gap-2.5 lg:grid-cols-2">
              {gaps.rows.map((gap, index) => (
                <GapCard
                  key={gap.id}
                  gap={gap}
                  index={index}
                  onOpen={gap.controlIds.length ? () => openControl(gap.controlIds[0]) : undefined}
                />
              ))}
            </div>
            <Pager offset={gapOffset} limit={12} total={gaps.total} onChange={setGapOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No governance gaps detected in the current evidence.</PanelEmpty>
        )}
      </Panel>

      {/* ---- Framework coverage ------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Scale}
          meta={`${data.frameworks.length} frameworks`}
          href="/dashboard/regulatory-mapping"
          hint="Framework compliance over the controls that could be measured, plus how many of its requirements are assessable at all."
        >
          Framework coverage
        </SectionLabel>
        <TableShell minWidth={860}>
          <thead>
            <tr>
              <Th>Framework</Th>
              <Th align="right">Score</Th>
              <Th>Status</Th>
              <Th align="right">Requirements</Th>
              <Th align="right">Coverage</Th>
              <Th align="right">Attestations</Th>
              <Th>Last validated</Th>
            </tr>
          </thead>
          <tbody>
            {data.frameworks.map((framework) => (
              <tr
                key={framework.id}
                onClick={() => setTarget({ kind: 'framework', id: framework.id })}
                className="cursor-pointer transition hover:bg-white/[0.03]"
              >
                <Td>
                  <div className="font-semibold text-white/85">{framework.shortName}</div>
                  <div className="text-[10px] text-white/35">
                    {framework.authority} · {framework.version}
                  </div>
                </Td>
                <Td align="right">{scoreCell(framework.score, framework.measured)}</Td>
                <Td>
                  <StatusBadge status={framework.status} size="sm" />
                </Td>
                <Td align="right" className="font-mono tabular-nums text-white/60">
                  {framework.requirementsMeasured}/{framework.requirementsTotal}
                </Td>
                <Td align="right" className="font-mono tabular-nums text-white/60">
                  {framework.coverage}%
                </Td>
                <Td align="right" className={cn('font-mono tabular-nums', framework.attestedEvidenceCount ? 'text-white/70' : 'text-white/25')}>
                  {framework.attestedEvidenceCount || '—'}
                </Td>
                <Td className="text-white/45">{relativeTime(framework.lastValidatedAt)}</Td>
              </tr>
            ))}
          </tbody>
        </TableShell>
        <Basis>
          A framework’s score covers only the controls the platform could measure for it. “Attestations” counts stored
          evidence rows naming that framework — where it reads “—”, the status rests on derived platform signals alone.
        </Basis>
      </Panel>

      {/* ---- Asset compliance --------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Database}
          meta={assets.total ? `${fmtNumber(assets.total)} assets` : undefined}
          hint="Per-asset compliance: which controls each asset fails, its findings, and whether any evidence is bound to it at all."
        >
          Asset compliance
        </SectionLabel>
        {assets.loading && !assets.rows.length ? (
          <GovernanceSkeleton rows={4} height={38} />
        ) : assets.rows.length ? (
          <>
            <TableShell minWidth={940}>
              <thead>
                <tr>
                  <Th>Asset</Th>
                  <Th>Owner</Th>
                  <Th>Status</Th>
                  <Th align="right">Failing controls</Th>
                  <Th align="right">Findings</Th>
                  <Th align="right">Violations</Th>
                  <Th align="right">Evidence</Th>
                  <Th>Freshness</Th>
                </tr>
              </thead>
              <tbody>
                {assets.rows.map((asset) => (
                  <tr
                    key={asset.assetId}
                    onClick={() => setTarget({ kind: 'asset', id: asset.assetId })}
                    className="cursor-pointer transition hover:bg-white/[0.03]"
                  >
                    <Td>
                      <div className="font-semibold text-white/85">{asset.name}</div>
                      <div className="text-[10px] text-white/35">
                        {asset.type} · {asset.environment}
                        {asset.internetFacing ? ' · internet-facing' : ''}
                      </div>
                    </Td>
                    <Td className={asset.owner === 'Unassigned' ? 'text-white/30' : 'text-white/65'}>{asset.owner}</Td>
                    <Td>
                      <StatusBadge status={asset.status} size="sm" />
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      <span className={asset.controlsFailing > 0 ? 'text-red-300' : 'text-white/40'}>{asset.controlsFailing}</span>
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      <span className={asset.criticalFindings > 0 ? 'text-red-300' : 'text-white/50'}>
                        {asset.openFindings}
                        {asset.criticalFindings > 0 ? ` (${asset.criticalFindings} crit)` : ''}
                      </span>
                    </Td>
                    <Td align="right" className="font-mono tabular-nums text-white/50">
                      {asset.policyViolations || '—'}
                    </Td>
                    <Td align="right" className="font-mono tabular-nums text-white/50">
                      {asset.evidenceCount}
                    </Td>
                    <Td>
                      <FreshnessChip state={asset.evidenceFreshness} />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={assetOffset} limit={15} total={assets.total} onChange={setAssetOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No assets discovered yet.</PanelEmpty>
        )}
        <Basis>
          Asset facts (posture, risk, readiness) are the same per-asset dossiers the Migration Planner uses, so an
          asset reads identically on both pages.
        </Basis>
      </Panel>

      {/* ---- Recent evidence ---------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={ShieldCheck}
          href="/dashboard/audit-vault"
          meta={`${fmtNumber(totals.evidence)} records`}
          hint="The newest evidence supporting or contradicting a control. The Audit Vault holds the full, searchable set."
        >
          Latest evidence
        </SectionLabel>
        {data.evidence.length ? (
          <div className="space-y-1.5">
            {data.evidence.slice(0, 12).map((record, index) => (
              <button
                key={record.id}
                type="button"
                onClick={() => setTarget({ kind: 'evidence', id: record.id })}
                style={riseStyle(index)}
                className="gov-rise flex w-full items-center gap-2 rounded-lg border border-white/8 bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-white/20 hover:bg-white/[0.05]"
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[11px] font-semibold text-white/80">{record.title}</span>
                  <span className="mt-0.5 block truncate font-mono text-[9.5px] text-white/35">
                    {record.source.table} · {record.source.collector} · {relativeTime(record.occurredAt)}
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  <SeverityBadge severity={record.severity} />
                  <Pill tone={record.outcome === 'contradicting' ? 'critical' : record.outcome === 'supporting' ? 'good' : 'neutral'}>
                    {record.outcome === 'contradicting' ? 'Contradicts' : record.outcome === 'supporting' ? 'Supports' : 'Info'}
                  </Pill>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <PanelEmpty>No evidence recorded yet.</PanelEmpty>
        )}
      </Panel>

      <GovernanceProvenance telemetry={data.telemetry} />

      <GovernanceDrawers
        view="compliance"
        target={target}
        onTarget={setTarget}
        revision={revision}
        reconciliation={<ReconciliationPanel report={data.reconciliation} />}
      />
    </div>
  );
}
