'use client';

/**
 * Quantum & Cryptographic Governance Center.
 *
 * The governance layer for cryptographic and post-quantum risk: which rules the
 * organisation has set, whether they are enforced, and what the estate is
 * actually doing against them.
 *
 * Every posture figure on this page (components, vulnerable components, PQC-ready
 * components, certificates, keys, readiness, risk) is MIRRORED from the Quantum
 * Readiness assessment rather than recounted here — which is what stops this
 * page reporting 137 cryptographic assets while Compliance reports 142.
 *
 * Policy rules are editable and the change is persisted, evaluated immediately
 * and written to the audit log, so "policy management" means managing policy,
 * not reading a static list.
 */

import { useCallback, useMemo, useState } from 'react';
import {
  Atom,
  Cpu,
  KeyRound,
  RefreshCw,
  Scale,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
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
  EnforcementBadge,
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
  POLICY_CATEGORY_LABEL,
  Panel,
  PanelEmpty,
  Pill,
  ReconciliationPanel,
  ScoreSkeleton,
  ScoreTile,
  SeverityBadge,
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
  useGovernanceActions,
  useGovernanceFilters,
  useGovernancePagedResource,
  useQuantumGovernance,
  type ControlSummary,
} from '@/hooks/use-governance';
import type { GovernanceGap, PolicyRecord, PolicyViolation } from '@/lib/governance/types';

/* ------------------------------------------------------------------ */
/* Policy rule card — visibility AND management (§6)                   */
/* ------------------------------------------------------------------ */

function PolicyCard({
  policy,
  index,
  storeAvailable,
  onSaved,
  onInspect,
}: {
  policy: PolicyRecord;
  index: number;
  storeAvailable: boolean;
  onSaved: (message: string) => void;
  onInspect: () => void;
}) {
  const { updatePolicy, pending } = useGovernanceActions('quantum');
  const [expanded, setExpanded] = useState(false);
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [enforcement, setEnforcement] = useState(policy.enforcement);

  const dirty =
    enforcement !== policy.enforcement ||
    policy.parameters.some((parameter) => parameter.key in draft && JSON.stringify(draft[parameter.key]) !== JSON.stringify(parameter.value));

  const save = useCallback(async () => {
    const result = await updatePolicy(policy.id, { enforcement, parameters: draft });
    onSaved(result.ok ? `${policy.title} updated.` : result.message);
    if (result.ok) setDraft({});
  }, [draft, enforcement, onSaved, policy.id, policy.title, updatePolicy]);

  const adherenceTone = policy.adherence === null ? 'neutral' : policy.adherence >= 95 ? 'good' : policy.adherence >= 80 ? 'warning' : 'critical';

  return (
    <article className="gov-rise rounded-xl border border-white/10 bg-white/[0.02] p-3.5" style={riseStyle(index)}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <EnforcementBadge enforcement={policy.enforcement} />
            <Pill tone="neutral">{POLICY_CATEGORY_LABEL[policy.category]}</Pill>
            {policy.tenantConfigured ? <Pill tone="info" title={`Overridden by your tenant${policy.updatedBy ? ` (${policy.updatedBy})` : ''}`}>Customised</Pill> : null}
          </div>
          <h3 className="mt-1.5 text-[12.5px] font-bold leading-snug text-white">{policy.title}</h3>
          <p className="mt-1 text-[10.5px] leading-relaxed text-white/45">{policy.rationale}</p>
          <p className="mt-1 font-mono text-[9.5px] text-cyan-300/60">{policy.standard}</p>
        </div>
        <div className="shrink-0 text-right">
          <div className={cn('font-mono text-[20px] font-black leading-none tabular-nums', TONE[adherenceTone].text)}>
            {policy.adherence === null ? '—' : `${policy.adherence}%`}
          </div>
          <div className="mt-0.5 text-[9px] font-black uppercase tracking-wider text-white/35">Adherence</div>
        </div>
      </div>

      <p className="mt-2 border-t border-white/[0.06] pt-2 text-[10.5px] leading-relaxed text-white/40">{policy.basis}</p>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-semibold">
        <span className="text-white/45">
          Evaluated <span className="font-mono text-white/70">{fmtNumber(policy.evaluated)}</span>
        </span>
        <span className={policy.violations > 0 ? 'text-red-300/85' : 'text-emerald-300/80'}>
          Violations <span className="font-mono">{fmtNumber(policy.violations)}</span>
        </span>
        {policy.criticalViolations > 0 ? (
          <span className="text-red-300">
            Critical <span className="font-mono">{fmtNumber(policy.criticalViolations)}</span>
          </span>
        ) : null}
      </div>

      {policy.violationSample.length ? (
        <ul className="mt-2 space-y-1">
          {policy.violationSample.slice(0, 3).map((violation) => (
            <li key={violation.id} className="flex items-start gap-1.5 rounded-md border border-white/[0.06] bg-black/20 px-2 py-1.5">
              <SeverityBadge severity={violation.severity} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[10.5px] font-semibold text-white/75">{violation.subject}</span>
                <span className="block truncate text-[9.5px] text-white/40">
                  {violation.observed} → expected {violation.expected}
                </span>
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
        >
          {expanded ? 'Hide settings' : 'Settings'}
        </button>
        {policy.violations > 0 ? (
          <button
            type="button"
            onClick={onInspect}
            className="rounded-md border border-red-400/30 bg-red-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-red-200 transition hover:bg-red-500/20"
          >
            View all {fmtNumber(policy.violations)}
          </button>
        ) : null}
      </div>

      {expanded ? (
        <div className="mt-2.5 space-y-2.5 rounded-lg border border-white/10 bg-black/25 p-2.5">
          {!storeAvailable ? (
            <p className="rounded-md border border-amber-400/25 bg-amber-500/[0.07] p-2 text-[10px] leading-relaxed text-amber-100/85">
              Tenant policy overrides cannot be saved: the governance policy store is not available in this environment.
              Apply <span className="font-mono">supabase/governance-schema.sql</span> to enable them. The platform default
              shown below is still fully evaluated.
            </p>
          ) : null}

          <label className="flex items-center justify-between gap-2">
            <span className="text-[9.5px] font-black uppercase tracking-wider text-white/45">Enforcement</span>
            <select
              value={enforcement}
              onChange={(event) => setEnforcement(event.target.value as PolicyRecord['enforcement'])}
              className="rounded-md border border-white/12 bg-black/40 px-2 py-1 text-[10.5px] font-semibold text-white/85 outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
            >
              <option value="enforced">Enforced</option>
              <option value="monitored">Monitored</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>

          {policy.parameters.map((parameter) => {
            const current = parameter.key in draft ? draft[parameter.key] : parameter.value;
            return (
              <div key={parameter.key} className="space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[9.5px] font-black uppercase tracking-wider text-white/45">
                    {parameter.label}
                    {parameter.unit ? <span className="ml-1 normal-case text-white/30">({parameter.unit})</span> : null}
                  </span>
                  {parameter.type === 'number' ? (
                    <input
                      type="number"
                      value={Number(current)}
                      onChange={(event) => setDraft((value) => ({ ...value, [parameter.key]: Number(event.target.value) }))}
                      className="w-24 rounded-md border border-white/12 bg-black/40 px-2 py-1 text-right font-mono text-[10.5px] text-white/85 outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                    />
                  ) : parameter.type === 'boolean' ? (
                    <input
                      type="checkbox"
                      checked={Boolean(current)}
                      onChange={(event) => setDraft((value) => ({ ...value, [parameter.key]: event.target.checked }))}
                      className="h-4 w-4 accent-cyan-400"
                    />
                  ) : (
                    <span className="max-w-[60%] truncate font-mono text-[10px] text-white/60" title={(current as string[]).join(', ')}>
                      {(current as string[]).join(', ')}
                    </span>
                  )}
                </div>
                <p className="text-[9.5px] leading-relaxed text-white/30">{parameter.hint}</p>
              </div>
            );
          })}

          <button
            type="button"
            onClick={save}
            disabled={!dirty || Boolean(pending) || !storeAvailable}
            className="w-full rounded-md border border-cyan-400/35 bg-cyan-500/12 px-3 py-1.5 text-[10px] font-black uppercase tracking-wider text-cyan-100 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-35"
          >
            {pending ? 'Saving…' : 'Save policy'}
          </button>
        </div>
      ) : null}
    </article>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function QuantumGovernanceCenter() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useQuantumGovernance();
  const { filters, setFilter, reset, activeCount } = useGovernanceFilters();
  const [target, setTarget] = useState<DrawerTarget>(null);
  const [controlOffset, setControlOffset] = useState(0);
  const [violationPolicy, setViolationPolicy] = useState<string | null>(null);
  const [violationOffset, setViolationOffset] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  const controls = useGovernancePagedResource<ControlSummary>(
    'quantum',
    '/controls',
    'controls',
    {
      limit: 25,
      offset: controlOffset,
      search: filters.search,
      status: filters.status,
      domain: filters.domain,
      severity: filters.severity,
      framework: filters.framework,
    },
    revision,
  );

  const violations = useGovernancePagedResource<PolicyViolation>(
    'quantum',
    violationPolicy ? `/policies/${encodeURIComponent(violationPolicy)}/violations` : '/policies',
    'violations',
    { limit: 25, offset: violationOffset, search: filters.search, severity: filters.severity },
    revision,
  );

  const gaps = useGovernancePagedResource<GovernanceGap>(
    'quantum',
    '/gaps',
    'gaps',
    { limit: 8, offset: 0, severity: filters.severity, domain: filters.domain },
    revision,
  );

  const policies = data?.policies ?? [];
  const filteredPolicies = useMemo(() => {
    const search = filters.search.trim().toLowerCase();
    return policies.filter((policy) => {
      if (filters.category !== 'all' && policy.category !== filters.category) return false;
      if (filters.enforcement !== 'all' && policy.enforcement !== filters.enforcement) return false;
      if (!search) return true;
      return `${policy.title} ${policy.rationale} ${policy.standard}`.toLowerCase().includes(search);
    });
  }, [policies, filters.search, filters.category, filters.enforcement]);

  const domainOptions = useMemo(
    () => [
      { value: 'all', label: 'All domains' },
      ...(data?.facets.domains ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.domains],
  );
  const categoryOptions = useMemo(
    () => [
      { value: 'all', label: 'All policy areas' },
      ...(data?.facets.policyCategories ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.policyCategories],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Atom} title="Quantum" accent="Governance" subtitle="Evaluating cryptographic policy against your estate…" />
        <ScoreSkeleton />
        <GovernanceSkeleton rows={4} height={120} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Atom} title="Quantum" accent="Governance" subtitle="Cryptographic policy, PQC posture and risk appetite." />
        <GovernanceError message={error || 'The governance model could not be computed.'} onRetry={reconnect} />
      </div>
    );
  }

  if (!data) return null;

  const { scores, totals, posture } = data;

  return (
    <div className={GOV_SHELL_CLASS}>
      <style>{GOV_SHELL_CSS}</style>

      <GovernanceHeader
        icon={Atom}
        title="Quantum"
        accent="Governance"
        subtitle="Cryptographic policy, post-quantum posture and risk appetite for the whole estate. Estate counts are mirrored from the Quantum Readiness assessment, so this page and that one can never disagree."
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

      {notice ? (
        <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/[0.07] px-4 py-2 text-[11px] font-semibold text-cyan-100">{notice}</div>
      ) : null}

      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void refresh(true)} /> : null}

      {!data.hasData ? (
        <NoEvidenceState
          title="No cryptographic evidence yet"
          detail="Policy rules are defined and ready, but there is nothing to evaluate them against. Discover your cryptographic estate and every rule begins reporting real adherence."
          actions={[
            { label: 'Run a discovery scan', href: '/dashboard/scanner', primary: true },
            { label: 'Review readiness', href: '/dashboard/quantum-readiness' },
          ]}
        />
      ) : null}

      {/* ---- Governance scores -------------------------------------- */}
      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5">
        <ScoreTile score={scores.governance} />
        <ScoreTile score={scores.pqcGovernance} />
        <ScoreTile score={scores.policyAdherence} />
        <ScoreTile score={scores.quantumReadiness} />
        <ScoreTile score={scores.quantumRisk} />
      </section>

      {/* ---- Canonical estate posture -------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Cpu}
          href="/dashboard/quantum-readiness"
          hint="These counts are mirrored from the Quantum Readiness assessment — the same figures CBOM Explorer, Assets and the Report Center publish. Governance does not recount them."
        >
          Cryptographic estate
        </SectionLabel>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
          <CountTile label="Components" value={posture.cryptoComponents} detail="Cryptographic components in the CBOM" hint="Canonical component count from the readiness assessment." />
          <CountTile
            label="Quantum-vulnerable"
            value={posture.vulnerableComponents}
            detail={posture.cryptoComponents ? `${Math.round((posture.vulnerableComponents / posture.cryptoComponents) * 100)}% of components` : undefined}
            tone={posture.vulnerableComponents > 0 ? 'critical' : 'good'}
            hint="Components classified quantum-vulnerable. Drives CTL-PQC-01 and CTL-PQC-03."
          />
          <CountTile
            label="PQC-ready"
            value={posture.pqcReadyComponents}
            detail="Post-quantum or hybrid"
            tone={posture.pqcReadyComponents > 0 ? 'good' : 'neutral'}
            hint="Post-quantum plus hybrid components."
          />
          <CountTile label="Certificates" value={posture.certificates} tone="neutral" hint="Certificate population behind the certificate controls." />
          <CountTile label="Managed keys" value={posture.keys} tone="neutral" hint="Key population behind the key-management controls." />
          <CountTile
            label="Critical findings"
            value={posture.criticalFindings}
            tone={posture.criticalFindings > 0 ? 'critical' : 'good'}
            hint="Per-instance critical severity count, mirrored from the readiness assessment."
          />
        </div>
        <Basis>
          Mirrored from the Quantum Readiness snapshot, computed once per tenant per 15-second window and shared by every
          module. Open the reconciliation report in the header to see each figure and its canonical producer.
        </Basis>
      </Panel>

      {/* ---- Control status + trend ---------------------------------- */}
      <section className="grid gap-3 xl:grid-cols-[1.15fr_1fr]">
        <Panel>
          <SectionLabel icon={ShieldCheck} hint="Cryptographic, key, transport, certificate, data and governance controls — the scope of this page.">
            Cryptographic control status
          </SectionLabel>
          <CoverageBar
            compliant={controls.rows.length ? data.controls.filter((control) => control.status === 'compliant').length : 0}
            partial={data.controls.filter((control) => control.status === 'partial').length}
            failing={data.controls.filter((control) => control.status === 'non-compliant').length}
            unassessed={data.controls.filter((control) => control.status === 'not-assessed').length}
            notApplicable={data.controls.filter((control) => control.status === 'not-applicable').length}
            onSegment={(status) => {
              setFilter('status', status);
              setControlOffset(0);
            }}
          />
          <Basis>{scores.pqcGovernance.basis}</Basis>
        </Panel>

        <Panel>
          <SectionLabel icon={Scale} hint="Governance activity per day. Days before your first observation are hatched rather than drawn as zero.">
            Governance activity
          </SectionLabel>
          <ActivityTrend
            points={data.trend}
            series={[
              { key: 'evidence', label: 'Evidence', tone: 'neutral', value: (point) => point.evidence },
              { key: 'opened', label: 'Findings opened', tone: 'critical', value: (point) => point.findingsOpened },
              { key: 'resolved', label: 'Findings resolved', tone: 'good', value: (point) => point.findingsResolved },
            ]}
          />
        </Panel>
      </section>

      {/* ---- Filters -------------------------------------------------- */}
      <FilterBar activeCount={activeCount} onReset={() => { reset(); setControlOffset(0); setViolationOffset(0); }}>
        <SearchInput value={filters.search} onChange={(value) => { setFilter('search', value); setControlOffset(0); }} placeholder="Search policies, controls, violations…" />
        <FilterSelect label="Policy area" value={filters.category} onChange={(value) => setFilter('category', value)} options={categoryOptions} />
        <FilterSelect
          label="Enforcement"
          value={filters.enforcement}
          onChange={(value) => setFilter('enforcement', value)}
          options={[
            { value: 'all', label: 'All modes' },
            { value: 'enforced', label: 'Enforced' },
            { value: 'monitored', label: 'Monitored' },
            { value: 'disabled', label: 'Disabled' },
          ]}
        />
        <FilterSelect label="Domain" value={filters.domain} onChange={(value) => { setFilter('domain', value); setControlOffset(0); }} options={domainOptions} />
        <FilterSelect
          label="Status"
          value={filters.status}
          onChange={(value) => { setFilter('status', value); setControlOffset(0); }}
          options={[
            { value: 'all', label: 'All statuses' },
            { value: 'non-compliant', label: 'Non-compliant' },
            { value: 'partial', label: 'Partial' },
            { value: 'compliant', label: 'Compliant' },
            { value: 'not-assessed', label: 'Not assessed' },
          ]}
        />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          onChange={(value) => { setFilter('severity', value); setViolationOffset(0); }}
          options={[
            { value: 'all', label: 'Any severity' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
      </FilterBar>

      {/* ---- Policy rules --------------------------------------------- */}
      <Panel id="policies">
        <SectionLabel
          icon={SlidersHorizontal}
          meta={`${filteredPolicies.length} of ${policies.length} rules`}
          hint="The cryptographic rulebook: approved and forbidden algorithms, key strength, TLS, PQC, certificate and key lifecycle, encryption, agility and the quantum risk ceiling. Every rule is evaluated against your real subjects."
        >
          Cryptographic policy
        </SectionLabel>
        {!data.telemetry.policyStoreAvailable ? (
          <p className="mb-3 rounded-lg border border-amber-400/25 bg-amber-500/[0.06] p-2.5 text-[10.5px] leading-relaxed text-amber-100/85">
            Showing the platform baseline. Tenant overrides cannot be persisted until{' '}
            <span className="font-mono">supabase/governance-schema.sql</span> is applied — every rule below is still
            evaluated against your real estate.
          </p>
        ) : null}
        {filteredPolicies.length ? (
          <div className="grid gap-2.5 lg:grid-cols-2">
            {filteredPolicies.map((policy, index) => (
              <PolicyCard
                key={policy.id}
                policy={policy}
                index={index}
                storeAvailable={data.telemetry.policyStoreAvailable}
                onSaved={(message) => {
                  setNotice(message);
                  void refresh(true);
                }}
                onInspect={() => {
                  setViolationPolicy(policy.id);
                  setViolationOffset(0);
                  document.getElementById('policy-violations')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }}
              />
            ))}
          </div>
        ) : (
          <NoMatches onClear={reset} />
        )}
      </Panel>

      {/* ---- Violations ------------------------------------------------ */}
      {violationPolicy ? (
        <Panel id="policy-violations">
          <SectionLabel
            icon={ShieldAlert}
            meta={violations.total ? `${fmtNumber(violations.total)} violations` : undefined}
            hint="Every subject failing this rule, with the observed value and what the rule expects."
          >
            {policies.find((policy) => policy.id === violationPolicy)?.title || 'Policy violations'}
          </SectionLabel>
          <div className="mb-2">
            <button
              type="button"
              onClick={() => setViolationPolicy(null)}
              className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/55 transition hover:bg-white/[0.08]"
            >
              Close
            </button>
          </div>
          {violations.loading && !violations.rows.length ? (
            <GovernanceSkeleton rows={4} height={36} />
          ) : violations.rows.length ? (
            <>
              <TableShell minWidth={860}>
                <thead>
                  <tr>
                    <Th>Subject</Th>
                    <Th>Asset</Th>
                    <Th>Observed</Th>
                    <Th>Expected</Th>
                    <Th align="right">Severity</Th>
                    <Th>Detected</Th>
                  </tr>
                </thead>
                <tbody>
                  {violations.rows.map((violation) => (
                    <tr key={violation.id}>
                      <Td>
                        <div className="font-semibold text-white/85">{violation.subject}</div>
                        <div className="font-mono text-[9.5px] text-white/30">
                          {violation.subjectType} · {violation.source.table}
                        </div>
                      </Td>
                      <Td className={violation.assetName ? 'text-white/60' : 'text-white/25'}>{violation.assetName || '—'}</Td>
                      <Td className="text-red-300/85">{violation.observed}</Td>
                      <Td className="text-white/55">{violation.expected}</Td>
                      <Td align="right">
                        <SeverityBadge severity={violation.severity} />
                      </Td>
                      <Td className="text-white/40">{relativeTime(violation.detectedAt)}</Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
              <Pager offset={violationOffset} limit={25} total={violations.total} onChange={setViolationOffset} />
            </>
          ) : (
            <PanelEmpty>No violations for this rule under the current filters.</PanelEmpty>
          )}
        </Panel>
      ) : null}

      {/* ---- Controls ------------------------------------------------- */}
      <Panel id="controls">
        <SectionLabel
          icon={KeyRound}
          meta={controls.total ? `${fmtNumber(controls.total)} controls` : undefined}
          hint="Cryptographic and post-quantum controls, evaluated against the same subjects the policy rules use."
        >
          Cryptographic controls
        </SectionLabel>
        {controls.loading && !controls.rows.length ? (
          <GovernanceSkeleton rows={5} height={38} />
        ) : controls.rows.length ? (
          <>
            <TableShell minWidth={940}>
              <thead>
                <tr>
                  <Th>Control</Th>
                  <Th>Domain</Th>
                  <Th align="right">Score</Th>
                  <Th>Status</Th>
                  <Th align="right">Failing / scope</Th>
                  <Th align="right">Severity</Th>
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
                    <Td align="right">
                      <SeverityBadge severity={control.severity} />
                    </Td>
                    <Td>
                      <FreshnessChip state={control.evidenceFreshness} ageDays={control.evidenceAgeDays} />
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
          <PanelEmpty>No cryptographic controls in scope.</PanelEmpty>
        )}
      </Panel>

      {/* ---- Risk governance gaps -------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={ShieldAlert}
          meta={gaps.total ? `${fmtNumber(gaps.total)} gaps` : undefined}
          href="/dashboard/quantum-remediation"
          hint="Cryptographic and post-quantum governance gaps ordered by severity and by how much closing each one changes."
        >
          Risk governance
        </SectionLabel>
        {gaps.loading && !gaps.rows.length ? (
          <GovernanceSkeleton rows={3} height={110} />
        ) : gaps.rows.length ? (
          <div className="grid gap-2.5 lg:grid-cols-2">
            {gaps.rows.map((gap, index) => (
              <GapCard key={gap.id} gap={gap} index={index} onOpen={gap.controlIds.length ? () => setTarget({ kind: 'control', id: gap.controlIds[0] }) : undefined} />
            ))}
          </div>
        ) : (
          <PanelEmpty>No cryptographic governance gaps detected in the current evidence.</PanelEmpty>
        )}
      </Panel>

      <GovernanceProvenance telemetry={data.telemetry} />

      <GovernanceDrawers
        view="quantum"
        target={target}
        onTarget={setTarget}
        revision={revision}
        reconciliation={<ReconciliationPanel report={data.reconciliation} />}
      />
    </div>
  );
}
