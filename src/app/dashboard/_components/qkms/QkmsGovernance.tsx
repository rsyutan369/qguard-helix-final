'use client';

/**
 * QKMS Governance — policies, violations, custody and entropy.
 *
 * A violation here is one KEY failing one RULE of one POLICY, carrying the
 * evidence that proves it. The same records feed the ownership and custody
 * factors of that key's risk score, which is what makes brief section 17 hold:
 * a custody violation on this page necessarily raises that key's risk on the
 * Risk Analysis page.
 */

import { useCallback, useMemo, useState } from 'react';
import { Atom, Database, FileClock, Gavel, Plus, ShieldCheck } from 'lucide-react';
import { useKeyGovernance, useQkmsActions } from '@/hooks/use-qkms';
import { CUSTODY_LABEL, POLICY_RULE_LABEL } from '@/lib/qkms/types';
import type { Severity } from '@/lib/qkms/types';
import { KeyDrawer } from './KeyDrawer';
import {
  ActionButton,
  BarRow,
  ExplainBox,
  ExportMenu,
  FilterSelect,
  Kpi,
  Notice,
  Panel,
  PanelEmpty,
  Pill,
  QkmsShell,
  SectionLabel,
  SeverityBadge,
  TONE,
  absoluteTime,
  fmtNumber,
  relativeTime,
  useNotice,
  useQkmsExport,
} from './shell';

const ENTROPY_COPY: Record<string, { label: string; tone: 'good' | 'info' | 'warning' | 'neutral'; meaning: string }> = {
  detected: { label: 'Detected', tone: 'good', meaning: 'Quantum entropy is actively in use — entropy events or QRNG-attributed keys were observed.' },
  configured: { label: 'Configured', tone: 'info', meaning: 'A QRNG-capable backend is configured, but no entropy event has been observed from it yet.' },
  available: { label: 'Available', tone: 'warning', meaning: 'No quantum source is configured. A hardware RNG is available to keys held in hardware custody; the rest rely on the OS CSPRNG.' },
  'not-available': { label: 'Not available', tone: 'neutral', meaning: 'No quantum or hardware entropy source was found. QKMS will not assert a quantum-entropy claim without evidence.' },
};

export default function QkmsGovernance() {
  const { data, state, error, live, verifiedAt, refresh, reconnect } = useKeyGovernance();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [ruleFilter, setRuleFilter] = useState('');
  const [showPolicyForm, setShowPolicyForm] = useState(false);

  const actions = useQkmsActions(() => void refresh(true));
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const violations = useMemo(
    () => (data?.violations ?? []).filter((row) =>
      (!severityFilter || row.severity === severityFilter)
      && (!ruleFilter || row.rule === ruleFilter)),
    [data, severityFilter, ruleFilter],
  );

  const metrics = data?.metrics;
  const entropy = data?.entropy;
  const entropyCopy = entropy ? ENTROPY_COPY[entropy.status] : null;

  return (
    <QkmsShell
      icon={Gavel}
      title="QKMS"
      accent="Governance"
      subtitle="Evaluate configured rules against recorded key metadata, custody reports and entropy evidence."
      live={live}
      state={state}
      error={error}
      hasData={Boolean(data)}
      generatedAt={data?.generatedAt ?? null}
      verifiedAt={verifiedAt}
      latestEvidenceAt={data?.latestEvidenceAt ?? null}
      telemetry={data?.telemetry ?? null}
      nav={data?.nav ?? null}
      onRefresh={() => void refresh(true)}
      onReconnect={reconnect}
      actions={<ExportMenu onExport={onExport} busy={exporter.busy} />}
    >
      <Notice notice={notice} onDismiss={dismiss} />

      {metrics ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Kpi
            label="Open violations"
            value={fmtNumber(metrics.governanceViolations)}
            detail={`across ${fmtNumber(metrics.keysWithViolations)} of ${fmtNumber(metrics.totalKeys)} key(s)`}
            tone={metrics.governanceViolations > 0 ? 'critical' : 'good'}
            hint="One key failing one rule of one policy. Never mixed with key counts or scanner findings."
          />
          <Kpi
            label="Policies in force"
            value={fmtNumber((data?.policies ?? []).filter((policy) => policy.enabled).length)}
            detail={`${fmtNumber((data?.policies ?? []).filter((policy) => policy.origin === 'tenant').length)} tenant-authored`}
            tone="neutral"
          />
          <Kpi
            label="Approved custody"
            value={metrics.custodyCoveragePercent === null ? '—' : `${metrics.custodyCoveragePercent}%`}
            unmeasured={metrics.custodyCoveragePercent === null}
            detail={`of keys with KNOWN custody · ${fmtNumber(metrics.unmanagedCustodyKeys)} of ${fmtNumber(metrics.totalKeys)} unmanaged or unknown`}
            tone={metrics.unmanagedCustodyKeys > 0 ? 'warning' : 'good'}
            hint="HSM, managed KMS or vault share of the keys whose storage location is established. Keys with unknown custody are excluded from the percentage and counted beside it, so an estate of mostly unknown custody can read 100% here — read the two figures together."
          />
          <Kpi
            label="Audit coverage"
            value={metrics.auditReadinessPercent === null ? '—' : `${metrics.auditReadinessPercent}%`}
            unmeasured={metrics.auditReadinessPercent === null}
            detail={`${fmtNumber(metrics.auditEvidenceRecords)} evidence record(s)`}
            tone={(metrics.auditReadinessPercent ?? 0) >= 80 ? 'good' : 'warning'}
            hint="Share of live keys carrying at least one evidence or audit record."
          />
        </div>
      ) : null}

      {/* ---- Policies ------------------------------------------------ */}
      <Panel>
        <SectionLabel
          icon={ShieldCheck}
          meta={
            <button
              type="button"
              onClick={() => setShowPolicyForm((value) => !value)}
              className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200"
            >
              <Plus className="h-3 w-3" aria-hidden="true" /> New policy
            </button>
          }
          hint="Baseline policies ship with QKMS and are marked as such. A tenant policy of the same name supersedes the baseline."
        >
          Policies
        </SectionLabel>

        {showPolicyForm ? (
          <PolicyForm
            busy={actions.pending === 'policy:new'}
            onCancel={() => setShowPolicyForm(false)}
            onSubmit={async (body) => {
              const result = await actions.createPolicy(body);
              show(result.ok, result.message);
              if (result.ok) setShowPolicyForm(false);
            }}
          />
        ) : null}

        {data?.policies.length ? (
          <div className="mt-3 grid gap-2 lg:grid-cols-2">
            {data.policies.map((policy) => (
              <div key={policy.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <h3 className="truncate text-[12px] font-black text-white">{policy.name}</h3>
                    <p className="mt-0.5 text-[10.5px] leading-snug text-white/45">{policy.description}</p>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <SeverityBadge severity={policy.severity} />
                    <Pill tone={policy.origin === 'baseline' ? 'neutral' : 'info'}>{policy.origin}</Pill>
                  </div>
                </div>

                <div className="mt-2.5 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-md border border-white/10 bg-black/20 py-1.5">
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/35">In scope</div>
                    <div className="font-mono text-[13px] font-black text-white">{fmtNumber(policy.keysInScope)}</div>
                  </div>
                  <div className="rounded-md border border-white/10 bg-black/20 py-1.5">
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Violations</div>
                    <div className={`font-mono text-[13px] font-black ${policy.violations > 0 ? 'text-red-300' : 'text-white/40'}`}>{fmtNumber(policy.violations)}</div>
                  </div>
                  <div
                    className="rounded-md border border-white/10 bg-black/20 py-1.5"
                    title={policy.compliance === null
                      ? policy.evaluation === 'disabled'
                        ? 'This policy is disabled, so it evaluated no key. That is not 100% compliance.'
                        : policy.evaluation === 'no-keys-in-scope'
                          ? 'No operational key falls inside this policy’s scope.'
                          : 'Some keys are missing the evidence needed to evaluate every configured rule.'
                      : `${policy.compliance}% of ${policy.keysInScope} in-scope keys passed the configured metadata rules.`}
                  >
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Policy pass rate</div>
                    {policy.compliance === null ? (
                      <div className="font-mono text-[11px] font-black uppercase tracking-wide text-white/40">{policy.evaluation === 'evaluated' ? 'Evidence needed' : 'Not evaluated'}</div>
                    ) : (
                      <div className={`font-mono text-[13px] font-black ${policy.compliance >= 95 ? 'text-emerald-300' : policy.compliance >= 70 ? 'text-amber-300' : 'text-red-300'}`}>{policy.compliance}%</div>
                    )}
                  </div>
                </div>
                {policy.evaluation !== 'evaluated' ? (
                  <p className="mt-1.5 text-[10px] leading-snug text-white/40">
                    {policy.evaluation === 'disabled'
                      ? 'Disabled — configured but not enforced. No key is evaluated against it.'
                      : 'Enabled, but no key is in its scope yet — configured, not yet evaluated.'}
                  </p>
                ) : null}

                <div className="mt-2 flex flex-wrap gap-1">
                  <Pill tone="neutral">{policy.environmentScope}</Pill>
                  {policy.requireOwner ? <Pill tone="neutral">Owner required</Pill> : null}
                  {policy.requireHsm ? <Pill tone="neutral">HSM required</Pill> : null}
                  {policy.requirePqc ? <Pill tone="neutral">PQC required</Pill> : null}
                  {!policy.allowExport ? <Pill tone="neutral">Policy prohibits export</Pill> : null}
                  {policy.rotationIntervalDays ? <Pill tone="neutral">Rotate {policy.rotationIntervalDays}d</Pill> : null}
                  {policy.maxKeyAgeDays ? <Pill tone="neutral">Max age {policy.maxKeyAgeDays}d</Pill> : null}
                </div>

                {policy.origin === 'tenant' ? (
                  <div className="mt-2">
                    <ActionButton
                      label={policy.enabled ? 'Disable' : 'Enable'}
                      tone={policy.enabled ? 'warning' : 'good'}
                      busy={actions.pending === `policy:${policy.id}`}
                      onClick={async () => {
                        const result = await actions.updatePolicy(policy.id, { enabled: !policy.enabled });
                        show(result.ok, result.message);
                      }}
                    />
                  </div>
                ) : (
                  <p className="mt-2 text-[10px] text-white/30">Baseline policy — create a tenant policy of the same name to override it.</p>
                )}
              </div>
            ))}
          </div>
        ) : <PanelEmpty>No policies are configured.</PanelEmpty>}
      </Panel>

      {/* ---- Violations ---------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Gavel}
          meta={<span>{fmtNumber(violations.length)} shown · {fmtNumber(data?.violationsTotal ?? 0)} total</span>}
        >
          Governance violations
        </SectionLabel>

        <div className="mb-3 flex flex-wrap gap-2">
          <FilterSelect
            label="Severity"
            value={severityFilter}
            onChange={setSeverityFilter}
            options={[
              { value: '', label: 'All severities' },
              ...(data?.violationsBySeverity ?? []).map((row) => ({ value: row.label, label: `${row.label} (${row.count})` })),
            ]}
          />
          <FilterSelect
            label="Rule"
            value={ruleFilter}
            onChange={setRuleFilter}
            options={[
              { value: '', label: 'All rules' },
              ...Object.entries(POLICY_RULE_LABEL).map(([value, label]) => ({ value, label })),
            ]}
          />
        </div>

        {violations.length ? (
          <ul className="space-y-2">
            {violations.map((violation) => (
              <li key={violation.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={violation.severity} />
                    <Pill tone="neutral">{POLICY_RULE_LABEL[violation.rule] || violation.rule}</Pill>
                    <span className="font-mono text-[9.5px] text-white/35">{violation.policyName}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedKey(violation.keyId)}
                    className="truncate text-[11px] font-bold text-cyan-300 hover:text-cyan-200"
                  >
                    {violation.keyLabel}
                  </button>
                </div>
                <p className="mt-1.5 text-[11.5px] leading-relaxed text-white/70">{violation.detail}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-cyan-300/80">{violation.remediation}</p>
                {violation.evidence.length ? (
                  <p className="mt-1.5 font-mono text-[9.5px] text-white/30">
                    Evidence: {violation.evidence.map((ref) => `${ref.table}:${ref.recordId.slice(0, 12)}`).join(' · ')}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <PanelEmpty>
            {(data?.violationsTotal ?? 0) > 0
              ? 'No violation matches these filters.'
              : metrics?.totalKeys
                ? 'No key violates a policy in force. This is a real result: every key was evaluated against every enabled policy.'
                : 'No keys have been discovered to evaluate against policy.'}
          </PanelEmpty>
        )}

        {data?.violationsByRule.length ? (
          <div className="mt-4">
            <h3 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Violations by rule</h3>
            <div className="space-y-0.5">
              {data.violationsByRule.map((row) => (
                <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone="critical" />
              ))}
            </div>
          </div>
        ) : null}
      </Panel>

      {/* ---- Custody + entropy --------------------------------------- */}
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel>
          <SectionLabel
            icon={Database}
            hint="A backend marked 'configured' was declared by you. One marked 'observed' was inferred from where keys were found — QKMS does not claim you configured it."
          >
            Storage backends
          </SectionLabel>
          {data?.backends.length ? (
            <div className="space-y-2">
              {data.backends.map((backend) => (
                <div key={backend.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="truncate text-[12px] font-black text-white">{backend.name}</h3>
                      <p className="mt-0.5 text-[10px] text-white/40">{backend.provider} · {backend.location}</p>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <Pill tone={backend.hsmBacked ? 'good' : backend.custody === 'unmanaged' || backend.custody === 'unknown' ? 'critical' : 'info'}>
                        {CUSTODY_LABEL[backend.custody]}
                      </Pill>
                      <Pill tone={backend.status === 'configured' ? 'good' : backend.status === 'observed' ? 'info' : 'warning'}>{backend.status}</Pill>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-[10.5px] text-white/45">
                    <span><span className="font-mono font-black text-white">{fmtNumber(backend.keys)}</span> key(s)</span>
                    <span className={backend.violations > 0 ? 'text-red-300' : ''}>
                      <span className="font-mono font-black">{fmtNumber(backend.violations)}</span> violation(s)
                    </span>
                    <span title={absoluteTime(backend.lastVerifiedAt)}>verified {relativeTime(backend.lastVerifiedAt)}</span>
                  </div>
                  <p className="mt-1 text-[10px] text-white/35">{backend.protectionLevel}</p>
                </div>
              ))}
            </div>
          ) : <PanelEmpty>No storage backend has been declared or observed.</PanelEmpty>}

          {data?.custodyDistribution.length ? (
            <div className="mt-3">
              <h3 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Keys by backend</h3>
              <div className="space-y-0.5">
                {data.custodyDistribution.map((row) => (
                  <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone={/HSM|KMS|Vault/i.test(row.label) ? 'good' : /Unknown/i.test(row.label) ? 'neutral' : 'warning'} />
                ))}
              </div>
            </div>
          ) : null}
        </Panel>

        <Panel>
          <SectionLabel
            icon={Atom}
            hint="Four distinct states, each requiring its own evidence. 'Available' is never claimed from the platform's general capability — only from a tenant record that advertises the source."
          >
            Entropy and QRNG
          </SectionLabel>
          {entropy && entropyCopy ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Pill tone={entropyCopy.tone}>
                  <span className={`h-1.5 w-1.5 rounded-full ${TONE[entropyCopy.tone].dot}`} aria-hidden="true" />
                  {entropyCopy.label}
                </Pill>
                {entropy.source ? <span className="font-mono text-[10.5px] text-white/50">{entropy.source}</span> : null}
              </div>

              <ExplainBox tone={entropyCopy.tone} title="What this means">{entropyCopy.meaning}</ExplainBox>
              <p className="mt-2 text-[11.5px] leading-relaxed text-white/60">{entropy.detail}</p>

              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                <div className="rounded-md border border-white/10 bg-black/25 py-2">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Entropy events</div>
                  <div className="font-mono text-[15px] font-black text-white">{fmtNumber(entropy.events)}</div>
                </div>
                <div className="rounded-md border border-white/10 bg-black/25 py-2">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Attributed keys</div>
                  <div className="font-mono text-[15px] font-black text-white">{fmtNumber(entropy.attributedKeys)}</div>
                </div>
                <div className="rounded-md border border-white/10 bg-black/25 py-2">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Latest</div>
                  <div className="font-mono text-[11px] font-black text-white">{relativeTime(entropy.latestAt)}</div>
                </div>
              </div>

              {entropy.distribution.length ? (
                <div className="mt-3">
                  <h3 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Entropy sources by key</h3>
                  <div className="space-y-0.5">
                    {entropy.distribution.map((row) => (
                      <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone={/qrng|quantum/i.test(row.label) ? 'good' : 'neutral'} />
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : <PanelEmpty>No entropy posture could be established.</PanelEmpty>}
        </Panel>
      </div>

      {/* ---- Audit --------------------------------------------------- */}
      <Panel>
        <SectionLabel icon={FileClock} meta={<span>{fmtNumber(data?.audit.length ?? 0)}</span>} hint="Who, what, when, and the before/after state — recorded automatically for every governed operation.">
          Audit evidence
        </SectionLabel>
        {data?.audit.length ? (
          <div className="-mx-1 overflow-x-auto px-1">
            <table className="w-full text-left text-[11.5px]" style={{ minWidth: 820 }}>
              <thead>
                <tr>
                  {['Event', 'Type', 'Actor', 'Key', 'Recorded', 'Source'].map((heading) => (
                    <th key={heading} scope="col" className="sticky top-0 z-10 border-b border-white/10 bg-[#0b1424] px-2.5 py-2 text-[9px] font-black uppercase tracking-[0.12em] text-white/45">
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.audit.map((row) => (
                  <tr key={row.id}>
                    <td className="border-b border-white/[0.06] px-2.5 py-2 text-white/75">{row.title}</td>
                    <td className="border-b border-white/[0.06] px-2.5 py-2"><span className="font-mono text-[10px] text-cyan-300">{row.eventType}</span></td>
                    <td className="border-b border-white/[0.06] px-2.5 py-2 text-white/55">{row.actor}</td>
                    <td className="border-b border-white/[0.06] px-2.5 py-2">
                      {row.keyId ? (
                        <button type="button" onClick={() => setSelectedKey(row.keyId!)} className="text-cyan-300 hover:text-cyan-200">
                          {row.keyLabel || row.keyId}
                        </button>
                      ) : <span className="text-white/30">—</span>}
                    </td>
                    <td className="border-b border-white/[0.06] px-2.5 py-2"><span className="font-mono text-[10px] text-white/45" title={absoluteTime(row.at)}>{relativeTime(row.at)}</span></td>
                    <td className="border-b border-white/[0.06] px-2.5 py-2"><span className="font-mono text-[9.5px] text-white/35">{row.table}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <PanelEmpty>
            No audit evidence has been recorded yet. Key operations performed through QKMS are logged here automatically.
          </PanelEmpty>
        )}
      </Panel>

      <KeyDrawer keyId={selectedKey} syncTo={data?.generatedAt ?? null} onClose={() => setSelectedKey(null)} onChanged={() => void refresh(true)} />
    </QkmsShell>
  );
}

/* ------------------------------------------------------------------ */
/* Policy form                                                         */
/* ------------------------------------------------------------------ */

function PolicyForm({
  onSubmit,
  onCancel,
  busy,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  const [form, setForm] = useState({
    name: '',
    description: '',
    environmentScope: 'production',
    severity: 'high' as Severity,
    rotationIntervalDays: 180,
    maxKeyAgeDays: 365,
    requireOwner: true,
    requireHsm: true,
    requirePqc: false,
    allowExport: false,
    blockedAlgorithms: 'RSA-2048, ECDSA P-256, 3DES, RC4',
  });

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (!form.name.trim()) return;
        onSubmit({ ...form, name: form.name.trim() });
      }}
      className="rounded-lg border border-cyan-400/25 bg-cyan-500/5 p-3"
    >
      <div className="grid gap-2 lg:grid-cols-2">
        <label className="block">
          <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Policy name</span>
          <input
            required
            value={form.name}
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
            placeholder="e.g. Production key custody"
            className="mt-1 h-8 w-full rounded-md border border-white/12 bg-black/30 px-2.5 text-[11px] text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          />
        </label>
        <label className="block">
          <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Description</span>
          <input
            value={form.description}
            onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
            placeholder="What this policy enforces and why"
            className="mt-1 h-8 w-full rounded-md border border-white/12 bg-black/30 px-2.5 text-[11px] text-white outline-none placeholder:text-white/30 focus-visible:ring-2 focus-visible:ring-cyan-300/70"
          />
        </label>
      </div>

      <div className="mt-2 flex flex-wrap gap-2">
        <FilterSelect
          label="Scope"
          value={form.environmentScope}
          onChange={(value) => setForm((current) => ({ ...current, environmentScope: value }))}
          options={['all', 'production', 'staging', 'development'].map((value) => ({ value, label: value }))}
        />
        <FilterSelect
          label="Severity"
          value={form.severity}
          onChange={(value) => setForm((current) => ({ ...current, severity: value as Severity }))}
          options={['critical', 'high', 'medium', 'low'].map((value) => ({ value, label: value }))}
        />
        <label className="flex items-center gap-1.5">
          <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Rotate (days)</span>
          <input
            type="number"
            min={1}
            max={3650}
            value={form.rotationIntervalDays}
            onChange={(event) => setForm((current) => ({ ...current, rotationIntervalDays: Number(event.target.value) || 180 }))}
            className="h-8 w-20 rounded-md border border-white/12 bg-black/30 px-2 text-[11px] text-white outline-none"
          />
        </label>
        <label className="flex items-center gap-1.5">
          <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Max age (days)</span>
          <input
            type="number"
            min={1}
            max={3650}
            value={form.maxKeyAgeDays}
            onChange={(event) => setForm((current) => ({ ...current, maxKeyAgeDays: Number(event.target.value) || 365 }))}
            className="h-8 w-20 rounded-md border border-white/12 bg-black/30 px-2 text-[11px] text-white outline-none"
          />
        </label>
      </div>

      <label className="mt-2 block">
        <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Blocked algorithms (comma separated)</span>
        <input
          value={form.blockedAlgorithms}
          onChange={(event) => setForm((current) => ({ ...current, blockedAlgorithms: event.target.value }))}
          className="mt-1 h-8 w-full rounded-md border border-white/12 bg-black/30 px-2.5 font-mono text-[11px] text-white outline-none"
        />
        <span className="mt-1 block text-[9.5px] text-white/30">
          Matched on whole algorithm tokens, so &ldquo;DSA&rdquo; blocks ECDSA and DSA without ever matching ML-DSA or SLH-DSA.
        </span>
      </label>

      <div className="mt-2 flex flex-wrap gap-3">
        {([
          ['requireOwner', 'Require owner'],
          ['requireHsm', 'Require HSM'],
          ['requirePqc', 'Require PQC migration'],
          ['allowExport', 'Allow export'],
        ] as const).map(([field, label]) => (
          <label key={field} className="flex items-center gap-1.5 text-[10.5px] font-semibold text-white/60">
            <input
              type="checkbox"
              checked={form[field]}
              onChange={(event) => setForm((current) => ({ ...current, [field]: event.target.checked }))}
              className="h-3.5 w-3.5 accent-cyan-400"
            />
            {label}
          </label>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <ActionButton label="Create policy" icon={Plus} tone="good" busy={busy} onClick={() => { if (form.name.trim()) onSubmit({ ...form, name: form.name.trim() }); }} />
        <button type="button" onClick={onCancel} className="px-2 text-[10px] font-black uppercase tracking-wider text-white/40 hover:text-white/70">
          Cancel
        </button>
      </div>
    </form>
  );
}
