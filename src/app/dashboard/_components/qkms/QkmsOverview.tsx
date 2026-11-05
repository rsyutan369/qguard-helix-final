'use client';

/**
 * QKMS Overview — the command centre.
 *
 * Answers, in order: what does the estate hold, how healthy is it, what is
 * blocking the post-quantum migration, and what needs attention now. Every
 * figure is a link into the page that owns it, so no number on this page is a
 * dead end (brief section 8: "Every number must drill down").
 */

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  CircleGauge,
  FileClock,
  GitBranch,
  KeyRound,
  Layers,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { useQkmsOverview, useQkmsActions } from '@/hooks/use-qkms';
import { KeyDrawer } from './KeyDrawer';
import { GateField, MeasuredGauge } from './motion';
import {
  BarRow,
  ExplainBox,
  ExportMenu,
  GateBadge,
  KeyTable,
  Kpi,
  Measured,
  Notice,
  Panel,
  PanelEmpty,
  Pill,
  QkmsShell,
  SectionLabel,
  SeverityBadge,
  TONE,
  fmtNumber,
  postureTone,
  distributionTone,
  gateTone,
  relativeTime,
  useNotice,
  useQkmsExport,
  whenRelative,
} from './shell';

export default function QkmsOverview() {
  const { data, state, error, live, verifiedAt, refresh, reconnect } = useQkmsOverview();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const actions = useQkmsActions(() => void refresh(true));
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const gate = data?.gate ?? null;
  const metrics = data?.metrics;

  const custodyRows = useMemo(() => data?.distributions.custody ?? [], [data]);
  const postureRows = useMemo(() => data?.distributions.postures ?? [], [data]);

  return (
    <QkmsShell
      icon={CircleGauge}
      title="QKMS"
      accent="Command Center"
      subtitle="One governed view of the cryptographic key estate: what exists, who owns it, how it is protected, and whether it can pass the post-quantum migration gate."
      live={live}
      state={state}
      error={error}
      hasData={data?.hasData ?? false}
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

      {/* ---- Migration gate: the headline decision ------------------- */}
      {gate ? (
        <Panel>
          <GateField tone={gateTone(gate.state)} live={live} />
          <div className="relative">
          <SectionLabel
            icon={ShieldCheck}
            href="/dashboard/qkms/readiness"
            hint="The gate is a decision, not a score. It states why, what evidence supports it, what blocks it, and what to do next."
            meta={gate.score !== null ? <span>{gate.score}% of prechecks pass</span> : undefined}
          >
            Migration gate
          </SectionLabel>

          <div className="flex flex-wrap items-center gap-4">
            <MeasuredGauge value={gate.score} tone={gateTone(gate.state)} label="Prechecks" />
            <div className="min-w-0 flex-1 space-y-2">
              <GateBadge state={gate.state} />
              <p className="text-[12.5px] leading-relaxed text-white/75">{gate.why}</p>
            </div>
          </div>

          {gate.blockers.length ? (
            <div className="mt-3">
              <h3 className="text-[9px] font-black uppercase tracking-wider text-red-300/80">Blocking</h3>
              <ul className="mt-1.5 space-y-1">
                {gate.blockers.map((blocker) => (
                  <li key={blocker} className="rounded-md border border-red-500/20 bg-red-500/5 px-2.5 py-1.5 text-[11px] leading-snug text-red-200/85">
                    {blocker}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {gate.requiredActions.length ? (
            <div className="mt-3">
              <h3 className="text-[9px] font-black uppercase tracking-wider text-white/35">Required to proceed</h3>
              <ol className="mt-1.5 space-y-1">
                {gate.requiredActions.map((action, index) => (
                  <li key={action} className="flex gap-2 rounded-md border border-white/10 bg-black/25 px-2.5 py-1.5 text-[11px] leading-snug text-white/65">
                    <span className="font-mono text-cyan-300">{index + 1}.</span>
                    {action}
                  </li>
                ))}
              </ol>
            </div>
          ) : null}
          </div>
        </Panel>
      ) : null}

      {/* ---- Estate KPIs -------------------------------------------- */}
      {metrics ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Kpi
            label="Keys under management"
            value={fmtNumber(metrics.totalKeys)}
            detail={`${fmtNumber(metrics.activeKeys)} active · ${fmtNumber(metrics.inUseKeys)} with observed usage`}
            tone="neutral"
            href="/dashboard/qkms/inventory"
            hint="Distinct key identities. Rows describing the same key material across the registry, generated keys, certificates, inventory and agent scans collapse onto one record."
          />
          <Kpi
            label="PQC readiness"
            value={metrics.pqcReadinessPercent === null ? '—' : `${metrics.pqcReadinessPercent}%`}
            unmeasured={metrics.pqcReadinessPercent === null}
            detail={`${fmtNumber(metrics.pqcReadyKeys)} post-quantum · ${fmtNumber(metrics.hybridKeys)} hybrid${metrics.declaredPqcKeys ? ` · ${fmtNumber(metrics.declaredPqcKeys)} declared, unverified` : ''}`}
            tone={metrics.pqcReadinessPercent !== null && metrics.pqcReadinessPercent >= 80 ? 'good' : 'warning'}
            href="/dashboard/qkms/readiness"
            hint="Post-quantum or hybrid share of keys that actually need a quantum decision. Symmetric and hash keys are excluded — they were never at Shor risk, and counting them would inflate this figure. Only EVIDENCED post-quantum material counts: a key whose PQC algorithm is only declared in the registry, with no scan or certificate confirming it, is shown as unverified and excluded."
          />
          <Kpi
            label="Critical-risk keys"
            value={fmtNumber(metrics.criticalRiskKeys)}
            detail={`${fmtNumber(metrics.highRiskKeys)} high · average ${metrics.averageRiskScore ?? '—'}`}
            tone={metrics.criticalRiskKeys > 0 ? 'critical' : 'good'}
            href="/dashboard/qkms/risk-analysis"
            hint="Weighted risk of 80 or above. One model produces this score and every QKMS page renders that same number."
          />
          <Kpi
            label="Governance violations"
            value={fmtNumber(metrics.governanceViolations)}
            detail={`across ${fmtNumber(metrics.keysWithViolations)} key(s)`}
            tone={metrics.governanceViolations > 0 ? 'critical' : 'good'}
            href="/dashboard/qkms/governance"
            hint="One key failing one rule of one policy. Counted in violations, never mixed with key counts or scanner findings."
          />

          <Kpi
            label="Rotation overdue"
            value={fmtNumber(metrics.rotationOverdueKeys)}
            detail={`${fmtNumber(metrics.rotationDueKeys)} due · ${fmtNumber(metrics.neverRotatedKeys)} never rotated`}
            tone={metrics.rotationOverdueKeys > 0 ? 'critical' : 'good'}
            href="/dashboard/qkms/rotation"
          />
          <Kpi
            label="Expiry pressure"
            value={fmtNumber(metrics.expiringSoonKeys)}
            detail={`${fmtNumber(metrics.expiredKeys)} already expired`}
            tone={metrics.expiredKeys > 0 ? 'critical' : metrics.expiringSoonKeys > 0 ? 'warning' : 'good'}
            href="/dashboard/qkms/lifecycle"
            hint="Keys inside the 45-day replacement window."
          />
          <Kpi
            label="Custody coverage"
            value={metrics.custodyCoveragePercent === null ? '—' : `${metrics.custodyCoveragePercent}%`}
            unmeasured={metrics.custodyCoveragePercent === null}
            detail={`${fmtNumber(metrics.hsmProtectedKeys)} HSM-backed · ${fmtNumber(metrics.unmanagedCustodyKeys)} unmanaged or unknown`}
            tone={metrics.unmanagedCustodyKeys > 0 ? 'warning' : 'good'}
            href="/dashboard/qkms/governance"
            hint="Share of keys with KNOWN custody that sit in an HSM, managed KMS or vault. Keys whose custody could not be established are excluded from the numerator and named separately."
          />
          <Kpi
            label="Ownership gaps"
            value={fmtNumber(metrics.orphanedKeys)}
            detail="No accountable owner — blocks rotation and migration approval"
            tone={metrics.orphanedKeys > 0 ? 'warning' : 'good'}
            href="/dashboard/qkms/lifecycle"
          />
        </div>
      ) : null}

      {/* ---- Posture, lifecycle, risk -------------------------------- */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel>
          <SectionLabel icon={Sparkles} href="/dashboard/qkms/readiness">PQC posture</SectionLabel>
          {postureRows.length ? (
            <div className="space-y-0.5">
              {postureRows.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={distributionTone(row)}
                />
              ))}
            </div>
          ) : <PanelEmpty>No key posture has been classified yet.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={GitBranch} href="/dashboard/qkms/lifecycle">Lifecycle distribution</SectionLabel>
          {data?.lifecycleFunnel.length ? (
            <div className="space-y-0.5">
              {data.lifecycleFunnel.filter((row) => row.count > 0).map((row) => (
                <BarRow
                  key={row.state}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={
                    row.state === 'rotation-overdue' || row.state === 'expired' ? 'critical'
                      : row.state === 'rotation-due' || row.state === 'suspended' ? 'warning'
                        : row.state === 'active' || row.state === 'in-use' || row.state === 'rotated' ? 'good' : 'neutral'
                  }
                />
              ))}
            </div>
          ) : <PanelEmpty>No lifecycle state has been established for any key.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={ShieldAlert} href="/dashboard/qkms/risk-analysis">Risk distribution</SectionLabel>
          {data?.riskDistribution.length ? (
            <div className="space-y-0.5">
              {data.riskDistribution.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={/Critical/.test(row.label) ? 'critical' : /High/.test(row.label) ? 'critical' : /Medium/.test(row.label) ? 'warning' : 'good'}
                />
              ))}
            </div>
          ) : <PanelEmpty>No key risk has been scored yet.</PanelEmpty>}
        </Panel>
      </div>

      {/* ---- Rotation posture + custody ------------------------------ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel>
          <SectionLabel
            icon={RefreshCw}
            href="/dashboard/qkms/rotation"
            hint="The denominator is keys whose rotation state can be determined. Keys with no creation, rotation or expiry evidence are excluded rather than counted as healthy."
          >
            Rotation posture
          </SectionLabel>
          {data?.rotationPosture ? (
            <>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {[
                  { label: 'Healthy', value: data.rotationPosture.healthy, tone: 'good' as const },
                  { label: 'Due', value: data.rotationPosture.due, tone: 'warning' as const },
                  { label: 'Overdue', value: data.rotationPosture.overdue, tone: 'critical' as const },
                  { label: 'Failed', value: data.rotationPosture.failed, tone: 'critical' as const },
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="text-[9px] font-black uppercase tracking-wider text-white/35">{item.label}</div>
                    <div className={`mt-1 text-xl font-black tabular-nums ${TONE[item.tone].text}`}>{fmtNumber(item.value)}</div>
                  </div>
                ))}
              </div>
              <div className="mt-2.5 grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Rotation health</div>
                  <div className="mt-1 text-[13px] font-black text-white"><Measured value={data.rotationPosture.healthPercent} fallback="Not determinable" /></div>
                  <div className="mt-0.5 text-[10px] text-white/35">{fmtNumber(data.rotationPosture.governedKeys)} governed key(s)</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Work-order success</div>
                  <div className="mt-1 text-[13px] font-black text-white"><Measured value={data.rotationPosture.successRate} fallback="No order has terminated" /></div>
                  <div className="mt-0.5 text-[10px] text-white/35">{fmtNumber(data.rotationPosture.jobsActive)} open</div>
                </div>
                <div className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/35">Next due</div>
                  <div className="mt-1 text-[13px] font-black text-white">{data.rotationPosture.nextDueAt ? whenRelative(data.rotationPosture.nextDueAt) : '—'}</div>
                  <div className="mt-0.5 text-[10px] text-white/35">blast radius {fmtNumber(data.rotationPosture.blastRadius)}</div>
                </div>
              </div>
            </>
          ) : <PanelEmpty>No rotation posture has been established.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={Lock} href="/dashboard/qkms/governance">Custody distribution</SectionLabel>
          {custodyRows.length ? (
            <div className="space-y-0.5">
              {custodyRows.map((row) => (
                <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone={/HSM|KMS|Vault/i.test(row.label) ? 'good' : /Unknown/i.test(row.label) ? 'neutral' : 'warning'} />
              ))}
            </div>
          ) : <PanelEmpty>No storage backend has been attributed to any key.</PanelEmpty>}

          {data?.entropy ? (
            <ExplainBox
              tone={data.entropy.status === 'detected' ? 'good' : data.entropy.status === 'not-available' ? 'neutral' : 'info'}
              title={`Entropy: ${data.entropy.status.replace(/-/g, ' ')}`}
            >
              {data.entropy.detail}
            </ExplainBox>
          ) : null}
        </Panel>
      </div>

      {/* ---- Highest-risk keys -------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={KeyRound}
          href="/dashboard/qkms/risk-analysis"
          meta={<span>Top {fmtNumber(data?.topRisks.length ?? 0)} of {fmtNumber(metrics?.totalKeys ?? 0)}</span>}
        >
          Highest-risk keys
        </SectionLabel>
        <KeyTable
          keys={data?.topRisks ?? []}
          columns={['key', 'algorithm', 'owner', 'asset', 'environment', 'custody', 'posture', 'lifecycle', 'rotation', 'violations', 'risk']}
          onSelect={setSelectedKey}
          selectedId={selectedKey}
          emptyMessage="No key risk has been scored for this tenant yet."
        />
      </Panel>

      {/* ---- Attention + violations + audit -------------------------- */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel>
          <SectionLabel icon={AlertTriangle}>Needs attention</SectionLabel>
          {data ? (
            <ul className="space-y-1.5">
              {[
                { label: 'Expired keys still in the estate', value: data.attention.expired, href: '/dashboard/qkms/lifecycle', tone: 'critical' as const },
                { label: 'Expiring within 45 days', value: data.attention.expiringSoon, href: '/dashboard/qkms/lifecycle', tone: 'warning' as const },
                { label: 'Rotation overdue or failed', value: data.attention.overdueRotation, href: '/dashboard/qkms/rotation', tone: 'critical' as const },
                { label: 'Keys with no owner', value: data.attention.orphaned, href: '/dashboard/qkms/lifecycle', tone: 'warning' as const },
              ].map((item) => (
                <li key={item.label}>
                  <Link
                    to={item.href}
                    className={`flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2 no-underline transition hover:brightness-125 ${item.value > 0 ? `${TONE[item.tone].border} ${TONE[item.tone].soft}` : 'border-white/10 bg-black/25'}`}
                  >
                    <span className="text-[11px] font-semibold text-white/70">{item.label}</span>
                    <span className={`font-mono text-sm font-black tabular-nums ${item.value > 0 ? TONE[item.tone].text : 'text-white/30'}`}>
                      {fmtNumber(item.value)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : null}
        </Panel>

        <Panel>
          <SectionLabel icon={Layers} href="/dashboard/qkms/governance">Top governance violations</SectionLabel>
          {data?.topViolations.length ? (
            <ul className="space-y-1.5">
              {data.topViolations.map((violation) => (
                <li key={violation.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <SeverityBadge severity={violation.severity} />
                    <button
                      type="button"
                      onClick={() => setSelectedKey(violation.keyId)}
                      className="truncate font-mono text-[9.5px] text-cyan-300 hover:text-cyan-200"
                    >
                      {violation.keyLabel}
                    </button>
                  </div>
                  <p className="mt-1.5 text-[11px] leading-snug text-white/65">{violation.detail}</p>
                </li>
              ))}
            </ul>
          ) : (
            <PanelEmpty>
              {metrics?.totalKeys ? 'No key violates a policy in force.' : 'No keys have been discovered to evaluate against policy.'}
            </PanelEmpty>
          )}
        </Panel>

        <Panel>
          <SectionLabel icon={FileClock} href="/dashboard/qkms/governance">Recent audit evidence</SectionLabel>
          {data?.recentAudit.length ? (
            <ol className="space-y-1.5">
              {data.recentAudit.map((entry) => (
                <li key={entry.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-[10px] text-cyan-300">{entry.eventType}</span>
                    <span className="font-mono text-[9.5px] text-white/35">{relativeTime(entry.at)}</span>
                  </div>
                  <p className="mt-1 truncate text-[11px] text-white/65" title={entry.title}>{entry.title}</p>
                </li>
              ))}
            </ol>
          ) : (
            <PanelEmpty>
              No audit evidence has been recorded yet. Key operations performed through QKMS are logged here automatically.
            </PanelEmpty>
          )}
        </Panel>
      </div>

      {/* ---- Algorithm portfolio ------------------------------------- */}
      <Panel>
        <SectionLabel icon={Activity} href="/dashboard/qkms/inventory">Algorithm portfolio</SectionLabel>
        {data?.distributions.algorithms.length ? (
          <div className="grid gap-x-5 gap-y-0.5 lg:grid-cols-2">
            {data.distributions.algorithms.map((row) => (
              <BarRow
                key={row.label}
                label={row.label}
                count={row.count}
                percent={row.percent}
                tone={distributionTone(row)}
                suffix={<Pill tone={postureTone('unknown')} className="hidden xl:inline-flex">{row.count === 1 ? '1 key' : `${row.count} keys`}</Pill>}
              />
            ))}
          </div>
        ) : <PanelEmpty>No key algorithms have been discovered.</PanelEmpty>}
      </Panel>

      <KeyDrawer keyId={selectedKey} syncTo={data?.generatedAt ?? null} onClose={() => setSelectedKey(null)} onChanged={() => void refresh(true)} />
    </QkmsShell>
  );
}
