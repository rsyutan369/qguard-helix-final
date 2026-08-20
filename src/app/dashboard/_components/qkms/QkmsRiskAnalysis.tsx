'use client';

/**
 * Key Risk Intelligence.
 *
 * The score shown here is the SAME score Inventory, Lifecycle, Rotation and
 * every export show for the same key, because it is produced once in
 * `lib/qkms/risk.ts` and only projected. Before this refactor the backend
 * published one model and this page recomputed a different one in the browser,
 * so a key could read 62 on Inventory and 81 here in the same session.
 *
 * Section 16 of the brief: "Every risk score must be explainable. Do not simply
 * display a number. Show: Risk Score → Contributing Factors → Evidence →
 * Recommended Action." Every row on this page opens a drawer that does exactly
 * that, and the factor decomposition is visible on the page itself.
 */

import { useCallback, useMemo, useState } from 'react';
import { Activity, ClipboardCheck, Gauge, Layers, ShieldAlert, Sparkles } from 'lucide-react';
import { useKeyRiskAnalysis, useKeyQuery, useQkmsActions } from '@/hooks/use-qkms';
import { RISK_WEIGHTS } from '@/lib/qkms/types';
import { KeyDrawer } from './KeyDrawer';
import {
  BarRow,
  ExplainBox,
  ExportMenu,
  FilterSelect,
  KeyTable,
  Kpi,
  Notice,
  Pager,
  Panel,
  PanelEmpty,
  QkmsShell,
  RiskBadge,
  SectionLabel,
  TONE,
  fmtNumber,
  useNotice,
  useQkmsExport,
  type KeyColumn,
} from './shell';

const COLUMNS: KeyColumn[] = [
  'key', 'algorithm', 'owner', 'asset', 'environment', 'custody',
  'posture', 'lifecycle', 'rotation', 'violations', 'risk',
];

/** What each factor actually measures — shown next to its average. */
const FACTOR_MEANING: Record<string, string> = {
  algorithm: 'Whether the primitive is broken, weakened or current — judged on the algorithm alone, never on surrounding metadata.',
  quantum: 'Shor exposure for asymmetric material and Grover exposure for symmetric. A 256-bit symmetric key scores low here by design.',
  lifecycle: 'Expiry proximity, key age and whether the key has fallen outside lifecycle governance.',
  rotation: 'Rotation obligation against the interval, and whether a work order has failed.',
  ownership: 'Whether an accountable owner exists, and open governance violations against the key.',
  custody: 'Where the material actually lives, and whether it can leave that backend.',
  exposure: 'Dependent assets, certificates and observed runtime traffic — what breaks if this key does.',
};

export default function QkmsRiskAnalysis() {
  const { data, state, error, live, refresh, reconnect } = useKeyRiskAnalysis();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const query = useKeyQuery({ limit: 25, sort: 'risk', dir: 'desc' });
  const actions = useQkmsActions(() => { void refresh(true); query.reload(); });
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const metrics = data?.metrics;

  /** Weighted contribution each factor makes to the estate's average score. */
  const factorRows = useMemo(() => {
    if (!data?.factorAverages.length) return [];
    return data.factorAverages.map((factor) => ({
      ...factor,
      contribution: Math.round((factor.average * factor.weight) / 10) / 10,
      meaning: FACTOR_MEANING[factor.key] || '',
    }));
  }, [data]);

  return (
    <QkmsShell
      icon={ShieldAlert}
      title="Key Risk"
      accent="Intelligence"
      subtitle="One weighted, explainable risk model across the whole key estate — the score, what produced it, the evidence behind it, and the action that reduces it."
      live={live}
      state={state}
      error={error}
      hasData={data?.hasData ?? false}
      generatedAt={data?.generatedAt ?? null}
      latestEvidenceAt={data?.latestEvidenceAt ?? null}
      telemetry={data?.telemetry ?? null}
      nav={data?.nav ?? null}
      onRefresh={() => { void refresh(true); query.reload(); }}
      onReconnect={reconnect}
      actions={<ExportMenu onExport={onExport} busy={exporter.busy} />}
    >
      <Notice notice={notice} onDismiss={dismiss} />

      {metrics ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Kpi
            label="Critical-risk keys"
            value={fmtNumber(metrics.criticalRiskKeys)}
            detail="Weighted score of 80 or above"
            tone={metrics.criticalRiskKeys > 0 ? 'critical' : 'good'}
          />
          <Kpi
            label="High-risk keys"
            value={fmtNumber(metrics.highRiskKeys)}
            detail="Weighted score 60–79"
            tone={metrics.highRiskKeys > 0 ? 'critical' : 'good'}
          />
          <Kpi
            label="Average risk"
            value={metrics.averageRiskScore === null ? '—' : String(metrics.averageRiskScore)}
            unmeasured={metrics.averageRiskScore === null}
            detail={`across ${fmtNumber(metrics.totalKeys)} key(s)`}
            tone={(metrics.averageRiskScore ?? 0) >= 60 ? 'critical' : (metrics.averageRiskScore ?? 0) >= 35 ? 'warning' : 'good'}
          />
          <Kpi
            label="Keys with violations"
            value={fmtNumber(metrics.keysWithViolations)}
            detail={`${fmtNumber(metrics.governanceViolations)} open violation(s)`}
            tone={metrics.keysWithViolations > 0 ? 'critical' : 'good'}
            href="/dashboard/qkms/governance"
            hint="A governance violation raises a floor under the key's risk score, so Governance and Risk Analysis cannot tell different stories about the same key."
          />
        </div>
      ) : null}

      {/* ---- Distribution + factor decomposition --------------------- */}
      <div className="grid gap-3 xl:grid-cols-2">
        <Panel>
          <SectionLabel icon={Gauge} hint="Bands are fixed: critical ≥ 80, high ≥ 60, medium ≥ 35, low ≥ 15, minimal below that.">
            Risk distribution
          </SectionLabel>
          {data?.distribution.length ? (
            <div className="space-y-0.5">
              {data.distribution.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={/Critical|High/.test(row.label) ? 'critical' : /Medium/.test(row.label) ? 'warning' : 'good'}
                  onClick={() => query.update({ risk: row.label.split(' ')[0].toLowerCase() === 'minimal' ? 'none' : row.label.split(' ')[0].toLowerCase() })}
                  title={`Filter the table to ${row.label}`}
                />
              ))}
            </div>
          ) : <PanelEmpty>No key risk has been scored yet.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel
            icon={Layers}
            hint="Each factor's estate-wide average and what it contributes to the headline. The weights sum to 100, so the contributions sum to the average score."
          >
            Risk model decomposition
          </SectionLabel>
          {factorRows.length ? (
            <div className="space-y-2">
              {factorRows.map((factor) => {
                const tone = factor.average >= 70 ? 'critical' : factor.average >= 40 ? 'warning' : 'good';
                return (
                  <div key={factor.key} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[10.5px] font-black uppercase tracking-wider text-white/65">{factor.label}</span>
                      <span className="font-mono text-[10px] tabular-nums text-white/45">
                        avg {factor.average} × {factor.weight}% = <span className={TONE[tone].text}>{factor.contribution.toFixed(1)}</span>
                      </span>
                    </div>
                    <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/10">
                      <span className="block h-full rounded-full" style={{ width: `${Math.max(2, factor.average)}%`, backgroundColor: TONE[tone].hex }} />
                    </div>
                    <p className="mt-1.5 text-[10px] leading-snug text-white/40">{factor.meaning}</p>
                    {factor.measuredKeys < (metrics?.totalKeys ?? 0) ? (
                      <p className="mt-1 text-[9.5px] font-semibold text-amber-300/70">
                        Measured for {fmtNumber(factor.measuredKeys)} of {fmtNumber(metrics?.totalKeys ?? 0)} key(s); the remainder scored on absent evidence and lower confidence.
                      </p>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : <PanelEmpty>No risk factors have been computed.</PanelEmpty>}

          <ExplainBox tone="neutral" title="The weights">
            {RISK_WEIGHTS.map((weight) => `${weight.label} ${weight.weight}%`).join(' · ')}. One model, computed server-side, rendered
            unchanged on every QKMS page and in every export.
          </ExplainBox>
        </Panel>
      </div>

      {/* ---- Quantum exposure + custody ------------------------------ */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel>
          <SectionLabel icon={Sparkles}>Quantum exposure by family</SectionLabel>
          {data?.distributions.families.length ? (
            <div className="space-y-0.5">
              {data.distributions.families.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={
                    /ML-KEM|ML-DSA|SLH-DSA|SHA3/i.test(row.label) ? 'good'
                      : /hybrid|MLKEM/i.test(row.label) ? 'info'
                        : /RSA|ECDSA|ECDHE|ECDH|Ed25519|X25519|DSA|Diffie/i.test(row.label) ? 'critical'
                          : /AES-256|ChaCha/i.test(row.label) ? 'good' : 'neutral'
                  }
                  onClick={() => query.update({ family: row.label })}
                />
              ))}
            </div>
          ) : <PanelEmpty>No algorithm families have been classified.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={Activity}>Posture</SectionLabel>
          {data?.distributions.postures.length ? (
            <div className="space-y-0.5">
              {data.distributions.postures.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={
                    /Post-Quantum|Quantum-Resistant/.test(row.label) ? 'good'
                      : /Hybrid/.test(row.label) ? 'info'
                        : /Deprecated|Vulnerable/.test(row.label) ? 'critical'
                          : /Weakened/.test(row.label) ? 'warning' : 'neutral'
                  }
                />
              ))}
            </div>
          ) : <PanelEmpty>No key posture has been classified.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={ShieldAlert}>Violation severity</SectionLabel>
          {data?.violationsBySeverity.length ? (
            <div className="space-y-0.5">
              {data.violationsBySeverity.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={row.label === 'critical' || row.label === 'high' ? 'critical' : row.label === 'medium' ? 'warning' : 'neutral'}
                />
              ))}
            </div>
          ) : (
            <PanelEmpty>
              {metrics?.totalKeys ? 'No key violates a policy in force.' : 'No keys have been discovered to evaluate.'}
            </PanelEmpty>
          )}

          {data?.distributions.custody.length ? (
            <div className="mt-3">
              <h3 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Custody exposure</h3>
              <div className="space-y-0.5">
                {data.distributions.custody.map((row) => (
                  <BarRow
                    key={row.label}
                    label={row.label}
                    count={row.count}
                    percent={row.percent}
                    tone={/HSM|KMS|Vault/i.test(row.label) ? 'good' : /Unknown/i.test(row.label) ? 'neutral' : 'warning'}
                  />
                ))}
              </div>
            </div>
          ) : null}
        </Panel>
      </div>

      {/* ---- Risk table ---------------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={Gauge}
          meta={<span>{fmtNumber(query.page?.keys.length ?? 0)} shown · {fmtNumber(query.page?.total ?? 0)} match</span>}
          hint="Select any key to see its full decomposition: every factor's sub-score, weight, contribution and reason, with the evidence rows behind them."
        >
          Key risk register
        </SectionLabel>

        <div className="mb-3 flex flex-wrap gap-2">
          <FilterSelect
            label="Risk"
            value={query.query.risk || ''}
            onChange={(value) => query.update({ risk: value })}
            options={[
              { value: '', label: 'All levels' },
              ...(data?.facets.riskLevels ?? []).map((option) => ({ value: option.value, label: `${option.value} (${option.count})` })),
            ]}
          />
          <FilterSelect
            label="Posture"
            value={query.query.posture || ''}
            onChange={(value) => query.update({ posture: value as never })}
            options={[
              { value: '', label: 'All postures' },
              ...(data?.facets.postures ?? []).map((option) => ({ value: option.value, label: `${option.value} (${option.count})` })),
            ]}
          />
          <FilterSelect
            label="Environment"
            value={query.query.environment || ''}
            onChange={(value) => query.update({ environment: value })}
            options={[
              { value: '', label: 'All environments' },
              ...(data?.facets.environments ?? []).map((option) => ({ value: option.value, label: `${option.value} (${option.count})` })),
            ]}
          />
          <FilterSelect
            label="Owner"
            value={query.query.owner || ''}
            onChange={(value) => query.update({ owner: value })}
            options={[
              { value: '', label: 'All owners' },
              ...(data?.facets.owners ?? []).map((option) => ({ value: option.value, label: `${option.value} (${option.count})` })),
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
            emptyMessage="No key matches these filters."
          />
        </div>
        <Pager offset={query.query.offset ?? 0} limit={query.query.limit ?? 25} total={query.page?.total ?? 0} onChange={query.setOffset} />
      </Panel>

      {/* ---- Remediation queue --------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={ClipboardCheck}
          meta={<span>{fmtNumber(data?.remediation.length ?? 0)}</span>}
          hint="Ordered by what must happen FIRST, not by which factor scored highest — a key with no owner cannot be rotated or migrated, so ownership precedes both."
        >
          Remediation queue
        </SectionLabel>
        {data?.remediation.length ? (
          <ol className="space-y-1.5">
            {data.remediation.map((item, index) => (
              <li key={item.keyId}>
                <button
                  type="button"
                  onClick={() => setSelectedKey(item.keyId)}
                  className="flex w-full items-start gap-3 rounded-lg border border-white/10 bg-black/25 p-3 text-left transition hover:border-cyan-400/40 hover:bg-black/40"
                >
                  <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-white/10 font-mono text-[10px] font-black text-white/60">
                    {index + 1}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-[11.5px] font-black text-white">{item.keyLabel}</span>
                      <RiskBadge level={item.level as never} score={item.score} />
                    </span>
                    <span className="mt-1 block text-[11px] leading-snug text-cyan-300/85">{item.action}</span>
                    <span className="mt-0.5 block text-[10px] leading-snug text-white/40">{item.rationale}</span>
                  </span>
                </button>
              </li>
            ))}
          </ol>
        ) : (
          <PanelEmpty>
            {metrics?.totalKeys
              ? 'No key scores above the remediation threshold. This is a real result, not an absence of data.'
              : 'No keys have been discovered to assess.'}
          </PanelEmpty>
        )}
      </Panel>

      <KeyDrawer keyId={selectedKey} onClose={() => setSelectedKey(null)} onChanged={() => { void refresh(true); query.reload(); }} />
    </QkmsShell>
  );
}
