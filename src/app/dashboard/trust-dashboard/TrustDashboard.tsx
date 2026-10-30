'use client';

/**
 * Cryptographic Trust Command Center — `/dashboard/trust-dashboard`.
 *
 * The executive surface of the trust suite: eight scored dimensions, fourteen
 * drill-through KPIs, the live cryptographic event stream, and the
 * reconciliation report that proves the numbers agree with the rest of the
 * platform.
 *
 * Every figure here is a projection of the shared Trust Fabric model, so a
 * count on this page is the same count Certificate Telemetry, Trust-State
 * Discovery, Multi-Cloud Telemetry, PKI Visibility, Assets and the Quantum
 * Readiness Engine publish. Nothing on this page is computed locally.
 */

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  Cloud,
  Database,
  Globe2,
  Radar,
  ShieldCheck,
} from 'lucide-react';
import {
  BarRow,
  ConnectionLost,
  Donut,
  ErrorState,
  FreshnessBar,
  NoDataState,
  Panel,
  PanelEmpty,
  Pill,
  ProvenanceFooter,
  SHELL_CSS,
  SectionLabel,
  StackedTrend,
  TONE,
  TableShell,
  Td,
  Th,
  fmtNumber,
  fmtPercent,
  relativeTime,
} from '../_components/observability/primitives';
import {
  Basis,
  EventStream,
  KpiSkeleton,
  LiveDot,
  ProviderChip,
  ReconciliationPanel,
  ScoreDial,
  StaleBanner,
  TRUST_SHELL_CLASS,
  TRUST_SHELL_CSS,
  TRUST_STATE_TONE,
  TrustKpiTile,
  TrustModuleNav,
  TrustPanel,
  TrustSkeleton,
  TrustStateBadge,
  riseStyle,
} from '../_components/trust/primitives';
import { useTrustDashboard } from '@/hooks/use-trust-fabric';
import { EXPIRY_BAND_LABEL, TRUST_STATE_LABEL, type ExpiryBand } from '@/lib/trust-fabric/types';
import { cn } from '@/lib/utils';

const BAND_TONE: Record<ExpiryBand, 'critical' | 'warning' | 'info' | 'good' | 'neutral'> = {
  expired: 'critical',
  critical: 'critical',
  high: 'warning',
  warning: 'info',
  healthy: 'good',
  unknown: 'neutral',
};

export default function TrustDashboard() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useTrustDashboard();
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await refresh(true);
    setRefreshing(false);
  }, [refresh]);

  /* ---- derived views over the payload (no business logic here) ---- */

  const stateRows = useMemo(
    () =>
      (data?.stateDistribution ?? []).map((row) => ({
        label: row.label,
        value: row.count,
        hex: TONE[TRUST_STATE_TONE[row.state]].hex,
      })),
    [data],
  );

  const criticalCount = useMemo(
    () => (data?.stateDistribution ?? []).filter((row) => row.state === 'critical' || row.state === 'expired' || row.state === 'invalid')
      .reduce((sum, row) => sum + row.count, 0),
    [data],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <KpiSkeleton count={8} />
        <TrustSkeleton rows={3} height={180} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <ErrorState message={error || 'Unable to load cryptographic trust intelligence.'} onRetry={() => void refresh(true)} />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className={TRUST_SHELL_CLASS}>
      <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>

      {/* ============ header ============ */}
      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Trust <span className="text-cyan-300">Command Center</span>
              <LiveDot live={live} />
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              Estate-wide cryptographic trust posture, assembled from your discovered assets, scanned certificates, transport telemetry
              and connected cloud accounts. Every number links to the records that produce it.
            </p>
          </div>
        </div>
        <FreshnessBar
          live={live}
          state={state}
          generatedAt={data.generatedAt}
          latestEvidenceAt={data.latestEvidenceAt}
          telemetry={data.telemetry}
          onRefresh={() => void onRefresh()}
          refreshing={refreshing}
        />
      </header>

      <TrustModuleNav />

      {!live && data ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void onRefresh()} /> : null}

      {!data.hasData ? (
        <NoDataState
          title="No cryptographic trust evidence yet"
          body="No telemetry or discovered assets are currently available for this tenant. Deploy a collector, connect a cloud account, or run an authorized scan — the trust posture below will populate from real evidence as soon as one of them reports."
          telemetry={data.telemetry}
        />
      ) : null}

      {/* ============ score dials ============ */}
      <section aria-label="Trust scores" className="grid grid-cols-2 gap-2.5 md:grid-cols-4 xl:grid-cols-8">
        {data.scores.map((score, index) => (
          <div key={score.key} className="tf-rise" style={riseStyle(index, 55)}>
            <ScoreDial score={score} />
          </div>
        ))}
      </section>

      {/* ============ executive KPIs ============ */}
      <section aria-label="Executive KPIs" className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-7">
        {data.kpis.map((kpi, index) => (
          <TrustKpiTile
            key={kpi.key}
            label={kpi.label}
            value={kpi.value}
            detail={kpi.detail}
            tone={kpi.tone}
            hint={kpi.hint}
            href={kpi.href}
            index={index}
          />
        ))}
      </section>

      {/* ============ posture + expiry + chain ============ */}
      <div className="grid gap-3 xl:grid-cols-3">
        <TrustPanel index={0}>
          <SectionLabel
            icon={Radar}
            hint="Every discovered trust subject — CA, certificate, endpoint, service, asset and cloud resource — resolved to exactly one state."
            meta={`${fmtNumber(data.totals.nodes)} subjects`}
          >
            Trust-state distribution
          </SectionLabel>
          {stateRows.length === 0 ? (
            <PanelEmpty>No trust subjects have been discovered yet.</PanelEmpty>
          ) : (
            <div className="flex flex-col items-center gap-3 lg:flex-row">
              <Donut
                rows={stateRows}
                centerLabel="Subjects"
                centerValue={fmtNumber(data.totals.nodes)}
              />
              <ul className="min-w-0 flex-1 space-y-1">
                {(data.stateDistribution ?? []).slice(0, 7).map((row) => (
                  <li key={row.state}>
                    <Link
                      to={`/dashboard/trust-state-discovery?state=${row.state}`}
                      className="flex items-center justify-between gap-2 rounded px-1 py-0.5 no-underline transition hover:bg-white/[0.05]"
                    >
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ backgroundColor: TONE[TRUST_STATE_TONE[row.state]].hex }}
                          aria-hidden="true"
                        />
                        <span className="truncate text-[10.5px] font-semibold text-white/65">{TRUST_STATE_LABEL[row.state]}</span>
                      </span>
                      <span className="shrink-0 font-mono text-[10.5px] text-white/45">
                        {fmtNumber(row.count)} · {fmtPercent(row.percent)}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <Basis>
            Measured on {fmtNumber(data.totals.measuredNodes)} of {fmtNumber(data.totals.nodes)} subjects. Subjects with no measurement
            are reported as Unknown, never folded into Healthy.
          </Basis>
        </TrustPanel>

        <TrustPanel index={1}>
          <SectionLabel
            icon={CalendarClock}
            hint="Certificates grouped by remaining validity. The bands are the platform standard: 7 / 30 / 60 days."
            href="/dashboard/certificate-telemetry"
            meta={`${fmtNumber(data.totals.certificates)} certificates`}
          >
            Certificate expiration risk
          </SectionLabel>
          {data.totals.certificates === 0 ? (
            <PanelEmpty>No certificates have been discovered in this tenant.</PanelEmpty>
          ) : (
            <div className="space-y-1.5">
              {data.certificateIntel.bands
                .filter((band) => band.count > 0)
                .map((band) => (
                  <BarRow
                    key={band.band}
                    label={EXPIRY_BAND_LABEL[band.band]}
                    count={band.count}
                    percent={band.percent}
                    tone={BAND_TONE[band.band]}
                    title={`${band.count} certificate(s) in the ${EXPIRY_BAND_LABEL[band.band]} band`}
                  />
                ))}
            </div>
          )}
          <Basis>
            Lifecycle: {fmtNumber(data.certificateIntel.lifecycle.valid)} valid · {fmtNumber(data.certificateIntel.lifecycle.expiring)}{' '}
            expiring · {fmtNumber(data.certificateIntel.lifecycle.expired)} expired ·{' '}
            {fmtNumber(data.certificateIntel.lifecycle.unknown)} with no recorded expiry.
          </Basis>
        </TrustPanel>

        <TrustPanel index={2}>
          <SectionLabel
            icon={ShieldCheck}
            hint="Result of running every chain check the collected evidence supports. Checks the platform genuinely cannot perform are reported as Not evaluated, never as a pass."
            href="/dashboard/certificate-telemetry?tab=chains"
          >
            Trust-chain validation
          </SectionLabel>
          {data.totals.certificates === 0 ? (
            <PanelEmpty>No certificate chains to validate.</PanelEmpty>
          ) : (
            <div className="space-y-1.5">
              <BarRow label="Passed every evaluable check" count={data.certificateIntel.chainValidation.passed} percent={pct(data.certificateIntel.chainValidation.passed, data.totals.certificates)} tone="good" />
              <BarRow label="Failing a check" count={data.certificateIntel.chainValidation.failed} percent={pct(data.certificateIntel.chainValidation.failed, data.totals.certificates)} tone="critical" />
              <BarRow label="Warning" count={data.certificateIntel.chainValidation.warned} percent={pct(data.certificateIntel.chainValidation.warned, data.totals.certificates)} tone="warning" />
              <BarRow label="Not evaluable" count={data.certificateIntel.chainValidation.notEvaluated} percent={pct(data.certificateIntel.chainValidation.notEvaluated, data.totals.certificates)} tone="neutral" />
            </div>
          )}
          <Basis>
            {fmtNumber(data.totals.chainPaths)} chain path(s) assembled from collected certificates. A chain the platform could not walk
            is reported as incomplete with the missing tier named, not scored as a failure. Checks run against recorded certificate fields:
            no path is built against a client trust store, and revocation is reported only when an OCSP/CRL result was collected — so
            &quot;passed&quot; never means &quot;verified trusted by a browser&quot;.
          </Basis>
        </TrustPanel>
      </div>

      {/* ============ trend ============ */}
      <TrustPanel index={3}>
        <SectionLabel
          icon={Activity}
          hint="Built from real evidence timestamps. A day with no collection is genuinely empty, not interpolated."
        >
          Trust posture over time
        </SectionLabel>
        <StackedTrend
          points={data.trend as unknown as Array<Record<string, number | string>>}
          series={[
            { key: 'certificatesObserved', label: 'Certificates observed', hex: TONE.neutral.hex },
            { key: 'quantumVulnerable', label: 'Quantum vulnerable', hex: TONE.critical.hex },
            { key: 'findingsOpened', label: 'Findings opened', hex: TONE.warning.hex },
          ]}
          emptyLabel="No dated cryptographic evidence in the observation window."
        />
      </TrustPanel>

      {/* ============ critical + events ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={4}>
          <SectionLabel
            icon={AlertTriangle}
            hint="Subjects in a Critical, Expired or Invalid trust state — the work queue, worst first."
            meta={`${fmtNumber(criticalCount)} total`}
          >
            Critical trust findings
          </SectionLabel>
          {data.criticalNodes.length === 0 ? (
            <PanelEmpty>
              No subject is currently in a critical, expired or invalid trust state.
            </PanelEmpty>
          ) : (
            <TableShell minWidth={640}>
              <thead>
                <tr>
                  <Th>Subject</Th>
                  <Th>State</Th>
                  <Th align="right">Blast radius</Th>
                  <Th align="right">Risk</Th>
                </tr>
              </thead>
              <tbody>
                {data.criticalNodes.slice(0, 10).map((node) => (
                  <tr key={node.id} className="border-b border-white/5 last:border-0 hover:bg-white/[0.03]">
                    <Td>
                      <Link to={node.href} className="block min-w-0 no-underline">
                        <span className="block truncate text-[11.5px] font-bold text-white/85">{node.label}</span>
                        <span className="block truncate text-[10px] text-white/40">{node.subtitle}</span>
                      </Link>
                    </Td>
                    <Td>
                      <TrustStateBadge state={node.state} reason={node.stateReason} size="sm" />
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[11px] text-white/60">{fmtNumber(node.dependentCount)}</span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[11px] text-white/60">{fmtNumber(node.riskScore)}</span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
          )}
        </TrustPanel>

        <TrustPanel index={5}>
          <SectionLabel
            icon={Activity}
            hint="Cryptographic and trust events derived from your own records over the last 30 days."
            href="/dashboard/trust-state-discovery?tab=events"
            meta={`${fmtNumber(data.totals.events)} events`}
          >
            Recent cryptographic events
          </SectionLabel>
          <EventStream events={data.events} limit={9} />
        </TrustPanel>
      </div>

      {/* ============ expiring queue ============ */}
      <TrustPanel index={6}>
        <SectionLabel
          icon={CalendarClock}
          hint="Certificates inside the renewal window or already expired, ordered by urgency, with the assets that break when they lapse."
          href="/dashboard/certificate-telemetry?band=high"
          meta={`${fmtNumber(data.expiring.length)} in window`}
        >
          Expiring &amp; expired certificates
        </SectionLabel>
        {data.expiring.length === 0 ? (
          <PanelEmpty>No certificate is expired or inside the 30-day renewal window.</PanelEmpty>
        ) : (
          <TableShell minWidth={880}>
            <thead>
              <tr>
                <Th>Certificate</Th>
                <Th>Band</Th>
                <Th>Owner</Th>
                <Th align="right">Affected assets</Th>
                <Th>Renewal</Th>
                <Th>Recommended action</Th>
              </tr>
            </thead>
            <tbody>
              {data.expiring.slice(0, 12).map((record) => {
                const certificate = data.certificateIndex.find((item) => item.id === record.certificateId);
                return (
                  <tr key={record.certificateId} className="border-b border-white/5 last:border-0 hover:bg-white/[0.03]">
                    <Td>
                      <Link
                        to={`/dashboard/certificate-telemetry?certificate=${encodeURIComponent(record.certificateId)}`}
                        className="block min-w-0 no-underline"
                      >
                        <span className="block truncate text-[11.5px] font-bold text-white/85">
                          {certificate?.name || certificate?.subject || 'Certificate'}
                        </span>
                        <span className="block truncate text-[10px] text-white/40">{certificate?.issuer || 'Issuer not recorded'}</span>
                      </Link>
                    </Td>
                    <Td>
                      <Pill tone={BAND_TONE[record.band]}>{EXPIRY_BAND_LABEL[record.band]}</Pill>
                    </Td>
                    <Td>
                      <span className={cn('text-[10.5px]', record.ownerKnown ? 'text-white/60' : 'text-amber-300/70')}>
                        {record.owner}
                      </span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[11px] text-white/60">{fmtNumber(record.affectedAssetCount)}</span>
                    </Td>
                    <Td>
                      <span className="text-[10.5px] capitalize text-white/55">{record.renewal.status.replace(/-/g, ' ')}</span>
                    </Td>
                    <Td>
                      <span className="text-[10.5px] leading-snug text-white/50">{record.remediation}</span>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </TableShell>
        )}
      </TrustPanel>

      {/* ============ cloud + regions ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={7}>
          <SectionLabel
            icon={Cloud}
            hint="Only clouds the tenant actually has evidence for. A connected account with no discovered resource is shown as connected but unmeasured."
            href="/dashboard/multi-cloud-telemetry"
            meta={`${fmtNumber(data.cloudSummary.connectorsActive)}/${fmtNumber(data.cloudSummary.connectorsConfigured)} connectors active`}
          >
            Cloud trust posture
          </SectionLabel>
          {data.cloudSummary.providers.length === 0 ? (
            <PanelEmpty>
              No cloud connector is configured and no asset carries cloud provider evidence, so there is no cross-cloud posture to report.
            </PanelEmpty>
          ) : (
            <ul className="space-y-1.5">
              {data.cloudSummary.providers.slice(0, 6).map((provider) => (
                <li
                  key={provider.provider}
                  className="tf-hover-lift rounded-lg border border-white/8 bg-black/20 p-2.5"
                  title={provider.stateReason}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <ProviderChip provider={provider.provider} label={provider.providerLabel} />
                    <div className="flex items-center gap-2">
                      <TrustStateBadge state={provider.state} reason={provider.stateReason} size="sm" />
                      <span
                        className={cn(
                          'font-mono text-[13px] font-black',
                          provider.trustScore === null ? 'text-white/30' : provider.trustScore >= 80 ? 'text-emerald-300' : 'text-amber-300',
                        )}
                      >
                        {provider.trustScore === null ? '—' : provider.trustScore}
                      </span>
                    </div>
                  </div>
                  <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[9.5px] text-white/40 sm:grid-cols-4">
                    <span>{fmtNumber(provider.resources)} resources</span>
                    <span>{fmtNumber(provider.regions.length)} regions</span>
                    <span>{fmtNumber(provider.certificates)} certificates</span>
                    <span>
                      {provider.encryptionCoverage === null ? 'Encryption not observed' : `${provider.encryptionCoverage}% encrypted`}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Basis>
            {fmtNumber(data.cloudSummary.totals.attributedResources)} of {fmtNumber(data.cloudSummary.totals.resources)} resources carry
            evidence naming a cloud. The remainder are reported as unattributed rather than assigned by assumption.
          </Basis>
        </TrustPanel>

        <TrustPanel index={8}>
          <SectionLabel
            icon={Globe2}
            hint="Per-region posture where at least one resource in the region carries an encryption or posture reading."
            href="/dashboard/multi-cloud-telemetry?tab=regions"
          >
            Regional risk distribution
          </SectionLabel>
          {data.cloudSummary.topRegions.length === 0 ? (
            <PanelEmpty>No region carries a cryptographic measurement.</PanelEmpty>
          ) : (
            <TableShell minWidth={560}>
              <thead>
                <tr>
                  <Th>Region</Th>
                  <Th>Cloud</Th>
                  <Th align="right">Resources</Th>
                  <Th align="right">Score</Th>
                  <Th>State</Th>
                </tr>
              </thead>
              <tbody>
                {data.cloudSummary.topRegions.map((region) => (
                  <tr key={`${region.provider}:${region.region}`} className="border-b border-white/5 last:border-0 hover:bg-white/[0.03]">
                    <Td>
                      <span className="font-mono text-[11px] text-white/75">{region.region}</span>
                      {region.anomaly ? (
                        <span className="mt-0.5 block text-[9.5px] leading-snug text-amber-300/70">{region.anomaly}</span>
                      ) : null}
                    </Td>
                    <Td>
                      <ProviderChip provider={region.provider} label={region.providerLabel} />
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[11px] text-white/55">{fmtNumber(region.resources)}</span>
                    </Td>
                    <Td align="right">
                      <span className={cn('font-mono text-[11px] font-bold', region.trustScore === null ? 'text-white/30' : 'text-white/70')}>
                        {region.trustScore === null ? 'n/m' : region.trustScore}
                      </span>
                    </Td>
                    <Td>
                      <TrustStateBadge state={region.state} size="sm" />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
          )}
        </TrustPanel>
      </div>

      {/* ============ reconciliation ============ */}
      <TrustPanel index={9}>
        <SectionLabel
          icon={Database}
          hint="Section 16 of the trust brief: rather than silently producing inconsistent results, the platform states where its records disagree and which source is authoritative."
        >
          Data reconciliation &amp; cross-module agreement
        </SectionLabel>
        <ReconciliationPanel report={data.reconciliation} />
      </TrustPanel>

      <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />
    </div>
  );
}

function pct(value: number, total: number): number {
  return total > 0 ? Math.round((value / total) * 100) : 0;
}
