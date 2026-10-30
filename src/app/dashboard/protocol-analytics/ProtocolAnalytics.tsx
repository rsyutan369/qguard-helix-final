'use client';

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, GitCompare, KeyRound, Layers, Signature, TrendingUp } from 'lucide-react';
import { cn } from '@/lib/utils';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useProtocolAnalytics, useTlsPkiDetail, type EndpointDetail, type EndpointSummary } from '@/hooks/use-tls-pki';
import { POSTURE_LABEL } from '@/lib/tls-pki/classify';
import type { DistributionRow } from '@/lib/tls-pki/types';
import { PostureStrip } from '../_components/observability/TlsPostureStrip';
import { EndpointInvestigation } from '../tls-telemetry/TlsTelemetry';
import {
  BarRow,
  ConnectionLost,
  Donut,
  Drawer,
  ErrorState,
  FreshnessBar,
  Kpi,
  ModuleNav,
  NoDataState,
  PageHeader,
  Panel,
  PanelEmpty,
  Pill,
  PostureBadge,
  ProvenanceFooter,
  SectionLabel,
  SeverityBadge,
  SHELL_CLASS,
  SHELL_CSS,
  Skeleton,
  StackedTrend,
  TableShell,
  Td,
  Th,
  TONE,
  POSTURE_TONE,
  RISK_TONE,
  fmtNumber,
  fmtPercent,
} from '../_components/observability/primitives';

/**
 * Protocol Analytics — the negotiation intelligence console.
 *
 * Every distribution on this page is measured over OBSERVATIONS and states its
 * denominator, and every row is clickable down to the endpoints it was measured
 * on: Protocol → Asset → Endpoint → Evidence.
 *
 * Two claims this page refuses to make from an absence of data:
 *   - "0 handshake failures" when nothing in the estate can report one. Only a
 *     runtime agent observes a failed negotiation; without one the tile reads
 *     "Not measured".
 *   - "No downgrades" for the same reason. Silence from an instrument that was
 *     never installed is not a clean result.
 */

export default function ProtocolAnalytics() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useProtocolAnalytics();
  const { loadEndpoint, loading: detailLoading } = useTlsPkiDetail('protocol');

  const [drill, setDrill] = useState<{ title: string; endpointIds: string[] } | null>(null);
  const [detail, setDetail] = useState<EndpointDetail | null>(null);

  const endpointById = useMemo(() => {
    const map = new Map<string, EndpointSummary>();
    for (const endpoint of data?.endpointIndex ?? []) map.set(endpoint.id, endpoint);
    return map;
  }, [data?.endpointIndex]);

  const openEndpoint = useCallback(
    async (id: string) => {
      const result = await loadEndpoint(id);
      if (result) {
        setDrill(null);
        setDetail(result);
      }
    },
    [loadEndpoint],
  );

  const showSkeleton = state === 'loading' && !data;
  const showHardError = state === 'error' && !data;
  const connectionLost = Boolean(data && !live && state !== 'loading');

  if (showSkeleton) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <Skeleton />
      </div>
    );
  }

  if (showHardError) {
    return (
      <div className={SHELL_CLASS}>
        <style>{SHELL_CSS}</style>
        <ErrorState message={error || 'The protocol analytics service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  const protocol = data?.protocol;
  const fsTotal = protocol ? protocol.forwardSecrecy.withFs + protocol.forwardSecrecy.withoutFs : 0;

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="assessment" />

      <PageHeader
        icon={Activity}
        title="Protocol"
        accent="Analytics"
        subtitle="How your estate actually negotiates: protocol versions, cipher suites, key agreement and signature algorithms — with post-quantum adoption measured against the same evidence every other module reads."
        right={
          <FreshnessBar
            live={live}
            state={state}
            generatedAt={data?.generatedAt ?? null}
            latestEvidenceAt={data?.latestEvidenceAt ?? null}
            telemetry={data?.telemetry ?? null}
            onRefresh={() => void refresh(true)}
            refreshing={state === 'loading'}
          />
        }
      />

      <ModuleNav />

      {connectionLost ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      {error && data ? (
        <p className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-[11px] text-red-200/85">{error}</p>
      ) : null}

      {data && protocol && protocol.totalObservations === 0 ? (
        <NoDataState
          title="No protocol observations yet"
          body="Protocol analytics is computed entirely from measured negotiations. Until a scan or a runtime collector reports one, there is nothing here to distribute."
          telemetry={data.telemetry}
        />
      ) : null}

      {data && protocol ? (
        <>
          <PostureStrip posture={data.posture} totals={{ endpoints: data.totals.endpoints, certificates: data.totals.certificates }} />

          {/* ---- Headline ------------------------------------------- */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Observations analysed"
              value={fmtNumber(protocol.totalObservations)}
              detail={`Basis for every percentage on this page: ${protocol.basis}`}
              tone="neutral"
              hint="Each observation is one measured protocol version, suite, key agreement or signature. Percentages below are shares of this number, not of your asset count."
            />
            <Kpi
              label="TLS 1.3 share"
              value={fmtPercent(protocol.versionDistribution.find((row) => row.label === 'TLS 1.3')?.percent ?? 0)}
              detail={`${fmtNumber(protocol.versionDistribution.find((row) => row.label === 'TLS 1.3')?.count ?? 0)} of ${fmtNumber(
                protocol.versionDistribution.reduce((sum, row) => sum + row.count, 0),
              )} protocol observations`}
              tone={(protocol.versionDistribution.find((row) => row.label === 'TLS 1.3')?.percent ?? 0) >= 80 ? 'good' : 'warning'}
              hint="TLS 1.3 is the only version that can negotiate hybrid ML-KEM groups, so it gates the whole post-quantum transport story."
            />
            <Kpi
              label="Handshake failures"
              value={fmtNumber(protocol.handshakeFailures)}
              detail={protocol.handshakeFailuresMeasured ? 'Observed by runtime collectors' : 'No instrument reports handshake outcomes'}
              tone={protocol.handshakeFailures ? 'critical' : 'good'}
              unmeasured={!protocol.handshakeFailuresMeasured}
              hint="Reported only where a runtime agent recorded the outcome of a negotiation. Scans record configuration, not live handshakes."
            />
            <Kpi
              label="Downgrade indicators"
              value={fmtNumber(protocol.downgradeEndpointIds.length)}
              detail={protocol.downgradeMeasured ? 'Endpoints with a flagged downgrade' : 'No instrument reports downgrade detection'}
              tone={protocol.downgradeEndpointIds.length ? 'critical' : 'good'}
              unmeasured={!protocol.downgradeMeasured}
              hint="A downgrade means a negotiation settled below what the endpoint supports — often a middlebox stripping modern extensions."
            />
          </div>

          {/* ---- Distributions -------------------------------------- */}
          <div className="grid gap-3 xl:grid-cols-2">
            <DistributionPanel
              icon={Layers}
              title="TLS version distribution"
              hint="Versions actually negotiated or advertised. TLS 1.0/1.1 are deprecated by RFC 8996; SSL 3.0 by RFC 7568."
              rows={protocol.versionDistribution}
              onDrill={setDrill}
              empty="No protocol version observed. Run a scan or deploy a collector."
            />
            <DistributionPanel
              icon={KeyRound}
              title="Key agreement distribution"
              hint="The primitive that decides quantum posture. ECDHE and X25519 alone are Shor-breakable; X25519MLKEM768 is the hybrid target."
              rows={protocol.keyExchangeDistribution}
              onDrill={setDrill}
              empty="No key agreement observed. Quantum posture cannot be stated for these endpoints — they read Unknown, not safe."
            />
            <DistributionPanel
              icon={GitCompare}
              title="Cipher suite distribution"
              hint="The suite's key exchange carries the quantum risk, never its bulk cipher: AES-256-GCM inside a static-RSA suite is not the weakness."
              rows={protocol.cipherDistribution}
              onDrill={setDrill}
              limit={10}
              empty="No cipher suite observed."
            />
            <DistributionPanel
              icon={Signature}
              title="Signature algorithm distribution"
              hint="Certificate and handshake signatures. RSA, ECDSA and Ed25519 are all forgeable by a CRQC; ML-DSA (FIPS 204) is the replacement."
              rows={protocol.signatureDistribution}
              onDrill={setDrill}
              limit={10}
              empty="No signature algorithm observed."
            />
          </div>

          {/* ---- Forward secrecy + adoption trend -------------------- */}
          <div className="grid gap-3 xl:grid-cols-[1fr_1.5fr]">
            <Panel>
              <SectionLabel
                icon={GitCompare}
                hint="Only observations that carry a key agreement can determine forward secrecy. A bulk cipher or hash has none, so it is counted as not-applicable — counting it as 'no forward secrecy' is how a quantum-safe cipher once appeared on a weakness list."
              >
                Forward secrecy
              </SectionLabel>
              {fsTotal + protocol.forwardSecrecy.notApplicable === 0 ? (
                <PanelEmpty>Nothing observed that determines forward secrecy.</PanelEmpty>
              ) : (
                <Donut
                  rows={[
                    { label: 'Forward secret', value: protocol.forwardSecrecy.withFs, hex: TONE.good.hex },
                    { label: 'Not forward secret', value: protocol.forwardSecrecy.withoutFs, hex: TONE.critical.hex },
                    { label: 'Not applicable', value: protocol.forwardSecrecy.notApplicable, hex: '#64748b' },
                  ].filter((row) => row.value > 0)}
                  centerLabel="of decidable"
                  centerValue={fsTotal ? fmtPercent((protocol.forwardSecrecy.withFs / fsTotal) * 100) : '—'}
                />
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={TrendingUp} meta="Last 14 days" hint="Observation counts by their own recorded timestamp. A flat line means no collection that day, not a stable posture.">
                Post-quantum adoption trend
              </SectionLabel>
              <StackedTrend
                points={protocol.adoptionTrend as unknown as Array<Record<string, string | number>>}
                series={[
                  { key: 'pqc', label: 'Post-quantum', hex: TONE.good.hex },
                  { key: 'hybrid', label: 'Hybrid', hex: TONE.info.hex },
                  { key: 'classical', label: 'Classical / legacy', hex: TONE.critical.hex },
                ]}
                emptyLabel="No dated protocol observations in the last 14 days"
              />
            </Panel>
          </div>

          {/* ---- Anomalies ------------------------------------------ */}
          <Panel>
            <SectionLabel icon={AlertTriangle} hint="Cross-endpoint patterns that a single observation cannot reveal.">
              Protocol anomalies
            </SectionLabel>
            {protocol.anomalies.length === 0 ? (
              <PanelEmpty>
                No cross-endpoint anomaly detected in the observations collected so far. This is only meaningful for measured endpoints — check
                coverage above.
              </PanelEmpty>
            ) : (
              <ul className="grid gap-2 lg:grid-cols-2">
                {protocol.anomalies.map((anomaly) => (
                  <li key={anomaly.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="text-[12px] font-black text-white">{anomaly.title}</h3>
                      <SeverityBadge severity={anomaly.severity} />
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-white/55">{anomaly.detail}</p>
                    <button
                      type="button"
                      onClick={() => setDrill({ title: anomaly.title, endpointIds: anomaly.endpointIds })}
                      className="mt-2 rounded-md border border-cyan-400/35 bg-cyan-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
                    >
                      {anomaly.endpointIds.length} affected endpoint(s)
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {/* ---- Legacy endpoints ----------------------------------- */}
          {protocol.legacyEndpointIds.length ? (
            <Panel className="border border-red-500/25">
              <SectionLabel icon={AlertTriangle} href="/dashboard/tls-orchestrator">
                Legacy protocol endpoints
              </SectionLabel>
              <p className="mb-3 text-[11.5px] leading-relaxed text-white/60">
                {fmtNumber(protocol.legacyEndpointIds.length)} endpoint(s) still answer on a protocol version deprecated by RFC 8996. Every one of
                them keeps a downgrade path open regardless of what else they support.
              </p>
              <EndpointTable
                endpointIds={protocol.legacyEndpointIds}
                endpointById={endpointById}
                onOpen={(id) => void openEndpoint(id)}
              />
            </Panel>
          ) : null}

          {/* ---- Findings ------------------------------------------- */}
          <Panel>
            <SectionLabel icon={Activity} href="/dashboard/tls-orchestrator" meta={`${data.findings.length} shown`}>
              Protocol, cipher and key-agreement findings
            </SectionLabel>
            {data.findings.length === 0 ? (
              <PanelEmpty>No open transport finding across the observations collected so far.</PanelEmpty>
            ) : (
              <TableShell minWidth={880}>
                <thead>
                  <tr>
                    <Th>Finding</Th>
                    <Th>Asset</Th>
                    <Th>Observed</Th>
                    <Th>Standard</Th>
                    <Th align="center">Severity</Th>
                    <Th align="right">Evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.findings.slice(0, 16).map((finding) => (
                    <tr key={finding.id} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <span className="block max-w-[320px] truncate font-semibold text-white" title={finding.title}>
                          {finding.title}
                        </span>
                      </Td>
                      <Td>
                        {finding.endpointId ? (
                          <button
                            type="button"
                            onClick={() => void openEndpoint(finding.endpointId!)}
                            className="max-w-[150px] truncate text-left text-[10.5px] text-cyan-300 hover:text-cyan-200"
                          >
                            {finding.assetName}
                          </button>
                        ) : (
                          <span className="text-[10.5px] text-white/55">{finding.assetName}</span>
                        )}
                      </Td>
                      <Td>
                        <span className="font-mono text-[10.5px] text-white/70">{finding.observed}</span>
                      </Td>
                      <Td>
                        <Pill tone="info">{finding.standard}</Pill>
                      </Td>
                      <Td align="center">
                        <SeverityBadge severity={finding.severity} />
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10px] text-white/40">{finding.evidence.length} record(s)</span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
          </Panel>

          <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />
        </>
      ) : null}

      {/* ---- Drill-down: distribution row → endpoints ------------- */}
      <Drawer
        open={Boolean(drill)}
        title={drill?.title ?? 'Endpoints'}
        subtitle={drill ? `${drill.endpointIds.length} endpoint(s) measured` : undefined}
        onClose={() => setDrill(null)}
      >
        {drill ? <EndpointTable endpointIds={drill.endpointIds} endpointById={endpointById} onOpen={(id) => void openEndpoint(id)} /> : null}
      </Drawer>

      {/* ---- Endpoint investigation ------------------------------- */}
      <Drawer
        open={Boolean(detail)}
        title={detail?.endpoint.name ?? 'Endpoint'}
        subtitle={detail ? `${detail.endpoint.host}${detail.endpoint.port ? `:${detail.endpoint.port}` : ''}` : undefined}
        onClose={() => setDetail(null)}
      >
        {detailLoading && !detail ? <PanelEmpty>Loading evidence…</PanelEmpty> : null}
        {detail ? <EndpointInvestigation detail={detail} /> : null}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Distribution panel                                                  */
/* ------------------------------------------------------------------ */

function DistributionPanel({
  icon,
  title,
  hint,
  rows,
  onDrill,
  limit = 8,
  empty,
}: {
  icon: typeof Layers;
  title: string;
  hint: string;
  rows: DistributionRow[];
  onDrill: (drill: { title: string; endpointIds: string[] }) => void;
  limit?: number;
  empty: string;
}) {
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  return (
    <Panel>
      <SectionLabel icon={icon} meta={total ? `${fmtNumber(total)} observations` : undefined} hint={hint}>
        {title}
      </SectionLabel>
      {rows.length === 0 ? (
        <PanelEmpty>{empty}</PanelEmpty>
      ) : (
        <div className="space-y-1">
          {rows.slice(0, limit).map((row) => (
            <BarRow
              key={row.label}
              label={row.label}
              count={row.count}
              percent={row.percent}
              tone={POSTURE_TONE[row.posture]}
              title={`${row.label} — ${POSTURE_LABEL[row.posture]} · measured on ${row.endpointIds.length} endpoint(s)`}
              onClick={() => onDrill({ title: `${title}: ${row.label}`, endpointIds: row.endpointIds })}
              suffix={
                <span className="hidden w-16 text-right font-mono text-[9.5px] text-white/30 sm:inline">
                  {row.endpointIds.length} ep
                </span>
              }
            />
          ))}
        </div>
      )}
      {rows.length > limit ? (
        <p className="mt-2 font-mono text-[9.5px] text-white/30">+{rows.length - limit} more distinct value(s)</p>
      ) : null}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Endpoint drill-down table                                           */
/* ------------------------------------------------------------------ */

function EndpointTable({
  endpointIds,
  endpointById,
  onOpen,
}: {
  endpointIds: string[];
  endpointById: Map<string, EndpointSummary>;
  onOpen: (id: string) => void;
}) {
  const rows = endpointIds.map((id) => endpointById.get(id)).filter(Boolean) as EndpointSummary[];
  if (rows.length === 0) {
    return <PanelEmpty>These observations are not bound to a resolvable endpoint.</PanelEmpty>;
  }
  return (
    <TableShell minWidth={620}>
      <thead>
        <tr>
          <Th>Endpoint</Th>
          <Th>Version</Th>
          <Th>Posture</Th>
          <Th align="right">Risk</Th>
        </tr>
      </thead>
      <tbody>
        {rows.slice(0, 100).map((endpoint) => (
          <tr key={endpoint.id} className="transition hover:bg-white/[0.04]">
            <Td>
              <button
                type="button"
                onClick={() => onOpen(endpoint.id)}
                className="text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
              >
                <span className="block max-w-[260px] truncate font-semibold text-white">{endpoint.name}</span>
                <span className="block max-w-[260px] truncate font-mono text-[9.5px] text-white/35">
                  {endpoint.host}
                  {endpoint.port ? `:${endpoint.port}` : ''} · {endpoint.environment}
                </span>
              </button>
            </Td>
            <Td>
              <span className={cn('font-mono text-[10.5px]', endpoint.negotiatedVersion ? 'text-white/75' : 'text-white/35')}>
                {endpoint.negotiatedVersion || 'Not observed'}
              </span>
            </Td>
            <Td>
              <PostureBadge posture={endpoint.posture} />
            </Td>
            <Td align="right">
              <Pill tone={RISK_TONE[endpoint.riskLevel]}>{endpoint.riskScore}</Pill>
            </Td>
          </tr>
        ))}
      </tbody>
    </TableShell>
  );
}
