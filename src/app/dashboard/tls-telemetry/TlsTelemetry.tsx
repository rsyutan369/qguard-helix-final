'use client';

import { cn } from '@/lib/utils';
import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Fingerprint,
  Radar,
  ShieldAlert,
  Waves,
} from 'lucide-react';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { useTlsPkiDetail, useTlsTelemetry, usePagedResource, type EndpointDetail } from '@/hooks/use-tls-pki';
import { POSTURE_LABEL } from '@/lib/tls-pki/classify';
import type { TlsEndpoint, TlsFinding } from '@/lib/tls-pki/types';
import { PostureStrip } from '../_components/observability/TlsPostureStrip';
import {
  BarRow,
  ConnectionLost,
  Drawer,
  ErrorState,
  EvidenceList,
  FilterSelect,
  FreshnessBar,
  Kpi,
  ModuleNav,
  NoDataState,
  PageHeader,
  Pager,
  Panel,
  PanelEmpty,
  Pill,
  PostureBadge,
  ProvenanceFooter,
  SearchInput,
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
  absoluteTime,
  fmtDays,
  fmtNumber,
  fmtPercent,
  relativeTime,
} from '../_components/observability/primitives';

/**
 * TLS Telemetry — the runtime transport observability console.
 *
 * Answers, in reading order:
 *   1. What transport cryptography is actually running right now?
 *   2. Which endpoints are quantum-vulnerable, and on what evidence?
 *   3. What is failing or being downgraded?
 *   4. What do I do about it, and where do I go next?
 *
 * Counting discipline: this page reports OBSERVATIONS and ENDPOINTS. It reports
 * handshake volume only where an agent actually recorded one — the previous
 * version manufactured a "connection" for every certificate row and security
 * event and then published the total as `totalConnections`.
 */

const PAGE_SIZE = 25;

/** How an endpoint's transport facts were obtained (see TlsEndpoint.transportBasis). */
const TRANSPORT_BASIS_LABEL = { 'live-traffic': 'Live traffic', 'scanner-probe': 'Scanner probe', mixed: 'Live + probe' } as const;
const TRANSPORT_BASIS_HINT = {
  'live-traffic': 'Observed by a runtime agent in real connections — what clients actually negotiate.',
  'scanner-probe': 'Accepted by the server when an active scan offered it. This is what the server PERMITS, not what clients negotiate.',
  mixed: 'Some facts were seen in live traffic, others only accepted during a scanner probe.',
} as const;

export default function TlsTelemetry() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = useTlsTelemetry();
  const { loadEndpoint, loading: detailLoading } = useTlsPkiDetail('telemetry');

  const [search, setSearch] = useState('');
  const [posture, setPosture] = useState('all');
  const [version, setVersion] = useState('all');
  const [risk, setRisk] = useState('all');
  const [transport, setTransport] = useState('measured');
  const [offset, setOffset] = useState(0);
  const [detail, setDetail] = useState<EndpointDetail | null>(null);

  /** Bumped by the live model so the open table refreshes in step with the KPIs. */
  const revision = useMemo(() => Date.parse(data?.generatedAt || '') || 0, [data?.generatedAt]);

  const query = useMemo(
    () => ({ search, posture, version, risk, transport, limit: PAGE_SIZE, offset, sort: 'risk' }),
    [search, posture, version, risk, transport, offset],
  );
  const {
    rows: endpoints,
    total: endpointTotal,
    loading: tableLoading,
  } = usePagedResource<TlsEndpoint>('telemetry', '/endpoints', 'endpoints', query, revision);

  const openEndpoint = useCallback(
    async (id: string) => {
      const result = await loadEndpoint(id);
      if (result) setDetail(result);
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
        <ErrorState message={error || 'The TLS telemetry service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  const versionOptions = [
    { value: 'all', label: 'All versions' },
    ...(data?.versionDistribution ?? []).map((row) => ({ value: row.label, label: row.label })),
  ];

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="monitoring" />

      <PageHeader
        icon={Waves}
        title="TLS"
        accent="Telemetry"
        subtitle="Live transport cryptography across your estate — what each endpoint negotiates, which observations prove it, and what has to change to become quantum safe."
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

      {data && !data.hasData ? (
        <NoDataState
          title="No TLS or PKI telemetry available yet"
          body="Nothing on this page is invented, so with no measured evidence there is nothing to show. Connect a source below and the console fills in as observations arrive."
          telemetry={data.telemetry}
        />
      ) : null}

      {data ? (
        <>
          <PostureStrip posture={data.posture} totals={{ endpoints: data.totals.endpoints, certificates: data.totals.certificates }} />

          {/* ---- Overview ------------------------------------------- */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Transport observations"
              value={fmtNumber(data.totals.observations)}
              detail={`${fmtNumber(data.totals.measuredEndpoints)} of ${fmtNumber(data.totals.endpoints)} endpoint(s) have transport evidence`}
              tone="neutral"
              hint="A measured transport fact: a negotiated protocol version, cipher suite, key agreement, signature or certificate. Configuration and policy findings are counted as findings, not observations."
            />
            <Kpi
              label="Handshake failures"
              value={fmtNumber(data.handshake.failures)}
              detail={data.handshake.measured ? 'Reported by runtime collectors' : 'No collector reports handshake outcomes'}
              tone={data.handshake.failures ? 'critical' : 'good'}
              unmeasured={!data.handshake.measured}
              hint="Only runtime agents can observe a failed handshake. With no runtime source this reads 'Not measured' rather than zero, because zero would imply every handshake succeeded."
            />
            <Kpi
              label="Downgrade signals"
              value={fmtNumber(data.handshake.downgradeEndpoints)}
              detail={data.handshake.downgradeMeasured ? 'Endpoints with a flagged downgrade' : 'No collector reports downgrade detection'}
              tone={data.handshake.downgradeEndpoints ? 'critical' : 'good'}
              unmeasured={!data.handshake.downgradeMeasured}
              hint="A downgrade is recorded when an agent observed a negotiation falling back to a weaker protocol or key agreement than the endpoint supports."
            />
            <Kpi
              label="Forward secrecy"
              value={`${fmtNumber(data.forwardSecrecy.withFs)} / ${fmtNumber(data.forwardSecrecy.withFs + data.forwardSecrecy.withoutFs)}`}
              detail={`${fmtNumber(data.forwardSecrecy.notApplicable)} observation(s) do not determine it`}
              tone={data.forwardSecrecy.withoutFs ? 'critical' : 'good'}
              hint="Forward secrecy is only decidable for observations that carry a key agreement. A bulk cipher or a hash has none, so it is counted as not-applicable rather than as 'no forward secrecy'."
            />
          </div>

          {/* ---- Timeline + distributions --------------------------- */}
          <div className="grid gap-3 xl:grid-cols-[1.5fr_1fr]">
            <Panel>
              <SectionLabel
                icon={Activity}
                meta="Last 14 days"
                hint="Each bar counts evidence rows whose own timestamp falls in that day. Days with no collection are genuinely empty, not interpolated."
              >
                Telemetry timeline
              </SectionLabel>
              <StackedTrend
                points={data.timeline as unknown as Array<Record<string, string | number>>}
                series={[
                  { key: 'observations', label: 'Transport observations', hex: TONE.neutral.hex },
                  { key: 'certificates', label: 'Certificate observations', hex: TONE.info.hex },
                  { key: 'findings', label: 'Findings', hex: TONE.warning.hex },
                ]}
                emptyLabel="No dated TLS evidence in the last 14 days"
              />
            </Panel>

            <Panel>
              <SectionLabel
                icon={Radar}
                href="/dashboard/protocol-analytics"
                hint="Distribution across measured protocol observations. Click a row to filter the endpoint table below."
              >
                Protocol versions
              </SectionLabel>
              {data.versionDistribution.length === 0 ? (
                <PanelEmpty>No protocol version has been observed. Run a scan or deploy an agent collector.</PanelEmpty>
              ) : (
                <div className="space-y-1">
                  {data.versionDistribution.map((row) => (
                    <BarRow
                      key={row.label}
                      label={row.label}
                      count={row.count}
                      percent={row.percent}
                      tone={POSTURE_TONE[row.posture]}
                      onClick={() => {
                        setVersion(row.label);
                        setOffset(0);
                      }}
                      title={`${row.label} — ${POSTURE_LABEL[row.posture]} · observed on ${row.endpointIds.length} endpoint(s)`}
                    />
                  ))}
                </div>
              )}
            </Panel>
          </div>

          <div className="grid gap-3 xl:grid-cols-2">
            <Panel>
              <SectionLabel
                icon={Fingerprint}
                href="/dashboard/protocol-analytics"
                hint="The key agreement decides quantum posture. A hybrid group (X25519 + ML-KEM) keeps the classical guarantee and adds post-quantum protection."
              >
                Key agreement
              </SectionLabel>
              {data.keyExchangeDistribution.length === 0 ? (
                <PanelEmpty>
                  No key agreement observed. Without it, quantum posture cannot be stated for these endpoints — they read &ldquo;Unknown&rdquo;, not
                  &ldquo;safe&rdquo;.
                </PanelEmpty>
              ) : (
                <div className="space-y-1">
                  {data.keyExchangeDistribution.slice(0, 8).map((row) => (
                    <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone={POSTURE_TONE[row.posture]} />
                  ))}
                </div>
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={ShieldAlert} hint="Cipher suites ranked by how often they were observed. The suite's key exchange, not its bulk cipher, carries the quantum risk.">
                Cipher suites
              </SectionLabel>
              {data.cipherDistribution.length === 0 ? (
                <PanelEmpty>No cipher suite observed yet.</PanelEmpty>
              ) : (
                <div className="space-y-1">
                  {data.cipherDistribution.map((row) => (
                    <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} tone={POSTURE_TONE[row.posture]} />
                  ))}
                </div>
              )}
            </Panel>
          </div>

          {/* ---- Anomalies ------------------------------------------ */}
          {data.anomalies.length ? (
            <Panel>
              <SectionLabel icon={AlertTriangle} hint="Patterns across endpoints that no single observation reveals on its own.">
                Protocol anomalies
              </SectionLabel>
              <ul className="grid gap-2 lg:grid-cols-2">
                {data.anomalies.map((anomaly) => (
                  <li key={anomaly.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="text-[12px] font-black text-white">{anomaly.title}</h3>
                      <SeverityBadge severity={anomaly.severity} />
                    </div>
                    <p className="mt-1.5 text-[11px] leading-relaxed text-white/55">{anomaly.detail}</p>
                    <p className="mt-1.5 font-mono text-[9.5px] text-white/30">{anomaly.endpointIds.length} endpoint(s) affected</p>
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}

          {/* ---- Asset telemetry table ------------------------------ */}
          <Panel>
            <SectionLabel
              icon={Waves}
              meta={`${fmtNumber(endpointTotal)} endpoint(s)`}
              hint="One row per endpoint (asset, or host when no asset is bound). The identity here is the same identity PKI Visibility, Protocol Analytics and the Orchestrator use."
            >
              Asset telemetry
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput
                value={search}
                onChange={(value) => {
                  setSearch(value);
                  setOffset(0);
                }}
                placeholder="Search asset, host, owner, cipher or key agreement"
              />
              <FilterSelect
                label="Posture"
                value={posture}
                onChange={(value) => {
                  setPosture(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  ...(Object.keys(POSTURE_LABEL) as Array<keyof typeof POSTURE_LABEL>).map((key) => ({
                    value: key,
                    label: POSTURE_LABEL[key],
                  })),
                ]}
              />
              <FilterSelect
                label="Version"
                value={version}
                onChange={(value) => {
                  setVersion(value);
                  setOffset(0);
                }}
                options={versionOptions}
              />
              <FilterSelect
                label="Risk"
                value={risk}
                onChange={(value) => {
                  setRisk(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'critical', label: 'Critical' },
                  { value: 'high', label: 'High' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'low', label: 'Low' },
                ]}
              />
              <FilterSelect
                label="Evidence"
                value={transport}
                onChange={(value) => {
                  setTransport(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'measured', label: 'Transport measured' },
                  { value: 'certificate-only', label: 'Certificate only' },
                  { value: 'all', label: 'All records' },
                ]}
              />
            </div>

            <p className="mb-3 text-[10.5px] leading-relaxed text-white/40">
              Showing endpoints observed negotiating a protocol, suite or key agreement (
              {fmtNumber(data.totals.measuredEndpoints)} of {fmtNumber(data.totals.endpoints)} records). The remaining{' '}
              {fmtNumber(data.totals.endpoints - data.totals.measuredEndpoints)} are known only through a certificate or signature — real records,
              but never observed negotiating, so they are excluded from every TLS percentage. Switch <strong>Evidence</strong> to see them.
              Under each version, <strong>Scanner probe</strong> means the server <em>accepted</em> these settings when an active scan offered
              them one at a time — what the server permits, not what clients negotiate. Only <strong>Live traffic</strong> comes from real connections.
            </p>

            {endpoints.length === 0 ? (
              <PanelEmpty>
                {tableLoading ? 'Loading endpoints…' : 'No endpoint matches these filters. Clear them, or run a scan to discover more endpoints.'}
              </PanelEmpty>
            ) : (
              <TableShell minWidth={1080}>
                <thead>
                  <tr>
                    <Th>Asset / endpoint</Th>
                    <Th>TLS version</Th>
                    <Th>Cipher suite</Th>
                    <Th>Key agreement</Th>
                    <Th>Signature</Th>
                    <Th>Certificate</Th>
                    <Th>PQC status</Th>
                    <Th align="right">Last observed</Th>
                    <Th align="right">Risk</Th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((endpoint) => (
                    <tr key={endpoint.id} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <button
                          type="button"
                          onClick={() => void openEndpoint(endpoint.id)}
                          className="text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                        >
                          <span className="block truncate font-semibold text-white">{endpoint.name}</span>
                          <span className="block truncate font-mono text-[10px] text-white/40">
                            {endpoint.host}
                            {endpoint.port ? `:${endpoint.port}` : ''} · {endpoint.environment}
                            {endpoint.internetFacing ? ' · internet-facing' : ''}
                          </span>
                        </button>
                      </Td>
                      <Td>
                        {endpoint.negotiatedVersion ? (
                          <span className="font-mono text-[11px]">{endpoint.negotiatedVersion}</span>
                        ) : (
                          <span className="text-[10.5px] text-white/35">Not observed</span>
                        )}
                        {endpoint.transportBasis ? (
                          <span
                            className={cn('mt-0.5 block text-[9px] font-black uppercase tracking-wider', endpoint.transportBasis === 'scanner-probe' ? 'text-white/45' : 'text-emerald-300')}
                            title={TRANSPORT_BASIS_HINT[endpoint.transportBasis]}
                          >
                            {TRANSPORT_BASIS_LABEL[endpoint.transportBasis]}
                          </span>
                        ) : null}
                      </Td>
                      <Td>
                        <span className="block max-w-[190px] truncate font-mono text-[10.5px]" title={endpoint.cipherSuites.join(', ')}>
                          {endpoint.cipherSuites[0] || <span className="text-white/35">Not observed</span>}
                        </span>
                        {endpoint.cipherSuites.length > 1 ? (
                          <span className="font-mono text-[9px] text-white/30">+{endpoint.cipherSuites.length - 1} more</span>
                        ) : null}
                      </Td>
                      <Td>
                        <span className="block max-w-[160px] truncate font-mono text-[10.5px]" title={endpoint.keyExchange.join(', ')}>
                          {endpoint.keyExchange[0] || <span className="text-white/35">Not observed</span>}
                        </span>
                      </Td>
                      <Td>
                        <span className="block max-w-[150px] truncate font-mono text-[10.5px]" title={endpoint.signatureAlgorithms.join(', ')}>
                          {endpoint.signatureAlgorithms[0] || <span className="text-white/35">Not observed</span>}
                        </span>
                      </Td>
                      <Td>
                        {endpoint.certificateIds.length ? (
                          <Link to="/dashboard/pki-visibility" className="text-[10.5px] text-cyan-300 hover:text-cyan-200">
                            {endpoint.certificateIds.length} · {fmtDays(endpoint.daysToExpiry)}
                          </Link>
                        ) : (
                          <span className="text-[10.5px] text-white/35">None linked</span>
                        )}
                      </Td>
                      <Td>
                        <PostureBadge posture={endpoint.posture} reason={endpoint.postureReason} />
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10.5px] text-white/50" title={absoluteTime(endpoint.lastObservedAt)}>
                          {relativeTime(endpoint.lastObservedAt)}
                        </span>
                      </Td>
                      <Td align="right">
                        <Pill tone={RISK_TONE[endpoint.riskLevel]}>{endpoint.riskScore}</Pill>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
            <Pager offset={offset} limit={PAGE_SIZE} total={endpointTotal} onChange={setOffset} />
          </Panel>

          {/* ---- Findings ------------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={ShieldAlert}
              meta={`${fmtNumber(data.totals.findingsFromScanner)} reported · ${fmtNumber(data.totals.findingsDerived)} derived`}
              href="/dashboard/tls-orchestrator"
              hint="Reported = filed by the scanner itself, and reconciles with the Scanner's own count. Derived = a weakness this engine establishes from a measured observation (a CBC suite, a deprecated version) that the scanner did not file separately. Both are evidence-backed; the split is shown so the totals can be reconciled against other modules rather than appearing to contradict them."
            >
              Evidence-backed findings
            </SectionLabel>
            {data.findings.length === 0 ? (
              <PanelEmpty>
                No transport finding is open. That is only meaningful for endpoints that were actually measured — see the coverage figure above.
              </PanelEmpty>
            ) : (
              <ul className="space-y-2">
                {data.findings.slice(0, 12).map((finding) => (
                  <FindingRow key={finding.id} finding={finding} onOpen={finding.endpointId ? () => void openEndpoint(finding.endpointId!) : undefined} />
                ))}
              </ul>
            )}
          </Panel>

          <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />
        </>
      ) : null}

      {/* ---- Investigation drawer -------------------------------- */}
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
/* Finding row                                                         */
/* ------------------------------------------------------------------ */

function FindingRow({ finding, onOpen }: { finding: TlsFinding; onOpen?: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="rounded-lg border border-white/10 bg-black/25 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-[12px] font-black text-white">{finding.title}</h3>
          <p className="mt-1 font-mono text-[10px] text-white/40">
            {finding.assetName} · observed <span className="text-cyan-300">{finding.observed}</span> ·{' '}
            {finding.instances > 1 ? `${finding.instances} instances · ` : ''}
            {relativeTime(finding.lastObservedAt)}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Pill tone="info">{finding.standard}</Pill>
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            className="rounded-md border border-white/12 bg-white/[0.04] px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
          >
            {open ? 'Hide' : 'Evidence'}
          </button>
          {onOpen ? (
            <button
              type="button"
              onClick={onOpen}
              className="rounded-md border border-cyan-400/35 bg-cyan-500/10 px-2 py-1 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
            >
              Investigate
            </button>
          ) : null}
        </div>
      </div>
      {open ? (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <div className="space-y-2">
            <div>
              <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Impact</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-white/65">{finding.impact}</p>
            </div>
            <div>
              <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Recommended remediation</h4>
              <p className="mt-1 text-[11px] leading-relaxed text-white/65">{finding.remediation}</p>
            </div>
            <div>
              <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Migration status</h4>
              <p className="mt-1 text-[11px] text-white/65">{finding.migrationStatus.replace(/_/g, ' ')}</p>
            </div>
          </div>
          <div>
            <h4 className="mb-1.5 text-[9px] font-black uppercase tracking-wider text-white/35">Evidence</h4>
            <EvidenceList evidence={finding.evidence} />
          </div>
        </div>
      ) : null}
    </li>
  );
}

/* ------------------------------------------------------------------ */
/* Endpoint investigation                                              */
/* ------------------------------------------------------------------ */

export function EndpointInvestigation({ detail }: { detail: EndpointDetail }) {
  const { endpoint, observations, certificates, findings, orchestration } = detail;

  return (
    <>
      <section className="rounded-lg border border-white/10 bg-black/25 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <PostureBadge posture={endpoint.posture} />
          <Pill tone={RISK_TONE[endpoint.riskLevel]}>Risk {endpoint.riskScore}</Pill>
          {endpoint.internetFacing ? <Pill tone="warning">Internet-facing</Pill> : null}
          <Pill tone="neutral">{endpoint.environment}</Pill>
          {endpoint.queued ? <Pill tone="info">Queued for migration</Pill> : null}
        </div>
        <p className="mt-2 text-[11.5px] leading-relaxed text-white/65">{endpoint.postureReason}</p>
        <dl className="mt-3 grid grid-cols-2 gap-2 text-[10.5px]">
          <div>
            <dt className="text-white/35">Owner</dt>
            <dd className="text-white/75">{endpoint.owner || 'Unassigned'}</dd>
          </div>
          <div>
            <dt className="text-white/35">Asset type</dt>
            <dd className="text-white/75">{endpoint.assetType}</dd>
          </div>
          <div>
            <dt className="text-white/35">Observations</dt>
            <dd className="text-white/75">{fmtNumber(endpoint.observationCount)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Handshakes recorded</dt>
            <dd className="text-white/75">{endpoint.handshakeCount === null ? 'Not measured' : fmtNumber(endpoint.handshakeCount)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Migration status</dt>
            <dd className="text-white/75">
              {endpoint.migrationStatus.replace(/_/g, ' ')} · {fmtPercent(endpoint.migrationProgressPct)}
            </dd>
          </div>
          <div>
            <dt className="text-white/35">Last observed</dt>
            <dd className="text-white/75">{absoluteTime(endpoint.lastObservedAt)}</dd>
          </div>
        </dl>
      </section>

      <section>
        <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">
          Observations ({fmtNumber(observations.length)})
        </h3>
        {observations.length === 0 ? (
          <PanelEmpty>No transport observation is recorded for this endpoint.</PanelEmpty>
        ) : (
          <ul className="space-y-1.5">
            {observations.map((observation) => (
              <li key={observation.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-white/85">{observation.observed}</span>
                  <div className="flex items-center gap-1.5">
                    <Pill tone="neutral">{observation.kind}</Pill>
                    <PostureBadge posture={observation.posture} />
                  </div>
                </div>
                <p className="mt-1 text-[10px] text-white/40">
                  Family: {observation.family} · Forward secrecy:{' '}
                  {observation.forwardSecrecy === null ? 'not applicable' : observation.forwardSecrecy ? 'yes' : 'no'} ·{' '}
                  {relativeTime(observation.observedAt)}
                </p>
                <p className="mt-1 font-mono text-[9px] text-white/30">
                  {observation.evidence.table} · {observation.evidence.recordId}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      {certificates.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Certificates ({certificates.length})</h3>
          <ul className="space-y-1.5">
            {certificates.map((cert) => (
              <li key={cert.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 truncate text-[11px] font-semibold text-white">{cert.subject}</span>
                  <PostureBadge posture={cert.posture} />
                </div>
                <p className="mt-1 font-mono text-[10px] text-white/40">
                  {cert.algorithmLabel} · issued by {cert.issuer} · {fmtDays(cert.daysToExpiry)}
                </p>
              </li>
            ))}
          </ul>
          <Link to="/dashboard/pki-visibility" className="mt-2 inline-block text-[10.5px] font-bold text-cyan-300 hover:text-cyan-200">
            Open in PKI Visibility →
          </Link>
        </section>
      ) : null}

      {findings.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Findings ({findings.length})</h3>
          <ul className="space-y-2">
            {findings.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </ul>
        </section>
      ) : null}

      {orchestration.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Planned remediation</h3>
          <ul className="space-y-1.5">
            {orchestration.map((item) => (
              <li key={item.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-black text-white">{item.actionLabel}</span>
                  <Pill tone="info">{item.status.replace(/-/g, ' ')}</Pill>
                </div>
                <p className="mt-1 text-[10.5px] leading-relaxed text-white/55">{item.changeSummary}</p>
              </li>
            ))}
          </ul>
          <Link to="/dashboard/tls-orchestrator" className="mt-2 inline-block text-[10.5px] font-bold text-cyan-300 hover:text-cyan-200">
            Open in TLS Orchestrator →
          </Link>
        </section>
      ) : null}

      {endpoint.assetId ? (
        <div className="flex flex-wrap gap-2">
          <Link
            to={`/dashboard/assets?asset=${encodeURIComponent(endpoint.assetId)}`}
            className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 no-underline transition hover:bg-white/[0.08]"
          >
            Open asset
          </Link>
          <Link
            to="/dashboard/migration-planner"
            className="rounded-lg border border-white/12 bg-white/[0.04] px-3 py-2 text-[10px] font-black uppercase tracking-wider text-white/70 no-underline transition hover:bg-white/[0.08]"
          >
            Migration planner
          </Link>
        </div>
      ) : null}
    </>
  );
}
