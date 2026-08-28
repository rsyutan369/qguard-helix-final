'use client';

import { useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Award, CalendarClock, GitBranch, Landmark, ScrollText, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import { usePagedResource, usePkiVisibility, useTlsPkiDetail, type CertificateDetail } from '@/hooks/use-tls-pki';
import { POSTURE_LABEL } from '@/lib/tls-pki/classify';
import type { CertificateLifecycle, PkiCertificate, TrustChainNode } from '@/lib/tls-pki/types';
import { PostureStrip } from '../_components/observability/TlsPostureStrip';
import {
  BarRow,
  ConnectionLost,
  Donut,
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
 * PKI Visibility — the certificate intelligence console.
 *
 * Certificates arrive from three different tables (the certificate store, the
 * scanner's component inventory, and agent evidence). They are merged here on
 * certificate IDENTITY — fingerprint, then serial, then subject+issuer — so one
 * certificate discovered twice is one row, not two. Before this refactor the
 * same certificate could be counted once per source and inflate every lifecycle
 * bucket it appeared in.
 *
 * The trust chain view distinguishes a CA that was actually measured (a
 * certificate for it exists in the tenant's inventory) from one that was only
 * INFERRED from an issuer string. Drawing an unmeasured issuer as if it were
 * verified would claim knowledge the platform does not have.
 */

const PAGE_SIZE = 25;

const LIFECYCLE_TONE: Record<CertificateLifecycle, 'good' | 'warning' | 'critical' | 'neutral'> = {
  valid: 'good',
  expiring: 'warning',
  expired: 'critical',
  revoked: 'critical',
  unknown: 'neutral',
};

export default function PkiVisibility() {
  const { data, state, error, live, lastSyncedAt, refresh, reconnect } = usePkiVisibility();
  const { loadCertificate, loading: detailLoading } = useTlsPkiDetail('pki');

  const [search, setSearch] = useState('');
  const [lifecycle, setLifecycle] = useState('all');
  const [posture, setPosture] = useState('all');
  const [issuer, setIssuer] = useState('all');
  const [offset, setOffset] = useState(0);
  const [detail, setDetail] = useState<CertificateDetail | null>(null);

  const revision = useMemo(() => Date.parse(data?.generatedAt || '') || 0, [data?.generatedAt]);
  const query = useMemo(
    () => ({ search, lifecycle, posture, issuer, limit: PAGE_SIZE, offset, sort: 'risk' }),
    [search, lifecycle, posture, issuer, offset],
  );
  const {
    rows: certificates,
    total: certificateTotal,
    loading: tableLoading,
  } = usePagedResource<PkiCertificate>('pki', '/certificates', 'certificates', query, revision);

  const openCertificate = useCallback(
    async (id: string) => {
      const result = await loadCertificate(id);
      if (result) setDetail(result);
    },
    [loadCertificate],
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
        <ErrorState message={error || 'The PKI visibility service did not respond.'} onRetry={reconnect} />
      </div>
    );
  }

  const lifecycleRows = data
    ? [
        { label: 'Valid', value: data.lifecycle.valid, hex: TONE.good.hex },
        { label: 'Expiring (30d)', value: data.lifecycle.expiring, hex: TONE.warning.hex },
        { label: 'Expired', value: data.lifecycle.expired, hex: TONE.critical.hex },
        { label: 'Revoked', value: data.lifecycle.revoked, hex: '#a78bfa' },
        { label: 'No expiry recorded', value: data.lifecycle.unknown, hex: '#64748b' },
      ].filter((row) => row.value > 0)
    : [];

  return (
    <div className={SHELL_CLASS}>
      <style>{SHELL_CSS}</style>
      <WorkflowRail activeStage="monitoring" />

      <PageHeader
        icon={Award}
        title="PKI"
        accent="Visibility"
        subtitle="Every certificate the platform can see, merged on identity across the certificate store, scanner inventory and agent evidence — with its lifecycle, its trust path and its post-quantum readiness."
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

      {data && data.totals.certificates === 0 ? (
        <NoDataState
          title="No certificates discovered yet"
          body="An empty certificate inventory is not a clean bill of health — it means nothing has looked. Connect a source below to build the inventory."
          telemetry={data.telemetry}
        />
      ) : null}

      {data ? (
        <>
          <PostureStrip posture={data.posture} totals={{ endpoints: data.totals.endpoints, certificates: data.totals.certificates }} />

          {/* ---- Lifecycle ------------------------------------------ */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Kpi
              label="Certificates"
              value={fmtNumber(data.totals.certificates)}
              detail="Distinct certificates after identity merge"
              tone="neutral"
              hint="Merged on fingerprint, then serial number, then subject + issuer. The same certificate seen by a scan and by an agent is one row."
            />
            <Kpi
              label="Expiring in 30 days"
              value={fmtNumber(data.lifecycle.expiring)}
              detail={`${fmtNumber(data.lifecycle.expired)} already expired`}
              tone={data.lifecycle.expiring || data.lifecycle.expired ? 'warning' : 'good'}
              hint="Renewal window. An expired certificate breaks endpoint authentication outright; clients either refuse the connection or users learn to click through the warning."
            />
            <Kpi
              label="Quantum vulnerable"
              value={fmtNumber(data.certificates.filter((cert) => cert.posture === 'quantum-vulnerable').length)}
              detail={`of ${fmtNumber(Math.min(data.certificates.length, data.totals.certificates))} shown · RSA / ECDSA / Ed25519 keys`}
              tone="critical"
              hint="Certificate keys breakable by Shor's algorithm. Reissue with ML-DSA-65 (FIPS 204), or a hybrid ECDSA P-256 + ML-DSA-65 chain during transition."
            />
            <Kpi
              label="No expiry recorded"
              value={fmtNumber(data.lifecycle.unknown)}
              detail="Lifecycle cannot be stated for these"
              tone={data.lifecycle.unknown ? 'warning' : 'good'}
              hint="A certificate whose validity window was never captured. It is shown as unknown rather than valid, because assuming validity is how an expired certificate goes unnoticed."
            />
          </div>

          <div className="grid gap-3 xl:grid-cols-[1fr_1.4fr]">
            <Panel>
              <SectionLabel icon={CalendarClock} hint="Lifecycle position of every merged certificate.">
                Certificate lifecycle
              </SectionLabel>
              {lifecycleRows.length === 0 ? (
                <PanelEmpty>No certificate lifecycle data.</PanelEmpty>
              ) : (
                <Donut rows={lifecycleRows} centerLabel="certificates" centerValue={fmtNumber(data.totals.certificates)} />
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={CalendarClock} hint="Click a bucket to filter the inventory below.">
                Expiry horizon
              </SectionLabel>
              {data.expiryBuckets.every((bucket) => bucket.count === 0) ? (
                <PanelEmpty>No expiry dates recorded on any certificate.</PanelEmpty>
              ) : (
                <div className="space-y-1">
                  {data.expiryBuckets.map((bucket) => (
                    <BarRow
                      key={bucket.label}
                      label={bucket.label}
                      count={bucket.count}
                      percent={bucket.percent}
                      tone={
                        bucket.label === 'Expired'
                          ? 'critical'
                          : bucket.label.startsWith('0-7')
                            ? 'critical'
                            : bucket.label.startsWith('8-30')
                              ? 'warning'
                              : bucket.label === 'No expiry recorded'
                                ? 'neutral'
                                : 'good'
                      }
                      onClick={() => {
                        setLifecycle(bucket.label === 'Expired' ? 'expired' : bucket.label === 'No expiry recorded' ? 'unknown' : 'all');
                        setOffset(0);
                      }}
                    />
                  ))}
                </div>
              )}
            </Panel>
          </div>

          {/* ---- Algorithms + issuers -------------------------------- */}
          <div className="grid gap-3 xl:grid-cols-2">
            <Panel>
              <SectionLabel icon={ShieldAlert} hint="Public-key algorithm and size, taken from the certificate itself rather than inferred from its name.">
                Certificate algorithms
              </SectionLabel>
              {data.algorithmDistribution.length === 0 ? (
                <PanelEmpty>No certificate algorithm recorded.</PanelEmpty>
              ) : (
                <div className="space-y-1">
                  {data.algorithmDistribution.length > 8 ? (
                    <div className="pb-1 text-[10px] text-white/35">
                      Showing the 8 most common of {fmtNumber(data.algorithmDistribution.length)} certificate algorithms.
                    </div>
                  ) : null}
                  {data.algorithmDistribution.slice(0, 8).map((row) => (
                    <BarRow
                      key={row.label}
                      label={row.label}
                      count={row.count}
                      percent={row.percent}
                      tone={POSTURE_TONE[row.posture]}
                      title={`${row.label} — ${POSTURE_LABEL[row.posture]}`}
                      onClick={() => {
                        setPosture(row.posture);
                        setOffset(0);
                      }}
                    />
                  ))}
                </div>
              )}
            </Panel>

            <Panel>
              <SectionLabel icon={Landmark} hint="Certificate authorities as named by the certificates themselves.">
                Issuers
              </SectionLabel>
              {data.issuers.length === 0 ? (
                <PanelEmpty>No issuer recorded on any certificate.</PanelEmpty>
              ) : (
                <TableShell minWidth={560}>
                  <thead>
                    <tr>
                      <Th>Issuer</Th>
                      <Th align="right">Certs</Th>
                      <Th align="right">Expiring</Th>
                      <Th align="right">Expired</Th>
                      <Th align="right">Quantum vuln.</Th>
                      <Th align="right">Avg risk</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.issuers.slice(0, 8).map((row) => (
                      <tr key={row.issuer} className="transition hover:bg-white/[0.04]">
                        <Td>
                          <button
                            type="button"
                            onClick={() => {
                              setIssuer(row.issuer);
                              setOffset(0);
                            }}
                            className="block max-w-[260px] truncate text-left text-white/80 hover:text-cyan-300"
                            title={row.issuer}
                          >
                            {row.issuer}
                          </button>
                        </Td>
                        <Td align="right">{fmtNumber(row.certificates)}</Td>
                        <Td align="right" className={row.expiring ? 'text-amber-300' : ''}>
                          {fmtNumber(row.expiring)}
                        </Td>
                        <Td align="right" className={row.expired ? 'text-red-300' : ''}>
                          {fmtNumber(row.expired)}
                        </Td>
                        <Td align="right" className={row.quantumVulnerable ? 'text-red-300' : ''}>
                          {fmtNumber(row.quantumVulnerable)}
                        </Td>
                        <Td align="right">{fmtNumber(row.averageRisk)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </TableShell>
              )}
              {data.issuers.length > 8 ? (
                <div className="mt-2 text-[10px] text-white/35">
                  Showing the 8 highest-volume of {fmtNumber(data.issuers.length)} issuers — use the issuer filter to reach the rest.
                </div>
              ) : null}
            </Panel>
          </div>

          {/* ---- Trust chain ---------------------------------------- */}
          <Panel>
            <SectionLabel
              icon={GitBranch}
              meta={`${data.trustChains.length} authority path(s)`}
              hint="Root or intermediate CA → issued certificate → the endpoint that presents it. A dimmed authority was inferred from an issuer string only: no certificate for it exists in your inventory, so its own algorithm and expiry are unknown."
            >
              Trust chains
            </SectionLabel>
            {data.trustChains.length === 0 ? (
              <PanelEmpty>No issuer relationship could be established from the certificates discovered so far.</PanelEmpty>
            ) : (
              <div className="grid gap-2 lg:grid-cols-2">
                {data.trustChains.slice(0, 8).map((node) => (
                  <TrustChainCard key={node.id} node={node} onOpenCertificate={openCertificate} />
                ))}
                {data.trustChains.length > 8 ? (
                  <div className="text-[10px] text-white/35 lg:col-span-2">
                    Showing 8 of {fmtNumber(data.trustChains.length)} discovered trust chains.
                  </div>
                ) : null}
              </div>
            )}
          </Panel>

          {/* ---- Inventory ------------------------------------------ */}
          <Panel>
            <SectionLabel icon={ScrollText} meta={`${fmtNumber(certificateTotal)} certificate(s)`}>
              Certificate inventory
            </SectionLabel>

            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SearchInput
                value={search}
                onChange={(value) => {
                  setSearch(value);
                  setOffset(0);
                }}
                placeholder="Search subject, SAN, issuer, serial or asset"
              />
              <FilterSelect
                label="Lifecycle"
                value={lifecycle}
                onChange={(value) => {
                  setLifecycle(value);
                  setOffset(0);
                }}
                options={[
                  { value: 'all', label: 'All' },
                  { value: 'valid', label: 'Valid' },
                  { value: 'expiring', label: 'Expiring' },
                  { value: 'expired', label: 'Expired' },
                  { value: 'revoked', label: 'Revoked' },
                  { value: 'unknown', label: 'Unknown' },
                ]}
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
                label="Issuer"
                value={issuer}
                onChange={(value) => {
                  setIssuer(value);
                  setOffset(0);
                }}
                /* Every issuer is selectable. Capping this list at 20 made
                   issuers outside the top 20 unreachable, so the filter could
                   not scope to part of the very estate it was filtering. */
                options={[{ value: 'all', label: 'All issuers' }, ...data.issuers.map((row) => ({ value: row.issuer, label: row.issuer }))]}
              />
            </div>

            {certificates.length === 0 ? (
              <PanelEmpty>{tableLoading ? 'Loading certificates…' : 'No certificate matches these filters.'}</PanelEmpty>
            ) : (
              <TableShell minWidth={1160}>
                <thead>
                  <tr>
                    <Th>Subject</Th>
                    <Th>Asset</Th>
                    <Th>Issuer</Th>
                    <Th>Algorithm</Th>
                    <Th>Signature</Th>
                    <Th align="right">Expires</Th>
                    <Th>Lifecycle</Th>
                    <Th>PQC status</Th>
                    <Th align="right">Risk</Th>
                  </tr>
                </thead>
                <tbody>
                  {certificates.map((cert) => (
                    <tr key={cert.id} className="transition hover:bg-white/[0.04]">
                      <Td>
                        <button
                          type="button"
                          onClick={() => void openCertificate(cert.id)}
                          className="block max-w-[240px] text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
                        >
                          <span className="block truncate font-semibold text-white" title={cert.subject}>
                            {cert.subject}
                          </span>
                          <span className="block truncate font-mono text-[9.5px] text-white/35">
                            {cert.serialNumber ? `sn ${cert.serialNumber}` : 'no serial recorded'}
                            {cert.san.length ? ` · ${cert.san.length} SAN` : ''}
                          </span>
                        </button>
                      </Td>
                      <Td>
                        <span className="block max-w-[150px] truncate text-[10.5px] text-white/65" title={cert.assetName}>
                          {cert.assetName}
                        </span>
                      </Td>
                      <Td>
                        <span className="block max-w-[190px] truncate text-[10.5px] text-white/65" title={cert.issuer}>
                          {cert.selfSigned ? 'Self-signed' : cert.issuer}
                        </span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10.5px]">
                          {cert.algorithmLabel}
                        </span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10.5px] text-white/60">
                          {cert.signatureAlgorithm || <span className="text-white/35">Not recorded</span>}
                        </span>
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[10.5px]" title={absoluteTime(cert.notAfter)}>
                          {fmtDays(cert.daysToExpiry)}
                        </span>
                      </Td>
                      <Td>
                        <Pill tone={LIFECYCLE_TONE[cert.lifecycle]}>{cert.lifecycle}</Pill>
                      </Td>
                      <Td>
                        <PostureBadge posture={cert.posture} />
                      </Td>
                      <Td align="right">
                        <Pill tone={RISK_TONE[cert.riskLevel]}>{cert.riskScore}</Pill>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
            )}
            <Pager offset={offset} limit={PAGE_SIZE} total={certificateTotal} onChange={setOffset} />
          </Panel>

          {/* ---- Certificate findings ------------------------------- */}
          <Panel>
            <SectionLabel icon={ShieldAlert} href="/dashboard/tls-orchestrator" meta={`${data.findings.length} shown`}>
              Certificate findings
            </SectionLabel>
            {data.findings.length === 0 ? (
              <PanelEmpty>No certificate finding is open across the certificates discovered so far.</PanelEmpty>
            ) : (
              <ul className="space-y-2">
                {data.findings.length > 10 ? (
                  <li className="rounded-lg border border-white/8 bg-white/[0.02] px-3 py-1.5 text-[10px] text-white/35">
                    Showing the 10 highest-severity of {fmtNumber(data.findings.length)} open certificate findings.
                  </li>
                ) : null}
                {data.findings.slice(0, 10).map((finding) => (
                  <li key={finding.id} className="rounded-lg border border-white/10 bg-black/25 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="text-[12px] font-black text-white">{finding.title}</h3>
                        <p className="mt-1 font-mono text-[10px] text-white/40">
                          {finding.assetName} · <span className="text-cyan-300">{finding.observed}</span> · {relativeTime(finding.lastObservedAt)}
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={finding.severity} />
                        <Pill tone="info">{finding.standard}</Pill>
                      </div>
                    </div>
                    <p className="mt-2 text-[11px] leading-relaxed text-white/60">{finding.remediation}</p>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <ProvenanceFooter telemetry={data.telemetry} />
        </>
      ) : null}

      <Drawer
        open={Boolean(detail)}
        title={detail?.certificate.subject ?? 'Certificate'}
        subtitle={detail ? `Issued by ${detail.certificate.issuer}` : undefined}
        onClose={() => setDetail(null)}
      >
        {detailLoading && !detail ? <PanelEmpty>Loading certificate…</PanelEmpty> : null}
        {detail ? <CertificateInvestigation detail={detail} /> : null}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Trust chain card                                                    */
/* ------------------------------------------------------------------ */

function TrustChainCard({ node, onOpenCertificate }: { node: TrustChainNode; onOpenCertificate: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const children = expanded ? node.children : node.children.slice(0, 4);

  return (
    <div className="rounded-lg border border-white/10 bg-black/25 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <Pill tone={node.kind === 'root' ? 'ai' : 'info'}>{node.kind}</Pill>
            {!node.measured ? (
              <Pill tone="neutral" title="No certificate for this authority exists in your inventory; the node comes from the issuer string on its children.">
                Issuer name only
              </Pill>
            ) : (
              <PostureBadge posture={node.posture} />
            )}
          </div>
          <h3 className={cn('mt-1.5 truncate text-[12px] font-black', node.measured ? 'text-white' : 'text-white/45')} title={node.label}>
            {node.label}
          </h3>
        </div>
        <span className="font-mono text-[9.5px] text-white/35">
          {node.children.length} cert · {node.endpointIds.length} endpoint
        </span>
      </div>

      {node.children.length === 0 ? (
        <p className="mt-2 text-[10.5px] text-white/35">No issued certificate recorded under this authority.</p>
      ) : (
        <ul className="mt-2 space-y-1 border-l border-white/10 pl-3">
          {children.map((child) => (
            <li key={child.id} className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => child.certificateIds[0] && onOpenCertificate(child.certificateIds[0])}
                className="min-w-0 flex-1 truncate text-left font-mono text-[10.5px] text-white/70 hover:text-cyan-300"
                title={child.label}
              >
                {child.label}
              </button>
              <PostureBadge posture={child.posture} />
            </li>
          ))}
        </ul>
      )}

      {node.children.length > 4 ? (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="mt-2 text-[10px] font-black uppercase tracking-wider text-cyan-300 hover:text-cyan-200"
        >
          {expanded ? 'Show fewer' : `Show all ${node.children.length}`}
        </button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Certificate investigation                                           */
/* ------------------------------------------------------------------ */

function CertificateInvestigation({ detail }: { detail: CertificateDetail }) {
  const { certificate, endpoint, findings, chain } = detail;
  return (
    <>
      <section className="rounded-lg border border-white/10 bg-black/25 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <PostureBadge posture={certificate.posture} />
          <Pill tone={LIFECYCLE_TONE[certificate.lifecycle]}>{certificate.lifecycle}</Pill>
          <Pill tone={RISK_TONE[certificate.riskLevel]}>Risk {certificate.riskScore}</Pill>
          {certificate.selfSigned ? <Pill tone="warning">Self-signed</Pill> : null}
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-2 text-[10.5px]">
          <div className="col-span-2">
            <dt className="text-white/35">Subject</dt>
            <dd className="break-words font-mono text-white/80">{certificate.subject}</dd>
          </div>
          <div className="col-span-2">
            <dt className="text-white/35">Issuer</dt>
            <dd className="break-words font-mono text-white/80">{certificate.issuer}</dd>
          </div>
          <div>
            <dt className="text-white/35">Public key</dt>
            <dd className="font-mono text-white/80">
              {certificate.algorithmLabel}
            </dd>
          </div>
          <div>
            <dt className="text-white/35">Signature</dt>
            <dd className="font-mono text-white/80">{certificate.signatureAlgorithm || 'Not recorded'}</dd>
          </div>
          <div>
            <dt className="text-white/35">Valid from</dt>
            <dd className="text-white/80">{absoluteTime(certificate.notBefore)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Valid to</dt>
            <dd className="text-white/80">{absoluteTime(certificate.notAfter)}</dd>
          </div>
          <div>
            <dt className="text-white/35">Serial</dt>
            <dd className="break-all font-mono text-white/80">{certificate.serialNumber || 'Not recorded'}</dd>
          </div>
          <div>
            <dt className="text-white/35">Fingerprint</dt>
            <dd className="break-all font-mono text-white/80">{certificate.fingerprint || 'Not recorded'}</dd>
          </div>
        </dl>
        {certificate.san.length ? (
          <div className="mt-3">
            <h4 className="text-[9px] font-black uppercase tracking-wider text-white/35">Subject alternative names</h4>
            <p className="mt-1 break-words font-mono text-[10px] text-white/65">{certificate.san.join(', ')}</p>
          </div>
        ) : null}
      </section>

      {endpoint ? (
        <section className="rounded-lg border border-white/10 bg-black/25 p-3">
          <h3 className="text-[10px] font-black uppercase tracking-wider text-white/40">Presented by</h3>
          <p className="mt-1.5 text-[12px] font-black text-white">{endpoint.name}</p>
          <p className="font-mono text-[10px] text-white/40">
            {endpoint.host}
            {endpoint.port ? `:${endpoint.port}` : ''} · {endpoint.negotiatedVersion || 'protocol not observed'}
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Link
              to="/dashboard/tls-telemetry"
              className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/70 no-underline hover:bg-white/[0.08]"
            >
              TLS telemetry
            </Link>
            <Link
              to="/dashboard/tls-orchestrator"
              className="rounded-md border border-cyan-400/35 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline hover:bg-cyan-500/20"
            >
              Remediate
            </Link>
          </div>
        </section>
      ) : null}

      {chain.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Trust path</h3>
          <ul className="space-y-1.5">
            {chain.map((node) => (
              <li key={node.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex items-center gap-1.5">
                  <Pill tone={node.kind === 'root' ? 'ai' : 'info'}>{node.kind}</Pill>
                  {!node.measured ? <Pill tone="neutral">Issuer name only</Pill> : null}
                </div>
                <p className="mt-1 break-words font-mono text-[10.5px] text-white/75">{node.label}</p>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section>
        <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Evidence</h3>
        <EvidenceList evidence={certificate.evidence} />
      </section>

      {findings.length ? (
        <section>
          <h3 className="mb-2 text-[10px] font-black uppercase tracking-wider text-white/40">Findings</h3>
          <ul className="space-y-1.5">
            {findings.map((finding) => (
              <li key={finding.id} className="rounded-lg border border-white/10 bg-black/25 p-2.5">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-[11px] font-black text-white">{finding.title}</span>
                  <SeverityBadge severity={finding.severity} />
                </div>
                <p className="mt-1 text-[10.5px] leading-relaxed text-white/60">{finding.remediation}</p>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </>
  );
}
