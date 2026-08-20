'use client';

/**
 * Enterprise Certificate Lifecycle & TLS Intelligence Center —
 * `/dashboard/certificate-telemetry`.
 *
 * The certificate records here are the SAME objects PKI Visibility and TLS
 * Telemetry render: both pages read `buildTlsPkiModel()` through the shared
 * Trust Fabric. A serial that appears once there appears once here, so the two
 * pages cannot report different certificate counts.
 *
 * What this page adds over PKI Visibility is the LIFECYCLE layer: expiry bands,
 * renewal state, ownership and deployment mapping, and per-certificate chain
 * validation that explains in operator language exactly why a certificate or
 * chain is failing (brief section 5).
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Activity,
  CalendarClock,
  FileWarning,
  Filter,
  Landmark,
  ScrollText,
  ShieldCheck,
  Workflow,
} from 'lucide-react';
import {
  BarRow,
  ConnectionLost,
  Donut,
  Drawer,
  ErrorState,
  FilterSelect,
  FreshnessBar,
  NoDataState,
  Pager,
  PanelEmpty,
  Pill,
  ProvenanceFooter,
  SHELL_CSS,
  SearchInput,
  SectionLabel,
  StackedTrend,
  TONE,
  TableShell,
  Td,
  Th,
  fmtNumber,
  fmtPercent,
  relativeTime,
  absoluteTime,
} from '../_components/observability/primitives';
import {
  Basis,
  ChainCheckList,
  EventStream,
  ExpiryMeter,
  KpiSkeleton,
  LiveDot,
  ProviderChip,
  StaleBanner,
  TRUST_SHELL_CLASS,
  TRUST_SHELL_CSS,
  TrustKpiTile,
  TrustModuleNav,
  TrustPanel,
  TrustSkeleton,
  TrustStateBadge,
} from '../_components/trust/primitives';
import {
  useCertificateTelemetry,
  useTrustFabricDetail,
  useTrustFilters,
  useTrustPagedResource,
  type CertificateDetail,
} from '@/hooks/use-trust-fabric';
import { EXPIRY_BAND_LABEL, type CertificateTrustRecord, type ExpiryBand, type PkiCertificate } from '@/lib/trust-fabric/types';
import { cn } from '@/lib/utils';

const BAND_TONE: Record<ExpiryBand, 'critical' | 'warning' | 'info' | 'good' | 'neutral'> = {
  expired: 'critical',
  critical: 'critical',
  high: 'warning',
  warning: 'info',
  healthy: 'good',
  unknown: 'neutral',
};

const PAGE_SIZE = 25;

export default function CertificateTelemetry() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useCertificateTelemetry();
  const { loadCertificate, loading: detailLoading } = useTrustFabricDetail('certificate');
  const [searchParams, setSearchParams] = useSearchParams();
  const { filters, setFilter, activeCount, reset } = useTrustFilters({
    band: searchParams.get('band') ?? 'all',
    posture: searchParams.get('posture') ?? 'all',
    state: searchParams.get('state') ?? 'all',
    issue: searchParams.get('issue') ?? 'all',
    sort: 'expiry',
  });
  const [offset, setOffset] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [detail, setDetail] = useState<CertificateDetail | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  /* ---- server-side table (section 15) ---- */
  const query = useMemo(
    () => ({
      search: filters.search,
      band: filters.band,
      state: filters.state,
      posture: filters.posture,
      issuer: filters.issuer,
      environment: filters.environment,
      provider: filters.provider,
      region: filters.region,
      algorithm: filters.algorithm,
      tlsVersion: filters.tlsVersion,
      owner: filters.owner,
      renewal: filters.renewal,
      issue: filters.issue,
      range: filters.range,
      sort: filters.sort,
      limit: PAGE_SIZE,
      offset,
    }),
    [filters, offset],
  );

  const table = useTrustPagedResource<PkiCertificate>('certificate', '/certificates', 'certificates', query, revision);
  const trustRows = (table.extra.certificateTrust ?? []) as CertificateTrustRecord[];
  const trustById = useMemo(() => new Map(trustRows.map((row) => [row.certificateId, row])), [trustRows]);

  // Reset paging whenever the filter set changes, so page 3 of an old filter
  // cannot render as page 3 of a new one.
  useEffect(() => {
    setOffset(0);
  }, [filters]);

  const openCertificate = useCallback(
    async (id: string) => {
      setDrawerOpen(true);
      setDetail(null);
      const result = await loadCertificate(id);
      if (result) setDetail(result);
    },
    [loadCertificate],
  );

  // Deep link: /dashboard/certificate-telemetry?certificate=<id> opens the drawer.
  useEffect(() => {
    const target = searchParams.get('certificate');
    if (target && !drawerOpen) void openCertificate(target);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
    setDetail(null);
    if (searchParams.get('certificate')) {
      const next = new URLSearchParams(searchParams);
      next.delete('certificate');
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await refresh(true);
    setRefreshing(false);
  }, [refresh]);

  const lifecycleRows = useMemo(() => {
    if (!data) return [];
    const lifecycle = data.certificateIntel.lifecycle;
    return [
      { label: 'Valid', value: lifecycle.valid, hex: TONE.good.hex },
      { label: 'Expiring', value: lifecycle.expiring, hex: TONE.warning.hex },
      { label: 'Expired', value: lifecycle.expired, hex: TONE.critical.hex },
      { label: 'Revoked', value: lifecycle.revoked, hex: TONE.critical.hex },
      { label: 'Unknown', value: lifecycle.unknown, hex: TONE.neutral.hex },
    ].filter((row) => row.value > 0);
  }, [data]);

  if (state === 'loading' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <KpiSkeleton count={6} />
        <TrustSkeleton rows={3} height={180} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={TRUST_SHELL_CLASS}>
        <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>
        <ErrorState message={error || 'Unable to load certificate telemetry.'} onRetry={() => void refresh(true)} />
      </div>
    );
  }

  if (!data) return null;

  const intel = data.certificateIntel;
  const expiringCount = intel.bands.filter((band) => band.band === 'critical' || band.band === 'high').reduce((sum, band) => sum + band.count, 0);

  return (
    <div className={TRUST_SHELL_CLASS}>
      <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>

      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <ScrollText className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Certificate <span className="text-cyan-300">Telemetry</span>
              <LiveDot live={live} />
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              Certificate lifecycle, chain validation and TLS intelligence over your real certificate inventory — the same records PKI
              Visibility and the Quantum Readiness Engine read.
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

      {!live ? <ConnectionLost onReconnect={reconnect} lastSyncedAt={lastSyncedAt} /> : null}
      {data.stale && data.staleSinceHours !== null ? <StaleBanner hours={data.staleSinceHours} onRefresh={() => void onRefresh()} /> : null}

      {data.totals.certificates === 0 ? (
        <NoDataState
          title="No certificates discovered"
          body="No telemetry or discovered certificates are currently available for this tenant. Certificates are collected by agent scans of your hosts, by cloud connectors reading managed certificate stores, and by authorized transport scans of your own endpoints."
          telemetry={data.telemetry}
        />
      ) : null}

      {/* ============ KPIs ============ */}
      <section aria-label="Certificate KPIs" className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <TrustKpiTile
          index={0}
          label="Total certificates"
          value={data.totals.certificates}
          detail="Deduplicated across inventory, scanner and runtime"
          tone="neutral"
          hint="One record per real certificate. Rows from certificates, crypto_inventory and scanner_evidence describing the same serial collapse onto one."
        />
        <TrustKpiTile
          index={1}
          label="Expiring ≤ 30 days"
          value={expiringCount}
          detail="Inside the renewal window"
          tone={expiringCount > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('band', 'high')}
          hint="Combines the critical (7 day) and high-risk (30 day) bands."
        />
        <TrustKpiTile
          index={2}
          label="Expired"
          value={intel.lifecycle.expired}
          detail={intel.lifecycle.expired > 0 ? 'Handshakes using these already fail' : 'None expired'}
          tone={intel.lifecycle.expired > 0 ? 'critical' : 'good'}
          onClick={() => setFilter('band', 'expired')}
          hint="Certificates whose notAfter date has passed."
        />
        <TrustKpiTile
          index={3}
          label="Chain failures"
          value={intel.chainValidation.failed}
          detail="At least one validation check failing"
          tone={intel.chainValidation.failed > 0 ? 'critical' : 'good'}
          onClick={() => setFilter('issue', 'chain-failure')}
          hint="Self-signed, name mismatch, weak key, broken signature hash or revoked."
        />
        <TrustKpiTile
          index={4}
          label="Orphan certificates"
          value={intel.orphans.length}
          detail="No asset or endpoint mapping"
          tone={intel.orphans.length > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('issue', 'orphan')}
          hint="In inventory but bound to nothing, so blast radius cannot be computed."
        />
        <TrustKpiTile
          index={5}
          label="Without an owner"
          value={intel.ownerless.length}
          detail="Renewal cannot be assigned"
          tone={intel.ownerless.length > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('issue', 'ownerless')}
          hint="No service_owner on the owning asset, so expiry alerts reach nobody."
        />
      </section>

      {/* ============ lifecycle / bands / issuers ============ */}
      <div className="grid gap-3 xl:grid-cols-3">
        <TrustPanel index={0}>
          <SectionLabel icon={ShieldCheck} hint="Current lifecycle position of every discovered certificate.">
            Lifecycle
          </SectionLabel>
          {lifecycleRows.length === 0 ? (
            <PanelEmpty>No certificates to classify.</PanelEmpty>
          ) : (
            <Donut rows={lifecycleRows} centerLabel="Certificates" centerValue={fmtNumber(data.totals.certificates)} />
          )}
        </TrustPanel>

        <TrustPanel index={1}>
          <SectionLabel
            icon={CalendarClock}
            hint="Expiration intelligence bands: expired, ≤7 days, ≤30 days, ≤60 days, and healthy beyond 60."
          >
            Expiration risk bands
          </SectionLabel>
          <div className="space-y-1.5">
            {intel.bands
              .filter((band) => band.count > 0)
              .map((band) => (
                <BarRow
                  key={band.band}
                  label={EXPIRY_BAND_LABEL[band.band]}
                  count={band.count}
                  percent={band.percent}
                  tone={BAND_TONE[band.band]}
                  onClick={() => setFilter('band', band.band)}
                  title={`Filter the inventory to the ${EXPIRY_BAND_LABEL[band.band]} band`}
                />
              ))}
          </div>
          <Basis>
            A certificate with no recorded validity window is placed in &ldquo;No expiry recorded&rdquo;, never in Healthy.
          </Basis>
        </TrustPanel>

        <TrustPanel index={2}>
          <SectionLabel icon={Landmark} hint="Issuing authorities observed in this tenant, with their certificate populations." href="/dashboard/pki-visibility">
            Issuing authorities
          </SectionLabel>
          {intel.issuers.length === 0 ? (
            <PanelEmpty>No issuer is recorded on any certificate.</PanelEmpty>
          ) : (
            <ul className="space-y-1">
              {intel.issuers.slice(0, 7).map((issuer) => (
                <li key={issuer.issuer}>
                  <button
                    type="button"
                    onClick={() => setFilter('issuer', issuer.issuer.toLowerCase())}
                    className="flex w-full items-center justify-between gap-2 rounded px-1 py-1 text-left transition hover:bg-white/[0.05]"
                  >
                    <span className="min-w-0 truncate text-[10.5px] font-semibold text-white/70">{issuer.issuer}</span>
                    <span className="shrink-0 font-mono text-[10px] text-white/40">
                      {fmtNumber(issuer.certificates)}
                      {issuer.expiring > 0 ? <span className="ml-1 text-amber-300">{issuer.expiring} exp</span> : null}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </TrustPanel>
      </div>

      {/* ============ expiry horizon + discovery trend ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={3}>
          <SectionLabel icon={CalendarClock} hint="Real notAfter dates bucketed by month across the next 12 months.">
            Expiration timeline
          </SectionLabel>
          {intel.expiryTimeline.length === 0 ? (
            <PanelEmpty>No certificate expires within the next 12 months, or no expiry dates are recorded.</PanelEmpty>
          ) : (
            <div className="space-y-1.5">
              {intel.expiryTimeline.map((point) => (
                <BarRow
                  key={point.date}
                  label={point.label}
                  count={point.count}
                  percent={Math.round((point.count / Math.max(1, Math.max(...intel.expiryTimeline.map((p) => p.count)))) * 100)}
                  tone="info"
                />
              ))}
            </div>
          )}
        </TrustPanel>

        <TrustPanel index={4}>
          <SectionLabel icon={Activity} hint="Certificates observed per day over the last 30 days, from real observation timestamps.">
            Certificate discovery trend
          </SectionLabel>
          <StackedTrend
            points={intel.discoveryTrend as unknown as Array<Record<string, number | string>>}
            series={[
              { key: 'discovered', label: 'Observed', hex: TONE.neutral.hex },
              { key: 'expiring', label: 'Expiring ≤30d', hex: TONE.warning.hex },
            ]}
            emptyLabel="No certificate has been observed in the last 30 days."
          />
        </TrustPanel>
      </div>

      {/* ============ inventory table ============ */}
      <TrustPanel index={5}>
        <SectionLabel
          icon={Filter}
          hint="Filtered and paged on the server against the same snapshot the KPIs came from, so no page of results can disagree with the header."
          meta={`${fmtNumber(table.total)} matching`}
        >
          Certificate inventory
        </SectionLabel>

        {/* ---- filter bar (section 10) ---- */}
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SearchInput
            value={filters.search}
            onChange={(value) => setFilter('search', value)}
            placeholder="Search common name, SAN, issuer, serial or owner"
          />
          <FilterSelect
            label="Band"
            value={filters.band}
            onChange={(value) => setFilter('band', value)}
            options={[{ value: 'all', label: 'All' }, ...intel.bands.map((band) => ({ value: band.band, label: `${EXPIRY_BAND_LABEL[band.band]} (${band.count})` }))]}
          />
          <FilterSelect
            label="Posture"
            value={filters.posture}
            onChange={(value) => setFilter('posture', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'quantum-vulnerable', label: 'Quantum vulnerable' },
              { value: 'hybrid-ready', label: 'Hybrid ready' },
              { value: 'pqc-ready', label: 'PQC ready' },
              { value: 'quantum-safe', label: 'Quantum safe' },
              { value: 'unknown', label: 'Unknown' },
            ]}
          />
          <FilterSelect
            label="Issuer"
            value={filters.issuer}
            onChange={(value) => setFilter('issuer', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.issuers.map((issuer) => ({ value: issuer.toLowerCase(), label: issuer }))]}
          />
          <FilterSelect
            label="Environment"
            value={filters.environment}
            onChange={(value) => setFilter('environment', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.environments.map((env) => ({ value: env.toLowerCase(), label: env }))]}
          />
          <FilterSelect
            label="Cloud"
            value={filters.provider}
            onChange={(value) => setFilter('provider', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.providers.map((provider) => ({ value: provider.id, label: provider.label }))]}
          />
          <FilterSelect
            label="Algorithm"
            value={filters.algorithm}
            onChange={(value) => setFilter('algorithm', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.algorithms.map((algorithm) => ({ value: algorithm.toLowerCase(), label: algorithm }))]}
          />
          <FilterSelect
            label="Issue"
            value={filters.issue}
            onChange={(value) => setFilter('issue', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'orphan', label: 'Orphan' },
              { value: 'ownerless', label: 'No owner' },
              { value: 'undeployed', label: 'No deployment' },
              { value: 'chain-failure', label: 'Chain failure' },
            ]}
          />
          <FilterSelect
            label="Renewal"
            value={filters.renewal}
            onChange={(value) => setFilter('renewal', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'not-started', label: 'Not started' },
              { value: 'planned', label: 'Planned' },
              { value: 'in-progress', label: 'In progress' },
              { value: 'renewed', label: 'Renewed' },
              { value: 'failed', label: 'Failed' },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={filters.sort}
            onChange={(value) => setFilter('sort', value)}
            options={[
              { value: 'expiry', label: 'Soonest expiry' },
              { value: 'risk', label: 'Highest risk' },
              { value: 'blast', label: 'Largest blast radius' },
              { value: 'name', label: 'Name' },
              { value: 'issuer', label: 'Issuer' },
            ]}
          />
          {activeCount > 0 ? (
            <button
              type="button"
              onClick={reset}
              className="rounded-md border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/20"
            >
              Clear {activeCount} filter{activeCount === 1 ? '' : 's'}
            </button>
          ) : null}
        </div>

        {table.error ? (
          <ErrorState message={table.error} onRetry={() => void refresh()} />
        ) : table.loading && table.rows.length === 0 ? (
          <TrustSkeleton rows={6} height={44} />
        ) : table.rows.length === 0 ? (
          <PanelEmpty>
            No certificate matches the current filters.
            {activeCount > 0 ? ' Clear the filters to see the full inventory.' : ''}
          </PanelEmpty>
        ) : (
          <>
            <TableShell minWidth={1180}>
              <thead>
                <tr>
                  <Th>Common name</Th>
                  <Th>Issuer</Th>
                  <Th>Algorithm</Th>
                  <Th>TLS</Th>
                  <Th>Valid until</Th>
                  <Th>Remaining</Th>
                  <Th>Trust state</Th>
                  <Th>Chain</Th>
                  <Th>Deployment</Th>
                  <Th align="right">Affected</Th>
                </tr>
              </thead>
              <tbody>
                {table.rows.map((certificate) => {
                  const trust = trustById.get(certificate.id);
                  return (
                    <tr
                      key={certificate.id}
                      onClick={() => void openCertificate(certificate.id)}
                      className="cursor-pointer border-b border-white/5 last:border-0 transition hover:bg-white/[0.04]"
                    >
                      <Td>
                        <span className="block max-w-[220px] truncate text-[11.5px] font-bold text-white/85">
                          {certificate.name || certificate.subject || 'Certificate'}
                        </span>
                        {certificate.san.length > 0 ? (
                          <span className="block max-w-[220px] truncate text-[9.5px] text-white/35">
                            {certificate.san.length} SAN{certificate.san.length === 1 ? '' : 's'}: {certificate.san.slice(0, 2).join(', ')}
                          </span>
                        ) : null}
                      </Td>
                      <Td>
                        <span className="block max-w-[170px] truncate text-[10.5px] text-white/55">
                          {certificate.issuer || 'Not recorded'}
                        </span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10.5px] text-white/65">{certificate.algorithmLabel}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10px] text-white/45">
                          {trust && trust.tlsVersions.length > 0 ? trust.tlsVersions.join(', ') : 'Not observed'}
                        </span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[10px] text-white/50">
                          {certificate.notAfter ? absoluteTime(certificate.notAfter).split(',')[0] : 'Not recorded'}
                        </span>
                      </Td>
                      <Td className="min-w-[120px]">
                        <ExpiryMeter days={certificate.daysToExpiry} />
                      </Td>
                      <Td>{trust ? <TrustStateBadge state={trust.state} reason={trust.checks.find((c) => c.status === 'fail')?.detail} size="sm" /> : null}</Td>
                      <Td>
                        {trust ? (
                          <span
                            className={cn(
                              'font-mono text-[10px]',
                              trust.failedChecks > 0 ? 'text-red-300' : trust.warnChecks > 0 ? 'text-amber-300' : 'text-emerald-300',
                            )}
                            title={`${trust.failedChecks} failing, ${trust.warnChecks} warning, ${trust.notEvaluatedChecks} not evaluable`}
                          >
                            {trust.failedChecks > 0
                              ? `${trust.failedChecks} fail`
                              : trust.warnChecks > 0
                                ? `${trust.warnChecks} warn`
                                : 'Pass'}
                          </span>
                        ) : null}
                      </Td>
                      <Td>
                        {trust ? (
                          trust.orphan ? (
                            <Pill tone="warning">Orphan</Pill>
                          ) : trust.deploymentKnown ? (
                            <span className="text-[10px] text-white/50">
                              {trust.provider !== 'unattributed' ? <ProviderChip provider={trust.provider} label={trust.providerLabel} /> : trust.environment || 'Mapped'}
                            </span>
                          ) : (
                            <span className="text-[10px] text-white/35">Not mapped</span>
                          )
                        ) : null}
                      </Td>
                      <Td align="right">
                        <span className="font-mono text-[11px] text-white/55">{trust ? fmtNumber(trust.affectedAssetCount) : '—'}</span>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </TableShell>
            <Pager offset={offset} limit={PAGE_SIZE} total={table.total} onChange={setOffset} />
          </>
        )}
      </TrustPanel>

      {/* ============ data quality + events ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={6}>
          <SectionLabel icon={FileWarning} hint="Reconciliation checks specific to the certificate inventory (section 16).">
            Certificate data quality
          </SectionLabel>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {[
              { label: 'Orphans', value: intel.orphans.length, filter: 'orphan', hint: 'No asset or endpoint mapping' },
              { label: 'No owner', value: intel.ownerless.length, filter: 'ownerless', hint: 'Renewal cannot be assigned' },
              { label: 'No deployment', value: intel.undeployed.length, filter: 'undeployed', hint: 'Never seen served anywhere' },
              { label: 'Duplicate groups', value: intel.duplicates.length, filter: 'all', hint: 'Same subject and issuer on more than one record' },
              { label: 'Renewal failures', value: intel.renewalFailures.length, filter: 'all', hint: 'A renewal job reported failure' },
              { label: 'Not evaluable', value: intel.chainValidation.notEvaluated, filter: 'all', hint: 'Too little evidence to run any chain check' },
            ].map((item) => (
              <button
                key={item.label}
                type="button"
                title={item.hint}
                onClick={() => item.filter !== 'all' && setFilter('issue', item.filter)}
                className="rounded-lg border border-white/8 bg-black/20 p-2.5 text-left transition hover:border-cyan-400/30 hover:bg-black/35"
              >
                <span className="block text-[9px] font-black uppercase tracking-wider text-white/35">{item.label}</span>
                <span className={cn('mt-1 block text-[18px] font-black leading-none', item.value > 0 ? 'text-amber-300' : 'text-emerald-300')}>
                  {fmtNumber(item.value)}
                </span>
              </button>
            ))}
          </div>
          <Basis>
            Duplicates are expected during renewal overlap. The platform reports the group rather than silently merging or double-counting
            it — the headline total of {fmtNumber(intel.reconciledTotal)} certificates already counts each real certificate once.
          </Basis>
        </TrustPanel>

        <TrustPanel index={7}>
          <SectionLabel icon={Activity} hint="Certificate lifecycle and chain events derived from your own records.">
            Certificate events
          </SectionLabel>
          <EventStream events={data.events} limit={9} emptyLabel="No certificate lifecycle events in the last 30 days." />
        </TrustPanel>
      </div>

      <ProvenanceFooter telemetry={data.telemetry} />

      {/* ============ drill-down drawer (section 11) ============ */}
      <Drawer
        open={drawerOpen}
        onClose={closeDrawer}
        title={detail?.certificate.name || detail?.certificate.subject || 'Certificate'}
        subtitle={detail?.certificate.serialNumber ? `Serial ${detail.certificate.serialNumber}` : undefined}
      >
        {detailLoading && !detail ? (
          <TrustSkeleton rows={5} height={52} />
        ) : !detail ? (
          <PanelEmpty>Certificate detail could not be loaded.</PanelEmpty>
        ) : (
          <CertificateDrawerBody detail={detail} />
        )}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Drawer body                                                         */
/* ------------------------------------------------------------------ */

function CertificateDrawerBody({ detail }: { detail: CertificateDetail }) {
  const { certificate, trust, chain, chainNodes, affected, endpoint } = detail;

  return (
    <div className="space-y-4">
      {/* identity */}
      <section>
        <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Identity</h3>
        <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
          <Field label="Subject" value={certificate.subject || '—'} />
          <Field label="Issuer" value={certificate.issuer || 'Not recorded'} />
          <Field label="Serial" value={certificate.serialNumber || 'Not recorded'} mono />
          <Field label="Fingerprint" value={certificate.fingerprint || 'Not recorded'} mono />
          <Field label="Algorithm" value={certificate.algorithmLabel} />
          <Field label="Key size" value={certificate.keySize ? `${certificate.keySize} bits` : 'Not recorded'} />
          <Field label="Signature" value={certificate.signatureAlgorithm || 'Not recorded'} />
          <Field label="Valid from" value={absoluteTime(certificate.notBefore)} />
          <Field label="Valid until" value={absoluteTime(certificate.notAfter)} />
          <Field label="Last observed" value={relativeTime(certificate.lastObservedAt)} />
        </dl>
        {certificate.san.length > 0 ? (
          <div className="mt-2">
            <span className="text-[9px] font-black uppercase tracking-wider text-white/35">Subject alternative names</span>
            <div className="mt-1 flex flex-wrap gap-1">
              {certificate.san.map((name) => (
                <span key={name} className="rounded border border-white/10 bg-black/25 px-1.5 py-0.5 font-mono text-[9.5px] text-white/55">
                  {name}
                </span>
              ))}
            </div>
          </div>
        ) : null}
      </section>

      {/* trust state */}
      {trust ? (
        <section>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h3 className="text-[9.5px] font-black uppercase tracking-wider text-white/35">Trust state</h3>
            <TrustStateBadge state={trust.state} size="sm" />
            <Pill tone={BAND_TONE[trust.band]}>{EXPIRY_BAND_LABEL[trust.band]}</Pill>
            {trust.provider !== 'unattributed' ? <ProviderChip provider={trust.provider} label={trust.providerLabel} /> : null}
          </div>
          <p className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.06] p-2.5 text-[11px] leading-relaxed text-cyan-100/80">
            <span className="font-black uppercase tracking-wider">Recommended action:</span> {trust.remediation}
          </p>
          <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
            <Field label="Owner" value={trust.owner} />
            <Field label="Environment" value={trust.environment || 'Not recorded'} />
            <Field label="Region" value={trust.region || 'Not recorded'} />
            <Field label="Account" value={trust.account || 'Not recorded'} />
            <Field label="Renewal" value={`${trust.renewal.status.replace(/-/g, ' ')} — ${trust.renewal.detail}`} />
            <Field label="Deployment" value={trust.orphan ? 'Orphan — bound to nothing' : trust.deploymentKnown ? 'Mapped' : 'Not mapped'} />
          </dl>
        </section>
      ) : null}

      {/* chain validation */}
      {trust ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">
            Chain validation — {trust.failedChecks} failing, {trust.warnChecks} warning, {trust.notEvaluatedChecks} not evaluable
          </h3>
          <ChainCheckList checks={trust.checks} />
        </section>
      ) : null}

      {/* chain path */}
      {chain && chainNodes.length > 0 ? (
        <section>
          <h3 className="mb-2 flex items-center gap-1.5 text-[9.5px] font-black uppercase tracking-wider text-white/35">
            <Workflow className="h-3 w-3" aria-hidden="true" /> Trust chain
          </h3>
          <ol className="space-y-1">
            {chainNodes.map((node, index) => (
              <li key={node.id} className="flex items-center gap-2 rounded-lg border border-white/8 bg-black/20 p-2">
                <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-white/8 text-[9px] font-black text-white/50">
                  {index + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <span className="block truncate text-[10.5px] font-bold text-white/80">{node.label}</span>
                  <span className="block truncate text-[9.5px] text-white/40">{node.stateReason}</span>
                </div>
                <TrustStateBadge state={node.state} size="sm" />
              </li>
            ))}
          </ol>
          {!chain.complete ? (
            <p className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.06] p-2 text-[10.5px] leading-relaxed text-amber-100/80">
              Chain is incomplete: {chain.incompleteReason}.
            </p>
          ) : null}
        </section>
      ) : null}

      {/* affected assets */}
      <section>
        <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">
          Affected assets {affected.length > 0 ? `(${affected.length})` : ''}
        </h3>
        {affected.length === 0 ? (
          <PanelEmpty>
            No asset dependency is mapped to this certificate, so the impact of its expiry cannot be traced. Build the dependency map to
            answer this.
          </PanelEmpty>
        ) : (
          <ul className="space-y-1">
            {affected.slice(0, 12).map((node) => (
              <li key={node.id}>
                <Link
                  to={node.href}
                  className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-black/20 p-2 no-underline transition hover:border-cyan-400/30"
                >
                  <span className="min-w-0 truncate text-[10.5px] font-semibold text-white/70">{node.label}</span>
                  <TrustStateBadge state={node.state} size="sm" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* endpoint */}
      {endpoint ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Serving endpoint</h3>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
            <Field label="Host" value={endpoint.port ? `${endpoint.host}:${endpoint.port}` : endpoint.host} mono />
            <Field label="Negotiated" value={endpoint.negotiatedVersion || 'Not observed'} />
            <Field label="Forward secrecy" value={endpoint.forwardSecrecy === null ? 'Not observed' : endpoint.forwardSecrecy ? 'Yes' : 'No'} />
            <Field label="Cipher suites" value={endpoint.cipherSuites.length ? endpoint.cipherSuites.slice(0, 2).join(', ') : 'Not observed'} />
          </dl>
        </section>
      ) : null}

      {/* evidence */}
      <section>
        <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Evidence</h3>
        <ul className="space-y-1">
          {certificate.evidence.slice(0, 8).map((ref, index) => (
            <li key={`${ref.recordId}-${index}`} className="rounded border border-white/8 bg-black/20 p-2 text-[10px]">
              <span className="font-mono text-cyan-300/70">{ref.table}</span>
              <span className="ml-2 text-white/45">{ref.detail}</span>
              <span className="ml-2 text-white/25">{relativeTime(ref.observedAt)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[9px] font-black uppercase tracking-wider text-white/30">{label}</dt>
      <dd className={cn('mt-0.5 truncate text-white/70', mono && 'font-mono text-[10px]')} title={value}>
        {value}
      </dd>
    </div>
  );
}
