'use client';

/**
 * Cross-Cloud Cryptographic Visibility & Distributed Encryption Monitoring —
 * `/dashboard/multi-cloud-telemetry`.
 *
 * Brief section 6 sets the constraint this page is built around: "Do not assume
 * a cloud asset exists unless it actually exists in the user's tenant data."
 *
 * There is no synthetic cloud inventory here. A resource on this page is a real
 * `assets` row whose own evidence — hostname, tag, metadata, ARN-like
 * identifier, or a connected account corroborating one of those — names a
 * cloud. Resources that are cloud-shaped but carry no such evidence are shown
 * in an explicit Unattributed bucket and are EXCLUDED from every per-provider
 * percentage, rather than being silently assigned to whichever cloud the tenant
 * happens to have connected.
 *
 * `Not observed` is used throughout for encryption state and key management.
 * It is a third value, distinct from both encrypted and unencrypted: without a
 * connector actually reading a resource's configuration, claiming either would
 * be an invention.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, Cloud, Filter, Globe2, KeyRound, Layers, ShieldAlert } from 'lucide-react';
import {
  BarRow,
  ConnectionLost,
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
  EncryptionBadge,
  EventStream,
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
  providerAccent,
  riseStyle,
} from '../_components/trust/primitives';
import {
  useMultiCloudTelemetry,
  useTrustFabricDetail,
  useTrustFilters,
  useTrustPagedResource,
  type CloudResourceDetail,
} from '@/hooks/use-trust-fabric';
import type { CloudProviderId, CloudResource } from '@/lib/trust-fabric/types';
import { cn } from '@/lib/utils';

const PAGE_SIZE = 25;

export default function MultiCloudTelemetry() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useMultiCloudTelemetry();
  const { loadCloudResource, loading: detailLoading } = useTrustFabricDetail('cloud');
  const { filters, setFilter, activeCount, reset } = useTrustFilters({ sort: 'risk' });
  const [offset, setOffset] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [detail, setDetail] = useState<CloudResourceDetail | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const query = useMemo(
    () => ({
      search: filters.search,
      provider: filters.provider,
      account: filters.account,
      region: filters.region,
      environment: filters.environment,
      encryption: filters.encryption,
      state: filters.state,
      posture: filters.posture,
      compliance: filters.compliance,
      attribution: filters.attribution,
      risk: filters.risk,
      range: filters.range,
      sort: filters.sort,
      limit: PAGE_SIZE,
      offset,
    }),
    [filters, offset],
  );

  const table = useTrustPagedResource<CloudResource>('cloud', '/cloud-resources', 'resources', query, revision);

  useEffect(() => {
    setOffset(0);
  }, [filters]);

  const openResource = useCallback(
    async (id: string) => {
      setDrawerOpen(true);
      setDetail(null);
      const result = await loadCloudResource(id);
      if (result) setDetail(result);
    },
    [loadCloudResource],
  );

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await refresh(true);
    setRefreshing(false);
  }, [refresh]);

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
        <ErrorState message={error || 'Unable to load multi-cloud telemetry.'} onRetry={() => void refresh(true)} />
      </div>
    );
  }

  if (!data) return null;

  const cloud = data.cloud;
  const measuredProviders = cloud.providers.filter((provider) => provider.provider !== 'unattributed');

  return (
    <div className={TRUST_SHELL_CLASS}>
      <style>{SHELL_CSS}{TRUST_SHELL_CSS}</style>

      <header className="flex flex-col gap-3 border-b border-white/10 pb-3.5 xl:flex-row xl:items-end xl:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-500/10 text-cyan-300 shadow-[0_0_28px_rgba(34,211,238,0.2)]">
            <Cloud className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-2xl font-black uppercase leading-none tracking-tight text-white lg:text-[26px]">
              Multi-Cloud <span className="text-cyan-300">Telemetry</span>
              <LiveDot live={live} />
            </h1>
            <p className="mt-1.5 max-w-3xl text-[12px] font-medium leading-relaxed text-white/45">
              Cross-cloud cryptographic posture over resources that genuinely exist in your tenant. Nothing here is assumed from a
              connected account alone — every resource states how its provider was determined.
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

      {cloud.totals.resources === 0 ? (
        <NoDataState
          title="No cloud resources discovered"
          body="No telemetry or discovered cloud resources are currently available for this tenant. Connect an AWS, Azure, Google Cloud or Kubernetes account, or tag your existing assets with their provider and account id — this page will populate from the resources that actually come back."
          telemetry={data.telemetry}
        />
      ) : null}

      {/* ============ KPIs ============ */}
      <section aria-label="Cloud KPIs" className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <TrustKpiTile
          index={0}
          label="Cloud resources"
          value={cloud.totals.attributedResources}
          detail={
            cloud.totals.unattributedResources > 0
              ? `${fmtNumber(cloud.totals.unattributedResources)} unattributed`
              : 'All resources attributed'
          }
          tone={cloud.totals.attributedResources > 0 ? 'info' : 'neutral'}
          hint="Resources whose own evidence names a cloud. Unattributed resources are excluded from every per-provider percentage."
        />
        <TrustKpiTile
          index={1}
          label="Clouds in scope"
          value={measuredProviders.length}
          detail={`${fmtNumber(cloud.connectorsActive)}/${fmtNumber(cloud.connectorsConfigured)} connectors active`}
          tone="neutral"
          hint="A cloud appears when it has either a connected account or at least one attributed resource."
        />
        <TrustKpiTile
          index={2}
          label="Encrypted"
          value={cloud.totals.encrypted}
          detail={`${fmtNumber(cloud.totals.encryptionNotObserved)} not observed`}
          tone={cloud.totals.unencrypted > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('encryption', 'encrypted')}
          hint="Resources with a real encryption reading. 'Not observed' means no connector has read the configuration — it is not a claim of either state."
        />
        <TrustKpiTile
          index={3}
          label="Unencrypted"
          value={cloud.totals.unencrypted}
          detail={cloud.totals.unencrypted > 0 ? 'Measured as lacking encryption' : 'None measured as unencrypted'}
          tone={cloud.totals.unencrypted > 0 ? 'critical' : 'good'}
          onClick={() => setFilter('encryption', 'unencrypted')}
          hint="Only resources whose evidence explicitly reports absent encryption."
        />
        <TrustKpiTile
          index={4}
          label="Quantum vulnerable"
          value={cloud.totals.quantumVulnerable}
          detail={`${fmtNumber(cloud.totals.pqcReady)} PQC or hybrid ready`}
          tone={cloud.totals.quantumVulnerable > 0 ? 'warning' : 'good'}
          onClick={() => setFilter('posture', 'quantum-vulnerable')}
          hint="Same posture classification the Quantum Readiness Engine and Migration Planner apply to these assets."
        />
        <TrustKpiTile
          index={5}
          label="KMS-managed"
          value={cloud.totals.kmsManaged}
          detail="Key manager identified from evidence"
          tone={cloud.totals.kmsManaged > 0 ? 'good' : 'neutral'}
          hint="A key manager is named only when a real signal identifies it — never defaulted."
        />
      </section>

      {/* ============ provider cards ============ */}
      <TrustPanel index={0}>
        <SectionLabel
          icon={Layers}
          hint="Per-cloud posture. A connected account with no discovered resource is shown as connected but unmeasured, rather than as healthy."
          meta={`${fmtNumber(cloud.providers.length)} clouds`}
        >
          Cross-cloud posture
        </SectionLabel>
        {cloud.providers.length === 0 ? (
          <PanelEmpty>No cloud provider is connected and no asset carries provider evidence.</PanelEmpty>
        ) : (
          <div className="grid gap-2.5 md:grid-cols-2 xl:grid-cols-3">
            {cloud.providers.map((provider, index) => {
              const accent = providerAccent(provider.provider);
              return (
                <button
                  key={provider.provider}
                  type="button"
                  onClick={() => setFilter('provider', provider.provider)}
                  style={{ ...riseStyle(index), borderColor: `${accent}33` }}
                  className="tf-rise tf-hover-lift rounded-xl border bg-black/25 p-3 text-left"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <ProviderChip provider={provider.provider} label={provider.providerLabel} />
                    <div className="flex items-center gap-2">
                      {provider.connected ? (
                        <Pill tone="good">Connected</Pill>
                      ) : provider.connectorCount > 0 ? (
                        <Pill tone="warning">{provider.connectorStatus}</Pill>
                      ) : (
                        <Pill tone="neutral">Evidence only</Pill>
                      )}
                      <span
                        className={cn(
                          'font-mono text-[18px] font-black leading-none',
                          provider.trustScore === null ? 'text-white/30' : provider.trustScore >= 80 ? 'text-emerald-300' : provider.trustScore >= 55 ? 'text-amber-300' : 'text-red-300',
                        )}
                        title={provider.measured ? 'Measured trust score' : 'No measured posture in this cloud'}
                      >
                        {provider.trustScore === null ? 'n/m' : provider.trustScore}
                      </span>
                    </div>
                  </div>

                  <p className="mt-1.5 text-[10px] leading-snug text-white/45">{provider.stateReason}</p>

                  <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[9.5px]">
                    <Metric label="Resources" value={fmtNumber(provider.resources)} />
                    <Metric label="Regions" value={fmtNumber(provider.regions.length)} />
                    <Metric label="Accounts" value={fmtNumber(provider.accounts.length)} />
                    <Metric label="Certificates" value={fmtNumber(provider.certificates)} />
                    <Metric
                      label="Encryption"
                      value={provider.encryptionCoverage === null ? 'Not observed' : `${provider.encryptionCoverage}%`}
                      tone={provider.encryptionCoverage === null ? 'muted' : provider.encryptionCoverage >= 90 ? 'good' : 'warn'}
                    />
                    <Metric
                      label="KMS"
                      value={provider.kmsResources > 0 ? provider.kmsProviders.slice(0, 1).join(', ') || fmtNumber(provider.kmsResources) : 'Not observed'}
                      tone={provider.kmsResources > 0 ? 'good' : 'muted'}
                    />
                    <Metric label="TLS 1.3" value={fmtNumber(provider.tls13Endpoints)} tone="good" />
                    <Metric
                      label="Legacy TLS"
                      value={fmtNumber(provider.legacyTlsEndpoints)}
                      tone={provider.legacyTlsEndpoints > 0 ? 'bad' : 'good'}
                    />
                    <Metric
                      label="Quantum vuln."
                      value={fmtNumber(provider.quantumVulnerableResources)}
                      tone={provider.quantumVulnerableResources > 0 ? 'warn' : 'good'}
                    />
                    <Metric
                      label="Critical"
                      value={fmtNumber(provider.criticalFindings)}
                      tone={provider.criticalFindings > 0 ? 'bad' : 'good'}
                    />
                  </dl>

                  <div className="mt-2 flex items-center justify-between gap-2 border-t border-white/8 pt-1.5">
                    <TrustStateBadge state={provider.state} reason={provider.stateReason} size="sm" />
                    <span className="font-mono text-[9px] text-white/30">
                      {provider.lastSyncAt ? `synced ${relativeTime(provider.lastSyncAt)}` : `seen ${relativeTime(provider.lastTelemetryAt)}`}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        )}
        <Basis>
          {fmtNumber(cloud.totals.attributedResources)} of {fmtNumber(cloud.totals.resources)} resources could be attributed to a named
          cloud. Percentages above are measured against attributed, measured resources only.
        </Basis>
      </TrustPanel>

      {/* ============ regions + drift ============ */}
      <div className="grid gap-3 xl:grid-cols-2">
        <TrustPanel index={1}>
          <SectionLabel
            icon={Globe2}
            hint="Regional cryptographic posture. A region is scored only where at least one resource in it carries an encryption reading."
            meta={`${fmtNumber(cloud.regions.length)} regions`}
          >
            Regional posture
          </SectionLabel>
          {cloud.regions.length === 0 ? (
            <PanelEmpty>No resource records a region, so regional posture cannot be reported.</PanelEmpty>
          ) : (
            <TableShell minWidth={620}>
              <thead>
                <tr>
                  <Th>Region</Th>
                  <Th>Cloud</Th>
                  <Th align="right">Resources</Th>
                  <Th align="right">Encrypted</Th>
                  <Th align="right">Certs</Th>
                  <Th align="right">Score</Th>
                  <Th>State</Th>
                </tr>
              </thead>
              <tbody>
                {cloud.regions.slice(0, 14).map((region) => (
                  <tr
                    key={`${region.provider}:${region.region}`}
                    onClick={() => {
                      setFilter('provider', region.provider);
                      setFilter('region', region.region.toLowerCase());
                    }}
                    className="cursor-pointer border-b border-white/5 last:border-0 transition hover:bg-white/[0.04]"
                  >
                    <Td>
                      <span className="font-mono text-[11px] text-white/75">{region.region}</span>
                      {region.anomaly ? (
                        <span className="mt-0.5 block max-w-[240px] text-[9.5px] leading-snug text-amber-300/70">{region.anomaly}</span>
                      ) : null}
                    </Td>
                    <Td>
                      <ProviderChip provider={region.provider} label={region.providerLabel} />
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/55">{fmtNumber(region.resources)}</span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/55">
                        {region.measured ? `${region.encrypted}/${region.encrypted + region.unencrypted}` : 'n/m'}
                      </span>
                    </Td>
                    <Td align="right">
                      <span className="font-mono text-[10.5px] text-white/55">{fmtNumber(region.certificates)}</span>
                    </Td>
                    <Td align="right">
                      <span className={cn('font-mono text-[10.5px] font-bold', region.trustScore === null ? 'text-white/30' : 'text-white/70')}>
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

        <div className="space-y-3">
          <TrustPanel index={2}>
            <SectionLabel
              icon={AlertTriangle}
              hint="The same policy applied differently across clouds. Only reported where two or more clouds carry measurements to compare."
            >
              Cross-cloud configuration drift
            </SectionLabel>
            {cloud.drift.length === 0 ? (
              <PanelEmpty>
                {measuredProviders.length < 2
                  ? 'Drift needs at least two measured clouds to compare. Connect another account to enable this comparison.'
                  : 'No material configuration drift detected between your clouds.'}
              </PanelEmpty>
            ) : (
              <ul className="space-y-1.5">
                {cloud.drift.map((item, index) => (
                  <li
                    key={item.id}
                    style={riseStyle(index, 40)}
                    className={cn(
                      'tf-rise rounded-lg border p-2.5',
                      item.severity === 'high' ? 'border-red-500/25 bg-red-500/[0.06]' : 'border-amber-500/25 bg-amber-500/[0.06]',
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10.5px] font-black uppercase tracking-wider text-white/80">{item.title}</span>
                      {item.providers.map((provider) => (
                        <ProviderChip key={provider} provider={provider} />
                      ))}
                    </div>
                    <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{item.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </TrustPanel>

          <TrustPanel index={3}>
            <SectionLabel icon={ShieldAlert} hint="Regions whose measured posture deviates materially from their provider's own baseline.">
              Regional anomalies
            </SectionLabel>
            {cloud.anomalies.length === 0 ? (
              <PanelEmpty>No region deviates materially from its provider baseline.</PanelEmpty>
            ) : (
              <ul className="space-y-1.5">
                {cloud.anomalies.slice(0, 6).map((anomaly, index) => (
                  <li key={anomaly.id} style={riseStyle(index, 40)} className="tf-rise rounded-lg border border-white/8 bg-black/20 p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <ProviderChip provider={anomaly.provider} />
                      <span className="font-mono text-[10px] text-white/60">{anomaly.region}</span>
                    </div>
                    <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{anomaly.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </TrustPanel>
        </div>
      </div>

      {/* ============ algorithm spread ============ */}
      <TrustPanel index={4}>
        <SectionLabel
          icon={KeyRound}
          hint="Where each cryptographic algorithm is actually deployed across your clouds — the weak-crypto and quantum-vulnerable distribution."
        >
          Algorithm distribution across clouds
        </SectionLabel>
        {cloud.algorithmSpread.length === 0 ? (
          <PanelEmpty>No encryption algorithm has been observed on any cloud resource.</PanelEmpty>
        ) : (
          <div className="space-y-2">
            {cloud.algorithmSpread.map((row) => (
              <div key={row.algorithm} className="rounded-lg border border-white/8 bg-black/20 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] font-bold text-white/80">{row.algorithm}</span>
                  <span className="font-mono text-[10px] text-white/40">{fmtNumber(row.total)} resources</span>
                </div>
                <div className="mt-1.5 flex h-2 overflow-hidden rounded-full bg-white/8">
                  {row.byProvider.map((slice) => (
                    <div
                      key={slice.provider}
                      title={`${slice.providerLabel}: ${slice.count}`}
                      style={{ width: `${(slice.count / row.total) * 100}%`, backgroundColor: providerAccent(slice.provider) }}
                    />
                  ))}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-2.5 gap-y-0.5 text-[9px] text-white/40">
                  {row.byProvider.map((slice) => (
                    <span key={slice.provider} className="inline-flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: providerAccent(slice.provider) }} aria-hidden="true" />
                      {slice.providerLabel} {slice.count}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </TrustPanel>

      {/* ============ resource table ============ */}
      <TrustPanel index={5}>
        <SectionLabel
          icon={Filter}
          hint="Server-side filtered and paged against the same snapshot the provider cards came from."
          meta={`${fmtNumber(table.total)} matching`}
        >
          Cloud resource inventory
        </SectionLabel>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SearchInput
            value={filters.search}
            onChange={(value) => setFilter('search', value)}
            placeholder="Search resource, service, account, region or key manager"
          />
          <FilterSelect
            label="Cloud"
            value={filters.provider}
            onChange={(value) => setFilter('provider', value)}
            options={[{ value: 'all', label: 'All' }, ...cloud.providers.map((provider) => ({ value: provider.provider, label: `${provider.providerLabel} (${provider.resources})` }))]}
          />
          <FilterSelect
            label="Account"
            value={filters.account}
            onChange={(value) => setFilter('account', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.accounts.map((account) => ({ value: account.id.toLowerCase(), label: account.label }))]}
          />
          <FilterSelect
            label="Region"
            value={filters.region}
            onChange={(value) => setFilter('region', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.regions.map((region) => ({ value: region.toLowerCase(), label: region }))]}
          />
          <FilterSelect
            label="Environment"
            value={filters.environment}
            onChange={(value) => setFilter('environment', value)}
            options={[{ value: 'all', label: 'All' }, ...data.facets.environments.map((env) => ({ value: env.toLowerCase(), label: env }))]}
          />
          <FilterSelect
            label="Encryption"
            value={filters.encryption}
            onChange={(value) => setFilter('encryption', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'encrypted', label: 'Encrypted' },
              { value: 'partially-encrypted', label: 'Partial' },
              { value: 'unencrypted', label: 'Unencrypted' },
              { value: 'not-observed', label: 'Not observed' },
            ]}
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
              { value: 'unknown', label: 'Unknown' },
            ]}
          />
          <FilterSelect
            label="Compliance"
            value={filters.compliance}
            onChange={(value) => setFilter('compliance', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'compliant', label: 'Compliant' },
              { value: 'non-compliant', label: 'Non-compliant' },
              { value: 'exception', label: 'Exception' },
              { value: 'not-assessed', label: 'Not assessed' },
            ]}
          />
          <FilterSelect
            label="Attribution"
            value={filters.attribution}
            onChange={(value) => setFilter('attribution', value)}
            options={[
              { value: 'all', label: 'All' },
              { value: 'attributed', label: 'Provider identified' },
              { value: 'unattributed', label: 'Unattributed' },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={filters.sort}
            onChange={(value) => setFilter('sort', value)}
            options={[
              { value: 'risk', label: 'Highest risk' },
              { value: 'name', label: 'Name' },
              { value: 'region', label: 'Region' },
              { value: 'provider', label: 'Cloud' },
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
          <PanelEmpty>No cloud resource matches the current filters.</PanelEmpty>
        ) : (
          <>
            <TableShell minWidth={1240}>
              <thead>
                <tr>
                  <Th>Resource</Th>
                  <Th>Cloud</Th>
                  <Th>Account</Th>
                  <Th>Region</Th>
                  <Th>Service</Th>
                  <Th>Encryption</Th>
                  <Th>Key management</Th>
                  <Th>TLS</Th>
                  <Th>State</Th>
                  <Th>Compliance</Th>
                  <Th>Last seen</Th>
                </tr>
              </thead>
              <tbody>
                {table.rows.map((resource) => (
                  <tr
                    key={resource.id}
                    onClick={() => void openResource(resource.id)}
                    className="cursor-pointer border-b border-white/5 last:border-0 transition hover:bg-white/[0.04]"
                  >
                    <Td>
                      <span className="block max-w-[210px] truncate text-[11.5px] font-bold text-white/85">{resource.name}</span>
                      <span className="block max-w-[210px] truncate text-[9.5px] text-white/35">{resource.resourceType}</span>
                    </Td>
                    <Td>
                      <ProviderChip provider={resource.provider} label={resource.providerLabel} />
                      {!resource.attribution.attributed ? (
                        <span className="mt-0.5 block text-[9px] text-white/30" title={resource.attribution.reason}>
                          no provider evidence
                        </span>
                      ) : null}
                    </Td>
                    <Td>
                      <span className="block max-w-[140px] truncate font-mono text-[10px] text-white/50">{resource.accountLabel}</span>
                    </Td>
                    <Td>
                      <span className="font-mono text-[10px] text-white/55">{resource.region || '—'}</span>
                    </Td>
                    <Td>
                      <span className="text-[10.5px] text-white/50">{resource.service || '—'}</span>
                    </Td>
                    <Td>
                      <EncryptionBadge state={resource.encryptionState} />
                    </Td>
                    <Td>
                      <span className={cn('text-[10px]', resource.keyManagementKnown ? 'text-white/60' : 'text-white/30')}>
                        {resource.keyManagement}
                      </span>
                    </Td>
                    <Td>
                      <span className="font-mono text-[10px] text-white/45">
                        {resource.tlsVersions.length ? resource.tlsVersions.join(', ') : 'Not observed'}
                      </span>
                    </Td>
                    <Td>
                      <TrustStateBadge state={resource.state} reason={resource.stateReason} size="sm" />
                    </Td>
                    <Td>
                      <span
                        className={cn(
                          'text-[10px] capitalize',
                          resource.complianceState === 'non-compliant'
                            ? 'text-red-300'
                            : resource.complianceState === 'compliant'
                              ? 'text-emerald-300'
                              : 'text-white/35',
                        )}
                        title={resource.complianceDetail}
                      >
                        {resource.complianceState.replace(/-/g, ' ')}
                      </span>
                    </Td>
                    <Td>
                      <span className="font-mono text-[9.5px] text-white/35">{relativeTime(resource.lastSeenAt)}</span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={offset} limit={PAGE_SIZE} total={table.total} onChange={setOffset} />
          </>
        )}
      </TrustPanel>

      {/* ============ events ============ */}
      <TrustPanel index={6}>
        <SectionLabel icon={Activity} hint="Cloud discovery and cryptographic change events from your own records.">
          Cloud cryptographic events
        </SectionLabel>
        <EventStream events={data.events} limit={10} emptyLabel="No cloud cryptographic events in the last 30 days." />
      </TrustPanel>

      <ProvenanceFooter telemetry={data.telemetry} reads={data.reads} />

      <Drawer
        open={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setDetail(null);
        }}
        title={detail?.resource.name || 'Cloud resource'}
        subtitle={detail ? `${detail.resource.providerLabel}${detail.resource.region ? ` · ${detail.resource.region}` : ''}` : undefined}
      >
        {detailLoading && !detail ? (
          <TrustSkeleton rows={5} height={52} />
        ) : !detail ? (
          <PanelEmpty>Resource detail could not be loaded.</PanelEmpty>
        ) : (
          <ResourceDrawerBody detail={detail} />
        )}
      </Drawer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sub-components                                                      */
/* ------------------------------------------------------------------ */

function Metric({ label, value, tone = 'default' }: { label: string; value: string; tone?: 'default' | 'good' | 'warn' | 'bad' | 'muted' }) {
  return (
    <div className="min-w-0">
      <dt className="truncate text-[8.5px] font-black uppercase tracking-wider text-white/30">{label}</dt>
      <dd
        className={cn(
          'truncate font-mono text-[10px] font-bold',
          tone === 'good' && 'text-emerald-300/85',
          tone === 'warn' && 'text-amber-300/85',
          tone === 'bad' && 'text-red-300/85',
          tone === 'muted' && 'text-white/30',
          tone === 'default' && 'text-white/60',
        )}
        title={value}
      >
        {value}
      </dd>
    </div>
  );
}

function ResourceDrawerBody({ detail }: { detail: CloudResourceDetail }) {
  const { resource, certificates, certificateTrust, endpoints, findings, region } = detail;

  return (
    <div className="space-y-4">
      <section>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <ProviderChip provider={resource.provider} label={resource.providerLabel} />
          <TrustStateBadge state={resource.state} size="sm" />
          <EncryptionBadge state={resource.encryptionState} />
        </div>
        <p className="rounded-lg border border-white/10 bg-black/25 p-2.5 text-[11px] leading-relaxed text-white/65">
          {resource.stateReason}
        </p>
        <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
          <Field label="Resource type" value={resource.resourceType} />
          <Field label="Service" value={resource.service || 'Not recorded'} />
          <Field label="Account" value={resource.accountLabel} />
          <Field label="Region" value={resource.region || 'Not recorded'} />
          <Field label="Environment" value={resource.environment || 'Not recorded'} />
          <Field label="Owner" value={resource.owner || 'Unassigned'} />
          <Field label="Key management" value={resource.keyManagement} />
          <Field
            label="Encryption algorithms"
            value={resource.encryptionAlgorithms.length ? resource.encryptionAlgorithms.join(', ') : 'Not observed'}
          />
          <Field label="Compliance" value={`${resource.complianceState.replace(/-/g, ' ')} — ${resource.complianceDetail}`} />
          <Field label="Last telemetry" value={relativeTime(resource.lastTelemetryAt)} />
        </dl>
      </section>

      {/* Attribution honesty trail - section 6. */}
      <section>
        <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Provider attribution</h3>
        <div
          className={cn(
            'rounded-lg border p-2.5',
            resource.attribution.attributed ? 'border-emerald-500/20 bg-emerald-500/[0.05]' : 'border-amber-500/25 bg-amber-500/[0.06]',
          )}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-white/70">
              {resource.attribution.attributed ? 'Attributed' : 'Not attributed'}
            </span>
            <span className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-white/50">
              {resource.attribution.method} · {resource.attribution.confidence}% confidence
            </span>
          </div>
          <p className="mt-1 text-[10.5px] leading-relaxed text-white/50">{resource.attribution.reason}</p>
        </div>
      </section>

      {region ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Region posture — {region.region}</h3>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[10.5px]">
            <Field label="Resources in region" value={fmtNumber(region.resources)} />
            <Field label="Region trust score" value={region.trustScore === null ? 'Not measured' : String(region.trustScore)} />
            <Field label="Encrypted" value={region.measured ? `${region.encrypted} of ${region.encrypted + region.unencrypted}` : 'Not observed'} />
            <Field label="Critical findings" value={fmtNumber(region.criticalFindings)} />
          </dl>
          {region.anomaly ? (
            <p className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.06] p-2 text-[10.5px] leading-relaxed text-amber-100/80">
              {region.anomaly}
            </p>
          ) : null}
        </section>
      ) : null}

      {certificates.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Certificates ({certificates.length})</h3>
          <ul className="space-y-1">
            {certificates.slice(0, 8).map((certificate) => {
              const trust = certificateTrust.find((record) => record.certificateId === certificate.id);
              return (
                <li key={certificate.id}>
                  <Link
                    to={`/dashboard/certificate-telemetry?certificate=${encodeURIComponent(certificate.id)}`}
                    className="block rounded-lg border border-white/8 bg-black/20 p-2 no-underline transition hover:border-cyan-400/30"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="min-w-0 truncate text-[10.5px] font-semibold text-white/75">
                        {certificate.name || certificate.subject}
                      </span>
                      {trust ? <TrustStateBadge state={trust.state} size="sm" /> : null}
                    </div>
                    <span className="mt-0.5 block font-mono text-[9.5px] text-white/40">
                      {certificate.algorithmLabel} ·{' '}
                      {certificate.daysToExpiry === null ? 'no expiry recorded' : `${certificate.daysToExpiry}d remaining`}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {endpoints.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">TLS endpoints ({endpoints.length})</h3>
          <ul className="space-y-1">
            {endpoints.slice(0, 6).map((endpoint) => (
              <li key={endpoint.id} className="rounded-lg border border-white/8 bg-black/20 p-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="min-w-0 truncate font-mono text-[10px] text-white/70">
                    {endpoint.port ? `${endpoint.host}:${endpoint.port}` : endpoint.host}
                  </span>
                  <span className="shrink-0 font-mono text-[9.5px] text-white/45">{endpoint.negotiatedVersion || 'Not observed'}</span>
                </div>
                <span className="mt-0.5 block text-[9.5px] text-white/40">{endpoint.postureReason}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {findings.length > 0 ? (
        <section>
          <h3 className="mb-2 text-[9.5px] font-black uppercase tracking-wider text-white/35">Findings ({findings.length})</h3>
          <ul className="space-y-1">
            {findings.slice(0, 8).map((finding) => (
              <li key={finding.id} className="rounded-lg border border-white/8 bg-black/20 p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10.5px] font-bold text-white/80">{finding.title}</span>
                  <span className="font-mono text-[9px] uppercase text-white/35">{finding.severity}</span>
                </div>
                <p className="mt-0.5 text-[9.5px] leading-snug text-cyan-200/60">
                  <span className="font-black uppercase">Fix:</span> {finding.remediation}
                </p>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <Link
        to={resource.href}
        className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-1.5 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 no-underline transition hover:bg-cyan-500/20"
      >
        Open asset record
      </Link>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[9px] font-black uppercase tracking-wider text-white/30">{label}</dt>
      <dd className="mt-0.5 truncate text-white/70" title={value}>
        {value}
      </dd>
    </div>
  );
}
