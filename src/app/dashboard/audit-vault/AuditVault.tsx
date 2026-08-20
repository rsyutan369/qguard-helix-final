'use client';

/**
 * Audit & Evidence Vault.
 *
 * The repository of record: every governance-relevant event in one normalised,
 * searchable timeline, and every evidence object with its provenance, content
 * digest, retention state and chain of custody.
 *
 * THE INTEGRITY CLAIM IS DELIBERATELY NARROW.
 * Evidence carries a SHA3-256 digest over its canonical content, anchored at
 * first observation. A later read that produces a different digest proves the
 * source record changed after anchoring — genuine tamper-evidence. It does NOT
 * make the underlying row immutable and it is not third-party notarisation, so
 * this page says "tamper-evident", never "immutable", and shows unanchored
 * records as exactly that rather than implying verification.
 */

import { useCallback, useMemo, useState } from 'react';
import {
  Archive,
  Fingerprint,
  History,
  RefreshCw,
  Scale,
  ScrollText,
  ShieldCheck,
  Timer,
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
  AUDIT_CATEGORY_LABEL,
  Basis,
  ConnectionChip,
  CountTile,
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
  IntegrityBadge,
  NoEvidenceState,
  NoMatches,
  Panel,
  PanelEmpty,
  Pill,
  ReconciliationPanel,
  RetentionBadge,
  ScoreSkeleton,
  ScoreTile,
  SeverityBadge,
  StaleBanner,
  StatusBadge,
  TONE,
  fmtNumber,
  relativeTime,
  absoluteTime,
  riseStyle,
  scoreCell,
} from '../_components/governance/primitives';
import { GovernanceDrawers, type DrawerTarget } from '../_components/governance/drawers';
import {
  useAuditVault,
  useGovernanceActions,
  useGovernanceFilters,
  useGovernancePagedResource,
} from '@/hooks/use-governance';
import type { AuditEvent, EvidenceRecord, GovernanceGap } from '@/lib/governance/types';

export default function AuditVault() {
  const { data, state, error, live, lastSyncedAt, revision, refresh, reconnect } = useAuditVault();
  const { anchorEvidence, pending } = useGovernanceActions('audit');
  const { filters, setFilter, reset, activeCount } = useGovernanceFilters({ range: '30d' });
  const [target, setTarget] = useState<DrawerTarget>(null);
  const [tab, setTab] = useState<'timeline' | 'evidence'>('timeline');
  const [eventOffset, setEventOffset] = useState(0);
  const [evidenceOffset, setEvidenceOffset] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  const events = useGovernancePagedResource<AuditEvent>(
    'audit',
    '/audit-events',
    'auditEvents',
    {
      limit: 30,
      offset: eventOffset,
      search: filters.search,
      category: filters.category,
      outcome: filters.outcome,
      severity: filters.severity,
      actorType: filters.actorType,
      range: filters.range,
    },
    revision,
  );

  const evidence = useGovernancePagedResource<EvidenceRecord>(
    'audit',
    '/evidence',
    'evidence',
    {
      limit: 25,
      offset: evidenceOffset,
      search: filters.search,
      kind: filters.kind,
      outcome: filters.outcome,
      integrity: filters.integrity,
      retention: filters.retention,
      freshness: filters.freshness,
      range: filters.range,
    },
    revision,
  );

  const gaps = useGovernancePagedResource<GovernanceGap>('audit', '/gaps', 'gaps', { limit: 6, offset: 0 }, revision);

  const anchorAll = useCallback(async () => {
    const result = await anchorEvidence({ scope: 'unanchored' });
    setNotice(result.message);
    if (result.ok) void refresh(true);
  }, [anchorEvidence, refresh]);

  const categoryOptions = useMemo(
    () => [
      { value: 'all', label: 'All categories' },
      ...(data?.facets.auditCategories ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.auditCategories],
  );
  const kindOptions = useMemo(
    () => [
      { value: 'all', label: 'All evidence kinds' },
      ...(data?.facets.evidenceKinds ?? []).map((entry) => ({ value: entry.id, label: `${entry.label} (${entry.count})` })),
    ],
    [data?.facets.evidenceKinds],
  );

  if (state === 'loading' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Archive} title="Audit" accent="Vault" subtitle="Normalising your audit trail and evidence store…" />
        <ScoreSkeleton count={4} />
        <GovernanceSkeleton rows={5} height={44} />
      </div>
    );
  }

  if (state === 'error' && !data) {
    return (
      <div className={GOV_SHELL_CLASS}>
        <style>{GOV_SHELL_CSS}</style>
        <GovernanceHeader icon={Archive} title="Audit" accent="Vault" subtitle="Audit trail, evidence integrity, retention and custody." />
        <GovernanceError message={error || 'The governance model could not be computed.'} onRetry={reconnect} />
      </div>
    );
  }

  if (!data) return null;

  const { scores, totals, integrity, retention } = data;

  return (
    <div className={GOV_SHELL_CLASS}>
      <style>{GOV_SHELL_CSS}</style>

      <GovernanceHeader
        icon={Archive}
        title="Audit"
        accent="Vault"
        subtitle="Every governance-relevant event and evidence object your tenant holds, with provenance, content digest, retention state and chain of custody."
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
          title="No audit records or evidence yet"
          detail="The vault records what your tenant actually does: scans, migrations, key and certificate lifecycle events, policy changes and attestations. Nothing has been recorded yet."
          actions={[
            { label: 'Run a discovery scan', href: '/dashboard/scanner', primary: true },
            { label: 'Review compliance', href: '/dashboard/compliance' },
          ]}
        />
      ) : null}

      {/* ---- Vault metrics ------------------------------------------- */}
      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
        <ScoreTile score={scores.auditIntegrity} />
        <ScoreTile score={scores.evidenceCoverage} />
        <ScoreTile score={scores.evidenceFreshness} />
        <ScoreTile score={scores.compliance} />
      </section>

      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <CountTile label="Audit events" value={totals.auditEvents} detail="Normalised across every source" tone="neutral" hint="Every audit-relevant record, reduced to one shape and one chronology." />
        <CountTile
          label="Failed / denied"
          value={totals.auditFailures}
          tone={totals.auditFailures > 0 ? 'critical' : 'good'}
          onOpen={() => {
            setFilter('outcome', 'failure');
            setTab('timeline');
            setEventOffset(0);
          }}
          hint="Audit records showing a failed or denied operation. Click to filter the timeline."
        />
        <CountTile label="Evidence records" value={totals.evidence} tone="neutral" hint="Unified evidence objects — the same records Compliance and Regulatory Mapping cite." />
        {/* When the anchor store is unavailable these read as measurements of
            zero — "0 anchored, 0 not anchored" — which is the same fabrication
            the rest of this layer refuses. Render them explicitly unmeasured. */}
        <CountTile
          label="Anchored"
          value={integrity.verified}
          detail={integrity.available ? `${integrity.unanchored} not anchored` : 'Anchor store unavailable'}
          tone={integrity.mismatch > 0 ? 'critical' : integrity.verified > 0 ? 'good' : 'warning'}
          unmeasured={!integrity.available}
          onOpen={() => {
            setFilter('integrity', integrity.available ? 'verified' : 'unavailable');
            setTab('evidence');
            setEvidenceOffset(0);
          }}
          hint="Records whose recomputed digest matches the digest anchored at first observation. Not measurable until the anchor store exists."
        />
        <CountTile
          label="Digest mismatch"
          value={integrity.mismatch}
          detail={integrity.available ? undefined : 'Anchor store unavailable'}
          tone={integrity.mismatch > 0 ? 'critical' : 'good'}
          unmeasured={!integrity.available}
          onOpen={() => {
            setFilter('integrity', integrity.available ? 'mismatch' : 'unavailable');
            setTab('evidence');
            setEvidenceOffset(0);
          }}
          hint="Records that changed after they were anchored. Investigate before relying on them. Not measurable until the anchor store exists."
        />
        <CountTile
          label="Past retention"
          value={retention.expired}
          detail={`${retention.expiring} expiring`}
          tone={retention.expired > 0 ? 'warning' : 'good'}
          onOpen={() => {
            setFilter('retention', 'expired');
            setTab('evidence');
            setEvidenceOffset(0);
          }}
          hint="Evidence past the platform retention window for its class."
        />
      </section>

      {/* ---- Integrity posture --------------------------------------- */}
      <section className="grid gap-3 xl:grid-cols-[1.2fr_1fr]">
        <Panel>
          <SectionLabel
            icon={Fingerprint}
            hint="What the integrity state actually proves, stated exactly as the engine can defend it."
            meta={integrity.available ? undefined : 'anchoring unavailable'}
          >
            Evidence integrity
          </SectionLabel>

          <p
            className={cn(
              'rounded-lg border p-3 text-[11.5px] leading-relaxed',
              integrity.mismatch > 0
                ? 'border-red-400/30 bg-red-500/[0.07] text-red-100/90'
                : integrity.verified > 0
                  ? 'border-emerald-400/25 bg-emerald-500/[0.06] text-emerald-100/90'
                  : 'border-amber-400/25 bg-amber-500/[0.06] text-amber-100/90',
            )}
          >
            {integrity.claim}
          </p>

          <div className="mt-3 flex h-3 overflow-hidden rounded-full border border-white/10 bg-white/5">
            {([
              ['verified', integrity.verified, TONE.good.hex],
              ['mismatch', integrity.mismatch, TONE.critical.hex],
              ['unanchored', integrity.unanchored, TONE.warning.hex],
              ['unavailable', integrity.unavailable, TONE.neutral.hex],
            ] as const)
              .filter(([, count]) => count > 0)
              .map(([label, count, hex]) => (
                <span
                  key={label}
                  title={`${label}: ${count}`}
                  style={{ width: `${(count / Math.max(1, integrity.total)) * 100}%`, backgroundColor: hex }}
                />
              ))}
          </div>

          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
            {[
              { label: 'Verified', value: integrity.verified, tone: 'good' as const },
              { label: 'Mismatch', value: integrity.mismatch, tone: 'critical' as const },
              { label: 'Not anchored', value: integrity.unanchored, tone: 'warning' as const },
              { label: 'Unavailable', value: integrity.unavailable, tone: 'neutral' as const },
            ].map((entry) => (
              <div key={entry.label}>
                <dt className="text-[9px] font-black uppercase tracking-wider text-white/35">{entry.label}</dt>
                <dd className={cn('mt-0.5 font-mono text-[14px] font-black tabular-nums', TONE[entry.tone].text)}>{fmtNumber(entry.value)}</dd>
              </div>
            ))}
          </dl>

          {integrity.available ? (
            <button
              type="button"
              onClick={anchorAll}
              disabled={Boolean(pending) || integrity.unanchored === 0}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/35 bg-cyan-500/12 px-3 py-1.5 text-[10.5px] font-black uppercase tracking-wider text-cyan-100 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-35"
            >
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
              {pending ? 'Anchoring…' : `Anchor ${fmtNumber(integrity.unanchored)} unanchored record${integrity.unanchored === 1 ? '' : 's'}`}
            </button>
          ) : (
            <p className="mt-3 rounded-lg border border-amber-400/25 bg-amber-500/[0.06] p-2.5 text-[10.5px] leading-relaxed text-amber-100/85">
              Anchoring is unavailable in this environment. Apply <span className="font-mono">supabase/governance-schema.sql</span>{' '}
              to enable tamper-evident anchoring — until then this page reports integrity as unestablished rather than
              claiming verification it cannot perform.
            </p>
          )}

          <Basis>
            Digests are SHA3-256 over the canonical (sorted-key) content of each evidence record, recomputed on every read.
            Tamper-evident — not immutable, and not third-party notarised: the anchor lives in the same database.
          </Basis>
        </Panel>

        <div className="space-y-3">
          <Panel>
            <SectionLabel icon={Timer} hint="Platform retention windows per evidence class, and where each record sits inside its window.">
              Retention
            </SectionLabel>
            <div className="space-y-2">
              {([
                ['Retained', retention.active, 'good'] as const,
                ['Expiring within 90 days', retention.expiring, 'warning'] as const,
                ['Past retention', retention.expired, 'critical'] as const,
                ['No window applies', retention.unspecified, 'neutral'] as const,
              ]).map(([label, count, tone]) => (
                <div key={label} className="flex items-center gap-2">
                  <span className="w-44 shrink-0 text-[10.5px] font-semibold text-white/55">{label}</span>
                  <span className="h-2 flex-1 overflow-hidden rounded-full bg-white/8">
                    <span
                      className="block h-full rounded-full"
                      style={{ width: `${(count / Math.max(1, retention.total)) * 100}%`, backgroundColor: TONE[tone].hex }}
                    />
                  </span>
                  <span className="w-10 shrink-0 text-right font-mono text-[10.5px] tabular-nums text-white/65">{fmtNumber(count)}</span>
                </div>
              ))}
            </div>
            <Basis>
              Windows describe the platform’s retention intent per evidence class (attestations and audit records 7 years,
              findings 3 years, scans 2 years, runtime 90 days). They are not a claim that rows are deleted on schedule.
            </Basis>
          </Panel>

          <Panel>
            <SectionLabel icon={ScrollText} hint="Which collector produced the evidence in the vault. Custody starts at the collector, not at the dashboard.">
              Custody by collector
            </SectionLabel>
            {data.custodyRollup.length ? (
              <div className="space-y-1.5">
                {data.custodyRollup.slice(0, 8).map((entry) => (
                  <div key={entry.collector} className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 truncate text-[10.5px] font-semibold text-white/60" title={entry.collector}>
                      {entry.collector}
                    </span>
                    <span className="h-1.5 w-24 overflow-hidden rounded-full bg-white/8">
                      <span
                        className="block h-full rounded-full bg-cyan-400/70"
                        style={{ width: `${(entry.count / Math.max(1, data.custodyRollup[0].count)) * 100}%` }}
                      />
                    </span>
                    <span className="w-12 shrink-0 text-right font-mono text-[10.5px] tabular-nums text-white/65">{fmtNumber(entry.count)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <PanelEmpty>No evidence recorded yet.</PanelEmpty>
            )}
          </Panel>
        </div>
      </section>

      {/* ---- Activity trend ------------------------------------------- */}
      <Panel>
        <SectionLabel icon={History} hint="Audit and evidence activity per day over the last 30 days. Days before your first observation are hatched rather than drawn as zero.">
          Vault activity
        </SectionLabel>
        <ActivityTrend
          points={data.trend}
          series={[
            { key: 'audit', label: 'Audit events', tone: 'info', value: (point) => point.auditEvents },
            { key: 'evidence', label: 'Evidence recorded', tone: 'neutral', value: (point) => point.evidence },
          ]}
        />
      </Panel>

      {/* ---- Filters -------------------------------------------------- */}
      <FilterBar activeCount={activeCount} onReset={() => { reset(); setEventOffset(0); setEvidenceOffset(0); }}>
        <SearchInput
          value={filters.search}
          onChange={(value) => { setFilter('search', value); setEventOffset(0); setEvidenceOffset(0); }}
          placeholder="Search events, evidence, actors, sources…"
        />
        <FilterSelect
          label="Range"
          value={filters.range}
          onChange={(value) => { setFilter('range', value); setEventOffset(0); setEvidenceOffset(0); }}
          options={[
            { value: 'all', label: 'All time' },
            { value: '24h', label: 'Last 24 hours' },
            { value: '7d', label: 'Last 7 days' },
            { value: '30d', label: 'Last 30 days' },
            { value: '90d', label: 'Last 90 days' },
            { value: '1y', label: 'Last year' },
          ]}
        />
        {tab === 'timeline' ? (
          <>
            <FilterSelect label="Category" value={filters.category} onChange={(value) => { setFilter('category', value); setEventOffset(0); }} options={categoryOptions} />
            <FilterSelect
              label="Outcome"
              value={filters.outcome}
              onChange={(value) => { setFilter('outcome', value); setEventOffset(0); }}
              options={[
                { value: 'all', label: 'Any outcome' },
                { value: 'success', label: 'Success' },
                { value: 'failure', label: 'Failure' },
                { value: 'denied', label: 'Denied' },
                { value: 'informational', label: 'Informational' },
              ]}
            />
            <FilterSelect
              label="Actor"
              value={filters.actorType}
              onChange={(value) => { setFilter('actorType', value); setEventOffset(0); }}
              options={[
                { value: 'all', label: 'Any actor' },
                { value: 'user', label: 'User' },
                { value: 'agent', label: 'Collector agent' },
                { value: 'connector', label: 'Connector' },
                { value: 'platform', label: 'Platform' },
              ]}
            />
          </>
        ) : (
          <>
            <FilterSelect label="Kind" value={filters.kind} onChange={(value) => { setFilter('kind', value); setEvidenceOffset(0); }} options={kindOptions} />
            <FilterSelect
              label="Integrity"
              value={filters.integrity}
              onChange={(value) => { setFilter('integrity', value); setEvidenceOffset(0); }}
              options={[
                { value: 'all', label: 'Any integrity state' },
                { value: 'verified', label: 'Verified' },
                { value: 'mismatch', label: 'Digest mismatch' },
                { value: 'unanchored', label: 'Not anchored' },
                { value: 'unavailable', label: 'Unavailable' },
              ]}
            />
            <FilterSelect
              label="Retention"
              value={filters.retention}
              onChange={(value) => { setFilter('retention', value); setEvidenceOffset(0); }}
              options={[
                { value: 'all', label: 'Any retention state' },
                { value: 'active', label: 'Retained' },
                { value: 'expiring', label: 'Expiring' },
                { value: 'expired', label: 'Past retention' },
                { value: 'unspecified', label: 'No window' },
              ]}
            />
          </>
        )}
        <FilterSelect
          label="Severity"
          value={filters.severity}
          onChange={(value) => { setFilter('severity', value); setEventOffset(0); }}
          options={[
            { value: 'all', label: 'Any severity' },
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
      </FilterBar>

      {/* ---- Timeline / evidence tabs ---------------------------------- */}
      <Panel>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex gap-1.5">
            {([
              ['timeline', 'Audit timeline', totals.auditEvents] as const,
              ['evidence', 'Evidence store', totals.evidence] as const,
            ]).map(([key, label, count]) => (
              <button
                key={key}
                type="button"
                onClick={() => setTab(key)}
                className={cn(
                  'rounded-lg border px-3 py-1.5 text-[10px] font-black uppercase tracking-wider transition',
                  tab === key
                    ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200'
                    : 'border-white/12 bg-white/[0.03] text-white/55 hover:bg-white/[0.08]',
                )}
              >
                {label} <span className="font-mono opacity-60">{fmtNumber(count)}</span>
              </button>
            ))}
          </div>
          <span className="font-mono text-[10px] text-white/30">
            {tab === 'timeline' ? `${fmtNumber(events.total)} matching` : `${fmtNumber(evidence.total)} matching`}
          </span>
        </div>

        {tab === 'timeline' ? (
          events.loading && !events.rows.length ? (
            <GovernanceSkeleton rows={6} height={38} />
          ) : events.rows.length ? (
            <>
              <TableShell minWidth={1020}>
                <thead>
                  <tr>
                    <Th>When</Th>
                    <Th>Action</Th>
                    <Th>Category</Th>
                    <Th>Actor</Th>
                    <Th>Subject</Th>
                    <Th>Outcome</Th>
                    <Th align="right">Severity</Th>
                    <Th>Source</Th>
                  </tr>
                </thead>
                <tbody>
                  {events.rows.map((event) => (
                    <tr key={event.id} onClick={() => setTarget({ kind: 'audit', id: event.id })} className="cursor-pointer transition hover:bg-white/[0.03]">
                      <Td>
                        <div className="font-mono text-[10.5px] tabular-nums text-white/70">{relativeTime(event.at)}</div>
                        <div className="font-mono text-[9px] text-white/25">{event.at ? absoluteTime(event.at) : 'undated'}</div>
                      </Td>
                      <Td className="font-semibold text-white/85">{event.action}</Td>
                      <Td className="text-white/50">{AUDIT_CATEGORY_LABEL[event.category]}</Td>
                      <Td>
                        <div className="text-white/65">{event.actor}</div>
                        <div className="font-mono text-[9px] text-white/25">{event.actorType}</div>
                      </Td>
                      <Td className="text-white/60">
                        <span className="block max-w-[220px] truncate" title={event.subject}>
                          {event.subject}
                        </span>
                      </Td>
                      <Td>
                        <Pill tone={event.outcome === 'failure' || event.outcome === 'denied' ? 'critical' : event.outcome === 'success' ? 'good' : 'neutral'}>
                          {event.outcome}
                        </Pill>
                      </Td>
                      <Td align="right">
                        <SeverityBadge severity={event.severity} />
                      </Td>
                      <Td className="font-mono text-[9.5px] text-white/35">{event.source.table}</Td>
                    </tr>
                  ))}
                </tbody>
              </TableShell>
              <Pager offset={eventOffset} limit={30} total={events.total} onChange={setEventOffset} />
            </>
          ) : activeCount > 0 ? (
            <NoMatches onClear={reset} />
          ) : (
            <PanelEmpty>No audit records in this window.</PanelEmpty>
          )
        ) : evidence.loading && !evidence.rows.length ? (
          <GovernanceSkeleton rows={6} height={38} />
        ) : evidence.rows.length ? (
          <>
            <TableShell minWidth={1060}>
              <thead>
                <tr>
                  <Th>Evidence</Th>
                  <Th>Kind</Th>
                  <Th>Asset</Th>
                  <Th>Outcome</Th>
                  <Th>Integrity</Th>
                  <Th>Retention</Th>
                  <Th>Freshness</Th>
                  <Th>Recorded</Th>
                </tr>
              </thead>
              <tbody>
                {evidence.rows.map((record) => (
                  <tr key={record.id} onClick={() => setTarget({ kind: 'evidence', id: record.id })} className="cursor-pointer transition hover:bg-white/[0.03]">
                    <Td>
                      <div className="font-semibold text-white/85">{record.title}</div>
                      <div className="font-mono text-[9.5px] text-white/30">
                        {record.source.table} · {record.source.collector}
                      </div>
                    </Td>
                    <Td className="capitalize text-white/55">{record.kind}</Td>
                    <Td className={record.assetName ? 'text-white/60' : 'text-white/25'}>{record.assetName || '—'}</Td>
                    <Td>
                      <Pill tone={record.outcome === 'contradicting' ? 'critical' : record.outcome === 'supporting' ? 'good' : 'neutral'}>
                        {record.outcome === 'contradicting' ? 'Contradicts' : record.outcome === 'supporting' ? 'Supports' : 'Info'}
                      </Pill>
                    </Td>
                    <Td>
                      <IntegrityBadge state={record.integrity.state} assurance={record.integrity.assurance} />
                    </Td>
                    <Td>
                      <RetentionBadge state={record.retention.state} expiresAt={record.retention.expiresAt} periodDays={record.retention.periodDays} />
                    </Td>
                    <Td>
                      <FreshnessChip state={record.freshness} ageDays={record.ageDays} />
                    </Td>
                    <Td className="font-mono text-[10px] text-white/45">{relativeTime(record.occurredAt)}</Td>
                  </tr>
                ))}
              </tbody>
            </TableShell>
            <Pager offset={evidenceOffset} limit={25} total={evidence.total} onChange={setEvidenceOffset} />
          </>
        ) : activeCount > 0 ? (
          <NoMatches onClear={reset} />
        ) : (
          <PanelEmpty>No evidence records in this window.</PanelEmpty>
        )}

        <Basis>
          Both tabs are served from the one governance model, filtered and paged on the server — so the counts above match
          the rows below and neither ships more than a page to the browser.
        </Basis>
      </Panel>

      {/* ---- Audit controls -------------------------------------------- */}
      <Panel>
        <SectionLabel icon={ShieldCheck} meta={`${data.controls.length} controls`} hint="The audit and evidence controls: logging, failure review, integrity anchoring, retention, freshness and attestation.">
          Audit controls
        </SectionLabel>
        {data.controls.length ? (
          <TableShell minWidth={860}>
            <thead>
              <tr>
                <Th>Control</Th>
                <Th align="right">Score</Th>
                <Th>Status</Th>
                <Th align="right">Failing / scope</Th>
                <Th>Evidence</Th>
                <Th>Basis</Th>
              </tr>
            </thead>
            <tbody>
              {data.controls.map((control) => (
                <tr key={control.id} onClick={() => setTarget({ kind: 'control', id: control.id })} className="cursor-pointer transition hover:bg-white/[0.03]">
                  <Td>
                    <div className="font-mono text-[9.5px] text-cyan-300/70">{control.code}</div>
                    <div className="font-semibold text-white/85">{control.title}</div>
                  </Td>
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
                  <Td>
                    <FreshnessChip state={control.evidenceFreshness} ageDays={control.evidenceAgeDays} />
                  </Td>
                  <Td className="max-w-[320px] text-[10px] text-white/40">{control.basis}</Td>
                </tr>
              ))}
            </tbody>
          </TableShell>
        ) : (
          <PanelEmpty>No audit controls in scope.</PanelEmpty>
        )}
      </Panel>

      {/* ---- Vault gaps ------------------------------------------------ */}
      {gaps.rows.length ? (
        <Panel>
          <SectionLabel icon={Archive} meta={`${fmtNumber(gaps.total)} gaps`} hint="Evidence and audit gaps: unanchored records, stale evidence, expired retention and unreviewed failures.">
            Evidence gaps
          </SectionLabel>
          <div className="grid gap-2.5 lg:grid-cols-2">
            {gaps.rows.map((gap, index) => (
              <GapCard key={gap.id} gap={gap} index={index} onOpen={gap.controlIds.length ? () => setTarget({ kind: 'control', id: gap.controlIds[0] }) : undefined} />
            ))}
          </div>
        </Panel>
      ) : null}

      <GovernanceProvenance telemetry={data.telemetry} />

      <GovernanceDrawers
        view="audit"
        target={target}
        onTarget={setTarget}
        revision={revision}
        reconciliation={<ReconciliationPanel report={data.reconciliation} />}
      />
    </div>
  );
}
