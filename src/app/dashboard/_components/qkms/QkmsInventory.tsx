'use client';

/**
 * Key Inventory — the authoritative register of the key estate.
 *
 * Search, filtering, sorting and pagination all run SERVER-SIDE against the
 * cached tenant model. The browser never holds the whole estate: a 40 000-key
 * inventory renders in the same time as a 40-key one, and the predecessor's
 * silent `slice(0, 260)` — which truncated the register without telling anyone
 * — is gone.
 */

import { useCallback, useMemo, useState } from 'react';
import { Boxes, Download, KeyRound, RefreshCw, SlidersHorizontal } from 'lucide-react';
import { useKeyInventory, useKeyQuery, useQkmsActions, type KeyQuery } from '@/hooks/use-qkms';
import { KeyDrawer } from './KeyDrawer';
import {
  ActionButton,
  BarRow,
  ExportMenu,
  FilterSelect,
  KeyTable,
  Kpi,
  Notice,
  Pager,
  Panel,
  PanelEmpty,
  QkmsShell,
  SearchInput,
  SectionLabel,
  fmtNumber,
  useNotice,
  useQkmsExport,
  type KeyColumn,
} from './shell';

const COLUMNS: KeyColumn[] = [
  'key', 'type', 'algorithm', 'version', 'owner', 'asset', 'environment',
  'custody', 'posture', 'requirement', 'lifecycle', 'rotation',
  'created', 'lastRotated', 'expiry', 'violations', 'risk',
];

/** Facet → filter-field mapping, so the bar is one declaration. */
const FILTERS: Array<{ field: keyof KeyQuery; label: string; facet: keyof NonNullable<ReturnType<typeof useKeyInventory>['data']>['facets'] }> = [
  { field: 'type', label: 'Type', facet: 'types' },
  { field: 'algorithm', label: 'Algorithm', facet: 'algorithms' },
  { field: 'owner', label: 'Owner', facet: 'owners' },
  { field: 'asset', label: 'Asset', facet: 'assets' },
  { field: 'environment', label: 'Env', facet: 'environments' },
  { field: 'backend', label: 'Backend', facet: 'backends' },
  { field: 'posture', label: 'Posture', facet: 'postures' },
  { field: 'lifecycle', label: 'Lifecycle', facet: 'lifecycles' },
  { field: 'rotation', label: 'Rotation', facet: 'rotations' },
  { field: 'risk', label: 'Risk', facet: 'riskLevels' },
  { field: 'requirement', label: 'Migration', facet: 'requirements' },
];

const EXPIRY_OPTIONS = [
  { value: '', label: 'Any expiry' },
  { value: '7', label: 'Within 7 days' },
  { value: '30', label: 'Within 30 days' },
  { value: '45', label: 'Within 45 days' },
  { value: '90', label: 'Within 90 days' },
  { value: '365', label: 'Within 1 year' },
];

export default function QkmsInventory() {
  const { data, state, error, live, refresh, reconnect } = useKeyInventory();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const query = useKeyQuery({ limit: 25, sort: 'risk', dir: 'desc' });
  const actions = useQkmsActions(() => {
    void refresh(true);
    query.reload();
  });
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const facets = data?.facets ?? null;
  const rows = query.page?.keys ?? data?.keys ?? [];
  const total = query.page?.total ?? data?.total ?? 0;

  const onSort = useCallback(
    (sortKey: string) => {
      query.update({
        sort: sortKey,
        dir: query.query.sort === sortKey && query.query.dir === 'desc' ? 'asc' : 'desc',
      });
    },
    [query],
  );

  const activeFilters = useMemo(
    () => FILTERS.filter((filter) => Boolean(query.query[filter.field])).length + (query.query.expiring ? 1 : 0) + (query.query.q ? 1 : 0),
    [query.query],
  );

  const metrics = data?.metrics;

  return (
    <QkmsShell
      icon={KeyRound}
      title="Key"
      accent="Inventory"
      subtitle="Every cryptographic key discovered across your registry, generated keys, certificates, crypto inventory and agent scans — deduplicated to one identity per key."
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
          <Kpi label="Total keys" value={fmtNumber(metrics.totalKeys)} detail="Distinct key identities" tone="neutral" />
          <Kpi
            label="Requiring migration"
            value={fmtNumber(metrics.keysRequiringMigration)}
            detail={`${fmtNumber(metrics.quantumVulnerableKeys)} quantum-vulnerable · ${fmtNumber(metrics.deprecatedKeys)} deprecated`}
            tone={metrics.keysRequiringMigration > 0 ? 'warning' : 'good'}
          />
          <Kpi
            label="Unmanaged custody"
            value={fmtNumber(metrics.unmanagedCustodyKeys)}
            detail="Not in an HSM, KMS or vault, or custody unknown"
            tone={metrics.unmanagedCustodyKeys > 0 ? 'critical' : 'good'}
          />
          <Kpi
            label="Ownership gaps"
            value={fmtNumber(metrics.orphanedKeys)}
            detail="Assign an owner to unblock rotation and migration"
            tone={metrics.orphanedKeys > 0 ? 'warning' : 'good'}
          />
        </div>
      ) : null}

      {/* ---- Register ------------------------------------------------ */}
      <Panel>
        <SectionLabel
          icon={SlidersHorizontal}
          meta={
            <span>
              {fmtNumber(rows.length)} shown · {fmtNumber(total)} match
              {activeFilters > 0 ? ` · ${activeFilters} filter(s)` : ''}
            </span>
          }
          hint="Filtering, sorting and paging run on the server against the cached tenant model, so the browser only ever loads the page you are looking at."
        >
          Key register
        </SectionLabel>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SearchInput
            value={query.query.q || ''}
            onChange={(value) => query.update({ q: value })}
            placeholder="Search key, alias, algorithm, owner, asset or fingerprint"
          />
          {activeFilters > 0 ? (
            <button
              type="button"
              onClick={() => query.update({
                q: '', type: '', algorithm: '', owner: '', asset: '', environment: '',
                backend: '', posture: '', lifecycle: '', rotation: '', risk: '', requirement: '', expiring: '',
              })}
              className="rounded-md border border-white/12 bg-white/[0.04] px-2.5 py-1.5 text-[10px] font-black uppercase tracking-wider text-white/60 transition hover:bg-white/[0.08]"
            >
              Clear filters
            </button>
          ) : null}
        </div>

        <div className="mb-3 flex flex-wrap gap-2">
          {facets
            ? FILTERS.map((filter) => {
              const options = facets[filter.facet] || [];
              if (!options.length) return null;
              return (
                <FilterSelect
                  key={String(filter.field)}
                  label={filter.label}
                  value={String(query.query[filter.field] ?? '')}
                  onChange={(value) => query.update({ [filter.field]: value } as Partial<KeyQuery>)}
                  options={[
                    { value: '', label: `All (${fmtNumber(options.reduce((sum, option) => sum + option.count, 0))})` },
                    ...options.map((option) => ({ value: option.value, label: `${option.value} (${option.count})` })),
                  ]}
                />
              );
            })
            : null}
          <FilterSelect
            label="Expiry"
            value={String(query.query.expiring ?? '')}
            onChange={(value) => query.update({ expiring: value })}
            options={EXPIRY_OPTIONS}
          />
          <FilterSelect
            label="Rows"
            value={String(query.query.limit ?? 25)}
            onChange={(value) => query.update({ limit: Number(value) || 25 })}
            options={[10, 25, 50, 100, 200].map((size) => ({ value: String(size), label: String(size) }))}
          />
        </div>

        {query.error ? (
          <div className="mb-3 rounded-lg border border-red-500/25 bg-red-500/10 p-2.5 text-[11px] text-red-200">{query.error}</div>
        ) : null}

        <div className={query.loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
          <KeyTable
            keys={rows}
            columns={COLUMNS}
            onSelect={setSelectedKey}
            selectedId={selectedKey}
            sort={query.query.sort}
            dir={query.query.dir}
            onSort={onSort}
            minWidth={1900}
            emptyMessage={
              activeFilters > 0
                ? 'No key matches these filters. Clear one to widen the search.'
                : 'No cryptographic keys have been discovered for this tenant.'
            }
            actions={(key) => (
              <ActionButton
                label="Rotate"
                icon={RefreshCw}
                tone="info"
                busy={actions.pending === `rotate:${key.id}`}
                onClick={async () => {
                  const result = await actions.requestRotation(key.id);
                  show(result.ok, result.message);
                }}
              />
            )}
          />
        </div>

        <Pager
          offset={query.query.offset ?? 0}
          limit={query.query.limit ?? 25}
          total={total}
          onChange={query.setOffset}
        />
      </Panel>

      {/* ---- Portfolio ----------------------------------------------- */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel>
          <SectionLabel icon={Boxes}>Key types</SectionLabel>
          {data?.distributions.keyClasses.length ? (
            <div className="space-y-0.5">
              {data.distributions.keyClasses.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  onClick={() => query.update({ type: row.label })}
                  title={`Filter the register to ${row.label}`}
                />
              ))}
            </div>
          ) : <PanelEmpty>No key types have been classified.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={Download}>Owners</SectionLabel>
          {data?.distributions.owners.length ? (
            <div className="space-y-0.5">
              {data.distributions.owners.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={row.label === 'Unassigned' ? 'warning' : 'neutral'}
                  onClick={() => query.update({ owner: row.label })}
                  title={`Filter the register to ${row.label}`}
                />
              ))}
            </div>
          ) : <PanelEmpty>No ownership has been recorded.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={Boxes}>Environments</SectionLabel>
          {data?.distributions.environments.length ? (
            <div className="space-y-0.5">
              {data.distributions.environments.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={row.label === 'production' ? 'info' : row.label === 'unknown' ? 'warning' : 'neutral'}
                  onClick={() => query.update({ environment: row.label })}
                  title={`Filter the register to ${row.label}`}
                />
              ))}
            </div>
          ) : <PanelEmpty>No environment has been attributed to any key.</PanelEmpty>}
        </Panel>
      </div>

      <KeyDrawer
        keyId={selectedKey}
        onClose={() => setSelectedKey(null)}
        onChanged={() => { void refresh(true); query.reload(); }}
      />
    </QkmsShell>
  );
}
