import { useState } from 'react';
import { GitCompareArrows } from 'lucide-react';
import { useLiveModel } from '@/hooks/use-live-resource';
import { useObservedPagedResource, useTelemetryAccount } from '@/hooks/use-observed-paged-resource';
import type { AssetTelemetryComparison, TelemetryAsset } from '@/lib/telemetry/asset-comparison';
import { ErrorState, Pager, Panel, PanelEmpty, TableShell, Td, Th } from './primitives';

const API = '/api/v1/dashboard/tls-telemetry';
const control = 'min-h-10 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg-strong)] px-3 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--qg-accent)]';
const time = (value: string | null) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Unrecorded';

export function TelemetryAssetComparison() {
  const { accountId } = useTelemetryAccount();
  return <AssetPicker key={accountId} />;
}

function AssetPicker() {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<TelemetryAsset[]>([]);
  const [applied, setApplied] = useState<string[]>([]);
  const assets = useObservedPagedResource<TelemetryAsset>(API + '/asset-options', 'assets', { search, offset }, 0, open);
  return (
    <Panel>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold"><GitCompareArrows aria-hidden="true" size={16} /> Inspect or compare assets</h2>
          <p className="mt-1 text-sm text-[var(--qg-text-secondary)]">Compare evidence for up to four registered assets. Dashboard totals cover the full estate.</p>
        </div>
        <div className="flex gap-2">
          <button className={control} type="button" aria-expanded={open} aria-controls="telemetry-asset-picker" onClick={() => setOpen(!open)}>{open ? 'Close picker' : 'Choose assets'}</button>
          {applied.length > 0 && <button className={control} type="button" onClick={() => { setApplied([]); setSelected([]); }}>Clear comparison</button>}
        </div>
      </div>
      {open && (
        <div id="telemetry-asset-picker" className="mt-4 space-y-3 border-t border-[var(--qg-card-border)] pt-3">
          <label className="grid max-w-sm gap-1 text-sm font-medium">Search registered assets
            <input className={control} value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
          </label>
          {assets.error ? <ErrorState message={assets.error} onRetry={assets.retry} />
            : assets.loading && !assets.rows.length ? <p role="status">Loading assets…</p>
            : !assets.rows.length ? <PanelEmpty>No registered assets match this search.</PanelEmpty>
            : <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {assets.rows.map((asset) => {
                const checked = selected.some((row) => row.id === asset.id);
                return <label className="flex min-w-0 items-start gap-2 rounded-lg border border-[var(--qg-card-border)] p-3 text-sm" key={asset.id}>
                  <input className="mt-1 shrink-0" type="checkbox" checked={checked} disabled={!checked && selected.length === 4}
                    onChange={() => setSelected(checked ? selected.filter((row) => row.id !== asset.id) : [...selected, asset])} />
                  <span className="min-w-0 break-words"><strong>{asset.name}</strong><br />{asset.type} · {asset.environment}</span>
                </label>;
              })}
            </div>}
          <Pager offset={offset} limit={20} total={assets.total} onChange={setOffset} />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap gap-1.5" aria-label="Selected assets">
              {selected.map((asset) => <button key={asset.id} type="button" className={control} aria-label={`Remove ${asset.name}`}
                onClick={() => setSelected(selected.filter((row) => row.id !== asset.id))}>{asset.name} ×</button>)}
            </div>
            <button className={control} type="button" disabled={!selected.length} onClick={() => { setApplied(selected.map((asset) => asset.id).sort()); setOpen(false); }}>View selected assets</button>
          </div>
        </div>
      )}
      {applied.length > 0 && <Comparison key={applied.join(',')} ids={applied} />}
    </Panel>
  );
}

const views = ['TLS observations', 'SSH scanner evidence', 'Certificates', 'Data protection', 'Findings', 'Configuration changes'] as const;
type EvidenceView = typeof views[number];

function Comparison({ ids }: { ids: string[] }) {
  const [view, setView] = useState<EvidenceView>('TLS observations');
  const [filter, setFilter] = useState('');
  const query = new URLSearchParams({ assets: ids.join(',') });
  const base = API + '/asset-comparison';
  const live = useLiveModel<AssetTelemetryComparison>({
    url: `${base}?${query}`, streamUrl: `${base}/stream?${query}`, event: 'asset-telemetry', channelPrefix: 'asset-telemetry',
    validate: (payload) => typeof payload.generatedAt === 'string' && Number.isFinite(Date.parse(payload.generatedAt)) &&
      Boolean(payload.tlsSnapshot && payload.encryptionSnapshot) && Array.isArray(payload.incompleteSources) &&
      Array.isArray(payload.assets) && JSON.stringify(payload.assets.map((row) => row?.id).sort()) === JSON.stringify(ids) &&
      payload.assets.every((asset) => asset.counts && ['certificates', 'transport', 'ssh', 'protection', 'findings', 'changes']
        .every((key) => Array.isArray(asset[key]))),
  });
  const data = live.data;
  if (!data) return <div className="mt-3">{live.error ? <ErrorState message={live.error} onRetry={live.reconnect} /> : <p role="status">Loading selected asset evidence…</p>}</div>;

  const rows = data.assets.flatMap((asset) => {
    switch (view) {
      case 'SSH scanner evidence': return asset.ssh.map((row) => ({
        key: row.id, fields: [asset.name, row.algorithm || 'SSH banner', row.algorithm ? `Advertised ${row.kind.toLowerCase()}` : 'Scanner banner',
          `${row.target} · ${row.version ? 'SSH ' + row.version : 'Version unrecorded'}`, time(row.observedAt)],
      }));
      case 'Configuration changes': return asset.changes.map((row) => ({
        key: row.id, fields: [asset.name, row.detail, 'Recorded configuration change', `${row.previous} → ${row.current}`, time(row.detectedAt)],
      }));
      case 'Certificates': return asset.certificates.map((row) => ({
        key: `${asset.id}:${row.id}`, fields: [asset.name, row.subject, `${row.lifecycle} · ${row.issuer || 'Issuer unrecorded'}`,
          `Key ${row.publicKeyAlgorithm || 'unrecorded'} · Signature ${row.signatureAlgorithm || 'unrecorded'} · Expires ${time(row.notAfter)}`, time(row.lastObservedAt)],
      }));
      case 'Data protection': return asset.protection.map((row) => ({
        key: row.id, fields: [asset.name, row.observed, row.evidence.source, `${row.layer} · ${row.strength.strength}`, time(row.observedAt)],
      }));
      case 'Findings': return asset.findings.map((row) => ({
        key: `${row.domain}:${row.id}`, fields: [asset.name, row.title, `${row.domain} · ${row.severity}`, row.observed, time(row.lastObservedAt)],
      }));
      default: return asset.transport.map((row) => ({
        key: row.id, fields: [asset.name, row.observed, row.basis === 'live-traffic' ? 'Runtime observation' : row.basis === 'scanner-probe' ? 'Probe evidence' : 'Inventory record',
          row.kind, time(row.observedAt)],
      }));
    }
  }).filter((row) => row.fields.join(' ').toLowerCase().includes(filter.trim().toLowerCase()));

  return (
    <div className="mt-4 space-y-3">
      {live.error && <ErrorState message={live.error} onRetry={live.reconnect} />}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-[var(--qg-text-secondary)]">
        <span role="status">{live.live ? 'Comparison stream connected' : 'Comparison stream reconnecting'}</span>
        <span>TLS / PKI snapshot {time(data.tlsSnapshot.generatedAt)}</span><span>Encryption snapshot {time(data.encryptionSnapshot.generatedAt)}</span>
        <button type="button" className={control} onClick={() => void live.refresh(true)} disabled={live.refreshing}>Refresh comparison</button>
      </div>
      {data.incompleteSources.length > 0 && <p className="break-words text-sm" role="status">Coverage is incomplete for {data.incompleteSources.map((source) => source.replaceAll('_', ' ')).join(', ')}.</p>}
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {data.assets.map((asset) => <div key={asset.id} className="min-w-0 break-words rounded-lg border border-[var(--qg-card-border)] p-3">
          <h3 className="font-semibold">{asset.name}</h3>
          <p className="text-sm text-[var(--qg-text-secondary)]">{asset.type} · {asset.environment}</p>
          {asset.counts.transport + asset.counts.ssh + asset.counts.certificates + asset.counts.protection === 0
            ? <p className="mt-2 text-sm">No assessment evidence in this window.</p>
            : <p className="mt-2 text-sm">{asset.counts.endpoints} TLS endpoints · {asset.counts.ssh} SSH observations · {asset.counts.certificates} certificates · {asset.counts.protection} data protection observations</p>}
        </div>)}
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <label className="grid gap-1 text-sm font-medium">Evidence view
          <select className={control} value={view} onChange={(event) => { setView(event.target.value as EvidenceView); setFilter(''); }}>
            {views.map((name) => <option key={name}>{name}</option>)}
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium">Filter evidence
          <input className={control} value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Protocol, algorithm, status or finding" />
        </label>
      </div>
      <p className="text-sm text-[var(--qg-text-secondary)]">Up to 25 recent rows per asset and evidence type.</p>
      {rows.length === 0 ? <PanelEmpty>No matching evidence in this view.</PanelEmpty> : (
        <TableShell minWidth={640}>
          <thead><tr>{['Asset', 'Record', 'Evidence / status', 'Details', 'Observed'].map((title) => <Th key={title}>{title}</Th>)}</tr></thead>
          <tbody>{rows.map((row) => <tr key={row.key}>{row.fields.map((field, index) => <Td key={index}>{field}</Td>)}</tr>)}</tbody>
        </TableShell>
      )}
    </div>
  );
}
