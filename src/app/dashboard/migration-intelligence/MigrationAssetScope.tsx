import { useEffect, useId, useState } from 'react';
import { ArrowDownRight, ArrowUpRight, Boxes, Clock, Network, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/contexts/auth-context';
import { Panel } from '@/app/dashboard/quantum-readiness/_shared';
import type { MigrationAssetOption, MigrationAssetScope as AssetScope } from '@/lib/migration/intelligence-scope';

const button = 'inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 text-sm font-semibold text-[var(--qg-text-primary)] hover:border-cyan-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:cursor-default disabled:opacity-50';
const card = 'min-w-0 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] p-3';
const muted = 'text-[var(--qg-text-secondary)]';
const pageSize = 20;
const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function label(value: string | null) {
  return value?.replace(/[_-]+/g, ' ') || 'Not recorded';
}

function timestamp(value: string | null) {
  return value ? date.format(new Date(value)) : 'Not recorded';
}

export function MigrationAssetScope({ assetId, asset, onSelect }: {
  assetId: string | null;
  asset: AssetScope | null;
  onSelect: (id: string | null) => void;
}) {
  const { session, user } = useAuth();
  const token = session?.user.id === user?.id ? session?.access_token : undefined;
  const searchId = useId();
  const [expanded, setExpanded] = useState(false);
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ query: string; offset: number; assets: MigrationAssetOption[]; total: number; partial: boolean; error: string | null } | null>(null);

  useEffect(() => {
    if (!expanded || !token) return;
    const controller = new AbortController();
    const delay = window.setTimeout(async () => {
      const params = new URLSearchParams({ q: query.trim(), offset: String(offset) });
      try {
        const response = await fetch('/api/v1/migration-intelligence/assets?' + params, {
          headers: { Authorization: 'Bearer ' + token },
          cache: 'no-store',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(12_000)]),
        });
        const payload = await response.json().catch(() => null);
        if (!response.ok || !Array.isArray(payload?.assets)) throw new Error(payload?.error?.message || 'Asset inventory lookup failed');
        if (!controller.signal.aborted) setResult({ query, offset, assets: payload.assets, total: payload.total, partial: payload.partial, error: null });
      } catch (error) {
        if (!controller.signal.aborted) setResult({ query, offset, assets: [], total: 0, partial: false, error: error instanceof Error ? error.message : 'Asset inventory lookup failed' });
      }
    }, 200);
    return () => { window.clearTimeout(delay); controller.abort(); };
  }, [attempt, expanded, offset, query, token]);

  const current = result?.query === query && result.offset === offset ? result : null;

  return (
    <Panel className="mb-5 p-4 sm:p-5">
      <section aria-label="Migration asset scope" className="text-[var(--qg-text-primary)]">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-cyan-500/30 bg-cyan-500/10 text-[var(--qg-accent)]">
              <Boxes size={20} aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <p className={'text-xs font-semibold ' + muted}>Migration intelligence scope</p>
              <h2 className="break-words text-lg font-bold">{asset?.name ?? (assetId ? 'Selected asset' : 'Entire estate')}</h2>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {assetId && <button type="button" className={button} onClick={() => onSelect(null)}>View entire estate</button>}
            <button type="button" className={button} aria-expanded={expanded} aria-controls={searchId}
              onClick={() => { setExpanded((open) => !open); setResult(null); }}>
              <Search size={16} aria-hidden="true" /> {assetId ? 'Change asset' : 'Select an asset'}
            </button>
          </div>
        </div>

        {expanded && (
          <div id={searchId} className="mt-4 space-y-3 border-t border-[var(--qg-card-border)] pt-4">
            <label className="block max-w-xl text-sm font-semibold">
              Search the scanner inventory
              <input type="search" autoFocus autoComplete="off" maxLength={120} value={query}
                onChange={(event) => { setQuery(event.target.value); setOffset(0); }}
                placeholder="Name, owner, environment, or type"
                className="mt-1.5 block min-h-11 w-full rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg)] px-3 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500" />
            </label>
            {!current ? <p className={'text-sm ' + muted} role="status">Loading assets…</p>
              : current.error ? <div role="status" className="flex flex-wrap items-center gap-3 text-sm"><span>{current.error}</span><button type="button" className={button} onClick={() => { setResult(null); setAttempt((value) => value + 1); }}>Retry</button></div>
              : !current.assets.length ? <p className={'text-sm ' + muted} role="status">No matching assets in the current scanner inventory.</p>
              : (
                <>
                  <p className={'text-xs ' + muted} role="status">
                    {offset + 1}–{offset + current.assets.length} of {current.total.toLocaleString()} matches{current.partial ? ' · Limited inventory coverage' : ''}
                  </p>
                  <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                    {current.assets.map((item) => <li key={item.id}>
                      <button type="button" aria-pressed={assetId === item.id} onClick={() => { setExpanded(false); onSelect(item.id); }}
                        className={button + ' h-full w-full min-w-0 justify-between px-3 py-2 text-left'}>
                        <span className="min-w-0 break-words"><strong className="block">{item.name}</strong><span className={'block text-xs font-normal ' + muted}>{label(item.type)} · {item.environment ?? 'Environment unspecified'} · {item.owner ?? 'Owner unassigned'}</span></span>
                        <ArrowUpRight size={15} aria-hidden="true" className="shrink-0" />
                      </button>
                    </li>)}
                  </ul>
                  {current.total > pageSize && <div className="flex gap-2">
                    <button type="button" className={button} disabled={offset === 0} onClick={() => setOffset((start) => Math.max(0, start - pageSize))}>Previous</button>
                    <button type="button" className={button} disabled={offset + pageSize >= current.total} onClick={() => setOffset((start) => start + pageSize)}>Next</button>
                  </div>}
                </>
              )}
          </div>
        )}
        {asset && <AssetEvidence asset={asset} onSelect={onSelect} />}
      </section>
    </Panel>
  );
}

function AssetEvidence({ asset, onSelect }: { asset: AssetScope; onSelect: (id: string) => void }) {
  const fields = [
    ['Accountable owner', asset.owner ?? 'Unassigned'],
    ['Business service', asset.businessService ?? 'Not recorded'],
    ['Environment', label(asset.environment)],
    ['Asset type', label(asset.type)],
    ['Inventory status', label(asset.inventoryStatus)],
    ['Scanner assessment', asset.scanStatus ?? 'Not recorded'],
    [asset.lastScannedSource === 'evidence' ? 'Latest scanner evidence' : 'Last recorded scan', timestamp(asset.lastScannedAt)],
  ];
  return (
    <div className="mt-4 space-y-4 border-t border-[var(--qg-card-border)] pt-4">
      <dl className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {fields.map(([name, value]) => <div key={name} className={card}>
          <dt className={'text-xs font-semibold ' + muted}>{name}</dt>
          <dd className="mt-1 break-words text-sm font-semibold">{value}</dd>
          {name === 'Accountable owner' && asset.ownerSource && <dd className={'mt-1 text-xs ' + muted}>{asset.ownerSource}</dd>}
        </div>)}
      </dl>
      <div className="grid gap-3 lg:grid-cols-2">
        <section className={card}>
          <h3 className="flex items-center gap-2 text-sm font-bold"><Network size={16} aria-hidden="true" /> Recorded asset relationships</h3>
          {asset.relationships.state === 'no-record' ? <p className={'mt-2 text-sm ' + muted}>This scanner asset has no persistent inventory ID for relationship lookup.</p>
            : asset.relationships.state === 'unavailable' ? <p className={'mt-2 text-sm ' + muted}>Relationship records are temporarily unavailable.</p>
              : !asset.relationships.total && !asset.relationships.rows.length ? <p className={'mt-2 text-sm ' + muted}>No relationships recorded for this asset.</p>
                : <>
                  <p className={'mt-2 text-xs ' + muted}>Showing {asset.relationships.rows.length}{asset.relationships.total === null ? '' : ' of ' + asset.relationships.total} recorded connections with an accessible asset record.</p>
                  <ul className="mt-2 max-h-72 divide-y divide-[var(--qg-card-border)] overflow-auto">
                    {asset.relationships.rows.map((row) => <li key={row.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                      <div className="min-w-0">
                        <p className="break-words text-sm font-semibold">{row.assetName}</p>
                        <p className={'break-words text-xs ' + muted}>{row.direction === 'incoming' ? 'Incoming' : 'Outgoing'} · {label(row.type)}{row.recordedAt && ' · Recorded ' + timestamp(row.recordedAt)}</p>
                      </div>
                      <button type="button" className={button} onClick={() => onSelect(row.assetId)} aria-label={'View migration intelligence for ' + row.assetName}>
                        <ArrowDownRight size={16} aria-hidden="true" /> View asset
                      </button>
                    </li>)}
                  </ul>
                </>}
        </section>
        <section className={card}>
          <h3 className="flex items-center gap-2 text-sm font-bold"><Clock size={16} aria-hidden="true" /> Recorded migration jobs</h3>
          {asset.jobs.state === 'no-record' ? <p className={'mt-2 text-sm ' + muted}>This scanner asset has no persistent inventory ID for job lookup.</p>
            : asset.jobs.state === 'unavailable' ? <p className={'mt-2 text-sm ' + muted}>Migration job records are temporarily unavailable.</p>
              : !asset.jobs.rows.length ? <p className={'mt-2 text-sm ' + muted}>No migration jobs recorded for this asset.</p>
                : <>
                  <p className={'mt-2 text-xs ' + muted}>Showing {asset.jobs.rows.length}{asset.jobs.total === null ? '' : ' of ' + asset.jobs.total} jobs, newest update first.</p>
                  <ul className="mt-2 divide-y divide-[var(--qg-card-border)]">
                    {asset.jobs.rows.map((job) => <li key={job.id} className="py-2">
                      <p className="break-words text-sm font-semibold">{job.name} <span className={'text-xs capitalize ' + muted}>· {label(job.status)}</span></p>
                      <p className={'break-words text-xs ' + muted}>{label(job.type)}{job.target && ' · ' + job.target}</p>
                      <p className={'text-xs ' + muted}>{[
                        job.startedAt && 'Started ' + timestamp(job.startedAt),
                        job.completedAt && 'Completed ' + timestamp(job.completedAt),
                        job.updatedAt && 'Updated ' + timestamp(job.updatedAt),
                      ].filter(Boolean).join(' · ') || 'No job timestamp recorded'}</p>
                    </li>)}
                  </ul>
                </>}
        </section>
      </div>
      <Link className={button} to={'/dashboard/assets?asset=' + encodeURIComponent(asset.id)}>
        Open asset record <ArrowUpRight size={15} aria-hidden="true" />
      </Link>
    </div>
  );
}
