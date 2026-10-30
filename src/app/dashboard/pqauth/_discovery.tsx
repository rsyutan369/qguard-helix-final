'use client';

import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import {
  ArrowRight, ChevronDown, ChevronRight, Fingerprint, History, Loader2, Play, Radar, ScanSearch, Server, ShieldAlert,
} from 'lucide-react';
import { AMBER, CYAN, GREEN, RED, SLATE, fmtInt, fullTimestamp, relativeTime } from '../_components/intel/kit';
import type { PQAuthDiscoveryHost, PQAuthHostResult, PQAuthSnapshot } from '@/types/pqauth-dashboard';
import {
  AgeBadge, Badge, Card, ClassBadge, EvidenceUrl, FilterChips, GATE_META, Notice, PROTOCOL_LABEL, Pager, Reveal, RouteLink, SearchBox, td, th, usePaged,
  ink,
} from './_ui';

const RESULT_META: Record<PQAuthHostResult, { label: string; hex: string; glyph: string; hint: string }> = {
  'identity-found': { label: 'Identity found', hex: GREEN, glyph: '✓', hint: 'Identity metadata was read and parsed.' },
  'no-identity': { label: 'No identity metadata', hex: SLATE, glyph: '○', hint: 'Every standard path answered without identity metadata — proof of absence.' },
  incomplete: { label: 'Incomplete', hex: AMBER, glyph: '◐', hint: 'Some probes failed or a document was malformed — absence is not proven.' },
  failed: { label: 'Failed', hex: RED, glyph: '✕', hint: 'No probe reached the host.' },
};

const OUTCOME_HEX = { found: GREEN, 'not-found': SLATE, unparseable: AMBER, error: RED } as const;

export function DiscoveryView({
  snapshot, startDiscovery, starting, startError,
}: {
  snapshot: PQAuthSnapshot;
  startDiscovery: (assetIds?: string[]) => Promise<void>;
  starting: boolean;
  startError: string | null;
}) {
  const { discovery, providers } = snapshot.identity;
  const reduce = useReducedMotion();
  const run = discovery.activeRun;
  const running = run?.status === 'running';
  const eligible = discovery.scope.filter((s) => s.eligible);
  const unsupported = discovery.scope.filter((s) => !s.eligible);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | PQAuthHostResult>('all');
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const hosts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return discovery.hosts.filter((h) => (filter === 'all' || h.result === filter) && (!q || `${h.host} ${h.assetName ?? ''}`.toLowerCase().includes(q)));
  }, [discovery.hosts, filter, query]);
  const paged = usePaged(hosts, 8);
  const counts = (r: PQAuthHostResult) => discovery.hosts.filter((h) => h.result === r).length;

  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });
  const runLabel = selected.size ? `Probe ${selected.size} selected` : `Probe all ${eligible.length} eligible`;

  return (
    <div className="space-y-4">
      {/* ---- Workflow ------------------------------------------------- */}
      <Reveal>
        <Card title="Discovery workflow" icon={Radar} meta={discovery.lastRunAt ? `last run ${relativeTime(discovery.lastRunAt)}` : 'never run'}>
          <ol className="flex flex-col gap-2 lg:flex-row lg:items-stretch">
            {discovery.stages.map((stage, index) => {
              const meta = GATE_META[stage.status];
              return (
                <Fragment key={stage.id}>
                  <li className="flex-1 rounded-xl border bg-white/[0.02] p-3" style={{ borderColor: `${meta.hex}40` }}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-black uppercase tracking-wider text-white/75">{index + 1}. {stage.label}</span>
                      <span className="font-mono text-[15px] font-black" style={{ color: ink(meta.hex) }}>{fmtInt(stage.count)}</span>
                    </div>
                    <div className="mt-1 text-[9px] font-black uppercase tracking-wider" style={{ color: ink(meta.hex) }}>{meta.glyph} {meta.label}</div>
                    <p className="mt-1 text-[10px] leading-snug text-white/45">{stage.description}</p>
                  </li>
                  {index < discovery.stages.length - 1 ? (
                    <li aria-hidden="true" className="hidden items-center text-white/20 lg:flex"><ArrowRight className="h-4 w-4" /></li>
                  ) : null}
                </Fragment>
              );
            })}
          </ol>

          {run ? (
            <div className="mt-4 rounded-xl border border-cyan-400/30 bg-cyan-500/[0.05] p-3.5" role="status" aria-live="polite">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex items-center gap-2 text-[11.5px] font-black text-cyan-200">
                  {running ? <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : null}
                  {running ? `Probing ${run.currentHost ?? 'hosts'}…` : run.status === 'completed' ? 'Discovery run complete' : 'Discovery run failed'}
                </span>
                <span className="font-mono text-[10.5px] text-white/55">
                  {run.hostsDone}/{run.hostsTotal} hosts · {run.providersFound} provider record(s) · started {relativeTime(run.startedAt)}
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/8" role="progressbar" aria-valuemin={0} aria-valuemax={run.hostsTotal} aria-valuenow={run.hostsDone} aria-label="Hosts probed">
                {/* Animates only while the server reports a genuinely running run. */}
                <motion.div
                  className="h-full rounded-full bg-cyan-400"
                  initial={false}
                  animate={{ width: `${run.hostsTotal ? (run.hostsDone / run.hostsTotal) * 100 : 0}%` }}
                  transition={reduce ? { duration: 0 } : { duration: 0.5, ease: 'easeOut' }}
                />
              </div>
              {run.error ? <p className="mt-2 text-[10.5px] text-amber-200">{run.error}</p> : null}
            </div>
          ) : null}
        </Card>
      </Reveal>

      {/* ---- Scope ----------------------------------------------------- */}
      <Reveal delay={0.04} className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Card
          title="Discovery scope"
          icon={Server}
          meta={`${eligible.length} eligible · ${unsupported.length} not probed`}
          action={(
            <button
              type="button"
              disabled={running || starting || !eligible.length}
              onClick={() => void startDiscovery(selected.size ? Array.from(selected) : undefined)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/15 px-3 py-2 text-[9.5px] font-black uppercase tracking-wider text-cyan-200 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70"
            >
              {starting ? <Loader2 className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <Play className="h-3.5 w-3.5" aria-hidden="true" />}
              {running ? 'Run in progress' : runLabel}
            </button>
          )}
        >
          <p className="mb-3 text-[11px] leading-relaxed text-white/50">
            Only hosts from your own asset inventory are probed — preferring each asset&apos;s authorized scan target. Each host receives at most five standard
            metadata requests (OIDC discovery, RFC 8414, three SAML locations) plus one JWKS fetch per provider found. Nothing is crawled.
          </p>
          {startError ? <div className="mb-3"><Notice tone="critical" icon={ShieldAlert} title="Discovery could not start">{startError}</Notice></div> : null}
          {eligible.length ? (
            <ul className="max-h-[300px] space-y-1.5 overflow-y-auto pr-1">
              {eligible.map((asset) => (
                <li key={asset.assetId}>
                  <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 transition hover:border-cyan-400/30">
                    <input type="checkbox" checked={selected.has(asset.assetId)} onChange={() => toggle(asset.assetId)} className="h-3.5 w-3.5 accent-cyan-400" aria-label={`Select ${asset.host}`} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[11.5px] text-white">{asset.host}</span>
                      <span className="block truncate text-[10px] text-white/50">{asset.reason}</span>
                    </span>
                    <span className="shrink-0 text-[9.5px] text-white/50">{asset.lastProbedAt ? `probed ${relativeTime(asset.lastProbedAt)}` : 'never probed'}</span>
                  </label>
                </li>
              ))}
            </ul>
          ) : (
            <Notice tone="warning" icon={ShieldAlert} title="No asset can be probed yet">
              Identity discovery needs a public hostname. Add a web target in the <Link to="/dashboard/scanner" className="text-cyan-200">PQC Scanner</Link>, then return here.
            </Notice>
          )}
        </Card>

        <Card title="Not probed — and why" icon={ShieldAlert} meta={`${unsupported.length} asset(s)`}>
          {unsupported.length ? (
            <ul className="max-h-[340px] space-y-1.5 overflow-y-auto pr-1">
              {unsupported.map((asset) => (
                <li key={asset.assetId} className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[11.5px] text-white/80">{asset.name}</span>
                    <Badge meta={{ label: 'Unsupported', hex: SLATE, glyph: '–', hint: asset.reason }} />
                  </div>
                  <p className="mt-0.5 text-[10px] text-white/50">{asset.reason}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[11px] text-white/50">Every asset in the inventory has a probe-able public hostname.</p>
          )}
        </Card>
      </Reveal>

      {/* ---- Host results ---------------------------------------------- */}
      <Reveal delay={0.08}>
        <Card title="Results by host" icon={ScanSearch} meta="latest run per host">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <SearchBox value={query} onChange={setQuery} placeholder="Search host or asset…" label="Search hosts" />
            <FilterChips
              label="Filter by result"
              value={filter}
              onChange={setFilter}
              options={[
                { key: 'all', label: 'All', count: discovery.hosts.length },
                { key: 'identity-found', label: 'Found', count: counts('identity-found') },
                { key: 'no-identity', label: 'None', count: counts('no-identity') },
                { key: 'incomplete', label: 'Incomplete', count: counts('incomplete') },
                { key: 'failed', label: 'Failed', count: counts('failed') },
              ]}
            />
          </div>
          {paged.total ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px]">
                <thead>
                  <tr className="border-b border-white/10">
                    <th className={th('w-8')}><span className="sr-only">Expand</span></th>
                    <th className={th()}>Host</th>
                    <th className={th()}>Result</th>
                    <th className={th()}>Providers</th>
                    <th className={th('text-right')}>Probed</th>
                  </tr>
                </thead>
                <tbody>
                  {paged.slice.map((host) => (
                    <HostRow key={`${host.assetId ?? host.host}`} host={host} open={expanded === (host.assetId ?? host.host)} onToggle={() => setExpanded((c) => (c === (host.assetId ?? host.host) ? null : host.assetId ?? host.host))} />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] text-white/50">
              {discovery.hosts.length ? 'No host matches the current filter.' : 'No host has been probed yet. Choose hosts in Discovery scope and start a run.'}
            </p>
          )}
          <Pager page={paged.page} pages={paged.pages} total={paged.total} setPage={paged.setPage} />
        </Card>
      </Reveal>

      {/* ---- Providers + history ---------------------------------------- */}
      <Reveal delay={0.12} className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card title="Discovered identity providers" icon={Fingerprint} meta={`${providers.length}`}>
          {providers.length ? (
            <div className="grid gap-3 md:grid-cols-2">
              {providers.map((p) => (
                <article key={p.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="truncate text-[13px] font-black text-white">{p.vendor ?? p.displayName}</h3>
                      <div className="text-[10px] text-white/50">{PROTOCOL_LABEL[p.protocol] ?? p.protocol}{p.vendor ? '' : ' · vendor not identified from issuer host'}</div>
                    </div>
                    <ClassBadge value={p.quantumClass} />
                  </div>
                  <div className="mt-2 truncate font-mono text-[10.5px] text-white/55" title={p.issuer}>{p.issuer}</div>
                  <dl className="mt-2 grid grid-cols-3 gap-2 text-center">
                    <div className="rounded-lg bg-white/[0.03] p-1.5"><dt className="text-[8.5px] font-black uppercase tracking-wider text-white/50">Keys</dt><dd className="font-mono text-[13px] text-white">{p.publishedKeyCount}</dd></div>
                    <div className="rounded-lg bg-white/[0.03] p-1.5"><dt className="text-[8.5px] font-black uppercase tracking-wider text-white/50">Classical</dt><dd className="font-mono text-[13px]" style={{ color: ink(p.vulnerableKeyCount ? RED : GREEN) }}>{p.vulnerableKeyCount}</dd></div>
                    <div className="rounded-lg bg-white/[0.03] p-1.5"><dt className="text-[8.5px] font-black uppercase tracking-wider text-white/50">Endpoints</dt><dd className="font-mono text-[13px] text-white">{p.endpoints.length}</dd></div>
                  </dl>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5"><AgeBadge age={p.age} at={p.lastSeenAt} /></div>
                  <div className="mt-2 text-[10px] text-white/50">Source: <EvidenceUrl url={p.sourceUrl} /></div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <RouteLink to={`/dashboard/pqauth/trust-graph?focus=provider:${p.id}`} tone="ghost">Trust graph</RouteLink>
                    <RouteLink to="/dashboard/pqauth/token-intelligence" tone="ghost">Keys</RouteLink>
                    <RouteLink to="/dashboard/pqauth/compatibility" tone="ghost">Compatibility</RouteLink>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="rounded-lg border border-dashed border-white/12 px-4 py-6 text-center text-[11px] leading-relaxed text-white/50">
              No provider is recorded. A provider appears only when a host serves a parseable OIDC / OAuth 2.0 document with an issuer, or SAML metadata with an entityID.
            </p>
          )}
        </Card>

        <Card title="Run history" icon={History} meta={`${discovery.runs.length} run(s)`}>
          {discovery.runs.length ? (
            <ul className="space-y-2">
              {discovery.runs.map((r) => (
                <li key={r.runId} className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2">
                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="text-white/80" title={fullTimestamp(r.finishedAt)}>{relativeTime(r.finishedAt)}</span>
                    <span className="font-mono text-white/45">{r.hosts} host(s) · {r.probes} probe(s)</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-3 font-mono text-[10px]">
                    <span style={{ color: ink(GREEN) }}>✓ {r.found} found</span>
                    <span style={{ color: ink(SLATE) }}>○ {r.notFound} not found</span>
                    <span style={{ color: ink(AMBER) }}>◐ {r.unparseable} unparseable</span>
                    <span style={{ color: ink(RED) }}>✕ {r.errors} error</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[11px] text-white/50">No discovery run recorded.</p>
          )}
          <p className="mt-3 text-[10px] leading-relaxed text-white/50">
            Discovery records feed the <Link to="/dashboard/pqauth/trust-graph" className="text-cyan-300">Trust Graph</Link>, <Link to="/dashboard/pqauth/token-intelligence" className="text-cyan-300">Token Intelligence</Link>,{' '}
            <Link to="/dashboard/pqauth/compatibility" className="text-cyan-300">Compatibility</Link>, <Link to="/dashboard/pqauth/migration-center" className="text-cyan-300">Migration Center</Link> and the{' '}
            <Link to="/dashboard/pqauth/digital-twin" className="text-cyan-300">Digital Twin</Link>.
          </p>
        </Card>
      </Reveal>
    </div>
  );
}

function HostRow({ host, open, onToggle }: { host: PQAuthDiscoveryHost; open: boolean; onToggle: () => void }) {
  const meta = RESULT_META[host.result];
  return (
    <>
      <tr className="border-b border-white/[0.05]">
        <td className={td()}>
          <button type="button" onClick={onToggle} aria-expanded={open} aria-label={`${open ? 'Hide' : 'Show'} probes for ${host.host}`} className="grid h-6 w-6 place-items-center rounded-md text-white/50 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70">
            {open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />}
          </button>
        </td>
        <td className={td()}>
          <div className="font-mono text-white">{host.host}</div>
          {host.assetName && host.assetName !== host.host ? <div className="text-[10px] text-white/50">asset {host.assetName}</div> : null}
        </td>
        <td className={td()}><Badge meta={meta} /></td>
        <td className={td('font-mono')}>{host.providerIds.length}</td>
        <td className={td('text-right text-white/50')} title={fullTimestamp(host.lastProbedAt)}>{relativeTime(host.lastProbedAt)}</td>
      </tr>
      {open ? (
        <tr className="border-b border-white/[0.05] bg-black/15">
          <td />
          <td colSpan={4} className="px-3 pb-3 pt-1">
            <p className="mb-2 text-[11px] leading-relaxed text-white/60">{host.explanation}</p>
            <ul className="space-y-1">
              {host.probes.map((probe) => (
                <li key={probe.id} className="grid grid-cols-[120px_minmax(0,1fr)_70px_100px] items-start gap-2 text-[10.5px]">
                  <span className="font-black uppercase tracking-wider text-white/45">{probe.method}</span>
                  <span className="min-w-0">
                    <span className="block truncate font-mono text-white/60" title={probe.url}>{probe.url}</span>
                    {probe.detail ? <span className="block text-white/50">{probe.detail}</span> : null}
                  </span>
                  <span className="font-mono text-white/45">{probe.httpStatus ?? 'no resp.'}</span>
                  <span className="font-black uppercase tracking-wider" style={{ color: ink(OUTCOME_HEX[probe.outcome] ?? CYAN) }}>{probe.outcome}</span>
                </li>
              ))}
            </ul>
          </td>
        </tr>
      ) : null}
    </>
  );
}

