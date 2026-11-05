'use client';

/**
 * Key Lifecycle — the control plane.
 *
 * Discovered → Active → In Use → Rotation Due → Rotated → Retired →
 * Decommissioned, plus the terminal and exception states. The state shown here
 * is the SAME state Rotation, Risk Analysis and every export render, because it
 * is computed once in `lib/qkms/lifecycle.ts` and only projected here.
 *
 * The `Unknown` and `Discovered` states are first-class and deliberately
 * visible: a key with no lifecycle metadata is the estate's least governed key,
 * and hiding it inside "Active" is how missing governance came to look healthy.
 */

import { useCallback, useState } from 'react';
import { CalendarClock, Fingerprint, GitBranch, History, Hourglass, Users } from 'lucide-react';
import { useKeyLifecycle, useKeyQuery, useQkmsActions } from '@/hooks/use-qkms';
import type { LifecycleState } from '@/lib/qkms/types';
import { KeyDrawer } from './KeyDrawer';
import {
  BarRow,
  ExportMenu,
  KeyTable,
  Kpi,
  Notice,
  Pager,
  Panel,
  PanelEmpty,
  QkmsShell,
  SectionLabel,
  TONE,
  fmtNumber,
  useNotice,
  useQkmsExport,
  type KeyColumn,
} from './shell';

const COLUMNS: KeyColumn[] = [
  'key', 'algorithm', 'owner', 'asset', 'environment', 'version',
  'lifecycle', 'rotation', 'created', 'lastUsed', 'lastRotated', 'expiry', 'risk',
];

const ATTENTION_PANELS: Array<{
  id: 'expired' | 'expiringSoon' | 'overdueRotation' | 'neverRotated' | 'longLived' | 'orphaned';
  label: string;
  detail: string;
  tone: 'critical' | 'warning' | 'neutral';
  filter: Record<string, string>;
}> = [
  { id: 'expired', label: 'Expired', detail: 'Past their expiry date and not yet retired', tone: 'critical', filter: { lifecycle: 'expired' } },
  { id: 'expiringSoon', label: 'Expiring within 45 days', detail: 'Inside the replacement window', tone: 'warning', filter: { expiring: '45' } },
  { id: 'overdueRotation', label: 'Rotation overdue or failed', detail: 'Past the rotation interval, or a failed work order', tone: 'critical', filter: { rotation: 'overdue' } },
  { id: 'neverRotated', label: 'Never rotated', detail: 'No rotation has ever been recorded', tone: 'warning', filter: { rotation: 'never-rotated' } },
  { id: 'longLived', label: 'Long-lived (over 2 years)', detail: 'Age exceeds the long-lived threshold', tone: 'warning', filter: {} },
  { id: 'orphaned', label: 'No accountable owner', detail: 'Blocks rotation and migration approval', tone: 'warning', filter: { owner: 'Unassigned' } },
];

export default function QkmsLifecycle() {
  const { data, state, error, live, verifiedAt, refresh, reconnect } = useKeyLifecycle();
  const { notice, show, dismiss } = useNotice();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const query = useKeyQuery({ limit: 25, sort: 'expiry', dir: 'asc' }, data?.generatedAt ?? null);
  const actions = useQkmsActions(() => { void refresh(true); query.reload(); });
  const exporter = useQkmsExport(actions.fetchExportModel);

  const onExport = useCallback(
    async (format: Parameters<typeof exporter.run>[0]) => {
      const result = await exporter.run(format);
      show(result.ok, result.message);
    },
    [exporter, show],
  );

  const metrics = data?.metrics;
  const activeState = query.query.lifecycle || '';

  const selectState = useCallback(
    (lifecycle: LifecycleState) => {
      query.update({ lifecycle: activeState === lifecycle ? '' : lifecycle, rotation: '', expiring: '', owner: '' });
    },
    [query, activeState],
  );

  return (
    <QkmsShell
      icon={GitBranch}
      title="Key"
      accent="Lifecycle"
      subtitle="Creation through decommission for every key: age, usage, rotation obligation, expiry and the keys that have fallen outside lifecycle governance entirely."
      live={live}
      state={state}
      error={error}
      hasData={data?.hasData ?? false}
      generatedAt={data?.generatedAt ?? null}
      verifiedAt={verifiedAt}
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
          <Kpi label="Active" value={fmtNumber(metrics.activeKeys)} detail={`${fmtNumber(metrics.inUseKeys)} with observed runtime usage`} tone="good" />
          <Kpi
            label="Expiry pressure"
            value={fmtNumber(metrics.expiringSoonKeys)}
            detail={`${fmtNumber(metrics.expiredKeys)} already expired`}
            tone={metrics.expiredKeys > 0 ? 'critical' : metrics.expiringSoonKeys > 0 ? 'warning' : 'good'}
          />
          <Kpi
            label="Rotation obligation"
            value={fmtNumber(metrics.rotationOverdueKeys + metrics.rotationDueKeys)}
            detail={`${fmtNumber(metrics.rotationOverdueKeys)} overdue · ${fmtNumber(metrics.neverRotatedKeys)} never rotated`}
            tone={metrics.rotationOverdueKeys > 0 ? 'critical' : 'warning'}
          />
          <Kpi
            label="Outside governance"
            value={fmtNumber((data?.counts.discovered ?? 0) + (data?.counts.unknown ?? 0))}
            detail="Discovered with no lifecycle metadata — classify and assign to bring under control"
            tone={(data?.counts.discovered ?? 0) > 0 ? 'warning' : 'good'}
            hint="These keys were found by scan or telemetry but carry no creation, rotation or expiry evidence. They are not counted as healthy."
          />
        </div>
      ) : null}

      {/* ---- Lifecycle funnel ---------------------------------------- */}
      <Panel>
        <SectionLabel
          icon={History}
          meta={activeState ? <button type="button" onClick={() => query.update({ lifecycle: '' })} className="text-cyan-300 hover:text-cyan-200">Clear</button> : undefined}
          hint="One state machine, computed once. The state here is the state Rotation, Risk Analysis and the exports all show for the same key."
        >
          Lifecycle state
        </SectionLabel>
        {data?.funnel.length ? (
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {data.funnel.map((row) => {
              const tone = row.state === 'expired' || row.state === 'rotation-overdue' ? 'critical'
                : row.state === 'rotation-due' || row.state === 'suspended' ? 'warning'
                  : row.state === 'active' || row.state === 'in-use' || row.state === 'rotated' ? 'good' : 'neutral';
              const selected = activeState === row.state;
              return (
                <button
                  key={row.state}
                  type="button"
                  onClick={() => selectState(row.state)}
                  className={`rounded-lg border p-2.5 text-left transition hover:brightness-125 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 ${selected ? 'border-cyan-400/50 bg-cyan-500/15' : `${TONE[tone].border} ${TONE[tone].soft}`}`}
                >
                  <div className="text-[9px] font-black uppercase tracking-wider text-white/45">{row.label}</div>
                  <div className={`mt-1 text-xl font-black tabular-nums ${TONE[tone].text}`}>{fmtNumber(row.count)}</div>
                  <div className="mt-0.5 text-[10px] text-white/35">{row.percent}% of estate</div>
                </button>
              );
            })}
          </div>
        ) : <PanelEmpty>No lifecycle state has been established for any key.</PanelEmpty>}
      </Panel>

      {/* ---- Age & expiry -------------------------------------------- */}
      <div className="grid gap-3 xl:grid-cols-3">
        <Panel>
          <SectionLabel icon={Hourglass} hint="Age is measured from the earliest creation evidence across every source that described the key.">
            Key age
          </SectionLabel>
          {data?.ageBuckets.length ? (
            <div className="space-y-0.5">
              {data.ageBuckets.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={/Over 2 years/.test(row.label) ? 'critical' : /1–2 years/.test(row.label) ? 'warning' : /unknown/i.test(row.label) ? 'neutral' : 'good'}
                />
              ))}
            </div>
          ) : <PanelEmpty>No creation dates have been observed.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={CalendarClock}>Expiry horizon</SectionLabel>
          {data?.expiryBuckets.length ? (
            <div className="space-y-0.5">
              {data.expiryBuckets.map((row) => (
                <BarRow
                  key={row.label}
                  label={row.label}
                  count={row.count}
                  percent={row.percent}
                  tone={/Expired/.test(row.label) ? 'critical' : /7 days|30 days/.test(row.label) ? 'warning' : /No expiry/.test(row.label) ? 'neutral' : 'good'}
                  onClick={/Within/.test(row.label) ? () => query.update({ expiring: row.label.replace(/\D/g, '') }) : undefined}
                />
              ))}
            </div>
          ) : <PanelEmpty>No expiry dates have been observed.</PanelEmpty>}
        </Panel>

        <Panel>
          <SectionLabel icon={Fingerprint}>Key type portfolio</SectionLabel>
          {data?.keyTypes.length ? (
            <div className="space-y-0.5">
              {data.keyTypes.map((row) => (
                <BarRow key={row.label} label={row.label} count={row.count} percent={row.percent} onClick={() => query.update({ type: row.label })} />
              ))}
            </div>
          ) : <PanelEmpty>No key types have been classified.</PanelEmpty>}
        </Panel>
      </div>

      {/* ---- Attention ----------------------------------------------- */}
      <Panel>
        <SectionLabel icon={Users} hint="Each figure is a key count. Selecting one filters the register below to exactly those keys.">
          Lifecycle exceptions
        </SectionLabel>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {ATTENTION_PANELS.map((panel) => {
            const count = data?.attentionCounts[panel.id] ?? 0;
            return (
              <button
                key={panel.id}
                type="button"
                onClick={() => Object.keys(panel.filter).length && query.update(panel.filter)}
                disabled={!Object.keys(panel.filter).length || count === 0}
                className={`rounded-lg border p-3 text-left transition disabled:cursor-default ${count > 0 ? `${TONE[panel.tone].border} ${TONE[panel.tone].soft} hover:brightness-125` : 'border-white/10 bg-black/25'}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-black uppercase tracking-wider text-white/50">{panel.label}</span>
                  <span className={`font-mono text-lg font-black tabular-nums ${count > 0 ? TONE[panel.tone].text : 'text-white/25'}`}>
                    {fmtNumber(count)}
                  </span>
                </div>
                <p className="mt-1 text-[10.5px] leading-snug text-white/40">{panel.detail}</p>
              </button>
            );
          })}
        </div>
      </Panel>

      {/* ---- Register ------------------------------------------------ */}
      <Panel>
        <SectionLabel
          icon={GitBranch}
          meta={<span>{fmtNumber(query.page?.keys.length ?? 0)} shown · {fmtNumber(query.page?.total ?? 0)} match</span>}
        >
          Keys by lifecycle
        </SectionLabel>
        {query.error ? (
          <div className="mb-3 rounded-lg border border-red-500/25 bg-red-500/10 p-2.5 text-[11px] text-red-200">{query.error}</div>
        ) : null}
        <div className={query.loading ? 'opacity-60 transition-opacity' : 'transition-opacity'}>
          <KeyTable
            keys={query.page?.keys ?? []}
            columns={COLUMNS}
            onSelect={setSelectedKey}
            selectedId={selectedKey}
            sort={query.query.sort}
            dir={query.query.dir}
            onSort={(sortKey) => query.update({ sort: sortKey, dir: query.query.sort === sortKey && query.query.dir === 'desc' ? 'asc' : 'desc' })}
            minWidth={1500}
            emptyMessage="No key matches this lifecycle filter."
          />
        </div>
        <Pager offset={query.query.offset ?? 0} limit={query.query.limit ?? 25} total={query.page?.total ?? 0} onChange={query.setOffset} />
      </Panel>

      <KeyDrawer keyId={selectedKey} syncTo={data?.generatedAt ?? null} onClose={() => setSelectedKey(null)} onChanged={() => { void refresh(true); query.reload(); }} />
    </QkmsShell>
  );
}
