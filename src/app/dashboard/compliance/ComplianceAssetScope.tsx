'use client';

import { useEffect, useRef, useState } from 'react';
import { ClipboardCheck, Download, Eye, Filter, RefreshCw } from 'lucide-react';
import {
  ConnectionChip, CoverageBar, GOV_SHELL_CLASS, GOV_SHELL_CSS, GovernanceError,
  GovernanceHeader, GovernanceModuleNav, GovernanceSkeleton, StatusBadge,
} from '../_components/governance/primitives';
import { Pager, PanelEmpty, TableShell, Td, Th } from '../_components/observability/primitives';
import { useAssetComplianceScope, useGovernancePagedResource } from '@/hooks/use-governance';
import type { AssetComplianceScope, ComplianceAssetOption } from '@/lib/governance/asset-scope';
import { CONTROL_STATUS_LABEL, MAX_COMPLIANCE_SELECTION } from '@/lib/governance/types';
import type { AssetReportTemplate } from '@/services/reporting/AssetReport';
import type { DocumentFormat } from '@/services/reporting/exporters/DocumentExporters';

const surface = 'rounded-xl border border-[var(--qg-card-border)] bg-[var(--qg-card-bg-strong)] p-4 shadow-sm sm:p-5';
const field = 'min-h-10 rounded-lg border border-[var(--qg-card-border)] bg-[var(--qg-card-bg-strong)] px-3 text-sm text-[var(--qg-dashboard-text)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--qg-accent)]';
const button = `${field} inline-flex items-center justify-center gap-2 font-semibold disabled:opacity-50`;
const time = (value: string | null) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Unrecorded';
const score = (value: number | null) => value === null ? 'Not assessed' : `${value}%`;

export function ComplianceAssetPicker({
  selected, onApply,
}: {
  selected: ComplianceAssetOption[];
  onApply: (assets: ComplianceAssetOption[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [draft, setDraft] = useState(selected);
  const options = useGovernancePagedResource<ComplianceAssetOption>('compliance', '/asset-options', 'assets', { search, offset, limit: 20 }, 0, open);
  const ids = new Set(draft.map((item) => item.id));
  const select = (asset: ComplianceAssetOption) => setDraft((previous) =>
    previous.some((item) => item.id === asset.id)
      ? previous.filter((item) => item.id !== asset.id)
      : [...previous, asset],
  );

  return (
    <section className={surface} aria-label="Compliance asset scope">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-bold"><Filter size={16} aria-hidden="true" /> Compliance scope</h2>
          <p className="mt-1 text-sm text-[var(--qg-dashboard-text-muted)]">
            {selected.length === 0 ? 'Organization overview' : selected.length === 1 ? selected[0].name : `${selected.length} selected assets`}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={button} aria-expanded={open} aria-controls="compliance-asset-options"
            onClick={() => { setDraft(selected); setSearch(''); setOffset(0); setOpen(!open); }}>
            {open ? 'Close picker' : 'Choose assets'}
          </button>
          {selected.length > 0 && <button type="button" className={button} onClick={() => { onApply([]); setOpen(false); }}>Clear selection</button>}
        </div>
      </div>
      {open && (
        <div id="compliance-asset-options" className="mt-4 space-y-3 border-t border-[var(--qg-card-border)] pt-4">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <label className="grid w-full max-w-md gap-1.5 text-sm font-semibold">
              Search registered assets
              <input className={field} value={search} placeholder="Search by asset name" onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
            </label>
            <span role="status" className="text-sm text-[var(--qg-dashboard-text-muted)]">{draft.length} selected · {options.total} matching</span>
          </div>
          {draft.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {draft.map((asset) => <button key={asset.id} type="button" className={button} onClick={() => select(asset)} aria-label={`Remove ${asset.name}`}>{asset.name} <span aria-hidden="true">×</span></button>)}
            </div>
          )}
          {options.error ? <GovernanceError message={options.error} onRetry={options.retry} />
            : options.loading && !options.rows.length ? <GovernanceSkeleton rows={3} />
            : options.rows.length === 0 ? <PanelEmpty>No registered assets match this search.</PanelEmpty>
            : (
              <>
                <div className="grid max-h-72 gap-1.5 overflow-auto sm:grid-cols-2 lg:grid-cols-3">
                  {options.rows.map((asset) => (
                    <label key={asset.id} className="flex min-w-0 cursor-pointer items-start gap-3 rounded-lg border border-[var(--qg-card-border)] p-3 has-[:checked]:border-[var(--qg-accent)]">
                      <input className="mt-1 h-4 w-4 shrink-0 accent-[var(--qg-accent)]" type="checkbox" checked={ids.has(asset.id)}
                        disabled={!ids.has(asset.id) && draft.length >= MAX_COMPLIANCE_SELECTION} onChange={() => select(asset)} />
                      <span className="min-w-0 break-words text-sm"><strong>{asset.name}</strong><br /><span className="text-[var(--qg-dashboard-text-muted)]">{asset.environment} · {asset.type} · {asset.owner}{asset.lifecycle === 'archived' ? ' · Archived' : ''}</span></span>
                    </label>
                  ))}
                </div>
                <Pager offset={offset} limit={20} total={options.total} onChange={setOffset} />
              </>
            )}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-[var(--qg-dashboard-text-muted)]">Select up to {MAX_COMPLIANCE_SELECTION} registered assets for one assessment and report.</p>
            <button type="button" className={`${button} !border-transparent !bg-[var(--qg-accent)] !text-[var(--qg-on-accent,white)]`}
              disabled={draft.length === 0} onClick={() => { onApply(draft); setOpen(false); }}>Apply asset scope</button>
          </div>
        </div>
      )}
    </section>
  );
}

function ScopeReport({ data, disabled }: { data: AssetComplianceScope; disabled: boolean }) {
  const [template, setTemplate] = useState<AssetReportTemplate>('executive');
  const [format, setFormat] = useState<DocumentFormat>('pdf');
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState('');
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);

  const generate = async (preview: boolean) => {
    if (disabled || pending) return;
    const tab = preview ? window.open('', '_blank') : null;
    if (preview && !tab) { setNotice('Enable pop-ups to preview this report. Downloads remain available.'); return; }
    if (tab) tab.opener = null;
    setPending(true);
    setNotice('');
    try {
      const { buildAssetComplianceDocument } = await import('@/services/reporting/ComplianceDocument');
      const { exportDocument, downloadDocument } = await import('@/services/reporting/exporters/DocumentExporters');
      const result = await exportDocument(buildAssetComplianceDocument(data, template), preview ? 'html' : format);
      if (!active.current) { tab?.close(); return; }
      if (tab) {
        const url = URL.createObjectURL(result.blob);
        tab.location.replace(url);
        window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      } else {
        downloadDocument(result);
      }
      setNotice(preview ? 'Report preview opened.' : 'Report downloaded.');
    } catch (error) {
      tab?.close();
      if (active.current) setNotice(error instanceof Error ? error.message : 'The report could not be generated.');
    } finally {
      if (active.current) setPending(false);
    }
  };

  return (
    <section className={surface} aria-label="Asset compliance report">
      <h2 className="text-base font-bold">Export compliance report</h2>
      <p className="mb-3 mt-1 text-sm text-[var(--qg-dashboard-text-muted)]">Reports use this selection and the assessment captured {time(data.generatedAt)}.</p>
      <div className="flex flex-wrap items-end gap-2.5">
        <label className="grid gap-1 text-sm font-semibold">Template
          <select className={field} value={template} onChange={(event) => setTemplate(event.target.value as AssetReportTemplate)}>
            <option value="executive">Executive brief</option><option value="technical">Technical register</option><option value="remediation">Remediation worklist</option>
          </select>
        </label>
        <label className="grid gap-1 text-sm font-semibold">Format
          <select className={field} value={format} onChange={(event) => setFormat(event.target.value as DocumentFormat)}>
            <option value="pdf">PDF</option><option value="csv">CSV</option><option value="json">JSON</option>
          </select>
        </label>
        <button type="button" className={button} disabled={disabled || pending} onClick={() => void generate(true)}><Eye size={16} aria-hidden="true" /> Preview</button>
        <button type="button" className={button} disabled={disabled || pending} onClick={() => void generate(false)}><Download size={16} aria-hidden="true" /> {pending ? 'Generating…' : 'Download report'}</button>
      </div>
      {notice && <p role="status" className="mt-3 text-sm">{notice}</p>}
    </section>
  );
}

const detailSections = ['Controls', 'Regulatory mappings', 'Findings', 'Remediation', 'Evidence', 'Audit events'] as const;
type DetailSection = typeof detailSections[number];

function ScopeDetails({ data }: { data: AssetComplianceScope }) {
  const [section, setSection] = useState<DetailSection>('Controls');
  const [filter, setFilter] = useState('all');
  const [offset, setOffset] = useState(0);
  const names = new Map(data.assets.map((asset) => [asset.id, asset.name]));
  const assetName = (id: string | null) => id ? names.get(id) ?? id : 'Unrecorded';
  const gapRows = data.controls.filter((row) => filter === 'all' || row.status === filter);
  const sections = {
    Controls: {
      columns: ['Control', 'Status', 'Coverage', 'Evidence basis', 'Action'],
      rows: gapRows.map((row) => ({ id: row.id, fields: [`${row.code} · ${row.title}`, <StatusBadge key="status" status={row.status} size="sm" />,
        `${row.satisfied} of ${row.population} passed`, row.basis, <a key="action" className="underline" href={row.remediationRoute}>Open module</a>] })),
    },
    'Regulatory mappings': {
      columns: ['Framework', 'Requirement', 'Scoped status', 'Controls measured'],
      rows: data.requirements.map((row) => ({ id: row.id, fields: [row.frameworkLabel, `${row.code} · ${row.title}`, CONTROL_STATUS_LABEL[row.status], `${row.controlsMeasured} of ${row.controlIds.length}`] })),
    },
    Findings: {
      columns: ['Asset', 'Finding', 'Severity', 'Recorded status', 'Source'],
      rows: [
        ...data.findings.map((row) => ({ id: row.id, fields: [assetName(row.assetId), row.title, row.severity ?? 'Unrated', row.statusLabel ?? 'Unrecorded', `${row.source.table}/${row.source.recordId}`] })),
        ...data.violations.map((row) => ({ id: row.id, fields: [assetName(row.assetId), row.subject, row.severity, row.observed, `${row.source.table}/${row.source.recordId}`] })),
      ],
    },
    Remediation: {
      columns: ['Asset', 'Job', 'Recorded status', 'Updated'],
      rows: data.remediation.map((row) => ({ id: row.id, fields: [assetName(row.assetId), row.title, row.status ?? 'Unrecorded', time(row.updatedAt)] })),
    },
    Evidence: {
      columns: ['Asset', 'Record', 'Outcome', 'Integrity', 'Last observed', 'Source'],
      rows: data.evidence.map((row) => ({ id: row.id, fields: [assetName(row.assetId), row.title, row.outcome, row.integrity.state, time(row.occurredAt || row.recordedAt), `${row.source.table}/${row.source.recordId}`] })),
    },
    'Audit events': {
      columns: ['Asset', 'Action', 'Outcome', 'Timestamp', 'Source'],
      rows: data.auditEvents.map((row) => ({ id: row.id, fields: [assetName(row.assetId), row.action, row.outcome, time(row.at), `${row.source.table}/${row.source.recordId}`] })),
    },
  };
  const current = sections[section];
  const page = Math.min(offset, Math.max(0, Math.floor((current.rows.length - 1) / 20) * 20));

  return (
    <section className={surface} aria-label="Selected asset assessments and evidence">
      <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Assessment sections">
        {detailSections.map((item) => (
          <button key={item} type="button" className={`${button} aria-pressed:border-[var(--qg-accent)]`} aria-pressed={item === section}
            onClick={() => { setSection(item); setOffset(0); }}>{item}</button>
        ))}
      </div>
      {section === 'Controls' && (
        <label className="mb-3 flex flex-wrap items-center gap-2 text-sm font-semibold">Control status
          <select className={field} value={filter} onChange={(event) => { setFilter(event.target.value); setOffset(0); }}>
            <option value="all">All statuses</option>
            {Object.entries(CONTROL_STATUS_LABEL).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
      )}
      {section === 'Regulatory mappings' && <p className="mb-3 text-sm text-[var(--qg-dashboard-text-muted)]">Mappings show the platform controls measured for this selection. Full framework compliance requires independent assessment.</p>}
      {current.rows.length ? (
        <>
          <TableShell minWidth={660}>
            <thead><tr>{current.columns.map((column) => <Th key={column}>{column}</Th>)}</tr></thead>
            <tbody>{current.rows.slice(page, page + 20).map((row) => <tr key={row.id}>{row.fields.map((entry, index) => <Td key={index}>{entry}</Td>)}</tr>)}</tbody>
          </TableShell>
          <Pager offset={page} limit={20} total={current.rows.length} onChange={setOffset} />
        </>
      ) : <PanelEmpty>No records are available for this selection and filter.</PanelEmpty>}
    </section>
  );
}

export function SelectedAssetCompliance({ assetIds, picker }: { assetIds: string[]; picker: React.ReactNode }) {
  const model = useAssetComplianceScope(assetIds);
  const data = model.data;
  const statuses = data?.controls ?? [];

  return (
    <div className={GOV_SHELL_CLASS}>
      <style>{GOV_SHELL_CSS}</style>
      <GovernanceHeader icon={ClipboardCheck} title="Compliance" accent="Command Center"
        subtitle="Control assessments, risk and evidence for the selected registered assets."
        right={<>
          <ConnectionChip live={model.live} lastSyncedAt={model.lastVerifiedAt} onReconnect={model.reconnect} />
          <button type="button" className={button} disabled={model.refreshing} onClick={() => void model.refresh(true)}><RefreshCw size={16} aria-hidden="true" /> Refresh</button>
        </>} />
      <GovernanceModuleNav />
      {picker}
      {model.error && <GovernanceError message={model.error} onRetry={model.reconnect} />}
      {!data && model.state === 'loading' && <GovernanceSkeleton rows={5} />}
      {data && (
        <>
          {(data.truncated || data.unavailableSources.length > 0) && (
            <section className={surface} role="status">
              <h2 className="font-bold">Evidence coverage is limited</h2>
              {data.truncated && <p className="text-sm">Some sources exceeded the governance read window. Additional evidence may exist.</p>}
              {data.unavailableSources.length > 0 && <p className="break-words text-sm">Unavailable sources · {data.unavailableSources.join(', ')}</p>}
            </section>
          )}
          <section className={surface} aria-label="Selected assets summary">
            <div className="grid gap-4 sm:grid-cols-3">
              <div><span className="text-sm text-[var(--qg-dashboard-text-muted)]">Measured-control compliance</span><p className="mt-1 text-2xl font-bold">{score(data.score)}</p></div>
              <div><span className="text-sm text-[var(--qg-dashboard-text-muted)]">Control coverage</span><p className="mt-1 text-2xl font-bold">{data.measured} / {data.controls.length}</p></div>
              <div><span className="text-sm text-[var(--qg-dashboard-text-muted)]">Latest attributed evidence</span><p className="mt-1 text-base font-bold">{time(data.latestEvidenceAt)}</p></div>
            </div>
            <div className="mt-4">
              <CoverageBar compliant={statuses.filter((row) => row.status === 'compliant').length}
                partial={statuses.filter((row) => row.status === 'partial').length}
                failing={statuses.filter((row) => row.status === 'non-compliant').length}
                unassessed={statuses.filter((row) => row.status === 'not-assessed').length}
                notApplicable={statuses.filter((row) => row.status === 'not-applicable').length} />
            </div>
          </section>
          <section className={surface} aria-label="Asset compliance scores">
            <h2 className="mb-3 text-base font-bold">Selected assets</h2>
            <TableShell minWidth={700}>
              <thead><tr>{['Asset', 'Compliance', 'Controls measured', 'Control gaps', 'Cryptographic posture', 'Risk'].map((label) => <Th key={label}>{label}</Th>)}</tr></thead>
              <tbody>{data.assets.map((asset) => (
                <tr key={asset.id}>
                  <Td><strong>{asset.name}</strong><span className="block text-xs text-[var(--qg-dashboard-text-muted)]">{asset.environment} · {asset.owner} · {asset.lifecycle}</span></Td>
                  <Td>{score(asset.score)}</Td><Td>{asset.measured} / {asset.controls}</Td><Td>{asset.gaps}</Td>
                  <Td>{asset.posture ?? 'Not assessed'}</Td><Td>{asset.riskScore === null ? 'Not assessed' : [asset.riskLevel, asset.riskScore].filter((item) => item !== null).join(' · ')}</Td>
                </tr>
              ))}</tbody>
            </TableShell>
          </section>
          <ScopeReport data={data} disabled={Boolean(model.error)} />
          <ScopeDetails data={data} />
        </>
      )}
    </div>
  );
}
