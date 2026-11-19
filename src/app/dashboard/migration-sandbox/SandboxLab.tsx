import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, ArrowRight, BookOpen, FileDown, FlaskConical, History, Search, ShieldCheck } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { useLiveResource } from '@/hooks/use-live-resource';
import { useMigrationAssets, type AssetDossier } from '@/hooks/use-migration-assets';
import { LAB_BASELINE, LAB_LEVELS, LAB_PRIMITIVES, LAB_TLS_GROUPS, labReadiness, tlsCertificateFor, type LabCapabilities, type LabConfiguration, type LabRun } from '@/lib/migration/sandbox-lab';
import './sandbox-lab.css';

const URL = '/api/v1/sandbox/lab';
const EMPTY = { runs: [] as LabRun[], total: 0 };
const TABLES = ['sandbox_lab_runs'];
const INITIAL: LabConfiguration = { primitives: [], tlsGroups: [], testDetected: false, compareTlsBaseline: false, analysis: true };
const STEPS = ['Select asset', 'Define sandbox', 'Choose migration', 'Configure checks', 'Execute', 'Analyze results', 'Assess readiness', 'Report and plan'];
const isLive = (run: LabRun) => ['queued', 'running', 'cancelling'].includes(run.status);
const timestamp = (value?: string | null) => value ? new Date(value).toLocaleString() : '—';
const display = (text: string) => text.replaceAll('_', ' ');

async function request<T>(token: string, url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (HTTP ${response.status}).`);
  if (!body) throw new Error('The API returned an unreadable response.');
  return (body.data ?? body) as T;
}

function useLabCapabilities(token: string | undefined) {
  const [value, setValue] = useState<(LabCapabilities & { executor: boolean; storage: 'available' | 'unavailable' }) | null>(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    setError('');
    void request<LabCapabilities & { executor: boolean; storage: 'available' | 'unavailable' }>(token, `${URL}/capabilities`, { signal: controller.signal })
      .then(setValue).catch((err) => { if (!controller.signal.aborted) { setValue(null); setError(err.message); } });
    return () => controller.abort();
  }, [token, revision]);
  return { value, error, refresh: () => setRevision((value) => value + 1) };
}

function recommendedProfile(asset: AssetDossier, capabilities: LabCapabilities | null) {
  const available = (algorithm: typeof LAB_PRIMITIVES[number]) => Boolean(capabilities?.primitives[algorithm]);
  const candidates = asset.algorithms.filter((row) => row.classification === 'vulnerable');
  const targets = candidates.map((row) => row.target).join(' ').toUpperCase();
  const tls = asset.tlsConfiguration.protocols.some((protocol) => /tls|ssl/i.test(protocol));
  const primitives = LAB_PRIMITIVES.filter((algorithm) => {
    if (!available(algorithm)) return false;
    if (algorithm === 'ML-KEM-768') return /ML-KEM|X25519MLKEM/.test(targets);
    if (algorithm === 'ML-DSA-65') return targets.includes('ML-DSA');
    return targets.includes(algorithm) && algorithm !== 'SLH-DSA-SHA2-128f';
  }).slice(0, 4);
  const config: LabConfiguration = {
    primitives, tlsGroups: [],
    testDetected: Boolean(capabilities?.worker && candidates.length),
    compareTlsBaseline: Boolean(tls && capabilities?.worker),
    analysis: true,
  };
  if (tls && capabilities?.tlsCertificates.X25519MLKEM768[tlsCertificateFor(config)]) config.tlsGroups = ['X25519MLKEM768'];
  return config;
}

function AssetEvidence({ asset, live }: { asset: LabRun['asset_snapshot']; live?: boolean }) {
  return (
    <div className="sbl-observed">
      <div className="sbl-heading"><div><h3>{asset.name}</h3><p>{asset.type} · {asset.environment} · {asset.owner}</p></div><span className="sbl-tag">{asset.migrationStatus}</span></div>
      <p className="sbl-muted break-all">{asset.hostname} · {asset.id}</p>
      <dl className="sbl-data">
        <div><dt>Quantum posture</dt><dd>{asset.hasEvidence ? asset.postureLabel : 'Assessment needed'}</dd></div>
        <div><dt>Risk and long-term exposure</dt><dd>{asset.hasEvidence ? `${asset.riskLevel} risk · ${asset.hndlLevel} HNDL` : 'Evidence needed'}</dd></div>
        <div><dt>Discovery and assessment</dt><dd>{timestamp(asset.discoveredAt)} · {timestamp(asset.lastEvidenceAt)}</dd></div>
        <div><dt>Observed protocols</dt><dd>{asset.tlsConfiguration.protocols.join(', ') || 'Unavailable'}{asset.tlsConfiguration.keyExchange.length ? ` · ${asset.tlsConfiguration.keyExchange.join(', ')}` : ''}</dd></div>
      </dl>
      <details className="sbl-details" open={live && !asset.hasEvidence ? true : undefined}><summary>Algorithms, certificates, and findings</summary>
        {asset.algorithms.length ? <ul>{asset.algorithms.map((row) => <li key={`${row.algorithm}:${row.category}`}><strong>{row.algorithm}</strong> · {row.category.replaceAll('-', ' ')} · {row.keySizes.length ? `${row.keySizes.join('/')} bit` : 'key size unrecorded'} · {row.classification}{row.protocols.length ? ` · ${row.protocols.join(', ')}` : ''}</li>)}</ul> : <p>Algorithm evidence is unavailable.</p>}
        {asset.certificates.length > 0 && <ul>{asset.certificates.map((certificate) => <li key={certificate.id}>{certificate.name} · {certificate.algorithm} {certificate.keySize || ''} · {certificate.issuer} · expires {timestamp(certificate.notAfter)}</li>)}</ul>}
        {asset.findings.length > 0 && <ul>{asset.findings.map((finding) => <li key={finding.id}><strong>{finding.title} · {finding.severity}</strong> — {finding.description}</li>)}</ul>}
        {asset.recommendations.length > 0 && <ul>{asset.recommendations.map((rec) => <li key={rec.id}>{rec.title} · {rec.detail}</li>)}</ul>}
      </details>
    </div>
  );
}

function EvidenceResults({ run }: { run: LabRun }) {
  return (
    <div className="sbl-evidence">
      {Object.entries(LAB_LEVELS).map(([key, level]) => {
        const results = run.results.filter((entry) => entry.level === key);
        return <section className="sbl-card" key={key}>
          <h3>{level.label}</h3><p className="sbl-muted">{level.scope}</p>
          {results.length ? results.map((entry, index) => (
            <details className="sbl-details sbl-check" key={`${entry.profile}-${entry.operation}-${index}`}>
              <summary><span>{entry.profile === LAB_BASELINE ? 'Baseline' : entry.profile} · {entry.operation}</span><span data-status={entry.status} className="sbl-tag">{display(entry.status)}</span></summary>
              <p>{entry.detail}</p>
              {entry.provider && <p className="sbl-muted">{entry.provider} · {timestamp(entry.observedAt)}</p>}
              {Boolean(entry.measures?.length) && <dl className="sbl-measurements">
                {entry.measures?.map(({ name, value, unit }) => <div key={name}><dt>{name}</dt><dd>{value.toLocaleString(undefined, { maximumFractionDigits: 3 })} {unit}</dd></div>)}
              </dl>}
              {entry.issues?.map((issue, index) => <div className="sbl-issue" key={index}>
                <strong>{issue.component} · {issue.severity} · {issue.blocks ? 'Blocks this assessment' : 'Follow-up'}</strong>
                <p>{issue.explanation}</p><p><b>Impact</b> {issue.impact}</p><p><b>Next action</b> {issue.remediation}</p>
              </div>)}
            </details>
          )) : <p className="sbl-empty">{isLive(run) ? 'Waiting for recorded evidence.' : 'No checks recorded at this level.'}</p>}
        </section>;
      })}
    </div>
  );
}

function CompareRuns({ runs }: { runs: LabRun[] }) {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const done = runs.filter((run) => run.status === 'finished');
  const selected = done.find((run) => run.id === left);
  const other = done.find((run) => run.id === right && run.asset_id === selected?.asset_id);
  if (done.length < 2) return null;
  const options = (runs: LabRun[]) => runs.map((run) => <option key={run.id} value={run.id}>{run.asset_snapshot.name} · {timestamp(run.created_at)}</option>);
  return (
    <section className="sbl-card">
      <h2>Compare configurations</h2><p className="sbl-muted">Select two finished sessions for the same asset. Compare individual measurements on the same provider and operation.</p>
      <div className="sbl-columns">
        <label>First session<select value={left} onChange={(event) => { setLeft(event.target.value); setRight(''); }}><option value="">Choose a session</option>{options(done)}</select></label>
        <label>Second session<select value={right} onChange={(event) => setRight(event.target.value)} disabled={!selected}><option value="">Choose a session for this asset</option>{options(done.filter((run) => run.id !== left && run.asset_id === selected?.asset_id))}</select></label>
      </div>
      {selected && other && <div className="sbl-columns"><EvidenceResults run={selected} /><EvidenceResults run={other} /></div>}
    </section>
  );
}

function TlsComparison({ run }: { run: LabRun }) {
  const handshakes = run.results.filter((entry) => entry.level === 'emulation' && entry.status === 'passed');
  if (!handshakes.some((entry) => entry.profile === LAB_BASELINE) || handshakes.length < 2) return null;
  return <div className="sbl-observed">
    <h3>Measured TLS comparison</h3>
    <p className="sbl-muted">Each column is a single in-memory handshake on the lab provider. Version, group, and synthetic certificate may differ between columns.</p>
    <div className="sbl-columns">{handshakes.map((entry) => (
      <div key={entry.profile}>
        <h3>{entry.profile}</h3>
        <dl className="sbl-measurements">{entry.measures?.filter(({ name }) => /handshake|certificate/.test(name.toLowerCase())).map(({ name, value, unit }) => (
          <div key={name}><dt>{name}</dt><dd>{value.toLocaleString()} {unit}</dd></div>
        ))}</dl>
      </div>
    ))}</div>
  </div>;
}

export function SandboxLab() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [params, setParams] = useSearchParams();
  const runId = params.get('runId');
  const selectedAsset = params.get('asset');
  const sourcePlan = params.get('planId');
  const view = params.get('view') === 'history' ? 'history' : runId ? 'results' : 'setup';
  const capabilities = useLabCapabilities(token);
  const stream = useLiveResource({
    url: `${URL}/runs`, streamUrl: `${URL}/stream${runId ? `?runId=${encodeURIComponent(runId)}` : ''}`,
    event: 'sandbox-lab', empty: EMPTY, realtimeTables: TABLES, channelPrefix: 'sandbox-lab',
  });
  const assetWindow = stream.lastReceivedAt && new Date(Math.floor(Date.parse(stream.lastReceivedAt) / 30_000) * 30_000).toISOString();
  const assets = useMigrationAssets(assetWindow);
  const selectAsset = assets.selectAsset;
  const [configuration, setConfiguration] = useState(INITIAL);
  const [localRun, setLocalRun] = useState<LabRun | null>(null);
  const [runError, setRunError] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [plans, setPlans] = useState<Array<{ id: string; name: string; status: string }>>([]);
  const [planId, setPlanId] = useState('');
  const [plansError, setPlansError] = useState('');
  const [plansOpen, setPlansOpen] = useState(false);
  const fromStream = stream.data.runs.find((item) => item.id === runId);
  const backup = localRun?.id === runId ? localRun : null;
  const run = fromStream && backup ? (fromStream.updated_at >= backup.updated_at ? fromStream : backup) : fromStream || backup;
  const dossier = assets.dossier?.id === selectedAsset ? assets.dossier : null;
  const active = stream.data.runs.some(isLive) || Boolean(run && isLive(run));

  useEffect(() => { selectAsset(selectedAsset); }, [selectAsset, selectedAsset]);
  useEffect(() => {
    if (!token || !runId || fromStream) return;
    const controller = new AbortController();
    setRunError('');
    request<LabRun>(token, `${URL}/runs/${encodeURIComponent(runId)}`, { signal: controller.signal })
      .then(setLocalRun).catch((err) => { if (!controller.signal.aborted) setRunError(err.message); });
    return () => controller.abort();
  }, [token, runId, fromStream]);
  const reportAssetId = run?.asset_id;
  useEffect(() => {
    if (!token || !reportAssetId || !plansOpen) return;
    const controller = new AbortController();
    setPlansError('');
    request<typeof plans>(token, `/api/v1/migration-planner/plans?assetId=${encodeURIComponent(reportAssetId)}`, { signal: controller.signal })
      .then(setPlans).catch((err) => { if (!controller.signal.aborted) setPlansError(err.message); });
    return () => controller.abort();
  }, [token, reportAssetId, plansOpen]);

  function change(patch: Record<string, string | null>) {
    setParams((current) => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(patch)) value ? next.set(key, value) : next.delete(key);
      return next;
    });
  }

  async function action(label: string, task: () => Promise<void>) {
    setBusy(label); setError('');
    try { await task(); }
    catch (err) { setError((err as Error).message); }
    finally { setBusy(''); }
  }

  async function begin(input: LabConfiguration, assetId = selectedAsset, planned = sourcePlan) {
    if (!token || !assetId) return;
    await action('start', async () => {
      const result = await request<LabRun>(token, `${URL}/runs`, { method: 'POST', body: JSON.stringify({ assetId, sourcePlanId: planned || undefined, configuration: input }) });
      setLocalRun(result);
      change({ runId: result.id, asset: assetId, view: null });
      void stream.refresh();
    });
  }

  const current = view === 'setup' ? (dossier?.hasEvidence ? 2 : 0)
    : run && isLive(run) ? run.status === 'queued' ? 1 : 4 : view === 'results' ? 6 : 7;
  const portfolioReady = assets.portfolio.generatedAt;
  const summary = useMemo(() => {
    const runs = stream.data.runs;
    const tested = new Set(runs.filter((record) => isLive(record)).map((record) => record.asset_id).filter(Boolean));
    const validated = new Set(runs.filter((record) => record.status === 'finished' && record.results.some((r) => r.level !== 'analysis' && r.profile !== LAB_BASELINE && r.status === 'passed')).map((record) => record.asset_id).filter(Boolean));
    const issues = new Set(runs.filter((record) => record.results.some((r) => r.level !== 'analysis' && ['failed', 'unsupported'].includes(r.status))).map((record) => record.asset_id).filter(Boolean));
    const investigation = new Set(runs.filter((record) => record.status === 'finished' && labReadiness(record).label !== 'Ready for migration planning').map((record) => record.asset_id).filter(Boolean));
    return [
      ['Saved environments', stream.data.total], ['Active sessions', runs.filter(isLive).length],
      ['Finished sessions', runs.filter((record) => record.status === 'finished').length],
      ['Executor failures', runs.filter((record) => record.status === 'failed').length],
      ['Assets being evaluated', tested.size], ['Assets with a passing lab check', validated.size],
      ['Assets with failed or unsupported checks', issues.size], ['Assets requiring follow-up', investigation.size],
    ] as const;
  }, [stream.data]);

  const hasTests = configuration.analysis || configuration.testDetected || configuration.compareTlsBaseline || configuration.primitives.length > 0 || configuration.tlsGroups.length > 0;
  const tlsCertificate = tlsCertificateFor(configuration);
  const unsupportedTls = configuration.tlsGroups.some((group) => !capabilities.value?.tlsCertificates[group][tlsCertificate]);
  const measured = run?.results.some((record) => record.level !== 'analysis' && record.profile !== LAB_BASELINE && record.status === 'passed');
  const readiness = run ? labReadiness(run) : null;
  const plannerUrl = run?.asset_id ? `/dashboard/migration-planner?asset=${encodeURIComponent(run.asset_id)}&labRun=${encodeURIComponent(run.id)}` : '/dashboard/migration-planner';
  return (
    <div className="sbl-page">
      <header className="sbl-card sbl-header">
        <div className="sbl-heading"><div><h1>Migration Sandbox</h1><p>Test a proposed cryptographic change against your asset’s recorded configuration before planning a rollout.</p></div>
          <div className="sbl-actions"><Link className="sbl-button" to="/dashboard/migration-planner">Migration Planner <ArrowRight size={16} aria-hidden /></Link><Link className="sbl-button" to={sourcePlan ? `?view=analysis&planId=${encodeURIComponent(sourcePlan)}` : '?view=analysis'}><BookOpen size={16} aria-hidden /> Analytical workspace</Link></div>
        </div>
        <div className="sbl-actions sbl-live"><span className="sbl-tag" role="status"><Activity size={14} aria-hidden /> {stream.sseConnected && !stream.error ? 'Live lab updates' : stream.transport === 'polling' || stream.error ? 'Reconnecting · showing last available data' : 'Connecting to lab records'}</span>{capabilities.value && <span className="sbl-muted">{capabilities.value.provider}</span>}</div>
      </header>

      <nav className="sbl-tabs" aria-label="Sandbox sections">
        <button aria-current={view === 'setup' ? 'page' : undefined} onClick={() => change({ runId: null, view: null })}><FlaskConical size={18} aria-hidden /> Configure tests</button>
        <button aria-current={view === 'results' ? 'page' : undefined} onClick={() => change({ runId: run?.id || stream.data.runs[0]?.id || null, view: null })} disabled={!run && !stream.data.runs.length}><Activity size={18} aria-hidden /> Run and results</button>
        <button aria-current={view === 'history' ? 'page' : undefined} onClick={() => change({ view: 'history' })}><History size={18} aria-hidden /> History and reports</button>
      </nav>

      {(error || stream.error) && <div className="sbl-alert" role="alert">{error || stream.error} <button className="sbl-button" onClick={() => { setError(''); void stream.refresh(); }}>Refresh records</button></div>}

      {view === 'setup' && (
        <>
          <section className="sbl-card"><div className="sbl-heading"><h2>Sandbox overview</h2><span className="sbl-muted">Activity across the latest 100 sessions</span></div>
            <dl className="sbl-metrics">{summary.map(([label, count]) => <div key={label}><dt>{label}</dt><dd>{stream.lastReceivedAt ? count : '—'}</dd></div>)}</dl>
          </section>
          <ol className="sbl-steps" aria-label="Sandbox workflow">{STEPS.map((step, index) => <li key={step} aria-current={index === current ? 'step' : undefined}><span>{index + 1}</span>{step}</li>)}</ol>
          <div className="sbl-setup">
            <section className="sbl-card sbl-assets">
              <h2>Select asset</h2><p className="sbl-muted">From your live cryptographic inventory.</p>
              <label className="sbl-search"><Search size={17} aria-hidden /><input aria-label="Search sandbox assets" placeholder="Search assets, hosts, owners" value={assets.filters.search} onChange={(event) => assets.setFilters({ ...assets.filters, search: event.target.value })} /></label>
              <div className="sbl-columns">
                <label>Posture<select value={assets.filters.posture} onChange={(event) => assets.setFilters({ ...assets.filters, posture: event.target.value })}><option value="all">All assets</option><option value="needs-migration">Vulnerable assets</option><option value="hybrid">Hybrid</option><option value="pqc">PQC</option></select></label>
                <label>Sort<select value={assets.filters.sort} onChange={(event) => assets.setFilters({ ...assets.filters, sort: event.target.value })}><option value="priority">Migration priority</option><option value="risk">Risk</option><option value="name">Name</option></select></label>
              </div>
              {assets.portfolioError && <p role="alert">{assets.portfolioError}</p>}
              <ul aria-busy={assets.portfolioLoading}>
                {assets.portfolio.assets.map((asset) => <li key={asset.id}>
                  <button className="sbl-asset" aria-pressed={asset.id === selectedAsset} onClick={() => { setConfiguration(INITIAL); change({ asset: asset.id, planId: asset.id === selectedAsset ? sourcePlan : null }); }}>
                    <strong>{asset.name}</strong><span>{asset.type} · {asset.environment} · {asset.priority} priority</span><small>{asset.cryptoPostureSummary}</small>
                  </button>
                </li>)}
              </ul>
              {!assets.portfolio.assets.length && !assets.portfolioLoading && portfolioReady && <p className="sbl-empty">No assets match this selection. <Link to="/dashboard/scanner">Open PQC Scanner</Link></p>}
              <div className="sbl-actions"><button className="sbl-button" disabled={!assets.page} onClick={() => assets.setPage(assets.page - 1)}>Previous</button><button className="sbl-button" disabled={(assets.page + 1) * assets.pageSize >= assets.portfolio.total} onClick={() => assets.setPage(assets.page + 1)}>Next</button><span className="sbl-muted">{portfolioReady ? `${assets.portfolio.total} matching` : 'Loading inventory…'}</span></div>
            </section>
            <section className="sbl-card">
              <h2>Sandbox environment and profiles</h2>
              {assets.dossierError && <p className="sbl-alert" role="alert">{assets.dossierError}</p>}
              {dossier ? <AssetEvidence asset={dossier} live /> : <p className="sbl-empty">{selectedAsset ? 'Loading the recorded asset configuration…' : 'Select an asset to load its observed cryptography and suggested replacements.'}</p>}
              {sourcePlan && <p className="sbl-muted">Scope imported from a Migration Planner proposal. The server checks that the plan includes this asset.</p>}
              <p className="sbl-muted">Each run uses a restricted local process and fresh test-only keys. TLS peers exchange data in memory. Only observed settings with supported adapters can be reproduced.</p>
              {capabilities.error && <p role="alert">{capabilities.error} <button className="sbl-button" onClick={capabilities.refresh}>Retry provider check</button></p>}
              {!capabilities.value && !capabilities.error && <p role="status">Checking provider operations and hybrid TLS support…</p>}
              {capabilities.value && !capabilities.value.executor && <p className="sbl-alert">{capabilities.value.storage === 'unavailable' ? 'Lab storage is unavailable. Ask an administrator to install the sandbox lab schema, then retry the provider check.' : 'A backend lab executor is unavailable.'} <button className="sbl-button" onClick={capabilities.refresh}>Retry provider check</button></p>}
              <form onSubmit={(event) => { event.preventDefault(); if (!busy && !active && hasTests && !unsupportedTls && dossier?.hasEvidence) void begin(configuration); }}>
                <div className="sbl-actions"><button className="sbl-button" type="button" disabled={!dossier?.hasEvidence || !capabilities.value} onClick={() => dossier && setConfiguration(recommendedProfile(dossier, capabilities.value))}>Use recommended checks</button><span className="sbl-muted">Adjust the selection to compare supported configurations.</span></div>
                <fieldset><legend>{LAB_LEVELS.execution.label}</legend>
                  <label className="sbl-option"><input type="checkbox" disabled={!capabilities.value?.worker} checked={configuration.testDetected} onChange={(event) => setConfiguration({ ...configuration, testDetected: event.target.checked })} /> Exercise supported detected primitives with generated keys</label>
                  <div className="sbl-options">{LAB_PRIMITIVES.map((algorithm) => {
                    const supported = Boolean(capabilities.value?.primitives[algorithm]);
                    return <label key={algorithm} className="sbl-option"><input type="checkbox" checked={configuration.primitives.includes(algorithm)} disabled={!supported || configuration.primitives.length >= 4 && !configuration.primitives.includes(algorithm)} onChange={(event) => setConfiguration({ ...configuration, primitives: event.target.checked ? [...configuration.primitives, algorithm] : configuration.primitives.filter((item) => item !== algorithm) })} /> {algorithm}{capabilities.value && !supported && <small>Unsupported</small>}</label>;
                  })}</div>
                </fieldset>
                <fieldset><legend>{LAB_LEVELS.emulation.label}</legend>
                  <label className="sbl-option"><input type="checkbox" disabled={!capabilities.value?.worker} checked={configuration.compareTlsBaseline} onChange={(event) => setConfiguration({ ...configuration, compareTlsBaseline: event.target.checked })} /> Compare the recorded TLS profile when enough evidence is available</label>
                  <div className="sbl-options">{LAB_TLS_GROUPS.map((group) => {
                    const checked = configuration.tlsGroups.includes(group);
                    const supported = capabilities.value?.tlsCertificates[group][tlsCertificate];
                    return <label className="sbl-option" key={group}><input type="checkbox" checked={checked} disabled={!checked && !supported} onChange={(event) => setConfiguration({ ...configuration, tlsGroups: event.target.checked ? [...configuration.tlsGroups, group] : configuration.tlsGroups.filter((item) => item !== group) })} /> {group}{capabilities.value && !supported && <small>Unsupported with {tlsCertificate.toUpperCase()}</small>}</label>;
                  })}</div>
                  <p className="sbl-muted">Proposed runs use TLS 1.3 with a synthetic certificate. If ML-DSA-65 or ML-DSA-87 is selected, the first selected signature profile is exercised with the hybrid group.</p>
                </fieldset>
                <fieldset><legend>{LAB_LEVELS.analysis.label}</legend><label className="sbl-option"><input type="checkbox" checked={configuration.analysis} onChange={(event) => setConfiguration({ ...configuration, analysis: event.target.checked })} /> Review dependencies, provider gaps, and likely rollout risks</label></fieldset>
                <div className="sbl-actions"><button className="sbl-button sbl-primary" type="submit" disabled={Boolean(busy) || active || !dossier?.hasEvidence || !hasTests || unsupportedTls || !capabilities.value?.executor}>{busy === 'start' ? 'Creating sandbox…' : 'Create sandbox and run checks'}</button>{active && <span className="sbl-muted">A session is already active.</span>}{unsupportedTls && <span className="sbl-muted">Remove the unsupported TLS combination or select a supported certificate profile.</span>}</div>
              </form>
            </section>
          </div>
        </>
      )}

      {view === 'results' && run && (
        <>
          <ol className="sbl-steps" aria-label="Sandbox workflow">{STEPS.map((step, index) => <li key={step} aria-current={index === current ? 'step' : undefined}><span>{index + 1}</span>{step}</li>)}</ol>
          <section className="sbl-card">
            <div className="sbl-heading"><div><h2>{run.asset_snapshot.name}</h2><p>Session {run.id}</p></div><span className="sbl-tag" role="status">{display(run.status)}</span></div>
            <p><strong>{run.current_operation}</strong></p>
            {run.planned_checks > 0 && <label className="sbl-progress">Recorded checks {run.results.length} of {run.planned_checks}<progress max={run.planned_checks} value={run.results.length} /></label>}
            <p className="sbl-muted">Started {timestamp(run.started_at)} · Finished {timestamp(run.finished_at)} · Cleanup {display(run.cleanup_status)}</p>
            {run.error && <p className="sbl-alert" role="alert">{run.error}</p>}
            <div className="sbl-actions">
              {isLive(run) && <button className="sbl-button" disabled={Boolean(busy) || run.status === 'cancelling'} onClick={() => token && void action('cancel', async () => { setLocalRun(await request<LabRun>(token, `${URL}/runs/${run.id}/cancel`, { method: 'POST' })); void stream.refresh(); })}>Cancel session</button>}
              {!isLive(run) && run.asset_id && <button className="sbl-button" disabled={Boolean(busy) || active} onClick={() => void begin(run.configuration, run.asset_id, run.source_plan_id)}>Run again</button>}
              <button className="sbl-button" disabled={Boolean(busy)} onClick={() => token && void action('export', async () => {
                const data = await request<unknown>(token, `${URL}/runs/${run.id}/report`);
                const objectUrl = window.URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
                const link = document.createElement('a');
                link.href = objectUrl; link.download = `sandbox-${run.id}.json`; link.click(); window.URL.revokeObjectURL(objectUrl);
              })}><FileDown size={16} aria-hidden /> Export evidence</button>
              {run.asset_id && <Link className="sbl-button" to={plannerUrl}>Review in Migration Planner <ArrowRight size={16} aria-hidden /></Link>}
            </div>
            <details className="sbl-details"><summary>Recorded operations ({run.logs.length})</summary><ol className="sbl-logs">{run.logs.map((log, index) => <li key={index}><time>{timestamp(log.at)}</time> {log.message}</li>)}</ol></details>
          </section>
          <section className="sbl-card"><h2>Recorded configuration and proposed change</h2>
            <div className="sbl-columns"><AssetEvidence asset={run.asset_snapshot} /><div className="sbl-observed"><h3>Proposed profiles</h3><p>{[...run.configuration.primitives, ...run.configuration.tlsGroups].join(', ') || 'Analytical and baseline checks'}</p><p className="sbl-muted">Timings and resource samples belong to the lab runtime. Handshake bytes cover the in-memory transport through client completion.</p></div></div>
            <TlsComparison run={run} />
          </section>
          <EvidenceResults run={run} />
          <section className="sbl-card">
            <div className="sbl-heading"><h2><ShieldCheck size={19} aria-hidden /> {readiness?.label}</h2></div><p>{readiness?.reason}</p>
            {run.attached_plan_id ? <p className="sbl-muted">Attached to proposal {run.attached_plan_id} · {timestamp(run.attached_at)}</p> : run.status === 'finished' && measured && reportAssetId && <details className="sbl-details" onToggle={(event) => setPlansOpen(event.currentTarget.open)}>
              <summary>Attach evidence to a migration proposal</summary>
              {plansError && <p role="alert">{plansError}</p>}
              {plans.length > 0 ? <form className="sbl-actions" onSubmit={(event) => {
                event.preventDefault();
                if (!token || !planId || busy) return;
                void action('attach', async () => { setLocalRun(await request<LabRun>(token, `${URL}/runs/${run.id}/attach`, { method: 'POST', body: JSON.stringify({ planId }) })); void stream.refresh(); });
              }}><label>Proposal<select value={planId} onChange={(event) => setPlanId(event.target.value)}><option value="">Select a plan</option>{plans.map((plan) => <option key={plan.id} value={plan.id}>{plan.name} · {display(plan.status)}</option>)}</select></label><button className="sbl-button" disabled={Boolean(busy) || !planId}>Attach verified record</button></form> : <p className="sbl-muted">Submit a scoped proposal for this asset in Migration Planner, then attach the evidence here.</p>}
            </details>}
          </section>
        </>
      )}
      {view === 'results' && !run && <section className="sbl-card"><h2>Sandbox session</h2><p role={runError ? 'alert' : 'status'}>{runError || 'Loading persisted results…'}</p></section>}
      {view === 'history' && <><section className="sbl-card"><h2>Session history</h2><p className="sbl-muted">Showing up to 100 recent runs. Open a session to view its stored evidence, rerun it, or export a report.</p>
        {stream.data.runs.length ? <ul className="sbl-history">{stream.data.runs.map((entry) => <li key={entry.id}><div><strong>{entry.asset_snapshot.name}</strong><p>{timestamp(entry.created_at)} · {entry.results.length} evidence records · {display(entry.status)}</p></div><Link className="sbl-button" to={`?asset=${encodeURIComponent(entry.asset_snapshot.id)}&runId=${encodeURIComponent(entry.id)}`}>Open evidence</Link></li>)}</ul> : <p className="sbl-empty">{stream.state === 'success' ? 'No lab sessions recorded.' : 'Waiting for session history.'}</p>}
      </section><CompareRuns runs={stream.data.runs} /></>}
    </div>
  );
}
