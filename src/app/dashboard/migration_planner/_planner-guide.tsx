import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ArrowRight, ChevronDown, ClipboardList, FileDown, FlaskConical, Radar, Rocket, ShieldCheck, ShieldAlert } from 'lucide-react';
import type { AssetDossier, AssetAlgorithm, PortfolioSummary } from '@/hooks/use-migration-assets';
import { integerFmt, longDate } from '@/app/dashboard/quantum-readiness/_shared';
import type { LiveMigrationJob } from '@/app/dashboard/live_migration_ops/LiveMigrationOps';
import { useLiveResource } from '@/hooks/use-live-resource';
import { isPassingValidation } from '@/lib/migration/job-safety';

export const SCANNER_PATH = '/dashboard/scanner';
const OPS_PATH = '/dashboard/live-migration';

function openTechnicalEvidence() {
  const details = document.querySelector<HTMLDetailsElement>('#asset-evidence');
  if (!details) return;
  details.open = true;
  details.querySelector('summary')?.focus();
}

export function operationHref(job: { id: string; planId: string | null }) {
  const params = new URLSearchParams({ jobId: job.id });
  if (job.planId) params.set('planId', job.planId);
  return `${OPS_PATH}?${params}`;
}

const REVIEW_BY_CATEGORY: Record<AssetAlgorithm['category'], { label: string; risk: string; verify: string }> = {
  'key-establishment': { label: 'Key establishment', risk: 'Traffic captured today could be decrypted by a future quantum computer.', verify: 'Check library and peer support. Test the negotiated group and fallback on every termination point.' },
  signature: { label: 'Digital signature', risk: 'A future quantum attacker could forge signatures or impersonate a trusted signer.', verify: 'Test signing, verification, certificate chains or token consumers, payload size, and key rotation.' },
  symmetric: { label: 'Symmetric encryption', risk: 'Legacy ciphers and short keys reduce the security margin for stored data or traffic.', verify: 'Check nonce handling, key rotation and authenticated decryption, including data encrypted before the change.' },
  hash: { label: 'Hashing / key derivation', risk: 'Deprecated digests can weaken integrity. The impact depends on how the primitive is used.', verify: 'Test interoperability with the actual format and check existing persisted hashes and derived keys.' },
  protocol: { label: 'Transport / TLS', risk: 'Deprecated transport can expose traffic to weaker negotiation or leave it vulnerable to future decryption.', verify: 'Test every supported client and proxy for accepted versions, negotiated groups and forward connectivity.' },
  unknown: { label: 'Use to confirm', risk: 'Impact depends on whether this primitive protects confidentiality, authenticity or integrity.', verify: 'Confirm the cryptographic role, provider and protocol profile with the asset owner before proposing a cutover.' },
};

export function AssetMigrationGuide({
  asset, onPlan, onSandbox, onDispatch, onReport, busy,
}: {
  asset: AssetDossier; onPlan: () => void; onSandbox: () => void; onDispatch: () => void; onReport: () => void; busy: boolean;
}) {
  const verificationPassed = asset.migrationStatus === 'Completed' && asset.validation.validated;
  const verified = verificationPassed && asset.posture === 'pqc' && asset.vulnerableComponentCount === 0;
  const sandbox = asset.latestSandbox;
  const [expanded, setExpanded] = useState<number | null>(null);
  const next = !asset.hasEvidence ? 0 : verified ? 5 : verificationPassed || ['Completed', 'Validating'].includes(asset.migrationStatus) ? 4
    : ['Queued', 'In Progress', 'Failed'].includes(asset.migrationStatus) ? 3 : asset.queued ? 2 : 1;
  const selected = expanded ?? next;
  const candidates = asset.algorithms.filter((algorithm) => algorithm.classification === 'vulnerable');
  const primary = candidates[0];
  const latestJob = asset.jobs[0];
  const steps = [
    { title: 'Discovery & assessment', icon: Radar, state: asset.hasEvidence ? 'Evidence recorded' : 'Scan needed', text: 'Review the current cryptography, confirm the finding and check how the asset is used. Verify data sensitivity and retention with the owner when that information was not captured.', action: asset.hasEvidence ? <button className="mp-button" onClick={openTechnicalEvidence}>Inspect technical evidence</button> : <Link className="mp-button" to={SCANNER_PATH}>Open PQC Scanner</Link> },
    { title: 'Migration planning', icon: ClipboardList, state: asset.queued ? 'In queue' : asset.hasEvidence ? 'Ready to review' : 'Awaiting discovery', text: 'Choose a supported candidate replacement. Identify the asset owner, dependent systems, and rollout order. Save the proposed scope for approval from the migration queue.', action: <button className="mp-button" onClick={onPlan} disabled={!asset.hasEvidence || busy}>{asset.queued ? 'Open migration queue' : 'Add to migration queue'}</button> },
    { title: 'Pre-migration validation', icon: FlaskConical, state: asset.validation.cutoverBlocked ? 'Review blockers' : 'Review lab evidence', text: 'Check the cryptographic provider, library versions, protocol support, downstream clients, and configuration conflicts. Test a canary in a representative environment and retain the current configuration for rollback.', action: <div className="flex flex-wrap gap-2">
      <button className="mp-button" onClick={onSandbox} disabled={!asset.hasEvidence || busy}>Test in Migration Sandbox</button>
      {sandbox?.planId && <Link className="mp-button" to={`/dashboard/migration-sandbox?view=analysis&planId=${encodeURIComponent(sandbox.planId)}`}>Open analytical history</Link>}
    </div> },
    { title: 'Migration execution', icon: Rocket, state: asset.migrationStatus, text: 'After rehearsal and change approval, use a staged rollout. Review agent and connector requirements, check the first deployment, and investigate failed operations before retrying.', action: latestJob && ['In Progress', 'Queued', 'Failed', 'Validating', 'Completed'].includes(asset.migrationStatus)
      ? <Link className="mp-button" to={operationHref(latestJob)}>Inspect execution</Link>
      : <button className="mp-button" onClick={onDispatch} disabled={!asset.hasEvidence || busy}>Review execution handoff</button> },
    { title: 'Post-migration validation', icon: ShieldCheck, state: verified ? 'Verified' : verificationPassed ? 'Passing check · posture pending' : asset.validation.lastStatus, text: 'Re-scan the asset. Verify the negotiated or active algorithm, connectivity and application behavior. Compare against the original finding and check that vulnerable paths are removed or accounted for.', action: latestJob ? <Link className="mp-button" to={operationHref(latestJob)}>Review validation and logs</Link> : <Link className="mp-button" to={SCANNER_PATH}>Open PQC Scanner</Link> },
    { title: 'Monitoring & compliance', icon: Activity, state: verified ? 'Monitor for drift' : 'Awaiting verified outcome', text: 'Monitor for fallback or configuration drift, retain job and scan evidence, and record remaining exceptions before closing the change.', action: <button className="mp-button" onClick={onReport} disabled={busy}><FileDown size={16} aria-hidden="true" /> Export asset evidence</button> },
  ];

  return (
    <div className="mp-card mp-guide">
      <div className="mp-heading-row">
        <div>
          <h3>Finding and next action</h3>
          <p>Current assessment for {asset.hostname === 'Evidence Not Available' ? asset.name : asset.hostname}</p>
        </div>
        <button className="mp-button" onClick={onReport} disabled={busy}><FileDown size={16} aria-hidden="true" /> Export evidence</button>
      </div>
      <div className="mp-finding-grid">
        <div><h4>What was detected?</h4><p>{primary ? `${primary.algorithm}${primary.keySizes.length ? ` · ${primary.keySizes.join(' / ')} bit` : ''}` : asset.findings[0]?.title || asset.cryptoPostureSummary}</p></div>
        <div><h4>Why does it matter?</h4><p>{primary ? REVIEW_BY_CATEGORY[primary.category].risk : asset.hasEvidence ? asset.riskAnalysis.explanation : 'A scan is needed to assess cryptographic exposure.'}</p></div>
        <div><h4>What should change?</h4><p>{primary?.target || (asset.hasEvidence ? asset.recommendations[0]?.title : 'Run a discovery scan to collect evidence.')}</p></div>
      </div>
      {candidates.length > 0 && (
        <details className="mp-disclosure">
          <summary>Review replacement candidates ({candidates.length}) <ChevronDown size={16} aria-hidden="true" /></summary>
          <div className="mp-candidates">
            {candidates.map((algorithm) => {
              const category = REVIEW_BY_CATEGORY[algorithm.category];
              return (
                <div className="mp-candidate" key={`${algorithm.algorithm}:${algorithm.category}`}>
                  <span className="mp-chip">{category.label}</span>
                  <h4>{algorithm.algorithm} → {algorithm.target}</h4>
                  <p>{algorithm.rationale}</p>
                  <p><strong>Compatibility and validation.</strong> {category.verify}</p>
                  {algorithm.standard && <p className="mp-muted">{algorithm.standard}</p>}
                </div>
              );
            })}
            <p className="mp-muted">{asset.dependencies.length} recorded dependencies. {asset.estimatedDowntime}</p>
          </div>
        </details>
      )}
      <div className="mp-heading-row mp-workflow-heading">
        <div><h3>Migration workflow</h3><p>Suggested next step · {steps[next].title}</p></div>
      </div>
      <ol className="mp-steps">
        {steps.map(({ title, icon: Icon, state, text, action }, index) => (
          <li key={title} data-current={selected === index}>
            <button type="button" className="mp-step" onClick={() => setExpanded(index)} aria-expanded={selected === index}>
              <Icon size={18} aria-hidden="true" />
              <span>{index + 1}. {title}</span>
              <span className="mp-step-state">{state}</span>
              <ChevronDown size={16} aria-hidden="true" />
            </button>
            {selected === index && <div className="mp-step-detail"><p>{text}</p>{action}</div>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function MigrationOverview({ summary, readiness, loading }: { summary: PortfolioSummary | null; readiness: number | null; loading: boolean }) {
  const metrics = [
    { label: 'Discovered assets', value: summary?.total },
    { label: 'Vulnerable assets', value: summary?.vulnerableAssets, hint: `${summary?.quantumVulnerable ?? 0} classified quantum-vulnerable` },
    { label: 'Immediate attention', value: summary?.immediateAttention, hint: 'Critical or high priority' },
    { label: 'Verified migrations', value: summary?.verifiedMigrations, hint: 'Completed, validated and PQC-ready' },
    { label: 'Active migrations', value: summary?.activeMigrations },
    { label: 'Pending migrations', value: summary?.pendingMigrations },
    { label: 'Quantum readiness', value: readiness, suffix: '/100' },
  ];
  const stages = [
    { name: 'Verified', count: summary?.verifiedMigrations ?? 0, tone: 'good' },
    { name: 'Active', count: summary?.activeMigrations ?? 0, tone: 'info' },
    { name: 'Pending', count: summary?.pendingMigrations ?? 0, tone: 'pending' },
    { name: 'Completed, verification outstanding', count: summary?.unverifiedCompletions ?? 0, tone: 'verify' },
    { name: 'Failed', count: summary?.failedMigrations ?? 0, tone: 'risk' },
  ];
  const terminal = stages[0].count + stages[3].count + stages[4].count;
  const total = stages.reduce((sum, stage) => sum + stage.count, 0);
  return (
    <section className="mp-card mp-overview" aria-labelledby="mp-overview-heading" aria-busy={loading}>
      <div className="mp-heading-row"><h2 id="mp-overview-heading">Migration overview</h2><span className="mp-muted">Current asset portfolio</span></div>
      <dl className="mp-metrics">
        {metrics.map(({ label, value, suffix, hint }) => (
          <div className="mp-metric" key={label}><dt>{label}</dt><dd>{value == null ? '—' : integerFmt(value)}{value != null && <small>{suffix}</small>}</dd>{value != null && hint && <p>{hint}</p>}</div>
        ))}
      </dl>
      <div className="mp-progress">
        <div className="mp-heading-row">
          <h3>Migration outcomes</h3>
          <span className="mp-muted">{terminal ? `${Math.round(stages[0].count / terminal * 100)}% verified success · ${terminal} terminal outcomes` : 'Awaiting completed or failed migrations'}</span>
        </div>
        <div className="mp-progress-track" aria-hidden="true">
          {total > 0 && stages.filter(({ count }) => count > 0).map(({ name, count, tone }) => <span key={name} data-tone={tone} style={{ flexGrow: count }} />)}
        </div>
        {summary && <ul className="mp-legend">{stages.map(({ name, count, tone }) => <li key={name}><i data-tone={tone} aria-hidden="true" />{name} <strong>{integerFmt(count)}</strong></li>)}</ul>}
      </div>
    </section>
  );
}

function jobGroup(status: string) {
  if (/^(completed|done)$/i.test(status)) return 'Completed';
  if (/^(failed|error|rolled_back|rollback_failed)$/i.test(status)) return 'Failed / rollback';
  if (/^(running|in_progress|validating|deploying|executing|rolling_back)$/i.test(status)) return 'Active';
  if (status === 'paused') return 'Paused';
  if (/^(canceled|cancelled)$/i.test(status)) return 'Cancelled';
  return 'Pending / other';
}

const EMPTY_OPERATIONS: { jobs: LiveMigrationJob[] } = { jobs: [] };
const OPERATION_TABLES = ['migration_jobs', 'migration_execution', 'migration_events', 'migration_telemetry', 'migration_validation_logs'];

export function MigrationMonitoring() {
  const { data, state, error, sseConnected, refresh } = useLiveResource({
    url: '/api/v1/migration/live',
    streamUrl: '/api/v1/migration/live/stream',
    event: 'migration-update',
    empty: EMPTY_OPERATIONS,
    realtimeTables: OPERATION_TABLES,
    channelPrefix: 'migration-planner-ops',
  });
  const jobs = (data.jobs || []).filter((job) => !job.isSandbox);
  const [filter, setFilter] = useState('All');
  const [limit, setLimit] = useState(12);
  const filtered = jobs.filter((job) => filter === 'All' || jobGroup(job.status) === filter);
  return (
    <section className="mp-card mp-monitor" aria-labelledby="mp-monitor-heading">
      <div className="mp-heading-row">
          <div><h2 id="mp-monitor-heading">Execution & validation</h2><p>Inspect recent migration operations and open their logs, validation evidence and available controls.</p></div>
        <div className="flex flex-wrap gap-2">
          <Link className="mp-button" to="/dashboard/migration-timeline">Migration history</Link>
          <Link className="mp-button mp-button-primary" to={OPS_PATH}>Live Migration Ops <ArrowRight size={16} aria-hidden="true" /></Link>
        </div>
      </div>
      <p className="mp-muted mt-2" role="status">{sseConnected ? 'Live operation updates' : 'Connecting to operation updates'}</p>
      {error && <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-[var(--mp-risk)]" role="alert"><span>{error}</span><button className="mp-button" onClick={() => void refresh()}>Retry</button></div>}
      <div className="mp-monitor-filters">
        {['All', 'Pending / other', 'Active', 'Paused', 'Completed', 'Failed / rollback', 'Cancelled'].map((name) => (
          <button className="mp-button" key={name} aria-pressed={name === filter} onClick={() => { setFilter(name); setLimit(12); }}>{name} <span>{name === 'All' ? jobs.length : jobs.filter((job) => jobGroup(job.status) === name).length}</span></button>
        ))}
      </div>
      {state === 'loading' && !jobs.length ? <p role="status">Loading migration jobs…</p> : filtered.length ? (
        <ul className="mp-job-list">
          {filtered.slice(0, limit).map((job) => {
            const failure = job.status === 'failed' ? [...(job.logs || [])].reverse().find((entry) => /error|critical|fail/i.test(entry.severity)) : undefined;
            const planId = typeof job.metadata?.planId === 'string' ? job.metadata.planId : null;
            return (
            <li key={job.id}>
              <div><strong>{job.asset}</strong><p>{job.currentStep}</p><p>Updated {longDate(job.updatedAt)}</p></div>
              <div><span className="mp-chip">{job.status.replaceAll('_', ' ')}</span><p>{integerFmt(job.progress)}% execution progress</p>{job.startedAt && <p>Started {longDate(job.startedAt)}</p>}</div>
              <div><strong>{isPassingValidation(job.validationStatus) ? 'Passing validation recorded' : job.validationStatus === 'pending' ? 'No passing validation recorded' : job.validationStatus}</strong><p>{job.logCount} log entries</p></div>
              <Link className="mp-button" to={operationHref({ id: job.id, planId })}>Inspect operation <ArrowRight size={15} aria-hidden="true" /></Link>
              {(job.dispatchBlock || (job.status === 'failed' && failure)) && <p className="col-span-full break-words text-[var(--mp-risk)]">{job.dispatchBlock?.reason || failure?.message}</p>}
            </li>
            );
          })}
        </ul>
      ) : state === 'success' && <div className="mp-empty"><ShieldAlert size={22} aria-hidden="true" /><p>{filter === 'All' ? 'No migration operations recorded.' : 'No operations match this status.'}</p></div>}
      {filtered.length > limit && <button className="mp-button" onClick={() => setLimit(limit + 12)}>Show more operations</button>}
    </section>
  );
}
