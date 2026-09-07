/**
 * Dev scan runner (§17-28, Spec-2 §35).
 *
 * The server-side entry point for a DEV assessment. It does the acquisition the
 * orchestrator does not know how to do — resolve a repository, or verify a
 * cluster/cloud/registry connection — then hands the resulting workspace to the
 * same orchestrator that runs Local scans.
 *
 * §57: "Dev repository scans must not execute synchronously inside the HTTP
 *       request." So this returns immediately with a scan handle, streams events
 *       to whoever is listening, and keeps the completed assessment in a bounded
 *       registry the API can read back. There is no queue infrastructure in this
 *       platform to hand off to, and inventing one would be a bigger change than
 *       the requirement justifies — a bounded in-process job registry with hard
 *       concurrency and TTL limits meets the actual constraint, which is that
 *       the HTTP request must not block.
 */

import type {
  ExposureAssessment,
  ScanEvent,
  ScanExclusions,
  ScanTarget,
  ScanTaskStatus,
} from '../types';
import { defaultExclusions } from '../types';
import type { EngineCredential } from '../engine-contract';
import { emptyWorkspace } from '../engine-contract';
import { runExposureScan } from '../orchestrator';
import { resolveProfile } from '../profiles';
/* Side-effect import: makes the live Kubernetes, registry and cloud engines
   executable in this (server) runtime. See dev/connectors.ts for why it is a
   side-effect import rather than a static one in the registry. */
import './connectors';
import { REPO_LIMITS, collectRepository } from './repo-collector';

/* ───────────────────────────────────────────────────────────── job registry ── */

export interface DevScanJob {
  scanId: string;
  userId: string | null;
  status: ScanTaskStatus;
  target: ScanTarget;
  profileId: string;
  createdAt: number;
  /** Ring buffer of events, so a late subscriber can catch up. */
  events: ScanEvent[];
  subscribers: Set<(event: ScanEvent) => void>;
  assessment: ExposureAssessment | null;
  error: string | null;
  cancelled: boolean;
}

const JOBS = new Map<string, DevScanJob>();
const MAX_JOBS = 200;
const JOB_TTL_MS = 60 * 60 * 1000;
const MAX_EVENTS_PER_JOB = 600;
const MAX_CONCURRENT_SCANS = 4;
let inFlight = 0;

function sweepJobs(): void {
  const now = Date.now();
  for (const [scanId, job] of JOBS) {
    if (now - job.createdAt > JOB_TTL_MS) JOBS.delete(scanId);
  }
  while (JOBS.size > MAX_JOBS) {
    const oldest = [...JOBS.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
    if (!oldest) break;
    JOBS.delete(oldest[0]);
  }
}

export function getJob(scanId: string, userId: string | null): DevScanJob | null {
  const job = JOBS.get(scanId);
  if (!job) return null;
  /* Tenant isolation (§45): the scan id is not a capability. A job created by
     one user is invisible to another even with the id in hand. */
  if (job.userId !== userId) return null;
  return job;
}

export function listJobs(userId: string | null): DevScanJob[] {
  return [...JOBS.values()].filter((job) => job.userId === userId).sort((a, b) => b.createdAt - a.createdAt);
}

export function cancelJob(scanId: string, userId: string | null): boolean {
  const job = getJob(scanId, userId);
  if (!job) return false;
  job.cancelled = true;
  return true;
}

export function subscribe(job: DevScanJob, listener: (event: ScanEvent) => void): () => void {
  job.subscribers.add(listener);
  return () => job.subscribers.delete(listener);
}

/* ───────────────────────────────────────────────────────────────── options ── */

export interface DevScanOptions {
  userId: string | null;
  tenantId?: string | null;
  profileId: string;
  customEngines?: string[];
  exclusions?: ScanExclusions;
  /** Repository target. */
  repositoryUrl?: string;
  branch?: string;
  /** Connector targets. */
  cluster?: { endpoint: string; namespaces: string[]; label: string };
  cloud?: { provider: 'aws' | 'azure' | 'gcp'; account: string; regions: string[] };
  container?: { image: string; registry?: string };
  credentials?: Partial<Record<EngineCredential['kind'], EngineCredential>>;
}

export interface DevScanHandle {
  scanId: string;
  status: ScanTaskStatus;
  engines: string[];
  /** null when the target could not be resolved before dispatch. */
  error: string | null;
}

/* ──────────────────────────────────────────────────────────────── dispatch ── */

/**
 * Start a Dev assessment. Returns as soon as the job is registered.
 *
 * Target resolution — deciding WHAT is being scanned — happens synchronously
 * because a bad URL must be an immediate 400, not a job that fails thirty
 * seconds later. Everything after that is asynchronous.
 */
export async function startDevScan(options: DevScanOptions): Promise<DevScanHandle> {
  sweepJobs();

  if (inFlight >= MAX_CONCURRENT_SCANS) {
    return {
      scanId: '',
      status: 'failed',
      engines: [],
      error: `The scanner is at capacity (${MAX_CONCURRENT_SCANS} concurrent assessments). Retry in a few seconds.`,
    };
  }

  const target = resolveTarget(options);
  if ('error' in target) {
    return { scanId: '', status: 'failed', engines: [], error: target.error };
  }

  const { engines } = resolveProfile('dev', options.profileId, options.customEngines);
  if (engines.length === 0) {
    return { scanId: '', status: 'failed', engines: [], error: 'The selected profile resolved to no runnable engines.' };
  }

  const scanId = `dev-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const job: DevScanJob = {
    scanId,
    userId: options.userId,
    status: 'queued',
    target: target.target,
    profileId: options.profileId,
    createdAt: Date.now(),
    events: [],
    subscribers: new Set(),
    assessment: null,
    error: null,
    cancelled: false,
  };
  JOBS.set(scanId, job);

  // Deliberately not awaited: the HTTP handler returns the handle immediately.
  void executeJob(job, options, engines).catch((error) => {
    job.status = 'failed';
    job.error = (error as Error).message;
  });

  return { scanId, status: 'queued', engines, error: null };
}

function resolveTarget(options: DevScanOptions): { target: ScanTarget } | { error: string } {
  if (options.repositoryUrl) {
    return {
      target: {
        kind: 'repository',
        url: options.repositoryUrl,
        provider: 'unknown',
        owner: '',
        repo: '',
        branch: options.branch,
        visibility: 'unknown',
      },
    };
  }
  if (options.cluster) {
    if (!options.cluster.namespaces?.length) {
      return { error: 'Select at least one namespace. This scanner never enumerates a whole cluster implicitly.' };
    }
    return {
      target: { kind: 'kubernetes', cluster: options.cluster.label, namespaces: options.cluster.namespaces, live: true },
    };
  }
  if (options.cloud) {
    if (!options.cloud.regions?.length) {
      return { error: 'Select at least one region. This scanner never enumerates a whole account implicitly.' };
    }
    return {
      target: { kind: 'cloud', provider: options.cloud.provider, account: options.cloud.account, regions: options.cloud.regions },
    };
  }
  if (options.container) {
    return { target: { kind: 'container', image: options.container.image, registry: options.container.registry } };
  }
  return { error: 'No scan target was supplied. Provide a repository URL, or select a connected cluster, cloud account or image.' };
}

/**
 * The share of the progress bar reserved for repository acquisition.
 *
 * Measured on a real public repository: 21.1s spent fetching 57 files against
 * 0.4s of engine execution — acquisition was 98% of the scan. The engines are
 * in-memory passes over a corpus that is already downloaded, so they will
 * always be the fast part of a repository scan. Reserving most of the bar for
 * the download is what makes the bar describe the wait the operator is actually
 * having; the remainder still animates through the real engine ledger.
 *
 * Targets with no acquisition phase (a cluster, cloud account or registry, where
 * the engines do the network work themselves) keep the whole range.
 */
export const ACQUISITION_PROGRESS_SHARE = 80;

/**
 * Maps a real read ratio onto the acquisition band.
 *
 * Exported so the progress model can be asserted without a network round-trip
 * (tools/scan-progress-check.ts) — inline arithmetic inside a publish callback
 * is arithmetic nobody can test.
 */
export function acquisitionProgress(done: number, total: number): number {
  if (!Number.isFinite(total) || total <= 0) return 0;
  const ratio = Math.max(0, Math.min(1, done / total));
  return Math.round(ratio * ACQUISITION_PROGRESS_SHARE);
}

async function executeJob(job: DevScanJob, options: DevScanOptions, engines: string[]): Promise<void> {
  inFlight += 1;
  try {
    const publish = (event: ScanEvent) => {
      job.events.push(event);
      if (job.events.length > MAX_EVENTS_PER_JOB) job.events.splice(0, job.events.length - MAX_EVENTS_PER_JOB);
      for (const subscriber of job.subscribers) {
        try {
          subscriber(event);
        } catch {
          /* a dead subscriber must never break the scan */
        }
      }
    };

    job.status = 'initializing';
    const workspace = emptyWorkspace();
    const exclusions = options.exclusions ?? defaultExclusions();

    /* ── acquisition ─────────────────────────────────────────────────────── */
    if (job.target.kind === 'repository') {
      publish({
        event: 'engine.started',
        scanId: job.scanId,
        timestamp: new Date().toISOString(),
        engineId: 'repository-discovery',
        engineLabel: 'Repository Discovery',
        state: 'running',
        step: 'Resolving repository',
        progress: 0,
      });

      const limits = options.profileId === 'quick' ? REPO_LIMITS.quick : options.profileId === 'deep' || options.profileId === 'full-dev' ? REPO_LIMITS.deep : REPO_LIMITS.standard;

      const collected = await collectRepository(job.target.url, {
        branch: options.branch,
        token: options.credentials?.['git-token']?.value?.token ?? null,
        limits,
        isCancelled: () => job.cancelled,
        onProgress: ({ done, total, current }) => {
          publish({
            event: 'engine.progress',
            scanId: job.scanId,
            timestamp: new Date().toISOString(),
            engineId: 'repository-discovery',
            engineLabel: 'Repository Discovery',
            state: 'running',
            step: `Reading ${current}`,
            units: { done, total, unit: 'files' },
            /* The real read ratio, mapped onto the acquisition band. Without
               this the bar could not move at all during the longest phase of
               the scan. */
            progress: acquisitionProgress(done, total),
          });
        },
      });

      if (!collected.resolution.ok) {
        job.status = 'failed';
        job.error = collected.resolution.notice ?? 'The repository could not be read.';
        publish({
          event: 'scan.failed',
          scanId: job.scanId,
          timestamp: new Date().toISOString(),
          message: job.error,
          detail: collected.resolution.recommendation,
        });
        return;
      }

      workspace.files = collected.workspace.files;
      workspace.meta = { ...collected.workspace.meta };
      for (const facet of collected.workspace.facets) workspace.facets.add(facet);
      workspace.meta.collectionLimitations = collected.limitations;

      // Refine the target now that the repository is resolved.
      job.target = {
        kind: 'repository',
        url: collected.ref.webUrl,
        provider: collected.ref.provider,
        owner: collected.ref.owner,
        repo: collected.ref.repo,
        branch: collected.resolution.branch,
        visibility: collected.resolution.visibility,
      };

      publish({
        event: 'engine.completed',
        scanId: job.scanId,
        timestamp: new Date().toISOString(),
        engineId: 'repository-discovery',
        engineLabel: 'Repository Discovery',
        state: 'completed',
        detail: `${collected.stats.read} of ${collected.stats.treeEntries} files read from branch ${collected.resolution.branch}.`,
        progress: ACQUISITION_PROGRESS_SHARE,
      });
    }

    /* ── execution ───────────────────────────────────────────────────────── */
    job.status = 'analyzing';
    const assessment = await runExposureScan({
      scanId: job.scanId,
      mode: 'dev',
      target: job.target,
      profileId: options.profileId,
      engineIds: engines,
      workspace,
      exclusions,
      tenantId: options.tenantId ?? null,
      userId: options.userId,
      credentials: options.credentials,
      budgetMs: 300_000,
      concurrency: 3,
      isCancelled: () => job.cancelled,
      onEvent: publish,
      /* The engines take the band acquisition did not use. A repository target
         has already spent the front of the bar downloading; every other Dev
         target does its own network work inside the engines and keeps the lot. */
      progressRange: job.target.kind === 'repository'
        ? { from: ACQUISITION_PROGRESS_SHARE, to: 99 }
        : { from: 0, to: 99 },
    });

    /* Collection limitations are folded into the assessment's coverage so the
       report's "what was not assessed" section is complete rather than split
       between the collector and the engines. */
    const limitations = (workspace.meta.collectionLimitations as Array<{ dimension: string; reason: string }> | undefined) ?? [];
    for (const limitation of limitations) {
      const duplicate = assessment.task.coverage.notAssessed.some((entry) => entry.dimension === limitation.dimension);
      if (!duplicate) assessment.task.coverage.notAssessed.push({ ...limitation, engineId: 'repository-discovery' });
    }

    job.assessment = assessment;
    job.status = assessment.task.status;
  } finally {
    inFlight -= 1;
  }
}
