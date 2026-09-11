/**
 * QGuard Helix Exposure Assessment Engine™ API — /api/v1/exposure
 *
 * The Local and Dev counterparts to /api/v1/public-scan. Mounted BEFORE the
 * subscription gateway so the anonymous surfaces (capabilities, engine
 * disclosure, public repository validation and public repository scanning)
 * work without an account — that is the product — while everything that
 * touches a tenant's own data or a stored credential requires authentication
 * and is tenant-scoped at every boundary (§45).
 *
 * SECURITY POSTURE FOR THE ANONYMOUS SURFACES
 *   • per-IP token bucket + a global in-flight cap
 *   • public repositories only; a private repository is refused, never
 *     attempted with a platform token that would leak another tenant's access
 *   • SSRF: only the five recognised Git platforms, resolved through the shared
 *     adapter, which itself refuses private hosts
 *   • privacy-first logging: repository slug and outcome only
 *
 * LOCAL MODE HAS NO SCAN ENDPOINT, DELIBERATELY. Local assessments execute in
 * the browser's own Web Worker so source never leaves the device (§43). The
 * only Local endpoint here is `/local/sync`, which accepts an already-sanitised
 * assessment when an authenticated user explicitly chooses to persist it.
 */

import { Router, type NextFunction, type Request, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import type { SupabaseClient, User } from '@supabase/supabase-js';
import { createAuthClient, getServerUser, getServiceClient, getToken } from '@/lib/supabase-server';
import {
  CAPABILITY_LABEL,
  type EngineCredential,
} from '@/lib/scanner/exposure/engine-contract';
import { descriptorsForMode, engineHealth } from '@/lib/scanner/exposure/registry';
/* Side-effect import: registers the server-only connector engines so /engines
   reports their real health rather than "descriptor only". */
import '@/lib/scanner/exposure/dev/connectors';
import { FACET_LABEL, planScan, profilesForMode, resolveProfile } from '@/lib/scanner/exposure/profiles';
import { knownAlgorithms } from '@/lib/scanner/exposure/algorithms';
import { engineVersion, knowledgeBaseSummary } from '@/lib/crypto/knowledge-base';
import { validateRepository } from '@/lib/scanner/exposure/dev/repo-collector';
import { cancelJob, getJob, listJobs, startDevScan, subscribe } from '@/lib/scanner/exposure/dev/run-dev-scan';
import { cbomToCsv, cbomToCycloneDx, cbomToJson } from '@/lib/scanner/exposure/cbom';
import {
  CONNECTION_LABEL,
  REQUIRED_PERMISSIONS,
  toEngineCredential,
  toPublicConnection,
  validateConnectionInput,
  type ConnectionKind,
  type DevConnection,
} from '@/lib/scanner/exposure/dev/connections';
import { probeCluster } from '@/lib/scanner/exposure/dev/k8s-live';
import { probeAzure } from '@/lib/scanner/exposure/dev/cloud/azure';
import { probeGcp } from '@/lib/scanner/exposure/dev/cloud/gcp';
import { getCallerIdentity } from '@/lib/scanner/exposure/dev/cloud/aws';
import { persistExposureAssessment } from './exposure-persistence';
import {
  deleteExposureHistoryEntry,
  historyFingerprint,
  HistoryQueryError,
  loadExposureHistory,
  loadExposureHistoryDetail,
  notifyHistoryChanged,
  onHistoryChanged,
} from './exposure-history';
import type { ExposureHistoryMode } from '@/lib/scanner/exposure/history';
import type { ExposureAssessment } from '@/lib/scanner/exposure/types';
import type { TargetFacet } from '@/lib/scanner/exposure/engine-contract';
import {
  EXPOSURE_MODE_MIN_TIER,
  exposureModeDenialMessage,
  plansIncluding,
  resolveExposureModeAccess,
  type AccessTier,
  type ExposureScanMode,
} from '@/lib/subscription-access';
import { resolveEntitlement } from './subscription-guard';

const router = Router();

type AuthedRequest = Request & { user?: User; token?: string; client?: SupabaseClient | null };

function jsonError(res: Response, status: number, code: string, message: string, detail?: unknown) {
  return res.status(status).json({ error: { code, message, detail } });
}

async function requireUserAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = getToken(req);
  if (!token) return jsonError(res, 401, 'UNAUTHORIZED', 'Authentication required.');
  const user = await getServerUser(token);
  if (!user) return jsonError(res, 401, 'UNAUTHORIZED', 'Invalid or expired token.');
  req.user = user;
  req.token = token;
  req.client = createAuthClient(token) || getServiceClient();
  next();
}

/** Attach the user when a token is present, but do not require one. */
async function optionalUserAuth(req: AuthedRequest, _res: Response, next: NextFunction) {
  const token = getToken(req);
  if (token) {
    const user = await getServerUser(token);
    if (user) {
      req.user = user;
      req.token = token;
      req.client = createAuthClient(token) || getServiceClient();
    }
  }
  next();
}

/* ------------------------------------------------------- mode entitlement -- */

/**
 * Per-MODE subscription enforcement.
 *
 * This router is mounted BEFORE the central subscription gateway, deliberately:
 * the anonymous Web assessment is the product's front door and must keep
 * working without an account. That exemption is granted by URL prefix, so it
 * would otherwise hand every Local and Dev endpoint the same free pass.
 *
 * So the gate lives here, per route, keyed on the MODE rather than the path -
 * and it reads the SAME matrix the UI reads (`EXPOSURE_MODE_MIN_TIER` in
 * lib/subscription-access), so a panel that offers a scan and an API that
 * refuses it cannot come apart.
 *
 * `resolveEntitlement` reads the caller's own newest billing row under their
 * own token (RLS-scoped); a paid tier requires a real active subscription row,
 * and owner accounts resolve to Elite.
 */
async function enforceMode(
  mode: ExposureScanMode,
  req: AuthedRequest,
  res: Response,
  /** The token the request actually carried, verified or not. */
  suppliedToken: string | null,
): Promise<boolean> {
  if (EXPOSURE_MODE_MIN_TIER[mode] === 'none') return true;

  const token = req.token ?? null;
  const user = req.user ?? null;

  if (!token || !user) {
    /* A token that was sent but could not be verified is a DIFFERENT problem
       from no token at all. The caller has an expired or malformed session and
       needs to sign in again — telling them to buy a plan they may already own
       sends them to the wrong place entirely. */
    if (suppliedToken) {
      jsonError(res, 401, 'INVALID_TOKEN',
        'Your session has expired or is not valid. Sign in again to run this assessment.',
        { mode, reason: 'invalid-token' });
      return false;
    }

    const access = resolveExposureModeAccess(mode, 'none', false, false);
    jsonError(res, 401, 'AUTHENTICATION_REQUIRED', exposureModeDenialMessage(access), {
      mode,
      requiredTier: access.requiredTier,
      includedIn: access.includedIn,
      reason: access.reason,
    });
    return false;
  }

  let entitlement;
  try {
    entitlement = await resolveEntitlement(user.id, user.email, token);
  } catch {
    /* An infrastructure failure resolving billing must not silently grant a
       paid feature. The central gateway fails OPEN because locking a whole
       dashboard out on a transient Supabase error is worse than a brief
       over-grant; here the blast radius is one scan, so this fails CLOSED and
       says so rather than pretending the scan is impossible. */
    jsonError(res, 503, 'ENTITLEMENT_UNAVAILABLE',
      'Your subscription could not be verified right now, so this assessment was not started. Please retry in a moment.',
      { mode });
    return false;
  }

  const access = resolveExposureModeAccess(mode, entitlement.tier, entitlement.isActive, true);
  if (access.allowed) return true;

  jsonError(res, 403, 'SUBSCRIPTION_REQUIRED', exposureModeDenialMessage(access), {
    mode,
    requiredTier: access.requiredTier,
    currentTier: entitlement.tier,
    status: entitlement.status,
    includedIn: access.includedIn,
    reason: access.reason,
  });
  return false;
}

/**
 * Where a caller's access token may come from.
 *
 * `EventSource` cannot set request headers — there is no API for it — so a
 * browser subscribing to a live stream has nowhere to put a bearer token except
 * the URL. Every other authenticated stream on this platform already accepts
 * `?token=` for exactly that reason (see `tokenFromRequest` in
 * api-server/crypto-agility.ts and siblings).
 *
 * The widening is granted PER ROUTE and never router-wide. A token in a URL is
 * more exposed than one in a header — it can reach proxy logs, browser history
 * and `Referer` — so only the read-only event stream accepts one. Starting,
 * cancelling, syncing or reading a scan stays header-only.
 */
function tokenFromRequest(req: AuthedRequest, allowQueryToken: boolean): string | null {
  const headerToken = getToken(req);
  if (headerToken) return headerToken;
  if (!allowQueryToken) return null;

  const queryToken = req.query.token;
  if (typeof queryToken === 'string' && queryToken.length > 0) return queryToken;
  if (Array.isArray(queryToken) && typeof queryToken[0] === 'string' && queryToken[0].length > 0) {
    return queryToken[0];
  }
  return null;
}

/** Middleware form: authenticate, then require the mode's plan. */
function requireMode(mode: ExposureScanMode, options: { allowQueryToken?: boolean } = {}) {
  return async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const token = tokenFromRequest(req, options.allowQueryToken === true);
    if (token) {
      const user = await getServerUser(token);
      if (user) {
        req.user = user;
        req.token = token;
        req.client = createAuthClient(token) || getServiceClient();
      }
    }
    if (!(await enforceMode(mode, req, res, token))) return;
    next();
  };
}

/* ─────────────────────────────────────────────────────────── rate limiting ── */

const RATE_WINDOW_MS = 60_000;
const ANON_MAX_SCANS = 3;
const AUTH_MAX_SCANS = 20;
const MAX_TRACKED = 5_000;

const buckets = new Map<string, { count: number; windowStart: number }>();

function clientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim()) return real.trim();
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function checkRate(key: string, max: number): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  if (buckets.size > MAX_TRACKED) {
    for (const [candidate, entry] of buckets) {
      if (now - entry.windowStart > RATE_WINDOW_MS) buckets.delete(candidate);
    }
  }
  const entry = buckets.get(key);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    buckets.set(key, { count: 1, windowStart: now });
    return { allowed: true, retryAfter: 0 };
  }
  entry.count += 1;
  if (entry.count > max) {
    return { allowed: false, retryAfter: Math.ceil((RATE_WINDOW_MS - (now - entry.windowStart)) / 1000) };
  }
  return { allowed: true, retryAfter: 0 };
}

/* ───────────────────────────────────────────────── connection store (memory) ─ */

/**
 * Connections live in a process-scoped store keyed by user id.
 *
 * Persisting a cloud credential to the database would require an encryption-at-
 * rest design, a key-management decision and a migration — none of which this
 * change is the right place to make. An in-process store means a connection
 * survives for the life of the server process and no longer, and the UI says
 * so. That is a real constraint, stated, rather than a credential silently
 * written somewhere it should not be.
 */
const connectionStore = (() => {
  const global = globalThis as typeof globalThis & { __qguard_exposure_connections__?: Map<string, DevConnection> };
  if (!global.__qguard_exposure_connections__) global.__qguard_exposure_connections__ = new Map();
  return global.__qguard_exposure_connections__;
})();

function userConnections(userId: string): DevConnection[] {
  return [...connectionStore.values()].filter((connection) => connection.userId === userId);
}

function credentialsFor(userId: string, connectionIds: string[]): Partial<Record<EngineCredential['kind'], EngineCredential>> {
  const credentials: Partial<Record<EngineCredential['kind'], EngineCredential>> = {};
  for (const id of connectionIds) {
    const connection = connectionStore.get(id);
    if (!connection || connection.userId !== userId) continue;
    const credential = toEngineCredential(connection);
    if (credential) credentials[credential.kind] = credential;
  }
  return credentials;
}

/* ═══════════════════════════════════════════════════════ anonymous surfaces ═ */

/** Capability disclosure — what each mode does and does not do (§79). */
router.get('/capabilities', (_req, res) => {
  res.json({
    data: {
      name: 'QGuard Helix Exposure Assessment Engine',
      version: '1.0.0',
      modes: [
        {
          id: 'web',
          label: 'Web',
          description: 'Internet-facing exposure assessment.',
          authentication: 'none',
          requiredTier: EXPOSURE_MODE_MIN_TIER.web,
          includedIn: [],
          executedBy: 'public-scan edge pipeline',
          analyzed: [
            'TLS protocol, cipher and named key-agreement group negotiation',
            'Served X.509 certificate chain',
            'Certificate Transparency and OCSP metadata',
            'Public DNS records and CAA issuance policy',
            'HTTP transport-security headers',
          ],
          notAnalyzed: ['Source code', 'Internal PKI and key management', 'Cloud and cluster configuration'],
        },
        {
          id: 'local',
          label: 'Local',
          description: 'Local device, filesystem and codebase assessment.',
          authentication: 'Basic plan or higher',
          requiredTier: EXPOSURE_MODE_MIN_TIER.local,
          includedIn: plansIncluding('local'),
          executedBy: 'browser Web Worker on the user\'s own device',
          privacy:
            'Files are read through the browser\'s File System Access API after an explicit OS-level authorisation, and are analysed in a Web Worker in the same tab. No file content, secret value or Git object is transmitted to this platform at any point. Only a sanitised assessment can be synchronised, and only when an authenticated user explicitly chooses to.',
          analyzed: [
            'Cryptographic usage across 16 languages',
            'Credential and key material (values fingerprinted, never stored)',
            'Dependency manifests across nine ecosystems',
            'TLS, PKI, SSH and application configuration',
            'X.509 certificates and OpenSSH keys',
            'Dockerfiles, Compose, Kubernetes, Helm, Kustomize',
            'Terraform, CloudFormation, Bicep, ARM, Ansible',
            'CI/CD pipelines across eight platforms',
            'Repository references, remotes and loose Git objects',
          ],
          notAnalyzed: [
            'Packed Git history (packfile delta reconstruction is not implemented in the browser)',
            'Binary artefacts and compiled objects',
            'Runtime behaviour — this is static analysis only',
          ],
        },
        {
          id: 'dev',
          label: 'Dev',
          description: 'Repository, container, Kubernetes and cloud-native assessment.',
          authentication: 'Pro plan or higher',
          requiredTier: EXPOSURE_MODE_MIN_TIER.dev,
          includedIn: plansIncluding('dev'),
          executedBy: 'api-server',
          analyzed: [
            'Public and private repositories on GitHub, GitLab, Bitbucket, Azure DevOps and self-hosted Git',
            'Everything the Local content engines analyse, over the fetched repository',
            'Live Kubernetes clusters (read-only ServiceAccount)',
            'Container registries (OCI manifests and config blobs, read-only)',
            'AWS, Azure and Google Cloud (read-only, metadata first)',
            'Cross-layer supply-chain correlation',
          ],
          notAnalyzed: [
            'Repository branches other than the one selected',
            'Layer blob contents — image analysis reads manifests and config, not filesystem layers',
            'Any resource the supplied credential cannot read; those are reported as Not Assessed',
          ],
        },
      ],
      algorithms: knownAlgorithms(),
      /* §54, §85: the knowledge base is disclosed, not described. Every number
         is a `.length` on a real registry, so a reader can tell the difference
         between "we cover 40 algorithms" and "we say we do". */
      knowledgeBase: knowledgeBaseSummary(),
      limits: {
        anonymousScansPerMinute: ANON_MAX_SCANS,
        authenticatedScansPerMinute: AUTH_MAX_SCANS,
      },
      guarantees: [
        'Every finding carries evidence; a finding cannot be constructed without it.',
        'Severity and confidence are separate fields and are never collapsed.',
        'Detection method is published: observed, inferred, potential or unknown.',
        'A dimension that could not be read is reported as Not Assessed, never as a pass.',
        'Secret values are fingerprinted and discarded; they are never stored, transmitted or displayed.',
        'Scanning is read-only. No repository, cluster, cloud or registry is ever modified.',
        'No repository code is executed at any point.',
      ],
    },
  });
});

/**
 * What THIS caller may actually run, per mode.
 *
 * The panels could compute this from the local matrix and the subscription
 * hook, and for first paint they do. This endpoint exists so the answer the UI
 * shows is the same answer the API will give when the scan is submitted — a
 * stale client-side billing read that says "allowed" and a server that says 403
 * is a worse experience than a locked button, and it is the failure mode a
 * purely client-side gate produces.
 *
 * Anonymous callers get a valid answer rather than a 401: `web` allowed,
 * `local` and `dev` refused with `unauthenticated`. That is what lets the page
 * SHOW what the paid modes do without letting anyone run them.
 */
router.get('/entitlement', async (req: AuthedRequest, res) => {
  const token = getToken(req);
  const user = token ? await getServerUser(token) : null;

  let tier: AccessTier = 'none';
  let status: string | null = null;
  let isActive = false;
  let degraded = false;

  if (user && token) {
    try {
      const entitlement = await resolveEntitlement(user.id, user.email, token);
      tier = entitlement.tier;
      status = entitlement.status;
      isActive = entitlement.isActive;
    } catch {
      /* Billing could not be read. Report the caller as unentitled AND say the
         reading is degraded, so the UI can show "could not verify" rather than
         a confident "upgrade required" that may be wrong. */
      degraded = true;
    }
  }

  const modes: ExposureScanMode[] = ['web', 'local', 'dev'];
  res.json({
    data: {
      authenticated: Boolean(user),
      tier,
      status,
      isActive,
      degraded,
      modes: Object.fromEntries(
        modes.map((mode) => {
          const access = resolveExposureModeAccess(mode, tier, isActive, Boolean(user));
          return [mode, { ...access, message: exposureModeDenialMessage(access) }];
        }),
      ),
    },
  });
});

/** The engine registry with real health (§61, Spec-2 §47). */
router.get('/engines', (req, res) => {
  const mode = typeof req.query.mode === 'string' ? req.query.mode : null;
  const health = engineHealth();
  const healthById = new Map(health.map((entry) => [entry.id, entry]));

  const modes = mode === 'web' || mode === 'local' || mode === 'dev' ? [mode] : (['web', 'local', 'dev'] as const);
  const data = modes.map((current) => ({
    mode: current,
    profiles: profilesForMode(current).map((profile) => ({
      id: profile.id,
      label: profile.label,
      description: profile.description,
      engines: profile.engines,
      covers: profile.covers,
      minTier: profile.minTier ?? null,
    })),
    engines: descriptorsForMode(current).map((descriptor) => ({
      id: descriptor.id,
      label: descriptor.label,
      description: descriptor.description,
      capability: descriptor.capability,
      capabilityLabel: CAPABILITY_LABEL[descriptor.capability],
      layer: descriptor.layer,
      dependsOn: descriptor.dependsOn ?? [],
      privacySensitive: Boolean(descriptor.privacySensitive),
      minTier: descriptor.minTier ?? null,
      health: healthById.get(descriptor.id)?.state ?? 'unavailable',
      healthDetail: healthById.get(descriptor.id)?.detail ?? 'This engine is not present in the registry.',
      /* §85-§87: the version that will be stamped on this engine's findings, so
         a difference between two scans can be attributed to a rule change
         rather than to the estate having changed. */
      version: engineVersion(descriptor.id).version,
      ruleSetVersion: engineVersion(descriptor.id).ruleSetVersion,
    })),
  }));

  res.json({ data: mode ? data[0] : data });
});

/** Validate a repository reference before scanning (§19). */
router.post('/dev/validate', requireMode('dev'), async (req: AuthedRequest, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!url) return jsonError(res, 400, 'MISSING_TARGET', 'Enter a repository URL to validate.');
  if (url.length > 512) return jsonError(res, 400, 'TARGET_TOO_LONG', 'That repository reference is too long.');

  const limit = checkRate(`validate:${clientIp(req)}`, req.user ? 60 : 15);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfter));
    return jsonError(res, 429, 'RATE_LIMITED', `Too many validation requests. Try again in ${limit.retryAfter}s.`);
  }

  /* An anonymous caller never gets a token — not even the platform's own env
     token. Doing so would let an unauthenticated visitor read any private
     repository the deployment happens to have access to. */
  const token = req.user
    ? userConnections(req.user.id).find((connection) => connection.kind === 'git-provider')?.secret?.token ?? null
    : null;

  try {
    const result = await validateRepository(url, token);
    if (!req.user && result.visibility === 'private') {
      return res.json({
        data: {
          ok: false,
          providerLabel: result.providerLabel,
          notice: 'That repository is private.',
          recommendation: 'Sign in and connect the provider to assess a private repository.',
          requiresToken: true,
        },
      });
    }
    res.json({ data: result });
  } catch (error) {
    jsonError(res, 502, 'VALIDATION_FAILED', (error as Error).message);
  }
});

/** Propose a scan plan for a set of detected facets (Spec-2 §32). */
router.post('/plan', (req, res) => {
  const mode = req.body?.mode === 'dev' ? 'dev' : 'local';
  const facets: TargetFacet[] = Array.isArray(req.body?.facets)
    ? req.body.facets.filter((facet: unknown): facet is TargetFacet => typeof facet === 'string' && facet in FACET_LABEL)
    : [];
  res.json({ data: planScan(mode, new Set(facets)) });
});

/* ═════════════════════════════════════════════════════════════ dev scanning ═ */

/** Start a Dev assessment (§47). Returns immediately with a scan handle. */
router.post('/scans', requireMode('dev'), async (req: AuthedRequest, res) => {
  const body = req.body ?? {};
  const userId = req.user?.id ?? null;

  const limit = checkRate(userId ? `scan:${userId}` : `scan:${clientIp(req)}`, userId ? AUTH_MAX_SCANS : ANON_MAX_SCANS);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfter));
    return jsonError(res, 429, 'RATE_LIMITED', `Assessment rate limit reached. Try again in ${limit.retryAfter}s.`);
  }

  const profileId = typeof body.profileId === 'string' ? body.profileId : 'standard';
  const customEngines: string[] = Array.isArray(body.engines) ? body.engines.filter((id: unknown) => typeof id === 'string') : [];
  const connectionIds: string[] = Array.isArray(body.connectionIds) ? body.connectionIds.filter((id: unknown) => typeof id === 'string') : [];

  /* `requireMode('dev')` has already established that this caller holds an
     active Pro or Elite plan, so `userId` is non-null here by construction.
     The check remains because a null user would mean the middleware was
     removed or reordered, and a Dev scan must never run unattributed. */
  if (!userId) {
    return jsonError(res, 401, 'UNAUTHORIZED', 'Development assessment requires an authenticated account.');
  }

  const credentials = userId && connectionIds.length ? credentialsFor(userId, connectionIds) : {};

  /* A cluster or cloud target must name a verified connection; the endpoint and
     scope come from the CONNECTION RECORD, never from the request body, so a
     caller cannot point a stored credential at an endpoint of their choosing. */
  let cluster: { endpoint: string; namespaces: string[]; label: string } | undefined;
  let cloud: { provider: 'aws' | 'azure' | 'gcp'; account: string; regions: string[] } | undefined;

  if (userId && connectionIds.length) {
    for (const id of connectionIds) {
      const connection = connectionStore.get(id);
      if (!connection || connection.userId !== userId) continue;
      if (connection.kind === 'kubernetes') {
        const namespaces = Array.isArray(body.namespaces) && body.namespaces.length
          ? body.namespaces.filter((entry: unknown): entry is string => typeof entry === 'string' && (connection.scope.namespaces ?? []).includes(entry))
          : connection.scope.namespaces ?? [];
        cluster = { endpoint: connection.endpoint, namespaces, label: connection.label };
        // The engine reads the endpoint from the credential, so bind it there.
        const credential = credentials.kubeconfig;
        if (credential) credential.value = { ...credential.value, endpoint: connection.endpoint };
      }
      if (connection.kind === 'aws' || connection.kind === 'azure' || connection.kind === 'gcp') {
        const regions = Array.isArray(body.regions) && body.regions.length
          ? body.regions.filter((entry: unknown): entry is string => typeof entry === 'string' && (connection.scope.regions ?? []).includes(entry))
          : connection.scope.regions ?? [];
        cloud = { provider: connection.kind, account: connection.endpoint || connection.label, regions };
      }
    }
  }

  const handle = await startDevScan({
    userId,
    tenantId: userId,
    profileId,
    customEngines,
    repositoryUrl: typeof body.repositoryUrl === 'string' ? body.repositoryUrl : undefined,
    branch: typeof body.branch === 'string' ? body.branch : undefined,
    cluster,
    cloud,
    container: typeof body.image === 'string' ? { image: body.image } : undefined,
    credentials,
    exclusions: body.exclusions,
  });

  if (handle.error) return jsonError(res, 400, 'SCAN_NOT_STARTED', handle.error);

  console.info(`[exposure] dev scan ${handle.scanId} started (${profileId}, ${handle.engines.length} engines)`);
  res.status(202).json({ data: handle });
});

/** Poll a scan. */
router.get('/scans/:scanId', requireMode('dev'), (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user?.id ?? null);
  if (!job) return jsonError(res, 404, 'NOT_FOUND', 'No such assessment.');
  res.json({
    data: {
      scanId: job.scanId,
      status: job.status,
      target: job.target,
      profileId: job.profileId,
      error: job.error,
      assessment: job.assessment,
    },
  });
});

/** Cancel a running scan. */
router.post('/scans/:scanId/cancel', requireMode('dev'), (req: AuthedRequest, res) => {
  const cancelled = cancelJob(req.params.scanId, req.user?.id ?? null);
  if (!cancelled) return jsonError(res, 404, 'NOT_FOUND', 'No such assessment.');
  res.json({ data: { scanId: req.params.scanId, cancelled: true } });
});

/**
 * Live event stream (§34).
 *
 * The ONE route that accepts `?token=`: its only client is `EventSource`, which
 * cannot send an Authorization header. Without this the subscription always
 * arrived anonymous, was refused 401, and the browser — which treats a non-2xx
 * on an event stream as fatal rather than retryable — reported the stream as
 * lost while the scan ran on happily behind it.
 */
router.get('/scans/:scanId/events', requireMode('dev', { allowQueryToken: true }), (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user?.id ?? null);
  if (!job) return jsonError(res, 404, 'NOT_FOUND', 'No such assessment.');

  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  let closed = false;
  const send = (event: { event: string; [key: string]: unknown }) => {
    if (closed) return;
    res.write(`event: ${event.event}\ndata: ${JSON.stringify(event)}\n\n`);
  };

  /* Replay whatever already happened, so a subscriber that connects after the
     scan started still renders a complete ledger rather than joining midway. */
  for (const event of job.events) send(event as unknown as { event: string });

  const unsubscribe = subscribe(job, (event) => {
    send(event as unknown as { event: string });
    if (event.event === 'scan.completed' || event.event === 'scan.cancelled' || event.event === 'scan.failed') {
      cleanup();
    }
  });

  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n');
  }, 15_000);

  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  };

  req.on('close', cleanup);

  // A job that finished before this subscriber arrived closes immediately.
  if (job.assessment || job.status === 'failed' || job.status === 'cancelled') cleanup();
});

/** Findings, filterable (§51). */
router.get('/scans/:scanId/findings', requireMode('dev'), (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user?.id ?? null);
  if (!job) return jsonError(res, 404, 'NOT_FOUND', 'No such assessment.');
  if (!job.assessment) return jsonError(res, 409, 'NOT_READY', 'The assessment has not completed.');

  const severity = typeof req.query.severity === 'string' ? req.query.severity.split(',') : null;
  const engineId = typeof req.query.engine === 'string' ? req.query.engine : null;
  const quantum = typeof req.query.quantum === 'string' ? req.query.quantum.split(',') : null;

  const findings = job.assessment.findings.filter((finding) => {
    if (severity && !severity.includes(finding.severity)) return false;
    if (engineId && finding.engineId !== engineId) return false;
    if (quantum && !quantum.includes(finding.quantumStatus)) return false;
    return true;
  });

  res.json({ data: { total: job.assessment.findings.length, returned: findings.length, findings } });
});

/** The correlated exposures (§39). */
router.get('/scans/:scanId/exposures', requireMode('dev'), (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user?.id ?? null);
  if (!job?.assessment) return jsonError(res, 404, 'NOT_FOUND', 'No completed assessment with that id.');
  res.json({ data: job.assessment.exposures });
});

/** CBOM export (§11, §56). */
router.get('/scans/:scanId/cbom', requireMode('dev'), (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user?.id ?? null);
  if (!job?.assessment) return jsonError(res, 404, 'NOT_FOUND', 'No completed assessment with that id.');

  const format = typeof req.query.format === 'string' ? req.query.format.toLowerCase() : 'json';
  const meta = {
    scanId: job.scanId,
    target: describeTarget(job.assessment),
    generatedAt: job.assessment.generatedAt,
  };
  const slug = meta.target.replace(/[^a-z0-9.-]/gi, '_').slice(0, 60);

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="qguard-cbom-${slug}.csv"`);
    return res.send(cbomToCsv(job.assessment.cbom));
  }
  if (format === 'cyclonedx') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="qguard-cbom-${slug}.cdx.json"`);
    return res.send(cbomToCycloneDx(job.assessment.cbom, meta));
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(cbomToJson(job.assessment.cbom, meta));
});

/** Scan history for the authenticated tenant (§54). */
router.get('/scans', requireMode('dev'), (req: AuthedRequest, res) => {
  const jobs = listJobs(req.user!.id).map((job) => ({
    scanId: job.scanId,
    status: job.status,
    target: job.target,
    profileId: job.profileId,
    startedAt: new Date(job.createdAt).toISOString(),
    findings: job.assessment?.findings.length ?? 0,
    quantumVulnerable: job.assessment?.intelligence.quantum.vulnerable ?? 0,
    scores: job.assessment?.task.scores ?? null,
  }));
  res.json({ data: jobs });
});

/* ═══════════════════════════════════════════════════════════════ connections ═ */

/** The permission disclosure the UI shows BEFORE a connect (§44). */
router.get('/dev/connection-requirements', (_req, res) => {
  res.json({
    data: Object.entries(REQUIRED_PERMISSIONS).map(([kind, permissions]) => ({
      kind,
      label: CONNECTION_LABEL[kind as ConnectionKind],
      permissions,
      readOnly: true,
      note: 'QGuard Helix never requests a write permission for assessment, and never modifies a connected resource.',
    })),
  });
});

router.get('/dev/connections', requireMode('dev'), (req: AuthedRequest, res) => {
  res.json({
    data: {
      connections: userConnections(req.user!.id).map(toPublicConnection),
      /* Stated plainly rather than discovered when the process restarts. */
      persistence:
        'Connections are held for the lifetime of the API server process. Credentials are never written to the database and are never returned to the browser.',
    },
  });
});

router.post('/dev/connections', requireMode('dev'), async (req: AuthedRequest, res) => {
  const body = req.body ?? {};
  const input = {
    kind: body.kind as ConnectionKind,
    label: typeof body.label === 'string' ? body.label.trim() : '',
    endpoint: typeof body.endpoint === 'string' ? body.endpoint.trim() : '',
    secret: (body.secret ?? {}) as Record<string, string>,
    scope: body.scope ?? {},
  };

  const validation = validateConnectionInput(input);
  if (!validation.ok) return jsonError(res, 400, 'INVALID_CONNECTION', validation.error ?? 'The connection details are not valid.');

  const connection: DevConnection = {
    id: randomUUID(),
    userId: req.user!.id,
    kind: input.kind,
    label: input.label,
    endpoint: input.endpoint,
    scope: input.scope,
    secret: input.secret,
    createdAt: new Date().toISOString(),
    lastVerifiedAt: null,
    status: 'unverified',
    statusDetail: 'Not yet verified.',
    grantedPermissions: [],
    deniedPermissions: [],
  };

  /* Verify immediately with a real probe (§9, §61). A connection that cannot be
     verified is stored as `unauthorized`/`unreachable` rather than as connected,
     so the UI can never show a green dot the backend did not earn. */
  try {
    await verifyConnection(connection);
  } catch (error) {
    connection.status = 'unreachable';
    connection.statusDetail = (error as Error).message;
  }

  connectionStore.set(connection.id, connection);
  console.info(`[exposure] connection ${connection.kind} registered for user (status ${connection.status})`);
  res.status(201).json({ data: toPublicConnection(connection) });
});

router.post('/dev/connections/:id/verify', requireMode('dev'), async (req: AuthedRequest, res) => {
  const connection = connectionStore.get(req.params.id);
  if (!connection || connection.userId !== req.user!.id) return jsonError(res, 404, 'NOT_FOUND', 'No such connection.');
  try {
    await verifyConnection(connection);
  } catch (error) {
    connection.status = 'unreachable';
    connection.statusDetail = (error as Error).message;
  }
  res.json({ data: toPublicConnection(connection) });
});

router.delete('/dev/connections/:id', requireMode('dev'), (req: AuthedRequest, res) => {
  const connection = connectionStore.get(req.params.id);
  if (!connection || connection.userId !== req.user!.id) return jsonError(res, 404, 'NOT_FOUND', 'No such connection.');
  connectionStore.delete(req.params.id);
  res.json({ data: { id: req.params.id, deleted: true } });
});

async function verifyConnection(connection: DevConnection): Promise<void> {
  connection.lastVerifiedAt = new Date().toISOString();

  switch (connection.kind) {
    case 'kubernetes': {
      const probe = await probeCluster({
        endpoint: connection.endpoint,
        token: connection.secret.token ?? '',
        insecure: false,
      });
      connection.status = probe.reachable ? (probe.denied.length ? 'degraded' : 'connected') : 'unreachable';
      connection.statusDetail = probe.detail;
      connection.grantedPermissions = probe.granted;
      connection.deniedPermissions = probe.denied;
      if (probe.namespaces.length && !connection.scope.namespaces?.length) {
        // Discovered, not auto-selected: the operator still chooses the scope.
        connection.scope = { ...connection.scope, namespaces: [] };
        (connection as DevConnection & { availableNamespaces?: string[] }).availableNamespaces = probe.namespaces;
      }
      break;
    }
    case 'aws': {
      const identity = await getCallerIdentity({
        accessKeyId: connection.secret.accessKeyId,
        secretAccessKey: connection.secret.secretAccessKey,
        sessionToken: connection.secret.sessionToken,
      });
      connection.status = identity.ok ? 'connected' : identity.denied ? 'unauthorized' : 'unreachable';
      connection.statusDetail = identity.ok
        ? `Connected read-only as ${identity.data?.arn}. Account ${identity.data?.account}.`
        : identity.reason ?? 'The AWS credential could not be verified.';
      if (identity.ok && identity.data) {
        connection.endpoint = identity.data.account;
        connection.grantedPermissions = ['sts:GetCallerIdentity'];
      }
      break;
    }
    case 'azure': {
      const probe = await probeAzure({
        tenantId: connection.secret.tenantId,
        clientId: connection.secret.clientId,
        clientSecret: connection.secret.clientSecret,
        subscriptionId: connection.secret.subscriptionId,
      });
      connection.status = probe.reachable ? (probe.denied.length ? 'degraded' : 'connected') : 'unreachable';
      connection.statusDetail = probe.detail;
      connection.grantedPermissions = probe.granted;
      connection.deniedPermissions = probe.denied;
      connection.endpoint = connection.secret.subscriptionId;
      break;
    }
    case 'gcp': {
      const probe = await probeGcp({ serviceAccountJson: connection.secret.serviceAccountJson, projectId: connection.secret.projectId });
      connection.status = probe.reachable ? (probe.denied.length ? 'degraded' : 'connected') : 'unreachable';
      connection.statusDetail = probe.detail;
      connection.grantedPermissions = probe.granted;
      connection.deniedPermissions = probe.denied;
      connection.endpoint = probe.projectId ?? connection.endpoint;
      break;
    }
    case 'registry':
    case 'git-provider': {
      /* No standalone probe: the first scan is the verification, and inventing
         a synthetic "connected" state before any real call would be exactly the
         claim §61 forbids. */
      connection.status = 'unverified';
      connection.statusDetail = 'Credentials stored. Access is verified on the first assessment that uses this connection.';
      break;
    }
    default:
      connection.status = 'unverified';
      connection.statusDetail = 'This connection type has no verification probe.';
  }
}

/* ═════════════════════════════════════════════════════════ local mode sync ══ */

/**
 * Persist a Local assessment into the tenant's inventory (§73, §53).
 *
 * The body is an assessment the BROWSER produced. It is therefore untrusted
 * input, and `persistExposureAssessment` re-derives everything it writes from
 * the finding fields rather than trusting any summary the client computed.
 * Nothing with a secret VALUE can arrive here, because the finding model has no
 * field that carries one.
 */
router.post('/local/sync', requireMode('local'), async (req: AuthedRequest, res) => {
  const assessment = req.body?.assessment as ExposureAssessment | undefined;
  if (!assessment || assessment.schemaVersion !== 1 || !Array.isArray(assessment.findings)) {
    return jsonError(res, 400, 'INVALID_ASSESSMENT', 'The assessment payload is missing or is not a version 1 document.');
  }
  if (assessment.findings.length > 5_000) {
    return jsonError(res, 413, 'ASSESSMENT_TOO_LARGE', 'The assessment carries more findings than the sync endpoint accepts. Narrow the scan scope or the profile.');
  }

  try {
    const result = await persistExposureAssessment({
      assessment,
      userId: req.user!.id,
      client: req.client ?? null,
      source: 'local',
    });
    /* The History stream lives in this process. Telling it now is what makes a
       just-recorded assessment appear in the tab without a reload. */
    if (!result.degraded) notifyHistoryChanged(req.user!.id);
    res.json({ data: result });
  } catch (error) {
    jsonError(res, 500, 'SYNC_FAILED', (error as Error).message);
  }
});

/** Persist a completed Dev assessment. */
router.post('/scans/:scanId/sync', requireMode('dev'), async (req: AuthedRequest, res) => {
  const job = getJob(req.params.scanId, req.user!.id);
  if (!job?.assessment) return jsonError(res, 404, 'NOT_FOUND', 'No completed assessment with that id.');
  try {
    const result = await persistExposureAssessment({
      assessment: job.assessment,
      userId: req.user!.id,
      client: req.client ?? null,
      source: 'dev',
    });
    if (!result.degraded) notifyHistoryChanged(req.user!.id);
    res.json({ data: result });
  } catch (error) {
    jsonError(res, 500, 'SYNC_FAILED', (error as Error).message);
  }
});

/* ═══════════════════════════════════════════════════════════════════ history ═ */

/**
 * The History surface for the Local and Dev assessment modes.
 *
 * `/dashboard/scanner?mode=local` and `?mode=dev` each gain a History tab that
 * reads these four routes. Everything they return comes from the tenant's own
 * recorded rows — sessions, findings and cryptographic components — so a scan
 * reviewed later reports exactly what it reported when it ran.
 *
 * The mode arrives as a query parameter rather than being baked into the path
 * because the entitlement differs between them (Local is BASIC, Dev is PRO) and
 * must be enforced per request. `requireHistoryMode` resolves it and then hands
 * off to the same `requireMode` gate every other route on this router uses, so
 * there is exactly one place where exposure entitlement is decided.
 */
function requireHistoryMode(options: { allowQueryToken?: boolean } = {}) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const requested = typeof req.query.mode === 'string' ? req.query.mode : '';
    if (requested !== 'local' && requested !== 'dev') {
      return jsonError(res, 400, 'BAD_REQUEST', "A mode of 'local' or 'dev' is required.");
    }
    (req as AuthedRequest & { historyMode?: ExposureHistoryMode }).historyMode = requested;
    return requireMode(requested, options)(req, res, next);
  };
}

function historyModeOf(req: AuthedRequest): ExposureHistoryMode {
  return (req as AuthedRequest & { historyMode?: ExposureHistoryMode }).historyMode ?? 'local';
}

/**
 * Report a history failure as a failure.
 *
 * A read that could not run must never reach the browser as an empty list: an
 * empty History tab has to mean "nothing recorded", and the moment it can also
 * mean "the query failed" the tab stops being evidence of anything.
 */
function historyError(res: Response, error: unknown) {
  if (error instanceof HistoryQueryError) {
    return jsonError(res, 502, 'HISTORY_QUERY_FAILED', error.message, { table: error.table });
  }
  return jsonError(res, 500, 'HISTORY_FAILED', (error as Error).message ?? 'The assessment history could not be read.');
}

/**
 * Live history for the tenant.
 *
 * Declared BEFORE `/history/:scanId` so the literal path is not captured as a
 * scan id — Express matches in registration order.
 */
router.get('/history/stream', requireHistoryMode({ allowQueryToken: true }), (req: AuthedRequest, res) => {
  const mode = historyModeOf(req);
  const userId = req.user!.id;
  const client = req.client;
  if (!client) return jsonError(res, 503, 'NO_DATABASE', 'No database client is available for this session.');

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  let closed = false;
  let lastFingerprint: string | null = null;
  let liveRunning = false;
  let timer: NodeJS.Timeout | null = null;
  let emitting = false;

  const send = (event: string, data: unknown) => {
    if (closed) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const emit = async (force: boolean) => {
    /* Overlapping ticks would queue database work behind a slow read and then
       deliver it out of order. One emit at a time, always. */
    if (closed || emitting) return;
    emitting = true;
    try {
      const payload = await loadExposureHistory(client, userId, mode, { fresh: force });
      liveRunning = payload.entries.some((entry) => entry.live?.running === true);
      const fingerprint = historyFingerprint(payload.entries);
      if (force || fingerprint !== lastFingerprint) {
        lastFingerprint = fingerprint;
        send('exposure-history', payload);
      }
    } catch (error) {
      send('exposure-history-error', {
        message: error instanceof Error ? error.message : 'The assessment history could not be read.',
      });
    } finally {
      emitting = false;
    }
  };

  /* The cadence follows the work: a running Dev assessment moves, a recorded
     history does not. Polling a settled history every three seconds would cost
     every open dashboard a query for nothing, and a recorded assessment already
     arrives instantly through the change signal below. */
  const schedule = () => {
    if (closed) return;
    timer = setTimeout(() => {
      void emit(false).then(schedule);
    }, liveRunning ? 3_000 : 15_000);
  };

  const unsubscribe = onHistoryChanged((changedUserId) => {
    if (changedUserId !== userId) return;
    void emit(true);
  });

  const heartbeat = setInterval(() => {
    if (!closed) res.write(': heartbeat\n\n');
  }, 25_000);

  void emit(true).then(schedule);

  req.on('close', () => {
    closed = true;
    unsubscribe();
    clearInterval(heartbeat);
    if (timer) clearTimeout(timer);
  });
});

/** The recorded assessments for this tenant and mode. */
router.get('/history', requireHistoryMode(), async (req: AuthedRequest, res) => {
  const client = req.client;
  if (!client) return jsonError(res, 503, 'NO_DATABASE', 'No database client is available for this session.');
  try {
    const payload = await loadExposureHistory(client, req.user!.id, historyModeOf(req));
    res.json({ data: payload });
  } catch (error) {
    historyError(res, error);
  }
});

/** One recorded assessment, rebuilt in full from its own rows. */
router.get('/history/:scanId', requireHistoryMode(), async (req: AuthedRequest, res) => {
  const client = req.client;
  if (!client) return jsonError(res, 503, 'NO_DATABASE', 'No database client is available for this session.');
  const scanId = String(req.params.scanId || '').trim();
  if (!scanId) return jsonError(res, 400, 'BAD_REQUEST', 'A scan id is required.');

  try {
    const detail = await loadExposureHistoryDetail(client, req.user!.id, historyModeOf(req), scanId);
    if (!detail) return jsonError(res, 404, 'NOT_FOUND', 'No recorded assessment with that id.');
    res.json({ data: detail });
  } catch (error) {
    historyError(res, error);
  }
});

/**
 * Delete one recorded assessment and everything it wrote.
 *
 * This removes real inventory: the findings, the cryptographic components and
 * the quantum exposures that assessment contributed stop being counted by every
 * dashboard that reads them. That is the intent — a superseded assessment must
 * not keep inflating the estate — and it is why the route is scoped to the
 * caller's own tenant and to this mode's own records on every statement.
 */
router.delete('/history/:scanId', requireHistoryMode(), async (req: AuthedRequest, res) => {
  const client = req.client;
  if (!client) return jsonError(res, 503, 'NO_DATABASE', 'No database client is available for this session.');
  const scanId = String(req.params.scanId || '').trim();
  if (!scanId) return jsonError(res, 400, 'BAD_REQUEST', 'A scan id is required.');

  try {
    const removed = await deleteExposureHistoryEntry(client, req.user!.id, historyModeOf(req), scanId);
    if (!removed) return jsonError(res, 404, 'NOT_FOUND', 'No recorded assessment with that id.');
    res.json({ data: removed });
  } catch (error) {
    historyError(res, error);
  }
});

/* ───────────────────────────────────────────────────────────────── helpers ── */

function describeTarget(assessment: ExposureAssessment): string {
  const target = assessment.task.target;
  switch (target.kind) {
    case 'repository': return `${target.owner}/${target.repo}`;
    case 'local': return target.rootName;
    case 'kubernetes': return target.cluster;
    case 'cloud': return `${target.provider}:${target.account}`;
    case 'container': return target.image;
    case 'web': return target.host;
    default: return 'assessment';
  }
}

export default router;
