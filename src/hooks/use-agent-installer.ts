import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import {
  AGENT_ROLES,
  CAPABILITY_LABELS,
  type AgentCommand,
  type AgentPlatform,
  type AgentRole,
  type ConnectionState,
} from '@/lib/agent-installer/agent-release';

/**
 * useAgentInstaller — data layer for the Qguard Helix Agent Center (/downloads).
 *
 * Owns the deployment side of an agent's life: what is published, generating a
 * real installer artifact, queueing work, and watching the agent come online.
 * Agent identity/policy CRUD stays with the existing /api/v1/agent-scanner
 * contract (and `useAgentCollector`), so there is exactly one enrollment path.
 *
 * Realtime (spec §28): a manually supervised EventSource with exponential
 * backoff, Last-Event-ID recovery and per-event de-duplication. `streamState`
 * reports what the connection is ACTUALLY doing — the UI never shows
 * "Connected" because a request once succeeded.
 */

const INSTALLER_API = '/api/v1/agent-installer';
const SCANNER_API = '/api/v1/agent-scanner';

export type StreamState = 'connecting' | 'connected' | 'reconnecting' | 'offline';

export type DeployedAgent = {
  id: string;
  name: string;
  status: string;
  hostname?: string | null;
  platform?: string | null;
  version?: string | null;
  capabilities?: Record<string, boolean>;
  policy?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  last_seen_at?: string | null;
  revoked_at?: string | null;
  created_at?: string;
  updated_at?: string;
  connectionState: ConnectionState;
  role: AgentRole;
  environment?: string | null;
  assignedAssetId?: string | null;
  assignedAssetName?: string | null;
  upgradeAvailable: boolean;
  pendingCommands: number;
  currentTask: string | null;
};

export type DeploymentSummary = {
  total: number;
  connected: number;
  connecting: number;
  waiting: number;
  offline: number;
  error: number;
  revoked: number;
  scanning: number;
  updatesAvailable: number;
  activeJobs: number;
};

export type RuntimeRelease = {
  version: string;
  channel: string;
  filename: string;
  bytes: number;
  sha256: string;
  sha3_256: string;
  builtAt: string;
  requiresNode: string;
  available: boolean;
  reason?: string;
};

export type PlatformInfo = {
  id: AgentPlatform;
  label: string;
  filename: string;
  language: string;
  architectures: string[];
  service: string;
  privileges: string;
  prerequisites: string[];
  quickCommand: string;
};

export type RoleInfo = {
  id: AgentRole;
  label: string;
  tagline: string;
  modules: string[];
  scanTypes: string[];
  capabilities: Record<string, boolean>;
  mutatesTargets: boolean;
  authority: string;
};

export type GeneratedPackage = {
  agentId: string;
  agentName: string;
  platform: AgentPlatform;
  role: AgentRole;
  filename: string;
  contentType: string;
  language: string;
  content: string;
  installerSha256: string;
  runtime: {
    version: string;
    sha256: string;
    sha3_256: string;
    bytes: number;
    builtAt: string;
    requiresNode: string;
  };
  instructions: {
    runCommand: string;
    privileges: string;
    prerequisites: string[];
    service: string;
    architectures: string[];
    quickCommand: string;
    label: string;
  };
};

export type AgentActivityEntry = {
  id: string;
  at: string;
  status: string;
  phase: string | null;
  stage: string | null;
  progress: number | null;
  message: string | null;
  evidenceCount: number | null;
};

export type AgentHealth = {
  agentId: string;
  connectionState: ConnectionState;
  lastSeenAt: string | null;
  installedVersion: string | null;
  latestVersion: string | null;
  upgradeAvailable: boolean;
  host: Record<string, unknown> | null;
  memory: Record<string, unknown> | null;
  process: Record<string, unknown> | null;
  counters: Record<string, unknown> | null;
  capabilities: Record<string, unknown> | null;
  telemetryAvailable: boolean;
  heartbeats: Array<{ id: string; status: string; observedAt: string; phase: string | null }>;
};

export type AgentEvidenceRow = {
  id: string;
  evidence_type?: string | null;
  asset_name?: string | null;
  asset_type?: string | null;
  target?: string | null;
  host?: string | null;
  port?: number | null;
  protocol?: string | null;
  observed_algorithm?: string | null;
  key_size?: number | null;
  certificate_fingerprint?: string | null;
  file_path?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  confidence?: string | null;
  raw_evidence?: Record<string, unknown> | null;
  observed_at?: string | null;
  created_at?: string | null;
};

export type AgentFindings = {
  /** false => the agent has produced no evidence. Render "Not Yet Assessed", never "0 findings". */
  scanned: boolean;
  evidence: AgentEvidenceRow[];
  alerts: Array<{
    id: string;
    severity?: string | null;
    category?: string | null;
    title?: string | null;
    message?: string | null;
    recommendation?: string | null;
    status?: string | null;
    created_at?: string | null;
  }>;
  collectorVersion: string | null;
  agentId: string;
};

export type AgentScanRecord = {
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  evidenceCount: number | null;
  runtimeEventCount?: number | null;
  remediationJobs?: number | null;
  status: string;
};

export type CreateAgentInput = {
  name: string;
  role: AgentRole;
  environment: string;
  description?: string;
  assetId?: string | null;
  assetName?: string | null;
  allowedTargets: string[];
  allowedPaths: string[];
  scanTypes: string[];
  intervalSeconds: number;
  alertThreshold: string;
  /** Explicit operator authorisation for a role that can change configuration. */
  remediationAuthorized: boolean;
  migrationAuthorized: boolean;
};

export type OneTimeToken = { agentId: string; token: string; createdAt: string; mode: 'created' | 'rotated' } | null;

/** An asset this tenant owns, with the agents already covering it. */
export type TenantAsset = {
  id: string;
  name: string;
  type?: string | null;
  environment?: string | null;
  criticality?: string | null;
  status?: string | null;
  ip_address?: string | null;
  service_owner?: string | null;
  updated_at?: string | null;
  agents: Array<{ id: string; name: string; connectionState: ConnectionState }>;
};

export type ActionResult<T = void> = { ok: boolean; message?: string; data?: T };

export type LiveScanProgress = {
  agentId: string;
  stage: string;
  progress: number;
  message: string;
  at: string;
};

const MAX_BACKOFF_MS = 30_000;

export function useAgentInstaller(enabled: boolean) {
  const { session } = useAuth();
  const token = session?.access_token;
  const tenantId = session?.user?.id || '';

  const [agents, setAgents] = useState<DeployedAgent[]>([]);
  const [summary, setSummary] = useState<DeploymentSummary | null>(null);
  const [release, setRelease] = useState<RuntimeRelease | null>(null);
  const [platforms, setPlatforms] = useState<PlatformInfo[]>([]);
  const [roles, setRoles] = useState<RoleInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [streamState, setStreamState] = useState<StreamState>('offline');
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);
  const [oneTimeToken, setOneTimeToken] = useState<OneTimeToken>(null);
  const [scanProgress, setScanProgress] = useState<Record<string, LiveScanProgress>>({});
  const [assets, setAssets] = useState<TenantAsset[]>([]);
  const [unassignedAgents, setUnassignedAgents] = useState<Array<{ id: string; name: string }>>([]);

  const didLoad = useRef(false);
  const seenEventIds = useRef<Set<string>>(new Set());
  const lastEventId = useRef<string>('');
  const backoff = useRef(1000);
  const sourceRef = useRef<EventSource | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const authHeaders = useCallback(() => (token ? { Authorization: `Bearer ${token}` } : null), [token]);

  /* ---------------- REST ---------------- */

  const loadSummary = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    try {
      const res = await fetch(`${INSTALLER_API}/summary`, { headers });
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error?.message || 'Unable to load deployed agents');
      setAgents(json?.data?.agents || []);
      setSummary(json?.data?.summary || null);
      setRelease(json?.data?.release || null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent deployment load failed');
    }
  }, [authHeaders]);

  const loadCatalog = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    try {
      const res = await fetch(`${INSTALLER_API}/releases`, { headers });
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error?.message || 'Unable to load agent releases');
      setRelease(json?.data?.current || null);
      setPlatforms(json?.data?.platforms || []);
      setRoles(json?.data?.roles || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release catalog load failed');
    }
  }, [authHeaders]);

  /** The tenant's own assets — the only things an agent may be bound to. */
  const loadAssets = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    try {
      const res = await fetch(`${INSTALLER_API}/assets`, { headers });
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error?.message || 'Unable to load assets');
      setAssets(json?.data?.assets || []);
      setUnassignedAgents(json?.data?.unassignedAgents || []);
    } catch (err) {
      // A missing asset inventory must not block deployment — the picker simply
      // shows its empty state and the agent is created unbound.
      setAssets([]);
      setUnassignedAgents([]);
      void err;
    }
  }, [authHeaders]);

  const refresh = useCallback(async () => {
    if (!didLoad.current) setLoading(true);
    await Promise.all([loadSummary(), loadCatalog(), loadAssets()]);
    didLoad.current = true;
    setLoading(false);
  }, [loadSummary, loadCatalog, loadAssets]);

  useEffect(() => {
    if (!enabled || !token) return;
    void refresh();
  }, [enabled, token, refresh]);

  /** Coalesce the refresh burst a chatty scan produces into one reload. */
  const scheduleRefresh = useCallback(() => {
    if (refreshTimer.current) return;
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null;
      void loadSummary();
    }, 1200);
  }, [loadSummary]);

  /* ---------------- SSE ---------------- */

  useEffect(() => {
    if (!enabled || !token) {
      setStreamState('offline');
      return;
    }

    let disposed = false;

    const connect = () => {
      if (disposed) return;
      setStreamState((prev) => (prev === 'connected' ? 'reconnecting' : prev === 'offline' ? 'connecting' : prev));

      const url = new URL(`${INSTALLER_API}/events/stream`, window.location.origin);
      url.searchParams.set('token', token);
      // EventSource cannot set headers, so the resume cursor rides the query string.
      if (lastEventId.current) url.searchParams.set('lastEventId', lastEventId.current);

      const source = new EventSource(url.toString());
      sourceRef.current = source;

      source.addEventListener('stream.ready', () => {
        if (disposed) return;
        backoff.current = 1000;
        setStreamState('connected');
      });

      source.addEventListener('stream.heartbeat', () => {
        if (!disposed) setStreamState('connected');
      });

      const handle = (name: string) => (message: Event) => {
        if (disposed) return;
        const event = message as MessageEvent;
        // De-duplicate: a replayed window after reconnect can resend ids we saw.
        if (event.lastEventId) {
          if (seenEventIds.current.has(event.lastEventId)) return;
          seenEventIds.current.add(event.lastEventId);
          if (seenEventIds.current.size > 2000) {
            seenEventIds.current = new Set([...seenEventIds.current].slice(-1000));
          }
          lastEventId.current = event.lastEventId;
        }

        let payload: Record<string, unknown> = {};
        try {
          payload = JSON.parse(event.data || '{}');
        } catch {
          return;
        }

        setLastEventAt(String(payload.at || new Date().toISOString()));

        if (name === 'agent.scan_progress' || name === 'agent.scan_completed') {
          const agentId = String(payload.agentId || '');
          if (agentId) {
            setScanProgress((prev) => ({
              ...prev,
              [agentId]: {
                agentId,
                stage: String(payload.stage || (name === 'agent.scan_completed' ? 'scan_complete' : 'running')),
                progress: typeof payload.progress === 'number' ? payload.progress : name === 'agent.scan_completed' ? 100 : 0,
                message: String(payload.message || ''),
                at: String(payload.at || new Date().toISOString()),
              },
            }));
          }
        }

        scheduleRefresh();
      };

      for (const name of [
        'agent.created',
        'agent.installation_started',
        'agent.enrollment_started',
        'agent.enrolled',
        'agent.connected',
        'agent.disconnected',
        'agent.heartbeat',
        'agent.scan_started',
        'agent.scan_progress',
        'agent.scan_completed',
        'agent.finding_detected',
        'agent.migration_started',
        'agent.migration_progress',
        'agent.migration_completed',
        'agent.upgrade_available',
        'agent.upgrade_started',
        'agent.upgrade_completed',
        'agent.error',
      ]) {
        source.addEventListener(name, handle(name));
      }

      source.onerror = () => {
        if (disposed) return;
        source.close();
        sourceRef.current = null;
        setStreamState('reconnecting');
        const delay = Math.min(backoff.current, MAX_BACKOFF_MS);
        backoff.current = Math.min(backoff.current * 2, MAX_BACKOFF_MS);
        reconnectTimer.current = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
      sourceRef.current?.close();
      sourceRef.current = null;
      setStreamState('offline');
    };
  }, [enabled, token, scheduleRefresh]);

  /* ---------------- Actions ---------------- */

  const call = useCallback(
    async <T,>(url: string, init: RequestInit = {}): Promise<ActionResult<T>> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in to manage agents.' };
      setBusy(true);
      try {
        const res = await fetch(url, {
          ...init,
          headers: { ...headers, 'Content-Type': 'application/json', ...(init.headers || {}) },
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(json?.error?.message || `Request failed (${res.status})`);
        return { ok: true, data: json?.data as T };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Request failed';
        setError(message);
        return { ok: false, message };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders],
  );

  /**
   * Creates the agent through the existing enrollment endpoint so tokens, policy
   * rows, audit events and security events all follow the one established path.
   */
  const createAgent = useCallback(
    async (input: CreateAgentInput): Promise<ActionResult<{ agentId: string; token: string }>> => {
      const definition = AGENT_ROLES.find((role) => role.id === input.role) || AGENT_ROLES[0];
      const capabilities: Record<string, boolean> = { ...definition.capabilities };
      // A role that CAN mutate still only does so when the operator said yes.
      if (!input.remediationAuthorized) {
        capabilities.remediation = false;
        capabilities.config_patches = false;
      }
      if (!input.migrationAuthorized) capabilities.migration = false;

      const result = await call<{ agent: { id: string }; enrollment: { agentId: string; agentToken: string } }>(
        `${SCANNER_API}/agents/enroll`,
        {
          method: 'POST',
          body: JSON.stringify({
            name: input.name,
            environment: input.environment,
            hostname: 'pending-customer-install',
            platform: 'customer-managed',
            version: release?.version || '0.1.0',
            capabilities,
            policy: {
              enabled: true,
              intervalSeconds: input.intervalSeconds,
              allowedTargets: input.allowedTargets,
              allowedPaths: input.allowedPaths,
              scanTypes: input.scanTypes,
              alertThreshold: input.alertThreshold,
            },
            metadata: {
              role: input.role,
              environment: input.environment,
              description: input.description || '',
              assetId: input.assetId || null,
              assetName: input.assetName || null,
              remediationAuthorized: input.remediationAuthorized,
              migrationAuthorized: input.migrationAuthorized,
              source: 'agent-center',
            },
          }),
        },
      );

      if (!result.ok || !result.data) return { ok: false, message: result.message };
      const agentId = result.data.enrollment?.agentId;
      const agentToken = result.data.enrollment?.agentToken;
      if (agentId && agentToken) {
        setOneTimeToken({ agentId, token: agentToken, createdAt: new Date().toISOString(), mode: 'created' });
      }
      await Promise.all([loadSummary(), loadAssets()]);
      return { ok: true, data: { agentId, token: agentToken } };
    },
    [call, loadSummary, loadAssets, release],
  );

  const rotateToken = useCallback(
    async (agentId: string): Promise<ActionResult<{ token: string }>> => {
      const result = await call<{ enrollment?: { agentToken?: string }; agentToken?: string }>(
        `${SCANNER_API}/agents/${agentId}/token/rotate`,
        { method: 'POST' },
      );
      if (!result.ok || !result.data) return { ok: false, message: result.message };
      const rotated = result.data.enrollment?.agentToken || result.data.agentToken;
      if (rotated) {
        setOneTimeToken({ agentId, token: rotated, createdAt: new Date().toISOString(), mode: 'rotated' });
      }
      await loadSummary();
      return { ok: true, data: { token: rotated || '' } };
    },
    [call, loadSummary],
  );

  const generatePackage = useCallback(
    async (agentId: string, platform: AgentPlatform, enrollmentToken: string): Promise<ActionResult<GeneratedPackage>> => {
      const result = await call<GeneratedPackage>(`${INSTALLER_API}/package`, {
        method: 'POST',
        body: JSON.stringify({ agentId, platform, token: enrollmentToken }),
      });
      if (result.ok) await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const revokeAgent = useCallback(
    async (agentId: string) => {
      const result = await call(`${SCANNER_API}/agents/${agentId}/revoke`, { method: 'POST' });
      await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const deleteAgent = useCallback(
    async (agentId: string) => {
      const result = await call(`${SCANNER_API}/agents/${agentId}`, { method: 'DELETE' });
      await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const requestScan = useCallback(
    async (agentId: string) => {
      const result = await call<{ command: AgentCommand; delivery: string; connectionState: ConnectionState }>(
        `${INSTALLER_API}/agents/${agentId}/scan`,
        { method: 'POST' },
      );
      await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const requestUpgrade = useCallback(
    async (agentId: string) => {
      const result = await call<{ command: AgentCommand; delivery: string }>(`${INSTALLER_API}/agents/${agentId}/upgrade`, {
        method: 'POST',
      });
      await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const setAgentEnabled = useCallback(
    async (agentId: string, nextEnabled: boolean) => {
      const result = await call<{ command: AgentCommand; delivery: string }>(
        `${INSTALLER_API}/agents/${agentId}/${nextEnabled ? 'enable' : 'disable'}`,
        { method: 'POST' },
      );
      await loadSummary();
      return result;
    },
    [call, loadSummary],
  );

  const loadHealth = useCallback(
    (agentId: string) => call<AgentHealth>(`${INSTALLER_API}/agents/${agentId}/health`),
    [call],
  );
  const loadActivity = useCallback(
    (agentId: string) => call<{ activity: AgentActivityEntry[] }>(`${INSTALLER_API}/agents/${agentId}/activity`),
    [call],
  );
  const loadFindings = useCallback(
    (agentId: string) => call<AgentFindings>(`${INSTALLER_API}/agents/${agentId}/findings`),
    [call],
  );
  const loadScans = useCallback(
    (agentId: string) => call<{ scans: AgentScanRecord[] }>(`${INSTALLER_API}/agents/${agentId}/scans`),
    [call],
  );
  const loadJobs = useCallback(
    (agentId: string) => call<{ queued: AgentCommand[]; history: AgentCommand[] }>(`${INSTALLER_API}/agents/${agentId}/jobs`),
    [call],
  );

  const clearOneTimeToken = useCallback(() => setOneTimeToken(null), []);

  const capabilityLabels = useMemo(() => CAPABILITY_LABELS, []);

  return {
    tenantId,
    agents,
    assets,
    unassignedAgents,
    summary,
    release,
    platforms,
    roles,
    loading,
    error,
    busy,
    streamState,
    lastEventAt,
    oneTimeToken,
    scanProgress,
    capabilityLabels,
    refresh,
    loadAssets,
    createAgent,
    rotateToken,
    generatePackage,
    revokeAgent,
    deleteAgent,
    requestScan,
    requestUpgrade,
    setAgentEnabled,
    loadHealth,
    loadActivity,
    loadFindings,
    loadScans,
    loadJobs,
    clearOneTimeToken,
    setError,
  };
}

/** Browser-side save of a generated artifact. Keeps the token out of any URL. */
export function downloadGeneratedPackage(pkg: GeneratedPackage) {
  const blob = new Blob([pkg.content], { type: `${pkg.contentType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = pkg.filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Revoke on the next tick so Safari has finished reading the blob.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** SHA-256 of the artifact the browser actually holds, for side-by-side verification. */
export async function digestOfPackage(pkg: GeneratedPackage): Promise<string> {
  const bytes = new TextEncoder().encode(pkg.content);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
