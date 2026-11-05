import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { useAgentScan } from './use-agent-scan';
import type { AgentBindingRequest } from '@/lib/agent-installer/agent-binding';

/**
 * useAgentCollector — self-contained data layer for the redesigned Agent
 * Collector Console.
 *
 * Wraps the /api/v1/agent-scanner/* REST + SSE contract (plus the shared
 * tenant asset picker for agent bindings) — every endpoint, RBAC gate, telemetry stream, audit write,
 * connector integration, cryptographic enforcement, snapshot/rollback and
 * approval workflow the previous inline UI drove is preserved. This hook only
 * reshapes how the frontend consumes them so the console can present a clean,
 * progressive-disclosure enterprise experience.
 */

export type CollectorAgent = {
  id: string;
  user_id: string;
  name: string;
  status: string;
  hostname?: string | null;
  platform?: string | null;
  version?: string | null;
  capabilities?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  last_seen_at?: string | null;
  revoked_at?: string | null;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
};

export type ScannerEvidenceRow = {
  id: string;
  agent_id?: string | null;
  evidence_type?: string | null;
  asset_name?: string | null;
  observed_algorithm?: string | null;
  host?: string | null;
  file_path?: string | null;
  raw_evidence?: Record<string, unknown> | null;
  observed_at?: string | null;
  created_at?: string | null;
};

export type ScannerAlertRow = {
  id: string;
  agent_id?: string | null;
  severity?: string | null;
  category?: string | null;
  title?: string | null;
  message?: string | null;
  metadata?: Record<string, unknown> | null;
  status?: string | null;
  created_at?: string | null;
};

export type ConnectorAccount = {
  id: string;
  provider: string;
  display_name?: string | null;
  status?: string | null;
  scopes?: string[];
  capabilities?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  last_sync_at?: string | null;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
};

export type PatchOption = {
  id: string;
  label: string;
  actionType: string;
  requiresConnector: boolean;
  requiredScopes: string[];
  summary: string;
  validation: string;
  mandatoryQuantumStack?: Record<string, unknown>;
  executionContract?: Record<string, unknown>;
};

export type PatchOptionGroup = { assetClass: string; options: PatchOption[] };

export type OperatorAction = {
  id: string;
  migration_id?: string | null;
  connector_account_id?: string | null;
  action_type?: string | null;
  asset_class?: string | null;
  status?: string | null;
  approval_mode?: string | null;
  patch_plan?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  validation?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  requested_at?: string | null;
  approved_at?: string | null;
  applied_at?: string | null;
  validated_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

export type OneTimeAgentToken = {
  agentId: string;
  token: string;
  createdAt: string;
  mode: 'created' | 'rotated';
} | null;

export type AgentPolicyInput = {
  enabled: boolean;
  intervalSeconds: number;
  allowedTargets: string[];
  allowedPaths: string[];
  scanTypes: string[];
  alertThreshold: string;
};

export type CreateCollectorInput = {
  name: string;
  environment: string;
  description?: string;
  tags?: string[];
  policy: AgentPolicyInput;
  /** Where this agent's findings are filed. Omitted uses its machine's device profile. */
  binding?: AgentBindingRequest;
};

/** A tenant asset an agent can be bound to, with the agents already bound to it. */
export type BindingTarget = {
  id: string;
  name: string;
  type?: string | null;
  environment?: string | null;
  criticality?: string | null;
  status?: string | null;
  ip_address?: string | null;
  service_owner?: string | null;
  updated_at?: string | null;
  binding_kind?: string | null;
  binding_path?: string | null;
  agents: Array<{ id: string; name: string }>;
};

/** Returned when a "create new" binding names an asset that already exists. */
export type BindingConflict = { id: string; name: string; type?: string | null };

export type LoadState = 'loading' | 'success' | 'error';

type ActionResult = {
  ok: boolean;
  message?: string;
  token?: OneTimeAgentToken;
  /** True when the server stored less than was requested (e.g. modules clamped to the plan). */
  adjusted?: boolean;
  /** Set when a new binding target's name is already taken by this asset. */
  conflict?: BindingConflict;
  /** Modules the server removed from a policy, and why. */
  denied?: PolicyDenied;
};

export type PolicyDenied = { plan: string[]; role: string[]; unknown: string[] };

const API = '/api/v1/agent-scanner';
// The tenant asset picker is served by the Agent Center API; one source for both consoles.
const BINDING_TARGETS_API = '/api/v1/agent-installer/assets';

function bindingConflictFrom(json: unknown): BindingConflict | undefined {
  const error = (json as { error?: { code?: string; detail?: { asset?: BindingConflict } } } | null)?.error;
  return error?.code === 'BINDING_NAME_EXISTS' && error.detail?.asset?.id ? error.detail.asset : undefined;
}

export function isAgentOnline(agent: CollectorAgent): boolean {
  if (agent.revoked_at || agent.status === 'revoked') return false;
  if (!agent.last_seen_at) return false;
  return Date.now() - Date.parse(agent.last_seen_at) < 10 * 60 * 1000;
}

export function agentDisplayStatus(agent: CollectorAgent): 'Online' | 'Offline' | 'Waiting' | 'Unhealthy' | 'Revoked' | 'Updating' {
  if (agent.revoked_at || agent.status === 'revoked') return 'Revoked';
  if (agent.status === 'updating') return 'Updating';
  if (agent.status === 'degraded' || agent.status === 'unhealthy') return 'Unhealthy';
  if (isAgentOnline(agent)) return 'Online';
  if (!agent.last_seen_at) return 'Waiting';
  return 'Offline';
}

/** Evidence-derived 0–100 health score (never fabricated — driven by heartbeat recency + status). */
export function agentHealthScore(agent: CollectorAgent): number {
  if (agent.revoked_at || agent.status === 'revoked') return 0;
  if (!agent.last_seen_at) return 0;
  const ageMs = Date.now() - Date.parse(agent.last_seen_at);
  const minutes = ageMs / 60000;
  let score = minutes <= 2 ? 100 : minutes <= 5 ? 90 : minutes <= 10 ? 75 : minutes <= 30 ? 45 : minutes <= 120 ? 25 : 10;
  if (agent.status === 'degraded' || agent.status === 'unhealthy') score = Math.min(score, 50);
  if (agent.status === 'updating') score = Math.min(score, 70);
  return Math.round(score);
}

export function connectionQuality(agent: CollectorAgent): 'Excellent' | 'Good' | 'Fair' | 'Poor' | 'None' {
  const score = agentHealthScore(agent);
  if (score >= 90) return 'Excellent';
  if (score >= 70) return 'Good';
  if (score >= 45) return 'Fair';
  if (score > 0) return 'Poor';
  return 'None';
}

export function useAgentCollector(enabled: boolean) {
  const { requestScan, scanning } = useAgentScan();
  const { session } = useAuth();
  const token = session?.access_token;

  const [agents, setAgents] = useState<CollectorAgent[]>([]);
  const [evidence, setEvidence] = useState<ScannerEvidenceRow[]>([]);
  const [alerts, setAlerts] = useState<ScannerAlertRow[]>([]);
  const [connectors, setConnectors] = useState<ConnectorAccount[]>([]);
  const [patchOptions, setPatchOptions] = useState<PatchOptionGroup[]>([]);
  const [operatorActions, setOperatorActions] = useState<OperatorAction[]>([]);
  const [state, setState] = useState<LoadState>('loading');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sseConnected, setSseConnected] = useState(false);
  const [lastSyncAt, setLastSyncAt] = useState<string | null>(null);
  const [oneTimeToken, setOneTimeToken] = useState<OneTimeAgentToken>(null);
  const [bindingTargets, setBindingTargets] = useState<BindingTarget[]>([]);
  const [bindingTargetsState, setBindingTargetsState] = useState<LoadState>('loading');
  const didInitialLoad = useRef(false);

  const authHeaders = useCallback((): Record<string, string> | null => {
    if (!token) return null;
    return { Authorization: `Bearer ${token}` };
  }, [token]);

  const fetchAll = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    if (!didInitialLoad.current) setState('loading');
    setError(null);
    try {
      const [agentsRes, evidenceRes, alertsRes, patchRes, actionsRes] = await Promise.all([
        fetch(`${API}/agents`, { headers }),
        fetch(`${API}/evidence`, { headers }),
        fetch(`${API}/alerts`, { headers }),
        fetch(`${API}/remediation/patch-options`, { headers }),
        fetch(`${API}/remediation/operator-actions`, { headers }),
      ]);
      const [agentsJson, evidenceJson, alertsJson, patchJson, actionsJson] = await Promise.all([
        agentsRes.json(), evidenceRes.json(), alertsRes.json(), patchRes.json(), actionsRes.json(),
      ]);
      if (!agentsRes.ok) throw new Error(agentsJson?.error?.message || 'Unable to load collectors');
      setAgents(agentsJson?.data?.agents || []);
      setEvidence(evidenceJson?.data?.evidence || []);
      setAlerts(alertsJson?.data?.alerts || []);
      setPatchOptions(patchJson?.data?.options || []);
      setConnectors(patchJson?.data?.connectors || []);
      setOperatorActions(actionsJson?.data?.actions || []);
      setState('success');
      didInitialLoad.current = true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Collector load failed');
      setState('error');
    }
  }, [authHeaders]);

  useEffect(() => {
    if (!enabled || !token) return;
    void fetchAll();
  }, [enabled, token, fetchAll]);

  // SSE — same agent-scanner-sync snapshot stream the old UI used.
  useEffect(() => {
    if (!enabled || !token) return;
    const source = new EventSource(`${API}/stream?token=${encodeURIComponent(token)}`);
    source.onopen = () => setSseConnected(true);
    source.onerror = () => setSseConnected(false);
    source.addEventListener('agent-scanner-sync', (message) => {
      try {
        const snapshot = JSON.parse((message as MessageEvent).data || '{}');
        if (Array.isArray(snapshot.agents)) setAgents(snapshot.agents);
        if (Array.isArray(snapshot.evidence)) setEvidence(snapshot.evidence);
        if (Array.isArray(snapshot.alerts)) setAlerts(snapshot.alerts);
        if (Array.isArray(snapshot.connectors)) setConnectors(snapshot.connectors);
        if (Array.isArray(snapshot.operatorActions)) setOperatorActions(snapshot.operatorActions);
        if (Array.isArray(snapshot.patchOptions)) setPatchOptions(snapshot.patchOptions);
        setLastSyncAt(snapshot.generatedAt || new Date().toISOString());
        setState('success');
      } catch {
        setSseConnected(false);
      }
    });
    return () => { source.close(); setSseConnected(false); };
  }, [enabled, token]);

  /* Binding targets load independently: an unreachable inventory must not
     block collector creation, it only empties the "existing asset" picker. */
  const loadBindingTargets = useCallback(async () => {
    const headers = authHeaders();
    if (!headers) return;
    setBindingTargetsState('loading');
    try {
      const res = await fetch(BINDING_TARGETS_API, { headers });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(json?.error?.message || 'Unable to load assets');
      setBindingTargets(Array.isArray(json?.data?.assets) ? json.data.assets : []);
      setBindingTargetsState('success');
    } catch {
      setBindingTargets([]);
      setBindingTargetsState('error');
    }
  }, [authHeaders]);

  useEffect(() => {
    if (!enabled || !token) return;
    void loadBindingTargets();
  }, [enabled, token, loadBindingTargets]);

  const request = useCallback(
    async (path: string, init: RequestInit, okMessage?: string): Promise<ActionResult> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in first.' };
      setBusy(true);
      setError(null);
      try {
        const res = await fetch(`${API}${path}`, {
          ...init,
          headers: { ...headers, 'Content-Type': 'application/json', ...(init.headers || {}) },
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(json?.error?.message || `Request failed (${res.status})`);
        await fetchAll();
        return { ok: true, message: okMessage, token: undefined };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Request failed';
        setError(message);
        return { ok: false, message };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders, fetchAll],
  );

  const createCollector = useCallback(
    async (input: CreateCollectorInput): Promise<ActionResult> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in first.' };
      setBusy(true);
      setError(null);
      try {
        const res = await fetch(`${API}/agents/enroll`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: input.name,
            environment: input.environment,
            hostname: 'pending-customer-install',
            platform: 'customer-managed',
            version: '0.1.0',
            capabilities: Object.fromEntries(input.policy.scanTypes.map((s) => [s, true])),
            policy: input.policy,
            metadata: {
              environment: input.environment,
              description: input.description || '',
              tags: input.tags || [],
              source: 'agent-collector-console',
            },
            binding: input.binding || { mode: 'none' },
          }),
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) {
          // A taken name is a choice for the operator, not a page-level error.
          const conflict = bindingConflictFrom(json);
          if (conflict) return { ok: false, message: json?.error?.message, conflict };
          throw new Error(json?.error?.message || 'Unable to create collector');
        }
        const agentId = json?.data?.enrollment?.agentId;
        const tok = json?.data?.enrollment?.agentToken;
        const oneTime: OneTimeAgentToken = agentId && tok ? { agentId, token: tok, createdAt: new Date().toISOString(), mode: 'created' } : null;
        if (oneTime) setOneTimeToken(oneTime);
        await Promise.all([fetchAll(), loadBindingTargets()]);
        return { ok: true, token: oneTime };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Collector creation failed';
        setError(message);
        return { ok: false, message };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders, fetchAll, loadBindingTargets],
  );

  /* Rebinding applies to evidence uploaded from now on; findings already
     filed keep the binding they were recorded under. */
  const updateBinding = useCallback(
    async (id: string, binding: AgentBindingRequest): Promise<ActionResult> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in first.' };
      setBusy(true);
      try {
        const res = await fetch(`${API}/agents/${id}/binding`, {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ binding }),
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) {
          const conflict = bindingConflictFrom(json);
          return { ok: false, message: json?.error?.message || `Request failed (${res.status})`, conflict };
        }
        await Promise.all([fetchAll(), loadBindingTargets()]);
        const next = json?.data?.binding as { assetName?: string } | null;
        return { ok: true, message: next?.assetName ? `New findings will be filed under ${next.assetName}.` : 'New findings will use this machine’s device profile.' };
      } catch (err) {
        return { ok: false, message: err instanceof Error ? err.message : 'Binding update failed' };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders, fetchAll, loadBindingTargets],
  );

  const rotateToken = useCallback(
    async (agentId: string): Promise<ActionResult> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in first.' };
      setBusy(true);
      try {
        const res = await fetch(`${API}/agents/${agentId}/token/rotate`, { method: 'POST', headers });
        const json = await res.json();
        if (!res.ok) throw new Error(json?.error?.message || 'Token rotation failed');
        const tok = json?.data?.enrollment?.agentToken || json?.data?.agentToken;
        const oneTime: OneTimeAgentToken = tok ? { agentId, token: tok, createdAt: new Date().toISOString(), mode: 'rotated' } : null;
        if (oneTime) setOneTimeToken(oneTime);
        await fetchAll();
        return { ok: true, token: oneTime };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Token rotation failed';
        setError(message);
        return { ok: false, message };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders, fetchAll],
  );

  const revokeCollector = useCallback((id: string) => request(`/agents/${id}/revoke`, { method: 'POST' }, 'Collector revoked.'), [request]);
  const deleteCollector = useCallback((id: string) => request(`/agents/${id}`, { method: 'DELETE' }, 'Collector deleted.'), [request]);
  /* The server clamps modules to the agent's role and the tenant's plan and
     returns what it removed. That is reported, not swallowed — "Policy
     updated" over a silently narrowed scope is how a dimension goes
     unassessed without anyone deciding it should. */
  const updatePolicy = useCallback(
    async (id: string, policy: AgentPolicyInput): Promise<ActionResult> => {
      const headers = authHeaders();
      if (!headers) return { ok: false, message: 'Sign in first.' };
      setBusy(true);
      setError(null);
      try {
        const res = await fetch(`${API}/agents/${id}/policy`, {
          method: 'PUT',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify(policy),
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(json?.error?.message || `Request failed (${res.status})`);
        await fetchAll();
        const denied: PolicyDenied = {
          plan: json?.data?.denied?.plan || [],
          role: json?.data?.denied?.role || [],
          unknown: json?.data?.denied?.unknown || [],
        };
        const removed = [
          denied.plan.length ? `not in your plan: ${denied.plan.join(', ')}` : '',
          denied.role.length ? `not part of this agent's role: ${denied.role.join(', ')}` : '',
          denied.unknown.length ? `not an agent module: ${denied.unknown.join(', ')}` : '',
        ].filter(Boolean).join('; ');
        return { ok: true, message: removed ? `Policy updated. Removed — ${removed}.` : 'Policy updated.', token: undefined, adjusted: Boolean(removed), denied };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Request failed';
        setError(message);
        return { ok: false, message };
      } finally {
        setBusy(false);
      }
    },
    [authHeaders, fetchAll],
  );
  const createConnector = useCallback((body: Record<string, unknown>) => request('/connectors', { method: 'POST', body: JSON.stringify(body) }, 'Cloud connection registered.'), [request]);
  /** Derive this account's QGuard Messaging device posture into evidence (same login, server-side). */
  const syncMessagingPosture = useCallback(() => request('/integrations/qguard-messaging/sync', { method: 'POST' }, 'QGuard Messaging devices imported.'), [request]);
  const createOperatorAction = useCallback((body: Record<string, unknown>) => request('/remediation/operator-actions', { method: 'POST', body: JSON.stringify(body) }, 'Remediation action created.'), [request]);
  const setOperatorStatus = useCallback((id: string, status: string, extra?: Record<string, unknown>) => request(`/remediation/operator-actions/${id}/status`, { method: 'POST', body: JSON.stringify({ status, ...(extra || {}) }) }, `Action ${status}.`), [request]);
  const acknowledgeAlert = useCallback((id: string) => request(`/alerts/${id}/acknowledge`, { method: 'POST' }, 'Alert acknowledged.'), [request]);
  const resolveAlert = useCallback((id: string) => request(`/alerts/${id}/resolve`, { method: 'POST' }, 'Alert resolved.'), [request]);
  const clearOneTimeToken = useCallback(() => setOneTimeToken(null), []);

  // Derived summary metrics (evidence-driven, never fabricated).
  const summary = useMemo(() => {
    const online = agents.filter(isAgentOnline).length;
    const revoked = agents.filter((a) => a.revoked_at || a.status === 'revoked').length;
    const openAlerts = alerts.filter((a) => !['resolved', 'closed', 'suppressed'].includes(String(a.status || 'open').toLowerCase()));
    const distinctAssets = new Set(evidence.map((e) => (e.asset_name || e.host || e.id)).filter(Boolean)).size;
    const pendingRemediation = operatorActions.filter((a) => ['planned', 'approved', 'applying', 'applied', 'validating', 'scheduled'].includes(String(a.status))).length;
    const lastHeartbeat = agents
      .map((a) => a.last_seen_at)
      .filter(Boolean)
      .sort((x, y) => Date.parse(String(y)) - Date.parse(String(x)))[0] || null;
    const lastEvidence = evidence
      .map((e) => e.observed_at || e.created_at)
      .filter(Boolean)
      .sort((x, y) => Date.parse(String(y)) - Date.parse(String(x)))[0] || null;
    /*
     * A collector that has NEVER sent a heartbeat is awaiting installation — it
     * is not "offline", which means it checked in and then stopped. Folding the
     * two together made this page report 3 offline collectors while the Agent
     * Center reported 3 awaiting install, for the same three rows (spec §17,
     * §29: one canonical state, and absence of data is never a status claim).
     */
    const awaitingInstall = agents.filter(
      (agent) => !agent.last_seen_at && !agent.revoked_at && agent.status !== 'revoked',
    ).length;
    return {
      registered: agents.length,
      online,
      awaitingInstall,
      offline: Math.max(0, agents.length - online - revoked - awaitingInstall),
      revoked,
      assetsDiscovered: distinctAssets,
      quantumRisks: openAlerts.length,
      pendingRemediation,
      lastHeartbeat,
      lastEvidence,
      evidenceCount: evidence.length,
    };
  }, [agents, alerts, evidence, operatorActions]);

  return {
    agents, evidence, alerts, connectors, patchOptions, operatorActions,
    state, error, busy: busy || scanning, sseConnected, lastSyncAt, oneTimeToken, summary,
    bindingTargets, bindingTargetsState, loadBindingTargets,
    refresh: fetchAll,
    createCollector, rotateToken, revokeCollector, deleteCollector, updatePolicy, updateBinding, requestScan,
    createConnector, syncMessagingPosture, createOperatorAction, setOperatorStatus, acknowledgeAlert, resolveAlert,
    clearOneTimeToken, setError,
  };
}
