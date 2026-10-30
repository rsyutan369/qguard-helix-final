'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';

export type ScannerFinding = {
  id?: string;
  algorithm?: string;
  category?: string;
  status?: string;
  threatLevel?: string;
  location?: string;
  evidence?: string;
  recommendation?: string;
  source?: string;
  keySize?: string | number | null;
  [key: string]: unknown;
};

export type ScannerIntelligenceSnapshot = {
  generatedAt: string;
  /**
   * Content fingerprint published by the API (excludes `generatedAt`). Two
   * snapshots with the same fingerprint describe the same estate, so the hook
   * skips the re-render, the cache rewrite and the dashboards' re-derivation.
   */
  fingerprint?: string;
  mode: string;
  summary: {
    totalAssets: number;
    totalComponents: number;
    vulnerableAssets: number;
    vulnerableComponents: number;
    pqcReadyComponents: number;
    pqcReadiness: number;
    riskScore: number;
    qScore: number;
    criticalFindings: number;
    totalFindings: number;
    activeScans: number;
    completedScans: number;
  };
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  cbom: {
    mode: string;
    entries: any[];
    stats: {
      totalComponents: number;
      quantumVulnerableComponents: number;
      pqcReadyComponents: number;
      totalInstances: number;
    };
  };
  assets: {
    mode: string;
    assets: any[];
  };
  exposure: {
    mode: string;
    nodes: any[];
    distribution: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  history: {
    mode: string;
    history: any[];
  };
  findings: ScannerFinding[];
  telemetry: any[];
  runtime: {
    operations: number;
    activeSessions: number;
    encryptedChannels: number;
    keyRotations: number;
    alerts: number;
    complianceScore: number;
  };
};

/** Exported for render fixtures (tools/intel-ops-render); the hook's own initial state. */
export const EMPTY_SNAPSHOT: ScannerIntelligenceSnapshot = {
  generatedAt: '',
  mode: 'none',
  summary: {
    totalAssets: 0,
    totalComponents: 0,
    vulnerableAssets: 0,
    vulnerableComponents: 0,
    pqcReadyComponents: 0,
    pqcReadiness: 0,
    riskScore: 0,
    qScore: 0,
    criticalFindings: 0,
    totalFindings: 0,
    activeScans: 0,
    completedScans: 0,
  },
  severityCounts: { critical: 0, high: 0, medium: 0, low: 0, safe: 0 },
  cbom: {
    mode: 'none',
    entries: [],
    stats: { totalComponents: 0, quantumVulnerableComponents: 0, pqcReadyComponents: 0, totalInstances: 0 },
  },
  assets: { mode: 'none', assets: [] },
  exposure: { mode: 'none', nodes: [], distribution: { critical: 0, high: 0, medium: 0, low: 0 } },
  history: { mode: 'none', history: [] },
  findings: [],
  telemetry: [],
  runtime: { operations: 0, activeSessions: 0, encryptedChannels: 0, keyRotations: 0, alerts: 0, complianceScore: 0 },
};

const SCANNER_CACHE_PREFIX = 'qguard-scanner-intelligence:v1:';
const SOFT_LOADING_LIMIT_MS = 2200;

function hasSnapshotData(snapshot?: ScannerIntelligenceSnapshot | null) {
  if (!snapshot) return false;
  return Boolean(
    snapshot.summary.totalAssets ||
    snapshot.summary.totalComponents ||
    snapshot.summary.totalFindings ||
    snapshot.cbom.entries.length ||
    snapshot.assets.assets.length ||
    snapshot.exposure.nodes.length ||
    snapshot.history.history.length ||
    snapshot.findings.length ||
    snapshot.telemetry.length,
  );
}

function readCachedSnapshot(cacheKey?: string | null) {
  if (!cacheKey || typeof window === 'undefined') return null;
  try {
    const cached = window.localStorage.getItem(cacheKey);
    if (!cached) return null;
    const snapshot = normalizeStreamSnapshot(JSON.parse(cached));
    return hasSnapshotData(snapshot) ? snapshot : null;
  } catch {
    return null;
  }
}

function writeCachedSnapshot(cacheKey: string | null | undefined, snapshot: ScannerIntelligenceSnapshot) {
  if (!cacheKey || typeof window === 'undefined' || !hasSnapshotData(snapshot)) return;
  try {
    window.localStorage.setItem(cacheKey, JSON.stringify(snapshot));
  } catch {
    // Local storage can be unavailable in hardened browser contexts.
  }
}

async function fetchScannerData(path: string, headers: HeadersInit, signal?: AbortSignal) {
  const res = await fetch(path, { headers, signal });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json?.error?.message || `Unable to load ${path}`);
  return json?.data || {};
}

type SeverityKey = keyof ScannerIntelligenceSnapshot['severityCounts'];

function normalizeThreatLevel(value: unknown): SeverityKey {
  const normalized = String(value || '').toUpperCase();
  if (normalized === 'CRITICAL') return 'critical';
  if (normalized === 'HIGH') return 'high';
  if (normalized === 'MEDIUM' || normalized === 'MODERATE') return 'medium';
  if (normalized === 'SAFE') return 'safe';
  return 'low';
}

function buildFallbackFindings(history: any[], cbomEntries: any[]): ScannerFinding[] {
  const storedFindings = history.flatMap((entry) => Array.isArray(entry.findings) ? entry.findings : []);
  if (storedFindings.length > 0) return storedFindings;

  return cbomEntries.map((entry) => ({
    id: entry.id,
    algorithm: entry.algorithm,
    category: entry.type || entry.component,
    status: entry.status,
    threatLevel: entry.riskSeverity === 'critical'
      ? 'CRITICAL'
      : entry.riskSeverity === 'high'
        ? 'HIGH'
        : entry.isQuantumSafe
          ? 'SAFE'
          : entry.isVulnerable
            ? 'MEDIUM'
            : 'LOW',
    location: entry.sourceAsset,
    evidence: entry.evidence,
    recommendation: entry.recommendation || entry.pqcReplacement,
    source: entry.detectionMethod || 'cbom-inventory',
    keySize: entry.keySize,
  }));
}

function buildSnapshotFromScannerApis(parts: {
  history: any;
  cbom: any;
  assets: any;
  exposure: any;
}): ScannerIntelligenceSnapshot {
  const history = Array.isArray(parts.history?.history) ? parts.history.history : [];
  const cbomEntries = Array.isArray(parts.cbom?.entries) ? parts.cbom.entries : [];
  const assets = Array.isArray(parts.assets?.assets) ? parts.assets.assets : [];
  const exposureNodes = Array.isArray(parts.exposure?.nodes) ? parts.exposure.nodes : [];
  const findings = buildFallbackFindings(history, cbomEntries);
  const latest = history[0] || null;

  const severityCounts = findings.reduce<ScannerIntelligenceSnapshot['severityCounts']>(
    (counts, finding) => {
      const level = normalizeThreatLevel(finding.threatLevel || finding.severity || finding.status);
      counts[level] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, safe: 0 },
  );

  const totalComponents = Number(parts.cbom?.stats?.totalComponents ?? cbomEntries.length);
  const vulnerableComponents = Number(
    parts.cbom?.stats?.quantumVulnerableComponents ??
    cbomEntries.filter((entry: any) => entry.isVulnerable).length,
  );
  const pqcReadyComponents = Number(
    parts.cbom?.stats?.pqcReadyComponents ??
    cbomEntries.filter((entry: any) => entry.isQuantumSafe).length,
  );
  const assetRiskAverage = assets.length > 0
    ? Math.round(assets.reduce((sum: number, asset: any) => sum + Number(asset.riskScore || 0), 0) / assets.length)
    : 0;
  const riskScore = Number(latest?.summary?.riskScore ?? assetRiskAverage ?? 0);
  const telemetry = history
    .flatMap((entry: any) => (entry.telemetry || []).map((event: any) => ({
      ...event,
      scanId: entry.scanId,
      target: entry.target,
      timestamp: event.timestamp || entry.startedAt,
    })))
    .sort((a: any, b: any) => Date.parse(b.timestamp || '') - Date.parse(a.timestamp || ''))
    .slice(0, 500);

  return {
    generatedAt: new Date().toISOString(),
    mode: parts.history?.mode || parts.cbom?.mode || parts.assets?.mode || parts.exposure?.mode || 'scanner-api',
    summary: {
      totalAssets: assets.length,
      totalComponents,
      vulnerableAssets: assets.filter((asset: any) => Number(asset.vulnerableCount || 0) > 0 || Number(asset.riskScore || 0) >= 40).length,
      vulnerableComponents,
      pqcReadyComponents,
      pqcReadiness: totalComponents > 0 ? Math.round((pqcReadyComponents / totalComponents) * 100) : 0,
      riskScore,
      qScore: Math.max(0, 100 - riskScore),
      criticalFindings: severityCounts.critical,
      totalFindings: findings.length,
      activeScans: history.filter((entry: any) => ['queued', 'running', 'analyzing'].includes(String(entry.status))).length,
      completedScans: history.filter((entry: any) => entry.status === 'completed').length,
    },
    severityCounts,
    cbom: {
      mode: parts.cbom?.mode || 'scanner-api',
      entries: cbomEntries,
      stats: {
        totalComponents,
        quantumVulnerableComponents: vulnerableComponents,
        pqcReadyComponents,
        totalInstances: Number(parts.cbom?.stats?.totalInstances ?? cbomEntries.reduce((sum: number, entry: any) => sum + Number(entry.instances || 1), 0)),
      },
    },
    assets: { mode: parts.assets?.mode || 'scanner-api', assets },
    exposure: {
      mode: parts.exposure?.mode || 'scanner-api',
      nodes: exposureNodes,
      distribution: parts.exposure?.distribution || { critical: 0, high: 0, medium: 0, low: 0 },
    },
    history: { mode: parts.history?.mode || 'scanner-api', history },
    findings,
    telemetry,
    runtime: {
      operations: telemetry.length,
      activeSessions: history.filter((entry: any) => !entry.completedAt && entry.status !== 'completed').length,
      encryptedChannels: cbomEntries.filter((entry: any) => String(entry.type).toLowerCase().includes('protocol') || String(entry.algorithm).toLowerCase().includes('tls')).length,
      keyRotations: cbomEntries.filter((entry: any) => String(entry.pqcReplacement || '').length > 0).length,
      alerts: severityCounts.critical + severityCounts.high,
      complianceScore: totalComponents > 0 ? Math.round((pqcReadyComponents / totalComponents) * 1000) / 10 : 0,
    },
  };
}

async function fetchScannerSnapshot(headers: HeadersInit, signal?: AbortSignal) {
  const [history, cbom, assets, exposure] = await Promise.all([
    fetchScannerData('/api/v1/scanner/history', headers, signal),
    fetchScannerData('/api/v1/scanner/cbom', headers, signal),
    fetchScannerData('/api/v1/scanner/assets', headers, signal),
    fetchScannerData('/api/v1/scanner/exposure-map', headers, signal),
  ]);

  return buildSnapshotFromScannerApis({ history, cbom, assets, exposure });
}

async function fetchScannerIntelligence(headers: HeadersInit, signal?: AbortSignal): Promise<ScannerIntelligenceSnapshot> {
  try {
    const snapshot = await fetchScannerData('/api/v1/scanner/intelligence', headers, signal);
    if (snapshot?.summary && snapshot?.cbom && snapshot?.assets && snapshot?.history) {
      return snapshot as ScannerIntelligenceSnapshot;
    }
    return buildSnapshotFromScannerApis({
      history: snapshot?.history,
      cbom: snapshot?.cbom,
      assets: snapshot?.assets,
      exposure: snapshot?.exposure,
    });
  } catch (err) {
    if (signal?.aborted) throw err;
    return fetchScannerSnapshot(headers, signal);
  }
}

function normalizeStreamSnapshot(payload: unknown): ScannerIntelligenceSnapshot | null {
  const snapshot = payload as Partial<ScannerIntelligenceSnapshot> | null;
  if (!snapshot?.summary || !snapshot.cbom || !snapshot.assets || !snapshot.history) return null;
  return {
    ...EMPTY_SNAPSHOT,
    ...snapshot,
    summary: { ...EMPTY_SNAPSHOT.summary, ...snapshot.summary },
    severityCounts: { ...EMPTY_SNAPSHOT.severityCounts, ...snapshot.severityCounts },
    cbom: {
      ...EMPTY_SNAPSHOT.cbom,
      ...snapshot.cbom,
      entries: Array.isArray(snapshot.cbom?.entries) ? snapshot.cbom.entries : [],
      stats: { ...EMPTY_SNAPSHOT.cbom.stats, ...snapshot.cbom?.stats },
    },
    assets: {
      ...EMPTY_SNAPSHOT.assets,
      ...snapshot.assets,
      assets: Array.isArray(snapshot.assets?.assets) ? snapshot.assets.assets : [],
    },
    exposure: {
      ...EMPTY_SNAPSHOT.exposure,
      ...snapshot.exposure,
      nodes: Array.isArray(snapshot.exposure?.nodes) ? snapshot.exposure.nodes : [],
      distribution: { ...EMPTY_SNAPSHOT.exposure.distribution, ...snapshot.exposure?.distribution },
    },
    history: {
      ...EMPTY_SNAPSHOT.history,
      ...snapshot.history,
      history: Array.isArray(snapshot.history?.history) ? snapshot.history.history : [],
    },
    findings: Array.isArray(snapshot.findings) ? snapshot.findings : [],
    telemetry: Array.isArray(snapshot.telemetry) ? snapshot.telemetry : [],
    runtime: { ...EMPTY_SNAPSHOT.runtime, ...snapshot.runtime },
  };
}

/**
 * How the page is currently receiving the estate:
 *  - `connecting` — nothing confirmed by the server yet
 *  - `stream`     — live SSE; the server re-checks the estate every tick
 *  - `polling`    — the stream is unavailable; REST snapshot every 8s
 *  - `manual`     — live updates switched off; refreshed on demand only
 *  - `offline`    — the last request failed; data on screen is not current
 */
export type ScannerTransport = 'connecting' | 'stream' | 'polling' | 'manual' | 'offline';

/** Where the snapshot on screen came from — a cache is never presented as live. */
export type ScannerSnapshotSource = 'none' | 'cache' | 'network';

/** How long the stream may stay silent before the REST fallback is used. */
const STREAM_FIRST_FRAME_GRACE_MS = 4000;

export function useScannerIntelligence(options: { live?: boolean } = {}) {
  const { session } = useAuth();
  const token = session?.access_token;
  const live = options.live !== false;
  const [data, setData] = useState<ScannerIntelligenceSnapshot>(EMPTY_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [source, setSource] = useState<ScannerSnapshotSource>('none');
  const [transport, setTransport] = useState<ScannerTransport>('connecting');
  /** When the server last confirmed the estate — a new snapshot OR an "unchanged" tick. */
  const [lastVerifiedAt, setLastVerifiedAt] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const fingerprintRef = useRef<string | null>(null);

  const authHeaders = useMemo(() => (token ? { Authorization: `Bearer ${token}` } : undefined), [token]);
  const cacheKey = useMemo(() => {
    const tenantKey =
      session?.user?.app_metadata?.tenant_id ||
      session?.user?.app_metadata?.organization_id ||
      session?.user?.user_metadata?.tenant_id ||
      session?.user?.user_metadata?.organization_id ||
      'default-tenant';
    const userKey = session?.user?.id || token?.slice(0, 24);
    return userKey ? `${SCANNER_CACHE_PREFIX}${tenantKey}:${userKey}` : null;
  }, [
    session?.user?.app_metadata?.organization_id,
    session?.user?.app_metadata?.tenant_id,
    session?.user?.id,
    session?.user?.user_metadata?.organization_id,
    session?.user?.user_metadata?.tenant_id,
    token,
  ]);

  /**
   * Apply a snapshot the SERVER produced. Identical content (same fingerprint)
   * only records that the server re-confirmed the estate: no re-render, no
   * 1 MB localStorage rewrite, no dashboard re-derivation.
   */
  const applyNetworkSnapshot = useCallback((snapshot: ScannerIntelligenceSnapshot) => {
    setSource('network');
    setLastVerifiedAt(snapshot.generatedAt || new Date().toISOString());
    if (snapshot.fingerprint && snapshot.fingerprint === fingerprintRef.current) return;
    fingerprintRef.current = snapshot.fingerprint || null;
    setData(snapshot);
    writeCachedSnapshot(cacheKey, snapshot);
  }, [cacheKey]);

  const refresh = useCallback(async () => {
    if (!authHeaders) {
      fingerprintRef.current = null;
      setData(EMPTY_SNAPSHOT);
      setSource('none');
      setLoading(false);
      setConnected(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const snapshot = await fetchScannerIntelligence(authHeaders);
      applyNetworkSnapshot(snapshot);
      setConnected(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load scanner intelligence');
      setConnected(false);
    } finally {
      setLoading(false);
    }
  }, [applyNetworkSnapshot, authHeaders]);

  useEffect(() => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    if (!authHeaders) {
      fingerprintRef.current = null;
      setData(EMPTY_SNAPSHOT);
      setSource('none');
      setTransport('offline');
      setLoading(false);
      setConnected(false);
      return () => controller.abort();
    }

    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let loadingTimer: ReturnType<typeof setTimeout> | null = null;
    let graceTimer: ReturnType<typeof setTimeout> | null = null;
    let eventSource: EventSource | null = null;
    let streamDelivering = false;
    const cachedSnapshot = readCachedSnapshot(cacheKey);

    setTransport('connecting');
    if (cachedSnapshot) {
      // Shown immediately, but labelled as cached until the server confirms it.
      fingerprintRef.current = cachedSnapshot.fingerprint || null;
      setData(cachedSnapshot);
      setSource('cache');
      setLoading(false);
    } else {
      // A different tenant/user (or none cached): never keep showing the
      // previous identity's snapshot while this one loads.
      fingerprintRef.current = null;
      setData(EMPTY_SNAPSHOT);
      setSource('none');
      setLoading(true);
      loadingTimer = setTimeout(() => {
        if (!controller.signal.aborted) setLoading(false);
      }, SOFT_LOADING_LIMIT_MS);
    }

    const clearPollTimer = () => {
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const markDelivered = () => {
      if (loadingTimer) {
        clearTimeout(loadingTimer);
        loadingTimer = null;
      }
      setLoading(false);
      setError(null);
      setConnected(true);
    };

    const pollSnapshot = () => {
      void fetchScannerIntelligence(authHeaders, controller.signal)
        .then((nextSnapshot) => {
          if (controller.signal.aborted) return;
          applyNetworkSnapshot(nextSnapshot);
          markDelivered();
          setTransport(!live ? 'manual' : streamDelivering ? 'stream' : 'polling');
        })
        .catch((err) => {
          if (!controller.signal.aborted) {
            setError(err instanceof Error ? err.message : 'Scanner intelligence refresh failed');
            setConnected(false);
            setLoading(false);
            setTransport('offline');
          }
        });
    };

    const startPolling = () => {
      if (!live || pollTimer || controller.signal.aborted) return;
      pollSnapshot();
      pollTimer = setInterval(pollSnapshot, 8000);
    };

    const connectStream = () => {
      if (!token || controller.signal.aborted) {
        startPolling();
        return;
      }

      eventSource?.close();
      eventSource = new EventSource(`/api/v1/scanner/intelligence/stream?token=${encodeURIComponent(token)}`);

      // The stream's first frame normally lands in well under a second. If it
      // stays silent (a buffering proxy, a stalled build) the page must not sit
      // blank: fall back to REST until a frame arrives. This replaces the old
      // unconditional mount-time poll, which downloaded every snapshot twice.
      if (graceTimer) clearTimeout(graceTimer);
      graceTimer = setTimeout(() => {
        graceTimer = null;
        if (!streamDelivering && !controller.signal.aborted) startPolling();
      }, STREAM_FIRST_FRAME_GRACE_MS);

      const onStreamFrame = () => {
        streamDelivering = true;
        clearPollTimer();
        if (graceTimer) {
          clearTimeout(graceTimer);
          graceTimer = null;
        }
        setTransport('stream');
        markDelivered();
      };

      eventSource.addEventListener('scanner-intelligence', (event) => {
        try {
          const snapshot = normalizeStreamSnapshot(JSON.parse((event as MessageEvent).data));
          if (!snapshot) throw new Error('Invalid scanner intelligence stream payload');
          applyNetworkSnapshot(snapshot);
          onStreamFrame();
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Unable to parse scanner intelligence stream');
        }
      });

      // The server re-checked the estate and nothing changed: record the
      // confirmation, keep the snapshot on screen untouched.
      eventSource.addEventListener('scanner-intelligence-unchanged', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data) as { generatedAt?: string; checkedAt?: string };
          setLastVerifiedAt(payload.generatedAt || payload.checkedAt || new Date().toISOString());
          onStreamFrame();
        } catch {
          /* a malformed confirmation carries no data to lose */
        }
      });

      eventSource.addEventListener('scanner-error', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data);
          setError(payload?.message || 'Scanner intelligence stream failed');
        } catch {
          setError('Scanner intelligence stream failed');
        }
      });

      eventSource.onerror = () => {
        eventSource?.close();
        eventSource = null;
        streamDelivering = false;
        setConnected(false);
        setTransport('polling');
        startPolling();
        if (!retryTimer && !controller.signal.aborted) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            connectStream();
          }, 15000);
        }
      };
    };

    if (live) {
      connectStream();
    } else {
      pollSnapshot();
    }

    return () => {
      controller.abort();
      eventSource?.close();
      clearPollTimer();
      if (retryTimer) clearTimeout(retryTimer);
      if (loadingTimer) clearTimeout(loadingTimer);
      if (graceTimer) clearTimeout(graceTimer);
      setConnected(false);
    };
  }, [applyNetworkSnapshot, authHeaders, cacheKey, token, live]);

  return {
    data,
    loading,
    error,
    connected,
    refresh,
    /** Where the snapshot on screen came from (`cache` is never presented as live). */
    source,
    /** True once the SERVER has answered (a snapshot or an error) — a cache does not count. */
    resolved: source === 'network' || error !== null,
    transport,
    lastVerifiedAt,
  };
}
