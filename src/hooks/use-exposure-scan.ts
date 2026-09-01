'use client';

/**
 * Dev Exposure Assessment — client hook.
 *
 * Drives /api/v1/exposure over SSE. The server owns execution; this hook owns
 * the live ledger the operator watches.
 *
 * The SSE subscription is opened AFTER the POST returns a scan id, and the
 * server replays every event it has already emitted on connect — so a slow
 * subscriber still renders the complete ledger rather than joining midway
 * through and showing engines that appear to have never started.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  EngineRun,
  ExposureAssessment,
  ExposureFinding,
  ScanEvent,
  ScanExclusions,
} from '@/lib/scanner/exposure/types';
import { descriptorsForMode } from '@/lib/scanner/exposure/registry';
import { resolveProfile } from '@/lib/scanner/exposure/profiles';

export type DevScanState = 'idle' | 'starting' | 'scanning' | 'complete' | 'error' | 'cancelled';

export interface RepositoryValidation {
  ok: boolean;
  providerLabel?: string;
  defaultBranch?: string;
  visibility?: 'public' | 'private' | 'unknown';
  notice?: string;
  recommendation?: string;
  requiresToken?: boolean;
  ref?: { owner: string; repo: string; webUrl: string; provider: string; selfHosted: boolean };
}

export interface DevScanStartOptions {
  repositoryUrl?: string;
  branch?: string;
  connectionIds?: string[];
  namespaces?: string[];
  regions?: string[];
  image?: string;
  profileId: string;
  customEngines?: string[];
  exclusions?: ScanExclusions;
}

export interface UseExposureScanResult {
  state: DevScanState;
  scanId: string | null;
  runs: EngineRun[];
  findings: ExposureFinding[];
  assessment: ExposureAssessment | null;
  progress: number;
  currentStep: string | null;
  error: string | null;
  errorDetail: string | null;
  validation: RepositoryValidation | null;
  validating: boolean;

  validate: (url: string) => Promise<RepositoryValidation | null>;
  start: (options: DevScanStartOptions) => Promise<void>;
  cancel: () => Promise<void>;
  reset: () => void;
}

function authHeaders(): HeadersInit {
  const headers: HeadersInit = { 'Content-Type': 'application/json' };
  try {
    /* The platform stores the Supabase session under a project-scoped key; the
       exact key varies by project ref, so the token is found by shape rather
       than by a hardcoded name. A missing token is not an error — the anonymous
       endpoints work without one. */
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith('sb-') || !key.endsWith('-auth-token')) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw);
      const token = parsed?.access_token ?? parsed?.currentSession?.access_token;
      if (token) {
        (headers as Record<string, string>).Authorization = `Bearer ${token}`;
        break;
      }
    }
  } catch {
    /* no session available — the anonymous path still works */
  }
  return headers;
}

export function useExposureScan(): UseExposureScanResult {
  const [state, setState] = useState<DevScanState>('idle');
  const [scanId, setScanId] = useState<string | null>(null);
  const [runs, setRuns] = useState<EngineRun[]>([]);
  const [findings, setFindings] = useState<ExposureFinding[]>([]);
  const [assessment, setAssessment] = useState<ExposureAssessment | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [validation, setValidation] = useState<RepositoryValidation | null>(null);
  const [validating, setValidating] = useState(false);

  const sourceRef = useRef<EventSource | null>(null);
  const progressFloor = useRef(0);

  const closeStream = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
  }, []);

  useEffect(() => closeStream, [closeStream]);

  const validate = useCallback(async (url: string): Promise<RepositoryValidation | null> => {
    if (!url.trim()) {
      setValidation(null);
      return null;
    }
    setValidating(true);
    try {
      const response = await fetch('/api/v1/exposure/dev/validate', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ url: url.trim() }),
      });
      const payload = await response.json();
      if (!response.ok) {
        const result: RepositoryValidation = {
          ok: false,
          notice: payload?.error?.message ?? 'The repository could not be validated.',
          recommendation: typeof payload?.error?.detail === 'string' ? payload.error.detail : undefined,
        };
        setValidation(result);
        return result;
      }
      setValidation(payload.data);
      return payload.data as RepositoryValidation;
    } catch (caught) {
      const result: RepositoryValidation = { ok: false, notice: (caught as Error).message };
      setValidation(result);
      return result;
    } finally {
      setValidating(false);
    }
  }, []);

  const start = useCallback(
    async (options: DevScanStartOptions) => {
      closeStream();
      progressFloor.current = 0;
      setState('starting');
      setError(null);
      setErrorDetail(null);
      setFindings([]);
      setAssessment(null);
      setProgress(0);
      setCurrentStep('Queueing assessment…');

      /* The ledger is seeded from the SAME profile resolution the server will
         perform, so every selected engine has a row before the first event
         arrives. Without this the rail materialises engine by engine, which
         makes a scan look like it is discovering its own plan as it goes. */
      const { engines } = resolveProfile('dev', options.profileId, options.customEngines ?? []);
      const descriptors = new Map(descriptorsForMode('dev').map((descriptor) => [descriptor.id, descriptor]));
      setRuns([
        {
          engineId: 'repository-discovery',
          label: 'Repository Discovery',
          state: 'pending',
          progress: 0,
          startedAt: null,
          completedAt: null,
          findingCount: 0,
        },
        ...engines.map((engineId) => ({
          engineId,
          label: descriptors.get(engineId)?.label ?? engineId,
          state: 'pending' as const,
          progress: 0,
          startedAt: null,
          completedAt: null,
          findingCount: 0,
        })),
      ]);

      let handle: { scanId: string } | null = null;
      try {
        const response = await fetch('/api/v1/exposure/scans', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify(options),
        });
        const payload = await response.json();
        if (!response.ok) {
          setError(payload?.error?.message ?? 'The assessment could not be started.');
          setErrorDetail(typeof payload?.error?.detail === 'string' ? payload.error.detail : null);
          setState('error');
          setCurrentStep(null);
          return;
        }
        handle = payload.data;
      } catch (caught) {
        setError((caught as Error).message || 'The assessment could not be started.');
        setState('error');
        setCurrentStep(null);
        return;
      }

      if (!handle?.scanId) {
        setError('The scanner did not return a scan id.');
        setState('error');
        return;
      }

      setScanId(handle.scanId);
      setState('scanning');

      const source = new EventSource(`/api/v1/exposure/scans/${encodeURIComponent(handle.scanId)}/events`);
      sourceRef.current = source;

      const applyEvent = (event: ScanEvent) => {
        if (typeof event.progress === 'number' && event.progress > progressFloor.current) {
          progressFloor.current = event.progress;
          setProgress(event.progress);
        }

        switch (event.event) {
          case 'engine.started':
          case 'engine.progress':
          case 'engine.completed':
          case 'engine.failed': {
            if (!event.engineId) break;
            setRuns((current) => {
              const exists = current.some((run) => run.engineId === event.engineId);
              const next = exists
                ? current
                : [
                    ...current,
                    {
                      engineId: event.engineId!,
                      label: event.engineLabel ?? event.engineId!,
                      state: 'pending' as const,
                      progress: 0,
                      startedAt: null,
                      completedAt: null,
                      findingCount: 0,
                    },
                  ];
              return next.map((run) =>
                run.engineId === event.engineId
                  ? {
                      ...run,
                      label: event.engineLabel ?? run.label,
                      state: event.state ?? run.state,
                      step: event.step ?? run.step,
                      units: event.units ?? run.units,
                      detail: event.detail ?? run.detail,
                      progress: event.state && event.state !== 'running' ? 100 : run.progress,
                    }
                  : run,
              );
            });
            if (event.step) setCurrentStep(`${event.engineLabel ?? event.engineId}: ${event.step}`);
            break;
          }

          case 'finding.discovered':
            if (event.finding) {
              setFindings((current) => [...current, event.finding as ExposureFinding]);
              setRuns((current) =>
                current.map((run) => (run.engineId === event.engineId ? { ...run, findingCount: run.findingCount + 1 } : run)),
              );
            }
            break;

          case 'scan.completed':
          case 'scan.cancelled':
          case 'scan.failed':
            if (event.result) {
              setAssessment(event.result);
              setRuns(event.result.task.runs);
              setFindings(event.result.findings);
            }
            if (event.event === 'scan.failed' && !event.result) {
              setError(event.message ?? 'The assessment failed.');
              setErrorDetail(event.detail ?? null);
              setState('error');
            } else {
              setState(event.event === 'scan.cancelled' ? 'cancelled' : 'complete');
            }
            setProgress(100);
            progressFloor.current = 100;
            setCurrentStep(null);
            closeStream();
            break;

          default:
            if (event.message) setCurrentStep(event.message);
            break;
        }
      };

      const names: ScanEvent['event'][] = [
        'scan.created', 'scan.started', 'engine.started', 'engine.progress', 'finding.discovered',
        'evidence.collected', 'engine.completed', 'engine.failed', 'correlation.completed',
        'scoring.completed', 'scan.completed', 'scan.cancelled', 'scan.failed',
      ];
      for (const name of names) {
        source.addEventListener(name, (raw) => {
          try {
            applyEvent(JSON.parse((raw as MessageEvent).data) as ScanEvent);
          } catch {
            /* a malformed frame is superseded by the next one */
          }
        });
      }

      source.addEventListener('error', () => {
        if (source.readyState !== EventSource.CLOSED) return;
        // A transport drop after completion is normal; before it is not.
        setState((current) => {
          if (current !== 'scanning') return current;
          setError('The connection to the assessment stream was lost. The scan may still be running — reload to reconnect.');
          return 'error';
        });
        closeStream();
      });
    },
    [closeStream],
  );

  const cancel = useCallback(async () => {
    if (!scanId) return;
    setCurrentStep('Cancelling…');
    try {
      await fetch(`/api/v1/exposure/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST', headers: authHeaders() });
    } catch {
      /* the scan will still hit its own budget */
    }
  }, [scanId]);

  const reset = useCallback(() => {
    closeStream();
    progressFloor.current = 0;
    setState('idle');
    setScanId(null);
    setRuns([]);
    setFindings([]);
    setAssessment(null);
    setProgress(0);
    setCurrentStep(null);
    setError(null);
    setErrorDetail(null);
    setValidation(null);
  }, [closeStream]);

  return {
    state,
    scanId,
    runs,
    findings,
    assessment,
    progress,
    currentStep,
    error,
    errorDetail,
    validation,
    validating,
    validate,
    start,
    cancel,
    reset,
  };
}

/* ─────────────────────────────────────────────────────────────── connections ─ */

export interface PublicConnectionView {
  id: string;
  kind: string;
  label: string;
  endpoint: string;
  scope: { namespaces?: string[]; regions?: string[] };
  status: string;
  statusDetail: string;
  grantedPermissions: string[];
  deniedPermissions: string[];
  lastVerifiedAt: string | null;
  readOnly: true;
}

/** Connections are authenticated-only; an anonymous caller gets an empty list. */
export function useExposureConnections() {
  const [connections, setConnections] = useState<PublicConnectionView[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/exposure/dev/connections', { headers: authHeaders() });
      if (!response.ok) {
        setConnections([]);
        return;
      }
      const payload = await response.json();
      setConnections(payload.data?.connections ?? []);
      setNotice(payload.data?.persistence ?? null);
    } catch {
      setConnections([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { connections, notice, loading, refresh };
}
