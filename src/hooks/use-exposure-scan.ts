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
import { useExposureAccess } from '@/hooks/use-exposure-access';
import {
  appendTelemetry,
  toTelemetryFrame,
  type ScanTelemetryFrame,
} from '@/lib/scanner/exposure/telemetry-frame';

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
  /**
   * Bounded console of the REAL SSE frames this scan emitted, newest last.
   * Built by the same translator the Local worker path uses, so one scan reads
   * identically wherever it ran.
   */
  telemetry: ScanTelemetryFrame[];
  /** Epoch ms the operator started the run. Null until they do. */
  startedAt: number | null;
  /** True while the EventSource is attached and delivering frames. */
  streamOpen: boolean;

  validate: (url: string) => Promise<RepositoryValidation | null>;
  start: (options: DevScanStartOptions) => Promise<void>;
  cancel: () => Promise<void>;
  reset: () => void;
}

/**
 * The caller's Supabase access token, or null.
 *
 * The platform stores the session under a project-scoped key whose exact name
 * varies by project ref, so the token is found by shape rather than by a
 * hardcoded name. A missing token is not an error — the anonymous endpoints
 * work without one.
 */
function accessToken(): string | null {
  try {
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (!key || !key.startsWith('sb-') || !key.endsWith('-auth-token')) continue;
      const raw = localStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw);
      const token = parsed?.access_token ?? parsed?.currentSession?.access_token;
      if (typeof token === 'string' && token.length > 0) return token;
    }
  } catch {
    /* no session available — the anonymous path still works */
  }
  return null;
}

function authHeaders(): HeadersInit {
  const headers: HeadersInit = { 'Content-Type': 'application/json' };
  const token = accessToken();
  if (token) (headers as Record<string, string>).Authorization = `Bearer ${token}`;
  return headers;
}

export function useExposureScan(): UseExposureScanResult {
  /**
   * Entitlement, resolved in the hook rather than in one component.
   *
   * Dev scans DO reach the server, and `requireMode('dev')` refuses an
   * unentitled caller with a 401 — that remains the real control, and this
   * cannot weaken it. What this adds is an honest refusal before the request:
   * without it an unentitled caller sees a raw authorisation failure from the
   * stream instead of being told which plan includes the mode.
   */
  const access = useExposureAccess('dev');
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
  const [telemetry, setTelemetry] = useState<ScanTelemetryFrame[]>([]);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [streamOpen, setStreamOpen] = useState(false);

  const sourceRef = useRef<EventSource | null>(null);
  const progressFloor = useRef(0);
  /** Sequence belongs to the stream, not the event — see telemetry-frame.ts. */
  const telemetrySeq = useRef(0);
  /**
   * The server replays every event it has already emitted when a subscriber
   * connects. Replayed frames must not be appended twice, so the console is
   * keyed on the event identity rather than on arrival.
   */
  const seenFrames = useRef<Set<string>>(new Set());

  /** Live state, readable from stream callbacks without re-binding them. */
  const stateRef = useRef<DevScanState>('idle');
  stateRef.current = state;
  const pollTimer = useRef<number | null>(null);

  const closeStream = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    setStreamOpen(false);
  }, []);

  const stopPolling = useCallback(() => {
    if (pollTimer.current === null) return;
    window.clearTimeout(pollTimer.current);
    pollTimer.current = null;
  }, []);

  /**
   * Follow a scan whose event stream went away.
   *
   * The scan runs on the SERVER. Losing the subscription says nothing about the
   * scan, so abandoning the run — and telling the operator to reload, which
   * cannot help because the scan id only ever lived in this component — throws
   * away work that is still completing. This polls the job endpoint instead,
   * which is an ordinary authenticated fetch and unaffected by whatever broke
   * the stream, and applies the result when it lands.
   */
  const followByPolling = useCallback((scanIdToFollow: string) => {
    if (pollTimer.current !== null) return;
    setCurrentStep('Live stream interrupted — following the assessment by polling.');

    const POLL_MS = 3_000;
    /* The server enforces its own scan budget; this is only the point past
       which the client stops asking, and it says so rather than hanging. */
    const deadline = Date.now() + 15 * 60_000;
    let consecutiveFailures = 0;

    const settle = (next: DevScanState, message?: string) => {
      stopPolling();
      setCurrentStep(null);
      if (message) setError(message);
      setState(next);
    };

    const tick = async () => {
      pollTimer.current = null;
      if (Date.now() > deadline) {
        settle('error', 'The assessment did not report a result within 15 minutes and is no longer being followed. Start it again, or check the scan history.');
        return;
      }

      try {
        const response = await fetch(`/api/v1/exposure/scans/${encodeURIComponent(scanIdToFollow)}`, {
          headers: authHeaders(),
        });
        if (!response.ok) throw new Error(`status ${response.status}`);
        const payload = await response.json();
        const job = payload?.data;
        consecutiveFailures = 0;

        if (job?.assessment) {
          const assessed = job.assessment as ExposureAssessment;
          setAssessment(assessed);
          setRuns(assessed.task.runs);
          setFindings(assessed.findings);
          setProgress(100);
          progressFloor.current = 100;
          settle(assessed.task.status === 'cancelled' ? 'cancelled' : 'complete');
          return;
        }
        if (job?.status === 'failed') {
          settle('error', job.error ?? 'The assessment failed.');
          return;
        }
        if (job?.status === 'cancelled') {
          settle('cancelled');
          return;
        }
      } catch {
        consecutiveFailures += 1;
        if (consecutiveFailures >= 5) {
          settle('error', 'The assessment stream was lost and the scan could not be reached to follow it. Start the assessment again.');
          return;
        }
      }

      pollTimer.current = window.setTimeout(() => void tick(), POLL_MS);
    };

    pollTimer.current = window.setTimeout(() => void tick(), POLL_MS);
  }, [stopPolling]);

  useEffect(() => () => {
    closeStream();
    stopPolling();
  }, [closeStream, stopPolling]);

  const validate = useCallback(async (url: string): Promise<RepositoryValidation | null> => {
    if (!url.trim()) {
      setValidation(null);
      return null;
    }
    /* The server refuses this too (`requireMode('dev')` — it resolves the
       repository through a platform adapter). Refusing here as well is not
       redundancy for its own sake: it turns a raw 401/403 body into the plan
       message the operator can act on, and spends no request doing it. */
    if (!access.allowed) {
      const result: RepositoryValidation = {
        ok: false,
        notice: access.message
          || (access.loading
            ? 'Your plan is still being verified. Try again in a moment.'
            : 'Development assessment requires an active plan that includes it.'),
      };
      setValidation(result);
      return result;
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
  }, [access.allowed, access.loading, access.message]);

  const start = useCallback(
    async (options: DevScanStartOptions) => {
      /* Refused before the request. The server refuses it too — this only
         decides whether the operator reads a plan message or a 401.
         Fails CLOSED while the entitlement is still resolving: the panel shows
         a skeleton until it clears, so nothing legitimate calls this in that
         window, and admitting the caller "because we do not know yet" would
         hold the gate open for a billing round-trip. */
      if (!access.allowed) {
        setError(
          access.message
            || (access.loading
              ? 'Your plan is still being verified. Try again in a moment.'
              : 'Development assessment requires an active plan that includes it.'),
        );
        setErrorDetail(null);
        setState('error');
        return;
      }

      closeStream();
      /* A new run supersedes any recovery poll still following the last one. */
      stopPolling();
      progressFloor.current = 0;
      setState('starting');
      setError(null);
      setErrorDetail(null);
      setFindings([]);
      setAssessment(null);
      setProgress(0);
      setTelemetry([]);
      telemetrySeq.current = 0;
      seenFrames.current = new Set();
      setStartedAt(Date.now());
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

      /* Bound to a const so the stream callbacks below can rely on it: TypeScript
         does not carry the null-narrowing of a `let` into a nested closure. */
      const startedScanId = handle.scanId;
      setScanId(startedScanId);
      setState('scanning');

      /* EventSource has no way to send an Authorization header, so the token
         travels in the query string — the same contract every other
         authenticated stream on this platform uses. Sending nothing means the
         server refuses the subscription with a 401 that the browser treats as
         fatal, which reads to the operator as "the connection was lost" even
         though the scan is running perfectly well. */
      const streamToken = accessToken();
      const streamUrl = `/api/v1/exposure/scans/${encodeURIComponent(startedScanId)}/events${
        streamToken ? `?token=${encodeURIComponent(streamToken)}` : ''
      }`;
      const source = new EventSource(streamUrl);
      sourceRef.current = source;
      setStreamOpen(true);

      const applyEvent = (event: ScanEvent) => {
        /* Console first, interpretation second — the feed records the stream,
           it does not paraphrase the state the stream produced. Replays are
           collapsed on event identity so a reconnect never doubles the log. */
        const identity = `${event.event}|${event.timestamp}|${event.engineId ?? ''}|${event.finding?.id ?? ''}|${event.step ?? ''}`;
        if (!seenFrames.current.has(identity)) {
          seenFrames.current.add(identity);
          telemetrySeq.current += 1;
          const frame = toTelemetryFrame(event, telemetrySeq.current);
          if (frame) setTelemetry((current) => appendTelemetry(current, frame));
        }

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
        /* CONNECTING means the browser is retrying on its own; only CLOSED is
           final. A drop after the terminal frame is normal and expected. */
        if (source.readyState !== EventSource.CLOSED) return;
        closeStream();
        if (stateRef.current !== 'scanning' && stateRef.current !== 'starting') return;
        followByPolling(startedScanId);
      });
    },
    [closeStream, followByPolling, stopPolling, access.allowed, access.loading, access.message],
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
    stopPolling();
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
    setTelemetry([]);
    telemetrySeq.current = 0;
    seenFrames.current = new Set();
    setStartedAt(null);
  }, [closeStream, stopPolling]);

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
    telemetry,
    startedAt,
    streamOpen,
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
  const access = useExposureAccess('dev');
  const [connections, setConnections] = useState<PublicConnectionView[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    /* `/dev/connections` is gated to Pro server-side, so an unentitled tab that
       calls it earns a 403 and nothing else. Skipping the request keeps the
       locked panel silent rather than having it fail in the background. */
    if (!access.allowed) {
      setConnections([]);
      return;
    }
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
  }, [access.allowed]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { connections, notice, loading, refresh };
}
