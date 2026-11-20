'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { openAuthenticatedEventStream } from '@/lib/authenticated-event-stream';
import { isPublicScanUsage, type PublicScanUsage } from '@/lib/public-scan-usage';
import type {
  PublicScanReport,
  PublicScanStage,
  PublicScanStageKey,
} from '@/lib/scanner/public-scan/types';

export type PublicScanState = 'idle' | 'scanning' | 'complete' | 'error';

/**
 * A single measurement, delivered the moment the scanner made it.
 *
 * Mirrors `ScanObservation` on the server. It is redeclared rather than
 * imported so the client bundle never pulls a `node:tls`-rooted module graph in
 * behind a type import.
 */
export interface PublicScanObservation {
  surface: 'dns' | 'tls' | 'certificate' | 'headers' | 'ocsp' | 'quantum';
  label: string;
  detail: string;
  status: 'pass' | 'warning' | 'critical' | 'info';
  severity: 'none' | 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Headline word for the surface. Only primary observations carry one. */
  verdict?: string;
  postQuantum?: boolean;
  /** Real completion counts inside a multi-measurement phase. Never a timer. */
  progress?: { done: number; total: number };
  at: number;
}

const STAGE_TEMPLATE: Array<Pick<PublicScanStage, 'key' | 'label' | 'description'>> = [
  { key: 'dns', label: 'DNS Resolution', description: 'Resolving public records and CAA policy' },
  { key: 'tls', label: 'TLS Handshake', description: 'Negotiating protocols and cipher suites' },
  { key: 'certificate', label: 'Certificate Collection', description: 'Reading the served X.509 chain' },
  { key: 'headers', label: 'Security Header Analysis', description: 'Inspecting HTTP transport controls' },
  { key: 'quantum', label: 'Quantum Assessment', description: 'Scoring post-quantum exposure' },
  { key: 'report', label: 'Executive Report', description: 'Composing the executive assessment' },
];

function initialStages(): PublicScanStage[] {
  return STAGE_TEMPLATE.map((stage) => ({ ...stage, state: 'waiting' }));
}

/** This visitor's place in the server's waiting line. Present only while waiting. */
export interface PublicScanQueue {
  position: number;
  queueLength: number;
  /** An estimate from the server's measured scan durations — label it as one. */
  estimatedWaitSeconds: number;
  running: number;
  capacity: number;
  /** Client clock when this position arrived, so a countdown can run between updates. */
  receivedAt: number;
}

export interface PublicScanRefusal {
  code: string;
  message: string;
  /** Seconds until retrying can succeed, when the server knows. */
  retryAfterSeconds: number | null;
  receivedAt: number;
}

export interface UsePublicScanResult {
  state: PublicScanState;
  stages: PublicScanStage[];
  report: PublicScanReport | null;
  error: string | null;
  /** Set while the assessment waits for a free slot; null once it runs. */
  queue: PublicScanQueue | null;
  /** How many visitors are watching this one scan, when it is shared; else null. */
  sharedViewers: number | null;
  refusal: PublicScanRefusal | null;
  /** 0-100 across the six workflow stages. */
  progress: number;
  /** Live measurements, in the order the scanner made them. */
  observations: PublicScanObservation[];
  usage: PublicScanUsage | null;
  usageError: string | null;
  refreshUsage: () => void;
  scan: (target: string) => void;
  reset: () => void;
}

/** Guard against an unbounded array if a target somehow produces a long tail. */
const OBSERVATIONS_MAX = 200;

export function usePublicScan(token: string | null, accountId: string | null): UsePublicScanResult {
  const [state, setState] = useState<PublicScanState>('idle');
  const [stages, setStages] = useState<PublicScanStage[]>(initialStages);
  const [report, setReport] = useState<PublicScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queue, setQueue] = useState<PublicScanQueue | null>(null);
  const [sharedViewers, setSharedViewers] = useState<number | null>(null);
  const [refusal, setRefusal] = useState<PublicScanRefusal | null>(null);
  const [observations, setObservations] = useState<PublicScanObservation[]>([]);
  const [allowance, setAllowance] = useState<{ accountId: string; usage: PublicScanUsage } | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);
  const sourceRef = useRef<(() => void) | null>(null);
  const usageRequest = useRef<AbortController | null>(null);
  const usage = accountId && allowance?.accountId === accountId ? allowance.usage : null;

  const publishUsage = useCallback((value: unknown) => {
    if (!accountId || !isPublicScanUsage(value)) return false;
    usageRequest.current?.abort();
    setUsageError(null);
    setAllowance({ accountId, usage: value });
    return true;
  }, [accountId]);

  const refreshUsage = useCallback(() => {
    if (!token || !accountId) return;
    usageRequest.current?.abort();
    const controller = new AbortController();
    usageRequest.current = controller;
    setUsageError(null);
    void fetch('/api/v1/public-scan/usage', {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(18_000)]),
      redirect: 'error',
    }).then(async (response) => {
      if (!response.ok) {
        if (response.status === 401 && !controller.signal.aborted) {
          setAllowance(null);
          setUsageError('Your session has expired. Sign in again to run an assessment.');
          return;
        }
        throw new Error('Allowance unavailable');
      }
      const payload = await response.json();
      if (!isPublicScanUsage(payload.data)) throw new Error('Allowance unavailable');
      if (!controller.signal.aborted) setAllowance({ accountId, usage: payload.data });
    }).catch(() => {
      if (!controller.signal.aborted) setUsageError('Could not refresh your scan allowance. Try again.');
    });
  }, [accountId, token]);

  useEffect(() => {
    refreshUsage();
    const refreshVisible = () => { if (document.visibilityState === 'visible') refreshUsage(); };
    window.addEventListener('focus', refreshVisible);
    document.addEventListener('visibilitychange', refreshVisible);
    return () => {
      usageRequest.current?.abort();
      window.removeEventListener('focus', refreshVisible);
      document.removeEventListener('visibilitychange', refreshVisible);
    };
  }, [refreshUsage]);

  useEffect(() => {
    if (!usage) return;
    const untilReset = Math.max(1000, Date.parse(usage.resetAt) - Date.now() + 800);
    const delay = usage.inProgress ? Math.min(untilReset, 15_000) : untilReset;
    const timer = window.setTimeout(refreshUsage, delay);
    return () => window.clearTimeout(timer);
  }, [usage, refreshUsage]);
  /** Monotonic floor for the reported progress. Cleared at the start of a run. */
  const progressFloor = useRef(0);

  const closeStream = useCallback(() => {
    sourceRef.current?.();
    sourceRef.current = null;
  }, []);

  useEffect(() => closeStream, [closeStream]);

  const reset = useCallback(() => {
    closeStream();
    progressFloor.current = 0;
    setState('idle');
    setStages(initialStages());
    setReport(null);
    setError(null);
    setQueue(null);
    setSharedViewers(null);
    setRefusal(null);
    setObservations([]);
  }, [closeStream]);

  useEffect(() => {
    reset();
    setAllowance(null);
    setUsageError(null);
  }, [accountId, reset]);

  const scan = useCallback(
    (target: string) => {
      const trimmed = target.trim();
      if (!trimmed || !token) return;

      reset();
      setState('scanning');

      const fail = (message: string) => {
        setError(message);
        setQueue(null);
        setState('error');
        closeStream();
      };

      sourceRef.current = openAuthenticatedEventStream('/api/v1/public-scan/stream', token, {
        onEvent(name, data) {
          try {
            const payload = JSON.parse(data);
            switch (name) {
              case 'scan-queued':
                if (typeof payload.position === 'number') setQueue({ ...payload, receivedAt: Date.now() });
                break;
              case 'scan-started':
                setQueue(null);
                break;
              case 'scan-shared':
                if (typeof payload.viewers === 'number') setSharedViewers(payload.viewers);
                break;
              case 'observation':
                if (payload.surface && payload.label) {
                  setObservations((current) => [...current, payload as PublicScanObservation].slice(-OBSERVATIONS_MAX));
                }
                break;
              case 'stage':
                setStages((current) => current.map((stage) =>
                  stage.key === payload.stage.key ? { ...stage, ...payload.stage } : stage));
                break;
              case 'scan-complete':
                if (!payload.report) {
                  fail('The assessment report could not be read.');
                  break;
                }
                if (!publishUsage(payload.usage)) refreshUsage();
                setQueue(null);
                setReport(payload.report);
                setStages((current) => current.map((stage) => stage.state === 'waiting' || stage.state === 'running'
                  ? { ...stage, state: 'complete' }
                  : stage));
                setState('complete');
                closeStream();
                break;
              case 'error':
                if (!publishUsage(payload.usage)) refreshUsage();
                fail(payload.message || 'The assessment could not be completed.');
                break;
            }
          } catch {
            // Malformed frames are ignored. A missing terminal frame is a connection error.
          }
        },
        async onResponseError(response) {
          const payload = await response.json().catch(() => null);
          if (!sourceRef.current || sourceRef.current !== stop) return;
          const detail = {
            code: payload?.error?.code ?? 'REFUSED',
            message: payload?.error?.message ?? 'The assessment could not be started.',
            retryAfterSeconds: typeof payload?.error?.retryAfterSeconds === 'number' ? payload.error.retryAfterSeconds : null,
            receivedAt: Date.now(),
          };
          if (response.status === 401) {
            usageRequest.current?.abort();
            setAllowance(null);
          } else if (!publishUsage(payload?.usage)) refreshUsage();
          setRefusal(detail);
          fail(detail.message);
        },
        onError() {
          refreshUsage();
          fail('Connection to the assessment service was lost.');
        },
      }, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: trimmed }),
      });
      const stop = sourceRef.current;
    },
    [closeStream, publishUsage, refreshUsage, reset, token],
  );

  /*
   * Progress weighted by how much work each stage actually is.
   *
   * Counting the six stages equally made the bar jump to 33%, sit there for the
   * whole TLS phase — which is most of a scan — and then finish in one step. The
   * weights below are the measured shares of a real assessment, and the TLS
   * stage additionally advances WITHIN itself from the named-group completion
   * counts the engine streams. Every input is work already finished, so the bar
   * can neither run ahead of the scanner nor freeze while it is measuring.
   */
  const STAGE_WEIGHT: Record<PublicScanStageKey, number> = {
    dns: 10,
    tls: 55,
    certificate: 10,
    headers: 10,
    quantum: 10,
    report: 5,
  };

  const latestGroupProgress = (() => {
    for (let index = observations.length - 1; index >= 0; index -= 1) {
      const candidate = observations[index].progress;
      if (candidate && candidate.total > 0) return candidate;
    }
    return null;
  })();

  const totalWeight = Object.values(STAGE_WEIGHT).reduce((sum, weight) => sum + weight, 0);
  const earned = stages.reduce((sum, stage) => {
    const weight = STAGE_WEIGHT[stage.key] ?? 0;
    // `unavailable` is a settled stage — it will not do any more work — so it
    // earns its full weight. Leaving it out stalled the bar at ~15% for the
    // whole run against an unreachable endpoint.
    if (stage.state === 'complete' || stage.state === 'failed' || stage.state === 'unavailable') {
      return sum + weight;
    }
    if (stage.state !== 'running') return sum;
    // A running stage contributes what it has actually measured. Only the TLS
    // stage reports sub-progress; the rest are short enough that a half-credit
    // placeholder is honest about the uncertainty.
    if (stage.key !== 'tls') return sum + weight * 0.5;
    /* The TLS stage is more than half the assessment and reports its own real
       sub-progress once group probing starts. Before that only the protocol and
       cipher enumeration has finished, so it claims a small fixed share — a 0.5
       placeholder here asserted half the longest stage was done before a single
       group had been offered, and the bar then fell backwards when the true
       count arrived. */
    return sum + weight * (latestGroupProgress
      ? Math.max(0.1, Math.min(0.97, latestGroupProgress.done / latestGroupProgress.total))
      : 0.1);
  }, 0);
  const computed = Math.min(100, Math.round((earned / totalWeight) * 100));
  /* A progress bar that moves backwards reads as a fault in the scanner even
     when every number behind it is honest — a stage flipping from a placeholder
     to its real sub-progress can legitimately lower a weighted estimate. The
     reported value therefore only ever climbs within a run; `scan()` and
     `reset()` clear the floor. */
  if (state === 'complete') progressFloor.current = 100;
  else if (state === 'scanning' && computed > progressFloor.current) progressFloor.current = computed;
  const progress = state === 'scanning' || state === 'complete' ? progressFloor.current : computed;

  return { state, stages, report, error, queue, sharedViewers, refusal, progress, observations, usage, usageError, refreshUsage, scan, reset };
}

export type { PublicScanReport, PublicScanStage, PublicScanStageKey };
