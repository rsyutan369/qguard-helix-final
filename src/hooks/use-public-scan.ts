'use client';

/**
 * Public Quantum Exposure Assessment™ — client hook.
 *
 * Drives /api/v1/public-scan/stream over SSE so the workflow rail animates in
 * real time, then holds the completed report. No authentication is involved:
 * this endpoint is deliberately anonymous.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
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

export interface UsePublicScanResult {
  state: PublicScanState;
  stages: PublicScanStage[];
  report: PublicScanReport | null;
  error: string | null;
  /** 0-100 across the six workflow stages. */
  progress: number;
  /** Live measurements, in the order the scanner made them. */
  observations: PublicScanObservation[];
  scan: (target: string) => void;
  reset: () => void;
}

/** Guard against an unbounded array if a target somehow produces a long tail. */
const OBSERVATIONS_MAX = 200;

export function usePublicScan(): UsePublicScanResult {
  const [state, setState] = useState<PublicScanState>('idle');
  const [stages, setStages] = useState<PublicScanStage[]>(initialStages);
  const [report, setReport] = useState<PublicScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [observations, setObservations] = useState<PublicScanObservation[]>([]);
  const sourceRef = useRef<EventSource | null>(null);
  /** Monotonic floor for the reported progress. Cleared at the start of a run. */
  const progressFloor = useRef(0);

  const closeStream = useCallback(() => {
    sourceRef.current?.close();
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
    setObservations([]);
  }, [closeStream]);

  const scan = useCallback(
    (target: string) => {
      const trimmed = target.trim();
      if (!trimmed) {
        setError('Enter a domain or https:// URL to assess.');
        setState('error');
        return;
      }

      closeStream();
      progressFloor.current = 0;
      setState('scanning');
      setStages(initialStages());
      setReport(null);
      setError(null);
      setObservations([]);

      const source = new EventSource(`/api/v1/public-scan/stream?target=${encodeURIComponent(trimmed)}`);
      sourceRef.current = source;

      source.addEventListener('observation', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data) as PublicScanObservation;
          if (!payload?.surface || !payload.label) return;
          setObservations((current) => [...current, payload].slice(-OBSERVATIONS_MAX));
        } catch {
          /* malformed frame — the scan continues, the report is authoritative */
        }
      });

      source.addEventListener('stage', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data) as { stage: PublicScanStage };
          setStages((current) =>
            current.map((stage) => (stage.key === payload.stage.key ? { ...stage, ...payload.stage } : stage)),
          );
        } catch {
          /* malformed frame — the next event supersedes it */
        }
      });

      source.addEventListener('scan-complete', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data) as { report: PublicScanReport };
          setReport(payload.report);
          setStages((current) =>
            current.map((stage) => (stage.state === 'waiting' || stage.state === 'running'
              ? { ...stage, state: 'complete' }
              : stage)),
          );
          setState('complete');
        } catch {
          setError('The assessment completed but the report could not be read.');
          setState('error');
        }
        closeStream();
      });

      source.addEventListener('error', (event) => {
        // Distinguish a server-sent `error` event (has data) from a transport drop.
        const data = (event as MessageEvent).data;
        if (typeof data === 'string' && data) {
          try {
            const payload = JSON.parse(data) as { message?: string };
            setError(payload.message || 'The assessment could not be completed.');
          } catch {
            setError('The assessment could not be completed.');
          }
        } else if (source.readyState === EventSource.CLOSED) {
          setError((current) => current ?? 'Connection to the assessment service was lost.');
        } else {
          return;
        }
        setState('error');
        closeStream();
      });
    },
    [closeStream],
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
    if (stage.state === 'complete' || stage.state === 'failed') return sum + weight;
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

  return { state, stages, report, error, progress, observations, scan, reset };
}

export type { PublicScanReport, PublicScanStage, PublicScanStageKey };
