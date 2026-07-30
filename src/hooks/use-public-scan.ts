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
  scan: (target: string) => void;
  reset: () => void;
}

export function usePublicScan(): UsePublicScanResult {
  const [state, setState] = useState<PublicScanState>('idle');
  const [stages, setStages] = useState<PublicScanStage[]>(initialStages);
  const [report, setReport] = useState<PublicScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  const closeStream = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
  }, []);

  useEffect(() => closeStream, [closeStream]);

  const reset = useCallback(() => {
    closeStream();
    setState('idle');
    setStages(initialStages());
    setReport(null);
    setError(null);
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
      setState('scanning');
      setStages(initialStages());
      setReport(null);
      setError(null);

      const source = new EventSource(`/api/v1/public-scan/stream?target=${encodeURIComponent(trimmed)}`);
      sourceRef.current = source;

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

  const done = stages.filter((stage) => stage.state === 'complete' || stage.state === 'failed').length;
  const running = stages.some((stage) => stage.state === 'running') ? 0.5 : 0;
  const progress = Math.round(((done + running) / stages.length) * 100);

  return { state, stages, report, error, progress, scan, reset };
}

export type { PublicScanReport, PublicScanStage, PublicScanStageKey };
