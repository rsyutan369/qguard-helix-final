'use client';

/**
 * Local Exposure Assessment — client hook.
 *
 * Owns the LOCAL mode lifecycle end to end: authorisation, collection,
 * worker-backed execution, live engine ledger, cancellation, and the completed
 * assessment.
 *
 * PRIVACY, structurally (§43): every file this hook touches goes from the OS
 * picker to a Web Worker in the same tab. There is no fetch, no upload and no
 * persistence in this module. The only thing that can ever leave the device is
 * the sanitised assessment, and only when the user explicitly syncs it — which
 * is a separate, opt-in call on the authenticated dashboard.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  EngineRun,
  ExposureAssessment,
  ExposureFinding,
  ScanEvent,
  ScanExclusions,
} from '@/lib/scanner/exposure/types';
import { defaultExclusions } from '@/lib/scanner/exposure/types';
import type { WorkspaceFile } from '@/lib/scanner/exposure/engine-contract';
import {
  collectFromDirectoryHandle,
  collectFromFileList,
  fingerprintProject,
  requestDirectory,
  supportsDirectoryInput,
  supportsDirectoryPicker,
  type CollectionResult,
  type ProjectFingerprint,
} from '@/lib/scanner/exposure/local/fs-collector';
import { compileExclusions } from '@/lib/scanner/exposure/orchestrator';
import { deriveFacets } from '@/lib/scanner/exposure/content/file-discovery';
import { planScan, resolveProfile, type ScanPlan } from '@/lib/scanner/exposure/profiles';
import { descriptorsForMode } from '@/lib/scanner/exposure/registry';

export type LocalScanState = 'idle' | 'authorizing' | 'collecting' | 'ready' | 'scanning' | 'complete' | 'error' | 'cancelled';

export interface UseLocalScanResult {
  state: LocalScanState;
  /** Browser capability, so the UI never offers a picker that does not exist. */
  capability: { picker: boolean; input: boolean; worker: boolean };
  /** What the user authorised, once they have. */
  fingerprint: ProjectFingerprint | null;
  collection: CollectionResult | null;
  /** The planner's proposal for the selected target. */
  plan: ScanPlan | null;
  /** Live ledger, one row per selected engine. */
  runs: EngineRun[];
  findings: ExposureFinding[];
  assessment: ExposureAssessment | null;
  progress: number;
  /** The engine currently reporting, for the status line. */
  currentStep: string | null;
  error: string | null;
  /** Collection limitations, surfaced before the scan starts. */
  limitations: Array<{ dimension: string; reason: string }>;

  selectDirectory: () => Promise<void>;
  selectFiles: (files: FileList | File[]) => Promise<void>;
  start: (options: { profileId: string; customEngines?: string[]; exclusions?: ScanExclusions }) => void;
  cancel: () => void;
  reset: () => void;
}

const WORKER_SUPPORTED = typeof window !== 'undefined' && typeof Worker !== 'undefined';

export function useLocalScan(): UseLocalScanResult {
  const [state, setState] = useState<LocalScanState>('idle');
  const [collection, setCollection] = useState<CollectionResult | null>(null);
  const [fingerprint, setFingerprint] = useState<ProjectFingerprint | null>(null);
  const [plan, setPlan] = useState<ScanPlan | null>(null);
  const [runs, setRuns] = useState<EngineRun[]>([]);
  const [findings, setFindings] = useState<ExposureFinding[]>([]);
  const [assessment, setAssessment] = useState<ExposureAssessment | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limitations, setLimitations] = useState<Array<{ dimension: string; reason: string }>>([]);

  const workerRef = useRef<Worker | null>(null);
  /** Monotonic floor — a progress bar that goes backwards reads as a fault. */
  const progressFloor = useRef(0);

  const capability = useMemo(
    () => ({
      picker: supportsDirectoryPicker(),
      input: supportsDirectoryInput(),
      worker: WORKER_SUPPORTED,
    }),
    [],
  );

  const terminateWorker = useCallback(() => {
    workerRef.current?.terminate();
    workerRef.current = null;
  }, []);

  useEffect(() => terminateWorker, [terminateWorker]);

  const ingest = useCallback((result: CollectionResult) => {
    setCollection(result);
    setFingerprint(fingerprintProject(result));
    setLimitations(result.limitations);
    setPlan(planScan('local', deriveFacets(result.files)));
    setState('ready');
  }, []);

  const selectDirectory = useCallback(async () => {
    setError(null);
    setState('authorizing');
    try {
      const handle = await requestDirectory();
      if (!handle) {
        setState(collection ? 'ready' : 'idle');
        return;
      }
      setState('collecting');
      const result = await collectFromDirectoryHandle(handle, {
        onProgress: ({ discovered, current }) => setCurrentStep(`Reading ${discovered} files — ${current}`),
      });
      setCurrentStep(null);
      ingest(result);
    } catch (caught) {
      setCurrentStep(null);
      setError((caught as Error).message || 'The selected folder could not be read.');
      setState('error');
    }
  }, [collection, ingest]);

  const selectFiles = useCallback(
    async (files: FileList | File[]) => {
      setError(null);
      setState('collecting');
      try {
        const result = await collectFromFileList(files, {
          onProgress: ({ discovered, current }) => setCurrentStep(`Reading ${discovered} files — ${current}`),
        });
        setCurrentStep(null);
        ingest(result);
      } catch (caught) {
        setCurrentStep(null);
        setError((caught as Error).message || 'The selected files could not be read.');
        setState('error');
      }
    },
    [ingest],
  );

  const start = useCallback(
    ({ profileId, customEngines = [], exclusions }: { profileId: string; customEngines?: string[]; exclusions?: ScanExclusions }) => {
      if (!collection) {
        setError('Authorise a folder or select files before starting the assessment.');
        setState('error');
        return;
      }
      if (!WORKER_SUPPORTED) {
        setError('This browser does not support Web Workers, which the local scanner requires in order to run without freezing the page.');
        setState('error');
        return;
      }

      const resolvedExclusions = exclusions ?? defaultExclusions();
      const { engines } = resolveProfile('local', profileId, customEngines);
      if (engines.length === 0) {
        setError('Select at least one engine to run.');
        setState('error');
        return;
      }

      const descriptors = new Map(descriptorsForMode('local').map((descriptor) => [descriptor.id, descriptor]));
      setRuns(
        engines.map((engineId) => ({
          engineId,
          label: descriptors.get(engineId)?.label ?? engineId,
          state: 'pending' as const,
          progress: 0,
          startedAt: null,
          completedAt: null,
          findingCount: 0,
        })),
      );
      setFindings([]);
      setAssessment(null);
      setError(null);
      setProgress(0);
      progressFloor.current = 0;
      setState('scanning');

      terminateWorker();
      const worker = new Worker(new URL('../lib/scanner/exposure/local/local-scan.worker.ts', import.meta.url), {
        type: 'module',
      });
      workerRef.current = worker;

      const isExcluded = compileExclusions(resolvedExclusions);
      const payload: WorkspaceFile[] = collection.files.filter((file) => !isExcluded(file.path));

      worker.addEventListener('message', (message: MessageEvent<{ type: string; event?: ScanEvent; message?: string }>) => {
        const data = message.data;
        if (data.type === 'error') {
          setError(data.message ?? 'The local assessment failed.');
          setState('error');
          terminateWorker();
          return;
        }
        if (data.type !== 'event' || !data.event) return;
        const event = data.event;

        if (typeof event.progress === 'number' && event.progress > progressFloor.current) {
          progressFloor.current = event.progress;
          setProgress(event.progress);
        }

        switch (event.event) {
          case 'engine.started':
          case 'engine.progress':
          case 'engine.completed':
          case 'engine.failed':
            if (!event.engineId) break;
            setRuns((current) =>
              current.map((run) =>
                run.engineId === event.engineId
                  ? {
                      ...run,
                      state: event.state ?? run.state,
                      step: event.step ?? run.step,
                      units: event.units ?? run.units,
                      detail: event.detail ?? run.detail,
                      progress: event.state && event.state !== 'running' ? 100 : run.progress,
                    }
                  : run,
              ),
            );
            if (event.step) setCurrentStep(`${event.engineLabel}: ${event.step}`);
            break;

          case 'finding.discovered':
            if (event.finding) {
              setFindings((current) => [...current, event.finding as ExposureFinding]);
              setRuns((current) =>
                current.map((run) =>
                  run.engineId === event.engineId ? { ...run, findingCount: run.findingCount + 1 } : run,
                ),
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
            setProgress(100);
            progressFloor.current = 100;
            setCurrentStep(null);
            setState(event.event === 'scan.cancelled' ? 'cancelled' : 'complete');
            terminateWorker();
            break;

          default:
            break;
        }
      });

      worker.addEventListener('error', (event) => {
        setError(event.message || 'The local scanner worker failed to start.');
        setState('error');
        terminateWorker();
      });

      worker.postMessage({
        type: 'start',
        scanId: `local-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
        profileId,
        engineIds: engines,
        files: payload,
        exclusions: resolvedExclusions,
        target: {
          kind: 'local',
          label: collection.rootName,
          rootName: collection.rootName,
          fileCount: payload.length,
          viaAgent: false,
        },
      });
    },
    [collection, terminateWorker],
  );

  const cancel = useCallback(() => {
    workerRef.current?.postMessage({ type: 'cancel' });
    setCurrentStep('Cancelling…');
  }, []);

  const reset = useCallback(() => {
    terminateWorker();
    progressFloor.current = 0;
    setState('idle');
    setCollection(null);
    setFingerprint(null);
    setPlan(null);
    setRuns([]);
    setFindings([]);
    setAssessment(null);
    setProgress(0);
    setCurrentStep(null);
    setError(null);
    setLimitations([]);
  }, [terminateWorker]);

  return {
    state,
    capability,
    fingerprint,
    collection,
    plan,
    runs,
    findings,
    assessment,
    progress,
    currentStep,
    error,
    limitations,
    selectDirectory,
    selectFiles,
    start,
    cancel,
    reset,
  };
}
