/**
 * Local scan Web Worker (§57).
 *
 * §57: "Local scans must not freeze the browser."
 *
 * The corpus is collected on the main thread (the File System Access API's
 * handles are not transferable), then the FILE CONTENTS are posted here and the
 * engines run off the main thread. A 6,000-file repository takes several
 * seconds of solid regex work; on the main thread that is a frozen tab, and in
 * a worker it is a responsive page with a live progress rail.
 *
 * The worker receives plain data and returns plain data. It has no network
 * access of its own and makes no requests — which is what makes the
 * local-only guarantee structural rather than a policy.
 */

/// <reference lib="webworker" />

import { runExposureScan } from '../orchestrator';
import type { ScanEvent, ScanExclusions, ScanTarget } from '../types';
import type { WorkspaceFile } from '../engine-contract';
import { emptyWorkspace } from '../engine-contract';

export interface LocalScanRequest {
  type: 'start';
  scanId: string;
  profileId: string;
  engineIds: string[];
  files: WorkspaceFile[];
  target: ScanTarget;
  exclusions: ScanExclusions;
  budgetMs?: number;
}

export interface LocalScanCancel {
  type: 'cancel';
}

export type LocalScanMessage = LocalScanRequest | LocalScanCancel;

export type LocalScanResponse =
  | { type: 'event'; event: ScanEvent }
  | { type: 'error'; message: string };

let cancelled = false;

self.addEventListener('message', async (message: MessageEvent<LocalScanMessage>) => {
  const data = message.data;

  if (data?.type === 'cancel') {
    cancelled = true;
    return;
  }

  if (data?.type !== 'start') return;
  cancelled = false;

  try {
    const workspace = emptyWorkspace();
    workspace.files = data.files;

    await runExposureScan({
      scanId: data.scanId,
      mode: 'local',
      target: data.target,
      profileId: data.profileId,
      engineIds: data.engineIds,
      workspace,
      exclusions: data.exclusions,
      localOnly: true,
      budgetMs: data.budgetMs ?? 240_000,
      // Two at a time in a worker: the engines are CPU-bound regex passes over
      // the same corpus, so more parallelism buys nothing on one thread and
      // only delays the first finding reaching the UI.
      concurrency: 2,
      isCancelled: () => cancelled,
      onEvent: (event) => {
        (self as unknown as Worker).postMessage({ type: 'event', event } satisfies LocalScanResponse);
      },
    });
  } catch (error) {
    (self as unknown as Worker).postMessage({
      type: 'error',
      message: (error as Error).message || 'The local assessment failed.',
    } satisfies LocalScanResponse);
  }
});
