/**
 * Dashboard Scanner — assessment session persistence.
 *
 * An enterprise assessment is long-running and is reviewed over minutes, not
 * seconds. Leaving the page to check an asset in CBOM, switching to another
 * browser tab, or reloading must not destroy the assessment on screen — so the
 * scanner's view state is checkpointed here and restored on mount.
 *
 * WHY sessionStorage, and not localStorage or IndexedDB:
 *
 *   • The state being kept is a VIEW of a scan, not the scan itself. Every scan
 *     is already persisted server-side and is readable from `/scanner/history`,
 *     so this store is a convenience, never a source of truth. Anything it
 *     holds that contradicts the backend is discarded on the next fetch.
 *   • sessionStorage is scoped to the browser tab, which is exactly the scope
 *     of "the assessment I am working on". A second tab opening the scanner
 *     should get a clean page rather than inheriting another tab's run, and a
 *     shared machine should not surface one operator's estate to the next.
 *   • It survives in-app navigation and a page reload, which is what the
 *     workflow actually requires. IndexedDB would survive more than that, at
 *     the cost of an async restore that would flash an empty hero first.
 *
 * HONESTY CONTRACT: a restored session is only ever a snapshot of what the
 * scanner already reported. A run that was still streaming when the page was
 * left is NOT restored as running — see `restoreStatus`.
 */

import type {
  DefensiveFinding,
  EnterpriseScanner2,
  HistoryTimeframe,
  LogEntry,
  ModuleLedger,
  ModuleState,
  ScanResultRecord,
  ScanStatus,
  ScanSummary,
  TabId,
} from './_types';

const STORAGE_PREFIX = 'qguard:scanner-session:v1:';

/** Telemetry is the largest field by far and the least valuable to restore in
 *  full — the last 200 lines are what an operator actually reads back. */
const MAX_RESTORED_LOGS = 200;

/** Refuse to write a snapshot larger than this. A quota exception is silent in
 *  some browsers and corrupts the slot in others; better to skip the write. */
const MAX_SNAPSHOT_BYTES = 3_500_000;

/** A queued target, mirroring ScannerDashboard's `ValidatedAsset`. */
export interface PersistedTarget {
  raw: string;
  normalized?: string;
  type?: string;
  valid: boolean;
  reason?: string;
}

export interface ScannerSessionSnapshot {
  version: 1;
  savedAt: number;
  /** Terminal status only — see `restoreStatus`. */
  status: ScanStatus;
  progress: number;
  jobId: string | null;
  scanStartedAt: number | null;
  summary: ScanSummary | null;
  findings: DefensiveFinding[];
  modules: ModuleState[];
  moduleLedger: ModuleLedger | null;
  scanResults: ScanResultRecord[];
  scanner2: EnterpriseScanner2 | null;
  logs: LogEntry[];
  error: string | null;
  /** True when the run was still streaming at checkpoint time. */
  wasStreaming: boolean;

  /* View state — the "restore exactly as the user left it" half. */
  targets: PersistedTarget[];
  authorizationAccepted: boolean;
  inputText: string;
  activeTab: TabId;
  sevFilter: string | null;
  searchQ: string;
  expandedFinding: string | null;
  historyTimeframe: HistoryTimeframe;
  selectedHistoryId: string | null;
  terminalPaused: boolean;
  terminalPinned: boolean;
  scrollY: number;
}

export type ScannerSessionInput = Omit<ScannerSessionSnapshot, 'version' | 'savedAt' | 'logs'> & {
  logs: LogEntry[];
};

function keyFor(userId: string | null | undefined): string | null {
  return userId ? `${STORAGE_PREFIX}${userId}` : null;
}

function storage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage;
  } catch {
    // Hardened browser contexts can throw on access, not just on write.
    return null;
  }
}

/**
 * The status a restored session is allowed to claim.
 *
 * A run that was mid-stream when the page was left did NOT finish and did not
 * fail — the client simply stopped listening, while the job carried on
 * server-side. Restoring it as `running` would spin a progress bar that can
 * never advance; restoring it as `completed` or `failed` would assert an
 * outcome nobody observed. So a streaming run restores as `idle`, and the
 * caller tells the operator where the real result will appear.
 */
export function restoreStatus(snapshot: ScannerSessionSnapshot): ScanStatus {
  return snapshot.wasStreaming ? 'idle' : snapshot.status;
}

export function loadScannerSession(userId: string | null | undefined): ScannerSessionSnapshot | null {
  const key = keyFor(userId);
  const store = storage();
  if (!key || !store) return null;
  try {
    const raw = store.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ScannerSessionSnapshot;
    if (parsed?.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveScannerSession(userId: string | null | undefined, input: ScannerSessionInput): void {
  const key = keyFor(userId);
  const store = storage();
  if (!key || !store) return;

  const snapshot: ScannerSessionSnapshot = {
    ...input,
    version: 1,
    savedAt: Date.now(),
    logs: input.logs.slice(-MAX_RESTORED_LOGS),
  };

  try {
    const serialized = JSON.stringify(snapshot);
    if (serialized.length > MAX_SNAPSHOT_BYTES) {
      // Too large to keep whole — drop telemetry and the per-target records
      // (both re-fetchable from history) rather than losing the session.
      const trimmed = JSON.stringify({ ...snapshot, logs: [], scanResults: [] });
      if (trimmed.length > MAX_SNAPSHOT_BYTES) return;
      store.setItem(key, trimmed);
      return;
    }
    store.setItem(key, serialized);
  } catch {
    // Quota exceeded or storage disabled — the session is a convenience, and
    // the scan itself is safe on the server either way.
  }
}

export function clearScannerSession(userId: string | null | undefined): void {
  const key = keyFor(userId);
  const store = storage();
  if (!key || !store) return;
  try {
    store.removeItem(key);
  } catch {
    // Nothing to do — see `saveScannerSession`.
  }
}
