import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Copy,
  Download,
  FileArchive,
  FileAudio,
  FileCode2,
  File as FileIcon,
  FileCheck2,
  FileImage,
  FileSpreadsheet,
  FileText,
  FileVideoCamera,
  Folder,
  FolderOpen,
  History,
  KeyRound,
  Loader2,
  LockKeyhole,
  Search,
  ShieldCheck,
  Terminal,
  Trash2,
  UnlockKeyhole,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Channel } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@/lib/tauri-dialog";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";
import type { QuantumSecurityReport, TelemetryEvent } from "@/lib/types";
import { type VaultProgress, phaseLabel, opLabel, formatThroughput, formatEta, overallPercent } from "@/lib/vault-progress";

// ---------------------------------------------------------------------------
// Quantum Vault — strictly LOCAL, zero-knowledge, post-quantum file vault.
//
// Every file/folder is encrypted and decrypted on this device and stored only
// on local/external disk as a `.qvault` container. Nothing is uploaded to any
// QGuard server. The Vault Explorer is driven by a device-local, metadata-only
// registry (no plaintext, no keys) so the UI can list what you've sealed.
//
// Crypto (Rust `vault_stream` v3): File -> AES-256-GCM (FEK) -> FEK wrapped by
// the Vault Master Key (VMK) -> VMK protected by X25519 + ML-KEM-1024 -> header
// signed with Ed25519 + ML-DSA-87. The recovery key protects a backup of the VMK.
// ---------------------------------------------------------------------------

interface VaultLocalStreamSummary {
  file_id: string;
  kind: "file" | "folder";
  name: string;
  content_type: string;
  original_size: number;
  total_chunks: number;
  source_path: string;
  output_path: string;
  suite: Record<string, string>;
}

type LocalVaultAction = "encrypt-file" | "encrypt-folder" | "decrypt-file" | "decrypt-folder";

interface QuantumVaultPageProps {
  userId: string;
  telemetry: TelemetryEvent[];
}

/** Device-local, metadata-only record of a sealed `.qvault` container. Never
 *  holds plaintext or key material — only what the Explorer needs to display. */
interface VaultRegistryEntry {
  id: string;
  name: string;
  kind: "file" | "folder";
  contentType: string;
  sizeBytes: number;
  totalChunks: number;
  qvaultPath: string;
  sourcePath: string;
  suite: Record<string, string>;
  status: "encrypted" | "decrypted";
  integrity: "verified" | "pending";
  hidden: boolean;
  createdAt: string;
  updatedAt: string;
}

interface VaultActivityEntry {
  id: string;
  at: string;
  source: "encrypt" | "decrypt" | "recover" | "reprotect" | "delete";
  title: string;
  detail: string;
  status: "success" | "failed" | "info";
}

interface VaultExplorerNode {
  id: string;
  type: "folder" | "file";
  name: string;
  path: string;
  parentPath: string | null;
  depth: number;
  entry: VaultRegistryEntry | null;
  entries: VaultRegistryEntry[];
  children: VaultExplorerNode[];
  item_count: number;
  size_bytes: number;
  updated_at: string;
}

interface VaultHistoryEntry {
  id: string;
  at: string;
  source: string;
  title: string;
  detail: string;
  status: string;
}

interface VaultTerminalLog {
  id: string;
  at: string;
  level: "info" | "success" | "error";
  message: string;
}

type VaultPanelTab = "operations" | "explorer" | "history";
type VaultStatusTone = "ok" | "warn" | "pending";

const archiveExtensions = new Set(["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"]);
const codeExtensions = new Set(["c", "cpp", "css", "go", "html", "java", "js", "json", "jsx", "py", "rs", "sql", "tsx", "ts", "xml", "yaml", "yml"]);
const spreadsheetExtensions = new Set(["csv", "ods", "tsv", "xls", "xlsx"]);

const vaultSecurityFallback: QuantumSecurityReport = {
  hybrid_session_status: "Unavailable",
  pqc_algorithm: "Status unavailable",
  forward_secrecy: "Status unavailable",
  hndl_protection: "Unavailable",
  quantum_safe_score: 0,
  key_rotation_history: [],
  warnings: ["Desktop security report is unavailable in this context"],
};

function describeError(error: unknown): string {
  if (!error) return "Unknown error";
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (typeof error === "object") {
    const record = error as Record<string, unknown>;
    const parts = [record.message, record.details, record.hint, record.code]
      .filter((part): part is string | number => typeof part === "string" || typeof part === "number")
      .map(String);
    if (parts.length > 0) return parts.join(" ");
    try {
      return JSON.stringify(record);
    } catch {
      return "Unexpected object error";
    }
  }
  return String(error);
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function cleanExplorerPath(value: string): string {
  return value
    .replace(/\\/g, "/")
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");
}

function pathBasename(value: string): string {
  return value.split(/[\\/]/).filter(Boolean).pop() ?? value;
}

function shortSuiteLabel(suite?: Record<string, string> | null): string {
  if (!suite) return "ML-KEM-1024";
  const kem = suite.pq_kem;
  return typeof kem === "string" && kem ? kem : "ML-KEM-1024";
}

function suiteLabel(suite?: Record<string, string> | null): string {
  if (!suite) return "ML-KEM-1024 + X25519 + HKDF-SHA3-256 + AES-256-GCM + ML-DSA-87 + Ed25519";
  return [
    suite.pq_kem ?? "ML-KEM-1024",
    suite.classical_kex ?? "X25519",
    suite.kdf ?? "HKDF-SHA3-256",
    suite.symmetric ?? "AES-256-GCM",
    suite.pq_signature ?? "ML-DSA-87",
    suite.classical_signature ?? "Ed25519",
  ].map(String).join(" + ");
}

function sortExplorerNodes(nodes: VaultExplorerNode[]): VaultExplorerNode[] {
  nodes.sort((a, b) => {
    if (a.type !== b.type) return a.type === "folder" ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  });
  nodes.forEach((node) => sortExplorerNodes(node.children));
  return nodes;
}

function flattenExplorerNodes(nodes: VaultExplorerNode[]): VaultExplorerNode[] {
  const flattened: VaultExplorerNode[] = [];
  const visit = (current: VaultExplorerNode[]) => {
    current.forEach((node) => {
      flattened.push(node);
      visit(node.children);
    });
  };
  visit(nodes);
  return flattened;
}

function flattenVisibleExplorerNodes(
  nodes: VaultExplorerNode[],
  expandedFolders: Record<string, boolean>,
): VaultExplorerNode[] {
  const flattened: VaultExplorerNode[] = [];
  const visit = (current: VaultExplorerNode[]) => {
    current.forEach((node) => {
      flattened.push(node);
      if (node.type === "folder" && expandedFolders[node.path]) visit(node.children);
    });
  };
  visit(nodes);
  return flattened;
}

function nodeItemText(node: VaultExplorerNode): string {
  if (node.type === "file") return formatBytes(node.size_bytes);
  return `${node.item_count} item${node.item_count === 1 ? "" : "s"} - ${formatBytes(node.size_bytes)}`;
}

function renderFileTypeIcon(node: VaultExplorerNode) {
  const contentType = node.entry?.contentType.toLowerCase() ?? "";
  const extension = node.name.includes(".") ? node.name.split(".").pop()?.toLowerCase() ?? "" : "";
  if (contentType.startsWith("image/")) return <FileImage className="shrink-0 text-sky-500" size={17} />;
  if (contentType.startsWith("audio/")) return <FileAudio className="shrink-0 text-violet-500" size={17} />;
  if (contentType.startsWith("video/")) return <FileVideoCamera className="shrink-0 text-rose-500" size={17} />;
  if (contentType.includes("pdf") || contentType.startsWith("text/") || ["doc", "docx", "md", "pdf", "rtf", "txt"].includes(extension)) {
    return <FileText className="shrink-0 text-blue-500" size={17} />;
  }
  if (spreadsheetExtensions.has(extension)) return <FileSpreadsheet className="shrink-0 text-emerald-500" size={17} />;
  if (archiveExtensions.has(extension)) return <FileArchive className="shrink-0 text-amber-500" size={17} />;
  if (codeExtensions.has(extension)) return <FileCode2 className="shrink-0 text-indigo-500" size={17} />;
  return <FileIcon className="shrink-0 text-ink-400" size={17} />;
}

const REGISTRY_VERSION = "v1";

export default function QuantumVaultPage({ userId, telemetry }: QuantumVaultPageProps) {
  const registryStorageKey = useMemo(() => `qguard.vault.registry.${REGISTRY_VERSION}:${userId}`, [userId]);
  const activityStorageKey = useMemo(() => `qguard.vault.activity.${REGISTRY_VERSION}:${userId}`, [userId]);
  const explorerStorageKey = useMemo(() => `qguard-vault-explorer:${userId}`, [userId]);

  const [status, setStatus] = useState("No active vault operation");
  const [terminalLogs, setTerminalLogs] = useState<VaultTerminalLog[]>([]);
  const [registry, setRegistry] = useState<VaultRegistryEntry[]>([]);
  const [activity, setActivity] = useState<VaultActivityEntry[]>([]);
  const [storeReady, setStoreReady] = useState(false);

  const [workspaceMode, setWorkspaceMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [localVaultBusy, setLocalVaultBusy] = useState<LocalVaultAction | null>(null);
  const [localVaultResult, setLocalVaultResult] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState<string | null>(null);

  const [recoveryStatus, setRecoveryStatus] = useState<{ enabled: boolean; mode: string | null; recipientKeyId: string | null; configuredAt: string | null } | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState<"setup" | "enable" | "decrypt-file" | "decrypt-folder" | "rewrap" | null>(null);
  const [recoveryMode, setRecoveryMode] = useState<"personal" | "enterprise" | "hybrid">("personal");
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("");
  const [enterpriseKeyInput, setEnterpriseKeyInput] = useState("");
  const [generatedRecoveryKey, setGeneratedRecoveryKey] = useState<string | null>(null);
  const [generatedEnterpriseKey, setGeneratedEnterpriseKey] = useState<string | null>(null);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [recoveryNotice, setRecoveryNotice] = useState<string | null>(null);

  const [securityReport, setSecurityReport] = useState<QuantumSecurityReport | null>(null);
  const [activeVaultTab, setActiveVaultTab] = useState<VaultPanelTab>("explorer");
  const [explorerQuery, setExplorerQuery] = useState("");
  const [recoveryModalOpen, setRecoveryModalOpen] = useState(false);
  const [vaultStatusModalOpen, setVaultStatusModalOpen] = useState(false);
  const [confirmDialog, setConfirmDialog] = useState<{ kind: "delete" | "remove"; entry: VaultRegistryEntry } | null>(null);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({});
  const [selectedExplorerNodeId, setSelectedExplorerNodeId] = useState<string | null>(null);

  const terminalRef = useRef<HTMLDivElement | null>(null);

  // Live, real-time crypto progress streamed from the Rust vault streamer.
  // `liveStep` carries the currently-displayed real event plus its stage-weighted
  // percentage and the REAL elapsed time (from the event's arrival), so throughput
  // and ETA stay accurate even while the step display is paced for readability.
  type LiveStep = { p: VaultProgress; pct: number; elapsedMs: number };
  const [liveStep, setLiveStep] = useState<LiveStep | null>(null);
  const progressStartRef = useRef<number>(0);
  const lastChunkLogRef = useRef<number>(-1);
  const stepQueueRef = useRef<Array<{ p: VaultProgress; receivedAt: number }>>([]);
  const drainTimerRef = useRef<number | undefined>(undefined);
  const maxPctRef = useRef<number>(0);

  // Cancel any in-flight progress playback timer on unmount.
  useEffect(() => () => { if (drainTimerRef.current !== undefined) window.clearTimeout(drainTimerRef.current); }, []);

  const appendLog = useCallback((level: VaultTerminalLog["level"], message: string) => {
    setTerminalLogs((current) => [
      ...current.slice(-120),
      { id: crypto.randomUUID(), at: new Date().toISOString(), level, message },
    ]);
  }, []);

  // Runs a vault stream command with a real-time progress Channel. The Rust side
  // streams REAL VaultProgress events (per crypto phase + per 1 MiB chunk). On-device
  // AES-256-GCM is so fast that small files finish in milliseconds, so we PLAY BACK
  // the real events through a queue at a human-readable cadence: each step is shown
  // for a beat, and the cadence auto-accelerates when events back up so large files
  // stay genuinely real-time. No values are fabricated — percentage is stage-weighted
  // over the steps that actually ran, and throughput/ETA use each event's real
  // arrival time.
  const runVaultStream = useCallback(
    async (command: string, args: Record<string, unknown>): Promise<VaultLocalStreamSummary> => {
      if (drainTimerRef.current !== undefined) {
        window.clearTimeout(drainTimerRef.current);
        drainTimerRef.current = undefined;
      }
      const startedAt = Date.now();
      progressStartRef.current = startedAt;
      lastChunkLogRef.current = -1;
      maxPctRef.current = 0;
      stepQueueRef.current = [];
      setLiveStep(null);

      const BASE_MS = 320; // readable pace per step when caught up
      const MIN_MS = 25; // fast catch-up when many events are queued (large files)
      const HOLD_MS = 1100; // keep the completed 100% bar visible briefly

      let producerDone = false;
      let finishPlayback: () => void = () => undefined;
      const playbackDone = new Promise<void>((resolve) => { finishPlayback = resolve; });

      const renderStep = (item: { p: VaultProgress; receivedAt: number }) => {
        const { p, receivedAt } = item;
        const pct = Math.max(maxPctRef.current, overallPercent(p));
        maxPctRef.current = pct;
        setLiveStep({ p, pct, elapsedMs: Math.max(0, receivedAt - startedAt) });
        if (p.phase === "chunk") {
          const decile = p.totalBytes > 0 ? Math.floor((p.processedBytes / p.totalBytes) * 10) : 0;
          if (decile !== lastChunkLogRef.current) {
            lastChunkLogRef.current = decile;
            appendLog("info", `${phaseLabel(p.phase)} · ${pct}% · chunk ${p.chunkIndex}/${p.totalChunks} · ${formatBytes(p.processedBytes)} / ${formatBytes(p.totalBytes)}`);
          }
        } else {
          appendLog(p.level === "success" ? "success" : "info", `▸ ${p.message}`);
        }
      };

      let graceChecks = 0; // brief wait for trailing channel events after the command resolves
      const drain = () => {
        const queue = stepQueueRef.current;
        if (queue.length === 0) {
          if (producerDone && graceChecks >= 3) {
            drainTimerRef.current = window.setTimeout(() => {
              drainTimerRef.current = undefined;
              setLiveStep(null);
              finishPlayback();
            }, HOLD_MS);
            return;
          }
          if (producerDone) graceChecks += 1;
          drainTimerRef.current = window.setTimeout(drain, 60); // await more events
          return;
        }
        graceChecks = 0;
        renderStep(queue.shift()!);
        // Accelerate as backlog grows so playback never lags far behind reality.
        const delay = Math.max(MIN_MS, Math.round(BASE_MS / (1 + queue.length)));
        drainTimerRef.current = window.setTimeout(drain, delay);
      };

      const onProgress = isTauriRuntime() ? new Channel<VaultProgress>() : null;
      if (onProgress) {
        onProgress.onmessage = (p) => {
          stepQueueRef.current.push({ p, receivedAt: Date.now() });
        };
        drain();
      }

      try {
        const summary = await safeInvoke<VaultLocalStreamSummary>(command, { ...args, onProgress });
        producerDone = true;
        if (onProgress) await playbackDone; // let the user watch the full sequence
        return summary;
      } catch (error) {
        producerDone = true;
        if (drainTimerRef.current !== undefined) {
          window.clearTimeout(drainTimerRef.current);
          drainTimerRef.current = undefined;
        }
        stepQueueRef.current = [];
        setLiveStep(null);
        throw error;
      }
    },
    [appendLog],
  );

  // Load device-local registry + activity once per user.
  useEffect(() => {
    setStoreReady(false);
    try {
      const savedRegistry = window.localStorage.getItem(registryStorageKey);
      setRegistry(savedRegistry ? (JSON.parse(savedRegistry) as VaultRegistryEntry[]) : []);
    } catch {
      setRegistry([]);
    }
    try {
      const savedActivity = window.localStorage.getItem(activityStorageKey);
      setActivity(savedActivity ? (JSON.parse(savedActivity) as VaultActivityEntry[]) : []);
    } catch {
      setActivity([]);
    }
    try {
      const savedState = window.localStorage.getItem(explorerStorageKey);
      const parsed = savedState ? (JSON.parse(savedState) as Record<string, unknown>) : {};
      const next: Record<string, boolean> = {};
      Object.entries(parsed).forEach(([path, expanded]) => {
        if (expanded === true) next[path] = true;
      });
      setExpandedFolders(next);
    } catch {
      setExpandedFolders({});
    }
    setStoreReady(true);
  }, [registryStorageKey, activityStorageKey, explorerStorageKey]);

  // Persist registry + activity (metadata only) whenever they change.
  useEffect(() => {
    if (!storeReady) return;
    try {
      window.localStorage.setItem(registryStorageKey, JSON.stringify(registry));
    } catch {
      // localStorage is optional; in-memory state still works this session.
    }
  }, [registry, registryStorageKey, storeReady]);

  useEffect(() => {
    if (!storeReady) return;
    try {
      window.localStorage.setItem(activityStorageKey, JSON.stringify(activity.slice(0, 200)));
    } catch {
      // optional
    }
  }, [activity, activityStorageKey, storeReady]);

  useEffect(() => {
    if (!storeReady) return;
    try {
      window.localStorage.setItem(explorerStorageKey, JSON.stringify(expandedFolders));
    } catch {
      // optional
    }
  }, [expandedFolders, explorerStorageKey, storeReady]);

  useEffect(() => {
    if (!terminalRef.current) return;
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLogs.length]);

  const pushActivity = useCallback((entry: Omit<VaultActivityEntry, "id" | "at">) => {
    setActivity((current) => [
      { id: crypto.randomUUID(), at: new Date().toISOString(), ...entry },
      ...current,
    ].slice(0, 200));
  }, []);

  const upsertRegistryFromSummary = useCallback(
    (summary: VaultLocalStreamSummary, status: VaultRegistryEntry["status"]) => {
      const now = new Date().toISOString();
      setRegistry((current) => {
        const name = cleanExplorerPath(summary.name) || pathBasename(summary.output_path) || summary.file_id.slice(0, 8);
        const existingIndex = current.findIndex(
          (item) => item.id === summary.file_id || item.qvaultPath === summary.output_path,
        );
        const base: VaultRegistryEntry = {
          id: summary.file_id,
          name,
          kind: summary.kind,
          contentType: summary.content_type,
          sizeBytes: summary.original_size,
          totalChunks: summary.total_chunks,
          qvaultPath: summary.output_path,
          sourcePath: summary.source_path,
          suite: summary.suite,
          status,
          integrity: "verified",
          hidden: false,
          createdAt: existingIndex >= 0 ? current[existingIndex].createdAt : now,
          updatedAt: now,
        };
        if (existingIndex >= 0) {
          const next = [...current];
          next[existingIndex] = { ...current[existingIndex], ...base };
          return next;
        }
        return [base, ...current];
      });
    },
    [],
  );

  const updateRegistryEntry = useCallback((id: string, patch: Partial<VaultRegistryEntry>) => {
    setRegistry((current) =>
      current.map((item) => (item.id === id ? { ...item, ...patch, updatedAt: new Date().toISOString() } : item)),
    );
  }, []);

  const visibleRegistry = useMemo(() => registry.filter((item) => !item.hidden), [registry]);

  // Build a folder/file tree from registry entry names (path-aware, like the
  // previous cloud explorer) so nested encrypted folders group correctly.
  const explorerTree = useMemo<VaultExplorerNode[]>(() => {
    const folders = new Map<string, VaultExplorerNode>();
    const roots: VaultExplorerNode[] = [];

    const addToParent = (node: VaultExplorerNode) => {
      if (!node.parentPath) {
        roots.push(node);
        return;
      }
      const parent = folders.get(node.parentPath);
      if (parent) parent.children.push(node);
      else roots.push(node);
    };

    const ensureFolder = (path: string, name: string, depth: number, parentPath: string | null, entry: VaultRegistryEntry) => {
      const current = folders.get(path);
      if (current) {
        current.entries.push(entry);
        current.item_count += 1;
        current.size_bytes += entry.sizeBytes;
        if (new Date(entry.updatedAt) > new Date(current.updated_at)) current.updated_at = entry.updatedAt;
        return;
      }
      const folder: VaultExplorerNode = {
        id: `folder-${path}`,
        type: "folder",
        name,
        path,
        parentPath,
        depth,
        entry: null,
        entries: [entry],
        children: [],
        item_count: 1,
        size_bytes: entry.sizeBytes,
        updated_at: entry.updatedAt,
      };
      folders.set(path, folder);
      addToParent(folder);
    };

    visibleRegistry.forEach((entry) => {
      const path = cleanExplorerPath(entry.name) || entry.id;
      const parts = path.split("/").filter(Boolean);
      const fileName = parts.at(-1) ?? path;
      let prefix = "";
      parts.slice(0, -1).forEach((part, index) => {
        const parentPath = prefix || null;
        prefix = prefix ? `${prefix}/${part}` : part;
        ensureFolder(prefix, part, index, parentPath, entry);
      });
      const parentPath = parts.length > 1 ? parts.slice(0, -1).join("/") : null;
      addToParent({
        id: `file-${entry.id}`,
        type: "file",
        name: fileName,
        path,
        parentPath,
        depth: Math.max(0, parts.length - 1),
        entry,
        entries: [entry],
        children: [],
        item_count: 1,
        size_bytes: entry.sizeBytes,
        updated_at: entry.updatedAt,
      });
    });

    return sortExplorerNodes(roots);
  }, [visibleRegistry]);

  const allExplorerNodes = useMemo(() => flattenExplorerNodes(explorerTree), [explorerTree]);
  const visibleExplorerNodes = useMemo(
    () => flattenVisibleExplorerNodes(explorerTree, expandedFolders),
    [expandedFolders, explorerTree],
  );
  const explorerFolderCount = useMemo(() => allExplorerNodes.filter((n) => n.type === "folder").length, [allExplorerNodes]);
  const explorerFileCount = useMemo(() => allExplorerNodes.filter((n) => n.type === "file").length, [allExplorerNodes]);

  const explorerSearch = explorerQuery.trim().toLowerCase();
  const filteredExplorerNodes = useMemo(() => {
    if (!explorerSearch) return visibleExplorerNodes;
    return allExplorerNodes.filter(
      (node) =>
        node.type === "file" &&
        (node.name.toLowerCase().includes(explorerSearch) || node.path.toLowerCase().includes(explorerSearch)),
    );
  }, [allExplorerNodes, explorerSearch, visibleExplorerNodes]);

  const historyEntries = useMemo<VaultHistoryEntry[]>(() => {
    const activityEntries: VaultHistoryEntry[] = activity.map((item) => ({
      id: `activity-${item.id}`,
      at: item.at,
      source: item.source,
      title: item.title,
      detail: item.detail,
      status: item.status,
    }));
    const telemetryEntries: VaultHistoryEntry[] = telemetry
      .filter((event) => event.stage.includes("vault") || event.stage.includes("file"))
      .map((event) => ({
        id: `telemetry-${event.id}`,
        at: event.created_at,
        source: "telemetry",
        title: event.stage.replace(/_/g, " "),
        detail: event.detail,
        status: `${event.progress}%`,
      }));
    const terminalEntries: VaultHistoryEntry[] = terminalLogs.map((log) => ({
      id: `terminal-${log.id}`,
      at: log.at,
      source: "terminal",
      title: log.level === "error" ? "terminal error" : log.level === "success" ? "terminal success" : "terminal",
      detail: log.message,
      status: log.level,
    }));
    return [...activityEntries, ...telemetryEntries, ...terminalEntries]
      .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
      .slice(0, 120);
  }, [activity, telemetry, terminalLogs]);

  useEffect(() => {
    const folderPaths = new Set(allExplorerNodes.filter((n) => n.type === "folder").map((n) => n.path));
    setExpandedFolders((current) => {
      let changed = false;
      const next: Record<string, boolean> = {};
      Object.entries(current).forEach(([path, expanded]) => {
        if (expanded && folderPaths.has(path)) next[path] = true;
        else if (expanded) changed = true;
      });
      return changed ? next : current;
    });
  }, [allExplorerNodes]);

  useEffect(() => {
    if (!selectedExplorerNodeId) return;
    if (!allExplorerNodes.some((node) => node.id === selectedExplorerNodeId)) setSelectedExplorerNodeId(null);
  }, [allExplorerNodes, selectedExplorerNodeId]);

  const loadRecoveryStatus = useCallback(async () => {
    const result = await safeInvoke<{ enabled: boolean; mode: string | null; recipientKeyId: string | null; configuredAt: string | null }>(
      "vault_recovery_status",
      undefined,
      { enabled: false, mode: null, recipientKeyId: null, configuredAt: null },
    );
    setRecoveryStatus(result);
  }, []);

  useEffect(() => {
    void loadRecoveryStatus();
  }, [loadRecoveryStatus]);

  const loadVaultSecurity = useCallback(async () => {
    const report = await safeInvoke<QuantumSecurityReport>("security_quantum_report", undefined, vaultSecurityFallback);
    setSecurityReport(report);
  }, []);

  useEffect(() => {
    void loadVaultSecurity();
  }, [loadVaultSecurity, vaultStatusModalOpen, registry.length, recoveryStatus?.enabled]);

  const localSuiteLine =
    "Crypto suite: X25519+ML-KEM-1024 / AES-256-GCM / HKDF-SHA3-256 / Ed25519+ML-DSA-87 (VMK envelope, on-device)";

  async function runLocalVault(action: LocalVaultAction, task: () => Promise<void>) {
    if (localVaultBusy) {
      appendLog("error", "A local vault operation is already running. Let it finish first.");
      return;
    }
    setLocalVaultBusy(action);
    setLocalVaultResult(null);
    try {
      await task();
    } catch (error) {
      const message = describeError(error);
      setStatus(message);
      appendLog("error", `Local vault operation failed: ${message}`);
      pushActivity({ source: action.startsWith("encrypt") ? "encrypt" : "decrypt", title: "Operation failed", detail: message, status: "failed" });
    } finally {
      setLocalVaultBusy(null);
    }
  }

  async function localEncryptFile() {
    await runLocalVault("encrypt-file", async () => {
      const source = await openDialog({ multiple: false, directory: false, title: "Select a file to encrypt" });
      if (typeof source !== "string") return;
      const dest = await saveDialog({ title: "Save encrypted vault file", defaultPath: `${pathBasename(source)}.qvault` });
      if (!dest) return;
      appendLog("info", localSuiteLine);
      appendLog("info", `Encrypting ${pathBasename(source)} → ${pathBasename(dest)}`);
      setStatus("Encrypting to a local quantum-safe vault file");
      const summary = await runVaultStream("vault_encrypt_path", { sourcePath: source, destPath: dest });
      upsertRegistryFromSummary(summary, "encrypted");
      const line = `Encrypted ${summary.name} (${formatBytes(summary.original_size)}, ${summary.total_chunks} chunk${summary.total_chunks === 1 ? "" : "s"}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "encrypt", title: "File encrypted", detail: line, status: "success" });
      setStatus("Local encrypted vault file saved");
      setLocalVaultResult(line);
    });
  }

  async function localEncryptFolder() {
    await runLocalVault("encrypt-folder", async () => {
      const source = await openDialog({ multiple: false, directory: true, title: "Select a folder to encrypt" });
      if (typeof source !== "string") return;
      const dest = await saveDialog({ title: "Save encrypted folder archive", defaultPath: `${pathBasename(source)}.qguard-folder.qvault` });
      if (!dest) return;
      appendLog("info", localSuiteLine);
      appendLog("info", `Archiving and encrypting folder ${pathBasename(source)} → ${pathBasename(dest)}`);
      setStatus("Encrypting folder into a single local archive");
      const summary = await runVaultStream("vault_encrypt_folder_path", { sourceDir: source, destPath: dest });
      upsertRegistryFromSummary(summary, "encrypted");
      const line = `Encrypted folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "encrypt", title: "Folder encrypted", detail: line, status: "success" });
      setStatus("Local encrypted folder archive saved");
      setLocalVaultResult(line);
    });
  }

  async function localDecryptFile() {
    await runLocalVault("decrypt-file", async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select an encrypted vault file",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const suggested = pathBasename(source).replace(/\.qvault$/i, "") || "restored-file";
      const dest = await saveDialog({ title: "Save decrypted file", defaultPath: suggested });
      if (!dest) return;
      appendLog("info", `Decrypting ${pathBasename(source)} on this device`);
      setStatus("Decrypting local vault file");
      const summary = await runVaultStream("vault_decrypt_path", { sourcePath: source, destPath: dest });
      const line = `Decrypted ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "decrypt", title: "File decrypted", detail: line, status: "success" });
      setStatus("Local file decrypted");
      setLocalVaultResult(line);
    });
  }

  async function localDecryptFolder() {
    await runLocalVault("decrypt-folder", async () => {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select an encrypted folder archive",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const dest = await openDialog({ multiple: false, directory: true, title: "Choose a folder to restore into" });
      if (typeof dest !== "string") return;
      appendLog("info", `Decrypting folder archive ${pathBasename(source)} into ${dest}`);
      setStatus("Restoring encrypted folder archive locally");
      const summary = await runVaultStream("vault_decrypt_folder_path", { sourcePath: source, destDir: dest });
      const line = `Restored folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "decrypt", title: "Folder decrypted", detail: line, status: "success" });
      setStatus("Local folder archive restored");
      setLocalVaultResult(line);
    });
  }

  // ---- Explorer row actions (operate on the saved .qvault path) -----------

  async function decryptRegistryEntry(entry: VaultRegistryEntry) {
    if (actionBusy) return;
    setActionBusy(`decrypt-${entry.id}`);
    try {
      if (entry.kind === "folder") {
        const dest = await openDialog({ multiple: false, directory: true, title: "Choose a folder to restore into" });
        if (typeof dest !== "string") return;
        setStatus(`Decrypting ${entry.name}`);
        const summary = await runVaultStream("vault_decrypt_folder_path", { sourcePath: entry.qvaultPath, destDir: dest });
        updateRegistryEntry(entry.id, { status: "decrypted" });
        const line = `Restored folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
        appendLog("success", line);
        pushActivity({ source: "decrypt", title: "Folder decrypted", detail: line, status: "success" });
        setStatus("Local folder archive restored");
      } else {
        const suggested = entry.name.replace(/\.qvault$/i, "") || pathBasename(entry.qvaultPath).replace(/\.qvault$/i, "") || "restored-file";
        const dest = await saveDialog({ title: "Save decrypted file", defaultPath: pathBasename(suggested) });
        if (!dest) return;
        setStatus(`Decrypting ${entry.name}`);
        const summary = await runVaultStream("vault_decrypt_path", { sourcePath: entry.qvaultPath, destPath: dest });
        updateRegistryEntry(entry.id, { status: "decrypted" });
        const line = `Decrypted ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
        appendLog("success", line);
        pushActivity({ source: "decrypt", title: "File decrypted", detail: line, status: "success" });
        setStatus("Local file decrypted");
      }
    } catch (error) {
      const message = describeError(error);
      appendLog("error", `Decrypt failed for ${entry.name}: ${message}`);
      pushActivity({ source: "decrypt", title: "Decrypt failed", detail: `${entry.name}: ${message}`, status: "failed" });
      setStatus(message);
    } finally {
      setActionBusy(null);
    }
  }

  async function reprotectRegistryEntry(entry: VaultRegistryEntry) {
    if (actionBusy) return;
    setActionBusy(`reprotect-${entry.id}`);
    try {
      setStatus(`Re-protecting ${entry.name}`);
      const summary = await runVaultStream("vault_rewrap_path", { sourcePath: entry.qvaultPath });
      updateRegistryEntry(entry.id, { suite: summary.suite, integrity: "verified" });
      appendLog("success", `Re-protected ${summary.name} (v3 VMK envelope / ML-DSA-87)`);
      pushActivity({ source: "reprotect", title: "File re-protected", detail: `${entry.name} upgraded to the v3 VMK envelope`, status: "success" });
      setStatus("Vault file re-protected");
    } catch (error) {
      const message = describeError(error);
      appendLog("error", `Re-protect failed for ${entry.name}: ${message}`);
      pushActivity({ source: "reprotect", title: "Re-protect failed", detail: `${entry.name}: ${message}`, status: "failed" });
      setStatus(message);
    } finally {
      setActionBusy(null);
    }
  }

  async function deleteRegistryFile(entry: VaultRegistryEntry) {
    if (actionBusy) return;
    setActionBusy(`delete-${entry.id}`);
    try {
      await safeInvoke("vault_delete_file", { sourcePath: entry.qvaultPath });
      setRegistry((current) => current.filter((item) => item.id !== entry.id));
      appendLog("success", `Permanently deleted ${pathBasename(entry.qvaultPath)} from disk`);
      pushActivity({ source: "delete", title: "Vault file deleted", detail: `${entry.name} permanently removed from disk`, status: "success" });
      setStatus(`${entry.name} deleted`);
    } catch (error) {
      const message = describeError(error);
      appendLog("error", `Delete failed for ${entry.name}: ${message}`);
      pushActivity({ source: "delete", title: "Delete failed", detail: `${entry.name}: ${message}`, status: "failed" });
      setStatus(message);
    } finally {
      setActionBusy(null);
    }
  }

  function removeFromList(entry: VaultRegistryEntry) {
    setRegistry((current) => current.filter((item) => item.id !== entry.id));
    appendLog("info", `Removed ${entry.name} from the local vault list (the .qvault file on disk is untouched)`);
  }

  function toggleHidden(entry: VaultRegistryEntry) {
    updateRegistryEntry(entry.id, { hidden: !entry.hidden });
  }

  function toggleExplorerFolder(node: VaultExplorerNode, forceExpanded?: boolean) {
    setSelectedExplorerNodeId(node.id);
    if (node.type !== "folder") return;
    setExpandedFolders((current) => ({ ...current, [node.path]: forceExpanded ?? !current[node.path] }));
  }

  function selectExplorerNode(node: VaultExplorerNode) {
    setSelectedExplorerNodeId(node.id);
    if (node.type === "folder") toggleExplorerFolder(node);
  }

  function handleExplorerNodeKeyDown(event: KeyboardEvent<HTMLDivElement>, node: VaultExplorerNode) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectExplorerNode(node);
      return;
    }
    if (node.type !== "folder") return;
    if (event.key === "ArrowRight" && !expandedFolders[node.path]) {
      event.preventDefault();
      toggleExplorerFolder(node, true);
    }
    if (event.key === "ArrowLeft" && expandedFolders[node.path]) {
      event.preventDefault();
      toggleExplorerFolder(node, false);
    }
  }

  function renderEntryActions(entry: VaultRegistryEntry) {
    const decryptBusy = actionBusy === `decrypt-${entry.id}`;
    const reprotectBusy = actionBusy === `reprotect-${entry.id}`;
    const deleteBusy = actionBusy === `delete-${entry.id}`;
    const disabled = Boolean(actionBusy);
    return (
      <div className="flex flex-nowrap items-center gap-2">
        <button type="button" disabled={disabled} onClick={() => decryptRegistryEntry(entry)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Decrypt (choose destination)">
          {decryptBusy ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => reprotectRegistryEntry(entry)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Re-protect (upgrade to v3 / add recovery)">
          {reprotectBusy ? <Loader2 className="animate-spin" size={16} /> : <ShieldCheck size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => setConfirmDialog({ kind: "remove", entry })} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Remove from list (keeps the file on disk)">
          <X size={16} />
        </button>
        <button type="button" disabled={disabled} onClick={() => setConfirmDialog({ kind: "delete", entry })} className="icon-button border-rose-200 text-rose-600 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-50" title="Permanently delete file from disk">
          {deleteBusy ? <Loader2 className="animate-spin" size={16} /> : <Trash2 size={16} />}
        </button>
      </div>
    );
  }

  // ---- Recovery -----------------------------------------------------------

  async function setupRecovery() {
    if (recoveryBusy) return;
    setRecoveryBusy("setup");
    setRecoveryNotice(null);
    try {
      const result = await safeInvoke<{ mode: string; recoveryKey: string | null; enterprisePrivateKey: string | null; enterpriseFingerprint: string | null }>(
        "vault_setup_recovery",
        { mode: recoveryMode },
      );
      setGeneratedRecoveryKey(result.recoveryKey ?? null);
      setGeneratedEnterpriseKey(result.enterprisePrivateKey ?? null);
      setRecoverySaved(false);
      appendLog("success", `Quantum-safe vault recovery configured (${result.mode}). Save the key material offline now.`);
      try {
        window.localStorage.setItem("qguard.vault.recovery.configured", "true");
      } catch {
        // optional flag used by onboarding
      }
      await loadRecoveryStatus();
    } catch (error) {
      const message = describeError(error);
      setRecoveryNotice(message);
      appendLog("error", `Recovery setup failed: ${message}`);
    } finally {
      setRecoveryBusy(null);
    }
  }

  async function enableRecoveryWithKey() {
    if (recoveryBusy) return;
    const key = recoveryKeyInput.trim();
    if (!key) {
      setRecoveryNotice("Enter your recovery key first.");
      return;
    }
    setRecoveryBusy("enable");
    setRecoveryNotice(null);
    try {
      await safeInvoke("vault_enable_recovery_with_phrase", { recoveryKey: key });
      setRecoveryKeyInput("");
      setRecoveryNotice("Recovery key enabled on this device. New vault files are protected by it.");
      appendLog("success", "Recovery key enabled on this device.");
      try {
        window.localStorage.setItem("qguard.vault.recovery.configured", "true");
      } catch {
        // optional
      }
      await loadRecoveryStatus();
    } catch (error) {
      const message = describeError(error);
      setRecoveryNotice(message);
      appendLog("error", `Enabling recovery key failed: ${message}`);
    } finally {
      setRecoveryBusy(null);
    }
  }

  function copyGeneratedRecoveryKey() {
    if (!generatedRecoveryKey) return;
    navigator.clipboard
      .writeText(generatedRecoveryKey)
      .then(() => setRecoveryNotice("Recovery key copied to clipboard."))
      .catch(() => setRecoveryNotice("Could not copy automatically — select and copy it manually."));
  }

  function downloadTextFile(name: string, body: string) {
    const blob = new Blob([body], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function downloadGeneratedRecoveryKey() {
    if (!generatedRecoveryKey) return;
    downloadTextFile(
      "qguard-vault-recovery-key.txt",
      `QGuard Quantum Vault — Recovery Key\n\nKeep this safe and OFFLINE. Anyone who has this key can decrypt your vault\nfiles, and QGuard cannot recover it for you if it is lost. Store it in a\npassword manager or print it and lock it away.\n\nRecovery key:\n${generatedRecoveryKey}\n`,
    );
    setRecoverySaved(true);
  }

  function downloadGeneratedEnterpriseKey() {
    if (!generatedEnterpriseKey) return;
    downloadTextFile(
      "qguard-vault-enterprise-recovery-key.txt",
      `QGuard Quantum Vault — Enterprise Recovery Key (ML-KEM-1024)\n\nThis is the enterprise recovery PRIVATE key. Store it offline under enterprise\nadmin control. Anyone with this key (and, for hybrid, the recovery key) can\nrecover protected vault material. QGuard never receives or stores it.\n\nEnterprise recovery key:\n${generatedEnterpriseKey}\n`,
    );
    setRecoverySaved(true);
  }

  async function recoverDecryptFile() {
    if (recoveryBusy) return;
    const recoveryKey = recoveryKeyInput.trim();
    const enterpriseKey = enterpriseKeyInput.trim();
    if (!recoveryKey && !enterpriseKey) {
      setRecoveryNotice("Enter your recovery key (or enterprise recovery key) first.");
      return;
    }
    setRecoveryBusy("decrypt-file");
    setRecoveryNotice(null);
    try {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select an encrypted vault file",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const suggested = pathBasename(source).replace(/\.qvault$/i, "") || "recovered-file";
      const dest = await saveDialog({ title: "Save recovered file", defaultPath: suggested });
      if (!dest) return;
      setStatus("Recovering vault file");
      const summary = enterpriseKey
        ? await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_path_with_enterprise", {
            sourcePath: source,
            destPath: dest,
            enterpriseKey,
            recoveryKey: recoveryKey || null,
          })
        : await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_path_with_recovery", {
            sourcePath: source,
            destPath: dest,
            recoveryKey,
          });
      const line = `Recovered ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "recover", title: "File recovered", detail: line, status: "success" });
      setStatus("File recovered");
      setRecoveryNotice(line);
    } catch (error) {
      const message = describeError(error);
      setStatus(message);
      setRecoveryNotice(message);
      appendLog("error", `Recovery failed: ${message}`);
    } finally {
      setRecoveryBusy(null);
    }
  }

  async function recoverDecryptFolder() {
    if (recoveryBusy) return;
    const recoveryKey = recoveryKeyInput.trim();
    const enterpriseKey = enterpriseKeyInput.trim();
    if (!recoveryKey && !enterpriseKey) {
      setRecoveryNotice("Enter your recovery key (or enterprise recovery key) first.");
      return;
    }
    setRecoveryBusy("decrypt-folder");
    setRecoveryNotice(null);
    try {
      const source = await openDialog({
        multiple: false,
        directory: false,
        title: "Select an encrypted folder archive",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      if (typeof source !== "string") return;
      const dest = await openDialog({ multiple: false, directory: true, title: "Choose a folder to restore into" });
      if (typeof dest !== "string") return;
      setStatus("Recovering vault folder");
      const summary = enterpriseKey
        ? await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_folder_path_with_enterprise", {
            sourcePath: source,
            destDir: dest,
            enterpriseKey,
            recoveryKey: recoveryKey || null,
          })
        : await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_folder_path_with_recovery", {
            sourcePath: source,
            destDir: dest,
            recoveryKey,
          });
      const line = `Recovered folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      pushActivity({ source: "recover", title: "Folder recovered", detail: line, status: "success" });
      setStatus("Folder recovered");
      setRecoveryNotice(line);
    } catch (error) {
      const message = describeError(error);
      setStatus(message);
      setRecoveryNotice(message);
      appendLog("error", `Recovery failed: ${message}`);
    } finally {
      setRecoveryBusy(null);
    }
  }

  async function reprotectExistingFiles() {
    if (recoveryBusy) return;
    setRecoveryBusy("rewrap");
    setRecoveryNotice(null);
    try {
      const selected = await openDialog({
        multiple: true,
        directory: false,
        title: "Select encrypted vault files to re-protect",
        filters: [{ name: "QGuard Vault", extensions: ["qvault"] }],
      });
      const paths = Array.isArray(selected) ? selected : typeof selected === "string" ? [selected] : [];
      if (paths.length === 0) return;
      setStatus(`Re-protecting ${paths.length} vault file${paths.length === 1 ? "" : "s"}`);
      let protectedCount = 0;
      const failures: string[] = [];
      for (const path of paths) {
        try {
          const summary = await runVaultStream("vault_rewrap_path", { sourcePath: path });
          protectedCount += 1;
          appendLog("success", `Re-protected ${summary.name}`);
        } catch (error) {
          failures.push(`${pathBasename(path)}: ${describeError(error)}`);
          appendLog("error", `Re-protect failed for ${pathBasename(path)}: ${describeError(error)}`);
        }
      }
      const summaryLine = `Re-protected ${protectedCount}/${paths.length} file${paths.length === 1 ? "" : "s"}.${failures.length ? ` Failed: ${failures.join("; ")}` : ""}`;
      pushActivity({ source: "reprotect", title: "Re-protect existing files", detail: summaryLine, status: failures.length ? "failed" : "success" });
      setStatus(failures.length ? "Some files could not be re-protected" : "Existing files re-protected");
      setRecoveryNotice(summaryLine);
    } catch (error) {
      const message = describeError(error);
      setStatus(message);
      setRecoveryNotice(message);
      appendLog("error", `Re-protect failed: ${message}`);
    } finally {
      setRecoveryBusy(null);
    }
  }

  // ---- Derived status -----------------------------------------------------

  const identityActive = securityReport === null
    ? null
    : securityReport.pqc_algorithm !== "No active device keys" && securityReport.pqc_algorithm !== "Status unavailable";
  const deviceTone: VaultStatusTone = identityActive === null ? "pending" : identityActive ? "ok" : "warn";
  const vaultTotalBytes = visibleRegistry.reduce((sum, entry) => sum + entry.sizeBytes, 0);
  const vaultLastActivityAt = activity[0]?.at ?? registry[0]?.updatedAt ?? null;
  const vaultStatusRows: Array<{ tone: VaultStatusTone; title: string; detail: string }> = [
    {
      tone: localVaultBusy ? "pending" : "ok",
      title: "Vault Ready",
      detail: localVaultBusy ? "Local crypto operation in progress" : "All systems operational — local-only",
    },
    {
      tone: recoveryStatus?.enabled ? "ok" : "warn",
      title: "Recovery Key Active",
      detail: recoveryStatus?.enabled
        ? `${recoveryStatus.mode ?? "personal"} mode${recoveryStatus.configuredAt ? ` - ${new Date(recoveryStatus.configuredAt).toLocaleDateString()}` : ""}`
        : "Not set up yet - open Recovery Key",
    },
    {
      tone: deviceTone,
      title: "Device Keys Active",
      detail: securityReport === null
        ? "Checking device key material..."
        : identityActive
          ? securityReport.pqc_algorithm
          : "No active device keys on this device",
    },
    {
      tone: deviceTone,
      title: "Signature Verification",
      detail: securityReport === null
        ? "Checking signing identity..."
        : identityActive
          ? "ML-DSA-87 + Ed25519 vault signing active"
          : "Signing identity unavailable",
    },
  ];

  function vaultStatusIcon(tone: VaultStatusTone) {
    if (tone === "ok") return <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-500" size={18} />;
    if (tone === "pending") return <Loader2 className="mt-0.5 shrink-0 animate-spin text-ink-400" size={18} />;
    return <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={18} />;
  }

  return (
    <div className="grid gap-4">
      {/* Panel 1 — Quantum Vault Workspace */}
      <section className="shell-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-sm font-bold text-white shadow-tight">1</span>
            <div className="min-w-0">
              <h2 className="text-base font-bold text-ink-950">Quantum Vault Workspace</h2>
              <p className="mt-0.5 text-sm text-ink-600">
                {workspaceMode === "encrypt"
                  ? "Encrypt files or folders into local quantum-safe .qvault containers — nothing leaves this device."
                  : "Decrypt your .qvault files on this device, or recover them with your recovery key."}
              </p>
            </div>
          </div>
          <div className="inline-flex rounded-lg border border-line bg-canvas p-1" role="tablist" aria-label="Workspace mode">
            <button
              type="button"
              role="tab"
              aria-selected={workspaceMode === "encrypt"}
              onClick={() => setWorkspaceMode("encrypt")}
              className={`flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-bold transition ${workspaceMode === "encrypt" ? "bg-cyan-600 text-white shadow-tight" : "text-ink-600 hover:text-cyan-700"}`}
            >
              <LockKeyhole size={15} /> Encrypt
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={workspaceMode === "decrypt"}
              onClick={() => setWorkspaceMode("decrypt")}
              className={`flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-bold transition ${workspaceMode === "decrypt" ? "bg-violet-600 text-white shadow-tight" : "text-ink-600 hover:text-violet-700"}`}
            >
              <UnlockKeyhole size={15} /> Decrypt
            </button>
          </div>
        </div>

        {workspaceMode === "encrypt" ? (
          <div
            onClick={() => {
              if (!localVaultBusy) localEncryptFile();
            }}
            onKeyDown={(event) => {
              if (localVaultBusy || (event.key !== "Enter" && event.key !== " ")) return;
              event.preventDefault();
              localEncryptFile();
            }}
            role="button"
            tabIndex={localVaultBusy ? -1 : 0}
            className="vault-upload-dropzone mt-4 flex min-h-52 flex-col items-center justify-center rounded-lg border border-dashed p-6 text-center transition focus:outline-none focus:ring-2 focus:ring-cyan-400/60"
          >
            {localVaultBusy?.startsWith("encrypt") ? <Loader2 className="vault-dropzone-icon mb-3 animate-spin" size={44} /> : <LockKeyhole className="vault-dropzone-icon mb-3" size={44} />}
            <div className="vault-dropzone-title text-lg font-bold">{localVaultBusy?.startsWith("encrypt") ? "Encryption running" : "Choose a file or folder to encrypt"}</div>
            <div className="vault-dropzone-subtitle mt-1 text-sm font-medium">Sealed on-device with the VMK envelope · X25519 + ML-KEM-1024 / AES-256-GCM / HKDF-SHA3-256 / ML-DSA-87</div>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              <button
                type="button"
                disabled={localVaultBusy !== null}
                onClick={(event) => { event.stopPropagation(); localEncryptFile(); }}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {localVaultBusy === "encrypt-file" ? <Loader2 className="animate-spin" size={16} /> : <LockKeyhole size={16} />} Encrypt File
              </button>
              <button
                type="button"
                disabled={localVaultBusy !== null}
                onClick={(event) => { event.stopPropagation(); localEncryptFolder(); }}
                className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-5 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {localVaultBusy === "encrypt-folder" ? <Loader2 className="animate-spin" size={16} /> : <FolderOpen size={16} />} Encrypt Folder
              </button>
            </div>
            <div className="vault-dropzone-note mt-3 text-xs">
              Local-only, offline, any size. Encrypted .qvault files stay exactly where you save them.
            </div>
          </div>
        ) : (
          <div
            onClick={() => {
              if (!localVaultBusy) localDecryptFile();
            }}
            onKeyDown={(event) => {
              if (localVaultBusy || (event.key !== "Enter" && event.key !== " ")) return;
              event.preventDefault();
              localDecryptFile();
            }}
            role="button"
            tabIndex={localVaultBusy ? -1 : 0}
            className="vault-upload-dropzone mt-4 flex min-h-52 flex-col items-center justify-center rounded-lg border border-dashed p-6 text-center transition focus:outline-none focus:ring-2 focus:ring-violet-400/60"
          >
            {localVaultBusy?.startsWith("decrypt") ? <Loader2 className="vault-dropzone-icon mb-3 animate-spin" size={44} /> : <UnlockKeyhole className="vault-dropzone-icon mb-3" size={44} />}
            <div className="vault-dropzone-title text-lg font-bold">{localVaultBusy?.startsWith("decrypt") ? "Decryption running" : "Choose a .qvault file or folder to decrypt"}</div>
            <div className="vault-dropzone-subtitle mt-1 text-sm font-medium">Restore on this device, or use the recovery key (Recovery Key panel) on a new device.</div>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              <button
                type="button"
                disabled={localVaultBusy !== null}
                onClick={(event) => { event.stopPropagation(); localDecryptFile(); }}
                className="flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {localVaultBusy === "decrypt-file" ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />} Decrypt File
              </button>
              <button
                type="button"
                disabled={localVaultBusy !== null}
                onClick={(event) => { event.stopPropagation(); localDecryptFolder(); }}
                className="flex items-center gap-2 rounded-lg border border-violet-200 bg-white px-5 py-2 text-sm font-bold text-violet-700 hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {localVaultBusy === "decrypt-folder" ? <Loader2 className="animate-spin" size={16} /> : <FolderOpen size={16} />} Decrypt Folder
              </button>
            </div>
            <div className="vault-dropzone-note mt-3 text-xs">
              Decryption happens entirely on this device. Lost this device? Use your recovery key on a new one.
            </div>
          </div>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          <span className="font-semibold text-emerald-600">{status}</span>
          {localVaultResult && <span className="status-pill bg-emerald-50 text-emerald-600"><CheckCircle2 size={12} /> {localVaultResult}</span>}
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          {[
            { algo: "ML-KEM-1024", label: "Key encapsulation", sub: "Protects the VMK · X25519", Icon: KeyRound, tone: "text-cyan-600" },
            { algo: "AES-256-GCM", label: "Bulk cipher", sub: "FEK · authenticated", Icon: LockKeyhole, tone: "text-cyan-600" },
            { algo: "HKDF-SHA3-256", label: "Key derivation", sub: "Wrap & recovery keys", Icon: Terminal, tone: "text-cyan-600" },
            { algo: "ML-DSA-87", label: "Signature", sub: "FIPS 204 L5 · Ed25519", Icon: FileCheck2, tone: "text-cyan-600" },
            { algo: "Quantum Safe", label: "FIPS 203 / 204", sub: "VMK envelope", Icon: ShieldCheck, tone: "text-emerald-600" },
          ].map((card) => (
            <div key={card.algo} className="rounded-lg border border-line bg-white p-3">
              <card.Icon className={card.tone} size={18} />
              <div className="mt-2 truncate font-mono text-sm font-bold text-ink-950">{card.algo}</div>
              <div className="text-xs font-semibold text-ink-600">{card.label}</div>
              <div className="text-[11px] text-ink-400">{card.sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Vault Crypto Terminal */}
      <section className="overflow-hidden rounded-lg border border-line bg-ink-950 shadow-soft">
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Terminal size={16} />
            Vault Crypto Terminal
          </div>
          <span className="text-xs font-semibold text-cyan-200">On-device vault logs</span>
        </div>
        {liveStep && (() => {
          const { p, pct, elapsedMs } = liveStep;
          return (
            <div className="border-b border-white/10 px-4 py-3">
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="flex items-center gap-2 font-bold text-white">
                  <Loader2 className="animate-spin text-cyan-300" size={13} />
                  {opLabel(p.op)} <span className="text-cyan-200">· {phaseLabel(p.phase)}</span>
                </span>
                <span className="font-mono text-cyan-200">{pct}%</span>
              </div>
              <div className="mt-1.5 truncate font-mono text-[11px] text-cyan-100/70">{p.message}</div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-violet-500 transition-[width] duration-300 ease-out"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-cyan-100/80">
                {p.totalBytes > 0 && <span>{formatBytes(p.processedBytes)} / {formatBytes(p.totalBytes)}</span>}
                {p.processedBytes > 0 && <span>{formatThroughput(p.processedBytes, elapsedMs)}</span>}
                {p.phase === "chunk" && <span>{formatEta(p.processedBytes, p.totalBytes, elapsedMs)}</span>}
                {p.totalChunks > 0 && <span>chunk {p.chunkIndex}/{p.totalChunks}</span>}
              </div>
            </div>
          );
        })()}
        <div ref={terminalRef} className="max-h-56 space-y-2 overflow-y-auto p-4 font-mono text-xs">
          {terminalLogs.length === 0 && (
            <div className="text-cyan-100/70">Waiting for an encrypt or decrypt action...</div>
          )}
          {terminalLogs.map((log) => (
            <div key={log.id} className={log.level === "error" ? "text-rose-300" : log.level === "success" ? "text-emerald-300" : "text-cyan-100"}>
              <span className="text-white/40">[{new Date(log.at).toLocaleTimeString()}]</span> {log.message}
            </div>
          ))}
        </div>
      </section>

      {/* Panel 2 — Vault Status & Recovery */}
      <section className="shell-card p-5">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-sm font-bold text-white shadow-tight">2</span>
          <div className="min-w-0">
            <h2 className="text-base font-bold text-ink-950">Vault Status &amp; Recovery</h2>
            <p className="mt-0.5 text-sm text-ink-600">Your local vault security and recovery configuration.</p>
          </div>
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          {/* Vault Status */}
          <div className="flex flex-col rounded-lg border border-line bg-white p-4">
            <div className="text-sm font-bold text-ink-950">Vault Status</div>
            <div className="mt-4 grid gap-4">
              {vaultStatusRows.map((row) => (
                <div key={row.title} className="flex items-start gap-3">
                  {vaultStatusIcon(row.tone)}
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-ink-950">{row.title}</div>
                    <div className="text-xs text-ink-500">{row.detail}</div>
                  </div>
                </div>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setVaultStatusModalOpen(true)}
              className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 transition hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700"
            >
              View Details
            </button>
          </div>

          {/* Recovery Key */}
          <div className="flex flex-col rounded-lg border border-line bg-white p-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                <KeyRound size={16} className="text-cyan-600" /> Recovery Key
              </div>
              <span className={`status-pill ${recoveryStatus?.enabled ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-700"}`}>
                {recoveryStatus?.enabled ? <><ShieldCheck size={12} /> Enabled</> : <><AlertTriangle size={12} /> Not set up</>}
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-ink-600">
              Quantum-safe, zero-knowledge recovery (HKDF-SHA3-256 / AES-256-GCM). Decrypt your vault on a new device if this one is lost — the key never leaves your hands.
            </p>
            {recoveryStatus?.enabled && (
              <p className="mt-2 text-[11px] text-ink-500">
                Mode: <span className="font-semibold capitalize text-ink-700">{recoveryStatus.mode ?? "personal"}</span>
                {recoveryStatus.configuredAt ? ` · ${new Date(recoveryStatus.configuredAt).toLocaleDateString()}` : ""}
              </p>
            )}
            <button
              type="button"
              onClick={() => setRecoveryModalOpen(true)}
              className="mt-auto flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700"
            >
              <KeyRound size={16} /> {recoveryStatus?.enabled ? "Manage recovery" : "Set up recovery"}
            </button>
            {recoveryNotice && (
              <div className="mt-2 break-words rounded-lg border border-cyan-100 bg-cyan-50 px-3 py-2 text-[11px] font-semibold text-cyan-700">{recoveryNotice}</div>
            )}
          </div>

          {/* Security Profile */}
          <div className="rounded-lg border border-line bg-white p-4">
            <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
              <ShieldCheck size={16} className="text-emerald-600" /> Security Profile
            </div>
            <dl className="mt-4 grid gap-2 text-xs">
              {([
                ["Profile", "High security (Quantum Vault)"],
                ["Envelope", "FEK → VMK → ML-KEM-1024"],
                ["Key exchange", "X25519 + ML-KEM-1024"],
                ["Signature", "Ed25519 + ML-DSA-87"],
                ["Cipher", "AES-256-GCM"],
                ["Key derivation", "HKDF-SHA3-256"],
                ["Zero-knowledge", "Local-only · keys never leave device"],
              ] as const).map(([term, value]) => (
                <div key={term} className="flex items-center justify-between gap-2 border-b border-line pb-2 last:border-0 last:pb-0">
                  <dt className="font-semibold text-ink-500">{term}</dt>
                  <dd className="text-right font-semibold text-ink-800">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      {/* Vault Status modal */}
      {confirmDialog && (() => {
        const { kind, entry } = confirmDialog;
        const kindLabel = entry.kind === "folder" ? "folder" : "file";
        const isDelete = kind === "delete";
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/50 p-4 backdrop-blur-sm" onClick={() => setConfirmDialog(null)}>
            <div className="w-full max-w-md rounded-xl border border-white/30 bg-white p-5 shadow-soft" onClick={(event) => event.stopPropagation()}>
              <div className="flex items-center gap-3">
                <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full ${isDelete ? "bg-rose-50 text-rose-600" : "bg-amber-50 text-amber-600"}`}>
                  {isDelete ? <Trash2 size={20} /> : <AlertTriangle size={20} />}
                </span>
                <div className="min-w-0">
                  <h3 className="text-base font-bold text-ink-950">
                    {isDelete ? `Permanently delete this ${kindLabel}?` : `Remove this ${kindLabel} from the list?`}
                  </h3>
                  <p className="mt-0.5 truncate text-xs text-ink-500" title={entry.name}>{entry.name}</p>
                </div>
              </div>
              <div className={`mt-4 rounded-lg border p-3 text-sm leading-relaxed ${isDelete ? "border-rose-200 bg-rose-50 text-rose-700" : "border-amber-200 bg-amber-50 text-amber-800"}`}>
                {isDelete
                  ? `Are you sure you want to permanently delete this ${kindLabel}? This erases the encrypted .qvault container from disk. It is unrecoverable and cannot be undone.`
                  : `Remove this ${kindLabel} from your vault list only. The encrypted .qvault file stays on disk and can be re-added later.`}
              </div>
              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmDialog(null)}
                  className="rounded-lg border border-line bg-white px-4 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setConfirmDialog(null);
                    if (isDelete) void deleteRegistryFile(entry);
                    else removeFromList(entry);
                  }}
                  className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-bold text-white transition ${isDelete ? "bg-rose-600 hover:bg-rose-700" : "bg-ink-950 hover:opacity-90"}`}
                >
                  {isDelete ? <><Trash2 size={15} /> Delete permanently</> : <><X size={15} /> Remove from list</>}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {vaultStatusModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/50 p-4 backdrop-blur-sm" onClick={() => setVaultStatusModalOpen(false)}>
          <div className="max-h-[88vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-white/30 bg-white p-5 shadow-soft" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-base font-bold text-ink-950">
                <ShieldCheck size={18} className="text-emerald-600" /> Vault Status
              </div>
              <button type="button" onClick={() => setVaultStatusModalOpen(false)} className="icon-button" title="Close"><X size={18} /></button>
            </div>
            <p className="mt-2 text-sm text-ink-600">
              Live security posture for your quantum vault on this device. Every value is derived from real device key material and your local vault registry. Nothing is stored in the cloud.
            </p>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {vaultStatusRows.map((row) => (
                <div key={row.title} className="flex items-start gap-3 rounded-lg border border-line bg-canvas p-3">
                  {vaultStatusIcon(row.tone)}
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-ink-950">{row.title}</div>
                    <div className="text-xs text-ink-500">{row.detail}</div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {([
                ["Files", String(explorerFileCount)],
                ["Folders", String(explorerFolderCount)],
                ["Encrypted", formatBytes(vaultTotalBytes)],
                ["Tracked", String(visibleRegistry.length)],
              ] as const).map(([label, value]) => (
                <div key={label} className="rounded-lg border border-line bg-white p-3">
                  <div className="text-lg font-bold text-ink-950">{value}</div>
                  <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-400">{label}</div>
                </div>
              ))}
            </div>

            <div className="mt-4 rounded-lg border border-line p-4">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                <ShieldCheck size={16} className="text-cyan-600" /> Device &amp; cryptographic posture
              </div>
              {securityReport ? (
                <dl className="mt-3 grid gap-2 text-xs">
                  {([
                    ["Hybrid session", securityReport.hybrid_session_status],
                    ["PQC algorithms", securityReport.pqc_algorithm],
                    ["Forward secrecy", securityReport.forward_secrecy],
                    ["HNDL protection", securityReport.hndl_protection],
                    ["Quantum-safe score", `${securityReport.quantum_safe_score}/100`],
                  ] as const).map(([term, value]) => (
                    <div key={term} className="flex items-center justify-between gap-2 border-b border-line pb-2 last:border-0 last:pb-0">
                      <dt className="font-semibold text-ink-500">{term}</dt>
                      <dd className="text-right font-semibold text-ink-800">{value}</dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <div className="mt-3 flex items-center gap-2 text-xs text-ink-500">
                  <Loader2 className="animate-spin" size={14} /> Reading device key material...
                </div>
              )}
              {securityReport && securityReport.warnings.length > 0 && (
                <div className="mt-3 space-y-1">
                  {securityReport.warnings.map((warning) => (
                    <div key={warning} className="flex items-start gap-2 rounded-lg border border-amber-100 bg-amber-50 px-3 py-2 text-[11px] font-semibold text-amber-800">
                      <AlertTriangle size={13} className="mt-0.5 shrink-0" /> {warning}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-4 rounded-lg border border-line p-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                  <KeyRound size={16} className="text-cyan-600" /> Recovery configuration
                </div>
                <span className={`status-pill ${recoveryStatus?.enabled ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-700"}`}>
                  {recoveryStatus?.enabled ? <><ShieldCheck size={12} /> Enabled</> : <><AlertTriangle size={12} /> Not set up</>}
                </span>
              </div>
              <p className="mt-2 text-xs text-ink-600">
                {recoveryStatus?.enabled
                  ? `Mode ${recoveryStatus.mode ?? "personal"}${recoveryStatus.recipientKeyId ? ` - enterprise key ${recoveryStatus.recipientKeyId}` : ""}${recoveryStatus.configuredAt ? ` - configured ${new Date(recoveryStatus.configuredAt).toLocaleString()}` : ""}. New vault files are protected automatically.`
                  : "No recovery key is configured. Set one up so you can decrypt your vault on a new device if this one is lost."}
              </p>
              <button
                type="button"
                onClick={() => { setVaultStatusModalOpen(false); setRecoveryModalOpen(true); }}
                className="mt-3 flex items-center justify-center gap-2 rounded-lg border border-cyan-200 bg-white px-4 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50"
              >
                <KeyRound size={16} /> {recoveryStatus?.enabled ? "Manage recovery" : "Set up recovery"}
              </button>
            </div>

            <div className="mt-4 rounded-lg border border-line p-4">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                  <History size={16} className="text-ink-500" /> Recent vault activity
                </div>
                <span className="text-[11px] font-semibold text-ink-400">{vaultLastActivityAt ? `Last activity ${new Date(vaultLastActivityAt).toLocaleString()}` : "No activity yet"}</span>
              </div>
              {historyEntries.length > 0 ? (
                <ul className="mt-3 space-y-2">
                  {historyEntries.slice(0, 6).map((entry) => (
                    <li key={entry.id} className="flex items-start gap-2 text-xs">
                      <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                      <div className="min-w-0 flex-1">
                        <div className="font-semibold capitalize text-ink-800">{entry.title}</div>
                        <div className="truncate text-ink-500">{entry.detail}</div>
                      </div>
                      <span className="shrink-0 text-[10px] text-ink-400">{new Date(entry.at).toLocaleTimeString()}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="mt-3 text-xs text-ink-500">No vault activity yet. Encrypt a file to see it here.</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Recovery management modal */}
      {recoveryModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/50 p-4 backdrop-blur-sm" onClick={() => setRecoveryModalOpen(false)}>
          <div className="max-h-[88vh] w-full max-w-xl overflow-y-auto rounded-xl border border-white/30 bg-white p-5 shadow-soft" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-base font-bold text-ink-950">
                <KeyRound size={18} className="text-cyan-600" /> Recovery Key
              </div>
              <button type="button" onClick={() => setRecoveryModalOpen(false)} className="icon-button" title="Close"><X size={18} /></button>
            </div>
            <p className="mt-2 text-sm text-ink-600">
              A quantum-safe recovery key (AES-256-GCM / HKDF-SHA3-256) lets you decrypt your vault files on a brand-new device if this one is lost, stolen, or damaged — install QGuard, sign in, and enter the key. It is one-way and zero-knowledge: never sent to or stored on the server, and it cannot be reverse-engineered or recreated.
            </p>

            {recoveryStatus?.enabled ? (
              <div className="mt-4 rounded-lg border border-emerald-100 bg-emerald-50 p-3">
                <div className="text-xs font-semibold text-emerald-700">
                  Recovery is active — mode <span className="capitalize">{recoveryStatus.mode ?? "personal"}</span>
                  {recoveryStatus.recipientKeyId ? ` · Enterprise key ${recoveryStatus.recipientKeyId}` : ""}
                  {recoveryStatus.configuredAt ? ` · configured ${new Date(recoveryStatus.configuredAt).toLocaleString()}` : ""}. New vault files are protected automatically.
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={recoveryBusy !== null}
                    onClick={reprotectExistingFiles}
                    title="Upgrade existing .qvault files to the v3 VMK envelope and add the recovery key"
                    className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-4 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {recoveryBusy === "rewrap" ? <Loader2 className="animate-spin" size={16} /> : <ShieldCheck size={16} />}
                    Re-protect existing files
                  </button>
                </div>
              </div>
            ) : (
              <div className="mt-4">
                <div className="grid grid-cols-3 gap-1 rounded-lg border border-line bg-canvas p-1" role="radiogroup" aria-label="Recovery mode">
                  {([
                    { id: "personal", label: "Personal" },
                    { id: "enterprise", label: "Enterprise" },
                    { id: "hybrid", label: "Hybrid" },
                  ] as const).map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      role="radio"
                      aria-checked={recoveryMode === m.id}
                      onClick={() => setRecoveryMode(m.id)}
                      className={`rounded-md px-2 py-1.5 text-xs font-bold transition ${recoveryMode === m.id ? "bg-cyan-600 text-white" : "text-ink-600 hover:bg-white/70"}`}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-[11px] leading-snug text-ink-500">
                  {recoveryMode === "personal" && "Recovery key only — HKDF-SHA3-256 → AES-256-GCM."}
                  {recoveryMode === "enterprise" && "Enterprise ML-KEM-1024 recipient only — for admin-held post-quantum recovery."}
                  {recoveryMode === "hybrid" && "Requires BOTH the recovery key and the ML-KEM-1024 key. For high-security tenants."}
                </p>
                <button
                  type="button"
                  disabled={recoveryBusy !== null}
                  onClick={setupRecovery}
                  className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {recoveryBusy === "setup" ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />}
                  Set up {recoveryMode} recovery
                </button>
              </div>
            )}

            <div className="mt-4 rounded-lg border border-line p-4">
              <div className="flex items-center gap-2 text-sm font-bold text-ink-950">
                <UnlockKeyhole size={16} /> Recover on a device
              </div>
              <p className="mt-1 text-xs text-ink-600">
                Enter your recovery key, then decrypt a .qvault file or folder straight from your external drive. You can also enable the key on this device so new files are protected by it too.
              </p>
              <input
                value={recoveryKeyInput}
                onChange={(event) => setRecoveryKeyInput(event.target.value)}
                placeholder="XXXX-XXXX-XXXX-…  (personal recovery key; required for personal & hybrid)"
                spellCheck={false}
                autoComplete="off"
                className="mt-3 w-full rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-sm outline-none focus:border-cyan-300"
              />
              <textarea
                value={enterpriseKeyInput}
                onChange={(event) => setEnterpriseKeyInput(event.target.value)}
                placeholder="QG-EK1-…  (enterprise ML-KEM-1024 recovery key; for enterprise & hybrid)"
                spellCheck={false}
                autoComplete="off"
                rows={2}
                className="mt-2 w-full resize-none rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-xs outline-none focus:border-cyan-300"
              />
              <div className="mt-3 grid gap-2 sm:grid-cols-3">
                <button
                  type="button"
                  disabled={recoveryBusy !== null || (!recoveryKeyInput.trim() && !enterpriseKeyInput.trim())}
                  onClick={recoverDecryptFile}
                  className="flex items-center justify-center gap-2 rounded-lg border border-emerald-200 bg-white px-3 py-2 text-sm font-bold text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {recoveryBusy === "decrypt-file" ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
                  Recover file
                </button>
                <button
                  type="button"
                  disabled={recoveryBusy !== null || (!recoveryKeyInput.trim() && !enterpriseKeyInput.trim())}
                  onClick={recoverDecryptFolder}
                  className="flex items-center justify-center gap-2 rounded-lg border border-emerald-200 bg-white px-3 py-2 text-sm font-bold text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {recoveryBusy === "decrypt-folder" ? <Loader2 className="animate-spin" size={16} /> : <FolderOpen size={16} />}
                  Recover folder
                </button>
                <button
                  type="button"
                  disabled={recoveryBusy !== null || !recoveryKeyInput.trim()}
                  onClick={enableRecoveryWithKey}
                  className="flex items-center justify-center gap-2 rounded-lg border border-line bg-white px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {recoveryBusy === "enable" ? <Loader2 className="animate-spin" size={16} /> : <KeyRound size={16} />}
                  Enable on this device
                </button>
              </div>
              {recoveryNotice && (
                <div className="mt-3 break-words rounded-lg border border-cyan-100 bg-cyan-50 px-3 py-2 text-xs font-semibold text-cyan-700">{recoveryNotice}</div>
              )}
            </div>
          </div>
        </div>
      )}

      {(generatedRecoveryKey || generatedEnterpriseKey) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/50 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-white/30 bg-white p-5 shadow-soft">
            <div className="flex items-center gap-2 text-base font-bold text-ink-950">
              <KeyRound size={18} className="text-cyan-600" /> Save your recovery key material
            </div>
            <div className="mt-2 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs font-semibold text-amber-800">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              Save this now and keep it offline — it is shown only once. QGuard cannot recover it for you if it is lost. Anyone with this key material and access to your encrypted vault data may be able to recover protected files.
            </div>
            {generatedRecoveryKey && (
              <div className="mt-3">
                <div className="text-[11px] font-bold uppercase tracking-wide text-ink-400">Recovery key</div>
                <div className="mt-1 select-all break-words rounded-lg border border-line bg-canvas p-3 text-center font-mono text-sm tracking-wide text-ink-950">{generatedRecoveryKey}</div>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <button type="button" onClick={copyGeneratedRecoveryKey} className="flex items-center justify-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"><Copy size={16} /> Copy</button>
                  <button type="button" onClick={downloadGeneratedRecoveryKey} className="flex items-center justify-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"><Download size={16} /> Download</button>
                </div>
              </div>
            )}
            {generatedEnterpriseKey && (
              <div className="mt-3">
                <div className="text-[11px] font-bold uppercase tracking-wide text-ink-400">Enterprise ML-KEM-1024 recovery key</div>
                <div className="mt-1 max-h-24 overflow-y-auto break-all rounded-lg border border-line bg-canvas p-3 font-mono text-[11px] text-ink-700">{generatedEnterpriseKey}</div>
                <button type="button" onClick={downloadGeneratedEnterpriseKey} className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg border border-line px-3 py-2 text-sm font-bold text-ink-700 hover:bg-canvas"><Download size={16} /> Download enterprise key</button>
              </div>
            )}
            <label className="mt-3 flex items-center gap-2 text-sm font-semibold text-ink-700">
              <input type="checkbox" checked={recoverySaved} onChange={(event) => setRecoverySaved(event.currentTarget.checked)} className="h-4 w-4 rounded border-line text-cyan-600 focus:ring-cyan-400" />
              I have saved my recovery key material in a safe place.
            </label>
            <button
              type="button"
              disabled={!recoverySaved}
              onClick={() => {
                setGeneratedRecoveryKey(null);
                setGeneratedEnterpriseKey(null);
                setRecoveryNotice("Recovery is active. New vault files are now protected.");
              }}
              className="mt-4 w-full rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* Panel 3 — Vault Explorer */}
      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-sm font-bold text-white shadow-tight">3</span>
              <div>
                <h2 className="text-sm font-bold text-ink-950">Vault Explorer</h2>
                <div className="mt-1 text-xs text-ink-600">Your encrypted .qvault files and folders on this device.</div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {activeVaultTab === "explorer" && (
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-400" size={15} />
                  <input
                    value={explorerQuery}
                    onChange={(event) => setExplorerQuery(event.currentTarget.value)}
                    placeholder="Search files…"
                    className="h-9 w-44 rounded-lg border border-line bg-canvas pl-8 pr-3 text-sm outline-none focus:border-cyan-300"
                  />
                </div>
              )}
              {[
                { id: "explorer" as const, label: "Files & Folders", icon: FolderOpen },
                { id: "operations" as const, label: "Operations", icon: ShieldCheck },
                { id: "history" as const, label: "History", icon: History },
              ].map((tab) => {
                const Icon = tab.icon;
                const active = activeVaultTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveVaultTab(tab.id)}
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-bold transition ${
                      active
                        ? "border-cyan-200 bg-cyan-50 text-cyan-700 shadow-tight"
                        : "border-line bg-white text-ink-500 hover:border-cyan-200 hover:text-cyan-700"
                    }`}
                  >
                    <Icon size={14} />
                    {tab.label}
                  </button>
                );
              })}
              <span className="status-pill bg-emerald-50 text-emerald-700"><ShieldCheck size={13} />Local-only</span>
            </div>
          </div>
        </div>

        {activeVaultTab === "operations" && (
          <>
            <div className="grid grid-cols-[1.4fr_120px_130px_140px_150px_190px] border-b border-line px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>Name</span><span>Status</span><span>Size</span><span>Algorithm</span><span>Date</span><span>Actions</span>
            </div>
            {visibleRegistry.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">No vault operations yet. Encrypt a file to start.</div>
            )}
            {visibleRegistry.map((entry) => (
              <div key={entry.id} className="grid grid-cols-[1.4fr_120px_130px_140px_150px_190px] items-center gap-3 border-b border-line px-4 py-3 text-sm">
                <div className="min-w-0">
                  <div className="truncate font-semibold text-ink-950">{entry.name}</div>
                  <div className="mt-1 truncate font-mono text-xs text-ink-400">{entry.qvaultPath}</div>
                </div>
                <span className={`status-pill justify-center ${entry.status === "decrypted" ? "bg-emerald-50 text-emerald-600" : "bg-cyan-50 text-cyan-700"}`}>
                  {entry.status === "decrypted" ? <UnlockKeyhole size={13} /> : <LockKeyhole size={13} />}
                  {entry.status}
                </span>
                <div className="text-xs text-ink-600">{formatBytes(entry.sizeBytes)}</div>
                <div className="truncate font-mono text-[11px] text-ink-500">{shortSuiteLabel(entry.suite)}</div>
                <div className="text-xs text-ink-500">{new Date(entry.updatedAt).toLocaleDateString()}</div>
                {renderEntryActions(entry)}
              </div>
            ))}
          </>
        )}

        {activeVaultTab === "explorer" && (
          <div className="overflow-x-auto">
            <div className="min-w-[1020px]">
            <div className="grid grid-cols-[minmax(180px,1.4fr)_120px_120px_90px_140px_110px_180px] gap-3 border-b border-line px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>Name</span><span>Status</span><span>Integrity</span><span>Size</span><span>Algorithm</span><span>Date</span><span>Actions</span>
            </div>
            {filteredExplorerNodes.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">{explorerSearch ? "No files match your search." : "No encrypted files or folders yet. Encrypt something to see it here."}</div>
            )}
            {filteredExplorerNodes.length > 0 && (
              <div role="tree" aria-label="Quantum Vault file explorer" className="max-h-[620px] overflow-y-auto">
                {filteredExplorerNodes.map((node) => {
                  const expanded = Boolean(expandedFolders[node.path]);
                  const selected = selectedExplorerNodeId === node.id;
                  const indent = explorerSearch ? 0 : node.depth;
                  return (
                    <div
                      key={node.id}
                      role="treeitem"
                      aria-level={node.depth + 1}
                      aria-expanded={node.type === "folder" ? expanded : undefined}
                      aria-selected={selected}
                      tabIndex={0}
                      onClick={() => selectExplorerNode(node)}
                      onKeyDown={(event) => handleExplorerNodeKeyDown(event, node)}
                      className={`vault-tree-row grid min-h-[60px] grid-cols-[minmax(180px,1.4fr)_120px_120px_90px_140px_110px_180px] items-center gap-3 border-b border-line px-4 py-3 text-sm outline-none transition ${
                        selected
                          ? "bg-cyan-50 shadow-[inset_3px_0_0_#0891b2]"
                          : "bg-white hover:bg-cyan-50/50 focus:bg-cyan-50/60"
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="flex min-w-0 items-center gap-2 font-semibold text-ink-950" style={{ paddingLeft: `${indent * 20}px` }}>
                          {node.type === "folder" && !explorerSearch ? (
                            <button
                              type="button"
                              onClick={(event) => {
                                event.stopPropagation();
                                toggleExplorerFolder(node);
                              }}
                              className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-ink-500 transition hover:bg-white hover:text-cyan-700"
                              aria-label={expanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
                            >
                              {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                            </button>
                          ) : (
                            <span className="h-6 w-6 shrink-0" aria-hidden="true" />
                          )}
                          {node.type === "folder"
                            ? expanded
                              ? <FolderOpen className="shrink-0 text-cyan-600" size={17} />
                              : <Folder className="shrink-0 text-cyan-600" size={17} />
                            : renderFileTypeIcon(node)}
                          <span className="truncate">{node.name}</span>
                        </div>
                        {(explorerSearch || node.depth > 0) && (
                          <div className="mt-0.5 truncate font-mono text-[11px] text-ink-400" style={{ paddingLeft: `${indent * 20 + 32}px` }}>{node.entry?.qvaultPath ?? node.path}</div>
                        )}
                      </div>
                      <div className="min-w-0">
                        {node.entry ? (
                          <span className={`status-pill justify-center ${node.entry.status === "decrypted" ? "bg-emerald-50 text-emerald-600" : "bg-cyan-50 text-cyan-700"}`}>
                            {node.entry.status === "decrypted" ? <UnlockKeyhole size={13} /> : <LockKeyhole size={13} />}
                            {node.entry.status}
                          </span>
                        ) : (
                          <span className="status-pill justify-center bg-ink-50 text-ink-600"><Folder size={13} />folder</span>
                        )}
                      </div>
                      <span className="status-pill justify-center bg-emerald-50 text-emerald-600">
                        <FileCheck2 size={13} />
                        {node.entry ? (node.entry.integrity === "verified" ? "Verified" : "Pending") : "Verified"}
                      </span>
                      <div className="text-xs font-semibold text-ink-600">{nodeItemText(node)}</div>
                      <div className="truncate font-mono text-[11px] text-ink-500">
                        {node.type === "file" ? shortSuiteLabel(node.entry?.suite ?? null) : "—"}
                      </div>
                      <div className="text-xs text-ink-500">{new Date(node.updated_at).toLocaleDateString()}</div>
                      <div onClick={(event) => event.stopPropagation()}>
                        {node.entry ? renderEntryActions(node.entry) : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-3 text-xs text-ink-500">
              <span>{explorerFileCount} files · {explorerFolderCount} folders</span>
              <div className="flex items-center gap-2">
                {selectedExplorerNodeId && (
                  <span className="status-pill max-w-full bg-white text-ink-600">
                    Selected {allExplorerNodes.find((node) => node.id === selectedExplorerNodeId)?.name ?? "item"}
                  </span>
                )}
                <span className="status-pill bg-ink-50 text-ink-600">{filteredExplorerNodes.length} shown</span>
              </div>
            </div>
          </div>
        )}

        {activeVaultTab === "history" && (
          <div>
            <div className="grid grid-cols-[180px_120px_180px_1fr_100px] border-b border-line px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>Time</span><span>Source</span><span>Activity</span><span>Details</span><span>Status</span>
            </div>
            {historyEntries.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">No vault history yet.</div>
            )}
            {historyEntries.map((entry) => (
              <div key={entry.id} className="grid grid-cols-[180px_120px_180px_1fr_100px] items-center gap-3 border-b border-line px-4 py-3 text-sm">
                <div className="text-xs font-semibold text-ink-500">{new Date(entry.at).toLocaleString()}</div>
                <span className="status-pill justify-center bg-ink-50 text-ink-600">{entry.source}</span>
                <div className="truncate font-semibold text-ink-800">{entry.title}</div>
                <div className="truncate text-ink-600">{entry.detail}</div>
                <div className="truncate text-xs font-bold text-ink-500">{entry.status}</div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
