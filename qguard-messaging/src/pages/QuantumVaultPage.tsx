import {
  ChevronDown,
  ChevronRight,
  CheckCircle2,
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
  Loader2,
  LockKeyhole,
  Pause,
  Play,
  ShieldCheck,
  Terminal,
  Trash2,
  UnlockKeyhole,
  UploadCloud,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import {
  blobFromBase64,
  createSecureDecryptionStream,
  enforceClientDecryptionRateLimit,
  normalizeDecryptionError,
  unlockDevicePrivateKey,
  validateDecryptionSession,
  type DecryptionStatus,
} from "@/lib/secure-decryption";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";
import type { TelemetryEvent, VaultFileSummary } from "@/lib/types";

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
  files: VaultFileSummary[];
  telemetry: TelemetryEvent[];
  onUploaded: () => void;
}

interface EncryptedEnvelope {
  nonce: number[];
  ciphertext: number[];
  tag: number[];
}

interface EncryptedFilePackage {
  metadata: {
    file_id: string;
    encrypted_name: string;
    original_size: number;
    chunk_size: number;
    content_type: string;
    merkle_root: string;
    created_at: string;
  };
  encrypted_chunks: EncryptedEnvelope[];
  wrapped_keys: Array<{ recipient_device_id: string; [key: string]: unknown }>;
  metadata_signature: Record<string, unknown>;
  signer_ed25519_public: number[];
  signer_mldsa_public: number[];
  suite: Record<string, unknown>;
}

interface EncryptedFolderPackage {
  qguard_encrypted_folder_version: number;
  exported_at: string;
  folder_path: string;
  file_count: number;
  size_bytes: number;
  algorithm: string;
  files: Array<{
    file_id: string;
    display_name: string;
    size_bytes: number;
    content_type: string;
    package: EncryptedFilePackage;
  }>;
}

interface VaultManifest {
  version: number;
  metadata: EncryptedFilePackage["metadata"];
  wrapped_keys: EncryptedFilePackage["wrapped_keys"];
  metadata_signature: Record<string, unknown>;
  signer_ed25519_public: number[];
  signer_mldsa_public: number[];
  suite: Record<string, unknown>;
  chunk_paths: string[];
}

interface VaultOperation {
  id: string;
  user_id: string;
  file_id: string | null;
  operation_type: "encrypt" | "verify" | "download_encrypted" | "decrypt_download" | "delete";
  display_name_hint: string;
  status: "queued" | "processing" | "completed" | "failed";
  current_operation: string;
  progress: number;
  size_bytes: number;
  processed_bytes: number;
  algorithm: string;
  integrity_status: "pending" | "verified" | "failed" | "not_checked";
  error_message: string | null;
  attempts: number;
  started_at: string;
  updated_at: string;
  completed_at: string | null;
}

interface PanelRow extends VaultOperation {
  file: VaultFileSummary | null;
  display_name: string;
}

type VaultPanelTab = "operations" | "explorer" | "history";

interface VaultExplorerNode {
  id: string;
  type: "folder" | "file";
  name: string;
  path: string;
  parentPath: string | null;
  depth: number;
  rows: PanelRow[];
  row: PanelRow | null;
  children: VaultExplorerNode[];
  item_count: number;
  size_bytes: number;
  status: VaultOperation["status"];
  progress: number;
  integrity_status: VaultOperation["integrity_status"];
  updated_at: string;
}

interface VaultHistoryEntry {
  id: string;
  at: string;
  source: "operation" | "telemetry" | "terminal";
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

interface VaultPipelineControl {
  state: "idle" | "running" | "stop_requested" | "paused";
  operationId: string | null;
  label: string | null;
}

const algorithmLabel = "ML-KEM-1024 + X25519 + HKDF-SHA3-256 + AES-256-GCM + ML-DSA-65 + Ed25519";
const archiveExtensions = new Set(["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"]);
const codeExtensions = new Set(["c", "cpp", "css", "go", "html", "java", "js", "json", "jsx", "py", "rs", "sql", "tsx", "ts", "xml", "yaml", "yml"]);
const spreadsheetExtensions = new Set(["csv", "ods", "tsv", "xls", "xlsx"]);

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

function isMissingVaultOperationsTable(error: unknown): boolean {
  const message = describeError(error).toLowerCase();
  return (
    message.includes("qguard_vault_operations") &&
    (message.includes("could not find") || message.includes("schema cache") || message.includes("pgrst205"))
  );
}

function isMissingDisplayNameHintColumn(error: unknown): boolean {
  const message = describeError(error).toLowerCase();
  return message.includes("display_name_hint")
    && (message.includes("could not find") || message.includes("schema cache") || message.includes("does not exist") || message.includes("column"));
}

function isMissingDeleteRecordRpc(error: unknown): boolean {
  const message = describeError(error).toLowerCase();
  return message.includes("delete_messaging_vault_file_record")
    && (message.includes("could not find") || message.includes("schema cache") || message.includes("does not exist"));
}

function isLocalOperationId(operationId: string): boolean {
  return operationId.startsWith("local-");
}

function isWrappedFileKeyUnavailable(message: string): boolean {
  const lower = message.toLowerCase();
  return lower.includes("wrapped file key")
    || lower.includes("wrapped for another device key")
    || lower.includes("older local key");
}

function isVaultObjectNotFoundError(error: unknown): boolean {
  const message = describeError(error).toLowerCase();
  return message.includes("object not found")
    || message.includes("not found")
    || message.includes("404")
    || message.includes("no such key")
    || message.includes("does not exist")
    || message.includes("the resource was not found");
}

function normalizeVaultFileAccessError(error: unknown): string {
  return isVaultObjectNotFoundError(error) ? "File no longer exists" : describeError(error);
}

function normalizeVaultActionError(error: unknown): string {
  return describeError(error) === "File no longer exists" ? "File no longer exists" : describeError(error);
}

function fileDisplayName(file: File): string {
  return (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
}

function suiteLabel(suite?: Record<string, unknown> | null): string {
  if (!suite) return algorithmLabel;
  return [
    suite.pq_kem ?? "ML-KEM-1024",
    suite.classical_kex ?? "X25519",
    suite.kdf ?? "HKDF-SHA3-256",
    suite.symmetric ?? "AES-256-GCM",
    suite.pq_signature ?? "ML-DSA-65",
    suite.classical_signature ?? "Ed25519",
  ].map(String).join(" + ");
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "calculating";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}m ${rest}s`;
}

function elapsedSeconds(row: VaultOperation): number {
  const end = row.completed_at ? new Date(row.completed_at).getTime() : Date.now();
  return Math.max(0, (end - new Date(row.started_at).getTime()) / 1000);
}

function etaSeconds(row: VaultOperation): number {
  if (row.status === "completed" || row.status === "failed" || row.progress <= 0) return 0;
  const elapsed = elapsedSeconds(row);
  return Math.max(0, (elapsed / row.progress) * (100 - row.progress));
}

function jsonBlob(value: unknown): Blob {
  return new Blob([JSON.stringify(value)], { type: "application/json" });
}

function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.rel = "noopener";
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
    anchor.remove();
  }, 1000);
}

function downloadTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function safeDownloadPart(value: string, fallback: string): string {
  const cleaned = cleanExplorerPath(value)
    .replace(/[<>:"\\|?*\x00-\x1F]+/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/[. ]+$/g, "");
  const candidate = cleaned || fallback;
  const safeCandidate = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i.test(candidate) ? `_${candidate}` : candidate;
  return safeCandidate.slice(0, 160);
}

function safeFileName(value: string, fallback: string): string {
  const parts = cleanExplorerPath(value).split("/").filter(Boolean);
  return safeDownloadPart(parts.at(-1) ?? value, fallback);
}

function safeArchiveName(value: string, fallback: string): string {
  return safeDownloadPart(cleanExplorerPath(value).replace(/\//g, "__"), fallback);
}

function encryptedPackageDownloadName(displayName: string, fileId: string): string {
  return `${safeArchiveName(displayName, `vault-${fileId.slice(0, 8)}`)}.qguard.encrypted.json`;
}

function encryptedFolderDownloadName(displayName: string): string {
  return `${safeArchiveName(displayName, "vault-folder")}.${downloadTimestamp()}.qguard-folder.encrypted.json`;
}

function decryptedDownloadName(displayName: string, fileId: string): string {
  return safeFileName(displayName, `${fileId.slice(0, 8)}.decrypted`);
}

function localDecryptedDownloadName(displayName: string, fileId: string, preservePath: boolean): string {
  return preservePath
    ? safeArchiveName(displayName, `${fileId.slice(0, 8)}.decrypted`)
    : decryptedDownloadName(displayName, fileId);
}

function vaultFileLabel(file: VaultFileSummary): string {
  const parts = file.storage_path.split("/");
  const fileId = file.id.slice(0, 8);
  return parts.at(-2) === "chunks" ? `Vault object ${fileId}` : `Vault object ${fileId}`;
}

function isEncryptedEnvelope(value: unknown): value is EncryptedEnvelope {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return Array.isArray(record.nonce) && Array.isArray(record.ciphertext) && Array.isArray(record.tag);
}

function isEncryptedFilePackage(value: unknown): value is EncryptedFilePackage {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  const metadata = record.metadata as Record<string, unknown> | undefined;
  if (!metadata) return false;
  return typeof metadata.file_id === "string"
    && typeof metadata.encrypted_name === "string"
    && Array.isArray(record.encrypted_chunks)
    && record.encrypted_chunks.every(isEncryptedEnvelope)
    && Array.isArray(record.wrapped_keys)
    && record.wrapped_keys.length > 0
    && Boolean(record.metadata_signature)
    && Array.isArray(record.signer_ed25519_public)
    && Array.isArray(record.signer_mldsa_public);
}

function isEncryptedFolderPackage(value: unknown): value is EncryptedFolderPackage {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return record.qguard_encrypted_folder_version === 1
    && Array.isArray(record.files)
    && record.files.every((item) => {
      if (!item || typeof item !== "object") return false;
      const file = item as Record<string, unknown>;
      return typeof file.display_name === "string" && isEncryptedFilePackage(file.package);
    });
}

async function uploadWithRetry(path: string, body: Blob, contentType: string): Promise<void> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const { error } = await supabase.storage
      .from("messaging-files")
      .upload(path, body, { contentType, upsert: true });
    if (!error) return;
    lastError = error;
    await new Promise((resolve) => window.setTimeout(resolve, 300 * (attempt + 1)));
  }
  throw lastError instanceof Error ? lastError : new Error(describeError(lastError ?? "Encrypted upload failed"));
}

async function downloadWithRetry(path: string): Promise<Blob> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const { data, error } = await supabase.storage.from("messaging-files").download(path);
    if (!error && data) return data;
    lastError = error;
    await new Promise((resolve) => window.setTimeout(resolve, 300 * (attempt + 1)));
  }
  throw lastError instanceof Error ? lastError : new Error(describeError(lastError ?? "Encrypted download failed"));
}

async function readStorageJson<T>(path: string): Promise<T> {
  const blob = await downloadWithRetry(path);
  return JSON.parse(await blob.text()) as T;
}

function operationTone(status: VaultOperation["status"]): string {
  if (status === "completed") return "bg-emerald-50 text-emerald-600";
  if (status === "failed") return "bg-rose-50 text-rose-600";
  if (status === "processing") return "bg-cyan-50 text-cyan-700";
  return "bg-amber-50 text-amber-600";
}

function operationDisplayStatus(row: VaultOperation): string {
  if (row.current_operation.toLowerCase().startsWith("paused")) return "paused";
  return row.status;
}

function operationDisplayTone(row: VaultOperation): string {
  if (operationDisplayStatus(row) === "paused") return "bg-amber-50 text-amber-700";
  return operationTone(row.status);
}

function integrityText(value: VaultOperation["integrity_status"]): string {
  if (value === "verified") return "Verified";
  if (value === "failed") return "Failed";
  if (value === "not_checked") return "Not checked";
  return "Pending";
}

function isCompletedDeleteOperation(operation: VaultOperation): boolean {
  return operation.operation_type === "delete" && operation.status === "completed";
}

function isOrphanedDeletedOperation(operation: VaultOperation): boolean {
  if (operation.file_id) return false;
  if (operation.operation_type === "delete") return true;
  const text = `${operation.current_operation} ${operation.error_message ?? ""}`.toLowerCase();
  return operation.operation_type === "decrypt_download"
    && operation.status === "failed"
    && (
      text.includes("file no longer exists")
      || text.includes("wrapped for another device key")
      || text.includes("vault object is wrapped")
      || text.includes("deleted")
    );
}

function shouldShowVaultOperation(
  operation: VaultOperation,
  visibleFileIds: Set<string>,
  deletedFileIds: Record<string, true>,
): boolean {
  if (isCompletedDeleteOperation(operation) || isOrphanedDeletedOperation(operation)) return false;
  if (operation.file_id && deletedFileIds[operation.file_id]) return false;
  if (operation.file_id && !visibleFileIds.has(operation.file_id) && operation.status !== "processing" && operation.status !== "queued") return false;
  return true;
}

function cleanExplorerPath(value: string): string {
  return value
    .replace(/\\/g, "/")
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");
}

function combineStatus(current: VaultOperation["status"], next: VaultOperation["status"]): VaultOperation["status"] {
  if (current === "failed" || next === "failed") return "failed";
  if (current === "processing" || next === "processing") return "processing";
  if (current === "queued" || next === "queued") return "queued";
  return "completed";
}

function combineIntegrity(
  current: VaultOperation["integrity_status"],
  next: VaultOperation["integrity_status"],
): VaultOperation["integrity_status"] {
  if (current === "failed" || next === "failed") return "failed";
  if (current === "verified" && next === "verified") return "verified";
  if (current === "not_checked" || next === "not_checked") return "not_checked";
  return "pending";
}

function isGenericVaultDisplayName(value: string): boolean {
  return cleanExplorerPath(value).toLowerCase().startsWith("vault object ");
}

function preferExplorerName(current: string | undefined, next: string): string {
  if (!current) return next;
  const currentDepth = cleanExplorerPath(current).split("/").filter(Boolean).length;
  const nextDepth = cleanExplorerPath(next).split("/").filter(Boolean).length;
  if (nextDepth > currentDepth) return next;
  if (nextDepth === currentDepth && next.length > current.length) return next;
  return current;
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
  const visit = (currentNodes: VaultExplorerNode[]) => {
    currentNodes.forEach((node) => {
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
  const visit = (currentNodes: VaultExplorerNode[]) => {
    currentNodes.forEach((node) => {
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
  const contentType = node.row?.file?.content_type.toLowerCase() ?? "";
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

export default function QuantumVaultPage({ userId, files, telemetry, onUploaded }: QuantumVaultPageProps) {
  const latestVaultTelemetry = useMemo(
    () => telemetry.find((event) => event.stage.includes("vault")) ?? telemetry[0] ?? null,
    [telemetry],
  );
  const [status, setStatus] = useState(latestVaultTelemetry?.detail ?? "No active vault operation");
  const [operations, setOperations] = useState<VaultOperation[]>([]);
  const [localNames, setLocalNames] = useState<Record<string, string>>({});
  const [resolvedFileNames, setResolvedFileNames] = useState<Record<string, string>>({});
  const [deletedFileIds, setDeletedFileIds] = useState<Record<string, true>>({});
  const [decryptionStatuses, setDecryptionStatuses] = useState<Record<string, DecryptionStatus>>({});
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [uploadBusy, setUploadBusy] = useState(false);
  const [localDecryptBusy, setLocalDecryptBusy] = useState(false);
  const [localVaultBusy, setLocalVaultBusy] = useState<LocalVaultAction | null>(null);
  const [localVaultResult, setLocalVaultResult] = useState<string | null>(null);
  const [pipelineControl, setPipelineControl] = useState<VaultPipelineControl>({ state: "idle", operationId: null, label: null });
  const [terminalLogs, setTerminalLogs] = useState<VaultTerminalLog[]>([]);
  const [activeVaultTab, setActiveVaultTab] = useState<VaultPanelTab>("operations");
  const [resaveDecryptedToVault, setResaveDecryptedToVault] = useState(false);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({});
  const [selectedExplorerNodeId, setSelectedExplorerNodeId] = useState<string | null>(null);
  const [explorerStateReady, setExplorerStateReady] = useState(false);
  const explorerStorageKey = useMemo(() => `qguard-vault-explorer:${userId}`, [userId]);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);
  const localDecryptFileInputRef = useRef<HTMLInputElement | null>(null);
  const localDecryptFolderInputRef = useRef<HTMLInputElement | null>(null);
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const missingOperationsTableLoggedRef = useRef(false);
  const stopRequestedRef = useRef(false);
  const resumePipelineRef = useRef<(() => void) | null>(null);

  const appendLog = useCallback((level: VaultTerminalLog["level"], message: string) => {
    setTerminalLogs((current) => [
      ...current.slice(-120),
      {
        id: crypto.randomUUID(),
        at: new Date().toISOString(),
        level,
        message,
      },
    ]);
  }, []);

  const loadOperations = useCallback(async () => {
    const { data, error } = await supabase
      .from("qguard_vault_operations")
      .select("id,user_id,file_id,operation_type,display_name_hint,status,current_operation,progress,size_bytes,processed_bytes,algorithm,integrity_status,error_message,attempts,started_at,updated_at,completed_at")
      .eq("user_id", userId)
      .order("updated_at", { ascending: false })
      .limit(500);
    if (error) {
      if (isMissingVaultOperationsTable(error) && !missingOperationsTableLoggedRef.current) {
        missingOperationsTableLoggedRef.current = true;
        appendLog("error", "Realtime vault operations table is missing or not refreshed in Supabase schema cache. Apply migration 009; encryption will continue with local terminal progress.");
      }
      return;
    }
    setOperations((current) => {
      const localOperations = current.filter((operation) => isLocalOperationId(operation.id));
      return [...localOperations, ...((data ?? []) as VaultOperation[])];
    });
  }, [appendLog, userId]);

  useEffect(() => {
    setStatus(latestVaultTelemetry?.detail ?? "No active vault operation");
  }, [latestVaultTelemetry]);

  useEffect(() => {
    loadOperations();
  }, [loadOperations]);

  useEffect(() => {
    const channel = supabase
      .channel(`qguard-vault-ops-${userId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "qguard_vault_operations", filter: `user_id=eq.${userId}` }, loadOperations)
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [loadOperations, userId]);

  useEffect(() => {
    const channel = supabase
      .channel(`qguard-vault-files-${userId}`)
      .on(
        "postgres_changes",
        { event: "DELETE", schema: "public", table: "messaging_vault_files", filter: `owner_user_id=eq.${userId}` },
        (payload) => {
          const deletedId = String(((payload.old ?? {}) as Record<string, unknown>).id ?? "");
          if (deletedId) {
            setDeletedFileIds((current) => ({ ...current, [deletedId]: true }));
            setOperations((current) => current.filter((operation) => operation.file_id !== deletedId));
          }
          appendLog("success", "Realtime file_deleted event received; vault UI state refreshed");
          loadOperations();
          onUploaded();
        },
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [appendLog, loadOperations, onUploaded, userId]);

  useEffect(() => {
    folderInputRef.current?.setAttribute("webkitdirectory", "");
    folderInputRef.current?.setAttribute("directory", "");
    localDecryptFolderInputRef.current?.setAttribute("webkitdirectory", "");
    localDecryptFolderInputRef.current?.setAttribute("directory", "");
  }, []);

  useEffect(() => {
    if (!terminalRef.current) return;
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLogs.length]);

  useEffect(() => {
    setExplorerStateReady(false);
    try {
      const savedState = window.localStorage.getItem(explorerStorageKey);
      const parsedState = savedState ? JSON.parse(savedState) as Record<string, unknown> : {};
      const nextExpandedFolders: Record<string, boolean> = {};
      Object.entries(parsedState).forEach(([path, expanded]) => {
        if (expanded === true) nextExpandedFolders[path] = true;
      });
      setExpandedFolders(nextExpandedFolders);
    } catch {
      setExpandedFolders({});
    } finally {
      setExplorerStateReady(true);
    }
  }, [explorerStorageKey]);

  useEffect(() => {
    if (!explorerStateReady) return;
    try {
      window.localStorage.setItem(explorerStorageKey, JSON.stringify(expandedFolders));
    } catch {
      // Local storage is optional; in-memory expansion state still works.
    }
  }, [expandedFolders, explorerStateReady, explorerStorageKey]);

  useEffect(() => () => {
    stopRequestedRef.current = false;
    resumePipelineRef.current?.();
    resumePipelineRef.current = null;
  }, []);

  const visibleFiles = useMemo(
    () => files.filter((file) => !file.revoked_at && !deletedFileIds[file.id]),
    [deletedFileIds, files],
  );

  const visibleFileIds = useMemo(() => new Set(visibleFiles.map((file) => file.id)), [visibleFiles]);

  const activeOperations = useMemo(
    () => operations.filter((operation) => shouldShowVaultOperation(operation, visibleFileIds, deletedFileIds)),
    [deletedFileIds, operations, visibleFileIds],
  );

  const panelRows = useMemo<PanelRow[]>(() => {
    const fileById = new Map(visibleFiles.map((file) => [file.id, file]));
    const displayNameByFile = new Map<string, string>();
    const latestByFile = new Map<string, VaultOperation>();
    const standalone: VaultOperation[] = [];

    activeOperations.forEach((operation) => {
      const displayNameHint = localNames[operation.id] ?? operation.display_name_hint;
      const explorerName = cleanExplorerPath(displayNameHint);
      if (operation.file_id && explorerName && !isGenericVaultDisplayName(explorerName)) {
        displayNameByFile.set(operation.file_id, preferExplorerName(displayNameByFile.get(operation.file_id), explorerName));
      }
      if (!operation.file_id) {
        standalone.push(operation);
        return;
      }
      const current = latestByFile.get(operation.file_id);
      if (!current || new Date(operation.updated_at) > new Date(current.updated_at)) {
        latestByFile.set(operation.file_id, operation);
      }
    });

    const rows: PanelRow[] = visibleFiles.map((file) => {
      const operation = latestByFile.get(file.id) ?? {
        id: `file-${file.id}`,
        user_id: userId,
        file_id: file.id,
        operation_type: "verify",
        display_name_hint: vaultFileLabel(file),
        status: file.revoked_at ? "failed" : "completed",
        current_operation: file.revoked_at ? "Revoked" : "Stored",
        progress: 100,
        size_bytes: file.size_bytes,
        processed_bytes: file.size_bytes,
        algorithm: suiteLabel(file.suite),
        integrity_status: "not_checked",
        error_message: null,
        attempts: 0,
        started_at: file.created_at,
        updated_at: file.created_at,
        completed_at: file.created_at,
      } satisfies VaultOperation;
      const operationDisplayName = localNames[operation.id] ?? operation.display_name_hint;
      const persistedName = file.display_name_hint && !isGenericVaultDisplayName(file.display_name_hint)
        ? cleanExplorerPath(file.display_name_hint)
        : undefined;
      return {
        ...operation,
        file,
        display_name: resolvedFileNames[file.id] ?? displayNameByFile.get(file.id) ?? persistedName ?? operationDisplayName,
      };
    });

    standalone.forEach((operation) => {
      rows.push({
        ...operation,
        file: operation.file_id ? fileById.get(operation.file_id) ?? null : null,
        display_name: localNames[operation.id] ?? operation.display_name_hint,
      });
    });

    return rows.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
  }, [activeOperations, localNames, resolvedFileNames, userId, visibleFiles]);

  const displayNameByFileId = useMemo(() => {
    const names = new Map<string, string>();
    panelRows.forEach((row) => {
      if (row.file) names.set(row.file.id, row.display_name);
    });
    return names;
  }, [panelRows]);

  const explorerTree = useMemo<VaultExplorerNode[]>(() => {
    const folders = new Map<string, VaultExplorerNode>();
    const rootNodes: VaultExplorerNode[] = [];

    const addToParent = (node: VaultExplorerNode) => {
      if (!node.parentPath) {
        rootNodes.push(node);
        return;
      }
      const parent = folders.get(node.parentPath);
      if (parent) parent.children.push(node);
      else rootNodes.push(node);
    };

    const ensureFolder = (path: string, name: string, depth: number, parentPath: string | null, row: PanelRow) => {
      const current = folders.get(path);
      if (current) {
        current.rows.push(row);
        current.status = combineStatus(current.status, row.status);
        current.progress = Math.round((current.progress * (current.rows.length - 1) + row.progress) / current.rows.length);
        current.integrity_status = combineIntegrity(current.integrity_status, row.integrity_status);
        current.item_count += 1;
        current.size_bytes += row.size_bytes;
        if (new Date(row.updated_at) > new Date(current.updated_at)) current.updated_at = row.updated_at;
        return current;
      }

      const folder: VaultExplorerNode = {
        id: `folder-${path}`,
        type: "folder",
        name,
        path,
        parentPath,
        depth,
        rows: [row],
        row: null,
        children: [],
        item_count: 1,
        size_bytes: row.size_bytes,
        status: row.status,
        progress: row.progress,
        integrity_status: row.integrity_status,
        updated_at: row.updated_at,
      };
      folders.set(path, folder);
      addToParent(folder);
      return folder;
    };

    panelRows.forEach((row) => {
      const fallbackName = row.file ? vaultFileLabel(row.file) : row.display_name;
      const path = cleanExplorerPath(row.display_name) || fallbackName;
      const parts = path.split("/").filter(Boolean);
      const fileName = parts.at(-1) ?? fallbackName;

      let prefix = "";
      parts.slice(0, -1).forEach((part, index) => {
        const parentPath = prefix || null;
        prefix = prefix ? `${prefix}/${part}` : part;
        ensureFolder(prefix, part, index, parentPath, row);
      });

      const parentPath = parts.length > 1 ? parts.slice(0, -1).join("/") : null;
      const fileNode: VaultExplorerNode = {
        id: `file-${row.file?.id ?? row.id}`,
        type: "file",
        name: fileName,
        path,
        parentPath,
        depth: Math.max(0, parts.length - 1),
        rows: [row],
        row,
        children: [],
        item_count: 1,
        size_bytes: row.size_bytes,
        status: row.status,
        progress: row.progress,
        integrity_status: row.integrity_status,
        updated_at: row.updated_at,
      };
      addToParent(fileNode);
    });

    return sortExplorerNodes(rootNodes);
  }, [panelRows]);

  const allExplorerNodes = useMemo(() => flattenExplorerNodes(explorerTree), [explorerTree]);
  const visibleExplorerNodes = useMemo(
    () => flattenVisibleExplorerNodes(explorerTree, expandedFolders),
    [expandedFolders, explorerTree],
  );
  const explorerFolderCount = useMemo(
    () => allExplorerNodes.filter((node) => node.type === "folder").length,
    [allExplorerNodes],
  );
  const explorerFileCount = useMemo(
    () => allExplorerNodes.filter((node) => node.type === "file").length,
    [allExplorerNodes],
  );

  useEffect(() => {
    const folderPaths = new Set(allExplorerNodes.filter((node) => node.type === "folder").map((node) => node.path));
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
    if (!allExplorerNodes.some((node) => node.id === selectedExplorerNodeId)) {
      setSelectedExplorerNodeId(null);
    }
  }, [allExplorerNodes, selectedExplorerNodeId]);

  const historyEntries = useMemo<VaultHistoryEntry[]>(() => {
    const operationEntries = activeOperations.map((operation) => ({
      id: `operation-${operation.id}`,
      at: operation.updated_at,
      source: "operation" as const,
      title: operation.operation_type.replace(/_/g, " "),
      detail: `${operation.display_name_hint} - ${operation.current_operation} (${operation.progress}%)`,
      status: operation.status,
    }));

    const telemetryEntries = telemetry
      .filter((event) => event.stage.includes("vault") || event.stage.includes("file"))
      .map((event) => ({
        id: `telemetry-${event.id}`,
        at: event.created_at,
        source: "telemetry" as const,
        title: event.stage.replace(/_/g, " "),
        detail: event.detail,
        status: `${event.progress}%`,
      }));

    const terminalEntries = terminalLogs.map((log) => ({
      id: `terminal-${log.id}`,
      at: log.at,
      source: "terminal" as const,
      title: log.level === "error" ? "terminal error" : log.level === "success" ? "terminal success" : "terminal",
      detail: log.message,
      status: log.level,
    }));

    return [...operationEntries, ...telemetryEntries, ...terminalEntries]
      .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
      .slice(0, 120);
  }, [activeOperations, telemetry, terminalLogs]);

  function fileActionDisplayName(file: VaultFileSummary): string {
    const resolvedName = resolvedFileNames[file.id];
    if (resolvedName) return resolvedName;
    const rowName = displayNameByFileId.get(file.id);
    if (rowName && !isGenericVaultDisplayName(rowName)) return rowName;
    const persistedName = file.display_name_hint ? cleanExplorerPath(file.display_name_hint) : "";
    if (persistedName && !isGenericVaultDisplayName(persistedName)) return persistedName;
    return rowName ?? vaultFileLabel(file);
  }

  function fileDecryptionStatus(file: VaultFileSummary, row?: PanelRow | null): DecryptionStatus {
    const localStatus = decryptionStatuses[file.id];
    if (localStatus) return localStatus;
    if (row?.operation_type === "decrypt_download") {
      if (row.status === "processing" || row.status === "queued") return "decrypting";
      if (row.status === "completed") return "decrypted";
      if (row.status === "failed") return "failed";
    }
    return "encrypted";
  }

  function renderDecryptionStatusPill(file: VaultFileSummary, row?: PanelRow | null) {
    const decryptionStatus = fileDecryptionStatus(file, row);
    const tone = decryptionStatus === "decrypted"
      ? "bg-emerald-50 text-emerald-600"
      : decryptionStatus === "decrypting"
        ? "bg-cyan-50 text-cyan-700"
        : decryptionStatus === "failed"
          ? "bg-rose-50 text-rose-600"
          : "bg-ink-50 text-ink-600";
    const Icon = decryptionStatus === "decrypted" ? UnlockKeyhole : decryptionStatus === "decrypting" ? Loader2 : LockKeyhole;
    return (
      <span className={`status-pill ${tone}`}>
        <Icon className={decryptionStatus === "decrypting" ? "animate-spin" : ""} size={13} />
        {decryptionStatus}
      </span>
    );
  }

  async function resolveFileActionDisplayName(file: VaultFileSummary, packageData?: EncryptedFilePackage): Promise<string> {
    const currentName = fileActionDisplayName(file);
    if (!isGenericVaultDisplayName(currentName) || !packageData) return currentName;

    const decryptedName = cleanExplorerPath(await safeInvoke<string>("vault_decrypt_file_name", { package: packageData }, currentName));
    if (!decryptedName || isGenericVaultDisplayName(decryptedName)) return currentName;

    setResolvedFileNames((current) => ({ ...current, [file.id]: decryptedName }));
    return decryptedName;
  }

  async function updateOperationDisplayName(operationId: string, displayName: string): Promise<void> {
    if (!operationId || isLocalOperationId(operationId)) {
      if (operationId) {
        setOperations((current) =>
          current.map((operation) =>
            operation.id === operationId ? { ...operation, display_name_hint: displayName } : operation,
          ),
        );
      }
      return;
    }

    const { error } = await supabase
      .from("qguard_vault_operations")
      .update({ display_name_hint: displayName, updated_at: new Date().toISOString() })
      .eq("id", operationId)
      .eq("user_id", userId);
    if (error) appendLog("error", `Display name update failed: ${describeError(error)}`);
  }

  async function createOperation(
    operationType: VaultOperation["operation_type"],
    file: VaultFileSummary | null,
    displayNameHint: string,
    sizeBytes: number,
  ): Promise<string> {
    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from("qguard_vault_operations")
      .insert({
        user_id: userId,
        file_id: file?.id ?? null,
        operation_type: operationType,
        display_name_hint: displayNameHint,
        status: "queued",
        current_operation: "Queued",
        progress: 0,
        size_bytes: sizeBytes,
        processed_bytes: 0,
        algorithm: algorithmLabel,
        integrity_status: operationType === "verify" ? "pending" : "not_checked",
        attempts: 1,
      })
      .select("id")
      .single();
    if (error) {
      if (isMissingVaultOperationsTable(error)) {
        if (!missingOperationsTableLoggedRef.current) {
          missingOperationsTableLoggedRef.current = true;
          appendLog("error", "Realtime vault operations table is missing or not refreshed in Supabase schema cache. Apply migration 009; encryption will continue with local terminal progress.");
        }
        const id = `local-${crypto.randomUUID()}`;
        const localOperation: VaultOperation = {
          id,
          user_id: userId,
          file_id: file?.id ?? null,
          operation_type: operationType,
          display_name_hint: displayNameHint,
          status: "queued",
          current_operation: "Queued",
          progress: 0,
          size_bytes: sizeBytes,
          processed_bytes: 0,
          algorithm: algorithmLabel,
          integrity_status: operationType === "verify" ? "pending" : "not_checked",
          error_message: null,
          attempts: 1,
          started_at: now,
          updated_at: now,
          completed_at: null,
        };
        setOperations((current) => [localOperation, ...current]);
        appendLog("info", `Queued local ${operationType} operation ${id.slice(6, 14)} for ${displayNameHint}`);
        return id;
      }
      throw error;
    }
    appendLog("info", `Queued ${operationType} operation ${String(data.id).slice(0, 8)} for ${displayNameHint}`);
    return String(data.id);
  }

  async function updateOperation(operationId: string, patch: Partial<VaultOperation>): Promise<void> {
    const now = new Date().toISOString();
    const nextPatch: Partial<VaultOperation> = {
      ...patch,
      updated_at: now,
    };
    if (patch.status === "completed" || patch.status === "failed") {
      nextPatch.completed_at = patch.completed_at ?? now;
    }
    if (isLocalOperationId(operationId)) {
      setOperations((current) =>
        current.map((operation) =>
          operation.id === operationId
            ? {
                ...operation,
                ...nextPatch,
              }
            : operation,
        ),
      );
      return;
    }
    const { error } = await supabase
      .from("qguard_vault_operations")
      .update(nextPatch)
      .eq("id", operationId)
      .eq("user_id", userId);
    if (error) {
      appendLog("error", `Realtime operation update failed: ${describeError(error)}`);
      return;
    }
    await loadOperations();
  }

  async function logVaultAction(
    operationId: string,
    stage: string,
    detail: string,
    progress: number,
    statusValue: "started" | "progress" | "verified" | "failed" | "complete" = "progress",
    fileId?: string | null,
  ) {
    await recordCryptoTelemetry({
      userId,
      scope: stage.includes("verify") ? "verification" : "vault",
      stage,
      detail,
      progress,
      status: statusValue,
      metadata: { operation_id: operationId, file_id: fileId ?? null },
    });
    appendLog(statusValue === "failed" ? "error" : statusValue === "complete" || statusValue === "verified" ? "success" : "info", `${stage}: ${detail}`);
  }

  function requestPipelineStop() {
    if (!uploadBusy || pipelineControl.state === "paused") return;
    stopRequestedRef.current = true;
    setPipelineControl((current) => ({
      state: current.state === "idle" ? "stop_requested" : "stop_requested",
      operationId: current.operationId,
      label: current.label,
    }));
    setStatus("Stop requested. The active crypto/upload step will pause at the next safe checkpoint.");
    appendLog("info", "Stop requested by user; the current in-flight chunk or crypto step will finish before pausing.");
  }

  function resumePipeline() {
    if (pipelineControl.state !== "paused" || !resumePipelineRef.current) return;
    appendLog("success", `Resume requested for ${pipelineControl.label ?? "vault operation"}`);
    resumePipelineRef.current();
  }

  async function waitIfStopRequested(operationId: string, displayName: string, checkpoint: string, progress: number): Promise<void> {
    if (!stopRequestedRef.current) return;

    const safeProgress = Math.max(0, Math.min(99, Math.round(progress)));
    setPipelineControl({ state: "paused", operationId, label: displayName });
    setStatus(`Paused ${displayName}`);
    await updateOperation(operationId, {
      status: "processing",
      current_operation: `Paused - ${checkpoint}`,
      progress: safeProgress,
    });
    await logVaultAction(operationId, "vault_operation_paused", `User paused ${checkpoint}`, safeProgress, "progress");

    await new Promise<void>((resolve) => {
      resumePipelineRef.current = resolve;
    });

    resumePipelineRef.current = null;
    stopRequestedRef.current = false;
    setPipelineControl({ state: "running", operationId, label: displayName });
    setStatus(`Resuming ${displayName}`);
    await updateOperation(operationId, {
      status: "processing",
      current_operation: `Resuming - ${checkpoint}`,
      progress: safeProgress,
    });
    await logVaultAction(operationId, "vault_operation_resumed", `User resumed ${checkpoint}`, safeProgress, "progress");
  }

  async function fetchPackage(
    file: VaultFileSummary,
    operationId: string,
    phase: string,
    progressStart = 8,
    progressSpan = 52,
  ): Promise<EncryptedFilePackage> {
    await updateOperation(operationId, {
      status: "processing",
      current_operation: `${phase}: downloading manifest`,
      progress: progressStart,
      processed_bytes: 0,
    });
    let manifest: VaultManifest;
    try {
      manifest = await readStorageJson<VaultManifest>(file.storage_path);
    } catch (error) {
      throw new Error(normalizeVaultFileAccessError(error));
    }
    const encryptedChunks: EncryptedEnvelope[] = [];
    const totalChunks = Math.max(1, manifest.chunk_paths.length);

    for (let index = 0; index < manifest.chunk_paths.length; index += 1) {
      let chunk: EncryptedEnvelope;
      try {
        chunk = await readStorageJson<EncryptedEnvelope>(manifest.chunk_paths[index]);
      } catch (error) {
        throw new Error(normalizeVaultFileAccessError(error));
      }
      encryptedChunks.push(chunk);
      const progress = Math.min(99, progressStart + Math.round(((index + 1) / totalChunks) * progressSpan));
      const processed = Math.min(file.size_bytes, Math.round(((index + 1) / totalChunks) * file.size_bytes));
      await updateOperation(operationId, {
        current_operation: `${phase}: fetching encrypted chunks`,
        progress,
        processed_bytes: processed,
      });
    }

    return {
      metadata: manifest.metadata,
      encrypted_chunks: encryptedChunks,
      wrapped_keys: manifest.wrapped_keys,
      metadata_signature: manifest.metadata_signature,
      signer_ed25519_public: manifest.signer_ed25519_public,
      signer_mldsa_public: manifest.signer_mldsa_public,
      suite: manifest.suite,
    };
  }

  async function encryptSelectedFile(file: File) {
    let operationId = "";
    const displayName = fileDisplayName(file);
    try {
      appendLog("info", `Selected ${displayName} (${formatBytes(file.size)})`);
      appendLog("info", `Crypto suite locked: PQC ML-KEM-1024 + ML-DSA-65; KDF HKDF-SHA3-256; cipher AES-256-GCM; signatures Ed25519 + ML-DSA-65`);
      setStatus(`Queued encryption for ${displayName}`);
      operationId = await createOperation("encrypt", null, displayName, file.size);
      setLocalNames((current) => ({ ...current, [operationId]: displayName }));
      setPipelineControl({ state: "running", operationId, label: displayName });
      setStatus("Encrypting locally");
      await updateOperation(operationId, {
        status: "processing",
        current_operation: "Reading file",
        progress: 5,
        size_bytes: file.size,
      });
      await logVaultAction(operationId, "vault_encrypt_started", "Client-side envelope encryption started", 5, "started");
      await waitIfStopRequested(operationId, displayName, "file intake", 5);

      appendLog("info", `Reading ${displayName} into the local encryption pipeline`);
      const bytes = new Uint8Array(await file.arrayBuffer());
      await waitIfStopRequested(operationId, displayName, "local file read", 12);
      await updateOperation(operationId, {
        current_operation: "Encrypting",
        progress: 18,
        processed_bytes: bytes.byteLength,
      });
      appendLog("info", "Generating per-file AES-256-GCM key and hybrid ML-KEM/X25519 wrap");
      await waitIfStopRequested(operationId, displayName, "key generation", 18);
      let binary = "";
      bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
      const encryptedPackage = await safeInvoke<EncryptedFilePackage>("vault_encrypt_upload", {
        request: {
          fileName: displayName,
          contentType: file.type || "application/octet-stream",
          plaintextBase64: btoa(binary),
        },
      });
      await waitIfStopRequested(operationId, displayName, "local encryption", 24);

      const ownerDeviceId = encryptedPackage.wrapped_keys[0]?.recipient_device_id ?? null;
      const fileId = encryptedPackage.metadata.file_id;
      const basePath = `${userId}/vault/${fileId}`;
      const chunkPaths: string[] = [];
      setStatus("Uploading encrypted chunks");
      appendLog("info", `${encryptedPackage.encrypted_chunks.length} encrypted chunk(s) produced; uploading ciphertext only`);
      await updateOperation(operationId, {
        current_operation: "Chunking",
        progress: 28,
        algorithm: suiteLabel(encryptedPackage.suite),
      });
      await waitIfStopRequested(operationId, displayName, "chunk staging", 28);

      for (let index = 0; index < encryptedPackage.encrypted_chunks.length; index += 1) {
        const chunkPath = `${basePath}/chunks/${index.toString().padStart(8, "0")}.json`;
        chunkPaths.push(chunkPath);
        const beforeChunkProgress = 35 + Math.round((index / encryptedPackage.encrypted_chunks.length) * 45);
        await waitIfStopRequested(operationId, displayName, `upload chunk ${index + 1}/${encryptedPackage.encrypted_chunks.length}`, beforeChunkProgress);
        await uploadWithRetry(chunkPath, jsonBlob(encryptedPackage.encrypted_chunks[index]), "application/qguard-vault-chunk+json");
        const progress = 35 + Math.round(((index + 1) / encryptedPackage.encrypted_chunks.length) * 45);
        const processed = Math.min(file.size, Math.round(((index + 1) / encryptedPackage.encrypted_chunks.length) * file.size));
        setStatus(`Uploaded encrypted chunk ${index + 1}/${encryptedPackage.encrypted_chunks.length}`);
        await updateOperation(operationId, {
          current_operation: "Uploading",
          progress,
          processed_bytes: processed,
        });
        await logVaultAction(operationId, "vault_chunk_uploaded", "Ciphertext chunk stored", progress, "progress", fileId);
        await waitIfStopRequested(operationId, displayName, `post-upload chunk ${index + 1}/${encryptedPackage.encrypted_chunks.length}`, progress);
      }

      const manifestPath = `${basePath}/manifest.json`;
      const manifest: VaultManifest = {
        version: 1,
        metadata: encryptedPackage.metadata,
        wrapped_keys: encryptedPackage.wrapped_keys,
        metadata_signature: encryptedPackage.metadata_signature,
        signer_ed25519_public: encryptedPackage.signer_ed25519_public,
        signer_mldsa_public: encryptedPackage.signer_mldsa_public,
        suite: encryptedPackage.suite,
        chunk_paths: chunkPaths,
      };
      await updateOperation(operationId, { current_operation: "Verifying manifest", progress: 88 });
      await waitIfStopRequested(operationId, displayName, "manifest verification", 88);
      appendLog("info", "Verifying ML-DSA-65 and Ed25519 metadata signatures");
      await safeInvoke("vault_verify_metadata", { package: encryptedPackage });
      appendLog("info", "Uploading signed vault manifest");
      await waitIfStopRequested(operationId, displayName, "manifest upload", 92);
      await uploadWithRetry(manifestPath, jsonBlob(manifest), "application/qguard-vault-manifest+json");
      await waitIfStopRequested(operationId, displayName, "vault record commit", 96);

      const vaultRecord = {
        id: fileId,
        owner_user_id: userId,
        owner_device_id: ownerDeviceId,
        storage_path: manifestPath,
        display_name_hint: displayName,
        encrypted_metadata: manifest,
        metadata_signature: encryptedPackage.metadata_signature,
        merkle_root: encryptedPackage.metadata.merkle_root,
        size_bytes: encryptedPackage.metadata.original_size,
        content_type: encryptedPackage.metadata.content_type,
        suite: encryptedPackage.suite,
      };
      let { error } = await supabase.from("messaging_vault_files").insert(vaultRecord);
      if (error && isMissingDisplayNameHintColumn(error)) {
        const { display_name_hint: _displayNameHint, ...legacyVaultRecord } = vaultRecord;
        const retry = await supabase.from("messaging_vault_files").insert(legacyVaultRecord);
        error = retry.error;
      }
      if (error) throw error;

      await updateOperation(operationId, {
        file_id: fileId,
        status: "completed",
        current_operation: "Completed",
        progress: 100,
        processed_bytes: file.size,
        integrity_status: "verified",
      });
      await logVaultAction(operationId, "vault_manifest_committed", "Signed encrypted vault manifest committed", 100, "complete", fileId);
      setStatus("Encrypted package uploaded");
      appendLog("success", `Encryption completed for ${displayName}`);
      onUploaded();
    } catch (err) {
      const message = describeError(err);
      setStatus(message);
      appendLog("error", `Encryption failed: ${message}`);
      if (operationId) {
        await updateOperation(operationId, {
          status: "failed",
          current_operation: "Failed",
          error_message: message,
          integrity_status: "failed",
        });
        await logVaultAction(operationId, "vault_upload_failed", "Vault encryption or upload failed", 0, "failed");
      }
    }
  }

  async function handleSelectedFiles(selected: File[]) {
    if (uploadBusy) {
      appendLog("error", "Vault pipeline is already running. Stop or resume the active job before adding more files.");
      return;
    }
    if (selected.length === 0) {
      appendLog("error", "No file was selected.");
      return;
    }
    setUploadBusy(true);
    setStatus(`Queued ${selected.length} file${selected.length === 1 ? "" : "s"} for encryption`);
    appendLog("info", `Vault intake received ${selected.length} file${selected.length === 1 ? "" : "s"}`);
    try {
      for (const file of selected) {
        await encryptSelectedFile(file);
      }
    } finally {
      stopRequestedRef.current = false;
      resumePipelineRef.current = null;
      setPipelineControl({ state: "idle", operationId: null, label: null });
      setUploadBusy(false);
    }
  }

  async function verifyFile(file: VaultFileSummary, options: { suppressBusy?: boolean } = {}) {
    let operationId = "";
    let displayName = fileActionDisplayName(file);
    if (!options.suppressBusy) setActionBusy(`verify-${file.id}`);
    try {
      operationId = await createOperation("verify", file, displayName, file.size_bytes);
      await logVaultAction(operationId, "vault_verify_started", "Manifest and signature verification started", 5, "started", file.id);
      appendLog("info", `Verifying encrypted vault package for ${displayName}`);
      const packageData = await fetchPackage(file, operationId, "Verifying");
      const resolvedName = await resolveFileActionDisplayName(file, packageData);
      if (resolvedName !== displayName) {
        displayName = resolvedName;
        await updateOperationDisplayName(operationId, displayName);
      }
      await updateOperation(operationId, { current_operation: "Verifying signatures", progress: 82 });
      await safeInvoke("vault_verify_metadata", { package: packageData });
      await updateOperation(operationId, {
        status: "completed",
        current_operation: "Verified",
        progress: 100,
        processed_bytes: file.size_bytes,
        integrity_status: "verified",
      });
      await logVaultAction(operationId, "vault_verify_completed", "ML-DSA-65 and Ed25519 signatures verified", 100, "verified", file.id);
      setStatus(`${displayName} verified`);
    } catch (err) {
      const message = normalizeVaultActionError(err);
      appendLog("error", `Verification failed: ${message}`);
      if (operationId) await updateOperation(operationId, { status: "failed", current_operation: "Verification failed", error_message: message, integrity_status: "failed" });
      await cleanupInvalidFileOperation(file, operationId, message);
      setStatus(message);
    } finally {
      if (!options.suppressBusy) setActionBusy(null);
    }
  }

  async function downloadEncrypted(file: VaultFileSummary, options: { suppressBusy?: boolean } = {}) {
    let operationId = "";
    let displayName = fileActionDisplayName(file);
    if (!options.suppressBusy) setActionBusy(`download-${file.id}`);
    try {
      operationId = await createOperation("download_encrypted", file, displayName, file.size_bytes);
      await logVaultAction(operationId, "vault_encrypted_download_started", "Authenticated encrypted download started", 5, "started", file.id);
      appendLog("info", `Preparing ciphertext-only export for ${displayName}`);
      const packageData = await fetchPackage(file, operationId, "Downloading encrypted");
      const resolvedName = await resolveFileActionDisplayName(file, packageData);
      if (resolvedName !== displayName) {
        displayName = resolvedName;
        await updateOperationDisplayName(operationId, displayName);
      }
      await updateOperation(operationId, { current_operation: "Packaging encrypted data", progress: 92 });
      downloadBlob(encryptedPackageDownloadName(displayName, file.id), jsonBlob(packageData));
      await updateOperation(operationId, {
        status: "completed",
        current_operation: "Encrypted download ready",
        progress: 100,
        processed_bytes: file.size_bytes,
        integrity_status: "not_checked",
      });
      await logVaultAction(operationId, "vault_encrypted_download_completed", "Encrypted vault package delivered", 100, "complete", file.id);
      setStatus(`${displayName} encrypted package downloaded`);
    } catch (err) {
      const message = normalizeVaultActionError(err);
      appendLog("error", `Encrypted download failed: ${message}`);
      if (operationId) await updateOperation(operationId, { status: "failed", current_operation: "Download failed", error_message: message });
      await cleanupInvalidFileOperation(file, operationId, message);
      setStatus(message);
    } finally {
      if (!options.suppressBusy) setActionBusy(null);
    }
  }

  async function decryptAndDownload(file: VaultFileSummary, options: { suppressBusy?: boolean } = {}) {
    let operationId = "";
    let displayName = fileActionDisplayName(file);
    if (!options.suppressBusy) setActionBusy(`decrypt-${file.id}`);
    setDecryptionStatuses((current) => ({ ...current, [file.id]: "decrypting" }));
    const stream = createSecureDecryptionStream("vault", (event) => {
      appendLog(event.data.level, `${event.data.stage}: ${event.data.detail}`);
    });
    try {
      operationId = await createOperation("decrypt_download", file, displayName, file.size_bytes);
      await logVaultAction(operationId, "vault_decrypt_download_started", "Client-side decrypt started", 5, "started", file.id);
      appendLog("info", `Preparing local decrypt for ${displayName}`);
      await validateDecryptionSession(userId, stream);
      enforceClientDecryptionRateLimit(userId, `vault:${file.id}`, stream);
      await unlockDevicePrivateKey(stream, userId);
      await updateOperation(operationId, { current_operation: "Key validation", progress: 26 });
      const packageData = await fetchPackage(file, operationId, "Preparing decrypt");
      const resolvedName = await resolveFileActionDisplayName(file, packageData);
      if (resolvedName !== displayName) {
        displayName = resolvedName;
        await updateOperationDisplayName(operationId, displayName);
      }
      stream.emit({
        stage: "hybrid_decapsulation",
        detail: "Recovering file key with ML-KEM-1024 + X25519",
        progress: 72,
        status: "progress",
        level: "info",
      });
      await updateOperation(operationId, { current_operation: "Hybrid key decapsulation", progress: 72 });
      stream.emit({
        stage: "aes_gcm_decrypt",
        detail: "Decrypting ciphertext chunks locally with AES-256-GCM",
        progress: 86,
        status: "progress",
        level: "info",
      });
      await updateOperation(operationId, { current_operation: "Decrypting locally", progress: 86 });
      const plaintextBase64 = await safeInvoke<string>("vault_download_decrypt", { package: packageData });
      stream.emit({
        stage: "integrity_verification",
        detail: "Ed25519 + ML-DSA-65 signatures and AES-GCM tags verified",
        progress: 94,
        status: "verified",
        level: "success",
      });
      const plaintextBlob = blobFromBase64(plaintextBase64, file.content_type);
      const restoredName = decryptedDownloadName(displayName, file.id);
      downloadBlob(restoredName, plaintextBlob);
      await updateOperation(operationId, {
        status: "completed",
        current_operation: "Decrypted download ready",
        progress: 100,
        processed_bytes: file.size_bytes,
        integrity_status: "verified",
      });
      stream.emit({
        stage: "decrypt_completed",
        detail: "Plaintext restored locally",
        progress: 100,
        status: "complete",
        level: "success",
      });
      await logVaultAction(operationId, "vault_decrypt_download_completed", "AEAD and signature checks passed before local plaintext restore", 100, "complete", file.id);
      setDecryptionStatuses((current) => ({ ...current, [file.id]: "decrypted" }));
      setStatus(`${displayName} decrypted locally`);
      if (resaveDecryptedToVault) {
        appendLog("info", `Re-saving ${restoredName} into Quantum Vault with a fresh envelope`);
        setUploadBusy(true);
        try {
          await encryptSelectedFile(new File([plaintextBlob], restoredName, { type: file.content_type || "application/octet-stream" }));
        } finally {
          stopRequestedRef.current = false;
          resumePipelineRef.current = null;
          setPipelineControl({ state: "idle", operationId: null, label: null });
          setUploadBusy(false);
        }
      }
    } catch (err) {
      const message = normalizeDecryptionError(err);
      const keyUnavailable = isWrappedFileKeyUnavailable(message);
      appendLog(
        "error",
        keyUnavailable
          ? `Decrypt failed: this vault object is wrapped for a different device key. Encrypted download and delete are still available. ${message}`
          : `Decrypt failed: ${message}`,
      );
      if (operationId) {
        await updateOperation(operationId, {
          status: "failed",
          current_operation: keyUnavailable ? "Device key unavailable" : "Decrypt failed",
          error_message: message,
          integrity_status: keyUnavailable ? "not_checked" : "failed",
        });
      }
      await cleanupInvalidFileOperation(file, operationId, message);
      setDecryptionStatuses((current) => ({ ...current, [file.id]: "failed" }));
      setStatus(message);
    } finally {
      if (!options.suppressBusy) setActionBusy(null);
    }
  }

  function localEncryptedDisplayName(file: File): string {
    return cleanExplorerPath(fileDisplayName(file)
      .replace(/\.qguard-folder\.encrypted\.json$/i, "")
      .replace(/\.qguard\.encrypted\.json$/i, "")
      .replace(/\.encrypted\.json$/i, ""));
  }

  async function decryptLocalPackage(
    packageData: EncryptedFilePackage,
    displayName: string,
    contentType: string,
    preservePath: boolean,
    stream: ReturnType<typeof createSecureDecryptionStream>,
  ): Promise<void> {
    let operationId = "";
    const fileId = packageData.metadata.file_id;
    const restoredContentType = contentType || packageData.metadata.content_type || "application/octet-stream";
    const sizeBytes = Number(packageData.metadata.original_size ?? 0);
    try {
      operationId = await createOperation("decrypt_download", null, displayName, sizeBytes);
      await logVaultAction(operationId, "vault_local_decrypt_started", "Local encrypted package decrypt started", 5, "started", fileId);
      await updateOperation(operationId, {
        status: "processing",
        current_operation: "Validating package signatures",
        progress: 32,
        size_bytes: sizeBytes,
      });
      appendLog("info", `Validating local encrypted package for ${displayName}`);
      await safeInvoke("vault_verify_metadata", { package: packageData });

      let restoredDisplayName = displayName;
      try {
        const decryptedName = cleanExplorerPath(await safeInvoke<string>("vault_decrypt_file_name", { package: packageData }));
        if (decryptedName) restoredDisplayName = preservePath && displayName.includes("/") ? displayName : decryptedName;
      } catch {
        // Filename decrypt is best-effort. Full decrypt below will return the real failure if keys are unavailable.
      }

      stream.emit({
        stage: "hybrid_decapsulation",
        detail: "Recovering local package file key with ML-KEM-1024 + X25519",
        progress: 62,
        status: "progress",
        level: "info",
      });
      await updateOperation(operationId, { current_operation: "Hybrid key decapsulation", progress: 62 });

      stream.emit({
        stage: "aes_gcm_decrypt",
        detail: "Decrypting uploaded ciphertext package locally",
        progress: 82,
        status: "progress",
        level: "info",
      });
      await updateOperation(operationId, { current_operation: "Decrypting local package", progress: 82 });
      const plaintextBase64 = await safeInvoke<string>("vault_download_decrypt", { package: packageData });
      const plaintextBlob = blobFromBase64(plaintextBase64, restoredContentType);
      const restoredName = localDecryptedDownloadName(restoredDisplayName, fileId, preservePath);
      downloadBlob(restoredName, plaintextBlob);

      stream.emit({
        stage: "integrity_verification",
        detail: "AES-GCM tags and dual signatures verified before local restore",
        progress: 96,
        status: "verified",
        level: "success",
      });
      await updateOperation(operationId, {
        status: "completed",
        current_operation: "Local decrypt ready",
        progress: 100,
        processed_bytes: sizeBytes,
        integrity_status: "verified",
      });
      await logVaultAction(operationId, "vault_local_decrypt_completed", "Local encrypted package restored", 100, "complete", fileId);
      appendLog("success", `Local decrypt completed for ${restoredName}`);

      if (resaveDecryptedToVault) {
        appendLog("info", `Re-saving local decrypt output ${restoredName} into Quantum Vault`);
        await encryptSelectedFile(new File([plaintextBlob], restoredName, { type: restoredContentType }));
      }
    } catch (error) {
      const message = normalizeDecryptionError(error);
      const keyUnavailable = isWrappedFileKeyUnavailable(message);
      appendLog(
        "error",
        keyUnavailable
          ? `Local decrypt failed: this package is not wrapped for the current local device key. ${message}`
          : `Local decrypt failed: ${message}`,
      );
      if (operationId) {
        await updateOperation(operationId, {
          status: "failed",
          current_operation: keyUnavailable ? "Device key unavailable" : "Local decrypt failed",
          error_message: message,
          integrity_status: keyUnavailable ? "not_checked" : "failed",
        });
      }
      throw new Error(message);
    }
  }

  async function purgeVaultOperationRows(fileId: string): Promise<void> {
    const { error } = await supabase
      .from("qguard_vault_operations")
      .delete()
      .eq("user_id", userId)
      .eq("file_id", fileId);
    if (error && !isMissingVaultOperationsTable(error)) {
      appendLog("error", `Vault operation cleanup failed: ${describeError(error)}`);
    }
  }

  function removeDeletedFileUiState(fileId: string, operationId?: string): void {
    setDeletedFileIds((current) => ({ ...current, [fileId]: true }));
    setOperations((current) =>
      current.filter((operation) =>
        operation.file_id !== fileId
        && operation.id !== operationId
        && !(operation.operation_type === "delete" && operation.status === "completed"),
      ),
    );
    setDecryptionStatuses((current) => {
      const next = { ...current };
      delete next[fileId];
      return next;
    });
    setResolvedFileNames((current) => {
      const next = { ...current };
      delete next[fileId];
      return next;
    });
  }

  async function cleanupInvalidFileOperation(file: VaultFileSummary, operationId: string, message: string): Promise<void> {
    if (message !== "File no longer exists") return;
    if (operationId && !isLocalOperationId(operationId)) {
      const { error } = await supabase
        .from("qguard_vault_operations")
        .delete()
        .eq("id", operationId)
        .eq("user_id", userId);
      if (error && !isMissingVaultOperationsTable(error)) appendLog("error", `Invalid operation cleanup failed: ${describeError(error)}`);
    }
    removeDeletedFileUiState(file.id, operationId);
    onUploaded();
  }

  async function handleLocalEncryptedFiles(selected: File[]) {
    if (localDecryptBusy) {
      appendLog("error", "A local decrypt job is already running.");
      return;
    }
    if (selected.length === 0) {
      appendLog("error", "No encrypted vault package was selected.");
      return;
    }

    setLocalDecryptBusy(true);
    setStatus(`Queued ${selected.length} encrypted package${selected.length === 1 ? "" : "s"} for local decrypt`);
    const stream = createSecureDecryptionStream("vault", (event) => {
      appendLog(event.data.level, `${event.data.stage}: ${event.data.detail}`);
    });

    try {
      appendLog("info", `Local decrypt intake received ${selected.length} file${selected.length === 1 ? "" : "s"}`);
      await validateDecryptionSession(userId, stream);
      enforceClientDecryptionRateLimit(userId, "vault:local-package-import", stream);
      await unlockDevicePrivateKey(stream, userId);

      let restoredCount = 0;
      for (const selectedFile of selected) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(await selectedFile.text()) as unknown;
        } catch (error) {
          appendLog("error", `${fileDisplayName(selectedFile)} is not a valid QGuard encrypted JSON package: ${describeError(error)}`);
          continue;
        }

        if (isEncryptedFolderPackage(parsed)) {
          appendLog("info", `Decrypting local encrypted folder export ${parsed.folder_path} (${parsed.files.length} file${parsed.files.length === 1 ? "" : "s"})`);
          for (const item of parsed.files) {
            try {
              await decryptLocalPackage(
                item.package,
                cleanExplorerPath(item.display_name || `${parsed.folder_path}/${item.file_id}`),
                item.content_type,
                true,
                stream,
              );
              restoredCount += 1;
            } catch {
              // Continue with remaining folder entries; the failed item is already logged.
            }
          }
          continue;
        }

        if (isEncryptedFilePackage(parsed)) {
          try {
            await decryptLocalPackage(
              parsed,
              localEncryptedDisplayName(selectedFile),
              parsed.metadata.content_type,
              fileDisplayName(selectedFile).includes("/"),
              stream,
            );
            restoredCount += 1;
          } catch {
            // Continue with remaining selected packages; the failed item is already logged.
          }
          continue;
        }

        appendLog("error", `${fileDisplayName(selectedFile)} is not a recognized QGuard encrypted file or folder package.`);
      }

      setStatus(restoredCount > 0 ? `${restoredCount} encrypted package${restoredCount === 1 ? "" : "s"} decrypted locally` : "No encrypted packages were restored");
    } catch (error) {
      setStatus(normalizeDecryptionError(error));
    } finally {
      setLocalDecryptBusy(false);
    }
  }

  async function deleteVaultRecord(file: VaultFileSummary): Promise<void> {
    await purgeVaultOperationRows(file.id);

    const rpcResult = await supabase.rpc("delete_messaging_vault_file_record", { p_file_id: file.id });
    if (!rpcResult.error && rpcResult.data === true) return;
    if (rpcResult.error && !isMissingDeleteRecordRpc(rpcResult.error)) {
      appendLog("error", `Secure delete RPC fallback failed: ${describeError(rpcResult.error)}`);
    }

    const deleteResult = await supabase
      .from("messaging_vault_files")
      .delete()
      .eq("id", file.id)
      .eq("owner_user_id", userId)
      .select("id");
    if (deleteResult.error) throw deleteResult.error;
    if ((deleteResult.data ?? []).length === 0) {
      throw new Error("Vault record was not deleted. Apply migration 014 to repair hard-delete access, then try again.");
    }
  }

  async function resolveVaultStoragePaths(file: VaultFileSummary): Promise<string[]> {
    const paths = new Set<string>([file.storage_path]);
    let manifestRead = false;

    try {
      const manifest = await readStorageJson<VaultManifest>(file.storage_path);
      if (Array.isArray(manifest.chunk_paths)) {
        manifest.chunk_paths.forEach((path) => paths.add(path));
        manifestRead = true;
      }
    } catch (error) {
      appendLog("error", `Manifest read failed; attempting storage folder cleanup: ${describeError(error)}`);
    }

    if (manifestRead) return Array.from(paths);

    const basePath = file.storage_path.replace(/\/manifest\.json$/i, "");
    if (basePath === file.storage_path) return Array.from(paths);

    for (let offset = 0; offset < 5000; offset += 1000) {
      const { data, error } = await supabase.storage
        .from("messaging-files")
        .list(`${basePath}/chunks`, { limit: 1000, offset, sortBy: { column: "name", order: "asc" } });
      if (error) throw error;
      const objects = data ?? [];
      objects.forEach((object) => paths.add(`${basePath}/chunks/${object.name}`));
      if (objects.length < 1000) break;
    }

    return Array.from(paths);
  }

  async function deleteFile(file: VaultFileSummary, options: { skipConfirm?: boolean; suppressBusy?: boolean; suppressRefresh?: boolean } = {}) {
    const displayName = fileActionDisplayName(file);
    if (!options.skipConfirm && !window.confirm(`Delete ${displayName} and its encrypted manifest/chunks?`)) return;
    let operationId = "";
    if (!options.suppressBusy) setActionBusy(`delete-${file.id}`);
    try {
      operationId = await createOperation("delete", file, displayName, file.size_bytes);
      await logVaultAction(operationId, "vault_delete_started", "Secure delete requested", 5, "started", file.id);
      await updateOperation(operationId, { status: "processing", current_operation: "Reading manifest", progress: 15 });
      const paths = await resolveVaultStoragePaths(file);
      appendLog("info", `Deleting ${displayName}: ${paths.length} storage object(s) queued for removal`);

      for (let index = 0; index < paths.length; index += 100) {
        const batch = paths.slice(index, index + 100);
        const { error: removeError } = await supabase.storage.from("messaging-files").remove(batch);
        if (removeError) throw removeError;
        const progress = 20 + Math.round((Math.min(paths.length, index + batch.length) / paths.length) * 55);
        await updateOperation(operationId, { current_operation: "Deleting encrypted storage objects", progress });
      }
      await updateOperation(operationId, { current_operation: "Deleting vault record", progress: 85 });
      await deleteVaultRecord(file);
      removeDeletedFileUiState(file.id, operationId);
      await logVaultAction(operationId, "vault_delete_completed", "Encrypted vault object deleted", 100, "complete", file.id);
      appendLog("success", `${displayName} permanently deleted from storage, metadata, and active operation views`);
      setStatus(`${displayName} deleted`);
      if (!options.suppressRefresh) onUploaded();
    } catch (err) {
      const message = describeError(err);
      appendLog("error", `Delete failed: ${message}`);
      if (operationId) await updateOperation(operationId, { status: "failed", current_operation: "Delete failed", error_message: message });
      setStatus(message);
    } finally {
      if (!options.suppressBusy) setActionBusy(null);
    }
  }

  function nodeFiles(node: VaultExplorerNode): VaultFileSummary[] {
    const seen = new Set<string>();
    return node.rows
      .map((row) => row.file)
      .filter((file): file is VaultFileSummary => Boolean(file))
      .filter((file) => {
        if (seen.has(file.id)) return false;
        seen.add(file.id);
        return true;
      });
  }

  function toggleExplorerFolder(node: VaultExplorerNode, forceExpanded?: boolean) {
    setSelectedExplorerNodeId(node.id);
    if (node.type !== "folder") return;
    setExpandedFolders((current) => ({
      ...current,
      [node.path]: forceExpanded ?? !current[node.path],
    }));
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

  async function downloadEncryptedFolder(node: VaultExplorerNode, targetFiles: VaultFileSummary[]) {
    let operationId = "";
    const folderLabel = cleanExplorerPath(node.path) || node.name || "vault folder";
    const totalFiles = Math.max(1, targetFiles.length);
    const totalBytes = targetFiles.reduce((sum, file) => sum + file.size_bytes, 0);
    let processedBytes = 0;

    try {
      operationId = await createOperation("download_encrypted", null, folderLabel, totalBytes);
      await logVaultAction(operationId, "vault_encrypted_folder_download_started", `Encrypted folder export started for ${folderLabel}`, 5, "started");
      appendLog("info", `Preparing ciphertext-only folder export for ${folderLabel} (${targetFiles.length} file${targetFiles.length === 1 ? "" : "s"})`);

      const encryptedFiles: Array<{
        file_id: string;
        display_name: string;
        size_bytes: number;
        content_type: string;
        package: EncryptedFilePackage;
      }> = [];

      for (let index = 0; index < targetFiles.length; index += 1) {
        const file = targetFiles[index];
        let displayName = fileActionDisplayName(file);
        const progressStart = 8 + Math.round((index / totalFiles) * 70);
        const progressSpan = Math.max(1, Math.round(50 / totalFiles));
        const packageData = await fetchPackage(file, operationId, `Bundling ${displayName}`, progressStart, progressSpan);
        displayName = await resolveFileActionDisplayName(file, packageData);
        processedBytes += file.size_bytes;
        encryptedFiles.push({
          file_id: file.id,
          display_name: displayName,
          size_bytes: file.size_bytes,
          content_type: file.content_type,
          package: packageData,
        });
        await updateOperation(operationId, {
          current_operation: `Bundled ${index + 1}/${targetFiles.length} encrypted file(s)`,
          progress: Math.min(92, 20 + Math.round(((index + 1) / totalFiles) * 68)),
          processed_bytes: processedBytes,
        });
      }

      await updateOperation(operationId, { current_operation: "Packaging encrypted folder export", progress: 95 });
      downloadBlob(encryptedFolderDownloadName(folderLabel), jsonBlob({
        qguard_encrypted_folder_version: 1,
        exported_at: new Date().toISOString(),
        folder_path: folderLabel,
        file_count: encryptedFiles.length,
        size_bytes: totalBytes,
        algorithm: algorithmLabel,
        files: encryptedFiles,
      }));
      await updateOperation(operationId, {
        status: "completed",
        current_operation: "Encrypted folder download ready",
        progress: 100,
        processed_bytes: totalBytes,
        integrity_status: "not_checked",
      });
      await logVaultAction(operationId, "vault_encrypted_folder_download_completed", "Encrypted folder package delivered", 100, "complete");
      setStatus(`${folderLabel} encrypted folder package downloaded`);
    } catch (err) {
      const message = describeError(err);
      appendLog("error", `Encrypted folder download failed: ${message}`);
      if (operationId) await updateOperation(operationId, { status: "failed", current_operation: "Folder download failed", error_message: message });
      setStatus(message);
    }
  }

  async function runFolderAction(node: VaultExplorerNode, action: "verify" | "download" | "decrypt" | "delete") {
    const targetFiles = nodeFiles(node);
    if (targetFiles.length === 0) {
      appendLog("error", `No vault files found under ${node.path}`);
      return;
    }
    if (action === "delete" && !window.confirm(`Delete ${targetFiles.length} encrypted vault object(s) under ${node.path}?`)) return;

    setActionBusy(`folder-${action}-${node.path}`);
    try {
      if (action === "download") {
        await downloadEncryptedFolder(node, targetFiles);
        return;
      }
      if (action === "decrypt") {
        appendLog("info", `Batch decrypt queued for ${targetFiles.length} file${targetFiles.length === 1 ? "" : "s"} under ${node.path}`);
      }
      for (const file of targetFiles) {
        if (action === "verify") await verifyFile(file, { suppressBusy: true });
        if (action === "decrypt") await decryptAndDownload(file, { suppressBusy: true });
        if (action === "delete") await deleteFile(file, { skipConfirm: true, suppressBusy: true, suppressRefresh: true });
      }
      if (action === "delete") onUploaded();
    } finally {
      setActionBusy(null);
    }
  }

  function renderActionButtons(row: PanelRow) {
    const isLiveUploadRow = uploadBusy
      && row.operation_type === "encrypt"
      && row.id === pipelineControl.operationId
      && row.status !== "completed"
      && row.status !== "failed";
    const canStop = isLiveUploadRow && pipelineControl.state !== "paused" && pipelineControl.state !== "stop_requested";
    const canResume = isLiveUploadRow && pipelineControl.state === "paused";
    const file = row.file;
    const verifyBusy = Boolean(file && actionBusy === `verify-${file.id}`);
    const downloadBusy = Boolean(file && actionBusy === `download-${file.id}`);
    const decryptBusy = Boolean(file && actionBusy === `decrypt-${file.id}`);
    const deleteBusy = Boolean(file && actionBusy === `delete-${file.id}`);
    const disabled = !file || Boolean(actionBusy);
    return (
      <div className="flex flex-wrap gap-2">
        {isLiveUploadRow && (
          <>
            <button
              type="button"
              disabled={!canStop}
              onClick={requestPipelineStop}
              className="icon-button border-amber-200 text-amber-700 hover:bg-amber-50 disabled:cursor-not-allowed disabled:opacity-50"
              title={pipelineControl.state === "stop_requested" ? "Stop requested" : "Stop upload/encryption"}
            >
              <Pause size={16} />
            </button>
            <button
              type="button"
              disabled={!canResume}
              onClick={resumePipeline}
              className="icon-button border-emerald-200 text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-50"
              title="Resume upload/encryption"
            >
              <Play size={16} />
            </button>
          </>
        )}
        <button type="button" disabled={disabled} onClick={() => file && verifyFile(file)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Verify">
          {verifyBusy ? <Loader2 className="animate-spin" size={16} /> : <CheckCircle2 size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => file && downloadEncrypted(file)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Download encrypted">
          {downloadBusy ? <Loader2 className="animate-spin" size={16} /> : <Download size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => file && decryptAndDownload(file)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Decrypt">
          {decryptBusy ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => file && deleteFile(file)} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Delete">
          {deleteBusy ? <Loader2 className="animate-spin" size={16} /> : <Trash2 size={16} />}
        </button>
      </div>
    );
  }

  function renderExplorerActions(node: VaultExplorerNode) {
    const disabled = nodeFiles(node).length === 0 || Boolean(actionBusy);
    if (node.type === "file" && node.row) return renderActionButtons(node.row);
    const verifyBusy = actionBusy === `folder-verify-${node.path}`;
    const downloadBusy = actionBusy === `folder-download-${node.path}`;
    const decryptBusy = actionBusy === `folder-decrypt-${node.path}`;
    const deleteBusy = actionBusy === `folder-delete-${node.path}`;
    return (
      <div className="flex flex-wrap gap-2">
        <button type="button" disabled={disabled} onClick={() => runFolderAction(node, "verify")} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Verify folder">
          {verifyBusy ? <Loader2 className="animate-spin" size={16} /> : <CheckCircle2 size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => runFolderAction(node, "download")} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Download encrypted folder package">
          {downloadBusy ? <Loader2 className="animate-spin" size={16} /> : <Download size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => runFolderAction(node, "decrypt")} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Decrypt folder">
          {decryptBusy ? <Loader2 className="animate-spin" size={16} /> : <UnlockKeyhole size={16} />}
        </button>
        <button type="button" disabled={disabled} onClick={() => runFolderAction(node, "delete")} className="icon-button disabled:cursor-not-allowed disabled:opacity-50" title="Delete folder files">
          {deleteBusy ? <Loader2 className="animate-spin" size={16} /> : <Trash2 size={16} />}
        </button>
      </div>
    );
  }

  function pathBasename(value: string): string {
    return value.split(/[\\/]/).filter(Boolean).pop() ?? value;
  }

  const localSuiteLine =
    "Crypto suite: X25519+ML-KEM-1024 / AES-256-GCM / HKDF-SHA3-256 / Ed25519+ML-DSA-65 (streaming, on-device)";

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
      const summary = await safeInvoke<VaultLocalStreamSummary>("vault_encrypt_path", { sourcePath: source, destPath: dest });
      const line = `Encrypted ${summary.name} (${formatBytes(summary.original_size)}, ${summary.total_chunks} chunk${summary.total_chunks === 1 ? "" : "s"}) → ${dest}`;
      appendLog("success", line);
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
      const summary = await safeInvoke<VaultLocalStreamSummary>("vault_encrypt_folder_path", { sourceDir: source, destPath: dest });
      const line = `Encrypted folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
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
      const summary = await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_path", { sourcePath: source, destPath: dest });
      const line = `Decrypted ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
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
      const summary = await safeInvoke<VaultLocalStreamSummary>("vault_decrypt_folder_path", { sourcePath: source, destDir: dest });
      const line = `Restored folder ${summary.name} (${formatBytes(summary.original_size)}) → ${dest}`;
      appendLog("success", line);
      setStatus("Local folder archive restored");
      setLocalVaultResult(line);
    });
  }

  return (
    <div className="grid gap-4">
      <section className="shell-card grid gap-4 p-5 xl:grid-cols-[1fr_1fr_320px]">
        <div
          onDragOver={(event) => {
            event.preventDefault();
          }}
          onClick={() => {
            if (!uploadBusy) fileInputRef.current?.click();
          }}
          onKeyDown={(event) => {
            if (uploadBusy || (event.key !== "Enter" && event.key !== " ")) return;
            event.preventDefault();
            fileInputRef.current?.click();
          }}
          onDrop={(event) => {
            event.preventDefault();
            const selected = Array.from(event.dataTransfer.files ?? []);
            handleSelectedFiles(selected).catch((error) => {
              const message = describeError(error);
              setStatus(message);
              appendLog("error", message);
              setUploadBusy(false);
            });
          }}
          role="button"
          tabIndex={uploadBusy ? -1 : 0}
          className="vault-upload-dropzone flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed p-4 text-center transition focus:outline-none focus:ring-2 focus:ring-cyan-400/60"
        >
          {uploadBusy ? <Loader2 className="vault-dropzone-icon mb-3 animate-spin" size={42} /> : <UploadCloud className="vault-dropzone-icon mb-3" size={42} />}
          <div className="vault-dropzone-title text-base font-bold">{uploadBusy ? "Encryption pipeline running" : "Click to select a file to Encrypt"}</div>
          <div className="vault-dropzone-subtitle mt-1 text-sm font-medium">Files are encrypted with X25519+ML-KEM-1024 / AES-256-GCM / HKDF-SHA3-256</div>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <button
              type="button"
              disabled={uploadBusy}
              onClick={(event) => {
                event.stopPropagation();
                fileInputRef.current?.click();
              }}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <UploadCloud size={16} />
              Choose File
            </button>
            <button
              type="button"
              disabled={uploadBusy}
              onClick={(event) => {
                event.stopPropagation();
                folderInputRef.current?.click();
              }}
              className="flex items-center gap-2 rounded-lg border border-cyan-200 bg-white px-4 py-2 text-sm font-bold text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <FolderOpen size={16} />
              Choose Folder
            </button>
            <button
              type="button"
              disabled={!uploadBusy || pipelineControl.state === "paused" || pipelineControl.state === "stop_requested"}
              onClick={(event) => {
                event.stopPropagation();
                requestPipelineStop();
              }}
              className="flex items-center gap-2 rounded-lg border border-amber-200 bg-white px-4 py-2 text-sm font-bold text-amber-700 hover:bg-amber-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Pause size={16} />
              Stop
            </button>
            <button
              type="button"
              disabled={pipelineControl.state !== "paused"}
              onClick={(event) => {
                event.stopPropagation();
                resumePipeline();
              }}
              className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-white px-4 py-2 text-sm font-bold text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Play size={16} />
              Resume
            </button>
          </div>
          <div className="vault-dropzone-note mt-3 text-xs">Drag files here or use the buttons. Status appears immediately below.</div>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(event) => {
              const selected = Array.from(event.currentTarget.files ?? []);
              handleSelectedFiles(selected).catch((error) => {
                const message = describeError(error);
                setStatus(message);
                appendLog("error", message);
                setUploadBusy(false);
              });
              event.currentTarget.value = "";
            }}
          />
          <input
            ref={folderInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(event) => {
              const selected = Array.from(event.currentTarget.files ?? []);
              handleSelectedFiles(selected).catch((error) => {
                const message = describeError(error);
                setStatus(message);
                appendLog("error", message);
                setUploadBusy(false);
              });
              event.currentTarget.value = "";
            }}
          />
        </div>
        <div
          onDragOver={(event) => {
            event.preventDefault();
          }}
          onClick={() => {
            if (!localDecryptBusy) localDecryptFileInputRef.current?.click();
          }}
          onKeyDown={(event) => {
            if (localDecryptBusy || (event.key !== "Enter" && event.key !== " ")) return;
            event.preventDefault();
            localDecryptFileInputRef.current?.click();
          }}
          onDrop={(event) => {
            event.preventDefault();
            const selected = Array.from(event.dataTransfer.files ?? []);
            handleLocalEncryptedFiles(selected).catch((error) => {
              const message = normalizeDecryptionError(error);
              setStatus(message);
              appendLog("error", message);
              setLocalDecryptBusy(false);
            });
          }}
          role="button"
          tabIndex={localDecryptBusy ? -1 : 0}
          className="vault-upload-dropzone flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed p-4 text-center transition focus:outline-none focus:ring-2 focus:ring-violet-400/60"
        >
          {localDecryptBusy ? <Loader2 className="vault-dropzone-icon mb-3 animate-spin" size={42} /> : <UnlockKeyhole className="vault-dropzone-icon mb-3" size={42} />}
          <div className="vault-dropzone-title text-base font-bold">{localDecryptBusy ? "Decryption pipeline running" : "Click to upload encrypted files to Decrypt"}</div>
          <div className="vault-dropzone-subtitle mt-1 text-sm font-medium">Upload downloaded .qguard encrypted file or folder JSON packages for local restore</div>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <button
              type="button"
              disabled={localDecryptBusy}
              onClick={(event) => {
                event.stopPropagation();
                localDecryptFileInputRef.current?.click();
              }}
              className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <UnlockKeyhole size={16} />
              Decrypt File
            </button>
            <button
              type="button"
              disabled={localDecryptBusy}
              onClick={(event) => {
                event.stopPropagation();
                localDecryptFolderInputRef.current?.click();
              }}
              className="flex items-center gap-2 rounded-lg border border-violet-200 bg-white px-4 py-2 text-sm font-bold text-violet-700 hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <FolderOpen size={16} />
              Decrypt Folder
            </button>
          </div>
          <div className="vault-dropzone-note mt-3 text-xs">Only packages wrapped for this device key can be decrypted.</div>
          <input
            ref={localDecryptFileInputRef}
            type="file"
            multiple
            accept=".json,.qguard"
            className="hidden"
            onChange={(event) => {
              const selected = Array.from(event.currentTarget.files ?? []);
              handleLocalEncryptedFiles(selected).catch((error) => {
                const message = normalizeDecryptionError(error);
                setStatus(message);
                appendLog("error", message);
                setLocalDecryptBusy(false);
              });
              event.currentTarget.value = "";
            }}
          />
          <input
            ref={localDecryptFolderInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(event) => {
              const selected = Array.from(event.currentTarget.files ?? []);
              handleLocalEncryptedFiles(selected).catch((error) => {
                const message = normalizeDecryptionError(error);
                setStatus(message);
                appendLog("error", message);
                setLocalDecryptBusy(false);
              });
              event.currentTarget.value = "";
            }}
          />
        </div>
        <div className="rounded-lg border border-line p-4">
          <div className="text-sm font-bold text-ink-950">Vault Activity</div>
          <div className="mt-3 text-sm font-semibold text-emerald-600">{status}</div>
          <div className="mt-3 flex flex-wrap gap-2">
            <span className={`status-pill ${
              pipelineControl.state === "paused"
                ? "bg-amber-50 text-amber-700"
                : pipelineControl.state === "stop_requested"
                  ? "bg-amber-50 text-amber-700"
                  : pipelineControl.state === "running"
                    ? "bg-cyan-50 text-cyan-700"
                    : "bg-ink-50 text-ink-600"
            }`}>
              {pipelineControl.state.replace("_", " ")}
            </span>
            {pipelineControl.label && <span className="status-pill max-w-full truncate bg-white text-ink-600">{pipelineControl.label}</span>}
          </div>
          <div className="mt-4 grid gap-2 text-sm text-ink-600">
            <div>{visibleFiles.length} encrypted files available</div>
            <div>{panelRows.length} active vault records</div>
            <div>{activeOperations.length} active realtime vault operation rows</div>
          </div>
          <label className="mt-4 flex items-center gap-2 rounded-lg border border-line bg-white px-3 py-2 text-xs font-semibold text-ink-600">
            <input
              type="checkbox"
              checked={resaveDecryptedToVault}
              onChange={(event) => setResaveDecryptedToVault(event.currentTarget.checked)}
              className="h-4 w-4 rounded border-line text-cyan-600 focus:ring-cyan-400"
            />
            Re-save decrypted output into Vault
          </label>
        </div>
        <div className="overflow-hidden rounded-lg border border-line bg-ink-950 xl:col-span-3">
          <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <Terminal size={16} />
              Vault Crypto Terminal
            </div>
            <span className="text-xs font-semibold text-cyan-200">User-scoped live vault logs</span>
          </div>
          <div ref={terminalRef} className="max-h-56 space-y-2 overflow-y-auto p-4 font-mono text-xs">
            {terminalLogs.length === 0 && (
              <div className="text-cyan-100/70">Waiting for file selection or decrypt action...</div>
            )}
            {terminalLogs.map((log) => (
              <div key={log.id} className={log.level === "error" ? "text-rose-300" : log.level === "success" ? "text-emerald-300" : "text-cyan-100"}>
                <span className="text-white/40">[{new Date(log.at).toLocaleTimeString()}]</span> {log.message}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="shell-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-bold text-ink-950">Local Vault</h2>
              <span className="status-pill bg-emerald-50 text-emerald-600"><ShieldCheck size={12} /> Offline · any size</span>
            </div>
            <p className="mt-1 max-w-2xl text-sm text-ink-600">
              Encrypt and decrypt files and folders straight to a location you choose on this device — no upload, no capacity limit. A folder is sealed into one archive and restores its full structure. Decryptable anytime on this device while you stay signed in.
            </p>
            <p className="mt-1 text-xs font-semibold text-cyan-700">{localSuiteLine}</p>
          </div>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <button
            type="button"
            disabled={localVaultBusy !== null}
            onClick={localEncryptFile}
            className="flex items-start gap-3 rounded-lg border border-cyan-200 bg-white p-4 text-left transition hover:border-cyan-300 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-600 text-white">
              {localVaultBusy === "encrypt-file" ? <Loader2 className="animate-spin" size={18} /> : <LockKeyhole size={18} />}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-ink-950">Encrypt file</div>
              <div className="mt-0.5 text-xs text-ink-600">Seal any file to a .qvault on disk</div>
            </div>
          </button>
          <button
            type="button"
            disabled={localVaultBusy !== null}
            onClick={localEncryptFolder}
            className="flex items-start gap-3 rounded-lg border border-cyan-200 bg-white p-4 text-left transition hover:border-cyan-300 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-600 text-white">
              {localVaultBusy === "encrypt-folder" ? <Loader2 className="animate-spin" size={18} /> : <FileArchive size={18} />}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-ink-950">Encrypt folder</div>
              <div className="mt-0.5 text-xs text-ink-600">Pack a folder into one encrypted archive</div>
            </div>
          </button>
          <button
            type="button"
            disabled={localVaultBusy !== null}
            onClick={localDecryptFile}
            className="flex items-start gap-3 rounded-lg border border-cyan-200 bg-white p-4 text-left transition hover:border-cyan-300 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white">
              {localVaultBusy === "decrypt-file" ? <Loader2 className="animate-spin" size={18} /> : <UnlockKeyhole size={18} />}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-ink-950">Decrypt file</div>
              <div className="mt-0.5 text-xs text-ink-600">Restore a .qvault file on this device</div>
            </div>
          </button>
          <button
            type="button"
            disabled={localVaultBusy !== null}
            onClick={localDecryptFolder}
            className="flex items-start gap-3 rounded-lg border border-cyan-200 bg-white p-4 text-left transition hover:border-cyan-300 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white">
              {localVaultBusy === "decrypt-folder" ? <Loader2 className="animate-spin" size={18} /> : <FolderOpen size={18} />}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-ink-950">Decrypt folder</div>
              <div className="mt-0.5 text-xs text-ink-600">Restore an encrypted folder archive</div>
            </div>
          </button>
        </div>
        {localVaultResult && (
          <div className="mt-3 break-words rounded-lg border border-emerald-100 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-700">
            {localVaultResult}
          </div>
        )}
      </section>

      <section className="shell-card overflow-hidden">
        <div className="border-b border-line p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-ink-950">Real-Time Telemetry & File Operations</h2>
              <div className="mt-1 text-xs text-ink-600">User-scoped Supabase Realtime updates for encryption, upload, verification, download, decrypt, and delete operations.</div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {[
                { id: "operations" as const, label: "Operations", icon: ShieldCheck },
                { id: "explorer" as const, label: "Files & Folders", icon: FolderOpen },
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
              <span className="status-pill bg-cyan-50 text-cyan-700"><ShieldCheck size={13} />WebSocket scoped</span>
            </div>
          </div>
        </div>

        {activeVaultTab === "operations" && (
          <>
            <div className="grid grid-cols-[1.2fr_120px_170px_150px_130px_150px_190px] border-b border-line px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>Name</span><span>Status</span><span>Operation</span><span>Progress</span><span>Size</span><span>Integrity</span><span>Actions</span>
            </div>

            {panelRows.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">No vault telemetry yet. Select a file to start encrypted processing.</div>
            )}

            {panelRows.map((row) => (
          <div key={`${row.id}-${row.file?.id ?? "op"}`} className="grid grid-cols-[1.2fr_120px_170px_150px_130px_150px_190px] items-center gap-3 border-b border-line px-4 py-3 text-sm">
            <div className="min-w-0">
              <div className="truncate font-semibold text-ink-950">{row.display_name}</div>
              <div className="mt-1 truncate font-mono text-xs text-ink-400">{row.file?.storage_path ?? row.id}</div>
              {row.file && <div className="mt-2 flex flex-wrap gap-2">{renderDecryptionStatusPill(row.file, row)}</div>}
              {row.error_message && <div className="mt-1 truncate text-xs font-semibold text-rose-600">{row.error_message}</div>}
            </div>
            <span className={`status-pill justify-center ${operationDisplayTone(row)}`}>{operationDisplayStatus(row)}</span>
            <div className="min-w-0">
              <div className="truncate font-semibold text-ink-700">{row.current_operation}</div>
              <div className="mt-1 truncate text-xs text-ink-400">{row.algorithm}</div>
            </div>
            <div>
              <div className="h-2 overflow-hidden rounded-full bg-canvas">
                <div className="h-full rounded-full bg-cyan-500 transition-all duration-300" style={{ width: `${row.progress}%` }} />
              </div>
              <div className="mt-1 text-xs font-semibold text-ink-600">{row.progress}% - ETA {formatDuration(etaSeconds(row))}</div>
            </div>
            <div className="text-xs text-ink-600">
              <div>{formatBytes(row.processed_bytes)}</div>
              <div>{formatBytes(row.size_bytes)}</div>
              <div>{formatDuration(elapsedSeconds(row))}</div>
            </div>
            <span className={`status-pill justify-center ${row.integrity_status === "verified" ? "bg-emerald-50 text-emerald-600" : row.integrity_status === "failed" ? "bg-rose-50 text-rose-600" : "bg-ink-50 text-ink-600"}`}>
              <FileCheck2 size={13} />
              {integrityText(row.integrity_status)}
            </span>
            {renderActionButtons(row)}
          </div>
        ))}
          </>
        )}

        {activeVaultTab === "explorer" && (
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
              <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-ink-500">
                <span className="status-pill bg-ink-50 text-ink-600">{explorerFileCount} files</span>
                <span className="status-pill bg-ink-50 text-ink-600">{explorerFolderCount} folders</span>
                <span className="status-pill bg-cyan-50 text-cyan-700">{visibleExplorerNodes.length} visible</span>
              </div>
              {selectedExplorerNodeId && (
                <span className="status-pill max-w-full bg-white text-ink-600">
                  Selected {allExplorerNodes.find((node) => node.id === selectedExplorerNodeId)?.name ?? "item"}
                </span>
              )}
            </div>
            <div className="grid grid-cols-[minmax(280px,1.4fr)_120px_150px_150px_180px] border-b border-line px-4 py-3 text-xs font-bold uppercase tracking-wide text-ink-400">
              <span>File Explorer</span><span>Status</span><span>Progress</span><span>Integrity</span><span>Actions</span>
            </div>
            {allExplorerNodes.length === 0 && (
              <div className="p-6 text-center text-sm text-ink-600">No encrypted files or folders yet.</div>
            )}
            {allExplorerNodes.length > 0 && (
              <div role="tree" aria-label="Quantum Vault file explorer" className="max-h-[620px] overflow-y-auto">
                {visibleExplorerNodes.map((node) => {
                  const expanded = Boolean(expandedFolders[node.path]);
                  const selected = selectedExplorerNodeId === node.id;
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
                      className={`vault-tree-row grid min-h-[64px] grid-cols-[minmax(280px,1.4fr)_120px_150px_150px_180px] items-center gap-3 border-b border-line px-4 py-3 text-sm outline-none transition ${
                        selected
                          ? "bg-cyan-50 shadow-[inset_3px_0_0_#0891b2]"
                          : "bg-white hover:bg-cyan-50/50 focus:bg-cyan-50/60"
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="flex min-w-0 items-center gap-2 font-semibold text-ink-950" style={{ paddingLeft: `${node.depth * 20}px` }}>
                          {node.type === "folder" ? (
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
                        <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-ink-400" style={{ paddingLeft: `${node.depth * 20 + 32}px` }}>
                          <span className="truncate">{node.path}</span>
                          <span className="font-sans font-semibold text-ink-500">{nodeItemText(node)}</span>
                          {node.row?.file && renderDecryptionStatusPill(node.row.file, node.row)}
                        </div>
                        {node.row?.error_message && <div className="mt-1 truncate text-xs font-semibold text-rose-600" style={{ paddingLeft: `${node.depth * 20 + 32}px` }}>{node.row.error_message}</div>}
                      </div>
                      <span className={`status-pill justify-center ${operationTone(node.status)}`}>{node.status}</span>
                      <div>
                        <div className="h-2 overflow-hidden rounded-full bg-canvas">
                          <div className="h-full rounded-full bg-cyan-500 transition-all duration-300" style={{ width: `${node.progress}%` }} />
                        </div>
                        <div className="mt-1 text-xs font-semibold text-ink-600">{node.progress}%</div>
                      </div>
                      <span className={`status-pill justify-center ${node.integrity_status === "verified" ? "bg-emerald-50 text-emerald-600" : node.integrity_status === "failed" ? "bg-rose-50 text-rose-600" : "bg-ink-50 text-ink-600"}`}>
                        <FileCheck2 size={13} />
                        {integrityText(node.integrity_status)}
                      </span>
                      <div onClick={(event) => event.stopPropagation()}>
                        {renderExplorerActions(node)}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
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
