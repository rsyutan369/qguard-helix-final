import {
  AlertTriangle,
  ArrowUpDown,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Cloud,
  CloudDownload,
  Download,
  Eye,
  FileText,
  FolderInput,
  FolderPlus,
  HardDrive,
  History,
  Image as ImageIcon,
  LayoutDashboard,
  LayoutGrid,
  LayoutList,
  List,
  Rows3,
  Loader2,
  Briefcase,
  UserRound,
  Pencil,
  RefreshCw,
  RotateCcw,
  Search,
  Share2,
  ShieldCheck,
  Star,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ask as askDialog, open as openDialog, save as saveDialog } from "@/lib/tauri-dialog";
import { isAndroidRuntime, isTauriRuntime } from "@/lib/tauri";
import { chooseDestinationFolder, prepareDestination } from "@/lib/vault-destination";
import { opLabel, phaseLabel, type VaultProgress } from "@/lib/vault-progress";
import {
  breadcrumb,
  byId,
  canPreview,
  childrenOf,
  describeStoreError,
  folderTotals,
  formatBytes,
  inTrash,
  integrityLabel,
  liveEntries,
  matchesFilter,
  progressPercent,
  sortEntries,
  trashRoots,
  vaultStore,
  type SortDirection,
  type SortKey,
  type StoreActivity,
  type StoreCategory,
  type StoreEntry,
  type StoreStatus,
} from "@/lib/vault-store";
import {
  describeCloudError,
  downloadCloudOnlyFiles,
  downloadToDevice,
  runCloudSync,
  vaultCloudCore,
  type CloudState,
  type SyncProgress,
} from "@/lib/vault-cloud";
import { libraryCore, type LibraryDevice } from "@/lib/vault-library";
import { releaseUnusedShareCopies } from "@/lib/vault-share";
import { onVaultSectionRequest, takeRequestedVaultSection } from "@/lib/vault-nav";
import { CloudBackupPanel } from "./CloudBackupPanel";
import { ShareDialog, SharedFiles } from "./Sharing";
import { HiddenVaultCard, PatternUnlockCard, type VaultLockControls } from "./VaultLockCards";
import { EntryIcon, EntryThumbnail } from "./EntryVisual";
import { MoveDialog, NameDialog, PreviewDialog, previewOfEntry, type PreviewSubject } from "./StorageDialogs";
import { ActivityList, StorageOverview, formatWhen } from "./StorageOverview";
import { StorageSecurity } from "./StorageSecurity";

// ---------------------------------------------------------------------------
// Quantum Vault Storage — the on-device encrypted library.
//
// The Rust core owns every record (see lib/vault-store.ts). This component
// keeps NO vault state of its own beyond view preferences: after any change it
// re-reads the status and listing from the core, so what is shown is what the
// sealed index and the disk actually hold.
// ---------------------------------------------------------------------------

type Section =
  | "overview"
  | "files"
  | "media"
  | "documents"
  | "personal"
  | "work"
  | "favorites"
  | "shared"
  | "trash"
  | "activity"
  | "security";

/**
 * The vault's sections, shown as cards in the same style as the Home
 * dashboard's Secure Chat / Calls / Quantum Vault / Contacts cards. Overview is
 * not a card: it is what the page shows when no section is open.
 */
const SECTION_CARDS: Array<{ id: Exclude<Section, "overview">; label: string; caption: string; Icon: typeof HardDrive }> = [
  { id: "files", label: "My Files", caption: "Everything in your vault, by folder", Icon: HardDrive },
  { id: "media", label: "Photos & Videos", caption: "Images and video clips", Icon: ImageIcon },
  { id: "documents", label: "Documents", caption: "PDFs, Office files and text", Icon: FileText },
  { id: "personal", label: "Personal", caption: "Your Personal folder", Icon: UserRound },
  { id: "work", label: "Work", caption: "Your Work folder", Icon: Briefcase },
  { id: "favorites", label: "Favorites", caption: "Files you have starred", Icon: Star },
  { id: "shared", label: "Shared", caption: "Shared by you and with you", Icon: Share2 },
  { id: "trash", label: "Trash", caption: "Deleted items, still encrypted", Icon: Trash2 },
  { id: "activity", label: "Activity", caption: "What happened in your vault", Icon: History },
  { id: "security", label: "Security & Backup", caption: "Integrity, recovery and cloud backup", Icon: ShieldCheck },
];

/** Cards shown before "Show all" is chosen. */
const DEFAULT_VISIBLE_CARDS = 6;

interface CardPrefs {
  /** Every section card is hidden; only the header row remains. */
  collapsed: boolean;
  /** All cards, not just the first DEFAULT_VISIBLE_CARDS. */
  showAll: boolean;
}

function readCardPrefs(key: string): CardPrefs {
  try {
    const saved = JSON.parse(window.localStorage.getItem(key) ?? "{}") as Partial<CardPrefs>;
    return { collapsed: saved.collapsed === true, showAll: saved.showAll === true };
  } catch {
    return { collapsed: false, showAll: false };
  }
}

const SECTION_CATEGORIES: Partial<Record<Section, StoreCategory[]>> = {
  media: ["image", "video"],
  documents: ["document"],
};

// Personal and Work are spaces the user files things into, whatever their
// type. Each is an ordinary folder of that name at the top of My Files (the
// same sealed index, encryption, sync and sharing as any folder), created the
// first time something is added there; moving a file between spaces is a
// normal Move.
const SPACE_FOLDERS: Partial<Record<Section, string>> = {
  personal: "Personal",
  work: "Work",
};

function findSpaceRoot(live: StoreEntry[], name: string): StoreEntry | null {
  const wanted = name.toLocaleLowerCase();
  return live.find((entry) => entry.kind === "folder" && !entry.parentId && entry.name.toLocaleLowerCase() === wanted) ?? null;
}

const IS_ANDROID = isAndroidRuntime();

interface Operation {
  title: string;
  detail: string;
  progress: VaultProgress | null;
}

interface Notice {
  tone: "success" | "error" | "info";
  text: string;
}

/**
 * How a folder's contents are laid out: large cards, compact tiles, content
 * panels (one per row, with details), or a details table.
 */
type ViewMode = "grid" | "tiles" | "content" | "list";

const VIEW_MODES: Array<{ mode: ViewMode; label: string; Icon: typeof LayoutGrid }> = [
  { mode: "grid", label: "Large icons", Icon: LayoutGrid },
  { mode: "tiles", label: "Tiles", Icon: LayoutList },
  { mode: "content", label: "Content", Icon: Rows3 },
  { mode: "list", label: "Details", Icon: List },
];

function readViewMode(key: string): ViewMode {
  try {
    const saved = window.localStorage.getItem(key);
    return VIEW_MODES.some((view) => view.mode === saved) ? (saved as ViewMode) : "grid";
  } catch {
    return "grid";
  }
}

/** "PDF file", "Folder" — from the name's extension, else the stored content type. */
function typeLabel(entry: StoreEntry): string {
  if (entry.kind === "folder") return "Folder";
  const dot = entry.name.lastIndexOf(".");
  const extension = dot > 0 && dot < entry.name.length - 1 ? entry.name.slice(dot + 1) : "";
  if (extension && extension.length <= 8) return `${extension.toUpperCase()} file`;
  return entry.contentType || "File";
}

function basename(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function IntegrityBadge({ entry }: { entry: StoreEntry }) {
  if (entry.kind !== "file") return null;
  // A file kept in the cloud only has no local copy whose integrity this
  // device could have checked: it shows just that it is in the cloud.
  if (entry.cloudObjectId && !entry.availableOffline) {
    return <CloudDownload className="shrink-0 text-cyan-600" size={14} aria-label="In your cloud backup only — opens after downloading" />;
  }
  const inCloud = !entry.cloudObjectId ? null : entry.cloudSharedOnly ? (
    <Share2 className="shrink-0 text-cyan-600" size={13} aria-label="Shared · one encrypted copy in the cloud, not a backup" />
  ) : (
    <Cloud className="shrink-0 text-cyan-600" size={13} aria-label="Backed up to the cloud" />
  );
  return (
    <>
      {inCloud}
      <IntegrityIcon entry={entry} />
    </>
  );
}

function IntegrityIcon({ entry }: { entry: StoreEntry }) {
  if (entry.integrity === "verified") return <CheckCircle2 className="shrink-0 text-emerald-600" size={14} aria-label="Integrity verified" />;
  if (entry.integrity === "failed" || entry.integrity === "missing") return <AlertTriangle className="shrink-0 text-rose-500" size={14} aria-label={integrityLabel(entry)} />;
  return <ShieldCheck className="shrink-0 text-ink-400" size={14} aria-label="Encrypted, not yet verified" />;
}

function ToolbarButton({ onClick, disabled, children, primary = false, title }: { onClick: () => void; disabled?: boolean; children: ReactNode; primary?: boolean; title?: string }) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${
        primary ? "bg-cyan-600 text-white shadow-tight hover:opacity-90" : "border border-line bg-white text-ink-800 hover:bg-canvas"
      }`}
    >
      {children}
    </button>
  );
}

export default function VaultStorage({
  userId,
  onOpenRecovery,
  vaultLock,
  sharedFilesWaiting = 0,
}: {
  userId: string;
  onOpenRecovery: () => void;
  /** Files shared with this account waiting for Accept / Decline (app-wide count). */
  sharedFilesWaiting?: number;
  /** Pattern unlock and hidden vaults; absent where the app lock is not wired in. */
  vaultLock?: VaultLockControls;
}) {
  const viewModeKey = `qguard.vault.storage.view:${userId}`;
  const [status, setStatus] = useState<StoreStatus | null>(null);
  const [entries, setEntries] = useState<StoreEntry[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  // The "someone sent you a file" notice can ask for Shared before the vault
  // mounts (it sits behind its lock); take that request as the first section.
  const [section, setSection] = useState<Section>(() => (takeRequestedVaultSection() === "shared" ? "shared" : "overview"));
  const [folderId, setFolderId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [viewMode, setViewMode] = useState<ViewMode>(() => readViewMode(viewModeKey));
  const cardPrefsKey = `qguard.vault.storage.cards:${userId}`;
  const [cardPrefs, setCardPrefs] = useState<CardPrefs>(() => readCardPrefs(cardPrefsKey));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [operation, setOperation] = useState<Operation | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [nameDialog, setNameDialog] = useState<{ mode: "new-folder" } | { mode: "rename"; entry: StoreEntry } | null>(null);
  const [moving, setMoving] = useState<StoreEntry[] | null>(null);
  const [previewing, setPreviewing] = useState<PreviewSubject | null>(null);
  const [sharing, setSharing] = useState<StoreEntry | null>(null);
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [libraryDevices, setLibraryDevices] = useState<LibraryDevice[]>([]);
  const [waitingForAccess, setWaitingForAccess] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [activity, setActivity] = useState<StoreActivity[] | null>(null);
  const [cloud, setCloud] = useState<CloudState | null>(null);
  const [cloudSyncing, setCloudSyncing] = useState(false);
  const [cloudProgress, setCloudProgress] = useState<SyncProgress | null>(null);

  const busy = operation !== null;
  const index = useMemo(() => byId(entries), [entries]);
  const live = useMemo(() => liveEntries(entries), [entries]);
  const spaceName = SPACE_FOLDERS[section] ?? null;
  const spaceRoot = useMemo(() => (spaceName ? findSpaceRoot(live, spaceName) : null), [live, spaceName]);
  /** A folder view: My Files, or a space (Personal, Work). */
  const browsing = section === "files" || spaceName !== null;
  // Inside a space, `folderId` null means the space's own folder.
  const currentFolder = spaceName ? (folderId ?? spaceRoot?.id ?? null) : folderId;
  const spaceFiles = useMemo(() => {
    const counts: Partial<Record<Section, number>> = {};
    for (const [id, name] of Object.entries(SPACE_FOLDERS) as Array<[Section, string]>) {
      const root = findSpaceRoot(live, name);
      counts[id] = root ? folderTotals(entries, root.id).files : 0;
    }
    return counts;
  }, [entries, live]);
  const maxPreviewBytes = status?.limits.maxPreviewBytes ?? 0;

  useEffect(() => {
    try {
      window.localStorage.setItem(viewModeKey, viewMode);
    } catch {
      // A view preference only.
    }
  }, [viewMode, viewModeKey]);

  useEffect(() => {
    try {
      window.localStorage.setItem(cardPrefsKey, JSON.stringify(cardPrefs));
    } catch {
      // A view preference only.
    }
  }, [cardPrefs, cardPrefsKey]);

  const refresh = useCallback(async () => {
    try {
      const nextStatus = await vaultStore.status();
      setStatus(nextStatus);
      setEntries(nextStatus.state === "ready" ? await vaultStore.list() : []);
      // Backup state needs the recovery settings readable; without them the
      // panel says so instead of guessing.
      setCloud(nextStatus.state === "ready" ? await vaultCloudCore.state().catch(() => null) : null);
      if (nextStatus.state === "ready") setDeviceId((await libraryCore.status().catch(() => null))?.deviceId ?? null);
      setLoadError(null);
    } catch (error) {
      setLoadError(describeStoreError(error));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // ...and hear it while the vault is already open.
  useEffect(
    () =>
      onVaultSectionRequest((requested) => {
        if (requested === "shared") {
          setSection("shared");
          setQuery("");
        }
      }),
    [],
  );

  useEffect(() => {
    if (section !== "activity") return;
    setActivity(null);
    vaultStore.activity().then(setActivity, (error) => setNotice({ tone: "error", text: describeStoreError(error) }));
  }, [section, entries]);

  // Navigation clears the selection; a folder that disappeared returns to the top.
  useEffect(() => setSelected(new Set()), [section, folderId]);
  useEffect(() => {
    if (folderId && (!index.has(folderId) || inTrash(index, folderId))) setFolderId(null);
  }, [folderId, index]);

  // The core recorded the sealed thumbnail; mirror just that flag locally
  // instead of re-reading the whole library once per thumbnail.
  const markThumbnail = useCallback((id: string) => {
    setEntries((current) => current.map((entry) => (entry.id === id ? { ...entry, hasThumbnail: true } : entry)));
  }, []);

  const onProgress = useCallback((progress: VaultProgress) => {
    setOperation((current) => (current ? { ...current, progress, detail: progress.phase === "file" ? progress.message : current.detail } : current));
  }, []);

  /** Run one long operation with the live progress panel; refresh afterwards. */
  const runOperation = useCallback(
    async <T,>(title: string, detail: string, job: () => Promise<T>): Promise<T | undefined> => {
      setOperation({ title, detail, progress: null });
      setNotice(null);
      try {
        return await job();
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
        return undefined;
      } finally {
        setOperation(null);
        await refresh();
      }
    },
    [refresh],
  );

  // ---- import ------------------------------------------------------------

  const importPaths = useCallback(
    async (paths: string[], parentId: string | null) => {
      if (paths.length === 0) return;
      let imported = 0;
      let skipped = 0;
      const failures: string[] = [];
      setNotice(null);
      setOperation({ title: `Encrypting into your vault`, detail: "", progress: null });
      try {
        for (const [position, path] of paths.entries()) {
          const name = basename(path);
          setOperation({ title: `Encrypting ${position + 1} of ${paths.length}`, detail: IS_ANDROID ? "" : name, progress: null });
          try {
            const kind = IS_ANDROID ? "file" : await vaultStore.pathKind(path);
            if (kind === "folder") {
              const outcome = await vaultStore.importFolder(path, parentId, onProgress);
              imported += outcome.imported;
              skipped += outcome.skippedDuplicates;
              failures.push(...outcome.failed.map((failure) => `${failure.name}: ${describeStoreError(failure.error)}`));
            } else if (kind === "file") {
              const outcome = await vaultStore.importFile(path, parentId, onProgress);
              if (outcome.skippedDuplicate) skipped += 1;
              else imported += 1;
            } else {
              failures.push(`${name}: not a file or folder`);
            }
          } catch (error) {
            const text = describeStoreError(error);
            failures.push(`${name}: ${text}`);
            if (text.includes("vault locked")) break;
          }
        }
      } finally {
        setOperation(null);
        await refresh();
      }
      const parts = [`${imported} file${imported === 1 ? "" : "s"} encrypted into your vault`];
      if (skipped > 0) parts.push(`${skipped} already in that folder (skipped)`);
      if (failures.length > 0) parts.push(`${failures.length} failed — ${failures.slice(0, 3).join("; ")}${failures.length > 3 ? "…" : ""}`);
      setNotice({ tone: failures.length > 0 ? (imported > 0 ? "info" : "error") : "success", text: parts.join(" · ") });
    },
    [onProgress, refresh],
  );

  /**
   * The folder new files and folders go into: the open folder in My Files or a
   * space, else the top level. A space's folder is created the first time
   * something goes into it.
   */
  const ensureTarget = useCallback(async (): Promise<string | null> => {
    if (!browsing) return null;
    if (!spaceName || currentFolder) return currentFolder;
    return (await vaultStore.createFolder(null, spaceName)).id;
  }, [browsing, spaceName, currentFolder]);

  const importInto = useCallback(
    async (paths: string[]) => {
      if (paths.length === 0) return;
      let target: string | null;
      try {
        target = await ensureTarget();
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
        return;
      }
      await importPaths(paths, target);
    },
    [ensureTarget, importPaths],
  );

  const pickFiles = useCallback(async () => {
    const picked = await openDialog({ multiple: true, directory: false, title: "Add files to your Quantum Vault" });
    const paths = picked == null ? [] : Array.isArray(picked) ? picked : [picked];
    await importInto(paths.map(String));
  }, [importInto]);

  const pickFolder = useCallback(async () => {
    const picked = await openDialog({ multiple: false, directory: true, title: "Add a folder to your Quantum Vault" });
    if (typeof picked === "string") await importInto([picked]);
  }, [importInto]);

  /** Move items into Personal or Work, creating that space's folder if needed. */
  const moveToSpace = useCallback(
    async (items: StoreEntry[], space: Section) => {
      const name = SPACE_FOLDERS[space];
      if (!name) return;
      // The spaces' own folders never move into one another.
      const spaceNames = new Set(Object.values(SPACE_FOLDERS).map((n) => n.toLocaleLowerCase()));
      const movable = items.filter((item) => !(item.kind === "folder" && !item.parentId && spaceNames.has(item.name.toLocaleLowerCase())));
      if (movable.length === 0) {
        setNotice({ tone: "info", text: `The ${Object.values(SPACE_FOLDERS).join(" and ")} folders stay at the top of My Files.` });
        return;
      }
      const moved = await runOperation(`Moving to ${name}`, "", async () => {
        const root = findSpaceRoot(liveEntries(entries), name) ?? (await vaultStore.createFolder(null, name));
        return vaultStore.move(
          movable.map((item) => item.id),
          root.id,
        );
      });
      if (moved) {
        setSelected(new Set());
        setNotice({ tone: "success", text: `Moved ${movable.length === 1 ? `"${movable[0].name}"` : `${movable.length} items`} to ${name}.` });
      }
    },
    [entries, runOperation],
  );

  // Desktop drag and drop: Tauri delivers dropped paths to the webview.
  const dropRef = useRef({ importInto, busy, ready: status?.state === "ready" });
  dropRef.current = { importInto, busy, ready: status?.state === "ready" };
  useEffect(() => {
    if (IS_ANDROID || !isTauriRuntime()) return;
    let unlisten: (() => void) | undefined;
    let disposed = false;
    import("@tauri-apps/api/webview")
      .then(({ getCurrentWebview }) =>
        getCurrentWebview().onDragDropEvent((event) => {
          const { type } = event.payload;
          if (type === "enter" || type === "over") setDragOver(dropRef.current.ready && !dropRef.current.busy);
          else if (type === "leave") setDragOver(false);
          else if (type === "drop") {
            setDragOver(false);
            const current = dropRef.current;
            if (current.busy || !current.ready) return;
            void current.importInto(event.payload.paths);
          }
        }),
      )
      .then((fn) => {
        if (disposed) fn();
        else unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  // ---- per-item actions -------------------------------------------------

  /** A file kept in the cloud only is downloaded (and verified) before use. */
  const ensureLocal = useCallback(
    async (entry: StoreEntry): Promise<boolean> => {
      if (entry.kind !== "file" || entry.availableOffline || !entry.cloudObjectId) return true;
      const done = await runOperation(`Downloading ${entry.name}`, "From your cloud backup · checking every part", async () => {
        await downloadToDevice(userId, entry);
        return true;
      });
      return done === true;
    },
    [runOperation, userId],
  );

  const exportEntry = useCallback(
    async (entry: StoreEntry) => {
      setPreviewing(null);
      if (entry.kind === "folder") {
        if (IS_ANDROID) {
          setNotice({ tone: "info", text: "Exporting a whole folder is available on desktop. On Android, export files one at a time." });
          return;
        }
        const dir = await openDialog({ multiple: false, directory: true, title: `Choose where to export "${entry.name}"` });
        if (typeof dir !== "string") return;
        // Files inside that are kept in the cloud only come down first.
        const inside = entries.filter((candidate) => {
          if (candidate.kind !== "file" || candidate.availableOffline || !candidate.cloudObjectId || candidate.trashedAt) return false;
          return breadcrumb(index, candidate.parentId).some((folder) => folder.id === entry.id);
        });
        if (inside.length > 0) {
          const fetched = await runOperation(`Downloading ${inside.length} file${inside.length === 1 ? "" : "s"}`, "From your cloud backup", () =>
            downloadCloudOnlyFiles(userId, inside),
          );
          if (!fetched || fetched.failed.length > 0) {
            if (fetched) setNotice({ tone: "error", text: `Some files could not be downloaded: ${fetched.failed.slice(0, 2).join("; ")}` });
            return;
          }
        }
        const outcome = await runOperation(`Exporting ${entry.name}`, "Decrypting and verifying each file", () => vaultStore.exportFolder(entry.id, dir, onProgress));
        if (outcome) setNotice({ tone: "success", text: `${outcome.files} file${outcome.files === 1 ? "" : "s"} decrypted to ${outcome.destination}. Exported copies are not encrypted.` });
        return;
      }
      if (!(await ensureLocal(entry))) return;
      let destination: string | null = null;
      try {
        if (IS_ANDROID) {
          const folder = await chooseDestinationFolder("Choose where to save the decrypted file");
          if (!folder) return;
          destination = await prepareDestination(folder.path, entry.name);
        } else {
          destination = await saveDialog({ title: "Export decrypted copy", defaultPath: entry.name });
        }
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
        return;
      }
      if (!destination) return;
      const target = destination;
      const outcome = await runOperation(`Exporting ${entry.name}`, "Decrypting and verifying", () => vaultStore.exportFile(entry.id, target, onProgress));
      if (outcome) setNotice({ tone: "success", text: `"${outcome.name}" decrypted and verified. The exported copy is not encrypted — delete it when you are done.` });
    },
    [onProgress, runOperation, ensureLocal, entries, index, userId],
  );

  const openEntry = useCallback(
    (entry: StoreEntry) => {
      if (entry.kind === "folder") {
        // A folder inside the open space stays in that space; any other
        // folder opens in My Files.
        const inSpace = spaceRoot !== null && breadcrumb(index, entry.id).some((folder) => folder.id === spaceRoot.id);
        if (!inSpace) setSection("files");
        setQuery("");
        setFolderId(inSpace && entry.id === spaceRoot?.id ? null : entry.id);
        return;
      }
      void (async () => {
        if (!(await ensureLocal(entry))) return;
        if (canPreview(entry, maxPreviewBytes)) setPreviewing(previewOfEntry(entry));
        else setSelected(new Set([entry.id]));
      })();
    },
    [maxPreviewBytes, ensureLocal, spaceRoot, index],
  );

  const verifyEntry = useCallback(
    async (entry: StoreEntry) => {
      if (!(await ensureLocal(entry))) return;
      const result = await runOperation(`Verifying ${entry.name}`, "Signed header, every chunk tag and the content hash", () => vaultStore.verify(entry.id, onProgress));
      if (result) setNotice({ tone: "success", text: `"${entry.name}" verified: authentic, complete and unaltered.` });
    },
    [onProgress, runOperation, ensureLocal],
  );

  const trashEntries = useCallback(
    async (targets: StoreEntry[]) => {
      if (targets.length === 0) return;
      try {
        await vaultStore.trash(targets.map((e) => e.id));
        setNotice({ tone: "info", text: `${targets.length === 1 ? `"${targets[0].name}"` : `${targets.length} items`} moved to Trash. Still encrypted; restore any time.` });
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
      }
      setSelected(new Set());
      await refresh();
    },
    [refresh],
  );

  const restoreEntries = useCallback(
    async (targets: StoreEntry[]) => {
      try {
        await vaultStore.restore(targets.map((e) => e.id));
        setNotice({ tone: "success", text: `${targets.length === 1 ? `"${targets[0].name}"` : `${targets.length} items`} restored.` });
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
      }
      setSelected(new Set());
      await refresh();
    },
    [refresh],
  );

  const purgeEntries = useCallback(
    async (targets: StoreEntry[] | "all") => {
      const label = targets === "all" ? "everything in the Trash" : targets.length === 1 ? `"${targets[0].name}"` : `${targets.length} items`;
      const confirmed = await askDialog(
        `Permanently delete ${label}?\n\nEach file's encryption key is destroyed with it. This cannot be undone, and the recovery key will not bring it back.`,
        { title: "Delete permanently", okLabel: "Delete permanently", cancelLabel: "Cancel" },
      ).catch(() => false);
      if (!confirmed) return;
      const outcome = await runOperation("Deleting permanently", "Destroying per-file keys and encrypted data", () =>
        targets === "all" ? vaultStore.emptyTrash() : vaultStore.purge(targets.map((e) => e.id)),
      );
      if (outcome) setNotice({ tone: "success", text: `${outcome.removedEntries} item${outcome.removedEntries === 1 ? "" : "s"} deleted permanently.` });
      setSelected(new Set());
    },
    [runOperation],
  );

  const toggleFavorite = useCallback(
    async (entry: StoreEntry) => {
      try {
        await vaultStore.setFavorite(entry.id, !entry.favorite);
      } catch (error) {
        setNotice({ tone: "error", text: describeStoreError(error) });
      }
      await refresh();
    },
    [refresh],
  );

  const verifyAll = useCallback(async () => {
    const report = await runOperation("Verifying every file", "Decrypting in memory and checking authenticity", () => vaultStore.verifyAll(onProgress));
    if (report) {
      const clean = report.failed === 0 && report.missing === 0;
      setNotice({
        tone: clean ? "success" : "error",
        text: `${report.checked} checked · ${report.verified} verified${report.failed ? ` · ${report.failed} failed` : ""}${report.missing ? ` · ${report.missing} missing` : ""}.`,
      });
    }
  }, [onProgress, runOperation]);

  const startFresh = useCallback(async () => {
    const confirmed = await askDialog(
      "Set the previous vault's library aside and start a new, empty one?\n\nNothing is deleted: the old encrypted files are moved, unchanged, to a folder next to the new library and still open with your recovery key.",
      { title: "Start a new library", okLabel: "Start fresh", cancelLabel: "Cancel" },
    ).catch(() => false);
    if (!confirmed) return;
    const outcome = await runOperation("Starting a new library", "", () => vaultStore.startFresh());
    if (outcome) setNotice({ tone: "success", text: `The previous library was kept, unchanged, at ${outcome.archivedTo}.` });
  }, [runOperation]);

  // ---- cloud backup -------------------------------------------------------

  const syncRunning = useRef(false);
  const runSync = useCallback(
    async (manual: boolean) => {
      if (!isTauriRuntime() || syncRunning.current) return;
      syncRunning.current = true;
      setCloudSyncing(true);
      try {
        const report = await runCloudSync(userId, setCloudProgress);
        setLibraryDevices(report.devices);
        setWaitingForAccess(report.waitingForAccess);
        if (report.stoppedBy) setNotice({ tone: "error", text: report.stoppedBy });
        else if (manual) {
          setNotice({
            tone: "success",
            text: `Backup up to date${report.uploaded ? ` · ${report.uploaded} file${report.uploaded === 1 ? "" : "s"} uploaded` : ""}${report.deleted ? ` · ${report.deleted} removed from the cloud` : ""}.`,
          });
        }
      } catch (error) {
        if (manual) setNotice({ tone: "error", text: describeCloudError(error) });
      } finally {
        syncRunning.current = false;
        setCloudSyncing(false);
        setCloudProgress(null);
        await refresh();
      }
    },
    [refresh, userId],
  );

  // Automatic sync: only when backup is on (or deletions are owed), only when
  // there is work, and never in a tight loop — the same outstanding work is
  // retried after 10 minutes, or as soon as the device comes back online.
  const lastAttempt = useRef<{ signature: string; at: number } | null>(null);
  const cloudWork = cloud
    ? (cloud.enabled && (cloud.pendingUploads > 0 || !cloud.indexCurrent)) || cloud.pendingDeletes > 0
    : false;
  const workSignature = cloud ? `${cloud.enabled}|${cloud.pendingUploads}|${cloud.pendingDeletes}|${cloud.indexCurrent}` : "";
  useEffect(() => {
    if (!cloudWork || busy || cloudSyncing || status?.state !== "ready") return;
    const previous = lastAttempt.current;
    if (previous && previous.signature === workSignature && Date.now() - previous.at < 10 * 60 * 1000) return;
    const timer = window.setTimeout(() => {
      lastAttempt.current = { signature: workSignature, at: Date.now() };
      void runSync(false);
    }, 2500);
    return () => window.clearTimeout(timer);
  }, [cloudWork, workSignature, busy, cloudSyncing, status?.state, runSync]);
  // Once per opening of the vault: receive the library key and other devices'
  // changes, even when this device has nothing of its own to upload.
  const checkedOnOpen = useRef(false);
  useEffect(() => {
    if (checkedOnOpen.current || status?.state !== "ready" || busy) return;
    checkedOnOpen.current = true;
    // Not cancelled on re-render: this must run once; runSync is single-flight.
    window.setTimeout(() => void runSync(false), 1500);
  }, [status?.state, busy, runSync]);
  // Once per opening: copies made only for shares that have since ended
  // (revoked, expired, declined) are taken back — with backup off they are
  // nobody's backup. The deletion itself runs with the next sync.
  const releasedOnOpen = useRef(false);
  useEffect(() => {
    if (releasedOnOpen.current || status?.state !== "ready" || !entries.some((entry) => entry.cloudSharedOnly)) return;
    releasedOnOpen.current = true;
    void releaseUnusedShareCopies(userId, entries)
      .then((released) => (released > 0 ? refresh() : undefined))
      .catch(() => undefined);
  }, [status?.state, entries, userId, refresh]);

  useEffect(() => {
    const retry = () => {
      lastAttempt.current = null;
      void refresh();
    };
    window.addEventListener("online", retry);
    const interval = window.setInterval(retry, 10 * 60 * 1000);
    return () => {
      window.removeEventListener("online", retry);
      window.clearInterval(interval);
    };
  }, [refresh]);

  const restoreMissing = useCallback(async () => {
    const outcome = await runOperation("Restoring from your cloud backup", "Downloading, checking each part, verifying each file", () =>
      downloadCloudOnlyFiles(userId, entries, (progress) => setOperation((current) => (current ? { ...current, detail: progress.label } : current))),
    );
    if (outcome) {
      setNotice({
        tone: outcome.failed.length ? "info" : "success",
        text: `${outcome.restored} file${outcome.restored === 1 ? "" : "s"} restored and verified.${outcome.failed.length ? ` ${outcome.failed.join("; ")}` : ""}`,
      });
    }
  }, [entries, runOperation, userId]);

  // ---- what is listed ---------------------------------------------------

  const listed = useMemo<StoreEntry[]>(() => {
    if (section === "trash") return sortEntries(trashRoots(entries), "date", "desc");
    const categories = SECTION_CATEGORIES[section];
    if (categories) return sortEntries(live.filter((e) => matchesFilter(e, { query, categories })), sortKey, sortDirection);
    if (section === "favorites") return sortEntries(live.filter((e) => matchesFilter(e, { query, favoritesOnly: true })), sortKey, sortDirection);
    if (browsing) {
      // A space whose folder does not exist yet holds nothing.
      if (spaceName && !spaceRoot) return [];
      let pool: StoreEntry[];
      if (!query.trim()) pool = childrenOf(live, currentFolder);
      else if (spaceRoot) pool = live.filter((e) => e.id !== spaceRoot.id && breadcrumb(index, e.parentId).some((folder) => folder.id === spaceRoot.id));
      else pool = live;
      return sortEntries(pool.filter((e) => matchesFilter(e, { query })), sortKey, sortDirection);
    }
    return [];
  }, [section, entries, live, query, browsing, spaceName, spaceRoot, currentFolder, index, sortKey, sortDirection]);

  const selectedEntries = useMemo(() => listed.filter((e) => selected.has(e.id)), [listed, selected]);
  const single = selectedEntries.length === 1 ? selectedEntries[0] : null;
  const showLocation = !browsing || query.trim().length > 0;
  // The space's own folder is the root of its path, so it is not repeated.
  const crumbs = useMemo(
    () => breadcrumb(index, currentFolder).filter((folder) => folder.id !== spaceRoot?.id),
    [index, currentFolder, spaceRoot],
  );

  const toggleSelect = (id: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const locationOf = (entry: StoreEntry) => {
    const chain = breadcrumb(index, entry.parentId);
    return chain.length ? chain.map((e) => e.name).join(" / ") : "My Files";
  };

  // ---- render -------------------------------------------------------------

  if (!status) {
    return (
      <div className="shell-card flex min-h-64 flex-col items-center justify-center gap-3 p-8 text-sm text-ink-600">
        {loadError ? (
          <>
            <AlertTriangle className="text-rose-500" size={28} />
            <p className="max-w-md text-center">{loadError}</p>
            <ToolbarButton onClick={() => void refresh()}>
              <RefreshCw size={14} /> Try again
            </ToolbarButton>
          </>
        ) : (
          <>
            <Loader2 className="animate-spin text-cyan-600" size={28} />
            Opening your encrypted vault index…
          </>
        )}
      </div>
    );
  }

  const ready = status.state === "ready";
  const listingSection = browsing || section === "media" || section === "documents" || section === "favorites" || section === "trash";
  const mediaGrid = section === "media";

  // Shared stays visible while a file is waiting for an answer, even when only
  // the first six cards are shown, so a waiting file is never hidden.
  const visibleCards = cardPrefs.showAll
    ? SECTION_CARDS
    : SECTION_CARDS.filter((card, position) => position < DEFAULT_VISIBLE_CARDS || (card.id === "shared" && sharedFilesWaiting > 0));

  /** Open a section; My Files and the spaces always open at their top folder. */
  const goToSection = (id: Section) => {
    setSection(id);
    setQuery("");
    if (id === "files" || SPACE_FOLDERS[id]) setFolderId(null);
  };

  /** The item count on a section's card, from the core's status; null = no count. */
  const sectionCount = (id: Section): number | null => {
    if (id === "trash") return status.trashed;
    if (id === "favorites") return status.favorites;
    if (id === "media") return status.categories.image.files + status.categories.video.files;
    if (id === "documents") return status.categories.document.files;
    if (id === "shared") return sharedFilesWaiting || null;
    return spaceFiles[id] ?? null;
  };

  /** A photo or video's sealed thumbnail, else the type icon, filling its box. */
  const entryVisual = (entry: StoreEntry, iconSize: number) =>
    entry.kind === "file" && (entry.category === "image" || entry.category === "video") && section !== "trash" ? (
      <EntryThumbnail entry={entry} maxPreviewBytes={maxPreviewBytes} onThumbnailSaved={markThumbnail} />
    ) : (
      <div className="flex h-full w-full items-center justify-center">
        <EntryIcon entry={entry} size={iconSize} />
      </div>
    );

  /** Size for a file; file count and total size for a folder. */
  const sizeText = (entry: StoreEntry) => {
    if (entry.kind !== "folder") return formatBytes(entry.sizeBytes);
    const totals = folderTotals(entries, entry.id);
    return `${totals.files} file${totals.files === 1 ? "" : "s"} · ${formatBytes(totals.bytes)}`;
  };

  const whenText = (entry: StoreEntry) => formatWhen(section === "trash" ? entry.trashedAt : entry.updatedAt);

  const selectBox = (entry: StoreEntry) => (
    <input
      type="checkbox"
      checked={selected.has(entry.id)}
      onChange={() => toggleSelect(entry.id)}
      aria-label={`Select ${entry.name}`}
      className="h-4 w-4 shrink-0 accent-cyan-600"
    />
  );

  /** Click opens (or selects, in Trash); the same on every layout. */
  const openOrSelect = (entry: StoreEntry) => (section === "trash" ? toggleSelect(entry.id) : openEntry(entry));

  return (
    <div className="relative grid grid-cols-1 gap-4">
      {/* Section cards, styled like the Home dashboard's area cards. Six show
          by default; "Show all" reveals the rest and Collapse hides them all. */}
      <nav aria-label="Quantum Vault sections" className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => goToSection("overview")}
            aria-current={section === "overview" ? "page" : undefined}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold transition ${
              section === "overview" ? "bg-cyan-600 text-white shadow-tight" : "border border-line bg-white text-ink-700 hover:bg-canvas"
            }`}
          >
            <LayoutDashboard size={15} /> Overview
          </button>
          {section !== "overview" && (
            <span className="flex min-w-0 items-center gap-1 text-sm text-ink-600">
              <ChevronRight size={14} className="shrink-0 text-ink-400" />
              <span className="truncate font-semibold text-ink-900">{SECTION_CARDS.find((card) => card.id === section)?.label}</span>
            </span>
          )}
          <button
            type="button"
            onClick={() => setCardPrefs((current) => ({ ...current, collapsed: !current.collapsed }))}
            aria-expanded={!cardPrefs.collapsed}
            aria-controls="vault-section-cards"
            className="ml-auto flex items-center gap-1 rounded-lg border border-line bg-white px-2.5 py-1.5 text-xs font-semibold text-ink-700 hover:bg-canvas"
          >
            {cardPrefs.collapsed ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
            {cardPrefs.collapsed ? "Show sections" : "Collapse"}
          </button>
        </div>

        {!cardPrefs.collapsed && (
          <>
            <div id="vault-section-cards" className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
              {visibleCards.map(({ id, label, caption, Icon }, position) => {
                const active = section === id;
                const count = sectionCount(id);
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => goToSection(id)}
                    aria-current={active ? "page" : undefined}
                    aria-label={`${label}${count ? `, ${count} item${count === 1 ? "" : "s"}` : ""}`}
                    className="qg-card qg-card-press qg-focusable qg-rise flex min-h-[112px] flex-col items-start justify-between gap-3 p-3.5 text-left"
                    // An outline, not a ring: .qg-card's own box-shadow would hide a ring.
                    style={{
                      ["--qg-i" as string]: position,
                      ...(active ? { outline: "2px solid var(--qg-helix)", outlineOffset: "-1px" } : {}),
                    }}
                  >
                    <span className="flex w-full items-start justify-between gap-2">
                      <span className="qg-tile-chip" style={{ color: "var(--qg-helix)" }}>
                        <Icon size={18} />
                      </span>
                      {count ? (
                        <span
                          className="qg-mono flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[10px] font-bold text-white"
                          style={{ background: "var(--qg-helix)" }}
                        >
                          {count > 99 ? "99+" : count}
                        </span>
                      ) : null}
                    </span>
                    <span className="min-w-0 self-stretch">
                      <span className="qg-display block truncate text-[15px] leading-tight">{label}</span>
                      <span className="mt-1 block text-[11.5px] leading-snug" style={{ color: "var(--qg-text-3)" }}>
                        {caption}
                      </span>
                    </span>
                  </button>
                );
              })}
            </div>
            <div className="mt-2 flex justify-center">
              <button
                type="button"
                onClick={() => setCardPrefs((current) => ({ ...current, showAll: !current.showAll }))}
                aria-expanded={cardPrefs.showAll}
                aria-controls="vault-section-cards"
                className="flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold text-cyan-600 hover:bg-canvas"
              >
                {cardPrefs.showAll ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                {cardPrefs.showAll ? "Show fewer" : `Show all ${SECTION_CARDS.length} (${SECTION_CARDS.length - DEFAULT_VISIBLE_CARDS} more)`}
              </button>
            </div>
          </>
        )}
      </nav>

      <div className="min-w-0 space-y-4">
        {/* Live progress — every value from the Rust stream. */}
        {operation && (
          <div className="shell-card p-4" role="status" aria-live="polite">
            <div className="flex items-center justify-between gap-3 text-sm">
              <span className="flex min-w-0 items-center gap-2 font-bold text-ink-950">
                <Loader2 className="shrink-0 animate-spin text-cyan-600" size={16} />
                <span className="truncate">{operation.title}</span>
              </span>
              <span className="font-mono text-xs text-ink-600">{operation.progress && operation.progress.totalBytes > 0 ? `${progressPercent(operation.progress)}%` : ""}</span>
            </div>
            {operation.detail && <p className="mt-1 truncate text-xs text-ink-600">{operation.detail}</p>}
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-canvas">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-600 transition-[width] duration-200"
                style={{ width: `${operation.progress && operation.progress.totalBytes > 0 ? progressPercent(operation.progress) : 4}%` }}
              />
            </div>
            {operation.progress && (
              <p className="mt-1.5 truncate font-mono text-[11px] text-ink-500">
                {opLabel(operation.progress.op)} · {phaseLabel(operation.progress.phase)}
                {operation.progress.totalBytes > 0 && ` · ${formatBytes(operation.progress.processedBytes)} / ${formatBytes(operation.progress.totalBytes)}`}
              </p>
            )}
          </div>
        )}

        {sharedFilesWaiting > 0 && section !== "shared" && (
          <button
            type="button"
            onClick={() => goToSection("shared")}
            className="flex w-full items-center gap-3 rounded-xl border border-line bg-cyan-50 p-3 text-left text-sm text-ink-800"
          >
            <Share2 className="shrink-0 text-cyan-600" size={18} />
            <span className="min-w-0 flex-1">
              <span className="font-semibold">
                {sharedFilesWaiting} file{sharedFilesWaiting === 1 ? " was" : "s were"} shared with you
              </span>{" "}
              and {sharedFilesWaiting === 1 ? "is" : "are"} waiting for you to accept or decline.
            </span>
            <span className="shrink-0 text-xs font-bold text-cyan-600">Review</span>
          </button>
        )}

        {notice && (
          <div
            className={`flex items-start gap-3 rounded-xl border p-3 text-sm ${
              notice.tone === "error" ? "border-line bg-rose-50 text-ink-800" : notice.tone === "success" ? "border-line bg-emerald-50 text-ink-800" : "border-line bg-cyan-50 text-ink-800"
            }`}
            role={notice.tone === "error" ? "alert" : "status"}
          >
            {notice.tone === "error" ? <AlertTriangle className="mt-0.5 shrink-0 text-rose-500" size={16} /> : <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={16} />}
            <span className="min-w-0 flex-1 break-words">{notice.text}</span>
            <button type="button" onClick={() => setNotice(null)} className="text-ink-500" aria-label="Dismiss">
              <X size={14} />
            </button>
          </div>
        )}

        {!ready && section !== "security" && (
          <div className="flex items-start gap-3 rounded-xl border border-line bg-amber-50 p-4 text-sm text-ink-800">
            <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={18} />
            <span>
              This vault storage was sealed by your previous vault key and cannot be opened with the current one. Nothing was changed.{" "}
              <button type="button" className="font-semibold text-cyan-600 underline" onClick={() => setSection("security")}>
                See your options
              </button>
            </span>
          </div>
        )}

        {section === "overview" && ready && <StorageOverview status={status} cloud={cloud} onImport={() => void pickFiles()} onOpenSection={setSection} />}

        {section === "security" && (
          <StorageSecurity
            status={status}
            busy={busy}
            onVerifyAll={() => void verifyAll()}
            onStartFresh={() => void startFresh()}
            onOpenRecovery={onOpenRecovery}
            lockPanel={
              vaultLock ? (
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <PatternUnlockCard controls={vaultLock} onNotice={(tone, text) => setNotice({ tone, text })} />
                  <HiddenVaultCard controls={vaultLock} onNotice={(tone, text) => setNotice({ tone, text })} />
                </div>
              ) : null
            }
            cloudPanel={
              ready ? (
                <CloudBackupPanel
                  userId={userId}
                  cloud={cloud}
                  syncing={cloudSyncing}
                  syncProgress={cloudProgress}
                  busy={busy}
                  onSyncNow={() => void runSync(true)}
                  onRestoreMissing={() => void restoreMissing()}
                  onChanged={refresh}
                  onOpenRecovery={onOpenRecovery}
                  onNotice={(tone, text) => setNotice({ tone, text })}
                  devices={libraryDevices}
                  waitingForAccess={waitingForAccess}
                  onJoined={() => runSync(false)}
                />
              ) : null
            }
          />
        )}

        {section === "shared" && ready && (
          <SharedFiles
            userId={userId}
            deviceId={deviceId}
            entries={entries}
            maxPreviewBytes={maxPreviewBytes}
            currentFolder={folderId}
            onNotice={(tone, text) => setNotice({ tone, text })}
            onChanged={refresh}
          />
        )}

        {section === "activity" && (
          <section className="shell-card p-4">
            <h3 className="text-sm font-bold text-ink-950">Vault activity</h3>
            <p className="text-xs text-ink-500">Kept inside your encrypted vault index on this device (latest 500).</p>
            <div className="mt-2">
              {activity === null ? (
                <div className="flex items-center gap-2 py-6 text-sm text-ink-600">
                  <Loader2 className="animate-spin" size={16} /> Loading…
                </div>
              ) : (
                <ActivityList activity={activity} empty="No vault activity yet." />
              )}
            </div>
          </section>
        )}

        {listingSection && ready && (
          <section className="shell-card min-w-0 p-4">
            {/* Toolbar */}
            <div className="flex flex-wrap items-center gap-2">
              {section !== "trash" ? (
                <>
                  <ToolbarButton primary disabled={busy} onClick={() => void pickFiles()}>
                    <Upload size={15} /> Add files
                  </ToolbarButton>
                  {!IS_ANDROID && (
                    <ToolbarButton disabled={busy} onClick={() => void pickFolder()} title="Encrypt a whole folder, keeping its structure">
                      <FolderInput size={15} /> Add folder
                    </ToolbarButton>
                  )}
                  {browsing && !query && (
                    <ToolbarButton disabled={busy} onClick={() => setNameDialog({ mode: "new-folder" })}>
                      <FolderPlus size={15} /> New folder
                    </ToolbarButton>
                  )}
                </>
              ) : (
                <ToolbarButton disabled={busy || listed.length === 0} onClick={() => void purgeEntries("all")}>
                  <Trash2 size={15} className="text-rose-500" /> Empty Trash
                </ToolbarButton>
              )}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {section !== "trash" && (
                  <label className="relative flex items-center">
                    <Search className="pointer-events-none absolute left-2.5 text-ink-400" size={14} />
                    <input
                      value={query}
                      onChange={(event) => setQuery(event.target.value)}
                      placeholder={section === "files" ? "Search the whole vault" : spaceName ? `Search ${spaceName}` : "Search"}
                      aria-label="Search vault"
                      className="w-44 rounded-lg border border-line bg-white py-2 pl-8 pr-2 text-sm text-ink-950 outline-none focus:ring-2 focus:ring-cyan-500/40 sm:w-56"
                    />
                  </label>
                )}
                {section !== "trash" && (
                  <label className="flex items-center gap-1 rounded-lg border border-line bg-white px-2 py-1.5 text-sm text-ink-700">
                    <ArrowUpDown size={14} />
                    <select
                      aria-label="Sort by"
                      value={`${sortKey}:${sortDirection}`}
                      onChange={(event) => {
                        const [key, direction] = event.target.value.split(":") as [SortKey, SortDirection];
                        setSortKey(key);
                        setSortDirection(direction);
                      }}
                      className="bg-transparent text-sm outline-none"
                    >
                      <option value="name:asc">Name A–Z</option>
                      <option value="name:desc">Name Z–A</option>
                      <option value="date:desc">Newest</option>
                      <option value="date:asc">Oldest</option>
                      <option value="size:desc">Largest</option>
                      <option value="size:asc">Smallest</option>
                      <option value="type:asc">Type</option>
                    </select>
                  </label>
                )}
                <div className="flex rounded-lg border border-line bg-white p-0.5" role="group" aria-label="View">
                  {VIEW_MODES.map(({ mode, label, Icon }) => (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={viewMode === mode}
                      onClick={() => setViewMode(mode)}
                      className={`rounded-md p-1.5 ${viewMode === mode ? "bg-canvas text-cyan-600" : "text-ink-500"}`}
                      aria-label={`${label} view`}
                      title={label}
                    >
                      <Icon size={15} />
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Breadcrumb */}
            {browsing && !query && (
              <nav aria-label="Folder path" className="mt-3 flex flex-wrap items-center gap-1 text-sm">
                <button type="button" onClick={() => setFolderId(null)} className={`rounded px-1.5 py-0.5 font-semibold ${folderId ? "text-cyan-600 hover:underline" : "text-ink-950"}`}>
                  {spaceName ?? "My Files"}
                </button>
                {crumbs.map((crumb, position) => (
                  <span key={crumb.id} className="flex items-center gap-1">
                    <ChevronRight className="text-ink-400" size={14} />
                    <button
                      type="button"
                      onClick={() => setFolderId(crumb.id)}
                      className={`max-w-48 truncate rounded px-1.5 py-0.5 font-semibold ${position === crumbs.length - 1 ? "text-ink-950" : "text-cyan-600 hover:underline"}`}
                    >
                      {crumb.name}
                    </button>
                  </span>
                ))}
              </nav>
            )}

            {/* Selection actions */}
            {selectedEntries.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-canvas p-2 text-sm">
                <span className="px-1 font-semibold text-ink-800">{selectedEntries.length} selected</span>
                {section === "trash" ? (
                  <>
                    <ToolbarButton disabled={busy} onClick={() => void restoreEntries(selectedEntries)}>
                      <RotateCcw size={14} /> Restore
                    </ToolbarButton>
                    <ToolbarButton disabled={busy} onClick={() => void purgeEntries(selectedEntries)}>
                      <Trash2 size={14} className="text-rose-500" /> Delete permanently
                    </ToolbarButton>
                  </>
                ) : (
                  <>
                    {single && single.kind === "file" && canPreview(single, maxPreviewBytes) && (
                      <ToolbarButton disabled={busy} onClick={() => openEntry(single)}>
                        {single.availableOffline ? <Eye size={14} /> : <CloudDownload size={14} />} Preview
                      </ToolbarButton>
                    )}
                    {single && single.kind === "file" && (
                      <ToolbarButton disabled={busy} onClick={() => setSharing(single)}>
                        <Share2 size={14} /> Share
                      </ToolbarButton>
                    )}
                    {single && (
                      <ToolbarButton disabled={busy} onClick={() => void exportEntry(single)}>
                        <Download size={14} /> Export
                      </ToolbarButton>
                    )}
                    {single && (
                      <ToolbarButton disabled={busy} onClick={() => setNameDialog({ mode: "rename", entry: single })}>
                        <Pencil size={14} /> Rename
                      </ToolbarButton>
                    )}
                    <ToolbarButton disabled={busy} onClick={() => setMoving(selectedEntries)}>
                      <FolderInput size={14} /> Move
                    </ToolbarButton>
                    {(Object.entries(SPACE_FOLDERS) as Array<[Section, string]>)
                      .filter(([space]) => space !== section)
                      .map(([space, name]) => (
                        <ToolbarButton key={space} disabled={busy} onClick={() => void moveToSpace(selectedEntries, space)} title={`Move into your ${name} folder`}>
                          {space === "work" ? <Briefcase size={14} /> : <UserRound size={14} />} To {name}
                        </ToolbarButton>
                      ))}
                    {single && (
                      <ToolbarButton disabled={busy} onClick={() => void toggleFavorite(single)}>
                        <Star size={14} className={single.favorite ? "text-amber-500" : ""} /> {single.favorite ? "Unfavorite" : "Favorite"}
                      </ToolbarButton>
                    )}
                    {single && single.kind === "file" && (
                      <ToolbarButton disabled={busy} onClick={() => void verifyEntry(single)}>
                        <ShieldCheck size={14} /> Verify
                      </ToolbarButton>
                    )}
                    <ToolbarButton disabled={busy} onClick={() => void trashEntries(selectedEntries)}>
                      <Trash2 size={14} className="text-rose-500" /> Trash
                    </ToolbarButton>
                  </>
                )}
                <button type="button" onClick={() => setSelected(new Set())} className="ml-auto rounded p-1 text-ink-500" aria-label="Clear selection">
                  <X size={14} />
                </button>
              </div>
            )}

            {/* Listing */}
            <div
              className="mt-3"
              onKeyDown={(event) => {
                if (event.key === "Delete" && selectedEntries.length > 0 && section !== "trash" && !busy) void trashEntries(selectedEntries);
              }}
            >
              {listed.length === 0 ? (
                <div className="rounded-xl border border-dashed border-line px-6 py-12 text-center text-sm text-ink-600">
                  {section === "trash"
                    ? "Trash is empty."
                    : query
                      ? `Nothing matches "${query}".`
                      : spaceName && !folderId
                        ? `Nothing in ${spaceName} yet. ${IS_ANDROID ? "Tap Add files" : "Add files, drag them here,"} or select files elsewhere and choose "To ${spaceName}". ${spaceName} is a folder at the top of My Files, encrypted like everything else.`
                        : browsing
                        ? IS_ANDROID
                          ? "This folder is empty. Tap Add files to encrypt files into it."
                          : "This folder is empty. Add files, or drag them onto this window."
                        : section === "favorites"
                          ? "Star files to keep them here."
                          : "No files of this kind in your vault yet."}
                </div>
              ) : viewMode === "grid" ? (
                <ul className={`grid gap-3 ${mediaGrid ? "grid-cols-2 sm:grid-cols-3 xl:grid-cols-5" : "grid-cols-2 sm:grid-cols-3 xl:grid-cols-4"}`}>
                  {listed.map((entry) => {
                    const isSelected = selected.has(entry.id);
                    const totals = entry.kind === "folder" ? folderTotals(entries, entry.id) : null;
                    return (
                      <li key={entry.id}>
                        <div
                          className={`group relative overflow-hidden rounded-xl border bg-white transition ${isSelected ? "border-cyan-500 ring-2 ring-cyan-500/40" : "border-line hover:shadow-tight"}`}
                        >
                          <button
                            type="button"
                            onClick={() => (section === "trash" ? toggleSelect(entry.id) : openEntry(entry))}
                            onDoubleClick={() => section !== "trash" && openEntry(entry)}
                            className="block w-full text-left"
                            aria-label={`${entry.kind === "folder" ? "Open folder" : "Open"} ${entry.name}`}
                          >
                            <div className={`overflow-hidden bg-canvas ${mediaGrid ? "aspect-square" : "aspect-[4/3]"}`}>
                              {entry.kind === "file" && (entry.category === "image" || entry.category === "video") && section !== "trash" ? (
                                <EntryThumbnail entry={entry} maxPreviewBytes={maxPreviewBytes} onThumbnailSaved={markThumbnail} />
                              ) : (
                                <div className="flex h-full w-full items-center justify-center">
                                  <EntryIcon entry={entry} size={34} />
                                </div>
                              )}
                            </div>
                            <div className="flex items-start gap-1.5 p-2.5">
                              <div className="min-w-0 flex-1">
                                <div className="truncate text-sm font-semibold text-ink-950" title={entry.name}>
                                  {entry.name}
                                </div>
                                <div className="truncate text-[11px] text-ink-500">
                                  {totals ? `${totals.files} file${totals.files === 1 ? "" : "s"} · ${formatBytes(totals.bytes)}` : `${formatBytes(entry.sizeBytes)} · ${formatWhen(entry.updatedAt)}`}
                                </div>
                                {showLocation && <div className="truncate text-[11px] text-ink-400">{locationOf(entry)}</div>}
                              </div>
                              {entry.favorite && <Star className="shrink-0 text-amber-500" size={13} />}
                              <IntegrityBadge entry={entry} />
                            </div>
                          </button>
                          <label className={`absolute left-2 top-2 flex h-6 w-6 items-center justify-center rounded-md bg-white/90 shadow-tight transition ${isSelected ? "opacity-100" : "opacity-100 sm:opacity-0 sm:group-hover:opacity-100"}`}>
                            <input type="checkbox" checked={isSelected} onChange={() => toggleSelect(entry.id)} aria-label={`Select ${entry.name}`} className="h-4 w-4 accent-cyan-600" />
                          </label>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : viewMode === "tiles" ? (
                // Tiles: a compact card per item — preview, name, type and size.
                <ul className="grid grid-cols-1 gap-2 min-[480px]:grid-cols-2 xl:grid-cols-3">
                  {listed.map((entry) => {
                    const isSelected = selected.has(entry.id);
                    return (
                      <li key={entry.id} className="min-w-0">
                        <div
                          className={`flex min-w-0 items-center gap-2.5 rounded-xl border bg-white p-2.5 transition ${isSelected ? "border-cyan-500 ring-2 ring-cyan-500/40" : "border-line hover:shadow-tight"}`}
                        >
                          {selectBox(entry)}
                          <button
                            type="button"
                            onClick={() => openOrSelect(entry)}
                            className="flex min-w-0 flex-1 items-center gap-3 text-left"
                            aria-label={`${entry.kind === "folder" ? "Open folder" : "Open"} ${entry.name}`}
                          >
                            <div className="h-12 w-12 shrink-0 overflow-hidden rounded-lg bg-canvas">{entryVisual(entry, 24)}</div>
                            <div className="min-w-0 flex-1">
                              <div className="truncate text-sm font-semibold text-ink-950" title={entry.name}>
                                {entry.name}
                              </div>
                              <div className="truncate text-[11px] text-ink-500">{typeLabel(entry)}</div>
                              <div className="truncate text-[11px] text-ink-500">{sizeText(entry)}</div>
                            </div>
                          </button>
                          <div className="flex shrink-0 items-center gap-1">
                            {entry.favorite && <Star className="shrink-0 text-amber-500" size={13} />}
                            <IntegrityBadge entry={entry} />
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : viewMode === "content" ? (
                // Content: one panel per row with a larger preview and the details beside it.
                <ul className="space-y-2">
                  {listed.map((entry) => {
                    const isSelected = selected.has(entry.id);
                    return (
                      <li key={entry.id}>
                        <div
                          className={`flex min-w-0 items-center gap-3 rounded-xl border bg-white p-3 transition ${isSelected ? "border-cyan-500 ring-2 ring-cyan-500/40" : "border-line hover:shadow-tight"}`}
                        >
                          {selectBox(entry)}
                          <button
                            type="button"
                            onClick={() => openOrSelect(entry)}
                            className="flex min-w-0 flex-1 items-center gap-3 text-left"
                            aria-label={`${entry.kind === "folder" ? "Open folder" : "Open"} ${entry.name}`}
                          >
                            <div className="h-14 w-14 shrink-0 overflow-hidden rounded-lg bg-canvas">{entryVisual(entry, 28)}</div>
                            <div className="min-w-0 flex-1">
                              <div className="flex min-w-0 items-center gap-1.5">
                                <span className="truncate text-sm font-semibold text-ink-950" title={entry.name}>
                                  {entry.name}
                                </span>
                                {entry.favorite && <Star className="shrink-0 text-amber-500" size={13} />}
                              </div>
                              <div className="truncate text-xs text-ink-500">
                                {typeLabel(entry)}
                                {showLocation && ` · ${locationOf(entry)}`}
                              </div>
                              {/* On a phone the size and date go under the name instead of a side column. */}
                              <div className="truncate text-[11px] text-ink-500 sm:hidden">
                                {sizeText(entry)} · {whenText(entry)}
                              </div>
                            </div>
                            <div className="hidden shrink-0 text-right text-xs sm:block">
                              <div className="font-semibold text-ink-800">{sizeText(entry)}</div>
                              <div className="text-ink-500">
                                {section === "trash" ? "Deleted" : "Modified"} {whenText(entry)}
                              </div>
                            </div>
                          </button>
                          {/* Reserved even for folders (no badge) so the size column lines up. */}
                          <div className="flex min-w-[14px] shrink-0 items-center justify-end gap-1">
                            <IntegrityBadge entry={entry} />
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-sm">
                    <thead>
                      <tr className="border-b border-line text-left text-xs font-semibold text-ink-500">
                        <th className="w-8 py-2 pl-2" />
                        <th className="py-2">Name</th>
                        {showLocation && <th className="py-2">Location</th>}
                        <th className="py-2 text-right">Size</th>
                        <th className="py-2 pl-4">{section === "trash" ? "Deleted" : "Modified"}</th>
                        <th className="py-2 pr-2 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {listed.map((entry) => {
                        const isSelected = selected.has(entry.id);
                        const totals = entry.kind === "folder" ? folderTotals(entries, entry.id) : null;
                        return (
                          <tr key={entry.id} className={`border-b border-line last:border-0 ${isSelected ? "bg-cyan-50" : "hover:bg-canvas"}`}>
                            <td className="py-2 pl-2">
                              <input type="checkbox" checked={isSelected} onChange={() => toggleSelect(entry.id)} aria-label={`Select ${entry.name}`} className="h-4 w-4 accent-cyan-600" />
                            </td>
                            <td className="max-w-0 py-2">
                              <button type="button" onClick={() => (section === "trash" ? toggleSelect(entry.id) : openEntry(entry))} className="flex w-full min-w-0 items-center gap-2 text-left">
                                <EntryIcon entry={entry} />
                                <span className="truncate font-semibold text-ink-950">{entry.name}</span>
                                {entry.favorite && <Star className="shrink-0 text-amber-500" size={12} />}
                              </button>
                            </td>
                            {showLocation && <td className="max-w-40 truncate py-2 text-xs text-ink-500">{locationOf(entry)}</td>}
                            <td className="whitespace-nowrap py-2 text-right text-ink-700">{totals ? `${totals.files} files` : formatBytes(entry.sizeBytes)}</td>
                            <td className="whitespace-nowrap py-2 pl-4 text-xs text-ink-500">{formatWhen(section === "trash" ? entry.trashedAt : entry.updatedAt)}</td>
                            <td className="py-2 pr-2">
                              <div className="flex justify-end">
                                <IntegrityBadge entry={entry} />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Properties of the single selected file */}
            {single && single.kind === "file" && (
              <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1.5 rounded-xl border border-line bg-canvas p-4 text-xs sm:grid-cols-2">
                {[
                  ["Name", single.name],
                  ["Location", locationOf(single)],
                  ["Type", `${single.contentType}${single.typeCheck === "mismatch" ? " — does not match its extension" : ""}`],
                  ["Size", `${formatBytes(single.sizeBytes)} (${formatBytes(single.storedBytes)} encrypted, ${single.totalChunks} chunk${single.totalChunks === 1 ? "" : "s"})`],
                  ["Added", formatWhen(single.createdAt)],
                  ["Modified", formatWhen(single.updatedAt)],
                  ["Protection", `v${single.containerVersion} container · ${single.pinBound ? "PIN-bound vault key" : "device-bound (legacy)"} · Ed25519 + ML-DSA-87`],
                  ["Recovery", single.recoveryProtected ? "Recoverable with your recovery key" : "No recovery wrap (added before recovery was set up)"],
                  ["Integrity", `${integrityLabel(single)}${single.lastVerifiedAt ? ` · ${formatWhen(single.lastVerifiedAt)}` : ""}`],
                  [
                    "Cloud",
                    !single.cloudObjectId
                      ? cloud?.enabled
                        ? "Waiting to back up"
                        : "Not backed up (backup off)"
                      : single.cloudSharedOnly
                        ? "Not backed up · one encrypted copy is in the cloud for sharing, removed once no share uses it"
                        : single.availableOffline
                          ? `Backed up${single.cloudBackedUpAt ? ` · ${formatWhen(single.cloudBackedUpAt)}` : ""}`
                          : "In your cloud backup only — opening it downloads it to this device",
                  ],
                  ["SHA3-256", single.plaintextSha3 ? `${single.plaintextSha3.slice(0, 16)}…${single.plaintextSha3.slice(-8)}` : "—"],
                ].map(([term, value]) => (
                  <div key={term} className="flex min-w-0 gap-2">
                    <dt className="w-20 shrink-0 font-semibold text-ink-600">{term}</dt>
                    <dd className={`min-w-0 break-words ${term === "SHA3-256" ? "font-mono" : ""} ${term === "Type" && single.typeCheck === "mismatch" ? "text-amber-500" : "text-ink-800"}`}>{value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
        )}
      </div>

      {dragOver && (
        <div className="pointer-events-none fixed inset-0 z-40 flex items-center justify-center bg-ink-950/50 backdrop-blur-sm">
          <div className="rounded-2xl border border-line bg-white px-10 py-8 text-center shadow-soft">
            <Upload className="mx-auto text-cyan-600" size={36} />
            <p className="mt-2 text-base font-bold text-ink-950">Drop to encrypt into {browsing && currentFolder ? index.get(currentFolder)?.name ?? "this folder" : (spaceName ?? "My Files")}</p>
            <p className="text-xs text-ink-500">Files and folders are encrypted on this device before they are stored.</p>
          </div>
        </div>
      )}

      {nameDialog && (
        <NameDialog
          title={nameDialog.mode === "new-folder" ? "New folder" : `Rename "${nameDialog.entry.name}"`}
          label={nameDialog.mode === "new-folder" ? "Folder name" : "New name"}
          initial={nameDialog.mode === "new-folder" ? "New folder" : nameDialog.entry.name}
          confirmLabel={nameDialog.mode === "new-folder" ? "Create" : "Rename"}
          onCancel={() => setNameDialog(null)}
          onConfirm={async (name) => {
            if (nameDialog.mode === "new-folder") await vaultStore.createFolder(await ensureTarget(), name);
            else await vaultStore.rename(nameDialog.entry.id, name);
            setNameDialog(null);
            await refresh();
          }}
        />
      )}

      {moving && (
        <MoveDialog
          entries={entries}
          moving={moving}
          onCancel={() => setMoving(null)}
          onConfirm={async (parentId) => {
            await vaultStore.move(moving.map((e) => e.id), parentId);
            setMoving(null);
            setSelected(new Set());
            setNotice({ tone: "success", text: `Moved ${moving.length === 1 ? `"${moving[0].name}"` : `${moving.length} items`}.` });
            await refresh();
          }}
        />
      )}

      {previewing && (
        <PreviewDialog
          subject={previewing}
          onClose={() => setPreviewing(null)}
          onExport={() => {
            const entry = index.get(previewing.key);
            if (entry) void exportEntry(entry);
          }}
        />
      )}

      {sharing && (
        <ShareDialog
          userId={userId}
          entry={sharing}
          backupOn={cloud?.enabled ?? false}
          onClose={() => setSharing(null)}
          onShared={(text) => {
            setNotice({ tone: "success", text });
            void refresh();
          }}
          onChanged={() => void refresh()}
        />
      )}
    </div>
  );
}
