import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Download,
  Eye,
  EyeOff,
  FolderInput,
  FolderPlus,
  Loader2,
  Lock,
  Pencil,
  ShieldAlert,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isAndroidRuntime } from "@/lib/tauri";
import { ask as askDialog, open as openDialog, save as saveDialog } from "@/lib/tauri-dialog";
import { chooseDestinationFolder, prepareDestination } from "@/lib/vault-destination";
import { hiddenVault, type HiddenSummary } from "@/lib/vault-hidden";
import type { VaultProgress } from "@/lib/vault-progress";
import {
  breadcrumb,
  byId,
  canPreview,
  childrenOf,
  describeStoreError,
  formatBytes,
  progressPercent,
  sortEntries,
  type StoreEntry,
} from "@/lib/vault-store";
import { EntryIcon } from "../storage/EntryVisual";
import { MoveDialog, NameDialog, PreviewDialog, type PreviewSubject } from "../storage/StorageDialogs";
import { formatWhen } from "../storage/StorageOverview";
import { RecoveryPhraseCard } from "./HiddenRecovery";

// The open hidden vault (src-tauri/src/vault/hidden.rs). Opened only by its
// pattern on the vault lock screen; while it is open the Quantum Vault stays
// locked. Every list, name and byte here comes from the core, which decrypts
// them from the hidden vault's own encrypted index and files.

const IS_ANDROID = isAndroidRuntime();
/** The core refuses bigger previews (store::MAX_PREVIEW_BYTES). */
const MAX_PREVIEW_BYTES = 64 * 1024 * 1024;

interface Operation {
  title: string;
  progress: VaultProgress | null;
}

function basename(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

export default function HiddenVaultPage({ onLock }: { onLock: () => void }) {
  const [entries, setEntries] = useState<StoreEntry[] | null>(null);
  const [summary, setSummary] = useState<HiddenSummary | null>(null);
  const [folderId, setFolderId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [operation, setOperation] = useState<Operation | null>(null);
  const [notice, setNotice] = useState<{ tone: "success" | "error" | "info"; text: string } | null>(null);
  const [nameDialog, setNameDialog] = useState<{ mode: "folder" } | { mode: "rename"; entry: StoreEntry } | null>(null);
  const [moving, setMoving] = useState<StoreEntry[] | null>(null);
  const [previewing, setPreviewing] = useState<PreviewSubject | null>(null);
  const [destroying, setDestroying] = useState(false);
  // The parent's callback changes identity every render; refresh must not.
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;

  const refresh = useCallback(async () => {
    try {
      const status = await hiddenVault.status();
      if (!status.open) {
        // Locked underneath us (inactivity, app hidden): back to the lock screen.
        onLockRef.current();
        return;
      }
      if (status.summary) setSummary(status.summary);
      setEntries(await hiddenVault.list());
    } catch (error) {
      setNotice({ tone: "error", text: describeStoreError(error) });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const index = useMemo(() => byId(entries ?? []), [entries]);
  useEffect(() => setSelected(new Set()), [folderId]);
  useEffect(() => {
    if (folderId && entries && !index.has(folderId)) setFolderId(null);
  }, [folderId, index, entries]);

  const listed = useMemo(() => sortEntries(childrenOf(entries ?? [], folderId), "name", "asc"), [entries, folderId]);
  const crumbs = useMemo(() => (folderId ? breadcrumb(index, folderId) : []), [index, folderId]);
  const selectedEntries = useMemo(() => listed.filter((entry) => selected.has(entry.id)), [listed, selected]);
  const single = selectedEntries.length === 1 ? selectedEntries[0] : null;
  const busy = operation !== null;

  const run = useCallback(
    async <T,>(title: string, job: (onProgress: (p: VaultProgress) => void) => Promise<T>): Promise<T | undefined> => {
      setOperation({ title, progress: null });
      setNotice(null);
      try {
        return await job((progress) => setOperation((current) => (current ? { ...current, progress } : current)));
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

  const addFiles = async () => {
    const picked = await openDialog({ multiple: true, directory: false, title: "Add files to this vault" });
    const paths = (picked == null ? [] : Array.isArray(picked) ? picked : [picked]).map(String);
    if (paths.length === 0) return;
    let added = 0;
    const failures: string[] = [];
    await run(`Encrypting ${paths.length} file${paths.length === 1 ? "" : "s"}`, async (onProgress) => {
      for (const path of paths) {
        try {
          await hiddenVault.importFile(path, folderId, onProgress);
          added += 1;
        } catch (error) {
          failures.push(`${IS_ANDROID ? "A file" : basename(path)}: ${describeStoreError(error)}`);
        }
      }
    });
    setNotice({
      tone: failures.length ? (added ? "info" : "error") : "success",
      text: [`${added} file${added === 1 ? "" : "s"} encrypted into this vault`, ...failures.slice(0, 2)].join(" · "),
    });
  };

  const exportEntry = async (entry: StoreEntry) => {
    setPreviewing(null);
    if (entry.kind === "folder") {
      setNotice({ tone: "info", text: "Export files one at a time from a hidden vault." });
      return;
    }
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
    const outcome = await run(`Exporting ${entry.name}`, (onProgress) => hiddenVault.exportFile(entry.id, target, onProgress));
    if (outcome) {
      setNotice({ tone: "success", text: `"${outcome.name}" decrypted and verified. The exported copy is an ordinary, unencrypted file outside the hidden vault — delete it when you are done.` });
    }
  };

  const remove = async (items: StoreEntry[]) => {
    const label = items.length === 1 ? `"${items[0].name}"` : `${items.length} items`;
    const confirmed = await askDialog(`Delete ${label} permanently?\n\nA hidden vault has no Trash. The keys are destroyed first, then the encrypted copy is overwritten — nothing can bring it back.`, {
      title: "Delete permanently",
      okLabel: "Delete",
      cancelLabel: "Cancel",
    }).catch(() => false);
    if (!confirmed) return;
    const removed = await run(`Deleting ${label}`, () => hiddenVault.remove(items.map((entry) => entry.id)));
    if (removed !== undefined) {
      setSelected(new Set());
      setNotice({ tone: "success", text: `${removed} item${removed === 1 ? "" : "s"} deleted permanently.` });
    }
  };

  const openEntry = (entry: StoreEntry) => {
    if (entry.kind === "folder") {
      setFolderId(entry.id);
      return;
    }
    if (canPreview(entry, MAX_PREVIEW_BYTES)) {
      setPreviewing({
        key: entry.id,
        name: entry.name,
        contentType: entry.contentType,
        category: entry.category,
        sizeBytes: entry.sizeBytes,
        load: () => hiddenVault.preview(entry.id),
        verifiedNote: "Decrypted in memory · every chunk and the content hash verified · nothing written to disk",
      });
    } else {
      setSelected(new Set([entry.id]));
      setNotice({ tone: "info", text: "This file type opens after you export it." });
    }
  };

  const toggle = (id: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="grid grid-cols-1 gap-4">
      <section className="shell-card min-w-0 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-violet-600 to-cyan-600 text-white shadow-tight">
              <EyeOff size={20} />
            </span>
            <div className="min-w-0">
              <h1 className="text-lg font-bold text-ink-950">Hidden vault</h1>
              <p className="text-xs text-ink-600">
                {summary ? `${summary.files} file${summary.files === 1 ? "" : "s"} · ${formatBytes(summary.bytes)}` : "Opening…"} · opened by its pattern
                · not listed anywhere
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onLock}
            className="flex items-center gap-2 rounded-lg bg-ink-950 px-4 py-2 text-sm font-bold text-white hover:opacity-90"
          >
            <Lock size={15} /> Lock
          </button>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" disabled={busy} onClick={() => void addFiles()} className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">
            <Upload size={14} /> Add files
          </button>
          <button type="button" disabled={busy} onClick={() => setNameDialog({ mode: "folder" })} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
            <FolderPlus size={14} /> New folder
          </button>
        </div>
      </section>

      {operation && (
        <div className="shell-card min-w-0 p-4" role="status" aria-live="polite">
          <div className="flex items-center justify-between gap-3 text-sm">
            <span className="flex min-w-0 items-center gap-2 font-bold text-ink-950">
              <Loader2 className="shrink-0 animate-spin text-cyan-600" size={16} />
              <span className="truncate">{operation.title}</span>
            </span>
            <span className="font-mono text-xs text-ink-600">{operation.progress && operation.progress.totalBytes > 0 ? `${progressPercent(operation.progress)}%` : ""}</span>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-canvas">
            <div
              className="h-full rounded-full bg-gradient-to-r from-violet-600 to-cyan-500 transition-[width] duration-200"
              style={{ width: `${operation.progress && operation.progress.totalBytes > 0 ? progressPercent(operation.progress) : 4}%` }}
            />
          </div>
        </div>
      )}

      {notice && (
        <div
          className={`flex items-start gap-3 rounded-xl border border-line p-3 text-sm text-ink-800 ${notice.tone === "error" ? "bg-rose-50" : notice.tone === "success" ? "bg-emerald-50" : "bg-cyan-50"}`}
          role={notice.tone === "error" ? "alert" : "status"}
        >
          {notice.tone === "error" ? <AlertTriangle className="mt-0.5 shrink-0 text-rose-500" size={16} /> : <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={16} />}
          <span className="min-w-0 flex-1 break-words">{notice.text}</span>
          <button type="button" onClick={() => setNotice(null)} className="text-ink-500" aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      <section className="shell-card min-w-0 p-4">
        <nav aria-label="Folder path" className="flex flex-wrap items-center gap-1 text-sm">
          <button type="button" onClick={() => setFolderId(null)} className={`rounded px-1.5 py-0.5 font-semibold ${folderId ? "text-cyan-600 hover:underline" : "text-ink-950"}`}>
            Hidden vault
          </button>
          {crumbs.map((crumb, position) => (
            <span key={crumb.id} className="flex min-w-0 items-center gap-1">
              <ChevronRight className="shrink-0 text-ink-400" size={14} />
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

        {selectedEntries.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-canvas p-2 text-sm">
            <span className="px-1 font-semibold text-ink-800">{selectedEntries.length} selected</span>
            {single && single.kind === "file" && canPreview(single, MAX_PREVIEW_BYTES) && (
              <button type="button" disabled={busy} onClick={() => openEntry(single)} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800 disabled:opacity-50">
                <Eye size={14} /> Preview
              </button>
            )}
            {single && single.kind === "file" && (
              <button type="button" disabled={busy} onClick={() => void exportEntry(single)} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800 disabled:opacity-50">
                <Download size={14} /> Export
              </button>
            )}
            {single && (
              <button type="button" disabled={busy} onClick={() => setNameDialog({ mode: "rename", entry: single })} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800 disabled:opacity-50">
                <Pencil size={14} /> Rename
              </button>
            )}
            <button type="button" disabled={busy} onClick={() => setMoving(selectedEntries)} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800 disabled:opacity-50">
              <FolderInput size={14} /> Move
            </button>
            <button type="button" disabled={busy} onClick={() => void remove(selectedEntries)} className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-rose-600 disabled:opacity-50">
              <Trash2 size={14} /> Delete
            </button>
            <button type="button" onClick={() => setSelected(new Set())} className="ml-auto rounded p-1 text-ink-500" aria-label="Clear selection">
              <X size={14} />
            </button>
          </div>
        )}

        <div className="mt-3">
          {entries === null ? (
            <div className="flex items-center gap-2 py-10 text-sm text-ink-600">
              <Loader2 className="animate-spin" size={16} /> Opening the encrypted index…
            </div>
          ) : listed.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line px-6 py-12 text-center text-sm text-ink-600">
              {folderId ? "This folder is empty." : "This vault is empty. Add the files you want to keep out of sight."}
            </div>
          ) : (
            <ul className="divide-y divide-line">
              {listed.map((entry) => (
                <li key={entry.id} className={`flex min-w-0 items-center gap-3 py-2 ${selected.has(entry.id) ? "bg-cyan-50/60" : ""}`}>
                  <input
                    type="checkbox"
                    checked={selected.has(entry.id)}
                    onChange={() => toggle(entry.id)}
                    aria-label={`Select ${entry.name}`}
                    className="ml-1 h-4 w-4 shrink-0 accent-cyan-600"
                  />
                  <button type="button" onClick={() => openEntry(entry)} className="flex min-w-0 flex-1 items-center gap-3 text-left" aria-label={`${entry.kind === "folder" ? "Open folder" : "Open"} ${entry.name}`}>
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-canvas">
                      <EntryIcon entry={entry} size={20} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-semibold text-ink-950" title={entry.name}>
                        {entry.name}
                      </span>
                      <span className="block truncate text-[11px] text-ink-500">
                        {entry.kind === "folder"
                          ? `${childrenOf(entries, entry.id).length} item${childrenOf(entries, entry.id).length === 1 ? "" : "s"}`
                          : `${formatBytes(entry.sizeBytes)} · ${formatWhen(entry.updatedAt)}`}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <RecoveryPhraseCard summary={summary} busy={busy} onChanged={setSummary} onNotice={setNotice} />

      <DuressCard summary={summary} busy={busy} onChanged={setSummary} onNotice={setNotice} />

      <section className="min-w-0 rounded-xl border border-line bg-white p-4 text-[11px] text-ink-600">
        <p>
          Stored only on this device: every file AES-256-GCM encrypted under its own key, kept in this vault's encrypted index, under a
          key made from your pattern and this device's secure key store. No cloud copy. If the pattern is forgotten, only this vault's
          12-word recovery phrase (if you set one up) opens it; without either, these files cannot be opened by anyone, including QGuard.
        </p>
        <button
          type="button"
          disabled={busy}
          onClick={() => setDestroying(true)}
          className="mt-3 flex items-center gap-2 rounded-lg border border-rose-200 px-3 py-1.5 text-xs font-bold text-rose-600 hover:bg-rose-50 disabled:opacity-50"
        >
          <Trash2 size={13} /> Delete this hidden vault
        </button>
      </section>

      {nameDialog && (
        <NameDialog
          title={nameDialog.mode === "folder" ? "New folder" : `Rename "${nameDialog.entry.name}"`}
          label={nameDialog.mode === "folder" ? "Folder name" : "New name"}
          initial={nameDialog.mode === "folder" ? "New folder" : nameDialog.entry.name}
          confirmLabel={nameDialog.mode === "folder" ? "Create" : "Rename"}
          onCancel={() => setNameDialog(null)}
          onConfirm={async (name) => {
            if (nameDialog.mode === "folder") await hiddenVault.createFolder(folderId, name);
            else await hiddenVault.rename(nameDialog.entry.id, name);
            setNameDialog(null);
            await refresh();
          }}
        />
      )}

      {moving && entries && (
        <MoveDialog
          entries={entries}
          moving={moving}
          onCancel={() => setMoving(null)}
          onConfirm={async (parentId) => {
            await hiddenVault.move(moving.map((entry) => entry.id), parentId);
            setMoving(null);
            setSelected(new Set());
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

      {destroying && <DestroyDialog onCancel={() => setDestroying(false)} onDestroyed={onLock} />}
    </div>
  );
}

// Duress erase (vault::hidden): armed, drawing this vault's pattern on the lock
// screen opens it as usual and destroys every other hidden vault in the
// background. The state shown comes from this vault's encrypted index; after
// it fires it reads "off", like a vault that was never armed.
function DuressCard({
  summary,
  busy,
  onChanged,
  onNotice,
}: {
  summary: HiddenSummary | null;
  busy: boolean;
  onChanged: (summary: HiddenSummary) => void;
  onNotice: (notice: { tone: "success" | "error" | "info"; text: string }) => void;
}) {
  const [saving, setSaving] = useState(false);
  const armed = Boolean(summary?.duressErase);

  const change = async (next: boolean) => {
    if (next) {
      const confirmed = await askDialog(
        "Arm duress erase for this vault?\n\nThe next time its pattern is drawn on the vault lock screen, this vault opens as usual and every OTHER hidden vault on this device is destroyed in the background. Nothing asks first, nothing can undo it, and no copy exists anywhere.\n\nTo add files to this vault later without setting it off, open it from Security & Backup inside your Quantum Vault.",
        { title: "Arm duress erase", okLabel: "Arm", cancelLabel: "Cancel" },
      ).catch(() => false);
      if (!confirmed) return;
    }
    setSaving(true);
    try {
      onChanged(await hiddenVault.setDuress(next));
      onNotice({
        tone: "success",
        text: next
          ? "Duress erase armed. Lock this vault now — and draw its pattern on the lock screen only when you mean it."
          : "Duress erase is off for this vault.",
      });
    } catch (error) {
      onNotice({ tone: "error", text: describeStoreError(error) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="min-w-0 rounded-xl border border-line bg-white p-4">
      <h2 className="flex items-center gap-2 text-sm font-bold text-ink-950">
        <ShieldAlert className={armed ? "shrink-0 text-rose-500" : "shrink-0 text-ink-400"} size={16} /> Duress erase
      </h2>
      <p className="mt-2 text-sm text-ink-700">
        {armed
          ? "Armed — the next time this vault's pattern is drawn on the vault lock screen, every other hidden vault on this device is destroyed."
          : "Off. To use this vault as a decoy, fill it with believable, harmless files. Armed, drawing its pattern on the lock screen also destroys every other hidden vault on this device."}
      </p>
      <p className="mt-2 text-[11px] text-ink-500">
        When it fires there is no prompt and no message: this vault opens like any other and from then on shows as off. The other
        vaults' keys are destroyed within moments, the rest of their files over the next few seconds. Your Quantum Vault is never
        touched. Someone examining the device afterwards can still see that files were deleted.
      </p>
      <button
        type="button"
        disabled={busy || saving || !summary}
        onClick={() => void change(!armed)}
        className={`mt-3 flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-bold disabled:opacity-50 ${armed ? "border border-line text-ink-800 hover:bg-canvas" : "border border-rose-200 text-rose-600 hover:bg-rose-50"}`}
      >
        {saving && <Loader2 className="animate-spin" size={13} />} {armed ? "Disarm" : "Arm duress erase"}
      </button>
    </section>
  );
}

function DestroyDialog({ onCancel, onDestroyed }: { onCancel: () => void; onDestroyed: () => void }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Delete this hidden vault">
      <div className="w-full max-w-md rounded-xl border border-line bg-white p-5 shadow-soft">
        <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <AlertTriangle className="text-rose-500" size={16} /> Delete this hidden vault?
        </h3>
        <p className="mt-2 text-sm text-ink-700">
          Every file in it is destroyed: the keys first, then the encrypted copies. There is no copy anywhere else and no way to undo
          this.
        </p>
        <label className="mt-3 block text-xs font-bold text-ink-700">
          Type <span className="font-mono text-rose-600">DELETE</span> to confirm
        </label>
        <input
          value={typed}
          onChange={(event) => setTyped(event.currentTarget.value)}
          placeholder="DELETE"
          className="mt-1.5 w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-rose-300"
        />
        {error && <p className="mt-2 text-xs font-semibold text-rose-600">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas">
            Cancel
          </button>
          <button
            type="button"
            disabled={busy || typed.trim() !== "DELETE"}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await hiddenVault.destroy();
                onDestroyed();
              } catch (err) {
                setError(describeStoreError(err));
                setBusy(false);
              }
            }}
            className="flex items-center gap-2 rounded-lg bg-rose-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-50"
          >
            {busy && <Loader2 className="animate-spin" size={14} />} Delete vault
          </button>
        </div>
      </div>
    </div>
  );
}
