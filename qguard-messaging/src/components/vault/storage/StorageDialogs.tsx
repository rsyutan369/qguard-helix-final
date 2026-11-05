import { Download, Folder, HardDrive, Loader2, ShieldCheck, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  breadcrumb,
  byId,
  describeStoreError,
  formatBytes,
  integrityLabel,
  moveTargets,
  vaultStore,
  type StoreEntry,
} from "@/lib/vault-store";

function DialogShell({ title, onClose, children, wide = false }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={title} onMouseDown={onClose}>
      <div
        className={`flex max-h-[90vh] w-full flex-col overflow-hidden rounded-xl border border-line bg-white shadow-soft ${wide ? "max-w-4xl" : "max-w-md"}`}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h3 className="truncate text-sm font-bold text-ink-950">{title}</h3>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-ink-500 hover:bg-canvas" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function NameDialog({
  title,
  label,
  initial,
  confirmLabel,
  onCancel,
  onConfirm,
}: {
  title: string;
  label: string;
  initial: string;
  confirmLabel: string;
  onCancel: () => void;
  onConfirm: (name: string) => Promise<void>;
}) {
  const [value, setValue] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const input = inputRef.current;
    if (!input) return;
    input.focus();
    // Select the stem so typing replaces the name but keeps the extension.
    const dot = initial.lastIndexOf(".");
    input.setSelectionRange(0, dot > 0 ? dot : initial.length);
  }, [initial]);

  const submit = async () => {
    if (!value.trim()) {
      setError("A name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onConfirm(value.trim());
    } catch (err) {
      setError(describeStoreError(err));
      setBusy(false);
    }
  };

  return (
    <DialogShell title={title} onClose={onCancel}>
      <form
        className="space-y-3 p-5"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <label className="block text-xs font-semibold text-ink-600" htmlFor="vault-name-input">
          {label}
        </label>
        <input
          id="vault-name-input"
          ref={inputRef}
          value={value}
          maxLength={200}
          onChange={(event) => setValue(event.target.value)}
          className="w-full rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-950 outline-none focus:ring-2 focus:ring-cyan-500/40"
        />
        {error && <p className="text-xs font-semibold text-rose-500">{error}</p>}
        <p className="text-[11px] text-ink-500">Names are kept only in your vault's encrypted index — never in the encrypted files on disk.</p>
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={onCancel} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas">
            Cancel
          </button>
          <button type="submit" disabled={busy} className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-60">
            {busy && <Loader2 className="animate-spin" size={14} />} {confirmLabel}
          </button>
        </div>
      </form>
    </DialogShell>
  );
}

export function MoveDialog({
  entries,
  moving,
  onCancel,
  onConfirm,
}: {
  entries: StoreEntry[];
  moving: StoreEntry[];
  onCancel: () => void;
  onConfirm: (parentId: string | null) => Promise<void>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const index = useMemo(() => byId(entries), [entries]);
  const targets = useMemo(() => moveTargets(entries, new Set(moving.map((e) => e.id))), [entries, moving]);

  const choose = async (parentId: string | null) => {
    setBusy(parentId ?? "root");
    setError(null);
    try {
      await onConfirm(parentId);
    } catch (err) {
      setError(describeStoreError(err));
      setBusy(null);
    }
  };

  const row = (key: string, parentId: string | null, label: string, depth: number) => (
    <button
      key={key}
      type="button"
      disabled={busy !== null}
      onClick={() => void choose(parentId)}
      className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm text-ink-800 hover:bg-canvas disabled:opacity-60"
      style={{ paddingLeft: 12 + depth * 16 }}
    >
      {busy === (parentId ?? "root") ? <Loader2 className="animate-spin text-cyan-600" size={15} /> : parentId ? <Folder className="text-amber-500" size={15} /> : <HardDrive className="text-cyan-600" size={15} />}
      <span className="truncate">{label}</span>
    </button>
  );

  return (
    <DialogShell title={`Move ${moving.length === 1 ? `"${moving[0].name}"` : `${moving.length} items`}`} onClose={onCancel}>
      <div className="max-h-[60vh] overflow-y-auto p-3">
        {row("root", null, "My Files (top level)", 0)}
        {targets.map((folder) => row(folder.id, folder.id, folder.name, breadcrumb(index, folder.id).length))}
        {targets.length === 0 && <p className="px-3 py-2 text-xs text-ink-500">No other folders yet.</p>}
      </div>
      {error && <p className="border-t border-line px-5 py-2 text-xs font-semibold text-rose-500">{error}</p>}
    </DialogShell>
  );
}

const TEXT_PREVIEW_LIMIT = 200_000;

/**
 * Shows a file the core decrypted into memory. The bytes arrive only after the
 * whole file authenticated (header, every chunk tag, content hash); they are
 * held in an object URL for as long as the dialog is open and released when it
 * closes. Nothing is written to disk.
 */
export interface PreviewSubject {
  /** Stable identity, so the viewer reloads only for another file. */
  key: string;
  name: string;
  contentType: string;
  category: string;
  sizeBytes: number;
  /** Authenticated plaintext, decrypted in memory by the core. */
  load: () => Promise<ArrayBuffer>;
  /** What the footer says once it opened. */
  verifiedNote?: string;
}

export function previewOfEntry(entry: StoreEntry): PreviewSubject {
  return {
    key: entry.id,
    name: entry.name,
    contentType: entry.contentType,
    category: entry.category,
    sizeBytes: entry.sizeBytes,
    load: () => vaultStore.preview(entry.id),
  };
}

export function PreviewDialog({ subject, onClose, onExport }: { subject: PreviewSubject; onClose: () => void; onExport?: () => void }) {
  const entry = subject;
  const [url, setUrl] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    (async () => {
      try {
        const bytes = await subject.load();
        if (cancelled) return;
        if (entry.contentType.startsWith("text/") || entry.contentType === "application/json") {
          const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
          setText(decoded.length > TEXT_PREVIEW_LIMIT ? `${decoded.slice(0, TEXT_PREVIEW_LIMIT)}\n\n… (truncated — export the file to see all of it)` : decoded);
        } else {
          objectUrl = URL.createObjectURL(new Blob([bytes], { type: entry.contentType }));
          setUrl(objectUrl);
        }
      } catch (err) {
        if (!cancelled) setError(describeStoreError(err));
      }
    })();
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
    // The loader is recreated per render; the subject's key decides reloads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subject.key, entry.contentType]);

  const loading = !url && text === null && !error;
  return (
    <DialogShell title={entry.name} onClose={onClose} wide>
      <div className="flex min-h-64 flex-1 items-center justify-center overflow-auto bg-canvas p-3">
        {loading && (
          <div className="flex flex-col items-center gap-2 text-sm text-ink-600">
            <Loader2 className="animate-spin text-cyan-600" size={26} />
            Decrypting and verifying in memory…
          </div>
        )}
        {error && <p className="max-w-md text-center text-sm font-semibold text-rose-500">{error}</p>}
        {url && entry.category === "image" && <img src={url} alt={entry.name} className="max-h-[70vh] max-w-full rounded-lg object-contain" />}
        {url && entry.category === "video" && (
          <video src={url} controls autoPlay className="max-h-[70vh] max-w-full rounded-lg bg-ink-950">
            This video format cannot be played here — export it to open it.
          </video>
        )}
        {url && entry.category === "audio" && <audio src={url} controls autoPlay className="w-full max-w-lg" />}
        {text !== null && <pre className="max-h-[70vh] w-full overflow-auto whitespace-pre-wrap break-words rounded-lg bg-white p-4 font-mono text-xs text-ink-900">{text}</pre>}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-5 py-3 text-xs text-ink-600">
        <span className="flex items-center gap-2">
          <ShieldCheck className="text-emerald-600" size={14} />
          {error ? "Not opened" : url || text !== null ? subject.verifiedNote ?? "Decrypted in memory · integrity verified · nothing written to disk" : "Opening…"}
          <span className="text-ink-400">· {formatBytes(entry.sizeBytes)}</span>
        </span>
        {onExport && (
          <button type="button" onClick={onExport} className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 font-semibold text-ink-800 hover:bg-canvas">
            <Download size={14} /> Export
          </button>
        )}
      </div>
    </DialogShell>
  );
}
