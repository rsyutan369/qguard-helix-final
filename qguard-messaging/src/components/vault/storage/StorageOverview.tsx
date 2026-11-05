import { AlertTriangle, CheckCircle2, Cloud, CloudOff, LockKeyhole, ShieldCheck, Upload } from "lucide-react";
import type { CloudState } from "@/lib/vault-cloud";
import { CATEGORY_LABELS, formatBytes, type StoreActivity, type StoreCategory, type StoreStatus } from "@/lib/vault-store";

// Every figure on this panel is a field of `vault_store_status`, which the core
// computes from the sealed index and the containers actually on disk.

const CATEGORY_ORDER: StoreCategory[] = ["image", "video", "document", "audio", "archive", "other"];
const CATEGORY_BAR: Record<StoreCategory, string> = {
  image: "bg-cyan-500",
  video: "bg-rose-500",
  document: "bg-violet-500",
  audio: "bg-emerald-500",
  archive: "bg-amber-500",
  other: "bg-ink-400",
};

export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const ACTION_LABELS: Record<string, string> = {
  import: "Encrypted into vault",
  export: "Exported",
  preview: "Preview",
  verify: "Integrity check",
  reprotect: "Re-protected",
  cloud_enable: "Cloud backup on",
  cloud_disable: "Cloud backup off",
  cloud_delete: "Cloud backup deleted",
  cloud_backup: "Backed up to cloud",
  cloud_restore: "Restored from cloud",
  cloud_share_copy: "Copy uploaded for sharing",
  cloud_share_copy_removed: "Sharing copy removed",
  share_create: "Shared",
  share_saved: "Saved from a share",
  library_create: "Library created",
  library_join: "Joined your library",
  library_rotate: "Library key renewed",
  library_merge: "Synced from your devices",
  rename: "Renamed",
  move: "Moved",
  create_folder: "Folder created",
  trash: "Moved to Trash",
  restore: "Restored",
  purge: "Deleted permanently",
  start_fresh: "New library started",
};

/** A label for an activity record; an action added later still reads as words. */
export function actionLabel(action: string): string {
  const known = ACTION_LABELS[action];
  if (known) return known;
  const words = action.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Activity";
}

export function ActivityList({ activity, empty }: { activity: StoreActivity[]; empty: string }) {
  if (activity.length === 0) return <p className="px-1 py-6 text-center text-sm text-ink-500">{empty}</p>;
  return (
    <ul className="divide-y divide-line">
      {activity.map((item) => (
        <li key={item.id} className="flex items-start gap-3 py-2.5">
          {item.outcome === "success" ? <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={15} /> : <AlertTriangle className="mt-0.5 shrink-0 text-rose-500" size={15} />}
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 text-sm">
              <span className="font-semibold text-ink-900">{actionLabel(item.action)}</span>
              <span className="min-w-0 max-w-full truncate text-ink-700">{item.name}</span>
            </div>
            {item.detail && <p className="mt-0.5 break-words text-xs text-ink-500">{item.detail}</p>}
            {/* On a phone the time goes under the text instead of squeezing it. */}
            <time className="mt-0.5 block text-[11px] text-ink-400 sm:hidden" dateTime={item.at}>{formatWhen(item.at)}</time>
          </div>
          <time className="hidden shrink-0 text-[11px] text-ink-400 sm:block" dateTime={item.at}>{formatWhen(item.at)}</time>
        </li>
      ))}
    </ul>
  );
}

export function StorageOverview({
  status,
  cloud,
  onImport,
  onOpenSection,
}: {
  status: StoreStatus;
  cloud: CloudState | null;
  onImport: () => void;
  onOpenSection: (section: "files" | "security" | "activity") => void;
}) {
  const totalFiles = status.files;
  const integrityIssues = status.failed + status.missing;
  const usedBytes = Math.max(status.plaintextBytes, 1);

  if (totalFiles === 0 && status.folders === 0 && status.trashed === 0) {
    return (
      <div className="rounded-xl border border-dashed border-line bg-white p-8 text-center">
        <LockKeyhole className="mx-auto text-cyan-600" size={40} />
        <h3 className="mt-3 text-lg font-bold text-ink-950">Your Quantum Vault is empty</h3>
        <p className="mx-auto mt-1 max-w-lg text-sm text-ink-600">
          Add photos, videos, documents or any other file. Each one is encrypted on this device before it is stored, and
          only opens while your vault is unlocked.
        </p>
        <button type="button" onClick={onImport} className="mt-5 inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-bold text-white hover:opacity-90">
          <Upload size={16} /> Add files
        </button>
        <p className="mt-4 text-[11px] text-ink-500">
          {cloud?.enabled ? "Encrypted on this device, then backed up as ciphertext" : "Stored only on this device · nothing is uploaded"}
        </p>
      </div>
    );
  }

  return (
    // Every grid below names its phone column (grid-cols-1 = minmax(0, 1fr)):
    // an implicit column is as wide as its longest unbreakable line, so one
    // long file name used to push the whole overview past a phone's screen.
    // The overview is deliberately one panel: the per-file metric cards and the
    // recent-activity list were removed to declutter it (activity has its own
    // section; integrity and recovery detail live in Security & Backup).
    <div className="space-y-4">
      <section className="min-w-0 rounded-xl border border-line bg-white p-4">
        <h3 className="text-sm font-bold text-ink-950">What's in your vault</h3>
        <div className="mt-3 flex h-2.5 w-full overflow-hidden rounded-full bg-canvas" aria-hidden="true">
          {CATEGORY_ORDER.map((category) =>
            status.categories[category].bytes > 0 ? (
              <div key={category} className={CATEGORY_BAR[category]} style={{ width: `${(status.categories[category].bytes / usedBytes) * 100}%` }} />
            ) : null,
          )}
        </div>
        <ul className="mt-3 grid grid-cols-1 gap-x-4 gap-y-2 text-sm min-[380px]:grid-cols-2">
          {CATEGORY_ORDER.map((category) => (
            <li key={category} className="flex min-w-0 items-center justify-between gap-2">
              <span className="flex min-w-0 items-center gap-2 text-ink-700">
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${CATEGORY_BAR[category]}`} />
                <span className="truncate">{CATEGORY_LABELS[category]}</span>
              </span>
              <span className="shrink-0 text-xs text-ink-500">
                {status.categories[category].files} · {formatBytes(status.categories[category].bytes)}
              </span>
            </li>
          ))}
        </ul>
        <div className="mt-4 space-y-2 border-t border-line pt-3 text-xs text-ink-600">
          <div className="flex items-start gap-2">
            <ShieldCheck className="mt-px shrink-0 text-emerald-600" size={14} />
            <span className="min-w-0">Encrypted locally · AES-256-GCM per file, per-file key sealed under your PIN-bound vault key</span>
          </div>
          {cloud?.enabled ? (
            <div className="flex items-start gap-2">
              <Cloud className="mt-px shrink-0 text-cyan-600" size={14} />
              <span className="min-w-0">
                Encrypted cloud backup on · {cloud.backedUpFiles} of {totalFiles} files backed up
                {cloud.pendingUploads > 0 ? ` · ${cloud.pendingUploads} waiting` : ""}
              </span>
            </div>
          ) : (
            <div className="flex items-start gap-2">
              <CloudOff className="mt-px shrink-0 text-ink-500" size={14} />
              <span className="min-w-0">Stored only on this device — cloud backup is off and nothing new is uploaded</span>
            </div>
          )}
          {status.typeMismatches > 0 && (
            <div className="flex items-start gap-2 text-amber-500">
              <AlertTriangle className="mt-px shrink-0" size={14} />
              <span className="min-w-0">
                {status.typeMismatches} file{status.typeMismatches === 1 ? "'s" : "s'"} name does not match its content type
              </span>
            </div>
          )}
        </div>
      </section>

      {(integrityIssues > 0 || status.orphanedObjects > 0) && (
        <button
          type="button"
          onClick={() => onOpenSection("security")}
          className="flex w-full items-center gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-left text-sm text-ink-800"
        >
          <AlertTriangle className="shrink-0 text-rose-500" size={18} />
          <span>
            {integrityIssues > 0 && `${integrityIssues} file${integrityIssues === 1 ? "" : "s"} failed integrity or ${integrityIssues === 1 ? "is" : "are"} missing. `}
            {status.orphanedObjects > 0 && `${status.orphanedObjects} encrypted object${status.orphanedObjects === 1 ? " is" : "s are"} not listed in the vault index. `}
            Review in Security.
          </span>
        </button>
      )}
    </div>
  );
}
