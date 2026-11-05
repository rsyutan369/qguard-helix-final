import { AlertTriangle, CheckCircle2, Cloud, CloudOff, CloudUpload, HardDrive, KeyRound, Loader2, LockKeyhole, RefreshCw, RotateCcw, Smartphone, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { ask as askDialog } from "@/lib/tauri-dialog";
import {
  describeCloudError,
  fetchCloudUsage,
  fetchPlanQuotas,
  openBackup,
  endRestore,
  restoreFromBackup,
  vaultCloudCore,
  type CloudObjectRow,
  type CloudState,
  type CloudUsage,
  type PlanQuota,
  type RestorePreview,
  type SyncProgress,
} from "@/lib/vault-cloud";
import { joinLibraryWithRecoveryKey, type LibraryDevice } from "@/lib/vault-library";
import { describeShareError, liveSharedObjectIds } from "@/lib/vault-share";
import { formatBytes } from "@/lib/vault-store";
import { requireSupabase } from "@/lib/supabase";
import { formatWhen } from "./StorageOverview";

// Backup & Sync. Every figure is read from the core (`vault_cloud_state`) or
// the database (`qv_cloud_usage`, `qv_plan_quotas`) — quotas are never written
// into the app.

function planLabel(plan: string): string {
  return plan.charAt(0).toUpperCase() + plan.slice(1).toLowerCase();
}

function RestoreDialog({
  userId,
  onClose,
  onRestored,
  onJoined,
}: {
  userId: string;
  onClose: () => void;
  onRestored: (text: string) => void;
  /** The account library was joined: bring it in (sync) and report. */
  onJoined: () => Promise<void>;
}) {
  const [recoveryKey, setRecoveryKey] = useState("");
  const [opened, setOpened] = useState<{ preview: RestorePreview; rows: CloudObjectRow[] } | null>(null);
  const [progress, setProgress] = useState<SyncProgress | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    if (busy) return;
    void endRestore();
    onClose();
  };

  const open = async () => {
    setBusy(true);
    setError(null);
    try {
      // The account library (phase 3): join it with the recovery key, then a
      // sync lists every backed-up file here, downloaded when opened.
      const joined = await joinLibraryWithRecoveryKey(requireSupabase(), recoveryKey.trim());
      if (joined) {
        setRecoveryKey("");
        await onJoined();
        onRestored(
          "Your vault library is connected on this device. Files from your backup now appear in My Files and download (checked and verified) when you open them — or use “Download all” in Backup.",
        );
        onClose();
        return;
      }
      // An account without a library: the per-device backup from before.
      setOpened(await openBackup(userId, recoveryKey.trim()));
    } catch (err) {
      setError(describeCloudError(err));
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!opened) return;
    setBusy(true);
    setError(null);
    try {
      const outcome = await restoreFromBackup(userId, opened.preview, opened.rows, setProgress);
      onRestored(
        `${outcome.restored} file${outcome.restored === 1 ? "" : "s"} restored from your cloud backup and verified.` +
          (outcome.failed.length ? ` ${outcome.failed.length} could not be restored — ${outcome.failed.slice(0, 2).join("; ")}` : ""),
      );
      onClose();
    } catch (err) {
      setError(describeCloudError(err));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const toRestore = opened?.preview.files.filter((f) => !f.present) ?? [];
  const already = (opened?.preview.files.length ?? 0) - toRestore.length;
  const restoreBytes = toRestore.reduce((sum, f) => sum + f.sizeBytes, 0);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Restore from cloud backup">
      <div className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-line bg-white shadow-soft">
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <h3 className="text-sm font-bold text-ink-950">Restore from cloud backup</h3>
          <button type="button" onClick={close} disabled={busy} className="rounded-md p-1 text-ink-500 hover:bg-canvas" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="space-y-3 overflow-y-auto p-5 text-sm">
          {!opened ? (
            <>
              <p className="text-ink-700">
                Your backup is sealed with your recovery key. Enter it to open the backup on this device. Signing in alone never
                opens it, and the key never leaves this device.
              </p>
              <label className="block text-xs font-semibold text-ink-600" htmlFor="vault-restore-key">
                Recovery key
              </label>
              <textarea
                id="vault-restore-key"
                value={recoveryKey}
                onChange={(event) => setRecoveryKey(event.target.value)}
                rows={3}
                autoComplete="off"
                spellCheck={false}
                className="w-full rounded-lg border border-line bg-white px-3 py-2 font-mono text-xs text-ink-950 outline-none focus:ring-2 focus:ring-cyan-500/40"
              />
              <button
                type="button"
                disabled={busy || recoveryKey.trim().length < 20}
                onClick={() => void open()}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 font-bold text-white disabled:opacity-60"
              >
                {busy ? <Loader2 className="animate-spin" size={14} /> : <KeyRound size={14} />} Open backup
              </button>
            </>
          ) : (
            <>
              <div className="flex items-start gap-2 rounded-lg border border-line bg-emerald-50 p-3 text-ink-800">
                <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={16} />
                <span>
                  Backup opened: {opened.preview.files.length} file{opened.preview.files.length === 1 ? "" : "s"} in {opened.preview.folders} folder
                  {opened.preview.folders === 1 ? "" : "s"}.{already > 0 ? ` ${already} already on this device.` : ""}
                </span>
              </div>
              {toRestore.length > 0 ? (
                <>
                  <ul className="max-h-48 divide-y divide-line overflow-y-auto rounded-lg border border-line">
                    {toRestore.slice(0, 100).map((file) => (
                      <li key={file.entryId} className="flex items-center justify-between gap-2 px-3 py-1.5 text-xs">
                        <span className="min-w-0 truncate text-ink-800">
                          {file.location ? <span className="text-ink-400">{file.location} / </span> : null}
                          {file.name}
                        </span>
                        <span className="shrink-0 text-ink-500">{formatBytes(file.sizeBytes)}</span>
                      </li>
                    ))}
                  </ul>
                  {toRestore.length > 100 && <p className="text-xs text-ink-500">…and {toRestore.length - 100} more.</p>}
                  <p className="text-xs text-ink-600">
                    Each file is downloaded, checked part by part, re-bound to this device's vault with your recovery key and opened
                    once to verify it before it is stored.
                  </p>
                  {progress && (
                    <div>
                      <div className="flex justify-between text-xs text-ink-600">
                        <span className="truncate">{progress.label}</span>
                        <span>
                          {progress.item} / {progress.items}
                        </span>
                      </div>
                      <div className="mt-1 h-2 w-full overflow-hidden rounded-full bg-canvas">
                        <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-600" style={{ width: `${progress.items ? (progress.item / progress.items) * 100 : 0}%` }} />
                      </div>
                    </div>
                  )}
                  <button type="button" disabled={busy} onClick={() => void restore()} className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 font-bold text-white disabled:opacity-60">
                    {busy ? <Loader2 className="animate-spin" size={14} /> : <RotateCcw size={14} />} Restore {toRestore.length} file{toRestore.length === 1 ? "" : "s"} ({formatBytes(restoreBytes)})
                  </button>
                </>
              ) : (
                <p className="text-ink-700">Everything in this backup is already on this device.</p>
              )}
            </>
          )}
          {error && <p className="text-xs font-semibold text-rose-500">{error}</p>}
        </div>
      </div>
    </div>
  );
}

export function CloudBackupPanel({
  userId,
  cloud,
  syncing,
  syncProgress,
  busy,
  onSyncNow,
  onRestoreMissing,
  onChanged,
  onOpenRecovery,
  onNotice,
  devices,
  waitingForAccess,
  onJoined,
}: {
  userId: string;
  /** The account's devices and which hold the library key (from the last sync). */
  devices: LibraryDevice[];
  /** This device has no library key and no way to get one by itself yet. */
  waitingForAccess: boolean;
  onJoined: () => Promise<void>;
  cloud: CloudState | null;
  syncing: boolean;
  syncProgress: SyncProgress | null;
  busy: boolean;
  onSyncNow: () => void;
  onRestoreMissing: () => void;
  onChanged: () => Promise<void>;
  onOpenRecovery: () => void;
  onNotice: (tone: "success" | "error" | "info", text: string) => void;
}) {
  const [usage, setUsage] = useState<CloudUsage | null>(null);
  const [plans, setPlans] = useState<PlanQuota[]>([]);
  const [usageError, setUsageError] = useState<string | null>(null);
  const [toggling, setToggling] = useState(false);
  const [restoring, setRestoring] = useState(false);

  const loadUsage = useCallback(async () => {
    try {
      const [nextUsage, nextPlans] = await Promise.all([fetchCloudUsage(), fetchPlanQuotas()]);
      setUsage(nextUsage);
      setPlans(nextPlans);
      setUsageError(null);
    } catch (error) {
      setUsageError(describeCloudError(error));
    }
  }, []);

  // Re-read whenever the core's view changes (after a sync, toggle or delete).
  useEffect(() => {
    void loadUsage();
  }, [loadUsage, cloud?.backedUpFiles, cloud?.sharedCopies, cloud?.pendingDeletes, cloud?.lastSyncAt]);

  const toggle = async (enabled: boolean) => {
    setToggling(true);
    try {
      await vaultCloudCore.setEnabled(enabled);
      await onChanged();
      if (enabled) onSyncNow();
      onNotice("info", enabled ? "Cloud backup is on. Encrypted copies are being uploaded." : "Cloud backup is off. Nothing more will be uploaded; existing backups are kept.");
    } catch (error) {
      onNotice("error", describeCloudError(error));
    } finally {
      setToggling(false);
    }
  };

  const deleteBackup = async () => {
    const confirmed = await askDialog(
      "Delete your entire cloud backup?\n\nEvery encrypted backup copy in the cloud is removed and backup is turned off. Files you are sharing keep their one encrypted copy until their shares end. The files on this device are not touched. If you lose this device afterwards, these files cannot be recovered.",
      { title: "Delete cloud backup", okLabel: "Delete backup", cancelLabel: "Cancel" },
    ).catch(() => false);
    if (!confirmed) return;
    try {
      // Never break a live share: the copies it uses stay, as shared copies.
      const inUse = await liveSharedObjectIds(userId);
      await vaultCloudCore.deleteBackup([...inUse]);
      await onChanged();
      onSyncNow();
    } catch (error) {
      onNotice("error", describeShareError(error));
    }
  };

  if (!cloud) {
    return (
      <section className="rounded-xl border border-line bg-white p-4 text-sm text-ink-600">
        <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <Cloud className="text-cyan-600" size={16} /> Backup &amp; synchronization
        </h3>
        <p className="mt-2">Backup status is unavailable until your recovery settings can be read on this device.</p>
      </section>
    );
  }

  const quota = usage?.quota_bytes ?? 0;
  const used = (usage?.used_bytes ?? 0) + (usage?.reserved_bytes ?? 0);
  const percent = quota > 0 ? Math.min(100, (used / quota) * 100) : 0;
  const entitled = Boolean(usage && usage.has_access && quota > 0);
  const paidPlans = plans.filter((p) => p.quota_bytes > 0);
  const upToDate = cloud.enabled && cloud.pendingUploads === 0 && cloud.pendingDeletes === 0 && cloud.indexCurrent && !cloud.lastError;

  return (
    <section className="rounded-xl border border-line bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
            <Cloud className="text-cyan-600" size={16} /> Encrypted cloud backup &amp; sync
          </h3>
          <p className="mt-1 max-w-2xl text-xs text-ink-600">
            Optional. When on, each file's encrypted container is uploaded, and your folder list is shared with your other
            devices, sealed under a library key only your devices hold. Names, types, keys and contents never leave this device
            unencrypted. The backup opens with your recovery key or on a device you approved — never with your account password.
          </p>
        </div>
        <label className={`flex items-center gap-2 text-sm font-semibold ${cloud.recoveryReady ? "text-ink-800" : "text-ink-400"}`}>
          <span>{cloud.enabled ? "On" : "Off"}</span>
          <button
            type="button"
            role="switch"
            aria-checked={cloud.enabled}
            aria-label="Cloud backup"
            disabled={toggling || busy || !cloud.recoveryReady || (!cloud.enabled && !entitled)}
            onClick={() => void toggle(!cloud.enabled)}
            className={`relative h-6 w-11 rounded-full transition disabled:opacity-50 ${cloud.enabled ? "bg-cyan-600" : "bg-ink-400"}`}
          >
            <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow-tight transition ${cloud.enabled ? "left-[22px]" : "left-0.5"}`} />
          </button>
        </label>
      </div>

      {!cloud.recoveryReady && (
        <div className="mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-line bg-amber-50 p-3 text-xs text-ink-800">
          <AlertTriangle className="shrink-0 text-amber-500" size={15} />
          <span className="flex-1">
            To back up from this device it needs your vault library key. Enter your recovery key on this device — or approve this
            device in the Device Trust Center on one of your other devices, open the vault there, then check again here.
          </span>
          <button type="button" disabled={syncing} onClick={onSyncNow} className="rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800 disabled:opacity-50">
            {syncing ? "Checking…" : "Check for access"}
          </button>
          <button type="button" onClick={onOpenRecovery} className="rounded-lg border border-line bg-white px-3 py-1.5 font-semibold text-ink-800">
            Enter recovery key
          </button>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="min-w-0 rounded-lg border border-line bg-canvas p-3 text-sm">
          <div className="flex items-center justify-between text-xs font-semibold text-ink-600">
            <span>Cloud storage{usage?.plan ? ` · ${planLabel(usage.plan)} plan` : ""}</span>
            {usage && <span>{entitled ? `${formatBytes(used)} of ${formatBytes(quota)}` : "Not included"}</span>}
          </div>
          {usage && entitled && (
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-white">
              <div className={`h-full rounded-full ${percent >= 95 ? "bg-rose-500" : percent >= 80 ? "bg-amber-500" : "bg-cyan-500"}`} style={{ width: `${percent}%` }} />
            </div>
          )}
          {usageError && <p className="mt-2 text-xs text-rose-500">{usageError}</p>}
          {usage && !entitled && (
            <p className="mt-2 text-xs text-ink-600">
              {usage.has_access ? "Your plan stores files on this device only." : "Your subscription is not active, so new backups are paused. Existing backups stay available to restore."}
              {paidPlans.length > 0 && ` Cloud backup: ${paidPlans.map((p) => `${planLabel(p.plan)} ${formatBytes(p.quota_bytes)}`).join(" · ")}.`}
            </p>
          )}
          {usage && entitled && percent >= 95 && <p className="mt-2 text-xs font-semibold text-rose-500">Storage limit reached — new files stay on this device until space is freed.</p>}
        </div>

        <div className="min-w-0 rounded-lg border border-line bg-canvas p-3 text-sm">
          <div className="flex items-center gap-2 font-semibold text-ink-900">
            {syncing ? (
              <Loader2 className="animate-spin text-cyan-600" size={15} />
            ) : !cloud.enabled ? (
              <CloudOff className="text-ink-500" size={15} />
            ) : cloud.lastError ? (
              <AlertTriangle className="text-amber-500" size={15} />
            ) : upToDate ? (
              <CheckCircle2 className="text-emerald-600" size={15} />
            ) : (
              <CloudUpload className="text-cyan-600" size={15} />
            )}
            {syncing ? "Synchronizing…" : !cloud.enabled ? "Backup off" : cloud.lastError ? "Needs attention" : upToDate ? "Synchronization complete" : "Synchronization pending"}
          </div>
          <dl className="mt-2 grid grid-cols-2 gap-1 text-xs">
            <dt className="text-ink-600">Backed up</dt>
            <dd className="text-right text-ink-900">
              {cloud.backedUpFiles} file{cloud.backedUpFiles === 1 ? "" : "s"} · {formatBytes(cloud.backedUpBytes)}
            </dd>
            <dt className="text-ink-600">Waiting to upload</dt>
            <dd className="text-right text-ink-900">{cloud.enabled ? `${cloud.pendingUploads} · ${formatBytes(cloud.pendingUploadBytes)}` : "—"}</dd>
            {cloud.sharedCopies > 0 && (
              <>
                <dt className="text-ink-600">Kept for sharing</dt>
                <dd className="text-right text-ink-900">
                  {cloud.sharedCopies} file{cloud.sharedCopies === 1 ? "" : "s"} · {formatBytes(cloud.sharedCopyBytes)}
                </dd>
              </>
            )}
            {cloud.pendingDeletes > 0 && (
              <>
                <dt className="text-ink-600">Waiting to remove</dt>
                <dd className="text-right text-ink-900">{cloud.pendingDeletes}</dd>
              </>
            )}
            <dt className="text-ink-600">Folders &amp; names</dt>
            <dd className="text-right text-ink-900">{cloud.indexCurrent ? "Backed up" : cloud.enabled ? "Pending" : "—"}</dd>
            <dt className="text-ink-600">Last sync</dt>
            <dd className="text-right text-ink-900">{formatWhen(cloud.lastSyncAt)}</dd>
          </dl>
          {cloud.lastError && <p className="mt-2 break-words text-xs text-amber-500">{cloud.lastError}</p>}
          {syncing && syncProgress && syncProgress.stage !== "done" && (
            <div className="mt-2">
              <p className="truncate text-[11px] text-ink-600">{syncProgress.label}</p>
              {syncProgress.bytesTotal > 0 && (
                <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-white">
                  <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-600 transition-[width]" style={{ width: `${Math.min(100, (syncProgress.bytesDone / syncProgress.bytesTotal) * 100)}%` }} />
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          disabled={syncing || busy || (!cloud.enabled && cloud.pendingDeletes === 0)}
          onClick={onSyncNow}
          className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-50"
        >
          <RefreshCw size={14} /> Back up now
        </button>
        {cloud.restorableMissing > 0 && (
          <button type="button" disabled={syncing || busy} onClick={onRestoreMissing} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
            <RotateCcw size={14} /> Download {cloud.restorableMissing} file{cloud.restorableMissing === 1 ? "" : "s"} kept in the cloud
          </button>
        )}
        <button type="button" disabled={syncing || busy} onClick={() => setRestoring(true)} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
          <KeyRound size={14} /> Restore from backup
        </button>
        {(cloud.backedUpFiles > 0 || cloud.indexCurrent) && (
          <button type="button" disabled={syncing || busy} onClick={() => void deleteBackup()} className="flex items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas disabled:opacity-50">
            <Trash2 size={14} className="text-rose-500" /> Delete cloud backup
          </button>
        )}
      </div>

      {devices.length > 0 && (
        <div className="mt-4 rounded-lg border border-line p-3">
          <h4 className="flex items-center gap-2 text-xs font-bold text-ink-900">
            <Smartphone className="text-cyan-600" size={14} /> Your devices
          </h4>
          <ul className="mt-2 divide-y divide-line text-xs">
            {devices.map((device) => (
              <li key={device.id} className="flex flex-wrap items-center gap-2 py-1.5">
                <span className="min-w-0 flex-1 truncate font-semibold text-ink-900">
                  {device.label}
                  {device.isThisDevice && <span className="ml-1 font-normal text-ink-500">(this device)</span>}
                </span>
                {device.revoked ? (
                  <span className="text-ink-500">Removed — cannot read anything added since</span>
                ) : !device.trusted ? (
                  <span className="text-amber-500">Not approved — approve it in the Device Trust Center</span>
                ) : device.hasLibraryKey ? (
                  <span className="flex items-center gap-1 text-emerald-600">
                    <CheckCircle2 size={12} /> Synced library
                  </span>
                ) : (
                  <span className="text-ink-500">Approved — receives the library key next time a vault is open</span>
                )}
              </li>
            ))}
          </ul>
          {waitingForAccess && (
            <p className="mt-2 text-[11px] text-amber-500">This device is waiting for the library key from one of your other devices.</p>
          )}
          <p className="mt-2 text-[11px] text-ink-500">
            Removing a device in the Device Trust Center gives your library a new key that device never receives. A device that
            has your recovery key can always re-open the library — replace the recovery key if you lose one you don't control.
          </p>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-2 text-[11px] text-ink-500 sm:grid-cols-3">
        <span className="flex items-start gap-1.5">
          <LockKeyhole className="mt-0.5 shrink-0" size={12} /> Uploaded: encrypted containers (AES-256-GCM, ML-DSA-87 signed) with no name or type, and your folder list sealed under your library key.
        </span>
        <span className="flex items-start gap-1.5">
          <HardDrive className="mt-0.5 shrink-0" size={12} /> Moving a file to Trash keeps its backup; deleting it permanently removes the cloud copy too.
        </span>
        <span className="flex items-start gap-1.5">
          <KeyRound className="mt-0.5 shrink-0" size={12} /> On a new device: unlock your vault, then <em>Restore from backup</em> with your recovery key.
        </span>
      </div>

      {restoring && (
        <RestoreDialog
          userId={userId}
          onJoined={onJoined}
          onClose={() => setRestoring(false)}
          onRestored={(text) => {
            onNotice("success", text);
            void onChanged();
          }}
        />
      )}
    </section>
  );
}
