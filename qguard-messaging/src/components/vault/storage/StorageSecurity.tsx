import { AlertTriangle, CheckCircle2, FileCheck2, HardDrive, KeyRound, Loader2, LockKeyhole, ShieldCheck } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { safeInvoke } from "@/lib/tauri";
import { formatBytes, type StoreStatus } from "@/lib/vault-store";
import { formatWhen } from "./StorageOverview";

interface RecoveryStatus {
  enabled: boolean;
  mode: string | null;
}

const SUITE = [
  { algo: "AES-256-GCM", role: "File content", detail: "A fresh random 256-bit key per file; every 1 MiB chunk authenticated and bound to its position" },
  { algo: "PIN-bound vault key", role: "Per-file key protection", detail: "Each file key is sealed under a key that exists only while the vault is unlocked" },
  { algo: "Ed25519 + ML-DSA-87", role: "Container signature", detail: "Hybrid signature (FIPS 204, Level 5) over every header: wrapped keys, size, chunk count" },
  { algo: "X25519 + ML-KEM-1024", role: "Recovery & sharing envelopes", detail: "Hybrid key encapsulation (FIPS 203) for enterprise recovery and recipient sharing" },
  { algo: "HKDF-SHA3-256", role: "Key separation", detail: "Index, thumbnail and recovery keys are derived separately; no key does two jobs" },
  { algo: "SHA3-256", role: "Content hash", detail: "Recorded at encryption; recomputed every time a file is opened or verified" },
];

export function StorageSecurity({
  status,
  busy,
  onVerifyAll,
  onStartFresh,
  onOpenRecovery,
  cloudPanel,
  lockPanel = null,
}: {
  status: StoreStatus;
  busy: boolean;
  onVerifyAll: () => void;
  onStartFresh: () => void;
  onOpenRecovery: () => void;
  /** The Backup & Sync panel (owned by VaultStorage, which runs the syncs). */
  cloudPanel: ReactNode;
  /** How the vault unlocks: pattern and hidden vaults (VaultLockCards). */
  lockPanel?: ReactNode;
}) {
  const [recovery, setRecovery] = useState<RecoveryStatus | null>(null);
  const [recoveryError, setRecoveryError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    safeInvoke<RecoveryStatus>("vault_recovery_status")
      .then((value) => !cancelled && setRecovery(value))
      .catch(() => !cancelled && setRecoveryError(true));
    return () => {
      cancelled = true;
    };
  }, []);

  const unprotected = status.files - status.recoveryProtected;
  const issues = status.failed + status.missing;

  return (
    <div className="space-y-4">
      {status.state === "foreign" && (
        <section className="rounded-xl border border-amber-200 bg-amber-50 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={18} />
            <div className="text-sm text-ink-800">
              <p className="font-bold">This storage belongs to your previous vault key</p>
              <p className="mt-1">
                Your vault was reset, so the library on this device can no longer be opened with the new key. Nothing has been
                changed or deleted. Its files still open with your recovery key (Encrypt &amp; Decrypt tools → Recovery). You can set
                the old library aside, unchanged, and start a new one.
              </p>
              <button type="button" disabled={busy} onClick={onStartFresh} className="mt-3 rounded-lg bg-amber-500 px-4 py-2 text-sm font-bold text-white disabled:opacity-60">
                Set old library aside and start fresh
              </button>
            </div>
          </div>
        </section>
      )}

      <section className="rounded-xl border border-line bg-white p-4">
        <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <ShieldCheck className="text-emerald-600" size={16} /> How your files are protected
        </h3>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {SUITE.map((item) => (
            <div key={item.algo} className="min-w-0 rounded-lg border border-line bg-canvas p-3">
              <div className="font-mono text-sm font-bold text-ink-950">{item.algo}</div>
              <div className="text-xs font-semibold text-cyan-600">{item.role}</div>
              <p className="mt-1 text-[11px] text-ink-600">{item.detail}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11px] text-ink-500">
          File names, folders and types are kept in an index encrypted under your vault key. The encrypted files on disk carry no
          name. Encryption protects confidentiality and integrity; it does not scan files for malware.
        </p>
      </section>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="min-w-0 rounded-xl border border-line bg-white p-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
            <FileCheck2 className="text-cyan-600" size={16} /> Integrity
          </h3>
          <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
            <dt className="text-ink-600">Verified</dt>
            <dd className="text-right font-semibold text-ink-950">{status.verified}</dd>
            <dt className="text-ink-600">Not yet verified</dt>
            <dd className="text-right font-semibold text-ink-950">{status.unverified}</dd>
            <dt className="text-ink-600">Failed</dt>
            <dd className={`text-right font-semibold ${status.failed > 0 ? "text-rose-500" : "text-ink-950"}`}>{status.failed}</dd>
            <dt className="text-ink-600">Missing</dt>
            <dd className={`text-right font-semibold ${status.missing > 0 ? "text-rose-500" : "text-ink-950"}`}>{status.missing}</dd>
            <dt className="text-ink-600">Unlisted encrypted objects</dt>
            <dd className="text-right font-semibold text-ink-950">{status.orphanedObjects}</dd>
            <dt className="text-ink-600">Last full check</dt>
            <dd className="text-right text-ink-800">{formatWhen(status.lastFullVerifyAt)}</dd>
          </dl>
          <p className="mt-3 text-[11px] text-ink-500">
            A full check decrypts every file in memory and confirms the signed header, every chunk tag and the recorded SHA3-256
            content hash. No plaintext is written.
            {issues > 0 && " Files that failed are never opened; restore them from another copy."}
            {status.orphanedObjects > 0 && " Unlisted objects are left by an interrupted import; they are ciphertext only."}
          </p>
          <button
            type="button"
            disabled={busy || status.state !== "ready" || status.files + status.trashed === 0}
            onClick={onVerifyAll}
            className="mt-3 flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-60"
          >
            {busy ? <Loader2 className="animate-spin" size={14} /> : <ShieldCheck size={14} />} Verify all files
          </button>
        </section>

        <section className="min-w-0 rounded-xl border border-line bg-white p-4">
          <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
            <KeyRound className="text-violet-600" size={16} /> Recovery &amp; device loss
          </h3>
          <div className="mt-3 space-y-2 text-sm text-ink-700">
            <div className="flex items-start gap-2">
              {recovery === null && !recoveryError ? (
                <Loader2 className="mt-0.5 animate-spin text-ink-400" size={15} />
              ) : recovery?.enabled ? (
                <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={15} />
              ) : (
                <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={15} />
              )}
              <span>
                {recoveryError
                  ? "Recovery status could not be read."
                  : recovery === null
                    ? "Checking recovery setup…"
                    : recovery.enabled
                      ? `Recovery key configured (${recovery.mode ?? "personal"} mode).`
                      : "No recovery key on this device. If you forget your vault PIN or the vault is reset, these files cannot be opened."}
              </span>
            </div>
            <div className="flex items-start gap-2">
              {unprotected === 0 ? <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={15} /> : <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={15} />}
              <span>
                {status.recoveryProtected} of {status.files} files carry a recovery wrap.
                {unprotected > 0 && " Files added before recovery was set up do not — re-add them to protect them."}
              </span>
            </div>
            <div className="flex items-start gap-2">
              {status.recoveryIndex ? <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={15} /> : <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={15} />}
              <span>{status.recoveryIndex ? "A copy of the index (names and folders) is sealed under your recovery key." : "No recovery copy of the index yet (needs a personal recovery key)."}</span>
            </div>
          </div>
          <p className="mt-3 text-[11px] text-ink-500">
            Signing in to your account never decrypts the vault. Only your vault PIN/password — or your recovery key — does.
          </p>
          <button type="button" onClick={onOpenRecovery} className="mt-3 rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-800 hover:bg-canvas">
            Manage recovery key
          </button>
        </section>
      </div>

      {lockPanel}

      {cloudPanel}

      <section className="rounded-xl border border-line bg-white p-4">
        <h3 className="flex items-center gap-2 text-sm font-bold text-ink-950">
          <HardDrive className="text-cyan-600" size={16} /> Local vault
        </h3>
        <div className="mt-2 flex items-center gap-2 text-sm text-ink-800">
          <LockKeyhole className="text-emerald-600" size={15} />
          {status.files} file{status.files === 1 ? "" : "s"} · {formatBytes(status.storedBytes)} encrypted in this app's private storage. Works offline.
        </div>
        <p className="mt-1 break-all font-mono text-[10px] text-ink-400">{status.storageLocation}</p>
      </section>
    </div>
  );
}
