import { useCallback, useEffect, useState } from "react";
import { HardDriveDownload, LifeBuoy, Users } from "lucide-react";
import { loadAccountRecovery } from "@/lib/account-recovery";
import {
  approveHelpRequest,
  base64ToBlob,
  collectIncomingShares,
  exportHistoryBackup,
  fileToBase64,
  finishRecovery,
  heldShares,
  helpRequests,
  importHistoryBackup,
  loadSocialRecovery,
  openRecoveryRequest,
  releasesFor,
  setupSocialRecovery,
  verifiedContactDevices,
  type GuardianCandidate,
  type HeldShareSummary,
  type PendingHelpRequest,
  type RecoveryRequest,
  type SocialRecoveryRecord,
} from "@/lib/recovery";
import { describeSavedFile, saveFileToDevice } from "@/lib/save-file";
import { supabase } from "@/lib/supabase";
import { isTauriRuntime, safeInvoke } from "@/lib/tauri";

type Note = { tone: "ok" | "error"; text: string } | null;
const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));
const inputClass = "rounded-lg border border-line bg-canvas px-3 py-1.5 text-sm outline-none focus:border-cyan-300";
const buttonClass = "rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas disabled:opacity-60";
const primaryClass = "rounded-lg bg-ink-950 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-60";

/**
 * Settings → Recovery (roadmap Phase 5). History backup under the recovery
 * key; recovering the recovery key itself with k of n verified contacts plus
 * a PIN; and the helper's side of that. Every secret step runs in the core.
 */
export function RecoveryCenterCard({ userId }: { userId: string }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<Note>(null);
  const [accountVerifier, setAccountVerifier] = useState<string | null>(null);
  const [deviceId, setDeviceId] = useState<string | null>(null);

  // History backup
  const [backupKey, setBackupKey] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);

  // Social recovery (owner)
  const [record, setRecord] = useState<SocialRecoveryRecord | null>(null);
  const [candidates, setCandidates] = useState<GuardianCandidate[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [threshold, setThreshold] = useState(2);
  const [setupPin, setSetupPin] = useState("");
  const [setupPinConfirm, setSetupPinConfirm] = useState("");
  const [setupKey, setSetupKey] = useState("");

  // Helper side
  const [held, setHeld] = useState<HeldShareSummary[]>([]);
  const [requests, setRequests] = useState<PendingHelpRequest[]>([]);

  // Recovering on a new device
  const [myRequest, setMyRequest] = useState<{ request: RecoveryRequest; code: string[] } | null>(null);
  const [arrived, setArrived] = useState(0);
  const [recoveryPin, setRecoveryPin] = useState("");
  const [recoveredKey, setRecoveredKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const bundle = await safeInvoke<{ device_id?: string } | null>("keys_upload_identity_bundle", { userId }, null).catch(() => null);
    const device = bundle?.device_id ?? null;
    setDeviceId(device);
    setAccountVerifier((await loadAccountRecovery(supabase, userId).catch(() => null))?.verifier ?? null);
    setRecord(await loadSocialRecovery(supabase, userId).catch(() => null));
    if (device) await collectIncomingShares(supabase, userId, device).catch(() => 0);
    setHeld(await heldShares().catch(() => []));
    setRequests(await helpRequests(supabase).catch(() => []));
  }, [userId]);

  useEffect(() => {
    if (isTauriRuntime()) void refresh();
  }, [refresh]);

  if (!isTauriRuntime()) return null;

  const run = async (key: string, action: () => Promise<void>) => {
    setBusy(key);
    setNote(null);
    try {
      await action();
    } catch (error) {
      setNote({ tone: "error", text: errorText(error) });
    } finally {
      setBusy(null);
    }
  };

  const makeBackup = () => run("backup", async () => {
    const backup = await exportHistoryBackup(backupKey.trim(), accountVerifier);
    const saved = await saveFileToDevice(backup.fileName, base64ToBlob(backup.fileB64));
    setNote({ tone: "ok", text: `Backup of ${backup.entries} message keys saved — ${describeSavedFile(saved)}. It opens only with your recovery key.` });
    setBackupKey("");
  });

  const restoreBackup = () => run("restore", async () => {
    if (!restoreFile) throw new Error("Choose a .qgbackup file first.");
    const result = await importHistoryBackup(backupKey.trim(), accountVerifier, await fileToBase64(restoreFile));
    setNote({
      tone: "ok",
      text: `Restored ${result.added} message keys (${result.alreadyHeld} were already here). Reopen a chat to read its history — messages that have expired or been deleted on the relay stay gone.`,
    });
    setBackupKey("");
    setRestoreFile(null);
  });

  const loadCandidates = () => run("candidates", async () => {
    setCandidates(await verifiedContactDevices(supabase, userId));
  });

  const saveSetup = () => run("setup", async () => {
    const guardians = (candidates ?? []).filter((candidate) => chosen.has(candidate.deviceId));
    if (guardians.length < 2) throw new Error("Choose at least two helpers.");
    if (threshold < 2 || threshold > guardians.length) throw new Error("The number needed must be between 2 and the number of helpers.");
    if (setupPin.length < 6) throw new Error("Use a PIN or passphrase of at least 6 characters.");
    if (setupPin !== setupPinConfirm) throw new Error("The two PINs do not match.");
    const saved = await setupSocialRecovery(supabase, userId, { recoveryKey: setupKey.trim(), accountVerifier, pin: setupPin, threshold, guardians });
    setRecord(saved);
    setSetupPin("");
    setSetupPinConfirm("");
    setSetupKey("");
    setCandidates(null);
    setChosen(new Set());
    setNote({ tone: "ok", text: `Saved. Any ${saved.threshold} of your ${saved.shareCount} helpers, together with your PIN, can get your recovery key back. Their apps store their part the next time they open Settings.` });
  });

  const approve = (pending: PendingHelpRequest) => run(`approve-${pending.request.requestId}`, async () => {
    await approveHelpRequest(supabase, userId, pending);
    setRequests((current) => current.filter((item) => item.request.requestId !== pending.request.requestId));
    setNote({ tone: "ok", text: "Your part was sent, sealed so only the device that asked can open it." });
  });

  const askForHelp = () => run("ask", async () => {
    const opened = await openRecoveryRequest(supabase, userId);
    setMyRequest(opened);
    setArrived((await releasesFor(supabase, opened.request.requestId)).length);
  });

  const checkArrivals = () => run("arrivals", async () => {
    if (!myRequest) return;
    setArrived((await releasesFor(supabase, myRequest.request.requestId)).length);
  });

  const rebuild = () => run("rebuild", async () => {
    if (!record || !myRequest) throw new Error("No recovery set-up was found for this account.");
    const key = await finishRecovery(supabase, userId, record, myRequest.request.requestId, recoveryPin);
    setRecoveredKey(key);
    setRecoveryPin("");
  });

  return (
    <section className="shell-card p-5">
      <div className="flex items-center gap-2 text-sm font-bold text-ink-950"><LifeBuoy size={18} /> Recovery</div>
      <div className="mt-3 space-y-5 text-sm text-ink-600">
        {/* History backup */}
        <div>
          <div className="flex items-center gap-2 font-semibold text-ink-900"><HardDriveDownload size={15} /> Message history backup</div>
          <p className="mt-0.5 text-xs">
            Saves the keys to your message history — not the messages — in a file only your recovery key opens. Restored
            on a new device, your history on the relay becomes readable again. Make a new backup now and then: it covers
            messages up to the moment it was made.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <input value={backupKey} onChange={(e) => setBackupKey(e.target.value)} type="password" placeholder="Recovery key" aria-label="Recovery key for the backup" className={`${inputClass} min-w-[220px] flex-1`} />
            <button type="button" disabled={busy !== null || !backupKey.trim()} onClick={() => void makeBackup()} className={buttonClass}>Make backup</button>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <input type="file" accept=".qgbackup,application/json" aria-label="History backup file" onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)} className="text-xs" />
            <button type="button" disabled={busy !== null || !restoreFile || !backupKey.trim()} onClick={() => void restoreBackup()} className={buttonClass}>Restore backup</button>
          </div>
        </div>

        {/* Owner: set up */}
        <div>
          <div className="flex items-center gap-2 font-semibold text-ink-900"><Users size={15} /> Recover your recovery key with help from contacts</div>
          <p className="mt-0.5 text-xs">
            If you lose every device and your recovery key, a few contacts you have verified can help you get the key back
            — but only together, and only with a PIN that only you know. No helper, and not the server, ever sees your key.
          </p>
          {record && (
            <p className="mt-1 text-xs font-semibold text-emerald-700">
              Set up: any {record.threshold} of {record.shareCount} helpers, plus your PIN (since {new Date(record.createdAt * 1000).toLocaleDateString()}).
            </p>
          )}
          {!candidates ? (
            <button type="button" disabled={busy !== null} onClick={() => void loadCandidates()} className={`${buttonClass} mt-2`}>
              {record ? "Change helpers…" : "Choose helpers…"}
            </button>
          ) : candidates.length < 2 ? (
            <p className="mt-2 text-xs text-amber-700">You need at least two verified contacts. Verify contacts from a chat (the ✓ button) first.</p>
          ) : (
            <div className="mt-2 space-y-2 rounded-lg border border-line bg-canvas p-3">
              {candidates.map((candidate) => (
                <label key={candidate.deviceId} className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={chosen.has(candidate.deviceId)}
                    onChange={(e) => setChosen((current) => {
                      const next = new Set(current);
                      if (e.target.checked) next.add(candidate.deviceId); else next.delete(candidate.deviceId);
                      return next;
                    })}
                  />
                  <span className="font-semibold text-ink-900">{candidate.name}</span> — {candidate.deviceLabel}
                </label>
              ))}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                Needed to recover:
                <select value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} className={inputClass} aria-label="Helpers needed">
                  {Array.from({ length: Math.max(1, chosen.size - 1) }, (_, i) => i + 2).map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
                of {chosen.size}
              </div>
              <div className="flex flex-wrap gap-2">
                <input value={setupPin} onChange={(e) => setSetupPin(e.target.value)} type="password" placeholder="Recovery PIN (6+ characters)" aria-label="Recovery PIN" className={inputClass} />
                <input value={setupPinConfirm} onChange={(e) => setSetupPinConfirm(e.target.value)} type="password" placeholder="Repeat it" aria-label="Repeat the recovery PIN" className={inputClass} />
                <input value={setupKey} onChange={(e) => setSetupKey(e.target.value)} type="password" placeholder="Your recovery key" aria-label="Recovery key" className={`${inputClass} min-w-[200px] flex-1`} />
              </div>
              <p className="text-[11px] text-ink-500">
                Choose a PIN you will remember without this app. Helpers who all agree could try to guess a short PIN, so a
                passphrase is safer.
              </p>
              <div className="flex gap-2">
                <button type="button" disabled={busy !== null} onClick={() => void saveSetup()} className={primaryClass}>Save</button>
                <button type="button" onClick={() => setCandidates(null)} className={buttonClass}>Cancel</button>
              </div>
            </div>
          )}
        </div>

        {/* Helper side */}
        {(held.length > 0 || requests.length > 0) && (
          <div>
            <div className="font-semibold text-ink-900">You are helping {held.length} {held.length === 1 ? "person" : "people"}</div>
            {requests.length === 0 ? (
              <p className="mt-0.5 text-xs">No one has asked for help.</p>
            ) : requests.map((pending) => (
              <div key={pending.request.requestId} className="mt-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
                <div className="font-semibold">Someone is asking to recover their account.</div>
                <p className="mt-1">
                  Call or meet them — not by message — and ask them to read the four words on their screen. Release your part
                  only if they match exactly:
                </p>
                <div className="mt-1 font-mono text-base font-bold text-ink-950">{pending.code.join(" ")}</div>
                <button type="button" disabled={busy !== null} onClick={() => void approve(pending)} className={`${primaryClass} mt-2`}>
                  The words match — release my part
                </button>
              </div>
            ))}
          </div>
        )}

        {/* New device */}
        {record && (
          <div>
            <div className="font-semibold text-ink-900">Lost your recovery key?</div>
            {!myRequest ? (
              <button type="button" disabled={busy !== null || !deviceId} onClick={() => void askForHelp()} className={`${buttonClass} mt-1`}>
                Ask my helpers
              </button>
            ) : (
              <div className="mt-1 space-y-2 text-xs">
                <p>Contact your helpers yourself and read them these words. They release their part only if the words match:</p>
                <div className="font-mono text-base font-bold text-ink-950">{myRequest.code.join(" ")}</div>
                <p>
                  {arrived} of {record.threshold} parts have arrived.{" "}
                  <button type="button" disabled={busy !== null} onClick={() => void checkArrivals()} className="font-bold text-cyan-700">Check again</button>
                </p>
                {arrived >= record.threshold && !recoveredKey && (
                  <div className="flex flex-wrap gap-2">
                    <input value={recoveryPin} onChange={(e) => setRecoveryPin(e.target.value)} type="password" placeholder="Your recovery PIN" aria-label="Recovery PIN" className={inputClass} />
                    <button type="button" disabled={busy !== null || !recoveryPin} onClick={() => void rebuild()} className={primaryClass}>Get my recovery key back</button>
                  </div>
                )}
                {recoveredKey && (
                  <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-emerald-900">
                    <div className="font-semibold">Your recovery key</div>
                    <div className="mt-1 break-all font-mono text-sm">{recoveredKey}</div>
                    <p className="mt-1">Write it down now. Use it in Quantum Vault → Recovery, and above to restore a history backup.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {note && (
          <div className={`rounded-md border p-2 text-xs font-semibold ${note.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-rose-100 bg-rose-50 text-rose-700"}`}>
            {note.text}
          </div>
        )}
      </div>
    </section>
  );
}
