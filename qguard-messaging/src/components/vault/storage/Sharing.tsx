import { AlertTriangle, CheckCircle2, Clock, CloudUpload, Download, Eye, Inbox, Loader2, Send, ShieldCheck, UserPlus, Users, X, XCircle } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ask as askDialog } from "@/lib/tauri-dialog";
import { PREVIEWABLE_TYPES, formatBytes, type StoreEntry } from "@/lib/vault-store";
import {
  createShare,
  describeShareError,
  listSharedByMe,
  listSharedWithMe,
  previewShared,
  releaseUnusedShareCopies,
  respondToShare,
  revokeShare,
  saveShared,
  searchPeople,
  type IncomingShare,
  type OutgoingShare,
  type PersonResult,
  type SharePermission,
} from "@/lib/vault-share";
import { EntryIcon } from "./EntryVisual";
import { PreviewDialog, type PreviewSubject } from "./StorageDialogs";
import { formatWhen } from "./StorageOverview";

// ---------------------------------------------------------------------------
// Secure sharing UI. Every state shown comes from the server (who was invited,
// who accepted, the access history) or from the core opening this device's
// envelope (name, type, size — the server never has them).
// ---------------------------------------------------------------------------

const EXPIRY_CHOICES: Array<{ label: string; hours: number | null }> = [
  { label: "No expiry", hours: null },
  { label: "1 hour", hours: 1 },
  { label: "1 day", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

export function ShareDialog({
  userId,
  entry,
  backupOn,
  onClose,
  onShared,
  onChanged,
}: {
  userId: string;
  entry: StoreEntry;
  /** Cloud backup is switched on (a copy uploaded to share is then also the backup). */
  backupOn: boolean;
  onClose: () => void;
  onShared: (text: string) => void;
  /** The vault's cloud state may have changed (a copy was uploaded, or taken back). */
  onChanged: () => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<PersonResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [chosen, setChosen] = useState<PersonResult[]>([]);
  const [permission, setPermission] = useState<SharePermission>("view");
  const [expiryHours, setExpiryHours] = useState<number | null>(24 * 7);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [upload, setUpload] = useState<{ done: number; total: number } | null>(null);
  const needsCopy = !entry.cloudObjectId;
  const uploadPercent = upload && upload.total > 0 ? Math.min(100, Math.round((upload.done / upload.total) * 100)) : 0;

  useEffect(() => {
    if (query.trim().length < 3) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setSearching(true);
      searchPeople(query)
        .then((found) => !cancelled && setResults(found))
        .catch((err) => !cancelled && setError(describeShareError(err)))
        .finally(() => !cancelled && setSearching(false));
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query]);

  const share = async () => {
    setBusy(true);
    setError(null);
    try {
      const expiresAt = expiryHours === null ? null : new Date(Date.now() + expiryHours * 3600 * 1000);
      const outcome = await createShare(userId, entry, chosen, permission, expiresAt, (done, total) => setUpload({ done, total }));
      onShared(
        `"${entry.name}" shared with ${outcome.people} ${outcome.people === 1 ? "person" : "people"} (${outcome.devices} device${outcome.devices === 1 ? "" : "s"}).` +
          (outcome.skipped.length ? ` Some devices were left out: ${outcome.skipped[0]}` : ""),
      );
      onClose();
    } catch (err) {
      setError(describeShareError(err));
      if (needsCopy) onChanged();
    } finally {
      setBusy(false);
      setUpload(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label={`Share ${entry.name}`}>
      <div className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-line bg-white shadow-soft">
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <h3 className="flex min-w-0 items-center gap-2 text-sm font-bold text-ink-950">
            <EntryIcon entry={entry} size={16} />
            <span className="truncate">Share "{entry.name}"</span>
          </h3>
          <button type="button" onClick={onClose} disabled={busy} className="rounded-md p-1 text-ink-500 hover:bg-canvas disabled:opacity-50" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="space-y-4 overflow-y-auto p-5 text-sm">
          {needsCopy && (
            <p className="flex items-start gap-2 rounded-lg border border-line bg-cyan-50 p-3 text-xs text-ink-800">
              <CloudUpload className="mt-0.5 shrink-0 text-cyan-600" size={14} />
              <span>
                No cloud backup needed. Sharing uploads one encrypted copy of this file only — sealed on this device, so the server cannot
                open it — and it counts toward your cloud storage.{" "}
                {backupOn
                  ? "Cloud backup is on, so the copy is also this file's backup."
                  : "Cloud backup stays off: the copy is removed from the cloud once no share uses it."}
              </span>
            </p>
          )}
          <div>
            <label className="block text-xs font-semibold text-ink-600" htmlFor="share-search">
              People
            </label>
            <input
              id="share-search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by name or @username"
              className="mt-1 w-full rounded-lg border border-line bg-white px-3 py-2 text-ink-950 outline-none focus:ring-2 focus:ring-cyan-500/40"
            />
            {searching && <p className="mt-1 text-xs text-ink-500">Searching…</p>}
            {results.length > 0 && (
              <ul className="mt-1 max-h-40 divide-y divide-line overflow-y-auto rounded-lg border border-line">
                {results
                  .filter((person) => !chosen.some((c) => c.userId === person.userId))
                  .map((person) => (
                    <li key={person.userId}>
                      <button
                        type="button"
                        onClick={() => {
                          setChosen((current) => [...current, person]);
                          setQuery("");
                        }}
                        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-canvas"
                      >
                        <UserPlus className="text-cyan-600" size={14} />
                        <span className="font-semibold text-ink-900">{person.displayName}</span>
                        {person.username && <span className="text-xs text-ink-500">@{person.username}</span>}
                      </button>
                    </li>
                  ))}
              </ul>
            )}
            {chosen.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {chosen.map((person) => (
                  <span key={person.userId} className="flex items-center gap-1 rounded-full border border-line bg-canvas px-2.5 py-1 text-xs font-semibold text-ink-800">
                    {person.displayName}
                    <button type="button" onClick={() => setChosen((current) => current.filter((c) => c.userId !== person.userId))} aria-label={`Remove ${person.displayName}`}>
                      <X size={12} />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <fieldset>
            <legend className="text-xs font-semibold text-ink-600">They can</legend>
            <div className="mt-1 grid grid-cols-2 gap-2">
              {([
                ["view", "View only", "Open it in QGuard Messaging"],
                ["download", "View and save", "Also save their own copy"],
              ] as const).map(([value, title, sub]) => (
                <label key={value} className={`cursor-pointer rounded-lg border p-2.5 ${permission === value ? "border-cyan-500 bg-cyan-50" : "border-line"}`}>
                  <input type="radio" name="share-permission" className="sr-only" checked={permission === value} onChange={() => setPermission(value)} />
                  <div className="font-semibold text-ink-900">{title}</div>
                  <div className="text-[11px] text-ink-500">{sub}</div>
                </label>
              ))}
            </div>
          </fieldset>

          <label className="block text-xs font-semibold text-ink-600">
            Access ends
            <select
              value={expiryHours === null ? "" : String(expiryHours)}
              onChange={(event) => setExpiryHours(event.target.value === "" ? null : Number(event.target.value))}
              className="mt-1 w-full rounded-lg border border-line bg-white px-3 py-2 text-sm text-ink-950"
            >
              {EXPIRY_CHOICES.map((choice) => (
                <option key={choice.label} value={choice.hours === null ? "" : String(choice.hours)}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>

          <div className="space-y-1.5 rounded-lg border border-line bg-canvas p-3 text-[11px] text-ink-600">
            <p className="flex items-start gap-1.5">
              <ShieldCheck className="mt-0.5 shrink-0 text-emerald-600" size={12} /> Each of their devices gets its own key envelope (X25519 + ML-KEM-1024), signed by this device (Ed25519 + ML-DSA-65). Everyone downloads the same single encrypted copy.
            </p>
            <p className="flex items-start gap-1.5">
              <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={12} /> You can revoke access at any time, which stops further downloads. It cannot take back a copy someone already saved, or a file they already opened. "View only" is enforced by the app, not by encryption.
            </p>
          </div>
          {upload && (
            <div aria-live="polite">
              <p className="text-[11px] text-ink-600">
                Uploading the encrypted copy · {uploadPercent}% of {formatBytes(upload.total)}
              </p>
              <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-canvas">
                <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-600 transition-[width]" style={{ width: `${uploadPercent}%` }} />
              </div>
            </div>
          )}
          {error && <p className="text-xs font-semibold text-rose-500">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-lg border border-line px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-canvas disabled:opacity-50">
            Cancel
          </button>
          <button
            type="button"
            disabled={busy || chosen.length === 0}
            onClick={() => void share()}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-50"
          >
            {busy ? <Loader2 className="animate-spin" size={14} /> : <Send size={14} />} {upload ? "Uploading…" : "Share"}
          </button>
        </div>
      </div>
    </div>
  );
}

function statusChip(status: string) {
  const tone =
    status === "accepted" ? "bg-emerald-50 text-emerald-600" : status === "pending" ? "bg-amber-50 text-amber-500" : "bg-canvas text-ink-500";
  return <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${tone}`}>{status}</span>;
}

const EVENT_LABELS: Record<string, string> = {
  created: "shared",
  accepted: "accepted",
  declined: "declined",
  opened: "opened",
  saved: "saved a copy",
  revoked: "revoked access",
};

export function SharedFiles({
  userId,
  deviceId,
  entries,
  maxPreviewBytes,
  currentFolder,
  onNotice,
  onChanged,
}: {
  userId: string;
  deviceId: string | null;
  entries: StoreEntry[];
  maxPreviewBytes: number;
  currentFolder: string | null;
  onNotice: (tone: "success" | "error" | "info", text: string) => void;
  onChanged: () => Promise<void>;
}) {
  const [tab, setTab] = useState<"incoming" | "outgoing">("incoming");
  const [incoming, setIncoming] = useState<IncomingShare[] | null>(null);
  const [outgoing, setOutgoing] = useState<OutgoingShare[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState<PreviewSubject | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      if (tab === "incoming") {
        if (!deviceId) return;
        setIncoming(await listSharedWithMe(userId, deviceId));
      } else {
        setOutgoing(await listSharedByMe(userId, entries));
        // Shares that ended (revoked, expired, declined) free a copy made only
        // for them. Best effort: tried again on the next visit.
        void releaseUnusedShareCopies(userId, entries)
          .then((released) => (released > 0 ? onChanged() : undefined))
          .catch(() => undefined);
      }
    } catch (err) {
      setError(describeShareError(err));
    }
    // entries change on every refresh; the outgoing list only needs names.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, userId, deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (key: string, job: () => Promise<void>) => {
    setBusy(key);
    try {
      await job();
    } catch (err) {
      onNotice("error", describeShareError(err));
    } finally {
      setBusy(null);
      await load();
    }
  };

  const pendingCount = useMemo(() => (incoming ?? []).filter((s) => s.status === "pending").length, [incoming]);

  return (
    <section className="shell-card min-w-0 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="inline-flex rounded-lg border border-line bg-canvas p-1" role="tablist" aria-label="Shared files">
          {([
            ["incoming", "Shared with me", Inbox],
            ["outgoing", "Shared by me", Users],
          ] as const).map(([id, label, Icon]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-bold ${tab === id ? "bg-cyan-600 text-white" : "text-ink-600"}`}
            >
              <Icon size={14} /> {label}
              {id === "incoming" && pendingCount > 0 && <span className="rounded-full bg-amber-500 px-1.5 text-[10px] text-white">{pendingCount}</span>}
            </button>
          ))}
        </div>
        <button type="button" onClick={() => void load()} className="text-xs font-semibold text-cyan-600 hover:underline">
          Refresh
        </button>
      </div>
      {error && <p className="mt-3 text-sm text-rose-500">{error}</p>}

      {tab === "incoming" && (
        <div className="mt-3">
          {!deviceId ? (
            <p className="py-8 text-center text-sm text-ink-600">Loading this device's identity…</p>
          ) : incoming === null ? (
            <div className="flex items-center gap-2 py-8 text-sm text-ink-600">
              <Loader2 className="animate-spin" size={16} /> Loading…
            </div>
          ) : incoming.length === 0 ? (
            <p className="rounded-xl border border-dashed border-line px-6 py-10 text-center text-sm text-ink-600">Nothing has been shared with you yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {incoming.map((share) => {
                const file = share.file;
                const canPreview = file && PREVIEWABLE_TYPES.has(file.contentType) && file.sizeBytes <= maxPreviewBytes;
                return (
                  <li key={share.shareId} className="flex flex-wrap items-center gap-3 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-semibold text-ink-950">{file?.name ?? "Encrypted file"}</div>
                      <div className="text-xs text-ink-500">
                        From {share.ownerName} · {file ? formatBytes(file.sizeBytes) : "—"} · {share.permission === "download" ? "view and save" : "view only"}
                        {share.expiresAt ? ` · until ${formatWhen(share.expiresAt)}` : ""}
                      </div>
                      {share.problem && <div className="mt-0.5 text-xs text-amber-500">{share.problem}</div>}
                    </div>
                    {statusChip(share.status)}
                    {share.status === "pending" ? (
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={busy !== null}
                          onClick={() => void act(share.shareId, () => respondToShare(share.shareId, true))}
                          className="flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-50"
                        >
                          <CheckCircle2 size={13} /> Accept
                        </button>
                        <button
                          type="button"
                          disabled={busy !== null}
                          onClick={() => void act(share.shareId, () => respondToShare(share.shareId, false))}
                          className="flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink-800 disabled:opacity-50"
                        >
                          <XCircle size={13} /> Decline
                        </button>
                      </div>
                    ) : (
                      <div className="flex gap-2">
                        {canPreview && file && (
                          <button
                            type="button"
                            disabled={busy !== null}
                            onClick={() =>
                              setPreviewing({
                                key: share.shareId,
                                name: file.name,
                                contentType: file.contentType,
                                category: file.category,
                                sizeBytes: file.sizeBytes,
                                load: () => previewShared(userId, share),
                                verifiedNote: `Decrypted in memory · signed by ${share.ownerName}'s device · content hash verified`,
                              })
                            }
                            className="flex items-center gap-1 rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink-800 disabled:opacity-50"
                          >
                            <Eye size={13} /> Preview
                          </button>
                        )}
                        {share.permission === "download" && file && (
                          <button
                            type="button"
                            disabled={busy !== null}
                            onClick={() =>
                              void act(share.shareId, async () => {
                                const saved = await saveShared(userId, share, currentFolder);
                                onNotice("success", `"${saved.name}" saved into your vault, re-sealed under your vault key and verified.`);
                                await onChanged();
                              })
                            }
                            className="flex items-center gap-1 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white disabled:opacity-50"
                          >
                            {busy === share.shareId ? <Loader2 className="animate-spin" size={13} /> : <Download size={13} />} Save to my vault
                          </button>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {tab === "outgoing" && (
        <div className="mt-3">
          {outgoing === null ? (
            <div className="flex items-center gap-2 py-8 text-sm text-ink-600">
              <Loader2 className="animate-spin" size={16} /> Loading…
            </div>
          ) : outgoing.length === 0 ? (
            <p className="rounded-xl border border-dashed border-line px-6 py-10 text-center text-sm text-ink-600">
              You have not shared anything yet. Select a file in My Files and choose Share — cloud backup does not need to be on.
            </p>
          ) : (
            <ul className="space-y-3">
              {outgoing.map((share) => {
                const ended = share.revokedAt !== null || (share.expiresAt !== null && new Date(share.expiresAt) <= new Date());
                return (
                  <li key={share.shareId} className="rounded-xl border border-line p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="min-w-0 flex-1 truncate font-semibold text-ink-950">{share.fileName}</span>
                      <span className="text-xs text-ink-500">
                        {share.permission === "download" ? "view and save" : "view only"} · {share.expiresAt ? `until ${formatWhen(share.expiresAt)}` : "no expiry"}
                      </span>
                      {ended ? (
                        <span className="rounded-full bg-canvas px-2 py-0.5 text-[11px] font-semibold text-ink-500">{share.revokedAt ? "revoked" : "expired"}</span>
                      ) : (
                        <button
                          type="button"
                          disabled={busy !== null}
                          onClick={() =>
                            void act(share.shareId, async () => {
                              const confirmed = await askDialog(
                                `Stop sharing "${share.fileName}" with everyone?\n\nThey can no longer download it. A copy someone already saved stays with them.`,
                                { title: "Revoke share", okLabel: "Revoke", cancelLabel: "Cancel" },
                              ).catch(() => false);
                              if (confirmed) await revokeShare(share.shareId, null);
                            })
                          }
                          className="rounded-lg border border-line px-3 py-1 text-xs font-semibold text-rose-500 disabled:opacity-50"
                        >
                          Revoke all
                        </button>
                      )}
                    </div>
                    <ul className="mt-2 space-y-1">
                      {share.recipients.map((recipient) => (
                        <li key={recipient.userId} className="flex items-center gap-2 text-xs">
                          <span className="flex-1 truncate text-ink-800">{recipient.name}</span>
                          {statusChip(recipient.status)}
                          {!ended && recipient.status !== "revoked" && recipient.status !== "declined" && (
                            <button
                              type="button"
                              disabled={busy !== null}
                              onClick={() => void act(`${share.shareId}:${recipient.userId}`, () => revokeShare(share.shareId, recipient.userId))}
                              className="text-rose-500 hover:underline disabled:opacity-50"
                            >
                              Revoke
                            </button>
                          )}
                        </li>
                      ))}
                    </ul>
                    {share.events.length > 0 && (
                      <details className="mt-2 text-xs text-ink-600">
                        <summary className="cursor-pointer font-semibold text-ink-700">
                          <Clock className="mr-1 inline" size={12} /> Access history ({share.events.length})
                        </summary>
                        <ul className="mt-1 space-y-0.5">
                          {share.events.map((event, index) => (
                            <li key={`${event.at}-${index}`}>
                              {formatWhen(event.at)} — {event.actor} {EVENT_LABELS[event.event] ?? event.event}
                            </li>
                          ))}
                        </ul>
                        <p className="mt-1 text-[11px] text-ink-400">"Opened" and "saved" are reported by the recipient's app; the server cannot see either.</p>
                      </details>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {previewing && <PreviewDialog subject={previewing} onClose={() => setPreviewing(null)} />}
    </section>
  );
}
