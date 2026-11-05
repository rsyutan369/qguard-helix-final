import {
  AlertTriangle,
  ArrowDownLeft,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  Clock,
  History,
  KeyRound,
  LockKeyhole,
  MessageSquare,
  Phone,
  PhoneMissed,
  RefreshCw,
  Search,
  ShieldCheck,
  Timer,
  Trash2,
  Users,
  Video,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { UserAvatar } from "@/components/UserAvatar";
import { useCall } from "@/components/call/CallProvider";
import {
  CALL_FILTERS,
  CALL_LOG_CHANGED,
  OUTCOME_LABEL,
  callHistory,
  callStats,
  describeCall,
  filterCalls,
  formatCallDuration,
  formatTalkTime,
  groupCallsByDay,
  outcomeIsAlert,
  type CallFilter,
  type CallRecord,
} from "@/lib/call-history";
import type { CallMedia } from "@/lib/call-types";
import { ask as askDialog } from "@/lib/tauri-dialog";
import type { ContactSummary, ConversationSummary } from "@/lib/types";
import { useIsMobile } from "@/lib/use-mobile";

// Calls: recent, missed, incoming and outgoing calls, and where new ones start.
//
// Every entry and every figure here comes from the call history the Rust core
// keeps sealed on this device (src-tauri/src/call_log.rs). The page sits behind
// the Secure Chat lock, and the core refuses to list the history while that
// lock is closed. Calling back hands over to Secure Chat, which picks the
// devices to ring with its own trust rules; this page never does.

interface CallsPageProps {
  conversations: ConversationSummary[];
  contacts: ContactSummary[];
  /** Start a call with this person (through Secure Chat). */
  onCall: (peerUserId: string, media: CallMedia) => void;
  /** Open the direct chat with this person. */
  onMessage: (peerUserId: string) => void;
}

function contactName(contact: ContactSummary): string {
  return contact.alias?.trim() || contact.display_name?.trim() || (contact.username ? `@${contact.username}` : "Secure contact");
}

function timeOfDay(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function fullDate(ms: number): string {
  return new Date(ms).toLocaleString([], { weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "message" in error) return String((error as { message: unknown }).message);
  return "Something went wrong.";
}

/** Direction / outcome glyph shown on the avatar. */
function DirectionBadge({ record }: { record: CallRecord }) {
  const missed = record.outcome === "missed";
  const Icon = missed ? PhoneMissed : record.direction === "incoming" ? ArrowDownLeft : ArrowUpRight;
  const tone = missed || record.outcome === "failed" ? "bg-rose-500" : record.outcome === "completed" ? "bg-emerald-500" : "bg-ink-500";
  return (
    <span className={`absolute -bottom-1.5 -right-1.5 flex h-5 w-5 items-center justify-center rounded-full text-white ring-2 ring-white ${tone}`} aria-hidden>
      <Icon size={11} strokeWidth={2.5} />
    </span>
  );
}

function StatTile({ icon, label, value, detail, tone = "default" }: {
  icon: ReactNode;
  label: string;
  value: string;
  detail: string;
  tone?: "default" | "alert" | "ok";
}) {
  const valueTone = tone === "alert" ? "text-rose-600" : tone === "ok" ? "text-emerald-600" : "text-ink-950";
  return (
    <div className="min-w-0 rounded-xl border border-line bg-white p-3.5">
      <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wide text-ink-500">
        {icon}
        <span className="truncate">{label}</span>
      </div>
      <div className={`mt-2 text-2xl font-bold tabular-nums leading-none ${valueTone}`}>{value}</div>
      <div className="mt-1.5 truncate text-[11px] text-ink-500">{detail}</div>
    </div>
  );
}

/** A panel that is a bottom sheet on phones and a centred dialog elsewhere. */
function Sheet({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-ink-950/50 backdrop-blur-sm sm:items-center sm:p-4" role="dialog" aria-modal="true" aria-label={title} onClick={onClose}>
      <div
        className="flex max-h-[88vh] w-full flex-col overflow-hidden rounded-t-2xl border border-line bg-white shadow-soft sm:max-w-md sm:rounded-2xl"
        onClick={(event) => event.stopPropagation()}
        style={{ paddingBottom: "env(safe-area-inset-bottom)" }}
      >
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
          <h2 className="truncate text-sm font-bold text-ink-950">{title}</h2>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-ink-500 hover:bg-canvas" aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

function CallBackButtons({ disabled, onCall, compact = false }: { disabled: boolean; onCall: (media: CallMedia) => void; compact?: boolean }) {
  const size = compact ? "h-9 w-9" : "h-10 w-10";
  return (
    <span className="flex shrink-0 items-center gap-1.5">
      <button
        type="button"
        disabled={disabled}
        onClick={(event) => { event.stopPropagation(); onCall("voice"); }}
        className={`flex ${size} items-center justify-center rounded-full border border-line text-cyan-700 transition hover:border-cyan-200 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-40`}
        title="Voice call"
        aria-label="Voice call"
      >
        <Phone size={16} />
      </button>
      <button
        type="button"
        disabled={disabled}
        onClick={(event) => { event.stopPropagation(); onCall("video"); }}
        className={`flex ${size} items-center justify-center rounded-full border border-line text-violet-700 transition hover:border-violet-200 hover:bg-violet-50 disabled:cursor-not-allowed disabled:opacity-40`}
        title="Video call"
        aria-label="Video call"
      >
        <Video size={16} />
      </button>
    </span>
  );
}

function ProtectionRow({ ok, title, detail }: { ok: boolean | null; title: string; detail: string }) {
  return (
    <li className="flex items-start gap-2.5 py-2">
      {ok === null ? (
        <span className="mt-0.5 h-4 w-4 shrink-0 rounded-full border border-line" aria-hidden />
      ) : ok ? (
        <CheckCircle2 className="mt-0.5 shrink-0 text-emerald-600" size={16} />
      ) : (
        <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={16} />
      )}
      <span className="min-w-0">
        <span className="block text-[13px] font-semibold text-ink-950">{title}</span>
        <span className="mt-0.5 block text-[11.5px] leading-snug text-ink-600">{detail}</span>
      </span>
    </li>
  );
}

function CallDetail({ record, name, callDisabled, onCall, onMessage, onDelete }: {
  record: CallRecord;
  name: string;
  callDisabled: boolean;
  onCall: (media: CallMedia) => void;
  onMessage: () => void;
  onDelete: () => void;
}) {
  const connected = record.outcome === "completed";
  const ringSecs = Math.max(0, Math.round(((record.answeredAt ?? record.endedAt) - record.startedAt) / 1000));
  return (
    <div className="p-5">
      <div className="flex flex-col items-center text-center">
        <span className="relative">
          <UserAvatar userId={record.group ? null : record.peerUserIds[0]} name={name} size={72} />
          {record.group && (
            <span className="absolute -bottom-1 -right-1 flex h-7 w-7 items-center justify-center rounded-full bg-violet-600 text-white ring-2 ring-white">
              <Users size={13} />
            </span>
          )}
        </span>
        <div className="mt-3 max-w-full truncate text-lg font-bold text-ink-950">{name}</div>
        <div className={`mt-0.5 text-sm ${outcomeIsAlert(record.outcome) ? "font-semibold text-rose-600" : "text-ink-600"}`}>{describeCall(record)}</div>
        <div className="mt-1 text-xs text-ink-500">{fullDate(record.startedAt)}</div>
      </div>

      {!record.group && (
        <div className="mt-4 grid grid-cols-3 gap-2">
          <button type="button" disabled={callDisabled} onClick={() => onCall("voice")} className="flex flex-col items-center gap-1.5 rounded-xl border border-line bg-white py-3 text-xs font-semibold text-ink-800 hover:bg-canvas disabled:opacity-40">
            <Phone size={18} className="text-cyan-700" /> Voice
          </button>
          <button type="button" disabled={callDisabled} onClick={() => onCall("video")} className="flex flex-col items-center gap-1.5 rounded-xl border border-line bg-white py-3 text-xs font-semibold text-ink-800 hover:bg-canvas disabled:opacity-40">
            <Video size={18} className="text-violet-700" /> Video
          </button>
          <button type="button" onClick={onMessage} className="flex flex-col items-center gap-1.5 rounded-xl border border-line bg-white py-3 text-xs font-semibold text-ink-800 hover:bg-canvas">
            <MessageSquare size={18} className="text-ink-700" /> Message
          </button>
        </div>
      )}
      {record.group && (
        <p className="mt-4 rounded-xl border border-line bg-canvas px-3 py-2.5 text-center text-xs text-ink-600">
          Group calls start from the group's chat.
        </p>
      )}

      <dl className="mt-5 grid grid-cols-2 gap-x-4 gap-y-3 rounded-xl border border-line p-4 text-[12.5px]">
        <div>
          <dt className="text-[11px] font-bold uppercase tracking-wide text-ink-500">Status</dt>
          <dd className={`mt-0.5 font-semibold ${outcomeIsAlert(record.outcome) ? "text-rose-600" : connected ? "text-emerald-600" : "text-ink-800"}`}>{OUTCOME_LABEL[record.outcome]}</dd>
        </div>
        <div>
          <dt className="text-[11px] font-bold uppercase tracking-wide text-ink-500">Type</dt>
          <dd className="mt-0.5 font-semibold capitalize text-ink-800">{record.group ? "Group " : ""}{record.media}</dd>
        </div>
        <div>
          <dt className="text-[11px] font-bold uppercase tracking-wide text-ink-500">{connected ? "Talk time" : "Rang for"}</dt>
          <dd className="mt-0.5 font-mono font-semibold tabular-nums text-ink-800">{formatCallDuration(connected ? record.durationSecs : ringSecs)}</dd>
        </div>
        <div>
          <dt className="text-[11px] font-bold uppercase tracking-wide text-ink-500">Ended</dt>
          <dd className="mt-0.5 font-semibold text-ink-800">{timeOfDay(record.endedAt)}</dd>
        </div>
      </dl>

      {record.failure && (
        <div className="mt-3 flex items-start gap-2 rounded-xl border border-line bg-rose-50 p-3 text-xs text-ink-800">
          <AlertTriangle className="mt-0.5 shrink-0 text-rose-500" size={14} />
          <span><span className="font-semibold">Why it failed:</span> {record.failure}</span>
        </div>
      )}

      <section className="mt-5">
        <h3 className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wide text-ink-500">
          <ShieldCheck size={13} className="text-emerald-600" /> Protection
        </h3>
        <ul className="mt-1 divide-y divide-line">
          <ProtectionRow
            ok={connected ? true : null}
            title={connected ? "End-to-end encrypted" : "No media was exchanged"}
            detail={connected
              ? "Key agreed with X25519 + ML-KEM-1024; every audio and video frame sealed with AES-256-GCM. The call never runs without it."
              : "The call did not connect, so nothing was sent."}
          />
          {connected && !record.group && (
            <>
              <ProtectionRow
                ok={record.forwardSecret}
                title={record.forwardSecret ? "Forward secret" : record.forwardSecret === false ? "Not forward secret" : "Forward secrecy not reported"}
                detail={record.forwardSecret
                  ? "Also keyed with a key pair made for this call alone and then destroyed."
                  : record.forwardSecret === false
                    ? "Their app predates per-call keys; the call used their long-term device key only."
                    : "The core did not report how this call was keyed."}
              />
              <ProtectionRow
                ok={record.peerVerified}
                title={record.peerVerified ? "Their device proved its identity" : record.peerVerified === false ? "Their device identity was not proven" : "Identity proof not reported"}
                detail={record.peerVerified
                  ? "It signed the call with the identity registered for that device."
                  : "Compare safety numbers on your next call to be sure who you are talking to."}
              />
            </>
          )}
          <ProtectionRow
            ok
            title="History kept on this device only"
            detail="This entry is sealed with your device key and is never uploaded or synced."
          />
        </ul>
      </section>

      <button type="button" onClick={onDelete} className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl border border-line py-2.5 text-xs font-bold text-rose-600 hover:bg-rose-50">
        <Trash2 size={14} /> Remove from history
      </button>
    </div>
  );
}

function NewCallPicker({ contacts, callDisabled, onCall }: {
  contacts: ContactSummary[];
  callDisabled: boolean;
  onCall: (peerUserId: string, media: CallMedia) => void;
}) {
  const [query, setQuery] = useState("");
  const callable = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return contacts
      .filter((contact) => contact.trust_state === "added" || contact.trust_state === "restricted")
      .filter((contact) => !needle || contactName(contact).toLocaleLowerCase().includes(needle) || contact.username.toLocaleLowerCase().includes(needle))
      .sort((a, b) => contactName(a).localeCompare(contactName(b)));
  }, [contacts, query]);
  return (
    <div>
      <div className="border-b border-line p-4">
        <label className="relative block">
          <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-400" size={15} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search contacts"
            aria-label="Search contacts"
            className="h-10 w-full rounded-xl border border-line bg-canvas pl-9 pr-3 text-sm text-ink-950 outline-none focus:border-cyan-300"
          />
        </label>
      </div>
      {callable.length === 0 ? (
        <p className="px-5 py-10 text-center text-sm text-ink-600">
          {contacts.length === 0 ? "No contacts yet. Add someone in Secure Chat → Contacts, then call them here." : "No contact matches."}
        </p>
      ) : (
        <ul className="divide-y divide-line">
          {callable.map((contact) => (
            <li key={contact.id} className="flex items-center gap-3 px-4 py-3">
              <UserAvatar userId={contact.contact_user_id} name={contactName(contact)} size={40} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-semibold text-ink-950">{contactName(contact)}</span>
                <span className="block truncate text-xs text-ink-500">@{contact.username}</span>
              </span>
              <CallBackButtons compact disabled={callDisabled} onCall={(media) => onCall(contact.contact_user_id, media)} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function CallsPage({ conversations, contacts, onCall, onMessage }: CallsPageProps) {
  const isMobile = useIsMobile();
  const call = useCall();
  const [records, setRecords] = useState<CallRecord[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [filter, setFilter] = useState<CallFilter>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  // Missed calls that were new when the page opened keep their marker for this
  // visit, even though opening the page marks them seen.
  const [freshMissed, setFreshMissed] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    try {
      const list = await callHistory.list();
      setRecords(list);
      setLoadError(null);
      return list;
    } catch (error) {
      setLoadError(describeError(error));
      return null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const list = await load();
      if (cancelled || !list) return;
      const unseen = list.filter((record) => record.outcome === "missed" && !record.seen).map((record) => record.id);
      if (unseen.length > 0) {
        setFreshMissed(new Set(unseen));
        await callHistory.markSeen().catch(() => undefined);
      }
    })();
    // A call that ends while the page is open appears straight away.
    const onChange = () => { void load(); };
    window.addEventListener(CALL_LOG_CHANGED, onChange);
    return () => {
      cancelled = true;
      window.removeEventListener(CALL_LOG_CHANGED, onChange);
    };
  }, [load]);

  const contactByUser = useMemo(() => new Map(contacts.map((contact) => [contact.contact_user_id, contact])), [contacts]);
  const nameOf = useCallback(
    (record: CallRecord) => {
      if (record.group) {
        const conversation = conversations.find((item) => item.id === record.conversationId);
        return conversation?.title?.trim() || record.peerName;
      }
      const contact = contactByUser.get(record.peerUserIds[0]);
      return contact ? contactName(contact) : record.peerName;
    },
    [contactByUser, conversations],
  );

  const all = records ?? [];
  const stats = useMemo(() => callStats(all, 7), [all]);
  const counts = useMemo(() => Object.fromEntries(CALL_FILTERS.map(({ id }) => [id, filterCalls(all, id, "").length])) as Record<CallFilter, number>, [all]);
  const visible = useMemo(() => {
    const byName = query.trim().toLocaleLowerCase();
    return filterCalls(all, filter, "").filter((record) => !byName || nameOf(record).toLocaleLowerCase().includes(byName));
  }, [all, filter, query, nameOf]);
  const groups = useMemo(() => groupCallsByDay(visible), [visible]);
  const selected = all.find((record) => record.id === selectedId) ?? null;
  // On a wide screen the first entry is shown beside the list.
  const shownDetail = selected ?? (!isMobile ? visible[0] ?? null : null);

  const busy = !["idle", "ended"].includes(call.state.phase);
  const callDisabled = !call.supported || busy;

  const startCall = (peerUserId: string, media: CallMedia) => {
    setPicking(false);
    setSelectedId(null);
    onCall(peerUserId, media);
  };

  const remove = async (record: CallRecord) => {
    try {
      await callHistory.remove([record.id]);
      setSelectedId(null);
      setNotice("Removed from your call history.");
    } catch (error) {
      setNotice(describeError(error));
    }
  };

  const clearAll = async () => {
    const confirmed = await askDialog(
      "Clear your whole call history on this device?\n\nEvery entry is deleted. It exists nowhere else, so this cannot be undone.",
      { title: "Clear call history", okLabel: "Clear history", cancelLabel: "Cancel" },
    ).catch(() => false);
    if (!confirmed) return;
    try {
      const removed = await callHistory.clear();
      setSelectedId(null);
      setNotice(`${removed} ${removed === 1 ? "entry" : "entries"} cleared.`);
    } catch (error) {
      setNotice(describeError(error));
    }
  };

  const detail = shownDetail && (
    <CallDetail
      record={shownDetail}
      name={nameOf(shownDetail)}
      callDisabled={callDisabled}
      onCall={(media) => startCall(shownDetail.peerUserIds[0], media)}
      onMessage={() => onMessage(shownDetail.peerUserIds[0])}
      onDelete={() => void remove(shownDetail)}
    />
  );

  return (
    <div className="grid min-w-0 grid-cols-1 gap-4 pb-6">
      {/* Header: what this is, how to start, and the week in numbers. */}
      <section className="shell-card min-w-0 overflow-hidden">
        <div className="h-1 w-full bg-gradient-to-r from-cyan-500 via-violet-600 to-cyan-500" aria-hidden />
        <div className="flex flex-wrap items-start justify-between gap-4 p-4 sm:p-5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 to-violet-600 text-white shadow-tight">
              <Phone size={20} />
            </span>
            <div className="min-w-0">
              <h1 className="text-lg font-bold text-ink-950">Calls</h1>
              <p className="text-xs leading-snug text-ink-600">
                Quantum-encrypted voice and video · history sealed on this device only
              </p>
            </div>
          </div>
          <div className="flex w-full gap-2 sm:w-auto">
            <button
              type="button"
              onClick={() => setPicking(true)}
              disabled={!call.supported}
              className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-600 px-4 py-2.5 text-sm font-bold text-white shadow-tight hover:opacity-90 disabled:opacity-50 sm:flex-none"
            >
              <Phone size={15} /> New call
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 border-t border-line bg-canvas/60 p-4 lg:grid-cols-4">
          <StatTile icon={<History size={13} />} label="Calls · 7 days" value={String(stats.total)} detail={`${all.length} in history`} />
          <StatTile
            icon={<PhoneMissed size={13} />}
            label="Missed · 7 days"
            value={String(stats.missed)}
            detail={freshMissed.size > 0 ? `${freshMissed.size} new since you last looked` : "None waiting"}
            tone={stats.missed > 0 ? "alert" : "default"}
          />
          <StatTile icon={<Timer size={13} />} label="Talk time · 7 days" value={formatTalkTime(stats.talkSecs)} detail={`${stats.connected} connected ${stats.connected === 1 ? "call" : "calls"}`} />
          <StatTile
            icon={<KeyRound size={13} />}
            label="Forward secret"
            value={stats.connected > 0 ? `${stats.forwardSecret}/${stats.connected}` : "—"}
            detail="Connected calls keyed with a one-time key"
            tone={stats.connected > 0 && stats.forwardSecret === stats.connected ? "ok" : "default"}
          />
        </div>
      </section>

      {!call.supported && (
        <div className="flex items-start gap-3 rounded-xl border border-line bg-amber-50 p-3.5 text-sm text-ink-800">
          <AlertTriangle className="mt-0.5 shrink-0 text-amber-500" size={16} />
          <span>This device cannot encrypt call media end to end, so it cannot place calls. Your history is still shown.</span>
        </div>
      )}

      {notice && (
        <div className="flex items-start gap-3 rounded-xl border border-line bg-cyan-50 p-3 text-sm text-ink-800" role="status">
          <CheckCircle2 className="mt-0.5 shrink-0 text-cyan-600" size={16} />
          <span className="min-w-0 flex-1">{notice}</span>
          <button type="button" onClick={() => setNotice(null)} className="text-ink-500" aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="shell-card min-w-0 p-0">
          {/* Filters + search */}
          <div className="flex flex-col gap-3 border-b border-line p-4">
            <div className="-mx-1 flex gap-1.5 overflow-x-auto px-1 pb-0.5" role="tablist" aria-label="Filter calls">
              {CALL_FILTERS.map(({ id, label }) => {
                const active = filter === id;
                return (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => setFilter(id)}
                    className={`flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-bold transition ${
                      active ? "bg-ink-950 text-white" : "border border-line bg-white text-ink-700 hover:bg-canvas"
                    }`}
                  >
                    {label}
                    <span className={`rounded-full px-1.5 text-[10px] tabular-nums ${active ? "bg-white/20" : id === "missed" && counts.missed > 0 ? "bg-rose-50 text-rose-600" : "bg-canvas text-ink-500"}`}>
                      {counts[id]}
                    </span>
                  </button>
                );
              })}
            </div>
            <label className="relative block">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-400" size={15} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by name"
                aria-label="Search calls"
                className="h-10 w-full rounded-xl border border-line bg-canvas pl-9 pr-3 text-sm text-ink-950 outline-none focus:border-cyan-300"
              />
            </label>
          </div>

          {/* The list */}
          {records === null && !loadError ? (
            <ul className="divide-y divide-line" aria-busy="true" aria-label="Loading calls">
              {[0, 1, 2, 3].map((n) => (
                <li key={n} className="flex items-center gap-3 px-4 py-3.5">
                  <span className="h-11 w-11 animate-pulse rounded-full bg-canvas" />
                  <span className="flex-1 space-y-2">
                    <span className="block h-3 w-1/3 animate-pulse rounded bg-canvas" />
                    <span className="block h-2.5 w-1/2 animate-pulse rounded bg-canvas" />
                  </span>
                </li>
              ))}
            </ul>
          ) : loadError ? (
            <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
              <LockKeyhole className="text-ink-400" size={26} />
              <p className="max-w-sm text-sm text-ink-700">{loadError}</p>
              <button type="button" onClick={() => void load()} className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-xs font-bold text-ink-800 hover:bg-canvas">
                <RefreshCw size={13} /> Try again
              </button>
            </div>
          ) : groups.length === 0 ? (
            <div className="flex flex-col items-center gap-3 px-6 py-14 text-center">
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-canvas text-ink-500">
                {filter === "missed" ? <PhoneMissed size={24} /> : <Phone size={24} />}
              </span>
              <p className="text-sm font-semibold text-ink-900">
                {all.length === 0 ? "No calls yet" : query ? `Nothing matches "${query}"` : `No ${filter === "all" ? "" : `${CALL_FILTERS.find((f) => f.id === filter)?.label.toLowerCase()} `}calls`}
              </p>
              <p className="max-w-sm text-xs leading-relaxed text-ink-600">
                {all.length === 0
                  ? "Calls you make and receive on this device appear here, including missed ones. Start one with New call, or from any chat."
                  : "Try another filter."}
              </p>
            </div>
          ) : (
            <div>
              {groups.map((group) => (
                <div key={group.key}>
                  <div className="sticky top-0 z-[1] border-b border-line bg-canvas/95 px-4 py-1.5 text-[11px] font-bold uppercase tracking-wide text-ink-500 backdrop-blur">
                    {group.label}
                  </div>
                  <ul className="divide-y divide-line">
                    {group.records.map((record) => {
                      const name = nameOf(record);
                      const alert = outcomeIsAlert(record.outcome);
                      const active = shownDetail?.id === record.id;
                      const sub = record.outcome === "completed"
                        ? formatCallDuration(record.durationSecs)
                        : record.outcome === "missed" ? null : OUTCOME_LABEL[record.outcome];
                      return (
                        <li key={record.id}>
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => setSelectedId(record.id)}
                            onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedId(record.id); } }}
                            className={`flex w-full cursor-pointer items-center gap-3 px-4 py-3 text-left transition hover:bg-canvas ${active && !isMobile ? "bg-cyan-50/60" : ""}`}
                            aria-label={`${name}, ${describeCall(record)}, ${timeOfDay(record.startedAt)}`}
                          >
                            <span className="relative shrink-0">
                              <UserAvatar userId={record.group ? null : record.peerUserIds[0]} name={name} size={44} />
                              <DirectionBadge record={record} />
                            </span>
                            <span className="min-w-0 flex-1">
                              <span className="flex items-center gap-1.5">
                                <span className={`truncate text-[14.5px] font-semibold ${alert ? "text-rose-600" : "text-ink-950"}`}>{name}</span>
                                {freshMissed.has(record.id) && <span className="h-2 w-2 shrink-0 rounded-full bg-rose-500" aria-label="New" />}
                              </span>
                              <span className="mt-0.5 flex min-w-0 items-center gap-1.5 text-xs text-ink-600">
                                {record.group ? <Users size={12} className="shrink-0" /> : record.media === "voice" ? <Phone size={12} className="shrink-0" /> : <Video size={12} className="shrink-0" />}
                                <span className="truncate">{describeCall(record)}{sub ? ` · ${sub}` : ""}</span>
                              </span>
                            </span>
                            <span className="flex shrink-0 items-center gap-3">
                              <span className="hidden text-right text-xs tabular-nums text-ink-500 sm:block">{timeOfDay(record.startedAt)}</span>
                              {!record.group && (
                                <span className="hidden sm:block">
                                  <CallBackButtons compact disabled={callDisabled} onCall={(media) => startCall(record.peerUserIds[0], media)} />
                                </span>
                              )}
                              <span className="flex flex-col items-end gap-1 sm:hidden">
                                <span className="text-[11px] tabular-nums text-ink-500">{timeOfDay(record.startedAt)}</span>
                                {!record.group && (
                                  <button
                                    type="button"
                                    disabled={callDisabled}
                                    onClick={(event) => { event.stopPropagation(); startCall(record.peerUserIds[0], record.media); }}
                                    className="flex h-8 w-8 items-center justify-center rounded-full text-cyan-700 hover:bg-cyan-50 disabled:opacity-40"
                                    aria-label={`Call ${name} back (${record.media})`}
                                  >
                                    {record.media === "voice" ? <Phone size={16} /> : <Video size={16} />}
                                  </button>
                                )}
                              </span>
                              <ChevronRight className="hidden text-ink-300 lg:block" size={16} aria-hidden />
                            </span>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Details beside the list on wide screens. */}
        {!isMobile && (
          <aside className="hidden min-w-0 lg:block">
            <div className="shell-card sticky top-4 min-w-0 p-0">
              {detail ?? (
                <div className="flex flex-col items-center gap-2 px-6 py-14 text-center text-sm text-ink-600">
                  <Clock size={22} className="text-ink-400" />
                  Select a call to see its details.
                </div>
              )}
            </div>
          </aside>
        )}
      </div>

      <section className="flex flex-col items-start justify-between gap-3 rounded-xl border border-line bg-white p-4 text-[11.5px] leading-relaxed text-ink-600 sm:flex-row sm:items-center">
        <span className="flex items-start gap-2">
          <LockKeyhole size={14} className="mt-0.5 shrink-0 text-emerald-600" />
          Your call history is encrypted with this device's key and never leaves it. Calls ring on every page, even while Secure Chat is locked; this list opens only after you unlock it.
        </span>
        <button
          type="button"
          disabled={all.length === 0}
          onClick={() => void clearAll()}
          className="flex shrink-0 items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 font-bold text-rose-600 hover:bg-rose-50 disabled:opacity-40"
        >
          <Trash2 size={13} /> Clear history
        </button>
      </section>

      {/* Phones (and narrow windows): details in a sheet. */}
      {selected && (isMobile || typeof window !== "undefined" && window.innerWidth < 1024) && (
        <Sheet title="Call details" onClose={() => setSelectedId(null)}>{detail}</Sheet>
      )}
      {picking && (
        <Sheet title="New quantum-encrypted call" onClose={() => setPicking(false)}>
          <NewCallPicker contacts={contacts} callDisabled={callDisabled} onCall={startCall} />
        </Sheet>
      )}
    </div>
  );
}
