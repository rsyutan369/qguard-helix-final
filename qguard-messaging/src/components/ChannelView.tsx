import { useCallback, useEffect, useRef, useState } from "react";
import { BadgeCheck, Copy, KeyRound, Loader2, Megaphone, Send, ShieldAlert, Ticket } from "lucide-react";
import {
  CHANNEL_INVITE_CHOICES,
  CHANNEL_KEY_BATCH,
  chunk,
  formatInviteCode,
  planKeyDistribution,
  rowToSealed,
  sealedToRow,
  type ChannelPostRow,
  type ChannelStatus,
  type ReaderDevice,
  type SealedChannelPost,
} from "@/lib/channels";
import type { GroupRole } from "@/lib/group-chat";
import { supabase } from "@/lib/supabase";
import { safeInvoke } from "@/lib/tauri";

interface OpenedPost {
  plaintext: string;
  authenticated: boolean;
}

interface PostView {
  row: ChannelPostRow;
  opened: OpenedPost | null;
  /** Why it could not be opened; "no-key" while the epoch key has not arrived. */
  problem: "no-key" | string | null;
}

interface InviteRow {
  id: string;
  expires_at: string;
  max_uses: number;
  uses: number;
  revoked_at: string | null;
}

const NO_KEY_MARKER = "has not reached this device";
const POST_LIMIT = 100;

/**
 * A channel's timeline (roadmap 7.4). Staff (owner and up to 3 admins) post;
 * readers read. Posts are opened by the core with the epoch key this device
 * holds; staff devices hand the current key to every member device that lacks
 * it, and start a new epoch when someone who held it has left.
 */
export function ChannelView({
  channel,
  userId,
  myRole,
  memberDevices,
  staffDeviceIds,
  keyVersion,
  distributeSignal,
  memberName,
  loadSenderIdentity,
  onSendKey,
  onRequestKey,
}: {
  channel: { id: string; member_user_ids: string[] };
  userId: string;
  myRole: GroupRole;
  memberDevices: ReaderDevice[];
  staffDeviceIds: string[];
  keyVersion: number;
  distributeSignal: number;
  memberName: (userId: string) => string;
  loadSenderIdentity: (deviceId: string) => Promise<unknown | null>;
  onSendKey: (key: { epochId: string; seq: number; key: string }, deviceIds: string[]) => Promise<void>;
  onRequestKey: (deviceIds: string[]) => Promise<void>;
}) {
  const staff = myRole === "owner" || myRole === "admin";
  const [posts, setPosts] = useState<PostView[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [posting, setPosting] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [keyState, setKeyState] = useState<ChannelStatus | null>(null);
  const [invites, setInvites] = useState<InviteRow[]>([]);
  const [newCode, setNewCode] = useState<string | null>(null);
  const requestedRef = useRef(false);
  const distributingRef = useRef(false);
  // The parent rebuilds these every render; effects key on their CONTENT (the
  // strings below) and read the latest values from refs, so a re-render can
  // never loop back into another key hand-out.
  const latest = useRef({ memberDevices, members: channel.member_user_ids, staffDeviceIds, onSendKey, onRequestKey, loadSenderIdentity });
  latest.current = { memberDevices, members: channel.member_user_ids, staffDeviceIds, onSendKey, onRequestKey, loadSenderIdentity };
  const devicesKey = memberDevices.map((device) => device.deviceId).sort().join(",");
  const membersKey = [...channel.member_user_ids].sort().join(",");
  const staffKey = [...staffDeviceIds].sort().join(",");

  // ---- key hand-out (staff) -------------------------------------------------
  const ensureKeys = useCallback(async (): Promise<ChannelStatus | null> => {
    if (!staff || distributingRef.current) return null;
    distributingRef.current = true;
    try {
      const { memberDevices: devices, members, onSendKey: sendKey } = latest.current;
      let status = await safeInvoke<ChannelStatus>("channel_status", { channelId: channel.id });
      const plan = planKeyDistribution({ status, memberUserIds: members, memberDevices: devices, myUserId: userId });
      if (plan.needsEpoch || plan.rotate) {
        status = await safeInvoke<ChannelStatus>("channel_new_epoch", { channelId: channel.id });
      }
      if (plan.missing.length > 0 && status.currentEpoch) {
        const exported = await safeInvoke<{ epochId: string; seq: number; key: string }>("channel_key_export", { channelId: channel.id, epochId: status.currentEpoch });
        for (const batch of chunk(plan.missing, CHANNEL_KEY_BATCH)) {
          await sendKey(exported, batch.map((device) => device.deviceId));
          status = await safeInvoke<ChannelStatus>("channel_mark_distributed", {
            channelId: channel.id,
            epochId: exported.epochId,
            deviceIds: batch.map((device) => device.deviceId),
            userIds: Array.from(new Set(batch.map((device) => device.userId))),
          });
        }
      }
      setKeyState(status);
      return status;
    } catch (error) {
      setNote({ tone: "error", text: `Could not share the channel key: ${error instanceof Error ? error.message : String(error)}` });
      return null;
    } finally {
      distributingRef.current = false;
    }
  }, [channel.id, staff, userId]);

  useEffect(() => {
    if (staff) void ensureKeys();
    else void safeInvoke<ChannelStatus>("channel_status", { channelId: channel.id }).then(setKeyState).catch(() => setKeyState(null));
    // devicesKey/membersKey: re-run when membership really changes.
  }, [channel.id, devicesKey, distributeSignal, ensureKeys, keyVersion, membersKey, staff]);

  // ---- posts ----------------------------------------------------------------
  const openPost = useCallback(async (row: ChannelPostRow): Promise<PostView> => {
    try {
      const senderIdentity = await latest.current.loadSenderIdentity(row.sender_device_id);
      const opened = await safeInvoke<OpenedPost & { postId: string }>("channel_open_post", { post: rowToSealed(row), senderIdentity });
      return { row, opened: { plaintext: opened.plaintext, authenticated: opened.authenticated }, problem: null };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { row, opened: null, problem: message.includes(NO_KEY_MARKER) ? "no-key" : message };
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    void supabase
      .from("messaging_channel_posts")
      .select("id,conversation_id,sender_user_id,sender_device_id,epoch_id,nonce,ciphertext,tag,signature,created_at")
      .eq("conversation_id", channel.id)
      .order("created_at", { ascending: false })
      .limit(POST_LIMIT)
      .then(async ({ data, error }) => {
        if (cancelled) return;
        if (error) {
          setLoadError("Posts could not be loaded. They will load when the relay is reachable.");
          setLoading(false);
          return;
        }
        const rows = ((data ?? []) as ChannelPostRow[]).reverse();
        const views = await Promise.all(rows.map(openPost));
        if (!cancelled) {
          setPosts(views);
          setLoading(false);
        }
      });
    const subscription = supabase
      .channel(`channel-posts-${channel.id}-${crypto.randomUUID()}`)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "messaging_channel_posts", filter: `conversation_id=eq.${channel.id}` }, (payload) => {
        const row = payload.new as ChannelPostRow;
        void openPost(row).then((view) => {
          if (!cancelled) setPosts((current) => (current.some((item) => item.row.id === row.id) ? current : [...current, view]));
        });
      })
      .on("postgres_changes", { event: "DELETE", schema: "public", table: "messaging_channel_posts", filter: `conversation_id=eq.${channel.id}` }, (payload) => {
        const id = String((payload.old as { id?: string }).id ?? "");
        if (id) setPosts((current) => current.filter((item) => item.row.id !== id));
      })
      .subscribe();
    return () => {
      cancelled = true;
      void supabase.removeChannel(subscription);
    };
  }, [channel.id, openPost]);

  // A key arrived: retry what could not be opened for lack of one.
  useEffect(() => {
    if (keyVersion === 0) return;
    let cancelled = false;
    void (async () => {
      const retried = await Promise.all(posts.map((view) => (view.problem === "no-key" ? openPost(view.row) : Promise.resolve(view))));
      if (!cancelled) setPosts(retried);
    })();
    return () => { cancelled = true; };
    // Only a new key should trigger a retry pass.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keyVersion]);

  // A reader without the key asks the staff's devices once per session.
  const waitingForKey = !staff && (keyState?.currentEpoch == null || posts.some((view) => view.problem === "no-key"));
  useEffect(() => {
    const staffDevices = latest.current.staffDeviceIds;
    if (!waitingForKey || requestedRef.current || staffDevices.length === 0 || loading) return;
    requestedRef.current = true;
    void latest.current.onRequestKey(staffDevices).catch(() => { requestedRef.current = false; });
  }, [loading, staffKey, waitingForKey]);

  // ---- invites (staff) --------------------------------------------------------
  const loadInvites = useCallback(async () => {
    if (!staff) return;
    const { data } = await supabase
      .from("messaging_channel_invites")
      .select("id,expires_at,max_uses,uses,revoked_at")
      .eq("conversation_id", channel.id)
      .is("revoked_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false });
    setInvites(((data ?? []) as InviteRow[]).filter((invite) => invite.uses < invite.max_uses));
  }, [channel.id, staff]);
  useEffect(() => { void loadInvites(); }, [loadInvites]);

  const createInvite = async (hours: number, uses: number) => {
    setNote(null);
    const { data, error } = await supabase.rpc("create_messaging_channel_invite", { p_conversation_id: channel.id, p_valid_hours: hours, p_max_uses: uses });
    if (error || typeof data !== "string") {
      setNote({ tone: "error", text: error?.message ?? "The invite could not be created." });
      return;
    }
    setNewCode(data);
    void loadInvites();
  };

  const revokeInvite = async (id: string) => {
    const { error } = await supabase.rpc("revoke_messaging_channel_invite", { p_invite_id: id });
    if (error) setNote({ tone: "error", text: error.message });
    void loadInvites();
  };

  // ---- posting (staff) ----------------------------------------------------------
  const post = async () => {
    const text = draft.trim();
    if (!text) return;
    setPosting(true);
    setNote(null);
    try {
      // Whoever left since the last post must not be able to read this one.
      const status = await ensureKeys();
      if (!status?.currentEpoch) throw new Error("The channel key is not ready yet.");
      const postId = crypto.randomUUID();
      const sealed = await safeInvoke<SealedChannelPost>("channel_seal_post", { channelId: channel.id, postId, plaintext: text });
      const { error } = await supabase.from("messaging_channel_posts").insert(sealedToRow(sealed));
      if (error) throw error;
      setDraft("");
    } catch (error) {
      setNote({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setPosting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 rounded-lg border border-line bg-white p-3 text-xs text-ink-600">
        <Megaphone size={16} className="mt-0.5 shrink-0 text-violet-600" />
        <span>
          Channel posts are encrypted once with the channel key and signed by the posting device. Only the owner and admins post.
          {staff
            ? ` The key is shared with ${keyState ? keyState.recipients.length : "…"} reader device${keyState?.recipients.length === 1 ? "" : "s"}; when someone leaves, the next post uses a new key they never get.`
            : " Other readers cannot see that you read this channel."}
        </span>
      </div>

      {staff && (
        <div className="rounded-lg border border-line bg-white p-3 text-xs text-ink-700">
          <div className="flex items-center gap-2 font-bold text-ink-900"><Ticket size={14} /> Invites</div>
          <div className="mt-2 flex flex-wrap gap-2">
            {CHANNEL_INVITE_CHOICES.map((choice) => (
              <button key={choice.label} type="button" onClick={() => void createInvite(choice.hours, choice.uses)} className="rounded-md border border-line bg-canvas px-2.5 py-1 font-semibold hover:bg-white">
                New invite: {choice.label}
              </button>
            ))}
          </div>
          {newCode && (
            <div className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 p-2">
              <div className="font-semibold text-emerald-900">Share this code privately. It is shown only now.</div>
              <div className="mt-1 flex items-center gap-2">
                <code className="font-mono text-sm font-bold tracking-wide text-ink-950">{formatInviteCode(newCode)}</code>
                <button type="button" onClick={() => void navigator.clipboard?.writeText(newCode)} className="icon-button h-7 w-7" title="Copy"><Copy size={13} /></button>
              </div>
            </div>
          )}
          {invites.length > 0 && (
            <ul className="mt-2 space-y-1">
              {invites.map((invite) => (
                <li key={invite.id} className="flex items-center justify-between gap-2 rounded-md bg-canvas px-2 py-1">
                  <span>{invite.uses}/{invite.max_uses} used · expires {new Date(invite.expires_at).toLocaleString()}</span>
                  <button type="button" onClick={() => void revokeInvite(invite.id)} className="font-semibold text-rose-700">Revoke</button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {loading && <div className="flex items-center gap-2 text-sm text-ink-500"><Loader2 size={14} className="animate-spin" /> Loading channel posts…</div>}
      {loadError && <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">{loadError}</div>}
      {!loading && !loadError && posts.length === 0 && (
        <div className="rounded-lg border border-dashed border-line bg-white/70 p-6 text-center text-sm text-ink-500">
          {staff ? "No posts yet. Write the first one below." : "No posts yet."}
        </div>
      )}
      {waitingForKey && !loading && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
          <KeyRound size={14} className="mt-0.5 shrink-0" />
          This device does not have the channel key yet. It has asked the channel&apos;s owner and admins; the key arrives the next time
          one of them has the channel open.
        </div>
      )}

      <div className="space-y-3">
        {posts.map((view) => (
          <article key={view.row.id} className="rounded-2xl border border-line bg-white px-4 py-3 shadow-tight">
            <div className="mb-1 flex items-center gap-2 text-[11px] font-bold text-violet-700">
              {view.row.sender_user_id === userId ? "You" : memberName(view.row.sender_user_id)}
              <span className="font-medium text-ink-400">{new Date(view.row.created_at).toLocaleString()}</span>
              {view.opened?.authenticated && <BadgeCheck size={12} className="text-emerald-600" aria-label="Signed by a recorded device" />}
            </div>
            {view.opened ? (
              <div className="whitespace-pre-wrap break-words text-sm text-ink-900">{view.opened.plaintext}</div>
            ) : view.problem === "no-key" ? (
              <div className="text-xs italic text-ink-500">Waiting for the key to this post.</div>
            ) : (
              <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-700"><ShieldAlert size={13} /> {view.problem}</div>
            )}
            {view.opened && !view.opened.authenticated && (
              <div className="mt-1 text-[11px] text-amber-700">Signed by a device you have not approved yet.</div>
            )}
          </article>
        ))}
      </div>

      {note && (
        <div className={`rounded-md border p-2 text-xs font-semibold ${note.tone === "ok" ? "border-emerald-100 bg-emerald-50 text-emerald-700" : "border-rose-100 bg-rose-50 text-rose-700"}`}>
          {note.text}
        </div>
      )}

      {staff && (
        <div className="flex items-end gap-2 rounded-lg border border-line bg-white p-3">
          <textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            rows={2}
            maxLength={20_000}
            placeholder="Write a post for every reader"
            aria-label="Channel post"
            className="min-w-0 flex-1 resize-none rounded-md border border-line bg-canvas px-3 py-2 text-sm outline-none focus:border-violet-300"
          />
          <button
            type="button"
            disabled={posting || !draft.trim()}
            onClick={() => void post()}
            className="flex h-10 items-center gap-2 rounded-lg bg-violet-600 px-4 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-50"
          >
            {posting ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />} Post
          </button>
        </div>
      )}
    </div>
  );
}
