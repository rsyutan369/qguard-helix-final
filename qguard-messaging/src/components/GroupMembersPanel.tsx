import { useState } from "react";
import { Crown, Loader2, LogOut, Pencil, Shield, ShieldOff, UserMinus, UserPlus, Users, X } from "lucide-react";
import {
  GROUP_MAX_ADMINS,
  GROUP_MAX_OTHER_MEMBERS,
  GROUP_NAME_MAX_CHARS,
  groupPermissions,
  sanitizeGroupName,
  type GroupRole,
} from "@/lib/group-chat";

export interface GroupMember {
  userId: string;
  name: string;
  role: GroupRole;
}

/**
 * Group members (roadmap 7.1). Who may do what mirrors migration 042: the
 * owner renames, appoints up to 3 admins and can hand the group over; admins
 * add their contacts and remove plain members; anyone but the owner can leave.
 * Removal and leaving only revoke the server's membership rows, and because
 * every message is sealed per device there is no shared key to rotate.
 */
export function GroupMembersPanel({ myUserId, groupName, members, addable, onRename, onAdd, onRemove, onSetAdmin, onTransfer, onLeave, onClose }: {
  myUserId: string;
  groupName: string | null;
  members: GroupMember[];
  addable: Array<{ userId: string; name: string }>;
  onRename: (name: string) => Promise<void>;
  onAdd: (userId: string) => Promise<void>;
  onRemove: (userId: string) => Promise<void>;
  onSetAdmin: (userId: string, admin: boolean) => Promise<void>;
  onTransfer: (userId: string) => Promise<void>;
  onLeave: () => Promise<void>;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState("");
  const [renaming, setRenaming] = useState<string | null>(null);
  const [confirmTransfer, setConfirmTransfer] = useState<string | null>(null);
  const myRole = members.find((member) => member.userId === myUserId)?.role ?? null;
  const adminCount = members.filter((member) => member.role === "admin").length;
  const mine = groupPermissions(myRole, null, adminCount);
  const full = members.length - 1 >= GROUP_MAX_OTHER_MEMBERS;

  const run = async (key: string, action: () => Promise<void>) => {
    setBusy(key);
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  };

  const smallButton = "flex items-center gap-1 rounded-md border border-line bg-white px-2 py-1 text-xs font-bold hover:bg-canvas disabled:opacity-60";

  return (
    <div className="rounded-lg border border-violet-200 bg-white p-4 text-sm text-ink-700 shadow-tight">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-bold text-ink-950"><Users size={16} className="text-violet-600" /> Members ({members.length})</div>
          <p className="mt-1 text-xs leading-relaxed text-ink-600">
            Each message is sealed separately to every member&apos;s devices. Someone removed stops receiving new messages; what
            they already received stays with them. Only the owner can rename the group.
          </p>
        </div>
        <button type="button" onClick={onClose} className="icon-button shrink-0" title="Close"><X size={14} /></button>
      </div>

      {mine.rename && (
        renaming === null ? (
          <button type="button" disabled={busy !== null} onClick={() => setRenaming(groupName ?? "")} className={`mt-3 ${smallButton} text-ink-700`}>
            <Pencil size={12} /> Rename group
          </button>
        ) : (
          <div className="mt-3 flex items-center gap-2">
            <input
              autoFocus
              value={renaming}
              maxLength={GROUP_NAME_MAX_CHARS}
              onChange={(event) => setRenaming(event.target.value)}
              aria-label="New group name"
              className="min-w-0 flex-1 rounded-md border border-line bg-canvas px-2 py-1.5 text-xs"
            />
            <button
              type="button"
              disabled={!sanitizeGroupName(renaming) || busy !== null}
              onClick={() => void run("rename", async () => { await onRename(renaming); setRenaming(null); })}
              className="flex items-center gap-1 rounded-md bg-violet-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-violet-700 disabled:opacity-60"
            >
              {busy === "rename" && <Loader2 size={12} className="animate-spin" />} Save
            </button>
            <button type="button" onClick={() => setRenaming(null)} className={`${smallButton} text-ink-700`}>Cancel</button>
          </div>
        )
      )}

      <ul className="mt-3 space-y-1">
        {members.map((member) => {
          const can = groupPermissions(myRole, member.role, adminCount);
          const isMe = member.userId === myUserId;
          return (
            <li key={member.userId} className="rounded-md bg-canvas px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2 truncate font-semibold text-ink-900">
                  {member.role === "owner" && <Crown size={13} className="shrink-0 text-amber-500" aria-label="Owner" />}
                  {member.role === "admin" && <Shield size={13} className="shrink-0 text-violet-600" aria-label="Admin" />}
                  {isMe ? `${member.name} (you)` : member.name}
                  <span className="text-[11px] font-medium text-ink-500">{member.role === "member" ? "" : member.role}</span>
                </span>
                {!isMe && (
                  <span className="flex flex-wrap items-center gap-1">
                    {can.makeAdmin && (
                      <button type="button" disabled={busy !== null} onClick={() => void run(`admin:${member.userId}`, () => onSetAdmin(member.userId, true))} className={`${smallButton} text-violet-700`}>
                        <Shield size={12} /> Make admin
                      </button>
                    )}
                    {can.dismissAdmin && (
                      <button type="button" disabled={busy !== null} onClick={() => void run(`admin:${member.userId}`, () => onSetAdmin(member.userId, false))} className={`${smallButton} text-ink-700`}>
                        <ShieldOff size={12} /> Dismiss admin
                      </button>
                    )}
                    {can.transferTo && (
                      <button type="button" disabled={busy !== null} onClick={() => setConfirmTransfer(member.userId)} className={`${smallButton} text-amber-700`}>
                        <Crown size={12} /> Make owner
                      </button>
                    )}
                    {can.remove && (
                      <button type="button" disabled={busy !== null} onClick={() => void run(`remove:${member.userId}`, () => onRemove(member.userId))} className={`${smallButton} text-rose-700`}>
                        {busy === `remove:${member.userId}` ? <Loader2 size={12} className="animate-spin" /> : <UserMinus size={12} />} Remove
                      </button>
                    )}
                  </span>
                )}
              </div>
              {confirmTransfer === member.userId && (
                <div className="mt-2 rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-900">
                  {member.name} becomes the owner: they alone can rename the group, appoint admins and hand it on. You stay in the group as
                  an admin if there is room (at most {GROUP_MAX_ADMINS}), otherwise as a member.
                  <div className="mt-2 flex gap-2">
                    <button
                      type="button"
                      disabled={busy !== null}
                      onClick={() => void run("transfer", async () => { await onTransfer(member.userId); setConfirmTransfer(null); })}
                      className="flex items-center gap-1 rounded-md bg-amber-600 px-3 py-1 text-xs font-bold text-white hover:bg-amber-700 disabled:opacity-60"
                    >
                      {busy === "transfer" && <Loader2 size={12} className="animate-spin" />} Make {member.name} the owner
                    </button>
                    <button type="button" onClick={() => setConfirmTransfer(null)} className={`${smallButton} text-ink-700`}>Cancel</button>
                  </div>
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {myRole === "owner" && <p className="mt-2 text-[11px] text-ink-500">Admins: {adminCount} of {GROUP_MAX_ADMINS}</p>}

      {mine.addMembers && (
        addable.length === 0 ? (
          <p className="mt-3 text-xs text-ink-500">Everyone in your contacts is already in this group.</p>
        ) : (
          <div className="mt-3 flex items-center gap-2">
            <select
              value={adding}
              onChange={(event) => setAdding(event.target.value)}
              disabled={full || busy !== null}
              aria-label="Contact to add"
              className="min-w-0 flex-1 rounded-md border border-line bg-canvas px-2 py-1.5 text-xs"
            >
              <option value="">{full ? "This group is full" : "Add a contact…"}</option>
              {addable.map((candidate) => <option key={candidate.userId} value={candidate.userId}>{candidate.name}</option>)}
            </select>
            <button
              type="button"
              disabled={!adding || full || busy !== null}
              onClick={() => void run("add", async () => { await onAdd(adding); setAdding(""); })}
              className="flex items-center gap-1 rounded-md bg-violet-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-violet-700 disabled:opacity-60"
            >
              {busy === "add" ? <Loader2 size={12} className="animate-spin" /> : <UserPlus size={12} />} Add
            </button>
          </div>
        )
      )}
      {mine.leave ? (
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => void run("leave", onLeave)}
          className="mt-3 flex items-center gap-1.5 rounded-md border border-rose-200 bg-white px-3 py-1.5 text-xs font-bold text-rose-700 hover:bg-rose-50 disabled:opacity-60"
        >
          {busy === "leave" ? <Loader2 size={12} className="animate-spin" /> : <LogOut size={12} />} Leave group
        </button>
      ) : myRole === "owner" && (
        <p className="mt-3 text-xs text-ink-500">To leave, first make someone else the owner.</p>
      )}
      {error && <div className="mt-3 rounded-md border border-rose-100 bg-rose-50 p-2 text-xs font-semibold text-rose-700">{error}</div>}
    </div>
  );
}
