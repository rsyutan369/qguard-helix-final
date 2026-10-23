import { useMemo, useState } from "react";
import { Loader2, Search, ShieldCheck, Users, UsersRound, X } from "lucide-react";
import {
  DEFAULT_MEMBER_LIMITS,
  GROUP_NAME_MAX_CHARS,
  formatMemberLimit,
  groupSelectionError,
  type MemberLimits,
} from "@/lib/group-chat";

export interface GroupCandidate {
  userId: string;
  name: string;
}

export type NewGroupKind = "group" | "large_group";

/**
 * "New group" (roadmap 7.1; large groups, migration 047): a name, a size and
 * the contacts to start with. The name is end-to-end encrypted; the server
 * learns only that a conversation with these members exists.
 *
 * Two sizes, because they protect messages differently:
 *   * a group (up to 32 people) seals every message separately to each
 *     member device: files, voice notes, reactions and calls work;
 *   * a large group (up to 1,000, raised by the server's limit table) encrypts
 *     each post once with a shared key handed to every member device; text
 *     posts and invite codes, as in a channel where everyone may post.
 */
export function NewGroupDialog({ candidates, limits = DEFAULT_MEMBER_LIMITS, onCreate, onClose }: {
  candidates: GroupCandidate[];
  limits?: MemberLimits;
  onCreate: (name: string, memberUserIds: string[], kind: NewGroupKind) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<NewGroupKind>("group");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const maxOthers = limits[kind] - 1;
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return needle ? candidates.filter((candidate) => candidate.name.toLowerCase().includes(needle)) : candidates;
  }, [candidates, search]);

  const create = async () => {
    const members = Array.from(chosen);
    const problem = groupSelectionError(members, name, kind, limits);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onCreate(name, members, kind);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const sizeOption = (value: NewGroupKind, title: string, detail: string, icon: React.ReactNode) => (
    <button
      type="button"
      role="radio"
      aria-checked={kind === value}
      onClick={() => { setKind(value); setError(null); }}
      className={`flex min-w-0 flex-1 items-start gap-2 rounded-lg border p-3 text-left transition ${kind === value ? "border-violet-400 bg-violet-50" : "border-line bg-white hover:bg-canvas"}`}
    >
      <span className={`mt-0.5 shrink-0 ${kind === value ? "text-violet-600" : "text-ink-500"}`}>{icon}</span>
      <span className="min-w-0">
        <span className="block text-sm font-bold text-ink-950">{title}</span>
        <span className="mt-0.5 block text-[11px] leading-snug text-ink-600">{detail}</span>
      </span>
    </button>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-ink-950/40 p-4 pt-[8vh] backdrop-blur-sm" onClick={onClose}>
      <div className="flex max-h-[88vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-white/30 bg-white/95 shadow-soft backdrop-blur-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 border-b border-line p-5">
          <div>
            <h2 className="flex items-center gap-2 text-base font-bold text-ink-950"><Users size={17} /> New group</h2>
            <div className="mt-1 flex items-center gap-2 text-xs font-semibold text-cyan-700">
              <ShieldCheck size={14} /> End-to-end encrypted · the name is hidden from the server
            </div>
          </div>
          <button type="button" onClick={onClose} className="icon-button h-8 w-8 shrink-0 bg-white/80" aria-label="Close new group"><X size={16} /></button>
        </div>
        <div className="min-h-0 space-y-3 overflow-y-auto p-5">
          <input
            autoFocus
            value={name}
            maxLength={GROUP_NAME_MAX_CHARS}
            onChange={(event) => setName(event.target.value)}
            placeholder="Group name (only members can see it)"
            aria-label="Group name"
            className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-violet-300"
          />
          <div role="radiogroup" aria-label="Group size" className="flex flex-col gap-2 sm:flex-row">
            {sizeOption(
              "group",
              `Group · up to ${formatMemberLimit(limits.group)}`,
              "Every message sealed separately to each device. Files, voice notes, reactions and calls.",
              <Users size={16} />,
            )}
            {sizeOption(
              "large_group",
              `Large group · up to ${formatMemberLimit(limits.large_group)}`,
              "One shared key per membership change. Text posts; invite people with a code.",
              <UsersRound size={16} />,
            )}
          </div>
          {candidates.length > 8 && (
            <div className="relative">
              <Search size={14} className="absolute left-3 top-2.5 text-ink-400" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search contacts"
                aria-label="Search contacts"
                className="w-full rounded-lg border border-line bg-canvas py-2 pl-9 pr-3 text-sm outline-none focus:border-violet-300"
              />
            </div>
          )}
          <div className="max-h-[34vh] space-y-1 overflow-y-auto rounded-lg border border-line bg-canvas p-2">
            {candidates.length === 0 ? (
              <p className="p-3 text-center text-xs text-ink-500">
                {kind === "large_group"
                  ? "No contacts yet. You can still create it and invite people with a code from the group."
                  : "Add contacts first — a group is made from people you have chatted with."}
              </p>
            ) : visible.length === 0 ? (
              <p className="p-3 text-center text-xs text-ink-500">No contact matches “{search}”.</p>
            ) : visible.map((candidate) => (
              <label key={candidate.userId} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-white">
                <input
                  type="checkbox"
                  checked={chosen.has(candidate.userId)}
                  disabled={!chosen.has(candidate.userId) && chosen.size >= maxOthers}
                  onChange={(event) => setChosen((current) => {
                    const next = new Set(current);
                    if (event.target.checked) next.add(candidate.userId); else next.delete(candidate.userId);
                    return next;
                  })}
                />
                <span className="truncate font-semibold text-ink-900">{candidate.name}</span>
              </label>
            ))}
          </div>
          {error && <div className="rounded-md border border-rose-100 bg-rose-50 p-2 text-xs font-semibold text-rose-700">{error}</div>}
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-ink-500">
              {chosen.size} chosen · {formatMemberLimit(chosen.size + 1)} of {formatMemberLimit(limits[kind])} people
            </span>
            <button type="button" disabled={busy} onClick={() => void create()} className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-60">
              {busy && <Loader2 size={14} className="animate-spin" />} {kind === "large_group" ? "Create large group" : "Create group"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
