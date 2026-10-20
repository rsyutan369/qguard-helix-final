import { useState } from "react";
import { Loader2, ShieldCheck, Users, X } from "lucide-react";
import { GROUP_MAX_OTHER_MEMBERS, GROUP_NAME_MAX_CHARS, groupSelectionError } from "@/lib/group-chat";

export interface GroupCandidate {
  userId: string;
  name: string;
}

/**
 * "New group" (roadmap 7.1): a name and two or more contacts. The name is sent
 * end-to-end encrypted as the group's first message; the server learns only
 * that a group with these members exists.
 */
export function NewGroupDialog({ candidates, onCreate, onClose }: {
  candidates: GroupCandidate[];
  onCreate: (name: string, memberUserIds: string[]) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    const members = Array.from(chosen);
    const problem = groupSelectionError(members, name);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onCreate(name, members);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-ink-950/40 p-4 pt-[12vh] backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-lg overflow-hidden rounded-xl border border-white/30 bg-white/95 shadow-soft backdrop-blur-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 border-b border-line p-5">
          <div>
            <h2 className="flex items-center gap-2 text-base font-bold text-ink-950"><Users size={17} /> New group</h2>
            <div className="mt-1 flex items-center gap-2 text-xs font-semibold text-cyan-700">
              <ShieldCheck size={14} /> Every message is sealed separately to each member&apos;s devices
            </div>
          </div>
          <button type="button" onClick={onClose} className="icon-button h-8 w-8 shrink-0 bg-white/80" aria-label="Close new group"><X size={16} /></button>
        </div>
        <div className="space-y-3 p-5">
          <input
            autoFocus
            value={name}
            maxLength={GROUP_NAME_MAX_CHARS}
            onChange={(event) => setName(event.target.value)}
            placeholder="Group name (only members can see it)"
            aria-label="Group name"
            className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-violet-300"
          />
          <div className="max-h-[40vh] space-y-1 overflow-y-auto rounded-lg border border-line bg-canvas p-2">
            {candidates.length === 0 ? (
              <p className="p-3 text-center text-xs text-ink-500">Add contacts first — a group is made from people you have chatted with.</p>
            ) : candidates.map((candidate) => (
              <label key={candidate.userId} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-white">
                <input
                  type="checkbox"
                  checked={chosen.has(candidate.userId)}
                  disabled={!chosen.has(candidate.userId) && chosen.size >= GROUP_MAX_OTHER_MEMBERS}
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
            <span className="text-xs text-ink-500">{chosen.size} chosen</span>
            <button type="button" disabled={busy} onClick={() => void create()} className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-60">
              {busy && <Loader2 size={14} className="animate-spin" />} Create group
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
