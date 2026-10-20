import { useState } from "react";
import { Loader2, LogIn, Megaphone, X } from "lucide-react";
import { normalizeInviteCode } from "@/lib/channels";
import { GROUP_NAME_MAX_CHARS, sanitizeGroupName } from "@/lib/group-chat";

function Shell({ title, icon, onClose, children }: { title: string; icon: React.ReactNode; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-ink-950/40 p-4 pt-[12vh] backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-md overflow-hidden rounded-xl border border-white/30 bg-white/95 shadow-soft backdrop-blur-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-center justify-between gap-3 border-b border-line p-5">
          <h2 className="flex items-center gap-2 text-base font-bold text-ink-950">{icon} {title}</h2>
          <button type="button" onClick={onClose} className="icon-button h-8 w-8 shrink-0 bg-white/80" aria-label="Close"><X size={16} /></button>
        </div>
        <div className="space-y-3 p-5">{children}</div>
      </div>
    </div>
  );
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

/** "New channel" (roadmap 7.4): a name; readers join later with invite codes. */
export function NewChannelDialog({ onCreate, onClose }: { onCreate: (name: string) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Shell title="New channel" icon={<Megaphone size={17} />} onClose={onClose}>
      <p className="text-xs leading-relaxed text-ink-600">
        You post; readers read. Posts are encrypted once with a channel key that only readers&apos; devices hold. Invite people with codes
        from the channel; readers do not see who else reads.
      </p>
      <input
        autoFocus
        value={name}
        maxLength={GROUP_NAME_MAX_CHARS}
        onChange={(event) => setName(event.target.value)}
        placeholder="Channel name (only readers can see it)"
        aria-label="Channel name"
        className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm outline-none focus:border-violet-300"
      />
      {error && <div className="rounded-md border border-rose-100 bg-rose-50 p-2 text-xs font-semibold text-rose-700">{error}</div>}
      <div className="flex justify-end">
        <button
          type="button"
          disabled={busy || !sanitizeGroupName(name)}
          onClick={() => void run(() => onCreate(name))}
          className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-60"
        >
          {busy && <Loader2 size={14} className="animate-spin" />} Create channel
        </button>
      </div>
    </Shell>
  );
}

/** "Join channel": an invite code from the channel's owner or an admin. */
export function JoinChannelDialog({ onJoin, onClose }: { onJoin: (code: string) => Promise<void>; onClose: () => void }) {
  const [code, setCode] = useState("");
  const { busy, error, setError, run } = useAction();
  const normalized = normalizeInviteCode(code);
  return (
    <Shell title="Join a channel" icon={<LogIn size={17} />} onClose={onClose}>
      <input
        autoFocus
        value={code}
        onChange={(event) => { setCode(event.target.value); setError(null); }}
        placeholder="xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx"
        aria-label="Invite code"
        className="w-full rounded-lg border border-line bg-canvas px-3 py-2.5 font-mono text-sm outline-none focus:border-violet-300"
      />
      {code && !normalized && <p className="text-xs text-ink-500">An invite code is 32 letters and digits.</p>}
      {error && <div className="rounded-md border border-rose-100 bg-rose-50 p-2 text-xs font-semibold text-rose-700">{error}</div>}
      <div className="flex justify-end">
        <button
          type="button"
          disabled={busy || !normalized}
          onClick={() => normalized && void run(() => onJoin(normalized))}
          className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-bold text-white hover:bg-violet-700 disabled:opacity-60"
        >
          {busy && <Loader2 size={14} className="animate-spin" />} Join
        </button>
      </div>
    </Shell>
  );
}
