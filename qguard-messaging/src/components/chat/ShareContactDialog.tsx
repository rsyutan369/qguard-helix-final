import { Search, Share2 } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import ChatDialog from "@/components/chat/ChatDialog";

export interface ShareTarget {
  id: string;
  title: string;
  subtitle: string;
  avatar: ReactNode;
}

/**
 * "Share contact": pick the chat to send the contact card to. The card is put
 * in that chat's message box for the user to review and send — it is never
 * sent without them pressing Send.
 */
export default function ShareContactDialog({
  contactName,
  targets,
  onPick,
  onClose,
}: {
  contactName: string;
  targets: ShareTarget[];
  onPick: (conversationId: string) => void;
  onClose: () => void;
}) {
  const [filter, setFilter] = useState("");
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return needle ? targets.filter((target) => target.title.toLowerCase().includes(needle)) : targets;
  }, [filter, targets]);

  return (
    <ChatDialog title={`Share ${contactName}`} subtitle="Choose a chat. The contact card is added to your message so you can check it before sending." icon={<Share2 size={18} />} onClose={onClose}>
      <label className="relative flex items-center">
        <Search className="pointer-events-none absolute left-2.5 text-ink-400" size={14} />
        <input
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder="Search chats"
          className="w-full rounded-lg border border-line bg-white py-2 pl-8 pr-2 text-sm text-ink-950 outline-none focus:border-violet-300"
          autoFocus
        />
      </label>
      <ul className="mt-3 divide-y divide-line">
        {shown.length === 0 ? (
          <li className="py-6 text-center text-sm text-ink-500">{targets.length === 0 ? "You have no other chats to share to yet." : "No chat matches."}</li>
        ) : (
          shown.map((target) => (
            <li key={target.id}>
              <button type="button" onClick={() => onPick(target.id)} className="flex w-full items-center gap-3 py-2.5 text-left hover:bg-canvas">
                {target.avatar}
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold text-ink-950">{target.title}</span>
                  <span className="block truncate text-xs text-ink-500">{target.subtitle}</span>
                </span>
              </button>
            </li>
          ))
        )}
      </ul>
    </ChatDialog>
  );
}
