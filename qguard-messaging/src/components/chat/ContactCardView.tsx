import { MessageSquarePlus, UserPlus, UserRound } from "lucide-react";
import type { ContactCard } from "@/lib/contact-card";

/**
 * A shared contact, shown inside the message bubble in place of its raw text.
 * "Add" adds them to your contacts; "Message" opens your chat with them.
 */
export default function ContactCardView({
  card,
  mine,
  isSelf,
  isContact,
  onAdd,
  onMessage,
}: {
  card: ContactCard;
  mine: boolean;
  isSelf: boolean;
  isContact: boolean;
  onAdd: () => void;
  onMessage: () => void;
}) {
  return (
    <div className={`rounded-lg border p-3 ${mine ? "border-white/30 bg-white/10" : "border-line bg-canvas"}`}>
      <div className={`text-[10px] font-bold uppercase tracking-wide ${mine ? "text-violet-100" : "text-ink-500"}`}>Contact</div>
      <div className="mt-1 flex items-center gap-2.5">
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${mine ? "bg-white/20" : "bg-violet-100 text-violet-700"}`}>
          <UserRound size={17} />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-sm font-bold">{card.name}</span>
          {card.username && <span className={`block truncate text-xs ${mine ? "text-violet-100" : "text-ink-500"}`}>@{card.username}</span>}
        </span>
      </div>
      {!mine && !isSelf && (
        <div className="mt-2.5 flex gap-2">
          {isContact ? (
            <button type="button" onClick={onMessage} className="flex items-center gap-1 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-bold text-white">
              <MessageSquarePlus size={13} /> Message
            </button>
          ) : (
            <button type="button" onClick={onAdd} className="flex items-center gap-1 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-bold text-white">
              <UserPlus size={13} /> Add to contacts
            </button>
          )}
        </div>
      )}
      {isSelf && !mine && <p className="mt-2 text-xs text-ink-500">This is you.</p>}
    </div>
  );
}
