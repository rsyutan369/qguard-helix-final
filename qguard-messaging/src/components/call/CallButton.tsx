import { Phone, Video } from "lucide-react";

/**
 * Start a quantum-encrypted call: voice (microphone only), video, or a group
 * video call (a separately encrypted link to each person). A group header has
 * no one-to-one buttons, so the group call uses the camera icon too; the
 * people icon there already means "Group members".
 */
export function CallButton({ disabled, title, onClick, media = "video" }: {
  disabled: boolean;
  title: string;
  onClick: () => void;
  media?: "voice" | "video" | "group";
}) {
  return (
    <button type="button" disabled={disabled} onClick={onClick} title={title} aria-label={title}
      className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-ink-700 hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700 disabled:cursor-not-allowed disabled:opacity-50">
      {media === "voice" ? <Phone size={17} /> : <Video size={18} />}
    </button>
  );
}
