import { Video } from "lucide-react";

export function CallButton({ disabled, title, onClick }: { disabled: boolean; title: string; onClick: () => void }) {
  return (
    <button type="button" disabled={disabled} onClick={onClick} title={title}
      className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-ink-700 hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700 disabled:cursor-not-allowed disabled:opacity-50">
      <Video size={18} />
    </button>
  );
}