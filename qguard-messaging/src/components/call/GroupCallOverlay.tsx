import { useEffect, useRef } from "react";
import { Loader2, Mic, MicOff, PhoneOff, ShieldCheck, Users, Video, VideoOff } from "lucide-react";
import type { GroupLinkView } from "@/lib/use-group-call";

function VideoTile({ stream, label, muted, status }: { stream: MediaStream | null; label: string; muted?: boolean; status?: string }) {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (ref.current && ref.current.srcObject !== stream) ref.current.srcObject = stream;
  }, [stream]);
  return (
    <div className="relative min-h-[180px] overflow-hidden rounded-xl bg-ink-900">
      {stream ? (
        <video ref={ref} autoPlay playsInline muted={muted} className="h-full w-full object-cover" />
      ) : (
        <div className="flex h-full min-h-[180px] items-center justify-center text-sm text-white/60">
          <Loader2 size={18} className="mr-2 animate-spin" /> {status ?? "Connecting…"}
        </div>
      )}
      <div className="absolute bottom-2 left-2 rounded-md bg-black/50 px-2 py-0.5 text-xs font-semibold text-white">{label}</div>
    </div>
  );
}

/**
 * Group call (roadmap 7.2): one tile per link. Each link is its own end-to-end
 * encrypted one-to-one call, so each tile is independently keyed.
 */
export function GroupCallOverlay({ links, localStream, names, micEnabled, cameraEnabled, onToggleMic, onToggleCamera, onLeave }: {
  links: GroupLinkView[];
  localStream: MediaStream | null;
  names: Record<string, string>;
  micEnabled: boolean;
  cameraEnabled: boolean;
  onToggleMic: () => void;
  onToggleCamera: () => void;
  onLeave: () => void;
}) {
  const statusOf = (phase: string) => (phase === "calling" ? "Ringing…" : phase === "ringing" ? "Joining…" : phase === "ended" ? "Left the call" : "Connecting…");
  return (
    <div className="fixed inset-0 z-[70] flex flex-col bg-ink-950 text-white">
      <div className="flex items-center justify-between gap-3 px-5 py-3">
        <div className="flex items-center gap-2 text-sm font-bold"><Users size={16} /> Group call</div>
        <div className="flex items-center gap-1.5 text-xs text-emerald-300"><ShieldCheck size={14} /> Each person&apos;s link is separately end-to-end encrypted</div>
      </div>
      <div className="grid flex-1 grid-cols-1 gap-3 overflow-y-auto p-4 sm:grid-cols-2">
        {links.map((link) => (
          <VideoTile
            key={link.slot}
            stream={link.phase === "connected" ? link.remoteStream : null}
            label={names[link.peerUserId] ?? "Group member"}
            status={statusOf(link.phase)}
          />
        ))}
        <VideoTile stream={localStream} label="You" muted status="Starting camera…" />
      </div>
      <div className="flex items-center justify-center gap-4 py-5" style={{ paddingBottom: "max(1.25rem, env(safe-area-inset-bottom))" }}>
        <button type="button" onClick={onToggleMic} title={micEnabled ? "Mute microphone" : "Unmute microphone"} className={`flex h-12 w-12 items-center justify-center rounded-full ${micEnabled ? "bg-white/15" : "bg-rose-500"}`}>{micEnabled ? <Mic size={20} /> : <MicOff size={20} />}</button>
        <button type="button" onClick={onToggleCamera} title={cameraEnabled ? "Turn camera off" : "Turn camera on"} className={`flex h-12 w-12 items-center justify-center rounded-full ${cameraEnabled ? "bg-white/15" : "bg-rose-500"}`}>{cameraEnabled ? <Video size={20} /> : <VideoOff size={20} />}</button>
        <button type="button" onClick={onLeave} title="Leave the call" className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 hover:bg-rose-600"><PhoneOff size={20} /></button>
      </div>
    </div>
  );
}

export function IncomingGroupCallModal({ inviterName, otherNames, onJoin, onDecline }: {
  inviterName: string;
  otherNames: string[];
  onJoin: () => void;
  onDecline: () => void;
}) {
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-2xl border border-white/20 bg-white p-6 text-center shadow-soft">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-violet-100 text-violet-700"><Users size={26} /></div>
        <h2 className="mt-3 text-lg font-bold text-ink-950">{inviterName} is calling</h2>
        <p className="mt-1 text-sm text-ink-600">Group call{otherNames.length ? ` with ${otherNames.join(" and ")}` : ""}. Each person&apos;s link is separately end-to-end encrypted.</p>
        <div className="mt-5 flex justify-center gap-3">
          <button type="button" onClick={onDecline} className="rounded-full bg-rose-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-rose-600">Decline</button>
          <button type="button" onClick={onJoin} className="rounded-full bg-emerald-500 px-5 py-2.5 text-sm font-bold text-white hover:bg-emerald-600">Join</button>
        </div>
      </div>
    </div>
  );
}
