import { useEffect, useRef, useState } from "react";
import { Mic, MicOff, PhoneOff, ShieldCheck, Video, VideoOff } from "lucide-react";
import type { CallState } from "@/lib/call-state";
import { qualityLabel, type CallQuality } from "@/lib/call-quality";

const QUALITY_OPTIONS: CallQuality[] = ["low", "auto", "hd"];

export function InCallOverlay(props: {
  state: CallState; localStream: MediaStream | null; remoteStream: MediaStream | null;
  micEnabled: boolean; cameraEnabled: boolean; peerName: string;
  quality: CallQuality; onSetQuality: (quality: CallQuality) => void;
  onHangup: () => void; onToggleMic: () => void; onToggleCamera: () => void;
}) {
  const localRef = useRef<HTMLVideoElement>(null);
  const remoteRef = useRef<HTMLVideoElement>(null);
  const [showSas, setShowSas] = useState(false);
  useEffect(() => { if (localRef.current) localRef.current.srcObject = props.localStream; }, [props.localStream]);
  useEffect(() => { if (remoteRef.current) remoteRef.current.srcObject = props.remoteStream; }, [props.remoteStream]);

  const phaseLabel = props.state.phase === "connected" ? "Connected"
    : props.state.phase === "connecting" ? "Connecting..."
    : props.state.phase === "calling" ? "Calling..." : props.state.phase;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-ink-950">
      <div className="flex items-center justify-between px-5 py-3 text-white">
        <div>
          <div className="text-sm font-bold">{props.peerName}</div>
          <div className="text-xs text-white/70">{phaseLabel}</div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center rounded-full bg-white/10 p-0.5" role="radiogroup" aria-label="Call quality">
            {QUALITY_OPTIONS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={props.quality === option}
                onClick={() => props.onSetQuality(option)}
                className={`rounded-full px-3 py-1 text-xs font-semibold transition ${props.quality === option ? "bg-white text-ink-950" : "text-white/70 hover:text-white"}`}
                title={option === "auto" ? "Auto — adapts to your device" : option === "low" ? "Low — saves CPU/bandwidth" : "HD — needs a strong device"}
              >
                {qualityLabel(option)}
              </button>
            ))}
          </div>
          <button type="button" onClick={() => setShowSas((v) => !v)} className="flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold text-emerald-300">
            <ShieldCheck size={14} /> Quantum-encrypted
          </button>
        </div>
      </div>
      <div className="relative flex-1">
        <video ref={remoteRef} autoPlay playsInline className="h-full w-full bg-black object-cover" />
        <video ref={localRef} autoPlay playsInline muted className="absolute bottom-24 right-5 h-36 w-48 rounded-lg border border-white/30 object-cover" />
        {showSas && props.state.safetyNumber && (
          <div className="absolute left-1/2 top-4 -translate-x-1/2 rounded-lg bg-white/95 px-4 py-2 text-center">
            <div className="text-[11px] font-bold uppercase text-ink-400">Safety number (say it aloud to verify)</div>
            <div className="font-mono text-sm font-bold text-ink-950">{props.state.safetyNumber}</div>
          </div>
        )}
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 text-center text-[11px] text-white/60">
          End-to-end encrypted. The server and network cannot see this call; only the person you called can see what you share.
        </div>
      </div>
      <div className="flex items-center justify-center gap-4 py-5">
        <button type="button" onClick={props.onToggleMic} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.micEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.micEnabled ? <Mic size={20} /> : <MicOff size={20} />}</button>
        <button type="button" onClick={props.onToggleCamera} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.cameraEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.cameraEnabled ? <Video size={20} /> : <VideoOff size={20} />}</button>
        <button type="button" onClick={props.onHangup} className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
      </div>
    </div>
  );
}