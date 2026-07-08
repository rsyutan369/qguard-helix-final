import { useEffect, useRef, useState } from "react";
import { BadgeCheck, Mic, MicOff, PhoneOff, ShieldCheck, Video, VideoOff } from "lucide-react";
import type { CallState } from "@/lib/call-state";
import { qualityLabel, type CallQuality } from "@/lib/call-quality";
import { UserAvatar } from "@/components/UserAvatar";

const QUALITY_OPTIONS: CallQuality[] = ["low", "auto", "hd"];

export function InCallOverlay(props: {
  state: CallState; localStream: MediaStream | null; remoteStream: MediaStream | null;
  micEnabled: boolean; cameraEnabled: boolean; peerName: string; peerUserId: string | null;
  quality: CallQuality; onSetQuality: (quality: CallQuality) => void;
  onHangup: () => void; onToggleMic: () => void; onToggleCamera: () => void;
}) {
  const localRef = useRef<HTMLVideoElement>(null);
  const remoteRef = useRef<HTMLVideoElement>(null);
  const [showSas, setShowSas] = useState(false);
  const [sasAcknowledged, setSasAcknowledged] = useState(false);
  const [typedSas, setTypedSas] = useState("");
  useEffect(() => { if (localRef.current) localRef.current.srcObject = props.localStream; }, [props.localStream]);
  useEffect(() => { if (remoteRef.current) remoteRef.current.srcObject = props.remoteStream; }, [props.remoteStream]);
  // Re-prompt verification for each new call (each call derives a fresh number).
  useEffect(() => { setSasAcknowledged(false); setTypedSas(""); }, [props.state.safetyNumber]);

  // Auto-reveal the safety number the moment media connects, and keep it up until
  // the user confirms it matches — so MITM verification isn't an easily-missed
  // optional step. The badge can re-open it afterwards.
  const hasSas = Boolean(props.state.safetyNumber);
  const autoReveal = props.state.phase === "connected" && hasSas && !sasAcknowledged;
  const sasVisible = hasSas && (autoReveal || showSas);

  // Typed confirmation: the user types the number their PEER reads to them over
  // the call (the out-of-band channel), and we check it equals OUR own number.
  // Only digits are compared, so dashes/spaces are optional.
  const targetSas = (props.state.safetyNumber ?? "").replace(/\D/g, "");
  const typedDigits = typedSas.replace(/\D/g, "").slice(0, targetSas.length);
  const typedMatch = targetSas.length > 0 && typedDigits === targetSas;
  const typedMismatch = typedDigits.length === targetSas.length && targetSas.length > 0 && !typedMatch;
  const confirmTyped = (value: string) => {
    setTypedSas(value);
    if (value.replace(/\D/g, "").slice(0, targetSas.length) === targetSas && targetSas.length > 0) {
      setSasAcknowledged(true);
      setShowSas(false);
    }
  };

  const phaseLabel = props.state.phase === "connected" ? "Connected"
    : props.state.phase === "connecting" ? "Connecting..."
    : props.state.phase === "calling" ? "Calling..." : props.state.phase;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-ink-950">
      <div className="flex items-center justify-between px-5 py-3 text-white">
        <div className="flex min-w-0 items-center gap-3">
          <UserAvatar userId={props.peerUserId} name={props.peerName} size={36} className="ring-2 ring-white/20" />
          <div className="min-w-0">
            <div className="truncate text-sm font-bold">{props.peerName}</div>
            <div className="text-xs text-white/70">{phaseLabel}</div>
          </div>
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
          <button
            type="button"
            onClick={() => setShowSas((v) => !v)}
            title={sasAcknowledged ? "Safety number verified — click to view again" : "Show the safety number to verify this call"}
            className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold transition ${sasAcknowledged ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-400/40" : "bg-white/10 text-emerald-300"}`}
          >
            {sasAcknowledged ? <BadgeCheck size={14} /> : <ShieldCheck size={14} />}
            {sasAcknowledged ? "Verified" : "Quantum-encrypted"}
          </button>
        </div>
      </div>
      <div className="relative flex-1">
        <video ref={remoteRef} autoPlay playsInline className="h-full w-full bg-black object-cover" />
        {!props.remoteStream && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 bg-ink-950/60">
            <div className="relative">
              <span className="absolute inset-0 animate-ping rounded-full bg-violet-500/30" />
              <UserAvatar userId={props.peerUserId} name={props.peerName} size={104} className="relative ring-4 ring-white/20" />
            </div>
            <div className="text-sm font-semibold text-white/80">{props.peerName}</div>
            <div className="text-xs text-white/60">{phaseLabel}</div>
          </div>
        )}
        <video ref={localRef} autoPlay playsInline muted className="absolute bottom-24 right-5 h-36 w-48 rounded-lg border border-white/30 object-cover" />
        {sasVisible && props.state.safetyNumber && (
          <div className="absolute left-1/2 top-4 z-10 w-[min(92vw,420px)] -translate-x-1/2 rounded-xl border border-emerald-300/50 bg-white/95 p-4 text-center shadow-soft backdrop-blur">
            <div className="flex items-center justify-center gap-2 text-[11px] font-bold uppercase tracking-wide text-emerald-600">
              <ShieldCheck size={14} /> Verify this call is private
            </div>
            <div className="mt-2 font-mono text-xl font-bold tracking-[0.15em] text-ink-950">{props.state.safetyNumber}</div>
            <p className="mt-2 text-[11px] leading-relaxed text-ink-600">
              Confirm this matches {props.peerName}'s screen — read it to each other aloud, or type the number they read to you below. It must match exactly.
            </p>
            {autoReveal ? (
              <>
                <input
                  value={typedSas}
                  onChange={(event) => confirmTyped(event.target.value)}
                  inputMode="numeric"
                  autoComplete="off"
                  placeholder="Type your peer's number"
                  aria-label="Type the safety number your peer reads to you"
                  className={`mt-3 w-full rounded-lg border bg-canvas px-3 py-2 text-center font-mono text-sm tracking-[0.15em] outline-none focus:border-cyan-300 ${
                    typedMismatch ? "border-rose-300" : typedMatch ? "border-emerald-400" : "border-line"
                  }`}
                />
                {typedMismatch && (
                  <div className="mt-2 text-[11px] font-semibold text-rose-600">
                    Doesn't match. Stop and don't share anything sensitive — the call may be intercepted.
                  </div>
                )}
                <div className="mt-3 flex items-center justify-center gap-2">
                  <button
                    type="button"
                    onClick={() => { setSasAcknowledged(true); setShowSas(false); }}
                    className="rounded-lg bg-emerald-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-emerald-700"
                  >
                    They match — continue
                  </button>
                </div>
              </>
            ) : (
              <div className="mt-3 flex items-center justify-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowSas(false)}
                  className="rounded-lg border border-line bg-white px-4 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas"
                >
                  Hide
                </button>
              </div>
            )}
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