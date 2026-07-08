import { useEffect } from "react";
import { PhoneIncoming, PhoneOff, Video } from "lucide-react";
import { UserAvatar } from "@/components/UserAvatar";

/**
 * Gentle two-tone ring while the modal is visible. Synthesised with WebAudio
 * (no audio asset, nothing to load) and stopped on unmount — accept, reject,
 * remote hangup, or timeout all silence it by tearing the modal down.
 */
function useRingtone() {
  useEffect(() => {
    const AudioCtxCtor = window.AudioContext
      ?? (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioCtxCtor) return undefined;
    let ctx: AudioContext;
    try {
      ctx = new AudioCtxCtor();
    } catch {
      return undefined;
    }
    const gain = ctx.createGain();
    gain.gain.value = 0;
    gain.connect(ctx.destination);
    const osc = ctx.createOscillator();
    osc.type = "sine";
    osc.frequency.value = 880;
    osc.connect(gain);
    osc.start();

    const beep = (at: number, freq: number) => {
      osc.frequency.setValueAtTime(freq, at);
      gain.gain.setValueAtTime(0, at);
      gain.gain.linearRampToValueAtTime(0.07, at + 0.04);
      gain.gain.setValueAtTime(0.07, at + 0.22);
      gain.gain.linearRampToValueAtTime(0, at + 0.3);
    };
    const cycle = () => {
      const t = ctx.currentTime + 0.02;
      beep(t, 880);
      beep(t + 0.42, 660);
    };
    cycle();
    const interval = window.setInterval(cycle, 2_400);

    return () => {
      window.clearInterval(interval);
      try {
        osc.stop();
      } catch {
        // Already stopped with the context.
      }
      void ctx.close().catch(() => undefined);
    };
  }, []);
}

export function IncomingCallModal({ callerName, callerUserId, onAccept, onReject }: { callerName: string; callerUserId: string | null; onAccept: () => void; onReject: () => void }) {
  useRingtone();
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-white/30 bg-white p-6 text-center shadow-soft">
        <div className="relative mx-auto h-20 w-20">
          <span className="absolute inset-0 animate-ping rounded-full bg-cyan-400/40" />
          <UserAvatar userId={callerUserId} name={callerName} size={80} className="relative ring-4 ring-cyan-100" />
          <span className="absolute -bottom-1 -right-1 flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500 text-white ring-2 ring-white">
            <Video size={15} />
          </span>
        </div>
        <div className="mt-4 text-lg font-bold text-ink-950">{callerName}</div>
        <div className="text-sm text-ink-600">Incoming quantum-encrypted video call</div>
        <div className="mt-6 flex justify-center gap-4">
          <button type="button" onClick={onReject} title="Decline" className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
          <button type="button" onClick={onAccept} title="Accept" className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500 text-white hover:bg-emerald-600"><PhoneIncoming size={20} /></button>
        </div>
      </div>
    </div>
  );
}
