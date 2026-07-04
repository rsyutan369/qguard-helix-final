import { useEffect } from "react";
import { PhoneIncoming, PhoneOff, Video } from "lucide-react";

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

export function IncomingCallModal({ callerName, onAccept, onReject }: { callerName: string; onAccept: () => void; onReject: () => void }) {
  useRingtone();
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-white/30 bg-white p-6 text-center shadow-soft">
        <div className="mx-auto flex h-16 w-16 animate-pulse items-center justify-center rounded-full bg-cyan-50 text-cyan-600"><Video size={28} /></div>
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
