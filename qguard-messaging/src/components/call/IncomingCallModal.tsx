import { useEffect, useState } from "react";
import { AlertTriangle, BadgeCheck, Phone, PhoneIncoming, PhoneOff, ShieldAlert, Video } from "lucide-react";
import { UserAvatar } from "@/components/UserAvatar";
import { describeIncomingAssurance, type ContactAssurance } from "@/lib/contact-verification";
import { useOptionalChatPreferences } from "@/lib/chat-preferences-context";

/**
 * Gentle two-tone ring while the modal is visible. Synthesised with WebAudio
 * (no audio asset, nothing to load) and stopped on unmount — accept, reject,
 * remote hangup, or timeout all silence it by tearing the modal down.
 * `enabled` false (Notifications & Sounds: "Ring for calls" off) keeps it silent;
 * the call itself still shows.
 */
function useRingtone(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return undefined;
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
  }, [enabled]);
}

export function IncomingCallModal({ callerName, callerUserId, media = "video", assurance, onAccept, onReject }: {
  callerName: string;
  callerUserId: string | null;
  /** What the caller asked for: answering a voice call never opens the camera. */
  media?: "voice" | "video";
  /** This device's own record for the calling device id; null while unknown. */
  assurance: ContactAssurance | null;
  onAccept: () => void;
  onReject: () => void;
}) {
  // "Ring for calls" for this person (their chat's setting, else the app-wide one).
  const prefs = useOptionalChatPreferences();
  const ring = prefs ? prefs.ringFor(callerUserId) : true;
  useRingtone(ring);
  const notice = describeIncomingAssurance(assurance, callerName);
  // A device never approved for this person needs a second, deliberate tap:
  // scam calls rely on an instant answer (design §7.1).
  const [confirming, setConfirming] = useState(false);
  const accept = () => {
    if (notice?.confirmToAnswer && !confirming) {
      setConfirming(true);
      return;
    }
    onAccept();
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-white/30 bg-white p-6 text-center shadow-soft">
        <div className="relative mx-auto h-20 w-20">
          <span className="absolute inset-0 animate-ping rounded-full bg-cyan-400/40" />
          <UserAvatar userId={callerUserId} name={callerName} size={80} className="relative ring-4 ring-cyan-100" />
          <span className="absolute -bottom-1 -right-1 flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500 text-white ring-2 ring-white">
            {media === "voice" ? <Phone size={15} /> : <Video size={15} />}
          </span>
        </div>
        <div className="mt-4 text-lg font-bold text-ink-950">{callerName}</div>
        <div className="text-sm text-ink-600">Incoming quantum-encrypted {media === "voice" ? "voice" : "video"} call</div>
        {notice && (
          <div
            className={`mt-4 flex items-start gap-2 rounded-lg border p-3 text-left text-xs leading-relaxed ${
              notice.tone === "ok"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : notice.tone === "warn"
                  ? "border-amber-200 bg-amber-50 text-amber-800"
                  : "border-rose-200 bg-rose-50 text-rose-800"
            }`}
          >
            {notice.tone === "ok" ? <BadgeCheck size={15} className="mt-0.5 shrink-0" /> : notice.tone === "warn" ? <AlertTriangle size={15} className="mt-0.5 shrink-0" /> : <ShieldAlert size={15} className="mt-0.5 shrink-0" />}
            <span>{notice.text}</span>
          </div>
        )}
        {confirming && (
          <div className="mt-3 text-xs font-semibold text-rose-700">Tap answer again to take the call anyway.</div>
        )}
        <div className="mt-6 flex justify-center gap-4">
          <button type="button" onClick={onReject} title="Decline" className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
          <button
            type="button"
            onClick={accept}
            title={confirming ? "Answer anyway" : "Accept"}
            aria-label={confirming ? "Answer anyway" : "Accept"}
            className={`flex h-12 items-center justify-center rounded-full text-white ${confirming ? "gap-2 bg-rose-600 px-4 text-xs font-bold hover:bg-rose-700" : "w-12 bg-emerald-500 hover:bg-emerald-600"}`}
          >
            <PhoneIncoming size={20} />{confirming && "Answer anyway"}
          </button>
        </div>
      </div>
    </div>
  );
}
