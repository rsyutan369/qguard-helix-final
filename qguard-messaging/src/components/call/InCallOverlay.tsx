import { useCallback, useEffect, useLayoutEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type RefObject } from "react";
import { Activity, AlertTriangle, BadgeCheck, Check, Copy, KeyRound, LockKeyhole, Maximize2, MessageSquareQuote, Mic, MicOff, Monitor, MonitorOff, Move, PhoneOff, ShieldCheck, Video, VideoOff } from "lucide-react";
import { formatCallDuration } from "@/lib/call-history";
import { callSecurityNeedsAttention, describeCallSecurity, formatVerifiedDate } from "@/lib/call-security";
import { checkCallPhrase, describePairing, fetchCallPhrase, type CallPhrase } from "@/lib/contact-verification";
import type { CallState } from "@/lib/call-state";
import { qualityLabel, type CallQuality } from "@/lib/call-quality";
import type { CallStatsSample } from "@/lib/call-stats";
import { UserAvatar } from "@/components/UserAvatar";

const QUALITY_OPTIONS: CallQuality[] = ["low", "auto", "hd"];

const fmtRes = (w: number | null, h: number | null, fps: number | null) =>
  w && h ? `${w}×${h}${fps ? `@${Math.round(fps)}` : ""}` : "—";
const fmtKbps = (bps: number | null) => (bps === null ? "—" : `${Math.max(1, Math.round(bps / 1000))} kbps`);

/**
 * Live connection diagnostics. The chip always shows the essentials (route +
 * received resolution); tapping it opens the full panel — encode/decode
 * resolution, fps, bitrates, RTT, loss and the encoder's limitation reason —
 * so a degraded call names its own cause instead of just looking blurry.
 */
function CallStatsPanel({ stats }: { stats: CallStatsSample }) {
  const [open, setOpen] = useState(false);
  const limited = stats.qualityLimitationReason && stats.qualityLimitationReason !== "none";
  const relayed = stats.route === "relay";
  const attention = Boolean(limited) || relayed;
  return (
    <div className="absolute bottom-4 left-4 z-10 text-left">
      {open && (
        <div className="mb-2 w-64 rounded-xl border border-white/15 bg-ink-950/90 p-3 text-[11px] leading-relaxed text-white/85 shadow-soft backdrop-blur">
          <div className="mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-wide text-white/50">
            <span>Connection diagnostics</span>
            <button type="button" onClick={() => setOpen(false)} className="text-white/50 hover:text-white">✕</button>
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
            <span className="text-white/50">Route</span>
            <span className={relayed ? "font-semibold text-amber-300" : "text-emerald-300"}>
              {stats.route === "relay" ? "Relay (TURN)" : stats.route === "direct" ? "Direct" : "Negotiating…"}
            </span>
            <span className="text-white/50">Receiving</span><span>{fmtRes(stats.inWidth, stats.inHeight, stats.inFps)}</span>
            <span className="text-white/50">Sending</span><span>{fmtRes(stats.outWidth, stats.outHeight, stats.outFps)}</span>
            <span className="text-white/50">Bitrate ↓ / ↑</span><span>{fmtKbps(stats.inBitrate)} / {fmtKbps(stats.outBitrate)}</span>
            <span className="text-white/50">Latency (RTT)</span><span>{stats.rttMs === null ? "—" : `${stats.rttMs} ms`}</span>
            <span className="text-white/50">Jitter</span><span>{stats.inJitterMs === null ? "—" : `${stats.inJitterMs} ms`}</span>
            <span className="text-white/50">Packets lost</span><span>{stats.inPacketsLost ?? "—"}</span>
            <span className="text-white/50">Codec</span><span>{stats.videoCodec?.replace("video/", "") ?? "—"}</span>
          </div>
          {limited && (
            <div className="mt-2 rounded-lg bg-amber-400/10 px-2 py-1 font-semibold text-amber-300">
              {stats.qualityLimitationReason === "cpu"
                ? "Quality limited by CPU load on this device"
                : stats.qualityLimitationReason === "bandwidth"
                  ? "Quality limited by network bandwidth"
                  : `Quality limited (${stats.qualityLimitationReason})`}
            </div>
          )}
          {relayed && (
            <div className="mt-1 rounded-lg bg-amber-400/10 px-2 py-1 text-amber-200/90">
              Media is routed via a relay server (still end-to-end encrypted); quality may be reduced.
            </div>
          )}
        </div>
      )}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Connection diagnostics"
        className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold backdrop-blur transition ${attention ? "bg-amber-400/15 text-amber-300" : "bg-white/10 text-white/70 hover:text-white"}`}
      >
        <Activity size={11} />
        {fmtRes(stats.inWidth, stats.inHeight, stats.inFps)}
        {relayed && <span>· relay</span>}
        {limited && <span>· limited</span>}
      </button>
    </div>
  );
}

/**
 * "Ask for their phrase" (call verification, roadmap Phase 3). Both devices of
 * a verified, paired contact derive the same four words for this call and this
 * 30-second window. One person asks, the other reads THEIR screen aloud, the
 * first compares — nothing is sent, so there is nothing on the wire to copy,
 * and a phrase heard in another call is useless here. The words are typed back
 * for the core to check (it accepts the window before and after, for clock
 * skew). Proves possession of the verified device, not the human — the copy
 * says so.
 */
function PhrasePanel({ state, peerName, onClose }: { state: CallState; peerName: string; onClose: () => void }) {
  const [phrase, setPhrase] = useState<CallPhrase | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [spoken, setSpoken] = useState("");
  const [verdict, setVerdict] = useState<"match" | "mismatch" | null>(null);
  const [checking, setChecking] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const { callId, peerUserId, peerDeviceId } = state;
  const name = peerName.trim() || "them";

  const load = useCallback(() => {
    if (!callId || !peerUserId || !peerDeviceId) return;
    fetchCallPhrase(peerUserId, peerDeviceId, callId)
      .then((next) => { setPhrase(next); setSecondsLeft(next.secondsLeft); setError(null); })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
  }, [callId, peerDeviceId, peerUserId]);
  useEffect(() => { load(); }, [load]);
  // Count down locally; fetch the next phrase when the window turns over.
  useEffect(() => {
    if (!phrase || phrase.words.length === 0) return undefined;
    const timer = window.setInterval(() => {
      setSecondsLeft((left) => {
        if (left <= 1) { load(); return 0; }
        return left - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [load, phrase]);

  const check = async () => {
    if (!callId || !peerUserId || !peerDeviceId) return;
    setChecking(true);
    try {
      setVerdict(await checkCallPhrase(peerUserId, peerDeviceId, callId, spoken) ? "match" : "mismatch");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setChecking(false);
    }
  };

  const unproven = !state.peerVerified;
  return (
    <div className="absolute left-1/2 top-4 z-10 w-[min(92vw,420px)] -translate-x-1/2 rounded-xl border border-cyan-300/50 bg-white/95 p-4 text-left shadow-soft backdrop-blur">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wide text-cyan-700">
          <MessageSquareQuote size={14} /> Is it really {name}?
        </div>
        <button type="button" onClick={onClose} className="text-xs font-bold text-ink-500 hover:text-ink-900">Close</button>
      </div>
      {unproven ? (
        <p className="mt-2 text-[12px] leading-relaxed text-amber-700">
          The other device could not be proven to be {name}&apos;s recorded device, so no phrase can vouch for it. Don&apos;t share anything sensitive.
        </p>
      ) : error ? (
        <p className="mt-2 text-[12px] text-rose-700">{error}</p>
      ) : !phrase ? (
        <p className="mt-2 text-[12px] text-ink-600">Loading…</p>
      ) : phrase.words.length === 0 ? (
        <p className="mt-2 text-[12px] leading-relaxed text-ink-700">
          {phrase.verifiedAt === null
            ? `You haven't verified ${name} yet, so there is no phrase to ask for. Compare safety numbers with them in your chat (Verify contact), then ask a question only they would know for this call.`
            : describePairing(phrase.pairing, name)}
        </p>
      ) : (
        <>
          <p className="mt-2 text-[12px] leading-relaxed text-ink-700">
            Ask {name} to read the four words on <em>their</em> screen. Don&apos;t read yours first. They should match:
          </p>
          <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1 font-mono text-lg font-bold text-ink-950">
            {phrase.words.map((word) => <span key={word}>{word}</span>)}
          </div>
          <div className="mt-1 text-[11px] text-ink-500">Changes in {secondsLeft}s — the previous and next phrase also count.</div>
          <div className="mt-3 flex gap-2">
            <input
              value={spoken}
              onChange={(event) => { setSpoken(event.target.value); setVerdict(null); }}
              placeholder="Or type the words they say"
              aria-label="Type the phrase your contact reads to you"
              autoComplete="off"
              className="min-w-0 flex-1 rounded-lg border border-line bg-canvas px-3 py-1.5 text-sm outline-none focus:border-cyan-300"
            />
            <button
              type="button"
              disabled={checking || spoken.trim().split(/\s+/).length < 4}
              onClick={() => void check()}
              className="rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-cyan-700 disabled:opacity-50"
            >
              Check
            </button>
          </div>
          {verdict === "match" && (
            <div className="mt-2 flex items-start gap-1.5 text-[12px] font-semibold text-emerald-700">
              <Check size={13} className="mt-0.5 shrink-0" />
              It matches: the other side holds the device you verified for {name}
              {phrase.verifiedAt ? ` on ${formatVerifiedDate(phrase.verifiedAt)}` : ""}.
            </div>
          )}
          {verdict === "mismatch" && (
            <div className="mt-2 flex items-start gap-1.5 text-[12px] font-semibold text-rose-700">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              Doesn&apos;t match. Don&apos;t share anything sensitive — this may not be {name}&apos;s device.
            </div>
          )}
          <p className="mt-3 border-t border-line pt-2 text-[11px] leading-relaxed text-ink-500">
            Proves the other side holds the device you verified — not who is holding it, and not whether a voice is real.
          </p>
        </>
      )}
    </div>
  );
}

/**
 * The stage of a voice call: no camera anywhere, so the person, the talk time
 * and what protects the call take the screen. Remote audio plays through the
 * hidden <audio> element (a voice call has no <video> to carry it).
 */
function VoiceStage({ peerName, peerUserId, statusLabel, connected, micEnabled, audioRef }: {
  peerName: string;
  peerUserId: string | null;
  statusLabel: string;
  connected: boolean;
  micEnabled: boolean;
  audioRef: RefObject<HTMLAudioElement | null>;
}) {
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center gap-6 overflow-hidden bg-[radial-gradient(circle_at_50%_32%,rgba(124,58,237,0.32),transparent_58%),radial-gradient(circle_at_50%_100%,rgba(8,145,178,0.22),transparent_55%)] px-6 pb-16 text-center">
      <audio ref={audioRef} autoPlay className="hidden" />
      <div className="relative flex h-44 w-44 items-center justify-center">
        {/* Rings breathe while ringing/connecting and settle once connected. */}
        <span className={`absolute inset-0 rounded-full border border-white/10 ${connected ? "" : "animate-ping"}`} />
        <span className="absolute inset-3 rounded-full border border-white/15" />
        <span className="absolute inset-6 rounded-full bg-white/5" />
        <UserAvatar userId={peerUserId} name={peerName} size={124} className="relative ring-4 ring-white/20" />
        {!micEnabled && (
          <span className="absolute bottom-3 right-3 flex h-9 w-9 items-center justify-center rounded-full bg-rose-500 text-white ring-4 ring-ink-950" title="Your microphone is muted">
            <MicOff size={16} />
          </span>
        )}
      </div>
      <div className="min-w-0 max-w-full">
        <div className="truncate text-2xl font-bold tracking-tight text-white">{peerName}</div>
        <div className="mt-1.5 font-mono text-sm tabular-nums text-white/70" aria-live="polite">{statusLabel}</div>
      </div>
      <div className="flex max-w-md flex-wrap items-center justify-center gap-2 text-[11px] font-semibold text-white/80">
        <span className="flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1.5 ring-1 ring-white/15">
          <LockKeyhole size={12} className="text-emerald-300" /> Voice only · camera never opened
        </span>
        <span className="flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1.5 ring-1 ring-white/15">
          <KeyRound size={12} className="text-cyan-300" /> X25519 + ML-KEM-1024
        </span>
        <span className="flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1.5 ring-1 ring-white/15">
          <ShieldCheck size={12} className="text-violet-300" /> AES-256-GCM on every audio frame
        </span>
      </div>
    </div>
  );
}

export function InCallOverlay(props: {
  state: CallState; localStream: MediaStream | null; remoteStream: MediaStream | null;
  micEnabled: boolean; cameraEnabled: boolean; reconnecting?: boolean; peerName: string; peerUserId: string | null;
  quality: CallQuality; onSetQuality: (quality: CallQuality) => void;
  stats?: CallStatsSample | null;
  onHangup: () => void; onToggleMic: () => void; onToggleCamera: () => void;
  /** Absent where the platform cannot capture a screen (Android). */
  screenShare?: { active: boolean; start: () => Promise<void>; stop: () => Promise<void> };
}) {
  const localRef = useRef<HTMLVideoElement>(null);
  const [screenShareError, setScreenShareError] = useState<string | null>(null);
  const toggleScreenShare = () => {
    const share = props.screenShare;
    if (!share) return;
    setScreenShareError(null);
    (share.active ? share.stop() : share.start()).catch((error: unknown) => {
      // Dismissing the system picker is a choice, not a failure.
      if (error instanceof DOMException && error.name === "NotAllowedError") return;
      setScreenShareError(error instanceof Error ? error.message : String(error));
    });
  };
  const remoteRef = useRef<HTMLVideoElement>(null);
  // A voice call plays the remote side through an <audio> element instead.
  const remoteAudioRef = useRef<HTMLAudioElement>(null);
  const isVoice = props.state.media === "voice";
  // Talk time, from the moment media connected (per call).
  const [connectedAt, setConnectedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { setConnectedAt(null); }, [props.state.callId]);
  useEffect(() => {
    if (props.state.phase === "connected") setConnectedAt((at) => at ?? Date.now());
  }, [props.state.phase]);
  useEffect(() => {
    if (connectedAt === null) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [connectedAt]);
  const talkTime = connectedAt !== null ? formatCallDuration((now - connectedAt) / 1000) : null;
  const stageRef = useRef<HTMLDivElement>(null);
  const pipRef = useRef<HTMLDivElement>(null);
  const [showSas, setShowSas] = useState(false);
  const [sasAcknowledged, setSasAcknowledged] = useState(false);
  const [typedSas, setTypedSas] = useState("");
  const [sasCopied, setSasCopied] = useState(false);
  const [showPhrase, setShowPhrase] = useState(false);
  // Whether the remote frame is cropped to fill (cover) or shown whole (contain).
  // "contain" answers "I can't see the caller's entire picture".
  const [remoteFit, setRemoteFit] = useState<"cover" | "contain">("cover");
  // Draggable self-preview position (top-left, in px, relative to the video
  // stage). Null until first measured, then defaulted to the top-right corner.
  const [pipPos, setPipPos] = useState<{ x: number; y: number } | null>(null);
  useEffect(() => { if (localRef.current) localRef.current.srcObject = props.localStream; }, [props.localStream]);
  useEffect(() => { if (remoteRef.current) remoteRef.current.srcObject = props.remoteStream; }, [props.remoteStream, isVoice]);
  useEffect(() => { if (remoteAudioRef.current) remoteAudioRef.current.srcObject = props.remoteStream; }, [props.remoteStream, isVoice]);

  // Keep the self-preview fully on-screen. Clamps a proposed position to the
  // stage bounds using the live element sizes (so it works at any PiP size).
  const clampPip = useCallback((x: number, y: number) => {
    const stage = stageRef.current;
    const pip = pipRef.current;
    if (!stage || !pip) return { x, y };
    const margin = 12;
    const maxX = Math.max(margin, stage.clientWidth - pip.offsetWidth - margin);
    const maxY = Math.max(margin, stage.clientHeight - pip.offsetHeight - margin);
    return { x: Math.min(Math.max(x, margin), maxX), y: Math.min(Math.max(y, margin), maxY) };
  }, []);

  // Default to the top-right (clear of the bottom controls) and re-clamp on
  // rotation / resize so the box never ends up off-screen — "automatic
  // detection and adjustment of screen size".
  useLayoutEffect(() => {
    const place = () => {
      const stage = stageRef.current;
      const pip = pipRef.current;
      if (!stage || !pip) return;
      setPipPos((prev) => (prev
        ? clampPip(prev.x, prev.y)
        : clampPip(stage.clientWidth - pip.offsetWidth - 12, 12)));
    };
    place();
    const observer = new ResizeObserver(place);
    if (stageRef.current) observer.observe(stageRef.current);
    window.addEventListener("orientationchange", place);
    return () => { observer.disconnect(); window.removeEventListener("orientationchange", place); };
  }, [clampPip]);

  const startPipDrag = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const pip = pipRef.current;
    const stage = stageRef.current;
    if (!pip || !stage) return;
    event.preventDefault();
    const pipRect = pip.getBoundingClientRect();
    const stageRect = stage.getBoundingClientRect();
    const grabX = event.clientX - pipRect.left;
    const grabY = event.clientY - pipRect.top;
    try { pip.setPointerCapture(event.pointerId); } catch { /* capture is best-effort */ }
    const onMove = (move: PointerEvent) => {
      setPipPos(clampPip(move.clientX - stageRect.left - grabX, move.clientY - stageRect.top - grabY));
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      try { pip.releasePointerCapture(event.pointerId); } catch { /* ignore */ }
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }, [clampPip]);
  // Re-prompt verification for each new call (each call derives a fresh number).
  useEffect(() => { setSasAcknowledged(false); setTypedSas(""); setSasCopied(false); setShowPhrase(false); }, [props.state.safetyNumber]);

  // Copy the safety number so users can paste it to the peer instead of
  // reading it aloud. The peer pastes it into their typed-confirmation field.
  const copySas = () => {
    const value = props.state.safetyNumber;
    if (!value) return;
    navigator.clipboard.writeText(value).then(
      () => {
        setSasCopied(true);
        window.setTimeout(() => setSasCopied(false), 2000);
      },
      () => undefined,
    );
  };

  // Auto-reveal the safety number the moment media connects, and keep it up until
  // the user confirms it matches — so MITM verification isn't an easily-missed
  // optional step. The badge can re-open it afterwards.
  const hasSas = Boolean(props.state.safetyNumber);
  const autoReveal = props.state.phase === "connected" && hasSas && !sasAcknowledged;
  // The phrase panel takes the same spot; while it is open it wins.
  const sasVisible = hasSas && (autoReveal || showSas) && !showPhrase;

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

  // What the core established for this call. Empty until media connects.
  const securityLines = describeCallSecurity(props.state, props.peerName);
  const securityAttention = callSecurityNeedsAttention(securityLines);

  const phaseLabel = props.reconnecting ? "Reconnecting…"
    : props.state.phase === "connected" ? (talkTime ? `Connected · ${talkTime}` : "Connected")
    : props.state.phase === "connecting" ? "Connecting..."
    : props.state.phase === "calling" ? "Calling..." : props.state.phase;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-ink-950">
      <div
        className="flex items-center justify-between gap-2 px-5 py-3 text-white"
        style={{ paddingTop: "max(0.75rem, env(safe-area-inset-top))" }}
      >
        <div className="flex min-w-0 items-center gap-3">
          <UserAvatar userId={props.peerUserId} name={props.peerName} size={36} className="ring-2 ring-white/20" />
          <div className="min-w-0">
            <div className="truncate text-sm font-bold">{props.peerName}</div>
            <div className={`flex items-center gap-1.5 text-xs ${props.reconnecting ? "font-semibold text-amber-300" : "text-white/70"}`}>
              {props.reconnecting && <span className="h-1.5 w-1.5 animate-ping rounded-full bg-amber-300" />}
              {phaseLabel}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {props.state.phase === "connected" && (
            <button
              type="button"
              onClick={() => setShowPhrase((open) => !open)}
              aria-pressed={showPhrase}
              title="Check it's really them: ask for the phrase on their screen"
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold transition ${showPhrase ? "bg-cyan-400 text-ink-950" : "bg-white/10 text-cyan-200 hover:text-white"}`}
            >
              <MessageSquareQuote size={14} /> <span className="hidden sm:inline">Ask for their phrase</span>
            </button>
          )}
          {/* Video quality has no meaning in a voice call. */}
          {!isVoice && (
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
          )}
          <button
            type="button"
            onClick={() => setShowSas((v) => !v)}
            title={securityAttention
              ? "This call is encrypted, but something about it is weaker than it could be — click for details"
              : sasAcknowledged ? "Safety number verified — click to view again" : "Show the safety number to verify this call"}
            className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold transition ${
              securityAttention
                ? "bg-amber-500/20 text-amber-200 ring-1 ring-amber-300/40"
                : sasAcknowledged ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-400/40" : "bg-white/10 text-emerald-300"
            }`}
          >
            {securityAttention ? <AlertTriangle size={14} /> : sasAcknowledged ? <BadgeCheck size={14} /> : <ShieldCheck size={14} />}
            {securityAttention ? "Encrypted — check details" : sasAcknowledged ? "Verified" : "Quantum-encrypted"}
          </button>
        </div>
      </div>
      <div ref={stageRef} className="relative flex-1 overflow-hidden">
        {isVoice ? (
          <VoiceStage
            peerName={props.peerName}
            peerUserId={props.peerUserId}
            statusLabel={phaseLabel}
            connected={props.state.phase === "connected"}
            micEnabled={props.micEnabled}
            audioRef={remoteAudioRef}
          />
        ) : (
        <>
        <video ref={remoteRef} autoPlay playsInline className={`h-full w-full bg-black ${remoteFit === "cover" ? "object-cover" : "object-contain"}`} />
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
        {/* Self-preview: draggable, responsive (scales with the viewport, never
            larger than a small fixed cap), and clamped on-screen. Positioned
            via state once measured; the CSS corner is only the pre-measure
            fallback so it never flashes off-screen. */}
        <div
          ref={pipRef}
          onPointerDown={startPipDrag}
          style={pipPos ? { left: pipPos.x, top: pipPos.y, right: "auto", bottom: "auto" } : undefined}
          className="group absolute right-3 top-3 z-20 aspect-[3/4] w-[26vw] min-w-[92px] max-w-[150px] cursor-grab touch-none select-none overflow-hidden rounded-xl border border-white/30 bg-black/70 shadow-soft transition-shadow active:cursor-grabbing active:shadow-lg"
          role="button"
          tabIndex={0}
          aria-label="Your camera preview — drag to reposition"
          title="Drag to reposition"
        >
          <video ref={localRef} autoPlay playsInline muted className="pointer-events-none h-full w-full object-cover" />
          {!props.cameraEnabled && (
            <div className="absolute inset-0 flex items-center justify-center bg-ink-950/80 text-white/70">
              <VideoOff size={18} />
            </div>
          )}
          <div className="pointer-events-none absolute inset-x-0 top-0 flex items-center justify-center gap-1 bg-gradient-to-b from-black/55 to-transparent py-1 text-[9px] font-bold uppercase tracking-wide text-white/85 opacity-0 transition group-hover:opacity-100 group-active:opacity-100">
            <Move size={10} /> You
          </div>
        </div>
        </>
        )}
        {showPhrase && props.state.phase === "connected" && (
          <PhrasePanel state={props.state} peerName={props.peerName} onClose={() => setShowPhrase(false)} />
        )}
        {sasVisible && props.state.safetyNumber && (
          <div className="absolute left-1/2 top-4 z-10 w-[min(92vw,420px)] -translate-x-1/2 rounded-xl border border-emerald-300/50 bg-white/95 p-4 text-center shadow-soft backdrop-blur">
            <div className="flex items-center justify-center gap-2 text-[11px] font-bold uppercase tracking-wide text-emerald-600">
              <ShieldCheck size={14} /> Verify this call is private
            </div>
            <div className="mt-2 font-mono text-xl font-bold tracking-[0.15em] text-ink-950">{props.state.safetyNumber}</div>
            <p className="mt-2 text-[11px] leading-relaxed text-ink-600">
              Confirm this matches {props.peerName}'s screen — read it to each other aloud, or copy yours and paste the number they send you below. It must match exactly.
            </p>
            {securityLines.length > 0 && (
              <ul className="mt-3 space-y-1.5 border-t border-line pt-3 text-left text-[11px] leading-relaxed">
                {securityLines.map((line) => (
                  <li key={line.text} className={`flex items-start gap-1.5 ${line.ok ? "text-ink-600" : "font-semibold text-amber-700"}`}>
                    {line.ok
                      ? <Check className="mt-0.5 shrink-0 text-emerald-600" size={12} />
                      : <AlertTriangle className="mt-0.5 shrink-0 text-amber-600" size={12} />}
                    <span>{line.text}</span>
                  </li>
                ))}
              </ul>
            )}
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
                    onClick={copySas}
                    className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas"
                    title="Copy the safety number to paste to your peer"
                  >
                    {sasCopied ? <Check className="text-emerald-600" size={13} /> : <Copy size={13} />}
                    {sasCopied ? "Copied" : "Copy"}
                  </button>
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
                  onClick={copySas}
                  className="flex items-center gap-1.5 rounded-lg border border-line bg-white px-3 py-1.5 text-xs font-bold text-ink-700 hover:bg-canvas"
                  title="Copy the safety number to paste to your peer"
                >
                  {sasCopied ? <Check className="text-emerald-600" size={13} /> : <Copy size={13} />}
                  {sasCopied ? "Copied" : "Copy"}
                </button>
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
          {isVoice
            ? "End-to-end encrypted. The server and network cannot hear this call; only the person you called can."
            : "End-to-end encrypted. The server and network cannot see this call; only the person you called can see what you share."}
        </div>
        {props.stats && props.state.phase === "connected" && <CallStatsPanel stats={props.stats} />}
        {(props.screenShare?.active || screenShareError) && (
          <div className={`absolute left-1/2 top-4 -translate-x-1/2 rounded-full px-3 py-1 text-xs font-semibold ${screenShareError ? "bg-rose-600 text-white" : "bg-cyan-600 text-white"}`}>
            {screenShareError ?? `${props.peerName} can see your screen — still end-to-end encrypted`}
          </div>
        )}
      </div>
      <div
        className="flex items-center justify-center gap-4 py-5"
        style={{ paddingBottom: "max(1.25rem, env(safe-area-inset-bottom))" }}
      >
        <button type="button" onClick={props.onToggleMic} title={props.micEnabled ? "Mute microphone" : "Unmute microphone"} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.micEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.micEnabled ? <Mic size={20} /> : <MicOff size={20} />}</button>
        {!isVoice && (
        <button type="button" onClick={props.onToggleCamera} title={props.cameraEnabled ? "Turn camera off" : "Turn camera on"} className={`flex h-12 w-12 items-center justify-center rounded-full ${props.cameraEnabled ? "bg-white/15 text-white" : "bg-rose-500 text-white"}`}>{props.cameraEnabled ? <Video size={20} /> : <VideoOff size={20} />}</button>
        )}
        {!isVoice && props.screenShare && props.state.phase === "connected" && (
          <button
            type="button"
            onClick={toggleScreenShare}
            title={props.screenShare.active ? "Stop sharing your screen" : "Share your screen"}
            aria-pressed={props.screenShare.active}
            className={`flex h-12 w-12 items-center justify-center rounded-full ${props.screenShare.active ? "bg-cyan-500 text-white" : "bg-white/15 text-white"}`}
          >
            {props.screenShare.active ? <MonitorOff size={20} /> : <Monitor size={20} />}
          </button>
        )}
        {!isVoice && (
        <button
          type="button"
          onClick={() => setRemoteFit((fit) => (fit === "cover" ? "contain" : "cover"))}
          title={remoteFit === "cover" ? "Fit whole picture (show the caller's full frame)" : "Fill screen (crop to fit)"}
          aria-pressed={remoteFit === "contain"}
          className={`flex h-12 w-12 items-center justify-center rounded-full ${remoteFit === "contain" ? "bg-cyan-500 text-white" : "bg-white/15 text-white"}`}
        >
          <Maximize2 size={20} />
        </button>
        )}
        <button type="button" onClick={props.onHangup} title="End call" className="flex h-12 w-12 items-center justify-center rounded-full bg-rose-500 text-white hover:bg-rose-600"><PhoneOff size={20} /></button>
      </div>
    </div>
  );
}