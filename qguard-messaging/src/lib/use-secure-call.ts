import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { resolveRtcConfiguration } from "@/lib/call-ice";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";
import { sendCallSignal, subscribeCallSignals } from "@/lib/call-signaling";
import type { CallSignalRow } from "@/lib/call-types";
import { safeInvoke } from "@/lib/tauri";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import {
  applyContentHints,
  applySenderParams,
  applyTrackConstraints,
  loadPersistedQuality,
  mediaConstraints,
  persistQuality,
  pinVideoCodec,
  type CallQuality,
} from "@/lib/call-quality";
import { startCallStatsMonitor, type CallStatsSample } from "@/lib/call-stats";
import { makeFrameTransform, type FrameCryptoOptions } from "@/lib/call-media-transform";

interface CallSetup { hybridCiphertext: unknown; sendKeyB64: string; recvKeyB64: string; safetyNumber: string; }

/**
 * Outgoing-call target. Carries the peer device's FULL published identity
 * bundle (KEM keys + signing keys + dual signature): the Rust side refuses to
 * encapsulate a call media key until the Ed25519 + ML-DSA-65 identity
 * signature validates, so a relay that swaps KEM keys cannot MITM a call.
 */
export interface CallPeer {
  userId: string;
  deviceId: string;
  x25519: number[];
  mlkem: number[];
  ed25519: number[];
  mldsa: number[];
  identitySignature: { ed25519: number[]; ml_dsa_65: number[] };
  displayName: string;
}

/** Signal-addressing for the active call: where offers/answers/ice/hangup go. */
interface CallRoute { conversationId: string; toUserId: string; toDeviceId: string; }

const AUDIO_CTX = [1, 0, 0, 0];
const VIDEO_CTX = [2, 0, 0, 0];

// Two encoded-transform plumbings deliver the same E2EE media encryption:
//   - "worker": RTCRtpScriptTransform (Chromium >= 115), runs in a Worker.
//   - "encoded-streams": createEncodedStreams (Chromium 86-114), main thread.
// A newly-installed app on an older WebView2 (seen on a Windows 11 VM) exposes
// ONLY the latter — without this fallback that peer couldn't start a call
// ("Video calling requires the desktop app") and every call it accepted died
// when `new RTCRtpScriptTransform` threw. The wire format is identical, so a
// "worker" peer (host) and an "encoded-streams" peer (VM) interoperate.
type TransformStrategy = "worker" | "encoded-streams" | "none";

function detectTransformStrategy(): TransformStrategy {
  if (typeof RTCRtpScriptTransform !== "undefined") return "worker";
  if (typeof RTCRtpSender !== "undefined" && "createEncodedStreams" in RTCRtpSender.prototype) {
    return "encoded-streams";
  }
  return "none";
}

const callSupported = () =>
  typeof RTCPeerConnection !== "undefined" && detectTransformStrategy() !== "none";

// Main-thread fallback: pipe one sender/receiver's encoded frames through the
// AES-256-GCM transform. Used when RTCRtpScriptTransform is unavailable.
async function pipeEncodedStreams(
  rtp: RTCRtpSender | RTCRtpReceiver,
  opts: FrameCryptoOptions,
): Promise<void> {
  const create = rtp.createEncodedStreams;
  if (!create) return;
  try {
    const streams = create.call(rtp);
    const transform = await makeFrameTransform(opts);
    void streams.readable.pipeThrough(transform).pipeTo(streams.writable);
  } catch {
    // createEncodedStreams throws if called twice or if the pc wasn't built with
    // encodedInsertableStreams; non-fatal.
  }
}

/**
 * Quantum-encrypted call engine. Runs APP-WIDE (see CallProvider): the signal
 * subscription only needs the local user + device, and everything a callee
 * needs to answer (conversation, caller ids, hybrid KEM ciphertext) arrives in
 * the offer row itself — so incoming calls ring on every page, not just while
 * Secure Chat is open. Outgoing calls pass the peer + conversation explicitly
 * to `startCall`.
 */
export function useSecureCall(args: { userId: string; deviceId: string }) {
  const [state, dispatch] = useReducer(callReducer, INITIAL_CALL_STATE);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [micEnabled, setMicEnabled] = useState(true);
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [reconnecting, setReconnecting] = useState(false);
  // Quality survives across calls/app restarts (localStorage) so a user who
  // picked HD (or Low) isn't silently reset to Auto on the next call.
  const [quality, setQualityState] = useState<CallQuality>(loadPersistedQuality);
  // Live diagnostics for the in-call overlay: route (direct/relay), encode &
  // decode resolution/fps/bitrate, RTT, loss, qualityLimitationReason.
  const [stats, setStats] = useState<CallStatsSample | null>(null);

  const pcRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const qualityRef = useRef<CallQuality>(loadPersistedQuality());
  const statsStopRef = useRef<(() => void) | null>(null);
  const workerRef = useRef<Worker | null>(null);
  const setupRef = useRef<CallSetup | null>(null);
  const routeRef = useRef<CallRoute | null>(null);
  const pendingOfferRef = useRef<CallSignalRow | null>(null);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  const phaseRef = useRef(state.phase);
  // Mirrors of call state for the signal subscription, so its handler can read
  // the current role/call id WITHOUT those being effect dependencies. The
  // subscription must stay mounted for the whole session: re-subscribing when a
  // call starts (role/callId change) tore down the Supabase channel mid-setup
  // and dropped the inbound `answer` / ICE candidates, so the call never
  // connected and ended on both ends.
  const callIdRef = useRef<string | null>(state.callId);
  const roleRef = useRef(state.role);
  const timeoutRef = useRef<number | undefined>(undefined);
  // Grace window for a transient ICE `disconnected` blip before we give up. A
  // WebRTC connection frequently flips connected → disconnected → connected on a
  // network path change or brief packet loss; tearing down on the first blip
  // drops calls that would have recovered on their own.
  const reconnectTimerRef = useRef<number | undefined>(undefined);
  const supported = useMemo(callSupported, []);
  const RECONNECT_GRACE_MS = 12000;

  const worker = useCallback(() => {
    if (!workerRef.current) {
      workerRef.current = new Worker(new URL("./call-crypto-worker.ts", import.meta.url), { type: "module" });
    }
    return workerRef.current;
  }, []);

  // Attach the E2EE media transforms for BOTH directions on every transceiver,
  // up-front — right after addTrack and BEFORE createOffer/createAnswer.
  //
  // The receive (decrypt) transform MUST be attached here, not in the async
  // `ontrack` event. In WebView2/Chromium, setting `receiver.transform` from
  // `ontrack` lands after the inbound pipeline is already wired, so the
  // transform never inserts and remote frames reach the decoders still
  // encrypted — the exact "loud static audio + no video" symptom. Attaching at
  // the transceiver level (the receiver exists the moment addTrack creates the
  // transceiver) guarantees the decryptor is in place before the first frame.
  const attachMediaTransforms = useCallback((pc: RTCPeerConnection, setup: CallSetup) => {
    const strategy = detectTransformStrategy();
    const w = strategy === "worker" ? worker() : null;
    for (const transceiver of pc.getTransceivers()) {
      const kind = transceiver.sender.track?.kind;
      if (kind !== "audio" && kind !== "video") continue;
      const contextTag = kind === "audio" ? AUDIO_CTX : VIDEO_CTX;
      const encryptOpts: FrameCryptoOptions = { operation: "encrypt", keyB64: setup.sendKeyB64, kind, contextTag };
      const decryptOpts: FrameCryptoOptions = { operation: "decrypt", keyB64: setup.recvKeyB64, kind, contextTag };
      if (w) {
        (transceiver.sender as RTCRtpSender).transform = new RTCRtpScriptTransform(w, encryptOpts);
        (transceiver.receiver as RTCRtpReceiver).transform = new RTCRtpScriptTransform(w, decryptOpts);
      } else {
        void pipeEncodedStreams(transceiver.sender, encryptOpts);
        void pipeEncodedStreams(transceiver.receiver, decryptOpts);
      }
    }
  }, [worker]);

  const flushPendingCandidates = useCallback(() => {
    const pc = pcRef.current;
    if (!pc) return;
    for (const c of pendingCandidatesRef.current) void pc.addIceCandidate(c);
    pendingCandidatesRef.current = [];
  }, []);

  const cleanup = useCallback(() => {
    statsStopRef.current?.();
    statsStopRef.current = null;
    setStats(null);
    pcRef.current?.getSenders().forEach((s) => s.track?.stop());
    pcRef.current?.close();
    pcRef.current = null;
    workerRef.current?.terminate();
    workerRef.current = null;
    setupRef.current = null;
    routeRef.current = null;
    pendingOfferRef.current = null;
    pendingCandidatesRef.current = [];
    if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
    if (reconnectTimerRef.current !== undefined) { window.clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = undefined; }
    setReconnecting(false);
    // Read the live stream from a ref so `cleanup` keeps a STABLE identity. If it
    // depended on `localStream` state, the unmount effect below would re-run on
    // every stream change and tear the active call down mid-negotiation (closing
    // the peer connection / worker and releasing the camera in a race).
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
    setLocalStream(null);
    setRemoteStream(null);
    // Call media fully released — stand down the freeze watchdog.
    void safeInvoke("call_watchdog_end", undefined, null);
  }, []);

  const armTimeout = useCallback((ms: number) => {
    if (timeoutRef.current !== undefined) window.clearTimeout(timeoutRef.current);
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = undefined;
      if (phaseRef.current !== "connected") {
        dispatch({ type: "failed", error: "Call timed out" });
        cleanup();
      }
    }, ms);
  }, [cleanup]);

  const buildPeerConnection = useCallback(async (callId: string, route: CallRoute) => {
    // Live STUN/TURN resolution (operator relay config → env → Open Relay):
    // cached + short-timeout, so it adds ~0ms in the steady state and can
    // never block a call — see call-ice.ts.
    // The legacy createEncodedStreams() plumbing requires this Chromium flag at
    // construction; RTCRtpScriptTransform doesn't need it, so we only set it when
    // the fallback will be used.
    const rtcConfig = await resolveRtcConfiguration();
    const pc = new RTCPeerConnection(
      detectTransformStrategy() === "encoded-streams"
        ? { ...rtcConfig, encodedInsertableStreams: true }
        : rtcConfig,
    );
    pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      void sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "ice", payload: { candidate: e.candidate.toJSON() },
      });
    };
    // Inbound decryption is wired up-front in attachMediaTransforms (before
    // negotiation) — see that function. Here we only surface the remote stream
    // to the UI.
    pc.ontrack = (e) => {
      setRemoteStream(e.streams[0] ?? null);
    };
    pc.onconnectionstatechange = () => {
      const cs = pc.connectionState;
      if (cs === "connected") {
        // Cleared the setup timeout and any in-flight reconnect grace: the media
        // path is (re)established.
        if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
        if (reconnectTimerRef.current !== undefined) { window.clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = undefined; }
        setReconnecting(false);
        if (setupRef.current) {
          dispatch({ type: "media-connected", safetyNumber: setupRef.current.safetyNumber });
          void recordCryptoTelemetry({ userId: args.userId, scope: "call", stage: "call_connected", detail: "Quantum-encrypted call connected", progress: 100, status: "complete", metadata: { call_id: callId } });
        }
        // Encoder ceilings can be ignored when set pre-ICE; re-assert them on
        // the established connection so the negotiated path runs at full tier.
        void applySenderParams(pc, qualityRef.current);
        // Live quality diagnostics for the whole connected span (idempotent
        // across reconnect blips — only one monitor per peer connection).
        if (!statsStopRef.current) {
          statsStopRef.current = startCallStatsMonitor(pc, setStats);
        }
        return;
      }
      // A hard, non-recoverable end: tear down immediately.
      if (cs === "failed" || cs === "closed") { endCall(false); return; }
      // A transient blip: surface "Reconnecting…" and let ICE try to recover for
      // a grace window instead of dropping the call outright.
      if (cs === "disconnected") {
        setReconnecting(true);
        if (reconnectTimerRef.current === undefined) {
          reconnectTimerRef.current = window.setTimeout(() => {
            reconnectTimerRef.current = undefined;
            if (pcRef.current && pcRef.current.connectionState !== "connected") endCall(false);
          }, RECONNECT_GRACE_MS);
        }
      }
    };
    pcRef.current = pc;
    return pc;
  }, [args.deviceId, args.userId]);

  const getMedia = useCallback(async () => {
    // Freeze watchdog: mark that a call is about to engage the media pipeline
    // BEFORE the camera opens. If the machine/app dies while the marker is set
    // (GPU driver wedge → hard restart), the next launch boots WebView2 in
    // GPU-safe software rendering. Cleared in cleanup() and on graceful close.
    // Fallback `null` keeps non-Tauri environments (tests, web preview) working.
    await safeInvoke("call_watchdog_begin", undefined, null);
    const constraints = mediaConstraints(qualityRef.current);
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch {
      // Camera missing/blocked or constraints rejected → fall back to audio-only
      // so a bad webcam can never hang the call (a key freeze guard).
      stream = await navigator.mediaDevices.getUserMedia({ audio: constraints.audio ?? true });
      setCameraEnabled(false);
    }
    // Steer encoder degradation decisions: camera = "motion", mic = "speech".
    applyContentHints(stream);
    localStreamRef.current = stream;
    setLocalStream(stream);
    return stream;
  }, []);

  const setQuality = useCallback(async (next: CallQuality) => {
    qualityRef.current = next;
    setQualityState(next);
    persistQuality(next);
    if (pcRef.current) await applySenderParams(pcRef.current, next);
    await applyTrackConstraints(localStream, next);
  }, [localStream]);

  const startCall = useCallback(async (peer: CallPeer, conversationId: string) => {
    if (!supported || !args.deviceId || !conversationId) return;
    const route: CallRoute = { conversationId, toUserId: peer.userId, toDeviceId: peer.deviceId };
    routeRef.current = route;
    const callId = crypto.randomUUID();
    dispatch({ type: "start-outgoing", callId, peerUserId: peer.userId, peerDeviceId: peer.deviceId });
    armTimeout(45000);
    try {
      const setup = await safeInvoke<CallSetup>("call_caller_setup", {
        peer: {
          user_id: peer.userId,
          device_id: peer.deviceId,
          x25519_identity_public: peer.x25519,
          mlkem_identity_public: peer.mlkem,
          ed25519_identity_public: peer.ed25519,
          mldsa_identity_public: peer.mldsa,
          identity_signature: peer.identitySignature,
        },
        callId,
      });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = await buildPeerConnection(callId, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Deterministic VP8: the E2EE frame crypto's unencrypted-header layout is
      // VP8-specific, so codec negotiation must never drift (see call-quality.ts).
      pinVideoCodec(pc);
      attachMediaTransforms(pc, setup);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({ call_id: callId, conversation_id: route.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: route.toUserId, to_device_id: route.toDeviceId, signal_type: "ring", payload: {} });
      await sendCallSignal({ call_id: callId, conversation_id: route.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: route.toUserId, to_device_id: route.toDeviceId, signal_type: "offer", payload: { sdp: offer.sdp, hybridCiphertext: setup.hybridCiphertext } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Call failed" });
      cleanup();
    }
  }, [args.deviceId, args.userId, armTimeout, attachMediaTransforms, buildPeerConnection, cleanup, getMedia, supported]);

  const accept = useCallback(async () => {
    const offer = pendingOfferRef.current;
    if (!offer) return;
    // Everything the callee needs travels in the offer row: the conversation,
    // the caller's user/device ids, and the hybrid KEM ciphertext.
    const route: CallRoute = { conversationId: offer.conversation_id, toUserId: offer.from_user_id, toDeviceId: offer.from_device_id };
    routeRef.current = route;
    dispatch({ type: "accept" });
    armTimeout(45000);
    try {
      const setup = await safeInvoke<CallSetup>("call_callee_setup", { hybridCiphertext: (offer.payload as { hybridCiphertext: unknown }).hybridCiphertext, callId: offer.call_id });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = await buildPeerConnection(offer.call_id, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Same VP8 pinning as the caller side, before the answer is created.
      pinVideoCodec(pc);
      attachMediaTransforms(pc, setup);
      await pc.setRemoteDescription({ type: "offer", sdp: String((offer.payload as { sdp: string }).sdp) });
      flushPendingCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({ call_id: offer.call_id, conversation_id: route.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: route.toUserId, to_device_id: route.toDeviceId, signal_type: "answer", payload: { sdp: answer.sdp } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Accept failed" });
      cleanup();
    }
  }, [args.deviceId, args.userId, armTimeout, attachMediaTransforms, buildPeerConnection, cleanup, flushPendingCandidates, getMedia]);

  const endCall = useCallback((notify: boolean) => {
    const route = routeRef.current;
    const callId = callIdRef.current;
    // Stable identity (reads the call id from a ref, not state) so it is NOT a
    // dependency that would re-subscribe the signal channel mid-call.
    if (notify && callId && route) {
      void sendCallSignal({ call_id: callId, conversation_id: route.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: route.toUserId, to_device_id: route.toDeviceId, signal_type: "hangup", payload: {} });
    }
    dispatch({ type: "ended" });
    cleanup();
  }, [args.deviceId, args.userId, cleanup]);

  const reject = useCallback(() => {
    const offer = pendingOfferRef.current;
    if (offer) {
      void sendCallSignal({ call_id: offer.call_id, conversation_id: offer.conversation_id, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: offer.from_user_id, to_device_id: offer.from_device_id, signal_type: "reject", payload: {} });
    }
    endCall(false);
  }, [args.deviceId, args.userId, endCall]);

  const hangup = useCallback(() => endCall(true), [endCall]);
  const toggleMic = useCallback(() => { localStream?.getAudioTracks().forEach((t) => (t.enabled = !t.enabled)); setMicEnabled((v) => !v); }, [localStream]);
  const toggleCamera = useCallback(() => { localStream?.getVideoTracks().forEach((t) => (t.enabled = !t.enabled)); setCameraEnabled((v) => !v); }, [localStream]);

  // Signal handling
  useEffect(() => {
    if (!args.userId || !args.deviceId) return;
    const unsub = subscribeCallSignals({
      userId: args.userId, deviceId: args.deviceId,
      onSignal: (row) => {
        if (row.from_user_id === args.userId) return;
        switch (row.signal_type) {
          case "offer": {
            // A re-delivered offer for the call we're already handling (realtime
            // can deliver an insert more than once): ignore it. Replying "busy"
            // to our own in-progress call is what tore it down on accept.
            if (row.call_id === callIdRef.current) return;
            const busy = ["ringing", "calling", "connecting", "connected"].includes(phaseRef.current);
            if (busy) {
              void sendCallSignal({
                call_id: row.call_id, conversation_id: row.conversation_id,
                from_user_id: args.userId, from_device_id: args.deviceId,
                to_user_id: row.from_user_id, to_device_id: row.from_device_id,
                signal_type: "busy", payload: {},
              });
              return;
            }
            pendingOfferRef.current = row;
            dispatch({ type: "incoming", callId: row.call_id, peerUserId: row.from_user_id, peerDeviceId: row.from_device_id });
            break;
          }
          case "answer":
            if (pcRef.current && roleRef.current === "caller") {
              void pcRef.current
                .setRemoteDescription({ type: "answer", sdp: String(row.payload.sdp) })
                .then(() => flushPendingCandidates());
              dispatch({ type: "remote-answered" });
            }
            break;
          case "ice": {
            if (!row.payload.candidate) break;
            const candidate = row.payload.candidate as RTCIceCandidateInit;
            if (pcRef.current?.remoteDescription) void pcRef.current.addIceCandidate(candidate);
            else pendingCandidatesRef.current.push(candidate);
            break;
          }
          case "reject": case "hangup": case "busy":
            endCall(false);
            break;
          default: break;
        }
      },
    });
    return unsub;
  }, [args.deviceId, args.userId, endCall, flushPendingCandidates]);

  // Keep synchronous mirrors of call state for ref-based decisions (busy
  // detection, role checks, hangup addressing) inside the signal handler, so it
  // never has to re-subscribe when a call starts or changes phase.
  useEffect(() => { phaseRef.current = state.phase; }, [state.phase]);
  useEffect(() => { callIdRef.current = state.callId; }, [state.callId]);
  useEffect(() => { roleRef.current = state.role; }, [state.role]);

  useEffect(() => () => cleanup(), [cleanup]);

  return { state, localStream, remoteStream, micEnabled, cameraEnabled, reconnecting, quality, setQuality, stats, supported, startCall, accept, reject, hangup, toggleMic, toggleCamera };
}
