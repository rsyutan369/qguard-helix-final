import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { buildRtcConfiguration } from "@/lib/call-ice";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";
import { sendCallSignal, subscribeCallSignals } from "@/lib/call-signaling";
import type { CallSignalRow } from "@/lib/call-types";
import { safeInvoke } from "@/lib/tauri";
import { recordCryptoTelemetry } from "@/lib/crypto-telemetry";
import {
  applySenderParams,
  applyTrackConstraints,
  DEFAULT_CALL_QUALITY,
  mediaConstraints,
  type CallQuality,
} from "@/lib/call-quality";

interface CallSetup { hybridCiphertext: unknown; sendKeyB64: string; recvKeyB64: string; safetyNumber: string; }
interface Peer { userId: string; deviceId: string; x25519: number[]; mlkem: number[]; displayName: string; }

const AUDIO_CTX = [1, 0, 0, 0];
const VIDEO_CTX = [2, 0, 0, 0];
const callSupported = () =>
  typeof RTCPeerConnection !== "undefined" && typeof RTCRtpScriptTransform !== "undefined";

export function useSecureCall(args: {
  userId: string; deviceId: string; conversationId: string | null; peer: Peer | null;
}) {
  const [state, dispatch] = useReducer(callReducer, INITIAL_CALL_STATE);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [micEnabled, setMicEnabled] = useState(true);
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [quality, setQualityState] = useState<CallQuality>(DEFAULT_CALL_QUALITY);

  const pcRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const qualityRef = useRef<CallQuality>(DEFAULT_CALL_QUALITY);
  const workerRef = useRef<Worker | null>(null);
  const setupRef = useRef<CallSetup | null>(null);
  const pendingOfferRef = useRef<CallSignalRow | null>(null);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  const phaseRef = useRef(state.phase);
  const timeoutRef = useRef<number | undefined>(undefined);
  const supported = useMemo(callSupported, []);

  const worker = useCallback(() => {
    if (!workerRef.current) {
      workerRef.current = new Worker(new URL("./call-crypto-worker.ts", import.meta.url), { type: "module" });
    }
    return workerRef.current;
  }, []);

  const attachSenderTransforms = useCallback((pc: RTCPeerConnection, setup: CallSetup) => {
    pc.getSenders().forEach((sender) => {
      const kind = sender.track?.kind === "audio" ? "audio" : "video";
      (sender as RTCRtpSender).transform = new RTCRtpScriptTransform(worker(), {
        operation: "encrypt", keyB64: setup.sendKeyB64, kind, contextTag: kind === "audio" ? AUDIO_CTX : VIDEO_CTX,
      });
    });
  }, [worker]);

  const flushPendingCandidates = useCallback(() => {
    const pc = pcRef.current;
    if (!pc) return;
    for (const c of pendingCandidatesRef.current) void pc.addIceCandidate(c);
    pendingCandidatesRef.current = [];
  }, []);

  const cleanup = useCallback(() => {
    pcRef.current?.getSenders().forEach((s) => s.track?.stop());
    pcRef.current?.close();
    pcRef.current = null;
    workerRef.current?.terminate();
    workerRef.current = null;
    setupRef.current = null;
    pendingOfferRef.current = null;
    pendingCandidatesRef.current = [];
    if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
    // Read the live stream from a ref so `cleanup` keeps a STABLE identity. If it
    // depended on `localStream` state, the unmount effect below would re-run on
    // every stream change and tear the active call down mid-negotiation (closing
    // the peer connection / worker and releasing the camera in a race).
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
    setLocalStream(null);
    setRemoteStream(null);
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

  const buildPeerConnection = useCallback((callId: string, peer: Peer) => {
    const pc = new RTCPeerConnection(buildRtcConfiguration());
    pc.onicecandidate = (e) => {
      if (!e.candidate || !args.conversationId) return;
      void sendCallSignal({
        call_id: callId, conversation_id: args.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: peer.userId, to_device_id: peer.deviceId,
        signal_type: "ice", payload: { candidate: e.candidate.toJSON() },
      });
    };
    pc.ontrack = (e) => {
      const setup = setupRef.current;
      if (setup) {
        const kind = e.track.kind === "audio" ? "audio" : "video";
        (e.receiver as RTCRtpReceiver).transform = new RTCRtpScriptTransform(worker(), {
          operation: "decrypt", keyB64: setup.recvKeyB64, kind, contextTag: kind === "audio" ? AUDIO_CTX : VIDEO_CTX,
        });
      }
      setRemoteStream(e.streams[0] ?? null);
    };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "connected" && setupRef.current) {
        if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
        dispatch({ type: "media-connected", safetyNumber: setupRef.current.safetyNumber });
        void recordCryptoTelemetry({ userId: args.userId, scope: "call", stage: "call_connected", detail: "Quantum-encrypted call connected", progress: 100, status: "complete", metadata: { call_id: callId } });
      }
      if (["failed", "disconnected", "closed"].includes(pc.connectionState)) endCall(false);
    };
    pcRef.current = pc;
    return pc;
  }, [args.conversationId, args.deviceId, args.userId, worker]);

  const getMedia = useCallback(async () => {
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
    localStreamRef.current = stream;
    setLocalStream(stream);
    return stream;
  }, []);

  const setQuality = useCallback(async (next: CallQuality) => {
    qualityRef.current = next;
    setQualityState(next);
    if (pcRef.current) await applySenderParams(pcRef.current, next);
    await applyTrackConstraints(localStream, next);
  }, [localStream]);

  const startCall = useCallback(async () => {
    if (!supported || !args.peer || !args.conversationId) return;
    const peer = args.peer;
    const callId = crypto.randomUUID();
    dispatch({ type: "start-outgoing", callId, peerUserId: peer.userId, peerDeviceId: peer.deviceId });
    armTimeout(45000);
    try {
      const setup = await safeInvoke<CallSetup>("call_caller_setup", { peerX25519Public: peer.x25519, peerMlkemPublic: peer.mlkem, callId });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = buildPeerConnection(callId, peer);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      attachSenderTransforms(pc, setup);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({ call_id: callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: peer.userId, to_device_id: peer.deviceId, signal_type: "ring", payload: {} });
      await sendCallSignal({ call_id: callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: peer.userId, to_device_id: peer.deviceId, signal_type: "offer", payload: { sdp: offer.sdp, hybridCiphertext: setup.hybridCiphertext } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Call failed" });
      cleanup();
    }
  }, [args, armTimeout, attachSenderTransforms, buildPeerConnection, cleanup, getMedia, supported]);

  const accept = useCallback(async () => {
    const offer = pendingOfferRef.current;
    if (!offer || !args.peer || !args.conversationId) return;
    dispatch({ type: "accept" });
    armTimeout(45000);
    try {
      const setup = await safeInvoke<CallSetup>("call_callee_setup", { hybridCiphertext: (offer.payload as { hybridCiphertext: unknown }).hybridCiphertext, callId: offer.call_id });
      setupRef.current = setup;
      const stream = await getMedia();
      const pc = buildPeerConnection(offer.call_id, args.peer);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      attachSenderTransforms(pc, setup);
      await pc.setRemoteDescription({ type: "offer", sdp: String((offer.payload as { sdp: string }).sdp) });
      flushPendingCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({ call_id: offer.call_id, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: offer.from_user_id, to_device_id: offer.from_device_id, signal_type: "answer", payload: { sdp: answer.sdp } });
    } catch (e) {
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Accept failed" });
      cleanup();
    }
  }, [args, armTimeout, attachSenderTransforms, buildPeerConnection, cleanup, flushPendingCandidates, getMedia]);

  const endCall = useCallback((notify: boolean) => {
    if (notify && state.callId && state.peerUserId && state.peerDeviceId && args.conversationId) {
      void sendCallSignal({ call_id: state.callId, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: state.peerUserId, to_device_id: state.peerDeviceId, signal_type: "hangup", payload: {} });
    }
    dispatch({ type: "ended" });
    cleanup();
  }, [args, cleanup, state]);

  const reject = useCallback(() => {
    const offer = pendingOfferRef.current;
    if (offer && args.conversationId) {
      void sendCallSignal({ call_id: offer.call_id, conversation_id: args.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: offer.from_user_id, to_device_id: offer.from_device_id, signal_type: "reject", payload: {} });
    }
    endCall(false);
  }, [args, endCall]);

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
            const busy = ["ringing", "calling", "connecting", "connected"].includes(phaseRef.current);
            if (busy) {
              if (args.conversationId) {
                void sendCallSignal({
                  call_id: row.call_id, conversation_id: args.conversationId,
                  from_user_id: args.userId, from_device_id: args.deviceId,
                  to_user_id: row.from_user_id, to_device_id: row.from_device_id,
                  signal_type: "busy", payload: {},
                });
              }
              return;
            }
            pendingOfferRef.current = row;
            dispatch({ type: "incoming", callId: row.call_id, peerUserId: row.from_user_id, peerDeviceId: row.from_device_id });
            break;
          }
          case "answer":
            if (pcRef.current && state.role === "caller") {
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
  }, [args.conversationId, args.deviceId, args.userId, endCall, flushPendingCandidates, state.role]);

  // Keep a synchronous mirror of the current phase for ref-based decisions
  // (busy detection, timeouts) inside callbacks that must not re-subscribe.
  useEffect(() => { phaseRef.current = state.phase; }, [state.phase]);

  useEffect(() => () => cleanup(), [cleanup]);

  return { state, localStream, remoteStream, micEnabled, cameraEnabled, quality, setQuality, supported, startCall, accept, reject, hangup, toggleMic, toggleCamera };
}