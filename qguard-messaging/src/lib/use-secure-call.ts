import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  describeCallConnectFailure,
  lastRelayHealth,
  prewarmRtcConfiguration,
  probeRelayHealth,
  resolveRtcConfiguration,
} from "@/lib/call-ice";
import { connectDeadlineMs } from "@/lib/call-deadline";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";
import { sendCallSignal, sendCallSignals, subscribeCallSignals, type CallSignalChannel } from "@/lib/call-signaling";
import { applyDecline } from "@/lib/call-targets";
import type { CallPeer, CallPeerDevice } from "@/lib/call-targets";
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
import { releaseCallWakeLock, requestCallWakeLock } from "@/lib/call-wake-lock";
import { makeFrameTransform, type FrameCryptoOptions } from "@/lib/call-media-transform";

interface CallSetup { hybridCiphertext: unknown; sendKeyB64: string; recvKeyB64: string; safetyNumber: string; }

/**
 * Outgoing-call target: one person and EVERY device they can be reached on.
 * Each device carries its FULL published identity bundle (KEM keys + signing
 * keys + dual signature) — the Rust side refuses to encapsulate a call media
 * key until the Ed25519 + ML-DSA-65 identity signature validates, so a relay
 * that swaps KEM keys cannot MITM a call. See lib/call-targets.ts for why the
 * target is a device LIST rather than a single device.
 */
export type { CallPeer, CallPeerDevice } from "@/lib/call-targets";

/** Signal-addressing for the active call: where offers/answers/ice/hangup go. */
interface CallRoute { conversationId: string; toUserId: string; toDeviceId: string; }

const AUDIO_CTX = [1, 0, 0, 0];
const VIDEO_CTX = [2, 0, 0, 0];

// Ring/offer rows older than this are leftovers from a previous session (the
// catch-up reader looks back over a window, and a device that was offline can
// see a long-dead call). Never pop an incoming-call modal for one. Matched to
// the caller's own 45s give-up: past that, nobody is still dialling.
const SIGNAL_FRESHNESS_MS = 45_000;
// How long `accept()` waits for the caller's offer row when the user answers
// off the ring — the ring is sent BEFORE the caller's camera and KEM setup, so
// a fast tap on Accept legitimately arrives first.
const OFFER_WAIT_MS = 30_000;

// ---- Give-up policy ----
//
// A single fixed 45s wall clock from the ring used to govern the whole call,
// and it dropped calls at the exact moment they were about to work. Observed:
// a multi-NIC Windows callee emitted its only usable candidate (the LAN UDP
// host address) 48s in, three seconds AFTER the caller had already given up and
// torn everything down. The clock was measuring the wrong thing — elapsed time
// says nothing about whether the connection is still making progress.
//
// So the two phases are now timed separately, and the connect phase is
// progress-based:
//   * RING     — nobody has answered. A pure wall clock is correct here: it
//                bounds how long a phone rings.
//   * CONNECT  — someone answered and ICE is working. The deadline resets on
//                every sign of progress (a candidate gathered, a candidate
//                received, an ICE state change), so a slow-but-advancing setup
//                is allowed to finish. STALL is how long we tolerate NO
//                progress at all; CEILING is the absolute backstop so a call
//                that trickles candidates forever still ends.
const RING_TIMEOUT_MS = 45_000;
const INCOMING_RING_TIMEOUT_MS = 60_000;
const CONNECT_STALL_MS = 20_000;
const CONNECT_CEILING_MS = 90_000;

// Chromium emits ICE candidates in bursts. One INSERT per candidate turned a
// burst into 6-10 sequential round trips on the call's critical path; coalescing
// them into a single batched write cuts that to one, and 40ms is short enough
// to be invisible next to a network round trip.
const ICE_BATCH_MS = 40;

function isFreshSignal(row: CallSignalRow): boolean {
  const at = new Date(row.created_at).getTime();
  if (!Number.isFinite(at)) return true;
  // Only "too old" is disqualifying; a device clock running behind the DB
  // yields a negative age, which is harmless.
  return Date.now() - at < SIGNAL_FRESHNESS_MS;
}

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
  // ---- Outgoing fan-out (caller side) ----
  // Every peer device this call is ringing. A hangup/give-up must reach ALL of
  // them, or the devices that did not win the race keep ringing forever.
  const ringTargetsRef = useRef<CallRoute[]>([]);
  // Per-device caller setup, pre-computed while the peer's devices ring. The
  // hybrid KEM ciphertext is encapsulated to ONE device's keys, so the winner's
  // setup is the one that gets attached to the peer connection. Pre-computing
  // keeps the post-answer path as fast as the old single-device flow.
  const setupsByDeviceRef = useRef<Map<string, CallSetup>>(new Map());
  // First device to accept wins; later accepts are told to stop ringing. Guards
  // the race where two of the peer's devices answer within the same tick.
  const answeredDeviceRef = useRef<string | null>(null);
  // An accept that arrived BEFORE this device's camera and per-device KEM setup
  // finished. The ring is sent first precisely so the peer can answer instantly,
  // so a fast tap legitimately beats our own setup; without this the accept
  // would be dropped and the call would hang until the give-up.
  const pendingAcceptDeviceRef = useRef<string | null>(null);
  const pendingOfferRef = useRef<CallSignalRow | null>(null);
  // The `ring` that opened the incoming-call modal. It carries the caller's
  // ids + conversation, so the callee can answer (and address `accept`/`reject`)
  // before the offer — which the caller only sends once its camera and hybrid
  // KEM setup finish — has landed.
  const pendingRingRef = useRef<CallSignalRow | null>(null);
  // Resolvers waiting for the offer of the call currently being answered.
  const offerWaitersRef = useRef<Array<(row: CallSignalRow) => void>>([]);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  // Live signal transport, so a call can switch it into fast catch-up polling.
  const signalChannelRef = useRef<CallSignalChannel | null>(null);
  // Bumped by cleanup(); lets a late `getUserMedia` resolution know its call is
  // already gone so it releases the camera instead of re-arming it.
  const callGenRef = useRef(0);
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
  // Absolute deadline for the connect phase (0 = not connecting). Set when a
  // call is answered; every ICE progress signal re-arms the stall timer against
  // whatever is left of it.
  const connectCeilingRef = useRef(0);
  // Outgoing ICE candidates waiting to be written as one batch.
  const iceQueueRef = useRef<Array<{ route: CallRoute; candidate: RTCIceCandidateInit }>>([]);
  const iceFlushTimerRef = useRef<number | undefined>(undefined);
  // One ICE restart per call. A restart is the standard recovery for a path
  // change (Wi-Fi to cellular, a NAT rebinding); allowing more than one would
  // let a genuinely dead call renegotiate in a loop instead of ending.
  const iceRestartUsedRef = useRef(false);
  const renegotiatingRef = useRef(false);
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
    // Invalidate any media capture still in flight. Camera warm-up now overlaps
    // signalling, so a call that fails or is hung up mid-setup can have a
    // `getUserMedia` promise that resolves AFTER teardown — without this guard
    // it would re-arm `localStreamRef` and leave the camera light on with no call.
    callGenRef.current += 1;
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
    ringTargetsRef.current = [];
    setupsByDeviceRef.current.clear();
    answeredDeviceRef.current = null;
    pendingAcceptDeviceRef.current = null;
    pendingOfferRef.current = null;
    pendingRingRef.current = null;
    offerWaitersRef.current = [];
    pendingCandidatesRef.current = [];
    if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
    if (reconnectTimerRef.current !== undefined) { window.clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = undefined; }
    if (iceFlushTimerRef.current !== undefined) { window.clearTimeout(iceFlushTimerRef.current); iceFlushTimerRef.current = undefined; }
    iceQueueRef.current = [];
    connectCeilingRef.current = 0;
    iceRestartUsedRef.current = false;
    renegotiatingRef.current = false;
    setReconnecting(false);
    // Read the live stream from a ref so `cleanup` keeps a STABLE identity. If it
    // depended on `localStream` state, the unmount effect below would re-run on
    // every stream change and tear the active call down mid-negotiation (closing
    // the peer connection / worker and releasing the camera in a race).
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
    setLocalStream(null);
    setRemoteStream(null);
    releaseCallWakeLock();
    // Call media fully released — stand down the freeze watchdog.
    void safeInvoke("call_watchdog_end", undefined, null);
  }, []);

  /**
   * Every device that must be told this call is over: the peer devices still
   * ringing from the outgoing fan-out, plus the device we actually bound to.
   *
   * A single-route hangup was only ever correct when a call rang one device.
   * Now that it forks, a give-up addressed to one device would leave the peer's
   * other phones ringing until their own 60s ceiling.
   */
  const teardownRoutes = useCallback((): CallRoute[] => {
    const routes = [...ringTargetsRef.current];
    const active = routeRef.current;
    if (active && !routes.some((route) => route.toDeviceId === active.toDeviceId)) routes.push(active);
    return routes;
  }, []);

  /** Send one signal type to a set of peer devices in a single round trip. */
  const signalRoutes = useCallback((callId: string, routes: CallRoute[], type: "hangup" | "ring") => {
    if (routes.length === 0) return;
    void sendCallSignals(
      routes.map((route) => ({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: type, payload: {},
      })),
    ).catch(() => undefined);
  }, [args.deviceId, args.userId]);

  const armTimeout = useCallback((ms: number) => {
    if (timeoutRef.current !== undefined) window.clearTimeout(timeoutRef.current);
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = undefined;
      if (phaseRef.current === "connected") return;
      // Every far end is now told about the give-up. Since the ring is sent
      // before any local setup, an unanswered call leaves the callee's phones
      // ringing — and because an outgoing call forks to ALL of the peer's
      // devices, this has to reach all of them, not just the bound route.
      const callId = callIdRef.current;
      if (callId) signalRoutes(callId, teardownRoutes(), "hangup");
      // A give-up during the RING phase means nobody picked up; a give-up after
      // that means the media path could not be built, which is worth explaining
      // (most often: no working relay between two different networks).
      dispatch({
        type: "failed",
        error: connectCeilingRef.current
          ? describeCallConnectFailure(lastRelayHealth())
          : "No answer.",
      });
      // Re-check the relay off the call path, so the NEXT call already knows.
      void probeRelayHealth(true).catch(() => undefined);
      cleanup();
    }, ms);
  }, [cleanup, signalRoutes, teardownRoutes]);

  /**
   * Enter the connect phase: the call has been answered and ICE is now
   * responsible for getting media flowing. Starts the absolute ceiling and arms
   * the first stall window.
   */
  const beginConnectPhase = useCallback(() => {
    connectCeilingRef.current = Date.now() + CONNECT_CEILING_MS;
    armTimeout(CONNECT_STALL_MS);
  }, [armTimeout]);

  /**
   * ICE did something. Push the stall deadline out, bounded by the ceiling.
   *
   * This is what stops a slow gatherer from being killed mid-handshake: as long
   * as candidates keep arriving or the ICE state keeps moving, the call is
   * still trying and is given room to finish.
   */
  const noteIceProgress = useCallback(() => {
    if (phaseRef.current === "connected") return;
    const next = connectDeadlineMs(Date.now(), connectCeilingRef.current, CONNECT_STALL_MS);
    if (next === null) return;
    armTimeout(next);
  }, [armTimeout]);

  /** Write every queued ICE candidate in one round trip. */
  const flushIceCandidates = useCallback((callId: string) => {
    if (iceFlushTimerRef.current !== undefined) {
      window.clearTimeout(iceFlushTimerRef.current);
      iceFlushTimerRef.current = undefined;
    }
    const queued = iceQueueRef.current;
    if (queued.length === 0) return;
    iceQueueRef.current = [];
    void sendCallSignals(queued.map(({ route, candidate }) => ({
      call_id: callId, conversation_id: route.conversationId,
      from_user_id: args.userId, from_device_id: args.deviceId,
      to_user_id: route.toUserId, to_device_id: route.toDeviceId,
      signal_type: "ice" as const, payload: { candidate },
    }))).catch(() => undefined);
  }, [args.deviceId, args.userId]);

  const queueIceCandidate = useCallback((callId: string, route: CallRoute, candidate: RTCIceCandidateInit) => {
    iceQueueRef.current.push({ route, candidate });
    if (iceFlushTimerRef.current !== undefined) return;
    iceFlushTimerRef.current = window.setTimeout(() => {
      iceFlushTimerRef.current = undefined;
      flushIceCandidates(callId);
    }, ICE_BATCH_MS);
  }, [flushIceCandidates]);

  /**
   * Recover a live call whose transport died, by renegotiating ICE.
   *
   * A `failed` peer connection is not necessarily a dead call: switching from
   * Wi-Fi to cellular, a NAT rebinding, or a VPN coming up invalidates every
   * candidate pair while both peers are still perfectly reachable. An ICE
   * restart re-gathers and re-pairs on the new path without touching the media
   * keys, so the call resumes instead of dropping.
   *
   * Only the offerer restarts (the answerer would collide with it), only once
   * per call, and only while a route and a peer connection still exist. Returns
   * true when a restart is under way, so the caller does not also tear down.
   */
  const tryIceRestart = useCallback((): boolean => {
    const pc = pcRef.current;
    const route = routeRef.current;
    const callId = callIdRef.current;
    const setup = setupRef.current;
    if (!pc || !route || !callId || !setup) return false;
    if (roleRef.current !== "caller") return false;
    if (iceRestartUsedRef.current || renegotiatingRef.current) return false;
    iceRestartUsedRef.current = true;
    renegotiatingRef.current = true;
    setReconnecting(true);
    signalChannelRef.current?.boost();
    beginConnectPhase();
    void (async () => {
      try {
        const offer = await pc.createOffer({ iceRestart: true });
        await pc.setLocalDescription(offer);
        await sendCallSignal({
          call_id: callId, conversation_id: route.conversationId,
          from_user_id: args.userId, from_device_id: args.deviceId,
          to_user_id: route.toUserId, to_device_id: route.toDeviceId,
          // The hybrid ciphertext is repeated so a peer running an older build,
          // which treats every offer as a fresh one, can still decapsulate. The
          // media keys themselves are unchanged: a restart re-negotiates the
          // transport, never the cryptography.
          signal_type: "offer", payload: { sdp: offer.sdp, hybridCiphertext: setup.hybridCiphertext, iceRestart: true },
        });
      } catch {
        renegotiatingRef.current = false;
        endCall(false);
      }
    })();
    return true;
  }, [args.deviceId, args.userId, beginConnectPhase]); // eslint-disable-line react-hooks/exhaustive-deps

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
      // End-of-candidates: flush whatever is still queued immediately rather
      // than waiting out the batch window.
      if (!e.candidate) { flushIceCandidates(callId); return; }
      // Gathering a candidate is progress — this is precisely the signal the old
      // fixed timeout ignored while it killed calls that were still working.
      noteIceProgress();
      queueIceCandidate(callId, route, e.candidate.toJSON());
    };
    // ICE state movement counts as progress too, so a connection that is
    // checking pairs is never mistaken for a stalled one.
    pc.oniceconnectionstatechange = () => noteIceProgress();
    pc.onicegatheringstatechange = () => noteIceProgress();
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
        connectCeilingRef.current = 0;
        renegotiatingRef.current = false;
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
      // `failed` is recoverable exactly once, via an ICE restart — the standard
      // remedy when the network path changes underneath a live call (Wi-Fi to
      // cellular, a NAT rebinding). Only the offerer may restart; the answerer
      // waits for the restart offer. `closed` is final.
      if (cs === "failed") {
        if (tryIceRestart()) return;
        endCall(false);
        return;
      }
      if (cs === "closed") { endCall(false); return; }
      // A transient blip: surface "Reconnecting…" and let ICE try to recover for
      // a grace window instead of dropping the call outright.
      if (cs === "disconnected") {
        setReconnecting(true);
        if (reconnectTimerRef.current === undefined) {
          reconnectTimerRef.current = window.setTimeout(() => {
            reconnectTimerRef.current = undefined;
            if (!pcRef.current || pcRef.current.connectionState === "connected") return;
            // Grace expired without recovery: try one ICE restart before ending.
            if (tryIceRestart()) return;
            endCall(false);
          }, RECONNECT_GRACE_MS);
        }
      }
    };
    pcRef.current = pc;
    return pc;
    // `args.userId` is read by the connect telemetry below; `endCall` is
    // deliberately NOT a dependency (stable-identity rule at the top of this
    // file -- making it one would re-subscribe the signal channel mid-call).
  }, [args.userId, flushIceCandidates, noteIceProgress, queueIceCandidate, tryIceRestart]);

  const getMedia = useCallback(async () => {
    // Freeze watchdog: mark that a call is about to engage the media pipeline
    // BEFORE the camera opens. If the machine/app dies while the marker is set
    // (GPU driver wedge → hard restart), the next launch boots WebView2 in
    // GPU-safe software rendering. Cleared in cleanup() and on graceful close.
    // Fallback `null` keeps non-Tauri environments (tests, web preview) working.
    const generation = callGenRef.current;
    // Hold the screen awake from the moment the camera engages: on Android a
    // screen timeout suspends the WebView and starves the peer connection, so
    // a long call would otherwise die of inactivity rather than of any fault.
    requestCallWakeLock();
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
    if (callGenRef.current !== generation) {
      stream.getTracks().forEach((t) => t.stop());
      throw new Error("Call ended before the camera was ready");
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

  /**
   * Resolve once the offer row for `callId` is in hand. The callee can answer
   * before the caller has finished opening its camera and deriving the hybrid
   * KEM key, so "Accept" must be able to wait for the offer instead of being a
   * no-op (which used to make an early tap do nothing at all).
   */
  const waitForOffer = useCallback((callId: string): Promise<CallSignalRow> => {
    const existing = pendingOfferRef.current;
    if (existing && existing.call_id === callId) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => {
        offerWaitersRef.current = offerWaitersRef.current.filter((w) => w !== waiter);
        reject(new Error("The caller never completed the connection setup"));
      }, OFFER_WAIT_MS);
      const waiter = (row: CallSignalRow) => {
        if (row.call_id !== callId) return;
        window.clearTimeout(timer);
        offerWaitersRef.current = offerWaitersRef.current.filter((w) => w !== waiter);
        resolve(row);
      };
      offerWaitersRef.current.push(waiter);
    });
  }, []);

  /**
   * A peer device accepted: bind the call to it, send it the offer built from
   * ITS pre-computed key material, and stop every other device ringing.
   *
   * Only the first accept wins — two of the peer's devices can answer within
   * the same tick, and the loser must be hung up rather than left half-joined.
   */
  const bindAcceptedDevice = useCallback(async (callId: string, deviceId: string) => {
    if (answeredDeviceRef.current) return;
    const route = ringTargetsRef.current.find((r) => r.toDeviceId === deviceId);
    const setup = setupsByDeviceRef.current.get(deviceId);
    const stream = localStreamRef.current;
    // Key material or media not ready yet (a very fast accept, which the
    // ring-first design makes likely): park it. startCall replays it the moment
    // the camera and the per-device KEM setups are ready.
    if (!route || !setup || !stream) {
      if (route) pendingAcceptDeviceRef.current = deviceId;
      return;
    }
    answeredDeviceRef.current = deviceId;
    routeRef.current = route;
    // Everyone else stops ringing immediately, before the offer round trip.
    signalRoutes(callId, ringTargetsRef.current.filter((r) => r.toDeviceId !== deviceId), "hangup");
    ringTargetsRef.current = [route];
    try {
      setupRef.current = setup;
      const pc = await buildPeerConnection(callId, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Deterministic VP8: the E2EE frame crypto's unencrypted-header layout is
      // VP8-specific, so codec negotiation must never drift (see call-quality.ts).
      pinVideoCodec(pc);
      // Transforms are attached BEFORE the offer, so no frame can ever leave
      // this device before its E2EE transform is in place.
      attachMediaTransforms(pc, setup);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "offer", payload: { sdp: offer.sdp, hybridCiphertext: setup.hybridCiphertext },
      });
      // Answered and negotiating: the wall clock hands over to the
      // progress-based deadline for the rest of the connect.
      beginConnectPhase();
    } catch (e) {
      signalRoutes(callId, [route], "hangup");
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Call failed" });
      cleanup();
    }
  }, [args.deviceId, args.userId, attachMediaTransforms, beginConnectPhase, buildPeerConnection, cleanup, signalRoutes]);

  const startCall = useCallback(async (peer: CallPeer, conversationId: string) => {
    if (!supported || !args.deviceId || !conversationId) return;
    if (peer.devices.length === 0) return;
    // FORK THE RING. A peer is a person, not a device: addressing the call to
    // one device meant that if they were sitting at any other one it never rang,
    // the caller sat on "Connecting…" until the give-up, and no safety number
    // was ever derived (it only exists once media connects). Ring every device
    // and let the first one to answer take the call.
    const routes: CallRoute[] = peer.devices.map((device) => ({
      conversationId, toUserId: peer.userId, toDeviceId: device.deviceId,
    }));
    ringTargetsRef.current = routes;
    // Provisionally address the most likely device (the caller's ordering puts
    // the most-recently-seen first) so a reject/timeout before anyone answers
    // still has somewhere to go; rebound for real on the winning accept.
    routeRef.current = routes[0];
    const callId = crypto.randomUUID();
    dispatch({ type: "start-outgoing", callId, peerUserId: peer.userId, peerDeviceId: peer.devices[0].deviceId });
    // Ring phase: a pure wall clock, bounding how long the peer's devices ring.
    armTimeout(RING_TIMEOUT_MS);
    // Fast catch-up polling for the whole setup window: the `accept`, `answer`
    // and first ICE candidates must not wait on a possibly-suspended WebSocket.
    signalChannelRef.current?.boost();
    try {
      // RING FIRST — one insert for every device, nothing else on the critical
      // path. Previously the ring went out only AFTER caller KEM setup + camera
      // open + ICE config resolution + offer creation, which on a phone is
      // several seconds of dead air.
      await sendCallSignals(routes.map((route) => ({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "ring" as const, payload: {},
      })));

      // Everything expensive runs CONCURRENTLY while the peer's devices ring:
      // the camera warm-up, the relay config read, and one KEM encapsulation
      // PER DEVICE. Pre-computing every device's setup is what keeps the
      // post-answer path as fast as the old single-device flow — the winner's
      // ciphertext is already in hand the moment they accept.
      const [stream] = await Promise.all([
        getMedia(),
        resolveRtcConfiguration().catch(() => undefined),
        ...peer.devices.map(async (device: CallPeerDevice) => {
          const setup = await safeInvoke<CallSetup>("call_caller_setup", {
            peer: {
              user_id: peer.userId,
              device_id: device.deviceId,
              x25519_identity_public: device.x25519,
              mlkem_identity_public: device.mlkem,
              ed25519_identity_public: device.ed25519,
              mldsa_identity_public: device.mldsa,
              identity_signature: device.identitySignature,
            },
            callId,
          });
          setupsByDeviceRef.current.set(device.deviceId, setup);
        }),
      ]);
      // Media is live and every device's key material is ready. The offer is
      // NOT sent yet: it is built for whichever device accepts, because the
      // hybrid ciphertext and the media keys are per-device. The callee already
      // sends `accept` and then waits for the offer (`waitForOffer`), so this
      // is the protocol it was written for — no wire change on the callee side.
      void stream;
      // A device that answered while we were still opening the camera.
      const early = pendingAcceptDeviceRef.current;
      if (early) {
        pendingAcceptDeviceRef.current = null;
        await bindAcceptedDevice(callId, early);
      }
    } catch (e) {
      signalRoutes(callId, routes, "hangup");
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Call failed" });
      cleanup();
    }
  }, [args.deviceId, args.userId, armTimeout, bindAcceptedDevice, cleanup, getMedia, signalRoutes, supported]);

  const accept = useCallback(async () => {
    // Either the ring (which arrives first) or the offer can be what is on
    // screen when the user taps Accept — both carry the caller's address.
    const incoming = pendingOfferRef.current ?? pendingRingRef.current;
    if (!incoming) return;
    const callId = incoming.call_id;
    const route: CallRoute = { conversationId: incoming.conversation_id, toUserId: incoming.from_user_id, toDeviceId: incoming.from_device_id };
    routeRef.current = route;
    dispatch({ type: "accept" });
    // Still a wall clock until the offer lands — nothing is negotiating yet.
    armTimeout(RING_TIMEOUT_MS);
    signalChannelRef.current?.boost();
    try {
      // Camera + relay config start NOW, overlapping the wait for the caller's
      // offer and the KEM decapsulation that follows it.
      const mediaPromise = getMedia();
      // The offer wait below can abort this accept; attaching a handler keeps a
      // superseded capture from surfacing as an unhandled rejection (the promise
      // is still consumed by the Promise.all when the accept succeeds).
      mediaPromise.catch(() => undefined);
      const configPromise = resolveRtcConfiguration().catch(() => undefined);
      // Tell the caller we are answering, so it can stop ringing us and (on a
      // build that waits for it) start pushing media setup immediately.
      void sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "accept", payload: {},
      }).catch(() => undefined);

      const offer = await waitForOffer(callId);
      pendingOfferRef.current = offer;
      const [setup, stream] = await Promise.all([
        safeInvoke<CallSetup>("call_callee_setup", { hybridCiphertext: (offer.payload as { hybridCiphertext: unknown }).hybridCiphertext, callId }),
        mediaPromise,
        configPromise,
      ]);
      setupRef.current = setup;
      const pc = await buildPeerConnection(callId, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Same VP8 pinning as the caller side, before the answer is created.
      pinVideoCodec(pc);
      attachMediaTransforms(pc, setup);
      await pc.setRemoteDescription({ type: "offer", sdp: String((offer.payload as { sdp: string }).sdp) });
      flushPendingCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({ call_id: callId, conversation_id: route.conversationId, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: route.toUserId, to_device_id: route.toDeviceId, signal_type: "answer", payload: { sdp: answer.sdp } });
      beginConnectPhase();
    } catch (e) {
      void sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "hangup", payload: {},
      }).catch(() => undefined);
      dispatch({ type: "failed", error: e instanceof Error ? e.message : "Accept failed" });
      cleanup();
    }
  }, [args.deviceId, args.userId, armTimeout, attachMediaTransforms, beginConnectPhase, buildPeerConnection, cleanup, flushPendingCandidates, getMedia, waitForOffer]);

  const endCall = useCallback((notify: boolean) => {
    const callId = callIdRef.current;
    // Stable identity (reads the call id from a ref, not state) so it is NOT a
    // dependency that would re-subscribe the signal channel mid-call.
    // Hanging up reaches EVERY device still ringing from the outgoing fan-out --
    // addressing only the bound route left the peer's other devices ringing.
    if (notify && callId) signalRoutes(callId, teardownRoutes(), "hangup");
    dispatch({ type: "ended" });
    cleanup();
  }, [cleanup, signalRoutes, teardownRoutes]);

  const reject = useCallback(() => {
    const incoming = pendingOfferRef.current ?? pendingRingRef.current;
    if (incoming) {
      void sendCallSignal({ call_id: incoming.call_id, conversation_id: incoming.conversation_id, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: incoming.from_user_id, to_device_id: incoming.from_device_id, signal_type: "reject", payload: {} });
    }
    endCall(false);
  }, [args.deviceId, args.userId, endCall]);

  const hangup = useCallback(() => endCall(true), [endCall]);
  const toggleMic = useCallback(() => { localStream?.getAudioTracks().forEach((t) => (t.enabled = !t.enabled)); setMicEnabled((v) => !v); }, [localStream]);
  const toggleCamera = useCallback(() => { localStream?.getVideoTracks().forEach((t) => (t.enabled = !t.enabled)); setCameraEnabled((v) => !v); }, [localStream]);

  // Signal handling
  useEffect(() => {
    if (!args.userId || !args.deviceId) return undefined;
    // Relay config is resolved once here (and again on resume) so it is warm
    // before any call rather than costing a round trip mid-setup.
    prewarmRtcConfiguration();

    /** Decline an incoming call we cannot take right now. */
    const replyBusy = (row: CallSignalRow) => {
      void sendCallSignal({
        call_id: row.call_id, conversation_id: row.conversation_id,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: row.from_user_id, to_device_id: row.from_device_id,
        signal_type: "busy", payload: {},
      }).catch(() => undefined);
    };

    /** Start ringing for `row` unless this device is already on a call. */
    const openIncoming = (row: CallSignalRow): boolean => {
      // Already handling this exact call: a re-delivered ring/offer (realtime
      // and the catch-up reader can both deliver it) must never answer "busy"
      // to our own in-progress call — that is what used to tear it down.
      if (row.call_id === callIdRef.current) return true;
      if (["ringing", "calling", "connecting", "connected"].includes(phaseRef.current)) {
        replyBusy(row);
        return false;
      }
      // Address the caller from the moment we start ringing, so a rejection or a
      // ring timeout can tell them — not only once the user has accepted.
      routeRef.current = {
        conversationId: row.conversation_id,
        toUserId: row.from_user_id,
        toDeviceId: row.from_device_id,
      };
      dispatch({ type: "incoming", callId: row.call_id, peerUserId: row.from_user_id, peerDeviceId: row.from_device_id });
      // A caller whose app dies mid-dial sends no hangup. Without a ceiling the
      // modal would ring forever; 60s is comfortably past the caller's own 45s
      // give-up (whose hangup normally dismisses this first).
      armTimeout(INCOMING_RING_TIMEOUT_MS);
      return true;
    };

    const channel = subscribeCallSignals({
      userId: args.userId, deviceId: args.deviceId,
      onSignal: (row) => {
        if (row.from_user_id === args.userId) return;
        switch (row.signal_type) {
          case "ring": {
            // The ring is the caller's FIRST write, sent before its camera and
            // KEM setup — this is what makes the phone light up immediately
            // instead of seconds later. A stale row from a long-dead call must
            // never pop the modal, hence the freshness gate.
            if (!isFreshSignal(row)) return;
            if (row.call_id === callIdRef.current) return;
            if (!openIncoming(row)) return;
            pendingRingRef.current = row;
            signalChannelRef.current?.boost();
            break;
          }
          case "offer": {
            if (!isFreshSignal(row)) return;
            const forCurrentCall = row.call_id === callIdRef.current;
            // Answering off the ring: `accept()` is already waiting for exactly
            // this row.
            if (forCurrentCall) {
              pendingOfferRef.current = row;
              const waiters = offerWaitersRef.current.slice();
              if (waiters.length > 0) {
                waiters.forEach((waiter) => waiter(row));
                return;
              }
              // No one is waiting for a first offer, so this is a RENEGOTIATION:
              // the peer restarted ICE to recover a path change. Answer it on
              // the existing peer connection — the media keys and the attached
              // E2EE transforms stay exactly as they are, only the transport is
              // re-negotiated.
              const pc = pcRef.current;
              if (!pc || !pc.remoteDescription) return;
              void (async () => {
                try {
                  setReconnecting(true);
                  signalChannelRef.current?.boost();
                  await pc.setRemoteDescription({ type: "offer", sdp: String(row.payload.sdp) });
                  flushPendingCandidates();
                  const answer = await pc.createAnswer();
                  await pc.setLocalDescription(answer);
                  await sendCallSignal({
                    call_id: row.call_id, conversation_id: row.conversation_id,
                    from_user_id: args.userId, from_device_id: args.deviceId,
                    to_user_id: row.from_user_id, to_device_id: row.from_device_id,
                    signal_type: "answer", payload: { sdp: answer.sdp },
                  });
                  beginConnectPhase();
                } catch {
                  endCall(false);
                }
              })();
              return;
            }
            if (!openIncoming(row)) return;
            pendingOfferRef.current = row;
            break;
          }
          case "answer":
            if (pcRef.current && roleRef.current === "caller") {
              renegotiatingRef.current = false;
              noteIceProgress();
              void pcRef.current
                .setRemoteDescription({ type: "answer", sdp: String(row.payload.sdp) })
                .then(() => flushPendingCandidates())
                .catch(() => undefined);
              dispatch({ type: "remote-answered" });
            }
            break;
          case "accept":
            // The callee is answering: keep signalling hot through connect, and
            // -- because an outgoing call rings ALL of the peer's devices -- bind
            // the call to whichever one answered. That is what produces the
            // offer; the losing devices are hung up inside bindAcceptedDevice.
            if (row.call_id === callIdRef.current) {
              signalChannelRef.current?.boost();
              if (roleRef.current === "caller") {
                void bindAcceptedDevice(row.call_id, row.from_device_id);
              }
            }
            break;
          case "ice": {
            if (!row.payload.candidate) break;
            if (row.call_id !== callIdRef.current) break;
            const candidate = row.payload.candidate as RTCIceCandidateInit;
            // The peer is still gathering, so the connection is still advancing:
            // hold the give-up open. This is the other half of the fix for calls
            // that were killed while the far end was slowly enumerating its
            // network interfaces.
            noteIceProgress();
            if (pcRef.current?.remoteDescription) void pcRef.current.addIceCandidate(candidate).catch(() => undefined);
            else pendingCandidatesRef.current.push(candidate);
            break;
          }
          case "reject": case "hangup": case "busy": {
            // Only the call this device is actually on may be torn down.
            if (row.call_id !== callIdRef.current) break;
            // Caller with a forked ring: a decline (or an automatic `busy`) from
            // ONE of the peer's devices only takes THAT device out of the ring.
            // Ending the whole call on the first one meant a peer whose desktop
            // happened to be on another call could not be reached on their phone
            // at all -- the desktop's automatic busy killed the ring everywhere.
            // Once a device has answered, only that device's signals end the call.
            if (roleRef.current === "caller") {
              const verdict = applyDecline(
                ringTargetsRef.current.map((route) => route.toDeviceId),
                row.from_device_id,
                answeredDeviceRef.current,
              );
              ringTargetsRef.current = ringTargetsRef.current.filter(
                (route) => verdict.remaining.includes(route.toDeviceId),
              );
              if (!verdict.endCall) break;
            }
            endCall(false);
            break;
          }
          default: break;
        }
      },
    });
    signalChannelRef.current = channel;

    // A resumed app has a cold relay cache and possibly a dead socket.
    const onResume = () => {
      if (document.visibilityState !== "visible") return;
      prewarmRtcConfiguration();
      channel.refresh();
    };
    document.addEventListener("visibilitychange", onResume);

    return () => {
      document.removeEventListener("visibilitychange", onResume);
      signalChannelRef.current = null;
      channel.close();
    };
    // All four are stable callbacks, so the transport stays mounted for the whole
    // session — re-subscribing mid-call is what used to drop the inbound answer.
  }, [args.deviceId, args.userId, armTimeout, beginConnectPhase, bindAcceptedDevice, endCall, flushPendingCandidates, noteIceProgress]);

  // Keep synchronous mirrors of call state for ref-based decisions (busy
  // detection, role checks, hangup addressing) inside the signal handler, so it
  // never has to re-subscribe when a call starts or changes phase.
  useEffect(() => { phaseRef.current = state.phase; }, [state.phase]);
  useEffect(() => { callIdRef.current = state.callId; }, [state.callId]);
  useEffect(() => { roleRef.current = state.role; }, [state.role]);

  useEffect(() => () => cleanup(), [cleanup]);

  return { state, localStream, remoteStream, micEnabled, cameraEnabled, reconnecting, quality, setQuality, stats, supported, startCall, accept, reject, hangup, toggleMic, toggleCamera };
}
