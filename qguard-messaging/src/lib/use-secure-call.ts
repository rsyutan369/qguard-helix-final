import { SCREEN_SHARE_CONSTRAINTS, screenShareSupported } from "@/lib/screen-share";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  CALL_STAGES,
  completeTimeline,
  createTimeline,
  describeTimeline,
  markTimeline,
  publishTimeline,
  type Timeline,
  type TimelineOutcome,
} from "@/lib/perf-timeline";
import {
  describeCallConnectFailure,
  lastRelayHealth,
  prewarmRtcConfiguration,
  probeRelayHealth,
  relayProvenForCalls,
  resolveRtcConfiguration,
} from "@/lib/call-ice";
import { connectDeadlineMs, shouldAttemptIceRecovery } from "@/lib/call-deadline";
import { callReducer, INITIAL_CALL_STATE } from "@/lib/call-state";
import { sendCallSignal, sendCallSignals, subscribeCallSignals, type CallSignalChannel } from "@/lib/call-signaling";
import { PRIMARY_SLOT, type CallSignalHub } from "@/lib/call-signal-hub";
import type { GroupInvite } from "@/lib/group-call";
import { fetchCallPeerIdentity } from "@/lib/call-peer-identity";
import { applyDecline, callPeerIdentityPayload, parseCallEphemeralKey } from "@/lib/call-targets";
import type { CallEphemeralKey, CallPeer, CallPeerDevice } from "@/lib/call-targets";
import { callMediaOf, type CallEndReason, type CallMedia, type CallSignalRow } from "@/lib/call-types";
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

/** Mirror of `commands::calls::CallSetup`. */
interface CallSetup {
  hybridCiphertext: unknown;
  /** Second encapsulation, to the callee's per-call key (caller side, forward-secret calls). */
  ephemeralCiphertext?: unknown;
  /** The caller's signature over the call's key material (caller side, forward-secret calls). */
  callerProof?: unknown;
  sendKeyB64: string;
  recvKeyB64: string;
  safetyNumber: string;
  forwardSecret?: boolean;
  peerAuthenticated?: boolean;
  /** When the user verified this exact device here (unix seconds), or null. */
  peerVerifiedAt?: number | null;
  /** A call challenge phrase can be shown with this device. */
  peerPaired?: boolean;
}

/**
 * How long the callee waits for the caller's registered identity before
 * answering without it. The call must not hang on a registry read; a caller
 * that could not be checked in time is reported as unverified.
 */
const CALLER_IDENTITY_WAIT_MS = 4_000;

function settleWithin<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    const timer = window.setTimeout(() => resolve(fallback), ms);
    promise.then(
      (value) => { window.clearTimeout(timer); resolve(value); },
      () => { window.clearTimeout(timer); resolve(fallback); },
    );
  });
}

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
// Lowered from 20s: with no dead relay stalling the ICE agent, gathering now
// completes in under three seconds, so twenty seconds of TOTAL silence is no
// longer evidence of a slow network — it is evidence of a path that will not
// come up. Progress still re-arms this, so a call that keeps gathering keeps
// its room; only a genuinely frozen one reaches a failure the user can act on.
const CONNECT_STALL_MS = 10_000;
const CONNECT_CEILING_MS = 90_000;

// When a connecting call should be re-examined to see whether RECOVERY has
// anything new to offer (chiefly: a relay that has since been proven healthy).
// This is not a give-up clock and never ends a call.
const ICE_RECOVERY_REVIEW_MS = 5_000;

// At most two ICE restarts per call. One is the standard remedy for a path
// change; a second exists so a call that began before the relay probe returned
// can re-gather WITH the relay once it is proven. Beyond that a restart is
// just a loop that keeps a dead call alive.
const MAX_ICE_RESTARTS = 2;

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
//
// FAILS THE CALL rather than the transform. This used to swallow every error
// with "non-fatal" — but the only thing standing between the media and the
// relay is this transform, so "it did not install" means the call runs with
// hop-by-hop DTLS-SRTP alone and no end-to-end encryption at all, while the UI
// still shows a safety number and says the call is quantum-encrypted. A silent
// downgrade to a weaker guarantee than the one displayed is worse than a call
// that refuses to start, so the promise rejects and the caller tears down.
async function pipeEncodedStreams(
  rtp: RTCRtpSender | RTCRtpReceiver,
  opts: FrameCryptoOptions,
): Promise<void> {
  const create = rtp.createEncodedStreams;
  if (!create) {
    throw new Error("This device cannot encrypt call media end-to-end (no encoded-transform support).");
  }
  const streams = create.call(rtp);
  const transform = await makeFrameTransform(opts);
  void streams.readable.pipeThrough(transform).pipeTo(streams.writable);
}

/**
 * Quantum-encrypted call engine. Runs APP-WIDE (see CallProvider): the signal
 * subscription only needs the local user + device, and everything a callee
 * needs to answer (conversation, caller ids, hybrid KEM ciphertext) arrives in
 * the offer row itself — so incoming calls ring on every page, not just while
 * Secure Chat is open. Outgoing calls pass the peer + conversation explicitly
 * to `startCall`.
 */
/**
 * `hub`/`slot` (group calls, roadmap 7.2): share one signal subscription with
 * other engine instances, each owning the calls routed to its slot. `isBusy`:
 * an engine elsewhere is on a call, so rings are answered "busy". Without them
 * the engine behaves exactly as it always has.
 */
export function useSecureCall(args: { userId: string; deviceId: string; hub?: CallSignalHub | null; slot?: string; isBusy?: () => boolean }) {
  const slot = args.slot ?? PRIMARY_SLOT;
  const hubRef = useRef(args.hub ?? null);
  hubRef.current = args.hub ?? null;
  const isBusyRef = useRef(args.isBusy);
  isBusyRef.current = args.isBusy;
  // The group invite an outgoing group link carries on its ring and offer.
  const groupInviteRef = useRef<GroupInvite | null>(null);
  // Voice or video for the call in progress (set by startCall / an incoming ring).
  const mediaRef = useRef<CallMedia>("video");
  const [state, dispatch] = useReducer(callReducer, INITIAL_CALL_STATE);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [micEnabled, setMicEnabled] = useState(true);
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const [reconnecting, setReconnecting] = useState(false);
  // Screen share (roadmap 7.3): the screen track REPLACES the camera track on
  // the existing video sender, so it rides the same per-frame AES-256-GCM
  // transform and the same pinned VP8 codec — nothing is renegotiated and no
  // frame leaves unencrypted.
  const [screenSharing, setScreenSharing] = useState(false);
  const screenTrackRef = useRef<MediaStreamTrack | null>(null);
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
  // The identity material of every device being rung, so that when one answers
  // with a per-call key the key agreement can be redone against it.
  const peerDevicesRef = useRef<Map<string, { userId: string; device: CallPeerDevice }>>(new Map());
  // First device to accept wins; later accepts are told to stop ringing. Guards
  // the race where two of the peer's devices answer within the same tick.
  const answeredDeviceRef = useRef<string | null>(null);
  // An accept that arrived BEFORE this device's camera and per-device KEM setup
  // finished. The ring is sent first precisely so the peer can answer instantly,
  // so a fast tap legitimately beats our own setup; without this the accept
  // would be dropped and the call would hang until the give-up.
  const pendingAcceptDeviceRef = useRef<{ deviceId: string; ephemeralKey: CallEphemeralKey | null } | null>(null);
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
  // How many ICE restarts this call has spent (bounded by MAX_ICE_RESTARTS).
  const iceRestartsUsedRef = useRef(0);
  // Whether the live peer connection already carries a proven relay, so a
  // restart can tell "I have something new to try" from "I would re-gather the
  // exact same servers and fail the exact same way".
  const relayInPcRef = useRef(false);
  // Timer for the recovery review described at ICE_RECOVERY_REVIEW_MS.
  const iceRecoveryTimerRef = useRef<number | undefined>(undefined);
  const renegotiatingRef = useRef(false);
  const supported = useMemo(callSupported, []);
  const RECONNECT_GRACE_MS = 12000;

  // ---------------------------------------------------------------------
  // Call setup timings
  // ---------------------------------------------------------------------
  // Every call failure in this deployment has looked the same from the outside
  // ("it rang, then ended") while having entirely different causes — a ring
  // delivered to an idle device, an ICE agent that never finished gathering, a
  // relay that could not allocate. Each was found only by reconstructing
  // timings afterwards from signal rows. Recording the stages as they happen
  // makes the next one readable from a single log line.
  const callTimelineRef = useRef<Timeline | null>(null);

  const beginCallTimeline = useCallback((callId: string, role: "caller" | "callee") => {
    const timeline = createTimeline("call", callId, performance.now());
    markTimeline(timeline, CALL_STAGES.initiated, performance.now());
    describeTimeline(timeline, { role });
    callTimelineRef.current = timeline;
  }, []);

  const markCallStage = useCallback((stage: string) => {
    const timeline = callTimelineRef.current;
    if (timeline) markTimeline(timeline, stage, performance.now());
  }, []);

  const describeCallTimeline = useCallback((detail: Record<string, string | number | boolean>) => {
    const timeline = callTimelineRef.current;
    if (timeline) describeTimeline(timeline, detail);
  }, []);

  /**
   * Close out the call's timeline. Records the relay verdict alongside the
   * stages, because "which stage did it die at" and "was a relay available"
   * are only diagnostic together.
   */
  const finishCallTimeline = useCallback((outcome: TimelineOutcome) => {
    const timeline = callTimelineRef.current;
    if (!timeline) return;
    callTimelineRef.current = null;
    describeTimeline(timeline, {
      relay: lastRelayHealth()?.status ?? "unknown",
      restarts: iceRestartsUsedRef.current,
    });
    publishTimeline(completeTimeline(timeline, outcome, performance.now()));
  }, []);

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
  const attachMediaTransforms = useCallback(async (pc: RTCPeerConnection, setup: CallSetup): Promise<void> => {
    const strategy = detectTransformStrategy();
    if (strategy === "none") {
      throw new Error("This device cannot encrypt call media end-to-end (no encoded-transform support).");
    }
    const w = strategy === "worker" ? worker() : null;
    // The encoded-streams plumbing must claim every stream SYNCHRONOUSLY, before
    // any await, for the same reason the transforms are attached at transceiver
    // level: once the inbound pipeline is wired, a late transform never inserts
    // and remote frames reach the decoder still encrypted. `pipeEncodedStreams`
    // runs `createEncodedStreams` before its first await, so starting them all
    // here and awaiting afterwards preserves that ordering.
    const pending: Array<Promise<void>> = [];
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
        pending.push(pipeEncodedStreams(transceiver.sender, encryptOpts));
        pending.push(pipeEncodedStreams(transceiver.receiver, decryptOpts));
      }
    }
    // Any transform that failed to install takes the call down with it.
    await Promise.all(pending);
  }, [worker]);

  const flushPendingCandidates = useCallback(() => {
    const pc = pcRef.current;
    if (!pc) return;
    for (const c of pendingCandidatesRef.current) void pc.addIceCandidate(c);
    pendingCandidatesRef.current = [];
  }, []);

  const cleanup = useCallback(() => {
    // A finished call no longer needs a route through a shared signal hub.
    if (callIdRef.current) hubRef.current?.release(callIdRef.current);
    groupInviteRef.current = null;
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
    peerDevicesRef.current.clear();
    answeredDeviceRef.current = null;
    pendingAcceptDeviceRef.current = null;
    pendingOfferRef.current = null;
    pendingRingRef.current = null;
    offerWaitersRef.current = [];
    pendingCandidatesRef.current = [];
    if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
    if (reconnectTimerRef.current !== undefined) { window.clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = undefined; }
    if (iceFlushTimerRef.current !== undefined) { window.clearTimeout(iceFlushTimerRef.current); iceFlushTimerRef.current = undefined; }
    if (iceRecoveryTimerRef.current !== undefined) { window.clearTimeout(iceRecoveryTimerRef.current); iceRecoveryTimerRef.current = undefined; }
    iceQueueRef.current = [];
    // Published only if setup never finished — a connected call already closed
    // its own timeline with "ok", and this is a no-op for it.
    finishCallTimeline("abandoned");
    connectCeilingRef.current = 0;
    iceRestartsUsedRef.current = 0;
    relayInPcRef.current = false;
    renegotiatingRef.current = false;
    setReconnecting(false);
    // Read the live stream from a ref so `cleanup` keeps a STABLE identity. If it
    // depended on `localStream` state, the unmount effect below would re-run on
    // every stream change and tear the active call down mid-negotiation (closing
    // the peer connection / worker and releasing the camera in a race).
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
    if (screenTrackRef.current) {
      screenTrackRef.current.onended = null;
      screenTrackRef.current.stop();
      screenTrackRef.current = null;
    }
    setScreenSharing(false);
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
      describeCallTimeline({ gaveUpIn: connectCeilingRef.current ? "connect" : "ring" });
      finishCallTimeline("timeout");
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

  // Set once `tryIceRestart` exists. The recovery review needs to call it, and
  // the restart needs `beginConnectPhase`, which needs the review — a ref
  // breaks that cycle without making any of the three unstable.
  const tryIceRestartRef = useRef<() => boolean>(() => false);

  /**
   * Re-examine a still-connecting call to see whether recovery has anything NEW
   * to offer, and restart ICE only if it does.
   *
   * The restraint is the point. An ICE restart abandons the current generation
   * of candidate pairs, so restarting a connection that was merely slow can
   * destroy the very handshake that was about to succeed — this codebase has
   * already been bitten by a give-up clock that killed a call three seconds
   * before its only usable candidate arrived. So this fires on new INFORMATION,
   * not on elapsed time: the one thing that genuinely changes the outcome is a
   * relay that has since been proven healthy and is not yet in the peer
   * connection. Without that, the existing generation is left to keep trying
   * and the normal progress/stall machinery decides its fate.
   */
  const armIceRecoveryReview = useCallback(() => {
    if (iceRecoveryTimerRef.current !== undefined) window.clearTimeout(iceRecoveryTimerRef.current);
    iceRecoveryTimerRef.current = window.setTimeout(() => {
      iceRecoveryTimerRef.current = undefined;
      const pc = pcRef.current;
      if (!pc) return;
      if (!shouldAttemptIceRecovery({
        connected: phaseRef.current === "connected" || pc.connectionState === "connected",
        relayInPeerConnection: relayInPcRef.current,
        relayProven: relayProvenForCalls(),
        restartsUsed: iceRestartsUsedRef.current,
        maxRestarts: MAX_ICE_RESTARTS,
      })) return;
      tryIceRestartRef.current();
    }, ICE_RECOVERY_REVIEW_MS);
  }, []);

  /**
   * Enter the connect phase: the call has been answered and ICE is now
   * responsible for getting media flowing. Starts the absolute ceiling and arms
   * the first stall window.
   */
  const beginConnectPhase = useCallback(() => {
    connectCeilingRef.current = Date.now() + CONNECT_CEILING_MS;
    armTimeout(CONNECT_STALL_MS);
    armIceRecoveryReview();
  }, [armTimeout, armIceRecoveryReview]);

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
    if (iceRestartsUsedRef.current >= MAX_ICE_RESTARTS || renegotiatingRef.current) return false;
    iceRestartsUsedRef.current += 1;
    renegotiatingRef.current = true;
    setReconnecting(true);
    signalChannelRef.current?.boost();
    beginConnectPhase();
    void (async () => {
      try {
        // Re-resolve the ICE servers before re-gathering. A call that started
        // before the relay probe returned had none, and a restart that
        // re-gathers the identical server set can only reproduce the identical
        // failure. `setConfiguration` applies the new servers to the restart's
        // gathering without touching the media keys or the attached E2EE
        // transforms — a restart renegotiates transport, never cryptography.
        if (!relayInPcRef.current && relayProvenForCalls()) {
          try {
            pc.setConfiguration(await resolveRtcConfiguration());
            relayInPcRef.current = true;
          } catch {
            // An older WebView may refuse setConfiguration; re-gathering on the
            // existing servers is still worth attempting.
          }
        }
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
        endCall(false, "connection-lost");
      }
    })();
    return true;
  }, [args.deviceId, args.userId, beginConnectPhase]); // eslint-disable-line react-hooks/exhaustive-deps
  tryIceRestartRef.current = tryIceRestart;

  const buildPeerConnection = useCallback(async (callId: string, route: CallRoute) => {
    // Live STUN/TURN resolution (operator relay config → env → Open Relay):
    // cached + short-timeout, so it adds ~0ms in the steady state and can
    // never block a call — see call-ice.ts.
    // The legacy createEncodedStreams() plumbing requires this Chromium flag at
    // construction; RTCRtpScriptTransform doesn't need it, so we only set it when
    // the fallback will be used.
    const rtcConfig = await resolveRtcConfiguration();
    // Remember whether this connection actually got a relay, so a later restart
    // can tell whether re-gathering would bring anything new.
    relayInPcRef.current = (rtcConfig.iceServers ?? []).some((server) =>
      [server.urls].flat().some((url) => /^turns?:/.test(String(url))));
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
    pc.oniceconnectionstatechange = () => {
      if (pc.iceConnectionState === "connected" || pc.iceConnectionState === "completed") {
        markCallStage(CALL_STAGES.iceConnected);
      }
      noteIceProgress();
    };
    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === "gathering") markCallStage(CALL_STAGES.iceStarted);
      // Gathering actually COMPLETING is the signal a dead relay used to
      // withhold forever, so it is worth recording explicitly.
      if (pc.iceGatheringState === "complete") describeCallTimeline({ gatheringComplete: true });
      noteIceProgress();
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
        connectCeilingRef.current = 0;
        renegotiatingRef.current = false;
        if (timeoutRef.current !== undefined) { window.clearTimeout(timeoutRef.current); timeoutRef.current = undefined; }
        if (reconnectTimerRef.current !== undefined) { window.clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = undefined; }
        if (iceRecoveryTimerRef.current !== undefined) { window.clearTimeout(iceRecoveryTimerRef.current); iceRecoveryTimerRef.current = undefined; }
        setReconnecting(false);
        markCallStage(CALL_STAGES.mediaConnected);
        if (setupRef.current) {
          markCallStage(CALL_STAGES.established);
          // Reported exactly as the core established them; an older peer leaves
          // both false and the call screen says so.
          const forwardSecret = setupRef.current.forwardSecret === true;
          const peerVerified = setupRef.current.peerAuthenticated === true;
          dispatch({
            type: "media-connected",
            safetyNumber: setupRef.current.safetyNumber,
            forwardSecret,
            peerVerified,
            peerVerifiedAt: setupRef.current.peerVerifiedAt ?? null,
            peerPaired: setupRef.current.peerPaired === true,
          });
          void recordCryptoTelemetry({
            userId: args.userId, scope: "call", stage: "call_connected",
            detail: forwardSecret
              ? "Quantum-encrypted call connected (per-call key, forward secret)"
              : "Quantum-encrypted call connected (identity key only, no forward secrecy: peer runs an older build)",
            progress: 100, status: "complete",
            metadata: { call_id: callId, forward_secret: forwardSecret, peer_verified: peerVerified },
          });
        }
        // Encoder ceilings can be ignored when set pre-ICE; re-assert them on
        // the established connection so the negotiated path runs at full tier.
        void applySenderParams(pc, qualityRef.current);
        // Live quality diagnostics for the whole connected span (idempotent
        // across reconnect blips — only one monitor per peer connection).
        if (!statsStopRef.current) {
          statsStopRef.current = startCallStatsMonitor(pc, setStats);
        }
        // The SETUP timeline is finished the moment media flows; the call's own
        // duration is a different measurement and not this one's business.
        finishCallTimeline("ok");
        return;
      }
      // `failed` is recoverable exactly once, via an ICE restart — the standard
      // remedy when the network path changes underneath a live call (Wi-Fi to
      // cellular, a NAT rebinding). Only the offerer may restart; the answerer
      // waits for the restart offer. `closed` is final.
      if (cs === "failed") {
        if (tryIceRestart()) return;
        endCall(false, "connection-lost");
        return;
      }
      if (cs === "closed") { endCall(false, "connection-lost"); return; }
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
            endCall(false, "connection-lost");
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
    if (mediaRef.current === "voice") {
      // A voice call never opens the camera. The microphone track rides the
      // same per-frame AES-256-GCM transform as in a video call.
      stream = await navigator.mediaDevices.getUserMedia({ audio: constraints.audio ?? true });
      setCameraEnabled(false);
    } else try {
      stream = await navigator.mediaDevices.getUserMedia(constraints);
      setCameraEnabled(stream.getVideoTracks().length > 0);
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
  const bindAcceptedDevice = useCallback(async (callId: string, deviceId: string, ephemeralKey: CallEphemeralKey | null) => {
    if (answeredDeviceRef.current) return;
    const route = ringTargetsRef.current.find((r) => r.toDeviceId === deviceId);
    const precomputed = setupsByDeviceRef.current.get(deviceId);
    const stream = localStreamRef.current;
    // Key material or media not ready yet (a very fast accept, which the
    // ring-first design makes likely): park it. startCall replays it the moment
    // the camera and the per-device KEM setups are ready.
    if (!route || !precomputed || !stream) {
      if (route) pendingAcceptDeviceRef.current = { deviceId, ephemeralKey };
      return;
    }
    answeredDeviceRef.current = deviceId;
    routeRef.current = route;
    // Everyone else stops ringing immediately, before the offer round trip.
    signalRoutes(callId, ringTargetsRef.current.filter((r) => r.toDeviceId !== deviceId), "hangup");
    ringTargetsRef.current = [route];
    try {
      // The answering device sent a key pair made for THIS call. Agree the
      // media key against it (as well as its identity key) so the call is
      // forward secret, and sign the result so the callee can tell who is
      // calling. The core verifies the per-call key's signature first; if that
      // fails the call fails — it must never quietly fall back to the
      // identity-only agreement, or stripping the key would be a downgrade.
      // An accept WITHOUT a key comes from a build that predates this, and
      // uses the agreement pre-computed while it rang.
      const answering = peerDevicesRef.current.get(deviceId);
      const setup = ephemeralKey && answering
        ? await safeInvoke<CallSetup>("call_caller_setup", {
          peer: callPeerIdentityPayload(answering.userId, answering.device),
          callId,
          ephemeral: ephemeralKey,
        })
        : precomputed;
      setupRef.current = setup;
      const pc = await buildPeerConnection(callId, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Deterministic VP8: the E2EE frame crypto's unencrypted-header layout is
      // VP8-specific, so codec negotiation must never drift (see call-quality.ts).
      pinVideoCodec(pc);
      // Transforms are attached BEFORE the offer, so no frame can ever leave
      // this device before its E2EE transform is in place.
      await attachMediaTransforms(pc, setup);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await applySenderParams(pc, qualityRef.current);
      await sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "offer",
        payload: {
          sdp: offer.sdp,
          hybridCiphertext: setup.hybridCiphertext,
          ...(setup.ephemeralCiphertext ? { ephemeralCiphertext: setup.ephemeralCiphertext, callerProof: setup.callerProof } : {}),
          ...(groupInviteRef.current ? { group: groupInviteRef.current } : {}),
          ...(mediaRef.current === "voice" ? { media: "voice" } : {}),
        },
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

  const startCall = useCallback(async (peer: CallPeer, conversationId: string, options?: { group?: GroupInvite; media?: CallMedia }) => {
    if (!supported || !args.deviceId || !conversationId) return;
    if (peer.devices.length === 0) return;
    groupInviteRef.current = options?.group ?? null;
    mediaRef.current = options?.media ?? "video";
    // FORK THE RING. A peer is a person, not a device: addressing the call to
    // one device meant that if they were sitting at any other one it never rang,
    // the caller sat on "Connecting…" until the give-up, and no safety number
    // was ever derived (it only exists once media connects). Ring every device
    // and let the first one to answer take the call.
    const routes: CallRoute[] = peer.devices.map((device) => ({
      conversationId, toUserId: peer.userId, toDeviceId: device.deviceId,
    }));
    ringTargetsRef.current = routes;
    peerDevicesRef.current = new Map(peer.devices.map((device) => [device.deviceId, { userId: peer.userId, device }]));
    // Provisionally address the most likely device (the caller's ordering puts
    // the most-recently-seen first) so a reject/timeout before anyone answers
    // still has somewhere to go; rebound for real on the winning accept.
    routeRef.current = routes[0];
    const callId = crypto.randomUUID();
    // Replies carry no group invite, so they must be routed by call id.
    hubRef.current?.claim(callId, slot);
    beginCallTimeline(callId, "caller");
    dispatch({ type: "start-outgoing", callId, peerUserId: peer.userId, peerDeviceId: peer.devices[0].deviceId, media: mediaRef.current, conversationId });
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
        signal_type: "ring" as const, payload: {
          ...(groupInviteRef.current ? { group: groupInviteRef.current } : {}),
          ...(mediaRef.current === "voice" ? { media: "voice" } : {}),
        },
      })));
      markCallStage(CALL_STAGES.signalingStarted);
      describeCallTimeline({ rang: routes.length });

      // Everything expensive runs CONCURRENTLY while the peer's devices ring:
      // the camera warm-up, the relay config read, and one KEM encapsulation
      // PER DEVICE. Pre-computing every device's setup is what keeps the
      // post-answer path as fast as the old single-device flow — the winner's
      // ciphertext is already in hand the moment they accept.
      const [stream] = await Promise.all([
        getMedia(),
        resolveRtcConfiguration().catch(() => undefined),
        ...peer.devices.map(async (device: CallPeerDevice) => {
          // Verifies each device's registered identity now, and is the
          // agreement used if the device that answers runs a build without
          // per-call keys. A device that answers WITH one gets a fresh
          // agreement in bindAcceptedDevice.
          const setup = await safeInvoke<CallSetup>("call_caller_setup", {
            peer: callPeerIdentityPayload(peer.userId, device),
            callId,
            ephemeral: null,
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
        await bindAcceptedDevice(callId, early.deviceId, early.ephemeralKey);
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
    // The callee measures its own setup. Both ends are instrumented because the
    // two see different halves of a failure: which end stopped making progress
    // is exactly what a one-sided log cannot tell you.
    beginCallTimeline(callId, "callee");
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
      // Who the registry says this caller device is: started now so it is
      // ready by the time the offer needs checking against it.
      const callerIdentityPromise = fetchCallPeerIdentity(route.toUserId, route.toDeviceId);
      // A key pair made for this call alone. Its public half goes to the caller
      // inside `accept`; the private half stays in the core's memory until the
      // offer arrives and is then destroyed, which is what makes the call
      // forward secret. If it cannot be made, the accept goes out without one
      // and the call is reported as not forward secret.
      const ephemeralKey = await safeInvoke<CallEphemeralKey>("call_callee_prepare", {
        callId, callerUserId: route.toUserId, callerDeviceId: route.toDeviceId,
      }).catch(() => null);
      // Tell the caller we are answering, so it can stop ringing us and (on a
      // build that waits for it) start pushing media setup immediately.
      void sendCallSignal({
        call_id: callId, conversation_id: route.conversationId,
        from_user_id: args.userId, from_device_id: args.deviceId,
        to_user_id: route.toUserId, to_device_id: route.toDeviceId,
        signal_type: "accept", payload: ephemeralKey ? { ephemeralKey } : {},
      }).catch(() => undefined);
      markCallStage(CALL_STAGES.signalingStarted);

      const offer = await waitForOffer(callId);
      pendingOfferRef.current = offer;
      const offered = offer.payload as { hybridCiphertext: unknown; ephemeralCiphertext?: unknown; callerProof?: unknown };
      // Only a forward-secret offer carries a caller signature to check.
      const callerIdentity = offered.ephemeralCiphertext
        ? await settleWithin(callerIdentityPromise, CALLER_IDENTITY_WAIT_MS, null)
        : null;
      const [setup, stream] = await Promise.all([
        safeInvoke<CallSetup>("call_callee_setup", {
          hybridCiphertext: offered.hybridCiphertext,
          callId,
          ephemeralCiphertext: offered.ephemeralCiphertext ?? null,
          callerProof: offered.callerProof ?? null,
          caller: callerIdentity,
        }),
        mediaPromise,
        configPromise,
      ]);
      setupRef.current = setup;
      const pc = await buildPeerConnection(callId, route);
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      // Same VP8 pinning as the caller side, before the answer is created.
      pinVideoCodec(pc);
      await attachMediaTransforms(pc, setup);
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

  const endCall = useCallback((notify: boolean, reason?: CallEndReason) => {
    const callId = callIdRef.current;
    // Stable identity (reads the call id from a ref, not state) so it is NOT a
    // dependency that would re-subscribe the signal channel mid-call.
    // Hanging up reaches EVERY device still ringing from the outgoing fan-out --
    // addressing only the bound route left the peer's other devices ringing.
    if (notify && callId) signalRoutes(callId, teardownRoutes(), "hangup");
    dispatch({ type: "ended", reason: reason ?? (notify ? "local-hangup" : undefined) });
    cleanup();
  }, [cleanup, signalRoutes, teardownRoutes]);

  const reject = useCallback(() => {
    const incoming = pendingOfferRef.current ?? pendingRingRef.current;
    if (incoming) {
      void sendCallSignal({ call_id: incoming.call_id, conversation_id: incoming.conversation_id, from_user_id: args.userId, from_device_id: args.deviceId, to_user_id: incoming.from_user_id, to_device_id: incoming.from_device_id, signal_type: "reject", payload: {} });
    }
    endCall(false, "local-reject");
  }, [args.deviceId, args.userId, endCall]);

  const hangup = useCallback(() => endCall(true), [endCall]);
  const toggleMic = useCallback(() => { localStream?.getAudioTracks().forEach((t) => (t.enabled = !t.enabled)); setMicEnabled((v) => !v); }, [localStream]);
  const toggleCamera = useCallback(() => {
    const tracks = localStream?.getVideoTracks() ?? [];
    if (tracks.length === 0) return; // a voice call (or no camera): nothing to turn on
    tracks.forEach((t) => (t.enabled = !t.enabled));
    setCameraEnabled((v) => !v);
  }, [localStream]);

  const stopScreenShare = useCallback(async () => {
    const screen = screenTrackRef.current;
    if (!screen) return;
    screenTrackRef.current = null;
    screen.onended = null;
    screen.stop();
    setScreenSharing(false);
    const sender = pcRef.current?.getSenders().find((s) => s.track === screen || s.track?.kind === "video");
    const camera = localStreamRef.current?.getVideoTracks()[0] ?? null;
    if (sender) await sender.replaceTrack(camera).catch(() => undefined);
  }, []);

  const startScreenShare = useCallback(async () => {
    if (!screenShareSupported()) throw new Error("Screen sharing is not available in this app version or platform.");
    if (screenTrackRef.current) return;
    const pc = pcRef.current;
    const sender = pc?.getSenders().find((s) => s.track?.kind === "video");
    if (!pc || !sender) {
      throw new Error("Screen sharing needs a call that started with video.");
    }
    const display = await navigator.mediaDevices.getDisplayMedia(SCREEN_SHARE_CONSTRAINTS);
    const track = display.getVideoTracks()[0];
    if (!track) {
      display.getTracks().forEach((t) => t.stop());
      throw new Error("No screen was chosen.");
    }
    // The call may have ended while the picker was open.
    if (pcRef.current !== pc) {
      track.stop();
      return;
    }
    // Text and UI: keep resolution, drop frame rate under pressure.
    track.contentHint = "detail";
    await sender.replaceTrack(track);
    screenTrackRef.current = track;
    // The platform's own "Stop sharing" control ends the track.
    track.onended = () => { void stopScreenShare(); };
    setScreenSharing(true);
  }, [stopScreenShare]);

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
      if (["ringing", "calling", "connecting", "connected"].includes(phaseRef.current) || isBusyRef.current?.()) {
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
      mediaRef.current = callMediaOf(row.payload);
      dispatch({ type: "incoming", callId: row.call_id, peerUserId: row.from_user_id, peerDeviceId: row.from_device_id, media: mediaRef.current, conversationId: row.conversation_id });
      // A caller whose app dies mid-dial sends no hangup. Without a ceiling the
      // modal would ring forever; 60s is comfortably past the caller's own 45s
      // give-up (whose hangup normally dismisses this first).
      armTimeout(INCOMING_RING_TIMEOUT_MS);
      return true;
    };

    /**
     * Is this signal from the device this call is actually with?
     *
     * `messaging_call_signals` is readable and writable by EVERY member of the
     * conversation (migration 023), and only `from_user_id = auth.uid()` is
     * enforced — `call_id`, `to_device_id` and `from_device_id` are all
     * attacker-chosen. So a third member of a group conversation, or any other
     * device of the peer's account, could write an `answer`, `ice`, `offer` or
     * `hangup` carrying the live `call_id` and this device would act on it:
     * re-pointing the transport at an endpoint of their choosing, or ending the
     * call outright. The media stays sealed (its key is encapsulated to the
     * device that actually answered), but taking over or killing someone's
     * session is not a thing a bystander may do.
     *
     * Binding is the answer, and which device is "the peer" depends on phase:
     *   - caller, before anyone answers: any device still being rung may speak;
     *   - caller, after `bindAcceptedDevice`: only the device that answered;
     *   - callee: only the caller the ring/offer came from.
     */
    const isSignalFromCallPeer = (row: CallSignalRow): boolean => {
      const answered = answeredDeviceRef.current;
      if (answered) return row.from_device_id === answered;
      if (roleRef.current === "caller" && ringTargetsRef.current.length > 0) {
        return ringTargetsRef.current.some(
          (route) => route.toDeviceId === row.from_device_id && route.toUserId === row.from_user_id,
        );
      }
      const route = routeRef.current;
      return Boolean(route && route.toDeviceId === row.from_device_id && route.toUserId === row.from_user_id);
    };

    const onSignal = (row: CallSignalRow) => {
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
              // An offer for the call in progress renegotiates live transport,
              // so it only counts from the peer this call is bound to.
              if (!isSignalFromCallPeer(row)) return;
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
                  endCall(false, "connection-lost");
                }
              })();
              return;
            }
            if (!openIncoming(row)) return;
            pendingOfferRef.current = row;
            break;
          }
          case "answer":
            // Unbound, an injected answer re-points the media transport at
            // whatever ICE endpoint the sender chose.
            if (row.call_id !== callIdRef.current) break;
            if (!isSignalFromCallPeer(row)) break;
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
            if (row.call_id === callIdRef.current && isSignalFromCallPeer(row)) {
              signalChannelRef.current?.boost();
              if (roleRef.current === "caller") {
                void bindAcceptedDevice(row.call_id, row.from_device_id, parseCallEphemeralKey(row.payload?.ephemeralKey));
              }
            }
            break;
          case "ice": {
            if (!row.payload.candidate) break;
            if (row.call_id !== callIdRef.current) break;
            if (!isSignalFromCallPeer(row)) break;
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
            // Only the call this device is actually on may be torn down...
            if (row.call_id !== callIdRef.current) break;
            // ...and only by a device that is part of it. Without this, any
            // other member of the conversation could end anyone's call by
            // writing one `hangup` row carrying the live call id.
            if (!isSignalFromCallPeer(row)) break;
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
            endCall(false, row.signal_type === "reject" ? "remote-declined" : row.signal_type === "busy" ? "remote-busy" : "remote-hangup");
            break;
          }
          default: break;
        }
    };
    const hub = hubRef.current;
    const channel = hub
      ? hub.attach(slot, onSignal)
      : subscribeCallSignals({ userId: args.userId, deviceId: args.deviceId, onSignal });
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
  }, [args.deviceId, args.userId, args.hub, slot, armTimeout, beginConnectPhase, bindAcceptedDevice, endCall, flushPendingCandidates, noteIceProgress]);

  // Keep synchronous mirrors of call state for ref-based decisions (busy
  // detection, role checks, hangup addressing) inside the signal handler, so it
  // never has to re-subscribe when a call starts or changes phase.
  useEffect(() => { phaseRef.current = state.phase; }, [state.phase]);
  useEffect(() => { callIdRef.current = state.callId; }, [state.callId]);
  useEffect(() => { roleRef.current = state.role; }, [state.role]);

  useEffect(() => () => cleanup(), [cleanup]);

  return {
    state, localStream, remoteStream, micEnabled, cameraEnabled, reconnecting, quality, setQuality, stats, supported,
    startCall, accept, reject, hangup, toggleMic, toggleCamera,
    screenShareSupported: screenShareSupported(), screenSharing, startScreenShare, stopScreenShare,
  };
}
