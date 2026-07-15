// Adaptive call media quality. Tier ceilings bound capture resolution/framerate
// and the encoder bitrate; the encoder still adapts DOWN under real CPU/network
// pressure (degradationPreference "balanced"), so the ceilings exist to define
// the best case, not to permanently constrain it. Defaults to "auto" (720p@30 —
// the production floor for "sharp on a laptop screen" per the media spec);
// users can opt into "hd" (1080p) or "low" for constrained networks, and the
// choice is persisted across calls.

export type CallQuality = "low" | "auto" | "hd";

export const DEFAULT_CALL_QUALITY: CallQuality = "auto";

const QUALITY_STORAGE_KEY = "qguard.call.quality";

interface QualityTier {
  width: number;
  height: number;
  frameRate: number;
  /** Target video encoder ceiling, bits per second. */
  maxBitrate: number;
  /** Opus target, bits per second (Chromium applies audio encodings.maxBitrate). */
  audioMaxBitrate: number;
}

const TIERS: Record<CallQuality, QualityTier> = {
  // low = constrained networks: stays tiny on purpose.
  low: { width: 320, height: 180, frameRate: 15, maxBitrate: 250_000, audioMaxBitrate: 24_000 },
  // auto = default. 720p@30 with a 2.5 Mbps ceiling: the previous 540p/1.2Mbps
  // ceiling could never render sharp on a fullscreen desktop window — the
  // remote view read as permanently blurry even on a perfect local path. The
  // encoder scales down under genuine pressure via the sender params below, so
  // a strong machine gets crisp 720p and a weak one degrades gracefully
  // instead of being capped at "soft" forever.
  auto: { width: 1280, height: 720, frameRate: 30, maxBitrate: 2_500_000, audioMaxBitrate: 64_000 },
  hd: { width: 1920, height: 1080, frameRate: 30, maxBitrate: 4_500_000, audioMaxBitrate: 96_000 },
};

export function qualityTier(quality: CallQuality): Readonly<QualityTier> {
  return TIERS[quality];
}

export function qualityLabel(quality: CallQuality): string {
  if (quality === "low") return "Low";
  if (quality === "hd") return "HD";
  return "Auto";
}

/** Restore the user's last quality selection (falls back to the default). */
export function loadPersistedQuality(): CallQuality {
  try {
    const raw = window.localStorage.getItem(QUALITY_STORAGE_KEY);
    if (raw === "low" || raw === "auto" || raw === "hd") return raw;
  } catch {
    // Storage unavailable (private mode, tests) — use the default.
  }
  return DEFAULT_CALL_QUALITY;
}

/** Persist the quality selection so the next call starts where the user left it. */
export function persistQuality(quality: CallQuality): void {
  try {
    window.localStorage.setItem(QUALITY_STORAGE_KEY, quality);
  } catch {
    // Best-effort.
  }
}

/**
 * Capture constraints for a tier. Uses `ideal`/`max` (never `exact`) so the
 * browser negotiates down on weak cameras/devices instead of failing or
 * over-capturing. Audio enables the standard DSP (echo cancel / noise / AGC).
 */
export function mediaConstraints(quality: CallQuality): MediaStreamConstraints {
  const tier = TIERS[quality];
  return {
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    video: {
      width: { ideal: tier.width, max: tier.width },
      height: { ideal: tier.height, max: tier.height },
      frameRate: { ideal: tier.frameRate, max: tier.frameRate },
    },
  };
}

/**
 * Content hints steer the encoder's degradation decisions per track: camera
 * video is "motion" (favor smooth playback over per-frame detail), mic audio
 * is "speech" (favor voice DSP/codec tuning). Best-effort — older engines
 * without the property simply ignore the assignment.
 */
export function applyContentHints(stream: MediaStream | null): void {
  if (!stream) return;
  for (const track of stream.getVideoTracks()) {
    try { track.contentHint = "motion"; } catch { /* unsupported */ }
  }
  for (const track of stream.getAudioTracks()) {
    try { track.contentHint = "speech"; } catch { /* unsupported */ }
  }
}

/**
 * Tune each sender's encoder for the tier:
 *  - video: bitrate/framerate ceilings + "balanced" degradation so the encoder
 *    trades BOTH resolution and framerate under load instead of locking into
 *    permanent blur ("maintain-framerate" always sacrificed resolution first);
 *  - audio: raise the Opus target above the ~32 kbps default and mark the
 *    stream high network priority (DSCP) so voice stays clear under congestion.
 * Best-effort: unsupported `setParameters` fields are ignored by the browser.
 */
export async function applySenderParams(pc: RTCPeerConnection, quality: CallQuality): Promise<void> {
  const tier = TIERS[quality];
  await Promise.all(
    pc.getSenders().map(async (sender) => {
      const kind = sender.track?.kind;
      if (kind !== "video" && kind !== "audio") return;
      try {
        const params = sender.getParameters();
        if (!params.encodings || params.encodings.length === 0) {
          params.encodings = [{}];
        }
        if (kind === "video") {
          (params as RTCRtpSendParameters & { degradationPreference?: RTCDegradationPreference }).degradationPreference =
            "balanced";
          params.encodings.forEach((encoding) => {
            encoding.maxBitrate = tier.maxBitrate;
            encoding.maxFramerate = tier.frameRate;
            encoding.scaleResolutionDownBy = 1;
          });
        } else {
          params.encodings.forEach((encoding) => {
            encoding.maxBitrate = tier.audioMaxBitrate;
            (encoding as RTCRtpEncodingParameters & { networkPriority?: RTCPriorityType }).networkPriority = "high";
            encoding.priority = "high";
          });
        }
        await sender.setParameters(params);
      } catch {
        // setParameters can reject if called at the wrong time; non-fatal.
      }
    }),
  );
}

/** Re-apply capture constraints to a live video track when the user changes tiers. */
export async function applyTrackConstraints(stream: MediaStream | null, quality: CallQuality): Promise<void> {
  if (!stream) return;
  const tier = TIERS[quality];
  await Promise.all(
    stream.getVideoTracks().map(async (track) => {
      try {
        await track.applyConstraints({
          width: { ideal: tier.width, max: tier.width },
          height: { ideal: tier.height, max: tier.height },
          frameRate: { ideal: tier.frameRate, max: tier.frameRate },
        });
      } catch {
        // Some cameras reject live re-constrain; ignore.
      }
    }),
  );
}

/**
 * Pin the video codec to VP8 (keeping rtx/red/ulpfec resilience payloads).
 * This is a CORRECTNESS requirement, not a preference: the E2EE frame crypto
 * (call-frame-crypto.ts) leaves exactly the VP8 payload-descriptor bytes
 * (10 keyframe / 3 delta) unencrypted for the RTP packetizer. If SDP default
 * ordering ever negotiated VP9/H264/AV1, those byte offsets would be wrong and
 * the depacketizer would receive encrypted codec headers — corrupt video on a
 * "successful" call. Pinning makes the negotiated codec deterministic on every
 * platform/WebView version. Best-effort: engines without setCodecPreferences
 * keep default ordering (VP8-first on every Chromium WebView we ship on).
 */
export function pinVideoCodec(pc: RTCPeerConnection): void {
  try {
    const caps = RTCRtpSender.getCapabilities?.("video");
    if (!caps?.codecs?.length) return;
    const allowed = ["video/vp8", "video/rtx", "video/red", "video/ulpfec"];
    const preferred = caps.codecs.filter((codec) => allowed.includes(codec.mimeType.toLowerCase()));
    if (!preferred.some((codec) => codec.mimeType.toLowerCase() === "video/vp8")) return;
    for (const transceiver of pc.getTransceivers()) {
      if (transceiver.sender.track?.kind !== "video") continue;
      if (typeof transceiver.setCodecPreferences === "function") {
        transceiver.setCodecPreferences(preferred);
      }
    }
  } catch {
    // Codec pinning is defense-in-depth; default ordering already yields VP8.
  }
}
